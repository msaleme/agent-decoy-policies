#!/usr/bin/env python3
# Copyright (c) 2026 msaleme. Licensed under the MIT License.
"""Prepare/check local-only Flex test bundles without authentication or Docker.

Requires installed Rust 1.89.0, cargo-anypoint, and PyYAML. Never opens registration
files. Generated test definitions are not Exchange publication artifacts.
"""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess

import yaml

ROOT = Path(__file__).resolve().parents[1]
POLICIES = ("mcp-honeytoken-tripwire", "decoy-tool-sentinel", "breadcrumb-misdirection")


def paths(root, policy):
    folder = root / policy
    release = folder / "target/wasm32-wasip1/release"
    stem = policy.replace("-", "_")
    return folder, release, stem


def fixture_name(folder):
    text = (folder / "tests/common/mod.rs").read_text()
    match = re.search(r'pub const POLICY_NAME: &str = "([a-z0-9-]+-impl)";', text)
    if not match:
        raise ValueError("fixture has no literal implementation name")
    return match[1]


def inspect_bundle(root, policy):
    folder, release, stem = paths(root, policy)
    errors = []
    try:
        name = fixture_name(folder)
        source = yaml.safe_load((folder / "definition/gcl.yaml").read_text())
        definition = yaml.safe_load((release / f"{stem}_definition.yaml").read_text())
        implementation = yaml.safe_load((release / f"{stem}_implementation.yaml").read_text())
        if definition.get("metadata", {}).get("name") != name.removesuffix("-impl"):
            errors.append("definition name does not match fixture")
        if definition.get("spec") != source.get("spec"):
            errors.append("definition differs from current source schema")
        for key in ("apiVersion", "kind"):
            if definition.get(key) != source.get(key):
                errors.append(f"definition {key} differs from source")
        for key, value in source.get("metadata", {}).get("labels", {}).items():
            if definition.get("metadata", {}).get("labels", {}).get(key) != value:
                errors.append("definition labels differ from source")
                break
        if implementation.get("metadata", {}).get("name") != name:
            errors.append("implementation name does not match fixture")
        refs = implementation["spec"]["extends"]
        namespace = definition.get("metadata", {}).get("namespace", "default")
        if not any(ref.get("name") == name.removesuffix("-impl")
                   and ref.get("namespace", "default") == namespace for ref in refs):
            errors.append("implementation does not extend the fixture definition")
        encoded = implementation["spec"]["properties"]["implementation"]["default"]
        binary = (release / f"{stem}.wasm").read_bytes()
        if not binary.startswith(b"\x00asm\x01\x00\x00\x00"):
            errors.append("release binary is not WASM version 1")
        if not isinstance(encoded, str) or not encoded.startswith("base64://"):
            errors.append("implementation is not an embedded base64 WASM resource")
        elif base64.b64decode(encoded.removeprefix("base64://"), validate=True) != binary:
            errors.append("embedded WASM differs from release binary")
    except (OSError, ValueError, TypeError, KeyError, AttributeError, yaml.YAMLError):
        # Do not echo raw YAML/configuration in diagnostics.
        errors.append("missing or malformed bundle asset")
    return errors


def hashed_inputs(folder, release, stem):
    files = [folder / "Cargo.toml", folder / "Cargo.lock", folder / "rust-toolchain.toml",
             folder / "definition/gcl.yaml", folder / "tests/common/mod.rs", folder / "tests/requests.rs"]
    files.extend(sorted((folder / "src").rglob("*.rs")))
    files.extend(release / f"{stem}{suffix}" for suffix in (".wasm", "_definition.yaml", "_implementation.yaml"))
    return {str(path.relative_to(folder)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}


def verify_provenance(folder, release, stem):
    try:
        record = json.loads((release / "runtime-bundle.json").read_text())
        return record.get("sha256") == hashed_inputs(folder, release, stem)
    except (OSError, ValueError, TypeError, AttributeError):
        return False


def prepare(root, policy):
    folder, release, stem = paths(root, policy)
    subprocess.run(["cargo", "+1.89.0", "build", "--target", "wasm32-wasip1", "--release", "--locked", "--offline"], cwd=folder, check=True)
    name = fixture_name(folder)
    # Local-mode Extension resource from the current source schema. Only identity
    # metadata is added. This is deliberately not an Exchange asset generator.
    definition = copy.deepcopy(yaml.safe_load((folder / "definition/gcl.yaml").read_text()))
    definition.setdefault("metadata", {}).update(name=name.removesuffix("-impl"), namespace="default")
    (release / f"{stem}_definition.yaml").write_text(yaml.safe_dump(definition, sort_keys=False, allow_unicode=True))
    subprocess.run(["cargo", "anypoint", "gcl-gen", "-d", name.removesuffix("-impl"), "-n", "default",
                    "-w", str(release / f"{stem}.wasm"), "-o", str(release / f"{stem}_implementation.yaml")],
                   cwd=folder, check=True)
    errors = inspect_bundle(root, policy)
    if errors:
        raise RuntimeError("; ".join(errors))
    record = {"scope": "local Flex runtime test bundle, not Exchange publication assets",
              "rust": "1.89.0", "runtime_fixture": "Flex 1.14.0",
              "sha256": hashed_inputs(folder, release, stem)}
    (release / "runtime-bundle.json").write_text(json.dumps(record, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true", help="Build offline and regenerate local test assets; never starts Docker")
    args = parser.parse_args()
    blocked = False
    for policy in POLICIES:
        folder, release, stem = paths(ROOT, policy)
        if args.prepare:
            try:
                prepare(ROOT, policy)
            except (OSError, subprocess.CalledProcessError, RuntimeError, ValueError, yaml.YAMLError):
                print(f"{policy}: asset preparation FAILED")
                return 1
        errors = inspect_bundle(ROOT, policy)
        if not verify_provenance(folder, release, stem):
            errors.append("missing or stale build provenance; run --prepare")
        print(f"{policy}: assets " + ("PASS" if not errors else "FAIL: " + "; ".join(errors)))
        # Existence-only check: never read, parse, copy, or print identity material.
        present = (folder / "tests/config/registration.yaml").is_file()
        print("  registration: " + ("present; validity NOT checked" if present else "MISSING; runtime blocked"))
        blocked |= bool(errors) or not present
    print("No runtime executed. Registration presence is not proof of validity or authorization.")
    return 2 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
