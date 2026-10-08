#!/usr/bin/env python3
# Copyright (c) 2026 msaleme. Licensed under the MIT License.
"""Generate real Exchange metadata locally, check runtime pins, and redact it.

Requires ANYPOINT_GROUP_ID and installed PDK tooling. Never publishes, changes
Cargo.toml, opens registration files, or prints generator output/identity values.
"""
import json
import os
import re
import subprocess

from flex_runtime_gate import POLICIES, ROOT, inspect_runtime_metadata


def redact_generated(folder, group_id):
    target = folder / "target"
    # build-asset-files creates metadata/GCL/POM files, including definition
    # variants; cover all of them, without touching compiled binaries/caches.
    directories = (target / name for name in
                   ("definition", "definition-dev", "implementation", "implementation-dev"))
    files = [path for directory in directories for path in directory.rglob("*") if path.is_file()]
    for path in files:
        data = path.read_bytes()
        if group_id in data:
            path.write_bytes(data.replace(group_id, b"<org-id>"))
    if any(group_id in path.read_bytes() or group_id in str(path).encode() for path in files):
        raise RuntimeError("group ID remains in generated assets")


def main():
    group_id = os.environ.get("ANYPOINT_GROUP_ID", "")
    if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", group_id):
        raise RuntimeError("ANYPOINT_GROUP_ID must be the owning Anypoint group UUID")
    for policy in POLICIES:
        folder = ROOT / policy
        try:
            result = subprocess.run(["cargo", "anypoint", "get-anypoint-metadata"],
                                    cwd=folder, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError("project metadata extraction failed; raw output withheld")
            metadata = json.loads(result.stdout)
            metadata["group-id"] = group_id
            result = subprocess.run(["make", "build-asset-files",
                                     "ANYPOINT_METADATA_JSON=" + json.dumps(metadata)],
                                    cwd=folder, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError("Exchange metadata generation failed; raw output withheld")
            errors = inspect_runtime_metadata(folder)
            if errors:
                raise RuntimeError("; ".join(errors))
            print(f"{policy}: both implementation variants require Flex 1.14.0")
        finally:
            redact_generated(folder, group_id.encode())
    print("Generated asset group IDs redacted and checked. Nothing published.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        # These messages are fixed diagnostics or relative metadata paths only.
        raise SystemExit(str(error)) from None
    except (OSError, ValueError):
        # Exceptions from subprocess/JSON processing must not echo input values.
        raise SystemExit("Exchange runtime verification FAILED; raw diagnostic output withheld") from None
