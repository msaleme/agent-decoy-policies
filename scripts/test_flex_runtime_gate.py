# Copyright (c) 2026 msaleme. Licensed under the MIT License.
"""Offline tests for the local Flex asset evidence gate; no Docker or identity access."""
import base64
import json
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import contextlib
import io

import yaml

spec = importlib.util.spec_from_file_location("gate", Path(__file__).with_name("flex_runtime_gate.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.policy = "sample-policy"
        folder = self.root / self.policy
        (folder / "definition").mkdir(parents=True)
        (folder / "tests/common").mkdir(parents=True)
        (folder / "tests/common/mod.rs").write_text('pub const POLICY_NAME: &str = "sample-v1-0-impl";\n')
        self.source = {"apiVersion": "gateway.mulesoft.com/v1alpha1", "kind": "Extension",
                       "metadata": {"labels": {"title": "Sample"}},
                       "spec": {"properties": {"mode": {"type": "string", "default": "block"}},
                                "required": ["mode"]}}
        (folder / "definition/gcl.yaml").write_text(yaml.safe_dump(self.source))
        self.release = folder / "target/wasm32-wasip1/release"
        self.release.mkdir(parents=True)
        self.wasm = self.release / "sample_policy.wasm"
        self.wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")
        definition = dict(self.source, metadata=dict(self.source["metadata"], name="sample-v1-0", namespace="default"))
        self.definition = self.release / "sample_policy_definition.yaml"
        self.definition.write_text(yaml.safe_dump(definition))
        self.implementation = self.release / "sample_policy_implementation.yaml"
        self.write_implementation(self.wasm.read_bytes())

    def write_implementation(self, binary):
        self.implementation.write_text(yaml.safe_dump({
            "apiVersion": "gateway.mulesoft.com/v1alpha1", "kind": "Extension",
            "metadata": {"name": "sample-v1-0-impl"},
            "spec": {"extends": [{"name": "sample-v1-0", "namespace": "default"}],
                     "properties": {"implementation": {"type": "string", "default": "base64://" + base64.b64encode(binary).decode()}}}}))

    def test_assets_only_does_not_require_registration(self):
        with patch.object(gate, "ROOT", self.root), patch.object(gate, "POLICIES", (self.policy,)), patch.object(gate, "verify_provenance", return_value=True), patch("sys.argv", ["gate", "--assets-only"]), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(), 0)

    def test_assets_only_still_rejects_invalid_assets(self):
        self.wasm.write_bytes(b"invalid")
        with patch.object(gate, "ROOT", self.root), patch.object(gate, "POLICIES", (self.policy,)), patch.object(gate, "verify_provenance", return_value=True), patch("sys.argv", ["gate", "--assets-only"]), contextlib.redirect_stdout(io.StringIO()):
            self.assertNotEqual(gate.main(), 0)

    def test_matching_bundle_passes(self):
        self.assertEqual(gate.inspect_bundle(self.root, self.policy), [])

    def test_stale_schema_is_rejected(self):
        source = self.source
        source["spec"]["properties"]["newField"] = {"type": "string"}
        (self.root / self.policy / "definition/gcl.yaml").write_text(yaml.safe_dump(source))
        self.assertIn("definition differs from current source schema", gate.inspect_bundle(self.root, self.policy))

    def test_missing_definition_name_is_rejected(self):
        data = yaml.safe_load(self.definition.read_text())
        del data["metadata"]["name"]
        self.definition.write_text(yaml.safe_dump(data))
        self.assertIn("definition name does not match fixture", gate.inspect_bundle(self.root, self.policy))

    def test_stale_embedded_wasm_is_rejected(self):
        self.write_implementation(b"old-wasm")
        self.assertIn("embedded WASM differs from release binary", gate.inspect_bundle(self.root, self.policy))

    def test_wrong_implementation_reference_is_rejected(self):
        data = yaml.safe_load(self.implementation.read_text())
        data["metadata"]["name"] = "other-impl"
        self.implementation.write_text(yaml.safe_dump(data))
        self.assertIn("implementation name does not match fixture", gate.inspect_bundle(self.root, self.policy))

    def test_build_provenance_detects_changed_source(self):
        folder = self.root / self.policy
        for name in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "tests/requests.rs"]:
            (folder / name).write_text("test fixture")
        (folder / "src").mkdir()
        source = folder / "src/lib.rs"
        source.write_text("old source")
        record = {"sha256": gate.hashed_inputs(folder, self.release, "sample_policy")}
        (self.release / "runtime-bundle.json").write_text(json.dumps(record))
        self.assertTrue(gate.verify_provenance(folder, self.release, "sample_policy"))
        backend = folder / "tests/backend.py"
        backend.write_text("new fixture")
        self.assertFalse(gate.verify_provenance(folder, self.release, "sample_policy"))
        backend.unlink()
        self.assertTrue(gate.verify_provenance(folder, self.release, "sample_policy"))
        source.write_text("new source")
        self.assertFalse(gate.verify_provenance(folder, self.release, "sample_policy"))

    def test_malformed_provenance_fails_closed(self):
        (self.release / "runtime-bundle.json").write_text("[]")
        self.assertFalse(gate.verify_provenance(self.root / self.policy, self.release, "sample_policy"))

    def test_corrupt_assets_report_failure(self):
        self.implementation.write_text("not: [valid")
        self.assertTrue(gate.inspect_bundle(self.root, self.policy))


if __name__ == "__main__":
    unittest.main()
