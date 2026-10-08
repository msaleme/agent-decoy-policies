# Copyright (c) 2026 msaleme. Licensed under the MIT License.
"""Check that generated definition and implementation variants are all redacted."""
from pathlib import Path
import tempfile
import unittest

from verify_exchange_runtime import redact_generated


class RedactionTests(unittest.TestCase):
    def test_redacts_all_generated_variants_and_rejects_identity_in_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            marker = b"test-group-marker"
            for variant in ("definition", "definition-dev", "implementation", "implementation-dev"):
                target = folder / "target" / variant
                target.mkdir(parents=True)
                (target / "exchange.json").write_bytes(b'{"groupId":"' + marker + b'"}')
            redact_generated(folder, marker)
            for path in (folder / "target").rglob("exchange.json"):
                self.assertEqual(path.read_bytes(), b'{"groupId":"<org-id>"}')
            (folder / "target/implementation" / marker.decode()).write_text("name exposure")
            with self.assertRaises(RuntimeError):
                redact_generated(folder, marker)


if __name__ == "__main__":
    unittest.main()
