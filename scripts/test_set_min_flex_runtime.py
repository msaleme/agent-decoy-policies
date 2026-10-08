# Copyright (c) 2026 msaleme. Licensed under the MIT License.
"""Exercise the shared parameterless post-generator pin in a policy directory."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from set_min_flex_runtime import METADATA_FILES


class RuntimePinTests(unittest.TestCase):
    def test_pins_both_variants_without_changing_other_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for relative in METADATA_FILES:
                path = folder / relative
                path.parent.mkdir(parents=True)
                path.write_text("minRuntimeVersion: 1.6.1\nname: coordinator\n")
            subprocess.run([sys.executable, str(Path(__file__).with_name("set_min_flex_runtime.py"))],
                           cwd=folder, check=True, capture_output=True)
            for relative in METADATA_FILES:
                self.assertEqual((folder / relative).read_text(),
                                 "minRuntimeVersion: 1.14.0\nname: coordinator\n")


if __name__ == "__main__":
    unittest.main()
