# Copyright (c) 2026 msaleme. Licensed under the MIT License.
"""Offline metadata-generation checks through each policy's actual Makefile environment."""
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml
from flex_runtime_gate import ROOT, POLICIES, fixture_name


class BuildContractTests(unittest.TestCase):
    def test_standard_make_generator_matches_runtime_fixture(self):
        for policy in POLICIES:
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as directory:
                folder = ROOT / policy
                expected = fixture_name(folder)
                binary = Path(directory) / 'empty.wasm'
                output = Path(directory) / 'implementation.yaml'
                # Only generator metadata is tested; this module is never executed.
                binary.write_bytes(b'\x00asm\x01\x00\x00\x00')
                rule = ('review-gcl:\n\t@cargo anypoint gcl-gen -d "$(DEFINITION_NAME)" '
                        '-n default -w "$(REVIEW_WASM)" -o "$(REVIEW_IMPL)"\n')
                subprocess.run(['make', '-s', '-f', 'Makefile', '-f', '-', 'review-gcl',
                                'DEFINITION_NAME=' + expected.removesuffix('-impl'),
                                'REVIEW_WASM=' + str(binary), 'REVIEW_IMPL=' + str(output)],
                               input=rule, text=True, cwd=folder, check=True, capture_output=True)
                generated = yaml.safe_load(output.read_text())
                self.assertEqual(generated['metadata']['name'], expected)
                reference = subprocess.check_output(
                    ['make', '-s', 'show-policy-ref-name',
                     'DEFINITION_NAME=' + expected.removesuffix('-impl')], cwd=folder, text=True)
                self.assertEqual(reference.strip(), expected)


if __name__ == '__main__':
    unittest.main()
