# Copyright (c) 2026 msaleme. Licensed under the MIT License.
import unittest
from unittest.mock import patch
import subprocess
import json
from gateway_resource_preflight import validate_limits, inspect_limits, docker, PreflightError


class ResourceLimitsTests(unittest.TestCase):
    def setUp(self):
        self.config = dict(running=True, memory=1073741824, swap=1073741824,
                           oom_disabled=False, privileged=False, cgroupns='private')
        self.kernel = ['1073741824', '0']

    def check(self):
        return validate_limits(self.config, self.kernel, 1073741824)

    def test_matching_hard_limit_and_disabled_swap(self):
        self.assertEqual(self.check(), 1073741824)

    def test_unlimited_or_oversized_memory_rejected(self):
        for value in (0, -1, 2147483648, True, '1073741824'):
            with self.subTest(value=value):
                self.config['memory'] = value
                with self.assertRaises(PreflightError): self.check()

    def test_swap_must_be_explicitly_disabled(self):
        for value in (0, -1, 2147483648, None):
            with self.subTest(value=value):
                self.config['swap'] = value
                with self.assertRaises(PreflightError): self.check()

    def test_kernel_must_confirm_docker_limit(self):
        for value in ('max', '2147483648', '0', 'bad', '536870912'):
            with self.subTest(value=value):
                self.kernel[0] = value
                with self.assertRaises(PreflightError): self.check()

    def test_kernel_swap_limit_must_be_zero(self):
        for value in ('max', '1024', 'bad'):
            with self.subTest(value=value):
                self.kernel[1] = value
                with self.assertRaises(PreflightError): self.check()

    def test_unsafe_or_stopped_container_rejected(self):
        for key, value in [('running', False), ('oom_disabled', True),
                           ('privileged', True), ('cgroupns', 'host')]:
            with self.subTest(key=key):
                old = self.config[key]
                self.config[key] = value
                with self.assertRaises(PreflightError): self.check()
                self.config[key] = old

    def test_incomplete_evidence_rejected(self):
        self.kernel = ['1073741824']
        with self.assertRaises(PreflightError): self.check()
        self.kernel = ['1073741824', '0']
        del self.config['memory']
        with self.assertRaises(PreflightError): self.check()

    def test_missing_state_evidence_rejected(self):
        for key in ('oom_disabled', 'privileged', 'running', 'cgroupns'):
            config = self.config.copy()
            del config[key]
            with self.subTest(key=key), self.assertRaises(PreflightError):
                validate_limits(config, self.kernel, 1073741824)

    def test_inspection_uses_immutable_id_and_only_limit_fields(self):
        cid = 'a' * 64
        with patch('gateway_resource_preflight.docker', side_effect=[
                cid, json.dumps(self.config), '1073741824\n0']) as command:
            self.assertEqual(inspect_limits('gateway', 1073741824), 1073741824)
        calls = [call.args for call in command.call_args_list]
        self.assertEqual(calls[1][-1], cid)
        self.assertEqual(calls[2], ('exec', cid, 'cat', '/sys/fs/cgroup/memory.max',
                                    '/sys/fs/cgroup/memory.swap.max'))
        self.assertNotIn('.Env', calls[1][2])
        self.assertNotIn('.Mounts', calls[1][2])

    def test_docker_errors_do_not_echo_output(self):
        result = subprocess.CompletedProcess([], 1, stdout='private-output', stderr='private-output')
        with patch('gateway_resource_preflight.subprocess.run', return_value=result):
            with self.assertRaises(PreflightError) as error: docker('inspect')
        self.assertNotIn('private-output', str(error.exception))

    def test_option_like_container_names_are_rejected_before_docker(self):
        with patch('gateway_resource_preflight.docker') as command:
            with self.assertRaises(PreflightError): inspect_limits('--help', 1073741824)
            command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
