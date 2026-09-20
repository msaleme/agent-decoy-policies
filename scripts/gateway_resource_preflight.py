#!/usr/bin/env python3
# Copyright (c) 2026 msaleme. Licensed under the MIT License.
"""Read-only Docker/cgroup-v2 memory admission check; does not inspect identities."""
import argparse
import json
import re
import subprocess
import sys


class PreflightError(ValueError):
    pass


def validate_limits(config, kernel, ceiling):
    required = {'running', 'memory', 'swap', 'oom_disabled', 'privileged', 'cgroupns'}
    if not isinstance(config, dict) or not required.issubset(config):
        raise PreflightError('Docker limit/state evidence is incomplete')
    if type(ceiling) is not int or ceiling <= 0:
        raise PreflightError('operator memory ceiling must be positive')
    if config.get('running') is not True:
        raise PreflightError('container must be running')
    if config.get('privileged') is not False or config.get('oom_disabled') not in (False, None):
        raise PreflightError('privileged mode and disabled OOM killing are unsupported')
    if config.get('cgroupns') != 'private':
        raise PreflightError('explicit private cgroup namespace is required')
    memory = config.get('memory')
    if type(memory) is not int or not 0 < memory <= ceiling:
        raise PreflightError('Docker hard memory limit is missing or exceeds the operator ceiling')
    if type(config.get('swap')) is not int or config['swap'] != memory:
        raise PreflightError('Docker memory-swap must equal the hard memory limit')
    if len(kernel) != 2 or any(not re.fullmatch(r'[0-9]+', value) for value in kernel):
        raise PreflightError('finite cgroup-v2 memory and swap limits could not be read')
    if int(kernel[0]) != memory or int(kernel[1]) != 0:
        raise PreflightError('kernel memory/swap limits do not match the required Docker limits')
    return memory


def docker(*args):
    try:
        result = subprocess.run(['docker', *args], capture_output=True, text=True,
                                timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise PreflightError('Docker command unavailable or timed out') from None
    if result.returncode:
        raise PreflightError('Docker inspection failed; raw output withheld')
    return result.stdout.strip()


def inspect_limits(container, ceiling):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', container):
        raise PreflightError('invalid container name or ID')
    # Resolve once, then use the immutable ID so a renamed/replaced name cannot
    # select a different container between inspect and exec. Never read Env/Mounts.
    cid = docker('inspect', '--type=container', '--format={{.Id}}', container)
    if not re.fullmatch(r'[0-9a-f]{64}', cid):
        raise PreflightError('Docker did not resolve one container ID')
    projection = ('{"running":{{json .State.Running}},"memory":{{json .HostConfig.Memory}},'
                  '"swap":{{json .HostConfig.MemorySwap}},'
                  '"oom_disabled":{{json .HostConfig.OomKillDisable}},'
                  '"privileged":{{json .HostConfig.Privileged}},'
                  '"cgroupns":{{json .HostConfig.CgroupnsMode}}}')
    try:
        config = json.loads(docker('inspect', '--type=container', '--format='+projection, cid))
    except (ValueError, TypeError):
        raise PreflightError('Docker limit metadata is invalid') from None
    # Fail before exec when Docker configuration itself is not admissible.
    validate_limits(config, [str(config.get('memory')), '0'], ceiling)
    kernel = docker('exec', cid, 'cat', '/sys/fs/cgroup/memory.max',
                    '/sys/fs/cgroup/memory.swap.max').splitlines()
    return validate_limits(config, kernel, ceiling)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('container')
    parser.add_argument('--max-memory-bytes', required=True, type=int,
                        help='operator-selected maximum aggregate container memory')
    args = parser.parse_args()
    try:
        memory = inspect_limits(args.container, args.max_memory_bytes)
    except PreflightError as error:
        print('FAIL: '+str(error), file=sys.stderr)
        return 1
    print(f'PASS: Docker and cgroup-v2 memory limit={memory} bytes; swap=0')
    print('Snapshot only: does not prove availability under load or response containment.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
