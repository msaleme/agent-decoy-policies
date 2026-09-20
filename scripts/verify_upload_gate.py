#!/usr/bin/env python3
# Copyright (c) 2026 msaleme. Licensed under the MIT License.
"""Credential-free Linux Docker wire tests for the optional outer upload gate."""
import concurrent.futures
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import sys
import subprocess
import threading
import time
import uuid

from gateway_resource_preflight import inspect_limits

IMAGE = 'haproxy:3.2-alpine@sha256:5961c68bc8a81c5124d0a98ab20f81b74717d6afe596e805977d9cf84c126222'
ROOT = Path(__file__).resolve().parents[1]


def docker(*args, check=True):
    result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=30)
    if check and result.returncode:
        raise RuntimeError('Docker test operation failed: '+args[0]+'; raw output withheld')
    return result


class Backend(http.server.BaseHTTPRequestHandler):
    admitted = []
    connections = 0
    queries = 0
    lock = threading.Lock()

    def do_POST(self):
        # Record at headers, before reading a possibly incomplete body.
        with self.lock:
            self.admitted.append(self.path)
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        with self.lock:
            Backend.queries += 1
            data = json.dumps({'admitted': self.admitted, 'connections': self.connections-self.queries}).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class BackendServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def get_request(self):
        connection = super().get_request()
        with Backend.lock:
            Backend.connections += 1
        return connection


def headers(path, length):
    return (f'POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {length}'
            '\r\nConnection: close\r\n\r\n').encode()


def exchange(port, data):
    with socket.create_connection(('127.0.0.1', port), timeout=5) as stream:
        stream.sendall(data)
        response = http.client.HTTPResponse(stream)
        try:
            response.begin()
        except http.client.RemoteDisconnected:
            return 0, b''  # Explicit connection rejection; never a success.
        body = response.read(131073)
        assert len(body) <= 131072
        return response.status, body


def slow(port):
    with socket.create_connection(('127.0.0.1', port), timeout=6) as stream:
        stream.sendall(headers('/slow', 100))
        finished = threading.Event()
        def upload():
            for _ in range(40):
                if finished.is_set(): break
                try: stream.sendall(b'x')
                except OSError: break
                finished.wait(0.1)
        sender = threading.Thread(target=upload, daemon=True)
        started = time.monotonic()
        sender.start()
        try:
            response = http.client.HTTPResponse(stream)
            response.begin()
            response.read(131073)
            assert response.status == 408, f'expected 408, got {response.status}'
            elapsed = time.monotonic() - started
            assert 1 <= elapsed < 4, f'upload deadline outside expected interval: {elapsed:.2f}'
        finally:
            finished.set()
            sender.join(timeout=1)


def verify_compose():
    environment = dict(os.environ, UPLOAD_GATE_CONFIG=str(ROOT / 'deployment/upload-gate/haproxy.cfg'))
    result = subprocess.run(['docker', 'compose',
        '-f', str(ROOT / 'mcp-honeytoken-tripwire/playground/docker-compose.yaml'),
        '-f', str(ROOT / 'deployment/docker-resource-limits.yaml'),
        '-f', str(ROOT / 'deployment/upload-gate/compose.yaml'), 'config', '--format', 'json'],
        env=environment, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, 'Compose profile could not be rendered'
    services = json.loads(result.stdout)['services']
    assert not services['local-flex'].get('ports'), 'direct Flex host-port bypass'
    assert services['upload-gate']['ports'][0]['host_ip'] == '127.0.0.1'
    assert int(services['upload-gate']['mem_limit']) == 134217728
    assert int(services['local-flex']['mem_limit']) == 1073741824
    print('PASS: rendered Compose removes direct Flex host port and retains memory caps', flush=True)


def main():
    with_flex = sys.argv[1:] == ['--flex']
    if sys.argv[1:] and not with_flex:
        raise SystemExit('Usage: verify_upload_gate.py [--flex]')
    verify_compose()
    name = 'decoy-upload-gate-'+uuid.uuid4().hex[:12]
    backend = name+'-backend'
    network = name+'-network'
    flex = name+'-flex'
    def admissions():
        result = docker('exec', backend, 'python', '-c',
                        'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8081/").read().decode())')
        evidence = json.loads(result.stdout)
        assert evidence['connections'] == len(evidence['admitted']), 'unexpected backend connection'
        return evidence['admitted']
    try:
        docker('network', 'create', network)
        docker('run', '-d', '--pull=never', '--network', network, '--network-alias', 'backend', '--name', backend,
               '--memory=128m', '--memory-swap=128m', '--pids-limit=64',
               '--mount', f'type=bind,source={ROOT / "scripts"},target=/scripts,readonly',
               'python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c',
               'python', '/scripts/verify_upload_gate.py', '--backend')
        if with_flex:
            policy = ROOT / 'mcp-honeytoken-tripwire'
            assert (policy / 'tests/config/registration.yaml').is_file(), 'authorized local registration required'
            config_root = '/usr/local/share/mulesoft/flex-gateway/conf.d'
            docker('run', '-d', '--pull=never', '--network', network, '--name', flex,
                   '--cgroupns=private', '--memory=1g', '--memory-swap=1g',
                   '-e', 'FLEX_DOWNSTREAM_CONNECTION_BUFFER_LIMIT_BYTES=131072',
                   '-e', 'FLEX_STREAM_IDLE_TIMEOUT_SECONDS=5',
                   '-e', 'FLEX_UPSTREAM_RESPONSE_TIMEOUT_SECONDS=5',
                   '--mount', f'type=bind,source={policy / "tests/config"},target={config_root}/common,readonly',
                   '--mount', f'type=bind,source={policy / "target/wasm32-wasip1/release"},target={config_root}/custom-policies,readonly',
                   '--mount', f'type=bind,source={ROOT / "deployment/upload-gate/flex-test-api.yaml"},target={config_root}/api.yaml,readonly',
                   'mulesoft/flex-gateway:1.14.0')
            for attempt in range(60):
                result = docker('exec', flex, 'flexctl', 'probe', '--check=readiness', check=False)
                if result.returncode == 0: break
                if attempt == 59: raise RuntimeError('Flex readiness failed; raw identity logs withheld')
                time.sleep(0.5)
            assert inspect_limits(flex, 1073741824) == 1073741824
        docker('run', '-d', '--pull=never', '--network', network, '--cgroupns=private',
               '--memory=128m', '--memory-swap=128m', '--pids-limit=64', '--name', name,
               '-p', '127.0.0.1::8080', '-e', 'EDGE_BIND=0.0.0.0:8080',
               '-e', f'FLEX_ADDRESS={flex if with_flex else backend}:8081',
               '--mount', f'type=bind,source={ROOT / "deployment/upload-gate/haproxy.cfg"},target=/usr/local/etc/haproxy/haproxy.cfg,readonly',
               IMAGE)
        port = int(docker('port', name, '8080/tcp').stdout.strip().rsplit(':', 1)[1])
        for attempt in range(50):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1): break
            except OSError:
                if attempt == 49: raise
                time.sleep(0.1)
        assert inspect_limits(name, 134217728) == 134217728
        assert exchange(port, headers('/clean', 5)+b'clean') == (200, b'clean')
        if with_flex:
            token = b'outer-gate-decoy'
            assert exchange(port, headers('/blocked', len(token))+token)[0] == 403
        slow(port)
        assert admissions() == ['/clean'], 'incomplete upload reached backend headers'
        print('PASS: active upload receives 408 within deadline; zero backend admission', flush=True)
        invalid = [
            b'POST /bad HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
            headers('/bad', 65537),
            b'POST /bad HTTP/1.1\r\nHost: localhost\r\n\r\n',
            b'POST /bad HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx',
        ]
        for wire in invalid:
            status, _ = exchange(port, wire)
            assert status == 0 or 400 <= status < 500, status
        saturated = headers('/bad', 65536).replace(b'Connection: close', b'X-Fill: '+b'h'*90000+b'\r\nConnection: close')+b'x'*50000
        status, _ = exchange(port, saturated)
        assert status == 0 or status in (400, 413), status
        large = b'x'*65536
        assert exchange(port, headers('/large', len(large))+large) == (200, large)
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(lambda _: slow(port), range(16)))
        assert exchange(port, headers('/recovery', 2)+b'ok') == (200, b'ok')
        assert admissions() == ['/clean', '/large', '/recovery'], admissions()
        print('PASS: malformed/unsupported framing rejected; 64 KiB admitted; 16 active uploads bounded; recovery succeeds', flush=True)
        print('PASS: aggregate gate memory cap verified at 128 MiB, swap disabled', flush=True)
        # Allocation is confined to this disposable 128 MiB cgroup. It may kill
        # the allocating child or the proxy; verify a kernel OOM event either way.
        exhausted = docker('exec', name, 'awk', 'BEGIN { s="x"; while (1) { s=s s } }', check=False)
        assert exhausted.returncode != 0, 'memory exhaustion unexpectedly succeeded'
        state = json.loads(docker('inspect', '--format={{json .State}}', name).stdout)
        if not state.get('OOMKilled'):
            events = docker('exec', name, 'cat', '/sys/fs/cgroup/memory.events').stdout
            counters = dict(line.split() for line in events.splitlines())
            assert int(counters.get('oom_kill', '0')) > 0, 'no kernel OOM kill observed'
        docker('restart', name)
        # Restart can assign a different ephemeral published port.
        port = int(docker('port', name, '8080/tcp').stdout.strip().rsplit(':', 1)[1])
        for attempt in range(50):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1): break
            except OSError:
                if attempt == 49: raise
                time.sleep(0.1)
        assert inspect_limits(name, 134217728) == 134217728
        assert exchange(port, headers('/after-oom', 2)+b'ok') == (200, b'ok')
        assert admissions() == ['/clean', '/large', '/recovery', '/after-oom']
        print('PASS: kernel OOM kill observed within cap; explicit restart restores service and limits', flush=True)
        if with_flex:
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                results = list(pool.map(lambda i: exchange(port, headers('/load-'+str(i), len(large))+large), range(16)))
            assert all(result == (200, large) for result in results)
            expected = ['/clean', '/large', '/recovery', '/after-oom'] + ['/load-'+str(i) for i in range(16)]
            assert sorted(admissions()) == sorted(expected)
            exhausted = docker('exec', flex, 'awk', 'BEGIN { s="x"; while (1) { s=s s } }', check=False)
            assert exhausted.returncode != 0
            state = json.loads(docker('inspect', '--format={{json .State}}', flex).stdout)
            if not state.get('OOMKilled'):
                counters = dict(line.split() for line in docker('exec', flex, 'cat', '/sys/fs/cgroup/memory.events').stdout.splitlines())
                assert int(counters.get('oom_kill', '0')) > 0
            docker('restart', flex)
            for attempt in range(60):
                if docker('exec', flex, 'flexctl', 'probe', '--check=readiness', check=False).returncode == 0: break
                if attempt == 59: raise RuntimeError('Flex did not recover after explicit restart')
                time.sleep(0.5)
            assert inspect_limits(flex, 1073741824) == 1073741824
            assert exchange(port, headers('/flex-recovery', 2)+b'ok') == (200, b'ok')
            assert sorted(admissions()) == sorted(expected+['/flex-recovery'])
            print('PASS: full chain, Honeytoken denial, 16 concurrent 64 KiB exchanges, Flex OOM and explicit restart under 1 GiB cap', flush=True)
    finally:
        docker('rm', '-f', name, check=False)
        if with_flex:
            docker('rm', '-f', flex, check=False)
        docker('rm', '-f', backend, check=False)
        docker('network', 'rm', network, check=False)


if __name__ == '__main__':
    if sys.argv[1:] == ['--backend']:
        BackendServer(('0.0.0.0', 8081), Backend).serve_forever()
    else:
        main()
