# Optional outer upload gate

This HAProxy 3.2.23 example gives the bounded POST endpoint an absolute **two-second
body collection deadline**, even when bytes keep arriving. Header receipt has a
separate two-second timeout. It accepts one decimal Content-Length of at most
65536 bytes, rejects transfer encoding and non-POST methods, waits for the body,
and checks received length against declared length before opening an upstream
connection. The final check prevents HAProxy's buffer-full exit from forwarding
an incomplete prefix.

This is an opt-in transport restriction, not a general MCP transport proxy. GET,
chunked uploads and streaming requests are excluded; HTTP/2 and TLS were not
verified. It leaves response content enforcement to Flex and does **not** close
the PDK double-write termination gap. It uses no header as trusted policy state.

## Local deployment profile

Prepare the authorized local registration and policy assets using the existing
Flex runbook, then run from the repository root:

```bash
export UPLOAD_GATE_CONFIG="$PWD/deployment/upload-gate/haproxy.cfg"
docker compose -f mcp-honeytoken-tripwire/playground/docker-compose.yaml \
  -f deployment/docker-resource-limits.yaml \
  -f deployment/upload-gate/compose.yaml up -d
```

Use a Docker Compose version supporting `!reset`. The rendered configuration
removes Flex's direct host port, exposes only the edge on **127.0.0.1:8080**, caps
Flex at 1 GiB and the edge at 128 MiB, and disables swap for both. Those are example
budgets, not production sizing recommendations. The overlay also sets Flex’s
per-stream buffer to 128 KiB and idle/response timers to five seconds. Other hosts/services on the Docker
network could still reach Flex: deployment network isolation must prevent that
bypass. This profile has been rendered and checked, not deployed with Flex here.

## Reproduce the credential-free test

```bash
docker pull haproxy:3.2-alpine@sha256:5961c68bc8a81c5124d0a98ab20f81b74717d6afe596e805977d9cf84c126222
docker pull python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c
python3 scripts/verify_upload_gate.py
```

Requires Linux containers, cgroup v2, Docker Compose, and Python 3. The test creates
uniquely named containers/network, exposes only a random loopback edge port, and
removes its resources in `finally`. It has no registration or platform credentials.
The backend records both TCP accepts and parsed request admissions; assertions
exclude its own local statistics queries.

Verified with the pinned image:

- A byte every 100 ms cannot extend the two-second body deadline: HTTP 408 before
  four seconds, no backend connection or request admission.
- Missing/conflicting lengths, transfer encoding, oversize declarations, and a
  buffer-filling incomplete body are rejected without backend admission.
- A complete 64 KiB body is admitted byte-for-byte.
- Sixteen concurrent active slow uploads time out; a subsequent clean request works.
- Docker and live cgroup limits agree at 128 MiB, with swap disabled.
- A deliberately allocating process triggers a kernel OOM kill inside that cgroup.
  An **explicit restart** then restores clean traffic and preserves the limits.
  This does not assert automatic restart, zero downtime, or which process is killed.

The active-upload regression fails without the body-wait rule. Removing the
complete-body guard also fails the buffer-full regression. Public CI runs these
actual Docker wire tests as a separate job.

## Complete Local Mode chain

With freshly prepared Honeytoken assets and an authorized disposable registration
in that policy’s own `tests/config` directory:

```bash
python3 scripts/flex_runtime_gate.py --prepare --assets-only
python3 scripts/verify_upload_gate.py --flex
```

This optional mode mounts the identity in place without reading or copying it,
starts Flex 1.14.0 without a published host port, and routes edge → Flex → synthetic
backend. It additionally verifies Honeytoken request denial, sixteen concurrent
64 KiB clean exchanges, the live 1 GiB Flex cgroup cap, an observed kernel OOM kill
within that cgroup, and successful traffic after an explicit Flex restart.
Both the default and `--flex` suites passed locally. The disposable Local Mode
registration was then deleted remotely before local removal. CI runs only the
default suite and receives no identity.

These are bounded local experiments, not an availability SLA or proof of automatic
recovery. Production adoption still requires ingress isolation and workload-specific
sizing. The [PDK response termination capability](../../mcp-honeytoken-tripwire/docs/pdk-response-termination-gap.md)
remains missing; neither the edge deadline nor an OOM restart proves containment
after both response-body writes fail.

[HAProxy's configuration manual](https://docs.haproxy.org/3.2/configuration.html#http-request%20wait-for-body)
documents body-wait timeout and buffer-full behavior. The byte-count comparison
addresses the latter explicitly.
