# Gateway resource preflight (#13)

Policy body-size limits and Flex per-stream buffers do not cap aggregate gateway
memory across concurrent streams. Apply a container memory limit separately and
verify that the kernel actually has that limit. A soft reservation is insufficient.

## Docker example

An opt-in Compose override is supplied in
[`deployment/docker-resource-limits.yaml`](../deployment/docker-resource-limits.yaml).
It sets a **1 GiB example** hard limit, disables swap, requests a private cgroup
namespace, and explicitly configures Flex buffer and timeout settings. Size the
memory budget for your deployment and validate availability under representative
load; this example is not a throughput or availability commitment.

From the repository root, after the policy assets and an authorized local
registration are prepared through the existing runbook:

```bash
docker compose -f mcp-honeytoken-tripwire/playground/docker-compose.yaml \
  -f deployment/docker-resource-limits.yaml up -d local-flex
# Substitute the exact running local-flex container ID printed by compose ps.
python3 scripts/gateway_resource_preflight.py CONTAINER_ID \
  --max-memory-bytes 1073741824
```

Apply the same override to the Sentinel or Breadcrumb playground by changing the
first Compose path. Relative mounts remain relative to that first Compose file.
This command starts infrastructure: it is a deployment instruction, not a command
run by the checker or credential-free CI.

The read-only checker resolves the container name to an immutable ID, reads only
selected Docker limit/state fields, and reads `memory.max` and `memory.swap.max`
inside its private cgroup namespace. It rejects unlimited/excessive memory,
implicit or enabled swap, disabled OOM killing, privileged containers, stopped
containers, kernel/config mismatches, and unsupported cgroup layouts. It never
reads registration files, Docker environment variables, or mounts, and suppresses
raw Docker error output. Linux cgroup v2 and `cat` in the container are required.

A pass is a **point-in-time configuration check**. Re-run after deployment changes.
It does not prove that the service remains available at the cap, that cgroup
accounting equals host-wide memory use, or that response bytes remain contained
when a policy write fails. OOM killing can make the gateway unavailable. Keep
runtime health and OOM monitoring in the deployment's operational checks.

## Evidence

The checker was tested against an isolated, network-disabled Alpine container:
no Docker hard limit was rejected; after setting memory and memory-swap to 256 MiB,
Docker and the live cgroup both reported a 268435456-byte limit and zero swap.
The container was then removed. This verifies the checker against a real kernel;
it is **not a Flex load test**. Unit regressions cover invalid and mismatched limits.

The Honeytoken raw-socket suite also sends the five bytes of a clean body at
500 ms intervals. With a one-second Flex stream-idle timeout, the two-second
upload is accepted. This explicitly tests that continuing activity can extend an
upload beyond the idle interval. It does not establish an absolute upload deadline.

## Outer gate now available

The [optional upload gate](../deployment/upload-gate/README.md) adds a tested
body collection deadline and complete-body admission. Its separate Docker suite
also exercises concurrent uploads, a kernel OOM kill, and explicit restart under
a 128 MiB cap. The optional Local Mode suite additionally verifies the complete
edge/Flex/synthetic-backend chain, sixteen concurrent 64 KiB exchanges, and Flex
OOM/explicit restart under a verified 1 GiB cgroup cap.

## Deployment limits after reviewer acceptance

- Apply and validate ingress isolation and workload-specific sizing in the target
  deployment. Local full-chain load/OOM/restart evidence is now available; it is
  not a production availability guarantee.
- Supported downstream termination after both response-body replacement attempts
  fail; see the [PDK gap](../mcp-honeytoken-tripwire/docs/pdk-response-termination-gap.md).

#6 and #13 were subsequently closed by the original reviewer. A subsequent authorized
[Connected Mode Sandbox run](CONNECTED-MONITORING-EVIDENCE.md) verified Sentinel
exported counts. Local cgroup or wire tests alone cannot supply that evidence.
See the [current acceptance status](REMAINING-ISSUES-PLAN.md).

## Sources

- [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/)
  documents hard limits and equal memory/memory-swap settings to disable swap.
- [Compose service settings](https://docs.docker.com/reference/compose-file/services/)
  documents `mem_limit`, `memswap_limit`, and private `cgroup` namespaces.
- [Flex Local Mode timeouts](https://docs.mulesoft.com/gateway/latest/local-timeout)
  distinguishes stream inactivity from upstream response timing.
