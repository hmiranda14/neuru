# neuru-agent

A **featherweight, push-based** metrics agent for [NEURU](https://github.com/hmiranda14/neuru) —
think Grafana Alloy / Datadog agent, but native to NEURU and dependency-free.

It runs as a small container on any remote Linux box, reads the host's `/proc`, `/sys` and
(optionally) the Docker socket, and **pushes** a health snapshot to NEURU every ~30 s over
**outbound HTTPS**. No inbound firewall rule, no SSH key, works behind NAT / CGNAT. Agents also
**offload polling from the NEURU server**, so a single NEURU scales to thousands of nodes.

The snapshot uses the **same shape** NEURU's SSH Linux Monitor produces, so an agent host renders
identically in **Linux Monitor** (`linux.php`) with zero server changes — CPU, memory, disks,
network, top processes, temperatures/fans, plus per-container Docker stats.

## Quick start

1. In NEURU: **Config → Poller → Remote Agents** → copy the **enrollment token** and **endpoint URL**.
2. On the box to monitor, drop [`docker-compose.yml`](./docker-compose.yml), fill in `NEURU_URL` +
   `NEURU_TOKEN`, then:
   ```sh
   docker compose up -d
   ```
3. Within ~30 s the host appears in NEURU → Linux Monitor (badge **via Agent**).

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `NEURU_URL` | — (required) | Full endpoint, e.g. `https://neuru.example.com/nm_agent_api.php` |
| `NEURU_TOKEN` | — (required) | Enrollment token from Config → Poller → Remote Agents |
| `NEURU_HOSTNAME` | host's hostname | Display name in NEURU |
| `NEURU_UID` | host `machine-id` | Stable identity (keeps re-registration idempotent) |
| `NEURU_INTERVAL` | `30` | Seconds between pushes (NEURU may override) |
| `NEURU_VERIFY_TLS` | `1` | Set `0` for a self-signed NEURU certificate |

## Why push (not a persistent socket)?

NEURU is PHP + Apache and can't hold thousands of long-lived WebSockets. The agent POSTs batched
JSON on an interval — stateless, horizontally scalable, and firewall-friendly. **Remote actions**
ride back on each POST's response (a per-host command queue), so no inbound channel is ever needed.

## Security

- The agent only ever makes **outbound** requests; it never listens.
- It authenticates with the shared enrollment token (`X-NEURU-Agent-Token`). Rotate it in NEURU to
  revoke every agent at once.
- All host mounts are **read-only** (`:ro`); the Docker socket is optional and read-only.
- Runs as a non-root user inside the container.

## Build locally

```sh
docker build -t neuru-agent:dev .
docker run --rm --pid host --network host \
  -e NEURU_URL="https://YOUR-NEURU/nm_agent_api.php" -e NEURU_TOKEN="…" \
  -v /proc:/host/proc:ro -v /sys:/host/sys:ro -v /:/host/root:ro \
  neuru-agent:dev
```

## What the SSH collector still adds

The agent covers CPU/mem/disk/net/sensors/top-processes/containers. A few items still come only from
the SSH Linux Monitor (they need host package managers / root block access): **systemd service
counts, pending OS updates, SMART disk health, firewall state**. You can run both on the same host.
