# NEURU Sentinel — wire threat sensor

A passive, out-of-band security sensor. It enrols with NEURU, pulls the **SPECTRE**
threat-intel matrix (known-bad C2/malware IPs + domains from Abuse.ch Feodo/URLhaus),
and watches your segment:

- **DNS queries** for known-bad domains (C2 lookups) → reported.
- **IP flows** from local hosts to known-bad IPs → reported.

**Detection only, zero latency, no TLS interception.** NEURU does the blocking —
VECTOR-SHIELD fans the block out to your Pi-hole/AdGuard/firewalls via Collective
Immunity, and NEURO-ISOLATION can quarantine an infected host on its gateway router.

Deploy 1-click from **NEURU → Containers**, or:
```sh
curl -O https://raw.githubusercontent.com/hmiranda14/neuru/main/scripts/neuru-sentinel/docker-compose.yml
# edit NEURU_URL + SENTINEL_TOKEN
docker compose up -d
```
Multi-arch: `ghcr.io/hmiranda14/neuru-sentinel:latest` (amd64 + arm64 / Raspberry Pi).
Free — NEURU open-core (only AI usage is ever billed).

> Note: the sensor is **optional**. SPECTRE + NetFlow correlation already protect you
> from the NEURU server itself; the sensor adds DNS-level visibility where you don't
> route DNS through Pi-hole/AdGuard.
