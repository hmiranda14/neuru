# NEURU-in-a-Box

The **entire NEURU platform in ONE container** — Apache + PHP 8.3 + an embedded **MariaDB**
+ the Python pollers + cron. It self-initializes the database and imports the schema on first
boot, so a single `docker run` (or a MikroTik `/container`) gives you a working NEURU: login,
monitoring, IPAM, switches, utilities, sentinel — everything. **n8n stays external/hosted**
(AI Flows ride the hosted proxy). Multi-arch (amd64 + arm64 / Raspberry Pi).

## Deploy
- **From another NEURU (easiest):** Containers → deploy the **NEURU** template to a Docker host
  (Pi/Ubuntu) or a **MikroTik x86 CHR** — with a live progress banner + an optional "federate to
  this NEURU" checkbox.
- **Manually:**
  ```sh
  curl -O https://raw.githubusercontent.com/hmiranda14/neuru/main/scripts/neuru-box/docker-compose.yml
  docker compose up -d          # first boot ~1-2 min (DB init + schema import)
  # then open http://<host>/  (admin / the NEURU_ADMIN_PASS you set)
  ```
Readiness: `GET /ready.php` returns 200 when Apache + DB + schema are all up.

## Federation (optional)
A **standalone** install is NOT federated. When **deployed from another NEURU**, it auto-enrols as
a **Federation slave** of that NEURU by default (opt-out in the deploy modal).

## MikroTik (x86 CHR only)
NEURU is resource-heavy → **x86 CHR only** (RouterOS 7.4+, container package, storage). The
`/container` install instructions live in the Portal Downloads section. Free — NEURU open-core.
