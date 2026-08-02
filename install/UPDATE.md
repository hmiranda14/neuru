# NEURU — Update the remote server to the current release

This brings an existing NEURU install (the one exported ~**2025-07-01**, 114 tables) up to the
**current** build (125 tables + many new modules). It's designed to be **safe and idempotent** —
you can re-run the DB step any number of times, and it never touches your operational data or secrets.

> The whole update is two things: **(1) copy the new app files**, **(2) run the schema updater**.
> NEURU self-creates its tables, so the DB step is almost entirely automatic.

---

## What's new since v1 (highlights)
- **MikroTik Firewall Control** + **3D Packet Tracer** (`mtfw.php`, `mtfw_trace.php`)
- **Router / Routing Command Centers** (`router_command.php`, `routing_command.php`)
- **WireGuard Orchestrator + IPAM** (`wireguard.php`, `ipam.php`)
- **Net Tools**: Live Ping, Traceroute map, Netstat, NS Lookup, **Port Scanner** (`portscan.php`)
- **Service Biosphere**, **DB Observatory**, **Router details**, **User profile**, and many fixes
- **Performance**: critical indexes on `nm_device_stats` (30s → 0.4s renders) + `session_write_close`
- New DB tables: `nm_bio_*`, `nm_mtfw_pending/snapshots`, `nm_routing_snapshots`, `nm_dbobs_cache`,
  `nm_ai_heal_link`; new columns + **new RBAC permissions** for every new module.

---

## 0) Back up first (always)
```bash
# on the remote host
docker exec <db-container> mysqldump -usisuser -psispass netmon > netmon-backup-$(date +%F).sql
cp -a /path/to/netmon /path/to/netmon.bak-$(date +%F)      # the app bind-mount
```

## 1) Copy the new app files
Nearly every file changed, so **sync the whole app directory** — it's the bind-mount, so the running
container picks the new code up immediately. **Exclude the per-install and runtime files** below.

```bash
rsync -av --delete \
  --exclude '.nm_secret.key' \      # per-install encryption key — NEVER overwrite (saved secrets become undecryptable)
  --exclude 'uploads/' \            # user-uploaded photos/media on the remote
  --exclude 'logs/' \
  --exclude '_diag_*.php' \         # dev-only diagnostics
  --exclude '*.bak*' \
  ./netmon/ user@remote:/path/to/netmon/
```
- `connection.php` uses the standard kit creds (`db` / `sisuser` / `sispass`) — safe to sync **unless
  you customized DB creds on the remote** (if so, add `--exclude 'connection.php'`).
- A precise list of what changed is in **`install/UPDATE_MANIFEST.txt`** (210 files) if you'd rather
  copy surgically.

## 2) Update the database (idempotent)
Run the updater — it runs every module's self-ensure (`CREATE TABLE IF NOT EXISTS` + guarded
`ALTER`s + default RBAC/config seeds) and adds the performance indexes. **Pick either:**

- **Browser (recommended)** — log in as admin, then open:
  `https://<remote>/install/apply_updates.php`
  You'll get a report (tables before→after, modules ensured, indexes).

- **CLI:**
  ```bash
  docker exec -w /var/www/html/netmon <web-container> php install/apply_updates.php
  ```

Re-run it any time; it only adds what's missing.

> **Why this matters even though tables self-create:** the exported `role_profiles` seed is from v1,
> so the **new module permissions** (mtfw, port scanner, WireGuard, IPAM, routing centers, …) only
> get seeded by this pass. Without it, an admin on the old DB won't see the new menu items.

## 3) Restart the Python daemons
Cron-driven collectors pick up new code automatically on their next tick. **Long-running daemons**
must be restarted so they run the new code (and re-ensure their schema):
```
scripts/nm_poller.py   scripts/nm_syslog.py   scripts/nm_netflow.py   scripts/nm_ping.py
scripts/nm_health.py   scripts/nm_discovery.py   scripts/nm_db_config.py   scripts/nm_ssh_fetch.py
```
Restart them however you run them (systemd unit, supervisor, `docker compose restart`, or kill+relaunch).
`nm_poller.py` now also creates the two `nm_device_stats` perf indexes on boot (harmless if present).

## 4) Verify
- `https://<remote>/install/apply_updates.php` → **0 failed**, tables at **125**.
- Log in → the new menu items appear (Device Tools → MikroTik Firewall; Net Tools → Port Scanner; etc.).
- Open a heavy page (e.g. **net_mon.php**) — it should render in well under a second.

---

## Fresh installs
`setup.php` now runs this same updater automatically right after importing `neuru-install.sql`
(which itself now contains all 125 tables), so a brand-new install is complete and fully permissioned
out of the box. Nothing extra to do.

## Rollback
- App files: restore the `netmon.bak-*` copy.
- Database: the updater is additive (new tables/columns/indexes/seeds); it removes nothing. If needed,
  restore `netmon-backup-*.sql`.
