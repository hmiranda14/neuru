<p align="center">
  <h1 align="center">NEURU — Neural Network Monitor</h1>
  <p align="center"><b>A futuristic, self-hosted NOC & network-monitoring portal.</b><br>
  Free. Open source. Yours to run.</p>
</p>

---

NEURU is a flat-file **PHP 8.3 + MySQL 8 + Python + n8n** monitoring platform that aims to
overpass industry-standard NMS tools while staying genuinely user-friendly. It runs entirely on
your own infrastructure in Docker — your data never leaves your network.

## ✨ Highlights

- **Agentless monitoring** over SNMP / SSH — routers (MikroTik, Cisco, …), Linux, Windows, switches, Pi-hole, databases.
- **Incident correlation & self-healing** — detect → correlate → propose/act → time-boxed auto-revert.
- **Immersive WebGL command centers** — NEURUTIK unified galaxy, Matrix Flow (IP NetFlow lasers), Traffic Hologram, DB Observatory, Service Biosphere, Routing fabric, Geo Wall.
- **AI-assisted NOC** (optional, self-hosted n8n flows) — root-cause, config manager, predictive health.
- **Collective Immunity** — block a threat once, fan it out to every Pi-hole & firewall.
- **NetFlow, Syslog, Smokeping, WireGuard/IPAM, Data Vault backups, Notification Center** — all built in.
- **RBAC**, HTTPS, timezone-correct storage, self-update, and a first-run web wizard.

## 🚀 Quick start (Docker)

```bash
# 1) grab a release installer (or clone this repo)
tar xzf neuru-installer-v<version>.tar.gz && cd neuru-installer

# 2) shared network + build + start
docker network create neuru-net
docker compose up -d --build          # first build takes a few minutes

# 3) finish in the browser wizard
#    http://<SERVER-IP>:8090/setup.php   → creates the schema + admin
```
Default login (change it immediately): `admin` / `admin@1.one`.
Raspberry Pi (ARM64): use the `neuru-installer-pi` package (`./install.sh`, one command).

## ⚙️ Configuration

Real config files hold per-install credentials and are **git-ignored**. Copy the shipped templates
and fill in your values:

```bash
cp connection.php.tpl        connection.php          # DB host/user/pass
cp connection-users.php.tpl  connection-users.php    # (if used)
cp nm_config.php.tpl         nm_config.php           # app config
```
Secrets (SSH keys, API tokens, Pi-hole/Telegram) are encrypted at rest with a per-install key
(`.nm_secret.key`, auto-generated on first boot — never commit it).

## 📄 License

**GNU Affero General Public License v3.0 (AGPL-3.0).** NEURU is free to use, study, modify and
share. If you run a modified version as a network service, you must make your source available to
its users. See [`LICENSE`](LICENSE).

## 🤝 Contributing

Issues and PRs welcome. Please don't commit secrets — the `.gitignore` already excludes real config,
keys and per-install state; use the `.tpl` templates.

---

<sub>NEURU is provided as-is, with no warranty. Built for operators who want a beautiful NOC they fully own.</sub>
