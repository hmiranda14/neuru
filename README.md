<p align="center">
  <h1 align="center">NEURU — Neural Network Monitor</h1>
  <p align="center"><b>A futuristic, self-hosted NOC & network-monitoring portal.</b><br>
  Free. Open source. Yours to run.</p>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-8bf3ff.svg"></a>
  <img alt="Free forever" src="https://img.shields.io/badge/price-free%20forever-2ee6a0.svg">
  <a href="https://neurunetpr.com"><img alt="Get your free license" src="https://img.shields.io/badge/free%20license-neurunetpr.com-4da3ff.svg"></a>
</p>

> **100% free & open source.** Run the entire platform on your own hardware with **unlimited nodes,
> forever**. Create a free account at **[neurunetpr.com](https://neurunetpr.com)** to get your license
> (and, optionally, hosted AI). The only thing ever metered is **AI usage** — and you can self-host
> that too with your own key.

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
# 1) grab the free installer from https://neurunetpr.com (or clone this repo)
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

## 📄 License & pricing

NEURU is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — see
[`LICENSE`](LICENSE). It is **free to use, study, modify and share**. If you run a modified version as
a network service, you must make your source available to its users.

**Pricing is simple — the platform is free, forever:**

| | |
|---|---|
| **NEURU Core** | Free · open source · **unlimited nodes** · no expiration · 10 activations · any OS |
| **NEURU AI Flows** *(optional)* | Pay only for AI usage (metered per token) — or **bring your own key** (OpenAI / Claude / Ollama) and pay nothing |

👉 **Get your free license** by creating an account at **[neurunetpr.com](https://neurunetpr.com)**
(you can also download the installers there), then paste the key into **Site Configuration → Licensing**.
Or just clone this repo and run it directly.

## 🤝 Contributing

Issues and PRs welcome. Please don't commit secrets — the `.gitignore` already excludes real config,
keys and per-install state; use the `.tpl` templates.

---

<sub>NEURU is provided as-is, with no warranty. Built for operators who want a beautiful NOC they fully own.</sub>
