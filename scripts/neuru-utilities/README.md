# NEURU Utilities

A one-container **stack of rescue & provisioning servers** you deploy next to your
network — **TFTP, SFTP, FTP/FTPS, HTTP/WebDAV firmware, NTP, iPerf3, syslog/trap
relay, File Browser** (PXE/ZTP and serial-over-IP arrive in later phases).

**The whole point: you never configure this box.** It enrols with NEURU using a
shared token, then a control agent (`util-agent.py`) **pulls the desired-state from
NEURU and reconciles** — turning each service on/off and writing its config from
what you set in **NEURU → Utilities**. NEURU is the only writer, so there is no
drift and no reason to ever SSH in.

## Deploy

1. In NEURU: **Utilities → Deploy** → copy the enrolment token.
2. On a Docker host on your network:
   ```sh
   curl -O https://raw.githubusercontent.com/hmiranda14/neuru/main/scripts/neuru-utilities/docker-compose.yml
   # edit NEURU_URL + UTIL_TOKEN
   docker compose up -d
   ```
   …or use NEURU's 1-click Portainer deploy.
3. The host appears in **NEURU → Utilities**. Flip on TFTP/SFTP/HTTP/NTP/iPerf3/…
   and set each service's options right there. Changes land within one poll (~20s).

## Why host networking

TFTP (69/udp), NTP (123/udp), syslog (514) and the upcoming PXE/DHCP-proxy need real
host ports and broadcast — Docker bridge NAT breaks them. The container is an
appliance; scope each service to your subnets in NEURU.

## Services & default ports

| Service | Port | Notes |
|---|---|---|
| File Browser | 8088/tcp | web file manager over the shared store |
| TFTP | 69/udp | firmware/config, ZTP |
| SFTP | 2222/tcp | secure backups |
| FTP/FTPS | 21/tcp | legacy gear |
| HTTP/WebDAV | 8080/tcp | firmware images |
| NTP | 123/udp | local time |
| iPerf3 | 5201/tcp | bandwidth tests |
| Syslog relay | 514/udp | forwards into NEURU |

The whole suite is **free** (NEURU open-core — only AI usage is ever billed).
Multi-arch image: `ghcr.io/hmiranda14/neuru-utilities:latest` (amd64 + arm64 / Raspberry Pi).
