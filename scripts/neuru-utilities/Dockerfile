# NEURU Utilities — one container, supervisord + util-agent, running the whole
# rescue/provisioning service stack. All services are configured CENTRALLY from
# NEURU (the agent pulls desired-state and reconciles). Multi-arch (amd64 + arm64).
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      supervisor python3 ca-certificates curl \
      tftpd-hpa openssh-server vsftpd nginx-light chrony iperf3 rsyslog \
      dnsmasq openssl procps iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/log/neuru-util /srv/neuru-utils/tftp /srv/neuru-utils/firmware \
             /srv/neuru-utils/backups /srv/neuru-utils/images /srv/neuru-utils/ztp \
             /var/lib/neuru-util-agent /etc/supervisor/conf.d /run/sshd

# File Browser (self-hosted web file manager) — arch-aware install
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) fb=linux-amd64;; arm64) fb=linux-arm64;; armhf) fb=linux-armv7;; *) fb=linux-amd64;; esac; \
    curl -fsSL "https://github.com/filebrowser/filebrowser/releases/latest/download/${fb}-filebrowser.tar.gz" \
      -o /tmp/fb.tar.gz || true; \
    if [ -s /tmp/fb.tar.gz ]; then tar -xzf /tmp/fb.tar.gz -C /usr/local/bin filebrowser && chmod +x /usr/local/bin/filebrowser; fi; \
    rm -f /tmp/fb.tar.gz

# dnsmasq ships enabled as a system service — we manage it via supervisord instead
RUN systemctl disable dnsmasq 2>/dev/null || true; rm -f /etc/dnsmasq.d/* 2>/dev/null || true

COPY util-agent.py /opt/neuru/util-agent.py
COPY util-listeners.py /opt/neuru/util-listeners.py
COPY supervisord.conf /etc/supervisor/supervisord.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /opt/neuru/util-agent.py /opt/neuru/util-listeners.py

# host networking is expected (TFTP/NTP/DHCP/syslog need real ports); ports listed for docs
EXPOSE 69/udp 123/udp 514/udp 2222/tcp 21/tcp 8080/tcp 8088/tcp 5201/tcp

ENTRYPOINT ["/entrypoint.sh"]
