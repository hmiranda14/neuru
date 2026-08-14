# NEURU Sentinel — wire threat sensor. Passive DNS + IP-reputation capture; reports
# hits to NEURU (which blocks via Collective Immunity). Multi-arch (amd64 + arm64).
FROM python:3.12-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpcap0.8 tcpdump ca-certificates \
 && pip install --no-cache-dir scapy \
 && rm -rf /var/lib/apt/lists/*
COPY sentinel-agent.py /opt/neuru/sentinel-agent.py
RUN chmod +x /opt/neuru/sentinel-agent.py
# host networking + NET_ADMIN/NET_RAW required for capture (see compose)
ENTRYPOINT ["python3", "/opt/neuru/sentinel-agent.py"]
