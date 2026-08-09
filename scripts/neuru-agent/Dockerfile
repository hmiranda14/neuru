# neuru-agent — featherweight remote collector for NEURU
# Pure Python 3 stdlib (no pip deps) → tiny image (~50 MB).
FROM python:3.12-alpine

LABEL org.opencontainers.image.title="neuru-agent" \
      org.opencontainers.image.description="Featherweight push-based metrics agent for NEURU" \
      org.opencontainers.image.source="https://github.com/hmiranda14/neuru" \
      org.opencontainers.image.licenses="AGPL-3.0"

COPY agent.py /app/agent.py
WORKDIR /app

ENV HOST_PROC=/host/proc \
    HOST_SYS=/host/sys \
    HOST_ROOT=/host/root \
    NEURU_INTERVAL=30 \
    PYTHONUNBUFFERED=1

# Runs as root — required to read the host mount table (/host/proc/1/mounts) and the
# Docker socket (root:docker). Standard for host-metrics agents (node_exporter, cAdvisor,
# datadog-agent). All host mounts are read-only; the agent only makes outbound requests.
ENTRYPOINT ["python3", "/app/agent.py"]
