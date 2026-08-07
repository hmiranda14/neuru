# neuru-agent — featherweight remote collector for NEURU
# Pure Python 3 stdlib (no pip deps) → tiny image (~50 MB).
FROM python:3.12-alpine

LABEL org.opencontainers.image.title="neuru-agent" \
      org.opencontainers.image.description="Featherweight push-based metrics agent for NEURU" \
      org.opencontainers.image.source="https://github.com/hmiranda14/neuru" \
      org.opencontainers.image.licenses="AGPL-3.0"

# non-root; still reads host /proc,/sys via the read-only bind mounts
RUN adduser -D -H -u 10001 neuru
COPY agent.py /app/agent.py
WORKDIR /app

ENV HOST_PROC=/host/proc \
    HOST_SYS=/host/sys \
    HOST_ROOT=/host/root \
    NEURU_INTERVAL=30 \
    PYTHONUNBUFFERED=1

USER neuru
ENTRYPOINT ["python3", "/app/agent.py"]
