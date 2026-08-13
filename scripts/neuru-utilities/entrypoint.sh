#!/bin/sh
# NEURU Utilities entrypoint — prep dirs/keys, then hand off to supervisord (which
# runs the control agent; the agent brings up the enabled services).
set -e

mkdir -p /var/log/neuru-util/remote /srv/neuru-utils/tftp /srv/neuru-utils/firmware \
         /srv/neuru-utils/backups /srv/neuru-utils/images /srv/neuru-utils/ztp \
         /etc/supervisor/conf.d /var/lib/neuru-util-agent /run/sshd

# SSH host keys (SFTP service reuses these)
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A >/dev/null 2>&1 || true

if [ -z "$NEURU_URL" ] || [ -z "$UTIL_TOKEN" ]; then
  echo "[entrypoint] WARNING: NEURU_URL and UTIL_TOKEN must be set — the agent won't enrol without them."
fi
echo "[entrypoint] neuru-utilities starting (NEURU_URL=${NEURU_URL:-unset})"

exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
