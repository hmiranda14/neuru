#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# NEURU — AUTO-APPLY watcher. Runs as ROOT via /etc/cron.d/neuru-apply every minute.
#
# When the Updates page stages + verifies a build it can't apply itself (the web
# user can't write the bind-mounted app dir), it drops `updates/PENDING`. We apply
# it here as root — so an update NEVER needs a manual `docker exec` step. The user
# just clicks "Apply update" and it happens.
#
# No-loop / no-double-apply: we CLAIM the marker (rename) before applying. On success
# the marker is cleared; on failure it's left as `.failed` (visible, won't re-loop).
# ─────────────────────────────────────────────────────────────────────────────
APP=/var/www/html/netmon
UPD="$APP/updates"
FLAG="$UPD/PENDING"
LOG="$UPD/auto-apply.log"

[ -f "$FLAG" ] || exit 0
# claim it so the next tick (or a concurrent run) doesn't apply twice
mv "$FLAG" "$FLAG.running" 2>/dev/null || exit 0

{
  echo "==== $(date) — auto-apply start ===="
  if bash "$APP/scripts/nm_apply_update.sh"; then
    echo "$(date) — auto-apply OK"
    rm -f "$FLAG.running"
    # sync the DB flags + history so the UI reflects the applied state (best-effort)
    php -r 'chdir("/var/www/html/netmon"); require "connection.php"; require "nm_update.php";
            $old=@file_get_contents("VERSION"); nm_update_set($conn,"update_staged","");
            nm_update_set($conn,"update_pending",""); if(function_exists("opcache_reset")) @opcache_reset();' 2>/dev/null || true
  else
    echo "$(date) — auto-apply FAILED (see log above) — marker kept as .failed"
    mv "$FLAG.running" "$FLAG.failed" 2>/dev/null || true
  fi
} >> "$LOG" 2>&1
