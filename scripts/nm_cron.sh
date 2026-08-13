#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# NEURU — cron wrapper. Resolves the inbound token from the DB AT CALL TIME and
# hits the given endpoint over localhost. This removes the <YOUR_CRON_TOKEN>
# placeholder footgun entirely: the token is always current (survives Rotate), a
# fresh install auto-seeds it, and no crontab editing is ever needed.
#
#   crontab:  * * * * * /var/www/html/netmon/scripts/nm_cron.sh cron_cluster.php
# ─────────────────────────────────────────────────────────────────────────────
APP=/var/www/html/netmon
EP="$1"
[ -n "$EP" ] || { echo "usage: nm_cron.sh <endpoint.php>"; exit 2; }
# basename-guard the endpoint (no path traversal / absolute URLs)
EP=$(basename "$EP")
TOK=$(php "$APP/scripts/nm_inbound_token.php" 2>/dev/null)
[ -n "$TOK" ] || exit 0   # no token yet (DB not ready) → skip this tick, try next minute
# Scheduled-Jobs gate (net_mon_config -> Scheduled Jobs): skip ONLY on an explicit "skip"
# (disabled or throttled in nm_job_schedule). Any other result (run/empty/error) -> run = FAIL-OPEN.
GATE=$(curl -s -m 8 -H "X-NetMon-Token: $TOK" "http://localhost/nm_job_gate.php?job=$EP" 2>/dev/null)
[ "$GATE" = "skip" ] && exit 0
curl -s -H "X-NetMon-Token: $TOK" "http://localhost/$EP" >/dev/null 2>&1
