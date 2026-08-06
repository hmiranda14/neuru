#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# NEURU container entrypoint — starts every background service so the stack comes
# up identically after a restart OR a rebuild. Lives in the bind-mounted app dir
# (./netmon) so it persists; referenced from the Dockerfile CMD.
# ─────────────────────────────────────────────────────────────────────────────
set +e

VENV=/opt/netmon-venv/bin/python3
APP=/var/www/html/netmon
# NEURU home user: server installs use 'hmiranda'; the Raspberry Pi edition uses 'neuru'.
# Auto-detect by which existing account's home holds netmon.cron (fall back to hmiranda),
# so this ONE entrypoint installs the crontab correctly on both. (Pi bug fix: the old
# hardcoded /home/hmiranda path didn't exist on the Pi → crontab never installed → no poller.)
NEURU_USER=hmiranda
for _u in hmiranda neuru; do
    if id "$_u" >/dev/null 2>&1 && [ -f "/home/$_u/netmon.cron" ]; then NEURU_USER="$_u"; break; fi
done
NEURU_HOME="/home/$NEURU_USER"
LOGS="$NEURU_HOME/netmon-logs"
mkdir -p "$LOGS" 2>/dev/null
chown "$NEURU_USER:$NEURU_USER" "$LOGS" 2>/dev/null

# 0a) SECRET KEY persistence: encrypted settings (Portainer/SSH/Pi-hole/Telegram tokens…) are
#     keyed by $APP/.nm_secret.key. If www-data can't persist it, every request gets a different
#     in-memory key → a saved secret "disappears" (can't be decrypted next request). Create it once
#     and make it readable by the web user so secrets survive requests AND restarts.
KEYF="$APP/.nm_secret.key"
[ -s "$KEYF" ] || { head -c32 /dev/urandom | base64 > "$KEYF" && echo "[entrypoint] generated .nm_secret.key"; }
chown www-data:www-data "$KEYF" 2>/dev/null; chmod 644 "$KEYF" 2>/dev/null

# 0a0) DB CONNECTION files ($conn + $conn2). The app requires $APP/connection.php (main DB) and
#      $APP/connection-users.php (a 2nd handle used by auth/audit). setup.php connects to the DB via
#      env and imports the schema — but NOTHING writes these files, and the bind-mounted app dir is
#      host-owned (not www-data) so PHP couldn't write them anyway. Result on a FRESH install: the
#      files never exist → $conn/$conn2 are null → EVERY authenticated page 500s right after login
#      ("Call to a member function prepare() on null"). We (root) generate them from the shipped .tpl
#      templates on boot, filling DB params from env (defaults match the compose "db" service). An
#      existing/custom connection.php is never overwritten.
NM_DB_HOST="${NM_DB_HOST:-db}"; NM_DB_NAME="${NM_DB_NAME:-netmon}"
NM_DB_USER="${NM_DB_USER:-sisuser}"; NM_DB_PASS="${NM_DB_PASS:-sispass}"
for _cf in connection connection-users; do
    _tpl="$APP/${_cf}.php.tpl"; _dst="$APP/${_cf}.php"
    if [ ! -s "$_dst" ] && [ -f "$_tpl" ]; then
        sed -e "s|__DB_HOST__|${NM_DB_HOST}|g" -e "s|__DB_NAME__|${NM_DB_NAME}|g" \
            -e "s|__DB_USER__|${NM_DB_USER}|g" -e "s|__DB_PASS__|${NM_DB_PASS}|g" "$_tpl" > "$_dst" \
            && echo "[entrypoint] generated ${_cf}.php from template (host=$NM_DB_HOST db=$NM_DB_NAME)"
    fi
    # Group-own by the CRON user ($NEURU_USER) so scheduled jobs can READ it. The crons run via
    # nm_cron.sh → nm_inbound_token.php → `require connection.php` AS $NEURU_USER (e.g. 'neuru' in
    # Docker). With the old www-data:www-data 640, that user — neither the owner nor in the www-data
    # group — hit "Permission denied" on connection.php, so the token resolver fatally errored,
    # nm_cron.sh got an empty token and `exit 0`-skipped EVERY tick → ALL background crons silently
    # dead on Docker installs (the web kept working because Apache runs as www-data). www-data still
    # OWNS it so Apache reads/writes; group=$NEURU_USER lets the cron user read; 640 keeps the DB
    # password off world-read. Runs every boot → self-heals existing installs on restart.
    chown "www-data:${NEURU_USER}" "$_dst" 2>/dev/null; chmod 640 "$_dst" 2>/dev/null
done

# 0a1) BOOT MARKER — record THIS container-boot time. The Updates page compares it to the last
#      'applied' update time: if an update was applied AFTER the last boot, the container still needs
#      a restart (so this entrypoint re-runs its self-heal AND the WireGuard sidecar reconnects the
#      tunnel that NEURU Flows ride on). A newer boot time here makes that "restart required" banner
#      clear itself — no manual dismissal.
if [ -f "$APP/connection.php" ]; then
    php -r 'require "'"$APP"'/connection.php"; $k="entrypoint_booted_at"; $t=date("c");
        $s=$conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES (?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
        if ($s) { $s->bind_param("ss",$k,$t); @$s->execute(); }' 2>/dev/null || true
fi

# 0a2) LICENSE FINGERPRINT persistence: the license binds to a machine fingerprint. In Docker the
#      raw signals (machine-id/MAC/hostname) change on every container recreate, which would flip
#      the fingerprint and de-activate a valid license. We freeze it in $APP/.nm_install_id. Ensure
#      the file exists and is www-data-writable so PHP can seed it (from the last portal-known
#      fingerprint, or machine-derived on a fresh box) and it then stays stable across recreates.
IDF="$APP/.nm_install_id"
[ -e "$IDF" ] || { : > "$IDF" && echo "[entrypoint] created .nm_install_id (empty — PHP will seed)"; }
chown www-data:www-data "$IDF" 2>/dev/null; chmod 644 "$IDF" 2>/dev/null

# 0b) WRITABLE STATE DIRS for the web user. The app dir is a bind-mount NOT owned by
#     www-data, so dirs shipped read-only (mode 755, host-owned) can't be written by PHP.
#     uploads = user images; updates/{staging,backups} = the self-updater's download+apply
#     area. Without this, "Download & verify" fails with "cannot write staging file".
for d in "$APP/uploads" "$APP/updates" "$APP/updates/staging" "$APP/updates/backups" "$APP/wg"; do
    mkdir -p "$d" 2>/dev/null
done
mkdir -p "$APP/backups" 2>/dev/null
chown -R www-data:www-data "$APP/uploads" "$APP/updates" "$APP/wg" "$APP/backups" 2>/dev/null
chmod -R 775 "$APP/uploads" "$APP/updates" 2>/dev/null
# wg/ holds the WireGuard client config (private key) → never web-serve it, tighter perms
[ -f "$APP/wg/.htaccess" ] || printf 'Require all denied\nDeny from all\n' > "$APP/wg/.htaccess" 2>/dev/null
chmod 750 "$APP/wg" 2>/dev/null
echo "[entrypoint] writable state dirs ensured (uploads, updates, wg)"

# 0a3) TUNNEL-MTU CLAMP (opt-in). When NEURU reaches monitored nodes over a VPN/WireGuard link,
#      the path MTU is < 1500 and Docker's NAT breaks PMTU-Discovery (the tunnel's ICMP
#      "fragmentation-needed" can't get back to the container) → 1500-byte DF packets silently
#      blackhole and SSH/SNMP/HTTP probes hang ("weird errors", false-down). Set NEURU_IF_MTU
#      (e.g. 1280, the IPv6 minimum, or 1400) to clamp the default interface + TCP MSS so probes
#      fit the tunnel. UNSET or >=1500 → no change (default; local-LAN installs are untouched).
#      Needs CAP_NET_ADMIN — already present wherever wg0 is used.
if [ -n "${NEURU_IF_MTU:-}" ] && [ "${NEURU_IF_MTU}" -ge 576 ] 2>/dev/null && [ "${NEURU_IF_MTU}" -lt 1500 ] 2>/dev/null; then
    IFACE="$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')"; IFACE="${IFACE:-eth0}"
    if ip link set dev "$IFACE" mtu "$NEURU_IF_MTU" 2>/dev/null; then
        echo "[entrypoint] tunnel-MTU clamp: $IFACE MTU=$NEURU_IF_MTU"
        # CRITICAL (universal): a WireGuard/VPN overlay (wg0 for hosted flows, tun/tap) rides OVER $IFACE
        # with ~60-80B encapsulation overhead. If its MTU stays LARGER than $IFACE, its packets exceed
        # $IFACE once encapsulated and blackhole → the hosted-flows tunnel (n8n/kb-ingest/smokeping) dies.
        # So clamp every overlay to NEURU_IF_MTU-80 too. (wg brought up LATER inherits the right MTU from
        # wg-quick's route-based auto-MTU, since $IFACE is already clamped.)
        WGMTU=$((NEURU_IF_MTU - 80))
        for OVL in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E '^(wg|tun|tap)[0-9]' || true); do
            ip link set dev "$OVL" mtu "$WGMTU" 2>/dev/null && echo "[entrypoint] tunnel-MTU clamp: $OVL MTU=$WGMTU (VPN overlay)"
        done
        MSS=$((NEURU_IF_MTU - 40))   # belt-and-suspenders: also clamp TCP SYN MSS so TCP segments fit
        iptables -t mangle -C OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS" 2>/dev/null \
          || iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS" 2>/dev/null \
          && echo "[entrypoint] tunnel-MTU clamp: TCP MSS=$MSS"
    else
        echo "[entrypoint] WARN: could not set MTU on $IFACE (needs CAP_NET_ADMIN)"
    fi
fi

# 0a4) AUTOMATIC tunnel-MTU self-heal (zero-config, surgical per-route — the definitive fix).
#      Independent of the NEURU_IF_MTU opt-in above and SAFE BY DEFAULT: NEURU probes each monitored
#      PRIVATE subnet and clamps to 1280 ONLY the ones that provably blackhole a full-size DF frame
#      over a tunnel (a pure-LAN subnet passes the probe → never touched → no throughput hit; wg0
#      stays healthy). The web side seeds candidate "<repIP> <cidr>" pairs here; the clamp is applied
#      by whoever holds CAP_NET_ADMIN — this container if granted, else the wg sidecar (shares this
#      netns + has the cap, runs it every loop). No opt-in, no host cron, reboot-safe.
if [ -f /var/www/html/netmon/connection.php ]; then
    php -r '
        require "/var/www/html/netmon/connection.php";
        $seen=[]; $out="";
        if ($r=@$conn->query("SELECT ip_address FROM nm_nodes WHERE ip_address<>\"\"")) {
            while ($x=$r->fetch_assoc()) { $ip=$x["ip_address"];
                if (!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)) continue;
                if (!(preg_match("/^10\\./",$ip)||preg_match("/^192\\.168\\./",$ip)||preg_match("/^172\\.(1[6-9]|2[0-9]|3[01])\\./",$ip))) continue; // RFC1918 only
                $p=explode(".",$ip); $c=$p[0].".".$p[1].".".$p[2].".0/24"; if(isset($seen[$c]))continue; $seen[$c]=1; $out.=$ip." ".$c."\n";
            }
        }
        @file_put_contents("/var/www/html/netmon/wg/nm_mtu_targets",$out);
    ' 2>/dev/null && echo "[entrypoint] mtu-autofix: seeded candidate targets"
    sh /var/www/html/netmon/scripts/nm_mtu_autofix.sh /var/www/html/netmon/wg/nm_mtu_targets 2>/dev/null || true
fi

# 0) CRITICAL Docker cron fix: pam_loginuid is 'required' but fails in containers
#    (no audit subsystem) → cron silently runs NO jobs. Make it optional.
sed -i '/pam_loginuid\.so/ s/required/optional/' /etc/pam.d/cron 2>/dev/null \
    && echo "[entrypoint] pam_loginuid fix applied"

# 0c) Cron wrapper — resolves the inbound token at RUNTIME so no <YOUR_CRON_TOKEN>
#     placeholder ever needs filling (the historical "all crons silently 401" footgun).
chmod +x "$APP/scripts/nm_cron.sh" 2>/dev/null
( php "$APP/scripts/nm_inbound_token.php" >/dev/null 2>&1 ) &   # best-effort seed once the DB is up

# 1) Install the NEURU crontab (user auto-detected above). MIGRATE any legacy "curl -H
#    X-NetMon-Token: <...> http://localhost/X.php" line to the runtime-token wrapper, so
#    EXISTING installs self-heal on restart (dead crons behind a placeholder token can't survive a boot).
CRONF="$NEURU_HOME/netmon.cron"
if [ -f "$CRONF" ]; then
    sed -i -E 's#curl -s -H "X-NetMon-Token: [^"]*" http://localhost/([a-z_]+\.php)#'"$APP"'/scripts/nm_cron.sh \1#g' "$CRONF"
    # self-heal: ensure background monitor crons that shipped in later versions exist
    #  (GPU/AI, Windows, Linux) — old persisted cron files never had them, so add if missing.
    ensure_cron(){ grep -q "$1" "$CRONF" || echo "$2 $APP/scripts/nm_cron.sh $1 >/dev/null 2>&1" >> "$CRONF"; }
    ensure_cron cron_gpu.php       "*/2 * * * *"
    ensure_cron cron_winhost.php   "*/5 * * * *"
    ensure_cron cron_linuxhost.php "*/5 * * * *"
    ensure_cron cron_cisco.php     "*/5 * * * *"
    ensure_cron cron_notify.php    "*/5 * * * *"
    ensure_cron cron_container_logs.php "*/5 * * * *"
    ensure_cron cron_autopilotv2.php "* * * * *"
    ensure_cron cron_biosphere.php  "* * * * *"
    ensure_cron cron_cluster.php    "* * * * *"
    ensure_cron cron_netdoc.php     "*/10 * * * *"
    ensure_cron cron_wearlife.php   "*/10 * * * *"
    ensure_cron cron_deck.php       "* * * * *"
    ensure_cron cron_vault.php      "0 * * * *"
    ensure_cron cron_update.php     "23 4 * * *"
    ensure_cron cron_license.php    "17 */6 * * *"
    crontab -u "$NEURU_USER" "$CRONF" && echo "[entrypoint] crontab installed for $NEURU_USER (runtime-token wrapper)"
fi

# 1b) AUTO-APPLY watcher — a ROOT cron that applies a staged update the web user can't apply
#     itself (bind-mount app dir is host-owned). This makes updates FULLY hands-off: the user
#     clicks "Apply update" and a root job finishes the job within a minute — no manual
#     `docker exec … nm_apply_update.sh` ever. cron.d entries run as the user named in column 6.
if [ -f "$APP/scripts/nm_apply_watch.sh" ]; then
    chmod +x "$APP/scripts/nm_apply_watch.sh" 2>/dev/null
    printf '* * * * * root %s/scripts/nm_apply_watch.sh >/dev/null 2>&1\n' "$APP" > /etc/cron.d/neuru-apply
    chmod 0644 /etc/cron.d/neuru-apply 2>/dev/null
    echo "[entrypoint] auto-apply watcher installed (/etc/cron.d/neuru-apply)"
fi
service cron start  && echo "[entrypoint] cron started"
service ssh  start  && echo "[entrypoint] ssh started"

# 2) NEURU syslog server (root → can bind 514). Restarts if it ever dies.
if [ -x "$VENV" ]; then
    ( while true; do
        "$VENV" "$APP/scripts/nm_syslog.py" >> "$LOGS/nm_syslog.log" 2>&1
        echo "[entrypoint] nm_syslog exited, restarting in 5s" >> "$LOGS/nm_syslog.log"
        sleep 5
      done ) &
    echo "[entrypoint] nm_syslog server started"

    # 2b) NEURU NetFlow/IPFIX collector (udp/2055 by default). Restarts if it dies.
    ( while true; do
        "$VENV" "$APP/scripts/nm_netflow.py" >> "$LOGS/nm_netflow.log" 2>&1
        echo "[entrypoint] nm_netflow exited, restarting in 5s" >> "$LOGS/nm_netflow.log"
        sleep 5
      done ) &
    echo "[entrypoint] nm_netflow collector started"
else
    echo "[entrypoint] WARNING: $VENV missing — pollers/syslog/netflow disabled (rebuild Dockerfile with the venv)"
fi

# 2c) HTTPS/TLS — self-signed vhost on :443 so the browser has a SECURE CONTEXT
#     (required for the AI Commander voice add-on: getUserMedia/mic only works over
#     HTTPS or localhost). Recreate-safe: cert persists in $APP/.nm_tls, vhost is
#     re-written here each boot. No-op if openssl is missing. :80 keeps working.
if [ -f "$APP/scripts/nm_https_setup.sh" ]; then
    sh "$APP/scripts/nm_https_setup.sh" || echo "[entrypoint] WARNING: HTTPS setup failed (voice needs HTTPS)"
fi

# 3) Apache in the foreground keeps the container alive.
echo "[entrypoint] starting apache (foreground)"
exec apachectl -D FOREGROUND
