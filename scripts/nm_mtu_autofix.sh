#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# NEURU — automatic tunnel-MTU self-heal (surgical, per-route). No opt-in, no host cron.
#
# Docker NAT defeats Path-MTU-Discovery: when a monitored subnet is reached over a VPN/
# WireGuard tunnel (path MTU < 1500), the container keeps emitting 1500-byte DF frames that
# silently blackhole → phantom packet loss / SSH·SNMP·HTTP probe hangs / false-down / bogus
# Smokeping loss. This script PROVES the blackhole per subnet (a full-size DF ping fails while
# a 1280-byte DF ping passes) and clamps ONLY those routes to MTU 1280. LAN subnets pass the
# big-DF probe → never touched (no throughput regression); wg0 (1420) over eth0 (1500) stays
# healthy. Idempotent + safe to run every boot / on a loop.
#
# Needs NET_ADMIN to write routes → runs in the wg sidecar (shares the web netns, has the cap)
# and/or the web entrypoint where the cap is granted. Without the cap it logs once and no-ops.
# Reads candidate "<probe_ip> <cidr>" lines (one representative host per monitored /24), written
# by the web side. Tools: ip(iproute2) + ping(iputils, needs -M do). Pure POSIX sh / busybox-ok.
# ─────────────────────────────────────────────────────────────────────────────
set -u
TARGETS="${1:-/config/nm_mtu_targets}"
CLAMP="${NEURU_MTU_CLAMP:-1280}"
BIGPAY=1472                       # 1500-byte frame (payload = 1500 - 28 IP/ICMP)
SMALLPAY=$(( CLAMP - 28 ))        # clamped-size frame (1280 → 1252)
LOG="[mtu-autofix]"

[ -r "$TARGETS" ] || exit 0
IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
GW=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
[ -n "$IFACE" ] && [ -n "$GW" ] || { echo "$LOG no default route yet"; exit 0; }

changed=0
while read -r PROBE CIDR _rest; do
    case "$PROBE" in ''|\#*) continue ;; esac
    [ -n "$CIDR" ] || continue
    # already clamped correctly → nothing to do (idempotent)
    if ip route show "$CIDR" 2>/dev/null | grep -q "mtu $CLAMP"; then continue; fi
    # host must answer at all (never clamp a genuinely-down host)
    ping -c1 -W2 "$PROBE" >/dev/null 2>&1 || continue
    # THE test: a full-size DF frame must FAIL and a clamped-size DF frame must PASS.
    #   big-DF passes      → path MTU is fine, not our problem  → skip
    #   small-DF also fails → real loss (not an MTU blackhole)  → skip (don't mask a real outage)
    ping -M do -s "$BIGPAY"   -c1 -W2 "$PROBE" >/dev/null 2>&1 && continue
    ping -M do -s "$SMALLPAY" -c1 -W2 "$PROBE" >/dev/null 2>&1 || continue
    # confirmed MTU blackhole → surgical per-route clamp
    if ip route replace "$CIDR" via "$GW" dev "$IFACE" mtu "$CLAMP" 2>/dev/null; then
        echo "$LOG clamped $CIDR via $GW dev $IFACE mtu $CLAMP (probe $PROBE: 1500-DF blackholed, ${CLAMP}-DF ok)"
        changed=1
    else
        echo "$LOG WARN: cannot set route MTU on $CIDR (needs NET_ADMIN) — skipping"
        exit 0
    fi
done < "$TARGETS"
[ "$changed" = 1 ] && ip route flush cache 2>/dev/null || true
exit 0
