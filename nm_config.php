<?php
// NetMon server-specific paths — generated for this container

define('VENV_PYTHON',  '/opt/netmon-venv/bin/python3');
define('SCRIPTS_DIR',  '/var/www/html/netmon/scripts');
define('LOG_DIR',      '/var/www/html/netmon/logs');
define('APP_ROOT',     '/var/www/html/netmon');

// n8n integration (set via Configuration tab or edit here — Phase 1)
define('N8N_BASE_URL', '');  // e.g. http://n8n:5678
define('N8N_API_KEY',  '');  // shared secret header value

// ─── Authoritative node reachability verdict (used by the "Poll now" buttons) ──
// Returns the device's TRUE state (up | degraded | down) plus a human detail line,
// derived from the alert engine's verdict (nm_alert_state) + the latest ICMP sample
// + SNMP telemetry freshness. "degraded" = pings fine but SNMP/telemetry is stale —
// the device is reachable, only its management plane is quiet (e.g. a printer asleep).
if (!function_exists('nm_node_live_verdict')) {
    function nm_node_live_verdict($conn, int $nid): array {
        $ls = null;
        if ($q = $conn->query("SELECT last_status FROM nm_alert_state WHERE entity_type='node' AND entity_id=" . $nid . " LIMIT 1")) {
            if ($q->num_rows) $ls = $q->fetch_assoc()['last_status'];
        }
        $pingUp = null; $loss = null; $lat = null;
        if ($pq = $conn->query("SELECT is_up, packet_loss, latency_ms FROM nm_ping_stats WHERE node_id=" . $nid . " ORDER BY id DESC LIMIT 1")) {
            if ($pq->num_rows) { $pr = $pq->fetch_assoc(); $pingUp = ((int)$pr['is_up'] === 1); $loss = $pr['packet_loss']; $lat = $pr['latency_ms']; }
        }
        $age = null;
        if ($sq = $conn->query("SELECT TIMESTAMPDIFF(MINUTE, MAX(recorded_at), NOW()) a FROM nm_port_stats WHERE node_id=" . $nid)) {
            if ($sq->num_rows) { $rr = $sq->fetch_assoc(); $age = ($rr['a'] === null) ? null : (int)$rr['a']; }
        }
        $down = in_array($ls, ['down','lowerlayerdown','notpresent','testing'], true);
        $state = $down ? 'down' : ($ls === 'degraded' ? 'degraded' : 'up');
        $bits = [];
        if ($pingUp !== null) {
            $bits[] = $pingUp
                ? ('ICMP reply' . ($lat !== null ? ' ' . round((float)$lat, 1) . 'ms' : '') . (($loss !== null && (float)$loss > 0) ? ', ' . round((float)$loss) . '% loss' : ''))
                : 'no ICMP reply';
        }
        if ($age !== null) $bits[] = ($age <= 11 ? 'SNMP fresh' : 'SNMP stale ~' . $age . ' min');
        return ['state'=>$state, 'ping_up'=>$pingUp, 'snmp_age_min'=>$age, 'detail'=>implode(' · ', $bits)];
    }
}
