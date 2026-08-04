<?php
require_once __DIR__ . '/nm_config.php';
// ─── LibreNMS Config — sourced from the DB (nm_settings), loaded before includes.
//     connection.php is output-safe (no echo/redirect), so it can load this early.
date_default_timezone_set('America/Puerto_Rico');

require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/nm_lnms.php';
require_once __DIR__ . '/nm_netstats.php';   // container-network history (DB-only read for the widget)
$_lnms_cfg = nm_lnms_get($conn);
define('LIBRENMS_URL',   $_lnms_cfg['url']);
define('LIBRENMS_TOKEN', $_lnms_cfg['token']);
$librenms_enabled = (bool)$_lnms_cfg['enabled'];

// ─── Graph Debug (visit ?graph_debug=1&device=3&type=device_bits) ─────────────
// Runs BEFORE includes so check.php cannot redirect or corrupt binary output
if (isset($_GET['graph_debug'])) {
    if (!$librenms_enabled) { header('Content-Type: text/plain'); echo "LibreNMS is disabled."; exit; }
    header('Content-Type: text/plain');
    $device = max(0, intval($_GET['device'] ?? 3));
    $type   = preg_replace('/[^a-zA-Z0-9_]/', '', $_GET['type'] ?? 'device_bits');

    // Test graph.php
    $url1 = LIBRENMS_URL . '/graph.php?' . http_build_query([
        'device' => $device, 'type' => $type,
        'from' => 'end-24h', 'to' => 'now', 'width' => 400, 'height' => 100,
        'api_token' => LIBRENMS_TOKEN,
    ]);
    $ch = curl_init($url1);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>15,
        CURLOPT_HTTPHEADER=>['X-Auth-Token: '.LIBRENMS_TOKEN], CURLOPT_FOLLOWLOCATION=>true]);
    $r1 = curl_exec($ch);
    $c1 = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $ct1 = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    curl_close($ch);

    // Test API graphs endpoint
    $url2 = LIBRENMS_URL . "/api/v0/devices/{$device}/graphs/{$type}?" . http_build_query([
        'from' => 'end-24h', 'to' => 'now', 'width' => 400, 'height' => 100,
        'api_token' => LIBRENMS_TOKEN,
    ]);
    $ch = curl_init($url2);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>15,
        CURLOPT_HTTPHEADER=>['X-Auth-Token: '.LIBRENMS_TOKEN]]);
    $r2 = curl_exec($ch);
    $c2 = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $ct2 = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    curl_close($ch);

    echo "=== graph.php test ===\n";
    echo "URL: {$url1}\n";
    echo "HTTP: {$c1} | Content-Type: {$ct1}\n";
    echo "Response length: " . strlen($r1) . " bytes\n";
    echo "First 200 bytes (hex): " . bin2hex(substr($r1, 0, 200)) . "\n";
    echo "First 200 chars: " . substr($r1, 0, 200) . "\n\n";

    echo "=== API graphs endpoint test ===\n";
    echo "URL: {$url2}\n";
    echo "HTTP: {$c2} | Content-Type: {$ct2}\n";
    echo "Response length: " . strlen($r2) . " bytes\n";
    echo "First 500 chars: " . substr($r2, 0, 500) . "\n";
    exit;
}

// ─── Graph Proxy ──────────────────────────────────────────────────────────────
if (isset($_GET['graph_proxy'])) {
    if (!$librenms_enabled) {
        // 1×1 transparent PNG placeholder — no curl call made
        header('Content-Type: image/png');
        echo base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==');
        exit;
    }
    $type   = preg_replace('/[^a-zA-Z0-9_]/', '', $_GET['type'] ?? 'device_bits');
    $device = max(0, intval($_GET['device'] ?? 0));
    $port   = max(0, intval($_GET['port']   ?? 0));
    $from   = in_array($_GET['from'] ?? '-1d', ['-1h','-6h','-1d','-1w','-1m','-1y'])
              ? $_GET['from'] : '-1d';
    $w = min(max(100, (int)($_GET['w'] ?? 700)), 1200);
    $h = min(max(60,  (int)($_GET['h'] ?? 150)), 500);

    // RRDtool relative time syntax — the format LibreNMS actually understands
    $rrd_from = ['-1h'=>'end-1h', '-6h'=>'end-6h', '-1d'=>'end-24h',
                 '-1w'=>'end-1w', '-1m'=>'end-30d', '-1y'=>'end-365d'];
    $from_str = $rrd_from[$from] ?? 'end-24h';

    // ── Strategy 1: graph.php — the actual LibreNMS renderer ─────────────────
    // api_token in query string + RRD time format
    $gp = [
        'type'      => $type,
        'from'      => $from_str,
        'to'        => 'now',
        'width'     => $w,
        'height'    => $h,
        'api_token' => LIBRENMS_TOKEN,
        'bg'        => 'f2f5fa',   // light background for better graph label readability
    ];
    if ($port > 0) {
        $gp['id'] = $port;         // port graphs use 'id' for port_id
    } else {
        $gp['device'] = $device;
    }

    $ch = curl_init(LIBRENMS_URL . '/graph.php?' . http_build_query($gp));
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 8,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HTTPHEADER     => ['X-Auth-Token: ' . LIBRENMS_TOKEN],
    ]);
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    header('Content-Type: image/png');
    header('Cache-Control: max-age=60, public');

    // Check for PNG magic bytes (\x89PNG) — don't trust Content-Type header
    if ($resp && $code === 200 && substr($resp, 0, 4) === "\x89PNG") {
        echo $resp;
        exit;
    }

    // ── Strategy 2: API endpoint (/api/v0/devices/{id}/graphs/{type}) ─────────
    // Also pass api_token in query and use RRD time format
    $endpoint = $port > 0
        ? "/api/v0/devices/{$device}/ports/{$port}/graphs/{$type}"
        : "/api/v0/devices/{$device}/graphs/{$type}";

    $q  = http_build_query([
        'from'      => $from_str,
        'to'        => 'now',
        'width'     => $w,
        'height'    => $h,
        'api_token' => LIBRENMS_TOKEN,
    ]);
    $ch = curl_init(LIBRENMS_URL . "{$endpoint}?{$q}");
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 8,
        CURLOPT_HTTPHEADER     => ['X-Auth-Token: ' . LIBRENMS_TOKEN],
    ]);
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $png = null;
    if ($resp && $code === 200) {
        if (substr($resp, 0, 4) === "\x89PNG") {
            // Raw binary PNG
            $png = $resp;
        } else {
            // JSON envelope: {"status":"ok","image":"<base64 or data URI>"}
            $json = json_decode($resp, true);
            if (is_array($json) && !empty($json['image'])) {
                $img_data = $json['image'];
                if (($pos = strpos($img_data, 'base64,')) !== false) {
                    $img_data = substr($img_data, $pos + 7);
                }
                $decoded = base64_decode($img_data, true);
                if ($decoded) $png = $decoded;
            }
        }
    }

    echo $png ?: base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==');
    exit;
}

// ─── Includes (after proxy/debug so binary responses are never corrupted) ───────
include("check.php");
require_once __DIR__ . '/connection.php';
require_once("access_control.php");
require_once __DIR__ . '/nm_nodemeta.php';   // device classifier + Command-Center link resolver
include('logger.php');

// ─── Access Check ─────────────────────────────────────────────────────────────
if (!checkAccess($conn, 'net_mon')) {
    header("Location: /denied_access.php?page=net_mon");
    exit;
}
// Release session file lock immediately — prevents browser freeze when
// refreshing because PHP holds the lock during all LibreNMS API calls below.
session_write_close();

// ─── On-demand single-node poll (per-card "Poll now" button) ─────────────────
// Runs the native poller for ONE node only (fast, ~2-3s) so the operator can
// force a fresh SNMP read instead of waiting for the */2 cron. Returns JSON; the
// live-update JS then refreshes the card values in place (no full reload).
if (($_GET['api'] ?? '') === 'poll_now') {
    header('Content-Type: application/json');
    $nid = (int)($_GET['node'] ?? $_POST['node'] ?? 0);
    if ($nid <= 0) { echo json_encode(['ok'=>false,'error'=>'missing node id']); exit; }
    $chk = $conn->query("SELECT id, display_name FROM nm_nodes WHERE id=" . $nid . " LIMIT 1");
    if (!$chk || !$chk->num_rows) { echo json_encode(['ok'=>false,'error'=>'unknown node']); exit; }
    $row = $chk->fetch_assoc();
    $py  = escapeshellarg(VENV_PYTHON);
    $scr = escapeshellarg(SCRIPTS_DIR . '/nm_poller.py');
    $out = shell_exec("timeout 45 $py $scr --node " . escapeshellarg((string)$nid) . " 2>&1");
    $ran = ($out !== null && strpos($out, 'Poll complete') !== false);
    // PRECISE verdict: "Poll complete" only means the poller RAN — NOT that the device is up.
    // Report the device's actual state (up | degraded | down) from the freshly-updated data,
    // so the operator never sees a misleading "no errors" on a device that's really down.
    $v = nm_node_live_verdict($conn, $nid);
    echo json_encode([
        'ok'      => $ran,
        'node'    => $nid,
        'name'    => $row['display_name'],
        'state'   => $v['state'],          // up | degraded | down
        'detail'  => $v['detail'],         // e.g. "ICMP reply 2.6ms · SNMP stale 111 min"
        'error'   => $ran ? null : 'poll did not complete',
    ]);
    exit;
}

// ─── NEURU Command Center (AI Commander V2) live activity ────────────────────
// (Replaces the deprecated NetAIObot / AI Command Center v1 feed, which is being removed.)
if (($_GET['api'] ?? '') === 'aiobot') {
    header('Content-Type: application/json');
    if (!is_file(__DIR__ . '/nm_autopilotv2.php')) { echo json_encode(['ok'=>false,'off'=>true]); exit; }
    require_once __DIR__ . '/nm_autopilotv2.php';
    if ($conn->query("SHOW TABLES LIKE 'nm_ap2_sessions'")->num_rows === 0) { echo json_encode(['ok'=>true,'never'=>true,'events'=>[]]); exit; }
    $ev = $conn->query("SELECT e.phase, LEFT(e.body,180) AS title, e.node_id, n.display_name, e.created_at
                        FROM nm_ap2_events e LEFT JOIN nm_nodes n ON n.id=e.node_id
                        ORDER BY e.id DESC LIMIT 12");
    $events = $ev ? $ev->fetch_all(MYSQLI_ASSOC) : [];
    $act  = (int)$conn->query("SELECT COUNT(*) c FROM nm_ap2_sessions WHERE status='active'")->fetch_assoc()['c'];
    $wait = (int)$conn->query("SELECT COUNT(*) c FROM nm_ap2_sessions WHERE status='awaiting_approval'")->fetch_assoc()['c'];
    $queued = (int)$conn->query("SELECT COUNT(*) c FROM nm_ap2_sessions WHERE status='queued'")->fetch_assoc()['c'];
    echo json_encode(['ok'=>true,'enabled'=>function_exists('nm_ap2_enabled')?nm_ap2_enabled($conn):true,
        'bot'=>($events[0]['phase'] ?? 'idle'),'active'=>$act,'awaiting'=>$wait,
        'queued'=>$queued,'events'=>$events]);
    exit;
}

// ─── Stream the chrome + LOADER to the browser NOW, before the multi-second data ──
// build below — otherwise the loader (which lives in header.php) only reaches the
// browser AFTER all the server-side work, so it appears ~4s late. header.php emits
// <!DOCTYPE>+loader+nav (no html/head wrappers), exactly the same bytes as before;
// only the TIMING changes. Page requests only (api calls must emit no HTML).
if (($_GET['api'] ?? '') === '') {
    $videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
    include('header.php');
    if (session_status() === PHP_SESSION_ACTIVE) session_write_close();   // header re-opened the session; release the lock again
    while (ob_get_level() > 0) @ob_end_flush(); @flush();                 // push the loader bytes out NOW
    $GLOBALS['_NM_HDR'] = true;
}

// ─── Load monitored nodes from DB (nm_nodes / nm_groups / nm_interfaces) ──────
// Tables are auto-created by net_mon_config.php on first visit there.
$NM_GROUPS    = [];
$NM_NODES     = [];   // keyed by a unique render-id (see nm_render_key)
$NM_IFACES    = [];   // keyed by the same render-id → [iface row, ...]
$DB_NODES_OK  = false;

// Unique per-node render key: LibreNMS device_id when present (>0), otherwise the
// negated DB id. Avoids the collision where every native node (lnms_device_id=0)
// mapped to key 0 and overwrote the others.
function nm_render_key($lnms_device_id, $db_id) {
    return ((int)$lnms_device_id > 0) ? (int)$lnms_device_id : -(int)$db_id;
}

$tbl_check = $conn->query("SHOW TABLES LIKE 'nm_nodes'");
if ($tbl_check && $tbl_check->num_rows > 0) {
    $DB_NODES_OK = true;
    $grp_res = $conn->query("SELECT * FROM nm_groups ORDER BY sort_order, name");
    while ($g = $grp_res->fetch_assoc()) $NM_GROUPS[$g['id']] = $g;

    $nod_res = $conn->query(
        "SELECT n.*, g.name grp_name, g.color grp_color
         FROM nm_nodes n LEFT JOIN nm_groups g ON g.id=n.group_id
         ORDER BY g.sort_order, n.sort_order, n.display_name");
    while ($n = $nod_res->fetch_assoc()) {
        $NM_NODES[nm_render_key($n['lnms_device_id'], $n['id'])] = $n;
    }

    if ($NM_NODES) {
        $ifc_res = $conn->query(
            "SELECT i.*, n.lnms_device_id FROM nm_interfaces i
             JOIN nm_nodes n ON n.id=i.node_id ORDER BY i.sort_order");
        while ($ifc = $ifc_res->fetch_assoc()) {
            $did = nm_render_key($ifc['lnms_device_id'], $ifc['node_id']);
            $NM_IFACES[$did][] = $ifc;
        }
    }
}

// Build $DEVICES from DB nodes (for the fetch/summary logic below)
$DEVICES = [];
foreach ($NM_NODES as $did => $n) {
    $DEVICES[$did] = [
        'name'     => $n['display_name'],
        'ip'       => $n['ip_address'] ?? '—',
        'os_icon'  => $n['os_icon']    ?? 'generic',
        'hw'       => $n['hw_model']   ?? '—',
        'location' => $n['location']   ?? '—',
    ];
}

// ─── GPU targets: map nm_nodes.id → nm_gpu_targets.id (so a node's Graphs tab can
//     show a GPU panel ONLY for boxes registered in the AI/GPU Monitor). ──────────
$GPU_NODES = [];
if ($conn->query("SHOW TABLES LIKE 'nm_gpu_targets'")->num_rows > 0) {
    $gq = $conn->query("SELECT node_id, MIN(id) tid FROM nm_gpu_targets WHERE node_id IS NOT NULL AND enabled=1 GROUP BY node_id");
    while ($gq && ($gr = $gq->fetch_assoc())) $GPU_NODES[(int)$gr['node_id']] = (int)$gr['tid'];
}

// ─── Command-Center maps: nm_nodes.id → win/linux host id, so a Windows/Linux node
//     can show a "Command Center" button linking straight to its immersive screen. ──
$WIN_HOSTS = [];  // node_id → nm_win_hosts.id
$LX_HOSTS  = [];  // node_id → nm_lx_hosts.id
if ($DB_NODES_OK) {
    if ($conn->query("SHOW TABLES LIKE 'nm_win_hosts'")->num_rows > 0) {
        $wq = $conn->query("SELECT node_id, MIN(id) hid FROM nm_win_hosts WHERE node_id IS NOT NULL GROUP BY node_id");
        while ($wq && ($wr = $wq->fetch_assoc())) $WIN_HOSTS[(int)$wr['node_id']] = (int)$wr['hid'];
    }
    if ($conn->query("SHOW TABLES LIKE 'nm_lx_hosts'")->num_rows > 0) {
        $lq = $conn->query("SELECT node_id, MIN(id) hid FROM nm_lx_hosts WHERE node_id IS NOT NULL GROUP BY node_id");
        while ($lq && ($lr = $lq->fetch_assoc())) $LX_HOSTS[(int)$lr['node_id']] = (int)$lr['hid'];
    }
}

// ─── Native poller port stats (fallback when LibreNMS isn't the data source) ──
// Keyed by nm_nodes.id → array of port rows shaped like LibreNMS port objects,
// so the Interfaces tab can render them with the same helpers.
$NATIVE_PORTS = [];
if ($DB_NODES_OK) {
    $has_ps = $conn->query("SHOW TABLES LIKE 'nm_port_stats'");
    if ($has_ps && $has_ps->num_rows > 0) {
        $np = $conn->query(
            "SELECT ps.node_id, ps.port_id, ps.oper_status, ps.in_rate, ps.out_rate,
                    ps.if_speed, ps.recorded_at, i.if_name, i.if_alias, i.if_index
             FROM nm_port_stats ps
             JOIN (SELECT node_id, port_id, MAX(recorded_at) mx
                   FROM nm_port_stats GROUP BY node_id, port_id) last
               ON last.node_id = ps.node_id AND last.port_id = ps.port_id
              AND last.mx = ps.recorded_at
             JOIN nm_interfaces i ON i.id = ps.port_id
             WHERE i.show_graph = 1
             ORDER BY i.sort_order, i.if_index");
        if ($np) while ($row = $np->fetch_assoc()) {
            $NATIVE_PORTS[(int)$row['node_id']][] = [
                'port_id'          => (int)$row['port_id'],
                'ifName'           => $row['if_name'],
                'ifAlias'          => $row['if_alias'] ?: '',
                'ifOperStatus'     => $row['oper_status'] ?: 'unknown',
                'ifSpeed'          => (int)$row['if_speed'],
                'ifInOctets_rate'  => $row['in_rate'],
                'ifOutOctets_rate' => $row['out_rate'],
                'polled_at'        => $row['recorded_at'],
            ];
        }
    }
}

// ─── API Helper ───────────────────────────────────────────────────────────────
function lnms_call($endpoint, $params = []) {
    $q  = $params ? ('?' . http_build_query($params)) : '';
    $ch = curl_init(LIBRENMS_URL . $endpoint . $q);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER  => true,
        CURLOPT_CONNECTTIMEOUT  => 2,
        CURLOPT_TIMEOUT         => 4,
        CURLOPT_HTTPHEADER      => ['X-Auth-Token: ' . LIBRENMS_TOKEN],
    ]);
    $resp = curl_exec($ch);
    $err  = curl_error($ch);
    curl_close($ch);
    if ($err || !$resp) return null;
    return json_decode($resp, true);
}

function fmt_rate($bps) {
    if ($bps === null || $bps === '') return '—';
    $bps = (float)$bps;
    if ($bps >= 1_000_000_000) return number_format($bps / 1_000_000_000, 2) . ' GB/s';
    if ($bps >= 1_000_000)     return number_format($bps / 1_000_000,     2) . ' MB/s';
    if ($bps >= 1_000)         return number_format($bps / 1_000,         1) . ' KB/s';
    return number_format($bps, 0) . ' B/s';
}

function fmt_bytes($bytes) {
    if ($bytes === null || $bytes === '') return '—';
    $bytes = (float)$bytes;
    if ($bytes >= 1099511627776) return round($bytes / 1099511627776, 2) . ' TB';
    if ($bytes >= 1073741824)    return round($bytes / 1073741824,    1) . ' GB';
    if ($bytes >= 1048576)       return round($bytes / 1048576,       0) . ' MB';
    if ($bytes >= 1024)          return round($bytes / 1024,          0) . ' KB';
    return number_format($bytes, 0) . ' B';
}

function fmt_uptime($seconds) {
    if (!$seconds) return '—';
    $s = (int)$seconds;
    $d = floor($s / 86400); $s -= $d * 86400;
    $h = floor($s / 3600);  $s -= $h * 3600;
    $m = floor($s / 60);
    $parts = [];
    if ($d) $parts[] = "{$d}d";
    if ($h) $parts[] = "{$h}h";
    if ($m) $parts[] = "{$m}m";
    return $parts ? implode(' ', $parts) : '<1m';
}

function graph_url($device = 0, $type = 'device_bits', $port = 0, $from = '-1d', $w = 700, $h = 150) {
    return 'lnms_graph.php?' . http_build_query([
        'device' => $device, 'port' => $port,
        'type' => $type, 'from' => $from, 'w' => $w, 'h' => $h
    ]);
}

function lnms_extract_rows($payload, $keys = []) {
    if (!is_array($payload)) return [];
    foreach ($keys as $k) {
        if (isset($payload[$k]) && is_array($payload[$k])) return $payload[$k];
    }
    if (isset($payload[0]) && is_array($payload[0])) return $payload;
    return [];
}

// ─── Fetch LibreNMS Data (only when enabled) ──────────────────────────────────
$device_map = [];
$ports_map  = [];
$alerts     = [];
$health_map = [];

// LibreNMS is an OPTIONAL enrichment helper (mainly node import) — NEURU's native poller
// already has the live data. Probe LibreNMS ONCE; if that first call doesn't answer
// (LibreNMS down, or the network path to it is down — e.g. a core router rebooting), skip
// EVERYTHING below. Without this circuit-breaker, N devices × ~4 curl calls each, all
// waiting out the connect/read timeout, would hang the whole dashboard for minutes.
$all_devices_raw = $librenms_enabled ? lnms_call('/api/v0/devices') : null;
if ($librenms_enabled && $all_devices_raw !== null) {

if (isset($all_devices_raw['devices'])) {
    foreach ($all_devices_raw['devices'] as $d) {
        $device_map[(int)$d['device_id']] = $d;
    }
}

// Only nodes actually mapped to LibreNMS have a positive render key; native
// (SNMP/ping/container) nodes use a NEGATIVE key (-db_id) and don't exist in
// LibreNMS — calling its API for them is a wasted round-trip per node per load.
// LibreNMS is just an enrichment helper, so keep it to the mapped nodes only.
$lnms_ids = array_values(array_filter(array_keys($DEVICES), fn($id) => (int)$id > 0));

foreach ($lnms_ids as $id) {
    $resp = lnms_call("/api/v0/devices/{$id}/ports", [
        'columns' => 'port_id,ifName,ifDescr,ifAlias,ifOperStatus,ifAdminStatus,ifSpeed,ifInOctets_rate,ifOutOctets_rate,ifType'
    ]);
    $ports_map[$id] = $resp['ports'] ?? null;
}

$alerts_raw = lnms_call('/api/v0/alerts', ['state' => 1, 'count' => 50]);
$alerts = $alerts_raw['alerts'] ?? [];

foreach ($lnms_ids as $id) {
    $cpu = lnms_call("/api/v0/devices/{$id}/health/processor");
    $mem = lnms_call("/api/v0/devices/{$id}/health/mempool");
    $sto = lnms_call("/api/v0/devices/{$id}/health/storage");

    $cpu_rows = lnms_extract_rows($cpu, ['data', 'sensors', 'processors', 'health']);
    $mem_rows = lnms_extract_rows($mem, ['data', 'sensors', 'mempools', 'health']);
    $sto_rows = lnms_extract_rows($sto, ['data', 'sensors', 'storage', 'storages', 'health']);

    $health_map[$id] = [
        'cpu'     => $cpu_rows,
        'mem'     => $mem_rows,
        'storage' => $sto_rows,
        'other'   => [],
    ];
}

// Fallback for LibreNMS installs where /health/* only returns graph metadata.
$all_sensors_raw = lnms_call('/api/v0/resources/sensors');
$all_sensors = lnms_extract_rows($all_sensors_raw, ['sensors', 'data']);
if ($all_sensors) {
    foreach ($all_sensors as $s) {
        $dev_id = (int)($s['device_id'] ?? 0);
        if (!$dev_id || !isset($health_map[$dev_id])) continue;

        $class = strtolower((string)($s['sensor_class'] ?? ''));
        if (in_array($class, ['processor', 'processors'], true)) {
            $health_map[$dev_id]['cpu'][] = [
                'processor_descr' => $s['sensor_descr'] ?? 'CPU',
                'processor_usage' => (float)($s['sensor_current'] ?? 0),
            ];
            continue;
        }
        if (in_array($class, ['mempool', 'mempools', 'memory'], true)) {
            $health_map[$dev_id]['mem'][] = [
                'mempool_descr' => $s['sensor_descr'] ?? 'Memory',
                'mempool_perc'  => (float)($s['sensor_current'] ?? 0),
                'mempool_used'  => 0,
                'mempool_total' => 0,
            ];
            continue;
        }
        if (in_array($class, ['storage', 'storages', 'disk'], true)) {
            $health_map[$dev_id]['storage'][] = [
                'storage_descr' => $s['sensor_descr'] ?? 'Storage',
                'storage_perc'  => (float)($s['sensor_current'] ?? 0),
                'storage_used'  => 0,
                'storage_size'  => 0,
            ];
            continue;
        }

        $health_map[$dev_id]['other'][] = $s;
    }
}

} // end if ($librenms_enabled)

// ─── Native enrichment (DB poller data → LibreNMS-shaped maps) ────────────────
// Lets the existing LibreNMS render path show SNMP-polled nodes (status, uptime,
// CPU/mem, ports, traffic, health, device info) when LibreNMS isn't the source.
// Authoritative DOWN set from the alert engine (nm_alert_state) — so a node the poller
// flagged down shows down on the card immediately, regardless of last-known stale values.
$NM_DOWN = []; $NM_DEGRADED = [];
$adr = $conn->query("SELECT node_id, last_status FROM nm_alert_state WHERE entity_type='node' AND last_status IN ('down','lowerlayerdown','notpresent','testing','degraded')");
while ($adr && ($ax = $adr->fetch_assoc())) {
    if ($ax['last_status'] === 'degraded') $NM_DEGRADED[(int)$ax['node_id']] = 1;
    else $NM_DOWN[(int)$ax['node_id']] = 1;
}
foreach ($NM_NODES as $did => $nd) {
    $ndid = (int)($nd['id'] ?? 0);
    if (!$ndid || !empty($device_map[$did])) continue;   // skip if LibreNMS already supplied it

    // ── Ping-only nodes: status + latency from nm_ping_stats (no SNMP) ─────────
    if (($nd['monitor_type'] ?? 'snmp') === 'ping') {
        $pr = $conn->query(
            "SELECT is_up, latency_ms, packet_loss, recorded_at,
                    TIMESTAMPDIFF(SECOND, recorded_at, NOW()) AS age_s FROM nm_ping_stats
             WHERE node_id={$ndid} ORDER BY id DESC LIMIT 1"
        );
        $p = $pr ? $pr->fetch_assoc() : null;
        // Compute freshness DB-side (TIMESTAMPDIFF vs NOW()) so it's timezone-consistent
        // regardless of whether the writer used PHP-local or MySQL/UTC time. ≤10 min.
        $fresh = $p && $p['age_s'] !== null && (int)$p['age_s'] <= 600;
        $ping_up = ($p && (int)$p['is_up'] === 1 && $fresh);
        $device_map[$did] = [
            'device_id'   => $ndid,
            'status'      => $ping_up ? 1 : 0,
            'state'       => $ping_up ? 'up' : 'down',
            'uptime'      => 0,
            'latency'     => $p ? $p['latency_ms'] : null,
            'packet_loss' => $p ? $p['packet_loss'] : null,
            'sysName'     => $nd['display_name'],
            'hostname'    => $nd['ip_address'],
            'ip'          => $nd['ip_address'],
            'location'    => $nd['location'] ?: null,
            'last_polled' => $p['recorded_at'] ?? null,
            'type'        => 'ping',
            'monitor'     => 'ping',
        ];
        $health_map[$did] = ['cpu' => [], 'mem' => [], 'storage' => [], 'other' => []];
        continue;
    }

    // Ports — reshape native rows (show_graph=1) into LibreNMS port objects
    if (!empty($NATIVE_PORTS[$ndid])) {
        $pm = [];
        foreach ($NATIVE_PORTS[$ndid] as $np) {
            $pm[] = [
                'port_id'          => $np['port_id'],
                'ifName'           => $np['ifName'],
                'ifDescr'          => $np['ifName'],
                'ifAlias'          => $np['ifAlias'],
                'ifOperStatus'     => $np['ifOperStatus'],
                'ifAdminStatus'    => 'up',
                'ifSpeed'          => $np['ifSpeed'],
                'ifInOctets_rate'  => $np['ifInOctets_rate'],
                'ifOutOctets_rate' => $np['ifOutOctets_rate'],
                'ifType'           => '',
            ];
        }
        $ports_map[$did] = $pm;
    }

    // Health — latest nm_device_stats snapshot, reshaped for the Health tab + card
    $health_map[$did] = ['cpu' => [], 'mem' => [], 'storage' => [], 'other' => []];
    $uptime_secs = 0;
    $hres = $conn->query(
        "SELECT metric_type, metric_key, value, raw_value FROM nm_device_stats
         WHERE node_id={$ndid}
           AND recorded_at = (SELECT MAX(recorded_at) FROM nm_device_stats WHERE node_id={$ndid})"
    );
    if ($hres) while ($h = $hres->fetch_assoc()) {
        $v = (float)$h['value'];
        switch ($h['metric_type']) {
            case 'cpu':
                if ($h['metric_key'] === 'avg') break;   // keep per-core, avoid double count
                $health_map[$did]['cpu'][] = ['processor_descr' => ucfirst($h['metric_key']), 'processor_usage' => $v];
                break;
            case 'memory':
                $used = (float)$h['raw_value']; $tot = $v > 0 ? $used / ($v / 100) : 0;
                $health_map[$did]['mem'][] = ['mempool_descr' => ucwords($h['metric_key']), 'mempool_perc' => $v, 'mempool_used' => $used, 'mempool_total' => $tot];
                break;
            case 'storage':
                $used = (float)$h['raw_value']; $tot = $v > 0 ? $used / ($v / 100) : 0;
                $health_map[$did]['storage'][] = ['storage_descr' => ucwords($h['metric_key']), 'storage_perc' => $v, 'storage_used' => $used, 'storage_size' => $tot];
                break;
            case 'uptime':
                if ($h['metric_key'] === 'seconds') $uptime_secs = $v;
                break;
            default:   // temperature, custom sensors
                $health_map[$did]['other'][] = ['sensor_descr' => ucwords($h['metric_key']), 'sensor_class' => $h['metric_type'], 'sensor_current' => $h['value']];
        }
    }

    // Status + last-polled. A node is UP only when its data is FRESH (polled within ~6 min,
    // i.e. ≤3 missed 2-min polls). NOTE: do NOT fall back to "any iface oper=up" — when a
    // device dies the poller skips it, so its last port row is frozen at oper='up' forever,
    // which kept dead nodes green. The alert engine's verdict (nm_alert_state) is authoritative.
    $lp = $conn->query(
        "SELECT GREATEST(
            COALESCE((SELECT MAX(recorded_at) FROM nm_port_stats   WHERE node_id={$ndid}), '1970-01-01'),
            COALESCE((SELECT MAX(recorded_at) FROM nm_device_stats WHERE node_id={$ndid}), '1970-01-01')
         ) AS last_poll, NOW() AS now_ts"
    )->fetch_assoc();
    $last_poll = ($lp && $lp['last_poll'] > '1971') ? $lp['last_poll'] : null;
    $fresh = $last_poll && (strtotime($lp['now_ts']) - strtotime($last_poll)) <= 360;   // ≤6 min
    // Tri-state (pristine): the alert engine's verdict is authoritative.
    //   down     → ICMP failed (truly off)            → red, status 0
    //   degraded → pings fine but SNMP telemetry stale → amber, status 1 (still REACHABLE)
    //   up       → fresh data and no verdict           → green, status 1
    //   (stale & no verdict yet → conservative down until the engine catches up)
    if (!empty($NM_DOWN[$ndid]))          { $state_str = 'down';     $is_up = false; }
    elseif (!empty($NM_DEGRADED[$ndid]))  { $state_str = 'degraded'; $is_up = true;  }
    elseif ($fresh)                       { $state_str = 'up';       $is_up = true;  }
    else                                  { $state_str = 'down';     $is_up = false; }

    $device_map[$did] = [
        'device_id'   => $ndid,
        'status'      => $is_up ? 1 : 0,
        'state'       => $state_str,
        'uptime'      => $uptime_secs,
        'sysName'     => $nd['hostname'] ?: $nd['display_name'],
        'hostname'    => $nd['hostname'] ?: $nd['ip_address'],
        'ip'          => $nd['ip_address'],
        'hardware'    => $nd['hw_model'] ?: null,
        'os'          => ($nd['os_icon'] && $nd['os_icon'] !== 'generic') ? strtoupper($nd['os_icon']) : null,
        'location'    => $nd['location'] ?: null,
        'snmpver'     => $nd['snmp_version'] ?: null,
        'last_polled' => $last_poll,
        'type'        => 'network',
    ];
}

// ─── Summary Counts ───────────────────────────────────────────────────────────
$summary = ['up' => 0, 'down' => 0, 'unknown' => 0, 'ports_up' => 0, 'ports_down' => 0, 'alerts' => count($alerts)];
foreach ($DEVICES as $id => $def) {
    $d = $device_map[$id] ?? null;
    if (!$d) { $summary['unknown']++; continue; }
    if ((int)$d['status'] === 1) $summary['up']++; else $summary['down']++;
}
foreach ($ports_map as $ports) {
    if (!$ports) continue;
    foreach ($ports as $p) {
        if (strtolower($p['ifAdminStatus'] ?? '') === 'down') continue;
        if (strtolower($p['ifOperStatus']  ?? '') === 'up') $summary['ports_up']++;
        else $summary['ports_down']++;
    }
}

// Container up/down (Portainer, cached ~30s). The session lock is already released (session_write_close
// above), so this slow external I/O can't freeze other requests; wrapped so it never breaks the dashboard.
$summary['cont_up'] = 0; $summary['cont_down'] = 0; $summary['cont_on'] = false;
try {
    if (!function_exists('nm_cmd_container_list') && is_file(__DIR__ . '/nm_command.php')) @require_once __DIR__ . '/nm_command.php';
    if (function_exists('nm_cmd_container_list')) {
        $cl = nm_cmd_container_list($conn);
        if (!empty($cl['ok'])) {
            $summary['cont_on'] = true;
            foreach (($cl['items'] ?? []) as $it) { if (($it['state'] ?? '') === 'running') $summary['cont_up']++; else $summary['cont_down']++; }
        }
    }
} catch (\Throwable $e) { /* never break the dashboard */ }

// ─── Live values endpoint (AJAX polling → moving counters, no full reload) ────
// Reuses everything already loaded above; emits a compact JSON of the fast-moving
// values (per-node status/health/traffic + summary + top talkers) and exits
// BEFORE any HTML so the dashboard JS can update the DOM in place every few sec.
if (($_GET['api'] ?? '') === 'live') {
    header('Content-Type: application/json');
    $live_devices = [];
    foreach ($NM_NODES as $did => $nd) {
        $d = $device_map[$did] ?? null;
        $status = !$d ? 'unknown' : ($d['state'] ?? ((int)$d['status'] === 1 ? 'up' : 'down'));
        $cpu = null;
        if (!empty($health_map[$did]['cpu'])) { $u = array_column($health_map[$did]['cpu'], 'processor_usage'); $cpu = count($u) ? (int)round(array_sum($u)/count($u)) : null; }
        $mem = null;
        if (!empty($health_map[$did]['mem'])) { $m = array_column($health_map[$did]['mem'], 'mempool_perc'); $mem = count($m) ? (int)round(array_sum($m)/count($m)) : null; }
        $ifs = [];
        foreach (($NM_IFACES[$did] ?? []) as $si) {
            $pid = (int)($si['lnms_port_id'] ?: $si['id']);
            if (!empty($ports_map[$did])) foreach ($ports_map[$did] as $p) {
                if ((int)$p['port_id'] === $pid) {
                    $ifs[] = ['pid'=>$pid, 'in'=>(float)($p['ifInOctets_rate'] ?? 0), 'out'=>(float)($p['ifOutOctets_rate'] ?? 0), 'oper'=>strtolower($p['ifOperStatus'] ?? 'unknown')];
                    break;
                }
            }
        }
        // Port counts (same tri-state tally the row-accordion header renders) so the
        // live poll can keep the "N up / N down / N dis" badges in sync too.
        $pup = 0; $pdown = 0; $pdis = 0; $has_ports = !empty($ports_map[$did]);
        if ($has_ports) foreach ($ports_map[$did] as $p) {
            $a = strtolower($p['ifAdminStatus'] ?? '');
            $o = strtolower($p['ifOperStatus']  ?? '');
            if ($a === 'down')   $pdis++;
            elseif ($o === 'up') $pup++;
            else                 $pdown++;
        }
        $live_devices[$did] = [
            'status'  => $status,
            'latency' => (isset($d['latency']) && $d['latency'] !== null) ? round((float)$d['latency']) : null,
            'loss'    => (isset($d['packet_loss']) && $d['packet_loss'] !== null) ? round((float)$d['packet_loss']) : null,
            'cpu'     => $cpu, 'mem' => $mem, 'ifaces' => $ifs,
            'uptime'  => isset($d['uptime']) ? (int)$d['uptime'] : 0,
            'has_ports' => $has_ports, 'pup' => $pup, 'pdown' => $pdown, 'pdis' => $pdis,
        ];
    }
    $tt = [];
    foreach ($ports_map as $dev_id => $ports) {
        if (!$ports) continue;
        foreach ($ports as $p) {
            $in = (float)($p['ifInOctets_rate'] ?? 0); $out = (float)($p['ifOutOctets_rate'] ?? 0); $tot = $in + $out;
            if ($tot < 1) continue;
            $tt[] = ['dev_id'=>$dev_id, 'device'=>$DEVICES[$dev_id]['name'] ?? "ID:$dev_id",
                     'iface'=>$p['ifName'] ?: ($p['ifDescr'] ?: '—'), 'in'=>$in, 'out'=>$out, 'total'=>$tot, 'port_id'=>(int)($p['port_id'] ?? 0)];
        }
    }
    usort($tt, fn($a, $b) => $b['total'] <=> $a['total']);
    echo json_encode([
        'ok' => true, 'ts' => time(),
        'summary'  => ['up'=>$summary['up'], 'down'=>$summary['down'], 'unknown'=>$summary['unknown'],
                       'ports_up'=>$summary['ports_up'], 'ports_down'=>$summary['ports_down'],
                       'cont_up'=>$summary['cont_up'], 'cont_down'=>$summary['cont_down'], 'cont_on'=>$summary['cont_on']],
        'devices'  => $live_devices,
        'top'      => array_slice($tt, 0, 9),
    ]);
    exit;
}

// ─── Load Header (already streamed early above for page requests) ───────────────
if (empty($GLOBALS['_NM_HDR'])) { include('header.php'); }
log_user_action($conn, 'view_page', 'net_mon.php');
if (empty($videoFile)) $videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Network Monitor | SG-PR Console</title>
    <!-- non-render-blocking: load FA async so the loader/page paint immediately (icons fill in) -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" media="print" onload="this.media='all'">
    <noscript><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"></noscript>
    <!-- defer: 251KB of charting only needed when a graph is opened — must NOT block the body/loader -->
    <script defer src="/chart.umd.min.js"></script>
    <script defer src="/chartjs-adapter-date-fns.bundle.min.js"></script>
    <?= function_exists('nm_tz_js') ? nm_tz_js() : '' ?>
    <style>
        /* ── Base (matches dev_tools.php) ────────────────────────────────────── */
        :root {
            --glass:  rgba(255,255,255,0.08);
            --border: rgba(255,255,255,0.15);
            --accent: #4da3ff;
            --up:     #2ecc71;
            --down:   #e74c3c;
            --warn:   #f39c12;
        }
        body { margin: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #000; color: #fff; overflow-x: hidden; }
        #bg-video { position: fixed; top: 0; left: 0; min-width: 100%; min-height: 100%; z-index: -1; object-fit: cover; opacity: 0.35; }
        .page-wrapper { max-width: 1600px; margin: 0 auto; padding: 20px; box-sizing: border-box; }

        /* ── Bento Grid ──────────────────────────────────────────────────────── */
        .bento-grid { display: grid; grid-template-columns: repeat(4, 1fr); grid-auto-rows: minmax(auto, auto); gap: 15px; }
        .glass-card { background: var(--glass); backdrop-filter: blur(20px); border: 1px solid var(--border); border-radius: 15px; padding: 20px; display: flex; flex-direction: column; transition: transform 0.2s, border-color 0.2s; }
        .glass-card:hover { border-color: var(--accent); }
        .span-2 { grid-column: span 2; }
        .span-4 { grid-column: span 4; }
        h2 { margin: 0 0 15px; font-size: 17px; color: var(--accent); display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }

        /* ── Header (identical to dev_tools) ────────────────────────────────── */
        .nav-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .modern-header-container { flex-grow: 1; margin-right: 20px; }
        .bento-glass-card-header { background: rgba(255,255,255,0.05); backdrop-filter: blur(15px); border: 1px solid rgba(255,255,255,0.1); border-radius: 20px; padding: 15px 25px; display: flex; justify-content: space-between; align-items: center; position: relative; overflow: hidden; }
        .visual-accent { position: absolute; top: 0; left: 0; width: 4px; height: 100%; background: var(--accent); box-shadow: 0 0 15px var(--accent); }
        .status-pill { display: inline-flex; align-items: center; gap: 8px; background: rgba(77,163,255,0.1); color: var(--accent); padding: 4px 12px; border-radius: 20px; font-size: 11px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; }
        .pulse-dot { width: 6px; height: 6px; background: var(--accent); border-radius: 50%; animation: pulse 2s infinite; }
        @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(77,163,255,0.7); } 70% { box-shadow: 0 0 0 10px rgba(77,163,255,0); } 100% { box-shadow: 0 0 0 0 rgba(77,163,255,0); } }
        .main-title { margin: 0; font-size: 28px; letter-spacing: -1px; }
        .orbit-container { position: relative; width: 50px; height: 50px; display: flex; align-items: center; justify-content: center; }
        .orbit-path { position: absolute; width: 100%; height: 100%; border: 1px dashed rgba(77,163,255,0.3); border-radius: 50%; animation: rotate 10s linear infinite; }
        .rotation-core { font-size: 20px; color: var(--accent); animation: rotate 3s linear infinite; }
        @keyframes rotate { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

        /* ── Summary Stats ───────────────────────────────────────────────────── */
        .stat-grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; }
        .stat-card { background: rgba(255,255,255,0.05); border: 1px solid var(--border); border-radius: 12px; padding: 15px; text-align: center; transition: border-color 0.2s; }
        .stat-card:hover { border-color: var(--accent); }
        .stat-val { font-size: 36px; font-weight: 700; line-height: 1; }
        .stat-lbl { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #aaa; margin-top: 4px; }
        .stat-up   .stat-val { color: var(--up); }
        .stat-down .stat-val { color: var(--down); }
        .stat-warn .stat-val { color: var(--warn); }
        .stat-blue .stat-val { color: var(--accent); }

        /* ── Device Quick Cards ───────────────────────────────────────────────── */
        .device-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }
        .device-card { background: rgba(255,255,255,0.05); border: 1px solid var(--border); border-radius: 12px; padding: 14px; cursor: pointer; transition: 0.2s; position: relative; }
        .device-card:hover { border-color: var(--accent); transform: translateY(-2px); }
        .device-card.status-up    { border-left: 3px solid var(--up); }
        .device-card.status-down  { border-left: 3px solid var(--down); }
        .device-card.status-degraded { border-left: 3px solid var(--warn); }
        .device-card.status-unknown { border-left: 3px solid #666; }
        .device-card-name { font-weight: 700; font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; padding-right: 20px; }
        .device-card-ip   { font-size: 11px; color: #aaa; font-family: monospace; }
        .status-dot { position: absolute; top: 12px; right: 12px; width: 9px; height: 9px; border-radius: 50%; }
        .status-dot.up      { background: var(--up);   box-shadow: 0 0 6px var(--up); }
        .status-dot.down    { background: var(--down); box-shadow: 0 0 6px var(--down); animation: blink 1s infinite; }
        .status-dot.degraded{ background: var(--warn); box-shadow: 0 0 6px var(--warn); animation: blink 2.2s infinite; }
        .status-dot.unknown { background: #555; }
        @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
        .device-card-meta { font-size: 10px; color: #777; margin-top: 6px; display: flex; flex-wrap: wrap; gap: 6px; }
        .type-badge { display: inline-block; font-size: 10px; padding: 2px 7px; border-radius: 8px; font-weight: 700; margin-top: 6px; }
        .badge-linux    { background: rgba(255,193,7,0.15);  color: #ffc107; }
        .badge-mikrotik { background: rgba(0,212,170,0.15);  color: #00d4aa; }
        .badge-cisco    { background: rgba(29,144,245,0.15); color: #1d90f5; }
        .badge-generic  { background: rgba(255,255,255,0.1); color: #aaa; }
        .badge-ping     { background: rgba(155,89,182,0.2);  color: #9b59b6; }

        /* ── Accordion ───────────────────────────────────────────────────────── */
        .dev-accordion { margin-bottom: 8px; border-radius: 12px; overflow: hidden; border: 1px solid var(--border); }
        .dev-accordion-header { background: rgba(255,255,255,0.06); padding: 12px 18px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; user-select: none; font-weight: 600; transition: 0.2s; }
        .dev-accordion-header:hover { background: rgba(77,163,255,0.12); }
        .dev-accordion-body { display: none; }
        .dev-accordion-body.open { display: block; }
        .dev-accordion-inner { padding: 16px; }

        /* ── Tabs ────────────────────────────────────────────────────────────── */
        .tab-bar { display: flex; gap: 6px; margin-bottom: 14px; flex-wrap: wrap; }
        .tab-btn { background: rgba(255,255,255,0.05); border: 1px solid var(--border); color: #aaa; padding: 6px 14px; border-radius: 8px; cursor: pointer; font-size: 12px; font-weight: 600; transition: 0.2s; }
        .tab-btn:hover, .tab-btn.active { background: var(--accent); color: #000; border-color: transparent; }
        .tab-panel { display: none; }
        .tab-panel.active { display: block; }

        /* ── Port Table ──────────────────────────────────────────────────────── */
        .port-table { width: 100%; border-collapse: collapse; font-size: 12px; font-family: 'Consolas', monospace; }
        .port-table th { background: rgba(255,255,255,0.06); color: #aaa; padding: 7px 12px; text-align: left; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; border-bottom: 1px solid var(--border); }
        .port-table td { padding: 7px 12px; border-bottom: 1px solid rgba(255,255,255,0.04); color: #e0e0e0; }
        .port-table tr:last-child td { border-bottom: none; }
        .port-table tr:hover td { background: rgba(255,255,255,0.04); }
        .st-up   { color: var(--up);   font-weight: 700; }
        .st-down { color: var(--down); font-weight: 700; }
        .st-dis  { color: var(--warn); }

        /* ── Graphs ──────────────────────────────────────────────────────────── */
        .graph-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
        .graph-block { background: rgba(0,0,0,0.3); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
        .graph-block-title { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #aaa; padding: 8px 12px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
        .graph-block img { width: 100%; height: auto; display: block; min-height: 80px; background: rgba(0,0,0,0.5); }
        .range-btn { font-size: 10px; padding: 2px 8px; border-radius: 4px; background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.12); color: #aaa; cursor: pointer; transition: 0.15s; }
        .range-btn:hover, .range-btn.active { background: var(--accent); color: #000; border-color: transparent; }

        /* ── Health Bars ─────────────────────────────────────────────────────── */
        .health-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; font-size: 12px; }
        .health-bar-track { flex: 1; height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; overflow: hidden; }
        .health-bar-fill { height: 100%; border-radius: 3px; transition: width 0.5s ease; }
        .fill-ok   { background: var(--up); }
        .fill-warn { background: var(--warn); }
        .fill-crit { background: var(--down); }

        /* ── Alert Rows ──────────────────────────────────────────────────────── */
        .alert-row { display: flex; align-items: flex-start; gap: 12px; padding: 10px; border-bottom: 1px solid rgba(255,255,255,0.06); }
        .alert-row:last-child { border-bottom: none; }
        .alert-sev { font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 8px; white-space: nowrap; }
        .sev-critical { background: rgba(231,76,60,0.2); color: #e74c3c; }
        .sev-warning  { background: rgba(243,156,18,0.2); color: #f39c12; }
        .sev-ok       { background: rgba(46,204,113,0.2); color: #2ecc71; }
        .sev-info     { background: rgba(77,163,255,0.2); color: #4da3ff; }
        .ai-pill      { font-size:9px; font-weight:700; letter-spacing:.5px; padding:1px 6px; border-radius:6px;
                        background:rgba(155,89,182,0.2); color:#b07cd6; margin-left:6px; vertical-align:middle; }
        .alert-info { flex: 1; }
        .alert-info b { font-size: 13px; }
        .alert-info small { color: #888; font-size: 11px; }

        /* ── Badges ──────────────────────────────────────────────────────────── */
        .badge { font-size: 11px; padding: 2px 8px; border-radius: 10px; font-weight: 700; }
        .badge-up   { background: rgba(46,204,113,0.2); color: var(--up); }
        .badge-down { background: rgba(231,76,60,0.2);  color: var(--down); }
        .badge-dis  { background: rgba(243,156,18,0.2); color: var(--warn); }

        /* ── Top Traffic ─────────────────────────────────────────────────────── */
        .traffic-table { width: 100%; border-collapse: collapse; font-size: 12px; }
        .traffic-table td { padding: 7px 10px; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .traffic-table tr:hover td { background: rgba(255,255,255,0.04); }
        .traffic-bar { width: 70px; height: 5px; background: rgba(255,255,255,0.1); border-radius: 3px; overflow: hidden; display: inline-block; vertical-align: middle; margin-left: 8px; }
        .traffic-bar-fill { height: 100%; background: var(--accent); border-radius: 3px; }
        .ctop-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 10px; }
        .ctop-row { background: rgba(255,255,255,0.04); border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; cursor: pointer; transition: border-color .15s, background .15s; }
        .ctop-row:hover { border-color: var(--accent); background: rgba(77,163,255,0.07); }
        .ctop-head { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
        .ctop-name { font-size: 12.5px; font-weight: 700; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .ctop-avg { font-size: 12px; font-family: monospace; color: var(--accent); white-space: nowrap; }
        .ctop-meta { display: flex; gap: 12px; font-size: 10.5px; font-family: monospace; color: #9aa; }

        /* ── Refresh Bar ─────────────────────────────────────────────────────── */
        .refresh-bar { display: flex; align-items: center; gap: 10px; font-size: 12px; color: #aaa; }
        .refresh-btn { background: rgba(77,163,255,0.15); border: 1px solid var(--accent); color: var(--accent); padding: 6px 14px; border-radius: 8px; cursor: pointer; font-size: 12px; font-weight: 600; display: flex; align-items: center; gap: 6px; transition: 0.2s; }
        .refresh-btn:hover { background: var(--accent); color: #000; }

        /* ── Info Grid ───────────────────────────────────────────────────────── */
        .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        .info-cell { background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.07); border-radius: 8px; padding: 10px; }
        .info-cell .lbl { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: #666; margin-bottom: 4px; }
        .info-cell .val { font-size: 13px; color: #e0e0e0; font-family: monospace; word-break: break-all; }

        /* ── Responsive ──────────────────────────────────────────────────────── */
        @media (max-width: 1100px) {
            .device-grid { grid-template-columns: repeat(3, 1fr); }
            .stat-grid   { grid-template-columns: repeat(3, 1fr); }
            .graph-grid  { grid-template-columns: 1fr; }
        }
        @media (max-width: 700px) {
            .bento-grid  { grid-template-columns: 1fr; }
            .span-2, .span-4 { grid-column: span 1; }
            .device-grid { grid-template-columns: 1fr 1fr; }
            .stat-grid   { grid-template-columns: repeat(2, 1fr); }
            .info-grid   { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
<video autoplay muted loop playsinline id="bg-video">
    <source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4">
</video>

<div class="page-wrapper">

    <!-- ── Header ─────────────────────────────────────────────────────────────── -->
    <header class="nav-header">
        <div class="modern-header-container">
            <div class="bento-glass-card-header">
                <div class="visual-accent"></div>
                <div class="content-left">
                    <div class="status-pill">
                        <span class="pulse-dot"></span> Live Network Intelligence
                    </div>
                    <h1 class="main-title">Network <span style="font-weight:300;">Monitor</span></h1>
                </div>
                <div class="refresh-bar" style="margin: 0 20px; gap: 8px;">
                    <span style="font-size:11px;color:#666;">Updated <?= function_exists('nm_local_now')?nm_local_now('H:i:s T'):date('H:i:s T') ?></span>
                    <button class="refresh-btn" onclick="doRefresh()" title="Refresh page">
                        <i class="fas fa-sync-alt" id="refresh-icon"></i> Refresh
                    </button>
                    <button class="refresh-btn" onclick="toggleRefreshPanel()" title="Auto-refresh settings" style="padding:6px 10px;">
                        <i class="fas fa-gear"></i>
                    </button>
                    <a href="net_mon_config.php" class="refresh-btn" style="text-decoration:none;padding:6px 12px;" title="Configure nodes">
                        <i class="fas fa-sliders"></i> Config
                    </a>
                    <?php if(!function_exists('_nm_can') || _nm_can('geomap')): ?>
                    <a href="geomap.php" class="refresh-btn" style="text-decoration:none;padding:6px 12px;border-color:rgba(168,85,247,.5);color:#c084fc;" title="Open the NOC Geo Wall in a new tab">
                        <i class="fas fa-earth-americas"></i> Geo Wall
                    </a>
                    <?php endif; ?>
                    <?php if(!function_exists('_nm_can') || _nm_can('command')): ?>
                    <a href="command.php" class="refresh-btn" style="text-decoration:none;padding:6px 12px;border-color:rgba(77,163,255,.5);color:#4da3ff;" title="Open the interactive Command Center">
                        <i class="fas fa-satellite-dish"></i> Command Center
                    </a>
                    <?php endif; ?>
                </div>
                <div class="icon-right">
                    <div class="orbit-container">
                        <div class="orbit-path"></div>
                        <i class="fa-solid fa-network-wired rotation-core"></i>
                    </div>
                </div>
            </div>
        </div>
    </header>

    <!-- ── Refresh settings panel (hidden by default) ─────────────────────────── -->
    <div id="refresh-panel" style="display:none;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.12);border-radius:12px;padding:14px 20px;margin-bottom:14px;display:none;align-items:center;gap:20px;flex-wrap:wrap;">
        <span style="font-size:12px;color:#aaa;font-weight:600;text-transform:uppercase;letter-spacing:.8px;"><i class="fas fa-clock"></i> Auto-Refresh</span>
        <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;">
            <input type="checkbox" id="auto-refresh-chk" onchange="applyAutoRefresh()" style="width:16px;height:16px;">
            Enable auto-refresh
        </label>
        <select id="refresh-interval" onchange="applyAutoRefresh()" style="background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.15);color:#fff;padding:6px 12px;border-radius:8px;font-size:12px;outline:none;">
            <option value="30">Every 30 seconds</option>
            <option value="60" selected>Every 1 minute</option>
            <option value="120">Every 2 minutes</option>
            <option value="300">Every 5 minutes</option>
            <option value="600">Every 10 minutes</option>
        </select>
        <span id="refresh-countdown" style="font-size:11px;color:#666;"></span>
    </div>

    <!-- ── Federated devices (remote sites, read-only) — populated only on a MASTER ── -->
    <div id="fed-strip" class="glass-card" style="display:none;margin-bottom:15px;">
      <h2 style="margin-bottom:12px;">
        <i class="fas fa-satellite" style="color:#4da3ff;"></i> Federated Devices
        <span style="font-size:11px;color:#7f93af;font-weight:400;margin-left:10px;">remote sites reporting to this master — status + latest metrics</span>
        <a href="federation.php" style="margin-left:auto;font-size:11px;color:#4da3ff;text-decoration:none;">Full metric view →</a>
      </h2>
      <div id="fed-strip-body"></div>
    </div>
    <style>
      #fed-strip .fss{ margin-bottom:12px; }
      #fed-strip .fss:last-child{ margin-bottom:0; }
      #fed-strip .fsh{ display:flex;align-items:center;gap:8px;font-size:12.5px;color:#cfe0f5;margin-bottom:7px;flex-wrap:wrap; }
      #fed-strip .fsh b{ color:#fff; }
      #fed-strip .fsbadge{ font-size:9px;font-weight:800;text-transform:uppercase;padding:1px 7px;border-radius:20px;border:1px solid; }
      #fed-strip .fsrow{ display:grid;grid-template-columns:repeat(auto-fill,minmax(215px,1fr));gap:8px; }
      #fed-strip .fsd{ display:flex;align-items:center;gap:8px;background:rgba(0,0,0,.28);border:1px solid rgba(255,255,255,.09);border-radius:9px;padding:7px 10px; }
      #fed-strip .fsd.dn{ border-color:rgba(255,92,108,.5);background:rgba(255,92,108,.07); }
      #fed-strip .fsdot{ width:8px;height:8px;border-radius:50%;flex:0 0 auto;box-shadow:0 0 6px currentColor; }
      #fed-strip .fsnm{ font-weight:700;font-size:12.5px;color:#eaf1fb;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1; }
      #fed-strip .fsm{ font-size:10.5px;color:#8aa2c4;font-variant-numeric:tabular-nums;white-space:nowrap; }
    </style>
    <script>
    (function(){
      const isDown=st=>['down','lowerlayerdown','notpresent','testing'].includes((st||'').toLowerCase());
      const E=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
      function metric(x){ const p=[]; if(x.cpu!=null)p.push('CPU '+x.cpu+'%'); if(x.ram!=null)p.push('RAM '+x.ram+'%'); if(x.disk!=null)p.push('DSK '+x.disk+'%'); return p.join(' · ')||'—'; }
      function render(sites){
        const strip=document.getElementById('fed-strip'), body=document.getElementById('fed-strip-body');
        let total=0;
        const html=(sites||[]).map(s=>{
          if(s.status==='offline'||s.status==='never') return '';   // a removed/decommissioned server drops off the strip
          const devs=s.devices||[]; if(!devs.length) return ''; total+=devs.length;
          const sc=s.status==='online'?'#41d18b':s.status==='stale'?'#f0a92c':'#ff5c6c';
          const cards=devs.map(x=>{ const dn=isDown(x.st),dg=(x.st||'').toLowerCase()==='degraded';
            const dot=dn?'#ff5c6c':dg?'#f0a92c':'#41d18b';
            return `<div class="fsd${dn?' dn':''}"><span class="fsdot" style="background:${dot}"></span>
              <span class="fsnm" title="${E(x.name)} — ${E(x.ip)}">${E(x.name)}</span>
              <span class="fsm">${metric(x)}</span></div>`; }).join('');
          return `<div class="fss"><div class="fsh"><i class="fas fa-location-dot" style="color:${sc}"></i>
            <b>${E(s.name)}</b><span class="fsbadge" style="border-color:${sc};color:${sc}">${E(s.status)}</span>
            <span style="color:#7f93af">${devs.length} device${devs.length!=1?'s':''}</span></div>
            <div class="fsrow">${cards}</div></div>`;
        }).join('');
        if(total){ body.innerHTML=html; strip.style.display=''; } else { strip.style.display='none'; }
      }
      function load(){ fetch('federation.php?api=fed_devices&scope=strip&_='+Date.now())
        .then(r=>r.json()).then(d=>{ if(d&&d.ok) render(d.sites); }).catch(()=>{}); }
      load(); setInterval(load, 30000);
    })();
    </script>

    <?php if ($DB_NODES_OK && empty($NM_NODES)): ?>
    <!-- ── No nodes configured ───────────────────────────────────────────────── -->
    <div class="glass-card" style="margin-bottom:15px;text-align:center;padding:40px 20px;">
        <div style="font-size:48px;margin-bottom:16px;"><i class="fas fa-server" style="color:#f39c12;"></i></div>
        <h2 style="justify-content:center;margin-bottom:8px;">No Nodes Configured</h2>
        <p style="color:#aaa;margin:0 0 20px;">
            LibreNMS is connected. Add nodes to monitor via the config page.
        </p>
        <a href="net_mon_config.php?tab=nodes" style="display:inline-flex;align-items:center;gap:8px;background:rgba(77,163,255,.15);border:1px solid #4da3ff;color:#4da3ff;padding:10px 22px;border-radius:10px;text-decoration:none;font-weight:600;">
            <i class="fas fa-plus-circle"></i> Add Nodes
        </a>
    </div>
    <?php else: ?>

    <!-- LibreNMS is a fully optional helper — NEURU's native poller provides live SNMP data on its
         own, so no "LibreNMS disabled" banner is shown here. -->

    <!-- ── Summary ────────────────────────────────────────────────────────────── -->
    <div class="glass-card" style="margin-bottom:15px;">
        <h2>
            <i class="fas fa-chart-bar"></i> Network Overview
            <span style="font-size:11px;color:#666;font-weight:400;margin-left:auto;">
                Last updated <?= function_exists('nm_local_now')?nm_local_now('H:i:s'):date('H:i:s') ?> <?= function_exists('nm_local_now')?nm_local_now('T'):date('T') ?>
            </span>
        </h2>
        <div class="stat-grid">
            <a class="stat-card stat-blue" href="#nm-device-list" style="text-decoration:none;color:inherit;display:block;" title="Jump to the device list">
                <div class="stat-val"><?= count($DEVICES) ?></div>
                <div class="stat-lbl">Total Devices</div>
            </a>
            <a class="stat-card stat-up" href="#nm-device-list" style="text-decoration:none;color:inherit;display:block;" title="Devices that are up">
                <div class="stat-val" id="stat-up"><?= $summary['up'] ?></div>
                <div class="stat-lbl">Devices Up</div>
            </a>
            <a class="stat-card <?= $summary['down'] > 0 ? 'stat-down' : 'stat-up' ?>" href="incidents.php" style="text-decoration:none;color:inherit;display:block;" title="View incidents for down devices">
                <div class="stat-val" id="stat-down"><?= $summary['down'] ?></div>
                <div class="stat-lbl">Devices Down</div>
            </a>
            <a class="stat-card stat-up" href="traffic_viewer.php" style="text-decoration:none;color:inherit;display:block;" title="Live interface traffic">
                <div class="stat-val" id="stat-ports-up"><?= $summary['ports_up'] ?></div>
                <div class="stat-lbl">Ports Up</div>
            </a>
            <a class="stat-card <?= $summary['ports_down'] > 0 ? 'stat-down' : 'stat-up' ?>" href="traffic_viewer.php" style="text-decoration:none;color:inherit;display:block;" title="Live interface traffic">
                <div class="stat-val" id="stat-ports-down"><?= $summary['ports_down'] ?></div>
                <div class="stat-lbl">Ports Down</div>
            </a>
            <?php if (!empty($summary['cont_on'])): ?>
            <a class="stat-card <?= $summary['cont_down'] > 0 ? 'stat-warn' : 'stat-up' ?>" href="containers.php" style="text-decoration:none;color:inherit;display:block;" title="Containers — running / stopped">
                <div class="stat-val"><span id="stat-cont-up" style="color:var(--up)"><?= $summary['cont_up'] ?></span><span style="color:#666;font-weight:400;font-size:.62em;padding:0 3px;">/</span><span id="stat-cont-down" style="color:<?= $summary['cont_down'] > 0 ? 'var(--down)' : 'var(--up)' ?>"><?= $summary['cont_down'] ?></span></div>
                <div class="stat-lbl">Containers &uarr;/&darr;</div>
            </a>
            <?php endif; ?>
            <a class="stat-card <?= $summary['alerts'] > 0 ? 'stat-warn' : 'stat-up' ?>" href="incidents.php" id="stat-alerts" style="text-decoration:none;color:inherit;display:block;" title="View active alerts">
                <div class="stat-val" id="stat-alerts-val" data-base="<?= $summary['alerts'] ?>"><?= $summary['alerts'] ?></div>
                <div class="stat-lbl">Active Alerts</div>
            </a>
        </div>
    </div>

    <span id="nm-device-list" style="position:relative;top:-70px;"></span><!-- KPI "Total/Up Devices" scroll target -->
    <!-- ── Grouped Node Cards ──────────────────────────────────────────────────── -->
    <?php
    // Build group buckets
    $card_groups = [];
    foreach ($NM_NODES as $did => $nd) {
        $gname = $nd['grp_name'] ?? '— Ungrouped —';
        $card_groups[$gname][] = ['did' => $did, 'nd' => $nd];
    }
    // Fallback: if nm_nodes is empty and we somehow got here, use $DEVICES
    if (empty($card_groups)) {
        foreach ($DEVICES as $id => $def) {
            $card_groups['Devices'][] = ['did' => $id, 'nd' => ['display_name'=>$def['name'],'ip_address'=>$def['ip'],'os_icon'=>$def['os_icon'],'hw_model'=>$def['hw'],'location'=>$def['location'],'grp_color'=>'#4da3ff']];
        }
    }
    foreach ($card_groups as $gname => $gcards):
        $grp_color = $gcards[0]['nd']['grp_color'] ?? '#4da3ff';
    ?>
    <div class="glass-card" style="margin-bottom:15px;">
        <h2 style="margin-bottom:14px;">
            <span style="width:12px;height:12px;border-radius:50%;background:<?= htmlspecialchars($grp_color) ?>;display:inline-block;flex-shrink:0;"></span>
            <?= htmlspecialchars($gname) ?>
            <span style="font-size:11px;color:#666;font-weight:400;margin-left:6px;"><?= count($gcards) ?> node<?= count($gcards)!=1?'s':'' ?></span>
            <span style="margin-left:auto;font-size:11px;color:#666;font-weight:400;">click a card to jump to details ↓</span>
        </h2>
        <div class="device-grid">
        <?php foreach ($gcards as $gc):
            $id  = $gc['did'];
            $def = $DEVICES[$id] ?? ['name'=>$gc['nd']['display_name'],'ip'=>$gc['nd']['ip_address']??'—','os_icon'=>$gc['nd']['os_icon']??'generic','hw'=>'','location'=>$gc['nd']['location']??''];
            $d   = $device_map[$id] ?? null;
            $status_str = !$d ? 'unknown' : ($d['state'] ?? ((int)$d['status'] === 1 ? 'up' : 'down'));
            $uptime_str = $d ? fmt_uptime($d['uptime'] ?? 0) : '—';

            $p_up = 0; $p_total = 0;
            if (!empty($ports_map[$id])) foreach ($ports_map[$id] as $p) {
                $p_total++;
                if (strtolower($p['ifAdminStatus'] ?? '') === 'down') continue;
                if (strtolower($p['ifOperStatus']  ?? '') === 'up') $p_up++;
            }

            $cpu_val = null;
            if (!empty($health_map[$id]['cpu'])) {
                $usages  = array_column($health_map[$id]['cpu'], 'processor_usage');
                $cpu_val = count($usages) ? (int)round(array_sum($usages) / count($usages)) : null;
            }
            $mem_val = null;
            if (!empty($health_map[$id]['mem'])) {
                $mems    = array_column($health_map[$id]['mem'], 'mempool_perc');
                $mem_val = count($mems) ? (int)round(array_sum($mems) / count($mems)) : null;
            }

            // Selected interface traffic for this node
            $sel_ifaces = $NM_IFACES[$id] ?? [];
            // Find port data for selected interfaces
            $iface_traffic = [];
            foreach ($sel_ifaces as $si) {
                $pid = (int)($si['lnms_port_id'] ?: $si['id']);   // native nodes use nm_interfaces.id
                if (!empty($ports_map[$id])) {
                    foreach ($ports_map[$id] as $p) {
                        if ((int)$p['port_id'] === $pid) {
                            $iface_traffic[] = [
                                'name'  => $si['display_name'] ?: $si['if_name'],
                                'in'    => $p['ifInOctets_rate']  ?? null,
                                'out'   => $p['ifOutOctets_rate'] ?? null,
                                'oper'  => strtolower($p['ifOperStatus'] ?? 'unknown'),
                                'pid'   => $pid,
                            ];
                            break;
                        }
                    }
                }
            }

            $type_class = [
                'linux'=>'badge-linux','mikrotik'=>'badge-mikrotik',
                'cisco'=>'badge-cisco','generic'=>'badge-generic','ping'=>'badge-ping',
            ][$def['os_icon']] ?? 'badge-generic';

            $cpu_c = $cpu_val !== null ? ($cpu_val>80?'#e74c3c':($cpu_val>60?'#f39c12':'#2ecc71')) : '#555';
            $mem_c = $mem_val !== null ? ($mem_val>85?'#e74c3c':($mem_val>70?'#f39c12':'#2ecc71')) : '#555';
        ?>
            <div class="device-card status-<?= $status_str ?>" data-dev="<?= $id ?>" onclick="openDevice(<?= $id ?>)" title="Jump to detail for <?= htmlspecialchars($def['name']) ?>">
                <div style="display:flex;align-items:flex-start;gap:8px;">
                    <div class="status-dot <?= $status_str ?>" style="margin-top:4px;flex-shrink:0;"></div>
                    <div style="flex:1;min-width:0;">
                        <div class="device-card-name"><?= htmlspecialchars($def['name']) ?></div>
                        <div class="device-card-ip"><?= htmlspecialchars($def['ip']) ?></div>
                    </div>
                    <span class="type-badge <?= $type_class ?>"><?= strtoupper($def['os_icon']) ?></span>
                </div>

                <?php if ($cpu_val !== null || $mem_val !== null): ?>
                <div style="margin-top:10px;display:flex;flex-direction:column;gap:5px;">
                    <?php if ($cpu_val !== null): ?>
                    <div style="display:flex;align-items:center;gap:6px;font-size:10px;">
                        <span style="color:#888;width:28px;">CPU</span>
                        <div style="flex:1;height:4px;background:rgba(255,255,255,.1);border-radius:2px;overflow:hidden;">
                            <div class="cpu-bar" style="width:<?= $cpu_val ?>%;height:100%;background:<?= $cpu_c ?>;border-radius:2px;transition:width .6s ease;"></div>
                        </div>
                        <span class="cpu-val" style="color:<?= $cpu_c ?>;width:28px;text-align:right;"><?= $cpu_val ?>%</span>
                    </div>
                    <?php endif; if ($mem_val !== null): ?>
                    <div style="display:flex;align-items:center;gap:6px;font-size:10px;">
                        <span style="color:#888;width:28px;">Mem</span>
                        <div style="flex:1;height:4px;background:rgba(255,255,255,.1);border-radius:2px;overflow:hidden;">
                            <div class="mem-bar" style="width:<?= $mem_val ?>%;height:100%;background:<?= $mem_c ?>;border-radius:2px;transition:width .6s ease;"></div>
                        </div>
                        <span class="mem-val" style="color:<?= $mem_c ?>;width:28px;text-align:right;"><?= $mem_val ?>%</span>
                    </div>
                    <?php endif; ?>
                </div>
                <?php endif; ?>

                <?php if ($iface_traffic): ?>
                <div style="margin-top:10px;border-top:1px solid rgba(255,255,255,.07);padding-top:8px;">
                    <?php foreach (array_slice($iface_traffic, 0, 3) as $it): ?>
                    <div style="display:flex;justify-content:space-between;font-size:10px;margin-bottom:3px;gap:4px;" data-pid="<?= $it['pid'] ?>">
                        <span style="color:#666;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:80px;" title="<?= htmlspecialchars($it['name']) ?>"><?= htmlspecialchars($it['name']) ?></span>
                        <span style="color:#2ecc71;white-space:nowrap;">↑<span class="t-out"><?= fmt_rate($it['out']) ?></span></span>
                        <span style="color:#4da3ff;white-space:nowrap;">↓<span class="t-in"><?= fmt_rate($it['in']) ?></span></span>
                    </div>
                    <?php endforeach; ?>
                    <?php if (count($iface_traffic) > 3): ?>
                    <div style="font-size:10px;color:#555;text-align:center;">+<?= count($iface_traffic)-3 ?> more…</div>
                    <?php endif; ?>
                </div>
                <?php endif; ?>

                <div class="device-card-meta" style="margin-top:8px;">
                    <?php if (isset($d['latency']) && $d['latency'] !== null): ?>
                        <span class="dev-latency"><i class="fas fa-stopwatch" style="color:#4da3ff;"></i> <?= round((float)$d['latency']) ?> ms<?php if (!empty($d['packet_loss']) && (float)$d['packet_loss'] > 0): ?> · <?= round((float)$d['packet_loss']) ?>% loss<?php endif; ?></span>
                    <?php endif; ?>
                    <?php if ($uptime_str !== '—'): ?>
                        <span><i class="fas fa-clock" style="color:#4da3ff;"></i> <?= $uptime_str ?></span>
                    <?php endif; ?>
                    <?php if ($p_total > 0): ?>
                        <span><i class="fas fa-ethernet"></i> <?= $p_up ?>/<?= $p_total ?> ports</span>
                    <?php endif; ?>
                    <?php if ($def['location']): ?>
                        <span style="color:#666;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><i class="fas fa-map-marker-alt"></i> <?= htmlspecialchars($def['location']) ?></span>
                    <?php endif; ?>
                </div>

                <?php
                // Ping-only devices have no interfaces — give them a direct button to
                // the real-time ICMP monitor instead of the (empty) interface views.
                $_isPingCard = (($NM_NODES[$id]['monitor_type'] ?? '') === 'ping') || ($def['os_icon'] === 'ping');
                $_pingNodeId = (int)($NM_NODES[$id]['id'] ?? 0);
                if ($_isPingCard && $_pingNodeId): ?>
                <a href="live_ping.php?node=<?= $_pingNodeId ?>" onclick="event.stopPropagation();"
                   style="margin-top:10px;display:flex;align-items:center;justify-content:center;gap:7px;
                          background:rgba(77,163,255,.15);border:1px solid rgba(77,163,255,.4);color:#4da3ff;
                          padding:7px;border-radius:8px;text-decoration:none;font-size:11px;font-weight:600;"
                   title="Open real-time ping monitor">
                    <i class="fas fa-satellite-dish"></i> Live Ping
                </a>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
        </div>
    </div>
    <?php endforeach; ?>


    <!-- ── Bento: Alerts + Top Traffic ───────────────────────────────────────── -->
    <div class="bento-grid" style="margin-bottom:15px;">

        <!-- Active Alerts -->
        <div class="glass-card span-2">
            <h2 style="justify-content:space-between;">
                <span>
                    <i class="fas fa-bell"></i> Active Alerts
                    <span class="badge badge-down" id="alerts-badge" style="margin-left:8px;<?= $summary['alerts'] > 0 ? '' : 'display:none;' ?>"><?= $summary['alerts'] ?></span>
                </span>
                <span style="font-size:11px;color:#666;font-weight:400;">infra · AI · containers</span>
            </h2>
            <div style="max-height:260px;overflow-y:auto;" id="alerts-list">
            <?php if (empty($alerts)): ?>
                <div style="color:var(--up);padding:20px 0;text-align:center;" id="alerts-empty">
                    <i class="fas fa-check-circle" style="font-size:28px;margin-bottom:8px;display:block;"></i>
                    All clear — no active alerts
                </div>
            <?php else: ?>
                <?php foreach ($alerts as $al):
                    $sev = strtolower($al['severity'] ?? 'warning');
                    $sev_class  = $sev === 'critical' ? 'sev-critical' : ($sev === 'ok' ? 'sev-ok' : 'sev-warning');
                    $dev_name   = $DEVICES[$al['device_id'] ?? 0]['name'] ?? "Device #{$al['device_id']}";
                ?>
                <div class="alert-row">
                    <span class="alert-sev <?= $sev_class ?>"><?= strtoupper($sev) ?></span>
                    <div class="alert-info">
                        <b><?= htmlspecialchars($al['name'] ?? 'Alert') ?></b><br>
                        <small><?= htmlspecialchars($dev_name) ?> &bull; <?= htmlspecialchars($al['timestamp'] ?? '') ?></small>
                    </div>
                </div>
                <?php endforeach; ?>
            <?php endif; ?>
            </div>
        </div>

        <!-- AI insights + container errors → merged into Active Alerts above -->
        <script>
        document.addEventListener('DOMContentLoaded', function(){
            const list = document.getElementById('alerts-list');
            if (!list) return;
            const e   = s => (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
            const CLS = {critical:'sev-critical',warning:'sev-warning',info:'sev-info'};
            // normalize varied severity vocab (ERROR/FAILED/FATAL → critical, etc.)
            const norm = s => { s=(s||'').toLowerCase();
                if (['critical','error','failed','fatal','down','crit'].includes(s)) return 'critical';
                if (['warning','warn'].includes(s)) return 'warning';
                if (s==='info') return 'info';
                return 'warning'; };
            const ago = sec => { sec=+sec||0; if(sec<60)return sec+'s ago'; const m=(sec/60)|0; if(m<60)return m+'m ago';
                                 const h=(m/60)|0; if(h<24)return h+'h ago'; return ((h/24)|0)+'d ago'; };
            let extra = 0;
            function bump(n){
                extra += n;
                const sv = document.getElementById('stat-alerts-val');
                const base = sv ? (+sv.dataset.base||0) : 0, total = base + extra;
                const b = document.getElementById('alerts-badge');
                if (b){ b.textContent = total; b.style.display = total>0 ? '' : 'none'; }
                if (sv){ sv.textContent = total; const card=document.getElementById('stat-alerts');
                    if (card){ card.classList.toggle('stat-warn', total>0); card.classList.toggle('stat-up', total===0); } }
            }
            function inject(html){
                const empty = document.getElementById('alerts-empty'); if (empty) empty.remove();
                list.insertAdjacentHTML('afterbegin', html);
            }
            function row(o){   // {sev,title,pill,meta,href}
                return `<a class="alert-row" href="${o.href}" style="text-decoration:none;color:inherit;">
                    <span class="alert-sev ${CLS[norm(o.sev)]||'sev-warning'}">${e((o.sev||'').toUpperCase())}</span>
                    <div class="alert-info"><b>${e(o.title)}${o.pill?`<span class="ai-pill">${e(o.pill)}</span>`:''}</b><br>
                    <small>${e(o.meta)}</small></div></a>`;
            }
            const CAP = 25;
            // ── AI Insights ──
            fetch('ai_insights.php?api=list&status=active&severity=all').then(r=>r.json()).then(r=>{
                const I = r.insights||[]; if (!I.length) return;
                I.slice(0,CAP).reverse().forEach(x => inject(row({
                    sev:x.severity, title:x.title, pill:'AI',
                    meta:`${x.node_name||'network-wide'} · ${x.kind||'insight'} · ${ago(x.age_sec)}`,
                    href:'ai_insights.php'
                })));
                bump(I.length);
            }).catch(()=>{});
            // ── Container errors ──
            fetch('container_errors.php?api=data&status=active&severity=').then(r=>r.json()).then(r=>{
                const I = r.incidents||[]; if (!I.length) return;
                const n = (r.summary && r.summary.active) ? r.summary.active : I.length;
                I.slice(0,CAP).reverse().forEach(x => inject(row({
                    sev:x.severity, title:`${x.container_name||'container'}: ${(x.ai_summary||x.error_text||'error').slice(0,90)}`,
                    pill:'CONTAINER',
                    meta:`${x.host||''}${x.occurrences>1?' · ×'+x.occurrences:''} · ${x.status}`,
                    href:'container_errors.php?focus='+x.id
                })));
                bump(n);
            }).catch(()=>{});
            // ── Router config drift ──
            fetch('config_mgr.php?api=dash_changes').then(r=>r.json()).then(r=>{
                const I = r.changes||[]; if (!I.length) return;
                I.slice(0,CAP).reverse().forEach(x => inject(row({
                    sev:'warning', title:`Config changed: ${x.name}`, pill:'CONFIG',
                    meta:`${x.host_ip||''} · ${x.vendor_key||''} · +${x.added}/-${x.removed} · ${x.detected_at}`,
                    href:'config_mgr.php?focus='+x.id
                })));
                bump(I.length);
            }).catch(()=>{});
            // ── NetFlow bandwidth anomalies ──
            fetch('netflow.php?api=dash_alerts').then(r=>r.json()).then(r=>{
                const I = (r.alerts)||[]; if (!I.length) return;
                I.slice(0,CAP).reverse().forEach(x => inject(row({
                    sev:x.severity, title:`High bandwidth: ${x.scope}`, pill:'NETFLOW',
                    meta:`${(+x.value_mbps).toFixed(1)} Mbps · threshold ${(+x.threshold_mbps).toFixed(1)} · since ${x.opened_at}`,
                    href:'netflow.php'
                })));
                bump(I.length);
            }).catch(()=>{});
        });
        </script>

        <!-- Top Traffic -->
        <div class="glass-card span-2">
            <h2><i class="fas fa-tachometer-alt"></i> Top Traffic Interfaces</h2>
            <?php
            $traffic_list = [];
            foreach ($ports_map as $dev_id => $ports) {
                if (!$ports) continue;
                foreach ($ports as $p) {
                    $in    = (float)($p['ifInOctets_rate']  ?? 0);
                    $out   = (float)($p['ifOutOctets_rate'] ?? 0);
                    $total = $in + $out;
                    if ($total < 1) continue;
                    $traffic_list[] = [
                        'device'  => $DEVICES[$dev_id]['name'] ?? "ID:$dev_id",
                        'iface'   => $p['ifName'] ?: ($p['ifDescr'] ?: '—'),
                        'in'      => $in, 'out' => $out, 'total' => $total,
                        'port_id' => (int)($p['port_id'] ?? 0),
                        'dev_id'  => $dev_id,
                    ];
                }
            }
            usort($traffic_list, fn($a, $b) => $b['total'] <=> $a['total']);
            $top_traffic = array_slice($traffic_list, 0, 9);
            $max_total   = $top_traffic ? max(array_column($top_traffic, 'total')) : 1;
            ?>
            <?php if (empty($top_traffic)): ?>
                <div style="color:#aaa;text-align:center;padding:20px 0;">No traffic data</div>
            <?php else: ?>
            <table class="traffic-table">
                <thead><tr style="font-size:10px;color:#555;text-transform:uppercase;">
                    <td>Device / Interface</td><td>In</td><td>Out</td>
                </tr></thead>
                <tbody id="top-traffic-body">
                <?php foreach ($top_traffic as $t):
                    $pct = $max_total > 0 ? round($t['total'] / $max_total * 100) : 0;
                ?>
                <tr style="cursor:pointer;" onclick="openDevice(<?= $t['dev_id'] ?>)">
                    <td>
                        <b style="font-size:12px;"><?= htmlspecialchars($t['device']) ?></b>
                        <span style="color:#aaa;font-size:11px;font-family:monospace;"> &bull; <?= htmlspecialchars($t['iface']) ?></span>
                        <div class="traffic-bar"><div class="traffic-bar-fill" style="width:<?= $pct ?>%"></div></div>
                    </td>
                    <td style="color:var(--up);font-size:11px;font-family:monospace;"><?= fmt_rate($t['in']) ?></td>
                    <td style="color:var(--accent);font-size:11px;font-family:monospace;"><?= fmt_rate($t['out']) ?></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>

    </div><!-- /bento-grid -->

    <!-- ── Container Network — Top Talkers (from container_net_samples history) ─── -->
    <?php $ctop = nm_netstats_top($conn, 0, 1, 10); $cmax = $ctop ? max(array_map(fn($x)=>$x['avg'], $ctop)) : 1; ?>
    <div class="glass-card" style="margin-bottom:15px;">
        <h2 style="justify-content:space-between;">
            <span><i class="fab fa-docker" style="color:#0db7ed;"></i> Container Network — Top Talkers</span>
            <a href="containers.php?view=network" style="font-size:11px;color:#888;font-weight:400;text-decoration:none;">last hour · live view →</a>
        </h2>
        <?php if (!$ctop): ?>
            <div style="color:#aaa;text-align:center;padding:26px 0;font-size:13px;">
                <i class="fab fa-docker" style="font-size:26px;display:block;margin-bottom:10px;color:#3a3f4a;"></i>
                No container network history yet.
                <div style="font-size:11px;color:#667;margin-top:6px;">Open <a href="containers.php?view=network" style="color:var(--accent);">Containers → Network</a>, or enable the 24/7 recorder
                    (<code style="color:#9aa;">cron_netstats.php</code>) so utilization keeps recording in the background.</div>
            </div>
        <?php else: ?>
        <div class="ctop-grid">
            <?php foreach ($ctop as $c): $pct = $cmax > 0 ? round($c['avg'] / $cmax * 100) : 0;
                  $_cHref = (!empty($c['cid']) && !empty($c['endpoint']))
                          ? 'containers.php?view=detail&endpoint=' . (int)$c['endpoint'] . '&container=' . urlencode($c['cid'])
                          : 'containers.php?view=network'; ?>
            <div class="ctop-row" onclick="location.href='<?= htmlspecialchars($_cHref, ENT_QUOTES) ?>'" title="Open <?= htmlspecialchars($c['name'], ENT_QUOTES) ?> in Containers">
                <div class="ctop-head">
                    <b class="ctop-name"><?= htmlspecialchars($c['name']) ?></b>
                    <span class="ctop-avg"><?= fmt_rate($c['avg']) ?><span style="color:#667;"> avg</span></span>
                </div>
                <div class="traffic-bar" style="width:100%;display:block;margin:6px 0 5px;"><div class="traffic-bar-fill" style="width:<?= $pct ?>%"></div></div>
                <div class="ctop-meta">
                    <span><i class="fas fa-arrow-down" style="color:var(--up);"></i> <?= fmt_bytes($c['rx']) ?></span>
                    <span><i class="fas fa-arrow-up" style="color:var(--accent);"></i> <?= fmt_bytes($c['tx']) ?></span>
                    <span style="margin-left:auto;color:var(--warn);">peak <?= fmt_rate($c['peak']) ?></span>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </div>

    <!-- ── NEURU Command Center (AI Commander V2) live activity ──────────────── -->
    <div class="glass-card span-4" id="aiobot-card" style="display:none;margin-bottom:15px;">
        <h2 style="justify-content:space-between;">
            <span><i class="fas fa-satellite-dish" style="color:#4da3ff;"></i> NEURU Command Center — live activity
                <span id="aiobot-state" style="font-size:11px;font-weight:700;margin-left:8px;"></span></span>
            <a href="autopilotv2.php" style="font-size:11px;color:#4da3ff;font-weight:400;text-decoration:none;">Open Command Center →</a>
        </h2>
        <div id="aiobot-log" style="max-height:230px;overflow:auto;font-size:12.5px;"></div>
    </div>

    <!-- ── Device Detail Accordion ───────────────────────────────────────────── -->
    <div class="glass-card">
        <h2><i class="fas fa-server"></i> Device Details
            <span style="font-size:11px;color:#666;font-weight:400;">interfaces · graphs · health · info</span>
        </h2>

        <?php foreach ($DEVICES as $id => $def):
            $d = $device_map[$id] ?? null;
            $status_str = !$d ? 'unknown' : ($d['state'] ?? ((int)$d['status'] === 1 ? 'up' : 'down'));
            $ports      = $ports_map[$id] ?? null;

            $p_up = 0; $p_down = 0; $p_dis = 0;
            if ($ports) foreach ($ports as $p) {
                $a = strtolower($p['ifAdminStatus'] ?? '');
                $o = strtolower($p['ifOperStatus']  ?? '');
                if ($a === 'down')   $p_dis++;
                elseif ($o === 'up') $p_up++;
                else                 $p_down++;
            }

            $has_issue    = ($p_down > 0 || $status_str === 'down' || $status_str === 'degraded');
            $left_color   = $status_str === 'up' ? 'var(--up)' : ($status_str === 'down' ? 'var(--down)' : ($status_str === 'degraded' ? 'var(--warn)' : '#555'));

            $graphs = [];
            if ($def['os_icon'] !== 'ping') {
                $graphs[] = ['key' => 'bits',      'label' => 'Traffic',   'type' => 'device_bits'];
                $graphs[] = ['key' => 'processor', 'label' => 'CPU',       'type' => 'device_processor'];
                $graphs[] = ['key' => 'mempool',   'label' => 'Memory',    'type' => 'device_mempool'];
                $graphs[] = ['key' => 'storage',   'label' => 'Storage',   'type' => 'device_storage'];
                $graphs[] = ['key' => 'uptime',    'label' => 'Uptime',    'type' => 'device_uptime'];
            }
            $graphs[] = ['key' => 'ping', 'label' => 'Ping / Latency', 'type' => 'device_ping'];
        ?>
        <div class="dev-accordion" id="acc-<?= $id ?>">
            <div class="dev-accordion-header" id="acchdr-<?= $id ?>" data-dev-row="<?= $id ?>"
                 onclick="toggleAccordion(<?= $id ?>)"
                 style="border-left: 3px solid <?= $left_color ?>;">
                <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                    <span class="dev-row-dot" style="width:8px;height:8px;border-radius:50%;background:<?= $left_color ?>;display:inline-block;flex-shrink:0;"></span>
                    <span style="font-family:monospace;color:#555;font-size:12px;">[<?= $id ?>]</span>
                    <span style="font-size:14px;"><?= htmlspecialchars($def['name']) ?></span>
                    <span style="font-size:12px;color:#888;font-family:monospace;"><?= htmlspecialchars($def['ip']) ?></span>
                    <?php if ($d && !empty($d['hardware'])): ?>
                        <span style="font-size:11px;color:#aaa;"><?= htmlspecialchars($d['hardware']) ?></span>
                    <?php elseif ($def['hw'] !== '—'): ?>
                        <span style="font-size:11px;color:#555;"><?= htmlspecialchars($def['hw']) ?></span>
                    <?php endif; ?>
                    <?php if ($d && !empty($d['os'])): ?>
                        <span style="font-size:11px;color:#aaa;"><?= htmlspecialchars($d['os'] . ' ' . ($d['version'] ?? '')) ?></span>
                    <?php endif; ?>
                    <?php if ($def['location'] && $def['location'] !== '—'): ?>
                        <span style="font-size:11px;color:#555;"><i class="fas fa-map-marker-alt"></i> <?= htmlspecialchars($def['location']) ?></span>
                    <?php endif; ?>
                </div>
                <div style="display:flex;align-items:center;gap:8px;flex-shrink:0;">
                    <span class="dev-row-badges" style="display:flex;align-items:center;gap:8px;">
                    <?php if ($ports !== null): ?>
                        <span class="badge badge-up"><?= $p_up ?> up</span>
                        <?php if ($p_down): ?><span class="badge badge-down"><?= $p_down ?> down</span><?php endif; ?>
                        <?php if ($p_dis):  ?><span class="badge badge-dis"><?= $p_dis ?>  dis</span><?php endif; ?>
                    <?php endif; ?>
                    </span>
                    <?php if ($d && !empty($d['uptime'])): ?>
                        <span style="font-size:11px;color:#aaa;"><i class="fas fa-clock" style="color:var(--accent);"></i> <?= fmt_uptime($d['uptime']) ?></span>
                    <?php endif; ?>
                    <i class="fas fa-chevron-down" id="chev-<?= $id ?>" style="color:#aaa;transition:transform 0.2s;"></i>
                </div>
            </div>

            <div class="dev-accordion-body <?= $has_issue ? 'open' : '' ?>" id="body-<?= $id ?>">
                <div class="dev-accordion-inner">
                    <!-- Tab Bar -->
                    <div class="tab-bar" id="tabs-<?= $id ?>" data-node-id="<?= (int)($NM_NODES[$id]['id']??0) ?>">
                        <button class="tab-btn active" onclick="switchTab(<?= $id ?>,'interfaces')"><i class="fas fa-ethernet"></i> Interfaces</button>
                        <button class="tab-btn" onclick="switchTab(<?= $id ?>,'graphs')"><i class="fas fa-chart-area"></i> Graphs</button>
                        <button class="tab-btn" onclick="switchTab(<?= $id ?>,'health')"><i class="fas fa-heartbeat"></i> Health</button>
                        <button class="tab-btn" onclick="switchTab(<?= $id ?>,'info')"><i class="fas fa-info-circle"></i> Device Info</button>
                        <?php
                        $_node = $NM_NODES[$id] ?? [];
                        $_nid  = (int)($_node['id'] ?? 0);
                        $_osic = $def['os_icon'] ?? ($_node['os_icon'] ?? 'generic');
                        // one classifier resolves the right destination: Windows/Linux → immersive
                        // Command Center when adopted, else router/ping/generic → router_details.php.
                        $_cc = $_nid ? nm_node_cc($_node, $WIN_HOSTS[$_nid] ?? null, $LX_HOSTS[$_nid] ?? null) : null;
                        $_ccUrl = $_cc['url'] ?? null; $_ccLbl = $_cc['label'] ?? ''; $_ccIcon = $_cc['icon'] ?? 'fa-circle-info';
                        $_ccKind = $_cc['kind'] ?? ''; $_ccIsScreen = in_array($_ccKind, ['windows','linux'], true) && strpos((string)$_ccUrl, '_screen.php') !== false;
                        // netstat over SSH only for adopted Windows/Linux hosts (unchanged)
                        $_nsUrl = null;
                        if ($_nid && $_osic === 'windows' && !empty($WIN_HOSTS[$_nid]))      $_nsUrl = 'netstat.php?target=win:' . (int)$WIN_HOSTS[$_nid];
                        elseif ($_nid && $_osic === 'linux' && !empty($LX_HOSTS[$_nid]))     $_nsUrl = 'netstat.php?target=lx:' . (int)$LX_HOSTS[$_nid];
                        ?>
                        <?php if ($_nid): ?>
                        <button type="button" onclick="pollNow(<?= $_nid ?>, this)"
                           class="tab-btn poll-now-btn" style="margin-left:auto;background:rgba(77,163,255,.1);border-color:rgba(77,163,255,.35);color:#4da3ff;"
                           title="Force a fresh SNMP poll of this device now">
                            <i class="fas fa-rotate"></i> <span class="pn-lbl">Poll now</span>
                        </button>
                        <?php endif; ?>
                        <?php if ($_ccUrl): ?>
                        <a href="<?= htmlspecialchars($_ccUrl) ?>"
                           class="tab-btn" style="text-decoration:none;<?= $_ccIsScreen
                               ? 'background:rgba(155,89,255,.12);border-color:rgba(155,89,255,.4);color:#b388ff;'
                               : 'background:rgba(77,163,255,.12);border-color:rgba(77,163,255,.4);color:#7bb8ff;' ?>"
                           title="<?= $_ccIsScreen ? 'Open the immersive Command Center for this host' : 'Open the full device / asset details page' ?>">
                            <i class="fas <?= htmlspecialchars($_ccIcon) ?>"></i> <?= htmlspecialchars($_ccLbl) ?>
                        </a>
                        <?php endif; ?>
                        <?php if ($_nid && $_ccKind === 'router'): ?>
                        <a href="routers.php?node=<?= $_nid ?>"
                           class="tab-btn" style="text-decoration:none;background:rgba(54,227,208,.1);border-color:rgba(54,227,208,.4);color:#36e3d0;"
                           title="Open this router in the Router Monitor (fleet view), preselected">
                            <i class="fas fa-route"></i> Router Monitor
                        </a>
                        <?php endif; ?>
                        <?php if ($_nsUrl): ?>
                        <a href="<?= $_nsUrl ?>"
                           class="tab-btn" style="text-decoration:none;background:rgba(0,212,170,.1);border-color:rgba(0,212,170,.4);color:#00d4aa;"
                           title="View this host's live sockets (netstat) over SSH">
                            <i class="fas fa-diagram-project"></i> Netstat
                        </a>
                        <?php endif; ?>
                        <?php if ($_nid): ?>
                        <a href="net_mon_stats.php?node=<?= $_nid ?>"
                           class="tab-btn" style="text-decoration:none;background:rgba(46,204,113,.1);border-color:rgba(46,204,113,.35);color:#2ecc71;">
                            <i class="fas fa-chart-line"></i> Statistics
                        </a>
                        <?php endif; ?>
                    </div>

                    <!-- Tab: Interfaces ──────────────────────────────────────── -->
                    <div class="tab-panel active" id="tab-<?= $id ?>-interfaces">
                        <?php
                        $_nodeDbId    = (int)($NM_NODES[$id]['id'] ?? 0);
                        $_nativePorts = $NATIVE_PORTS[$_nodeDbId] ?? [];
                        ?>
                        <?php if (!empty($_nativePorts)): ?>
                            <!-- Native SNMP poller data (no LibreNMS) -->
                            <div style="margin:2px 0 10px;font-size:11px;color:#888;">
                                <i class="fas fa-database" style="color:var(--accent);"></i>
                                Source: native SNMP poller<?php if (!empty($_nativePorts[0]['polled_at'])): ?> — last poll <?= htmlspecialchars($_nativePorts[0]['polled_at']) ?><?php endif; ?>.
                                In/Out rates populate after two consecutive polls.
                            </div>
                            <div style="overflow-x:auto;">
                            <table class="port-table">
                                <thead>
                                    <tr>
                                        <th>Interface</th><th>Oper</th><th>Speed</th>
                                        <th style="color:var(--up);">In</th><th style="color:var(--accent);">Out</th>
                                        <th>Alias</th><th></th>
                                    </tr>
                                </thead>
                                <tbody>
                                <?php foreach ($_nativePorts as $p):
                                    $oper  = strtolower($p['ifOperStatus']);
                                    $iname = $p['ifName'] ?: '—';
                                    $alias = $p['ifAlias'] ?: '—';
                                    $in    = fmt_rate($p['ifInOctets_rate']  ?? null);
                                    $out   = fmt_rate($p['ifOutOctets_rate'] ?? null);
                                    $speed = !empty($p['ifSpeed']) ? number_format($p['ifSpeed'] / 1_000_000, 0) . ' Mbps' : '—';
                                    $pid   = (int)$p['port_id'];
                                    $oper_html = ($oper === 'up')
                                        ? '<span class="st-up"><i class="fas fa-circle" style="font-size:8px;"></i> up</span>'
                                        : '<span class="st-down"><i class="fas fa-times-circle"></i> ' . htmlspecialchars($oper) . '</span>';
                                ?>
                                <tr style="<?= $oper === 'up' ? '' : 'opacity:0.5;' ?>">
                                    <td style="font-weight:600;">
                                        <?php if ($_nodeDbId && $pid): ?>
                                            <a href="live_mon.php?node=<?= $_nodeDbId ?>&iface=<?= $pid ?>"
                                               style="color:#e0e0e0;text-decoration:none;border-bottom:1px dashed rgba(255,255,255,0.2);"
                                               title="Open live monitor for this interface">
                                                <?= htmlspecialchars($iname) ?>
                                            </a>
                                        <?php else: ?>
                                            <?= htmlspecialchars($iname) ?>
                                        <?php endif; ?>
                                    </td>
                                    <td><?= $oper_html ?></td>
                                    <td style="color:#aaa;"><?= $speed ?></td>
                                    <td style="color:var(--up);"><?= htmlspecialchars($in) ?></td>
                                    <td style="color:var(--accent);"><?= htmlspecialchars($out) ?></td>
                                    <td style="color:#555;font-size:11px;"><?= htmlspecialchars($alias) ?></td>
                                    <td>
                                        <?php if ($_nodeDbId && $pid): ?>
                                        <a class="tab-btn" style="padding:3px 8px;font-size:10px;text-decoration:none;"
                                           href="net_mon_stats.php?node=<?= $_nodeDbId ?>&port=<?= $pid ?>">
                                            <i class="fas fa-chart-line"></i>
                                        </a>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                                </tbody>
                            </table>
                            </div>
                        <?php elseif (!empty($d['monitor']) && $d['monitor'] === 'ping'): ?>
                            <div style="color:#aaa;padding:14px;text-align:center;">
                                <i class="fas fa-satellite-dish" style="color:#4da3ff;"></i>
                                Ping-only node — reachability monitored via ICMP<?php if (isset($d['latency']) && $d['latency'] !== null): ?>
                                (last <?= round((float)$d['latency']) ?> ms, <?= round((float)($d['packet_loss'] ?? 0)) ?>% loss)<?php endif; ?>.
                                No SNMP interfaces are collected for this node.
                                <?php $_pnid = (int)($NM_NODES[$id]['id'] ?? 0); if ($_pnid): ?>
                                <div style="margin-top:12px;">
                                    <a href="live_ping.php?node=<?= $_pnid ?>"
                                       style="display:inline-flex;align-items:center;gap:8px;background:rgba(77,163,255,.15);
                                              border:1px solid rgba(77,163,255,.4);color:#4da3ff;padding:8px 16px;
                                              border-radius:8px;text-decoration:none;font-size:12px;font-weight:600;">
                                        <i class="fas fa-satellite-dish"></i> Open Live Ping Monitor
                                    </a>
                                </div>
                                <?php endif; ?>
                            </div>
                        <?php elseif ($ports === null): ?>
                            <div style="color:#e74c3c;padding:10px;"><i class="fas fa-exclamation-triangle"></i> No port data — device may be unreachable or not running SNMP.</div>
                        <?php elseif (empty($ports)): ?>
                            <div style="color:#aaa;padding:10px;">No interfaces returned for this device.</div>
                        <?php else: ?>
                        <div style="overflow-x:auto;">
                        <table class="port-table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Interface</th>
                                    <th>Type</th>
                                    <th>Admin</th>
                                    <th>Oper</th>
                                    <th>Speed</th>
                                    <th style="color:var(--up);">In</th>
                                    <th style="color:var(--accent);">Out</th>
                                    <th>Alias</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                            <?php
                            /* Filter to only show interfaces saved for monitoring */
                            $_spids   = array_flip(array_map('intval', array_column($NM_IFACES[$id]??[], 'lnms_port_id')));
                            $_fports  = $_spids
                                ? array_values(array_filter($ports, fn($p) => isset($_spids[(int)($p['port_id']??0)])))
                                : [];
                            if (empty($_fports)): ?>
                            <tr><td colspan="10" style="text-align:center;color:#888;padding:20px;font-size:12px;">
                                <i class="fas fa-info-circle"></i>
                                No interfaces selected for monitoring on this device.
                                <a href="net_mon_config.php" style="color:#4da3ff;margin-left:4px;">Configure in settings</a>
                            </td></tr>
                            <?php else: foreach ($_fports as $p):
                                $admin    = strtolower($p['ifAdminStatus'] ?? 'unknown');
                                $oper     = strtolower($p['ifOperStatus']  ?? 'unknown');
                                $iname    = $p['ifName'] ?: ($p['ifDescr'] ?: '—');
                                $alias    = $p['ifAlias'] ?: '—';
                                $in       = fmt_rate($p['ifInOctets_rate']  ?? null);
                                $out      = fmt_rate($p['ifOutOctets_rate'] ?? null);
                                $speed    = !empty($p['ifSpeed']) ? number_format($p['ifSpeed'] / 1_000_000, 0) . ' Mbps' : '—';
                                $port_id  = (int)($p['port_id'] ?? 0);

                                if ($admin === 'down') {
                                    $admin_html = '<span class="st-dis"><i class="fas fa-lock"></i> disabled</span>';
                                    $row_style  = 'opacity:0.45;';
                                } else {
                                    $admin_html = '<span class="st-up"><i class="fas fa-check"></i> up</span>';
                                    $row_style  = '';
                                }
                                $oper_html = ($oper === 'up')
                                    ? '<span class="st-up"><i class="fas fa-circle" style="font-size:8px;"></i> up</span>'
                                    : '<span class="st-down"><i class="fas fa-times-circle"></i> ' . htmlspecialchars($oper) . '</span>';
                            ?>
                            <tr style="<?= $row_style ?>">
                                <td style="color:#444;"><?= $port_id ?></td>
                                <td style="font-weight:600;">
                                    <?php if ($port_id): ?>
                                        <a href="live_mon.php?device=<?= $id ?>&port=<?= $port_id ?>"
                                           style="color:#e0e0e0;text-decoration:none;border-bottom:1px dashed rgba(255,255,255,0.2);"
                                           title="Open live monitor for this interface">
                                            <?= htmlspecialchars($iname) ?>
                                        </a>
                                    <?php else: ?>
                                        <?= htmlspecialchars($iname) ?>
                                    <?php endif; ?>
                                </td>
                                <td style="color:#666;font-size:11px;"><?= htmlspecialchars($p['ifType'] ?? '—') ?></td>
                                <td><?= $admin_html ?></td>
                                <td><?= $oper_html ?></td>
                                <td style="color:#aaa;"><?= $speed ?></td>
                                <td style="color:var(--up);"><?= htmlspecialchars($in) ?></td>
                                <td style="color:var(--accent);"><?= htmlspecialchars($out) ?></td>
                                <td style="color:#555;font-size:11px;"><?= htmlspecialchars($alias) ?></td>
                                <td>
                                    <?php if ($port_id && $oper === 'up'): ?>
                                    <button class="tab-btn" style="padding:3px 8px;font-size:10px;"
                                            onclick="showPortGraph(<?= $port_id ?>,<?= $id ?>)">
                                        <i class="fas fa-chart-line"></i>
                                    </button>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endforeach; endif; ?>
                            </tbody>
                        </table>
                        </div>
                        <?php endif; ?>
                    </div>

                    <!-- Tab: Graphs (Chart.js from DB) ──────────────────────── -->
                    <?php
                    $node_id_g   = (int)($NM_NODES[$id]['id'] ?? 0);
                    $_isPingG    = ($NM_NODES[$id]['monitor_type'] ?? 'snmp') === 'ping';
                    $dev_ifaces  = array_values(array_filter($NM_IFACES[$id] ?? [], fn($i) => (int)$i['show_graph'] === 1));
                    $ports_json  = htmlspecialchars(json_encode(array_map(
                        fn($i) => ['pid'=>(int)$i['id'], 'name'=>$i['display_name']?:$i['if_name']?:"Port {$i['id']}"],
                        $dev_ifaces
                    )), ENT_QUOTES);
                    ?>
                    <div class="tab-panel" id="tab-<?= $id ?>-graphs"
                         data-node-id="<?= $node_id_g ?>"
                         data-monitor="<?= $_isPingG ? 'ping' : 'snmp' ?>"
                         data-ports="<?= $ports_json ?>">

                        <!-- Range selector -->
                        <div style="display:flex;gap:6px;margin-bottom:14px;align-items:center;flex-wrap:wrap;">
                            <span style="font-size:11px;color:#666;text-transform:uppercase;letter-spacing:.8px;">Range:</span>
                            <?php foreach(['1h'=>'1H','6h'=>'6H','24h'=>'1D','7d'=>'7D','30d'=>'30D'] as $r=>$rl): ?>
                            <button class="range-btn <?= $r==='24h'?'active':'' ?>"
                                    onclick="setDevRange(<?= $id ?>,'<?= $r ?>',this)">
                                <?= $rl ?>
                            </button>
                            <?php endforeach; ?>
                            <?php if ($node_id_g): ?>
                            <a href="net_mon_stats.php?node=<?= $node_id_g ?>"
                               style="margin-left:auto;font-size:11px;color:#4da3ff;text-decoration:none;">
                                <i class="fas fa-chart-area"></i> Full Stats
                            </a>
                            <?php endif; ?>
                        </div>

                        <?php if ($_isPingG): ?>
                        <!-- Ping latency / availability chart (ping-only node) -->
                        <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#555;margin-bottom:8px;">
                            <i class="fas fa-satellite-dish" style="color:var(--accent);"></i> ICMP Reachability (from DB)
                        </div>
                        <div class="graph-block">
                            <div class="graph-block-title">
                                <span>Latency &amp; Availability — <?= htmlspecialchars($NM_NODES[$id]['ip_address'] ?? '') ?></span>
                                <span id="pingst-<?= $id ?>" style="font-size:10px;color:#555;"></span>
                            </div>
                            <div style="position:relative;height:180px;padding:4px;">
                                <canvas id="ping-<?= $id ?>"></canvas>
                            </div>
                            <div id="pingleg-<?= $id ?>"
                                 style="padding:6px 12px;font-size:10px;color:#666;border-top:1px solid rgba(255,255,255,.05);min-height:26px;"></div>
                        </div>
                        <?php else: ?>

                        <!-- Per-interface traffic charts -->
                        <?php if ($dev_ifaces): ?>
                        <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#555;margin-bottom:8px;">
                            <i class="fas fa-ethernet" style="color:var(--accent);"></i> Interface Traffic (from DB)
                        </div>
                        <div class="graph-grid" style="margin-bottom:16px;">
                            <?php foreach ($dev_ifaces as $ifc):
                                $pid   = (int)$ifc['id'];
                                $dname = htmlspecialchars($ifc['display_name'] ?: $ifc['if_name'] ?: "Port $pid");
                            ?>
                            <div class="graph-block">
                                <div class="graph-block-title">
                                    <span><?= $dname ?></span>
                                    <span id="trfst-<?= $id ?>-<?= $pid ?>" style="font-size:10px;color:#555;"></span>
                                </div>
                                <div style="position:relative;height:100px;padding:4px;">
                                    <canvas id="trf-<?= $id ?>-<?= $pid ?>"></canvas>
                                </div>
                                <div id="trfleg-<?= $id ?>-<?= $pid ?>"
                                     style="padding:6px 12px;font-size:10px;color:#666;border-top:1px solid rgba(255,255,255,.05);display:flex;gap:14px;flex-wrap:wrap;min-height:26px;"></div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                        <?php else: ?>
                        <div style="color:#888;padding:16px;text-align:center;font-size:12px;margin-bottom:12px;">
                            <i class="fas fa-info-circle"></i> No interfaces configured for monitoring.
                            <a href="net_mon_config.php" style="color:#4da3ff;margin-left:6px;">Configure</a>
                        </div>
                        <?php endif; ?>

                        <!-- CPU / Memory / Storage / Custom health charts -->
                        <?php if ($node_id_g): ?>
                        <div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#555;margin-bottom:8px;">
                            <i class="fas fa-heartbeat" style="color:#e74c3c;"></i> Device Health (from DB)
                        </div>
                        <div class="graph-grid">
                            <div class="graph-block">
                                <div class="graph-block-title">
                                    <span>CPU</span>
                                    <span id="cpust-<?= $id ?>" style="font-size:10px;color:#555;"></span>
                                </div>
                                <div style="position:relative;height:90px;padding:4px;">
                                    <canvas id="cpu-<?= $id ?>"></canvas>
                                </div>
                                <div id="cpuleg-<?= $id ?>"
                                     style="padding:6px 12px;font-size:10px;color:#666;border-top:1px solid rgba(255,255,255,.05);min-height:22px;"></div>
                            </div>
                            <div class="graph-block">
                                <div class="graph-block-title">
                                    <span>Memory</span>
                                    <span id="memst-<?= $id ?>" style="font-size:10px;color:#555;"></span>
                                </div>
                                <div style="position:relative;height:90px;padding:4px;">
                                    <canvas id="mem-<?= $id ?>"></canvas>
                                </div>
                                <div id="memleg-<?= $id ?>"
                                     style="padding:6px 12px;font-size:10px;color:#666;border-top:1px solid rgba(255,255,255,.05);min-height:22px;"></div>
                            </div>
                            <div class="graph-block">
                                <div class="graph-block-title">
                                    <span>Storage</span>
                                    <span id="diskst-<?= $id ?>" style="font-size:10px;color:#555;"></span>
                                </div>
                                <div style="position:relative;height:90px;padding:4px;">
                                    <canvas id="disk-<?= $id ?>"></canvas>
                                </div>
                                <div id="diskleg-<?= $id ?>"
                                     style="padding:6px 12px;font-size:10px;color:#666;border-top:1px solid rgba(255,255,255,.05);min-height:22px;"></div>
                            </div>
                            <div class="graph-block" id="custblock-<?= $id ?>" style="display:none;">
                                <div class="graph-block-title">
                                    <span>Custom Sensors</span>
                                    <span id="custst-<?= $id ?>" style="font-size:10px;color:#555;"></span>
                                </div>
                                <div style="position:relative;height:90px;padding:4px;">
                                    <canvas id="cust-<?= $id ?>"></canvas>
                                </div>
                                <div id="custleg-<?= $id ?>"
                                     style="padding:6px 12px;font-size:10px;color:#666;border-top:1px solid rgba(255,255,255,.05);min-height:22px;"></div>
                            </div>
                            <?php if (isset($GPU_NODES[$node_id_g])): ?>
                            <!-- GPU panel — only for nodes registered in the AI/GPU Monitor -->
                            <div class="graph-block" id="gpublock-<?= $id ?>" data-gpu-node="<?= $node_id_g ?>" data-gpu-target="<?= (int)$GPU_NODES[$node_id_g] ?>">
                                <div class="graph-block-title">
                                    <span><i class="fas fa-microchip" style="color:#76b900;"></i> GPU</span>
                                    <a href="gpu.php?target=<?= (int)$GPU_NODES[$node_id_g] ?>" style="font-size:10px;" title="Open the AI / GPU Monitor for this server">dashboard <i class="fas fa-arrow-up-right-from-square"></i></a>
                                </div>
                                <div style="position:relative;height:90px;padding:4px;">
                                    <canvas id="gpu-<?= $id ?>"></canvas>
                                </div>
                                <div id="gpuleg-<?= $id ?>"
                                     style="padding:6px 12px;font-size:10px;color:#666;border-top:1px solid rgba(255,255,255,.05);min-height:22px;">GPU…</div>
                            </div>
                            <?php endif; ?>
                        </div>
                        <?php endif; ?>
                        <?php endif; /* _isPingG */ ?>
                    </div>

                    <!-- Tab: Health ──────────────────────────────────────────── -->
                    <div class="tab-panel" id="tab-<?= $id ?>-health">
                        <?php
                        $cpus = $health_map[$id]['cpu'] ?? null;
                        $mems = $health_map[$id]['mem'] ?? null;
                        $stores = $health_map[$id]['storage'] ?? null;
                        $others = $health_map[$id]['other'] ?? null;
                        ?>
                        <?php if (!$cpus && !$mems && !$stores && !$others): ?>
                            <div style="color:#aaa;padding:14px;text-align:center;">
                                <i class="fas fa-info-circle"></i>
                                No health/sensor data available for this device (may not support SNMP MIBs for CPU/memory/storage).
                            </div>
                        <?php else: ?>
                            <?php if ($cpus): ?>
                            <div style="margin-bottom:18px;">
                                <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#aaa;margin-bottom:10px;">
                                    <i class="fas fa-microchip" style="color:var(--accent);"></i> CPU Processors
                                </div>
                                <?php foreach ($cpus as $cpu):
                                    $pct = (int)($cpu['processor_usage'] ?? 0);
                                    $fc  = $pct > 80 ? 'fill-crit' : ($pct > 60 ? 'fill-warn' : 'fill-ok');
                                    $vc  = $pct > 80 ? '#e74c3c'   : ($pct > 60 ? '#f39c12'   : '#2ecc71');
                                ?>
                                <div class="health-row">
                                    <span style="min-width:160px;font-size:11px;color:#ccc;"><?= htmlspecialchars($cpu['processor_descr'] ?? 'CPU') ?></span>
                                    <div class="health-bar-track"><div class="health-bar-fill <?= $fc ?>" style="width:<?= $pct ?>%"></div></div>
                                    <span style="min-width:38px;text-align:right;font-size:12px;font-weight:700;color:<?= $vc ?>;"><?= $pct ?>%</span>
                                </div>
                                <?php endforeach; ?>
                            </div>
                            <?php endif; ?>

                            <?php if ($mems): ?>
                            <div>
                                <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#aaa;margin-bottom:10px;">
                                    <i class="fas fa-memory" style="color:var(--accent);"></i> Memory Pools
                                </div>
                                <?php foreach ($mems as $mem):
                                    $pct   = (int)($mem['mempool_perc']  ?? 0);
                                    $used  = (int)($mem['mempool_used']  ?? 0);
                                    $total = (int)($mem['mempool_total'] ?? 0);
                                    $fc    = $pct > 90 ? 'fill-crit' : ($pct > 75 ? 'fill-warn' : 'fill-ok');
                                    $vc    = $pct > 90 ? '#e74c3c'   : ($pct > 75 ? '#f39c12'   : '#2ecc71');
                                    $uf    = $used  > 1073741824 ? round($used/1073741824,1).'GB'  : ($used  > 1048576 ? round($used/1048576).'MB'  : ($used  > 1024 ? round($used/1024).'KB'  : $used.'B'));
                                    $tf    = $total > 1073741824 ? round($total/1073741824,1).'GB' : ($total > 1048576 ? round($total/1048576).'MB' : ($total > 1024 ? round($total/1024).'KB' : $total.'B'));
                                ?>
                                <div class="health-row">
                                    <span style="min-width:160px;font-size:11px;color:#ccc;"><?= htmlspecialchars($mem['mempool_descr'] ?? 'Memory') ?></span>
                                    <div class="health-bar-track"><div class="health-bar-fill <?= $fc ?>" style="width:<?= $pct ?>%"></div></div>
                                    <span style="min-width:38px;text-align:right;font-size:12px;font-weight:700;color:<?= $vc ?>;"><?= $pct ?>%</span>
                                    <span style="font-size:11px;color:#555;"><?= $uf ?> / <?= $tf ?></span>
                                </div>
                                <?php endforeach; ?>
                            </div>
                            <?php endif; ?>

                            <?php if ($stores): ?>
                            <div style="margin-top:18px;">
                                <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#aaa;margin-bottom:10px;">
                                    <i class="fas fa-hdd" style="color:var(--accent);"></i> Storage
                                </div>
                                <?php foreach ($stores as $st):
                                    $pct = (int)round($st['storage_perc'] ?? $st['storage_percentage'] ?? 0);
                                    $used = (float)($st['storage_used'] ?? $st['storage_used_bytes'] ?? 0);
                                    $size = (float)($st['storage_size'] ?? $st['storage_total'] ?? $st['storage_total_bytes'] ?? 0);
                                    if ($size <= 0 && $used > 0 && $pct > 0) {
                                        $size = $used / ($pct / 100);
                                    }
                                    $fc = $pct > 90 ? 'fill-crit' : ($pct > 80 ? 'fill-warn' : 'fill-ok');
                                    $vc = $pct > 90 ? '#e74c3c' : ($pct > 80 ? '#f39c12' : '#2ecc71');
                                    $desc = $st['storage_descr'] ?? $st['storage_mnt'] ?? $st['storage_index'] ?? 'Storage';
                                ?>
                                <div class="health-row">
                                    <span style="min-width:160px;font-size:11px;color:#ccc;"><?= htmlspecialchars((string)$desc) ?></span>
                                    <div class="health-bar-track"><div class="health-bar-fill <?= $fc ?>" style="width:<?= $pct ?>%"></div></div>
                                    <span style="min-width:38px;text-align:right;font-size:12px;font-weight:700;color:<?= $vc ?>;"><?= $pct ?>%</span>
                                    <span style="font-size:11px;color:#555;"><?= fmt_bytes($used) ?> / <?= fmt_bytes($size) ?></span>
                                </div>
                                <?php endforeach; ?>
                            </div>
                            <?php endif; ?>

                            <?php if ($others): ?>
                            <div style="margin-top:18px;">
                                <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#aaa;margin-bottom:10px;">
                                    <i class="fas fa-wave-square" style="color:var(--accent);"></i> Other Sensors
                                </div>
                                <?php foreach ($others as $s):
                                    $val = $s['sensor_current'] ?? '—';
                                    $cls = strtoupper((string)($s['sensor_class'] ?? 'sensor'));
                                    $desc = $s['sensor_descr'] ?? $cls;
                                ?>
                                <div class="health-row">
                                    <span style="min-width:160px;font-size:11px;color:#ccc;">
                                        <?= htmlspecialchars($desc) ?>
                                        <span style="color:#666;">(<?= htmlspecialchars($cls) ?>)</span>
                                    </span>
                                    <div class="health-bar-track"><div class="health-bar-fill fill-ok" style="width:100%"></div></div>
                                    <span style="min-width:70px;text-align:right;font-size:12px;font-weight:700;color:#e0e0e0;"><?= htmlspecialchars((string)$val) ?></span>
                                </div>
                                <?php endforeach; ?>
                            </div>
                            <?php endif; ?>
                        <?php endif; ?>
                    </div>

                    <!-- Tab: Device Info ─────────────────────────────────────── -->
                    <div class="tab-panel" id="tab-<?= $id ?>-info">
                        <?php if (!$d): ?>
                            <div style="color:#e74c3c;padding:10px;"><i class="fas fa-exclamation-triangle"></i> Device not found in LibreNMS — check if ID <?= $id ?> exists.</div>
                        <?php else: ?>
                        <div class="info-grid">
                            <?php
                            $info_fields = [
                                'sysName'     => ['label' => 'System Name',  'icon' => 'tag'],
                                'hostname'    => ['label' => 'Hostname',     'icon' => 'server'],
                                'ip'          => ['label' => 'IP Address',   'icon' => 'network-wired'],
                                'hardware'    => ['label' => 'Hardware',     'icon' => 'microchip'],
                                'os'          => ['label' => 'OS',           'icon' => 'code'],
                                'version'     => ['label' => 'OS Version',   'icon' => 'code-branch'],
                                'serial'      => ['label' => 'Serial',       'icon' => 'barcode'],
                                'location'    => ['label' => 'Location',     'icon' => 'map-marker-alt'],
                                'uptime'      => ['label' => 'Uptime',       'icon' => 'clock'],
                                'last_polled' => ['label' => 'Last Polled',  'icon' => 'sync'],
                                'snmpver'     => ['label' => 'SNMP Version', 'icon' => 'plug'],
                                'features'    => ['label' => 'Features',     'icon' => 'star'],
                                'type'        => ['label' => 'Device Type',  'icon' => 'hdd'],
                                'community'   => ['label' => 'SNMP Community','icon' => 'key'],
                            ];
                            foreach ($info_fields as $field => $meta):
                                $val = $d[$field] ?? null;
                                if ($field === 'uptime' && $val) $val = fmt_uptime((int)$val) . ' (' . number_format($val) . 's)';
                                if (!$val || $val === '') continue;
                            ?>
                            <div class="info-cell">
                                <div class="lbl"><i class="fas fa-<?= $meta['icon'] ?>"></i> <?= $meta['label'] ?></div>
                                <div class="val"><?= htmlspecialchars($val) ?></div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                        <?php endif; ?>
                    </div>

                </div><!-- /inner -->
            </div><!-- /body -->
        </div><!-- /accordion -->
        <?php endforeach; ?>

    </div><!-- /device-detail glass-card -->

</div><!-- /page-wrapper -->

<script>
// ── Accordion ─────────────────────────────────────────────────────────────────
function toggleAccordion(id) {
    const body = document.getElementById('body-' + id);
    const chev = document.getElementById('chev-' + id);
    if (!body) return;
    body.classList.toggle('open');
    if (chev) chev.style.transform = body.classList.contains('open') ? 'rotate(180deg)' : '';
}

function openDevice(id) {
    const body = document.getElementById('body-' + id);
    const chev = document.getElementById('chev-' + id);
    const acc  = document.getElementById('acc-'  + id);
    if (!body || !acc) return;
    if (!body.classList.contains('open')) {
        body.classList.add('open');
        if (chev) chev.style.transform = 'rotate(180deg)';
    }
    setTimeout(() => acc.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
}

// ── Per-card "Poll now": force a fresh single-node SNMP poll, then refresh live ──
async function pollNow(nodeId, btn){
    if (!btn || btn.disabled) return;
    const lbl  = btn.querySelector('.pn-lbl');
    const icon = btn.querySelector('i');
    const orig = lbl ? lbl.textContent : '';
    btn.disabled = true; btn.style.opacity = '.75';
    if (icon) icon.classList.add('fa-spin');
    if (lbl)  lbl.textContent = 'Polling…';
    try {
        const r = await fetch('net_mon.php?api=poll_now&node=' + encodeURIComponent(nodeId) + '&_t=' + Date.now(), {credentials:'same-origin'});
        const d = await r.json().catch(()=>null);
        if (d && d.ok) {
            // PRECISE verdict — no more ambiguous "Updated". Say exactly what the device is.
            const map = { up:['● UP','#2ecc71'], degraded:['⚠ REACHABLE · SNMP STALE','#f39c12'], down:['● DOWN','#e74c3c'] };
            const m = map[d.state] || ['Updated','#4da3ff'];
            if (lbl) lbl.textContent = m[0];
            btn.style.color = m[1]; btn.style.borderColor = m[1];
            btn.title = (d.detail || '') + (d.state==='degraded' ? ' — device answers ping; only its SNMP/telemetry is stale (not down).' : '');
            if (window.nmLivePoll) { try { await window.nmLivePoll(); } catch(e){} }   // refresh card values in place
        } else {
            if (lbl) lbl.textContent = 'Failed';
        }
    } catch(e) {
        if (lbl) lbl.textContent = 'Failed';
    } finally {
        if (icon) icon.classList.remove('fa-spin');
        setTimeout(() => { btn.disabled = false; btn.style.opacity = ''; btn.style.color=''; btn.style.borderColor=''; if (lbl) lbl.textContent = orig; }, 3200);
    }
}

// ── Chart.js helpers ──────────────────────────────────────────────────────────
const _NM_CHARTS  = {};
const _DEV_RANGES = {};

function fmtBps(v) {
    if (v === null || v === undefined || isNaN(v)) return '—';
    v = Math.abs(+v);
    if (v >= 1e9)  return (v/1e9).toFixed(2)  + ' GB/s';
    if (v >= 1e6)  return (v/1e6).toFixed(2)  + ' MB/s';
    if (v >= 1e3)  return (v/1e3).toFixed(1)  + ' KB/s';
    return v.toFixed(0) + ' B/s';
}

function mkGrad(ctx, hex, alpha) {
    alpha = alpha ?? 0.35;
    const g = ctx.createLinearGradient(0, 0, 0, ctx.canvas.height || 100);
    const r=parseInt(hex.slice(1,3),16), gv=parseInt(hex.slice(3,5),16), b=parseInt(hex.slice(5,7),16);
    g.addColorStop(0, `rgba(${r},${gv},${b},${alpha})`);
    g.addColorStop(1, `rgba(${r},${gv},${b},0)`);
    return g;
}

function chartOpts(yFmtFn) {
    return {
        responsive: true, maintainAspectRatio: false, animation: false,
        plugins: {
            legend: { display: false },
            tooltip: {
                mode: 'index', intersect: false,
                backgroundColor: 'rgba(0,0,0,.85)', titleColor:'#aaa', bodyColor:'#fff',
                padding: 8, borderColor:'rgba(255,255,255,.1)', borderWidth:1,
                callbacks: { label: ctx => ' ' + ctx.dataset.label + ': ' + yFmtFn(ctx.parsed.y) }
            }
        },
        scales: {
            x: {
                type: 'time',
                time: { tooltipFormat:'MMM d HH:mm', displayFormats:{minute:'HH:mm',hour:'HH:mm',day:'MMM d'} },
                grid: { color:'rgba(255,255,255,.04)' },
                ticks: { color:'#555', maxTicksLimit:7, font:{size:10} }
            },
            y: {
                beginAtZero: true,
                grid: { color:'rgba(255,255,255,.04)' },
                ticks: { color:'#555', font:{size:10}, callback: v => yFmtFn(v) }
            }
        }
    };
}

function loadTrafficChart(devId, nodeId, portId, range) {
    const cid   = 'trf-'+devId+'-'+portId;
    const canvas = document.getElementById(cid);
    if (!canvas) return;
    const stEl  = document.getElementById('trfst-'+devId+'-'+portId);
    const legEl = document.getElementById('trfleg-'+devId+'-'+portId);
    if (stEl) stEl.textContent = 'Loading…';

    fetch('net_mon_stats.php?api=port_traffic&node_id='+nodeId+'&port_id='+portId+'&range='+range, {credentials:'same-origin'})
    .then(r=>r.json()).then(d => {
        if (d.err || !d.rows?.length) {
            if (stEl) stEl.textContent = d.err || 'No data';
            return;
        }
        const labels  = d.rows.map(r => r.ts);
        const inData  = d.rows.map(r => +r.in_avg  || 0);
        const outData = d.rows.map(r => +r.out_avg || 0);

        if (_NM_CHARTS[cid]) _NM_CHARTS[cid].destroy();
        const ctx = canvas.getContext('2d');
        _NM_CHARTS[cid] = new Chart(ctx, {
            type: 'line',
            data: {
                labels,
                datasets: [
                    { label:'In',  data: inData,  borderColor:'#4da3ff', borderWidth:1.5,
                      backgroundColor: mkGrad(ctx,'#4da3ff'), fill:true, tension:0.3, pointRadius:0 },
                    { label:'Out', data: outData, borderColor:'#2ecc71', borderWidth:1.5,
                      backgroundColor: mkGrad(ctx,'#2ecc71'), fill:true, tension:0.3, pointRadius:0 },
                ]
            },
            options: chartOpts(fmtBps)
        });

        if (stEl) stEl.textContent = '';
        if (legEl) legEl.innerHTML =
            `<span style="color:#4da3ff;">↓ In</span> Avg:${fmtBps(d.avg_in)} Peak:${fmtBps(d.peak_in)} 95th:${fmtBps(d.p95_in)}` +
            `&nbsp;&nbsp;<span style="color:#2ecc71;">↑ Out</span> Avg:${fmtBps(d.avg_out)} Peak:${fmtBps(d.peak_out)} 95th:${fmtBps(d.p95_out)}`;
    }).catch(() => { if (stEl) stEl.textContent = 'Error'; });
}

function loadHealthChart(devId, nodeId, type, range) {
    const ID_MAP = { cpu:'cpu', memory:'mem', storage:'disk', custom:'cust' };
    const ST_MAP = { cpu:'cpust', memory:'memst', storage:'diskst', custom:'custst' };
    const LG_MAP = { cpu:'cpuleg', memory:'memleg', storage:'diskleg', custom:'custleg' };
    const cid    = (ID_MAP[type] || type) + '-' + devId;
    const canvas = document.getElementById(cid);
    if (!canvas) return;
    const stEl  = document.getElementById((ST_MAP[type] || type+'st') + '-' + devId);
    const legEl = document.getElementById((LG_MAP[type] || type+'leg') + '-' + devId);
    if (stEl) stEl.textContent = 'Loading…';

    const isRaw = (type === 'custom');  // custom sensors are raw values, not %
    const yFmt  = isRaw ? v => (+v).toFixed(1) : v => v.toFixed(1) + '%';

    fetch('net_mon_stats.php?api=device_metrics&node_id='+nodeId+'&type='+type+'&range='+range, {credentials:'same-origin'})
    .then(r=>r.json()).then(d => {
        if (d.err || !d.times?.length) {
            if (stEl) stEl.textContent = d.err || 'No data';
            if (type === 'custom') {
                const blk = document.getElementById('custblock-'+devId);
                if (blk) blk.style.display = 'none';
            }
            return;
        }

        if (type === 'custom') {
            const blk = document.getElementById('custblock-'+devId);
            if (blk) blk.style.display = 'block';
        }

        const palette = ['#4da3ff','#2ecc71','#f39c12','#e74c3c','#9b59b6','#1abc9c','#e67e22','#3498db'];
        const labels  = d.times || [];

        // >20 cores → avg only; ≤20 cores → per-core (handles MikroTik and HP EliteDesk)
        let keys;
        if (type === 'cpu') {
            const coreKeys = (d.keys || []).filter(k => /^(cpu\d+|core_\d+)$/.test(k));
            if (coreKeys.length > 20)      keys = ['avg'];
            else if (coreKeys.length > 0)  keys = coreKeys;
            else keys = (d.keys || []).filter(k => k !== 'avg' && k !== 'CPU Idle');
        } else {
            keys = (d.keys || []).filter(k => k !== 'avg');
        }

        const datasets = keys.map((k, i) => ({
            label:      k,
            data:       labels.map(ts => d.data?.[ts]?.[k] ?? null),
            borderColor:palette[i % palette.length],
            borderWidth:1.5, backgroundColor:'transparent',
            tension:0.3, pointRadius:0, spanGaps:true,
        }));

        if (!datasets.length && labels.length) {
            const avgVals = labels.map(ts => d.data?.[ts]?.avg ?? null);
            datasets.push({ label:'avg', data:avgVals, borderColor:palette[0],
                borderWidth:1.5, backgroundColor:'transparent', tension:0.3, pointRadius:0, spanGaps:true });
        }

        if (_NM_CHARTS[cid]) _NM_CHARTS[cid].destroy();
        const ctx = canvas.getContext('2d');
        _NM_CHARTS[cid] = new Chart(ctx, {
            type: 'line',
            data: { labels, datasets },
            options: chartOpts(yFmt)
        });

        if (stEl) stEl.textContent = '';
        if (legEl && d.stats) {
            const displayKeys = Object.keys(d.stats).filter(k => k !== 'avg' || !keys.length);
            legEl.innerHTML = displayKeys.map((k, i) => {
                const s = d.stats[k];
                return `<span style="color:${palette[i%palette.length]};font-weight:700;">${k}</span>` +
                       ` Min:${yFmt(s.min)} Avg:${yFmt(s.avg)} Max:${yFmt(s.max)}` +
                       (s.cur !== null ? ` Cur:${yFmt(s.cur)}` : '');
            }).join(' &nbsp; ');
        }
    }).catch(() => { if (stEl) stEl.textContent = 'Error'; });
}

function loadDevCharts(devId) {
    const panel = document.getElementById('tab-'+devId+'-graphs');
    if (!panel) return;
    const nodeId = parseInt(panel.dataset.nodeId || '0', 10);
    const range  = _DEV_RANGES[devId] || '24h';

    if (panel.dataset.monitor === 'ping') { loadPingChart(devId, nodeId, range); return; }

    const ports  = JSON.parse(panel.dataset.ports || '[]');
    ports.forEach(p => loadTrafficChart(devId, nodeId, p.pid, range));
    if (nodeId) {
        loadHealthChart(devId, nodeId, 'cpu',     range);
        loadHealthChart(devId, nodeId, 'memory',  range);
        loadHealthChart(devId, nodeId, 'storage', range);
        loadHealthChart(devId, nodeId, 'custom',  range);
        if (document.getElementById('gpublock-'+devId)) loadGpuChart(devId, nodeId, range);
    }
}

// GPU panel (only present for nodes registered in the AI/GPU Monitor)
function loadGpuChart(devId, nodeId, range) {
    const canvas = document.getElementById('gpu-'+devId);
    if (!canvas || !nodeId) return;
    const legEl = document.getElementById('gpuleg-'+devId);
    const cid   = 'gpu-'+devId;
    fetch('net_mon_stats.php?api=gpu_stats&node_id='+nodeId+'&range='+range, {credentials:'same-origin'})
    .then(r=>r.json()).then(d => {
        const blk = document.getElementById('gpublock-'+devId);
        if (!d || !d.has_gpu) { if (blk) blk.style.display='none'; return; }
        const e = s => (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
        // live one-liner + loaded models in the legend strip
        const live = (d.gpus||[]).map(g => { const s=g.latest||{}; const mp=s.mem_total_mb>0?Math.round(100*s.mem_used_mb/s.mem_total_mb):'—';
            return `<b style="color:#76b900;">${e(g.name||('GPU'+g.gpu_index))}</b> ${Math.round(s.util_pct||0)}% · VRAM ${mp}%${s.temp_c!=null?' · '+Math.round(s.temp_c)+'°C':''}${s.power_w!=null?' · '+Math.round(s.power_w)+'W':''}`; }).join(' &nbsp; ');
        const mods = (d.models||[]).map(m => e(m.name)).join(', ');
        if (legEl) legEl.innerHTML = live + (mods ? `<div style="color:#8a909a;margin-top:2px;">model: ${mods}</div>` : '');
        if (!d.times || !d.times.length) { if (_NM_CHARTS[cid]) { _NM_CHARTS[cid].destroy(); delete _NM_CHARTS[cid]; } return; }
        const ctx = canvas.getContext('2d');
        if (_NM_CHARTS[cid]) _NM_CHARTS[cid].destroy();
        _NM_CHARTS[cid] = new Chart(ctx, {
            type:'line',
            data:{ labels:d.times, datasets:[
                { label:'GPU %',  data:d.util, borderColor:'#76b900', borderWidth:1.5, backgroundColor:mkGrad(ctx,'#76b900'), fill:true,  tension:0.3, pointRadius:0, spanGaps:true },
                { label:'VRAM %', data:d.vram, borderColor:'#4da3ff', borderWidth:1.3, backgroundColor:'transparent', fill:false, tension:0.3, pointRadius:0, spanGaps:true },
                { label:'°C',     data:d.temp, borderColor:'#f39c12', borderWidth:1.3, backgroundColor:'transparent', fill:false, tension:0.3, pointRadius:0, spanGaps:true },
            ]},
            options: chartOpts(v => (+v).toFixed(0))
        });
    }).catch(() => {});
}

function loadPingChart(devId, nodeId, range) {
    const canvas = document.getElementById('ping-'+devId);
    if (!canvas || !nodeId) return;
    const stEl  = document.getElementById('pingst-'+devId);
    const legEl = document.getElementById('pingleg-'+devId);
    const cid   = 'ping-'+devId;
    if (stEl) stEl.textContent = 'Loading…';

    fetch('net_mon_stats.php?api=ping_history&node_id='+nodeId+'&range='+range, {credentials:'same-origin'})
    .then(r=>r.json()).then(d => {
        if (d.err || !d.times?.length) {
            if (stEl) stEl.textContent = d.err || 'No ping data yet — runs each minute';
            if (_NM_CHARTS[cid]) { _NM_CHARTS[cid].destroy(); delete _NM_CHARTS[cid]; }
            return;
        }
        if (_NM_CHARTS[cid]) _NM_CHARTS[cid].destroy();
        _NM_CHARTS[cid] = new Chart(canvas.getContext('2d'), {
            type: 'line',
            data: { labels: d.times, datasets: [{
                label: 'Latency (ms)', data: d.latency,
                borderColor: '#4da3ff', backgroundColor: 'rgba(77,163,255,.12)',
                borderWidth: 1.6, tension: 0.3, pointRadius: 0, spanGaps: false, fill: true,
            }]},
            options: chartOpts(v => (+v).toFixed(0) + ' ms')
        });
        if (stEl) stEl.textContent = '';
        const s = d.summary || {};
        const av = parseFloat(s.availability || 0);
        const avc = av >= 99 ? '#2ecc71' : (av >= 95 ? '#f39c12' : '#e74c3c');
        if (legEl) legEl.innerHTML =
            `<span style="color:${avc};font-weight:700;">Availability ${av.toFixed(2)}%</span>` +
            `&nbsp;&nbsp;<span style="color:#4da3ff;">Latency</span> Avg:${s.avg_lat ?? '—'}ms Min:${s.min_lat ?? '—'}ms Max:${s.max_lat ?? '—'}ms` +
            `&nbsp;&nbsp;Loss:${s.loss ?? '—'}%&nbsp;&nbsp;<span style="color:#555;">${s.n || 0} samples</span>`;
    }).catch(() => { if (stEl) stEl.textContent = 'Error'; });
}

function setDevRange(devId, range, btn) {
    _DEV_RANGES[devId] = range;
    const panel = document.getElementById('tab-'+devId+'-graphs');
    if (panel) panel.querySelectorAll('.range-btn').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    loadDevCharts(devId);
}

// ── Tabs ──────────────────────────────────────────────────────────────────────
const TAB_ORDER = ['interfaces', 'graphs', 'health', 'info'];

function switchTab(devId, tabKey) {
    TAB_ORDER.forEach(k => {
        const p = document.getElementById('tab-' + devId + '-' + k);
        if (p) p.classList.remove('active');
    });
    const bar = document.getElementById('tabs-' + devId);
    if (bar) bar.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));

    const panel = document.getElementById('tab-' + devId + '-' + tabKey);
    if (panel) panel.classList.add('active');
    if (bar) {
        const idx = TAB_ORDER.indexOf(tabKey);
        const btns = bar.querySelectorAll('.tab-btn');
        if (btns[idx]) btns[idx].classList.add('active');
    }

    if (tabKey === 'graphs') loadDevCharts(devId);
}

// ── Port graph button in interface tab → open live monitor ────────────────────
function showPortGraph(portId, devId) {
    location.href='live_mon.php?device=' + devId + '&port=' + portId;
}

// ── Rotate chevrons for pre-opened accordions ─────────────────────────────────
document.querySelectorAll('.dev-accordion-body.open').forEach(el => {
    const id   = el.id.replace('body-', '');
    const chev = document.getElementById('chev-' + id);
    if (chev) chev.style.transform = 'rotate(180deg)';
});

// ── Refresh controls ──────────────────────────────────────────────────────────
function doRefresh() {
    const icon = document.getElementById('refresh-icon');
    if (icon) icon.classList.add('fa-spin');
    setTimeout(() => location.reload(), 300);
}

function toggleRefreshPanel() {
    const p = document.getElementById('refresh-panel');
    if (!p) return;
    p.style.display = p.style.display === 'none' || !p.style.display ? 'flex' : 'none';
}

let _refreshTimer = null;
let _countdown    = 0;
let _countdownEl  = null;

function applyAutoRefresh() {
    clearInterval(_refreshTimer);
    const chk  = document.getElementById('auto-refresh-chk');
    const sel  = document.getElementById('refresh-interval');
    const secs = parseInt(sel?.value || '60', 10);
    localStorage.setItem('nm_auto_refresh', chk?.checked ? '1' : '0');
    localStorage.setItem('nm_refresh_interval', String(secs));
    if (!chk?.checked) {
        const cd = document.getElementById('refresh-countdown');
        if (cd) cd.textContent = '';
        return;
    }
    _countdown = secs;
    _countdownEl = document.getElementById('refresh-countdown');
    _refreshTimer = setInterval(() => {
        _countdown--;
        if (_countdownEl) _countdownEl.textContent = `Next refresh in ${_countdown}s`;
        if (_countdown <= 0) location.reload();
    }, 1000);
    if (_countdownEl) _countdownEl.textContent = `Next refresh in ${_countdown}s`;
}

// Restore settings from localStorage on load
(function () {
    const enabled  = localStorage.getItem('nm_auto_refresh') === '1';
    const interval = parseInt(localStorage.getItem('nm_refresh_interval') || '60', 10);
    const chk = document.getElementById('auto-refresh-chk');
    const sel = document.getElementById('refresh-interval');
    if (chk) chk.checked = enabled;
    if (sel) sel.value   = String(interval);
    if (enabled) applyAutoRefresh();
})();
</script>
<?php endif; // $librenms_enabled ?>

<!-- ── LIVE dashboard: poll values & update the DOM in place (no full reload) ── -->
<div id="live-badge" title="Live updating">
  <span class="live-pulse"></span><span id="live-badge-txt">LIVE</span>
</div>
<style>
#live-badge{position:fixed;bottom:18px;left:18px;z-index:2500;display:flex;align-items:center;gap:8px;
  background:rgba(15,23,42,.9);backdrop-filter:blur(8px);border:1px solid rgba(46,204,113,.5);
  color:#2ecc71;font-size:11px;font-weight:700;letter-spacing:.6px;padding:7px 14px;border-radius:20px;
  box-shadow:0 6px 20px rgba(0,0,0,.45);cursor:default;user-select:none;transition:opacity .3s;}
#live-badge.stale{border-color:rgba(243,156,18,.5);color:#f39c12;}
.live-pulse{width:8px;height:8px;border-radius:50%;background:currentColor;box-shadow:0 0 0 0 currentColor;animation:livepulse 1.8s infinite;}
@keyframes livepulse{0%{box-shadow:0 0 0 0 rgba(46,204,113,.6);}70%{box-shadow:0 0 0 7px rgba(46,204,113,0);}100%{box-shadow:0 0 0 0 rgba(46,204,113,0);}}
.rate-flash{animation:rateflash 1s ease;}
@keyframes rateflash{0%{background:rgba(77,163,255,.28);}100%{background:transparent;}}
.stat-val{transition:color .3s;}
</style>
<script>
(function(){
  const POLL = 5000;
  let inFlight = false;

  const fmtRate = bps => {
    bps = +bps || 0;
    if (bps >= 1e9) return (bps/1e9).toFixed(2)+' GB/s';
    if (bps >= 1e6) return (bps/1e6).toFixed(2)+' MB/s';
    if (bps >= 1e3) return (bps/1e3).toFixed(1)+' KB/s';
    return Math.round(bps)+' B/s';
  };
  const esc = s => (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  const cpuColor = v => v==null?'#555':(v>80?'#e74c3c':(v>60?'#f39c12':'#2ecc71'));
  const memColor = v => v==null?'#555':(v>85?'#e74c3c':(v>70?'#f39c12':'#2ecc71'));

  // animate an integer element toward a target value
  function tween(el, to){
    if(!el) return;
    const from = parseInt(el.textContent.replace(/[^\d-]/g,''),10) || 0;
    to = parseInt(to,10) || 0;
    if(from === to){ el.textContent = to; return; }
    const steps = 14, start = performance.now(), dur = 480;
    function frame(now){
      const t = Math.min(1,(now-start)/dur);
      const eased = 1-Math.pow(1-t,3);
      el.textContent = Math.round(from + (to-from)*eased);
      if(t<1) requestAnimationFrame(frame); else el.textContent = to;
    }
    requestAnimationFrame(frame);
  }
  function setStatCard(cardId, valId, val, dangerWhenPositive){
    const v = document.getElementById(valId); if(!v) return;
    tween(v, val);
    const card = v.closest('.stat-card');
    if(card && dangerWhenPositive){
      card.classList.toggle('stat-down', val>0);
      card.classList.toggle('stat-up', val===0);
    }
  }
  function flash(el){ if(!el) return; el.classList.remove('rate-flash'); void el.offsetWidth; el.classList.add('rate-flash'); }

  function apply(d){
    // ── summary stat cards ──
    const s = d.summary||{};
    tween(document.getElementById('stat-up'), s.up);
    setStatCard(null,'stat-down', s.down||0, true);
    tween(document.getElementById('stat-ports-up'), s.ports_up);
    tween(document.getElementById('stat-ports-down'), s.ports_down);
    if(s.cont_on){ tween(document.getElementById('stat-cont-up'), s.cont_up); tween(document.getElementById('stat-cont-down'), s.cont_down); }

    // ── per-device cards ──
    const devs = d.devices||{};
    for(const id in devs){
      const dev = devs[id];
      const card = document.querySelector('.device-card[data-dev="'+id+'"]');
      if(!card) continue;
      // status
      card.classList.remove('status-up','status-down','status-degraded','status-unknown');
      card.classList.add('status-'+dev.status);
      const dot = card.querySelector('.status-dot');
      if(dot){ dot.classList.remove('up','down','degraded','unknown'); dot.classList.add(dev.status); }
      // cpu / mem
      if(dev.cpu!=null){ const b=card.querySelector('.cpu-bar'), v=card.querySelector('.cpu-val');
        if(b) b.style.width=dev.cpu+'%'; if(b) b.style.background=cpuColor(dev.cpu);
        if(v){ v.textContent=dev.cpu+'%'; v.style.color=cpuColor(dev.cpu); } }
      if(dev.mem!=null){ const b=card.querySelector('.mem-bar'), v=card.querySelector('.mem-val');
        if(b) b.style.width=dev.mem+'%'; if(b) b.style.background=memColor(dev.mem);
        if(v){ v.textContent=dev.mem+'%'; v.style.color=memColor(dev.mem); } }
      // interface traffic
      (dev.ifaces||[]).forEach(f=>{
        const row = card.querySelector('[data-pid="'+f.pid+'"]'); if(!row) return;
        const out = row.querySelector('.t-out'), inn = row.querySelector('.t-in');
        const no = fmtRate(f.out), ni = fmtRate(f.in);
        if(out && out.textContent!==no){ out.textContent=no; flash(out.parentElement); }
        if(inn && inn.textContent!==ni){ inn.textContent=ni; flash(inn.parentElement); }
      });
      // latency
      if(dev.latency!=null){
        const lat = card.querySelector('.dev-latency');
        if(lat) lat.innerHTML='<i class="fas fa-stopwatch" style="color:#4da3ff;"></i> '+dev.latency+' ms'+
          (dev.loss && dev.loss>0 ? ' · '+dev.loss+'% loss' : '');
      }
    }

    // ── accordion ROW headers — keep each node's row in lock-step with its card ──
    // (the row used to freeze at page-load state until a full reload; now it tracks
    //  the SAME authoritative status the card does, every poll → no card/row drift)
    const stColor = st => st==='up' ? '#2ecc71' : st==='down' ? '#e74c3c' : st==='degraded' ? '#f39c12' : '#555';
    for(const id in devs){
      const dev = devs[id];
      const hdr = document.getElementById('acchdr-'+id);
      if(!hdr) continue;
      const col = stColor(dev.status);
      hdr.style.borderLeftColor = col;
      const dot = hdr.querySelector('.dev-row-dot');
      if(dot) dot.style.background = col;
      // port badges (N up / N down / N dis) — rebuild only when the counts change
      if(dev.has_ports){
        const bw = hdr.querySelector('.dev-row-badges');
        if(bw){
          let html = '<span class="badge badge-up">'+(dev.pup||0)+' up</span>';
          if(dev.pdown) html += '<span class="badge badge-down">'+dev.pdown+' down</span>';
          if(dev.pdis)  html += '<span class="badge badge-dis">'+dev.pdis+'  dis</span>';
          if(bw.innerHTML.trim() !== html) bw.innerHTML = html;
        }
      }
    }

    // ── top traffic ──
    const tb = document.getElementById('top-traffic-body');
    if(tb && d.top){
      const max = d.top.length ? Math.max.apply(null, d.top.map(t=>t.total)) : 1;
      tb.innerHTML = d.top.map(t=>{
        const pct = max>0 ? Math.round(t.total/max*100) : 0;
        return '<tr style="cursor:pointer;" onclick="openDevice('+t.dev_id+')">'+
          '<td><b style="font-size:12px;">'+esc(t.device)+'</b>'+
          '<span style="color:#aaa;font-size:11px;font-family:monospace;"> &bull; '+esc(t.iface)+'</span>'+
          '<div class="traffic-bar"><div class="traffic-bar-fill" style="width:'+pct+'%"></div></div></td>'+
          '<td style="color:var(--up);font-size:11px;font-family:monospace;">'+fmtRate(t.in)+'</td>'+
          '<td style="color:var(--accent);font-size:11px;font-family:monospace;">'+fmtRate(t.out)+'</td></tr>';
      }).join('');
    }

    // badge
    const b=document.getElementById('live-badge'); if(b){ b.classList.remove('stale');
      document.getElementById('live-badge-txt').textContent='LIVE'; }
  }

  // Only reveal the page when BOTH the first live data has landed AND the (huge) document has fully
  // loaded + painted — otherwise the loader lifts onto a half-rendered/empty dashboard for a few
  // seconds (the api=live response can beat the document's own render). rAF×2 ⇒ a real paint happened.
  let liveReady=false, pageLoaded=(document.readyState==='complete');
  function revealWhenReady(){ if(liveReady && pageLoaded && window.NMLoader){
    requestAnimationFrame(()=>requestAnimationFrame(()=>window.NMLoader.hide())); } }
  if(!pageLoaded) window.addEventListener('load', ()=>{ pageLoaded=true; revealWhenReady(); });

  async function poll(){
    if(inFlight || document.hidden) return;
    inFlight = true;
    try{
      const r = await fetch('net_mon.php?api=live&_t='+Date.now());
      if(r.ok){ const d = await r.json(); if(d && d.ok){ apply(d);
        if(!liveReady){ liveReady=true; if(window.NMLoader)NMLoader.msg('rendering dashboard…'); revealWhenReady(); } } }
    }catch(e){
      const b=document.getElementById('live-badge');
      if(b){ b.classList.add('stale'); document.getElementById('live-badge-txt').textContent='RECONNECTING'; }
    }finally{ inFlight = false; }
  }
  window.nmLivePoll = poll;   // exposed so the per-card "Poll now" button can refresh in place
  setInterval(poll, POLL);
  document.addEventListener('visibilitychange', ()=>{ if(!document.hidden) poll(); });
  if(window.NMLoader){ NMLoader.keep(); NMLoader.msg('gathering live device data…'); }  // hold loader until data AND page are ready
  poll();
})();

// ── NEURU Command Center (AI Commander V2) live activity (polls its own lightweight endpoint) ──
(function(){
  const card=document.getElementById('aiobot-card'); if(!card) return;
  const esc=s=>(s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  const ST={observe:['OBSERVING','#22d3ee'],think:['THINKING','#9b6bff'],act:['ACTING','#f39c12'],result:['VERIFYING','#2ecc71'],narrate:['NARRATING','#c08fd6'],error:['ERROR','#e74c3c'],system:['STANDBY','#8a909a'],idle:['IDLE','#8a909a']};
  const ICON={observe:'fa-satellite-dish',think:'fa-brain',act:'fa-bolt',result:'fa-circle-check',narrate:'fa-comment-dots',error:'fa-triangle-exclamation',system:'fa-gear'};
  function nlt(ts){ return window.nmTimeStr?window.nmTimeStr(ts):(ts||''); }
  async function tick(){
    let r=null; try{ r=await fetch('net_mon.php?api=aiobot&_='+Date.now()).then(x=>x.json()); }catch(e){ return; }
    if(!r||!r.ok||r.never||r.off){ card.style.display='none'; return; }   // module not set up → hide
    if(!(r.events&&r.events.length) && !r.active && !r.awaiting){ card.style.display='none'; return; }
    card.style.display='';
    const s=ST[r.bot]||ST.idle, col=r.enabled?s[1]:'#e74c3c';
    document.getElementById('aiobot-state').innerHTML=
      `<span style="color:${col};">● ${r.enabled?s[0]:'OFFLINE'}</span>`
      +` <span style="color:#8a909a;font-weight:400;">· ${r.active} active · ${r.awaiting} awaiting · ${r.queued} queued</span>`;
    document.getElementById('aiobot-log').innerHTML=(r.events||[]).map(e=>{
      const c=e.phase==='result'?'#ff9c91':(e.phase==='think'?'#cdb4ff':(e.phase==='observe'?'#7fe6f5':(e.phase==='act'?'#f3c879':'#aeb6c2')));
      return `<div style="display:flex;gap:8px;align-items:center;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.05);">
        <span style="font-size:9px;font-weight:800;background:rgba(77,163,255,.16);color:#bcd;border:1px solid rgba(77,163,255,.3);padding:1px 7px;border-radius:20px;white-space:nowrap;"><i class="fas fa-server" style="font-size:8px;"></i> ${esc(e.display_name||'')}</span>
        <i class="fas ${ICON[e.phase]||'fa-circle'}" style="color:${c};"></i>
        <span style="color:${c};flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(e.title||e.phase)}</span>
        <span style="color:#667;font-size:10px;">${nlt(e.created_at)}</span></div>`;
    }).join('')||'<div style="color:#8a909a;padding:10px;">Idle — nothing running right now.</div>';
  }
  tick(); setInterval(tick, 5000);
  document.addEventListener('visibilitychange', ()=>{ if(!document.hidden) tick(); });
})();
</script>
</body>
</html>
