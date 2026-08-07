<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — neuru-agent INBOUND receiver. A lightweight container on a remote Linux
// box PUSHES telemetry here over outbound HTTPS. Machine-to-machine: NOT
// session-auth'd — authenticated by the shared enrollment token in the
// `X-NEURU-Agent-Token` header (generate/rotate in Config → Poller → Remote Agents).
//
// Endpoints (?ep=…, POST JSON):
//   ep=hello    → { ok, server:"neuru", version, interval }        (unauth probe)
//   ep=register → body { uid, hostname, ip?, agent_version? }
//                 → { ok, host_id, node_id, name, interval }
//   ep=ingest   → body { uid, health:{…}, containers:[…]?, agent_rtt_ms? }
//                 → { ok, interval, commands:[…] }   (commands = queued remote actions)
//
// `health` is the SAME shape the SSH Linux Monitor produces (host/cores/cpu/
// mem_*/net_*/disks[]/top_cpu[]/top_mem[]/temps[]/fans[]/sensors[]) → it lands in
// nm_lx_health and renders in linux.php with zero new UI. See nm_agent.php.
// ─────────────────────────────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');

require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/nm_agent.php';
require_once __DIR__ . '/nm_linuxhost.php';   // nm_lx_ensure()

if (function_exists('session_write_close')) { @session_write_close(); }   // never hold the session lock

$ep  = $_GET['ep'] ?? 'hello';
$AGENT_INTERVAL = 30;   // seconds between pushes (agent honors this)

function _agent_out(array $o, int $code = 200): void {
    http_response_code($code);
    echo json_encode($o);
    exit;
}

// ── ep=hello — unauthenticated liveness probe (agent bootstrap sanity check) ──
if ($ep === 'hello') {
    $ver = @trim(@file_get_contents(__DIR__ . '/VERSION')) ?: 'dev';
    _agent_out(['ok'=>true, 'server'=>'neuru', 'version'=>$ver, 'interval'=>$AGENT_INTERVAL]);
}

// ── AuthN: constant-time enrollment-token check ──────────────────────────────
$tok = $_SERVER['HTTP_X_NEURU_AGENT_TOKEN'] ?? '';
if ($tok === '') $tok = $_SERVER['HTTP_X_NETMON_AGENT_TOKEN'] ?? '';   // tolerant alias
if ($tok === '' && isset($_GET['token'])) $tok = (string)$_GET['token'];
if (!nm_agent_verify($conn, $tok)) {
    _agent_out(['ok'=>false, 'err'=>'Unauthorized — bad or missing X-NEURU-Agent-Token'], 401);
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    _agent_out(['ok'=>false, 'err'=>'POST required'], 405);
}

$raw = file_get_contents('php://input');
$in  = json_decode($raw, true);
if (!is_array($in)) $in = $_POST;

$uid = (string)($in['uid'] ?? '');
if ($uid === '') _agent_out(['ok'=>false, 'err'=>'missing uid'], 400);

// ── ep=register — idempotent enrolment by uid ────────────────────────────────
if ($ep === 'register') {
    $host = (string)($in['hostname'] ?? $uid);
    $meta = ['ip' => (string)($in['ip'] ?? ($_SERVER['REMOTE_ADDR'] ?? '')),
             'agent_version' => (string)($in['agent_version'] ?? '')];
    $res = nm_agent_register($conn, $uid, $host, $meta);
    if (empty($res['ok'])) _agent_out(['ok'=>false, 'err'=>$res['error'] ?? 'register failed'], 500);
    _agent_out(['ok'=>true, 'host_id'=>$res['host_id'], 'node_id'=>$res['node_id'],
                'name'=>$res['name'], 'interval'=>$AGENT_INTERVAL]);
}

// ── ep=ingest — a telemetry batch ────────────────────────────────────────────
if ($ep === 'ingest') {
    $r = nm_agent_resolve($conn, $uid);
    if (!$r) {   // agent knows a uid we've never registered → auto-enrol on the fly
        $host = (string)($in['hostname'] ?? $uid);
        $reg  = nm_agent_register($conn, $uid, $host,
                    ['ip'=>(string)($in['ip'] ?? ($_SERVER['REMOTE_ADDR'] ?? '')),
                     'agent_version'=>(string)($in['agent_version'] ?? '')]);
        if (empty($reg['ok'])) _agent_out(['ok'=>false, 'err'=>'unregistered uid'], 404);
        $r = ['host_id'=>$reg['host_id'], 'node_id'=>$reg['node_id']];
    }
    $health     = is_array($in['health'] ?? null)     ? $in['health']     : [];
    $containers = is_array($in['containers'] ?? null) ? $in['containers'] : [];
    if (isset($in['agent_rtt_ms'])) $health['agent_rtt_ms'] = (float)$in['agent_rtt_ms'];

    // Agent reporting back results of previously-queued commands
    if (is_array($in['acks'] ?? null) && function_exists('nm_agent_ack')) {
        try { nm_agent_ack($conn, $in['acks']); } catch (\Throwable $e) {}
    }

    $res = nm_agent_ingest($conn, (int)$r['host_id'], (int)$r['node_id'], $health, $containers);
    if (empty($res['ok'])) _agent_out(['ok'=>false, 'err'=>$res['error'] ?? 'ingest failed'], 500);

    // Command channel (Phase 3): drain any queued remote actions for this host on the POST response.
    $commands = [];
    if (function_exists('nm_agent_take_commands')) {
        try { $commands = nm_agent_take_commands($conn, (int)$r['host_id']); } catch (\Throwable $e) {}
    }
    _agent_out(['ok'=>true, 'interval'=>$AGENT_INTERVAL, 'commands'=>$commands]);
}

_agent_out(['ok'=>false, 'err'=>'unknown ep'], 400);
