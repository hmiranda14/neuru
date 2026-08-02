<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Router Commander n8n-facing callback API. Single dispatcher: ?ep=<x>&id=N.
// Auth: shared inbound token (n8n_inbound_token) via X-NetMon-Token / X-API-Key /
// Authorization: Bearer — same as nm_containers_api.php.
//
//   POST rc_log&id=        ← n8n appends transcript line(s) {level,line|message} or {lines:[]}
//   POST rc_proposal&id=   ← n8n proposes a command {command, rationale?, risky?, type?}
//   POST rc_continue&id=   ← n8n signals "command finished" → loop the AI (linux path)
//   POST rc_result&id=     ← n8n reports final {status:'resolved|failed', log?}
//
// (KB embedding reuses the shared nm_containers_api.php?ep=kb_export / kb_vectorized.)
// ─────────────────────────────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
date_default_timezone_set('America/Puerto_Rico');

require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/nm_n8n.php';
require_once __DIR__ . '/nm_rcflow.php';

function rcj($p, int $code = 200) { http_response_code($code); echo json_encode($p, JSON_UNESCAPED_SLASHES); exit; }

$presented = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_SERVER['HTTP_X_API_KEY'] ?? '');
if ($presented === '' && !empty($_SERVER['HTTP_AUTHORIZATION'])) {
    if (preg_match('/Bearer\s+(.+)/i', $_SERVER['HTTP_AUTHORIZATION'], $m)) $presented = trim($m[1]);
}
if (!nm_n8n_verify_inbound($conn, $presented)) rcj(['ok'=>false,'error'=>'Unauthorized — bad or missing X-NetMon-Token'], 401);

nm_rc_ensure($conn);
$ep   = $_GET['ep'] ?? '';
$id   = (int)($_GET['id'] ?? 0);
$body = json_decode(file_get_contents('php://input'), true);
if (!is_array($body)) $body = $_POST;

$sess = nm_rc_session($conn, $id);
if (!$sess && $ep !== '') rcj(['ok'=>false,'error'=>'Session not found'], 404);

switch ($ep) {

case 'rc_log': {
    $rows = [];
    if (isset($body['lines']) && is_array($body['lines'])) $rows = $body['lines'];
    else $rows = [['level'=>$body['level'] ?? 'info', 'line'=>$body['line'] ?? ($body['message'] ?? '')]];
    $n = 0;
    $st = $conn->prepare("INSERT INTO nm_rc_logs(session_id,level,line) VALUES(?,?,?)");
    foreach ($rows as $l) {
        $lvl = substr((string)($l['level'] ?? 'info'), 0, 16);
        $txt = (string)($l['line'] ?? ($l['message'] ?? ''));
        if ($txt === '') { $so=trim((string)($l['stdout']??'')); $se=trim((string)($l['stderr']??'')); $txt=trim($so.($so!==''&&$se!==''?"\n":'').$se); }
        if ($txt === '' || $txt === '[object Object]') continue;
        $st->bind_param('iss',$id,$lvl,$txt); $st->execute(); $n++;
    }
    rcj(['ok'=>true,'inserted'=>$n]);
}

case 'rc_proposal': {
    $cmd = trim((string)($body['command'] ?? ''));
    if ($cmd === '') rcj(['ok'=>false,'error'=>'command required'], 422);
    $j = json_encode([
        'command'   => $cmd,
        'rationale' => (string)($body['rationale'] ?? ''),
        'risky'     => (bool)($body['risky'] ?? false),
        'type'      => (string)($body['type'] ?? 'command'),
    ], JSON_UNESCAPED_SLASHES);
    $st = $conn->prepare("INSERT INTO nm_rc_logs(session_id,level,line) VALUES(?,'proposal',?)");
    $st->bind_param('is',$id,$j); $st->execute();
    rcj(['ok'=>true]);
}

case 'rc_continue': {
    $r = nm_rc_continue($conn, $id);
    rcj($r);
}

case 'rc_result': {
    $status = ($body['status'] ?? '') === 'resolved' ? 'resolved' : 'failed';
    $log = (string)($body['log'] ?? ($body['message'] ?? ($body['summary'] ?? '')));
    $done = ($status === 'resolved' ? '✓ ' : '✗ ') . ($log !== '' ? $log : ($status === 'resolved' ? 'Resolved.' : 'Did not resolve.'));
    $st = $conn->prepare("INSERT INTO nm_rc_logs(session_id,level,line) VALUES(?,'done',?)");
    $st->bind_param('is',$id,$done); $st->execute();
    if ($status === 'resolved') { $conn->query("UPDATE nm_rc_sessions SET status='resolved' WHERE id={$id}"); }
    rcj(['ok'=>true]);
}

default:
    rcj(['ok'=>false,'error'=>'Unknown endpoint','endpoints'=>['rc_log','rc_proposal','rc_continue','rc_result']], 404);
}
