<?php
// NEURU — Deception Grid inbound capture (Phase 2 ready). A deployed honeypot (or an n8n flow
// relaying it) POSTs each attacker interaction here; we record it against the active diversion for
// that source IP so the "attacker theater" (P2) can replay their moves. Token-verified.
//   POST decoy_api.php?ep=event  { src_ip, kind, data }   header: X-NetMon-Token
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_decoy.php';
require __DIR__ . '/nm_n8n.php';

header('Content-Type: application/json; charset=utf-8');
$hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
if (!nm_n8n_verify_inbound($conn, $hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }

$ep = $_GET['ep'] ?? 'event';
if ($ep === 'event') {
    nm_decoy_ensure($conn);
    $body = json_decode(file_get_contents('php://input'), true) ?: $_POST;
    $src  = trim((string)($body['src_ip'] ?? ''));
    $kind = substr((string)($body['kind'] ?? 'hit'), 0, 16);
    $data = is_string($body['data'] ?? null) ? $body['data'] : json_encode($body['data'] ?? $body);
    if ($src === '') { echo json_encode(['ok'=>false,'error'=>'src_ip required']); exit; }
    // attach to the current active diversion for this source (if any)
    $r = $conn->query("SELECT id FROM nm_decoy_diversions WHERE src_ip='".$conn->real_escape_string($src)."' AND status='active' ORDER BY id DESC LIMIT 1");
    $did = ($r && $r->num_rows) ? (int)$r->fetch_assoc()['id'] : 0;
    $st = $conn->prepare("INSERT INTO nm_decoy_events (diversion_id,kind,src_ip,data) VALUES (?,?,?,?)");
    $st->bind_param('isss', $did, $kind, $src, $data); $st->execute(); $st->close();
    echo json_encode(['ok'=>true,'diversion_id'=>$did]); exit;
}
echo json_encode(['ok'=>false,'error'=>'unknown endpoint']);
