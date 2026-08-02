<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU Data Core — n8n INBOUND callback. The 'db-advisor' / DB Solution Center flow
// POSTs ranked recommendations here. Token-verified (X-NetMon-Token); NO user session
// (mirrors aiopilot_api.php). Stores into nm_db_advice (de-duped by fingerprint).
//
// Expected body:
// { "target_id": 3, "advice": [ { "kind":"index|maintenance|config|kill|other",
//     "title":"…", "rationale":"…", "ddl":"CREATE INDEX …", "risk":"low|medium|high",
//     "benefit":"~42 min/day saved", "fingerprint":"stable-id" }, … ] }
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_n8n.php';
require __DIR__ . '/nm_dbmon.php';
header('Content-Type: application/json; charset=utf-8');

$cfg  = nm_n8n_get($conn);
$hdr  = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_SERVER['HTTP_X_API_KEY'] ?? ($_GET['token'] ?? ''));
$want = (string)($cfg['inbound_token'] ?? '');
if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }

$b = json_decode(file_get_contents('php://input'), true) ?: [];
$target = (int)($b['target_id'] ?? 0);
if (!$target || !nm_db_target($conn, $target)) { echo json_encode(['ok'=>false,'error'=>'Unknown target_id']); exit; }

$items = $b['advice'] ?? $b['suggestions'] ?? [];
if (!is_array($items)) { echo json_encode(['ok'=>false,'error'=>'advice[] required']); exit; }

$n = 0;
foreach ($items as $a) { if (is_array($a)) { nm_db_advice_add($conn, $target, $a); $n++; } }
echo json_encode(['ok'=>true, 'stored'=>$n]);
