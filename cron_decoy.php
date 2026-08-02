<?php
// NEURU — Deception Grid safety sweep: auto-revert any diversion past its TTL.
// MUST run via curl→localhost (Apache/www-data) — it applies MikroTik NAT changes over SSH and
// SSH credentials only decrypt under www-data, not the CLI SAPI.
//   * * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_decoy.php
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_decoy.php';
require __DIR__ . '/nm_n8n.php';

header('Content-Type: application/json; charset=utf-8');
$cfg  = nm_n8n_get($conn);
$hdr  = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
$want = (string)($cfg['inbound_token'] ?? '');
if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }

$sweep = nm_decoy_sweep($conn);          // safety net: TTL auto-revert + block-supersedes-divert
$auto  = nm_decoy_auto_tick($conn);      // F2·P2: autonomous detect→divert→analyze→promote (if ON)
echo json_encode(['ok'=>true,'sweep'=>$sweep,'auto'=>$auto]);
