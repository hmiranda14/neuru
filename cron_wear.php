<?php
// NEURU — daily wear/stress snapshot for the trend sparkline.
//   30 4 * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_wear.php
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_wear.php';
require __DIR__ . '/nm_n8n.php';
if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
}
$n = nm_wear_snapshot($conn);
echo $IS_CLI ? "wear snapshot: {$n} nodes\n" : json_encode(['ok'=>true,'snapshotted'=>$n,'at'=>date('c')]);
