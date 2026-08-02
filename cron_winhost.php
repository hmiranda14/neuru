<?php
// NEURU — Windows-over-SSH poller (Phase 1: Event Log). Later phases hook in here.
//   */2 * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_winhost.php
// Runs via curl→localhost (www-data) so SSH credentials decrypt correctly.
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_winhost.php';
require __DIR__ . '/nm_n8n.php';
if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
}
$res = nm_win_poll_all($conn);
nm_win_prune($conn, 30);
echo $IS_CLI ? ("win poll: ".json_encode($res)."\n") : json_encode(['ok'=>true,'hosts'=>$res,'at'=>gmdate('c')]);
