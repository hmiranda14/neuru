<?php
// NEURU — TP-Link Easy Smart switch poll tick (no SNMP/syslog → scrape web UI).
//   */2 * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_tplink.php
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_tplink.php';
require __DIR__ . '/nm_n8n.php';
if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
}
nm_tp_ensure($conn);
$res = nm_tp_poll_all($conn);
nm_tp_prune($conn, 7);
echo $IS_CLI ? ("tplink: ".json_encode($res)."\n") : json_encode(['ok'=>true,'switches'=>$res,'at'=>date('c')]);
