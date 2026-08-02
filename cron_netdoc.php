<?php
// NEURU — Connection Doctor MONITOR. Records ping/jitter/loss/stability history per rig so you can see EXACTLY
// when your connection lagged (not just live).
//   */10 * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_netdoc.php
// Runs via curl→localhost (www-data) so SSH credentials decrypt correctly (secret ops need the web user).
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_netdoc.php';
require __DIR__ . '/nm_n8n.php';
if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
}
nm_netdoc_ensure($conn);
$rigs = function_exists('nm_win_hosts') ? nm_win_hosts($conn) : [];
$done = 0;
foreach ($rigs as $r) {
    if (array_key_exists('enabled',$r) && !$r['enabled']) continue;
    try { $res = nm_netdoc_run($conn, $r, ''); if (!empty($res['ok'])) $done++; } catch (\Throwable $e) {}
}
echo $IS_CLI ? ("netdoc monitor: {$done} rig(s) recorded\n") : json_encode(['ok'=>true,'rigs'=>$done,'at'=>gmdate('c')]);
