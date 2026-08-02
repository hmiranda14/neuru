<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Self-Healing tick. Runs enabled playbooks (detect → propose/act) and
// auto-reverts time-boxed actions. SAFE: does nothing while playbooks are OFF.
//   */2 * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_heal.php
// ─────────────────────────────────────────────────────────────────────────────
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_heal.php';
require __DIR__ . '/nm_n8n.php';
if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
}
$res = nm_heal_run($conn);
echo $IS_CLI ? ("heal: ".json_encode($res)."\n") : json_encode(['ok'=>true] + $res + ['at'=>date('c')]);
