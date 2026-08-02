<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — predictive health evaluator. Trends nm_health_samples and refreshes
// nm_health_predictions (days-to-failure). Run hourly (trends move over days):
//   15 * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_health.php
// The Python collector (scripts/nm_health.py) feeds the samples every ~5 min.
// ─────────────────────────────────────────────────────────────────────────────
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_health.php';
require __DIR__ . '/nm_n8n.php';

if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
}

if (nm_health_setting($conn,'health_enabled','1') === '0') { echo $IS_CLI ? "disabled\n" : json_encode(['ok'=>true,'skipped'=>'disabled']); exit; }

$res = nm_health_evaluate($conn);
echo $IS_CLI ? ("health: ".json_encode($res)."\n") : json_encode(['ok'=>true] + $res + ['at'=>date('c')]);
