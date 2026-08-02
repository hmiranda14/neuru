<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — NetFlow bandwidth-alert evaluator. Runs every minute (curl→localhost so
// it runs as www-data). The collector (nm_netflow.py) writes the aggregates; this
// just evaluates per-app bandwidth vs thresholds/baseline and opens/clears alerts.
//   * * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_netflow.php
// ─────────────────────────────────────────────────────────────────────────────
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_netflow.php';
require __DIR__ . '/nm_n8n.php';

if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_SERVER['HTTP_X_API_KEY'] ?? '');
    if (!$hdr && !empty($_SERVER['HTTP_AUTHORIZATION'])) $hdr = preg_replace('/^Bearer\s+/i', '', $_SERVER['HTTP_AUTHORIZATION']);
    if (!$hdr && isset($_GET['token'])) $hdr = $_GET['token'];
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) {
        http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit;
    }
}

$nf = nm_nf_settings($conn);
if (!$nf['enabled']) { echo $IS_CLI ? "netflow disabled\n" : json_encode(['ok'=>true,'skipped'=>'disabled']); exit; }

$r = nm_nf_eval_alerts($conn, 5);
echo $IS_CLI ? ("netflow eval: opened {$r['opened']} cleared {$r['cleared']} (apps {$r['apps']})\n")
             : json_encode(['ok'=>true] + $r + ['at'=>date('c')]);
