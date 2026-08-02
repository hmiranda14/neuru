<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — scheduled report sender. Runs hourly; sends the email report when the
// configured day/hour matches and it hasn't gone out yet today.
//   0 * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_reports.php
// ─────────────────────────────────────────────────────────────────────────────
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_sla.php';
require __DIR__ . '/nm_n8n.php';

if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? '';
    if (!$hdr && isset($_GET['token'])) $hdr = $_GET['token'];
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
}

$force = isset($_GET['force']) || ($IS_CLI && in_array('--force', $argv ?? [], true));
if (!$force && !nm_report_due($conn)) { echo $IS_CLI ? "not due\n" : json_encode(['ok'=>true,'skipped'=>'not due']); exit; }

$S = nm_sla_settings($conn);
$r = nm_report_send($conn, '', $S['period']);
if (!empty($r['ok'])) {
    $now = date('Y-m-d H:i:s');
    $st = $conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES('report_last_sent',?) ON DUPLICATE KEY UPDATE setting_val=?");
    $st->bind_param('ss', $now, $now); $st->execute(); $st->close();
}
echo $IS_CLI ? ("report: ".json_encode($r)."\n") : json_encode(['ok'=>true] + $r + ['at'=>date('c')]);
