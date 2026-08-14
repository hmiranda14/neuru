<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU Sentinel tick. Refreshes the SPECTRE threat-intel matrix (hourly) and
// correlates recent NetFlow flows against it (every run) → auto-block via Collective
// Immunity (+ optional quarantine). Run every few minutes:
//   */3 * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_sentinel.php
// ─────────────────────────────────────────────────────────────────────────────
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_sentinel.php';
require __DIR__ . '/nm_n8n.php';

if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
}

nm_sentinel_ensure($conn);
$scfg = nm_sentinel_cfg($conn);
if (($scfg['enabled'] ?? '1') === '0') { echo $IS_CLI ? "disabled\n" : json_encode(['ok'=>true,'skipped'=>'disabled']); exit; }

$out = ['ok'=>true,'feeds'=>null,'flows'=>0];

// SPECTRE feed refresh — hourly (throttle via a last-run marker)
$last = 0;
$r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='sentinel_feeds_last' LIMIT 1");
if ($r && ($x=$r->fetch_row())) $last = (int)$x[0];
if (time() - $last >= 3600) {
    try { $out['feeds'] = nm_sentinel_refresh_feeds($conn); } catch (\Throwable $e) { $out['feeds'] = ['error'=>$e->getMessage()]; }
    nm_sentinel_cfg_set($conn, 'feeds_last', (string)time());
}

// Correlate recent flows against the matrix (auto-response per config)
try { $scan = nm_sentinel_scan_flows($conn, 5); $out['flows'] = $scan['hits'] ?? 0; } catch (\Throwable $e) { $out['flows_error'] = $e->getMessage(); }

echo $IS_CLI ? ("sentinel: feeds=".json_encode($out['feeds'])." flows_hits=".$out['flows']."\n") : json_encode($out);
