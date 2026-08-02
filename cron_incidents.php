<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — incident correlation tick. Collects every source's open alerts and
// correlates them into incidents (root cause + impact + lifecycle). Run minutely:
//   * * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_incidents.php
// ─────────────────────────────────────────────────────────────────────────────
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_incidents.php';
require __DIR__ . '/nm_notify.php';
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

$r = nm_inc_correlate($conn);
// notify/escalate right after correlation (best-effort — never break the tick)
$n = ['sent'=>0];
try { $n = nm_notify_process($conn); } catch (\Throwable $e) { $n = ['error'=>$e->getMessage()]; }

echo $IS_CLI
    ? "incidents: {$r['signals']} signals → {$r['incidents']} incidents (opened {$r['opened']}, updated {$r['updated']}, resolved {$r['resolved']}) · notify: ".json_encode($n)."\n"
    : json_encode(['ok'=>true] + $r + ['notify'=>$n, 'at'=>date('c')]);
