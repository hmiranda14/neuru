<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — background Smokeping latency recorder. Pulls Smokeping's RRD samples
// (via the n8n SSH flow → rrdtool fetch) into nm_latency_samples so NEURU owns the
// latency history independently of Smokeping. Run from cron every ~5 min:
//   */5 * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_smokeping.php >/dev/null
// or CLI:  */5 * * * * php /var/www/html/netmon/cron_smokeping.php
// ─────────────────────────────────────────────────────────────────────────────
$IS_CLI = (PHP_SAPI === 'cli');

require __DIR__ . '/connection.php';
require __DIR__ . '/nm_smokeping.php';
require __DIR__ . '/nm_n8n.php';

if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_SERVER['HTTP_X_API_KEY'] ?? '');
    if (!$hdr && !empty($_SERVER['HTTP_AUTHORIZATION'])) $hdr = preg_replace('/^Bearer\s+/i', '', $_SERVER['HTTP_AUTHORIZATION']);
    if (!$hdr && isset($_GET['token'])) $hdr = $_GET['token'];
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'Unauthorized — bad or missing X-NetMon-Token']);
        exit;
    }
}

$hours = isset($_GET['hours']) ? (int)$_GET['hours'] : (($IS_CLI && isset($argv[1])) ? (int)$argv[1] : 2);
$r = nm_sp_record($conn, null, $hours);

if ($IS_CLI) {
    echo $r['ok'] ? "recorded {$r['inserted']} samples from {$r['targets']} targets\n" : ("error: " . ($r['error'] ?? 'failed') . "\n");
} else {
    echo json_encode($r + ['at' => date('c')]);
}
