<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — daily Router Configuration backup. Triggers an n8n SSH fetch per device
// (slug 'config-backup'), then NEURU diffs/versions/alerts. Run via cron once/day:
//
//   30 2 * * *  /opt/netmon-venv/bin/python3 -c ''   # (no — PHP below)
//   30 2 * * *  php /var/www/html/netmon/cron_config.php           # CLI (no token)
//   30 2 * * *  curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_config.php
//
// CLI runs need no token; HTTP runs require the shared X-NetMon-Token.
// ─────────────────────────────────────────────────────────────────────────────
$IS_CLI = (PHP_SAPI === 'cli');
@set_time_limit(0);                 // SSH-fetch each router synchronously
@ini_set('max_execution_time', '0');

require __DIR__ . '/connection.php';
require __DIR__ . '/nm_confmgr.php';
require __DIR__ . '/nm_n8n.php';    // only for the inbound-token check on HTTP runs

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

$summary = nm_cm_backup_all($conn, $IS_CLI ? 'cron' : 'cron-http');

if ($IS_CLI) {
    echo sprintf("[config-backup %s] %d devices · %d ok · %d changed · %d baseline · %d failed\n",
        date('c'), $summary['total'], $summary['ok'], $summary['changed'], $summary['baseline'], $summary['failed']);
    foreach ($summary['devices'] as $d) echo "  - {$d['name']}: {$d['result']}\n";
} else {
    echo json_encode($summary + ['at' => date('c')]);
}
