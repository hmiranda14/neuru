<?php
// NEURU — Cisco-specific poll (env sensors + CDP neighbors) for every Cisco node.
//   */5 * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_cisco.php
// Runs via curl→localhost (www-data) so any encrypted creds decrypt correctly and it
// shares the same token gate as the other HTTP crons. Also runnable from CLI for tests.
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_cisco.php';
require __DIR__ . '/nm_n8n.php';
if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg  = nm_n8n_get($conn);
    $hdr  = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) {
        http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit;
    }
}

nm_cisco_ensure($conn);
$summary = nm_cisco_poll_now($conn);

echo $IS_CLI
    ? ("cisco poll: " . json_encode($summary) . "\n")
    : json_encode(['ok'=>true] + $summary + ['at'=>gmdate('c')]);
