<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — background container-network recorder. Samples every running
// container's RX/TX into container_net_samples so utilization history accumulates
// 24/7 (independent of anyone having the Network tab open).
//
// Run from cron every minute (reuses the shared n8n inbound token — "no new keys"):
//   * * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_netstats.php >/dev/null
// or via CLI (no token needed):
//   * * * * * php /var/www/html/netmon/cron_netstats.php
// or point an n8n Schedule node at it with the X-NetMon-Token header.
// ─────────────────────────────────────────────────────────────────────────────
$IS_CLI = (PHP_SAPI === 'cli');

require __DIR__ . '/connection.php';
require __DIR__ . '/nm_portainer.php';
require __DIR__ . '/nm_netstats.php';
require __DIR__ . '/nm_n8n.php';

if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    // Token auth (same shared inbound token the container API uses).
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

$pcfg = nm_portainer_cfg($conn);
if (!nm_portainer_configured($pcfg)) {
    $msg = ['ok' => false, 'error' => 'Portainer not configured'];
    echo $IS_CLI ? "Portainer not configured\n" : json_encode($msg);
    exit;
}

// Sample every UP endpoint (so multi-host setups all record).
$eps = nm_portainer_endpoints($pcfg);
$endpoints = $eps['ok'] ? nm_portainer_norm_endpoints($eps['data']) : [];
$result = [];
foreach ($endpoints as $e) {
    if (!$e['up']) continue;
    [$rows, $err] = nm_netstats_sample($conn, $pcfg, (int)$e['id']);
    $result[] = ['endpoint' => $e['id'], 'name' => $e['name'], 'sampled' => count($rows), 'error' => $err ?: null];
}

if ($IS_CLI) {
    foreach ($result as $r) printf("endpoint %d (%s): sampled %d%s\n", $r['endpoint'], $r['name'], $r['sampled'], $r['error'] ? " — {$r['error']}" : '');
    if (!$result) echo "no up endpoints\n";
} else {
    echo json_encode(['ok' => true, 'endpoints' => $result, 'at' => date('c')]);
}
