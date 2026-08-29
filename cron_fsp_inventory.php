<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — FSP inventory sweep. Pushes NOC's nodes into NEURU FSP's installed
// base (POST /assets, upsert on a stable asset_tag) so service tickets resolve
// by serial. Idempotent — safe to run daily; converges, never clones.
//   0 3 * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_fsp_inventory.php
// A disabled/unconfigured FSP integration (or inventory push off) is a no-op.
// ─────────────────────────────────────────────────────────────────────────────
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_n8n.php';
require __DIR__ . '/nm_fsp.php';

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

$res = ['ok'=>false, 'skipped'=>true];
try { $res = nm_fsp_push_inventory($conn); } catch (\Throwable $e) { $res = ['ok'=>false,'err'=>$e->getMessage()]; }

echo $IS_CLI
    ? "fsp inventory: " . json_encode($res) . "\n"
    : json_encode(['ok'=>true, 'result'=>$res, 'at'=>date('c')]);
