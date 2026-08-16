<?php
// NEURU — WireGuard peer stats poll (per-peer handshake + traffic over SSH).
//   */2 * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_wireguard.php
// Runs via curl→localhost (www-data) so SSH credentials decrypt correctly.
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_wireguard.php';
require __DIR__ . '/nm_n8n.php';
if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
}
$res = nm_wg_poll_all_stats($conn);
nm_wg_traffic_prune($conn, 14);
// NEURU-in-a-Box brain tunnel: auto-wire the native neuru-brain WG on any MikroTik that hosts a box,
// the moment WireGuard gets enabled on the box (zero RouterOS steps for the user). Best-effort.
$wgrec = null;
try { require_once __DIR__ . '/nm_router_ctr.php'; if (function_exists('nm_rctr_wg_reconcile')) $wgrec = nm_rctr_wg_reconcile($conn); } catch (\Throwable $e) {}
echo $IS_CLI ? ("wg stats: ".json_encode($res)." | brain-reconcile: ".json_encode($wgrec)."\n") : json_encode(['ok'=>true,'servers'=>$res,'brain'=>$wgrec,'at'=>date('c')]);
