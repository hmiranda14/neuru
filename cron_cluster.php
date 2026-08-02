<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Cluster tick cron.
//   * * * * *  curl -s -H "X-NetMon-Token: <n8n_inbound_token>" http://localhost/cron_cluster.php
// Runs via curl→localhost (www-data) so the encrypted cluster token decrypts.
//   • role=slave  → build + push the site rollup (buffer offline, flush on reconnect)
//   • role=master → fold in the master's own local rollup + prune old history
//   • role=standalone → no-op
// ─────────────────────────────────────────────────────────────────────────────
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_cluster.php';
require __DIR__ . '/nm_n8n.php';

if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
}

$role = nm_cluster_cfg($conn)['role'];
$res = ['role'=>$role];
try {   // AUDIT-FIX: a slow/failed site or command must never 500 the whole tick
    if ($role === 'slave') {
        $res += nm_cluster_push($conn);
    } elseif ($role === 'master') {
        $res += nm_cluster_self_ingest($conn);
        $res['own_cmds'] = nm_cluster_master_apply_own($conn);   // F3: master applies fleet commands to itself
        $res['fed_inc'] = nm_cluster_sync_incidents($conn);       // federated incidents → central notify pipeline
        nm_cluster_prune($conn, 14);
    } else {
        $res += ['ok'=>true, 'note'=>'standalone — nothing to do'];
    }
} catch (\Throwable $e) {
    $res += ['ok'=>false, 'error'=>substr($e->getMessage(), 0, 160)];
    error_log('NEURU cron_cluster error: ' . $e->getMessage());
}

echo $IS_CLI ? ("cluster: " . json_encode($res) . "\n") : json_encode(['ok'=>!empty($res['ok'])] + $res + ['at'=>gmdate('c')]);
