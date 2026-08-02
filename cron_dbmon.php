<?php
// NEURU Data Core — DB poll (per-target probe + live counters → nm_db_samples).
//   * * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_dbmon.php
// Runs via curl→localhost (www-data) so encrypted DB passwords + SSH creds decrypt.
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_dbmon.php';
require __DIR__ . '/nm_n8n.php';
if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
}
$res = nm_db_poll_all($conn);
nm_db_prune($conn, 14);
// schema-drift capture (self-throttled to db_schema_interval_h, default 6h — so this is cheap every minute)
// + replication health capture for replica-role targets (cheap SHOW REPLICA STATUS)
$drift = []; $repl = [];
foreach (nm_db_targets($conn) as $t) { if (!$t['enabled']) continue;
    $r = nm_db_schema_capture($conn, (int)$t['id']);
    if (!empty($r['changed'])) $drift[$t['id']] = $r['summary'] ?? 'changed';
    if (($t['role'] ?? 'standalone') === 'replica') { $rr = nm_db_repl_capture($conn, (int)$t['id']); if (!empty($rr['ok'])) $repl[$t['id']] = 'io='.$rr['io'].' sql='.$rr['sql'].' behind='.($rr['behind']??'?'); }
}
echo $IS_CLI ? ("db poll: " . json_encode($res) . " drift: " . json_encode($drift) . " repl: " . json_encode($repl) . "\n")
             : json_encode(['ok'=>true,'targets'=>$res,'drift'=>$drift,'repl'=>$repl,'at'=>gmdate('c')]);
