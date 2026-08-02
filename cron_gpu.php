<?php
// NEURU — AI/GPU monitor poll (per-target nvidia-smi/rocm-smi + Ollama over SSH).
//   * * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_gpu.php
// Runs via curl→localhost (www-data) so SSH credentials decrypt correctly.
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_gpu.php';
require __DIR__ . '/nm_n8n.php';
if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
}
$res = nm_gpu_poll_all($conn);
nm_gpu_prune($conn, 14);
echo $IS_CLI ? ("gpu poll: ".json_encode($res)."\n") : json_encode(['ok'=>true,'targets'=>$res,'at'=>gmdate('c')]);
