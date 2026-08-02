<?php
// NEURU — Service Biosphere poller. Probes every enabled service, stores a sample,
// prunes old ones. MUST run via curl→localhost (Apache/www-data): the SQL metabolic
// probe resolves Data Core creds via nm_secret_decrypt, which only works under www-data.
//   * * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_biosphere.php
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_biosphere.php';
require __DIR__ . '/nm_n8n.php';

header('Content-Type: application/json; charset=utf-8');
$cfg  = nm_n8n_get($conn);
$hdr  = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
$want = (string)($cfg['inbound_token'] ?? '');
if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }

$set = nm_bio_settings($conn);
if (!$set['enabled']) { echo json_encode(['ok'=>true,'skipped'=>'biosphere disabled']); exit; }

$poll  = nm_bio_poll_all($conn);
$pruned = nm_bio_prune($conn);
// P2: DNS DGA audit — throttled to every bio_dns_min minutes (the cron itself fires every minute)
$audit = nm_bio_dns_tick($conn);
// P3: synthetic-persona journeys (only when enabled) — run due headless-browser journeys via n8n
$synth = $set['synthetic'] ? nm_bio_synthetic_tick($conn) : ['skipped'=>true];
echo json_encode(['ok'=>true, 'polled'=>$poll, 'pruned'=>$pruned, 'dns_audit'=>$audit, 'synthetic'=>$synth]);
