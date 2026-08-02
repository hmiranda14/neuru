<?php
// NEURU — Service Biosphere inbound callback. The n8n 'bio-dns-audit' flow POSTs domain verdicts
// here (async), so the AI classification can run on its own schedule. Token-verified.
//   POST bio_api.php?ep=flag   header: X-NetMon-Token
//   body: { "verdicts": [ { "domain": "...", "verdict": "dga|tunneling|poison|benign", "score": 0-100, "reason": "..." } ] }
//   (a single {domain,verdict,...} object is also accepted)
// High-confidence DGA verdicts (score ≥ bio_dga_promote) auto-promote to a fleet-wide Immunity block.
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_biosphere.php';
require __DIR__ . '/nm_n8n.php';

header('Content-Type: application/json; charset=utf-8');
$hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
if (!nm_n8n_verify_inbound($conn, $hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }

$ep = $_GET['ep'] ?? 'flag';
if ($ep === 'flag') {
    $body = json_decode(file_get_contents('php://input'), true) ?: $_POST;
    $verdicts = $body['verdicts'] ?? $body['results'] ?? null;
    if ($verdicts === null && isset($body['domain'])) $verdicts = [$body];   // single-object form
    if (!is_array($verdicts)) { echo json_encode(['ok'=>false,'error'=>'expected a verdicts array']); exit; }
    $flagged = 0; $promoted = 0;
    foreach ($verdicts as $v) {
        if (!is_array($v)) continue;
        $r = nm_bio_ingest_dns_verdict($conn, $v);
        if (!empty($r['flagged']))  $flagged++;
        if (!empty($r['promoted'])) $promoted++;
    }
    echo json_encode(['ok'=>true, 'flagged'=>$flagged, 'promoted'=>$promoted]); exit;
}
if ($ep === 'synthetic') {   // P3 — async headless-journey result from the n8n bio-http-synthetic flow
    $body = json_decode(file_get_contents('php://input'), true) ?: $_POST;
    $sid  = (int)($body['service_id'] ?? 0);
    $result = is_array($body['result'] ?? null) ? $body['result'] : $body;   // {result:{…}} or a bare result
    if ($sid <= 0) { echo json_encode(['ok'=>false,'error'=>'service_id required']); exit; }
    echo json_encode(nm_bio_ingest_synthetic($conn, $sid, $result)); exit;
}
echo json_encode(['ok'=>false, 'error'=>'unknown endpoint']);
