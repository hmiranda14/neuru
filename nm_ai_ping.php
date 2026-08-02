<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — AI Gateway registration ping.
// The NEURU Portal calls this when a customer registers their install for the
// hosted "NEURU AI Flows" service: it POSTs here with the customer's inbound
// token in X-NetMon-Token to prove that {base_url, token} is a real, reachable
// NEURU that accepts that token. Read-only, token-gated, returns product identity.
//   POST/GET  https://<customer-neuru>/nm_ai_ping.php
//   auth:     X-NetMon-Token: <token>  |  Authorization: Bearer <token>  |  ?token=
//   200 {ok:true, product:"neuru", version, ts}   |   401 {ok:false,error}
// ─────────────────────────────────────────────────────────────────────────────
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_n8n.php';
header('Content-Type: application/json; charset=utf-8');

$tok = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? '';
if ($tok === '' && !empty($_SERVER['HTTP_AUTHORIZATION'])) $tok = preg_replace('/^Bearer\s+/i', '', $_SERVER['HTTP_AUTHORIZATION']);
if ($tok === '' && isset($_GET['token'])) $tok = (string)$_GET['token'];

if (!nm_n8n_verify_inbound($conn, $tok)) {
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => 'unauthorized']);
    exit;
}

$ver = @trim((string)@file_get_contents(__DIR__ . '/VERSION'));
echo json_encode(['ok' => true, 'product' => 'neuru', 'version' => ($ver !== '' ? $ver : 'unknown'), 'ts' => date('c')]);
