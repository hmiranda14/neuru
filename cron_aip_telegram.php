<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — NetAIObot two-way Telegram approval poller.
// Reads the operator's Approve/Deny button taps from Telegram (getUpdates) and
// applies the decision to the matching pending action.
//
// MUST run via curl→localhost (Apache/www-data) — the Telegram bot token is stored
// ENCRYPTED and nm_secret_decrypt only works under www-data, NOT the CLI SAPI.
//
// Cron (every minute):
//   * * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_aip_telegram.php
// ─────────────────────────────────────────────────────────────────────────────
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_aiopilot.php';
require __DIR__ . '/nm_n8n.php';

header('Content-Type: application/json; charset=utf-8');

// Auth: this endpoint touches secrets + executes approved actions — require the shared token.
$cfg  = nm_n8n_get($conn);
$hdr  = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
$want = (string)($cfg['inbound_token'] ?? '');
if ($want === '' || !hash_equals($want, (string)$hdr)) {
    http_response_code(401);
    echo json_encode(['ok'=>false,'error'=>'Unauthorized — bad or missing X-NetMon-Token']);
    exit;
}

// short long-poll (seconds) — keep well under the curl/PHP request budget.
$longpoll = max(0, min(25, (int)($_GET['wait'] ?? 0)));
$res = nm_aip_tg_poll($conn, $longpoll);
echo json_encode(['ok'=>!empty($res['ok'])] + $res);
