<?php
// NEURU — weather poll tick. Triggers the n8n weather flow + prunes expired alerts.
//   */15 * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_weather.php
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_weather.php';
require __DIR__ . '/nm_n8n.php';
if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
}
$conn->query("DELETE FROM nm_weather_alerts WHERE expires IS NOT NULL AND expires < NOW()");
$r = nm_wx_poll($conn);
echo $IS_CLI ? ("weather: ".json_encode($r)."\n") : json_encode(['ok'=>true]+$r+['at'=>date('c')]);
