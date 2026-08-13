<?php
// NEURU — generic FLOW SCHEDULER. Fires the webhook flows the OWNER scheduled in the Portal VIP
// (ai_flow.schedule_minutes → synced into nm_settings 'flow_schedule' = {slug:minutes}). Each fire
// goes nm_n8n_call → hosted flow → its gatecheck → the run is REGISTERED + BILLED + visible. So a
// scheduled flow "just runs" on its cadence and the owner sees it, never blind.
//
// SAFE BY DESIGN — zero double-fire:
//   • Default 'flow_schedule' is empty → this cron no-ops until the owner sets a cadence in the VIP.
//   • $EXCLUDE = flows ALREADY driven by a dedicated NEURU cron (biosphere/anomaly/config/smokeping/
//     weather/notify) → never fired here (their own cron owns them).
//   • Per-flow throttle in nm_settings 'flowsched_last_<slug>' so a */5 cron respects each cadence.
//
//   */5 * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_flows.php
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_n8n.php';
require_once __DIR__ . '/nm_tz.php';

header('Content-Type: application/json; charset=utf-8');
$cfg  = nm_n8n_get($conn);
$hdr  = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
$want = (string)($cfg['inbound_token'] ?? '');
if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }

// Flows already fired by a dedicated cron — NEVER schedule them here (would double-fire = double-bill).
$EXCLUDE = ['bio-dns-audit','bio-http-synthetic','anomaly-learn','anomaly-detect','config-backup','smokeping-manage','weather-poll','neuru-notify'];

$sched = json_decode(_nm_set_get($conn, 'flow_schedule', '{}'), true);
if (!is_array($sched) || !$sched) { echo json_encode(['ok'=>true, 'note'=>'no scheduled flows']); exit; }

$tz  = function_exists('nm_tz_get') ? nm_tz_get($conn) : 'UTC';
$now = time();
$out = [];
foreach ($sched as $slug => $mins) {
    $slug = (string)$slug; $mins = (int)$mins;
    if ($mins <= 0 || in_array($slug, $EXCLUDE, true)) { $out[$slug] = 'skipped'; continue; }
    $wh = nm_n8n_webhook_by_slug($conn, $slug);
    if (!$wh || empty($wh['enabled'])) { $out[$slug] = 'not synced'; continue; }
    $lastKey = 'flowsched_last_' . $slug;
    $last = 0;
    try { if ($r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='" . $conn->real_escape_string($lastKey) . "' LIMIT 1")) { if ($x = $r->fetch_row()) $last = (int)$x[0]; } } catch (\Throwable $e) {}
    if (($now - $last) < $mins * 60) { $out[$slug] = 'throttled'; continue; }
    try {
        [$code, , $err] = nm_n8n_call($conn, $slug, ['app_timezone' => $tz, 'scheduled' => true], 30);
        $out[$slug] = ['http' => $code, 'err' => $err];
        try { if ($s = $conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)")) { $nv = (string)$now; $s->bind_param('ss', $lastKey, $nv); $s->execute(); $s->close(); } } catch (\Throwable $e) {}
    } catch (\Throwable $e) { $out[$slug] = ['err' => substr($e->getMessage(), 0, 120)]; }
}
echo json_encode(['ok' => true, 'tz' => $tz, 'fired' => $out]);
