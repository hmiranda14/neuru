<?php
// NEURU — Anomaly flows DRIVER. Universal, webhook-based (NOT n8n-scheduled): NEURU
// triggers the two anomaly flows on schedule so EVERY install runs them against ITS OWN
// endpoints — nm_n8n_call() stamps the payload with this install's callback_base +
// callback_token (nm_n8n_neuru_block), so the flow reads nm_ai_api.php and posts to
// nm_ai_ingest.php on THIS box, with THIS box's token. No dev IP, no per-install injection.
//
//   • anomaly-detect  → every run  (cron cadence ~10 min): z-score latest vs baseline → insights
//   • anomaly-learn   → throttled to every 6 h            : recompute per-metric baselines
//
// Runs via curl→localhost (Apache/www-data), authed by the inbound token:
//   */10 * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_anomaly.php
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_n8n.php';
require_once __DIR__ . '/nm_tz.php';

header('Content-Type: application/json; charset=utf-8');
$cfg  = nm_n8n_get($conn);
$hdr  = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
$want = (string)($cfg['inbound_token'] ?? '');
if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }

// The two flows carry the install's timezone so the LEARN/DETECT hour_of_week buckets match the
// overlay's local-time convention (net_mon_stats.php: ((getDay()+6)%7)*24 + getHours()).
$tz      = function_exists('nm_tz_get') ? nm_tz_get($conn) : 'UTC';
$payload = ['app_timezone' => $tz];

// Fire a flow ONLY if its webhook is registered + enabled (synced from the Portal). Absent →
// quiet no-op, so an install that hasn't synced the anomaly flows never errors or logs noise.
$fire = function (string $slug) use ($conn, $payload): array {
    $wh = nm_n8n_webhook_by_slug($conn, $slug);
    if (!$wh || empty($wh['enabled'])) return ['slug'=>$slug, 'skipped'=>'not synced'];
    try {
        [$code, , $err] = nm_n8n_call($conn, $slug, $payload, 30);
        return ['slug'=>$slug, 'http'=>$code, 'err'=>$err];
    } catch (\Throwable $e) {
        return ['slug'=>$slug, 'err'=>substr($e->getMessage(), 0, 120)];
    }
};

$out = ['ok'=>true, 'tz'=>$tz];

// DETECT — every run.
$out['detect'] = $fire('anomaly-detect');

// LEARN — throttled to every 6 h via nm_settings (best-effort; UTC unix clock, mysqli-safe).
$LEARN_EVERY = 6 * 3600;
$now = time();
$last = 0;
try { if ($r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='anomaly_learn_last' LIMIT 1")) { if ($x = $r->fetch_row()) $last = (int)$x[0]; } } catch (\Throwable $e) {}
if (($now - $last) >= $LEARN_EVERY) {
    $out['learn'] = $fire('anomaly-learn');
    // stamp last-run only if we actually reached the flow (don't burn the 6 h window on a no-op)
    if (empty($out['learn']['skipped'])) {
        try { if ($s = $conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES('anomaly_learn_last',?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)")) { $nv = (string)$now; $s->bind_param('s', $nv); $s->execute(); $s->close(); } } catch (\Throwable $e) {}
    }
} else {
    $out['learn'] = ['skipped'=>'throttled', 'next_in_min'=>(int)ceil(($LEARN_EVERY - ($now - $last)) / 60)];
}

echo json_encode($out);
