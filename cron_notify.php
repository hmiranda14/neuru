<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Notification Center maintenance tick. Flushes the digest queue into
// per-channel summaries and self-alerts when a channel keeps failing. Runs every
// few minutes:  */5 * * * * scripts/nm_cron.sh cron_notify.php
// (Incident delivery/escalation runs minutely from cron_incidents.php.)
// ─────────────────────────────────────────────────────────────────────────────
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_notify.php';
require __DIR__ . '/nm_n8n.php';

if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_SERVER['HTTP_X_API_KEY'] ?? '');
    if (!$hdr && !empty($_SERVER['HTTP_AUTHORIZATION'])) $hdr = preg_replace('/^Bearer\s+/i', '', $_SERVER['HTTP_AUTHORIZATION']);
    if (!$hdr && isset($_GET['token'])) $hdr = $_GET['token'];
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) {
        http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit;
    }
}

$out = ['digest'=>['digests_sent'=>0], 'health_alerts'=>0];

// 1) Flush batched (digest / quiet-hour) events into summaries.
try { $out['digest'] = nm_notify_digest_flush($conn); } catch (\Throwable $e) { $out['digest_err'] = $e->getMessage(); }

// 2) Self-alert on a persistently-failing channel (routed to any HEALTHY channel
//    subscribed to 'system'). Guarded to once per channel per 6h so it never spams.
try {
    $health = nm_notify_channel_health($conn);
    $lastRaw = '';
    if ($r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='notify_health_alerted' LIMIT 1"))
        $lastRaw = ($x=$r->fetch_row()) ? $x[0] : '';
    $last = json_decode((string)$lastRaw, true); if (!is_array($last)) $last = [];
    $now = time(); $changed = false;
    foreach ($health as $cid => $st) {
        if (($st['fails'] ?? 0) < 5) continue;
        if (isset($last[$cid]) && ($now - (int)$last[$cid]) < 6*3600) continue;   // already warned recently
        $full = nm_notify_channel_get($conn, (int)$cid);
        $nm = $full['name'] ?? ('channel#'.$cid);
        nm_notify_event($conn, 'system', 'warning', "Notification channel \"$nm\" is failing",
            "The last {$st['fails']} deliveries to \"$nm\" failed — check its token/URL in the Notification Center.",
            ['entity'=>'channel#'.$cid, 'source'=>'notify_health']);
        $last[$cid] = $now; $changed = true; $out['health_alerts']++;
    }
    if ($changed) {
        $j = json_encode($last);
        $stt = $conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES('notify_health_alerted',?) ON DUPLICATE KEY UPDATE setting_val=?");
        $stt->bind_param('ss',$j,$j); $stt->execute(); $stt->close();
    }
} catch (\Throwable $e) { $out['health_err'] = $e->getMessage(); }

echo $IS_CLI
    ? "notify cron: digests={$out['digest']['digests_sent']} health_alerts={$out['health_alerts']}\n"
    : json_encode(['ok'=>true] + $out + ['at'=>date('c')]);
