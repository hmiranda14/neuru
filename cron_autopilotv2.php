<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — AI Commander V2.0 cron. Every minute: SCAN the signal bus (normalize all
// enabled channels → nm_ap2_signals, dedup + drop 'ignore'-ruled), then PACE (promote
// NEW signals into dispatched sessions, bounded, one investigation per node). Periodically
// refreshes the fleet map. No-op while the master switch (ap2_enabled) is OFF.
//   * * * * * /var/www/html/netmon/scripts/nm_cron.sh cron_autopilotv2.php
// ─────────────────────────────────────────────────────────────────────────────
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_autopilotv2.php';

$CLI = (PHP_SAPI === 'cli');
if (!$CLI) {
    header('Content-Type: application/json');
    $tok = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $ok = function_exists('nm_n8n_verify_inbound') ? nm_n8n_verify_inbound($conn, (string)$tok)
        : hash_equals((string)nm_ap2_get($conn, 'n8n_inbound_token', ''), (string)$tok);
    if (!$ok) { http_response_code(403); echo json_encode(['ok' => false, 'error' => 'forbidden']); exit; }
}
$out = function (array $a) use ($CLI) { echo $CLI ? json_encode($a) . "\n" : json_encode($a); exit; };

nm_ap2_ensure($conn);
if (!nm_ap2_enabled($conn)) $out(['ok' => true, 'skipped' => 'ap2_disabled']);

// reap stale sessions (active/awaiting > 20 min with no update → idle, free the slot). We do NOT set the
// signal to 'stale' here — that pre-empted nm_ap2_pace's orphan reconciler (which retries the signal as 'new').
try { $conn->query("UPDATE nm_ap2_sessions SET status='idle' WHERE status IN('active','awaiting_approval') AND updated_at < (NOW() - INTERVAL 20 MINUTE)"); } catch (\Throwable $e) {}

// PRUNE terminal rows (once/hour) so the tables — and the auto-resolve/scan working set — don't grow unbounded.
$lastPrune = (int)strtotime(nm_ap2_get($conn, 'ap2_prune_at', '2000-01-01'));
if (time() - $lastPrune > 3600) { nm_ap2_set($conn, 'ap2_prune_at', gmdate('Y-m-d H:i:s'));
    try { $conn->query("DELETE FROM nm_ap2_signals WHERE status IN('resolved','ignored','stale') AND last_seen < (NOW() - INTERVAL 2 DAY)"); } catch (\Throwable $e) {}
    try { $conn->query("DELETE FROM nm_ap2_events   WHERE created_at < (NOW() - INTERVAL 7 DAY)"); } catch (\Throwable $e) {}
    try { $conn->query("DELETE FROM nm_ap2_sessions WHERE status IN('done','idle','error') AND updated_at < (NOW() - INTERVAL 7 DAY)"); } catch (\Throwable $e) {}
    try { $conn->query("DELETE FROM nm_ap2_tg_approvals WHERE status<>'pending' AND decided_at < (NOW() - INTERVAL 7 DAY)"); } catch (\Throwable $e) {}
}

// refresh the fleet map every ~10 min (cheap cursor in settings)
$lastFleet = (int)strtotime(nm_ap2_get($conn, 'ap2_fleet_at', '2000-01-01'));
$fleet = 0;
if (time() - $lastFleet > 600) { $fleet = nm_ap2_fleet_refresh($conn); nm_ap2_set($conn, 'ap2_fleet_at', gmdate('Y-m-d H:i:s')); }

$scan = nm_ap2_scan($conn);   // signal bus
$pace = nm_ap2_pace($conn);   // promote → dispatch

$out(['ok' => true, 'scan' => $scan, 'pace' => $pace, 'fleet_refreshed' => $fleet]);
