<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Stream Decks telemetry cron (cron_deck.php)
//
// Keeps the deck's PC telemetry cache warm so the live preview + the on-PC plugin read
// pre-populated values (instant) instead of triggering a 15-30s SSH round-trip on every
// poll. Refreshes the configured rig's tiered cache (nm_deck_refresh_cache) and stamps a
// heartbeat (deck_cron_last) so nm_deck_telemetry knows the cron owns refresh.
//
// Token-gated like every other cron:  nm_cron.sh cron_deck.php  (run every minute).
// No-op when no rig is selected (NOC-only decks need no SSH) or the module is unused.
// ─────────────────────────────────────────────────────────────────────────────
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_deck.php';

$CLI = (PHP_SAPI === 'cli');

if (!$CLI) {
    header('Content-Type: application/json');
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? '';
    if ($hdr === '' && isset($_GET['token'])) $hdr = (string)$_GET['token'];
    $want = nm_deck_get($conn, 'n8n_inbound_token', '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(403); echo json_encode(['ok' => false, 'error' => 'forbidden']); exit; }
}
$out = function (array $a) use ($CLI) { echo $CLI ? (json_encode($a) . "\n") : json_encode($a); exit; };

// Warm EVERY rig any tile targets for PC metrics (default rig + all bound r/n targets) — so multi-node
// scenes stay realtime. Node/NOC metrics are cheap DB reads (no warming needed).
$rigs = nm_deck_active_rigs($conn);

// Nothing to warm if no PC rig is targeted — the NOC + node vitals are always live/cheap.
if (!$rigs) { nm_deck_set($conn, 'deck_cron_last', (string)time()); $out(['ok' => true, 'skipped' => 'no_pc_targets']); }

$t0 = microtime(true);
@set_time_limit(70);   // the loop below runs up to ~52s; don't let PHP's 30s cap kill it mid-refresh

// Loop within the minute so the pad feels realtime even though cron granularity is 1/min. Bounded to
// ~52s so it never overlaps the next tick. Each cycle refreshes every targeted rig's tiered cache +
// stamps the heartbeat so nm_deck_cron_alive() stays true and the API serves warm cache.
$refresh  = max(5, (int)(nm_deck_get($conn, 'deck_refresh', '15') ?: 15));
$deadline = $t0 + 52;
$cycles = 0;
do {
    foreach ($rigs as $r) { try { nm_deck_refresh_cache($conn, $r, false); } catch (\Throwable $e) { /* one bad SSH cycle never wedges the cron */ } }
    nm_deck_set($conn, 'deck_cron_last', (string)time());
    $cycles++;
    if (microtime(true) + $refresh >= $deadline) break;
    sleep($refresh);
} while (microtime(true) < $deadline);

// echo a compact status for the cron log (first targeted rig)
$rig = $rigs[0];
$fast = json_decode(nm_deck_get($conn, 'deck_pcfast_' . $rig, ''), true) ?: [];
$slow = json_decode(nm_deck_get($conn, 'deck_pcslow_' . $rig, ''), true) ?: [];
$out(['ok' => true, 'rigs' => $rigs, 'cycles' => $cycles, 'took_ms' => (int)round((microtime(true) - $t0) * 1000),
      'pc_ok' => !empty($fast['ok']),
      'fast' => ['cpu' => $fast['cpu'] ?? null, 'gpu' => $fast['gpu'] ?? null, 'gpu_temp' => $fast['gpu_temp'] ?? null, 'age' => time() - (int)($fast['ts'] ?? 0)],
      'slow' => ['nvme' => $slow['nvme'] ?? null, 'ping' => $slow['ping'] ?? null, 'age' => time() - (int)($slow['ts'] ?? 0)]]);
