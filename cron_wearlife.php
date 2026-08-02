<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Hardware Longevity accumulator cron.  */10 * * * *
// Snapshots every monitored Windows rig's wear sensors (temps/fans/loads via LHM +
// SSD SMART) and folds them into nm_hw_wear so the Health Passport projections build
// passively over time — the gamer doesn't have to sit on the page. Best-effort per rig
// (a slow/offline rig never blocks the others). Sample dt is capped in nm_wl_accumulate.
// ─────────────────────────────────────────────────────────────────────────────
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_wearlife.php';

$rows = function_exists('nm_win_hosts') ? nm_win_hosts($conn) : [];
$done = 0;
foreach ($rows as $h) {
    $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn, $h) : null;
    if (!$ssh) continue;
    try { $r = nm_wl_scan($conn, (int)$h['id'], $ssh); if (!empty($r['ok'])) $done++; } catch (\Throwable $e) {}
}
echo "wearlife: accumulated {$done}/" . count($rows) . " rig(s)\n";
