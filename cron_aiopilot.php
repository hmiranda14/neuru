<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — AI Copilot loop (cron). For each SELECTED+enabled device, if there's a
// live concern (down/degraded, or an open critical/warning insight) and no active
// session in the last few minutes, wake NetAIObot: start a session + dispatch the
// full context to the n8n brain. Dispatch is OUTBOUND-only (no secrets) so it is
// safe from CLI; any SSH/action runs later in the n8n callback (Apache/www-data).
//
// Cron: every 2 min →  */2 * * * * php /var/www/html/netmon/cron_aiopilot.php
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_config.php';
require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/nm_aiopilot.php';

nm_aip_ensure($conn);
$log = function ($m) { echo '[' . date('Y-m-d H:i:s') . "] $m\n"; };

if (!nm_aip_enabled($conn)) { $log('AI Copilot master switch is OFF — skipping.'); exit; }

$devs = nm_aip_devices($conn);
if (!$devs) { $log('No devices selected for AI Copilot. Done.'); exit; }

// 1) ENQUEUE every concerned device (covers ALL of them, not just one).
$enq = 0;
foreach ($devs as $d) {
    if (empty($d['enabled'])) continue;
    $nid = (int)$d['node_id'];

    // Concern detection: down/degraded OR an open critical/warning insight
    $concern = false; $why = '';
    $as = $conn->query("SELECT last_status FROM nm_alert_state WHERE entity_type='node' AND entity_id=$nid LIMIT 1");
    if ($as && $as->num_rows) {
        $ls = $as->fetch_assoc()['last_status'];
        if (in_array($ls, ['down','degraded','lowerlayerdown','notpresent','testing'], true)) { $concern = true; $why = "state=$ls"; }
    }
    if (!$concern) {
        $ci = $conn->query("SELECT COUNT(*) c FROM nm_ai_insights WHERE node_id=$nid
                            AND status IN ('open','acknowledged') AND severity IN ('critical','warning')");
        if ($ci && (int)$ci->fetch_assoc()['c'] > 0) { $concern = true; $why = 'open critical/warning insight'; }
    }
    if (!$concern) continue;

    $name = $conn->query("SELECT display_name FROM nm_nodes WHERE id=$nid")->fetch_assoc()['display_name'] ?? "node $nid";
    if (nm_aip_enqueue($conn, $nid, 'cron', "Auto-investigation: $name ($why)")) { $enq++; $log("Queued $name (#$nid) — $why"); }
}

// 1b) PROACTIVE PULSE — keep NetAIObot alive + catch issues early: periodically OBSERVE the
// healthy node that has gone longest without a look (>= aip_pulse_min). We enqueue only the
// single most-stale node per run, so it rotates gently through the fleet and self-limits to
// roughly one pass per node per cadence. Concerned nodes (handled above) skip this.
$pulseMin = (int)nm_aip_setting($conn, 'aip_pulse_min', '30');   // 0 = disabled
if ($pulseMin > 0) {
    $best = null; $bestAge = -1.0;
    foreach ($devs as $d) {
        if (empty($d['enabled'])) continue;
        $nid = (int)$d['node_id'];
        // skip if it already has a live session (concern-queued above, or still running)
        $live = $conn->query("SELECT 1 FROM nm_aip_sessions WHERE node_id=$nid AND status IN ('queued','active','awaiting_approval') LIMIT 1");
        if ($live && $live->num_rows) continue;
        $lr = $conn->query("SELECT UNIX_TIMESTAMP(MAX(created_at)) mx FROM nm_aip_sessions WHERE node_id=$nid");
        $mx = $lr ? (int)($lr->fetch_assoc()['mx'] ?? 0) : 0;
        $ageMin = $mx ? (time() - $mx) / 60.0 : 1e9;   // never observed → very stale
        if ($ageMin >= $pulseMin && $ageMin > $bestAge) { $bestAge = $ageMin; $best = $nid; }
    }
    if ($best) {
        $name = $conn->query("SELECT display_name FROM nm_nodes WHERE id=$best")->fetch_assoc()['display_name'] ?? "node $best";
        if (nm_aip_enqueue($conn, $best, 'pulse', "Proactive health pulse: $name")) {
            $enq++; $log(sprintf("Pulse-queued %s (#%d) — proactive observation (%.0fm since last)", $name, $best, $bestAge));
        }
    }
}

// 2) PACE the queue: promote a few to the LLM, bounded by max_concurrent + spaced by gap.
$p = nm_aip_pace($conn);
$log("Done. Enqueued $enq · promoted {$p['promoted']} (active={$p['active']}, queued left={$p['queued']}).");
