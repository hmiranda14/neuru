<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Container Error AI analysis (resilient, SYNCHRONOUS).
//
// Restores the "AI Insight" on container incidents after the n8n flow-wipe disaster
// that de-registered the dedicated `container-analyze` flow. Instead of depending on
// that one (often-missing) flow + an async callback (which silently drops if the
// callback base can't reach us), this calls whatever AI-RCA flow IS live, reads the
// analysis straight from the HTTP reply, and writes ai_summary/ai_solution itself.
//
// Flow preference (first that is registered + enabled wins):
//   1. `container-analyze` — the dedicated Error-Watch analyze flow (historical/"like before").
//   2. `log-rca`           — the general Log Root-Cause-Analysis flow (a container error IS a
//                            log line needing RCA). Same metered LiteLLM brain, always shipped.
// Both are metered per-token via `_neuru.vkey` (nm_n8n_call injects it) — billing unchanged.
//
// Response mapping is defensive so it works for BOTH shapes:
//   container-analyze → {summary, solution}
//   log-rca           → {summary, root_cause, recommended_actions[], confidence}
// ─────────────────────────────────────────────────────────────────────────────

if (!function_exists('nm_container_ai_analyze')) {

// Which live flow will handle the analysis? Returns a slug or '' if none is available.
function nm_erroranalyze_pick_flow(mysqli $conn): string {
    if (!function_exists('nm_n8n_webhook_by_slug')) return '';
    foreach (['container-analyze', 'log-rca'] as $slug) {
        $wh = nm_n8n_webhook_by_slug($conn, $slug);
        if ($wh && !empty($wh['enabled']) && trim((string)($wh['url'] ?? '')) !== '') return $slug;
    }
    return '';
}

// Analyze ONE incident synchronously. Writes ai_summary/ai_solution on success (and flips
// 'analyzing' → 'open'); leaves any prior analysis untouched on failure. Never throws.
// Returns ['ok'=>bool, 'via'=>slug, 'summary'=>..., 'solution'=>..., 'error'=>..., 'http'=>int].
function nm_container_ai_analyze(mysqli $conn, int $id, int $timeout = 40): array {
    if (!function_exists('nm_n8n_call')) return ['ok' => false, 'error' => 'nm_n8n_call unavailable'];

    $st = $conn->prepare("SELECT id,container_name,host,host_ip,severity,error_text,last_seen,status
                          FROM container_incidents WHERE id=? LIMIT 1");
    $st->bind_param('i', $id); $st->execute();
    $inc = $st->get_result()->fetch_assoc(); $st->close();
    if (!$inc) return ['ok' => false, 'error' => 'incident not found'];

    $err = trim((string)$inc['error_text']);
    if ($err === '') return ['ok' => false, 'error' => 'incident has no error text'];

    $slug = nm_erroranalyze_pick_flow($conn);
    if ($slug === '') return ['ok' => false, 'error' => 'no AI-analyze flow available (enable an n8n webhook slug "container-analyze" or "log-rca")'];

    // One payload that satisfies BOTH flow contracts:
    //  • log-rca reads `logs` (array of {message,timestamp,source}) + `node`
    //  • container-analyze reads `error`/`container_name`/`severity`
    $when = strtotime((string)$inc['last_seen']);
    $logs = [[
        'message'   => substr($err, 0, 4000),
        'timestamp' => gmdate('c', $when ?: time()),
        'source'    => (string)$inc['container_name'],
        'level'     => (string)$inc['severity'],
    ]];
    $payload = [
        'event'          => 'analyze',
        'incident_id'    => $id,
        'container_name' => (string)$inc['container_name'],
        'host'           => (string)$inc['host'],
        'host_ip'        => (string)$inc['host_ip'],
        'severity'       => (string)$inc['severity'],
        'error'          => $err,
        'error_text'     => $err,
        'logs'           => $logs,
        'node'           => ['name' => (string)$inc['container_name'], 'ip' => (string)$inc['host_ip']],
    ];

    [$code, $j, $e] = nm_n8n_call($conn, $slug, $payload, $timeout);
    $http = (int)$code;
    if ($http < 200 || $http >= 300) return ['ok' => false, 'via' => $slug, 'http' => $http, 'error' => "flow \"$slug\" HTTP $http" . ($e ? " ($e)" : '')];
    if (is_string($j)) { $d = json_decode($j, true); if (is_array($d)) $j = $d; }
    if (!is_array($j)) return ['ok' => false, 'via' => $slug, 'http' => $http, 'error' => "flow \"$slug\" returned non-JSON"];

    // Some flows wrap the payload ({ok, result:{...}} / {data:{...}}) — unwrap.
    foreach (['result', 'data', 'analysis', 'output'] as $k) {
        if (isset($j[$k]) && is_array($j[$k]) && (isset($j[$k]['summary']) || isset($j[$k]['recommended_actions']) || isset($j[$k]['solution']))) { $j = $j[$k]; break; }
    }

    // ── map to summary + solution (defensive across both shapes) ──
    $summary = trim((string)($j['summary'] ?? ($j['ai_summary'] ?? ($j['answer'] ?? ''))));
    $rootc   = trim((string)($j['root_cause'] ?? ''));
    if ($rootc !== '' && stripos($summary, $rootc) === false) {
        $summary = ($summary !== '' ? rtrim($summary, '.') . '. ' : '') . 'Root cause: ' . $rootc . '.';
    }
    $solution = trim((string)($j['solution'] ?? ($j['ai_solution'] ?? ($j['fix'] ?? ''))));
    if ($solution === '' && !empty($j['recommended_actions']) && is_array($j['recommended_actions'])) {
        $steps = []; $i = 1;
        foreach ($j['recommended_actions'] as $a) { $a = trim((string)$a); if ($a !== '') $steps[] = ($i++) . '. ' . $a; }
        $solution = implode("\n", $steps);
    }
    if (!empty($j['confidence']) && $solution !== '') {
        $conf = (float)$j['confidence'];
        if ($conf > 0 && $conf <= 1) $solution .= "\n\n(AI confidence: " . round($conf * 100) . "%)";
    }

    if ($summary === '' && $solution === '') return ['ok' => false, 'via' => $slug, 'http' => $http, 'error' => "flow \"$slug\" returned an empty analysis"];

    // Persist. COALESCE(NULLIF) so an empty field never wipes an existing one.
    $sumV = $summary !== '' ? $summary : null;
    $solV = $solution !== '' ? $solution : null;
    try {
        $u = $conn->prepare("UPDATE container_incidents
            SET ai_summary=COALESCE(?,ai_summary), ai_solution=COALESCE(?,ai_solution),
                status=IF(status='analyzing','open',status) WHERE id=?");
        $u->bind_param('ssi', $sumV, $solV, $id); $u->execute(); $u->close();
    } catch (\Throwable $x) { return ['ok' => false, 'via' => $slug, 'http' => $http, 'error' => 'DB write failed: ' . $x->getMessage()]; }

    return ['ok' => true, 'via' => $slug, 'http' => $http, 'summary' => $summary, 'solution' => $solution];
}

// Batch: analyze up to $limit incidents currently parked in 'analyzing' with no summary yet.
// Used by the native cron so NEW container errors get AI Insight automatically (like before),
// capped so one cron tick never stalls on a slow LLM. Returns [done, failed].
function nm_container_ai_analyze_pending(mysqli $conn, int $limit = 5, int $timeout = 30): array {
    if (nm_erroranalyze_pick_flow($conn) === '') return ['done' => 0, 'failed' => 0, 'skipped' => 'no_flow'];
    $ids = [];
    if ($r = $conn->query("SELECT id FROM container_incidents
                           WHERE status='analyzing' AND (ai_summary IS NULL OR ai_summary='')
                           ORDER BY last_seen DESC LIMIT " . max(1, min(20, $limit)))) {
        while ($x = $r->fetch_row()) $ids[] = (int)$x[0];
    }
    $done = $failed = 0;
    foreach ($ids as $iid) {
        $res = nm_container_ai_analyze($conn, $iid, $timeout);
        if (!empty($res['ok'])) $done++; else $failed++;
    }
    return ['done' => $done, 'failed' => $failed];
}

} // function_exists guard
