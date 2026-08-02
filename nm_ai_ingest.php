<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — AI/automation INBOUND receiver. n8n flows POST results here (insights,
// RCA cards, incidents, anomaly findings). Machine-to-machine: NOT session-auth'd
// — authenticated by the shared inbound token in the `X-NetMon-Token` header
// (generate/rotate it in Config → Integrations & AI).
//
// POST JSON:
//   { "action":"insight"|"alert"|"ping",
//     "node_id": <int|null>, "kind":"rca|anomaly|incident|...",
//     "severity":"info|warning|critical", "title":"...", "body":"...",
//     "data":{...}, "correlation_key":"optional-group-id" }
//
// Response: { "ok": true, "id": <insight id> }  (or { ok:false, err }).
// ─────────────────────────────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');

require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/nm_n8n.php';

// ── AuthN: constant-time token check ──────────────────────────────────────────
$hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? '';
if ($hdr === '' && isset($_GET['token'])) $hdr = (string)$_GET['token'];   // fallback for simple flows
if (!nm_n8n_verify_inbound($conn, $hdr)) {
    http_response_code(401);
    echo json_encode(['ok'=>false, 'err'=>'Unauthorized — bad or missing X-NetMon-Token']);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    echo json_encode(['ok'=>false, 'err'=>'POST required']);
    exit;
}

$in     = json_decode(file_get_contents('php://input'), true);
if (!is_array($in)) $in = $_POST;
$action = $in['action'] ?? 'insight';

if ($action === 'ping') {
    echo json_encode(['ok'=>true, 'pong'=>true, 'ts'=>date('c')]);
    exit;
}

// Batch-upsert learned baselines from the anomaly-learn flow.
// { action:"baseline_upsert", baselines:[ {node_id,metric_type,metric_key,hour_of_week,mean,stdev,samples}, ... ] }
if ($action === 'baseline_upsert') {
    $rows = $in['baselines'] ?? [];
    if (!is_array($rows) || !$rows) { echo json_encode(['ok'=>false,'err'=>'baselines[] required']); exit; }
    $st = $conn->prepare("INSERT INTO nm_ai_baselines
        (node_id, metric_type, metric_key, hour_of_week, mean, stdev, samples)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE mean=VALUES(mean), stdev=VALUES(stdev), samples=VALUES(samples)");
    $n = 0;
    foreach ($rows as $b) {
        $nid = (int)($b['node_id'] ?? 0);
        $mt  = substr((string)($b['metric_type'] ?? ''), 0, 40);
        $mk  = substr((string)($b['metric_key'] ?? ''), 0, 80);
        $hw  = (int)($b['hour_of_week'] ?? -1);
        if (!$nid || $mt === '' || $hw < 0 || $hw > 167) continue;
        $mean = (float)($b['mean'] ?? 0); $sd = (float)($b['stdev'] ?? 0); $smp = (int)($b['samples'] ?? 0);
        $st->bind_param('issiddi', $nid, $mt, $mk, $hw, $mean, $sd, $smp);
        if ($st->execute()) $n++;
    }
    echo json_encode(['ok'=>true, 'upserted'=>$n]);
    exit;
}

// ── Anomaly sanitizer ─────────────────────────────────────────────────────────
// The z-score detect flow over-fires because severity is mapped from raw |z|. Two
// invalid cases dominate: (a) UPTIME — a monotonic counter that can't be z-scored
// (every reboot looks like a huge negative-z "critical anomaly"); (b) VARIANCE
// COLLAPSE — a near-constant metric (e.g. /boot at 10.3%) has stdev≈0, so a 0.01pp
// move yields astronomical z and a false critical. We grade capacity metrics by
// absolute level + effect size (not raw z) and drop pure non-events. Mutates $in;
// returns a non-empty reason to SUPPRESS the card, or '' to store it.
// All anomaly thresholds are operator-configurable in net_mon_config.php → Thresholds
// (stored in nm_settings under thr_*). nm_ai_thr() reads them once, cached, with a safe
// (deliberately NON-sensitive) default so we err toward NOT alarming.
function nm_ai_thr($key, $def) {
    static $cache = null;
    if ($cache === null) {
        $cache = []; global $conn;
        if ($conn && ($r = @$conn->query("SELECT setting_key, setting_val FROM nm_settings WHERE setting_key LIKE 'thr\\_%'"))) {
            while ($r && ($x = $r->fetch_assoc())) $cache[$x['setting_key']] = $x['setting_val'];
        }
    }
    return (isset($cache[$key]) && $cache[$key] !== '') ? (float)$cache[$key] : (float)$def;
}

function nm_ai_anomaly_filter(array &$in): string {
    if (($in['kind'] ?? '') !== 'anomaly') return '';
    $d = $in['data'] ?? null;
    if (!is_array($d) || empty($d['metric_type'])) return '';
    $mt   = strtolower(trim((string)$d['metric_type']));
    $obs  = array_key_exists('observed', $d) ? (float)$d['observed'] : null;
    $mean = array_key_exists('mean', $d)     ? (float)$d['mean']     : null;
    if ($obs === null || $mean === null) return '';
    $absdev = abs($obs - $mean);
    $key    = trim((string)($d['metric_key'] ?? ''));

    // (1) UPTIME is monotonic ⇒ z-scoring it is invalid. A device is "recently rebooted"
    //     ONLY when its uptime is genuinely SMALL in absolute terms — NOT merely below a
    //     noisy hourly baseline. (Bug fixed: a box up 121h was flagged "recently rebooted"
    //     just because the baseline expected 312h.) Above the window → drop as noise.
    if ($mt === 'uptime') {
        if ($obs >= $mean - 60) return 'uptime-normal';          // up at least as long as usual
        $h     = $obs / 3600.0;
        $maxH  = nm_ai_thr('thr_reboot_max_h', 12);              // only flag if up < this many hours
        $warnH = nm_ai_thr('thr_reboot_warn_h', 3);             // and a very fresh reboot is a warning
        if ($h > $maxH) return 'uptime-baseline-noise';          // long uptime, just a higher baseline → NOT a reboot
        $in['severity'] = 'info';                                // a reboot is an informational FACT, never an incident-worthy alarm
        $in['title']    = preg_replace('/^\s*Anomalous uptime/i', 'Device recently rebooted', (string)($in['title'] ?? ''));
        $in['body']     = 'Uptime ≈ ' . round($h, 1) . 'h — the device restarted within the last '
                        . round($maxH) . 'h. (Informational: uptime is a counter, not a statistical anomaly.)';
        $d['reframed']  = 'reboot'; $in['data'] = $d;
        return '';
    }

    // (2) Capacity percentages (0..100): grade by ABSOLUTE LEVEL, and only when usage is
    //     CLIMBING toward full. A usage DROP (e.g. memory 45%→9%) is relief, never an
    //     alarm; and a low absolute level is fine no matter how large the z (variance
    //     collapse, e.g. expected 45.07±0.13 → z=-271). Thresholds are configurable.
    if (in_array($mt, ['storage', 'disk', 'memory', 'ram'], true)) {
        // "available/free" metrics INVERT the meaning (high = more headroom = GOOD) and are
        // usually raw bytes/KB, not %. We can't grade them as usage → never alarm (real
        // pressure shows up on the matching USED % metric). Also drop anything that isn't a
        // 0..100 percentage (e.g. 1,485,456 KB free graded as "97%+ critical").
        if (preg_match('/avail|free|headroom/i', $key))  return 'capacity-headroom';
        if ($obs > 100.5 || $mean > 100.5)               return 'capacity-non-percent';
        $isDisk = ($mt === 'storage' || $mt === 'disk');
        $info  = nm_ai_thr($isDisk ? 'thr_disk_info' : 'thr_mem_info', 80);
        $warn  = nm_ai_thr($isDisk ? 'thr_disk_warn' : 'thr_mem_warn', 90);
        $crit  = nm_ai_thr($isDisk ? 'thr_disk_crit' : 'thr_mem_crit', $isDisk ? 96 : 97);
        $floor = $isDisk ? 5.0 : 8.0;                            // min meaningful pp move
        $rise  = $obs - $mean;                                   // + = climbing toward full (the only bad way)
        if      ($obs >= $crit)                       $in['severity'] = 'critical';
        elseif  ($obs >= $warn)                       $in['severity'] = 'warning';
        elseif  ($obs >= $info && $rise >= $floor)    $in['severity'] = 'info';   // at/above info level AND rising
        else return 'capacity-non-event';            // low level, or usage dropped (relief) → not a problem
        if ($key !== '' && stripos((string)($in['title'] ?? ''), $key) === false)
            $in['title'] = rtrim((string)($in['title'] ?? '')) . ' (' . $key . ')';   // disambiguate / vs /boot
        return '';
    }

    // (3) CPU / processor: grade by ABSOLUTE level too. A z-spike at low utilisation
    //     (1%→3%) is statistical noise, not an operational problem — only sustained HIGH
    //     cpu matters. Drop anything below a meaningful level regardless of z/deviation.
    if (in_array($mt, ['cpu', 'processor'], true)) {
        $info = nm_ai_thr('thr_cpu_info', 70); $warn = nm_ai_thr('thr_cpu_warn', 85); $crit = nm_ai_thr('thr_cpu_crit', 95);
        if      ($obs >= $crit) $in['severity'] = 'critical';
        elseif  ($obs >= $warn) $in['severity'] = 'warning';
        elseif  ($obs >= $info) $in['severity'] = 'info';
        else return 'cpu-low';                       // below the info level → not anomalous in any useful sense
        return '';
    }

    // (4) Everything else (custom sensors, load, …): severity should track effect size,
    //     not raw z. Demote a "critical" when it's only a modest deviation (|z|<10) OR
    //     when a near-zero stdev inflated z on a tiny absolute move — neither is critical.
    $z  = array_key_exists('z', $d)     ? (float)$d['z']     : null;
    $sd = array_key_exists('stdev', $d) ? (float)$d['stdev'] : null;
    if (($in['severity'] ?? '') === 'critical' && $z !== null
        && (abs($z) < 10 || ($sd !== null && $sd <= $absdev * 1e-3))) {
        $in['severity'] = 'warning';
    }
    return '';
}

if (in_array($action, ['insight', 'alert', 'incident'], true)) {
    // The portal runs its OWN topology incident correlation (nm_incidents.php) and is the
    // SINGLE source of truth. n8n's "blast-radius" flow used to POST kind='incident'
    // "Master incident" cards which duplicated it and caused 3-way inconsistency — we no
    // longer ingest them. (Disable the n8n "blast-radius" workflow too; anomaly-baseline
    // and the other flows are unaffected.)
    if (strtolower(trim((string)($in['kind'] ?? ''))) === 'incident'
        || stripos((string)($in['title'] ?? ''), 'Master incident') === 0) {
        echo json_encode(['ok'=>true, 'stored'=>false, 'filtered'=>'incident-correlation-handled-by-portal']);
        exit;
    }
    $__filtered = nm_ai_anomaly_filter($in);
    if ($__filtered !== '') {   // suppressed at the boundary — observable in n8n's exec log, not silent
        echo json_encode(['ok'=>true, 'stored'=>false, 'filtered'=>$__filtered]);
        exit;
    }
    // ── QUALITY GATE: drop NON-ACTIONABLE remediations ─────────────────────────────
    // The self-heal flow's fail-safe returns "Insufficient Data/Context for Remediation" cards
    // with a no-op `echo '…'` playbook and target=unknown when the LLM had nothing to act on
    // (or was called with a probe/thin payload). Those aren't findings — they'd only clutter the
    // user's incident list with an "Approve & Apply echo" card that says nothing useful. Reject
    // at the boundary so the operator only ever sees actionable, legible remediations.
    if (strtolower(trim((string)($in['kind'] ?? ''))) === 'remediation') {
        $_rtxt = strtolower((string)($in['title'] ?? '') . ' ' . (string)($in['body'] ?? ''));
        $_rd   = is_array($in['data'] ?? null) ? $in['data'] : [];
        $_pb   = strtolower(trim((string)($_rd['playbook'] ?? '')));
        if (preg_match('/insufficient (data|context|information)|not enough (data|context|information)|no actionable|please (provide|review|specify)|human should (investigate|review|look)/', $_rtxt)
            || preg_match('/^\s*echo\b/', $_pb) || $_pb === '') {
            echo json_encode(['ok'=>true, 'stored'=>false, 'filtered'=>'non-actionable-remediation']);
            exit;
        }
    }
    $node_id  = isset($in['node_id']) && $in['node_id'] !== '' ? (int)$in['node_id'] : null;
    $kind     = substr(trim((string)($in['kind'] ?? ($action === 'alert' ? 'incident' : 'insight'))), 0, 40);
    $severity = substr(trim((string)($in['severity'] ?? 'info')), 0, 20);
    $title    = substr(trim((string)($in['title'] ?? 'AI insight')), 0, 255);
    $body     = isset($in['body']) ? (string)$in['body'] : null;
    $corr     = isset($in['correlation_key']) ? substr(trim((string)$in['correlation_key']), 0, 120) : null;
    $data     = isset($in['data']) ? json_encode($in['data']) : null;
    $src      = substr(trim((string)($in['source'] ?? 'n8n')), 0, 40);

    // ── Filter BENIGN transient connection-cancellation log-noise (kind=rca) ─────────────────
    // The log-RCA flow "analyzes" harmless lines that Go services / cloudflared tunnels / the
    // NEURU↔Portal link emit constantly — "context canceled", "request canceled by the remote",
    // "stream cancellation" — and turns EACH into a scary but meaningless WARNING incident with a
    // cryptic title. These mean a client or the remote peer closed a connection early — NOT an
    // outage (a real outage surfaces through node-down / latency / error-rate signals instead).
    // Drop them at the boundary so they never become incidents.
    if ($kind === 'rca') {
        $_hay = strtolower($title . ' ' . (string)$body);
        if (preg_match('/context cancel(l?ed|lation)|cancel(l?ed|lation) by the remote|remote (server|service)[^.]{0,40}cancel|stream cancell?ation|stream was cancell?ed|request (was )?cancell?ed|client (disconnected|closed|hung up)|connection reset by peer|broken pipe|use of closed network connection/', $_hay)) {
            echo json_encode(['ok'=>true, 'stored'=>false, 'filtered'=>'benign-transient-cancellation']);
            exit;
        }
    }

    // ── LINK a returned remediation to the anomaly that requested it (Suggest fix) ──────────
    // ai_insights.php records node→correlation_key in nm_ai_heal_link when the user clicks Suggest
    // fix; adopt it here (unless the flow already echoed one) so they render as ONE grouped card.
    if ($kind === 'remediation' && ($corr === null || $corr === '') && $node_id !== null) {
        try {
            $lr = $conn->query("SELECT correlation_key FROM nm_ai_heal_link WHERE node_id={$node_id} AND requested_at > (NOW() - INTERVAL 60 MINUTE) LIMIT 1");
            if ($lr && $lr->num_rows) { $ck = (string)$lr->fetch_assoc()['correlation_key']; if ($ck !== '') $corr = substr($ck, 0, 120); }
        } catch (\Throwable $e) { /* table may not exist yet — no link */ }
    }

    // ── DEDUP at the ingest boundary ──────────────────────────────────────────
    // The AI flows re-fire the SAME finding every cycle (anomaly still true, remediation re-proposed)
    // which flooded the list with near-identical cards (e.g. two "Adjust Black Ink Level" 40s apart).
    // If an OPEN/ACK'd insight already covers this (same correlation_key, or same node+kind+title in
    // the last 24h), REFRESH it and resurface it instead of inserting a duplicate.
    // NOTE: must match the SAME kind — an anomaly and its remediation share a correlation_key on
    // purpose (to group into one card); they must NOT dedup into each other.
    $dupId = 0;
    if ($corr !== null && $corr !== '') {
        $q = $conn->prepare("SELECT id FROM nm_ai_insights WHERE correlation_key=? AND kind=? AND status IN ('open','acknowledged') ORDER BY id DESC LIMIT 1");
        $q->bind_param('ss', $corr, $kind); $q->execute(); $r = $q->get_result();
        if ($r && $row = $r->fetch_assoc()) $dupId = (int)$row['id']; $q->close();
    }
    if (!$dupId) {
        if ($node_id === null) {
            $q = $conn->prepare("SELECT id FROM nm_ai_insights WHERE node_id IS NULL AND kind=? AND title=? AND status IN ('open','acknowledged') AND created_at > (NOW() - INTERVAL 24 HOUR) ORDER BY id DESC LIMIT 1");
            $q->bind_param('ss', $kind, $title);
        } else {
            $q = $conn->prepare("SELECT id FROM nm_ai_insights WHERE node_id=? AND kind=? AND title=? AND status IN ('open','acknowledged') AND created_at > (NOW() - INTERVAL 24 HOUR) ORDER BY id DESC LIMIT 1");
            $q->bind_param('iss', $node_id, $kind, $title);
        }
        $q->execute(); $r = $q->get_result();
        if ($r && $row = $r->fetch_assoc()) $dupId = (int)$row['id']; $q->close();
    }
    if ($dupId) {
        // refresh content + resurface (created_at=NOW so it re-sorts to the top); keep old body/data if new is null
        $u = $conn->prepare("UPDATE nm_ai_insights SET severity=?, body=COALESCE(?,body), data=COALESCE(?,data), source=?, created_at=NOW() WHERE id=?");
        $u->bind_param('ssssi', $severity, $body, $data, $src, $dupId); $u->execute(); $u->close();
        echo json_encode(['ok'=>true, 'id'=>$dupId, 'deduped'=>true]);
        exit;
    }

    $st = $conn->prepare("INSERT INTO nm_ai_insights
        (node_id, kind, severity, title, body, data, source, correlation_key)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    $st->bind_param('isssssss', $node_id, $kind, $severity, $title, $body, $data, $src, $corr);
    if (!$st->execute()) { http_response_code(500); echo json_encode(['ok'=>false,'err'=>$conn->error]); exit; }
    echo json_encode(['ok'=>true, 'id'=>$conn->insert_id]);
    exit;
}

echo json_encode(['ok'=>false, 'err'=>"Unknown action '{$action}'"]);
