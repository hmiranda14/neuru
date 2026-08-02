<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — NATIVE container-log collector (replaces the external n8n "Container Log
// Collector" flow). NEURU sits ON the customer's LAN, so it reaches their Portainer
// directly — the hosted n8n never can (private network). Every 5 min it lists running
// containers via Portainer, pulls each one's NEW logs (since-cursor), parses the docker
// multiplexed stream, and stores them in `container_logs` — the SAME table the viewer
// (container_logs.php) reads and the Error-Watch/AI-fix modules use.
//
// Token-gated like the other crons:  nm_cron.sh cron_container_logs.php  (every 5 min).
// Toggle: nm_settings 'container_logs_collect' ('0' disables). No-op if Portainer isn't set up.
// ─────────────────────────────────────────────────────────────────────────────
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_portainer.php';
require_once __DIR__ . '/nm_n8n.php';          // nm_n8n_call (metered AI flow invocation)
require_once __DIR__ . '/nm_erroranalyze.php'; // nm_container_ai_analyze_pending (auto AI Insight)

$CLI = (PHP_SAPI === 'cli');
function _cl_get($conn, $k, $d = '') {
    $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='" . $conn->real_escape_string($k) . "' LIMIT 1");
    return ($r && ($x = $r->fetch_row())) ? $x[0] : $d;
}

// ── auth (shared inbound token, same as every other cron endpoint) ──────────────
if (!$CLI) {
    header('Content-Type: application/json');
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? '';
    if ($hdr === '' && isset($_GET['token'])) $hdr = (string)$_GET['token'];
    $want = (string)_cl_get($conn, 'n8n_inbound_token', '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(403); echo json_encode(['ok' => false, 'error' => 'forbidden']); exit; }
}
$out = function (array $a) use ($CLI) { echo $CLI ? (json_encode($a) . "\n") : json_encode($a); exit; };

// ── guards: enabled + Portainer configured ─────────────────────────────────────
if (_cl_get($conn, 'container_logs_collect', '1') === '0') $out(['ok' => true, 'skipped' => 'disabled']);
$cfg = nm_portainer_cfg($conn);
if (!nm_portainer_configured($cfg)) $out(['ok' => true, 'skipped' => 'portainer_not_configured']);

$tail = (int)_cl_get($conn, 'container_logs_tail', '500') ?: 500;

// ── collect ─────────────────────────────────────────────────────────────────────
$eR = nm_portainer_call($cfg, 'GET', '/api/endpoints', null, 12);
$endpoints = $eR['ok'] ? (array)$eR['data'] : [];
if (!$endpoints && !$eR['ok']) $out(['ok' => false, 'error' => 'portainer endpoints: ' . ($eR['error'] ?? '?')]);

$stmt = $conn->prepare("INSERT IGNORE INTO container_logs
    (endpoint_id,container_id,container_name,stream,log_ts,message,line_hash) VALUES (?,?,?,?,?,?,?)");

$conts = $ins = $dup = 0; $errs = [];
foreach ($endpoints as $e) {
    $eid = (int)($e['Id'] ?? 0); if (!$eid) continue;
    $cR = nm_portainer_containers($cfg, $eid, false);   // all=0 → running only
    if (!$cR['ok']) { $errs[] = "endpoint $eid: " . $cR['error']; continue; }
    foreach (array_map('nm_portainer_norm_container', (array)$cR['data']) as $c) {
        $cid = (string)($c['cid'] ?? ''); $cname = (string)($c['name'] ?? '');
        if ($cid === '' || (($c['state'] ?? '') !== 'running')) continue;
        $conts++;

        // since-cursor = the newest line we already stored for this container (avoid re-pulling history)
        $since = 0;
        if ($q = $conn->query("SELECT UNIX_TIMESTAMP(MAX(log_ts)) FROM container_logs WHERE container_id='" . $conn->real_escape_string($cid) . "'")) {
            if (($row = $q->fetch_row()) && $row[0]) $since = (int)$row[0];
        }
        $path = "/api/endpoints/{$eid}/docker/containers/" . rawurlencode($cid) . "/logs"
              . "?stdout=1&stderr=1&timestamps=1&tail={$tail}" . ($since ? "&since=" . ($since + 1) : "");
        $lr = nm_portainer_call($cfg, 'GET', $path, null, 20);
        if (!$lr['ok']) { $errs[] = "$cname: " . $lr['error']; continue; }
        $raw = is_string($lr['data']) ? $lr['data'] : '';
        if (trim($raw) === '') continue;

        foreach (explode("\n", $raw) as $ln) {
            if ($ln === '') continue;
            // strip docker's 8-byte multiplex frame header (stream in byte 0), if present
            $stream = 'stdout';
            $c0 = ord($ln[0]);
            if ($c0 === 1 || $c0 === 2) { $stream = ($c0 === 2) ? 'stderr' : 'stdout'; $ln = substr($ln, 8); }
            $ln = preg_replace('/^[\x00-\x08]+/', '', $ln);
            // split "2026-06-12T10:00:00.123Z the message"
            $ts = null; $msg = $ln;
            if (preg_match('/^(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s(.*)$/s', $ln, $m)) {
                $t = strtotime(preg_replace('/\.\d+/', '', $m[1])); if ($t) $ts = gmdate('Y-m-d H:i:s', $t);
                $msg = $m[2];
            }
            $msg = rtrim($msg, "\r\n");
            if ($msg === '' || in_array($msg, ['[object Object]', 'Array'], true)) continue;
            $hash = sha1($cid . '|' . ($ts ?? '') . '|' . $stream . '|' . $msg);
            $stmt->bind_param('issssss', $eid, $cid, $cname, $stream, $ts, $msg, $hash);
            $stmt->execute();
            if ($conn->affected_rows > 0) $ins++; else $dup++;
        }
    }
}

// retention prune (occasional, cheap) — mirror the ingest endpoint's policy
if (random_int(1, 20) === 1) {
    $days = (int)_cl_get($conn, 'container_logs_retention_days', '7') ?: 7;
    $conn->query("DELETE FROM container_logs WHERE created_at < NOW() - INTERVAL {$days} DAY LIMIT 5000");
}

// ── NATIVE Error-Watch: scan the freshly-collected logs → upsert container_incidents ────────────
// NEURU is ON the LAN, so it detects errors itself from container_logs — NO n8n required (n8n, if
// present, is now ONLY for the optional AI summary/solution). Same keywords + fingerprint + dedup as
// the incidents endpoint, so both paths stay consistent. A recurring error also REOPENS a resolved
// incident (ignored stays muted). Toggle: nm_settings 'error_watch_enabled' ('0' disables).
$ew = ['scanned' => 0, 'errors' => 0, 'new' => 0];
if (_cl_get($conn, 'error_watch_enabled', '1') !== '0') {
    $norm = function (string $e): string {   // == nm_normalize_error() so fingerprints match the n8n path
        $x = strtolower(trim($e));
        $x = preg_replace('/\d{4}-\d{2}-\d{2}[t ][\d:.]+z?/', '#ts', $x) ?? $x;
        $x = preg_replace('/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b/', '#ip', $x) ?? $x;
        $x = preg_replace('/\b[0-9a-f]{8,}\b/', '#hex', $x) ?? $x;
        $x = preg_replace('/\b\d+\b/', '#n', $x) ?? $x;
        $x = preg_replace('/\s+/', ' ', $x) ?? $x;
        return substr(trim($x), 0, 800);
    };
    $split = fn($s) => array_values(array_filter(array_map('trim', preg_split('/[,\n]/', (string)$s))));
    $kw = $split(_cl_get($conn, 'error_watch_keywords', 'ERROR,ERR,FAILED'));
    $ig = $split(_cl_get($conn, 'error_watch_ignore', ''));
    if ($kw) {
        // cursor = last container_logs.id scanned. First run seeds at the current MAX so we detect only
        // NEW lines from here on (never backfill/flood the whole history into incidents).
        $cursor = (int)_cl_get($conn, 'error_watch_last_log_id', '0');
        $logMax = (int)(($m0 = $conn->query("SELECT MAX(id) m FROM container_logs")) && ($x0 = $m0->fetch_assoc()) ? ($x0['m'] ?? 0) : 0);
        // First run seeds at the current MAX (detect only NEW lines, never backfill). Also SELF-HEAL a
        // stale cursor that points PAST the newest log — e.g. after a config restore onto a fresh log
        // table — otherwise the scanner would silently detect nothing forever.
        if ($cursor === 0 || $cursor > $logMax) {
            $cursor = $logMax;
            $conn->query("INSERT INTO nm_settings(setting_key,setting_val) VALUES('error_watch_last_log_id','{$cursor}') ON DUPLICATE KEY UPDATE setting_val='{$cursor}'");
        }
        $aiOn = _cl_get($conn, 'error_watch_ai', '1') !== '0';
        $initStatus = $aiOn ? 'analyzing' : 'open';
        $reopen = _cl_get($conn, 'error_watch_reopen', '1') !== '0';
        // resolved_by/resolved_at cleared BEFORE status is reassigned (MySQL evaluates SET left→right,
        // so these three IFs must all read the OLD 'resolved' status → order matters).
        $reopenSql = $reopen
            ? "resolved_by=IF(status='resolved',NULL,resolved_by), resolved_at=IF(status='resolved',NULL,resolved_at), status=IF(status='resolved','{$initStatus}',status),"
            : "";
        $ups = $conn->prepare("INSERT INTO container_incidents
            (endpoint_id,host,host_ip,container_id,container_name,severity,error_text,fingerprint,status,first_seen,last_seen)
            VALUES (?,?,?,?,?,?,?,?,'{$initStatus}',?,?)
            ON DUPLICATE KEY UPDATE occurrences=occurrences+1, last_seen=GREATEST(last_seen,VALUES(last_seen)),
                severity=VALUES(severity), {$reopenSql} id=LAST_INSERT_ID(id)");
        $maxId = $cursor; $host = ''; $hip = '';
        $res = $conn->query("SELECT id,endpoint_id,container_id,container_name,log_ts,message
                             FROM container_logs WHERE id > {$cursor} ORDER BY id ASC LIMIT 3000");
        while ($res && ($lg = $res->fetch_assoc())) {
            $maxId = max($maxId, (int)$lg['id']); $ew['scanned']++;
            $msg = (string)$lg['message'];
            $msg = preg_replace('/\x1b\[[0-9;]*m/', '', $msg) ?? $msg;   // strip ANSI colour codes (portainer etc.)
            $low = strtolower($msg);
            $hit = false; foreach ($kw as $k) { if ($k !== '' && strpos($low, strtolower($k)) !== false) { $hit = true; break; } }
            if (!$hit) continue;
            if ($ig) foreach ($ig as $g) { if ($g !== '' && strpos($low, strtolower($g)) !== false) { $hit = false; break; } }
            if (!$hit) continue;
            $ew['errors']++;
            $errText = substr(trim($msg), 0, 4000);
            $cname = (string)$lg['container_name'];
            $fp = sha1($cname . '|' . $norm($errText));
            $sev = (strpos($low,'fatal')!==false || strpos($low,'panic')!==false) ? 'CRITICAL'
                 : ((strpos($low,'warn')!==false) ? 'WARNING' : 'ERROR');
            $eid = (int)$lg['endpoint_id']; $cid = (string)$lg['container_id'];
            $ts = $lg['log_ts'] ?: gmdate('Y-m-d H:i:s');
            try {
                $ups->bind_param('isssssssss', $eid,$host,$hip,$cid,$cname,$sev,$errText,$fp,$ts,$ts);
                $ups->execute();
                if ($conn->affected_rows === 1) $ew['new']++;
            } catch (\Throwable $e) { /* one bad line never aborts the scan */ }
        }
        $conn->query("UPDATE nm_settings SET setting_val='{$maxId}' WHERE setting_key='error_watch_last_log_id'");
    }

    // ── AUTO AI Insight: analyze incidents parked in 'analyzing' via the live AI-RCA flow ──────────
    // NEW errors were just upserted as status='analyzing' (when AI is on). Fill their ai_summary/
    // ai_solution NOW by calling whatever analyze flow is live (container-analyze → else log-rca),
    // reading the reply synchronously — no dependency on a dedicated flow or an async callback (the
    // pair that both broke in the flow-wipe). Capped per tick so a slow LLM never stalls the cron.
    if ($aiOn ?? false) {
        try {
            $limit = (int)_cl_get($conn, 'error_watch_ai_batch', '5') ?: 5;
            $ew['ai'] = nm_container_ai_analyze_pending($conn, $limit, 30);
        } catch (\Throwable $e) { $ew['ai'] = ['error' => $e->getMessage()]; }
    }
}

$out(['ok' => true, 'containers' => $conts, 'inserted' => $ins, 'dup' => $dup, 'error_watch' => $ew, 'errors' => array_slice($errs, 0, 5)]);
