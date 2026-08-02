<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — Containers n8n-facing API (the /api/v1/* equivalent, re-architected
// for NetMon's flat-file routing). Single dispatcher: ?ep=<endpoint>[&id=N].
// Machine-to-machine: authenticated by the shared container API key, presented as
//   X-API-Key: <key>      (preferred, matches the original flows)
//   Authorization: Bearer <key>   (also accepted)
// compared (hash_equals) to the `containers_api_key` setting.
//
// Endpoints (ep=) — map of original path → NetMon dispatcher:
//   GET  containers              ← GET  /api/v1/containers
//   POST logs                    ← POST /api/v1/containers/logs
//   GET  incidents_config        ← GET  /api/v1/incidents/config
//   POST incidents               ← POST /api/v1/incidents
//   POST incident_solution&id=   ← POST /api/v1/incidents/{id}/solution
//   POST incident_remediation&id=← POST /api/v1/incidents/{id}/remediation
//   POST fix_proposal&id=        ← POST /api/v1/incidents/{id}/fix-proposal
//   POST fix_continue&id=        ← POST /api/v1/incidents/{id}/fix-continue
//   POST fix_log&id=             ← POST /api/v1/incidents/{id}/fix-log
//   POST fix_result&id=          ← POST /api/v1/incidents/{id}/fix-result
//   GET  kb_export               ← GET  /api/v1/kb/export
//   POST kb_vectorized&id=       ← POST /api/v1/kb/{id}/vectorized
// ─────────────────────────────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
date_default_timezone_set('America/Puerto_Rico');

require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/nm_portainer.php';
require_once __DIR__ . '/nm_n8n.php';

function cj($p, int $code = 200) { http_response_code($code); echo json_encode($p, JSON_UNESCAPED_SLASHES); exit; }

// ── Auth ──────────────────────────────────────────────────────────────────────
// Reuses the SAME shared inbound token (`n8n_inbound_token`) that all the other
// AI flows already use — no separate key. Accept it via X-NetMon-Token (preferred,
// consistent with the rest of NetMon), X-API-Key, or Authorization: Bearer.
$presented = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_SERVER['HTTP_X_API_KEY'] ?? '');
if ($presented === '' && !empty($_SERVER['HTTP_AUTHORIZATION'])) {
    if (preg_match('/Bearer\s+(.+)/i', $_SERVER['HTTP_AUTHORIZATION'], $m)) $presented = trim($m[1]);
}
if (!nm_n8n_verify_inbound($conn, $presented)) {
    cj(['ok'=>false, 'error'=>'Unauthorized — bad or missing X-NetMon-Token'], 401);
}

$ep   = $_GET['ep'] ?? '';
$id   = (int)($_GET['id'] ?? 0);
$body = json_decode(file_get_contents('php://input'), true);
if (!is_array($body)) $body = $_POST;
$now  = date('Y-m-d H:i:s');

function nm_setting($conn, $key, $def = '') {
    $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='" . $conn->real_escape_string($key) . "' LIMIT 1");
    return $r && ($x = $r->fetch_row()) ? $x[0] : $def;
}
// Strip volatile bits so similar errors group under one fingerprint (verbatim port).
function nm_normalize_error(string $e): string {
    $x = strtolower(trim($e));
    $x = preg_replace('/\d{4}-\d{2}-\d{2}[t ][\d:.]+z?/', '#ts', $x) ?? $x;
    $x = preg_replace('/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b/', '#ip', $x) ?? $x;
    $x = preg_replace('/\b[0-9a-f]{8,}\b/', '#hex', $x) ?? $x;
    $x = preg_replace('/\b\d+\b/', '#n', $x) ?? $x;
    $x = preg_replace('/\s+/', ' ', $x) ?? $x;
    return substr(trim($x), 0, 800);
}
if (!function_exists('nm_kb_doc')) {   // also defined (guarded) in nm_solutionkb.php — equivalent body
function nm_kb_doc(array $r): string {
    $t = "Subject: {$r['container_name']}\nSeverity: {$r['severity']}\n\nProblem:\n{$r['error_text']}\n\n"
       . "Summary:\n{$r['summary']}\n\nResolution:\n{$r['resolution']}\n\nSession transcript:\n{$r['transcript']}";
    return substr($t, 0, 14000);
}
}
function base_url(): string {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    return $scheme . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost');
}

// ── Dispatch ──────────────────────────────────────────────────────────────────
switch ($ep) {

case 'containers': {  // GET — n8n pulls inventory + host IP
    $cfg = nm_portainer_cfg($conn);
    if (!nm_portainer_configured($cfg)) cj(['ok'=>false,'error'=>'Portainer not configured'], 503);
    $eR = nm_portainer_endpoints($cfg);
    $envs = []; $containers = [];
    $hostMap = $cfg['host_map'];
    foreach (($eR['ok'] ? (array)$eR['data'] : []) as $e) {
        $eid = (int)($e['Id'] ?? 0); $name = $e['Name'] ?? '';
        $url = $e['URL'] ?? ''; $type = (int)($e['Type'] ?? 0);
        $ip = $hostMap[strtolower($name)] ?? '';
        if ($ip === '' && preg_match('#tcp://([\d.]+)#', $url, $mm)) $ip = $mm[1];
        if ($ip === '' && ($type === 1)) { if (preg_match('#//([\d.]+)#', $cfg['url'], $mm)) $ip = $mm[1]; }
        $cR = nm_portainer_containers($cfg, $eid, false);
        $list = $cR['ok'] ? array_map('nm_portainer_norm_container', (array)$cR['data']) : [];
        $envs[] = ['endpoint_id'=>$eid,'name'=>$name,'host_ip'=>$ip,'up'=>(($e['Status'] ?? 1)==1),
                   'container_count'=>count($list),'error'=>$cR['ok']?'':$cR['error']];
        foreach ($list as $c) $containers[] = ['endpoint_id'=>$eid,'host'=>$name,'host_ip'=>$ip,
            'container_id'=>$c['cid'],'name'=>$c['name'],'state'=>$c['state']];
    }
    cj(['ok'=>true,'environments'=>$envs,'containers'=>$containers]);
}

case 'logs': {  // POST — n8n pushes log batches
    $batches = isset($body['batches']) && is_array($body['batches']) ? $body['batches'] : [$body];
    $st = $conn->prepare("INSERT IGNORE INTO container_logs
        (endpoint_id,container_id,container_name,stream,log_ts,message,line_hash)
        VALUES (?,?,?,?,?,?,?)");
    $recv = $ins = $dup = 0;
    foreach ($batches as $b) {
        $eid = (int)($b['endpoint_id'] ?? 0); $cid = (string)($b['container_id'] ?? '');
        $cname = (string)($b['container_name'] ?? '');
        foreach (($b['lines'] ?? []) as $ln) {
            $recv++;
            if (is_string($ln)) { $stream='stdout'; $ts=null; $msg=$ln; }
            else { $stream = ($ln['stream'] ?? 'stdout') === 'stderr' ? 'stderr' : 'stdout';
                   $rawts = $ln['ts'] ?? ($ln['timestamp'] ?? ''); $msg = (string)($ln['message'] ?? ($ln['log'] ?? ''));
                   $ts = null; if ($rawts) { $rawts = preg_replace('/\.\d+/', '', $rawts); $t = strtotime($rawts); if ($t) $ts = gmdate('Y-m-d H:i:s', $t); } }
            $msg = rtrim($msg, "\r\n");
            if ($msg === '' || in_array($msg, ['[object Object]','Array','[object Promise]'], true)) continue;
            $hash = sha1($cid.'|'.($ts ?? '').'|'.$stream.'|'.$msg);
            $st->bind_param('issssss', $eid,$cid,$cname,$stream,$ts,$msg,$hash);
            $st->execute();
            if ($conn->affected_rows > 0) $ins++; else $dup++;
        }
    }
    $pruned = 0;
    if (random_int(1,20) === 1) {
        $days = (int)nm_setting($conn,'container_logs_retention_days','7') ?: 7;
        $conn->query("DELETE FROM container_logs WHERE created_at < NOW() - INTERVAL {$days} DAY LIMIT 5000");
        $pruned = $conn->affected_rows;
    }
    cj(['ok'=>true,'received'=>$recv,'inserted'=>$ins,'duplicates'=>$dup,'pruned'=>$pruned]);
}

case 'incidents_config': {  // GET
    $enabled = nm_setting($conn,'error_watch_enabled','1') !== '0';
    $kw = trim(nm_setting($conn,'error_watch_keywords','ERROR,ERR,FAILED'));
    $ig = trim(nm_setting($conn,'error_watch_ignore',''));
    $split = fn($s) => array_values(array_filter(array_map('trim', preg_split('/[,\n]/', $s))));
    cj(['ok'=>true,'enabled'=>$enabled,'keywords'=>$split($kw),'ignore'=>$split($ig)]);
}

case 'incidents': {  // POST — report a detected error (dedup → incident)
    $err = trim((string)($body['error'] ?? ($body['message'] ?? '')));
    if ($err === '') cj(['ok'=>false,'error'=>'Empty error'], 422);
    $cname = (string)($body['container_name'] ?? '');
    $fp = sha1($cname.'|'.nm_normalize_error($err));
    $sev = strtoupper((string)($body['severity'] ?? 'ERROR'));
    $eid = (int)($body['endpoint_id'] ?? 0);
    $host = (string)($body['host'] ?? ''); $hip = (string)($body['host_ip'] ?? '');
    $cid = (string)($body['container_id'] ?? '');
    $ts = ($body['ts'] ?? '') ? date('Y-m-d H:i:s', strtotime($body['ts'])) : $now;
    // AI toggle (error_watch_ai): when OFF, new errors are recorded as plain 'open' incidents (no AI
    // analysis is expected/requested) so they never hang in 'analyzing' waiting for a flow that isn't running.
    $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='error_watch_ai' LIMIT 1");
    $aiOn = !($r && ($x = $r->fetch_row()) && $x[0] === '0');
    $initStatus = $aiOn ? 'analyzing' : 'open';
    $st = $conn->prepare("INSERT INTO container_incidents
        (endpoint_id,host,host_ip,container_id,container_name,severity,error_text,fingerprint,status,first_seen,last_seen)
        VALUES (?,?,?,?,?,?,?,?,'{$initStatus}',?,?)
        ON DUPLICATE KEY UPDATE occurrences=occurrences+1, last_seen=GREATEST(last_seen,VALUES(last_seen)),
            severity=VALUES(severity), host_ip=VALUES(host_ip), id=LAST_INSERT_ID(id)");
    $st->bind_param('isssssssss',$eid,$host,$hip,$cid,$cname,$sev,$err,$fp,$ts,$ts);
    $st->execute();
    $iid = $conn->insert_id;
    $isNew = ($conn->affected_rows === 1);
    // needs_solution: new, or stale (>30m) without a solution
    $needs = $isNew;
    if (!$isNew) {
        $q = $conn->query("SELECT ai_solution, last_seen FROM container_incidents WHERE id={$iid}");
        $row = $q ? $q->fetch_assoc() : null;
        if ($row && empty($row['ai_solution'])) $needs = true;
    }
    cj(['ok'=>true,'id'=>$iid,'is_new'=>$isNew,'needs_solution'=>$needs]);
}

case 'incident_solution': {  // POST &id=
    $sum = $body['ai_summary'] ?? ($body['summary'] ?? null);
    $sol = $body['ai_solution'] ?? ($body['solution'] ?? null);
    if ($sum === null && $sol === null) cj(['ok'=>false,'error'=>'summary or solution required'], 422);
    $st = $conn->prepare("UPDATE container_incidents SET ai_summary=COALESCE(?,ai_summary),
        ai_solution=COALESCE(?,ai_solution), status=IF(status='analyzing','open',status) WHERE id=?");
    $st->bind_param('ssi',$sum,$sol,$id); $st->execute();
    cj(['ok'=>true,'updated'=>$conn->affected_rows]);
}

case 'incident_remediation': {  // POST &id=
    $status = ($body['status'] ?? '') === 'fixed' ? 'fixed' : 'failed';
    $log = (string)($body['log'] ?? ($body['message'] ?? ''));
    $st = $conn->prepare("UPDATE container_incidents SET remediation_status=?, remediation_log=?, remediated_at=NOW() WHERE id=?");
    $st->bind_param('ssi',$status,$log,$id); $st->execute();
    cj(['ok'=>true,'updated'=>$conn->affected_rows]);
}

case 'fix_proposal': {  // POST &id=
    $cmd = trim((string)($body['command'] ?? ''));
    if ($cmd === '') cj(['ok'=>false,'error'=>'command required'], 422);
    $line = json_encode(['command'=>$cmd,'rationale'=>(string)($body['rationale'] ?? ''),'risky'=>(bool)($body['risky'] ?? false)]);
    $st = $conn->prepare("INSERT INTO container_fix_logs (incident_id,level,line) VALUES (?,'proposal',?)");
    $st->bind_param('is',$id,$line); $st->execute();
    cj(['ok'=>true]);
}

case 'fix_log': {  // POST &id=
    $lines = isset($body['lines']) && is_array($body['lines']) ? $body['lines'] : [$body];
    $st = $conn->prepare("INSERT INTO container_fix_logs (incident_id,level,line) VALUES (?,?,?)");
    $n = 0;
    foreach ($lines as $l) {
        if (!is_array($l)) { $l = ['line' => (string)$l]; }   // n8n may post a bare string per element
        $lvl = substr((string)($l['level'] ?? 'out'), 0, 16);
        // Accept whatever key the flow used for the SSH output (line/message/output/stdout/stderr/text/data).
        $txt = (string)($l['line'] ?? ($l['message'] ?? ($l['output'] ?? ($l['text'] ?? ($l['data'] ?? '')))));
        if ($txt === '') {
            $so = trim((string)($l['stdout'] ?? '')); $se = trim((string)($l['stderr'] ?? ''));
            $txt = trim($so . ($so !== '' && $se !== '' ? "\n" : '') . $se);
        }
        if ($txt === '') continue;
        $st->bind_param('iss',$id,$lvl,$txt); $st->execute(); $n++;
    }
    cj(['ok'=>true,'inserted'=>$n]);
}

case 'fix_continue': {  // POST &id= — portal loops the AI on new command output
    require_once __DIR__ . '/nm_fixflow.php';
    $r = nm_fix_continue($conn, $id);   // caps at 40 cmds; else re-fires the AI (mode=auto)
    cj($r);
}

case 'fix_result': {  // POST &id=
    $status = ($body['status'] ?? '') === 'fixed' ? 'fixed' : 'failed';
    // The auto-loop closer posts {status:'fixed', summary:<AI closing note>}.
    $log = (string)($body['log'] ?? ($body['message'] ?? ($body['summary'] ?? '')));
    $done = ($status === 'fixed' ? '✓ ' : '✗ ') . ($log !== '' ? $log : ($status === 'fixed' ? 'Resolved.' : 'Fix failed.'));
    $st=$conn->prepare("INSERT INTO container_fix_logs (incident_id,level,line) VALUES (?,'done',?)"); $st->bind_param('is',$id,$done); $st->execute();
    $st = $conn->prepare("UPDATE container_incidents SET fix_status=?, fix_finished_at=NOW() WHERE id=?");
    $st->bind_param('si',$status,$id); $st->execute();
    cj(['ok'=>true]);
}

case 'kb_export': {  // GET — n8n pulls entries to embed
    $all = ($_GET['all'] ?? '') === '1';
    $lim = max(1, min(500, (int)($_GET['limit'] ?? 200)));
    $where = $all ? '' : 'WHERE vectorized_at IS NULL';
    $r = $conn->query("SELECT * FROM container_kb {$where} ORDER BY id DESC LIMIT {$lim}");
    $out = [];
    while ($r && $row = $r->fetch_assoc()) {
        $out[] = ['id'=>(int)$row['id'],'incident_id'=>$row['incident_id'],'container_name'=>$row['container_name'],
            'image'=>$row['image'],'severity'=>$row['severity'],'fingerprint'=>$row['fingerprint'],'tags'=>$row['tags'],
            'content_hash'=>$row['content_hash'],'text'=>nm_kb_doc($row),'vectorized_at'=>$row['vectorized_at'],
            'vectorized_url'=>base_url().'/nm_containers_api.php?ep=kb_vectorized&id='.$row['id']];
    }
    cj(['ok'=>true,'count'=>count($out),'entries'=>$out]);
}

case 'kb_vectorized': {  // POST &id=
    $ref = substr((string)($body['vector_ref'] ?? ($body['ref'] ?? '')), 0, 128);
    $st = $conn->prepare("UPDATE container_kb SET vectorized_at=NOW(), vector_ref=? WHERE id=?");
    $st->bind_param('si',$ref,$id); $st->execute();
    cj(['ok'=>true,'updated'=>$conn->affected_rows]);
}

default:
    cj(['ok'=>false,'error'=>'Unknown endpoint','endpoints'=>['containers','logs','incidents_config','incidents',
        'incident_solution','incident_remediation','fix_proposal','fix_continue','fix_log','fix_result','kb_export','kb_vectorized']], 404);
}
