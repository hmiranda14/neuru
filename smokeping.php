<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Smokeping (latency/packet-loss). Optional embedded tool:
//   • embeds the configured Smokeping web UI in an iframe, and
//   • manages monitored targets remotely WITHOUT AI: NEURU composes a safe,
//     base64-wrapped `docker exec` command and POSTs it to an n8n webhook
//     (smokeping_manage_url) that SSHes to the Docker host and runs it.
// NEURU owns a dedicated `+ NEURU` section in the Smokeping Targets file.
// All host/container/path/URL are configurable (Config → Integrations → Smokeping).
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_secrets.php');     // nm_ssh_resolve_host
require_once('nm_n8n.php');         // shared inbound token
require_once('nm_smokeping.php');   // latency history (own DB) + recorder/history
require_once('nm_confmgr.php');     // nm_cm_ssh_fetch — direct SSH to the host (native, no n8n needed)
require_once('nm_audit.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'smokeping')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=smokeping'); exit;
}

// ── Settings ──────────────────────────────────────────────────────────────────
function sp_set($conn, $k, $d='') { $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; }
$SP = [
    'url'          => sp_set($conn, 'smokeping_url', ''),
    'enabled'      => sp_set($conn, 'smokeping_enabled', '0') === '1',
    'host_ip'      => sp_set($conn, 'smokeping_host_ip', ''),
    'container'    => sp_set($conn, 'smokeping_container', '') ?: 'smokeping',
    'targets_path' => sp_set($conn, 'smokeping_targets_path', '') ?: '/config/Targets',
    'manage_url'   => sp_set($conn, 'smokeping_manage_url', ''),
    'reload_cmd'   => sp_set($conn, 'smokeping_reload_cmd', ''),
    'data_path'    => sp_set($conn, 'smokeping_data_path', '') ?: '/data',
    'section'      => 'NEURU',   // the Targets section + RRD subdir NEURU owns
];

// ── Helpers (command composition + n8n call) ──────────────────────────────────
function sp_valid_key($s)  { return (bool)preg_match('/^[A-Za-z0-9_]{1,40}$/', $s); }
function sp_valid_host($s) { return (bool)preg_match('/^[A-Za-z0-9_.:-]{1,100}$/', $s); }
function sp_clean_label($s){ return trim(preg_replace('/[^A-Za-z0-9 _.:()\\/-]/', '', (string)$s)); }
function sp_valid_path($s) { return (bool)preg_match('#^[A-Za-z0-9_./-]{1,200}$#', $s); }

// docker exec wrapper that runs an arbitrary sh script inside the container,
// base64-encoded so no user value can break quoting or inject anything.
function sp_exec_wrap($container, $script) {
    return "docker exec " . escapeshellarg($container) . " sh -c " . escapeshellarg('echo ' . base64_encode($script) . ' | base64 -d | sh');
}
function sp_reload_cmd($SP) {
    if (trim($SP['reload_cmd']) !== '') return $SP['reload_cmd'];
    $c = escapeshellarg($SP['container']);
    return "docker exec {$c} smokeping --reload 2>/dev/null || docker restart {$c}";
}

// POST a composed command to the n8n manage webhook (which SSHes + runs it).
// Returns ['ok','stdout','stderr','exit','error'].
function sp_call_manage($conn, $SP, $action, $command) {
    if (trim($SP['manage_url']) === '') return ['ok'=>false,'error'=>'No manage webhook configured'];
    if (trim($SP['host_ip']) === '')    return ['ok'=>false,'error'=>'No Docker host IP configured'];
    $ssh = nm_ssh_resolve_host($conn, $SP['host_ip']);
    if (!$ssh) return ['ok'=>false,'error'=>'No SSH credential assigned to host '.$SP['host_ip'].' (Config → SSH Credentials)'];
    // Guarantee a complete ssh{} so n8n's dynamic SSH never falls back to localhost
    // (the incident-440 ECONNREFUSED ::1:22 / exit:255 failure mode).
    $ssh['host'] = $SP['host_ip'];
    $ssh['port'] = (int)($ssh['port'] ?? 22) ?: 22;
    $hasSecret = !empty($ssh['password']) || !empty($ssh['private_key']);
    if (empty($ssh['host']) || empty($ssh['username']) || !$hasSecret) {
        return ['ok'=>false,'error'=>'SSH credential for '.$SP['host_ip'].' is incomplete — needs host, username and a password/key (Config → SSH Credentials).'];
    }
    $cfg = nm_n8n_get($conn);
    $payload = [
        'action'       => $action,
        'command'      => $command,
        'host_ip'      => $SP['host_ip'],
        'container'    => $SP['container'],
        'targets_path' => $SP['targets_path'],
        'ssh'          => $ssh,
        'ssh_user'     => $ssh['username'] ?? '',
        'ssh_password' => $ssh['password'] ?? '',
        'ssh_port'     => $ssh['port'] ?? 22,
        'ssh_host'     => $SP['host_ip'],
    ];
    $ch = curl_init($SP['manage_url']);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>json_encode($payload),
        CURLOPT_CONNECTTIMEOUT=>5, CURLOPT_TIMEOUT=>30, CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_SSL_VERIFYHOST=>false,
        CURLOPT_HTTPHEADER=>['Content-Type: application/json','X-NetMon-Token: '.$cfg['inbound_token']]]);
    $body = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $cerr = curl_error($ch); curl_close($ch);
    if ($body === false || $code === 0) {
        // Connection-level failure (refused / timeout / DNS / route) — surface the real reason.
        $hint = ($code===0) ? ' — check the webhook URL is reachable from the server and the n8n flow is ACTIVE (use the production /webhook/ URL, not /webhook-test/)' : '';
        return ['ok'=>false,'error'=>'Cannot reach manage webhook: '.($cerr ?: 'connection failed').$hint,'stdout'=>'','stderr'=>(string)$body];
    }
    if ($code < 200 || $code >= 300) {
        $snip = trim(mb_substr((string)$body, 0, 200));
        $hint = ($code===404) ? ' — 404 usually means the n8n flow is not Active, or this is a test URL. Activate the flow and use the production /webhook/ URL.' : '';
        return ['ok'=>false,'error'=>"Webhook HTTP {$code}{$hint}".($snip!==''?" · {$snip}":''),'stdout'=>'','stderr'=>(string)$body];
    }
    $j = json_decode($body, true);
    if (!is_array($j)) return ['ok'=>true,'stdout'=>(string)$body,'stderr'=>'','exit'=>0];   // flow returned raw text
    return ['ok'=>($j['ok'] ?? true) && (($j['exit'] ?? 0) === 0 || !isset($j['exit'])),
            'stdout'=>(string)($j['stdout'] ?? ($j['output'] ?? '')), 'stderr'=>(string)($j['stderr'] ?? ''),
            'exit'=>(int)($j['exit'] ?? 0), 'error'=>($j['error'] ?? null)];
}

// The interactive SSH fetch echoes the command + emits terminal escapes (e.g. "[?2004l"); strip them
// and keep only from the first real "@@@<target>" block so the parsers see clean rrdtool output.
function sp_ssh_clean($out) {
    $out = preg_replace('/\x1b\[[0-9;?]*[A-Za-z]/', '', (string)$out);
    $p = strpos($out, '@@@');
    return $p !== false ? substr($out, $p) : $out;
}

// Run a host command for Smokeping. PREFER direct SSH from NEURU to the Docker host (native, robust,
// no n8n dependency — NEURU is usually on the same LAN). The n8n manage webhook is only a FALLBACK for
// deployments where NEURU genuinely can't reach the host. Same signature as sp_call_manage.
function sp_run($conn, $SP, $action, $command) {
    if (function_exists('nm_cm_ssh_fetch') && function_exists('nm_ssh_resolve_host') && trim((string)$SP['host_ip']) !== '') {
        $ssh = nm_ssh_resolve_host($conn, $SP['host_ip']);
        if ($ssh && !empty($ssh['username']) && (!empty($ssh['password']) || !empty($ssh['private_key']))) {
            $ssh['host'] = $SP['host_ip']; $ssh['port'] = (int)($ssh['port'] ?? 22) ?: 22;
            // sentinel (no '@@@') → stdout is never empty (nm_cm_ssh_fetch treats empty as failure)
            $r = nm_cm_ssh_fetch($ssh, $command . "\necho NMSPEND", 35);
            if (!empty($r['ok'])) return ['ok'=>true, 'stdout'=>sp_ssh_clean($r['config'] ?? ''), 'stderr'=>'', 'exit'=>0, 'via'=>'ssh'];
            $sshErr = 'Direct SSH to '.$SP['host_ip'].' failed: '.($r['error'] ?? 'unknown');
        }
    }
    return ['ok'=>false, 'error'=>($sshErr ?? ('No complete SSH credential for host '.$SP['host_ip'].' (Config → SSH Credentials)')), 'stdout'=>'', 'stderr'=>''];
}

// Parse NEURU-managed targets (the `+ NEURU` section) out of a Targets file dump.
function sp_parse_targets($text) {
    $out = []; $in = false; $cur = null;
    foreach (preg_split('/\r?\n/', (string)$text) as $line) {
        if (preg_match('/^\+\s+(\S+)/', $line, $m)) { $in = (strcasecmp($m[1],'NEURU')===0); if ($cur){$out[]=$cur;$cur=null;} continue; }
        if (!$in) continue;
        if (preg_match('/^\+\+\s+(\S+)/', $line, $m)) { if ($cur) $out[]=$cur; $cur = ['key'=>$m[1],'host'=>'','title'=>'','menu'=>'']; continue; }
        if ($cur && preg_match('/^\s*(host|title|menu)\s*=\s*(.+)$/', $line, $m)) $cur[strtolower($m[1])] = trim($m[2]);
    }
    if ($cur) $out[] = $cur;
    return $out;
}

// NEURU nodes that become Smokeping targets (tied by IP). Stable per-node key from
// the display name; collisions get the node id appended.
function sp_node_targets($conn) {
    $rows = []; $seen = [];
    $r = $conn->query("SELECT id, display_name, ip_address, COALESCE(monitor_type,'snmp') mt FROM nm_nodes WHERE ip_address IS NOT NULL AND ip_address<>'' ORDER BY display_name");
    while ($r && $x = $r->fetch_assoc()) {
        $ip = trim($x['ip_address']);
        if ($ip === '' || !sp_valid_host($ip)) continue;
        $key = preg_replace('/_+/', '_', trim(preg_replace('/[^A-Za-z0-9_]/', '_', $x['display_name']), '_'));
        if ($key === '') $key = 'node' . $x['id'];
        if (isset($seen[$key])) $key .= '_' . $x['id'];
        $seen[$key] = 1;
        $rows[] = ['id'=>(int)$x['id'], 'name'=>$x['display_name'], 'ip'=>$ip, 'key'=>$key, 'mt'=>$x['mt']];
    }
    return $rows;
}

// Parse the combined `rrdtool lastupdate` dump (blocks separated by @@@<key>) into
// { key => {rtt_ms, loss, at} }. Smokeping FPing RRD DS: uptime, loss, median, ping*.
function sp_parse_lastupdate($text) {
    $out = [];
    foreach (preg_split('/^@@@/m', (string)$text) as $blk) {
        $blk = trim($blk); if ($blk === '') continue;
        $lines = preg_split('/\r?\n/', $blk);
        $key = trim(array_shift($lines)); if ($key === '') continue;
        $hdr = null; $data = null; $ts = null;
        foreach ($lines as $ln) {
            $ln = trim($ln); if ($ln === '') continue;
            if (preg_match('/^(\d+):\s*(.+)$/', $ln, $m)) { $ts = (int)$m[1]; $data = preg_split('/\s+/', trim($m[2])); }
            elseif ($hdr === null && preg_match('/[a-zA-Z]/', $ln)) { $hdr = preg_split('/\s+/', $ln); }
        }
        if (!$hdr || !$data) { $out[$key] = ['rtt_ms'=>null,'loss'=>null,'at'=>null]; continue; }
        $idx = array_flip($hdr);
        $med = (isset($idx['median']) && isset($data[$idx['median']])) ? $data[$idx['median']] : null;
        $los = (isset($idx['loss'])   && isset($data[$idx['loss']]))   ? $data[$idx['loss']]   : null;
        $out[$key] = [
            'rtt_ms' => (is_numeric($med) ? round((float)$med * 1000, 2) : null),
            'loss'   => (is_numeric($los) ? (float)$los : null),
            'at'     => $ts,
        ];
    }
    return $out;
}

// ── API ───────────────────────────────────────────────────────────────────────
if ($api !== '') {
    if (function_exists('session_write_close')) session_write_close();   // SSH-via-n8n is slow; don't hold the lock
    header('Content-Type: application/json; charset=utf-8');
    if (!$SP['enabled'])            { echo json_encode(['ok'=>false,'error'=>'Smokeping is disabled']); exit; }
    // Target management runs via native direct SSH to the Docker host (sp_run) — it needs the host IP
    // + an SSH credential, NOT the legacy n8n manage webhook. Gate on host_ip so same-host/LAN Smokeping
    // installs (no n8n) can manage targets. (manage_url is an unused fallback; sp_run never calls it.)
    if (trim($SP['host_ip'])===''){ echo json_encode(['ok'=>false,'error'=>'No Docker host IP configured (Config → Integrations → Smokeping)']); exit; }
    $path = $SP['targets_path'];
    if (!sp_valid_path($path)) { echo json_encode(['ok'=>false,'error'=>'Invalid targets path']); exit; }

    if ($api === 'targets_list') {
        $cmd = "docker exec " . escapeshellarg($SP['container']) . " cat " . escapeshellarg($path);
        $r = sp_run($conn, $SP, 'list', $cmd);
        if (!$r['ok']) { echo json_encode(['ok'=>false,'error'=>$r['error'] ?? 'failed','stderr'=>$r['stderr']??'']); exit; }
        echo json_encode(['ok'=>true,'targets'=>sp_parse_targets($r['stdout'])]);
        exit;
    }

    if ($api === 'target_add') {
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $key = trim($_POST['key'] ?? ''); $host = trim($_POST['host'] ?? '');
        $title = sp_clean_label($_POST['title'] ?? '') ?: $host;
        if (!sp_valid_key($key))  { echo json_encode(['ok'=>false,'error'=>'Invalid name (letters, digits, _ only)']); exit; }
        if (!sp_valid_host($host)){ echo json_encode(['ok'=>false,'error'=>'Invalid host/IP']); exit; }
        $menu = $key;
        $script = "F=" . escapeshellarg($path) . "\n"
                . "grep -q '^+ NEURU\$' \"\$F\" || printf '\\n+ NEURU\\nmenu = NEURU\\ntitle = NEURU-managed targets\\n' >> \"\$F\"\n"
                . "grep -q '^++ {$key}\$' \"\$F\" && exit 0\n"
                . "printf '\\n++ {$key}\\nmenu = " . addcslashes($menu, "'\\") . "\\ntitle = " . addcslashes($title, "'\\") . "\\nhost = {$host}\\n' >> \"\$F\"\n";
        $cmd = sp_exec_wrap($SP['container'], $script) . " && ( " . sp_reload_cmd($SP) . " )";
        $r = sp_run($conn, $SP, 'add', $cmd);
        nm_audit($conn, 'smokeping.target_add', ['target_type'=>'smokeping_target','target_id'=>$key,'details'=>['host'=>$host,'ok'=>$r['ok']]]);
        echo json_encode(['ok'=>$r['ok'],'message'=>$r['ok']?'Added & reloaded':($r['error']??'failed'),'stderr'=>$r['stderr']??'']);
        exit;
    }

    if ($api === 'target_remove') {
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $key = trim($_POST['key'] ?? '');
        if (!sp_valid_key($key)) { echo json_encode(['ok'=>false,'error'=>'Invalid name']); exit; }
        $script = "F=" . escapeshellarg($path) . "\n"
                . "awk '\n"
                . "/^\\+\\+ {$key}\$/ {skip=1; next}\n"
                . "skip==1 && /^[[:space:]]*\$/ {skip=0; next}\n"
                . "skip==1 && /^\\+/ {skip=0}\n"
                . "skip==1 {next}\n"
                . "{print}\n"
                . "' \"\$F\" > \"\$F.nmtmp\" && cat \"\$F.nmtmp\" > \"\$F\" && rm -f \"\$F.nmtmp\"\n";
        $cmd = sp_exec_wrap($SP['container'], $script) . " && ( " . sp_reload_cmd($SP) . " )";
        $r = sp_run($conn, $SP, 'remove', $cmd);
        nm_audit($conn, 'smokeping.target_remove', ['target_type'=>'smokeping_target','target_id'=>$key,'details'=>['ok'=>$r['ok']]]);
        echo json_encode(['ok'=>$r['ok'],'message'=>$r['ok']?'Removed & reloaded':($r['error']??'failed'),'stderr'=>$r['stderr']??'']);
        exit;
    }

    if ($api === 'reload') {
        $r = sp_run($conn, $SP, 'reload', sp_reload_cmd($SP));
        nm_audit($conn, 'smokeping.reload', ['target_type'=>'smokeping','details'=>['ok'=>$r['ok']]]);
        echo json_encode(['ok'=>$r['ok'],'message'=>$r['ok']?'Reloaded':($r['error']??'failed'),'stderr'=>$r['stderr']??'']);
        exit;
    }

    // Declaratively rebuild the `+ NEURU` section from ALL nm_nodes (tie by IP).
    // Strips the old NEURU section (kept last) and re-appends a fresh one, then reloads.
    if ($api === 'sync_nodes') {
        $nodes = sp_node_targets($conn);
        if (!$nodes) { echo json_encode(['ok'=>false,'error'=>'No nodes with a valid IP to sync']); exit; }
        $script  = "F=" . escapeshellarg($path) . "\n";
        // remove existing `+ NEURU` section (from its header to the next top-level `+ ` or EOF)
        $script .= "awk '/^\\+ NEURU\$/{skip=1;next} skip&&/^\\+ /{skip=0} skip{next} {print}' \"\$F\" > \"\$F.nmtmp\" && cat \"\$F.nmtmp\" > \"\$F\" && rm -f \"\$F.nmtmp\"\n";
        $script .= "printf '\\n+ NEURU\\nmenu = NEURU\\ntitle = NEURU-managed targets\\n' >> \"\$F\"\n";
        foreach ($nodes as $nd) {
            $menu  = sp_clean_label($nd['name']) ?: $nd['key'];
            $title = sp_clean_label($nd['name'] . ' (' . $nd['ip'] . ')');
            $script .= "printf '\\n++ {$nd['key']}\\nmenu = " . addcslashes($menu, "'\\") . "\\ntitle = " . addcslashes($title, "'\\") . "\\nhost = {$nd['ip']}\\n' >> \"\$F\"\n";
        }
        $cmd = sp_exec_wrap($SP['container'], $script) . " && ( " . sp_reload_cmd($SP) . " )";
        $r = sp_run($conn, $SP, 'sync', $cmd);
        nm_audit($conn, 'smokeping.sync_nodes', ['target_type'=>'smokeping','details'=>['count'=>count($nodes),'ok'=>$r['ok']]]);
        echo json_encode(['ok'=>$r['ok'],'message'=>$r['ok']?('Synced '.count($nodes).' nodes & reloaded'):($r['error']??'failed'),'count'=>count($nodes),'stderr'=>$r['stderr']??'']);
        exit;
    }

    // Pull the latest latency/loss for every NEURU target from its RRD (one SSH call).
    if ($api === 'latency') {
        $dir = rtrim($SP['data_path'], '/') . '/' . $SP['section'];
        if (!sp_valid_path($dir)) { echo json_encode(['ok'=>false,'error'=>'Invalid data path']); exit; }
        $script = "D=" . escapeshellarg($dir) . "\n"
                . "for f in \"\$D\"/*.rrd; do [ -e \"\$f\" ] || continue; n=\$(basename \"\$f\" .rrd); echo \"@@@\$n\"; rrdtool lastupdate \"\$f\" 2>/dev/null; done\n";
        $cmd = sp_exec_wrap($SP['container'], $script);
        $r = sp_run($conn, $SP, 'latency', $cmd);
        if (!$r['ok']) { echo json_encode(['ok'=>false,'error'=>$r['error'] ?? 'failed','stderr'=>$r['stderr']??'']); exit; }
        echo json_encode(['ok'=>true,'latency'=>sp_parse_lastupdate($r['stdout'])]);
        exit;
    }

    // Pull Smokeping's RRD samples into NEURU's own table (manual trigger; cron does it too).
    if ($api === 'record') {
        $r = nm_sp_record($conn, null, (int)($_GET['hours'] ?? 2));
        nm_audit($conn, 'smokeping.record', ['target_type'=>'smokeping','details'=>['inserted'=>$r['inserted']??0,'ok'=>$r['ok']]]);
        echo json_encode($r);
        exit;
    }

    // NEURU-owned latency history for one node → our own chart (no Smokeping embed).
    if ($api === 'history') {
        $nid = (int)($_GET['node'] ?? 0);
        if (!$nid) { echo json_encode(['ok'=>false,'error'=>'No node']); exit; }
        echo json_encode(['ok'=>true,'series'=>nm_sp_history($conn, $nid, (int)($_GET['hours'] ?? 24))]);
        exit;
    }

    // Compact per-node sparkline data (last hour) for the table — one call.
    if ($api === 'sparks') {
        echo json_encode(['ok'=>true,'sparks'=>nm_sp_spark_all($conn, (int)($_GET['hours'] ?? 1))]);
        exit;
    }

    // Active + recently-cleared latency alerts.
    if ($api === 'alerts') {
        echo json_encode(['ok'=>true] + nm_sp_alerts($conn));
        exit;
    }

    // Per-node + global threshold overrides (for the editor).
    if ($api === 'thresholds_get') {
        echo json_encode(['ok'=>true] + nm_sp_thresholds($conn));
        exit;
    }

    // Save a per-node threshold override (node>0) — blank fields clear the override.
    if ($api === 'thresholds_save') {
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $nid = (int)($_POST['node'] ?? 0);
        if ($nid <= 0) { echo json_encode(['ok'=>false,'error'=>'node required']); exit; }
        $empty = trim($_POST['rtt_warn']??'')==='' && trim($_POST['rtt_crit']??'')==='' && trim($_POST['loss_warn']??'')==='' && trim($_POST['loss_crit']??'')==='';
        if ($empty) nm_sp_threshold_clear($conn, $nid);
        else nm_sp_threshold_save($conn, $nid, ['rtt_warn'=>$_POST['rtt_warn']??'','rtt_crit'=>$_POST['rtt_crit']??'','loss_warn'=>$_POST['loss_warn']??'','loss_crit'=>$_POST['loss_crit']??'']);
        nm_audit($conn, 'smokeping.threshold_save', ['target_type'=>'nm_node','target_id'=>$nid,'details'=>['cleared'=>$empty]]);
        echo json_encode(['ok'=>true,'cleared'=>$empty]);
        exit;
    }

    // Re-evaluate alerts now (after a threshold change).
    if ($api === 'eval') {
        echo json_encode(nm_sp_eval_alerts($conn));
        exit;
    }

    echo json_encode(['ok'=>false,'error'=>'Unknown endpoint']);
    exit;
}

$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
include('header.php');
log_user_action($conn, 'view_page', 'smokeping.php');
// Manageable when we can reach the Docker host over native SSH (host IP set). The n8n manage webhook
// is a legacy/unused fallback — requiring it hid the panel for same-host/LAN installs that work fine.
$canManage = trim($SP['host_ip']) !== '';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><title>Smokeping | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --smoke:#0db7ed; --ok:#2ecc71; --warn:#f39c12; --stop:#e74c3c; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
.wrap{ max-width:1600px; margin:0 auto; padding:16px 20px 50px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; } .card h3{ margin:0 0 12px; font-size:13px; color:var(--smoke); text-transform:uppercase; letter-spacing:1px; }
.btn{ background:rgba(255,255,255,.06); border:1px solid var(--border); color:#cfd3da; padding:7px 12px; border-radius:8px; cursor:pointer; font-size:12px; display:inline-flex; gap:6px; align-items:center; }
.btn:hover{ background:rgba(255,255,255,.13); color:#fff; } .btn.go:hover{ border-color:var(--ok); color:var(--ok);} .btn.stop:hover{ border-color:var(--stop); color:var(--stop);}
input[type=text]{ background:rgba(0,0,0,.4); border:1px solid var(--border); color:#ddd; border-radius:8px; padding:8px 11px; font-size:13px; outline:none; }
input[type=text]:focus{ border-color:var(--accent); }
table{ width:100%; border-collapse:collapse; font-size:13px; } th{ text-align:left; padding:8px 10px; font-size:10px; text-transform:uppercase; letter-spacing:1px; color:#7c828c; border-bottom:1px solid var(--border); }
td{ padding:8px 10px; border-bottom:1px solid rgba(255,255,255,.05); } tr:hover td{ background:rgba(255,255,255,.03); }
.empty{ text-align:center; color:#667; padding:50px 20px; } .empty i{ font-size:40px; color:#333; display:block; margin-bottom:12px; }
.msg{ font-size:12px; margin-left:6px; } .mono{ font-family:Consolas,monospace; }
.spin-dot{ width:13px; height:13px; border:2px solid rgba(255,255,255,.2); border-top-color:var(--accent); border-radius:50%; display:inline-block; animation:sp .7s linear infinite; vertical-align:middle; } @keyframes sp{ to{ transform:rotate(360deg);} }
.badge{ font-size:10px; font-weight:700; padding:2px 8px; border-radius:6px; text-transform:uppercase; }
.b-crit{ background:rgba(231,76,60,.18); color:var(--stop);} .b-warn{ background:rgba(243,156,18,.18); color:var(--warn);}
.al-row{ display:flex; align-items:center; gap:12px; padding:9px 4px; border-bottom:1px solid rgba(255,255,255,.05); font-size:13px; }
.al-row:last-child{ border-bottom:0; }
.modal-bg{ position:fixed; inset:0; background:rgba(0,0,0,.6); display:none; align-items:center; justify-content:center; z-index:2000; }
.modal-bg.show{ display:flex; }
.modal{ background:#0f1722; border:1px solid var(--border); border-radius:14px; padding:20px 22px; width:380px; max-width:92vw; }
.modal h3{ margin:0 0 4px; font-size:15px; color:#fff; } .modal .sub{ font-size:11px; color:#7c828c; margin-bottom:14px; }
.modal label{ font-size:11px; color:#9aa; display:block; margin-bottom:4px; }
.modal input{ width:100%; background:rgba(0,0,0,.4); border:1px solid var(--border); color:#ddd; border-radius:8px; padding:8px 10px; font-size:13px; }
<?= nm_chrome_css() ?>
</style></head><body>
<div class="wrap">
    <?php nm_page_header('<i class="fas fa-wave-square"></i>Smokeping', '', 'Latency Monitoring', 'fa-solid fa-wave-square',
        ($SP['url']!=='' ? '<a class="refresh-btn" href="'.htmlspecialchars($SP['url']).'" target="_blank" rel="noopener"><i class="fas fa-arrow-up-right-from-square"></i> Open</a>' : '')); ?>

<?php if (!$SP['enabled']): ?>
    <div class="glass empty"><i class="fas fa-wave-square"></i>
        <div style="font-size:16px;color:#aaa;">Smokeping isn't enabled yet.</div>
        <div style="font-size:12px;color:#667;margin-top:6px;">Configure it in <a href="net_mon_config.php?tab=integrations">Config → Integrations → Smokeping</a>.</div></div>
<?php else: ?>

    <?php if ($canManage): $NODES = sp_node_targets($conn); ?>

    <!-- Active latency alerts -->
    <div class="glass card" id="alerts-card" style="display:none;border-left:4px solid var(--stop);">
        <h3 style="display:flex;justify-content:space-between;align-items:center;">
            <span><i class="fas fa-bell"></i> Latency Alerts <span id="al-count" class="badge" style="margin-left:6px;"></span></span>
            <span style="font-size:11px;color:#667;text-transform:none;font-weight:400;">thresholds in <a href="net_mon_config.php?tab=integrations" style="color:var(--accent);">Config</a> · per-node ⚙ below</span>
        </h3>
        <div id="alerts-body"></div>
    </div>

    <div class="glass card">
        <h3 style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
            <span><i class="fas fa-wave-square"></i> Node Latency <span style="color:#667;text-transform:none;font-weight:400;">— NEURU nodes monitored by Smokeping (tied by IP)</span></span>
            <span><button class="btn go" onclick="syncNodes()" title="Push all NEURU nodes to Smokeping as targets"><i class="fas fa-rotate"></i> Sync nodes → Smokeping</button>
                  <button class="btn" onclick="loadLatency()"><i class="fas fa-bolt"></i> Refresh latency</button>
                  <button class="btn" onclick="recordNow()" title="Pull Smokeping's RRD samples into NEURU's database now"><i class="fas fa-database"></i> Record now</button>
                  <button class="btn" onclick="spReload()"><i class="fas fa-arrows-rotate"></i> Reload</button></span>
        </h3>
        <div style="font-size:12px;color:#9aa;margin-bottom:10px;"><span id="sync-msg" class="msg"></span></div>
        <table><thead><tr><th>Node</th><th>IP</th><th>RTT (median)</th><th>Loss</th><th>Trend (1h)</th><th></th></tr></thead>
        <tbody id="t-body">
        <?php if (!$NODES): ?><tr><td colspan="6" style="color:#667;padding:16px;">No nodes with IPs yet. Add nodes in <a href="net_mon_config.php?tab=nodes">Config → Nodes</a>.</td></tr>
        <?php else: foreach ($NODES as $nd): ?>
            <tr data-key="<?= htmlspecialchars($nd['key']) ?>" data-node="<?= (int)$nd['id'] ?>" data-name="<?= htmlspecialchars($nd['name'], ENT_QUOTES) ?>">
                <td><a href="#" class="cname" style="font-weight:600;" onclick="showChart(<?= (int)$nd['id'] ?>,this.closest('tr').dataset.name);return false;"><?= htmlspecialchars($nd['name']) ?></a>
                    <span class="mono" style="color:#667;font-size:10px;"><?= htmlspecialchars($nd['mt']) ?></span></td>
                <td class="mono" style="color:var(--accent);"><?= htmlspecialchars($nd['ip']) ?></td>
                <td class="rtt mono" style="color:#9aa;"><span class="spin-dot" style="width:10px;height:10px;"></span></td>
                <td class="loss mono" style="color:#9aa;">—</td>
                <td><canvas class="spark" data-node="<?= (int)$nd['id'] ?>" width="120" height="26" style="width:120px;height:26px;cursor:pointer;" onclick="showChart(<?= (int)$nd['id'] ?>,this.closest('tr').dataset.name)"></canvas></td>
                <td style="text-align:right;white-space:nowrap;">
                    <button class="btn" title="Alert thresholds for this node" onclick="editThresh(<?= (int)$nd['id'] ?>,this.closest('tr').dataset.name)"><i class="fas fa-gear"></i></button>
                    <button class="btn" title="NEURU chart" onclick="showChart(<?= (int)$nd['id'] ?>,this.closest('tr').dataset.name)"><i class="fas fa-chart-line"></i></button></td></tr>
        <?php endforeach; endif ?>
        </tbody></table>
        <div style="font-size:11px;color:#667;margin-top:10px;"><i class="fas fa-circle-info"></i> Data is pulled from Smokeping's RRDs into NEURU's own database (independent history). Click a node for its full latency chart. The recorder cron keeps it current; “Record now” pulls on demand.</div>
    </div>

    <!-- NEURU-rendered latency chart (from our DB) -->
    <div class="glass card" id="chart-card" style="display:none;">
        <h3 style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
            <span><i class="fas fa-chart-line"></i> <span id="chart-title">Latency</span> <span id="chart-stats" style="color:#9aa;text-transform:none;font-weight:400;font-size:11px;"></span></span>
            <span id="range-btns">
                <?php foreach (['3'=>'3h','24'=>'24h','168'=>'7d','720'=>'30d'] as $h=>$lbl): ?>
                <button class="btn range" data-h="<?= $h ?>" onclick="setRange(<?= $h ?>,this)"<?= $h==='24'?' style="border-color:var(--accent);color:var(--accent);"':'' ?>><?= $lbl ?></button>
                <?php endforeach; ?>
            </span>
        </h3>
        <canvas id="lat-chart" style="width:100%;height:240px;"></canvas>
    </div>
    <?php endif ?>

    <?php if (!$canManage): ?>
    <div class="glass empty"><i class="fas fa-wave-square"></i>
        <div style="color:#aaa;">Set the Docker host IP (and an SSH credential for it) in
            <a href="net_mon_config.php?tab=integrations">Config → Integrations → Smokeping</a> to manage targets here.</div></div>
    <?php endif ?>

<?php endif ?>
</div>

<!-- Per-node alert thresholds modal -->
<div class="modal-bg" id="thr-modal">
  <div class="modal">
    <h3><i class="fas fa-bell"></i> Alert thresholds — <span id="thr-node">node</span></h3>
    <div class="sub">Leave all blank to use the global defaults. RTT in ms, loss in lost pings.</div>
    <input type="hidden" id="thr-id">
    <div style="display:flex;gap:10px;margin-bottom:10px;">
      <div style="flex:1;"><label>RTT warn</label><input type="number" step="0.1" id="thr-rw" placeholder="global"></div>
      <div style="flex:1;"><label>RTT crit</label><input type="number" step="0.1" id="thr-rc" placeholder="global"></div>
    </div>
    <div style="display:flex;gap:10px;margin-bottom:16px;">
      <div style="flex:1;"><label>Loss warn</label><input type="number" step="0.1" id="thr-lw" placeholder="global"></div>
      <div style="flex:1;"><label>Loss crit</label><input type="number" step="0.1" id="thr-lc" placeholder="global"></div>
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end;">
      <button class="btn" onclick="closeThresh()">Cancel</button>
      <button class="btn go" onclick="saveThresh()"><i class="fas fa-floppy-disk"></i> Save</button>
    </div>
    <div id="thr-msg" style="font-size:11px;color:#9aa;margin-top:8px;text-align:right;"></div>
  </div>
</div>

<?= function_exists('nm_tz_js') ? nm_tz_js($conn) : '' /* sets window.NM_TZ + nmClock so chart times honor the configured app timezone, not the browser */ ?>
<script>
const CAN_MANAGE = <?= $canManage ? 'true':'false' ?>;
let _thr = {global:{}, nodes:{}};
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function rttColor(ms){ if(ms==null) return '#9aa'; if(ms<20) return 'var(--ok)'; if(ms<80) return 'var(--warn)'; return 'var(--stop)'; }

async function loadLatency(){
    const rows=document.querySelectorAll('#t-body tr[data-key]'); if(!rows.length) return;
    try{ const r=await fetch('smokeping.php?api=latency&_='+Date.now()).then(r=>r.json());
        const L=(r.ok&&r.latency)?r.latency:{};
        rows.forEach(tr=>{ const k=tr.dataset.key, d=L[k];
            const rc=tr.querySelector('.rtt'), lc=tr.querySelector('.loss');
            if(!d || d.rtt_ms==null){ rc.innerHTML='<span style="color:#667;">no data</span>'; lc.textContent='—'; return; }
            rc.textContent=d.rtt_ms.toFixed(2)+' ms'; rc.style.color=rttColor(d.rtt_ms);
            const loss=(d.loss==null)?0:d.loss; lc.textContent=loss>0?(loss+' lost'):'0'; lc.style.color=loss>0?'var(--stop)':'var(--ok)';
        });
        if(!r.ok){ const m=document.getElementById('sync-msg'); m.textContent=r.error||'latency fetch failed'; m.style.color='var(--warn)'; }
    }catch(e){ document.querySelectorAll('#t-body .rtt').forEach(c=>c.textContent='—'); }
}
async function syncNodes(){
    const m=document.getElementById('sync-msg');
    if(!confirm('Push all NEURU nodes to Smokeping (rebuilds the +NEURU section) and reload?')) return;
    m.innerHTML='<span class="spin-dot"></span> syncing…'; m.style.color='#9aa';
    const r=await fetch('smokeping.php?api=sync_nodes',{method:'POST'}).then(r=>r.json()).catch(()=>({ok:false,error:'failed'}));
    m.textContent=r.message||(r.ok?'Synced':r.error); m.style.color=r.ok?'var(--ok)':'var(--stop)';
    if(r.ok) setTimeout(loadLatency, 1500);
}
async function spReload(){
    const m=document.getElementById('sync-msg'); m.innerHTML='<span class="spin-dot"></span> reloading…'; m.style.color='#9aa';
    const r=await fetch('smokeping.php?api=reload').then(r=>r.json()).catch(()=>({ok:false,error:'failed'}));
    m.textContent=r.message||(r.ok?'Reloaded':r.error); m.style.color=r.ok?'var(--ok)':'var(--stop)';
}
async function recordNow(){
    const m=document.getElementById('sync-msg'); m.innerHTML='<span class="spin-dot"></span> pulling RRD data…'; m.style.color='#9aa';
    const r=await fetch('smokeping.php?api=record&hours=6').then(r=>r.json()).catch(()=>({ok:false,error:'failed'}));
    m.textContent=r.ok?('Recorded '+(r.inserted||0)+' samples from '+(r.targets||0)+' targets'):(r.error||'failed'); m.style.color=r.ok?'var(--ok)':'var(--stop)';
    if(r.ok){ loadSparks(); if(_chartNode) showChart(_chartNode,_chartName); }
}

// ── sparklines (last hour, from our DB) ───────────────────────────────────────
function drawSpark(cv, vals){
    const dpr=devicePixelRatio, w=cv.width=cv.clientWidth*dpr, h=cv.height=26*dpr, ctx=cv.getContext('2d');
    ctx.clearRect(0,0,w,h);
    const pts=(vals||[]).filter(v=>v!=null); if(pts.length<2){ ctx.fillStyle='#556'; ctx.font=(10*dpr)+'px sans-serif'; ctx.fillText('—',2,16*dpr); return; }
    const mn=Math.min(...pts), mx=Math.max(...pts), rng=(mx-mn)||1;
    ctx.beginPath(); pts.forEach((v,i)=>{ const x=w*i/(pts.length-1), y=h-3*dpr-(h-6*dpr)*(v-mn)/rng; i?ctx.lineTo(x,y):ctx.moveTo(x,y); });
    ctx.strokeStyle=rttColor(pts[pts.length-1]); ctx.lineWidth=1.4*dpr; ctx.stroke();
}
async function loadSparks(){
    try{ const r=await fetch('smokeping.php?api=sparks&hours=1&_='+Date.now()).then(r=>r.json());
        if(!r.ok) return; const S=r.sparks||{};
        document.querySelectorAll('canvas.spark').forEach(cv=>drawSpark(cv, S[cv.dataset.node]||[]));
    }catch(e){}
}

// ── NEURU-rendered latency chart (from our DB) ────────────────────────────────
let _chartNode=0, _chartName='', _chartHours=24;
function fmtTime(ts,hours){
    if(window.NM_TZ){ return hours<=24 ? nmClock(ts) : new Intl.DateTimeFormat('en-US',{timeZone:window.NM_TZ,month:'numeric',day:'numeric'}).format(new Date(ts*1000)); }
    const d=new Date(ts*1000); return hours<=24 ? d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}) : (d.getMonth()+1)+'/'+d.getDate();
}
function setRange(h,btn){ _chartHours=h; document.querySelectorAll('#range-btns .range').forEach(b=>b.style.cssText=''); if(btn) btn.style.cssText='border-color:var(--accent);color:var(--accent);'; if(_chartNode) showChart(_chartNode,_chartName); }
async function showChart(nodeId,name){
    _chartNode=nodeId; _chartName=name||('Node '+nodeId);
    const card=document.getElementById('chart-card'); card.style.display='block';
    document.getElementById('chart-title').textContent=_chartName+' — latency';
    document.getElementById('chart-stats').textContent='loading…';
    card.scrollIntoView({behavior:'smooth',block:'nearest'});
    try{ const r=await fetch(`smokeping.php?api=history&node=${nodeId}&hours=${_chartHours}&_=`+Date.now()).then(r=>r.json());
        if(!r.ok){ document.getElementById('chart-stats').textContent=r.error||'failed'; return; }
        renderChart(r.series||[]);
    }catch(e){ document.getElementById('chart-stats').textContent='request failed'; }
}
function renderChart(series){
    const cv=document.getElementById('lat-chart'), dpr=devicePixelRatio;
    const w=cv.width=cv.clientWidth*dpr, h=cv.height=240*dpr, ctx=cv.getContext('2d');
    ctx.clearRect(0,0,w,h);
    const padL=46*dpr, padR=10*dpr, padT=12*dpr, padB=22*dpr;
    const rtts=series.map(s=>s.rtt).filter(v=>v!=null);
    const stats=document.getElementById('chart-stats');
    if(rtts.length<2){ stats.textContent='no data yet (run “Record now”, or wait for the cron)'; ctx.fillStyle='#667'; ctx.font=(13*dpr)+'px sans-serif'; ctx.fillText('No samples in range',padL,h/2); return; }
    const mx=Math.max(...rtts)*1.2||10, avg=rtts.reduce((a,b)=>a+b,0)/rtts.length, mxv=Math.max(...rtts);
    const lossN=series.filter(s=>s.loss>0).length;
    stats.textContent=`avg ${avg.toFixed(2)} ms · peak ${mxv.toFixed(2)} ms · ${series.length} pts${lossN?` · ${lossN} with loss`:''}`;
    const t0=series[0].t, t1=series[series.length-1].t, tr=(t1-t0)||1;
    const X=t=>padL+(w-padL-padR)*(t-t0)/tr, Y=v=>h-padB-(h-padT-padB)*Math.min(v,mx)/mx;
    // grid + y labels
    ctx.font=(10*dpr)+'px Consolas,monospace'; ctx.textBaseline='middle'; ctx.textAlign='right';
    for(let g=0;g<=4;g++){ const y=padT+(h-padT-padB)*g/4; ctx.strokeStyle='rgba(255,255,255,.06)'; ctx.beginPath(); ctx.moveTo(padL,y); ctx.lineTo(w-padR,y); ctx.stroke();
        ctx.fillStyle='rgba(255,255,255,.4)'; ctx.fillText((mx*(4-g)/4).toFixed(mx<10?1:0)+'ms', padL-5*dpr, y); }
    // loss markers (red vertical ticks)
    series.forEach(s=>{ if(s.loss>0){ ctx.strokeStyle='rgba(231,76,60,.5)'; ctx.lineWidth=1*dpr; ctx.beginPath(); const x=X(s.t); ctx.moveTo(x,padT); ctx.lineTo(x,h-padB); ctx.stroke(); } });
    // rtt line + fill (skip null gaps)
    ctx.beginPath(); let started=false;
    series.forEach(s=>{ if(s.rtt==null){ started=false; return; } const x=X(s.t),y=Y(s.rtt); started?ctx.lineTo(x,y):ctx.moveTo(x,y); started=true; });
    ctx.strokeStyle='#4da3ff'; ctx.lineWidth=1.8*dpr; ctx.stroke();
    // x labels (start / mid / end)
    ctx.fillStyle='rgba(255,255,255,.45)'; ctx.textAlign='center'; ctx.textBaseline='top';
    [0,.5,1].forEach(f=>{ const t=t0+tr*f; ctx.fillText(fmtTime(t,_chartHours), padL+(w-padL-padR)*f, h-padB+5*dpr); });
}
// ── alerts panel ──────────────────────────────────────────────────────────────
function alStr(a){ const u=a.metric==='rtt'?'ms':' lost'; const v=(a.value==null?'—':(+a.value).toFixed(a.metric==='rtt'?2:1)); return `${a.metric.toUpperCase()} ${v}${u} ≥ ${(+a.threshold).toFixed(a.metric==='rtt'?0:1)}${u}`; }
async function loadAlerts(){
    try{ const r=await fetch('smokeping.php?api=alerts&_='+Date.now()).then(r=>r.json());
        const card=document.getElementById('alerts-card'), body=document.getElementById('alerts-body'), cnt=document.getElementById('al-count');
        if(!r.ok){ card.style.display='none'; return; }
        const open=r.open||[];
        if(!open.length){ card.style.display='none'; return; }
        card.style.display='block';
        const crit=open.filter(a=>a.severity==='crit').length, warn=open.length-crit;
        card.style.borderLeftColor = crit? 'var(--stop)':'var(--warn)';
        cnt.className='badge '+(crit?'b-crit':'b-warn'); cnt.textContent=open.length+(crit?(' · '+crit+' crit'):'');
        body.innerHTML=open.map(a=>`<div class="al-row">
            <span class="badge ${a.severity==='crit'?'b-crit':'b-warn'}">${a.severity}</span>
            <b style="min-width:160px;">${esc(a.display_name)}</b>
            <span class="mono" style="color:var(--accent);">${esc(a.ip_address)}</span>
            <span class="mono" style="color:${a.severity==='crit'?'var(--stop)':'var(--warn)'};">${alStr(a)}</span>
            <span style="margin-left:auto;color:#667;font-size:11px;">since ${esc((window.nmLocal?nmLocal(a.opened_at):(a.opened_at||'')).slice(5,16))}</span>
            <a class="btn" onclick="showChart(${a.node_id},'${esc(a.display_name)}')" style="cursor:pointer;"><i class="fas fa-chart-line"></i></a></div>`).join('');
    }catch(e){}
}

// ── per-node threshold editor ─────────────────────────────────────────────────
async function ensureThr(){ if(Object.keys(_thr.global).length) return; try{ const r=await fetch('smokeping.php?api=thresholds_get').then(r=>r.json()); if(r.ok) _thr={global:r.global||{},nodes:r.nodes||{}}; }catch(e){} }
async function editThresh(id,name){
    await ensureThr();
    const t=_thr.nodes[id]||{}, g=_thr.global;
    document.getElementById('thr-node').textContent=name; document.getElementById('thr-id').value=id;
    const set=(el,v,gv)=>{ const e=document.getElementById(el); e.value=(v==null?'':v); e.placeholder='global '+(gv==null?'—':gv); };
    set('thr-rw',t.rtt_warn,g.rtt_warn); set('thr-rc',t.rtt_crit,g.rtt_crit); set('thr-lw',t.loss_warn,g.loss_warn); set('thr-lc',t.loss_crit,g.loss_crit);
    document.getElementById('thr-msg').textContent=''; document.getElementById('thr-modal').classList.add('show');
}
function closeThresh(){ document.getElementById('thr-modal').classList.remove('show'); }
async function saveThresh(){
    const id=document.getElementById('thr-id').value, m=document.getElementById('thr-msg');
    const fd=new FormData(); fd.append('node',id);
    fd.append('rtt_warn',document.getElementById('thr-rw').value.trim());
    fd.append('rtt_crit',document.getElementById('thr-rc').value.trim());
    fd.append('loss_warn',document.getElementById('thr-lw').value.trim());
    fd.append('loss_crit',document.getElementById('thr-lc').value.trim());
    m.innerHTML='<span class="spin-dot"></span> saving…';
    const r=await fetch('smokeping.php?api=thresholds_save',{method:'POST',body:fd}).then(r=>r.json()).catch(()=>({ok:false}));
    if(r.ok){ _thr.nodes={}; _thr.global={}; await fetch('smokeping.php?api=eval'); m.textContent=r.cleared?'Cleared (using global)':'Saved'; setTimeout(()=>{closeThresh();loadAlerts();},700); }
    else m.textContent=r.error||'failed';
}
document.getElementById('thr-modal')?.addEventListener('click',e=>{ if(e.target.id==='thr-modal') closeThresh(); });

window.addEventListener('resize',()=>{ if(_chartNode) showChart(_chartNode,_chartName); loadSparks(); });
if(CAN_MANAGE){ loadLatency(); loadSparks(); loadAlerts(); setInterval(loadLatency, 60000); setInterval(loadSparks, 120000); setInterval(loadAlerts, 60000); }

// Deep-link: ?node=<id> auto-opens that target's latency chart + scrolls to its row
// (so "Smokeping" from an insight / incident lands on the right device).
(function(){ const fn=parseInt(new URLSearchParams(location.search).get('node')||'0',10)||0;
    if(!fn) return;
    setTimeout(()=>{ const tr=document.querySelector('tr[data-node="'+fn+'"]');
        showChart(fn, tr ? tr.dataset.name : ('Node #'+fn));
        if(tr){ tr.style.outline='2px solid var(--accent)'; tr.scrollIntoView({behavior:'smooth',block:'center'}); }
    }, 400);   // let the table + sparklines paint first
})();
</script>
</body></html>
