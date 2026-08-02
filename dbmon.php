<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU Data Core — Database Observatory (Phase 1: fleet + connectivity)
// Page: a live fleet of every configured DB target (status, version, connections).
// API : targets CRUD + test + node/engine helpers — also consumed by the
//       net_mon_config.php "Databases" tab. The deep interfaces (Deadlock Radar,
//       CRUD Heatmap, Index Archaeologist, Schema Drift) arrive in the next parts.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
include('logger.php');
require_once('nm_dbmon.php');
require_once('nm_n8n.php');
@require_once('nm_tz.php');

$api = $_GET['api'] ?? '';
// Page needs 'dbmon'; the management API also accepts 'net_mon_config' so the
// Config → Databases tab can manage targets without a separate grant.
$canPage = checkAccess($conn, 'dbmon');
$canApi  = $canPage || checkAccess($conn, 'net_mon_config');
if (($api && !$canApi) || (!$api && !$canPage)) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'err'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=dbmon'); exit;
}
$uid = (int)($_SESSION['UID'] ?? 0);
// CRITICAL: release the PHP session lock NOW. DB/SSH probes can take seconds (or hang on a
// firewalled host); holding the session would block EVERY other request for this user and
// freeze the whole portal. We only read $_SESSION above and never write it after this point.
if (session_status() === PHP_SESSION_ACTIVE) @session_write_close();

if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');

    if ($api === 'engines') {
        $out = [];
        foreach (nm_db_engines() as $k=>$m) $out[$k] = ['label'=>$m['label'],'port'=>$m['port'],'caps'=>nm_db_transport_caps($k)];
        echo json_encode(['ok'=>true,'engines'=>$out]); exit;
    }
    if ($api === 'nodes') {
        $rows = [];
        $r = $conn->query("SELECT id,display_name,ip_address,os_icon FROM nm_nodes ORDER BY display_name");
        while ($r && ($x=$r->fetch_assoc())) $rows[] = $x;
        echo json_encode(['ok'=>true,'nodes'=>$rows]); exit;
    }
    if ($api === 'targets') { echo json_encode(['ok'=>true,'targets'=>nm_db_targets($conn)]); exit; }

    if ($api === 'save') {
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $b = json_decode(file_get_contents('php://input'), true) ?? [];
        $res = nm_db_target_save($conn, $b, $uid);
        if ($res['ok']) nm_audit($conn, 'dbmon.target_save', ['target_type'=>'db_target','target_id'=>$res['id'],'details'=>['name'=>$b['display_name']??'','engine'=>$b['engine']??'']]);
        echo json_encode($res); exit;
    }
    if ($api === 'delete') {
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $b = json_decode(file_get_contents('php://input'), true) ?? [];
        $id = (int)($b['id'] ?? 0);
        nm_audit($conn, 'dbmon.target_delete', ['target_type'=>'db_target','target_id'=>$id]);
        echo json_encode(nm_db_target_delete($conn, $id)); exit;
    }
    if ($api === 'test') {
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $b = json_decode(file_get_contents('php://input'), true) ?? [];
        echo json_encode(nm_db_test($conn, (int)($b['id'] ?? 0))); exit;
    }
    // ── live observatory data (processlist + lock chains + slow queries) ──
    if ($api === 'live' || $api === 'heatmap') {
        $t = nm_db_target($conn, (int)($_GET['target'] ?? 0));
        if (!$t) { echo json_encode(['ok'=>false,'error'=>'Target not found']); exit; }
        if (($t['transport'] ?? 'direct') === 'direct') {
            $caps = nm_db_transport_caps($t['engine']);
            if (!$caps['direct']) { echo json_encode(['ok'=>false,'error'=>$caps['direct_reason']]); exit; }
        }
        try {
            $mon = nm_db_monitor($conn, $t);
            $data = ($api === 'live') ? $mon->live() : $mon->heatmap();
            if ($api === 'live') { $data['probe'] = $mon->probe(); $data['target'] = ['id'=>(int)$t['id'],'name'=>$t['display_name'],'engine'=>$t['engine'],'transport'=>$t['transport'],'node_id'=>$t['node_id']]; }
            echo json_encode($data);
        } catch (\Throwable $e) {
            nm_db_set_status($conn, (int)$t['id'], 'error', $e->getMessage(), null);
            echo json_encode(['ok'=>false,'error'=>$e->getMessage()]);
        }
        exit;
    }
    // ── KILL a session (mutating → needs the dbmon perm, audited) ──
    if ($api === 'kill') {
        if (!$canPage) { echo json_encode(['ok'=>false,'error'=>'The dbmon permission is required to kill sessions']); exit; }
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $b = json_decode(file_get_contents('php://input'), true) ?? [];
        $t = nm_db_target($conn, (int)($b['target'] ?? 0)); $pid = (int)($b['pid'] ?? 0);
        if (!$t || $pid <= 0) { echo json_encode(['ok'=>false,'error'=>'Bad target/pid']); exit; }
        try {
            nm_db_monitor($conn, $t)->killPid($pid);
            nm_audit($conn, 'dbmon.kill', ['target_type'=>'db_target','target_id'=>(int)$t['id'],'details'=>['pid'=>$pid,'db'=>$t['display_name']]]);
            echo json_encode(['ok'=>true]);
        } catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>$e->getMessage()]); }
        exit;
    }
    // ── Index Archaeologist: live top queries (digest analysis) ──
    if ($api === 'queries') {
        $t = nm_db_target($conn, (int)($_GET['target'] ?? 0));
        if (!$t) { echo json_encode(['ok'=>false,'error'=>'Target not found']); exit; }
        if (($t['transport'] ?? 'direct') === 'direct') { $caps=nm_db_transport_caps($t['engine']); if(!$caps['direct']){ echo json_encode(['ok'=>false,'error'=>$caps['direct_reason']]); exit; } }
        try { echo json_encode(nm_db_monitor($conn,$t)->topQueries()); }
        catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>$e->getMessage(),'queries'=>[]]); }
        exit;
    }
    // ── advice list (Index Archaeologist + Solution Center) ──
    if ($api === 'advice') { echo json_encode(['ok'=>true,'advice'=>nm_db_advice_list($conn,(int)($_GET['target']??0))]); exit; }
    // ── ship the DB context to the n8n 'db-advisor' flow (it posts suggestions back to dbmon_api.php) ──
    if ($api === 'advice_analyze') {
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $b = json_decode(file_get_contents('php://input'), true) ?? [];
        $t = nm_db_target($conn, (int)($b['target'] ?? 0));
        if (!$t) { echo json_encode(['ok'=>false,'error'=>'Target not found']); exit; }
        try {
            $mon = nm_db_monitor($conn,$t);
            $tq  = $mon->topQueries(); $hm = $mon->heatmap();
            $schema = nm_db_schema_get($conn,(int)$t['id']);
            $cfg = nm_n8n_get($conn);
            $payload = [
                'event'=>'db_advise', 'target_id'=>(int)$t['id'], 'engine'=>$t['engine'], 'db_name'=>$t['db_name'],
                'top_queries'=>array_slice($tq['queries']??[],0,25),
                'tables'=>array_slice($hm['tables']??[],0,60),
                'schema_objects'=>$schema['snapshot']['item_count']??0,
                'callback'=>(($cfg['portal_base']??'') ?: ('http://localhost')) . '/dbmon_api.php',
            ];
            [$code,$resp,$err] = nm_n8n_call($conn, 'db-advisor', $payload, 25);
            $ok = ($code>=200 && $code<300);
            // Honest hint: only say "register the webhook" if it REALLY isn't registered/enabled.
            // A registered flow that failed is almost always a transient tunnel/host blip → say so,
            // so a momentary hiccup doesn't look like a broken install (testers should just retry).
            $wh = function_exists('nm_n8n_webhook_by_slug') ? nm_n8n_webhook_by_slug($conn,'db-advisor') : null;
            $registered = $wh && !empty($wh['enabled']) && trim((string)($wh['url'] ?? '')) !== '';
            if ($ok)              $hint = 'Sent — suggestions will appear here when the n8n flow posts them back.';
            elseif (!$registered) $hint = 'The "db-advisor" flow isn\'t configured. Enable it in Config → Integrations & AI (or run Sync Flows) and activate it in n8n.';
            else                  $hint = 'The AI advisor didn\'t respond just now (timeout, or the n8n tunnel/host was briefly unreachable). This is usually transient — try again in a moment.';
            echo json_encode(['ok'=>$ok, 'http'=>$code, 'reply'=>substr((string)$resp,0,300),
                'error'=>$ok?null:($err ?: ('the flow returned HTTP '.$code)), 'hint'=>$hint]);
        } catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>$e->getMessage()]); }
        exit;
    }
    // ── apply / dismiss a recommendation (mutating → dbmon perm, audited) ──
    if ($api === 'advice_apply') {
        if (!$canPage) { echo json_encode(['ok'=>false,'error'=>'The dbmon permission is required to apply changes']); exit; }
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $b = json_decode(file_get_contents('php://input'), true) ?? [];
        $res = nm_db_apply_advice($conn, (int)($b['id']??0), $uid);
        nm_audit($conn, 'dbmon.advice_apply', ['target_type'=>'db_advice','target_id'=>(int)($b['id']??0),'details'=>['ok'=>$res['ok']]]);
        echo json_encode($res); exit;
    }
    if ($api === 'advice_dismiss') {
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $b = json_decode(file_get_contents('php://input'), true) ?? [];
        nm_db_advice_set_status($conn, (int)($b['id']??0), 'dismissed', null);
        echo json_encode(['ok'=>true]); exit;
    }
    // ── replication: live master/replica health + GTID gap ──
    if ($api === 'replication') {
        echo json_encode(nm_db_repl_status($conn, (int)($_GET['target'] ?? 0))); exit;
    }
    // ── replication drift: per-table row compare (estimate; exact for one table on demand) ──
    if ($api === 'repl_drift') {
        $exact = isset($_GET['table']) && $_GET['table'] !== '' ? (string)$_GET['table'] : null;
        echo json_encode(nm_db_repl_drift($conn, (int)($_GET['target'] ?? 0), $exact)); exit;
    }
    // ── schema drift: read stored snapshot + drift events (fast, no live connect) ──
    if ($api === 'schema') {
        echo json_encode(nm_db_schema_get($conn, (int)($_GET['target'] ?? 0))); exit;
    }
    // ── force a fresh schema capture now (live fingerprint) ──
    if ($api === 'schema_capture') {
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $b = json_decode(file_get_contents('php://input'), true) ?? [];
        echo json_encode(nm_db_schema_capture($conn, (int)($b['target'] ?? 0), true)); exit;
    }
    // ── trend samples for the sparkline ──
    if ($api === 'samples') {
        $tid = (int)($_GET['target'] ?? 0); $rows = [];
        $r = $conn->query("SELECT UNIX_TIMESTAMP(sampled_at) ts, connections, max_connections, threads_running, blocked, slow
                           FROM nm_db_samples WHERE target_id=$tid ORDER BY id DESC LIMIT 120");
        while ($r && ($x=$r->fetch_assoc())) $rows[] = $x;
        echo json_encode(['ok'=>true,'samples'=>array_reverse($rows)]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}

log_user_action($conn, 'view_page', 'dbmon.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Data Core — DB Observatory | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" media="print" onload="this.media='all'">
<noscript><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"></noscript>
<?= function_exists('nm_tz_js') ? nm_tz_js() : '' ?>
<style>
:root{ --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.13); }
html{ background:#05080f; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; color:#e7ecf3; background:transparent!important; }
.wrap{ max-width:1280px; margin:0 auto; padding:22px 20px 70px; }
h1{ font-size:22px; display:flex; align-items:center; gap:12px; margin:0 0 4px; }
h1 .sub{ font-size:12px; color:#8a93a3; font-weight:400; }
.bn{ background:rgba(77,163,255,.08); border:1px solid rgba(77,163,255,.3); border-radius:12px; padding:12px 16px; margin:14px 0 20px; font-size:13px; color:#bcd4ee; display:flex; gap:10px; align-items:center; }
.bn a{ color:#9cc7ff; }
.grid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(310px,1fr)); gap:16px; }
.card{ background:var(--glass); border:1px solid var(--border); border-radius:15px; padding:16px 18px; position:relative; }
#db-skyline:fullscreen{ height:100vh; width:100vw; border-radius:0; background:transparent; }
#db-skyline:fullscreen::backdrop{ background:#070b12; }
.card.ok{ border-left:4px solid var(--ok); } .card.error{ border-left:4px solid var(--crit); } .card.unknown{ border-left:4px solid #667; }
.card h3{ margin:0 0 2px; font-size:16px; display:flex; align-items:center; gap:9px; }
.eng{ font-size:9.5px; font-weight:700; letter-spacing:.5px; text-transform:uppercase; padding:2px 8px; border-radius:6px; background:rgba(255,255,255,.08); color:#bcd; }
.tp{ font-size:9.5px; color:#8a93a3; border:1px solid var(--border); border-radius:5px; padding:1px 6px; }
.meta{ font-size:11.5px; color:#8a93a3; font-family:monospace; margin:3px 0 12px; }
.kv{ display:flex; justify-content:space-between; font-size:12.5px; padding:3px 0; border-bottom:1px solid rgba(255,255,255,.05); }
.kv b{ font-weight:700; } .pill{ position:absolute; top:14px; right:14px; font-size:10px; font-weight:700; padding:3px 9px; border-radius:20px; }
.pill.ok{ color:var(--ok); background:rgba(46,204,113,.14);} .pill.error{ color:var(--crit); background:rgba(231,76,60,.14);} .pill.unknown{ color:#9aa; background:rgba(255,255,255,.06);}
.satbar{ height:6px; border-radius:4px; background:rgba(255,255,255,.09); overflow:hidden; margin-top:3px;}
.satbar i{ display:block; height:100%; border-radius:4px; }
.btn{ display:inline-flex; align-items:center; gap:7px; background:rgba(77,163,255,.12); border:1px solid rgba(77,163,255,.4); color:#9cc7ff; padding:7px 13px; border-radius:9px; font-size:12.5px; cursor:pointer; text-decoration:none; }
.btn:hover{ background:rgba(77,163,255,.22); color:#fff; }
.empty{ text-align:center; color:#5a6472; padding:60px 20px; } .empty i{ font-size:44px; display:block; margin-bottom:14px; color:var(--accent); }
.spin{ width:15px;height:15px;border:2px solid rgba(255,255,255,.2);border-top-color:var(--accent);border-radius:50%;display:inline-block;animation:sp .7s linear infinite;vertical-align:middle;}
@keyframes sp{ to{ transform:rotate(360deg);} }
/* ── detail observatory ── */
.back{ display:inline-flex;align-items:center;gap:7px;color:#9cc7ff;text-decoration:none;font-size:13px;margin-bottom:10px; }
.kpis{ display:flex;gap:14px;flex-wrap:wrap;margin:6px 0 18px; }
.kpi{ background:var(--glass);border:1px solid var(--border);border-radius:12px;padding:12px 16px;min-width:120px; }
.kpi .n{ font-size:24px;font-weight:800; } .kpi .l{ font-size:11px;color:#8a93a3;text-transform:uppercase;letter-spacing:.5px; }
.sec{ background:var(--glass);border:1px solid var(--border);border-radius:15px;padding:16px 18px;margin-bottom:16px; }
.sec h2{ font-size:15px;margin:0 0 4px;display:flex;align-items:center;gap:9px; } .sec .h{ font-size:11.5px;color:#8a93a3;margin:0 0 12px; }
#radar{ position:relative;height:400px;border-radius:14px;overflow:hidden;background:radial-gradient(circle at 50% 50%,rgba(77,163,255,.06),transparent 72%);border:1px solid rgba(77,163,255,.12); }
#radar svg{ position:absolute;inset:0;width:100%;height:100%;pointer-events:none; }
.qbub{ position:absolute;transform:translate(-50%,-50%);min-width:54px;max-width:120px;padding:7px 9px;border-radius:11px;cursor:pointer;
  background:rgba(77,163,255,.14);border:1px solid rgba(77,163,255,.5);text-align:center;transition:transform .15s; z-index:2; }
.qbub:hover{ transform:translate(-50%,-50%) scale(1.08); }
.qbub.slow{ background:rgba(231,76,60,.18);border-color:var(--crit); animation:pulse 1.3s infinite; }
.qbub.block{ background:rgba(243,156,18,.18);border-color:var(--warn); }
.qbub .pid{ font-size:11px;font-weight:800; } .qbub .t{ font-size:10px;color:#bcd; white-space:nowrap;overflow:hidden;text-overflow:ellipsis; }
@keyframes pulse{ 50%{ box-shadow:0 0 0 6px rgba(231,76,60,.12);} }
.radar-empty{ position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:#5a6472;font-size:13px; }
.qpanel{ margin-top:12px;border:1px solid var(--border);border-radius:11px;padding:12px;background:rgba(0,0,0,.25);display:none; }
.qpanel pre{ background:rgba(0,0,0,.45);border:1px solid rgba(255,255,255,.1);border-radius:8px;padding:10px;font-size:12px;color:#cfe;white-space:pre-wrap;word-break:break-word;max-height:160px;overflow:auto; }
.hmgrid{ display:grid;grid-template-columns:repeat(auto-fill,minmax(58px,1fr));gap:5px; }
.hcell{ aspect-ratio:1;border-radius:6px;cursor:pointer;border:1px solid rgba(255,255,255,.08);display:flex;align-items:flex-end;padding:4px;overflow:hidden;transition:transform .12s; }
.hcell:hover{ transform:scale(1.12);z-index:3;border-color:#fff; }
.hcell span{ font-size:8.5px;color:rgba(255,255,255,.85);line-height:1.05;word-break:break-all; }
.hlegend{ display:flex;gap:16px;font-size:11px;color:#8a93a3;margin-top:10px;align-items:center;flex-wrap:wrap; }
.hlegend i{ width:12px;height:12px;border-radius:3px;display:inline-block;vertical-align:middle;margin-right:5px; }
table.pl{ width:100%;border-collapse:collapse;font-size:12px; } table.pl td,table.pl th{ padding:5px 7px;border-bottom:1px solid rgba(255,255,255,.05);text-align:left;vertical-align:top; }
table.pl th{ color:#7c828c;font-size:10px;text-transform:uppercase; } .qx{ font-family:Consolas,monospace;color:#bcd;max-width:520px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }
.kbtn{ background:rgba(231,76,60,.14);border:1px solid rgba(231,76,60,.5);color:#ff9b8f;padding:3px 9px;border-radius:7px;font-size:11px;cursor:pointer; }
.kbtn:hover{ background:var(--crit);color:#fff; }
</style>
</head>
<body>
<?php include('header.php'); ?>
<script src="three.min.js"></script>
<script src="three-orbitcontrols.js"></script>
<div class="wrap">
  <h1><i class="fas fa-database" style="color:var(--accent);"></i> Data Core <span class="sub">Database Observatory — treat every DB as a living ecosystem</span></h1>
  <div class="bn" id="bn"><i class="fas fa-circle-info"></i>
    <span>Configure targets in <a href="net_mon_config.php?tab=databases">Config → Databases</a>. Click a database to open its live <b>Deadlock Radar</b> &amp; <b>CRUD Heatmap</b>. <span style="color:#778;">(Next: Index Archaeologist &amp; Schema Drift.)</span></span>
  </div>
  <div id="fleet"><div class="empty"><span class="spin"></span></div></div>
  <div id="detail" style="display:none;"></div>
</div>

<script>
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function dur(s){ s=+s||0; const d=Math.floor(s/86400),h=Math.floor(s%86400/3600); return d?`${d}d ${h}h`:(h?`${h}h`:`${Math.floor(s/60)}m`); }
function clr(p){ return p>=90?'var(--crit)':(p>=75?'var(--warn)':'var(--ok)'); }
// fetch with a hard client-side timeout so a slow/hung probe never spins the UI forever
function jfetch(url,opts,ms){ const c=new AbortController(); const id=setTimeout(()=>c.abort(),ms||16000);
  return fetch(url,Object.assign({signal:c.signal},opts||{})).then(r=>r.json()).catch(()=>null).finally(()=>clearTimeout(id)); }

async function load(){
  const r=await fetch('dbmon.php?api=targets&_='+Date.now()).then(r=>r.json()).catch(()=>null);
  const box=document.getElementById('fleet');
  const T=(r&&r.targets)||[];
  if(!T.length){ box.innerHTML=`<div class="empty"><i class="fas fa-database"></i>
    <div style="font-size:16px;color:#aaa;">No databases configured yet.</div>
    <div style="font-size:12px;color:#667;margin-top:6px;">Add one in <a href="net_mon_config.php?tab=databases" style="color:var(--accent)">Config → Databases</a> — link it to a monitored node and pick direct or SSH transport.</div></div>`; return; }
  box.innerHTML='<div class="grid">'+T.map(cardHTML).join('')+'</div>';
}
function cardHTML(t){
  const st=t.last_status||'unknown';
  const node=t.node_name?`<a href="troubleshoot.php?node=${t.node_id}" style="color:#9cc7ff;text-decoration:none;">${esc(t.node_name)}</a>`:'<span style="color:#778;">no node</span>';
  return `<div class="card ${st}">
    <span class="pill ${st}">${st.toUpperCase()}</span>
    <h3>${esc(t.display_name)}</h3>
    <div style="display:flex;gap:7px;align-items:center;margin-top:4px;"><span class="eng">${esc(t.engine)}</span><span class="tp">${esc(t.transport)}</span></div>
    <div class="meta">${esc(t.host)}:${esc(t.port||'')}${t.db_name?(' / '+esc(t.db_name)):''} &middot; node: ${node}</div>
    ${t.last_version?`<div class="kv"><span>Version</span><b>${esc(t.last_version)}</b></div>`:''}
    ${t.last_error?`<div class="kv" style="color:var(--crit);"><span>Last error</span><b title="${esc(t.last_error)}">${esc(t.last_error.slice(0,38))}</b></div>`:''}
    <div class="kv"><span>Last checked</span><b>${t.last_checked?(window.nmLocal?window.nmLocal(t.last_checked):esc(t.last_checked)):'never'}</b></div>
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;">
      <button class="btn" onclick="openDetail(${t.id})"><i class="fas fa-satellite-dish"></i> Observe</button>
      <button class="btn" onclick="testT(${t.id},this)" style="background:transparent;border-color:var(--border);color:#bcc8d6;"><i class="fas fa-plug"></i> Test</button>
      <a class="btn" href="net_mon_config.php?tab=databases" style="background:transparent;border-color:var(--border);color:#bcc8d6;"><i class="fas fa-gear"></i> Config</a>
    </div>
    <div id="probe-${t.id}" style="margin-top:10px;"></div>
  </div>`;
}
async function testT(id,btn){
  btn.disabled=true; const old=btn.innerHTML; btn.innerHTML='<span class="spin"></span> testing…';
  const r=await fetch('dbmon.php?api=test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}).then(r=>r.json()).catch(()=>({ok:false,error:'request failed'}));
  btn.disabled=false; btn.innerHTML=old;
  const box=document.getElementById('probe-'+id);
  if(!r.ok){ box.innerHTML=`<div style="color:var(--crit);font-size:12px;"><i class="fas fa-circle-xmark"></i> ${esc(r.error||'failed')}</div>`; return; }
  const p=r.probe||{}, used=+p.connections||0, max=+p.max_connections||0, pct=max?Math.round(used/max*100):0;
  box.innerHTML=`<div class="kv"><span>Version</span><b>${esc(p.version||'')}</b></div>
    <div class="kv"><span>Uptime</span><b>${dur(p.uptime_s)}</b></div>
    ${p.db_bytes!=null?`<div class="kv"><span>Data size${p.db_count?` · ${p.db_count} db`+(p.db_count>1?'s':''):''}</span><b>${fmtB(p.db_bytes)}</b></div>`:''}
    <div class="kv"><span>Active / running</span><b>${esc(p.threads_running)}</b></div>
    <div style="font-size:12px;margin-top:6px;"><span style="color:#8a93a3;">Connections ${used}/${max||'?'}</span>
      <div class="satbar"><i style="width:${Math.min(100,pct)}%;background:${clr(pct)};"></i></div></div>`;
  setTimeout(load, 1200);
}

// ───────────────────────── Detail observatory ─────────────────────────
let DET={id:0,live:null,timer:null,htimer:null,rtimer:null};
function openDetail(id){ history.replaceState(null,'','dbmon.php?target='+id); showDetail(id); }
function closeDetail(){ if(DET.timer)clearInterval(DET.timer); if(DET.htimer)clearInterval(DET.htimer); if(DET.rtimer)clearInterval(DET.rtimer); disposeDbSkyline(); DET={id:0,live:null,timer:null,htimer:null,rtimer:null};
  history.replaceState(null,'','dbmon.php'); document.getElementById('detail').style.display='none';
  document.getElementById('fleet').style.display=''; document.getElementById('bn').style.display=''; load(); }
function showDetail(id){
  DET.id=id;
  document.getElementById('fleet').style.display='none'; document.getElementById('bn').style.display='none';
  const d=document.getElementById('detail'); d.style.display='';
  d.innerHTML=`<a class="back" onclick="closeDetail()"><i class="fas fa-arrow-left"></i> All databases</a>
    <h2 id="d-title" style="font-size:20px;margin:0 0 2px;">Loading…</h2>
    <div class="kpis" id="d-kpis"></div>
    <div class="sec" id="repl-sec" style="display:none;"><h2><i class="fas fa-clone" style="color:#3aa0ff;"></i> Replication</h2>
      <div id="repl"></div>
      <div id="repl-drift" style="margin-top:12px;"></div></div>
    <div class="sec"><h2><i class="fas fa-circle-nodes" style="color:#e74c3c;"></i> Deadlock Radar</h2>
      <p class="h">Active sessions as bubbles; a <span style="color:#e74c3c;">red arrow</span> means the source query is <b>blocking</b> the target. Red bubbles are running longer than the slow threshold. Click any bubble to inspect or kill it.</p>
      <div id="radar"><div class="radar-empty"><span class="spin"></span></div></div>
      <div class="qpanel" id="qpanel"></div>
    </div>
    <div class="sec"><h2><i class="fas fa-fire" style="color:#f39c12;"></i> CRUD Heatmap</h2>
      <p class="h">Every table as a tile — <b>brighter = busier</b>, hue from <span style="color:#4da3ff;">read-heavy</span> to <span style="color:#e74c3c;">write-heavy</span>, larger text = more rows. Hover for detail.</p>
      <div id="heat"><div class="radar-empty" style="position:static;padding:30px;"><span class="spin"></span></div></div>
      <div class="hlegend"><span><i style="background:#4da3ff;"></i>read-heavy</span><span><i style="background:#e74c3c;"></i>write-heavy</span><span><i style="background:#1a2230;"></i>cold/idle</span></div>
    </div>
    <div class="sec"><h2><i class="fas fa-city" style="color:#22d3ee;"></i> Table Storage — Data Skyline
        <button class="btn" style="margin-left:auto;font-size:11px;padding:4px 9px;" onclick="dbSkyFull()"><i class="fas fa-expand"></i> Fullscreen</button></h2>
      <p class="h">Every table as a tower — <b>height = disk size</b>. Drag to orbit; the tables eating the most space stand tallest.</p>
      <div id="db-skyline" style="width:100%;height:330px;border-radius:12px;overflow:hidden;background:radial-gradient(ellipse at 50% 120%,rgba(34,211,238,.08),transparent 70%);"></div>
      <div id="db-skyline-legend" class="hlegend" style="flex-wrap:wrap;"></div>
    </div>
    <div class="sec"><h2><i class="fas fa-code-branch" style="color:#9b59b6;"></i> Schema Drift
        <button class="btn" style="margin-left:auto;font-size:11px;padding:4px 9px;" onclick="captureSchema(this)"><i class="fas fa-camera"></i> Capture now</button></h2>
      <p class="h">NEURU fingerprints the schema (tables, columns, types, indexes) and flags any change — a column added, an <code>INT→BIGINT</code>, a new index — even if it was applied by hand and never documented.</p>
      <div id="schema"><div class="radar-empty" style="position:static;padding:20px;"><span class="spin"></span></div></div></div>
    <div class="sec"><h2><i class="fas fa-magnifying-glass-chart" style="color:#2ecc71;"></i> Index Archaeologist &amp; Solution Center
        <button class="btn" style="margin-left:auto;font-size:11px;padding:4px 9px;" onclick="analyzeAI(this)"><i class="fas fa-wand-magic-sparkles"></i> Analyze with AI</button></h2>
      <p class="h">Top queries by total time. A <span style="color:var(--crit);">NO-INDEX</span> badge = full table scan (the disk reads millions of rows). "Analyze with AI" ships these + the schema to your n8n advisor, which posts back index/maintenance recommendations you can apply with one click (gated).</p>
      <div id="advice"></div>
      <div id="queries" style="margin-top:12px;"><div class="radar-empty" style="position:static;padding:20px;"><span class="spin"></span></div></div></div>
    <div class="sec"><h2><i class="fas fa-list" style="color:#4da3ff;"></i> Active sessions &amp; slow queries</h2>
      <div id="plist"></div></div>`;
  pollLive(); pollHeat(); loadSchema(); loadQueries(); loadAdvice(); loadRepl();
  DET.timer=setInterval(pollLive,5000); DET.htimer=setInterval(pollHeat,20000);
  DET.rtimer=setInterval(loadRepl,15000);
}
async function pollLive(){
  if(document.hidden) return;
  const r=await jfetch('dbmon.php?api=live&target='+DET.id+'&_='+Date.now(),null,16000);
  if(!r){ document.getElementById('radar').innerHTML='<div class="radar-empty" style="color:var(--warn);">Probe timed out — the database is slow or unreachable. Retrying…</div>'; return; }
  if(!r.ok){ document.getElementById('d-title').innerHTML=esc((r&&r.error)||'error'); document.getElementById('radar').innerHTML=`<div class="radar-empty" style="color:var(--crit);">${esc((r&&r.error)||'connection failed')}</div>`; return; }
  DET.live=r;
  const tt=r.target||{}, p=r.probe||{};
  document.getElementById('d-title').innerHTML=`${esc(tt.name||'')} <span style="font-size:12px;color:#8a93a3;font-weight:400;">${esc(tt.engine||'')} · ${esc(tt.transport||'')} · ${esc(p.version||'')}</span>`;
  const used=+p.connections||0,max=+p.max_connections||0,pct=max?Math.round(used/max*100):0;
  document.getElementById('d-kpis').innerHTML=
    `<div class="kpi"><div class="n" style="color:${clr(pct)}">${used}/${max||'?'}</div><div class="l">connections</div></div>
     <div class="kpi"><div class="n">${esc(p.threads_running)}</div><div class="l">running</div></div>
     <div class="kpi"><div class="n" style="color:${(r.locks||[]).length?'var(--crit)':'var(--ok)'}">${(r.locks||[]).length}</div><div class="l">lock waits</div></div>
     <div class="kpi"><div class="n" style="color:${(r.slow||[]).length?'var(--warn)':'var(--ok)'}">${(r.slow||[]).length}</div><div class="l">slow (≥${r.slow_threshold}s)</div></div>
     ${p.db_bytes!=null?`<div class="kpi"><div class="n">${fmtB(p.db_bytes)}</div><div class="l">data size</div></div>`:''}
     <div class="kpi"><div class="n">${dur(p.uptime_s)}</div><div class="l">uptime</div></div>`;
  renderRadar(r); renderPlist(r);
}
function renderRadar(r){
  const box=document.getElementById('radar'); const W=box.clientWidth||800,H=400,cx=W/2,cy=H/2,R=Math.min(W,H)/2-72;
  const locks=r.locks||[]; const lockPids=new Set(); locks.forEach(l=>{lockPids.add(String(l.waiting_pid));lockPids.add(String(l.blocking_pid));});
  let procs=(r.processlist||[]).filter(p=>String(p.query||'').trim()!=='' || lockPids.has(String(p.pid)));
  // ensure lock participants present even if idle-in-transaction
  procs=procs.slice(0,26);
  if(!procs.length){ box.innerHTML='<div class="radar-empty"><i class="fas fa-circle-check" style="margin-right:8px;color:var(--ok);"></i> No active sessions — all calm.</div>'; return; }
  const slowSet=new Set((r.slow||[]).map(s=>String(s.pid)));
  const blockSet=new Set(locks.map(l=>String(l.blocking_pid)));
  const pos={}; procs.forEach((p,i)=>{ const a=(i/procs.length)*Math.PI*2-Math.PI/2; pos[String(p.pid)]={x:cx+R*Math.cos(a),y:cy+R*Math.sin(a)}; });
  let svg='<svg><defs><marker id="ar" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="#e74c3c"/></marker></defs>';
  locks.forEach(l=>{ const a=pos[String(l.blocking_pid)],b=pos[String(l.waiting_pid)]; if(a&&b) svg+=`<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="#e74c3c" stroke-width="2" stroke-dasharray="5 4" marker-end="url(#ar)"><animate attributeName="stroke-dashoffset" from="18" to="0" dur="0.6s" repeatCount="indefinite"/></line>`; });
  svg+='</svg>';
  let bubbles='';
  procs.forEach(p=>{ const ppid=String(p.pid); const cls=slowSet.has(ppid)?'slow':(blockSet.has(ppid)?'block':''); const pp=pos[ppid];
    bubbles+=`<div class="qbub ${cls}" style="left:${pp.x}px;top:${pp.y}px;" onclick='showQ(${JSON.stringify(p)})' title="${esc((p.query||'').slice(0,120))}">
      <div class="pid">#${esc(p.pid)}</div><div class="t">${esc(p.secs)}s · ${esc((p.command||p.state||'').slice(0,10))}</div></div>`; });
  box.innerHTML=svg+bubbles;
}
function showQ(p){
  const el=document.getElementById('qpanel'); el.style.display='block';
  el.innerHTML=`<div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;">
      <div style="font-size:13px;"><b>PID ${esc(p.pid)}</b> &middot; ${esc(p.user||'')}${p.db?(' @ '+esc(p.db)):''} &middot; ${esc(p.secs)}s &middot; ${esc(p.state||p.command||'')}</div>
      <button class="kbtn" onclick="killQ(${+p.pid})"><i class="fas fa-skull"></i> Kill session</button></div>
    <pre>${esc(p.query||'(no query text)')}</pre>`;
}
async function killQ(pid){
  if(!confirm('KILL session #'+pid+' on this database?\n\nThis terminates the running query/connection. This is logged.')) return;
  const r=await fetch('dbmon.php?api=kill',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:DET.id,pid})}).then(r=>r.json()).catch(()=>({ok:false,error:'request failed'}));
  if(!r.ok) alert('Kill failed:\n'+(r.error||'unknown')); else { document.getElementById('qpanel').style.display='none'; pollLive(); }
}
function renderPlist(r){
  const pl=r.processlist||[];
  if(!pl.length){ document.getElementById('plist').innerHTML='<div style="color:#5a6472;padding:12px;text-align:center;">No active sessions.</div>'; return; }
  const slowSet=new Set((r.slow||[]).map(s=>String(s.pid)));
  document.getElementById('plist').innerHTML=`<table class="pl"><thead><tr><th>PID</th><th>User</th><th>DB</th><th>State</th><th>Time</th><th>Query</th><th></th></tr></thead><tbody>`+
    pl.slice(0,60).map(p=>`<tr style="${slowSet.has(String(p.pid))?'background:rgba(231,76,60,.07);':''}">
      <td><b>${esc(p.pid)}</b></td><td>${esc(p.user||'')}</td><td>${esc(p.db||'')}</td><td>${esc(p.state||p.command||'')}</td>
      <td style="color:${(+p.secs>=r.slow_threshold)?'var(--crit)':'#bcd'};">${esc(p.secs)}s</td>
      <td class="qx" title="${esc(p.query||'')}">${esc((p.query||'').slice(0,140))}</td>
      <td><button class="kbtn" onclick="killQ(${+p.pid})" title="Kill"><i class="fas fa-skull"></i></button></td></tr>`).join('')+`</tbody></table>`;
}
async function pollHeat(){
  if(document.hidden) return;
  const r=await jfetch('dbmon.php?api=heatmap&target='+DET.id+'&_='+Date.now(),null,16000);
  const box=document.getElementById('heat'); if(!box) return;
  if(!r||!r.ok){ box.innerHTML=`<div class="radar-empty" style="position:static;padding:20px;color:#8a93a3;">${esc((r&&r.error)||'no data')}</div>`; return; }
  const tbl=(r.tables||[]); if(!tbl.length){ box.innerHTML='<div class="radar-empty" style="position:static;padding:20px;color:#8a93a3;">No user tables found.</div>'; return; }
  const maxAct=Math.max(1,...tbl.map(t=>(+t.reads)+(+t.writes))); const maxRows=Math.max(1,...tbl.map(t=>+t.rows||0));
  box.innerHTML='<div class="hmgrid">'+tbl.slice(0,160).map(t=>{
    const act=(+t.reads)+(+t.writes), intensity=act/maxAct, wfrac=act?(+t.writes/act):0;
    // hue: blue (read) → red (write); brightness by intensity (min floor so cold tiles are visible)
    const b=0.14+0.86*Math.sqrt(intensity);
    const rC=Math.round(40+ (wfrac)*200*b + 10), gC=Math.round(30+ (1-Math.abs(wfrac-0.5)*2)*60*b), bC=Math.round(40+ (1-wfrac)*200*b + 10);
    const fs=8.5+ (Math.sqrt((+t.rows||0)/maxRows))*4;
    const tip=`${t.schema}.${t.name}\nreads ${fmtN(t.reads)} · writes ${fmtN(t.writes)} · rows ${fmtN(t.rows)} · ${fmtB(t.bytes)}`;
    return `<div class="hcell" style="background:rgb(${rC},${gC},${bC});" title="${esc(tip)}"><span style="font-size:${fs.toFixed(1)}px;">${esc(t.name.slice(0,14))}</span></div>`;
  }).join('')+'</div>';
  buildDbSkyline(tbl);
}
// ── Data Skyline (three.js): one tower per table, height = disk bytes ──────────
let DBSKY=null;
function dbSkyFull(){ const el=document.getElementById('db-skyline'); if(!el)return;
  if(document.fullscreenElement){ document.exitFullscreen(); return; }
  Promise.resolve((el.requestFullscreen||el.webkitRequestFullscreen||function(){}).call(el))
    .then(()=>{ const bg=document.getElementById('nm-netbg'); if(bg) el.appendChild(bg); })  // particles behind the towers (z-index:-1)
    .catch(()=>{}); }
document.addEventListener('fullscreenchange',()=>{
  if(!document.fullscreenElement){ const bg=document.getElementById('nm-netbg'); if(bg && bg.parentNode!==document.body) document.body.appendChild(bg); }
  if(DBSKY&&DBSKY.resize) setTimeout(DBSKY.resize,80);
});
function disposeDbSkyline(){ if(DBSKY){ try{ cancelAnimationFrame(DBSKY.raf); DBSKY.rnd.dispose(); DBSKY.host.innerHTML=''; }catch(e){} DBSKY=null; } }
function buildDbSkyline(tables){
  const host=document.getElementById('db-skyline'); if(!host) return;
  const T=(tables||[]).filter(t=>+t.bytes>0).sort((a,b)=>b.bytes-a.bytes).slice(0,60);
  const leg=document.getElementById('db-skyline-legend');
  if(leg) leg.innerHTML=T.slice(0,8).map(t=>`<span><i style="background:#22d3ee;"></i>${esc(t.name.slice(0,16))} · ${fmtB(t.bytes)}</span>`).join('');
  if(!window.THREE){ host.innerHTML='<div class="radar-empty" style="position:static;padding:20px;color:#8a93a3;">3D view unavailable.</div>'; return; }
  if(!T.length){ host.innerHTML='<div class="radar-empty" style="position:static;padding:20px;color:#8a93a3;">No table sizes reported.</div>'; return; }
  if(DBSKY) return;   // build once per detail-open (table sizes change slowly) — avoid a 20s rebuild flicker
  disposeDbSkyline();
  const W=host.clientWidth||600, H=host.clientHeight||330;
  const scene=new THREE.Scene(), cam=new THREE.PerspectiveCamera(46,W/H,0.1,2000); cam.position.set(0,26,48);
  const rnd=new THREE.WebGLRenderer({antialias:true,alpha:true}); rnd.setSize(W,H); rnd.setPixelRatio(Math.min(2,devicePixelRatio)); host.appendChild(rnd.domElement);
  scene.add(new THREE.AmbientLight(0x8899bb,0.95)); const dl=new THREE.DirectionalLight(0xffffff,0.9); dl.position.set(20,40,20); scene.add(dl);
  const ctrl=new THREE.OrbitControls(cam,rnd.domElement); ctrl.enableDamping=true; ctrl.maxPolarAngle=Math.PI*0.49; ctrl.minDistance=18; ctrl.maxDistance=110;
  scene.add(new THREE.GridHelper(90,22,0x22314a,0x162032));
  const maxB=Math.max(...T.map(t=>+t.bytes),1), n=T.length, cols=Math.ceil(Math.sqrt(n)), gap=7, towers=[];
  T.forEach((t,i)=>{
    const h=Math.max(1.2, Math.pow(t.bytes/maxB,0.5)*24);
    const x=((i%cols)-(cols-1)/2)*gap, z=(Math.floor(i/cols)-(Math.ceil(n/cols)-1)/2)*gap;
    const wf=(+t.reads+ +t.writes)?(+t.writes/(+t.reads + +t.writes)):0.3;   // hue read→write
    const col=new THREE.Color().setHSL(0.58-0.5*wf,0.7,0.55);
    const m=new THREE.Mesh(new THREE.BoxGeometry(3.6,h,3.6), new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:0.28,metalness:0.4,roughness:0.35,transparent:true,opacity:0.92}));
    m.position.set(x,h/2,z); m.scale.y=0.01; scene.add(m); towers.push(m);
    const cv=document.createElement('canvas'); cv.width=256; cv.height=64; const g=cv.getContext('2d');
    g.fillStyle='#e6e9ee'; g.font='bold 24px Segoe UI,sans-serif'; g.textAlign='center'; g.fillText(t.name.slice(0,16),128,28);
    g.fillStyle='#9fd6e8'; g.font='19px Segoe UI'; g.fillText(fmtB(t.bytes),128,52);
    const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:new THREE.CanvasTexture(cv),transparent:true})); sp.scale.set(9,2.25,1); sp.position.set(x,h+2.4,z); scene.add(sp);
  });
  let tk=0; function loop(){ DBSKY.raf=requestAnimationFrame(loop); tk+=0.016; towers.forEach(m=>{ if(m.scale.y<1)m.scale.y=Math.min(1,m.scale.y+0.06); m.material.emissiveIntensity=0.22+0.1*Math.sin(tk*1.5+m.position.x); }); ctrl.update(); rnd.render(scene,cam); }
  DBSKY={host,rnd,cam,raf:0,resize(){ const w=host.clientWidth||600,h2=host.clientHeight||330; cam.aspect=w/h2; cam.updateProjectionMatrix(); rnd.setSize(w,h2); }}; loop();
}
function fmtN(n){ n=+n||0; if(n>=1e9)return (n/1e9).toFixed(1)+'B'; if(n>=1e6)return (n/1e6).toFixed(1)+'M'; if(n>=1e3)return (n/1e3).toFixed(1)+'k'; return ''+n; }
function fmtB(n){ n=+n||0; const u=['B','KB','MB','GB','TB']; let i=0; while(n>=1024&&i<u.length-1){n/=1024;i++;} return n.toFixed(i?1:0)+' '+u[i]; }

async function loadSchema(){
  const r=await jfetch('dbmon.php?api=schema&target='+DET.id+'&_='+Date.now(),null,12000);
  const box=document.getElementById('schema'); if(!box) return;
  if(!r||!r.ok){ box.innerHTML='<div class="radar-empty" style="position:static;padding:16px;color:#8a93a3;">No schema snapshot yet.</div>'; return; }
  const snap=r.snapshot, drifts=r.drifts||[];
  let h='';
  if(snap) h+=`<div style="font-size:12px;color:#8a93a3;margin-bottom:10px;"><i class="fas fa-fingerprint"></i> ${snap.item_count} schema objects · baseline ${window.nmLocal?window.nmLocal(snap.captured_at):esc(snap.captured_at)} · <span style="font-family:monospace;">${esc((snap.schema_hash||'').slice(0,10))}</span></div>`;
  if(!drifts.length){ h+='<div style="color:var(--ok);font-size:13px;"><i class="fas fa-circle-check"></i> No drift detected — schema matches the baseline.</div>'; box.innerHTML=h; return; }
  h+=drifts.map((d,i)=>{
    const chips=(d.changes||[]).slice(0,40).map(c=>{
      const col=c.kind==='added'?'#2ecc71':(c.kind==='removed'?'#e74c3c':'#f39c12');
      const sign=c.kind==='added'?'+':(c.kind==='removed'?'−':'~');
      const detail=c.kind==='changed'?`${esc(c.item)}: ${esc(c.from)} → ${esc(c.to)}`:`${esc(c.item)}${c.to?(' = '+esc(c.to)):(c.from?(' = '+esc(c.from)):'')}`;
      return `<div style="font-size:11.5px;font-family:Consolas,monospace;color:${col};padding:2px 0;">${sign} ${detail}</div>`;
    }).join('');
    return `<div style="border-left:3px solid #9b59b6;padding:8px 12px;margin-bottom:10px;background:rgba(155,89,182,.06);border-radius:0 8px 8px 0;">
      <div style="display:flex;justify-content:space-between;gap:10px;cursor:pointer;" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
        <b style="font-size:13px;">${esc(d.summary)}</b><span style="color:#8a93a3;font-size:12px;">${window.nmLocal?window.nmLocal(d.detected_at):esc(d.detected_at)} <i class="fas fa-caret-down"></i></span></div>
      <div style="display:${i===0?'block':'none'};margin-top:7px;">${chips}</div></div>`;
  }).join('');
  box.innerHTML=h;
}
async function captureSchema(btn){
  const old=btn.innerHTML; btn.disabled=true; btn.innerHTML='<span class="spin"></span> capturing…';
  const r=await fetch('dbmon.php?api=schema_capture',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:DET.id})}).then(r=>r.json()).catch(()=>({ok:false,error:'request failed'}));
  btn.disabled=false; btn.innerHTML=old;
  if(!r.ok){ alert('Capture failed:\n'+(r.error||'unknown')); return; }
  if(r.skipped) alert('Snapshot is current ('+r.skipped+').'); else if(r.changed) alert('Schema drift detected: '+(r.summary||'')); else if(r.baseline) alert('Baseline captured ✓'); else alert('No change — schema matches the last snapshot.');
  loadSchema();
}

async function loadQueries(){
  const r=await jfetch('dbmon.php?api=queries&target='+DET.id+'&_='+Date.now(),null,14000);
  const box=document.getElementById('queries'); if(!box) return;
  if(!r||!r.ok){ box.innerHTML=`<div class="radar-empty" style="position:static;padding:16px;color:#8a93a3;">${esc((r&&r.error)||'query stats unavailable')}</div>`; return; }
  const q=r.queries||[]; if(!q.length){ box.innerHTML='<div class="radar-empty" style="position:static;padding:16px;color:#8a93a3;">No query statistics yet.</div>'; return; }
  box.innerHTML=`<div style="font-size:11px;color:#8a93a3;margin-bottom:6px;">source: ${esc(r.source||'')}</div><table class="pl"><thead><tr><th>Query</th><th>Calls</th><th>Total</th><th>Avg</th><th>Rows examined</th><th></th></tr></thead><tbody>`+
    q.slice(0,25).map(x=>`<tr>
      <td class="qx" title="${esc(x.query||'')}">${esc((x.query||'').slice(0,120))}</td>
      <td>${fmtN(x.calls)}</td><td><b>${esc(x.total_s)}s</b></td><td>${esc(x.avg_ms)}ms</td>
      <td>${fmtN(x.rows_examined)}</td>
      <td>${x.no_index?'<span class="kbtn" style="cursor:default;background:rgba(231,76,60,.18);">NO-INDEX</span>':''}</td></tr>`).join('')+`</tbody></table>`;
}
async function loadAdvice(){
  const r=await jfetch('dbmon.php?api=advice&target='+DET.id+'&_='+Date.now(),null,10000);
  const box=document.getElementById('advice'); if(!box) return;
  const A=((r&&r.advice)||[]).filter(a=>a.status==='proposed');
  if(!A.length){ box.innerHTML=''; return; }
  const rc={low:'#2ecc71',medium:'#f39c12',high:'#e74c3c'};
  box.innerHTML=A.map(a=>{
    const canApply=(a.kind==='index'||a.kind==='maintenance');
    return `<div style="border:1px solid rgba(46,204,113,.3);background:rgba(46,204,113,.05);border-radius:11px;padding:11px 13px;margin-bottom:9px;">
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
        <b style="font-size:13.5px;">${esc(a.title)}</b>
        <span class="eng">${esc(a.kind)}</span>
        <span style="font-size:10px;font-weight:700;color:${rc[a.risk]||'#889'};border:1px solid ${rc[a.risk]||'#889'};border-radius:5px;padding:1px 7px;">risk: ${esc(a.risk)}</span>
        ${a.benefit?`<span style="font-size:11.5px;color:#9fb0c4;">${esc(a.benefit)}</span>`:''}
        <span style="margin-left:auto;font-size:10px;color:#778;">${esc(a.source)}</span></div>
      ${a.rationale?`<div style="font-size:12.5px;color:#cdd6e2;margin-top:6px;">${esc(a.rationale)}</div>`:''}
      ${a.ddl?`<pre style="background:rgba(0,0,0,.45);border:1px solid rgba(255,255,255,.1);border-radius:8px;padding:9px;font-size:12px;color:#cfe;overflow:auto;margin:8px 0 0;white-space:pre-wrap;">${esc(a.ddl)}</pre>`:''}
      <div style="margin-top:9px;display:flex;gap:8px;">
        ${canApply?`<button class="btn" style="background:rgba(46,204,113,.16);border-color:#2ecc71;color:#9cffc7;" onclick="applyAdvice(${a.id},this)"><i class="fas fa-bolt"></i> Apply</button>`
                  :`<span style="font-size:11.5px;color:#8a93a3;align-self:center;">apply by hand (review first)</span>`}
        <button class="btn" style="background:transparent;border-color:var(--border);color:#bcc8d6;" onclick="dismissAdvice(${a.id})"><i class="fas fa-ban"></i> Dismiss</button>
      </div></div>`;
  }).join('');
}
async function analyzeAI(btn){
  const old=btn.innerHTML; btn.disabled=true; btn.innerHTML='<span class="spin"></span> shipping…';
  const r=await fetch('dbmon.php?api=advice_analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:DET.id})}).then(r=>r.json()).catch(()=>({ok:false,error:'request failed'}));
  btn.disabled=false; btn.innerHTML=old;
  alert(r.ok?('✓ Sent to the AI advisor (HTTP '+(r.http||'?')+').\n\n'+(r.hint||'')):('Could not analyze:\n'+(r.error||r.reply||'unknown')+'\n\n'+(r.hint||'')));
  setTimeout(loadAdvice,3000);
}
async function applyAdvice(id,btn){
  if(!confirm('Apply this change to the database?\n\nThis runs the statement now. It is logged. Review the SQL above first.')) return;
  const old=btn.innerHTML; btn.disabled=true; btn.innerHTML='<span class="spin"></span> applying…';
  const r=await fetch('dbmon.php?api=advice_apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}).then(r=>r.json()).catch(()=>({ok:false,error:'request failed'}));
  btn.disabled=false; btn.innerHTML=old;
  if(!r.ok) alert('Apply failed:\n'+(r.error||'unknown')); else { loadAdvice(); loadSchema(); }
}
async function dismissAdvice(id){
  await fetch('dbmon.php?api=advice_dismiss',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}); loadAdvice();
}

async function loadRepl(){
  const sec=document.getElementById('repl-sec'); if(!sec) return;
  const r=await jfetch('dbmon.php?api=replication&target='+DET.id+'&_='+Date.now(),null,16000);
  if(!r||!r.ok||(r.role==='standalone'&&!(r.self&&r.self.is_replica)&&!(r.self&&r.self.replicas_connected))){ sec.style.display='none'; return; }
  sec.style.display='';
  const box=document.getElementById('repl'); const s=r.self||{};
  const dot=(ok)=>`<span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:${ok?'var(--ok)':'var(--crit)'};box-shadow:0 0 6px ${ok?'var(--ok)':'var(--crit)'};"></span>`;
  if(r.role==='replica' || s.is_replica){
    const lag=s.seconds_behind, lagc=(lag==null)?'#889':(lag>=r.lag_crit?'var(--crit)':(lag>=r.lag_warn?'var(--warn)':'var(--ok)'));
    const healthy=s.io_running&&s.sql_running;
    let gtidGap='';
    if(r.master&&r.master.ok&&r.master.gtid_executed&&s.gtid_executed){
      const same=(r.master.gtid_executed.trim()===s.gtid_executed.trim());
      gtidGap=`<div class="kv"><span>GTID consistency</span><b style="color:${same?'var(--ok)':'var(--warn)'}">${same?'in sync':'replica behind / diverged'}</b></div>`;
    }
    box.innerHTML=`<div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;font-size:13px;margin-bottom:8px;">
        <span style="padding:5px 12px;border:1px solid var(--border);border-radius:8px;">${esc(r.master&&r.master.name?r.master.name:(s.source_host||'source'))}</span>
        <span style="color:${healthy?'var(--ok)':'var(--crit)'};font-size:20px;">⟶</span>
        <span style="padding:5px 12px;border:1px solid ${healthy?'rgba(46,204,113,.5)':'rgba(231,76,60,.5)'};border-radius:8px;">${esc(r.name)} <b>(replica)</b></span>
        ${lag!=null?`<span style="margin-left:auto;font-size:22px;font-weight:800;color:${lagc};">${lag}s <span style="font-size:11px;color:#8a93a3;font-weight:400;">behind</span></span>`:''}</div>
      <div class="kv"><span>${dot(s.io_running)} IO thread</span><b>${s.io_running?'running':'STOPPED'}</b></div>
      <div class="kv"><span>${dot(s.sql_running)} SQL thread</span><b>${s.sql_running?'running':'STOPPED'}</b></div>
      ${gtidGap}
      ${s.last_error?`<div class="kv" style="color:var(--crit);"><span>Last error</span><b title="${esc(s.last_error)}">${esc(s.last_error.slice(0,60))}</b></div>`:''}
      <button class="btn" style="margin-top:10px;" onclick="loadDrift()"><i class="fas fa-scale-balanced"></i> Compare tables (master ↔ replica)</button>`;
  } else {
    box.innerHTML=`<div style="font-size:13px;">This is a <b>master/source</b> — <b style="color:var(--ok);">${s.replicas_connected!=null?s.replicas_connected:'?'}</b> replica(s) connected.
      ${(s.replicas_connected===0)?'<span style="color:var(--warn);"> No replicas are currently connected.</span>':''}</div>`;
  }
}
async function loadDrift(){
  const box=document.getElementById('repl-drift'); box.innerHTML='<span class="spin"></span> comparing tables (verifying drift with exact counts)…';
  const r=await jfetch('dbmon.php?api=repl_drift&target='+DET.id+'&_='+Date.now(),null,20000);
  if(!r||!r.ok){ box.innerHTML=`<div style="color:var(--crit);font-size:12px;">${esc((r&&r.error)||'compare failed')}</div>`; return; }
  const T=r.tables||[];
  box.innerHTML=`<div style="font-size:11.5px;color:#8a93a3;margin-bottom:6px;">${esc(r.master)} ↔ ${esc(r.replica)} · ${r.drift_count} table(s) differ. ${esc(r.note||'')}</div>
    <table class="pl"><thead><tr><th>Table</th><th>Master</th><th>Replica</th><th>Δ</th><th></th></tr></thead><tbody>`+
    T.slice(0,200).map(t=>{
      const d=t.delta, dc=(t.missing||(d!=null&&d!==0))?'var(--warn)':'var(--ok)';
      const dtxt=t.missing?'missing':(d==null?'—':(d>0?'+':'')+fmtN(d));
      const exBadge=t.exact?' <span title="verified with exact COUNT(*)" style="color:var(--ok);font-size:10px;">✓</span>':'';
      return `<tr style="${(t.missing||(d!=null&&d!==0))?'background:rgba(243,156,18,.06);':''}">
        <td><b>${esc(t.table)}</b>${exBadge}</td><td>${t.master_rows==null?'—':fmtN(t.master_rows)}</td><td>${t.replica_rows==null?'—':fmtN(t.replica_rows)}</td>
        <td style="color:${dc};">${dtxt}</td>
        <td><button class="btn" style="font-size:10px;padding:3px 8px;" onclick="exactCount('${esc(t.table)}',this)">exact</button></td></tr>`;
    }).join('')+`</tbody></table>`;
}
async function exactCount(table,btn){
  const old=btn.innerHTML; btn.disabled=true; btn.innerHTML='<span class="spin"></span>';
  const r=await jfetch('dbmon.php?api=repl_drift&target='+DET.id+'&table='+encodeURIComponent(table)+'&_='+Date.now(),null,30000);
  btn.disabled=false;
  if(!r||!r.ok){ btn.innerHTML=old; alert('Exact count failed:\n'+((r&&r.error)||'unknown')); return; }
  const d=r.delta, ok=(d===0); const cell=btn.closest('tr');
  cell.querySelector('td:nth-child(2)').textContent=r.master_rows==null?'—':fmtN(r.master_rows);
  cell.querySelector('td:nth-child(3)').textContent=r.replica_rows==null?'—':fmtN(r.replica_rows);
  const dtd=cell.querySelector('td:nth-child(4)'); dtd.textContent=d==null?'—':(d>0?'+':'')+fmtN(d); dtd.style.color=ok?'var(--ok)':'var(--crit)';
  btn.innerHTML='✓ exact';
}

// router: ?target=ID → detail, else fleet
(function(){ const t=parseInt(new URLSearchParams(location.search).get('target')||'0',10)||0;
  if(t) showDetail(t); else load();
  document.addEventListener('visibilitychange',()=>{ if(!document.hidden&&DET.id){ pollLive(); } });
})();
</script>
</body>
</html>
