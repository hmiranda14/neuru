<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Cisco Orchestrator (F4). RBAC: 'cisco_orch'. Engine: nm_cisco_orch.php.
// Config backup / version / diff / drift (reuses nm_confmgr) + per-platform
// Safe-Apply (commit-confirm with auto-rollback, modelled on nm_mtfw). Targets
// routers / switches / firewalls; WLC/AireOS controllers are handled in the WiFi
// Control Center (interactive login, not standard IOS). See docs/NEURU_CISCO_SUITE_PLAN.md.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_cisco_orch.php');
include('logger.php');

$api = $_GET['api'] ?? ($_POST['api'] ?? '');
$isPost = ($_SERVER['REQUEST_METHOD'] === 'POST');
if (!checkAccess($conn, 'cisco_orch')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=cisco_orch'); exit;
}
nm_cisco_ensure($conn);
$CSRF = $_SESSION['csrf_token'] ?? ($_SESSION['csrf_token'] = bin2hex(random_bytes(32)));
$uid  = (int)($_SESSION['user_id'] ?? 0) ?: null;

function co_node($conn, int $nid): ?array {
    foreach (nm_cisco_orch_nodes($conn) as $n) if ((int)$n['id'] === $nid) return $n;
    return null;
}

if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');

    // CSRF on all mutating actions
    $mut = in_array($api, ['backup','apply','keep','revert'], true);
    if ($mut) {
        if (!$isPost || !hash_equals($CSRF, (string)($_POST['csrf'] ?? ''))) { echo json_encode(['ok'=>false,'error'=>'bad csrf']); exit; }
    }
    // release the session lock BEFORE any slow SSH/SNMP so one request can't freeze the portal
    // ($CSRF/$uid are already captured in locals; auth is done).
    if (function_exists('session_write_close')) @session_write_close();

    if ($api === 'devices') {
        $out = [];
        foreach (nm_cisco_orch_nodes($conn) as $n) {
            $nid = (int)$n['id'];
            $latest = nm_cisco_orch_latest($conn, $nid);
            $pend = nm_cisco_orch_pending_list($conn, $nid);
            $out[] = [
                'id'=>$nid, 'name'=>$n['display_name'], 'ip'=>$n['ip_address'], 'hw'=>$n['hw_model'],
                'class'=>$n['cisco_class'], 'platform'=>$n['platform'],
                'version'=>$latest? (int)$latest['version'] : 0,
                'backup_at'=>$latest['captured_at'] ?? null,
                'added'=>$latest? (int)$latest['added'] : 0, 'removed'=>$latest? (int)$latest['removed'] : 0,
                'armed'=>count($pend),
            ];
        }
        // WLC nodes are intentionally excluded (managed in WiFi Control Center)
        $wlc = [];
        foreach (nm_cisco_nodes($conn) as $n) if (($n['cisco_class'] ?? '')==='wlc') $wlc[] = $n['display_name'];
        echo json_encode(['ok'=>true, 'devices'=>$out, 'wlc'=>$wlc]); exit;
    }

    if ($api === 'versions') {
        $nid = (int)($_GET['id'] ?? 0);
        echo json_encode(['ok'=>true, 'versions'=>nm_cisco_orch_versions($conn, $nid)]); exit;
    }
    if ($api === 'diff') {
        $nid = (int)($_GET['id'] ?? 0);
        $from = isset($_GET['from']) ? (int)$_GET['from'] : null;
        $to   = isset($_GET['to'])   ? (int)$_GET['to']   : null;
        echo json_encode(nm_cisco_orch_diff($conn, $nid, $from, $to)); exit;
    }
    if ($api === 'config') {
        $cid = (int)($_GET['cid'] ?? 0);
        echo json_encode(['ok'=>true, 'text'=>nm_cisco_orch_config_text($conn, $cid)]); exit;
    }
    if ($api === 'pending') {
        $nid = (int)($_GET['id'] ?? 0);
        echo json_encode(['ok'=>true, 'pending'=>nm_cisco_orch_pending_list($conn, $nid)]); exit;
    }

    if ($api === 'backup') {
        $n = co_node($conn, (int)($_POST['id'] ?? 0));
        if (!$n) { echo json_encode(['ok'=>false,'error'=>'not an orchestrator node']); exit; }
        log_user_action($conn, 'cisco_orch_backup', $n['display_name']);
        echo json_encode(nm_cisco_orch_backup($conn, $n)); exit;
    }

    if ($api === 'dryrun') {   // read-only preview; POST but no side effects (no csrf strictly needed, but harmless)
        $nid = (int)($_POST['id'] ?? $_GET['id'] ?? 0);
        $n = co_node($conn, $nid);
        if (!$n) { echo json_encode(['ok'=>false,'error'=>'not an orchestrator node']); exit; }
        $cfg = (string)($_POST['config'] ?? $_GET['config'] ?? '');
        $window = (int)($_POST['window'] ?? $_GET['window'] ?? 5);
        $lines = array_values(array_filter(array_map('rtrim', preg_split('/\r?\n/', $cfg)), fn($l)=>trim($l)!==''));
        $plan = nm_cisco_saf_plan(nm_cisco_orch_platform($n), $lines, $window, 'preview');
        echo json_encode(['ok'=>true, 'plan'=>$plan, 'preview'=>nm_cisco_saf_preview($plan), 'lines'=>count($lines)]); exit;
    }

    if ($api === 'apply') {
        $n = co_node($conn, (int)($_POST['id'] ?? 0));
        if (!$n) { echo json_encode(['ok'=>false,'error'=>'not an orchestrator node']); exit; }
        $cfg = (string)($_POST['config'] ?? '');
        $window = (int)($_POST['window'] ?? 5);
        $lines = array_values(array_filter(array_map('rtrim', preg_split('/\r?\n/', $cfg)), fn($l)=>trim($l)!==''));
        log_user_action($conn, 'cisco_orch_apply', $n['display_name'].' ('.count($lines).' lines)');
        echo json_encode(nm_cisco_saf_apply($conn, $n, $lines, $window, $uid)); exit;
    }

    if ($api === 'keep' || $api === 'revert') {
        $n = co_node($conn, (int)($_POST['id'] ?? 0));
        if (!$n) { echo json_encode(['ok'=>false,'error'=>'not an orchestrator node']); exit; }
        $token = (string)($_POST['token'] ?? '');
        log_user_action($conn, 'cisco_orch_'.$api, $n['display_name']);
        echo json_encode(nm_cisco_saf_finalize($conn, $n, $token, $api)); exit;
    }

    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}

log_user_action($conn, 'view_page', 'cisco_orch.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cisco Orchestrator | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cisco:#00bceb; --orch:#b388ff; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.14; }
.wrap{ max-width:1360px; margin:0 auto; padding:18px 20px 44px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.btn{ background:rgba(179,136,255,.14); border:1px solid rgba(179,136,255,.4); color:#dcc9ff; border-radius:9px; padding:8px 14px; font-size:13px; cursor:pointer; }
.btn:hover{ background:rgba(179,136,255,.25); } .btn.ghost{ background:transparent; border-color:var(--border); color:#aab; } .btn.sm{ padding:3px 9px; font-size:11px; }
.btn.danger{ background:rgba(231,76,60,.16); border-color:rgba(231,76,60,.45); color:#f2a49b; } .btn.ok{ background:rgba(46,204,113,.16); border-color:rgba(46,204,113,.45); color:#8fe6b4; }
.btn:disabled{ opacity:.5; cursor:not-allowed; }
.muted{ color:#7c828c; font-size:12px; } .mono{ font-family:'SFMono-Regular',Consolas,monospace; }
.grid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(340px,1fr)); gap:14px; }
.dcard{ padding:14px 16px; } .dcard .nm{ font-size:15px; font-weight:800; } .dcard .ip{ font-size:11px; color:#8a909a; }
.pf{ font-size:9.5px; font-weight:800; text-transform:uppercase; letter-spacing:.4px; padding:3px 8px; border-radius:20px; background:rgba(179,136,255,.16); color:#d3bcff; }
.kv{ display:flex; justify-content:space-between; font-size:12px; padding:4px 0; border-bottom:1px solid rgba(255,255,255,.05); }
.acts{ display:flex; gap:7px; margin-top:10px; flex-wrap:wrap; }
.drawer-bg{ position:fixed; inset:0; background:rgba(0,0,0,.55); z-index:80; display:none; }
.drawer{ position:fixed; top:0; right:0; height:100%; width:640px; max-width:97vw; background:#0c1015; border-left:1px solid var(--border); z-index:81; transform:translateX(100%); transition:transform .28s; overflow:auto; padding:20px 22px; }
.drawer.open{ transform:translateX(0); }
textarea{ width:100%; min-height:150px; background:rgba(255,255,255,.05); color:#e6e9ee; border:1px solid var(--border); border-radius:9px; padding:10px 12px; font-family:monospace; font-size:12.5px; resize:vertical; }
pre{ background:#0a0e14; border:1px solid var(--border); border-radius:9px; padding:12px; font-size:12px; overflow:auto; max-height:320px; white-space:pre-wrap; }
.diff .add{ color:#8fe6b4; } .diff .del{ color:#f2a49b; } .diff .hdr{ color:#8fb7ff; }
.sec{ font-size:12px; text-transform:uppercase; letter-spacing:.6px; color:#d3bcff; margin:16px 0 8px; font-weight:700; }
.warn{ background:rgba(231,76,60,.1); border:1px solid rgba(231,76,60,.35); border-radius:10px; padding:11px 13px; font-size:12.5px; color:#f6b9b2; }
.row{ display:flex; gap:10px; align-items:center; } .row label{ font-size:12px; color:#9aa1ab; }
input[type=number]{ width:70px; background:rgba(255,255,255,.06); color:#e6e9ee; border:1px solid var(--border); border-radius:7px; padding:6px 8px; }
.armed{ background:rgba(243,156,18,.1); border:1px solid rgba(243,156,18,.35); border-radius:10px; padding:11px 13px; margin-top:10px; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fa-solid fa-sliders"></i> Cisco Orchestrator', '',
    'Config backup · diff · drift · Safe-Apply', 'fa-solid fa-sliders',
    '<button class="btn ghost sm" onclick="backupAll(this)"><i class="fas fa-cloud-arrow-down"></i> Backup all</button>'); ?>

<div class="glass card" style="padding:11px 16px;"><div class="muted"><i class="fas fa-circle-info"></i>
  Config backup/versioning reuses the Config Manager pipeline. <b>Safe-Apply</b> arms a native
  commit-confirm (IOS/IOS-XE/ASA <span class="mono">reload in</span>, IOS-XR <span class="mono">commit confirmed</span>,
  NX-OS <span class="mono">checkpoint</span>) so a bad change auto-reverts — <b>Dry-run</b> shows the exact
  sequence first. AireOS controllers are managed in the <a href="wifi.php">WiFi Control Center</a>, not here.</div></div>

<div id="empty" class="glass card" style="display:none;"><div class="muted">No Cisco router/switch/firewall detected yet.</div></div>
<div id="wlcnote" class="glass card" style="display:none;padding:10px 15px;"></div>
<div class="grid" id="grid"><div class="muted">Loading…</div></div>

<div class="drawer-bg" id="dbg" onclick="closeDrawer()"></div>
<div class="drawer glass" id="drawer"></div>

<script>
const CSRF=<?= json_encode($CSRF) ?>;
let DEV=[];
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function post(api,body){ body=body||{}; body.api=api; body.csrf=CSRF; return fetch('cisco_orch.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:Object.entries(body).map(([k,v])=>k+'='+encodeURIComponent(v)).join('&')}).then(r=>r.json()).catch(()=>null); }
function get(qs){ return fetch('cisco_orch.php?'+qs).then(r=>r.json()).catch(()=>null); }

async function load(){
  const r=await get('api=devices'); if(!r||!r.ok) return;
  DEV=r.devices;
  const wn=document.getElementById('wlcnote');
  if(r.wlc&&r.wlc.length){ wn.style.display='block'; wn.innerHTML=`<span class="muted"><i class="fas fa-wifi"></i> ${r.wlc.length} controller(s) (${r.wlc.map(esc).join(', ')}) are managed in the <a href="wifi.php">WiFi Control Center</a> — AireOS uses an interactive login, not standard IOS.</span>`; }
  const g=document.getElementById('grid');
  if(!DEV.length){ document.getElementById('empty').style.display='block'; g.innerHTML=''; return; }
  g.innerHTML=DEV.map(d=>`<div class="glass dcard">
    <div style="display:flex;align-items:flex-start;gap:8px;">
      <div style="flex:1;min-width:0"><div class="nm">${esc(d.name)}</div><div class="ip">${esc(d.ip||'')} · ${esc(d.hw||'')||esc(d.class)}</div></div>
      <span class="pf">${esc(d.platform)}</span>
    </div>
    <div style="margin-top:9px">
      <div class="kv"><span>Config version</span><b>${d.version||'—'}</b></div>
      <div class="kv"><span>Last backup</span><b>${d.backup_at?esc(d.backup_at.slice(0,16)):'never'}</b></div>
      <div class="kv"><span>Last change</span><b>${d.version>1?('+'+d.added+' / -'+d.removed):'—'}</b></div>
      ${d.armed?`<div class="kv"><span style="color:#f3c37b">⚠ Armed changes</span><b style="color:#f3c37b">${d.armed}</b></div>`:''}
    </div>
    <div class="acts">
      <button class="btn sm" onclick="backupOne(${d.id},this)"><i class="fas fa-cloud-arrow-down"></i> Backup</button>
      <button class="btn ghost sm" onclick="openVersions(${d.id})"><i class="fas fa-clock-rotate-left"></i> Versions</button>
      <button class="btn ghost sm" onclick="openApply(${d.id})"><i class="fas fa-sliders"></i> Safe-Apply</button>
      <a class="btn ghost sm" href="config_mgr.php"><i class="fas fa-file-code"></i> Config Mgr</a>
    </div>
  </div>`).join('');
}
function dev(id){ return DEV.find(d=>d.id==id); }

async function backupOne(id,btn){ const o=btn.innerHTML; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i>'; btn.disabled=true;
  const r=await post('backup',{id}); btn.innerHTML=o; btn.disabled=false;
  if(!r||!r.ok){ alert('Backup failed: '+((r&&r.error)||'?')); return; }
  alert(r.changed?('New version v'+r.version+' (+'+(r.added||0)+' / -'+(r.removed||0)+')'):'No change (still v'+r.version+')'); load();
}
async function backupAll(btn){ const o=btn.innerHTML; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Backing up…'; btn.disabled=true;
  for(const d of DEV){ await post('backup',{id:d.id}); } btn.innerHTML=o; btn.disabled=false; load(); }

// ── versions / diff ───────────────────────────────────────────────────────────
async function openVersions(id){
  const d=dev(id); const dr=document.getElementById('drawer'); document.getElementById('dbg').style.display='block'; dr.classList.add('open');
  dr.innerHTML='<div class="muted">Loading…</div>';
  const r=await get('api=versions&id='+id);
  const vs=(r&&r.versions)||[];
  let rows=vs.map(v=>`<div class="kv"><span>v${v.version} · ${esc((v.captured_at||'').slice(0,16))}</span>
     <span>${v.version>1?('+'+v.added+'/-'+v.removed):'first'} <button class="btn ghost sm" onclick="viewConfig(${v.id},${v.version})">view</button>
     ${v.version>1?`<button class="btn ghost sm" onclick="viewDiff(${id},${v.version-1},${v.version})">diff</button>`:''}</span></div>`).join('');
  dr.innerHTML=`<div style="display:flex;align-items:center;gap:10px"><div style="flex:1;font-size:17px;font-weight:800">${esc(d.name)} — versions</div><button class="btn sm ghost" onclick="closeDrawer()">✕</button></div>
    <div class="sec">History</div>${rows||'<div class="muted">No backups yet — hit Backup.</div>'}
    <div id="viewer"></div>`;
}
async function viewConfig(cid,ver){ const r=await get('api=config&cid='+cid); document.getElementById('viewer').innerHTML=`<div class="sec">Config v${ver}</div><pre>${esc((r&&r.text)||'(empty)')}</pre>`; }
async function viewDiff(id,from,to){ const r=await get('api=diff&id='+id+'&from='+from+'&to='+to);
  if(!r||!r.ok){ document.getElementById('viewer').innerHTML='<div class="muted">No diff.</div>'; return; }
  const html=(r.diff||'').split('\n').map(l=>{ const c=l[0]; const cl=c==='+'?'add':c==='-'?'del':(c==='@'?'hdr':''); return `<span class="${cl}">${esc(l)}</span>`; }).join('\n');
  document.getElementById('viewer').innerHTML=`<div class="sec">Diff v${from} → v${to} (+${r.added}/-${r.removed})</div><pre class="diff">${html}</pre>`;
}

// ── Safe-Apply ────────────────────────────────────────────────────────────────
async function openApply(id){
  const d=dev(id); const dr=document.getElementById('drawer'); document.getElementById('dbg').style.display='block'; dr.classList.add('open');
  dr.innerHTML=`<div style="display:flex;align-items:center;gap:10px"><div style="flex:1;font-size:17px;font-weight:800">${esc(d.name)} — Safe-Apply <span class="pf">${esc(d.platform)}</span></div><button class="btn sm ghost" onclick="closeDrawer()">✕</button></div>
    <div class="sec">Configuration lines</div>
    <textarea id="cfg" placeholder="interface GigabitEthernet0/1&#10; description NEURU-managed&#10; no shutdown"></textarea>
    <div class="row" style="margin-top:10px">
      <label>Rollback window</label><input type="number" id="win" value="5" min="1" max="60"> <span class="muted">min</span>
      <button class="btn" style="margin-left:auto" onclick="dryrun(${id})"><i class="fas fa-eye"></i> Dry-run preview</button>
    </div>
    <div id="preview"></div>
    <div id="armedbox"></div>`;
  refreshArmed(id);
}
async function dryrun(id){
  const cfg=document.getElementById('cfg').value, win=document.getElementById('win').value;
  const r=await post('dryrun',{id,config:cfg,window:win});
  if(!r||!r.ok){ document.getElementById('preview').innerHTML='<div class="muted">Nothing to preview.</div>'; return; }
  const timed=r.plan.timed;
  document.getElementById('preview').innerHTML=`<div class="sec">Dry-run — ${r.lines} line(s), method ${r.plan.method.toUpperCase()}</div>
    <pre>${esc(r.preview)}</pre>
    <div class="warn"><b>⚠ Live apply is experimental.</b> Interactive <span class="mono">reload in</span> confirm prompts vary by IOS train — <b>verify on a lab device first</b>. ${timed?`If you don't Keep within the window, the device auto-reverts (anti-lockout).`:`NX-OS has no auto-timer — you must Keep or Revert manually.`}</div>
    <div class="row" style="margin-top:10px"><label><input type="checkbox" id="ack"> I understand — arm live apply</label>
      <button class="btn danger" style="margin-left:auto" onclick="applyLive(${id})"><i class="fas fa-bolt"></i> Apply (armed)</button></div>`;
}
async function applyLive(id){
  if(!document.getElementById('ack').checked){ alert('Tick the acknowledgement first.'); return; }
  const cfg=document.getElementById('cfg').value, win=document.getElementById('win').value;
  const r=await post('apply',{id,config:cfg,window:win});
  if(!r||!r.ok){ alert('Apply failed: '+((r&&r.error)||'?')+(r&&r.output?('\n\n'+r.output):'')); return; }
  alert('Armed (token '+r.token+'). '+(r.timed?'Keep it before the window expires or it auto-reverts.':'Keep or Revert manually.')); refreshArmed(id);
}
async function refreshArmed(id){
  const r=await get('api=pending&id='+id); const box=document.getElementById('armedbox'); if(!box) return;
  const ps=(r&&r.pending)||[];
  box.innerHTML=ps.length? '<div class="sec">Armed changes</div>'+ps.map(p=>`<div class="armed"><div style="display:flex;align-items:center;gap:8px">
     <div style="flex:1"><b class="mono">${esc(p.token)}</b> · ${esc(p.method)} · ${esc((p.created_at||'').slice(11,16))}${p.window_min?(' · '+p.window_min+'m'):''}</div>
     <button class="btn ok sm" onclick="finalize(${id},'${esc(p.token)}','keep',this)"><i class="fas fa-check"></i> Keep</button>
     <button class="btn danger sm" onclick="finalize(${id},'${esc(p.token)}','revert',this)"><i class="fas fa-rotate-left"></i> Revert now</button></div></div>`).join('') : '';
}
async function finalize(id,token,action,btn){ const o=btn.innerHTML; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i>'; btn.disabled=true;
  const r=await post(action,{id,token}); btn.innerHTML=o; btn.disabled=false;
  if(!r||!r.ok){ alert(action+' failed: '+((r&&r.error)||'?')); return; }
  alert('Change '+r.status+'.'); refreshArmed(id); load();
}
function closeDrawer(){ document.getElementById('drawer').classList.remove('open'); document.getElementById('dbg').style.display='none'; }
load();
</script>
</body></html>
