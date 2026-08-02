<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — NetAIObot history. What the agent did, per device: every session with its
// full Observe→Think→Act→Result timeline (executed commands in RED) + actions taken.
// Read-only audit view. Perm: 'aiopilot'.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');   // applies the configured display tz (UTC storage) via nm_tz_apply
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_aiopilot.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'aiopilot')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'denied']); exit; }
    header('Location: /denied_access.php?page=aiopilot_history'); exit;
}
nm_aip_ensure($conn);

if ($api === 'sessions') {
    header('Content-Type: application/json; charset=utf-8');
    $node = (int)($_GET['node'] ?? 0);
    $w = $node ? " AND s.node_id=$node" : '';
    $r = $conn->query("SELECT s.id,s.node_id,s.trigger_kind,s.status,s.title,s.summary,s.created_at,s.updated_at,n.display_name,
                              (SELECT COUNT(*) FROM nm_aip_events e WHERE e.session_id=s.id) ev,
                              (SELECT COUNT(*) FROM nm_aip_actions a WHERE a.session_id=s.id AND a.status IN ('done','auto')) acts
                       FROM nm_aip_sessions s JOIN nm_nodes n ON n.id=s.node_id
                       WHERE 1=1 $w ORDER BY s.id DESC LIMIT 100");
    echo json_encode(['ok'=>true,'sessions'=>$r ? $r->fetch_all(MYSQLI_ASSOC) : []]); exit;
}
if ($api === 'events') {
    header('Content-Type: application/json; charset=utf-8');
    $sid = (int)($_GET['session'] ?? 0);
    $r = $conn->query("SELECT e.id,e.phase,e.title,e.body,e.created_at,n.display_name
                       FROM nm_aip_events e JOIN nm_nodes n ON n.id=e.node_id
                       WHERE e.session_id=$sid ORDER BY e.id ASC LIMIT 400");
    echo json_encode(['ok'=>true,'events'=>$r ? $r->fetch_all(MYSQLI_ASSOC) : []]); exit;
}

log_user_action($conn, 'view_page', 'aiopilot_history.php');
$nodes = [];
$nr = $conn->query("SELECT DISTINCT n.id,n.display_name FROM nm_aip_sessions s JOIN nm_nodes n ON n.id=s.node_id ORDER BY n.display_name");
while ($nr && $x = $nr->fetch_assoc()) $nodes[] = $x;
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetAIObot History | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --accent:#4da3ff; --ai:#9b6bff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cyan:#22d3ee; --border:rgba(255,255,255,.12); }
*,*::before,*::after{ box-sizing:border-box; } html{ background:#05060f; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#e6e9ee; }
.wrap{ max-width:1280px; margin:0 auto; padding:16px 20px 50px; }
.glass{ background:rgba(255,255,255,.05); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.muted{ color:#8a909a; font-size:12px; } .mono{ font-family:monospace; }
.tgt-sel{ background:rgba(10,16,28,.85); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:7px 12px; font-size:13px; }
.sess{ padding:12px 15px; margin-bottom:10px; cursor:pointer; transition:border-color .15s; }
.sess:hover{ border-color:var(--accent); }
.sess .top{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
.sess .nm{ font-weight:700; } .sess .ti{ color:#aeb6c2; font-size:13px; }
.st{ font-size:10px; font-weight:800; padding:2px 9px; border-radius:20px; text-transform:uppercase; letter-spacing:.5px; }
.st.resolved{ background:rgba(46,204,113,.18); color:#9af3c0; } .st.active{ background:rgba(77,163,255,.18); color:#bcd; }
.st.awaiting_approval{ background:rgba(243,156,18,.2); color:#f3c879; } .st.failed{ background:rgba(231,76,60,.2); color:#ff9c91; }
.st.idle,.st.queued{ background:rgba(155,155,170,.16); color:#bcc; }
.chip{ font-size:10px; color:#8a909a; background:rgba(255,255,255,.05); border:1px solid var(--border); padding:1px 8px; border-radius:20px; }
.tl{ margin-top:12px; display:none; border-top:1px solid var(--border); padding-top:12px; }
.tl.open{ display:block; }
.ev{ border-left:3px solid #444; padding:7px 11px; border-radius:0 8px 8px 0; background:rgba(255,255,255,.03); margin-bottom:7px; }
.ev .h{ font-size:12px; font-weight:700; display:flex; gap:8px; align-items:center; }
.ev .b{ font-size:12px; color:#aeb6c2; margin-top:3px; white-space:pre-wrap; line-height:1.45; }
.ev .when{ margin-left:auto; font-size:10px; color:#667; font-weight:400; }
.ev.observe{ border-left-color:var(--cyan); } .ev.observe .h{ color:#7fe6f5; }
.ev.think{ border-left-color:var(--ai); } .ev.think .h{ color:#cdb4ff; }
.ev.act{ border-left-color:var(--warn); } .ev.act .h{ color:#f3c879; }
.ev.result{ border-left:3px solid var(--crit); background:rgba(231,76,60,.07); } .ev.result .h{ color:#ff9c91; }
.ev.result .b{ background:rgba(0,0,0,.35); border-radius:6px; padding:7px 9px; margin-top:5px; font-family:monospace; color:#ffd7d1; }
.ran-badge{ font-size:9px; font-weight:800; background:rgba(231,76,60,.28); color:#ff9c91; padding:1px 7px; border-radius:20px; margin-left:6px; }
.node-chip{ font-size:10px; font-weight:800; background:rgba(77,163,255,.16); color:#bcd; border:1px solid rgba(77,163,255,.32); padding:1px 8px; border-radius:20px; white-space:nowrap; }
.node-chip i{ font-size:9px; margin-right:3px; color:var(--accent); }
.ev.system{ border-left-color:#667; } .ev.system .h{ color:#9aa; }
.ev.error{ border-left-color:var(--crit); } .ev.error .h{ color:#ff9c91; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-clock-rotate-left"></i> NetAIObot History', '',
    'What the agent did · per device', 'fa-solid fa-robot',
    '<select id="node" class="tgt-sel" onchange="load()"><option value="0">All devices</option>'
    . implode('', array_map(fn($n)=>'<option value="'.(int)$n['id'].'">'.htmlspecialchars($n['display_name']).'</option>', $nodes))
    . '</select> <a href="aiopilot.php" class="refresh-btn" style="text-decoration:none;"><i class="fas fa-robot"></i> Command Center</a>'); ?>

<div id="list"><div class="muted" style="padding:20px;">Loading…</div></div>
</div>
<script src="/nm_netbg.js"></script>
<?= function_exists('nm_tz_js') ? nm_tz_js() : '' ?>
<script>
const esc=s=>(s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
// full date+time in the configured display tz (app_timezone); stored values are UTC
const nl=ts=>window.nmLocal?window.nmLocal(ts,false):(ts||'');
const phaseIcon=p=>({observe:'fa-satellite-dish',think:'fa-brain',act:'fa-bolt',result:'fa-circle-check',error:'fa-triangle-exclamation',system:'fa-gear'}[p]||'fa-circle');

async function load(){
  const node=document.getElementById('node').value||0;
  const r=await fetch('aiopilot_history.php?api=sessions&node='+node).then(x=>x.json()).catch(()=>null);
  const box=document.getElementById('list');
  if(!r||!r.ok||!r.sessions.length){ box.innerHTML='<div class="muted glass" style="padding:24px;">No sessions yet.</div>'; return; }
  box.innerHTML=r.sessions.map(s=>`<div class="glass sess" onclick="toggle(${s.id})">
     <div class="top">
       <span class="st ${esc(s.status)}">${esc(s.status)}</span>
       <span class="nm">${esc(s.display_name)}</span>
       <span class="ti">${esc(s.title||'')}</span>
       <span class="chip">${esc(s.trigger_kind)}</span>
       <span class="chip"><i class="fas fa-wave-square"></i> ${s.ev} steps</span>
       ${+s.acts>0?`<span class="chip" style="color:#ff9c91;border-color:rgba(231,76,60,.4);"><i class="fas fa-bolt"></i> ${s.acts} executed</span>`:''}
       <span class="when muted" style="margin-left:auto;">${nl(s.created_at)}</span>
     </div>
     ${s.summary?`<div class="muted" style="margin-top:6px;">${esc(s.summary).slice(0,400)}</div>`:''}
     <div class="tl" id="tl-${s.id}"></div>
   </div>`).join('');
}
async function toggle(id){
  const tl=document.getElementById('tl-'+id); if(!tl) return;
  if(tl.classList.contains('open')){ tl.classList.remove('open'); return; }
  tl.classList.add('open'); tl.innerHTML='<div class="muted">Loading timeline…</div>';
  const r=await fetch('aiopilot_history.php?api=events&session='+id).then(x=>x.json()).catch(()=>null);
  if(!r||!r.ok){ tl.innerHTML='<div class="muted">Failed to load.</div>'; return; }
  tl.innerHTML = r.events.length ? r.events.map(e=>`<div class="ev ${esc(e.phase)}">
     <div class="h"><span class="node-chip"><i class="fas fa-server"></i>${esc(e.display_name||'')}</span>
        <i class="fas ${phaseIcon(e.phase)}"></i> ${esc(e.title||e.phase)}
        ${e.phase==='result'?'<span class="ran-badge">⚡ RAN ON DEVICE</span>':''}
        <span class="when">${nl(e.created_at)}</span></div>
     ${e.body?`<div class="b">${esc(e.body).slice(0,2000)}</div>`:''}</div>`).join('') : '<div class="muted">No steps recorded.</div>';
}
load();
</script>
</body></html>
