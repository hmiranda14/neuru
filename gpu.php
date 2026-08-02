<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — AI / GPU Server Monitor UI. RBAC: 'gpu'. Engine: nm_gpu.php.
// Agentless GPU telemetry over SSH (nvidia-smi / rocm-smi / Windows counters) +
// Ollama model correlation. Designed for AI inference boxes (Ollama / LM Studio).
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_gpu.php');
include('logger.php');

$api = $_GET['api'] ?? '';
$act = $_POST['action'] ?? '';
if (!checkAccess($conn, 'gpu')) {
    if ($api || $act) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=gpu'); exit;
}
nm_gpu_ensure($conn);
if (function_exists('session_write_close')) @session_write_close(); // free session lock before slow SSH/n8n I/O (prevents whole-portal freeze)

$uid = (int)($_SESSION['user_id'] ?? 0) ?: null;

if ($act !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if ($act === 'target_add')    { $r=nm_gpu_target_add($conn,$_POST,$uid); log_user_action($conn,'gpu_target_add',$_POST['name']??''); echo json_encode($r); exit; }
    if ($act === 'target_update') { echo json_encode(nm_gpu_target_update($conn,(int)($_POST['id']??0),$_POST)); exit; }
    if ($act === 'target_delete') { echo json_encode(nm_gpu_target_delete($conn,(int)($_POST['id']??0))); exit; }
    if ($act === 'poll')          { $t=nm_gpu_target($conn,(int)($_POST['id']??0)); echo json_encode($t?nm_gpu_poll_target($conn,$t):['ok'=>false,'error'=>'no target']); exit; }
    echo json_encode(['ok'=>false,'error'=>'unknown action']); exit;
}
if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if ($api === 'targets') { echo json_encode(['ok'=>true,'targets'=>nm_gpu_targets($conn)]); exit; }
    if ($api === 'gpus')    { $tid=(int)($_GET['target']??0); echo json_encode(['ok'=>true,'gpus'=>nm_gpu_list($conn,$tid),'models'=>nm_gpu_models($conn,$tid),'ai'=>nm_gpu_ai_status($conn,$tid)]); exit; }
    if ($api === 'series')  { echo json_encode(['ok'=>true,'points'=>nm_gpu_series($conn,(int)($_GET['gpu']??0),(int)($_GET['mins']??60))]); exit; }
    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}

log_user_action($conn,'view_page','gpu.php');
$nodes = [];
$nr = $conn->query("SELECT id,display_name,ip_address FROM nm_nodes ORDER BY display_name LIMIT 1000");
while ($nr && ($x=$nr->fetch_assoc())) $nodes[] = $x;
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI / GPU Monitor | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --gpu:#76b900; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.18; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 40px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:8px 14px; font-size:13px; cursor:pointer; }
.btn:hover{ background:rgba(77,163,255,.25); } .btn.ghost{ background:transparent; border-color:var(--border); color:#aab; } .btn.sm{ padding:3px 9px; font-size:11px; }
.btn.danger{ color:#f0a59d; border-color:rgba(231,76,60,.4); }
.tt{ display:inline-block; font-size:10px; font-weight:700; padding:2px 8px; border-radius:20px; background:rgba(118,185,0,.16); color:#aee06a; text-transform:uppercase; }
.st{ font-size:11px; font-weight:700; } .st.ok{ color:var(--ok);} .st.error{ color:var(--crit);} .st.new{ color:#8a909a;}
.tgrid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(300px,1fr)); gap:14px; margin-bottom:18px; }
.tcard{ padding:13px 15px; cursor:pointer; } .tcard.active{ border-color:var(--gpu); box-shadow:0 0 0 1px rgba(118,185,0,.3) inset; }
.tcard .nm{ font-size:15px; font-weight:800; } .tcard .meta{ font-size:11px; color:#8a909a; margin:4px 0; }
.gcard{ padding:16px 18px; margin-bottom:14px; }
.gcard h3{ margin:0 0 2px; font-size:16px; } .gcard .sub{ color:#8a909a; font-size:11px; margin-bottom:12px; }
.metrics{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:14px; }
.metric .lab{ font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; display:flex; justify-content:space-between; }
.metric .val{ font-size:20px; font-weight:800; margin:2px 0 5px; }
.bar{ height:7px; border-radius:6px; background:rgba(255,255,255,.08); overflow:hidden; }
.bar > i{ display:block; height:100%; border-radius:6px; transition:width .4s; }
table{ width:100%; border-collapse:collapse; font-size:12.5px; }
th{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; padding:6px 9px; border-bottom:1px solid var(--border); }
td{ padding:6px 9px; border-bottom:1px solid rgba(255,255,255,.05); }
.muted{ color:#7c828c; font-size:12px; } .mono{ font-family:monospace; }
.modal-bg{ position:fixed; inset:0; background:rgba(0,0,0,.6); z-index:90; display:none; align-items:flex-start; justify-content:center; padding-top:7vh; overflow:auto; }
.modal{ width:460px; max-width:95vw; padding:22px 24px; } .modal h3{ margin:0 0 14px; }
.modal label{ display:block; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; margin:10px 0 4px; }
.modal input,.modal select{ width:100%; background:rgba(255,255,255,.06); color:#e6e9ee; border:1px solid var(--border); border-radius:8px; padding:9px 11px; font-size:13px; }
.row{ display:flex; gap:10px; } .row>div{ flex:1; }
.actions{ display:flex; gap:10px; justify-content:flex-end; margin-top:18px; align-items:center; }
select, .modal select{ background:#1b2129 !important; color:#e6e9ee; } option{ background:#1b2129; color:#e6e9ee; }
.modelpill{ display:inline-flex; align-items:center; gap:6px; background:rgba(118,185,0,.12); border:1px solid rgba(118,185,0,.3); color:#cfe9a3; border-radius:20px; padding:4px 11px; font-size:12px; margin:3px 4px 3px 0; }
.rdot{ width:8px; height:8px; border-radius:50%; background:#2ecc71; display:inline-block; box-shadow:0 0 6px #2ecc71; animation:rpulse 1.6s ease-in-out infinite; }
@keyframes rpulse{ 0%,100%{opacity:1;} 50%{opacity:.35;} }
.hidefor{ display:none; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-microchip"></i>AI / GPU Monitor', '', 'Inference box telemetry', 'fa-solid fa-microchip',
    '<button class="refresh-btn" onclick="loadTargets()"><i class="fas fa-rotate"></i> Refresh</button>'); ?>

<div class="glass card" style="padding:11px 16px;"><div class="muted"><i class="fas fa-circle-info"></i>
  GPUs expose no SNMP OID for utilization, so NEURU reads <b>nvidia-smi / rocm-smi / Windows GPU counters over SSH</b> (agentless) and correlates load with the <b>Ollama</b> model that's loaded. Add your AI server below — it needs SSH reachable (OpenSSH is built into Windows&nbsp;10/11/Server&nbsp;2019+).</div></div>

<div style="margin-bottom:6px;display:flex;gap:8px;flex-wrap:wrap;">
  <button class="btn" onclick="openTarget()"><i class="fas fa-plus"></i> Add AI server</button>
  <span class="muted" id="auto-msg" style="align-self:center;"></span>
</div>
<div class="tgrid" id="targets"><div class="muted">Loading…</div></div>

<div id="detail" class="hidefor">
  <div class="glass card" id="detail-head" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;"></div>
  <div id="models-wrap"></div>
  <div id="gpus"></div>
</div>

<!-- target modal -->
<div class="modal-bg" id="tbg"><div class="glass modal">
  <h3 id="t-title">Add AI server</h3>
  <input type="hidden" id="t-id">
  <label>Name</label><input id="t-name" placeholder="ollama-rtx4090">
  <div class="row">
    <div><label>Monitored node (SSH)</label><select id="t-node"><option value="">— pick a node —</option>
      <?php foreach($nodes as $n): ?><option value="<?= (int)$n['id'] ?>"><?= htmlspecialchars($n['display_name']) ?> (<?= htmlspecialchars($n['ip_address']) ?>)</option><?php endforeach; ?></select></div>
    <div><label>…or host IP</label><input id="t-host" placeholder="192.168.0.50"></div>
  </div>
  <label>Ollama API URL <span class="muted">— optional, read over SSH-localhost</span></label>
  <input id="t-ollama" placeholder="http://localhost:11434">
  <div class="row">
    <div><label>Temp warn (°C)</label><input id="t-tw" type="number" value="85"></div>
    <div><label>VRAM warn (%)</label><input id="t-vw" type="number" value="90"></div>
  </div>
  <p class="muted" style="margin-top:8px;">SSH credential comes from the node (or the default). On Windows the box needs <span class="mono">nvidia-smi</span>/<span class="mono">curl</span> on PATH (both ship with the driver / Windows).</p>
  <div class="actions"><span class="muted" id="t-msg" style="margin-right:auto;"></span>
    <button class="btn ghost" onclick="closeM('tbg')">Cancel</button><button class="btn" onclick="saveTarget()">Save</button></div>
</div></div>

<script>
let TGT=[], SEL=<?= (int)($_GET['target'] ?? 0) ?>, autoTimer=null;
// tz helpers come from header.php (nm_tz_js); fall back to raw string if absent
if(typeof window.nmLocal!=='function')   window.nmLocal=(u)=>u||'';
if(typeof window.nmTimeStr!=='function') window.nmTimeStr=(u)=>u||'';
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function gv(id){ return document.getElementById(id).value; }
function closeM(id){ document.getElementById(id).style.display='none'; }
async function post(b){ return fetch('gpu.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b}).then(r=>r.json()).catch(()=>null); }
function clr(v,a,b){ v=+v; return v>=b?'var(--crit)':(v>=a?'var(--warn)':'var(--ok)'); }
function relAge(s){ if(s==null)return 'never'; s=+s; if(s<60)return s+'s ago'; if(s<3600)return Math.floor(s/60)+'m ago'; if(s<86400)return Math.floor(s/3600)+'h ago'; return Math.floor(s/86400)+'d ago'; }
function fmtMB(mb){ mb=+mb||0; return mb>=1024?(mb/1024).toFixed(1)+' GB':mb+' MB'; }

async function loadTargets(){
  const r=await fetch('gpu.php?api=targets').then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok)return; TGT=r.targets;
  document.getElementById('targets').innerHTML = TGT.length? TGT.map(t=>`
    <div class="glass tcard ${t.id==SEL?'active':''}" onclick="selTarget(${t.id})">
      <div class="nm">${esc(t.name)} ${t.vendor?`<span class="tt">${esc(t.vendor)}</span>`:''}</div>
      <div class="meta">${esc(t.node_name||t.host_ip||'—')} · ${t.gpu_count} GPU(s)${t.ollama_url?' · ollama':''}</div>
      <div class="st ${esc(t.status)}">● ${esc(t.status)}${t.last_error?' — '+esc((t.last_error||'').slice(0,60)):''}</div>
      <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;">
        <button class="btn sm" onclick="event.stopPropagation();pollNow(${t.id})"><i class="fas fa-satellite-dish"></i> Poll now</button>
        <button class="btn ghost sm" onclick="event.stopPropagation();editTarget(${t.id})">edit</button>
        <button class="btn ghost sm danger" onclick="event.stopPropagation();delTarget(${t.id})">delete</button>
      </div>
    </div>`).join('') : '<div class="muted">No AI servers yet — add one to start monitoring its GPU.</div>';
  if(SEL && !TGT.find(t=>t.id==SEL)){ SEL=0; document.getElementById('detail').classList.add('hidefor'); }
  if(SEL){ document.getElementById('detail').classList.remove('hidefor'); loadDetail(); }
}
function selTarget(id){ SEL=id; loadTargets(); document.getElementById('detail').classList.remove('hidefor'); loadDetail(); }

async function loadDetail(){
  if(!SEL)return;
  const t=TGT.find(x=>x.id==SEL); if(!t)return;
  const r=await fetch('gpu.php?api=gpus&target='+SEL).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok)return;
  document.getElementById('detail-head').innerHTML =
    `<div style="font-size:18px;font-weight:800;"><i class="fas fa-server" style="color:var(--gpu)"></i> ${esc(t.name)}</div>`+
    `<span class="muted">${esc(t.node_name||t.host_ip||'')}</span>`+
    (t.vendor?`<span class="tt">${esc(t.vendor)}</span>`:'')+
    `<span class="muted" style="margin-left:auto;">last poll ${t.last_poll?esc(nmLocal(t.last_poll,true)):'—'}</span>`+
    `<button class="btn sm" onclick="pollNow(${SEL})"><i class="fas fa-satellite-dish"></i> Poll now</button>`;
  // Ollama models
  renderAI(r.ai||{enabled:false}, r.models||[]);
  // GPU cards
  document.getElementById('gpus').innerHTML = r.gpus.length? r.gpus.map(g=>gpuCard(g,t)).join('') : '<div class="glass card muted">No GPU samples yet — hit “Poll now”.</div>';
  r.gpus.forEach(g=>drawSpark(g.id));
}
let _aiExpand=false;
function renderAI(ai, models){
  const mw=document.getElementById('models-wrap');
  if(!ai.enabled){ mw.innerHTML=''; return; }
  if(!ai.ok){
    mw.innerHTML=`<div class="glass card" style="border-left:3px solid var(--warn);"><b style="color:var(--warn)"><i class="fas fa-robot"></i> Ollama not reachable</b>
      <span class="muted"> at ${esc(ai.url)} — check the URL, that Ollama is running, and that <code>curl</code> can reach it from the server (bind OLLAMA_HOST=0.0.0.0 for LAN access).</span></div>`;
    return;
  }
  const running=models.filter(m=>m.running==1), lib=models.slice().sort((a,b)=>(b.size_mb||0)-(a.size_mb||0));
  const head=`<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px;">
    <b style="font-size:14px;"><i class="fas fa-robot" style="color:#76b900"></i> Ollama</b>
    <span class="tt">v${esc(ai.version||'?')}</span>
    <span class="muted" style="font-size:11px;">${esc(ai.url)}</span>
    <span style="margin-left:auto;font-size:11px;" class="muted"><b style="color:var(--ok)">${running.length}</b> running · <b>${ai.installed}</b> installed · ${fmtMB(ai.library_mb)} library</span></div>`;
  const runHtml = running.length
    ? `<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:6px;">`+running.map(m=>`<span class="modelpill"><span class="rdot"></span>${esc(m.name)} <b>${fmtMB(m.vram_mb)}</b> VRAM${m.expires_at?` <span class="muted">· unloads ${esc(nmTimeStr(m.expires_at))}</span>`:''}</span>`).join('')+`</div>`
    : `<div class="muted" style="font-size:12px;margin-bottom:6px;"><i class="fas fa-moon"></i> No model loaded in VRAM right now (idle). The library below is ready to load.</div>`;
  const shown = _aiExpand ? lib : lib.slice(0,8);
  const rows = shown.map(m=>`<tr${m.running==1?' style="background:rgba(118,185,0,.07)"':''}>
    <td>${m.running==1?'<span class="rdot"></span> ':''}<b>${esc(m.name)}</b></td>
    <td class="mono">${m.size_mb?fmtMB(m.size_mb):'—'}</td>
    <td>${esc(m.family||'—')}</td><td class="mono">${esc(m.params||'—')}</td><td class="mono">${esc(m.quant||'—')}</td>
    <td class="muted" style="font-size:11px;">${m.modified_at?esc(nmLocal(m.modified_at)):'—'}</td></tr>`).join('');
  const more = lib.length>8 ? `<div style="text-align:center;margin-top:8px;"><button class="btn ghost sm" onclick="_aiExpand=!_aiExpand;loadDetail()">${_aiExpand?'Show less':('Show all '+lib.length+' models')}</button></div>` : '';
  mw.innerHTML=`<div class="glass card">${head}${runHtml}
    <div style="overflow-x:auto;"><table><thead><tr><th>Model</th><th>Size</th><th>Family</th><th>Params</th><th>Quant</th><th>Pulled</th></tr></thead><tbody>${rows||'<tr><td colspan="6" class="muted">No models installed.</td></tr>'}</tbody></table></div>${more}</div>`;
}
function metric(lab,val,unit,pct,color,extra){
  return `<div class="metric"><div class="lab"><span>${lab}</span>${extra||''}</div>
    <div class="val" style="color:${color}">${val}<span style="font-size:12px;color:#8a909a;font-weight:500;"> ${unit||''}</span></div>
    <div class="bar"><i style="width:${Math.max(0,Math.min(100,pct))}%;background:${color}"></i></div></div>`;
}
function gpuCard(g,t){
  const s=g.latest;
  if(!s) return `<div class="glass gcard"><h3>${esc(g.name||'GPU '+g.gpu_index)}</h3><div class="muted">No samples yet.</div></div>`;
  const tw=+t.temp_warn||85, vw=+t.vram_warn||90;
  const memPct = s.mem_total_mb>0 ? (s.mem_used_mb/s.mem_total_mb*100) : (+s.mem_util_pct||0);
  const util=+s.util_pct||0;
  let m='';
  m+=metric('GPU utilization', Math.round(util), '%', util, clr(util,70,90));
  m+=metric('VRAM', fmtMB(s.mem_used_mb)+(s.mem_total_mb?' / '+fmtMB(s.mem_total_mb):''), '', memPct, clr(memPct,75,vw), `<span class="mono" style="color:#8a909a">${Math.round(memPct)}%</span>`);
  if(s.temp_c!=null) m+=metric('Temperature', Math.round(s.temp_c), '°C', (s.temp_c/Math.max(tw,1))*100, clr(s.temp_c,tw-15,tw));
  if(s.power_w!=null) m+=metric('Power', Math.round(s.power_w), 'W', s.power_limit_w>0?(s.power_w/s.power_limit_w*100):50, clr(s.power_limit_w>0?(s.power_w/s.power_limit_w*100):0,70,95), s.power_limit_w>0?`<span class="muted">/ ${Math.round(s.power_limit_w)}W</span>`:'');
  if(s.fan_pct!=null) m+=metric('Fan', Math.round(s.fan_pct), '%', s.fan_pct, clr(s.fan_pct,70,90));
  if(s.clock_sm_mhz!=null) m+=metric('SM clock', Math.round(s.clock_sm_mhz), 'MHz', 50, 'var(--accent)');
  const procs = g.procs&&g.procs.length? `<div style="margin-top:14px;"><div class="lab" style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#8a909a;margin-bottom:4px;">Processes using this GPU</div>
    <table><thead><tr><th>PID</th><th>VRAM</th><th>Process</th></tr></thead><tbody>${g.procs.map(p=>`<tr><td class="mono">${p.pid}</td><td class="mono">${fmtMB(p.used_mb)}</td><td class="mono" style="font-size:11px;">${esc(p.name)}</td></tr>`).join('')}</tbody></table></div>` : '';
  return `<div class="glass gcard">
    <h3>${esc(g.name||'GPU '+g.gpu_index)} <span class="muted" style="font-size:12px;font-weight:400;">#${g.gpu_index}${g.driver_version?' · driver '+esc(g.driver_version):''}</span> <span class="muted" style="font-size:11px;float:right;">${relAge(s.age)}</span></h3>
    <div class="sub">${esc(g.uuid||'')}</div>
    <div class="metrics">${m}</div>
    <div style="margin-top:12px;"><svg id="spark-${g.id}" width="100%" height="42" preserveAspectRatio="none" viewBox="0 0 300 42"></svg></div>
    ${procs}
  </div>`;
}
async function drawSpark(gid){
  const el=document.getElementById('spark-'+gid); if(!el)return;
  const r=await fetch('gpu.php?api=series&gpu='+gid+'&mins=60').then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok||r.points.length<2){ el.innerHTML=''; return; }
  const W=300,H=42, u=r.points.map(p=>+p.util_pct||0), mx=100;
  const path=u.map((v,i)=>`${(i/(u.length-1))*W},${H-(v/mx)*(H-3)-2}`).join(' ');
  const area=`0,${H} `+path+` ${W},${H}`;
  el.innerHTML=`<polygon points="${area}" fill="rgba(118,185,0,.12)"/><polyline points="${path}" fill="none" stroke="var(--gpu)" stroke-width="1.5"/>`;
}

async function pollNow(id){
  const am=document.getElementById('auto-msg'); am.style.color='#9aa'; am.innerHTML='<i class="fas fa-spinner fa-spin"></i> Polling over SSH…';
  const r=await post(new URLSearchParams({action:'poll',id}));
  if(r&&r.ok){ am.style.color='var(--ok)'; am.textContent='✓ '+r.vendor+' · '+r.gpus+' GPU(s)'; }
  else { am.style.color='var(--crit)'; am.textContent='✗ '+(r?esc(r.error):'failed'); }
  loadTargets();
}
function openTarget(){ ['t-name','t-host','t-ollama'].forEach(i=>document.getElementById(i).value=''); document.getElementById('t-id').value=''; document.getElementById('t-node').value=''; document.getElementById('t-tw').value=85; document.getElementById('t-vw').value=90; document.getElementById('t-title').textContent='Add AI server'; document.getElementById('t-msg').textContent=''; document.getElementById('tbg').style.display='flex'; }
function editTarget(id){ const t=TGT.find(x=>x.id==id); if(!t)return;
  document.getElementById('t-id').value=id; document.getElementById('t-title').textContent='Edit: '+t.name;
  document.getElementById('t-name').value=t.name||''; document.getElementById('t-node').value=t.node_id||''; document.getElementById('t-host').value=t.host_ip||'';
  document.getElementById('t-ollama').value=t.ollama_url||''; document.getElementById('t-tw').value=t.temp_warn||85; document.getElementById('t-vw').value=t.vram_warn||90;
  document.getElementById('t-msg').textContent=''; document.getElementById('tbg').style.display='flex'; }
async function saveTarget(){
  const id=gv('t-id');
  const b=new URLSearchParams({action:id?'target_update':'target_add',id,name:gv('t-name'),node_id:gv('t-node'),host_ip:gv('t-host'),ollama_url:gv('t-ollama'),temp_warn:gv('t-tw'),vram_warn:gv('t-vw'),enabled:'1'});
  const r=await post(b);
  if(r&&r.ok){ closeM('tbg'); if(!id&&r.id){ SEL=r.id; } loadTargets(); }
  else document.getElementById('t-msg').innerHTML='<span style="color:var(--crit)">'+(r?esc(r.error):'failed')+'</span>';
}
async function delTarget(id){ if(!confirm('Delete this AI server and all its GPU history?'))return; await post(new URLSearchParams({action:'target_delete',id})); if(SEL==id)SEL=0; loadTargets(); }

loadTargets();
autoTimer=setInterval(()=>{ loadTargets(); }, 15000);
</script>
</body></html>
