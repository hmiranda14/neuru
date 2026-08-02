<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Chaos Test / Blast-Radius. Pick a node → see the cascade if it dies
// (using the real topology + redundancy) and which business services it takes
// down. Ranks single points of failure. RBAC: 'chaos'. Engine: nm_chaos.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_chaos.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'chaos')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=chaos'); exit;
}
nm_chaos_ensure($conn);
$canConfig = nm_can($conn,'net_mon_config');

if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    $body = json_decode(file_get_contents('php://input'), true) ?? $_POST;
    if ($api === 'simulate')      { echo json_encode(['ok'=>true,'sim'=>nm_chaos_simulate($conn,(int)($_GET['id']??0))]); exit; }
    if ($api === 'spofs')         { echo json_encode(['ok'=>true,'spofs'=>nm_chaos_spofs($conn,20)]); exit; }
    if ($api === 'services_list') {
        $G=nm_chaos_graph($conn);
        echo json_encode(['ok'=>true,'services'=>nm_chaos_services($conn),'roots'=>array_map('intval',nm_chaos_roots($conn,$G))]); exit;
    }
    if ($api === 'service_get')   { echo json_encode(['ok'=>true,'deps'=>nm_chaos_service_deps($conn,(int)($_GET['id']??0))]); exit; }
    if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
    if (!$canConfig) { echo json_encode(['ok'=>false,'error'=>'Configuration access required']); exit; }
    if ($api === 'service_save')  { $id=nm_chaos_service_save($conn,$body); nm_audit($conn,'chaos.service.save',['target_id'=>$id]); echo json_encode(['ok'=>(bool)$id,'id'=>$id]); exit; }
    if ($api === 'service_delete'){ nm_chaos_service_delete($conn,(int)($body['id']??0)); echo json_encode(['ok'=>true]); exit; }
    if ($api === 'save_core') {
        $ids=implode(',', array_map('intval', (array)($body['core']??[])));
        $st=$conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES('chaos_core_node_ids',?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
        $st->bind_param('s',$ids); $st->execute();
        nm_audit($conn,'chaos.core.save'); echo json_encode(['ok'=>true]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'Unknown endpoint']); exit;
}

$nodes=[]; $nr=$conn->query("SELECT id,display_name FROM nm_nodes ORDER BY display_name"); while($nr&&$x=$nr->fetch_assoc()) $nodes[]=$x;
$coreIds = array_filter(array_map('intval', explode(',', (string)nm_chaos_setting($conn,'chaos_core_node_ids',''))));
log_user_action($conn,'view_page','chaos.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Chaos Test | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --chaos:#e67e22; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.18; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 40px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; } .card h3{ margin:0 0 12px; font-size:12px; color:var(--accent); text-transform:uppercase; letter-spacing:1px; }
.tabs{ display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap; } .tab{ background:rgba(255,255,255,.05); border:1px solid var(--border); color:#aaa; padding:8px 15px; border-radius:8px; cursor:pointer; font-size:12px; font-weight:600; }
.tab.active{ background:var(--chaos); color:#1a0e03; border-color:transparent; } .pane{ display:none; } .pane.active{ display:block; }
.inp,select{ background:rgba(0,0,0,.4); border:1px solid var(--border); color:#eee; border-radius:9px; padding:9px 11px; font-size:13px; }
.btn{ background:rgba(255,255,255,.06); border:1px solid var(--border); color:#cfd3da; padding:9px 14px; border-radius:9px; cursor:pointer; font-size:12px; display:inline-flex; gap:7px; align-items:center; }
.btn:hover{ background:rgba(255,255,255,.13); color:#fff; } .btn.chaos{ background:rgba(230,126,34,.2); border-color:var(--chaos); color:#f0a868; } .btn.chaos:hover{ background:var(--chaos); color:#1a0e03; }
.btn.danger:hover{ border-color:var(--crit); color:var(--crit); }
.row{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; } .muted{ color:#7c828c; font-size:12px; }
.failcard{ border:1px solid rgba(231,76,60,.5); background:rgba(231,76,60,.1); border-radius:12px; padding:16px 18px; text-align:center; }
.failcard .nm{ font-size:20px; font-weight:800; color:#f0a59d; } .failcard .ic{ font-size:30px; color:var(--crit); margin-bottom:6px; }
.casc{ display:flex; align-items:center; justify-content:center; color:var(--chaos); font-size:22px; margin:6px 0; }
.nodes{ display:grid; grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); gap:9px; }
.nd{ border:1px solid rgba(231,76,60,.35); background:rgba(231,76,60,.07); border-radius:9px; padding:9px 11px; font-size:12.5px; font-weight:600; }
.nd i{ color:var(--crit); margin-right:6px; }
.svc{ border:1px solid var(--border); border-left-width:4px; border-radius:10px; padding:12px 14px; margin-bottom:10px; }
.svc.down{ border-left-color:var(--crit); background:rgba(231,76,60,.06);} .svc.degraded{ border-left-color:var(--warn); background:rgba(243,156,18,.05);} .svc.ok{ border-left-color:var(--ok);}
.svc .t{ display:flex; justify-content:space-between; align-items:center; } .svc .nm{ font-weight:700; }
.sbadge{ font-size:9px; font-weight:800; padding:2px 8px; border-radius:5px; text-transform:uppercase; }
.sb-down{ background:rgba(231,76,60,.18); color:var(--crit);} .sb-degraded{ background:rgba(243,156,18,.18); color:var(--warn);} .sb-ok{ background:rgba(46,204,113,.16); color:var(--ok);}
.bar{ height:7px; border-radius:4px; background:rgba(255,255,255,.08); overflow:hidden; margin-top:7px; } .bar>i{ display:block; height:100%; }
table{ width:100%; border-collapse:collapse; font-size:13px; } th,td{ text-align:left; padding:9px 10px; border-bottom:1px solid rgba(255,255,255,.07); }
th{ color:#7c828c; font-size:11px; text-transform:uppercase; letter-spacing:.5px; }
.chk{ max-height:230px; overflow:auto; border:1px solid var(--border); border-radius:8px; padding:8px; }
.chk label{ display:flex; align-items:center; gap:8px; font-size:12.5px; margin:3px 0; color:#cfd3da; }
.pill{ font-size:9px; font-weight:700; padding:2px 7px; border-radius:5px; }
.p-high{ background:rgba(231,76,60,.16); color:var(--crit);} .p-medium{ background:rgba(243,156,18,.16); color:var(--warn);} .p-low{ background:rgba(77,163,255,.16); color:var(--accent);}
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-burst"></i>Chaos Test', '', 'Blast-Radius Simulation', 'fa-solid fa-burst'); ?>

<div class="tabs">
  <div class="tab active" data-pane="sim" onclick="showPane('sim')"><i class="fas fa-burst"></i> Chaos Test</div>
  <div class="tab" data-pane="spof" onclick="showPane('spof');loadSpofs()"><i class="fas fa-bomb"></i> Single Points of Failure</div>
  <div class="tab" data-pane="svc" onclick="showPane('svc');loadServices()"><i class="fas fa-sitemap"></i> Services &amp; Core</div>
</div>

<div class="pane active" id="pane-sim">
  <div class="glass card">
    <h3><i class="fas fa-burst"></i> What breaks if a node dies?</h3>
    <div class="row">
      <select class="inp" id="sim-node" style="flex:1;min-width:220px;">
        <option value="">— pick a node to fail —</option>
        <?php foreach($nodes as $n): ?><option value="<?= (int)$n['id'] ?>"><?= htmlspecialchars($n['display_name']) ?></option><?php endforeach; ?>
      </select>
      <button class="btn chaos" onclick="simulate(this)"><i class="fas fa-burst"></i> Run Chaos Test</button>
    </div>
    <div class="muted" style="margin-top:8px;">Uses the real topology (gateway + manual links). A node only counts as lost if it has <b>no surviving path</b> to the core — redundant links protect it.</div>
  </div>
  <div id="sim-result"></div>
</div>

<div class="pane" id="pane-spof">
  <div class="glass card">
    <h3><i class="fas fa-bomb"></i> Single points of failure <span class="muted" style="text-transform:none;letter-spacing:0;">— worst-first; fix these for resilience</span></h3>
    <div style="overflow-x:auto;"><table><thead><tr><th>#</th><th>Node</th><th>Nodes isolated</th><th>Services down</th><th>Services degraded</th><th></th></tr></thead>
      <tbody id="spof-tb"><tr><td colspan="6" class="muted" style="text-align:center;padding:16px;">Loading…</td></tr></tbody></table></div>
  </div>
</div>

<div class="pane" id="pane-svc">
  <div class="glass card">
    <h3><i class="fas fa-server"></i> Core / egress nodes <span class="muted" style="text-transform:none;letter-spacing:0;">— where the network reaches the internet</span></h3>
    <p class="muted" style="margin:0 0 10px;">Designate your real core/uplink node(s) for accurate blast-radius. If none picked, NEURU uses gateway-less nodes (less precise).</p>
    <div class="chk" id="core-chk">
      <?php foreach($nodes as $n): ?><label><input type="checkbox" class="corechk" value="<?= (int)$n['id'] ?>" <?= in_array((int)$n['id'],$coreIds,true)?'checked':'' ?> <?= $canConfig?'':'disabled' ?>> <?= htmlspecialchars($n['display_name']) ?></label><?php endforeach; ?>
    </div>
    <?php if($canConfig): ?><div class="row" style="margin-top:10px;"><button class="btn" onclick="saveCore(this)"><i class="fas fa-save"></i> Save core</button><span class="muted" id="core-msg"></span></div><?php endif; ?>
  </div>

  <div class="glass card">
    <h3><span><i class="fas fa-sitemap"></i> Business services</span> <?php if($canConfig): ?><button class="btn" onclick="svcForm()" style="float:right;"><i class="fas fa-plus"></i> Add service</button><?php endif; ?></h3>
    <p class="muted" style="margin:0 0 12px;">Map each service (VoIP, Database, Portal…) to the nodes it depends on. Mark a node <b>critical</b> if losing it takes the whole service down.</p>
    <div id="svc-form" style="display:none;" class="glass" style="padding:12px;border-radius:10px;margin-bottom:12px;"></div>
    <div id="svc-list"><div class="muted">Loading…</div></div>
  </div>
</div>
</div>
<script>
const CAN=<?= $canConfig?'true':'false' ?>;
const NODES=<?= json_encode(array_map(fn($n)=>['id'=>(int)$n['id'],'name'=>$n['display_name']],$nodes)) ?>;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function showPane(p){ document.querySelectorAll('.pane').forEach(x=>x.classList.remove('active')); document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active')); document.getElementById('pane-'+p).classList.add('active'); document.querySelector(`.tab[data-pane="${p}"]`).classList.add('active'); }
async function post(api,obj){ return fetch('chaos.php?api='+api,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj||{})}).then(r=>r.json()).catch(()=>({ok:false,error:'failed'})); }

async function simulate(btn){
  const id=+document.getElementById('sim-node').value; const out=document.getElementById('sim-result');
  if(!id){ out.innerHTML='<div class="muted">Pick a node first.</div>'; return; }
  btn.disabled=true; out.innerHTML='<div class="muted">Simulating…</div>';
  const r=await fetch('chaos.php?api=simulate&id='+id).then(r=>r.json()).catch(()=>null); btn.disabled=false;
  if(!r||!r.ok){ out.innerHTML='<div class="muted">Error.</div>'; return; }
  const s=r.sim;
  const svcHtml = s.services.length ? s.services.map(v=>{
    const col=v.status==='down'?'var(--crit)':v.status==='degraded'?'var(--warn)':'var(--ok)';
    return `<div class="svc ${v.status}"><div class="t"><span class="nm">${esc(v.name)} <span class="pill p-${v.criticality}">${v.criticality}</span></span><span class="sbadge sb-${v.status}">${v.status} · ${v.impact}%</span></div>
      ${v.affected_nodes.length?`<div class="muted" style="margin-top:4px;">losing: ${v.affected_nodes.map(esc).join(', ')}</div>`:''}
      <div class="bar"><i style="width:${v.impact}%;background:${col};"></i></div></div>`;
  }).join('') : '<div class="muted">No business services defined yet — add them in the “Services & Core” tab to see business impact.</div>';
  out.innerHTML = `
    <div class="glass card">
      <div class="failcard"><div class="ic"><i class="fas fa-skull-crossbones"></i></div><div class="nm">${esc(s.fail.name)}</div>
        <div class="muted">fails ${s.fail_is_root?'· this is a core/egress node':''}</div></div>
      <div class="casc"><i class="fas fa-arrow-down"></i></div>
      <h3 style="margin-top:0;"><i class="fas fa-network-wired"></i> Blast radius — ${s.blast_count} node(s) isolated ${s.blast_count? '':'<span class="muted" style="text-transform:none;">(protected by redundancy 🎉)</span>'}</h3>
      ${s.blast_count? `<div class="nodes">${s.blast.map(b=>`<div class="nd"><i class="fas fa-plug-circle-xmark"></i>${esc(b.name)}</div>`).join('')}</div>`:''}
      <div class="casc"><i class="fas fa-arrow-down"></i></div>
      <h3><i class="fas fa-briefcase"></i> Business impact</h3>
      ${svcHtml}
      <div class="muted" style="margin-top:10px;border-top:1px solid var(--border);padding-top:8px;">Reachable nodes before failure: ${s.reachable_before}. Core/egress: ${s.roots.map(r=>esc(r.name)).join(', ')||'—'}.</div>
    </div>`;
}

async function loadSpofs(){
  const r=await fetch('chaos.php?api=spofs').then(r=>r.json()).catch(()=>null); const tb=document.getElementById('spof-tb');
  if(!r||!r.ok){ tb.innerHTML='<tr><td colspan="6" class="muted">Error.</td></tr>'; return; }
  if(!r.spofs.length){ tb.innerHTML='<tr><td colspan="6" class="muted" style="text-align:center;padding:16px;">No single points of failure — every node has redundancy or no downstream. 🎉</td></tr>'; return; }
  tb.innerHTML=r.spofs.map((s,i)=>`<tr>
    <td><b>${i+1}</b></td><td><b>${esc(s.name)}</b></td>
    <td>${s.blast}</td>
    <td>${s.svc_down?`<span style="color:var(--crit);font-weight:700;">${s.svc_down}</span>`:'—'}</td>
    <td>${s.svc_deg?`<span style="color:var(--warn);">${s.svc_deg}</span>`:'—'}</td>
    <td style="text-align:right;"><button class="btn" onclick="document.getElementById('sim-node').value=${s.id};showPane('sim');simulate(this)"><i class="fas fa-burst"></i> Test</button></td></tr>`).join('');
}

let _svcRoots=[];
async function loadServices(){
  const r=await fetch('chaos.php?api=services_list').then(r=>r.json()).catch(()=>null); const el=document.getElementById('svc-list');
  if(!r||!r.ok){ el.innerHTML='<div class="muted">Error.</div>'; return; }
  if(!r.services.length){ el.innerHTML='<div class="muted">No services yet. Add one to model business impact.</div>'; return; }
  el.innerHTML=r.services.map(s=>`<div class="svc ok" style="border-left-color:#444;"><div class="t">
    <span class="nm">${esc(s.name)} <span class="pill p-${s.criticality}">${s.criticality}</span> <span class="muted">· ${s.dep_count} node(s)</span></span>
    ${CAN?`<span><button class="btn" onclick='editSvc(${s.id})'><i class="fas fa-pen"></i></button> <button class="btn danger" onclick="delSvc(${s.id})"><i class="fas fa-trash"></i></button></span>`:''}
    </div>${s.description?`<div class="muted" style="margin-top:3px;">${esc(s.description)}</div>`:''}</div>`).join('');
}
function svcForm(svc,deps){ svc=svc||{}; deps=deps||[];
  const depSet={}; deps.forEach(d=>depSet[d.node_id]={crit:d.is_critical==1});
  document.getElementById('svc-form').style.display='block';
  document.getElementById('svc-form').innerHTML=`
    <input type="hidden" id="f-id" value="${svc.id||0}">
    <div class="row" style="gap:10px;"><div style="flex:2;"><label class="muted">Name</label><input class="inp" id="f-name" value="${esc(svc.name||'')}" placeholder="VoIP / SIP trunks" style="width:100%;"></div>
      <div style="flex:1;"><label class="muted">Criticality</label><select class="inp" id="f-crit" style="width:100%;">${['high','medium','low'].map(c=>`<option ${svc.criticality===c?'selected':''}>${c}</option>`).join('')}</select></div></div>
    <div style="margin-top:8px;"><label class="muted">Description</label><input class="inp" id="f-desc" value="${esc(svc.description||'')}" style="width:100%;"></div>
    <label class="muted" style="display:block;margin:10px 0 4px;">Depends on nodes <span style="color:#888;">(✔ critical = its loss = service down)</span></label>
    <div class="chk">${NODES.map(n=>`<label><input type="checkbox" class="depchk" value="${n.id}" ${depSet[n.id]?'checked':''}> ${esc(n.name)} <label style="margin-left:auto;color:#888;"><input type="checkbox" class="depcrit" data-n="${n.id}" ${depSet[n.id]&&depSet[n.id].crit?'checked':''}> critical</label></label>`).join('')}</div>
    <div class="row" style="margin-top:10px;"><button class="btn chaos" onclick="saveSvc()"><i class="fas fa-save"></i> Save service</button><button class="btn" onclick="document.getElementById('svc-form').style.display='none'">Cancel</button></div>`;
}
async function editSvc(id){ const r=await fetch('chaos.php?api=service_get&id='+id).then(r=>r.json()); const svcs=await fetch('chaos.php?api=services_list').then(r=>r.json());
  const svc=(svcs.services||[]).find(s=>s.id==id); svcForm(svc,r.deps||[]); }
async function saveSvc(){
  const deps=[...document.querySelectorAll('.depchk:checked')].map(c=>({node_id:+c.value, is_critical: document.querySelector(`.depcrit[data-n="${c.value}"]`)?.checked?1:0, weight:1}));
  const b={ id:+document.getElementById('f-id').value, name:document.getElementById('f-name').value, criticality:document.getElementById('f-crit').value, description:document.getElementById('f-desc').value, deps };
  if(!b.name.trim()){ alert('Name required'); return; }
  const r=await post('service_save',b); if(r.ok){ document.getElementById('svc-form').style.display='none'; loadServices(); } else alert(r.error||'Failed');
}
async function delSvc(id){ if(!confirm('Delete this service?'))return; await post('service_delete',{id}); loadServices(); }
async function saveCore(btn){ btn.disabled=true; const core=[...document.querySelectorAll('.corechk:checked')].map(c=>+c.value); const r=await post('save_core',{core}); btn.disabled=false; document.getElementById('core-msg').textContent=r.ok?'Saved ✓':(r.error||'Failed'); }
</script>
</body></html>
