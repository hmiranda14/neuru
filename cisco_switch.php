<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Cisco Switches (F1). RBAC: 'cisco_switch'. Engine: nm_cisco.php.
// A living WebGL front-panel of a Cisco switch: every port rendered as it sits on
// the chassis, coloured by link/admin state, glowing with live throughput, with a
// PoE ring, click-to-inspect detail, VLAN map and PoE budget. Port facts come from
// the Cisco collector (nm_cisco_ports); live traffic overlays from nm_port_stats.
// See docs/NEURU_CISCO_SUITE_PLAN.md (F1).
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_cisco.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'cisco_switch')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=cisco_switch'); exit;
}
nm_cisco_ensure($conn);

function csw_switches($conn): array {
    $out = [];
    foreach (nm_cisco_nodes($conn) as $n) {
        if (($n['cisco_class'] ?? '') !== 'switch') continue;
        $nid = (int)$n['id'];
        $cnt = 0;
        try { $r=$conn->query("SELECT COUNT(*) c FROM nm_cisco_ports WHERE node_id=$nid"); $cnt=(int)$r->fetch_assoc()['c']; } catch (\Throwable $e) {}
        $out[] = ['id'=>$nid,'name'=>$n['display_name'],'ip'=>$n['ip_address'],
                  'hw'=>$n['hw_model'],'ports'=>$cnt];
    }
    return $out;
}

if ($api !== '') {
    if (function_exists('session_write_close')) @session_write_close();
    header('Content-Type: application/json; charset=utf-8');

    if ($api === 'switches') { echo json_encode(['ok'=>true,'switches'=>csw_switches($conn)]); exit; }

    if ($api === 'panel') {
        $nid = (int)($_GET['id'] ?? 0);
        $n = null;
        foreach (nm_cisco_nodes($conn) as $x) { if ((int)$x['id']===$nid) { $n=$x; break; } }
        if (!$n) { echo json_encode(['ok'=>false,'error'=>'not a cisco node']); exit; }
        $ports = nm_cisco_ports_list($conn, $nid);
        $vlans = nm_cisco_vlans_list($conn, $nid);
        $poeCnt = 0; $poeW = 0.0;
        foreach ($ports as $p) {
            if (($p['poe_status'] ?? '') === 'delivering') { $poeCnt++; $poeW += (float)($p['poe_watts'] ?? 0); }
        }
        echo json_encode([
            'ok'=>true,
            'node'=>['id'=>$nid,'name'=>$n['display_name'],'ip'=>$n['ip_address'],'hw'=>$n['hw_model'],
                     'class_label'=>nm_cisco_class_label($n['cisco_class'])],
            'ports'=>$ports, 'vlans'=>$vlans,
            'poe'=>['count'=>$poeCnt,'watts'=>round($poeW,1)],
        ]); exit;
    }

    if ($api === 'repoll') {
        $nid = (int)($_GET['id'] ?? 0) ?: null;
        echo json_encode(['ok'=>true] + nm_cisco_poll_now($conn, $nid)); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}

log_user_action($conn, 'view_page', 'cisco_switch.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cisco Switches | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cisco:#00bceb; --poe:#f6b93b; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.14; }
.wrap{ max-width:1360px; margin:0 auto; padding:18px 20px 44px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.btn{ background:rgba(0,188,235,.14); border:1px solid rgba(0,188,235,.4); color:#bfeefb; border-radius:9px; padding:8px 14px; font-size:13px; cursor:pointer; }
.btn:hover{ background:rgba(0,188,235,.25); } .btn.ghost{ background:transparent; border-color:var(--border); color:#aab; } .btn.sm{ padding:3px 9px; font-size:11px; }
.muted{ color:#7c828c; font-size:12px; } .mono{ font-family:monospace; }
.sel{ background:#1b2129; color:#e6e9ee; border:1px solid var(--border); border-radius:8px; padding:8px 11px; font-size:13px; }
.stats{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:14px; }
.stat{ padding:11px 15px; } .stat .n{ font-size:24px; font-weight:800; line-height:1; } .stat .l{ font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; margin-top:4px; }
.stat .n.ok{ color:var(--ok);} .stat .n.poe{ color:var(--poe);} .stat .n.cisco{ color:var(--cisco);}
#panelWrap{ position:relative; height:340px; border-radius:14px; overflow:hidden; }
#panel{ width:100%; height:100%; display:block; }
#tip{ position:absolute; pointer-events:none; background:rgba(6,10,16,.92); border:1px solid var(--border); border-radius:8px; padding:7px 10px; font-size:11.5px; display:none; z-index:5; max-width:230px; }
.legend{ display:flex; gap:14px; flex-wrap:wrap; font-size:11px; color:#9aa1ab; margin-top:8px; }
.legend i{ width:10px; height:10px; border-radius:3px; display:inline-block; margin-right:5px; vertical-align:middle; }
.cols{ display:grid; grid-template-columns:1fr 340px; gap:16px; } @media(max-width:960px){ .cols{ grid-template-columns:1fr; } }
.pdetail .lab{ font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; } .pdetail .v{ font-size:14px; font-weight:700; margin-bottom:9px; }
.vchip{ display:inline-flex; align-items:center; gap:6px; font-size:11px; padding:4px 10px; border-radius:20px; border:1px solid var(--border); margin:3px 4px 3px 0; }
.dot{ width:8px; height:8px; border-radius:50%; display:inline-block; }
table{ width:100%; border-collapse:collapse; font-size:12.5px; } th{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; padding:5px 8px; border-bottom:1px solid var(--border);} td{ padding:5px 8px; border-bottom:1px solid rgba(255,255,255,.05);}
.pill-warn{ color:#f3c37b; } .fallback-grid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(46px,1fr)); gap:5px; }
.fp{ height:34px; border-radius:5px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; font-size:10px; font-weight:700; cursor:pointer; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fa-solid fa-ethernet"></i> Cisco Switches', '',
    'Live front-panel · PoE · VLAN map', 'fa-solid fa-ethernet',
    '<select id="swsel" class="sel" onchange="pick(this.value)"></select>
     <button class="btn ghost sm" onclick="repoll(this)"><i class="fas fa-rotate"></i> Re-poll</button>'); ?>

<div id="empty" class="glass card" style="display:none;">
  <div class="muted"><i class="fas fa-circle-info"></i> No Cisco <b>switch</b> detected yet. A node is treated as a switch when its
  model/name looks like a Catalyst/Nexus/switch. Once discovered, its ports appear here within 5&nbsp;minutes
  (<span class="mono">cron_cisco.php</span>). Health/CDP for all Cisco gear lives in <a href="cisco.php">Cisco Fleet</a>.</div>
</div>

<div id="live" style="display:none;">
  <div class="stats" id="stats"></div>
  <div class="cols">
    <div class="glass card" style="margin:0;">
      <div id="panelWrap">
        <canvas id="panel"></canvas>
        <div id="tip"></div>
      </div>
      <div class="legend">
        <span><i style="background:#2ecc71"></i>Up (glow = traffic)</span>
        <span><i style="background:#586172"></i>Link down</span>
        <span><i style="background:#20262e"></i>Admin down</span>
        <span><i style="background:var(--poe);border-radius:50%"></i>PoE</span>
        <span><i style="background:#00bceb"></i>Uplink</span>
        <span class="muted">drag to rotate · click a port</span>
      </div>
    </div>
    <div>
      <div class="glass card pdetail" id="pdetail" style="margin:0 0 14px;">
        <div class="muted">Click a port to inspect.</div>
      </div>
      <div class="glass card" id="vlanbox" style="margin:0;">
        <div class="muted" style="margin-bottom:8px;"><i class="fas fa-network-wired"></i> VLANs</div>
        <div id="vlans"><span class="muted">—</span></div>
      </div>
    </div>
  </div>
</div>

<script src="three.min.js"></script>
<script src="three-orbitcontrols.js"></script>
<script>
let SW=[], CUR=0, PORTS=[], TIMER=null, WEBGL=true;
let renderer,scene,camera,controls,raycaster,mouse,portMeshes=[],hovered=null,clock;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function fmtbps(b){ b=+b||0; if(b>=1e9)return (b/1e9).toFixed(2)+' Gb/s'; if(b>=1e6)return (b/1e6).toFixed(1)+' Mb/s'; if(b>=1e3)return (b/1e3).toFixed(0)+' Kb/s'; return b+' b/s'; }
function isUplink(p){ const n=(p.if_name||'').toLowerCase(); return (p.speed_mbps||0)>1000 || /ten|twenty|forty|hundred|sfp|xe-|te-/.test(n); }
function isAccess(p){ const n=(p.if_name||'').toLowerCase(); return (p.if_type===6 || /ethernet|fast|gig/.test(n)) && !isUplink(p); }

async function boot(){
  const r=await fetch('cisco_switch.php?api=switches').then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok){ return; }
  SW=r.switches;
  const sel=document.getElementById('swsel');
  if(!SW.length){ document.getElementById('empty').style.display='block'; sel.style.display='none'; return; }
  sel.innerHTML=SW.map(s=>`<option value="${s.id}">${esc(s.name)} — ${esc(s.hw||'switch')} (${s.ports} ports)</option>`).join('');
  document.getElementById('live').style.display='block';
  pick(SW[0].id);
}
function pick(id){ CUR=+id; if(TIMER)clearInterval(TIMER); loadPanel(); TIMER=setInterval(loadPanel,6000); }

async function loadPanel(){
  const r=await fetch('cisco_switch.php?api=panel&id='+CUR).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok) return;
  PORTS=r.ports||[];
  renderStats(r);
  renderVlans(r.vlans||[]);
  buildPanel();
}
function renderStats(r){
  const up=PORTS.filter(p=>p.oper_status==='up').length;
  const tot=PORTS.length;
  const cells=[
    ['n cisco',tot,'Ports'],
    ['n ok',up,'Up'],
    ['n',tot-up,'Down/idle'],
    ['n poe',r.poe.count,'PoE ports'],
    ['n poe',r.poe.watts+' W','PoE draw'],
    ['n',(r.vlans||[]).length,'VLANs'],
  ];
  document.getElementById('stats').innerHTML=cells.map(c=>`<div class="glass stat"><div class="${c[0]}">${c[1]}</div><div class="l">${c[2]}</div></div>`).join('');
}
function renderVlans(vl){
  const box=document.getElementById('vlans');
  if(!vl.length){ box.innerHTML='<span class="muted">No VLAN table (VTP) reported.</span>'; return; }
  box.innerHTML=vl.map(v=>`<span class="vchip"><span class="dot" style="background:${v.state==='active'?'var(--ok)':'#586172'}"></span>
     <b>${v.vlan_id}</b> ${esc(v.name||'')} <span class="muted">· ${v.port_count}p</span></span>`).join('');
}

// ── colour helpers ────────────────────────────────────────────────────────────
function portColor(p){
  if(p.admin_status==='down') return 0x20262e;
  if(p.oper_status!=='up')     return 0x586172;
  if(isUplink(p))              return 0x00bceb;
  return 0x2ecc71;
}
function portUtil(p){ // 0..1 for glow
  const sp=(p.speed_mbps||0)*1e6; const rate=Math.max(p.in_rate||0,p.out_rate||0);
  if(p.in_util!=null||p.out_util!=null) return Math.min(1,Math.max(p.in_util||0,p.out_util||0)/100);
  if(!sp||!rate) return 0; return Math.min(1, rate/sp);
}

// ── WebGL front-panel ─────────────────────────────────────────────────────────
function label(txt){
  const c=document.createElement('canvas'); c.width=64; c.height=32; const x=c.getContext('2d');
  x.fillStyle='#cfe8f2'; x.font='bold 20px Segoe UI'; x.textAlign='center'; x.textBaseline='middle';
  x.fillText(txt,32,16); const t=new THREE.CanvasTexture(c);
  const s=new THREE.Sprite(new THREE.SpriteMaterial({map:t,transparent:true})); s.scale.set(2.4,1.2,1); return s;
}
function initGL(){
  const canvas=document.getElementById('panel');
  try{ renderer=new THREE.WebGLRenderer({canvas,antialias:true,alpha:true}); }
  catch(e){ WEBGL=false; return; }
  const W=canvas.clientWidth||900,H=canvas.clientHeight||340;
  renderer.setPixelRatio(Math.min(2,devicePixelRatio)); renderer.setSize(W,H,false);
  scene=new THREE.Scene();
  camera=new THREE.PerspectiveCamera(42,W/H,0.1,500); camera.position.set(0,26,34); camera.lookAt(0,0,0);
  controls=new THREE.OrbitControls(camera,renderer.domElement);
  controls.enablePan=false; controls.minDistance=22; controls.maxDistance=70;
  controls.maxPolarAngle=Math.PI*0.49; controls.target.set(0,0,0);
  scene.add(new THREE.AmbientLight(0xffffff,0.7));
  const dl=new THREE.DirectionalLight(0xffffff,0.6); dl.position.set(10,30,20); scene.add(dl);
  raycaster=new THREE.Raycaster(); mouse=new THREE.Vector2(); clock=new THREE.Clock();
  canvas.addEventListener('mousemove',onMove); canvas.addEventListener('click',onClick);
  addEventListener('resize',resizeGL);
  animate();
}
function resizeGL(){ if(!renderer)return; const c=document.getElementById('panel'); const W=c.clientWidth,H=c.clientHeight; renderer.setSize(W,H,false); camera.aspect=W/H; camera.updateProjectionMatrix(); }
function buildPanel(){
  if(!renderer && WEBGL) initGL();
  if(!WEBGL){ fallbackPanel(); return; }
  if(!scene) return;
  portMeshes.forEach(m=>{ scene.remove(m.mesh); if(m.lbl)scene.remove(m.lbl); }); portMeshes=[];
  const access=PORTS.filter(isAccess).sort((a,b)=>trail(a)-trail(b));
  const uplinks=PORTS.filter(isUplink).sort((a,b)=>trail(a)-trail(b));
  const cols=Math.max(1,Math.ceil(access.length/2));
  const sx=1.9, gy=2.1, x0=-(cols-1)*sx/2, chassisW=cols*sx+4;
  // chassis
  const base=new THREE.Mesh(new THREE.BoxGeometry(chassisW+uplinks.length*1.6+3,1,7),
    new THREE.MeshStandardMaterial({color:0x0c1219,metalness:.6,roughness:.5}));
  base.position.set(0,-1.1,0); scene.add(base); portMeshes.push({mesh:base});
  const geo=new THREE.BoxGeometry(1.5,0.9,1.5);
  function place(p,x,y){
    const col=portColor(p);
    const mat=new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:0.15,metalness:.3,roughness:.4});
    const m=new THREE.Mesh(geo,mat); m.position.set(x,0,y); m.userData=p; scene.add(m);
    let ring=null;
    if(p.poe_status==='delivering'){
      ring=new THREE.Mesh(new THREE.TorusGeometry(1.15,0.09,8,24),new THREE.MeshBasicMaterial({color:0xf6b93b}));
      ring.rotation.x=Math.PI/2; ring.position.set(x,0.55,y); scene.add(ring);
    }
    portMeshes.push({mesh:m,ring:ring,data:p});
  }
  access.forEach((p,i)=>{ const col=Math.floor(i/2), row=i%2; place(p, x0+col*sx, row?1.1:-1.1); });
  const ux0=x0+cols*sx+2.2;
  uplinks.forEach((p,i)=>{ place(p, ux0+i*1.8, 0); });
}
function trail(p){ const m=(p.if_name||'').match(/(\d+)\s*$/); return m?+m[1]:0; }
function fallbackPanel(){
  const wrap=document.getElementById('panelWrap');
  const cells=PORTS.slice().sort((a,b)=>trail(a)-trail(b)).map(p=>{
    const c='#'+portColor(p).toString(16).padStart(6,'0');
    return `<div class="fp" style="border-color:${c};box-shadow:0 0 8px ${c}55" title="${esc(p.if_name||'')}" onclick="showPortByIfx(${+p.if_index||0})">${trail(p)||''}</div>`;
  }).join('');
  wrap.innerHTML=`<div style="padding:14px;height:100%;overflow:auto"><div class="muted" style="margin-bottom:8px">WebGL unavailable — grid view</div><div class="fallback-grid">${cells}</div></div>`;
}
function onMove(e){
  if(!renderer)return; const r=renderer.domElement.getBoundingClientRect();
  mouse.x=((e.clientX-r.left)/r.width)*2-1; mouse.y=-((e.clientY-r.top)/r.height)*2+1;
  raycaster.setFromCamera(mouse,camera);
  const hits=raycaster.intersectObjects(portMeshes.filter(m=>m.data).map(m=>m.mesh));
  const tip=document.getElementById('tip');
  if(hits.length){ const p=hits[0].object.userData;
    tip.style.display='block'; tip.style.left=(e.clientX-r.left+12)+'px'; tip.style.top=(e.clientY-r.top+12)+'px';
    tip.innerHTML=`<b>${esc(p.if_name||'')}</b><br>${esc(p.oper_status||'?')} · ${p.speed_mbps||'?'} Mb/s${p.vlan?(' · VLAN '+p.vlan):''}<br>▲ ${fmtbps(p.out_rate)} ▼ ${fmtbps(p.in_rate)}`;
  } else tip.style.display='none';
}
function onClick(){
  const hits=raycaster.intersectObjects(portMeshes.filter(m=>m.data).map(m=>m.mesh));
  if(hits.length) showPort(hits[0].object.userData);
}
function showPortByIfx(ifx){ const p=PORTS.find(x=>(+x.if_index)===(+ifx)); if(p) showPort(p); }
function showPort(p){
  const d=document.getElementById('pdetail');
  const row=(l,v)=>`<div class="lab">${l}</div><div class="v">${v}</div>`;
  d.innerHTML=`<div style="font-size:15px;font-weight:800;margin-bottom:10px">${esc(p.if_name||('if'+p.if_index))}</div>`+
    row('State',`${esc(p.oper_status||'?')} / admin ${esc(p.admin_status||'?')}`)+
    row('Speed / Duplex',`${p.speed_mbps||'?'} Mb/s · ${esc(p.duplex||'?')}`)+
    row('VLAN',p.vlan||'—')+
    row('PoE',p.poe_status?`${esc(p.poe_status)}${p.poe_watts?(' · '+p.poe_watts+' W'):''}`:'—')+
    row('Traffic',`▲ ${fmtbps(p.out_rate)} &nbsp; ▼ ${fmtbps(p.in_rate)}`);
}
function animate(){
  if(!renderer)return; requestAnimationFrame(animate);
  const t=clock?clock.getElapsedTime():0;
  portMeshes.forEach(m=>{ if(!m.data)return;
    const u=portUtil(m.data); const on=m.data.oper_status==='up';
    m.mesh.material.emissiveIntensity = on ? (0.25 + u*0.9*(0.6+0.4*Math.sin(t*3+m.mesh.position.x))) : 0.05;
    if(m.ring){ m.ring.material.color.setHSL(0.11,1,0.5+0.1*Math.sin(t*4)); }
  });
  if(controls)controls.update();
  renderer.render(scene,camera);
}

async function repoll(btn){
  const old=btn.innerHTML; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i>'; btn.disabled=true;
  await fetch('cisco_switch.php?api=repoll&id='+CUR).then(r=>r.json()).catch(()=>null);
  btn.innerHTML=old; btn.disabled=false; loadPanel();
}
boot();
</script>
</body></html>
