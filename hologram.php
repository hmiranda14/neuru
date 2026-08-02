<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Traffic Hologram (Volumetric Digital Twin, F1 · Phase 1).
// A 3D gemelo digital where bandwidth is VOLUMETRIC: GPU particle streams flow
// through virtual cables — density ∝ throughput, color = the app that's flowing.
// Reuses net_mon_map.php?api=topo (authoritative nodes+links+live rates+status)
// VERBATIM and adds ?api=enrich (per-node NetFlow app color) from nm_hologram.php.
// Read-only. three.js is self-hosted (CSP script-src 'self'). RBAC: 'hologram'.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_hologram.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'hologram')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=hologram'); exit;
}
nm_holo_ensure($conn);
if (function_exists('session_write_close')) @session_write_close();

if ($api === 'enrich') {
    header('Content-Type: application/json; charset=utf-8');
    $s = nm_holo_settings($conn);
    echo json_encode(nm_holo_enrich($conn, $s['window_min']) + ['settings' => $s]);
    exit;
}
if ($api === 'node') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(nm_holo_node_detail($conn, (int)($_GET['id'] ?? 0)));
    exit;
}
$SET = nm_holo_settings($conn);
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Traffic Hologram · 3D Twin | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cyan:#22d3ee; --border:rgba(255,255,255,.12); }
*,*::before,*::after{ box-sizing:border-box; }
html{ background:#04050c; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#e6e9ee; }
<?= nm_chrome_css() ?>
/* ── full-bleed 3D stage ─────────────────────────────────────────────────── */
/* transparent stage → the site's NMNetBG particle background (fixed, z-index:-1, mounted by
   header.php) shows through for visual consistency with the rest of the portal. Only a soft top
   glow is layered on top; the WebGL canvas clears with alpha 0. */
#holo-stage{ position:relative; width:100%; height:calc(100vh - 74px); min-height:520px; overflow:hidden;
  background:radial-gradient(1200px 700px at 50% 0%, rgba(40,70,140,.16), transparent 72%); }
#holo-stage:fullscreen{ height:100vh; }
#holo-canvas{ position:absolute; inset:0; display:block; z-index:1; }
.holo-hud{ position:absolute; z-index:6; pointer-events:none; }
.holo-hud .glass{ background:rgba(9,13,24,.62); backdrop-filter:blur(12px); border:1px solid var(--border); border-radius:12px; pointer-events:auto; }
/* title / legend top-left */
#holo-top{ top:14px; left:14px; max-width:340px; }
#holo-top .glass{ padding:12px 14px; }
#holo-title{ font-size:15px; font-weight:800; letter-spacing:.4px; display:flex; align-items:center; gap:9px; }
#holo-title i{ color:var(--cyan); }
#holo-sub{ font-size:11px; color:#8a909a; margin-top:2px; }
#holo-legend{ margin-top:10px; display:flex; flex-direction:column; gap:5px; max-height:34vh; overflow:auto; }
#holo-filter{ top:14px; left:366px; max-width:min(560px,44vw); }
#holo-filter .glass{ padding:10px 13px; }
.ftitle{ font-size:11px; color:#9db4d6; text-transform:uppercase; letter-spacing:.5px; display:flex; align-items:center; gap:7px; }
.fchips{ display:flex; flex-wrap:wrap; gap:6px; margin-top:8px; max-height:150px; overflow:auto; }
.fchip{ font-size:11px; padding:3px 10px; border-radius:20px; border:1px solid rgba(255,255,255,.14); color:#c3ccd8; cursor:pointer; opacity:.6; white-space:nowrap; user-select:none; }
.fchip:hover{ opacity:.9; } .fchip.on{ opacity:1; background:rgba(54,227,208,.14); border-color:rgba(54,227,208,.5); color:#bff2ee; }
.fchip.all.on{ background:rgba(77,163,255,.16); border-color:rgba(77,163,255,.55); color:#bcd8ff; }
@media(max-width:820px){ #holo-filter{ left:14px; top:auto; bottom:120px; max-width:70vw; } }
.leg{ display:flex; align-items:center; gap:8px; font-size:12px; }
.leg .sw{ width:11px; height:11px; border-radius:50%; box-shadow:0 0 8px currentColor; }
/* stats top-right */
#holo-stats{ top:14px; right:14px; }
#holo-stats .glass{ padding:10px 14px; display:flex; gap:16px; }
.hstat{ text-align:center; } .hstat .n{ font-size:20px; font-weight:800; line-height:1; } .hstat .l{ font-size:9px; color:#8a909a; text-transform:uppercase; letter-spacing:.6px; margin-top:3px; }
.hstat .n.ok{ color:#7af3b0; } .hstat .n.crit{ color:#ff9b91; } .hstat .n.cyan{ color:var(--cyan); }
/* controls — vertical stack top-right (under the stats), clear of the bottom-right Copilot wand */
#holo-ctl{ top:80px; right:14px; display:flex; flex-direction:column; gap:8px; }
.hbtn{ pointer-events:auto; background:rgba(10,16,28,.78); border:1px solid var(--border); color:#cfe4ff; border-radius:9px;
  min-width:38px; height:36px; padding:0 12px; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:7px; font-size:13px; }
.hbtn:hover{ border-color:var(--accent); color:#fff; }
.hbtn.on{ border-color:var(--cyan); color:#fff; background:rgba(34,211,238,.16); }
/* hint bottom-left */
#holo-hint{ bottom:16px; left:16px; font-size:11px; color:#8a909a; }
#holo-hint .glass{ padding:7px 12px; }
/* node dossier — full-height slide-in drawer on the LEFT (least-crowded edge), scrollable */
#holo-info{ position:absolute; z-index:12; left:0; top:0; height:100%; width:400px; max-width:88vw;
  display:none; transform:translateX(-12px); }
#holo-info .glass{ height:100%; border-radius:0 16px 16px 0; border-left:none; padding:0; display:flex; flex-direction:column;
  box-shadow:24px 0 60px rgba(0,0,0,.45); background:rgba(8,12,22,.90); }
#holo-dh{ padding:14px 16px 12px; border-bottom:1px solid var(--border); position:relative; }
#holo-dh h3{ margin:0; font-size:16px; display:flex; align-items:center; gap:9px; padding-right:24px; }
#holo-dh .meta{ font-size:12px; color:#9aa3af; margin-top:4px; }
#holo-dh .x{ position:absolute; top:12px; right:12px; cursor:pointer; color:#9aa3af; font-size:15px; }
#holo-dh .x:hover{ color:#fff; }
#holo-db{ padding:12px 16px 20px; overflow-y:auto; flex:1; }
#holo-db::-webkit-scrollbar{ width:8px; } #holo-db::-webkit-scrollbar-thumb{ background:rgba(255,255,255,.12); border-radius:8px; }
/* quick stat grid */
.dgrid{ display:grid; grid-template-columns:repeat(3,1fr); gap:8px; margin-bottom:14px; }
.dcell{ background:rgba(255,255,255,.04); border:1px solid var(--border); border-radius:9px; padding:8px 9px; }
.dcell .l{ font-size:9px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; }
.dcell .v{ font-size:15px; font-weight:700; margin-top:2px; }
/* section */
.dsec{ margin:16px 0 6px; font-size:11px; text-transform:uppercase; letter-spacing:.7px; color:#7fd3ff; display:flex; align-items:center; gap:7px; }
.dsec .cnt{ color:#6b7686; font-weight:400; }
.ditem{ background:rgba(255,255,255,.03); border:1px solid var(--border); border-left:3px solid #5a6577; border-radius:8px; padding:8px 10px; margin-bottom:7px; font-size:12px; }
.ditem .t{ font-weight:600; color:#e6e9ee; display:flex; justify-content:space-between; gap:8px; }
.ditem .d{ color:#9aa3af; margin-top:3px; line-height:1.4; word-break:break-word; }
.ditem.crit{ border-left-color:#e74c3c; } .ditem.warn{ border-left-color:#f3b52c; }
.ditem.info{ border-left-color:#4da3ff; } .ditem.ok{ border-left-color:#2ee6a0; } .ditem.ai{ border-left-color:#9b6bff; }
.dbadge{ font-size:9px; padding:2px 6px; border-radius:20px; background:rgba(255,255,255,.08); color:#cfd6e0; white-space:nowrap; }
.dbadge.crit{ background:rgba(231,76,60,.2); color:#ff9b91; } .dbadge.warn{ background:rgba(243,181,44,.2); color:#ffd479; }
.dbadge.ok{ background:rgba(46,230,160,.18); color:#7af3b0; } .dbadge.done{ background:rgba(46,230,160,.18); color:#7af3b0; }
.dbadge.denied,.dbadge.failed{ background:rgba(231,76,60,.2); color:#ff9b91; } .dbadge.proposed{ background:rgba(243,181,44,.2); color:#ffd479; }
.dmuted{ color:#6b7686; font-size:12px; padding:2px 0 4px; }
.dlog{ font-family:monospace; font-size:11px; padding:5px 8px; border-radius:6px; background:rgba(255,255,255,.03); margin-bottom:4px; line-height:1.35; }
.dlog .ts{ color:#6b7686; } .dlog.sev-crit{ color:#ff9b91; } .dlog.sev-warn{ color:#ffd479; } .dlog.sev-info{ color:#a9b4c2; }
#holo-dacts{ display:flex; gap:7px; flex-wrap:wrap; padding:12px 16px; border-top:1px solid var(--border); }
#holo-dacts a.act{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:8px; padding:7px 11px; font-size:12px; text-decoration:none; }
#holo-dacts a.act:hover{ border-color:var(--accent); color:#fff; }
#holo-dacts a.act.ai{ background:rgba(155,107,255,.16); border-color:rgba(155,107,255,.5); color:#d9c8ff; }
/* tooltip */
#holo-tip{ position:absolute; z-index:9; pointer-events:none; display:none; background:rgba(6,10,20,.92); border:1px solid var(--border);
  border-radius:7px; padding:6px 9px; font-size:12px; white-space:nowrap; transform:translate(-50%,-140%); }
#holo-tip b{ color:#fff; }
#holo-empty{ position:absolute; inset:0; display:none; align-items:center; justify-content:center; flex-direction:column; gap:10px; color:#8a909a; text-align:center; padding:24px; }
</style>
</head>
<body>
<?php include('header.php'); ?>

<div id="holo-stage">
  <canvas id="holo-canvas"></canvas>

  <div id="holo-top" class="holo-hud"><div class="glass">
    <div id="holo-title"><i class="fa-solid fa-cube"></i> Traffic Hologram</div>
    <div id="holo-sub">Volumetric digital twin — particles = live bandwidth, color = application</div>
    <div id="holo-legend"></div>
  </div></div>

  <div id="holo-filter" class="holo-hud" style="display:none;"><div class="glass">
    <div class="ftitle"><i class="fa-solid fa-filter"></i> Focus routers <span id="ffhint" style="text-transform:none;letter-spacing:0;color:#6f7a8c;font-weight:400;"></span></div>
    <div id="holo-filter-chips" class="fchips"></div>
  </div></div>

  <div id="holo-stats" class="holo-hud"><div class="glass">
    <div class="hstat"><div class="n ok" id="s-up">—</div><div class="l">Up</div></div>
    <div class="hstat"><div class="n crit" id="s-down">—</div><div class="l">Down</div></div>
    <div class="hstat"><div class="n" id="s-links">—</div><div class="l">Links</div></div>
    <div class="hstat"><div class="n cyan" id="s-thru">—</div><div class="l">Throughput</div></div>
  </div></div>

  <div id="holo-ctl" class="holo-hud">
    <button class="hbtn on" id="b-labels" title="Toggle labels (nodes + interface speeds)"><i class="fa-solid fa-tag"></i></button>
    <button class="hbtn" id="b-rt" title="⚡ Real-Time: live SNMP link speeds every 2s (SNMP v1/v2c)"><i class="fa-solid fa-gauge-high"></i></button>
    <button class="hbtn on" id="b-spin" title="Auto-rotate"><i class="fa-solid fa-arrows-rotate"></i></button>
    <button class="hbtn" id="b-fit" title="Reset view"><i class="fa-solid fa-crosshairs"></i></button>
    <button class="hbtn" id="b-full" title="Fullscreen"><i class="fa-solid fa-expand"></i></button>
  </div>

  <div id="holo-hint" class="holo-hud"><div class="glass"><i class="fa-solid fa-hand-pointer"></i> Drag to orbit · scroll to zoom · click a node to investigate</div></div>

  <div id="holo-info" class="holo-hud"><div class="glass">
    <div id="holo-dh">
      <span class="x" onclick="document.getElementById('holo-info').style.display='none'"><i class="fa-solid fa-xmark"></i></span>
      <h3 id="hi-name">—</h3>
      <div class="meta" id="hi-meta">—</div>
    </div>
    <div id="holo-db"><div class="dmuted">Loading node dossier…</div></div>
    <div id="holo-dacts"></div>
  </div></div>

  <div id="holo-tip"></div>
  <div id="holo-empty"><i class="fa-solid fa-cube" style="font-size:34px;opacity:.4;"></i>
    <div id="holo-empty-msg">Building the hologram…</div></div>
</div>

<script src="three.min.js"></script>
<script src="three-orbitcontrols.js"></script>
<script>
const HOLO_POLL = <?= (int)$SET['poll_sec'] ?> * 1000;
const PARTICLE_CAP = <?= (int)$SET['particle_cap'] ?>;

// ── WebGL support gate ───────────────────────────────────────────────────────
(function(){
  let ok=false; try{ const c=document.createElement('canvas'); ok=!!(window.WebGLRenderingContext && (c.getContext('webgl')||c.getContext('experimental-webgl'))); }catch(e){}
  if(!ok || typeof THREE==='undefined'){
    document.getElementById('holo-empty').style.display='flex';
    document.getElementById('holo-empty-msg').innerHTML='Your browser/GPU can\'t render WebGL.<br>Try the <a href="geomap.php" style="color:#6cf">Geo Wall</a> or <a href="net_mon_map.php" style="color:#6cf">Network Map</a> instead.';
    if(window.NMLoader) NMLoader.hide();
    throw new Error('no webgl');
  }
})();

// ── helpers ─────────────────────────────────────────────────────────────────
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
// timestamps stored in UTC → shown in the configured display tz (falls back to raw if tz JS absent)
function nl(ts){ try{ return window.nmTimeStr ? window.nmTimeStr(ts) : (ts||''); }catch(e){ return ts||''; } }
function fmtBps(bytesPerSec){ const b=(+bytesPerSec||0)*8; // → bits/sec
  if(b>=1e9) return (b/1e9).toFixed(2)+' Gb/s'; if(b>=1e6) return (b/1e6).toFixed(1)+' Mb/s';
  if(b>=1e3) return (b/1e3).toFixed(0)+' Kb/s'; return Math.round(b)+' b/s'; }
const STATUS_COLOR={ up:0x2ee6a0, degraded:0xf3b52c, lowerlayerdown:0xf3b52c, testing:0xf3b52c,
  down:0xe74c3c, notpresent:0x9aa3af, unknown:0x6b7686 };

// ── three.js scene ───────────────────────────────────────────────────────────
const stage=document.getElementById('holo-stage'), canvas=document.getElementById('holo-canvas');
const renderer=new THREE.WebGLRenderer({canvas,antialias:true,alpha:true});
renderer.setClearColor(0x000000,0);
const scene=new THREE.Scene();
scene.fog=new THREE.FogExp2(0x04050c,0.00055);   // light depth fade — keeps far particles visible
const camera=new THREE.PerspectiveCamera(55,1,1,6000);
camera.position.set(0,260,620);
const controls=new THREE.OrbitControls(camera,renderer.domElement);
controls.enableDamping=true; controls.dampingFactor=.08; controls.autoRotate=true; controls.autoRotateSpeed=.5;
controls.minDistance=90; controls.maxDistance=2600;
scene.add(new THREE.AmbientLight(0x8899cc,0.9));
const key=new THREE.PointLight(0x88bbff,0.7,0); key.position.set(300,500,400); scene.add(key);

// groups
const gNodes=new THREE.Group(), gLinks=new THREE.Group(), gLabels=new THREE.Group();
scene.add(gLinks); scene.add(gNodes); scene.add(gLabels);

// particle system (single Points for the whole scene)
const pGeom=new THREE.BufferGeometry();
const pPos=new Float32Array(PARTICLE_CAP*3), pCol=new Float32Array(PARTICLE_CAP*3),
      pAlpha=new Float32Array(PARTICLE_CAP), pSize=new Float32Array(PARTICLE_CAP);
pGeom.setAttribute('position',new THREE.BufferAttribute(pPos,3));
pGeom.setAttribute('aColor',new THREE.BufferAttribute(pCol,3));
pGeom.setAttribute('aAlpha',new THREE.BufferAttribute(pAlpha,1));
pGeom.setAttribute('aSize',new THREE.BufferAttribute(pSize,1));
const pMat=new THREE.ShaderMaterial({
  transparent:true, depthWrite:false, blending:THREE.AdditiveBlending,
  vertexShader:`attribute vec3 aColor; attribute float aAlpha; attribute float aSize; varying vec3 vC; varying float vA;
    void main(){ vC=aColor; vA=aAlpha; vec4 mv=modelViewMatrix*vec4(position,1.0);
      gl_PointSize=aSize*(360.0/max(1.0,-mv.z)); gl_Position=projectionMatrix*mv; }`,
  // brighter, punchier particles: a hot white-ish core fading to the app color, boosted for additive
  fragmentShader:`varying vec3 vC; varying float vA;
    void main(){ float d=length(gl_PointCoord-vec2(0.5)); if(d>0.5) discard;
      float core=smoothstep(0.5,0.0,d); float a=core*vA; if(a<0.01) discard;
      vec3 col=mix(vC*1.9, vec3(1.0), pow(core,3.0)*0.55);   // saturated body + white-hot centre
      gl_FragColor=vec4(col, a); }`
});
const points=new THREE.Points(pGeom,pMat); points.frustumCulled=false; scene.add(points);

// ── state ────────────────────────────────────────────────────────────────────
let NODES=[], LINKS=[], POS={}, NODEMESH={}, LABELS={}, ENRICH={nodes:{},apps:{}};
let ALLNODES=[], ALLLINKS=[], FILTER=new Set(), FILTER_DIRTY=false, _filterBuilt=false;   // router focus filter
const ROUTER_OS=['mikrotik','routeros','router','cisco','juniper','arista','fortinet','fortigate','ubiquiti','edgeos','edgerouter','vyos','pfsense','opnsense'];
function isRouterNode(n){ return ROUTER_OS.includes(String(n.icon||n.os_icon||'').toLowerCase()); }
function filterTopo(){ if(!FILTER.size) return [ALLNODES, ALLLINKS];
  const vis=new Set([...FILTER]);
  ALLLINKS.forEach(l=>{ if(FILTER.has(String(l.source)))vis.add(String(l.target)); if(FILTER.has(String(l.target)))vis.add(String(l.source)); });
  return [ALLNODES.filter(n=>vis.has(String(n.id))), ALLLINKS.filter(l=>vis.has(String(l.source))&&vis.has(String(l.target)))]; }
function populateFilter(){ if(_filterBuilt) return; const routers=ALLNODES.filter(isRouterNode); if(routers.length<2){ return; } _filterBuilt=true;
  document.getElementById('holo-filter').style.display='block';
  document.getElementById('holo-filter-chips').innerHTML='<span class="fchip all on" data-r="all" onclick="toggleFilter(\'all\')">◎ All</span>'
    + routers.map(r=>`<span class="fchip" data-r="${esc(String(r.id))}" onclick="toggleFilter('${esc(String(r.id))}')">${esc(r.name||('node '+r.id))}</span>`).join(''); }
function toggleFilter(id){ if(id==='all'){ FILTER.clear(); } else { id=String(id); if(FILTER.has(id))FILTER.delete(id); else FILTER.add(id); }
  document.querySelectorAll('#holo-filter-chips .fchip').forEach(c=>{ const r=c.dataset.r; c.classList.toggle('on', r==='all'?FILTER.size===0:FILTER.has(r)); });
  document.getElementById('ffhint').textContent = FILTER.size? ('· '+FILTER.size+' selected + connected devices') : '· all nodes';
  refilter(); }
function refilter(){ FILTER_DIRTY=true; const [fn,fl]=filterTopo(); NODES=fn; LINKS=fl; if(WEBGL){ rebuild(); fitView(); } renderHUD(); FILTER_DIRTY=false; }
let PART=[];              // per-particle: {link, dir, phase}
let LINKR=[];             // per-link runtime: {a,b,rate,norm,pool0,pool,active,speed,color}
let USED=0, MAXRATE=1, spin=true, showLabels=true, built=false;

function labelSprite(text,color){
  const c=document.createElement('canvas'), ct=c.getContext('2d'); const f=42;
  ct.font=`600 ${f}px Segoe UI,sans-serif`; const w=Math.ceil(ct.measureText(text).width)+20;
  c.width=w; c.height=f+18; ct.font=`600 ${f}px Segoe UI,sans-serif`;
  ct.fillStyle='rgba(6,10,20,.55)'; ct.fillRect(0,0,w,c.height);
  ct.fillStyle=color||'#dfe7f2'; ct.textBaseline='middle'; ct.fillText(text,10,c.height/2);
  const tex=new THREE.CanvasTexture(c); tex.minFilter=THREE.LinearFilter;
  const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:tex,transparent:true,depthWrite:false}));
  sp.scale.set(w*0.16,c.height*0.16,1); return sp;
}

// ── interface + live speed labels on the cables (redrawable for realtime) ──────
let LINKLABELS=[];         // {sprite,canvas,ctx,tex,link,redraw()}
let rtMode=false, rtTimer=null;
function fmtBps(b){ b=+b||0; if(b<=0)return '0'; const u=['B','K','M','G']; let i=0; while(b>=1024&&i<3){b/=1024;i++;} return b.toFixed(b<10&&i>0?1:0)+u[i]+'/s'; }
function makeLinkLabel(){
  const c=document.createElement('canvas'); c.width=340; c.height=112; const ct=c.getContext('2d');
  const tex=new THREE.CanvasTexture(c); tex.minFilter=THREE.LinearFilter;
  const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:tex,transparent:true,depthWrite:false,depthTest:false}));
  sp.scale.set(340*0.075,112*0.075,1);
  const o={sprite:sp,tex,link:null,
    redraw(ifn,inR,outR){ ct.clearRect(0,0,c.width,c.height); ct.textAlign='center'; ct.textBaseline='middle';
      if(ifn){ ct.font='600 30px Segoe UI,sans-serif'; ct.fillStyle='#9fb6d8'; ct.fillText(String(ifn).slice(0,18),170,26); }
      ct.font='bold 34px Segoe UI,sans-serif';
      ct.textAlign='right'; ct.fillStyle='#4bd6ff'; ct.fillText('↓'+fmtBps(inR),166,76);
      ct.textAlign='left';  ct.fillStyle='#39d98a'; ct.fillText('↑'+fmtBps(outR),178,76);
      tex.needsUpdate=true; }};
  return o;
}
function updateLinkLabels(){ LINKLABELS.forEach(ll=>{
  // prefer the CURRENT link object via LINKR (re-pointed on every topo refresh) — reading ll.link
  // directly goes stale after a refresh swaps the LINKS array, which froze the realtime values.
  const l=(ll.li!=null && LINKR[ll.li] && LINKR[ll.li].link) || ll.link; if(!l)return;
  ll.redraw((l.tgt_if&&l.tgt_if.name)||(l.src_if&&l.src_if.name)||l.label||'', +l.in_rate||0, +l.out_rate||0); }); }

// deterministic 3D force layout (spring-electrical), seeded on a sphere by index.
function computeLayout(nodes,links){
  const idset={}; nodes.forEach((n,i)=>idset[n.id]=i);
  const p=nodes.map((n,i)=>{ const g=2.399963*i, y=1-(i/Math.max(1,nodes.length-1))*2;
    const r=Math.sqrt(Math.max(0,1-y*y)); return new THREE.Vector3(Math.cos(g)*r,y,Math.sin(g)*r).multiplyScalar(260); });
  const edges=links.filter(l=>idset[l.source]!=null&&idset[l.target]!=null).map(l=>[idset[l.source],idset[l.target]]);
  const K=190, iters=260;
  for(let it=0; it<iters; it++){
    const disp=p.map(()=>new THREE.Vector3());
    for(let i=0;i<p.length;i++) for(let j=i+1;j<p.length;j++){
      const d=new THREE.Vector3().subVectors(p[i],p[j]); let len=d.length()||0.01;
      const f=(K*K)/len/len*260; d.multiplyScalar(f/len); disp[i].add(d); disp[j].sub(d);
    }
    for(const [a,b] of edges){ const d=new THREE.Vector3().subVectors(p[a],p[b]); const len=d.length()||0.01;
      const f=len*len/K/40; d.multiplyScalar(f/len); disp[a].sub(d); disp[b].add(d); }
    const cool=1-it/iters;
    for(let i=0;i<p.length;i++){ const dl=disp[i].length()||0.01; p[i].add(disp[i].multiplyScalar(Math.min(dl,22*cool)/dl)); }
  }
  const out={}; nodes.forEach((n,i)=>out[n.id]=p[i]); return out;
}

function rebuild(){
  // clear
  [gNodes,gLinks,gLabels].forEach(g=>{ while(g.children.length) g.remove(g.children[0]); });
  NODEMESH={}; LABELS={}; LINKR=[]; PART=[]; USED=0; LINKLABELS=[];
  if(!NODES.length){ document.getElementById('holo-empty').style.display='flex';
    document.getElementById('holo-empty-msg').textContent='No nodes to render yet.'; return; }
  document.getElementById('holo-empty').style.display='none';
  POS=computeLayout(NODES,LINKS);

  // nodes + labels
  const nGeo=new THREE.SphereGeometry(7,20,20);
  NODES.forEach(n=>{
    const col=STATUS_COLOR[n.status]||STATUS_COLOR.unknown;
    const m=new THREE.Mesh(nGeo,new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:.9,roughness:.35,metalness:.2}));
    m.position.copy(POS[n.id]); m.userData=n; gNodes.add(m); NODEMESH[n.id]=m;
    // glow halo — also carries the node userData so it's a generous click target (it sits in
    // front of the smaller core sphere, so the raycaster hits it first).
    const halo=new THREE.Mesh(new THREE.SphereGeometry(13,16,16),
      new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:.22,blending:THREE.AdditiveBlending,depthWrite:false}));
    halo.position.copy(POS[n.id]); halo.userData=n; gNodes.add(halo);
    const lab=labelSprite(n.name||('node '+n.id));
    lab.position.copy(POS[n.id]).add(new THREE.Vector3(0,16,0)); lab.visible=showLabels; gLabels.add(lab); LABELS[n.id]=lab;
  });

  // links: cable + particle allocation proportional to rate
  MAXRATE=1; LINKS.forEach(l=>{ MAXRATE=Math.max(MAXRATE,(+l.in_rate||0)+(+l.out_rate||0)); });
  const logMax=Math.log(1+MAXRATE);
  // budget particles across links by their rate share
  LINKS.forEach(l=>{
    if(!POS[l.source]||!POS[l.target]) return;
    const a=POS[l.source], b=POS[l.target];
    const rate=(+l.in_rate||0)+(+l.out_rate||0);
    const norm=logMax>0?Math.log(1+rate)/logMax:0;
    // cable
    const cg=new THREE.BufferGeometry().setFromPoints([a,b]);
    const cable=new THREE.Line(cg,new THREE.LineBasicMaterial({color:0x2b3b63,transparent:true,opacity:.5}));
    cable.userData={link:l}; gLinks.add(cable);
    // color from busier endpoint's app (fallback cyan)
    const ea=ENRICH.nodes[l.source], eb=ENRICH.nodes[l.target];
    const inR=+l.in_rate||0, outR=+l.out_rate||0;
    const appHex=(outR>=inR? (ea&&ea.color) : (eb&&eb.color)) || (ea&&ea.color) || (eb&&eb.color) || '#22d3ee';
    const col=new THREE.Color(appHex);
    const pool=Math.max(8,Math.round(28+norm*260));   // busier link → bigger pool
    LINKR.push({a,b,rate,norm,pool0:USED,pool:0,active:0,speed:0,color:col,inR,outR,link:l});
    const li=LINKR.length-1;
    for(let k=0;k<pool && USED<PARTICLE_CAP;k++){
      const dir=(k%2===0)?1:-1;                        // half out (a→b), half in (b→a)
      PART.push({link:li,dir, phase:Math.random()});
      pCol[USED*3]=col.r; pCol[USED*3+1]=col.g; pCol[USED*3+2]=col.b;
      pSize[USED]=3.6+norm*3.8; pAlpha[USED]=0;
      USED++;
    }
    LINKR[li].pool=USED-LINKR[li].pool0;
    // interface + live ↓/↑ speed label at the cable midpoint
    const ifn=(l.tgt_if&&l.tgt_if.name)||(l.src_if&&l.src_if.name)||l.label||'';
    if(ifn || inR>0 || outR>0){ const ll=makeLinkLabel(); ll.link=l; ll.li=li; ll.redraw(ifn,inR,outR);
      ll.sprite.position.copy(a.clone().lerp(b,0.5)).add(new THREE.Vector3(0,6,0)); ll.sprite.visible=showLabels;
      gLabels.add(ll.sprite); LINKLABELS.push(ll); }
  });
  pGeom.setDrawRange(0,USED);
  pGeom.attributes.aColor.needsUpdate=true; pGeom.attributes.aSize.needsUpdate=true;
  applyRates();
  built=true;
  if(window.NMLoader) NMLoader.hide();
  if(!fitDone){ fitView(); fitDone=true; }
}

// map live rates → per-link active particle count + speed + brightness (called each poll)
function applyRates(){
  LINKR.forEach(L=>{
    const l=L.link, rate=(+l.in_rate||0)+(+l.out_rate||0);
    const norm=Math.log(1+rate)/Math.max(0.001,Math.log(1+MAXRATE));
    L.rate=rate; L.norm=norm;
    L.active=Math.max(rate>0?3:0, Math.round(L.pool*Math.pow(norm,0.7)));
    L.speed=0.06+norm*0.5;                    // faster where busier
    const bright=0.55+norm*0.95;              // vivid even on quiet links; blazing on busy ones
    for(let k=0;k<L.pool;k++){ const idx=L.pool0+k; pAlpha[idx]=(k<L.active)?bright:0; }
  });
  pGeom.attributes.aAlpha.needsUpdate=true;
}

// ── animation ────────────────────────────────────────────────────────────────
let fitDone=false, hidden=false, lastT=performance.now();
const _a=new THREE.Vector3(),_b=new THREE.Vector3();
function animate(now){
  requestAnimationFrame(animate);
  if(hidden) return;
  const dt=Math.min(0.05,(now-lastT)/1000); lastT=now;
  controls.autoRotate=spin; controls.update();
  // advance particles
  for(let i=0;i<USED;i++){
    const P=PART[i], L=LINKR[P.link]; if(!L) continue;
    const k=i-L.pool0; if(k>=L.active){ continue; }   // inactive → frozen/hidden (alpha 0)
    P.phase+=L.speed*dt; if(P.phase>1) P.phase-=1;
    const t=(P.dir>0)?P.phase:(1-P.phase);
    _a.copy(L.a); _b.copy(L.b);
    pPos[i*3]  =_a.x+(_b.x-_a.x)*t;
    pPos[i*3+1]=_a.y+(_b.y-_a.y)*t;
    pPos[i*3+2]=_a.z+(_b.z-_a.z)*t;
  }
  pGeom.attributes.position.needsUpdate=true;
  renderer.render(scene,camera);
}

// ── data load ────────────────────────────────────────────────────────────────
async function loadScene(first){
  let topo=null, enr=null;
  try{ [topo,enr]=await Promise.all([
    fetch('net_mon_map.php?api=topo&_='+Date.now()).then(r=>r.json()),
    fetch('hologram.php?api=enrich&_='+Date.now()).then(r=>r.json())
  ]); }catch(e){ return; }
  if(!topo||!topo.nodes) return;
  ENRICH=enr&&enr.nodes?enr:{nodes:{},apps:{}};
  ALLNODES=topo.nodes; ALLLINKS=topo.links; populateFilter();
  const [fn,fl]=filterTopo();
  const sameShape = built && !FILTER_DIRTY && NODES.length===fn.length && LINKS.length===fl.length;
  NODES=fn; LINKS=fl;
  if(!sameShape){ rebuild(); } else {
    // fast path: same topology → just refresh rates + node status colors
    LINKS.forEach((l,i)=>{ if(LINKR[i]) LINKR[i].link=l; });
    NODES.forEach(n=>{ const m=NODEMESH[n.id]; if(m){ const c=STATUS_COLOR[n.status]||STATUS_COLOR.unknown; m.material.color.setHex(c); m.material.emissive.setHex(c);} });
    if(rtMode){ rtPollHolo(); }              // ⚡ realtime owns the rates → re-apply (particles + labels); don't let the cron snapshot clobber it
    else { applyRates(); updateLinkLabels(); }   // cron refresh → reflect the new rates in particles AND labels
  }
  renderHUD();
}

function renderHUD(){
  let up=0,down=0,thru=0;
  NODES.forEach(n=>{ if(n.status==='up') up++; else if(n.status==='down') down++; });
  LINKS.forEach(l=>{ thru+=(+l.in_rate||0)+(+l.out_rate||0); });
  document.getElementById('s-up').textContent=up;
  document.getElementById('s-down').textContent=down;
  document.getElementById('s-links').textContent=LINKS.length;
  document.getElementById('s-thru').textContent=fmtBps(thru);
  // legend from enrich apps
  const apps=ENRICH.apps||{}; const keys=Object.keys(apps).slice(0,14);
  const leg=document.getElementById('holo-legend');
  leg.innerHTML=keys.length? keys.map(a=>`<div class="leg"><span class="sw" style="background:${apps[a]};color:${apps[a]}"></span>${esc(a)}</div>`).join('')
    : '<div class="leg" style="color:#6b7686">No NetFlow app data yet — streams show volume.</div>';
}

// ── interaction (raycast) ─────────────────────────────────────────────────────
const ray=new THREE.Raycaster(); ray.params.Points.threshold=6; const mouse=new THREE.Vector2();
function pick(ev){ const r=canvas.getBoundingClientRect();
  mouse.x=((ev.clientX-r.left)/r.width)*2-1; mouse.y=-((ev.clientY-r.top)/r.height)*2+1;
  ray.setFromCamera(mouse,camera); return ray.intersectObjects(gNodes.children,false); }
canvas.addEventListener('mousemove',ev=>{
  const hit=pick(ev); const tip=document.getElementById('holo-tip');
  if(hit.length && hit[0].object.userData && hit[0].object.userData.id){
    const n=hit[0].object.userData; tip.style.display='block'; tip.style.left=ev.clientX+'px'; tip.style.top=(ev.clientY-6)+'px';
    tip.innerHTML=`<b>${esc(n.name)}</b> · ${esc(n.ip||'')}<br>${esc((n.status||'').toUpperCase())}`;
    canvas.style.cursor='pointer';
  } else { tip.style.display='none'; canvas.style.cursor='grab'; }
});
canvas.addEventListener('click',ev=>{
  const hit=pick(ev);
  if(hit.length && hit[0].object.userData && hit[0].object.userData.id){ openInfo(hit[0].object.userData); }
});
function dcell(l,v){ return `<div class="dcell"><div class="l">${esc(l)}</div><div class="v">${esc(v)}</div></div>`; }
function dsec(icon,label,cnt){ return `<div class="dsec"><i class="fa-solid fa-${icon}"></i> ${esc(label)} <span class="cnt">${cnt||0}</span></div>`; }
function sevCls(s){ s=(s||'').toLowerCase(); if(s.startsWith('crit'))return'crit'; if(s.startsWith('warn'))return'warn'; if(s==='info')return'info'; return ''; }
function ditem(sev,title,detailHtml,extraCls){ const c=extraCls||sevCls(sev);
  return `<div class="ditem ${c}"><div class="t"><span>${esc(title||'—')}</span>${sev?`<span class="dbadge ${sevCls(sev)}">${esc(sev)}</span>`:''}</div>${detailHtml?`<div class="d">${detailHtml}</div>`:''}</div>`; }
function upStr(sec){ sec=+sec; if(!sec)return'—'; const d=Math.floor(sec/86400),h=Math.floor(sec%86400/3600),m=Math.floor(sec%3600/60);
  return d>0? (d+'d '+h+'h') : (h+'h '+m+'m'); }

async function openInfo(n){
  const box=document.getElementById('holo-info'); box.style.display='block';
  const sc='#'+((STATUS_COLOR[n.status]||0x6b7686).toString(16).padStart(6,'0'));
  document.getElementById('hi-name').innerHTML=`<i class="fa-solid fa-circle" style="font-size:11px;color:${sc}"></i> ${esc(n.name)}`;
  document.getElementById('hi-meta').textContent=(n.ip||'')+(n.status?(' · '+n.status.toUpperCase()):'');
  const body=document.getElementById('holo-db'); body.innerHTML='<div class="dmuted">Loading node dossier…</div>';
  document.getElementById('holo-dacts').innerHTML='';
  let d=null, errTxt='';
  try{
    const resp=await fetch('hologram.php?api=node&id='+n.id+'&_='+Date.now());
    const txt=await resp.text();
    try{ d=JSON.parse(txt); }catch(pe){ errTxt='HTTP '+resp.status+' · non-JSON: '+txt.slice(0,220); }
  }catch(e){ errTxt='network: '+(e&&e.message||e); }
  if(!d||!d.ok){
    body.innerHTML='<div class="dmuted">Could not load node details.'+(errTxt?'<br><br><span style="color:#ff9b91;font-family:monospace;font-size:10px;word-break:break-all">'+esc(errTxt)+'</span>':'')+'</div>';
    return;
  }
  try{ body.innerHTML=renderDossier(d); }
  catch(re){ console.error('hologram dossier render error',re);
    body.innerHTML='<div class="dmuted">Render error: <span style="color:#ff9b91;font-family:monospace">'+esc(re&&re.message||re)+'</span></div>'; return; }
  const N=d.node, ip=encodeURIComponent(N.ip||'');
  document.getElementById('holo-dacts').innerHTML=
    `<a class="act ai" href="aiopilot.php"><i class="fa-solid fa-robot"></i> AI Command</a>`+
    `<a class="act" href="troubleshoot.php"><i class="fa-solid fa-stethoscope"></i> Investigate</a>`+
    `<a class="act" href="net_mon_stats.php?node=${N.id}"><i class="fa-solid fa-chart-bar"></i> Stats</a>`+
    `<a class="act" href="log_mon.php?node=${N.id}"><i class="fa-solid fa-file-lines"></i> Logs</a>`+
    (N.ip?`<a class="act" href="netflow.php?host=${ip}"><i class="fa-solid fa-chart-area"></i> NetFlow</a>`:'');
}

function renderDossier(d){
  const N=d.node, e=ENRICH.nodes[N.id]; let h='';
  h+='<div class="dgrid">'
    +dcell('Status',(N.status||'?').toUpperCase())
    +dcell('24h Uptime',N.avail_24h!=null?N.avail_24h+'%':'—')
    +dcell('Latency',N.latency_ms!=null?(Math.round(N.latency_ms*10)/10)+' ms':'—')
    +dcell('CPU',N.cpu!=null?Math.round(N.cpu)+'%':'—')
    +dcell('Memory',N.memory!=null?Math.round(N.memory)+'%':'—')
    +dcell('Uptime',N.uptime_sec?upStr(N.uptime_sec):'—')
    +'</div>';
  h+=`<div class="dmuted">${esc(N.os||'')} · ${esc(N.monitor_type||'')} · ${esc(N.subnet||'')}`
    +(e&&e.app?` · top app <span style="color:${e.color}">${esc(e.app)}</span>`:'')
    +(N.last_poll?` · polled ${esc(nl(N.last_poll))}`:'')+`</div>`;

  // NetAIObot — what the AI observed / proposed / auto-corrected
  h+=dsec('robot','NetAIObot activity',d.ai.sessions);
  if(d.ai.last){ const L=d.ai.last;
    h+=`<div class="ditem ai"><div class="t"><span>Last session</span><span class="dbadge ${esc(L.status)}">${esc(L.status)}</span></div>`
      +`<div class="d">${esc(L.summary||L.title||'')}</div><div class="d" style="color:#6b7686">${esc(nl(L.created_at))}</div></div>`;
  }
  if(d.ai.actions.length){ d.ai.actions.forEach(a=>{ const when=a.executed_at||a.proposed_at;
    h+=`<div class="ditem ai"><div class="t"><span>⚙️ ${esc(a.tool)} <span class="dbadge ${esc(a.status)}">${esc(a.status)}</span> <span class="dbadge">${esc(a.risk)}</span></span><span class="dbadge">${esc(a.trigger_kind||'')}</span></div>`
      +(a.reason?`<div class="d">${esc(a.reason)}</div>`:'')
      +(a.result?`<div class="d" style="font-family:monospace;font-size:11px;color:#8fd7b0">${esc(a.result)}</div>`:'')
      +`<div class="d" style="color:#6b7686">${esc(nl(when))}</div></div>`; });
  } else if(!d.ai.last){ h+='<div class="dmuted">No AI agent activity on this node yet. Add it in the AI Command Center to have NetAIObot watch it.</div>'; }

  h+=dsec('lightbulb','AI Insights',d.insights.length);
  if(d.insights.length) d.insights.forEach(i=>{ h+=ditem(i.severity,i.title,`${esc(i.kind||'')} · ${esc(i.source||'')} · ${esc(i.status)} · ${esc(nl(i.created_at))}`); });
  else h+='<div class="dmuted">No AI insights.</div>';

  h+=dsec('triangle-exclamation','Incidents affecting node',d.incidents.length);
  if(d.incidents.length) d.incidents.forEach(i=>{ h+=ditem(i.severity,i.title,`${esc(i.status)} · ${i.root_source?('root: '+esc(i.root_source)+' · '):''}${esc(nl(i.opened_at))}`); });
  else h+='<div class="dmuted">No open incidents.</div>';

  h+=dsec('heart-pulse','Predictive Health',d.health.length);
  if(d.health.length) d.health.forEach(x=>{ const eta=x.eta_days!=null?` ~${Math.round(x.eta_days)}d`:''; h+=ditem(x.severity,`${esc(x.metric)} — ${esc(x.kind)}${eta}`,esc(x.detail||x.direction||'')); });
  else h+='<div class="dmuted">No degradation forecast.</div>';

  h+=dsec('ethernet','Top interfaces',d.interfaces.length);
  if(d.interfaces.length) d.interfaces.forEach(f=>{ h+=`<div class="ditem ${f.oper_status==='up'?'ok':(f.oper_status==='down'?'crit':'')}"><div class="t"><span>${esc(f.name)}</span><span class="dbadge">${esc(f.oper_status||'')}</span></div><div class="d">▼ ${fmtBps(f.in_rate)} &nbsp; ▲ ${fmtBps(f.out_rate)}</div></div>`; });
  else h+='<div class="dmuted">No interface stats.</div>';

  h+=dsec('file-lines','Recent logs',d.logs.length);
  if(d.logs.length) d.logs.forEach(l=>{ const sv=(+l.severity<=3)?'sev-crit':(+l.severity===4?'sev-warn':'sev-info');
    h+=`<div class="dlog ${sv}"><span class="ts">${esc(nl(l.received_at))}</span> ${l.tag?('['+esc(l.tag)+'] '):''}${esc((l.message||'').slice(0,240))}</div>`; });
  else h+='<div class="dmuted">No recent logs matched this node\'s IP.</div>';

  return h;
}

// ── controls / chrome ─────────────────────────────────────────────────────────
function fitView(){ if(!NODES.length) return;
  const box=new THREE.Box3(); Object.values(POS).forEach(p=>box.expandByPoint(p));
  const c=box.getCenter(new THREE.Vector3()), sz=box.getSize(new THREE.Vector3());
  const r=Math.max(sz.x,sz.y,sz.z,120); controls.target.copy(c);
  camera.position.set(c.x, c.y+r*0.5, c.z+r*1.7); camera.near=1; camera.far=r*20; camera.updateProjectionMatrix(); }
document.getElementById('b-fit').onclick=()=>fitView();
document.getElementById('b-spin').onclick=e=>{ spin=!spin; e.currentTarget.classList.toggle('on',spin); };
document.getElementById('b-labels').onclick=e=>{ showLabels=!showLabels; e.currentTarget.classList.toggle('on',showLabels);
  Object.values(LABELS).forEach(l=>l.visible=showLabels); LINKLABELS.forEach(ll=>ll.sprite.visible=showLabels); };
// ⚡ REAL-TIME: live SNMP link sampling every 2s (reuses net_mon_map's rt engine)
document.getElementById('b-rt').onclick=e=>{ rtMode=!rtMode; e.currentTarget.classList.toggle('on',rtMode);
  if(rtMode){ clearInterval(rtTimer); rtTimer=setInterval(rtPollHolo,2000); rtPollHolo(); }
  else { clearInterval(rtTimer); rtTimer=null; } };
async function rtPollHolo(){
  if(!rtMode || !LINKS.length) return;
  const pidMap=new Map();
  LINKS.forEach(l=>{ const p=(l.tgt_if&&l.tgt_if.pid)||(l.src_if&&l.src_if.pid)||0; if(p){ if(!pidMap.has(p))pidMap.set(p,[]); pidMap.get(p).push(l); } });
  const pids=[...pidMap.keys()]; if(!pids.length) return;
  let d=null; try{ d=await fetch('net_mon_map.php?api=rt&pids='+pids.join(',')+'&_='+Date.now()).then(r=>r.json()); }catch(e){ return; }
  if(!d||!d.ok||!d.rt) return;
  pidMap.forEach((ls,pid)=>{ const r=d.rt[pid]; if(r){ ls.forEach(l=>{ if(r.in!=null)l.in_rate=r.in; if(r.out!=null)l.out_rate=r.out; }); } });
  MAXRATE=1; LINKS.forEach(l=>{ MAXRATE=Math.max(MAXRATE,(+l.in_rate||0)+(+l.out_rate||0)); });
  applyRates(); updateLinkLabels();
}
document.getElementById('b-full').onclick=()=>{ if(document.fullscreenElement) document.exitFullscreen(); else stage.requestFullscreen&&stage.requestFullscreen(); };

function resize(){ const w=stage.clientWidth,h=stage.clientHeight;
  renderer.setPixelRatio(Math.min(window.devicePixelRatio||1,2));
  renderer.setSize(w,h,false); camera.aspect=w/h; camera.updateProjectionMatrix(); }
window.addEventListener('resize',resize);
// Keep the site's NMNetBG particle canvas visible in fullscreen: it's position:fixed on <body>,
// so it vanishes when only #holo-stage is fullscreened. Move it INTO the stage while fullscreen
// (behind the WebGL canvas), and back to <body> on exit — preserving the normal page behaviour.
document.addEventListener('fullscreenchange',()=>{
  const bg=document.getElementById('nm-netbg');
  if(bg){ if(document.fullscreenElement===stage){ stage.insertBefore(bg,stage.firstChild); bg.style.zIndex='0'; }
          else { document.body.appendChild(bg); bg.style.zIndex='-1'; } }
  const i=document.querySelector('#b-full i'); if(i) i.className='fa-solid '+(document.fullscreenElement?'fa-compress':'fa-expand');
  setTimeout(()=>{ resize(); window.dispatchEvent(new Event('resize')); },80);
});
document.addEventListener('visibilitychange',()=>{ hidden=document.hidden; if(!hidden) lastT=performance.now(); });

// ── boot ──────────────────────────────────────────────────────────────────────
if(window.NMLoader) NMLoader.msg&&NMLoader.msg('Rendering hologram…');
resize(); animate(performance.now());
loadScene(true).then(()=>{ setInterval(()=>loadScene(false), HOLO_POLL); });
</script>
</body></html>
