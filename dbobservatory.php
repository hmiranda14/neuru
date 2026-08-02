<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Data Core Observatory (holographic DB twin). Every configured database is a
// living 3D REACTOR: the core pulses with running threads, an orbital ring fills with the
// connection pool (red when saturated), a GALAXY of table tiles (heatmap) spins around it
// (size = rows, colour = read↔write), a replication CONDUIT streams particles master→replica
// (green in-sync / amber behind / red thread-down), and locks freeze the core. Every visual
// maps to a TRUE Data Core signal. three.js self-hosted (CSP). RBAC: 'dbobs'. Read-mostly.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_dbobs.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'dbobs')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=dbobs'); exit;
}
nm_dbobs_ensure($conn);
if (function_exists('session_write_close')) @session_write_close();

if ($api) {
    header('Content-Type: application/json; charset=utf-8');
    $uid = (int)($_SESSION['user_id'] ?? 0) ?: null;
    try {
        switch ($api) {
            case 'scene':  echo json_encode(nm_dbobs_scene($conn, !empty($_GET['force']))); break;
            case 'detail': echo json_encode(nm_dbobs_detail($conn, (int)($_GET['id'] ?? 0))); break;
            case 'apply': {   // apply a whitelisted advice item (operator is here → clicking IS approval)
                $aid = (int)($_POST['advice'] ?? 0);
                $r = $conn->query("SELECT kind, ddl FROM nm_db_advice WHERE id=$aid LIMIT 1");
                $a = $r ? $r->fetch_assoc() : null;
                if (!$a) { echo json_encode(['ok'=>false,'error'=>'advice not found']); break; }
                if (!nm_db_advice_allowed_sql((string)$a['kind'], (string)$a['ddl'])) { echo json_encode(['ok'=>false,'error'=>'Manual-only DDL — apply it in Data Core.']); break; }
                $res = nm_db_apply_advice($conn, $aid, $uid);
                if (!empty($res['ok']) && is_file(__DIR__.'/nm_biosphere.php')) { require_once __DIR__.'/nm_biosphere.php';
                    if (function_exists('nm_bio_broadcast')) { try { nm_bio_broadcast($conn, "⚡ Data Core tune APPLIED\n".mb_substr((string)$a['ddl'],0,200), 'Data Core'); } catch (\Throwable $e) {} } }
                if (function_exists('nm_audit')) nm_audit($conn, 'dbobs.apply', ['target_type'=>'db_advice','target_id'=>$aid,'details'=>['ok'=>!empty($res['ok'])]]);
                echo json_encode($res); break;
            }
            default: echo json_encode(['ok'=>false, 'error'=>'unknown api']);
        }
    } catch (\Throwable $e) { echo json_encode(['ok'=>false, 'error'=>$e->getMessage()]); }
    exit;
}
$SET = nm_dbobs_settings($conn);
$canEdit = checkAccess($conn, 'dbmon') || checkAccess($conn, 'net_mon_config');
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Data Core Observatory · Holographic | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --accent:#4da3ff; --ok:#2ee6a0; --warn:#f3b52c; --sick:#ff7a45; --crit:#e74c3c; --cyan:#22d3ee; --db:#7c9dff; --border:rgba(255,255,255,.12); }
*,*::before,*::after{ box-sizing:border-box; }
html{ background:#04050c; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#e6e9ee; }
<?= nm_chrome_css() ?>
#obs-stage{ position:relative; width:100%; height:calc(100vh - 74px); min-height:520px; overflow:hidden;
  background:radial-gradient(1200px 720px at 50% 0%, rgba(40,60,140,.16), transparent 72%); }
#obs-stage:fullscreen{ height:100vh; }
#obs-canvas{ position:absolute; inset:0; display:block; z-index:1; }
.obs-hud{ position:absolute; z-index:6; pointer-events:none; }
.obs-hud .glass{ background:rgba(9,13,24,.62); backdrop-filter:blur(12px); border:1px solid var(--border); border-radius:12px; pointer-events:auto; }
#obs-top{ top:14px; left:14px; max-width:330px; } #obs-top .glass{ padding:12px 14px; }
#obs-title{ font-size:15px; font-weight:800; letter-spacing:.4px; display:flex; align-items:center; gap:9px; } #obs-title i{ color:var(--db); }
#obs-sub{ font-size:11px; color:#8a909a; margin-top:2px; line-height:1.4; }
#obs-legend{ margin-top:10px; display:flex; flex-wrap:wrap; gap:6px 12px; }
.leg{ display:flex; align-items:center; gap:6px; font-size:11px; color:#c3ccd8; } .leg .sw{ width:10px; height:10px; border-radius:50%; box-shadow:0 0 8px currentColor; }
#obs-stats{ top:14px; right:14px; } #obs-stats .glass{ padding:10px 14px; display:flex; gap:15px; }
.bstat{ text-align:center; } .bstat .n{ font-size:19px; font-weight:800; line-height:1; } .bstat .l{ font-size:9px; color:#8a909a; text-transform:uppercase; letter-spacing:.6px; margin-top:3px; }
.bstat .n.ok{ color:#7af3b0; } .bstat .n.crit{ color:#ff9b91; } .bstat .n.cyan{ color:var(--cyan); } .bstat .n.warn{ color:#ffd479; }
#obs-ctl{ top:80px; right:14px; display:flex; flex-direction:column; gap:8px; }
.bbtn{ pointer-events:auto; background:rgba(10,16,28,.78); border:1px solid var(--border); color:#cfe4ff; border-radius:9px; min-width:38px; height:36px; padding:0 12px; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:7px; font-size:13px; }
.bbtn:hover{ border-color:var(--accent); color:#fff; } .bbtn.on{ border-color:var(--cyan); color:#fff; background:rgba(34,211,238,.16); }
#obs-hint{ bottom:16px; left:16px; font-size:11px; color:#8a909a; } #obs-hint .glass{ padding:7px 12px; }
#obs-info{ position:absolute; z-index:12; left:0; top:0; height:100%; width:430px; max-width:92vw; display:none; }
#obs-info .glass{ height:100%; border-radius:0 16px 16px 0; border-left:none; padding:0; display:flex; flex-direction:column; box-shadow:24px 0 60px rgba(0,0,0,.45); background:rgba(8,12,22,.93); }
#obs-dh{ padding:14px 16px 12px; border-bottom:1px solid var(--border); position:relative; }
#obs-dh h3{ margin:0; font-size:16px; display:flex; align-items:center; gap:9px; padding-right:24px; }
#obs-dh .meta{ font-size:12px; color:#9aa3af; margin-top:4px; }
#obs-dh .x{ position:absolute; top:12px; right:12px; cursor:pointer; color:#9aa3af; font-size:15px; } #obs-dh .x:hover{ color:#fff; }
#obs-db{ padding:12px 16px 20px; overflow-y:auto; flex:1; }
#obs-db::-webkit-scrollbar{ width:8px; } #obs-db::-webkit-scrollbar-thumb{ background:rgba(255,255,255,.12); border-radius:8px; }
.dgrid{ display:grid; grid-template-columns:repeat(3,1fr); gap:8px; margin-bottom:14px; }
.dcell{ background:rgba(255,255,255,.04); border:1px solid var(--border); border-radius:9px; padding:8px 9px; }
.dcell .l{ font-size:9px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; } .dcell .v{ font-size:15px; font-weight:700; margin-top:2px; }
.dsec{ margin:16px 0 6px; font-size:11px; text-transform:uppercase; letter-spacing:.7px; color:#9db8ff; display:flex; align-items:center; gap:7px; } .dsec .cnt{ color:#6b7686; font-weight:400; }
.ditem{ background:rgba(255,255,255,.03); border:1px solid var(--border); border-left:3px solid #5a6577; border-radius:8px; padding:8px 10px; margin-bottom:7px; font-size:12px; }
.ditem .t{ font-weight:600; color:#e6e9ee; display:flex; justify-content:space-between; gap:8px; } .ditem .d{ color:#9aa3af; margin-top:3px; line-height:1.4; word-break:break-word; }
.ditem.crit{ border-left-color:#e74c3c; } .ditem.warn{ border-left-color:#f3b52c; } .ditem.ok{ border-left-color:#2ee6a0; }
.dbadge{ font-size:9px; padding:2px 6px; border-radius:20px; background:rgba(255,255,255,.08); color:#cfd6e0; white-space:nowrap; }
.dbadge.crit{ background:rgba(231,76,60,.2); color:#ff9b91; } .dbadge.warn{ background:rgba(243,181,44,.2); color:#ffd479; } .dbadge.ok{ background:rgba(46,230,160,.18); color:#7af3b0; }
.dmuted{ color:#6b7686; font-size:12px; padding:2px 0 4px; } .qrow{ font-family:monospace; font-size:11px; color:#cdd6e2; }
.spark{ display:flex; align-items:flex-end; gap:2px; height:38px; margin:6px 0 2px; } .spark i{ flex:1; border-radius:2px 2px 0 0; min-height:2px; background:#4da3ff; opacity:.85; }
#obs-dacts{ display:flex; gap:7px; flex-wrap:wrap; padding:12px 16px; border-top:1px solid var(--border); }
#obs-dacts a.act,#obs-dacts button.act{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:8px; padding:7px 11px; font-size:12px; text-decoration:none; cursor:pointer; }
#obs-dacts .act:hover{ border-color:var(--accent); color:#fff; }
#obs-tip{ position:absolute; z-index:9; pointer-events:none; display:none; background:rgba(6,10,20,.92); border:1px solid var(--border); border-radius:7px; padding:6px 9px; font-size:12px; white-space:nowrap; transform:translate(-50%,-140%); } #obs-tip b{ color:#fff; }
#obs-empty{ position:absolute; inset:0; display:none; align-items:center; justify-content:center; flex-direction:column; gap:12px; color:#8a909a; text-align:center; padding:24px; }
#obs-fallback{ display:none; position:absolute; inset:0; z-index:2; overflow:auto; padding:70px 20px 20px; }
.bento{ display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:14px; max-width:1200px; margin:0 auto; }
.bcard{ background:rgba(9,13,24,.7); border:1px solid var(--border); border-radius:14px; padding:16px; cursor:pointer; }
.bcard .bh{ display:flex; align-items:center; gap:9px; font-weight:700; } .bcard .bm{ font-size:11px; color:#8a909a; margin-top:6px; }
</style>
</head>
<body>
<?php include('header.php'); ?>

<div id="obs-stage">
  <canvas id="obs-canvas"></canvas>

  <div id="obs-top" class="obs-hud"><div class="glass">
    <div id="obs-title"><i class="fa-solid fa-database"></i> Data Core Observatory</div>
    <div id="obs-sub">Each database is a live reactor — core pulses with load, ring = connection pool, galaxy = table I/O, conduit = replication.</div>
    <div id="obs-legend">
      <div class="leg"><span class="sw" style="background:var(--ok);color:var(--ok)"></span>Healthy</div>
      <div class="leg"><span class="sw" style="background:var(--warn);color:var(--warn)"></span>Stressed</div>
      <div class="leg"><span class="sw" style="background:var(--sick);color:var(--sick)"></span>Sick</div>
      <div class="leg"><span class="sw" style="background:var(--crit);color:var(--crit)"></span>Critical</div>
    </div>
  </div></div>

  <div id="obs-stats" class="obs-hud"><div class="glass">
    <div class="bstat"><div class="n cyan" id="s-dbs">—</div><div class="l">Cores</div></div>
    <div class="bstat"><div class="n" id="s-conns">—</div><div class="l">Conns</div></div>
    <div class="bstat"><div class="n warn" id="s-slow">—</div><div class="l">Slow</div></div>
    <div class="bstat"><div class="n crit" id="s-locks">—</div><div class="l">Locks</div></div>
    <div class="bstat"><div class="n ok" id="s-repl">—</div><div class="l">Repl OK</div></div>
  </div></div>

  <div id="obs-ctl" class="obs-hud">
    <button class="bbtn on" id="b-labels" title="Toggle labels"><i class="fa-solid fa-tag"></i></button>
    <button class="bbtn on" id="b-spin" title="Auto-rotate"><i class="fa-solid fa-arrows-rotate"></i></button>
    <button class="bbtn" id="b-fit" title="Reset view"><i class="fa-solid fa-crosshairs"></i></button>
    <button class="bbtn" id="b-full" title="Fullscreen"><i class="fa-solid fa-expand"></i></button>
  </div>

  <div id="obs-hint" class="obs-hud"><div class="glass"><i class="fa-solid fa-hand-pointer"></i> Drag to orbit · scroll to zoom · click a reactor for its dossier</div></div>

  <div id="obs-info" class="obs-hud"><div class="glass">
    <div id="obs-dh"><span class="x" onclick="document.getElementById('obs-info').style.display='none'"><i class="fa-solid fa-xmark"></i></span>
      <h3 id="oi-name">—</h3><div class="meta" id="oi-meta">—</div></div>
    <div id="obs-db"><div class="dmuted">Loading reactor dossier…</div></div>
    <div id="obs-dacts"></div>
  </div></div>

  <div id="obs-tip"></div>
  <div id="obs-empty"><i class="fa-solid fa-database" style="font-size:34px;opacity:.4;"></i>
    <div id="obs-empty-msg">Spinning up the observatory…</div></div>
  <div id="obs-fallback"><div class="bento" id="bento"></div></div>
</div>

<script src="three.min.js"></script>
<script src="three-orbitcontrols.js"></script>
<script>
const OBS_POLL = <?= (int)$SET['poll_sec'] ?> * 1000;
const CAN_EDIT = <?= $canEdit ? 'true':'false' ?>;
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function nl(ts){ try{ return window.nmTimeStr ? window.nmTimeStr(ts) : (ts||''); }catch(e){ return ts||''; } }
function fmtN(n){ n=+n||0; if(n>=1e9)return (n/1e9).toFixed(1)+'B'; if(n>=1e6)return (n/1e6).toFixed(1)+'M'; if(n>=1e3)return (n/1e3).toFixed(1)+'k'; return ''+Math.round(n); }
function upStr(s){ s=+s; if(!s)return'—'; const d=Math.floor(s/86400),h=Math.floor(s%86400/3600); return d>0?(d+'d '+h+'h'):(h+'h '+Math.floor(s%3600/60)+'m'); }
function fmtBy(n){ if(n==null)return'—'; n=+n||0; const u=['B','KB','MB','GB','TB','PB']; let i=0; while(n>=1024&&i<u.length-1){n/=1024;i++;} return n.toFixed(i?1:0)+' '+u[i]; }
const LEVEL_COLOR={ healthy:0x2ee6a0, stressed:0xf3b52c, sick:0xff7a45, critical:0xe74c3c, unknown:0x6b7686 };
const LEVEL_HEX ={ healthy:'#2ee6a0', stressed:'#f3b52c', sick:'#ff7a45', critical:'#e74c3c', unknown:'#6b7686' };

let WEBGL=true;
(function(){ let ok=false; try{ const c=document.createElement('canvas'); ok=!!(window.WebGLRenderingContext&&(c.getContext('webgl')||c.getContext('experimental-webgl'))); }catch(e){}
  if(!ok||typeof THREE==='undefined'){ WEBGL=false; document.getElementById('obs-fallback').style.display='block'; document.getElementById('obs-canvas').style.display='none'; if(window.NMLoader) NMLoader.hide(); } })();

let DBS=[], LINKS=[];
let renderer,scene,camera,controls,stage,canvas,gCores,gLabels,gLinks;
let CORE={}, POS={}, spin=true, showLabels=true, built=false, fitDone=false, hidden=false, lastT=0;
let LINKR=[];  // per-link particle runtime

function initGL(){
  stage=document.getElementById('obs-stage'); canvas=document.getElementById('obs-canvas');
  renderer=new THREE.WebGLRenderer({canvas,antialias:true,alpha:true}); renderer.setClearColor(0x000000,0);
  scene=new THREE.Scene(); scene.fog=new THREE.FogExp2(0x04050c,0.00045);
  camera=new THREE.PerspectiveCamera(55,1,1,8000); camera.position.set(0,180,760);
  controls=new THREE.OrbitControls(camera,renderer.domElement); controls.enableDamping=true; controls.dampingFactor=.08;
  controls.autoRotate=true; controls.autoRotateSpeed=.4; controls.minDistance=90; controls.maxDistance=3400;
  scene.add(new THREE.AmbientLight(0x8899cc,0.85)); const key=new THREE.PointLight(0xafc4ff,0.6,0); key.position.set(300,500,400); scene.add(key);
  gCores=new THREE.Group(); gLabels=new THREE.Group(); gLinks=new THREE.Group(); scene.add(gLinks); scene.add(gCores); scene.add(gLabels);
}
function labelSprite(text,color){ const c=document.createElement('canvas'),ct=c.getContext('2d'); const f=40;
  ct.font=`600 ${f}px Segoe UI,sans-serif`; const w=Math.ceil(ct.measureText(text).width)+20; c.width=w; c.height=f+16;
  ct.font=`600 ${f}px Segoe UI,sans-serif`; ct.fillStyle='rgba(6,10,20,.55)'; ct.fillRect(0,0,w,c.height);
  ct.fillStyle=color||'#dfe7f2'; ct.textBaseline='middle'; ct.fillText(text,10,c.height/2);
  const tex=new THREE.CanvasTexture(c); tex.minFilter=THREE.LinearFilter;
  const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:tex,transparent:true,depthWrite:false})); sp.scale.set(w*0.16,c.height*0.16,1); return sp; }

// galaxy shader (table tiles as glowing points around a core)
const GAL_VS=`attribute vec3 aColor; attribute float aSize; attribute float aAlpha; varying vec3 vC; varying float vA;
  void main(){ vC=aColor; vA=aAlpha; vec4 mv=modelViewMatrix*vec4(position,1.0); gl_PointSize=aSize*(300.0/max(1.0,-mv.z)); gl_Position=projectionMatrix*mv; }`;
const GAL_FS=`varying vec3 vC; varying float vA; void main(){ float d=length(gl_PointCoord-vec2(0.5)); if(d>0.5) discard;
  float core=smoothstep(0.5,0.0,d); gl_FragColor=vec4(mix(vC*1.7,vec3(1.0),pow(core,3.0)*0.5), core*vA); }`;

function galaxyFor(db){
  const n=(db.top_tables||[]).length; const g=new THREE.BufferGeometry();
  if(!n){ return null; }
  const pos=new Float32Array(n*3), col=new Float32Array(n*3), sz=new Float32Array(n), al=new Float32Array(n);
  const maxRows=Math.max(1,...db.top_tables.map(t=>+t.rows||0)); const maxAct=Math.max(1,...db.top_tables.map(t=>(+t.reads)+(+t.writes)));
  db.top_tables.forEach((t,i)=>{ const a=2.399963*i; const r=46+Math.sqrt((i+1)/n)*88;   // spiral disc, clear of the core+ring
    pos[i*3]=Math.cos(a)*r; pos[i*3+1]=(Math.sin(i*1.7)*10); pos[i*3+2]=Math.sin(a)*r;
    const act=((+t.reads)+(+t.writes)); const wr=act>0?(+t.writes)/act:0;   // 0 read → 1 write
    const c=new THREE.Color().setHSL(0.58-wr*0.58,0.9,0.6);                // blue(read)→red(write)
    col[i*3]=c.r; col[i*3+1]=c.g; col[i*3+2]=c.b;
    sz[i]=5.5+Math.sqrt((+t.rows||0)/maxRows)*10; al[i]=0.6+ (act/maxAct)*0.4; });   // bigger + always visible
  g.setAttribute('position',new THREE.BufferAttribute(pos,3)); g.setAttribute('aColor',new THREE.BufferAttribute(col,3));
  g.setAttribute('aSize',new THREE.BufferAttribute(sz,1)); g.setAttribute('aAlpha',new THREE.BufferAttribute(al,1));
  const m=new THREE.ShaderMaterial({transparent:true,depthWrite:false,blending:THREE.AdditiveBlending,vertexShader:GAL_VS,fragmentShader:GAL_FS});
  return new THREE.Points(g,m);
}
function ringFor(load,colHex){  // connection-pool gauge ring
  const grp=new THREE.Group(); const N=40, lit=Math.round(Math.min(1,load)*N);
  const col=new THREE.Color(load>=0.85?0xe74c3c:(load>=0.7?0xf3b52c:0x4da3ff));
  const geo=new THREE.BoxGeometry(2.4,2.4,5.5);
  for(let i=0;i<N;i++){ const on=i<lit; const a=i/N*Math.PI*2; const r=30;
    const m=new THREE.Mesh(geo,new THREE.MeshBasicMaterial({color:on?col:0x2a3550,transparent:true,opacity:on?0.95:0.25}));
    m.position.set(Math.cos(a)*r,0,Math.sin(a)*r); m.lookAt(0,0,0); grp.add(m); }
  grp.rotation.x=Math.PI/2.6; return grp;
}

function layout(dbs,links){ const pos={}; const parent={}; links.forEach(l=>parent[l.to]=l.from);
  const anchors=dbs.filter(d=>!parent[d.id]); const n=anchors.length||1; const R=180+n*40;
  anchors.forEach((d,i)=>{ const a=(i/n)*Math.PI*2; pos[d.id]=new THREE.Vector3(Math.cos(a)*R, (i%2?18:-18), Math.sin(a)*R); });
  dbs.forEach(d=>{ if(parent[d.id]!=null && pos[parent[d.id]]){ const p=pos[parent[d.id]]; pos[d.id]=p.clone().add(new THREE.Vector3(120,40,40)); } });
  dbs.forEach((d,i)=>{ if(!pos[d.id]) pos[d.id]=new THREE.Vector3((i-dbs.length/2)*180,0,0); });
  return pos; }

function buildScene(){
  [gCores,gLabels,gLinks].forEach(g=>{ while(g.children.length) g.remove(g.children[0]); });
  CORE={}; LINKR=[];
  if(!DBS.length){ document.getElementById('obs-empty').style.display='flex';
    document.getElementById('obs-empty-msg').innerHTML='No databases configured.<br>Add them in <b>Data Core</b> (Config → Databases).'; if(window.NMLoader)NMLoader.hide(); return; }
  document.getElementById('obs-empty').style.display='none';
  POS=layout(DBS,LINKS);
  const coreGeo=new THREE.IcosahedronGeometry(22,3);
  DBS.forEach(d=>{ const col=LEVEL_COLOR[d.level]||LEVEL_COLOR.unknown;
    const grp=new THREE.Group(); grp.position.copy(POS[d.id]);
    const core=new THREE.Mesh(coreGeo,new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:.9,roughness:.3,metalness:.35,flatShading:true}));
    core.userData=d; grp.add(core);
    const halo=new THREE.Mesh(new THREE.SphereGeometry(30,20,20),new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:.10,blending:THREE.AdditiveBlending,depthWrite:false}));
    halo.userData=d; grp.add(halo);
    const ring=ringFor(d.viz.load||0,col); grp.add(ring);
    const gal=galaxyFor(d); if(gal) grp.add(gal);
    gCores.add(grp);
    const lab=labelSprite((d.name||('db'+d.id))+(d.role==='replica'?' ⟲':(d.role==='master'?' ★':'')), LEVEL_HEX[d.level]);
    lab.position.copy(POS[d.id]).add(new THREE.Vector3(0,44,0)); lab.visible=showLabels; gLabels.add(lab);
    CORE[d.id]={grp,core,halo,ring,gal,label:lab,db:d,t:Math.random()*10,sizeMul:0.7+(d.viz.size||0)*0.9};
  });
  // replication conduits (particles flow master→replica)
  LINKS.forEach(l=>{ if(!POS[l.from]||!POS[l.to]) return;
    const a=POS[l.from], b=POS[l.to], mid=a.clone().add(b).multiplyScalar(.5); mid.y+=50;
    const curve=new THREE.QuadraticBezierCurve3(a,mid,b);
    const behind=l.behind, down=(!l.io||!l.sql);
    const hex=down?0xe74c3c:((behind!=null&&behind>30)?0xf3b52c:0x2ee6a0);
    const cg=new THREE.BufferGeometry().setFromPoints(curve.getPoints(40));
    gLinks.add(new THREE.Line(cg,new THREE.LineBasicMaterial({color:hex,transparent:true,opacity:.35})));
    // particle stream
    const P=26; const pg=new THREE.BufferGeometry(); const pp=new Float32Array(P*3);
    pg.setAttribute('position',new THREE.BufferAttribute(pp,3));
    const pm=new THREE.PointsMaterial({color:hex,size:5,transparent:true,opacity:.95,blending:THREE.AdditiveBlending,depthWrite:false});
    const pts=new THREE.Points(pg,pm); gLinks.add(pts);
    const speed=down?0:(0.05+1/(1+(behind||0))*0.5);
    LINKR.push({curve,pts,pp,P,phase:0,speed,down});
  });
  built=true; if(window.NMLoader) NMLoader.hide(); if(!fitDone){ fitView(); fitDone=true; }
}

function applyLive(){ DBS.forEach(d=>{ const C=CORE[d.id]; if(!C) return; C.db=d; C.sizeMul=0.7+(d.viz.size||0)*0.9;
  const col=LEVEL_COLOR[d.level]||LEVEL_COLOR.unknown; C.core.material.color.setHex(col); C.core.material.emissive.setHex(col); C.halo.material.color.setHex(col);
  C.grp.remove(C.ring); C.ring=ringFor(d.viz.load||0,col); C.grp.add(C.ring);
}); }

function animate(now){ requestAnimationFrame(animate); if(hidden||!WEBGL) return;
  const dt=Math.min(0.05,(now-lastT)/1000); lastT=now; controls.autoRotate=spin; controls.update();
  Object.values(CORE).forEach(C=>{ C.t+=dt; const v=C.db.viz||{};
    // core pulse ∝ load/running; frozen → slow icy shiver
    const rate=v.frozen?1.2:(2+ (v.pulse||0)*6); const s=1+Math.sin(C.t*rate)*(0.03+(v.pulse||0)*0.05);
    const sm=C.sizeMul||1;   // on-disk size → bigger reactor core (log-scaled server-side)
    C.core.scale.setScalar(s*sm); C.core.material.emissiveIntensity=0.7+Math.sin(C.t*rate)*0.35+(v.slow||0)*0.3;
    C.halo.scale.setScalar((1+(v.load||0)*0.5+Math.sin(C.t*rate)*0.05)*sm);
    if(C.gal) C.gal.rotation.y+=dt*(0.15+(v.pulse||0)*0.5);
    C.core.rotation.y+=dt*0.3; C.core.rotation.x+=dt*0.12;
  });
  // conduit particles
  LINKR.forEach(L=>{ if(L.down){ L.pts.visible=false; return; } L.pts.visible=true; L.phase=(L.phase+L.speed*dt)%1;
    for(let i=0;i<L.P;i++){ const t=(L.phase+i/L.P)%1; const p=L.curve.getPoint(t); L.pp[i*3]=p.x; L.pp[i*3+1]=p.y; L.pp[i*3+2]=p.z; }
    L.pts.geometry.attributes.position.needsUpdate=true; });
  renderer.render(scene,camera); }

function fitView(){ if(!Object.keys(POS).length) return; const box=new THREE.Box3(); Object.values(POS).forEach(p=>box.expandByPoint(p));
  const c=box.getCenter(new THREE.Vector3()), sz=box.getSize(new THREE.Vector3()); const r=Math.max(sz.x,sz.y,sz.z,180);
  controls.target.copy(c); camera.position.set(c.x,c.y+r*0.4,c.z+r*1.7); camera.near=1; camera.far=r*24; camera.updateProjectionMatrix(); }
function resize(){ if(!WEBGL) return; const w=stage.clientWidth,h=stage.clientHeight; renderer.setPixelRatio(Math.min(window.devicePixelRatio||1,2)); renderer.setSize(w,h,false); camera.aspect=w/h; camera.updateProjectionMatrix(); }

function bindPick(){ const ray=new THREE.Raycaster(); const mouse=new THREE.Vector2();
  function pick(ev){ const r=canvas.getBoundingClientRect(); mouse.x=((ev.clientX-r.left)/r.width)*2-1; mouse.y=-((ev.clientY-r.top)/r.height)*2+1; ray.setFromCamera(mouse,camera); return ray.intersectObjects(gCores.children,true); }
  canvas.addEventListener('mousemove',ev=>{ const hit=pick(ev); const tip=document.getElementById('obs-tip');
    const o=hit.find(h=>h.object.userData&&h.object.userData.id);
    if(o){ const d=o.object.userData; tip.style.display='block'; tip.style.left=ev.clientX+'px'; tip.style.top=(ev.clientY-6)+'px';
      const v=d.vitals||{}; tip.innerHTML=`<b>${esc(d.name)}</b> · ${esc(d.engine)} ${esc(d.role)}<br>${esc((d.level||'?').toUpperCase())}${v.connections!=null?(' · '+v.connections+'/'+ (v.max_connections||'?')+' conns'):''}${v.db_bytes!=null?(' · '+fmtBy(v.db_bytes)):''}`; canvas.style.cursor='pointer'; }
    else { tip.style.display='none'; canvas.style.cursor='grab'; } });
  canvas.addEventListener('click',ev=>{ const hit=pick(ev); const o=hit.find(h=>h.object.userData&&h.object.userData.id); if(o) openInfo(o.object.userData); });
}

async function loadScene(first){
  let d=null; try{ d=await fetch('dbobservatory.php?api=scene&_='+Date.now()).then(r=>r.json()); }catch(e){ if(window.NMLoader)NMLoader.hide(); return; }
  if(!d||!d.ok){ if(window.NMLoader)NMLoader.hide(); return; }
  const same= built && d.dbs.length===DBS.length && d.dbs.every((x,i)=>DBS[i]&&DBS[i].id===x.id) && d.links.length===LINKS.length;
  DBS=d.dbs; LINKS=d.links;
  if(WEBGL){ if(!same) buildScene(); else applyLive(); } else renderFallback();
  const h=d.hud||{}; document.getElementById('s-dbs').textContent=h.dbs!=null?h.dbs:DBS.length;
  document.getElementById('s-conns').textContent=fmtN(h.connections||0); document.getElementById('s-slow').textContent=h.slow||0;
  document.getElementById('s-locks').textContent=h.locks||0; document.getElementById('s-repl').textContent=(h.repl_ok||0)+(h.repl_bad?('/'+ (h.repl_ok+h.repl_bad)):'');
}
function renderFallback(){ const el=document.getElementById('bento');
  if(!DBS.length){ el.innerHTML='<div class="dmuted" style="grid-column:1/-1;text-align:center">No databases configured.</div>'; return; }
  el.innerHTML=DBS.map(d=>{ const hex=LEVEL_HEX[d.level]||LEVEL_HEX.unknown; const v=d.vitals||{};
    return `<div class="bcard" onclick='openInfoById(${d.id})'><div class="bh"><i class="fa-solid fa-database" style="color:${hex}"></i> ${esc(d.name)} <span class="dbadge" style="margin-left:auto">${esc(d.role)}</span></div>
      <div class="bm">Status: <b style="color:${hex}">${esc((d.level||'?').toUpperCase())}</b>${d.ok?'':' · UNREACHABLE'}</div>
      <div class="bm">${v.connections!=null?(v.connections+'/'+(v.max_connections||'?')+' conns · '):''}${d.slow||0} slow · ${d.locks||0} locks${d.no_index?(' · '+d.no_index+' no-index'):''}</div></div>`; }).join(''); }

// ── dossier ───────────────────────────────────────────────────────────────────
function openInfoById(id){ const d=DBS.find(x=>x.id===id); if(d) openInfo(d); }
function dcell(l,v){ return `<div class="dcell"><div class="l">${esc(l)}</div><div class="v">${esc(v)}</div></div>`; }
function dsec(icon,label,cnt){ return `<div class="dsec"><i class="fa-solid fa-${icon}"></i> ${esc(label)} <span class="cnt">${cnt!=null?cnt:''}</span></div>`; }
async function openInfo(d){ const box=document.getElementById('obs-info'); box.style.display='block';
  const hex=LEVEL_HEX[d.level]||LEVEL_HEX.unknown;
  document.getElementById('oi-name').innerHTML=`<i class="fa-solid fa-database" style="color:${hex}"></i> ${esc(d.name)}`;
  document.getElementById('oi-meta').innerHTML=`${esc(d.engine)} · ${esc(d.role)} · ${esc(d.host||'')}`;
  const body=document.getElementById('obs-db'); body.innerHTML='<div class="dmuted">Loading reactor dossier…</div>'; document.getElementById('obs-dacts').innerHTML='';
  let r=null,err=''; try{ const resp=await fetch('dbobservatory.php?api=detail&id='+d.id+'&_='+Date.now()); const txt=await resp.text(); try{ r=JSON.parse(txt); }catch(pe){ err='HTTP '+resp.status+' · '+txt.slice(0,180); } }catch(e){ err='network: '+(e&&e.message||e); }
  if(!r||!r.ok){ body.innerHTML='<div class="dmuted">Could not load details.'+(err?'<br><span style="color:#ff9b91;font-family:monospace;font-size:10px">'+esc(err)+'</span>':(r&&r.error?'<br>'+esc(r.error):''))+'</div>'; return; }
  try{ body.innerHTML=renderDossier(r,d); }catch(e){ body.innerHTML='<div class="dmuted">Render error: '+esc(e&&e.message||e)+'</div>'; return; }
  document.getElementById('obs-dacts').innerHTML=`<a class="act" href="dbmon.php?target=${d.id}"><i class="fa-solid fa-database"></i> Open in Data Core</a>`;
}
function renderDossier(r,d){ const p=r.probe||{}, v=d.vitals||{}; let h='';
  h+='<div class="dgrid">'+dcell('Status',(d.level||'?').toUpperCase())+dcell('Version',(p.version||'').split('-')[0]||'—')+dcell('Uptime',upStr(p.uptime_s))
    +dcell('Conns',(p.connections!=null?p.connections:(v.connections??'—'))+'/'+(p.max_connections||v.max_connections||'?'))
    +dcell('Running',p.threads_running!=null?p.threads_running:'—')+dcell('Saturation',v.saturation!=null?v.saturation+'%':'—')
    +dcell('Data size',fmtBy(p.db_bytes!=null?p.db_bytes:v.db_bytes))+'</div>';
  if(r.error) h+=`<div class="ditem crit"><div class="d">${esc(r.error)}</div></div>`;
  // replication
  if(r.replication){ const R=r.replication; if(R.is_replica||R.replicas_connected){ h+=dsec('code-branch','Replication');
    if(R.is_replica){ const bad=(!R.io_running||!R.sql_running); h+=`<div class="ditem ${bad?'crit':(R.seconds_behind>30?'warn':'ok')}"><div class="t"><span>Replica of ${esc(R.source_host||'source')}</span><span class="dbadge ${bad?'crit':'ok'}">${bad?'thread down':'running'}</span></div><div class="d">IO ${R.io_running?'✓':'✗'} · SQL ${R.sql_running?'✓':'✗'} · ${R.seconds_behind==null?'lag n/a':(R.seconds_behind+'s behind')}</div>${R.last_error?`<div class="d" style="color:#ff9b91">${esc(R.last_error)}</div>`:''}</div>`; }
    else h+=`<div class="ditem ok"><div class="t"><span>Master / source</span><span class="dbadge ok">${R.replicas_connected!=null?R.replicas_connected:'?'} replica(s)</span></div></div>`; } }
  // top queries
  if(r.top_queries&&r.top_queries.length){ h+=dsec('magnifying-glass-chart','Heaviest queries',r.top_queries.length);
    r.top_queries.forEach(q=>{ h+=`<div class="ditem ${q.no_index?'warn':''}"><div class="t"><span>${q.avg_ms!=null?Math.round(q.avg_ms)+' ms avg':''} ${q.calls?('· '+fmtN(q.calls)+' calls'):''}</span>${q.no_index?'<span class="dbadge warn">no index</span>':''}</div><div class="d qrow">${esc((q.query||'').slice(0,150))}</div></div>`; }); }
  // slow + locks
  if(r.locks&&r.locks.length){ h+=dsec('snowflake','Lock waits',r.locks.length); r.locks.forEach(l=>{ h+=`<div class="ditem crit"><div class="d qrow">#${esc(l.waiting_pid||'')} blocked by #${esc(l.blocking_pid||'')}</div><div class="d">${esc((l.waiting_query||'').slice(0,120))}</div></div>`; }); }
  if(r.slow&&r.slow.length){ h+=dsec('hourglass-half','Slow queries',r.slow.length); r.slow.forEach(s=>{ h+=`<div class="ditem warn"><div class="t"><span>${esc(s.secs)}s · ${esc(s.user||'')}</span></div><div class="d qrow">${esc((s.query||'').slice(0,130))}</div></div>`; }); }
  // AI advice
  if(r.advice&&r.advice.length){ h+=dsec('flask','Metabolic advisor',r.advice.length);
    r.advice.forEach(a=>{ const auto=/^(index|maintenance)$/i.test(a.kind);
      h+=`<div class="ditem ${a.risk==='high'?'crit':(a.risk==='medium'?'warn':'ok')}"><div class="t"><span>${esc(a.title||a.kind)}</span><span class="dbadge">${esc(a.risk||'')}</span></div>${a.rationale?`<div class="d">${esc(a.rationale)}</div>`:''}${a.ddl?`<div class="d qrow">${esc((a.ddl||'').slice(0,160))}</div>`:''}${(CAN_EDIT&&auto)?`<div class="d" style="margin-top:6px"><button class="act" style="padding:4px 8px;font-size:11px;border-color:rgba(46,204,113,.5);color:#8fe3b0" onclick="applyAdvice(${a.id},${d.id})">⚡ Apply now</button></div>`:''}</div>`; }); }
  // table galaxy detail
  if(r.top_tables&&r.top_tables.length){ h+=dsec('table-cells','Busiest tables (galaxy)',r.top_tables.length);
    const mx=Math.max(1,...r.top_tables.map(t=>(+t.reads)+(+t.writes)));
    r.top_tables.forEach(t=>{ const act=((+t.reads)+(+t.writes)); const w=Math.round(act/mx*100); h+=`<div class="ditem"><div class="t"><span>${esc(t.name)}</span><span class="dbadge">${fmtN(t.rows)} rows</span></div><div class="d">▲ R ${fmtN(t.reads)} · ✎ W ${fmtN(t.writes)}</div><div style="height:4px;background:rgba(255,255,255,.06);border-radius:3px;margin-top:5px"><div style="height:100%;width:${w}%;border-radius:3px;background:linear-gradient(90deg,#4da3ff,#e74c3c)"></div></div></div>`; }); }
  // trend
  if(r.trend&&r.trend.length){ const mx=Math.max(1,...r.trend.map(t=>+t.connections||0)); h+=dsec('wave-square','Connections trend',r.trend.length);
    h+='<div class="spark">'+r.trend.map(t=>{ const hh=Math.round((+t.connections||0)/mx*36); const c=(+t.blocked>0)?'#e74c3c':((+t.slow>0)?'#f3b52c':'#4da3ff'); return `<i style="height:${Math.max(2,hh)}px;background:${c}"></i>`; }).join('')+'</div>'; }
  return h; }
async function applyAdvice(adviceId,dbId){ if(!confirm('Apply this tuning DDL to the database now?\n\nRuns immediately (whitelisted CREATE INDEX / ANALYZE / OPTIMIZE only) and notifies your channels.')) return;
  const r=await fetch('dbobservatory.php?api=apply',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'advice='+adviceId}).then(r=>r.json());
  alert(r.ok?'✅ Applied.':('Failed: '+(r.error||'?'))); const d=DBS.find(x=>x.id===dbId); if(d&&r.ok) setTimeout(()=>openInfo(d),400); }

// controls / chrome
if(WEBGL){ initGL(); bindPick();
  document.getElementById('b-fit').onclick=()=>fitView();
  document.getElementById('b-spin').onclick=e=>{ spin=!spin; e.currentTarget.classList.toggle('on',spin); };
  document.getElementById('b-labels').onclick=e=>{ showLabels=!showLabels; e.currentTarget.classList.toggle('on',showLabels); Object.values(CORE).forEach(C=>C.label.visible=showLabels); };
  document.getElementById('b-full').onclick=()=>{ if(document.fullscreenElement) document.exitFullscreen(); else stage.requestFullscreen&&stage.requestFullscreen(); };
  window.addEventListener('resize',resize);
  document.addEventListener('fullscreenchange',()=>{ const bg=document.getElementById('nm-netbg');
    if(bg){ if(document.fullscreenElement===stage){ stage.insertBefore(bg,stage.firstChild); bg.style.zIndex='0'; } else { document.body.appendChild(bg); bg.style.zIndex='-1'; } }
    const i=document.querySelector('#b-full i'); if(i) i.className='fa-solid '+(document.fullscreenElement?'fa-compress':'fa-expand'); setTimeout(()=>resize(),80); });
  document.addEventListener('visibilitychange',()=>{ hidden=document.hidden; if(!hidden) lastT=performance.now(); });
}
if(window.NMLoader){ NMLoader.keep(); NMLoader.msg&&NMLoader.msg('Spinning up the observatory…'); }  // hold loader until the reactors are built
if(WEBGL){ resize(); lastT=performance.now(); animate(performance.now()); }
loadScene(true).then(()=>{ setInterval(()=>loadScene(false), OBS_POLL); });
</script>
</body></html>
