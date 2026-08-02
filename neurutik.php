<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — NEURUTIK · the UNIFIED command center. One WebGL galaxy of every node,
// with toggleable layers that overlay the metaphors of the individual command
// centers onto the SAME nodes: ⚡Traffic (nm_port_stats), 🧭Routes
// (nm_routing_topology), 🗄️DB (nm_dbobs_scene), 🧬Services (nm_bio_scene),
// 🌌Hologram (nm_holo_enrich). Click a node → full dossier (nm_holo_node_detail)
// + a deep-link to that node's OWN command center (nm_node_cc). Does NOT replace
// any existing command center — community-requested unification. RBAC: 'neurutik'.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_nodemeta.php');   // nm_node_kind, nm_node_cc
include('logger.php');

if (!checkAccess($conn, 'neurutik')) { header('Location: /denied_access.php?page=neurutik'); exit; }

// ── Inventory: every node with its kind, live vitals + the ready-made deep-link
//    to its per-kind command center (windows→win_screen, linux→linux_screen,
//    router→router_details, etc. via nm_node_cc). Keyed by node_id.
if (!function_exists('nk_inventory')) {
    function nk_inventory($conn): array {
        $win = []; $lx = [];
        try { if ($r = $conn->query("SELECT id,node_id FROM nm_win_hosts WHERE node_id IS NOT NULL")) while ($x = $r->fetch_assoc()) $win[(int)$x['node_id']] = (int)$x['id']; } catch (\Throwable $e) {}
        try { if ($r = $conn->query("SELECT id,node_id FROM nm_lx_hosts  WHERE node_id IS NOT NULL")) while ($x = $r->fetch_assoc()) $lx[(int)$x['node_id']]  = (int)$x['id']; } catch (\Throwable $e) {}
        $inc = [];
        try { if ($r = $conn->query("SELECT root_node_id,COUNT(*) c FROM nm_incidents WHERE status IN('open','acknowledged') AND root_node_id IS NOT NULL GROUP BY root_node_id")) while ($x = $r->fetch_assoc()) $inc[(int)$x['root_node_id']] = (int)$x['c']; } catch (\Throwable $e) {}
        $ping = [];
        try { if ($r = $conn->query("SELECT ps.node_id,ps.is_up,ps.latency_ms FROM nm_ping_stats ps INNER JOIN (SELECT node_id,MAX(id) mid FROM nm_ping_stats GROUP BY node_id) lx ON ps.node_id=lx.node_id AND ps.id=lx.mid")) while ($x = $r->fetch_assoc()) $ping[(int)$x['node_id']] = $x; } catch (\Throwable $e) {}
        $out = [];
        $r = $conn->query("SELECT id,display_name,ip_address,os_icon,COALESCE(monitor_type,'snmp') monitor_type FROM nm_nodes ORDER BY id");
        while ($r && $n = $r->fetch_assoc()) {
            $nid = (int)$n['id'];
            $cc  = nm_node_cc($n, $win[$nid] ?? null, $lx[$nid] ?? null);
            $p   = $ping[$nid] ?? null;
            $out[$nid] = [
                'id'=>$nid, 'name'=>$n['display_name'], 'ip'=>$n['ip_address'],
                'kind'=>nm_node_kind($n),
                'up'=>$p !== null ? (int)$p['is_up'] : null,
                'latency'=>$p !== null && $p['latency_ms'] !== null ? round((float)$p['latency_ms'], 1) : null,
                'incidents'=>$inc[$nid] ?? 0,
                'cc_url'=>$cc['url'], 'cc_label'=>$cc['label'], 'cc_icon'=>$cc['icon'], 'cc_perm'=>$cc['perm'],
            ];
        }
        return ['ok'=>true, 'nodes'=>$out, 'ts'=>time()];
    }
}

$__api = $_GET['api'] ?? '';
if ($__api !== '') {
    if (function_exists('session_write_close')) @session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    try {
        if ($__api === 'inventory') {
            echo json_encode(nk_inventory($conn));
        } elseif ($__api === 'node') {
            require_once('nm_hologram.php');
            echo json_encode(nm_holo_node_detail($conn, (int)($_GET['id'] ?? 0)));
        } elseif ($__api === 'layer') {
            $L = $_GET['l'] ?? '';
            if ($L === 'routes')        { require_once('nm_routing.php');   echo json_encode(['ok'=>true] + nm_routing_topology($conn, null)); }
            elseif ($L === 'db')        { require_once('nm_dbobs.php'); $scene = nm_dbobs_scene($conn);
                // nm_dbobs_scene omits node_id — attach it so the UI can tether each DB to its host node.
                $nmap = []; if ($r = $conn->query("SELECT id,node_id FROM nm_db_targets WHERE node_id IS NOT NULL")) while ($x = $r->fetch_assoc()) $nmap[(int)$x['id']] = (int)$x['node_id'];
                if (!empty($scene['dbs'])) { foreach ($scene['dbs'] as &$db) { $db['node_id'] = $nmap[(int)$db['id']] ?? null; } unset($db); }
                echo json_encode($scene); }
            elseif ($L === 'services')  { require_once('nm_biosphere.php'); echo json_encode(nm_bio_scene($conn)); }
            elseif ($L === 'holo')      { require_once('nm_hologram.php');  echo json_encode(nm_holo_enrich($conn, (int)($_GET['win'] ?? 15))); }
            else echo json_encode(['ok'=>false, 'error'=>'unknown layer']);
        } elseif ($__api === 'path') {
            require_once('nm_routing.php');
            echo json_encode(nm_routing_path($conn, (int)($_GET['from'] ?? 0), trim((string)($_GET['dest'] ?? ''))));
        } else {
            echo json_encode(['ok'=>false, 'error'=>'unknown api']);
        }
    } catch (\Throwable $e) {
        echo json_encode(['ok'=>false, 'error'=>$e->getMessage()]);
    }
    exit;
}

log_user_action($conn, 'view_page', 'neurutik.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cyan:#22d3ee; --purple:#b388ff; --border:rgba(255,255,255,.12); }
*,*::before,*::after{ box-sizing:border-box; }
html{ background:#04050c; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#e6e9ee; }
<?= nm_chrome_css() ?>
#nk-stage{ position:relative; width:100%; height:calc(100vh - 74px); min-height:520px; overflow:hidden;
  background:radial-gradient(1200px 700px at 50% 0%, rgba(40,70,140,.16), transparent 72%); }
#nk-stage:fullscreen{ height:100vh; }
#nk-canvas{ position:absolute; inset:0; display:block; z-index:1; }
.nk-hud{ position:absolute; z-index:6; pointer-events:none; }
.nk-hud .glass{ background:rgba(9,13,24,.62); backdrop-filter:blur(12px); border:1px solid var(--border); border-radius:12px; pointer-events:auto; }
#nk-top{ top:14px; left:14px; max-width:360px; }
#nk-top .glass{ padding:12px 14px; }
#nk-title{ font-size:16px; font-weight:800; letter-spacing:.6px; display:flex; align-items:center; gap:9px; }
#nk-title i{ color:var(--cyan); }
#nk-title .tag{ font-size:9px; font-weight:700; letter-spacing:1px; color:#04121a; background:linear-gradient(90deg,#36e3d0,#4da3ff); padding:2px 7px; border-radius:20px; margin-left:2px; }
#nk-sub{ font-size:11px; color:#8a909a; margin-top:3px; }
/* layer chips */
#nk-layers{ margin-top:11px; display:flex; flex-wrap:wrap; gap:6px; }
.lchip{ font-size:11px; padding:5px 11px; border-radius:20px; border:1px solid rgba(255,255,255,.14); color:#c3ccd8; cursor:pointer; opacity:.62; white-space:nowrap; user-select:none; display:inline-flex; align-items:center; gap:6px; transition:.15s; }
.lchip:hover{ opacity:.92; }
.lchip.on{ opacity:1; }
.lchip.on[data-l="traffic"]{ background:rgba(54,227,208,.16); border-color:rgba(54,227,208,.55); color:#bff2ee; }
.lchip.on[data-l="routes"]{ background:rgba(179,136,255,.16); border-color:rgba(179,136,255,.55); color:#dcccff; }
.lchip.on[data-l="db"]{ background:rgba(46,230,160,.14); border-color:rgba(46,230,160,.5); color:#9df3c6; }
.lchip.on[data-l="services"]{ background:rgba(243,181,44,.15); border-color:rgba(243,181,44,.5); color:#ffe0a0; }
.lchip.on[data-l="holo"]{ background:rgba(77,163,255,.16); border-color:rgba(77,163,255,.55); color:#bcd8ff; }
/* stats top-right */
#nk-stats{ top:14px; right:14px; }
#nk-stats .glass{ padding:10px 14px; display:flex; gap:15px; }
.nkstat{ text-align:center; } .nkstat .n{ font-size:19px; font-weight:800; line-height:1; } .nkstat .l{ font-size:9px; color:#8a909a; text-transform:uppercase; letter-spacing:.6px; margin-top:3px; }
.nkstat .n.ok{ color:#7af3b0; } .nkstat .n.crit{ color:#ff9b91; } .nkstat .n.cyan{ color:var(--cyan); } .nkstat .n.warn{ color:#ffd479; }
#nk-ctl{ top:86px; right:14px; display:flex; flex-direction:column; gap:8px; }
.nkbtn{ pointer-events:auto; background:rgba(10,16,28,.78); border:1px solid var(--border); color:#cfe4ff; border-radius:9px; min-width:38px; height:36px; padding:0 12px; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:7px; font-size:13px; }
.nkbtn:hover{ border-color:var(--accent); color:#fff; } .nkbtn.on{ border-color:var(--cyan); color:#fff; background:rgba(34,211,238,.16); }
#nk-legend{ position:absolute; bottom:16px; right:16px; z-index:6; }
#nk-legend .glass{ padding:9px 12px; display:flex; flex-direction:column; gap:5px; max-width:230px; }
.leg{ display:flex; align-items:center; gap:8px; font-size:11.5px; color:#c3ccd8; } .leg .sw{ width:10px; height:10px; border-radius:50%; box-shadow:0 0 8px currentColor; flex:0 0 auto; }
#nk-hint{ bottom:16px; left:16px; font-size:11px; color:#8a909a; } #nk-hint .glass{ padding:7px 12px; }
/* dossier drawer (left) */
#nk-info{ position:absolute; z-index:12; left:0; top:0; height:100%; width:410px; max-width:88vw; display:none; }
#nk-info .glass{ height:100%; border-radius:0 16px 16px 0; border-left:none; padding:0; display:flex; flex-direction:column; box-shadow:24px 0 60px rgba(0,0,0,.45); background:rgba(8,12,22,.92); }
#nk-dh{ padding:14px 16px 12px; border-bottom:1px solid var(--border); position:relative; }
#nk-dh h3{ margin:0; font-size:16px; display:flex; align-items:center; gap:9px; padding-right:24px; }
#nk-dh .meta{ font-size:12px; color:#9aa3af; margin-top:4px; }
#nk-dh .x{ position:absolute; top:12px; right:12px; cursor:pointer; color:#9aa3af; font-size:15px; } #nk-dh .x:hover{ color:#fff; }
#nk-kind{ font-size:9px; font-weight:700; letter-spacing:1px; text-transform:uppercase; padding:2px 8px; border-radius:20px; background:rgba(77,163,255,.18); color:#bcd8ff; }
#nk-db{ padding:12px 16px 20px; overflow-y:auto; flex:1; }
#nk-db::-webkit-scrollbar{ width:8px; } #nk-db::-webkit-scrollbar-thumb{ background:rgba(255,255,255,.12); border-radius:8px; }
.dgrid{ display:grid; grid-template-columns:repeat(3,1fr); gap:8px; margin-bottom:14px; }
.dcell{ background:rgba(255,255,255,.04); border:1px solid var(--border); border-radius:9px; padding:8px 9px; }
.dcell .l{ font-size:9px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; } .dcell .v{ font-size:15px; font-weight:700; margin-top:2px; }
.dsec{ margin:16px 0 6px; font-size:11px; text-transform:uppercase; letter-spacing:.7px; color:#7fd3ff; display:flex; align-items:center; gap:7px; } .dsec .cnt{ color:#6b7686; font-weight:400; }
.ditem{ background:rgba(255,255,255,.03); border:1px solid var(--border); border-left:3px solid #5a6577; border-radius:8px; padding:8px 10px; margin-bottom:7px; font-size:12px; }
.ditem .t{ font-weight:600; color:#e6e9ee; display:flex; justify-content:space-between; gap:8px; } .ditem .d{ color:#9aa3af; margin-top:3px; line-height:1.4; word-break:break-word; }
.ditem.crit{ border-left-color:#e74c3c; } .ditem.warn{ border-left-color:#f3b52c; } .ditem.info{ border-left-color:#4da3ff; } .ditem.ok{ border-left-color:#2ee6a0; } .ditem.ai{ border-left-color:#9b6bff; }
.dbadge{ font-size:9px; padding:2px 6px; border-radius:20px; background:rgba(255,255,255,.08); color:#cfd6e0; white-space:nowrap; }
.dbadge.crit{ background:rgba(231,76,60,.2); color:#ff9b91; } .dbadge.warn{ background:rgba(243,181,44,.2); color:#ffd479; } .dbadge.ok{ background:rgba(46,230,160,.18); color:#7af3b0; }
.dmuted{ color:#6b7686; font-size:12px; padding:2px 0 4px; }
.dlog{ font-family:monospace; font-size:11px; padding:5px 8px; border-radius:6px; background:rgba(255,255,255,.03); margin-bottom:4px; line-height:1.35; } .dlog .ts{ color:#6b7686; } .dlog.sev-crit{ color:#ff9b91; } .dlog.sev-warn{ color:#ffd479; } .dlog.sev-info{ color:#a9b4c2; }
#nk-dacts{ display:flex; gap:7px; flex-wrap:wrap; padding:12px 16px; border-top:1px solid var(--border); }
#nk-dacts a.act{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:8px; padding:8px 12px; font-size:12px; text-decoration:none; display:inline-flex; align-items:center; gap:7px; }
#nk-dacts a.act:hover{ border-color:var(--accent); color:#fff; } #nk-dacts a.act.primary{ background:rgba(54,227,208,.16); border-color:rgba(54,227,208,.5); color:#bff2ee; font-weight:700; }
#nk-tip{ position:absolute; z-index:9; pointer-events:none; display:none; background:rgba(6,10,20,.92); border:1px solid var(--border); border-radius:7px; padding:6px 9px; font-size:12px; white-space:nowrap; transform:translate(-50%,-140%); } #nk-tip b{ color:#fff; }
#nk-empty{ position:absolute; inset:0; display:none; align-items:center; justify-content:center; flex-direction:column; gap:10px; color:#8a909a; text-align:center; padding:24px; }
</style>
</head>
<body>
<?php include('header.php'); ?>

<div id="nk-stage">
  <canvas id="nk-canvas"></canvas>

  <div id="nk-top" class="nk-hud"><div class="glass">
    <div id="nk-title"><i class="fa-solid fa-satellite-dish"></i> NEURUTIK <span class="tag">UNIFIED</span></div>
    <div id="nk-sub">Every node in one galaxy · click a node for its command center</div>
    <div id="nk-layers">
      <span class="lchip" data-l="traffic"><i class="fa-solid fa-bolt"></i> Traffic</span>
      <span class="lchip" data-l="routes"><i class="fa-solid fa-diagram-project"></i> Routes</span>
      <span class="lchip" data-l="db"><i class="fa-solid fa-database"></i> DB</span>
      <span class="lchip" data-l="services"><i class="fa-solid fa-dna"></i> Services</span>
      <span class="lchip" data-l="holo"><i class="fa-solid fa-cube"></i> Hologram</span>
    </div>
  </div></div>

  <div id="nk-path" class="nk-hud" style="display:none; top:118px; left:14px; max-width:340px;"><div class="glass" style="padding:10px 13px;">
    <div style="font-size:11px;color:#dcccff;text-transform:uppercase;letter-spacing:.5px;display:flex;align-items:center;gap:7px;"><i class="fa-solid fa-route"></i> Path simulator</div>
    <select id="nk-path-from" style="width:100%;background:rgba(0,0,0,.4);border:1px solid var(--border);color:#cfe4ff;border-radius:7px;padding:6px 8px;font-size:12px;margin-top:8px;"></select>
    <div style="display:flex;gap:6px;margin-top:6px;">
      <input id="nk-path-dest" placeholder="dest IP · e.g. 8.8.8.8" onkeydown="if(event.key==='Enter')pathSim()" style="flex:1;background:rgba(0,0,0,.4);border:1px solid var(--border);color:#7fd1ff;border-radius:7px;padding:6px 8px;font-family:Consolas,monospace;font-size:12px;">
      <button class="nkbtn" style="height:auto;padding:6px 12px;" onclick="pathSim()"><i class="fa-solid fa-play"></i></button>
    </div>
    <div id="nk-path-out" style="font-size:12px;margin-top:8px;color:#9aa3af;min-height:16px;"></div>
  </div></div>

  <div id="nk-stats" class="nk-hud"><div class="glass">
    <div class="nkstat"><div class="n" id="s-nodes">—</div><div class="l">Nodes</div></div>
    <div class="nkstat"><div class="n ok" id="s-up">—</div><div class="l">Up</div></div>
    <div class="nkstat"><div class="n crit" id="s-down">—</div><div class="l">Down</div></div>
    <div class="nkstat"><div class="n warn" id="s-inc">—</div><div class="l">Incidents</div></div>
    <div class="nkstat"><div class="n cyan" id="s-thru">—</div><div class="l">Throughput</div></div>
  </div></div>

  <div id="nk-ctl" class="nk-hud">
    <button class="nkbtn on" id="b-labels" title="Toggle labels"><i class="fa-solid fa-tag"></i></button>
    <button class="nkbtn on" id="b-spin" title="Auto-rotate"><i class="fa-solid fa-arrows-rotate"></i></button>
    <button class="nkbtn" id="b-fit" title="Reset view"><i class="fa-solid fa-crosshairs"></i></button>
    <button class="nkbtn" id="b-full" title="Fullscreen"><i class="fa-solid fa-expand"></i></button>
  </div>

  <div id="nk-legend" class="nk-hud"><div class="glass" id="nk-legend-body"></div></div>
  <div id="nk-hint" class="nk-hud"><div class="glass"><i class="fa-solid fa-hand-pointer"></i> Drag to orbit · scroll to zoom · click a node · toggle layers ↖</div></div>

  <div id="nk-info" class="nk-hud"><div class="glass">
    <div id="nk-dh">
      <span class="x" onclick="document.getElementById('nk-info').style.display='none'; NK.sel=null;"><i class="fa-solid fa-xmark"></i></span>
      <h3 id="hi-name">—</h3>
      <div class="meta"><span id="nk-kind">—</span> <span id="hi-meta"></span></div>
    </div>
    <div id="nk-db"><div class="dmuted">Loading node dossier…</div></div>
    <div id="nk-dacts"></div>
  </div></div>

  <div id="nk-tip"></div>
  <div id="nk-empty"><i class="fa-solid fa-satellite-dish" style="font-size:34px;opacity:.4;"></i><div id="nk-empty-msg">Building the galaxy…</div></div>
</div>

<script src="three.min.js"></script>
<script src="three-orbitcontrols.js"></script>
<script>
const NK = { nodes:[], links:[], inv:{}, meshes:{}, sel:null, layers:{traffic:false,routes:false,db:false,services:false,holo:false}, enrich:{}, labels:true, spin:true };

// ── WebGL guard ──────────────────────────────────────────────────────────────
(function(){ let ok=false; try{ const c=document.createElement('canvas'); ok=!!(window.WebGLRenderingContext && (c.getContext('webgl')||c.getContext('experimental-webgl'))); }catch(e){}
  if(!ok || typeof THREE==='undefined'){ const e=document.getElementById('nk-empty'); e.style.display='flex'; document.getElementById('nk-empty-msg').textContent='WebGL is not available in this browser.'; }
})();

const stage=document.getElementById('nk-stage'), canvas=document.getElementById('nk-canvas');
const renderer=new THREE.WebGLRenderer({canvas,antialias:true,alpha:true});
renderer.setPixelRatio(Math.min(devicePixelRatio,2));
const scene=new THREE.Scene(); scene.fog=new THREE.FogExp2(0x04050c,0.0006);
const camera=new THREE.PerspectiveCamera(55,1,1,8000); camera.position.set(0,220,760);
const controls=new THREE.OrbitControls(camera,renderer.domElement);
controls.enableDamping=true; controls.dampingFactor=.08; controls.autoRotate=true; controls.autoRotateSpeed=.35; controls.minDistance=120; controls.maxDistance=3200;
scene.add(new THREE.AmbientLight(0x8899cc,0.95));
const key=new THREE.PointLight(0x88bbff,0.7,0); key.position.set(300,500,400); scene.add(key);

const gNodes=new THREE.Group(), gLinks=new THREE.Group(), gLabels=new THREE.Group(), gLayer=new THREE.Group();
scene.add(gLinks); scene.add(gLayer); scene.add(gNodes); scene.add(gLabels);

const KIND_COLOR={ router:0x4da3ff, linux:0xf3b52c, windows:0x36a3ff, ping:0x9aa3af, snmp:0x8a7dff };
const STATUS_COLOR={ up:0x2ee6a0, down:0xe74c3c, degraded:0xf3b52c, unknown:0x6b7686 };
function nodeColor(n){ if(n.status==='down') return 0xe74c3c; if(n.incidents>0) return 0xf3b52c; if(n.status==='degraded') return 0xf3b52c; return STATUS_COLOR[n.status]||0x6b7686; }
function resize(){ const w=stage.clientWidth,h=stage.clientHeight; renderer.setSize(w,h,false); camera.aspect=w/h; camera.updateProjectionMatrix(); }
new ResizeObserver(resize).observe(stage); resize();

// ── ported scene kit (DB reactor + Biosphere membrane, verbatim from the sources) ──
const LEVEL_COLOR={ healthy:0x2ee6a0, stressed:0xf3b52c, sick:0xff7a45, critical:0xe74c3c, unknown:0x6b7686 };
const CORE_GEO=new THREE.IcosahedronGeometry(9,2);
NK.layerAnim=[];   // {kind:'core'|'gal'|'shader'|'conduit', ...} rebuilt each applyLayers, ticked in animate()
NK.pickExtra=[];   // extra clickable meshes from layers (DB reactors, service cells)

// galaxy shader (table tiles / vital orbs as glowing points)
const GAL_VS=`attribute vec3 aColor; attribute float aSize; attribute float aAlpha; varying vec3 vC; varying float vA;
  void main(){ vC=aColor; vA=aAlpha; vec4 mv=modelViewMatrix*vec4(position,1.0); gl_PointSize=aSize*(300.0/max(1.0,-mv.z)); gl_Position=projectionMatrix*mv; }`;
const GAL_FS=`varying vec3 vC; varying float vA; void main(){ float d=length(gl_PointCoord-vec2(0.5)); if(d>0.5) discard;
  float core=smoothstep(0.5,0.0,d); gl_FragColor=vec4(mix(vC*1.7,vec3(1.0),pow(core,3.0)*0.5), core*vA); }`;
// table galaxy for a DB (size=rows, color=read↔write)
function dbGalaxy(db){ const tt=db.top_tables||[]; const n=tt.length; if(!n) return null;
  const g=new THREE.BufferGeometry(); const pos=new Float32Array(n*3),col=new Float32Array(n*3),sz=new Float32Array(n),al=new Float32Array(n);
  const maxRows=Math.max(1,...tt.map(t=>+t.rows||0)), maxAct=Math.max(1,...tt.map(t=>(+t.reads)+(+t.writes)));
  tt.forEach((t,i)=>{ const a=2.399963*i, r=20+Math.sqrt((i+1)/n)*40; pos[i*3]=Math.cos(a)*r; pos[i*3+1]=Math.sin(i*1.7)*5; pos[i*3+2]=Math.sin(a)*r;
    const act=(+t.reads)+(+t.writes), wr=act>0?(+t.writes)/act:0; const c=new THREE.Color().setHSL(0.58-wr*0.58,0.9,0.6);
    col[i*3]=c.r;col[i*3+1]=c.g;col[i*3+2]=c.b; sz[i]=4+Math.sqrt((+t.rows||0)/maxRows)*8; al[i]=0.6+(act/maxAct)*0.4; });
  g.setAttribute('position',new THREE.BufferAttribute(pos,3)); g.setAttribute('aColor',new THREE.BufferAttribute(col,3));
  g.setAttribute('aSize',new THREE.BufferAttribute(sz,1)); g.setAttribute('aAlpha',new THREE.BufferAttribute(al,1));
  return new THREE.Points(g,new THREE.ShaderMaterial({transparent:true,depthWrite:false,blending:THREE.AdditiveBlending,vertexShader:GAL_VS,fragmentShader:GAL_FS})); }
// vital-orb galaxy for a service (size=latency, alpha=recency)
function svcGalaxy(orbits){ const n=(orbits||[]).length; if(!n) return null; const g=new THREE.BufferGeometry();
  const pos=new Float32Array(n*3),col=new Float32Array(n*3),sz=new Float32Array(n),al=new Float32Array(n); const maxLat=Math.max(1,...orbits.map(o=>+o.lat||0));
  orbits.forEach((o,i)=>{ const a=2.399963*i, r=15+Math.sqrt((i+1)/n)*20; pos[i*3]=Math.cos(a)*r; pos[i*3+1]=Math.sin(i*1.7)*4; pos[i*3+2]=Math.sin(a)*r;
    const hex=(o.ok===0)?LEVEL_COLOR.critical:(LEVEL_COLOR[o.level]!=null?LEVEL_COLOR[o.level]:LEVEL_COLOR.unknown); const c=new THREE.Color(hex);
    col[i*3]=c.r;col[i*3+1]=c.g;col[i*3+2]=c.b; sz[i]=3.5+Math.sqrt((+o.lat||0)/maxLat)*6; al[i]=0.35+((i+1)/n)*0.6; });
  g.setAttribute('position',new THREE.BufferAttribute(pos,3)); g.setAttribute('aColor',new THREE.BufferAttribute(col,3));
  g.setAttribute('aSize',new THREE.BufferAttribute(sz,1)); g.setAttribute('aAlpha',new THREE.BufferAttribute(al,1));
  return new THREE.Points(g,new THREE.ShaderMaterial({transparent:true,depthWrite:false,blending:THREE.AdditiveBlending,vertexShader:GAL_VS,fragmentShader:GAL_FS})); }
// connection-pool gauge ring (lit segments = load)
function poolRing(load){ const grp=new THREE.Group(); const N=32, lit=Math.round(Math.min(1,load||0)*N);
  const col=new THREE.Color(load>=0.85?0xe74c3c:(load>=0.7?0xf3b52c:0x4da3ff)); const geo=new THREE.BoxGeometry(1.8,1.8,4);
  for(let i=0;i<N;i++){ const on=i<lit,a=i/N*Math.PI*2,r=18; const m=new THREE.Mesh(geo,new THREE.MeshBasicMaterial({color:on?col:0x2a3550,transparent:true,opacity:on?0.95:0.22}));
    m.position.set(Math.cos(a)*r,0,Math.sin(a)*r); m.lookAt(0,0,0); grp.add(m); } grp.rotation.x=Math.PI/2.6; return grp; }
// GLSL Ashima simplex noise → organic breathing membrane (verbatim from Biosphere)
const SNOISE=`vec4 permute(vec4 x){return mod(((x*34.0)+1.0)*x,289.0);} vec4 taylorInvSqrt(vec4 r){return 1.79284291400159-0.85373472095314*r;}
float snoise(vec3 v){ const vec2 C=vec2(1.0/6.0,1.0/3.0); const vec4 D=vec4(0.0,0.5,1.0,2.0); vec3 i=floor(v+dot(v,C.yyy)); vec3 x0=v-i+dot(i,C.xxx);
  vec3 g=step(x0.yzx,x0.xyz); vec3 l=1.0-g; vec3 i1=min(g.xyz,l.zxy); vec3 i2=max(g.xyz,l.zxy); vec3 x1=x0-i1+1.0*C.xxx; vec3 x2=x0-i2+2.0*C.xxx; vec3 x3=x0-1.0+3.0*C.xxx;
  i=mod(i,289.0); vec4 p=permute(permute(permute(i.z+vec4(0.0,i1.z,i2.z,1.0))+i.y+vec4(0.0,i1.y,i2.y,1.0))+i.x+vec4(0.0,i1.x,i2.x,1.0));
  float n_=1.0/7.0; vec3 ns=n_*D.wyz-D.xzx; vec4 j=p-49.0*floor(p*ns.z*ns.z); vec4 x_=floor(j*ns.z); vec4 y_=floor(j-7.0*x_); vec4 x=x_*ns.x+ns.yyyy; vec4 y=y_*ns.x+ns.yyyy; vec4 h=1.0-abs(x)-abs(y);
  vec4 b0=vec4(x.xy,y.xy); vec4 b1=vec4(x.zw,y.zw); vec4 s0=floor(b0)*2.0+1.0; vec4 s1=floor(b1)*2.0+1.0; vec4 sh=-step(h,vec4(0.0)); vec4 a0=b0.xzyw+s0.xzyw*sh.xxyy; vec4 a1=b1.xzyw+s1.xzyw*sh.zzww;
  vec3 p0=vec3(a0.xy,h.x); vec3 p1=vec3(a0.zw,h.y); vec3 p2=vec3(a1.xy,h.z); vec3 p3=vec3(a1.zw,h.w); vec4 norm=taylorInvSqrt(vec4(dot(p0,p0),dot(p1,p1),dot(p2,p2),dot(p3,p3))); p0*=norm.x;p1*=norm.y;p2*=norm.z;p3*=norm.w;
  vec4 m=max(0.6-vec4(dot(x0,x0),dot(x1,x1),dot(x2,x2),dot(x3,x3)),0.0); m=m*m; return 42.0*dot(m*m,vec4(dot(p0,x0),dot(p1,x1),dot(p2,x2),dot(p3,x3))); }`;
const CELL_VERT=SNOISE+`uniform float uTime,uPulse,uFrozen,uSludge; varying vec3 vN; varying vec3 vPos;
void main(){ vN=normal; vPos=position; float spd=mix(0.35+uPulse*1.6,0.04,uFrozen); float amp=mix(0.10+uPulse*0.42,0.03,uFrozen);
  float n=snoise(normal*(1.5+uPulse*1.4)+vec3(uTime*spd)); n+=0.4*snoise(normal*3.4-vec3(uTime*spd*0.6)); float disp=n*amp-uSludge*0.10*(0.5+0.5*normal.y);
  vec3 pos=position+normal*disp; gl_Position=projectionMatrix*modelViewMatrix*vec4(pos,1.0); }`;
const CELL_FRAG=SNOISE+`uniform float uTime,uInfect,uSludge,uFrozen,uHiber,uDisabled; uniform vec3 uColor; varying vec3 vN; varying vec3 vPos;
void main(){ vec3 L=normalize(vec3(0.5,0.8,0.6)); float diff=0.45+0.55*max(dot(normalize(vN),L),0.0); vec3 base=uColor; base=mix(base,vec3(0.20,0.24,0.16),uSludge*0.7); base=mix(base,vec3(0.55,0.78,1.0),uFrozen*0.6);
  vec3 col=base*diff; float rim=pow(1.0-max(dot(normalize(vN),vec3(0.0,0.0,1.0)),0.0),2.2); col+=uColor*rim*0.9;
  float inf=snoise(vPos*2.6+vec3(uTime*0.15)); float patch=smoothstep(1.0-uInfect*1.4,1.02-uInfect*1.4,inf); col=mix(col,vec3(0.06,0.01,0.02),patch*uInfect); col+=vec3(0.9,0.15,0.1)*patch*uInfect*0.5;
  float alpha=mix(0.6,0.24,uHiber); alpha=mix(alpha,0.12,uDisabled); gl_FragColor=vec4(col,alpha); }`;
const MEMBRANE_GEO=new THREE.IcosahedronGeometry(13,5);
function reactorCore(colHex){ return new THREE.Mesh(CORE_GEO,new THREE.MeshStandardMaterial({color:colHex,emissive:colHex,emissiveIntensity:.9,roughness:.3,metalness:.35,flatShading:true})); }

// ── deterministic force layout (seeded, stable across polls) ─────────────────
function hash(i){ let x=Math.sin(i*127.1+12.7)*43758.5453; return x-Math.floor(x); }
function computeLayout(nodes,links){
  const idx={}; nodes.forEach((n,i)=>idx[n.id]=i);
  const P=nodes.map((n,i)=>{ const t=hash(n.id)*Math.PI*2, u=hash(n.id*3.3)*2-1, r=260+hash(n.id*7.7)*120;
    const s=Math.sqrt(Math.max(0,1-u*u)); return new THREE.Vector3(Math.cos(t)*s*r, u*r*0.6, Math.sin(t)*s*r); });
  const edges=links.map(l=>[idx[l.source],idx[l.target]]).filter(e=>e[0]!=null&&e[1]!=null);
  for(let it=0;it<90;it++){ const disp=P.map(()=>new THREE.Vector3());
    for(let i=0;i<P.length;i++) for(let j=i+1;j<P.length;j++){ const d=new THREE.Vector3().subVectors(P[i],P[j]); let len=d.length()||0.01; const f=6200/(len*len); d.multiplyScalar(f/len); disp[i].add(d); disp[j].sub(d); }
    for(const [a,b] of edges){ const d=new THREE.Vector3().subVectors(P[a],P[b]); const len=d.length()||0.01; const f=(len-150)*0.02; d.multiplyScalar(f/len); disp[a].sub(d); disp[b].add(d); }
    for(let i=0;i<P.length;i++){ disp[i].clampLength(0,26); P[i].add(disp[i]); }
  }
  return P;
}

// ── label sprite ─────────────────────────────────────────────────────────────
function makeLabel(text){ const c=document.createElement('canvas'); const ctx=c.getContext('2d'); ctx.font='600 26px Segoe UI,sans-serif';
  const w=ctx.measureText(text).width+16; c.width=w; c.height=40; ctx.font='600 26px Segoe UI,sans-serif'; ctx.fillStyle='rgba(6,10,20,.72)'; ctx.fillRect(0,0,w,40); ctx.fillStyle='#dbe6f5'; ctx.textBaseline='middle'; ctx.fillText(text,8,22);
  const tex=new THREE.CanvasTexture(c); tex.minFilter=THREE.LinearFilter; const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:tex,transparent:true,depthWrite:false,depthTest:false}));
  sp.scale.set(w*0.32,13,1); return sp; }

// ── link particle system (shared) — density/brightness ∝ throughput ──────────
let linkPoints=null;
function buildLinks(nodes,links,P){
  gLinks.clear(); if(linkPoints){ linkPoints.geometry.dispose(); linkPoints=null; }
  const idx={}; nodes.forEach((n,i)=>idx[n.id]=i);
  const segs=[]; const per=[]; let total=0;
  links.forEach(l=>{ const a=idx[l.source],b=idx[l.target]; if(a==null||b==null) return;
    const rate=(l.in_rate||0)+(l.out_rate||0); const cnt=Math.max(6,Math.min(60,Math.round(8+Math.log10(1+rate)*7)));
    segs.push({a,b,rate,cnt}); total+=cnt;
    const g=new THREE.BufferGeometry().setFromPoints([P[a],P[b]]);
    gLinks.add(new THREE.Line(g,new THREE.LineBasicMaterial({color:0x2a3550,transparent:true,opacity:.28}))); });
  // particles
  const pos=new Float32Array(total*3), col=new Float32Array(total*3), al=new Float32Array(total), sz=new Float32Array(total);
  const meta=[]; let o=0;
  segs.forEach(s=>{ for(let k=0;k<s.cnt;k++){ meta.push({a:s.a,b:s.b,t:Math.random(),spd:0.15+Math.random()*0.25,rate:s.rate,dir:k%2?1:-1}); al[o]=.5; sz[o]=8+Math.min(10,Math.log10(1+s.rate)); o++; } });
  const geo=new THREE.BufferGeometry();
  geo.setAttribute('position',new THREE.BufferAttribute(pos,3)); geo.setAttribute('aColor',new THREE.BufferAttribute(col,3));
  geo.setAttribute('aAlpha',new THREE.BufferAttribute(al,1)); geo.setAttribute('aSize',new THREE.BufferAttribute(sz,1));
  const mat=new THREE.ShaderMaterial({ transparent:true, depthWrite:false, blending:THREE.AdditiveBlending,
    vertexShader:`attribute vec3 aColor; attribute float aAlpha; attribute float aSize; varying vec3 vC; varying float vA;
      void main(){ vC=aColor; vA=aAlpha; vec4 mv=modelViewMatrix*vec4(position,1.0); gl_PointSize=aSize*(300.0/-mv.z); gl_Position=projectionMatrix*mv; }`,
    fragmentShader:`varying vec3 vC; varying float vA; void main(){ float d=length(gl_PointCoord-vec2(.5)); if(d>.5) discard; float a=smoothstep(.5,.0,d)*vA; gl_FragColor=vec4(vC,a); }` });
  linkPoints=new THREE.Points(geo,mat); linkPoints.frustumCulled=false; linkPoints.userData={meta,P}; scene.add(linkPoints);
}

// ── build scene from inventory + topo ────────────────────────────────────────
const raycaster=new THREE.Raycaster(); const mouse=new THREE.Vector2();
function rebuild(){
  gNodes.clear(); gLabels.clear(); NK.meshes={};
  const nodes=NK.nodes, links=NK.links; if(!nodes.length){ document.getElementById('nk-empty').style.display='flex'; document.getElementById('nk-empty-msg').textContent='No nodes yet.'; return; }
  document.getElementById('nk-empty').style.display='none';
  const P=computeLayout(nodes,links);
  nodes.forEach((n,i)=>{ n._p=P[i];
    const inv=NK.inv[n.id]||{}; n.kind=inv.kind||'snmp'; n.incidents=inv.incidents||0; if(inv.latency!=null)n.latency=inv.latency;
    const col=nodeColor(n);
    const core=new THREE.Mesh(new THREE.IcosahedronGeometry(11,1), new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:.5,metalness:.3,roughness:.4}));
    core.position.copy(P[i]); core.userData={id:n.id,node:n,base:11}; gNodes.add(core);
    const halo=new THREE.Mesh(new THREE.SphereGeometry(16,16,16), new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:.14,blending:THREE.AdditiveBlending,depthWrite:false})); halo.position.copy(P[i]); gNodes.add(halo);
    // kind ring
    const ring=new THREE.Mesh(new THREE.TorusGeometry(15,0.7,8,32), new THREE.MeshBasicMaterial({color:KIND_COLOR[n.kind]||0x8a7dff,transparent:true,opacity:.6})); ring.position.copy(P[i]); ring.rotation.x=Math.PI/2; gNodes.add(ring);
    const lbl=makeLabel(n.name||('#'+n.id)); lbl.position.copy(P[i]).add(new THREE.Vector3(0,22,0)); gLabels.add(lbl);
    NK.meshes[n.id]={core,halo,ring,lbl,pulse:hash(n.id)*6.28};
  });
  buildLinks(nodes,links,P);
  gLabels.visible=NK.labels;
  updateStats();
  applyLayers();
}

function updateStats(){
  let up=0,down=0,inc=0,thru=0;
  NK.nodes.forEach(n=>{ if(n.status==='up')up++; else if(n.status==='down')down++; inc+=(n.incidents||0); });
  NK.links.forEach(l=>thru+=(l.in_rate||0)+(l.out_rate||0));
  document.getElementById('s-nodes').textContent=NK.nodes.length;
  document.getElementById('s-up').textContent=up; document.getElementById('s-down').textContent=down;
  document.getElementById('s-inc').textContent=inc;
  document.getElementById('s-thru').textContent=fmtbps(thru);
}
function fmtbps(b){ b=+b; if(!b||!isFinite(b))return '0'; const u=['bps','K','M','G','T']; let i=0; while(b>=1000&&i<u.length-1){b/=1000;i++;} return b.toFixed(b<10?1:0)+u[i]; }

// ── layers ───────────────────────────────────────────────────────────────────
function legend(items){ document.getElementById('nk-legend-body').innerHTML = items.length? items.map(x=>`<div class="leg"><span class="sw" style="color:${x.c}"></span>${x.t}</div>`).join('') : '<div class="leg" style="color:#6b7686">Toggle a layer ↖</div>'; }
async function toggleLayer(l){ NK.layers[l]=!NK.layers[l]; document.querySelector(`.lchip[data-l="${l}"]`).classList.toggle('on',NK.layers[l]);
  if(NK.layers[l]){ await loadLayer(l); } applyLayers(); }
async function loadLayer(l){
  try{
    if(l==='holo'){ const d=await fetch(`neurutik.php?api=layer&l=holo&_=${Date.now()}`).then(r=>r.json()); if(d.ok){ NK.enrich=d.nodes||{}; NK.apps=d.apps||{}; } }
    else if(l==='routes'){ const d=await fetch(`neurutik.php?api=layer&l=routes&_=${Date.now()}`).then(r=>r.json()); NK.routes=d.ok?d:null; }
    else if(l==='db'){ const d=await fetch(`neurutik.php?api=layer&l=db&_=${Date.now()}`).then(r=>r.json()); NK.db=d.ok?d:null; }
    else if(l==='services'){ const d=await fetch(`neurutik.php?api=layer&l=services&_=${Date.now()}`).then(r=>r.json()); NK.services=d.ok?d:null; }
  }catch(e){}
}
function applyLayers(){
  gLayer.clear(); NK.layerAnim=[]; NK.pickExtra=[];
  const leg=[];
  // Traffic: brighten link particles by rate + hot color near saturation
  // Hologram: color link particles by top app of an endpoint
  if(linkPoints){ const {meta}=linkPoints.userData; const col=linkPoints.geometry.getAttribute('aColor');
    for(let i=0;i<meta.length;i++){ const m=meta[i]; let c=new THREE.Color(0x36e3d0);
      if(NK.layers.holo){ const endNode=NK.nodes[m.dir>0?m.b:m.a]; const e=endNode&&NK.enrich[endNode.id]; if(e&&e.color){ c=new THREE.Color(e.color); } }
      if(NK.layers.traffic){ const norm=Math.min(1,Math.log10(1+m.rate)/9); c.lerp(new THREE.Color(0xff6a4d),norm*0.7); }
      col.setXYZ(i,c.r,c.g,c.b); }
    col.needsUpdate=true;
  }
  if(NK.layers.traffic) leg.push({c:'#36e3d0',t:'Traffic — brightness ∝ rate'});
  if(NK.layers.holo && NK.apps){ Object.keys(NK.apps).slice(0,6).forEach(a=>leg.push({c:NK.apps[a],t:a})); }
  // Routes: draw proto-colored conduits between routers
  if(NK.layers.routes && NK.routes){ drawRoutes(); leg.push({c:'#36e3d0',t:'connected'},{c:'#4da3ff',t:'static'},{c:'#b388ff',t:'dynamic'},{c:'#ffb454',t:'default→net'}); }
  // DB: reactor satellite next to its mapped node (or float near center)
  if(NK.layers.db && NK.db){ drawDB(); leg.push({c:'#2ee6a0',t:'DB reactor · pulse=load'}); }
  // Services: cells orbit their node
  if(NK.layers.services && NK.services){ drawServices(); leg.push({c:'#f3b52c',t:'Service cell · GLSL membrane'}); }
  legend(leg);
  const pp=document.getElementById('nk-path'); if(pp){ pp.style.display=NK.layers.routes?'block':'none'; if(NK.layers.routes) fillPathFrom(); else clearPath(); }
}
function nodePos(id){ const m=NK.meshes[id]; return m?m.core.position:null; }
const PROTO={connected:0x36e3d0,static:0x4da3ff,dynamic:0xb388ff,internet:0xffb454,blackhole:0xe74c3c};

// ── 🧭 ROUTES — protocol-coloured L3 fabric with flowing packets + subnet boxes + internet cloud ──
function drawRoutes(){ const t=NK.routes; if(!t||!t.links) return;
  // internet cloud (top) for default routes
  let inet=null; if(t.internet){ inet=new THREE.Mesh(new THREE.IcosahedronGeometry(14,1),new THREE.MeshBasicMaterial({color:0xffb454,transparent:true,opacity:.5,wireframe:true})); inet.position.set(0,260,0); gLayer.add(inet); }
  t.links.forEach(l=>{ const from=nodePos(l.from); if(!from) return; let to=null;
    if(l.kind==='router'){ to=nodePos(parseInt((''+l.to).replace('r:',''))); }
    else if(l.kind==='internet'){ to=inet?inet.position:new THREE.Vector3(0,260,0); }
    else if(l.kind==='subnet'){ const off=new THREE.Vector3((hash(l.from*7+1)*2-1)*46,(hash(l.from*13+3)*2-1)*30,(hash(l.from*17+5)*2-1)*46); to=from.clone().add(off);
      const box=new THREE.Mesh(new THREE.BoxGeometry(4,4,4),new THREE.MeshBasicMaterial({color:0x36e3d0,transparent:true,opacity:.6})); box.position.copy(to); gLayer.add(box); }
    if(!to) return; const mid=from.clone().add(to).multiplyScalar(.5); mid.y+=34;
    const curve=new THREE.QuadraticBezierCurve3(from,mid,to); const hex=PROTO[l.protocol]||(l.is_default?0xffb454:0x8a93a6);
    const g=new THREE.BufferGeometry().setFromPoints(curve.getPoints(22)); gLayer.add(new THREE.Line(g,new THREE.LineBasicMaterial({color:hex,transparent:true,opacity:.45})));
    // flowing packets
    const P=(l.kind==='router')?10:5; const pg=new THREE.BufferGeometry(); const pp=new Float32Array(P*3); pg.setAttribute('position',new THREE.BufferAttribute(pp,3));
    const pts=new THREE.Points(pg,new THREE.PointsMaterial({color:hex,size:l.kind==='router'?5:3,transparent:true,opacity:.9,blending:THREE.AdditiveBlending,depthWrite:false})); gLayer.add(pts);
    NK.layerAnim.push({kind:'conduit',curve,pts,pp,P,phase:Math.random(),speed:l.kind==='router'?0.5:0.28}); });
}
// ── 🗄️ DB — full reactor: core + halo + pool-ring + table galaxy + replication conduits ──
function dbPos(db,i){ const host=db.node_id?nodePos(db.node_id):null; if(host) return host.clone().add(new THREE.Vector3(48,40,0)); const n=(NK.db.dbs||[]).length||1, a=(i/n)*6.28; return new THREE.Vector3(Math.cos(a)*220,160,Math.sin(a)*220); }
function drawDB(){ const dbs=NK.db.dbs||[]; const pos={};
  dbs.forEach((db,i)=>{ const p=dbPos(db,i); pos[db.id]=p; const col=LEVEL_COLOR[db.level]||LEVEL_COLOR.unknown; const grp=new THREE.Group(); grp.position.copy(p);
    // tether the DB reactor to its HOST node so the relationship is visible
    const host=db.node_id?nodePos(db.node_id):null;
    if(host){ const tg=new THREE.BufferGeometry().setFromPoints([host.clone(),p.clone()]);
      gLayer.add(new THREE.Line(tg,new THREE.LineBasicMaterial({color:col,transparent:true,opacity:.35})));
      const midp=host.clone().lerp(p,0.5); const dot=new THREE.Mesh(new THREE.SphereGeometry(1.6,8,8),new THREE.MeshBasicMaterial({color:col})); dot.position.copy(midp); gLayer.add(dot); }
    const core=reactorCore(col); core.userData={pick:'db',db:db}; grp.add(core); NK.pickExtra.push(core);
    const halo=new THREE.Mesh(new THREE.SphereGeometry(13,18,18),new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:.10,blending:THREE.AdditiveBlending,depthWrite:false})); grp.add(halo);
    grp.add(poolRing((db.viz&&db.viz.load)||0));
    const gal=dbGalaxy(db); if(gal) grp.add(gal);
    grp.userData.dbid=db.id; gLayer.add(grp);
    // DB label (🗄 name) so each reactor is identifiable
    const lbl=makeLabel('🗄 '+(db.name||('db'+db.id))); lbl.position.copy(p).add(new THREE.Vector3(0,22,0)); lbl.visible=NK.labels; gLayer.add(lbl);
    const v=db.viz||{}; NK.layerAnim.push({kind:'reactor',core,halo,gal,t:Math.random()*10,pulse:v.pulse||0,load:v.load||0,slow:v.slow||0,frozen:v.frozen||0,size:0.8+(v.size||0)*0.9}); });
  // replication conduits (master→replica)
  (NK.db.links||[]).forEach(l=>{ const a=pos[l.from],b=pos[l.to]; if(!a||!b) return; const mid=a.clone().add(b).multiplyScalar(.5); mid.y+=44;
    const curve=new THREE.QuadraticBezierCurve3(a,mid,b); const down=(!l.io||!l.sql); const hex=down?0xe74c3c:((l.behind!=null&&l.behind>30)?0xf3b52c:0x2ee6a0);
    const g=new THREE.BufferGeometry().setFromPoints(curve.getPoints(30)); gLayer.add(new THREE.Line(g,new THREE.LineBasicMaterial({color:hex,transparent:true,opacity:.35})));
    const P=18; const pg=new THREE.BufferGeometry(); const pp=new Float32Array(P*3); pg.setAttribute('position',new THREE.BufferAttribute(pp,3));
    const pts=new THREE.Points(pg,new THREE.PointsMaterial({color:hex,size:4,transparent:true,opacity:.95,blending:THREE.AdditiveBlending,depthWrite:false})); gLayer.add(pts);
    NK.layerAnim.push({kind:'conduit',curve,pts,pp,P,phase:0,speed:down?0:(0.05+1/(1+(l.behind||0))*0.4)}); });
}
// ── 🧬 SERVICES — living GLSL membrane cells that breathe, infect, sludge, freeze — orbiting their node ──
function drawServices(){ const svcs=NK.services.services||[]; const byNode={};
  svcs.forEach(s=>{ const host=s.node_id?nodePos(s.node_id):null; if(!host) return; const k=s.node_id; byNode[k]=(byNode[k]||0); const idx=byNode[k]++;
    const ang=idx*2.399963+hash(s.id)*6.28; const orb=new THREE.Vector3(Math.cos(ang)*40,14+Math.sin(idx*1.3)*16,Math.sin(ang)*40); const p=host.clone().add(orb);
    const col=new THREE.Color(LEVEL_COLOR[(s.vitals&&s.vitals.level)]||LEVEL_COLOR.unknown); const v=s.viz||{};
    const mat=new THREE.ShaderMaterial({transparent:true,uniforms:{ uTime:{value:Math.random()*20},uPulse:{value:v.pulse||0},uInfect:{value:v.infection||0},uSludge:{value:v.sludge||0},uFrozen:{value:v.frozen||0},uHiber:{value:v.hibernating||0},uDisabled:{value:v.disabled||0},uColor:{value:col} },vertexShader:CELL_VERT,fragmentShader:CELL_FRAG});
    const cell=new THREE.Mesh(MEMBRANE_GEO,mat); cell.position.copy(p); cell.userData={pick:'svc',node_id:s.node_id,svc:s}; gLayer.add(cell); NK.pickExtra.push(cell);
    const core=reactorCore(col.getHex()); core.scale.setScalar(.55); core.position.copy(p); gLayer.add(core);
    const gal=svcGalaxy(s.orbits); if(gal){ gal.position.copy(p); gLayer.add(gal); }
    NK.layerAnim.push({kind:'cell',mat,core,gal,t:Math.random()*10,pulse:v.pulse||0,frozen:v.frozen||0}); }); }

// ── dossier ──────────────────────────────────────────────────────────────────
async function openNode(id){
  NK.sel=id; const inv=NK.inv[id]||{}; const info=document.getElementById('nk-info'); info.style.display='block';
  document.getElementById('hi-name').textContent=inv.name||('Node #'+id);
  document.getElementById('nk-kind').textContent=inv.kind||'node';
  document.getElementById('hi-meta').textContent=inv.ip||'';
  document.getElementById('nk-db').innerHTML='<div class="dmuted">Loading node dossier…</div>';
  // deep-link to this node's OWN command center
  const acts=document.getElementById('nk-dacts');
  acts.innerHTML = (inv.cc_url? `<a class="act primary" href="${inv.cc_url}"><i class="fa-solid ${inv.cc_icon||'fa-arrow-up-right-from-square'}"></i> ${inv.cc_label||'Open Command Center'} →</a>`:'')
    + `<a class="act" href="troubleshoot.php?node=${id}"><i class="fa-solid fa-wrench"></i> Investigate</a>`;
  let d; try{ d=await fetch(`neurutik.php?api=node&id=${id}&_=${Date.now()}`).then(r=>r.json()); }catch(e){ d={ok:false,error:''+e}; }
  if(!d||!d.ok||!d.node){ document.getElementById('nk-db').innerHTML='<div class="dmuted">No dossier available.'+(d&&d.error?' <span style="color:#ff9b91">'+esc(d.error)+'</span>':'')+'</div>'; return; }
  try{ renderDossier(d); }catch(e){ document.getElementById('nk-db').innerHTML='<div class="dmuted" style="color:#ff9b91">Dossier render error: '+esc(''+e)+'</div>'; }
}
function esc(s){ return (''+(s==null?'':s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function sevClass(s){ s=(''+s).toLowerCase(); if(s.includes('crit'))return 'crit'; if(s.includes('warn')||s==='medium')return 'warn'; if(s.includes('ok')||s==='resolved')return 'ok'; return 'info'; }
function renderDossier(d){
  const n=d.node; let h='';
  const cells=[ ['Status',n.status||'—'], ['Latency',n.latency_ms!=null?n.latency_ms+' ms':'—'], ['Avail 24h',n.avail_24h!=null?n.avail_24h+'%':'—'],
    ['CPU',n.cpu!=null?Math.round(n.cpu)+'%':'—'], ['Memory',n.memory!=null?Math.round(n.memory)+'%':'—'], ['Uptime',n.uptime_sec?fmtUp(n.uptime_sec):'—'] ];
  h+='<div class="dgrid">'+cells.map(c=>`<div class="dcell"><div class="l">${c[0]}</div><div class="v">${esc(c[1])}</div></div>`).join('')+'</div>';
  const sec=(t,c)=>`<div class="dsec">${t} ${c!=null?`<span class="cnt">${c}</span>`:''}</div>`;
  if(d.incidents&&d.incidents.length){ h+=sec('<i class="fa-solid fa-triangle-exclamation"></i> Incidents',d.incidents.length);
    d.incidents.forEach(x=>h+=`<div class="ditem ${sevClass(x.severity)}"><div class="t">${esc(x.title)}<span class="dbadge ${sevClass(x.severity)}">${esc(x.status)}</span></div><div class="d">${esc(x.root_source||'')} · ${esc((x.opened_at||'').slice(5,16))}</div></div>`); }
  if(d.insights&&d.insights.length){ h+=sec('<i class="fa-solid fa-brain"></i> AI Insights',d.insights.length);
    d.insights.slice(0,6).forEach(x=>h+=`<div class="ditem ${sevClass(x.severity)}"><div class="t">${esc(x.title)}<span class="dbadge">${esc(x.kind||'')}</span></div><div class="d">${esc(x.source||'')} · ${esc((x.created_at||'').slice(5,16))}</div></div>`); }
  if(d.health&&d.health.length){ h+=sec('<i class="fa-solid fa-heart-pulse"></i> Predictive Health',d.health.length);
    d.health.forEach(x=>h+=`<div class="ditem ${sevClass(x.severity)}"><div class="t">${esc(x.metric)} ${esc(x.direction||'')}<span class="dbadge warn">${x.eta_days!=null?('~'+x.eta_days+'d'):''}</span></div><div class="d">${esc(x.detail||'')}</div></div>`); }
  if(d.interfaces&&d.interfaces.length){ h+=sec('<i class="fa-solid fa-ethernet"></i> Interfaces',d.interfaces.length);
    d.interfaces.slice(0,8).forEach(x=>h+=`<div class="ditem ${(''+x.oper_status).toLowerCase()==='up'?'ok':'crit'}"><div class="t">${esc(x.name||x.if_name)}<span class="dbadge">${esc(x.oper_status)}</span></div><div class="d">▲ ${fmtbps(x.out_rate||0)} · ▼ ${fmtbps(x.in_rate||0)}</div></div>`); }
  if(d.ai&&d.ai.length){ h+=sec('<i class="fa-solid fa-robot"></i> NetAIObot',d.ai.length);
    d.ai.slice(0,5).forEach(x=>h+=`<div class="ditem ai"><div class="t">${esc(x.tool)}<span class="dbadge ${sevClass(x.status)}">${esc(x.status)}</span></div><div class="d">${esc(x.reason||x.result||'')}</div></div>`); }
  if(d.logs&&d.logs.length){ h+=sec('<i class="fa-solid fa-scroll"></i> Recent logs',d.logs.length);
    d.logs.slice(0,8).forEach(x=>h+=`<div class="dlog sev-${sevClass(x.severity)}"><span class="ts">${esc((x.received_at||'').slice(5,16))}</span> ${esc(x.tag||'')} ${esc((x.message||'').slice(0,120))}</div>`); }
  document.getElementById('nk-db').innerHTML=h||'<div class="dmuted">No details.</div>';
}
function fmtUp(s){ s=+s; const d=Math.floor(s/86400),hh=Math.floor(s%86400/3600); return d>0?`${d}d ${hh}h`:`${hh}h`; }

// ── 🧭 path simulator (longest-prefix hop-by-hop, animated gold tube) ─────────
let pathAnim=null, pathObjs=[];
function fillPathFrom(){ const sel=document.getElementById('nk-path-from'); const routers=Object.values(NK.inv).filter(n=>n.kind==='router'); const cur=sel.value;
  sel.innerHTML = routers.length ? routers.map(r=>`<option value="${r.id}">from ${esc(r.name)}</option>`).join('') : '<option value="">no routers</option>'; if(cur) sel.value=cur; }
function clearPath(){ pathObjs.forEach(o=>{ scene.remove(o); if(o.geometry)o.geometry.dispose(); }); pathObjs=[]; pathAnim=null; }
async function pathSim(){ const from=+document.getElementById('nk-path-from').value; const dest=document.getElementById('nk-path-dest').value.trim(); const out=document.getElementById('nk-path-out');
  if(!from||!dest){ out.innerHTML='<span style="color:#ffd479">pick a source + type a dest IP</span>'; return; }
  out.textContent='Tracing…';
  let d; try{ d=await fetch(`neurutik.php?api=path&from=${from}&dest=${encodeURIComponent(dest)}&_=${Date.now()}`).then(r=>r.json()); }catch(e){ out.textContent='request failed'; return; }
  clearPath();
  if(!d.ok){ out.innerHTML='<span style="color:#ff9b91">'+esc(d.error||'no route')+'</span>'; return; }
  const oc={delivered:'#2ee6a0',internet:'#ffb454',blackhole:'#e74c3c',loop:'#e74c3c','no-route':'#ff9b91',unresolved:'#ffd479',maxhops:'#ffd479'}[d.outcome]||'#7fd1ff';
  out.innerHTML=`<b style="color:${oc}">${esc(d.outcome)}</b> · ${(d.hops||[]).length} hop(s)`;
  const pts=[]; (d.hops||[]).forEach(h=>{ const p=nodePos(h.node); if(p) pts.push(p.clone()); });
  if(d.outcome==='internet'||d.outcome==='delivered'){ pts.push(new THREE.Vector3(0,260,0)); }
  if(pts.length>=2){ const curve=new THREE.CatmullRomCurve3(pts);
    const tube=new THREE.Mesh(new THREE.TubeGeometry(curve,64,2.6,8,false),new THREE.MeshBasicMaterial({color:0xffd76a,transparent:true,opacity:.45,blending:THREE.AdditiveBlending,depthWrite:false})); scene.add(tube); pathObjs.push(tube);
    const P=34; const pg=new THREE.BufferGeometry(); const pp=new Float32Array(P*3); pg.setAttribute('position',new THREE.BufferAttribute(pp,3));
    const pmesh=new THREE.Points(pg,new THREE.PointsMaterial({color:0xffe08a,size:8,transparent:true,blending:THREE.AdditiveBlending,depthWrite:false})); scene.add(pmesh); pathObjs.push(pmesh);
    pathAnim={curve,pmesh,pp,P,phase:0}; }
}

// ── interaction ──────────────────────────────────────────────────────────────
function pick(ev){ const r=canvas.getBoundingClientRect(); mouse.x=((ev.clientX-r.left)/r.width)*2-1; mouse.y=-((ev.clientY-r.top)/r.height)*2+1; raycaster.setFromCamera(mouse,camera);
  const targets=gNodes.children.filter(o=>o.userData&&o.userData.id!=null).concat(NK.pickExtra||[]); return raycaster.intersectObjects(targets,false); }
canvas.addEventListener('click',ev=>{ const hits=pick(ev); if(!hits.length) return; const u=hits[0].object.userData;
  if(u.id!=null) openNode(u.id); else if(u.pick==='db') openDb(u.db); else if(u.pick==='svc'){ if(u.node_id) openNode(u.node_id); else openSvc(u.svc); } });

// DB reactor dossier (data already in hand from the layer) → link to Data Core
function openDb(db){ NK.sel=null; const info=document.getElementById('nk-info'); info.style.display='block';
  document.getElementById('hi-name').textContent=db.name||('DB #'+db.id); document.getElementById('nk-kind').textContent=db.engine||'database'; document.getElementById('hi-meta').textContent=(db.role||'')+(db.host?(' · '+db.host):'');
  const v=db.viz||{}; const cells=[['Status',db.status||db.level||'—'],['Conns',db.vitals&&db.vitals.connections!=null?db.vitals.connections:'—'],['Pool',v.load!=null?Math.round(v.load*100)+'%':'—'],['Slow',db.slow!=null?db.slow:'—'],['Locks',db.locks!=null?db.locks:'—'],['Queries',db.queries!=null?db.queries:'—']];
  let h='<div class="dgrid">'+cells.map(c=>`<div class="dcell"><div class="l">${c[0]}</div><div class="v">${esc(c[1])}</div></div>`).join('')+'</div>';
  if(db.top_tables&&db.top_tables.length){ h+='<div class="dsec"><i class="fa-solid fa-table"></i> Top tables <span class="cnt">'+db.top_tables.length+'</span></div>';
    db.top_tables.slice(0,8).forEach(t=>h+=`<div class="ditem"><div class="t">${esc(t.name)}<span class="dbadge">${(+t.rows||0).toLocaleString()} rows</span></div><div class="d">R ${fmtbps((+t.reads||0)*8).replace('bps','')} · W ${fmtbps((+t.writes||0)*8).replace('bps','')}</div></div>`); }
  // relate the DB to its HOST node
  const host=db.node_id?NK.inv[db.node_id]:null;
  if(host){ h+=`<div class="dsec"><i class="fa-solid fa-server"></i> Host node</div><div class="ditem ok"><div class="t">${esc(host.name)}<span class="dbadge">${esc(host.kind)}</span></div><div class="d">${esc(host.ip||'')} — click to open the node dossier</div></div>`; }
  document.getElementById('nk-db').innerHTML=h;
  const hostAct=host?`<a class="act" href="javascript:void(0)" onclick="openNode(${db.node_id})"><i class="fa-solid fa-server"></i> Host: ${esc(host.name)} →</a>`:'';
  document.getElementById('nk-dacts').innerHTML=`<a class="act primary" href="dbmon.php?target=${db.id}"><i class="fa-solid fa-database"></i> Open in Data Core →</a>`+hostAct+`<a class="act" href="dbobservatory.php"><i class="fa-solid fa-satellite"></i> Observatory</a>`;
}
// Service cell dossier (unmapped services with no node) → link to Biosphere / troubleshoot
function openSvc(s){ NK.sel=null; const info=document.getElementById('nk-info'); info.style.display='block';
  document.getElementById('hi-name').textContent=s.name||('Service #'+s.id); document.getElementById('nk-kind').textContent=s.kind||'service'; document.getElementById('hi-meta').textContent=s.target||'';
  const vt=s.vitals||{}; const cells=[['Health',vt.level||'—'],['Latency',vt.latency_ms!=null?vt.latency_ms+' ms':'—'],['Errors',vt.err_rate!=null?vt.err_rate+'%':'—']];
  document.getElementById('nk-db').innerHTML='<div class="dgrid">'+cells.map(c=>`<div class="dcell"><div class="l">${c[0]}</div><div class="v">${esc(c[1])}</div></div>`).join('')+'</div>';
  document.getElementById('nk-dacts').innerHTML=`<a class="act primary" href="biosphere.php"><i class="fa-solid fa-dna"></i> Service Biosphere →</a>`;
}
const tip=document.getElementById('nk-tip');
canvas.addEventListener('mousemove',ev=>{ const hits=pick(ev); if(hits.length){ const u=hits[0].object.userData; let label='';
    if(u.node){ const inv=NK.inv[u.node.id]||{}; label=`<b>${esc(u.node.name)}</b> · ${esc(inv.kind||'')}${inv.incidents?` · ⚠ ${inv.incidents}`:''}`; }
    else if(u.pick==='db'){ label=`<b>${esc(u.db.name)}</b> · ${esc(u.db.engine||'db')} · ${esc(u.db.level||u.db.status||'')}`; }
    else if(u.pick==='svc'){ label=`<b>${esc(u.svc.name)}</b> · ${esc(u.svc.kind||'service')}`; }
    tip.style.display='block'; tip.style.left=ev.clientX-canvas.getBoundingClientRect().left+'px'; tip.style.top=ev.clientY-canvas.getBoundingClientRect().top+'px'; tip.innerHTML=label; canvas.style.cursor='pointer'; }
  else { tip.style.display='none'; canvas.style.cursor='default'; } });

// controls
document.getElementById('b-labels').onclick=function(){ NK.labels=!NK.labels; gLabels.visible=NK.labels; this.classList.toggle('on',NK.labels); };
document.getElementById('b-spin').onclick=function(){ NK.spin=!NK.spin; controls.autoRotate=NK.spin; this.classList.toggle('on',NK.spin); };
document.getElementById('b-fit').onclick=function(){ camera.position.set(0,220,760); controls.target.set(0,0,0); };
document.getElementById('b-full').onclick=function(){ if(!document.fullscreenElement) stage.requestFullscreen(); else document.exitFullscreen(); };
// keep the site's NMNetBG particle canvas visible in fullscreen (position:fixed on <body> → vanishes
// when only #nk-stage is fullscreened) — reparent it into the stage while fullscreen, restore on exit.
document.addEventListener('fullscreenchange',()=>{
  const bg=document.getElementById('nm-netbg');
  if(bg){ if(document.fullscreenElement===stage){ stage.insertBefore(bg,stage.firstChild); bg.style.zIndex='0'; }
          else { document.body.appendChild(bg); bg.style.zIndex='-1'; } }
  const i=document.querySelector('#b-full i'); if(i) i.className='fa-solid '+(document.fullscreenElement?'fa-compress':'fa-expand');
  setTimeout(()=>{ resize(); window.dispatchEvent(new Event('resize')); },80);
});
document.querySelectorAll('.lchip').forEach(c=>c.onclick=()=>toggleLayer(c.dataset.l));

// ── animation ────────────────────────────────────────────────────────────────
let tPrev=performance.now();
function animate(){ requestAnimationFrame(animate); const now=performance.now(), dt=(now-tPrev)/1000; tPrev=now;
  controls.update();
  // node pulse
  const t=now*0.001;
  for(const id in NK.meshes){ const m=NK.meshes[id]; const s=1+Math.sin(t*2+m.pulse)*0.06; m.core.scale.setScalar(s); m.ring.rotation.z+=0.004; }
  // link particles flow
  if(linkPoints){ const {meta,P}=linkPoints.userData; const pos=linkPoints.geometry.getAttribute('position'); const al=linkPoints.geometry.getAttribute('aAlpha');
    for(let i=0;i<meta.length;i++){ const m=meta[i]; m.t+=dt*m.spd*(NK.layers.traffic?1.6:1)*m.dir; if(m.t>1)m.t-=1; if(m.t<0)m.t+=1;
      const a=P[m.a],b=P[m.b]; pos.setXYZ(i,a.x+(b.x-a.x)*m.t,a.y+(b.y-a.y)*m.t,a.z+(b.z-a.z)*m.t);
      al.setX(i,.35+(NK.layers.traffic?Math.min(.6,Math.log10(1+m.rate)/6):.15)); }
    pos.needsUpdate=true; al.needsUpdate=true; }
  // layer animation (reactors, membranes, conduits)
  for(const A of NK.layerAnim){
    if(A.kind==='reactor'){ A.t+=dt; const rate=A.frozen?1.2:(2+A.pulse*6); const s=1+Math.sin(A.t*rate)*(0.05+A.pulse*0.06);
      A.core.scale.setScalar(s*A.size); A.core.material.emissiveIntensity=0.7+Math.sin(A.t*rate)*0.35+A.slow*0.3; A.halo.scale.setScalar((1+A.load*0.5+Math.sin(A.t*rate)*0.05)*A.size); if(A.gal) A.gal.rotation.y+=dt*(0.15+A.pulse*0.5); }
    else if(A.kind==='cell'){ A.mat.uniforms.uTime.value+=dt; A.t+=dt; const rate=A.frozen?1.2:(2+A.pulse*5); A.core.scale.setScalar(0.55*(1+Math.sin(A.t*rate)*0.06)); if(A.gal) A.gal.rotation.y+=dt*(0.2+A.pulse*0.5); }
    else if(A.kind==='conduit'){ A.phase=(A.phase+dt*A.speed)%1; for(let k=0;k<A.P;k++){ const tt=(A.phase+k/A.P)%1; const pt=A.curve.getPoint(tt); A.pp[k*3]=pt.x; A.pp[k*3+1]=pt.y; A.pp[k*3+2]=pt.z; } A.pts.geometry.attributes.position.needsUpdate=true; }
  }
  if(pathAnim){ pathAnim.phase=(pathAnim.phase+dt*0.4)%1; for(let k=0;k<pathAnim.P;k++){ const tt=(pathAnim.phase+k/pathAnim.P)%1; const pt=pathAnim.curve.getPoint(tt); pathAnim.pp[k*3]=pt.x; pathAnim.pp[k*3+1]=pt.y; pathAnim.pp[k*3+2]=pt.z; } pathAnim.pmesh.geometry.attributes.position.needsUpdate=true; }
  renderer.render(scene,camera);
}
animate();

// ── load + poll ──────────────────────────────────────────────────────────────
async function load(){
  try{
    const [topo,inv]=await Promise.all([
      fetch(`net_mon_map.php?api=topo&_=${Date.now()}`).then(r=>r.json()).catch(()=>null),
      fetch(`neurutik.php?api=inventory&_=${Date.now()}`).then(r=>r.json()).catch(()=>null),
    ]);
    if(inv&&inv.ok) NK.inv=inv.nodes||{};
    if(topo&&topo.nodes){ NK.nodes=topo.nodes.map(n=>({id:n.id,name:n.name,ip:n.ip,status:n.status,icon:n.icon||n.os_icon})); NK.links=(topo.links||[]).map(l=>({source:l.source,target:l.target,in_rate:l.in_rate||0,out_rate:l.out_rate||0})); }
    else if(inv&&inv.ok){ // fallback: no topo → just nodes from inventory
      NK.nodes=Object.values(NK.inv).map(n=>({id:n.id,name:n.name,ip:n.ip,status:n.up===1?'up':(n.up===0?'down':'unknown')})); NK.links=[]; }
    rebuild();
    // refresh active layers
    for(const l in NK.layers) if(NK.layers[l]) await loadLayer(l);
    applyLayers();
  }catch(e){ document.getElementById('nk-empty').style.display='flex'; document.getElementById('nk-empty-msg').textContent='Could not load the galaxy.'; }
}
load(); setInterval(()=>{ if(!document.hidden) load(); }, 15000);
</script>
</body>
</html>
