<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Routing Command Center. The live L3 forwarding fabric of the whole estate:
// routers as reactor cores, their routing tables as protocol-coloured conduits toward
// gateways, connected subnets orbiting, an Internet cloud for default routes. Route
// gateways are resolved to the OWNING router → the real topology is rebuilt from the
// routing tables. Path simulator (LPM), NetFlow-on-routes overlay, route drift/flap,
// and loop detection. Reuses nm_routing.php + the WebGL patterns. RBAC: 'routing_center'.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_routing.php');
include('logger.php');

if (!checkAccess($conn, 'routing_center')) { header('Location: /denied_access.php?page=routing_center'); exit; }

$__api = $_GET['api'] ?? '';
if ($__api !== '') {
    if (function_exists('session_write_close')) @session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    try {
        if ($__api === 'topology') {
            $nodes = null; if (!empty($_GET['nodes'])) { $nodes = array_map('intval', array_filter(explode(',', $_GET['nodes']))); if (!$nodes) $nodes = null; }
            $t = nm_routing_topology($conn, $nodes);
            $t['loops'] = nm_routing_detect_loops($t);
            echo json_encode(['ok'=>true] + $t);
        } elseif ($__api === 'routes') {
            $n = nm_router_node($conn, (int)($_GET['node'] ?? 0));
            if (!$n) { echo json_encode(['ok'=>false,'error'=>'unknown node']); }
            else { $f = nm_routing_fetch($conn, $n); $routes = $f['routes'] ?? [];
                $diff = nm_routing_diff($conn, (int)$n['id'], $routes);
                if ($routes) nm_routing_snapshot_save($conn, (int)$n['id'], $routes);   // stamp for next drift compare
                echo json_encode(['ok'=>!empty($f['ok']), 'source'=>$f['source'], 'truncated'=>!empty($f['truncated']),
                    'error'=>$f['error'] ?? '', 'routes'=>$routes, 'drift'=>$diff]); }
        } elseif ($__api === 'path') {
            echo json_encode(nm_routing_path($conn, (int)($_GET['from'] ?? 0), trim((string)($_GET['dest'] ?? ''))));
        } elseif ($__api === 'overlay') {
            // NetFlow → route: LPM-match live destination IPs to this router's routes → mbps per route dst
            $n = nm_router_node($conn, (int)($_GET['node'] ?? 0));
            if (!$n) { echo json_encode(['ok'=>false]); }
            else {
                $routes = nm_routing_fetch($conn, $n)['routes'] ?? [];
                $fl = function_exists('nm_router_flows') ? nm_router_flows($conn, $n, 30) : ['ok'=>false];
                $agg = [];
                if (!empty($fl['ok'])) foreach (array_merge($fl['outbound'] ?? [], $fl['inbound'] ?? []) as $c) {
                    if (!nm_routing_is_ip($c['ip'])) continue;
                    $rt = nm_routing_lpm($routes, $c['ip']); if (!$rt) continue;
                    $agg[$rt['dst']] = ($agg[$rt['dst']] ?? 0) + (float)$c['mbps'];
                }
                echo json_encode(['ok'=>true, 'node'=>(int)$n['id'], 'by_route'=>$agg]);
            }
        } else echo json_encode(['ok'=>false, 'error'=>'unknown api']);
    } catch (\Throwable $e) { echo json_encode(['ok'=>false, 'error'=>$e->getMessage()]); }
    exit;
}

log_user_action($conn, 'view_page', 'routing_command.php');
include('header.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(11,15,26,.62); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cyan:#36e3d0; --amber:#ffb454; --purple:#b388ff; }
html{ background:#04060d; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#d4dce8; overflow-x:hidden; }
<?= nm_chrome_css() ?>
#rc-stage{ position:relative; width:100%; height:calc(100vh - 74px); min-height:520px; overflow:hidden; background:radial-gradient(1200px 700px at 50% 12%, rgba(60,80,160,.16), transparent 72%); }
#rc-stage:fullscreen{ height:100vh; }
#rc-canvas{ position:absolute; inset:0; display:block; }
.rc-hud{ position:absolute; z-index:6; pointer-events:none; }
.rc-hud .glass{ background:var(--glass); backdrop-filter:blur(13px); border:1px solid var(--border); border-radius:13px; pointer-events:auto; }
#rc-top{ top:14px; left:16px; max-width:420px; } #rc-top .glass{ padding:12px 15px; }
#rc-title{ font-size:16px; font-weight:800; display:flex; align-items:center; gap:10px; } #rc-title i{ color:var(--accent); }
#rc-sub{ font-size:11.5px; color:#9fb0c4; margin-top:3px; line-height:1.45; }
.rc-row{ display:flex; align-items:center; gap:8px; margin-top:10px; flex-wrap:wrap; }
.rc-row label{ font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8b95a7; }
#rc-dev,#rc-from,#rc-dest{ background:rgba(0,0,0,.35); border:1px solid var(--border); color:#e6edf7; border-radius:8px; padding:7px 9px; font-size:12.5px; }
#rc-dev{ flex:1; min-width:130px; } #rc-dev option,#rc-from option{ background:#0d1526; }
#rc-dest{ width:130px; } #rc-from{ max-width:130px; }
.rc-go{ background:linear-gradient(135deg,#4da3ff,#6a5cff); border:none; color:#fff; border-radius:8px; padding:7px 12px; font-size:12px; font-weight:600; cursor:pointer; }
#rc-filters{ margin-top:9px; display:flex; gap:7px; flex-wrap:wrap; }
.pf{ font-size:10.5px; padding:3px 9px; border-radius:20px; border:1px solid var(--border); cursor:pointer; user-select:none; display:inline-flex; align-items:center; gap:5px; opacity:.55; }
.pf.on{ opacity:1; } .pf .d{ width:8px;height:8px;border-radius:50%; }
#rc-stats{ top:14px; right:16px; } #rc-stats .glass{ padding:9px 15px; display:flex; gap:16px; }
.st{ text-align:center; } .st .n{ font-size:18px; font-weight:800; line-height:1; } .st .l{ font-size:8.5px; color:#8b95a7; text-transform:uppercase; letter-spacing:.5px; margin-top:3px; }
.st .n.cy{ color:var(--cyan);} .st .n.am{ color:var(--amber);} .st .n.pu{ color:var(--purple);} .st .n.crit{ color:#ff8b80;}
#rc-ctl{ top:78px; right:16px; display:flex; flex-direction:column; gap:8px; }
.cbtn{ pointer-events:auto; background:rgba(12,18,30,.8); border:1px solid var(--border); color:#cfe4ff; border-radius:9px; width:38px; height:36px; cursor:pointer; display:flex; align-items:center; justify-content:center; font-size:14px; }
.cbtn:hover{ border-color:var(--accent); color:#fff; } .cbtn.on{ border-color:var(--cyan); color:#fff; background:rgba(54,227,208,.15); }
#rc-warn{ bottom:52px; left:50%; transform:translateX(-50%); } #rc-warn .glass{ padding:7px 14px; font-size:12px; color:#ffce6b; border-color:rgba(243,156,18,.4); cursor:pointer; display:none; }
#rc-hint{ bottom:14px; left:50%; transform:translateX(-50%); font-size:11px; color:#8b95a7; } #rc-hint .glass{ padding:6px 12px; }
#rc-empty{ position:absolute; inset:0; display:none; align-items:center; justify-content:center; flex-direction:column; gap:12px; color:#8b95a7; text-align:center; padding:24px; z-index:3; }
/* panel (left) */
#rc-panel{ position:absolute; z-index:12; left:0; top:0; height:100%; width:360px; max-width:92vw; display:none; }
#rc-panel .glass{ height:100%; border-radius:0 16px 16px 0; border-left:none; display:flex; flex-direction:column; background:rgba(8,12,22,.93); box-shadow:24px 0 60px rgba(0,0,0,.5); }
#rp-head{ padding:14px 16px 12px; border-bottom:1px solid var(--border); position:relative; }
#rp-head h3{ margin:0; font-size:15px; display:flex; align-items:center; gap:9px; padding-right:22px; }
#rp-head .meta{ font-size:11.5px; color:#9aa3af; margin-top:4px; } #rp-head .x{ position:absolute; top:12px; right:13px; cursor:pointer; color:#9aa3af; } #rp-head .x:hover{ color:#fff; }
#rp-body{ padding:12px 16px; overflow-y:auto; flex:1; font-size:12.5px; }
.rp-tot{ display:flex; gap:12px; margin-bottom:12px; flex-wrap:wrap; } .rp-tot .b{ font-size:15px; font-weight:800; } .rp-tot .l{ font-size:8.5px;color:#8b95a7;letter-spacing:.5px; }
.rsec{ font-size:10px; text-transform:uppercase; letter-spacing:.6px; color:#9db4d6; margin:12px 0 7px; }
.rrow{ display:flex; align-items:center; gap:8px; margin-bottom:5px; font-family:Consolas,monospace; font-size:11.5px; }
.rrow .pd{ width:8px;height:8px;border-radius:50%;flex:none; } .rrow .dst{ color:#dbe3ee; min-width:118px; } .rrow .gw{ color:#9fb0c4; margin-left:auto; }
.dim{ color:#6f7a8c; } .chip{ font-size:9px; padding:1px 7px; border-radius:20px; background:rgba(255,255,255,.08); color:#cfd6e0; }
.chip.add{ background:rgba(46,204,113,.18); color:#7fe0a3;} .chip.rem{ background:rgba(231,76,60,.2); color:#ff9b91;}
#rp-acts{ padding:12px 16px; border-top:1px solid var(--border); display:flex; gap:8px; flex-wrap:wrap; }
#rp-acts a{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:8px; padding:8px 11px; font-size:12px; text-decoration:none; cursor:pointer; }
#rc-fallback{ display:none; position:absolute; inset:0; z-index:2; overflow:auto; padding:70px 20px 20px; } .bento{ display:grid; grid-template-columns:repeat(auto-fill,minmax(240px,1fr)); gap:14px; max-width:1200px; margin:0 auto; } .bcard{ background:var(--glass); border:1px solid var(--border); border-radius:14px; padding:16px; }
</style>

<div id="rc-stage">
  <canvas id="rc-canvas"></canvas>

  <div id="rc-top" class="rc-hud"><div class="glass">
    <div id="rc-title"><i class="fa-solid fa-diagram-project"></i> Routing Command Center</div>
    <div id="rc-sub">The live L3 fabric rebuilt from every router's routing table. Conduits = routes (coloured by protocol) flowing to their next-hop. Click a router; simulate a path.</div>
    <div class="rc-row"><label>Show</label><select id="rc-dev"><option value="all">◎ All routers</option></select></div>
    <div class="rc-row"><label>Trace</label>
      <select id="rc-from"><option value="0">from…</option></select>
      <input id="rc-dest" placeholder="dest IP e.g. 8.8.8.8">
      <button class="rc-go" onclick="tracePath()"><i class="fa-solid fa-route"></i> Path</button>
    </div>
    <div id="rc-filters">
      <span class="pf on" data-p="connected" onclick="togP(this)"><span class="d" style="background:var(--cyan)"></span>connected</span>
      <span class="pf on" data-p="static" onclick="togP(this)"><span class="d" style="background:var(--accent)"></span>static</span>
      <span class="pf on" data-p="dynamic" onclick="togP(this)"><span class="d" style="background:var(--purple)"></span>dynamic</span>
      <span class="pf on" data-p="internet" onclick="togP(this)"><span class="d" style="background:var(--amber)"></span>default→net</span>
      <span class="pf" data-p="overlay" onclick="togOverlay(this)"><i class="fa-solid fa-chart-area" style="font-size:9px"></i> NetFlow load</span>
    </div>
  </div></div>

  <div id="rc-stats" class="rc-hud"><div class="glass">
    <div class="st"><div class="n cy" id="s-rt">—</div><div class="l">Routers</div></div>
    <div class="st"><div class="n" id="s-routes">—</div><div class="l">Routes</div></div>
    <div class="st"><div class="n cy" id="s-sub">—</div><div class="l">Subnets</div></div>
    <div class="st"><div class="n am" id="s-net">—</div><div class="l">Net Exits</div></div>
    <div class="st"><div class="n crit" id="s-loop">—</div><div class="l">Loops</div></div>
  </div></div>

  <div id="rc-ctl" class="rc-hud">
    <button class="cbtn on" id="b-spin" title="Auto-rotate"><i class="fa-solid fa-arrows-rotate"></i></button>
    <button class="cbtn" id="b-fit" title="Reset view"><i class="fa-solid fa-crosshairs"></i></button>
    <button class="cbtn" id="b-full" title="Fullscreen"><i class="fa-solid fa-expand"></i></button>
  </div>

  <div id="rc-warn" class="rc-hud"><div class="glass" id="warn-box" onclick="showLoops()"></div></div>
  <div id="rc-hint" class="rc-hud"><div class="glass"><i class="fa-solid fa-hand-pointer"></i> drag to orbit · click a router for its routes · trace a destination path</div></div>

  <div id="rc-panel" class="rc-hud"><div class="glass">
    <div id="rp-head"><span class="x" onclick="closePanel()"><i class="fa-solid fa-xmark"></i></span>
      <h3 id="rp-name">—</h3><div class="meta" id="rp-meta">—</div></div>
    <div class="rp-tot" id="rp-tot"></div>
    <div id="rp-body"><div class="dim">Loading routes…</div></div>
    <div id="rp-acts"></div>
  </div></div>

  <div id="rc-empty"><i class="fa-solid fa-diagram-project" style="font-size:38px;opacity:.4"></i>
    <div>No router-class devices registered.<br>Add routers in <b>Configuration → Nodes</b>.</div></div>
  <div id="rc-fallback"><div class="bento" id="bento"></div></div>
</div>

<script src="three.min.js"></script>
<script src="three-orbitcontrols.js"></script>
<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const PC={connected:0x36e3d0, static:0x4da3ff, dynamic:0xb388ff, internet:0xffb454, blackhole:0xe74c3c, subnet:0x36e3d0};
const PHEX={connected:'#36e3d0', static:'#4da3ff', dynamic:'#b388ff', internet:'#ffb454', blackhole:'#e74c3c'};
function coreCol(r){ return r.up===false?0xe74c3c:((r.incidents||0)>0?0xf39c12:0x4da3ff); }
function linkProto(l){ return l.kind==='internet'?'internet':(l.kind==='subnet'?'connected':l.protocol); }

let TOPO=null, MODE='all', PFILT={connected:1,static:1,dynamic:1,internet:1}, OVERLAY=false, OVER={};
let renderer,scene,camera,controls,stage,canvas,gNodes,gLinks,inet,selRing,R3={},spin=true;
let RN={}, SUB={}, LINKS=[], PATHFX=null;

let WEBGL=true;
(function(){ let ok=false; try{ const c=document.createElement('canvas'); ok=!!(window.WebGLRenderingContext&&(c.getContext('webgl')||c.getContext('experimental-webgl'))); }catch(e){}
  if(!ok||typeof THREE==='undefined'){ WEBGL=false; document.getElementById('rc-canvas').style.display='none'; document.getElementById('rc-fallback').style.display='block'; if(window.NMLoader)NMLoader.hide(); } })();

function labelSprite(text,color,scale){ const c=document.createElement('canvas'),x=c.getContext('2d'),f=34;
  x.font=`700 ${f}px Segoe UI`; const w=Math.ceil(x.measureText(text).width)+16; c.width=w; c.height=f+12;
  x.font=`700 ${f}px Segoe UI`; x.fillStyle='rgba(6,10,20,.55)'; x.fillRect(0,0,w,c.height); x.fillStyle=color||'#dfe7f2'; x.textBaseline='middle'; x.fillText(text,8,c.height/2);
  const tx=new THREE.CanvasTexture(c); tx.minFilter=THREE.LinearFilter;
  const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:tx,transparent:true,depthWrite:false})); sp.scale.set(w*(scale||0.14),c.height*(scale||0.14),1); return sp; }

function initGL(){
  stage=document.getElementById('rc-stage'); canvas=document.getElementById('rc-canvas');
  renderer=new THREE.WebGLRenderer({canvas,antialias:true,alpha:true}); renderer.setClearColor(0x000000,0);
  scene=new THREE.Scene(); scene.fog=new THREE.FogExp2(0x04060d,0.00055);
  camera=new THREE.PerspectiveCamera(55,1,0.5,8000); camera.position.set(0,320,640);
  controls=new THREE.OrbitControls(camera,renderer.domElement); controls.enableDamping=true; controls.dampingFactor=.08; controls.autoRotate=true; controls.autoRotateSpeed=.3; controls.minDistance=90; controls.maxDistance=4000;
  scene.add(new THREE.AmbientLight(0x8899cc,0.95)); const key=new THREE.PointLight(0xafc4ff,0.7,0); key.position.set(300,500,400); scene.add(key);
  gLinks=new THREE.Group(); gNodes=new THREE.Group(); scene.add(gLinks); scene.add(gNodes);
  selRing=new THREE.Mesh(new THREE.TorusGeometry(30,1.2,10,44),new THREE.MeshBasicMaterial({color:0xffffff,transparent:true,opacity:.7,blending:THREE.AdditiveBlending,depthWrite:false})); selRing.visible=false; scene.add(selRing);
  const ray=new THREE.Raycaster(); const mouse=new THREE.Vector2();
  function pick(ev){ const r=canvas.getBoundingClientRect(); mouse.x=((ev.clientX-r.left)/r.width)*2-1; mouse.y=-((ev.clientY-r.top)/r.height)*2+1; ray.setFromCamera(mouse,camera);
    return ray.intersectObjects(Object.values(RN).map(n=>n.core).filter(Boolean),false); }
  canvas.addEventListener('click',ev=>{ const h=pick(ev); if(h.length&&h[0].object.userData&&h[0].object.userData.id!=null) focusRouter(h[0].object.userData.id); });
  canvas.addEventListener('mousemove',ev=>{ canvas.style.cursor=pick(ev).length?'pointer':'grab'; });
  function resize(){ const w=stage.clientWidth,h=stage.clientHeight; renderer.setPixelRatio(Math.min(devicePixelRatio||1,2)); renderer.setSize(w,h,false); camera.aspect=w/h; camera.updateProjectionMatrix(); }
  resize(); window.addEventListener('resize',resize); R3.resize=resize;
  document.addEventListener('visibilitychange',()=>{ R3.hidden=document.hidden; if(!R3.hidden)R3.last=performance.now(); });
  R3.last=performance.now(); animate();
}

function build(){
  while(gNodes.children.length) gNodes.remove(gNodes.children[0]);
  while(gLinks.children.length) gLinks.remove(gLinks.children[0]);
  RN={}; SUB={}; LINKS=[]; PATHFX=null;
  const routers=(TOPO.routers||[]).filter(r=>MODE==='all'||r.id==MODE);
  if(!routers.length){ document.getElementById('rc-empty').style.display='flex'; if(window.NMLoader)NMLoader.hide(); return; }
  document.getElementById('rc-empty').style.display='none';
  const n=routers.length, R=190+n*30, coreGeo=new THREE.IcosahedronGeometry(16,2);
  const pos={}; routers.forEach((r,i)=>{ const a=(i/n)*Math.PI*2; pos[r.id]=new THREE.Vector3(Math.cos(a)*R,(i%2?14:-14),Math.sin(a)*R); });
  // internet cloud
  inet=null;
  if(TOPO.internet){ inet=new THREE.Mesh(new THREE.IcosahedronGeometry(30,1),new THREE.MeshStandardMaterial({color:0xffb454,emissive:0xffb454,emissiveIntensity:.5,transparent:true,opacity:.5,flatShading:true}));
    inet.position.set(0,150,0); gNodes.add(inet); const il=labelSprite('🌐 Internet','#ffd9a8',0.18); il.position.set(0,182,0); gNodes.add(il); }
  // routers
  routers.forEach(r=>{ const col=coreCol(r); const grp=new THREE.Group(); grp.position.copy(pos[r.id]); gNodes.add(grp);
    const core=new THREE.Mesh(coreGeo,new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:.9,roughness:.3,metalness:.4,flatShading:true})); core.userData=r; grp.add(core);
    const halo=new THREE.Mesh(new THREE.SphereGeometry(23,18,18),new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:.09,blending:THREE.AdditiveBlending,depthWrite:false})); grp.add(halo);
    const lab=labelSprite(r.name,'#eaf1ff',0.15); lab.position.set(0,34,0); grp.add(lab);
    RN[r.id]={grp,core,halo,pos:pos[r.id],router:r,t:Math.random()*10};
  });
  // subnet leaves (place near first owner)
  (TOPO.subnets||[]).forEach((s,si)=>{ const owner=(s.owners||[]).find(o=>pos[o]); if(!owner) return;
    const base=pos[owner]; const ang=si*2.399963; const off=new THREE.Vector3(Math.cos(ang)*46,(si%2?10:-10)-6,Math.sin(ang)*46);
    const p=base.clone().add(off).multiplyScalar(1).add(base.clone().normalize().multiplyScalar(30));
    const node=new THREE.Mesh(new THREE.BoxGeometry(6,6,6),new THREE.MeshBasicMaterial({color:0x2f5a55})); node.position.copy(p); gNodes.add(node);
    const lab=labelSprite(s.cidr,'#8fded4',0.085); lab.position.copy(p).add(new THREE.Vector3(0,7,0)); gNodes.add(lab);
    SUB['s:'+s.cidr]={pos:p,node,cidr:s.cidr};
  });
  // links
  (TOPO.links||[]).forEach(l=>{ const from=pos[l.from]; if(!from) return;
    let to; if(l.kind==='internet'){ if(!inet) return; to=inet.position; } else if(l.kind==='subnet'){ const s=SUB[l.to]; if(!s) return; to=s.pos; } else { to=pos[parseInt(l.to.slice(2))]; if(!to) return; }
    const proto=linkProto(l), col=PC[proto]||0x888888;
    const mid=from.clone().add(to).multiplyScalar(0.5); mid.y+=(l.kind==='router'?46:16);
    const curve=new THREE.QuadraticBezierCurve3(from,mid,to);
    const line=new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(24)),new THREE.LineBasicMaterial({color:col,transparent:true,opacity:.28}));
    gLinks.add(line);
    const P=(l.kind==='subnet')?8:14, g=new THREE.BufferGeometry(), pp=new Float32Array(P*3); g.setAttribute('position',new THREE.BufferAttribute(pp,3));
    const pts=new THREE.Points(g,new THREE.PointsMaterial({color:col,size:(l.kind==='router'?6:4.5),sizeAttenuation:false,transparent:true,opacity:.95,blending:THREE.AdditiveBlending,depthWrite:false}));
    gLinks.add(pts);
    LINKS.push({l,proto,curve,line,pts,pp,P,phase:Math.random(),speed:(l.kind==='router'?0.22:0.14)});
  });
  applyFilters();
  document.getElementById('rc-empty').style.display='none';
  if(window.NMLoader)NMLoader.hide(); fitAll();
}

function animate(){ requestAnimationFrame(animate); if(!WEBGL||R3.hidden) return;
  const now=performance.now(), dt=Math.min(0.05,(now-R3.last)/1000); R3.last=now; controls.autoRotate=spin; controls.update();
  Object.values(RN).forEach(o=>{ o.t+=dt; const s=1+Math.sin(o.t*2.1)*0.03; o.core.scale.setScalar(s); o.core.material.emissiveIntensity=0.7+Math.sin(o.t*2.1)*0.3; o.core.rotation.y+=dt*0.25; o.halo.scale.setScalar(1+Math.sin(o.t*1.5)*0.05); });
  if(inet){ inet.rotation.y+=dt*0.2; inet.material.emissiveIntensity=0.4+0.25*Math.sin(now*0.002); }
  LINKS.forEach(L=>{ if(!L.pts.visible) return; let boost=1;
    if(OVERLAY){ const m=(OVER[L.l.from]||{})[L.l.dst]; boost=m?1+Math.min(3,Math.log10(1+m*1e6)*0.5):0.5; }
    L.phase=(L.phase+L.speed*dt*(0.6+boost*0.5))%1;
    for(let i=0;i<L.P;i++){ const t=(L.phase+i/L.P)%1; const p=L.curve.getPoint(t); L.pp[i*3]=p.x;L.pp[i*3+1]=p.y;L.pp[i*3+2]=p.z; }
    L.pts.geometry.attributes.position.needsUpdate=true; L.pts.material.size=(L.l.kind==='router'?6:4.5)*(OVERLAY?Math.max(.6,boost):1);
  });
  if(PATHFX){ PATHFX.phase=(PATHFX.phase+dt*0.5)%1; const t=PATHFX.phase*PATHFX.curve.length; }
  if(selRing.visible&&MODE!=='all'&&RN[MODE]){ selRing.position.copy(RN[MODE].pos); selRing.lookAt(camera.position); selRing.material.opacity=0.35+0.35*Math.abs(Math.sin(now*0.003)); }
  renderer.render(scene,camera);
}
function fitAll(){ const box=new THREE.Box3(); Object.values(RN).forEach(o=>box.expandByPoint(o.pos)); if(inet)box.expandByPoint(inet.position);
  if(box.isEmpty())return; const ctr=box.getCenter(new THREE.Vector3()),sz=box.getSize(new THREE.Vector3()),r=Math.max(sz.x,sz.z,180)+150;
  controls.target.copy(ctr); camera.position.set(ctr.x,ctr.y+r*0.6,ctr.z+r*1.4); camera.updateProjectionMatrix(); }
function fitCluster(id){ const o=RN[id]; if(!o)return; controls.target.copy(o.pos); camera.position.set(o.pos.x,o.pos.y+120,o.pos.z+230); camera.updateProjectionMatrix(); }

function applyFilters(){ LINKS.forEach(L=>{ const show=(MODE==='all'||L.l.from==MODE||(L.l.kind==='router'&&parseInt(L.l.to.slice(2))==MODE)) && (PFILT[L.proto]!==0); L.pts.visible=show; L.line.visible=show; }); }
function togP(el){ const p=el.dataset.p; PFILT[p]=PFILT[p]?0:1; el.classList.toggle('on',!!PFILT[p]); applyFilters(); }

// ── data ─────────────────────────────────────────────────────────────────────
async function load(){
  let d=null; try{ d=await fetch('routing_command.php?api=topology&_='+Date.now()).then(r=>r.json()); }catch(e){}
  if(!d||!d.ok){ if(window.NMLoader)NMLoader.hide(); return; } TOPO=d;
  const sel=document.getElementById('rc-dev'), from=document.getElementById('rc-from');
  sel.innerHTML='<option value="all">◎ All routers</option>'+TOPO.routers.map(r=>`<option value="${r.id}">${esc(r.name)}</option>`).join('');
  from.innerHTML='<option value="0">from…</option>'+TOPO.routers.map(r=>`<option value="${r.id}">${esc(r.name)}</option>`).join('');
  sel.value=(MODE==='all'?'all':String(MODE));
  if(WEBGL) build(); else renderFallback();
  document.getElementById('s-rt').textContent=TOPO.routers.length;
  document.getElementById('s-routes').textContent=TOPO.stats.routes;
  document.getElementById('s-sub').textContent=TOPO.subnets.length;
  document.getElementById('s-net').textContent=(TOPO.links||[]).filter(l=>l.kind==='internet').length;
  const nl=(TOPO.loops||[]).length; document.getElementById('s-loop').textContent=nl;
  const wb=document.getElementById('warn-box'); if(nl){ wb.style.display='block'; wb.innerHTML=`<i class="fa-solid fa-triangle-exclamation"></i> ${nl} routing loop(s) detected — click to inspect`; } else wb.style.display='none';
}
async function focusRouter(id){ MODE=id; document.getElementById('rc-dev').value=String(id); selRing.visible=true; applyFilters(); fitCluster(id);
  const r=(TOPO.routers||[]).find(x=>x.id==id); if(!r)return;
  document.getElementById('rc-panel').style.display='block';
  document.getElementById('rp-name').innerHTML=`<i class="fa-solid ${r.mikrotik?'fa-dharmachakra':'fa-route'}" style="color:${coreHex(r)}"></i> ${esc(r.name)}`;
  document.getElementById('rp-meta').innerHTML=`${esc(r.ip||'')} · ${r.route_count} routes · source: ${esc(r.source)}${r.truncated?' (capped)':''}`;
  const bp=r.by_proto||{};
  document.getElementById('rp-tot').innerHTML=[['connected','cy'],['static',''],['dynamic','pu'],['blackhole','crit']].map(([k,c])=>`<div><div class="l">${k}</div><div class="b" style="color:${PHEX[k]||'#dbe3ee'}">${bp[k]||0}</div></div>`).join('')
    +`<div><div class="l">transit-in</div><div class="b">${(r.transit_from||[]).length}</div></div>`;
  document.getElementById('rp-acts').innerHTML=`<a href="router_details.php?node=${id}"><i class="fa-solid fa-gauge-high"></i> Router Details</a> <a href="router_command.php" >Traffic CC</a>`;
  document.getElementById('rp-body').innerHTML='<div class="dim">Loading routes…</div>';
  let d=null; try{ d=await fetch('routing_command.php?api=routes&node='+id+'&_='+Date.now()).then(r=>r.json()); }catch(e){}
  if(!d||!d.ok){ document.getElementById('rp-body').innerHTML='<div class="dim">'+esc((d&&d.error)||'no routes')+'</div>'; return; }
  const drift=d.drift||{}; let h='';
  if((drift.added||[]).length||(drift.removed||[]).length){ h+='<div class="rsec">⚡ Route drift since last check</div>';
    (drift.added||[]).slice(0,8).forEach(x=>h+=`<div class="rrow"><span class="chip add">+</span><span class="dst">${esc(x)}</span></div>`);
    (drift.removed||[]).slice(0,8).forEach(x=>h+=`<div class="rrow"><span class="chip rem">−</span><span class="dst">${esc(x)}</span></div>`); }
  const rs=(d.routes||[]).slice().sort((a,b)=>a.prefix-b.prefix);
  h+=`<div class="rsec">Routing table (${(d.routes||[]).length}${d.truncated?', capped':''})</div>`;
  h+=rs.map(rt=>`<div class="rrow"><span class="pd" style="background:${PHEX[rt.protocol]||'#888'}"></span><span class="dst">${esc(rt.dst)}</span><span class="gw">${rt.is_default?'★ ':''}${esc(rt.gw)}</span></div>`).join('')||'<div class="dim">no routes</div>';
  if((r.transit_from||[]).length){ h+='<div class="rsec">↩ Routers that transit through me</div>'+r.transit_from.map(t=>{ const rr=(TOPO.routers||[]).find(x=>x.id==t); return `<div class="rrow"><span class="dst">${esc(rr?rr.name:('#'+t))}</span></div>`; }).join(''); }
  document.getElementById('rp-body').innerHTML=h;
}
function coreHex(r){ return r.up===false?'#ff8b80':((r.incidents||0)>0?'#ffce6b':'#7bb8ff'); }
function closePanel(){ document.getElementById('rc-panel').style.display='none'; }

// ── path simulator ───────────────────────────────────────────────────────────
async function tracePath(){ const from=+document.getElementById('rc-from').value, dest=document.getElementById('rc-dest').value.trim();
  if(!from||!dest){ alert('Pick a source router and enter a destination IP.'); return; }
  let d=null; try{ d=await fetch('routing_command.php?api=path&from='+from+'&dest='+encodeURIComponent(dest)+'&_='+Date.now()).then(r=>r.json()); }catch(e){}
  if(!d||!d.ok){ alert((d&&d.error)||'trace failed'); return; }
  highlightPath(d);
  document.getElementById('rc-panel').style.display='block';
  document.getElementById('rp-name').innerHTML=`<i class="fa-solid fa-route" style="color:#ffd479"></i> Path → ${esc(dest)}`;
  const oc={delivered:'✅ delivered (connected)',internet:'🌐 exits to Internet',blackhole:'⛔ blackholed',loop:'🔁 routing LOOP',['no-route']:'❌ no route',unresolved:'⚠ next-hop unresolved',maxhops:'⚠ max hops'}[d.outcome]||d.outcome;
  document.getElementById('rp-meta').textContent='Outcome: '+oc;
  document.getElementById('rp-tot').innerHTML='';
  document.getElementById('rp-body').innerHTML='<div class="rsec">Hop-by-hop (LPM)</div>'+d.hops.map((h,i)=>`<div class="rrow"><span class="chip">${i+1}</span><span class="dst">${esc(h.name)}</span><span class="gw">${h.route?esc(h.route)+' → '+esc(h.gw||''):'—'}</span></div>`).join('');
  document.getElementById('rp-acts').innerHTML=`<a onclick="clearPath()"><i class="fa-solid fa-xmark"></i> Clear path</a>`;
}
function highlightPath(d){ clearPath(); const seq=d.hops.map(h=>h.node); const cols=[];
  // dim everything, then draw a gold tube through the router hops (+ internet if exit)
  gLinks.children.forEach(o=>{ if(o.material)o.material.opacity*=0.25; });
  const pts=[]; seq.forEach(nid=>{ if(RN[nid]) pts.push(RN[nid].pos.clone()); });
  if(d.outcome==='internet'&&inet) pts.push(inet.position.clone());
  if(pts.length<2){ return; }
  const curve=new THREE.CatmullRomCurve3(pts); const tube=new THREE.Mesh(new THREE.TubeGeometry(curve,64,2.2,8,false),new THREE.MeshBasicMaterial({color:0xffd479,transparent:true,opacity:.5,blending:THREE.AdditiveBlending,depthWrite:false}));
  gLinks.add(tube); const P=24,g=new THREE.BufferGeometry(),pp=new Float32Array(P*3); g.setAttribute('position',new THREE.BufferAttribute(pp,3));
  const pk=new THREE.Points(g,new THREE.PointsMaterial({color:0xffe9b0,size:9,sizeAttenuation:false,transparent:true,blending:THREE.AdditiveBlending,depthWrite:false})); gLinks.add(pk);
  PATHFX={curve,tube,pk,pp,P,phase:0}; // animate the pulse
  const anim=()=>{ if(!PATHFX)return; PATHFX.phase=(PATHFX.phase+0.01)%1; for(let i=0;i<P;i++){ const t=(PATHFX.phase+i/P*0.15)%1; const p=curve.getPoint(t); pp[i*3]=p.x;pp[i*3+1]=p.y;pp[i*3+2]=p.z; } g.attributes.position.needsUpdate=true; PATHFX.raf=requestAnimationFrame(anim); }; anim();
}
function clearPath(){ if(PATHFX){ if(PATHFX.raf)cancelAnimationFrame(PATHFX.raf); gLinks.remove(PATHFX.tube); gLinks.remove(PATHFX.pk); PATHFX=null; } if(TOPO&&WEBGL) build(); }

// ── NetFlow overlay ──────────────────────────────────────────────────────────
async function togOverlay(el){ OVERLAY=!OVERLAY; el.classList.toggle('on',OVERLAY);
  if(OVERLAY){ OVER={}; await Promise.all((TOPO.routers||[]).map(r=> fetch('routing_command.php?api=overlay&node='+r.id).then(x=>x.json()).then(d=>{ if(d&&d.ok) OVER[d.node]=d.by_route; }).catch(()=>{}))); }
}
function showLoops(){ if(!TOPO||!TOPO.loops.length)return; const l=TOPO.loops[0]; MODE='all'; document.getElementById('rc-dev').value='all'; build();
  alert('Routing loop: '+l.map(n=>n.name).join(' → ')); }

function renderFallback(){ const el=document.getElementById('bento');
  el.innerHTML=(TOPO&&TOPO.routers.length)?TOPO.routers.map(r=>`<div class="bcard"><div style="font-weight:700"><i class="fa-solid fa-route" style="color:#7bb8ff"></i> ${esc(r.name)}</div>
    <div style="font-size:12px;color:#8b95a7;margin-top:6px">${r.route_count} routes · ${(r.by_proto.connected||0)}C ${(r.by_proto.static||0)}S ${(r.by_proto.dynamic||0)}D · ${(r.defaults||[]).length} default</div>
    <a href="router_details.php?node=${r.id}" style="color:#4da3ff;font-size:12px">Router details →</a></div>`).join(''):'<div style="color:#8b95a7;grid-column:1/-1;text-align:center">No routers.</div>'; }

if(WEBGL){ initGL();
  document.getElementById('rc-dev').onchange=e=>{ const v=e.target.value; MODE=(v==='all')?'all':+v; selRing.visible=(MODE!=='all'); clearPath(); if(MODE==='all'){ closePanel(); build(); fitAll(); } else { build(); focusRouter(MODE); } };
  document.getElementById('b-spin').onclick=e=>{ spin=!spin; e.currentTarget.classList.toggle('on',spin); };
  document.getElementById('b-fit').onclick=()=>{ MODE='all'; document.getElementById('rc-dev').value='all'; selRing.visible=false; clearPath(); closePanel(); build(); fitAll(); };
  document.getElementById('b-full').onclick=()=>{ if(document.fullscreenElement) document.exitFullscreen(); else stage.requestFullscreen&&stage.requestFullscreen(); };
  document.addEventListener('fullscreenchange',()=>{ const bg=document.getElementById('nm-netbg'); if(bg){ if(document.fullscreenElement===stage){ stage.insertBefore(bg,stage.firstChild); bg.style.zIndex='0'; } else { document.body.appendChild(bg); bg.style.zIndex='-1'; } } const i=document.querySelector('#b-full i'); if(i)i.className='fa-solid '+(document.fullscreenElement?'fa-compress':'fa-expand'); setTimeout(()=>R3.resize&&R3.resize(),80); });
}
document.addEventListener('DOMContentLoaded',()=>{ if(window.NMLoader){ NMLoader.keep(); NMLoader.msg&&NMLoader.msg('building the routing fabric…'); } load(); setInterval(load, 45000); });
</script>
</body></html>
