<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Router Command Center. Every registered router as its own live WebGL
// traffic hologram (core + interface ports + real per-interface packet streams) in
// one immersive, fullscreen-able command space — the fleet-wide sibling of
// router_details.php. Pick one router or all; click an interface to watch its real
// NetFlow conversations fly to/from their actual destinations (geo-tagged).
// Reuses nm_router_list() + nm_router_traffic_probe() + nm_router_flows(). RBAC: 'router_center'.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_router.php');
include('logger.php');

if (!checkAccess($conn, 'router_center')) { header('Location: /denied_access.php?page=router_center'); exit; }

$__api = $_GET['api'] ?? '';
if ($__api !== '') {
    if (function_exists('session_write_close')) @session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    try {
        if ($__api === 'list') { echo json_encode(['ok'=>true, 'routers'=>nm_router_list($conn)]); }
        elseif ($__api === 'traffic') {
            $n = nm_router_node($conn, (int)($_GET['node'] ?? 0));
            echo json_encode($n ? nm_router_traffic_or_config($conn, $n) : ['ok'=>false,'error'=>'unknown node']);
        } elseif ($__api === 'flows') {
            $n = nm_router_node($conn, (int)($_GET['node'] ?? 0));
            echo json_encode($n ? nm_router_flows($conn, $n, 30) : ['ok'=>false,'error'=>'unknown node']);
        } else echo json_encode(['ok'=>false, 'error'=>'unknown api']);
    } catch (\Throwable $e) { echo json_encode(['ok'=>false, 'error'=>$e->getMessage()]); }
    exit;
}

log_user_action($conn, 'view_page', 'router_command.php');
include('header.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(11,15,26,.62); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cyan:#36e3d0; --amber:#ffb454; }
html{ background:#04060d; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#d4dce8; overflow-x:hidden; }
<?= nm_chrome_css() ?>
#rc-stage{ position:relative; width:100%; height:calc(100vh - 74px); min-height:520px; overflow:hidden;
  background:radial-gradient(1200px 680px at 50% 18%, rgba(50,80,160,.16), transparent 72%); }
#rc-stage:fullscreen{ height:100vh; }
#rc-canvas{ position:absolute; inset:0; display:block; }
.rc-hud{ position:absolute; z-index:6; pointer-events:none; }
.rc-hud .glass{ background:var(--glass); backdrop-filter:blur(13px); border:1px solid var(--border); border-radius:13px; pointer-events:auto; }
#rc-top{ top:14px; left:16px; max-width:380px; } #rc-top .glass{ padding:12px 15px; }
#rc-title{ font-size:16px; font-weight:800; display:flex; align-items:center; gap:10px; } #rc-title i{ color:var(--accent); }
#rc-sub{ font-size:11.5px; color:#9fb0c4; margin-top:3px; line-height:1.45; }
.rc-selrow{ display:flex; align-items:center; gap:8px; margin-top:10px; }
.rc-selrow label{ font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8b95a7; }
#rc-dev{ flex:1; background:rgba(0,0,0,.35); border:1px solid var(--border); color:#e6edf7; border-radius:8px; padding:7px 9px; font-size:12.5px; }
#rc-dev option{ background:#0d1526; color:#e6e9ee; }
#rc-legend{ margin-top:9px; display:flex; gap:12px; flex-wrap:wrap; font-size:11px; color:#c3ccd8; }
#rc-legend .dot{ width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:5px;box-shadow:0 0 7px currentColor;vertical-align:middle; }
#rc-stats{ top:14px; right:16px; } #rc-stats .glass{ padding:9px 15px; display:flex; gap:17px; }
.st{ text-align:center; } .st .n{ font-size:19px; font-weight:800; line-height:1; } .st .l{ font-size:8.5px; color:#8b95a7; text-transform:uppercase; letter-spacing:.5px; margin-top:3px; }
.st .n.cy{ color:var(--cyan);} .st .n.am{ color:var(--amber);} .st .n.ok{ color:#5fe39a;} .st .n.crit{ color:#ff8b80;}
#rc-ctl{ top:78px; right:16px; display:flex; flex-direction:column; gap:8px; }
.cbtn{ pointer-events:auto; background:rgba(12,18,30,.8); border:1px solid var(--border); color:#cfe4ff; border-radius:9px; width:38px; height:36px; cursor:pointer; display:flex; align-items:center; justify-content:center; font-size:14px; }
.cbtn:hover{ border-color:var(--accent); color:#fff; } .cbtn.on{ border-color:var(--cyan); color:#fff; background:rgba(54,227,208,.15); }
#rc-hint{ bottom:14px; left:50%; transform:translateX(-50%); font-size:11px; color:#8b95a7; } #rc-hint .glass{ padding:6px 12px; }
#rc-empty{ position:absolute; inset:0; display:none; align-items:center; justify-content:center; flex-direction:column; gap:12px; color:#8b95a7; text-align:center; padding:24px; z-index:3; }
/* focus panel — LEFT side */
#rc-panel{ position:absolute; z-index:12; left:0; top:0; height:100%; width:340px; max-width:92vw; display:none; }
#rc-panel .glass{ height:100%; border-radius:0 16px 16px 0; border-left:none; display:flex; flex-direction:column; background:rgba(8,12,22,.93); box-shadow:24px 0 60px rgba(0,0,0,.5); }
#rp-head{ padding:14px 16px 12px; border-bottom:1px solid var(--border); position:relative; }
#rp-head h3{ margin:0; font-size:15px; display:flex; align-items:center; gap:9px; padding-right:22px; word-break:break-word; }
#rp-head .meta{ font-size:11.5px; color:#9aa3af; margin-top:4px; }
#rp-head .x{ position:absolute; top:12px; right:13px; cursor:pointer; color:#9aa3af; } #rp-head .x:hover{ color:#fff; }
#rp-body{ padding:12px 16px; overflow-y:auto; flex:1; }
.rp-tot{ display:flex; gap:15px; margin-bottom:12px; } .rp-tot .b{ font-size:15px; font-weight:800; } .rp-tot .l{ font-size:8.5px;color:#8b95a7;letter-spacing:.5px; }
.ifrow{ display:flex; align-items:center; gap:8px; margin-bottom:8px; font-size:12px; cursor:pointer; padding:2px 4px; border-radius:6px; }
.ifrow:hover{ background:rgba(255,255,255,.05); }
.ifrow .sd{ width:8px;height:8px;border-radius:50%;flex:none;box-shadow:0 0 6px currentColor; }
.ifrow .nm{ min-width:60px; color:#dbe3ee; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.ifrow .bars{ flex:1; display:flex; flex-direction:column; gap:2px; } .ifrow .bar{ height:4px; border-radius:3px; background:rgba(255,255,255,.07); overflow:hidden; } .ifrow .bar>i{ display:block; height:100%; border-radius:3px; }
.ifrow .v{ min-width:62px; text-align:right; color:#9fb0c4; font-size:10px; font-variant-numeric:tabular-nums; }
.nfsec{ font-size:10px; text-transform:uppercase; letter-spacing:.6px; color:#9db4d6; margin:2px 0 7px; }
.nfline{ display:flex; align-items:center; gap:7px; font-size:11.5px; margin-bottom:5px; }
.nfline .fl{ font-size:13px; } .nfline .ip{ color:#dbe3ee; font-family:Consolas,monospace; } .nfline .ap{ color:#8b95a7; margin-left:auto; } .nfline .mb{ color:#9fb0c4; min-width:44px; text-align:right; font-variant-numeric:tabular-nums; }
.dim{ color:#6f7a8c; font-size:11.5px; }
#rp-acts{ padding:12px 16px; border-top:1px solid var(--border); display:flex; gap:8px; flex-wrap:wrap; }
#rp-acts a{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:8px; padding:8px 11px; font-size:12px; text-decoration:none; cursor:pointer; }
#rp-acts a:hover{ border-color:var(--accent); color:#fff; }
#rc-fallback{ display:none; position:absolute; inset:0; z-index:2; overflow:auto; padding:70px 20px 20px; }
.bento{ display:grid; grid-template-columns:repeat(auto-fill,minmax(240px,1fr)); gap:14px; max-width:1200px; margin:0 auto; }
.bcard{ background:var(--glass); border:1px solid var(--border); border-radius:14px; padding:16px; }
</style>

<div id="rc-stage">
  <canvas id="rc-canvas"></canvas>

  <div id="rc-top" class="rc-hud"><div class="glass">
    <div id="rc-title"><i class="fa-solid fa-route"></i> Router Command Center</div>
    <div id="rc-sub">Pick a router (or all). Each core streams real per-interface traffic — <b style="color:var(--cyan)">cyan in</b> / <b style="color:var(--amber)">amber out</b>. Click an interface to watch its NetFlow fly to real destinations.</div>
    <div class="rc-selrow"><label>Show</label>
      <select id="rc-dev"><option value="all">◎ All routers</option></select>
    </div>
    <div id="rc-legend">
      <span><i class="dot" style="background:var(--cyan)"></i>inbound</span>
      <span><i class="dot" style="background:var(--amber)"></i>outbound</span>
      <span><i class="dot" style="background:#4da3ff"></i>healthy</span>
      <span><i class="dot" style="background:var(--warn)"></i>incident</span>
      <span><i class="dot" style="background:var(--crit)"></i>down</span>
    </div>
  </div></div>

  <div id="rc-stats" class="rc-hud"><div class="glass">
    <div class="st"><div class="n cy" id="s-rt">—</div><div class="l">Routers</div></div>
    <div class="st"><div class="n ok" id="s-up">—</div><div class="l">Online</div></div>
    <div class="st"><div class="n cy" id="s-in">—</div><div class="l">Total In</div></div>
    <div class="st"><div class="n am" id="s-out">—</div><div class="l">Total Out</div></div>
    <div class="st"><div class="n crit" id="s-inc">—</div><div class="l">Incidents</div></div>
  </div></div>

  <div id="rc-ctl" class="rc-hud">
    <button class="cbtn on" id="b-spin" title="Auto-rotate"><i class="fa-solid fa-arrows-rotate"></i></button>
    <button class="cbtn" id="b-fit" title="Reset view"><i class="fa-solid fa-crosshairs"></i></button>
    <button class="cbtn" id="b-full" title="Fullscreen"><i class="fa-solid fa-expand"></i></button>
  </div>

  <div id="rc-hint" class="rc-hud"><div class="glass"><i class="fa-solid fa-hand-pointer"></i> drag to orbit · scroll to zoom · click a router, then an interface</div></div>

  <div id="rc-panel" class="rc-hud"><div class="glass">
    <div id="rp-head"><span class="x" onclick="closePanel()"><i class="fa-solid fa-xmark"></i></span>
      <h3 id="rp-name">—</h3><div class="meta" id="rp-meta">—</div></div>
    <div class="rp-tot" id="rp-tot"></div>
    <div id="rp-body"><div class="dim">Sampling…</div></div>
    <div id="rp-acts"></div>
  </div></div>

  <div id="rc-empty"><i class="fa-solid fa-route" style="font-size:38px;opacity:.4"></i>
    <div>No router-class devices registered.<br>Add MikroTik / Cisco devices in <b>Configuration → Nodes</b>.</div></div>
  <div id="rc-fallback"><div class="bento" id="bento"></div></div>
</div>

<script src="three.min.js"></script>
<script src="three-orbitcontrols.js"></script>
<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function fmtbps(b){ b=+b||0; if(b>=1e9)return (b/1e9).toFixed(2)+' Gbps'; if(b>=1e6)return (b/1e6).toFixed(1)+' Mbps'; if(b>=1e3)return (b/1e3).toFixed(0)+' kbps'; return Math.round(b)+' bps'; }
function lbps(b){ return Math.log10(1+Math.max(0,+b||0)); }
function coreCol(r){ return r.up===false?0xe74c3c:((r.incidents||0)>0?0xf39c12:0x4da3ff); }

let ROUTERS=[], CL={}, R3={}, spin=true, MODE='all', selIf=null, NF=null;
let renderer,scene,camera,controls,stage,canvas,gClusters,selRing;

let WEBGL=true;
(function(){ let ok=false; try{ const c=document.createElement('canvas'); ok=!!(window.WebGLRenderingContext&&(c.getContext('webgl')||c.getContext('experimental-webgl'))); }catch(e){}
  if(!ok||typeof THREE==='undefined'){ WEBGL=false; document.getElementById('rc-canvas').style.display='none'; document.getElementById('rc-fallback').style.display='block'; if(window.NMLoader)NMLoader.hide(); } })();

function labelSprite(text,color,scale){ const c=document.createElement('canvas'),x=c.getContext('2d'),f=36;
  x.font=`700 ${f}px Segoe UI`; const w=Math.ceil(x.measureText(text).width)+16; c.width=w; c.height=f+12;
  x.font=`700 ${f}px Segoe UI`; x.fillStyle='rgba(6,10,20,.55)'; x.fillRect(0,0,w,c.height); x.fillStyle=color||'#dfe7f2'; x.textBaseline='middle'; x.fillText(text,8,c.height/2);
  const tx=new THREE.CanvasTexture(c); tx.minFilter=THREE.LinearFilter;
  const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:tx,transparent:true,depthWrite:false})); sp.scale.set(w*(scale||0.14),c.height*(scale||0.14),1); return sp; }

function initGL(){
  stage=document.getElementById('rc-stage'); canvas=document.getElementById('rc-canvas');
  renderer=new THREE.WebGLRenderer({canvas,antialias:true,alpha:true}); renderer.setClearColor(0x000000,0);
  scene=new THREE.Scene(); scene.fog=new THREE.FogExp2(0x04060d,0.0007);
  camera=new THREE.PerspectiveCamera(54,1,0.5,7000); camera.position.set(0,220,560);
  controls=new THREE.OrbitControls(camera,renderer.domElement); controls.enableDamping=true; controls.dampingFactor=.08;
  controls.autoRotate=true; controls.autoRotateSpeed=.35; controls.minDistance=70; controls.maxDistance=3200;
  scene.add(new THREE.AmbientLight(0x8899cc,0.95)); const key=new THREE.PointLight(0xafc4ff,0.7,0); key.position.set(300,500,400); scene.add(key);
  gClusters=new THREE.Group(); scene.add(gClusters);
  selRing=new THREE.Mesh(new THREE.TorusGeometry(46,1.4,10,48),new THREE.MeshBasicMaterial({color:0xffffff,transparent:true,opacity:.7,blending:THREE.AdditiveBlending,depthWrite:false})); selRing.visible=false; scene.add(selRing);
  const ray=new THREE.Raycaster(); const mouse=new THREE.Vector2();
  function targets(){ const t=[]; Object.values(CL).forEach(c=>{ if(!c.grp.visible)return; t.push(c.core); Object.values(c.pnodes).forEach(p=>t.push(p.node)); }); return t; }
  function pick(ev){ const r=canvas.getBoundingClientRect(); mouse.x=((ev.clientX-r.left)/r.width)*2-1; mouse.y=-((ev.clientY-r.top)/r.height)*2+1; ray.setFromCamera(mouse,camera); return ray.intersectObjects(targets(),false); }
  canvas.addEventListener('click',ev=>{ const h=pick(ev); if(!h.length)return; const u=h[0].object.userData;
    if(u&&u.iface) selectIface(u.cid,u.name); else if(u&&u.id!=null) focusRouter(u.id); });
  canvas.addEventListener('mousemove',ev=>{ canvas.style.cursor=pick(ev).length?'pointer':'grab'; });
  function resize(){ const w=stage.clientWidth,h=stage.clientHeight; renderer.setPixelRatio(Math.min(devicePixelRatio||1,2)); renderer.setSize(w,h,false); camera.aspect=w/h; camera.updateProjectionMatrix(); }
  resize(); window.addEventListener('resize',resize); R3.resize=resize;
  document.addEventListener('visibilitychange',()=>{ R3.hidden=document.hidden; if(!R3.hidden)R3.last=performance.now(); });
  R3.last=performance.now(); animate();
}

function layout(n){ const pos=[]; if(n<=1){ pos.push(new THREE.Vector3(0,0,0)); return pos; }
  const CR=210+n*36; for(let i=0;i<n;i++){ const a=(i/n)*Math.PI*2; pos.push(new THREE.Vector3(Math.cos(a)*CR,(i%2?18:-18),Math.sin(a)*CR)); } return pos; }

function buildScene(){
  while(gClusters.children.length){ gClusters.remove(gClusters.children[0]); } CL={}; NF=null;
  if(!ROUTERS.length){ document.getElementById('rc-empty').style.display='flex'; if(window.NMLoader)NMLoader.hide(); return; }
  document.getElementById('rc-empty').style.display='none';
  const pos=layout(ROUTERS.length); const coreGeo=new THREE.IcosahedronGeometry(20,2);
  ROUTERS.forEach((r,i)=>{ const grp=new THREE.Group(); grp.position.copy(pos[i]); gClusters.add(grp); const col=coreCol(r);
    const core=new THREE.Mesh(coreGeo,new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:.9,roughness:.3,metalness:.4,flatShading:true})); core.userData=r; grp.add(core);
    const halo=new THREE.Mesh(new THREE.SphereGeometry(30,20,20),new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:.09,blending:THREE.AdditiveBlending,depthWrite:false})); grp.add(halo);
    const lab=labelSprite(r.name,'#eaf1ff',0.17); lab.position.set(0,44,0); grp.add(lab);
    const ports=new THREE.Group(), flows=new THREE.Group(), nfg=new THREE.Group(); grp.add(flows); grp.add(ports); grp.add(nfg);
    CL[r.id]={grp,core,halo,lab,ports,flows,nfg,pos:pos[i],router:r,pnodes:{},t:Math.random()*10,built:false};
  });
  if(window.NMLoader)NMLoader.hide(); applyMode();
}

function buildPorts(cl,ifs){ const list=ifs.filter(f=>!f.disabled).slice(0,16);
  [cl.ports,cl.flows].forEach(g=>{ while(g.children.length){ const c=g.children[0]; g.remove(c); if(c.geometry)c.geometry.dispose(); } }); cl.pnodes={};
  const n=list.length||1, R=54;
  list.forEach((f,i)=>{ const a=(i/n)*Math.PI*2; const p=new THREE.Vector3(Math.cos(a)*R,(i%2?8:-8),Math.sin(a)*R);
    const up=f.running, col=up?0x2ee6a0:0xe74c3c;
    const node=new THREE.Mesh(new THREE.OctahedronGeometry(5,0),new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:.8,flatShading:true,roughness:.4}));
    node.position.copy(p); node.userData={iface:true,cid:cl.router.id,name:f.name}; cl.ports.add(node);
    const lab=labelSprite(f.name,up?'#cfe0ff':'#ff9b91',0.1); lab.position.copy(p).add(new THREE.Vector3(0,11,0)); cl.ports.add(lab);
    const mid=p.clone().multiplyScalar(0.5); mid.y+=16; const curve=new THREE.QuadraticBezierCurve3(new THREE.Vector3(0,0,0),mid,p);
    cl.flows.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(20)),new THREE.LineBasicMaterial({color:up?0x2f4468:0x5a2530,transparent:true,opacity:.35})));
    const mk=hex=>{ const P=18,g=new THREE.BufferGeometry(),pp=new Float32Array(P*3); g.setAttribute('position',new THREE.BufferAttribute(pp,3));
      const pts=new THREE.Points(g,new THREE.PointsMaterial({color:hex,size:6,sizeAttenuation:false,transparent:true,opacity:.95,blending:THREE.AdditiveBlending,depthWrite:false})); cl.flows.add(pts); return {pts,pp,P}; };
    cl.pnodes[f.name]={node,curve,rx:mk(0x36e3d0),tx:mk(0xffb454),phase:Math.random(),f,up};
  });
  cl.built=true;
}
function updatePorts(cl,ifs){ ifs.forEach(f=>{ const p=cl.pnodes[f.name]; if(!p)return; p.f=f; p.up=f.running;
  const col=f.running?0x2ee6a0:0xe74c3c; p.node.material.color.setHex(col); p.node.material.emissive.setHex(col);
  p.node.scale.setScalar(0.8+Math.min(2,lbps(f.rx_bps+f.tx_bps)*0.26)); }); }

// ── NetFlow burst: real conversations fly to/from their destinations ─────────────
function clearNF(){ if(NF&&NF.cl){ while(NF.cl.nfg.children.length){ const c=NF.cl.nfg.children[0]; NF.cl.nfg.remove(c); if(c.geometry)c.geometry.dispose(); } } NF=null; }
function buildNetflow(cl,data){ clearNF(); NF={cl,streams:[]}; const g=cl.nfg;
  const place=(arr,sign,hex,dir)=>{ const n=arr.length||1; arr.forEach((f,i)=>{ const az=i*2.399963; const inc=Math.acos(1-(i+0.5)/n*0.9);
      const rad=130+Math.min(70,lbps((+f.mbps||0)*1e6)*11); const rr=Math.sin(inc)*rad+60; const y=sign*(24+Math.cos(inc)*80);
      const pos=new THREE.Vector3(Math.cos(az)*rr,y,Math.sin(az)*rr); const col=f.ext?hex:0x8a93a6;
      const node=new THREE.Mesh(new THREE.SphereGeometry(3.6,10,10),new THREE.MeshBasicMaterial({color:col})); node.position.copy(pos); g.add(node);
      const mid=pos.clone().multiplyScalar(0.5); mid.y+=sign*24; const curve=new THREE.QuadraticBezierCurve3(new THREE.Vector3(0,0,0),mid,pos);
      g.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(20)),new THREE.LineBasicMaterial({color:col,transparent:true,opacity:.22})));
      const P=14,bg=new THREE.BufferGeometry(),pp=new Float32Array(P*3); bg.setAttribute('position',new THREE.BufferAttribute(pp,3));
      const pts=new THREE.Points(bg,new THREE.PointsMaterial({color:col,size:5.5,sizeAttenuation:false,transparent:true,opacity:.95,blending:THREE.AdditiveBlending,depthWrite:false})); g.add(pts);
      NF.streams.push({curve,pts,pp,P,phase:Math.random(),dir,mbps:+f.mbps||0});
      const lab=labelSprite((f.flag?f.flag+' ':'')+f.ip,dir>0?'#ffddb0':'#c2f4ef',0.095); lab.position.copy(pos).add(new THREE.Vector3(0,7,0)); g.add(lab);
    }); };
  place(data.outbound||[],1,0xffb454,1);    // outbound: up · amber · core→dst
  place(data.inbound||[],-1,0x36e3d0,-1);   // inbound: down · cyan · src→core
}

function animate(){ requestAnimationFrame(animate); if(!WEBGL||R3.hidden) return;
  const now=performance.now(), dt=Math.min(0.05,(now-R3.last)/1000); R3.last=now; controls.autoRotate=spin; controls.update();
  Object.values(CL).forEach(cl=>{ if(!cl.grp.visible)return; cl.t+=dt;
    const s=1+Math.sin(cl.t*2.1)*0.03; cl.core.scale.setScalar(s); cl.core.material.emissiveIntensity=0.7+Math.sin(cl.t*2.1)*0.3;
    cl.core.rotation.y+=dt*0.25; cl.halo.scale.setScalar(1+Math.sin(cl.t*1.5)*0.05);
    Object.values(cl.pnodes).forEach(p=>{ const rxb=+p.f.rx_bps||0, txb=+p.f.tx_bps||0;
      const flow=(st,speed,dir,active)=>{ if(!st)return; const vis=active&&speed>0.05; st.pts.visible=vis; if(!vis)return; p.phase=(p.phase+speed*dt)%1;
        for(let i=0;i<st.P;i++){ let t=(p.phase+i/st.P)%1; if(dir<0)t=1-t; const pt=p.curve.getPoint(t); st.pp[i*3]=pt.x;st.pp[i*3+1]=pt.y;st.pp[i*3+2]=pt.z; }
        st.pts.geometry.attributes.position.needsUpdate=true; st.pts.material.opacity=0.5+Math.min(0.5,lbps(dir<0?rxb:txb)*0.08); };
      flow(p.rx,p.up?(0.05+lbps(rxb)*0.12):0,-1,p.up&&rxb>0); flow(p.tx,p.up?(0.05+lbps(txb)*0.12):0,1,p.up&&txb>0); });
  });
  if(NF){ NF.streams.forEach(s=>{ s.phase=(s.phase+(0.05+lbps(s.mbps*1e6)*0.06)*dt)%1;
    for(let i=0;i<s.P;i++){ let t=(s.phase+i/s.P)%1; if(s.dir<0)t=1-t; const p=s.curve.getPoint(t); s.pp[i*3]=p.x;s.pp[i*3+1]=p.y;s.pp[i*3+2]=p.z; }
    s.pts.geometry.attributes.position.needsUpdate=true; }); }
  if(selRing.visible&&MODE!=='all'&&CL[MODE]){ selRing.position.copy(CL[MODE].grp.position); selRing.lookAt(camera.position); selRing.material.opacity=0.35+0.35*Math.abs(Math.sin(now*0.003)); }
  renderer.render(scene,camera);
}
function fitAll(){ if(!Object.keys(CL).length) return; const box=new THREE.Box3(); Object.values(CL).forEach(c=>box.expandByPoint(c.pos));
  const ctr=box.getCenter(new THREE.Vector3()), sz=box.getSize(new THREE.Vector3()), r=Math.max(sz.x,sz.z,150)+140;
  controls.target.copy(ctr); camera.position.set(ctr.x,ctr.y+r*0.5,ctr.z+r*1.45); camera.updateProjectionMatrix(); }
function fitCluster(cl){ if(!cl) return; const p=cl.pos; controls.target.copy(p); camera.position.set(p.x,p.y+70,p.z+165); camera.updateProjectionMatrix(); }

// ── mode / selection ─────────────────────────────────────────────────────────
function applyMode(){ const single=(MODE!=='all');
  Object.values(CL).forEach(c=>{ c.grp.visible = !single || (c.router.id==MODE); });
  selRing.visible = single;
  if(single){ if(NF&&NF.cl&&NF.cl.router.id!=MODE) clearNF(); fitCluster(CL[MODE]); }
  else { clearNF(); closePanel(); fitAll(); }
}
function focusRouter(id){ MODE=id; selIf=null; document.getElementById('rc-dev').value=String(id); applyMode(); openSummary(id); }
function openSummary(id){ const cl=CL[id]; if(!cl)return; const r=cl.router;
  document.getElementById('rc-panel').style.display='block';
  document.getElementById('rp-name').innerHTML=`<i class="fa-solid ${r.mikrotik?'fa-dharmachakra':'fa-route'}" style="color:${r.up===false?'#ff8b80':((r.incidents||0)>0?'#ffce6b':'#7bb8ff')}"></i> ${esc(r.name)}`;
  document.getElementById('rp-meta').innerHTML=`${esc(r.ip||'')}${r.model?' · '+esc(r.model):''}${r.grp?' · '+esc(r.grp):''}`;
  renderSummary(cl);
  document.getElementById('rp-acts').innerHTML=`<a href="router_details.php?node=${r.id}"><i class="fa-solid fa-gauge-high"></i> Full Details</a> <a href="router_commander.php?node=${r.id}&host=${esc(r.ip)}" target="_blank"><i class="fa-solid fa-terminal"></i> Commander</a>`+(r.mikrotik?` <a href="mtfw.php?node=${r.id}"><i class="fa-solid fa-shield-halved"></i> Device Manager</a>`:'');
}
function renderSummary(cl){ if(MODE!==cl.router.id||selIf) return; const r=cl.router;
  document.getElementById('rp-tot').innerHTML=`<div><div class="l">▼ IN</div><div class="b" style="color:var(--cyan)">${fmtbps(cl.trx||0)}</div></div>
    <div><div class="l">▲ OUT</div><div class="b" style="color:var(--amber)">${fmtbps(cl.ttx||0)}</div></div>
    <div><div class="l">PORTS</div><div class="b">${(cl.lastIfs||[]).filter(x=>x.running).length}/${(cl.lastIfs||[]).length}</div></div>`;
  const ifs=(cl.lastIfs||[]).slice().sort((a,b)=>(b.rx_bps+b.tx_bps)-(a.rx_bps+a.tx_bps)); const mx=Math.max(1,...ifs.map(f=>Math.max(f.rx_bps,f.tx_bps)));
  const noLive = (cl.live===false) ? `<div class="dim" style="margin-bottom:9px;color:#ffce6b"><i class="fa-solid fa-plug-circle-xmark"></i> No SSH credential — showing polled interfaces (no live rates/flows). Assign one in <a href="net_mon_config.php?tab=nodes" style="color:#4da3ff">Config → Nodes</a>.</div>` : '';
  document.getElementById('rp-body').innerHTML = noLive + '<div class="nfsec">Interfaces — click one to trace its NetFlow</div>'+ (ifs.length? ifs.map(f=>{ const col=f.disabled?'#6f7a8c':(f.running?'#2ecc71':'#e74c3c');
    return `<div class="ifrow" onclick="selectIface(${cl.router.id},'${esc(f.name)}')"><span class="sd" style="color:${col}"></span><span class="nm">${esc(f.name)}</span>
      <span class="bars"><span class="bar"><i style="width:${Math.round(f.rx_bps/mx*100)}%;background:var(--cyan)"></i></span><span class="bar"><i style="width:${Math.round(f.tx_bps/mx*100)}%;background:var(--amber)"></i></span></span>
      <span class="v">${fmtbps(f.rx_bps)}<br>${fmtbps(f.tx_bps)}</span></div>`; }).join('') : '<div class="dim">Sampling live counters… (needs SSH)</div>'); }

async function selectIface(cid,name){ if(MODE!=cid){ MODE=cid; document.getElementById('rc-dev').value=String(cid); applyMode(); } selIf=name;
  const cl=CL[cid]; if(!cl)return; document.getElementById('rc-panel').style.display='block';
  document.getElementById('rp-name').innerHTML=`<i class="fa-solid fa-diagram-project" style="color:var(--accent)"></i> ${esc(cl.router.name)} · ${esc(name)}`;
  document.getElementById('rp-meta').textContent='Live NetFlow — real destinations & sources (30 min)';
  document.getElementById('rp-tot').innerHTML=''; document.getElementById('rp-body').innerHTML='<div class="dim">Tracing flows…</div>';
  document.getElementById('rp-acts').innerHTML=`<a onclick="backToRouter(${cid})"><i class="fa-solid fa-arrow-left"></i> Interfaces</a> <a href="netflow.php" target="_blank"><i class="fa-solid fa-chart-area"></i> Full NetFlow</a>`;
  let d=null; try{ d=await fetch('router_command.php?api=flows&node='+cid+'&_='+Date.now()).then(r=>r.json()); }catch(e){}
  if(!d||!d.ok){ document.getElementById('rp-body').innerHTML='<div class="dim">'+esc((d&&d.error)||'No NetFlow exported by this router.')+'</div>'; clearNF(); return; }
  buildNetflow(cl,d);
  const row=(f,dir)=>`<div class="nfline"><span style="color:${dir>0?'#ffd9a8':'#bff2ee'}">${dir>0?'▲':'▼'}</span><span class="fl">${f.flag||'🏠'}</span><span class="ip">${esc(f.ip)}</span><span class="ap">${esc(f.app||'')}</span><span class="mb">${(+f.mbps).toFixed(2)}M</span></div>`;
  document.getElementById('rp-body').innerHTML =
    `<div class="nfsec">▲ Outbound → destinations (${d.out_total||0})</div>`+((d.outbound||[]).map(f=>row(f,1)).join('')||'<div class="dim">none</div>')+
    `<div class="nfsec" style="margin-top:12px">▼ Inbound ← sources (${d.in_total||0})</div>`+((d.inbound||[]).map(f=>row(f,-1)).join('')||'<div class="dim">none seen</div>');
}
function backToRouter(cid){ selIf=null; clearNF(); openSummary(cid); }
function closePanel(){ selIf=null; document.getElementById('rc-panel').style.display='none'; }

// ── data ─────────────────────────────────────────────────────────────────────
async function loadList(){
  let d=null; try{ d=await fetch('router_command.php?api=list&_='+Date.now()).then(r=>r.json()); }catch(e){}
  if(!d||!d.ok) return; ROUTERS=d.routers||[];
  const sel=document.getElementById('rc-dev'); sel.innerHTML='<option value="all">◎ All routers</option>'+ROUTERS.map(r=>`<option value="${r.id}">${esc(r.name)}</option>`).join('');
  sel.value=(MODE==='all'?'all':String(MODE));
  if(WEBGL) buildScene(); else renderFallback();
  document.getElementById('s-rt').textContent=ROUTERS.length;
  document.getElementById('s-up').textContent=ROUTERS.filter(r=>r.up).length;
  document.getElementById('s-inc').textContent=ROUTERS.reduce((a,r)=>a+(r.incidents||0),0);
  pollAll();
}
async function pollAll(){ if(!WEBGL||document.hidden||!ROUTERS.length) return; let tin=0,tout=0;
  await Promise.all(ROUTERS.map(r=> fetch('router_command.php?api=traffic&node='+r.id+'&_='+Date.now()).then(x=>x.json()).then(d=>{
    if(!d||!d.ok) return; const cl=CL[r.id]; if(!cl) return; const ifs=d.interfaces||[];
    if(!cl.built) buildPorts(cl,ifs); else if(ifs.length!==Object.keys(cl.pnodes).length) buildPorts(cl,ifs); else updatePorts(cl,ifs);
    cl.lastIfs=ifs; cl.trx=d.total_rx_bps||0; cl.ttx=d.total_tx_bps||0; cl.live=(d.live!==false); cl.errmsg=d.error||''; tin+=cl.trx; tout+=cl.ttx;
    if(MODE==r.id && !selIf) renderSummary(cl);
  }).catch(()=>{}) ));
  document.getElementById('s-in').textContent=fmtbps(tin); document.getElementById('s-out').textContent=fmtbps(tout);
}

function renderFallback(){ const el=document.getElementById('bento');
  el.innerHTML=ROUTERS.length?ROUTERS.map(r=>`<div class="bcard"><div style="font-weight:700"><i class="fa-solid fa-route" style="color:${r.up===false?'#ff8b80':'#7bb8ff'}"></i> ${esc(r.name)}</div>
    <div style="font-size:12px;color:#8b95a7;margin-top:6px">${esc(r.ip||'')} · ${r.up===false?'DOWN':(r.uptime24!=null?r.uptime24+'% 24h':'up')} · ${r.incidents||0} incidents</div>
    <a href="router_details.php?node=${r.id}" style="color:#4da3ff;font-size:12px">Open details →</a></div>`).join(''):'<div style="color:#8b95a7;grid-column:1/-1;text-align:center">No routers registered.</div>'; }

if(WEBGL){ initGL();
  document.getElementById('rc-dev').onchange=e=>{ const v=e.target.value; if(v==='all'){ MODE='all'; selIf=null; applyMode(); } else focusRouter(+v); };
  document.getElementById('b-spin').onclick=e=>{ spin=!spin; e.currentTarget.classList.toggle('on',spin); };
  document.getElementById('b-fit').onclick=()=>{ MODE='all'; selIf=null; document.getElementById('rc-dev').value='all'; applyMode(); };
  document.getElementById('b-full').onclick=()=>{ if(document.fullscreenElement) document.exitFullscreen(); else stage.requestFullscreen&&stage.requestFullscreen(); };
  document.addEventListener('fullscreenchange',()=>{ const bg=document.getElementById('nm-netbg');
    if(bg){ if(document.fullscreenElement===stage){ stage.insertBefore(bg,stage.firstChild); bg.style.zIndex='0'; } else { document.body.appendChild(bg); bg.style.zIndex='-1'; } }
    const i=document.querySelector('#b-full i'); if(i) i.className='fa-solid '+(document.fullscreenElement?'fa-compress':'fa-expand'); setTimeout(()=>R3.resize&&R3.resize(),80); });
}
document.addEventListener('DOMContentLoaded',()=>{ if(window.NMLoader) NMLoader.keep(); loadList(); setInterval(pollAll, 12000); });
</script>
</body></html>
