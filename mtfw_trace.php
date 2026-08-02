<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — MikroTik Firewall PACKET TRACER. A Cisco-Packet-Tracer-style 3D view:
// a packet flies through the firewall's rule "gates" one by one — sailing past
// rules it doesn't match and stopping at the exact gate that ACCEPTS or DROPS it.
// Read-only (walks the live rules; no router change). RBAC: 'mtfw'.
// Data: mtfw.php?api=routers | ?api=trace  (engine nm_mtfw_trace in nm_mtfw.php).
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
include('logger.php');
if (!checkAccess($conn, 'mtfw')) { header('Location: /denied_access.php?page=mtfw'); exit; }
$initNode = (int)($_GET['node'] ?? 0);
log_user_action($conn, 'view_page', 'mtfw_trace.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="three.min.js"></script>
<script src="three-orbitcontrols.js"></script>
<style>
:root{ --glass:rgba(11,16,27,.72); --border:rgba(255,255,255,.12); --accent:#4da3ff; --cyan:#36e3d0; --ok:#2ee66e; --warn:#f0a92c; --crit:#ff5a5a; }
html{ background:#05080f; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#d4dce8; }
<?= nm_chrome_css() ?>
.tw{ max-width:1560px; margin:0 auto; padding:16px 20px 30px; }
.tbar{ display:flex; align-items:center; gap:14px; padding:12px 16px; margin-bottom:14px; flex-wrap:wrap;
  background:var(--glass); backdrop-filter:blur(13px); border:1px solid var(--border); border-radius:14px; }
.tbar .ttl{ font-size:18px; font-weight:800; display:flex; align-items:center; gap:10px; } .tbar .ttl i{ color:#36e3d0; }
.tbar select,.tbar a.back{ background:rgba(0,0,0,.35); border:1px solid var(--border); color:#e6edf7; border-radius:9px; padding:8px 12px; font-size:13px; text-decoration:none; }
.tbar a.back:hover{ border-color:var(--accent); color:#fff; }
#stage{ position:relative; height:78vh; min-height:600px; border-radius:16px; overflow:hidden; border:1px solid var(--border);
  background:radial-gradient(circle at 50% 30%,rgba(20,42,64,.4),rgba(5,8,15,.96) 72%); }
#stage:fullscreen,#stage:-webkit-full-screen{ height:100vh!important; width:100vw!important; border-radius:0; border:none; }
#tcanvas{ position:absolute; inset:0; width:100%; height:100%; display:block; z-index:1; }
/* in fullscreen the body-level particle canvas is reparented INTO #stage (see moveBg) */
#stage:fullscreen #nm-netbg,#stage:-webkit-full-screen #nm-netbg{ z-index:0!important; }
.panel{ position:absolute; background:rgba(8,12,22,.82); backdrop-filter:blur(12px); border:1px solid var(--border); border-radius:13px; z-index:4; }
#form{ top:14px; left:14px; width:300px; padding:14px 15px; }
#form h3{ margin:0 0 10px; font-size:13px; font-weight:800; display:flex; align-items:center; gap:8px; } #form h3 i{ color:#36e3d0; }
.frow{ display:grid; grid-template-columns:1fr 1fr; gap:8px; }
label{ display:block; font-size:10px; text-transform:uppercase; letter-spacing:.4px; color:#8b95a7; margin:8px 0 3px; }
.inp{ width:100%; background:rgba(0,0,0,.35); border:1px solid var(--border); color:#e6edf7; border-radius:8px; padding:7px 9px; font-size:12.5px; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:8px 12px; font-size:13px; cursor:pointer; }
.btn:hover{ border-color:var(--accent); color:#fff; } .btn.g{ background:linear-gradient(135deg,#36e3d0,#4da3ff); border:none; color:#04121a; font-weight:700; }
.btn.sm{ padding:6px 9px; font-size:12px; }
#playbar{ display:flex; align-items:center; gap:7px; margin-top:11px; }
#playbar input[type=range]{ flex:1; accent-color:#36e3d0; }
#verdict{ top:14px; left:50%; transform:translateX(-50%); padding:11px 20px; text-align:center; display:none; min-width:260px; }
#verdict .v{ font-size:18px; font-weight:800; } #verdict .s{ font-size:11.5px; color:#9fb0c2; margin-top:2px; }
#log{ top:14px; right:14px; width:320px; max-height:calc(78vh - 28px); padding:12px 6px 12px 12px; display:flex; flex-direction:column; }
#log h3{ margin:0 0 8px; font-size:12px; font-weight:800; color:#cfe0f7; text-transform:uppercase; letter-spacing:.6px; }
#steps{ overflow:auto; padding-right:6px; }
.st{ display:flex; align-items:center; gap:9px; padding:7px 9px; border-radius:8px; margin-bottom:5px; font-size:12px;
  border:1px solid var(--border); border-left:3px solid #46516a; background:rgba(255,255,255,.02); transition:all .15s; }
.st.miss{ opacity:.5; } .st.match{ border-left-color:#f0a92c; } .st.accept{ border-left-color:#2ee66e; } .st.drop{ border-left-color:#ff5a5a; }
.st.cur{ opacity:1; background:rgba(54,227,208,.12); border-color:rgba(54,227,208,.5); box-shadow:0 0 0 1px rgba(54,227,208,.3); }
.st .si{ font-weight:800; color:#8391a5; font-variant-numeric:tabular-nums; min-width:20px; text-align:right; }
.st .sa{ font-size:9px; font-weight:800; text-transform:uppercase; padding:2px 6px; border-radius:5px; background:rgba(255,255,255,.08); }
.st.accept .sa{ background:rgba(46,230,110,.2); color:#8ff0b6; } .st.drop .sa{ background:rgba(255,90,90,.2); color:#ffb0b0; } .st.match .sa{ background:rgba(240,169,44,.2); color:#ffd98a; }
.st .sm{ flex:1; min-width:0; font-family:Consolas,monospace; font-size:10.5px; color:#b9c4d4; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.st .why{ font-size:9px; color:#6c7688; }
.muted{ color:#8b95a7; font-size:12px; } .dim{ color:#6f7a8c; }
#hint{ position:absolute; inset:0; display:flex; align-items:center; justify-content:center; flex-direction:column; gap:12px; z-index:3; pointer-events:none; color:#6f7c90; }
#hint i{ font-size:46px; color:#2a4a5e; }
@media(max-width:1100px){ #log{ display:none; } #form{ width:270px; } }
</style>

<?php include('header.php'); ?>
<div class="tw">
  <div class="tbar">
    <div class="ttl"><i class="fa-solid fa-satellite-dish"></i> Firewall Packet Tracer</div>
    <select id="node" onchange="onNode()"><option value="">Select a router…</option></select>
    <span style="flex:1"></span>
    <a class="back" id="fsbtn" onclick="toggleFs()" style="cursor:pointer"><i class="fa-solid fa-expand"></i> Fullscreen</a>
    <a class="back" href="mtfw.php"><i class="fa-solid fa-arrow-left"></i> Firewall Control</a>
  </div>

  <div id="stage">
    <canvas id="tcanvas"></canvas>

    <div class="panel" id="form">
      <h3><i class="fa-solid fa-cube"></i> Craft a packet</h3>
      <div class="frow">
        <div><label>Chain</label><select class="inp" id="p-chain"><option>input</option><option selected>forward</option><option>output</option></select></div>
        <div><label>Protocol</label><select class="inp" id="p-proto"><option value="tcp">tcp</option><option value="udp">udp</option><option value="icmp">icmp</option><option value="">any</option></select></div>
      </div>
      <label>Source IP</label><input class="inp" id="p-src" placeholder="70.45.1.1">
      <label>Destination IP</label><input class="inp" id="p-dst" placeholder="192.168.0.25">
      <div class="frow">
        <div><label>Dst port</label><input class="inp" id="p-dport" placeholder="8001"></div>
        <div><label>Conn-state</label><select class="inp" id="p-state"><option selected>new</option><option>established</option><option>related</option><option>invalid</option></select></div>
      </div>
      <label>In-interface <span class="dim" style="text-transform:none">(how it enters — key for WAN blocks)</span></label>
      <select class="inp" id="p-inif"><option value="">any interface</option></select>
      <button class="btn g" style="width:100%;margin-top:12px;" onclick="runTrace()"><i class="fa-solid fa-play"></i> Trace packet</button>
      <div id="playbar" style="display:none;">
        <button class="btn sm" id="pp" onclick="togglePlay()"><i class="fa-solid fa-pause"></i></button>
        <button class="btn sm" onclick="replay()" title="Replay"><i class="fa-solid fa-rotate-left"></i></button>
        <input type="range" id="spd" min="0.4" max="3" step="0.1" value="1" oninput="document.getElementById('spdl').textContent=this.value+'x'">
        <span class="muted" id="spdl" style="min-width:30px">1x</span>
      </div>
      <div class="muted" id="ferr" style="margin-top:9px;"></div>
      <div class="dim" style="font-size:10.5px;line-height:1.5;margin-top:10px;border-top:1px solid rgba(255,255,255,.07);padding-top:9px;">
        <i class="fa-solid fa-circle-info"></i> Traces the real RouterOS path: <b>dst-nat</b> (prerouting) → <b>filter</b> → <b>src-nat</b> (postrouting).
        LAN↔LAN traffic uses the <b>forward</b> chain (input = traffic to the router itself). <b>src-nat/masquerade never unblocks a filter DROP</b> — to allow a flow, add a filter ACCEPT rule.
        <b>established/related</b> = return traffic (normally accepted) — use <b>new</b> to test a fresh connection.
      </div>
    </div>

    <div class="panel" id="verdict"><div class="v" id="v-txt"></div><div class="s" id="v-sub"></div></div>

    <div class="panel" id="log">
      <h3>Rule-by-rule trace</h3>
      <div id="steps"><div class="dim" style="padding:8px">Craft a packet and press <b>Trace</b>.</div></div>
    </div>

    <div id="hint"><i class="fa-solid fa-diagram-project"></i><div>Pick a router, craft a packet, and watch it fly the firewall.</div></div>
  </div>
</div>

<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const INIT_NODE=<?= json_encode($initNode) ?>;
let NODE=0, T={}, GATES=[], PKT=null, TRAIL=null, WP=[], STATE='idle', legI=0, legT=0, dwell=0, RES=null, done=false;
let IFACES=[];
const GAP=95, GATE_R=26;

// ── router list ──
async function loadRouters(){
  const d=await fetch('mtfw.php?api=routers').then(r=>r.json()).catch(()=>null);
  const sel=document.getElementById('node'); if(!d||!d.ok){ return; }
  sel.innerHTML='<option value="">Select a router…</option>'+d.routers.map(r=>`<option value="${r.id}">${esc(r.name)} (${esc(r.ip)})</option>`).join('');
  if(INIT_NODE){ sel.value=INIT_NODE; NODE=INIT_NODE; loadInterfaces(); }
}
function onNode(){ NODE=+document.getElementById('node').value||0; loadInterfaces(); }
// live interface list for the In-interface picker (also carries interface-list membership)
async function loadInterfaces(){
  const sel=document.getElementById('p-inif'); IFACES=[];
  sel.innerHTML='<option value="">any interface</option>';
  if(!NODE) return;
  sel.innerHTML='<option value="">loading…</option>';
  const d=await fetch('mtfw.php?api=interfaces&node='+NODE+'&_='+Date.now()).then(r=>r.json()).catch(()=>null);
  if(!d||!d.ok){ sel.innerHTML='<option value="">any interface</option>'; return; }
  IFACES=d.interfaces||[];
  sel.innerHTML='<option value="">any interface</option>'+IFACES.map(i=>{
    const tag=i.lists&&i.lists.length?' · '+i.lists.join('/'):''; return `<option value="${esc(i.name)}">${esc(i.name)}${esc(tag)}</option>`;
  }).join('');
}

// ── three.js scene ──
function initThree(){
  const cv=document.getElementById('tcanvas'), wrap=cv.parentElement, w=wrap.clientWidth||1200, h=wrap.clientHeight||620;
  const rn=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true}); rn.setPixelRatio(Math.min(2,devicePixelRatio)); rn.setSize(w,h,false);
  const sc=new THREE.Scene(); sc.fog=new THREE.FogExp2(0x05080f,0.0011);
  const cam=new THREE.PerspectiveCamera(52,w/h,0.1,12000); cam.position.set(-60,150,260);
  const ctr=new THREE.OrbitControls(cam,cv); ctr.enableDamping=true; ctr.dampingFactor=.09; ctr.maxPolarAngle=Math.PI*0.49;
  sc.add(new THREE.AmbientLight(0x8fb0d0,0.75)); const pl=new THREE.PointLight(0x6fd8ff,1.0,0); pl.position.set(0,300,200); sc.add(pl);
  T={rn,sc,cam,ctr,root:new THREE.Group(),ct:0,follow:new THREE.Vector3()}; sc.add(T.root);
  T.resize=()=>{ const w=wrap.clientWidth,h=wrap.clientHeight; if(!w||!h)return; cam.aspect=w/h; cam.updateProjectionMatrix(); rn.setSize(w,h,false); };
  addEventListener('resize',T.resize);
  animate();
}
// ── fullscreen the stage ──
function toggleFs(){ const st=document.getElementById('stage');
  const fsEl=document.fullscreenElement||document.webkitFullscreenElement;
  if(!fsEl){ (st.requestFullscreen||st.webkitRequestFullscreen||function(){}).call(st); }
  else{ (document.exitFullscreen||document.webkitExitFullscreen||function(){}).call(document); }
}
// Reparent the live particle canvas (#nm-netbg) INTO #stage while fullscreen so it stays
// visible (a child fullscreen hides the body-level canvas), then move it back on exit.
function moveBg(into){ const bg=document.getElementById('nm-netbg'); if(!bg) return;
  if(into){ const st=document.getElementById('stage'); bg.style.zIndex='0'; st.insertBefore(bg, st.firstChild); }
  else{ bg.style.zIndex='-1'; document.body.insertBefore(bg, document.body.firstChild); }
  setTimeout(()=>window.dispatchEvent(new Event('resize')), 40);   // let nm_netbg refit
}
function _fsSync(){ const on=!!(document.fullscreenElement||document.webkitFullscreenElement);
  const b=document.getElementById('fsbtn'); if(b) b.innerHTML='<i class="fa-solid fa-'+(on?'compress':'expand')+'"></i> '+(on?'Exit fullscreen':'Fullscreen');
  moveBg(on);
  setTimeout(()=>{ if(T.resize) T.resize(); },80);
}
document.addEventListener('fullscreenchange',_fsSync);
document.addEventListener('webkitfullscreenchange',_fsSync);
function makeLabel(text,color,scale){ const c=document.createElement('canvas'); const pad=8,fs=34; c.width=512; c.height=96;
  const g=c.getContext('2d'); g.font='bold '+fs+'px Consolas,monospace'; g.fillStyle=color||'#dfe9f5'; g.textBaseline='middle';
  g.shadowColor='rgba(0,0,0,.8)'; g.shadowBlur=6; g.fillText(text,pad,c.height/2);
  const tx=new THREE.CanvasTexture(c); tx.minFilter=THREE.LinearFilter;
  const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:tx,transparent:true,depthWrite:false})); sp.scale.set((scale||1)*70,(scale||1)*13,1); return sp;
}
function nodeMesh(color,label,sub){ const g=new THREE.Group();
  const m=new THREE.Mesh(new THREE.IcosahedronGeometry(22,2), new THREE.MeshStandardMaterial({color,emissive:color,emissiveIntensity:.8,roughness:.3,metalness:.4,flatShading:true})); g.add(m);
  const halo=new THREE.Mesh(new THREE.SphereGeometry(34,20,20), new THREE.MeshBasicMaterial({color,transparent:true,opacity:.12,blending:THREE.AdditiveBlending,depthWrite:false})); g.add(halo);
  const l=makeLabel(label,'#eaf3ff',1.15); l.position.set(0,46,0); g.add(l);
  if(sub){ const s=makeLabel(sub,'#93a8c0',.85); s.position.set(0,32,0); g.add(s); }
  g.userData.core=m; g.userData.halo=halo; return g;
}

function clearScene(){ while(T.root.children.length) T.root.remove(T.root.children[0]); GATES=[]; PKT=null; TRAIL=null; WP=[]; RES=null; done=false; }

function buildScene(tr){
  clearScene();
  const steps=tr.steps||[]; const N=steps.length;
  const accept=(tr.kind==='accept');
  const endX=(N>0?(N-1)*GAP:0);
  // conduit line
  const cg=new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(-150,0,0),new THREE.Vector3(endX+ (accept?200:60),0,0)]);
  T.root.add(new THREE.Line(cg,new THREE.LineBasicMaterial({color:0x1d3346,transparent:true,opacity:.5})));
  // SRC / DST nodes — DST shows the EFFECTIVE (post-NAT) destination when NAT rewrote it
  const srcIp=document.getElementById('p-src').value.trim()||'src';
  const formDst=document.getElementById('p-dst').value.trim()||'dst';
  const effDst=(tr.effective&&tr.effective.dst)?tr.effective.dst:formDst;
  const dstIp=(effDst&&effDst!==formDst)?(effDst+'  (NAT←'+formDst+')'):formDst;
  const src=nodeMesh(0x4da3ff,'SRC',srcIp); src.position.set(-150,0,0); T.root.add(src);
  let dst=null;
  if(accept){ dst=nodeMesh(0x2ee66e,'DST',dstIp); dst.position.set(endX+200,0,0); dst.userData.dim=true; T.root.add(dst); T.dst=dst; }
  else T.dst=null;
  // gates
  steps.forEach((s,i)=>{ const x=i*GAP; const isNat=(s.kind==='nat'); const isDropAct=['drop','reject','tarpit'].includes(s.action);
    let col=0x37485c, op=.5, tube=1.4, glow=false;
    if(isNat){ col=0xc084fc; op=1; tube=2.6; glow=true; }                 // NAT gate = purple
    else if(s.terminal){ col=isDropAct?0xff5a5a:0x2ee66e; op=1; tube=3; glow=true; }
    else if(s.matched){ col=0xf0a92c; op=.9; tube=2.2; glow=true; }
    const ring=new THREE.Mesh(new THREE.TorusGeometry(GATE_R,tube,10,40), new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:glow?.8:.25,roughness:.4,metalness:.3,transparent:true,opacity:op}));
    ring.rotation.y=Math.PI/2; ring.position.set(x,0,0); T.root.add(ring);
    let disc=null;
    if(s.terminal && isDropAct){ disc=new THREE.Mesh(new THREE.CircleGeometry(GATE_R-2,40), new THREE.MeshBasicMaterial({color:0xff5a5a,transparent:true,opacity:.16,side:THREE.DoubleSide,blending:THREE.AdditiveBlending,depthWrite:false})); disc.rotation.y=Math.PI/2; disc.position.set(x,0,0); T.root.add(disc); }
    // labels
    let topTxt, topCol, subTxt, subCol;
    if(isNat){ topTxt=(s.stage==='dstnat'?'⇄ DST-NAT':'⇄ SRC-NAT')+' #'+s.idx; topCol='#e2c6ff'; subTxt=s.transform||s.action; subCol='#c9a8f0'; }
    else { topTxt='#'+s.idx+' '+s.action; topCol=s.terminal?(isDropAct?'#ffb0b0':'#8ff0b6'):(s.matched?'#ffd98a':'#6f7c90'); subTxt=s.miss?('flew past · '+s.miss):s.summary.slice(0,30); subCol=s.matched?'#9fb2c8':'#5c6a7e'; }
    const lab=makeLabel(topTxt, topCol, .9); lab.position.set(x,44,0); if(!isNat && !s.matched) lab.material.opacity=.6; T.root.add(lab);
    const sub=makeLabel((subTxt||'').slice(0,36), subCol, .7); sub.position.set(x,31,0); if(!isNat && !s.matched) sub.material.opacity=.45; T.root.add(sub);
    GATES.push({mesh:ring,disc,x,step:s,i,flash:0,drop:isDropAct,nat:isNat});
  });
  // packet + trail
  PKT=new THREE.Mesh(new THREE.SphereGeometry(7,20,20), new THREE.MeshStandardMaterial({color:0xbfeaff,emissive:0x6fd8ff,emissiveIntensity:1.4,roughness:.2,metalness:.3}));
  PKT.position.set(-150,0,0); T.root.add(PKT);
  const ph=new THREE.Mesh(new THREE.SphereGeometry(13,16,16), new THREE.MeshBasicMaterial({color:0x6fd8ff,transparent:true,opacity:.28,blending:THREE.AdditiveBlending,depthWrite:false})); PKT.add(ph);
  TRAIL=makeTrail();
  // waypoints: SRC → each gate → (DST if accept)
  WP=[{pos:new THREE.Vector3(-150,0,0),kind:'src'}];
  steps.forEach((s,i)=>WP.push({pos:new THREE.Vector3(i*GAP,0,0),kind:'gate',step:s,i}));
  if(accept) WP.push({pos:new THREE.Vector3(endX+200,0,0),kind:'dst'});
  RES={kind:tr.kind,verdict:tr.verdict,decided:tr.decided_by,hints:tr.hints||[]};
  legI=0; legT=0; dwell=0; STATE='play'; done=false;
  document.getElementById('hint').style.display='none';
  document.getElementById('playbar').style.display='flex';
  document.getElementById('verdict').style.display='none';
  setPP(true);
}
function makeTrail(){ const N=42; const g=new THREE.BufferGeometry(); const pos=new Float32Array(N*3);
  for(let i=0;i<N;i++){ pos[i*3]=-150; } g.setAttribute('position',new THREE.BufferAttribute(pos,3));
  const line=new THREE.Line(g,new THREE.LineBasicMaterial({color:0x6fd8ff,transparent:true,opacity:.5,blending:THREE.AdditiveBlending,depthWrite:false}));
  line.userData={pos,N}; T.root.add(line); return line;
}
function pushTrail(p){ if(!TRAIL)return; const {pos,N}=TRAIL.userData; for(let i=N-1;i>0;i--){ pos[i*3]=pos[(i-1)*3]; pos[i*3+1]=pos[(i-1)*3+1]; pos[i*3+2]=pos[(i-1)*3+2]; }
  pos[0]=p.x; pos[1]=p.y; pos[2]=p.z; TRAIL.geometry.attributes.position.needsUpdate=true; }

// ── animation ──
let SPEED=1;
function animate(){ requestAnimationFrame(animate); if(!T.rn)return; T.ct+=0.016; SPEED=+document.getElementById('spd').value||1;
  // gate idle spin + flashes
  GATES.forEach(g=>{ g.mesh.rotation.x+=0.01; if(g.flash>0){ g.flash-=0.05; g.mesh.material.emissiveIntensity=(g.step.matched?0.8:0.25)+g.flash*2.2; g.mesh.scale.setScalar(1+g.flash*0.5);} });
  if(PKT){ PKT.children[0] && (PKT.children[0].scale.setScalar(1+Math.sin(T.ct*6)*0.12)); }
  if(STATE==='play' && WP.length>1){ stepAnim(); }
  // camera follow the packet while playing
  if(PKT && (STATE==='play')){ T.follow.lerp(PKT.position,0.08);
    const desired=new THREE.Vector3(PKT.position.x-70,150,250); T.cam.position.lerp(desired,0.05); T.ctr.target.lerp(T.follow,0.1); }
  // pulse dst if accepted+lit
  if(T.dst && !T.dst.userData.dim){ const s=1+Math.sin(T.ct*3)*0.08; T.dst.userData.halo.scale.setScalar(s); }
  T.ctr.update(); T.rn.render(T.sc,T.cam);
}
function stepAnim(){
  if(dwell>0){ dwell-=0.016*SPEED; if(dwell<=0) advanceLeg(); return; }
  const a=WP[legI].pos, b=WP[legI+1] && WP[legI+1].pos; if(!b){ finish(); return; }
  const dur=0.5; legT+=0.016*SPEED/dur;
  const t=Math.min(1,legT); const e=t<.5?2*t*t:1-Math.pow(-2*t+2,2)/2;   // ease in-out
  PKT.position.lerpVectors(a,b,e); pushTrail(PKT.position);
  if(t>=1){ arriveAt(legI+1); }
}
function arriveAt(idx){ const wp=WP[idx]; legT=0;
  if(wp.kind==='gate'){ const g=GATES[wp.i]; g.flash=1; highlightStep(wp.i);
    dwell=(wp.step.terminal?0.55:0.26);   // pause to "evaluate" the rule (terminal lingers)
  } else if(wp.kind==='dst'){ finish(); }
  else advanceLeg();
}
function advanceLeg(){ // called after the evaluate-dwell at the gate we just reached (WP[legI+1])
  const arrived=WP[legI+1];
  if(arrived && arrived.kind==='gate' && arrived.step.terminal && GATES[arrived.i] && GATES[arrived.i].drop){
    finish(); return;              // terminal DROP → the packet stops dead at this red gate
  }
  legI++; legT=0;                  // otherwise continue (a terminal ACCEPT passes THROUGH to DST)
  if(legI>=WP.length-1){ finish(); }
}
function finish(){ if(done)return; done=true; STATE='done'; setPP(true,true);
  const acc=(RES.kind==='accept');
  if(acc && T.dst){ T.dst.userData.dim=false; T.dst.userData.core.material.emissiveIntensity=1.4; }
  // explosion for drop
  if(!acc && PKT){ burst(PKT.position, 0xff5a5a); PKT.visible=false; }
  const vb=document.getElementById('verdict'); vb.style.display='block';
  document.getElementById('v-txt').innerHTML=(acc?'✅ ':'⛔ ')+esc(RES.verdict);
  document.getElementById('v-txt').style.color=acc?'#8ff0b6':'#ffb0b0';
  const sub=RES.decided!=null?('decided by rule #'+RES.decided):'no matching rule — default policy';
  const hints=(RES.hints||[]).map(h=>{ const c=h.kind==='chain'?'#f0a92c':'#c084fc'; const ic=h.kind==='chain'?'fa-diagram-project':'fa-shuffle';
    return `<div style="margin-top:8px;text-align:left;font-size:11.5px;line-height:1.5;color:${h.kind==='chain'?'#ffd98a':'#e2c6ff'};background:rgba(255,255,255,.04);border:1px solid var(--border);border-left:3px solid ${c};border-radius:8px;padding:8px 11px"><i class="fa-solid ${ic}" style="color:${c}"></i> ${esc(h.text)}</div>`; }).join('');
  document.getElementById('v-sub').innerHTML=sub+hints;
}
function burst(pos,color){ const N=60; const g=new THREE.BufferGeometry(); const p=new Float32Array(N*3); const v=[];
  for(let i=0;i<N;i++){ p[i*3]=pos.x;p[i*3+1]=pos.y;p[i*3+2]=pos.z; const dir=new THREE.Vector3(Math.random()-.5,Math.random()-.5,Math.random()-.5).normalize().multiplyScalar(1.2+Math.random()*2.4); v.push(dir); }
  g.setAttribute('position',new THREE.BufferAttribute(p,3));
  const pts=new THREE.Points(g,new THREE.PointsMaterial({color,size:4,transparent:true,opacity:1,blending:THREE.AdditiveBlending,depthWrite:false})); T.root.add(pts);
  let life=1; const tick=()=>{ life-=0.02; if(life<=0){ T.root.remove(pts); pts.geometry.dispose(); return; }
    const arr=g.attributes.position.array; for(let i=0;i<N;i++){ arr[i*3]+=v[i].x; arr[i*3+1]+=v[i].y; arr[i*3+2]+=v[i].z; } g.attributes.position.needsUpdate=true; pts.material.opacity=life; requestAnimationFrame(tick); };
  tick();
}

// ── step log ──
function renderSteps(tr){ const el=document.getElementById('steps');
  el.innerHTML=(tr.steps||[]).map((s,i)=>{
    if(s.kind==='nat'){ return `<div class="st" id="st-${i}" style="border-left-color:#c084fc"><span class="si" style="color:#c9a8f0">${s.idx}</span><span class="sa" style="background:rgba(192,132,252,.2);color:#e2c6ff">${s.stage==='dstnat'?'dst-nat':'src-nat'}</span>
      <span class="sm" style="color:#d9c6f0">${esc(s.transform||s.action)}</span></div>`; }
    const cls=s.terminal?(tr.kind==='drop'||['drop','reject','tarpit'].includes(s.action)?'drop':'accept'):(s.matched?'match':'miss');
    return `<div class="st ${cls}" id="st-${i}"><span class="si">${s.idx}</span><span class="sa">${esc(s.action)}</span>
      <span class="sm">${esc(s.summary)}${s.matched?'':' <span class="why">✕ '+esc(s.miss)+'</span>'}${s.note?' <span class="why">'+esc(s.note)+'</span>':''}</span></div>`; }).join('')
    || '<div class="dim" style="padding:8px">No rules evaluated in this chain.</div>'; }
function highlightStep(i){ document.querySelectorAll('.st.cur').forEach(e=>e.classList.remove('cur'));
  const el=document.getElementById('st-'+i); if(el){ el.classList.add('cur'); el.scrollIntoView({block:'nearest',behavior:'smooth'}); } }

// ── controls ──
function setPP(playing,ended){ const b=document.getElementById('pp'); b.innerHTML=ended?'<i class="fa-solid fa-check"></i>':(playing?'<i class="fa-solid fa-pause"></i>':'<i class="fa-solid fa-play"></i>'); }
function togglePlay(){ if(done)return; STATE=(STATE==='play')?'pause':'play'; setPP(STATE==='play'); }
function replay(){ if(!RES){return;} PKT&&(PKT.visible=true); legI=0; legT=0; dwell=0; done=false; STATE='play';
  document.getElementById('verdict').style.display='none'; if(T.dst){ T.dst.userData.dim=true; T.dst.userData.core.material.emissiveIntensity=.8; }
  document.querySelectorAll('.st.cur').forEach(e=>e.classList.remove('cur')); setPP(true); }

async function runTrace(){
  NODE=+document.getElementById('node').value||0; const err=document.getElementById('ferr'); err.textContent='';
  if(!NODE){ err.innerHTML='<span style="color:#ffb0b0">Select a router first.</span>'; return; }
  const inif=document.getElementById('p-inif').value.trim();
  const pkt={chain:document.getElementById('p-chain').value,protocol:document.getElementById('p-proto').value,
    src:document.getElementById('p-src').value.trim(),dst:document.getElementById('p-dst').value.trim(),
    dst_port:document.getElementById('p-dport').value.trim(),state:document.getElementById('p-state').value};
  if(inif){ pkt.in_if=inif; const ifObj=IFACES.find(i=>i.name===inif); pkt.in_if_lists=ifObj?ifObj.lists:[]; }
  // (no in_if picked ⇒ omit in_if_lists so interface-list rules stay unresolved/wildcard)
  err.innerHTML='<i class="fa-solid fa-spinner fa-spin"></i> Reading live rules over SSH…';
  const d=await fetch('mtfw.php?api=trace&node='+NODE,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pkt})}).then(r=>r.json()).catch(()=>null);
  if(!d||!d.ok){ err.innerHTML='<span style="color:#ffb0b0">'+esc((d&&d.error)||'trace failed')+'</span>'; return; }
  err.textContent='';
  renderSteps(d); buildScene(d);
}

window.addEventListener('DOMContentLoaded',()=>{ initThree(); loadRouters(); if(window.NMLoader)NMLoader.hide(); });
</script>
</body></html>
