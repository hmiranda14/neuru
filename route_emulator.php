<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — MikroTik ROUTING EMULATOR. A full-screen 3D A→B forwarding trace: a
// packet travels the router's real pipeline — SOURCE → ingress → dst-nat → ROUTE
// decision → filter → src-nat → egress → DEST — considering the live routing table,
// NAT and firewall, and halts (red) at the exact stage that drops/blackholes it or
// arrives (green) at the destination. Read-only. RBAC: 'mtfw'.
// Data: mtfw.php?api=routers | ?api=route_emulate  (engine nm_mtfw_route_emulate).
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
include('logger.php');
if (!checkAccess($conn, 'mtfw')) { header('Location: /denied_access.php?page=mtfw'); exit; }
$initNode = (int)($_GET['node'] ?? 0);
log_user_action($conn, 'view_page', 'route_emulator.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="three.min.js"></script>
<script src="three-orbitcontrols.js"></script>
<style>
:root{ --glass:rgba(11,16,27,.72); --border:rgba(255,255,255,.12); --accent:#4da3ff; --cyan:#36e3d0; --ok:#2ee66e; --warn:#f0a92c; --crit:#ff5a5a; }
html{ background:#05080f; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#d4dce8; }
<?= nm_chrome_css() ?>
.tw{ max-width:1620px; margin:0 auto; padding:16px 20px 30px; }
.tbar{ display:flex; align-items:center; gap:14px; padding:12px 16px; margin-bottom:14px; flex-wrap:wrap;
  background:var(--glass); backdrop-filter:blur(13px); border:1px solid var(--border); border-radius:14px; }
.tbar .ttl{ font-size:18px; font-weight:800; display:flex; align-items:center; gap:10px; } .tbar .ttl i{ color:#c084fc; }
.tbar select,.tbar a.back{ background:rgba(0,0,0,.35); border:1px solid var(--border); color:#e6edf7; border-radius:9px; padding:8px 12px; font-size:13px; text-decoration:none; cursor:pointer; }
.tbar a.back:hover{ border-color:var(--accent); color:#fff; }
#stage{ position:relative; height:80vh; min-height:620px; border-radius:16px; overflow:hidden; border:1px solid var(--border);
  background:radial-gradient(circle at 50% 34%,rgba(30,26,64,.42),rgba(5,8,15,.96) 72%); }
#stage:fullscreen,#stage:-webkit-full-screen{ height:100vh!important; width:100vw!important; border-radius:0; border:none; }
#rcanvas{ position:absolute; inset:0; width:100%; height:100%; display:block; z-index:1; }
#stage:fullscreen #nm-netbg,#stage:-webkit-full-screen #nm-netbg{ z-index:0!important; }
.panel{ position:absolute; background:rgba(8,12,22,.84); backdrop-filter:blur(12px); border:1px solid var(--border); border-radius:13px; z-index:4; }
#form{ top:14px; left:14px; width:300px; padding:14px 15px; }
#form h3{ margin:0 0 10px; font-size:13px; font-weight:800; display:flex; align-items:center; gap:8px; } #form h3 i{ color:#c084fc; }
.frow{ display:grid; grid-template-columns:1fr 1fr; gap:8px; }
label{ display:block; font-size:10px; text-transform:uppercase; letter-spacing:.4px; color:#8b95a7; margin:8px 0 3px; }
.inp{ width:100%; background:rgba(0,0,0,.35); border:1px solid var(--border); color:#e6edf7; border-radius:8px; padding:7px 9px; font-size:12.5px; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:8px 12px; font-size:13px; cursor:pointer; }
.btn:hover{ border-color:var(--accent); color:#fff; } .btn.g{ background:linear-gradient(135deg,#c084fc,#4da3ff); border:none; color:#fff; font-weight:700; }
.btn.sm{ padding:6px 9px; font-size:12px; }
#playbar{ display:flex; align-items:center; gap:7px; margin-top:11px; }
#playbar input[type=range]{ flex:1; accent-color:#c084fc; }
#verdict{ top:14px; left:50%; transform:translateX(-50%); padding:11px 22px; text-align:center; display:none; min-width:280px; }
#verdict .v{ font-size:19px; font-weight:800; } #verdict .s{ font-size:11.5px; color:#9fb0c2; margin-top:2px; }
#route{ bottom:14px; left:50%; transform:translateX(-50%); padding:10px 18px; display:none; max-width:80%; }
#route .rk{ font-size:9px; font-weight:800; text-transform:uppercase; letter-spacing:.8px; color:#8b95a7; }
#route .rv{ font-size:13px; color:#e6edf7; margin-top:2px; } #route .rv b{ color:#c0a5ff; } #route .rv .mono{ font-family:Consolas,monospace; color:#bff2d2; }
#log{ top:14px; right:14px; width:330px; max-height:calc(80vh - 28px); padding:12px 6px 12px 12px; display:flex; flex-direction:column; }
#log h3{ margin:0 0 8px; font-size:12px; font-weight:800; color:#cfe0f7; text-transform:uppercase; letter-spacing:.6px; }
#steps{ overflow:auto; padding-right:6px; }
.st{ display:flex; align-items:center; gap:9px; padding:7px 9px; border-radius:8px; margin-bottom:5px; font-size:12px;
  border:1px solid var(--border); border-left:3px solid #46516a; background:rgba(255,255,255,.02); }
.st.miss{ opacity:.5; } .st.match{ border-left-color:#f0a92c; } .st.accept{ border-left-color:#2ee66e; } .st.drop{ border-left-color:#ff5a5a; } .st.nat{ border-left-color:#c084fc; }
.st .sa{ font-size:9px; font-weight:800; text-transform:uppercase; padding:2px 6px; border-radius:5px; background:rgba(255,255,255,.08); }
.st.accept .sa{ background:rgba(46,230,110,.2); color:#8ff0b6; } .st.drop .sa{ background:rgba(255,90,90,.2); color:#ffb0b0; } .st.match .sa{ background:rgba(240,169,44,.2); color:#ffd98a; } .st.nat .sa{ background:rgba(192,132,252,.2); color:#d9bcff; }
.st .sm{ flex:1; min-width:0; font-family:Consolas,monospace; font-size:10.5px; color:#b9c4d4; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
#hints{ padding:0 6px 6px 12px; } .hcall{ font-size:11px; border-radius:8px; padding:8px 10px; margin-top:7px; border:1px solid; line-height:1.5; }
.hcall.chain{ background:rgba(240,169,44,.1); border-color:rgba(240,169,44,.4); color:#f0c98a; } .hcall.nat{ background:rgba(192,132,252,.1); border-color:rgba(192,132,252,.4); color:#d9bcff; }
.muted{ color:#8b95a7; font-size:12px; } .dim{ color:#6f7a8c; }
#hint{ position:absolute; inset:0; display:flex; align-items:center; justify-content:center; flex-direction:column; gap:12px; z-index:3; pointer-events:none; color:#6f7c90; }
#hint i{ font-size:46px; color:#3a2a5e; }
@media(max-width:1150px){ #log{ display:none; } #form{ width:270px; } }
</style>

<?php include('header.php'); ?>
<div class="tw">
  <div class="tbar">
    <div class="ttl"><i class="fa-solid fa-route"></i> MikroTik Routing Emulator</div>
    <select id="node" onchange="onNode()"><option value="">Select a router…</option></select>
    <span style="flex:1"></span>
    <a class="back" id="fsbtn" onclick="toggleFs()"><i class="fa-solid fa-expand"></i> Fullscreen</a>
    <a class="back" href="mtfw.php"><i class="fa-solid fa-arrow-left"></i> Firewall Control</a>
  </div>

  <div id="stage">
    <canvas id="rcanvas"></canvas>

    <div class="panel" id="form">
      <h3><i class="fa-solid fa-diagram-project"></i> Trace A → B</h3>
      <label>Source IP (A)</label><input class="inp" id="p-src" placeholder="192.168.0.100">
      <label>Destination IP (B)</label><input class="inp" id="p-dst" placeholder="8.8.8.8">
      <div class="frow">
        <div><label>Protocol</label><select class="inp" id="p-proto"><option value="tcp">tcp</option><option value="udp" selected>udp</option><option value="icmp">icmp</option><option value="">any</option></select></div>
        <div><label>Dst port</label><input class="inp" id="p-dport" placeholder="53"></div>
      </div>
      <div class="frow">
        <div><label>Conn-state</label><select class="inp" id="p-state"><option selected>new</option><option>established</option><option>related</option></select></div>
        <div><label>Src port</label><input class="inp" id="p-sport" placeholder="(any)"></div>
      </div>
      <button class="btn g" style="width:100%;margin-top:12px;" onclick="runEmu()"><i class="fa-solid fa-play"></i> Emulate route</button>
      <div id="playbar" style="display:none;">
        <button class="btn sm" onclick="replay()" title="Replay"><i class="fa-solid fa-rotate-left"></i></button>
        <input type="range" id="spd" min="0.4" max="3" step="0.1" value="1" oninput="SPD=+this.value;document.getElementById('spdl').textContent=this.value+'x'">
        <span class="muted" id="spdl" style="min-width:30px">1x</span>
      </div>
      <div class="muted" id="ferr" style="margin-top:9px;"></div>
      <div class="dim" style="font-size:10.5px;line-height:1.5;margin-top:10px;border-top:1px solid rgba(255,255,255,.07);padding-top:9px;">
        <i class="fa-solid fa-circle-info"></i> Full forwarding path on ONE router: ingress → <b>dst-nat</b> → <b>routing decision</b> (real route table) → <b>forward filter</b> → <b>src-nat</b> → egress. Stops at whatever drops/blackholes it, or reaches B.
      </div>
    </div>

    <div class="panel" id="verdict"><div class="v" id="v-txt"></div><div class="s" id="v-sub"></div></div>
    <div class="panel" id="route"><div class="rk">Routing decision</div><div class="rv" id="r-txt"></div></div>

    <div class="panel" id="log">
      <h3>Pipeline trace</h3>
      <div id="steps"><div class="dim" style="padding:8px">Enter A and B, press <b>Emulate</b>.</div></div>
      <div id="hints"></div>
    </div>

    <div id="hint"><i class="fa-solid fa-route"></i><div>Pick a router, enter source & destination, watch the packet route A→B.</div></div>
  </div>
</div>

<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const INIT_NODE=<?= json_encode($initNode) ?>;
let NODE=0, RES=null, SPD=1;
const STAGES=[
  {key:'src',   label:'SOURCE'},
  {key:'in',    label:'INGRESS'},
  {key:'dstnat',label:'DST-NAT'},
  {key:'route', label:'ROUTE'},
  {key:'filter',label:'FILTER'},
  {key:'srcnat',label:'SRC-NAT'},
  {key:'out',   label:'EGRESS'},
  {key:'dst',   label:'DEST'}
];
const GAP=70;

async function loadRouters(){
  const d=await fetch('mtfw.php?api=routers').then(r=>r.json()).catch(()=>null);
  const sel=document.getElementById('node'); if(!d||!d.ok) return;
  sel.innerHTML='<option value="">Select a router…</option>'+d.routers.map(r=>`<option value="${r.id}">${esc(r.name)} (${esc(r.ip)})</option>`).join('');
  if(INIT_NODE){ sel.value=INIT_NODE; NODE=INIT_NODE; }
}
function onNode(){ NODE=+document.getElementById('node').value||0; }

// ── three.js pipeline scene ──
let scene,cam,renderer,controls,rings=[],labels=[],conduit,packet,glow,raf=0;
const stageX=i=>(i-(STAGES.length-1)/2)*GAP;
function makeLabel(text,sub,color){
  const c=document.createElement('canvas'); c.width=340; c.height=120; const x=c.getContext('2d');
  x.fillStyle=color||'#cfe0f7'; x.font='bold 30px Segoe UI, sans-serif'; x.textAlign='center';
  x.fillText(text,170,40);
  if(sub){ x.fillStyle='#9fb0c2'; x.font='22px Consolas, monospace'; const s=sub.length>26?sub.slice(0,25)+'…':sub; x.fillText(s,170,78); }
  const tex=new THREE.CanvasTexture(c); tex.needsUpdate=true;
  const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:tex,transparent:true,depthTest:false}));
  sp.scale.set(52,18,1); return sp;
}
function initScene(){
  const cv=document.getElementById('rcanvas');
  scene=new THREE.Scene();
  cam=new THREE.PerspectiveCamera(52, cv.clientWidth/cv.clientHeight, 0.1, 3000);
  cam.position.set(0,40,300);
  renderer=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true});
  renderer.setPixelRatio(Math.min(devicePixelRatio,2));
  resize();
  controls=new THREE.OrbitControls(cam,renderer.domElement); controls.enableDamping=true; controls.dampingFactor=.08; controls.minDistance=120; controls.maxDistance=700;
  scene.add(new THREE.AmbientLight(0x8899bb,0.7));
  const pl=new THREE.PointLight(0xffffff,0.8); pl.position.set(0,120,180); scene.add(pl);
  // conduit
  const pts=STAGES.map((s,i)=>new THREE.Vector3(stageX(i),0,0));
  conduit=new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), new THREE.LineBasicMaterial({color:0x2a3550,transparent:true,opacity:.6}));
  scene.add(conduit);
  // stage rings + labels
  STAGES.forEach((s,i)=>{
    const isEnd=(i===0||i===STAGES.length-1);
    const geo=isEnd?new THREE.IcosahedronGeometry(11,1):new THREE.TorusGeometry(12,2.4,16,40);
    const m=new THREE.Mesh(geo,new THREE.MeshStandardMaterial({color:0x2b3a5a,emissive:0x0a1626,metalness:.5,roughness:.35,transparent:true,opacity:.95}));
    m.position.set(stageX(i),0,0); if(!isEnd)m.rotation.y=Math.PI/2; scene.add(m); rings.push(m);
    const lab=makeLabel(s.label,'',isEnd?'#8ff0b6':'#cfe0f7'); lab.position.set(stageX(i),24,0); scene.add(lab); labels.push(lab);
  });
  // packet
  packet=new THREE.Mesh(new THREE.SphereGeometry(4.6,24,24), new THREE.MeshStandardMaterial({color:0x36e3d0,emissive:0x0c6b60,emissiveIntensity:1.4}));
  glow=new THREE.Sprite(new THREE.SpriteMaterial({map:glowTex(),color:0x36e3d0,transparent:true,opacity:.9,depthTest:false}));
  glow.scale.set(30,30,1); packet.add(glow);
  packet.position.set(stageX(0),0,0); packet.visible=false; scene.add(packet);
  window.addEventListener('resize',resize);
  loop();
}
function glowTex(){ const c=document.createElement('canvas'); c.width=c.height=128; const x=c.getContext('2d');
  const g=x.createRadialGradient(64,64,0,64,64,64); g.addColorStop(0,'rgba(255,255,255,.9)'); g.addColorStop(.3,'rgba(120,240,220,.5)'); g.addColorStop(1,'rgba(0,0,0,0)');
  x.fillStyle=g; x.fillRect(0,0,128,128); const t=new THREE.CanvasTexture(c); return t; }
function resize(){ const cv=document.getElementById('rcanvas'); const w=cv.clientWidth||cv.parentElement.clientWidth, h=cv.clientHeight||cv.parentElement.clientHeight;
  renderer.setSize(w,h,false); cam.aspect=w/h; cam.updateProjectionMatrix(); }
// ── animation (consistent with the Packet Tracer: trail + ease-in-out + camera-follow + gate flash + burst) ──
let anim=null, TRAIL=null, camFollow=new THREE.Vector3();
function loop(){ raf=requestAnimationFrame(loop); const t=performance.now()/1000;
  rings.forEach((r,i)=>{ if(r.geometry.type==='TorusGeometry') r.rotation.z=t*0.6+i;
    const f=r.userData.flash||0; if(f>0){ r.userData.flash=f-0.05; r.material.emissiveIntensity=.6+f*2.4; r.scale.setScalar(1+f*0.45); }
    else if(r.userData.pulse){ r.scale.setScalar(1+Math.sin(t*3)*0.1); } else r.scale.setScalar(1); });
  if(glow) glow.material.rotation=t;
  if(packet&&packet.visible) packet.scale.setScalar(1+Math.sin(t*6)*0.12);
  animatePacket();
  if(anim&&!anim.done&&packet.visible){ camFollow.lerp(packet.position,0.08);
    cam.position.lerp(new THREE.Vector3(packet.position.x-25,42,300),0.04); controls.target.lerp(camFollow,0.1); }
  controls&&controls.update(); renderer&&renderer.render(scene,cam);
}
function setStageLabel(i,sub,color){ const s=STAGES[i]; scene.remove(labels[i]); const lab=makeLabel(s.label,sub,color); lab.position.set(stageX(i),24,0); scene.add(lab); labels[i]=lab; }
function colorStage(i,hex){ if(!rings[i])return; rings[i].material.color.setHex(hex); rings[i].material.emissive.setHex(hex); rings[i].material.emissiveIntensity=.6; }
function resetStages(){ rings.forEach(r=>{ r.material.color.setHex(0x2b3a5a); r.material.emissive.setHex(0x0a1626); r.userData.flash=0; r.userData.pulse=false; }); }
function makeTrail(){ const N=42,g=new THREE.BufferGeometry(),pos=new Float32Array(N*3); for(let i=0;i<N;i++)pos[i*3]=stageX(0);
  g.setAttribute('position',new THREE.BufferAttribute(pos,3));
  const line=new THREE.Line(g,new THREE.LineBasicMaterial({color:0x36e3d0,transparent:true,opacity:.5,blending:THREE.AdditiveBlending,depthWrite:false}));
  line.userData={pos,N}; scene.add(line); return line; }
function pushTrail(p){ if(!TRAIL)return; const {pos,N}=TRAIL.userData; for(let i=N-1;i>0;i--){pos[i*3]=pos[(i-1)*3];pos[i*3+1]=pos[(i-1)*3+1];pos[i*3+2]=pos[(i-1)*3+2];} pos[0]=p.x;pos[1]=p.y;pos[2]=p.z; TRAIL.geometry.attributes.position.needsUpdate=true; }
function startAnim(stopIdx,ok){ if(TRAIL){scene.remove(TRAIL);TRAIL=null;} TRAIL=makeTrail();
  anim={leg:0,stop:stopIdx,ok:ok,t:0,dwell:0,done:false};
  packet.visible=true; packet.position.set(stageX(0),0,0);
  packet.material.color.setHex(0x36e3d0); packet.material.emissive.setHex(0x0c6b60); glow.material.color.setHex(0x36e3d0); }
function animatePacket(){ if(!anim||anim.done) return; const dt=0.016*SPD;
  if(anim.dwell>0){ anim.dwell-=dt; if(anim.dwell<=0){ anim.leg++; anim.t=0; } return; }   // dwell over → advance to travel from the arrived stage
  const a=stageX(anim.leg), b=stageX(anim.leg+1); anim.t+=dt/0.5;
  const t=Math.min(1,anim.t), e=t<.5?2*t*t:1-Math.pow(-2*t+2,2)/2;
  packet.position.x=a+(b-a)*e; pushTrail(packet.position);
  if(t>=1){ const idx=anim.leg+1; if(rings[idx])rings[idx].userData.flash=1;
    colorStage(idx, (idx===anim.stop&&!anim.ok)?0xff5a5a:0x36e3d0);
    if(idx>=anim.stop){ finishAnim(); return; }   // ARRIVED at the stop stage → finish here (no overshoot)
    anim.dwell=0.28; }
}
function finishAnim(){ if(!anim)return; anim.done=true; const ok=anim.ok, stop=anim.stop;
  if(ok){ colorStage(STAGES.length-1,0x2ee66e); rings[STAGES.length-1].userData.pulse=true;
    packet.material.color.setHex(0x2ee66e); packet.material.emissive.setHex(0x0a5a26); glow.material.color.setHex(0x2ee66e); packet.position.x=stageX(STAGES.length-1); }
  else { colorStage(stop,0xff5a5a); burst(new THREE.Vector3(stageX(stop),0,0),0xff5a5a); packet.visible=false; if(TRAIL)TRAIL.material.color.setHex(0xff5a5a); }
}
function burst(pos,color){ const N=60,g=new THREE.BufferGeometry(),p=new Float32Array(N*3),v=[];
  for(let i=0;i<N;i++){p[i*3]=pos.x;p[i*3+1]=pos.y;p[i*3+2]=pos.z;v.push(new THREE.Vector3(Math.random()-.5,Math.random()-.5,Math.random()-.5).normalize().multiplyScalar(1+Math.random()*2.2));}
  g.setAttribute('position',new THREE.BufferAttribute(p,3));
  const pts=new THREE.Points(g,new THREE.PointsMaterial({color,size:3.6,transparent:true,opacity:1,blending:THREE.AdditiveBlending,depthWrite:false})); scene.add(pts);
  let life=1; (function tick(){ life-=0.02; if(life<=0){scene.remove(pts);pts.geometry.dispose();return;} const arr=g.attributes.position.array; for(let i=0;i<N;i++){arr[i*3]+=v[i].x;arr[i*3+1]+=v[i].y;arr[i*3+2]+=v[i].z;} g.attributes.position.needsUpdate=true; pts.material.opacity=life; requestAnimationFrame(tick); })(); }

// ── run ──
async function runEmu(){
  if(!NODE){ document.getElementById('ferr').textContent='Select a router first.'; return; }
  const src=document.getElementById('p-src').value.trim(), dst=document.getElementById('p-dst').value.trim();
  if(!src||!dst){ document.getElementById('ferr').textContent='Enter both source and destination IP.'; return; }
  document.getElementById('ferr').textContent='Tracing…';
  const pkt={ src, dst, protocol:document.getElementById('p-proto').value,
    dst_port:document.getElementById('p-dport').value.trim(), src_port:document.getElementById('p-sport').value.trim(),
    state:document.getElementById('p-state').value };   // keys MUST match nm_mtfw_trace ($pkt['state'], dst_port…)
  const d=await fetch('mtfw.php?api=route_emulate&node='+NODE,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pkt})}).then(r=>r.json()).catch(()=>null);
  if(!d||!d.ok){ document.getElementById('ferr').textContent=(d&&d.error)||'trace failed'; return; }
  document.getElementById('ferr').textContent=''; RES=d; render(d);
}
function replay(){ if(RES) render(RES); }

function render(d){
  document.getElementById('hint').style.display='none';
  document.getElementById('playbar').style.display='flex';
  resetStages();
  // stage sublabels
  setStageLabel(0, d.src, '#8ff0b6');
  setStageLabel(1, d.in_if, '#cfe0f7');
  setStageLabel(2, (d.eff_dst&&d.eff_dst!==d.dst)?('→ '+d.eff_dst):'no change', d.eff_dst!==d.dst?'#d9bcff':'#8b95a7');
  const rt=d.route||{}; const routeBad=['none','blackhole','invalid','unknown'].includes(rt.type);
  setStageLabel(3, routeBad?(rt.type.toUpperCase()):(rt.type+' '+(d.out_if||'?')), routeBad?'#ff9b91':'#c0a5ff');
  setStageLabel(4, (d.kind==='accept')?'accept':(d.verdict||d.kind), (d.kind==='accept')?'#8ff0b6':'#ffb0b0');
  const srcnatStep=(d.steps||[]).find(s=>s.stage==='srcnat'&&s.kind==='nat');
  setStageLabel(5, srcnatStep?(srcnatStep.transform||'masquerade'):'—', srcnatStep?'#d9bcff':'#8b95a7');
  setStageLabel(6, (d.out_if||'?')+(d.next_hop?(' → '+d.next_hop):''), '#cfe0f7');
  setStageLabel(7, d.eff_dst||d.dst, '#8ff0b6');
  // stop stage
  let stopIdx=STAGES.length-1, ok=true;
  if(routeBad){ stopIdx=3; ok=false; }
  else if(d.kind==='drop'||d.kind==='reject'){ stopIdx=4; ok=false; }
  startAnim(stopIdx, ok);
  // verdict
  const v=document.getElementById('verdict'); v.style.display='block';
  const good=(d.kind==='accept'); v.style.borderColor=good?'rgba(46,230,110,.5)':'rgba(255,90,90,.5)';
  document.getElementById('v-txt').textContent=(d.verdict||'').toUpperCase(); document.getElementById('v-txt').style.color=good?'#8ff0b6':'#ffb0b0';
  document.getElementById('v-sub').textContent=good?(d.src+' reaches '+ (d.eff_dst||d.dst)+' via '+(d.out_if||'?')):(d.src+' → '+d.dst+' blocked');
  // route panel
  const rp=document.getElementById('route'); rp.style.display='block';
  document.getElementById('r-txt').innerHTML= routeBad
    ? `<b>${esc(rt.type)}</b> — no forwarding path for <span class="mono">${esc(d.eff_dst||d.dst)}</span>`
    : `<span class="mono">${esc(d.eff_dst||d.dst)}</span> matches <b>${esc(rt.dst||'?')}</b> (${esc(rt.type)}) → out <b>${esc(d.out_if||'?')}</b> · next-hop <span class="mono">${esc(d.next_hop||'—')}</span>`;
  // steps
  const box=document.getElementById('steps'); const steps=d.steps||[];
  box.innerHTML = steps.length ? steps.map(s=>{
    let cls,tag,txt;
    if(s.kind==='nat'){ cls='nat'; tag=(s.stage==='dstnat'?'DST-NAT':'SRC-NAT'); txt=s.transform||s.summary||s.action||''; }
    else { const isDrop=['drop','reject','tarpit'].includes(s.action);
      cls=s.terminal?(isDrop?'drop':'accept'):(s.matched?'match':'miss');
      tag=s.action||''; txt=s.miss?('flew past · '+s.miss):(s.summary||''); }
    return `<div class="st ${cls}"><span class="sa">${esc(tag)}</span><span class="sm">${esc(txt)}</span></div>`;
  }).join('') : '<div class="dim" style="padding:6px">No firewall steps (accepted by default policy).</div>';
  // hints
  const hp=document.getElementById('hints'); const hints=d.hints||[];
  hp.innerHTML=hints.map(h=>`<div class="hcall ${esc(h.kind||'chain')}">${esc(h.text||h.msg||'')}</div>`).join('');
}

// ── fullscreen (reparent particle bg) ──
function toggleFs(){ const s=document.getElementById('stage'); if(!document.fullscreenElement){ s.requestFullscreen&&s.requestFullscreen(); } else { document.exitFullscreen&&document.exitFullscreen(); } }
document.addEventListener('fullscreenchange',()=>{ const bg=document.getElementById('nm-netbg'); const s=document.getElementById('stage');
  if(document.fullscreenElement===s){ if(bg)s.appendChild(bg); } else { if(bg)document.body.appendChild(bg); }
  setTimeout(resize,60); document.getElementById('fsbtn').innerHTML=document.fullscreenElement?'<i class="fa-solid fa-compress"></i> Exit':'<i class="fa-solid fa-expand"></i> Fullscreen'; });

window.addEventListener('DOMContentLoaded',()=>{ loadRouters(); if(window.THREE){ initScene(); } });
</script>
