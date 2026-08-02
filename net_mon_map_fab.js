/* NEURU — Network Map "Fabric" view (Map View 1). A futuristic WebGL scene modeled on the
   Routing Commander: nodes are glowing cores with halos grouped by subnet, links are animated
   conduits whose flowing particles ride the live traffic, orbit to explore, click a node → dossier.
   Self-contained module (window.NMFab). Falls back gracefully if WebGL/THREE is unavailable. */
(function(){
const STC = { up:0x2ee66e, down:0xff5a5a, degraded:0xf0a92c, unknown:0x8592a8 };
const stc = s => STC[(s||'unknown')] ?? STC.unknown;

let renderer, scene, camera, controls, canvas, host, raf=null, onClick=null;
let gNodes, gLinks, nodeMeshes=[], linkFx=[], linkLabels=[], flowPts=[], ray, mouse, built=false, running=false, framed=false, trafficOn=true, spin=true, curById=new Map();

function fmtBps(b){ b=+b||0; if(b<=0) return '0'; const u=['B/s','K','M','G']; let i=0; while(b>=1024&&i<3){b/=1024;i++;} return b.toFixed(b<10&&i>0?1:0)+u[i]; }

// A billboard label at a link's midpoint: interface name + live ↓in / ↑out speeds (like Classic).
function linkLabel(ifname, inR, outR){
  const c=document.createElement('canvas'), x=c.getContext('2d'); c.width=560; c.height=170;
  x.textAlign='center'; x.textBaseline='middle';
  if(ifname){ x.font='600 38px Segoe UI, sans-serif'; x.fillStyle='#9fb6d8'; x.shadowColor='#0a1220'; x.shadowBlur=8; x.fillText(String(ifname).slice(0,20),280,42); }
  x.font='bold 42px Segoe UI, sans-serif'; x.shadowColor='#02060d'; x.shadowBlur=10;
  x.textAlign='right'; x.fillStyle='#4bd6ff'; x.fillText('↓'+fmtBps(inR), 272, 112);
  x.textAlign='left';  x.fillStyle='#39d98a'; x.fillText('↑'+fmtBps(outR), 296, 112);
  const t=new THREE.CanvasTexture(c); t.anisotropy=2;
  const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:t,transparent:true,depthWrite:false,depthTest:false}));
  sp.scale.set(58,17.6,1); sp.visible=trafficOn; return sp;
}

function labelSprite(text, hex){
  const c=document.createElement('canvas'), x=c.getContext('2d'); c.width=512; c.height=128;
  x.font='bold 52px Segoe UI, sans-serif'; x.textAlign='center'; x.textBaseline='middle';
  x.shadowColor=hex; x.shadowBlur=18; x.fillStyle='#eaf2ff'; x.fillText(text,256,64);
  const t=new THREE.CanvasTexture(c); t.anisotropy=2;
  const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:t,transparent:true,depthWrite:false}));
  sp.scale.set(46,11.5,1); return sp;
}

function ready(){ return typeof THREE!=='undefined' && !!renderer; }

function init(hostEl, canvasEl, clickCb){
  host=hostEl; canvas=canvasEl; onClick=clickCb;
  try {
    renderer=new THREE.WebGLRenderer({canvas,antialias:true,alpha:true}); renderer.setClearColor(0x000000,0);
    renderer.setPixelRatio(Math.min(2,window.devicePixelRatio||1));
    scene=new THREE.Scene(); scene.fog=new THREE.FogExp2(0x05080f,0.0016);
    camera=new THREE.PerspectiveCamera(52, 1, 0.1, 4000); camera.position.set(0,120,320);
    controls=new THREE.OrbitControls(camera, canvas); controls.enableDamping=true; controls.dampingFactor=0.08;
    controls.maxDistance=1200; controls.minDistance=40;
    controls.autoRotate=true; controls.autoRotateSpeed=0.32;   // the scene ORBITS (like Routing Commander) — toggle static via setSpin()
    scene.add(new THREE.AmbientLight(0x8899cc,0.95));
    const dl=new THREE.DirectionalLight(0xffffff,0.65); dl.position.set(120,240,160); scene.add(dl);
    const pl=new THREE.PointLight(0xafc4ff,0.6,0); pl.position.set(220,380,300); scene.add(pl);   // key light → defined, glossy spheres
    gLinks=new THREE.Group(); gNodes=new THREE.Group(); scene.add(gLinks); scene.add(gNodes);
    ray=new THREE.Raycaster(); mouse=new THREE.Vector2();
    canvas.addEventListener('click', ev=>{
      const r=canvas.getBoundingClientRect(); mouse.x=((ev.clientX-r.left)/r.width)*2-1; mouse.y=-((ev.clientY-r.top)/r.height)*2+1;
      ray.setFromCamera(mouse,camera); const hit=ray.intersectObjects(nodeMeshes,false);
      if(hit.length && hit[0].object.userData && onClick) onClick(hit[0].object.userData);
    });
    canvas.addEventListener('mousemove', ev=>{ const r=canvas.getBoundingClientRect();
      mouse.x=((ev.clientX-r.left)/r.width)*2-1; mouse.y=-((ev.clientY-r.top)/r.height)*2+1; ray.setFromCamera(mouse,camera);
      canvas.style.cursor=ray.intersectObjects(nodeMeshes,false).length?'pointer':'grab'; });
    window.addEventListener('resize', resize);
    return true;
  } catch(e){ console.error('NMFab init', e); renderer=null; return false; }
}

// 3D layout: subnet clusters arranged on a big ring, nodes on a small ring inside each cluster.
function layout(nodes){
  const groups=new Map();
  nodes.forEach(n=>{ const k=n.net_key||'default'; if(!groups.has(k)) groups.set(k,[]); groups.get(k).push(n); });
  const keys=[...groups.keys()].sort(); const G=keys.length;
  const Rg = Math.max(120, G*46);                    // cluster ring radius
  keys.forEach((k,gi)=>{
    const ga = (gi/G)*Math.PI*2;
    const cx=Math.cos(ga)*Rg, cz=Math.sin(ga)*Rg;
    const arr=groups.get(k), m=arr.length;
    const Rn=Math.max(26, m*10);
    arr.forEach((n,ni)=>{
      const na=(ni/Math.max(1,m))*Math.PI*2;
      n._p={ x: cx + Math.cos(na)*(m>1?Rn:0), y: (Math.sin(na*2)* (m>2?14:0)), z: cz + Math.sin(na)*(m>1?Rn:0) };
    });
  });
  return {groups,keys};
}

function clearScene(){
  nodeMeshes.forEach(m=>{ gNodes.remove(m.parent||m); }); nodeMeshes=[];
  while(gNodes.children.length) gNodes.remove(gNodes.children[0]);
  while(gLinks.children.length) gLinks.remove(gLinks.children[0]);
  linkFx=[]; linkLabels=[]; flowPts=[];
}
function setTraffic(on){ trafficOn=!!on;
  linkLabels.forEach(s=>{ s.visible=trafficOn; });
  flowPts.forEach(p=>{ p.visible=trafficOn; });
}
function clearLinks(){ while(gLinks.children.length) gLinks.remove(gLinks.children[0]); linkFx=[]; linkLabels=[]; flowPts=[]; }
// Build all link conduits + flow particles + interface/speed labels. Reused for the periodic
// rebuild AND for live realtime updates (rebuilds only the links, not the node meshes → no flicker).
function buildLinks(links){
  clearLinks();
  (links||[]).forEach(l=>{
    const s=curById.get(typeof l.source==='object'?l.source.id:l.source), t=curById.get(typeof l.target==='object'?l.target.id:l.target);
    if(!s||!t||!s._p||!t._p) return;
    const a=new THREE.Vector3(s._p.x,s._p.y,s._p.z), b=new THREE.Vector3(t._p.x,t._p.y,t._p.z);
    gLinks.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([a,b]),
      new THREE.LineBasicMaterial({color:0x2b3d63,transparent:true,opacity:0.5})));
    const rate=(+l.in_rate||0)+(+l.out_rate||0);
    const P=Math.max(2, Math.min(10, Math.round(rate/50000)+2));
    const geo=new THREE.BufferGeometry(); const pos=new Float32Array(P*3);
    for(let i=0;i<P;i++){ pos[i*3]=a.x; pos[i*3+1]=a.y; pos[i*3+2]=a.z; }
    geo.setAttribute('position', new THREE.BufferAttribute(pos,3));
    const col = rate>0 ? 0x39d98a : 0x3a6ea5;
    const pts=new THREE.Points(geo, new THREE.PointsMaterial({color:col,size:3.2,transparent:true,opacity:0.9,blending:THREE.AdditiveBlending,depthWrite:false}));
    pts.visible=trafficOn; gLinks.add(pts); flowPts.push(pts);
    const speed = rate>0 ? Math.min(0.02, 0.004 + rate/4e7) : 0.006;
    linkFx.push({a,b,geo,P,offs:Array.from({length:P},(_,i)=>i/P),speed});
    const ifn=(l.tgt_if&&l.tgt_if.name)||(l.src_if&&l.src_if.name)||l.label||'';
    if(ifn || (+l.in_rate||0)>0 || (+l.out_rate||0)>0){
      const sp=linkLabel(ifn, +l.in_rate||0, +l.out_rate||0);
      sp.position.copy(a.clone().lerp(b,0.5)).add(new THREE.Vector3(0,7,0)); gLinks.add(sp); linkLabels.push(sp);
    }
  });
}
function updateLinks(links){ if(!ready()) return; buildLinks(links); }   // live realtime — links only, no node rebuild

function render(nodes, links){
  if(!ready()) return;
  layout(nodes);
  clearScene();
  curById=new Map(nodes.map(n=>[n.id,n]));
  // nodes
  nodes.forEach(n=>{
    const col=stc(n.status); const grp=new THREE.Group(); grp.position.set(n._p.x,n._p.y,n._p.z);
    // Better-defined sphere core (Icosahedron subdiv 2 + glossy standard material) — matches Routing Commander.
    const core=new THREE.Mesh(new THREE.IcosahedronGeometry(10,2),
      new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:0.9,roughness:0.3,metalness:0.45,flatShading:true}));
    core.userData=n; grp.add(core); nodeMeshes.push(core);
    const halo=new THREE.Mesh(new THREE.SphereGeometry(17,20,20),
      new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:0.09,blending:THREE.AdditiveBlending,depthWrite:false})); grp.add(halo);
    const ring=new THREE.Mesh(new THREE.TorusGeometry(14,0.7,8,44),
      new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:0.55,blending:THREE.AdditiveBlending,depthWrite:false})); ring.rotation.x=Math.PI/2; grp.add(ring);
    const lab=labelSprite((n.name||('#'+n.id)).slice(0,22), '#'+col.toString(16).padStart(6,'0')); lab.position.set(0,-21,0); grp.add(lab);
    grp.userData={core,halo,ring,base:col,ph:Math.random()*6.28}; gNodes.add(grp);   // ph = per-node pulse phase
  });
  buildLinks(links);
  built=true;
  // frame the fabric ONCE — don't yank the camera on periodic refreshes (keeps the user's orbit)
  if(!framed){
    const box=new THREE.Box3().setFromObject(gNodes); const c=box.getCenter(new THREE.Vector3()), sz=box.getSize(new THREE.Vector3());
    controls.target.copy(c); const rad=Math.max(sz.x,sz.z,60); camera.position.set(c.x, c.y+rad*0.55, c.z+rad*1.5);
    framed=true;
  }
  resize();
  start();
}

function tick(){
  if(!running) return; raf=requestAnimationFrame(tick);
  const t=performance.now()*0.001;
  // per-node breathing pulse: core scale + emissive + spin, ring spin, halo pulse (like Routing Commander)
  gNodes.children.forEach(g=>{ const u=g.userData; if(!u||!u.core) return;
    const ph=t*2.1+(u.ph||0), s=1+Math.sin(ph)*0.045;
    u.core.scale.setScalar(s); u.core.material.emissiveIntensity=0.7+Math.sin(ph)*0.3; u.core.rotation.y=t*0.3;
    if(u.ring) u.ring.rotation.z=t*0.5;
    if(u.halo){ u.halo.scale.setScalar(1+Math.sin(t*1.5+(u.ph||0))*0.06); u.halo.material.opacity=0.08+0.05*(0.5+0.5*Math.sin(t*2+g.position.x)); }
  });
  controls.autoRotate=spin;   // scene orbit unless the user pinned it static
  // flow particles ride the links
  linkFx.forEach(fx=>{ const p=fx.geo.attributes.position.array;
    for(let i=0;i<fx.P;i++){ fx.offs[i]=(fx.offs[i]+fx.speed)%1; const u=fx.offs[i];
      p[i*3]=fx.a.x+(fx.b.x-fx.a.x)*u; p[i*3+1]=fx.a.y+(fx.b.y-fx.a.y)*u; p[i*3+2]=fx.a.z+(fx.b.z-fx.a.z)*u; }
    fx.geo.attributes.position.needsUpdate=true; });
  controls.update(); renderer.render(scene,camera);
}
function start(){ if(!ready()||running) return; running=true; tick(); }
function stop(){ running=false; if(raf) cancelAnimationFrame(raf); raf=null; }
function resize(){ if(!ready()||!host) return; const w=host.clientWidth||600, h=host.clientHeight||500;
  renderer.setSize(w,h,false); camera.aspect=w/h; camera.updateProjectionMatrix(); }
function show(){ if(canvas) canvas.style.display='block'; resize(); start(); }
function hide(){ stop(); if(canvas) canvas.style.display='none'; }

function reframe(){ if(!ready()||!gNodes||!gNodes.children.length) return;
  const box=new THREE.Box3().setFromObject(gNodes); const c=box.getCenter(new THREE.Vector3()), sz=box.getSize(new THREE.Vector3());
  controls.target.copy(c); const rad=Math.max(sz.x,sz.z,60); camera.position.set(c.x, c.y+rad*0.55, c.z+rad*1.5); framed=true; }
function setSpin(on){ spin=!!on; if(controls) controls.autoRotate=spin; }   // orbit (default) ↔ static
function getSpin(){ return spin; }
window.NMFab={ init, render, show, hide, resize, ready, reframe, setTraffic, updateLinks, setSpin, getSpin };
})();
