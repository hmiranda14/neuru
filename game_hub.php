<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — GAMERS HUB. The gaming section's landing: a full-WebGL holographic hub with
// a central NEURU core and every gaming tool as a floating portal-card in a ring,
// wired to the core by energy streams. Hover pops a card; clicking warp-dives into
// the page. Cards are drawn to canvas textures → genuine 3D WebGL cards. RBAC gates
// each card by its page perm. Standard dark layout. Universal.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
include('logger.php');

if (!checkAccess($conn, 'gaming')) { header('Location: /denied_access.php?page=gaming'); exit; }

// [perm, url, name, tagline, colorHex, emoji]
$all = [
    ['gaming',    'gaming.php',          'Gaming Deck',       'Immersive 3D rig command center',        '#b06bff', '🎮'],
    ['gaming',    'game_lab.php',        'Game Lab',          'One-click optimizers & fixers',          '#7CFFB2', '🧪'],
    ['gaming',    'reality.php',         'Parallel Reality',  'Preview & collapse your rig\'s futures',  '#4da3ff', '⚛️'],
    ['gaming',    'synaptic.php',        'Synaptic Map',      'Your reflexes ↔ your machine',            '#a884ff', '🧠'],
    ['gaming',    'benchmark.php',       'PC Benchmark',      'Is your PC built for gaming? Real score',  '#ffcf6b', '📊'],
    ['gaming',    'longevity.php',       'Hardware Longevity','Wear & lifespan — your rig health passport','#7CFFB2', '🫀'],
    ['gaming',    'net_doctor.php',      'Connection Doctor', 'Is the lag WiFi, ISP, or the game?',      '#39e1ff', '🩺'],
    ['gaming',    'fan_profiler.php',    'Fan Profiler',      'Tune fan curves — run cooler',            '#36e3d0', '🌀'],
    ['pc_doctor', 'pc_troubleshoot.php', 'PC Doctor',         'Your real PC in 3D — click a part',       '#ffcf6b', '🖥️'],
    ['stream_decks','stream_decks.php',  'Stream Decks',      'Your rig + NOC on a physical Stream Dock', '#38e0ff', '🎛️'],
];
$tools = [];
foreach ($all as $t) { try { if (checkAccess($conn, $t[0])) $tools[] = ['url'=>$t[1],'name'=>$t[2],'tag'=>$t[3],'color'=>$t[4],'emoji'=>$t[5]]; } catch (\Throwable $e) {} }

$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
include('header.php');
?>
<video autoplay muted loop playsinline id="bg-video" style="position:fixed;inset:0;z-index:-3;object-fit:cover;min-width:100%;min-height:100%;opacity:.05"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<script src="/three.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --cy:#39e1ff; --pk:#b06bff; --bd:rgba(120,150,255,.16); }
*,*::before,*::after{ box-sizing:border-box; }
html{ background:#04060d; }
body{ margin:0; background:#04060d !important; color:#e6ecf7; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; overflow:hidden; }
#nm-netbg{ z-index:0 !important; opacity:.55; }
<?= function_exists('nm_chrome_css') ? nm_chrome_css() : '' ?>
#hubgl{ position:fixed; inset:0; z-index:1; width:100%; height:100%; display:block; cursor:grab; }
#hubgl.hot{ cursor:pointer; }
#hubgl.grab{ cursor:grabbing; }
.hub-head{ position:fixed; top:72px; left:26px; right:auto; z-index:2; pointer-events:none; }
.hub-head .brand{ display:flex; align-items:center; gap:14px; }
.hub-head .tick{ width:5px; height:48px; border-radius:4px; background:linear-gradient(180deg,var(--cy),var(--pk)); box-shadow:0 0 18px rgba(120,150,255,.65); flex:none; }
.hub-head h1{ margin:0; font-size:clamp(22px,2.6vw,38px); font-weight:900; letter-spacing:5px; line-height:1;
  background:linear-gradient(90deg,var(--cy),var(--pk)); -webkit-background-clip:text; background-clip:text; color:transparent;
  filter:drop-shadow(0 4px 22px rgba(120,90,255,.35)); }
.hub-head .sub{ margin-top:5px; font-size:11.5px; letter-spacing:3px; text-transform:uppercase; color:#8fb4dd; }
@media(max-width:760px){ .hub-head{ top:64px; left:16px; } .hub-head .tick{ height:40px; } }
.hub-hint{ position:fixed; bottom:22px; left:0; right:0; z-index:2; text-align:center; font-size:12px; color:#7f9dc8; letter-spacing:2px; pointer-events:none; }
#warp{ position:fixed; inset:0; z-index:50; pointer-events:none; opacity:0; background:radial-gradient(circle at 50% 50%, #ffffff 0%, rgba(120,180,255,.4) 22%, transparent 60%); transition:opacity .12s linear; }
#warpName{ position:fixed; inset:0; z-index:51; display:grid; place-items:center; pointer-events:none; opacity:0; transition:opacity .25s; font-size:30px; font-weight:900; letter-spacing:6px; color:#fff; text-shadow:0 0 30px var(--cy); text-transform:uppercase; }
</style>

<div class="hub-head"><div class="brand"><span class="tick"></span><div><h1>GAMERS HUB</h1><div class="sub">◈ choose your tool ◈</div></div></div></div>
<canvas id="hubgl"></canvas>
<div class="hub-hint">Drag to rotate · scroll to zoom · double-click to reset · click a portal to dive in</div>
<div id="warp"></div><div id="warpName"></div>

<script>
const TOOLS = <?= json_encode($tools) ?>;
(function(){
  if(!window.THREE){ location.href = TOOLS[0] ? TOOLS[0].url : 'gaming.php'; return; }
  const cv=document.getElementById('hubgl');
  const rn=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true}); rn.setPixelRatio(Math.min(2,devicePixelRatio)); rn.setSize(innerWidth,innerHeight);
  const sc=new THREE.Scene(), cam=new THREE.PerspectiveCamera(55,innerWidth/innerHeight,.1,200); cam.position.set(0,0,20);

  // ── world group: everything the user can rotate/zoom lives in here ──
  const world=new THREE.Group(); sc.add(world);

  // ── central NEURU core ──
  const coreG=new THREE.Group(); world.add(coreG);
  const core=new THREE.Mesh(new THREE.IcosahedronGeometry(2.0,1), new THREE.MeshBasicMaterial({color:0x39e1ff,wireframe:true,transparent:true,opacity:.85}));
  const core2=new THREE.Mesh(new THREE.IcosahedronGeometry(2.7,0), new THREE.MeshBasicMaterial({color:0xb06bff,wireframe:true,transparent:true,opacity:.22}));
  coreG.add(core,core2);

  // ── draw a card to a canvas texture (the "WebGL card" face) ──
  function cardTexture(t, hot){
    const W=512,H=650, c=document.createElement('canvas'); c.width=W; c.height=H; const x=c.getContext('2d');
    const col=t.color;
    // glass panel
    const r=42; x.beginPath(); x.moveTo(r,0); x.arcTo(W,0,W,H,r); x.arcTo(W,H,0,H,r); x.arcTo(0,H,0,0,r); x.arcTo(0,0,W,0,r); x.closePath();
    const g=x.createLinearGradient(0,0,0,H); g.addColorStop(0,'rgba(14,20,40,.92)'); g.addColorStop(1,'rgba(8,12,26,.96)'); x.fillStyle=g; x.fill();
    // inner scanlines
    x.globalAlpha=.06; x.strokeStyle=col; for(let yy=60;yy<H;yy+=16){ x.beginPath(); x.moveTo(20,yy); x.lineTo(W-20,yy); x.stroke(); } x.globalAlpha=1;
    // neon border
    x.lineWidth=hot?9:5; x.strokeStyle=col; x.shadowColor=col; x.shadowBlur=hot?46:22;
    x.beginPath(); x.moveTo(r,3); x.arcTo(W-3,3,W-3,H-3,r); x.arcTo(W-3,H-3,3,H-3,r); x.arcTo(3,H-3,3,3,r); x.arcTo(3,3,W-3,3,r); x.closePath(); x.stroke(); x.shadowBlur=0;
    // corner ticks
    x.strokeStyle=col; x.lineWidth=4; [[28,28,1,1],[W-28,28,-1,1],[28,H-28,1,-1],[W-28,H-28,-1,-1]].forEach(p=>{ x.beginPath(); x.moveTo(p[0],p[1]+30*p[3]); x.lineTo(p[0],p[1]); x.lineTo(p[0]+30*p[2],p[1]); x.stroke(); });
    // emoji
    x.font='150px "Segoe UI Emoji","Noto Color Emoji",sans-serif'; x.textAlign='center'; x.textBaseline='middle';
    x.shadowColor=col; x.shadowBlur=30; x.fillText(t.emoji, W/2, 210); x.shadowBlur=0;
    // title
    x.fillStyle='#f2f8ff'; x.font='800 46px "Segoe UI",sans-serif'; x.fillText(t.name.toUpperCase(), W/2, 380);
    // tagline (wrap)
    x.fillStyle='#a9c2e6'; x.font='26px "Segoe UI",sans-serif';
    const words=t.tag.split(' '); let line='', yy=440; for(const w of words){ if(x.measureText(line+w).width>W-70){ x.fillText(line.trim(),W/2,yy); line=w+' '; yy+=34; } else line+=w+' '; } x.fillText(line.trim(),W/2,yy);
    // enter chip
    x.fillStyle=col; x.font='800 24px "Segoe UI",sans-serif'; x.shadowColor=col; x.shadowBlur=hot?24:10; x.fillText('◈ ENTER', W/2, H-56); x.shadowBlur=0;
    const tex=new THREE.CanvasTexture(c); tex.anisotropy=4; tex.needsUpdate=true; return tex;
  }

  // ── build the ring of cards ──
  const N=TOOLS.length, R=Math.max(6.4, N*1.35), cards=[];
  const CW=3.1, CH=3.95;
  TOOLS.forEach((t,i)=>{
    const ang = -Math.PI/2 + (i/N)*Math.PI*2;
    const px=Math.cos(ang)*R, py=Math.sin(ang)*R*0.62;   // squash vertically → wider ellipse
    const grp=new THREE.Group(); grp.position.set(px,py,0);
    const col=new THREE.Color(t.color);
    const face=new THREE.Mesh(new THREE.PlaneGeometry(CW,CH), new THREE.MeshBasicMaterial({map:cardTexture(t,false),transparent:true}));
    const halo=new THREE.Mesh(new THREE.PlaneGeometry(CW+0.5,CH+0.5), new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:0,blending:THREE.AdditiveBlending,depthWrite:false})); halo.position.z=-0.05;
    grp.add(halo,face);
    // energy stream core → card
    const lg=new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0,0,0), new THREE.Vector3(px,py,0)]);
    const line=new THREE.Line(lg, new THREE.LineBasicMaterial({color:col,transparent:true,opacity:.22}));
    world.add(line);
    // travelling pulse along the stream
    const pulse=new THREE.Mesh(new THREE.SphereGeometry(.14,10,10), new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:.9})); world.add(pulse);
    world.add(grp);
    cards.push({t,grp,face,halo,line,pulse,px,py,phase:Math.random()*6.28,tex:face.material.map,hotTex:null,base:{x:px,y:py},hover:0});
  });

  // ── interaction ──
  const ray=new THREE.Raycaster(), mouse=new THREE.Vector2(-2,-2); let hoverI=-1, warping=false, mx=0,my=0;
  // drag-to-rotate + scroll-to-zoom state
  let dragging=false, moved=false, downX=0, downY=0, lastX=0, lastY=0;
  let tYaw=0, tPitch=0, yaw=0, pitch=0, tCamZ=20, autorot=true, autoTmr=null;
  const _bbq=new THREE.Quaternion();   // reused for per-card billboarding
  cv.addEventListener('pointermove',e=>{ const r=cv.getBoundingClientRect(); mouse.x=((e.clientX-r.left)/r.width)*2-1; mouse.y=-((e.clientY-r.top)/r.height)*2+1; mx=(e.clientX/innerWidth-.5); my=(e.clientY/innerHeight-.5);
    if(dragging){ if(Math.hypot(e.clientX-downX,e.clientY-downY)>6) moved=true;
      tYaw += (e.clientX-lastX)*0.006; tPitch += (e.clientY-lastY)*0.005; tPitch=Math.max(-0.75,Math.min(0.75,tPitch));
      lastX=e.clientX; lastY=e.clientY; } });
  cv.addEventListener('pointerleave',()=>{ mouse.x=-2; mouse.y=-2; });
  cv.addEventListener('pointerdown',e=>{ dragging=true; moved=false; downX=lastX=e.clientX; downY=lastY=e.clientY; autorot=false; clearTimeout(autoTmr); cv.classList.add('grab'); try{cv.setPointerCapture(e.pointerId);}catch(_){} });
  addEventListener('pointerup',()=>{ if(!dragging) return; dragging=false; cv.classList.remove('grab'); autoTmr=setTimeout(()=>{autorot=true;},4000); });
  cv.addEventListener('wheel',e=>{ e.preventDefault(); tCamZ=Math.max(8,Math.min(38, tCamZ + e.deltaY*0.012)); }, {passive:false});
  cv.addEventListener('dblclick',()=>{ tYaw=0; tPitch=0; tCamZ=20; });   // reset view
  cv.addEventListener('click',()=>{ if(hoverI>=0 && !warping && !moved) dive(hoverI); });

  function setHot(i,on){ const c=cards[i]; if(on&&!c.hotTex)c.hotTex=cardTexture(c.t,true); c.face.material.map=on?c.hotTex:c.tex; c.face.material.needsUpdate=true; }

  function dive(i){
    warping=true; const c=cards[i];
    document.getElementById('warpName').textContent=c.t.name;
    const t0=performance.now(); const sx=c.grp.position.x, sy=c.grp.position.y;
    (function anim(){ const k=Math.min(1,(performance.now()-t0)/620); const e=k*k;
      // chosen card flies to the camera & scales up; others streak outward + fade
      c.grp.position.set(sx*(1-e), sy*(1-e), e*17); c.grp.scale.setScalar(1+e*5); c.face.material.opacity=1-Math.max(0,(e-.7)/.3);
      cards.forEach((o,j)=>{ if(j===i)return; o.grp.position.z=-e*20; o.face.material.opacity=1-e; o.line.material.opacity=(1-e)*.22; });
      coreG.scale.setScalar(1+e*3.5); core.material.opacity=0.85*(1-e); core2.material.opacity=0.22*(1-e);
      document.getElementById('warp').style.opacity=String(e);
      document.getElementById('warpName').style.opacity=String(Math.min(1,e*1.6));
      if(k<1){ requestAnimationFrame(anim); } else { location.href=c.t.url; }
    })();
  }

  // ── intro: cards fly in from far ──
  let intro=0;
  (function loop(){ requestAnimationFrame(loop); const t=performance.now()*0.001;
    if(intro<1) intro=Math.min(1,intro+0.02);
    // user rotate (drag) + gentle idle auto-spin + zoom (wheel), all eased
    if(autorot && !dragging && !warping) tYaw += 0.0016;
    yaw += (tYaw-yaw)*0.08; pitch += (tPitch-pitch)*0.08;
    world.rotation.y=yaw; world.rotation.x=pitch;
    cam.position.z += (tCamZ-cam.position.z)*0.08;
    core.rotation.y+=.01; core.rotation.x+=.004; core2.rotation.y-=.006; core.scale.setScalar(1+Math.sin(t*3)*.05);
    if(!warping){
      // hover pick
      ray.setFromCamera(mouse,cam); const hits=ray.intersectObjects(cards.map(c=>c.face));
      const hi = hits.length ? cards.findIndex(c=>c.face===hits[0].object) : -1;
      if(hi!==hoverI){ if(hoverI>=0)setHot(hoverI,false); if(hi>=0)setHot(hi,true); hoverI=hi; cv.classList.toggle('hot',hi>=0); }
      // parallax
      cam.position.x += ((mx*3)-cam.position.x)*.05; cam.position.y += ((-my*2)-cam.position.y)*.05; cam.lookAt(0,0,0);
      cards.forEach((c,i)=>{
        const on=i===hoverI; c.hover += ((on?1:0)-c.hover)*.15;
        const bob=Math.sin(t*1.4+c.phase)*0.35*intro;
        const zi = -18*(1-intro) + c.hover*3.2 + bob*0.4;   // fly in from z=-18
        c.grp.position.set(c.base.x*intro, c.base.y*intro + bob, zi);
        // BILLBOARD: cancel the world's rotation so the card face always points at the camera.
        // (Without this the card orbits AND rotates with the world → goes edge-on / back-face and
        // disappears while dragging.) Position still orbits; only orientation is locked to the screen.
        _bbq.copy(world.quaternion).invert().multiply(cam.quaternion);
        c.grp.quaternion.copy(_bbq);
        c.grp.rotateY(mx*0.25 + (on?Math.sin(t*4)*0.03:0));   // subtle live tilt on top
        c.grp.rotateX(my*0.2);
        c.grp.scale.setScalar(0.6+0.4*intro + c.hover*0.18);
        c.halo.material.opacity = c.hover*0.5 + 0.08;
        c.line.material.opacity = (0.16 + c.hover*0.5)*intro;
        // pulse travels core→card
        const pk=((t*0.5 + i/N)%1); c.pulse.position.set(c.base.x*pk*intro, (c.base.y*intro+bob)*pk, zi*pk);
        c.pulse.material.opacity=(0.9-Math.abs(pk-0.5))*intro;
        c.pulse.scale.setScalar(0.6+c.hover*0.8);
      });
    }
    rn.render(sc,cam);
  })();
  addEventListener('resize',()=>{ cam.aspect=innerWidth/innerHeight; cam.updateProjectionMatrix(); rn.setSize(innerWidth,innerHeight); });
})();
</script>
</body></html>
