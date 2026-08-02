<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — PC DOCTOR. Fullscreen WebGL virtualization of the gamer's actual PC:
// a 3D motherboard with the REAL CPU / RAM / GPU / NVMe / SATA / PCIe parts.
// Click any component → its true brand · model · version + live temp + a real
// manufacturer link & photo search. Data "currents" flow across the board driven
// by live CPU/GPU load. Parallel to Game Mode. Perm 'pc_doctor'. Engine: nm_pcdoctor.php
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_pcdoctor.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'pc_doctor')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=pc_doctor'); exit;
}
if (function_exists('session_write_close')) @session_write_close();   // slow SSH work must not hold the session lock

if ($api) {
    header('Content-Type: application/json');
    try {
        if ($api === 'rigs') {
            $rows = function_exists('nm_win_hosts') ? nm_win_hosts($conn) : [];
            $out = array_map(fn($r)=>['id'=>(int)$r['id'],'name'=>$r['name'],'ip'=>$r['host_ip']??''], $rows);
            echo json_encode(['ok'=>true,'rigs'=>$out]); exit;
        }
        $rid = (int)($_GET['rig'] ?? 0);
        $h = $rid && function_exists('nm_win_host') ? nm_win_host($conn,$rid) : null;
        if ($api === 'hardware') {
            if (!$h) { echo json_encode(['ok'=>false,'error'=>'pick a rig']); exit; }
            $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn,$h) : null;
            if (!$ssh) { echo json_encode(['ok'=>false,'error'=>'no SSH for this rig']); exit; }
            log_user_action($conn,'pcd_scan',$h['name']??('rig '.$rid));
            echo json_encode(nm_pcd_hardware($ssh)); exit;
        }
        if ($api === 'live') {
            if (!$h) { echo json_encode(['ok'=>false,'error'=>'pick a rig']); exit; }
            echo json_encode(nm_pcd_live($conn,$h)); exit;
        }
        if ($api === 'diag') {
            if (!$h) { echo json_encode(['ok'=>false,'error'=>'pick a rig']); exit; }
            log_user_action($conn,'pcd_diag',$h['name']??('rig '.$rid));
            echo json_encode(nm_pcd_diagnostics($conn,$h)); exit;
        }
        echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
    } catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>'server error']); exit; }
}
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PC Doctor | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="/three.min.js"></script>
<script src="/nm_netbg.js"></script>
<style>
:root{ --cy:#39e1ff; --pk:#b06bff; --ok:#2ee66e; --warn:#f0a92c; --crit:#ff4d6d; --bd:rgba(120,150,255,.16); }
*,*::before,*::after{ box-sizing:border-box; }
html,body{ margin:0; height:100%; font-family:'Segoe UI',Tahoma,sans-serif; background:radial-gradient(ellipse at 50% 36%,#0a1226 0%,#05070f 62%,#02040a 100%); color:#e6ecf7; overflow:hidden; }
#nm-netbg{ z-index:0 !important; opacity:.85; }   /* NEURU particle network, behind the transparent 3D canvas */
#pcd{ position:fixed; inset:0; z-index:1; }
#pcgl{ position:absolute; inset:0; display:block; cursor:grab; background:transparent; }
#pcgl.drag{ cursor:grabbing; } #pcgl.hot{ cursor:pointer; }
/* top control bar */
#pctop{ position:absolute; top:16px; left:18px; right:18px; z-index:5; display:flex; align-items:center; gap:12px; flex-wrap:wrap; pointer-events:none; }
#pctop > *{ pointer-events:auto; }
.brand{ font-size:20px; font-weight:900; letter-spacing:2px; background:linear-gradient(90deg,#39e1ff,#b06bff); -webkit-background-clip:text; background-clip:text; color:transparent; }
.brand small{ display:block; font-size:9px; letter-spacing:4px; color:#7f9dc8; -webkit-text-fill-color:#7f9dc8; }
select.rig,.tbtn{ background:rgba(17,26,43,.72); color:#dbe6f5; border:1px solid var(--bd); border-radius:10px; padding:9px 13px; font-size:13px; cursor:pointer; backdrop-filter:blur(8px); }
.tbtn:hover{ border-color:var(--cy); } a.tbtn{ text-decoration:none; }
#pcstat{ font-size:12px; color:#8fb0dd; }
/* floating title */
#pctitle{ position:absolute; top:70px; left:0; right:0; text-align:center; z-index:3; pointer-events:none; }
#pctitle .t{ font-size:clamp(18px,2.4vw,30px); font-weight:900; letter-spacing:2px; background:linear-gradient(90deg,#39e1ff,#b06bff,#ff4dd0); -webkit-background-clip:text; background-clip:text; color:transparent; }
#pctitle .s{ font-size:12px; letter-spacing:3px; color:#8fb0dd; text-transform:uppercase; margin-top:2px; }
/* part labels projected over the 3D board */
#pclabels{ position:absolute; inset:0; z-index:2; pointer-events:none; }
.plab{ position:absolute; transform:translate(-50%,-50%); text-align:center; white-space:nowrap; will-change:transform,opacity; }
.plab .pn{ font-size:12px; font-weight:700; letter-spacing:.5px; color:#dfeeff; text-shadow:0 1px 6px #000,0 0 12px rgba(0,0,0,.8); }
.plab .pv{ font-size:18px; font-weight:800; font-variant-numeric:tabular-nums; letter-spacing:.3px; line-height:1.12; color:#dfeeff; text-shadow:0 1px 8px #000,0 0 14px rgba(0,0,0,.8); }
.plab .pv.c-ok{ color:#39e1ff } .plab .pv.c-good{ color:#2ee66e } .plab .pv.c-warn{ color:#f0a92c } .plab .pv.c-crit{ color:#ff4d6d; text-shadow:0 0 16px rgba(255,77,109,.6) }
.plab .pt{ font-size:11px; font-weight:800; font-variant-numeric:tabular-nums; }
.plab .pt.c-ok{ color:#2ee66e } .plab .pt.c-warn{ color:#f0a92c } .plab .pt.c-crit{ color:#ff4d6d }
/* live HUD — the whole machine at a glance */
#pchud{ position:absolute; left:50%; transform:translateX(-50%); bottom:34px; z-index:4; display:none; gap:14px; align-items:center; flex-wrap:wrap; justify-content:center; padding:11px 18px; max-width:94vw; background:rgba(8,13,26,.5); border:1px solid rgba(120,150,255,.2); border-radius:16px; backdrop-filter:blur(10px); pointer-events:none; box-shadow:0 10px 40px rgba(0,0,0,.4); }
#pchud.on{ display:flex; }
.hb{ display:flex; flex-direction:column; gap:4px; min-width:110px; }
.hb .hbl{ font-size:9.5px; letter-spacing:2px; text-transform:uppercase; color:#8fb0dd; display:flex; justify-content:space-between; gap:8px; }
.hb .hbv{ color:#dfeeff; font-weight:800; font-variant-numeric:tabular-nums; }
.hb .hbt{ height:6px; border-radius:4px; background:rgba(255,255,255,.08); overflow:hidden; }
.hb .hbf{ display:block; height:100%; width:0; border-radius:4px; background:#39e1ff; transition:width .5s ease; }
.hsep{ width:1px; height:36px; background:rgba(120,150,255,.18); }
#hdDrives{ display:flex; gap:11px; flex-wrap:wrap; }
.hdrv{ display:flex; align-items:center; gap:6px; font-size:11px; color:#cfe0f5; }
.hdrv .hdid{ font-weight:800; } .hdrv .hdbar{ width:54px; height:6px; border-radius:4px; background:rgba(255,255,255,.08); overflow:hidden; } .hdrv .hdbar span{ display:block; height:100%; border-radius:4px; } .hdrv .hdpct{ color:#9fb4d8; }
/* detail panel */
#pcpanel{ position:absolute; top:0; right:0; height:100%; width:min(400px,92vw); z-index:8; background:linear-gradient(180deg,rgba(9,14,28,.94),rgba(6,10,20,.96)); border-left:1px solid rgba(120,150,255,.22); backdrop-filter:blur(14px); transform:translateX(105%); transition:transform .32s cubic-bezier(.2,.8,.2,1); overflow-y:auto; box-shadow:-16px 0 50px rgba(0,0,0,.5); }
#pcpanel.on{ transform:translateX(0); }
.pp-h{ padding:22px 22px 14px; border-bottom:1px solid rgba(120,150,255,.14); position:relative; }
.pp-kind{ font-size:11px; letter-spacing:3px; text-transform:uppercase; color:#8fb0dd; }
.pp-title{ font-size:21px; font-weight:800; margin-top:6px; line-height:1.25; }
.pp-x{ position:absolute; top:16px; right:16px; background:rgba(255,120,150,.14); border:1px solid rgba(255,120,150,.4); color:#ffd0da; width:34px; height:34px; border-radius:9px; cursor:pointer; font-size:15px; }
.pp-x:hover{ background:rgba(255,77,109,.28); }
.pp-body{ padding:18px 22px 30px; }
.pp-temp{ display:flex; align-items:baseline; gap:8px; margin-bottom:16px; }
.pp-temp .v{ font-size:40px; font-weight:900; font-variant-numeric:tabular-nums; } .pp-temp .l{ font-size:12px; color:#8fb0dd; }
.pp-row{ display:flex; justify-content:space-between; gap:14px; padding:9px 0; border-top:1px solid rgba(120,150,255,.09); font-size:13.5px; }
.pp-row span{ color:#8fb0dd; } .pp-row b{ color:#eaf2ff; text-align:right; font-weight:600; word-break:break-word; }
.pp-links{ display:flex; flex-direction:column; gap:9px; margin-top:20px; }
.pp-links a{ display:flex; align-items:center; gap:10px; text-decoration:none; padding:11px 14px; border-radius:11px; font-size:13.5px; font-weight:600; background:rgba(57,225,255,.1); border:1px solid rgba(57,225,255,.3); color:#dff4ff; }
.pp-links a:hover{ background:rgba(57,225,255,.2); } .pp-links a i{ width:16px; text-align:center; }
.pp-note{ font-size:11.5px; color:#6f8bb0; margin-top:16px; line-height:1.5; }
#pchint{ position:absolute; bottom:12px; left:0; right:0; text-align:center; font-size:11px; color:rgba(140,165,200,.5); z-index:3; pointer-events:none; }
#pcload{ position:absolute; inset:0; z-index:9; display:flex; align-items:center; justify-content:center; background:#04060d; flex-direction:column; gap:16px; }
#pcload .sp{ width:52px; height:52px; border:3px solid rgba(120,150,255,.2); border-top-color:#39e1ff; border-radius:50%; animation:spin 1s linear infinite; }
@keyframes spin{ to{ transform:rotate(360deg) } }
#pcload .m{ font-size:14px; color:#8fb0dd; letter-spacing:1px; }
/* diagnostics panel (left slide-in) */
#pcdiag{ position:absolute; top:0; left:0; height:100%; width:min(420px,94vw); z-index:8; background:linear-gradient(180deg,rgba(9,14,28,.95),rgba(6,10,20,.97)); border-right:1px solid rgba(120,150,255,.22); backdrop-filter:blur(14px); transform:translateX(-105%); transition:transform .32s cubic-bezier(.2,.8,.2,1); overflow-y:auto; box-shadow:16px 0 50px rgba(0,0,0,.5); }
#pcdiag.on{ transform:translateX(0); }
.dg-h{ padding:20px 22px 14px; border-bottom:1px solid rgba(120,150,255,.14); display:flex; justify-content:space-between; align-items:flex-start; gap:12px; }
.dg-kind{ font-size:11px; letter-spacing:3px; text-transform:uppercase; color:#8fb0dd; }
.dg-title{ font-size:21px; font-weight:800; margin-top:5px; }
.dg-body{ padding:14px 18px 30px; }
.dg-load{ display:flex; flex-direction:column; align-items:center; gap:12px; padding:40px 0; color:#8fb0dd; font-size:13px; }
.dg-load .sp{ width:40px; height:40px; border:3px solid rgba(120,150,255,.2); border-top-color:#39e1ff; border-radius:50%; animation:spin 1s linear infinite; }
.dg-score{ text-align:center; padding:10px 0 18px; }
.dg-score .b{ display:inline-block; padding:8px 20px; border-radius:30px; font-weight:800; font-size:15px; letter-spacing:.5px; }
.dg-score .b.ok{ background:rgba(46,230,110,.14); color:#7dffb0; border:1px solid rgba(46,230,110,.4); }
.dg-score .b.warn{ background:rgba(240,169,44,.14); color:#ffd98a; border:1px solid rgba(240,169,44,.4); }
.dg-score .b.crit{ background:rgba(255,77,109,.16); color:#ffb3c2; border:1px solid rgba(255,77,109,.45); }
.dgc{ border:1px solid rgba(120,150,255,.14); border-radius:12px; padding:12px 14px; margin-bottom:10px; background:rgba(255,255,255,.02); }
.dgc.crit{ border-color:rgba(255,77,109,.4); background:rgba(255,77,109,.06); } .dgc.warn{ border-color:rgba(240,169,44,.35); background:rgba(240,169,44,.05); }
.dgc .t{ display:flex; align-items:center; gap:9px; font-weight:700; font-size:14px; }
.dgc .dot{ width:9px; height:9px; border-radius:50%; flex:0 0 auto; }
.dgc .dot.ok{ background:#2ee66e } .dgc .dot.warn{ background:#f0a92c } .dgc .dot.crit{ background:#ff4d6d; box-shadow:0 0 8px #ff4d6d } .dgc .dot.info{ background:#39e1ff }
.dgc .sm{ font-size:12.5px; color:#c3d4ec; margin:6px 0 0 18px; }
.dgc .dl{ font-size:12px; color:#8fa8ca; margin:6px 0 0 18px; line-height:1.6; }
.dgc .dl div::before{ content:'· '; color:#5f7799; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php nm_gamers_hub_pill(); ?>
<div id="pcd">
  <canvas id="pcgl"></canvas>
  <div id="pctop">
    <div class="brand">◈ NEURU<small>PC DOCTOR</small></div>
    <select class="rig" id="rig" onchange="pickRig()"><option value="">Loading rigs…</option></select>
    <button class="tbtn" onclick="rescan()" title="Re-read the hardware inventory"><i class="fa-solid fa-rotate"></i> Scan</button>
    <button class="tbtn" id="diagBtn" onclick="runDiag()" title="Run a full read-only health check over SSH"><i class="fa-solid fa-stethoscope"></i> Diagnose</button>
    <button class="tbtn" onclick="toggleFs()" title="Fullscreen"><i class="fa-solid fa-expand"></i></button>
    <a class="tbtn" href="gaming.php" title="Back to Game Mode"><i class="fa-solid fa-gamepad"></i> Game Mode</a>
    <span id="pcstat"></span>
  </div>
  <div id="pctitle"><div class="t" id="pcName">NEURU PC Doctor</div><div class="s" id="pcSub">pick a rig to virtualize your machine</div></div>
  <div id="pclabels"></div>
  <div id="pchud">
    <div class="hb" id="hb-cpu"><div class="hbl"><span>CPU</span><span class="hbv">—</span></div><div class="hbt"><span class="hbf"></span></div></div>
    <div class="hb" id="hb-ram"><div class="hbl"><span>RAM</span><span class="hbv">—</span></div><div class="hbt"><span class="hbf"></span></div></div>
    <div class="hb" id="hb-gpu"><div class="hbl"><span>GPU</span><span class="hbv">—</span></div><div class="hbt"><span class="hbf"></span></div></div>
    <div class="hb" id="hb-net" style="min-width:98px"><div class="hbl"><span>NET</span><span class="hbv">—</span></div><div class="hbt"><span class="hbf" style="width:100%;opacity:.22"></span></div></div>
    <div class="hsep"></div>
    <div id="hdDrives"></div>
  </div>
  <div id="pchint">drag to orbit · scroll to zoom · click any component for its real specs</div>

  <div id="pcpanel">
    <div class="pp-h"><div class="pp-kind" id="ppKind">component</div><div class="pp-title" id="ppTitle">—</div><button class="pp-x" onclick="closePanel()">✕</button></div>
    <div class="pp-body">
      <div class="pp-temp" id="ppTempWrap" style="display:none"><span class="v" id="ppTemp">—</span><span class="l">°C live</span></div>
      <div id="ppRows"></div>
      <div class="pp-links" id="ppLinks"></div>
      <div class="pp-note" id="ppNote"></div>
    </div>
  </div>

  <!-- Diagnostics report (slide-in, left) -->
  <div id="pcdiag">
    <div class="dg-h"><div><div class="dg-kind">System health check</div><div class="dg-title" id="dgTitle">Diagnostics</div></div><button class="pp-x" onclick="closeDiag()">✕</button></div>
    <div class="dg-body" id="dgBody"><div class="dg-load"><div class="sp"></div><div>Running read-only checks over SSH…</div></div></div>
  </div>

  <div id="pcload" style="display:none"><div class="sp"></div><div class="m" id="pcloadMsg">Reading your hardware over SSH…</div></div>
</div>

<script>
const $=s=>document.querySelector(s);
function esc(s){ return (''+s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
let RIG=0, HW=null, LIVE={}, liveTimer=null;

async function loadRigs(){ try{ const r=await fetch('?api=rigs').then(r=>r.json()); const sel=$('#rig');
  if(!r.ok||!r.rigs.length){ sel.innerHTML='<option value="">No Windows rigs — add one in Windows Monitor</option>'; return; }
  sel.innerHTML='<option value="">— pick your rig —</option>'+r.rigs.map(x=>`<option value="${x.id}">${esc(x.name)} (${esc(x.ip)})</option>`).join(''); }catch(e){} }
function pickRig(){ RIG=+$('#rig').value||0; closePanel(); if(liveTimer)clearInterval(liveTimer);
  if(!RIG){ $('#pcSub').textContent='pick a rig to virtualize your machine'; $('#pchud').classList.remove('on'); return; } rescan(); }
async function rescan(){ if(!RIG){ alert('Pick a rig first'); return; }
  $('#pcload').style.display='flex'; $('#pcloadMsg').textContent='Reading your hardware over SSH…'; $('#pcstat').textContent='';
  try{ const r=await fetch('?api=hardware&rig='+RIG).then(r=>r.json());
    if(!r.ok){ $('#pcloadMsg').textContent='✖ '+(r.error||'failed'); setTimeout(()=>$('#pcload').style.display='none',2200); return; }
    HW=r; buildBoard(r); $('#pcload').style.display='none'; $('#pchud').classList.add('on');
    $('#pcName').textContent=(r.system.brand||'')+' '+(r.system.model||'Gaming Rig'); $('#pcSub').textContent=(r.cpu.name||'')+' · '+(r.system.ram_gb||0)+'GB RAM';
    const sel=$('#rig'); $('#pcstat').textContent='◉ '+(sel.options[sel.selectedIndex]?.text||''); refreshLive(); liveTimer=setInterval(refreshLive,4000);
  }catch(e){ $('#pcloadMsg').textContent='✖ error'; setTimeout(()=>$('#pcload').style.display='none',2000); } }
async function refreshLive(){ if(!RIG)return; try{ const r=await fetch('?api=live&rig='+RIG).then(r=>r.json()); if(r.ok){ LIVE=r; applyLive(); if(SEL) fillPanel(SEL.info); } }catch(e){} }

// Fullscreen the WHOLE document, not just #pcd — the particle canvas (#nm-netbg) is a sibling of #pcd, so
// fullscreening #pcd alone would render only #pcd and hide the particles. documentElement keeps everything.
function toggleFs(){ if(!document.fullscreenElement){ const el=document.documentElement; (el.requestFullscreen||el.webkitRequestFullscreen||function(){}).call(el); } else { (document.exitFullscreen||document.webkitExitFullscreen||function(){}).call(document); } }

// ═══════════════ WebGL virtual motherboard ═══════════════
let RN,SC,CAM,RAY,MOUSE,COMPS=[],CUR=[],SEL=null,HOVER=null,FANS=[],FANGROUP=null;
let ctl={az:0.7,pol:0.62,rad:44, taz:0.7,tpol:0.62,trad:44, drag:false,lx:0,ly:0,moved:0};
function initGL(){
  const cv=$('#pcgl'); RN=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true}); RN.setPixelRatio(Math.min(2,devicePixelRatio)); RN.setSize(innerWidth,innerHeight);
  SC=new THREE.Scene(); SC.fog=new THREE.FogExp2(0x04060d,0.006);
  CAM=new THREE.PerspectiveCamera(52,innerWidth/innerHeight,.1,400);
  SC.add(new THREE.AmbientLight(0x5a6b9a,0.9));
  const d1=new THREE.DirectionalLight(0xbcd4ff,1.05); d1.position.set(10,26,14); SC.add(d1);
  const p1=new THREE.PointLight(0x39e1ff,0.7,120); p1.position.set(-16,14,-10); SC.add(p1);
  const p2=new THREE.PointLight(0xb06bff,0.6,120); p2.position.set(18,10,16); SC.add(p2);
  RAY=new THREE.Raycaster(); MOUSE=new THREE.Vector2();
  FANGROUP=new THREE.Group(); SC.add(FANGROUP);
  bindControls(cv);
  addEventListener('resize',()=>{ RN.setSize(innerWidth,innerHeight); CAM.aspect=innerWidth/innerHeight; CAM.updateProjectionMatrix(); });
  glLoop();
}
function bindControls(cv){
  const down=e=>{ ctl.drag=true; ctl.moved=0; const p=e.touches?e.touches[0]:e; ctl.lx=p.clientX; ctl.ly=p.clientY; cv.classList.add('drag'); };
  const move=e=>{ const p=e.touches?e.touches[0]:e; if(ctl.drag){ const dx=p.clientX-ctl.lx, dy=p.clientY-ctl.ly; ctl.lx=p.clientX; ctl.ly=p.clientY; ctl.moved+=Math.abs(dx)+Math.abs(dy);
      ctl.taz-=dx*0.005; ctl.tpol=Math.max(0.12,Math.min(1.45,ctl.tpol+dy*0.005)); if(e.touches&&e.cancelable)e.preventDefault(); }
    MOUSE.x=(p.clientX/innerWidth)*2-1; MOUSE.y=-(p.clientY/innerHeight)*2+1; };
  const up=e=>{ if(ctl.drag && ctl.moved<6){ pickAt(); } ctl.drag=false; cv.classList.remove('drag'); };
  cv.addEventListener('mousedown',down); addEventListener('mousemove',move); addEventListener('mouseup',up);
  cv.addEventListener('touchstart',down,{passive:false}); cv.addEventListener('touchmove',move,{passive:false}); addEventListener('touchend',up);
  cv.addEventListener('wheel',e=>{ ctl.trad=Math.max(16,Math.min(90,ctl.trad*(1+(e.deltaY>0?0.09:-0.09)))); e.preventDefault(); },{passive:false});
}
function disposeBoard(){ COMPS.forEach(c=>{ SC.remove(c.group); c.el.remove(); }); COMPS=[]; CUR.forEach(c=>SC.remove(c.pts)); CUR=[]; SEL=null; if(BOARD){SC.remove(BOARD);BOARD=null;} }
let BOARD=null;
const MAT=(col,opt={})=>new THREE.MeshStandardMaterial(Object.assign({color:col,metalness:.55,roughness:.5},opt));
function edgeGlow(w,h,d,col){ const g=new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(w,h,d)), new THREE.LineBasicMaterial({color:col,transparent:true,opacity:.55})); return g; }

// build a labelled clickable component: a solid block (+optional accents) + edge glow + HTML label
function makeComp(def){
  const g=new THREE.Group(); g.position.set(def.x,def.h/2,def.z);
  const body=new THREE.Mesh(new THREE.BoxGeometry(def.w,def.h,def.d), MAT(def.color, def.empty?{opacity:.4,transparent:true,metalness:.2,roughness:.9}:{}));
  g.add(body); g.add(edgeGlow(def.w,def.h,def.d, def.empty?0x33415e:def.glow||0x39e1ff));
  if(def.type==='gpu'){ g.userData.fans=[]; [-def.w*0.28,0,def.w*0.28].forEach(fx=>{ const fan=new THREE.Group();
      const ring=new THREE.Mesh(new THREE.TorusGeometry(def.d*0.34,0.08,8,28), new THREE.MeshBasicMaterial({color:0x9fe8ff})); fan.add(ring);
      for(let b=0;b<5;b++){ const bl=new THREE.Mesh(new THREE.BoxGeometry(def.d*0.30,0.05,0.5), new THREE.MeshBasicMaterial({color:0x6fd0ff,transparent:true,opacity:.55})); bl.rotation.y=b/5*Math.PI*2; fan.add(bl); }
      fan.rotation.x=Math.PI/2; fan.position.set(fx,def.h/2+0.08,0); g.add(fan); g.userData.fans.push(fan); }); }
  if(def.type==='cpu'){ for(let i=-1;i<=1;i++)for(let j=-1;j<=1;j++){ const fin=new THREE.Mesh(new THREE.BoxGeometry(def.w*0.9,0.5,0.12), new THREE.MeshStandardMaterial({color:0xcdd8ea,metalness:.8,roughness:.3})); fin.position.set(0,def.h/2+0.25,j*def.d*0.28); g.add(fin); } }
  if(def.type==='ram'&&!def.empty){ const led=new THREE.Mesh(new THREE.BoxGeometry(def.w*0.7,0.12,def.d*0.85), new THREE.MeshBasicMaterial({color:def.glow||0xff5ce0})); led.position.y=def.h/2+0.02; g.add(led); g.userData.led=led; g.userData.ledHue=(def.glow||0xff5ce0); }
  // additive glow halo so active parts pop against the particle field
  if(!def.empty){ const halo=new THREE.Mesh(new THREE.BoxGeometry(def.w*1.14,def.h*1.3,def.d*1.14), new THREE.MeshBasicMaterial({color:def.glow||0x39e1ff,transparent:true,opacity:.05,blending:THREE.AdditiveBlending,depthWrite:false})); g.add(halo); g.userData.halo=halo; }
  body.userData.comp=true; g.userData.body=body; if(!def.empty) body.material.emissive=new THREE.Color(def.glow||0x39e1ff), body.material.emissiveIntensity=0.12;
  const el=document.createElement('div'); el.className='plab'; el.innerHTML='<div class="pn"></div><div class="pv"></div><div class="pt"></div>'; $('#pclabels').appendChild(el);
  el.querySelector('.pn').textContent=def.short;
  const comp={group:g,body,el,pn:el.querySelector('.pn'),pv:el.querySelector('.pv'),pt:el.querySelector('.pt'),info:def.info,def,metric:def.metric||'',tempKeys:def.tempKeys||def.info&&def.info.tempKeys,base:new THREE.Color(def.color),_load:0};
  SC.add(g); COMPS.push(comp); return comp;
}
// a current: particles along a poly-path; speed rises with load
function makeCurrent(path,color){ const N=26,geo=new THREE.BufferGeometry(),pos=new Float32Array(N*3); geo.setAttribute('position',new THREE.BufferAttribute(pos,3));
  const pts=new THREE.Points(geo,new THREE.PointsMaterial({color,size:.5,map:PDOT,transparent:true,opacity:.9,depthWrite:false,blending:THREE.AdditiveBlending})); SC.add(pts);
  CUR.push({pts,path,N,off:Math.random(),color}); }
const PDOT=(()=>{ const c=document.createElement('canvas'); c.width=c.height=48; const x=c.getContext('2d'); const gr=x.createRadialGradient(24,24,0,24,24,24); gr.addColorStop(0,'#fff'); gr.addColorStop(.4,'rgba(255,255,255,.85)'); gr.addColorStop(1,'rgba(255,255,255,0)'); x.fillStyle=gr; x.beginPath(); x.arc(24,24,24,0,7); x.fill(); return new THREE.CanvasTexture(c); })();

function buildBoard(hw){
  disposeBoard();
  // PCB
  BOARD=new THREE.Group();
  const pcb=new THREE.Mesh(new THREE.BoxGeometry(30,0.5,34), MAT(0x0c2417,{metalness:.3,roughness:.75})); pcb.position.y=-0.25; BOARD.add(pcb);
  const trace=new THREE.GridHelper(30,30,0x1f6f4a,0x123a2a); trace.position.y=0.02; BOARD.add(trace); trace.material.opacity=.4; trace.material.transparent=true;
  SC.add(BOARD);
  const L=(a)=>a&&a.length?a:[]; const gpu=L(hw.gpu), mem=L(hw.mem), disks=L(hw.disks), pcie=L(hw.pcie);
  const nvme=disks.filter(d=>d.bus==='NVMe'), sata=disks.filter(d=>d.bus!=='NVMe');

  // CPU (top-center)
  makeComp({type:'cpu',metric:'cpu',x:-3,z:-9,w:5,d:5,h:1.4,color:0xd7deeb,glow:0x8bd0ff,short:'CPU',tempKeys:['cpu','core','tctl','package'],
    info:{kind:'Processor',title:hw.cpu.name||'CPU',rows:hw.cpu.specs||[],links:hw.cpu,tempKeys:['cpu','core','package','tctl']}});
  // RAM slots (right of CPU) — one per DIMM, empties greyed
  const SLOTS=Math.max(4,mem.length);
  for(let i=0;i<SLOTS;i++){ const m=mem[i]; const glow=[0xff5ce0,0x39e1ff,0xffd23a,0x7dff9b][i%4];
    makeComp({type:'ram',metric:m?'ram':'',tempKeys:['memory','dram','ram'],x:5+i*1.35,z:-8,w:0.85,d:7,h:5,color:m?0x1a2740:0x141c2b,glow:m?glow:0x33415e,empty:!m,short:m?('DIMM '+(i+1)):'empty',
      info:m?{kind:'Memory · '+(m.slot||('DIMM '+(i+1))),title:(m.brand?m.brand+' ':'')+(m.part||'RAM module'),rows:m.specs||[],links:m}:{kind:'Memory slot',title:'Empty DIMM slot',rows:[['Status','Not populated']],links:null}}); }
  // GPU (big card, lower area)
  const g0=gpu[0];
  makeComp({type:'gpu',metric:'gpu',x:0,z:6,w:22,d:5,h:2,color:0x11151f,glow:0x39e1ff,short:'GPU',tempKeys:['gpu'],
    info:g0?{kind:'Graphics Card',title:g0.name,rows:g0.specs||[],links:g0,tempKeys:['gpu']}:{kind:'Graphics',title:'No discrete GPU detected',rows:[],links:null}});
  // extra GPUs (iGPU etc.) as a small chip
  if(gpu.length>1){ const g1=gpu[1]; makeComp({type:'chip',x:-12,z:6,w:2.6,d:2.6,h:0.8,color:0x1a2233,glow:0x7a5cff,short:'iGPU',info:{kind:'Graphics (secondary)',title:g1.name,rows:[['Brand',g1.brand],['VRAM',g1.vram?(g1.vram+' MB'):''],['Driver',g1.driver]],links:g1}}); }
  // NVMe M.2 (thin sticks between CPU and GPU)
  nvme.slice(0,3).forEach((d,i)=>{ makeComp({type:'m2',metric:'disktemp',x:-8+i*0.1,z:-1+i*3,w:9,d:1.3,h:0.4,color:0x14233a,glow:0x2ee6c0,short:'NVMe',tempKeys:['nvme','drive','ssd'],
    info:{kind:'NVMe SSD (M.2)',title:d.name,rows:d.specs||[],links:d,tempKeys:['nvme','drive','ssd','temperature']}}); });
  // SATA drives (right bay)
  sata.slice(0,4).forEach((d,i)=>{ makeComp({type:'sata',metric:'disktemp',tempKeys:['drive','sata','ssd','hdd','disk'],x:11.5,z:2+i*2.4,w:5.5,d:2,h:1.2,color:0x1b2233,glow:0x9fb4ff,short:d.media||'SATA',
    info:{kind:'Storage · '+(d.bus||'SATA'),title:d.name,rows:d.specs||[],links:d}}); });
  // Chipset heatsink (clickable → board)
  makeComp({type:'chip',x:-2,z:11,w:4,d:4,h:0.9,color:0x1a2233,glow:0xb06bff,short:'Chipset',
    info:{kind:'Motherboard',title:(hw.board.brand?hw.board.brand+' ':'')+(hw.board.product||'Mainboard'),rows:hw.board.specs||[],links:hw.board}});
  // PCIe cards (net/audio) — lower slots
  pcie.slice(0,3).forEach((p,i)=>{ makeComp({type:'pcie',metric:p.kind==='Network'?'net':'',x:-10+i*4,z:13,w:3,d:1,h:2.2,color:0x121a2b,glow:0x66e0ff,short:p.kind,
    info:{kind:'PCIe · '+p.kind,title:p.name,rows:p.specs||[],links:p}}); });

  // data currents (PSU→CPU, CPU→RAM, PSU→GPU)
  makeCurrent([new THREE.Vector3(14,1,-12),new THREE.Vector3(2,1,-9),new THREE.Vector3(-3,1.4,-9)],0x39e1ff);      // 24-pin → CPU
  makeCurrent([new THREE.Vector3(-3,1.4,-9),new THREE.Vector3(4,2,-8),new THREE.Vector3(8,4,-8)],0xff5ce0);        // CPU → RAM
  makeCurrent([new THREE.Vector3(14,1,-12),new THREE.Vector3(6,1,-2),new THREE.Vector3(0,2,6)],0x2ee6c0);          // PSU → GPU
  makeCurrent([new THREE.Vector3(-3,1.4,-9),new THREE.Vector3(-2,1,2),new THREE.Vector3(-2,1,11)],0xb06bff);       // CPU → chipset
  applyLive();
}

// map live temps onto components (colour + label) + tint currents by load
function tempFor(keys){ if(!keys||!LIVE)return null; const T=(LIVE.temps||[]); let best=null;
  if(keys.includes('gpu')&&LIVE.gpu_temp!=null) best=LIVE.gpu_temp;
  T.forEach(t=>{ const n=(t.name||'').toLowerCase(); if(keys.some(k=>n.includes(k))){ if(best==null||t.val>best)best=t.val; } });
  return best; }
function grade(t){ return t==null?'':(t<60?'ok':t<80?'warn':'crit'); }
// pull any LHM sensor bucket (loads/clocks/powers/voltages/fans/data) whose name matches a component's keys
function sensorsFor(bucket,keys){ if(!keys)return []; return (LIVE[bucket]||[]).filter(x=>{ const n=(x.name||'').toLowerCase(); return keys.some(k=>n.includes(k)); }); }
function gradePct(p){ return p==null?'':(p<70?'ok':p<90?'warn':'crit'); }
const fmtBps=b=>b==null?'—':(b>1e6?(b/1e6).toFixed(1)+' MB/s':(b/1e3).toFixed(0)+' KB/s');
// per-component live metric → {txt,grade,load 0..1} pulled from LIVE
function liveMetric(c){
  switch(c.metric){
    case 'cpu':  { const p=LIVE.cpu; return {txt:p!=null?Math.round(p)+'%':'', g:gradePct(p), load:(p||0)/100}; }
    case 'ram':  { const p=LIVE.ram_pct; return {txt:p!=null?Math.round(p)+'%':'', g:gradePct(p), load:(p||0)/100}; }
    case 'gpu':  { const p=LIVE.gpu; return {txt:p!=null?Math.round(p)+'%':'', g:gradePct(p), load:(p||0)/100}; }
    case 'net':  { const n=LIVE.net; return {txt:n!=null?fmtBps(n):'', g:'ok', load:Math.min(1,(n||0)/6e6)}; }
    case 'disktemp': { const t=tempFor(c.tempKeys); return {txt:t!=null?Math.round(t)+'°':'', g:grade(t), load:t!=null?Math.min(1,Math.max(0,(t-35)/45)):0}; }
    default: { const t=tempFor(c.tempKeys); return {txt:t!=null?Math.round(t)+'°':'', g:grade(t), load:t!=null?Math.min(1,Math.max(0,(t-40)/45)):0}; }
  }
}
// ── real cooling fans on the board — one spinning 3D fan per live sensor fan, red + "STOPPED" if 0 RPM ──
function makeFan3D(){ const g=new THREE.Group();
  const ring=new THREE.Mesh(new THREE.TorusGeometry(1.15,0.09,10,40), new THREE.MeshBasicMaterial({color:0x39e1ff})); g.add(ring);
  const hub=new THREE.Mesh(new THREE.CylinderGeometry(0.22,0.22,0.2,16), new THREE.MeshStandardMaterial({color:0x0b1220,metalness:.6,roughness:.4})); hub.rotation.x=Math.PI/2; g.add(hub);
  const blades=new THREE.Group(); for(let i=0;i<7;i++){ const b=new THREE.Mesh(new THREE.BoxGeometry(0.9,0.34,0.03), new THREE.MeshBasicMaterial({color:0x8bf3ff,transparent:true,opacity:.6})); const a=i/7*Math.PI*2; b.position.set(Math.cos(a)*0.55,Math.sin(a)*0.55,0); b.rotation.z=a+0.6; blades.add(b); } g.add(blades);
  g.userData.blades=blades; g.userData.ring=ring; return g; }
function syncFans(){ if(!FANGROUP)return; const fans=LIVE.fans||[];
  while(FANS.length<fans.length){ const grp=makeFan3D(); FANGROUP.add(grp); const el=document.createElement('div'); el.className='plab'; el.innerHTML='<div class="pn"></div><div class="pv"></div>'; $('#pclabels').appendChild(el); FANS.push({grp,el,pn:el.querySelector('.pn'),pv:el.querySelector('.pv')}); }
  while(FANS.length>fans.length){ const f=FANS.pop(); FANGROUP.remove(f.grp); f.el.remove(); }
  const n=FANS.length, spread=Math.min(4.2, 26/Math.max(1,n));
  FANS.forEach((f,i)=>{ const d=fans[i]||{}; const rpm=d.val||0, stopped=rpm===0; f._rpm=rpm;
    f.grp.position.set((i-(n-1)/2)*spread, 1.6, 17); f.grp.scale.setScalar(Math.min(1.15,spread/3));
    const col=stopped?0xff4d6d:0x39e1ff; f.grp.userData.ring.material.color.setHex(col); f.grp.userData.blades.children.forEach(b=>b.material.color.setHex(stopped?0xff8fa3:0x8bf3ff));
    f.pn.textContent=d.name||('Fan '+(i+1)); f.pv.textContent=stopped?'⚠ STOPPED':(rpm+' RPM'); f.pv.className='pv '+(stopped?'c-crit':'c-ok');
  });
}
function applyLive(){
  syncFans();
  COMPS.forEach(c=>{
    if(c.def.empty){ return; }
    const m=liveMetric(c); c._load=m.load; c._grade=m.g;
    const t=tempFor(c.tempKeys); c._temp=t;
    // primary live value on the label (big) + temp underline
    c.pv.textContent=m.txt; c.pv.className='pv'+(m.g?(' c-'+m.g):'');
    if(c.metric && c.metric!=='disktemp' && t!=null){ c.pt.textContent=Math.round(t)+'°'; c.pt.className='pt'+(grade(t)?(' c-'+grade(t)):''); }
    else c.pt.textContent='';
    // heat colour on the body from temp; otherwise a load tint
    if(t!=null){ const hot=Math.min(1,Math.max(0,(t-45)/45)); c.body.material.emissive=new THREE.Color().setHSL(0.6-hot*0.6,1,0.5); }
    else c.body.material.emissive=new THREE.Color(c.def.glow||0x39e1ff);
  });
  updateHud();
}
// bottom live HUD — the whole machine at a glance (CPU · RAM · GPU · NET + per-drive usage bars)
function updateHud(){
  const bar=(id,pct,extra)=>{ const el=$('#hb-'+id); if(!el)return; const p=pct==null?0:Math.max(0,Math.min(100,pct)); const g=gradePct(pct); const col={ok:'#39e1ff',warn:'#f0a92c',crit:'#ff4d6d'}[g]||'#39e1ff';
    el.querySelector('.hbf').style.width=p+'%'; el.querySelector('.hbf').style.background=col; el.querySelector('.hbv').textContent=(pct==null?'—':Math.round(pct)+'%')+(extra?(' '+extra):''); };
  bar('cpu',LIVE.cpu, null);
  bar('ram',LIVE.ram_pct, LIVE.ram_total?('· '+(LIVE.ram_used/1024).toFixed(1)+'/'+(LIVE.ram_total/1024).toFixed(0)+'G'):'');
  bar('gpu',LIVE.gpu, LIVE.gpu_temp!=null?('· '+LIVE.gpu_temp+'°'):'');
  const nv=$('#hb-net'); if(nv) nv.querySelector('.hbv').textContent=fmtBps(LIVE.net);
  // per-drive usage chips
  const dv=$('#hdDrives'); if(dv){ const ds=LIVE.disks||[]; dv.innerHTML=ds.map(d=>{ const g=gradePct(d.used); const col={ok:'#39e1ff',warn:'#f0a92c',crit:'#ff4d6d'}[g]||'#39e1ff';
    return `<div class="hdrv"><span class="hdid">${esc(d.id)}</span><div class="hdbar"><span style="width:${d.used}%;background:${col}"></span></div><span class="hdpct">${d.used}%</span></div>`; }).join(''); }
}

function pickAt(){ RAY.setFromCamera(MOUSE,CAM); const hit=RAY.intersectObjects(COMPS.map(c=>c.body),false);
  if(hit.length){ const comp=COMPS.find(c=>c.body===hit[0].object); if(comp) openPanel(comp); } }
function openPanel(comp){ SEL=comp; COMPS.forEach(c=>c.group.scale.setScalar(1)); comp.group.scale.setScalar(1.08); fillPanel(comp.info); $('#pcpanel').classList.add('on'); }
function closePanel(){ SEL=null; COMPS.forEach(c=>c.group.scale.setScalar(1)); $('#pcpanel').classList.remove('on'); }
function fillPanel(info){ if(!info)return; $('#ppKind').textContent=info.kind||'component'; $('#ppTitle').textContent=info.title||'—';
  const t = SEL? SEL._temp : null; const tw=$('#ppTempWrap'); if(t!=null){ tw.style.display='flex'; $('#ppTemp').textContent=Math.round(t); $('#ppTemp').style.color={ok:'#2ee66e',warn:'#f0a92c',crit:'#ff4d6d'}[grade(t)]||'#39e1ff'; } else tw.style.display='none';
  // live metric row(s) for the selected component
  let live='';
  if(SEL && SEL.metric){ const m=liveMetric(SEL); const lbl={cpu:'Live load',ram:'Memory in use',gpu:'GPU load',net:'Throughput',disktemp:'Drive temp'}[SEL.metric];
    const col={ok:'#39e1ff',good:'#2ee66e',warn:'#f0a92c',crit:'#ff4d6d'}[m.g]||'#39e1ff';
    if(lbl && m.txt) live+=`<div class="pp-row" style="border-top:0"><span>${lbl}</span><b style="color:${col}">${esc(m.txt)}</b></div>`;
    if(SEL.metric==='gpu' && LIVE.vram_pct!=null) live+=`<div class="pp-row"><span>VRAM used</span><b>${LIVE.vram_pct}% · ${(LIVE.vram_used/1024).toFixed(1)}/${(LIVE.vram_total/1024).toFixed(0)} GB</b></div>`;
    if(SEL.metric==='ram' && LIVE.ram_total) live+=`<div class="pp-row"><span>System RAM</span><b>${(LIVE.ram_used/1024).toFixed(1)} / ${(LIVE.ram_total/1024).toFixed(0)} GB</b></div>`;
  }
  // rich LibreHardwareMonitor sensors for this component — clock · power · load · voltage · fan
  if(SEL && SEL.tempKeys){ const K=SEL.tempKeys; const R=(k,v,c)=>`<div class="pp-row"><span>${k}</span><b${c?(' style="color:'+c+'"'):''}>${esc(v)}</b></div>`;
    const mx=a=>a.length?Math.max(...a.map(x=>x.val)):null, sum=a=>a.reduce((s,x)=>s+(x.val||0),0);
    const clk=mx(sensorsFor('clocks',K)); if(clk) live+=R('Clock',Math.round(clk)+' MHz');
    const pw=sensorsFor('powers',K); if(pw.length) live+=R('Power',Math.round(sum(pw))+' W');
    const ld=mx(sensorsFor('loads',K)); if(ld!=null && SEL.metric!=='cpu' && SEL.metric!=='gpu' && SEL.metric!=='ram') live+=R('Load',Math.round(ld)+'%');
    const vo=sensorsFor('voltages',K); if(vo.length) live+=R('Voltage',vo[0].val.toFixed(3)+' V');
    const fn=mx(sensorsFor('fans',K)); if(fn) live+=R('Fan',Math.round(fn)+' RPM');
  }
  $('#ppRows').innerHTML=live+(info.rows||[]).filter(r=>r[1]!==''&&r[1]!=null&&r[1]!==undefined).map(r=>`<div class="pp-row"><span>${esc(r[0])}</span><b>${esc(r[1])}</b></div>`).join('')||'<div class="pp-row"><span>No details</span><b>—</b></div>';
  const lk=info.links; let h='';
  if(lk){ if(lk.vendor_url) h+=`<a href="${esc(lk.vendor_url)}" target="_blank" rel="noopener"><i class="fa-solid fa-globe"></i> Manufacturer page</a>`;
    if(lk.spec_url) h+=`<a href="${esc(lk.spec_url)}" target="_blank" rel="noopener"><i class="fa-solid fa-file-lines"></i> Full specifications</a>`;
    if(lk.img_url) h+=`<a href="${esc(lk.img_url)}" target="_blank" rel="noopener"><i class="fa-solid fa-image"></i> Real product photos</a>`; }
  $('#ppLinks').innerHTML=h;
  $('#ppNote').textContent = t!=null?'Live temperature updates every 4s from the rig\'s sensors.':'';
}

function glLoop(){
  requestAnimationFrame(glLoop); if(!RN)return;
  ctl.az+=(ctl.taz-ctl.az)*0.1; ctl.pol+=(ctl.tpol-ctl.pol)*0.1; ctl.rad+=(ctl.trad-ctl.rad)*0.1;
  CAM.position.set(Math.sin(ctl.az)*Math.cos(ctl.pol)*ctl.rad, Math.sin(ctl.pol)*ctl.rad, Math.cos(ctl.az)*Math.cos(ctl.pol)*ctl.rad); CAM.lookAt(0,0,0);
  // hover highlight
  if(!ctl.drag){ RAY.setFromCamera(MOUSE,CAM); const hit=RAY.intersectObjects(COMPS.map(c=>c.body),false); const h=hit.length?COMPS.find(c=>c.body===hit[0].object):null;
    if(h!==HOVER){ if(HOVER&&HOVER!==SEL)HOVER.group.scale.setScalar(1); HOVER=h; if(h&&h!==SEL)h.group.scale.setScalar(1.05); $('#pcgl').classList.toggle('hot',!!h); } }
  // spin gpu fans + ram leds pulse
  const t=performance.now?0:0; const now=Date.now()*0.001;
  // currents flow — faster with load
  const load=Math.min(1,((LIVE.cpu||0)+(LIVE.gpu||0))/160); const spd=0.06+load*0.5;
  CUR.forEach(c=>{ c.off=(c.off+spd*0.016)%1; const pos=c.pts.geometry.attributes.position, a=pos.array, seg=c.path.length-1;
    for(let i=0;i<c.N;i++){ let f=(c.off + i/c.N)%1; const s=Math.min(seg-1,Math.floor(f*seg)); const lf=f*seg-s; const p0=c.path[s],p1=c.path[s+1];
      a[i*3]=p0.x+(p1.x-p0.x)*lf; a[i*3+1]=p0.y+(p1.y-p0.y)*lf+Math.sin(now*3+i)*0.05; a[i*3+2]=p0.z+(p1.z-p0.z)*lf; } pos.needsUpdate=true; });
  // project labels
  const W=innerWidth,H=innerHeight, v=new THREE.Vector3();
  COMPS.forEach(c=>{
    if(!c.def.empty){ const ld=c._load||0;
      c.body.material.emissiveIntensity=0.12+ld*0.7+Math.sin(now*3+c.def.x)*0.06*ld;       // pulse harder under load
      const halo=c.group.userData.halo; if(halo) halo.material.opacity=0.04+ld*0.24;
      const fans=c.group.userData.fans; if(fans){ const spd=0.05+ld*0.55; fans.forEach(f=>f.rotation.z+=spd); }  // GPU fans spin with util
      const led=c.group.userData.led; if(led) led.material.color.set(c.group.userData.ledHue).offsetHSL(Math.sin(now*0.7+c.def.x)*0.06,0,ld*0.12);
    }
    v.setFromMatrixPosition(c.group.matrixWorld); v.y+=c.def.h/2+0.6; v.project(CAM);
    const px=(v.x*0.5+0.5)*W, py=(-v.y*0.5+0.5)*H; const vis=v.z<1;
    c.el.style.opacity=vis?(c.def.empty?'0.35':'1'):'0'; c.el.style.transform='translate(-50%,-50%) translate('+px.toFixed(1)+'px,'+py.toFixed(1)+'px)'; });
  // spin + label the cooling fans
  FANS.forEach(f=>{ const bl=f.grp.userData.blades, rpm=f._rpm||0; if(bl) bl.rotation.z += rpm>0?(0.05+Math.min(1,rpm/2600)*0.5):0;
    v.setFromMatrixPosition(f.grp.matrixWorld); v.y+=1.5; v.project(CAM); const px=(v.x*0.5+0.5)*W, py=(-v.y*0.5+0.5)*H;
    f.el.style.opacity=v.z<1?'1':'0'; f.el.style.transform='translate(-50%,-50%) translate('+px.toFixed(1)+'px,'+py.toFixed(1)+'px)'; });
  RN.render(SC,CAM);
}
// ── Diagnostics — run the read-only SSH health battery + render the report ──
async function runDiag(){ if(!RIG){ alert('Pick a rig first'); return; }
  $('#pcdiag').classList.add('on'); $('#dgBody').innerHTML='<div class="dg-load"><div class="sp"></div><div>Running read-only checks over SSH…<br>(SMART · crashes · devices · GPU · thermals)</div></div>';
  const b=$('#diagBtn'); b.disabled=true;
  try{ const r=await fetch('?api=diag&rig='+RIG).then(r=>r.json());
    if(!r.ok){ $('#dgBody').innerHTML='<div class="dgc crit"><div class="t"><span class="dot crit"></span>'+esc(r.error||'failed')+'</div></div>'; b.disabled=false; return; }
    const words={ok:'All healthy ✓',warn:'Needs attention',crit:'Problems found'};
    let h='<div class="dg-score"><span class="b '+esc(r.overall)+'">'+words[r.overall]+(r.crit||r.warn?('  ·  '+(r.crit?r.crit+' critical ':'')+(r.warn?r.warn+' warning':'')):'')+'</span></div>';
    h+=(r.checks||[]).map(c=>{ const dl=(c.detail||[]).map(d=>'<div>'+esc(d)+'</div>').join('');
      return '<div class="dgc '+(c.status==='crit'?'crit':c.status==='warn'?'warn':'')+'"><div class="t"><span class="dot '+esc(c.status)+'"></span>'+esc(c.label)+'</div><div class="sm">'+esc(c.summary)+'</div>'+(dl?'<div class="dl">'+dl+'</div>':'')+'</div>'; }).join('');
    $('#dgBody').innerHTML=h||'<div class="sm" style="color:#8fa8ca">No checks returned.</div>';
  }catch(e){ $('#dgBody').innerHTML='<div class="dgc crit"><div class="t"><span class="dot crit"></span>error running diagnostics</div></div>'; }
  b.disabled=false;
}
function closeDiag(){ $('#pcdiag').classList.remove('on'); }
addEventListener('keydown',e=>{ if(e.key==='Escape'){ if($('#pcdiag').classList.contains('on'))closeDiag(); else if($('#pcpanel').classList.contains('on'))closePanel(); else if(document.fullscreenElement)document.exitFullscreen(); } });

try{ if(window.NMNetBG) NMNetBG.init({ color:'#4da3ff', density:0.85, linkDist:150, mouseDist:180 }); }catch(e){}
initGL(); loadRigs();
</script>
</body></html>
