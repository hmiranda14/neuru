<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — HARDWARE LONGEVITY · Health Passport. A full-WebGL, cumulative wear &
// lifespan view of the gamer's rig: SSD/NVMe NAND endurance (real SMART), thermal
// stress, VRM power-delivery stress, and fan bearing wear — accumulated over time,
// projected honestly. Central health core + 4 orbiting subsystem gauges, a shareable
// passport, and a maintenance forecast. Standard dark gaming layout. RBAC 'gaming'.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_wearlife.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'gaming')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=gaming'); exit;
}

if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if (function_exists('session_write_close')) @session_write_close();
    if ($api === 'rigs') {
        $rows = function_exists('nm_win_hosts') ? nm_win_hosts($conn) : [];
        echo json_encode(['ok'=>true,'rigs'=>array_map(fn($r)=>['id'=>(int)$r['id'],'name'=>$r['name']??('rig '.$r['id'])], $rows)]);
        exit;
    }
    // passport publish + management are rig-independent (operate on a cert / Portal id) → no rig gate
    if ($api === 'publish') {
        $cid = preg_replace('/[^A-Za-z0-9\-]/','', (string)($_POST['cert'] ?? $_GET['cert'] ?? ''));
        $pass = (string)($_POST['password'] ?? '');
        echo json_encode($cid!=='' ? nm_wl_cert_publish($conn,$cid,$pass) : ['ok'=>false,'error'=>'no cert id']); exit;
    }
    if ($api === 'shared') { echo json_encode(nm_wl_cert_shared_list($conn)); exit; }
    if ($api === 'revoke') { $pid=preg_replace('/[^A-Za-z0-9\-]/','', (string)($_POST['id'] ?? '')); echo json_encode($pid!==''?nm_wl_cert_revoke($conn,$pid):['ok'=>false,'error'=>'no id']); exit; }
    if ($api === 'setpass') { $pid=preg_replace('/[^A-Za-z0-9\-]/','', (string)($_POST['id'] ?? '')); $pw=(string)($_POST['password'] ?? ''); echo json_encode($pid!==''?nm_wl_cert_setpass($conn,$pid,$pw):['ok'=>false,'error'=>'no id']); exit; }
    $rid = (int)($_GET['rig'] ?? 0);
    if (!$rid) { echo json_encode(['ok'=>false,'error'=>'Pick a rig first.']); exit; }
    if ($api === 'passport') { echo json_encode(nm_wl_passport($conn,$rid)); exit; }
    if ($api === 'scan') {
        $h = function_exists('nm_win_host') ? nm_win_host($conn,$rid) : null;
        if (!$h) { echo json_encode(['ok'=>false,'error'=>'Rig not found.']); exit; }
        $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn,$h) : null;
        if (!$ssh) { echo json_encode(['ok'=>false,'error'=>'This rig has no SSH configured — add credentials in the Windows monitor.']); exit; }
        log_user_action($conn,'longevity_scan','rig '.$rid);
        echo json_encode(nm_wl_scan($conn,$rid,$ssh)); exit;
    }
    if ($api === 'cert') {
        $h = function_exists('nm_win_host') ? nm_win_host($conn,$rid) : null;
        $name = $h['name'] ?? '';
        $r = nm_wl_cert_issue($conn,$rid,(string)$name);
        if (!empty($r['ok'])) $r['url'] = 'passport.php?cert='.$r['id'];
        echo json_encode($r); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'unknown endpoint']); exit;
}

$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
include('header.php'); nm_gamers_hub_pill();
?>
<video autoplay muted loop playsinline id="bg-video" style="position:fixed;inset:0;z-index:-3;object-fit:cover;min-width:100%;min-height:100%;opacity:.07"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<script src="/three.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --cy:#39e1ff; --pk:#b06bff; --gr:#7CFFB2; --gd:#ffcf6b; --rd:#ff7a9c; --td:#36e3d0; --bd:rgba(120,150,255,.16); }
*,*::before,*::after{ box-sizing:border-box; }
html{ background:#04060d; }
body{ margin:0; background:#04060d !important; color:#e6ecf7; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; overflow-x:hidden; }
#nm-netbg{ z-index:0 !important; opacity:.5; }
<?= function_exists('nm_chrome_css') ? nm_chrome_css() : '' ?>
.lg{ max-width:1240px; margin:0 auto; padding:16px 20px 70px; position:relative; z-index:1; }
.lg-head{ display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
.lg-head h1{ margin:0; font-size:25px; font-weight:900; display:flex; align-items:center; gap:12px; }
.lg-head h1 i{ color:var(--gr); }
.ctrls{ margin-left:auto; display:flex; align-items:center; gap:9px; flex-wrap:wrap; }
.ctrls select{ background:rgba(6,12,24,.7); border:1px solid var(--bd); color:#dfeeff; border-radius:10px; padding:9px 12px; font-size:13px; }
.runbtn{ display:inline-flex; align-items:center; gap:9px; border:0; cursor:pointer; font-weight:800; font-size:14px; color:#04121f; padding:11px 18px; border-radius:12px; background:linear-gradient(90deg,var(--gr),#a7ffcf); box-shadow:0 6px 22px rgba(124,255,178,.3); transition:.15s; }
.runbtn:hover{ transform:translateY(-2px); } .runbtn:disabled{ opacity:.55; cursor:default; transform:none; }
.lg-sub{ color:#9fb0d8; font-size:13px; margin:5px 0 14px; }
.glass{ background:rgba(10,14,30,.5); backdrop-filter:blur(14px); border:1px solid var(--bd); border-radius:18px; }
.hero{ display:grid; grid-template-columns:1.5fr .9fr; gap:16px; align-items:stretch; }
@media(max-width:920px){ .hero{ grid-template-columns:1fr; } }
#reactor{ position:relative; height:520px; overflow:hidden; }
#reactor:fullscreen{ height:100vh; width:100vw; border-radius:0; background:#04060d; }
#lgGL{ width:100%; height:100%; display:block; cursor:grab; } #lgGL.drag{ cursor:grabbing; }
/* In-fullscreen overlays: run control (top) + full results panel (right). Hidden windowed. */
#glTop,#glPanel{ display:none; }
#reactor:fullscreen #glTop{ display:flex; position:absolute; top:14px; left:16px; z-index:9; align-items:center; gap:9px; flex-wrap:wrap; max-width:56%; }
#reactor:fullscreen #glTop .runbtn{ padding:9px 15px; font-size:13px; }
#reactor:fullscreen #glPanel{ display:block; position:absolute; top:14px; right:14px; bottom:44px; width:370px; max-width:44%; overflow-y:auto; padding:14px 15px; border-radius:14px; background:rgba(8,13,28,.88); border:1px solid var(--bd); box-shadow:0 10px 30px rgba(0,0,0,.5); z-index:8; }
#reactor:fullscreen #gradeOv{ align-items:flex-start; justify-content:center; padding-left:6%; }
#glPanel .pt{ font-size:19px; font-weight:900; } #glPanel .pm{ font-size:11.5px; color:#c3d3ee; line-height:1.5; margin-top:3px; }
#glPanel h4{ margin:12px 0 4px; font-size:11px; letter-spacing:.5px; text-transform:uppercase; color:#8fa4c8; }
#glPanel .prow{ display:flex; align-items:center; gap:8px; margin-top:8px; }
#glPanel .prow .pk{ font-size:11px; font-weight:800; width:64px; } #glPanel .prow .pv{ font-size:13px; font-weight:900; width:32px; text-align:right; }
#glPanel .prow .pb{ flex:1; height:7px; border-radius:6px; background:rgba(255,255,255,.08); overflow:hidden; } #glPanel .prow .pb i{ display:block; height:100%; border-radius:6px; }
#glPanel .pf{ margin-top:8px; padding-top:8px; border-top:1px dashed rgba(120,150,255,.14); font-size:11.5px; color:#c3d3ee; line-height:1.5; } #glPanel .pf b{ color:#eaf2ff; }
.mapbtns{ position:absolute; top:14px; right:14px; display:flex; gap:8px; z-index:9; }
.mapbtn{ background:rgba(10,16,34,.72); border:1px solid var(--bd); color:#dbe9ff; border-radius:10px; padding:8px 11px; font-size:12px; font-weight:700; cursor:pointer; display:inline-flex; align-items:center; gap:7px; transition:.15s; }
.mapbtn:hover{ border-color:var(--gr); color:#fff; }
#gradeOv{ position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; pointer-events:none; text-align:center; }
#gradeOv .big{ font-size:74px; font-weight:900; line-height:.95; color:#fff; text-shadow:0 0 30px rgba(124,255,178,.5); }
#gradeOv .max{ font-size:13px; color:#8fa4c8; letter-spacing:1px; }
#gradeOv .tier{ margin-top:11px; font-size:14px; font-weight:900; padding:6px 15px; border-radius:999px; display:none; }
#gradeOv .idle{ font-size:14px; color:#9fb0d8; max-width:72%; }
#mapTip{ position:absolute; pointer-events:none; z-index:8; background:rgba(6,12,26,.92); border:1px solid var(--bd); border-radius:10px; padding:7px 11px; font-size:12px; color:#eaf2ff; transform:translate(-50%,-140%); opacity:0; transition:opacity .12s; white-space:nowrap; }
#legend{ position:absolute; left:0; right:0; bottom:0; display:flex; gap:14px; flex-wrap:wrap; justify-content:center; padding:8px 12px; background:linear-gradient(0deg,rgba(4,6,13,.85),transparent); font-size:11px; color:#9fb0d8; pointer-events:none; }
#legend i.d{ width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:5px; }
.runside{ display:flex; flex-direction:column; gap:14px; }
.console{ padding:16px 18px; flex:1; }
.console h3{ margin:0 0 6px; font-size:14px; font-weight:800; display:flex; align-items:center; gap:8px; }
.console .hs{ font-size:11.5px; color:#8fa4c8; line-height:1.55; }
.obs{ margin-top:12px; font-size:12px; color:#c3d3ee; } .obs b{ color:#eaf2ff; }
.tierbanner{ margin-top:16px; padding:16px 20px; display:none; align-items:center; gap:16px; flex-wrap:wrap; border-left:4px solid var(--gr); }
.tierbanner .tk{ font-size:30px; font-weight:900; } .tierbanner .tt{ font-size:12.5px; color:#d7e3f7; line-height:1.5; flex:1; min-width:240px; }
.grid4{ display:grid; grid-template-columns:repeat(auto-fit,minmax(270px,1fr)); gap:14px; margin-top:16px; }
.sub{ padding:16px 17px; }
.sub .sh{ display:flex; align-items:center; gap:10px; }
.sub .si{ width:34px; height:34px; border-radius:10px; display:grid; place-items:center; font-size:15px; }
.sub .sn{ font-size:14px; font-weight:800; } .sub .badge{ font-size:9.5px; font-weight:800; padding:2px 7px; border-radius:999px; margin-left:6px; text-transform:uppercase; letter-spacing:.4px; }
.badge.measured{ background:rgba(124,255,178,.16); color:#7CFFB2; } .badge.estimate{ background:rgba(255,207,107,.16); color:#ffcf6b; }
.sub .sv{ margin-left:auto; font-size:22px; font-weight:900; font-variant-numeric:tabular-nums; }
.sub .bar{ height:8px; border-radius:6px; background:rgba(255,255,255,.07); margin-top:9px; overflow:hidden; }
.sub .bar i{ display:block; height:100%; border-radius:6px; width:0; transition:width 1s cubic-bezier(.2,.8,.2,1); }
.sub .sd{ font-size:12px; color:#cdd9ef; margin-top:9px; line-height:1.5; }
.sub .sp{ font-size:12px; margin-top:7px; line-height:1.5; } .sub .sp.warn{ color:#ffcf6b; } .sub .sp.ok{ color:#9ef0c4; }
.sub .se{ font-size:11px; color:#8fa4c8; margin-top:6px; }
.section-h{ margin:22px 2px 10px; font-size:15px; font-weight:800; display:flex; align-items:center; gap:9px; color:#eaf2ff; }
.maint{ display:flex; flex-direction:column; gap:9px; }
.mrow{ padding:12px 15px; display:flex; gap:12px; align-items:flex-start; border-left:3px solid var(--gd); font-size:12.5px; color:#d7e3f7; line-height:1.5; }
.mrow i{ color:var(--gd); font-size:16px; margin-top:1px; }
.err{ display:none; margin-top:14px; padding:13px 16px; border-radius:12px; background:rgba(255,90,122,.1); border:1px solid rgba(255,90,122,.35); color:#ffb4c2; font-size:13px; }
.muted{ color:#8fa4c8; }
/* share / passport card */
#shareCard{ display:none; margin-top:16px; padding:18px 20px; border-left:4px solid var(--gd); }
#shareCard h3{ margin:0 0 4px; font-size:15px; font-weight:900; display:flex; align-items:center; gap:9px; }
#shareCard .cid{ font-family:monospace; font-size:13px; color:#ffcf6b; letter-spacing:1px; }
#shareCard .row{ display:flex; gap:9px; flex-wrap:wrap; align-items:center; margin-top:12px; }
#shareCard input{ background:rgba(6,12,24,.7); border:1px solid var(--bd); color:#dfeeff; border-radius:10px; padding:9px 12px; font-size:13px; }
#shareCard .sbtn{ display:inline-flex; align-items:center; gap:7px; cursor:pointer; border:0; font-weight:800; font-size:13px; color:#04121f; background:linear-gradient(90deg,var(--gd),#ffe0a3); border-radius:10px; padding:9px 15px; }
#shareCard .lbtn{ display:inline-flex; align-items:center; gap:7px; cursor:pointer; text-decoration:none; border:1px solid var(--bd); background:rgba(10,16,34,.6); color:#dbe9ff; border-radius:10px; padding:9px 15px; font-size:13px; font-weight:700; }
#shareCard .hint{ font-size:11.5px; color:#8fa4c8; margin-top:8px; line-height:1.5; }
#shareOut{ display:none; margin-top:12px; padding:12px 14px; border-radius:12px; background:rgba(124,255,178,.06); border:1px solid rgba(124,255,178,.3); font-size:12.5px; color:#d7e3f7; line-height:1.6; }
#shareOut code{ background:rgba(120,150,255,.14); padding:2px 8px; border-radius:6px; color:#cfe4ff; word-break:break-all; }
</style>

<div class="lg">
  <div class="lg-head">
    <h1><i class="fa-solid fa-heart-pulse"></i> Hardware Longevity</h1>
    <div class="ctrls">
      <span class="muted" style="font-size:12px">Rig</span>
      <select id="rigSel"><option>Loading…</option></select>
      <button class="runbtn" id="scanBtn" onclick="scan()"><i class="fa-solid fa-stethoscope"></i> Scan now</button>
      <button class="mapbtn" id="certBtn" onclick="genCert()" title="Generate a shareable, data-backed NEURU System Passport — a re-sell certificate of this rig's real recorded history."><i class="fa-solid fa-certificate"></i> Passport</button>
    </div>
  </div>
  <div class="lg-sub">A living <b>Health Passport</b> for your rig. NEURU accumulates real telemetry over time — SSD write-wear (SMART), thermal &amp; power-stress hours, fan RPM — and projects what's aging and when to service it. <b>Runs longer = smarter projections.</b></div>

  <div class="hero">
    <div class="glass" id="reactor">
      <canvas id="lgGL"></canvas>
      <div class="mapbtns"><button class="mapbtn" id="fsBtn" title="Fullscreen"><i class="fa-solid fa-expand"></i> Fullscreen</button></div>
      <div id="glTop">
        <select id="rigSelFs" onchange="setRig(this.value)"></select>
        <button class="runbtn" id="scanBtnFs" onclick="scan()"><i class="fa-solid fa-stethoscope"></i> Scan now</button>
      </div>
      <div id="glPanel"></div>
      <div id="gradeOv">
        <div class="idle" id="ovIdle"><i class="fa-solid fa-heart-pulse" style="font-size:32px;color:var(--gr)"></i><br><br>Pick a rig &amp; hit <b>Scan now</b>.<br>Your longevity grade builds here over time.</div>
        <div class="big" id="ovGrade" style="display:none">—</div>
        <div class="max" id="ovMax" style="display:none">LONGEVITY GRADE</div>
        <div class="tier" id="ovTier"></div>
      </div>
      <div id="mapTip"></div>
      <div id="legend">
        <span><i class="d" style="background:#7CFFB2"></i>SSD/NVMe</span>
        <span><i class="d" style="background:#ff7a9c"></i>Thermal</span>
        <span><i class="d" style="background:#ffcf6b"></i>VRM/Power</span>
        <span><i class="d" style="background:#36e3d0"></i>Fans</span>
        <span class="muted">ring = health · size = health</span>
      </div>
    </div>
    <div class="runside">
      <div class="glass console">
        <h3><i class="fa-solid fa-clipboard-check" style="color:var(--gr)"></i> How this works</h3>
        <div class="hs">Every scan (or the background cron) takes a snapshot of your rig's sensors and folds it into a running total. <b>SSD wear</b> is read straight from SMART — that projection is real. <b>Thermal / VRM / fan</b> wear can't be measured directly, so NEURU tracks your <b>exposure</b> (hours in hot / full-power / high-RPM zones) and flags it honestly as an estimate.</div>
        <div class="obs" id="obsBox"></div>
      </div>
      <div class="glass console" id="hwBox" style="display:none">
        <h3><i class="fa-solid fa-microchip" style="color:var(--cy)"></i> Rig</h3>
        <div class="hs" id="hwInfo"></div>
      </div>
    </div>
  </div>

  <div class="glass" id="shareCard">
    <h3><i class="fa-solid fa-certificate" style="color:var(--gd)"></i> System Passport issued — <span class="cid" id="scId"></span></h3>
    <div class="muted" style="font-size:12.5px;margin-top:2px">A frozen, tamper-evident snapshot of this rig's real recorded history. The figures are built server-side from NEURU's telemetry — they can't be edited.</div>
    <div class="row">
      <a class="lbtn" id="scView" href="#" target="_blank"><i class="fa-solid fa-eye"></i> View certificate</a>
    </div>
    <div class="row" style="margin-top:14px;border-top:1px dashed rgba(120,150,255,.14);padding-top:14px">
      <div style="width:100%;font-size:12.5px;color:#c3d3ee;margin-bottom:4px"><b>Share with a buyer (external):</b> publish it to the NEURU Portal (public, always-on) behind a password only they'll know.</div>
      <input type="password" id="scPass" placeholder="Set a password for the buyer" maxlength="64">
      <button class="sbtn" id="scPub" onclick="publishCert()"><i class="fa-solid fa-cloud-arrow-up"></i> Publish &amp; share</button>
    </div>
    <div class="hint">The buyer opens the Portal link and enters this password — no NEURU login needed, and your home NEURU stays private (nothing exposed to the internet).</div>
    <div id="shareOut"></div>
  </div>

  <div class="glass" id="sharedMgr" style="display:none;margin-top:16px;padding:16px 20px">
    <h3 style="margin:0 0 4px;font-size:15px;font-weight:900;display:flex;align-items:center;gap:9px"><i class="fa-solid fa-share-nodes" style="color:var(--cy)"></i> Shared passports <span class="muted" style="font-size:12px;font-weight:400">— published to the NEURU Portal</span></h3>
    <div class="muted" style="font-size:12px;margin-bottom:8px">Manage the links you shared with buyers — see views, change a password, or revoke (removes it from the Portal).</div>
    <div id="sharedList"></div>
  </div>

  <div class="glass tierbanner" id="tierBanner">
    <div class="tk" id="tbK"></div>
    <div><div style="font-size:16px;font-weight:900" id="tbName"></div><div class="tt" id="tbMean"></div></div>
  </div>

  <div class="grid4" id="subs"></div>

  <div class="section-h" id="maintH" style="display:none"><i class="fa-solid fa-calendar-check" style="color:var(--gd)"></i> Maintenance forecast</div>
  <div class="maint" id="maint"></div>
  <div class="err" id="err"></div>
</div>

<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const SKEY={nand:'#7CFFB2',thermal:'#ff7a9c',vrm:'#ffcf6b',fan:'#36e3d0'};
const ORDER=['nand','thermal','vrm','fan'];
let RIG='', GL=null, RUNNING=false;

function setRig(v){ RIG=v; const a=document.getElementById('rigSel'),b=document.getElementById('rigSelFs'); if(a&&a.value!==v)a.value=v; if(b&&b.value!==v)b.value=v; loadPassport(); }
async function loadRigs(){
  try{ const d=await fetch('longevity.php?api=rigs').then(r=>r.json());
    const opts=(d.ok&&d.rigs.length)?d.rigs.map(r=>`<option value="${r.id}">${esc(r.name)}</option>`).join(''):'<option value="">No rigs</option>';
    document.getElementById('rigSel').innerHTML=opts; const fs=document.getElementById('rigSelFs'); if(fs) fs.innerHTML=opts;
    if(d.ok&&d.rigs.length){ setRig(document.getElementById('rigSel').value); }
    else { ['scanBtn','scanBtnFs'].forEach(id=>{ const b=document.getElementById(id); if(b) b.disabled=true; }); }
  }catch(e){}
}
document.getElementById('rigSel').addEventListener('change',e=>setRig(e.target.value));

async function loadPassport(){
  if(!RIG) return;
  let d; try{ d=await fetch(`longevity.php?api=passport&rig=${RIG}&_=${Date.now()}`).then(r=>r.json()); }catch(e){ return; }
  if(d&&d.ok) render(d,true);
}
function setScanBtns(disabled,html){ ['scanBtn','scanBtnFs'].forEach(id=>{ const b=document.getElementById(id); if(b){ b.disabled=disabled; b.innerHTML=html; } }); }
async function scan(){
  if(!RIG||RUNNING) return; RUNNING=true;
  setScanBtns(true,'<i class="fa-solid fa-spinner fa-spin"></i> Scanning…');
  document.getElementById('err').style.display='none'; if(GL) GL.spinUp();
  let d; try{ d=await fetch(`longevity.php?api=scan&rig=${RIG}&_=${Date.now()}`).then(r=>r.json()); }catch(e){ d={ok:false,error:'Network error contacting the rig.'}; }
  RUNNING=false; setScanBtns(false,'<i class="fa-solid fa-rotate-right"></i> Scan again');
  if(!d.ok){ const e=document.getElementById('err'); e.textContent='⚠ '+(d.error||'Scan failed.'); e.style.display='block'; if(GL) GL.idle(); return; }
  render(d,false);
}

function render(d,quiet){
  const subs=d.subsystems||[];
  // WebGL
  if(GL) GL.setResult(subs, d.tier?d.tier[2]:'#7CFFB2');
  // grade overlay
  document.getElementById('ovIdle').style.display=(d.grade==null)?'block':'none';
  document.getElementById('ovGrade').style.display=(d.grade==null)?'none':'block';
  document.getElementById('ovMax').style.display=(d.grade==null)?'none':'block';
  if(d.grade!=null){
    const el=document.getElementById('ovGrade'); if(!quiet){ const t0=performance.now(); (function up(t){ const k=Math.min(1,(t-t0)/1200); el.textContent=Math.round(d.grade*(1-Math.pow(1-k,3))); if(k<1)requestAnimationFrame(up); })(t0); } else el.textContent=d.grade;
    const ot=document.getElementById('ovTier'); if(d.tier){ ot.textContent=d.tier[0]+' · '+d.tier[1]; ot.style.display='inline-block'; ot.style.background=d.tier[2]+'22'; ot.style.color=d.tier[2]; ot.style.border='1px solid '+d.tier[2]+'66'; }
  }
  // observed + hw
  document.getElementById('obsBox').innerHTML = d.observed_hours!=null ? `Watched <b>${d.observed_hours} h</b> so far${d.first_seen?` · since ${esc((d.first_seen||'').slice(0,10))}`:''}. Keep NEURU running (or let the cron scan) for sharper projections.` : '';
  if(d.gpu&&d.gpu.name){ document.getElementById('hwBox').style.display='block'; document.getElementById('hwInfo').innerHTML=`${esc(d.gpu.name)}${d.gpu.vram?` · ${d.gpu.vram} GB VRAM`:''}`; }
  // tier banner
  const tb=document.getElementById('tierBanner');
  if(d.tier){ tb.style.display='flex'; tb.style.borderLeftColor=d.tier[2]; document.getElementById('tbK').textContent=d.tier[0]; document.getElementById('tbK').style.color=d.tier[2]; document.getElementById('tbName').textContent='Longevity: '+d.tier[1]; document.getElementById('tbMean').textContent='Composite of the measurable subsystems (SSD wear weighs most). '+(d.grade>=75?'Your rig is aging gracefully.':d.grade>=45?'Some subsystems are accumulating stress — see the forecast.':'Service is recommended soon.'); }
  else tb.style.display='none';
  // subsystem cards
  document.getElementById('subs').innerHTML=subs.map(s=>{
    const col=SKEY[s.key]||'#4da3ff'; const h=s.health; const hv=(h==null)?'—':h;
    const badge=s.measured?'<span class="badge measured">measured</span>':'<span class="badge estimate">estimate</span>';
    const pc=(s.projection||'').toLowerCase(); const pcls=/plan|nearing|heavy|high|swap|service|replace/.test(pc)?'warn':'ok';
    return `<div class="sub glass"><div class="sh">
      <div class="si" style="background:${col}22;color:${col}"><i class="fa-solid ${s.icon||'fa-cube'}"></i></div>
      <div><div class="sn">${esc(s.name)}${badge}</div></div>
      <div class="sv" style="color:${h==null?'#8fa4c8':col}">${hv}${h==null?'':'<span style="font-size:12px" class="muted">/100</span>'}</div></div>
      <div class="bar"><i data-w="${h==null?0:h}" style="background:${col};box-shadow:0 0 10px ${col}"></i></div>
      <div class="sd"><b style="color:#cfe0ff">${esc(s.value)}</b> — ${esc(s.detail)}</div>
      <div class="sp ${pcls}">${/warn/.test(pcls)?'⚠ ':'✓ '}${esc(s.projection)}</div>
      ${s.extra?`<div class="se">${esc(s.extra)}</div>`:''}
    </div>`;
  }).join('');
  requestAnimationFrame(()=>document.querySelectorAll('.sub .bar i').forEach(i=>i.style.width=(i.dataset.w||0)+'%'));
  // maintenance forecast
  const m=d.maintenance||[];
  document.getElementById('maintH').style.display=m.length?'flex':'none';
  document.getElementById('maint').innerHTML=m.map(x=>`<div class="mrow glass"><i class="fa-solid fa-screwdriver-wrench"></i><div>${esc(x)}</div></div>`).join('') || (subs.length?'<div class="mrow glass" style="border-left-color:#7CFFB2"><i class="fa-solid fa-check" style="color:#7CFFB2"></i><div>Nothing needs attention yet — your rig is in good shape. Keep scanning to stay ahead.</div></div>':'');
  renderPanel(d);   // mirror everything into the in-fullscreen overlay
}
// Compact "everything" panel shown INSIDE the WebGL fullscreen (grade + subsystems + forecast).
function renderPanel(d){
  const p=document.getElementById('glPanel'); if(!p) return; const subs=d.subsystems||[]; const tc=d.tier?d.tier[2]:'#7CFFB2';
  const rows=subs.map(s=>{ const col=SKEY[s.key]||'#4da3ff'; const h=s.health; return `<div class="prow"><span class="pk" style="color:${col}">${esc((s.name||'').replace(/ \(.*/,'').replace('SSD / NVMe','SSD'))}</span><div class="pb"><i style="width:${h==null?0:h}%;background:${col};box-shadow:0 0 8px ${col}"></i></div><span class="pv" style="color:${h==null?'#8fa4c8':col}">${h==null?'—':h}</span></div>`; }).join('');
  const fc=(d.maintenance||[]).map(x=>`<div class="pf">🔧 ${esc(x)}</div>`).join('') || (subs.length?'<div class="pf" style="color:#9ef0c4">✓ Nothing needs attention yet.</div>':'');
  p.innerHTML=`<div class="pt" style="color:${tc}">${d.tier?('Grade '+d.grade+' · '+esc(d.tier[1])):'Hardware Longevity'}</div>`
    +`<div class="pm">${d.observed_hours!=null?('Watched '+d.observed_hours+' h. '):''}${d.gpu&&d.gpu.name?esc(d.gpu.name):''}</div>`
    +`<h4>Subsystem health</h4>${rows}`
    +`<h4>Maintenance forecast</h4>${fc}`;
}

// ── WebGL health reactor: core + 4 subsystem gauge-nodes ──
function initGL(){
  const cv=document.getElementById('lgGL'); if(!window.THREE||!cv) return null;
  let W=cv.clientWidth||760,H=cv.clientHeight||520;
  const rn=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true,powerPreference:'high-performance'}); rn.setPixelRatio(Math.min(2,devicePixelRatio)); rn.setSize(W,H,false);
  const sc=new THREE.Scene(), cam=new THREE.PerspectiveCamera(55,W/H,.1,100); cam.position.set(0,1.2,27);
  const starGeo=new THREE.BufferGeometry(),SN=640,sp=new Float32Array(SN*3);
  for(let i=0;i<SN;i++){ const rr=24+Math.random()*34,a=Math.random()*Math.PI*2,b=Math.acos(2*Math.random()-1); sp[i*3]=rr*Math.sin(b)*Math.cos(a); sp[i*3+1]=rr*Math.sin(b)*Math.sin(a); sp[i*3+2]=rr*Math.cos(b); }
  starGeo.setAttribute('position',new THREE.BufferAttribute(sp,3));
  const stars=new THREE.Points(starGeo,new THREE.PointsMaterial({color:0x4da3ff,size:.13,transparent:true,opacity:.55,sizeAttenuation:true})); sc.add(stars);
  const root=new THREE.Group(); sc.add(root);
  const core=new THREE.Mesh(new THREE.IcosahedronGeometry(2.6,1),new THREE.MeshBasicMaterial({color:0x7CFFB2,wireframe:true,transparent:true,opacity:.9})); root.add(core);
  const glow=new THREE.Mesh(new THREE.IcosahedronGeometry(3.3,0),new THREE.MeshBasicMaterial({color:0x7CFFB2,wireframe:true,transparent:true,opacity:.15})); root.add(glow);
  const impGeo=new THREE.SphereGeometry(.24,8,8); let nodes=[],nodeMeshes=[],spin=1,coreCol=new THREE.Color(0x7CFFB2),SUBS=[];
  function ringLine(rad,a0,a1,col,op){ const seg=52,p=[]; for(let k=0;k<=seg;k++){ const a=a0+(a1-a0)*k/seg; p.push(new THREE.Vector3(Math.cos(a)*rad,Math.sin(a)*rad,0)); } return new THREE.Line(new THREE.BufferGeometry().setFromPoints(p),new THREE.LineBasicMaterial({color:col,transparent:true,opacity:op})); }
  function label(name,val,hex){ const c=document.createElement('canvas'); c.width=300;c.height=88; const x=c.getContext('2d'); x.font='900 40px "Segoe UI",sans-serif'; x.fillStyle=hex; x.textAlign='center'; x.shadowColor=hex; x.shadowBlur=15; x.fillText(val,150,40); x.shadowBlur=0; x.font='700 19px "Segoe UI",sans-serif'; x.fillStyle='#dbe7fb'; x.fillText(name,150,74); const tex=new THREE.CanvasTexture(c); tex.minFilter=THREE.LinearFilter; const s=new THREE.Sprite(new THREE.SpriteMaterial({map:tex,transparent:true,depthTest:false})); s.scale.set(6.2,1.82,1); return s; }
  function clearNodes(){ nodes.forEach(b=>{ root.remove(b.grp); b.grp.traverse(o=>{ if(o.geometry&&o.geometry!==impGeo)o.geometry.dispose(); if(o.material){ if(o.material.map)o.material.map.dispose(); o.material.dispose(); } }); }); nodes=[]; nodeMeshes=[]; }
  const NM={nand:'SSD',thermal:'Thermal',vrm:'VRM',fan:'Fans'};
  function build(subs){ clearNodes(); ORDER.forEach((key,i)=>{ const s=(subs||[]).find(x=>x.key===key)||{key,health:0};
      const ang=(i/4)*Math.PI*2-Math.PI/2,r=11.5,hex=SKEY[key],col=new THREE.Color(hex); const hv=(s.health==null?0:s.health)/100; const ex=Math.cos(ang)*r,ey=Math.sin(ang)*r; const grp=new THREE.Group();
      grp.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0,0,0),new THREE.Vector3(ex,ey,0)]),new THREE.LineBasicMaterial({color:col,transparent:true,opacity:.25+hv*.5})));
      const track=ringLine(2,-Math.PI/2,Math.PI*1.5,col,.12); track.position.set(ex,ey,0); grp.add(track);
      const gauge=ringLine(2,-Math.PI/2,-Math.PI/2+Math.max(.02,hv)*Math.PI*2,col,.92); gauge.position.set(ex,ey,0); grp.add(gauge);
      const node=new THREE.Mesh(new THREE.IcosahedronGeometry(.8+hv*1.4,0),new THREE.MeshBasicMaterial({color:col,wireframe:true,transparent:true,opacity:.5+hv*.5})); node.position.set(ex,ey,0); node.userData={key,name:NM[key],health:s.health}; grp.add(node); nodeMeshes.push(node);
      const lbl=label(NM[key],(s.health==null?'—':String(s.health)),hex); lbl.position.set(ex,ey+(1.6+hv*1.4)+1.2,0); grp.add(lbl);
      const imp=new THREE.Mesh(impGeo,new THREE.MeshBasicMaterial({color:hex,transparent:true,opacity:.85})); grp.add(imp);
      root.add(grp); nodes.push({grp,node,imp,ex,ey,phase:i/4}); }); }
  build([]);
  const ray=new THREE.Raycaster(),m=new THREE.Vector2(),tip=document.getElementById('mapTip'); let hov=-1,drag=false,px=0,py=0,yaw=0,pitch=-.12,autoY=true;
  cv.addEventListener('pointerdown',e=>{ drag=true;autoY=false;px=e.clientX;py=e.clientY;cv.classList.add('drag'); cv.setPointerCapture&&cv.setPointerCapture(e.pointerId); });
  addEventListener('pointerup',()=>{ drag=false; cv.classList.remove('drag'); });
  cv.addEventListener('pointermove',e=>{ const rect=cv.getBoundingClientRect(); if(drag){ yaw+=(e.clientX-px)*.008; pitch=Math.max(-1.1,Math.min(1.1,pitch+(e.clientY-py)*.006)); px=e.clientX;py=e.clientY; tip.style.opacity='0'; return; }
    m.x=((e.clientX-rect.left)/rect.width)*2-1; m.y=-((e.clientY-rect.top)/rect.height)*2+1; ray.setFromCamera(m,cam); const h=ray.intersectObjects(nodeMeshes,false);
    if(h.length){ const u=h[0].object.userData; hov=1; cv.style.cursor='pointer'; tip.innerHTML=`<b style="color:${SKEY[u.key]}">${esc(u.name)}</b> · ${u.health==null?'n/a':u.health+'/100'}`; tip.style.left=(e.clientX-rect.left)+'px'; tip.style.top=(e.clientY-rect.top)+'px'; tip.style.opacity='1'; } else { hov=-1; cv.style.cursor='grab'; tip.style.opacity='0'; } });
  cv.addEventListener('pointerleave',()=>{ tip.style.opacity='0'; });
  cv.addEventListener('wheel',e=>{ e.preventDefault(); cam.position.z=Math.max(16,Math.min(40,cam.position.z+e.deltaY*.02)); },{passive:false});
  let paused=false,raf=0; function resize(){ W=cv.clientWidth;H=cv.clientHeight; if(W&&H){ cam.aspect=W/H; cam.updateProjectionMatrix(); rn.setSize(W,H,false);} }
  addEventListener('resize',resize); document.addEventListener('fullscreenchange',()=>setTimeout(resize,60));
  document.addEventListener('visibilitychange',()=>{ paused=document.hidden; if(!paused){ cancelAnimationFrame(raf); loop(); } });
  function loop(){ if(paused) return; raf=requestAnimationFrame(loop); const t=Date.now(); stars.rotation.y+=.0004;
    core.rotation.y+=.01*spin; core.rotation.x+=.005*spin; glow.rotation.y-=.006; core.scale.setScalar(1+Math.sin(t*.004)*.05); core.material.color.lerp(coreCol,.04); glow.material.color.copy(core.material.color);
    if(autoY&&hov<0&&!drag) yaw+=.001; root.rotation.y=yaw; root.rotation.x=pitch;
    nodes.forEach(b=>{ b.node.rotation.y+=.02; b.node.rotation.x+=.01; b.phase=(b.phase+.011)%1; const f=b.phase; b.imp.position.set(b.ex*f,b.ey*f,0); b.imp.material.opacity=.85*(1-Math.abs(f-.5)*1.2); b.node.scale.setScalar(1+Math.sin(t*.005+b.ex)*.06); });
    rn.render(sc,cam); }
  loop();
  return { spinUp(){ spin=3.2; coreCol=new THREE.Color(0x7CFFB2); }, setResult(subs,tierHex){ spin=1; coreCol=new THREE.Color(tierHex); SUBS=subs; build(subs); }, idle(){ spin=1; } };
}
let CERT=null;
async function genCert(){
  if(!RIG) return; const b=document.getElementById('certBtn'); const old=b.innerHTML; b.disabled=true; b.innerHTML='<i class="fa-solid fa-spinner fa-spin"></i> Issuing…';
  try{ const r=await fetch(`longevity.php?api=cert&rig=${RIG}&_=${Date.now()}`).then(x=>x.json());
    if(r.ok&&r.id){ CERT=r.id; document.getElementById('scId').textContent=r.id; document.getElementById('scView').href=r.url;
      document.getElementById('shareOut').style.display='none'; document.getElementById('scPass').value='';
      document.getElementById('shareCard').style.display='block'; document.getElementById('shareCard').scrollIntoView({behavior:'smooth',block:'nearest'}); }
    else alert('Could not issue the passport'+(r.error?': '+r.error:'.'));
  }catch(e){ alert('Could not issue the passport.'); }
  b.disabled=false; b.innerHTML=old;
}
async function publishCert(){
  if(!CERT) return; const pass=document.getElementById('scPass').value;
  if(pass.length<4){ alert('Set a password of at least 4 characters for the buyer.'); return; }
  const b=document.getElementById('scPub'); const old=b.innerHTML; b.disabled=true; b.innerHTML='<i class="fa-solid fa-spinner fa-spin"></i> Publishing…';
  try{ const f=new FormData(); f.append('cert',CERT); f.append('password',pass);
    const r=await fetch('longevity.php?api=publish',{method:'POST',body:f}).then(x=>x.json());
    const out=document.getElementById('shareOut');
    if(r.ok&&r.url){ out.style.display='block'; out.innerHTML=`✅ <b>Published to the NEURU Portal.</b> Give the buyer BOTH:<br>· Link: <code>${esc(r.url)}</code> <a href="#" onclick="navigator.clipboard.writeText('${esc(r.url)}');this.textContent='✓ copied';return false;" style="color:#7CFFB2;margin-left:6px">copy</a><br>· Password: <code>${esc(pass)}</code> (you set this — share it privately)`; loadShared(); }
    else { out.style.display='block'; out.style.borderColor='rgba(255,90,122,.4)'; out.innerHTML='⚠ '+esc(r.error||'Publish failed.'); }
  }catch(e){ alert('Publish failed.'); }
  b.disabled=false; b.innerHTML=old;
}
async function loadShared(){
  try{ const d=await fetch(`longevity.php?api=shared&_=${Date.now()}`).then(r=>r.json());
    const mgr=document.getElementById('sharedMgr'), list=document.getElementById('sharedList');
    if(!d.ok || !(d.passports||[]).length){ mgr.style.display='none'; return; }
    const base=location.origin+'/passport.php?id=';   // note: buyers use the PORTAL url; this local one only if reachable
    list.innerHTML=d.passports.map(p=>{
      const url='https://neurunetpr.com/passport.php?id='+esc(p.id);
      return `<div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:10px 8px;border-bottom:1px dashed rgba(120,150,255,.12)">
        <div style="min-width:150px"><b>${esc(p.rig_name||'PC')}</b><div class="muted" style="font-size:11px">${esc(p.id)} · ${p.views||0} view${p.views==1?'':'s'}${p.last_view?(' · last '+esc((p.last_view||'').slice(0,10))):''}</div></div>
        <a class="lbtn" href="${url}" target="_blank" style="padding:7px 12px;font-size:12px"><i class="fa-solid fa-link"></i> Open</a>
        <button class="lbtn" style="padding:7px 12px;font-size:12px;cursor:pointer" onclick="chgPass('${esc(p.id)}')"><i class="fa-solid fa-key"></i> Change password</button>
        <button class="lbtn" style="padding:7px 12px;font-size:12px;cursor:pointer;color:#ff8ea1;border-color:rgba(255,90,122,.4)" onclick="revokeShare('${esc(p.id)}')"><i class="fa-solid fa-trash-can"></i> Revoke</button>
      </div>`;
    }).join('');
    mgr.style.display='block';
  }catch(e){}
}
async function revokeShare(id){
  if(!confirm('Revoke this shared passport? The buyer\'s link will stop working immediately.')) return;
  const f=new FormData(); f.append('id',id);
  try{ const r=await fetch('longevity.php?api=revoke',{method:'POST',body:f}).then(x=>x.json()); if(r.ok) loadShared(); else alert('Revoke failed'+(r.error?': '+r.error:'.')); }catch(e){ alert('Revoke failed.'); }
}
async function chgPass(id){
  const pw=prompt('New password for this shared passport (min 4 chars):'); if(pw===null) return;
  if(pw.length<4){ alert('Password too short.'); return; }
  const f=new FormData(); f.append('id',id); f.append('password',pw);
  try{ const r=await fetch('longevity.php?api=setpass',{method:'POST',body:f}).then(x=>x.json()); alert(r.ok?('Password updated. Share the new one with the buyer.'):('Failed'+(r.error?': '+r.error:'.'))); }catch(e){ alert('Failed.'); }
}
loadRigs(); GL=initGL(); loadShared();
document.getElementById('fsBtn').addEventListener('click',()=>{ const w=document.getElementById('reactor'); if(!document.fullscreenElement){ (w.requestFullscreen||w.webkitRequestFullscreen||function(){}).call(w); } else document.exitFullscreen(); });
document.addEventListener('fullscreenchange',()=>{ const b=document.getElementById('fsBtn'); b.innerHTML=document.fullscreenElement?'<i class="fa-solid fa-compress"></i> Exit':'<i class="fa-solid fa-expand"></i> Fullscreen'; });
</script>
</body></html>
