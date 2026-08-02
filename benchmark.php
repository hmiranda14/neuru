<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — PC BENCHMARK. "Is this PC good for gaming?" answered with a real, scientific
// NEURU Score (0–10,000) + Tier + a detailed, plain-English explanation of every finding.
// The benchmark runs locally on the rig via PowerShell-over-SSH (nm_benchmark.php); this
// page is the full-WebGL, fully-animated front-end. Standard dark gaming layout. RBAC 'gaming'.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_benchmark.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'gaming')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=gaming'); exit;
}

if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if (function_exists('session_write_close')) @session_write_close();   // release lock BEFORE slow SSH

    if ($api === 'rigs') {
        $rows = function_exists('nm_win_hosts') ? nm_win_hosts($conn) : [];
        echo json_encode(['ok'=>true,'rigs'=>array_map(fn($r)=>['id'=>(int)$r['id'],'name'=>$r['name']??('rig '.$r['id'])], $rows)]);
        exit;
    }
    if ($api === 'run') {
        $rid = (int)($_GET['rig'] ?? 0);
        $h   = $rid ? (function_exists('nm_win_host') ? nm_win_host($conn,$rid) : null) : null;
        if (!$h)   { echo json_encode(['ok'=>false,'error'=>'Pick a rig first.']); exit; }
        $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn,$h) : null;
        if (!$ssh) { echo json_encode(['ok'=>false,'error'=>'This rig has no SSH configured — add credentials in the Windows monitor.']); exit; }
        $res = nm_bench_run($conn,$ssh);
        if (!empty($res['ok'])) {
            $note = mb_substr(trim((string)($_GET['note'] ?? '')), 0, 120);
            $id   = nm_bench_save($conn,$rid,$res,$note);        // persist so runs can be compared over time
            $res['run_id'] = $id; $res['note'] = $note;
            // compare against the immediately-previous run (the one before this save)
            $hist = nm_bench_history($conn,$rid,2);
            if (count($hist) >= 2) $res['compare'] = nm_bench_compare($hist[1], $hist[0]);
        }
        echo json_encode($res); exit;
    }
    if ($api === 'history') {
        $rid = (int)($_GET['rig'] ?? 0);
        echo json_encode(['ok'=>true,'runs'=>$rid?nm_bench_history($conn,$rid,30):[]]); exit;
    }
    if ($api === 'label') {
        $rid=(int)($_POST['rig']??0); $id=(int)($_POST['id']??0); $note=(string)($_POST['note']??'');
        echo json_encode(['ok'=>($rid&&$id)?nm_bench_label($conn,$rid,$id,$note):false]); exit;
    }
    if ($api === 'delete') {
        $rid=(int)($_POST['rig']??0); $id=(int)($_POST['id']??0);
        echo json_encode(['ok'=>($rid&&$id)?nm_bench_delete($conn,$rid,$id):false]); exit;
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
:root{ --cy:#39e1ff; --pk:#b06bff; --bl:#4da3ff; --gd:#ffcf6b; --rd:#ff7a9c; --gr:#7CFFB2; --td:#36e3d0; --bd:rgba(120,150,255,.16); }
*,*::before,*::after{ box-sizing:border-box; }
html{ background:#04060d; }
body{ margin:0; background:#04060d !important; color:#e6ecf7; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; overflow-x:hidden; }
#nm-netbg{ z-index:0 !important; opacity:.5; }
<?= function_exists('nm_chrome_css') ? nm_chrome_css() : '' ?>
.bm{ max-width:1240px; margin:0 auto; padding:16px 20px 70px; position:relative; z-index:1; }
.bm-head{ display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
.bm-head h1{ margin:0; font-size:25px; font-weight:900; display:flex; align-items:center; gap:12px; }
.bm-head h1 i{ color:var(--gd); }
.ctrls{ margin-left:auto; display:flex; align-items:center; gap:9px; flex-wrap:wrap; }
.ctrls select{ background:rgba(6,12,24,.7); border:1px solid var(--bd); color:#dfeeff; border-radius:10px; padding:9px 12px; font-size:13px; }
.runbtn{ display:inline-flex; align-items:center; gap:9px; border:0; cursor:pointer; font-weight:800; font-size:14px; color:#04121f; padding:11px 18px; border-radius:12px; background:linear-gradient(90deg,var(--gd),#ffd98a); box-shadow:0 6px 22px rgba(255,207,107,.35); transition:.15s; }
.runbtn:hover{ transform:translateY(-2px); box-shadow:0 10px 30px rgba(255,207,107,.5); }
.runbtn:disabled{ opacity:.55; cursor:default; transform:none; box-shadow:none; }
.bm-sub{ color:#9fb0d8; font-size:13px; margin:5px 0 14px; }
.glass{ background:rgba(10,14,30,.5); backdrop-filter:blur(14px); border:1px solid var(--bd); border-radius:18px; }
/* hero reactor */
.hero{ display:grid; grid-template-columns:1.5fr .9fr; gap:16px; align-items:stretch; }
@media(max-width:920px){ .hero{ grid-template-columns:1fr; } }
#reactor{ position:relative; height:520px; overflow:hidden; }
#reactor:fullscreen{ height:100vh; width:100vw; border-radius:0; background:#04060d; }
#benchGL{ width:100%; height:100%; display:block; cursor:grab; }
/* In-fullscreen overlays: run controls (top) + full results panel (right). Hidden windowed. */
#glTop,#glPanel{ display:none; }
#reactor:fullscreen #glTop{ display:flex; position:absolute; top:14px; left:16px; z-index:9; align-items:center; gap:9px; flex-wrap:wrap; max-width:60%; }
#reactor:fullscreen #glTop .runbtn{ padding:9px 15px; font-size:13px; }
#reactor:fullscreen #glPanel{ display:block; position:absolute; top:14px; right:14px; bottom:44px; width:360px; max-width:44%; overflow-y:auto; padding:14px 15px; border-radius:14px; background:rgba(8,13,28,.86); border:1px solid var(--bd); box-shadow:0 10px 30px rgba(0,0,0,.5); z-index:8; }
#reactor:fullscreen #scoreOv{ align-items:flex-start; justify-content:center; padding-left:6%; }
#reactor:fullscreen .mapbtns{ top:14px; }
/* compact result blocks inside the fullscreen panel */
#glPanel .pt{ font-size:20px; font-weight:900; }
#glPanel .pm{ font-size:11.5px; color:#c3d3ee; line-height:1.5; margin-top:3px; }
#glPanel .pfps{ margin-top:10px; font-size:12px; color:#9ef0c4; }
#glPanel .prow{ display:flex; align-items:center; gap:8px; margin-top:9px; }
#glPanel .prow .pk{ font-size:11px; font-weight:800; width:38px; }
#glPanel .prow .pv{ font-size:13px; font-weight:900; width:32px; text-align:right; font-variant-numeric:tabular-nums; }
#glPanel .prow .pb{ flex:1; height:7px; border-radius:6px; background:rgba(255,255,255,.08); overflow:hidden; }
#glPanel .prow .pb i{ display:block; height:100%; border-radius:6px; }
#glPanel .pf{ margin-top:9px; padding-top:9px; border-top:1px dashed rgba(120,150,255,.14); }
#glPanel .pf .fh{ font-size:12px; font-weight:800; } #glPanel .pf .fx{ font-size:11px; color:#c3d3ee; line-height:1.5; margin-top:2px; }
#glPanel h4{ margin:12px 0 2px; font-size:11px; letter-spacing:.5px; text-transform:uppercase; color:#8fa4c8; }
#benchGL.drag{ cursor:grabbing; }
.mapbtns{ position:absolute; top:14px; right:14px; display:flex; gap:8px; z-index:9; }
.mapbtn{ background:rgba(10,16,34,.72); border:1px solid var(--bd); color:#dbe9ff; border-radius:10px; padding:8px 11px; font-size:12px; font-weight:700; cursor:pointer; display:inline-flex; align-items:center; gap:7px; transition:.15s; }
.mapbtn:hover{ border-color:var(--cy); color:#fff; }
#scoreOv{ position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; pointer-events:none; text-align:center; }
#scoreOv .big{ font-size:78px; font-weight:900; line-height:.95; font-variant-numeric:tabular-nums; color:#fff; text-shadow:0 0 34px rgba(57,225,255,.55); letter-spacing:-1px; }
#scoreOv .max{ font-size:14px; color:#8fa4c8; margin-top:2px; letter-spacing:1px; }
#scoreOv .tier{ margin-top:12px; font-size:15px; font-weight:900; padding:6px 16px; border-radius:999px; letter-spacing:.5px; display:none; }
#scoreOv .idle{ font-size:15px; color:#9fb0d8; max-width:70%; }
#mapTip{ position:absolute; pointer-events:none; z-index:8; background:rgba(6,12,26,.92); border:1px solid var(--bd); border-radius:10px; padding:7px 11px; font-size:12px; color:#eaf2ff; transform:translate(-50%,-140%); opacity:0; transition:opacity .12s; white-space:nowrap; }
#mapLegend{ position:absolute; left:0; right:0; bottom:0; display:flex; gap:14px; flex-wrap:wrap; justify-content:center; padding:8px 12px; background:linear-gradient(0deg,rgba(4,6,13,.85),transparent); font-size:11px; color:#9fb0d8; pointer-events:none; }
#mapLegend i.d{ width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:5px; }
/* run console */
.runside{ display:flex; flex-direction:column; gap:14px; }
.console{ padding:16px 18px; flex:1; }
.console h3{ margin:0 0 10px; font-size:14px; font-weight:800; display:flex; align-items:center; gap:8px; }
.stage{ display:flex; align-items:center; gap:11px; padding:8px 0; border-bottom:1px dashed rgba(120,150,255,.12); font-size:13px; color:#9fb0d8; }
.stage:last-child{ border-bottom:0; }
.stage .ic{ width:22px; height:22px; border-radius:50%; display:grid; place-items:center; font-size:11px; background:rgba(255,255,255,.06); color:#7f90b4; flex:none; }
.stage.run .ic{ background:rgba(57,225,255,.16); color:var(--cy); animation:spin 1s linear infinite; }
.stage.done .ic{ background:rgba(124,255,178,.16); color:var(--gr); }
.stage.done{ color:#dfe9fb; }
@keyframes spin{ to{ transform:rotate(360deg); } }
.fpsbox{ padding:15px 18px; text-align:center; }
.fpsbox .v{ font-size:34px; font-weight:900; color:var(--gr); font-variant-numeric:tabular-nums; }
.fpsbox .l{ font-size:11px; color:#8fa4c8; letter-spacing:1px; text-transform:uppercase; }
.fpsbox .s{ font-size:12px; color:#c3d3ee; margin-top:5px; }
/* tier banner */
.tierbanner{ margin-top:16px; padding:16px 20px; display:none; align-items:center; gap:16px; flex-wrap:wrap; border-left:4px solid var(--cy); }
.tierbanner .tk{ font-size:30px; font-weight:900; }
.tierbanner .tt{ font-size:12.5px; color:#d7e3f7; line-height:1.5; flex:1; min-width:240px; }
/* components */
.grid4{ display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:14px; margin-top:16px; }
.comp{ padding:16px 17px; position:relative; overflow:hidden; }
.comp .ch{ display:flex; align-items:center; gap:10px; }
.comp .ci{ width:34px; height:34px; border-radius:10px; display:grid; place-items:center; font-size:15px; }
.comp .cn{ font-size:14px; font-weight:800; } .comp .cw{ font-size:10.5px; color:#8fa4c8; }
.comp .cs{ margin-left:auto; font-size:26px; font-weight:900; font-variant-numeric:tabular-nums; }
.comp .cv{ font-size:12px; color:#cdd9ef; margin-top:9px; font-weight:600; }
.comp .bar{ height:8px; border-radius:6px; background:rgba(255,255,255,.07); margin-top:8px; overflow:hidden; }
.comp .bar i{ display:block; height:100%; border-radius:6px; width:0; transition:width 1s cubic-bezier(.2,.8,.2,1); }
.comp .cm{ font-size:11.5px; color:#9fb0d8; margin-top:10px; line-height:1.5; }
.comp .cd{ font-size:11.5px; color:#c7d5ee; margin-top:6px; line-height:1.5; }
.comp .cd b{ color:#eaf2ff; }
/* findings */
.section-h{ margin:22px 2px 10px; font-size:15px; font-weight:800; display:flex; align-items:center; gap:9px; color:#eaf2ff; }
.finds{ display:flex; flex-direction:column; gap:10px; }
.find{ padding:13px 15px; display:flex; gap:13px; align-items:flex-start; border-left:3px solid var(--bd); }
.find.ok{ border-left-color:var(--gr); } .find.warn{ border-left-color:var(--gd); } .find.crit{ border-left-color:var(--rd); }
.find .fe{ font-size:22px; line-height:1; flex:none; }
.find .ft{ font-size:13.5px; font-weight:800; }
.find .fm{ font-size:12.5px; color:#d3dff3; margin-top:3px; line-height:1.55; }
.find .fd{ font-size:11.5px; color:#93a4c6; margin-top:5px; line-height:1.5; }
.find a.jump{ display:inline-flex; align-items:center; gap:6px; margin-top:8px; text-decoration:none; font-size:11.5px; font-weight:800; color:#04121f; background:linear-gradient(90deg,var(--cy),#7fe9ff); padding:6px 11px; border-radius:8px; }
.hwstrip{ display:flex; gap:8px; flex-wrap:wrap; margin-top:14px; }
.hw{ font-size:11.5px; color:#b9c8e4; background:rgba(10,16,34,.55); border:1px solid var(--bd); border-radius:9px; padding:7px 11px; }
.hw b{ color:#eaf2ff; }
.noteIn{ background:rgba(6,12,24,.7); border:1px solid var(--bd); color:#dfeeff; border-radius:10px; padding:9px 12px; font-size:13px; min-width:160px; }
/* compare banner */
.cmp{ margin-top:16px; padding:14px 18px; display:none; align-items:center; gap:14px; flex-wrap:wrap; border-left:4px solid var(--gr); }
.cmp .big{ font-size:26px; font-weight:900; font-variant-numeric:tabular-nums; }
.cmp .lbl{ font-size:12.5px; color:#c3d3ee; }
.delta{ font-size:12px; font-weight:800; padding:3px 9px; border-radius:999px; font-variant-numeric:tabular-nums; }
.delta.up{ background:rgba(124,255,178,.16); color:#7CFFB2; } .delta.dn{ background:rgba(255,122,156,.16); color:#ff9db0; } .delta.flat{ background:rgba(160,170,190,.14); color:#aab4c6; }
.cmp .parts{ display:flex; gap:7px; flex-wrap:wrap; margin-left:auto; }
.cmp .parts .delta{ font-size:11px; }
/* history */
.histwrap{ padding:14px 16px; margin-top:16px; }
.histwrap h3{ margin:0 0 4px; font-size:15px; font-weight:800; display:flex; align-items:center; gap:9px; }
.histwrap .hs{ font-size:11.5px; color:#8fa4c8; margin-bottom:12px; }
.hrow{ display:flex; align-items:center; gap:12px; padding:10px 8px; border-bottom:1px dashed rgba(120,150,255,.12); flex-wrap:wrap; }
.hrow:last-child{ border-bottom:0; }
.hrow .tchip{ font-size:12px; font-weight:900; width:30px; height:30px; border-radius:9px; display:grid; place-items:center; flex:none; }
.hrow .hsc{ font-size:19px; font-weight:900; font-variant-numeric:tabular-nums; min-width:74px; }
.hrow .hmeta{ font-size:11px; color:#8fa4c8; }
.hrow .hnote{ background:rgba(255,255,255,.04); border:1px solid var(--bd); color:#dfeaf9; border-radius:8px; padding:5px 9px; font-size:12px; min-width:150px; flex:1; }
.hrow .subs{ display:flex; gap:6px; flex-wrap:wrap; }
.hrow .sm{ font-size:10.5px; color:#b9c8e4; background:rgba(10,16,34,.5); border:1px solid var(--bd); border-radius:7px; padding:3px 7px; }
.hrow .del{ background:none; border:0; color:#ff8ea1; cursor:pointer; font-size:14px; opacity:.7; } .hrow .del:hover{ opacity:1; }
.hrow.newrun{ animation:flash 1.6s ease; }
@keyframes flash{ 0%{ background:rgba(124,255,178,.14);} 100%{ background:transparent; } }
.err{ display:none; margin-top:14px; padding:13px 16px; border-radius:12px; background:rgba(255,90,122,.1); border:1px solid rgba(255,90,122,.35); color:#ffb4c2; font-size:13px; }
.muted{ color:#8fa4c8; }
</style>

<div class="bm">
  <div class="bm-head">
    <h1><i class="fa-solid fa-gauge-high"></i> PC Benchmark</h1>
    <div class="ctrls">
      <span class="muted" style="font-size:12px">Rig</span>
      <select id="rigSel"><option>Loading…</option></select>
      <input class="noteIn" id="noteIn" maxlength="120" placeholder="Label (e.g. Before optimize)" title="Optional label saved with this run so you can compare before/after">
      <button class="runbtn" id="runBtn" onclick="runBench()"><i class="fa-solid fa-play"></i> Run Benchmark</button>
    </div>
  </div>
  <div class="bm-sub">A real, reproducible test that runs <b>on your rig</b> (CPU, memory & storage) and scores whether it's built for gaming — with a plain-English reason for every finding. The heavy work runs locally on the PC; nothing is guessed.</div>

  <div class="hero">
    <div class="glass" id="reactor">
      <canvas id="benchGL"></canvas>
      <div class="mapbtns"><button class="mapbtn" id="fsBtn" title="Fullscreen"><i class="fa-solid fa-expand"></i> Fullscreen</button></div>
      <div id="glTop">
        <select id="rigSelFs" onchange="setRig(this.value)"></select>
        <input class="noteIn" id="noteInFs" maxlength="120" placeholder="Label (optional)" style="min-width:130px">
        <button class="runbtn" id="runBtnFs" onclick="runBench()"><i class="fa-solid fa-play"></i> Run</button>
      </div>
      <div id="glPanel"></div>
      <div id="scoreOv">
        <div class="idle" id="ovIdle"><i class="fa-solid fa-gauge-high" style="font-size:34px;color:var(--gd)"></i><br><br>Pick a rig and hit <b>Run Benchmark</b>.<br>Your NEURU Score builds here.</div>
        <div class="big" id="ovScore" style="display:none">0</div>
        <div class="max" id="ovMax" style="display:none">NEURU SCORE · / 10,000</div>
        <div class="tier" id="ovTier"></div>
      </div>
      <div id="mapTip"></div>
      <div id="mapLegend">
        <span><i class="d" style="background:#b06bff"></i>GPU</span>
        <span><i class="d" style="background:#4da3ff"></i>CPU</span>
        <span><i class="d" style="background:#36e3d0"></i>RAM</span>
        <span><i class="d" style="background:#ffcf6b"></i>Storage</span>
        <span class="muted">node size &amp; ring = sub-score</span>
      </div>
    </div>
    <div class="runside">
      <div class="glass console">
        <h3><i class="fa-solid fa-terminal" style="color:var(--cy)"></i> Benchmark run</h3>
        <div id="stages"></div>
      </div>
      <div class="glass fpsbox" id="fpsBox" style="display:none">
        <div class="v" id="fpsV">—</div>
        <div class="l">est. FPS in AAA</div>
        <div class="s" id="fpsS"></div>
      </div>
    </div>
  </div>

  <div class="glass tierbanner" id="tierBanner">
    <div class="tk" id="tbK"></div>
    <div><div style="font-size:16px;font-weight:900" id="tbName"></div><div class="tt" id="tbMean"></div></div>
  </div>

  <div class="grid4" id="comps"></div>

  <div class="section-h" id="findH" style="display:none"><i class="fa-solid fa-clipboard-list" style="color:var(--gd)"></i> What this means &amp; how to level up</div>
  <div class="finds" id="finds"></div>

  <div class="hwstrip" id="hwStrip"></div>

  <div class="glass cmp" id="cmpBanner">
    <i class="fa-solid fa-code-compare" style="font-size:22px;color:var(--gr)"></i>
    <div><div class="big" id="cmpScore"></div><div class="lbl" id="cmpLbl"></div></div>
    <div class="parts" id="cmpParts"></div>
  </div>

  <div class="glass histwrap" id="histWrap" style="display:none">
    <h3><i class="fa-solid fa-clock-rotate-left" style="color:var(--cy)"></i> Benchmark history — compare before vs after</h3>
    <div class="hs">Every run is saved for this rig. Optimize (Game Lab / Fan Profiler), run again, and watch the score climb. Edit a label or 🗑 to remove a run.</div>
    <div id="histList"></div>
  </div>

  <div class="err" id="err"></div>
</div>

<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const CKEY={gpu:'#b06bff',cpu:'#4da3ff',ram:'#36e3d0',disk:'#ffcf6b'};
const TIERC={S:'#7CFFB2',A:'#4da3ff',B:'#39e1ff',C:'#ffcf6b',D:'#ff7a9c'};
let RIG='', GL=null, RUNNING=false;

function setRig(v){ RIG=v; const a=document.getElementById('rigSel'), b=document.getElementById('rigSelFs');
  if(a&&a.value!==v)a.value=v; if(b&&b.value!==v)b.value=v; document.getElementById('cmpBanner').style.display='none'; loadHistory(); }
async function loadRigs(){
  try{ const d=await fetch('benchmark.php?api=rigs').then(r=>r.json());
    const opts=(d.ok&&d.rigs.length)?d.rigs.map(r=>`<option value="${r.id}">${esc(r.name)}</option>`).join(''):'<option value="">No rigs</option>';
    document.getElementById('rigSel').innerHTML=opts; const fs=document.getElementById('rigSelFs'); if(fs) fs.innerHTML=opts;
    if(d.ok&&d.rigs.length){ setRig(document.getElementById('rigSel').value); }
    else { document.getElementById('runBtn').disabled=true; const rb=document.getElementById('runBtnFs'); if(rb) rb.disabled=true; }
  }catch(e){}
}
document.getElementById('rigSel').addEventListener('change',e=>setRig(e.target.value));

function dchip(v,unit){ v=v||0; const cls=v>0?'up':(v<0?'dn':'flat'); const sign=v>0?'+':''; return `<span class="delta ${cls}">${sign}${v.toLocaleString()}${unit||''}</span>`; }

async function loadHistory(){
  if(!RIG){ document.getElementById('histWrap').style.display='none'; return; }
  let d; try{ d=await fetch(`benchmark.php?api=history&rig=${RIG}&_=${Date.now()}`).then(r=>r.json()); }catch(e){ return; }
  renderHistory(d.runs||[], -1);
}
function renderHistory(runs, newId){
  const w=document.getElementById('histWrap');
  if(!runs.length){ w.style.display='none'; return; }
  w.style.display='block';
  document.getElementById('histList').innerHTML=runs.map((r,i)=>{
    const older=runs[i+1]; const dScore=older?(r.neuru_score-older.neuru_score):0;
    const delta=older?dchip(dScore):'<span class="delta flat">baseline</span>';
    const tc=TIERC[r.tier_key]||'#39e1ff';
    return `<div class="hrow${r.id===newId?' newrun':''}">
      <div class="tchip" style="background:${tc}22;color:${tc}">${esc(r.tier_key||'?')}</div>
      <div class="hsc" style="color:${tc}">${(r.neuru_score||0).toLocaleString()}</div>
      ${delta}
      <div class="subs"><span class="sm" style="color:#c9b6ff">GPU ${r.gpu_score}</span><span class="sm" style="color:#a9cbff">CPU ${r.cpu_score}</span><span class="sm" style="color:#9ef0e4">RAM ${r.ram_score}</span><span class="sm" style="color:#ffe0a3">DSK ${r.disk_score}</span><span class="sm">~${r.fps_avg} FPS</span></div>
      <input class="hnote" value="${esc(r.note||'')}" placeholder="add a label…" onchange="labelRun(${r.id},this.value)">
      <div class="hmeta">${esc((r.created_at||'').replace('T',' ').slice(0,16))}</div>
      <button class="del" title="Delete run" onclick="deleteRun(${r.id})"><i class="fa-solid fa-trash-can"></i></button>
    </div>`;
  }).join('');
}
async function labelRun(id,note){ const f=new FormData(); f.append('rig',RIG); f.append('id',id); f.append('note',note); try{ await fetch('benchmark.php?api=label',{method:'POST',body:f}); }catch(e){} }
async function deleteRun(id){ if(!confirm('Delete this saved benchmark run?'))return; const f=new FormData(); f.append('rig',RIG); f.append('id',id); try{ await fetch('benchmark.php?api=delete',{method:'POST',body:f}); }catch(e){} loadHistory(); }

function renderCompare(c){
  if(!c){ document.getElementById('cmpBanner').style.display='none'; return; }
  const b=document.getElementById('cmpBanner'); b.style.display='flex';
  const up=c.score>0, flat=c.score===0; b.style.borderLeftColor=up?'#7CFFB2':(flat?'#8fa4c8':'#ff7a9c');
  document.getElementById('cmpScore').innerHTML=`${c.score>0?'+':''}${(c.score||0).toLocaleString()} <span style="font-size:14px" class="muted">NEURU Score</span>`;
  document.getElementById('cmpScore').style.color=up?'#7CFFB2':(flat?'#cfe0ff':'#ff9db0');
  document.getElementById('cmpLbl').textContent=up?`Improved since your last run${c.prev.note?` ("${c.prev.note}")`:''} — your optimizations are working! 🚀`:(flat?'Same as your last run.':`Down vs your last run${c.prev.note?` ("${c.prev.note}")`:''} — something regressed.`);
  document.getElementById('cmpParts').innerHTML=['gpu','cpu','ram','disk'].map(k=>`<span class="delta ${c[k]>0?'up':(c[k]<0?'dn':'flat')}">${k.toUpperCase()} ${c[k]>0?'+':''}${c[k]}</span>`).join('')+dchip(c.fps,' FPS');
}

const STAGES=[
  ['probe','Probing hardware (CPU · GPU · RAM · disk)'],
  ['cpu','CPU compute test — 4M-op single-thread loop'],
  ['disk','Storage test — every drive, real write speed'],
  ['gpu','Classifying GPU gaming capability'],
  ['score','Composing the NEURU Score'],
];
function renderStages(state){
  document.getElementById('stages').innerHTML=STAGES.map((s,i)=>{
    const st=state[i]||'wait';
    const ic=st==='done'?'<i class="fa-solid fa-check"></i>':(st==='run'?'<i class="fa-solid fa-gear"></i>':(i+1));
    return `<div class="stage ${st}"><div class="ic">${ic}</div><div>${esc(s[1])}</div></div>`;
  }).join('');
}
renderStages({});

function setRunBtns(disabled, html){ ['runBtn','runBtnFs'].forEach(id=>{ const b=document.getElementById(id); if(b){ b.disabled=disabled; b.innerHTML=html; } }); }
async function runBench(){
  if(!RIG||RUNNING) return; RUNNING=true;
  setRunBtns(true,'<i class="fa-solid fa-spinner fa-spin"></i> Running…');
  document.getElementById('err').style.display='none';
  // reset UI
  document.getElementById('ovIdle').style.display='none';
  document.getElementById('ovScore').style.display='block'; document.getElementById('ovMax').style.display='block';
  document.getElementById('ovScore').textContent='0'; document.getElementById('ovTier').style.display='none';
  document.getElementById('tierBanner').style.display='none'; document.getElementById('comps').innerHTML='';
  document.getElementById('finds').innerHTML=''; document.getElementById('findH').style.display='none';
  document.getElementById('fpsBox').style.display='none'; document.getElementById('hwStrip').innerHTML='';
  if(GL) GL.spinUp();
  // cosmetic staged progress while the single SSH call runs
  const state={}; let si=0; renderStages(state);
  state[0]='run'; renderStages(state);
  const ticker=setInterval(()=>{ if(si<STAGES.length-1){ state[si]='done'; si++; state[si]='run'; renderStages(state);} }, 900);

  const note=encodeURIComponent(document.getElementById('noteIn').value||document.getElementById('noteInFs').value||'');
  let d; try{ d=await fetch(`benchmark.php?api=run&rig=${RIG}&note=${note}&_=${Date.now()}`).then(r=>r.json()); }catch(e){ d={ok:false,error:'Network error contacting the rig.'}; }
  clearInterval(ticker);
  RUNNING=false; setRunBtns(false,'<i class="fa-solid fa-rotate-right"></i> Run Again');

  if(!d.ok){
    STAGES.forEach((_,i)=>state[i]='wait'); renderStages(state);
    document.getElementById('ovScore').style.display='none'; document.getElementById('ovMax').style.display='none';
    document.getElementById('ovIdle').style.display='block';
    const e=document.getElementById('err'); e.textContent='⚠ '+(d.error||'Benchmark failed.'); e.style.display='block';
    if(GL) GL.idle(); return;
  }
  STAGES.forEach((_,i)=>state[i]='done'); renderStages(state);
  render(d);
}

function render(d){
  // WebGL nodes + tier color
  if(GL) GL.setResult(d.components||[], d.tier?.color||'#39e1ff');
  // count-up score
  const target=d.neuru_score||0; const el=document.getElementById('ovScore'); const t0=performance.now(); const dur=1400;
  (function up(t){ const k=Math.min(1,(t-t0)/dur); const v=Math.round(target*(1-Math.pow(1-k,3))); el.textContent=v.toLocaleString(); if(k<1) requestAnimationFrame(up); })(t0);
  // tier chip in overlay
  const ot=document.getElementById('ovTier'); ot.textContent=d.tier?.name||''; ot.style.display='inline-block';
  ot.style.background=(d.tier?.color||'#39e1ff')+'22'; ot.style.color=d.tier?.color||'#39e1ff'; ot.style.border='1px solid '+(d.tier?.color||'#39e1ff')+'66';
  document.getElementById('reactor').style.setProperty('--tier',d.tier?.color||'#39e1ff');
  // tier banner
  const tb=document.getElementById('tierBanner'); tb.style.display='flex'; tb.style.borderLeftColor=d.tier?.color||'#39e1ff';
  document.getElementById('tbK').textContent=d.tier?.key||''; document.getElementById('tbK').style.color=d.tier?.color||'#39e1ff';
  document.getElementById('tbName').textContent=d.tier?.name||''; document.getElementById('tbMean').textContent=d.tier?.meaning||'';
  // fps
  if(d.fps){ document.getElementById('fpsBox').style.display='block'; document.getElementById('fpsV').textContent='~'+d.fps.avg;
    document.getElementById('fpsS').textContent=`${d.fps.low1} FPS 1% low @ ${esc(d.fps.res)} · panel ${d.fps.refresh||60}Hz`; }
  // components
  document.getElementById('comps').innerHTML=(d.components||[]).map(c=>{
    const col=CKEY[c.key]||'#4da3ff'; const st=c.status||'ok';
    return `<div class="comp glass"><div class="ch">
      <div class="ci" style="background:${col}22;color:${col}"><i class="fa-solid ${c.icon||'fa-cube'}"></i></div>
      <div><div class="cn">${esc(c.name)}</div><div class="cw">weight ${c.weight}% of score</div></div>
      <div class="cs" style="color:${col}">${c.score}</div></div>
      <div class="cv">${esc(c.value)}</div>
      <div class="bar"><i data-w="${c.score}" style="background:${col};box-shadow:0 0 10px ${col}"></i></div>
      <div class="cm"><b style="color:#cfe0ff">What it is:</b> ${esc(c.mean)}</div>
      <div class="cd"><b>The data:</b> ${esc(c.data)}</div>
    </div>`;
  }).join('');
  requestAnimationFrame(()=>document.querySelectorAll('.comp .bar i').forEach(i=>i.style.width=(i.dataset.w||0)+'%'));
  // findings
  document.getElementById('findH').style.display='flex';
  document.getElementById('finds').innerHTML=(d.findings||[]).map(f=>{
    const jump=f.tool?`<br><a class="jump" href="${esc(f.url||'#')}"><i class="fa-solid fa-arrow-right"></i> Open ${esc(f.tool)}</a>`:'';
    return `<div class="find glass ${esc(f.status||'ok')}"><div class="fe">${f.icon||'•'}</div>
      <div><div class="ft">${esc(f.title)}</div><div class="fm">${esc(f.mean)}</div><div class="fd">${esc(f.data)}</div>${jump}</div></div>`;
  }).join('');
  // hardware strip
  const h=d.hardware||{};
  const chips=[['GPU',h.gpu||'?'],['VRAM',(h.vram||'?')+' GB'],['CPU',h.cpu||'?'],['RAM',(h.ram_gb||'?')+' GB'],['Storage',h.disk||'?'],['Display',(h.res||'?')+' @ '+(h.refresh||'?')+'Hz'],['OS',h.os||'?']];
  document.getElementById('hwStrip').innerHTML=chips.map(c=>`<div class="hw"><b>${esc(c[0])}:</b> ${esc(c[1])}</div>`).join('');
  // comparison vs previous run + refresh saved history (highlight the new row)
  renderCompare(d.compare);
  renderPanel(d);   // populate the in-fullscreen results overlay with the same info
  document.getElementById('noteIn').value=''; document.getElementById('noteInFs').value='';
  loadHistoryHighlight(d.run_id||-1);
}
// Compact "everything" panel shown INSIDE the WebGL fullscreen (scores + findings + FPS).
function renderPanel(d){
  const p=document.getElementById('glPanel'); if(!p) return; const tc=d.tier?.color||'#39e1ff';
  const comps=(d.components||[]).map(c=>{ const col=CKEY[c.key]||'#4da3ff'; return `<div class="prow"><span class="pk" style="color:${col}">${c.key.toUpperCase()}</span><div class="pb"><i style="width:${c.score}%;background:${col};box-shadow:0 0 8px ${col}"></i></div><span class="pv" style="color:${col}">${c.score}</span></div>`; }).join('');
  const finds=(d.findings||[]).map(f=>`<div class="pf"><div class="fh">${f.icon||'•'} ${esc(f.title)}</div><div class="fx">${esc(f.mean)}</div></div>`).join('');
  p.innerHTML=`<div class="pt" style="color:${tc}">${esc(d.tier?.name||'')}</div><div class="pm">${esc(d.tier?.meaning||'')}</div>
    <div class="pfps">🎮 ~${d.fps?.avg||'?'} FPS avg · ${d.fps?.low1||'?'} 1% low @ ${esc(d.fps?.res||'')}</div>
    <h4>Component scores</h4>${comps}
    <h4>What it means &amp; how to level up</h4>${finds}`;
}
async function loadHistoryHighlight(newId){
  if(!RIG) return;
  let d; try{ d=await fetch(`benchmark.php?api=history&rig=${RIG}&_=${Date.now()}`).then(r=>r.json()); }catch(e){ return; }
  renderHistory(d.runs||[], newId);
}

// ── WebGL benchmark reactor: core + 4 component nodes (gauge rings, labels) ──
function initGL(){
  const cv=document.getElementById('benchGL'); if(!window.THREE||!cv) return null;
  let W=cv.clientWidth||760, H=cv.clientHeight||520;
  const rn=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true,powerPreference:'high-performance'});
  rn.setPixelRatio(Math.min(2,devicePixelRatio)); rn.setSize(W,H,false);
  const sc=new THREE.Scene(), cam=new THREE.PerspectiveCamera(55,W/H,.1,100); cam.position.set(0,1.2,27);
  // WebGL particle starfield in the SCENE so the constellation persists even in fullscreen
  const starGeo=new THREE.BufferGeometry(), SN=680, sp=new Float32Array(SN*3);
  for(let i=0;i<SN;i++){ const rr=24+Math.random()*34, a=Math.random()*Math.PI*2, b=Math.acos(2*Math.random()-1); sp[i*3]=rr*Math.sin(b)*Math.cos(a); sp[i*3+1]=rr*Math.sin(b)*Math.sin(a); sp[i*3+2]=rr*Math.cos(b); }
  starGeo.setAttribute('position',new THREE.BufferAttribute(sp,3));
  const stars=new THREE.Points(starGeo, new THREE.PointsMaterial({color:0x4da3ff,size:0.13,transparent:true,opacity:.6,sizeAttenuation:true})); sc.add(stars);
  const root=new THREE.Group(); root.rotation.x=-0.12; sc.add(root);
  const core=new THREE.Mesh(new THREE.IcosahedronGeometry(2.6,1), new THREE.MeshBasicMaterial({color:0x39e1ff,wireframe:true,transparent:true,opacity:.9})); root.add(core);
  const glow=new THREE.Mesh(new THREE.IcosahedronGeometry(3.3,0), new THREE.MeshBasicMaterial({color:0x39e1ff,wireframe:true,transparent:true,opacity:.15})); root.add(glow);
  const scan=new THREE.Mesh(new THREE.TorusGeometry(5.2,.05,8,64), new THREE.MeshBasicMaterial({color:0x39e1ff,transparent:true,opacity:.5})); scan.rotation.x=Math.PI/2; root.add(scan);
  const impGeo=new THREE.SphereGeometry(.24,8,8);
  const ORDER=['gpu','cpu','ram','disk']; let nodes=[], nodeMeshes=[], spin=1.0, coreCol=new THREE.Color(0x39e1ff);

  function ringLine(rad,a0,a1,col,op){ const seg=52,p=[]; for(let k=0;k<=seg;k++){ const a=a0+(a1-a0)*k/seg; p.push(new THREE.Vector3(Math.cos(a)*rad,Math.sin(a)*rad,0)); } return new THREE.Line(new THREE.BufferGeometry().setFromPoints(p), new THREE.LineBasicMaterial({color:col,transparent:true,opacity:op})); }
  function label(name,val,hex){
    const c=document.createElement('canvas'); c.width=300;c.height=88; const x=c.getContext('2d');
    x.font='900 40px "Segoe UI",sans-serif'; x.fillStyle=hex; x.textAlign='center'; x.shadowColor=hex; x.shadowBlur=15; x.fillText(val,150,40);
    x.shadowBlur=0; x.font='700 20px "Segoe UI",sans-serif'; x.fillStyle='#dbe7fb'; x.fillText(name,150,74);
    const tex=new THREE.CanvasTexture(c); tex.minFilter=THREE.LinearFilter;
    const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:tex,transparent:true,depthTest:false})); sp.scale.set(6.2,1.82,1); return sp;
  }
  function clearNodes(){ nodes.forEach(b=>{ root.remove(b.grp); b.grp.traverse(o=>{ if(o.geometry&&o.geometry!==impGeo)o.geometry.dispose(); if(o.material){ if(o.material.map)o.material.map.dispose(); o.material.dispose(); } }); }); nodes=[]; nodeMeshes=[]; }
  function build(comps){
    clearNodes();
    ORDER.forEach((key,i)=>{
      const c=(comps||[]).find(x=>x.key===key)||{key,name:key.toUpperCase(),score:0};
      const ang=(i/4)*Math.PI*2 - Math.PI/2, r=11.5; const hex=CKEY[key]; const col=new THREE.Color(hex);
      const s=(c.score||0)/100; const ex=Math.cos(ang)*r, ey=Math.sin(ang)*r; const grp=new THREE.Group();
      grp.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0,0,0),new THREE.Vector3(ex,ey,0)]), new THREE.LineBasicMaterial({color:col,transparent:true,opacity:.25+s*.5})));
      const track=ringLine(2.0,-Math.PI/2,Math.PI*1.5,col,.12); track.position.set(ex,ey,0); grp.add(track);
      const gauge=ringLine(2.0,-Math.PI/2,-Math.PI/2+Math.max(.02,s)*Math.PI*2,col,.92); gauge.position.set(ex,ey,0); grp.add(gauge);
      const node=new THREE.Mesh(new THREE.IcosahedronGeometry(.8+s*1.5,0), new THREE.MeshBasicMaterial({color:col,wireframe:true,transparent:true,opacity:.5+s*.5}));
      node.position.set(ex,ey,0); node.userData={key,name:c.name,score:c.score}; grp.add(node); nodeMeshes.push(node);
      const lbl=label((c.name||key).replace(/\s*\(.*\)/,''), String(c.score||0), hex); lbl.position.set(ex, ey+(1.6+s*1.5)+1.2, 0); grp.add(lbl);
      const imp=new THREE.Mesh(impGeo,new THREE.MeshBasicMaterial({color:hex,transparent:true,opacity:.85})); grp.add(imp);
      root.add(grp); nodes.push({grp,node,imp,ex,ey,s,phase:i/4});
    });
  }
  build([]);

  // hover tooltip + drag-to-rotate (gamer-style orbit with the mouse)
  const ray=new THREE.Raycaster(), m=new THREE.Vector2(); const tip=document.getElementById('mapTip'); let hov=-1;
  let drag=false, px=0, py=0, yaw=0, pitch=-0.12, autoY=true;
  cv.addEventListener('pointerdown',ev=>{ drag=true; autoY=false; px=ev.clientX; py=ev.clientY; cv.classList.add('drag'); cv.setPointerCapture&&cv.setPointerCapture(ev.pointerId); });
  addEventListener('pointerup',ev=>{ if(drag){ drag=false; cv.classList.remove('drag'); } });
  cv.addEventListener('pointermove',ev=>{ const rect=cv.getBoundingClientRect();
    if(drag){ yaw+=(ev.clientX-px)*0.008; pitch=Math.max(-1.1,Math.min(1.1,pitch+(ev.clientY-py)*0.006)); px=ev.clientX; py=ev.clientY; tip.style.opacity='0'; return; }
    m.x=((ev.clientX-rect.left)/rect.width)*2-1; m.y=-((ev.clientY-rect.top)/rect.height)*2+1;
    ray.setFromCamera(m,cam); const h=ray.intersectObjects(nodeMeshes,false);
    if(h.length){ const u=h[0].object.userData; hov=1; cv.style.cursor='pointer'; tip.innerHTML=`<b style="color:${CKEY[u.key]}">${esc(u.name)}</b> · ${u.score}/100`; tip.style.left=(ev.clientX-rect.left)+'px'; tip.style.top=(ev.clientY-rect.top)+'px'; tip.style.opacity='1'; }
    else { hov=-1; cv.style.cursor='grab'; tip.style.opacity='0'; } });
  cv.addEventListener('pointerleave',()=>{ tip.style.opacity='0'; });
  // scroll = zoom
  cv.addEventListener('wheel',ev=>{ ev.preventDefault(); cam.position.z=Math.max(16,Math.min(40,cam.position.z+ev.deltaY*0.02)); },{passive:false});

  let paused=false, raf=0;
  function resize(){ W=cv.clientWidth;H=cv.clientHeight; if(W&&H){ cam.aspect=W/H; cam.updateProjectionMatrix(); rn.setSize(W,H,false);} }
  addEventListener('resize',resize);
  document.addEventListener('fullscreenchange',()=>setTimeout(resize,60));
  document.addEventListener('visibilitychange',()=>{ paused=document.hidden; if(!paused){ cancelAnimationFrame(raf); loop(); } });
  function loop(){ if(paused) return; raf=requestAnimationFrame(loop); const t=Date.now();
    stars.rotation.y+=.0004; stars.rotation.x+=.0001;
    core.rotation.y+=.01*spin; core.rotation.x+=.005*spin; glow.rotation.y-=.006; core.scale.setScalar(1+Math.sin(t*.004)*.05);
    core.material.color.lerp(coreCol,0.04); glow.material.color.copy(core.material.color);
    scan.rotation.z+=.03*spin; scan.material.opacity=0.15+0.35*Math.abs(Math.sin(t*.002))*(spin>1?1:.4);
    if(autoY && hov<0 && !drag) yaw+=0.0011;
    root.rotation.y=yaw; root.rotation.x=pitch;
    nodes.forEach((b,i)=>{ b.node.rotation.y+=.02; b.node.rotation.x+=.01;
      const spd=.008+b.s*.016; b.phase=(b.phase+spd)%1; const f=b.phase; b.imp.position.set(b.ex*f,b.ey*f,0); b.imp.material.opacity=.85*(1-Math.abs(f-.5)*1.2);
      b.node.scale.setScalar(1+Math.sin(t*.005+b.ex)*.06);
    });
    rn.render(sc,cam);
  }
  loop();
  return {
    spinUp(){ spin=3.2; coreCol=new THREE.Color(0x39e1ff); build([]); },
    setResult(comps,tierHex){ spin=1.0; coreCol=new THREE.Color(tierHex); build(comps); },
    idle(){ spin=1.0; build([]); }
  };
}

loadRigs();
GL=initGL();

// Fullscreen — the WebGL reactor ONLY (the animation), but with in-canvas overlays so you
// still see every score + finding AND can run the test from inside fullscreen.
document.getElementById('fsBtn').addEventListener('click',()=>{
  const w=document.getElementById('reactor');
  if(!document.fullscreenElement){ (w.requestFullscreen||w.webkitRequestFullscreen||function(){}).call(w); }
  else document.exitFullscreen();
});
document.addEventListener('fullscreenchange',()=>{
  const b=document.getElementById('fsBtn'); const on=!!document.fullscreenElement;
  b.innerHTML=on?'<i class="fa-solid fa-compress"></i> Exit':'<i class="fa-solid fa-expand"></i> Fullscreen';
});
</script>
</body></html>
