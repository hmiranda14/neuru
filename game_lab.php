<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — GAME LAB. One-click gamer optimizers/fixers over the same agentless
// PowerShell-SSH engine as the rest of Gaming (nm_gamefix + nm_winhost). Six tools,
// one "Tactical Console" UX. RBAC: 'gaming'. Universal — any monitored Windows rig.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_gamefix.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'gaming')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=gaming'); exit;
}

// ── API ───────────────────────────────────────────────────────────────────────
if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if (function_exists('session_write_close')) @session_write_close();   // release the lock BEFORE slow SSH

    if ($api === 'rigs') {
        $rows = function_exists('nm_win_hosts') ? nm_win_hosts($conn) : [];
        echo json_encode(['ok'=>true,'rigs'=>array_map(fn($r)=>['id'=>(int)$r['id'],'name'=>$r['name']??('rig '.$r['id'])], $rows)]);
        exit;
    }

    $rid  = (int)($_GET['rig'] ?? $_POST['rig'] ?? 0);
    $tool = preg_replace('/[^a-z]/','', (string)($_GET['tool'] ?? $_POST['tool'] ?? ''));
    $h    = $rid ? (function_exists('nm_win_host') ? nm_win_host($conn,$rid) : null) : null;
    if (!$h)   { echo json_encode(['ok'=>false,'error'=>'Pick a rig first.']); exit; }
    if (!array_key_exists($tool, nm_gf_tools())) { echo json_encode(['ok'=>false,'error'=>'Unknown tool.']); exit; }
    $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn,$h) : null;
    if (!$ssh) { echo json_encode(['ok'=>false,'error'=>'This rig has no SSH configured — add credentials in the Windows monitor.']); exit; }

    if ($api === 'probe') {
        log_user_action($conn,'gamelab_probe',$tool.' @ '.($h['name']??$rid));
        echo json_encode(nm_gf_probe($ssh,$tool)); exit;
    }
    if ($api === 'fix') {
        $fix = (string)($_POST['fix'] ?? '');
        log_user_action($conn,'gamelab_fix',$tool.':'.$fix.' @ '.($h['name']??$rid));
        echo json_encode(nm_gf_fix($conn,$ssh,$tool,$fix)); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'unknown endpoint']); exit;
}

$tools = nm_gf_tools();
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
include('header.php'); nm_gamers_hub_pill();
?>
<video autoplay muted loop playsinline id="bg-video" style="position:fixed;inset:0;z-index:-3;object-fit:cover;min-width:100%;min-height:100%;opacity:.08"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<script src="/three.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --cy:#39e1ff; --pk:#b06bff; --bl:#4da3ff; --gd:#ffcf6b; --rd:#ff5a7a; --gr:#7CFFB2; --bd:rgba(120,150,255,.16); }
*,*::before,*::after{ box-sizing:border-box; }
html{ background:#04060d; }
body{ margin:0; background:#04060d !important; color:#e6ecf7; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; overflow-x:hidden; }
#nm-netbg{ z-index:0 !important; }
<?= function_exists('nm_chrome_css') ? nm_chrome_css() : '' ?>
.gl{ max-width:1200px; margin:0 auto; padding:18px 20px 70px; color:#dbe6f5; position:relative; z-index:1; }
.gl *{ box-sizing:border-box; }

/* ── HERO with WebGL reactor ── */
.gl-hero{ position:relative; min-height:252px; border-radius:22px; overflow:hidden; margin-bottom:24px;
  border:1px solid rgba(120,150,255,.22);
  background:radial-gradient(120% 150% at 82% 18%, rgba(57,225,255,.10), transparent 55%),
             radial-gradient(120% 160% at 12% 96%, rgba(176,107,255,.13), transparent 55%),
             linear-gradient(160deg, rgba(9,14,28,.9), rgba(5,8,18,.92));
  box-shadow:0 22px 64px rgba(0,0,0,.45), inset 0 0 70px rgba(57,225,255,.05); }
#labbg{ position:absolute; inset:0; width:100%; height:100%; display:block; }
.gl-hero .scrim{ position:absolute; inset:0; pointer-events:none;
  background:linear-gradient(100deg, rgba(4,7,15,.94) 18%, rgba(4,7,15,.5) 48%, transparent 74%); }
.gl-hero .hc{ position:relative; z-index:2; padding:32px 34px; max-width:580px; }
.gl-badge{ display:inline-flex; align-items:center; gap:8px; font-size:11px; font-weight:800; letter-spacing:2px; text-transform:uppercase;
  color:#8be9ff; background:rgba(57,225,255,.1); border:1px solid rgba(57,225,255,.3); padding:5px 13px; border-radius:30px; margin-bottom:15px; }
.gl-badge .dot{ width:7px; height:7px; border-radius:50%; background:#39e1ff; box-shadow:0 0 10px #39e1ff; animation:pulseDot 1.6s infinite; }
@keyframes pulseDot{ 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.35;transform:scale(.65)} }
.gl-title{ margin:0; font-size:clamp(36px,5.4vw,58px); font-weight:900; letter-spacing:1px; line-height:.95;
  background:linear-gradient(92deg,#eafcff,#8be9ff 42%,#eafcff); -webkit-background-clip:text; background-clip:text; color:transparent;
  filter:drop-shadow(0 0 26px rgba(57,225,255,.4)); animation:titleFlick 7s infinite; }
.gl-title .lab{ background:linear-gradient(92deg,#b06bff,#ff7ac0 55%,#ffcf6b); -webkit-background-clip:text; background-clip:text; color:transparent;
  filter:drop-shadow(0 0 26px rgba(176,107,255,.5)); }
@keyframes titleFlick{ 0%,96%,100%{opacity:1} 96.5%{opacity:.62} 97.2%{opacity:1} 97.7%{opacity:.82} 98.2%{opacity:1} }
.gl-sub{ color:#a9c4e6; font-size:14px; margin:13px 0 18px; max-width:450px; line-height:1.55; }
.rigsel{ display:inline-flex; align-items:center; gap:10px; background:rgba(6,12,24,.6); border:1px solid rgba(57,225,255,.28);
  border-radius:12px; padding:7px 8px 7px 14px; box-shadow:0 0 26px rgba(57,225,255,.08); }
.rigsel .rl{ color:#8be9ff; font-size:11px; font-weight:800; letter-spacing:1.5px; text-transform:uppercase; display:flex; align-items:center; gap:7px; white-space:nowrap; }
.rigsel select{ background:rgba(3,7,16,.85); border:1px solid rgba(120,150,255,.3); color:#dfeeff; border-radius:9px; padding:8px 12px; font-size:13px; outline:none; cursor:pointer; }

/* ── optimizer modules ── */
.gl-secttl{ display:flex; align-items:center; gap:11px; font-size:12px; font-weight:800; letter-spacing:2.5px; text-transform:uppercase; color:#7fa8d6; margin:0 2px 16px; }
.gl-secttl i{ color:var(--cy); }
.gl-secttl::after{ content:''; flex:1; height:1px; background:linear-gradient(90deg,rgba(120,150,255,.35),transparent); }
.gl-grid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(330px,1fr)); gap:18px; perspective:1300px; }
.tool{ --c:#4da3ff; position:relative; background:linear-gradient(165deg,rgba(14,20,38,.74),rgba(8,12,24,.66)); backdrop-filter:blur(14px);
  border:1px solid rgba(255,255,255,.09); border-radius:18px; padding:20px 20px 18px; overflow:hidden; transform-style:preserve-3d;
  transition:transform .18s cubic-bezier(.2,.7,.3,1), box-shadow .25s, border-color .25s; opacity:0; animation:cardIn .6s cubic-bezier(.2,.8,.3,1) forwards; }
@keyframes cardIn{ from{opacity:0; transform:translateY(26px) rotateX(-7deg)} to{opacity:1; transform:none} }
.tool::before{ content:''; position:absolute; inset:0; border-radius:18px; padding:1.2px; pointer-events:none; opacity:0; transition:opacity .3s;
  background:radial-gradient(180px 180px at var(--mx,50%) var(--my,0%), var(--c), transparent 62%);
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0); -webkit-mask-composite:xor; mask-composite:exclude; }
.tool:hover{ border-color:transparent; box-shadow:0 24px 64px rgba(0,0,0,.5), 0 0 46px -10px var(--c); }
.tool:hover::before{ opacity:.95; }
.tool .shine{ content:''; position:absolute; top:0; left:-60%; width:42%; height:100%; pointer-events:none; transform:skewX(-18deg);
  background:linear-gradient(105deg,transparent,rgba(255,255,255,.1),transparent); transition:left .65s ease; }
.tool:hover .shine{ left:135%; }
.tool .ic{ position:relative; width:52px; height:52px; border-radius:15px; display:grid; place-items:center; font-size:24px; margin-bottom:14px; }
.tool .ic::after{ content:''; position:absolute; inset:-5px; border-radius:18px; border:1px solid var(--c); opacity:.35; animation:ringPulse 2.6s ease-in-out infinite; }
@keyframes ringPulse{ 0%,100%{transform:scale(1);opacity:.35} 55%{transform:scale(1.16);opacity:0} }
.tool h3{ margin:0 0 6px; font-size:17.5px; font-weight:800; color:#f2f8ff; }
.tool p{ margin:0 0 16px; font-size:12.5px; color:#9db4d2; line-height:1.55; min-height:40px; }
.tool .rdy{ position:absolute; top:15px; right:16px; font-size:9.5px; font-weight:800; letter-spacing:1.5px; color:#7CFFB2; display:flex; align-items:center; gap:5px; text-transform:uppercase; opacity:.8; }
.tool .rdy .d{ width:6px; height:6px; border-radius:50%; background:#7CFFB2; box-shadow:0 0 8px #7CFFB2; animation:pulseDot 1.9s infinite; }
.runbtn{ position:relative; width:100%; border:none; border-radius:12px; padding:12px; font-size:13.5px; font-weight:800; cursor:pointer; color:#04121a;
  display:flex; align-items:center; justify-content:center; gap:8px; overflow:hidden; transition:transform .12s, filter .15s, box-shadow .2s; }
.runbtn:hover{ filter:brightness(1.15); box-shadow:0 10px 26px -8px var(--c); transform:translateY(-1px); }
.runbtn:active{ transform:translateY(0); }
@media(prefers-reduced-motion:reduce){ .tool,.gl-title,.tool .ic::after,.gl-badge .dot,.tool .rdy .d{ animation:none!important; } }
/* ── Tactical Console ── */
#glcOverlay{ position:fixed; inset:0; z-index:900; background:rgba(3,7,16,.72); backdrop-filter:blur(6px); display:none; align-items:center; justify-content:center; padding:24px; }
#glc{ width:min(720px,96vw); max-height:90vh; overflow:auto; background:linear-gradient(160deg,rgba(10,16,32,.98),rgba(8,12,24,.98)); border:1px solid rgba(120,150,255,.35); border-radius:18px; box-shadow:0 24px 80px rgba(0,0,0,.6); }
#glc .glc-h{ display:flex; align-items:center; gap:12px; padding:16px 20px; border-bottom:1px solid rgba(255,255,255,.08); }
#glc .glc-h .ic{ width:40px; height:40px; border-radius:11px; display:grid; place-items:center; font-size:19px; }
#glc .glc-h h2{ margin:0; font-size:18px; font-weight:800; flex:1; }
#glc .glc-x{ cursor:pointer; color:#8fb4dd; font-size:20px; }
#glc .glc-body{ padding:18px 20px; }
.glc-steps{ font-family:Consolas,'SF Mono',monospace; font-size:13px; line-height:1.9; }
.glc-steps .st{ display:flex; align-items:center; gap:10px; opacity:0; transform:translateX(-8px); transition:opacity .25s, transform .25s; }
.glc-steps .st.in{ opacity:1; transform:none; }
.glc-steps .st .lbl{ flex:1; color:#c6d6 ; color:#cdd9ea; }
.glc-steps .st .tag{ font-weight:800; font-size:11px; padding:2px 9px; border-radius:20px; white-space:nowrap; }
.tag.ok{ background:rgba(124,255,178,.16); color:#7CFFB2; } .tag.warn{ background:rgba(255,207,107,.16); color:var(--gd); } .tag.err{ background:rgba(255,90,122,.16); color:var(--rd); }
.glc-steps .st .dt{ color:#7f97b6; font-size:11.5px; }
.glc-score{ display:flex; align-items:center; gap:16px; margin:18px 0; padding:14px 16px; border:1px solid rgba(255,255,255,.08); border-radius:14px; background:rgba(255,255,255,.02); }
.badges{ display:flex; flex-wrap:wrap; gap:8px; }
.bdg{ font-size:11.5px; font-weight:800; padding:4px 11px; border-radius:20px; }
.bdg.green{ background:rgba(124,255,178,.16); color:#7CFFB2; } .bdg.amber{ background:rgba(255,207,107,.16); color:var(--gd); } .bdg.red{ background:rgba(255,90,122,.16); color:var(--rd); }
.glc-find{ margin:6px 0 4px; }
.glc-find .f{ font-size:12.5px; color:#c3d3e8; padding:7px 12px; border-left:3px solid rgba(120,150,255,.5); background:rgba(120,150,255,.06); border-radius:0 8px 8px 0; margin-bottom:7px; }
.glc-fixes{ margin-top:14px; display:flex; flex-direction:column; gap:9px; }
.fixbtn{ text-align:left; border:1px solid rgba(120,150,255,.35); background:rgba(120,150,255,.08); color:#eaf2ff; border-radius:12px; padding:11px 14px; cursor:pointer; transition:background .15s, border-color .15s; }
.fixbtn:hover{ background:rgba(120,150,255,.16); border-color:var(--bl); }
.fixbtn .ft{ font-weight:800; font-size:13.5px; display:flex; align-items:center; gap:8px; }
.fixbtn .fd{ font-size:11.5px; color:#9db4d2; margin-top:3px; }
.fixbtn.danger{ border-color:rgba(255,207,107,.4); background:rgba(255,207,107,.07); }
.glc-msg{ margin-top:12px; font-size:13px; padding:11px 14px; border-radius:11px; }
.glc-msg.ok{ background:rgba(124,255,178,.1); color:#bff5d6; border:1px solid rgba(124,255,178,.25); }
.glc-msg.err{ background:rgba(255,90,122,.1); color:#ffc2cf; border:1px solid rgba(255,90,122,.25); }
.glc-spin{ text-align:center; padding:26px; color:#8fb4dd; }
.glc-spin i{ font-size:26px; }
</style>

<div class="gl">
  <div class="gl-hero">
    <canvas id="labbg"></canvas>
    <div class="scrim"></div>
    <div class="hc">
      <div class="gl-badge"><span class="dot"></span> Agentless · Reversible · Zero terminal</div>
      <h1 class="gl-title">GAME <span class="lab">LAB</span></h1>
      <div class="gl-sub">One-click optimizers for your rig — purge lag, kill crashes, tune drivers &amp; storage, lock your FPS. Every fix is reversible.</div>
      <div class="rigsel">
        <span class="rl"><i class="fa-solid fa-crosshairs"></i> Target rig</span>
        <select id="rigSel"><option value="">Loading…</option></select>
      </div>
    </div>
  </div>

  <div class="gl-secttl"><i class="fa-solid fa-microchip"></i> Optimizer Modules</div>

  <div class="gl-grid" id="grid">
    <?php $ci=0; foreach ($tools as $k=>$t): ?>
    <div class="tool" data-tool="<?= $k ?>" style="--c:<?= $t[2] ?>;animation-delay:<?= $ci*70 ?>ms">
      <span class="shine"></span>
      <span class="rdy"><span class="d"></span> Ready</span>
      <div class="ic" style="background:<?= $t[2] ?>1e;border:1px solid <?= $t[2] ?>55;color:<?= $t[2] ?>"><i class="fa-solid <?= $t[1] ?>"></i></div>
      <h3><?= htmlspecialchars($t[0]) ?></h3>
      <p><?= htmlspecialchars($t[3]) ?></p>
      <button class="runbtn" style="background:linear-gradient(120deg,<?= $t[2] ?>,<?= $t[2] ?>cc)" onclick="runTool('<?= $k ?>')"><i class="fa-solid fa-play"></i> Run scan</button>
    </div>
    <?php $ci++; endforeach; ?>
  </div>
</div>

<div id="glcOverlay" onclick="if(event.target===this)closeGlc()">
  <div id="glc">
    <div class="glc-h"><div class="ic" id="glcIc"></div><h2 id="glcTitle"></h2><span class="glc-x" onclick="closeGlc()"><i class="fa-solid fa-xmark"></i></span></div>
    <div class="glc-body" id="glcBody"></div>
  </div>
</div>

<script>
const TOOLS = <?= json_encode(array_map(fn($t)=>['t'=>$t[0],'i'=>$t[1],'c'=>$t[2]], $tools)) ?>;
const esc = s => String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let RIG = '';

async function loadRigs(){
  try{ const d=await fetch('game_lab.php?api=rigs').then(r=>r.json());
    const sel=document.getElementById('rigSel');
    if(d.ok && d.rigs.length){ sel.innerHTML=d.rigs.map(r=>`<option value="${r.id}">${esc(r.name)}</option>`).join(''); RIG=sel.value; }
    else sel.innerHTML='<option value="">No rigs — add a Windows host</option>';
  }catch(e){ document.getElementById('rigSel').innerHTML='<option value="">error</option>'; }
}
document.getElementById('rigSel').addEventListener('change', e=>RIG=e.target.value);

function rc(score){ return score>=85?'var(--gr)':(score>=60?'var(--gd)':'var(--rd)'); }

async function runTool(tool){
  if(!RIG){ alert('Pick a rig first.'); return; }
  const t=TOOLS[tool];
  document.getElementById('glcIc').style.cssText=`background:${t.c}22;border:1px solid ${t.c}55;color:${t.c}`;
  document.getElementById('glcIc').innerHTML=`<i class="fa-solid ${t.i}"></i>`;
  document.getElementById('glcTitle').textContent=t.t;
  document.getElementById('glcBody').innerHTML='<div class="glc-spin"><i class="fa-solid fa-satellite-dish fa-beat-fade"></i><div style="margin-top:10px">Scanning your rig…</div></div>';
  document.getElementById('glcOverlay').style.display='flex';
  let d; try{ d=await fetch(`game_lab.php?api=probe&tool=${tool}&rig=${RIG}&_=${Date.now()}`).then(r=>r.json()); }
  catch(e){ d={ok:false,error:'Request failed.'}; }
  renderProbe(tool,d);
}

function renderProbe(tool,d){
  const body=document.getElementById('glcBody');
  if(!d.ok){ body.innerHTML=`<div class="glc-msg err"><i class="fa-solid fa-triangle-exclamation"></i> ${esc(d.error||'Scan failed.')}</div>`; return; }
  const steps=(d.steps||[]).map(s=>`<div class="st"><i class="fa-solid ${s.status==='ok'?'fa-circle-check':(s.status==='warn'?'fa-triangle-exclamation':'fa-circle-xmark')}" style="color:${s.status==='ok'?'var(--gr)':(s.status==='warn'?'var(--gd)':'var(--rd)')}"></i><span class="lbl">${esc(s.label)}</span><span class="dt">${esc(s.detail||'')}</span><span class="tag ${s.status}">${s.status.toUpperCase()}</span></div>`).join('');
  const badges=(d.badges||[]).map(b=>`<span class="bdg ${b[0]}">${esc(b[1])}</span>`).join('');
  const find=(d.findings||[]).map(f=>`<div class="f">${esc(f)}</div>`).join('');
  const fixes=(d.fixes||[]).map(f=>`<button class="fixbtn ${f.danger?'danger':''}" onclick='applyFix(${JSON.stringify(tool)},${JSON.stringify(f.key)},${JSON.stringify(f.label)},${JSON.stringify(f.desc)},${f.danger?1:0})'><div class="ft"><i class="fa-solid fa-wand-magic-sparkles" style="color:var(--cy)"></i> ${esc(f.label)}</div><div class="fd">${esc(f.desc)}</div></button>`).join('');
  body.innerHTML=`
    <div class="glc-steps" id="glcSteps">${steps}</div>
    <div class="glc-score">
      <div style="position:relative;width:88px;height:88px;flex:0 0 auto">
        <canvas id="glcOrb" width="176" height="176" style="width:88px;height:88px"></canvas>
        <b style="position:absolute;inset:0;display:grid;place-items:center;font-size:23px;font-weight:900;color:${rc(d.score||0)};text-shadow:0 0 14px ${rc(d.score||0)}">${d.score||0}</b>
      </div>
      <div style="flex:1"><div style="font-size:11px;color:#8fb4dd;letter-spacing:1px;text-transform:uppercase;margin-bottom:7px">Stability Score</div><div class="badges">${badges}</div></div>
    </div>
    ${find?`<div class="glc-find">${find}</div>`:''}
    ${fixes?`<div style="font-size:11px;color:#8fb4dd;letter-spacing:1px;text-transform:uppercase;margin:14px 0 2px">1-Click Fixes</div><div class="glc-fixes">${fixes}</div>`:'<div class="glc-msg ok" style="margin-top:14px"><i class="fa-solid fa-circle-check"></i> Nothing to fix — this looks healthy. 🟢</div>'}
  `;
  // animate the step log + WebGL score orb + bg pulse
  const els=[...document.querySelectorAll('#glcSteps .st')];
  els.forEach((el,i)=>setTimeout(()=>el.classList.add('in'), 90*i));
  renderOrb(d.score||0);
}

// ── WebGL: holographic score orb (in the console) ──
let _orbRAF=null;
function renderOrb(score){
  const cv=document.getElementById('glcOrb'); if(!window.THREE||!cv) return;
  if(_orbRAF){ cancelAnimationFrame(_orbRAF); _orbRAF=null; }
  const col = score>=85?0x7CFFB2:(score>=60?0xffcf6b:0xff5a7a);
  const rn=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true}); rn.setPixelRatio(Math.min(2,devicePixelRatio)); rn.setSize(88,88,false);
  const sc=new THREE.Scene(), cam=new THREE.PerspectiveCamera(50,1,.1,20); cam.position.z=3.5;
  const core=new THREE.Mesh(new THREE.IcosahedronGeometry(1.12,1), new THREE.MeshBasicMaterial({color:col,wireframe:true,transparent:true,opacity:.95}));
  const shell=new THREE.Mesh(new THREE.IcosahedronGeometry(1.42,1), new THREE.MeshBasicMaterial({color:col,wireframe:true,transparent:true,opacity:.16}));
  sc.add(core,shell);
  const bad=(100-score)/100;
  (function loop(){ _orbRAF=requestAnimationFrame(loop); const t=Date.now();
    core.rotation.y+=.012+bad*.022; core.rotation.x+=.006; shell.rotation.y-=.008; shell.rotation.z+=.004;
    const s=1+Math.sin(t*.004)*(.03+bad*.07); core.scale.setScalar(s); shell.scale.setScalar(1+Math.sin(t*.003+1)*.04);
    rn.render(sc,cam);
  })();
}

async function applyFix(tool,key,label,desc,danger){
  if(danger && !confirm(label+'\n\n'+desc+'\n\nThis runs on your PC. Continue?')) return;
  const btn=event.currentTarget; btn.disabled=true; btn.style.opacity=.6;
  btn.querySelector('.ft').innerHTML='<i class="fa-solid fa-gear fa-spin" style="color:var(--cy)"></i> Applying…';
  const fd=new URLSearchParams({rig:RIG,tool:tool,fix:key});
  let d; try{ d=await fetch('game_lab.php?api=fix',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:fd}).then(r=>r.json()); }
  catch(e){ d={ok:false,error:'Request failed.'}; }
  const log=(d.log||[]).map(l=>`<div class="st in"><i class="fa-solid fa-angle-right" style="color:var(--cy)"></i><span class="lbl">${esc(l)}</span><span class="tag ok">DONE</span></div>`).join('');
  const msg=`<div class="glc-msg ${d.ok?'ok':'err'}"><i class="fa-solid ${d.ok?'fa-circle-check':'fa-triangle-exclamation'}"></i> ${esc(d.ok?(d.msg||'Applied.'):(d.error||'Failed.'))}</div>`;
  const wrap=document.createElement('div'); wrap.style.marginTop='12px';
  wrap.innerHTML=`<div class="glc-steps">${log}</div>${msg}`;
  document.getElementById('glcBody').appendChild(wrap);
  btn.querySelector('.ft').innerHTML='<i class="fa-solid fa-circle-check" style="color:var(--gr)"></i> '+esc(label);
  wrap.scrollIntoView({behavior:'smooth',block:'center'});
}
function closeGlc(){ document.getElementById('glcOverlay').style.display='none'; if(_orbRAF){cancelAnimationFrame(_orbRAF);_orbRAF=null;} }
document.addEventListener('keydown',e=>{ if(e.key==='Escape')closeGlc(); });

// ── WebGL "Lab Reactor" hero ──────────────────────────────────────────────────
function labHero(){
  const cv=document.getElementById('labbg'); if(!window.THREE||!cv) return;
  const wrap=cv.parentElement;
  const rn=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true}); rn.setPixelRatio(Math.min(2,devicePixelRatio));
  const sc=new THREE.Scene(), cam=new THREE.PerspectiveCamera(55,2,.1,100); cam.position.z=6.4;
  const g=new THREE.Group(); g.position.x=2.2; sc.add(g);
  const core =new THREE.Mesh(new THREE.IcosahedronGeometry(1.5,1),  new THREE.MeshBasicMaterial({color:0x39e1ff,wireframe:true,transparent:true,opacity:.9}));
  const inner=new THREE.Mesh(new THREE.IcosahedronGeometry(0.95,0), new THREE.MeshBasicMaterial({color:0xb06bff,wireframe:true,transparent:true,opacity:.55}));
  const shell=new THREE.Mesh(new THREE.IcosahedronGeometry(2.15,1), new THREE.MeshBasicMaterial({color:0x4da3ff,wireframe:true,transparent:true,opacity:.12}));
  g.add(core,inner,shell);
  const ring =new THREE.Mesh(new THREE.TorusGeometry(2.7,.016,8,90), new THREE.MeshBasicMaterial({color:0x39e1ff,transparent:true,opacity:.35})); ring.rotation.x=1.15; g.add(ring);
  const ring2=new THREE.Mesh(new THREE.TorusGeometry(3.15,.01,8,90), new THREE.MeshBasicMaterial({color:0xb06bff,transparent:true,opacity:.22})); ring2.rotation.set(1.15,.5,0); g.add(ring2);
  const N=520, pos=new Float32Array(N*3); for(let i=0;i<N;i++){ pos[i*3]=(Math.random()-.5)*28; pos[i*3+1]=(Math.random()-.5)*16; pos[i*3+2]=(Math.random()-.5)*20-4; }
  const sg=new THREE.BufferGeometry(); sg.setAttribute('position',new THREE.BufferAttribute(pos,3));
  const stars=new THREE.Points(sg,new THREE.PointsMaterial({color:0x9fd6ff,size:.05,transparent:true,opacity:.7})); sc.add(stars);
  function size(){ const w=wrap.clientWidth||800,h=wrap.clientHeight||252; rn.setSize(w,h,false); cam.aspect=w/h; cam.updateProjectionMatrix(); }
  size(); addEventListener('resize',size);
  let mx=0,my=0; wrap.addEventListener('mousemove',e=>{ const r=wrap.getBoundingClientRect(); mx=((e.clientX-r.left)/r.width-.5); my=((e.clientY-r.top)/r.height-.5); });
  (function loop(){ requestAnimationFrame(loop); const t=Date.now()*.001;
    core.rotation.y+=.004; core.rotation.x=Math.sin(t*.3)*.12; inner.rotation.y-=.012; inner.rotation.x+=.007; shell.rotation.y+=.002;
    ring.rotation.z+=.004; ring2.rotation.z-=.003; stars.rotation.y+=.0004; core.scale.setScalar(1+Math.sin(t*1.6)*.03);
    cam.position.x += (mx*1.5 - cam.position.x)*.05; cam.position.y += (-my*1.1 - cam.position.y)*.05; cam.lookAt(1.6,0,0);
    rn.render(sc,cam);
  })();
}
// ── card 3D tilt + glow-follows-cursor ──
function labCards(){
  document.querySelectorAll('.tool').forEach(card=>{
    card.addEventListener('mousemove',e=>{ const r=card.getBoundingClientRect(); const px=(e.clientX-r.left)/r.width-.5, py=(e.clientY-r.top)/r.height-.5;
      card.style.transform=`translateY(-4px) rotateX(${(-py*7).toFixed(2)}deg) rotateY(${(px*9).toFixed(2)}deg)`;
      card.style.setProperty('--mx',((e.clientX-r.left)/r.width*100).toFixed(1)+'%');
      card.style.setProperty('--my',((e.clientY-r.top)/r.height*100).toFixed(1)+'%');
    });
    card.addEventListener('mouseleave',()=>{ card.style.transform=''; });
  });
}
labHero(); labCards();
loadRigs();
</script>
</body></html>
