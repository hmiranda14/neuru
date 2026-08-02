<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Netstat graph (Net Tools). Live socket table of the NOC host, read
// straight from /proc/net/{tcp,tcp6,udp,udp6} (no `ss`/`netstat` binary), grouped
// by remote peer + state, with an interactive node graph. RBAC: 'nettools_netstat'.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_nettools.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'nettools_netstat')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=nettools_netstat'); exit;
}
nm_nt_ensure($conn);
$EMBED = (($_GET['embed'] ?? '') === '1');   // Commander overlay → hide the site nav (keep the node picker)
// Release the session lock BEFORE the (up to 45s) remote SSH netstat — otherwise one slow/hung
// host freezes THIS user's whole portal (the "halt"). Every other Net Tools page already does this.
if (function_exists('session_write_close')) session_write_close();

if ($api === 'data') {
    header('Content-Type: application/json; charset=utf-8');
    $target = (string)($_GET['target'] ?? 'local');
    if ($target === '' || $target === 'local') {
        echo json_encode(['ok'=>true,'host'=>'NOC host','kind'=>'local'] + nm_nt_netstat_summary());
    } else {
        echo json_encode(nm_nt_netstat_remote($conn, $target));
    }
    exit;
}

// Host pickers: every Windows + Linux SSH host (so the operator can view ANY
// server's real netstat, not just the local NOC box).
$WIN_HOSTS = []; $LX_HOSTS = [];
if ($conn->query("SHOW TABLES LIKE 'nm_win_hosts'")->num_rows > 0) {
    $r = $conn->query("SELECT id,name,host_ip FROM nm_win_hosts ORDER BY name");
    while ($r && $x = $r->fetch_assoc()) $WIN_HOSTS[] = $x;
}
if ($conn->query("SHOW TABLES LIKE 'nm_lx_hosts'")->num_rows > 0) {
    $r = $conn->query("SELECT id,name,host_ip FROM nm_lx_hosts ORDER BY name");
    while ($r && $x = $r->fetch_assoc()) $LX_HOSTS[] = $x;
}
// Initial target from URL (deep-link from net_mon.php): ?target=win:<id> | lx:<id>
$INIT_TARGET = preg_match('/^(win|lx):\d+$/', (string)($_GET['target'] ?? '')) ? $_GET['target'] : 'local';

log_user_action($conn,'view_page','netstat.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Netstat | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="/vis-network.min.js"></script>
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; }
*,*::before,*::after{ box-sizing:border-box; }
/* PARTICLES (Command-Center recipe): dark bg lives on <html>; <body> is TRANSPARENT so the
   header.php #nm-netbg canvas (position:fixed; z-index:-1) shows through. An opaque body bg
   would hide the particles — this is the bug we hit repeatedly. NEVER put an opaque bg on body. */
html{ background:#05080f; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#e6e9ee; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 40px; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.kpis{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:16px; }
.kpi{ padding:10px 18px; text-align:center; } .kpi .n{ font-size:22px; font-weight:800; } .kpi .l{ font-size:10px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; }
.sec-h{ margin:0 0 8px; font-size:12px; color:var(--accent); text-transform:uppercase; letter-spacing:1px; }
.tgt-sel{ background:rgba(10,16,28,.85); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:7px 12px; font-size:13px; margin-right:8px; max-width:340px; }
.tgt-sel optgroup{ background:#0a0f1a; } .tgt-sel option{ background:#0a0f1a; }

/* ── IMMERSIVE explorer (modeled on netflow.php's #ex-wrap) ────────────────────
   #ns-wrap holds the map (left, flex) + a side panel (right: remote peers + listening).
   It is the FULLSCREEN TARGET: clicking ⛶ fullscreens THIS wrapper (not <html>), and the
   live particle canvas (#nm-netbg) is reparented INTO it so the particles stay visible. */
#ns-wrap{ display:flex; gap:10px; height:66vh; min-height:480px; position:relative;
  border:1px solid var(--border); border-radius:14px; overflow:hidden; background:#05080e; margin-bottom:16px; }
#graph{ flex:1; position:relative; z-index:1; background:transparent;
  background-image:radial-gradient(circle at 50% 40%, rgba(77,163,255,.05), transparent 72%); }
#ns-side{ width:330px; flex:0 0 330px; position:relative; z-index:1; overflow:auto;
  border-left:1px solid rgba(255,255,255,.08); padding:12px 12px 16px; background:rgba(5,8,14,.42); backdrop-filter:blur(5px); }
#ns-fsctrl{ position:absolute; top:10px; left:10px; z-index:6; display:flex; gap:6px; }
.icon-btn{ background:rgba(10,16,28,.72); border:1px solid var(--border); color:#cfe4ff; border-radius:8px;
  min-width:34px; height:32px; padding:0 9px; cursor:pointer; font-size:13px; display:inline-flex; align-items:center; justify-content:center; gap:6px; }
.icon-btn:hover{ border-color:var(--accent); color:#fff; background:rgba(77,163,255,.16); }
#ns-cap{ position:absolute; bottom:10px; left:12px; z-index:6; font-size:11px; color:#8a97aa;
  background:rgba(5,8,14,.55); border:1px solid var(--border); border-radius:8px; padding:5px 10px; backdrop-filter:blur(4px); }
#ns-side .ns-divider{ height:1px; background:rgba(255,255,255,.08); margin:14px 0 12px; }
/* fullscreen: the wrapper fills the screen; particle canvas sits behind the graph */
#ns-wrap:fullscreen, #ns-wrap:-webkit-full-screen{ background:#05080e; padding:14px; height:100vh!important; gap:14px; border:none; border-radius:0; }
#ns-wrap:fullscreen #ns-side, #ns-wrap:-webkit-full-screen #ns-side{ width:380px; flex:0 0 380px; border-radius:12px; }
#ns-wrap:fullscreen #nm-netbg, #ns-wrap:-webkit-full-screen #nm-netbg{ z-index:0!important; }
/* Futuristic loading overlay */
#ns-loader{ position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:18px;
  background:radial-gradient(circle at 50% 45%, rgba(10,16,28,.85), rgba(5,8,15,.96)); border-radius:12px; z-index:5; }
.ns-orbit{ width:84px; height:84px; border-radius:50%; border:2px solid rgba(77,163,255,.18); border-top-color:var(--accent);
  border-right-color:#9b59ff; display:flex; align-items:center; justify-content:center; animation:nsspin 1.05s linear infinite; box-shadow:0 0 28px rgba(77,163,255,.35); }
.ns-orbit i{ font-size:30px; color:#cfe4ff; animation:nspulse 1.6s ease-in-out infinite; }
@keyframes nsspin{ to{ transform:rotate(360deg); } } @keyframes nspulse{ 0%,100%{ opacity:.55; transform:scale(.92);} 50%{ opacity:1; transform:scale(1.08);} }
.ns-ltxt{ font-size:13px; letter-spacing:1.5px; text-transform:uppercase; color:#9fb6d6; font-family:monospace; }
table{ width:100%; border-collapse:collapse; font-size:12.5px; }
th{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; padding:7px 8px; border-bottom:1px solid var(--border); }
td{ padding:7px 8px; border-bottom:1px solid rgba(255,255,255,.05); } .mono{ font-family:monospace; } .muted{ color:#7c828c; font-size:12px; }
.pill{ display:inline-block; font-size:10px; font-weight:700; padding:1px 7px; border-radius:20px; background:rgba(77,163,255,.14); color:#bcd; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:8px 14px; font-size:13px; cursor:pointer; }
.tag{ font-size:10px; padding:1px 7px; border-radius:6px; margin-right:3px; } .est{ background:rgba(46,204,113,.14); color:#7fe0a3; } .lis{ background:rgba(243,156,18,.14); color:#f0c674; } .tw{ background:rgba(155,155,170,.14); color:#bcc; }
<?= nm_chrome_css() ?>
body.embed{ padding-top:0 !important; } body.embed #nm-topbar,body.embed #bg-video,body.embed video{ display:none !important; } body.embed .wrap{ padding:8px 12px 12px !important; max-width:none !important; }
</style></head><body class="<?= $EMBED?'embed':'' ?>">
<?php include('header.php'); ?>
<!-- No <video> background: like the Command Centers, the futuristic look comes from the
     header.php #nm-netbg particle canvas (visible because <body> is transparent). -->
<div class="wrap">
<?php nm_page_header('<i class="fas fa-diagram-project"></i>Netstat', '', 'Net Tools · live sockets', 'fa-solid fa-diagram-project',
  '<select id="target" onchange="changeTarget()" class="tgt-sel">'
  . '<option value="local">🖥 This NOC host (local)</option>'
  . (count($WIN_HOSTS) ? '<optgroup label="Windows servers (SSH)">'
      . implode('', array_map(fn($h)=>'<option value="win:'.(int)$h['id'].'"'.($INIT_TARGET==='win:'.$h['id']?' selected':'').'>🪟 '.htmlspecialchars($h['name']).' — '.htmlspecialchars($h['host_ip']).'</option>', $WIN_HOSTS))
      . '</optgroup>' : '')
  . (count($LX_HOSTS) ? '<optgroup label="Linux servers (SSH)">'
      . implode('', array_map(fn($h)=>'<option value="lx:'.(int)$h['id'].'"'.($INIT_TARGET==='lx:'.$h['id']?' selected':'').'>🐧 '.htmlspecialchars($h['name']).' — '.htmlspecialchars($h['host_ip']).'</option>', $LX_HOSTS))
      . '</optgroup>' : '')
  . '</select>'
  . '<button class="refresh-btn" onclick="load()"><i class="fas fa-rotate"></i> Refresh</button>'); ?>

<div class="kpis">
  <div class="glass kpi"><div class="n" id="k-total">—</div><div class="l">sockets</div></div>
  <div class="glass kpi"><div class="n" id="k-est" style="color:var(--ok)">—</div><div class="l">established</div></div>
  <div class="glass kpi"><div class="n" id="k-listen" style="color:var(--warn)">—</div><div class="l">listening</div></div>
  <div class="glass kpi"><div class="n" id="k-peers">—</div><div class="l">remote peers</div></div>
  <div class="glass kpi"><div class="n" id="k-tw">—</div><div class="l">time_wait</div></div>
</div>

<div id="err-box" class="glass card" style="display:none;border-color:rgba(231,76,60,.5);background:rgba(231,76,60,.08);"></div>

<!-- Immersive explorer: map (left) + side panel (right) in ONE wrapper that fullscreens -->
<div id="ns-wrap">
  <!-- floating icon controls (top-left), like netflow's #ex-fsctrl -->
  <div id="ns-fsctrl">
    <button class="icon-btn" onclick="load()" title="Refresh now"><i class="fas fa-rotate"></i></button>
    <button class="icon-btn" id="fs-btn" onclick="toggleFs()" title="Fullscreen"><i class="fas fa-expand"></i></button>
  </div>

  <!-- the socket map -->
  <div id="graph"></div>
  <div id="ns-cap"><i class="fas fa-circle-nodes" style="color:var(--accent)"></i>
    Center = <b id="center-lbl" style="color:#cfe4ff;">this host</b> · edges = active remote peers (thicker = more)</div>

  <!-- side panel: remote peers + listening (stays inside the wrapper, so it shows in fullscreen) -->
  <div id="ns-side">
    <h3 class="sec-h">Remote peers</h3>
    <table><thead><tr><th>Remote IP</th><th>Port</th><th>Proto</th><th>State</th><th>#</th></tr></thead><tbody id="edges"></tbody></table>
    <div class="ns-divider"></div>
    <h3 class="sec-h">Listening</h3>
    <div id="listen" class="mono" style="font-size:12px;line-height:1.9;"></div>
  </div>

  <!-- futuristic loading overlay (shown while an SSH host is queried) -->
  <div id="ns-loader" style="display:none;">
    <div class="ns-orbit"><i class="fas fa-diagram-project"></i></div>
    <div class="ns-ltxt" id="ns-ltxt">Connecting…</div>
  </div>
</div>
</div>
<script>
let net=null, TARGET=<?= json_encode($INIT_TARGET) ?>, autoTimer=null, centerLabel='NOC host', loaderTimer=null;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function stTag(s){ const m={ESTABLISHED:'est',LISTEN:'lis',TIME_WAIT:'tw'}; return (s||'').split(',').map(x=>`<span class="tag ${m[x]||'tw'}">${esc(x)}</span>`).join(''); }

const LOAD_MSGS=['Opening SSH channel…','Enumerating sockets…','Resolving remote peers…','Building the graph…'];
function showLoader(on){
  const el=document.getElementById('ns-loader'); if(!el)return;
  if(on){ el.style.display='flex'; let i=0; const t=document.getElementById('ns-ltxt');
    t.textContent=LOAD_MSGS[0]; clearInterval(loaderTimer);
    loaderTimer=setInterval(()=>{ i=(i+1)%LOAD_MSGS.length; t.textContent=LOAD_MSGS[i]; },1100);
  } else { el.style.display='none'; clearInterval(loaderTimer); loaderTimer=null; }
}

function changeTarget(){
  TARGET=document.getElementById('target').value;
  history.replaceState(null,'','netstat.php'+(TARGET==='local'?'':'?target='+encodeURIComponent(TARGET)));
  scheduleAuto(); load();
}
function scheduleAuto(){
  clearInterval(autoTimer);
  // local /proc read is cheap → 8s; remote SSH is heavier → 25s.
  autoTimer=setInterval(load, TARGET==='local'?8000:25000);
}

let _loading=false;
async function load(){
  if(_loading) return;                 // don't stack a 2nd SSH while one is still in flight
  _loading=true;
  const remote = TARGET!=='local';
  const eb=document.getElementById('err-box'); eb.style.display='none';
  if(remote) showLoader(true);
  let r=null, timedOut=false;
  const ac=new AbortController(); const to=setTimeout(()=>{ timedOut=true; ac.abort(); }, remote?60000:15000);
  try{ r=await fetch('netstat.php?api=data&target='+encodeURIComponent(TARGET)+'&_='+Date.now(),{signal:ac.signal}).then(r=>r.json()); }catch(e){}
  clearTimeout(to); showLoader(false); _loading=false;
  if(!r){ eb.style.display='block'; eb.innerHTML='<i class="fas fa-triangle-exclamation" style="color:var(--crit)"></i> '+(timedOut?'Timed out — the host took too long to respond (it may be heavily loaded or unreachable over SSH).':'Request failed.'); return; }
  if(!r.ok){
    eb.style.display='block';
    eb.innerHTML='<i class="fas fa-triangle-exclamation" style="color:var(--crit)"></i> '+esc(r.error||'Error')
      + (r.down?' <span class="muted">— host may be powered off or unreachable.</span>':'');
    ['k-total','k-est','k-listen','k-peers','k-tw'].forEach(id=>document.getElementById(id).textContent='—');
    document.getElementById('edges').innerHTML='<tr><td colspan="5" class="muted">No data.</td></tr>';
    document.getElementById('listen').innerHTML='<span class="muted">—</span>';
    if(net){ net.destroy(); net=null; }
    return;
  }
  centerLabel=r.host||'host';
  document.getElementById('center-lbl').textContent=centerLabel;
  document.getElementById('k-total').textContent=r.total;
  document.getElementById('k-est').textContent=r.by_state.ESTABLISHED||0;
  document.getElementById('k-listen').textContent=r.listen.length;
  document.getElementById('k-peers').textContent=r.edges.length;
  document.getElementById('k-tw').textContent=r.by_state.TIME_WAIT||0;
  document.getElementById('edges').innerHTML = r.edges.length? r.edges.map(e=>`<tr>
    <td class="mono">${esc(e.raddr)}</td><td>${e.rport}</td><td><span class="pill">${esc(e.proto)}</span></td>
    <td>${stTag(e.states)}</td><td><b>${e.count}</b></td></tr>`).join('') : '<tr><td colspan="5" class="muted">No active remote connections.</td></tr>';
  document.getElementById('listen').innerHTML = r.listen.length? r.listen.map(l=>`<span class="pill" style="margin:2px 4px 2px 0;">${esc(l.proto)}/${l.port}</span>`).join('') : '<span class="muted">none</span>';
  drawGraph(r.edges);
}
function drawGraph(edges){
  const nodes=[{id:'__host',label:centerLabel,shape:'box',color:{background:'#1f6feb',border:'#4da3ff'},font:{color:'#fff',size:16},margin:10}];
  const links=[];
  edges.slice(0,40).forEach((e,i)=>{ const id='r'+i;
    nodes.push({id,label:e.raddr+'\n:'+e.rport,shape:'dot',size:8+Math.min(20,e.count*2),
      color:{background:'#2ecc71',border:'#7fe0a3'},font:{color:'#cdd',size:11}});
    links.push({from:'__host',to:id,width:1+Math.min(6,e.count),color:{color:'rgba(77,163,255,.4)'}});
  });
  const data={nodes:new vis.DataSet(nodes),edges:new vis.DataSet(links)};
  const opts={physics:{stabilization:true,barnesHut:{springLength:120}},interaction:{hover:true},nodes:{borderWidth:1}};
  if(net) net.destroy();
  net=new vis.Network(document.getElementById('graph'),data,opts);
}
// Fullscreen the WRAPPER (#ns-wrap = map + side panel) — exactly like netflow.php's #ex-wrap.
// To keep the particles visible we REPARENT the #nm-netbg canvas into the wrapper while
// fullscreen (a child fullscreen hides the body-level canvas), then move it back on exit.
function toggleFs(){
  const w=document.getElementById('ns-wrap'); const rf=w.requestFullscreen||w.webkitRequestFullscreen;
  if(!document.fullscreenElement && !document.webkitFullscreenElement){ rf&&rf.call(w); }
  else { (document.exitFullscreen||document.webkitExitFullscreen||function(){}).call(document); }
}
function moveBg(into){
  const bg=document.getElementById('nm-netbg'); if(!bg) return;   // live particle canvas
  if(into){ const w=document.getElementById('ns-wrap'); bg.style.zIndex='0'; w.insertBefore(bg, w.firstChild); }
  else { bg.style.zIndex='-1'; document.body.insertBefore(bg, document.body.firstChild); }
  setTimeout(()=>window.dispatchEvent(new Event('resize')), 50);   // refit the canvas
}
function _fsSync(){
  const on=!!(document.fullscreenElement||document.webkitFullscreenElement);
  const b=document.getElementById('fs-btn');
  if(b) b.innerHTML = on ? '<i class="fas fa-compress"></i>' : '<i class="fas fa-expand"></i>';
  moveBg(on);
  setTimeout(()=>{ if(net){ net.redraw(); net.fit(); } },160);   // vis-network re-measures its container
}
document.addEventListener('fullscreenchange',_fsSync);
document.addEventListener('webkitfullscreenchange',_fsSync);

scheduleAuto(); load();
</script>
</body></html>
