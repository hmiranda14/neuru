<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Federated Device Command Center. Opens a REMOTE device (from a slave
// site) on the MASTER as if it were local: the device's NATIVE dashboard
// (router_details / win_screen / linux_screen / ping) is embedded read-only via a
// short-lived HMAC SSO token (no second login) — plus a toggle drawer of the
// master-accumulated metric history (CPU/RAM/disk graphs, built from the minutely
// rollups). RBAC: 'federation'. Data: federation.php?api=fed_device (nm_cluster.php).
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_cluster.php');
require_once('nm_fed_auth.php');
include('logger.php');

if (!checkAccess($conn, 'federation')) { header('Location: /denied_access.php?page=federation'); exit; }
nm_cluster_ensure($conn);

$role = (string)($_SESSION['role'] ?? 'guest');
$site = (string)($_GET['site'] ?? '');
$rid  = (int)($_GET['id'] ?? 0);

$data = nm_cluster_fed_device($conn, $role, $site, $rid, 24);
if (!$data) { header('Location: /federation.php'); exit; }
log_user_action($conn, 'view_page', 'fed_device.php#'.$site.':'.$rid);

$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
include('header.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script defer src="/chart.umd.min.js"></script>
<script defer src="/chartjs-adapter-date-fns.bundle.min.js"></script>
<style>
  html{ background:#05080f; }
  body{ margin:0; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; background:transparent !important; color:#e6edf7; }
  .fdwrap{ max-width:1600px; margin:0 auto; padding:10px 16px 22px; }
  .fdbar{ display:flex; align-items:center; gap:13px; padding:11px 16px; margin-bottom:12px; flex-wrap:wrap;
    background:rgba(16,22,34,.62); backdrop-filter:blur(13px); border:1px solid rgba(255,255,255,.1); border-radius:14px; }
  .fdback{ display:inline-flex; align-items:center; gap:7px; color:#8aa2c4; text-decoration:none; font-size:13px; }
  .fdback:hover{ color:#4da3ff; }
  .fdic{ width:42px; height:42px; border-radius:11px; display:grid; place-items:center; font-size:20px; background:rgba(77,163,255,.13); border:1px solid rgba(77,163,255,.34); color:#7fb2ff; flex:0 0 auto; }
  .fdname{ font-size:18px; font-weight:800; color:#fff; }
  .fdmeta{ display:flex; align-items:center; gap:9px; flex-wrap:wrap; font-size:12px; color:#8aa2c4; margin-top:2px; }
  .fddot{ width:10px; height:10px; border-radius:50%; box-shadow:0 0 9px currentColor; }
  .fdtag{ font-size:10px; font-weight:800; text-transform:uppercase; padding:2px 8px; border-radius:20px; background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#9cc7ff; }
  .fdbadge{ font-size:10px; font-weight:800; text-transform:uppercase; padding:2px 8px; border-radius:20px; border:1px solid; }
  .fdsp{ flex:1; }
  .btn{ display:inline-flex; align-items:center; gap:8px; background:rgba(77,163,255,.15); border:1px solid rgba(77,163,255,.42); color:#cfe4ff; border-radius:10px; padding:8px 14px; font-size:12.5px; cursor:pointer; text-decoration:none; font-weight:600; }
  .btn:hover{ border-color:#4da3ff; color:#fff; } .btn.g{ background:linear-gradient(135deg,#36e3d0,#4da3ff); border:none; color:#04121a; }
  .frame-wrap{ position:relative; }
  #fd-frame{ width:100%; height:calc(100vh - 150px); min-height:480px; border:1px solid rgba(255,255,255,.1); border-radius:14px; background:#05080f; display:block; }
  .fdhint{ text-align:center; font-size:12px; color:#7f93af; margin-top:8px; }
  .fdhint a{ color:#4da3ff; text-decoration:none; }
  .fdnotice{ background:rgba(16,22,34,.62); border:1px solid rgba(240,169,44,.4); border-radius:14px; padding:26px; text-align:center; color:#e9c98a; font-size:13.5px; }
  .fdnotice b{ color:#fff; }
  /* metrics drawer */
  #fd-metrics{ display:none; margin-bottom:12px; }
  .fdgrid{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-bottom:12px; }
  @media(max-width:760px){ .fdgrid{ grid-template-columns:1fr; } #fd-frame{ height:calc(100vh - 120px); } }
  .glass{ background:rgba(16,22,34,.62); backdrop-filter:blur(13px); border:1px solid rgba(255,255,255,.1); border-radius:14px; }
  .gauge{ padding:15px 18px; text-align:center; }
  .gauge .gl{ font-size:10.5px; font-weight:800; letter-spacing:1px; text-transform:uppercase; color:#7f93af; }
  .gauge .gv{ font-size:32px; font-weight:800; margin:5px 0 9px; font-variant-numeric:tabular-nums; }
  .gtrack{ height:8px; background:rgba(255,255,255,.09); border-radius:8px; overflow:hidden; }
  .gtrack i{ display:block; height:100%; border-radius:8px; transition:width .5s; }
  .fdcharts{ padding:16px 18px; }
  .fdch-head{ display:flex; align-items:center; gap:12px; margin-bottom:10px; flex-wrap:wrap; }
  .fdch-head b{ color:#fff; font-size:14px; }
  .rng{ display:flex; gap:6px; margin-left:auto; }
  .rng button{ background:rgba(255,255,255,.06); border:1px solid rgba(255,255,255,.14); color:#aab8cc; border-radius:7px; padding:5px 11px; font-size:12px; cursor:pointer; }
  .rng button.on{ background:rgba(77,163,255,.2); border-color:#4da3ff; color:#fff; }
  .fdnote{ color:#7f93af; font-size:12.5px; padding:22px; text-align:center; }
</style>

<div class="fdwrap">
  <div class="fdbar">
    <a class="fdback" href="/federation.php"><i class="fa-solid fa-arrow-left"></i> Devices</a>
    <div class="fdic"><i id="fd-ic" class="fa-solid fa-microchip"></i></div>
    <div>
      <div class="fdname" id="fd-name">…</div>
      <div class="fdmeta">
        <span class="fddot" id="fd-dot" style="background:#41d18b"></span>
        <span id="fd-st" style="font-weight:700;color:#cfe0f5"></span>
        <span class="fdtag" id="fd-site">site</span>
        <span class="fdbadge" id="fd-sst">—</span>
        <span id="fd-ip" style="font-family:monospace"></span>
        <span id="fd-up"></span>
      </div>
    </div>
    <span class="fdsp"></span>
    <button class="btn" onclick="toggleMetrics()"><i class="fa-solid fa-chart-line"></i> <span id="fd-mtog">Metrics history</span></button>
    <a class="btn g" id="fd-open" target="_blank" rel="noopener" style="display:none"><i class="fa-solid fa-up-right-from-square"></i> Open in tab ↗</a>
  </div>

  <!-- master-accumulated metrics (toggle) -->
  <div id="fd-metrics">
    <div class="fdgrid">
      <div class="glass gauge"><div class="gl">CPU</div><div class="gv" id="g-cpu">—</div><div class="gtrack"><i id="gb-cpu" style="width:0;background:#41d18b"></i></div></div>
      <div class="glass gauge"><div class="gl">RAM</div><div class="gv" id="g-ram">—</div><div class="gtrack"><i id="gb-ram" style="width:0;background:#41d18b"></i></div></div>
      <div class="glass gauge"><div class="gl">Disk</div><div class="gv" id="g-disk">—</div><div class="gtrack"><i id="gb-disk" style="width:0;background:#41d18b"></i></div></div>
    </div>
    <div class="glass fdcharts">
      <div class="fdch-head"><b><i class="fa-solid fa-chart-line" style="color:#4da3ff"></i> Metrics history</b>
        <span style="color:#7f93af;font-size:12px">accrued on this master from each check-in</span>
        <div class="rng" id="fd-rng"><button data-h="6">6h</button><button data-h="24" class="on">24h</button><button data-h="168">7d</button></div>
      </div>
      <div style="position:relative;height:260px"><canvas id="fd-chart"></canvas></div>
      <div id="fd-empty" class="fdnote" style="display:none"></div>
    </div>
  </div>

  <!-- the NATIVE dashboard, embedded (read-only, no login) -->
  <div class="frame-wrap" id="fd-frame-wrap"></div>
</div>

<script>
const SITE=<?= json_encode($site) ?>, RID=<?= (int)$rid ?>;
const BOOT=<?= json_encode($data) ?>;
let HOURS=24, CHART=null, FRAMED=false;
const KIND_ICO={router:'fa-diagram-project',windows:'fa-brands fa-windows',linux:'fa-brands fa-linux',ping:'fa-wave-square',snmp:'fa-microchip'};
const E=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const isDown=st=>['down','lowerlayerdown','notpresent','testing'].includes((st||'').toLowerCase());
function upt(s){ if(s==null)return '—'; s=+s; if(s<3600)return Math.round(s/60)+'m'; if(s<86400)return (s/3600).toFixed(1)+'h'; return Math.round(s/86400)+'d'; }
function col(v){ return v>=90?'#ff5c6c':v>=75?'#f0a92c':'#41d18b'; }
function gauge(id,v){ const el=document.getElementById('g-'+id),bar=document.getElementById('gb-'+id);
  if(v==null){ el.textContent='—'; el.style.color='#5c6b82'; bar.style.width='0'; return; }
  el.textContent=v+'%'; el.style.color=col(v); bar.style.width=Math.max(2,Math.min(100,v))+'%'; bar.style.background=col(v); }
function toggleMetrics(){ const m=document.getElementById('fd-metrics'); const on=m.style.display==='none'||!m.style.display;
  m.style.display=on?'block':'none'; document.getElementById('fd-mtog').textContent=on?'Hide metrics':'Metrics history'; if(on) drawChart((window._HIST||[])); }

function paint(d){
  const dev=d.device, s=d.site;
  document.getElementById('fd-ic').className='fa-solid '+(KIND_ICO[dev.kind]||'fa-microchip');
  document.getElementById('fd-name').textContent=dev.name||('#'+dev.id);
  document.getElementById('fd-ip').textContent=dev.ip||'';
  document.getElementById('fd-up').textContent=dev.up!=null?('· up '+upt(dev.up)):'';
  document.getElementById('fd-site').textContent=s.name+(s.is_self?' · this master':'');
  const dn=isDown(dev.st), dg=(dev.st||'').toLowerCase()==='degraded';
  const dot=dn?'#ff5c6c':dg?'#f0a92c':'#41d18b';
  document.getElementById('fd-dot').style.background=dot;
  document.getElementById('fd-st').textContent=(dev.st||'up').toUpperCase(); document.getElementById('fd-st').style.color=dot;
  const sc=s.status==='online'?'#41d18b':s.status==='stale'?'#f0a92c':'#ff5c6c';
  const sst=document.getElementById('fd-sst'); sst.textContent=s.status; sst.style.borderColor=sc; sst.style.color=sc;
  gauge('cpu',dev.cpu); gauge('ram',dev.ram); gauge('disk',dev.disk);
  // open-in-tab (native page, normal login)
  const op=document.getElementById('fd-open');
  if(d.deeplink){ op.href=d.deeplink; op.style.display=''; op.querySelector('span')||(op.innerHTML='<i class="fa-solid fa-up-right-from-square"></i> '+E(d.olabel||'Open')+' ↗'); }
  else op.style.display='none';
  window._HIST=d.history||[];
  // embed the native dashboard
  if(!FRAMED){ mountFrame(d); FRAMED=true; }
}

function mountFrame(d){
  const w=document.getElementById('fd-frame-wrap');
  if(d.embed_url){
    w.innerHTML='<iframe id="fd-frame" src="'+E(d.embed_url)+'" allow="fullscreen"></iframe>'
      +'<div class="fdhint">Native dashboard embedded read-only. Not loading? '
      +(d.deeplink?'<a href="'+E(d.deeplink)+'" target="_blank" rel="noopener">Open it in a tab ↗</a>':'set this site’s Portal URL in Federation → Sites')
      +' · your browser must be able to reach the site’s URL.</div>';
  } else {
    w.innerHTML='<div class="fdnotice"><b>No embed URL for '+E(d.site.name)+'.</b><br>'
      +'To open this remote device’s native dashboard, set the site’s <b>Portal URL</b> in '
      +'<b>Federation → Sites</b> (the base URL of that slave portal, e.g. http://192.168.x.x:PORT). '
      +'Then reopen this device — its live router/Windows/Linux/ping view loads here, no second login.</div>';
  }
}

function drawChart(hist){
  const empty=document.getElementById('fd-empty'), cv=document.getElementById('fd-chart');
  if(!hist.length){ cv.style.display='none'; empty.style.display='';
    empty.innerHTML='<i class="fa-solid fa-hourglass-half"></i> History accrues on this master from each check-in — the graphs fill in over the next few minutes.';
    if(CHART){ CHART.destroy(); CHART=null; } return; }
  cv.style.display=''; empty.style.display='none';
  if(typeof Chart==='undefined'){ setTimeout(()=>drawChart(hist),200); return; }
  const pts=hist.map(h=>({t:h.t.replace(' ','T')+'Z',cpu:h.cpu,ram:h.ram,disk:h.disk}));
  const mk=(label,key,c)=>({label,data:pts.map(p=>({x:p.t,y:p[key]})),borderColor:c,backgroundColor:c+'22',borderWidth:2,pointRadius:0,tension:.32,spanGaps:true,fill:true});
  const ds=[mk('CPU %','cpu','#4da3ff'),mk('RAM %','ram','#36e3d0'),mk('Disk %','disk','#c084fc')];
  if(CHART){ CHART.data.datasets=ds; CHART.update('none'); return; }
  CHART=new Chart(document.getElementById('fd-chart').getContext('2d'),{ type:'line', data:{datasets:ds},
    options:{ responsive:true, maintainAspectRatio:false, interaction:{mode:'index',intersect:false},
      scales:{ x:{type:'time',time:{tooltipFormat:'MMM d HH:mm'},ticks:{color:'#7f93af',maxRotation:0,autoSkip:true,maxTicksLimit:8},grid:{color:'rgba(255,255,255,.05)'}},
               y:{min:0,max:100,ticks:{color:'#7f93af',callback:v=>v+'%'},grid:{color:'rgba(255,255,255,.05)'}} },
      plugins:{ legend:{labels:{color:'#cfe0f5',usePointStyle:true,boxWidth:8}}, tooltip:{callbacks:{label:c=>c.dataset.label+': '+(c.parsed.y==null?'—':c.parsed.y+'%')}} } } });
}

async function load(){ const d=await fetch('federation.php?api=fed_device&site='+encodeURIComponent(SITE)+'&id='+RID+'&hours='+HOURS+'&_='+Date.now())
    .then(r=>r.json()).catch(()=>null);
  if(d&&d.ok){ // refresh vitals + history only (don't remount the iframe)
    window._HIST=d.history||[]; const dev=d.device;
    gauge('cpu',dev.cpu); gauge('ram',dev.ram); gauge('disk',dev.disk);
    if(document.getElementById('fd-metrics').style.display==='block') drawChart(window._HIST);
  } }

document.getElementById('fd-rng').addEventListener('click',e=>{ const b=e.target.closest('button'); if(!b)return;
  HOURS=+b.dataset.h; document.querySelectorAll('#fd-rng button').forEach(x=>x.classList.toggle('on',x===b)); load(); });

paint(BOOT);
setInterval(load, 20000);
</script>
