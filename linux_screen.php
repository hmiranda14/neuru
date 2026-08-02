<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Linux Command Center (immersive, FLOATING-WIDGET dashboard). One box,
// ALL of it (live diag + health + events + LAN traffic) as draggable / resizable /
// collapsible glass widgets over the sitewide particle bg, with a per-user saved
// layout and a dynamic detail dock when you click an item. Pulls linux.php JSON
// APIs (?api=diag|health|events|ifaces); layout persists via ?action=layout_save.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_linuxhost.php');
include('logger.php');

if (!checkAccess($conn, 'linux')) { header('Location: /denied_access.php?page=linux'); exit; }
nm_lx_ensure($conn);

$hid  = (int)($_GET['host'] ?? 0);
$host = $hid ? nm_lx_host($conn, $hid) : null;
if (!$host) { header('Location: /linux.php'); exit; }
log_user_action($conn, 'view_page', 'win_screen.php#'.$hid);

$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
include('header.php');
?>
<!-- Font Awesome — header.php does NOT load it; without this the NetOps Copilot (injected
     by header.php) AND our own icons break on this page. Matches net_mon.php's link. -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(10,14,22,.62); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cyan:#36e3d0; --purple:#c084fc; --win:#3aa0ff; }
/* PARTICLES: the dark colour MUST go on <html> (root, painted at the very back) and
   <body> stays TRANSPARENT — an opaque body bg paints OVER the NMNetBG canvas
   (position:fixed; z-index:-1) and hides it. Font (net_mon's) still lives on body. */
html{ background:#05080f; }
body{ margin:0; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; background:transparent !important; color:#fff; overflow-x:hidden; }
.ws *{ box-sizing:border-box; }
.ws{ position:relative; color:#d4dce8; }
.mono,.ws-mmsg{ font-family:'Consolas',monospace; }

/* top bar */
.ws-bar{ display:flex; align-items:center; gap:12px; flex-wrap:wrap; margin:10px 14px;
  background:linear-gradient(90deg,rgba(58,160,255,.10),rgba(54,227,208,.04)); border:1px solid rgba(58,160,255,.22);
  border-radius:14px; padding:11px 16px; box-shadow:inset 0 0 40px rgba(58,160,255,.05); position:relative; z-index:5; }
.ws-bar .ic{ font-size:24px; color:var(--win); filter:drop-shadow(0 0 8px rgba(58,160,255,.6)); }
.ws-bar h1{ margin:0; font-size:21px; font-weight:800; letter-spacing:.4px; color:#fff; }
.ws-bar .os{ font-size:11px; color:#8fa0b4; }
.ws-dot{ width:10px; height:10px; border-radius:50%; background:var(--ok); animation:pulse 2s infinite; }
.ws-dot.bad{ background:var(--crit); }
@keyframes pulse{ 0%{box-shadow:0 0 0 0 rgba(46,204,113,.5)} 70%{box-shadow:0 0 0 9px rgba(46,204,113,0)} 100%{box-shadow:0 0 0 0 rgba(46,204,113,0)} }
.ws-sp{ margin-left:auto; }
.ws-btn{ display:inline-flex; align-items:center; gap:7px; cursor:pointer; font-size:12.5px; font-weight:600; color:#cfe0f5;
  background:var(--glass); border:1px solid var(--border); padding:7px 12px; border-radius:9px; text-decoration:none; transition:all .15s; }
.ws-btn:hover{ border-color:var(--accent); color:#fff; box-shadow:0 0 14px rgba(77,163,255,.35); }
.ws-btn.pbtn{ padding:3px 9px; font-size:11px; font-weight:500; }
.ws-when{ font-size:11px; color:#7d8aa0; }

/* floating-widget canvas */
#ws-canvas{ position:relative; margin:0 6px; min-height:calc(100vh - 96px); }
.wgt{ position:absolute; width:320px; background:var(--glass); backdrop-filter:blur(13px); border:1px solid var(--border); border-radius:13px;
  box-shadow:0 10px 30px rgba(0,0,0,.45); display:flex; flex-direction:column; overflow:hidden; transition:box-shadow .18s, opacity .3s, transform .3s; opacity:0; transform:translateY(10px); }
.wgt.in{ opacity:1; transform:none; }
.wgt:hover{ box-shadow:0 0 0 1px rgba(77,163,255,.28), 0 14px 38px rgba(0,0,0,.55); }
.wgt.drag{ z-index:60!important; box-shadow:0 0 0 2px var(--accent), 0 20px 54px rgba(0,0,0,.7); }
.wgt::before{ content:''; position:absolute; top:0; left:0; right:0; height:2px; background:linear-gradient(90deg,transparent,var(--accent),var(--cyan),transparent); background-size:200% 100%; animation:sweep 4s linear infinite; opacity:.8; }
@keyframes sweep{ to{ background-position:200% 0 } }
.wgt-h{ display:flex; align-items:center; gap:8px; padding:8px 11px; cursor:grab; border-bottom:1px solid var(--border); user-select:none; background:linear-gradient(90deg,rgba(58,160,255,.07),transparent); }
.wgt-h .t{ font-size:11px; text-transform:uppercase; letter-spacing:1px; color:#aab8c9; display:flex; align-items:center; gap:7px; font-weight:700; }
.wgt-h .t i{ color:var(--win); }
.wgt-h .cnt{ font-size:10px; color:#6f7d92; font-weight:400; letter-spacing:0; text-transform:none; }
.wgt-h .btns{ margin-left:auto; display:flex; gap:3px; }
.wgt-h .wb{ cursor:pointer; color:#7d8aa0; width:20px; height:18px; line-height:18px; text-align:center; font-size:11px; border-radius:5px; }
.wgt-h .wb:hover{ color:#fff; background:rgba(255,255,255,.08); }
.wgt-b{ padding:11px 13px; overflow:auto; flex:1; }
.wgt.collapsed{ height:auto!important; } .wgt.collapsed .wgt-b, .wgt.collapsed .wgt-rs{ display:none; }
.wgt-rs{ position:absolute; right:1px; bottom:1px; width:16px; height:16px; cursor:nwse-resize; }
.wgt-rs::after{ content:''; position:absolute; right:3px; bottom:3px; width:7px; height:7px; border-right:2px solid #5a6678; border-bottom:2px solid #5a6678; }
.wgt-rs:hover::after{ border-color:var(--accent); }

/* shared content bits */
.kv{ display:flex; justify-content:space-between; gap:10px; font-size:12.5px; padding:3px 0; } .kv b{ color:#eaf0f7; font-weight:600; }
.brow{ margin-bottom:8px; } .blab{ display:flex; justify-content:space-between; font-size:12px; margin-bottom:3px; } .blab b{ color:#eaf0f7; }
.bar{ height:7px; border-radius:5px; background:rgba(255,255,255,.07); overflow:hidden; } .bar>i{ display:block; height:100%; border-radius:5px; transition:width 1s cubic-bezier(.22,1,.36,1); }
.sel{ cursor:pointer; border-radius:6px; padding:1px 3px; margin:0 -3px; } .sel:hover{ background:rgba(77,163,255,.12); }
.chip{ display:inline-block; font-size:10.5px; border:1px solid var(--border); border-radius:11px; padding:2px 9px; margin:3px 4px 0 0; }
.chip.ok{ border-color:rgba(46,204,113,.4); color:#9fe0b0; } .chip.bad{ border-color:rgba(231,76,60,.45); color:#f0a59d; } .chip.warn{ border-color:rgba(243,156,18,.45); color:#f0c674; }
.svcb{ background:rgba(54,227,208,.12); border:1px solid rgba(54,227,208,.42); color:#8ee6da; border-radius:6px; padding:1px 8px; margin-left:7px; cursor:pointer; font-size:10px; font-weight:600; } .svcb:hover{ background:var(--cyan); color:#06121a; }
.ev{ display:flex; gap:9px; align-items:flex-start; padding:6px 0; border-bottom:1px solid rgba(255,255,255,.05); font-size:12px; cursor:pointer; }
.ev:hover{ background:rgba(255,255,255,.04); border-radius:6px; } .ev .lv{ width:7px;height:7px;border-radius:50%;margin-top:5px;flex:0 0 auto; }
.ev .lv1{ background:var(--crit) } .ev .lv2{ background:#e88 } .ev .lv3{ background:var(--warn) }
.ev .em{ color:#c3ccd8; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; } .ev .et{ color:#6f7d92; font-size:10.5px; }
.muted{ color:#7d8aa0; } .sgrp{ margin-bottom:10px; } .sgrp .sh{ font-size:10px; text-transform:uppercase; letter-spacing:1px; color:#6f7d92; margin:0 0 4px; }
/* mini gauges inside the Vitals widget */
.gwrap{ display:flex; gap:6px; flex-wrap:wrap; justify-content:space-around; }
.gauge{ position:relative; text-align:center; width:140px; }
.gauge svg{ width:104px; height:104px; }
.gauge .gv{ position:absolute; top:42%; left:0; right:0; transform:translateY(-50%); font-size:21px; font-weight:800; color:#eef4ff; }
.gauge .gl{ font-size:10px; text-transform:uppercase; letter-spacing:1.2px; color:#8fa0b4; margin-top:-6px; }
.gauge .gs{ font-size:10.5px; color:#9fb0c4; }
.ring-bg{ fill:none; stroke:rgba(255,255,255,.07); stroke-width:8; }
.ring-fg{ fill:none; stroke-width:8; stroke-linecap:round; transform:rotate(-90deg); transform-origin:50% 50%; transition:stroke-dashoffset 1s cubic-bezier(.22,1,.36,1); filter:drop-shadow(0 0 4px currentColor); }

/* detail dock */
/* dock slides in from the LEFT (the NetOps Copilot AI sidebar owns the right edge — keep
   them from colliding) */
#ws-dock{ position:fixed; top:0; left:0; height:100vh; width:350px; max-width:92vw; background:rgba(9,13,21,.975); backdrop-filter:blur(16px);
  border-right:1px solid rgba(77,163,255,.3); box-shadow:12px 0 44px rgba(0,0,0,.6); transform:translateX(-102%); transition:transform .3s cubic-bezier(.22,1,.36,1); z-index:75; display:flex; flex-direction:column; }
#ws-dock.open{ transform:none; }
.dock-h{ padding:14px 16px; border-bottom:1px solid var(--border); display:flex; align-items:center; gap:10px; font-weight:700; color:#fff; font-size:15px; }
.dock-h .x{ margin-left:auto; cursor:pointer; color:#8295ab; } .dock-h .x:hover{ color:#fff; }
.dock-b{ padding:15px 16px; overflow:auto; flex:1; font-size:13px; color:#cdd6e2; line-height:1.5; }
.dock-b .dk{ font-size:10.5px; text-transform:uppercase; letter-spacing:.5px; color:#7d8aa0; margin-top:12px; }
.dock-b .dv{ color:#eaf0f7; font-weight:600; } .dock-b pre{ background:#05080e; border:1px solid var(--border); border-radius:9px; padding:11px; font-size:12px; white-space:pre-wrap; word-break:break-word; max-height:42vh; overflow:auto; font-family:Consolas,monospace; }
.dock-kill{ background:rgba(231,76,60,.14); border:1px solid var(--crit); color:#f0a59d; border-radius:8px; padding:7px 13px; cursor:pointer; font-weight:700; font-size:12.5px; margin-top:14px; } .dock-kill:hover{ background:var(--crit); color:#fff; }

/* loader */
.ws-loader{ position:fixed; inset:0; z-index:50; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:18px; background:radial-gradient(circle at 50% 42%, rgba(8,14,26,.5), rgba(2,4,8,.72)); backdrop-filter:blur(3px); transition:opacity .55s; }
.ws-loader.hide{ opacity:0; pointer-events:none; }
.wl-rings{ position:relative; width:128px; height:128px; }
.wl-rings i{ position:absolute; border-radius:50%; border:2px solid transparent; }
.wl-rings i:nth-child(1){ inset:0; border-top-color:var(--accent); border-right-color:var(--accent); animation:spin 1.1s linear infinite; box-shadow:0 0 16px rgba(77,163,255,.35); }
.wl-rings i:nth-child(2){ inset:16px; border-bottom-color:var(--cyan); border-left-color:var(--cyan); animation:spin 1.7s linear infinite reverse; }
.wl-rings i:nth-child(3){ inset:32px; border-top-color:var(--purple); border-right-color:var(--purple); animation:spin .9s linear infinite; }
.wl-core{ position:absolute; inset:50px; border-radius:50%; background:radial-gradient(circle,var(--accent),transparent 72%); animation:pcore 1.4s ease-in-out infinite; }
@keyframes spin{ to{ transform:rotate(360deg) } } @keyframes pcore{ 0%,100%{ transform:scale(.65); opacity:.55 } 50%{ transform:scale(1.12); opacity:1 } }
.wl-txt{ font-size:15px; color:#dfeaf8; font-weight:700; text-shadow:0 0 12px rgba(77,163,255,.45); } .wl-sub{ font-size:11.5px; color:#8295ab; margin-top:-8px; }
.wl-prog{ width:230px; height:3px; border-radius:3px; background:rgba(255,255,255,.08); overflow:hidden; } .wl-prog>i{ display:block; height:100%; width:38%; border-radius:3px; background:linear-gradient(90deg,transparent,var(--accent),var(--cyan),transparent); animation:wlslide 1.3s linear infinite; }
@keyframes wlslide{ from{ transform:translateX(-130%) } to{ transform:translateX(330%) } }
/* Fullscreen the WHOLE document (not just #ws) so the particle canvas — which lives in
   <body>, outside #ws — is included and stays visible. Hide the site nav for an immersive
   wall; normal page scroll keeps every widget reachable. */
html:fullscreen, html:-webkit-full-screen{ overflow-y:auto; background:#05080f; }
html:fullscreen #nm-topbar, html:-webkit-full-screen #nm-topbar{ display:none; }
</style>

<div class="ws" id="ws">
  <div class="ws-bar">
    <i class="fab fa-linux ic"></i>
    <div><h1 id="ws-name"><?= htmlspecialchars($host['name']) ?></h1><div class="os" id="ws-os">loading…</div></div>
    <span class="ws-dot" id="ws-dot"></span>
    <div class="ws-sp"></div>
    <span class="ws-when" id="ws-when"></span>
    <label class="ws-btn pbtn"><input type="checkbox" id="ws-auto" style="margin:0 4px 0 0;"> auto</label>
    <button class="ws-btn" onclick="loadAll()"><i class="fas fa-rotate"></i> Refresh</button>
    <button class="ws-btn" onclick="resetLayout()" title="Reset widget positions"><i class="fas fa-rotate-left"></i> Reset</button>
    <button class="ws-btn" onclick="goFs()"><i class="fas fa-expand"></i> Fullscreen</button>
    <a class="ws-btn" href="linux.php"><i class="fas fa-arrow-left"></i> Back</a>
  </div>

  <?php
    // Down/degraded advisory — SSH-based widgets return nothing on an unreachable host, so
    // say so plainly instead of rendering a blank canvas the operator has to puzzle over.
    $wsNid = (int)($host['node_id'] ?? 0); $wsVerdict = null;
    if ($wsNid) {
        if (!function_exists('nm_node_live_verdict') && is_file(__DIR__.'/nm_config.php')) require_once __DIR__.'/nm_config.php';
        if (function_exists('nm_node_live_verdict')) { try { $wsVerdict = nm_node_live_verdict($conn, $wsNid); } catch (\Throwable $e) {} }
    }
    $wsState  = $wsVerdict['state'] ?? null;
    $wsHostSt = strtolower((string)($host['status'] ?? ''));
    $wsDown   = ($wsState === 'down') || in_array($wsHostSt, ['down','error'], true);
    $wsDeg    = !$wsDown && ($wsState === 'degraded');
    if ($wsDown || $wsDeg): $isDown = $wsDown; ?>
  <div style="margin:0 14px 12px;padding:13px 16px;border-radius:12px;display:flex;align-items:center;gap:14px;flex-wrap:wrap;
       background:<?= $isDown?'rgba(231,76,60,.14)':'rgba(243,156,18,.13)' ?>;border:1px solid <?= $isDown?'rgba(231,76,60,.5)':'rgba(243,156,18,.5)' ?>;">
    <i class="fas fa-<?= $isDown?'triangle-exclamation':'circle-exclamation' ?>" style="font-size:22px;color:<?= $isDown?'#ff7a6e':'#ffce6b' ?>"></i>
    <div style="flex:1;min-width:220px;">
      <div style="font-weight:700;font-size:15px;color:<?= $isDown?'#ff9d92':'#ffd98a' ?>"><?= $isDown?'This device appears DOWN':'This device is DEGRADED' ?></div>
      <div style="font-size:12.5px;color:#b6c0cf;margin-top:2px;"><?= $isDown
          ? 'It is not responding to monitoring — live diagnostics over SSH are unavailable, so the widgets below stay empty until it recovers.'
          : 'It is reachable but showing problems; some live widgets may be incomplete.' ?><?= !empty($host['last_error']) ? ' · '.htmlspecialchars($host['last_error']) : '' ?></div>
    </div>
    <a class="ws-btn" href="router_details.php?node=<?= $wsNid ?>"><i class="fas fa-circle-info"></i> Device details</a>
    <a class="ws-btn" href="incidents.php"><i class="fas fa-triangle-exclamation"></i> Incidents</a>
  </div>
  <?php endif; ?>

  <div id="ws-canvas"></div>

  <div id="ws-dock"><div class="dock-h"><span id="dk-title">Detail</span><i class="fas fa-xmark x" onclick="closeDock()"></i></div><div class="dock-b" id="dk-body"></div></div>

  <div class="ws-loader" id="ws-loader">
    <div class="wl-rings"><i></i><i></i><i></i><div class="wl-core"></div></div>
    <div class="wl-txt" id="wl-txt">Connecting to <?= htmlspecialchars($host['name']) ?>…</div>
    <div class="wl-sub" id="wl-sub">opening SSH session</div>
    <div class="wl-prog"><i></i></div>
  </div>
</div>

<script>
const HID = <?= $hid ?>;
const NODE_ID = <?= (int)($host['node_id'] ?? 0) ?>;
const POST = b => fetch('linux.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b}).then(r=>r.json()).catch(()=>null);
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function clr(p,a,b){ p=+p; return p>=b?'var(--crit)':p>=a?'var(--warn)':'var(--ok)'; }
function fmtGB(v){ v=+v||0; return v>=1?v.toFixed(v<10?1:0)+' GB':Math.round(v*1024)+' MB'; }
function fmtKBs(v){ v=+v||0; return v>=1024?(v/1024).toFixed(1)+' MB/s':Math.round(v)+' KB/s'; }
function bps(v){ v=+v||0; if(v>=1e9)return (v/1e9).toFixed(2)+' Gbps'; if(v>=1e6)return (v/1e6).toFixed(1)+' Mbps'; if(v>=1e3)return (v/1e3).toFixed(0)+' Kbps'; return Math.round(v)+' bps'; }
function relAge(s){ if(s==null)return ''; s=+s; if(s<60)return s+'s'; if(s<3600)return Math.floor(s/60)+'m'; if(s<86400)return Math.floor(s/3600)+'h'; return Math.floor(s/86400)+'d'; }
function nl(x){ return (window.nmLocal?nmLocal(x):(x||'')); }
function uptime(b){ if(!b)return '—'; const ms=Date.now()-new Date(b).getTime(); if(isNaN(ms))return '—'; const d=Math.floor(ms/864e5),h=Math.floor(ms%864e5/36e5),m=Math.floor(ms%36e5/6e4); return (d?d+'d ':'')+(h?h+'h ':'')+m+'m'; }
function sparkSvg(arr,color,h){ h=h||24; arr=(arr||[]).map(v=>+v||0); if(arr.length<2)return `<div style="height:${h}px"></div>`;
  const mx=Math.max.apply(null,arr.concat([1])),mn=Math.min.apply(null,arr.concat([0])),rng=(mx-mn)||1,step=100/(arr.length-1);
  const pts=arr.map((v,i)=>`${(i*step).toFixed(2)},${(h-((v-mn)/rng)*(h-3)-1.5).toFixed(2)}`).join(' ');
  return `<svg viewBox="0 0 100 ${h}" preserveAspectRatio="none" style="width:100%;height:${h}px;display:block"><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5" vector-effect="non-scaling-stroke" stroke-linejoin="round" style="filter:drop-shadow(0 0 3px ${color})"/></svg>`; }
let DATA={d:null,h:null,ev:null,ifd:null}, _hist={cpu:[],mem:[],temp:[],disk:[]}, _autoT=null, _lastDiag=null, _evList=[];
function pushHist(k,v){ (_hist[k]=_hist[k]||[]).push(+v||0); if(_hist[k].length>40)_hist[k].shift(); }

function goFs(){ const el=document.documentElement; if(!document.fullscreenElement){ (el.requestFullscreen||el.webkitRequestFullscreen).call(el); } else document.exitFullscreen(); }
document.getElementById('ws-auto').addEventListener('change',e=>{ if(e.target.checked){ _autoT=setInterval(loadAll,12000); } else { clearInterval(_autoT); _autoT=null; } });

// ── actions ──
function killProc(enc){ const name=decodeURIComponent(enc);
  if(!confirm('Force-kill ALL processes named "'+name+'" on this host? Audited.'))return;
  document.getElementById('ws-when').innerHTML='<i class="fas fa-spinner fa-spin"></i> killing '+esc(name)+'…';
  POST(new URLSearchParams({action:'kill_proc',host_id:HID,name})).then(r=>{ if(r&&r.ok){ closeDock(); setTimeout(loadAll,700);} else alert('Could not kill: '+(r?esc(r.error):'failed')); }); }
function svcAction(svc,act){ act=act||'restart'; if(!confirm(act.toUpperCase()+' service "'+svc+'" on this host? Audited.'))return;
  document.getElementById('ws-when').innerHTML='<i class="fas fa-spinner fa-spin"></i> '+act+' '+esc(svc)+'…';
  POST(new URLSearchParams({action:'svc_action',host_id:HID,svc,act})).then(r=>{ if(r&&r.ok){ setTimeout(loadAll,800);} else alert('Failed: '+(r?esc(r.error||r.err||'failed'):'failed')); }); }
function pollEvents(){ document.getElementById('ws-when').innerHTML='<i class="fas fa-spinner fa-spin"></i> polling Event Log…'; POST(new URLSearchParams({action:'poll',id:HID})).then(()=>loadAll()); }
function pollHealth(){ document.getElementById('ws-when').innerHTML='<i class="fas fa-spinner fa-spin"></i> polling health…'; POST(new URLSearchParams({action:'poll_health',id:HID})).then(()=>loadAll()); }

// ── detail dock ──
function openDock(title,icon,html){ document.getElementById('dk-title').innerHTML=`<i class="fas ${icon}" style="color:var(--win)"></i> ${esc(title)}`;
  document.getElementById('dk-body').innerHTML=html; document.getElementById('ws-dock').classList.add('open'); }
function closeDock(){ document.getElementById('ws-dock').classList.remove('open'); }
function dkProc(enc){ const p=JSON.parse(decodeURIComponent(enc));
  openDock(p.name||'Process','fa-microchip',
    `<div class="dk">Working set</div><div class="dv">${p.mb!=null?p.mb+' MB':'—'}</div>
     <div class="dk">Live CPU</div><div class="dv">${p.pct!=null?p.pct+' %':'—'}</div>
     <div class="dk">Instances</div><div class="dv">${p.inst||1}</div>
     <div class="dk">Process name</div><div class="dv mono">${esc(p.name||'')}</div>
     <button class="dock-kill" onclick='killProc(${JSON.stringify(encodeURIComponent(p.name||""))})'><i class="fas fa-xmark"></i> Force-kill all "${esc(p.name)}"</button>`); }
function dkSensor(enc){ const s=JSON.parse(decodeURIComponent(enc)); const U={Temperature:'°C',Fan:' rpm',Voltage:' V',Clock:' MHz',Load:'%',Control:'%',Power:' W',Level:'%',Throughput:' MB/s',Data:' GB',SmallData:' MB'}[s.type]||'';
  openDock(s.name||'Sensor','fa-gauge-high',`<div class="dk">Type</div><div class="dv">${esc(s.type)}</div><div class="dk">Value</div><div class="dv" style="font-size:22px">${s.val}${U}</div><div class="dk">Source</div><div class="dv">${esc((DATA.d&&DATA.d.sensor_src)||'')}</div>`); }
function dkIface(i){ const f=(DATA.ifd&&DATA.ifd.ifaces||[])[i]; if(!f)return;
  openDock(f.name||'Interface','fa-ethernet',
    `<div class="dk">IP</div><div class="dv mono">${esc(f.ip||'—')}</div>
     <div class="dk">State</div><div class="dv">${esc(f.oper||'?')}</div>
     <div class="dk">In (rx)</div><div class="dv" style="color:var(--cyan)">${bps(f.in_rate)}</div>${sparkSvg(f.in_series,'#36e3d0',34)}
     <div class="dk">Out (tx)</div><div class="dv" style="color:var(--accent)">${bps(f.out_rate)}</div>${sparkSvg(f.out_series,'#4da3ff',34)}
     <div class="dk">Link speed</div><div class="dv">${f.if_speed?bps(f.if_speed):'—'}</div>`); }
function showEvt(i){ const e=_evList[i]; if(!e)return; const lc={1:'var(--crit)',2:'#e88',3:'var(--warn)'}[e.level]||'var(--accent)';
  const rows=[['Host',e.host_name],['Log',e.log_name],['Level',{1:'Critical',2:'Error',3:'Warning'}[e.level]||('Lv'+e.level)],['Event ID',e.event_id],['Provider',e.provider],['Record',e.record_id],['When',nl(e.created_at)],['Age',relAge(e.age)+' ago']];
  openDock('Event '+e.event_id,'fa-file-lines',
    rows.filter(x=>x[1]!=null&&x[1]!=='').map(x=>`<div class="dk">${x[0]}</div><div class="dv">${esc(x[1])}</div>`).join('')
    +`<div class="dk">Message</div><pre>${esc(e.message||'(no message)')}</pre>`); }

// ── animated arc gauge (used inside Vitals widget) ──
function gauge(label,val,unit,sub,color,spark){ const r=44,C=2*Math.PI*r,pct=Math.max(0,Math.min(100,+val||0)),off=C*(1-pct/100);
  return `<div class="gauge"><svg viewBox="0 0 104 104"><circle class="ring-bg" cx="52" cy="52" r="${r}"></circle>
    <circle class="ring-fg" cx="52" cy="52" r="${r}" style="stroke:${color};stroke-dasharray:${C.toFixed(1)};stroke-dashoffset:${C.toFixed(1)}" data-off="${off.toFixed(1)}"></circle></svg>
    <div class="gv" data-to="${(+val||0)}" data-unit="${unit}">0${unit}</div><div class="gl">${label}</div><div class="gs">${sub||''}</div>
    ${spark&&spark.length>1?`<div style="padding:4px 8px 0">${sparkSvg(spark,color,18)}</div>`:''}</div>`; }
function animGauges(){ document.querySelectorAll('.ring-fg').forEach(c=>requestAnimationFrame(()=>c.style.strokeDashoffset=c.dataset.off));
  document.querySelectorAll('.gv').forEach(el=>{ const to=+el.dataset.to||0,u=el.dataset.unit||'',t0=performance.now();
    (function step(t){ const k=Math.min(1,(t-t0)/800),v=to*(1-Math.pow(1-k,3)); el.textContent=(to%1===0?Math.round(v):v.toFixed(1))+u; if(k<1)requestAnimationFrame(step); })(t0); }); }

function bar(lab,val,unit,frac,color,sub,onclick){
  return `<div class="brow ${onclick?'sel':''}" ${onclick||''}><div class="blab"><span>${esc(lab)}</span><b>${val}${unit}${sub?` <span class="muted" style="font-weight:400">${sub}</span>`:''}</b></div>
    <div class="bar"><i style="width:${Math.max(2,Math.min(100,frac*100)).toFixed(0)}%;background:${color}"></i></div></div>`; }

// ── widget body builders (read DATA) ──
function bVitals(){ const d=DATA.d; if(!d)return DATA.diagErr?`<div class="muted" style="line-height:1.55;font-size:12px"><i class="fas fa-triangle-exclamation" style="color:var(--warn)"></i> ${esc(DATA.diagErr)}</div>`:'<div class="muted">…</div>';
  const mp=+d.mem_pct||0,cpu=+d.cpu||0,worstDisk=(d.disks||[]).reduce((a,k)=>Math.max(a,+k.pct||0),0),topTemp=(d.temps||[]).reduce((a,t)=>Math.max(a,+t.c||0),0);
  pushHist('cpu',cpu);pushHist('mem',mp);pushHist('temp',topTemp);pushHist('disk',worstDisk);
  return `<div class="gwrap">${gauge('CPU',cpu,'%',(d.cores?d.cores+' cores':''),clr(cpu,65,85),_hist.cpu)}
    ${gauge('Memory',mp,'%',fmtGB((+d.mem_used||0)/1024)+' / '+fmtGB((+d.mem_total||0)/1024),clr(mp,80,90),_hist.mem)}
    ${gauge('Hottest',topTemp,'°',(d.sensor_src?'via '+esc(d.sensor_src):''),clr(topTemp,70,85),_hist.temp)}
    ${gauge('Disk',worstDisk,'%',(d.disks||[]).length+' vol',clr(worstDisk,85,92),_hist.disk)}</div>`; }
function memSeg(lbl,mb,tot,col){ return `<div class="brow" style="margin-bottom:6px"><div class="blab" style="font-size:11.5px"><span>${lbl}</span><b>${fmtGB((+mb||0)/1024)}</b></div><div class="bar"><i style="width:${Math.max(0,Math.min(100,(+mb||0)/(tot||1)*100)).toFixed(0)}%;background:${col}"></i></div></div>`; }
function bMem(){ const d=DATA.d; if(!d)return '<div class="muted">…</div>'; const mm=d.top_mem||[],mx=mm.reduce((a,x)=>Math.max(a,+x.mb||0),1);
  if(!mm.length && d.via==='alloy'){ const tot=+d.mem_total||1;
    return `<div class="kv" style="margin-bottom:8px"><span>In use</span><b style="color:${clr(+d.mem_pct||0,80,90)}">${d.mem_pct}% · ${fmtGB((+d.mem_used||0)/1024)} / ${fmtGB(tot/1024)}</b></div>`
      +memSeg('Used',d.mem_used,tot,clr(+d.mem_pct||0,80,90))+memSeg('Cached',d.mem_cached,tot,'#36e3d0')+memSeg('Buffers',d.mem_buffers,tot,'#c084fc')
      +((+d.swap_total)?memSeg('Swap ('+fmtGB((+d.swap_total)/1024)+')',d.swap_used,d.swap_total,'#f39c12'):'')
      +`<div class="muted" style="margin-top:6px;font-size:10.5px">Per-process breakdown + kill need <b>SSH</b>.</div>`; }
  return mm.length?mm.map(x=>bar(x.name,x.mb,' MB',(+x.mb||0)/mx,clr(+d.mem_pct||0,80,90),(x.inst>1?'×'+x.inst:''),`onclick='dkProc(${JSON.stringify(encodeURIComponent(JSON.stringify(x)))})'`)).join(''):'<div class="muted">—</div>'; }
function bCpu(){ const d=DATA.d; if(!d)return '<div class="muted">…</div>';
  if(!(d.top_cpu||[]).length && d.via==='alloy'){ const cc=d.cpu_cores||[];
    return `<div class="kv"><span>CPU load</span><b style="color:${clr(+d.cpu||0,65,85)}">${d.cpu}% · ${d.cores||'?'} cores</b></div>`
      +`<div class="kv" style="margin-bottom:8px"><span>Load avg (1/5/15m)</span><b>${esc(d.load||'—')}</b></div>`
      +(cc.length?cc.map(c=>`<div class="brow" style="margin-bottom:4px"><div class="blab" style="font-size:10.5px"><span>Core ${c.core}</span><b>${c.pct}%</b></div><div class="bar" style="height:5px"><i style="width:${Math.min(100,+c.pct||0)}%;background:${clr(+c.pct||0,60,85)}"></i></div></div>`).join(''):'')
      +`<div class="muted" style="margin-top:7px;font-size:10.5px">Per-process top + kill need <b>SSH</b>.</div>`; }
  const cc=d.top_cpu||[],mx=cc.reduce((a,x)=>Math.max(a,+x.pct||0),1);
  return cc.length?cc.map(x=>bar(x.name,x.pct,'%',(+x.pct||0)/mx,clr(+x.pct,15,40),x.mb?x.mb+' MB':'',`onclick='dkProc(${JSON.stringify(encodeURIComponent(JSON.stringify(x)))})'`)).join(''):'<div class="muted">Idle.</div>'; }
function bNet(){ const d=DATA.d; if(!d)return '<div class="muted">…</div>'; const nc=d.net_conn||[],nif=d.net_ifaces||[],nmx=nif.reduce((a,i)=>Math.max(a,(+i.rx||0)+(+i.tx||0)),1);
  return `<div class="kv"><span>Throughput</span><b><span style="color:var(--cyan)">↓ ${fmtKBs(d.net_rx)}</span> &nbsp; <span style="color:var(--accent)">↑ ${fmtKBs(d.net_tx)}</span></b></div>`+
    (nif.length?`<div class="sgrp" style="margin-top:9px"><div class="sh">Per interface</div>`+nif.map(i=>`<div class="brow" style="margin-bottom:5px"><div class="blab" style="font-size:11.5px"><span>${esc(i.name)}</span><b><span style="color:var(--cyan)">↓${i.rx>=1024?(i.rx/1024).toFixed(1)+'M':i.rx+'K'}</span> <span style="color:var(--accent)">↑${i.tx>=1024?(i.tx/1024).toFixed(1)+'M':i.tx+'K'}</span></b></div><div class="bar" style="height:5px"><i style="width:${Math.min(100,((+i.rx||0)+(+i.tx||0))/nmx*100).toFixed(0)}%;background:#7fc1ff"></i></div></div>`).join('')+`</div>`
     :(nc.length?`<div class="sgrp" style="margin-top:8px"><div class="sh">Top talkers</div>`+nc.map(x=>`<div class="kv"><span>${esc(x.name||'?')}</span><b class="mono">${x.conns}</b></div>`).join('')+`</div>`:'')); }
function bDisks(){ const d=DATA.d; if(!d)return '<div class="muted">…</div>'; const dk=d.disks||[];
  return dk.length?dk.map(k=>{const u=(+k.size||0)-(+k.free||0);return `<div class="brow"><div class="blab"><span><b>${esc(k.id)}</b> ${fmtGB(k.free)} free</span><span class="muted">${fmtGB(u)} / ${fmtGB(k.size)} · ${k.pct}%</span></div><div class="bar"><i style="width:${+k.pct||0}%;background:${clr(k.pct,85,92)}"></i></div></div>`;}).join(''):'<div class="muted">—</div>'; }
function bFans(){ const d=DATA.d; if(!d)return '<div class="muted">…</div>'; const fans=d.fans||[],temps=d.temps||[],mx=fans.reduce((a,x)=>Math.max(a,+x.rpm||0),1);
  if(!fans.length&&!temps.length) return `<div class="muted" style="font-size:11.5px;line-height:1.5">No fan/thermal sensors${(d.sensor_types&&d.sensor_types.length)?` — exposing: ${d.sensor_types.map(t=>esc(t.type)+'×'+t.n).join(', ')}`:''}. Run LibreHardwareMonitor as admin.</div>`;
  return (fans.length?fans.map(x=>bar(x.name,x.rpm,' rpm',(+x.rpm||0)/mx,'#7fc1ff','')).join(''):'')
    +(temps.length?temps.map(x=>`<div class="kv"><span>${esc(x.name)}</span><b style="color:${clr(x.c,70,85)}">${x.c}°C</b></div>`).join(''):''); }
function bSensors(){ const d=DATA.d; if(!d)return '<div class="muted">…</div>'; const U={Voltage:' V',Clock:' MHz',Load:'%',Control:'%',Power:' W',Level:'%',Data:' GB',SmallData:' MB',Throughput:' MB/s',Current:' A',Energy:' mWh'};const TO=['Load','Clock','Power','Voltage','Control','Throughput','Data','Level'];
  const by={}; (d.sensors||[]).forEach(s=>{ if(s.type==='Fan'||s.type==='Temperature')return; (by[s.type]=by[s.type]||[]).push(s); });
  const ks=Object.keys(by).sort((a,b)=>{const ia=TO.indexOf(a),ib=TO.indexOf(b);return (ia<0?99:ia)-(ib<0?99:ib);});
  if(!ks.length){ const tn=(d.sensors||[]).filter(s=>s.type==='Temperature'||s.type==='Fan').length; return tn?`<div class="muted" style="font-size:11.5px;line-height:1.5">${tn} temp/fan sensor(s) — shown in the <b>Fans &amp; temps</b> widget. Extra sensors (load/clock/power/voltage) need <b>lm-sensors over SSH</b>.</div>`:'<div class="muted">No extra sensors.</div>'; }
  return ks.map(t=>{const u=U[t]!=null?U[t]:'',pct=(t==='Load'||t==='Control'||t==='Level');
    return `<div class="sgrp"><div class="sh">${esc(t)}</div>`+by[t].map(s=>`<div class="kv sel" onclick='dkSensor(${JSON.stringify(encodeURIComponent(JSON.stringify(s)))})'><span>${esc(s.name)}</span><b${pct?` style="color:${clr(s.val,70,90)}"`:''}>${s.val}${u}</b></div>`).join('')+`</div>`; }).join(''); }
function bLan(){ const ifd=DATA.ifd; if(!ifd||!ifd.ok)return '<div class="muted">…</div>'; const ifs=ifd.ifaces||[];
  if(!ifs.length)return '<div class="muted">Node has no monitored interfaces.</div>';
  return ifs.map((f,i)=>{ const up=(''+(f.oper||'')).toLowerCase()==='up'||(''+(f.oper||''))==='1';
    return `<div class="brow sel" onclick="dkIface(${i})"><div class="blab"><span>${esc(f.name)} <span class="chip ${up?'ok':'bad'}" style="padding:0 6px">${up?'up':esc(f.oper||'?')}</span></span>
      <b><span style="color:var(--cyan)">↓${bps(f.in_rate)}</span> <span style="color:var(--accent)">↑${bps(f.out_rate)}</span></b></div>
      <div style="display:flex;gap:6px"><div style="flex:1">${sparkSvg(f.in_series,'#36e3d0',20)}</div><div style="flex:1">${sparkSvg(f.out_series,'#4da3ff',20)}</div></div></div>`; }).join(''); }
function bHealth(){ const h=DATA.h; if(!h||!h.has||!h.data)return '<div class="muted">No health snapshot yet. <span class="ws-btn pbtn" onclick="pollHealth()">re-poll</span></div>';
  const d=h.data,def=d.defender,fw=(d.firewall||[]).map(f=>`<span class="chip ${f.on?'ok':'bad'}">${esc(f.name)} ${f.on?'on':'OFF'}</span>`).join(''),pd=(d.pdisks||[]).map(p=>`<span class="chip ${p.health=='Healthy'?'ok':'bad'}">${esc(p.name)} · ${esc(p.health||'?')}</span>`).join(''),stopped=d.svc_stopped_auto||[];
  return `<div style="text-align:right;margin-bottom:6px"><span class="ws-btn pbtn" onclick="pollHealth()"><i class="fas fa-satellite-dish"></i> re-poll</span></div>
    <div class="kv"><span>OS</span><b style="text-align:right">${esc(d.os||'?')}</b></div>
    <div class="kv"><span>Uptime</span><b>${uptime(d.boot)}</b></div>
    <div class="kv"><span>Services</span><b>${d.svc_running||0}/${d.svc_total||0} running</b></div>
    <div class="kv"><span>Last patch</span><b>${esc(d.last_hotfix||'?')}</b></div>
    <div class="sgrp" style="margin-top:9px"><div class="sh">Security</div>${def?`<div class="kv"><span>Antivirus</span><span class="chip ${def.av?'ok':'bad'}">${def.av?'on':'OFF'}</span></div><div class="kv"><span>Real-time</span><span class="chip ${def.rt?'ok':'bad'}">${def.rt?'on':'OFF'}</span></div>`:''}<div class="kv" style="margin-top:4px"><span>Firewall</span><span>${fw||'—'}</span></div></div>
    ${pd?`<div class="sgrp"><div class="sh">Physical disks / SMART</div>${pd}</div>`:''}
    ${stopped.length?`<div class="sgrp"><div class="sh">${stopped.length} auto service(s) stopped — click start</div>${stopped.map(s=>`<span class="chip warn">${esc(s.disp||s.name)}<button class="svcb" onclick="svcAction('${esc(s.name)}','restart')">start</button></span>`).join('')}</div>`:'<div class="chip ok" style="margin-top:6px">All auto services running</div>'}`; }
function bEvents(){ const ev=DATA.ev; if(!ev||!ev.ok)return '<div class="muted">…</div>'; _evList=ev.events||[]; const list=_evList.slice(0,30),s=ev.summary||{};
  return `<div style="text-align:right;margin-bottom:6px"><span class="ws-btn pbtn" onclick="pollEvents()"><i class="fas fa-satellite-dish"></i> poll now</span></div>`+
    (list.length?list.map((e,i)=>`<div class="ev" onclick="showEvt(${i})"><span class="lv lv${e.level}"></span><div style="min-width:0;flex:1"><div class="em">${esc((e.message||'').slice(0,110))}</div><div class="et">${esc(e.provider||'')} · ${esc(nl(e.created_at))} · ${relAge(e.age)} ago</div></div></div>`).join(''):'<div class="muted">No recent events.</div>'); }

// ── GPU widget (shows only when this host's node has a matching GPU in the GPU Monitor) ──
function bGpu(){ const g=DATA.gpu; if(!g||!g.has_gpu)return '<div class="muted">No GPU matched for this node.</div>';
  const cur=function(a){ a=a||[]; for(var i=a.length-1;i>=0;i--)if(a[i]!=null)return a[i]; return null; };
  function row(lbl,arr,unit,color){ const v=cur(arr),series=(arr||[]).filter(function(x){return x!=null;});
    return `<div class="brow"><div class="blab"><span><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${color};margin-right:6px"></span>${lbl}</span><b>${v==null?'—':v+unit}</b></div>${sparkSvg(series,color,22)}</div>`; }
  const nm=(g.gpus&&g.gpus[0]&&g.gpus[0].name)?g.gpus[0].name:(g.name||'GPU');
  const models=(g.models||[]).slice(0,5).map(function(m){return `<span class="chip" style="border-color:rgba(155,89,182,.4);color:#c8a8e8">${esc(m.name)}</span>`;}).join('');
  const link=NODE_ID?`<a href="gpu.php" title="Open GPU / AI Monitor" style="float:right;color:var(--accent)"><i class="fas fa-arrow-up-right-from-square"></i></a>`:'';
  return `<div style="font-size:12px;font-weight:600;color:#cfe0f5;margin-bottom:9px">${esc(nm)}${link}</div>`
    +row('GPU',g.util,'%','#2ecc71')+row('VRAM',g.vram,'%','#4da3ff')+row('Temp',g.temp,'°C','#f39c12')+row('Power',g.power,'W','#c084fc')
    +(models?`<div class="sgrp" style="margin-top:9px"><div class="sh">Models loaded</div>${models}</div>`:''); }

// ── widget registry + counts ──
const WIDGETS={
  vitals:{t:'Vitals',i:'fa-heart-pulse',w:600,h:210,render:bVitals,after:animGauges},
  gpu:{t:'GPU',i:'fa-microchip',w:320,h:300,render:bGpu,cnt:()=>{const g=DATA.gpu;return (g&&g.has_gpu&&g.gpus&&g.gpus.length)?g.gpus.length:'';}},
  memory:{t:'Memory consumers',i:'fa-memory',w:320,h:320,render:bMem,cnt:()=>DATA.d?(DATA.d.top_mem||[]).length:''},
  cpu:{t:'CPU consumers',i:'fa-microchip',w:340,h:320,render:bCpu,cnt:()=>DATA.d?(DATA.d.top_cpu||[]).length:''},
  network:{t:'Network',i:'fa-network-wired',w:300,h:300,render:bNet},
  lan:{t:'LAN traffic',i:'fa-ethernet',w:340,h:220,render:bLan,cnt:()=>DATA.ifd?(DATA.ifd.ifaces||[]).length:''},
  disks:{t:'Disks',i:'fa-hard-drive',w:320,h:180,render:bDisks},
  fans:{t:'Fans & temps',i:'fa-fan',w:300,h:200,render:bFans},
  sensors:{t:'Sensors',i:'fa-gauge-high',w:340,h:440,render:bSensors,cnt:()=>{ if(!DATA.d)return ''; const n=(DATA.d.sensors||[]).filter(s=>s.type!=='Fan'&&s.type!=='Temperature').length; return n||''; }},
  health:{t:'Host health',i:'fa-shield-halved',w:320,h:440,render:bHealth},
  events:{t:'Event log',i:'fa-file-lines',w:380,h:360,render:bEvents,cnt:()=>{const s=DATA.ev&&DATA.ev.summary;return s?`${s.crit||0}C ${s.err||0}E ${s.warn||0}W`:'';}},
};
const ORDER=['vitals','gpu','memory','cpu','network','lan','disks','fans','sensors','health','events'];
let LAYOUT={};

function widgetEl(id){ return document.getElementById('wg-'+id); }
function buildWidget(id){ const def=WIDGETS[id]; const el=document.createElement('div'); el.className='wgt'; el.id='wg-'+id;
  el.innerHTML=`<div class="wgt-h"><span class="t"><i class="fas ${def.i}"></i> ${esc(def.t)} <span class="cnt" id="wc-${id}"></span></span>
    <span class="btns"><span class="wb cl" title="Collapse"><i class="fas fa-minus"></i></span></span></div>
    <div class="wgt-b" id="wb-${id}"></div><div class="wgt-rs"></div>`;
  document.getElementById('ws-canvas').appendChild(el);
  el.querySelector('.cl').onclick=(e)=>{ e.stopPropagation(); LAYOUT[id].collapsed=!LAYOUT[id].collapsed; applyCollapse(id); saveLayout(); };
  makeDraggable(el,id); makeResizable(el,id);
  requestAnimationFrame(()=>el.classList.add('in'));
  return el; }
function applyCollapse(id){ const el=widgetEl(id); if(!el)return; const c=!!LAYOUT[id].collapsed; el.classList.toggle('collapsed',c); el.querySelector('.cl i').className='fas '+(c?'fa-plus':'fa-minus'); }
function applyGeom(id){ const el=widgetEl(id),L=LAYOUT[id]; if(!el)return; el.style.left=(L.x||0)+'px'; el.style.top=(L.y||0)+'px'; el.style.width=(L.w||WIDGETS[id].w)+'px'; if(!L.collapsed)el.style.height=(L.h||WIDGETS[id].h)+'px'; }
function renderWidget(id){ const def=WIDGETS[id],b=document.getElementById('wb-'+id); if(!b)return; try{ b.innerHTML=def.render(); }catch(e){ b.innerHTML='<div class="muted">err</div>'; }
  const c=document.getElementById('wc-'+id); if(c&&def.cnt){ try{ c.textContent=def.cnt(); }catch(e){} } if(def.after){ try{ def.after(); }catch(e){} } }

function makeDraggable(el,id){ const h=el.querySelector('.wgt-h'); let sx,sy,ox,oy,drag=false;
  h.addEventListener('mousedown',e=>{ if(e.target.closest('.wb'))return; drag=true; el.classList.add('drag'); h.style.cursor='grabbing';
    const cv=document.getElementById('ws-canvas').getBoundingClientRect(); sx=e.clientX; sy=e.clientY; ox=el.offsetLeft; oy=el.offsetTop; e.preventDefault();
    const mv=ev=>{ if(!drag)return; let nx=ox+(ev.clientX-sx),ny=oy+(ev.clientY-sy); nx=Math.max(0,Math.min(nx,cv.width-60)); ny=Math.max(0,ny); el.style.left=nx+'px'; el.style.top=ny+'px'; };
    const up=()=>{ if(!drag)return; drag=false; el.classList.remove('drag'); h.style.cursor='grab'; document.removeEventListener('mousemove',mv); document.removeEventListener('mouseup',up);
      LAYOUT[id].x=el.offsetLeft; LAYOUT[id].y=el.offsetTop; growCanvas(); saveLayout(); };
    document.addEventListener('mousemove',mv); document.addEventListener('mouseup',up); }); }
function makeResizable(el,id){ const r=el.querySelector('.wgt-rs'); let sx,sy,ow,oh,rz=false;
  r.addEventListener('mousedown',e=>{ rz=true; sx=e.clientX; sy=e.clientY; ow=el.offsetWidth; oh=el.offsetHeight; e.preventDefault(); e.stopPropagation();
    const mv=ev=>{ if(!rz)return; el.style.width=Math.max(220,ow+(ev.clientX-sx))+'px'; el.style.height=Math.max(110,oh+(ev.clientY-sy))+'px'; };
    const up=()=>{ if(!rz)return; rz=false; document.removeEventListener('mousemove',mv); document.removeEventListener('mouseup',up);
      LAYOUT[id].w=el.offsetWidth; LAYOUT[id].h=el.offsetHeight; growCanvas(); saveLayout(); };
    document.addEventListener('mousemove',mv); document.addEventListener('mouseup',up); }); }
function growCanvas(){ const cv=document.getElementById('ws-canvas'); let max=0; ORDER.forEach(id=>{ const el=widgetEl(id); if(el)max=Math.max(max,el.offsetTop+el.offsetHeight); }); cv.style.minHeight=(max+30)+'px'; }

// masonry default positions (columns) when the user has no saved layout
function defaultLayout(){ const L={}; const cw=document.getElementById('ws-canvas').clientWidth||1200; const gap=12; const cols=Math.max(1,Math.floor((cw+gap)/(330+gap))); const colH=new Array(cols).fill(8); const colW=Math.floor((cw-gap*(cols-1))/cols);
  ORDER.forEach(id=>{ const def=WIDGETS[id]; let span=Math.min(cols,Math.max(1,Math.round((def.w+gap)/(colW+gap)))); // wide widgets span columns
    // find the column window of `span` with the smallest max height
    let best=0,bestH=Infinity; for(let c=0;c<=cols-span;c++){ let mh=0; for(let k=c;k<c+span;k++)mh=Math.max(mh,colH[k]); if(mh<bestH){bestH=mh;best=c;} }
    const x=best*(colW+gap), y=bestH, w=colW*span+gap*(span-1);
    L[id]={x,y,w,h:def.h,collapsed:false}; const nh=y+def.h+gap; for(let k=best;k<best+span;k++)colH[k]=nh; });
  return L; }

function mountWidgets(){ ORDER.forEach(id=>{
    if(id==='gpu' && !(DATA.gpu&&DATA.gpu.has_gpu)){ const e=widgetEl(id); if(e)e.remove(); return; }
    if(!widgetEl(id))buildWidget(id); applyGeom(id); applyCollapse(id); renderWidget(id); }); growCanvas(); }

// ── layout persistence (per-user, DB) ──
let _saveT=null;
function saveLayout(){ clearTimeout(_saveT); _saveT=setTimeout(()=>{ POST(new URLSearchParams({action:'layout_save',layout:JSON.stringify(LAYOUT)})); },600); }
async function loadLayout(){ try{ const r=await fetch('linux.php?api=layout_get').then(r=>r.json()); const def=defaultLayout();
  if(r&&r.ok&&r.layout){ ORDER.forEach(id=>{ LAYOUT[id]=Object.assign(def[id]||{x:0,y:0,w:WIDGETS[id].w,h:WIDGETS[id].h,collapsed:false}, r.layout[id]||{}); }); }
  else LAYOUT=def; }catch(e){ LAYOUT=defaultLayout(); } }
function resetLayout(){ ORDER.forEach(id=>{ const el=widgetEl(id); if(el)el.remove(); }); LAYOUT=defaultLayout(); mountWidgets(); saveLayout(); }

// ── loader ──
const WL_MSGS=[['Connecting over SSH…','negotiating the session'],['Sampling processes…','two-pass CPU & memory'],['Reading sensors…','fans · temps · power · clocks'],['Querying health & events…','SMART · Defender · Event Log'],['Composing the wall…','laying out widgets']];
let _wlT=null,_wlI=0;
function cycleWl(){ const m=WL_MSGS[_wlI%WL_MSGS.length]; document.getElementById('wl-txt').textContent=m[0]; document.getElementById('wl-sub').textContent=m[1]; _wlI++; }
function showLoader(){ document.getElementById('ws-loader').classList.remove('hide'); _wlI=0; cycleWl(); if(!_wlT)_wlT=setInterval(cycleWl,1500); }
function hideLoader(){ if(_wlT){clearInterval(_wlT);_wlT=null;} document.getElementById('ws-loader').classList.add('hide'); }

// ── orchestration ──
async function loadAll(){
  document.getElementById('ws-when').innerHTML='<i class="fas fa-spinner fa-spin"></i> probing…';
  if(!_lastDiag) showLoader();
  const [dg,hl,ev,ifd,gp]=await Promise.all([
    fetch('linux.php?api=diag&host='+HID+'&_='+Date.now()).then(r=>r.json()).catch(()=>null),
    fetch('linux.php?api=health&host='+HID).then(r=>r.json()).catch(()=>null),
    fetch('linux.php?api=events&host='+HID+'&limit=40').then(r=>r.json()).catch(()=>null),
    fetch('linux.php?api=ifaces&host='+HID+'&_='+Date.now()).then(r=>r.json()).catch(()=>null),
    NODE_ID?fetch('net_mon_stats.php?api=gpu_stats&node_id='+NODE_ID+'&range=6h',{credentials:'same-origin'}).then(r=>r.json()).catch(()=>null):Promise.resolve(null)
  ]);
  DATA={d:(dg&&dg.ok)?dg.data:DATA.d, h:hl, ev:ev, ifd:ifd, gpu:gp, diagErr:(dg&&!dg.ok)?(dg.error||'Live diagnostics failed'):null};
  const dot=document.getElementById('ws-dot');
  if(dg&&dg.ok){ _lastDiag=dg.data; dot.className='ws-dot'; document.getElementById('ws-os').textContent=(dg.data.host||'')+(dg.data.cores?' · '+dg.data.cores+' cores':''); }
  else { dot.className='ws-dot bad'; document.getElementById('ws-os').textContent=(dg?esc(dg.error||'diag failed'):'unreachable'); }
  if(hl&&hl.data&&hl.data.os) document.getElementById('ws-os').textContent=hl.data.os;
  mountWidgets();
  document.getElementById('ws-when').innerHTML='<i class="fas fa-circle-check" style="color:var(--ok)"></i> '+new Date().toLocaleTimeString();
  hideLoader();
}
document.addEventListener('keydown',e=>{ if(e.key==='Escape')closeDock(); });
(async function(){ await loadLayout(); await loadAll(); })();
</script>
</body></html>
