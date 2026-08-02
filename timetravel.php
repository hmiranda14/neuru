<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Time-Travel Debugging. Drag the slider back in time and the whole NOC
// re-renders to that minute: node up/down + CPU, link load, top NetFlow talkers,
// incidents open then, and the syslog burst. Hit Play to watch a storm propagate.
// RBAC: 'timetravel'. Engine: nm_timetravel.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_timetravel.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'timetravel')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=timetravel'); exit;
}
nm_tt_ensure_perm($conn);
// Release the session lock before snapshot work (read-only) so scrubbing stays fluid and
// never serializes behind itself or blocks other portal pages.
if (session_status() === PHP_SESSION_ACTIVE) @session_write_close();

if ($api === 'snapshot') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok'=>true,'snap'=>nm_tt_snapshot($conn, $_GET['at'] ?? 'now')]); exit;
}

$range = nm_tt_range($conn);
log_user_action($conn,'view_page','timetravel.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Time-Travel | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --purple:#9b59b6; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.18; }
.wrap{ max-width:1400px; margin:0 auto; padding:18px 20px 40px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:15px 17px; } .card h3{ margin:0 0 12px; font-size:12px; color:var(--accent); text-transform:uppercase; letter-spacing:1px; display:flex; justify-content:space-between; align-items:center; }
/* time control */
.tt-bar{ padding:16px 20px; margin-bottom:16px; }
.tt-top{ display:flex; align-items:center; gap:16px; flex-wrap:wrap; margin-bottom:12px; }
.tt-clock{ font-size:24px; font-weight:800; letter-spacing:.5px; font-variant-numeric:tabular-nums; }
.tt-clock .d{ color:#8a909a; font-size:14px; font-weight:600; }
.tt-live{ font-size:10px; font-weight:800; padding:3px 10px; border-radius:20px; text-transform:uppercase; letter-spacing:1px; }
.live-on{ background:rgba(46,204,113,.16); color:var(--ok); } .live-off{ background:rgba(243,156,18,.16); color:var(--warn); }
.btn{ background:rgba(255,255,255,.06); border:1px solid var(--border); color:#cfd3da; padding:8px 12px; border-radius:9px; cursor:pointer; font-size:12px; display:inline-flex; gap:6px; align-items:center; }
.btn:hover{ background:rgba(255,255,255,.13); color:#fff; } .btn.play{ background:rgba(155,89,182,.2); border-color:var(--purple); color:#c08fd6; }
.slider{ width:100%; -webkit-appearance:none; height:8px; border-radius:6px; background:linear-gradient(90deg,#1a2330,#26405c); outline:none; }
.slider::-webkit-slider-thumb{ -webkit-appearance:none; width:20px; height:20px; border-radius:50%; background:var(--accent); cursor:pointer; box-shadow:0 0 10px var(--accent); border:2px solid #0a0e14; }
.slider::-moz-range-thumb{ width:18px; height:18px; border-radius:50%; background:var(--accent); cursor:pointer; border:2px solid #0a0e14; }
.ticks{ display:flex; justify-content:space-between; font-size:10px; color:#667; margin-top:5px; }
/* summary */
.sumrow{ display:grid; grid-template-columns:repeat(6,1fr); gap:10px; margin-bottom:16px; } @media(max-width:820px){ .sumrow{ grid-template-columns:repeat(3,1fr); } }
.sm{ padding:12px 14px; text-align:center; } .sm .n{ font-size:22px; font-weight:800; } .sm .l{ font-size:10px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; }
/* panels */
.grid{ display:grid; grid-template-columns:1fr 1fr; gap:16px; } @media(max-width:980px){ .grid{ grid-template-columns:1fr; } }
.nodes{ display:grid; grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); gap:9px; }
.node{ border:1px solid var(--border); border-left-width:3px; border-radius:9px; padding:8px 10px; background:rgba(0,0,0,.25); }
.node b{ font-size:12px; } .node .meta{ font-size:10.5px; color:#8a909a; margin-top:3px; }
.n-up{ border-left-color:var(--ok); } .n-down{ border-left-color:var(--crit); background:rgba(231,76,60,.08); } .n-unknown{ border-left-color:#555; opacity:.6; }
.bar{ height:7px; border-radius:4px; background:rgba(255,255,255,.08); overflow:hidden; margin-top:4px; }
.bar > i{ display:block; height:100%; background:var(--accent); }
.lk{ font-size:12px; padding:7px 0; border-bottom:1px solid rgba(255,255,255,.06); }
.lk .top{ display:flex; justify-content:space-between; gap:8px; }
.muted{ color:#7c828c; font-size:12px; } .mono{ font-family:Consolas,monospace; }
.inc{ font-size:12.5px; padding:7px 0; border-bottom:1px solid rgba(255,255,255,.06); }
.sev-dot{ display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; }
.sd-critical{ background:var(--crit);} .sd-warning{ background:var(--warn);} .sd-info{ background:var(--accent);}
.log{ font-family:Consolas,monospace; font-size:11.5px; padding:3px 0; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.lg-err{ color:#e9978f;} .lg-warn{ color:#f0c674;} .lg-ok{ color:#aeb6c0;}
/* clickable affordance + detail modal */
.clk{ cursor:pointer; transition:background .15s, box-shadow .15s; }
.sm.clk:hover,.lk.clk:hover,.inc.clk:hover{ background:rgba(77,163,255,.08); box-shadow:inset 0 0 0 1px rgba(77,163,255,.22); }
.node.clk:hover{ box-shadow:inset 0 0 0 1px rgba(77,163,255,.3); }
.sm.clk .l::after{ content:' ›'; color:var(--accent); }
#tt-modal{ position:fixed; inset:0; z-index:6000; display:none; align-items:center; justify-content:center; background:rgba(2,4,8,.68); backdrop-filter:blur(3px); }
#tt-modal.show{ display:flex; }
.tt-mcard{ width:min(640px,95%); max-height:88%; display:flex; flex-direction:column; background:rgba(12,17,26,.98); border:1px solid rgba(77,163,255,.3); border-radius:14px; box-shadow:0 24px 70px rgba(0,0,0,.7); }
.tt-mh{ display:flex; align-items:center; gap:10px; padding:13px 16px; border-bottom:1px solid var(--border); font-weight:700; color:#fff; }
.tt-mh .ti{ flex:1; min-width:0; } .tt-mh .x{ cursor:pointer; color:#8a909a; font-size:18px; } .tt-mh .x:hover{ color:#f0a59d; }
.tt-when{ font-size:11px; font-weight:400; color:#8a909a; }
.tt-mb{ overflow:auto; padding:14px 16px; font-size:13px; line-height:1.55; }
.tt-kv{ display:grid; grid-template-columns:repeat(auto-fit,minmax(110px,1fr)); gap:8px; margin-bottom:12px; }
.tt-kv > div{ background:rgba(255,255,255,.04); border:1px solid var(--border); border-radius:9px; padding:8px 10px; }
.tt-kv .k{ font-size:9.5px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; }
.tt-kv .v{ font-size:17px; font-weight:800; margin-top:2px; }
.tt-sub{ font-size:10.5px; text-transform:uppercase; letter-spacing:.5px; color:#8a929c; margin:13px 0 6px; display:flex; align-items:center; gap:7px; }
.tt-row{ display:flex; gap:9px; align-items:center; padding:7px 10px; border:1px solid var(--border); border-left-width:3px; border-radius:9px; margin-bottom:6px; font-size:12.5px; }
.tt-row.clk:hover{ border-color:var(--accent); }
.tt-row .main{ flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.tt-row .val{ font-family:Consolas,monospace; white-space:nowrap; color:#cfe4ff; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-clock-rotate-left"></i>Time-Travel', '', 'Historical NOC Replay', 'fa-solid fa-clock-rotate-left',
    '<a class="refresh-btn" href="net_mon.php"><i class="fas fa-gauge-high"></i> Live Dashboard</a>'); ?>

<!-- Time control -->
<div class="glass tt-bar">
  <div class="tt-top">
    <div class="tt-clock"><span class="d" id="tt-date">—</span> <span id="tt-time">—</span></div>
    <span class="tt-live live-on" id="tt-live">● LIVE</span>
    <div style="margin-left:auto;display:flex;gap:7px;flex-wrap:wrap;">
      <button class="btn" onclick="jump(-86400)">−24h</button>
      <button class="btn" onclick="jump(-14400)">−4h</button>
      <button class="btn" onclick="jump(-3600)">−1h</button>
      <button class="btn" onclick="jump(-300)"><i class="fas fa-backward-step"></i> 5m</button>
      <button class="btn" onclick="jump(300)">5m <i class="fas fa-forward-step"></i></button>
      <button class="btn play" id="tt-play" onclick="togglePlay()"><i class="fas fa-play"></i> Play</button>
      <button class="btn" onclick="goLive()"><i class="fas fa-bolt"></i> Now</button>
    </div>
  </div>
  <input type="range" class="slider" id="tt-slider" min="<?= (int)$range['min'] ?>" max="<?= (int)$range['max'] ?>" value="<?= (int)$range['max'] ?>" step="60">
  <div class="ticks"><span id="tk-min">—</span><span class="muted">drag to scrub · ~<?= round(($range['max']-$range['min'])/86400,1) ?> days of history</span><span id="tk-max">now</span></div>
</div>

<!-- Summary -->
<div class="sumrow">
  <div class="glass sm clk" onclick="showSummary('up')"><div class="n" style="color:var(--ok)" id="s-up">—</div><div class="l">Nodes up</div></div>
  <div class="glass sm clk" onclick="showSummary('down')"><div class="n" style="color:var(--crit)" id="s-down">—</div><div class="l">Nodes down</div></div>
  <div class="glass sm clk" onclick="showSummary('unknown')"><div class="n" style="color:#8a909a" id="s-unk">—</div><div class="l">Unknown</div></div>
  <div class="glass sm clk" onclick="showSummary('incidents')"><div class="n" style="color:var(--warn)" id="s-inc">—</div><div class="l">Incidents open</div></div>
  <div class="glass sm clk" onclick="showSummary('syslog')"><div class="n" id="s-syslog">—</div><div class="l">Syslog / min</div></div>
  <div class="glass sm clk" onclick="showSummary('nf')"><div class="n" style="color:var(--purple)" id="s-nf">—</div><div class="l">NetFlow Mbps</div></div>
</div>

<div class="grid">
  <div class="glass card" style="grid-column:1 / -1;">
    <h3><i class="fas fa-diagram-project"></i> Node state <span class="muted" id="node-when" style="text-transform:none;letter-spacing:0;"></span></h3>
    <div class="nodes" id="p-nodes"><div class="muted">Loading…</div></div>
  </div>
  <div class="glass card">
    <h3><i class="fas fa-gauge-high"></i> Top links by load</h3>
    <div id="p-links"><div class="muted">Loading…</div></div>
  </div>
  <div class="glass card">
    <h3><i class="fas fa-chart-area"></i> Top NetFlow talkers</h3>
    <div id="p-flows"><div class="muted">Loading…</div></div>
  </div>
  <div class="glass card">
    <h3><i class="fas fa-triangle-exclamation"></i> Incidents open at this moment</h3>
    <div id="p-incs"><div class="muted">Loading…</div></div>
  </div>
  <div class="glass card">
    <h3><i class="fas fa-file-lines"></i> Syslog around this minute</h3>
    <div id="p-syslog"><div class="muted">Loading…</div></div>
  </div>
</div>
</div>

<div id="tt-modal"><div class="tt-mcard">
  <div class="tt-mh"><span class="ti" id="tt-title">Details</span><span class="x" onclick="ttClose()"><i class="fas fa-xmark"></i></span></div>
  <div class="tt-mb" id="tt-body"></div>
</div></div>

<script>
const MIN=<?= (int)$range['min'] ?>, MAX=<?= (int)$range['max'] ?>;
const slider=document.getElementById('tt-slider');
let playT=null, fetchT=null, lastReq=0, playing=false;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function pad(n){ return String(n).padStart(2,'0'); }
function fmt(ts){ return { date: window.nmDate?nmDate(ts):new Date(ts*1000).toISOString().slice(0,10), time: window.nmClock?nmClock(ts):'' }; }
document.getElementById('tk-min').textContent=fmt(MIN).date+' '+fmt(MIN).time;
function setClock(ts){ const f=fmt(ts); document.getElementById('tt-date').textContent=f.date; document.getElementById('tt-time').textContent=f.time;
    const live=ts>=MAX-90; const el=document.getElementById('tt-live'); el.textContent=live?'● LIVE':'⏱ PAST'; el.className='tt-live '+(live?'live-on':'live-off'); }
let LAST=null;
function render(s){
    LAST=s;
    const su=s.summary;
    document.getElementById('s-up').textContent=su.up; document.getElementById('s-down').textContent=su.down;
    document.getElementById('s-unk').textContent=su.unknown; document.getElementById('s-inc').textContent=su.incidents;
    document.getElementById('s-syslog').textContent=su.syslog_rate; document.getElementById('s-nf').textContent=su.nf_mbps;
    document.getElementById('node-when').textContent='@ '+(window.nmLocal?nmLocal(s.at,true):s.at);
    // nodes
    document.getElementById('p-nodes').innerHTML = s.nodes.map(n=>`<div class="node n-${n.state} clk" onclick="showNode(${n.id})">
        <b>${esc(n.name)}</b><div class="meta">${n.state==='up'?'<span style="color:var(--ok)">● up</span>':n.state==='down'?'<span style="color:var(--crit)">● down</span>':'<span style="color:#888">○ no data</span>'}
        ${n.cpu!=null?` · CPU ${n.cpu}%`:''}${n.latency!=null?` · ${n.latency}ms`:''}</div></div>`).join('') || '<div class="muted">No nodes.</div>';
    // links
    document.getElementById('p-links').innerHTML = s.links.length ? s.links.slice(0,12).map((l,i)=>{
        const u=Math.max(l.in_util||0,l.out_util||0); const col=u>=80?'var(--crit)':u>=50?'var(--warn)':'var(--accent)';
        return `<div class="lk clk" onclick="showLink(${i})"><div class="top"><span>${esc(l.node)} <span class="muted">${esc(l.iface)}</span></span><span>↓${l.in_mbps} ↑${l.out_mbps} Mbps</span></div>
            <div class="bar"><i style="width:${Math.min(100,u)}%;background:${col};"></i></div></div>`;
    }).join('') : '<div class="muted">No interface samples at this time.</div>';
    // flows
    document.getElementById('p-flows').innerHTML = s.netflow.flows.length ? s.netflow.flows.map((f,i)=>`<div class="lk clk" onclick="showFlow(${i})">
        <div class="top"><span class="mono">${esc(f.src)} → ${esc(f.dst)}</span><span><b>${f.mbps}</b> Mbps</span></div>
        <div class="muted">${esc(f.app)}/${esc(f.proto)} · ${f.pkts} pkts</div></div>`).join('') : '<div class="muted">No NetFlow at this minute.</div>';
    // incidents
    document.getElementById('p-incs').innerHTML = s.incidents.length ? s.incidents.slice(0,12).map((it,idx)=>`<div class="inc clk" onclick="showInc(${idx})">
        <span class="sev-dot sd-${it.severity}"></span><b>${esc(it.title)}</b>
        ${it.impact_count>0?`<span class="muted"> · impacts ${it.impact_count}</span>`:''}
        <div class="muted">opened ${esc(window.nmLocal?nmLocal(it.opened_at):it.opened_at)}</div></div>`).join('') : '<div class="muted">No incidents open at this moment. 🎉</div>';
    // syslog
    document.getElementById('p-syslog').innerHTML = `<div class="muted" style="margin-bottom:6px;">${s.syslog.rate} msgs in the last 60s${s.syslog.errors?` · <span style="color:var(--crit)">${s.syslog.errors} errors</span>`:''}</div>`+
        (s.syslog.lines.length ? s.syslog.lines.map(l=>{ const c=l.sev<=3?'lg-err':(l.sev<=4?'lg-warn':'lg-ok');
            return `<div class="log ${c}">${esc(window.nmTimeStr?nmTimeStr(l.at):l.at.substr(11))} ${esc(l.host)} ${esc(l.tag)}: ${esc(l.msg)}</div>`; }).join('') : '<div class="muted">No logs.</div>');
}
/* ── Detail popups (all rendered from the loaded snapshot = the scrubbed moment) ── */
function ttWhen(){ return LAST ? (window.nmLocal?nmLocal(LAST.at,true):LAST.at) : ''; }
function ttOpen(title,html){ document.getElementById('tt-title').innerHTML=title+` <span class="tt-when">@ ${esc(ttWhen())}</span>`;
    document.getElementById('tt-body').innerHTML=html; document.getElementById('tt-modal').classList.add('show'); }
function ttClose(){ document.getElementById('tt-modal').classList.remove('show'); }
document.addEventListener('keydown',e=>{ if(e.key==='Escape') ttClose(); });
document.getElementById('tt-modal').addEventListener('click',e=>{ if(e.target.id==='tt-modal') ttClose(); });

function showNode(id){ if(!LAST)return; const n=(LAST.nodes||[]).find(x=>x.id===id); if(!n)return;
    const ip=n.ip||''; const stCol=n.state==='up'?'var(--ok)':n.state==='down'?'var(--crit)':'#8a909a';
    const stTxt=n.state==='up'?'UP':n.state==='down'?'DOWN':'NO DATA';
    const links=(LAST.links||[]).filter(l=>l.node===n.name);
    const flows=((LAST.netflow||{}).flows||[]).filter(f=>f.src===ip||f.dst===ip);
    const logs=((LAST.syslog||{}).lines||[]).filter(l=>l.host && (l.host===n.name||l.host===ip));
    let h=`<div class="tt-kv">
        <div><div class="k">Status</div><div class="v" style="color:${stCol}">${stTxt}</div></div>
        ${n.cpu!=null?`<div><div class="k">CPU</div><div class="v">${n.cpu}%</div></div>`:''}
        ${n.latency!=null?`<div><div class="k">Latency</div><div class="v">${n.latency}<span style="font-size:11px"> ms</span></div></div>`:''}
        ${n.loss!=null?`<div><div class="k">Pkt loss</div><div class="v">${n.loss}%</div></div>`:''}
        <div><div class="k">IP</div><div class="v mono" style="font-size:13px;">${esc(ip||'—')}</div></div></div>`;
    h+=`<div class="tt-sub"><i class="fas fa-gauge-high"></i> Interfaces (${links.length})</div>`;
    h+= links.length? links.map(l=>{const u=Math.max(l.in_util||0,l.out_util||0);
        return `<div class="tt-row" style="border-left-color:var(--accent);"><span class="main">${esc(l.iface)}${l.oper&&String(l.oper).toLowerCase()!=='up'?` <span style="color:var(--crit)">[${esc(l.oper)}]</span>`:''}</span><span class="val">↓${l.in_mbps} ↑${l.out_mbps} Mbps${u?` · ${u}%`:''}</span></div>`;}).join('') : '<div class="muted">No interface samples.</div>';
    h+=`<div class="tt-sub"><i class="fas fa-chart-area"></i> NetFlow involving this host (${flows.length})</div>`;
    h+= flows.length? flows.map(f=>`<div class="tt-row" style="border-left-color:var(--purple);"><span class="main mono">${esc(f.src)} → ${esc(f.dst)} <span class="muted">${esc(f.app)}/${esc(f.proto)}</span></span><span class="val">${f.mbps} Mbps</span></div>`).join('') : '<div class="muted">No flows at this minute (NetFlow keeps top-N).</div>';
    h+=`<div class="tt-sub"><i class="fas fa-file-lines"></i> Syslog from this host</div>`;
    h+= logs.length? logs.map(l=>{const c=l.sev<=3?'lg-err':(l.sev<=4?'lg-warn':'lg-ok');return `<div class="log ${c}" style="white-space:normal;">${esc(window.nmTimeStr?nmTimeStr(l.at):String(l.at).substr(11))} ${esc(l.tag)}: ${esc(l.msg)}</div>`;}).join('') : '<div class="muted">No syslog lines from this host in the window.</div>';
    ttOpen(`<span style="color:${stCol}">●</span> ${esc(n.name)}`, h);
}
function showLink(i){ if(!LAST)return; const l=(LAST.links||[])[i]; if(!l)return;
    const node=(LAST.nodes||[]).find(n=>n.name===l.node); const u=Math.max(l.in_util||0,l.out_util||0);
    let h=`<div class="tt-kv">
        <div><div class="k">In</div><div class="v" style="color:var(--accent)">${l.in_mbps}<span style="font-size:11px"> Mbps</span></div></div>
        <div><div class="k">Out</div><div class="v" style="color:var(--accent)">${l.out_mbps}<span style="font-size:11px"> Mbps</span></div></div>
        <div><div class="k">Utilisation</div><div class="v" style="color:${u>=80?'var(--crit)':u>=50?'var(--warn)':'var(--ok)'}">${u||0}%</div></div>
        <div><div class="k">Oper</div><div class="v" style="font-size:14px;color:${l.oper&&String(l.oper).toLowerCase()==='up'?'var(--ok)':'var(--crit)'}">${esc(l.oper||'—')}</div></div></div>`;
    if(node) h+=`<div class="tt-row clk" onclick="showNode(${node.id})" style="border-left-color:var(--ok);"><span class="main"><i class="fas fa-server"></i> ${esc(l.node)} — full device state</span><span class="val">›</span></div>`;
    ttOpen(`<i class="fas fa-ethernet" style="color:var(--accent)"></i> ${esc(l.node)} <span class="muted">${esc(l.iface)}</span>`, h);
}
function showFlow(i){ if(!LAST)return; const f=((LAST.netflow||{}).flows||[])[i]; if(!f)return;
    const srcN=(LAST.nodes||[]).find(n=>n.ip===f.src), dstN=(LAST.nodes||[]).find(n=>n.ip===f.dst);
    let h=`<div class="tt-kv">
        <div><div class="k">Throughput</div><div class="v" style="color:var(--purple)">${f.mbps}<span style="font-size:11px"> Mbps</span></div></div>
        <div><div class="k">Packets</div><div class="v">${f.pkts}</div></div>
        <div><div class="k">App</div><div class="v" style="font-size:14px">${esc(f.app)}</div></div>
        <div><div class="k">Proto</div><div class="v" style="font-size:14px">${esc(f.proto)}</div></div></div>
      <div class="tt-row" style="border-left-color:var(--purple);"><span class="main mono">${esc(f.src)} → ${esc(f.dst)}</span></div>`;
    if(srcN) h+=`<div class="tt-row clk" onclick="showNode(${srcN.id})" style="border-left-color:var(--ok);"><span class="main"><i class="fas fa-server"></i> Source is ${esc(srcN.name)}</span><span class="val">›</span></div>`;
    if(dstN) h+=`<div class="tt-row clk" onclick="showNode(${dstN.id})" style="border-left-color:var(--ok);"><span class="main"><i class="fas fa-server"></i> Destination is ${esc(dstN.name)}</span><span class="val">›</span></div>`;
    h+=`<div class="muted" style="margin-top:8px;">NetFlow bucket ${esc((LAST.netflow||{}).bucket||'—')} · total ${(LAST.netflow||{}).total_mbps||0} Mbps this minute.</div>`;
    ttOpen(`<i class="fas fa-chart-area" style="color:var(--purple)"></i> Flow detail`, h);
}
function showInc(idx){ if(!LAST)return; const it=(LAST.incidents||[])[idx]; if(!it)return;
    const col=it.severity==='critical'?'var(--crit)':it.severity==='warning'?'var(--warn)':'var(--accent)';
    let h=`<div class="tt-kv">
        <div><div class="k">Severity</div><div class="v" style="font-size:14px;color:${col}">${esc(String(it.severity||'').toUpperCase())}</div></div>
        ${it.impact_count>0?`<div><div class="k">Impacts</div><div class="v">${it.impact_count}</div></div>`:''}
        <div><div class="k">Opened</div><div class="v" style="font-size:12px">${esc(window.nmLocal?nmLocal(it.opened_at):it.opened_at)}</div></div></div>`;
    if(it.impact) h+=`<div class="tt-sub">Impact</div><div style="color:#cdd4dd;">${esc(it.impact)}</div>`;
    h+=`<div class="muted" style="margin-top:10px;">State as of the scrubbed moment. Open <a href="incidents.php" target="_blank">Incident Command ↗</a> for the live record.</div>`;
    ttOpen(`<span class="sev-dot sd-${it.severity}"></span> ${esc(it.title)}`, h);
}
function showSummary(kind){ if(!LAST)return;
    if(kind==='up'||kind==='down'||kind==='unknown'){
        const list=(LAST.nodes||[]).filter(n=>n.state===kind);
        const title={up:'<span style="color:var(--ok)">●</span> Nodes up',down:'<span style="color:var(--crit)">●</span> Nodes down',unknown:'<span style="color:#8a909a">○</span> Unknown / no data'}[kind];
        const h= list.length? list.map(n=>`<div class="tt-row clk" onclick="showNode(${n.id})" style="border-left-color:${n.state==='up'?'var(--ok)':n.state==='down'?'var(--crit)':'#555'};"><span class="main"><b>${esc(n.name)}</b> <span class="muted mono">${esc(n.ip||'')}</span></span><span class="val">${n.cpu!=null?'CPU '+n.cpu+'%':''}${n.latency!=null?' · '+n.latency+'ms':''}<span style="color:var(--accent)"> ›</span></span></div>`).join('') : '<div class="muted">None at this moment.</div>';
        ttOpen(title, h); return;
    }
    if(kind==='incidents'){
        const list=LAST.incidents||[];
        const h= list.length? list.map((it,idx)=>`<div class="tt-row clk" onclick="showInc(${idx})" style="border-left-color:${it.severity==='critical'?'var(--crit)':it.severity==='warning'?'var(--warn)':'var(--accent)'};"><span class="main"><span class="sev-dot sd-${it.severity}"></span>${esc(it.title)}</span><span class="val">${it.impact_count>0?'impacts '+it.impact_count:''} ›</span></div>`).join('') : '<div class="muted">No incidents open at this moment. 🎉</div>';
        ttOpen('<i class="fas fa-triangle-exclamation" style="color:var(--warn)"></i> Incidents open', h); return;
    }
    if(kind==='syslog'){
        const sl=LAST.syslog||{lines:[]};
        let h=`<div class="tt-kv"><div><div class="k">Msgs / 60s</div><div class="v">${sl.rate||0}</div></div><div><div class="k">Errors</div><div class="v" style="color:${sl.errors?'var(--crit)':'var(--ok)'}">${sl.errors||0}</div></div></div><div class="tt-sub">Recent lines</div>`;
        h+= (sl.lines&&sl.lines.length)? sl.lines.map(l=>{const c=l.sev<=3?'lg-err':(l.sev<=4?'lg-warn':'lg-ok');return `<div class="log ${c}" style="white-space:normal;">${esc(window.nmTimeStr?nmTimeStr(l.at):String(l.at).substr(11))} <b>${esc(l.host)}</b> ${esc(l.tag)}: ${esc(l.msg)}</div>`;}).join('') : '<div class="muted">No logs.</div>';
        ttOpen('<i class="fas fa-file-lines" style="color:var(--accent)"></i> Syslog activity', h); return;
    }
    if(kind==='nf'){
        const nf=LAST.netflow||{flows:[]};
        let h=`<div class="muted" style="margin-bottom:10px;">Total <b style="color:var(--purple)">${nf.total_mbps||0} Mbps</b> attributed this minute${nf.bucket?` · bucket ${esc(nf.bucket)}`:''}. Click a flow for detail.</div>`;
        h+= (nf.flows&&nf.flows.length)? nf.flows.map((f,i)=>`<div class="tt-row clk" onclick="showFlow(${i})" style="border-left-color:var(--purple);"><span class="main mono">${esc(f.src)} → ${esc(f.dst)} <span class="muted">${esc(f.app)}/${esc(f.proto)}</span></span><span class="val">${f.mbps} Mbps ›</span></div>`).join('') : '<div class="muted">No NetFlow at this minute.</div>';
        ttOpen('<i class="fas fa-chart-area" style="color:var(--purple)"></i> NetFlow talkers', h); return;
    }
}

let snapAbort=null;
async function fetchSnap(ts){
    const req=++lastReq;
    if(snapAbort) snapAbort.abort();          // cancel any in-flight scrub so requests never pile up
    snapAbort=new AbortController();
    let r=null;
    try{ r=await fetch('timetravel.php?api=snapshot&at='+ts,{signal:snapAbort.signal}).then(r=>r.json()); }catch(e){ return; }
    if(!r||!r.ok||req!==lastReq) return;  // ignore stale responses
    render(r.snap);
}
function onScrub(){ setClock(+slider.value); clearTimeout(fetchT); fetchT=setTimeout(()=>fetchSnap(+slider.value),120); }
slider.addEventListener('input', onScrub);
function jump(sec){ slider.value=Math.max(MIN,Math.min(MAX,(+slider.value)+sec)); onScrub(); }
function goLive(){ slider.value=MAX; stopPlay(); onScrub(); }
function togglePlay(){ playing?stopPlay():startPlay(); }
function startPlay(){ const b=document.getElementById('tt-play'); b.innerHTML='<i class="fas fa-pause"></i> Pause'; b.style.color='#fff';
    playing=true; playStep(); }
// Sequential playback: advance → load → render → THEN schedule the next frame. This keeps
// it fluid even when a snapshot takes ~1s (a fixed interval would outrun the fetch and the
// stale-guard would drop frames → "data not moving with the slider").
async function playStep(){
    if(!playing) return;
    let v=(+slider.value)+300; if(v>MAX) v=MAX;
    slider.value=v; setClock(v);
    await fetchSnap(v);                 // wait until this frame actually renders
    if(!playing) return;
    if(v>=MAX){ stopPlay(); return; }
    playT=setTimeout(playStep, 200);   // small breath between frames
}
function stopPlay(){ playing=false; if(playT){ clearTimeout(playT); playT=null; }
    const b=document.getElementById('tt-play'); b.innerHTML='<i class="fas fa-play"></i> Play'; b.style.color=''; }
// init at "now"
setClock(MAX); fetchSnap(MAX);
</script>
</body></html>
