<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — SNMP Switches. A cockpit for every SNMP-managed switch (MikroTik SwOS/
// CRS, generic L2). Live port faceplate (link/speed/utilization from IF-MIB), with
// links to the full stats + a per-node role override. RBAC: 'switches'. Engine: nm_switches.php
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_switches.php');
include('logger.php');

$api = $_GET['api'] ?? ''; $act = $_POST['action'] ?? '';
if (!checkAccess($conn,'switches')) {
    if ($api||$act){ header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=switches'); exit;
}
nm_sw_ensure($conn);
if (function_exists('session_write_close')) @session_write_close();

if ($act === 'set_role') { header('Content-Type: application/json'); echo json_encode(nm_sw_set_role($conn,(int)($_POST['node_id']??0),(string)($_POST['role']??'auto'))); exit; }
if ($api === 'list') {
    header('Content-Type: application/json');
    $out=[];
    foreach (nm_sw_snmp_switches($conn) as $s) {
        $ports = nm_sw_ports($conn,(int)$s['id']);
        $up = count(array_filter($ports, fn($p)=>$p['status']==='up'));
        $out[] = ['id'=>(int)$s['id'],'name'=>$s['display_name'],'ip'=>$s['ip_address'],'model'=>$s['hw_model'],
                  'os'=>$s['os_icon'],'role'=>nm_sw_role($s),'ports'=>$ports,'up'=>$up,'total'=>count($ports),
                  'vitals'=>nm_sw_vitals($conn,(int)$s['id']),'thru'=>nm_sw_throughput($ports)];
    }
    echo json_encode(['ok'=>true,'switches'=>$out,'candidates'=>nm_sw_candidates($conn)]); exit;
}

log_user_action($conn,'view_page','snmp_switch.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SNMP Switches | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.15; }
.wrap{ max-width:1200px; margin:0 auto; padding:18px 20px 48px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.sw{ padding:18px 20px; margin-bottom:18px; }
.sw-head{ display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
.sw-ic{ width:46px; height:46px; border-radius:12px; background:rgba(77,163,255,.12); border:1px solid rgba(77,163,255,.3); display:flex; align-items:center; justify-content:center; color:var(--accent); font-size:20px; }
.sw-name{ font-size:17px; font-weight:800; } .sw-meta{ font-size:12px; color:#8a909a; }
.pill{ font-size:10px; font-weight:700; padding:3px 10px; border-radius:20px; background:rgba(46,204,113,.14); color:#7fe0a3; }
.muted{ color:#7c828c; font-size:12px; } .mono{ font-family:monospace; }
.select{ background:#1b2129; color:#e6e9ee; border:1px solid var(--border); border-radius:8px; padding:6px 9px; font-size:12px; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:8px; padding:6px 12px; font-size:12px; cursor:pointer; }
/* ── Switch faceplate ─────────────────────────────────────────────────────── */
.faceplate{ margin-top:16px; padding:14px; background:linear-gradient(180deg,#0c1016,#080b10); border:1px solid #1c222c; border-radius:12px; }
.ports{ display:grid; grid-template-columns:repeat(auto-fill,minmax(56px,1fr)); gap:9px; }
.port{ aspect-ratio:1.25; border-radius:7px; border:1px solid rgba(255,255,255,.08); display:flex; flex-direction:column; align-items:center; justify-content:center; cursor:pointer; position:relative; transition:transform .08s, box-shadow .08s; background:#11161d; }
.port:hover{ transform:translateY(-2px); box-shadow:0 0 0 2px var(--accent); }
.port .n{ font-size:12px; font-weight:800; } .port .sp{ font-size:8.5px; color:#8a909a; margin-top:1px; }
.port.up{ background:linear-gradient(180deg,rgba(46,204,113,.28),rgba(46,204,113,.10)); border-color:rgba(46,204,113,.45); }
.port.up .n{ color:#8ff0b5; } .port.up::after{ content:""; position:absolute; top:5px; right:5px; width:6px; height:6px; border-radius:50%; background:var(--ok); box-shadow:0 0 7px var(--ok); }
.port.busy{ background:linear-gradient(180deg,rgba(243,156,18,.30),rgba(243,156,18,.10)); border-color:rgba(243,156,18,.5); }
.port.busy .n{ color:#ffcf7a; } .port.busy::after{ content:""; position:absolute; top:5px; right:5px; width:6px; height:6px; border-radius:50%; background:var(--warn); box-shadow:0 0 7px var(--warn); }
.port.down{ opacity:.5; } .port.down .n{ color:#7a828c; }
.port .pbar{ width:80%; height:3px; border-radius:2px; background:rgba(255,255,255,.1); margin-top:4px; overflow:hidden; }
.port .pbar>i{ display:block; height:100%; background:var(--ok); }
.port.busy .pbar>i{ background:var(--warn); }
.legend{ display:flex; gap:16px; margin-top:12px; font-size:11px; color:#9aa3ad; }
.legend i{ width:11px; height:11px; border-radius:3px; display:inline-block; margin-right:5px; vertical-align:-1px; }
.ptbl{ width:100%; border-collapse:collapse; margin-top:14px; font-size:12px; }
.ptbl th{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; padding:6px 8px; border-bottom:1px solid var(--border); }
.ptbl td{ padding:6px 8px; border-bottom:1px solid rgba(255,255,255,.05); }
.ptbl tbody tr:hover{ background:rgba(77,163,255,.06); }
.vitals{ display:inline-flex; gap:12px; margin-left:4px; }
.vitals .v{ color:#9aa3ad; } .vitals .v i{ opacity:.7; margin-right:3px; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-ethernet"></i>SNMP Switches', '', 'Managed L2 · live port faceplate', 'fa-solid fa-ethernet',
    '<a class="refresh-btn" href="switch_center.php"><i class="fas fa-arrow-left"></i> Switch Center</a> <button class="refresh-btn" onclick="load()"><i class="fas fa-rotate"></i> Refresh</button>'); ?>
<div id="list"><div class="muted">Loading…</div></div>
<div class="glass" id="tagbox" style="padding:14px 18px;margin-top:8px;display:none;">
  <div class="muted" style="margin-bottom:8px;"><i class="fas fa-tags"></i> Not showing a switch you expect? NEURU classes devices automatically from the model/OS — mark any monitored SNMP device as a switch here:</div>
  <div id="cands" style="display:flex;flex-direction:column;gap:6px;"></div>
</div>
</div>
<script>
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function spd(mbps){ if(!mbps)return''; return mbps>=1000?(mbps/1000)+'G':mbps+'M'; }
// in_rate/out_rate are BYTES/sec → show bits/sec (standard for network traffic)
function fbps(bytesPerSec){ const b=(bytesPerSec||0)*8; if(b<1000)return Math.round(b)+' bps'; if(b<1e6)return (b/1e3).toFixed(1)+' Kbps'; if(b<1e9)return (b/1e6).toFixed(2)+' Mbps'; return (b/1e9).toFixed(2)+' Gbps'; }
function upt(sec){ if(!sec)return'—'; const d=Math.floor(sec/86400),h=Math.floor(sec%86400/3600); return d?d+'d '+h+'h':h+'h'; }
async function post(b){ return fetch('snmp_switch.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b}).then(r=>r.json()).catch(()=>null); }
const ROLES=['auto','switch','router','server','ap','firewall','other'];
function portCard(nid,p){
  const cls = p.status==='up' ? (p.util>=70?'busy':'up') : 'down';
  const sp = p.speed? spd(Math.round(p.speed/1000000)) : '';
  const util = Math.round(Math.max(p.util||0,0));
  const tip = esc(p.name)+(p.alias?' ('+esc(p.alias)+')':'')+' · '+(p.status||'?')+(sp?' · '+sp:'')+' · ▼ '+fbps(p.in_rate)+' ▲ '+fbps(p.out_rate)+' · '+util+'%';
  const bar = p.status==='up'? `<div class="pbar"><i style="width:${Math.min(util,100)}%"></i></div>`:'';
  return `<div class="port ${cls}" title="${tip}" onclick="location.href='net_mon_stats.php?node=${nid}&port=${p.port_id}'">
    <div class="n">${esc(String(p.name).replace(/[^0-9]/g,'')||p.if_index||'')}</div>
    <div class="sp">${sp||(p.status==='up'?'up':'—')}</div>${bar}</div>`;
}
function portRow(nid,p){
  const stc = p.status==='up'?'#7fe0a3':(p.status==='down'?'#7a828c':'#f0c674');
  return `<tr onclick="location.href='net_mon_stats.php?node=${nid}&port=${p.port_id}'" style="cursor:pointer">
    <td class="mono">${esc(p.name)}</td><td style="color:${stc}">${esc(p.status||'?')}</td>
    <td>${p.speed?spd(Math.round(p.speed/1000000)):'—'}</td>
    <td class="mono">▼ ${fbps(p.in_rate)}</td><td class="mono">▲ ${fbps(p.out_rate)}</td>
    <td>${p.status==='up'?Math.round(Math.max(p.util||0,0))+'%':'—'}</td></tr>`;
}
function swCard(s){
  const v=s.vitals||{}, t=s.thru||{in:0,out:0};
  const vitals = [
    v.uptime?`<span class="v"><i class="fas fa-clock"></i> up ${upt(v.uptime)}</span>`:'',
    (v.cpu!=null)?`<span class="v"><i class="fas fa-microchip"></i> CPU ${Math.round(v.cpu)}%</span>`:'',
    (v.mem!=null)?`<span class="v"><i class="fas fa-memory"></i> Mem ${Math.round(v.mem)}%</span>`:'',
    (v.temp!=null && v.temp>0)?`<span class="v"><i class="fas fa-temperature-half"></i> ${Math.round(v.temp)}°C</span>`:''
  ].filter(Boolean).join('');
  const face = s.ports.length? `<div class="faceplate"><div class="ports">${s.ports.map(p=>portCard(s.id,p)).join('')}</div>
      <div class="legend"><span><i style="background:rgba(46,204,113,.6)"></i>Up</span><span><i style="background:rgba(243,156,18,.7)"></i>Busy &ge;70%</span><span><i style="background:#11161d;border:1px solid #333"></i>Down</span>
      <span style="margin-left:auto">click a port → traffic graph</span></div>
      <table class="ptbl"><thead><tr><th>Port</th><th>Link</th><th>Speed</th><th>In</th><th>Out</th><th>Util</th></tr></thead>
        <tbody>${s.ports.map(p=>portRow(s.id,p)).join('')}</tbody></table></div>`
    : '<div class="muted" style="margin-top:12px;">No port data yet — the SNMP poller will populate the faceplate on its next run.</div>';
  const roleOpts = ROLES.map(r=>`<option value="${r}" ${r===s.role?'selected':''}>${r}</option>`).join('');
  return `<div class="glass sw">
    <div class="sw-head">
      <div class="sw-ic"><i class="fas fa-ethernet"></i></div>
      <div style="flex:1;min-width:0;">
        <div class="sw-name">${esc(s.name)} <span class="pill">${s.up}/${s.total} up</span>
          <span class="pill" style="background:rgba(77,163,255,.14);color:#bcd">▼ ${fbps(t.in)} ▲ ${fbps(t.out)}</span></div>
        <div class="sw-meta"><span class="mono">${esc(s.ip)}</span>${s.model?' · '+esc(s.model):''} <span class="vitals">${vitals}</span></div>
      </div>
      <select class="select" onchange="setRole(${s.id},this.value)" title="Device role">${roleOpts}</select>
      <a class="btn" href="net_mon_stats.php?node=${s.id}"><i class="fas fa-chart-line"></i> SNMP graphs</a>
    </div>
    ${face}
  </div>`;
}
async function load(){
  const r=await fetch('snmp_switch.php?api=list').then(r=>r.json()).catch(()=>null);
  const box=document.getElementById('list');
  if(!r||!r.ok){ box.innerHTML='<div class="muted">Load failed</div>'; return; }
  box.innerHTML = r.switches.length? r.switches.map(swCard).join('')
    : '<div class="glass" style="padding:22px;text-align:center;color:#8a909a;">No SNMP switches detected yet. Use the tagging box below to mark a device, or add a switch as an SNMP node.</div>';
  const tb=document.getElementById('tagbox'), cb=document.getElementById('cands');
  if(r.candidates&&r.candidates.length){ tb.style.display='block';
    cb.innerHTML=r.candidates.map(c=>`<div style="display:flex;align-items:center;gap:10px;">
      <span class="mono" style="min-width:140px">${esc(c.ip)}</span><span style="flex:1">${esc(c.name)}${c.model?' <span class="muted">— '+esc(c.model)+'</span>':''}</span>
      <button class="btn" onclick="setRole(${c.id},'switch')"><i class="fas fa-plus"></i> Mark as switch</button></div>`).join('');
  } else tb.style.display='none';
}
async function setRole(id,role){ await post(new URLSearchParams({action:'set_role',node_id:id,role})); load(); }
load();
</script>
</body></html>
