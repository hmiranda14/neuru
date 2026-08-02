<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — CONNECTION DOCTOR. Fullscreen WebGL "data highway": YOU → Router → ISP
// → Internet → Game server, each waypoint measured from BOTH your PC (real ICMP
// over SSH) and the NOC (TCP), with live ping / jitter / packet-loss / stability
// and a plain verdict: is the lag your WiFi, your ISP, or the game? Sibling of PC
// Doctor. Reached from Game Mode. Perm 'gaming'. Engine: nm_netdoc.php
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_netdoc.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'gaming')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=gaming'); exit;
}
if (function_exists('session_write_close')) @session_write_close();

if ($api) {
    header('Content-Type: application/json');
    try {
        if ($api === 'rigs') {
            $rows = function_exists('nm_win_hosts') ? nm_win_hosts($conn) : [];
            echo json_encode(['ok'=>true,'rigs'=>array_map(fn($r)=>['id'=>(int)$r['id'],'name'=>$r['name'],'ip'=>$r['host_ip']??''], $rows)]); exit;
        }
        $rid = (int)($_GET['rig'] ?? 0);
        $h = $rid && function_exists('nm_win_host') ? nm_win_host($conn,$rid) : null;
        if ($api === 'servers') {   // reuse the Game Server Status list (famous + your own) as the target dropdown
            $s = function_exists('nm_gaming_servers_status') ? nm_gaming_servers_status($conn, false) : ['official'=>[],'custom'=>[]];
            $pick = fn($a)=>array_map(fn($x)=>['name'=>$x['name'],'game'=>$x['game'],'host'=>$x['host'],'port'=>(int)$x['port']], $a);
            echo json_encode(['ok'=>true,'official'=>$pick($s['official']??[]),'custom'=>$pick($s['custom']??[])]); exit;
        }
        if ($api === 'server_add') {   // add a server to the shared list (also shows up in Game Server Status)
            $tok=(string)($_POST['csrf'] ?? ''); // best-effort; write reuses gaming's add
            $r = function_exists('nm_gaming_server_add') ? nm_gaming_server_add($conn, [
                'name'=>(string)($_POST['name']??''),'host'=>(string)($_POST['host']??''),'port'=>(string)($_POST['port']??''),
                'proto'=>(string)($_POST['proto']??'tcp'),'game'=>(string)($_POST['game']??'Custom')
            ], (string)($_SESSION['username']??'operator')) : ['ok'=>false,'error'=>'unavailable'];
            echo json_encode($r); exit;
        }
        if ($api === 'run') {
            if (!$h) { echo json_encode(['ok'=>false,'error'=>'pick a rig']); exit; }
            $tgt = trim((string)($_GET['target'] ?? ''));
            if ($tgt!==''){ $hostOnly=preg_replace('/:\d+$/','',$tgt); if(!nm_netdoc_valid_host($hostOnly)) $tgt=''; }
            log_user_action($conn,'netdoc_run',$h['name']??('rig '.$rid));
            echo json_encode(nm_netdoc_run($conn,$h,$tgt)); exit;
        }
        if ($api === 'history') {
            echo json_encode(['ok'=>true,'hist'=>nm_netdoc_get_history($conn,$rid,(int)($_GET['hours'] ?? 24))]); exit;
        }
        echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
    } catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>'server error']); exit; }
}
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Connection Doctor | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="/three.min.js"></script>
<script src="/nm_netbg.js"></script>
<style>
:root{ --cy:#39e1ff; --pk:#b06bff; --ok:#2ee66e; --warn:#f0a92c; --crit:#ff4d6d; --bd:rgba(120,150,255,.16); }
*,*::before,*::after{ box-sizing:border-box; }
html,body{ margin:0; height:100%; font-family:'Segoe UI',Tahoma,sans-serif; background:radial-gradient(ellipse at 50% 34%,#0a1226 0%,#05070f 62%,#02040a 100%); color:#e6ecf7; overflow:hidden; }
#nm-netbg{ z-index:0 !important; opacity:.85; }
#nd{ position:fixed; inset:0; z-index:1; }
#ndgl{ position:absolute; inset:0; display:block; cursor:grab; background:transparent; }
#ndgl.drag{ cursor:grabbing; }
#ndtop{ position:absolute; top:16px; left:18px; right:18px; z-index:5; display:flex; align-items:center; gap:11px; flex-wrap:wrap; pointer-events:none; }
#ndtop > *{ pointer-events:auto; }
.brand{ font-size:20px; font-weight:900; letter-spacing:2px; background:linear-gradient(90deg,#39e1ff,#b06bff); -webkit-background-clip:text; background-clip:text; color:transparent; }
.brand small{ display:block; font-size:9px; letter-spacing:4px; color:#7f9dc8; -webkit-text-fill-color:#7f9dc8; }
select.rig,.tin,.tbtn{ background:rgba(17,26,43,.72); color:#dbe6f5; border:1px solid var(--bd); border-radius:10px; padding:9px 13px; font-size:13px; cursor:pointer; backdrop-filter:blur(8px); }
.tin{ cursor:text; width:190px; } .tbtn:hover{ border-color:var(--cy); } a.tbtn{ text-decoration:none; }
.tbtn.go{ background:linear-gradient(90deg,rgba(57,225,255,.22),rgba(176,107,255,.22)); border-color:rgba(57,225,255,.55); font-weight:700; }
/* verdict banner */
#ndverd{ position:absolute; top:70px; left:50%; transform:translateX(-50%); z-index:4; max-width:min(760px,92vw); text-align:center; padding:14px 22px; border-radius:16px; background:rgba(9,14,28,.55); border:1px solid var(--bd); backdrop-filter:blur(10px); display:none; }
#ndverd.on{ display:block; }
#ndverd .vt{ font-size:clamp(16px,2.2vw,24px); font-weight:800; }
#ndverd .vd{ font-size:13px; color:#c3d4ec; margin-top:6px; line-height:1.55; }
#ndverd .vn{ font-size:12px; color:#8fb0dd; margin-top:8px; font-style:italic; }
#ndverd.ok{ border-color:rgba(46,230,110,.45);} #ndverd.ok .vt{ color:#7dffb0; }
#ndverd.warn{ border-color:rgba(240,169,44,.5);} #ndverd.warn .vt{ color:#ffd98a; }
#ndverd.crit{ border-color:rgba(255,77,109,.55);} #ndverd.crit .vt{ color:#ffb3c2; }
/* projected hop labels */
#ndlabels{ position:absolute; inset:0; z-index:2; pointer-events:none; }
.hop{ position:absolute; transform:translate(-50%,-50%); text-align:center; white-space:nowrap; will-change:transform; }
.hop .hn{ font-size:12.5px; font-weight:800; letter-spacing:.5px; color:#eaf3ff; text-shadow:0 1px 6px #000,0 0 12px rgba(0,0,0,.8); }
.hop .hip{ font-size:10px; color:rgba(150,180,220,.7); }
.hop .hp{ font-size:22px; font-weight:900; font-variant-numeric:tabular-nums; line-height:1.1; margin-top:2px; text-shadow:0 2px 8px #000; }
.hop .hs{ font-size:11px; color:rgba(180,205,240,.8); }
.hop .hn2{ font-size:10.5px; color:rgba(120,150,255,.85); margin-top:1px; }
.hop.c-good .hp{ color:#2ee66e } .hop.c-ok .hp{ color:#39e1ff } .hop.c-warn .hp{ color:#f0a92c } .hop.c-crit .hp{ color:#ff4d6d; text-shadow:0 0 16px rgba(255,77,109,.6) }
/* bottom tiles */
#ndtiles{ position:absolute; bottom:26px; left:50%; transform:translateX(-50%); z-index:4; display:none; gap:12px; flex-wrap:wrap; justify-content:center; padding:0 12px; max-width:96vw; }
#ndtiles.on{ display:flex; }
.tile{ background:rgba(8,13,26,.55); border:1px solid var(--bd); border-radius:14px; padding:10px 16px; text-align:center; min-width:104px; backdrop-filter:blur(9px); }
.tile .n{ font-size:23px; font-weight:900; font-variant-numeric:tabular-nums; } .tile .l{ font-size:9.5px; letter-spacing:2px; text-transform:uppercase; color:#8fb0dd; margin-top:2px; }
.tile .n.c-good{ color:#2ee66e } .tile .n.c-ok{ color:#39e1ff } .tile .n.c-warn{ color:#f0a92c } .tile .n.c-crit{ color:#ff4d6d }
#ndhint{ position:absolute; bottom:6px; left:0; right:0; text-align:center; font-size:11px; color:rgba(140,165,200,.5); z-index:3; pointer-events:none; }
#ndadd{ position:absolute; top:64px; left:18px; z-index:7; width:300px; background:rgba(9,14,28,.95); border:1px solid rgba(120,150,255,.28); border-radius:14px; padding:16px 18px; backdrop-filter:blur(12px); box-shadow:0 14px 44px rgba(0,0,0,.5); display:none; }
#ndadd.on{ display:block; }
/* history panel */
#ndhist{ position:absolute; left:0; right:0; bottom:0; z-index:6; background:rgba(6,10,20,.93); border-top:1px solid rgba(120,150,255,.22); backdrop-filter:blur(12px); padding:14px 20px 18px; transform:translateY(105%); transition:transform .3s cubic-bezier(.2,.8,.2,1); }
#ndhist.on{ transform:translateY(0); }
#ndhist .hh{ display:flex; justify-content:space-between; align-items:center; font-size:14px; font-weight:700; color:#dfeeff; margin-bottom:8px; } #ndhist .hh small{ color:#8fb0dd; font-weight:400; font-size:12px; margin-left:8px; }
#ndhist canvas{ width:100%; height:120px; display:block; background:rgba(8,14,28,.4); border:1px solid rgba(120,150,255,.12); border-radius:10px; }
#ndhist .hlbl{ font-size:11px; color:#8fb0dd; margin:4px 0 12px; }
#ndload{ position:absolute; inset:0; z-index:9; display:none; align-items:center; justify-content:center; flex-direction:column; gap:16px; background:rgba(4,6,13,.82); }
#ndload .sp{ width:54px; height:54px; border:3px solid rgba(120,150,255,.2); border-top-color:#39e1ff; border-radius:50%; animation:spin 1s linear infinite; }
@keyframes spin{ to{ transform:rotate(360deg) } }
#ndload .m{ font-size:14px; color:#8fb0dd; letter-spacing:.5px; text-align:center; max-width:420px; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php nm_gamers_hub_pill(); ?>
<div id="nd">
  <canvas id="ndgl"></canvas>
  <div id="ndtop">
    <div class="brand">◈ NEURU<small>CONNECTION DOCTOR</small></div>
    <select class="rig" id="rig"><option value="">Loading rigs…</option></select>
    <select class="rig" id="tgtSel" style="max-width:240px" onchange="onTgt()" title="Pick a server from your Game Server Status list, auto-detect the running game, or add your own"><option value="">🎮 Auto-detect running game</option></select>
    <input class="tin" id="tgt" placeholder="host or IP" style="display:none" title="Custom host / IP to test">
    <button class="tbtn go" id="runBtn" onclick="runDiag()"><i class="fa-solid fa-wave-square"></i> Run diagnosis</button>
    <button class="tbtn" id="histBtn" onclick="toggleHist()" title="Show the recorded history — see exactly when it lagged"><i class="fa-solid fa-chart-line"></i> History</button>
    <select class="rig" id="hrs" style="width:auto" onchange="if($('#ndhist').classList.contains('on'))loadHistory()"><option value="3">3h</option><option value="24" selected>24h</option><option value="168">7d</option><option value="720">30d</option></select>
    <button class="tbtn" onclick="toggleFs()" title="Fullscreen"><i class="fa-solid fa-expand"></i></button>
    <a class="tbtn" href="gaming.php" title="Back to Game Mode"><i class="fa-solid fa-gamepad"></i></a>
  </div>
  <div id="ndadd">
    <div style="font-weight:700;margin-bottom:9px;font-size:14px">➕ Add a game server</div>
    <input class="tin" id="ad-name" placeholder="name (e.g. My CS2 server)" style="width:100%;margin-bottom:7px">
    <input class="tin" id="ad-host" placeholder="host or IP (e.g. play.hypixel.net)" style="width:100%;margin-bottom:7px">
    <input class="tin" id="ad-port" placeholder="port (optional — 25565 MC · 27015 CS2)" style="width:100%;margin-bottom:10px">
    <button class="tbtn go" onclick="addServer(this)">Save</button> <button class="tbtn" onclick="document.getElementById('ndadd').classList.remove('on')">Cancel</button>
    <div id="ad-msg" style="font-size:12px;color:#8fb0dd;margin-top:8px"></div>
  </div>
  <div id="ndverd"><div class="vt" id="verdT"></div><div class="vd" id="verdD"></div><div class="vn" id="verdN"></div></div>
  <div id="ndlabels"></div>
  <div id="ndtiles"></div>
  <div id="ndhint">drag to orbit · scroll to zoom · YOU → Router → ISP → Internet → Game · measured from your PC and the NOC</div>
  <div id="ndhist">
    <div class="hh"><span><i class="fa-solid fa-chart-line"></i> Connection history <small id="histSub"></small></span><button class="tbtn" style="padding:5px 10px" onclick="toggleHist()">✕</button></div>
    <canvas id="histPing"></canvas>
    <div class="hlbl">Ping (ms) + jitter band · red bands = when NEURU flagged a problem</div>
    <canvas id="histLoss"></canvas>
    <div class="hlbl">Packet loss (%)</div>
  </div>
  <div id="ndload"><div class="sp"></div><div class="m" id="ndloadMsg">Measuring your connection over SSH…<br>tracing the path + pinging each hop from your PC and the NOC (~20s)</div></div>
</div>
<script>
const $=s=>document.querySelector(s);
function esc(s){ return (''+s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
let RIG=0, DATA=null;
// a 'filtered' hop (0 ping replies) just doesn't answer ICMP — it's NEUTRAL, never red
function grade(p){ if(!p||!p.ok||p.filtered)return ''; const ms=p.avg,j=p.jitter,l=p.loss; if(l>=3||j>=25||ms>=140)return 'crit'; if(l>0||j>=12||ms>=100)return 'warn'; if(ms!=null&&ms<40&&(j==null||j<6))return 'good'; return 'ok'; }
const GCOL={good:0x2ee66e,ok:0x39e1ff,warn:0xf0a92c,crit:0xff4d6d};

async function loadRigs(){ try{ const r=await fetch('?api=rigs').then(r=>r.json()); const s=$('#rig');
  if(!r.ok||!r.rigs.length){ s.innerHTML='<option value="">No Windows rigs — add one in Windows Monitor</option>'; return; }
  s.innerHTML='<option value="">— pick your rig —</option>'+r.rigs.map(x=>`<option value="${x.id}">${esc(x.name)} (${esc(x.ip)})</option>`).join('');
  s.onchange=()=>{ RIG=+s.value||0; }; }catch(e){} }
async function loadServers(){ try{ const r=await fetch('?api=servers').then(r=>r.json()); if(!r.ok)return; const s=$('#tgtSel');
  let h='<option value="">🎮 Auto-detect running game</option>';
  if((r.custom||[]).length) h+='<optgroup label="My servers">'+r.custom.map(x=>`<option value="${esc(x.host)}:${x.port}">${esc(x.name)} (${esc(x.host)})</option>`).join('')+'</optgroup>';
  if((r.official||[]).length) h+='<optgroup label="Popular game services">'+r.official.map(x=>`<option value="${esc(x.host)}:${x.port}">${esc(x.name)}</option>`).join('')+'</optgroup>';
  h+='<option value="__custom__">✎ Custom host / IP…</option><option value="__add__">➕ Add a server…</option>';
  s.innerHTML=h;
}catch(e){} }
function onTgt(){ const v=$('#tgtSel').value; $('#tgt').style.display = v==='__custom__'?'inline-block':'none';
  if(v==='__add__'){ $('#ndadd').classList.add('on'); $('#tgtSel').value=''; } }
function curTarget(){ const v=$('#tgtSel').value; if(v==='__custom__') return $('#tgt').value.trim(); if(v==='__add__'||v==='') return ''; return v; }
async function addServer(btn){ const host=$('#ad-host').value.trim(); if(!host){ $('#ad-msg').textContent='host is required'; return; } btn.disabled=true; $('#ad-msg').textContent='saving…';
  try{ const fd=new FormData(); fd.append('name',$('#ad-name').value); fd.append('host',host); fd.append('port',$('#ad-port').value); fd.append('proto','tcp'); fd.append('game','Custom');
    const r=await fetch('?api=server_add',{method:'POST',body:fd}).then(r=>r.json());
    if(r.ok){ $('#ad-msg').textContent='saved ✓'; $('#ad-name').value=''; $('#ad-host').value=''; $('#ad-port').value=''; await loadServers(); $('#tgtSel').value=host+':'+($('#ad-port').value||443); setTimeout(()=>$('#ndadd').classList.remove('on'),700); }
    else $('#ad-msg').textContent='error: '+(r.error||'?');
  }catch(e){ $('#ad-msg').textContent='error'; } btn.disabled=false; }
async function runDiag(){ RIG=+$('#rig').value||0; if(!RIG){ alert('Pick a rig first'); return; }
  $('#ndload').style.display='flex'; const b=$('#runBtn'); b.disabled=true;
  try{ const tgt=encodeURIComponent(curTarget());
    const r=await fetch('?api=run&rig='+RIG+'&target='+tgt).then(r=>r.json());
    $('#ndload').style.display='none'; b.disabled=false;
    if(!r.ok){ $('#ndloadMsg').textContent='✖ '+(r.error||'failed'); $('#ndload').style.display='flex'; setTimeout(()=>$('#ndload').style.display='none',2200); return; }
    DATA=r; buildPath(r); showVerdict(r.verdict); showTiles(r);
    if($('#ndhist').classList.contains('on')) loadHistory();
  }catch(e){ $('#ndload').style.display='none'; b.disabled=false; }
}
function toggleFs(){ if(!document.fullscreenElement){ const el=document.documentElement; (el.requestFullscreen||el.webkitRequestFullscreen||function(){}).call(el);} else { (document.exitFullscreen||document.webkitExitFullscreen||function(){}).call(document);} }

function showVerdict(v){ if(!v)return; const el=$('#ndverd'); el.className='on '+(v.level||'ok'); $('#verdT').textContent=v.title||''; $('#verdD').textContent=v.detail||''; $('#verdN').textContent=v.note||''; }
function showTiles(r){ const g=r.hops.find(h=>h.id==='game')||r.hops.find(h=>h.id==='internet'); const p=(g&&g.pc)||{}; const gr=grade(p);
  const T=[['PING',p.avg!=null?Math.round(p.avg):'—','ms',gr],['JITTER',p.jitter!=null?Math.round(p.jitter):'—','ms',p.jitter>=25?'crit':p.jitter>=12?'warn':'ok'],
    ['LOSS',p.loss!=null?p.loss:'—','%',p.loss>=3?'crit':p.loss>0?'warn':'good'],['STABILITY',p.stability!=null?p.stability:'—','%',p.stability>=90?'good':p.stability>=75?'ok':p.stability>=50?'warn':'crit']];
  $('#ndtiles').className='on'; $('#ndtiles').innerHTML=T.map(t=>`<div class="tile"><div class="n c-${t[3]||'ok'}">${t[1]}<span style="font-size:11px;color:#8fb0dd"> ${t[2]}</span></div><div class="l">${t[0]}</div></div>`).join(''); }

// ═══════════ History (monitoring) — see EXACTLY when it lagged ═══════════
function toggleHist(){ const p=$('#ndhist'); const on=!p.classList.contains('on'); p.classList.toggle('on',on); $('#histBtn').classList.toggle('go',on); if(on)loadHistory(); }
async function loadHistory(){ const rig=+$('#rig').value||RIG; if(!rig){ $('#histSub').textContent='— pick a rig first'; return; }
  const hrs=$('#hrs').value; try{ const r=await fetch('?api=history&rig='+rig+'&hours='+hrs).then(r=>r.json()); if(!r.ok)return; const H=r.hist||[];
    $('#histSub').textContent = H.length?(H.length+' samples · last '+({3:'3h',24:'24h',168:'7 days',720:'30 days'}[hrs]||hrs+'h')):'no history yet — runs + the monitor cron fill this over time';
    drawPingChart($('#histPing'),H); drawLossChart($('#histLoss'),H);
  }catch(e){} }
function _cv(c){ const dpr=Math.min(2,devicePixelRatio),w=c.clientWidth,h=c.clientHeight; c.width=w*dpr; c.height=h*dpr; const x=c.getContext('2d'); x.setTransform(dpr,0,0,dpr,0,0); x.clearRect(0,0,w,h); return {x,w,h}; }
function drawPingChart(cv,H){ const {x,w,h}=_cv(cv); if(!H.length){ x.fillStyle='#6f8bb0'; x.font='12px sans-serif'; x.fillText('No history yet — run a diagnosis, or enable the monitor cron to auto-record.',14,h/2); return; }
  const pad=30,pw=w-pad*2,ph=h-20,t0=H[0].t,t1=H[H.length-1].t||t0+1,span=Math.max(1,t1-t0);
  const maxP=Math.max(60,...H.map(d=>(d.ping||0)+(d.jitter||0)))*1.15;
  const X=t=>pad+pw*((t-t0)/span), Y=v=>10+ph*(1-Math.min(1,v/maxP));
  x.strokeStyle='rgba(120,150,255,.1)'; x.fillStyle='#5f7799'; x.font='9px sans-serif';
  for(let i=0;i<=3;i++){ const yy=10+ph*i/3; x.beginPath();x.moveTo(pad,yy);x.lineTo(w-pad,yy);x.stroke(); x.fillText(Math.round(maxP*(1-i/3))+'ms',2,yy+3); }
  H.forEach((d,i)=>{ if(d.lvl==='crit'){ const x0=X(d.t),x1=i<H.length-1?X(H[i+1].t):x0+3; x.fillStyle='rgba(255,77,109,.13)'; x.fillRect(x0,10,Math.max(2,x1-x0),ph); } });
  // jitter band
  x.beginPath(); let st=false; H.forEach(d=>{ if(d.ping==null)return; const px=X(d.t),py=Y(Math.max(0,d.ping-(d.jitter||0))); st?x.lineTo(px,py):x.moveTo(px,py); st=true; });
  for(let i=H.length-1;i>=0;i--){ const d=H[i]; if(d.ping==null)continue; x.lineTo(X(d.t),Y(d.ping+(d.jitter||0))); } x.closePath(); x.fillStyle='rgba(57,225,255,.12)'; x.fill();
  // ping line
  x.beginPath(); st=false; H.forEach(d=>{ if(d.ping==null)return; const px=X(d.t),py=Y(d.ping); st?x.lineTo(px,py):x.moveTo(px,py); st=true; }); x.strokeStyle='#39e1ff'; x.lineWidth=1.6; x.stroke();
  x.fillStyle='#5f7799'; x.textAlign='center'; [0,.5,1].forEach(f=>{ const dt=new Date((t0+span*f)*1000); x.fillText(dt.getHours()+':'+('0'+dt.getMinutes()).slice(-2),pad+pw*f,h-4); }); x.textAlign='left';
}
function drawLossChart(cv,H){ const {x,w,h}=_cv(cv); if(!H.length)return; const pad=30,pw=w-pad*2,ph=h-20,t0=H[0].t,t1=H[H.length-1].t||t0+1,span=Math.max(1,t1-t0),maxL=Math.max(5,...H.map(d=>d.loss||0)),X=t=>pad+pw*((t-t0)/span);
  x.strokeStyle='rgba(120,150,255,.1)'; x.fillStyle='#5f7799'; x.font='9px sans-serif';
  for(let i=0;i<=2;i++){ const yy=10+ph*i/2; x.beginPath();x.moveTo(pad,yy);x.lineTo(w-pad,yy);x.stroke(); x.fillText(Math.round(maxL*(1-i/2))+'%',2,yy+3); }
  H.forEach(d=>{ if(!d.loss)return; const px=X(d.t),bh=ph*Math.min(1,d.loss/maxL); x.fillStyle=d.loss>=3?'#ff4d6d':'#f0a92c'; x.fillRect(px-1.5,10+ph-bh,3,bh); });
}
// ═══════════ WebGL data highway ═══════════
let RN,SC,CAM,NODES=[],LINKS=[],ctl={az:0.0,pol:0.12,rad:34,taz:0.0,tpol:0.12,trad:34,drag:false,lx:0,ly:0};
const DOT=(()=>{ const c=document.createElement('canvas'); c.width=c.height=48; const x=c.getContext('2d'); const g=x.createRadialGradient(24,24,0,24,24,24); g.addColorStop(0,'#fff'); g.addColorStop(.4,'rgba(255,255,255,.85)'); g.addColorStop(1,'rgba(255,255,255,0)'); x.fillStyle=g; x.beginPath(); x.arc(24,24,24,0,7); x.fill(); return new THREE.CanvasTexture(c); })();
function initGL(){ const cv=$('#ndgl'); RN=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true}); RN.setPixelRatio(Math.min(2,devicePixelRatio)); RN.setSize(innerWidth,innerHeight);
  SC=new THREE.Scene(); SC.fog=new THREE.FogExp2(0x04060d,0.008); CAM=new THREE.PerspectiveCamera(56,innerWidth/innerHeight,.1,400);
  SC.add(new THREE.AmbientLight(0x5a6b9a,0.9)); const d=new THREE.DirectionalLight(0xbcd4ff,1); d.position.set(6,20,14); SC.add(d);
  bindControls(cv); addEventListener('resize',()=>{ RN.setSize(innerWidth,innerHeight); CAM.aspect=innerWidth/innerHeight; CAM.updateProjectionMatrix(); }); loop(); }
function bindControls(cv){ const c=ctl;
  const dn=e=>{ c.drag=true; const p=e.touches?e.touches[0]:e; c.lx=p.clientX; c.ly=p.clientY; cv.classList.add('drag'); };
  const mv=e=>{ if(!c.drag)return; const p=e.touches?e.touches[0]:e; c.taz-=(p.clientX-c.lx)*0.005; c.tpol=Math.max(-0.4,Math.min(1.2,c.tpol+(p.clientY-c.ly)*0.005)); c.lx=p.clientX; c.ly=p.clientY; if(e.touches&&e.cancelable)e.preventDefault(); };
  const up=()=>{ c.drag=false; cv.classList.remove('drag'); };
  cv.addEventListener('mousedown',dn); addEventListener('mousemove',mv); addEventListener('mouseup',up);
  cv.addEventListener('touchstart',dn,{passive:false}); cv.addEventListener('touchmove',mv,{passive:false}); addEventListener('touchend',up);
  cv.addEventListener('wheel',e=>{ c.trad=Math.max(16,Math.min(80,c.trad*(1+(e.deltaY>0?0.09:-0.09)))); e.preventDefault(); },{passive:false}); }
function makeNode(col,you){ const g=new THREE.Group();
  const core=new THREE.Mesh(new THREE.IcosahedronGeometry(you?1.2:1.5,1), new THREE.MeshBasicMaterial({color:col,wireframe:true,transparent:true,opacity:.9})); g.add(core);
  const halo=new THREE.Mesh(new THREE.SphereGeometry(you?1.5:1.9,20,20), new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:.14,blending:THREE.AdditiveBlending,depthWrite:false})); g.add(halo);
  const ring=new THREE.Mesh(new THREE.TorusGeometry(you?2.1:2.6,0.05,8,48), new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:.6})); ring.rotation.x=Math.PI/2.3; g.add(ring);
  g.userData={core,halo,ring}; return g; }
function makeLink(a,b,col){ const N=22,geo=new THREE.BufferGeometry(),pos=new Float32Array(N*3); geo.setAttribute('position',new THREE.BufferAttribute(pos,3));
  const pts=new THREE.Points(geo,new THREE.PointsMaterial({color:col,size:.42,map:DOT,transparent:true,opacity:.92,depthWrite:false,blending:THREE.AdditiveBlending})); SC.add(pts);
  const line=new THREE.Line(new THREE.BufferGeometry().setFromPoints([a,b]), new THREE.LineBasicMaterial({color:col,transparent:true,opacity:.28})); SC.add(line);
  return {pts,line,a,b,N,off:Math.random(),col}; }
function clearScene(){ NODES.forEach(n=>{ SC.remove(n.grp); n.el.remove(); }); NODES=[]; LINKS.forEach(l=>{ SC.remove(l.pts); SC.remove(l.line); }); LINKS=[]; }
function buildPath(r){ clearScene();
  // origin YOU + the hops
  const seq=[{id:'you',label:'YOU (your PC)',ip:'',pc:{ok:true,avg:0},you:1}].concat(r.hops);
  const n=seq.length, span=32, x0=-span/2;
  seq.forEach((hp,i)=>{ const p=hp.pc||{}, noc=hp.noc||{}; const filt=!hp.you&&p&&p.filtered; const gr=hp.you?'':grade(hp.pc);
    const col=hp.you?0x9fd0ff:(filt?0x8fa8c8:(GCOL[gr]||0x39e1ff));   // filtered hop = neutral grey, never red
    const grp=makeNode(col,!!hp.you); const x=x0+span*(i/(n-1)); grp.position.set(x, Math.sin(i/(n-1)*Math.PI)*2.2, 0); SC.add(grp);
    const el=document.createElement('div'); el.className='hop'; el.innerHTML='<div class="hn"></div><div class="hip"></div><div class="hp"></div><div class="hs"></div><div class="hn2"></div>'; $('#ndlabels').appendChild(el);
    el.querySelector('.hn').textContent=hp.label||hp.id;
    el.querySelector('.hip').textContent=hp.ip||'';
    el.querySelector('.hp').textContent = hp.you?'★':(filt?'⋯':(p.ok&&p.avg!=null?Math.round(p.avg)+'ms':(hp.ip?'—':'n/a')));
    el.querySelector('.hs').textContent = hp.you?'origin':(filt?'no ping reply (normal for routers)':((p.ok)?('±'+(p.jitter!=null?Math.round(p.jitter):0)+'ms · '+(p.loss||0)+'% loss'):''));
    el.querySelector('.hn2').textContent = (noc.ok&&noc.avg!=null)?('NOC '+Math.round(noc.avg)+'ms'):'';
    el.className='hop'+(gr?(' c-'+gr):'');
    NODES.push({grp,el,x,y:grp.position.y,hp,gr}); });
  // links coloured by the DOWNSTREAM hop's health
  for(let i=0;i<NODES.length-1;i++){ const a=NODES[i].grp.position.clone(), b=NODES[i+1].grp.position.clone(); const gr=NODES[i+1].gr; LINKS.push(makeLink(a,b,GCOL[gr]||0x39e1ff)); }
}
function loop(){ requestAnimationFrame(loop); if(!RN)return;
  ctl.az+=(ctl.taz-ctl.az)*0.1; ctl.pol+=(ctl.tpol-ctl.pol)*0.1; ctl.rad+=(ctl.trad-ctl.rad)*0.1;
  CAM.position.set(Math.sin(ctl.az)*Math.cos(ctl.pol)*ctl.rad, 2+Math.sin(ctl.pol)*ctl.rad, Math.cos(ctl.az)*Math.cos(ctl.pol)*ctl.rad); CAM.lookAt(0,1.5,0);
  const now=Date.now()*0.001;
  NODES.forEach((nd,i)=>{ const c=nd.grp.userData; c.core.rotation.y+=0.01; c.ring.rotation.z+=0.006;
    const pulse=1+(nd.gr==='crit'?Math.abs(Math.sin(now*4))*0.25:Math.sin(now*1.5+i)*0.05); c.halo.scale.setScalar(pulse);
    c.halo.material.opacity=nd.gr==='crit'?(0.12+Math.abs(Math.sin(now*4))*0.2):0.14; });
  // flow particles — speed inversely with latency (worse link = choppier/slower)
  LINKS.forEach((l,i)=>{ const nd=NODES[i+1]; const p=nd&&nd.hp&&nd.hp.pc||{}; const q=p.avg!=null?Math.max(0.1,1-Math.min(1,p.avg/160)):0.7; const spd=0.05+q*0.5;
    l.off=(l.off+spd*0.016)%1; const pos=l.pts.geometry.attributes.position, arr=pos.array;
    for(let k=0;k<l.N;k++){ let f=(l.off+k/l.N)%1; arr[k*3]=l.a.x+(l.b.x-l.a.x)*f; arr[k*3+1]=l.a.y+(l.b.y-l.a.y)*f+Math.sin(now*3+k)*0.05; arr[k*3+2]=l.a.z+(l.b.z-l.a.z)*f; } pos.needsUpdate=true; });
  // project labels
  const W=innerWidth,H=innerHeight,v=new THREE.Vector3();
  NODES.forEach(nd=>{ v.setFromMatrixPosition(nd.grp.matrixWorld); v.y+=2.4; v.project(CAM); const px=(v.x*0.5+0.5)*W, py=(-v.y*0.5+0.5)*H;
    nd.el.style.opacity=v.z<1?'1':'0'; nd.el.style.transform='translate(-50%,-50%) translate('+px.toFixed(1)+'px,'+py.toFixed(1)+'px)'; });
  RN.render(SC,CAM);
}
addEventListener('keydown',e=>{ if(e.key==='Escape'&&document.fullscreenElement)document.exitFullscreen(); });
try{ if(window.NMNetBG) NMNetBG.init({color:'#4da3ff',density:0.85,linkDist:150,mouseDist:180}); }catch(e){}
initGL(); loadRigs(); loadServers();
</script>
</body></html>
