<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Geo Map NOC video-wall. Full-screen, READ-ONLY kiosk: nodes plotted on
// a world map with animated traffic "comets" on links, NetFlow arcs, and live
// incident/down/traffic/container/NetFlow panels. Reuses net_mon_map.php?api=topo
// for the topology+traffic. RBAC: 'geomap' (the 'dashboard' role lands here).
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_geomap.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'geomap')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=geomap'); exit;
}
nm_geomap_ensure($conn);

if ($api === 'geo') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok'=>true] + nm_geomap_payload($conn));
    exit;
}

log_user_action($conn,'view_page','geomap.php');
$me = htmlspecialchars($_SESSION['username'] ?? '');
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NEURU — NOC Geo Wall</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<script src="/leaflet.min.js"></script>
<script src="/nm_wallwidgets.js"></script>
<style>
:root{ --bg:#05080e; --glass:rgba(255,255,255,.05); --border:rgba(255,255,255,.10); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cyan:#36e3d0; }
*,*::before,*::after{ box-sizing:border-box; } html,body{ height:100%; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:var(--bg); color:#e6e9ee; overflow:hidden; }
#wall{ display:grid; grid-template-rows:54px 1fr; height:100vh; }
#bar{ display:flex; align-items:center; gap:18px; padding:0 18px; background:linear-gradient(90deg,#0a1018,#0d1622); border-bottom:1px solid var(--border); }
#bar .logo{ font-weight:800; font-size:18px; letter-spacing:1px; color:#fff; display:flex; align-items:center; gap:9px; }
#bar .logo i{ color:var(--accent); }
.chip{ display:flex; align-items:center; gap:7px; font-size:13px; background:var(--glass); border:1px solid var(--border); padding:5px 12px; border-radius:20px; }
.chip b{ font-size:15px; } .chip.ok b{ color:var(--ok);} .chip.crit b{ color:var(--crit);} .chip.warn b{ color:var(--warn);} .chip.cyan b{ color:var(--cyan);}
#bar .sp{ margin-left:auto; } #clock{ font-variant-numeric:tabular-nums; font-size:15px; color:#cfd6df; }
.logout{ color:#8a909a; text-decoration:none; font-size:13px; } .logout:hover{ color:#f0a59d; }
.wallbtn{ background:var(--glass); border:1px solid var(--border); color:#cfd6df; border-radius:8px; padding:5px 10px; font-size:13px; cursor:pointer; } .wallbtn:hover{ border-color:var(--accent); color:#fff; }
#main{ display:grid; grid-template-columns:330px 1fr 350px; gap:10px; padding:10px; min-height:0; }
.col{ display:flex; flex-direction:column; gap:10px; min-height:0; overflow:hidden; }
.panel{ background:var(--glass); backdrop-filter:blur(14px); border:1px solid var(--border); border-radius:12px; padding:12px 14px; display:flex; flex-direction:column; min-height:0; }
.panel h3{ margin:0 0 9px; font-size:11px; text-transform:uppercase; letter-spacing:1.4px; color:var(--accent); display:flex; justify-content:space-between; align-items:center; }
.panel h3 .cnt{ color:#8a909a; font-weight:600; } .panel .body{ overflow:auto; min-height:0; }
.panel.grow{ flex:1; } .panel.grow .body{ flex:1; }
#mapwrap{ position:relative; border-radius:14px; overflow:hidden; border:1px solid var(--border); }
#map{ position:absolute; inset:0; background:#070b12; } .leaflet-container{ background:#070b12; font-family:inherit; }
#fx{ position:absolute; inset:0; pointer-events:none; z-index:450; }
.row{ display:flex; align-items:center; gap:9px; padding:7px 4px; border-bottom:1px solid rgba(255,255,255,.05); font-size:12.5px; }
.row:last-child{ border-bottom:none; } .dot{ width:9px;height:9px;border-radius:50%;flex:0 0 auto; } .mono{ font-family:monospace; } .muted{ color:#7c828c; }
.sev-critical{ color:#f0a59d;} .sev-warning{ color:#f0c674;} .sev-info{ color:#9fbfe0;}
.bar-bg{ flex:1; height:7px; background:rgba(255,255,255,.07); border-radius:5px; overflow:hidden; } .bar-bg>i{ display:block; height:100%; background:linear-gradient(90deg,#2ecc71,#4da3ff); }
.k{ font-weight:700; } .pill{ font-size:10px; padding:1px 7px; border-radius:12px; background:rgba(77,163,255,.14); color:#bcd; }
.donut{ display:flex; gap:14px; align-items:center; } .donut .big{ font-size:30px; font-weight:800; }
.empty{ color:#5b6470; font-size:12px; text-align:center; padding:18px 0; }
.legend{ position:absolute; bottom:8px; left:8px; z-index:500; background:rgba(5,8,14,.7); border:1px solid var(--border); border-radius:8px; padding:6px 10px; font-size:11px; display:flex; gap:12px; }
.legend span{ display:flex; align-items:center; gap:5px; }
</style></head><body>
<div id="wall">
  <div id="bar">
    <div class="logo"><i class="fa-solid fa-earth-americas"></i> NEURU <span style="font-weight:400;color:#8a909a;font-size:13px;">NOC Geo Wall</span></div>
    <div class="chip ok"><i class="fa-solid fa-circle-check"></i> up <b id="c-up">—</b></div>
    <div class="chip crit"><i class="fa-solid fa-circle-xmark"></i> down <b id="c-down">—</b></div>
    <div class="chip warn"><i class="fa-solid fa-triangle-exclamation"></i> incidents <b id="c-inc">—</b></div>
    <div class="chip cyan"><i class="fa-brands fa-docker"></i> containers <b id="c-cont">—</b></div>
    <div class="chip"><i class="fa-solid fa-shield-halved" style="color:#c084fc"></i> WG peers <b id="c-wg" style="color:#c084fc">—</b></div>
    <div class="sp"></div>
    <div id="clock">—</div>
    <button id="fsbtn" class="wallbtn" title="Toggle full screen" onclick="toggleFull()"><i class="fa-solid fa-expand"></i></button>
    <a class="logout" href="logout.php" title="Logout"><i class="fa-solid fa-right-from-bracket"></i> <?= $me ?></a>
  </div>
  <div id="main">
    <!-- LEFT -->
    <div class="col">
      <div class="panel grow"><h3><span><i class="fa-solid fa-triangle-exclamation"></i> Incidents to attend</span><span class="cnt" id="n-inc">0</span></h3><div class="body" id="p-inc"></div></div>
      <div class="panel grow"><h3><span><i class="fa-solid fa-plug-circle-xmark"></i> Nodes down</span><span class="cnt" id="n-down">0</span></h3><div class="body" id="p-down"></div></div>
    </div>
    <!-- MAP -->
    <div id="mapwrap"><div id="map"></div><canvas id="fx"></canvas>
      <div class="legend"><span><i class="fa-solid fa-circle" style="color:#2ecc71"></i> up</span><span><i class="fa-solid fa-circle" style="color:#e74c3c"></i> down</span>
        <span><span style="width:16px;height:2px;background:#4da3ff;display:inline-block"></span> traffic</span><span><span style="width:16px;height:2px;background:#36e3d0;display:inline-block"></span> NetFlow</span></div>
    </div>
    <!-- RIGHT -->
    <div class="col">
      <div class="panel"><h3><span><i class="fa-brands fa-docker"></i> Containers</span></h3><div id="p-cont" class="donut"><span class="muted">—</span></div></div>
      <div class="panel grow"><h3><span><i class="fa-solid fa-gauge-high"></i> Top traffic</span></h3><div class="body" id="p-top"></div></div>
      <div class="panel grow"><h3><span><i class="fa-solid fa-fire"></i> NetFlow talkers</span><span class="cnt" id="n-nf">0</span></h3><div class="body" id="p-nf"></div></div>
    </div>
  </div>
</div>
<script>
const REFRESH=20000;
let map, fx, ctx, NODES={}, LINKS=[], ARCS=[], WGPEERS=[], GROUPS={}, EXPANDED=new Set(), ORIGIN=null, maxLoad=1, dirty=true;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function fmtR(v){ v=+v||0; if(v>=1e9)return (v/1e9).toFixed(1)+'G'; if(v>=1e6)return (v/1e6).toFixed(1)+'M'; if(v>=1e3)return (v/1e3).toFixed(1)+'k'; return v.toFixed(0); }
function clock(){ const d=new Date(); document.getElementById('clock').textContent=d.toLocaleTimeString(); }
setInterval(clock,1000); clock();

// Full-screen the whole wall (kiosk / NOC monitor). Refit the map + fx canvas after.
function toggleFull(){
  const el=document.documentElement;
  if(!document.fullscreenElement){ (el.requestFullscreen||el.webkitRequestFullscreen||function(){}).call(el); }
  else { (document.exitFullscreen||document.webkitExitFullscreen||function(){}).call(document); }
}
document.addEventListener('fullscreenchange',()=>{
  const fs=!!document.fullscreenElement;
  const b=document.querySelector('#fsbtn i'); if(b) b.className='fa-solid '+(fs?'fa-compress':'fa-expand');
  setTimeout(()=>{ if(typeof map!=='undefined' && map) map.invalidateSize(); window.dispatchEvent(new Event('resize')); dirty=true; },180);
});

function initMap(){
  map=L.map('map',{worldCopyJump:true,zoomControl:true,attributionControl:false,preferCanvas:true}).setView([18.4,-66.1],7);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{subdomains:'abcd',maxZoom:19}).addTo(map);
  fx=document.getElementById('fx'); ctx=fx.getContext('2d');
  const ro=()=>{ const w=document.getElementById('mapwrap'); fx.width=w.clientWidth; fx.height=w.clientHeight; dirty=true; };
  window.addEventListener('resize',ro); setTimeout(()=>{map.invalidateSize();ro();},150);
  map.on('move zoom moveend zoomend',()=>{dirty=true;});
  // click a multi-node cluster to expand/collapse it (see the individual nodes)
  map.on('click',e=>{
    const cp=e.containerPoint;
    for(const key in GROUPS){ const grp=GROUPS[key]; if(grp.members.length<2)continue;
      const p=map.latLngToContainerPoint([grp.lat,grp.lon]);
      if(Math.hypot(p.x-cp.x,p.y-cp.y) < (EXPANDED.has(key)?16:22)){
        EXPANDED.has(key)?EXPANDED.delete(key):EXPANDED.add(key); dirty=true; return;
      }
    }
  });
  requestAnimationFrame(animate);
}
function P(lat,lon){ const p=map.latLngToContainerPoint([lat,lon]); return [p.x,p.y]; }
function loadColor(t){ t=Math.min(1,t); const r=t<.5?Math.round(46+(243-46)*t*2):243, g=t<.5?Math.round(204-(204-156)*t*2):Math.round(156-(156-76)*(t-.5)*2), b=t<.5?Math.round(113-(113-18)*t*2):Math.round(18+(60-18)*(t-.5)*2); return `rgb(${r},${g},${b})`; }

function animate(ts){
  if(ctx){
    const W=fx.width,H=fx.height; ctx.clearRect(0,0,W,H);
    // ── traffic links + comets ──
    LINKS.forEach(l=>{
      const a=NODES[l.s], b=NODES[l.t]; if(!a||!b||a.lat==null||b.lat==null)return;
      const [x1,y1]=P(a.lat,a.lon),[x2,y2]=P(b.lat,b.lon);
      const load=(l.in+l.out)||0, t=maxLoad?load/maxLoad:0, col=loadColor(t);
      ctx.strokeStyle='rgba(120,150,190,.18)'; ctx.lineWidth=1; ctx.beginPath(); ctx.moveTo(x1,y1); ctx.lineTo(x2,y2); ctx.stroke();
      if(load<=0)return;
      const n=Math.max(1,Math.min(7,Math.round(t*7)+1)), speed=0.00006+t*0.00022, len=Math.hypot(x2-x1,y2-y1);
      for(let i=0;i<n;i++){
        let ph=((ts*speed)+(i/n))%1;
        const x=x1+(x2-x1)*ph, y=y1+(y2-y1)*ph;
        const g=ctx.createRadialGradient(x,y,0,x,y,5); g.addColorStop(0,col); g.addColorStop(1,'rgba(0,0,0,0)');
        ctx.fillStyle=g; ctx.beginPath(); ctx.arc(x,y,5,0,7); ctx.fill();
      }
    });
    // ── NetFlow arcs (origin → external talker) ──
    if(ORIGIN) ARCS.forEach((arc,idx)=>{
      const [x1,y1]=P(ORIGIN.lat,ORIGIN.lon),[x2,y2]=P(arc.lat,arc.lon);
      const mx=(x1+x2)/2, my=(y1+y2)/2-Math.hypot(x2-x1,y2-y1)*0.28;
      ctx.strokeStyle='rgba(54,227,208,.25)'; ctx.lineWidth=1; ctx.beginPath(); ctx.moveTo(x1,y1); ctx.quadraticCurveTo(mx,my,x2,y2); ctx.stroke();
      let ph=((ts*0.00012)+(idx*0.13))%1, mt=1-ph;
      const x=mt*mt*x1+2*mt*ph*mx+ph*ph*x2, y=mt*mt*y1+2*mt*ph*my+ph*ph*y2;
      const g=ctx.createRadialGradient(x,y,0,x,y,4.5); g.addColorStop(0,'#36e3d0'); g.addColorStop(1,'rgba(0,0,0,0)');
      ctx.fillStyle=g; ctx.beginPath(); ctx.arc(x,y,4.5,0,7); ctx.fill();
    });
    const pulse=0.5+0.5*Math.sin(ts*0.004);
    // ── WireGuard tunnels (server → connected peer's public endpoint) + purple peer bulbs ──
    WGPEERS.forEach((p,idx)=>{
      if(p.slat==null||p.lat==null)return;
      const [x1,y1]=P(p.slat,p.slon),[x2,y2]=P(p.lat,p.lon);
      const mx=(x1+x2)/2,my=(y1+y2)/2-Math.hypot(x2-x1,y2-y1)*0.22;
      ctx.strokeStyle='rgba(168,85,247,.22)'; ctx.lineWidth=1; ctx.beginPath(); ctx.moveTo(x1,y1); ctx.quadraticCurveTo(mx,my,x2,y2); ctx.stroke();
      let ph=((ts*0.00014)+(idx*0.17))%1, mt=1-ph;
      const cxp=mt*mt*x1+2*mt*ph*mx+ph*ph*x2, cyp=mt*mt*y1+2*mt*ph*my+ph*ph*y2;
      let g=ctx.createRadialGradient(cxp,cyp,0,cxp,cyp,4); g.addColorStop(0,'#c084fc'); g.addColorStop(1,'rgba(0,0,0,0)');
      ctx.fillStyle=g; ctx.beginPath(); ctx.arc(cxp,cyp,4,0,7); ctx.fill();
      g=ctx.createRadialGradient(x2,y2,0,x2,y2,12); g.addColorStop(0,'#a855f7'); g.addColorStop(1,'rgba(0,0,0,0)');
      ctx.fillStyle=g; ctx.globalAlpha=.6; ctx.beginPath(); ctx.arc(x2,y2,12,0,7); ctx.fill(); ctx.globalAlpha=1;
      ctx.fillStyle='#c084fc'; ctx.beginPath(); ctx.arc(x2,y2,3.5,0,7); ctx.fill();
      ctx.fillStyle='rgba(216,180,254,.85)'; ctx.font='10px Segoe UI'; ctx.textAlign='center'; ctx.fillText(p.name||'',x2,y2+15);
    });
    // ── nodes — clustered by location; click a cluster to expand (spiderfy) ──
    const drawNode=(nd,x,y,dy)=>{
      const col=nd.status==='down'?'#e74c3c':nd.status==='up'?'#2ecc71':'#8a909a';
      const rad=nd.status==='down'?(7+pulse*6):7;
      let g=ctx.createRadialGradient(x,y,0,x,y,rad*2.4); g.addColorStop(0,col); g.addColorStop(1,'rgba(0,0,0,0)');
      ctx.fillStyle=g; ctx.globalAlpha=nd.status==='down'?(.5+pulse*.5):.6; ctx.beginPath(); ctx.arc(x,y,rad*2.4,0,7); ctx.fill();
      ctx.globalAlpha=1; ctx.fillStyle=col; ctx.beginPath(); ctx.arc(x,y,4,0,7); ctx.fill();
      ctx.fillStyle='rgba(230,235,240,.92)'; ctx.font='11px Segoe UI'; ctx.textAlign='center'; ctx.fillText(nd.name||'',x,y+dy);
    };
    for(const key in GROUPS){ const grp=GROUPS[key]; const [cx,cy]=P(grp.lat,grp.lon);
      const members=grp.members.map(id=>NODES[id]).filter(Boolean); if(!members.length)continue;
      if(members.length===1){ drawNode(members[0],cx,cy,18); continue; }
      if(!EXPANDED.has(key)){
        const anyDown=members.some(m=>m.status==='down'), allUp=members.every(m=>m.status==='up');
        const col=anyDown?'#e74c3c':allUp?'#2ecc71':'#f39c12';
        let g=ctx.createRadialGradient(cx,cy,0,cx,cy,22); g.addColorStop(0,col); g.addColorStop(1,'rgba(0,0,0,0)');
        ctx.fillStyle=g; ctx.globalAlpha=.5; ctx.beginPath(); ctx.arc(cx,cy,22,0,7); ctx.fill(); ctx.globalAlpha=1;
        ctx.fillStyle=col; ctx.beginPath(); ctx.arc(cx,cy,12,0,7); ctx.fill();
        ctx.fillStyle='#05080e'; ctx.font='bold 12px Segoe UI'; ctx.textAlign='center'; ctx.textBaseline='middle'; ctx.fillText(members.length,cx,cy); ctx.textBaseline='alphabetic';
        ctx.fillStyle='rgba(230,235,240,.8)'; ctx.font='10px Segoe UI'; ctx.fillText((members[0].city||'site')+' · '+members.length+' nodes — click',cx,cy+26);
      } else {
        const R=Math.max(48,members.length*9);
        members.forEach((m,i)=>{ const a=2*Math.PI*i/members.length - Math.PI/2; const mx=cx+R*Math.cos(a), my=cy+R*Math.sin(a);
          ctx.strokeStyle='rgba(255,255,255,.16)'; ctx.lineWidth=1; ctx.beginPath(); ctx.moveTo(cx,cy); ctx.lineTo(mx,my); ctx.stroke();
          drawNode(m,mx,my,16);
        });
        ctx.fillStyle='rgba(255,255,255,.55)'; ctx.beginPath(); ctx.arc(cx,cy,3,0,7); ctx.fill();
        ctx.fillStyle='rgba(150,160,175,.8)'; ctx.font='9px Segoe UI'; ctx.textAlign='center'; ctx.fillText('click to collapse',cx,cy-R-8);
      }
    }
  }
  requestAnimationFrame(animate);
}

async function load(){
  let topo=null, geo=null;
  try{ [topo,geo]=await Promise.all([
    fetch('net_mon_map.php?api=topo').then(r=>r.json()),
    fetch('geomap.php?api=geo').then(r=>r.json())]); }catch(e){ return; }
  if(!geo||!geo.ok) return;
  const G=geo.geo||{}; ORIGIN=geo.origin;
  // merge topo status/traffic onto geolocated nodes
  const tnodes={}; (topo&&topo.nodes||[]).forEach(n=>tnodes[n.id]=n);
  const NN={}; let up=0,down=0;
  for(const id in G){ const g=G[id], tn=tnodes[id]||{};
    NN[id]={id:+id,name:g.name,ip:g.ip,lat:g.lat,lon:g.lon,city:g.city,country:g.country,
      status:tn.status||'unknown',cpu:tn.cpu,mem:tn.mem,in:tn.total_in||0,out:tn.total_out||0};
    if(NN[id].status==='up')up++; else if(NN[id].status==='down')down++;
  }
  NODES=NN;
  // cluster nodes that share (≈) a location — data centers stack at one point
  const GG={};
  for(const id in NN){ const n=NN[id]; const k=n.lat.toFixed(3)+','+n.lon.toFixed(3); (GG[k]=GG[k]||{members:[]}).members.push(+id); }
  for(const k in GG){ const m=GG[k].members; let la=0,lo=0; m.forEach(id=>{la+=NN[id].lat;lo+=NN[id].lon;}); GG[k].lat=la/m.length; GG[k].lon=lo/m.length; }
  GROUPS=GG; [...EXPANDED].forEach(k=>{ if(!GG[k])EXPANDED.delete(k); });
  // links between two geolocated nodes
  const LL=[]; let mx=1;
  (topo&&topo.links||[]).forEach(l=>{ if(NN[l.source]&&NN[l.target]){ const load=(l.in_rate||0)+(l.out_rate||0); if(load>mx)mx=load;
    LL.push({s:l.source,t:l.target,in:l.in_rate||0,out:l.out_rate||0}); }});
  LINKS=LL; maxLoad=mx;
  ARCS=(geo.netflow||[]).filter(t=>t.geo).map(t=>({lat:t.geo.lat,lon:t.geo.lon,ip:t.ip}));
  // WireGuard connected peers (purple), tunnel origin = their server's node geo (else origin)
  WGPEERS=(geo.wgpeers||[]).map(p=>{ const s=NN[p.srv_node];
    return {name:p.name,lat:p.geo.lat,lon:p.geo.lon,city:p.geo.city,country:p.geo.country,endpoint:p.endpoint,iface:p.iface,srv:p.srv_name,
      slat:s?s.lat:(ORIGIN?ORIGIN.lat:null),slon:s?s.lon:(ORIGIN?ORIGIN.lon:null)}; });
  document.getElementById('c-wg').textContent=WGPEERS.length;
  // first load → fit map to nodes + WG peer endpoints
  if(!load._fit){ const pts=Object.values(NN).map(n=>[n.lat,n.lon]).concat(WGPEERS.map(p=>[p.lat,p.lon])); if(pts.length){ map.fitBounds(pts,{padding:[60,60],maxZoom:9}); } load._fit=true; }
  dirty=true;

  // ── chips ──
  document.getElementById('c-up').textContent=up;
  document.getElementById('c-down').textContent=down;
  document.getElementById('c-inc').textContent=(geo.incidents||[]).length;
  const c=geo.containers||{}; document.getElementById('c-cont').textContent=c.ok?(c.running+'/'+c.total):'—';
  // ── feed the sonification widget (muted until enabled) ──
  if(window.NMSonify&&window.NMWall) NMSonify.apply(NMWall.pulseFrom({netflow:geo.netflow,incidents:geo.incidents,down:geo.down,nodes:NODES}));

  // ── incidents ──
  const inc=geo.incidents||[]; document.getElementById('n-inc').textContent=inc.length;
  document.getElementById('p-inc').innerHTML = inc.length? inc.map(i=>`<div class="row">
     <span class="dot" style="background:${i.severity==='critical'?'#e74c3c':i.severity==='warning'?'#f39c12':'#4da3ff'}"></span>
     <div style="flex:1;"><div class="sev-${esc(i.severity)}" style="font-weight:600;">${esc(i.title)}</div>
     <div class="muted" style="font-size:11px;">${esc(i.root_entity||'')} · ${esc((i.status||'').toUpperCase())} · impact ${i.impact_count||0}</div></div></div>`).join('')
     : '<div class="empty"><i class="fa-solid fa-circle-check" style="color:#2ecc71"></i> All clear</div>';
  // ── down ──
  const dn=geo.down||[]; document.getElementById('n-down').textContent=dn.length;
  document.getElementById('p-down').innerHTML = dn.length? dn.map(d=>`<div class="row"><span class="dot" style="background:#e74c3c"></span>
     <div style="flex:1;"><b>${esc(d.name)}</b> <span class="muted mono">${esc(d.ip)}</span></div></div>`).join('')
     : '<div class="empty"><i class="fa-solid fa-circle-check" style="color:#2ecc71"></i> Everything reachable</div>';
  // ── containers ──
  document.getElementById('p-cont').innerHTML = c.ok? `<div class="big" style="color:#2ecc71">${c.running}</div>
     <div style="font-size:12px;line-height:1.7;"><div>running <b>${c.running}</b></div><div class="muted">exited ${c.exited} · total ${c.total}</div></div>`
     : '<span class="muted">Portainer not configured</span>';
  // ── top traffic ──
  const top=geo.top||[], tmax=Math.max(1,...top.map(t=>t.total));
  document.getElementById('p-top').innerHTML = top.length? top.map(t=>`<div class="row">
     <div style="width:96px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><b>${esc(t.name)}</b></div>
     <div class="bar-bg"><i style="width:${Math.round(t.total/tmax*100)}%"></i></div>
     <div class="mono" style="width:64px;text-align:right;font-size:11px;">${fmtR(t.in_rate)}/${fmtR(t.out_rate)}</div></div>`).join('')
     : '<div class="empty">No traffic data</div>';
  // ── netflow ──
  const nf=geo.netflow||[]; document.getElementById('n-nf').textContent=nf.length;
  document.getElementById('p-nf').innerHTML = nf.length? nf.map(t=>`<div class="row">
     <span class="dot" style="background:${t.geo?'#36e3d0':'#5b6470'}"></span>
     <div style="flex:1;"><span class="mono">${esc(t.ip)}</span> ${t.geo?`<span class="muted" style="font-size:11px;">${esc((t.geo.city?t.geo.city+', ':'')+(t.geo.country||''))}</span>`:''}</div>
     <div class="k mono" style="font-size:11px;">${t.mbps} Mb/s</div></div>`).join('')
     : '<div class="empty">No NetFlow data</div>';
}
initMap(); load(); setInterval(load,REFRESH);
if(window.NMWall) NMWall.addSonify();   // NOC-wall widget dock (sonification — muted by default)
</script>
</body></html>
