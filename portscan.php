<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Port Scanner (Net Tools). On-demand TCP connect scan of any monitored
// node or any IP/hostname, streamed live over SSE and visualized as a WebGL
// sonar (open ports burst green on a phyllotaxis disk, a sweep line rotates).
// Pure-PHP scan (no nmap). RBAC: 'nettools_portscan'. Engine: nm_portscan.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_portscan.php');
require_once('nm_audit.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'nettools_portscan')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=nettools_portscan'); exit;
}
nm_nt_ensure($conn);
$EMBED = (($_GET['embed'] ?? '') === '1');   // embedded as a Commander overlay → strip chrome, autostart from ?target

// ── Pre-flight resolve/vet: returns whether a public target needs confirmation ─
if ($api === 'check') {
    header('Content-Type: application/json');
    $rz = nm_ps_resolve($conn, $_GET['target'] ?? '', false);
    if ($rz['ok'])                       echo json_encode(['ok'=>true,'ip'=>$rz['ip'],'host'=>$rz['host'],'private'=>$rz['private']?1:0,'needs_confirm'=>0]);
    elseif ($rz['error']==='confirm_public') echo json_encode(['ok'=>true,'ip'=>$rz['ip'],'host'=>$rz['host'],'private'=>0,'needs_confirm'=>1]);
    else                                 echo json_encode(['ok'=>false,'error'=>$rz['error']]);
    exit;
}

// ── SSE scan stream ───────────────────────────────────────────────────────────
if ($api === 'stream') {
    $confirm = (($_GET['confirm'] ?? '') === '1');
    $rz = nm_ps_resolve($conn, $_GET['target'] ?? '', $confirm);
    @set_time_limit(0);
    while (ob_get_level()) ob_end_flush();
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('X-Accel-Buffering: no');
    @ini_set('zlib.output_compression', '0');
    $send = function ($ev, $data) { echo "event: {$ev}\ndata: " . json_encode($data) . "\n\n"; @ob_flush(); @flush(); };
    if (!$rz['ok']) { $send('error', ['code'=>$rz['error'], 'ip'=>$rz['ip'] ?? null]); exit; }
    session_write_close();   // release the PHP session lock BEFORE the (slow) scan

    $ip = $rz['ip'];
    $presets = nm_ps_presets(); $pk = (string)($_GET['preset'] ?? '');
    $ports = isset($presets[$pk]) ? $presets[$pk]['ports'] : nm_ps_parse_ports((string)($_GET['ports'] ?? ''), 65535);
    if (!$ports) $ports = $presets['top100']['ports'];
    $ports = array_slice(array_values($ports), 0, 65535);   // allow a true full 1-65535 sweep
    $total = count($ports);

    // Adaptive scan profile: big sweeps use more parallelism + a tighter per-port timeout so the
    // dominant cost (firewall-dropped "filtered" ports, which each wait the full timeout) stays bounded.
    if ($total > 20000)      { $chunkSz = 256; $timeout = 0.6; $budget = 900; }
    elseif ($total > 4000)   { $chunkSz = 200; $timeout = 0.8; $budget = 480; }
    else                     { $chunkSz = 120; $timeout = min(3.0, max(0.4, (float)($_GET['timeout'] ?? 1.2))); $budget = 150; }

    if (function_exists('nm_audit')) nm_audit($conn, 'nettools.portscan',
        ['target_type'=>'host','target_id'=>$rz['host'],'details'=>['ip'=>$ip,'ports'=>$total,'public'=>$rz['private']?0:1]]);
    log_user_action($conn, 'nettools_portscan', $rz['host'] . ' (' . $total . 'p)');

    $send('meta', ['ip'=>$ip,'host'=>$rz['host'],'private'=>$rz['private']?1:0,'ports'=>$ports,'total'=>$total]);
    $open = $closed = $filtered = 0; $started = time();
    foreach (array_chunk($ports, $chunkSz) as $chunk) {
        if (connection_aborted()) break;
        if (time() - $started > $budget) { $send('done', ['reason'=>'time limit ('.$budget.'s)','open'=>$open,'closed'=>$closed,'filtered'=>$filtered,'aborted'=>1]); exit; }
        $rr = nm_ps_scan_chunk($ip, $chunk, $timeout);
        $items = [];
        foreach ($chunk as $p) {
            $st = $rr[$p] ?? 'filtered';
            if ($st === 'open') { $open++; $send('open', ['p'=>$p,'svc'=>nm_ps_service($p)]); }
            elseif ($st === 'closed') $closed++;
            else $filtered++;
            $items[] = ['p'=>$p, 's'=>$st[0]];   // o | c | f
        }
        $send('chunk', ['items'=>$items,'open'=>$open,'closed'=>$closed,'filtered'=>$filtered,'scanned'=>$open+$closed+$filtered]);
    }
    $send('done', ['reason'=>'complete','open'=>$open,'closed'=>$closed,'filtered'=>$filtered]);
    exit;
}

log_user_action($conn, 'view_page', 'portscan.php');

// node picker: monitored nodes that have an IP
$nodes = [];
$nr = $conn->query("SELECT id, display_name, ip_address FROM nm_nodes WHERE ip_address IS NOT NULL AND ip_address<>'' ORDER BY display_name");
while ($nr && ($n = $nr->fetch_assoc())) $nodes[] = $n;
$presets = nm_ps_presets();
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Port Scanner | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="three.min.js"></script>
<script src="three-orbitcontrols.js"></script>
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ee66e; --warn:#f0a92c; --crit:#e74c3c; }
*,*::before,*::after{ box-sizing:border-box; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#05070d; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-2; object-fit:cover; opacity:.12; }
.wrap{ max-width:1280px; margin:0 auto; padding:18px 20px 40px; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.bar{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:16px; }
select.t,input.t{ background:#141a22; color:#e6e9ee; border:1px solid var(--border); border-radius:9px; padding:10px 13px; font-size:14px; font-family:monospace; }
input.t{ min-width:240px; } select.t{ min-width:150px; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:10px 16px; font-size:13px; cursor:pointer; }
.btn:hover{ background:rgba(77,163,255,.25); } .btn.stop{ background:rgba(231,76,60,.15); border-color:rgba(231,76,60,.45); color:#f0a59d; }
.btn:disabled{ opacity:.5; cursor:default; }
.lay{ display:grid; grid-template-columns:340px 1fr; gap:16px; align-items:start; }
@media(max-width:900px){ .lay{ grid-template-columns:1fr; } }
.kpis{ display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-bottom:14px; }
.kpi{ padding:11px; text-align:center; } .kpi .n{ font-size:22px; font-weight:800; } .kpi .l{ font-size:10px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; }
.muted{ color:#7c828c; font-size:12px; } .lbl{ font-size:11px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; margin:2px 0 5px; }
#sonar-wrap{ position:relative; height:78vh; min-height:680px; border-radius:14px; overflow:hidden; background:radial-gradient(circle at 50% 45%,rgba(20,40,60,.35),rgba(5,7,13,.9) 70%); }
#sonar{ position:absolute; inset:0; width:100%; height:100%; display:block; } #status{ position:absolute; top:12px; left:14px; font-size:12px; z-index:3; }
#legend{ position:absolute; bottom:10px; left:14px; display:flex; gap:14px; font-size:11px; z-index:3; }
.lg{ display:flex; align-items:center; gap:6px; color:#c3ccd8; } .lg .sw{ width:10px; height:10px; border-radius:50%; box-shadow:0 0 8px currentColor; }
.dot{ display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:6px; }
#openlist{ max-height:280px; overflow:auto; } .prow{ display:flex; justify-content:space-between; align-items:center; padding:7px 9px; border-bottom:1px solid rgba(255,255,255,.06); font-size:13px; }
.prow .pt{ font-family:monospace; font-weight:800; color:var(--ok); } .prow .svc{ font-size:11px; color:#9fb0c2; }
.pbadge{ font-size:9.5px; padding:2px 7px; border-radius:20px; background:rgba(46,230,110,.16); color:#8ff0b6; }
.tabs{ display:flex; gap:8px; margin-bottom:10px; } .tab{ font-size:12px; padding:6px 12px; border-radius:8px; cursor:pointer; color:#9aa; border:1px solid transparent; }
.tab.on{ background:rgba(77,163,255,.14); border-color:rgba(77,163,255,.35); color:#cfe4ff; }
.hint{ font-size:11.5px; color:#7c828c; margin-top:2px; }
<?= nm_chrome_css() ?>
body.embed{ background:transparent !important; padding-top:0 !important; }
body.embed #nm-topbar, body.embed #bg-video{ display:none !important; }
body.embed .wrap{ padding:8px 12px 12px !important; max-width:none !important; }
body.embed #sonar-wrap{ height:calc(100vh - 130px) !important; min-height:0 !important; }
</style></head><body class="<?= $EMBED?'embed':'' ?>">
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php if(!$EMBED) nm_page_header('<i class="fas fa-satellite-dish"></i>Port Scanner', '', 'Net Tools · on-demand TCP scan', 'fa-solid fa-satellite-dish',''); ?>

<div class="bar">
  <select class="t" id="node" onchange="pickNode()">
    <option value="">— pick a node —</option>
    <?php foreach ($nodes as $n): ?>
      <option value="<?= htmlspecialchars($n['ip_address']) ?>"><?= htmlspecialchars($n['display_name']) ?> · <?= htmlspecialchars($n['ip_address']) ?></option>
    <?php endforeach; ?>
  </select>
  <input class="t" id="target" placeholder="…or IP / hostname" onkeydown="if(event.key==='Enter')start()">
  <select class="t" id="preset" onchange="onPreset()">
    <?php foreach ($presets as $k=>$p): ?>
      <option value="<?= htmlspecialchars($k) ?>"<?= $k==='top100'?' selected':'' ?>><?= htmlspecialchars($p['label']) ?> (<?= count($p['ports']) ?>)</option>
    <?php endforeach; ?>
    <option value="__custom">Custom ports…</option>
  </select>
  <input class="t" id="ports" placeholder="22,80,443,8000-8100" style="display:none;min-width:200px;">
  <button class="btn" id="go" onclick="start()"><i class="fas fa-play"></i> Scan</button>
  <button class="btn stop" id="stopb" onclick="stop()" style="display:none;"><i class="fas fa-stop"></i> Stop</button>
</div>

<div class="lay">
  <div>
    <div class="kpis">
      <div class="glass kpi"><div class="n" id="k-open" style="color:var(--ok)">0</div><div class="l">open</div></div>
      <div class="glass kpi"><div class="n" id="k-closed">0</div><div class="l">closed</div></div>
      <div class="glass kpi"><div class="n" id="k-filt" style="color:var(--warn)">0</div><div class="l">filtered</div></div>
      <div class="glass kpi"><div class="n" id="k-prog">0%</div><div class="l">scanned</div></div>
    </div>
    <div class="glass card">
      <div class="tabs"><div class="tab on" id="tab-open" onclick="showTab('open')">Open ports</div><div class="tab" id="tab-info" onclick="showTab('info')">Target</div></div>
      <div id="pane-open"><div id="openlist"><span class="muted">Open ports appear here as they're found.</span></div></div>
      <div id="pane-info" style="display:none;font-size:13px;line-height:1.7;"><span class="muted">Run a scan to see resolved target details.</span></div>
    </div>
  </div>

  <div class="glass" id="sonar-wrap">
    <div id="status"><span class="dot" style="background:#555;"></span><span id="status-t">idle</span></div>
    <canvas id="sonar"></canvas>
    <div id="legend">
      <span class="lg"><span class="sw" style="background:var(--ok);color:var(--ok)"></span>open</span>
      <span class="lg"><span class="sw" style="background:#26506e;color:#26506e"></span>closed</span>
      <span class="lg"><span class="sw" style="background:var(--warn);color:var(--warn)"></span>filtered</span>
      <span class="lg"><span class="sw" style="background:#38506a;color:#38506a"></span>pending</span>
    </div>
  </div>
</div>
<div class="hint"><i class="fas fa-circle-info"></i> Pure TCP connect scan from the NOC host (no nmap). <b>filtered</b> = no response (a firewall likely dropped the probe). Public targets ask for confirmation before scanning.</div>
</div>

<script>
const PRESETS = <?= json_encode(array_map(fn($p)=>$p['label'], $presets)) ?>;
let es=null, PORTIDX={}, PTS=null, COLORS=null, GEO=null, sweep=null, three3={}, raf=0, SCAN=null;
const DISK_R = 360;   // radius of the phyllotaxis port disk (also drives ring/sweep size)
const C = { pending:[0.22,0.31,0.42], open:[0.18,0.90,0.43], closed:[0.10,0.20,0.30], filtered:[0.55,0.42,0.17] };

function setStatus(c,t){ document.getElementById('status').innerHTML='<span class="dot" style="background:'+c+';"></span><span id="status-t">'+t+'</span>'; }
function esc(s){ return (''+s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function pickNode(){ const v=document.getElementById('node').value; if(v){ document.getElementById('target').value=v; } }
function onPreset(){ document.getElementById('ports').style.display = document.getElementById('preset').value==='__custom'?'inline-block':'none'; }
function showTab(w){ document.getElementById('tab-open').classList.toggle('on',w==='open'); document.getElementById('tab-info').classList.toggle('on',w==='info');
  document.getElementById('pane-open').style.display=w==='open'?'block':'none'; document.getElementById('pane-info').style.display=w==='info'?'block':'none'; }

// ───────── three.js sonar ─────────
function initThree(){
  const cv=document.getElementById('sonar'), wrap=cv.parentElement;
  const w=wrap.clientWidth||900, h=wrap.clientHeight||560;
  const rn=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true}); rn.setPixelRatio(Math.min(2,devicePixelRatio)); rn.setSize(w,h,false);
  const sc=new THREE.Scene(); const cam=new THREE.PerspectiveCamera(50,w/h,0.1,6000); cam.position.set(0,250,300); cam.lookAt(0,0,0);
  const ctr=new THREE.OrbitControls(cam,cv); ctr.enableDamping=true; ctr.dampingFactor=.08; ctr.maxPolarAngle=Math.PI*0.49; ctr.minDistance=160; ctr.maxDistance=1400;
  sc.add(new THREE.AmbientLight(0x88aacc,0.7)); const pl=new THREE.PointLight(0x4da3ff,1.1,0); pl.position.set(0,340,160); sc.add(pl);
  // grid rings
  for(let r=90;r<=DISK_R;r+=90){ const g=new THREE.RingGeometry(r-0.5,r+0.5,140); const m=new THREE.MeshBasicMaterial({color:0x1c3346,transparent:true,opacity:.5,side:THREE.DoubleSide}); const ring=new THREE.Mesh(g,m); ring.rotation.x=-Math.PI/2; sc.add(ring); }
  // target core
  const core=new THREE.Mesh(new THREE.IcosahedronGeometry(18,2), new THREE.MeshStandardMaterial({color:0x4da3ff,emissive:0x1e6fbf,emissiveIntensity:1,roughness:.3,metalness:.4,flatShading:true})); sc.add(core);
  const halo=new THREE.Mesh(new THREE.SphereGeometry(28,20,20), new THREE.MeshBasicMaterial({color:0x4da3ff,transparent:true,opacity:.12,blending:THREE.AdditiveBlending,depthWrite:false})); sc.add(halo);
  // sweep line
  const sg=new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0,0.5,0),new THREE.Vector3(DISK_R,0.5,0)]);
  sweep=new THREE.Line(sg,new THREE.LineBasicMaterial({color:0x2ee66e,transparent:true,opacity:.7}));
  const sweepFan=new THREE.Mesh(new THREE.CircleGeometry(DISK_R,48,0,0.34), new THREE.MeshBasicMaterial({color:0x2ee66e,transparent:true,opacity:.06,side:THREE.DoubleSide,blending:THREE.AdditiveBlending,depthWrite:false}));
  sweepFan.rotation.x=-Math.PI/2; const sweepGrp=new THREE.Group(); sweepGrp.add(sweep); sweepGrp.add(sweepFan); sc.add(sweepGrp);
  three3={rn,sc,cam,ctr,core,halo,sweepGrp,markers:new THREE.Group(),t:0}; sc.add(three3.markers);
  addEventListener('resize',()=>{ const w=wrap.clientWidth,h=wrap.clientHeight; if(!w||!h)return; three3.cam.aspect=w/h; three3.cam.updateProjectionMatrix(); rn.setSize(w,h,false); });
  animate();
}
function animate(){ raf=requestAnimationFrame(animate); const T=three3; if(!T.rn)return; T.t+=0.016;
  T.core.rotation.y+=0.01; T.core.rotation.x+=0.004; T.halo.scale.setScalar(1+Math.sin(T.t*2)*0.06);
  if(SCAN){ T.sweepGrp.rotation.y-=0.045; } // sweep only while scanning
  // pulse open markers
  T.markers.children.forEach(m=>{ m.userData.t+=0.05; const s=1+Math.sin(m.userData.t)*0.28; m.scale.setScalar(s); });
  T.ctr.update(); T.rn.render(T.sc,T.cam);
}
// phyllotaxis disk layout for N ports
function buildDisk(ports){
  const T=three3; if(PTS){ T.sc.remove(PTS); PTS.geometry.dispose(); } T.markers.clear();
  const N=ports.length, maxR=DISK_R, GA=Math.PI*(3-Math.sqrt(5));
  const pos=new Float32Array(N*3), col=new Float32Array(N*3); PORTIDX={};
  for(let i=0;i<N;i++){ const r=Math.sqrt((i+0.5)/N)*maxR, a=i*GA;
    pos[i*3]=Math.cos(a)*r; pos[i*3+1]=0.6; pos[i*3+2]=Math.sin(a)*r;
    col[i*3]=C.pending[0]; col[i*3+1]=C.pending[1]; col[i*3+2]=C.pending[2];
    PORTIDX[ports[i]]=i;
  }
  GEO=new THREE.BufferGeometry(); GEO.setAttribute('position',new THREE.BufferAttribute(pos,3)); GEO.setAttribute('color',new THREE.BufferAttribute(col,3)); COLORS=col;
  const sz = N>20000?2.0:(N>4000?3.2:5.5);   // shrink dots on huge sweeps so the disk stays readable
  const mat=new THREE.PointsMaterial({size:sz,vertexColors:true,sizeAttenuation:true,transparent:true,opacity:.95});
  PTS=new THREE.Points(GEO,mat); T.sc.add(PTS);
}
function setPort(p,state){ const i=PORTIDX[p]; if(i==null||!COLORS)return; const c=C[state]||C.filtered;
  COLORS[i*3]=c[0]; COLORS[i*3+1]=c[1]; COLORS[i*3+2]=c[2]; GEO.attributes.color.needsUpdate=true;
  if(state==='open'){ // pop a pulsing marker + beam from core
    const T=three3, x=GEO.attributes.position.array[i*3], z=GEO.attributes.position.array[i*3+2];
    const mk=new THREE.Mesh(new THREE.SphereGeometry(4.4,14,14),new THREE.MeshBasicMaterial({color:0x2ee66e,transparent:true,opacity:.95,blending:THREE.AdditiveBlending,depthWrite:false}));
    mk.position.set(x,1.2,z); mk.userData={t:Math.random()*6}; T.markers.add(mk);
    const bg=new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0,1,0),new THREE.Vector3(x,1,z)]);
    T.markers.add(new THREE.Line(bg,new THREE.LineBasicMaterial({color:0x2ee66e,transparent:true,opacity:.28})));
  }
}

// ───────── scan control ─────────
async function start(){
  const t=document.getElementById('target').value.trim(); if(!t){ alert('Pick a node or enter a target'); return; }
  stop(); resetUI();
  setStatus('#f0a92c','resolving…');
  const chk=await fetch('portscan.php?api=check&target='+encodeURIComponent(t)).then(r=>r.json()).catch(()=>null);
  if(!chk||!chk.ok){ setStatus('#e74c3c', chk?esc(chk.error):'resolve failed'); return; }
  let confirm='0';
  if(chk.needs_confirm){
    if(!window.confirm('⚠ '+t+' resolves to a PUBLIC address ('+chk.ip+').\n\nOnly scan hosts you are authorized to test. Continue?')){ setStatus('#555','cancelled'); return; }
    confirm='1';
  }
  const preset=document.getElementById('preset').value;
  const q=new URLSearchParams({target:t,confirm});
  if(preset==='__custom') q.set('ports',document.getElementById('ports').value.trim()); else q.set('preset',preset);
  SCAN={total:0}; document.getElementById('go').style.display='none'; document.getElementById('stopb').style.display='inline-block';
  setStatus('#f0a92c','starting…');
  es=new EventSource('portscan.php?api=stream&'+q.toString());
  es.addEventListener('meta',e=>{ const d=JSON.parse(e.data); SCAN.total=d.total;
    buildDisk(d.ports); setStatus('#2ee66e','scanning '+esc(d.host)+' ('+d.ip+')');
    document.getElementById('pane-info').innerHTML=
      `<div><b>Host</b> — ${esc(d.host)}</div><div><b>IP</b> — <span style="font-family:monospace">${esc(d.ip)}</span></div>`+
      `<div><b>Scope</b> — ${d.private?'<span style="color:var(--ok)">private / RFC1918</span>':'<span style="color:var(--warn)">public</span>'}</div>`+
      `<div><b>Ports</b> — ${d.total}</div>`;
  });
  es.addEventListener('chunk',e=>{ const d=JSON.parse(e.data);
    d.items.forEach(it=> setPort(it.p, it.s==='o'?'open':(it.s==='c'?'closed':'filtered')));
    document.getElementById('k-open').textContent=d.open; document.getElementById('k-closed').textContent=d.closed; document.getElementById('k-filt').textContent=d.filtered;
    const pct=SCAN.total?Math.round(d.scanned/SCAN.total*100):0; document.getElementById('k-prog').textContent=pct+'%';
  });
  es.addEventListener('open',e=>{ const d=JSON.parse(e.data); addOpen(d.p,d.svc); });
  es.addEventListener('error',e=>{ try{ const d=JSON.parse(e.data); setStatus('#e74c3c', d.code==='confirm_public'?'needs confirmation':esc(d.code||'error')); }catch(_){ } cleanup(); });
  es.addEventListener('done',e=>{ const d=JSON.parse(e.data); setStatus(d.open>0?'#2ee66e':'#8a909a', 'done · '+d.open+' open'+(d.aborted?' (time limit)':'')); cleanup(); });
  es.onerror=()=>{ if(es&&es.readyState===2){ setStatus('#e74c3c','disconnected'); cleanup(); } };
}
function addOpen(p,svc){ const l=document.getElementById('openlist'); if(l.querySelector('.muted'))l.innerHTML='';
  const d=document.createElement('div'); d.className='prow';
  d.innerHTML=`<span><span class="pt">${p}</span> ${svc?`<span class="svc">${esc(svc)}</span>`:''}</span><span class="pbadge">OPEN</span>`;
  l.appendChild(d);
}
function resetUI(){ ['k-open','k-closed','k-filt'].forEach(i=>document.getElementById(i).textContent='0'); document.getElementById('k-prog').textContent='0%';
  document.getElementById('openlist').innerHTML='<span class="muted">Open ports appear here as they\'re found.</span>'; showTab('open');
  if(PTS){ three3.sc.remove(PTS); PTS=null; } three3.markers&&three3.markers.clear(); }
function cleanup(){ if(es){es.close();es=null;} SCAN=null; document.getElementById('go').style.display='inline-block'; document.getElementById('stopb').style.display='none'; }
function stop(){ cleanup(); }
window.addEventListener('DOMContentLoaded',()=>{ initThree(); onPreset(); if(window.NMLoader) NMLoader.hide();
  const q=new URLSearchParams(location.search); const tg=q.get('target'); if(tg){ const inp=document.getElementById('target'); if(inp) inp.value=tg; if(q.get('autostart')==='1') setTimeout(start,350); }
});
</script>
</body></html>
