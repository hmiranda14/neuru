<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — NEURUTIK Matrix Flow. An IP-centric 3D flow matrix (NOT the topology
// hologram): every conversation is a LASER between src↔dst IPs — beam thickness =
// bandwidth (Mbps), pulse speed = latency (ms), red/broken = packet loss, thick
// yellow = saturation, red fan = port-scan/anomaly. Local IPs orbit an inner
// plane; external IPs are prisms on the outer perimeter. Reuses NetFlow
// (nm_nf_*) + geo (nm_geo_badge) + ping stats. RBAC: 'matrix_flow'.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_netflow.php');
require_once('nm_nettools.php');
require_once('nm_nodemeta.php');
include('logger.php');

if (!checkAccess($conn, 'matrix_flow')) { header('Location: /denied_access.php?page=matrix_flow'); exit; }

// ── Build the flow matrix: enriched src↔dst conversations from NetFlow ────────
if (!function_exists('mfx_matrix')) {
    function mfx_matrix($conn, int $mins): array {
        nm_nf_ensure($conn);
        $mins = max(1, min(1440, $mins)); $secs = $mins * 60;
        // 1) top conversations by volume
        $edges = []; $ipset = [];
        $r = $conn->query("SELECT src_ip, dst_ip, SUM(bytes) b, SUM(flows) f,
                                  SUBSTRING_INDEX(GROUP_CONCAT(app_port ORDER BY bytes DESC),',',1) ap,
                                  SUBSTRING_INDEX(GROUP_CONCAT(protocol ORDER BY bytes DESC),',',1) pr
                           FROM nm_netflow_flows WHERE bucket >= (NOW() - INTERVAL $mins MINUTE)
                           GROUP BY src_ip, dst_ip ORDER BY b DESC LIMIT 90");
        while ($r && $x = $r->fetch_assoc()) {
            $mbps = (float)$x['b'] * 8 / $secs / 1e6;
            $edges[] = ['src'=>$x['src_ip'], 'dst'=>$x['dst_ip'], 'mbps'=>round($mbps, 3),
                        'port'=>(int)$x['ap'], 'proto'=>nm_nf_proto_name((int)$x['pr']),
                        'app'=>nm_nf_app_name((int)$x['ap'], (int)$x['pr']), 'flows'=>(int)$x['f']];
            $ipset[$x['src_ip']] = 1; $ipset[$x['dst_ip']] = 1;
        }
        // 2) port-scan detection — the REAL signature is a huge fan-out of destinations/ports with
        //    TINY per-flow payloads (SYN probes, no data). Legit high-fanout hosts (routers/NAT/DNS,
        //    a browser hitting many CDNs) move real bytes, so the avg-bytes/flow gate excludes them.
        $scan = [];
        $r = $conn->query("SELECT src_ip, COUNT(DISTINCT dst_ip) dd, COUNT(DISTINCT dst_port) dp,
                                  SUM(flows) tf, SUM(bytes) tb, SUM(bytes)/GREATEST(SUM(flows),1) bpf
                           FROM nm_netflow_flows WHERE bucket >= (NOW() - INTERVAL $mins MINUTE)
                           GROUP BY src_ip
                           HAVING (dp >= 120 OR dd >= 60) AND bpf < 600 AND tf >= 30");
        while ($r && $x = $r->fetch_assoc()) $scan[$x['src_ip']] = ['dd'=>(int)$x['dd'], 'dp'=>(int)$x['dp'], 'bpf'=>round((float)$x['bpf'])];
        // NOTE: intentionally NOT pulling nm_threats/Immunity here — that engine currently over-flags
        // benign IPs (Apple/Google + NEURU's own Portal/n8n servers) as 'portscan', which would show
        // bogus anomalies. Only the tiny-payload fan-out heuristic above (a true scan signature) drives
        // the anomaly badge, so a flagged node is a real behavioural outlier.
        $threats = [];
        // 3) known nodes (ip → node) + latest ping (latency/loss)
        $known = [];
        $r = $conn->query("SELECT id,display_name,ip_address,os_icon,COALESCE(monitor_type,'snmp') monitor_type FROM nm_nodes WHERE ip_address<>''");
        while ($r && $x = $r->fetch_assoc()) $known[$x['ip_address']] = $x;
        $ping = [];
        $r = $conn->query("SELECT ps.node_id,ps.latency_ms,ps.packet_loss FROM nm_ping_stats ps
                           INNER JOIN (SELECT node_id,MAX(id) mid FROM nm_ping_stats GROUP BY node_id) l ON ps.node_id=l.node_id AND ps.id=l.mid");
        while ($r && $x = $r->fetch_assoc()) $ping[(int)$x['node_id']] = $x;
        // 4) build node objects (+ geo for external, capped for speed)
        $nodes = []; $extCount = 0; $geoBudget = 45;
        foreach (array_keys($ipset) as $ip) {
            $isNode = isset($known[$ip]); $priv = nm_nt_is_private($ip);
            $n = ['ip'=>$ip, 'name'=>$ip, 'local'=>($isNode || $priv), 'lat'=>null, 'loss'=>null, 'in'=>0, 'out'=>0, 'deg'=>0];
            if ($isNode) {
                $k = $known[$ip]; $n['name'] = $k['display_name']; $n['node_id'] = (int)$k['id']; $n['kind'] = nm_node_kind($k);
                $cc = nm_node_cc($k, null, null); $n['cc_url'] = $cc['url']; $n['cc_label'] = $cc['label']; $n['cc_icon'] = $cc['icon'];
                $p = $ping[(int)$k['id']] ?? null; if ($p) { $n['lat'] = $p['latency_ms'] !== null ? (float)$p['latency_ms'] : null; $n['loss'] = $p['packet_loss'] !== null ? (float)$p['packet_loss'] : null; }
            } elseif (!$priv) {
                $extCount++; if ($geoBudget-- > 0) { $g = nm_geo_badge($conn, $ip); if ($g) { $n['geo'] = $g['cc']; $n['flag'] = $g['flag']; $n['country'] = $g['country']; $n['asn'] = $g['asn']; } }
            }
            if (isset($scan[$ip])) $n['scan'] = $scan[$ip];
            if (isset($threats[$ip])) $n['threat'] = $threats[$ip];
            $nodes[$ip] = $n;
        }
        // 5) per-edge loss/latency (from the local endpoint's ping) + in/out aggregation + saturation
        $maxM = 0; foreach ($edges as $e) $maxM = max($maxM, $e['mbps']);
        foreach ($edges as &$e) {
            $sn = $nodes[$e['src']] ?? null; $dn = $nodes[$e['dst']] ?? null;
            $e['loss'] = ($sn && $sn['loss'] !== null) ? $sn['loss'] : (($dn && $dn['loss'] !== null) ? $dn['loss'] : 0);
            $e['lat']  = ($sn && $sn['lat']  !== null) ? $sn['lat']  : (($dn && $dn['lat']  !== null) ? $dn['lat']  : 25);
            $e['scan'] = isset($scan[$e['src']]) || isset($threats[$e['src']]) || isset($threats[$e['dst']]);
            $e['sat']  = ($maxM > 1 && $e['mbps'] >= $maxM * 0.55);
            if (isset($nodes[$e['src']])) { $nodes[$e['src']]['out'] += $e['mbps']; $nodes[$e['src']]['deg']++; }
            if (isset($nodes[$e['dst']])) { $nodes[$e['dst']]['in']  += $e['mbps']; $nodes[$e['dst']]['deg']++; }
        } unset($e);
        $anom = 0; foreach ($nodes as $n) if (isset($n['scan']) || isset($n['threat'])) $anom++;
        return ['ok'=>true, 'nodes'=>array_values($nodes), 'edges'=>$edges, 'win'=>$mins, 'ts'=>time(),
                'hud'=>['flows'=>count($edges), 'ext'=>$extCount, 'scans'=>$anom, 'thru'=>round(array_sum(array_column($edges, 'mbps')), 2)]];
    }
    // per-IP dossier: its heaviest flows with ports (for the drawer)
    function mfx_ipflows($conn, string $ip, int $mins): array {
        nm_nf_ensure($conn); $mins = max(1, min(1440, $mins)); $secs = $mins * 60; $ipE = $conn->real_escape_string($ip); $out = [];
        $r = $conn->query("SELECT src_ip,dst_ip,app_port,protocol,SUM(bytes) b,SUM(flows) f FROM nm_netflow_flows
                           WHERE bucket >= (NOW() - INTERVAL $mins MINUTE) AND (src_ip='$ipE' OR dst_ip='$ipE')
                           GROUP BY src_ip,dst_ip,app_port,protocol ORDER BY b DESC LIMIT 20");
        while ($r && $x = $r->fetch_assoc()) $out[] = ['src'=>$x['src_ip'],'dst'=>$x['dst_ip'],'dir'=>($x['src_ip']===$ip?'out':'in'),
            'peer'=>($x['src_ip']===$ip?$x['dst_ip']:$x['src_ip']),'app'=>nm_nf_app_name((int)$x['app_port'],(int)$x['protocol']),
            'port'=>(int)$x['app_port'],'proto'=>nm_nf_proto_name((int)$x['protocol']),'mbps'=>round((float)$x['b']*8/$secs/1e6,3),'flows'=>(int)$x['f']];
        return ['ok'=>true, 'ip'=>$ip, 'flows'=>$out];
    }
}

$__api = $_GET['api'] ?? '';
if ($__api !== '') {
    if (function_exists('session_write_close')) @session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    try {
        if ($__api === 'matrix')      echo json_encode(mfx_matrix($conn, (int)($_GET['win'] ?? 5)));
        elseif ($__api === 'ipflows') echo json_encode(mfx_ipflows($conn, trim((string)($_GET['ip'] ?? '')), (int)($_GET['win'] ?? 5)));
        else echo json_encode(['ok'=>false, 'error'=>'unknown api']);
    } catch (\Throwable $e) { echo json_encode(['ok'=>false, 'error'=>$e->getMessage()]); }
    exit;
}

log_user_action($conn, 'view_page', 'matrix_flow.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cyan:#22d3ee; --purple:#b388ff; --border:rgba(255,255,255,.12); }
*,*::before,*::after{ box-sizing:border-box; }
html{ background:#04050c; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#e6e9ee; }
<?= nm_chrome_css() ?>
#mfx-stage{ position:relative; width:100%; height:calc(100vh - 74px); min-height:520px; overflow:hidden; background:radial-gradient(1200px 700px at 50% 0%, rgba(40,70,140,.16), transparent 72%); }
#mfx-stage:fullscreen{ height:100vh; }
#mfx-canvas{ position:absolute; inset:0; display:block; z-index:1; }
.mfx-hud{ position:absolute; z-index:6; pointer-events:none; }
.mfx-hud .glass{ background:rgba(9,13,24,.62); backdrop-filter:blur(12px); border:1px solid var(--border); border-radius:12px; pointer-events:auto; }
#mfx-top{ top:14px; left:14px; max-width:360px; }
#mfx-top .glass{ padding:12px 14px; }
#mfx-title{ font-size:16px; font-weight:800; letter-spacing:.6px; display:flex; align-items:center; gap:9px; }
#mfx-title i{ color:var(--cyan); }
#mfx-title .tag{ font-size:9px; font-weight:700; letter-spacing:1px; color:#04121a; background:linear-gradient(90deg,#36e3d0,#b388ff); padding:2px 7px; border-radius:20px; }
#mfx-sub{ font-size:11px; color:#8a909a; margin-top:3px; }
#mfx-legend{ margin-top:10px; display:flex; flex-direction:column; gap:5px; }
.leg{ display:flex; align-items:center; gap:8px; font-size:11.5px; color:#c3ccd8; } .leg .sw{ width:16px; height:4px; border-radius:3px; box-shadow:0 0 8px currentColor; flex:0 0 auto; } .leg .dot{ width:10px;height:10px;border-radius:50%;box-shadow:0 0 8px currentColor;flex:0 0 auto; }
#mfx-stats{ top:14px; right:14px; }
#mfx-stats .glass{ padding:10px 14px; display:flex; gap:15px; }
.mstat{ text-align:center; } .mstat .n{ font-size:19px; font-weight:800; line-height:1; } .mstat .l{ font-size:9px; color:#8a909a; text-transform:uppercase; letter-spacing:.6px; margin-top:3px; }
.mstat .n.ok{ color:#7af3b0; } .mstat .n.crit{ color:#ff9b91; } .mstat .n.cyan{ color:var(--cyan); } .mstat .n.warn{ color:#ffd479; }
#mfx-ctl{ top:86px; right:14px; display:flex; flex-direction:column; gap:8px; }
.mbtn{ pointer-events:auto; background:rgba(10,16,28,.78); border:1px solid var(--border); color:#cfe4ff; border-radius:9px; min-width:38px; height:36px; padding:0 12px; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:7px; font-size:13px; }
.mbtn:hover{ border-color:var(--accent); color:#fff; } .mbtn.on{ border-color:var(--cyan); color:#fff; background:rgba(34,211,238,.16); }
.mbtn.rt.on{ border-color:#ff6a4d; background:rgba(255,106,77,.18); color:#ffd0c4; }
#mfx-win{ position:absolute; bottom:16px; left:16px; z-index:6; } #mfx-win .glass{ padding:7px 12px; display:flex; align-items:center; gap:8px; font-size:12px; color:#9aa3af; }
#mfx-win select{ background:rgba(0,0,0,.4); border:1px solid var(--border); color:#cfe4ff; border-radius:7px; padding:4px 8px; font-size:12px; }
#mfx-hint{ bottom:16px; left:50%; transform:translateX(-50%); font-size:11px; color:#8a909a; } #mfx-hint .glass{ padding:7px 12px; }
/* dossier drawer (left) — identical idiom to NEURUTIK */
#mfx-info{ position:absolute; z-index:12; left:0; top:0; height:100%; width:400px; max-width:88vw; display:none; }
#mfx-info .glass{ height:100%; border-radius:0 16px 16px 0; border-left:none; padding:0; display:flex; flex-direction:column; box-shadow:24px 0 60px rgba(0,0,0,.45); background:rgba(8,12,22,.92); }
#mfx-dh{ padding:14px 16px 12px; border-bottom:1px solid var(--border); position:relative; }
#mfx-dh h3{ margin:0; font-size:16px; display:flex; align-items:center; gap:9px; padding-right:24px; word-break:break-all; }
#mfx-dh .meta{ font-size:12px; color:#9aa3af; margin-top:4px; }
#mfx-dh .x{ position:absolute; top:12px; right:12px; cursor:pointer; color:#9aa3af; font-size:15px; } #mfx-dh .x:hover{ color:#fff; }
#mfx-kind{ font-size:9px; font-weight:700; letter-spacing:1px; text-transform:uppercase; padding:2px 8px; border-radius:20px; background:rgba(77,163,255,.18); color:#bcd8ff; }
#mfx-kind.ext{ background:rgba(179,136,255,.18); color:#dcccff; } #mfx-kind.scan{ background:rgba(231,76,60,.22); color:#ff9b91; }
#mfx-db{ padding:12px 16px 20px; overflow-y:auto; flex:1; }
#mfx-db::-webkit-scrollbar{ width:8px; } #mfx-db::-webkit-scrollbar-thumb{ background:rgba(255,255,255,.12); border-radius:8px; }
.dgrid{ display:grid; grid-template-columns:repeat(3,1fr); gap:8px; margin-bottom:14px; }
.dcell{ background:rgba(255,255,255,.04); border:1px solid var(--border); border-radius:9px; padding:8px 9px; }
.dcell .l{ font-size:9px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; } .dcell .v{ font-size:15px; font-weight:700; margin-top:2px; }
.dsec{ margin:16px 0 6px; font-size:11px; text-transform:uppercase; letter-spacing:.7px; color:#7fd3ff; display:flex; align-items:center; gap:7px; } .dsec .cnt{ color:#6b7686; font-weight:400; }
.ditem{ background:rgba(255,255,255,.03); border:1px solid var(--border); border-left:3px solid #5a6577; border-radius:8px; padding:8px 10px; margin-bottom:7px; font-size:12px; }
.ditem .t{ font-weight:600; color:#e6e9ee; display:flex; justify-content:space-between; gap:8px; } .ditem .d{ color:#9aa3af; margin-top:3px; line-height:1.4; word-break:break-word; }
.ditem.out{ border-left-color:#ffb454; } .ditem.in{ border-left-color:#36e3d0; }
.dbadge{ font-size:9px; padding:2px 6px; border-radius:20px; background:rgba(255,255,255,.08); color:#cfd6e0; white-space:nowrap; }
.dalert{ background:rgba(231,76,60,.12); border:1px solid rgba(231,76,60,.4); color:#ff9b91; border-radius:9px; padding:9px 11px; margin-bottom:12px; font-size:12px; }
#mfx-dacts{ display:flex; gap:7px; flex-wrap:wrap; padding:12px 16px; border-top:1px solid var(--border); }
#mfx-dacts a.act{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:8px; padding:8px 12px; font-size:12px; text-decoration:none; display:inline-flex; align-items:center; gap:7px; }
#mfx-dacts a.act:hover{ border-color:var(--accent); color:#fff; } #mfx-dacts a.act.primary{ background:rgba(54,227,208,.16); border-color:rgba(54,227,208,.5); color:#bff2ee; font-weight:700; }
#mfx-tip{ position:absolute; z-index:9; pointer-events:none; display:none; background:rgba(6,10,20,.94); border:1px solid var(--border); border-radius:7px; padding:6px 9px; font-size:12px; white-space:nowrap; transform:translate(-50%,-150%); } #mfx-tip b{ color:#fff; }
#mfx-empty{ position:absolute; inset:0; display:none; align-items:center; justify-content:center; flex-direction:column; gap:10px; color:#8a909a; text-align:center; padding:24px; }
</style>
</head>
<body>
<?php include('header.php'); ?>

<div id="mfx-stage">
  <canvas id="mfx-canvas"></canvas>

  <div id="mfx-top" class="mfx-hud"><div class="glass">
    <div id="mfx-title"><i class="fa-solid fa-diagram-project"></i> NEURUTIK <span class="tag">MATRIX FLOW</span></div>
    <div id="mfx-sub">IP flow matrix · laser thickness = bandwidth, pulse = latency, red = loss</div>
    <div id="mfx-legend">
      <div class="leg"><span class="sw" style="color:#36e3d0"></span> normal flow</div>
      <div class="leg"><span class="sw" style="color:#ffcc44"></span> saturation (bottleneck)</div>
      <div class="leg"><span class="sw" style="color:#e74c3c"></span> packet loss / broken</div>
      <div class="leg"><span class="dot" style="color:#4da3ff"></span> local IP &nbsp; <span class="dot" style="color:#b388ff"></span> external IP</div>
    </div>
  </div></div>

  <div id="mfx-stats" class="mfx-hud"><div class="glass">
    <div class="mstat"><div class="n cyan" id="s-flows">—</div><div class="l">Flows</div></div>
    <div class="mstat"><div class="n" id="s-thru">—</div><div class="l">Throughput</div></div>
    <div class="mstat"><div class="n" id="s-ext">—</div><div class="l">External</div></div>
    <div class="mstat"><div class="n crit" id="s-scan">—</div><div class="l">Anomalies</div></div>
  </div></div>

  <div id="mfx-ctl" class="mfx-hud">
    <button class="mbtn rt" id="b-rt" title="⚡ Real-Time: refresh every 2s"><i class="fa-solid fa-bolt"></i></button>
    <button class="mbtn on" id="b-labels" title="Toggle labels"><i class="fa-solid fa-tag"></i></button>
    <button class="mbtn on" id="b-spin" title="Auto-rotate"><i class="fa-solid fa-arrows-rotate"></i></button>
    <button class="mbtn" id="b-focus" title="Clear Laser Focus (show all)" style="display:none;"><i class="fa-solid fa-eye"></i></button>
    <button class="mbtn" id="b-fit" title="Reset view"><i class="fa-solid fa-crosshairs"></i></button>
    <button class="mbtn" id="b-full" title="Fullscreen"><i class="fa-solid fa-expand"></i></button>
  </div>

  <div id="mfx-win" class="mfx-hud"><div class="glass"><i class="fa-solid fa-clock"></i> Window
    <select id="mfx-window"><option value="1">1 min</option><option value="5" selected>5 min</option><option value="15">15 min</option><option value="60">1 hour</option></select>
    <span id="mfx-rate" style="color:#6f7a8c;"></span>
  </div></div>

  <div id="mfx-hint" class="mfx-hud"><div class="glass"><i class="fa-solid fa-hand-pointer"></i> click an IP to Laser-Focus · hover a beam for port · drag to orbit</div></div>

  <div id="mfx-info" class="mfx-hud"><div class="glass">
    <div id="mfx-dh">
      <span class="x" onclick="document.getElementById('mfx-info').style.display='none'; MFX.sel=null; setFocus(null);"><i class="fa-solid fa-xmark"></i></span>
      <h3 id="mi-name">—</h3>
      <div class="meta"><span id="mfx-kind">—</span> <span id="mi-meta"></span></div>
    </div>
    <div id="mfx-db"><div class="dmuted">—</div></div>
    <div id="mfx-dacts"></div>
  </div></div>

  <div id="mfx-tip"></div>
  <div id="mfx-empty"><i class="fa-solid fa-diagram-project" style="font-size:34px;opacity:.4;"></i><div id="mfx-empty-msg">Waiting for NetFlow data…</div></div>
</div>

<script src="three.min.js"></script>
<script src="three-orbitcontrols.js"></script>
<script>
const MFX = { nodes:[], edges:[], np:{}, meshes:{}, beams:[], sel:null, focus:null, labels:true, spin:true, rt:false, win:5, tmr:null };

(function(){ let ok=false; try{ const c=document.createElement('canvas'); ok=!!(window.WebGLRenderingContext && (c.getContext('webgl')||c.getContext('experimental-webgl'))); }catch(e){}
  if(!ok || typeof THREE==='undefined'){ const e=document.getElementById('mfx-empty'); e.style.display='flex'; document.getElementById('mfx-empty-msg').textContent='WebGL is not available in this browser.'; } })();

const stage=document.getElementById('mfx-canvas').parentNode, canvas=document.getElementById('mfx-canvas');
const renderer=new THREE.WebGLRenderer({canvas,antialias:true,alpha:true}); renderer.setPixelRatio(Math.min(devicePixelRatio,2));
const scene=new THREE.Scene(); scene.fog=new THREE.FogExp2(0x04050c,0.00045);
const camera=new THREE.PerspectiveCamera(55,1,1,9000); camera.position.set(0,320,900);
const controls=new THREE.OrbitControls(camera,renderer.domElement); controls.enableDamping=true; controls.dampingFactor=.08; controls.autoRotate=true; controls.autoRotateSpeed=.3; controls.minDistance=140; controls.maxDistance=4200;
scene.add(new THREE.AmbientLight(0x8899cc,0.95)); const kl=new THREE.PointLight(0x88bbff,0.6,0); kl.position.set(300,500,400); scene.add(kl);
const gNodes=new THREE.Group(), gBeams=new THREE.Group(), gLabels=new THREE.Group(), gFx=new THREE.Group();
scene.add(gBeams); scene.add(gFx); scene.add(gNodes); scene.add(gLabels);
function resize(){ const w=stage.clientWidth,h=stage.clientHeight; renderer.setSize(w,h,false); camera.aspect=w/h; camera.updateProjectionMatrix(); }
new ResizeObserver(resize).observe(stage); resize();

function label(text,color){ const c=document.createElement('canvas'),ct=c.getContext('2d'); ct.font='600 26px Segoe UI,sans-serif';
  const w=ct.measureText(text).width+16; c.width=w; c.height=38; ct.font='600 26px Segoe UI,sans-serif'; ct.fillStyle='rgba(6,10,20,.66)'; ct.fillRect(0,0,w,38); ct.fillStyle=color||'#dbe6f5'; ct.textBaseline='middle'; ct.fillText(text,8,20);
  const tex=new THREE.CanvasTexture(c); tex.minFilter=THREE.LinearFilter; const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:tex,transparent:true,depthWrite:false,depthTest:false})); sp.scale.set(w*0.3,11,1); return sp; }

// layout: local IPs on an inner orbital plane, external IPs on the outer perimeter
function layout(){ MFX.np={}; const loc=MFX.nodes.filter(n=>n.local), ext=MFX.nodes.filter(n=>!n.local);
  const RL=200, RE=520;
  loc.forEach((n,i)=>{ const a=(i/Math.max(1,loc.length))*Math.PI*2; MFX.np[n.ip]=new THREE.Vector3(Math.cos(a)*RL,(i%2?24:-24),Math.sin(a)*RL); });
  ext.forEach((n,i)=>{ const a=(i/Math.max(1,ext.length))*Math.PI*2; const y=((i*47)%320)-160; MFX.np[n.ip]=new THREE.Vector3(Math.cos(a)*RE,y,Math.sin(a)*RE); });
}
function isAnom(n){ return !!(n.scan||n.threat); }
function nodeColor(n){ if(isAnom(n)) return 0xe74c3c; if(n.loss>5) return 0xe74c3c; if(n.loss>1||(n.in+n.out)>400) return 0xf3b52c; return n.local?0x4da3ff:0xb388ff; }
function beamColor(e){ if(e.loss>2) return new THREE.Color(0xe74c3c); if(e.sat) return new THREE.Color(0xffcc44); if(e.scan) return new THREE.Color(0xe74c3c); return new THREE.Color(0x36e3d0); }
function lbps(m){ return Math.log10(1+Math.max(0,m)); }

function rebuild(){
  gNodes.clear(); gBeams.clear(); gLabels.clear(); gFx.clear(); MFX.meshes={}; MFX.beams=[];
  if(!MFX.nodes.length){ document.getElementById('mfx-empty').style.display='flex'; document.getElementById('mfx-empty-msg').textContent='No NetFlow conversations in this window.'; return; }
  document.getElementById('mfx-empty').style.display='none';
  layout();
  MFX.nodes.forEach(n=>{ const p=MFX.np[n.ip]; if(!p) return; const col=nodeColor(n);
    let geo = n.local ? new THREE.SphereGeometry(7+Math.min(8,lbps(n.in+n.out)*3),18,18) : new THREE.OctahedronGeometry(6+Math.min(7,lbps(n.in+n.out)*3),0);
    const m=new THREE.Mesh(geo,new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:.55,metalness:.3,roughness:.4})); m.position.copy(p); m.userData={ip:n.ip,node:n}; gNodes.add(m);
    const halo=new THREE.Mesh(new THREE.SphereGeometry((n.local?12:10),16,16),new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:.13,blending:THREE.AdditiveBlending,depthWrite:false})); halo.position.copy(p); gNodes.add(halo);
    // scan node: red spiky warning ring
    if(isAnom(n)){ const ring=new THREE.Mesh(new THREE.TorusGeometry(16,1.1,8,28),new THREE.MeshBasicMaterial({color:0xe74c3c,transparent:true,opacity:.7})); ring.position.copy(p); gFx.add(ring); MFX.meshes[n.ip]&&0; }
    const nm=(n.flag?n.flag+' ':'')+ (n.name||n.ip); const lb=label(nm.length>22?nm.slice(0,22)+'…':nm, isAnom(n)?'#ff9b91':(n.local?'#cfe4ff':'#dcccff')); lb.position.copy(p).add(new THREE.Vector3(0,16,0)); lb.visible=MFX.labels; gLabels.add(lb);
    MFX.meshes[n.ip]={mesh:m,halo,node:n,pulse:Math.random()*6.28};
  });
  // beams
  MFX.edges.forEach(e=>{ const a=MFX.np[e.src], b=MFX.np[e.dst]; if(!a||!b) return; const col=beamColor(e);
    const mid=a.clone().add(b).multiplyScalar(.5); mid.y+=28+lbps(e.mbps)*10; const curve=new THREE.QuadraticBezierCurve3(a,mid,b);
    const rad=0.35+lbps(e.mbps)*1.25;   // thickness ∝ bandwidth
    const tube=new THREE.Mesh(new THREE.TubeGeometry(curve,26,rad,7,false), new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:e.loss>2?0.28:0.42,blending:THREE.AdditiveBlending,depthWrite:false}));
    tube.userData={edge:e}; gBeams.add(tube);
    // travelling pulse (speed ∝ 1/latency); loss → flicker/broken
    const P=Math.max(6,Math.round(6+lbps(e.mbps)*8)); const pg=new THREE.BufferGeometry(); const pp=new Float32Array(P*3); pg.setAttribute('position',new THREE.BufferAttribute(pp,3));
    const pts=new THREE.Points(pg,new THREE.PointsMaterial({color:col,size:2.5+rad,transparent:true,opacity:.95,blending:THREE.AdditiveBlending,depthWrite:false})); gBeams.add(pts);
    const spd=Math.max(0.05,Math.min(0.6,0.62-(+e.lat||25)/500));
    MFX.beams.push({edge:e,tube,pts,pp,P,curve,phase:Math.random(),speed:spd,loss:+e.loss||0,baseTube:(e.loss>2?0.28:0.42),dim:1});
  });
  gLabels.visible=MFX.labels; applyFocus();
}
// focus only sets a per-beam dim factor; the animation loop is the SINGLE writer of
// material.opacity (base*dim) so the two never fight and clearing focus always restores.
function applyFocus(){ const f=MFX.focus;
  MFX.beams.forEach(B=>{ const on=!f||B.edge.src===f||B.edge.dst===f; B.dim=on?1:0.07; });
  for(const ip in MFX.meshes){ const M=MFX.meshes[ip]; const on=!f||ip===f||MFX.edges.some(e=>(e.src===ip&&e.dst===f)||(e.dst===ip&&e.src===f)); M.halo.material.opacity=on?0.13:0.03; }
}
function setFocus(ip){ MFX.focus=ip; document.getElementById('b-focus').style.display=ip?'inline-flex':'none'; applyFocus(); }

function updHud(h){ document.getElementById('s-flows').textContent=h.flows; document.getElementById('s-thru').textContent=fmtM(h.thru); document.getElementById('s-ext').textContent=h.ext; const sc=document.getElementById('s-scan'); sc.textContent=h.scans; sc.className='n '+(h.scans>0?'crit':''); }
function fmtM(m){ m=+m||0; if(m>=1000) return (m/1000).toFixed(1)+'G'; if(m>=1) return m.toFixed(0)+'M'; if(m>0) return (m*1000).toFixed(0)+'K'; return '0'; }

// ── dossier ──────────────────────────────────────────────────────────────────
function esc(s){ return (''+(s==null?'':s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
async function openIp(ip){ const n=MFX.nodes.find(x=>x.ip===ip); if(!n) return; MFX.sel=ip; setFocus(ip);
  const info=document.getElementById('mfx-info'); info.style.display='block';
  document.getElementById('mi-name').textContent=(n.flag?n.flag+' ':'')+(n.name||ip);
  const kind=document.getElementById('mfx-kind'); kind.textContent=isAnom(n)?'⚠ anomaly':(n.local?(n.kind||'local'):'external'); kind.className=isAnom(n)?'scan':(n.local?'':'ext');
  document.getElementById('mi-meta').textContent=ip+(n.country?(' · '+n.country):'')+(n.asn?(' · '+n.asn):'');
  let h='';
  if(n.threat) h+=`<div class="dalert"><i class="fa-solid fa-shield-virus"></i> <b>Known threat · ${esc(n.threat.severity)}</b> — flagged by NEURU Collective Immunity as <b>${esc(n.threat.source)}</b>. This IP is on the block/watch list.</div>`;
  if(n.scan) h+=`<div class="dalert"><i class="fa-solid fa-triangle-exclamation"></i> <b>Port-scan pattern</b> — ${n.scan.dd} destinations · ${n.scan.dp} ports with tiny (~${n.scan.bpf}B/flow) payloads. Possible scan / anomalous outbound.</div>`;
  const cells=[['In',fmtM(n.in)+'bps'],['Out',fmtM(n.out)+'bps'],['Peers',n.deg||0],['Latency',n.lat!=null?(+n.lat).toFixed(1)+'ms':'—'],['Loss',n.loss!=null?(+n.loss).toFixed(1)+'%':'—'],['Type',n.local?'local':'external']];
  h+='<div class="dgrid">'+cells.map(c=>`<div class="dcell"><div class="l">${c[0]}</div><div class="v">${esc(c[1])}</div></div>`).join('')+'</div>';
  h+='<div class="dsec"><i class="fa-solid fa-right-left"></i> Top flows</div><div id="mfx-flowlist"><div class="dmuted">Loading…</div></div>';
  document.getElementById('mfx-db').innerHTML=h;
  const acts=document.getElementById('mfx-dacts');
  acts.innerHTML=(n.cc_url?`<a class="act primary" href="${n.cc_url}"><i class="fa-solid ${n.cc_icon||'fa-arrow-up-right-from-square'}"></i> ${esc(n.cc_label||'Command Center')} →</a>`:'')
    + `<a class="act" href="netflow.php?host=${encodeURIComponent(ip)}"><i class="fa-solid fa-chart-area"></i> NetFlow</a>`
    + (n.local&&n.node_id?`<a class="act" href="troubleshoot.php?node=${n.node_id}"><i class="fa-solid fa-wrench"></i> Investigate</a>`:'');
  try{ const d=await fetch(`matrix_flow.php?api=ipflows&ip=${encodeURIComponent(ip)}&win=${MFX.win}&_=${Date.now()}`).then(r=>r.json());
    const el=document.getElementById('mfx-flowlist');
    el.innerHTML=(d.ok&&d.flows.length)? d.flows.map(f=>`<div class="ditem ${f.dir}"><div class="t">${f.dir==='out'?'▲':'▼'} ${esc(f.peer)}<span class="dbadge">${esc(f.proto)} ${f.port}</span></div><div class="d">${esc(f.app)} · ${fmtM(f.mbps)}bps · ${f.flows} flows</div></div>`).join('') : '<div class="dmuted">No flows.</div>';
  }catch(e){ document.getElementById('mfx-flowlist').innerHTML='<div class="dmuted">Could not load flows.</div>'; }
}

// ── interaction ──────────────────────────────────────────────────────────────
const ray=new THREE.Raycaster(), mouse=new THREE.Vector2(); const tip=document.getElementById('mfx-tip');
function pickNode(ev){ const r=canvas.getBoundingClientRect(); mouse.x=((ev.clientX-r.left)/r.width)*2-1; mouse.y=-((ev.clientY-r.top)/r.height)*2+1; ray.setFromCamera(mouse,camera); return ray.intersectObjects(gNodes.children.filter(o=>o.userData&&o.userData.ip),false); }
function pickBeam(ev){ const r=canvas.getBoundingClientRect(); mouse.x=((ev.clientX-r.left)/r.width)*2-1; mouse.y=-((ev.clientY-r.top)/r.height)*2+1; ray.setFromCamera(mouse,camera); return ray.intersectObjects(gBeams.children.filter(o=>o.userData&&o.userData.edge),false); }
canvas.addEventListener('click',ev=>{ const h=pickNode(ev); if(h.length) openIp(h[0].object.userData.ip); });
canvas.addEventListener('mousemove',ev=>{ const rr=canvas.getBoundingClientRect(); const hn=pickNode(ev);
  if(hn.length){ const n=hn[0].object.userData.node; tip.style.display='block'; tip.style.left=(ev.clientX-rr.left)+'px'; tip.style.top=(ev.clientY-rr.top)+'px'; tip.innerHTML=`<b>${esc((n.flag?n.flag+' ':'')+(n.name||n.ip))}</b> · ▲${fmtM(n.out)} ▼${fmtM(n.in)}${isAnom(n)?' · ⚠ '+(n.threat?'threat':'scan'):''}`; canvas.style.cursor='pointer'; return; }
  const hb=pickBeam(ev);
  if(hb.length){ const e=hb[0].object.userData.edge; tip.style.display='block'; tip.style.left=(ev.clientX-rr.left)+'px'; tip.style.top=(ev.clientY-rr.top)+'px'; tip.innerHTML=`<b>${esc(e.proto)} ${e.port}</b> ${esc(e.app)} · ${fmtM(e.mbps)}bps${e.loss>2?` · <span style="color:#ff9b91">${(+e.loss).toFixed(0)}% loss</span>`:''}`; canvas.style.cursor='pointer'; return; }
  tip.style.display='none'; canvas.style.cursor='default';
});
document.getElementById('b-labels').onclick=function(){ MFX.labels=!MFX.labels; gLabels.visible=MFX.labels; this.classList.toggle('on',MFX.labels); };
document.getElementById('b-spin').onclick=function(){ MFX.spin=!MFX.spin; controls.autoRotate=MFX.spin; this.classList.toggle('on',MFX.spin); };
document.getElementById('b-focus').onclick=function(){ MFX.sel=null; setFocus(null); };
document.getElementById('b-fit').onclick=function(){ camera.position.set(0,320,900); controls.target.set(0,0,0); };
document.getElementById('b-full').onclick=function(){ if(!document.fullscreenElement) stage.requestFullscreen(); else document.exitFullscreen(); };
// keep the site's NMNetBG particle canvas visible in fullscreen (it's position:fixed on <body>,
// so it vanishes when only #mfx-stage is fullscreened) — move it into the stage while fullscreen.
document.addEventListener('fullscreenchange',()=>{
  const bg=document.getElementById('nm-netbg');
  if(bg){ if(document.fullscreenElement===stage){ stage.insertBefore(bg,stage.firstChild); bg.style.zIndex='0'; }
          else { document.body.appendChild(bg); bg.style.zIndex='-1'; } }
  const i=document.querySelector('#b-full i'); if(i) i.className='fa-solid '+(document.fullscreenElement?'fa-compress':'fa-expand');
  setTimeout(()=>{ resize(); window.dispatchEvent(new Event('resize')); },80);
});
document.getElementById('b-rt').onclick=function(){ MFX.rt=!MFX.rt; this.classList.toggle('on',MFX.rt); schedule(); document.getElementById('mfx-rate').textContent=MFX.rt?'⚡ real-time 2s':''; };
document.getElementById('mfx-window').onchange=function(){ MFX.win=+this.value; load(); };

// ── animation ────────────────────────────────────────────────────────────────
let tPrev=performance.now();
function animate(){ requestAnimationFrame(animate); const now=performance.now(), dt=(now-tPrev)/1000; tPrev=now; controls.update();
  const t=now*0.001;
  for(const ip in MFX.meshes){ const M=MFX.meshes[ip]; const n=M.node; const s=1+Math.sin(t*(isAnom(n)?6:2)+M.pulse)*(isAnom(n)?0.14:0.06); M.mesh.scale.setScalar(s); }
  gFx.children.forEach(o=>{ o.rotation.z+=0.03; o.scale.setScalar(1+Math.sin(t*5)*0.12); });
  for(const B of MFX.beams){ B.phase=(B.phase+dt*B.speed)%1; const d=(B.dim==null?1:B.dim);
    const brk=B.loss>2 && (Math.sin(t*12+B.phase*10)<(B.loss/50));   // loss → intermittent/broken pulses
    for(let k=0;k<B.P;k++){ const tt=(B.phase+k/B.P)%1; const pt=B.curve.getPoint(tt); B.pp[k*3]=pt.x; B.pp[k*3+1]=pt.y; B.pp[k*3+2]=pt.z; }
    B.pts.geometry.attributes.position.needsUpdate=true; B.pts.material.opacity=(brk?0.12:0.95)*d;
    B.tube.material.opacity=(B.loss>2 ? 0.28*(0.45+0.55*Math.abs(Math.sin(t*6+B.phase*6))) : B.baseTube)*d;
  }
  renderer.render(scene,camera);
}
animate();

// ── load + poll ──────────────────────────────────────────────────────────────
async function load(){
  try{ const d=await fetch(`matrix_flow.php?api=matrix&win=${MFX.win}&_=${Date.now()}`).then(r=>r.json());
    if(!d.ok){ document.getElementById('mfx-empty').style.display='flex'; document.getElementById('mfx-empty-msg').textContent='NetFlow error: '+(d.error||'?'); return; }
    MFX.nodes=d.nodes||[]; MFX.edges=d.edges||[]; rebuild(); updHud(d.hud||{flows:0,thru:0,ext:0,scans:0});
    if(MFX.sel && MFX.nodes.find(n=>n.ip===MFX.sel)) setFocus(MFX.sel);
  }catch(e){ document.getElementById('mfx-empty').style.display='flex'; document.getElementById('mfx-empty-msg').textContent='Could not load the flow matrix.'; }
}
function schedule(){ if(MFX.tmr) clearInterval(MFX.tmr); MFX.tmr=setInterval(()=>{ if(!document.hidden) load(); }, MFX.rt?2000:6000); }
load(); schedule();
</script>
</body>
</html>
