<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Realtime Traffic Viewer (Command Center). A full-WebGL "laser" view of
// live per-interface traffic: each monitored interface becomes an animated beam —
// thicker/faster/brighter with more throughput, hot-coloured near saturation. Pick
// any device + interfaces (or all). Real data from nm_port_stats (in_rate/out_rate/
// if_speed/oper), polled live. three.js self-hosted (CSP script-src 'self').
// RBAC: 'traffic_view'. Reuses the shared particle bg via header.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'traffic_view')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=traffic_viewer'); exit;
}

// ── live per-interface rates (latest sample per node,port) ───────────────────
if ($api === 'inventory' || $api === 'live') {
    header('Content-Type: application/json; charset=utf-8');
    if (function_exists('session_write_close')) @session_write_close();
    if (!$conn->query("SHOW TABLES LIKE 'nm_port_stats'")->num_rows) { echo json_encode(['ok'=>true,'rows'=>[]]); exit; }

    // optional port filter (?ports=csv of ints, or 'all')
    $portFilter = '';
    $pin = (string)($_GET['ports'] ?? 'all');
    if ($pin !== '' && $pin !== 'all') {
        $ids = array_filter(array_map('intval', explode(',', $pin)));
        if ($ids) $portFilter = ' AND ps.port_id IN (' . implode(',', $ids) . ')';
    }
    $sql = "SELECT ps.node_id, n.display_name AS node, ps.port_id, i.if_name, i.if_alias,
                   ps.in_rate, ps.out_rate, ps.if_speed, ps.oper_status, ps.recorded_at
            FROM nm_port_stats ps
            JOIN (SELECT node_id, port_id, MAX(recorded_at) mx FROM nm_port_stats
                  WHERE recorded_at > (NOW() - INTERVAL 20 MINUTE) GROUP BY node_id, port_id) last
              ON last.node_id = ps.node_id AND last.port_id = ps.port_id AND last.mx = ps.recorded_at
            JOIN nm_interfaces i ON i.id = ps.port_id
            JOIN nm_nodes n ON n.id = ps.node_id
            WHERE i.show_graph = 1 AND i.is_dummy = 0" . $portFilter . "
            ORDER BY n.display_name, i.sort_order, i.if_index";
    $rows = [];
    if ($r = $conn->query($sql)) {
        while ($x = $r->fetch_assoc()) {
            $in = (float)$x['in_rate']; $out = (float)$x['out_rate']; $sp = (float)$x['if_speed'];
            $util = $sp > 0 ? min(100, round(max($in,$out) / $sp * 100, 1)) : null;
            $rows[] = [
                'pid'   => (int)$x['port_id'],
                'nid'   => (int)$x['node_id'],
                'node'  => (string)$x['node'],
                'name'  => (string)($x['if_name'] ?: ('port ' . $x['port_id'])),
                'alias' => (string)($x['if_alias'] ?: ''),
                'in'    => $in, 'out' => $out,
                'speed' => $sp, 'util' => $util,
                'oper'  => strtolower((string)($x['oper_status'] ?: 'unknown')),
                'at'    => (string)$x['recorded_at'],
            ];
        }
    }
    echo json_encode(['ok'=>true, 'rows'=>$rows, 'server_ms'=>round(microtime(true)*1000)]);
    exit;
}

// ── TRUE realtime sample: live SNMP counter read → delta → instantaneous rates ─
if ($api === 'sample') {
    header('Content-Type: application/json; charset=utf-8');
    if (function_exists('session_write_close')) @session_write_close();
    try { $conn->query("CREATE TABLE IF NOT EXISTS nm_rt_samples (pid INT PRIMARY KEY, in_oct BIGINT UNSIGNED, out_oct BIGINT UNSIGNED,
        ie BIGINT UNSIGNED, oe BIGINT UNSIGNED, idc BIGINT UNSIGNED, odc BIGINT UNSIGNED, ts DOUBLE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); } catch (\Throwable $e) {}
    $pids = array_slice(array_values(array_filter(array_map('intval', explode(',', (string)($_GET['pids'] ?? ''))))), 0, 32);
    if (!$pids) { echo json_encode(['ok'=>true, 'rt'=>[], 'dt'=>0]); exit; }
    $inList = implode(',', $pids);
    // resolve SNMP targets (v1/v2c only; v3 skipped → client keeps near-live for those)
    $targets = [];
    if ($r = $conn->query("SELECT i.id pid, n.ip_address ip, n.snmp_community comm, n.snmp_version ver, i.if_index idx
                           FROM nm_interfaces i JOIN nm_nodes n ON n.id=i.node_id
                           WHERE i.id IN ($inList) AND i.if_index>0 AND COALESCE(n.snmp_community,'')<>'' AND n.snmp_version IN('v1','v2c')")) {
        while ($x = $r->fetch_assoc()) $targets[] = ['pid'=>(int)$x['pid'],'ip'=>$x['ip'],'comm'=>$x['comm'],'ver'=>$x['ver'],'idx'=>(int)$x['idx']];
    }
    if (!$targets) { echo json_encode(['ok'=>true, 'rt'=>[], 'note'=>'no SNMP v1/v2c interfaces in selection']); exit; }

    // call the parallel SNMP sampler
    $py = is_file('/opt/netmon-venv/bin/python3') ? '/opt/netmon-venv/bin/python3' : 'python3';
    $cur = [];
    $spec = [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];
    if (function_exists('proc_open') && ($proc = @proc_open([$py, __DIR__.'/scripts/nm_rt_sample.py'], $spec, $pipes))) {
        fwrite($pipes[0], json_encode(['targets'=>$targets])); fclose($pipes[0]);
        $o = stream_get_contents($pipes[1]); fclose($pipes[1]); @fclose($pipes[2]); @proc_close($proc);
        $cur = json_decode((string)$o, true) ?: [];
    }
    // load previous counters for the delta
    $prev = [];
    if ($pr = $conn->query("SELECT * FROM nm_rt_samples WHERE pid IN ($inList)")) while ($x=$pr->fetch_assoc()) $prev[(int)$x['pid']] = $x;
    $now = microtime(true); $rt = [];
    $up = $conn->prepare("INSERT INTO nm_rt_samples (pid,in_oct,out_oct,ie,oe,idc,odc,ts) VALUES (?,?,?,?,?,?,?,?)
        ON DUPLICATE KEY UPDATE in_oct=VALUES(in_oct),out_oct=VALUES(out_oct),ie=VALUES(ie),oe=VALUES(oe),idc=VALUES(idc),odc=VALUES(odc),ts=VALUES(ts)");
    foreach ($cur as $pidS=>$c) {
        $pid = (int)$pidS;
        if (empty($c['ok'])) { $rt[$pid]=['ok'=>0]; continue; }
        $p = $prev[$pid] ?? null;
        // ── Counter-cache aliasing guard (kills the realtime "flip to 0") ───────────────
        // Many snmpd builds cache IF-MIB octet counters for a few seconds. Polling faster than
        // that cache (we sample ~1.5s) returns the IDENTICAL counter on the in-between reads →
        // a naïve delta is 0 → the rate flapped 0 / real / 0 / real every poll (worst on
        // low-traffic ifaces whose counters advance slowly). FIX: when the octet counters are
        // unchanged from our stored baseline, HOLD — do NOT advance the baseline and report no
        // new rate (omit in/out; the client keeps the last value). The next read where the
        // counter actually moves then spans the FULL elapsed time → a correct AVERAGE rate,
        // with no zero dips and no doubled spikes.
        if ($p && (float)$c['in']==(float)$p['in_oct'] && (float)$c['out']==(float)$p['out_oct']) {
            $rt[$pid] = ['ok'=>1, 'dt'=>round($now-(float)$p['ts'],2), 'hold'=>1];
            continue;   // keep the previous baseline (counters + ts) so dt accumulates
        }
        $dt = $p ? ($now - (float)$p['ts']) : 0;
        $rate = function($n,$o) use($dt){ if($dt<=0.15||$dt>30) return null; $d=(float)$n-(float)$o; return $d>=0 ? $d/$dt : null; }; // null on wrap/first
        $row = ['ok'=>1, 'dt'=>round($dt,2)];
        if ($p) {
            $bin=$rate($c['in'],$p['in_oct']);  $bout=$rate($c['out'],$p['out_oct']);
            $row['in']  = $bin!==null ? round($bin*8) : null;      // bytes→bits
            $row['out'] = $bout!==null ? round($bout*8) : null;
            $row['ie']  = $rate($c['ie'],$p['ie']);   $row['oe'] = $rate($c['oe'],$p['oe']);
            $row['id']  = $rate($c['id'],$p['idc']);  $row['od'] = $rate($c['od'],$p['odc']);
        }
        $rt[$pid] = $row;
        $up->bind_param('iddddddd', $pid, $c['in'],$c['out'],$c['ie'],$c['oe'],$c['id'],$c['od'], $now);
        // BIGINT UNSIGNED via 'd' (double) keeps big counters safe enough for delta math
        try { $up->execute(); } catch (\Throwable $e) {}
    }
    echo json_encode(['ok'=>true, 'rt'=>$rt, 'sampled'=>count($rt), 'server_ms'=>round(microtime(true)*1000)]);
    exit;
}

log_user_action($conn, 'view_page', 'traffic_viewer.php');
include('header.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" media="print" onload="this.media='all'">
<noscript><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"></noscript>
<style>
:root{ --in:#36e3d0; --out:#ff9d4d; --accent:#4da3ff; --glass:rgba(12,16,26,.62); --border:rgba(255,255,255,.12); --ease:cubic-bezier(.22,.61,.36,1); }
html{ background:#04060c; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; color:#e7ecf3; background:transparent!important; overflow:hidden; }
#tv-canvas{ position:fixed; inset:0; z-index:0; display:block; }
.tv-hud{ position:fixed; z-index:5; }
/* top bar */
#tv-top{ top:64px; left:0; right:0; display:flex; align-items:center; gap:14px; padding:12px 20px; pointer-events:none; }
#tv-top>*{ pointer-events:auto; }
#tv-title{ font-size:19px; font-weight:800; letter-spacing:.4px; display:flex; align-items:center; gap:11px;
  background:linear-gradient(100deg,#7fc0ff,#36e3d0 60%,#ff9d4d); -webkit-background-clip:text; background-clip:text; color:transparent; }
#tv-title i{ color:#36e3d0; -webkit-text-fill-color:#36e3d0; }
.tv-chip{ background:var(--glass); border:1px solid var(--border); border-radius:22px; padding:7px 14px; font-size:12.5px; color:#cfe0f2; display:inline-flex; align-items:center; gap:8px; backdrop-filter:blur(9px); }
.tv-chip .liv{ width:8px;height:8px;border-radius:50%;background:#36e3d0;box-shadow:0 0 9px #36e3d0;animation:tvp 1.6s ease-in-out infinite; }
@keyframes tvp{0%,100%{opacity:.4;transform:scale(.8)}50%{opacity:1;transform:scale(1.15)}}
.tv-btn{ background:var(--glass); border:1px solid var(--border); color:#cfe0f2; border-radius:11px; padding:9px 13px; font-size:13px; cursor:pointer; display:inline-flex; align-items:center; gap:8px; backdrop-filter:blur(9px); }
.tv-btn:hover{ border-color:var(--accent); color:#fff; } .tv-btn.on{ border-color:#36e3d0; color:#8ff0e4; box-shadow:0 0 16px rgba(54,227,208,.2); }
.tv-spacer{ flex:1; }
/* selector drawer */
#tv-drawer{ top:112px; left:16px; bottom:20px; width:300px; background:var(--glass); border:1px solid var(--border); border-radius:16px; backdrop-filter:blur(14px);
  display:flex; flex-direction:column; overflow:hidden; transition:transform .35s var(--ease), opacity .25s; box-shadow:0 24px 60px rgba(0,0,0,.5); }
#tv-drawer.hide{ transform:translateX(-330px); opacity:0; pointer-events:none; }
.tv-dh{ padding:13px 15px; border-bottom:1px solid var(--border); display:flex; align-items:center; gap:9px; }
.tv-dh b{ font-size:13px; } .tv-dh .muted{ font-size:11px; color:#8391a5; margin-left:auto; }
.tv-search{ padding:10px 12px; border-bottom:1px solid var(--border); }
.tv-search input{ width:100%; box-sizing:border-box; background:rgba(0,0,0,.3); border:1px solid var(--border); color:#e7ecf3; border-radius:9px; padding:9px 11px; font-size:13px; outline:none; }
.tv-list{ flex:1; overflow:auto; padding:6px; }
.tv-dev{ margin-bottom:4px; }
.tv-dev>.dvh{ display:flex; align-items:center; gap:8px; padding:8px 10px; border-radius:9px; cursor:pointer; font-size:13px; font-weight:600; }
.tv-dev>.dvh:hover{ background:rgba(255,255,255,.05); } .tv-dev>.dvh i.cv{ transition:transform .2s; font-size:11px; color:#7c8797; }
.tv-dev.open>.dvh i.cv{ transform:rotate(90deg); }
.tv-dev .ifs{ display:none; padding:2px 0 6px 8px; } .tv-dev.open .ifs{ display:block; }
.tv-if{ display:flex; align-items:center; gap:9px; padding:6px 10px; border-radius:8px; cursor:pointer; font-size:12.5px; color:#c3cddb; }
.tv-if:hover{ background:rgba(255,255,255,.04); }
.tv-if .cbx{ width:15px;height:15px;border-radius:4px;border:1px solid var(--border);display:inline-flex;align-items:center;justify-content:center;font-size:9px;color:#04121a;flex:none; }
.tv-if.on .cbx{ background:#36e3d0; border-color:#36e3d0; } .tv-if .nm{ flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.tv-if .rt{ font-size:10px; color:#7c8797; font-variant-numeric:tabular-nums; }
.tv-dfoot{ padding:10px 12px; border-top:1px solid var(--border); display:flex; gap:8px; }
.tv-dfoot .tv-btn{ flex:1; justify-content:center; padding:8px; font-size:12px; }
/* right detail panel */
#tv-detail{ top:112px; right:16px; bottom:20px; width:322px; background:var(--glass); border:1px solid var(--border); border-radius:16px; backdrop-filter:blur(14px);
  overflow:auto; padding:6px; transition:transform .35s var(--ease), opacity .25s; box-shadow:0 24px 60px rgba(0,0,0,.5); }
#tv-detail.hide{ transform:translateX(350px); opacity:0; pointer-events:none; }
.tv-card{ background:rgba(255,255,255,.03); border:1px solid var(--border); border-radius:12px; padding:11px 13px; margin:6px; position:relative; overflow:hidden; }
.tv-card::before{ content:''; position:absolute; left:0; top:0; bottom:0; width:3px; background:var(--c,#4da3ff); box-shadow:0 0 10px var(--c); }
.tv-card .cn{ font-weight:700; font-size:13px; display:flex; align-items:center; gap:8px; } .tv-card .cn .dev{ color:#8391a5; font-weight:400; font-size:11px; }
.tv-card .cn .st{ margin-left:auto; font-size:9px; text-transform:uppercase; letter-spacing:.5px; padding:2px 7px; border-radius:20px; }
.tv-card .cn .st.up{ background:rgba(54,227,208,.16); color:#8ff0e4; } .tv-card .cn .st.down{ background:rgba(231,76,60,.18); color:#ff8b80; } .tv-card .cn .st.unknown{ background:rgba(255,255,255,.08); color:#aeb9c8; }
.tv-io{ display:flex; gap:10px; margin-top:9px; }
.tv-io>div{ flex:1; } .tv-io .l{ font-size:9px; text-transform:uppercase; letter-spacing:.5px; color:#7c8797; }
.tv-io .r{ font-size:15px; font-weight:800; font-variant-numeric:tabular-nums; } .tv-io .in .r{ color:var(--in); } .tv-io .out .r{ color:var(--out); }
.tv-meta{ display:flex; gap:12px; margin-top:8px; font-size:10.5px; color:#9aa7b8; }
.tv-spark{ height:26px; margin-top:8px; display:block; width:100%; }
.tv-empty{ color:#7c8797; text-align:center; padding:24px; font-size:13px; }
/* floating lane labels (projected) */
#tv-labels{ position:fixed; inset:0; z-index:2; pointer-events:none; }
.tv-lab{ position:absolute; transform:translate(-50%,-50%); font-size:11px; white-space:nowrap; text-shadow:0 2px 8px #000;
  background:rgba(6,10,18,.5); border:1px solid var(--border); border-radius:20px; padding:3px 10px; backdrop-filter:blur(4px); }
.tv-lab b{ color:#eaf2ff; } .tv-lab .i{ color:var(--in); } .tv-lab .o{ color:var(--out); font-variant-numeric:tabular-nums; }
#tv-fallback{ position:fixed; inset:0; display:none; align-items:center; justify-content:center; z-index:9; color:#9aa7b8; }
@media (max-width:820px){ #tv-detail{ display:none; } #tv-drawer{ width:82vw; } }
</style>

<canvas id="tv-canvas"></canvas>
<div id="tv-labels"></div>
<div id="tv-fallback"><div style="text-align:center"><i class="fa-solid fa-triangle-exclamation" style="font-size:32px;color:#f0a92c"></i><br><br>WebGL is not available in this browser.</div></div>

<div id="tv-top" class="tv-hud">
  <div id="tv-title"><i class="fa-solid fa-wave-square"></i> Realtime Traffic Viewer</div>
  <span class="tv-chip"><span class="liv"></span> <span id="tv-live">live</span></span>
  <span class="tv-chip" id="tv-count">0 interfaces</span>
  <div class="tv-spacer"></div>
  <button class="tv-btn on" id="tv-toggle-drawer" onclick="tvToggle('drawer')"><i class="fa-solid fa-list-check"></i> Interfaces</button>
  <button class="tv-btn on" id="tv-toggle-detail" onclick="tvToggle('detail')"><i class="fa-solid fa-gauge-high"></i> Detail</button>
  <button class="tv-btn" id="tv-rt" onclick="tvRealtime()" title="Live SNMP sampling of the selected interfaces (~1.5s)"><i class="fa-solid fa-bolt"></i> Realtime</button>
  <button class="tv-btn" id="tv-pause" onclick="tvPause()"><i class="fa-solid fa-pause"></i></button>
  <button class="tv-btn" onclick="tvFull()"><i class="fa-solid fa-expand"></i></button>
</div>

<div id="tv-drawer" class="tv-hud">
  <div class="tv-dh"><i class="fa-solid fa-diagram-project" style="color:#36e3d0"></i> <b>Devices &amp; interfaces</b> <span class="muted" id="tv-selc">0 sel</span></div>
  <div class="tv-search"><input id="tv-filter" placeholder="filter device / interface…" oninput="tvRenderList()"></div>
  <div class="tv-list" id="tv-devlist"></div>
  <div class="tv-dfoot">
    <button class="tv-btn" onclick="tvSelectAll(true)"><i class="fa-solid fa-check-double"></i> All</button>
    <button class="tv-btn" onclick="tvSelectAll(false)"><i class="fa-solid fa-xmark"></i> Clear</button>
  </div>
</div>

<div id="tv-detail" class="tv-hud"><div id="tv-cards"></div></div>

<script src="three.min.js"></script>
<script src="three-orbitcontrols.js"></script>
<script>
if(window.NMLoader) NMLoader.keep();
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function fmtRate(b){ b=+b||0; if(b>=1e9)return (b/1e9).toFixed(2)+' Gb/s'; if(b>=1e6)return (b/1e6).toFixed(2)+' Mb/s'; if(b>=1e3)return (b/1e3).toFixed(1)+' Kb/s'; return Math.round(b)+' b/s'; }
function fmtSpeed(b){ b=+b||0; if(!b)return '—'; if(b>=1e9)return (b/1e9)+'G'; if(b>=1e6)return (b/1e6)+'M'; return b; }
function fmtErr(v){ v=+v||0; if(v===0)return '0'; if(v>=10)return Math.round(v); if(v>=1)return v.toFixed(1); return v.toFixed(2); }
const norm=b=>Math.min(1, Math.log10(1+(+b||0))/Math.log10(1+2e9));   // 0..1 log scale up to ~2 Gb/s

const SEL_KEY='nm_tv_sel';
let INV=[];                 // inventory rows (latest)
let SEL=new Set(JSON.parse(localStorage.getItem(SEL_KEY)||'[]'));
let LANES=new Map();        // pid → lane object
let DATA=new Map();         // pid → latest row (+ history + peak)
let paused=false, drawerOn=true, detailOn=true, rtOn=false, rtBusy=false, rtTimer=null;

// ── three.js scene ───────────────────────────────────────────────────────────
let renderer,scene,camera,controls,clock, WEBGL=true;
const beamVert=`varying vec2 vUv; void main(){ vUv=uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0);}`;
const beamFrag=`precision highp float; varying vec2 vUv;
uniform float uTime,uSpeed,uCore,uUtil,uDir,uOn; uniform vec3 uColor;
void main(){
  float d=abs(vUv.y-0.5)*2.0;
  float beam=exp(-pow(d/max(uCore,0.015),2.0));
  float dash=0.5+0.5*sin((vUv.x*46.0 - uTime*uSpeed*uDir)*6.2831);
  dash=pow(dash,3.0);
  float a=beam*(0.28+0.72*dash)*uOn;
  vec3 col=mix(uColor, vec3(1.0,0.42,0.32), uUtil);
  gl_FragColor=vec4(col*(1.0+uUtil*0.6), a);
}`;
const dotVert=`precision highp float; attribute float aoff;
uniform float uTime,uSpeed,uDir,uLen,uSize; varying float vp;
void main(){ float p=fract(aoff+uDir*uTime*uSpeed); vp=p; vec3 pos=position; pos.x=(p-0.5)*uLen;
  vec4 mv=modelViewMatrix*vec4(pos,1.0); gl_PointSize=uSize*(360.0/max(1.0,-mv.z)); gl_Position=projectionMatrix*mv; }`;
const dotFrag=`precision highp float; varying float vp; uniform vec3 uColor; uniform float uUtil,uOn;
void main(){ vec2 c=gl_PointCoord-0.5; float d=length(c); if(d>0.5)discard; float a=smoothstep(0.5,0.0,d)*uOn;
  gl_FragColor=vec4(mix(uColor,vec3(1.0,0.6,0.4),uUtil), a); }`;

const LANE_LEN=220, DOTS=54;
function initGL(){
  const canvas=$('#tv-canvas');
  try{ renderer=new THREE.WebGLRenderer({canvas,antialias:true,alpha:true}); }
  catch(e){ WEBGL=false; $('#tv-fallback').style.display='flex'; if(window.NMLoader)NMLoader.hide(); return; }
  renderer.setPixelRatio(Math.min(2,devicePixelRatio)); renderer.setSize(innerWidth,innerHeight);
  scene=new THREE.Scene(); scene.fog=new THREE.FogExp2(0x04060c,0.0016);
  camera=new THREE.PerspectiveCamera(52, innerWidth/innerHeight, 1, 3000);
  camera.position.set(0,0,360);
  controls=new THREE.OrbitControls(camera, renderer.domElement);
  controls.enableDamping=true; controls.dampingFactor=0.08; controls.enablePan=true;
  controls.minDistance=120; controls.maxDistance=1200; controls.maxPolarAngle=Math.PI*0.85; controls.minPolarAngle=Math.PI*0.15;
  clock=new THREE.Clock();
  addEventListener('resize',()=>{ renderer.setSize(innerWidth,innerHeight); camera.aspect=innerWidth/innerHeight; camera.updateProjectionMatrix(); });
  animate();
}
function beamMesh(dir,color,y){
  const u={ uTime:{value:0},uSpeed:{value:1},uCore:{value:0.05},uUtil:{value:0},uDir:{value:dir},uOn:{value:1},uColor:{value:new THREE.Color(color)} };
  const m=new THREE.Mesh(new THREE.PlaneGeometry(LANE_LEN,10,1,1),
    new THREE.ShaderMaterial({uniforms:u,vertexShader:beamVert,fragmentShader:beamFrag,transparent:true,depthWrite:false,blending:THREE.AdditiveBlending}));
  m.position.y=y; m.userData.u=u; return m;
}
function dotCloud(dir,color,y){
  const g=new THREE.BufferGeometry(), pos=new Float32Array(DOTS*3), off=new Float32Array(DOTS);
  for(let i=0;i<DOTS;i++){ pos[i*3]=0; pos[i*3+1]=y+(Math.random()-0.5)*4.2; pos[i*3+2]=(Math.random()-0.5)*3; off[i]=Math.random(); }
  g.setAttribute('position',new THREE.BufferAttribute(pos,3)); g.setAttribute('aoff',new THREE.BufferAttribute(off,1));
  const u={ uTime:{value:0},uSpeed:{value:1},uDir:{value:dir},uLen:{value:LANE_LEN},uSize:{value:8},uColor:{value:new THREE.Color(color)},uUtil:{value:0},uOn:{value:1} };
  const p=new THREE.Points(g,new THREE.ShaderMaterial({uniforms:u,vertexShader:dotVert,fragmentShader:dotFrag,transparent:true,depthWrite:false,blending:THREE.AdditiveBlending}));
  p.userData.u=u; return p;
}
function buildLanes(){
  // clear
  LANES.forEach(l=>{ scene.remove(l.group); l.group.traverse(o=>{ o.geometry&&o.geometry.dispose(); o.material&&o.material.dispose(); }); });
  LANES.clear();
  const pids=[...SEL].filter(p=>INV.find(r=>r.pid===p));
  const n=pids.length, dY=26, top=(n-1)*dY/2;
  pids.forEach((pid,idx)=>{
    const y=top-idx*dY, grp=new THREE.Group(); grp.position.y=y;
    const bIn=beamMesh(1,0x36e3d0, 3.0), bOut=beamMesh(-1,0xff9d4d,-3.0);
    const dIn=dotCloud(1,0x9ff6ec, 3.0), dOut=dotCloud(-1,0xffc48a,-3.0);
    grp.add(bIn,bOut,dIn,dOut);
    scene.add(grp);
    LANES.set(pid,{group:grp,y,bIn,bOut,dIn,dOut,
      // start-of-lane world point for the projected label
      anchor:new THREE.Vector3(-LANE_LEN/2-6, y, 0)});
  });
  // fit camera distance to lane count
  const need=Math.max(240, n*dY*1.15 + 120);
  if(controls){ controls.target.set(0,0,0); camera.position.set(0, 0, Math.max(camera.position.z, need)); controls.update(); }
  tvUpdateVisuals(); tvRenderCards();
  $('#tv-count').textContent = n+' interface'+(n!==1?'s':'');
}
function animate(){
  requestAnimationFrame(animate);
  if(!renderer) return;
  const t=clock.getElapsedTime();
  if(!paused) LANES.forEach(l=>{ [l.bIn,l.bOut,l.dIn,l.dOut].forEach(o=>o.userData.u.uTime.value=t); });
  controls&&controls.update();
  renderer.render(scene,camera);
  projectLabels();
}
// map current DATA → lane shader uniforms
function tvUpdateVisuals(){
  LANES.forEach((l,pid)=>{
    const d=DATA.get(pid)||{}; const inN=norm(d.in), outN=norm(d.out);
    const uIn=d.util!=null?Math.min(1,d.util/100):inN*0.6, uOut=d.util!=null?Math.min(1,d.util/100):outN*0.6;
    const down=(d.oper&&d.oper!=='up');
    setLane(l.bIn,l.dIn, inN, uIn, down);
    setLane(l.bOut,l.dOut, outN, uOut, down);
  });
}
function setLane(beam,dots,intensity,util,down){
  const bu=beam.userData.u, du=dots.userData.u;
  bu.uCore.value=0.05+0.55*intensity; bu.uSpeed.value=0.25+3.4*intensity; bu.uUtil.value=util; bu.uOn.value=down?0.12:1;
  du.uSize.value=5+30*intensity; du.uSpeed.value=0.12+0.9*intensity; du.uUtil.value=util; du.uOn.value=down?0.15:1;
}
// project each lane anchor to screen for the HTML label
let lblAcc=0;
function projectLabels(){
  lblAcc++; if(lblAcc%2) return;                 // throttle to ~30fps
  const box=$('#tv-labels'); const v=new THREE.Vector3();
  let html='';
  LANES.forEach((l,pid)=>{
    const d=DATA.get(pid)||{}; v.copy(l.anchor).project(camera);
    if(v.z>1) return;
    const x=(v.x*0.5+0.5)*innerWidth, y=(-v.y*0.5+0.5)*innerHeight;
    html+=`<div class="tv-lab" style="left:${x}px;top:${y}px"><b>${esc(d.name||'')}</b>${d.node?` <span style="color:#7fb0e8;font-weight:400">@ ${esc(d.node)}</span>`:''} · <span class="i">▲${fmtRate(d.in)}</span> <span class="o">▼${fmtRate(d.out)}</span></div>`;
  });
  box.innerHTML=html;
}

// ── data / polling ───────────────────────────────────────────────────────────
async function tvPoll(){   // near-live from the DB (2-min poller): metadata + traffic when NOT realtime
  try{
    const r=await fetch('traffic_viewer.php?api=live&ports=all&_='+Date.now()).then(x=>x.json());
    if(!r||!r.ok) return;
    INV=r.rows;
    r.rows.forEach(row=>{
      const d=DATA.get(row.pid)||{hist:[],peakIn:0,peakOut:0};
      d.pid=row.pid; d.node=row.node; d.name=row.name; d.alias=row.alias; d.speed=row.speed; d.oper=row.oper; d.at=row.at;
      if(!rtOn){                                   // DB drives traffic when realtime is OFF
        d.in=row.in; d.out=row.out; d.util=row.util;
        d.hist=(d.hist||[]).concat([[row.in,row.out]]).slice(-40);
        d.peakIn=Math.max(d.peakIn||0,row.in); d.peakOut=Math.max(d.peakOut||0,row.out);
      } else if(d.in===undefined){ d.in=row.in; d.out=row.out; d.util=row.util; }
      DATA.set(row.pid,d);
    });
    if(SEL.size===0 && !localStorage.getItem(SEL_KEY+'_touched')){ INV.forEach(r=>SEL.add(r.pid)); buildLanes(); }
    else { let need=false; SEL.forEach(p=>{ if(INV.find(r=>r.pid===p)&&!LANES.has(p)) need=true; }); if(need) buildLanes(); else tvUpdateVisuals(); }
    tvRenderList(); tvRenderCards();
    if(!rtOn) $('#tv-live').textContent='near-live (2-min poll) · '+new Date().toLocaleTimeString();
    if(window.NMLoader) NMLoader.hide();
  }catch(e){ $('#tv-live').textContent='reconnecting…'; }
}
// ── TRUE realtime: live SNMP delta of the SELECTED interfaces (~1.5s) ──
async function tvSample(){
  if(!rtOn || rtBusy) return; const pids=[...SEL]; if(!pids.length) return;
  rtBusy=true; const t0=performance.now();
  try{
    const r=await fetch('traffic_viewer.php?api=sample&pids='+pids.join(',')+'&_='+Date.now()).then(x=>x.json());
    if(r&&r.ok){
      let got=0;
      Object.entries(r.rt||{}).forEach(([pid,v])=>{ const d=DATA.get(+pid); if(!d||!v.ok) return;
        if(v.hold){ d.rt=true; DATA.set(+pid,d); return; }   // cached snmpd counter → keep last values, no flip to 0
        if(v.in!=null){ d.in=v.in; d.out=v.out; got++;
          d.hist=(d.hist||[]).concat([[v.in,v.out]]).slice(-40);
          d.peakIn=Math.max(d.peakIn||0,v.in); d.peakOut=Math.max(d.peakOut||0,v.out);
          d.util = d.speed>0 ? Math.min(100, +(Math.max(v.in,v.out)/d.speed*100).toFixed(1)) : d.util;
        }
        d.ie=v.ie; d.oe=v.oe; d.id=v.id; d.od=v.od; d.rt=true;
        DATA.set(+pid,d);
      });
      tvUpdateVisuals(); tvRenderCards();
      $('#tv-live').textContent='⚡ REALTIME · '+Math.round(performance.now()-t0)+'ms · '+got+' live';
    }
  }catch(e){}
  finally{ rtBusy=false; }
}
function tvRealtime(){
  rtOn=!rtOn; const b=$('#tv-rt'); b.classList.toggle('on',rtOn);
  b.innerHTML = rtOn ? '<i class="fa-solid fa-bolt"></i> Realtime ON' : '<i class="fa-solid fa-bolt"></i> Realtime';
  if(rtOn){ tvSample(); rtTimer=setInterval(tvSample,1500); }
  else { clearInterval(rtTimer); rtTimer=null; $('#tv-live').textContent='near-live'; }
}

// ── selector UI ──────────────────────────────────────────────────────────────
function tvRenderList(){
  const q=($('#tv-filter').value||'').toLowerCase();
  const devs={}; INV.forEach(r=>{ (devs[r.node]=devs[r.node]||[]).push(r); });
  let html='';
  Object.keys(devs).sort().forEach(dev=>{
    const ifs=devs[dev].filter(r=>!q || (dev+' '+r.name+' '+r.alias).toLowerCase().includes(q));
    if(!ifs.length) return;
    const selN=ifs.filter(r=>SEL.has(r.pid)).length;
    const open=q||selN>0;
    html+=`<div class="tv-dev ${open?'open':''}"><div class="dvh" onclick="this.parentNode.classList.toggle('open')">
      <i class="fa-solid fa-chevron-right cv"></i><i class="fa-solid fa-server" style="color:#7fb2ff"></i>${esc(dev)}
      <span style="margin-left:auto;font-size:10px;color:#7c8797">${selN}/${ifs.length}</span></div><div class="ifs">`;
    ifs.forEach(r=>{
      const on=SEL.has(r.pid), tot=(+r.in||0)+(+r.out||0);
      html+=`<div class="tv-if ${on?'on':''}" onclick="tvToggleIf(${r.pid})">
        <span class="cbx">${on?'<i class="fa-solid fa-check"></i>':''}</span>
        <span class="nm" title="${esc(r.alias||r.name)}">${esc(r.name)}</span>
        <span class="rt">${fmtRate(tot)}</span></div>`;
    });
    html+='</div></div>';
  });
  $('#tv-devlist').innerHTML=html||'<div class="tv-empty">No live interfaces in the last 20 min.</div>';
  $('#tv-selc').textContent=SEL.size+' sel';
}
function persistSel(){ localStorage.setItem(SEL_KEY,JSON.stringify([...SEL])); localStorage.setItem(SEL_KEY+'_touched','1'); }
function tvToggleIf(pid){ SEL.has(pid)?SEL.delete(pid):SEL.add(pid); persistSel(); buildLanes(); tvRenderList(); }
function tvSelectAll(on){ SEL=new Set(on?INV.map(r=>r.pid):[]); persistSel(); buildLanes(); tvRenderList(); }

// ── detail cards ─────────────────────────────────────────────────────────────
function tvRenderCards(){
  const pids=[...SEL].filter(p=>DATA.has(p));
  if(!pids.length){ $('#tv-cards').innerHTML='<div class="tv-empty">Select interfaces to see engineering detail.</div>'; return; }
  let html='';
  pids.forEach(pid=>{
    const d=DATA.get(pid); const busy=Math.max(norm(d.in),norm(d.out));
    const col=d.oper!=='up'?'#8391a5':(busy>0.75?'#ff7a6e':busy>0.4?'#ffcf6b':'#36e3d0');
    html+=`<div class="tv-card" style="--c:${col}">
      <div class="cn">${esc(d.name)} <span class="dev">· ${esc(d.node)}</span><span class="st ${esc(d.oper)}">${esc(d.oper)}</span></div>
      <div class="tv-io"><div class="in"><div class="l">▲ In</div><div class="r">${fmtRate(d.in)}</div></div>
        <div class="out"><div class="l">▼ Out</div><div class="r">${fmtRate(d.out)}</div></div></div>
      <div class="tv-meta"><span>util <b style="color:#e7ecf3">${d.util!=null?d.util+'%':'—'}</b></span>
        <span>link <b style="color:#e7ecf3">${fmtSpeed(d.speed)}</b></span>
        <span>peak ▲${fmtRate(d.peakIn)} ▼${fmtRate(d.peakOut)}</span></div>
      ${(d.ie!=null||d.id!=null)?`<div class="tv-meta"><span>err <b style="color:${(d.ie||d.oe)?'#ff7a6e':'#8ff0b6'}">${fmtErr((d.ie||0)+(d.oe||0))}</b>/s</span>
        <span>disc <b style="color:${(d.id||d.od)?'#ffcf6b':'#8ff0b6'}">${fmtErr((d.id||0)+(d.od||0))}</b>/s</span>
        ${d.rt?'<span style="color:#36e3d0">⚡ live</span>':''}</div>`:''}
      <canvas class="tv-spark" data-pid="${pid}"></canvas></div>`;
  });
  $('#tv-cards').innerHTML=html;
  $$('#tv-cards .tv-spark').forEach(c=>drawSpark(c, DATA.get(+c.dataset.pid)));
}
function drawSpark(cv,d){ if(!d||!d.hist)return; const w=cv.width=cv.clientWidth*2, h=cv.height=52, x=cv.getContext('2d');
  const H=d.hist, mx=Math.max(1,...H.flat()); x.clearRect(0,0,w,h);
  [[0,'#36e3d0'],[1,'#ff9d4d']].forEach(([k,c])=>{ x.beginPath(); H.forEach((p,i)=>{ const px=i/(H.length-1||1)*w, py=h-(p[k]/mx)*(h-4)-2; i?x.lineTo(px,py):x.moveTo(px,py); });
    x.strokeStyle=c; x.lineWidth=2; x.globalAlpha=.95; x.stroke(); }); }

// ── controls ─────────────────────────────────────────────────────────────────
function tvToggle(which){ if(which==='drawer'){ drawerOn=!drawerOn; $('#tv-drawer').classList.toggle('hide',!drawerOn); $('#tv-toggle-drawer').classList.toggle('on',drawerOn); }
  else { detailOn=!detailOn; $('#tv-detail').classList.toggle('hide',!detailOn); $('#tv-toggle-detail').classList.toggle('on',detailOn); } }
function tvPause(){ paused=!paused; $('#tv-pause').innerHTML=paused?'<i class="fa-solid fa-play"></i>':'<i class="fa-solid fa-pause"></i>'; $('#tv-pause').classList.toggle('on',paused); }
function tvFull(){ if(!document.fullscreenElement) document.documentElement.requestFullscreen&&document.documentElement.requestFullscreen(); else document.exitFullscreen(); }

// ── boot ─────────────────────────────────────────────────────────────────────
(function boot(){
  if(typeof THREE==='undefined'){ $('#tv-fallback').style.display='flex'; if(window.NMLoader)NMLoader.hide(); return; }
  initGL();
  if(!WEBGL) return;
  tvPoll(); setInterval(()=>{ if(!document.hidden) tvPoll(); }, 3000);
})();
</script>
</body></html>
