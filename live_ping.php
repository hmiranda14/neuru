<?php
// Live ICMP ping monitor — real-time reachability for ping-only (or any) nodes.
// URL: ?node=<nm_node_id>
// Each poll runs an actual ICMP ping on the server and writes nm_ping_stats, so
// the historical graphs (net_mon_stats.php) keep accumulating while you watch live.

date_default_timezone_set('America/Puerto_Rico');

include('check.php');
include('connection.php');
require_once('access_control.php');
include('logger.php');

$nm_node_id = max(0, (int)($_GET['node'] ?? 0));
$is_ping_api = (($_GET['api'] ?? '') === 'ping');

if (!checkAccess($conn, 'net_mon')) {
    if ($is_ping_api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'err'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=live_ping');
    exit;
}

// ── API: run a real-time ICMP ping NOW, persist to nm_ping_stats ───────────────
if ($is_ping_api) {
    header('Content-Type: application/json; charset=utf-8');
    session_write_close();
    if (!$nm_node_id) { echo json_encode(['ok'=>false,'err'=>'No node']); exit; }

    $nr   = $conn->query("SELECT ip_address FROM nm_nodes WHERE id={$nm_node_id} LIMIT 1");
    $node = $nr ? $nr->fetch_assoc() : null;
    $ip   = $node['ip_address'] ?? '';
    // allow only IPv4/IPv6/hostname-safe characters
    $ip   = preg_replace('/[^0-9a-zA-Z.:\-]/', '', $ip);
    if (!$ip) { echo json_encode(['ok'=>false,'err'=>'Node has no IP']); exit; }

    // 2 quick echo requests, 1s deadline each — low latency for a live loop.
    $cmd  = "/usr/bin/ping -c 2 -W 1 -n " . escapeshellarg($ip) . " 2>&1";
    $out  = shell_exec($cmd);
    $loss = 100.0; $avg = null;
    if (preg_match('/(\d+(?:\.\d+)?)%\s*packet loss/', $out, $m)) $loss = (float)$m[1];
    if (preg_match('#=\s*[\d.]+/([\d.]+)/#', $out, $m))           $avg  = (float)$m[1];
    $up = $loss < 100.0;

    // Use the DB clock (NOW()) so recorded_at matches the background poller and the
    // dashboard freshness check (TIMESTAMPDIFF vs NOW()) — avoids PHP-local vs MySQL
    // timezone skew that made fresh pings look stale on the dashboard.
    $lat = $avg !== null ? $avg : 'NULL';
    $conn->query("INSERT INTO nm_ping_stats (node_id, recorded_at, is_up, latency_ms, packet_loss)
                  VALUES ({$nm_node_id}, NOW(), " . ($up ? 1 : 0) . ", {$lat}, {$loss})");

    echo json_encode([
        'ok'      => true,
        'up'      => $up,
        'latency' => $avg,
        'loss'    => $loss,
        'ts'      => date('H:i:s'),
    ]);
    exit;
}

// ── Page load ─────────────────────────────────────────────────────────────────
$node = null;
if ($nm_node_id) {
    $nr = $conn->query("SELECT id, display_name, ip_address, os_icon,
                               COALESCE(monitor_type,'snmp') monitor_type
                        FROM nm_nodes WHERE id={$nm_node_id} LIMIT 1");
    $node = $nr ? $nr->fetch_assoc() : null;
}

// Picker for the no-selection state — list ping nodes first, then everything else
$pick = [];
$pr = $conn->query("SELECT id, display_name, ip_address, COALESCE(monitor_type,'snmp') mt
                    FROM nm_nodes WHERE ip_address IS NOT NULL AND ip_address<>''
                    ORDER BY (monitor_type='ping') DESC, display_name");
if ($pr) while ($r = $pr->fetch_assoc()) $pick[] = $r;

// Recent ping history (seed the live chart so it isn't empty on open)
$seed = [];
if ($nm_node_id) {
    $sr = $conn->query("SELECT recorded_at, is_up, latency_ms
                        FROM nm_ping_stats WHERE node_id={$nm_node_id}
                        ORDER BY id DESC LIMIT 60");
    if ($sr) { while ($r = $sr->fetch_assoc()) $seed[] = $r; $seed = array_reverse($seed); }
}

$host      = $node ? htmlspecialchars($node['display_name']) : 'Select a device';
$ip_addr   = htmlspecialchars($node['ip_address'] ?? '');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';

include('header.php');
log_user_action($conn, 'view_page', 'live_ping.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Live Ping Monitor<?= $node ? ' — '.$host : '' ?></title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="/chart.umd.min.js"></script>
<script src="/chartjs-adapter-date-fns.bundle.min.js"></script>
<style>
:root{ --glass:rgba(255,255,255,.08); --border:rgba(255,255,255,.15); --accent:#4da3ff; --up:#2ecc71; --down:#e74c3c; --warn:#f39c12; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#fff; overflow-x:hidden; }
#bg-video{ position:fixed; top:0; left:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.35; }
.page-wrapper{ max-width:1300px; margin:0 auto; padding:20px; box-sizing:border-box; }
.glass-card{ background:var(--glass); backdrop-filter:blur(20px); border:1px solid var(--border); border-radius:15px; padding:18px; }
.top-row{ display:grid; grid-template-columns:1fr auto; gap:12px; align-items:center; margin-bottom:14px; }
.title{ margin:0; font-size:22px; letter-spacing:-.4px; }
.sub{ font-size:12px; color:#9aa0a6; margin-top:4px; }
.btn{ background:rgba(77,163,255,.18); border:1px solid var(--accent); color:var(--accent); padding:8px 12px; border-radius:8px; cursor:pointer; font-size:12px; text-decoration:none; display:inline-flex; gap:8px; align-items:center; }
.btn:hover{ background:var(--accent); color:#000; }
.btn.ghost{ background:rgba(255,255,255,.05); border-color:var(--border); color:#bbb; }
.btn.ghost:hover{ background:rgba(255,255,255,.12); color:#fff; }

.status-hero{ display:flex; align-items:center; gap:18px; flex-wrap:wrap; margin-bottom:14px; }
.status-badge{ font-size:26px; font-weight:800; padding:10px 22px; border-radius:14px; display:inline-flex; align-items:center; gap:12px; letter-spacing:1px; }
.status-up{ background:rgba(46,204,113,.15); color:var(--up); border:1px solid rgba(46,204,113,.4); }
.status-down{ background:rgba(231,76,60,.15); color:var(--down); border:1px solid rgba(231,76,60,.4); }
.status-unknown{ background:rgba(255,255,255,.06); color:#888; border:1px solid var(--border); }
.live-dot{ width:9px; height:9px; border-radius:50%; background:var(--up); display:inline-block; animation:pulse 1.4s infinite; }
.live-dot.off{ background:#777; animation:none; }
@keyframes pulse{ 0%,100%{box-shadow:0 0 0 0 rgba(46,204,113,.7)} 50%{box-shadow:0 0 0 7px rgba(46,204,113,0)} }

.stat-grid{ display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin:4px 0 14px; }
.stat{ background:rgba(255,255,255,.05); border:1px solid var(--border); border-radius:10px; padding:12px; }
.lbl{ font-size:10px; text-transform:uppercase; letter-spacing:1px; color:#8a8a8a; margin-bottom:6px; }
.val{ font-size:20px; font-weight:700; }

.poll-bar{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-bottom:12px; }
.poll-label{ font-size:10px; text-transform:uppercase; letter-spacing:.8px; color:#555; }
.chart-area{ position:relative; height:300px; padding:6px; }
select{ background:rgba(0,0,0,.4); border:1px solid var(--border); color:#ddd; border-radius:7px; padding:7px 10px; font-size:12px; }

@media(max-width:1000px){ .stat-grid{ grid-template-columns:repeat(2,1fr); } .top-row{ grid-template-columns:1fr; } }
</style>
</head>
<body>
<video autoplay muted loop playsinline id="bg-video">
    <source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4">
</video>

<div class="page-wrapper">
<?php if (!$node): ?>
    <!-- No selection — picker -->
    <div class="glass-card">
        <div class="top-row">
            <div><h1 class="title"><i class="fas fa-satellite-dish" style="color:var(--accent)"></i> Live Ping Monitor</h1>
                 <div class="sub">Real-time ICMP reachability — pick a device to watch.</div></div>
            <a class="btn ghost" href="net_mon.php"><i class="fas fa-arrow-left"></i> Dashboard</a>
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:8px;">
            <select id="pick" onchange="if(this.value)location.href='live_ping.php?node='+this.value;">
                <option value="">— select a device —</option>
                <?php foreach ($pick as $p): ?>
                <option value="<?= (int)$p['id'] ?>"><?= htmlspecialchars($p['display_name']) ?> (<?= htmlspecialchars($p['ip_address']) ?>)<?= $p['mt']==='ping'?' · ping-only':'' ?></option>
                <?php endforeach; ?>
            </select>
        </div>
    </div>
<?php else: ?>
    <div class="glass-card">
        <div class="top-row">
            <div>
                <h1 class="title"><i class="fas fa-satellite-dish" style="color:var(--accent)"></i> <?= $host ?></h1>
                <div class="sub"><i class="fas fa-network-wired"></i> <?= $ip_addr ?>
                    <?= $node['monitor_type']==='ping' ? '· ping-only node' : '· ICMP view' ?></div>
            </div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
                <a class="btn ghost" href="net_mon_stats.php?node=<?= $nm_node_id ?>"><i class="fas fa-chart-area"></i> History</a>
                <a class="btn ghost" href="net_mon.php"><i class="fas fa-arrow-left"></i> Dashboard</a>
            </div>
        </div>

        <div class="status-hero">
            <div id="status-badge" class="status-badge status-unknown"><i class="fas fa-circle-notch fa-spin"></i> CHECKING</div>
            <div style="font-size:12px;color:#888;">
                <span id="live-dot" class="live-dot"></span>
                <span id="live-text">Live — pinging every <span id="iv-text">2</span>s</span>
            </div>
        </div>

        <div class="stat-grid">
            <div class="stat"><div class="lbl"><i class="fas fa-stopwatch"></i> Current RTT</div><div class="val" id="v-cur" style="color:var(--accent)">—</div></div>
            <div class="stat"><div class="lbl"><i class="fas fa-arrow-down"></i> Min</div><div class="val" id="v-min">—</div></div>
            <div class="stat"><div class="lbl"><i class="fas fa-equals"></i> Avg</div><div class="val" id="v-avg">—</div></div>
            <div class="stat"><div class="lbl"><i class="fas fa-arrow-up"></i> Max</div><div class="val" id="v-max">—</div></div>
            <div class="stat"><div class="lbl"><i class="fas fa-percent"></i> Loss (session)</div><div class="val" id="v-loss" style="color:var(--down)">—</div></div>
        </div>

        <div class="poll-bar">
            <button class="btn" id="btn-pause" onclick="togglePause()"><i class="fas fa-pause"></i> Pause</button>
            <span class="poll-label">Interval</span>
            <select id="iv" onchange="setIv()">
                <option value="1000">1s</option>
                <option value="2000" selected>2s</option>
                <option value="5000">5s</option>
                <option value="10000">10s</option>
            </select>
            <span class="poll-label" style="margin-left:auto;">Sent <b id="c-sent">0</b> · Lost <b id="c-lost" style="color:var(--down)">0</b> · Last <span id="c-last">—</span></span>
        </div>

        <div class="glass-card" style="padding:8px;">
            <div class="chart-area"><canvas id="chart-ping"></canvas></div>
        </div>
    </div>
<?php endif; ?>
</div>

<?php if ($node): ?>
<script>
const NODE_ID = <?= $nm_node_id ?>;
let intervalMs = 2000, timer = null, paused = false;
let sent = 0, lost = 0;
let rttMin = null, rttMax = null, rttSum = 0, rttN = 0;

// Seed from recent history
const SEED = <?= json_encode($seed) ?>;
const labels = [], rttData = [];
// recorded_at is stored in UTC (DB session is +00:00) — append 'Z' so the browser
// parses it as UTC and renders it in local time, instead of mislabeling it by the
// timezone offset (which also caused the live points to bridge a 4h gap = the "fan").
SEED.forEach(s => {
    labels.push(new Date(s.recorded_at.replace(' ','T')+'Z'));
    rttData.push(s.is_up == 1 && s.latency_ms !== null ? +s.latency_ms : null);
});
// Track the last plotted time so we can render an HONEST gap (not a flat bridge)
// whenever the live loop stalls — e.g. the browser throttles this 2s timer while
// the tab is in the background. Persistent history lives in the poller (History).
let lastPlotMs = SEED.length ? new Date(SEED[SEED.length-1].recorded_at.replace(' ','T')+'Z').getTime() : Date.now();

Chart.defaults.color = '#666';
const ctx = document.getElementById('chart-ping').getContext('2d');
function grad(){ const g=ctx.createLinearGradient(0,0,0,300);
    g.addColorStop(0,'rgba(77,163,255,.35)'); g.addColorStop(.7,'rgba(77,163,255,.05)'); g.addColorStop(1,'rgba(77,163,255,0)'); return g; }
const chart = new Chart(ctx, {
    type:'line',
    data:{ labels, datasets:[{
        label:'RTT (ms)', data:rttData, borderColor:'#4da3ff', backgroundColor:grad(),
        borderWidth:2, pointRadius:0, tension:.35, fill:true, spanGaps:false }] },
    options:{
        responsive:true, maintainAspectRatio:false, animation:false,
        interaction:{ mode:'index', intersect:false },
        plugins:{ legend:{ display:false },
            tooltip:{ callbacks:{ label:c => c.parsed.y==null?'timeout':(c.parsed.y.toFixed(2)+' ms') } } },
        scales:{
            x:{ type:'time', time:{ tooltipFormat:'HH:mm:ss', displayFormats:{ second:'HH:mm:ss', minute:'HH:mm' } },
                grid:{ color:'rgba(255,255,255,.04)' }, ticks:{ color:'#555', maxTicksLimit:8 } },
            y:{ beginAtZero:true, grid:{ color:'rgba(255,255,255,.04)' },
                ticks:{ color:'#555', callback:v=>v+' ms' }, title:{ display:true, text:'latency', color:'#555' } }
        }
    }
});

function fmtMs(v){ return v==null ? '—' : (+v).toFixed(2)+' ms'; }
function setStatus(up, checking){
    const b = document.getElementById('status-badge');
    if (checking){ b.className='status-badge status-unknown'; b.innerHTML='<i class="fas fa-circle-notch fa-spin"></i> CHECKING'; return; }
    if (up){ b.className='status-badge status-up'; b.innerHTML='<i class="fas fa-check-circle"></i> UP'; }
    else   { b.className='status-badge status-down'; b.innerHTML='<i class="fas fa-times-circle"></i> DOWN'; }
}

async function doPing(){
    try{
        const r = await fetch('live_ping.php?api=ping&node='+NODE_ID+'&_='+Date.now()).then(r=>r.json());
        if(!r.ok){ return; }
        sent++;
        const up = r.up, rtt = (up && r.latency!=null) ? +r.latency : null;
        if(!up) lost++;
        setStatus(up, false);

        // stats
        if(rtt!=null){ rttMin = rttMin==null?rtt:Math.min(rttMin,rtt); rttMax = rttMax==null?rtt:Math.max(rttMax,rtt); rttSum+=rtt; rttN++; }
        document.getElementById('v-cur').textContent  = up ? fmtMs(rtt) : 'timeout';
        document.getElementById('v-cur').style.color  = up ? 'var(--accent)' : 'var(--down)';
        document.getElementById('v-min').textContent  = fmtMs(rttMin);
        document.getElementById('v-max').textContent  = fmtMs(rttMax);
        document.getElementById('v-avg').textContent  = rttN ? fmtMs(rttSum/rttN) : '—';
        document.getElementById('v-loss').textContent = sent ? ((lost/sent*100).toFixed(1)+'%') : '—';
        document.getElementById('c-sent').textContent = sent;
        document.getElementById('c-lost').textContent = lost;
        document.getElementById('c-last').textContent = new Date().toLocaleTimeString();

        // chart push (cap 120 points). If the loop stalled (tab backgrounded /
        // paused), insert a null break so the line shows a real gap instead of a
        // misleading flat bridge across the missing time.
        const nowMs = Date.now();
        if (nowMs - lastPlotMs > Math.max(3*intervalMs, 15000)) {
            chart.data.labels.push(new Date(lastPlotMs + intervalMs));
            chart.data.datasets[0].data.push(null);
        }
        lastPlotMs = nowMs;
        chart.data.labels.push(new Date(nowMs));
        chart.data.datasets[0].data.push(rtt);
        while(chart.data.labels.length > 130){ chart.data.labels.shift(); chart.data.datasets[0].data.shift(); }
        chart.update('none');
    }catch(e){ /* keep looping */ }
}

function loop(){ clearTimeout(timer); if(paused) return;
    doPing().finally(()=>{ if(!paused) timer = setTimeout(loop, intervalMs); }); }

function togglePause(){
    paused = !paused;
    const b = document.getElementById('btn-pause'), d = document.getElementById('live-dot'), t = document.getElementById('live-text');
    if(paused){ b.innerHTML='<i class="fas fa-play"></i> Resume'; d.classList.add('off'); t.textContent='Paused'; clearTimeout(timer); }
    else { b.innerHTML='<i class="fas fa-pause"></i> Pause'; d.classList.remove('off'); t.innerHTML='Live — pinging every <span id="iv-text">'+(intervalMs/1000)+'</span>s'; loop(); }
}
function setIv(){ intervalMs = +document.getElementById('iv').value;
    const e=document.getElementById('iv-text'); if(e) e.textContent=(intervalMs/1000);
    if(!paused) loop(); }

// Don't fire the 2s loop into a backgrounded tab (browsers throttle it anyway,
// which is what produced the flat "blank" stretches). Stop on hide, resume on show.
document.addEventListener('visibilitychange', () => {
    if (document.hidden) { clearTimeout(timer); }
    else if (!paused)    { loop(); }   // doPing() inserts a gap break for the stall
});

setStatus(false, true);
loop();
</script>
<?php endif; ?>
</body>
</html>
