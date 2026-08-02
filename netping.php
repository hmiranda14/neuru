<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Live Ping (Net Tools). Streams ping output in real time over SSE and
// charts RTT live. RBAC: 'nettools_ping'. Engine: nm_nettools.php.
// Ad-hoc / interactive — distinct from Smokeping (scheduled latency history).
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_nettools.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'nettools_ping')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=nettools_ping'); exit;
}
nm_nt_ensure($conn);
$EMBED = (($_GET['embed'] ?? '') === '1');   // Commander overlay → strip chrome + autostart from ?target

// ── SSE stream: ping <target>, one event per reply/timeout ────────────────────
if ($api === 'stream') {
    $target = nm_nt_valid_target($_GET['target'] ?? '');
    if (!$target) { http_response_code(400); header('Content-Type: text/plain'); echo 'invalid target'; exit; }
    @set_time_limit(0);
    while (ob_get_level()) ob_end_flush();
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('X-Accel-Buffering: no');
    @ini_set('zlib.output_compression', '0');
    $send = function($ev, $data){ echo "event: {$ev}\ndata: ".json_encode($data)."\n\n"; @ob_flush(); @flush(); };
    log_user_action($conn, 'nettools_ping', $target);

    // argv (no shell). -O prints a line on timeout too; -n no rDNS; -i 1 one/sec.
    $proc = @proc_open(['ping','-O','-n','-i','1','-W','2',$target], [1=>['pipe','w'],2=>['pipe','w']], $pipes);
    if (!is_resource($proc)) { $send('error', ['msg'=>'cannot start ping']); exit; }
    stream_set_blocking($pipes[1], false);
    $send('start', ['target'=>$target]);
    $start = time(); $rxbuf = '';
    while (true) {
        if (connection_aborted()) break;
        if (time() - $start > 180) { $send('done', ['reason'=>'time limit (180s)']); break; }
        $rxbuf .= (string)stream_get_contents($pipes[1]);
        while (($nl = strpos($rxbuf, "\n")) !== false) {
            $line = substr($rxbuf, 0, $nl); $rxbuf = substr($rxbuf, $nl + 1);
            if (preg_match('/icmp_seq=(\d+).*ttl=(\d+).*time=([\d.]+)/', $line, $m)) {
                $send('reply', ['seq'=>(int)$m[1],'ttl'=>(int)$m[2],'rtt'=>(float)$m[3]]);
            } elseif (preg_match('/no answer yet for icmp_seq=(\d+)/', $line, $m)) {
                $send('loss', ['seq'=>(int)$m[1]]);
            } elseif (stripos($line,'unreachable')!==false || stripos($line,'failure')!==false) {
                $send('reply', ['error'=>trim($line)]);
            }
        }
        if (!proc_get_status($proc)['running'] && $rxbuf === '') break;
        usleep(150000);
    }
    if (is_resource($proc)) { @proc_terminate($proc); @fclose($pipes[1]); @fclose($pipes[2]); @proc_close($proc); }
    $send('done', ['reason'=>'stopped']);
    exit;
}

log_user_action($conn,'view_page','netping.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Live Ping | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="/chart.umd.min.js"></script>
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; }
*,*::before,*::after{ box-sizing:border-box; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.18; }
.wrap{ max-width:1100px; margin:0 auto; padding:18px 20px 40px; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.bar{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:16px; }
input.t{ background:#1b2129; color:#e6e9ee; border:1px solid var(--border); border-radius:9px; padding:10px 14px; font-size:14px; min-width:260px; font-family:monospace; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:10px 16px; font-size:13px; cursor:pointer; }
.btn:hover{ background:rgba(77,163,255,.25); } .btn.stop{ background:rgba(231,76,60,.15); border-color:rgba(231,76,60,.45); color:#f0a59d; }
.kpis{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin-bottom:16px; }
.kpi{ padding:12px; text-align:center; } .kpi .n{ font-size:22px; font-weight:800; } .kpi .l{ font-size:10px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; }
.muted{ color:#7c828c; font-size:12px; } #log{ font-family:monospace; font-size:12px; max-height:180px; overflow:auto; }
#log div.loss{ color:#f0a59d; } .dot{ display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px; }
<?= nm_chrome_css() ?>
body.embed{ background:transparent !important; padding-top:0 !important; } body.embed #nm-topbar,body.embed #bg-video,body.embed video{ display:none !important; } body.embed .wrap{ padding:8px 12px 12px !important; max-width:none !important; }
</style></head><body class="<?= $EMBED?'embed':'' ?>">
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php if(!$EMBED) nm_page_header('<i class="fas fa-tower-broadcast"></i>Live Ping', '', 'Net Tools · real-time', 'fa-solid fa-tower-broadcast',''); ?>

<div class="bar">
  <input class="t" id="target" placeholder="host or IP (e.g. 8.8.8.8)" value="8.8.8.8" onkeydown="if(event.key==='Enter')start()">
  <button class="btn" id="go" onclick="start()"><i class="fas fa-play"></i> Start</button>
  <button class="btn stop" id="stopb" onclick="stop()" style="display:none;"><i class="fas fa-stop"></i> Stop</button>
  <span class="muted" id="status"><span class="dot" style="background:#555;"></span>idle</span>
</div>

<div class="kpis">
  <div class="glass kpi"><div class="n" id="k-last" style="color:var(--accent)">—</div><div class="l">last ms</div></div>
  <div class="glass kpi"><div class="n" id="k-min">—</div><div class="l">min</div></div>
  <div class="glass kpi"><div class="n" id="k-avg">—</div><div class="l">avg</div></div>
  <div class="glass kpi"><div class="n" id="k-max">—</div><div class="l">max</div></div>
  <div class="glass kpi"><div class="n" id="k-loss" style="color:var(--crit)">0%</div><div class="l">loss</div></div>
</div>

<div class="glass card"><canvas id="chart" height="90"></canvas></div>
<div class="glass card"><div id="log"><span class="muted">Enter a host and press Start.</span></div></div>
</div>
<script>
let es=null, chart=null, sent=0, recv=0, rtts=[], labels=[], data=[];
function setStatus(c,t){ document.getElementById('status').innerHTML='<span class="dot" style="background:'+c+';"></span>'+t; }
function initChart(){
  if(chart) chart.destroy();
  chart=new Chart(document.getElementById('chart'),{type:'line',data:{labels,datasets:[{label:'RTT ms',data,borderColor:'#4da3ff',backgroundColor:'rgba(77,163,255,.15)',fill:true,tension:.3,pointRadius:0,spanGaps:false}]},
    options:{animation:false,responsive:true,scales:{x:{ticks:{color:'#8a909a',maxTicksLimit:10}},y:{beginAtZero:true,ticks:{color:'#8a909a'}}},plugins:{legend:{display:false}}}});
}
function logln(html,cls){ const l=document.getElementById('log'); if(l.querySelector('.muted'))l.innerHTML=''; const d=document.createElement('div'); if(cls)d.className=cls; d.innerHTML=html; l.prepend(d); while(l.childElementCount>300)l.lastChild.remove(); }
function fmt(n){ return n==null?'—':(+n).toFixed(1); }
function stats(){
  const k=document.getElementById('k-loss'); const loss=sent? Math.round((sent-recv)/sent*100):0; k.textContent=loss+'%';
  if(rtts.length){ document.getElementById('k-min').textContent=fmt(Math.min(...rtts)); document.getElementById('k-max').textContent=fmt(Math.max(...rtts));
    document.getElementById('k-avg').textContent=fmt(rtts.reduce((a,b)=>a+b,0)/rtts.length); }
}
function start(){
  const t=document.getElementById('target').value.trim(); if(!t)return;
  stop(); sent=recv=0; rtts=[]; labels.length=0; data.length=0; initChart();
  document.getElementById('go').style.display='none'; document.getElementById('stopb').style.display='inline-block';
  setStatus('#f39c12','connecting…');
  es=new EventSource('netping.php?api=stream&target='+encodeURIComponent(t));
  es.addEventListener('start',e=>{ setStatus('#2ecc71','pinging '+JSON.parse(e.data).target); });
  es.addEventListener('reply',e=>{ const d=JSON.parse(e.data); sent++;
    if(d.error){ logln('✗ '+d.error,'loss'); stats(); return; }
    recv++; rtts.push(d.rtt); document.getElementById('k-last').textContent=fmt(d.rtt);
    labels.push('#'+d.seq); data.push(d.rtt); if(labels.length>120){labels.shift();data.shift();} chart.update();
    logln('seq='+d.seq+' ttl='+d.ttl+' <b>'+fmt(d.rtt)+' ms</b>'); stats(); });
  es.addEventListener('loss',e=>{ const d=JSON.parse(e.data); sent++; labels.push('#'+d.seq); data.push(null); if(labels.length>120){labels.shift();data.shift();} chart.update();
    logln('seq='+d.seq+' <b>timeout</b>','loss'); stats(); });
  es.addEventListener('error',e=>{ try{logln('✗ '+JSON.parse(e.data).msg,'loss');}catch(_){ } });
  es.addEventListener('done',e=>{ setStatus('#555','stopped'); cleanup(); });
  es.onerror=()=>{ setStatus('#e74c3c','disconnected'); };
}
function cleanup(){ if(es){es.close();es=null;} document.getElementById('go').style.display='inline-block'; document.getElementById('stopb').style.display='none'; }
function stop(){ cleanup(); if(document.getElementById('status').textContent.indexOf('idle')<0 && !es) setStatus('#555','stopped'); }
initChart();
</script>
<script>window.addEventListener("DOMContentLoaded",function(){var q=new URLSearchParams(location.search),tg=q.get("target");if(tg){var i=document.getElementById("target");if(i){i.value=tg;}if(q.get("autostart")==="1"){var f=window.trace||window.start||window.lookup||window.run;if(f)setTimeout(f,350);}}});</script>
</body></html>
