<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — SLA, Capacity & Reports (Pillar 4). Gated by permission 'reports'.
// ─────────────────────────────────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) session_start();
include_once __DIR__ . '/connection.php';
require_once __DIR__ . '/access_control.php';
require_once __DIR__ . '/nm_sla.php';
require_once __DIR__ . '/nm_chrome.php';

if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$CSRF = $_SESSION['csrf_token'];

// ── Report export: Excel (.xls, HTML-table — zero deps) + print-to-PDF view ──
if (isset($_GET['export'])) {
    if (empty($_SESSION['username']) || !checkAccess($conn, 'reports')) { http_response_code(403); exit('Unauthorized'); }
    $fmt = (string)$_GET['export'];
    $range = (string)($_GET['range'] ?? '30d'); if (!in_array($range, ['24h','7d','30d'], true)) $range = '30d';
    $mins = nm_sla_mins($range);
    $plabel = ['24h'=>'Last 24 hours','7d'=>'Last 7 days','30d'=>'Last 30 days'][$range] ?? $range;
    $ee = fn($s)=>htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');

    if ($fmt === 'xls') {
        $sla = nm_sla_all($conn, $mins);
        $set = nm_sla_settings($conn);
        $cap = nm_cap_forecast($conn, 30, (float)($set['cap_threshold'] ?? 85), 200);
        header('Content-Type: application/vnd.ms-excel; charset=utf-8');
        header('Content-Disposition: attachment; filename="NEURU-report-'.date('Ymd-His').'.xls"');
        header('Cache-Control: no-store');
        echo "<html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:x='urn:schemas-microsoft-com:office:excel'><head><meta charset='utf-8'></head><body>";
        echo "<table border='0'><tr><td style='font-size:20px;font-weight:bold;color:#1a4f8a'>NEURU — Network Report</td></tr>";
        echo "<tr><td>Period: {$ee($plabel)} &nbsp;·&nbsp; Generated: ".date('Y-m-d H:i')."</td></tr></table><br>";
        // Availability
        echo "<table border='1' cellspacing='0' cellpadding='5'><tr style='background:#1a4f8a;color:#fff;font-weight:bold'>
            <td>Node</td><td>Type</td><td>Uptime %</td><td>Downtime (min)</td><td>Outages</td><td>SLA target %</td><td>Meets SLA</td></tr>";
        foreach ($sla as $r) {
            $bg = empty($r['meets']) ? "background:#ffd9d9" : "";
            echo "<tr style='$bg'><td>{$ee($r['display_name'])}</td><td>{$ee($r['monitor_type']??'')}</td>"
               . "<td>".number_format((float)($r['uptime']??0),3)."</td><td>".(int)($r['down_min']??0)."</td>"
               . "<td>".(int)($r['outages']??0)."</td><td>".$ee($r['target']??'')."</td><td>".(empty($r['meets'])?'NO':'yes')."</td></tr>";
        }
        echo "</table><br>";
        // Capacity
        echo "<table border='1' cellspacing='0' cellpadding='5'><tr style='background:#1a4f8a;color:#fff;font-weight:bold'>
            <td>Node</td><td>Interface</td><td>Now %</td><td>Peak %</td><td>Trend %/day</td><td>Forecast (days to full)</td></tr>";
        foreach ($cap as $c) {
            $bg = !empty($c['over']) ? "background:#fff0d9" : "";
            $eta = ($c['eta_days']===null||$c['eta_days']==='') ? '—' : (int)$c['eta_days'];
            echo "<tr style='$bg'><td>{$ee($c['node'])}</td><td>{$ee($c['iface'])}</td>"
               . "<td>".number_format((float)($c['current']??0),1)."</td><td>".number_format((float)($c['peak']??0),1)."</td>"
               . "<td>".number_format((float)($c['slope_day']??0),2)."</td><td>$eta</td></tr>";
        }
        echo "</table></body></html>";
        exit;
    }
    if ($fmt === 'pdf') {
        // A print-optimized HTML view (reuses the report engine) that opens the browser's
        // print dialog → "Save as PDF". No PDF library needed; renders exactly as designed.
        header('Content-Type: text/html; charset=utf-8');
        $body = function_exists('nm_report_html') ? nm_report_html($conn, $range) : '<p>Report unavailable.</p>';
        echo "<!doctype html><html><head><meta charset='utf-8'><title>NEURU Report — {$ee($plabel)}</title>";
        echo "<style>body{font-family:Segoe UI,Arial,sans-serif;background:#fff;color:#111;margin:0;padding:26px;}
              .nm-print-bar{position:fixed;top:0;left:0;right:0;background:#0d1526;color:#cfe4ff;padding:9px 16px;font-size:13px;display:flex;gap:12px;align-items:center;z-index:9;}
              .nm-print-bar button{background:#4da3ff;border:none;color:#fff;padding:7px 14px;border-radius:7px;cursor:pointer;font-size:13px;}
              .nm-print-body{margin-top:52px;} table{border-collapse:collapse;} @media print{.nm-print-bar{display:none;}.nm-print-body{margin-top:0;}}</style></head><body>";
        echo "<div class='nm-print-bar'>📄 NEURU Report — {$ee($plabel)} &nbsp;·&nbsp; use your browser's <b>Save as PDF</b> <button onclick='window.print()'>Print / Save PDF</button></div>";
        echo "<div class='nm-print-body'>{$body}</div>";
        echo "<script>window.addEventListener('load',()=>setTimeout(()=>window.print(),400));</script></body></html>";
        exit;
    }
    http_response_code(400); exit('Unknown export format');
}

if (isset($_GET['api']) || isset($_POST['api'])) {
    header('Content-Type: application/json');
    if (empty($_SESSION['username']) || !checkAccess($conn, 'reports')) { http_response_code(403); echo json_encode(['ok'=>false,'err'=>'Unauthorized']); exit; }
    $api = $_GET['api'] ?? $_POST['api'];
    $isPost = ($_SERVER['REQUEST_METHOD'] === 'POST');
    if ($isPost && (($_POST['csrf'] ?? '') !== $_SESSION['csrf_token'])) { http_response_code(400); echo json_encode(['ok'=>false,'err'=>'Invalid CSRF']); exit; }
    $range = $_GET['range'] ?? '7d'; $mins = nm_sla_mins($range);
    try {
        switch ($api) {
        case 'sla': {
            $rows = nm_sla_all($conn, $mins);
            $up=0;$down=0;$avg=0;$miss=0;
            foreach ($rows as $r){ if($r['last']==='up')$up++;else $down++; $avg+=$r['uptime']; if(!$r['meets'])$miss++; }
            echo json_encode(['ok'=>true,'nodes'=>$rows,'target'=>nm_sla_settings($conn)['target'],
                'stats'=>['up'=>$up,'down'=>$down,'avg'=>$rows?round($avg/count($rows),3):0,'breaching'=>$miss]]);
            break;
        }
        case 'capacity':
            echo json_encode(['ok'=>true,'interfaces'=>nm_cap_forecast($conn, max(2,(int)($mins/1440))),'threshold'=>nm_sla_settings($conn)['cap_threshold']]);
            break;
        case 'report_settings':
            echo json_encode(['ok'=>true,'settings'=>nm_sla_settings($conn)]);
            break;
        case 'report_save': {
            if (!$isPost){ echo json_encode(['ok'=>false,'err'=>'POST']); break; }
            $set=function($k,$v)use($conn){$st=$conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=?");$st->bind_param('sss',$k,$v,$v);$st->execute();$st->close();};
            $set('sla_target', (string)((float)($_POST['sla_target'] ?? 99.9)));
            $set('cap_threshold', (string)max(1,min(100,(int)($_POST['cap_threshold'] ?? 80))));
            $set('report_enabled', !empty($_POST['report_enabled'])?'1':'0');
            $set('report_freq', in_array($_POST['report_freq']??'',['daily','weekly'],true)?$_POST['report_freq']:'weekly');
            $set('report_hour', (string)max(0,min(23,(int)($_POST['report_hour']??7))));
            $set('report_dow', (string)max(1,min(7,(int)($_POST['report_dow']??1))));
            $set('report_period', in_array($_POST['report_period']??'',['24h','7d','30d'],true)?$_POST['report_period']:'7d');
            $set('report_recipients', trim($_POST['report_recipients']??''));
            echo json_encode(['ok'=>true]); break;
        }
        case 'report_preview':
            header('Content-Type: text/html; charset=utf-8');
            echo nm_report_html($conn, nm_sla_settings($conn)['period']);
            exit;
        case 'report_send': {
            if (!$isPost){ echo json_encode(['ok'=>false,'err'=>'POST']); break; }
            $r = nm_report_send($conn, trim($_POST['to'] ?? ''), nm_sla_settings($conn)['period']);
            nm_audit($conn,'report.send',['details'=>['sent'=>$r['sent']??0]]);
            echo json_encode($r); break;
        }
        default: http_response_code(400); echo json_encode(['ok'=>false,'err'=>'Unknown']);
        }
    } catch (\Throwable $e) { http_response_code(500); echo json_encode(['ok'=>false,'err'=>$e->getMessage()]); }
    exit;
}

include('check.php');
if (!checkAccess($conn, 'reports')) { header('Location: /denied_access.php?page=reports'); exit; }
include('header.php');
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SLA & Reports | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
<?= nm_chrome_css() ?>
:root{--glass:rgba(255,255,255,0.07);--border:rgba(255,255,255,0.13);--accent:#4da3ff;--up:#2ecc71;--down:#e74c3c;--warn:#f39c12;--mut:#8a909a;}
body{margin:0;font-family:'Segoe UI',Tahoma,sans-serif;background:#000;color:#fff;overflow-x:hidden;}
.wrap{max-width:1400px;margin:0 auto;padding:18px 22px 60px;}
.glass-card{background:var(--glass);backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:16px;padding:18px 20px;margin-bottom:18px;}
h2{margin:0 0 14px;font-size:14px;color:var(--accent);display:flex;align-items:center;gap:9px;}
.seg{display:inline-flex;border:1px solid var(--border);border-radius:9px;overflow:hidden;}
.seg button{background:transparent;border:none;color:var(--mut);padding:7px 14px;font-size:12px;font-weight:700;cursor:pointer;}
.seg button.on{background:var(--accent);color:#000;}
.btn{padding:8px 14px;border-radius:9px;border:1px solid var(--border);background:rgba(255,255,255,.05);color:#cfd3da;font-size:12.5px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:7px;text-decoration:none;}
.btn:hover{border-color:var(--accent);color:#fff;}
.btn-primary{background:rgba(77,163,255,.15);border-color:var(--accent);color:var(--accent);}
.btn-success{background:rgba(46,204,113,.15);border-color:var(--up);color:var(--up);}
.bento{display:grid;grid-template-columns:repeat(4,1fr);gap:13px;margin-bottom:16px;}
@media(max-width:800px){.bento{grid-template-columns:repeat(2,1fr);}}
.kpi{background:var(--glass);border:1px solid var(--border);border-radius:14px;padding:15px 18px;}
.kpi .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--mut);}
.kpi .val{font-size:28px;font-weight:800;margin-top:3px;}
table{width:100%;border-collapse:collapse;font-size:13px;}
th{text-align:left;color:var(--mut);font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.5px;padding:8px 9px;border-bottom:1px solid var(--border);}
td{padding:8px 9px;border-bottom:1px solid rgba(255,255,255,.05);}
.bar{height:7px;border-radius:4px;background:rgba(255,255,255,.07);overflow:hidden;display:inline-block;width:90px;vertical-align:middle;margin-left:8px;}
.bar i{display:block;height:100%;}
.tag{font-size:10px;padding:2px 8px;border-radius:6px;font-weight:700;}
.t-ok{background:rgba(46,204,113,.16);color:#2ecc71;}.t-bad{background:rgba(231,76,60,.18);color:#ff6b6b;}.t-warn{background:rgba(243,156,18,.18);color:#f5b73d;}
.mut{color:var(--mut);} .mono{font-family:ui-monospace,monospace;}
.fld{display:flex;flex-direction:column;gap:5px;}.fld label{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--mut);}
.form-input,.form-select{background:rgba(255,255,255,.07);border:1px solid var(--border);color:#fff;padding:8px 12px;border-radius:8px;font-size:13px;outline:none;box-sizing:border-box;width:100%;}
.form-select{background:rgba(20,30,50,.95);}
.sw{position:relative;display:inline-block;width:42px;height:23px;}.sw input{opacity:0;width:0;height:0;}
.sw .sl{position:absolute;cursor:pointer;inset:0;background:#3a3f4b;border-radius:23px;transition:.25s;}.sw .sl::before{content:'';position:absolute;width:17px;height:17px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.25s;}
.sw input:checked+.sl{background:var(--up);}.sw input:checked+.sl::before{transform:translateX(19px);}
.hidden{display:none!important;}
#toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(120%);background:#11151d;border:1px solid var(--border);border-left:4px solid var(--accent);border-radius:10px;padding:12px 18px;font-size:13px;z-index:2000;transition:.3s;}#toast.show{transform:translateX(-50%) translateY(0);}
</style>
</head>
<body>
<div class="wrap">
<?php nm_page_header('SLA', '&amp; Reports', 'Availability · Capacity · Reporting', 'fa-solid fa-gauge-high'); ?>
<?php nm_module_tabs([
    ['icon'=>'fa-solid fa-heart-pulse','label'=>'Availability (SLA)','href'=>'#sla','active'=>true],
    ['icon'=>'fa-solid fa-gauge-high','label'=>'Capacity','href'=>'#capacity','active'=>false],
    ['icon'=>'fa-solid fa-envelope-open-text','label'=>'Scheduled Reports','href'=>'#reports','active'=>false],
]); ?>

<div style="display:flex;gap:10px;align-items:center;margin-bottom:14px;" id="range-bar">
  <span class="mut" style="font-size:12px;">Period</span>
  <div class="seg" id="range-seg"><button data-r="24h">24h</button><button data-r="7d" class="on">7d</button><button data-r="30d">30d</button></div>
  <div style="margin-left:auto;display:flex;gap:8px;">
    <button onclick="location.href='reports.php?export=xls&range='+RANGE" title="Download an Excel spreadsheet of Availability + Capacity"
      style="background:rgba(33,115,70,.18);border:1px solid rgba(46,204,113,.5);color:#8ef0b8;border-radius:8px;padding:8px 13px;font-size:12.5px;cursor:pointer;"><i class="fas fa-file-excel"></i> Excel</button>
    <button onclick="window.open('reports.php?export=pdf&range='+RANGE,'_blank')" title="Open a print-ready report → Save as PDF"
      style="background:rgba(200,60,60,.16);border:1px solid rgba(231,76,60,.5);color:#ff9b91;border-radius:8px;padding:8px 13px;font-size:12.5px;cursor:pointer;"><i class="fas fa-file-pdf"></i> PDF</button>
  </div>
</div>

<!-- SLA -->
<section id="tab-sla">
  <div class="bento">
    <div class="kpi"><div class="lbl">Avg Uptime</div><div class="val" style="color:var(--accent)" id="k-avg">—</div></div>
    <div class="kpi"><div class="lbl">Nodes Up</div><div class="val" style="color:var(--up)" id="k-up">—</div></div>
    <div class="kpi"><div class="lbl">Nodes Down</div><div class="val" style="color:var(--down)" id="k-down">—</div></div>
    <div class="kpi"><div class="lbl">Breaching SLA</div><div class="val" style="color:var(--warn)" id="k-breach">—</div></div>
  </div>
  <div class="glass-card">
    <h2><i class="fa-solid fa-heart-pulse"></i> Availability vs target <span class="mut" id="sla-target" style="font-weight:400;"></span></h2>
    <div style="overflow-x:auto;"><table>
      <thead><tr><th>Node</th><th>Type</th><th>Uptime</th><th>Downtime</th><th>Outages</th><th>State</th><th>SLA</th></tr></thead>
      <tbody id="sla-tbody"><tr><td colspan="7" class="mut" style="text-align:center;padding:20px;">Loading…</td></tr></tbody>
    </table></div>
  </div>
</section>

<!-- CAPACITY -->
<section id="tab-capacity" class="hidden">
  <div class="glass-card">
    <h2><i class="fa-solid fa-gauge-high"></i> Interface capacity — forecast to <span id="cap-thr" class="mut" style="font-weight:400;"></span></h2>
    <div style="overflow-x:auto;"><table>
      <thead><tr><th>Interface</th><th>Now</th><th>Peak</th><th>Trend / day</th><th>Forecast</th></tr></thead>
      <tbody id="cap-tbody"><tr><td colspan="5" class="mut" style="text-align:center;padding:20px;">Loading…</td></tr></tbody>
    </table></div>
    <p class="mut" style="font-size:11px;margin-top:10px;"><i class="fa-solid fa-circle-info"></i> Forecast = linear trend of utilization; “~Nd” = days until the link crosses the threshold at the current growth rate.</p>
  </div>
</section>

<!-- REPORTS -->
<section id="tab-reports" class="hidden">
  <div class="glass-card">
    <h2><i class="fa-solid fa-envelope-open-text"></i> Scheduled email report</h2>
    <p class="mut" style="font-size:12px;margin:-8px 0 14px;">A network summary (uptime, capacity, incidents) emailed on a schedule via your SMTP. Configure SMTP in <a href="net_mon_config.php?tab=integrations" style="color:var(--accent);">Config → Integrations → SMTP</a>.</p>
    <div style="display:flex;align-items:center;gap:14px;margin-bottom:14px;">
      <label style="display:flex;align-items:center;gap:9px;"><span class="sw"><input type="checkbox" id="r-enabled"><span class="sl"></span></span><b style="font-size:13px;">Enable scheduled report</b></label>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:14px;">
      <div class="fld"><label>Frequency</label><select class="form-select" id="r-freq" onchange="dowVis()"><option value="daily">Daily</option><option value="weekly">Weekly</option></select></div>
      <div class="fld" id="r-dow-wrap"><label>Day of week</label><select class="form-select" id="r-dow"><option value="1">Monday</option><option value="2">Tuesday</option><option value="3">Wednesday</option><option value="4">Thursday</option><option value="5">Friday</option><option value="6">Saturday</option><option value="7">Sunday</option></select></div>
      <div class="fld"><label>Hour (0–23)</label><input class="form-input" type="number" id="r-hour" min="0" max="23" value="7"></div>
      <div class="fld"><label>Report period</label><select class="form-select" id="r-period"><option value="24h">Last 24h</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option></select></div>
    </div>
    <div class="fld" style="margin-bottom:14px;"><label>Recipients (comma-separated)</label><input class="form-input" type="text" id="r-recipients" placeholder="boss@company.com, noc@company.com"></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">
      <div class="fld"><label>SLA target (%)</label><input class="form-input" type="number" step="0.01" id="r-sla" value="99.9"></div>
      <div class="fld"><label>Capacity threshold (%)</label><input class="form-input" type="number" id="r-cap" value="80"></div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;">
      <button class="btn btn-success" onclick="saveReport()"><i class="fa-solid fa-floppy-disk"></i> Save</button>
      <button class="btn" onclick="previewReport()"><i class="fa-solid fa-eye"></i> Preview</button>
      <button class="btn btn-primary" onclick="sendNow()"><i class="fa-solid fa-paper-plane"></i> Send now</button>
    </div>
  </div>
  <div class="glass-card hidden" id="preview-card">
    <h2><i class="fa-solid fa-eye"></i> Preview</h2>
    <iframe id="preview-frame" style="width:100%;height:620px;border:1px solid var(--border);border-radius:10px;background:#fff;"></iframe>
  </div>
</section>
</div>

<div id="toast"></div>
<script>
const CSRF='<?= $CSRF ?>'; let RANGE='7d';
function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2600);}
function utilColor(v){ return v>=80?'#e74c3c':v>=60?'#f39c12':'#2ecc71'; }
async function api(a,data){ let opt={}; if(data){const fd=new FormData();fd.append('api',a);fd.append('csrf',CSRF);for(const k in data)fd.append(k,data[k]);opt={method:'POST',body:fd};}
  const r=await fetch('reports.php?api='+a+'&range='+RANGE,opt); const j=await r.json().catch(()=>({ok:false,err:'bad'})); if(!r.ok||j.err){toast(j.err||('HTTP '+r.status));throw new Error(j.err);} return j; }

document.querySelectorAll('.nm-tab').forEach(t=>t.addEventListener('click',e=>{e.preventDefault();
  document.querySelectorAll('.nm-tab').forEach(x=>x.classList.remove('is-active'));t.classList.add('is-active');
  const id=t.getAttribute('href').slice(1); ['sla','capacity','reports'].forEach(s=>document.getElementById('tab-'+s).classList.toggle('hidden',s!==id));
  document.getElementById('range-bar').style.display = (id==='reports')?'none':'flex';
  if(id==='sla')loadSla(); if(id==='capacity')loadCap(); if(id==='reports')loadReport();
}));
document.querySelectorAll('#range-seg button').forEach(b=>b.addEventListener('click',()=>{
  document.querySelectorAll('#range-seg button').forEach(x=>x.classList.remove('on'));b.classList.add('on');RANGE=b.dataset.r;
  if(!document.getElementById('tab-sla').classList.contains('hidden'))loadSla(); else if(!document.getElementById('tab-capacity').classList.contains('hidden'))loadCap();
}));

async function loadSla(){
  const d=await api('sla');
  document.getElementById('k-avg').textContent=d.stats.avg+'%';
  document.getElementById('k-up').textContent=d.stats.up;
  document.getElementById('k-down').textContent=d.stats.down;
  document.getElementById('k-breach').textContent=d.stats.breaching;
  document.getElementById('sla-target').textContent='(target '+d.target+'%)';
  document.getElementById('sla-tbody').innerHTML = d.nodes.length ? d.nodes.map(n=>{
    const col=n.meets?'#2ecc71':'#e74c3c';
    return `<tr>
      <td><b>${esc(n.display_name)}</b><div class="mut mono" style="font-size:10px;">${esc(n.ip_address||'')}</div></td>
      <td class="mut">${esc(n.monitor_type)}</td>
      <td style="color:${col};font-weight:700;">${n.uptime}%<span class="bar"><i style="width:${Math.min(100,n.uptime)}%;background:${col};"></i></span></td>
      <td>${n.down_min} min</td><td>${n.outages}</td>
      <td>${n.last==='up'?'<span class="tag t-ok">up</span>':'<span class="tag t-bad">down</span>'}</td>
      <td>${n.meets?'<span class="tag t-ok">met</span>':'<span class="tag t-bad">breach</span>'}</td></tr>`;
  }).join('') : '<tr><td colspan="7" class="mut" style="text-align:center;padding:20px;">No availability data yet.</td></tr>';
}
async function loadCap(){
  const d=await api('capacity'); document.getElementById('cap-thr').textContent=d.threshold+'%';
  document.getElementById('cap-tbody').innerHTML = d.interfaces.length ? d.interfaces.map(c=>{
    const fc = c.over?`<span class="tag t-bad">over ${d.threshold}%</span>`:(c.eta_days!=null?`<span class="tag t-warn">~${c.eta_days}d to ${d.threshold}%</span>`:'<span class="tag t-ok">stable</span>');
    return `<tr><td><b>${esc(c.node)}</b> <span class="mut mono">· ${esc(c.iface)}</span></td>
      <td style="color:${utilColor(c.current)};font-weight:700;">${c.current}%<span class="bar"><i style="width:${Math.min(100,c.current)}%;background:${utilColor(c.current)};"></i></span></td>
      <td>${c.peak}%</td><td class="mono">${c.slope_day>0?'+':''}${c.slope_day}%</td><td>${fc}</td></tr>`;
  }).join('') : '<tr><td colspan="5" class="mut" style="text-align:center;padding:20px;"><i class="fa-solid fa-circle-check" style="color:var(--up);"></i> No utilization data yet.</td></tr>';
}
function dowVis(){ document.getElementById('r-dow-wrap').style.display = document.getElementById('r-freq').value==='weekly'?'':'none'; }
async function loadReport(){
  const d=await api('report_settings'); const s=d.settings;
  document.getElementById('r-enabled').checked=s.enabled; document.getElementById('r-freq').value=s.freq;
  document.getElementById('r-dow').value=s.dow||1; document.getElementById('r-hour').value=s.hour;
  document.getElementById('r-period').value=s.period; document.getElementById('r-recipients').value=s.recipients||'';
  document.getElementById('r-sla').value=s.target; document.getElementById('r-cap').value=s.cap_threshold; dowVis();
}
async function saveReport(){
  await api('report_save',{report_enabled:document.getElementById('r-enabled').checked?1:'',report_freq:document.getElementById('r-freq').value,
    report_dow:document.getElementById('r-dow').value,report_hour:document.getElementById('r-hour').value,report_period:document.getElementById('r-period').value,
    report_recipients:document.getElementById('r-recipients').value.trim(),sla_target:document.getElementById('r-sla').value,cap_threshold:document.getElementById('r-cap').value});
  toast('Saved');
}
function previewReport(){ document.getElementById('preview-card').classList.remove('hidden'); document.getElementById('preview-frame').src='reports.php?api=report_preview&_='+Date.now(); }
async function sendNow(){ const to=document.getElementById('r-recipients').value.trim();
  toast('Sending report…'); try{ const r=await api('report_send',{to}); toast(r.ok?('Report sent to '+r.sent+' recipient(s)'):('Failed: '+((r.errors&&r.errors[0])||r.err||'?'))); }catch(e){} }
loadSla();
</script>
</body></html>
