<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Thresholds & Sensitivity (Site Configuration)
// One place to tune EVERY alarm threshold so the portal errs toward NOT crying wolf.
// Anomaly grading (CPU/memory/disk levels), reboot-detection window, latency/loss
// alert thresholds, incident minimum-severity, and AI-insight auto-expiry TTL.
// Stored in nm_settings (thr_* + ai_insight_ttl_hours) and nm_latency_thresholds(0).
// Read by: nm_ai_ingest.php (nm_ai_thr), nm_incidents.php, nm_smokeping.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'net_mon_config')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'err'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=thresholds'); exit;
}

// Defaults (deliberately NON-sensitive). key => [default, min, max].
$DEF = [
    'thr_cpu_info'=>[70,1,100],  'thr_cpu_warn'=>[85,1,100],  'thr_cpu_crit'=>[95,1,100],
    'thr_mem_info'=>[80,1,100],  'thr_mem_warn'=>[90,1,100],  'thr_mem_crit'=>[97,1,100],
    'thr_disk_info'=>[80,1,100], 'thr_disk_warn'=>[90,1,100], 'thr_disk_crit'=>[96,1,100],
    'thr_reboot_max_h'=>[12,1,720], 'thr_reboot_warn_h'=>[3,0,168],
    'ai_insight_ttl_hours'=>[6,1,168],
];
// latency globals live in nm_latency_thresholds(node_id=0)
$LAT_DEF = ['rtt_warn'=>120,'rtt_crit'=>300,'loss_warn'=>5,'loss_crit'=>15];

if ($api === 'load') {
    header('Content-Type: application/json');
    $vals = [];
    foreach ($DEF as $k=>$m) $vals[$k] = $m[0];
    if ($r = $conn->query("SELECT setting_key,setting_val FROM nm_settings WHERE setting_key LIKE 'thr\\_%' OR setting_key='ai_insight_ttl_hours'"))
        while ($x=$r->fetch_assoc()) if (isset($vals[$x['setting_key']]) && $x['setting_val']!=='') $vals[$x['setting_key']] = $x['setting_val'];
    $vals['thr_incident_min_sev'] = 'warning';
    if ($r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='thr_incident_min_sev' LIMIT 1"))
        if ($x=$r->fetch_row()) { $v=strtolower(trim((string)$x[0])); if (in_array($v,['info','warning','critical'],true)) $vals['thr_incident_min_sev']=$v; }
    $lat = $LAT_DEF;
    @$conn->query("CREATE TABLE IF NOT EXISTS nm_latency_thresholds (node_id INT PRIMARY KEY, rtt_warn DOUBLE NULL, rtt_crit DOUBLE NULL, loss_warn DOUBLE NULL, loss_crit DOUBLE NULL) ENGINE=InnoDB");
    if ($r = $conn->query("SELECT rtt_warn,rtt_crit,loss_warn,loss_crit FROM nm_latency_thresholds WHERE node_id=0 LIMIT 1"))
        if ($x=$r->fetch_assoc()) foreach ($LAT_DEF as $k=>$d) if ($x[$k]!==null) $lat[$k]=$x[$k];
    echo json_encode(['ok'=>true,'vals'=>$vals,'lat'=>$lat]);
    exit;
}

if ($api === 'save') {
    header('Content-Type: application/json');
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') { echo json_encode(['ok'=>false,'err'=>'POST required']); exit; }
    $b = json_decode(file_get_contents('php://input'), true) ?? [];
    $st = $conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
    foreach ($DEF as $k=>$m) {
        if (!array_key_exists($k,$b)) continue;
        $v = (float)$b[$k]; $v = max($m[1], min($m[2], $v));
        $vs = (string)(($v == (int)$v) ? (int)$v : $v);
        $st->bind_param('ss', $k, $vs); $st->execute();
    }
    // incident min severity
    $ms = strtolower(trim((string)($b['thr_incident_min_sev'] ?? 'warning')));
    if (!in_array($ms,['info','warning','critical'],true)) $ms='warning';
    $kk='thr_incident_min_sev'; $st->bind_param('ss',$kk,$ms); $st->execute();
    $st->close();
    // latency globals (node_id=0) — clamp + warn<crit
    $rw=max(1,(float)($b['rtt_warn']??120)); $rc=max($rw+1,(float)($b['rtt_crit']??300));
    $lw=max(0,min(100,(float)($b['loss_warn']??5))); $lc=max($lw+0.1,min(100,(float)($b['loss_crit']??15)));
    @$conn->query("CREATE TABLE IF NOT EXISTS nm_latency_thresholds (node_id INT PRIMARY KEY, rtt_warn DOUBLE NULL, rtt_crit DOUBLE NULL, loss_warn DOUBLE NULL, loss_crit DOUBLE NULL) ENGINE=InnoDB");
    $ls = $conn->prepare("INSERT INTO nm_latency_thresholds (node_id,rtt_warn,rtt_crit,loss_warn,loss_crit) VALUES (0,?,?,?,?)
                          ON DUPLICATE KEY UPDATE rtt_warn=VALUES(rtt_warn),rtt_crit=VALUES(rtt_crit),loss_warn=VALUES(loss_warn),loss_crit=VALUES(loss_crit)");
    $ls->bind_param('dddd',$rw,$rc,$lw,$lc); $ls->execute(); $ls->close();
    nm_audit($conn, 'thresholds.save', ['target_type'=>'settings','details'=>['min_sev'=>$ms]]);
    echo json_encode(['ok'=>true]);
    exit;
}

log_user_action($conn, 'view_page', 'thresholds.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Thresholds & Sensitivity | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" media="print" onload="this.media='all'">
<noscript><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"></noscript>
<style>
:root{ --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.13); }
html{ background:#05080f; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; color:#e7ecf3; background:transparent!important; }
.wrap{ max-width:920px; margin:0 auto; padding:22px 20px 80px; }
h1{ font-size:21px; display:flex; align-items:center; gap:11px; }
h1 .sub{ font-size:12px; color:#8a93a3; font-weight:400; }
.card{ background:var(--glass); border:1px solid var(--border); border-radius:15px; padding:18px 20px; margin-bottom:16px; }
.card h2{ font-size:15px; margin:0 0 4px; display:flex; align-items:center; gap:9px; }
.card .hint{ font-size:12.5px; color:#8a93a3; margin:0 0 14px; line-height:1.55; }
.grid{ display:flex; gap:18px; flex-wrap:wrap; }
.fld{ display:flex; flex-direction:column; gap:5px; min-width:150px; }
.fld label{ font-size:11.5px; color:#9fb0c4; text-transform:uppercase; letter-spacing:.5px; }
.fld .row{ display:flex; align-items:center; gap:8px; }
.fld input[type=number]{ width:78px; background:#0d1422; color:#e7ecf3; border:1px solid var(--border); border-radius:8px; padding:8px 10px; font-size:14px; }
.fld .u{ font-size:12px; color:#778; }
.fld .lvl{ font-size:9.5px; font-weight:700; padding:1px 7px; border-radius:5px; }
.lvl.info{ color:var(--accent); background:rgba(77,163,255,.14);} .lvl.warn{ color:var(--warn); background:rgba(243,156,18,.14);} .lvl.crit{ color:var(--crit); background:rgba(231,76,60,.14);}
select{ background:#0d1422; color:#e7ecf3; border:1px solid var(--border); border-radius:8px; padding:9px 12px; font-size:14px; }
.bar{ position:sticky; bottom:0; background:linear-gradient(180deg,transparent,#05080f 40%); padding:16px 0 6px; display:flex; gap:12px; align-items:center; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.45); color:#9cc7ff; padding:11px 22px; border-radius:10px; font-size:14px; font-weight:700; cursor:pointer; }
.btn:hover{ background:var(--accent); color:#04243f; }
.btn.ghost{ background:transparent; border-color:var(--border); color:#bcc8d6; font-weight:400; }
.msg{ font-size:13px; }
</style>
</head>
<body>
<?php include('header.php'); ?>
<div class="wrap">
  <h1><i class="fas fa-sliders" style="color:var(--accent);"></i> Thresholds &amp; Sensitivity
      <span class="sub">tune every alarm so the portal errs toward NOT crying wolf</span></h1>

  <div class="card">
    <h2><i class="fas fa-microchip" style="color:var(--accent);"></i> CPU</h2>
    <p class="hint">A CPU anomaly only matters when utilisation is actually HIGH. A z-spike at low load (1%→3%) is noise and is dropped. Set the absolute % levels below which CPU is never alarmed.</p>
    <div class="grid">
      <div class="fld"><label><span class="lvl info">INFO</span> at or above</label><div class="row"><input type="number" id="thr_cpu_info"><span class="u">%</span></div></div>
      <div class="fld"><label><span class="lvl warn">WARNING</span> at or above</label><div class="row"><input type="number" id="thr_cpu_warn"><span class="u">%</span></div></div>
      <div class="fld"><label><span class="lvl crit">CRITICAL</span> at or above</label><div class="row"><input type="number" id="thr_cpu_crit"><span class="u">%</span></div></div>
    </div>
  </div>

  <div class="card">
    <h2><i class="fas fa-memory" style="color:var(--accent);"></i> Memory</h2>
    <p class="hint">Memory is graded by absolute usage and only when it is CLIMBING toward full — a usage drop (e.g. 45%→9%) is relief, never an alarm. Below the INFO level nothing fires.</p>
    <div class="grid">
      <div class="fld"><label><span class="lvl info">INFO</span> at or above</label><div class="row"><input type="number" id="thr_mem_info"><span class="u">%</span></div></div>
      <div class="fld"><label><span class="lvl warn">WARNING</span> at or above</label><div class="row"><input type="number" id="thr_mem_warn"><span class="u">%</span></div></div>
      <div class="fld"><label><span class="lvl crit">CRITICAL</span> at or above</label><div class="row"><input type="number" id="thr_mem_crit"><span class="u">%</span></div></div>
    </div>
  </div>

  <div class="card">
    <h2><i class="fas fa-hard-drive" style="color:var(--accent);"></i> Disk / Storage</h2>
    <p class="hint">Same logic as memory — only rising disk usage toward full is alarmed.</p>
    <div class="grid">
      <div class="fld"><label><span class="lvl info">INFO</span> at or above</label><div class="row"><input type="number" id="thr_disk_info"><span class="u">%</span></div></div>
      <div class="fld"><label><span class="lvl warn">WARNING</span> at or above</label><div class="row"><input type="number" id="thr_disk_warn"><span class="u">%</span></div></div>
      <div class="fld"><label><span class="lvl crit">CRITICAL</span> at or above</label><div class="row"><input type="number" id="thr_disk_crit"><span class="u">%</span></div></div>
    </div>
  </div>

  <div class="card">
    <h2><i class="fas fa-power-off" style="color:var(--accent);"></i> Reboot detection</h2>
    <p class="hint">A device is only flagged "recently rebooted" when its uptime is genuinely small — NOT merely below a noisy hourly baseline (which falsely flagged boxes up 5 days). Above the window, the event is ignored. Reboots are always <b>informational</b> (they never open an incident).</p>
    <div class="grid">
      <div class="fld"><label>Only flag if uptime under</label><div class="row"><input type="number" id="thr_reboot_max_h"><span class="u">hours</span></div></div>
    </div>
  </div>

  <div class="card">
    <h2><i class="fas fa-wave-square" style="color:var(--accent);"></i> Latency &amp; packet loss (global default)</h2>
    <p class="hint">Default thresholds for every Smokeping target (per-node overrides set on the Smokeping page win). 1% loss was far too sensitive — most paths blip ≥1%. These apply to all nodes without an override.</p>
    <div class="grid">
      <div class="fld"><label><span class="lvl warn">WARNING</span> RTT over</label><div class="row"><input type="number" id="rtt_warn"><span class="u">ms</span></div></div>
      <div class="fld"><label><span class="lvl crit">CRITICAL</span> RTT over</label><div class="row"><input type="number" id="rtt_crit"><span class="u">ms</span></div></div>
      <div class="fld"><label><span class="lvl warn">WARNING</span> loss over</label><div class="row"><input type="number" id="loss_warn" step="0.5"><span class="u">%</span></div></div>
      <div class="fld"><label><span class="lvl crit">CRITICAL</span> loss over</label><div class="row"><input type="number" id="loss_crit" step="0.5"><span class="u">%</span></div></div>
    </div>
  </div>

  <div class="card">
    <h2><i class="fas fa-triangle-exclamation" style="color:var(--accent);"></i> Incident sensitivity</h2>
    <p class="hint">The minimum AI-insight severity allowed to open an incident on the Incident Command page. Keep at <b>Warning</b> so informational findings (e.g. "recently rebooted") never arm an incident.</p>
    <div class="grid">
      <div class="fld"><label>Open incidents from</label>
        <select id="thr_incident_min_sev">
          <option value="info">Info and above (most sensitive)</option>
          <option value="warning">Warning and above (recommended)</option>
          <option value="critical">Critical only (least sensitive)</option>
        </select></div>
      <div class="fld"><label>Auto-resolve stale AI insights after</label><div class="row"><input type="number" id="ai_insight_ttl_hours"><span class="u">hours</span></div></div>
    </div>
  </div>

  <div class="bar">
    <button class="btn" onclick="save()"><i class="fas fa-floppy-disk"></i> Save thresholds</button>
    <button class="btn ghost" onclick="load()">Reset to current</button>
    <span class="msg" id="msg"></span>
  </div>
</div>

<script>
const KEYS=['thr_cpu_info','thr_cpu_warn','thr_cpu_crit','thr_mem_info','thr_mem_warn','thr_mem_crit',
  'thr_disk_info','thr_disk_warn','thr_disk_crit','thr_reboot_max_h','ai_insight_ttl_hours'];
const LAT=['rtt_warn','rtt_crit','loss_warn','loss_crit'];
async function load(){
  const r=await fetch('thresholds.php?api=load&_='+Date.now()).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok){ msg('Could not load','crit'); return; }
  KEYS.forEach(k=>{ if(document.getElementById(k)) document.getElementById(k).value=r.vals[k]; });
  document.getElementById('thr_incident_min_sev').value=r.vals.thr_incident_min_sev||'warning';
  LAT.forEach(k=>{ if(document.getElementById(k)) document.getElementById(k).value=r.lat[k]; });
  msg('Loaded current values','ok');
}
async function save(){
  const body={};
  KEYS.forEach(k=>body[k]=document.getElementById(k).value);
  LAT.forEach(k=>body[k]=document.getElementById(k).value);
  body.thr_incident_min_sev=document.getElementById('thr_incident_min_sev').value;
  msg('Saving…','');
  const r=await fetch('thresholds.php?api=save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(r=>r.json()).catch(()=>({ok:false}));
  if(r.ok){ msg('✓ Saved — new alarms use these thresholds; existing ones re-evaluate within a minute.','ok'); }
  else msg('Save failed: '+(r.err||'unknown'),'crit');
}
function msg(t,c){ const m=document.getElementById('msg'); m.textContent=t; m.style.color=c==='ok'?'var(--ok)':(c==='crit'?'var(--crit)':'#8a93a3'); }
load();
</script>
</body>
</html>
