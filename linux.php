<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Linux Monitor (agentless, over SSH). RBAC: 'linux'. Engine: nm_linuxhost.php.
// Phase 1: hosts registry + journal (journalctl) + health + diagnostics + service watchdog.
// (Phases 2-4 — host health, service watchdog, AI commander — add tabs here.)
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_linuxhost.php');
include('logger.php');

$api = $_GET['api'] ?? '';
$act = $_POST['action'] ?? '';
if (!checkAccess($conn, 'linux')) {
    if ($api || $act) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=linux'); exit;
}
nm_lx_ensure($conn);
if (function_exists('session_write_close')) @session_write_close(); // free session lock before slow SSH/n8n I/O (prevents whole-portal freeze)

$uid = (int)($_SESSION['user_id'] ?? 0) ?: null;

if ($act !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if ($act === 'host_add')    { $r=nm_lx_host_add($conn,$_POST,$uid); log_user_action($conn,'lx_host_add',$_POST['name']??''); echo json_encode($r); exit; }
    if ($act === 'host_update') { echo json_encode(nm_lx_host_update($conn,(int)($_POST['id']??0),$_POST)); exit; }
    if ($act === 'host_delete') { echo json_encode(nm_lx_host_delete($conn,(int)($_POST['id']??0))); exit; }
    if ($act === 'poll')        { $h=nm_lx_host($conn,(int)($_POST['id']??0)); echo json_encode($h?nm_lx_poll_events($conn,$h):['ok'=>false,'error'=>'no host']); exit; }
    if ($act === 'poll_health') { $h=nm_lx_host($conn,(int)($_POST['id']??0)); echo json_encode($h?nm_lx_poll_health($conn,$h):['ok'=>false,'error'=>'no host']); exit; }
    if ($act === 'watch_add')   { echo json_encode(nm_lx_watch_add($conn,(int)($_POST['host_id']??0),$_POST,$uid)); exit; }
    if ($act === 'watch_update'){ echo json_encode(nm_lx_watch_update($conn,(int)($_POST['id']??0),$_POST)); exit; }
    if ($act === 'watch_delete'){ echo json_encode(nm_lx_watch_delete($conn,(int)($_POST['id']??0))); exit; }
    if ($act === 'svc_action')  { log_user_action($conn,'lx_svc_'.($_POST['act']??''),($_POST['svc']??'').' on host '.($_POST['host_id']??'')); echo json_encode(nm_lx_service_action_by_id($conn,(int)($_POST['host_id']??0),(string)($_POST['svc']??''),(string)($_POST['act']??'start'),$uid)); exit; }
    if ($act === 'watch_check') { $h=nm_lx_host($conn,(int)($_POST['id']??0)); echo json_encode($h?nm_lx_watch_check($conn,$h):['ok'=>false,'error'=>'no host']); exit; }
    if ($act === 'kill_proc')   { $h=nm_lx_host($conn,(int)($_POST['host_id']??0)); log_user_action($conn,'lx_kill_proc',($_POST['name']??'').' on host '.($_POST['host_id']??'')); echo json_encode($h?nm_lx_kill_process($conn,$h,(string)($_POST['name']??''),$uid):['ok'=>false,'error'=>'no host']); exit; }
    if ($act === 'layout_save') {  // per-user floating-widget layout for the Command Center
        $conn->query("CREATE TABLE IF NOT EXISTS nm_lx_layout (uid INT PRIMARY KEY, layout TEXT, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $u=(int)($uid ?? 0); $lay=(string)($_POST['layout'] ?? '');
        if (!$u || strlen($lay)>60000) { echo json_encode(['ok'=>false]); exit; }
        $dec=json_decode($lay,true); if(!is_array($dec)){ echo json_encode(['ok'=>false]); exit; }
        $je=$conn->real_escape_string(json_encode($dec,JSON_UNESCAPED_SLASHES));
        $conn->query("INSERT INTO nm_lx_layout (uid,layout) VALUES ({$u},'{$je}') ON DUPLICATE KEY UPDATE layout=VALUES(layout)");
        echo json_encode(['ok'=>true]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'unknown action']); exit;
}
if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if ($api === 'hosts')   { echo json_encode(['ok'=>true,'hosts'=>nm_lx_hosts($conn)]); exit; }
    if ($api === 'health')  { echo json_encode(nm_lx_health_get($conn,(int)($_GET['host']??0))); exit; }
    if ($api === 'watches') { echo json_encode(['ok'=>true,'watches'=>nm_lx_watches($conn,(int)($_GET['host']??0)),'actions'=>nm_lx_actions_recent($conn,(int)($_GET['host']??0),20)]); exit; }
    if ($api === 'services_live') { $h=nm_lx_host($conn,(int)($_GET['host']??0)); echo json_encode($h?nm_lx_services_live($conn,$h):['ok'=>false,'error'=>'no host']); exit; }
    if ($api === 'diag') { $h=nm_lx_host($conn,(int)($_GET['host']??0)); log_user_action($conn,'lx_diag',$h['name']??('host '.($_GET['host']??''))); echo json_encode($h?nm_lx_diagnose($conn,$h):['ok'=>false,'error'=>'no host']); exit; }
    if ($api === 'ifaces') {   // monitored LAN interfaces (+ recent traffic) of the host's node
        $h = nm_lx_host($conn,(int)($_GET['host']??0));
        $nid = $h ? (int)($h['node_id'] ?? 0) : 0;
        if (!$nid) { echo json_encode(['ok'=>true,'node_id'=>0,'ifaces'=>[]]); exit; }
        $out = [];
        $ir = $conn->query("SELECT id, COALESCE(NULLIF(display_name,''),if_name) name, if_ip_address ip
                            FROM nm_interfaces WHERE node_id={$nid} AND show_graph=1 ORDER BY sort_order,id LIMIT 24");
        while ($ir && ($x = $ir->fetch_assoc())) {
            $pid = (int)$x['id'];
            $sr  = $conn->query("SELECT in_rate,out_rate,oper_status,if_speed FROM nm_port_stats WHERE port_id={$pid} ORDER BY recorded_at DESC LIMIT 24");
            $rows = $sr ? array_reverse($sr->fetch_all(MYSQLI_ASSOC)) : [];   // oldest→newest
            $latest = $rows ? end($rows) : null;
            $out[] = [
                'name'=>$x['name'], 'ip'=>$x['ip'],
                'oper'=>$latest['oper_status'] ?? null, 'if_speed'=>$latest ? (float)$latest['if_speed'] : 0,
                'in_rate'=>$latest ? (float)$latest['in_rate'] : 0, 'out_rate'=>$latest ? (float)$latest['out_rate'] : 0,
                'in_series'=>array_map(fn($r)=>(float)$r['in_rate'], $rows),
                'out_series'=>array_map(fn($r)=>(float)$r['out_rate'], $rows),
            ];
        }
        echo json_encode(['ok'=>true,'node_id'=>$nid,'ifaces'=>$out]); exit;
    }
    if ($api === 'layout_get') {
        $conn->query("CREATE TABLE IF NOT EXISTS nm_lx_layout (uid INT PRIMARY KEY, layout TEXT, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $u=(int)($uid ?? 0); $r=$u?$conn->query("SELECT layout FROM nm_lx_layout WHERE uid={$u}"):null;
        $row=$r?$r->fetch_assoc():null; $lay=($row && $row['layout'])?json_decode($row['layout'],true):null;
        echo json_encode(['ok'=>true,'layout'=>is_array($lay)?$lay:null]); exit;
    }
    if ($api === 'events')  { echo json_encode(['ok'=>true,
        'events'=>nm_lx_events($conn,(int)($_GET['host']??0),['lv'=>$_GET['lv']??'','level'=>$_GET['level']??'','log'=>$_GET['log']??'','q'=>$_GET['q']??'','limit'=>(int)($_GET['limit']??200)]),
        'summary'=>nm_lx_event_summary($conn,(int)($_GET['host']??0))]); exit; }
    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}

log_user_action($conn,'view_page','linux.php');
$nodes = [];
$nr = $conn->query("SELECT id,display_name,ip_address,os_icon FROM nm_nodes ORDER BY display_name LIMIT 1000");
while ($nr && ($x=$nr->fetch_assoc())) $nodes[] = $x;
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Linux Monitor | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --win:#0078d4; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.18; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 40px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:8px 14px; font-size:13px; cursor:pointer; }
.btn:hover{ background:rgba(77,163,255,.25); } .btn.ghost{ background:transparent; border-color:var(--border); color:#aab; } .btn.sm{ padding:3px 9px; font-size:11px; }
.btn.danger{ color:#f0a59d; border-color:rgba(231,76,60,.4); }
.tabs{ display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap; }
.tab{ background:rgba(255,255,255,.05); border:1px solid var(--border); color:#aab; padding:9px 18px; border-radius:10px; cursor:pointer; font-size:13px; font-weight:600; }
.tab.active{ background:rgba(0,120,212,.18); border-color:var(--win); color:#7fc1ff; }
.tab.soon{ opacity:.5; cursor:default; }
.tp{ display:none; } .tp.active{ display:block; }
.hgrid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(300px,1fr)); gap:14px; margin-bottom:16px; }
.hcard{ padding:13px 15px; }
.hcard .nm{ font-size:15px; font-weight:800; } .hcard .meta{ font-size:11px; color:#8a909a; margin:4px 0; }
.st{ font-size:11px; font-weight:700; } .st.ok{ color:var(--ok);} .st.error{ color:var(--crit);} .st.new{ color:#8a909a;} .st.down{ color:var(--crit); }
@keyframes nmdownpulse{0%,100%{opacity:1}50%{opacity:.45}} .st.down{ animation:nmdownpulse 1.6s infinite; }
.kpis{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:12px; }
.kpi{ flex:1; min-width:120px; padding:12px 14px; text-align:center; } .kpi .n{ font-size:24px; font-weight:800; } .kpi .l{ font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; }
.bar-ctl{ display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:10px; }
.bar-ctl select,.bar-ctl input{ background:#1b2129; color:#e6e9ee; border:1px solid var(--border); border-radius:8px; padding:7px 10px; font-size:12.5px; }
table{ width:100%; border-collapse:collapse; font-size:12.5px; }
th{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; padding:7px 9px; border-bottom:1px solid var(--border); }
td{ padding:7px 9px; border-bottom:1px solid rgba(255,255,255,.05); vertical-align:top; }
tr.lv1 td:first-child,tr.lv2 td:first-child{ border-left:3px solid var(--crit); } tr.lv3 td:first-child{ border-left:3px solid var(--warn); }
.lvb{ font-size:10px; font-weight:700; padding:2px 7px; border-radius:5px; white-space:nowrap; }
.lvb.l1{ background:rgba(231,76,60,.2); color:#f0a59d; } .lvb.l2{ background:rgba(231,76,60,.14); color:#e88; } .lvb.l3{ background:rgba(243,156,18,.16); color:#f0c674; }
.msg{ max-width:560px; color:#c7ccd3; cursor:pointer; }
.muted{ color:#7c828c; font-size:12px; } .mono{ font-family:monospace; }
.modal-bg{ position:fixed; inset:0; background:rgba(0,0,0,.6); z-index:90; display:none; align-items:flex-start; justify-content:center; padding-top:7vh; overflow:auto; }
.modal{ width:520px; max-width:95vw; padding:22px 24px; } .modal h3{ margin:0 0 14px; }
.modal label{ display:block; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; margin:10px 0 4px; }
.modal input,.modal select{ width:100%; background:rgba(255,255,255,.06); color:#e6e9ee; border:1px solid var(--border); border-radius:8px; padding:9px 11px; font-size:13px; }
.row{ display:flex; gap:10px; } .row>div{ flex:1; }
.actions{ display:flex; gap:10px; justify-content:flex-end; margin-top:18px; align-items:center; }
.tt{ display:inline-block; font-size:10px; font-weight:700; padding:2px 8px; border-radius:20px; background:rgba(0,120,212,.18); color:#7fc1ff; }
select option{ background:#1b2129; color:#e6e9ee; }
.hsecs{ display:grid; grid-template-columns:repeat(auto-fill,minmax(330px,1fr)); gap:14px; }
.hsec{ padding:14px 16px; } .hsec h4{ margin:0 0 10px; font-size:12px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; }
.kv{ display:flex; justify-content:space-between; font-size:12.5px; padding:3px 0; } .kv b{ color:#e6e9ee; font-weight:600; }
.gbar{ height:8px; border-radius:6px; background:rgba(255,255,255,.08); overflow:hidden; margin:3px 0 2px; } .gbar>i{ display:block; height:100%; border-radius:6px; }
.chip{ display:inline-block; font-size:11px; border:1px solid var(--border); border-radius:11px; padding:2px 9px; margin:3px 4px 0 0; }
.chip.good{ border-color:rgba(46,204,113,.4); color:#9fe0b0; } .chip.bad{ border-color:rgba(231,76,60,.45); color:#f0a59d; } .chip.warnc{ border-color:rgba(243,156,18,.45); color:#f0c674; }
.step{ font-size:13px; margin:10px 0 5px; }
.codebox{ display:flex; align-items:center; gap:8px; background:#0a0d12; border:1px solid var(--border); border-radius:9px; padding:9px 11px; }
.codebox code{ flex:1; font-family:Consolas,monospace; font-size:12px; color:#bfe8c9; white-space:pre-wrap; word-break:break-all; }
.cbtn{ background:rgba(255,255,255,.06); border:1px solid var(--border); color:#aab; border-radius:7px; padding:4px 9px; cursor:pointer; font-size:11px; flex:0 0 auto; }
.cbtn:hover{ color:#fff; border-color:var(--accent); }
.hidefor{ display:none; }
.dgs-row{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:14px; }
.dg{ padding:12px 14px; text-align:center; } .dgl{ font-size:10px; text-transform:uppercase; letter-spacing:1px; color:#8a909a; }
.dgv{ font-size:26px; font-weight:800; line-height:1.2; margin:2px 0; } .dgs{ font-size:11px; }
.dverdict{ margin-bottom:14px; display:flex; flex-direction:column; gap:7px; }
.dvline{ display:flex; gap:9px; align-items:flex-start; font-size:13px; line-height:1.45; } .dvline b{ color:#fff; }
.dbar{ margin-bottom:9px; } .dbl{ display:flex; justify-content:space-between; font-size:12.5px; margin-bottom:2px; } .dbl b{ color:#e6e9ee; font-weight:600; }
.killb{ background:rgba(231,76,60,.12); border:1px solid rgba(231,76,60,.4); color:#f0a59d; border-radius:6px; padding:1px 7px; margin-left:8px; cursor:pointer; font-size:10.5px; font-weight:600; vertical-align:middle; }
.killb:hover{ background:var(--crit); color:#fff; border-color:var(--crit); }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fab fa-linux"></i>Linux Monitor', '', 'Agentless over SSH', 'fa-brands fa-linux',
    '<button class="refresh-btn" onclick="loadHosts();loadEvents()"><i class="fas fa-rotate"></i> Refresh</button>'); ?>

<div class="glass card" style="padding:11px 16px;"><div class="muted"><i class="fas fa-circle-info"></i>
  NEURU reads each Linux box's <b>journal/syslog</b> (and CPU/mem/disk/services/sensors) via <b>bash over SSH</b> — native tools (<code>journalctl</code>, <code>free</code>, <code>df</code>, <code>ps</code>, <code>systemctl</code>, <code>sensors</code>). Add a host below; it uses that node's SSH credential. Critical/Error/Warning journal entries are pulled every couple of minutes. <span style="color:#6f7d92;">(Built so a future <b>Grafana Alloy</b> source can replace SSH without changing this UI.)</span>
  &nbsp;<a href="#" onclick="openSsh();return false;"><i class="fas fa-circle-question"></i> SSH &amp; sudo setup</a></div></div>

<div class="tabs">
  <div class="tab active" data-t="hosts" onclick="showTab('hosts')"><i class="fas fa-server"></i> Hosts</div>
  <div class="tab" data-t="diag" onclick="showTab('diag')"><i class="fas fa-stethoscope"></i> Troubleshoot</div>
  <div class="tab" data-t="events" onclick="showTab('events')"><i class="fas fa-file-lines"></i> Event Log</div>
  <div class="tab" data-t="health" onclick="showTab('health')"><i class="fas fa-heart-pulse"></i> Health</div>
  <div class="tab" data-t="services" onclick="showTab('services')"><i class="fas fa-gears"></i> Service Watchdog</div>
</div>

<div id="tp-hosts" class="tp active">
  <div style="margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap;">
    <button class="btn" onclick="openHost()"><i class="fas fa-plus"></i> Add Linux host</button>
    <button class="btn ghost" onclick="openSsh()"><i class="fab fa-linux"></i> SSH &amp; sudo setup</button>
  </div>
  <div class="hgrid" id="hosts"><div class="muted">Loading…</div></div>
</div>

<div id="tp-events" class="tp">
  <div class="kpis">
    <div class="glass kpi"><div class="n" id="k-crit" style="color:var(--crit)">—</div><div class="l">Critical (24h)</div></div>
    <div class="glass kpi"><div class="n" id="k-err" style="color:#e88">—</div><div class="l">Errors (24h)</div></div>
    <div class="glass kpi"><div class="n" id="k-warn" style="color:var(--warn)">—</div><div class="l">Warnings (24h)</div></div>
  </div>
  <div class="glass card">
    <div class="bar-ctl">
      <select id="f-host" onchange="loadEvents()"><option value="0">All hosts</option></select>
      <select id="f-lv" onchange="loadEvents()"><option value="">All levels</option><option value="1">Critical</option><option value="2">Error</option><option value="3">Warning</option></select>
      <select id="f-log" onchange="loadEvents()"><option value="">All logs</option><option value="System">System</option><option value="Application">Application</option></select>
      <input id="f-q" placeholder="search message / provider / id" style="flex:1;min-width:160px;" oninput="debLoad()">
      <button class="btn ghost sm" onclick="loadEvents()"><i class="fas fa-rotate"></i></button>
    </div>
    <div style="overflow-x:auto;"><table><thead><tr><th>When</th><th>Level</th><th>Host</th><th>Log</th><th>Event</th><th>Source</th><th>Message</th></tr></thead>
      <tbody id="ev-body"><tr><td colspan="7" class="muted">Loading…</td></tr></tbody></table></div>
  </div>
</div>

<div id="tp-health" class="tp">
  <div class="bar-ctl">
    <select id="h-sel" onchange="loadHealth()"></select>
    <button class="btn sm" onclick="refreshHealth()"><i class="fas fa-satellite-dish"></i> Refresh now</button>
    <span class="muted" id="h-when" style="align-self:center;"></span>
  </div>
  <div id="health"><div class="glass card muted">Pick a host.</div></div>
</div>

<div id="tp-services" class="tp">
  <div class="bar-ctl">
    <select id="s-sel" onchange="loadWatches()"></select>
    <button class="btn" onclick="openPicker()"><i class="fas fa-plus"></i> Watch a service</button>
    <button class="btn ghost sm" onclick="checkWatch()"><i class="fas fa-satellite-dish"></i> Check now</button>
    <span class="muted" id="s-msg" style="align-self:center;"></span>
  </div>
  <div class="glass card" style="padding:10px 14px;"><div class="muted" style="font-size:12px;"><i class="fas fa-shield-halved"></i>
    Pick the services that must stay running. NEURU checks them every couple of minutes. Turn on <b>Auto-restart</b> for a service and NEURU will <b>Start it over SSH</b> when it's found stopped (5-minute backoff so it never loops). Auto-restart is <b>off by default</b> — every action is audited below.</div></div>
  <div class="glass card" style="overflow-x:auto;"><table><thead><tr>
    <th>Service</th><th>State</th><th>Auto-restart</th><th>Restarts</th><th>Last action</th><th></th></tr></thead>
    <tbody id="watch-body"><tr><td colspan="6" class="muted">Pick a host.</td></tr></tbody></table></div>
  <h3 style="font-size:12px;color:var(--win);text-transform:uppercase;letter-spacing:1px;margin:18px 0 8px;">Action log (audit)</h3>
  <div class="glass card" style="overflow-x:auto;"><table><thead><tr><th>When</th><th>Service</th><th>Action</th><th>Result</th><th>Detail</th></tr></thead>
    <tbody id="act-body"><tr><td colspan="5" class="muted">—</td></tr></tbody></table></div>
</div>

<div id="tp-diag" class="tp">
  <div class="glass card" style="padding:10px 14px;"><div class="muted" style="font-size:12px;"><i class="fas fa-stethoscope"></i>
    Live deep-dive over SSH — runs a 0.7s snapshot on the box and shows <b>exactly what is consuming memory, CPU and network right now</b> (processes aggregated by name, with live CPU% and throughput), plus disks and <b>fan RPM / temperatures</b>. Nothing is installed on the host; nothing is stored — it's a point-in-time probe you can re-run. <span class="muted">Fans/temps come from <b>lm-sensors</b> (<code>apt install lm-sensors &amp;&amp; sensors-detect</code>); network talkers need <code>ss</code> + sudo.</span></div></div>
  <div class="bar-ctl">
    <select id="d-sel" onchange="clearDiag()"></select>
    <button class="btn" onclick="runDiag()"><i class="fas fa-satellite-dish"></i> Run live diagnostics</button>
    <label class="muted" style="display:flex;gap:6px;align-items:center;font-size:12px;"><input type="checkbox" id="d-auto" style="width:auto;" onchange="toggleDiagAuto()"> auto every 15s</label>
    <span class="muted" id="d-msg" style="align-self:center;"></span>
  </div>
  <div id="diag"><div class="glass card muted">Pick a host and hit <b>Run live diagnostics</b>.</div></div>
</div>
</div>

<!-- host modal -->
<div class="modal-bg" id="hbg"><div class="glass modal">
  <h3 id="h-title">Add Linux host</h3>
  <input type="hidden" id="h-id">
  <label>Name</label><input id="h-name" placeholder="WIN-DESKTOP-01">
  <div class="row">
    <div><label>Monitored node (SSH)</label><select id="h-node" onchange="alloyPrefill(true)"><option value="">— pick a node —</option>
      <?php foreach($nodes as $n): ?><option value="<?= (int)$n['id'] ?>" data-ip="<?= htmlspecialchars($n['ip_address']) ?>"><?= htmlspecialchars($n['display_name']) ?> (<?= htmlspecialchars($n['ip_address']) ?>)</option><?php endforeach; ?></select></div>
    <div><label>…or host IP</label><input id="h-host" placeholder="192.168.0.20" oninput="alloyPrefill(true)"></div>
  </div>
  <div class="row" style="margin-top:8px;">
    <div><label>Live metrics source</label><select id="h-source" onchange="srcChange()">
      <option value="ssh">SSH (bash) — full: processes, kill, services, journal</option>
      <option value="alloy">Grafana Alloy — system metrics from this box's Alloy</option></select></div>
    <div id="h-alloy-row" style="display:none;"><label>Alloy metrics URL <span class="muted">(blank = http://&lt;ip&gt;:12345/metrics)</span></label><input id="h-alloy" placeholder="http://192.168.0.240:12345/metrics"></div>
  </div>
  <p class="muted" style="margin-top:8px;"><b>SSH</b> needs sshd + a credential on the node (journal read via group <code>systemd-journal</code>; <code>sudo</code> for <code>systemctl</code> restarts). <b>Alloy</b> reads that box's Grafana Alloy directly (no SSH) but is system-level only — events/processes/kill/services still need SSH. Configure Alloy defaults in <b>Site Configuration → Grafana Alloy</b>.</p>
  <div class="actions"><span class="muted" id="h-msg" style="margin-right:auto;"></span>
    <button class="btn ghost" onclick="closeM('hbg')">Cancel</button><button class="btn" onclick="saveHost()">Save</button></div>
</div></div>

<!-- service picker modal -->
<div class="modal-bg" id="pkbg"><div class="glass modal" style="width:640px;">
  <h3><i class="fas fa-gears"></i> Watch a service</h3>
  <input id="pk-q" placeholder="filter by name / display name…" oninput="filterPicker()" style="width:100%;background:rgba(255,255,255,.06);color:#e6e9ee;border:1px solid var(--border);border-radius:8px;padding:9px 11px;font-size:13px;">
  <label style="display:flex;gap:8px;align-items:center;margin:10px 0 4px;font-size:12px;color:#aab;"><input type="checkbox" id="pk-auto" style="width:auto;"> Arm auto-restart for the ones I add (NEURU will start them if they stop)</label>
  <div id="pk-list" style="max-height:48vh;overflow:auto;margin-top:8px;"><span class="muted">Loading services from the host over SSH…</span></div>
  <div class="actions"><span class="muted" style="margin-right:auto;font-size:11px;">Don't see it? Type the exact service short-name in the box and press <b>Add by name</b>.</span>
    <button class="btn ghost" onclick="addByName()">Add by name</button><button class="btn ghost" onclick="closeM('pkbg')">Done</button></div>
</div></div>

<!-- SSH setup guide modal -->
<div class="modal-bg" id="sshbg"><div class="glass modal" style="width:680px;">
  <h3><i class="fab fa-linux" style="color:var(--win)"></i> SSH &amp; sudo setup on a Linux box</h3>
  <div style="font-size:13px;line-height:1.6;max-height:70vh;overflow:auto;padding-right:4px;">
    <p class="muted" style="margin:0 0 12px;">Most Linux distros already run <b>sshd</b>. Do this <b>on the Linux machine</b> you want NEURU to monitor.</p>

    <div class="step"><b>1 · Ensure SSH server is installed &amp; running</b> (Debian/Ubuntu):</div>
    <div class="codebox"><code id="c1">sudo apt install -y openssh-server && sudo systemctl enable --now ssh</code><button class="cbtn" onclick="cpc('c1')"><i class="fas fa-copy"></i></button></div>
    <div class="muted" style="font-size:12px;margin:4px 0 12px;">RHEL/Fedora: <code>sudo dnf install -y openssh-server &amp;&amp; sudo systemctl enable --now sshd</code></div>

    <div class="step"><b>2 · Let the SSH user read the journal</b> (so Event Log works without root):</div>
    <div class="codebox"><code id="c2">sudo usermod -aG systemd-journal,adm $USER</code><button class="cbtn" onclick="cpc('c2')"><i class="fas fa-copy"></i></button></div>

    <div class="step" style="margin-top:12px;"><b>3 · Allow service restarts</b> (Service Watchdog) — give that user passwordless sudo for systemctl:</div>
    <div class="codebox"><code id="c3">echo "$USER ALL=(root) NOPASSWD: /usr/bin/systemctl" | sudo tee /etc/sudoers.d/neuru-systemctl</code><button class="cbtn" onclick="cpc('c3')"><i class="fas fa-copy"></i></button></div>

    <div class="step" style="margin-top:12px;"><b>4 · (Optional) fans &amp; temperatures</b> — install lm-sensors:</div>
    <div class="codebox"><code id="c4">sudo apt install -y lm-sensors && sudo sensors-detect --auto</code><button class="cbtn" onclick="cpc('c4')"><i class="fas fa-copy"></i></button></div>
    <div class="muted" style="font-size:12px;margin:4px 0 12px;">Network "top talkers" also needs <code>ss</code> (iproute2, usually preinstalled) and sudo for per-process mapping.</div>

    <div class="step" style="margin-top:12px;"><b>5 · Tell NEURU the credential</b></div>
    <div class="muted" style="font-size:12.5px;margin:2px 0 12px;">In <b>Config → Integrations &amp; AI → SSH Credentials</b>, add the username + password (or key), then assign it to that node (or set it as the default). Then come back here and <b>Add Linux host</b>.</div>

    <div class="glass" style="padding:10px 12px;border-left:3px solid var(--win);">
      <b style="font-size:12px;"><i class="fas fa-lightbulb"></i> Notes</b>
      <ul style="margin:6px 0 0;padding-left:18px;font-size:12px;color:#aab;line-height:1.6;">
        <li>NEURU runs plain <b>bash over SSH</b> (no agent installed). CPU/mem/disk/processes work out of the box via <code>/proc</code>.</li>
        <li><b>Event Log</b> = <code>journalctl</code> (systemd). On non-systemd boxes it falls back gracefully (fewer events).</li>
        <li>For the <b>AI / GPU Monitor</b>: <code>nvidia-smi</code> + <code>curl</code> on PATH; for Ollama set <code>OLLAMA_HOST=0.0.0.0</code>.</li>
        <li><b>Grafana Alloy:</b> this module is built so an Alloy/Prometheus source can later replace SSH — same data, same UI.</li>
      </ul>
    </div>
  </div>
  <div class="actions"><button class="btn" onclick="closeM('sshbg')">Got it</button></div>
</div></div>

<!-- event detail modal -->
<div class="modal-bg" id="ebg"><div class="glass modal" style="width:640px;">
  <h3 id="e-title">Event</h3>
  <div id="e-meta" class="muted" style="margin-bottom:10px;"></div>
  <pre id="e-msg" style="background:#0a0d12;border:1px solid var(--border);border-radius:10px;padding:14px;font-size:12.5px;white-space:pre-wrap;word-break:break-word;max-height:50vh;overflow:auto;"></pre>
  <div class="actions"><button class="btn ghost" onclick="copyEvt()"><i class="fas fa-copy"></i> Copy</button><button class="btn" onclick="closeM('ebg')">Done</button></div>
</div></div>

<script>
let HOSTS=[], _evtCache=[], _deb=null, autoTimer=null;
const ALLOY_PORT='<?= htmlspecialchars(_nm_lx_setting($conn,'alloy_port','12345')) ?>', ALLOY_PATH='<?= htmlspecialchars(_nm_lx_setting($conn,'alloy_path','/metrics')) ?>';
function lxNodeIp(){ const ip=(document.getElementById('h-host').value||'').trim(); if(ip)return ip; const o=document.getElementById('h-node').selectedOptions[0]; return o?(o.getAttribute('data-ip')||''):''; }
function alloyPrefill(force){ const f=document.getElementById('h-alloy'); const ip=lxNodeIp();
  if(document.getElementById('h-source').value!=='alloy')return;
  if(ip && (force||!f.value.trim())) f.value='http://'+ip+':'+ALLOY_PORT+ALLOY_PATH; }
function srcChange(){ document.getElementById('h-alloy-row').style.display=document.getElementById('h-source').value==='alloy'?'block':'none'; alloyPrefill(false); }
if(typeof window.nmLocal!=='function')   window.nmLocal=(u)=>u||'';
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function gv(id){ return document.getElementById(id).value; }
function closeM(id){ document.getElementById(id).style.display='none'; }
async function post(b){ return fetch('linux.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b}).then(r=>r.json()).catch(()=>null); }
function showTab(t){ document.querySelectorAll('.tp').forEach(p=>p.classList.remove('active')); document.querySelectorAll('.tab[data-t]').forEach(b=>b.classList.remove('active'));
  document.getElementById('tp-'+t).classList.add('active'); document.querySelector('.tab[data-t="'+t+'"]').classList.add('active'); if(t==='events') loadEvents(); if(t==='health') loadHealth(); if(t==='services') loadWatches();
  if(t!=='diag'){ stopDiagAuto(); } }
function fmtGB(v){ v=+v||0; return v>=1?v.toFixed(v<10?1:0)+' GB':Math.round(v*1024)+' MB'; }
function uptimeStr(boot){ if(!boot)return '—'; const ms=Date.now()-new Date(boot).getTime(); if(isNaN(ms))return '—'; const d=Math.floor(ms/86400000),h=Math.floor(ms%86400000/3600000),m=Math.floor(ms%3600000/60000); return (d?d+'d ':'')+(h?h+'h ':'')+m+'m'; }
function clr(p,a,b){ p=+p; return p>=b?'var(--crit)':p>=a?'var(--warn)':'var(--ok)'; }
function relAge(s){ if(s==null)return ''; s=+s; if(s<60)return s+'s'; if(s<3600)return Math.floor(s/60)+'m'; if(s<86400)return Math.floor(s/3600)+'h'; return Math.floor(s/86400)+'d'; }

async function loadHosts(){
  const r=await fetch('linux.php?api=hosts').then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok)return; HOSTS=r.hosts;
  document.getElementById('hosts').innerHTML = HOSTS.length? HOSTS.map(h=>`
    <div class="glass hcard">
      <div class="nm"><i class="fab fa-linux" style="color:var(--win)"></i> ${esc(h.name)} ${h.err24>0?`<span class="tt" style="background:rgba(231,76,60,.18);color:#f0a59d;">${h.err24} err/24h</span>`:''}</div>
      <div class="meta">${esc(h.node_name||h.host_ip||'—')} · ${h.event_count} events stored · <span class="tt" style="background:${h.source==='alloy'?'rgba(247,103,7,.18);color:#ffb877':'rgba(58,160,255,.18);color:#9cc8ff'};">${h.source==='alloy'?'via Alloy':'via SSH'}</span></div>
      <div class="st ${esc(h.status)}">● ${esc((h.status||'').toUpperCase())}${h.status!=='down'&&h.last_error?' — '+esc((h.last_error||'').slice(0,70)):(h.status==='down'?' — host unreachable (powered off?)':'')}</div>
      <div class="meta">last pull ${h.last_event_poll?esc(nmLocal(h.last_event_poll)):'—'}</div>
      <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;">
        <a class="btn sm" style="text-decoration:none;background:linear-gradient(90deg,rgba(58,160,255,.22),rgba(54,227,208,.12));border-color:rgba(58,160,255,.5);" href="linux_screen.php?host=${h.id}" title="Full-screen Command Center — ALL of this box, live & futuristic"><i class="fas fa-display"></i> Command Center</a>
        <button class="btn sm" onclick="pollNow(${h.id})"><i class="fas fa-satellite-dish"></i> Poll now</button>
        <button class="btn sm" onclick="diagHost(${h.id})" title="Live system diagnostics — what's eating memory/CPU/network right now"><i class="fas fa-stethoscope"></i> Troubleshoot</button>
        <a class="btn sm ghost" style="text-decoration:none;" href="router_commander.php?${h.node_id?('node='+h.node_id):('host='+encodeURIComponent(h.host_ip||''))}&vendor=linux" title="Open the AI Commander with this host preselected"><i class="fas fa-wand-magic-sparkles"></i> AI Commander</a>
        <button class="btn ghost sm" onclick="viewHostEvents(${h.id})">events</button>
        <button class="btn ghost sm" onclick="editHost(${h.id})">edit</button>
        <button class="btn ghost sm danger" onclick="delHost(${h.id})">delete</button>
      </div>
    </div>`).join('') : '<div class="muted">No Linux hosts yet — add one to start pulling its Event Log.</div>';
  // populate the events host filter
  const fh=document.getElementById('f-host'); const cur=fh.value;
  fh.innerHTML='<option value="0">All hosts</option>'+HOSTS.map(h=>`<option value="${h.id}">${esc(h.name)}</option>`).join(''); fh.value=cur;
  // populate the health + services host selectors
  ['h-sel','s-sel','d-sel'].forEach(idn=>{ const sel=document.getElementById(idn); const cur=sel.value;
    sel.innerHTML=HOSTS.map(h=>`<option value="${h.id}">${esc(h.name)}</option>`).join('');
    if(cur) sel.value=cur; else if(HOSTS.length) sel.value=HOSTS[0].id; });
}
function viewHostEvents(id){ showTab('events'); document.getElementById('f-host').value=id; loadEvents(); }
async function pollNow(id){
  const r=await post(new URLSearchParams({action:'poll',id}));
  if(r&&r.ok) alert('✓ Pulled '+r.fetched+' event(s), '+r.new+' new.'); else alert('✗ '+(r?esc(r.error):'failed'));
  loadHosts(); loadEvents();
}
function openSsh(){ document.getElementById('sshbg').style.display='flex'; }
function cpc(id){ const t=document.getElementById(id).textContent; (navigator.clipboard?navigator.clipboard.writeText(t):0); const b=event.currentTarget; const o=b.innerHTML; b.innerHTML='<i class="fas fa-check"></i>'; setTimeout(()=>b.innerHTML=o,1200); }
function openHost(){ ['h-name','h-host','h-alloy'].forEach(i=>document.getElementById(i).value=''); document.getElementById('h-id').value=''; document.getElementById('h-node').value=''; document.getElementById('h-source').value='ssh'; document.getElementById('h-alloy-row').style.display='none'; document.getElementById('h-title').textContent='Add Linux host'; document.getElementById('h-msg').textContent=''; document.getElementById('hbg').style.display='flex'; }
function editHost(id){ const h=HOSTS.find(x=>x.id==id); if(!h)return;
  document.getElementById('h-id').value=id; document.getElementById('h-title').textContent='Edit: '+h.name;
  document.getElementById('h-name').value=h.name||''; document.getElementById('h-node').value=h.node_id||''; document.getElementById('h-host').value=h.host_ip||'';
  document.getElementById('h-source').value=h.source||'ssh'; document.getElementById('h-alloy').value=h.alloy_url||'';
  document.getElementById('h-alloy-row').style.display=(h.source==='alloy')?'block':'none';
  document.getElementById('h-msg').textContent=''; document.getElementById('hbg').style.display='flex'; }
async function saveHost(){
  const id=gv('h-id');
  const b=new URLSearchParams({action:id?'host_update':'host_add',id,name:gv('h-name'),node_id:gv('h-node'),host_ip:gv('h-host'),source:gv('h-source'),alloy_url:gv('h-alloy'),enabled:'1'});
  const r=await post(b);
  if(r&&r.ok){ closeM('hbg'); loadHosts(); } else document.getElementById('h-msg').innerHTML='<span style="color:var(--crit)">'+(r?esc(r.error):'failed')+'</span>';
}
async function delHost(id){ if(!confirm('Delete this host and its stored events?'))return; await post(new URLSearchParams({action:'host_delete',id})); loadHosts(); loadEvents(); }

function debLoad(){ clearTimeout(_deb); _deb=setTimeout(loadEvents,350); }
async function loadEvents(){
  const host=document.getElementById('f-host').value||0, lv=gv('f-lv'), log=gv('f-log'), q=gv('f-q');
  const r=await fetch(`linux.php?api=events&host=${host}&lv=${lv}&log=${encodeURIComponent(log)}&q=${encodeURIComponent(q)}&limit=300`).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok)return; _evtCache=r.events;
  const s=r.summary||{}; document.getElementById('k-crit').textContent=s.crit||0; document.getElementById('k-err').textContent=s.err||0; document.getElementById('k-warn').textContent=s.warn||0;
  document.getElementById('ev-body').innerHTML = r.events.length? r.events.map((e,i)=>{
    const lvl={1:['l1','Critical'],2:['l2','Error'],3:['l3','Warning']}[e.level]||['','Lv'+e.level];
    return `<tr class="lv${e.level}">
      <td class="mono muted" style="white-space:nowrap;" title="${esc(nmLocal(e.created_at))}">${esc(nmLocal(e.created_at))}<div style="font-size:10px;">${relAge(e.age)} ago</div></td>
      <td><span class="lvb ${lvl[0]}">${lvl[1]}</span></td>
      <td>${esc(e.host_name)}</td><td class="mono">${esc(e.log_name)}</td>
      <td class="mono">${e.event_id}</td><td class="mono" style="font-size:11px;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(e.provider)}">${esc(e.provider)}</td>
      <td class="msg" onclick="showEvt(${i})">${esc((e.message||'').slice(0,160))}${(e.message||'').length>160?'…':''}</td></tr>`;
  }).join('') : '<tr><td colspan="7" class="muted">No events match. Add a host &amp; “Poll now”, or widen the filters.</td></tr>';
}
function showEvt(i){ const e=_evtCache[i]; if(!e)return;
  document.getElementById('e-title').textContent=`Event ${e.event_id} — ${e.provider||''}`;
  document.getElementById('e-meta').innerHTML=`${esc(e.host_name)} · ${esc(e.log_name)} · ${esc(nmLocal(e.created_at))} · level ${e.level}`;
  document.getElementById('e-msg').textContent=e.message||'(no message)';
  document.getElementById('ebg').style.display='flex';
}
function copyEvt(){ navigator.clipboard.writeText(document.getElementById('e-msg').textContent); }

// ── Phase 2: Host health ──
async function loadHealth(){
  const id=document.getElementById('h-sel').value;
  if(!id){ document.getElementById('health').innerHTML='<div class="glass card muted">Add a host first.</div>'; document.getElementById('h-when').textContent=''; return; }
  const r=await fetch('linux.php?api=health&host='+id).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok){ document.getElementById('health').innerHTML='<div class="glass card muted">failed to load</div>'; return; }
  if(!r.has){ document.getElementById('health').innerHTML='<div class="glass card muted"><i class="fas fa-heart-pulse"></i> No health snapshot yet — click <b>Refresh now</b> (or wait for the cron).</div>'; document.getElementById('h-when').textContent=''; return; }
  document.getElementById('h-when').textContent='snapshot '+nmLocal(r.sampled_at)+' · '+relAge(r.age)+' ago';
  renderHealth(r.data||{});
}
async function refreshHealth(){
  const id=document.getElementById('h-sel').value; if(!id)return;
  const w=document.getElementById('h-when'); w.innerHTML='<i class="fas fa-spinner fa-spin"></i> querying host over SSH…';
  const r=await post(new URLSearchParams({action:'poll_health',id}));
  if(!r||!r.ok) w.innerHTML='<span style="color:var(--crit)">✗ '+(r?esc(r.error):'failed')+'</span>';
  loadHealth();
}
function renderHealth(d){
  const memUsed=(+d.mem_total||0)-(+d.mem_free||0), memPct=d.mem_total?Math.round(memUsed/d.mem_total*100):0;
  const fw=(d.firewall||[]).map(f=>`<span class="chip ${f.on?'good':'bad'}">${esc(f.name)} ${f.on?'on':'OFF'}</span>`).join('');
  const upd=(+d.updates||0);
  const sec = `<div class="kv"><span>Pending updates</span><b style="color:${upd>0?'var(--warn)':'var(--ok)'}">${upd}</b></div>
      <div class="kv"><span>Load average</span><b>${esc(d.load||'—')}</b></div>`;
  const stopped=(d.svc_stopped_auto||[]);
  const disks=(d.disks||[]).map(k=>{ const used=(+k.size||0)-(+k.free||0), p=k.size?Math.round(used/k.size*100):0;
    return `<div style="margin-bottom:8px;"><div class="kv"><span><b>${esc(k.id)}</b> ${fmtGB(k.free)} free</span><span class="muted">${fmtGB(used)} / ${fmtGB(k.size)} · ${p}%</span></div>
      <div class="gbar"><i style="width:${p}%;background:${clr(p,80,92)}"></i></div></div>`; }).join('')||'<div class="muted">—</div>';
  const pdisks=(d.pdisks||[]).map(p=>`<span class="chip ${p.health=='Healthy'?'good':'bad'}" title="${esc(p.op||'')}">${esc(p.name)} · ${esc(p.media||'')} · ${esc(p.health||'?')}</span>`).join('')||'';
  const procRows=(arr,withCpu)=>arr.map(p=>`<tr><td>${esc(p.name)}</td>${withCpu?`<td class="mono">${p.cpu}s</td>`:''}<td class="mono">${p.mb} MB</td></tr>`).join('');
  document.getElementById('health').innerHTML=`<div class="hsecs">
    <div class="glass hsec"><h4><i class="fas fa-server"></i> System</h4>
      <div class="kv"><span>Host</span><b>${esc(d.host||'?')}</b></div>
      <div class="kv"><span>OS</span><b style="text-align:right;">${esc(d.os||'?')}</b></div>
      <div class="kv"><span>Kernel</span><b>${esc(d.osver||'?')}</b></div>
      <div class="kv"><span>Uptime</span><b>${uptimeStr(d.boot)}</b></div>
      <div class="kv" style="margin-top:6px;"><span>Load avg (1/5/15m)</span><b>${esc(d.load||'—')}</b></div>
      <div class="kv" style="margin-top:6px;"><span>Memory</span><b style="color:${clr(memPct,75,90)}">${fmtGB(memUsed/1024)} / ${fmtGB((+d.mem_total||0)/1024)} · ${memPct}%</b></div>
      <div class="gbar"><i style="width:${memPct}%;background:${clr(memPct,75,90)}"></i></div></div>

    <div class="glass hsec"><h4><i class="fas fa-hard-drive"></i> Disks</h4>${disks}
      ${pdisks?`<div style="margin-top:8px;">${pdisks}</div>`:''}</div>

    <div class="glass hsec"><h4><i class="fas fa-shield-halved"></i> Security &amp; updates</h4>${sec}
      <div class="kv" style="margin-top:6px;"><span>Firewall</span><span>${fw||'—'}</span></div></div>

    <div class="glass hsec"><h4><i class="fas fa-gears"></i> Services <span class="muted" style="text-transform:none;letter-spacing:0;">(${d.svc_running||0}/${d.svc_total||0} running)</span></h4>
      ${stopped.length?`<div class="muted" style="margin-bottom:5px;">${stopped.length} auto-start service(s) stopped:</div>`+stopped.map(s=>`<div class="kv"><span><span class="chip warnc">stopped</span> ${esc(s.disp||s.name)}</span></div>`).join(''):'<div class="chip good">All automatic services running</div>'}</div>

    <div class="glass hsec"><h4><i class="fas fa-microchip"></i> Top processes — CPU</h4>
      <table><thead><tr><th>Process</th><th>CPU</th><th>RAM</th></tr></thead><tbody>${procRows(d.proc_cpu||[],true)}</tbody></table></div>

    <div class="glass hsec"><h4><i class="fas fa-memory"></i> Top processes — Memory</h4>
      <table><thead><tr><th>Process</th><th>RAM</th></tr></thead><tbody>${procRows(d.proc_mem||[],false)}</tbody></table></div>
  </div>`;
}

// ── Live System Diagnostics ──
let _diagTimer=null, _diagBusy=false;
function clearDiag(){ document.getElementById('diag').innerHTML='<div class="glass card muted">Pick a host and hit <b>Run live diagnostics</b>.</div>'; document.getElementById('d-msg').textContent=''; }
function diagHost(id){ showTab('diag'); const s=document.getElementById('d-sel'); if(s) s.value=id; runDiag(); }
function toggleDiagAuto(){ if(document.getElementById('d-auto').checked){ _diagTimer=setInterval(()=>{ if(!_diagBusy) runDiag(true); },15000); } else stopDiagAuto(); }
function stopDiagAuto(){ if(_diagTimer){ clearInterval(_diagTimer); _diagTimer=null; } const c=document.getElementById('d-auto'); if(c) c.checked=false; }
function fmtKBs(v){ v=+v||0; if(v>=1024)return (v/1024).toFixed(1)+' MB/s'; return Math.round(v)+' KB/s'; }
async function runDiag(quiet){
  const id=document.getElementById('d-sel').value;
  if(!id){ document.getElementById('d-msg').textContent='Add/select a host first.'; return; }
  _diagBusy=true; const msg=document.getElementById('d-msg'); msg.innerHTML='<i class="fas fa-spinner fa-spin"></i> probing over SSH…';
  if(!quiet) document.getElementById('diag').innerHTML='<div class="glass card muted"><i class="fas fa-spinner fa-spin"></i> Running a live snapshot on the host (~1–4s)…</div>';
  const r=await fetch('linux.php?api=diag&host='+id+'&_='+Date.now()).then(r=>r.json()).catch(()=>null);
  _diagBusy=false;
  if(!r||!r.ok){ msg.textContent='';
    document.getElementById('diag').innerHTML='<div class="glass card" style="border-left:3px solid var(--crit);"><b style="color:#f0a59d;"><i class="fas fa-circle-exclamation"></i> Diagnostics failed.</b><div class="muted" style="margin-top:6px;">'+esc(r?(r.error||'unknown error'):'no response')+'</div>'+(r&&r.raw?'<pre class="mono muted" style="font-size:11px;margin-top:8px;white-space:pre-wrap;max-height:160px;overflow:auto;">'+esc(r.raw)+'</pre>':'')+'</div>'; return; }
  msg.innerHTML='<i class="fas fa-circle-check" style="color:var(--ok)"></i> '+new Date().toLocaleTimeString();
  renderDiag(r.data||{});
}
function verdict(d){
  const f=[], mp=+d.mem_pct||0, cpu=+d.cpu||0;
  const tm=(d.top_mem||[])[0], tc=(d.top_cpu||[])[0];
  if(mp>=90) f.push(['crit','Memory critically high — '+mp+'% used'+(tm?'. Biggest consumer: <b>'+esc(tm.name)+'</b> — '+tm.mb+' MB'+(tm.inst>1?' across '+tm.inst+' processes':'')+'.':'.')]);
  else if(mp>=80) f.push(['warn','Memory under pressure — '+mp+'% used'+(tm?'. Top: <b>'+esc(tm.name)+'</b> ('+tm.mb+' MB).':'.')]);
  if(cpu>=85) f.push(['crit','CPU saturated at '+cpu+'%'+(tc?'. Hottest: <b>'+esc(tc.name)+'</b> at '+tc.pct+'%.':'.')]);
  else if(cpu>=65) f.push(['warn','CPU busy at '+cpu+'%'+(tc&&tc.pct>=15?'. '+esc(tc.name)+' using '+tc.pct+'%.':'.')]);
  (d.disks||[]).forEach(k=>{ if(+k.pct>=92) f.push(['crit','Disk '+esc(k.id)+' nearly full ('+k.pct+'%, '+fmtGB(k.free)+' free).']); else if(+k.pct>=85) f.push(['warn','Disk '+esc(k.id)+' filling up ('+k.pct+'%).']); });
  if(!f.length) f.push(['ok','Healthy — no memory, CPU or disk pressure right now.']);
  return f;
}
function barRow(name,val,unit,frac,color,sub,kill){
  const kb = kill ? `<button class="killb" title="Force-kill ${esc(kill)} on the host" onclick="killProc('${encodeURIComponent(kill)}')"><i class="fas fa-xmark"></i> kill</button>` : '';
  return `<div class="dbar"><div class="dbl"><span>${esc(name)}${kb}</span><b>${val}${unit}${sub?` <span class="muted" style="font-weight:400;">${sub}</span>`:''}</b></div>
    <div class="gbar"><i style="width:${Math.max(2,Math.min(100,frac*100)).toFixed(0)}%;background:${color}"></i></div></div>`;
}
async function killProc(enc){
  const name=decodeURIComponent(enc); const id=document.getElementById('d-sel').value; if(!id)return;
  if(!confirm('Force-kill ALL processes named "'+name+'" on this host?\n\nThey are terminated immediately — any unsaved work in them is lost. This is audited.')) return;
  const msg=document.getElementById('d-msg'); msg.innerHTML='<i class="fas fa-spinner fa-spin"></i> killing '+esc(name)+'…';
  const r=await post(new URLSearchParams({action:'kill_proc',host_id:id,name}));
  if(r&&r.ok){ msg.innerHTML='<span style="color:var(--ok)"><i class="fas fa-circle-check"></i> killed '+(r.killed||0)+' '+esc(name)+'</span>'; setTimeout(()=>runDiag(true),700); }
  else { msg.textContent=''; alert('Could not kill '+name+':\n\n'+(r?esc(r.error):'failed')); }
}
function renderDiag(d){
  const mp=+d.mem_pct||0, cpu=+d.cpu||0;
  const usedGB=(+d.mem_used||0)/1024, totGB=(+d.mem_total||0)/1024;
  const worstDisk=(d.disks||[]).reduce((a,k)=>Math.max(a,+k.pct||0),0);
  const g=(label,val,sub,color)=>`<div class="glass dg"><div class="dgl">${label}</div><div class="dgv" style="color:${color}">${val}</div><div class="dgs muted">${sub}</div></div>`;
  const gauges=`<div class="dgs-row">
    ${g('CPU',cpu+'%',d.cores?d.cores+' cores':'',clr(cpu,65,85))}
    ${g('Memory',mp+'%',fmtGB(usedGB)+' / '+fmtGB(totGB),clr(mp,80,90))}
    ${g('Network','↓'+fmtKBs(d.net_rx),'↑ '+fmtKBs(d.net_tx),'#7fc1ff')}
    ${g('Disk',worstDisk+'%',(d.disks||[]).length+' volume(s)',clr(worstDisk,85,92))}</div>`;
  const fv=verdict(d);
  const vcol=x=>x==='crit'?'var(--crit)':x==='warn'?'var(--warn)':'var(--ok)';
  const vb=`<div class="glass card dverdict" style="border-left:3px solid ${vcol(fv[0][0])};">
    ${fv.map(x=>`<div class="dvline"><i class="fas ${x[0]==='ok'?'fa-circle-check':x[0]==='crit'?'fa-circle-exclamation':'fa-triangle-exclamation'}" style="color:${vcol(x[0])}"></i> <span>${x[1]}</span></div>`).join('')}</div>`;
  const mm=(d.top_mem||[]); const mmax=mm.reduce((a,x)=>Math.max(a,+x.mb||0),1);
  const memPanel=`<div class="glass hsec"><h4><i class="fas fa-memory"></i> Memory consumers</h4>
    ${mm.length?mm.map(x=>barRow(x.name,x.mb,' MB',(+x.mb||0)/mmax,clr(mp,80,90),(x.inst>1?'×'+x.inst:'')+(x.pct>=5?' · '+x.pct+'% cpu':''),x.name)).join(''):'<div class="muted">—</div>'}</div>`;
  const cc=(d.top_cpu||[]); const cmax=cc.reduce((a,x)=>Math.max(a,+x.pct||0),1);
  const cpuPanel=`<div class="glass hsec"><h4><i class="fas fa-microchip"></i> CPU consumers <span class="muted" style="text-transform:none;letter-spacing:0;">(live %)</span></h4>
    ${cc.length?cc.map(x=>barRow(x.name,x.pct,'%',(+x.pct||0)/cmax,clr(+x.pct,15,40),x.mb?x.mb+' MB':'',x.name)).join(''):'<div class="muted">Idle — nothing above 0% this instant.</div>'}</div>`;
  const nc=(d.net_conn||[]);
  const netPanel=`<div class="glass hsec"><h4><i class="fas fa-network-wired"></i> Network</h4>
    <div class="kv"><span>Throughput</span><b>↓ ${fmtKBs(d.net_rx)} &nbsp; ↑ ${fmtKBs(d.net_tx)}</b></div>
    <div class="muted" style="margin:9px 0 4px;font-size:10px;text-transform:uppercase;letter-spacing:1px;">Top talkers (established TCP)</div>
    ${nc.length?`<table><thead><tr><th>Process</th><th>Conns</th><th></th></tr></thead><tbody>${nc.map(x=>`<tr><td>${esc(x.name||'?')}</td><td class="mono">${x.conns}</td><td style="text-align:right;">${x.name?`<button class="killb" title="Force-kill ${esc(x.name)}" onclick="killProc('${encodeURIComponent(x.name)}')"><i class="fas fa-xmark"></i></button>`:''}</td></tr>`).join('')}</tbody></table>`:'<div class="muted">No active connections reported.</div>'}</div>`;
  const dk=(d.disks||[]);
  const diskPanel=`<div class="glass hsec"><h4><i class="fas fa-hard-drive"></i> Disks</h4>
    ${dk.length?dk.map(k=>{const u=(+k.size||0)-(+k.free||0);return `<div style="margin-bottom:8px;"><div class="kv"><span><b>${esc(k.id)}</b> ${fmtGB(k.free)} free</span><span class="muted">${fmtGB(u)} / ${fmtGB(k.size)} · ${k.pct}%</span></div><div class="gbar"><i style="width:${+k.pct||0}%;background:${clr(k.pct,85,92)}"></i></div></div>`;}).join(''):'<div class="muted">—</div>'}</div>`;
  // fans & temperatures (from lm-sensors over SSH)
  const fans=(d.fans||[]), temps=(d.temps||[]); const fanmax=fans.reduce((a,x)=>Math.max(a,+x.rpm||0),1);
  const sensorPanel=`<div class="glass hsec"><h4><i class="fas fa-fan"></i> Fans &amp; temperatures ${d.sensor_src?`<span class="muted" style="text-transform:none;letter-spacing:0;">via ${esc(d.sensor_src)}</span>`:''}</h4>
    ${(fans.length||temps.length)
      ? (fans.length?fans.map(x=>barRow(x.name,x.rpm,' rpm',(+x.rpm||0)/fanmax,'#7fc1ff','')).join('')
          :`<div class="muted" style="font-size:11.5px;line-height:1.5;margin-bottom:6px;">No <b>fan</b> sensors reported (temps came through). The board's fan tachometers may not be exposed — try <code>sudo sensors-detect --auto</code> on the host, or this hardware has no readable fan tach.</div>`)
        + (temps.length?`<div style="margin-top:6px;">`+temps.map(x=>`<div class="kv"><span>${esc(x.name)}</span><b style="color:${clr(x.c,70,85)}">${x.c}°C</b></div>`).join('')+`</div>`:'')
      : `<div class="muted" style="font-size:12px;line-height:1.55;">No fan/thermal sensors on this host. To read <b>fan RPM &amp; temps</b>, install <b>lm-sensors</b>:<br>
        <code>sudo apt install -y lm-sensors && sudo sensors-detect --auto</code><br>
        then re-run diagnostics — NEURU reads <code>sensors -u</code> over SSH.</div>`}</div>`;
  // every other sensor type the monitor exposes (Load/Clocks/Power/Voltage/Control/Throughput…)
  const SUNIT={Temperature:'°C',Fan:' rpm',Voltage:' V',Clock:' MHz',Load:'%',Control:'%',Power:' W',Level:'%',Flow:' L/h',Data:' GB',SmallData:' MB',Throughput:' MB/s',Current:' A',Energy:' mWh',Factor:'',Frequency:' Hz'};
  const TORDER=['Load','Clock','Power','Voltage','Control','Level','Data','SmallData','Throughput','Current','Energy','Flow','Factor','Frequency'];
  const byType={}; (d.sensors||[]).forEach(s=>{ if(s.type==='Fan'||s.type==='Temperature')return; (byType[s.type]=byType[s.type]||[]).push(s); });
  const otherPanels=Object.keys(byType).sort((a,b)=>{const ia=TORDER.indexOf(a),ib=TORDER.indexOf(b);return (ia<0?99:ia)-(ib<0?99:ib);}).map(t=>{
    const u=(SUNIT[t]!=null?SUNIT[t]:''), pctType=(t==='Load'||t==='Control'||t==='Level');
    const rows=byType[t].map(s=>`<div class="kv"><span>${esc(s.name)}</span><b${pctType?` style="color:${clr(s.val,70,90)}"`:''}>${s.val}${u}</b></div>`).join('');
    const ic={Load:'fa-gauge-high',Clock:'fa-wave-square',Power:'fa-bolt',Voltage:'fa-plug',Control:'fa-sliders',Throughput:'fa-arrows-up-down',Data:'fa-database',SmallData:'fa-database',Level:'fa-droplet',Current:'fa-bolt',Energy:'fa-battery-half'}[t]||'fa-gauge';
    return `<div class="glass hsec"><h4><i class="fas ${ic}"></i> ${esc(t)} <span class="muted" style="text-transform:none;letter-spacing:0;">(${byType[t].length})</span></h4>${rows}</div>`;
  }).join('');
  document.getElementById('diag').innerHTML=gauges+vb+`<div class="hsecs">${memPanel}${cpuPanel}${netPanel}${diskPanel}${sensorPanel}${otherPanels}</div>`;
}

// ── Phase 3: Service watchdog ──
let _allSvcs=[];
function svcStateChip(s){ const ok=(s||'').toLowerCase()==='running'; const stp=(s||'').toLowerCase()==='stopped';
  return `<span class="chip ${ok?'good':(stp?'bad':'warnc')}">${esc(s||'—')}</span>`; }
async function loadWatches(){
  const id=document.getElementById('s-sel').value;
  if(!id){ document.getElementById('watch-body').innerHTML='<tr><td colspan="6" class="muted">Add a host first.</td></tr>'; return; }
  const r=await fetch('linux.php?api=watches&host='+id).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok)return;
  document.getElementById('watch-body').innerHTML = r.watches.length? r.watches.map(w=>`<tr>
    <td><b>${esc(w.display_name||w.service_name)}</b><div class="mono muted" style="font-size:10px;">${esc(w.service_name)}</div></td>
    <td>${svcStateChip(w.last_state)}<div class="muted" style="font-size:10px;">${w.last_checked?relAge(w.checked_age)+' ago':'—'}</div></td>
    <td><label class="sw"><input type="checkbox" ${w.auto_restart==1?'checked':''} onchange="toggleAuto(${w.id},this.checked)"> <span>${w.auto_restart==1?'<span style="color:var(--ok)">armed</span>':'off'}</span></label></td>
    <td class="mono">${w.restart_count||0}</td>
    <td class="muted" style="font-size:11px;">${w.last_action_at?esc(nmLocal(w.last_action_at)):'—'}</td>
    <td style="white-space:nowrap;">
      <button class="btn ghost sm" title="Start/Restart now" onclick="svcAction(${id},'${esc(w.service_name)}','restart')"><i class="fas fa-rotate-right"></i></button>
      <button class="btn ghost sm danger" title="Stop watching" onclick="delWatch(${w.id})"><i class="fas fa-trash"></i></button></td></tr>`).join('')
    : '<tr><td colspan="6" class="muted">No watched services yet — click “Watch a service”.</td></tr>';
  document.getElementById('act-body').innerHTML = (r.actions&&r.actions.length)? r.actions.map(a=>`<tr>
    <td class="muted" style="white-space:nowrap;">${esc(nmLocal(a.created_at))}</td><td>${esc(a.service_name)}</td><td>${esc(a.action)}</td>
    <td>${a.ok==1?'<span style="color:var(--ok)">✓ ok</span>':'<span style="color:var(--crit)">✗ fail</span>'}</td>
    <td class="muted" style="font-size:11px;max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(a.detail)}">${esc(a.detail||'')}</td></tr>`).join('')
    : '<tr><td colspan="5" class="muted">No actions yet.</td></tr>';
}
async function toggleAuto(id,on){
  if(on && !confirm('Arm auto-restart?\n\nNEURU will START this service over SSH whenever it is found stopped (max once every 5 min). Every action is audited.'))
    { loadWatches(); return; }
  await post(new URLSearchParams({action:'watch_update',id,auto_restart:on?'1':'0'})); loadWatches();
}
async function delWatch(id){ if(!confirm('Stop watching this service?'))return; await post(new URLSearchParams({action:'watch_delete',id})); loadWatches(); }
async function svcAction(host,svc,act){
  if(!confirm((act==='restart'?'Restart':'Start')+' service “'+svc+'” on the host now (over SSH)?'))return;
  const m=document.getElementById('s-msg'); m.style.color='#9aa'; m.innerHTML='<i class="fas fa-spinner fa-spin"></i> '+act+'ing '+svc+'…';
  const r=await post(new URLSearchParams({action:'svc_action',host_id:host,svc,act}));
  if(r&&r.ok){ m.style.color='var(--ok)'; m.textContent='✓ '+svc+' '+act+'ed'; } else { m.style.color='var(--crit)'; m.textContent='✗ '+(r?esc(r.detail||r.error):'failed'); }
  loadWatches();
}
async function checkWatch(){
  const id=document.getElementById('s-sel').value; if(!id)return;
  const m=document.getElementById('s-msg'); m.style.color='#9aa'; m.innerHTML='<i class="fas fa-spinner fa-spin"></i> checking over SSH…';
  const r=await post(new URLSearchParams({action:'watch_check',id}));
  if(r&&r.ok){ m.style.color='var(--ok)'; m.textContent='✓ checked '+r.checked+(r.acted?' · restarted '+r.acted:''); } else { m.style.color='var(--crit)'; m.textContent='✗ '+(r?esc(r.error):'failed'); }
  loadWatches();
}
async function openPicker(){
  const id=document.getElementById('s-sel').value; if(!id){alert('Pick a host first');return;}
  document.getElementById('pk-q').value=''; document.getElementById('pk-auto').checked=false;
  document.getElementById('pk-list').innerHTML='<span class="muted"><i class="fas fa-spinner fa-spin"></i> Loading services from the host over SSH…</span>';
  document.getElementById('pkbg').style.display='flex';
  const r=await fetch('linux.php?api=services_live&host='+id).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok){ document.getElementById('pk-list').innerHTML='<span style="color:var(--crit)">✗ '+(r?esc(r.error):'failed')+' — you can still “Add by name”.</span>'; _allSvcs=[]; return; }
  _allSvcs=r.services||[]; filterPicker();
}
function filterPicker(){
  const q=(document.getElementById('pk-q').value||'').toLowerCase();
  const rows=_allSvcs.filter(s=>!q||(s.Name||'').toLowerCase().includes(q)||(s.DisplayName||'').toLowerCase().includes(q)).slice(0,300);
  document.getElementById('pk-list').innerHTML = rows.length? rows.map(s=>`<div class="kv" style="padding:5px 2px;border-bottom:1px solid rgba(255,255,255,.05);">
    <span>${svcStateChip(s.State)} <b>${esc(s.DisplayName||s.Name)}</b> <span class="mono muted" style="font-size:10px;">${esc(s.Name)} · ${esc(s.StartMode)}</span></span>
    <button class="btn sm" onclick="addWatch('${esc(s.Name)}','${esc((s.DisplayName||'').replace(/'/g,''))}')">watch</button></div>`).join('')
    : '<span class="muted">No match.</span>';
}
async function addWatch(name,disp){
  const id=document.getElementById('s-sel').value, auto=document.getElementById('pk-auto').checked?'1':'';
  const r=await post(new URLSearchParams({action:'watch_add',host_id:id,service_name:name,display_name:disp,auto_restart:auto}));
  if(r&&r.ok){ const m=document.getElementById('s-msg'); m.style.color='var(--ok)'; m.textContent='✓ watching '+name; loadWatches(); }
  else alert(r?esc(r.error):'failed');
}
function addByName(){ const n=(document.getElementById('pk-q').value||'').trim(); if(!n){alert('Type a service short-name');return;} addWatch(n,n); }

loadHosts().then(()=>{
  // deep-link: linux.php?tab=diag&host=N → jump straight to a live troubleshoot
  const q=new URLSearchParams(location.search), tab=q.get('tab'), host=q.get('host');
  if(host){ ['h-sel','s-sel','d-sel','f-host'].forEach(id=>{ const s=document.getElementById(id); if(s&&[...s.options].some(o=>o.value==host)) s.value=host; }); }
  if(tab && document.querySelector('.tab[data-t="'+tab+'"]')){ showTab(tab); if(tab==='diag' && host) runDiag(); }
});
autoTimer=setInterval(()=>{ loadHosts(); if(document.getElementById('tp-events').classList.contains('active')) loadEvents(); if(document.getElementById('tp-services').classList.contains('active')) loadWatches(); }, 30000);
</script>
</body></html>
