<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — WiFi Control Center (cockpit). Monitor + control WiFi controllers of any
// family over SSH: live clients (with on-demand RSSI/SNR/throughput), access points,
// SSIDs, RF, and core actions (deauth · block/unblock a MAC · reboot an AP or the
// controller) behind confirm + audit. Universal via the nm_wifi.php driver model —
// the cockpit only shows what THIS controller's driver supports.
// RBAC: 'wifi' to view; admin for every write (register/remove a controller, actions).
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_wifi.php');
require_once('nm_audit.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'wifi')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=wifi'); exit;
}
nm_wifi_ensure($conn);
$role    = (string)($_SESSION['role'] ?? 'guest');
$isAdmin = ($role === 'admin');
$uid     = (int)($_SESSION['UID'] ?? 0) ?: null;

if ($api !== '') {
    if (function_exists('session_write_close')) @session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    $body = json_decode(file_get_contents('php://input'), true) ?: $_POST;
    $needAdmin = function() use ($isAdmin) { if (!$isAdmin) { echo json_encode(['ok'=>false,'error'=>'Admin only — controller changes and actions require the admin role.']); exit; } };
    $ctrlOf = function(int $id) use ($conn) { $c = nm_wifi_controller($conn, $id); if (!$c) { echo json_encode(['ok'=>false,'error'=>'controller not found']); exit; } return $c; };
    try {
        if ($api === 'controllers') { echo json_encode(['ok'=>true,'controllers'=>nm_wifi_controllers($conn),'can_admin'=>$isAdmin]); exit; }
        if ($api === 'candidates')  { $needAdmin(); echo json_encode(['ok'=>true,'candidates'=>nm_wifi_candidates($conn),'drivers'=>nm_wifi_drivers()]); exit; }
        if ($api === 'add')         { $needAdmin(); echo json_encode(nm_wifi_add($conn,(int)($body['node_id']??0),(string)($body['driver']??'auto'),(string)($body['label']??''),$uid)); exit; }
        if ($api === 'update')      { $needAdmin(); echo json_encode(nm_wifi_update($conn,(int)($body['id']??0),$body)); exit; }
        if ($api === 'delete')      { $needAdmin(); echo json_encode(nm_wifi_delete($conn,(int)($body['id']??0))); exit; }
        if ($api === 'detect')      { $c=$ctrlOf((int)($_GET['id']??0)); echo json_encode(nm_wifi_detect($conn,(int)$c['node_id'])); exit; }
        if ($api === 'snapshot')    {
            $c=$ctrlOf((int)($_GET['id']??0));
            $keys=array_values(array_filter(array_map('trim', explode(',', (string)($_GET['keys']??'clients')))));
            echo json_encode(nm_wifi_snapshot($conn,$c,$keys,!empty($_GET['raw']))); exit;
        }
        if ($api === 'detail')      { $c=$ctrlOf((int)($_GET['id']??0)); echo json_encode(nm_wifi_client_detail($conn,$c,(string)($_GET['mac']??''))); exit; }
        if ($api === 'action')      {
            $needAdmin(); $c=$ctrlOf((int)($body['id']??0));
            $action=(string)($body['action']??'');
            echo json_encode(nm_wifi_action($conn,$c,$action,(array)($body['params']??[]),$uid)); exit;
        }
        echo json_encode(['ok'=>false,'error'=>'unknown api']);
    } catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>$e->getMessage()]); }
    exit;
}

log_user_action($conn,'view_page','wifi.php');
$ctrls = nm_wifi_controllers($conn);
$preId = (int)($_GET['id'] ?? 0);
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(12,16,26,.62); --border:rgba(255,255,255,.12); --accent:#4da3ff; --cyan:#36e3d0; --ok:#2ee66e; --warn:#f0a92c; --crit:#ff5a5a; }
html{ background:#05080f; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent!important; color:#d4dce8; }
<?= nm_chrome_css() ?>
.wf{ max-width:1320px; margin:0 auto; padding:16px 20px 60px; } .wf *{ box-sizing:border-box; }
.glass{ background:var(--glass); backdrop-filter:blur(13px); border:1px solid var(--border); border-radius:14px; }
.bar{ display:flex; align-items:center; gap:13px; padding:12px 18px; margin-bottom:15px; flex-wrap:wrap; }
.title{ font-size:19px; font-weight:800; display:flex; align-items:center; gap:11px; } .title i{ color:var(--cyan); }
.wsel{ background:rgba(0,0,0,.4); border:1px solid var(--border); color:#e6edf7; border-radius:9px; padding:9px 12px; font-size:13px; min-width:200px; cursor:pointer; }
.wchip{ font-size:10px; font-weight:800; text-transform:uppercase; letter-spacing:.5px; padding:3px 9px; border-radius:20px; background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#bcd8ff; }
.sp{ flex:1; }
.tabs{ display:flex; gap:6px; flex-wrap:wrap; } .tab{ padding:8px 14px; border-radius:9px; border:1px solid var(--border); cursor:pointer; font-size:13px; color:#aeb8c7; } .tab.on{ background:rgba(54,227,208,.14); border-color:rgba(54,227,208,.45); color:#bff3ec; }
.btn{ display:inline-flex; align-items:center; gap:7px; background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:8px 13px; font-size:12.5px; cursor:pointer; text-decoration:none; font-weight:600; }
.btn:hover{ border-color:var(--accent); color:#fff; } .btn:disabled{ opacity:.45; cursor:not-allowed; } .btn.sm{ padding:5px 9px; font-size:12px; }
.btn.g{ background:linear-gradient(135deg,#36e3d0,#4da3ff); border:none; color:#04121a; font-weight:700; } .btn.warn{ border-color:rgba(240,169,44,.5); color:#ffd98a; } .btn.danger{ border-color:rgba(255,90,90,.5); color:#ff9b91; }
.card{ padding:16px 18px; margin-bottom:15px; }
.kpis{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:15px; }
.kpi{ padding:14px 16px; } .kpi .n{ font-size:28px; font-weight:800; font-variant-numeric:tabular-nums; } .kpi .l{ font-size:10px; text-transform:uppercase; letter-spacing:.6px; color:#8a909a; margin-top:2px; } .kpi i{ float:right; font-size:20px; opacity:.5; }
table{ width:100%; border-collapse:collapse; font-size:13px; } th{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; padding:9px 11px; border-bottom:1px solid var(--border); } td{ padding:9px 11px; border-bottom:1px solid rgba(255,255,255,.05); vertical-align:middle; }
tr:hover td{ background:rgba(255,255,255,.02); }
.mac{ font-family:Consolas,monospace; font-size:12px; color:#cfe0f5; }
.pill{ font-size:10px; font-weight:700; padding:2px 8px; border-radius:20px; }
.pill.ok{ background:rgba(46,230,110,.15); color:#8ff0b6; } .pill.warn{ background:rgba(240,169,44,.16); color:#ffd98a; } .pill.bad{ background:rgba(255,90,90,.15); color:#ffb0b0; } .pill.dim{ background:rgba(255,255,255,.07); color:#aeb8c7; }
.rssi{ display:inline-flex; align-items:center; gap:6px; } .rssibar{ width:46px; height:6px; border-radius:6px; background:rgba(255,255,255,.1); overflow:hidden; } .rssibar i{ display:block; height:100%; }
.muted{ color:#8a909a; font-size:12.5px; } .dim{ color:#6f7a8c; } .empty{ text-align:center; color:#6f7a8c; padding:52px 20px; } .empty i{ font-size:42px; display:block; margin-bottom:14px; color:#2a4a5e; }
.acts{ display:flex; gap:6px; justify-content:flex-end; }
.hide{ display:none; }
label{ display:block; font-size:10.5px; text-transform:uppercase; letter-spacing:.4px; color:#8b95a7; margin:12px 0 5px; }
.inp,select.inp{ width:100%; background:rgba(0,0,0,.35); border:1px solid var(--border); color:#e6edf7; border-radius:9px; padding:9px 11px; font-size:13px; }
.row2{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }
pre.raw{ background:#05080e; border:1px solid var(--border); border-radius:9px; padding:11px 13px; font-family:Consolas,monospace; font-size:11.5px; color:#8ee6da; overflow-x:auto; white-space:pre; max-height:340px; }
/* client detail drawer */
#wd-scrim{ position:fixed; inset:0; background:rgba(3,6,12,.55); z-index:900; display:none; }
#wd-draw{ position:fixed; top:0; right:0; bottom:0; width:380px; max-width:94vw; z-index:901; transform:translateX(100%); transition:transform .26s; background:rgba(10,14,23,.97); backdrop-filter:blur(16px); border-left:1px solid var(--border); display:flex; flex-direction:column; }
#wd-draw.open{ transform:translateX(0); }
.wd-hd{ display:flex; align-items:center; gap:10px; padding:15px 17px; border-bottom:1px solid var(--border); } .wd-hd .t{ font-weight:800; color:#fff; } .wd-hd .x{ margin-left:auto; cursor:pointer; color:#8aa2c4; font-size:18px; }
.wd-body{ overflow-y:auto; padding:15px 17px; flex:1; } .wd-body .kv{ display:flex; justify-content:space-between; gap:12px; padding:6px 0; border-bottom:1px solid rgba(255,255,255,.05); font-size:12.5px; } .wd-body .kv b{ color:#cfe0f5; font-weight:600; } .wd-body .kv span{ color:#8aa2c4; text-align:right; word-break:break-word; }
#toast{ position:fixed; bottom:22px; left:50%; transform:translateX(-50%) translateY(20px); background:rgba(16,22,34,.96); border:1px solid var(--border); color:#e6edf7; padding:11px 17px; border-radius:11px; font-size:13px; z-index:9999; opacity:0; pointer-events:none; transition:.25s; max-width:540px; }
#toast.show{ opacity:1; transform:translateX(-50%) translateY(0); } #toast.ok{ border-color:rgba(46,230,110,.5); } #toast.bad{ border-color:rgba(255,90,90,.5); }
</style>

<?php include('header.php'); ?>
<div class="wf">
  <div class="bar glass">
    <div class="title"><i class="fa-solid fa-wifi"></i> WiFi Control Center</div>
    <select class="wsel" id="ctrlSel" onchange="pickCtrl()">
      <option value="">— choose a controller —</option>
      <?php foreach ($ctrls as $c): ?>
      <option value="<?= (int)$c['id'] ?>" <?= $c['id']===$preId?'selected':'' ?>><?= htmlspecialchars($c['name']) ?><?= $c['ip']?' · '.htmlspecialchars($c['ip']):'' ?></option>
      <?php endforeach; ?>
    </select>
    <span class="wchip" id="drvchip" style="display:none">driver</span>
    <span class="sp"></span>
    <div class="tabs" id="tabs">
      <div class="tab on" data-t="overview" onclick="tab('overview')">Overview</div>
      <div class="tab" data-t="clients" onclick="tab('clients')">Clients</div>
      <div class="tab" data-t="aps" onclick="tab('aps')">Access Points</div>
      <div class="tab" data-t="wlans" onclick="tab('wlans')">WLANs</div>
      <div class="tab" data-t="rf" onclick="tab('rf')">RF</div>
      <?php if ($isAdmin): ?><div class="tab" data-t="manage" onclick="tab('manage')"><i class="fa-solid fa-gear"></i> Manage</div><?php endif; ?>
    </div>
  </div>

  <?php if (empty($ctrls)): ?>
    <div class="glass card empty" id="noctrl">
      <i class="fa-solid fa-wifi"></i>
      <div style="font-size:16px;color:#e6edf7;font-weight:700;margin-bottom:6px">No WiFi controllers yet</div>
      <div class="muted" style="max-width:520px;margin:0 auto 16px">Register any node that's a WiFi controller (Cisco AireOS / Mobility Express, a WLC, an autonomous AP…). NEURU auto-detects its type and drives it over SSH — monitor clients &amp; RF, deauth/block a MAC, reboot an AP. It needs the node to have an SSH credential set.</div>
      <?php if ($isAdmin): ?><button class="btn g" onclick="tab('manage')"><i class="fa-solid fa-plus"></i> Register a controller</button>
      <?php else: ?><div class="dim">Ask an admin to register one.</div><?php endif; ?>
    </div>
  <?php endif; ?>

  <!-- OVERVIEW -->
  <div id="tp-overview" class="tp">
    <div class="kpis" id="ov-kpis" style="display:none">
      <div class="glass kpi"><i class="fa-solid fa-users"></i><div class="n" id="k-clients">–</div><div class="l">Clients</div></div>
      <div class="glass kpi"><i class="fa-solid fa-tower-cell"></i><div class="n" id="k-aps">–</div><div class="l">Access Points</div></div>
      <div class="glass kpi"><i class="fa-solid fa-broadcast-tower"></i><div class="n" id="k-wlans">–</div><div class="l">WLANs</div></div>
      <div class="glass kpi"><i class="fa-solid fa-clock"></i><div class="n" id="k-uptime" style="font-size:16px">–</div><div class="l">Uptime</div></div>
    </div>
    <div class="glass card" id="ov-sys" style="display:none">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><b style="font-size:15px"><i class="fa-solid fa-circle-info" style="color:#4da3ff"></i> Controller</b><span class="sp" style="flex:1"></span><button class="btn sm" onclick="refresh()"><i class="fa-solid fa-rotate"></i> Refresh</button></div>
      <div id="ov-sysbody" class="muted">Loading…</div>
    </div>
    <div class="glass card empty" id="ov-hint"><i class="fa-solid fa-hand-pointer"></i><div class="muted">Pick a controller above to see its live status.</div></div>
  </div>

  <!-- CLIENTS -->
  <div id="tp-clients" class="tp hide">
    <div class="glass card">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap">
        <b style="font-size:15px"><i class="fa-solid fa-users" style="color:#4da3ff"></i> Associated clients</b>
        <span class="muted" id="cl-count"></span><span class="sp" style="flex:1"></span>
        <input class="inp" id="cl-q" placeholder="filter MAC / AP / SSID…" style="max-width:220px" oninput="renderClients()">
        <button class="btn sm" onclick="loadClients()"><i class="fa-solid fa-rotate"></i></button>
      </div>
      <div style="overflow-x:auto"><table><thead><tr><th>Client MAC</th><th>Access Point</th><th>WLAN</th><th>Protocol</th><th>Status</th><th></th></tr></thead><tbody id="cl-body"><tr><td colspan="6" class="muted" style="padding:20px">Pick a controller.</td></tr></tbody></table></div>
    </div>
  </div>

  <!-- ACCESS POINTS -->
  <div id="tp-aps" class="tp hide">
    <div class="glass card">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px"><b style="font-size:15px"><i class="fa-solid fa-tower-cell" style="color:#36e3d0"></i> Access points</b><span class="sp" style="flex:1"></span><button class="btn sm" onclick="loadAps()"><i class="fa-solid fa-rotate"></i></button></div>
      <div style="overflow-x:auto"><table><thead><tr><th>AP Name</th><th>Model</th><th>MAC</th><th>IP</th><th>Clients</th><th></th></tr></thead><tbody id="ap-body"><tr><td colspan="6" class="muted" style="padding:20px">Pick a controller.</td></tr></tbody></table></div>
    </div>
  </div>

  <!-- WLANS -->
  <div id="tp-wlans" class="tp hide">
    <div class="glass card">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px"><b style="font-size:15px"><i class="fa-solid fa-broadcast-tower" style="color:#c084fc"></i> WLANs / SSIDs</b><span class="sp" style="flex:1"></span><button class="btn sm" onclick="loadWlans()"><i class="fa-solid fa-rotate"></i></button></div>
      <div style="overflow-x:auto"><table><thead><tr><th>ID</th><th>Profile / SSID</th><th>Status</th><th>Interface</th></tr></thead><tbody id="wl-body"><tr><td colspan="4" class="muted" style="padding:20px">Pick a controller.</td></tr></tbody></table></div>
    </div>
  </div>

  <!-- RF -->
  <div id="tp-rf" class="tp hide">
    <div class="glass card">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px"><b style="font-size:15px"><i class="fa-solid fa-signal" style="color:#f0a92c"></i> Radio / RF (5 GHz)</b><span class="sp" style="flex:1"></span><button class="btn sm" onclick="loadRf()"><i class="fa-solid fa-rotate"></i></button></div>
      <div style="overflow-x:auto"><table><thead><tr><th>AP Name</th><th>Channel</th><th>Tx Power</th><th>Admin</th><th>Oper</th></tr></thead><tbody id="rf-body"><tr><td colspan="5" class="muted" style="padding:20px">Pick a controller.</td></tr></tbody></table></div>
    </div>
  </div>

  <?php if ($isAdmin): ?>
  <!-- MANAGE -->
  <div id="tp-manage" class="tp hide">
    <div class="glass card" style="max-width:760px">
      <b style="font-size:15px"><i class="fa-solid fa-plus" style="color:#36e3d0"></i> Register a WiFi controller</b>
      <div class="muted" style="margin:4px 0 8px">Pick a node that runs a WiFi controller. It must have an SSH credential set (Config → Nodes). Leave driver on <b>Auto-detect</b> unless you know the family.</div>
      <div class="row2">
        <div><label>Node</label><select class="inp" id="ad-node"><option value="">— loading nodes —</option></select></div>
        <div><label>Controller type</label><select class="inp" id="ad-driver"><option value="auto">Auto-detect (recommended)</option></select></div>
      </div>
      <label>Label <span class="dim" style="text-transform:none">(optional)</span></label><input class="inp" id="ad-label" placeholder="e.g. HQ WiFi">
      <div style="display:flex;gap:10px;margin-top:16px;align-items:center"><button class="btn g" onclick="addCtrl()"><i class="fa-solid fa-plus"></i> Register</button><span id="ad-msg" class="muted"></span></div>
    </div>
    <div class="glass card">
      <b style="font-size:15px">Registered controllers</b>
      <div style="overflow-x:auto;margin-top:10px"><table><thead><tr><th>Name</th><th>Node IP</th><th>Driver</th><th>Detected</th><th>Last OK</th><th></th></tr></thead><tbody id="mg-body"></tbody></table></div>
    </div>
    <div class="glass card">
      <div style="display:flex;align-items:center;gap:10px"><b style="font-size:15px"><i class="fa-solid fa-terminal" style="color:#8aa2c4"></i> Raw CLI transcript <span class="muted" style="font-weight:400">(debug — see exactly what the controller returned)</span></b><span class="sp" style="flex:1"></span>
        <select class="inp" id="raw-key" style="max-width:170px"><option value="sysinfo">show sysinfo</option><option value="clients">show client summary</option><option value="aps">show ap summary</option><option value="wlans">show wlan summary</option><option value="rf">show ap dot11 5ghz</option></select>
        <button class="btn sm" onclick="loadRaw()"><i class="fa-solid fa-play"></i> Fetch</button></div>
      <pre class="raw" id="raw-out" style="margin-top:11px">Pick a controller, choose a command, Fetch.</pre>
    </div>
  </div>
  <?php endif; ?>
</div>

<!-- client detail drawer -->
<div id="wd-scrim" onclick="closeDetail()"></div>
<aside id="wd-draw">
  <div class="wd-hd"><i class="fa-solid fa-user" style="color:#4da3ff"></i> <span class="t" id="wd-mac">client</span><span class="x" onclick="closeDetail()">✕</span></div>
  <div class="wd-body" id="wd-body">Loading…</div>
</aside>

<div id="toast"><span id="toast-msg"></span></div>

<script>
const CTRLS=<?= json_encode($ctrls) ?>, IS_ADMIN=<?= $isAdmin?'true':'false' ?>;
let CID=<?= $preId ?: 'null' ?>, CUR_TAB='overview', DRIVER='', DATA={clients:[],aps:[],wlans:[],rf:[],sysinfo:{}};
const E=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function toast(m,ok){ const t=document.getElementById('toast'); document.getElementById('toast-msg').innerHTML=m; t.className='show'+(ok===true?' ok':ok===false?' bad':''); clearTimeout(window._t); window._t=setTimeout(()=>t.className='',4200); }
function ctrlName(){ const s=document.getElementById('ctrlSel'); return s.options[s.selectedIndex]?.textContent.trim()||''; }

function tab(t){ CUR_TAB=t; document.querySelectorAll('#tabs .tab').forEach(x=>x.classList.toggle('on',x.dataset.t===t));
  document.querySelectorAll('.tp').forEach(x=>x.classList.add('hide')); const el=document.getElementById('tp-'+t); if(el)el.classList.remove('hide');
  if(!CID && t!=='manage') return;
  if(t==='overview') loadOverview(); else if(t==='clients') loadClients(); else if(t==='aps') loadAps(); else if(t==='wlans') loadWlans(); else if(t==='rf') loadRf(); else if(t==='manage') loadManage();
}
function pickCtrl(){ CID=+document.getElementById('ctrlSel').value||null; DRIVER=''; document.getElementById('drvchip').style.display='none';
  try{ history.replaceState(null,'', CID?('?id='+CID):location.pathname); }catch(e){}
  ['ov-kpis','ov-sys'].forEach(id=>document.getElementById(id)&&(document.getElementById(id).style.display='none'));
  const h=document.getElementById('ov-hint'); if(h) h.style.display=CID?'none':'';
  if(CID) tab(CUR_TAB==='manage'?'overview':CUR_TAB); }

function setDriver(d){ if(!d)return; DRIVER=d; const c=document.getElementById('drvchip'); c.textContent=d; c.style.display=''; }

async function snap(keys,raw){ if(!CID) return null;
  const r=await fetch('wifi.php?api=snapshot&id='+CID+'&keys='+encodeURIComponent(keys)+(raw?'&raw=1':'')+'&_='+Date.now()).then(x=>x.json()).catch(()=>null);
  if(r&&r.ok){ setDriver(r.driver); return r; } if(r&&r.error) toast(E(r.error),false); return r; }

async function loadOverview(){
  const hint=document.getElementById('ov-hint'); if(hint)hint.style.display='none';
  const sb=document.getElementById('ov-sysbody'); document.getElementById('ov-sys').style.display=''; sb.innerHTML='<i class="fa-solid fa-spinner fa-spin"></i> Querying controller over SSH…';
  const r=await snap('sysinfo,clients,aps,wlans');
  if(!r||!r.ok){ sb.innerHTML='<span class="dim">'+E((r&&r.error)||'could not reach controller')+'</span>'; return; }
  DATA.sysinfo=r.data.sysinfo||{}; DATA.clients=r.data.clients||[]; DATA.aps=r.data.aps||[]; DATA.wlans=r.data.wlans||[];
  document.getElementById('ov-kpis').style.display='';
  document.getElementById('k-clients').textContent=DATA.clients.length;
  document.getElementById('k-aps').textContent=DATA.aps.length;
  document.getElementById('k-wlans').textContent=DATA.wlans.length;
  const sys=DATA.sysinfo; const up=sys['Up Time']||sys['System Up Time']||sys['Uptime']||'–';
  document.getElementById('k-uptime').textContent=up;
  const show=['System Name','Product Name','Product Version','Management IP Address','System Time','Country','Maximum number of APs supported','Burned-in MAC Address'];
  let html='<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:6px 22px">';
  const want=Object.keys(sys).length?Object.keys(sys):[];
  (show.filter(k=>sys[k]!==undefined).length?show.filter(k=>sys[k]!==undefined):want.slice(0,12)).forEach(k=>{ html+='<div class="kv" style="display:flex;justify-content:space-between;gap:12px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.05);font-size:12.5px"><b style="color:#9fb2c8;font-weight:600">'+E(k)+'</b><span style="color:#e6edf7;text-align:right">'+E(sys[k])+'</span></div>'; });
  html+='</div>'; sb.innerHTML=Object.keys(sys).length?html:'<span class="dim">No sysinfo parsed. Check the Manage → Raw transcript to tune the driver.</span>';
}
function refresh(){ tab(CUR_TAB); }

async function loadClients(){
  const b=document.getElementById('cl-body'); b.innerHTML='<tr><td colspan="6" class="muted" style="padding:20px"><i class="fa-solid fa-spinner fa-spin"></i> Loading clients…</td></tr>';
  const r=await snap('clients'); if(!r||!r.ok){ b.innerHTML='<tr><td colspan="6" class="dim" style="padding:20px">'+E((r&&r.error)||'failed')+'</td></tr>'; return; }
  DATA.clients=r.data.clients||[]; renderClients();
}
function renderClients(){
  const q=(document.getElementById('cl-q').value||'').toLowerCase();
  const rows=DATA.clients.filter(c=>!q||(c.mac+' '+c.ap+' '+c.wlan).toLowerCase().includes(q));
  document.getElementById('cl-count').textContent=DATA.clients.length+' associated';
  const b=document.getElementById('cl-body');
  if(!rows.length){ b.innerHTML='<tr><td colspan="6" class="muted" style="padding:20px">'+(DATA.clients.length?'No match.':'No clients associated.')+'</td></tr>'; return; }
  b.innerHTML=rows.map(c=>{ const st=(c.status||'').toLowerCase();
    const stp=st.includes('assoc')?'ok':st.includes('excl')||st.includes('black')?'bad':'dim';
    return '<tr><td class="mac">'+E(c.mac)+'</td><td>'+E(c.ap||'–')+'</td><td>'+E(c.wlan||'–')+'</td><td><span class="pill dim">'+E(c.proto||'–')+'</span></td>'
      +'<td><span class="pill '+stp+'">'+E(c.status||'–')+'</span></td>'
      +'<td class="acts"><button class="btn sm" onclick="detail(\''+E(c.mac)+'\')"><i class="fa-solid fa-magnifying-glass"></i></button>'
      +(IS_ADMIN?'<button class="btn sm warn" title="Deauthenticate (kick)" onclick="act(\'deauth\',{mac:\''+E(c.mac)+'\'},\'Deauth '+E(c.mac)+'?\')"><i class="fa-solid fa-user-slash"></i></button>'
        +'<button class="btn sm danger" title="Block (exclusion list)" onclick="act(\'block\',{mac:\''+E(c.mac)+'\'},\'Block '+E(c.mac)+' on this controller?\')"><i class="fa-solid fa-ban"></i></button>':'')
      +'</td></tr>'; }).join('');
}

async function loadAps(){ const b=document.getElementById('ap-body'); b.innerHTML='<tr><td colspan="6" class="muted" style="padding:20px"><i class="fa-solid fa-spinner fa-spin"></i> Loading…</td></tr>';
  const r=await snap('aps'); if(!r||!r.ok){ b.innerHTML='<tr><td colspan="6" class="dim" style="padding:20px">'+E((r&&r.error)||'failed')+'</td></tr>'; return; }
  DATA.aps=r.data.aps||[];
  b.innerHTML=DATA.aps.length?DATA.aps.map(a=>'<tr><td><b style="color:#eaf1fb">'+E(a.name)+'</b></td><td>'+E(a.model||'–')+'</td><td class="mac">'+E(a.mac||'–')+'</td><td>'+E(a.ip||'–')+'</td><td>'+E(a.clients||'0')+'</td>'
    +'<td class="acts">'+(IS_ADMIN?'<button class="btn sm warn" title="Reboot this AP" onclick="act(\'reboot_ap\',{ap:\''+E(a.name)+'\'},\'Reboot AP '+E(a.name)+'? It will drop its clients for ~2 min.\')"><i class="fa-solid fa-power-off"></i> Reboot</button>':'')+'</td></tr>').join('')
    :'<tr><td colspan="6" class="muted" style="padding:20px">No APs.</td></tr>';
}
async function loadWlans(){ const b=document.getElementById('wl-body'); b.innerHTML='<tr><td colspan="4" class="muted" style="padding:20px"><i class="fa-solid fa-spinner fa-spin"></i> Loading…</td></tr>';
  const r=await snap('wlans'); if(!r||!r.ok){ b.innerHTML='<tr><td colspan="4" class="dim" style="padding:20px">'+E((r&&r.error)||'failed')+'</td></tr>'; return; }
  DATA.wlans=r.data.wlans||[];
  b.innerHTML=DATA.wlans.length?DATA.wlans.map(w=>{ const on=(w.status||'').toLowerCase().includes('enab');
    return '<tr><td>'+E(w.id||'–')+'</td><td><b style="color:#eaf1fb">'+E(w.name||'–')+'</b></td><td><span class="pill '+(on?'ok':'dim')+'">'+E(w.status||'–')+'</span></td><td>'+E(w.iface||'–')+'</td></tr>'; }).join('')
    :'<tr><td colspan="4" class="muted" style="padding:20px">No WLANs.</td></tr>';
}
async function loadRf(){ const b=document.getElementById('rf-body'); b.innerHTML='<tr><td colspan="5" class="muted" style="padding:20px"><i class="fa-solid fa-spinner fa-spin"></i> Loading…</td></tr>';
  const r=await snap('rf'); if(!r||!r.ok){ b.innerHTML='<tr><td colspan="5" class="dim" style="padding:20px">'+E((r&&r.error)||'failed')+'</td></tr>'; return; }
  DATA.rf=r.data.rf||[];
  b.innerHTML=DATA.rf.length?DATA.rf.map(x=>{ const oper=(x.oper||'').toLowerCase().includes('up');
    return '<tr><td><b style="color:#eaf1fb">'+E(x.ap)+'</b></td><td><span class="pill dim">'+E(x.channel||'–')+'</span></td><td>'+E(x.power||'–')+'</td><td>'+E(x.admin||'–')+'</td><td><span class="pill '+(oper?'ok':'bad')+'">'+E(x.oper||'–')+'</span></td></tr>'; }).join('')
    :'<tr><td colspan="5" class="muted" style="padding:20px">No RF data.</td></tr>';
}

// client detail drawer
async function detail(mac){
  document.getElementById('wd-scrim').style.display='block'; document.getElementById('wd-draw').classList.add('open');
  document.getElementById('wd-mac').textContent=mac; const b=document.getElementById('wd-body'); b.innerHTML='<i class="fa-solid fa-spinner fa-spin"></i> Querying client…';
  const r=await fetch('wifi.php?api=detail&id='+CID+'&mac='+encodeURIComponent(mac)+'&_='+Date.now()).then(x=>x.json()).catch(()=>null);
  if(!r||!r.ok){ b.innerHTML='<span class="dim">'+E((r&&r.error)||'failed')+'</span>'; return; }
  const d=r.detail||{}; const keys=Object.keys(d);
  if(!keys.length){ b.innerHTML='<span class="dim">No detail parsed.</span><pre class="raw" style="margin-top:10px">'+E(r.raw||'')+'</pre>'; return; }
  const pref=['Client MAC Address','Client Username','AP Name','Wireless LAN Network Name (SSID)','BSSID','Connected For','Channel','Radio Type','802.11 Authentication','Policy Manager State','RSSI','SNR','Mobility State','Data Rate','Client Type'];
  const order=[...pref.filter(k=>d[k]!==undefined),...keys.filter(k=>!pref.includes(k))];
  b.innerHTML=order.map(k=>'<div class="kv"><b>'+E(k)+'</b><span>'+E(d[k])+'</span></div>').join('');
}
function closeDetail(){ document.getElementById('wd-scrim').style.display='none'; document.getElementById('wd-draw').classList.remove('open'); }

// control action
async function act(action,params,confirmMsg){
  if(!CID) return; if(confirmMsg && !confirm(confirmMsg)) return;
  toast('<i class="fa-solid fa-spinner fa-spin"></i> Sending…');
  const r=await fetch('wifi.php?api=action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:CID,action,params})}).then(x=>x.json()).catch(()=>null);
  if(r&&r.ok){ toast('<i class="fa-solid fa-check"></i> '+E(r.summary||'done'),true); setTimeout(()=>{ if(CUR_TAB==='clients')loadClients(); else if(CUR_TAB==='aps')loadAps(); },1200); }
  else toast('<i class="fa-solid fa-xmark"></i> '+E((r&&r.error)||'failed'),false);
}

// manage
async function loadManage(){
  const r=await fetch('wifi.php?api=candidates&_='+Date.now()).then(x=>x.json()).catch(()=>null);
  if(r&&r.ok){ const ns=document.getElementById('ad-node'); ns.innerHTML='<option value="">— pick a node —</option>'+r.candidates.map(n=>'<option value="'+n.id+'">'+E(n.name)+(n.ip?(' · '+E(n.ip)):'')+'</option>').join('');
    const ds=document.getElementById('ad-driver'); ds.innerHTML='<option value="auto">Auto-detect (recommended)</option>'+Object.entries(r.drivers).map(([k,d])=>'<option value="'+k+'"'+(d.supported?'':' ')+'>'+E(d.label)+(d.supported?'':' (slot)')+'</option>').join(''); }
  const cr=await fetch('wifi.php?api=controllers&_='+Date.now()).then(x=>x.json()).catch(()=>null);
  const b=document.getElementById('mg-body');
  if(cr&&cr.ok){ b.innerHTML=cr.controllers.length?cr.controllers.map(c=>'<tr><td><b style="color:#eaf1fb">'+E(c.name)+'</b></td><td>'+E(c.ip||'–')+'</td><td>'+E(c.driver)+'</td><td>'+E(c.detected||'–')+'</td><td class="muted">'+E(c.last_ok||'never')+(c.last_err?'<br><span style="color:#ffb0b0">'+E(c.last_err)+'</span>':'')+'</td>'
    +'<td class="acts"><button class="btn sm" onclick="reDetect('+c.id+')" title="Re-detect type"><i class="fa-solid fa-wand-magic-sparkles"></i></button><button class="btn sm danger" onclick="delCtrl('+c.id+')"><i class="fa-solid fa-trash"></i></button></td></tr>').join('')
    :'<tr><td colspan="6" class="muted" style="padding:16px">None yet.</td></tr>'; }
}
async function addCtrl(){ const node_id=+document.getElementById('ad-node').value||0; const driver=document.getElementById('ad-driver').value; const label=document.getElementById('ad-label').value.trim();
  if(!node_id){ document.getElementById('ad-msg').textContent='Pick a node.'; return; }
  const r=await fetch('wifi.php?api=add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({node_id,driver,label})}).then(x=>x.json()).catch(()=>null);
  if(r&&r.ok){ toast('Controller registered — reloading…',true); setTimeout(()=>location.href='wifi.php',900); } else document.getElementById('ad-msg').textContent=(r&&r.error)||'failed';
}
async function delCtrl(id){ if(!confirm('Remove this controller from NEURU? (the device is not touched)')) return;
  const r=await fetch('wifi.php?api=delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}).then(x=>x.json()).catch(()=>null);
  if(r&&r.ok){ toast('Removed',true); loadManage(); if(CID===id){ CID=null; location.href='wifi.php'; } }
}
async function reDetect(id){ toast('<i class="fa-solid fa-spinner fa-spin"></i> Detecting over SSH…');
  const r=await fetch('wifi.php?api=detect&id='+id+'&_='+Date.now()).then(x=>x.json()).catch(()=>null);
  if(r&&r.ok){ toast('Detected: '+E(r.driver),true); loadManage(); } else toast('<i class="fa-solid fa-xmark"></i> '+E((r&&r.error)||'not detected'),false);
}
async function loadRaw(){ if(!CID){ toast('Pick a controller first.'); return; }
  const key=document.getElementById('raw-key').value; const o=document.getElementById('raw-out'); o.textContent='Fetching over SSH…';
  const r=await snap(key,true); o.textContent=(r&&r.ok&&r.raw&&r.raw[key]!==undefined)?(r.raw[key]||'(empty)'):((r&&r.error)||'failed');
}

// boot
if(CID){ document.getElementById('ctrlSel').value=CID; tab('overview'); }
else if(<?= empty($ctrls) && $isAdmin ? 'true':'false' ?>){ /* stay on overview; empty state shown */ }
</script>
