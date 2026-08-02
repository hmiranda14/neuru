<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — NetFlow Traffic Analyzer (SolarWinds NTA-style). Reads the aggregates
// written by scripts/nm_netflow.py. Gated by permission key 'netflow'.
// ─────────────────────────────────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) session_start();
include_once __DIR__ . '/connection.php';
require_once __DIR__ . '/access_control.php';
require_once __DIR__ . '/nm_netflow.php';
require_once __DIR__ . '/nm_nettools.php';   // nm_geo_badge() — country flag for external talkers
require_once __DIR__ . '/nm_chrome.php';

if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$CSRF = $_SESSION['csrf_token'];

// ── JSON API ─────────────────────────────────────────────────────────────────
if (isset($_GET['api']) || isset($_POST['api'])) {
    header('Content-Type: application/json');
    if (empty($_SESSION['username']) || !checkAccess($conn, 'netflow')) {
        http_response_code(403); echo json_encode(['ok'=>false,'err'=>'Unauthorized']); exit;
    }
    session_write_close();
    $api = $_GET['api'] ?? $_POST['api'];
    $isPost = ($_SERVER['REQUEST_METHOD'] === 'POST');
    if ($isPost && (($_POST['csrf'] ?? '') !== $_SESSION['csrf_token'])) {
        http_response_code(400); echo json_encode(['ok'=>false,'err'=>'Invalid CSRF']); exit;
    }
    $range = $_GET['range'] ?? '1h';
    $exp   = trim($_GET['exporter'] ?? '');
    $mins  = nm_nf_minutes($range);

    try {
        switch ($api) {
        case 'overview':
            // flag external talkers with their country (nm_geo_badge skips private/LAN IPs)
            $geoTalk = function(array $rows) use ($conn) {
                if (!function_exists('nm_geo_badge')) return $rows;
                foreach ($rows as &$r) { $g = nm_geo_badge($conn, $r['ip'] ?? '');
                    $r['geo'] = $g ? ['flag'=>$g['flag'],'country'=>$g['country'],'city'=>$g['city']] : null; }
                unset($r); return $rows;
            };
            echo json_encode(['ok'=>true,
                'summary'  => nm_nf_summary($conn, $mins, $exp),
                'status'   => nm_nf_status($conn),
                'series'   => nm_nf_timeseries($conn, $range, $exp),
                'apps'     => nm_nf_top_apps($conn, $mins, $exp, 12),
                'protocols'=> nm_nf_top_protocols($conn, $mins, $exp, 8),
                'talkers_src'=> $geoTalk(nm_nf_top_talkers($conn, $mins, 'src', $exp, 10)),
                'talkers_dst'=> $geoTalk(nm_nf_top_talkers($conn, $mins, 'dst', $exp, 10)),
                'convos'   => nm_nf_top_conversations($conn, $mins, $exp, 20),
                'exporters'=> nm_nf_exporters($conn),
                'alerts'   => nm_nf_open_alerts($conn, 25),
            ]);
            break;
        case 'thresholds_get':
            echo json_encode(['ok'=>true, 'thresholds'=>nm_nf_thresholds($conn),
                'apps'=>array_map(fn($a)=>$a['app'], nm_nf_top_apps($conn, 1440, '', 30))]);
            break;
        case 'thresholds_save':
            if (!$isPost) { echo json_encode(['ok'=>false,'err'=>'POST only']); break; }
            $scope = trim($_POST['scope'] ?? '');
            if ($scope === '') { echo json_encode(['ok'=>false,'err'=>'scope required']); break; }
            nm_nf_threshold_save($conn, $scope, $_POST['warn'] ?? '', $_POST['crit'] ?? '');
            nm_audit($conn, 'netflow.threshold', ['target_type'=>'netflow','target_id'=>$scope,
                'details'=>['warn'=>$_POST['warn']??'','crit'=>$_POST['crit']??'']]);
            echo json_encode(['ok'=>true]);
            break;
        case 'eval':
            echo json_encode(['ok'=>true] + nm_nf_eval_alerts($conn, 5));
            break;
        case 'dash_alerts':   // lightweight feed for the dashboard Active-Alerts strip
            echo json_encode(['ok'=>true, 'alerts'=>nm_nf_open_alerts($conn, 25)]);
            break;
        case 'flows':         // Flow Explorer — directional flow rows
            echo json_encode(['ok'=>true,
                'flows'=>nm_nf_flows($conn, $mins, $exp, trim($_GET['host'] ?? ''), $_GET['dir'] ?? 'both', 200)]);
            break;
        case 'graph':         // Flow Explorer — node/edge directional map
            echo json_encode(['ok'=>true] + nm_nf_flow_graph($conn, $mins, $exp, trim($_GET['host'] ?? ''), 80));
            break;
        default:
            http_response_code(400); echo json_encode(['ok'=>false,'err'=>'Unknown endpoint']);
        }
    } catch (\Throwable $e) {
        http_response_code(500); echo json_encode(['ok'=>false,'err'=>$e->getMessage()]);
    }
    exit;
}

// ── HTML page ────────────────────────────────────────────────────────────────
include('check.php');
if (!checkAccess($conn, 'netflow')) { header('Location: /denied_access.php?page=netflow'); exit; }
$NF = nm_nf_settings($conn);
include('header.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetFlow | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="/chart.umd.min.js"></script>
<script src="/chartjs-adapter-date-fns.bundle.min.js"></script>
<script src="/d3.v7.min.js"></script>
<style>
<?= nm_chrome_css() ?>
:root{--glass:rgba(255,255,255,0.07);--border:rgba(255,255,255,0.13);--accent:#4da3ff;--up:#2ecc71;--down:#e74c3c;--warn:#f39c12;--mut:#8a909a;}
body{margin:0;font-family:'Segoe UI',Tahoma,sans-serif;background:#000;color:#fff;overflow-x:hidden;}
.wrap{max-width:1600px;margin:0 auto;padding:18px 22px 60px;}
.glass-card{background:var(--glass);backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:16px;padding:18px 20px;margin-bottom:18px;}
h2{margin:0 0 14px;font-size:14px;color:var(--accent);display:flex;align-items:center;gap:9px;}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:16px;}
.seg{display:inline-flex;border:1px solid var(--border);border-radius:9px;overflow:hidden;}
.seg button{background:transparent;border:none;color:var(--mut);padding:7px 13px;font-size:12px;font-weight:700;cursor:pointer;}
.seg button.on{background:var(--accent);color:#000;}
.form-select{background:rgba(20,30,50,.95);border:1px solid var(--border);color:#fff;padding:7px 12px;border-radius:8px;font-size:12.5px;outline:none;}
.btn{padding:7px 13px;border-radius:8px;border:1px solid var(--border);background:rgba(255,255,255,.05);color:#cfd3da;font-size:12px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:7px;text-decoration:none;}
.btn:hover{border-color:var(--accent);color:#fff;}
.bento{display:grid;grid-template-columns:repeat(5,1fr);gap:13px;margin-bottom:18px;}
@media(max-width:1100px){.bento{grid-template-columns:repeat(2,1fr);}}
.kpi{background:var(--glass);border:1px solid var(--border);border-radius:14px;padding:14px 16px;}
.kpi .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--mut);}
.kpi .val{font-size:24px;font-weight:800;margin-top:3px;}
.grid2{display:grid;grid-template-columns:1.5fr 1fr;gap:16px;}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;}
@media(max-width:1000px){.grid2,.grid3{grid-template-columns:1fr;}}
table{width:100%;border-collapse:collapse;font-size:12.5px;}
th{text-align:left;color:var(--mut);font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.5px;padding:6px 8px;border-bottom:1px solid var(--border);}
td{padding:6px 8px;border-bottom:1px solid rgba(255,255,255,.05);}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;}
.bar{height:6px;border-radius:4px;background:rgba(255,255,255,.07);overflow:hidden;margin-top:4px;}
.bar i{display:block;height:100%;background:var(--accent);}
.tag{font-size:10px;padding:2px 8px;border-radius:6px;font-weight:700;}
.t-app{background:rgba(77,163,255,.14);color:#7fc0ff;}
.mut{color:var(--mut);}
.statusbar{display:inline-flex;align-items:center;gap:7px;font-size:11px;padding:5px 12px;border-radius:20px;border:1px solid var(--border);}
.statusbar.ok{border-color:rgba(46,204,113,.4);color:#2ecc71;} .statusbar.bad{border-color:rgba(243,156,18,.5);color:#f39c12;}
.dot{width:7px;height:7px;border-radius:50%;background:currentColor;}
.nf-mapbtn{background:rgba(77,163,255,.12);border:1px solid rgba(77,163,255,.35);color:#cfe4ff;border-radius:8px;padding:5px 11px;font-size:11px;cursor:pointer;font-weight:600;}
.nf-mapbtn:hover{background:rgba(77,163,255,.24);}
#ex-wrap:fullscreen{background:#05080e;padding:16px;height:100vh!important;gap:14px;}
#ex-wrap:fullscreen #ex-side{width:360px;flex:0 0 360px;}
#ex-wrap:fullscreen #ex-graph{box-shadow:inset 0 0 120px rgba(77,163,255,.06);}
.ex-flowrow{display:flex;align-items:center;gap:7px;padding:7px 2px;border-bottom:1px solid rgba(255,255,255,.05);font-size:11.5px;}
.ex-flowrow .fbar{height:3px;border-radius:3px;background:linear-gradient(90deg,#2ecc71,#4da3ff);margin-top:3px;}
.ex-flowrow .mono{font-family:ui-monospace,monospace;}
.ex-ip{cursor:pointer;border-radius:3px;padding:0 1px;}
.ex-ip:hover{text-decoration:underline;filter:brightness(1.25);}
/* while fullscreen, the live particle canvas is reparented here — keep it behind the graph */
#ex-wrap:fullscreen #nm-netbg{z-index:0!important;}
.disabled-note{background:rgba(243,156,18,.1);border:1px solid rgba(243,156,18,.4);color:#f5b73d;border-radius:12px;padding:20px;text-align:center;}
.alert-card{display:flex;align-items:center;gap:12px;padding:9px 12px;border-radius:10px;margin-bottom:8px;border:1px solid var(--border);}
.alert-card.crit{border-color:rgba(231,76,60,.5);background:rgba(231,76,60,.07);}
.alert-card.warn{border-color:rgba(243,156,18,.5);background:rgba(243,156,18,.07);}
.sev-badge{font-size:10px;font-weight:800;text-transform:uppercase;padding:2px 8px;border-radius:6px;}
.sev-badge.crit{background:rgba(231,76,60,.2);color:#ff6b6b;} .sev-badge.warn{background:rgba(243,156,18,.2);color:#f5b73d;}
/* threshold modal */
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.72);backdrop-filter:blur(4px);display:none;align-items:flex-start;justify-content:center;z-index:1000;padding:40px 16px;overflow-y:auto;}
.modal-bg.show{display:flex;}
.modal{background:#0d1119;border:1px solid var(--border);border-radius:16px;width:100%;max-width:560px;padding:22px 24px;}
.modal h3{margin:0 0 14px;font-size:16px;}
.fld{display:flex;flex-direction:column;gap:5px;margin-bottom:12px;}
.fld label{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--mut);}
.form-input{background:rgba(255,255,255,.07);border:1px solid var(--border);color:#fff;padding:8px 12px;border-radius:8px;font-size:13px;outline:none;width:100%;box-sizing:border-box;}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:14px;}
.hidden{display:none!important;}
#toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(120%);background:#11151d;border:1px solid var(--border);border-left:4px solid var(--accent);border-radius:10px;padding:12px 18px;font-size:13px;z-index:2000;transition:.3s;}
#toast.show{transform:translateX(-50%) translateY(0);}
</style>
</head>
<body>
<div class="wrap">
<?php nm_page_header('NetFlow', 'Analyzer', 'Traffic Intelligence', 'fa-solid fa-chart-area'); ?>

<?php if (!$NF['enabled']): ?>
  <div class="disabled-note">
    <i class="fa-solid fa-triangle-exclamation" style="font-size:24px;display:block;margin-bottom:8px;"></i>
    NetFlow collection is disabled. Enable it and set the listen port in
    <a href="net_mon_config.php?tab=integrations" style="color:#f5b73d;">Config → Integrations → NetFlow</a>,
    then point your routers' flow export at this server.
  </div>
<?php endif; ?>

<div class="toolbar">
  <div class="seg" id="range-seg">
    <button data-r="15m">15m</button><button data-r="1h" class="on">1h</button>
    <button data-r="6h">6h</button><button data-r="24h">24h</button><button data-r="7d">7d</button>
  </div>
  <select class="form-select" id="exp-sel"><option value="">All exporters</option></select>
  <span class="statusbar" id="status-bar"><span class="dot"></span><span id="status-txt">…</span></span>
  <button class="btn" style="margin-left:auto;" onclick="openThresholds()"><i class="fa-solid fa-sliders"></i> Alert thresholds</button>
  <a class="btn" href="net_mon_config.php?tab=integrations"><i class="fa-solid fa-gear"></i> Setup</a>
</div>

<?php nm_module_tabs([
    ['icon'=>'fa-solid fa-gauge-high','label'=>'Overview','href'=>'#tab-overview','active'=>true],
    ['icon'=>'fa-solid fa-route','label'=>'Flow Explorer','href'=>'#tab-explorer','active'=>false],
]); ?>

<section id="tab-overview">
<!-- alerts -->
<div class="glass-card hidden" id="alerts-card" style="border-color:rgba(243,156,18,.35);">
  <h2 style="color:var(--warn);"><i class="fa-solid fa-bolt"></i> Bandwidth Alerts <span id="alerts-count" class="mut" style="font-weight:400;"></span></h2>
  <div id="alerts-list"></div>
</div>

<div class="bento">
  <div class="kpi"><div class="lbl">Avg Bandwidth</div><div class="val" style="color:var(--accent)" id="k-bw">—</div></div>
  <div class="kpi"><div class="lbl">Total Traffic</div><div class="val" id="k-bytes">—</div></div>
  <div class="kpi"><div class="lbl">Flows</div><div class="val" id="k-flows">—</div></div>
  <div class="kpi"><div class="lbl">Talkers</div><div class="val" style="color:var(--up)" id="k-talkers">—</div></div>
  <div class="kpi"><div class="lbl">Exporters</div><div class="val" id="k-exporters">—</div></div>
</div>

<div class="grid2">
  <div class="glass-card"><h2><i class="fa-solid fa-chart-area"></i> Bandwidth over time</h2>
    <div style="height:240px;"><canvas id="bwChart"></canvas></div></div>
  <div class="glass-card"><h2><i class="fa-solid fa-layer-group"></i> Top Applications</h2>
    <div id="apps"><div class="mut" style="padding:12px;">Loading…</div></div></div>
</div>

<div class="grid3" style="margin-top:16px;">
  <div class="glass-card"><h2><i class="fa-solid fa-upload"></i> Top Talkers (Source)</h2>
    <table><tbody id="talk-src"></tbody></table></div>
  <div class="glass-card"><h2><i class="fa-solid fa-download"></i> Top Talkers (Dest)</h2>
    <table><tbody id="talk-dst"></tbody></table></div>
  <div class="glass-card"><h2><i class="fa-solid fa-diagram-project"></i> Protocols</h2>
    <div id="protos"><div class="mut" style="padding:12px;">Loading…</div></div></div>
</div>

<div class="glass-card" style="margin-top:16px;">
  <h2><i class="fa-solid fa-right-left"></i> Top Conversations</h2>
  <div style="overflow-x:auto;"><table>
    <thead><tr><th>Source</th><th>Destination</th><th>Application</th><th style="text-align:right;">Bandwidth</th><th style="text-align:right;">Flows</th></tr></thead>
    <tbody id="convos"><tr><td colspan="5" class="mut" style="text-align:center;padding:20px;">Loading…</td></tr></tbody>
  </table></div>
</div>
</section>

<!-- ════════════════════ FLOW EXPLORER ════════════════════ -->
<section id="tab-explorer" class="hidden">
  <div class="glass-card">
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;">
      <div style="position:relative;">
        <i class="fa-solid fa-magnifying-glass" style="position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--mut);font-size:12px;"></i>
        <input class="form-input" id="ex-host" placeholder="Trace a host IP, e.g. 192.168.0.25" style="padding-left:32px;width:300px;" onkeydown="if(event.key==='Enter'){loadExplorer(true);}">
      </div>
      <div class="seg" id="ex-dir">
        <button data-d="both" class="on">Both ways</button>
        <button data-d="out">From host&nbsp;→</button>
        <button data-d="in">→&nbsp;To host</button>
      </div>
      <button class="btn" onclick="loadExplorer(true)"><i class="fa-solid fa-arrows-rotate"></i> Apply</button>
      <button class="btn" onclick="document.getElementById('ex-host').value='';loadExplorer(true);"><i class="fa-solid fa-xmark"></i> Clear</button>
      <span class="mut" id="ex-hint" style="font-size:11px;margin-left:auto;">Click any node or IP to trace its path.</span>
    </div>
  </div>
  <div class="glass-card">
    <h2 style="display:flex;align-items:center;gap:8px;"><i class="fa-solid fa-diagram-project"></i> Traffic Path Map
      <span class="mut" style="font-weight:400;font-size:11px;">arrows = direction · thickness = bandwidth · node size = total traffic · scroll = zoom · drag = pan</span>
      <span style="margin-left:auto;display:flex;gap:6px;">
        <button class="nf-mapbtn" onclick="nfZoomReset()" title="Reset zoom &amp; re-center"><i class="fa-solid fa-crosshairs"></i></button>
        <button class="nf-mapbtn" onclick="nfFull()" id="nf-fsbtn" title="Toggle full screen"><i class="fa-solid fa-expand"></i> Full screen</button>
      </span>
    </h2>
    <div id="ex-wrap" style="display:flex;gap:10px;height:64vh;min-height:480px;position:relative;border-radius:12px;overflow:hidden;background:#05080e;">
      <div id="ex-fsctrl" style="position:absolute;top:10px;left:10px;z-index:6;display:flex;gap:6px;flex-wrap:wrap;">
        <button class="nf-mapbtn" id="ex-clear" onclick="clearHost()" title="Clear the host filter" style="display:none;"><i class="fa-solid fa-filter-circle-xmark"></i> Clear filter</button>
        <button class="nf-mapbtn" onclick="nfZoomReset()" title="Reset zoom &amp; re-center"><i class="fa-solid fa-crosshairs"></i></button>
        <button class="nf-mapbtn" id="ex-fsbtn2" onclick="nfFull()" title="Toggle full screen"><i class="fa-solid fa-expand"></i></button>
      </div>
      <div id="ex-graph" style="flex:1;position:relative;z-index:1;border-radius:12px;overflow:hidden;background:radial-gradient(circle at 50% 40%, rgba(77,163,255,.05), transparent 72%);"></div>
      <div id="ex-side" style="width:290px;flex:0 0 290px;position:relative;z-index:1;overflow:auto;border-left:1px solid rgba(255,255,255,.08);padding-left:12px;background:rgba(5,8,14,.40);backdrop-filter:blur(4px);border-radius:0 12px 12px 0;">
        <div class="mut" style="font-size:10.5px;text-transform:uppercase;letter-spacing:1.2px;margin:10px 0 8px;"><i class="fa-solid fa-bolt"></i> Live top flows <span style="text-transform:none;letter-spacing:0;">· click an IP to trace</span></div>
        <div id="ex-side-list"><div class="mut" style="font-size:12px;">Apply a window to load flows.</div></div>
      </div>
    </div>
  </div>
  <div class="glass-card">
    <h2><i class="fa-solid fa-list"></i> Directional Flows</h2>
    <div style="overflow-x:auto;max-height:60vh;"><table>
      <thead><tr><th>Source</th><th></th><th>Destination</th><th>Application</th><th>Proto</th>
        <th style="text-align:right;">Bandwidth</th><th style="text-align:right;">Packets</th><th style="text-align:right;">Flows</th></tr></thead>
      <tbody id="ex-flows"><tr><td colspan="8" class="mut" style="text-align:center;padding:20px;">Apply to load flows.</td></tr></tbody>
    </table></div>
  </div>
</section>

<!-- threshold modal -->
<div class="modal-bg" id="thr-modal"><div class="modal">
  <h3><i class="fa-solid fa-sliders"></i> Bandwidth Alert Thresholds</h3>
  <div class="mut" style="font-size:12px;margin-bottom:14px;">Alert when an application's bandwidth crosses these limits (Mbps). The global default applies
    to every app; add a per-app override below. Leave blank to use the global / disable. A baseline anomaly also fires when an app jumps to
    <b><?= (int)$NF['baseline_mult'] ?>×</b> its 24h average.</div>
  <div class="row2">
    <div class="fld"><label>Global warn (Mbps)</label><input class="form-input" id="g-warn" type="number" step="0.1"></div>
    <div class="fld"><label>Global crit (Mbps)</label><input class="form-input" id="g-crit" type="number" step="0.1"></div>
  </div>
  <div style="border-top:1px solid var(--border);margin:8px 0 12px;"></div>
  <div class="row2" style="grid-template-columns:1.4fr 1fr 1fr;align-items:end;">
    <div class="fld"><label>Application</label>
      <select class="form-select" id="app-sel" style="width:100%;"></select></div>
    <div class="fld"><label>Warn</label><input class="form-input" id="a-warn" type="number" step="0.1"></div>
    <div class="fld"><label>Crit</label><input class="form-input" id="a-crit" type="number" step="0.1"></div>
  </div>
  <div id="app-thr-list" style="font-size:11px;color:var(--mut);"></div>
  <div class="modal-actions">
    <button class="btn" onclick="closeM('thr-modal')">Close</button>
    <button class="btn" style="border-color:var(--accent);color:var(--accent);" onclick="saveAppThr()">Save app override</button>
    <button class="btn" style="background:rgba(46,204,113,.15);border-color:var(--up);color:var(--up);" onclick="saveGlobalThr()">Save global</button>
  </div>
</div></div>

<div id="toast"></div>
<script>
const ENABLED = <?= $NF['enabled']?'true':'false' ?>;
const CSRF = <?= json_encode($CSRF) ?>;
let RANGE='1h', EXPORTER='', bwChart=null, _booted=false;
function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2400);}
function closeM(id){document.getElementById(id).classList.remove('show');}
const mbps = v => v==null?'—':(v>=1000?(v/1000).toFixed(2)+' Gbps':v>=1?v.toFixed(1)+' Mbps':(v*1000).toFixed(0)+' Kbps');
const bytesH = b => { b=+b||0; const u=['B','KB','MB','GB','TB']; let i=0; while(b>=1024&&i<u.length-1){b/=1024;i++;} return b.toFixed(b<10&&i>0?2:0)+' '+u[i]; };
const numH = n => (+n||0).toLocaleString();

async function api(name, extra){ const r=await fetch(`netflow.php?api=${name}&range=${RANGE}&exporter=${encodeURIComponent(EXPORTER)}${extra||''}`).then(r=>r.json()); return r; }

function barList(el, items, label, valFn, color){
  const max = items.length ? Math.max.apply(null, items.map(valFn)) : 1;
  document.getElementById(el).innerHTML = items.length ? items.map(it=>`
    <div style="margin-bottom:9px;"><div style="display:flex;justify-content:space-between;font-size:12px;gap:8px;">
      <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${label(it)}</span>
      <span class="mut mono" style="white-space:nowrap;">${mbps(it.mbps)}</span></div>
      <div class="bar"><i style="width:${Math.round(valFn(it)/max*100)}%;background:${color||'var(--accent)'}"></i></div></div>`).join('')
    : '<div class="mut" style="padding:12px;">No data in this window.</div>';
}
function ipRows(el, items){
  const max = items.length?Math.max.apply(null,items.map(x=>x.mbps)):1;
  document.getElementById(el).innerHTML = items.length ? items.map(x=>`<tr>
    <td><span class="mono">${esc(x.ip)}</span>${x.geo?` <span class="mut" title="${esc(x.geo.country)}${x.geo.city?' · '+esc(x.geo.city):''}">${x.geo.flag} ${esc(x.geo.country)}</span>`:''}<div class="bar"><i style="width:${Math.round(x.mbps/max*100)}%"></i></div></td>
    <td style="text-align:right;white-space:nowrap;" class="mono">${mbps(x.mbps)}</td></tr>`).join('')
    : '<tr><td class="mut">No data</td></tr>';
}

async function loadOverview(){
  if(!ENABLED) return;
  let d; try{ d=await api('overview'); }catch(e){ return; }
  if(!d.ok) return;
  // status
  const st=d.status||{}, sb=document.getElementById('status-bar');
  sb.className='statusbar '+(st.alive?'ok':'bad');
  document.getElementById('status-txt').textContent = st.alive
    ? `collector live · ${numH(st.packets)} pkts · ${numH(st.flows)} flows${st.dropped>0?' · '+numH(st.dropped)+' dropped':''}`
    : (st.last_flush_ts ? `collector stale (${st.age_sec}s ago)` : 'no data received yet — point routers here');
  // kpis
  const s=d.summary||{};
  document.getElementById('k-bw').textContent = mbps(s.avg_mbps);
  document.getElementById('k-bytes').textContent = bytesH(s.bytes);
  document.getElementById('k-flows').textContent = numH(s.flows);
  document.getElementById('k-talkers').textContent = numH(s.talkers);
  document.getElementById('k-exporters').textContent = numH(s.exporters);
  // exporters dropdown
  const sel=document.getElementById('exp-sel');
  if(!_booted){ sel.innerHTML='<option value="">All exporters</option>'+(d.exporters||[]).map(e=>`<option value="${esc(e.exporter)}">${esc(e.exporter)}</option>`).join(''); }
  // chart
  const ctx=document.getElementById('bwChart').getContext('2d');
  const g=ctx.createLinearGradient(0,0,0,240); g.addColorStop(0,'rgba(77,163,255,.35)'); g.addColorStop(1,'rgba(77,163,255,0)');
  const labels=(d.series||[]).map(p=>new Date(p.t*1000)), data=(d.series||[]).map(p=>p.mbps);
  if(bwChart) bwChart.destroy();
  bwChart=new Chart(ctx,{type:'line',data:{labels,datasets:[{label:'Mbps',data,borderColor:'#4da3ff',backgroundColor:g,borderWidth:2,pointRadius:0,fill:true,tension:.3}]},
    options:{responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{display:false}},
      scales:{x:{type:'time',ticks:{color:'#666',maxTicksLimit:8},grid:{color:'rgba(255,255,255,.04)'}},
              y:{beginAtZero:true,ticks:{color:'#666',callback:v=>v+' M'},grid:{color:'rgba(255,255,255,.04)'}}}}});
  // apps / protocols / talkers / convos
  barList('apps', d.apps||[], it=>`<span class="tag t-app">${esc(it.app)}</span>`, it=>it.mbps);
  barList('protos', d.protocols||[], it=>esc(it.proto), it=>it.mbps, '#9b59b6');
  ipRows('talk-src', d.talkers_src||[]);
  ipRows('talk-dst', d.talkers_dst||[]);
  const cv=d.convos||[];
  document.getElementById('convos').innerHTML = cv.length ? cv.map(c=>`<tr>
    <td class="mono">${esc(c.src)}</td><td class="mono">${esc(c.dst)}</td>
    <td><span class="tag t-app">${esc(c.app)}</span></td>
    <td style="text-align:right;" class="mono">${mbps(c.mbps)}</td>
    <td style="text-align:right;" class="mono">${numH(c.flows)}</td></tr>`).join('')
    : '<tr><td colspan="5" class="mut" style="text-align:center;padding:20px;">No conversations in this window.</td></tr>';
  // alerts
  const al=d.alerts||[], ac=document.getElementById('alerts-card');
  ac.classList.toggle('hidden', al.length===0);
  document.getElementById('alerts-count').textContent = al.length?`(${al.length} active)`:'';
  document.getElementById('alerts-list').innerHTML = al.map(a=>{
    const c=a.severity==='critical'?'crit':'warn';
    return `<div class="alert-card ${c}"><span class="sev-badge ${c}">${esc(a.severity)}</span>
      <b>${esc(a.scope)}</b> using <b>${(+a.value_mbps).toFixed(1)} Mbps</b>
      <span class="mut">(threshold ${(+a.threshold_mbps).toFixed(1)} Mbps${a.baseline_mbps?', baseline '+(+a.baseline_mbps).toFixed(1):''})</span>
      <span class="mut" style="margin-left:auto;font-size:11px;">since ${esc(a.opened_at)}</span></div>`;
  }).join('');
  _booted=true;
}

// tabs
let TAB='overview', EXDIR='both';
function refreshActive(graphToo){ if(TAB==='explorer') loadExplorer(graphToo); else loadOverview(); }
document.querySelectorAll('.nm-tab').forEach(t=>t.addEventListener('click',e=>{
  e.preventDefault();
  document.querySelectorAll('.nm-tab').forEach(x=>x.classList.remove('is-active')); t.classList.add('is-active');
  TAB=t.getAttribute('href').slice(5); // 'tab-xxx' → 'xxx'
  document.getElementById('tab-overview').classList.toggle('hidden', TAB!=='overview');
  document.getElementById('tab-explorer').classList.toggle('hidden', TAB!=='explorer');
  refreshActive(true);
}));
// direction segmented
document.querySelectorAll('#ex-dir button').forEach(b=>b.addEventListener('click',()=>{
  document.querySelectorAll('#ex-dir button').forEach(x=>x.classList.remove('on')); b.classList.add('on');
  EXDIR=b.dataset.d; loadExplorer(true);
}));

// range + exporter
document.querySelectorAll('#range-seg button').forEach(b=>b.addEventListener('click',()=>{
  document.querySelectorAll('#range-seg button').forEach(x=>x.classList.remove('on')); b.classList.add('on');
  RANGE=b.dataset.r; refreshActive(true);
}));
document.getElementById('exp-sel').addEventListener('change',e=>{ EXPORTER=e.target.value; refreshActive(true); });

// thresholds modal
async function openThresholds(){
  const d=await fetch('netflow.php?api=thresholds_get').then(r=>r.json());
  document.getElementById('g-warn').value=d.thresholds.global.warn_mbps||'';
  document.getElementById('g-crit').value=d.thresholds.global.crit_mbps||'';
  const sel=document.getElementById('app-sel');
  sel.innerHTML=(d.apps||[]).map(a=>`<option>${esc(a)}</option>`).join('');
  const apps=d.thresholds.apps||{};
  document.getElementById('app-thr-list').innerHTML = Object.keys(apps).length
    ? 'Overrides: '+Object.entries(apps).map(([k,v])=>`<b>${esc(k)}</b> (w:${v.warn_mbps??'—'}/c:${v.crit_mbps??'—'})`).join(', ')
    : 'No per-app overrides yet.';
  sel.onchange=()=>{ const a=apps[sel.value]; document.getElementById('a-warn').value=a?a.warn_mbps||'':''; document.getElementById('a-crit').value=a?a.crit_mbps||'':''; };
  sel.onchange();
  document.getElementById('thr-modal').classList.add('show');
}
async function saveThr(scope,warn,crit){
  const fd=new FormData(); fd.append('api','thresholds_save'); fd.append('csrf',CSRF); fd.append('scope',scope); fd.append('warn',warn); fd.append('crit',crit);
  const r=await fetch('netflow.php?api=thresholds_save',{method:'POST',body:fd}).then(r=>r.json());
  if(r.ok){ toast('Saved'); openThresholds(); } else toast(r.err||'Failed');
}
function saveGlobalThr(){ saveThr('__global__', document.getElementById('g-warn').value, document.getElementById('g-crit').value); }
function saveAppThr(){ const a=document.getElementById('app-sel').value; if(!a){toast('Pick an app');return;} saveThr(a, document.getElementById('a-warn').value, document.getElementById('a-crit').value); }

// ════════════════════ FLOW EXPLORER ════════════════════
function setHost(ip){ document.getElementById('ex-host').value=ip; document.getElementById('ex-hint').textContent='Tracing '+ip; updateClearBtn(); loadExplorer(true); }
function clearHost(){ const h=document.getElementById('ex-host'); if(h)h.value=''; const t=document.getElementById('ex-hint'); if(t)t.textContent=''; updateClearBtn(); loadExplorer(true); }
function updateClearBtn(){ const v=((document.getElementById('ex-host')||{}).value||'').trim(); const b=document.getElementById('ex-clear'); if(b) b.style.display=v?'inline-flex':'none'; }
function dirArrow(){ return '<i class="fa-solid fa-arrow-right" style="color:var(--accent);"></i>'; }

async function loadExplorer(graphToo){
  if(!ENABLED) return;
  const host=document.getElementById('ex-host').value.trim();
  updateClearBtn();
  // directional flow table
  try{
    const d=await api('flows','&host='+encodeURIComponent(host)+'&dir='+EXDIR);
    const F=d.flows||[];
    document.getElementById('ex-flows').innerHTML = F.length ? F.map(f=>{
      const hot = host && (f.src===host||f.dst===host);
      return `<tr style="${hot?'background:rgba(77,163,255,.06);':''}">
        <td class="mono"><a href="#" onclick="setHost('${esc(f.src)}');return false;" style="color:#cfe3ff;text-decoration:none;">${esc(f.src)}</a></td>
        <td style="text-align:center;color:var(--accent);"><i class="fa-solid fa-arrow-right"></i></td>
        <td class="mono"><a href="#" onclick="setHost('${esc(f.dst)}');return false;" style="color:#cfe3ff;text-decoration:none;">${esc(f.dst)}</a></td>
        <td><span class="tag t-app">${esc(f.app)}</span></td>
        <td class="mut mono">${esc(f.proto)}</td>
        <td style="text-align:right;" class="mono">${mbps(f.mbps)}</td>
        <td style="text-align:right;" class="mono mut">${numH(f.packets)}</td>
        <td style="text-align:right;" class="mono mut">${numH(f.flows)}</td></tr>`;
    }).join('') : '<tr><td colspan="8" class="mut" style="text-align:center;padding:20px;">No flows'+(host?(' for '+esc(host)):'')+' in this window.</td></tr>';
  }catch(e){}
  // graph (skip on silent auto-refresh to avoid re-layout jumpiness)
  if(graphToo){
    try{ const g=await api('graph','&host='+encodeURIComponent(host)); renderGraph(g, host); }catch(e){}
  }
}

let _sim=null;
let _svg=null,_zoom=null,_zoomG=null,_nfRO=null;
function renderGraph(g, host){
  const el=document.getElementById('ex-graph'); el.innerHTML='';
  const nodes=(g.nodes||[]).map(n=>({...n, total:(+n.in||0)+(+n.out||0)}));
  const edges=(g.edges||[]).map(e=>({source:e.src, target:e.dst, mbps:+e.mbps||0, app:e.app}));
  renderFlowSide(edges);
  if(!nodes.length){ el.innerHTML='<div class="mut" style="text-align:center;padding:60px;">No traffic to map'+(host?(' for '+esc(host)):'')+' in this window.</div>'; return; }
  const W=el.clientWidth||900, H=el.clientHeight||460;
  const maxBw=Math.max(1,...edges.map(e=>e.mbps)), maxTot=Math.max(1,...nodes.map(n=>n.total));
  const rS=d3.scaleSqrt().domain([0,maxTot]).range([6,26]);
  const wS=d3.scaleLinear().domain([0,maxBw]).range([1,7]);
  const svg=d3.select(el).append('svg').attr('width','100%').attr('height','100%')
    .attr('viewBox',`0 0 ${W} ${H}`).style('display','block'); _svg=svg;
  svg.append('defs').append('marker').attr('id','nf-arrow').attr('viewBox','0 -5 10 10').attr('refX',22)
    .attr('refY',0).attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto')
    .append('path').attr('d','M0,-5L10,0L0,5').attr('fill','#4da3ff').attr('opacity',.7);
  const zoomG=svg.append('g'); _zoomG=zoomG;
  const link=zoomG.append('g').selectAll('line').data(edges).join('line')
    .attr('stroke','#4da3ff').attr('stroke-opacity',.35).attr('stroke-width',d=>wS(d.mbps))
    .attr('marker-end','url(#nf-arrow)');
  link.append('title').text(d=>`${d.source} → ${d.target} · ${d.app} · ${d.mbps.toFixed(2)} Mbps`);
  const node=zoomG.append('g').selectAll('g').data(nodes).join('g').style('cursor','pointer')
    .on('click',(e,d)=>setHost(d.id))
    .call(d3.drag()
      .on('start',(e,d)=>{ if(e.sourceEvent)e.sourceEvent.stopPropagation(); if(!e.active)_sim.alphaTarget(.3).restart(); d.fx=d.x; d.fy=d.y; })
      .on('drag',(e,d)=>{ d.fx=e.x; d.fy=e.y; })
      .on('end',(e,d)=>{ if(!e.active)_sim.alphaTarget(0); d.fx=null; d.fy=null; }));
  node.append('circle').attr('r',d=>rS(d.total))
    .attr('fill',d=>d.id===host?'#4da3ff':(d.out>d.in?'rgba(46,204,113,.85)':'rgba(155,89,182,.85)'))
    .attr('stroke',d=>d.id===host?'#fff':'rgba(255,255,255,.25)').attr('stroke-width',d=>d.id===host?2.5:1);
  node.append('title').text(d=>`${d.id}\n↑ out ${d.out.toFixed(2)} Mbps · ↓ in ${d.in.toFixed(2)} Mbps · ${d.deg} peers`);
  node.append('text').text(d=>d.id).attr('x',0).attr('y',d=>rS(d.total)+11)
    .attr('text-anchor','middle').attr('fill','#aeb6c2').attr('font-size','9.5px').attr('font-family','ui-monospace,monospace');
  _zoom=d3.zoom().scaleExtent([0.2,8]).on('zoom',e=>zoomG.attr('transform',e.transform));
  svg.call(_zoom).on('dblclick.zoom',null);
  _sim=d3.forceSimulation(nodes)
    .force('link',d3.forceLink(edges).id(d=>d.id).distance(d=>90+wS(d.mbps)*4))
    .force('charge',d3.forceManyBody().strength(-260))
    .force('center',d3.forceCenter(W/2,H/2))
    .force('collide',d3.forceCollide().radius(d=>rS(d.total)+14))
    .on('tick',()=>{
      link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
      node.attr('transform',d=>`translate(${d.x},${d.y})`);
    });
  if(!_nfRO){ _nfRO=new ResizeObserver(()=>nfResize()); _nfRO.observe(el); }
}
function nfResize(){
  const el=document.getElementById('ex-graph'); if(!el||!_svg||!_sim)return;
  const W=el.clientWidth||900,H=el.clientHeight||460;
  _svg.attr('viewBox',`0 0 ${W} ${H}`);
  _sim.force('center',d3.forceCenter(W/2,H/2)); _sim.alpha(.25).restart();
}
function renderFlowSide(edges){
  const box=document.getElementById('ex-side-list'); if(!box)return;
  const top=[...edges].sort((a,b)=>b.mbps-a.mbps).slice(0,18), mx=Math.max(1,...top.map(e=>e.mbps));
  box.innerHTML = top.length? top.map(e=>`<div class="ex-flowrow"><div style="flex:1;min-width:0;">
      <div class="mono" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"><span class="ex-ip" style="color:#7fe0a3;" onclick="setHost('${esc(e.source)}')" title="Trace ${esc(e.source)}">${esc(e.source)}</span> <span style="color:#566;">→</span> <span class="ex-ip" style="color:#c89be0;" onclick="setHost('${esc(e.target)}')" title="Trace ${esc(e.target)}">${esc(e.target)}</span></div>
      <div style="display:flex;justify-content:space-between;color:#8a909a;"><span>${esc(e.app||'')}</span><span class="mono" style="color:#cfe4ff;">${e.mbps.toFixed(2)} Mb/s</span></div>
      <div class="fbar" style="width:${Math.round(e.mbps/mx*100)}%"></div></div></div>`).join('')
    : '<div class="mut" style="font-size:12px;">No flows in this window.</div>';
}
function nfZoomReset(){ if(_svg&&_zoom){ _svg.transition().duration(400).call(_zoom.transform, d3.zoomIdentity); } nfResize(); }
function nfFull(){
  const w=document.getElementById('ex-wrap'); const rf=w.requestFullscreen||w.webkitRequestFullscreen;
  if(!document.fullscreenElement && !document.webkitFullscreenElement){ rf&&rf.call(w); }
  else { (document.exitFullscreen||document.webkitExitFullscreen||function(){}).call(document); }
}
function nfMoveBg(into){
  const bg=document.getElementById('nm-netbg'); if(!bg)return;   // the live interactive particle canvas
  if(into){ const w=document.getElementById('ex-wrap'); bg.style.zIndex='0'; w.insertBefore(bg, w.firstChild); }
  else { bg.style.zIndex='-1'; document.body.insertBefore(bg, document.body.firstChild); }
  setTimeout(()=>window.dispatchEvent(new Event('resize')),50);   // refit the canvas to the new container
}
document.addEventListener('fullscreenchange',()=>{
  const fs=!!document.fullscreenElement;
  const b=document.getElementById('nf-fsbtn'); if(b) b.innerHTML=fs?'<i class="fa-solid fa-compress"></i> Exit':'<i class="fa-solid fa-expand"></i> Full screen';
  const b2=document.getElementById('ex-fsbtn2'); if(b2) b2.innerHTML=fs?'<i class="fa-solid fa-compress"></i>':'<i class="fa-solid fa-expand"></i>';
  updateClearBtn();
  nfMoveBg(fs);
  setTimeout(nfResize,160);
});

if(ENABLED){
  loadOverview();
  setInterval(()=>{ if(!document.hidden) refreshActive(false); }, 15000);
  document.addEventListener('visibilitychange',()=>{ if(!document.hidden) refreshActive(false); });
  // deep-link: ?host=IP (e.g. from Network Sonar's "Open in NetFlow") → open Flow Explorer filtered to that host
  (function(){ const h=new URLSearchParams(location.search).get('host'); if(!h) return;
    const e=document.getElementById('ex-host'); if(e) e.value=h;
    const tab=document.querySelector('.nm-tab[href="#tab-explorer"]'); if(tab) tab.click(); else loadExplorer(true); })();
}
document.querySelectorAll('.modal-bg').forEach(m=>m.addEventListener('click',e=>{ if(e.target===m) m.classList.remove('show'); }));
</script>
</body>
</html>
