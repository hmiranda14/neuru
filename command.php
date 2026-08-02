<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Command Center. The interactive, in-portal sibling of the read-only NOC
// Geo Wall (geomap.php). Full-bleed geographic map with a futuristic HUD of glass
// widgets you can add / remove / drag / collapse (layout saved per-user), a
// click-a-node troubleshoot dock (Live Ping / Traceroute), and a fullscreen mode
// that carries the site particle background. Reuses net_mon_map.php?api=topo for
// the topology+traffic and nm_geomap.php's overlay payload VERBATIM. RBAC: 'command'.
// ─────────────────────────────────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) session_start();
include_once __DIR__ . '/connection.php';
require_once __DIR__ . '/access_control.php';
require_once __DIR__ . '/nm_command.php';
require_once __DIR__ . '/nm_widgets.php';   // Widget SDK: data broker + manifest + registry

if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$CSRF = $_SESSION['csrf_token'];

// ── JSON API ─────────────────────────────────────────────────────────────────
if (isset($_GET['api']) || isset($_POST['api'])) {
    header('Content-Type: application/json; charset=utf-8');
    if (empty($_SESSION['username']) || !checkAccess($conn, 'command')) {
        http_response_code(403); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit;
    }
    $api = $_GET['api'] ?? $_POST['api'];
    $uid = (int)($_SESSION['UID'] ?? 0);

    if ($api === 'dash') {
        $want = array_filter(array_map('trim', explode(',', $_GET['w'] ?? '')));
        session_write_close();
        echo json_encode(['ok'=>true] + nm_cmd_payload($conn, $want));
        exit;
    }
    if ($api === 'syslog_detail') {
        session_write_close();
        echo json_encode(nm_cmd_syslog_detail($conn, trim($_GET['host'] ?? ''), trim($_GET['ip'] ?? '')));
        exit;
    }
    // ── Widget SDK endpoints ─────────────────────────────────────────────────
    if ($api === 'ds') {                       // data broker (per-source permission enforced inside)
        session_write_close();
        $params = []; if (isset($_GET['p'])) { $p = json_decode($_GET['p'], true); if (is_array($p)) $params = $p; }
        echo json_encode(nm_ds_resolve($conn, $_GET['source'] ?? '', $params));
        exit;
    }
    if ($api === 'widgets_list') {             // installed widgets + the data-source catalog + sdk version
        session_write_close();
        echo json_encode(['ok'=>true, 'widgets'=>nm_widgets_list($conn, $uid),
            'catalog'=>nm_ds_catalog(), 'sdk'=>NM_WIDGET_SDK]);
        exit;
    }
    if ($api === 'marketplace') {              // official (NEURU) + community widgets
        session_write_close();
        echo json_encode(['ok'=>true] + nm_widgets_marketplace($conn, $uid));
        exit;
    }
    if ($api === 'widget_validate') {
        if (($_POST['csrf'] ?? '') !== $_SESSION['csrf_token']) { http_response_code(400); echo json_encode(['ok'=>false,'errors'=>['Invalid CSRF']]); exit; }
        echo json_encode(nm_widget_validate(json_decode($_POST['manifest'] ?? 'null', true)));
        exit;
    }
    if ($api === 'widget_install') {
        if (($_POST['csrf'] ?? '') !== $_SESSION['csrf_token']) { http_response_code(400); echo json_encode(['ok'=>false,'errors'=>['Invalid CSRF']]); exit; }
        $isAdmin = ($_SESSION['role'] ?? '') === 'admin';
        echo json_encode(nm_widget_install($conn, $uid, json_decode($_POST['manifest'] ?? 'null', true), $_POST['scope'] ?? 'user', $isAdmin));
        exit;
    }
    if ($api === 'widget_remove') {
        if (($_POST['csrf'] ?? '') !== $_SESSION['csrf_token']) { http_response_code(400); echo json_encode(['ok'=>false]); exit; }
        $isAdmin = ($_SESSION['role'] ?? '') === 'admin';
        echo json_encode(nm_widget_remove($conn, $uid, $_POST['widget_id'] ?? '', $isAdmin));
        exit;
    }
    if ($api === 'layout_get') {
        session_write_close();
        echo json_encode(['ok'=>true, 'layout'=>nm_cmd_layout_get($conn, $uid)]);
        exit;
    }
    if ($api === 'layout_save') {
        if (($_POST['csrf'] ?? '') !== $_SESSION['csrf_token']) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Invalid CSRF']); exit; }
        $raw = json_decode($_POST['layout'] ?? 'null', true);
        if (!is_array($raw)) { echo json_encode(['ok'=>false,'error'=>'Bad layout']); exit; }
        echo json_encode(nm_cmd_layout_set($conn, $uid, $raw));
        exit;
    }
    if ($api === 'gpu_list') {       // every monitored GPU target (for the GPU widget selector)
        session_write_close();
        $out = [];
        if ($conn->query("SHOW TABLES LIKE 'nm_gpu_targets'")->num_rows) {
            $r = $conn->query("SELECT t.id,t.name,t.node_id,n.display_name node_name
                               FROM nm_gpu_targets t LEFT JOIN nm_nodes n ON n.id=t.node_id
                               WHERE t.enabled=1 ORDER BY t.name");
            while ($r && $x = $r->fetch_assoc()) $out[] = $x;
        }
        echo json_encode(['ok'=>true,'targets'=>$out]); exit;
    }
    if ($api === 'aiobot') {          // NetAIObot live activity for the wall widget / dashboard
        session_write_close();
        require_once __DIR__ . '/nm_aiopilot.php';
        nm_aip_ensure($conn);
        $ev = $conn->query("SELECT e.phase,e.title,e.node_id,n.display_name,e.created_at
                            FROM nm_aip_events e JOIN nm_nodes n ON n.id=e.node_id
                            ORDER BY e.id DESC LIMIT 14");
        $events = $ev ? $ev->fetch_all(MYSQLI_ASSOC) : [];
        $act = (int)$conn->query("SELECT COUNT(*) c FROM nm_aip_sessions WHERE status='active'")->fetch_assoc()['c'];
        $wait= (int)$conn->query("SELECT COUNT(*) c FROM nm_aip_sessions WHERE status='awaiting_approval'")->fetch_assoc()['c'];
        echo json_encode(['ok'=>true,'enabled'=>nm_aip_enabled($conn),'bot'=>($events[0]['phase'] ?? 'idle'),
            'active'=>$act,'awaiting'=>$wait,'queued'=>nm_aip_queue_depth($conn),'events'=>$events]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'Unknown api']); exit;
}

// ── HTML page ────────────────────────────────────────────────────────────────
include('check.php');
if (!checkAccess($conn, 'command')) { header('Location: /denied_access.php?page=command'); exit; }
nm_cmd_ensure($conn);
require_once __DIR__ . '/logger.php';
log_user_action($conn, 'view_page', 'command.php');
include('header.php');   // portal nav + NMNetBG particle background (initialized on body)
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<script src="/leaflet.min.js"></script>
<script src="/nm_wallwidgets.js"></script>
<script src="/nm_widgetkit.js"></script>
<style>
html,body{ background:#000 !important; margin:0; overflow-x:hidden; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; }
:root{ --glass:rgba(255,255,255,.055); --border:rgba(255,255,255,.11); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cyan:#36e3d0; --purple:#c084fc; }
#cc-stage *,#cc-stage *::before,#cc-stage *::after{ box-sizing:border-box; }
#cc-stage{ position:relative; height:calc(100vh - 60px); min-height:520px; margin:6px; border:1px solid rgba(77,163,255,.14); border-radius:14px; overflow:hidden; background:rgba(4,7,12,.28); box-shadow:0 0 0 1px rgba(0,0,0,.4), inset 0 0 60px rgba(0,0,0,.35); }
#cc-map{ position:absolute; inset:0; background:transparent; z-index:1; }
.leaflet-container{ background:transparent !important; font-family:inherit; }
.leaflet-tile-pane{ opacity:.85; }
#cc-stage{ color:#eef1f5; }
#cc-fx{ position:absolute; inset:0; pointer-events:none; z-index:2; }
/* top HUD bar over the map */
#cc-bar{ position:absolute; top:10px; left:10px; right:10px; z-index:30; display:flex; align-items:center; gap:9px; flex-wrap:wrap;
  background:rgba(5,8,14,.55); backdrop-filter:blur(10px); border:1px solid var(--border); border-radius:12px; padding:7px 12px; }
#cc-bar .ttl{ font-weight:700; letter-spacing:.5px; display:flex; align-items:center; gap:8px; color:#fff; }
#cc-bar .ttl i{ color:var(--accent); }
.cc-chip{ display:flex; align-items:center; gap:6px; font-size:12.5px; background:var(--glass); border:1px solid var(--border); padding:4px 10px; border-radius:18px; }
.cc-chip b{ font-size:14px; } .cc-chip.ok b{color:var(--ok);} .cc-chip.crit b{color:var(--crit);} .cc-chip.warn b{color:var(--warn);} .cc-chip.cyan b{color:var(--cyan);} .cc-chip.purple b{color:var(--purple);}
#cc-bar .sp{ margin-left:auto; }
.cc-btn{ display:inline-flex; align-items:center; gap:6px; cursor:pointer; font-size:12.5px; color:#cfd6df; background:var(--glass); border:1px solid var(--border); padding:5px 11px; border-radius:9px; user-select:none; }
.cc-btn:hover{ border-color:var(--accent); color:#fff; }
#cc-clock{ font-variant-numeric:tabular-nums; font-size:13px; color:#aeb6c0; }
/* widgets menu */
#cc-menu{ position:absolute; top:54px; right:10px; z-index:40; width:240px; max-height:62vh; overflow:auto; display:none;
  background:rgba(7,11,18,.96); border:1px solid var(--border); border-radius:12px; padding:8px; box-shadow:0 18px 50px rgba(0,0,0,.6); }
#cc-menu h4{ margin:4px 6px 8px; font-size:11px; letter-spacing:1.3px; text-transform:uppercase; color:var(--accent); }
.cc-mrow{ display:flex; align-items:center; gap:9px; padding:7px 8px; border-radius:8px; font-size:13px; cursor:pointer; }
.cc-mrow:hover{ background:var(--glass); } .cc-mrow i.w{ width:16px; text-align:center; color:#8a909a; }
.cc-mrow .tog{ margin-left:auto; width:30px; height:17px; border-radius:10px; background:#2a313c; position:relative; transition:.15s; }
.cc-mrow.on .tog{ background:var(--accent); } .cc-mrow .tog::after{ content:''; position:absolute; top:2px; left:2px; width:13px; height:13px; border-radius:50%; background:#fff; transition:.15s; }
.cc-mrow.on .tog::after{ left:15px; }
/* floating glass widget */
.cc-w{ position:absolute; z-index:20; width:300px; color:#eef1f5; background:rgba(10,14,22,.94); backdrop-filter:blur(16px); border:1px solid rgba(255,255,255,.16);
  border-radius:12px; box-shadow:0 14px 40px rgba(0,0,0,.65); display:flex; flex-direction:column; max-height:46vh; }
.cc-w.collapsed{ max-height:none; }
.cc-w-h{ display:flex; align-items:center; gap:8px; padding:8px 11px; cursor:grab; border-bottom:1px solid var(--border); }
.cc-w-h.collapsed{ border-bottom:none; }
.cc-w-h .ti{ font-size:11px; text-transform:uppercase; letter-spacing:1.2px; color:var(--accent); display:flex; align-items:center; gap:7px; flex:1; }
.cc-w-h .cnt{ color:#9aa3ad; font-size:11px; font-weight:600; }
.cc-w-h .x{ color:#7c828c; cursor:pointer; font-size:12px; padding:2px 4px; } .cc-w-h .x:hover{ color:#f0a59d; }
.cc-w-h .cl{ color:#7c828c; cursor:pointer; font-size:12px; padding:2px 4px; } .cc-w-h .cl:hover{ color:#fff; }
.cc-w-b{ overflow:auto; padding:6px 11px 10px; }
.cc-w.collapsed .cc-w-b{ display:none; }
.row{ display:flex; align-items:center; gap:9px; padding:6px 2px; border-bottom:1px solid rgba(255,255,255,.09); font-size:13px; color:#eef1f5; }
.row:last-child{ border-bottom:none; } .dot{ width:9px;height:9px;border-radius:50%;flex:0 0 auto; } .mono{ font-family:monospace; } .muted{ color:#a7afba; }
.sev-critical{color:#f0a59d;} .sev-warning{color:#f0c674;} .sev-info{color:#9fbfe0;}
.bar-bg{ flex:1; height:6px; background:rgba(255,255,255,.07); border-radius:5px; overflow:hidden; } .bar-bg>i{ display:block; height:100%; background:linear-gradient(90deg,#2ecc71,#4da3ff); }
.k{ font-weight:700; } .empty{ color:#5b6470; font-size:12px; text-align:center; padding:14px 0; }
.cc-w-b::-webkit-scrollbar{ width:7px; } .cc-w-b::-webkit-scrollbar-thumb{ background:rgba(255,255,255,.14); border-radius:4px; }
.nodelink{ cursor:pointer; } .nodelink:hover{ text-decoration:underline; color:var(--accent); }
.spark{ display:block; width:74px; height:20px; }
.ntw-in{ background:#1b2129; color:#e6e9ee; border:1px solid var(--border); border-radius:7px; padding:6px 9px; font-size:12px; font-family:monospace; }
.ntw-b{ padding:5px 9px; font-size:11.5px; }
.ntw-out{ margin-top:7px; font-family:monospace; font-size:11.5px; max-height:200px; overflow:auto; background:rgba(0,0,0,.4); border-radius:7px; padding:7px 9px; white-space:pre-wrap; line-height:1.5; display:none; }
.cw-sel{ background:#1b2129; color:#e6e9ee; border:1px solid var(--border); border-radius:7px; padding:3px 6px; font-size:11px; max-width:120px; }
/* troubleshoot dock */
#cc-dock{ position:absolute; left:50%; transform:translateX(-50%); bottom:12px; z-index:35; display:none; width:min(560px,92%);
  background:rgba(7,11,18,.93); border:1px solid var(--border); border-radius:12px; padding:10px 12px; box-shadow:0 16px 44px rgba(0,0,0,.6); }
#cc-dock .dh{ display:flex; align-items:center; gap:10px; margin-bottom:8px; }
#cc-dock .dh b{ color:#fff; } #cc-dock .dh .ip{ font-family:monospace; color:var(--cyan); }
#cc-dock .dh .x{ margin-left:auto; cursor:pointer; color:#8a909a; } #cc-dock .dh .x:hover{ color:#f0a59d; }
#cc-dock .tools{ display:flex; gap:8px; flex-wrap:wrap; }
#cc-dock .out{ margin-top:9px; font-family:monospace; font-size:12px; max-height:170px; overflow:auto; background:rgba(0,0,0,.35); border-radius:8px; padding:8px 10px; display:none; white-space:pre-wrap; line-height:1.5; }
.legend{ position:absolute; bottom:10px; right:10px; z-index:25; background:rgba(5,8,14,.66); border:1px solid var(--border); border-radius:9px; padding:6px 10px; font-size:11px; display:flex; gap:12px; }
.legend span{ display:flex; align-items:center; gap:5px; }
/* keep particle bg visible behind the (semi-transparent) map */
#cc-stage:fullscreen{ margin:0; height:100vh; border:none; border-radius:0; }
#cc-stage:fullscreen #nm-netbg{ z-index:0 !important; }
select,option{ background:#1b2129; color:#e6e9ee; }
/* detail modal */
#cc-modal{ position:absolute; inset:0; z-index:60; display:none; align-items:center; justify-content:center; background:rgba(2,4,8,.62); backdrop-filter:blur(3px); }
#cc-modal.show{ display:flex; }
.cc-modal-card{ width:min(560px,94%); max-height:84%; display:flex; flex-direction:column; background:rgba(12,17,26,.98); border:1px solid rgba(77,163,255,.3); border-radius:14px; box-shadow:0 24px 70px rgba(0,0,0,.7); }
.cc-modal-h{ display:flex; align-items:center; gap:10px; padding:13px 16px; border-bottom:1px solid var(--border); font-weight:700; color:#fff; }
.cc-modal-h #cc-modal-title{ flex:1; min-width:0; }
.cc-modal-h .x{ cursor:pointer; color:#8a909a; } .cc-modal-h .x:hover{ color:#f0a59d; }
.cc-modal-b{ overflow:auto; padding:14px 16px; font-size:13px; line-height:1.5; }
.cc-kv{ display:flex; gap:10px; padding:5px 0; border-bottom:1px solid rgba(255,255,255,.06); }
.cc-kv .k{ width:120px; flex:0 0 auto; color:#8a929c; font-weight:600; } .cc-kv .v{ flex:1; min-width:0; word-break:break-word; }
.cc-sig{ border:1px solid var(--border); border-radius:9px; padding:8px 10px; margin-top:8px; background:rgba(255,255,255,.025); }
.cc-pill{ font-size:10px; font-weight:700; padding:2px 8px; border-radius:6px; text-transform:uppercase; }
.cc-modal-act{ display:flex; gap:8px; flex-wrap:wrap; margin:12px 0 4px; }
.cc-abtn{ display:inline-flex; align-items:center; gap:6px; cursor:pointer; font-size:12px; font-weight:600; color:#cfd6df; background:var(--glass); border:1px solid var(--border); padding:6px 12px; border-radius:8px; text-decoration:none; }
.cc-abtn:hover{ border-color:var(--accent); color:#fff; } .cc-abtn.ok:hover{ border-color:var(--ok); color:var(--ok); } .cc-abtn.mut:hover{ border-color:#8a909a; }
/* widget builder */
#cc-builder{ position:absolute; inset:0; z-index:65; display:none; align-items:center; justify-content:center; background:rgba(2,4,8,.62); backdrop-filter:blur(3px); }
#cc-builder.show{ display:flex; }
.cc-bld-tabs{ display:flex; gap:4px; padding:8px 14px 0; border-bottom:1px solid var(--border); }
.cc-bld-tab{ background:none; border:none; color:#8a929c; font-size:12.5px; font-weight:700; padding:8px 14px; cursor:pointer; border-bottom:2px solid transparent; }
.cc-bld-tab.on{ color:#fff; border-bottom-color:var(--accent); }
.cc-bld-grid{ display:grid; grid-template-columns:1fr 1fr; gap:10px 14px; }
.cc-bld-grid label, .cc-bld-map label{ display:flex; flex-direction:column; gap:4px; font-size:11px; color:#8a929c; font-weight:600; }
.cc-in{ background:#1b2129; color:#e6e9ee; border:1px solid var(--border); border-radius:8px; padding:7px 10px; font-size:13px; }
.cc-bld-map{ margin-top:12px; padding-top:12px; border-top:1px solid var(--border); display:grid; grid-template-columns:1fr 1fr; gap:10px 14px; }
.cc-bld-prev-h{ display:flex; align-items:center; justify-content:space-between; margin:14px 0 6px; font-size:11px; text-transform:uppercase; letter-spacing:1px; color:#8a929c; }
.cc-bld-prev{ background:rgba(8,12,19,.7); border:1px solid var(--border); border-radius:10px; padding:10px 12px; min-height:80px; max-height:240px; overflow:auto; }
.cc-src-fields{ grid-column:1/-1; font-size:10.5px; color:#7c828c; }
.b-mrow{ display:flex; align-items:center; gap:9px; padding:7px 9px; border:1px solid var(--border); border-radius:8px; margin-bottom:7px; font-size:12.5px; }
</style>

<div id="cc-stage">
  <div id="cc-map"></div>
  <canvas id="cc-fx"></canvas>

  <div id="cc-bar">
    <span class="ttl"><i class="fa-solid fa-satellite-dish"></i> Command Center</span>
    <span class="cc-chip ok"><i class="fa-solid fa-circle-check"></i> up <b id="c-up">—</b></span>
    <span class="cc-chip crit"><i class="fa-solid fa-circle-xmark"></i> down <b id="c-down">—</b></span>
    <span class="cc-chip warn"><i class="fa-solid fa-triangle-exclamation"></i> inc <b id="c-inc">—</b></span>
    <span class="cc-chip cyan"><i class="fa-brands fa-docker"></i> cont <b id="c-cont">—</b></span>
    <span class="cc-chip purple"><i class="fa-solid fa-shield-halved"></i> WG <b id="c-wg">—</b></span>
    <span class="sp"></span>
    <span id="cc-clock">—</span>
    <a class="cc-btn" href="hologram.php" title="3D Traffic Hologram — volumetric digital twin" style="text-decoration:none;"><i class="fa-solid fa-cube"></i> Hologram</a>
    <span class="cc-btn" id="b-widgets"><i class="fa-solid fa-table-cells-large"></i> Widgets</span>
    <span class="cc-btn" id="b-reset" title="Reset layout"><i class="fa-solid fa-rotate-left"></i></span>
    <span class="cc-btn" id="b-fit" title="Fit map to nodes"><i class="fa-solid fa-crosshairs"></i></span>
    <span class="cc-btn" id="b-full" title="Fullscreen"><i class="fa-solid fa-expand"></i></span>
  </div>

  <div id="cc-menu"><h4>Widgets</h4>
    <div class="cc-mrow" onclick="openBuilder()" style="color:#7dd3fc;border:1px dashed rgba(77,163,255,.4);justify-content:center;margin-bottom:6px;">
      <i class="fa-solid fa-plus"></i> Create / Import widget</div>
    <div id="cc-mlist"></div></div>

  <div id="cc-modal"><div class="cc-modal-card">
    <div class="cc-modal-h"><span id="cc-modal-title">Details</span><span class="x" onclick="closeModal()"><i class="fa-solid fa-xmark"></i></span></div>
    <div class="cc-modal-b" id="cc-modal-body"></div>
  </div></div>

  <div id="cc-builder"><div class="cc-modal-card" style="width:min(760px,96%);">
    <div class="cc-modal-h"><i class="fa-solid fa-puzzle-piece" style="color:#4da3ff;"></i> <span style="flex:1;">Widget Builder</span>
      <a class="cc-abtn" href="widgets.php" target="_blank" title="Open the full Widget Studio" style="margin-right:6px;"><i class="fa-solid fa-up-right-from-square"></i> Studio</a>
      <span class="x" onclick="closeBuilder()"><i class="fa-solid fa-xmark"></i></span></div>
    <div class="cc-modal-b" id="cc-builder-body"></div>
  </div></div>

  <div id="cc-dock">
    <div class="dh"><i class="fa-solid fa-wrench" style="color:var(--accent)"></i> <b id="dk-name">node</b> <span class="ip" id="dk-ip"></span>
      <span class="x" onclick="dockClose()"><i class="fa-solid fa-xmark"></i></span></div>
    <div class="tools">
      <span class="cc-btn" onclick="dockPing()"><i class="fa-solid fa-tower-broadcast"></i> Live Ping</span>
      <span class="cc-btn" onclick="dockTrace()"><i class="fa-solid fa-route"></i> Traceroute</span>
      <a class="cc-btn" id="dk-open-ping" target="_blank"><i class="fa-solid fa-up-right-from-square"></i> Full Ping</a>
      <a class="cc-btn" id="dk-open-trace" target="_blank"><i class="fa-solid fa-up-right-from-square"></i> Full Trace</a>
    </div>
    <div class="out" id="dk-out"></div>
  </div>

  <div class="legend">
    <span><i class="fa-solid fa-circle" style="color:#2ecc71"></i> up</span>
    <span><i class="fa-solid fa-circle" style="color:#e74c3c"></i> down</span>
    <span><span style="width:15px;height:2px;background:#4da3ff;display:inline-block"></span> traffic</span>
    <span><span style="width:15px;height:2px;background:#36e3d0;display:inline-block"></span> NetFlow</span>
    <span><span style="width:15px;height:2px;background:#c084fc;display:inline-block"></span> WG</span>
  </div>
</div>

<script>
const CSRF=<?= json_encode($CSRF) ?>;
const CAN_GLOBAL=<?= (($_SESSION['role'] ?? '') === 'admin') ? 'true' : 'false' ?>;
const REFRESH=20000;
let map, fx, ctx, NODES={}, LINKS=[], ARCS=[], WGPEERS=[], GROUPS={}, EXPANDED=new Set(), ORIGIN=null, maxLoad=1, DATA={};
let DIRTY=true, FITTED=false;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function fmtR(v){ v=+v||0; if(v>=1e9)return (v/1e9).toFixed(1)+'G'; if(v>=1e6)return (v/1e6).toFixed(1)+'M'; if(v>=1e3)return (v/1e3).toFixed(1)+'k'; return v.toFixed(0); }
function clock(){ document.getElementById('cc-clock').textContent=new Date().toLocaleTimeString(); }
setInterval(clock,1000); clock();

/* ── Widget catalog ── id, title, icon, default-on, default side, render(data) ── */
const WIDGETS={
  nettools:{t:'Net Tools', i:'fa-toolbox', on:false, side:'l', static:true, render:()=>nettoolsHTML()},
  aiobot: {t:'NetAIObot', i:'fa-robot', on:false, side:'l', static:true, render:()=>'<div class="empty">…</div>', onmount:el=>mountAiobot(el)},
  gpu:    {t:'GPU', i:'fa-microchip', on:false, side:'r', static:true, render:()=>'<div class="empty">…</div>', onmount:el=>mountGpu(el)},
  sonify:{t:'Network Sonar', i:'fa-satellite-dish', on:false, side:'l', static:true, render:()=>window.NMWall?NMWall.sonifyHTML():'', onmount:el=>{ if(window.NMWall) NMWall.wireSonify(el); }},
  inc:    {t:'Incidents', i:'fa-triangle-exclamation', on:true,  side:'l', render:d=>renderIncidents(d.incidents||[])},
  down:   {t:'Nodes down', i:'fa-plug-circle-xmark',   on:true,  side:'l', render:d=>renderDown(d.down||[])},
  syslog: {t:'Syslog', i:'fa-file-lines',              on:true,  side:'l', render:d=>renderSyslog(d.syslog||[])},
  top_if: {t:'Top Interfaces', i:'fa-ethernet',        on:true,  side:'r', render:d=>renderTopIf(d.top_if||[])},
  netflow:{t:'NetFlow Top-20', i:'fa-fire',            on:true,  side:'r', render:d=>renderNetflow(d.netflow||[])},
  smoke:  {t:'Latency (Smokeping)', i:'fa-wave-square',on:true,  side:'r', render:d=>renderSmoke(d.smoke||[])},
  ph_q:   {t:'Pi-hole Top Queries', i:'fa-shield-halved', on:true, side:'r', render:d=>renderPhQ(d.pihole||{})},
  cont:   {t:'Containers', i:'fa-docker', fa:'brands', on:true,  side:'r', render:d=>renderCont(d.containers||{})},
  top_node:{t:'Top Traffic Nodes', i:'fa-gauge-high',  on:false, side:'r', render:d=>renderTopNode(d.top||[])},
  ph_c:   {t:'Pi-hole Top Clients', i:'fa-network-wired', on:false, side:'r', render:d=>renderPhC(d.pihole||{})},
  wg:     {t:'WireGuard Peers', i:'fa-shield-halved',  on:false, side:'r', render:d=>renderWG(d.wgpeers||[])},
};
const ORDER=['nettools','aiobot','sonify','inc','down','syslog','top_if','netflow','smoke','gpu','ph_q','cont','top_node','ph_c','wg'];

// ── NetAIObot live widget (what the AI is doing right now + recent log) ──────
function mountAiobot(b){ const w=b.closest('.cc-w');
  const tick=async()=>{ let r=null; try{ r=await fetch('command.php?api=aiobot').then(x=>x.json()); }catch(e){}
    b.innerHTML=(!r||!r.ok)?'<div class="empty">AI Command Center unavailable</div>':aiobotHTML(r); };
  tick(); if(w){ if(w._t)clearInterval(w._t); w._t=setInterval(tick,4000); } }
function aiobotHTML(r){
  const st={observe:['OBSERVING','#22d3ee'],think:['THINKING','#9b6bff'],act:['ACTING','#f39c12'],result:['VERIFYING','#2ecc71'],error:['ERROR','#e74c3c'],system:['STANDBY','#8a909a'],idle:['IDLE','#8a909a']}[r.bot]||['IDLE','#8a909a'];
  const c=r.enabled?st[1]:'#e74c3c';
  const head=`<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
     <span style="width:9px;height:9px;border-radius:50%;background:${c};box-shadow:0 0 8px ${c};"></span>
     <b style="color:${c};font-size:12px;letter-spacing:.5px;">${r.enabled?st[0]:'OFFLINE'}</b>
     <span style="margin-left:auto;font-size:10px;color:#8a909a;" title="active · awaiting · queued"><i class="fa-solid fa-bolt"></i>${r.active} <i class="fa-solid fa-clock"></i>${r.awaiting} <i class="fa-solid fa-layer-group"></i>${r.queued}</span></div>`;
  const ev=(r.events||[]).map(e=>{ const ic={observe:'fa-satellite-dish',think:'fa-brain',act:'fa-bolt',result:'fa-circle-check',error:'fa-triangle-exclamation',system:'fa-gear'}[e.phase]||'fa-circle';
    const col=e.phase==='result'?'#ff9c91':(e.phase==='think'?'#cdb4ff':(e.phase==='observe'?'#7fe6f5':(e.phase==='act'?'#f3c879':'#aeb6c2')));
    return `<div style="display:flex;gap:6px;align-items:flex-start;font-size:11px;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.05);">
      <span style="font-size:9px;font-weight:800;background:rgba(77,163,255,.16);color:#bcd;border:1px solid rgba(77,163,255,.3);padding:0 6px;border-radius:20px;white-space:nowrap;">${esc(e.display_name||'')}</span>
      <i class="fa-solid ${ic}" style="color:${col};margin-top:2px;"></i>
      <span style="color:${col};flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(e.title||e.phase)}</span></div>`; }).join('');
  return head+(ev||'<div class="empty">idle — nothing running</div>');
}

// ── GPU widget WITH a selector for ANY monitored GPU (was stuck on one) ──────
function mountGpu(b){ const w=b.closest('.cc-w'); let targets=[], selNode=null;
  const draw=async()=>{
    if(!targets.length){ const t=await fetch('command.php?api=gpu_list').then(x=>x.json()).catch(()=>null);
      targets=(t&&t.targets)||[]; if(!targets.length){ b.innerHTML='<div class="empty">No GPUs monitored.</div>'; return; }
      if(selNode==null) selNode=+targets[0].node_id; }
    const opts=targets.map(t=>`<option value="${t.node_id}"${(+t.node_id===+selNode)?' selected':''}>${esc(t.name||t.node_name||('node '+t.node_id))}</option>`).join('');
    let g=null; try{ g=await fetch('net_mon_stats.php?api=gpu_stats&node_id='+selNode+'&range=6h',{credentials:'same-origin'}).then(x=>x.json()); }catch(e){}
    b.innerHTML=`<select class="gpu-sel" style="width:100%;background:rgba(10,16,28,.85);border:1px solid rgba(77,163,255,.4);color:#cfe4ff;border-radius:7px;padding:5px 8px;font-size:12px;margin-bottom:6px;">${opts}</select>`+gpuBody(g);
    const s=b.querySelector('.gpu-sel'); if(s) s.onchange=()=>{ selNode=+s.value; draw(); };
  };
  draw(); if(w){ if(w._t)clearInterval(w._t); w._t=setInterval(draw,6000); } }
function gpuRows(nm,util,vram,temp,power){
  const row=(l,v,u,c)=>`<div style="display:flex;align-items:center;gap:8px;font-size:11px;padding:3px 0;"><span style="width:7px;height:7px;border-radius:50%;background:${c};box-shadow:0 0 6px ${c};"></span><span style="color:#9aa;width:48px;">${l}</span><b style="color:${c};margin-left:auto;">${v==null?'—':v+u}</b></div>`;
  return `<div style="font-size:11px;color:#8a909a;margin:2px 0 4px;">${esc(nm)}</div>`
    +row('GPU',util,'%','#2ecc71')+row('VRAM',vram,'%','#4da3ff')+row('Temp',temp,'°C','#f39c12')+row('Power',power,'W','#c084fc');
}
function gpuBody(g){
  if(!g||!g.has_gpu) return '<div class="empty">No live GPU data for this target.</div>';
  const gpus=(g.gpus&&g.gpus.length)?g.gpus:[];
  if(!gpus.length){ const last=a=>Array.isArray(a)?[...a].reverse().find(v=>v!=null):a;
    return gpuRows(g.name||'GPU', last(g.util), last(g.vram), last(g.temp), last(g.power)); }
  return gpus.map(x=>{ const l=x.latest||{}; const vram=(l.mem_total_mb? Math.round(100*l.mem_used_mb/l.mem_total_mb):null);
    return gpuRows(x.name||('GPU '+x.gpu_index), l.util_pct, vram, l.temp_c, (l.power_w!=null?Math.round(l.power_w):null)); }).join('<div style="height:7px;border-top:1px solid rgba(255,255,255,.06);margin-top:5px;"></div>');
}
let CONT_HOST='';
let LAYOUT={};   // id => {on, x, y, collapsed}

/* ── Map + animation (reuses the Geo Wall engine) ── */
function initMap(){
  map=L.map('cc-map',{worldCopyJump:true,zoomControl:true,attributionControl:false,preferCanvas:true}).setView([18.4,-66.1],6);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{subdomains:'abcd',maxZoom:19}).addTo(map);
  fx=document.getElementById('cc-fx'); ctx=fx.getContext('2d');
  const ro=()=>{ const s=document.getElementById('cc-stage'); fx.width=s.clientWidth; fx.height=s.clientHeight; DIRTY=true; map.invalidateSize(); };
  window.addEventListener('resize',ro); setTimeout(ro,160);
  map.on('move zoom moveend zoomend',()=>{DIRTY=true;});
  map.on('click',e=>{
    const cp=e.containerPoint;
    // cluster expand
    for(const key in GROUPS){ const grp=GROUPS[key]; if(grp.members.length<2)continue;
      const p=map.latLngToContainerPoint([grp.lat,grp.lon]);
      if(Math.hypot(p.x-cp.x,p.y-cp.y) < (EXPANDED.has(key)?16:22)){ EXPANDED.has(key)?EXPANDED.delete(key):EXPANDED.add(key); DIRTY=true; return; } }
    // node click → troubleshoot dock (hit-test single/expanded nodes)
    let best=null,bd=18;
    for(const key in GROUPS){ const grp=GROUPS[key]; const [cx,cy]=P(grp.lat,grp.lon);
      const members=grp.members.map(id=>NODES[id]).filter(Boolean);
      if(members.length===1){ const dd=Math.hypot(cx-cp.x,cy-cp.y); if(dd<bd){bd=dd;best=members[0];} }
      else if(EXPANDED.has(key)){ const R=Math.max(48,members.length*9);
        members.forEach((m,i)=>{ const a=2*Math.PI*i/members.length-Math.PI/2; const mx=cx+R*Math.cos(a),my=cy+R*Math.sin(a);
          const dd=Math.hypot(mx-cp.x,my-cp.y); if(dd<bd){bd=dd;best=m;} }); } }
    if(best) openDock(best);
  });
  requestAnimationFrame(animate);
}
function P(lat,lon){ const p=map.latLngToContainerPoint([lat,lon]); return [p.x,p.y]; }
function loadColor(t){ t=Math.min(1,t); const r=t<.5?Math.round(46+(243-46)*t*2):243, g=t<.5?Math.round(204-(204-156)*t*2):Math.round(156-(156-76)*(t-.5)*2), b=t<.5?Math.round(113-(113-18)*t*2):Math.round(18+(60-18)*(t-.5)*2); return `rgb(${r},${g},${b})`; }
function animate(ts){
  if(ctx){
    const W=fx.width,H=fx.height; ctx.clearRect(0,0,W,H);
    LINKS.forEach(l=>{ const a=NODES[l.s],b=NODES[l.t]; if(!a||!b||a.lat==null||b.lat==null)return;
      const [x1,y1]=P(a.lat,a.lon),[x2,y2]=P(b.lat,b.lon);
      const load=(l.in+l.out)||0, t=maxLoad?load/maxLoad:0, col=loadColor(t);
      ctx.strokeStyle='rgba(120,150,190,.18)'; ctx.lineWidth=1; ctx.beginPath(); ctx.moveTo(x1,y1); ctx.lineTo(x2,y2); ctx.stroke();
      if(load<=0)return; const n=Math.max(1,Math.min(7,Math.round(t*7)+1)), speed=0.00006+t*0.00022;
      for(let i=0;i<n;i++){ let ph=((ts*speed)+(i/n))%1; const x=x1+(x2-x1)*ph,y=y1+(y2-y1)*ph;
        const g=ctx.createRadialGradient(x,y,0,x,y,5); g.addColorStop(0,col); g.addColorStop(1,'rgba(0,0,0,0)');
        ctx.fillStyle=g; ctx.beginPath(); ctx.arc(x,y,5,0,7); ctx.fill(); } });
    if(ORIGIN) ARCS.forEach((arc,idx)=>{ const [x1,y1]=P(ORIGIN.lat,ORIGIN.lon),[x2,y2]=P(arc.lat,arc.lon);
      const mx=(x1+x2)/2,my=(y1+y2)/2-Math.hypot(x2-x1,y2-y1)*0.28;
      ctx.strokeStyle='rgba(54,227,208,.25)'; ctx.lineWidth=1; ctx.beginPath(); ctx.moveTo(x1,y1); ctx.quadraticCurveTo(mx,my,x2,y2); ctx.stroke();
      let ph=((ts*0.00012)+(idx*0.13))%1, mt=1-ph; const x=mt*mt*x1+2*mt*ph*mx+ph*ph*x2, y=mt*mt*y1+2*mt*ph*my+ph*ph*y2;
      const g=ctx.createRadialGradient(x,y,0,x,y,4.5); g.addColorStop(0,'#36e3d0'); g.addColorStop(1,'rgba(0,0,0,0)');
      ctx.fillStyle=g; ctx.beginPath(); ctx.arc(x,y,4.5,0,7); ctx.fill(); });
    const pulse=0.5+0.5*Math.sin(ts*0.004);
    WGPEERS.forEach((p,idx)=>{ if(p.slat==null||p.lat==null)return; const [x1,y1]=P(p.slat,p.slon),[x2,y2]=P(p.lat,p.lon);
      const mx=(x1+x2)/2,my=(y1+y2)/2-Math.hypot(x2-x1,y2-y1)*0.22;
      ctx.strokeStyle='rgba(168,85,247,.22)'; ctx.lineWidth=1; ctx.beginPath(); ctx.moveTo(x1,y1); ctx.quadraticCurveTo(mx,my,x2,y2); ctx.stroke();
      let ph=((ts*0.00014)+(idx*0.17))%1, mt=1-ph; const cxp=mt*mt*x1+2*mt*ph*mx+ph*ph*x2, cyp=mt*mt*y1+2*mt*ph*my+ph*ph*y2;
      let g=ctx.createRadialGradient(cxp,cyp,0,cxp,cyp,4); g.addColorStop(0,'#c084fc'); g.addColorStop(1,'rgba(0,0,0,0)');
      ctx.fillStyle=g; ctx.beginPath(); ctx.arc(cxp,cyp,4,0,7); ctx.fill();
      g=ctx.createRadialGradient(x2,y2,0,x2,y2,12); g.addColorStop(0,'#a855f7'); g.addColorStop(1,'rgba(0,0,0,0)');
      ctx.fillStyle=g; ctx.globalAlpha=.6; ctx.beginPath(); ctx.arc(x2,y2,12,0,7); ctx.fill(); ctx.globalAlpha=1;
      ctx.fillStyle='#c084fc'; ctx.beginPath(); ctx.arc(x2,y2,3.5,0,7); ctx.fill();
      ctx.fillStyle='rgba(216,180,254,.85)'; ctx.font='10px Segoe UI'; ctx.textAlign='center'; ctx.fillText(p.name||'',x2,y2+15); });
    const drawNode=(nd,x,y,dy)=>{ const col=nd.status==='down'?'#e74c3c':nd.status==='up'?'#2ecc71':'#8a909a';
      const rad=nd.status==='down'?(7+pulse*6):7; let g=ctx.createRadialGradient(x,y,0,x,y,rad*2.4);
      g.addColorStop(0,col); g.addColorStop(1,'rgba(0,0,0,0)');
      ctx.fillStyle=g; ctx.globalAlpha=nd.status==='down'?(.5+pulse*.5):.6; ctx.beginPath(); ctx.arc(x,y,rad*2.4,0,7); ctx.fill();
      ctx.globalAlpha=1; ctx.fillStyle=col; ctx.beginPath(); ctx.arc(x,y,4,0,7); ctx.fill();
      ctx.fillStyle='rgba(230,235,240,.92)'; ctx.font='11px Segoe UI'; ctx.textAlign='center'; ctx.fillText(nd.name||'',x,y+dy); };
    for(const key in GROUPS){ const grp=GROUPS[key]; const [cx,cy]=P(grp.lat,grp.lon);
      const members=grp.members.map(id=>NODES[id]).filter(Boolean); if(!members.length)continue;
      if(members.length===1){ drawNode(members[0],cx,cy,18); continue; }
      if(!EXPANDED.has(key)){ const anyDown=members.some(m=>m.status==='down'), allUp=members.every(m=>m.status==='up');
        const col=anyDown?'#e74c3c':allUp?'#2ecc71':'#f39c12';
        let g=ctx.createRadialGradient(cx,cy,0,cx,cy,22); g.addColorStop(0,col); g.addColorStop(1,'rgba(0,0,0,0)');
        ctx.fillStyle=g; ctx.globalAlpha=.5; ctx.beginPath(); ctx.arc(cx,cy,22,0,7); ctx.fill(); ctx.globalAlpha=1;
        ctx.fillStyle=col; ctx.beginPath(); ctx.arc(cx,cy,12,0,7); ctx.fill();
        ctx.fillStyle='#05080e'; ctx.font='bold 12px Segoe UI'; ctx.textAlign='center'; ctx.textBaseline='middle'; ctx.fillText(members.length,cx,cy); ctx.textBaseline='alphabetic';
        ctx.fillStyle='rgba(230,235,240,.8)'; ctx.font='10px Segoe UI'; ctx.fillText((members[0].city||'site')+' · '+members.length+' nodes — click',cx,cy+26);
      } else { const R=Math.max(48,members.length*9);
        members.forEach((m,i)=>{ const a=2*Math.PI*i/members.length-Math.PI/2; const mx=cx+R*Math.cos(a),my=cy+R*Math.sin(a);
          ctx.strokeStyle='rgba(255,255,255,.16)'; ctx.lineWidth=1; ctx.beginPath(); ctx.moveTo(cx,cy); ctx.lineTo(mx,my); ctx.stroke(); drawNode(m,mx,my,16); });
        ctx.fillStyle='rgba(255,255,255,.55)'; ctx.beginPath(); ctx.arc(cx,cy,3,0,7); ctx.fill();
        ctx.fillStyle='rgba(150,160,175,.8)'; ctx.font='9px Segoe UI'; ctx.textAlign='center'; ctx.fillText('click to collapse',cx,cy-R-8); } }
  }
  requestAnimationFrame(animate);
}

/* ── data load ── */
function enabledKeys(){ return ORDER.filter(id=>LAYOUT[id]&&LAYOUT[id].on); }
async function load(){
  let topo=null,dash=null;
  const w=enabledKeys().filter(k=>['top_if','smoke','ph_q','ph_c','syslog','cont'].includes(k)).map(k=>({ph_q:'pihole',ph_c:'pihole'}[k]||k));
  try{ [topo,dash]=await Promise.all([
    fetch('net_mon_map.php?api=topo').then(r=>r.json()),
    fetch('command.php?api=dash&w='+encodeURIComponent([...new Set(w)].join(','))).then(r=>r.json())]); }catch(e){ return; }
  if(!dash||!dash.ok) return;
  DATA=dash;
  const G=dash.geo||{}; ORIGIN=dash.origin;
  const tnodes={}; (topo&&topo.nodes||[]).forEach(n=>tnodes[n.id]=n);
  const NN={}; let up=0,down=0;
  for(const id in G){ const g=G[id], tn=tnodes[id]||{};
    NN[id]={id:+id,name:g.name,ip:g.ip,lat:g.lat,lon:g.lon,city:g.city,country:g.country,
      status:tn.status||'unknown',in:tn.total_in||0,out:tn.total_out||0};
    if(NN[id].status==='up')up++; else if(NN[id].status==='down')down++; }
  NODES=NN;
  const GG={}; for(const id in NN){ const n=NN[id]; const k=n.lat.toFixed(3)+','+n.lon.toFixed(3); (GG[k]=GG[k]||{members:[]}).members.push(+id); }
  for(const k in GG){ const m=GG[k].members; let la=0,lo=0; m.forEach(id=>{la+=NN[id].lat;lo+=NN[id].lon;}); GG[k].lat=la/m.length; GG[k].lon=lo/m.length; }
  GROUPS=GG; [...EXPANDED].forEach(k=>{ if(!GG[k])EXPANDED.delete(k); });
  const LL=[]; let mx=1; (topo&&topo.links||[]).forEach(l=>{ if(NN[l.source]&&NN[l.target]){ const load=(l.in_rate||0)+(l.out_rate||0); if(load>mx)mx=load; LL.push({s:l.source,t:l.target,in:l.in_rate||0,out:l.out_rate||0}); }});
  LINKS=LL; maxLoad=mx;
  ARCS=(dash.netflow||[]).filter(t=>t.geo).map(t=>({lat:t.geo.lat,lon:t.geo.lon,ip:t.ip}));
  WGPEERS=(dash.wgpeers||[]).map(p=>{ const s=NN[p.srv_node]; return {name:p.name,lat:p.geo.lat,lon:p.geo.lon,endpoint:p.endpoint,iface:p.iface,srv:p.srv_name,
      slat:s?s.lat:(ORIGIN?ORIGIN.lat:null),slon:s?s.lon:(ORIGIN?ORIGIN.lon:null)}; });
  if(!FITTED){ const pts=Object.values(NN).map(n=>[n.lat,n.lon]).concat(WGPEERS.map(p=>[p.lat,p.lon])); if(pts.length){ map.fitBounds(pts,{padding:[70,70],maxZoom:9}); } FITTED=true; }
  DIRTY=true;
  // chips
  document.getElementById('c-up').textContent=up;
  document.getElementById('c-down').textContent=down;
  document.getElementById('c-inc').textContent=(dash.incidents||[]).length;
  const c=dash.containers||{}; document.getElementById('c-cont').textContent=c.ok?(c.running+'/'+c.total):'—';
  document.getElementById('c-wg').textContent=WGPEERS.length;
  // feed the sonification widget (muted until enabled)
  if(window.NMSonify&&window.NMWall) NMSonify.apply(NMWall.pulseFrom({netflow:dash.netflow,incidents:dash.incidents,down:dash.down,nodes:NODES}));
  renderAll();
}

/* ── widget body renderers ── */
function nodelink(name,ip){ return ip?`<span class="nodelink" onclick="openDockIP('${esc(ip)}','${esc(name)}')">${esc(name)}</span>`:esc(name); }
function renderIncidents(inc){ return inc.length? inc.map(i=>`<div class="row nodelink" style="cursor:pointer;" onclick="showIncident(${i.id})" title="View incident details"><span class="dot" style="background:${i.severity==='critical'?'#e74c3c':i.severity==='warning'?'#f39c12':'#4da3ff'}"></span>
   <div style="flex:1;"><div class="sev-${esc(i.severity)}" style="font-weight:600;">${esc(i.title)}</div>
   <div class="muted" style="font-size:11px;">${esc(i.root_entity||'')} · ${esc((i.status||'').toUpperCase())} · impact ${i.impact_count||0}</div></div>
   <i class="fa-solid fa-chevron-right" style="color:#5b6470;font-size:10px;"></i></div>`).join('')
   : '<div class="empty"><i class="fa-solid fa-circle-check" style="color:#2ecc71"></i> All clear</div>'; }
function renderDown(dn){ return dn.length? dn.map(d=>`<div class="row"><span class="dot" style="background:#e74c3c"></span>
   <div style="flex:1;"><b>${nodelink(d.name,d.ip)}</b> <span class="muted mono">${esc(d.ip)}</span></div></div>`).join('')
   : '<div class="empty"><i class="fa-solid fa-circle-check" style="color:#2ecc71"></i> Everything reachable</div>'; }
function renderSyslog(sl){ const sc=s=>s<=3?'#f0a59d':s<=4?'#f0c674':'#9fbfe0';
  return sl.length? sl.map(s=>`<div class="row nodelink" style="align-items:flex-start;cursor:pointer;" onclick="showSyslog('${esc(s.host)}','${esc(s.ip||'')}')" title="View host details + log history">
   <span class="dot" style="background:${sc(s.sev)};margin-top:4px;"></span>
   <div style="flex:1;min-width:0;"><div style="display:flex;gap:6px;font-size:11px;"><b>${esc(s.host)}</b><span class="muted">${esc(s.tag||'')}</span><span class="muted" style="margin-left:auto;">${esc((s.at||'').slice(11,19))}</span></div>
   <div style="font-size:11.5px;word-break:break-word;">${esc(s.msg)}</div></div></div>`).join('')
   : '<div class="empty">No syslog data</div>'; }
function renderTopIf(top){ const mx=Math.max(1,...top.map(t=>t.total));
  return top.length? top.map(t=>`<div class="row"><div style="width:118px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
   <b>${nodelink(t.node,t.ip)}</b><div class="muted" style="font-size:10.5px;">${esc(t.iface)}</div></div>
   <div class="bar-bg"><i style="width:${Math.round(t.total/mx*100)}%"></i></div>
   <div class="mono" style="width:58px;text-align:right;font-size:11px;">${fmtR(t.in_rate)}/${fmtR(t.out_rate)}</div></div>`).join('')
   : '<div class="empty">No interface data</div>'; }
function renderTopNode(top){ const mx=Math.max(1,...top.map(t=>t.total));
  return top.length? top.map(t=>`<div class="row"><div style="width:104px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><b>${nodelink(t.name,t.ip)}</b></div>
   <div class="bar-bg"><i style="width:${Math.round(t.total/mx*100)}%"></i></div>
   <div class="mono" style="width:58px;text-align:right;font-size:11px;">${fmtR(t.in_rate)}/${fmtR(t.out_rate)}</div></div>`).join('')
   : '<div class="empty">No traffic data</div>'; }
function renderNetflow(nf){ return nf.length? nf.map(t=>`<div class="row"><span class="dot" style="background:${t.geo?'#36e3d0':'#5b6470'}"></span>
   <div style="flex:1;"><span class="mono nodelink" onclick="openDockIP('${esc(t.ip)}','${esc(t.ip)}')">${esc(t.ip)}</span>
   ${t.geo?`<span class="muted" style="font-size:11px;"> ${esc((t.geo.city?t.geo.city+', ':'')+(t.geo.country||''))}</span>`:''}</div>
   <div class="k mono" style="font-size:11px;">${t.mbps} Mb/s</div></div>`).join('')
   : '<div class="empty">No NetFlow data</div>'; }
function sparkSvg(arr){ const v=arr.filter(x=>x!=null); if(v.length<2)return ''; const mn=Math.min(...v),mx=Math.max(...v),rg=(mx-mn)||1;
  const pts=arr.map((x,i)=>x==null?null:[i/(arr.length-1)*72+1, 18-(x-mn)/rg*16]).filter(Boolean).map(p=>p.join(',')).join(' ');
  return `<svg class="spark" viewBox="0 0 74 20"><polyline points="${pts}" fill="none" stroke="#4da3ff" stroke-width="1.5"/></svg>`; }
function renderSmoke(sm){ return sm.length? sm.map(s=>`<div class="row"><div style="flex:1;min-width:0;"><b>${esc(s.name)}</b></div>
   ${sparkSvg(s.spark||[])}<div class="mono" style="width:50px;text-align:right;font-size:11px;color:${s.rtt>120?'#f0a59d':s.rtt>60?'#f0c674':'#9fe0b0'}">${s.rtt}ms</div></div>`).join('')
   : '<div class="empty">No latency data</div>'; }
function renderPhQ(ph){ if(!ph.ok)return '<div class="empty">Pi-hole not configured</div>'; const q=ph.queries||[], mx=Math.max(1,...q.map(x=>x.count));
  const hd=ph.total!=null?`<div class="row muted" style="font-size:11px;"><div style="flex:1;">${(ph.total||0).toLocaleString()} queries</div><div>${ph.blocked_pct!=null?ph.blocked_pct+'% blocked':''}</div></div>`:'';
  return hd+(q.length? q.map(x=>`<div class="row"><div style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11.5px;" class="mono">${esc(x.name)}</div>
   <div class="bar-bg" style="max-width:70px;"><i style="width:${Math.round(x.count/mx*100)}%"></i></div><div class="mono" style="width:42px;text-align:right;font-size:11px;">${x.count}</div></div>`).join('')
   : '<div class="empty">No query data</div>'); }
function renderPhC(ph){ if(!ph.ok)return '<div class="empty">Pi-hole not configured</div>'; const cs=ph.clients||[], mx=Math.max(1,...cs.map(x=>x.count));
  return cs.length? cs.map(x=>`<div class="row"><div style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11.5px;"><b>${esc(x.name)}</b></div>
   <div class="bar-bg" style="max-width:70px;"><i style="width:${Math.round(x.count/mx*100)}%"></i></div><div class="mono" style="width:42px;text-align:right;font-size:11px;">${x.count}</div></div>`).join('')
   : '<div class="empty">No client data</div>'; }
function renderCont(c){
  const L=DATA.cont_list||{ok:false}; const items=L.items||[]; const hosts=L.hosts||[];
  if(!L.ok && !c.ok) return '<div class="empty">Portainer not configured</div>';
  if(CONT_HOST && !hosts.includes(CONT_HOST)) CONT_HOST='';
  const run=items.filter(x=>x.state==='running').length;
  const filtered=CONT_HOST? items.filter(x=>x.host===CONT_HOST):items;
  const stColor=s=>s==='running'?'#2ecc71':s==='exited'?'#e74c3c':'#f39c12';
  let html=`<div class="row" style="gap:8px;">
     <div style="font-size:20px;font-weight:800;color:#2ecc71;">${run}</div>
     <div class="muted" style="font-size:11px;flex:1;">running / ${items.length} total</div>
     <select class="cw-sel" onchange="CONT_HOST=this.value;rerenderCont()"><option value="">all hosts</option>
       ${hosts.map(h=>`<option ${h===CONT_HOST?'selected':''}>${esc(h)}</option>`).join('')}</select></div>`;
  html+= filtered.length? filtered.map(x=>`<div class="row ${x.cid?'nodelink':''}" ${x.cid?`style="cursor:pointer;" onclick="showContainer(${x.eid},'${esc(x.cid)}','${esc(x.name)}')" title="View container details"`:''}>
     <span class="dot" style="background:${stColor(x.state)}"></span>
     <div style="flex:1;min-width:0;"><div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><b>${esc(x.name)}</b></div>
       <div class="muted" style="font-size:10.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(x.host)} · ${esc(x.image)}</div></div>
     <span class="muted" style="font-size:10px;">${esc(x.state)}</span>${x.cid?'<i class="fa-solid fa-chevron-right" style="color:#5b6470;font-size:10px;"></i>':''}</div>`).join('')
   : '<div class="empty">No containers'+(CONT_HOST?' on '+esc(CONT_HOST):'')+'</div>';
  return html;
}
function rerenderCont(){ const b=document.getElementById('wb-cont'); if(b) b.innerHTML=renderCont(DATA.containers||{}); }

/* ── Net Tools widget (ping / traceroute / nslookup inline) ── */
let _ntwEs=null;
function nettoolsHTML(){ return `<div style="display:flex;gap:6px;margin-bottom:7px;">
    <input id="ntw-target" class="ntw-in" style="flex:1;" placeholder="host or IP" onkeydown="if(event.key==='Enter')ntwPing()"></div>
  <div style="display:flex;gap:5px;flex-wrap:wrap;align-items:center;">
    <span class="cc-btn ntw-b" onclick="ntwPing()"><i class="fa-solid fa-tower-broadcast"></i> Ping</span>
    <span class="cc-btn ntw-b" onclick="ntwTrace()"><i class="fa-solid fa-route"></i> Trace</span>
    <select id="ntw-type" class="ntw-in"><option>A</option><option>AAAA</option><option>MX</option><option>NS</option><option>TXT</option><option>CNAME</option><option>SOA</option><option>PTR</option><option>ANY</option></select>
    <span class="cc-btn ntw-b" onclick="ntwLookup()"><i class="fa-solid fa-magnifying-glass-location"></i> Lookup</span>
    <span class="cc-btn ntw-b" onclick="ntwStop()" title="Stop"><i class="fa-solid fa-stop"></i></span></div>
  <div id="ntw-out" class="ntw-out"></div>`; }
function ntwTarget(){ const v=(document.getElementById('ntw-target')||{}).value; return (v||'').trim(); }
function ntwOut(){ const o=document.getElementById('ntw-out'); o.style.display='block'; return o; }
function ntwStop(){ if(_ntwEs){ _ntwEs.close(); _ntwEs=null; } }
function ntwPing(){ const ip=ntwTarget(); if(!ip)return; ntwStop(); const o=ntwOut(); o.textContent='pinging '+ip+' …\n'; let n=0;
  _ntwEs=new EventSource('netping.php?api=stream&target='+encodeURIComponent(ip));
  _ntwEs.addEventListener('reply',e=>{ const d=JSON.parse(e.data); o.textContent+=`seq ${d.seq}  ttl ${d.ttl}  ${d.rtt} ms\n`; o.scrollTop=o.scrollHeight; if(++n>40)ntwStop(); });
  _ntwEs.addEventListener('loss',e=>{ const d=JSON.parse(e.data); o.textContent+=`seq ${d.seq}  * timeout\n`; o.scrollTop=o.scrollHeight; });
  _ntwEs.onerror=()=>{ ntwStop(); o.textContent+='— ping stream ended —\n'; }; }
function ntwTrace(){ const ip=ntwTarget(); if(!ip)return; ntwStop(); const o=ntwOut(); o.textContent='tracing '+ip+' … (~15–30s)\n';
  fetch('nettrace.php?api=trace&target='+encodeURIComponent(ip)).then(r=>r.json()).then(d=>{ if(!d.ok){ o.textContent+='error: '+(d.error||'failed')+'\n'; return; }
    (d.hops||[]).forEach(h=>{ const loc=(h.geo&&!h.geo.private)?` ${h.geo.city||''}${h.geo.country?', '+h.geo.country:''}`:'';
      o.textContent+=`${String(h.ttl).padStart(2)}  ${(h.ip||'*').padEnd(16)} ${h.rtt!=null?h.rtt+'ms':'   '}${loc}\n`; });
    o.textContent+='— done —\n'; o.scrollTop=o.scrollHeight; }).catch(()=>{ o.textContent+='trace failed\n'; }); }
function ntwLookup(){ const ip=ntwTarget(); if(!ip)return; ntwStop(); const ty=(document.getElementById('ntw-type')||{}).value||'A'; const o=ntwOut(); o.textContent='lookup '+ip+' ('+ty+') …\n';
  fetch('netlookup.php?api=lookup&target='+encodeURIComponent(ip)+'&type='+encodeURIComponent(ty)).then(r=>r.json()).then(d=>{ if(!d.ok){ o.textContent+='error: '+(d.error||'failed')+'\n'; return; }
    const recs=d.records||[]; if(!recs.length){ o.textContent+='no '+d.type+' records\n'; return; }
    recs.forEach(x=>{ o.textContent+=`${(x.type||'').padEnd(6)} ${x.value}${x.ttl!=null?'  ttl '+x.ttl:''}\n`; }); o.scrollTop=o.scrollHeight; }).catch(()=>{ o.textContent+='lookup failed\n'; }); }
function renderWG(wp){ return wp.length? wp.map(p=>`<div class="row"><span class="dot" style="background:#c084fc"></span>
   <div style="flex:1;"><b>${esc(p.name)}</b> <span class="muted mono" style="font-size:11px;">${esc(p.endpoint)}</span></div></div>`).join('')
   : '<div class="empty">No connected peers</div>'; }

/* ── HUD widget framework ── */
function widgetEl(id){ return document.getElementById('w-'+id); }
function buildWidget(id){
  const def=WIDGETS[id]; const el=document.createElement('div'); el.className='cc-w'; el.id='w-'+id;
  const fa=def.fa==='brands'?'fa-brands':'fa-solid';
  el.innerHTML=`<div class="cc-w-h"><span class="ti"><i class="${fa} ${def.i}"></i> ${esc(def.t)} <span class="cnt" id="wc-${id}"></span></span>
    <span class="cl" title="Collapse"><i class="fa-solid fa-minus"></i></span><span class="x" title="Remove"><i class="fa-solid fa-xmark"></i></span></div>
    <div class="cc-w-b" id="wb-${id}"><div class="empty">…</div></div>`;
  document.getElementById('cc-stage').appendChild(el);
  el.querySelector('.x').onclick=()=>toggleWidget(id,false);
  el.querySelector('.cl').onclick=()=>{ LAYOUT[id].collapsed=!LAYOUT[id].collapsed; applyCollapse(id); saveLayout(); };
  makeDraggable(el,id);
  if(def.static){ const b=document.getElementById('wb-'+id); try{ b.innerHTML=def.render(DATA); }catch(e){} if(def.onmount){ try{ def.onmount(b); }catch(e){} } }
  return el;
}
function applyCollapse(id){ const el=widgetEl(id); if(!el)return; el.classList.toggle('collapsed',!!LAYOUT[id].collapsed);
  el.querySelector('.cc-w-h').classList.toggle('collapsed',!!LAYOUT[id].collapsed);
  el.querySelector('.cl i').className='fa-solid '+(LAYOUT[id].collapsed?'fa-plus':'fa-minus'); }
function makeDraggable(el,id){ const h=el.querySelector('.cc-w-h'); let sx,sy,ox,oy,drag=false;
  h.addEventListener('mousedown',e=>{ if(e.target.closest('.x,.cl'))return; drag=true; h.style.cursor='grabbing';
    const st=document.getElementById('cc-stage').getBoundingClientRect(); sx=e.clientX; sy=e.clientY; ox=el.offsetLeft; oy=el.offsetTop; e.preventDefault();
    const mv=ev=>{ if(!drag)return; let nx=ox+(ev.clientX-sx), ny=oy+(ev.clientY-sy);
      nx=Math.max(0,Math.min(nx,st.width-el.offsetWidth)); ny=Math.max(0,Math.min(ny,st.height-el.offsetHeight));
      el.style.left=nx+'px'; el.style.top=ny+'px'; el.style.right='auto'; };
    const up=()=>{ if(!drag)return; drag=false; h.style.cursor='grab'; document.removeEventListener('mousemove',mv); document.removeEventListener('mouseup',up);
      LAYOUT[id].x=el.offsetLeft; LAYOUT[id].y=el.offsetTop; saveLayout(); };
    document.addEventListener('mousemove',mv); document.addEventListener('mouseup',up); });
}
function positionWidget(id){ const el=widgetEl(id); if(!el)return; const L=LAYOUT[id];
  if(L.x!=null&&L.y!=null){ el.style.left=L.x+'px'; el.style.top=L.y+'px'; el.style.right='auto'; return; }
  // auto-stack into columns; wrap to a new column when one would overflow the stage
  const stage=document.getElementById('cc-stage'); const SH=stage.clientHeight||600;
  const side=WIDGETS[id].side;
  const h=Math.min(el.offsetHeight||190, Math.round(SH*0.42))+10;
  if(side==='l'){ window._lx=window._lx??10; window._ly=window._ly??58;
    if(window._ly>SH-120){ window._ly=58; window._lx+=314; }
    el.style.left=window._lx+'px'; el.style.right='auto'; el.style.top=window._ly+'px'; window._ly+=h;
  } else { window._rx=window._rx??10; window._ry=window._ry??58;
    if(window._ry>SH-120){ window._ry=58; window._rx+=314; }
    el.style.right=window._rx+'px'; el.style.left='auto'; el.style.top=window._ry+'px'; window._ry+=h;
  }
}
function renderAll(){ enabledKeys().forEach(id=>{ if(WIDGETS[id].static)return; const b=document.getElementById('wb-'+id); if(b){ try{ b.innerHTML=WIDGETS[id].render(DATA);}catch(e){ b.innerHTML='<div class="empty">err</div>'; } } }); }
function mountWidgets(){ window._lx=10; window._ly=58; window._rx=10; window._ry=58;
  ORDER.forEach(id=>{ if(LAYOUT[id]&&LAYOUT[id].on){ if(!widgetEl(id)) buildWidget(id); applyCollapse(id); } });
  renderAll();   // render first so offsetHeight is real before we stack
  window._lx=10; window._ly=58; window._rx=10; window._ry=58;
  ORDER.forEach(id=>{ if(LAYOUT[id]&&LAYOUT[id].on) positionWidget(id); });
  buildMenu();
}
function toggleWidget(id,on){ LAYOUT[id].on=on;
  if(on){
    if(!widgetEl(id)){
      // drop it at a visible cascade spot so it never lands hidden behind another widget
      const placed=ORDER.filter(k=>LAYOUT[k]&&LAYOUT[k].on&&widgetEl(k)).length;
      const stage=document.getElementById('cc-stage');
      LAYOUT[id].x=Math.min(40+(placed%7)*36, Math.max(40,(stage.clientWidth-320)));
      LAYOUT[id].y=72+(placed%7)*34;
      buildWidget(id); applyCollapse(id); positionWidget(id);
    }
    const el=widgetEl(id); el.style.display='flex';
    if(!WIDGETS[id].static){ try{ document.getElementById('wb-'+id).innerHTML=WIDGETS[id].render(DATA);}catch(e){} }
    // brief flash so you can see where it appeared
    el.style.transition='box-shadow .2s'; el.style.boxShadow='0 0 0 2px var(--accent), 0 14px 40px rgba(0,0,0,.65)';
    setTimeout(()=>{ el.style.boxShadow=''; },1100);
  } else { const el=widgetEl(id); if(el){ if(el._t) clearInterval(el._t); el.remove(); } if(id==='sonify'&&window.NMSonify) NMSonify.setMuted(true); }
  buildMenu(); saveLayout(); }
function buildMenu(){ const ml=document.getElementById('cc-mlist'); ml.innerHTML=ORDER.map(id=>{ const d=WIDGETS[id], on=LAYOUT[id]&&LAYOUT[id].on, fa=d.fa==='brands'?'fa-brands':'fa-solid';
  return `<div class="cc-mrow ${on?'on':''}" data-id="${id}"><i class="w ${fa} ${d.i}"></i> ${esc(d.t)} <span class="tog"></span></div>`; }).join('');
  ml.querySelectorAll('.cc-mrow').forEach(r=>r.onclick=()=>toggleWidget(r.dataset.id, !(LAYOUT[r.dataset.id]&&LAYOUT[r.dataset.id].on))); }

/* ── layout persistence (per-user, DB) ── */
function defaultLayout(){ const L={}; ORDER.forEach(id=>L[id]={on:WIDGETS[id].on,collapsed:false,x:null,y:null}); return L; }
let _saveT=null;
function saveLayout(){ clearTimeout(_saveT); _saveT=setTimeout(()=>{ const fd=new FormData(); fd.append('api','layout_save'); fd.append('csrf',CSRF); fd.append('layout',JSON.stringify(LAYOUT));
  fetch('command.php',{method:'POST',body:fd}).catch(()=>{}); },600); }
async function loadLayout(){ try{ const r=await fetch('command.php?api=layout_get').then(r=>r.json());
    if(r&&r.ok&&r.layout){ const L=defaultLayout(); for(const id in r.layout){ L[id]=Object.assign(L[id]||{on:false,collapsed:false,x:null,y:null}, r.layout[id]); } LAYOUT=L; }
    else LAYOUT=defaultLayout(); }catch(e){ LAYOUT=defaultLayout(); } }

/* ── Widget SDK: load installed (declarative) widgets from the registry ── */
let SDK_CATALOG={};
async function loadUserWidgets(){
  let r; try{ r=await fetch('command.php?api=widgets_list').then(x=>x.json()); }catch(e){ return; }
  if(!r||!r.ok) return; SDK_CATALOG=r.catalog||{};
  (r.widgets||[]).forEach(w=>{ const m=w.manifest||{}, wid='usr:'+w.widget_id;
    if(WIDGETS[wid]) return;
    WIDGETS[wid]={ t:(m.name||w.widget_id)+(w.scope==='global'?'':' ·you'), i:(m.icon||'fa-puzzle-piece'), on:false, side:'r', static:true, user:true, sdk:m,
      render:()=>`<div class="empty">…</div>`, onmount:el=>mountUserDecl(m, el) };
    ORDER.push(wid);
    if(!LAYOUT[wid]) LAYOUT[wid]={on:false,collapsed:false,x:null,y:null};
  });
}
// declarative rendering now lives in the shared kit (nm_widgetkit.js)
function mountUserDecl(m,el){ if(window.NMWidgetKit) NMWidgetKit.mountDeclarative(m,el,'command.php'); }

/* ── Widget Builder — mounts the shared kit UI into the modal ── */
async function openBuilder(){ document.getElementById('cc-menu').style.display='none';
  if(!Object.keys(SDK_CATALOG).length){ try{ const r=await fetch('command.php?api=widgets_list').then(x=>x.json()); if(r&&r.ok) SDK_CATALOG=r.catalog||{}; }catch(e){} }
  NMWidgetKit.mountBuilder(document.getElementById('cc-builder-body'), { catalog:SDK_CATALOG, csrf:CSRF, base:'command.php', canGlobal:CAN_GLOBAL,
    toast:(msg)=>toast(msg), onSaved:async(m)=>{ await reloadWidgetRegistry(); if(m){ const wid='usr:'+m.id; if(LAYOUT[wid]&&!LAYOUT[wid].on) toggleWidget(wid,true); } } });
  document.getElementById('cc-builder').classList.add('show'); }
function closeBuilder(){ document.getElementById('cc-builder').classList.remove('show'); }
/* re-sync the in-memory registry after install/remove (handles add/edit/delete) */
async function reloadWidgetRegistry(){
  let r; try{ r=await fetch('command.php?api=widgets_list').then(x=>x.json()); }catch(e){ return; }
  if(!r||!r.ok) return; SDK_CATALOG=r.catalog||SDK_CATALOG;
  const have=new Set((r.widgets||[]).map(w=>'usr:'+w.widget_id));
  ORDER.filter(id=>id.indexOf('usr:')===0&&!have.has(id)).forEach(id=>{ const el=widgetEl(id); if(el){ if(el._t)clearInterval(el._t); el.remove(); }
    delete WIDGETS[id]; delete LAYOUT[id]; const ix=ORDER.indexOf(id); if(ix>=0) ORDER.splice(ix,1); });
  (r.widgets||[]).forEach(w=>{ const m=w.manifest||{}, wid='usr:'+w.widget_id; const wasOn=LAYOUT[wid]&&LAYOUT[wid].on;
    WIDGETS[wid]={ t:(m.name||w.widget_id)+(w.scope==='global'?'':' ·you'), i:(m.icon||'fa-puzzle-piece'), on:wasOn||false, side:'r', static:true, user:true, sdk:m,
      render:()=>`<div class="empty">…</div>`, onmount:el=>mountUserDecl(m,el) };
    if(ORDER.indexOf(wid)<0) ORDER.push(wid);
    if(!LAYOUT[wid]) LAYOUT[wid]={on:false,collapsed:false,x:null,y:null};
    const el=widgetEl(wid); if(el){ const b=document.getElementById('wb-'+wid); if(b) mountUserDecl(m,b); }   // live re-render if shown
  });
  buildMenu();
}
function resetLayout(){ ORDER.forEach(id=>{ const el=widgetEl(id); if(el) el.remove(); }); LAYOUT=defaultLayout(); mountWidgets(); saveLayout(); }

/* ── troubleshoot dock ── */
let _es=null;
function openDock(nd){ openDockIP(nd.ip,nd.name); }
function openDockIP(ip,name){ if(!ip)return; dockClose(); document.getElementById('dk-name').textContent=name||ip;
  document.getElementById('dk-ip').textContent=ip; document.getElementById('cc-dock').dataset.ip=ip;
  document.getElementById('dk-open-ping').href='netping.php?target='+encodeURIComponent(ip);
  document.getElementById('dk-open-trace').href='nettrace.php?target='+encodeURIComponent(ip);
  document.getElementById('dk-out').style.display='none'; document.getElementById('dk-out').textContent='';
  document.getElementById('cc-dock').style.display='block'; }
function dockClose(){ if(_es){ _es.close(); _es=null; } document.getElementById('cc-dock').style.display='none'; }
function dockOut(){ const o=document.getElementById('dk-out'); o.style.display='block'; return o; }
function dockPing(){ const ip=document.getElementById('cc-dock').dataset.ip; if(!ip)return; if(_es){_es.close();_es=null;}
  const o=dockOut(); o.textContent='pinging '+ip+' …\n'; let n=0;
  _es=new EventSource('netping.php?api=stream&target='+encodeURIComponent(ip));
  _es.addEventListener('reply',e=>{ const d=JSON.parse(e.data); o.textContent+=`seq ${d.seq}  ttl ${d.ttl}  ${d.rtt} ms\n`; o.scrollTop=o.scrollHeight; if(++n>40){_es.close();_es=null;} });
  _es.addEventListener('loss',e=>{ const d=JSON.parse(e.data); o.textContent+=`seq ${d.seq}  * timeout\n`; o.scrollTop=o.scrollHeight; });
  _es.onerror=()=>{ if(_es){_es.close();_es=null;} o.textContent+='— ping stream ended —\n'; }; }
function dockTrace(){ const ip=document.getElementById('cc-dock').dataset.ip; if(!ip)return; if(_es){_es.close();_es=null;}
  const o=dockOut(); o.textContent='tracing '+ip+' … (may take ~15–30s)\n';
  fetch('nettrace.php?api=trace&target='+encodeURIComponent(ip)).then(r=>r.json()).then(d=>{
    if(!d.ok){ o.textContent+='error: '+(d.error||'failed')+'\n'; return; }
    (d.hops||[]).forEach(h=>{ const loc=h.city||h.country?` ${h.city||''}${h.country?', '+h.country:''}`:''; const asn=h.asn?'  AS'+h.asn:'';
      o.textContent+=`${String(h.hop).padStart(2)}  ${(h.ip||'*').padEnd(16)} ${h.rtt!=null?h.rtt+'ms':'   '}${loc}${asn}\n`; });
    o.textContent+='— done —\n'; o.scrollTop=o.scrollHeight; }).catch(()=>{ o.textContent+='trace failed\n'; }); }

/* ── detail modal (incident + container) ── */
function openModal(title,html){ document.getElementById('cc-modal-title').innerHTML=title; document.getElementById('cc-modal-body').innerHTML=html; document.getElementById('cc-modal').classList.add('show'); }
function closeModal(){ document.getElementById('cc-modal').classList.remove('show'); }
function kv(k,v){ return v?`<div class="cc-kv"><div class="k">${esc(k)}</div><div class="v">${v}</div></div>`:''; }
function sevColor(s){ return s==='critical'?'#e74c3c':s==='warning'?'#f39c12':'#4da3ff'; }
function stColorOf(s){ return s==='running'?'#2ecc71':s==='exited'?'#e74c3c':'#f39c12'; }

async function showIncident(id){
  openModal('<i class="fa-solid fa-spinner fa-spin"></i> Loading incident…','<div class="empty">…</div>');
  let r; try{ r=await fetch('incidents.php?api=get&id='+id).then(x=>x.json()); }catch(e){ r=null; }
  if(!r||!r.ok){ document.getElementById('cc-modal-body').innerHTML='<div class="empty">Details unavailable (need Incident access).</div>'; return; }
  const i=r.incident, sc=sevColor(i.severity);
  document.getElementById('cc-modal-title').innerHTML=`<span class="cc-pill" style="background:${sc}22;color:${sc};">${esc(i.severity)}</span> ${esc(i.title)}`;
  const sigs=(i.signals||[]).map(s=>`<div class="cc-sig"><div style="display:flex;gap:8px;"><span class="cc-pill" style="background:${sevColor(s.severity)}22;color:${sevColor(s.severity)};">${esc(s.source||'')}</span>
     <b style="flex:1;">${esc(s.title||s.entity||'')}</b><span class="muted" style="font-size:10px;">${esc((s.status||'').toUpperCase())}</span></div>
     ${s.detail?`<div class="muted" style="font-size:11.5px;margin-top:4px;">${esc(String(s.detail).slice(0,400))}</div>`:''}
     <div class="muted" style="font-size:10.5px;margin-top:3px;">first ${esc((window.nmLocal?nmLocal(s.first_seen):(s.first_seen||'')).slice(5,16))} · last ${esc((window.nmLocal?nmLocal(s.last_seen):(s.last_seen||'')).slice(5,16))}</div></div>`).join('') || '<div class="muted">No signals.</div>';
  const act = i.status==='muted'
     ? `<span class="cc-abtn" onclick="incAction(${i.id},'open')"><i class="fa-solid fa-bell"></i> Un-ignore</span>`
     : `${i.status!=='acknowledged'&&i.status!=='resolved'?`<span class="cc-abtn" onclick="incAction(${i.id},'acknowledged')"><i class="fa-solid fa-eye"></i> Acknowledge</span>`:''}
        ${i.status!=='resolved'?`<span class="cc-abtn ok" onclick="incAction(${i.id},'resolved')"><i class="fa-solid fa-check"></i> Resolve</span>`:`<span class="cc-abtn" onclick="incAction(${i.id},'open')"><i class="fa-solid fa-rotate-left"></i> Reopen</span>`}
        <span class="cc-abtn mut" onclick="incAction(${i.id},'muted')"><i class="fa-solid fa-bell-slash"></i> Ignore</span>`;
  document.getElementById('cc-modal-body').innerHTML =
    kv('Status', `<span class="cc-pill st-${esc(i.status)}" style="background:${sc}18;color:${sc};">${esc(i.status)}</span>`)+
    kv('Root cause', i.root_source?`${esc(i.root_source)}${i.root_entity?(' · '+esc(i.root_entity)):''}`:'')+
    kv('Impact', (i.impact_count>0?(i.impact||'')+' ('+i.impact_count+' affected)':''))+
    kv('Signals', (i.signal_count||0)+'')+
    kv('Opened', esc((i.opened_at||'').replace('T',' ')))+
    kv('Updated', esc((i.updated_at||'').replace('T',' ')))+
    (i.acked_by?kv('Acknowledged by', esc(i.acked_by)):'')+
    `<div class="cc-modal-act">${act}<a class="cc-abtn" href="incidents.php" target="_blank"><i class="fa-solid fa-up-right-from-square"></i> Open in Incidents</a></div>`+
    `<div style="margin-top:10px;font-size:11px;color:#8a929c;text-transform:uppercase;letter-spacing:1px;">Signals</div>${sigs}`;
}
async function incAction(id,status){
  const fd=new FormData(); fd.append('api','set_status'); fd.append('csrf',CSRF); fd.append('id',id); fd.append('status',status);
  try{ await fetch('incidents.php?api=set_status',{method:'POST',body:fd}); }catch(e){}
  showIncident(id); load();   // refresh modal + dashboard
}

async function showContainer(eid,cid,name){
  openModal('<i class="fa-solid fa-spinner fa-spin"></i> Loading '+esc(name)+'…','<div class="empty">…</div>');
  let r; try{ r=await fetch('containers.php?api=detail_data&endpoint='+eid+'&container='+encodeURIComponent(cid)).then(x=>x.json()); }catch(e){ r=null; }
  if(!r||!r.ok){ document.getElementById('cc-modal-body').innerHTML='<div class="empty">Details unavailable (need Containers access or container is gone).</div>'; return; }
  const d=r.detail||{}, s=r.stats||null, st=(d.state||d.status||'').toLowerCase(), sc=stColorOf(st);
  document.getElementById('cc-modal-title').innerHTML=`<i class="fa-brands fa-docker" style="color:#56c7ed;"></i> ${esc(d.name||name)}`;
  const ports=(d.ports||[]).map(p=>esc(typeof p==='string'?p:(p.pub?p.pub+'→':'')+(p.priv||p.port||''))).join(', ');
  const nets=(d.networks||[]).map(n=>esc(n.name)+(n.ip?' ('+esc(n.ip)+')':'')).join(', ');
  const mounts=(d.mounts||[]).map(m=>esc((m.source||m.name||'')+' → '+(m.dest||''))).join('<br>');
  const env=(d.env||[]).map(e=>esc(e.k+'='+e.v)).join('<br>');
  let statsHtml='';
  if(s){ const mb=b=>(b/1048576).toFixed(b>=104857600?0:1)+' MB';
    statsHtml = kv('CPU', (s.cpu_pct!=null?(+s.cpu_pct).toFixed(1)+'%':''))
      + kv('Memory', (s.mem_used?mb(s.mem_used)+(s.mem_pct?' ('+(+s.mem_pct).toFixed(1)+'%)':''):''))
      + kv('Net I/O', (s.net_rx!=null?'↓ '+mb(s.net_rx)+' · ↑ '+mb(s.net_tx):'')); }
  document.getElementById('cc-modal-body').innerHTML =
    kv('State', `<span class="cc-pill" style="background:${sc}22;color:${sc};">${esc(d.state||st||'?')}</span> <span class="muted">${esc(d.status||'')}</span>`)+
    (d.health?kv('Health', esc(d.health)):'')+
    kv('Image', esc(d.image||''))+
    kv('Created', esc((d.created||'').replace('T',' ').slice(0,19)))+
    kv('Ports', ports)+
    kv('Networks', nets)+
    statsHtml+
    (mounts?kv('Mounts', mounts):'')+
    (env?kv('Env', `<div style="max-height:120px;overflow:auto;font-family:monospace;font-size:11px;">${env}</div>`):'')+
    `<div class="cc-modal-act"><a class="cc-abtn" href="containers.php?view=detail&endpoint=${eid}&container=${encodeURIComponent(cid)}" target="_blank"><i class="fa-solid fa-up-right-from-square"></i> Open in Containers</a></div>`;
}

const SEVN=['EMERG','ALERT','CRIT','ERR','WARN','NOTICE','INFO','DEBUG'];
function sevCol(s){ return s<=3?'#f0a59d':s===4?'#f0c674':'#9fbfe0'; }
async function showSyslog(host,ip){
  openModal('<i class="fa-solid fa-spinner fa-spin"></i> Loading '+esc(host)+'…','<div class="empty">…</div>');
  let r; try{ r=await fetch('command.php?api=syslog_detail&host='+encodeURIComponent(host)+'&ip='+encodeURIComponent(ip)).then(x=>x.json()); }catch(e){ r=null; }
  if(!r||!r.ok){ document.getElementById('cc-modal-body').innerHTML='<div class="empty">No log detail available.</div>'; return; }
  const n=r.node, sv=r.sev||{};
  const stCol=n?(n.status==='up'?'#2ecc71':n.status==='down'?'#e74c3c':'#8a909a'):'#8a909a';
  document.getElementById('cc-modal-title').innerHTML=`<i class="fa-solid fa-file-lines" style="color:#4da3ff;"></i> ${esc(host)}`+
    (n?` <span class="cc-pill" style="background:${stCol}22;color:${stCol};margin-left:4px;">${esc(n.status)}</span>`:'');
  // node panel
  let nodeHtml = n
    ? kv('Node', `<b>${esc(n.name)}</b>`)+kv('Status', `<span class="cc-pill" style="background:${stCol}22;color:${stCol};">${esc(n.status)}</span>`)+
      kv('IP', esc(n.ip||''))+kv('Monitor', esc(n.monitor_type||''))
    : kv('Host', `${esc(host)} ${ip?'· '+esc(ip):''}`)+`<div class="muted" style="font-size:11.5px;padding:4px 0;">No monitored node matches this host — it may be an unmanaged device sending syslog.</div>`;
  // severity summary
  const chips = `<div class="cc-modal-act" style="margin-top:6px;">
     <span class="cc-pill" style="background:#f0a59d22;color:#f0a59d;">${sv.err||0} err</span>
     <span class="cc-pill" style="background:#f0c67422;color:#f0c674;">${sv.warn||0} warn</span>
     <span class="cc-pill" style="background:#9fbfe022;color:#9fbfe0;">${sv.info||0} info</span></div>`;
  // log list
  const logs=(r.logs||[]).map(l=>`<div class="cc-sig" style="padding:6px 9px;">
     <div style="display:flex;gap:8px;align-items:baseline;">
       <span class="cc-pill" style="background:${sevCol(l.sev)}22;color:${sevCol(l.sev)};">${esc(SEVN[l.sev]||('S'+l.sev))}</span>
       <span class="muted" style="font-size:10.5px;">${esc(l.tag||'')}</span>
       <span class="muted" style="font-size:10.5px;margin-left:auto;">${esc((l.at||'').replace('T',' ').slice(5,19))}</span></div>
     <div style="font-family:monospace;font-size:11.5px;word-break:break-word;margin-top:3px;">${esc(l.msg)}</div></div>`).join('') || '<div class="muted">No recent log lines for this host.</div>';
  const actions = `<div class="cc-modal-act">
     ${(n&&n.ip)?`<span class="cc-abtn" onclick="closeModal();openDockIP('${esc(n.ip)}','${esc(n.name)}')"><i class="fa-solid fa-wrench"></i> Troubleshoot</span>`:''}
     <a class="cc-abtn" href="log_mon.php" target="_blank"><i class="fa-solid fa-up-right-from-square"></i> Open in Logs</a></div>`;
  document.getElementById('cc-modal-body').innerHTML = nodeHtml + chips + actions +
    `<div style="margin-top:10px;font-size:11px;color:#8a929c;text-transform:uppercase;letter-spacing:1px;">Recent log lines (this host)</div>${logs}`;
}
document.addEventListener('keydown',e=>{ if(e.key==='Escape'){ closeModal(); closeBuilder(); } });
document.getElementById('cc-modal').addEventListener('click',e=>{ if(e.target.id==='cc-modal') closeModal(); });
document.getElementById('cc-builder').addEventListener('click',e=>{ if(e.target.id==='cc-builder') closeBuilder(); });

/* ── particle bg: keep the site canvas inside the stage (both normal & fullscreen)
      so it glows behind the semi-transparent map everywhere — matching other pages ── */
function attachBg(tries){ tries=tries||0; const bg=document.getElementById('nm-netbg'); const stage=document.getElementById('cc-stage');
  if(!bg){ if(tries<25) setTimeout(()=>attachBg(tries+1),150); return; }
  stage.appendChild(bg); bg.style.zIndex='0';
  setTimeout(()=>window.dispatchEvent(new Event('resize')),60); }
function toggleFull(){ const s=document.getElementById('cc-stage'); if(document.fullscreenElement) document.exitFullscreen(); else s.requestFullscreen&&s.requestFullscreen(); }
document.addEventListener('fullscreenchange',()=>{ const fs=!!document.fullscreenElement;
  attachBg();   // canvas stays a child of the stage through fullscreen; just refit
  document.querySelector('#b-full i').className='fa-solid '+(fs?'fa-compress':'fa-expand'); setTimeout(()=>{ const s=document.getElementById('cc-stage');
    fx.width=s.clientWidth; fx.height=s.clientHeight; map.invalidateSize(); DIRTY=true; },160); });

/* ── wire up ── */
document.getElementById('b-widgets').onclick=()=>{ const m=document.getElementById('cc-menu'); m.style.display=m.style.display==='block'?'none':'block'; };
document.addEventListener('click',e=>{ if(!e.target.closest('#cc-menu')&&!e.target.closest('#b-widgets')) document.getElementById('cc-menu').style.display='none'; });
document.getElementById('b-reset').onclick=resetLayout;
document.getElementById('b-fit').onclick=()=>{ const pts=Object.values(NODES).map(n=>[n.lat,n.lon]); if(pts.length) map.fitBounds(pts,{padding:[70,70],maxZoom:9}); };
document.getElementById('b-full').onclick=toggleFull;

(async function(){ initMap(); attachBg(); await loadLayout(); await loadUserWidgets(); mountWidgets(); await load(); setInterval(load,REFRESH);
  if(new URLSearchParams(location.search).get('builder')) openBuilder();   // deep-link from the Site Config nav entry
})();
</script>
</body></html>
