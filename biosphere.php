<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Service Biosphere (services as living organisms · Phase 1).
// Each monitored service (DNS/HTTP/SQL/SMTP) is a living 3D CELL: the membrane
// (noise-displaced vertex shader) breathes at a rate ∝ real latency, paints dark
// "infection" patches on real 4xx/5xx, turns to "sludge" on SQL saturation/slow
// queries, and "freezes" to ice on a lock/deadlock. Every visual = a TRUE signal.
// Reuses vendored three.min.js (CSP script-src 'self') + Data Core + Pi-hole +
// Immunity + incident correlation. RBAC: 'biosphere'. All probing is server-side.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_biosphere.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'biosphere')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=biosphere'); exit;
}
nm_bio_ensure($conn);
if (function_exists('session_write_close')) @session_write_close();

// ── JSON API ──────────────────────────────────────────────────────────────────
if ($api) {
    header('Content-Type: application/json; charset=utf-8');
    $uid = (int)($_SESSION['user_id'] ?? 0) ?: null;
    try {
        switch ($api) {
            case 'scene':   echo json_encode(nm_bio_scene($conn)); break;
            case 'service': echo json_encode(nm_bio_service_detail($conn, (int)($_GET['id'] ?? 0))); break;
            case 'list':    echo json_encode(['ok'=>true, 'services'=>nm_bio_services($conn, false)]); break;
            case 'refs': {  // dropdown sources for the add/edit form
                $tgts = function_exists('nm_db_targets') ? nm_db_targets($conn) : [];
                $phs  = [];
                if (is_file(__DIR__.'/nm_pihole.php')) { require_once __DIR__.'/nm_pihole.php'; if (function_exists('nm_ph_servers')) $phs = nm_ph_servers($conn); }
                $nodes = [];
                $nr = $conn->query("SELECT id, display_name FROM nm_nodes ORDER BY display_name");
                while ($nr && $x=$nr->fetch_assoc()) $nodes[] = $x;
                echo json_encode(['ok'=>true, 'db_targets'=>array_map(fn($t)=>['id'=>$t['id'],'name'=>$t['display_name'],'engine'=>$t['engine']], $tgts),
                                  'piholes'=>array_map(fn($p)=>['id'=>$p['id'],'name'=>$p['name']], $phs), 'nodes'=>$nodes]);
                break;
            }
            case 'save':      echo json_encode(nm_bio_service_save($conn, $_POST, $uid)); break;
            case 'delete':    echo json_encode(nm_bio_service_delete($conn, (int)($_POST['id'] ?? 0))); break;
            case 'probe': {   // ad-hoc test probe (no sample stored) for the form
                $s = nm_bio_service($conn, (int)($_GET['id'] ?? 0));
                if (!$s) { echo json_encode(['ok'=>false,'error'=>'unknown service']); break; }
                $sm = nm_bio_probe($conn, $s); echo json_encode(['ok'=>true, 'sample'=>$sm]); break;
            }
            case 'link_save': echo json_encode(nm_bio_link_save($conn, (int)($_POST['from'] ?? 0), (int)($_POST['to'] ?? 0), (string)($_POST['kind'] ?? 'depends'))); break;
            case 'link_del':  echo json_encode(nm_bio_link_delete($conn, (int)($_POST['from'] ?? 0), (int)($_POST['to'] ?? 0))); break;
            case 'promote':   echo json_encode(nm_bio_flag_promote($conn, (int)($_POST['flag'] ?? 0), $uid)); break;
            case 'flags':     echo json_encode(['ok'=>true, 'flags'=>nm_bio_flags_all($conn, (string)($_GET['status'] ?? 'open'))]); break;
            case 'flag_resolve': echo json_encode(nm_bio_flag_resolve($conn, (int)($_POST['flag'] ?? 0))); break;
            case 'flag_resolve_all': echo json_encode(nm_bio_flags_resolve_all($conn, (string)($_POST['kind'] ?? ''))); break;
            case 'dns_audit': echo json_encode(nm_bio_dns_audit($conn)); break;
            case 'advise':    echo json_encode(nm_bio_sql_advise($conn, (int)($_POST['id'] ?? 0))); break;
            case 'autotune':  echo json_encode(nm_bio_tg_send_autotune($conn, (int)($_POST['advice'] ?? 0), $uid)); break;
            case 'apply_advice': echo json_encode(nm_bio_apply_advice($conn, (int)($_POST['advice'] ?? 0), $uid)); break;
            case 'journey_get': echo json_encode(nm_bio_journey_get($conn, (int)($_GET['id'] ?? 0))); break;
            case 'journey_save': {
                $steps   = json_decode((string)($_POST['steps'] ?? '[]'), true) ?: [];
                $persona = json_decode((string)($_POST['persona'] ?? '{}'), true) ?: [];
                echo json_encode(nm_bio_journey_save($conn, (int)($_POST['id'] ?? 0), $steps, $persona)); break;
            }
            case 'synthetic': echo json_encode(nm_bio_synthetic_dispatch($conn, (int)($_POST['id'] ?? 0))); break;
            case 'setting': {
                foreach (['bio_poll_sec','bio_sample_days','bio_lat_warn','bio_lat_crit','bio_enabled','bio_dns_audit','bio_dns_limit','bio_dns_min','bio_dga_promote','bio_synthetic','bio_synth_min','bio_vct_warn'] as $k)
                    if (isset($_POST[$k])) nm_bio_set($conn, $k, (string)$_POST[$k]);
                echo json_encode(['ok'=>true]); break;
            }
            default: echo json_encode(['ok'=>false, 'error'=>'unknown api']);
        }
    } catch (\Throwable $e) { echo json_encode(['ok'=>false, 'error'=>$e->getMessage()]); }
    exit;
}
$SET = nm_bio_settings($conn);
$canEdit = checkAccess($conn, 'biosphere');
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Service Biosphere · Living Twin | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --accent:#4da3ff; --ok:#2ee6a0; --warn:#f3b52c; --sick:#ff7a45; --crit:#e74c3c; --cyan:#22d3ee; --dna:#9b6bff; --border:rgba(255,255,255,.12); }
*,*::before,*::after{ box-sizing:border-box; }
html{ background:#04050c; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#e6e9ee; }
<?= nm_chrome_css() ?>
#bio-stage{ position:relative; width:100%; height:calc(100vh - 74px); min-height:520px; overflow:hidden;
  background:radial-gradient(1200px 720px at 50% 0%, rgba(60,40,120,.16), transparent 72%); }
#bio-stage:fullscreen{ height:100vh; }
#bio-canvas{ position:absolute; inset:0; display:block; z-index:1; }
.bio-hud{ position:absolute; z-index:6; pointer-events:none; }
.bio-hud .glass{ background:rgba(9,13,24,.62); backdrop-filter:blur(12px); border:1px solid var(--border); border-radius:12px; pointer-events:auto; }
#bio-top{ top:14px; left:14px; max-width:330px; }
#bio-top .glass{ padding:12px 14px; }
#bio-title{ font-size:15px; font-weight:800; letter-spacing:.4px; display:flex; align-items:center; gap:9px; }
#bio-title i{ color:var(--dna); }
#bio-sub{ font-size:11px; color:#8a909a; margin-top:2px; line-height:1.4; }
#bio-legend{ margin-top:10px; display:flex; flex-wrap:wrap; gap:6px 12px; }
.leg{ display:flex; align-items:center; gap:6px; font-size:11px; color:#c3ccd8; }
.leg .sw{ width:10px; height:10px; border-radius:50%; box-shadow:0 0 8px currentColor; }
#bio-stats{ top:14px; right:14px; }
#bio-stats .glass{ padding:10px 14px; display:flex; gap:16px; }
.bstat{ text-align:center; } .bstat .n{ font-size:20px; font-weight:800; line-height:1; } .bstat .l{ font-size:9px; color:#8a909a; text-transform:uppercase; letter-spacing:.6px; margin-top:3px; }
.bstat .n.ok{ color:#7af3b0; } .bstat .n.sick{ color:#ffb08a; } .bstat .n.crit{ color:#ff9b91; } .bstat .n.cyan{ color:var(--cyan); }
#bio-ctl{ top:80px; right:14px; display:flex; flex-direction:column; gap:8px; }
.bbtn{ pointer-events:auto; background:rgba(10,16,28,.78); border:1px solid var(--border); color:#cfe4ff; border-radius:9px;
  min-width:38px; height:36px; padding:0 12px; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:7px; font-size:13px; }
.bbtn:hover{ border-color:var(--accent); color:#fff; } .bbtn.on{ border-color:var(--cyan); color:#fff; background:rgba(34,211,238,.16); }
.bbtn.dna{ border-color:rgba(155,107,255,.5); color:#d9c8ff; } .bbtn.dna:hover{ background:rgba(155,107,255,.16); }
#bio-hint{ bottom:16px; left:16px; font-size:11px; color:#8a909a; } #bio-hint .glass{ padding:7px 12px; }
/* detail drawer (left) */
#bio-info{ position:absolute; z-index:12; left:0; top:0; height:100%; width:420px; max-width:90vw; display:none; }
#bio-info .glass{ height:100%; border-radius:0 16px 16px 0; border-left:none; padding:0; display:flex; flex-direction:column;
  box-shadow:24px 0 60px rgba(0,0,0,.45); background:rgba(8,12,22,.92); }
#bio-dh{ padding:14px 16px 12px; border-bottom:1px solid var(--border); position:relative; }
#bio-dh h3{ margin:0; font-size:16px; display:flex; align-items:center; gap:9px; padding-right:24px; }
#bio-dh .meta{ font-size:12px; color:#9aa3af; margin-top:4px; }
#bio-dh .x{ position:absolute; top:12px; right:12px; cursor:pointer; color:#9aa3af; font-size:15px; } #bio-dh .x:hover{ color:#fff; }
#bio-db{ padding:12px 16px 20px; overflow-y:auto; flex:1; }
#bio-db::-webkit-scrollbar{ width:8px; } #bio-db::-webkit-scrollbar-thumb{ background:rgba(255,255,255,.12); border-radius:8px; }
.dgrid{ display:grid; grid-template-columns:repeat(3,1fr); gap:8px; margin-bottom:14px; }
.dcell{ background:rgba(255,255,255,.04); border:1px solid var(--border); border-radius:9px; padding:8px 9px; }
.dcell .l{ font-size:9px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; }
.dcell .v{ font-size:15px; font-weight:700; margin-top:2px; }
.dsec{ margin:16px 0 6px; font-size:11px; text-transform:uppercase; letter-spacing:.7px; color:#c7b3ff; display:flex; align-items:center; gap:7px; }
.dsec .cnt{ color:#6b7686; font-weight:400; }
.ditem{ background:rgba(255,255,255,.03); border:1px solid var(--border); border-left:3px solid #5a6577; border-radius:8px; padding:8px 10px; margin-bottom:7px; font-size:12px; }
.ditem .t{ font-weight:600; color:#e6e9ee; display:flex; justify-content:space-between; gap:8px; }
.ditem .d{ color:#9aa3af; margin-top:3px; line-height:1.4; word-break:break-word; }
.ditem.crit{ border-left-color:#e74c3c; } .ditem.warn{ border-left-color:#f3b52c; } .ditem.ok{ border-left-color:#2ee6a0; }
.dbadge{ font-size:9px; padding:2px 6px; border-radius:20px; background:rgba(255,255,255,.08); color:#cfd6e0; white-space:nowrap; }
.dbadge.crit{ background:rgba(231,76,60,.2); color:#ff9b91; } .dbadge.warn{ background:rgba(243,181,44,.2); color:#ffd479; } .dbadge.ok{ background:rgba(46,230,160,.18); color:#7af3b0; }
.dmuted{ color:#6b7686; font-size:12px; padding:2px 0 4px; }
.spark{ display:flex; align-items:flex-end; gap:2px; height:40px; margin:6px 0 2px; }
.spark i{ flex:1; border-radius:2px 2px 0 0; min-height:2px; background:#2ee6a0; opacity:.85; }
.qrow{ font-family:monospace; font-size:11px; color:#cdd6e2; }
#bio-dacts{ display:flex; gap:7px; flex-wrap:wrap; padding:12px 16px; border-top:1px solid var(--border); }
#bio-dacts a.act,#bio-dacts button.act{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:8px; padding:7px 11px; font-size:12px; text-decoration:none; cursor:pointer; }
#bio-dacts .act:hover{ border-color:var(--accent); color:#fff; }
#bio-tip{ position:absolute; z-index:9; pointer-events:none; display:none; background:rgba(6,10,20,.92); border:1px solid var(--border); border-radius:7px; padding:6px 9px; font-size:12px; white-space:nowrap; transform:translate(-50%,-140%); }
#bio-tip b{ color:#fff; }
#bio-empty{ position:absolute; inset:0; display:none; align-items:center; justify-content:center; flex-direction:column; gap:12px; color:#8a909a; text-align:center; padding:24px; }
/* manage drawer (right) */
#bio-manage{ position:absolute; z-index:14; right:0; top:0; height:100%; width:440px; max-width:92vw; display:none; }
#bio-manage .glass{ height:100%; border-radius:16px 0 0 16px; border-right:none; padding:0; display:flex; flex-direction:column; background:rgba(8,12,22,.95); box-shadow:-24px 0 60px rgba(0,0,0,.5); }
#bio-mh{ padding:14px 16px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; }
#bio-mh h3{ margin:0; font-size:15px; } #bio-mh .x{ cursor:pointer; color:#9aa3af; } #bio-mh .x:hover{ color:#fff; }
#bio-mb{ padding:14px 16px; overflow-y:auto; flex:1; }
.svc-row{ display:flex; align-items:center; gap:10px; background:rgba(255,255,255,.03); border:1px solid var(--border); border-radius:9px; padding:9px 11px; margin-bottom:8px; }
.svc-row .dot{ width:10px; height:10px; border-radius:50%; flex:none; box-shadow:0 0 8px currentColor; }
.svc-row .nm{ font-weight:600; font-size:13px; } .svc-row .sub{ font-size:11px; color:#8a909a; }
.svc-row .sp{ flex:1; } .svc-row a{ color:#9fb7d6; cursor:pointer; font-size:12px; margin-left:8px; } .svc-row a:hover{ color:#fff; }
.kpill{ font-size:9px; text-transform:uppercase; letter-spacing:.5px; padding:2px 7px; border-radius:20px; background:rgba(155,107,255,.15); color:#cbb6ff; }
.bio-field{ margin-bottom:10px; } .bio-field label{ display:block; font-size:11px; color:#9aa3af; margin-bottom:4px; text-transform:uppercase; letter-spacing:.4px; }
.bio-field input,.bio-field select{ width:100%; background:rgba(255,255,255,.05); border:1px solid var(--border); border-radius:8px; color:#e6e9ee; padding:8px 10px; font-size:13px; }
/* native <option> popup: force a dark, readable palette (otherwise light text on white = invisible) */
.bio-field select option,.bio-field select optgroup{ background:#0d1526; color:#e6e9ee; }
.bio-field.hide{ display:none; }
.brow{ display:flex; gap:10px; } .brow>*{ flex:1; }
.bio-btn{ background:linear-gradient(135deg,#7c4dff,#4da3ff); border:none; color:#fff; border-radius:9px; padding:9px 14px; font-size:13px; font-weight:600; cursor:pointer; }
.bio-btn.ghost{ background:transparent; border:1px solid var(--border); color:#cfe4ff; } .bio-btn.ghost:hover{ border-color:var(--accent); }
.bio-note{ font-size:11px; color:#7a8291; margin-top:8px; line-height:1.5; }
#probe-out{ font-family:monospace; font-size:11px; color:#8fd7b0; margin-top:8px; white-space:pre-wrap; word-break:break-word; }
.mtab{ display:flex; gap:6px; margin-bottom:12px; } .mtab button{ flex:1; background:rgba(255,255,255,.04); border:1px solid var(--border); color:#aab4c2; border-radius:8px; padding:7px; font-size:12px; cursor:pointer; } .mtab button.on{ background:rgba(124,77,255,.18); border-color:rgba(124,77,255,.5); color:#fff; }
/* journey editor modal */
#bio-journey{ position:fixed; inset:0; z-index:60; background:rgba(3,5,12,.72); backdrop-filter:blur(4px); display:flex; align-items:center; justify-content:center; padding:24px; }
.jrn-card{ width:560px; max-width:96vw; max-height:90vh; background:rgba(9,13,24,.98); border:1px solid var(--border); border-radius:16px; display:flex; flex-direction:column; box-shadow:0 30px 80px rgba(0,0,0,.6); }
.jrn-body{ padding:16px; overflow-y:auto; }
.jrn-row{ display:flex; gap:6px; align-items:center; margin-bottom:6px; }
.jrn-row select,.jrn-row input{ background:rgba(255,255,255,.05); border:1px solid var(--border); border-radius:7px; color:#e6e9ee; padding:6px 8px; font-size:12px; }
.jrn-row select{ flex:0 0 96px; } .jrn-row .sel{ flex:1; } .jrn-row .val{ flex:1; }
.jrn-row .rm{ flex:0 0 26px; cursor:pointer; color:#ff9b91; text-align:center; }
.jrn-row select option{ background:#0d1526; color:#e6e9ee; }
/* 2D fallback */
#bio-fallback{ display:none; position:absolute; inset:0; z-index:2; overflow:auto; padding:70px 20px 20px; }
.bento{ display:grid; grid-template-columns:repeat(auto-fill,minmax(200px,1fr)); gap:14px; max-width:1200px; margin:0 auto; }
.bcard{ background:rgba(9,13,24,.7); border:1px solid var(--border); border-radius:14px; padding:16px; cursor:pointer; }
.bcard .bh{ display:flex; align-items:center; gap:9px; font-weight:700; } .bcard .bm{ font-size:11px; color:#8a909a; margin-top:6px; }
</style>
</head>
<body>
<?php include('header.php'); ?>

<div id="bio-stage">
  <canvas id="bio-canvas"></canvas>

  <div id="bio-top" class="bio-hud"><div class="glass">
    <div id="bio-title"><i class="fa-solid fa-dna"></i> Service Biosphere</div>
    <div id="bio-sub">Each cell is a live service — the membrane breathes on real latency, infects on 4xx/5xx, sludges on DB pressure, freezes on locks.</div>
    <div id="bio-legend">
      <div class="leg"><span class="sw" style="background:var(--ok);color:var(--ok)"></span>Healthy</div>
      <div class="leg"><span class="sw" style="background:var(--warn);color:var(--warn)"></span>Stressed</div>
      <div class="leg"><span class="sw" style="background:var(--sick);color:var(--sick)"></span>Sick</div>
      <div class="leg"><span class="sw" style="background:var(--crit);color:var(--crit)"></span>Critical</div>
    </div>
  </div></div>

  <div id="bio-stats" class="bio-hud"><div class="glass">
    <div class="bstat"><div class="n ok" id="s-healthy">—</div><div class="l">Healthy</div></div>
    <div class="bstat"><div class="n sick" id="s-sick">—</div><div class="l">Ailing</div></div>
    <div class="bstat"><div class="n crit" id="s-down">—</div><div class="l">Down</div></div>
    <div class="bstat"><div class="n cyan" id="s-total">—</div><div class="l">Cells</div></div>
  </div></div>

  <div id="bio-ctl" class="bio-hud">
    <?php if ($canEdit): ?><button class="bbtn dna" id="b-manage" title="Manage services"><i class="fa-solid fa-sliders"></i></button><?php endif; ?>
    <button class="bbtn on" id="b-labels" title="Toggle labels"><i class="fa-solid fa-tag"></i></button>
    <button class="bbtn on" id="b-spin" title="Auto-rotate"><i class="fa-solid fa-arrows-rotate"></i></button>
    <button class="bbtn" id="b-fit" title="Reset view"><i class="fa-solid fa-crosshairs"></i></button>
    <button class="bbtn" id="b-full" title="Fullscreen"><i class="fa-solid fa-expand"></i></button>
  </div>

  <div id="bio-hint" class="bio-hud"><div class="glass"><i class="fa-solid fa-hand-pointer"></i> Drag to orbit · scroll to zoom · click a cell to open its dossier</div></div>

  <div id="bio-stale" class="bio-hud" style="display:none; top:16px; left:50%; transform:translateX(-50%); pointer-events:none;">
    <div class="glass" style="border-color:rgba(243,181,44,.55); background:rgba(40,30,8,.85); color:#ffd479; font-size:12px; display:flex; align-items:center; gap:8px;">
      <i class="fa-solid fa-triangle-exclamation"></i><span id="bio-stale-msg"></span></div></div>

  <div id="bio-info" class="bio-hud"><div class="glass">
    <div id="bio-dh">
      <span class="x" onclick="document.getElementById('bio-info').style.display='none'"><i class="fa-solid fa-xmark"></i></span>
      <h3 id="bi-name">—</h3><div class="meta" id="bi-meta">—</div>
    </div>
    <div id="bio-db"><div class="dmuted">Loading cell dossier…</div></div>
    <div id="bio-dacts"></div>
  </div></div>

  <div id="bio-tip"></div>
  <div id="bio-empty"><i class="fa-solid fa-dna" style="font-size:34px;opacity:.4;"></i>
    <div id="bio-empty-msg">Culturing the biosphere…</div></div>

  <div id="bio-fallback"><div class="bento" id="bento"></div></div>

  <?php if ($canEdit): ?>
  <div id="bio-manage" class="bio-hud"><div class="glass">
    <div id="bio-mh"><h3><i class="fa-solid fa-sliders" style="color:var(--dna)"></i> Manage Biosphere</h3>
      <span class="x" onclick="document.getElementById('bio-manage').style.display='none'"><i class="fa-solid fa-xmark"></i></span></div>
    <div class="mtab">
      <button class="on" data-mt="svc" onclick="mtab('svc')">Services</button>
      <button data-mt="add" onclick="mtab('add')">Add / Edit</button>
      <button data-mt="flags" onclick="mtab('flags')">Antibodies</button>
      <button data-mt="set" onclick="mtab('set')">Settings</button>
    </div>
    <div id="bio-mb">
      <div id="mt-svc"><div class="dmuted">Loading…</div></div>
      <div id="mt-add" style="display:none">
        <input type="hidden" id="f-id">
        <div class="bio-field"><label>Service name</label><input id="f-name" placeholder="Prod DNS · api.example.com"></div>
        <div class="bio-field"><label>Kind</label><select id="f-kind" onchange="kindChange()">
          <option value="http">HTTP / HTTPS</option><option value="dns">DNS</option><option value="sql">SQL (Data Core)</option>
          <option value="smtp">SMTP</option><option value="generic">Generic TCP</option></select></div>
        <div class="bio-field" id="fw-target"><label>Target host / URL</label><input id="f-target" placeholder="8.8.8.8  or  https://api.example.com/health"></div>
        <div class="brow">
          <div class="bio-field" id="fw-port"><label>Port</label><input id="f-port" type="number" placeholder="auto"></div>
          <div class="bio-field" id="fw-probe"><label>DNS test name</label><input id="f-probe" placeholder="cloudflare.com"></div>
        </div>
        <div class="bio-field hide" id="fw-dbt"><label>Data Core target</label><select id="f-dbt"></select></div>
        <div class="bio-field hide" id="fw-ph"><label>Pi-hole (optional, for cache-hit)</label><select id="f-ph"><option value="">— none —</option></select></div>
        <div class="brow">
          <div class="bio-field hide" id="fw-expect"><label>Expect HTTP code</label><input id="f-expect" type="number" placeholder="200 (or blank = 2xx/3xx)"></div>
          <div class="bio-field hide" id="fw-match"><label>Body must contain</label><input id="f-match" placeholder="optional string"></div>
        </div>
        <div class="bio-field"><label>Located at node (optional)</label><select id="f-node"><option value="">— none —</option></select></div>
        <div style="display:flex;gap:9px;margin-top:6px;align-items:center">
          <button class="bio-btn" onclick="saveSvc()">Save cell</button>
          <button class="bio-btn ghost" onclick="testProbe()">Test probe</button>
          <button class="bio-btn ghost" onclick="resetForm()">Clear</button>
        </div>
        <div id="probe-out"></div>
        <div class="bio-note">SQL cells reuse <b>Data Core</b> — no new credentials. Membrane vitals come only from live protocol probes; nothing is faked.</div>
      </div>
      <div id="mt-flags" style="display:none">
        <div class="bio-note" style="margin:0 0 10px">🧬 <b>Antibodies</b> — AI/analyzer findings. DNS DGA/poison verdicts and SQL metabolic distress land here; promote a domain to a fleet-wide Immunity block, or resolve a handled flag.</div>
        <div style="display:flex;gap:8px;margin-bottom:10px"><button class="bio-btn ghost" onclick="runDnsAudit(this)"><i class="fa-solid fa-virus-covid"></i> Run DNS audit now</button></div>
        <div id="flags-list"><div class="dmuted">Loading…</div></div>
      </div>
      <div id="mt-set" style="display:none">
        <div class="brow"><div class="bio-field"><label>Probe every (s)</label><input id="s-poll" type="number" min="5" value="<?= (int)$SET['poll_sec'] ?>"></div>
          <div class="bio-field"><label>Keep samples (days)</label><input id="s-days" type="number" value="<?= (int)$SET['sample_days'] ?>"></div></div>
        <div class="brow"><div class="bio-field"><label>Latency warn (ms)</label><input id="s-lw" type="number" value="<?= (int)$SET['lat_warn'] ?>"></div>
          <div class="bio-field"><label>Latency critical (ms)</label><input id="s-lc" type="number" value="<?= (int)$SET['lat_crit'] ?>"></div></div>
        <div class="bio-field"><label>Biosphere polling</label><select id="s-en"><option value="1"<?= $SET['enabled']?' selected':'' ?>>Enabled</option><option value="0"<?= $SET['enabled']?'':' selected' ?>>Paused</option></select></div>
        <div class="brow"><div class="bio-field"><label>DNS DGA audit (AI)</label><select id="s-dns"><option value="1"<?= $SET['dns_audit']?' selected':'' ?>>Enabled</option><option value="0"<?= $SET['dns_audit']?'':' selected' ?>>Off</option></select></div>
          <div class="bio-field"><label>Audit every (min)</label><input id="s-dnm" type="number" min="1" value="<?= (int)$SET['dns_min'] ?>"></div></div>
        <div class="brow"><div class="bio-field"><label>Domains per audit</label><input id="s-dnl" type="number" min="1" max="500" value="<?= (int)$SET['dns_limit'] ?>"></div>
          <div class="bio-field"><label>Auto-block score ≥</label><input id="s-dga" type="number" value="<?= (int)$SET['dga_promote'] ?>"></div></div>
        <div class="brow"><div class="bio-field"><label>Synthetic journeys (P3)</label><select id="s-syn"><option value="1"<?= $SET['synthetic']?' selected':'' ?>>Enabled</option><option value="0"<?= $SET['synthetic']?'':' selected' ?>>Off</option></select></div>
          <div class="bio-field"><label>Run every (min)</label><input id="s-synm" type="number" value="<?= (int)$SET['synth_min'] ?>"></div>
          <div class="bio-field"><label>VCT warn (ms)</label><input id="s-vct" type="number" value="<?= (int)$SET['vct_warn'] ?>"></div></div>
        <button class="bio-btn" onclick="saveSet()">Save settings</button>
        <div class="bio-note">The cron <code>cron_biosphere.php</code> must run every minute (curl→localhost with the X-NetMon-Token) for cells to breathe with fresh vitals.</div>
      </div>
    </div>
  </div></div>

  <!-- P3: synthetic journey editor modal -->
  <div id="bio-journey" style="display:none">
    <div class="jrn-card">
      <div id="bio-mh"><h3><i class="fa-solid fa-user-astronaut" style="color:var(--dna)"></i> Synthetic journey <span id="jrn-svc" style="color:#8a909a;font-weight:400"></span></h3>
        <span class="x" onclick="document.getElementById('bio-journey').style.display='none'"><i class="fa-solid fa-xmark"></i></span></div>
      <div class="jrn-body">
        <div class="bio-note" style="margin:0 0 12px">A headless browser (in n8n) runs these steps as a real user and measures <b>Visual Completeness Time</b>. If a step fails, the cell splits a wireframe clone. Selectors are CSS. Use <code>{{username}}</code>/<code>{{password}}</code> in a fill value to inject the persona login.</div>
        <div class="dsec"><i class="fa-solid fa-right-to-bracket"></i> Login persona <span class="cnt">(optional)</span></div>
        <div class="bio-field"><label>Login URL</label><input id="jp-url" placeholder="https://app.example.com/login (blank = no login)"></div>
        <div class="brow"><div class="bio-field"><label>User field selector</label><input id="jp-us" placeholder="#username"></div>
          <div class="bio-field"><label>Pass field selector</label><input id="jp-ps" placeholder="#password"></div></div>
        <div class="brow"><div class="bio-field"><label>Submit selector</label><input id="jp-sub" placeholder="button[type=submit]"></div>
          <div class="bio-field"><label>Username</label><input id="jp-user" placeholder="synthetic-monitor"></div></div>
        <div class="bio-field"><label>Password <span id="jp-pwnote" style="color:#7a8291"></span></label><input id="jp-pw" type="password" placeholder="stored encrypted (.nm_secret.key)"></div>
        <div class="dsec" style="margin-top:14px"><i class="fa-solid fa-list-check"></i> Steps <span class="cnt" id="jrn-count"></span></div>
        <div id="jrn-steps"></div>
        <button class="bio-btn ghost" style="margin-top:4px" onclick="addStep()"><i class="fa-solid fa-plus"></i> Add step</button>
        <div style="display:flex;gap:9px;margin-top:14px"><button class="bio-btn" onclick="saveJourney()">Save journey</button>
          <button class="bio-btn ghost" onclick="saveJourney(true)">Save &amp; run</button></div>
      </div>
    </div>
  </div>
  <?php endif; ?>
</div>

<script src="three.min.js"></script>
<script src="three-orbitcontrols.js"></script>
<script>
// UI scene refresh is DECOUPLED from the server probe interval (bio_poll_sec): probing is throttled
// server-side, so the browser just re-reads the DB at a live cadence (5–20s) regardless of poll_sec.
const BIO_POLL = Math.min(20, Math.max(5, <?= (int)$SET['poll_sec'] ?>)) * 1000;
const CAN_EDIT = <?= $canEdit ? 'true':'false' ?>;
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function nl(ts){ try{ return window.nmTimeStr ? window.nmTimeStr(ts) : (ts||''); }catch(e){ return ts||''; } }
const LEVEL_COLOR={ healthy:0x2ee6a0, stressed:0xf3b52c, sick:0xff7a45, critical:0xe74c3c, unknown:0x6b7686 };
const LEVEL_HEX ={ healthy:'#2ee6a0', stressed:'#f3b52c', sick:'#ff7a45', critical:'#e74c3c', unknown:'#6b7686' };

// ── WebGL gate → 2D fallback ─────────────────────────────────────────────────
let WEBGL=true;
(function(){ let ok=false; try{ const c=document.createElement('canvas'); ok=!!(window.WebGLRenderingContext&&(c.getContext('webgl')||c.getContext('experimental-webgl'))); }catch(e){}
  if(!ok||typeof THREE==='undefined'){ WEBGL=false; document.getElementById('bio-fallback').style.display='block'; document.getElementById('bio-canvas').style.display='none'; if(window.NMLoader) NMLoader.hide(); } })();

let SERVICES=[], LINKS=[];

// ═══════════════ 3D biosphere ═══════════════
let renderer,scene,camera,controls,stage,canvas,gCells,gLinks,gLabels,gClones;
let CELL={}, CORE={}, HALO={}, GAL={}, CLONE={}, LABELS={}, LINKMESH=[], spin=true, showLabels=true, built=false, fitDone=false, hidden=false, lastT=0;
const CORE_GEO=new THREE.IcosahedronGeometry(11,2);   // crisp faceted reactor core (same construction as Data Core Observatory)

// GLSL: Ashima simplex noise (public domain) — organic membrane displacement
const SNOISE=`
vec4 permute(vec4 x){return mod(((x*34.0)+1.0)*x,289.0);}
vec4 taylorInvSqrt(vec4 r){return 1.79284291400159-0.85373472095314*r;}
float snoise(vec3 v){ const vec2 C=vec2(1.0/6.0,1.0/3.0); const vec4 D=vec4(0.0,0.5,1.0,2.0);
  vec3 i=floor(v+dot(v,C.yyy)); vec3 x0=v-i+dot(i,C.xxx);
  vec3 g=step(x0.yzx,x0.xyz); vec3 l=1.0-g; vec3 i1=min(g.xyz,l.zxy); vec3 i2=max(g.xyz,l.zxy);
  vec3 x1=x0-i1+1.0*C.xxx; vec3 x2=x0-i2+2.0*C.xxx; vec3 x3=x0-1.0+3.0*C.xxx;
  i=mod(i,289.0); vec4 p=permute(permute(permute(i.z+vec4(0.0,i1.z,i2.z,1.0))+i.y+vec4(0.0,i1.y,i2.y,1.0))+i.x+vec4(0.0,i1.x,i2.x,1.0));
  float n_=1.0/7.0; vec3 ns=n_*D.wyz-D.xzx; vec4 j=p-49.0*floor(p*ns.z*ns.z);
  vec4 x_=floor(j*ns.z); vec4 y_=floor(j-7.0*x_); vec4 x=x_*ns.x+ns.yyyy; vec4 y=y_*ns.x+ns.yyyy; vec4 h=1.0-abs(x)-abs(y);
  vec4 b0=vec4(x.xy,y.xy); vec4 b1=vec4(x.zw,y.zw); vec4 s0=floor(b0)*2.0+1.0; vec4 s1=floor(b1)*2.0+1.0; vec4 sh=-step(h,vec4(0.0));
  vec4 a0=b0.xzyw+s0.xzyw*sh.xxyy; vec4 a1=b1.xzyw+s1.xzyw*sh.zzww;
  vec3 p0=vec3(a0.xy,h.x); vec3 p1=vec3(a0.zw,h.y); vec3 p2=vec3(a1.xy,h.z); vec3 p3=vec3(a1.zw,h.w);
  vec4 norm=taylorInvSqrt(vec4(dot(p0,p0),dot(p1,p1),dot(p2,p2),dot(p3,p3))); p0*=norm.x;p1*=norm.y;p2*=norm.z;p3*=norm.w;
  vec4 m=max(0.6-vec4(dot(x0,x0),dot(x1,x1),dot(x2,x2),dot(x3,x3)),0.0); m=m*m;
  return 42.0*dot(m*m,vec4(dot(p0,x0),dot(p1,x1),dot(p2,x2),dot(p3,x3))); }`;

const CELL_VERT=SNOISE+`
uniform float uTime,uPulse,uFrozen,uSludge; varying vec3 vN; varying vec3 vPos; varying float vDisp;
void main(){ vN=normal; vPos=position;
  float spd=mix(0.35+uPulse*1.6, 0.04, uFrozen);           // breathe faster when stressed; freeze on locks
  float amp=mix(0.10+uPulse*0.42, 0.03, uFrozen);          // swell when latency high; stiff when frozen
  float n=snoise(normal*(1.5+uPulse*1.4)+vec3(uTime*spd));
  n+=0.4*snoise(normal*3.4-vec3(uTime*spd*0.6));
  float disp=n*amp - uSludge*0.10*(0.5+0.5*normal.y);       // sludge sags the lower membrane
  vDisp=disp;
  vec3 pos=position+normal*disp;
  gl_Position=projectionMatrix*modelViewMatrix*vec4(pos,1.0); }`;

const CELL_FRAG=SNOISE+`
uniform float uTime,uInfect,uSludge,uFrozen,uHiber,uDisabled; uniform vec3 uColor; varying vec3 vN; varying vec3 vPos; varying float vDisp;
void main(){ vec3 L=normalize(vec3(0.5,0.8,0.6)); float diff=0.45+0.55*max(dot(normalize(vN),L),0.0);
  vec3 base=uColor;
  // sludge → murky, desaturated, darker
  base=mix(base, vec3(0.20,0.24,0.16), uSludge*0.7);
  // frozen → icy blue tint
  base=mix(base, vec3(0.55,0.78,1.0), uFrozen*0.6);
  vec3 col=base*diff;
  // rim/fresnel glow
  float rim=pow(1.0-max(dot(normalize(vN),vec3(0.0,0.0,1.0)),0.0),2.2);
  col+=uColor*rim*0.9;
  // infection: dark necrotic patches driven by 4xx/5xx rate
  float inf=snoise(vPos*2.6+vec3(uTime*0.15));
  float patch=smoothstep(1.0-uInfect*1.4, 1.02-uInfect*1.4, inf);
  col=mix(col, vec3(0.06,0.01,0.02), patch*uInfect);
  col+=vec3(0.9,0.15,0.1)*patch*uInfect*0.5;               // angry red rim on the necrosis edge
  float alpha=mix(0.6, 0.24, uHiber);                        // translucent membrane so the glowing nucleus shows through; hibernating → fainter
  alpha=mix(alpha, 0.12, uDisabled);
  gl_FragColor=vec4(col, alpha); }`;

// ── orbiting galaxy of glowing orbs (ported verbatim from Data Core Observatory) ──
// each orb = one recent vital sample: colour = health level, size = latency, alpha = recency.
const GAL_VS=`attribute vec3 aColor; attribute float aSize; attribute float aAlpha; varying vec3 vC; varying float vA;
  void main(){ vC=aColor; vA=aAlpha; vec4 mv=modelViewMatrix*vec4(position,1.0); gl_PointSize=aSize*(300.0/max(1.0,-mv.z)); gl_Position=projectionMatrix*mv; }`;
const GAL_FS=`varying vec3 vC; varying float vA; void main(){ float d=length(gl_PointCoord-vec2(0.5)); if(d>0.5) discard;
  float core=smoothstep(0.5,0.0,d); gl_FragColor=vec4(mix(vC*1.7,vec3(1.0),pow(core,3.0)*0.5), core*vA); }`;
function galaxyFor(orbits){ const n=(orbits||[]).length; if(!n) return null; const g=new THREE.BufferGeometry();
  const pos=new Float32Array(n*3), col=new Float32Array(n*3), sz=new Float32Array(n), al=new Float32Array(n);
  const maxLat=Math.max(1,...orbits.map(o=>+o.lat||0));
  orbits.forEach((o,i)=>{ const a=2.399963*i; const r=30+Math.sqrt((i+1)/n)*40;   // spiral disc clear of the membrane
    pos[i*3]=Math.cos(a)*r; pos[i*3+1]=(Math.sin(i*1.7)*7); pos[i*3+2]=Math.sin(a)*r;
    const hex=(o.ok===0)?LEVEL_COLOR.critical:(LEVEL_COLOR[o.level]!=null?LEVEL_COLOR[o.level]:LEVEL_COLOR.unknown);
    const c=new THREE.Color(hex); col[i*3]=c.r; col[i*3+1]=c.g; col[i*3+2]=c.b;
    sz[i]=4.5+Math.sqrt((+o.lat||0)/maxLat)*8; al[i]=0.35+((i+1)/n)*0.6; });   // newer orbs brighter → sweeping comet trail
  g.setAttribute('position',new THREE.BufferAttribute(pos,3)); g.setAttribute('aColor',new THREE.BufferAttribute(col,3));
  g.setAttribute('aSize',new THREE.BufferAttribute(sz,1)); g.setAttribute('aAlpha',new THREE.BufferAttribute(al,1));
  const m=new THREE.ShaderMaterial({transparent:true,depthWrite:false,blending:THREE.AdditiveBlending,vertexShader:GAL_VS,fragmentShader:GAL_FS});
  return new THREE.Points(g,m); }

function labelSprite(text,color){ const c=document.createElement('canvas'),ct=c.getContext('2d'); const f=40;
  ct.font=`600 ${f}px Segoe UI,sans-serif`; const w=Math.ceil(ct.measureText(text).width)+20; c.width=w; c.height=f+16;
  ct.font=`600 ${f}px Segoe UI,sans-serif`; ct.fillStyle='rgba(6,10,20,.55)'; ct.fillRect(0,0,w,c.height);
  ct.fillStyle=color||'#dfe7f2'; ct.textBaseline='middle'; ct.fillText(text,10,c.height/2);
  const tex=new THREE.CanvasTexture(c); tex.minFilter=THREE.LinearFilter;
  const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:tex,transparent:true,depthWrite:false})); sp.scale.set(w*0.14,c.height*0.14,1); return sp; }

function initGL(){
  stage=document.getElementById('bio-stage'); canvas=document.getElementById('bio-canvas');
  renderer=new THREE.WebGLRenderer({canvas,antialias:true,alpha:true}); renderer.setClearColor(0x000000,0);
  scene=new THREE.Scene(); scene.fog=new THREE.FogExp2(0x04050c,0.0006);
  camera=new THREE.PerspectiveCamera(55,1,1,6000); camera.position.set(0,120,520);
  controls=new THREE.OrbitControls(camera,renderer.domElement); controls.enableDamping=true; controls.dampingFactor=.08;
  controls.autoRotate=true; controls.autoRotateSpeed=.45; controls.minDistance=70; controls.maxDistance=2400;
  scene.add(new THREE.AmbientLight(0x8899cc,0.8)); const key=new THREE.PointLight(0xafc4ff,0.6,0); key.position.set(300,500,400); scene.add(key);
  gCells=new THREE.Group(); gLinks=new THREE.Group(); gLabels=new THREE.Group(); gClones=new THREE.Group();
  scene.add(gLinks); scene.add(gCells); scene.add(gClones); scene.add(gLabels);
}

// phyllotaxis layout on a disc, gentle z-depth by kind, radius scales with count
function layout(list){ const pos={}; const n=list.length; const R=120+n*16;
  const zByKind={dns:60,http:0,sql:-60,smtp:30,generic:-30};
  list.forEach((s,i)=>{ const a=2.399963*i; const r=R*Math.sqrt((i+0.5)/Math.max(1,n));
    pos[s.id]=new THREE.Vector3(Math.cos(a)*r, (zByKind[s.kind]||0)*0.5 + Math.sin(i*1.3)*18, Math.sin(a)*r); });
  return pos; }
let POS={};

function buildScene(){
  [gCells,gLinks,gLabels,gClones].forEach(g=>{ while(g.children.length) g.remove(g.children[0]); });
  CELL={}; CORE={}; HALO={}; GAL={}; CLONE={}; LABELS={}; LINKMESH=[];
  if(!SERVICES.length){ document.getElementById('bio-empty').style.display='flex';
    document.getElementById('bio-empty-msg').innerHTML=CAN_EDIT?'No services yet.<br>Open <b>Manage → Add</b> to culture your first cell.':'No services configured yet.'; if(window.NMLoader)NMLoader.hide(); return; }
  document.getElementById('bio-empty').style.display='none';
  POS=layout(SERVICES);
  const geo=new THREE.IcosahedronGeometry(20,5);
  SERVICES.forEach(s=>{
    const col=new THREE.Color(LEVEL_COLOR[s.vitals.level]||LEVEL_COLOR.unknown);
    const mat=new THREE.ShaderMaterial({ transparent:true, uniforms:{
      uTime:{value:Math.random()*20}, uPulse:{value:s.viz.pulse||0}, uInfect:{value:s.viz.infection||0},
      uSludge:{value:s.viz.sludge||0}, uFrozen:{value:s.viz.frozen||0}, uHiber:{value:s.viz.hibernating||0},
      uDisabled:{value:s.viz.disabled||0}, uColor:{value:col} }, vertexShader:CELL_VERT, fragmentShader:CELL_FRAG });
    const m=new THREE.Mesh(geo,mat); m.position.copy(POS[s.id]); m.userData=s; gCells.add(m); CELL[s.id]=m;
    // crisp faceted reactor core inside the membrane (identical build to Data Core Observatory) — pulses with load
    const core=new THREE.Mesh(CORE_GEO,new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:.9,roughness:.3,metalness:.35,flatShading:true}));
    core.position.copy(POS[s.id]); core.userData=s; gCells.add(core); CORE[s.id]={mesh:core,t:Math.random()*10};
    // additive halo (exact Data Core Observatory params: r=30, opacity .10)
    const halo=new THREE.Mesh(new THREE.SphereGeometry(30,20,20), new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:.10,blending:THREE.AdditiveBlending,depthWrite:false}));
    halo.position.copy(POS[s.id]); halo.userData=s; gCells.add(halo); HALO[s.id]=halo;
    // orbiting galaxy of recent-vital orbs
    const gal=galaxyFor(s.orbits); if(gal){ gal.userData._n=(s.orbits||[]).length; gal.position.copy(POS[s.id]); gCells.add(gal); GAL[s.id]=gal; }
    const lab=labelSprite(s.name,LEVEL_HEX[s.vitals.level]); lab.position.copy(POS[s.id]).add(new THREE.Vector3(0,34,0)); lab.visible=showLabels; gLabels.add(lab); LABELS[s.id]=lab;
    // P3: a "wireframe clone" ghost that splits off an HTTP cell when its synthetic journey breaks —
    // the rendered UX diverging from the healthy structure (hidden until viz.ux > 0).
    if(s.kind==='http'){ const wf=new THREE.Mesh(geo,new THREE.MeshBasicMaterial({color:0x9fb7ff,wireframe:true,transparent:true,opacity:0,depthWrite:false}));
      wf.position.copy(POS[s.id]); wf.visible=false; wf.userData=s; gClones.add(wf); CLONE[s.id]=wf; }
  });
  // symbiosis pathways
  LINKS.forEach(l=>{ if(!POS[l.from]||!POS[l.to]) return;
    const a=POS[l.from], b=POS[l.to], mid=a.clone().add(b).multiplyScalar(0.5); mid.y+=40;
    const curve=new THREE.QuadraticBezierCurve3(a,mid,b); const g=new THREE.BufferGeometry().setFromPoints(curve.getPoints(30));
    const line=new THREE.Line(g,new THREE.LineBasicMaterial({color:0x7c6bff,transparent:true,opacity:.35})); gLinks.add(line);
    LINKMESH.push({line,from:l.from,to:l.to}); });
  built=true; applyViz(); if(window.NMLoader) NMLoader.hide();
  if(!fitDone){ fitView(); fitDone=true; }
}

function applyViz(){ SERVICES.forEach(s=>{ const m=CELL[s.id]; if(!m) return; const u=m.material.uniforms;
  u.uPulse.value=s.viz.pulse||0; u.uInfect.value=s.viz.infection||0; u.uSludge.value=s.viz.sludge||0;
  u.uFrozen.value=s.viz.frozen||0; u.uHiber.value=s.viz.hibernating||0; u.uDisabled.value=s.viz.disabled||0;
  const col=LEVEL_COLOR[s.vitals.level]||LEVEL_COLOR.unknown;
  u.uColor.value=new THREE.Color(col);
  // reactor core + halo track health colour
  const C=CORE[s.id]; if(C){ C.mesh.material.color.setHex(col); C.mesh.material.emissive.setHex(col); }
  const H=HALO[s.id]; if(H){ H.material.color.setHex(col); }
  // rebuild the orbiting galaxy from the latest samples (small n, cheap)
  const oldG=GAL[s.id]; const orbSig=(s.orbits||[]).length;
  if(oldG && oldG.userData._n!==orbSig){ gCells.remove(oldG); oldG.geometry.dispose(); oldG.material.dispose(); delete GAL[s.id]; }
  if(!GAL[s.id]){ const gal=galaxyFor(s.orbits); if(gal){ gal.userData._n=orbSig; gal.position.copy(POS[s.id]); gCells.add(gal); GAL[s.id]=gal; } }
  // P3 wireframe clone: split it off proportional to how much of the journey broke
  const wf=CLONE[s.id]; if(wf){ const ux=s.viz.ux||0; wf.visible=ux>0; wf.userData=s;
    if(ux>0){ wf.material.opacity=Math.min(0.9,0.25+ux*0.75); const off=8+ux*26; wf.position.copy(POS[s.id]).add(new THREE.Vector3(off,off*0.35,off*0.5)); wf.scale.setScalar(1+ux*0.18); } }
}); }

function animate(now){ requestAnimationFrame(animate); if(hidden||!WEBGL) return;
  const dt=Math.min(0.05,(now-lastT)/1000); lastT=now; controls.autoRotate=spin; controls.update();
  Object.values(CELL).forEach(m=>{ m.material.uniforms.uTime.value+=dt; });
  // reactor core: pulse ∝ latency-load, frozen → slow icy shiver (same behaviour as Data Core Observatory)
  SERVICES.forEach(s=>{ const C=CORE[s.id]; if(!C) return; const v=s.viz||{}; C.t+=dt;
    const rate=v.frozen?1.2:(2+(v.pulse||0)*6); const sc=1+Math.sin(C.t*rate)*(0.04+(v.pulse||0)*0.06);
    C.mesh.scale.setScalar(sc); C.mesh.material.emissiveIntensity=0.7+Math.sin(C.t*rate)*0.35+(v.sludge||0)*0.3;
    C.mesh.rotation.y+=dt*0.3; C.mesh.rotation.x+=dt*0.12;
    const H=HALO[s.id]; if(H) H.scale.setScalar(1+(v.pulse||0)*0.4+Math.sin(C.t*rate)*0.05);
    const G=GAL[s.id]; if(G) G.rotation.y+=dt*(0.12+(v.pulse||0)*0.4); });
  // fractured clones tumble slowly (feels like a detached, glitching UX shell)
  Object.values(CLONE).forEach(wf=>{ if(wf.visible){ wf.rotation.y+=dt*0.6; wf.rotation.x+=dt*0.25; } });
  // pulse the symbiosis lines
  const t=now*0.001; LINKMESH.forEach(L=>{ L.line.material.opacity=0.2+0.2*(0.5+0.5*Math.sin(t*2)); });
  renderer.render(scene,camera); }

function fitView(){ if(!Object.keys(POS).length) return; const box=new THREE.Box3(); Object.values(POS).forEach(p=>box.expandByPoint(p));
  const c=box.getCenter(new THREE.Vector3()), sz=box.getSize(new THREE.Vector3()); const r=Math.max(sz.x,sz.y,sz.z,120);
  controls.target.copy(c); camera.position.set(c.x,c.y+r*0.4,c.z+r*1.8); camera.near=1; camera.far=r*20; camera.updateProjectionMatrix(); }
function resize(){ if(!WEBGL) return; const w=stage.clientWidth,h=stage.clientHeight; renderer.setPixelRatio(Math.min(window.devicePixelRatio||1,2)); renderer.setSize(w,h,false); camera.aspect=w/h; camera.updateProjectionMatrix(); }

// ── raycast interaction ───────────────────────────────────────────────────────
function bindPick(){ const ray=new THREE.Raycaster(); const mouse=new THREE.Vector2();
  function pick(ev){ const r=canvas.getBoundingClientRect(); mouse.x=((ev.clientX-r.left)/r.width)*2-1; mouse.y=-((ev.clientY-r.top)/r.height)*2+1; ray.setFromCamera(mouse,camera); return ray.intersectObjects(gCells.children.concat(gClones.children),false); }
  canvas.addEventListener('mousemove',ev=>{ const hit=pick(ev); const tip=document.getElementById('bio-tip');
    if(hit.length&&hit[0].object.userData&&hit[0].object.userData.id){ const s=hit[0].object.userData; tip.style.display='block'; tip.style.left=ev.clientX+'px'; tip.style.top=(ev.clientY-6)+'px';
      const v=s.vitals; tip.innerHTML=`<b>${esc(s.name)}</b> · ${esc(s.kind.toUpperCase())}<br>${esc((v.level||'?').toUpperCase())}${v.latency_ms!=null?(' · '+Math.round(v.latency_ms)+'ms'):''}`; canvas.style.cursor='pointer'; }
    else { tip.style.display='none'; canvas.style.cursor='grab'; } });
  canvas.addEventListener('click',ev=>{ const hit=pick(ev); if(hit.length&&hit[0].object.userData&&hit[0].object.userData.id) openInfo(hit[0].object.userData); });
}

// ═══════════════ data ═══════════════
async function loadScene(first){
  let d=null; try{ d=await fetch('biosphere.php?api=scene&_='+Date.now()).then(r=>r.json()); }catch(e){ return; }
  if(!d||!d.ok) return;
  const same= built && d.services.length===SERVICES.length && d.services.every((s,i)=>SERVICES[i]&&SERVICES[i].id===s.id) && d.links.length===LINKS.length;
  SERVICES=d.services; LINKS=d.links;
  if(WEBGL){ if(!same) buildScene(); else applyViz(); }
  else renderFallback();
  renderHUD();
  updateFreshness(d);
}
// Warn when vitals are stale (cron_biosphere.php not polling): grey/frozen cells otherwise look
// like a bug. Stale = newest sample older than 3× the poll interval (min 3 min).
function updateFreshness(d){ const el=document.getElementById('bio-stale'); if(!el) return;
  const age=d.fresh_age, poll=Math.max(60,+d.poll_sec||60), thresh=Math.max(180,poll*3);
  if(age==null){ el.style.display=SERVICES.length?'block':'none';
    document.getElementById('bio-stale-msg').innerHTML='No vitals yet — run <b>cron_biosphere.php</b> (every minute) to bring the cells to life.'; return; }
  if(age>thresh){ el.style.display='block';
    const m=age>=90?Math.round(age/60)+' min':age+'s';
    document.getElementById('bio-stale-msg').innerHTML='Vitals are <b>'+m+'</b> stale — is <b>cron_biosphere.php</b> running every minute? Cells show their last known state.';
  } else el.style.display='none';
}
function renderHUD(){ let healthy=0,sick=0,down=0; SERVICES.forEach(s=>{ const v=s.vitals; if(v.ok===0) down++; else if(v.level==='sick'||v.level==='critical') sick++; else if(v.level==='healthy') healthy++; });
  document.getElementById('s-healthy').textContent=healthy; document.getElementById('s-sick').textContent=sick;
  document.getElementById('s-down').textContent=down; document.getElementById('s-total').textContent=SERVICES.length; }

function renderFallback(){ const el=document.getElementById('bento');
  if(!SERVICES.length){ el.innerHTML='<div class="dmuted" style="grid-column:1/-1;text-align:center">No services configured yet.</div>'; return; }
  el.innerHTML=SERVICES.map(s=>{ const v=s.vitals; const hex=LEVEL_HEX[v.level]||LEVEL_HEX.unknown;
    return `<div class="bcard" onclick='openInfoById(${s.id})'><div class="bh"><i class="fa-solid ${esc(s.icon)}" style="color:${hex}"></i> ${esc(s.name)} <span class="kpill" style="margin-left:auto">${esc(s.kind)}</span></div>
      <div class="bm">Status: <b style="color:${hex}">${esc((v.level||'?').toUpperCase())}</b>${v.ok===0?' · DOWN':''}</div>
      <div class="bm">${v.latency_ms!=null?('Latency '+Math.round(v.latency_ms)+' ms · '):''}${v.err_rate?('Err '+Math.round(v.err_rate*100)+'% · '):''}score ${v.score!=null?v.score:'—'}</div></div>`; }).join(''); }

// ═══════════════ detail drawer ═══════════════
function openInfoById(id){ const s=SERVICES.find(x=>x.id===id); if(s) openInfo(s); }
function dcell(l,v){ return `<div class="dcell"><div class="l">${esc(l)}</div><div class="v">${esc(v)}</div></div>`; }
function dsec(icon,label,cnt){ return `<div class="dsec"><i class="fa-solid fa-${icon}"></i> ${esc(label)} <span class="cnt">${cnt!=null?cnt:''}</span></div>`; }
async function openInfo(s){ const box=document.getElementById('bio-info'); box.style.display='block';
  const hex=LEVEL_HEX[s.vitals.level]||LEVEL_HEX.unknown;
  document.getElementById('bi-name').innerHTML=`<i class="fa-solid ${esc(s.icon)}" style="color:${hex}"></i> ${esc(s.name)}`;
  document.getElementById('bi-meta').innerHTML=`${esc(s.kind.toUpperCase())} · ${esc(s.target||'')} ${s.node_name?('· '+esc(s.node_name)):''}`;
  const body=document.getElementById('bio-db'); body.innerHTML='<div class="dmuted">Loading cell dossier…</div>'; document.getElementById('bio-dacts').innerHTML='';
  let d=null,err=''; try{ const resp=await fetch('biosphere.php?api=service&id='+s.id+'&_='+Date.now()); const txt=await resp.text(); try{ d=JSON.parse(txt); }catch(pe){ err='HTTP '+resp.status+' · '+txt.slice(0,180); } }catch(e){ err='network: '+(e&&e.message||e); }
  if(!d||!d.ok){ body.innerHTML='<div class="dmuted">Could not load cell details.'+(err?'<br><span style="color:#ff9b91;font-family:monospace;font-size:10px">'+esc(err)+'</span>':'')+'</div>'; return; }
  try{ body.innerHTML=renderDossier(d,s); }catch(re){ body.innerHTML='<div class="dmuted">Render error: <span style="color:#ff9b91;font-family:monospace">'+esc(re&&re.message||re)+'</span></div>'; return; }
  const acts=[]; if(s.node_id){ acts.push(`<a class="act" href="troubleshoot.php"><i class="fa-solid fa-stethoscope"></i> Investigate</a>`); }
  if(d.service.kind==='sql'&&d.service.db_target_id){ acts.push(`<a class="act" href="dbmon.php"><i class="fa-solid fa-database"></i> Data Core</a>`); }
  if(d.service.kind==='dns'){ acts.push(`<a class="act" href="pihole.php"><i class="fa-solid fa-shield-halved"></i> Pi-hole</a>`); }
  if(CAN_EDIT){ acts.push(`<button class="act" onclick="editSvc(${d.service.id})"><i class="fa-solid fa-pen"></i> Edit</button>`); }
  document.getElementById('bio-dacts').innerHTML=acts.join('');
}
function renderDossier(d,s){ const v=s.vitals; const last=d.last||{}; let h='';
  h+='<div class="dgrid">'+dcell('Health',v.score!=null?v.score+'/100':'—')+dcell('Status',(v.level||'?').toUpperCase())
    +dcell('Latency',v.latency_ms!=null?Math.round(v.latency_ms)+' ms':'—')+dcell('24h Uptime',d.avail_24h!=null?d.avail_24h+'%':'—')
    +dcell('Err rate',v.err_rate!=null?Math.round(v.err_rate*100)+'%':'—')+dcell('Cache-hit',v.cache_hit!=null?v.cache_hit+'%':'—')+'</div>';
  h+=`<div class="dmuted">Last checked ${last.ts?esc(nl(last.ts)):'—'} · thresholds ${d.thresholds.lat_warn}/${d.thresholds.lat_crit} ms</div>`;
  // latency sparkline
  if(d.trend&&d.trend.length){ const mx=Math.max(1,...d.trend.map(t=>+t.latency_ms||0));
    h+=dsec('wave-square','Latency trend',d.trend.length)+'<div class="spark">'+d.trend.map(t=>{ const hh=Math.round((+t.latency_ms||0)/mx*38); const c=t.ok==0?'#e74c3c':(t.level==='sick'||t.level==='critical'?'#ff7a45':(t.level==='stressed'?'#f3b52c':'#2ee6a0')); return `<i style="height:${Math.max(2,hh)}px;background:${c}"></i>`; }).join('')+'</div>'; }
  // kind-specific vitals
  const e=d.extra||{};
  if(s.kind==='sql'){ h+=dsec('gauge-high','Metabolic vitals');
    h+='<div class="dgrid">'+dcell('Conns',e.connections!=null?e.connections+(e.max_connections?('/'+e.max_connections):''):'—')+dcell('Saturation',e.saturation!=null?e.saturation+'%':'—')+dcell('Running',e.threads_running!=null?e.threads_running:'—')+dcell('Slow',e.slow!=null?e.slow:'—')+dcell('Locks',e.blocked!=null?e.blocked:'—')+dcell('Engine',e.engine||'—')+'</div>';
    if(d.top_queries&&d.top_queries.length){ h+=dsec('magnifying-glass-chart','Heaviest queries',d.top_queries.length);
      d.top_queries.forEach(q=>{ h+=`<div class="ditem ${q.no_index?'warn':''}"><div class="t"><span>${q.avg_ms!=null?Math.round(q.avg_ms)+' ms avg':''} ${q.calls?('· '+q.calls+' calls'):''}</span>${q.no_index?'<span class="dbadge warn">no index</span>':''}</div><div class="d qrow">${esc((q.query||'').slice(0,160))}</div></div>`; }); }
    // Metabolic advisor: reuse Data Core 'db-advisor'; whitelisted advice → Telegram Auto-Tune
    h+=dsec('flask','Metabolic advisor',d.advice?d.advice.length:0);
    if(d.advice&&d.advice.length){ d.advice.forEach(a=>{ const auto=/^(index|maintenance)$/i.test(a.kind);
      h+=`<div class="ditem ${a.risk==='high'?'crit':(a.risk==='medium'?'warn':'ok')}"><div class="t"><span>${esc(a.title||a.kind)}</span><span class="dbadge">${esc(a.risk||'')}</span></div>${a.rationale?`<div class="d">${esc(a.rationale)}</div>`:''}${a.ddl?`<div class="d qrow">${esc((a.ddl||'').slice(0,180))}</div>`:''}${(CAN_EDIT&&auto)?`<div class="d" style="margin-top:6px"><button class="act" style="padding:4px 8px;font-size:11px;border-color:rgba(46,204,113,.5);color:#8fe3b0" onclick="applyTune(${a.id},${s.id})">⚡ Apply now</button></div>`:(CAN_EDIT?'<div class="d" style="color:#7a8291">Manual-only — apply in Data Core.</div>':'')}</div>`; }); }
    else h+=`<div class="dmuted">No suggestions yet.${CAN_EDIT?` <button class="act" style="padding:3px 8px;font-size:11px" onclick="analyzeSql(${s.id},this)">🧠 Analyze now</button>`:''}</div>`; }
  else if(s.kind==='http'){ h+=dsec('window-maximize','HTTP vitals'); h+='<div class="dgrid">'+dcell('Code',e.code!=null?e.code:'—')+dcell('TTFB',e.ttfb_ms!=null?Math.round(e.ttfb_ms)+' ms':'—')+dcell('Size',e.size!=null?Math.round(e.size/102.4)/10+' KB':'—')+'</div>'; if(e.reason) h+=`<div class="ditem ${(e.code>=400||e.code===0||e.code==null)?'crit':''}"><div class="d">${esc(e.reason)}</div></div>`; if(e.error) h+=`<div class="ditem crit"><div class="d">${esc(e.error)}</div></div>`; }
  else if(s.kind==='dns'){ h+=dsec('globe','DNS vitals'); h+='<div class="dgrid">'+dcell('Answers',e.answers!=null?e.answers:'—')+dcell('RCODE',e.rcode!=null?e.rcode:'—')+dcell('Probe',e.probe_name||'—')+(e.pihole?dcell('Cached',v.cache_hit!=null?v.cache_hit+'%':'—')+dcell('Blocked',e.blocked_pct!=null?e.blocked_pct+'%':'—'):'')+'</div>'; }
  else if(s.kind==='smtp'){ h+=dsec('envelope','SMTP vitals'); if(e.banner) h+=`<div class="ditem ok"><div class="d qrow">${esc(e.banner)}</div></div>`; if(e.error) h+=`<div class="ditem crit"><div class="d">${esc(e.error)}</div></div>`; }
  // P3: synthetic UX journey (HTTP cells)
  if(s.kind==='http'){ const sy=d.synthetic, j=d.journey;
    h+=dsec('user-astronaut','Synthetic UX journey', sy?sy.steps_total:0);
    if(sy){ h+='<div class="dgrid">'+dcell('VCT',sy.vct_ms!=null?Math.round(sy.vct_ms)+' ms':'—')+dcell('Steps',sy.steps_ok+'/'+sy.steps_total)+dcell('Result',sy.ok?'PASS':'BROKEN')+'</div>';
      if(!sy.ok&&sy.broken_step) h+=`<div class="ditem crit"><div class="t"><span>✂ Broke at: ${esc(sy.broken_step)}</span></div><div class="d">A wireframe clone split off this cell — the rendered UX diverged from the healthy structure.</div></div>`;
      if(sy.steps&&sy.steps.length) h+='<div style="display:flex;flex-wrap:wrap;gap:4px;margin:6px 0">'+sy.steps.map(st=>`<span class="dbadge ${st.ok?'ok':'crit'}">${esc(st.name||st.type||'step')}${st.ms!=null?(' '+Math.round(st.ms)+'ms'):''}</span>`).join('')+'</div>';
      h+=`<div class="dmuted">last run ${esc(nl(sy.ts))}${sy.console_errors?(' · '+sy.console_errors+' console errors'):''}${sy.has_shot?' · 📷':''}</div>`;
    } else h+='<div class="dmuted">No journey run yet.</div>';
    if(CAN_EDIT){ const steps=(j&&j.steps)?j.steps.length:0, hasLogin=j&&j.persona&&j.persona.login_url;
      h+='<div class="d" style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap">'+
         ((steps||hasLogin)?`<button class="act" style="padding:4px 8px;font-size:11px" onclick="runJourney(${s.id},this)">▶ Run now</button>`:'')+
         `<button class="act" style="padding:4px 8px;font-size:11px" onclick="editJourney(${s.id})">✎ ${steps?'Edit':'Define'} journey${steps?(' ('+steps+')'):''}</button></div>`; }
  }
  // flags
  if(d.flags&&d.flags.length){ h+=dsec('flag','AI / analyzer flags',d.flags.length); d.flags.forEach(f=>{ h+=`<div class="ditem ${f.severity==='high'?'crit':'warn'}"><div class="t"><span>${esc(f.kind)} — ${esc(f.indicator||'')}</span><span class="dbadge ${f.severity==='high'?'crit':'warn'}">${esc(f.severity)}</span></div>${f.detail?`<div class="d">${esc(f.detail)}</div>`:''}${CAN_EDIT&&f.indicator?`<div class="d"><button class="act" style="padding:4px 8px;font-size:11px" onclick="promoteFlag(${f.id})">🛡 Block fleet-wide</button></div>`:''}</div>`; }); }
  // symbiosis
  if((d.deps&&d.deps.length)||(d.feeds&&d.feeds.length)){ h+=dsec('diagram-project','Symbiosis');
    d.deps.forEach(x=>{ h+=`<div class="ditem"><div class="t"><span>→ depends on ${esc(x.name)}</span><span class="dbadge">${esc(x.kind)}</span></div></div>`; });
    d.feeds.forEach(x=>{ h+=`<div class="ditem"><div class="t"><span>← feeds ${esc(x.name)}</span><span class="dbadge">${esc(x.kind)}</span></div></div>`; }); }
  return h; }

async function promoteFlag(id,fromFlags){ if(!confirm('Promote this indicator to a fleet-wide Immunity block?')) return;
  const r=await fetch('biosphere.php?api=promote',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'flag='+id}).then(r=>r.json());
  alert(r.ok?('Blocked across '+(r.distributed||0)+' defenders.'):('Failed: '+(r.error||'?'))); if(fromFlags) loadFlags(); }
// SQL metabolic: engage the Data Core advisor (suggestions post back async), then Auto-Tune via Telegram
async function analyzeSql(id,btn){ const o=btn.innerHTML; btn.disabled=true; btn.innerHTML='<i class="fa-solid fa-spinner fa-spin"></i>';
  const r=await fetch('biosphere.php?api=advise',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'id='+id}).then(r=>r.json()).catch(()=>({ok:false,error:'request failed'})); btn.disabled=false; btn.innerHTML=o;
  alert(r.ok?('Advisor engaged. '+(r.note||'Suggestions appear as they post back — reopen this cell in a moment.')):('Failed: '+(r.error||r.note||'?'))); }
// You're in the portal clicking the button → that IS the approval. Apply the whitelisted DDL now,
// then announce it to the enabled notification channels (no self-approval round-trip).
async function applyTune(adviceId,svcId){ if(!confirm('Apply this tuning DDL to the database now?\n\nIt runs immediately (whitelisted CREATE INDEX / ANALYZE / OPTIMIZE only) and a heads-up is sent to your notification channels.')) return;
  const r=await fetch('biosphere.php?api=apply_advice',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'advice='+adviceId}).then(r=>r.json());
  alert(r.ok?('✅ Applied.'+(r.channels?(' Notified '+(r.notified||0)+'/'+r.channels+' channel(s).'):' (no notification channels enabled)')):('Failed: '+(r.error||'?')));
  loadScene(false); const s=SERVICES.find(x=>x.id===svcId); if(s&&r.ok) setTimeout(()=>openInfo(s),400); }

// ═══════════════ P3 synthetic journey editor ═══════════════
const STEP_TYPES=['goto','fill','click','expect','expect_text','wait'];
let JRN_SVC=0;
function stepRow(st){ st=st||{type:'click',selector:'',value:''};
  const d=document.createElement('div'); d.className='jrn-row';
  d.innerHTML=`<select class="ty">${STEP_TYPES.map(t=>`<option ${t===st.type?'selected':''}>${t}</option>`).join('')}</select>`+
    `<input class="sel" placeholder="CSS selector / URL" value="${esc(st.selector||'')}">`+
    `<input class="val" placeholder="value (for fill / expect_text / wait ms)" value="${esc(st.value||'')}">`+
    `<div class="rm" onclick="this.parentNode.remove();jrnCount()"><i class="fa-solid fa-trash"></i></div>`;
  return d; }
function addStep(st){ document.getElementById('jrn-steps').appendChild(stepRow(st)); jrnCount(); }
function jrnCount(){ document.getElementById('jrn-count').textContent='('+document.querySelectorAll('#jrn-steps .jrn-row').length+')'; }
async function editJourney(id){ JRN_SVC=id; const svc=SERVICES.find(x=>x.id===id);
  document.getElementById('jrn-svc').textContent=svc?('· '+svc.name):'';
  const d=await fetch('biosphere.php?api=journey_get&id='+id).then(r=>r.json());
  const p=(d&&d.persona)||{}, steps=(d&&d.steps)||[];
  document.getElementById('jp-url').value=p.login_url||''; document.getElementById('jp-us').value=p.user_selector||'';
  document.getElementById('jp-ps').value=p.pass_selector||''; document.getElementById('jp-sub').value=p.submit_selector||'';
  document.getElementById('jp-user').value=p.username||''; document.getElementById('jp-pw').value='';
  document.getElementById('jp-pwnote').textContent=p.has_password?'— stored (leave blank to keep)':'';
  const box=document.getElementById('jrn-steps'); box.innerHTML=''; (steps.length?steps:[{type:'goto',selector:'',value:''}]).forEach(addStep); jrnCount();
  document.getElementById('bio-journey').style.display='flex'; }
async function saveJourney(runAfter){ const steps=[...document.querySelectorAll('#jrn-steps .jrn-row')].map(r=>({type:r.querySelector('.ty').value,selector:r.querySelector('.sel').value,value:r.querySelector('.val').value})).filter(s=>s.selector||s.value||s.type==='wait');
  const persona={login_url:document.getElementById('jp-url').value,user_selector:document.getElementById('jp-us').value,pass_selector:document.getElementById('jp-ps').value,submit_selector:document.getElementById('jp-sub').value,username:document.getElementById('jp-user').value};
  const pw=document.getElementById('jp-pw').value; if(pw) persona.password=pw;
  const b=new URLSearchParams(); b.set('id',JRN_SVC); b.set('steps',JSON.stringify(steps)); b.set('persona',JSON.stringify(persona));
  const r=await fetch('biosphere.php?api=journey_save',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b.toString()}).then(r=>r.json());
  if(!r.ok){ alert('Save failed: '+(r.error||'?')); return; }
  document.getElementById('bio-journey').style.display='none';
  if(runAfter) runJourney(JRN_SVC); else { const s=SERVICES.find(x=>x.id===JRN_SVC); if(s) openInfo(s); } }
async function runJourney(id,btn){ if(btn){ btn.disabled=true; btn.innerHTML='<i class="fa-solid fa-spinner fa-spin"></i>'; }
  const r=await fetch('biosphere.php?api=synthetic',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'id='+id}).then(r=>r.json()).catch(()=>({ok:false,error:'request failed'}));
  alert(r.ok?('🧑‍🚀 '+(r.note||'Journey dispatched.')):('Failed: '+(r.error||r.note||'?')));
  const s=SERVICES.find(x=>x.id===id); if(s) setTimeout(()=>openInfo(s),600); loadScene(false); }

// ═══════════════ management ═══════════════
let REFS={db_targets:[],piholes:[],nodes:[]};
function mtab(t){ ['svc','add','flags','set'].forEach(x=>{ document.getElementById('mt-'+x).style.display=x===t?'block':'none'; document.querySelector('.mtab button[data-mt="'+x+'"]').classList.toggle('on',x===t); });
  if(t==='svc') loadSvcList(); if(t==='add') loadRefs(); if(t==='flags') loadFlags(); }
async function loadFlags(){ const el=document.getElementById('flags-list'); const d=await fetch('biosphere.php?api=flags&status=open').then(r=>r.json());
  if(!d||!d.ok||!d.flags.length){ el.innerHTML='<div class="dmuted">No open antibodies. 🟢 The biosphere is clean.</div>'; return; }
  const kc={}; d.flags.forEach(f=>{ kc[f.kind]=(kc[f.kind]||0)+1; }); const n=d.flags.length;
  let bar='<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap"><span class="dmuted">'+n+(n>=60?'+':'')+' open antibod'+(n===1?'y':'ies')+'</span><span style="display:flex;gap:6px;flex-wrap:wrap">';
  Object.keys(kc).filter(k=>kc[k]>1).forEach(k=>{ bar+='<button class="act" style="padding:4px 8px;font-size:11px" onclick="resolveAllFlags(\''+k+'\')">✓ Resolve all '+esc(k)+' ('+kc[k]+')</button>'; });
  bar+='<button class="act" style="padding:4px 8px;font-size:11px" onclick="resolveAllFlags(\'\')">✓ Resolve all</button></span></div>';
  el.innerHTML=bar+d.flags.map(f=>{ const crit=f.severity==='high'; return `<div class="ditem ${crit?'crit':'warn'}"><div class="t"><span>${esc(f.kind)}${f.indicator?(' — '+esc(f.indicator)):''}</span><span class="dbadge ${crit?'crit':'warn'}">${esc(f.severity)}</span></div>
    <div class="d">${esc(f.svc_name||'')}${f.detail?(' · '+esc(f.detail)):''}</div>
    <div class="d" style="display:flex;gap:6px;margin-top:6px">${f.indicator?`<button class="act" style="padding:4px 8px;font-size:11px" onclick="promoteFlag(${f.id},1)">🛡 Block fleet-wide</button>`:''}<button class="act" style="padding:4px 8px;font-size:11px" onclick="resolveFlag(${f.id})">✓ Resolve</button></div></div>`; }).join(''); }
async function resolveFlag(id){ await fetch('biosphere.php?api=flag_resolve',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'flag='+id}); loadFlags(); }
async function resolveAllFlags(kind){ const label=kind?('all "'+kind+'" antibodies'):'ALL open antibodies';
  if(!confirm('Resolve '+label+'? This dismisses them (marks them resolved).')) return;
  const r=await fetch('biosphere.php?api=flag_resolve_all',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'kind='+encodeURIComponent(kind||'')}).then(r=>r.json()).catch(()=>({ok:false}));
  loadFlags(); }
async function runDnsAudit(btn){ const o=btn.innerHTML; btn.disabled=true; btn.innerHTML='<i class="fa-solid fa-spinner fa-spin"></i> Auditing…';
  const r=await fetch('biosphere.php?api=dns_audit').then(r=>r.json()).catch(()=>({ok:false,error:'request failed'})); btn.disabled=false; btn.innerHTML=o;
  alert(r.ok?`Audited ${r.candidates||0} domains · flagged ${r.flagged||0} · auto-blocked ${r.promoted||0}.\n${r.note||''}`:('Failed: '+(r.error||r.note||'?'))); loadFlags(); }
async function openManage(){ document.getElementById('bio-manage').style.display='block'; mtab('svc'); loadRefs(); }
async function loadRefs(){ if(REFS._loaded) return; const d=await fetch('biosphere.php?api=refs').then(r=>r.json()); if(d&&d.ok){ REFS=d; REFS._loaded=true;
  document.getElementById('f-dbt').innerHTML=d.db_targets.map(t=>`<option value="${t.id}">${esc(t.name)} (${esc(t.engine)})</option>`).join('')||'<option value="">— no Data Core targets —</option>';
  document.getElementById('f-ph').innerHTML='<option value="">— none —</option>'+d.piholes.map(p=>`<option value="${p.id}">${esc(p.name)}</option>`).join('');
  document.getElementById('f-node').innerHTML='<option value="">— none —</option>'+d.nodes.map(n=>`<option value="${n.id}">${esc(n.display_name)}</option>`).join(''); } }
async function loadSvcList(){ const el=document.getElementById('mt-svc'); const d=await fetch('biosphere.php?api=list').then(r=>r.json());
  if(!d||!d.ok||!d.services.length){ el.innerHTML='<div class="dmuted">No services yet. Use the <b>Add</b> tab.</div>'; return; }
  el.innerHTML=d.services.map(s=>{ const hex=LEVEL_HEX[s.last_level]||LEVEL_HEX.unknown; return `<div class="svc-row"><span class="dot" style="color:${hex};background:${hex}"></span>
    <div><div class="nm">${esc(s.name)} ${s.enabled==0?'<span class="dbadge">paused</span>':''}</div><div class="sub">${esc(s.kind.toUpperCase())} · ${esc(s.target||('target #'+s.db_target_id))}</div></div>
    <span class="sp"></span><a onclick="editSvc(${s.id})">Edit</a><a onclick="delSvc(${s.id},'${esc(s.name).replace(/'/g,"")}')" style="color:#ff9b91">Delete</a></div>`; }).join(''); }
function kindChange(){ const k=document.getElementById('f-kind').value;
  const show=(id,on)=>document.getElementById(id).classList.toggle('hide',!on);
  show('fw-target',k!=='sql'); show('fw-port',k!=='sql'&&k!=='http'); show('fw-probe',k==='dns'); show('fw-dbt',k==='sql');
  show('fw-ph',k==='dns'); show('fw-expect',k==='http'); show('fw-match',k==='http'); }
function resetForm(){ ['f-id','f-name','f-target','f-port','f-probe','f-expect','f-match'].forEach(i=>document.getElementById(i).value=''); document.getElementById('f-kind').value='http'; document.getElementById('f-node').value=''; document.getElementById('f-ph').value=''; document.getElementById('probe-out').textContent=''; kindChange(); }
async function editSvc(id){ await loadRefs(); const d=await fetch('biosphere.php?api=service&id='+id).then(r=>r.json()); if(!d||!d.ok) return; const s=d.service;
  document.getElementById('bio-manage').style.display='block'; mtab('add');
  document.getElementById('f-id').value=s.id; document.getElementById('f-name').value=s.name; document.getElementById('f-kind').value=s.kind;
  document.getElementById('f-target').value=s.target||''; document.getElementById('f-port').value=s.port||''; document.getElementById('f-node').value=s.node_id||'';
  document.getElementById('f-dbt').value=s.db_target_id||''; document.getElementById('f-ph').value=s.pihole_id||'';
  const e=d.extra||{}; document.getElementById('f-probe').value=e.probe_name||''; kindChange(); }
function formPayload(){ const k=document.getElementById('f-kind').value; const p={};
  if(k==='dns'&&document.getElementById('f-probe').value) p.probe_name=document.getElementById('f-probe').value;
  if(k==='http'){ if(document.getElementById('f-expect').value) p.expect_code=document.getElementById('f-expect').value; if(document.getElementById('f-match').value) p.match=document.getElementById('f-match').value; }
  const b=new URLSearchParams(); b.set('id',document.getElementById('f-id').value||''); b.set('name',document.getElementById('f-name').value); b.set('kind',k);
  b.set('target',document.getElementById('f-target').value); b.set('port',document.getElementById('f-port').value); b.set('db_target_id',document.getElementById('f-dbt').value);
  b.set('pihole_id',document.getElementById('f-ph').value); b.set('node_id',document.getElementById('f-node').value); b.set('enabled','1');
  Object.keys(p).forEach(kk=>b.set('params['+kk+']',p[kk])); return b; }
async function saveSvc(){ const b=formPayload(); if(!b.get('name')){ alert('Name required'); return; }
  const r=await fetch('biosphere.php?api=save',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b.toString()}).then(r=>r.json());
  if(r.ok){ resetForm(); mtab('svc'); loadScene(false); } else alert('Save failed: '+(r.error||'?')); }
async function delSvc(id,name){ if(!confirm('Delete service "'+name+'" and its samples?')) return;
  await fetch('biosphere.php?api=delete',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'id='+id}); loadSvcList(); loadScene(false); }
async function testProbe(){ const out=document.getElementById('probe-out'); const b=formPayload();
  if(!document.getElementById('f-id').value){ out.textContent='Save the service first, then Test probe reads it back live.'; return; }
  out.textContent='Probing…'; const r=await fetch('biosphere.php?api=probe&id='+document.getElementById('f-id').value).then(r=>r.json());
  if(r.ok){ const s=r.sample; const rn=(s.extra&&s.extra.reason)?(' — '+s.extra.reason):''; out.textContent=(s.ok?'✅ OK':('❌ DOWN'+rn))+`  latency=${s.latency_ms}ms  err=${s.err_rate}\n`+JSON.stringify(s.extra,null,1); } else out.textContent='Error: '+(r.error||'?'); }
async function saveSet(){ const b=new URLSearchParams(); b.set('bio_poll_sec',document.getElementById('s-poll').value); b.set('bio_sample_days',document.getElementById('s-days').value);
  b.set('bio_lat_warn',document.getElementById('s-lw').value); b.set('bio_lat_crit',document.getElementById('s-lc').value); b.set('bio_enabled',document.getElementById('s-en').value);
  b.set('bio_dns_audit',document.getElementById('s-dns').value); b.set('bio_dns_limit',document.getElementById('s-dnl').value); b.set('bio_dns_min',document.getElementById('s-dnm').value); b.set('bio_dga_promote',document.getElementById('s-dga').value);
  b.set('bio_synthetic',document.getElementById('s-syn').value); b.set('bio_synth_min',document.getElementById('s-synm').value); b.set('bio_vct_warn',document.getElementById('s-vct').value);
  const r=await fetch('biosphere.php?api=setting',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b.toString()}).then(r=>r.json()); alert(r.ok?'Saved. Reload to apply the poll interval.':'Failed'); }

// ── controls / chrome ─────────────────────────────────────────────────────────
if(WEBGL){ initGL(); bindPick();
  document.getElementById('b-fit').onclick=()=>fitView();
  document.getElementById('b-spin').onclick=e=>{ spin=!spin; e.currentTarget.classList.toggle('on',spin); };
  document.getElementById('b-labels').onclick=e=>{ showLabels=!showLabels; e.currentTarget.classList.toggle('on',showLabels); Object.values(LABELS).forEach(l=>l.visible=showLabels); };
  document.getElementById('b-full').onclick=()=>{ if(document.fullscreenElement) document.exitFullscreen(); else stage.requestFullscreen&&stage.requestFullscreen(); };
  window.addEventListener('resize',resize);
  document.addEventListener('fullscreenchange',()=>{ const bg=document.getElementById('nm-netbg');
    if(bg){ if(document.fullscreenElement===stage){ stage.insertBefore(bg,stage.firstChild); bg.style.zIndex='0'; } else { document.body.appendChild(bg); bg.style.zIndex='-1'; } }
    const i=document.querySelector('#b-full i'); if(i) i.className='fa-solid '+(document.fullscreenElement?'fa-compress':'fa-expand');
    setTimeout(()=>{ resize(); },80); });
  document.addEventListener('visibilitychange',()=>{ hidden=document.hidden; if(!hidden) lastT=performance.now(); });
}
if(CAN_EDIT){ const mb=document.getElementById('b-manage'); if(mb) mb.onclick=openManage; }

// ── boot ──────────────────────────────────────────────────────────────────────
if(window.NMLoader) NMLoader.msg&&NMLoader.msg('Culturing the biosphere…');
if(WEBGL){ resize(); lastT=performance.now(); animate(performance.now()); }
loadScene(true).then(()=>{ setInterval(()=>loadScene(false), BIO_POLL); });
</script>
</body></html>
