<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Device / Router Details (immersive full dossier for any node that isn't a
// deep Windows/Linux host: routers, ping-only probes, generic SNMP gear). Renders
// INSTANTLY from already-polled DB data (vitals, latency, incidents, interfaces,
// asset/inventory + equipment photo), then asynchronously enriches with a LIVE
// RouterOS SSH probe (identity, resources, counts, live interfaces). Particle bg +
// animated gauges, in the win_screen / linux_screen family. RBAC: 'net_mon'.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_nodemeta.php');
require_once('nm_router.php');
require_once('nm_media.php');
include('logger.php');

if (!checkAccess($conn, 'net_mon')) { header('Location: /denied_access.php?page=net_mon'); exit; }

$nid  = (int)($_GET['node'] ?? 0);
$node = $nid ? nm_router_node($conn, $nid) : null;
if (!$node) { header('Location: /net_mon.php'); exit; }
$kind = $node['kind'];

// ── async endpoints (slow SSH → release the session lock first) ──────────────────
$__api = $_GET['api'] ?? '';
if (in_array($__api, ['live','traffic','netflow'], true)) {
    if (function_exists('session_write_close')) @session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    try {
        if ($__api === 'live')         echo json_encode(nm_router_live_probe($conn, $node));
        elseif ($__api === 'traffic')  echo json_encode(nm_router_traffic_or_config($conn, $node));
        else                           echo json_encode(nm_router_netflow($conn, $node, 60));
    } catch (\Throwable $e) { echo json_encode(['ok'=>false, 'error'=>$e->getMessage()]); }
    exit;
}

log_user_action($conn, 'view_page', 'router_details.php#'.$nid);
$snap = nm_router_db_snapshot($conn, $node);

// asset / warranty helpers
$warranty = $node['warranty_expiry'] ?? null; $wStat = null; $wDays = null;
if ($warranty) {
    $wDays = (int)floor((strtotime($warranty) - time()) / 86400);
    $wStat = $wDays < 0 ? 'expired' : ($wDays <= 90 ? 'soon' : 'ok');
}
$KIND_META = [
    'router'  => ['ic'=>'fa-route','col'=>'#4da3ff','name'=>'Router'],
    'ping'    => ['ic'=>'fa-satellite-dish','col'=>'#36e3d0','name'=>'Ping Device'],
    'windows' => ['ic'=>'fa-window-maximize','col'=>'#3aa0ff','name'=>'Windows Host'],
    'linux'   => ['ic'=>'fa-server','col'=>'#f0b429','name'=>'Linux Host'],
    'snmp'    => ['ic'=>'fa-server','col'=>'#8a93a6','name'=>'SNMP Device'],
];
$km = $KIND_META[$kind] ?? $KIND_META['snmp'];
$lat = $snap['latency'];
$isUp = $lat ? ((int)$lat['is_up'] === 1) : null;
$canLive = ($kind === 'router');
$e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES);
include('header.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" media="print" onload="this.media='all'">
<noscript><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"></noscript>
<style>
:root{ --glass:rgba(12,16,26,.62); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cyan:#36e3d0; --purple:#c084fc; --kind:<?= $km['col'] ?>; }
html{ background:#05080f; }
/* canonical NEURU font stack (matches net_mon / win_screen / linux_screen) so type renders
   identically across the app — no font shift when navigating into this page. */
body{ margin:0; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; -webkit-font-smoothing:antialiased; text-rendering:optimizeLegibility; background:transparent !important; color:#d4dce8; overflow-x:hidden; }
<?= nm_chrome_css() ?>
.rd{ position:relative; max-width:1400px; margin:0 auto; padding:18px 20px 60px; }
.rd *{ box-sizing:border-box; }
.rd a{ color:inherit; }
.glass{ background:var(--glass); backdrop-filter:blur(13px); border:1px solid var(--border); border-radius:16px; }
.rd-hero{ display:flex; gap:20px; align-items:stretch; padding:18px; margin-bottom:16px; flex-wrap:wrap; }
.rd-photo{ width:190px; min-width:190px; height:150px; border-radius:12px; overflow:hidden; position:relative; flex:none;
  border:1px solid rgba(255,255,255,.14); background:radial-gradient(120px 90px at 50% 30%, rgba(77,163,255,.14), rgba(6,10,20,.6));
  display:flex; align-items:center; justify-content:center; box-shadow:0 8px 30px rgba(0,0,0,.4), inset 0 0 40px rgba(77,163,255,.05); }
.rd-photo img{ width:100%; height:100%; object-fit:cover; }
.rd-photo .ph-none{ color:var(--kind); font-size:46px; opacity:.5; }
.rd-photo .ph-scan{ position:absolute; inset:0; background:linear-gradient(0deg,transparent, rgba(77,163,255,.10) 50%, transparent); animation:scan 4s linear infinite; pointer-events:none; }
@keyframes scan{ 0%{transform:translateY(-100%)} 100%{transform:translateY(100%)} }
.rd-idc{ flex:1; min-width:260px; display:flex; flex-direction:column; justify-content:center; }
.rd-name{ font-size:26px; font-weight:800; letter-spacing:.3px; display:flex; align-items:center; gap:12px; }
.rd-name .kbadge{ font-size:12px; font-weight:700; padding:4px 11px; border-radius:20px; background:color-mix(in srgb, var(--kind) 18%, transparent); color:var(--kind); border:1px solid color-mix(in srgb, var(--kind) 45%, transparent); }
.rd-sub{ color:#8b95a7; font-size:13px; margin-top:5px; display:flex; gap:16px; flex-wrap:wrap; }
.rd-sub b{ color:#c7d0de; font-weight:600; }
.rd-quick{ display:flex; gap:10px; margin-top:14px; flex-wrap:wrap; }
.qv{ background:rgba(255,255,255,.03); border:1px solid var(--border); border-radius:11px; padding:9px 14px; min-width:104px; }
.qv .l{ font-size:9px; text-transform:uppercase; letter-spacing:.6px; color:#7d8697; }
.qv .v{ font-size:19px; font-weight:800; margin-top:3px; line-height:1; }
.qv .v.ok{ color:#4be08b; } .qv .v.crit{ color:#ff7a6e; } .qv .v.cyan{ color:var(--cyan); } .qv .v.warn{ color:#ffcf6b; }
.rd-actions{ display:flex; gap:8px; align-items:flex-start; flex-wrap:wrap; }
.rbtn{ background:rgba(77,163,255,.12); border:1px solid rgba(77,163,255,.4); color:#bcd8ff; border-radius:10px; padding:9px 13px; font-size:13px; cursor:pointer; text-decoration:none; display:inline-flex; align-items:center; gap:8px; white-space:nowrap; }
.rbtn:hover{ border-color:var(--accent); color:#fff; }
.rbtn.ghost{ background:rgba(255,255,255,.03); border-color:var(--border); color:#aeb8c7; }
.grid{ display:grid; grid-template-columns:repeat(12,1fr); gap:16px; }
.card{ padding:16px; }
.c6{ grid-column:span 6; } .c4{ grid-column:span 4; } .c8{ grid-column:span 8; } .c12{ grid-column:span 12; } .c3{ grid-column:span 3; }
@media(max-width:1000px){ .c6,.c4,.c8,.c3{ grid-column:span 12; } }
.ctitle{ font-size:12px; text-transform:uppercase; letter-spacing:.8px; color:#9db4d6; display:flex; align-items:center; gap:9px; margin-bottom:13px; }
.ctitle .sp{ margin-left:auto; font-size:11px; color:#6f7a8c; text-transform:none; letter-spacing:0; }
.kv{ display:grid; grid-template-columns:auto 1fr; gap:7px 14px; font-size:13px; }
.kv .k{ color:#7d8697; } .kv .v{ color:#dbe3ee; text-align:right; font-weight:600; word-break:break-word; }
.gauges{ display:flex; gap:16px; flex-wrap:wrap; justify-content:space-around; }
.gauge{ text-align:center; }
.ring{ --p:0; --gc:var(--accent); width:96px; height:96px; border-radius:50%; margin:0 auto;
  background:conic-gradient(var(--gc) calc(var(--p)*1%), rgba(255,255,255,.07) 0); display:flex; align-items:center; justify-content:center; position:relative; transition:background .6s ease; }
.ring::before{ content:''; position:absolute; inset:9px; border-radius:50%; background:#0a0e17; }
.ring .rv{ position:relative; font-size:19px; font-weight:800; color:#e6edf7; }
.gauge .gl{ margin-top:8px; font-size:11px; color:#8b95a7; text-transform:uppercase; letter-spacing:.5px; }
.gauge .gs{ font-size:11px; color:#6f7a8c; }
.cgrid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(110px,1fr)); gap:10px; }
.cstat{ background:rgba(255,255,255,.03); border:1px solid var(--border); border-radius:11px; padding:11px 12px; }
.cstat .n{ font-size:22px; font-weight:800; color:#e6edf7; line-height:1; } .cstat .n i{ font-size:14px; }
.cstat .l{ font-size:10px; color:#8b95a7; margin-top:5px; text-transform:uppercase; letter-spacing:.4px; }
.tbl{ width:100%; border-collapse:collapse; font-size:12.5px; }
.tbl th{ text-align:left; color:#8090a4; font-weight:600; font-size:10px; text-transform:uppercase; letter-spacing:.5px; padding:6px 8px; border-bottom:1px solid var(--border); }
.tbl td{ padding:7px 8px; border-bottom:1px solid rgba(255,255,255,.05); }
.tbl tr:hover td{ background:rgba(255,255,255,.02); }
.dot{ width:8px; height:8px; border-radius:50%; display:inline-block; box-shadow:0 0 7px currentColor; }
.pill{ font-size:10px; padding:2px 8px; border-radius:20px; background:rgba(255,255,255,.06); color:#c7d0de; }
.pill.up{ background:rgba(46,204,113,.16); color:#63e29b; } .pill.down{ background:rgba(231,76,60,.18); color:#ff8b80; }
.pill.expired{ background:rgba(231,76,60,.18); color:#ff8b80; } .pill.soon{ background:rgba(243,156,18,.18); color:#ffce6b; } .pill.ok{ background:rgba(46,204,113,.16); color:#63e29b; }
.inc{ border-left:3px solid #5a6577; background:rgba(255,255,255,.03); border-radius:8px; padding:9px 11px; margin-bottom:8px; }
.inc.critical{ border-left-color:#e74c3c; } .inc.high{ border-left-color:#ff7a45; } .inc.medium{ border-left-color:#f39c12; } .inc.low,.inc.info{ border-left-color:#4da3ff; }
.inc .t{ font-weight:600; font-size:13px; } .inc .m{ font-size:11px; color:#8b95a7; margin-top:3px; }
.spark{ display:flex; align-items:flex-end; gap:2px; height:46px; margin-top:8px; }
.spark i{ flex:1; min-height:2px; border-radius:2px 2px 0 0; background:var(--cyan); opacity:.85; }
.muted{ color:#6f7a8c; font-size:12.5px; }
.notes{ white-space:pre-wrap; font-size:12.5px; color:#c2ccd9; line-height:1.5; }
#live-loader{ display:flex; align-items:center; gap:12px; color:#9db4d6; font-size:13px; }
#live-loader .spin{ width:16px; height:16px; border:2px solid rgba(77,163,255,.25); border-top-color:var(--accent); border-radius:50%; animation:sp 0.8s linear infinite; }
@keyframes sp{ to{ transform:rotate(360deg) } }
.livewrap.off{ opacity:.6; }
/* WebGL traffic hologram */
#holo{ background:radial-gradient(900px 500px at 50% 25%, rgba(60,90,170,.14), rgba(6,10,20,.4) 70%); }
#rtr-canvas{ position:absolute; inset:0; width:100%; height:100%; display:block; }
.holo-hud{ position:absolute; z-index:5; pointer-events:none; font-size:12px; }
.holo-tl{ top:14px; left:16px; max-width:60%; } .ht-title{ font-size:15px; font-weight:800; display:flex; align-items:center; gap:9px; } .ht-sub{ color:#9fb0c4; font-size:11.5px; margin-top:3px; line-height:1.4; }
.holo-tr{ top:12px; right:16px; display:flex; gap:16px; background:rgba(9,13,24,.5); backdrop-filter:blur(8px); border:1px solid var(--border); border-radius:12px; padding:9px 15px; }
.holo-tr .tot{ text-align:center; } .holo-tr .tl{ font-size:8.5px; color:#8b95a7; letter-spacing:.5px; display:block; } .holo-tr b{ font-size:16px; } .holo-tr .cy{ color:var(--cyan); } .holo-tr .am{ color:#ffb454; }
.holo-br{ bottom:12px; right:16px; display:flex; gap:14px; align-items:center; color:#9fb0c4; }
.holo-br .dot{ width:9px; height:9px; border-radius:50%; display:inline-block; margin-right:5px; box-shadow:0 0 7px currentColor; }
.holo-detail{ left:16px; bottom:46px; width:292px; background:rgba(9,13,24,.74); backdrop-filter:blur(12px); border:1px solid var(--border); border-radius:12px; padding:11px 13px; pointer-events:auto; box-shadow:0 10px 34px rgba(0,0,0,.45); }
.pd-head{ display:flex; align-items:center; gap:8px; font-weight:800; font-size:14px; } .pd-head .pd-x{ margin-left:auto; cursor:pointer; color:#9aa3af; } .pd-head .pd-x:hover{ color:#fff; }
.pd-meta{ font-size:11px; color:#8b95a7; margin-top:4px; }
.pd-now{ display:flex; gap:20px; margin:9px 0 6px; } .pd-now .pl{ font-size:8.5px; letter-spacing:.5px; display:block; color:#8b95a7; } .pd-now b{ font-size:15px; font-variant-numeric:tabular-nums; } .pd-now .cy{ color:var(--cyan);} .pd-now .am{ color:#ffb454; }
#pd-spark{ width:100%; height:64px; display:block; border-radius:6px; background:rgba(0,0,0,.2); }
.pd-hint{ font-size:9px; color:#6f7a8c; margin-top:5px; text-align:right; }
.holo-detail .badge{ font-size:8.5px; padding:2px 7px; border-radius:20px; } .badge.up{ background:rgba(46,204,113,.18); color:#7fe0a3;} .badge.down{ background:rgba(231,76,60,.2); color:#ff9b91;} .badge.off{ background:rgba(255,255,255,.1); color:#9aa;}
.holo-loader{ position:absolute; inset:0; z-index:6; display:flex; align-items:center; justify-content:center; gap:12px; color:#9db4d6; font-size:13px; background:rgba(6,10,20,.35); }
.holo-loader .spin{ width:18px; height:18px; border:2px solid rgba(77,163,255,.25); border-top-color:var(--accent); border-radius:50%; animation:sp .8s linear infinite; }
.holo-fallback{ position:absolute; inset:0; z-index:4; overflow:auto; padding:64px 18px 18px; }
.nfbar{ display:flex; align-items:center; gap:9px; margin-bottom:7px; font-size:12.5px; }
.nfbar .nm{ min-width:92px; color:#dbe3ee; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.nfbar .track{ flex:1; height:8px; background:rgba(255,255,255,.06); border-radius:5px; overflow:hidden; } .nfbar .track>i{ display:block; height:100%; border-radius:5px; background:linear-gradient(90deg,var(--accent),var(--cyan)); }
.nfbar .val{ min-width:70px; text-align:right; color:#9fb0c4; font-variant-numeric:tabular-nums; }
</style>

<div class="rd">
  <!-- HERO -->
  <div class="rd-hero glass">
    <div class="rd-photo">
      <?php if (!empty($node['photo_url'])): ?><img src="<?= $e($node['photo_url']) ?>" alt="equipment"><?php else: ?><i class="fa-solid <?= $km['ic'] ?> ph-none"></i><?php endif; ?>
      <div class="ph-scan"></div>
    </div>
    <div class="rd-idc">
      <div class="rd-name"><i class="fa-solid <?= $km['ic'] ?>" style="color:var(--kind)"></i> <?= $e($node['display_name']) ?>
        <span class="kbadge"><?= $e($km['name']) ?></span>
        <?php if (!empty($node['grp_name'])): ?><span class="pill" style="background:<?= $e($node['grp_color'] ?: '#4da3ff') ?>22;color:<?= $e($node['grp_color'] ?: '#9db4d6') ?>"><?= $e($node['grp_name']) ?></span><?php endif; ?>
      </div>
      <div class="rd-sub">
        <span><b><?= $e($node['ip_address'] ?: '—') ?></b></span>
        <?php if (!empty($node['hostname'])): ?><span>host <b><?= $e($node['hostname']) ?></b></span><?php endif; ?>
        <?php if (!empty($node['hw_model'])): ?><span title="SNMP sysDescr"><b><?= $e(mb_strimwidth($node['hw_model'],0,60,'…')) ?></b></span><?php endif; ?>
        <span>monitor <b><?= $e($node['monitor_type'] ?: 'snmp') ?></b></span>
      </div>
      <div class="rd-quick">
        <div class="qv"><div class="l">Reachability</div><div class="v <?= $isUp===true?'ok':($isUp===false?'crit':'') ?>"><?= $isUp===true?'UP':($isUp===false?'DOWN':'—') ?></div></div>
        <div class="qv"><div class="l">Latency</div><div class="v cyan"><?= $lat && $lat['latency_ms']!==null ? round((float)$lat['latency_ms'],2).' ms' : '—' ?></div></div>
        <div class="qv"><div class="l">Loss</div><div class="v <?= $lat && (float)($lat['packet_loss']??0)>0?'warn':'' ?>"><?= $lat && $lat['packet_loss']!==null ? round((float)$lat['packet_loss']).'%' : '—' ?></div></div>
        <div class="qv"><div class="l">24h Uptime</div><div class="v <?= $snap['uptime24']!==null ? ($snap['uptime24']>=99.5?'ok':($snap['uptime24']>=95?'warn':'crit')) : '' ?>"><?= $snap['uptime24']!==null ? $snap['uptime24'].'%' : '—' ?></div></div>
        <div class="qv"><div class="l">Open Incidents</div><div class="v <?= count($snap['incidents'])?'crit':'ok' ?>"><?= count($snap['incidents']) ?></div></div>
      </div>
    </div>
    <div class="rd-actions">
      <?php if ($kind==='router'): ?><a class="rbtn" href="routers.php"><i class="fa-solid fa-route"></i> Router Monitor</a><?php else: ?><a class="rbtn" href="net_mon.php"><i class="fa-solid fa-chart-line"></i> Dashboard</a><?php endif; ?>
      <a class="rbtn ghost" href="net_mon_stats.php?node=<?= $nid ?>" target="_blank"><i class="fa-solid fa-chart-bar"></i> Statistics</a>
      <?php if ($kind==='router'): ?><a class="rbtn ghost" href="router_commander.php?node=<?= $nid ?>&host=<?= $e($node['ip_address']) ?>" target="_blank"><i class="fa-solid fa-terminal"></i> Commander</a><?php endif; ?>
      <a class="rbtn ghost" href="config_mgr.php" target="_blank"><i class="fa-solid fa-file-shield"></i> Config</a>
    </div>
  </div>

  <div class="grid">
    <!-- WebGL traffic hologram (router only) -->
    <?php if ($canLive): ?>
    <div class="glass c12" id="holo" style="padding:0;position:relative;overflow:hidden;min-height:430px;">
      <canvas id="rtr-canvas"></canvas>
      <div class="holo-hud holo-tl">
        <div class="ht-title"><i class="fa-solid fa-diagram-project" style="color:var(--kind)"></i> Live Traffic Hologram</div>
        <div class="ht-sub">Each port streams real throughput — cyan in, amber out. A dead link goes red &amp; still; a fat pipe glows.</div>
      </div>
      <div class="holo-hud holo-tr" id="holo-tot">
        <div class="tot"><span class="tl">▼ IN</span><b id="tot-rx" class="cy">—</b></div>
        <div class="tot"><span class="tl">▲ OUT</span><b id="tot-tx" class="am">—</b></div>
        <div class="tot"><span class="tl">PORTS</span><b id="tot-if">—</b></div>
      </div>
      <div class="holo-hud holo-br" id="holo-legend">
        <span><i class="dot" style="background:#36e3d0"></i> inbound</span>
        <span><i class="dot" style="background:#ffb454"></i> outbound</span>
        <span><i class="dot" style="background:#e74c3c"></i> down</span>
        <span id="holo-when" style="opacity:.6"></span>
      </div>
      <div class="holo-hud holo-detail" id="port-detail" style="display:none;">
        <div class="pd-head"><i class="fa-solid fa-ethernet" style="color:var(--kind)"></i><span id="pd-name">—</span> <span class="badge" id="pd-state"></span><i class="fa-solid fa-xmark pd-x" onclick="closePort()"></i></div>
        <div class="pd-meta" id="pd-meta"></div>
        <div class="pd-now"><div><span class="pl">▼ IN</span><b id="pd-rx" class="cy">—</b></div><div><span class="pl">▲ OUT</span><b id="pd-tx" class="am">—</b></div><div><span class="pl">PEAK</span><b id="pd-peak">—</b></div></div>
        <canvas id="pd-spark" width="264" height="64"></canvas>
        <div class="pd-hint">live · cyan in / amber out</div>
      </div>
      <div id="holo-loader" class="holo-loader"><div class="spin"></div> <span id="holo-msg">sampling live interface counters…</span></div>
      <div id="holo-fallback" class="holo-fallback" style="display:none"></div>
    </div>
    <?php endif; ?>

    <!-- LIVE panels (router only) -->
    <?php if ($canLive): ?>
    <div class="glass card c12 livewrap" id="livewrap">
      <div class="ctitle"><i class="fa-solid fa-satellite-dish" style="color:var(--kind)"></i> Live RouterOS Telemetry <span class="sp" id="live-when"></span></div>
      <div id="live-loader"><div class="spin"></div> <span id="live-msg">Establishing secure SSH channel…</span></div>
      <div id="live-body" style="display:none">
        <div class="grid" style="gap:16px">
          <div class="c4"><div class="ctitle" style="margin-bottom:9px"><i class="fa-solid fa-microchip"></i> Resources</div><div class="gauges" id="g-res"></div></div>
          <div class="c4"><div class="ctitle" style="margin-bottom:9px"><i class="fa-solid fa-id-card"></i> Identity</div><div class="kv" id="g-ident"></div></div>
          <div class="c4"><div class="ctitle" style="margin-bottom:9px"><i class="fa-solid fa-layer-group"></i> Footprint</div><div class="cgrid" id="g-counts"></div></div>
          <div class="c12"><div class="ctitle" style="margin-bottom:9px"><i class="fa-solid fa-ethernet"></i> Interfaces <span class="sp" id="if-count"></span></div><div style="overflow:auto"><table class="tbl" id="g-ifaces"></table></div></div>
        </div>
      </div>
      <div id="live-err" style="display:none" class="muted"></div>
    </div>
    <?php endif; ?>

    <!-- Asset / Inventory -->
    <div class="glass card c6">
      <div class="ctitle"><i class="fa-solid fa-box-archive"></i> Asset / Inventory
        <a class="sp" href="net_mon_config.php?tab=nodes" style="color:#6f7a8c;text-decoration:none" title="Edit in Configuration">edit ›</a></div>
      <?php
        $assetRows = [
          'Manufacturer' => $node['manufacturer'] ?? '', 'Model' => $node['model'] ?? '',
          'Serial number' => $node['serial_number'] ?? '', 'Asset tag' => $node['asset_tag'] ?? '',
          'Purchase date' => $node['purchase_date'] ?? '',
        ];
        $anyAsset = false; foreach ($assetRows as $v) if (trim((string)$v) !== '') { $anyAsset = true; break; }
        if ($warranty) $anyAsset = true;
      ?>
      <?php if ($anyAsset || !empty($node['asset_notes'])): ?>
      <div class="kv">
        <?php foreach ($assetRows as $k=>$v): if (trim((string)$v)==='') continue; ?>
        <div class="k"><?= $e($k) ?></div><div class="v"><?= $e($v) ?></div>
        <?php endforeach; ?>
        <?php if ($warranty): ?>
        <div class="k">Warranty</div><div class="v"><?= $e($warranty) ?> <span class="pill <?= $wStat ?>"><?= $wStat==='expired'?('expired '.abs($wDays).'d ago'):($wStat==='soon'?($wDays.'d left'):'in warranty') ?></span></div>
        <?php endif; ?>
      </div>
      <?php if (!empty($node['asset_notes'])): ?><div class="notes" style="margin-top:12px;border-top:1px dashed var(--border);padding-top:10px"><?= $e($node['asset_notes']) ?></div><?php endif; ?>
      <?php else: ?>
      <div class="muted">No asset details yet. Add model, serial, warranty &amp; an equipment photo in <a href="net_mon_config.php?tab=nodes" style="color:var(--accent)">Configuration → Nodes</a>.</div>
      <?php endif; ?>
    </div>

    <!-- Reachability / latency -->
    <div class="glass card c6">
      <div class="ctitle"><i class="fa-solid fa-wave-square"></i> Reachability <span class="sp">last <?= count($snap['trend']) ?> samples</span></div>
      <?php if ($snap['trend']): ?>
        <?php $mx = 1; foreach ($snap['trend'] as $t) $mx = max($mx, (float)($t['latency_ms']??0)); ?>
        <div class="spark">
          <?php foreach ($snap['trend'] as $t): $h = $mx>0 ? round((float)($t['latency_ms']??0)/$mx*44) : 2; $c = ((int)($t['is_up']??0)!==1)?'#e74c3c':((float)($t['packet_loss']??0)>0?'#f39c12':'#36e3d0'); ?>
          <i style="height:<?= max(2,$h) ?>px;background:<?= $c ?>" title="<?= $e($t['recorded_at']??'') ?> · <?= $t['latency_ms']!==null?round((float)$t['latency_ms'],2).'ms':'—' ?>"></i>
          <?php endforeach; ?>
        </div>
        <div class="muted" style="margin-top:8px">Peak <?= round($mx,2) ?> ms · <?= $snap['uptime24']!==null?('24h availability '.$snap['uptime24'].'%'):'no 24h data' ?></div>
      <?php else: ?><div class="muted">No ping history yet for this node.</div><?php endif; ?>
      <?php if ($snap['metrics']): ?>
      <div class="kv" style="margin-top:14px">
        <?php foreach ($snap['metrics'] as $m=>$row): ?>
        <div class="k"><?= $e(ucwords(str_replace('_',' ',$m))) ?></div><div class="v"><?= $e(round((float)$row['value'],2)) ?></div>
        <?php endforeach; ?>
      </div>
      <?php endif; ?>
    </div>

    <!-- Incidents -->
    <div class="glass card c6">
      <div class="ctitle"><i class="fa-solid fa-triangle-exclamation"></i> Open Incidents <span class="sp"><?= count($snap['incidents']) ?></span></div>
      <?php if ($snap['incidents']): foreach ($snap['incidents'] as $i): ?>
        <div class="inc <?= $e($i['severity']) ?>">
          <div class="t"><?= $e($i['title']) ?></div>
          <div class="m"><?= $e(ucfirst($i['severity'])) ?> · <?= $e($i['status']) ?> · opened <?= $e($i['opened_at']) ?> · <?= (int)$i['signal_count'] ?> signal(s)</div>
        </div>
      <?php endforeach; else: ?>
        <div class="muted"><i class="fa-solid fa-circle-check" style="color:var(--ok)"></i> No open incidents — device is clean.</div>
      <?php endif; ?>
      <a class="rbtn ghost" style="margin-top:6px" href="incidents.php" target="_blank"><i class="fa-solid fa-list"></i> Incident Command</a>
    </div>

    <!-- Configured interfaces (DB) -->
    <div class="glass card c6">
      <div class="ctitle"><i class="fa-solid fa-network-wired"></i> Interfaces (monitored) <span class="sp"><?= count($snap['interfaces']) ?></span></div>
      <?php if ($snap['interfaces']): ?>
      <div style="overflow:auto;max-height:320px">
        <table class="tbl">
          <thead><tr><th>Name</th><th>Alias</th><th>IP</th><th>Idx</th></tr></thead>
          <tbody>
          <?php foreach ($snap['interfaces'] as $if): ?>
            <tr><td><?= $e($if['display_name'] ?: $if['if_name']) ?></td><td class="muted"><?= $e($if['if_alias']) ?></td><td><?= $e($if['if_ip_address']) ?></td><td class="muted"><?= $e($if['if_index']) ?></td></tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php else: ?><div class="muted">No monitored interfaces. <?= $kind==='ping'?'This is a ping-only device.':'Run a poll or enable SNMP to discover interfaces.' ?></div><?php endif; ?>
    </div>

    <!-- NetFlow (if this router exports flows) -->
    <?php if ($kind==='router'): ?>
    <div class="glass card c12" id="nfwrap" style="display:none">
      <div class="ctitle"><i class="fa-solid fa-chart-area" style="color:var(--kind)"></i> NetFlow — what's flowing through here <span class="sp">last 60 min</span></div>
      <div class="grid" style="gap:16px">
        <div class="c6"><div class="ctitle" style="margin-bottom:9px"><i class="fa-solid fa-layer-group"></i> Top applications</div><div id="nf-apps"></div></div>
        <div class="c6"><div class="ctitle" style="margin-bottom:9px"><i class="fa-solid fa-users"></i> Top talkers</div><div id="nf-talkers"></div></div>
      </div>
      <a class="rbtn ghost" style="margin-top:10px" href="netflow.php" target="_blank"><i class="fa-solid fa-chart-area"></i> Full NetFlow Analyzer</a>
    </div>
    <?php endif; ?>
  </div>
</div>

<?php if ($canLive): ?>
<script src="three.min.js"></script>
<script src="three-orbitcontrols.js"></script>
<?php endif; ?>
<script>
const RD_NODE = <?= $nid ?>, RD_CAN_LIVE = <?= $canLive ? 'true':'false' ?>, RD_KIND = '<?= $e($kind) ?>';
const KIND_COL = 0x<?= sprintf('%06x', hexdec(ltrim($km['col'],'#'))) ?>;
const esc = s => String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function fmtbps(b){ b=+b||0; if(b>=1e9)return (b/1e9).toFixed(2)+' Gbps'; if(b>=1e6)return (b/1e6).toFixed(1)+' Mbps'; if(b>=1e3)return (b/1e3).toFixed(0)+' kbps'; return Math.round(b)+' bps'; }
function fmtBytes(b){ if(b==null) return '—'; const u=['B','KB','MB','GB','TB']; let i=0; b=+b; while(b>=1024&&i<u.length-1){b/=1024;i++;} return (b<10&&i>0?b.toFixed(1):Math.round(b))+' '+u[i]; }
function ring(pct, val, label, sub, color){ pct=Math.max(0,Math.min(100,+pct||0));
  const gc = color || (pct>=90?'#e74c3c':pct>=75?'#f39c12':'#4da3ff');
  return `<div class="gauge"><div class="ring" style="--p:${pct};--gc:${gc}"><div class="rv">${val}</div></div><div class="gl">${esc(label)}</div>${sub?`<div class="gs">${esc(sub)}</div>`:''}</div>`; }

const LOAD_MSGS = ['Establishing secure SSH channel…','Reading /system resource…','Enumerating interfaces…','Counting routes, leases &amp; firewall…','Compiling live dossier…'];
let msgIx = 0, msgTimer = null;
function cycleMsgs(){ const el=document.getElementById('live-msg'); if(!el) return;
  msgTimer=setInterval(()=>{ msgIx=(msgIx+1)%LOAD_MSGS.length; el.innerHTML=LOAD_MSGS[msgIx]; }, 1600); }

async function loadLive(){
  if(!RD_CAN_LIVE) return; cycleMsgs();
  let d=null, err='';
  try{ const r=await fetch('router_details.php?api=live&node='+RD_NODE+'&_='+Date.now()); const txt=await r.text(); try{ d=JSON.parse(txt); }catch(pe){ err='HTTP '+r.status+' · '+txt.slice(0,180); } }
  catch(ex){ err='network: '+(ex&&ex.message||ex); }
  clearInterval(msgTimer);
  const loader=document.getElementById('live-loader'); loader.style.display='none';
  if(!d || !d.ok){ document.getElementById('livewrap').classList.add('off');
    const eb=document.getElementById('live-err'); eb.style.display='block';
    eb.innerHTML='<i class="fa-solid fa-plug-circle-xmark" style="color:#f39c12"></i> Live SSH telemetry unavailable — '+esc((d&&d.error)||err||'unknown')+'.<br><span style="color:#6f7a8c">The monitored data above is still live. Add/verify an SSH credential in <a href="config_mgr.php" style="color:#4da3ff">Config Manager</a> to unlock RouterOS telemetry.</span>';
    return; }
  renderLive(d.data);
  document.getElementById('live-body').style.display='block';
  const w=document.getElementById('live-when'); if(w) w.textContent='updated '+new Date().toLocaleTimeString();
}

function renderLive(D){
  const R=D.resources||{}, I=D.identity||{}, C=D.counts||{};
  // resource gauges
  const g=[];
  if(R.cpu_load!=null) g.push(ring(R.cpu_load, Math.round(R.cpu_load)+'%', 'CPU', (R.cpu_count?R.cpu_count+' core':'')+(R.cpu_freq?' · '+Math.round(R.cpu_freq)+'MHz':'')));
  if(R.mem_used_pct!=null) g.push(ring(R.mem_used_pct, Math.round(R.mem_used_pct)+'%', 'Memory', fmtBytes(R.mem_total-R.mem_free)+' / '+fmtBytes(R.mem_total)));
  if(R.hdd_used_pct!=null) g.push(ring(R.hdd_used_pct, Math.round(R.hdd_used_pct)+'%', 'Storage', fmtBytes(R.hdd_total-R.hdd_free)+' / '+fmtBytes(R.hdd_total)));
  if(R.temp!=null) g.push(ring(Math.min(100,R.temp), Math.round(R.temp)+'°', 'Temp', R.voltage!=null?(R.voltage+' V'):'', R.temp>=65?'#e74c3c':R.temp>=55?'#f39c12':'#36e3d0'));
  document.getElementById('g-res').innerHTML = g.join('') || '<div class="muted">No resource data.</div>';
  // identity
  const idRows=[['Model',I.model],['Serial',I.serial],['Board',I.board],['RouterOS',I.version],['Firmware',I.firmware],['Arch',I.arch],['Uptime',I.uptime],['Platform',I.platform]];
  document.getElementById('g-ident').innerHTML = idRows.filter(r=>r[1]).map(r=>`<div class="k">${esc(r[0])}</div><div class="v">${esc(r[1])}</div>`).join('') || '<div class="muted">—</div>';
  // counts
  const cDefs=[['routes','Routes','fa-route'],['addresses','IP Addrs','fa-location-dot'],['leases_bound','DHCP Leases','fa-address-card'],['fw_filter','FW Filter','fa-shield'],['fw_nat','NAT Rules','fa-right-left'],['fw_addrlist','Addr-Lists','fa-list'],['wifi_clients','WiFi','fa-wifi'],['capsman_clients','CAPsMAN','fa-tower-broadcast'],['ppp_active','PPP','fa-user-check'],['neighbors','Neighbors','fa-diagram-project'],['active_users','Admins on','fa-user-shield']];
  document.getElementById('g-counts').innerHTML = cDefs.filter(d=>C[d[0]]!=null).map(d=>`<div class="cstat"><div class="n"><i class="fa-solid ${d[2]}" style="color:#6f8bb5"></i> ${C[d[0]]}</div><div class="l">${esc(d[1])}</div></div>`).join('') || '<div class="muted">—</div>';
  // interfaces
  const ifs=D.interfaces||[];
  document.getElementById('if-count').textContent = ifs.length+' total · '+ifs.filter(x=>x.running).length+' up';
  const t=document.getElementById('g-ifaces');
  t.innerHTML = '<thead><tr><th></th><th>Name</th><th>Type</th><th>RX</th><th>TX</th><th>Comment</th></tr></thead><tbody>'+
    ifs.map(x=>{ const col=x.disabled?'#6f7a8c':(x.running?'#2ecc71':'#e74c3c');
      return `<tr><td><span class="dot" style="color:${col}"></span></td><td>${esc(x.name)}</td><td class="muted">${esc(x.type)}</td><td>${fmtBytes(x.rx)}</td><td>${fmtBytes(x.tx)}</td><td class="muted">${esc(x.comment)}</td></tr>`; }).join('')+'</tbody>';
}

// ═══════════════ WebGL TRAFFIC HOLOGRAM ═══════════════
// The router = a glowing core; each interface = a port on a ring; real per-interface
// throughput drives particle streams (cyan in / amber out). Down port → red, still.
let H={}; // scene state
const GAL_VS=`attribute vec3 aColor; attribute float aSize; attribute float aAlpha; varying vec3 vC; varying float vA;
  void main(){ vC=aColor; vA=aAlpha; vec4 mv=modelViewMatrix*vec4(position,1.0); gl_PointSize=aSize*(300.0/max(1.0,-mv.z)); gl_Position=projectionMatrix*mv; }`;
const GAL_FS=`varying vec3 vC; varying float vA; void main(){ float d=length(gl_PointCoord-vec2(0.5)); if(d>0.5) discard;
  float c=smoothstep(0.5,0.0,d); gl_FragColor=vec4(mix(vC*1.7,vec3(1.0),pow(c,3.0)*0.5), c*vA); }`;
function lbps(b){ return Math.log10(1+Math.max(0,+b||0)); }   // 0..~10 log scale

function holoInit(){
  const stage=document.getElementById('holo'), canvas=document.getElementById('rtr-canvas');
  let ok=false; try{ const c=document.createElement('canvas'); ok=!!(window.WebGLRenderingContext&&(c.getContext('webgl')||c.getContext('experimental-webgl'))); }catch(e){}
  if(!ok || typeof THREE==='undefined'){ document.getElementById('holo-loader').style.display='none'; document.getElementById('holo-fallback').style.display='block'; H.dead=true; return; }
  const renderer=new THREE.WebGLRenderer({canvas,antialias:true,alpha:true}); renderer.setClearColor(0x000000,0);
  const scene=new THREE.Scene(); scene.fog=new THREE.FogExp2(0x05080f,0.0016);
  const camera=new THREE.PerspectiveCamera(52,1,0.1,4000); camera.position.set(0,90,260);
  const controls=new THREE.OrbitControls(camera,renderer.domElement); controls.enableDamping=true; controls.dampingFactor=.08;
  controls.autoRotate=true; controls.autoRotateSpeed=.5; controls.minDistance=90; controls.maxDistance=900; controls.enablePan=false;
  scene.add(new THREE.AmbientLight(0x8899cc,0.9)); const key=new THREE.PointLight(0xafc4ff,0.7,0); key.position.set(200,300,300); scene.add(key);
  // core
  const coreGeo=new THREE.IcosahedronGeometry(20,2);
  const core=new THREE.Mesh(coreGeo,new THREE.MeshStandardMaterial({color:KIND_COL,emissive:KIND_COL,emissiveIntensity:.9,roughness:.3,metalness:.4,flatShading:true}));
  scene.add(core);
  const halo=new THREE.Mesh(new THREE.SphereGeometry(30,24,24),new THREE.MeshBasicMaterial({color:KIND_COL,transparent:true,opacity:.09,blending:THREE.AdditiveBlending,depthWrite:false})); scene.add(halo);
  const gPorts=new THREE.Group(), gFlows=new THREE.Group(), gLabels=new THREE.Group(); scene.add(gFlows); scene.add(gPorts); scene.add(gLabels);
  H={renderer,scene,camera,controls,stage,canvas,core,halo,gPorts,gFlows,gLabels,ports:{},hist:{},sel:null,lastIfs:[],t:0,last:performance.now(),hidden:false};
  // selection ring (billboarded, pulsing) marks the port you clicked
  const selRing=new THREE.Mesh(new THREE.TorusGeometry(11,0.7,10,40),new THREE.MeshBasicMaterial({color:0xffffff,transparent:true,opacity:.85,blending:THREE.AdditiveBlending,depthWrite:false}));
  selRing.visible=false; scene.add(selRing); H.selRing=selRing;
  // click a port → drill into that interface's live traffic
  const ray=new THREE.Raycaster(); const mouse=new THREE.Vector2();
  function pick(ev){ const r=canvas.getBoundingClientRect(); mouse.x=((ev.clientX-r.left)/r.width)*2-1; mouse.y=-((ev.clientY-r.top)/r.height)*2+1; ray.setFromCamera(mouse,camera); return ray.intersectObjects(gPorts.children,false); }
  canvas.addEventListener('click',ev=>{ const hit=pick(ev); if(hit.length&&hit[0].object.userData&&hit[0].object.userData.name) selectPort(hit[0].object.userData.name); });
  canvas.addEventListener('mousemove',ev=>{ canvas.style.cursor=pick(ev).length?'pointer':'grab'; });
  function resize(){ const w=stage.clientWidth,h=stage.clientHeight||430; renderer.setPixelRatio(Math.min(devicePixelRatio||1,2)); renderer.setSize(w,h,false); camera.aspect=w/h; camera.updateProjectionMatrix(); }
  resize(); window.addEventListener('resize',resize);
  document.addEventListener('visibilitychange',()=>{ H.hidden=document.hidden; if(!H.hidden)H.last=performance.now(); });
  animate();
}
function selectPort(name){ H.sel=name; const p=H.ports[name]; if(p&&H.selRing){ H.selRing.position.copy(p.node.position); H.selRing.visible=true; }
  if(!H.hist[name]) H.hist[name]=[]; document.getElementById('port-detail').style.display='block'; renderPortDetail(); }
function closePort(){ H.sel=null; if(H.selRing)H.selRing.visible=false; document.getElementById('port-detail').style.display='none'; }
function renderPortDetail(){ if(!H.sel) return; const f=(H.lastIfs||[]).find(x=>x.name===H.sel);
  document.getElementById('pd-name').textContent=H.sel;
  const st=document.getElementById('pd-state');
  if(!f){ st.className='badge off'; st.textContent='n/a'; } else { st.className='badge '+(f.disabled?'off':(f.running?'up':'down')); st.textContent=f.disabled?'disabled':(f.running?'up':'down'); }
  document.getElementById('pd-meta').textContent=f?((f.type||'interface')):'';
  document.getElementById('pd-rx').textContent=f?fmtbps(f.rx_bps):'—';
  document.getElementById('pd-tx').textContent=f?fmtbps(f.tx_bps):'—';
  const hist=H.hist[H.sel]||[]; const peak=Math.max(0,...hist.map(h=>Math.max(h.rx,h.tx)));
  document.getElementById('pd-peak').textContent=hist.length?fmtbps(peak):'—';
  drawSpark(document.getElementById('pd-spark'), hist); }
function drawSpark(cv,hist){ const ctx=cv.getContext('2d'),W=cv.width,Hh=cv.height; ctx.clearRect(0,0,W,Hh);
  if(!hist.length){ ctx.fillStyle='#6f7a8c'; ctx.font='11px Segoe UI'; ctx.fillText('collecting samples…',8,Hh/2); return; }
  const mx=Math.max(1,...hist.map(h=>Math.max(h.rx,h.tx))), n=hist.length, step=W/Math.max(1,n-1);
  const line=(key,color)=>{ ctx.beginPath(); hist.forEach((h,i)=>{ const x=i*step,y=Hh-3-(h[key]/mx)*(Hh-8); i?ctx.lineTo(x,y):ctx.moveTo(x,y); });
    ctx.strokeStyle=color; ctx.lineWidth=1.7; ctx.stroke();
    ctx.lineTo((n-1)*step,Hh); ctx.lineTo(0,Hh); ctx.closePath(); const g=ctx.createLinearGradient(0,0,0,Hh); g.addColorStop(0,color+'55'); g.addColorStop(1,color+'00'); ctx.fillStyle=g; ctx.fill(); };
  line('rx','#36e3d0'); line('tx','#ffb454'); }
function labelSprite(text,color){ const c=document.createElement('canvas'),x=c.getContext('2d'),f=34;
  x.font=`600 ${f}px Segoe UI`; const w=Math.ceil(x.measureText(text).width)+16; c.width=w; c.height=f+12;
  x.font=`600 ${f}px Segoe UI`; x.fillStyle='rgba(6,10,20,.5)'; x.fillRect(0,0,w,c.height); x.fillStyle=color||'#dfe7f2'; x.textBaseline='middle'; x.fillText(text,8,c.height/2);
  const tx=new THREE.CanvasTexture(c); tx.minFilter=THREE.LinearFilter;
  const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:tx,transparent:true,depthWrite:false})); sp.scale.set(w*0.16,c.height*0.16,1); return sp; }

function holoBuild(ifs){
  if(H.dead) return;
  // keep meaningful ports: not disabled; cap to 18 busiest/named
  const list=ifs.filter(f=>!f.disabled).slice(0,18);
  [H.gPorts,H.gFlows,H.gLabels].forEach(g=>{ while(g.children.length){ const c=g.children[0]; g.remove(c); if(c.geometry)c.geometry.dispose(); } });
  H.ports={};
  const n=list.length||1, R=95;
  list.forEach((f,i)=>{ const a=(i/n)*Math.PI*2; const pos=new THREE.Vector3(Math.cos(a)*R,(i%2?12:-12),Math.sin(a)*R);
    const up=f.running, col=up?0x2ee6a0:0xe74c3c;
    const node=new THREE.Mesh(new THREE.OctahedronGeometry(6,0),new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:.8,flatShading:true,roughness:.4}));
    node.position.copy(pos); node.userData=f; H.gPorts.add(node);
    // curve core→port
    const mid=pos.clone().multiplyScalar(0.5); mid.y+=26;
    const curve=new THREE.QuadraticBezierCurve3(new THREE.Vector3(0,0,0),mid,pos);
    const line=new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(24)),new THREE.LineBasicMaterial({color:up?0x2a3a5a:0x5a2530,transparent:true,opacity:.35})); H.gFlows.add(line);
    // two particle streams: rx (inbound, cyan) + tx (outbound, amber)
    const mk=(hex)=>{ const P=22,g=new THREE.BufferGeometry(),pp=new Float32Array(P*3); g.setAttribute('position',new THREE.BufferAttribute(pp,3));
      const m=new THREE.PointsMaterial({color:hex,size:5,transparent:true,opacity:.95,blending:THREE.AdditiveBlending,depthWrite:false}); const pts=new THREE.Points(g,m); H.gFlows.add(pts); return {pts,pp,P}; };
    const rx=mk(0x36e3d0), tx=mk(0xffb454);
    const lab=labelSprite(f.name,up?'#cfe0ff':'#ff9b91'); lab.position.copy(pos).add(new THREE.Vector3(0,12,0)); H.gLabels.add(lab);
    H.ports[f.name]={node,curve,rx,tx,phase:Math.random(),f,up};
  });
  document.getElementById('holo-loader').style.display='none';
  H.built=true;
}
function holoUpdate(ifs){ if(H.dead||!H.built) return;
  ifs.forEach(f=>{ const p=H.ports[f.name]; if(!p)return; p.f=f; p.up=f.running;
    const col=f.running?0x2ee6a0:0xe74c3c; p.node.material.color.setHex(col); p.node.material.emissive.setHex(col);
    const load=lbps(f.rx_bps+f.tx_bps); p.node.scale.setScalar(0.8+Math.min(2.2,load*0.28));   // fat pipe = big node
  });
}
function animate(){ requestAnimationFrame(animate); if(H.dead||H.hidden) return;
  const now=performance.now(), dt=Math.min(0.05,(now-H.last)/1000); H.last=now;
  H.t+=dt; H.controls.update();
  const s=1+Math.sin(H.t*2.2)*0.03; H.core.scale.setScalar(s); H.core.material.emissiveIntensity=0.7+Math.sin(H.t*2.2)*0.3;
  H.core.rotation.y+=dt*0.25; H.core.rotation.x+=dt*0.1; H.halo.scale.setScalar(1+Math.sin(H.t*1.6)*0.05);
  Object.values(H.ports).forEach(p=>{
    const rxb=+p.f.rx_bps||0, txb=+p.f.tx_bps||0;
    const rxSpeed=p.up?(0.05+lbps(rxb)*0.12):0, txSpeed=p.up?(0.05+lbps(txb)*0.12):0;
    const flow=(stream,speed,dir,active)=>{ if(!stream)return; const vis=active&&speed>0.051; stream.pts.visible=vis; if(!vis)return;
      p.phase=(p.phase+speed*dt)%1;
      for(let i=0;i<stream.P;i++){ let t=(p.phase+i/stream.P)%1; if(dir<0)t=1-t; const pt=p.curve.getPoint(t); stream.pp[i*3]=pt.x; stream.pp[i*3+1]=pt.y; stream.pp[i*3+2]=pt.z; }
      stream.pts.geometry.attributes.position.needsUpdate=true;
      stream.pts.material.opacity=0.5+Math.min(0.5,lbps(dir<0?rxb:txb)*0.08); };
    flow(p.rx,rxSpeed,-1,p.up && rxb>0);   // inbound: port→core
    flow(p.tx,txSpeed, 1,p.up && txb>0);   // outbound: core→port
  });
  if(H.selRing&&H.selRing.visible){ H.selRing.lookAt(H.camera.position); const ps=1+0.12*Math.sin(H.t*5); H.selRing.scale.setScalar(ps); H.selRing.material.opacity=0.5+0.4*Math.abs(Math.sin(H.t*3)); }
  H.renderer.render(H.scene,H.camera);
}

async function loadTraffic(){
  if(!RD_CAN_LIVE || H.dead || document.hidden) return;   // don't SSH-poll a hidden tab
  let d=null; try{ d=await fetch('router_details.php?api=traffic&node='+RD_NODE+'&_='+Date.now()).then(r=>r.json()); }catch(e){}
  if(!d || !d.ok){ if(!H.built){ document.getElementById('holo-loader').style.display='none';
      document.getElementById('holo-fallback').style.display='block';
      document.getElementById('holo-fallback').innerHTML='<div class="muted"><i class="fa-solid fa-plug-circle-xmark" style="color:#f39c12"></i> Live traffic needs SSH — '+esc((d&&d.error)||'unavailable')+'. Add an SSH credential in <a href="config_mgr.php" style="color:#4da3ff">Config Manager</a>.</div>'; }
    return; }
  const ifs=d.interfaces||[]; H.lastIfs=ifs;
  if(!H.built) holoBuild(ifs); else if(ifs.length!==Object.keys(H.ports).length) holoBuild(ifs); else holoUpdate(ifs);
  // accumulate per-interface throughput history for the click-to-drill sparkline
  ifs.forEach(f=>{ const h=(H.hist[f.name]=H.hist[f.name]||[]); h.push({rx:+f.rx_bps||0,tx:+f.tx_bps||0}); if(h.length>60)h.shift(); });
  if(H.sel){ if(H.ports[H.sel]&&H.selRing){ H.selRing.position.copy(H.ports[H.sel].node.position); renderPortDetail(); } else closePort(); }
  document.getElementById('tot-rx').textContent=fmtbps(d.total_rx_bps);
  document.getElementById('tot-tx').textContent=fmtbps(d.total_tx_bps);
  document.getElementById('tot-if').textContent=ifs.filter(x=>x.running).length+'/'+ifs.length;
  const w=document.getElementById('holo-when'); if(w) w.textContent='· '+new Date().toLocaleTimeString();
}

async function loadNetflow(){
  if(RD_KIND!=='router') return;
  let d=null; try{ d=await fetch('router_details.php?api=netflow&node='+RD_NODE+'&_='+Date.now()).then(r=>r.json()); }catch(e){}
  if(!d || !d.ok) return;
  document.getElementById('nfwrap').style.display='block';
  const bar=(nm,val,mx,unit)=>`<div class="nfbar"><span class="nm">${esc(nm)}</span><span class="track"><i style="width:${mx?Math.max(3,Math.round(val/mx*100)):0}%"></i></span><span class="val">${unit}</span></div>`;
  const apps=d.apps||[]; const amx=Math.max(1,...apps.map(a=>+a.bytes||+a.mbps||+a.flows||0));
  document.getElementById('nf-apps').innerHTML=apps.length?apps.map(a=>{ const v=+a.mbps||((+a.bytes||0)/1e6); return bar(a.app||a.application||a.name||'?', +a.mbps||+a.bytes||+a.flows||0, amx, (a.mbps!=null?(+a.mbps).toFixed(2)+' Mbps':fmtBytes(a.bytes))); }).join(''):'<div class="muted">No app data.</div>';
  const tk=d.talkers||[]; const tmx=Math.max(1,...tk.map(t=>+t.mbps||+t.bytes||0));
  document.getElementById('nf-talkers').innerHTML=tk.length?tk.map(t=>bar(t.ip||t.host||'?', +t.mbps||+t.bytes||0, tmx, (t.mbps!=null?(+t.mbps).toFixed(2)+' Mbps':fmtBytes(t.bytes)))).join(''):'<div class="muted">No talker data.</div>';
}

document.addEventListener('DOMContentLoaded', ()=>{ if(window.NMLoader) NMLoader.hide(); loadLive();
  if(RD_CAN_LIVE){ holoInit(); loadTraffic(); setInterval(loadTraffic, 9000); }
  loadNetflow(); setInterval(loadNetflow, 60000);
});
</script>
</body></html>
