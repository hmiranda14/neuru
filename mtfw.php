<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — MikroTik Firewall Control. A visual, object-based firewall editor for
// RouterOS: see the live filter/NAT rules per chain (in order, with hit counters),
// build/edit rules as objects, PREVIEW the exact commands, and inject them with a
// SAFE-APPLY auto-rollback (commit-confirm) so a bad rule can't lock you out.
// Plus: what-if packet simulator, templates, route/firewall drift, dead-rule flags.
// RBAC: 'mtfw'. Engine: nm_mtfw.php.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_mtfw.php');
include('logger.php');

if (!checkAccess($conn, 'mtfw')) { header('Location: /denied_access.php?page=mtfw'); exit; }
nm_mtfw_ensure($conn);
$uid = (int)($_SESSION['UID'] ?? 0);
$initNode = (int)($_GET['node'] ?? 0);   // preselect a router (from routers.php / command center links)

$api = $_GET['api'] ?? '';
if ($api !== '') {
    if (function_exists('session_write_close')) @session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    $body = json_decode(file_get_contents('php://input'), true) ?: $_POST;
    $node = null; $nid = (int)($_GET['node'] ?? $body['node'] ?? 0);
    if ($nid) $node = nm_router_node($conn, $nid);
    try {
        if ($api === 'routers') {
            $rs = array_values(array_filter(nm_router_list($conn), fn($r)=>strtolower((string)$r['os_icon']) === 'mikrotik' || strtolower((string)$r['os_icon']) === 'routeros'));
            echo json_encode(['ok'=>true, 'routers'=>$rs]); exit;
        }
        if (!$node) { echo json_encode(['ok'=>false,'error'=>'select a MikroTik router']); exit; }
        if (!nm_mtfw_supported($node)) { echo json_encode(['ok'=>false,'error'=>'not a MikroTik router']); exit; }
        $table = in_array(($_GET['table'] ?? $body['table'] ?? 'filter'), nm_mtfw_tables(), true) ? ($_GET['table'] ?? $body['table'] ?? 'filter') : 'filter';

        if ($api === 'fetch') {
            $f = nm_mtfw_fetch($conn, $node, $table);
            if (empty($f['ok'])) { echo json_encode($f); exit; }
            $al = nm_mtfw_fetch_addrlists($conn, $node);
            $drift = nm_mtfw_drift($conn, $nid, $table, $f['rules']);
            nm_mtfw_snapshot_save($conn, $nid, $table, $f['rules'], 'view', $uid);
            echo json_encode(['ok'=>true, 'table'=>$table, 'rules'=>$f['rules'], 'addrlists'=>($al['lists'] ?? []), 'drift'=>$drift]); exit;
        }
        if ($api === 'dryrun') {
            echo json_encode(nm_mtfw_dryrun((string)($body['op'] ?? 'add'), $table, $body['data'] ?? [], $body['existing'] ?? [])); exit;
        }
        if ($api === 'apply') {
            $data = $body['data'] ?? []; $data['existing'] = $body['existing'] ?? []; $data['uid'] = $uid;
            echo json_encode(nm_mtfw_apply($conn, $node, (string)($body['op'] ?? 'add'), $table, $data, !empty($body['safe']), (int)($body['window'] ?? 2))); exit;
        }
        if ($api === 'keep')   { echo json_encode(nm_mtfw_keep($conn, $node, (string)($body['token'] ?? ''))); exit; }
        if ($api === 'revert') { echo json_encode(nm_mtfw_revert_now($conn, $node, (string)($body['token'] ?? ''))); exit; }
        if ($api === 'whatif') {
            $f = nm_mtfw_fetch($conn, $node, 'filter'); if (empty($f['ok'])) { echo json_encode($f); exit; }
            echo json_encode(['ok'=>true] + nm_mtfw_whatif($f['rules'], $body['pkt'] ?? [])); exit;
        }
        if ($api === 'interfaces') {   // In-interface picker for the Packet Tracer
            echo json_encode(nm_mtfw_fetch_interfaces($conn, $node)); exit;
        }
        if ($api === 'trace') {   // full step-by-step packet trace for the Packet Tracer page
            $f = nm_mtfw_fetch($conn, $node, 'filter'); if (empty($f['ok'])) { echo json_encode($f); exit; }
            $lists = nm_mtfw_addrlist_members($conn, $node);
            $natR = nm_mtfw_fetch($conn, $node, 'nat');           // NAT table → dst-nat (pre) + src-nat (post)
            $nat  = !empty($natR['ok']) ? $natR['rules'] : [];
            echo json_encode(nm_mtfw_trace($f['rules'], $body['pkt'] ?? [], $lists, $nat)); exit;
        }
        // ── Network Objects (Address Lists · IP Addresses · Interfaces/VETH) ──
        if ($api === 'objlist') {   // kind = addrlist | ipaddr | iface
            $okind = (string)($_GET['kind'] ?? $body['kind'] ?? '');
            $r = nm_mtfw_fetch_kind($conn, $node, $okind);
            if ($okind === 'addrlist' && !empty($r['ok'])) $r['usedby'] = nm_mtfw_addrlist_usedby($conn, $node);
            echo json_encode($r); exit;
        }
        if ($api === 'obj_dryrun') {
            echo json_encode(nm_mtfw_obj_dryrun((string)($body['kind'] ?? ''), (string)($body['op'] ?? 'add'), $body['data'] ?? [], $body['existing'] ?? [])); exit;
        }
        if ($api === 'obj_apply') {
            $data = $body['data'] ?? []; $data['existing'] = $body['existing'] ?? []; $data['uid'] = $uid;
            echo json_encode(nm_mtfw_obj_apply($conn, $node, (string)($body['kind'] ?? ''), (string)($body['op'] ?? 'add'), $data, !empty($body['safe']), (int)($body['window'] ?? 2))); exit;
        }
        if ($api === 'route_emulate') {   // full A→B forwarding trace (routing + nat + firewall)
            echo json_encode(nm_mtfw_route_emulate($conn, $node, $body['pkt'] ?? [])); exit;
        }
        if ($api === 'torch') {   // live traffic (connection tracking)
            echo json_encode(nm_mtfw_torch($conn, $node, ['protocol'=>(string)($_GET['protocol']??$body['protocol']??''), 'address'=>(string)($_GET['address']??$body['address']??'')])); exit;
        }
        // ── Telemetry (Logging + Traffic-Flow, auto-wired to NEURU) ──
        if ($api === 'telemetry') {   // endpoints + flow settings for the tab header
            $fs = nm_mtfw_flow_settings($conn, $node);
            echo json_encode(['ok'=>true, 'endpoints'=>nm_mtfw_neuru_endpoints($conn, $node), 'flow'=>($fs['settings'] ?? null)]); exit;
        }
        if ($api === 'save_neuru_ip') {
            $ip = trim((string)($body['ip'] ?? '')); if ($ip!=='' && !filter_var($ip, FILTER_VALIDATE_IP)) { echo json_encode(['ok'=>false,'error'=>'invalid IP']); exit; }
            try { $st=$conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES ('telemetry_neuru_ip',?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)"); $st->bind_param('s',$ip); $st->execute(); } catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>$e->getMessage()]); exit; }
            echo json_encode(['ok'=>true]); exit;
        }
        // one-click preview (build only) + apply (REBUILDS server-side from ip/port — client never sends raw commands)
        if ($api === 'ship_syslog_dry')  { $ep=nm_mtfw_neuru_endpoints($conn,$node); echo json_encode(nm_mtfw_ship_syslog_build((string)($body['ip']??$ep['ip']),(int)($body['port']??$ep['syslog_port']),(string)($body['topics']??'info,error,warning,critical'))); exit; }
        if ($api === 'export_flow_dry')  { $ep=nm_mtfw_neuru_endpoints($conn,$node); echo json_encode(nm_mtfw_export_flow_build((string)($body['ip']??$ep['ip']),(int)($body['port']??$ep['netflow_port']),(string)($body['version']??'9'))); exit; }
        if ($api === 'ship_syslog') {
            $ep=nm_mtfw_neuru_endpoints($conn,$node);
            $b=nm_mtfw_ship_syslog_build((string)($body['ip']??$ep['ip']),(int)($body['port']??$ep['syslog_port']),(string)($body['topics']??'info,error,warning,critical'));
            if(empty($b['ok'])){ echo json_encode($b); exit; }
            echo json_encode(nm_mtfw_raw_apply($conn,$node,$b['cmd'],$b['revert'],$b['desc'],!empty($body['safe']),(int)($body['window']??2),$uid,'obj:syslog')); exit;
        }
        if ($api === 'export_flow') {
            $ep=nm_mtfw_neuru_endpoints($conn,$node);
            $b=nm_mtfw_export_flow_build((string)($body['ip']??$ep['ip']),(int)($body['port']??$ep['netflow_port']),(string)($body['version']??'9'));
            if(empty($b['ok'])){ echo json_encode($b); exit; }
            echo json_encode(nm_mtfw_raw_apply($conn,$node,$b['cmd'],$b['revert'],$b['desc'],!empty($body['safe']),(int)($body['window']??2),$uid,'obj:flow')); exit;
        }
        echo json_encode(['ok'=>false, 'error'=>'unknown api']);
    } catch (\Throwable $e) { echo json_encode(['ok'=>false, 'error'=>$e->getMessage()]); }
    exit;
}

$TPL = nm_mtfw_templates();
$e = fn($s)=>htmlspecialchars((string)$s, ENT_QUOTES);
include('header.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(12,16,26,.6); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cyan:#36e3d0; }
html{ background:#05080f; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#d4dce8; }
<?= nm_chrome_css() ?>
.fw{ max-width:1280px; margin:0 auto; padding:18px 20px 60px; }
.fw *{ box-sizing:border-box; }
.glass{ background:var(--glass); backdrop-filter:blur(13px); border:1px solid var(--border); border-radius:14px; }
.fw-bar{ display:flex; align-items:center; gap:14px; padding:14px 18px; margin-bottom:16px; flex-wrap:wrap; }
.fw-title{ font-size:19px; font-weight:800; display:flex; align-items:center; gap:11px; } .fw-title i{ color:#ff7a45; }
.fw-bar select,.inp{ background:rgba(0,0,0,.35); border:1px solid var(--border); color:#e6edf7; border-radius:9px; padding:8px 11px; font-size:13px; }
.inp{ width:100%; max-width:100%; }
.card .row>div, .row>div{ min-width:0; }   /* let grid cells shrink so inputs don't overflow */
.tabs{ display:flex; gap:6px; margin-left:auto; } .tab{ padding:8px 14px; border-radius:9px; border:1px solid var(--border); cursor:pointer; font-size:13px; } .tab.on{ background:rgba(255,122,69,.14); border-color:rgba(255,122,69,.5); color:#ffcbb0; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:8px 13px; font-size:13px; cursor:pointer; }
.btn:hover{ border-color:var(--accent); color:#fff; } .btn.g{ background:linear-gradient(135deg,#4da3ff,#6a5cff); border:none; color:#fff; } .btn.no{ background:transparent; color:#aeb8c7; } .btn.danger{ border-color:rgba(231,76,60,.5); color:#ff9b91; }
.grid{ display:grid; grid-template-columns:1fr 320px; gap:16px; } @media(max-width:960px){ .grid{ grid-template-columns:1fr; } }
.card{ padding:16px 18px; margin-bottom:16px; }
.chain{ display:flex; align-items:center; gap:9px; margin:20px 0 10px; padding:7px 12px; border-radius:9px;
  background:linear-gradient(90deg,rgba(77,163,255,.10),rgba(77,163,255,0)); border:1px solid rgba(77,163,255,.16); border-left:3px solid #4da3ff; }
.chain .cn{ font-size:12px; font-weight:800; text-transform:uppercase; letter-spacing:1.2px; color:#cfe0f7; }
.chain .cnt{ font-size:10px; font-weight:700; color:#9db4d6; background:rgba(77,163,255,.16); border-radius:20px; padding:2px 9px; }
.chain i{ color:#4da3ff; }
.rule{ display:grid; grid-template-columns:30px 92px minmax(0,1fr) 128px 70px; align-items:center; column-gap:12px;
  padding:8px 12px; border:1px solid var(--border); border-left:3px solid #5a6577; border-radius:9px; margin-bottom:6px;
  font-size:12.5px; background:rgba(255,255,255,.022); transition:background .12s,border-color .12s; }
.rule:hover{ background:rgba(77,163,255,.06); border-color:rgba(77,163,255,.3); }
.rule.a{ border-left-color:#2ecc71; } .rule.d{ border-left-color:#e74c3c; } .rule.r{ border-left-color:#f39c12; } .rule.j{ border-left-color:#4da3ff; } .rule.nat{ border-left-color:#c084fc; }
.rule.off{ opacity:.5; } .rule.dyn{ opacity:.72; }
.rule .ord{ color:#7c8798; text-align:right; font-variant-numeric:tabular-nums; font-size:12px; font-weight:700; }
.act{ font-size:9.5px; font-weight:800; padding:3px 0; border-radius:6px; text-transform:uppercase; text-align:center; letter-spacing:.4px; }
.act.accept{ background:rgba(46,204,113,.18); color:#7fe0a3; } .act.drop{ background:rgba(231,76,60,.2); color:#ff9b91; } .act.reject{ background:rgba(243,156,18,.2); color:#ffce6b; } .act.jump{ background:rgba(77,163,255,.18); color:#bcd8ff; } .act.other{ background:rgba(192,132,252,.18); color:#d9bcff; }
.match{ min-width:0; font-family:Consolas,monospace; font-size:11.5px; color:#c7d0de; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.match b{ color:#eaf1ff; } .cmt{ color:#8b95a7; }
.hitcol{ text-align:right; } .hits{ font-size:10.5px; color:#93a0b3; font-variant-numeric:tabular-nums; white-space:nowrap; } .hits.hot{ color:#ffb08a; } .hits.dead{ color:#5a6577; }
.heat{ height:3px; border-radius:3px; background:rgba(255,255,255,.06); margin-top:4px; overflow:hidden; }
.heat i{ display:block; height:100%; border-radius:3px; }
.tools{ display:flex; gap:2px; justify-content:flex-end; }
.rule .tg{ cursor:pointer; color:#8b95a7; width:22px; height:22px; display:inline-flex; align-items:center; justify-content:center; border-radius:6px; }
.rule .tg:hover{ color:#fff; background:rgba(255,255,255,.09); }
.dot{ width:8px;height:8px;border-radius:50%;display:inline-block; }
label{ display:block; font-size:10.5px; text-transform:uppercase; letter-spacing:.4px; color:#8b95a7; margin:9px 0 4px; }
.ed .row{ display:grid; grid-template-columns:1fr 1fr; gap:10px; } .ed .inp,.ed select{ width:100%; }
.states{ display:flex; gap:10px; flex-wrap:wrap; font-size:12px; color:#c7d0de; } .states label{ text-transform:none; letter-spacing:0; margin:0; color:#c7d0de; display:flex; align-items:center; gap:5px; }
.pill{ font-size:10px; padding:2px 8px; border-radius:20px; background:rgba(255,255,255,.06); color:#cfd6e0; cursor:pointer; } .pill:hover{ background:rgba(255,255,255,.12); }
.modal{ position:fixed; inset:0; z-index:70; background:rgba(3,5,12,.72); backdrop-filter:blur(4px); display:none; align-items:center; justify-content:center; padding:24px; }
.mcard{ width:620px; max-width:96vw; max-height:90vh; overflow:auto; background:rgba(9,13,24,.98); border:1px solid var(--border); border-radius:16px; padding:20px 22px; }
.mcard *{ box-sizing:border-box; }   /* modals live OUTSIDE .fw → give them box-sizing so inputs don't overflow/overlap */
.ed .row>div{ min-width:0; }
.cmdbox{ font-family:Consolas,monospace; font-size:12px; background:rgba(0,0,0,.4); border:1px solid var(--border); border-radius:9px; padding:11px 13px; color:#bff2d2; white-space:pre-wrap; word-break:break-all; margin:8px 0; }
.cmdbox.rev{ color:#ffce9b; }
.warnbox{ background:rgba(243,156,18,.12); border:1px solid rgba(243,156,18,.4); border-radius:10px; padding:11px 14px; font-size:12.5px; color:#ffd98a; margin:10px 0; }
#keepbar{ position:fixed; left:50%; bottom:20px; transform:translateX(-50%); z-index:80; display:none; }
#keepbar .glass{ padding:12px 18px; display:flex; align-items:center; gap:14px; border-color:rgba(243,156,18,.5); box-shadow:0 12px 40px rgba(0,0,0,.5); }
#keepbar .cd{ font-size:22px; font-weight:800; color:#ffce6b; min-width:44px; text-align:center; }
.muted{ color:#8b95a7; font-size:12.5px; } .dim{ color:#6f7a8c; }
.al{ display:flex; align-items:center; gap:8px; font-size:12px; margin-bottom:5px; } .al .n{ color:#dbe3ee; } .al .c{ margin-left:auto; color:#8b95a7; }
.orow{ display:flex; align-items:center; gap:12px; padding:9px 11px; border-bottom:1px solid rgba(255,255,255,.05); }
.orow:hover{ background:rgba(255,255,255,.02); } .orow.off{ opacity:.5; } .orow.dyn{ opacity:.65; }
.orow .match{ flex:1; min-width:0; font-size:13px; color:#dbe3ee; overflow:hidden; text-overflow:ellipsis; }
.orow .match b{ color:#fff; } .mono{ font-family:Consolas,monospace; color:#bff2d2; }
.usedby{ font-size:11px; color:#8b95a7; margin-left:6px; } .usedby b{ color:#c084fc; }
.btn.sm{ padding:5px 10px; font-size:12px; }
.tel-neuru{ border-color:rgba(54,227,208,.3); }
.tel-sec{ padding:14px 16px; } .tel-h{ display:flex; align-items:center; gap:9px; font-size:14px; font-weight:700; margin-bottom:2px; flex-wrap:wrap; }
.tel-sub{ font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:1px; color:#7f8ba0; margin:14px 0 4px; }
.torhd,.torrow{ display:grid; grid-template-columns:56px minmax(0,1.3fr) minmax(0,1.3fr) 92px 92px 60px; align-items:center; gap:10px; padding:8px 13px; }
.torhd{ font-size:10px; font-weight:800; text-transform:uppercase; letter-spacing:1px; color:#7f8ba0; border-bottom:1px solid var(--border); }
.torrow{ position:relative; border-bottom:1px solid rgba(255,255,255,.04); font-size:12.5px; }
.torrow:hover{ background:rgba(255,255,255,.02); } .torrow .mono{ white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.torrow .tp{ font-size:10px; font-weight:800; text-align:center; padding:2px 0; border-radius:6px; background:rgba(255,255,255,.07); color:#aeb8c7; }
.torrow .tp.tcp{ background:rgba(77,163,255,.16); color:#8fc0ff; } .torrow .tp.udp{ background:rgba(192,132,252,.16); color:#d0abff; } .torrow .tp.icmp{ background:rgba(240,169,44,.16); color:#f0c674; }
.torrow .rt{ font-variant-numeric:tabular-nums; text-align:right; font-weight:600; } .rt.up{ color:#7fe0a3; } .rt.down{ color:#8fc0ff; }
.toract{ display:flex; gap:6px; justify-content:flex-end; } .toract .tg{ cursor:pointer; color:#8b95a7; } .toract .tg:hover{ color:#ff9b91; }
.torbar{ position:absolute; left:0; bottom:0; height:2px; width:100%; } .torbar i{ display:block; height:100%; background:linear-gradient(90deg,#36e3d0,#4da3ff); border-radius:2px; transition:width .6s; }
</style>

<div class="fw">
  <div class="fw-bar glass">
    <div class="fw-title"><i class="fa-solid fa-shield-halved"></i> MikroTik Device Manager</div>
    <select id="fw-node" onchange="loadFw()"><option value="">Select a router…</option></select>
    <div class="tabs" id="fw-tabs">
      <div class="tab on" data-t="filter" onclick="setTab('filter')">Filter</div>
      <div class="tab" data-t="nat" onclick="setTab('nat')">NAT</div>
      <div class="tab" data-t="addrlist" onclick="setTab('addrlist')">Address Lists</div>
      <div class="tab" data-t="ipaddr" onclick="setTab('ipaddr')">Addresses</div>
      <div class="tab" data-t="route" onclick="setTab('route')">Routes</div>
      <div class="tab" data-t="iface" onclick="setTab('iface')">Interfaces</div>
      <div class="tab" data-t="torch" onclick="setTab('torch')">Torch</div>
      <div class="tab" data-t="telemetry" onclick="setTab('telemetry')">Telemetry</div>
    </div>
    <button class="btn no" onclick="loadFw()"><i class="fa-solid fa-rotate"></i></button>
  </div>

  <div class="grid">
    <div>
      <div class="glass card">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
          <div style="font-weight:700;font-size:14px;" id="fw-h">Rules</div>
          <span id="fw-drift" class="pill" style="display:none;background:rgba(243,156,18,.18);color:#ffce6b;"></span>
          <span style="flex:1"></span>
          <button class="btn g" id="fw-add" onclick="addNew()"><i class="fa-solid fa-plus"></i> New rule</button>
        </div>
        <div class="muted" id="fw-help" style="margin-bottom:8px;">Rules are evaluated <b>top-to-bottom per chain</b> — order matters. Colour = hit-count heatmap; faded = disabled/dynamic.</div>
        <div id="fw-list"><div class="dim">Select a router to load its firewall.</div></div>
      </div>
    </div>
    <div>
      <div class="glass card" style="position:relative;overflow:hidden;border-color:rgba(54,227,208,.28);">
        <div style="position:absolute;inset:0;background:radial-gradient(circle at 100% 0%,rgba(54,227,208,.14),transparent 55%);pointer-events:none;"></div>
        <div style="font-weight:700;font-size:13px;margin-bottom:6px;"><i class="fa-solid fa-satellite-dish" style="color:#36e3d0"></i> Packet Tracer</div>
        <div class="muted" style="margin-bottom:12px;">Watch a packet fly through the firewall in 3D — every rule it's tested against, and the exact gate that <b style="color:#7fe0a3">accepts</b> or <b style="color:#ff9b91">drops</b> it. Read-only; no router change.</div>
        <button class="btn g" style="width:100%;background:linear-gradient(135deg,#36e3d0,#4da3ff);" onclick="openTracer()"><i class="fa-solid fa-play"></i> Open Packet Tracer</button>
        <div style="margin-top:12px;border-top:1px solid rgba(255,255,255,.08);padding-top:12px;">
          <div style="font-weight:700;font-size:13px;margin-bottom:6px;"><i class="fa-solid fa-route" style="color:#c084fc"></i> Routing Emulator</div>
          <div class="muted" style="margin-bottom:10px;">Full <b>A → B</b> forwarding trace across <b>routing + NAT + firewall</b> — see the exact path, out-interface and next-hop, in 3D.</div>
          <button class="btn g" style="width:100%;background:linear-gradient(135deg,#c084fc,#4da3ff);" onclick="openEmulator()"><i class="fa-solid fa-diagram-project"></i> Open Routing Emulator</button>
        </div>
      </div>
      <div class="glass card">
        <div style="font-weight:700;font-size:13px;margin-bottom:9px;"><i class="fa-solid fa-layer-group"></i> Address-list objects</div>
        <div id="fw-al"><div class="dim">—</div></div>
      </div>
      <div class="glass card">
        <div style="font-weight:700;font-size:13px;margin-bottom:9px;"><i class="fa-solid fa-wand-magic-sparkles"></i> Templates</div>
        <?php foreach ($TPL as $k=>$t): ?>
        <div style="margin-bottom:9px;"><button class="btn no" style="width:100%;text-align:left" onclick="useTpl('<?= $e($k) ?>')"><i class="fa-solid fa-bolt" style="color:#ffce6b"></i> <?= $e($t['label']) ?></button>
          <div class="muted" style="font-size:11px;margin-top:3px;"><?= $e($t['desc']) ?></div></div>
        <?php endforeach; ?>
      </div>
    </div>
  </div>
</div>

<!-- editor modal -->
<div class="modal" id="ed-modal"><div class="mcard ed">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;"><h3 id="ed-title" style="margin:0;font-size:16px;">New rule</h3><span style="flex:1"></span><i class="fa-solid fa-xmark" style="cursor:pointer;color:#9aa3af" onclick="closeEd()"></i></div>
  <input type="hidden" id="ed-op"><input type="hidden" id="ed-id">
  <div class="row">
    <div><label>Chain</label><select class="inp" id="ed-chain"></select></div>
    <div><label>Action</label><select class="inp" id="ed-action"></select></div>
    <div><label>Protocol</label><select class="inp" id="ed-proto"></select></div>
    <div><label>Connection-state</label><div class="states" id="ed-states"></div></div>
    <div><label>Src address / range</label><input class="inp" id="ed-src" placeholder="10.0.0.0/24 or 1.2.3.4"></div>
    <div><label>Dst address</label><input class="inp" id="ed-dst" placeholder="blank = any"></div>
    <div><label>Src port(s)</label><input class="inp" id="ed-sport" placeholder="e.g. 1024-65535"></div>
    <div><label>Dst port(s)</label><input class="inp" id="ed-dport" placeholder="e.g. 80,443"></div>
    <div><label>In interface</label><select class="inp" id="ed-inif" onchange="edCombo('ed-inif')"></select>
      <input class="inp" id="ed-inif_c" style="display:none;margin-top:6px" placeholder="e.g. !ether1 (negate) or an interface-list"></div>
    <div><label>Out interface</label><select class="inp" id="ed-outif" onchange="edCombo('ed-outif')"></select>
      <input class="inp" id="ed-outif_c" style="display:none;margin-top:6px" placeholder="type a custom value"></div>
    <div><label>Src address-list</label><select class="inp" id="ed-sal" onchange="edCombo('ed-sal')"></select>
      <input class="inp" id="ed-sal_c" style="display:none;margin-top:6px" placeholder="type a new / custom list name"></div>
    <div><label>Dst address-list</label><select class="inp" id="ed-dal" onchange="edCombo('ed-dal')"></select>
      <input class="inp" id="ed-dal_c" style="display:none;margin-top:6px" placeholder="type a new / custom list name"></div>
  </div>
  <div id="ed-nat" style="display:none"><div class="row">
    <div><label>To addresses (dst-nat)</label><input class="inp" id="ed-toaddr" placeholder="192.168.88.10"></div>
    <div><label>To ports</label><input class="inp" id="ed-toports" placeholder="8080"></div>
  </div></div>
  <div class="row"><div><label>Jump target</label><input class="inp" id="ed-jump" placeholder="only for action=jump"></div>
    <div><label>Comment</label><input class="inp" id="ed-cmt" placeholder="what this rule does"></div></div>
  <label style="margin-top:10px"><input type="checkbox" id="ed-log"> log matches &nbsp; · &nbsp; <input type="checkbox" id="ed-dis"> create disabled</label>
  <label>Placement</label><select class="inp" id="ed-place"><option value="">bottom of chain (append)</option></select>
  <div style="display:flex;gap:9px;margin-top:16px;"><button class="btn g" onclick="preview()"><i class="fa-solid fa-eye"></i> Preview command</button><button class="btn no" onclick="closeEd()">Cancel</button></div>
</div></div>

<!-- network-object add/edit modal (Address Lists · Addresses · Interfaces/VETH) -->
<div class="modal" id="obj-modal"><div class="mcard">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;"><h3 id="obj-title" style="margin:0;font-size:16px;">New</h3><span style="flex:1"></span><i class="fa-solid fa-xmark" style="cursor:pointer;color:#9aa3af" onclick="hide('obj-modal')"></i></div>
  <div id="obj-fields"></div>
  <div style="display:flex;gap:9px;margin-top:16px;"><button class="btn g" onclick="previewObj()"><i class="fa-solid fa-eye"></i> Preview command</button><button class="btn no" onclick="hide('obj-modal')">Cancel</button></div>
  <div id="obj-msg" style="margin-top:9px;font-size:12px;color:#ff9b91"></div>
</div></div>
<datalist id="ifnames"></datalist>

<!-- dry-run / apply modal -->
<div class="modal" id="dr-modal"><div class="mcard">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;"><h3 style="margin:0;font-size:16px;"><i class="fa-solid fa-eye" style="color:#4da3ff"></i> Command preview</h3><span style="flex:1"></span><i class="fa-solid fa-xmark" style="cursor:pointer;color:#9aa3af" onclick="hide('dr-modal')"></i></div>
  <div class="muted" id="dr-desc"></div>
  <label>Will run on the router</label><div class="cmdbox" id="dr-cmd"></div>
  <label>Auto-rollback (if you don't confirm)</label><div class="cmdbox rev" id="dr-rev"></div>
  <div class="warnbox"><i class="fa-solid fa-shield-halved"></i> <b>Safe-Apply</b> installs a RouterOS scheduler that runs the rollback in <select id="dr-win" style="background:transparent;border:none;color:#ffd98a;font-weight:700;"><option>2</option><option>3</option><option>5</option><option>10</option></select> min. If you get locked out, the router reverts itself. Click <b>Keep</b> after to make it permanent.</div>
  <div style="display:flex;gap:9px;margin-top:8px;align-items:center;flex-wrap:wrap;">
    <label style="margin:0;text-transform:none;color:#d4dce8"><input type="checkbox" id="dr-safe" checked> Safe-Apply (recommended)</label>
    <span style="flex:1"></span>
    <button class="btn g" onclick="doApply()"><i class="fa-solid fa-bolt"></i> Apply to router</button>
    <button class="btn no" onclick="hide('dr-modal')">Cancel</button>
  </div>
</div></div>

<!-- keep/commit-confirm bar -->
<div id="keepbar"><div class="glass"><i class="fa-solid fa-triangle-exclamation" style="color:#ffce6b;font-size:18px"></i>
  <div><div style="font-weight:700">Change applied — confirm it's working</div><div class="muted" id="keep-desc" style="font-size:11.5px"></div></div>
  <div class="cd" id="keep-cd">—</div>
  <button class="btn g" onclick="keepChange()"><i class="fa-solid fa-check"></i> Keep</button>
  <button class="btn danger" onclick="revertChange()">Revert now</button>
</div></div>

<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const ACTIONS=<?= json_encode(nm_mtfw_actions()) ?>, CHAINS=<?= json_encode(nm_mtfw_chains()) ?>, PROTOS=<?= json_encode(nm_mtfw_protocols()) ?>, STATES=<?= json_encode(nm_mtfw_states()) ?>, TPL=<?= json_encode(nm_mtfw_templates()) ?>;
const CLIENT_IP=<?= json_encode($_SERVER['REMOTE_ADDR'] ?? '') ?>;
let NODE=0, TABLE='filter', RULES=[], ADDR={}, PEND=null, keepTimer=null;
let IFACES=[], IFACES_NODE=0;   // live interface names for the in/out dropdowns (cached per router)
// Populate the In/Out-interface + Src/Dst address-list <select> dropdowns with live router data.
function edComboFill(id, opts, blankLabel){ const s=document.getElementById(id); if(!s)return; const cur=s.value;
  s.innerHTML=`<option value="">${blankLabel}</option>`+opts.map(o=>`<option value="${esc(o)}">${esc(o)}</option>`).join('')+`<option value="__custom__">✏️ custom / new…</option>`;
  if(cur && [...s.options].some(o=>o.value===cur)) s.value=cur;
}
function fillDatalists(){
  const al=Object.keys(ADDR).sort();
  edComboFill('ed-sal', al, '— none —'); edComboFill('ed-dal', al, '— none —');
  edComboFill('ed-inif', IFACES, 'any');  edComboFill('ed-outif', IFACES, 'any');
}
// selecting "custom" reveals the paired text box
function edCombo(id){ const s=document.getElementById(id), c=document.getElementById(id+'_c'); if(!c)return; const cust=s.value==='__custom__'; c.style.display=cust?'block':'none'; if(cust)c.focus(); }
// set a combo to a value: pick it if it's an option, else switch to custom + fill the text box
function edComboSet(id, val){ const s=document.getElementById(id), c=document.getElementById(id+'_c'); if(!s)return; val=(val==null?'':String(val));
  if(val===''){ s.value=''; if(c){c.value='';c.style.display='none';} return; }
  if([...s.options].some(o=>o.value===val)){ s.value=val; if(c){c.value='';c.style.display='none';} }
  else { s.value='__custom__'; if(c){ c.value=val; c.style.display='block'; } }
}
// read a field whether it is a plain input or a combo (select + custom box)
function edGet(id){ const s=document.getElementById(id); if(s && s.tagName==='SELECT'){ return s.value==='__custom__' ? ((document.getElementById(id+'_c').value||'').trim()) : (s.value||'').trim(); } return ((s&&s.value)||'').trim(); }
async function loadIfaces(){
  if(!NODE){ IFACES=[]; fillDatalists(); return; }
  if(IFACES_NODE===NODE && IFACES.length){ fillDatalists(); return; }   // cached for this router
  const d=await fetch('mtfw.php?api=interfaces&node='+NODE).then(r=>r.json()).catch(()=>null);
  IFACES=(d&&d.ok&&Array.isArray(d.interfaces))?d.interfaces.map(x=>x.name).filter(Boolean):[];
  IFACES_NODE=NODE; fillDatalists();
  // if the editor is open, refresh the interface dropdowns preserving the current selection
  const m=document.getElementById('ed-modal'); if(m && m.style.display!=='none'){ ['ed-inif','ed-outif'].forEach(id=>edComboSet(id, edGet(id))); }
}
let KIND=null, OBJ=[], IFNAMES=[], USEDBY={};
function hide(id){ document.getElementById(id).style.display='none'; }
function show(id){ document.getElementById(id).style.display='flex'; }
async function post(api,obj){ return fetch('mtfw.php?api='+api+'&node='+NODE,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj||{})}).then(r=>r.json()).catch(()=>({ok:false,error:'request failed'})); }

const INIT_NODE=<?= json_encode($initNode) ?>;
async function loadRouters(){ const d=await fetch('mtfw.php?api=routers').then(r=>r.json()).catch(()=>null); if(!d||!d.ok)return;
  const sel=document.getElementById('fw-node');
  sel.innerHTML='<option value="">Select a router…</option>'+d.routers.map(r=>`<option value="${r.id}">${esc(r.name)} (${esc(r.ip)})</option>`).join('');
  if(INIT_NODE){ sel.value=INIT_NODE; if(sel.value){ NODE=INIT_NODE; loadFw(); } } }
function setTab(t){ document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('on',x.dataset.t===t));
  document.getElementById('fw-add').style.display=(t==='telemetry'||t==='torch')?'none':'';
  stopTorch();
  if(t==='filter'||t==='nat'){ KIND=null; TABLE=t; document.getElementById('ed-nat').style.display=(t==='nat')?'block':'none'; loadFw(); }
  else if(t==='telemetry'){ KIND='telemetry'; loadTelemetry(); }
  else if(t==='torch'){ KIND='torch'; loadTorch(); }
  else { KIND=t; loadObj(t); } }
function refreshView(){ if(KIND==='telemetry') loadTelemetry(); else if(KIND==='torch'){/* auto-polls */} else if(KIND) loadObj(KIND); else loadFw(); }
function addNew(){ if(!NODE){alert('Select a router first.');return;} if(KIND&&KIND!=='telemetry'){ (KIND==='iface')?openObj('veth','add',null):openObj(KIND,'add',null); } else newRule(); }

async function loadFw(){ NODE=+document.getElementById('fw-node').value||0; const list=document.getElementById('fw-list');
  if(!NODE){ list.innerHTML='<div class="dim">Select a router to load its firewall.</div>'; return; }
  list.innerHTML='<div class="dim"><i class="fa-solid fa-spinner fa-spin"></i> Reading /ip firewall '+TABLE+' over SSH…</div>';
  const d=await fetch('mtfw.php?api=fetch&node='+NODE+'&table='+TABLE+'&_='+Date.now()).then(r=>r.json()).catch(()=>null);
  if(!d||!d.ok){ list.innerHTML='<div class="warnbox">'+esc((d&&d.error)||'failed')+'</div>'; return; }
  RULES=d.rules||[]; ADDR=d.addrlists||{};
  fillDatalists(); loadIfaces();   // back the editor's interface + address-list dropdowns with live data
  document.getElementById('fw-h').textContent='/ip firewall '+TABLE+' — '+RULES.length+' rules';
  // drift
  const dr=d.drift||{}; const nch=(dr.added||[]).length+(dr.removed||[]).length; const de=document.getElementById('fw-drift');
  if(dr.had_prev&&nch){ de.style.display='inline'; de.textContent='⚡ '+nch+' rule change(s) since last view'; } else de.style.display='none';
  // address-list objects
  document.getElementById('fw-al').innerHTML=Object.keys(ADDR).length?Object.entries(ADDR).map(([n,c])=>`<div class="al"><span class="dot" style="background:#c084fc"></span><span class="n">${esc(n)}</span><span class="c">${c} entr${c==1?'y':'ies'}</span></div>`).join(''):'<div class="dim">No address-lists.</div>';
  renderRules();
}
function renderRules(){ const byChain={}; RULES.forEach((r,i)=>{ r._i=i; (byChain[r.chain]=byChain[r.chain]||[]).push(r); });
  const maxHits=Math.max(1,...RULES.map(r=>r.packets||0));
  let h=''; Object.keys(byChain).forEach(ch=>{ h+=`<div class="chain"><i class="fa-solid fa-diagram-next"></i> <span class="cn">${esc(ch)} chain</span> <span class="cnt">${byChain[ch].length} rule${byChain[ch].length==1?'':'s'}</span></div>`;
    byChain[ch].forEach(r=>{ h+=ruleRow(r,maxHits); }); });
  document.getElementById('fw-list').innerHTML=h||'<div class="dim">No rules in this table.</div>';
  // suggest a baseline on an unprotected router
  if(TABLE==='filter' && RULES.filter(r=>!r.dynamic).length===0){
    document.getElementById('fw-list').insertAdjacentHTML('afterbegin',
      '<div class="warnbox" style="background:rgba(77,163,255,.1);border-color:rgba(77,163,255,.45);color:#bcd8ff"><i class="fa-solid fa-shield-halved"></i> This router has <b>no firewall filter rules — it is unprotected</b>. <a onclick="useTpl(\'baseline\')" style="color:#7fe0a3;cursor:pointer;font-weight:700">★ Inject the baseline firewall →</a></div>');
  }
}
function actClass(a){ if(a==='accept')return 'accept'; if(a==='drop')return 'drop'; if(a==='reject'||a==='tarpit')return 'reject'; if(a==='jump'||a==='return')return 'jump'; return 'other'; }
function ruleRow(r,maxHits){ const p=r.props||{}; const ac=actClass(r.action);
  const bl=r.action==='accept'?'a':(r.action==='drop'?'d':(r.action==='reject'?'r':(r.action==='jump'?'j':(TABLE==='nat'?'nat':''))));
  const match=[]; if(p['src-address'])match.push('src='+esc(p['src-address'])); if(p['src-address-list'])match.push('srclist='+esc(p['src-address-list']));
  if(p['dst-address'])match.push('dst='+esc(p['dst-address'])); if(p['dst-address-list'])match.push('dstlist='+esc(p['dst-address-list']));
  if(p['protocol'])match.push('<b>'+esc(p['protocol'])+'</b>'); if(p['dst-port'])match.push('dport='+esc(p['dst-port'])); if(p['src-port'])match.push('sport='+esc(p['src-port']));
  if(p['connection-state'])match.push('state='+esc(p['connection-state'])); if(p['in-interface'])match.push('in='+esc(p['in-interface'])); if(p['out-interface'])match.push('out='+esc(p['out-interface']));
  if(p['to-addresses'])match.push('→'+esc(p['to-addresses'])+(p['to-ports']?':'+esc(p['to-ports']):''));
  const pkts=r.packets||0; const hot=pkts>maxHits*0.15, dead=pkts===0&&!r.disabled;
  const hits=pkts>0?fmtN(pkts)+' pkts':(r.disabled?'disabled':'never hit');
  const pct=pkts>0?Math.max(4,Math.round(pkts/maxHits*100)):0;
  const heatCol=pct>60?'#ff7a45':(pct>25?'#f0a92c':'#4da3ff');
  return `<div class="rule ${bl} ${r.disabled?'off':''} ${r.dynamic?'dyn':''}">
    <span class="ord">${r.idx}</span>
    <span class="act ${ac}">${esc(r.action)}</span>
    <span class="match">${match.join(' · ')||'<span class="dim">match all</span>'}${r.comment?' <span class="cmt">// '+esc(r.comment.replace(/\s*\[nfw[0-9a-f]+\]\s*/,''))+'</span>':''}</span>
    <span class="hitcol"><span class="hits ${hot?'hot':''} ${dead?'dead':''}" title="${fmtN(r.bytes||0)} bytes">${hits}</span><span class="heat"><i style="width:${pct}%;background:${heatCol}"></i></span></span>
    <span class="tools">${r.dynamic?'<span class="dim" title="dynamic rule — read only" style="width:22px;text-align:center">🔒</span>':`<span class="tg" title="${r.disabled?'enable':'disable'}" onclick="toggleRule(${r._i})"><i class="fa-solid fa-power-off"></i></span>
    <span class="tg" title="edit" onclick="editRule(${r._i})"><i class="fa-solid fa-pen"></i></span>
    <span class="tg" title="delete" onclick="delRule(${r._i})"><i class="fa-solid fa-trash"></i></span>`}</span>
  </div>`;
}
function fmtN(n){ n=+n||0; if(n>=1e9)return (n/1e9).toFixed(1)+'B'; if(n>=1e6)return (n/1e6).toFixed(1)+'M'; if(n>=1e3)return (n/1e3).toFixed(1)+'k'; return ''+n; }

// ── editor ──
function fillSelect(id,arr,val){ document.getElementById(id).innerHTML=arr.map(a=>`<option ${a===val?'selected':''}>${esc(a)}</option>`).join(''); }
function newRule(){ if(!NODE){alert('Select a router first.');return;} openEd('add',null); }
function needId(r){ if(!r||!r.id){ alert('Could not resolve this rule\'s router id — reload the firewall (↻) and try again.'); loadFw(); return false; } return true; }
function editRule(i){ if(!needId(RULES[i]))return; openEd('set',RULES[i]); }
function openEd(op,r){ fillDatalists(); loadIfaces(); document.getElementById('ed-op').value=op; document.getElementById('ed-title').textContent=op==='add'?'New rule':'Edit rule';
  fillSelect('ed-chain',CHAINS, r?r.chain:(TABLE==='nat'?'srcnat':'forward')); fillSelect('ed-action',ACTIONS.filter(a=>a), r?r.action:'accept'); fillSelect('ed-proto',PROTOS.map(p=>p||'(any)'), r&&r.props.protocol?r.props.protocol:'(any)');
  document.getElementById('ed-states').innerHTML=STATES.map(s=>`<label><input type="checkbox" class="wi-st" value="${s}" ${r&&(r.props['connection-state']||'').split(',').includes(s)?'checked':''}> ${s}</label>`).join('');
  const p=r?r.props:{}; const g=(k)=>p[k]||'';
  document.getElementById('ed-src').value=g('src-address'); document.getElementById('ed-dst').value=g('dst-address');
  document.getElementById('ed-sport').value=g('src-port'); document.getElementById('ed-dport').value=g('dst-port');
  edComboSet('ed-inif', g('in-interface')); edComboSet('ed-outif', g('out-interface'));
  edComboSet('ed-sal', g('src-address-list')); edComboSet('ed-dal', g('dst-address-list'));
  document.getElementById('ed-toaddr').value=g('to-addresses'); document.getElementById('ed-toports').value=g('to-ports');
  document.getElementById('ed-jump').value=g('jump-target'); document.getElementById('ed-cmt').value=r?(r.comment||'').replace(/\s*\[nfw[0-9a-f]+\]\s*/,''):'';
  document.getElementById('ed-log').checked=(g('log')==='yes'); document.getElementById('ed-dis').checked=!!(r&&r.disabled);
  document.getElementById('ed-nat').style.display=(TABLE==='nat')?'block':'none';
  // placement dropdown from current chain rules
  const pl=document.getElementById('ed-place'); const ch=document.getElementById('ed-chain').value;
  pl.innerHTML='<option value="">bottom of chain (append)</option>'+RULES.filter(x=>x.chain===ch&&x.id).map(x=>`<option value="${x.id}">before #${x.idx} (${esc(x.action)} ${esc((x.comment||'').slice(0,20))})</option>`).join('');
  document.getElementById('ed-id').value=r?r.id:''; window._edExisting=r||{};
  show('ed-modal');
}
function closeEd(){ hide('ed-modal'); }
function edData(){ const props={ chain:document.getElementById('ed-chain').value, action:document.getElementById('ed-action').value };
  const proto=document.getElementById('ed-proto').value; if(proto&&proto!=='(any)')props.protocol=proto;
  const map={'ed-src':'src-address','ed-dst':'dst-address','ed-sport':'src-port','ed-dport':'dst-port','ed-inif':'in-interface','ed-outif':'out-interface','ed-sal':'src-address-list','ed-dal':'dst-address-list','ed-jump':'jump-target','ed-cmt':'comment','ed-toaddr':'to-addresses','ed-toports':'to-ports'};
  for(const [id,k] of Object.entries(map)){ const v=edGet(id); if(v)props[k]=v; }
  const st=[...document.querySelectorAll('#ed-states .wi-st:checked')].map(x=>x.value); if(st.length)props['connection-state']=st.join(',');
  if(document.getElementById('ed-log').checked)props.log='yes'; if(document.getElementById('ed-dis').checked)props.disabled='yes';
  const data={props}; const place=document.getElementById('ed-place').value; if(place)data.place_before=place;
  const id=document.getElementById('ed-id').value; if(id)data.id=id;
  return data;
}
async function preview(){ const op=document.getElementById('ed-op').value; const data=edData();
  const d=await post('dryrun',{op,table:TABLE,data,existing:window._edExisting});
  if(!d.ok){ alert(d.error||'invalid'); return; }
  window._pending={op,data,existing:window._edExisting};
  document.getElementById('dr-desc').textContent=d.desc||''; document.getElementById('dr-cmd').textContent=d.cmd||'';
  document.getElementById('dr-rev').textContent=d.revert||'(none)'; closeEd(); show('dr-modal');
}
async function doApply(){ const p=window._pending; if(!p)return; const safe=document.getElementById('dr-safe').checked; const win=+document.getElementById('dr-win').value||2;
  if(!safe && !confirm('Apply WITHOUT the auto-rollback safety net? A bad change could lock you out.'))return;
  const d = (p.mode==='ship') ? await post('ship_syslog',{ip:p.params.ip,safe,window:win})
          : (p.mode==='flow') ? await post('export_flow',{ip:p.params.ip,safe,window:win})
          : (p.mode==='obj')  ? await post('obj_apply',{kind:p.kind,op:p.op,data:p.data,existing:p.existing,safe,window:win})
          : await post('apply',{op:p.op,table:TABLE,data:p.data,existing:p.existing,safe,window:win});
  hide('dr-modal');
  if(!d.ok){ alert('Apply failed: '+(d.error||'?')); return; }
  refreshView();
  if(d.safe && d.token){ PEND={token:d.token,desc:d.desc}; startKeep(win); }
  else alert('Applied.'+(d.safe?'':' (no auto-rollback for this op)'));
}
function toggleRule(i){ const r=RULES[i]; if(!needId(r))return; window._pending={op:'toggle',data:{id:r.id,enable:!!r.disabled},existing:r};
  document.getElementById('dr-desc').textContent=(r.disabled?'Enable':'Disable')+' rule #'+r.idx; document.getElementById('dr-cmd').textContent='/ip firewall '+TABLE+' '+(r.disabled?'enable':'disable')+' '+r.id;
  document.getElementById('dr-rev').textContent='/ip firewall '+TABLE+' '+(r.disabled?'disable':'enable')+' '+r.id; show('dr-modal'); }
function delRule(i){ const r=RULES[i]; if(r.dynamic){alert('Dynamic rules are read-only.');return;} if(!needId(r))return;
  window._pending={op:'remove',data:{id:r.id},existing:r};
  document.getElementById('dr-desc').textContent='Remove rule #'+r.idx+' ('+r.action+' '+r.chain+') — tip: disabling is safer than deleting.';
  document.getElementById('dr-cmd').textContent='/ip firewall '+TABLE+' remove '+r.id; document.getElementById('dr-rev').textContent='(re-add on rollback)'; show('dr-modal'); }

// ── safe-apply keep/revert ──
function startKeep(win){ let left=win*60; const bar=document.getElementById('keepbar'); bar.style.display='block';
  document.getElementById('keep-desc').textContent=(PEND.desc||'change')+' — auto-reverts if not kept';
  const tick=()=>{ const m=Math.floor(left/60),s=left%60; document.getElementById('keep-cd').textContent=m+':'+String(s).padStart(2,'0');
    if(left--<=0){ clearInterval(keepTimer); bar.style.display='none'; alert('⏱ Auto-rollback window elapsed — the router reverted the change.'); refreshView(); PEND=null; } };
  tick(); if(keepTimer)clearInterval(keepTimer); keepTimer=setInterval(tick,1000); }
async function keepChange(){ if(!PEND)return; const d=await post('keep',{token:PEND.token}); if(keepTimer)clearInterval(keepTimer);
  document.getElementById('keepbar').style.display='none'; alert(d.ok?'✅ Change kept — auto-rollback cancelled.':'Could not cancel rollback: '+(d.error||'?')); PEND=null; refreshView(); }
async function revertChange(){ if(!PEND)return; const d=await post('revert',{token:PEND.token}); if(keepTimer)clearInterval(keepTimer);
  document.getElementById('keepbar').style.display='none'; alert(d.ok?'↩ Reverted.':'Revert failed: '+(d.error||'?')); PEND=null; refreshView(); }

// ══ NETWORK OBJECTS (Address Lists · Addresses · Interfaces/VETH) ══
const OBJMETA={
  addrlist:{path:'/ip firewall address-list', add:'New entry', noun:'entries',
    help:'Named IP groups referenced by firewall rules. <b>used-by</b> shows which rules reference each list. Add / edit / delete, or send a list <b>→ Immunity</b>.'},
  ipaddr:{path:'/ip address', add:'New address', noun:'addresses',
    help:'Interface IP addresses. ⚠ <b>editing the address you manage the router through can lock you out</b> — Safe-Apply auto-reverts if you don’t press Keep.'},
  route:{path:'/ip route', add:'New route', noun:'routes',
    help:'The routing table — where each destination is sent. Add / edit / delete <b>static</b> routes; connected & dynamic (OSPF/BGP/DHCP) routes are read-only 🔒. ⚠ a bad route can black-hole traffic — Safe-Apply auto-reverts. Test any change in the <b>Routing Emulator</b>.'},
  iface:{path:'/interface', add:'New VETH', noun:'interfaces',
    help:'Interfaces + VETH. Edit MTU / comment, enable / disable, or create a VETH. Physical NICs can be toggled but not removed.'}
};
const OBJFIELDS={
  addrlist:[['list','List','list_combo','e.g. mgmt'],['address','Address','text','IP, CIDR or a.b.c.d-a.b.c.e'],['timeout','Timeout','text','optional · e.g. 1d, 30m'],['comment','Comment','text','']],
  ipaddr:[['address','Address','text','IP/cidr · e.g. 10.0.0.1/24'],['interface','Interface','iface_select','ether2'],['comment','Comment','text','']],
  route:[['dst-address','Destination','text','0.0.0.0/0 or 10.0.0.0/24'],['gateway','Gateway','gw_combo','IP or interface'],['distance','Distance','text','1'],['comment','Comment','text','']],
  iface:[['mtu','MTU','text','e.g. 1500'],['comment','Comment','text','']],
  veth:[['name','Name','text','e.g. veth1'],['address','Address','text','optional · IP/cidr'],['gateway','Gateway','text','optional'],['comment','Comment','text','']],
  logaction:[['name','Name','text','e.g. neuru-syslog'],['target','Target','select:memory,disk,echo,remote','remote'],['remote','Remote IP','text','only for target=remote'],['remote-port','Remote port','text','514']],
  logrule:[['topics','Topics','text','e.g. info,error,firewall'],['action','Action','text','memory / neuru-syslog'],['prefix','Prefix','text','optional']],
  flowtarget:[['dst-address','Collector IP','text','e.g. 192.168.0.25'],['port','Port','text','2055'],['version','Version','select:9,5,1,ipfix','9'],['src-address','Src address','text','optional']],
  flowcfg:[['enabled','Enabled','select:yes,no','yes'],['interfaces','Interfaces','text','all'],['cache-entries','Cache entries','text','8k']]
};
const KLABEL={addrlist:'address-list entry',ipaddr:'IP address',route:'route',iface:'interface',veth:'VETH',logaction:'logging action',logrule:'logging rule',flowtarget:'flow target',flowcfg:'traffic-flow settings'};
function findObj(id){ return OBJ.find(o=>o.id===id); }
function cleanTag(c){ return (c||'').replace(/\s*\[nob[0-9a-f]+\]\s*/,''); }

async function loadObj(kind){ NODE=+document.getElementById('fw-node').value||0; const list=document.getElementById('fw-list');
  const m=OBJMETA[kind]; document.getElementById('fw-drift').style.display='none';
  document.getElementById('fw-add').innerHTML='<i class="fa-solid fa-plus"></i> '+m.add;
  document.getElementById('fw-help').innerHTML=m.help;
  if(!NODE){ list.innerHTML='<div class="dim">Select a router.</div>'; document.getElementById('fw-h').textContent=m.path; return; }
  document.getElementById('fw-h').textContent=m.path;
  list.innerHTML='<div class="dim"><i class="fa-solid fa-spinner fa-spin"></i> Reading '+m.path+' over SSH…</div>';
  const d=await fetch('mtfw.php?api=objlist&kind='+kind+'&node='+NODE+'&_='+Date.now()).then(r=>r.json()).catch(()=>null);
  if(!d||!d.ok){ list.innerHTML='<div class="warnbox">'+esc((d&&d.error)||'failed')+'</div>'; return; }
  OBJ=d.rows||[]; USEDBY=d.usedby||{};
  if(kind==='iface'){ IFNAMES=OBJ.map(o=>o.name).filter(Boolean); document.getElementById('ifnames').innerHTML=IFNAMES.map(n=>`<option value="${esc(n)}">`).join(''); }
  document.getElementById('fw-h').textContent=m.path+' — '+OBJ.length+' '+m.noun;
  renderObj(kind);
}
// which filter/nat rules reference an address-list (from the last loaded RULES if in view)
function objName(o,kind){ if(kind==='addrlist')return 'list '+o.list+' → '+o.address; if(kind==='ipaddr')return o.address+' on '+o.interface; if(kind==='route')return 'route '+o.dst+' via '+o.gateway; return (o.name||'')+' ('+(o.type||'')+')'; }
function renderObj(kind){ const list=document.getElementById('fw-list');
  if(!OBJ.length){ list.innerHTML='<div class="dim">No '+OBJMETA[kind].noun+'.</div>'; return; }
  list.innerHTML=OBJ.map(o=>objRow(o,kind)).join('');
}
function objRow(o,kind){
  let main='';
  if(kind==='addrlist'){ const ub=USEDBY[o.list]||0; main=`<b>${esc(o.list)}</b> <span class="mono">${esc(o.address)}</span>${o.timeout?' <span class="dim">timeout '+esc(o.timeout)+'</span>':''}${ub?` <span class="usedby">used by <b>${ub}</b> rule${ub==1?'':'s'}</span>`:''}`; }
  else if(kind==='ipaddr') main=`<span class="mono">${esc(o.address)}</span> <span class="dim">on</span> <b>${esc(o.interface)}</b>`;
  else if(kind==='route') main=`<span class="mono">${esc(o.dst)}</span> <span class="dim">via</span> <b>${esc(o.gateway)}</b>${o.distance?' <span class="dim">dist '+esc(o.distance)+'</span>':''}${o.active?' <span class="pill" style="background:rgba(65,209,139,.15);color:#7fe0a3">active</span>':' <span class="pill" style="background:rgba(255,255,255,.06);color:#8b95a7">inactive</span>'}`;
  else main=`<b>${esc(o.name)}</b> <span class="dim">${esc(o.type)}</span>${o.running?' <span class="pill" style="background:rgba(65,209,139,.15);color:#7fe0a3">running</span>':''}${o.mtu?' <span class="dim">mtu '+esc(o.mtu)+'</span>':''}`;
  const cmt=o.comment?` <span class="cmt">// ${esc(cleanTag(o.comment))}</span>`:'';
  const badge=o.disabled?' <span class="pill" style="background:rgba(255,90,90,.15);color:#ff9b91">disabled</span>':'';
  let tools;
  if(o.dynamic){ tools='<span class="dim" title="dynamic — read only" style="width:22px;text-align:center">🔒</span>'; }
  else {
    const canDel=(kind==='addrlist'||kind==='ipaddr'||kind==='route'||(kind==='iface'&&o.type==='veth'));
    tools=`<span class="tg" title="${o.disabled?'enable':'disable'}" onclick="toggleObj('${o.id}')"><i class="fa-solid fa-power-off"></i></span>
      <span class="tg" title="edit" onclick="editObj('${o.id}')"><i class="fa-solid fa-pen"></i></span>
      ${canDel?`<span class="tg" title="delete" onclick="delObj('${o.id}')"><i class="fa-solid fa-trash"></i></span>`:''}`;
  }
  return `<div class="orow ${o.disabled?'off':''} ${o.dynamic?'dyn':''}"><span class="match">${main}${cmt}${badge}</span><span class="tools">${tools}</span></div>`;
}
function needOId(o){ if(!o||!o.id){ alert('Could not resolve this object\'s router id — reload (↻) and try again.'); refreshView(); return false; } return true; }
function editObj(id){ const o=findObj(id); if(!needOId(o))return; openObj(KIND==='iface'?'iface':KIND,'set',o); }
let LISTNAMES=[];
async function ensureIfaces(){ if(IFNAMES.length||!NODE)return; const d=await fetch('mtfw.php?api=objlist&kind=iface&node='+NODE).then(r=>r.json()).catch(()=>null); if(d&&d.ok) IFNAMES=(d.rows||[]).map(o=>o.name).filter(Boolean); }
async function ensureLists(){ if(!NODE)return; const d=await fetch('mtfw.php?api=objlist&kind=addrlist&node='+NODE).then(r=>r.json()).catch(()=>null); LISTNAMES=(d&&d.ok)?[...new Set((d.rows||[]).map(o=>o.list).filter(Boolean))]:LISTNAMES; }
async function openObj(kind,op,o){ window._objKind=kind; window._objOp=op; window._objExisting=o||{};
  if(kind==='ipaddr'||kind==='veth'||kind==='route') await ensureIfaces();
  if(kind==='addrlist') await ensureLists();
  document.getElementById('obj-title').textContent=(op==='add'?'New ':'Edit ')+KLABEL[kind];
  let head=''; if(kind==='iface'&&o) head=`<div class="muted" style="margin-bottom:6px">${esc(o.name)} <span class="dim">(${esc(o.type)})</span></div>`;
  const fields=OBJFIELDS[kind].map(([k,label,type,ph])=>{
    let val=o&&o[k]!=null?o[k]:'';
    if(k==='remote-port'&&o&&o.remoteport!=null)val=o.remoteport; if(k==='dst-address'&&o&&o.dst!=null)val=o.dst; if(k==='src-address'&&o&&o.src!=null)val=o.src;
    if(k==='comment')val=cleanTag(val);
    const lab=`<label style="display:block;font-size:11px;color:#8b95a7;margin:9px 0 3px">${esc(label)}</label>`;
    if(type&&type.indexOf('select:')===0){ const opts=type.slice(7).split(','); return lab+`<select class="inp" id="of-${k}">`+opts.map(op=>`<option ${String(val)===op?'selected':''}>${esc(op)}</option>`).join('')+`</select>`; }
    if(type==='iface_select'){ let opts=[...IFNAMES]; if(val&&!opts.includes(val))opts.unshift(val);
      return lab+`<select class="inp" id="of-${k}">`+(op==='add'&&!val?'<option value="">— pick an interface —</option>':'')+opts.map(n=>`<option ${String(val)===n?'selected':''}>${esc(n)}</option>`).join('')+`</select>`; }
    if(type==='gw_combo'){ return lab+`<input class="inp" id="of-${k}" list="ifnames" autocomplete="off" value="${esc(val)}" placeholder="${esc(ph||'')}">`
      +`<datalist id="ifnames">`+IFNAMES.map(n=>`<option value="${esc(n)}">`).join('')+`</datalist>`
      +`<div class="dim" style="font-size:10px;margin-top:2px">pick an interface or type a gateway IP</div>`; }
    if(type==='list_combo'){ return lab+`<input class="inp" id="of-${k}" list="listnames" autocomplete="off" value="${esc(val)}" placeholder="${esc(ph||'')}">`
      +`<datalist id="listnames">`+LISTNAMES.map(n=>`<option value="${esc(n)}">`).join('')+`</datalist>`
      +`<div class="dim" style="font-size:10px;margin-top:2px">pick an existing list or type a new name</div>`; }
    return lab+`<input class="inp" id="of-${k}" value="${esc(val)}" placeholder="${esc(ph||'')}">`;
  }).join('');
  document.getElementById('obj-fields').innerHTML=head+fields;
  document.getElementById('obj-msg').textContent=''; show('obj-modal');
}
function objData(){ const kind=window._objKind, op=window._objOp; const data={};
  OBJFIELDS[kind].forEach(([k])=>{ const el=document.getElementById('of-'+k); if(el){ const v=el.value.trim(); if(v!=='')data[k]=v; } });
  if(op==='set'&&window._objExisting) data.id=window._objExisting.id;
  return data;
}
async function previewObj(){ const kind=window._objKind, op=window._objOp; const data=objData();
  const d=await post('obj_dryrun',{kind,op,data,existing:window._objExisting});
  if(!d.ok){ document.getElementById('obj-msg').textContent=d.error||'invalid'; return; }
  window._pending={mode:'obj',kind,op,data,existing:window._objExisting};
  document.getElementById('dr-desc').textContent=d.desc||''; document.getElementById('dr-cmd').textContent=d.cmd||'';
  document.getElementById('dr-rev').textContent=d.revert||'(none)'; hide('obj-modal'); show('dr-modal');
}
function toggleObj(id){ const o=findObj(id); if(!needOId(o))return; const kind=(KIND==='iface')?'iface':KIND;
  window._pending={mode:'obj',kind,op:'toggle',data:{id:o.id,enable:!!o.disabled},existing:o};
  const path=OBJMETA[KIND].path;
  document.getElementById('dr-desc').textContent=(o.disabled?'Enable':'Disable')+' '+objName(o,KIND);
  document.getElementById('dr-cmd').textContent=path+' '+(o.disabled?'enable':'disable')+' '+o.id;
  document.getElementById('dr-rev').textContent=path+' '+(o.disabled?'disable':'enable')+' '+o.id; show('dr-modal');
}
function delObj(id){ const o=findObj(id); if(o&&o.dynamic){alert('Dynamic objects are read-only.');return;} if(!needOId(o))return;
  const kind=(KIND==='iface'&&o.type==='veth')?'veth':KIND;
  window._pending={mode:'obj',kind,op:'remove',data:{id:o.id},existing:o};
  const path={addrlist:'/ip firewall address-list',ipaddr:'/ip address',veth:'/interface veth',iface:'/interface'}[kind];
  document.getElementById('dr-desc').textContent='Remove '+objName(o,KIND)+' — tip: disabling is safer than deleting.';
  document.getElementById('dr-cmd').textContent=path+' remove '+o.id;
  document.getElementById('dr-rev').textContent='(re-add on rollback)'; show('dr-modal');
}

// ══ TELEMETRY (Logging + Traffic-Flow → NEURU) ══
let TEL={};
async function loadTelemetry(){ NODE=+document.getElementById('fw-node').value||0;
  document.getElementById('fw-drift').style.display='none'; document.getElementById('fw-h').textContent='Telemetry → NEURU';
  document.getElementById('fw-help').innerHTML='Configure the router to ship <b>logs</b> (syslog) and <b>NetFlow</b> to NEURU — or any target — right from here. One-click auto-fills NEURU’s own endpoints. Safe-Apply on every change.';
  const list=document.getElementById('fw-list');
  if(!NODE){ list.innerHTML='<div class="dim">Select a router.</div>'; return; }
  list.innerHTML='<div class="dim"><i class="fa-solid fa-spinner fa-spin"></i> Reading logging + traffic-flow over SSH…</div>';
  const [t,la,lr,ft]=await Promise.all([
    fetch('mtfw.php?api=telemetry&node='+NODE+'&_='+Date.now()).then(r=>r.json()).catch(()=>null),
    fetch('mtfw.php?api=objlist&kind=logaction&node='+NODE).then(r=>r.json()).catch(()=>null),
    fetch('mtfw.php?api=objlist&kind=logrule&node='+NODE).then(r=>r.json()).catch(()=>null),
    fetch('mtfw.php?api=objlist&kind=flowtarget&node='+NODE).then(r=>r.json()).catch(()=>null)
  ]);
  if(!t||!t.ok){ list.innerHTML='<div class="warnbox">'+esc((t&&t.error)||'failed to read telemetry')+'</div>'; return; }
  TEL={endpoints:t.endpoints||{}, flow:t.flow||{}, logactions:(la&&la.rows)||[], logrules:(lr&&lr.rows)||[], flowtargets:(ft&&ft.rows)||[]};
  renderTelemetry();
}
function renderTelemetry(){
  const ep=TEL.endpoints||{}, fl=TEL.flow||{}; const ip=ep.ip||''; const flowOn=(fl.enabled==='yes'||fl.enabled==='true');
  document.getElementById('fw-list').innerHTML=`
  <div class="glass card tel-neuru">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <b style="font-size:14px"><i class="fa-solid fa-satellite" style="color:#36e3d0"></i> NEURU endpoint</b>
      <span class="muted">where the router sends logs / flows</span><span style="flex:1"></span>
      <input class="inp" id="tel-ip" value="${esc(ip)}" placeholder="192.168.0.x" style="max-width:150px">
      <button class="btn no" onclick="saveNeuruIp()"><i class="fa-solid fa-floppy-disk"></i> Save</button>
      ${ep.auto_ip&&!ep.saved?`<span class="muted" title="detected from the router's view of NEURU's SSH">auto ${esc(ep.auto_ip)}</span>`:''}
    </div>
    <div style="display:flex;gap:10px;margin-top:12px;flex-wrap:wrap">
      <button class="btn g" onclick="shipSyslog()"><i class="fa-solid fa-scroll"></i> Ship logs to NEURU :${ep.syslog_port}</button>
      <button class="btn g" onclick="exportFlow()"><i class="fa-solid fa-wave-square"></i> Export NetFlow to NEURU :${ep.netflow_port}</button>
    </div>
  </div>
  <div class="glass card tel-sec"><div class="tel-h"><i class="fa-solid fa-scroll" style="color:#4da3ff"></i> Logging <span class="muted">rules → actions</span><span style="flex:1"></span><button class="btn no sm" onclick="openObj('logrule','add',null)"><i class="fa-solid fa-plus"></i> Rule</button><button class="btn no sm" onclick="openObj('logaction','add',null)"><i class="fa-solid fa-plus"></i> Action</button></div>
    <div class="muted" style="margin:2px 0 8px">Rules route <b>topics</b> (info, error, firewall…) to an <b>action</b> — memory, disk, or a <b>remote</b> syslog like NEURU.</div>
    ${TEL.logrules.map(o=>telRow(o,'logrule')).join('')||'<div class="dim" style="padding:6px">No logging rules.</div>'}
    <div class="tel-sub">Actions</div>
    ${TEL.logactions.map(o=>telRow(o,'logaction')).join('')||'<div class="dim" style="padding:6px">No actions.</div>'}
  </div>
  <div class="glass card tel-sec"><div class="tel-h"><i class="fa-solid fa-wave-square" style="color:#c084fc"></i> Traffic-Flow (NetFlow) <span class="pill" style="background:${flowOn?'rgba(65,209,139,.15)':'rgba(255,90,90,.15)'};color:${flowOn?'#7fe0a3':'#ff9b91'}">${flowOn?'enabled':'disabled'}</span><span style="flex:1"></span><button class="btn no sm" onclick="toggleFlow(${flowOn?1:0})"><i class="fa-solid fa-power-off"></i> ${flowOn?'Disable':'Enable'}</button><button class="btn no sm" onclick="openObj('flowtarget','add',null)"><i class="fa-solid fa-plus"></i> Target</button></div>
    <div class="muted" style="margin:2px 0 8px">Exports flow records to collectors. interfaces=<b>${esc(fl.interfaces||'—')}</b> · cache=<b>${esc(fl['cache-entries']||'—')}</b></div>
    ${TEL.flowtargets.map(o=>telRow(o,'flowtarget')).join('')||'<div class="dim" style="padding:6px">No flow targets.</div>'}
  </div>`;
}
function telRow(o,kind){ let main='';
  if(kind==='logrule') main=`<b>${esc(o.topics)}</b> <span class="dim">→</span> <span class="mono">${esc(o.action)}</span>${o.prefix?' <span class="dim">prefix '+esc(o.prefix)+'</span>':''}`;
  else if(kind==='logaction'){ const rem=o.target==='remote'; main=`<b>${esc(o.name)}</b> <span class="dim">${esc(o.target)}</span>${rem?` <span class="mono">${esc(o.remote)}:${esc(o.remoteport)}</span>`:''}`; }
  else main=`<span class="mono">${esc(o.dst)}:${esc(o.port)}</span> <span class="dim">NetFlow v${esc(o.version)}</span>`;
  const badge=o.disabled?' <span class="pill" style="background:rgba(255,90,90,.15);color:#ff9b91">disabled</span>':'';
  const builtin=(kind==='logaction'&&o.builtin);
  let tools;
  if(o.dynamic){ tools='<span class="dim">🔒</span>'; }
  else tools=`<span class="tg" title="${o.disabled?'enable':'disable'}" onclick="telToggle('${kind}','${o.id}')"><i class="fa-solid fa-power-off"></i></span>
    <span class="tg" title="edit" onclick="telEdit('${kind}','${o.id}')"><i class="fa-solid fa-pen"></i></span>
    ${builtin?'':`<span class="tg" title="delete" onclick="telDel('${kind}','${o.id}')"><i class="fa-solid fa-trash"></i></span>`}`;
  return `<div class="orow ${o.disabled?'off':''}"><span class="match">${main}${badge}</span><span class="tools">${tools}</span></div>`;
}
function telFind(kind,id){ const a=kind==='logrule'?TEL.logrules:kind==='logaction'?TEL.logactions:TEL.flowtargets; return (a||[]).find(o=>o.id===id); }
function telEdit(kind,id){ const o=telFind(kind,id); if(!o)return; openObj(kind,'set',o); }
function telPath(kind){ return {logrule:'/system logging',logaction:'/system logging action',flowtarget:'/ip traffic-flow target'}[kind]; }
function telToggle(kind,id){ const o=telFind(kind,id); if(!o)return; window._pending={mode:'obj',kind,op:'toggle',data:{id:o.id,enable:!!o.disabled},existing:o};
  document.getElementById('dr-desc').textContent=(o.disabled?'Enable':'Disable')+' '+KLABEL[kind];
  document.getElementById('dr-cmd').textContent=telPath(kind)+' '+(o.disabled?'enable':'disable')+' '+o.id;
  document.getElementById('dr-rev').textContent=telPath(kind)+' '+(o.disabled?'disable':'enable')+' '+o.id; show('dr-modal'); }
function telDel(kind,id){ const o=telFind(kind,id); if(!o)return; window._pending={mode:'obj',kind,op:'remove',data:{id:o.id},existing:o};
  document.getElementById('dr-desc').textContent='Remove '+KLABEL[kind];
  document.getElementById('dr-cmd').textContent=telPath(kind)+' remove '+o.id;
  document.getElementById('dr-rev').textContent='(re-add on rollback)'; show('dr-modal'); }
function toggleFlow(isOn){ const en=isOn?'no':'yes'; window._pending={mode:'obj',kind:'flowcfg',op:'set',data:{enabled:en},existing:TEL.flow};
  document.getElementById('dr-desc').textContent=(isOn?'Disable':'Enable')+' traffic-flow';
  document.getElementById('dr-cmd').textContent='/ip traffic-flow set enabled='+en;
  document.getElementById('dr-rev').textContent='/ip traffic-flow set enabled='+(isOn?'yes':'no'); show('dr-modal'); }
async function saveNeuruIp(){ const ip=document.getElementById('tel-ip').value.trim(); const d=await post('save_neuru_ip',{ip}); if(!d.ok){alert(d.error||'failed');return;} loadTelemetry(); }
async function shipSyslog(){ const ip=document.getElementById('tel-ip').value.trim()||TEL.endpoints.ip;
  const d=await post('ship_syslog_dry',{ip}); if(!d.ok){ alert(d.error||'error'); return; }
  window._pending={mode:'ship',params:{ip}};
  document.getElementById('dr-desc').textContent=d.desc||''; document.getElementById('dr-cmd').textContent=d.cmd||''; document.getElementById('dr-rev').textContent=d.revert||'(none)'; show('dr-modal'); }
async function exportFlow(){ const ip=document.getElementById('tel-ip').value.trim()||TEL.endpoints.ip;
  const d=await post('export_flow_dry',{ip}); if(!d.ok){ alert(d.error||'error'); return; }
  window._pending={mode:'flow',params:{ip}};
  document.getElementById('dr-desc').textContent=d.desc||''; document.getElementById('dr-cmd').textContent=d.cmd||''; document.getElementById('dr-rev').textContent=d.revert||'(none)'; show('dr-modal'); }

// ══ TORCH (live traffic via connection tracking) ══
let torchTimer=null, TORCH_PREV={}, TORCH_ROWS=[], TORCH_SORT='rate', TORCH_ON=true;
function stopTorch(){ if(torchTimer){ clearInterval(torchTimer); torchTimer=null; } }
function fkey(r){ return r.proto+'|'+r.src+'|'+r.dst; }
function loadTorch(){ NODE=+document.getElementById('fw-node').value||0;
  document.getElementById('fw-drift').style.display='none'; document.getElementById('fw-h').textContent='Torch — live traffic';
  document.getElementById('fw-help').innerHTML='Real-time traffic from the router’s connection tracker. Rates are computed live from byte deltas. Filter, sort, and act on a talker: <b>block</b> it or add it to an <b>address-list</b>.';
  const list=document.getElementById('fw-list');
  if(!NODE){ list.innerHTML='<div class="dim">Select a router.</div>'; return; }
  TORCH_PREV={}; TORCH_LAST=0;
  list.innerHTML=`<div class="glass card" style="padding:12px 14px;display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <b style="font-size:13px"><i class="fa-solid fa-satellite-dish" style="color:#36e3d0"></i> Live</b>
      <select class="inp" id="tor-proto" style="max-width:110px" onchange="torchPoll()"><option value="">any proto</option><option>tcp</option><option>udp</option><option>icmp</option></select>
      <input class="inp" id="tor-addr" placeholder="filter address…" style="max-width:170px" oninput="torchRender()">
      <select class="inp" id="tor-sort" style="max-width:150px" onchange="TORCH_SORT=this.value;torchRender()"><option value="rate">sort: total rate</option><option value="up">sort: ↑ rate</option><option value="down">sort: ↓ rate</option><option value="bytes">sort: bytes</option></select>
      <label class="muted" style="display:flex;align-items:center;gap:6px"><input type="checkbox" id="tor-live" checked onchange="TORCH_ON=this.checked;this.checked?startTorch():stopTorch()"> auto</label>
      <span style="flex:1"></span><span id="tor-stat" class="muted"></span>
    </div>
    <div class="glass card" style="padding:0"><div id="tor-list"><div class="dim" style="padding:14px"><i class="fa-solid fa-spinner fa-spin"></i> Reading connections…</div></div></div>`;
  torchPoll(); startTorch();
}
function startTorch(){ stopTorch(); if(TORCH_ON) torchTimer=setInterval(torchPoll,2500); }
let TORCH_LAST=0;
async function torchPoll(){ if(KIND!=='torch'||!NODE)return; const proto=(document.getElementById('tor-proto')||{}).value||'';
  const d=await fetch('mtfw.php?api=torch&node='+NODE+'&protocol='+encodeURIComponent(proto)+'&_='+Date.now()).then(r=>r.json()).catch(()=>null);
  if(!d||!d.ok){ const el=document.getElementById('tor-list'); if(el)el.innerHTML='<div class="warnbox" style="margin:12px">'+esc((d&&d.error)||'failed')+'</div>'; return; }
  const now=Date.now(); const dt=TORCH_LAST?Math.max(0.5,(now-TORCH_LAST)/1000):0; TORCH_LAST=now;
  const cur={};
  (d.rows||[]).forEach(r=>{ const k=fkey(r); const pv=TORCH_PREV[k];
    r.up = (dt&&pv)?Math.max(0,(r.ob-pv.ob)/dt*8):0;   // bits/s
    r.down = (dt&&pv)?Math.max(0,(r.rb-pv.rb)/dt*8):0;
    cur[k]={ob:r.ob,rb:r.rb}; });
  TORCH_PREV=cur; TORCH_ROWS=d.rows||[];
  document.getElementById('tor-stat').textContent=(d.total||0)+' connections'+(d.capped?' (capped '+d.count+')':'');
  torchRender();
}
function torchRender(){ const el=document.getElementById('tor-list'); if(!el)return;
  const af=(document.getElementById('tor-addr')||{}).value||''; let rows=TORCH_ROWS.slice();
  if(af) rows=rows.filter(r=>(r.src+' '+r.dst).toLowerCase().includes(af.toLowerCase()));
  rows.sort((a,b)=> TORCH_SORT==='up'?(b.up-a.up): TORCH_SORT==='down'?(b.down-a.down): TORCH_SORT==='bytes'?((b.ob+b.rb)-(a.ob+a.rb)) : ((b.up+b.down)-(a.up+a.down)));
  rows=rows.slice(0,120);
  if(!rows.length){ el.innerHTML='<div class="dim" style="padding:14px">No connections match.</div>'; return; }
  const mx=Math.max(1,...rows.map(r=>r.up+r.down));
  el.innerHTML='<div class="torhd"><span>proto</span><span>source</span><span>destination</span><span>↑ rate</span><span>↓ rate</span><span></span></div>'+
    rows.map(r=>{ const sip=(r.src||'').split(':')[0]; const pct=Math.round((r.up+r.down)/mx*100);
      return `<div class="torrow">
        <span class="tp ${esc(r.proto)}">${esc(r.proto||'?')}</span>
        <span class="mono" title="${esc(r.src)}">${esc(r.src)}</span>
        <span class="mono" title="${esc(r.dst)}">${esc(r.dst)}</span>
        <span class="rt up">${rate(r.up)}</span>
        <span class="rt down">${rate(r.down)}</span>
        <span class="toract"><span class="tg" title="block source ${esc(sip)}" onclick="torchBlock('${esc(sip)}')"><i class="fa-solid fa-ban"></i></span>
          <span class="tg" title="add ${esc(sip)} to an address-list" onclick="torchList('${esc(sip)}')"><i class="fa-solid fa-layer-group"></i></span></span>
        <span class="torbar"><i style="width:${pct}%"></i></span>
      </div>`; }).join('');
}
function rate(bps){ bps=+bps||0; if(bps<1)return '<span class="dim">—</span>'; if(bps>=1e9)return (bps/1e9).toFixed(1)+' Gb/s'; if(bps>=1e6)return (bps/1e6).toFixed(1)+' Mb/s'; if(bps>=1e3)return (bps/1e3).toFixed(0)+' kb/s'; return Math.round(bps)+' b/s'; }
function torchList(ip){ if(!ip)return; openObj('addrlist','add',{address:ip}); }   // reuse the addr-list add modal, prefilled (kind carried by _objKind)
function torchBlock(ip){ if(!ip)return; if(!confirm('Open a firewall rule to DROP forward traffic from '+ip+'?'))return;
  stopTorch(); document.querySelector('.tab[data-t="filter"]').click();
  setTimeout(()=>openEd('add',{chain:'forward',action:'drop',props:{'src-address':ip},comment:'torch block '+ip,disabled:false,dynamic:false,id:null,idx:0}),350); }

// ── packet tracer (own page) ──
function openTracer(){ if(!NODE){alert('Select a router first.');return;} location.href='mtfw_trace.php?node='+NODE; }
function openEmulator(){ if(!NODE){alert('Select a router first.');return;} location.href='route_emulator.php?node='+NODE; }

// ── templates ──
function useTpl(k){ if(!NODE){alert('Select a router first.');return;} const t=TPL[k]; if(!t)return;
  if(t.batch){ baselineFlow(t); return; }
  if(t.rules.length===1){ if(t.table)setTab(t.table);
    openEd('add',{chain:t.rules[0].chain,action:t.rules[0].action,props:t.rules[0],comment:t.rules[0].comment||''}); return; }
  alert('Template "'+t.label+'" contains '+t.rules.length+' rules. They will open one-by-one in the editor to review + apply (each with Safe-Apply). Placeholders like {IP}/{PORT}/{HOST}/{WAN} — edit before applying.');
  openEd('add',{chain:t.rules[0].chain,action:t.rules[0].action,props:t.rules[0],comment:t.rules[0].comment||''});
}
// Whole-ruleset (baseline) injection as ONE Safe-Apply unit.
async function baselineFlow(t){
  if(t.table && TABLE!==t.table){ TABLE=t.table; document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('on',x.dataset.t===TABLE)); }
  const ip=prompt('Inject "'+t.label.replace('★ ','')+'"?\n\n'+t.rules.length+' rules will be added in order. To avoid lock-out, your management IP is added to the "mgmt" address-list (referenced by the "accept management" rule).\n\nManagement IP (edit if wrong · blank = skip · applied with Safe-Apply auto-rollback):', CLIENT_IP||'');
  if(ip===null) return;
  const data={rules:t.rules}; if(ip.trim())data.mgmt_ip=ip.trim();
  const d=await post('dryrun',{op:'batch',table:'filter',data});
  if(!d.ok){ alert('Cannot build baseline: '+(d.error||'?')); return; }
  window._pending={op:'batch',data,existing:{}};
  document.getElementById('dr-desc').textContent=d.desc||''; document.getElementById('dr-cmd').textContent=d.cmd||'';
  document.getElementById('dr-rev').textContent=d.revert||''; document.getElementById('dr-safe').checked=true; show('dr-modal');
}

document.addEventListener('DOMContentLoaded',()=>{ if(window.NMLoader)NMLoader.hide(); loadRouters(); });
</script>
</body></html>
