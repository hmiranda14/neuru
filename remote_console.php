<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Federated Remote Console. From the MASTER, drive a remote slave site's
// WHOLE menu as if you were sitting in front of it: pick a site, pick any module,
// and its NATIVE page loads embedded read-only via the short-lived HMAC SSO token
// (no second login). Mirrors the local nav ($_nm_groups) so the operator sees the
// entire remote portal; each module is either embeddable now (allowlisted, audited
// no-secret-over-GET) or locked with the reason (action / secret / admin).
//
// Read-only by design: the fed bypass authorizes GET only, so every dashboard
// renders + auto-refreshes live, while writes (POST) stay blocked. Remote ACTIONS
// (restart a service, block an IP, run a probe) are a separate workstream — they
// flow through the cluster command queue (nm_cluster_cmd_enqueue), applied by the
// slave on its own tick, NOT through this embed. RBAC: 'federation'.
// Engine: nm_cluster.php + nm_fed_auth.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_cluster.php');
require_once('nm_fed_auth.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'federation')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=federation'); exit;
}
nm_cluster_ensure($conn);
$role    = (string)($_SESSION['role'] ?? 'guest');
$isAdmin = ($role === 'admin');
$uid     = (int)($_SESSION['UID'] ?? 0) ?: null;
$cfg  = nm_cluster_cfg($conn);
$selfSlug = (string)($cfg['site_slug'] ?? '');

// Phase-3 remote action catalog — the ONLY write path (the embed itself is GET-only).
// Each maps to a vetted engine the slave runs under its own privilege. Admin-only.
function nm_rc_actions(): array {
    return [
        'poll_now'    => ['label'=>'Re-poll node',        'scope'=>'node', 'icon'=>'fa-rotate',        'risk'=>'safe'],
        'svc_restart' => ['label'=>'Restart service',     'scope'=>'svc',  'icon'=>'fa-arrows-rotate', 'risk'=>'medium'],
        'block_ip'    => ['label'=>'Block IP / domain',   'scope'=>'site', 'icon'=>'fa-ban',           'risk'=>'medium'],
        'maintenance' => ['label'=>'Maintenance window',  'scope'=>'site', 'icon'=>'fa-screwdriver-wrench','risk'=>'safe'],
    ];
}

// ── API ──────────────────────────────────────────────────────────────────────
if ($api !== '') {
    if (function_exists('session_write_close')) @session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    try {
        // Mint a fresh embed URL for one module of one site (tokens are short-lived,
        // so we mint on click rather than at page load).
        if ($api === 'open') {
            $slug = nm_cluster_slugify((string)($_GET['site'] ?? ''));
            $page = basename((string)($_GET['page'] ?? ''));
            if (!nm_fed_page_allowed($page)) { echo json_encode(['ok'=>false,'error'=>'This module is not available for remote viewing.']); exit; }
            $isSelf = ($slug !== '' && $slug === $selfSlug);
            $site = null;
            foreach (nm_cluster_sites_visible($conn, $role) as $s) if ($s['site'] === $slug) { $site = $s; break; }
            if (!$site && !$isSelf) { echo json_encode(['ok'=>false,'error'=>'Site not found or not visible to your role.']); exit; }
            if ($isSelf) {
                $embed = '/' . $page . '?embed=1';
                $deep  = '/' . $page;
            } else {
                $embed = nm_fed_master_embed_url($conn, $slug, $page, 1800);
                $ep = rtrim((string)($site['endpoint'] ?? ''), '/');
                $deep = $ep !== '' ? $ep . '/' . $page : '';
                if ($embed === '') { echo json_encode(['ok'=>false,'error'=>'no_embed','deeplink'=>$deep]); exit; }
            }
            echo json_encode(['ok'=>true, 'embed_url'=>$embed, 'deeplink'=>$deep, 'page'=>$page, 'self'=>$isSelf]); exit;
        }
        // ── Phase-3 remote actions ──────────────────────────────────────────────
        // The site's device inventory (from its last rollup) — populates the node picker.
        if ($api === 'devices') {
            $slug = nm_cluster_slugify((string)($_GET['site'] ?? ''));
            $devs = [];
            foreach (nm_cluster_fed_devices($conn, $role, true) as $blk) {
                if ($blk['site'] !== $slug) continue;
                foreach ($blk['devices'] as $d) $devs[] = ['id'=>(int)($d['id'] ?? 0),'name'=>(string)($d['name'] ?? ''),'ip'=>(string)($d['ip'] ?? ''),'kind'=>(string)($d['kind'] ?? 'snmp'),'st'=>(string)($d['st'] ?? 'up')];
            }
            echo json_encode(['ok'=>true,'devices'=>$devs]); exit;
        }
        // Recent commands + per-site delivery (the results feed), filtered to the chosen site.
        if ($api === 'cmd_list') {
            $slug = nm_cluster_slugify((string)($_GET['site'] ?? ''));
            $rows = [];
            foreach (nm_cluster_cmd_list($conn, 40) as $c) {
                // per-command, this site's delivery status
                $d = @$conn->query("SELECT status,detail,TIMESTAMPDIFF(SECOND,acted_at,UTC_TIMESTAMP()) age FROM nm_cluster_cmd_delivery WHERE command_id=".(int)$c['id']." AND site_slug='".$conn->real_escape_string($slug)."' LIMIT 1");
                $dr = ($d && $d->num_rows) ? $d->fetch_assoc() : null;
                if (!$dr) continue;   // command not targeted at this site
                $rows[] = ['id'=>$c['id'],'type'=>$c['type'],'summary'=>$c['summary'],'age'=>$c['age'],
                    'status'=>$dr['status'],'detail'=>(string)($dr['detail'] ?? ''),'acted_age'=>$dr['age']!==null?(int)$dr['age']:null];
            }
            echo json_encode(['ok'=>true,'commands'=>$rows]); exit;
        }
        // Enqueue a remote action. Admin-only; validated + parameter-sanitized; audited by cmd_enqueue.
        if ($api === 'action') {
            if (!$isAdmin) { echo json_encode(['ok'=>false,'error'=>'Admin only — remote actions require the admin role.']); exit; }
            $body = json_decode(file_get_contents('php://input'), true) ?: $_POST;
            $slug = nm_cluster_slugify((string)($body['site'] ?? ''));
            $type = (string)($body['type'] ?? '');
            $cat  = nm_rc_actions();
            if (!isset($cat[$type])) { echo json_encode(['ok'=>false,'error'=>'Unknown action.']); exit; }
            $isSelf = ($slug !== '' && $slug === $selfSlug);
            $site = null; foreach (nm_cluster_sites_visible($conn, $role) as $s) if ($s['site'] === $slug) { $site = $s; break; }
            if (!$site && !$isSelf) { echo json_encode(['ok'=>false,'error'=>'Site not found or not visible.']); exit; }
            // build + validate the payload per action type
            $payload = [];
            if ($type === 'poll_now') {
                $nid = (int)($body['node_id'] ?? 0);
                if ($nid <= 0) { echo json_encode(['ok'=>false,'error'=>'Pick a node.']); exit; }
                $payload = ['node_id'=>$nid, 'summary'=>'Re-poll node #'.$nid];
            } elseif ($type === 'svc_restart') {
                $nid = (int)($body['node_id'] ?? 0);
                $kind = ($body['kind'] ?? '')==='windows' ? 'windows' : (($body['kind'] ?? '')==='linux' ? 'linux' : '');
                $svc  = substr(trim((string)($body['service'] ?? '')), 0, 80);
                if ($nid<=0 || !$kind || $svc==='') { echo json_encode(['ok'=>false,'error'=>'Node, OS and service name are required.']); exit; }
                if (!preg_match('/^[A-Za-z0-9 ._@\\-]{1,80}$/', $svc)) { echo json_encode(['ok'=>false,'error'=>'Service name has invalid characters.']); exit; }
                $payload = ['node_id'=>$nid,'kind'=>$kind,'service'=>$svc, 'summary'=>'Restart '.$svc.' on node #'.$nid];
            } elseif ($type === 'block_ip') {
                $ind = substr(trim((string)($body['indicator'] ?? '')), 0, 180);
                $it  = in_array(($body['ind_type'] ?? 'ip'), ['ip','domain','regex'], true) ? $body['ind_type'] : 'ip';
                if ($ind==='') { echo json_encode(['ok'=>false,'error'=>'Indicator required.']); exit; }
                $payload = ['indicator'=>$ind,'ind_type'=>$it,'severity'=>'high','reason'=>'Remote Console block','summary'=>$it.' '.$ind];
            } elseif ($type === 'maintenance') {
                $mins = max(1, min(1440, (int)($body['minutes'] ?? 30)));
                $nm   = substr(trim((string)($body['name'] ?? '')) ?: 'Remote maintenance', 0, 80);
                $payload = ['minutes'=>$mins,'name'=>$nm,'summary'=>$nm.' ('.$mins.'min)'];
            }
            $r = nm_cluster_cmd_enqueue($conn, $type, $payload, [$slug], $uid);
            if (!empty($r['ok']) && $isSelf) $r['own'] = nm_cluster_master_apply_own($conn);   // master's own site → apply now
            $r['delivery'] = $isSelf ? 'applied on this master' : 'queued — the site applies it on its next check-in (~1 min)';
            echo json_encode($r); exit;
        }
        echo json_encode(['ok'=>false,'error'=>'unknown api']);
    } catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>$e->getMessage()]); }
    exit;
}

log_user_action($conn, 'view_page', 'remote_console.php');

// Sites for the selector — visible slaves (+ self, so you can drive your own portal too).
$sites = nm_cluster_sites_visible($conn, $role);
$groups = nm_fed_module_groups();
$embeddable = 0; foreach ($groups as $g) foreach ($g['items'] as $it) if ($it['embed']) $embeddable++;
$preSite = nm_cluster_slugify((string)($_GET['site'] ?? ''));

include('header.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(12,16,26,.62); --border:rgba(255,255,255,.12); --accent:#4da3ff; --cyan:#36e3d0; --ok:#2ee66e; --warn:#f0a92c; --crit:#ff5a5a; }
html{ background:#05080f; } body{ margin:0; font-family:'Segoe UI',Tahoma,Geneva,sans-serif; background:transparent!important; color:#d4dce8; }
<?= nm_chrome_css() ?>
.rc{ display:flex; flex-direction:column; height:calc(100vh - 62px); min-height:560px; padding:12px 16px 14px; box-sizing:border-box; gap:11px; }
.rc *{ box-sizing:border-box; }
.glass{ background:var(--glass); backdrop-filter:blur(13px); border:1px solid var(--border); border-radius:14px; }
/* top bar */
.rcbar{ display:flex; align-items:center; gap:12px; padding:10px 15px; flex-wrap:wrap; flex:0 0 auto; }
.rcback{ display:inline-flex; align-items:center; gap:7px; color:#8aa2c4; text-decoration:none; font-size:12.5px; }
.rcback:hover{ color:var(--accent); }
.rctitle{ font-size:17px; font-weight:800; display:flex; align-items:center; gap:10px; color:#fff; }
.rctitle i{ color:var(--cyan); }
.rcsel{ display:flex; align-items:center; gap:8px; }
.rcsel select{ background:rgba(0,0,0,.4); border:1px solid var(--border); color:#e6edf7; border-radius:9px; padding:8px 12px; font-size:13px; min-width:190px; cursor:pointer; }
.sdot{ width:10px; height:10px; border-radius:50%; box-shadow:0 0 8px currentColor; flex:0 0 auto; }
.sdot.online{ color:#2ee66e; background:#2ee66e; } .sdot.stale{ color:#f0a92c; background:#f0a92c; } .sdot.offline,.sdot.never{ color:#ff5a5a; background:#ff5a5a; }
.robadge{ font-size:9.5px; font-weight:800; text-transform:uppercase; letter-spacing:.6px; padding:3px 9px; border-radius:20px; background:rgba(240,169,44,.15); border:1px solid rgba(240,169,44,.45); color:#ffd98a; display:inline-flex; align-items:center; gap:5px; }
.sp{ flex:1; }
.btn{ display:inline-flex; align-items:center; gap:7px; background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:8px 13px; font-size:12.5px; cursor:pointer; text-decoration:none; font-weight:600; }
.btn:hover{ border-color:var(--accent); color:#fff; } .btn:disabled{ opacity:.4; cursor:not-allowed; }
/* body split */
.rcbody{ display:flex; gap:11px; flex:1; min-height:0; }
.rail{ width:255px; flex:0 0 auto; display:flex; flex-direction:column; padding:11px; min-height:0; }
.railq{ width:100%; background:rgba(0,0,0,.4); border:1px solid var(--border); color:#e6edf7; border-radius:9px; padding:8px 11px; font-size:12.5px; margin-bottom:9px; flex:0 0 auto; }
.raillist{ overflow-y:auto; flex:1; margin:-3px; padding:3px; }
.rgrp{ margin-bottom:11px; }
.rgh{ font-size:9.5px; font-weight:800; text-transform:uppercase; letter-spacing:.7px; color:#7c8698; margin:4px 6px 6px; display:flex; align-items:center; gap:7px; }
.rgh i{ color:#4a5a72; }
.mod{ display:flex; align-items:center; gap:9px; padding:8px 10px; border-radius:9px; cursor:pointer; font-size:12.5px; color:#c4d0e0; border:1px solid transparent; margin-bottom:2px; user-select:none; }
.mod:hover{ background:rgba(77,163,255,.09); border-color:rgba(77,163,255,.22); color:#fff; }
.mod.on{ background:rgba(54,227,208,.14); border-color:rgba(54,227,208,.5); color:#bff3ec; }
.mod i.mic{ width:17px; text-align:center; color:#7fb2ff; flex:0 0 auto; }
.mod.on i.mic{ color:var(--cyan); }
.mod .ml{ flex:1; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.mod.locked{ cursor:not-allowed; color:#67728a; }
.mod.locked:hover{ background:rgba(255,255,255,.03); border-color:transparent; color:#8593a8; }
.mod.locked i.mic{ color:#4a5568; }
.lk{ font-size:9px; flex:0 0 auto; color:#5a6478; }
.lk.action{ color:#7d88a0; } .lk.secret{ color:#c46a6a; }
.railfoot{ flex:0 0 auto; font-size:10.5px; color:#6f7a8c; padding:9px 5px 2px; border-top:1px solid rgba(255,255,255,.06); margin-top:5px; line-height:1.5; }
/* stage */
.stage{ flex:1; position:relative; overflow:hidden; min-width:0; display:flex; flex-direction:column; }
.stagehd{ display:flex; align-items:center; gap:10px; padding:9px 14px; border-bottom:1px solid var(--border); flex:0 0 auto; font-size:12.5px; color:#aeb8c7; }
.stagehd b{ color:#fff; font-size:13.5px; }
.stagehd .rop{ margin-left:auto; display:flex; gap:8px; }
#rc-frame{ flex:1; width:100%; border:0; background:#05080f; display:block; min-height:0; }
.rc-empty{ flex:1; display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center; color:#7f93af; padding:30px; }
.rc-empty .ico{ width:96px; height:96px; border-radius:26px; display:grid; place-items:center; font-size:44px; background:rgba(77,163,255,.08); border:1px solid rgba(77,163,255,.22); color:#5b9bff; margin-bottom:20px; box-shadow:0 0 46px rgba(77,163,255,.16); }
.rc-empty h2{ margin:0 0 8px; color:#e6edf7; font-size:19px; font-weight:800; }
.rc-empty p{ margin:0; max-width:440px; font-size:13px; line-height:1.6; }
.rc-empty p b{ color:#cfe0f5; }
.rc-load{ position:absolute; inset:0; display:none; align-items:center; justify-content:center; flex-direction:column; gap:14px; background:rgba(5,8,15,.82); backdrop-filter:blur(3px); z-index:20; color:#9fb2c8; font-size:13px; }
.rc-spin{ width:44px; height:44px; border:3px solid rgba(77,163,255,.2); border-top-color:#4da3ff; border-radius:50%; animation:rcspin .8s linear infinite; }
@keyframes rcspin{ to{ transform:rotate(360deg); } }
#rc-stage-wrap:fullscreen,#rc-stage-wrap:-webkit-full-screen{ border-radius:0; }
/* toast */
#rc-toast{ position:fixed; bottom:22px; left:50%; transform:translateX(-50%) translateY(20px); background:rgba(16,22,34,.96); border:1px solid rgba(240,169,44,.45); color:#ffe0a3; padding:11px 17px; border-radius:11px; font-size:13px; z-index:9999; opacity:0; pointer-events:none; transition:.25s; max-width:520px; box-shadow:0 10px 40px rgba(0,0,0,.5); }
#rc-toast.show{ opacity:1; transform:translateX(-50%) translateY(0); }
#rc-toast i{ color:#f0a92c; margin-right:7px; }
@media(max-width:820px){ .rail{ width:200px; } .rc{ height:auto; } .rcbody{ flex-direction:column; } .stage{ min-height:70vh; } }
.btn.act{ background:linear-gradient(135deg,#f0a92c,#ff7a4d); border:none; color:#1a0f04; font-weight:800; }
/* actions drawer */
#actScrim{ position:fixed; inset:0; background:rgba(3,6,12,.55); backdrop-filter:blur(2px); z-index:900; display:none; }
#actDraw{ position:fixed; top:0; right:0; bottom:0; width:400px; max-width:94vw; z-index:901; transform:translateX(100%); transition:transform .28s cubic-bezier(.4,0,.2,1);
  background:rgba(10,14,23,.97); backdrop-filter:blur(16px); border-left:1px solid var(--border); display:flex; flex-direction:column; box-shadow:-18px 0 60px rgba(0,0,0,.5); }
#actDraw.open{ transform:translateX(0); }
.ad-hd{ display:flex; align-items:center; gap:11px; padding:15px 17px; border-bottom:1px solid var(--border); flex:0 0 auto; }
.ad-hd .t{ font-size:15px; font-weight:800; color:#fff; display:flex; align-items:center; gap:9px; } .ad-hd .t i{ color:#f0a92c; }
.ad-hd .x{ margin-left:auto; cursor:pointer; color:#8aa2c4; font-size:18px; padding:4px 8px; border-radius:7px; } .ad-hd .x:hover{ background:rgba(255,255,255,.08); color:#fff; }
.ad-body{ overflow-y:auto; padding:15px 17px; flex:1; }
.ad-site{ font-size:12px; color:#8aa2c4; margin-bottom:13px; } .ad-site b{ color:#cfe0f5; }
.ad-warn{ font-size:11.5px; color:#e9c98a; background:rgba(240,169,44,.1); border:1px solid rgba(240,169,44,.3); border-radius:9px; padding:9px 11px; margin-bottom:14px; line-height:1.5; }
.ad-l{ display:block; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8b95a7; margin:13px 0 6px; }
.ad-in,.ad-sel{ width:100%; background:rgba(0,0,0,.4); border:1px solid var(--border); color:#e6edf7; border-radius:9px; padding:9px 11px; font-size:13px; }
.ad-tabs{ display:grid; grid-template-columns:1fr 1fr; gap:7px; margin-bottom:4px; }
.ad-atab{ display:flex; align-items:center; gap:7px; padding:9px 10px; border:1px solid var(--border); border-radius:9px; cursor:pointer; font-size:12px; color:#c4d0e0; background:rgba(255,255,255,.02); }
.ad-atab:hover{ border-color:rgba(240,169,44,.4); color:#fff; } .ad-atab.on{ background:rgba(240,169,44,.14); border-color:rgba(240,169,44,.5); color:#ffd98a; }
.ad-atab i{ width:15px; text-align:center; }
.ad-risk{ font-size:9px; font-weight:800; text-transform:uppercase; padding:1px 6px; border-radius:20px; margin-left:auto; }
.ad-risk.safe{ background:rgba(46,230,110,.14); color:#8ff0b6; } .ad-risk.medium{ background:rgba(240,169,44,.16); color:#ffd98a; }
.ad-run{ width:100%; margin-top:18px; background:linear-gradient(135deg,#f0a92c,#ff7a4d); border:none; color:#1a0f04; font-weight:800; border-radius:10px; padding:12px; font-size:13.5px; cursor:pointer; display:flex; align-items:center; justify-content:center; gap:8px; }
.ad-run:hover{ filter:brightness(1.08); } .ad-run:disabled{ opacity:.5; cursor:not-allowed; }
.ad-msg{ margin-top:11px; font-size:12.5px; text-align:center; min-height:18px; }
.ad-feed{ border-top:1px solid var(--border); margin-top:6px; padding:14px 17px; flex:0 0 auto; max-height:42%; overflow-y:auto; }
.ad-feed .fh{ font-size:10px; text-transform:uppercase; letter-spacing:.6px; color:#8b95a7; margin-bottom:10px; display:flex; align-items:center; gap:7px; }
.cmd{ display:flex; gap:9px; padding:8px 9px; border:1px solid var(--border); border-left:3px solid #46516a; border-radius:8px; margin-bottom:6px; background:rgba(255,255,255,.02); }
.cmd.done{ border-left-color:#2ee66e; } .cmd.failed{ border-left-color:#ff5a5a; } .cmd.pending{ border-left-color:#f0a92c; }
.cmd .ci{ margin-top:2px; flex:0 0 auto; }
.cmd .ct{ font-size:12px; color:#e6edf7; line-height:1.35; } .cmd .cd{ font-size:10.5px; color:#8a97ab; margin-top:2px; word-break:break-word; }
.cmd .cst{ font-size:9px; font-weight:800; text-transform:uppercase; padding:1px 6px; border-radius:20px; margin-left:auto; flex:0 0 auto; height:fit-content; }
.cmd.done .cst{ background:rgba(46,230,110,.15); color:#8ff0b6; } .cmd.failed .cst{ background:rgba(255,90,90,.15); color:#ffb0b0; } .cmd.pending .cst{ background:rgba(240,169,44,.15); color:#ffd98a; }
.ad-empty{ color:#6f7a8c; font-size:12px; text-align:center; padding:16px; }
</style>

<div class="rc">
  <!-- TOP BAR -->
  <div class="glass rcbar">
    <a class="rcback" href="/federation.php"><i class="fa-solid fa-arrow-left"></i> Federation</a>
    <div class="rctitle"><i class="fa-solid fa-satellite-dish"></i> Remote Console</div>
    <div class="rcsel">
      <span class="sdot" id="sdot"></span>
      <select id="siteSel" onchange="pickSite()">
        <option value="">— choose a site —</option>
        <?php foreach ($sites as $s):
            $isSelf = ($s['site'] === $selfSlug);
            $lbl = $s['name'] . ($isSelf ? ' · this master' : '');
        ?>
        <option value="<?= htmlspecialchars($s['site']) ?>"
                data-status="<?= htmlspecialchars($s['status']) ?>"
                data-endpoint="<?= htmlspecialchars($s['endpoint'] ?? '') ?>"
                data-self="<?= $isSelf ? 1 : 0 ?>"
                <?= $s['site'] === $preSite ? 'selected' : '' ?>><?= htmlspecialchars($lbl) ?></option>
        <?php endforeach; ?>
      </select>
    </div>
    <span class="robadge"><i class="fa-solid fa-eye"></i> Read-only</span>
    <span class="sp"></span>
    <?php if ($isAdmin): ?>
    <button class="btn act" id="actBtn" onclick="toggleActions()"><i class="fa-solid fa-bolt"></i> Actions</button>
    <?php endif; ?>
    <a class="btn" id="openTab" target="_blank" rel="noopener" style="display:none"><i class="fa-solid fa-up-right-from-square"></i> Open in tab ↗</a>
    <button class="btn" id="fsBtn" onclick="rcFs()" disabled><i class="fa-solid fa-up-right-and-down-left-from-center"></i> Fullscreen</button>
  </div>

  <!-- BODY -->
  <div class="rcbody">
    <!-- MODULE RAIL -->
    <div class="glass rail">
      <input class="railq" id="railq" placeholder="🔍 filter modules…" oninput="filterMods()">
      <div class="raillist" id="raillist">
        <?php foreach ($groups as $g): ?>
        <div class="rgrp" data-grp>
          <div class="rgh"><i class="<?= htmlspecialchars($g['icon']) ?>"></i> <?= htmlspecialchars($g['name']) ?></div>
          <?php foreach ($g['items'] as $it):
              $lockTitle = $it['embed'] ? '' :
                  ($it['lock']==='secret' ? 'Not embeddable — this page can expose credentials over GET (excluded for security).' :
                  ($it['lock']==='admin'  ? 'Local site administration — out of scope for a remote read console.' :
                                            'View not available yet — this module performs actions on the device. Remote actions arrive in the command-queue phase.'));
          ?>
          <div class="mod <?= $it['embed'] ? '' : 'locked' ?>"
               data-page="<?= htmlspecialchars($it['file']) ?>"
               data-label="<?= htmlspecialchars($it['label']) ?>"
               data-embed="<?= $it['embed'] ? 1 : 0 ?>"
               data-lock="<?= htmlspecialchars($it['lock']) ?>"
               data-name="<?= htmlspecialchars(strtolower($it['label'])) ?>"
               title="<?= htmlspecialchars($lockTitle) ?>"
               onclick="clickMod(this)">
            <i class="mic <?= htmlspecialchars($it['icon']) ?>"></i>
            <span class="ml"><?= htmlspecialchars($it['label']) ?></span>
            <?php if (!$it['embed']): ?>
              <i class="fa-solid <?= $it['lock']==='secret'?'fa-lock':'fa-hand' ?> lk <?= htmlspecialchars($it['lock']) ?>"></i>
            <?php endif; ?>
          </div>
          <?php endforeach; ?>
        </div>
        <?php endforeach; ?>
      </div>
      <div class="railfoot"><i class="fa-solid fa-circle-info"></i> <?= $embeddable ?> modules viewable live. Locked ones (<i class="fa-solid fa-hand" style="color:#7d88a0"></i> action / <i class="fa-solid fa-lock" style="color:#c46a6a"></i> secret) are handled by the remote-action phase.</div>
    </div>

    <!-- STAGE -->
    <div class="glass stage" id="rc-stage-wrap">
      <div class="stagehd" id="stagehd" style="display:none">
        <i class="fa-solid fa-window-maximize" id="stg-ic"></i>
        <b id="stg-title">—</b>
        <span id="stg-site" style="color:#8aa2c4"></span>
        <div class="rop"><span class="robadge"><i class="fa-solid fa-eye"></i> Live · read-only</span></div>
      </div>
      <div class="rc-empty" id="rc-empty">
        <div class="ico"><i class="fa-solid fa-satellite-dish"></i></div>
        <h2>Drive a remote site as if you were there</h2>
        <p><?php if (empty($sites)): ?>
          No remote sites are registered yet. Add one in <b>Federation → Sites</b>, then it appears here with its full menu.
          <?php else: ?>
          Pick a <b>site</b> above, then any <b>module</b> from the rail — its native page loads here, live and read-only, with no second login. Your browser embeds the remote portal directly (it must be able to reach that site's URL).
          <?php endif; ?></p>
      </div>
      <iframe id="rc-frame" allow="fullscreen" style="display:none"></iframe>
      <div class="rc-load" id="rc-load"><div class="rc-spin"></div><div>Establishing secure remote view…</div></div>
    </div>
  </div>
</div>

<?php if ($isAdmin): $ACTS = nm_rc_actions(); ?>
<div id="actScrim" onclick="toggleActions(false)"></div>
<aside id="actDraw" aria-hidden="true">
  <div class="ad-hd">
    <div class="t"><i class="fa-solid fa-bolt"></i> Remote Actions</div>
    <span class="x" onclick="toggleActions(false)">✕</span>
  </div>
  <div class="ad-body">
    <div class="ad-site">Target site: <b id="ad-sitename">—</b></div>
    <div class="ad-warn"><i class="fa-solid fa-shield-halved"></i> These are the only <b>write</b> operations here. Each runs the site's own vetted engine and is <b>audited</b>. Remote sites apply it on their next check-in (~1&nbsp;min) and report the result back below.</div>

    <div class="ad-l">Action</div>
    <div class="ad-tabs" id="ad-tabs">
      <?php foreach ($ACTS as $k => $a): ?>
      <div class="ad-atab" data-act="<?= htmlspecialchars($k) ?>" data-scope="<?= htmlspecialchars($a['scope']) ?>" onclick="pickAct(this)">
        <i class="fa-solid <?= htmlspecialchars($a['icon']) ?>"></i> <span><?= htmlspecialchars($a['label']) ?></span>
        <span class="ad-risk <?= htmlspecialchars($a['risk']) ?>"><?= htmlspecialchars($a['risk']) ?></span>
      </div>
      <?php endforeach; ?>
    </div>

    <!-- per-action forms -->
    <div id="af-poll_now" class="af" style="display:none">
      <div class="ad-l">Node</div>
      <select class="ad-sel" id="pn-node"><option value="">— loading devices —</option></select>
      <div style="font-size:11.5px;color:#7f93af;margin-top:7px">Forces an immediate re-poll and reports the device's live verdict.</div>
    </div>
    <div id="af-svc_restart" class="af" style="display:none">
      <div class="ad-l">Host (node)</div>
      <select class="ad-sel" id="sr-node"><option value="">— loading devices —</option></select>
      <div class="ad-l">OS</div>
      <select class="ad-sel" id="sr-kind"><option value="linux">Linux (systemctl)</option><option value="windows">Windows (Restart-Service)</option></select>
      <div class="ad-l">Service name</div>
      <input class="ad-in" id="sr-svc" placeholder="e.g. nginx  ·  Spooler" autocomplete="off">
      <div style="font-size:11.5px;color:#7f93af;margin-top:7px">Read the exact service name from the site's <b>Service Watchdog</b> / Linux / Windows page (embed it first).</div>
    </div>
    <div id="af-block_ip" class="af" style="display:none">
      <div class="ad-l">Type</div>
      <select class="ad-sel" id="bi-type"><option value="ip">IP address</option><option value="domain">Domain</option><option value="regex">Regex</option></select>
      <div class="ad-l">Indicator</div>
      <input class="ad-in" id="bi-ind" placeholder="45.140.17.9  ·  bad-domain.com" autocomplete="off">
      <div style="font-size:11.5px;color:#7f93af;margin-top:7px">Blocks fleet-wide at the site via its own Collective Immunity (Pi-holes + firewalls).</div>
    </div>
    <div id="af-maintenance" class="af" style="display:none">
      <div class="ad-l">Silence alerts for (minutes)</div>
      <input class="ad-in" id="mw-min" type="number" min="1" max="1440" value="30">
      <div class="ad-l">Label</div>
      <input class="ad-in" id="mw-name" placeholder="Remote maintenance" autocomplete="off">
      <div style="font-size:11.5px;color:#7f93af;margin-top:7px">Opens a maintenance window now → suppresses every alert at that site for the duration.</div>
    </div>

    <button class="ad-run" id="ad-run" onclick="runAction()" disabled><i class="fa-solid fa-bolt"></i> <span>Choose an action</span></button>
    <div class="ad-msg" id="ad-msg"></div>
  </div>
  <div class="ad-feed">
    <div class="fh"><i class="fa-solid fa-list-check"></i> Results for this site <span style="margin-left:auto;font-size:10px;color:#5f6b80" id="ad-feed-t"></span></div>
    <div id="ad-feed-list"><div class="ad-empty">No remote actions yet.</div></div>
  </div>
</aside>
<?php endif; ?>

<div id="rc-toast"><i class="fa-solid fa-triangle-exclamation"></i><span id="rc-toast-msg"></span></div>

<script>
const SELF_SLUG=<?= json_encode($selfSlug) ?>;
let CUR_SITE='', CUR_PAGE='', CUR_DEEP='';
const E=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

function toast(msg){ const t=document.getElementById('rc-toast'); document.getElementById('rc-toast-msg').innerHTML=msg;
  t.classList.add('show'); clearTimeout(window._tt); window._tt=setTimeout(()=>t.classList.remove('show'),4200); }

function selOpt(){ const s=document.getElementById('siteSel'); return s.options[s.selectedIndex]; }
function pickSite(){
  const o=selOpt(); CUR_SITE=o.value||'';
  const dot=document.getElementById('sdot');
  dot.className='sdot '+(o.dataset.status||'');
  // reset the stage
  CUR_PAGE=''; CUR_DEEP='';
  document.querySelectorAll('.mod.on').forEach(m=>m.classList.remove('on'));
  const f=document.getElementById('rc-frame'); f.style.display='none'; f.src='about:blank';
  document.getElementById('stagehd').style.display='none';
  document.getElementById('openTab').style.display='none';
  document.getElementById('fsBtn').disabled=true;
  const emp=document.getElementById('rc-empty'); emp.style.display='flex';
  if(CUR_SITE){ emp.querySelector('h2').textContent=o.textContent.trim();
    emp.querySelector('p').innerHTML='Pick any <b>module</b> from the rail to open its live view for <b>'+E(o.textContent.trim())+'</b>.'; }
  // remember selection in URL (no reload)
  try{ history.replaceState(null,'', CUR_SITE?('?site='+encodeURIComponent(CUR_SITE)):location.pathname); }catch(e){}
}

function clickMod(el){
  if(el.dataset.embed!=='1'){
    const lk=el.dataset.lock;
    toast(lk==='secret'
      ? '<b>'+E(el.dataset.label)+'</b> can expose credentials over GET — excluded from remote view for security.'
      : '<b>'+E(el.dataset.label)+'</b> performs actions on the device. Remote actions arrive in the command-queue phase — viewing isn\'t available yet.');
    return;
  }
  if(!CUR_SITE){ toast('Choose a <b>site</b> first.'); return; }
  const page=el.dataset.page, label=el.dataset.label;
  document.querySelectorAll('.mod.on').forEach(m=>m.classList.remove('on'));
  el.classList.add('on');
  loadModule(page,label,el.querySelector('.mic').className);
}

async function loadModule(page,label,iconClass){
  CUR_PAGE=page;
  document.getElementById('rc-empty').style.display='none';
  document.getElementById('rc-load').style.display='flex';
  const hd=document.getElementById('stagehd'); hd.style.display='flex';
  document.getElementById('stg-title').textContent=label;
  const o=selOpt(); document.getElementById('stg-site').textContent='· '+o.textContent.trim();
  const ic=document.getElementById('stg-ic'); ic.className=(iconClass||'fa-solid fa-window-maximize').replace('mic ','')+'';
  document.getElementById('fsBtn').disabled=false;
  const r=await fetch('remote_console.php?api=open&site='+encodeURIComponent(CUR_SITE)+'&page='+encodeURIComponent(page)+'&_='+Date.now())
    .then(x=>x.json()).catch(()=>null);
  document.getElementById('rc-load').style.display='none';
  if(!r||!r.ok){
    if(r&&r.error==='no_embed'){
      CUR_DEEP=r.deeplink||'';
      showNoEmbed(o.textContent.trim(), CUR_DEEP);
      return;
    }
    toast((r&&r.error)?E(r.error):'Could not open that module.');
    document.getElementById('rc-empty').style.display='flex';
    document.getElementById('stagehd').style.display='none';
    return;
  }
  CUR_DEEP=r.deeplink||'';
  const f=document.getElementById('rc-frame');
  f.style.display='block'; f.src=r.embed_url;
  const ot=document.getElementById('openTab');
  if(CUR_DEEP){ ot.href=CUR_DEEP; ot.style.display=''; } else ot.style.display='none';
}

function showNoEmbed(siteName, deep){
  const f=document.getElementById('rc-frame'); f.style.display='none';
  const emp=document.getElementById('rc-empty'); emp.style.display='flex';
  emp.querySelector('.ico').innerHTML='<i class="fa-solid fa-link-slash"></i>';
  emp.querySelector('h2').textContent='No embed link for '+siteName;
  emp.querySelector('p').innerHTML='Set this site\'s <b>Portal URL</b> in <b>Federation → Sites</b> (the base URL of that slave portal), then reopen — its live view loads here with no second login.'
    +(deep?' Meanwhile you can <a href="'+E(deep)+'" target="_blank" rel="noopener" style="color:#4da3ff">open it in a tab ↗</a>.':'');
  document.getElementById('openTab').style.display='none';
  document.getElementById('fsBtn').disabled=true;
}

function filterMods(){
  const q=document.getElementById('railq').value.trim().toLowerCase();
  document.querySelectorAll('#raillist [data-grp]').forEach(g=>{
    let any=false;
    g.querySelectorAll('.mod').forEach(m=>{ const hit=!q||m.dataset.name.includes(q); m.style.display=hit?'':'none'; if(hit)any=true; });
    g.style.display=any?'':'none';
  });
}

function rcFs(){ const w=document.getElementById('rc-stage-wrap');
  if(document.fullscreenElement){ document.exitFullscreen(); return; }
  (w.requestFullscreen||w.webkitRequestFullscreen||function(){}).call(w); }

// ── Phase-3 Remote Actions drawer ─────────────────────────────────────────
let CUR_ACT='', FEED_TIMER=null, DEVS=[];
const hasActions=!!document.getElementById('actDraw');

function toggleActions(force){
  const d=document.getElementById('actDraw'); if(!d) return;
  const open = force===undefined ? !d.classList.contains('open') : !!force;
  if(open && !CUR_SITE){ toast('Choose a <b>site</b> first, then run actions on it.'); return; }
  d.classList.toggle('open',open); document.getElementById('actScrim').style.display=open?'block':'none';
  d.setAttribute('aria-hidden', open?'false':'true');
  if(open){
    document.getElementById('ad-sitename').textContent=selOpt().textContent.trim();
    loadDevices(); loadFeed();
    clearInterval(FEED_TIMER); FEED_TIMER=setInterval(loadFeed, 8000);
  } else { clearInterval(FEED_TIMER); FEED_TIMER=null; }
}

function pickAct(el){
  CUR_ACT=el.dataset.act;
  document.querySelectorAll('#ad-tabs .ad-atab').forEach(t=>t.classList.toggle('on',t===el));
  document.querySelectorAll('.af').forEach(f=>f.style.display='none');
  const form=document.getElementById('af-'+CUR_ACT); if(form) form.style.display='block';
  const btn=document.getElementById('ad-run'); btn.disabled=false;
  btn.querySelector('span').textContent='Run: '+el.querySelector('span').textContent;
  document.getElementById('ad-msg').textContent='';
}

async function loadDevices(){
  if(!CUR_SITE) return;
  const r=await fetch('remote_console.php?api=devices&site='+encodeURIComponent(CUR_SITE)+'&_='+Date.now()).then(x=>x.json()).catch(()=>null);
  DEVS=(r&&r.ok&&r.devices)?r.devices:[];
  const opt='<option value="">'+(DEVS.length?'— pick a node —':'— no devices reported —')+'</option>'
    +DEVS.map(d=>'<option value="'+d.id+'" data-kind="'+E(d.kind)+'">'+E(d.name||('#'+d.id))+(d.ip?(' · '+E(d.ip)):'')+'</option>').join('');
  ['pn-node','sr-node'].forEach(id=>{ const s=document.getElementById(id); if(s) s.innerHTML=opt; });
  // auto-set OS from node kind on the restart form
  const srn=document.getElementById('sr-node');
  if(srn) srn.onchange=function(){ const k=this.options[this.selectedIndex]?.dataset.kind; const ks=document.getElementById('sr-kind');
    if(k==='windows'||k==='linux') ks.value=k; };
}

async function runAction(){
  if(!CUR_ACT||!CUR_SITE) return;
  const body={site:CUR_SITE,type:CUR_ACT};
  if(CUR_ACT==='poll_now'){ body.node_id=+document.getElementById('pn-node').value||0; if(!body.node_id) return acMsg('Pick a node.','#ffb0b0'); }
  else if(CUR_ACT==='svc_restart'){ body.node_id=+document.getElementById('sr-node').value||0; body.kind=document.getElementById('sr-kind').value; body.service=document.getElementById('sr-svc').value.trim();
    if(!body.node_id) return acMsg('Pick a host.','#ffb0b0'); if(!body.service) return acMsg('Enter the service name.','#ffb0b0');
    if(!confirm('Restart "'+body.service+'" on the selected host at '+selOpt().textContent.trim()+'?')) return; }
  else if(CUR_ACT==='block_ip'){ body.indicator=document.getElementById('bi-ind').value.trim(); body.ind_type=document.getElementById('bi-type').value;
    if(!body.indicator) return acMsg('Enter an indicator.','#ffb0b0'); }
  else if(CUR_ACT==='maintenance'){ body.minutes=+document.getElementById('mw-min').value||30; body.name=document.getElementById('mw-name').value.trim(); }
  const btn=document.getElementById('ad-run'); btn.disabled=true;
  acMsg('<i class="fa-solid fa-spinner fa-spin"></i> Queuing…','#9fb2c8');
  const r=await fetch('remote_console.php?api=action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(x=>x.json()).catch(()=>null);
  btn.disabled=false;
  if(r&&r.ok){ acMsg('<i class="fa-solid fa-check"></i> '+E(r.delivery||'queued'),'#8ff0b6');
    if(CUR_ACT==='svc_restart')document.getElementById('sr-svc').value='';
    if(CUR_ACT==='block_ip')document.getElementById('bi-ind').value='';
    setTimeout(loadFeed,700); }
  else acMsg('<i class="fa-solid fa-xmark"></i> '+E((r&&r.error)||'failed'),'#ffb0b0');
}
function acMsg(html,col){ const m=document.getElementById('ad-msg'); m.innerHTML=html; m.style.color=col||'#9fb2c8'; }

async function loadFeed(){
  if(!CUR_SITE) return;
  const r=await fetch('remote_console.php?api=cmd_list&site='+encodeURIComponent(CUR_SITE)+'&_='+Date.now()).then(x=>x.json()).catch(()=>null);
  const wrap=document.getElementById('ad-feed-list'); if(!wrap) return;
  const cmds=(r&&r.ok&&r.commands)?r.commands:[];
  document.getElementById('ad-feed-t').textContent=cmds.length?(cmds.length+' recent'):'';
  if(!cmds.length){ wrap.innerHTML='<div class="ad-empty">No remote actions yet for this site.</div>'; return; }
  const ICO={poll_now:'fa-rotate',svc_restart:'fa-arrows-rotate',block_ip:'fa-ban',maintenance:'fa-screwdriver-wrench'};
  const ago=s=>s==null?'':(s<60?s+'s':s<3600?Math.round(s/60)+'m':Math.round(s/3600)+'h')+' ago';
  wrap.innerHTML=cmds.map(c=>{ const st=c.status||'pending';
    return '<div class="cmd '+st+'"><i class="fa-solid '+(ICO[c.type]||'fa-bolt')+' ci" style="color:#f0a92c"></i>'
      +'<div style="flex:1"><div class="ct">'+E(c.summary||c.type)+'</div>'
      +(c.detail?('<div class="cd">'+E(c.detail)+'</div>'):'')
      +'<div class="cd" style="color:#5f6b80">'+E(ago(st==='pending'?c.age:c.acted_age))+'</div></div>'
      +'<span class="cst">'+E(st)+'</span></div>'; }).join('');
}

// keep the drawer in sync when the site changes
const _pickSite=pickSite;
pickSite=function(){ _pickSite.apply(this,arguments);
  if(hasActions && document.getElementById('actDraw').classList.contains('open')){
    if(!CUR_SITE){ toggleActions(false); }
    else { document.getElementById('ad-sitename').textContent=selOpt().textContent.trim(); loadDevices(); loadFeed(); }
  }
};

// preselect from ?site=
if(document.getElementById('siteSel').value) pickSite();
</script>
<?php // end remote_console.php ?>
