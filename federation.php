<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Federation cockpit (Phase 1). Overview of every site in the cluster
// (filtered by the viewer's role visibility) + admin config: set this install's
// role (standalone|master|slave), its site identity, register slave sites (with
// per-site tokens), and the role→site visibility policy. Engine: nm_cluster.php.
// RBAC: 'federation' (overview). Admin-only for the Sites/Visibility/Setup tabs.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once __DIR__.'/nm_maptiles.php';   // shared keyless basemap (CARTO now needs a key)
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_cluster.php');
require_once('nm_incidents.php');   // nm_inc_set_status for the federated desk
require_once('nm_audit.php');
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

if ($api !== '') {
    if (function_exists('session_write_close')) @session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    $body = json_decode(file_get_contents('php://input'), true) ?: $_POST;
    $adminOnly = function() use ($isAdmin) { if (!$isAdmin) { echo json_encode(['ok'=>false,'error'=>'admin only']); exit; } };
    try {
        // Master-only, throttled, self-ignores on slave/standalone: keeps the master's OWN
        // site fresh while viewed so it never shows "stale" against itself if the cron lagged.
        if (in_array($api, ['overview','wall','devices','fed_devices','fedincidents'], true)) nm_cluster_self_refresh($conn);
        // ── viewer-facing ──
        if ($api === 'overview') {
            $cfg = nm_cluster_cfg($conn);
            // A SLAVE sees only ITSELF (its own rollup) + its sync status to the master — by design,
            // the fleet view lives on the master. The master sees the whole cluster.
            if ($cfg['role'] === 'slave') {
                $roll = nm_cluster_build_rollup($conn);
                $lastOk  = nm_cluster_setting($conn, 'cluster_last_push_ok', '');
                $lastErr = nm_cluster_setting($conn, 'cluster_last_push_err', '');
                $buffered = 0; $q = @$conn->query("SELECT COUNT(*) c FROM nm_cluster_outbox"); if ($q) $buffered = (int)$q->fetch_assoc()['c'];
                $okAge = $lastOk ? (time() - strtotime($lastOk . ' UTC')) : null;
                $status = ($okAge !== null && $okAge < 150 && $buffered === 0) ? 'online' : ($buffered > 0 ? 'stale' : 'offline');
                $self = ['site'=>$cfg['site_slug'] ?: 'this-site', 'name'=>$cfg['site_name'] ?: 'This site',
                    'status'=>$status, 'age'=>$okAge, 'self'=>1, 'lat'=>null, 'lon'=>null,
                    'nodes'=>$roll['nodes'], 'incidents'=>$roll['incidents']];
                echo json_encode(['ok'=>true, 'role'=>'slave', 'sites'=>[$self],
                    'sync'=>['status'=>$status, 'last_ok'=>$lastOk, 'last_err'=>$lastErr, 'buffered'=>$buffered, 'master'=>$cfg['master_url']]]); exit;
            }
            echo json_encode(['ok'=>true, 'role'=>$cfg['role'], 'sites'=>nm_cluster_sites_visible($conn, $role)]); exit;
        }
        if ($api === 'wall') { echo json_encode(['ok'=>true] + nm_cluster_wall($conn, $role)); exit; }
        if ($api === 'fedincidents') {
            // federated incidents = the master's cluster-sourced incidents, filtered by visibility
            $visible = null;
            if ($role !== 'admin') { $visible = []; foreach (nm_cluster_sites_visible($conn,$role) as $s) $visible[$s['site']] = 1; }
            $incs = []; $pat = [];
            $r = $conn->query("SELECT id,corr_key,title,severity,status,root_entity, TIMESTAMPDIFF(SECOND,opened_at,NOW()) age
                FROM nm_incidents WHERE root_source='cluster' AND (status IN('open','acknowledged') OR resolved_at > (NOW()-INTERVAL 2 HOUR))
                ORDER BY FIELD(severity,'critical','warning','info'), (status='open') DESC, updated_at DESC LIMIT 200");
            while ($r && ($x = $r->fetch_assoc())) {
                $slug = preg_match('/^cluster:(?:down|inc):([a-z0-9_-]+)/', $x['corr_key'], $m) ? $m[1] : '';
                if ($visible !== null && $slug !== '' && !isset($visible[$slug])) continue;
                $isDown = strpos($x['corr_key'], 'cluster:down:') === 0;
                $nt = $isDown ? '' : preg_replace('/^\[[^\]]*\]\s*/', '', (string)$x['title']);
                $incs[] = ['id'=>(int)$x['id'],'site'=>$x['root_entity'],'title'=>$x['title'],'severity'=>$x['severity'],'status'=>$x['status'],'age'=>(int)$x['age'],'down'=>$isDown?1:0];
                if (!$isDown && $nt !== '') { $pat[$nt]['sites'][$x['root_entity']] = 1; $pat[$nt]['sev'] = $x['severity']; }
            }
            $patterns = [];
            foreach ($pat as $t => $p) if (count($p['sites']) >= 2) $patterns[] = ['title'=>$t,'sites'=>array_keys($p['sites']),'count'=>count($p['sites']),'severity'=>$p['sev']];
            echo json_encode(['ok'=>true,'incidents'=>$incs,'patterns'=>$patterns]); exit;
        }
        if ($api === 'tt_range') { echo json_encode(['ok'=>true] + nm_cluster_tt_range($conn)); exit; }
        if ($api === 'tt_at')    { $at = (int)($_GET['at'] ?? $body['at'] ?? 0); echo json_encode(['ok'=>true,'at'=>$at,'sites'=>nm_cluster_tt_at($conn,$at,$role)]); exit; }
        if ($api === 'fed_devices') {   // federated device inventory (per site). scope=strip → remote sites only (for net_mon.php)
            $scope = (string)($_GET['scope'] ?? $body['scope'] ?? 'full');
            echo json_encode(['ok'=>true, 'scope'=>$scope, 'sites'=>nm_cluster_fed_devices($conn, $role, $scope !== 'strip')]); exit;
        }
        if ($api === 'fed_device') {    // one remote device: meta + accumulated history + deep-link
            $d = nm_cluster_fed_device($conn, $role, (string)($_GET['site'] ?? ''), (int)($_GET['id'] ?? 0), (int)($_GET['hours'] ?? 24));
            if (!$d) { echo json_encode(['ok'=>false,'error'=>'device not found or not visible']); exit; }
            echo json_encode(['ok'=>true] + $d); exit;
        }
        if ($api === 'inc_status') {
            $adminOnly();
            $id = (int)($body['id'] ?? 0); $to = ($body['status'] ?? '') === 'resolved' ? 'resolved' : 'acknowledged';
            nm_inc_set_status($conn, $id, $to, (string)($_SESSION['username'] ?? 'admin'));
            nm_audit($conn, 'cluster.inc_'.$to, ['target_type'=>'incident','target_id'=>$id]);
            echo json_encode(['ok'=>true]); exit;
        }
        // ── admin ──
        if ($api === 'cfg')     { $adminOnly(); echo json_encode(['ok'=>true,'cfg'=>nm_cluster_cfg($conn)]); exit; }
        if ($api === 'save_cfg') {
            $adminOnly();
            $r = ($body['cluster_role'] ?? '') ; if (in_array($r, ['standalone','master','slave'], true)) nm_cluster_set($conn,'cluster_role',$r);
            if (isset($body['site_slug'])) nm_cluster_set($conn,'cluster_site_slug', nm_cluster_slugify((string)$body['site_slug']));
            if (isset($body['site_name'])) nm_cluster_set($conn,'cluster_site_name', substr(trim((string)$body['site_name']),0,120));
            if (isset($body['master_url'])) {
                $mu = rtrim(trim((string)$body['master_url']),'/');
                if ($mu !== '' && !preg_match('#^https?://#i', $mu)) { echo json_encode(['ok'=>false,'error'=>'master URL must start with http:// or https://']); exit; }
                nm_cluster_set($conn,'cluster_master_url', $mu);
            }
            if (!empty($body['token'])) nm_cluster_my_token_set($conn, trim((string)$body['token']));
            nm_audit($conn,'cluster.save_cfg',['details'=>['role'=>$r]]);
            echo json_encode(['ok'=>true,'cfg'=>nm_cluster_cfg($conn)]); exit;
        }
        if ($api === 'push_now') {   // slave: force a rollup push (test the link)
            $adminOnly(); echo json_encode(nm_cluster_push($conn)); exit;
        }
        if ($api === 'health') { $adminOnly(); echo json_encode(['ok'=>true] + nm_cluster_health($conn)); exit; }
        if ($api === 'probe')  { $adminOnly(); echo json_encode(['ok'=>true,'probe'=>nm_cluster_probe_master($conn)]); exit; }
        if ($api === 'enroll') { $adminOnly(); echo json_encode(nm_cluster_enroll_apply($conn, (string)($body['code'] ?? ''))); exit; }
        if ($api === 'enroll_code') { $adminOnly();
            $mu = trim((string)($body['master_url'] ?? ''));
            if ($mu === '') { $sch = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http'; $mu = $sch . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost'); }
            echo json_encode(nm_cluster_enroll_code($conn, (int)($body['id'] ?? 0), $mu)); exit;
        }
        if ($api === 'sites')      { $adminOnly(); echo json_encode(['ok'=>true,'sites'=>nm_cluster_sites($conn)]); exit; }
        if ($api === 'site_save')  { $adminOnly(); echo json_encode(nm_cluster_site_upsert($conn,$body,$uid)); exit; }
        if ($api === 'site_token') { $adminOnly(); echo json_encode(nm_cluster_site_token_reset($conn,(int)($body['id']??0))); exit; }
        if ($api === 'site_delete'){ $adminOnly(); echo json_encode(nm_cluster_site_delete($conn,(int)($body['id']??0))); exit; }
        if ($api === 'cmd_list')   { $adminOnly(); echo json_encode(['ok'=>true,'commands'=>nm_cluster_cmd_list($conn,30)]); exit; }
        if ($api === 'cmd_block')  {
            $adminOnly();
            $ind = trim((string)($body['indicator'] ?? ''));
            $itype = in_array(($body['ind_type'] ?? 'ip'), ['ip','domain','regex'], true) ? $body['ind_type'] : 'ip';
            if ($ind === '') { echo json_encode(['ok'=>false,'error'=>'indicator required']); exit; }
            $sites = (($body['scope'] ?? 'all') === 'all') ? ['*'] : (array)($body['sites'] ?? []);
            $r = nm_cluster_cmd_enqueue($conn, 'block_ip', ['indicator'=>$ind,'ind_type'=>$itype,'reason'=>substr((string)($body['reason'] ?? 'blocked from Federation'),0,180),'severity'=>'high','summary'=>$itype.' '.$ind], $sites, $uid);
            if (!empty($r['ok'])) $r['own'] = nm_cluster_master_apply_own($conn);   // apply to the master right away
            echo json_encode($r); exit;
        }
        if ($api === 'roles')      { $adminOnly(); $rs=[]; $r=$conn->query("SELECT DISTINCT role_name FROM role_profiles WHERE role_name<>'admin' ORDER BY role_name"); while($r&&($x=$r->fetch_row()))$rs[]=$x[0]; echo json_encode(['ok'=>true,'roles'=>$rs,'sites'=>array_map(fn($s)=>['slug'=>$s['site'],'name'=>$s['name']],nm_cluster_sites($conn)),'visibility'=>nm_cluster_visibility_all($conn)]); exit; }
        if ($api === 'vis_set')    { $adminOnly(); echo json_encode(nm_cluster_visibility_set($conn,(string)($body['role']??''),(array)($body['sites']??[]))); exit; }
        echo json_encode(['ok'=>false,'error'=>'unknown api']);
    } catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>$e->getMessage()]); }
    exit;
}

log_user_action($conn,'view_page','federation.php');
$cfg = nm_cluster_cfg($conn);
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<script src="/leaflet.min.js"></script>
<style>
:root{ --glass:rgba(12,16,26,.62); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ee66e; --warn:#f0a92c; --crit:#ff5a5a; --cyan:#36e3d0; }
html{ background:#05080f; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#d4dce8; }
<?= nm_chrome_css() ?>
.fd{ max-width:1240px; margin:0 auto; padding:18px 20px 60px; } .fd *{ box-sizing:border-box; }
.glass{ background:var(--glass); backdrop-filter:blur(13px); border:1px solid var(--border); border-radius:14px; }
.bar{ display:flex; align-items:center; gap:13px; padding:13px 18px; margin-bottom:16px; flex-wrap:wrap; }
.title{ font-size:19px; font-weight:800; display:flex; align-items:center; gap:11px; } .title i{ color:#36e3d0; }
.rolechip{ font-size:10px; font-weight:800; text-transform:uppercase; letter-spacing:.6px; padding:3px 10px; border-radius:20px; }
.rolechip.master{ background:rgba(54,227,208,.16); color:#7ff0e4; } .rolechip.slave{ background:rgba(77,163,255,.16); color:#bcd8ff; } .rolechip.standalone{ background:rgba(255,255,255,.08); color:#aeb8c7; }
.tabs{ display:flex; gap:6px; margin-left:auto; flex-wrap:wrap; } .tab{ padding:8px 14px; border-radius:9px; border:1px solid var(--border); cursor:pointer; font-size:13px; color:#aeb8c7; } .tab.on{ background:rgba(54,227,208,.14); border-color:rgba(54,227,208,.45); color:#bff3ec; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:9px 14px; font-size:13px; cursor:pointer; }
.btn:hover{ border-color:var(--accent); color:#fff; } .btn.g{ background:linear-gradient(135deg,#36e3d0,#4da3ff); border:none; color:#04121a; font-weight:700; } .btn.sm{ padding:6px 9px; font-size:12px; } .btn.danger{ border-color:rgba(255,90,90,.45); color:#ff9b91; }
.grid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:14px; }
.site{ padding:16px 18px; position:relative; border-left:3px solid #46516a; }
.site.online{ border-left-color:#2ee66e; } .site.stale{ border-left-color:#f0a92c; } .site.offline,.site.never{ border-left-color:#ff5a5a; }
.site h3{ margin:0 0 3px; font-size:16px; display:flex; align-items:center; gap:9px; } .site .slug{ font-family:monospace; font-size:10.5px; color:#7c8698; }
.stat{ position:absolute; top:15px; right:16px; font-size:9.5px; font-weight:800; text-transform:uppercase; letter-spacing:.5px; padding:3px 9px; border-radius:20px; }
.stat.online{ background:rgba(46,230,110,.16); color:#8ff0b6; } .stat.stale{ background:rgba(240,169,44,.16); color:#ffd98a; } .stat.offline,.stat.never{ background:rgba(255,90,90,.16); color:#ffb0b0; }
.metrics{ display:flex; gap:18px; margin:14px 0 4px; } .metric .n{ font-size:22px; font-weight:800; } .metric .l{ font-size:9.5px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; }
.bar2{ height:5px; border-radius:4px; background:rgba(255,255,255,.08); overflow:hidden; margin-top:10px; display:flex; }
.bar2 i{ height:100%; } .seen{ font-size:11px; color:#8a909a; margin-top:9px; }
.muted{ color:#8a909a; font-size:12.5px; } .dim{ color:#6f7a8c; } .empty{ text-align:center; color:#6f7a8c; padding:56px 20px; } .empty i{ font-size:44px; display:block; margin-bottom:14px; color:#2a4a5e; }
table{ width:100%; border-collapse:collapse; font-size:13px; } th{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; padding:9px 11px; border-bottom:1px solid var(--border); } td{ padding:9px 11px; border-bottom:1px solid rgba(255,255,255,.05); }
label{ display:block; font-size:10.5px; text-transform:uppercase; letter-spacing:.4px; color:#8b95a7; margin:12px 0 5px; }
.inp,select.inp{ width:100%; background:rgba(0,0,0,.35); border:1px solid var(--border); color:#e6edf7; border-radius:9px; padding:9px 11px; font-size:13px; }
.card{ padding:18px 20px; margin-bottom:16px; } .row2{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }
.tokbox{ font-family:Consolas,monospace; font-size:12px; background:rgba(0,0,0,.4); border:1px solid rgba(54,227,208,.4); border-radius:9px; padding:10px 12px; color:#8ff0e4; word-break:break-all; margin:8px 0; }
.callout{ background:rgba(77,163,255,.06); border:1px solid rgba(77,163,255,.2); border-radius:11px; padding:12px 14px; margin-top:18px; }
.co-head{ display:flex; align-items:center; justify-content:space-between; gap:10px; font-size:10.5px; text-transform:uppercase; letter-spacing:.5px; color:#9fb2c8; margin-bottom:9px; }
.cronline{ display:block; font-family:Consolas,'Courier New',monospace; font-size:12px; line-height:1.5; color:#bcd8ff; background:rgba(0,0,0,.4); border:1px solid var(--border); border-radius:8px; padding:11px 13px; white-space:pre; overflow-x:auto; }
.rolehint{ font-size:12.5px; color:#9fb2c8; background:rgba(255,255,255,.03); border:1px solid var(--border); border-left:3px solid #36e3d0; border-radius:9px; padding:10px 13px; margin-top:9px; line-height:1.5; }
.rolehint b{ color:#e6edf7; }
.setcard{ max-width:660px; padding:22px 24px; }
.setcard b.h{ font-size:16px; } .divlite{ height:1px; background:rgba(255,255,255,.07); margin:18px 0; }
.hide{ display:none; } .tg{ cursor:pointer; color:#9fb2c8; padding:5px 7px; border-radius:6px; } .tg:hover{ background:rgba(255,255,255,.08); color:#fff; } .tg.danger:hover{ color:#ff9b91; }
.viz{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.chk{ display:inline-flex; align-items:center; gap:6px; font-size:12px; color:#cdd6e2; padding:5px 9px; border:1px solid var(--border); border-radius:8px; cursor:pointer; } .chk input{ accent-color:#36e3d0; }
/* ── Geo Wall ── */
#fed-side{ position:absolute; top:0; right:0; bottom:0; width:330px; background:rgba(6,10,18,.86); backdrop-filter:blur(10px); border-left:1px solid var(--border); z-index:500; display:flex; flex-direction:column; }
.fs-head{ padding:12px 14px; border-bottom:1px solid var(--border); font-size:11px; text-transform:uppercase; letter-spacing:.6px; color:#9fb2c8; display:flex; align-items:center; gap:8px; }
.fs-head #fed-inc-n{ margin-left:auto; color:#ffd98a; font-weight:800; }
#fed-inc{ overflow:auto; padding:9px 11px; flex:1; }
.inc{ display:flex; gap:9px; padding:8px 9px; border:1px solid var(--border); border-left:3px solid #46516a; border-radius:8px; margin-bottom:6px; background:rgba(255,255,255,.02); }
.inc.critical{ border-left-color:#ff5a5a; } .inc.warning{ border-left-color:#f0a92c; } .inc.info,.inc.low{ border-left-color:#4da3ff; }
.inc .idot{ width:8px; height:8px; border-radius:50%; margin-top:5px; flex:0 0 auto; box-shadow:0 0 8px currentColor; }
.inc .it{ font-size:12px; color:#e6edf7; line-height:1.35; } .inc .im{ font-size:10.5px; color:#8a97ab; margin-top:2px; }
.inc .sbadge{ font-size:9px; font-weight:800; padding:1px 6px; border-radius:20px; background:rgba(54,227,208,.14); color:#8ff0e4; }
#fed-ctrl{ position:absolute; top:12px; left:12px; z-index:500; display:flex; gap:6px; }
#fed-nocoord{ position:absolute; bottom:12px; left:12px; z-index:500; font-size:11.5px; color:#9fb2c8; background:rgba(6,10,18,.7); border:1px solid var(--border); border-radius:8px; padding:5px 10px; display:none; }
#wall-wrap:fullscreen,#wall-wrap:-webkit-full-screen{ height:100vh!important; width:100vw!important; border-radius:0; }
.leaflet-popup-content-wrapper,.leaflet-popup-tip{ background:#0d1420; color:#e6edf7; border:1px solid var(--border); } .leaflet-popup-content{ margin:11px 13px; font-size:12.5px; } .leaflet-popup-content b{ color:#fff; }
.spop .st{ font-size:9.5px; font-weight:800; text-transform:uppercase; padding:2px 7px; border-radius:20px; }
.leaflet-tooltip.sitelbl{ background:transparent; border:none; box-shadow:none; color:#eaf3ff; font-weight:700; font-size:11px; text-shadow:0 0 7px rgba(0,0,0,.95),0 0 3px rgba(0,0,0,.9); } .leaflet-tooltip.sitelbl::before{ display:none; }
/* federated device inventory */
.dvsite{ display:flex; align-items:center; gap:9px; margin-bottom:13px; flex-wrap:wrap; font-size:14px; }
.dvsite b{ color:#fff; }
.dv-badge{ font-size:9.5px; font-weight:800; text-transform:uppercase; padding:2px 8px; border-radius:20px; border:1px solid; }
.dv-self{ font-size:9.5px; font-weight:800; text-transform:uppercase; padding:2px 8px; border-radius:20px; background:rgba(77,163,255,.16); border:1px solid rgba(77,163,255,.5); color:#9cc7ff; }
.dvgrid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(210px,1fr)); gap:11px; }
.dvcard{ display:block; text-decoration:none; color:inherit; background:rgba(0,0,0,.28); border:1px solid var(--border); border-radius:11px; padding:11px 12px; transition:border-color .15s,transform .15s,background .15s; }
.dvcard:hover{ border-color:var(--accent); transform:translateY(-2px); background:rgba(77,163,255,.08); }
.dvcard.dvdown{ border-color:rgba(255,92,108,.5); background:rgba(255,92,108,.07); }
.dvcard .dvopen{ float:right; color:#4da3ff; font-weight:700; opacity:0; transition:opacity .15s; }
.dvcard:hover .dvopen{ opacity:1; }
.dvtop{ display:flex; align-items:center; gap:8px; margin-bottom:3px; }
.dvn{ font-weight:700; color:#eaf1fb; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; flex:1; font-size:13px; }
.dvdot{ width:9px; height:9px; border-radius:50%; box-shadow:0 0 7px currentColor; flex:0 0 auto; }
.dvip{ font-family:monospace; font-size:11.5px; color:#8aa2c4; margin-bottom:8px; }
.dvm{ display:flex; align-items:center; gap:7px; margin:4px 0; font-size:11px; }
.dvm-l{ width:34px; color:#7f93af; font-weight:700; letter-spacing:.4px; }
.dvm-track{ flex:1; height:6px; background:rgba(255,255,255,.08); border-radius:6px; overflow:hidden; }
.dvm-track i{ display:block; height:100%; border-radius:6px; }
.dvm-v{ width:34px; text-align:right; color:#cfe0f5; font-variant-numeric:tabular-nums; }
.dvm-na{ flex:1; color:#5c6b82; }
.dvup{ margin-top:7px; font-size:11px; color:#7f93af; } .dvup i{ margin-right:4px; }
/* How to Configure guide */
#tp-howto .howintro{ font-size:13.5px; line-height:1.6; }
#tp-howto .howcols{ display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1fr); gap:14px; margin-bottom:14px; align-items:stretch; } @media(max-width:900px){ #tp-howto .howcols{ grid-template-columns:1fr; } }
#tp-howto .howcols > .card{ margin-bottom:0; min-width:0; display:flex; flex-direction:column; }
#tp-howto .howcols > .card .howdone{ margin-top:auto; padding-top:8px; }
#tp-howto .howstep{ min-width:0; }
#tp-howto .howstep > div{ min-width:0; }
#tp-howto .howhd{ display:flex; align-items:center; gap:9px; font-size:15px; font-weight:800; color:#fff; margin-bottom:14px; flex-wrap:wrap; }
#tp-howto .howrole{ font-size:10px; font-weight:800; letter-spacing:1px; padding:3px 10px; border-radius:20px; }
#tp-howto .howrole.master{ background:rgba(54,227,208,.16); border:1px solid rgba(54,227,208,.5); color:#8ff0e4; }
#tp-howto .howrole.slave{ background:rgba(77,163,255,.16); border:1px solid rgba(77,163,255,.5); color:#9cc7ff; }
#tp-howto .howstep{ display:flex; gap:12px; margin-bottom:13px; font-size:13px; line-height:1.55; color:#c8d3e2; }
#tp-howto .howstep b{ color:#eef3fa; }
#tp-howto .howstep ul{ margin:6px 0 0; padding-left:18px; } #tp-howto .howstep li{ margin:3px 0; }
#tp-howto .hownum{ flex:0 0 26px; height:26px; border-radius:50%; display:grid; place-items:center; font-weight:800; font-size:12.5px; background:rgba(77,163,255,.16); border:1px solid rgba(77,163,255,.45); color:#9cc7ff; }
#tp-howto .howcode{ margin-top:7px; background:#05080e; border:1px solid rgba(255,255,255,.1); border-radius:8px; padding:9px 11px; font-family:Consolas,monospace; font-size:11.5px; color:#8ee6da; overflow-x:auto; white-space:nowrap; }
#tp-howto .hownote{ margin-top:7px; font-size:12px; color:#e9c98a; background:rgba(240,169,44,.1); border:1px solid rgba(240,169,44,.32); border-radius:8px; padding:7px 10px; }
#tp-howto .howdone{ margin-top:6px; font-size:12.5px; color:#8ff0c0; font-weight:600; }
#tp-howto .howtrb{ margin:0; padding-left:18px; font-size:13px; line-height:1.7; color:#c8d3e2; } #tp-howto .howtrb b{ color:#eef3fa; }
#tp-howto code{ background:rgba(255,255,255,.07); padding:1px 6px; border-radius:5px; font-family:Consolas,monospace; font-size:.92em; color:#cfe0f5; }
</style>

<?php include('header.php'); ?>
<div class="fd">
  <div class="bar glass">
    <div class="title"><i class="fa-solid fa-sitemap"></i> Federation</div>
    <span class="rolechip <?= htmlspecialchars($cfg['role']) ?>" id="rolechip"><?= htmlspecialchars($cfg['role']) ?></span>
    <span class="muted" id="idchip"><?= $cfg['site_name'] ? htmlspecialchars($cfg['site_name']).' · '.htmlspecialchars($cfg['site_slug']) : 'no site identity set' ?></span>
    <div class="tabs" id="tabs">
      <div class="tab on" data-t="overview" onclick="tab('overview')">Overview</div>
      <div class="tab" data-t="wall" onclick="tab('wall')">Geo Wall</div>
      <div class="tab" data-t="incidents" onclick="tab('incidents')">Incidents</div>
      <div class="tab" data-t="devices" onclick="DVFILTER='';tab('devices')">Devices</div>
      <div class="tab" data-t="timetravel" onclick="tab('timetravel')">Time Travel</div>
      <?php if ($isAdmin): ?>
      <div class="tab" data-t="immunity" onclick="tab('immunity')">Immunity</div>
      <div class="tab" data-t="sites" onclick="tab('sites')">Sites</div>
      <div class="tab" data-t="visibility" onclick="tab('visibility')">Visibility</div>
      <div class="tab" data-t="setup" onclick="tab('setup')">Setup</div>
      <div class="tab" data-t="health" onclick="tab('health')"><i class="fa-solid fa-heart-pulse"></i> Health</div>
      <div class="tab" data-t="howto" onclick="tab('howto')"><i class="fa-solid fa-circle-question"></i> How to Configure</div>
      <?php endif; ?>
    </div>
  </div>

  <!-- OVERVIEW -->
  <div id="tp-overview">
    <div id="ov-grid" class="grid"><div class="glass card muted">Loading cluster…</div></div>
  </div>

  <!-- GEO WALL -->
  <div id="tp-wall" class="hide">
    <div class="glass" id="wall-wrap" style="position:relative;height:76vh;min-height:560px;border-radius:14px;overflow:hidden;">
      <div id="fed-map" style="position:absolute;inset:0;background:#0a0f18;"></div>
      <div id="fed-side">
        <div class="fs-head"><i class="fa-solid fa-triangle-exclamation" style="color:#f0a92c"></i> Federated incidents <span id="fed-inc-n"></span></div>
        <div id="fed-inc"><div class="dim" style="padding:10px">Loading…</div></div>
      </div>
      <div id="fed-ctrl">
        <button class="btn sm" onclick="fedFit()" title="Fit all sites"><i class="fa-solid fa-crop-simple"></i></button>
        <button class="btn sm" id="fed-fsb" onclick="fedFs()"><i class="fa-solid fa-up-right-and-down-left-from-center"></i> Fullscreen</button>
      </div>
      <div id="fed-nocoord"></div>
    </div>
  </div>

  <!-- CLUSTER TIME-TRAVEL -->
  <div id="tp-timetravel" class="hide">
    <div class="glass card">
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <b style="font-size:15px"><i class="fa-solid fa-clock-rotate-left" style="color:#c084fc"></i> Replay the cluster</b>
        <button class="btn sm" id="tt-play" onclick="ttPlay()"><i class="fa-solid fa-play"></i> Play</button>
        <button class="btn sm" onclick="ttNow()"><i class="fa-solid fa-forward-fast"></i> Now</button>
        <span style="flex:1"></span>
        <span id="tt-label" style="font-family:monospace;font-size:14px;color:#e6edf7">—</span>
      </div>
      <input type="range" id="tt-slider" min="0" max="100" value="100" style="width:100%;margin-top:14px;accent-color:#c084fc" oninput="ttScrub()">
      <div class="muted" id="tt-hint" style="font-size:11.5px;margin-top:4px">Drag to any past minute — every site's state then (from the rollup history) renders below.</div>
    </div>
    <div id="tt-grid" class="grid"></div>
  </div>

  <!-- FEDERATED DEVICE INVENTORY (full metrics) -->
  <div id="tp-devices" class="hide">
    <div class="glass card" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
      <b style="font-size:15px"><i class="fa-solid fa-server" style="color:#4da3ff"></i> Every device across the cluster</b>
      <span class="muted">latest snapshot each site pushed — status + CPU / RAM / disk / uptime</span>
      <span style="flex:1"></span>
      <input id="dv-q" class="inp" placeholder="filter name / IP / site…" style="max-width:220px" oninput="dvRender()">
      <label class="muted" style="display:flex;align-items:center;gap:6px;font-size:12px"><input type="checkbox" id="dv-down" onchange="dvRender()"> down only</label>
      <button class="btn sm" onclick="dvLoad()"><i class="fa-solid fa-rotate"></i></button>
    </div>
    <div id="dv-wrap"><div class="glass card muted">Loading devices…</div></div>
  </div>

  <!-- FEDERATED INCIDENT DESK -->
  <div id="tp-incidents" class="hide">
    <div id="fi-patterns"></div>
    <div class="glass card">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><b style="font-size:15px"><i class="fa-solid fa-triangle-exclamation" style="color:#f0a92c"></i> Incidents across the cluster</b><span class="muted">every site, in one desk</span><span style="flex:1"></span><span id="fi-count" class="muted"></span></div>
      <div class="muted" style="margin-bottom:12px;font-size:12px">These are the master's federated incidents (site offline + mirrored site-criticals). They also flow through the <b>Notification Center</b> and appear in the main Incident desk.</div>
      <table><thead><tr><th>Severity</th><th>Site</th><th>Incident</th><th>Age</th><th>Status</th><?php if($isAdmin):?><th></th><?php endif;?></tr></thead><tbody id="fi-body"></tbody></table>
    </div>
  </div>

  <?php if ($isAdmin): ?>
  <!-- CLUSTER IMMUNITY -->
  <div id="tp-immunity" class="hide">
    <div class="glass card" style="max-width:720px">
      <b style="font-size:15px"><i class="fa-solid fa-shield-virus" style="color:#ff8f8f"></i> Block a threat across the cluster</b>
      <div class="muted" style="margin:4px 0 12px">Block once here → it fans out to <b>every site</b>. Each site applies it through its own <b>Collective Immunity</b> (Pi-holes + firewalls). Idempotent &amp; safe; slaves pick it up on their next tick.</div>
      <div class="row2">
        <div><label>Type</label><select class="inp" id="im-type"><option value="ip">IP address</option><option value="domain">Domain</option><option value="regex">Regex</option></select></div>
        <div><label>Scope</label><select class="inp" id="im-scope" onchange="imScope()"><option value="all">All sites</option><option value="pick">Specific sites…</option></select></div>
      </div>
      <div id="im-sites" class="hide"><label>Sites</label><div class="viz" id="im-sitechips"></div></div>
      <label>Indicator</label><input class="inp" id="im-ind" placeholder="e.g. 45.140.17.9  ·  bad-domain.com">
      <label>Reason <span class="dim" style="text-transform:none">(optional)</span></label><input class="inp" id="im-reason" placeholder="why — shown in each site's audit">
      <div style="display:flex;gap:10px;margin-top:16px;align-items:center">
        <button class="btn g" style="background:linear-gradient(135deg,#ff7a7a,#ff4d4d)" onclick="clusterBlock()"><i class="fa-solid fa-ban"></i> Block cluster-wide</button>
        <span id="im-msg" class="muted"></span>
      </div>
    </div>
    <div class="glass card">
      <b style="font-size:15px">Recent cluster actions</b>
      <div class="muted" style="margin:4px 0 12px">Per-site delivery — <span style="color:#8ff0b6">done</span> when a site confirms it applied the block, <span style="color:#ffd98a">pending</span> until its next check-in.</div>
      <table><thead><tr><th>Action</th><th>Type</th><th>Delivery</th><th>When</th></tr></thead><tbody id="cmd-body"></tbody></table>
    </div>
  </div>

  <!-- SITES -->
  <div id="tp-sites" class="hide">
    <div class="glass card">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;"><b style="font-size:15px">Registered sites</b><span class="muted">slaves that push telemetry to this master</span><span style="flex:1"></span><button class="btn g" onclick="siteForm()"><i class="fa-solid fa-plus"></i> Register site</button></div>
      <table><thead><tr><th>Site</th><th>Slug</th><th>Endpoint</th><th>Token</th><th>Enabled</th><th></th></tr></thead><tbody id="sites-body"></tbody></table>
      <div class="muted" style="margin-top:10px;font-size:11.5px"><i class="fa-solid fa-circle-info"></i> On each slave, open <b>Federation → Setup</b>, set role = <b>slave</b>, the same slug, this master's URL, and paste the site token.</div>
    </div>
  </div>

  <!-- VISIBILITY -->
  <div id="tp-visibility" class="hide">
    <div class="glass card">
      <b style="font-size:15px">Who sees which sites</b>
      <div class="muted" style="margin:4px 0 14px">Per role. <b>admin</b> always sees every site. A role with nothing checked sees no sites (deny-wins).</div>
      <div id="vis-body" class="muted">Loading…</div>
    </div>
  </div>

  <!-- SETUP -->
  <div id="tp-setup" class="hide">
    <!-- Quick enroll (one-paste) — the fast path for slaves -->
    <div class="glass setcard" style="border-color:rgba(54,227,208,.35)">
      <b class="h"><i class="fa-solid fa-ticket" style="color:#36e3d0"></i> Quick enroll a slave (recommended)</b>
      <div class="muted" style="margin:4px 0 12px">On the <b>master</b>: <b>Sites</b> tab → a site → <b>Enroll code</b> → copy it. Paste it here to set role, slug, master URL &amp; token in <b>one step</b> — then it live-tests the link. No copying three fields, no slug typos, no 401s.</div>
      <textarea class="inp" id="enr-code" rows="2" placeholder="paste NEURU1.… enrollment code" style="resize:vertical;font-family:monospace"></textarea>
      <div style="display:flex;gap:10px;margin-top:10px;align-items:center;flex-wrap:wrap">
        <button class="btn g" onclick="enroll()"><i class="fa-solid fa-bolt"></i> Enroll &amp; connect</button>
        <span id="enr-msg" class="muted"></span>
      </div>
    </div>

    <div class="glass setcard">
      <b class="h">This install's role</b>
      <div class="muted" style="margin:4px 0 14px">Same codebase — the role is just configuration. A <b>standalone</b> ignores the cluster entirely.</div>
      <label>Role</label>
      <select class="inp" id="c-role" onchange="roleUI()"><option value="standalone">Standalone — no cluster</option><option value="master">Master — aggregates the sites</option><option value="slave">Slave — pushes to a master</option></select>
      <div class="rolehint" id="rolehint"></div>
      <div class="divlite"></div>
      <div class="row2">
        <div><label>Site slug <span class="dim" style="text-transform:none">(id, e.g. sanjuan)</span></label><input class="inp" id="c-slug" placeholder="sanjuan"></div>
        <div><label>Site name</label><input class="inp" id="c-name" placeholder="HQ San Juan"></div>
      </div>
      <div id="slave-cfg" class="hide">
        <label>Master URL <span class="dim" style="text-transform:none">(base, e.g. https://hq.example.com/netmon)</span></label><input class="inp" id="c-master" placeholder="https://hq.example.com">
        <label>Cluster token for THIS site <span class="dim" style="text-transform:none">(from the master's Sites tab)</span></label><input class="inp" id="c-token" placeholder="paste the token · leave blank to keep">
      </div>
      <div style="display:flex;gap:10px;margin-top:18px;align-items:center;flex-wrap:wrap">
        <button class="btn g" onclick="saveCfg()"><i class="fa-solid fa-floppy-disk"></i> Save</button>
        <button class="btn" id="pushb" onclick="pushNow()" style="display:none"><i class="fa-solid fa-paper-plane"></i> Test push to master</button>
        <span id="setup-msg" class="muted"></span>
      </div>
      <div class="callout" id="cron-callout">
        <div class="co-head"><span><i class="fa-solid fa-clock"></i> Add this cron on the host</span><button class="btn sm" onclick="copyCron(this)"><i class="fa-regular fa-copy"></i> Copy</button></div>
        <code class="cronline" id="cronline">* * * * * /var/www/html/netmon/scripts/nm_cron.sh cron_cluster.php</code>
      </div>
    </div>
  </div>

  <!-- HEALTH -->
  <div id="tp-health" class="hide">
    <div class="glass setcard">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <b class="h"><i class="fa-solid fa-heart-pulse" style="color:#36e3d0"></i> Federation health</b>
        <span class="rolechip" id="hz-role"></span>
        <span style="flex:1"></span>
        <button class="btn" onclick="loadHealth()"><i class="fa-solid fa-rotate"></i> Re-check</button>
      </div>
      <div class="muted" style="margin:4px 0 14px">Live checks — <span style="color:#8ff0b6">green</span> = good, <span style="color:#ff9b91">red</span> tells you exactly what to fix. This is the fast answer to "why is it offline / 401?".</div>
      <div id="hz-list" class="muted">Running checks…</div>
    </div>
  </div>

  <!-- HOW TO CONFIGURE -->
  <?php $__intok = ''; { $q = @$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='n8n_inbound_token' LIMIT 1"); if ($q && $q->num_rows) $__intok = (string)$q->fetch_assoc()['setting_val']; } $__ct = htmlspecialchars($__intok !== '' ? $__intok : '<your cron token>'); ?>
  <div id="tp-howto" class="hide">
    <div class="glass card howintro">
      <b>Build a NEURU cluster in minutes.</b> One portal is the <b>MASTER</b> (aggregates every site); each remote
      site is a <b>SLAVE</b> that pushes its vitals + inventory up. It's the same app — the role is just configuration.
      <b>Always configure the MASTER first</b> (that's where each site's token is minted), then each slave.
    </div>

    <div class="howcols">
      <!-- MASTER -->
      <div class="glass card">
        <div class="howhd"><span class="howrole master">MASTER</span> the HQ portal that sees everything</div>

        <div class="howstep"><span class="hownum">1</span><div>
          <b>Set the role &amp; identity.</b> Open the <b>Setup</b> tab → Role = <b>Master</b>. Fill
          <b>Site slug</b> (e.g. <code>hq</code>) and <b>Site name</b> (e.g. HQ San Juan) → <b>Save</b>.
        </div></div>

        <div class="howstep"><span class="hownum">2</span><div>
          <b>Add the cron</b> on the master host (keeps its own card fresh + runs cluster duties):
          <div class="howcode">* * * * * curl -s -H "X-NetMon-Token: <?= $__ct ?>" http://localhost/cron_cluster.php &gt;/dev/null 2&gt;&amp;1</div>
        </div></div>

        <div class="howstep"><span class="hownum">3</span><div>
          <b>Register each slave.</b> <b>Sites</b> tab → <b>Register site</b>:
          <ul>
            <li><b>Slug</b> — must MATCH the slug you'll set on that slave (e.g. <code>ponce</code>).</li>
            <li><b>Name</b> — a friendly label.</li>
            <li><b>Portal URL</b> — the slave's base URL (e.g. <code>http://192.168.10.1:8090</code>). <b>Required</b> to open that site's devices natively.</li>
            <li><b>Lat / Lon</b> — optional, for the Geo Wall.</li>
          </ul>
          Save → <b>copy the token</b> shown once — you paste it into that slave (step 3 on the right).
        </div></div>

        <div class="howstep"><span class="hownum">4</span><div>
          <b>(Optional) Visibility.</b> <b>Visibility</b> tab → which roles see which sites (<code>*</code> = all).
        </div></div>
        <div class="howdone">✓ The master now shows every site in Overview / Geo Wall / Devices as they check in.</div>
      </div>

      <!-- SLAVE -->
      <div class="glass card">
        <div class="howhd"><span class="howrole slave">SLAVE</span> each remote site — repeat per site</div>

        <div class="howstep"><span class="hownum">1</span><div>
          <b>Set the role &amp; identity.</b> On the remote portal, <b>Setup</b> tab → Role = <b>Slave</b>.
          <b>Site slug</b> must be the SAME slug you registered on the master (e.g. <code>ponce</code>) + a Site name.
        </div></div>

        <div class="howstep"><span class="hownum">2</span><div>
          <b>Point it at the master.</b> <b>Master URL</b> = the master's base URL (e.g. <code>http://192.168.0.25:8090</code>).
        </div></div>

        <div class="howstep"><span class="hownum">3</span><div>
          <b>Paste the token</b> (from the master's Sites tab) into <b>Cluster token for THIS site</b> → <b>Save</b>.
          <div class="hownote">⚠ Set the token here in the WEB UI, never by CLI — a CLI-set secret can't be decrypted by the web server later.</div>
        </div></div>

        <div class="howstep"><span class="hownum">4</span><div>
          <b>Add the cron</b> on the slave host — this is what pushes the data up:
          <div class="howcode">* * * * * curl -s -H "X-NetMon-Token: &lt;the slave's own cron token&gt;" http://localhost/cron_cluster.php &gt;/dev/null 2&gt;&amp;1</div>
        </div></div>

        <div class="howstep"><span class="hownum">5</span><div>
          <b>Test it.</b> Click <b>Test push to master</b> → it should read <b>Online</b>. Within ~1 min the site appears on the master.
        </div></div>
        <div class="howdone">✓ A slave sees only itself; the master sees it + every other site.</div>
      </div>
    </div>

    <!-- device embed -->
    <div class="glass card">
      <div class="howhd"><i class="fa-solid fa-server" style="color:#4da3ff"></i> Open a remote device's FULL native dashboard</div>
      <div class="muted" style="margin-bottom:10px">On the master: <b>Devices</b> tab → click any device → its native page (router / Windows / Linux / ping) opens embedded, read-only, with <b>no second login</b>.</div>
      <div class="howstep"><span class="hownum">A</span><div>The site's <b>Portal URL</b> must be set (master → Sites → that site).</div></div>
      <div class="howstep"><span class="hownum">B</span><div>Your <b>browser</b> must be able to reach that Portal URL (same LAN / VPN). The master server itself can't reach the slave through NAT — your browser loads the embed directly.</div></div>
      <div class="howstep"><span class="hownum">C</span><div>If it won't load, use <b>Open in tab ↗</b> (logs into the slave normally). The master's <b>own</b> devices always work — same portal, no token needed.</div></div>
    </div>

    <!-- troubleshooting -->
    <div class="glass card">
      <div class="howhd"><i class="fa-solid fa-wrench" style="color:#f0a92c"></i> Troubleshooting</div>
      <ul class="howtrb">
        <li><b>Slave says "buffered / HTTP 401"</b> → wrong token. Reset it (master → Sites → the site → reset) and paste the new one on the slave's Setup.</li>
        <li><b>Master's own card is "stale"</b> → the master is missing its <code>cron_cluster.php</code> line (master step 2). The dashboard also self-refreshes while you view it.</li>
        <li><b>Slave sees no other sites / no master nodes</b> → by design. Data flows UP; the fleet view lives on the master.</li>
        <li><b>Self-signed HTTPS between sites</b> → set <code>cluster_ssl_verify</code> = <code>0</code> in nm_settings (default is verify ON).</li>
        <li><b>Both sides need the cron line</b> — the slave to push, the master to ingest + self-refresh.</li>
      </ul>
    </div>
  </div>
  <?php endif; ?>
</div>

<!-- site register modal -->
<div class="glass" id="site-modal" style="display:none;position:fixed;inset:0;z-index:70;background:rgba(3,5,12,.72);backdrop-filter:blur(4px);border:none;border-radius:0;align-items:center;justify-content:center;"><div class="glass" style="width:460px;max-width:96vw;padding:22px 24px;">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;"><h3 style="margin:0;font-size:16px;" id="sm-title">Register site</h3><span style="flex:1"></span><i class="fa-solid fa-xmark" style="cursor:pointer;color:#9aa3af" onclick="closeSite()"></i></div>
  <input type="hidden" id="sm-id">
  <div class="row2"><div><label>Slug</label><input class="inp" id="sm-slug" placeholder="ponce"></div><div><label>Name</label><input class="inp" id="sm-name" placeholder="Ponce"></div></div>
  <label>Portal URL <span class="dim" style="text-transform:none">(base URL of this slave's portal — needed to open its devices natively)</span></label><input class="inp" id="sm-ep" placeholder="http://192.168.10.1:8090">
  <div class="row2"><div><label>Latitude <span class="dim" style="text-transform:none">(Geo Wall)</span></label><input class="inp" id="sm-lat" placeholder="18.01"></div><div><label>Longitude</label><input class="inp" id="sm-lon" placeholder="-66.61"></div></div>
  <label class="chk" style="margin-top:12px"><input type="checkbox" id="sm-en" checked> Enabled</label>
  <div id="sm-tok" class="hide"><div class="muted" style="margin-top:10px">Token for this site — copy it to the slave now (shown once):</div><div class="tokbox" id="sm-tokv"></div><button class="btn sm" onclick="copyEl('sm-tokv',this)"><i class="fa-regular fa-copy"></i> Copy token</button></div>
  <div style="display:flex;gap:9px;margin-top:16px;justify-content:flex-end"><button class="btn" onclick="closeSite()">Close</button><button class="btn g" id="sm-save" onclick="saveSite()"><i class="fa-solid fa-plus"></i> Save</button></div>
  <div id="sm-msg" style="margin-top:9px;font-size:12px;color:#ff9b91"></div>
</div></div>

<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const IS_ADMIN=<?= $isAdmin?'true':'false' ?>;
let CUR='overview', polling=null;
async function jget(u){ return fetch(u).then(r=>r.json()).catch(()=>null); }
async function jpost(api,obj){ return fetch('federation.php?api='+api,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj||{})}).then(r=>r.json()).catch(()=>({ok:false,error:'request failed'})); }
function relAge(s){ if(s==null)return 'never'; s=+s; if(s<60)return s+'s ago'; if(s<3600)return Math.floor(s/60)+'m ago'; if(s<86400)return Math.floor(s/3600)+'h ago'; return Math.floor(s/86400)+'d ago'; }

function tab(t){ CUR=t; document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('on',x.dataset.t===t));
  ['overview','wall','incidents','devices','timetravel','immunity','sites','visibility','setup','health','howto'].forEach(x=>{ const el=document.getElementById('tp-'+x); if(el)el.classList.toggle('hide',x!==t); });
  if(t==='overview')loadOverview(); if(t==='wall'){ initFedMap(); loadWall(); } if(t==='incidents')loadFedIncidents(); if(t==='devices')dvLoad(); if(t==='timetravel')loadTimeTravel(); if(t==='immunity')loadImmunity(); if(t==='sites')loadSites(); if(t==='visibility')loadVis(); if(t==='setup')loadCfg(); if(t==='health')loadHealth();
}
// ── federated device inventory (full metric view) ──
let DV=[], DVFILTER='';
function drillSite(slug){ DVFILTER=slug; tab('devices'); }        // overview card → only this server's devices
function clearDvFilter(){ DVFILTER=''; dvRender(); }
const KIND_ICO={router:'fa-diagram-project',windows:'fa-windows fa-brands',linux:'fa-linux fa-brands',ping:'fa-wave-square',snmp:'fa-microchip'};
function upt(s){ if(s==null)return '—'; s=+s; if(s<3600)return Math.round(s/60)+'m'; if(s<86400)return (s/3600).toFixed(1)+'h'; return Math.round(s/86400)+'d'; }
function mBar(label,v){ if(v==null)return `<div class="dvm"><span class="dvm-l">${label}</span><span class="dvm-na">—</span></div>`;
  const c=v>=90?'#ff5c6c':v>=75?'#f0a92c':'#41d18b';
  return `<div class="dvm"><span class="dvm-l">${label}</span><span class="dvm-track"><i style="width:${Math.max(3,Math.min(100,v))}%;background:${c}"></i></span><span class="dvm-v">${v}%</span></div>`; }
async function dvLoad(){ const w=document.getElementById('dv-wrap'); w.innerHTML='<div class="glass card muted">Loading devices…</div>';
  const d=await jget('federation.php?api=fed_devices&scope=full&_='+Date.now());
  if(!d||!d.ok){ w.innerHTML='<div class="glass card muted">Could not load.</div>'; return; }
  DV=d.sites||[]; dvRender();
}
function dvRender(){ const w=document.getElementById('dv-wrap'); const q=(document.getElementById('dv-q').value||'').toLowerCase().trim();
  const downOnly=document.getElementById('dv-down').checked;
  const isDown=st=>['down','lowerlayerdown','notpresent','testing'].includes((st||'').toLowerCase());
  let any=0;
  const html=DV.map(s=>{
    if(DVFILTER && s.site!==DVFILTER) return '';
    let devs=(s.devices||[]);
    if(downOnly) devs=devs.filter(x=>isDown(x.st));
    if(q) devs=devs.filter(x=>((x.name||'')+' '+(x.ip||'')+' '+s.name).toLowerCase().includes(q));
    if(!devs.length) return '';
    any+=devs.length;
    const sc=s.status==='online'?'#41d18b':s.status==='stale'?'#f0a92c':'#ff5c6c';
    const tag=s.is_self?'<span class="dv-self">this master</span>':'';
    const cards=devs.map(x=>{ const dn=isDown(x.st), dg=(x.st||'').toLowerCase()==='degraded';
      const dot=dn?'#ff5c6c':dg?'#f0a92c':'#41d18b';
      const href='fed_device.php?site='+encodeURIComponent(s.site)+'&id='+encodeURIComponent(x.id);
      return `<a class="dvcard${dn?' dvdown':''}" href="${href}" title="Open ${esc(x.name)} command center">
        <div class="dvtop"><i class="fa-solid ${KIND_ICO[x.kind]||'fa-microchip'}" style="color:#8aa2c4"></i>
          <span class="dvn">${esc(x.name)}</span>
          <span class="dvdot" style="background:${dot}" title="${esc(x.st)}"></span></div>
        <div class="dvip">${esc(x.ip||'—')}</div>
        ${mBar('CPU',x.cpu)}${mBar('RAM',x.ram)}${mBar('DISK',x.disk)}
        <div class="dvup"><i class="fa-solid fa-clock"></i> up ${upt(x.up)} <span class="dvopen">open →</span></div>
      </a>`; }).join('');
    return `<div class="glass card"><div class="dvsite"><i class="fa-solid fa-location-dot" style="color:${sc}"></i>
      <b>${esc(s.name)}</b> <span class="muted">${esc(s.site)}</span> ${tag}
      <span class="dv-badge" style="border-color:${sc};color:${sc}">${s.status}</span>
      <span style="flex:1"></span><span class="muted">${devs.length} device${devs.length!=1?'s':''}</span>
      ${s.capped?'<span class="dv-badge" style="border-color:#f0a92c;color:#f0a92c" title="site has more devices than the push cap">capped</span>':''}</div>
      <div class="dvgrid">${cards}</div></div>`;
  }).join('');
  const fbanner = DVFILTER ? `<div class="glass card" style="display:flex;align-items:center;gap:10px;margin-bottom:12px;"><i class="fa-solid fa-filter" style="color:#4da3ff"></i> Showing only <b>${esc(DVFILTER)}</b>'s devices <span style="flex:1"></span><button class="btn sm" onclick="clearDvFilter()"><i class="fa-solid fa-xmark"></i> Show all servers</button></div>` : '';
  w.innerHTML=fbanner + (any? html : '<div class="glass card muted">'+(DVFILTER?'This server has no devices reporting yet.':'No federated devices yet. Once a site (or this master itself) checks in with its inventory, its devices appear here — tagged by origin.')+'</div>');
}
// ── cluster time-travel ──
let TT={min:0,max:0,playing:false,timer:null}, _ttT=null;
async function loadTimeTravel(){ const d=await jget('federation.php?api=tt_range'); if(!d||!d.ok)return;
  TT.min=d.min; TT.max=d.max; const sl=document.getElementById('tt-slider');
  if(!TT.max){ document.getElementById('tt-grid').innerHTML='<div class="glass card muted" style="grid-column:1/-1">No cluster history yet — it accrues once sites check in over time.</div>'; document.getElementById('tt-label').textContent='—'; return; }
  sl.min=TT.min; sl.max=TT.max; sl.step=Math.max(1,Math.round((TT.max-TT.min)/600)); sl.value=TT.max; ttScrub();
}
function ttScrub(){ const at=+document.getElementById('tt-slider').value; const dt=new Date(at*1000);
  document.getElementById('tt-label').textContent=dt.toLocaleString();
  clearTimeout(_ttT); _ttT=setTimeout(()=>ttRender(at),110); }
async function ttRender(at){ const d=await jget('federation.php?api=tt_at&at='+at); const g=document.getElementById('tt-grid'); if(!d||!d.ok)return;
  g.innerHTML=d.sites.length? d.sites.map(s=>{ const n=s.nodes, tot=Math.max(1,n.total), pu=n.up/tot*100,pd=n.down/tot*100,pg=n.degraded/tot*100;
    return `<div class="glass site ${s.status}"><span class="stat ${s.status}">${s.status}</span><h3>${esc(s.name)}</h3><div class="slug">${esc(s.site)}</div>
      <div class="metrics"><div class="metric"><div class="n" style="color:var(--ok)">${n.up}</div><div class="l">up</div></div>
      <div class="metric"><div class="n" style="color:${n.down?'var(--crit)':'#6f7a8c'}">${n.down}</div><div class="l">down</div></div>
      <div class="metric"><div class="n" style="color:${n.degraded?'var(--warn)':'#6f7a8c'}">${n.degraded}</div><div class="l">deg</div></div>
      <div class="metric"><div class="n" style="color:${s.incidents.open?'var(--warn)':'#6f7a8c'}">${s.incidents.open}</div><div class="l">inc${s.incidents.critical?' ·'+s.incidents.critical+'🔴':''}</div></div></div>
      <div class="bar2"><i style="width:${pu}%;background:#2ee66e"></i><i style="width:${pg}%;background:#f0a92c"></i><i style="width:${pd}%;background:#ff5a5a"></i></div>
      <div class="seen">${s.status==='never'?'no data at this time':(s.gap!=null?('as of '+relAge(s.gap)+' before this point'):'')}</div></div>`; }).join('')
    : '<div class="glass card muted" style="grid-column:1/-1">No sites visible.</div>'; }
function ttPlay(){ const b=document.getElementById('tt-play'); if(TT.playing){ TT.playing=false; clearInterval(TT.timer); b.innerHTML='<i class="fa-solid fa-play"></i> Play'; return; }
  if(!TT.max)return; TT.playing=true; b.innerHTML='<i class="fa-solid fa-pause"></i> Pause'; const sl=document.getElementById('tt-slider');
  if(+sl.value>=TT.max) sl.value=TT.min;
  TT.timer=setInterval(()=>{ let v=+sl.value+(+sl.step*4); if(v>=TT.max){ v=TT.max; sl.value=v; ttScrub(); ttPlay(); return; } sl.value=v; ttScrub(); }, 400); }
function ttNow(){ if(TT.playing)ttPlay(); const sl=document.getElementById('tt-slider'); sl.value=TT.max; ttScrub(); }
// ── federated incident desk ──
async function loadFedIncidents(){ const d=await jget('federation.php?api=fedincidents&_='+Date.now()); if(!d||!d.ok)return;
  const pel=document.getElementById('fi-patterns');
  pel.innerHTML=d.patterns.length? `<div class="glass card" style="border-left:3px solid #ff8f8f"><b style="font-size:14px"><i class="fa-solid fa-link" style="color:#ff8f8f"></i> Cross-site patterns</b><div class="muted" style="margin:3px 0 10px">The same issue is active at multiple sites — likely one shared cause.</div>`+
    d.patterns.map(p=>`<div class="inc ${esc(p.severity)}" style="margin-bottom:6px"><span class="idot" style="background:${p.severity==='critical'?'#ff5a5a':'#f0a92c'}"></span><div><div class="it">${esc(p.title)}</div><div class="im">🔗 <b>${p.count} sites</b>: ${p.sites.map(esc).join(', ')}</div></div></div>`).join('')+`</div>` : '';
  const open=d.incidents.filter(i=>i.status!=='resolved').length; document.getElementById('fi-count').innerHTML=open?`<b style="color:#ffd98a">${open}</b> open`:'all clear 🎉';
  const tb=document.getElementById('fi-body');
  tb.innerHTML=d.incidents.length? d.incidents.map(i=>{ const c=i.severity==='critical'?'#ff5a5a':(i.severity==='warning'?'#f0a92c':'#4da3ff');
    const st=i.status==='resolved'?'<span style="color:#8ff0b6">resolved</span>':(i.status==='acknowledged'?'<span style="color:#ffd98a">ack</span>':'<span style="color:#ff9b91">open</span>');
    return `<tr style="${i.status==='resolved'?'opacity:.5':''}"><td><span style="display:inline-block;background:${c};width:9px;height:9px;border-radius:50%;box-shadow:0 0 8px ${c}"></span> ${esc(i.severity)}</td>
      <td><span class="sbadge">${esc(i.site)}</span></td><td>${i.down?'<i class="fa-solid fa-plug-circle-xmark" style="color:#ff5a5a"></i> ':''}${esc(i.title)}</td>
      <td class="muted">${relAge(i.age)}</td><td>${st}</td>
      ${IS_ADMIN?`<td style="text-align:right;white-space:nowrap">${i.status!=='resolved'?`<span class="tg" title="Acknowledge" onclick="fiSet(${i.id},'ack')"><i class="fa-solid fa-check"></i></span><span class="tg" title="Resolve" onclick="fiSet(${i.id},'resolved')"><i class="fa-solid fa-circle-check"></i></span>`:''}</td>`:''}</tr>`; }).join('')
    : '<tr><td colspan="'+(IS_ADMIN?6:5)+'" class="muted" style="padding:16px;text-align:center">No cluster incidents 🎉</td></tr>';
}
async function fiSet(id,to){ const d=await jpost('inc_status',{id,status:to==='resolved'?'resolved':'ack'}); if(d&&d.ok)loadFedIncidents(); }
// ── cluster immunity ──
function imScope(){ document.getElementById('im-sites').classList.toggle('hide',document.getElementById('im-scope').value!=='pick'); }
async function loadImmunity(){ const r=await jget('federation.php?api=sites');
  if(r&&r.ok){ document.getElementById('im-sitechips').innerHTML=r.sites.length? r.sites.map(s=>`<label class="chk"><input type="checkbox" class="im-site" value="${esc(s.site)}"> ${esc(s.name)}</label>`).join(''):'<span class="dim">no sites registered</span>'; }
  loadCmds(); }
async function loadCmds(){ const d=await jget('federation.php?api=cmd_list'); const tb=document.getElementById('cmd-body'); if(!d||!d.ok)return;
  tb.innerHTML=d.commands.length? d.commands.map(c=>{ const p=c.payload||{};
    const del=`<span style="color:#8ff0b6">${c.done}✓</span>`+(c.pending?` · <span style="color:#ffd98a">${c.pending} pending</span>`:'')+(c.failed?` · <span style="color:#ff9b91">${c.failed} failed</span>`:'')+` <span class="dim">/ ${c.total}</span>`;
    return `<tr><td><b>${esc(c.summary||c.type)}</b></td><td class="dim">${esc(p.ind_type||c.type)}</td><td>${del}</td><td class="muted">${relAge(c.age)}</td></tr>`; }).join('')
    : '<tr><td colspan="4" class="muted" style="padding:16px">No cluster actions yet.</td></tr>'; }
async function clusterBlock(){ const ind=document.getElementById('im-ind').value.trim(); const m=document.getElementById('im-msg');
  if(!ind){ m.textContent='Enter an indicator'; m.style.color='#ff9b91'; return; }
  const scope=document.getElementById('im-scope').value, sites=[...document.querySelectorAll('.im-site:checked')].map(x=>x.value);
  if(scope==='pick' && !sites.length){ m.textContent='Pick at least one site'; m.style.color='#ff9b91'; return; }
  if(!confirm('Block "'+ind+'" across '+(scope==='all'?'ALL sites':sites.length+' site(s)')+'?\nEach site applies it via its Immunity engine (Pi-holes + firewalls).'))return;
  m.style.color='#8a909a'; m.innerHTML='<i class="fa-solid fa-spinner fa-spin"></i> Queuing…';
  const d=await jpost('cmd_block',{indicator:ind,ind_type:document.getElementById('im-type').value,reason:document.getElementById('im-reason').value.trim(),scope,sites});
  if(d&&d.ok){ m.style.color='#8ff0b6'; m.textContent='✓ Queued for '+d.targets+' site(s)'+(d.own?' · master applied now':''); document.getElementById('im-ind').value=''; document.getElementById('im-reason').value=''; loadCmds(); }
  else { m.style.color='#ff9b91'; m.textContent='✗ '+((d&&d.error)||'failed'); } }

// ── geo wall ──
let FED_MAP=null, FED_MK={}, FED_LAYER=null;
function initFedMap(){ if(FED_MAP){ setTimeout(()=>FED_MAP.invalidateSize(),60); return; }
  FED_MAP=L.map('fed-map',{worldCopyJump:true,zoomControl:true,attributionControl:false,preferCanvas:true}).setView([18.4,-66.1],7);
  <?= nm_map_tile_js($conn) ?>.addTo(FED_MAP);
  FED_LAYER=L.layerGroup().addTo(FED_MAP);
}
function siteColor(s){ if(s.status==='offline'||s.status==='never')return '#7c8698'; if(s.nodes.down>0||s.incidents.critical>0)return '#ff5a5a'; if(s.status==='stale'||s.nodes.degraded>0||s.incidents.open>0)return '#f0a92c'; return '#2ee66e'; }
function sitePopup(s){ const c=siteColor(s); return `<div class="spop"><b>${esc(s.name)}</b> <span class="st" style="background:${c}22;color:${c}">${esc(s.status)}</span><br>
  <span style="color:#8a97ab;font-family:monospace">${esc(s.site)}</span><br>
  <b style="color:#2ee66e">${s.nodes.up}</b> up · <b style="color:${s.nodes.down?'#ff5a5a':'#6f7a8c'}">${s.nodes.down}</b> down · <b style="color:${s.nodes.degraded?'#f0a92c':'#6f7a8c'}">${s.nodes.degraded}</b> deg<br>
  ${s.incidents.open} incident(s)${s.incidents.critical?' · <span style="color:#ff5a5a">'+s.incidents.critical+' critical</span>':''}<br>
  <span style="color:#8a97ab;font-size:11px">seen ${s.age==null?'never':relAge(s.age)} · ${s.nodes.total} nodes</span></div>`; }
async function loadWall(){ const d=await jget('federation.php?api=wall&_='+Date.now()); if(!d||!d.ok||!FED_MAP)return;
  FED_LAYER.clearLayers(); FED_MK={}; const pts=[]; let noco=0;
  d.sites.forEach(s=>{ if(s.lat==null||s.lon==null){ noco++; return; } const c=siteColor(s); const r=9+Math.min(15,(s.nodes.total||0)*0.7);
    L.circleMarker([s.lat,s.lon],{radius:r+8,color:c,weight:0,fillColor:c,fillOpacity:.12}).addTo(FED_LAYER);
    const mk=L.circleMarker([s.lat,s.lon],{radius:r,color:c,weight:2,fillColor:c,fillOpacity:.4}).bindPopup(sitePopup(s)).bindTooltip(s.name,{permanent:true,direction:'top',offset:[0,-r-4],className:'sitelbl'});
    mk.addTo(FED_LAYER); FED_MK[s.site]=mk; pts.push([s.lat,s.lon]);
  });
  const nc=document.getElementById('fed-nocoord'); nc.style.display=noco?'block':'none'; nc.innerHTML=noco?('<i class="fa-solid fa-location-dot"></i> '+noco+' site(s) without coordinates — set lat/lon in <b>Sites</b>'):'';
  if(pts.length && !loadWall._fit){ FED_MAP.fitBounds(pts,{padding:[70,70],maxZoom:9}); loadWall._fit=true; }
  const inc=d.incidents||[]; document.getElementById('fed-inc-n').textContent=inc.length||'';
  document.getElementById('fed-inc').innerHTML=inc.length? inc.map(i=>`<div class="inc ${esc(i.severity)}" onclick="fedFocus('${esc(i.site)}')" style="cursor:pointer">
    <span class="idot" style="background:${i.severity==='critical'?'#ff5a5a':(i.severity==='warning'?'#f0a92c':'#4da3ff')}"></span>
    <div><div class="it">${esc(i.title)}</div><div class="im"><span class="sbadge">${esc(i.site_name||i.site)}</span> ${i.node?esc(i.node)+' · ':''}${relAge(i.age_s)}</div></div></div>`).join('')
    : '<div class="dim" style="padding:14px;text-align:center">No open incidents across the cluster 🎉</div>';
}
function fedFocus(site){ const mk=FED_MK[site]; if(mk){ FED_MAP.setView(mk.getLatLng(),9,{animate:true}); mk.openPopup(); } }
function fedFit(){ const pts=Object.values(FED_MK).map(m=>m.getLatLng()); if(pts.length)FED_MAP.fitBounds(pts,{padding:[70,70],maxZoom:9}); }
function fedFs(){ const w=document.getElementById('wall-wrap'), fs=document.fullscreenElement||document.webkitFullscreenElement;
  if(!fs){ (w.requestFullscreen||w.webkitRequestFullscreen||function(){}).call(w); } else { (document.exitFullscreen||document.webkitExitFullscreen||function(){}).call(document); } }
function _fedFsSync(){ const on=!!(document.fullscreenElement||document.webkitFullscreenElement); const b=document.getElementById('fed-fsb'); if(b)b.innerHTML='<i class="fa-solid fa-'+(on?'down-left-and-up-right-to-center':'up-right-and-down-left-from-center')+'"></i> '+(on?'Exit':'Fullscreen'); setTimeout(()=>{ if(FED_MAP)FED_MAP.invalidateSize(); },140); }
document.addEventListener('fullscreenchange',_fedFsSync); document.addEventListener('webkitfullscreenchange',_fedFsSync);

// ── overview ──
async function loadOverview(){ const d=await jget('federation.php?api=overview&_='+Date.now()); const g=document.getElementById('ov-grid'); if(!d||!d.ok)return;
  if(!d.sites.length){ g.innerHTML='<div class="glass empty" style="grid-column:1/-1"><i class="fa-solid fa-sitemap"></i>'+(d.role==='standalone'?'This install is <b>standalone</b>.<br><span class="muted">'+(IS_ADMIN?'Set a role in <b>Setup</b> to start a cluster.':'Ask an admin to configure the cluster.')+'</span>':'No sites visible to you yet.')+'</div>'; return; }
  // slave sync banner (this install reports UP to the master; it sees only itself)
  let banner='';
  if(d.sync){ const s=d.sync; const c=s.status==='online'?'#2ee66e':(s.status==='stale'?'#f0a92c':'#ff5a5a');
    banner=`<div class="glass card" style="grid-column:1/-1;border-left:3px solid ${c}"><b><i class="fa-solid fa-tower-broadcast" style="color:${c}"></i> Reporting to master</b>
      <div class="muted" style="margin-top:4px">${s.master?('→ '+esc(s.master)):'no master URL set'} · <b style="color:${c}">${esc(s.status)}</b>${s.buffered?(' · '+s.buffered+' buffered offline'):''}${s.last_ok?(' · last OK '+esc(s.last_ok)+' UTC'):''}${(s.status!=='online'&&s.last_err)?('<br><span style="color:#ff9b91">'+esc(s.last_err)+'</span>'):''}</div>
      <div class="muted" style="margin-top:6px;font-size:11px">This is a <b>slave</b> — it shows only its own site. The full cluster view lives on the master.</div></div>`; }
  g.innerHTML=banner + d.sites.map(s=>{ const n=s.nodes, up=n.up,dn=n.down,dg=n.degraded,tot=Math.max(1,n.total);
    const pu=up/tot*100, pd=dn/tot*100, pg=dg/tot*100;
    return `<div class="glass site ${s.status}" style="cursor:pointer" title="Show only ${esc(s.name)}'s devices" onclick="drillSite('${esc(s.site)}')">
      <span class="stat ${s.status}">${s.status}</span>
      <h3>${esc(s.name)}</h3><div class="slug">${esc(s.site)}</div>
      <div class="metrics">
        <div class="metric"><div class="n" style="color:var(--ok)">${up}</div><div class="l">up</div></div>
        <div class="metric"><div class="n" style="color:${dn?'var(--crit)':'#6f7a8c'}">${dn}</div><div class="l">down</div></div>
        <div class="metric"><div class="n" style="color:${dg?'var(--warn)':'#6f7a8c'}">${dg}</div><div class="l">degraded</div></div>
        <div class="metric"><div class="n" style="color:${s.incidents.open?'var(--warn)':'#6f7a8c'}">${s.incidents.open}</div><div class="l">incidents${s.incidents.critical?' · '+s.incidents.critical+'🔴':''}</div></div>
      </div>
      <div class="bar2"><i style="width:${pu}%;background:#2ee66e"></i><i style="width:${pg}%;background:#f0a92c"></i><i style="width:${pd}%;background:#ff5a5a"></i></div>
      <div class="seen"><i class="fa-solid fa-tower-broadcast"></i> ${s.status==='never'?'no data yet':'seen '+relAge(s.age)} · ${n.total} nodes</div>
    </div>`; }).join('');
}

// ── setup ──
async function loadCfg(){ const d=await jget('federation.php?api=cfg'); if(!d||!d.ok)return; const c=d.cfg;
  document.getElementById('c-role').value=c.role; document.getElementById('c-slug').value=c.site_slug; document.getElementById('c-name').value=c.site_name; document.getElementById('c-master').value=c.master_url;
  document.getElementById('c-token').placeholder=c.has_token?'token set · leave blank to keep':'paste the token';
  roleUI(); }
const ROLE_HINT={
  standalone:`<b>Standalone.</b> This portal runs on its own — no telemetry leaves it and it shows nothing about other sites. Pick <b>master</b> or <b>slave</b> to join a cluster.`,
  master:`<b>Master.</b> Aggregates the whole cluster: it ingests each slave's rollup and shows the federated Overview. Register your slaves (and hand out their tokens) in the <b>Sites</b> tab. It also appears as a site itself.`,
  slave:`<b>Slave.</b> Keeps monitoring locally and, every minute, pushes a compact rollup (nodes up/down, incidents) to the master below. If the master is unreachable it buffers offline and flushes on reconnect — raw telemetry stays here.`
};
function roleUI(){ const r=document.getElementById('c-role').value;
  document.getElementById('slave-cfg').classList.toggle('hide',r!=='slave');
  document.getElementById('pushb').style.display=(r==='slave')?'inline-flex':'none';
  document.getElementById('rolehint').innerHTML=ROLE_HINT[r]||'';
  document.getElementById('cron-callout').style.display=(r==='standalone')?'none':'block';
}
function copyCron(btn){ copyText(document.getElementById('cronline').textContent,btn); }
function copyEl(id,btn){ copyText(document.getElementById(id).textContent,btn); }
function copyText(t,btn){ navigator.clipboard.writeText(t).then(()=>{ const o=btn.innerHTML; btn.innerHTML='<i class="fa-solid fa-check"></i> Copied'; setTimeout(()=>btn.innerHTML=o,1400); }).catch(()=>{}); }
async function saveCfg(){ const b={cluster_role:document.getElementById('c-role').value,site_slug:document.getElementById('c-slug').value.trim(),site_name:document.getElementById('c-name').value.trim(),master_url:document.getElementById('c-master').value.trim()};
  const tk=document.getElementById('c-token').value.trim(); if(tk)b.token=tk;
  const d=await jpost('save_cfg',b); const m=document.getElementById('setup-msg');
  if(d&&d.ok){ m.textContent='✓ Saved'; m.style.color='#8ff0b6'; document.getElementById('rolechip').textContent=d.cfg.role; document.getElementById('rolechip').className='rolechip '+d.cfg.role; document.getElementById('idchip').textContent=d.cfg.site_name?d.cfg.site_name+' · '+d.cfg.site_slug:'no site identity set'; document.getElementById('c-token').value=''; } else { m.textContent='✗ '+((d&&d.error)||'failed'); m.style.color='#ff9b91'; }
}
async function pushNow(){ const m=document.getElementById('setup-msg'); m.style.color='#8a909a'; m.innerHTML='<i class="fa-solid fa-spinner fa-spin"></i> Pushing…';
  const d=await jpost('push_now',{});
  if(d&&d.ok){ m.style.color='#8ff0b6'; m.textContent='✓ Online — pushed to master'+(d.flushed?(' (+'+d.flushed+' buffered)'):''); return; }
  m.style.color='#ff9b91';
  if(d&&(d.mode==='auth'||d.mode==='rejected')) m.innerHTML='⛔ '+esc(d.error||'rejected by master');
  else m.textContent='✗ master unreachable — buffered offline'+(d&&d.error?(' ('+esc(d.error)+')'):''); }

// ── health ──
async function loadHealth(){ const L=document.getElementById('hz-list'), R=document.getElementById('hz-role'); L.innerHTML='<i class="fa-solid fa-spinner fa-spin"></i> Running checks…';
  const d=await jget('federation.php?api=health'); if(!d||!d.ok){ L.innerHTML='<span style="color:#ff9b91">Could not run checks.</span>'; return; }
  R.textContent=d.role; R.className='rolechip '+d.role;
  const ic={ok:'<i class="fa-solid fa-circle-check" style="color:#6ee7a8"></i>',warn:'<i class="fa-solid fa-triangle-exclamation" style="color:#ffcf6b"></i>',fail:'<i class="fa-solid fa-circle-xmark" style="color:#ff8b80"></i>'};
  L.innerHTML='<div style="display:flex;flex-direction:column;gap:8px">'+d.checks.map(c=>`
    <div style="display:flex;gap:11px;align-items:flex-start;padding:11px 13px;border:1px solid var(--border);border-radius:11px;background:${c.status==='fail'?'rgba(231,76,60,.06)':c.status==='warn'?'rgba(240,169,44,.05)':'rgba(46,204,113,.04)'}">
      <div style="font-size:16px;line-height:1.2">${ic[c.status]||''}</div>
      <div style="flex:1;min-width:0">
        <div style="font-weight:700;color:#e6edf7">${esc(c.label)}</div>
        <div class="muted" style="margin-top:2px">${esc(c.detail)}</div>
        ${c.fix?`<div style="margin-top:6px;font-size:12px;color:#9fc4ea"><i class="fa-solid fa-wrench" style="opacity:.7"></i> ${esc(c.fix)}</div>`:''}
      </div>
    </div>`).join('')+'</div>'
    + (d.fails?`<div style="margin-top:12px;color:#ff9b91"><b>${d.fails}</b> issue(s) to fix above.</div>`:'<div style="margin-top:12px;color:#8ff0b6"><i class="fa-solid fa-circle-check"></i> All checks passed — the cluster link is healthy.</div>');
}
// ── enroll (slave: paste; master: generate per site) ──
async function enroll(){ const code=document.getElementById('enr-code').value.trim(), m=document.getElementById('enr-msg');
  if(!code){ m.textContent='paste a code first'; m.style.color='#ffcf6b'; return; }
  m.style.color='#8a909a'; m.innerHTML='<i class="fa-solid fa-spinner fa-spin"></i> Enrolling…';
  const d=await jpost('enroll',{code}); if(!d||!d.ok){ m.style.color='#ff9b91'; m.textContent='✗ '+((d&&d.error)||'failed'); return; }
  const p=d.probe||{};
  if(p.ok){ m.style.color='#8ff0b6'; m.innerHTML='✓ Enrolled as <b>'+esc(d.slug)+'</b> → '+esc(d.master)+' · <b>connected</b>'; }
  else { m.style.color='#ffcf6b'; m.innerHTML='Enrolled as <b>'+esc(d.slug)+'</b>, but the live test failed: '+esc(p.reason||'?')+' — open <b>Health</b>.'; }
  document.getElementById('enr-code').value=''; loadCfg();
}
async function enrollCode(id,name){ const d=await jpost('enroll_code',{id});
  if(!d||!d.ok){ alert('Could not generate code: '+((d&&d.error)||'failed')); return; }
  prompt('Enrollment code for "'+name+'" — paste it on the slave (Federation → Setup → Quick enroll):', d.code);
}

// ── sites ──
async function loadSites(){ const d=await jget('federation.php?api=sites'); const tb=document.getElementById('sites-body'); if(!d||!d.ok)return;
  tb.innerHTML=d.sites.length? d.sites.map(s=>`<tr>
    <td><b>${esc(s.name)}</b></td><td class="dim" style="font-family:monospace">${esc(s.site)}</td>
    <td class="dim" style="font-size:11px">${esc(s.endpoint||'—')}</td>
    <td>${s.has_token?'<span class="dim">•••• set</span>':'<span style="color:#ff9b91">none</span>'} <span class="tg" title="reset token" onclick="resetTok(${s.id},'${esc(s.name)}')"><i class="fa-solid fa-key"></i></span></td>
    <td>${s.enabled?'<span style="color:#8ff0b6">yes</span>':'<span class="dim">no</span>'}</td>
    <td style="text-align:right"><span class="tg" title="enrollment code (paste on the slave)" onclick="enrollCode(${s.id},'${esc(s.name)}')"><i class="fa-solid fa-ticket"></i></span><span class="tg" title="edit" onclick='editSite(${JSON.stringify(s)})'><i class="fa-solid fa-pen"></i></span><span class="tg danger" title="delete" onclick="delSite(${s.id},'${esc(s.name)}')"><i class="fa-solid fa-trash"></i></span></td></tr>`).join('')
    : '<tr><td colspan="6" class="muted" style="padding:18px">No sites yet — click <b>Register site</b>.</td></tr>';
}
function siteForm(){ document.getElementById('sm-title').textContent='Register site'; document.getElementById('sm-id').value=''; document.getElementById('sm-slug').value=''; document.getElementById('sm-name').value=''; document.getElementById('sm-ep').value=''; document.getElementById('sm-lat').value=''; document.getElementById('sm-lon').value=''; document.getElementById('sm-en').checked=true; document.getElementById('sm-slug').disabled=false; document.getElementById('sm-tok').classList.add('hide'); document.getElementById('sm-msg').textContent=''; document.getElementById('site-modal').style.display='flex'; }
function editSite(s){ document.getElementById('sm-title').textContent='Edit site'; document.getElementById('sm-id').value=s.id; document.getElementById('sm-slug').value=s.site; document.getElementById('sm-slug').disabled=true; document.getElementById('sm-name').value=s.name; document.getElementById('sm-ep').value=s.endpoint||''; document.getElementById('sm-lat').value=s.lat!=null?s.lat:''; document.getElementById('sm-lon').value=s.lon!=null?s.lon:''; document.getElementById('sm-en').checked=!!s.enabled; document.getElementById('sm-tok').classList.add('hide'); document.getElementById('sm-msg').textContent=''; document.getElementById('site-modal').style.display='flex'; }
function closeSite(){ document.getElementById('site-modal').style.display='none'; loadSites(); }
async function saveSite(){ const id=document.getElementById('sm-id').value; const b={id:id||0,site_slug:document.getElementById('sm-slug').value.trim(),name:document.getElementById('sm-name').value.trim(),endpoint_url:document.getElementById('sm-ep').value.trim(),lat:document.getElementById('sm-lat').value.trim(),lon:document.getElementById('sm-lon').value.trim(),enabled:document.getElementById('sm-en').checked?1:0};
  const d=await jpost('site_save',b); if(!d||!d.ok){ document.getElementById('sm-msg').textContent=(d&&d.error)||'failed'; return; }
  // Lock the row identity so any further Save is an EDIT (never re-mints the token).
  document.getElementById('sm-id').value=d.id;
  document.getElementById('sm-slug').disabled=true;
  if(d.created && d.token){   // brand-new site → the token minted by site_save, shown ONCE
    document.getElementById('sm-tok').classList.remove('hide');
    document.getElementById('sm-tokv').textContent=d.token;
    document.getElementById('sm-title').textContent='Site registered ✓ — copy the token, then Close';
    loadSites();
    return;   // keep the modal open so the shown token == the stored token until Close
  }
  closeSite();
}
async function resetTok(id,name){ if(!confirm('Reset the token for “'+name+'”?\nThe old token stops working — update the slave with the new one.'))return; const t=await jpost('site_token',{id}); if(t&&t.ok){ prompt('New token for '+name+' (copy to the slave):',t.token); loadSites(); } }
async function delSite(id,name){ if(!confirm('Delete site “'+name+'” and its history?'))return; const d=await jpost('site_delete',{id}); if(d&&d.ok)loadSites(); }

// ── visibility ──
async function loadVis(){ const d=await jget('federation.php?api=roles'); const el=document.getElementById('vis-body'); if(!d||!d.ok)return;
  if(!d.roles.length){ el.innerHTML='<span class="dim">No non-admin roles defined.</span>'; return; }
  el.innerHTML=d.roles.map(role=>{ const have=(d.visibility[role]||[]); const all=have.includes('*');
    const chips=`<label class="chk"><input type="checkbox" data-role="${esc(role)}" data-site="*" ${all?'checked':''} onchange="visStar(this)"> <b>All sites</b></label>`+
      d.sites.map(s=>`<label class="chk"><input type="checkbox" data-role="${esc(role)}" data-site="${esc(s.slug)}" ${(all||have.includes(s.slug))?'checked':''} ${all?'disabled':''}> ${esc(s.name)} <span class="dim">(${esc(s.slug)})</span></label>`).join('');
    return `<div style="margin-bottom:16px"><div style="font-weight:700;margin-bottom:8px;text-transform:capitalize">${esc(role)}</div><div class="viz">${chips}</div><button class="btn sm" style="margin-top:8px" onclick="visSave('${esc(role)}')">Save ${esc(role)}</button></div>`;
  }).join('');
}
function visStar(cb){ const role=cb.dataset.role; document.querySelectorAll(`#vis-body input[data-role="${CSS.escape(role)}"]`).forEach(x=>{ if(x.dataset.site!=='*'){ x.disabled=cb.checked; if(cb.checked)x.checked=true; } }); }
async function visSave(role){ const sites=[]; document.querySelectorAll(`#vis-body input[data-role="${CSS.escape(role)}"]:checked`).forEach(x=>sites.push(x.dataset.site));
  const finalSites=sites.includes('*')?['*']:sites; const d=await jpost('vis_set',{role,sites:finalSites}); if(d&&d.ok){ loadVis(); } }

// init
loadOverview(); polling=setInterval(()=>{ if(CUR==='overview')loadOverview(); else if(CUR==='wall')loadWall(); else if(CUR==='incidents')loadFedIncidents(); }, 15000);
window.addEventListener('DOMContentLoaded',()=>{ if(window.NMLoader)NMLoader.hide(); });
</script>
</body></html>
