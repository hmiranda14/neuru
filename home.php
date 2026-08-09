<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Command Deck (launchpad / landing). Post-login home: a live NOC-vitals
// hero + a searchable, RBAC-filtered grid of every module the user can open, with
// pinned favourites + recents. Built from nm_perm_catalog() so it always reflects
// the real page list + permissions.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_access.php');
include('logger.php');
@require_once('nm_tz.php');

$uid  = (int)($_SESSION['UID'] ?? 0);
$role = $_SESSION['role'] ?? 'guest';
$user = $_SESSION['username'] ?? '';
$api  = $_GET['api'] ?? '';

// ── Live vitals (polled) ─────────────────────────────────────────────────────
if ($api === 'vitals') {
    header('Content-Type: application/json; charset=utf-8');
    if (session_status() === PHP_SESSION_ACTIVE) @session_write_close();
    $q = fn($sql)=>(($r=$conn->query($sql)) ? $r->fetch_assoc() : null);
    $has = fn($t)=>($conn->query("SHOW TABLES LIKE '".$t."'")->num_rows>0);

    $total = (int)($q("SELECT COUNT(*) c FROM nm_nodes")['c'] ?? 0);
    $down=0; $degraded=0;
    if ($r=$conn->query("SELECT last_status,COUNT(*) c FROM nm_alert_state WHERE entity_type='node' AND last_status IN('down','degraded','lowerlayerdown','notpresent','testing') GROUP BY last_status"))
        while ($x=$r->fetch_assoc()){ if($x['last_status']==='degraded') $degraded+=(int)$x['c']; else $down+=(int)$x['c']; }
    $up = max(0, $total - $down - $degraded);

    $incOpen=0; $incCrit=0;
    if ($has('nm_incidents')) {
        $incOpen=(int)($q("SELECT COUNT(*) c FROM nm_incidents WHERE status IN('open','acknowledged')")['c'] ?? 0);
        $incCrit=(int)($q("SELECT COUNT(*) c FROM nm_incidents WHERE status IN('open','acknowledged') AND severity='critical'")['c'] ?? 0);
    }
    $botActive=0; $botLast=null; $botEnabled=false;
    if ($has('nm_ap2_sessions')) {   // NEURU Commander (v2) — the live autonomous brain
        $botActive=(int)($q("SELECT COUNT(*) c FROM nm_ap2_sessions WHERE status IN('active','awaiting_approval')")['c'] ?? 0);
        if ($has('nm_ap2_events')) $botLast=$q("SELECT TIMESTAMPDIFF(MINUTE,MAX(created_at),NOW()) a FROM nm_ap2_events")['a'] ?? null;
        $botEnabled = (($q("SELECT setting_val v FROM nm_settings WHERE setting_key='ap2_enabled'")['v'] ?? '0') === '1');
    } elseif ($has('nm_aip_sessions')) {   // fallback: legacy NetAIObot (v1) if v2 isn't present
        $botActive=(int)($q("SELECT COUNT(*) c FROM nm_aip_sessions WHERE status IN('active','awaiting_approval')")['c'] ?? 0);
        $botLast=$q("SELECT TIMESTAMPDIFF(MINUTE,MAX(created_at),NOW()) a FROM nm_aip_events")['a'] ?? null;
    }
    $dbok=null;
    if ($has('nm_db_targets')) $dbok=(int)($q("SELECT COUNT(*) c FROM nm_db_targets WHERE enabled=1 AND last_status='ok'")['c'] ?? 0);
    // avg uptime last 24h (cheap: ping-based nodes)
    $slaAvg=null;
    if ($r=$conn->query("SELECT node_id, AVG(is_up)*100 u FROM nm_ping_stats WHERE recorded_at>=(NOW()-INTERVAL 1440 MINUTE) GROUP BY node_id")) {
        $s=0;$n=0; while($x=$r->fetch_assoc()){ $s+=(float)$x['u']; $n++; } if($n) $slaAvg=round($s/$n,2);
    }
    echo json_encode(['ok'=>true,'nodes'=>['total'=>$total,'up'=>$up,'down'=>$down,'degraded'=>$degraded],
        'incidents'=>['open'=>$incOpen,'critical'=>$incCrit],'bot'=>['active'=>$botActive,'last_min'=>$botLast,'enabled'=>$botEnabled],
        'db_ok'=>$dbok,'sla_avg'=>$slaAvg]);
    exit;
}

log_user_action($conn, 'view_page', 'home.php');

// ── Build the RBAC-filtered app grid from the permission catalog ─────────────
$catalog = nm_perm_catalog();
$CAT_ORDER = ['Command Centers','Monitoring','AI Tools','Ext Monitoring','Healing','Gaming','Net Tools','Device Tools','Logs & AI','Infrastructure','Site Configuration','Administration'];
$CAT_META = [
  'Command Centers'    =>['#22d3ee','fa-satellite-dish'],
  'Monitoring'         =>['#4da3ff','fa-gauge-high'],
  'AI Tools'           =>['#9b6bff','fa-brain'],
  'Ext Monitoring'     =>['#36e3d0','fa-satellite-dish'],
  'Healing'            =>['#16c79a','fa-shield-heart'],
  'Gaming'             =>['#b06bff','fa-gamepad'],
  'Net Tools'          =>['#f39c12','fa-toolbox'],
  'Device Tools'       =>['#9b59b6','fa-network-wired'],
  'Logs & AI'          =>['#2ecc71','fa-wand-magic-sparkles'],
  'Infrastructure'     =>['#e67e22','fa-server'],
  'Site Configuration' =>['#7f8c9a','fa-sliders'],
  'Administration'     =>['#e74c3c','fa-user-shield'],
];
$apps = [];
foreach ($catalog as $e) {
    [$key,$label,$category,$icon,$page] = array_pad($e, 5, null);
    if (!$page) continue;                             // no page → not launchable
    if (!nm_user_can($conn, $uid, $role, $key)) continue;
    if ($category === 'Gaming') continue;             // Gaming is expanded in full below
    $apps[$category][] = ['key'=>$key,'label'=>html_entity_decode($label),'icon'=>$icon,'page'=>$page];
}
// Gaming: the nav funnels everything through the Gamers Hub, so the Command Deck lists
// EVERY gaming tool as its own launch card. All share the 'gaming' perm (PC Doctor →
// 'pc_doctor'); kept out of the perm catalog so RBAC admin stays one clean toggle each.
$gaming_tools = [
  ['gaming',    'Gamers Hub',        'fa-solid fa-gamepad',      'game_hub.php'],
  ['gaming',    'Gaming Deck',       'fa-solid fa-cube',         'gaming.php'],
  ['gaming',    'Game Lab',          'fa-solid fa-flask-vial',   'game_lab.php'],
  ['gaming',    'Parallel Reality',  'fa-solid fa-atom',         'reality.php'],
  ['gaming',    'Synaptic Map',      'fa-solid fa-brain',        'synaptic.php'],
  ['gaming',    'PC Benchmark',      'fa-solid fa-gauge-high',   'benchmark.php'],
  ['gaming',    'Hardware Longevity','fa-solid fa-heart-pulse',  'longevity.php'],
  ['gaming',    'Connection Doctor', 'fa-solid fa-wave-square',  'net_doctor.php'],
  ['gaming',    'Fan Profiler',      'fa-solid fa-fan',          'fan_profiler.php'],
  ['pc_doctor', 'PC Doctor',         'fa-solid fa-microchip',    'pc_troubleshoot.php'],
];
foreach ($gaming_tools as $g) {
    if (!nm_user_can($conn, $uid, $role, $g[0])) continue;
    $apps['Gaming'][] = ['key'=>$g[0],'label'=>$g[1],'icon'=>$g[2],'page'=>$g[3]];
}
$appCount = 0; foreach ($apps as $g) $appCount += count($g);
// flat JSON for client search + pinned/recent
$flat = [];
foreach ($apps as $cat=>$list) foreach ($list as $a) $flat[] = $a + ['cat'=>$cat, 'color'=>($CAT_META[$cat][0] ?? '#4da3ff')];
// KPI → destination page, but ONLY if the user can open it (else the card isn't clickable)
$vgo = function(string $key, string $page) use ($conn,$uid,$role){ return nm_user_can($conn,$uid,$role,$key) ? $page : ''; };
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Command Deck | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" media="print" onload="this.media='all'">
<noscript><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"></noscript>
<?= function_exists('nm_tz_js') ? nm_tz_js() : '' ?>
<style>
:root{ --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --glass:rgba(255,255,255,.055); --border:rgba(255,255,255,.12); --ease:cubic-bezier(.22,.61,.36,1); }
html{ background:#05080f; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; color:#e7ecf3; background:transparent!important; overflow-x:hidden; }
.wrap{ max-width:1500px; margin:0 auto; padding:22px 22px 80px; animation:deckFade .8s var(--ease) both; }
@keyframes deckFade{ from{ opacity:0; transform:translateY(10px);} to{ opacity:1; transform:none; } }

/* faint moving aurora behind everything (above the particle canvas, under content) */
.aurora{ position:fixed; inset:-20% -10% auto -10%; height:70vh; z-index:-1; pointer-events:none; filter:blur(70px); opacity:.32;
  background:radial-gradient(40% 60% at 20% 30%, rgba(54,227,208,.30), transparent 70%),
             radial-gradient(45% 55% at 80% 20%, rgba(120,110,255,.28), transparent 70%),
             radial-gradient(40% 50% at 55% 70%, rgba(77,163,255,.24), transparent 70%);
  animation:aurora 24s ease-in-out infinite alternate; }
@keyframes aurora{ 0%{ transform:translate3d(-3%,-2%,0) scale(1);} 50%{ transform:translate3d(4%,2%,0) scale(1.12);} 100%{ transform:translate3d(-2%,3%,0) scale(1.05);} }

/* ── hero ── */
.hero{ display:flex; align-items:flex-end; gap:20px; flex-wrap:wrap; margin-bottom:16px; }
.hi{ font-size:15px; color:#8a93a3; } .hi b{ color:#e7ecf3; }
.hero h1{ font-size:clamp(26px,4vw,38px); margin:2px 0 0; font-weight:800; letter-spacing:.5px;
  background:linear-gradient(100deg,#7fc0ff 0%,#36e3d0 40%,#9b6bff 75%,#7fc0ff 100%); background-size:220% auto;
  -webkit-background-clip:text; background-clip:text; color:transparent; animation:shine 9s linear infinite; }
@keyframes shine{ to{ background-position:220% center; } }
.clock{ margin-left:auto; text-align:right; } .clock .t{ font-size:26px; font-weight:800; font-variant-numeric:tabular-nums; letter-spacing:1px; }
.clock .d{ font-size:12px; color:#8a93a3; }

/* ── vitals ── */
.vitals{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:20px; }
.v{ background:var(--glass); border:1px solid var(--border); border-radius:14px; padding:14px 16px; position:relative; overflow:hidden;
  transition:transform .3s var(--ease), box-shadow .3s var(--ease), border-color .3s; opacity:0; transform:translateY(10px); animation:rise .5s var(--ease) forwards; }
.v:hover{ transform:translateY(-3px); border-color:color-mix(in srgb,var(--c) 55%,transparent); box-shadow:0 10px 26px rgba(0,0,0,.4),0 0 20px color-mix(in srgb,var(--c) 22%,transparent); }
.v::after{ content:''; position:absolute; inset:0 auto 0 0; width:3px; background:var(--c,#4da3ff); box-shadow:0 0 12px var(--c); }
.v::before{ content:''; position:absolute; top:0; left:0; right:0; height:1px; background:linear-gradient(90deg,transparent,var(--c),transparent); opacity:.5; animation:sweep 3.5s linear infinite; }
@keyframes sweep{ 0%{ transform:translateX(-100%);} 100%{ transform:translateX(100%);} }
.v .n{ font-size:24px; font-weight:800; font-variant-numeric:tabular-nums; } .v .l{ font-size:11px; color:#8a93a3; text-transform:uppercase; letter-spacing:.5px; }
.v .s{ font-size:11px; margin-top:2px; }
.v.clk{ cursor:pointer; }
.v .khint{ position:absolute; top:11px; right:12px; color:var(--c); font-size:12px; opacity:0; transform:translateX(-5px); transition:.22s var(--ease); }
.v.clk:hover .khint{ opacity:.85; transform:none; }
.v.clk:active{ transform:translateY(-1px) scale(.985); }
.ripple{ position:absolute; border-radius:50%; pointer-events:none; z-index:2; transform:translate(-50%,-50%) scale(0); mix-blend-mode:screen;
  background:radial-gradient(circle,color-mix(in srgb,var(--c) 60%,transparent),transparent 62%); animation:rip .6s var(--ease) forwards; }
@keyframes rip{ to{ transform:translate(-50%,-50%) scale(1); opacity:0; } }
.v.burst{ animation:vburst .45s var(--ease); }
@keyframes vburst{ 0%{ box-shadow:none;} 45%{ box-shadow:0 0 0 2px var(--c),0 0 46px color-mix(in srgb,var(--c) 55%,transparent);} 100%{ box-shadow:none;} }

/* ── search + toolbar ── */
.toolbar{ display:flex; gap:12px; align-items:center; margin-bottom:22px; flex-wrap:wrap; }
.search{ position:relative; flex:1; min-width:240px; }
.search i.mag{ position:absolute; left:16px; top:50%; transform:translateY(-50%); color:#5a6472; }
.search input{ width:100%; box-sizing:border-box; background:rgba(255,255,255,.05); border:1px solid var(--border); border-radius:14px; color:#e7ecf3; font-size:16px; padding:15px 16px 15px 46px; outline:none; transition:border-color .2s, box-shadow .2s; }
.search input:focus{ border-color:var(--accent); box-shadow:0 0 0 3px rgba(77,163,255,.15); }
.search .kbd{ position:absolute; right:14px; top:50%; transform:translateY(-50%); font-size:11px; color:#5a6472; border:1px solid var(--border); border-radius:6px; padding:2px 7px; }
.seg{ display:inline-flex; background:rgba(255,255,255,.05); border:1px solid var(--border); border-radius:12px; padding:3px; }
.seg button{ background:none; border:0; color:#9aa5b4; font:inherit; font-size:13px; padding:9px 14px; border-radius:9px; cursor:pointer; display:inline-flex; align-items:center; gap:7px; transition:.2s; }
.seg button.on{ background:linear-gradient(120deg,rgba(77,163,255,.25),rgba(54,227,208,.22)); color:#eaf6ff; box-shadow:inset 0 0 0 1px rgba(54,227,208,.35); }
.tbtn{ background:rgba(255,255,255,.05); border:1px solid var(--border); color:#cfe0f2; border-radius:12px; padding:11px 15px; font:inherit; font-size:13px; cursor:pointer; display:inline-flex; align-items:center; gap:8px; transition:.2s; white-space:nowrap; }
.tbtn:hover{ border-color:var(--accent); color:#fff; } .tbtn.live{ border-color:rgba(54,227,208,.5); color:#8ff0e4; box-shadow:0 0 16px rgba(54,227,208,.18); }
.tbtn i.dotp{ width:8px;height:8px;border-radius:50%;background:#36e3d0;box-shadow:0 0 8px #36e3d0;animation:pulse 1.6s ease-in-out infinite; }
@keyframes pulse{ 0%,100%{ opacity:.4; transform:scale(.85);} 50%{ opacity:1; transform:scale(1.15);} }

/* ── category rail ── */
.rail{ display:flex; gap:9px; overflow-x:auto; padding:4px 2px 12px; margin-bottom:6px; scrollbar-width:none; }
.rail::-webkit-scrollbar{ display:none; }
.chip{ display:inline-flex; align-items:center; gap:8px; white-space:nowrap; background:var(--glass); border:1px solid var(--border); color:#aeb9c8;
  border-radius:30px; padding:8px 15px; font-size:13px; cursor:pointer; transition:.25s var(--ease); position:relative; }
.chip i{ color:var(--c); } .chip .cc{ font-size:11px; color:#68727f; }
.chip.on{ color:#fff; border-color:color-mix(in srgb,var(--c) 60%,transparent); background:color-mix(in srgb,var(--c) 16%,transparent); box-shadow:0 0 20px color-mix(in srgb,var(--c) 28%,transparent); transform:translateY(-1px); }
.chip.on .cc{ color:#cfe0f2; }

/* ── DECK carousel ── */
.stage{ position:relative; }
.deck{ display:flex; gap:26px; overflow-x:auto; scroll-snap-type:x mandatory; padding:14px 20px 26px; perspective:1600px; scrollbar-width:none; scroll-behavior:smooth; }
.deck::-webkit-scrollbar{ display:none; }
.slide{ scroll-snap-align:center; flex:0 0 min(1120px,86vw); min-width:min(1120px,86vw); transform-style:preserve-3d;
  will-change:transform,opacity; transition:opacity .2s linear; }
.slidecard{ background:linear-gradient(160deg,rgba(18,24,36,.72),rgba(10,14,22,.68)); border:1px solid var(--border); border-radius:22px; padding:22px 24px 26px;
  box-shadow:0 30px 70px rgba(0,0,0,.5); position:relative; overflow:hidden; }
.slidecard::before{ content:''; position:absolute; inset:0; border-radius:22px; padding:1px; pointer-events:none;
  background:linear-gradient(120deg,color-mix(in srgb,var(--c) 55%,transparent),transparent 45%); -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0); -webkit-mask-composite:xor; mask-composite:exclude; opacity:.6; }
.slidecard::after{ content:''; position:absolute; top:-30%; right:-12%; width:340px; height:340px; border-radius:50%; pointer-events:none;
  background:radial-gradient(circle,color-mix(in srgb,var(--c) 20%,transparent),transparent 68%); }
.slide-h{ display:flex; align-items:center; gap:14px; margin-bottom:18px; position:relative; }
.slide-h .sic{ width:52px; height:52px; border-radius:14px; display:flex; align-items:center; justify-content:center; font-size:23px; color:var(--c);
  background:color-mix(in srgb,var(--c) 15%,transparent); box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--c) 40%,transparent), 0 0 22px color-mix(in srgb,var(--c) 22%,transparent); }
.slide-h h2{ margin:0; font-size:22px; font-weight:800; letter-spacing:.3px; } .slide-h .sc{ font-size:12px; color:#7c8797; margin-top:2px; }
.slide-h::after{ content:''; position:absolute; left:66px; right:0; bottom:-9px; height:2px; background:linear-gradient(90deg,var(--c),transparent 60%); opacity:.55; }

/* ── app grid + cards ── */
.grid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr)); gap:13px; }
.app{ background:var(--glass); border:1px solid var(--border); border-radius:15px; padding:16px; cursor:pointer; position:relative; overflow:hidden;
  transition:transform .18s var(--ease), border-color .18s, box-shadow .18s; opacity:0; transform:translateY(12px); animation:rise .5s var(--ease) forwards; transform-style:preserve-3d; }
@keyframes rise{ to{ opacity:1; transform:translateY(0);} }
.app:hover{ border-color:var(--c); box-shadow:0 14px 34px rgba(0,0,0,.45), 0 0 26px color-mix(in srgb,var(--c) 34%, transparent); }
.app::before{ content:''; position:absolute; top:-40%; right:-30%; width:130px; height:130px; border-radius:50%; background:radial-gradient(circle,color-mix(in srgb,var(--c) 26%,transparent),transparent 70%); opacity:0; transition:.25s; }
.app:hover::before{ opacity:1; }
.app .ic{ width:44px; height:44px; border-radius:12px; display:flex; align-items:center; justify-content:center; font-size:20px; color:var(--c);
  background:color-mix(in srgb,var(--c) 14%, transparent); margin-bottom:11px; transition:transform .2s var(--ease); }
.app:hover .ic{ transform:translateZ(24px) scale(1.06); }
.app .nm{ font-weight:700; font-size:14px; line-height:1.25; } .app .cat{ font-size:10px; color:#7c828c; margin-top:3px; text-transform:uppercase; letter-spacing:.5px; }
.app .pin{ position:absolute; top:11px; right:12px; color:#5a6472; font-size:12px; opacity:0; transition:.15s; z-index:3; } .app:hover .pin{ opacity:1; } .app .pin.on{ opacity:1; color:var(--warn); }
.app .go{ position:absolute; bottom:12px; right:14px; color:var(--c); font-size:12px; opacity:0; transform:translateX(-6px); transition:.2s var(--ease); }
.app:hover .go{ opacity:.9; transform:none; }

/* ── deck nav (arrows + dots) ── */
.arrow{ position:absolute; top:44%; z-index:6; width:46px; height:46px; border-radius:50%; display:flex; align-items:center; justify-content:center;
  background:rgba(12,17,27,.72); border:1px solid var(--border); color:#cfe0f2; cursor:pointer; backdrop-filter:blur(8px); transition:.2s; }
.arrow:hover{ border-color:var(--accent); color:#fff; box-shadow:0 0 22px rgba(77,163,255,.3); transform:scale(1.06); }
.arrow.prev{ left:6px; } .arrow.next{ right:6px; }
.dots{ display:flex; gap:8px; justify-content:center; margin-top:6px; }
.dots b{ width:8px; height:8px; border-radius:50%; background:rgba(255,255,255,.2); cursor:pointer; transition:.3s var(--ease); }
.dots b.on{ width:26px; border-radius:5px; background:linear-gradient(90deg,#4da3ff,#36e3d0); box-shadow:0 0 12px rgba(54,227,208,.5); }

/* ── stacked grid mode (classic) ── */
.sec-h{ display:flex; align-items:center; gap:10px; margin:26px 0 12px; }
.sec-h .dot{ width:9px; height:9px; border-radius:50%; box-shadow:0 0 10px currentColor; } .sec-h h2{ font-size:14px; margin:0; text-transform:uppercase; letter-spacing:1px; color:#bcc8d6; }
.sec-h .ct{ font-size:11px; color:#5a6472; }
#grid-view .catblock{ animation:rise .5s var(--ease) both; }

.empty{ text-align:center; color:#5a6472; padding:34px; }
.hidden{ display:none !important; }
@media (max-width:640px){ .deck{ padding:14px 16px 24px; } .slide{ flex-basis:88vw; min-width:88vw; } .arrow{ display:none; } }
@media (prefers-reduced-motion:reduce){
  .aurora,.hero h1,.v::before,.tbtn i.dotp{ animation:none !important; }
  .app,.v,.wrap,#grid-view .catblock{ animation:none !important; opacity:1 !important; transform:none !important; }
  .deck{ scroll-behavior:auto; }
}
</style>
</head>
<body>
<?php include('header.php'); ?>
<div class="aurora"></div>
<div class="wrap">
  <div class="hero">
    <div>
      <div class="hi" id="greet">Welcome back<?= $user?', <b>'.htmlspecialchars($user).'</b>':'' ?></div>
      <h1>NEURU Command Deck</h1>
    </div>
    <div class="clock"><div class="t" id="clk">--:--</div><div class="d" id="cdate"></div></div>
  </div>

  <div class="vitals" id="vitals">
    <div class="v" style="--c:var(--ok)" data-go="<?= $vgo('net_mon','net_mon.php') ?>"><div class="n" id="v-up">—</div><div class="l">Nodes up</div><div class="s" id="v-updn" style="color:#8a93a3;"></div></div>
    <div class="v" style="--c:var(--crit)" data-go="<?= $vgo('incidents','incidents.php') ?>"><div class="n" id="v-inc">—</div><div class="l">Open incidents</div><div class="s" id="v-inccrit" style="color:#8a93a3;"></div></div>
    <div class="v" style="--c:var(--accent)" data-go="<?= $vgo('sla_live','sla.php') ?>"><div class="n" id="v-sla">—</div><div class="l">Avg uptime 24h</div></div>
    <div class="v" style="--c:#9b59b6" data-go="<?= $vgo('autopilotv2','autopilotv2.php') ?>"><div class="n" id="v-bot">—</div><div class="l">NEURU Commander</div><div class="s" id="v-botlast" style="color:#8a93a3;"></div></div>
    <div class="v" style="--c:#e67e22" data-go="<?= $vgo('dbmon','dbmon.php') ?>"><div class="n" id="v-db">—</div><div class="l">Databases OK</div></div>
    <div class="v" style="--c:#36e3d0" data-act="grid"><div class="n"><?= $appCount ?></div><div class="l">Modules available</div></div>
  </div>

  <div class="toolbar">
    <div class="search">
      <i class="fas fa-magnifying-glass mag"></i>
      <input id="q" type="text" placeholder="Search modules… (type to filter, Enter to open the first match)" autocomplete="off" oninput="filter()" onkeydown="if(event.key==='Enter')openFirst()">
      <span class="kbd">/ to search</span>
    </div>
    <div class="seg" id="viewseg">
      <button data-v="deck" class="on" onclick="setView('deck')"><i class="fa-solid fa-clone"></i> Deck</button>
      <button data-v="grid" onclick="setView('grid')"><i class="fa-solid fa-table-cells-large"></i> Grid</button>
    </div>
    <button class="tbtn" id="tourbtn" onclick="toggleTour()" title="Auto-glide through the sections"><i class="fa-solid fa-play"></i> Auto-tour</button>
  </div>

  <!-- DECK (carousel) -->
  <div id="deck-view">
    <div class="rail" id="rail"></div>
    <div class="stage">
      <div class="arrow prev" onclick="deckMove(-1)" aria-label="Previous"><i class="fa-solid fa-chevron-left"></i></div>
      <div class="deck" id="deck"></div>
      <div class="arrow next" onclick="deckMove(1)" aria-label="Next"><i class="fa-solid fa-chevron-right"></i></div>
    </div>
    <div class="dots" id="dots"></div>
  </div>

  <!-- GRID (classic stacked) -->
  <div id="grid-view" class="hidden"><div id="cats"></div></div>

  <!-- SEARCH RESULTS -->
  <div id="results" class="hidden"><div class="grid" id="results-grid"></div></div>

  <div class="empty hidden" id="noresult">No module matches — try another term.</div>
</div>

<script>
const APPS=<?= json_encode($flat, JSON_UNESCAPED_SLASHES) ?>;
const USER=<?= json_encode($user) ?>;
const CATORDER=<?= json_encode($CAT_ORDER) ?>;
const CATMETA=<?= json_encode($CAT_META) ?>;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
const PIN_KEY='nm_home_pins', REC_KEY='nm_home_recent';
const pins=()=>JSON.parse(localStorage.getItem(PIN_KEY)||'[]');
const recents=()=>JSON.parse(localStorage.getItem(REC_KEY)||'[]');
function appByPage(p){ return APPS.find(a=>a.page===p); }

const RM = matchMedia('(prefers-reduced-motion: reduce)').matches;
const VIEW_KEY='nm_home_view';
const catColor=c=>(CATMETA[c]||['#4da3ff'])[0];
const catIcon=c=>'fa-solid '+((CATMETA[c]||[,'fa-cube'])[1]||'fa-cube');

function card(a,i){
  const on=pins().includes(a.page);
  return `<div class="app" data-page="${a.page}" data-search="${esc((a.label+' '+a.cat+' '+a.page).toLowerCase())}" style="--c:${a.color};animation-delay:${Math.min(i*28,340)}ms" onclick="openApp('${a.page}')">
    <i class="fas fa-thumbtack pin ${on?'on':''}" title="Pin/unpin" onclick="event.stopPropagation();togglePin('${a.page}')"></i>
    <div class="ic"><i class="${esc(a.icon)}"></i></div>
    <div class="nm">${esc(a.label)}</div><div class="cat">${esc(a.cat)}</div>
    <i class="fa-solid fa-arrow-right go"></i></div>`;
}
function openApp(k){ const a=appByPage(k); if(!a) return; pushRecent(k); location.href=a.page; }
function pushRecent(k){ let r=recents().filter(x=>x!==k); r.unshift(k); r=r.slice(0,6); localStorage.setItem(REC_KEY,JSON.stringify(r)); }
function togglePin(k){ let p=pins(); p=p.includes(k)?p.filter(x=>x!==k):[k,...p].slice(0,12); localStorage.setItem(PIN_KEY,JSON.stringify(p)); buildAll(); }

// ── build the ordered "slides": Pinned, Recent, then each category ──
function slideDefs(){
  const S=[];
  const P=pins().map(appByPage).filter(Boolean);   if(P.length) S.push({id:'__pin',title:'Pinned',icon:'fa-solid fa-thumbtack',color:'#f39c12',apps:P});
  const R=recents().map(appByPage).filter(Boolean); if(R.length) S.push({id:'__rec',title:'Recent',icon:'fa-solid fa-clock-rotate-left',color:'#4da3ff',apps:R});
  const cats=[...CATORDER,...[...new Set(APPS.map(a=>a.cat))].filter(c=>!CATORDER.includes(c))];
  cats.forEach(c=>{ const list=APPS.filter(a=>a.cat===c); if(list.length) S.push({id:c,title:c,icon:catIcon(c),color:catColor(c),apps:list}); });
  return S;
}
let SLIDES=[], CUR=0;
function buildAll(){ SLIDES=slideDefs(); if(CUR>=SLIDES.length) CUR=0; renderDeck(); renderGrid(); applyView(); }

function renderDeck(){
  document.getElementById('deck').innerHTML=SLIDES.map((s,si)=>`<div class="slide" data-si="${si}" style="--c:${s.color}">
    <div class="slidecard"><div class="slide-h"><div class="sic"><i class="${s.icon}"></i></div>
      <div><h2>${esc(s.title)}</h2><div class="sc">${s.apps.length} module${s.apps.length!==1?'s':''}</div></div></div>
      <div class="grid">${s.apps.map((a,i)=>card(a,i)).join('')}</div></div></div>`).join('');
  document.getElementById('rail').innerHTML=SLIDES.map((s,si)=>`<div class="chip" data-si="${si}" style="--c:${s.color}" onclick="goTo(${si})"><i class="${s.icon}"></i>${esc(s.title)}<span class="cc">${s.apps.length}</span></div>`).join('');
  document.getElementById('dots').innerHTML=SLIDES.map((s,si)=>`<b data-si="${si}" onclick="goTo(${si})"></b>`).join('');
  fitDeck(); markActive(CUR); requestAnimationFrame(()=>{ jumpTo(CUR); depth(); });
}
// symmetric padding so ANY slide (first/last included) can sit dead-centre
function fitDeck(){ const deck=document.getElementById('deck'), el=deck.querySelector('.slide'); if(!el) return;
  const pad=Math.max(16,(deck.clientWidth-el.offsetWidth)/2); deck.style.paddingLeft=pad+'px'; deck.style.paddingRight=pad+'px'; }
const centerLeft=(el)=>{ const deck=document.getElementById('deck'); return Math.round(el.offsetLeft-(deck.clientWidth-el.offsetWidth)/2); };
function jumpTo(i){ const els=slideEls(); if(!els[i])return; const deck=document.getElementById('deck'); const b=deck.style.scrollBehavior; deck.style.scrollBehavior='auto'; deck.scrollLeft=centerLeft(els[i]); deck.style.scrollBehavior=b; }
function renderGrid(){
  document.getElementById('cats').innerHTML=SLIDES.map(s=>`<div class="catblock" style="--c:${s.color}">
    <div class="sec-h"><span class="dot" style="background:${s.color};color:${s.color}"></span><h2>${esc(s.title)}</h2><span class="ct">${s.apps.length}</span></div>
    <div class="grid">${s.apps.map((a,i)=>card(a,i)).join('')}</div></div>`).join('');
}

// ── carousel navigation ──
const slideEls=()=>[...document.querySelectorAll('#deck .slide')];
function goTo(i){ const deck=document.getElementById('deck'), els=slideEls(); if(!els.length) return; i=Math.max(0,Math.min(els.length-1,i)); CUR=i;
  deck.scrollTo({left:centerLeft(els[i]), behavior:RM?'auto':'smooth'}); markActive(i); stagger(els[i]); }
function deckMove(d){ goTo(CUR+d); }
function markActive(i){ document.querySelectorAll('#rail .chip').forEach((c,k)=>c.classList.toggle('on',k===i));
  document.querySelectorAll('#dots b').forEach((b,k)=>b.classList.toggle('on',k===i));
  const ac=document.querySelector('#rail .chip.on'); if(ac) ac.scrollIntoView({inline:'center',block:'nearest',behavior:RM?'auto':'smooth'}); }
function stagger(sl){ if(RM) return; sl.querySelectorAll('.app').forEach((el,i)=>{ el.style.animation='none'; void el.offsetWidth; el.style.animationDelay=Math.min(i*30,320)+'ms'; el.style.animation=''; }); }
// coverflow depth: scale/fade slides by distance from the deck's centre
let raf=0;
function depth(){ if(RM) return; const deck=document.getElementById('deck'); if(!deck.children.length) return; const cx=deck.scrollLeft+deck.clientWidth/2; let best=1e9,bi=CUR;
  slideEls().forEach((el,i)=>{ const c=el.offsetLeft+el.offsetWidth/2, d=Math.abs(c-cx), t=Math.min(1,d/(el.offsetWidth*0.9)), sc=el.firstElementChild;
    sc.style.transform=`scale(${(1-t*0.14).toFixed(3)}) rotateY(${((c<cx?1:-1)*t*6).toFixed(2)}deg)`; sc.style.opacity=(1-t*0.5).toFixed(3);
    if(d<best){ best=d; bi=i; } });
  if(bi!==CUR){ CUR=bi; markActive(bi); } }
function onScroll(){ if(raf) return; raf=requestAnimationFrame(()=>{ raf=0; depth(); }); }

// ── views (deck / grid) + live search results ──
const curView=()=>localStorage.getItem(VIEW_KEY)||'deck';
function setView(v){ localStorage.setItem(VIEW_KEY,v); applyView(); }
function applyView(){ const v=curView(), searching=!!(document.getElementById('q').value||'').trim();
  document.querySelectorAll('#viewseg button').forEach(b=>b.classList.toggle('on',b.dataset.v===v));
  document.getElementById('deck-view').classList.toggle('hidden', searching || v!=='deck');
  document.getElementById('grid-view').classList.toggle('hidden', searching || v!=='grid');
  document.getElementById('results').classList.toggle('hidden', !searching);
  if(!searching && v==='deck') requestAnimationFrame(()=>{ fitDeck(); jumpTo(CUR); depth(); }); }
function filter(){ const q=(document.getElementById('q').value||'').trim().toLowerCase();
  if(!q){ document.getElementById('noresult').classList.add('hidden'); applyView(); return; }
  if(tour) stopTour();
  const res=APPS.filter(a=>(a.label+' '+a.cat+' '+a.page).toLowerCase().includes(q));
  document.getElementById('results-grid').innerHTML=res.map((a,i)=>card(a,i)).join('');
  document.getElementById('noresult').classList.toggle('hidden',res.length>0); applyView(); }
function openFirst(){ const q=(document.getElementById('q').value||'').trim().toLowerCase();
  if(q){ const r=APPS.find(a=>(a.label+' '+a.cat+' '+a.page).toLowerCase().includes(q)); if(r) openApp(r.page); return; }
  const el=document.querySelector('#results-grid .app, #deck .slide .app, #grid-view .app'); if(el) openApp(el.dataset.page); }

// ── auto-tour ──
let tour=null;
function toggleTour(){ if(tour){ stopTour(); return; }
  document.getElementById('q').value=''; setView('deck'); filter();
  tour=setInterval(()=>goTo((CUR+1)%Math.max(1,SLIDES.length)),6000);
  const b=document.getElementById('tourbtn'); b.classList.add('live'); b.innerHTML='<i class="dotp"></i> Touring…'; }
function stopTour(){ if(tour) clearInterval(tour); tour=null; const b=document.getElementById('tourbtn'); b.classList.remove('live'); b.innerHTML='<i class="fa-solid fa-play"></i> Auto-tour'; }

// ── magnetic tilt on cards ──
function bindTilt(){ if(RM) return; const w=document.querySelector('.wrap');
  w.addEventListener('pointermove',e=>{ const el=e.target.closest('.app'); if(!el) return; const r=el.getBoundingClientRect();
    const px=(e.clientX-r.left)/r.width-0.5, py=(e.clientY-r.top)/r.height-0.5;
    el.style.transform=`perspective(600px) rotateX(${(-py*8).toFixed(2)}deg) rotateY(${(px*10).toFixed(2)}deg) translateY(-4px)`; });
  w.addEventListener('pointerout',e=>{ const el=e.target.closest('.app'); if(el && !el.contains(e.relatedTarget)) el.style.transform=''; }); }

// ── clock + greeting ──
function clock(){ const d=new Date(); document.getElementById('clk').textContent=d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
  document.getElementById('cdate').textContent=d.toLocaleDateString([], {weekday:'long',month:'long',day:'numeric'});
  const h=d.getHours(); const g=h<12?'Good morning':h<19?'Good afternoon':'Good evening';
  const el=document.getElementById('greet'); if(el) el.innerHTML=g+(USER?(', <b>'+esc(USER)+'</b>'):''); }

// ── vitals (with one-time count-up) ──
let firstV=true;
function animN(el,to){ to=+to||0; if(RM||!firstV){ el.textContent=to; return; } let s=0; const step=Math.max(1,Math.ceil(to/28));
  const t=setInterval(()=>{ s+=step; if(s>=to){ s=to; clearInterval(t); } el.textContent=s; },26); }
async function vitals(){
  const r=await fetch('home.php?api=vitals&_='+Date.now()).then(r=>r.json()).catch(()=>null); if(!r||!r.ok) return;
  const n=r.nodes;
  document.getElementById('v-up').textContent=n.up+'/'+n.total;
  document.getElementById('v-updn').innerHTML=(n.down?`<span style="color:var(--crit)">${n.down} down</span> · `:'')+(n.degraded?`<span style="color:var(--warn)">${n.degraded} degraded</span>`:(n.down?'':'all healthy'));
  const inc=document.getElementById('v-inc'); animN(inc,r.incidents.open); inc.style.color=r.incidents.open?'var(--crit)':'var(--ok)';
  document.getElementById('v-inccrit').textContent=r.incidents.critical?(r.incidents.critical+' critical'):'clear';
  document.getElementById('v-sla').textContent=(r.sla_avg!=null?r.sla_avg+'%':'—');
  const bot=document.getElementById('v-bot'); bot.textContent=r.bot.active?(r.bot.active+' active'):(r.bot.enabled?'watching':'idle');
  bot.style.color=r.bot.active?'var(--warn)':(r.bot.enabled?'#43e08a':'#8a93a3');
  document.getElementById('v-botlast').textContent=(r.bot.last_min!=null?('last '+r.bot.last_min+'m ago'):(r.bot.enabled?'auto-scan on':''));
  const db=document.getElementById('v-db'); if(r.db_ok!=null) animN(db,r.db_ok); else db.textContent='—';
  firstV=false;
}

// ── wire up ──
document.getElementById('deck').addEventListener('scroll',onScroll,{passive:true});
['pointerdown','wheel','keydown'].forEach(ev=>document.getElementById('deck').addEventListener(ev,()=>{ if(tour) stopTour(); },{passive:true}));
document.addEventListener('keydown',e=>{
  if(e.key==='/' && document.activeElement.id!=='q'){ e.preventDefault(); document.getElementById('q').focus(); return; }
  if(document.activeElement.id==='q') return;
  if(curView()==='deck' && !(document.getElementById('q').value||'').trim()){
    if(e.key==='ArrowRight') deckMove(1); else if(e.key==='ArrowLeft') deckMove(-1); }
});
let rsz=0; window.addEventListener('resize',()=>{ clearTimeout(rsz); rsz=setTimeout(()=>{ if(curView()==='deck'){ fitDeck(); jumpTo(CUR); depth(); } },120); });

// ── clickable KPIs (vitals → their page) with a warp/ripple FX ──
function bindKPIs(){
  document.querySelectorAll('#vitals .v').forEach(card=>{
    const go=card.dataset.go, act=card.dataset.act;
    if(!go && !act) return;
    card.classList.add('clk');
    card.title = act==='grid' ? 'View all modules' : 'Open';
    card.insertAdjacentHTML('beforeend', act==='grid'
      ? '<i class="fa-solid fa-table-cells-large khint"></i>'
      : '<i class="fa-solid fa-arrow-up-right-from-square khint"></i>');
    card.addEventListener('click',e=>{
      const r=card.getBoundingClientRect(), rp=document.createElement('span'); rp.className='ripple';
      const size=Math.max(r.width,r.height)*2.3; rp.style.width=rp.style.height=size+'px';
      rp.style.left=(e.clientX-r.left)+'px'; rp.style.top=(e.clientY-r.top)+'px';
      card.appendChild(rp); setTimeout(()=>rp.remove(),650);
      card.classList.remove('burst'); void card.offsetWidth; card.classList.add('burst');
      if(act==='grid'){ document.getElementById('q').value=''; setView('grid'); setTimeout(()=>document.getElementById('grid-view').scrollIntoView({behavior:RM?'auto':'smooth',block:'start'}),150); return; }
      if(go) setTimeout(()=>{ location.href=go; }, RM?0:280);
    });
  });
}

buildAll();
bindTilt();
bindKPIs();
clock(); setInterval(clock,1000);
vitals(); setInterval(vitals,15000);
window.addEventListener('load',()=>{ if(window.NMLoader) NMLoader.hide(); });
</script>
</body>
</html>
