<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Switch Control Center. A hub under Monitoring that unifies every switch
// class NEURU knows: SNMP switches, Cisco switches, and unmanaged switches — each
// a NEURU-styled tile with a live count linking to its dedicated cockpit. RBAC: 'switches'.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_switches.php');
include('logger.php');
if (!checkAccess($conn, 'switches')) { header('Location: /denied_access.php?page=switches'); exit; }
if (function_exists('session_write_close')) @session_write_close();

$counts = nm_sw_counts($conn);
$total  = $counts['snmp'] + $counts['cisco'] + $counts['unmanaged'];
log_user_action($conn,'view_page','switch_center.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';

// which tiles the user is allowed to open
$can = fn($k)=> checkAccess($conn,$k);
$tiles = [
    ['snmp',      'SNMP Switches',      'snmp_switch.php',  'fa-solid fa-ethernet',       $counts['snmp'],      'switches',
        'Any SNMP-managed switch — MikroTik SwOS/CRS, generic L2. Live port faceplate, status, speed & utilization.', '#4da3ff'],
    ['cisco',     'Cisco Switches',     'cisco_switch.php', 'fa-solid fa-network-wired',  $counts['cisco'],     'cisco_switch',
        'Catalyst / Nexus fleet — the full Cisco switch cockpit with orchestration.', '#16c79a'],
    ['unmanaged', 'Unmanaged Switches', 'l2switch.php',     'fa-solid fa-diagram-project',$counts['unmanaged'], 'l2switch',
        'Dumb / Easy-Smart switches (TP-Link, ping-only) — reachability and link view via web-scrape.', '#c58bff'],
];
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Switch Control Center | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.16; }
.wrap{ max-width:1200px; margin:0 auto; padding:18px 20px 48px; } a{ text-decoration:none; color:inherit; }
.grid{ display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:20px; margin-top:8px; }
.tile{ position:relative; border:1px solid var(--border); border-radius:18px; padding:26px 24px; overflow:hidden;
  background:var(--glass); backdrop-filter:blur(16px); transition:transform .12s, border-color .12s, box-shadow .12s; cursor:pointer; min-height:210px; display:flex; flex-direction:column; }
.tile:hover{ transform:translateY(-4px); }
.tile .glow{ position:absolute; inset:0; opacity:.12; background:radial-gradient(600px 200px at 20% -20%, var(--c), transparent 70%); pointer-events:none; }
.tile .ic{ width:56px; height:56px; border-radius:14px; display:flex; align-items:center; justify-content:center; font-size:24px; color:var(--c); background:color-mix(in srgb, var(--c) 16%, transparent); border:1px solid color-mix(in srgb, var(--c) 35%, transparent); }
.tile h2{ margin:16px 0 4px; font-size:20px; }
.tile .desc{ color:#9aa3ad; font-size:12.5px; line-height:1.55; flex:1; }
.tile .foot{ display:flex; align-items:center; justify-content:space-between; margin-top:16px; }
.tile .count{ font-size:34px; font-weight:800; line-height:1; } .tile .count small{ font-size:12px; font-weight:600; color:#8a909a; margin-left:6px; }
.tile .go{ font-size:12.5px; color:var(--c); font-weight:700; } .tile.disabled{ opacity:.5; cursor:not-allowed; }
.tile.disabled:hover{ transform:none; }
.sum{ display:flex; gap:10px; flex-wrap:wrap; margin:10px 0 18px; }
.chip{ background:var(--glass); border:1px solid var(--border); border-radius:20px; padding:7px 15px; font-size:13px; font-weight:700; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-ethernet"></i>Switch Control Center', '', 'Every switch, one cockpit', 'fa-solid fa-ethernet',
    '<a class="refresh-btn" href="switch_center.php"><i class="fas fa-rotate"></i> Refresh</a>'); ?>

<div class="sum">
  <span class="chip"><i class="fas fa-layer-group" style="color:var(--accent)"></i> <?= $total ?> switches total</span>
  <span class="chip" style="color:#7fb4ff"><?= $counts['snmp'] ?> SNMP</span>
  <span class="chip" style="color:#7fe0a3"><?= $counts['cisco'] ?> Cisco</span>
  <span class="chip" style="color:#c9a7ff"><?= $counts['unmanaged'] ?> unmanaged</span>
</div>

<div class="grid">
<?php foreach ($tiles as [$k,$label,$url,$icon,$cnt,$perm,$desc,$color]):
    $ok = $can($perm); ?>
  <?php if ($ok): ?><a href="<?= $url ?>" class="tile" style="--c:<?= $color ?>"><?php else: ?><div class="tile disabled" style="--c:<?= $color ?>" title="No access"><?php endif; ?>
    <div class="glow"></div>
    <div class="ic"><i class="<?= $icon ?>"></i></div>
    <h2><?= htmlspecialchars($label) ?></h2>
    <div class="desc"><?= htmlspecialchars($desc) ?></div>
    <div class="foot">
      <div class="count"><?= (int)$cnt ?><small>device<?= $cnt==1?'':'s' ?></small></div>
      <div class="go"><?= $ok ? 'Open '.($k==='snmp'?'faceplate':'cockpit').' <i class="fas fa-arrow-right"></i>' : 'No access' ?></div>
    </div>
  <?php if ($ok): ?></a><?php else: ?></div><?php endif; ?>
<?php endforeach; ?>
</div>

<p class="chip" style="display:inline-block;margin-top:22px;color:#8a909a;font-weight:400;">
  <i class="fas fa-circle-info"></i> A monitored device is classed as a switch automatically from its model/OS
  (MikroTik SwOS·CSS·CRS, Cisco Catalyst·Nexus, HP ProCurve, Aruba, Juniper EX·QFX, TP-Link Easy-Smart…). Override any
  node's role inside <b>SNMP Switches</b>.
</p>
</div>
</body></html>
