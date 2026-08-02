<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Site Configuration Center. A Command-Deck-style hub for every page in
// the "Site Configuration" nav group, RBAC-filtered. It reads the SAME $_nm_groups
// source header.php builds (available after the include), so it can NEVER drift
// from the menu — add a nav item and it appears here automatically.
// RBAC: any authenticated user (like home.php); each card is filtered by _nm_can().
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_access.php');
include('logger.php');
log_user_action($conn, 'view_page', 'site_config.php');
$user = $_SESSION['username'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Site Configuration Center — NEURU</title>
<!-- FontAwesome — same source home.php uses (icons were blank when pointed at a non-existent local path) -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" media="print" onload="this.media='all'">
<noscript><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"></noscript>
<style>
  /* Global NEURU shell — MUST match other pages or the font falls back to serif (the recurring "font bug"):
     dark html bg, transparent body so header's constellation canvas shows through, Segoe UI + light text. */
  html{ background:#05080f; }
  body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; color:#e7ecf3; background:transparent!important; overflow-x:hidden; }
  .cc-wrap{ position:relative; z-index:1; max-width:1240px; margin:0 auto; padding:26px 22px 70px; }
  .cc-hero{ display:flex; align-items:center; gap:16px; margin-bottom:4px; }
  .cc-hero .hic{ width:54px; height:54px; border-radius:16px; display:grid; place-items:center; font-size:23px; color:#cfe4ff;
    background:linear-gradient(150deg,rgba(77,163,255,.24),rgba(139,92,246,.10)); border:1px solid rgba(77,163,255,.30);
    box-shadow:0 0 26px rgba(77,163,255,.18); }
  .cc-hero h1{ font-size:26px; margin:0; font-weight:800; letter-spacing:.3px;
    background:linear-gradient(90deg,#8ab6ff,#b79bff); -webkit-background-clip:text; background-clip:text; -webkit-text-fill-color:transparent; }
  .cc-hero p{ margin:4px 0 0; font-size:13px; color:#8ea0b8; }
  .cc-toolbar{ margin:22px 0 18px; position:relative; }
  .cc-toolbar i.fa-search{ position:absolute; left:16px; top:50%; transform:translateY(-50%); color:#5a6b85; font-size:14px; pointer-events:none; }
  #cc-q{ width:100%; box-sizing:border-box; padding:14px 16px 14px 44px; font-size:14px; color:#e6edf6;
    background:rgba(14,20,32,.66); border:1px solid rgba(255,255,255,.09); border-radius:14px; outline:none; transition:border-color .15s; }
  #cc-q:focus{ border-color:#4da3ff; box-shadow:0 0 0 3px rgba(77,163,255,.12); }
  .cc-grid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(196px,1fr)); gap:14px; }
  .cc-card{ position:relative; overflow:hidden; text-decoration:none; color:inherit; border-radius:15px; padding:16px;
    background:rgba(255,255,255,.055); border:1px solid rgba(255,255,255,.12);
    transition:transform .18s cubic-bezier(.4,.2,.2,1), border-color .18s, box-shadow .18s; }
  .cc-card:hover{ transform:translateY(-4px); border-color:var(--c);
    box-shadow:0 14px 34px rgba(0,0,0,.45), 0 0 26px color-mix(in srgb,var(--c) 34%, transparent); }
  .cc-card::before{ content:''; position:absolute; top:-42%; right:-32%; width:132px; height:132px; border-radius:50%;
    background:radial-gradient(circle,color-mix(in srgb,var(--c) 28%,transparent),transparent 70%); opacity:0; transition:.25s; }
  .cc-card:hover::before{ opacity:1; }
  .cc-ic{ width:46px; height:46px; border-radius:13px; display:flex; align-items:center; justify-content:center; font-size:20px;
    color:var(--c); background:color-mix(in srgb,var(--c) 15%, transparent); margin-bottom:13px; transition:transform .2s cubic-bezier(.4,.2,.2,1); }
  .cc-card:hover .cc-ic{ transform:scale(1.08); }
  .cc-lb{ font-weight:700; font-size:14px; line-height:1.28; }
  .cc-sub{ font-size:10px; color:#7c828c; margin-top:4px; text-transform:uppercase; letter-spacing:.6px; }
  .cc-go{ position:absolute; bottom:14px; right:15px; color:var(--c); font-size:12px; opacity:0; transform:translateX(-6px); transition:.2s cubic-bezier(.4,.2,.2,1); }
  .cc-card:hover .cc-go{ opacity:.9; transform:none; }
  #cc-none{ display:none; text-align:center; color:#66748c; padding:40px; font-size:13px; }
  @media (prefers-reduced-motion:reduce){ .cc-card{ transition:none; } }
</style>
</head>
<body>
<?php include('header.php'); ?>
<div class="cc-wrap">
  <div class="cc-hero">
    <div class="hic"><i class="fa-solid fa-sliders"></i></div>
    <div>
      <h1>Site Configuration Center</h1>
      <p>Every setup, admin &amp; configuration page in one place<?= $user ? ', '.htmlspecialchars($user) : '' ?>.</p>
    </div>
  </div>

  <div class="cc-toolbar">
    <i class="fa-solid fa-search"></i>
    <input id="cc-q" type="text" autocomplete="off" placeholder="Search configuration pages…" oninput="ccFilter()" onkeydown="if(event.key==='Enter')ccOpenFirst()">
  </div>

  <div class="cc-grid" id="cc-grid">
    <?php
    // Same source as the nav — filtered by the user's permissions (each card only if _nm_can).
    // Harmonious COOL palette (NEURU blues/teals/purples) — coherent, not a rainbow.
    $palette = ['#4da3ff','#22d3ee','#36e3d0','#9b6bff','#16c79a'];
    // "Config" alone is vague ("config what?") — expand it into its actual sections so the user sees
    // exactly where to go (esp. Add Nodes + Integrations). Each deep-links to net_mon_config.php?tab=…
    $_cfg_tabs = [
        ['nodes',        'fa-solid fa-server',            'Add & Manage Nodes'],
        ['integrations', 'fa-solid fa-plug',              'Integrations & AI'],
        ['discovery',    'fa-solid fa-magnifying-glass',  'Discovery'],
        ['interfaces',   'fa-solid fa-ethernet',          'Interfaces'],
        ['links',        'fa-solid fa-diagram-project',   'Connections'],
        ['snmp',         'fa-solid fa-sitemap',           'SNMP & OIDs'],
        ['poller',       'fa-solid fa-satellite-dish',    'Poller'],
        ['credentials',  'fa-solid fa-key',               'SSH Credentials'],
        ['databases',    'fa-solid fa-database',          'Databases'],
        ['containers',   'fa-brands fa-docker',           'Containers'],
        ['switches',     'fa-solid fa-network-wired',     'Unmanaged Switches'],
        ['settings',     'fa-solid fa-gear',              'Global Settings'],
    ];
    $items = $_nm_groups['Site Configuration']['items'] ?? [];
    $i = 0;
    foreach ($items as $it):
        $perm = $it[0]; $href = $it[1]; $icon = $it[2]; $label = $it[3];
        $blank = (($it[4] ?? '') === '_blank');
        if ($href === 'site_config.php') continue;                 // don't link to self
        $can = ($perm === '__always') || ($perm === '__smokeping') || _nm_can($perm);
        if (!$can) continue;
        // Expand the single "Config" item into one card per section (Nodes, Integrations, …).
        if ($href === 'net_mon_config.php') {
            foreach ($_cfg_tabs as $tb) {
                [$tkey, $ticon, $tlabel] = $tb;
                $c = $palette[$i % count($palette)]; $i++;
                echo '<a class="cc-card" style="--c:' . $c . '" href="net_mon_config.php?tab=' . $tkey . '" data-l="config ' . htmlspecialchars(strtolower($tlabel)) . '">'
                   . '<div class="cc-ic"><i class="' . $ticon . '"></i></div>'
                   . '<div class="cc-lb">' . htmlspecialchars($tlabel) . '</div>'
                   . '<div class="cc-sub">Config</div>'
                   . '<i class="fa-solid fa-arrow-right cc-go"></i></a>';
            }
            continue;
        }
        $c = $palette[$i % count($palette)]; $i++;
    ?>
    <a class="cc-card" style="--c:<?= $c ?>" href="<?= htmlspecialchars($href) ?>"<?= $blank ? ' target="_blank" rel="noopener"' : '' ?> data-l="<?= htmlspecialchars(strtolower($label)) ?>">
        <div class="cc-ic"><i class="<?= htmlspecialchars($icon) ?>"></i></div>
        <div class="cc-lb"><?= htmlspecialchars($label) ?></div>
        <div class="cc-sub"><?= $blank ? 'External' : 'Configuration' ?></div>
        <i class="fa-solid <?= $blank ? 'fa-up-right-from-square' : 'fa-arrow-right' ?> cc-go"></i>
    </a>
    <?php endforeach; ?>
  </div>
  <div id="cc-none"><i class="fa-solid fa-magnifying-glass"></i> No configuration pages match — try another word.</div>
</div>

<script>
function ccFilter(){
  const q=(document.getElementById('cc-q').value||'').trim().toLowerCase();
  let shown=0;
  document.querySelectorAll('#cc-grid .cc-card').forEach(c=>{
    const hit = !q || (c.dataset.l||'').indexOf(q)>=0;
    c.style.display = hit ? '' : 'none'; if(hit) shown++;
  });
  document.getElementById('cc-none').style.display = shown ? 'none' : '';
}
function ccOpenFirst(){
  const c=[...document.querySelectorAll('#cc-grid .cc-card')].find(x=>x.style.display!=='none');
  if(c) window.location.href=c.getAttribute('href');
}
</script>
</body>
</html>
