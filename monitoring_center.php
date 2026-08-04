<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Monitoring Center. A Command-Deck-style hub for every monitoring page,
// grouped into category sections (Monitoring · AI Tools · Ext Monitoring). Reads the
// SAME $_nm_groups source header.php builds (available after the include) so it can
// NEVER drift from the menu. RBAC: any authenticated user; each card is _nm_can-filtered.
// (Mirrors site_config.php — keep the shell rule / FA CDN or the font falls back to serif.)
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_access.php');
include('logger.php');
log_user_action($conn, 'view_page', 'monitoring_center.php');
$user = $_SESSION['username'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Monitoring Center — NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" media="print" onload="this.media='all'">
<noscript><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"></noscript>
<style>
  /* Global NEURU shell — MUST match other pages or the font falls back to serif (the recurring bug). */
  html{ background:#05080f; }
  body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; color:#e7ecf3; background:transparent!important; overflow-x:hidden; }
  .mc-wrap{ position:relative; z-index:1; max-width:1300px; margin:0 auto; padding:26px 22px 70px; }
  .mc-hero{ display:flex; align-items:center; gap:16px; margin-bottom:4px; }
  .mc-hero .hic{ width:54px; height:54px; border-radius:16px; display:grid; place-items:center; font-size:23px; color:#cfe4ff;
    background:linear-gradient(150deg,rgba(77,163,255,.24),rgba(54,227,208,.10)); border:1px solid rgba(77,163,255,.30); box-shadow:0 0 26px rgba(77,163,255,.18); }
  .mc-hero h1{ font-size:26px; margin:0; font-weight:800; letter-spacing:.3px;
    background:linear-gradient(90deg,#8ab6ff,#5fe0d0); -webkit-background-clip:text; background-clip:text; -webkit-text-fill-color:transparent; }
  .mc-hero p{ margin:4px 0 0; font-size:13px; color:#8ea0b8; }
  .mc-toolbar{ margin:22px 0 20px; position:relative; }
  .mc-toolbar i.fa-search{ position:absolute; left:16px; top:50%; transform:translateY(-50%); color:#5a6b85; font-size:14px; pointer-events:none; }
  #mc-q{ width:100%; box-sizing:border-box; padding:14px 16px 14px 44px; font-size:14px; color:#e6edf6;
    background:rgba(14,20,32,.66); border:1px solid rgba(255,255,255,.09); border-radius:14px; outline:none; transition:border-color .15s; }
  #mc-q:focus{ border-color:#4da3ff; box-shadow:0 0 0 3px rgba(77,163,255,.12); }
  .mc-section{ margin-bottom:26px; }
  .mc-sec-h{ display:flex; align-items:center; gap:11px; margin:0 0 13px; }
  .mc-sec-h .sic{ width:34px; height:34px; border-radius:10px; display:grid; place-items:center; font-size:15px; color:var(--c);
    background:color-mix(in srgb,var(--c) 15%,transparent); border:1px solid color-mix(in srgb,var(--c) 30%,transparent); }
  .mc-sec-h h2{ font-size:15px; margin:0; font-weight:700; letter-spacing:.4px; }
  .mc-sec-h .ct{ font-size:11px; color:#66748c; font-weight:600; }
  .mc-grid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(196px,1fr)); gap:14px; }
  .mc-card{ position:relative; overflow:hidden; text-decoration:none; color:inherit; border-radius:15px; padding:16px;
    background:rgba(255,255,255,.055); border:1px solid rgba(255,255,255,.12);
    transition:transform .18s cubic-bezier(.4,.2,.2,1), border-color .18s, box-shadow .18s; }
  .mc-card:hover{ transform:translateY(-4px); border-color:var(--c);
    box-shadow:0 14px 34px rgba(0,0,0,.45), 0 0 26px color-mix(in srgb,var(--c) 34%, transparent); }
  .mc-card::before{ content:''; position:absolute; top:-42%; right:-32%; width:132px; height:132px; border-radius:50%;
    background:radial-gradient(circle,color-mix(in srgb,var(--c) 28%,transparent),transparent 70%); opacity:0; transition:.25s; }
  .mc-card:hover::before{ opacity:1; }
  .mc-ic{ width:46px; height:46px; border-radius:13px; display:flex; align-items:center; justify-content:center; font-size:20px;
    color:var(--c); background:color-mix(in srgb,var(--c) 15%, transparent); margin-bottom:13px; transition:transform .2s cubic-bezier(.4,.2,.2,1); }
  .mc-card:hover .mc-ic{ transform:scale(1.08); }
  .mc-lb{ font-weight:700; font-size:14px; line-height:1.28; }
  .mc-sub{ font-size:10px; color:#7c828c; margin-top:4px; text-transform:uppercase; letter-spacing:.6px; }
  .mc-go{ position:absolute; bottom:14px; right:15px; color:var(--c); font-size:12px; opacity:0; transform:translateX(-6px); transition:.2s cubic-bezier(.4,.2,.2,1); }
  .mc-card:hover .mc-go{ opacity:.9; transform:none; }
  #mc-none{ display:none; text-align:center; color:#66748c; padding:40px; font-size:13px; }
  @media (prefers-reduced-motion:reduce){ .mc-card{ transition:none; } }
</style>
</head>
<body>
<?php include('header.php'); ?>
<div class="mc-wrap">
  <div class="mc-hero">
    <div class="hic"><i class="fa-solid fa-gauge-high"></i></div>
    <div>
      <h1>Monitoring Center</h1>
      <p>Every monitoring, telemetry &amp; observability tool in one place<?= $user ? ', '.htmlspecialchars($user) : '' ?>.</p>
    </div>
  </div>

  <div class="mc-toolbar">
    <i class="fa-solid fa-search"></i>
    <input id="mc-q" type="text" autocomplete="off" placeholder="Search monitoring tools…" oninput="mcFilter()" onkeydown="if(event.key==='Enter')mcOpenFirst()">
  </div>

  <?php
  // Sections = the monitoring-family nav groups, each with its home.php signature color. Reads the SAME
  // $_nm_groups source → adding a tool to any of these nav groups auto-appears here. Nothing left out.
  $sections = [
      'Monitoring'     => '#4da3ff',
      'AI Tools'       => '#9b6bff',
      'Ext Monitoring' => '#36e3d0',
  ];
  foreach ($sections as $gname => $col):
      $grp = $_nm_groups[$gname] ?? null;
      if (!$grp) continue;
      // RBAC filter (mirror the nav): __always always; __smokeping only when the tool is enabled; else _nm_can.
      $vis = [];
      foreach ($grp['items'] as $it) {
          $perm = $it[0];
          if (($it[1] ?? '') === 'monitoring_center.php') continue; // don't list this hub inside itself (self-link → nowhere)
          if ($perm === '__smokeping') { if (!empty($_nm_sp_on)) $vis[] = $it; continue; }
          if ($perm === '__always')    { $vis[] = $it; continue; }
          if (function_exists('_nm_can') ? _nm_can($perm) : true) $vis[] = $it;
      }
      if (!$vis) continue;
      $secIcon = $grp['icon'] ?? 'fa-solid fa-gauge-high';
  ?>
  <div class="mc-section" data-sec="<?= htmlspecialchars(strtolower($gname)) ?>">
    <div class="mc-sec-h" style="--c:<?= $col ?>">
      <div class="sic"><i class="<?= htmlspecialchars($secIcon) ?>"></i></div>
      <h2><?= htmlspecialchars($gname) ?></h2>
      <span class="ct"><?= count($vis) ?></span>
    </div>
    <div class="mc-grid">
      <?php foreach ($vis as $it): $blank = (($it[4] ?? '') === '_blank'); ?>
      <a class="mc-card" style="--c:<?= $col ?>" href="<?= htmlspecialchars($it[1]) ?>"<?= $blank ? ' target="_blank" rel="noopener"' : '' ?> data-l="<?= htmlspecialchars(strtolower($it[3])) ?>">
        <div class="mc-ic"><i class="<?= htmlspecialchars($it[2]) ?>"></i></div>
        <div class="mc-lb"><?= htmlspecialchars($it[3]) ?></div>
        <div class="mc-sub"><?= $blank ? 'External' : htmlspecialchars($gname) ?></div>
        <i class="fa-solid <?= $blank ? 'fa-up-right-from-square' : 'fa-arrow-right' ?> mc-go"></i>
      </a>
      <?php endforeach; ?>
    </div>
  </div>
  <?php endforeach; ?>

  <div id="mc-none"><i class="fa-solid fa-magnifying-glass"></i> No monitoring tools match — try another word.</div>
</div>

<script>
function mcFilter(){
  const q=(document.getElementById('mc-q').value||'').trim().toLowerCase();
  let shown=0;
  document.querySelectorAll('.mc-section').forEach(sec=>{
    let vis=0;
    sec.querySelectorAll('.mc-card').forEach(c=>{
      const hit = !q || (c.dataset.l||'').indexOf(q)>=0;
      c.style.display = hit ? '' : 'none'; if(hit){ vis++; shown++; }
    });
    sec.style.display = vis ? '' : 'none';   // hide a whole section when nothing in it matches
  });
  document.getElementById('mc-none').style.display = shown ? 'none' : '';
}
function mcOpenFirst(){
  const c=[...document.querySelectorAll('.mc-card')].find(x=>x.style.display!=='none' && x.offsetParent!==null);
  if(c) window.location.href=c.getAttribute('href');
}
</script>
</body>
</html>
