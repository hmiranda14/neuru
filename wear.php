<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Technical-Debt & Wear dashboard. RPG-style HP bars per node from the
// chronic Stress Index. RBAC: 'wear'. Engine: nm_wear.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_wear.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'wear')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=wear'); exit;
}
nm_wear_ensure($conn);

if ($api === 'data') {
    header('Content-Type: application/json; charset=utf-8');
    $w = nm_wear_compute($conn, 30);
    foreach ($w as &$n) { $n['trend'] = nm_wear_trend($conn,(int)$n['id'],30); }
    $avg = $w ? round(array_sum(array_map(fn($x)=>$x['health'],$w))/count($w)) : 100;
    $risk = count(array_filter($w, fn($x)=>$x['stress']>=65));
    echo json_encode(['ok'=>true,'nodes'=>$w,'avg_health'=>$avg,'at_risk'=>$risk]); exit;
}
log_user_action($conn,'view_page','wear.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Wear &amp; Stress | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.18; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 40px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; } .card h3{ margin:0 0 12px; font-size:12px; color:var(--accent); text-transform:uppercase; letter-spacing:1px; }
.kpis{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-bottom:16px; }
.kpi{ padding:14px 16px; text-align:center; } .kpi .n{ font-size:26px; font-weight:800; } .kpi .l{ font-size:11px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; }
.nodes{ display:grid; grid-template-columns:repeat(auto-fill,minmax(310px,1fr)); gap:14px; }
.node{ padding:14px 16px; } .node .top{ display:flex; justify-content:space-between; align-items:baseline; gap:8px; }
.node .nm{ font-weight:700; font-size:14px; } .node .model{ font-size:10.5px; color:#7c828c; }
.hp{ position:relative; height:20px; border-radius:10px; background:rgba(255,255,255,.07); overflow:hidden; margin:10px 0 6px; border:1px solid rgba(255,255,255,.08); }
.hp > i{ display:block; height:100%; border-radius:10px; transition:width .6s; }
.hp .lbl{ position:absolute; inset:0; display:flex; align-items:center; justify-content:center; font-size:11px; font-weight:800; text-shadow:0 1px 2px rgba(0,0,0,.6); }
.factors{ font-size:11.5px; color:#aab; line-height:1.7; margin-top:6px; }
.factors span{ display:inline-block; background:rgba(243,156,18,.1); border:1px solid rgba(243,156,18,.25); color:#f0c674; border-radius:6px; padding:1px 7px; margin:2px 3px 0 0; }
.rec{ font-size:12px; margin-top:8px; padding-top:8px; border-top:1px solid rgba(255,255,255,.07); }
.rec.crit{ color:#f0a59d;} .rec.high{ color:#f0c674;} .rec.mod{ color:#cdd2d8;} .rec.ok{ color:#9fdcb6;}
.spark{ margin-top:6px; } .muted{ color:#7c828c; font-size:12px; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-heart-crack"></i>Wear &amp; Stress', '', 'Hardware Lifespan', 'fa-solid fa-heart-crack',
    '<button class="refresh-btn" onclick="load()"><i class="fas fa-rotate"></i> Recompute</button>'); ?>

<div class="kpis">
  <div class="glass kpi"><div class="n" id="k-health" style="color:var(--ok)">—</div><div class="l">Avg fleet health</div></div>
  <div class="glass kpi"><div class="n" id="k-risk" style="color:var(--crit)">—</div><div class="l">Nodes at risk</div></div>
  <div class="glass kpi"><div class="n" id="k-total">—</div><div class="l">Nodes scored</div></div>
</div>

<div class="glass card" style="padding:12px 16px;">
  <div class="muted">Each node has a <b style="color:#cfd3da">HP bar</b> driven by a chronic <b>Stress Index</b> (power-cycles, sustained CPU, memory, link flaps, degradation alerts, load). Higher stress = shorter lifespan. Temperature factors activate automatically once you enable SFP/sensor OIDs in Predictive Health.</div>
</div>

<div class="nodes" id="nodes"><div class="muted">Loading…</div></div>
</div>
<script>
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function hpColor(h){ return h>=70?'linear-gradient(90deg,#27ae60,#2ecc71)':h>=40?'linear-gradient(90deg,#e67e22,#f39c12)':'linear-gradient(90deg,#c0392b,#e74c3c)'; }
function recClass(s){ return s>=85?'crit':s>=65?'high':s>=40?'mod':'ok'; }
function spark(t){ if(!t||t.length<2)return''; const w=120,h=22,mx=100,mn=0; const pts=t.map((v,i)=>`${(i/(t.length-1))*w},${h-(v/mx)*(h-2)-1}`).join(' '); return `<svg class="spark" width="${w}" height="${h}"><polyline points="${pts}" fill="none" stroke="#e67e22" stroke-width="1.4"/></svg>`; }
async function load(){
  const r=await fetch('wear.php?api=data').then(r=>r.json()).catch(()=>null); if(!r||!r.ok)return;
  document.getElementById('k-health').textContent=r.avg_health+'%';
  document.getElementById('k-health').style.color=r.avg_health>=70?'var(--ok)':r.avg_health>=40?'var(--warn)':'var(--crit)';
  document.getElementById('k-risk').textContent=r.at_risk;
  document.getElementById('k-total').textContent=r.nodes.length;
  document.getElementById('nodes').innerHTML=r.nodes.map(n=>`
    <div class="glass node">
      <div class="top"><span class="nm">${esc(n.name)}</span><span class="muted">${n.uptime_days!=null?n.uptime_days+'d up':''}</span></div>
      <div class="model">${esc(n.model||n.ip||'')}</div>
      <div class="hp"><i style="width:${n.health}%;background:${hpColor(n.health)};"></i><div class="lbl">${n.health} / 100 HP · stress ${n.stress}</div></div>
      ${n.factors&&n.factors.length?`<div class="factors">${n.factors.map(f=>`<span>${esc(f)}</span>`).join('')}</div>`:'<div class="muted" style="margin-top:4px;">No stress factors detected.</div>'}
      ${spark(n.trend)}
      <div class="rec ${recClass(n.stress)}"><i class="fas fa-${n.stress>=65?'triangle-exclamation':'circle-check'}"></i> ${esc(n.recommendation)}</div>
    </div>`).join('');
}
// Hold the global loader until the first data render lands (content arrives via AJAX
// AFTER window.load, so without this the loader hides too early and the page flashes blank).
if(window.NMLoader){ NMLoader.keep(); NMLoader.msg('computing wear & stress…'); }
load().finally(()=>{ if(window.NMLoader) NMLoader.hide(); });
setInterval(load, 60000);
</script>
</body></html>
