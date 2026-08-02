<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Widget Studio. The dedicated home for the Widget SDK: build (no-code),
// import / AI, manage your widgets, and browse the available data sources. The
// builder UI + rendering come from the shared nm_widgetkit.js; all server calls
// (broker + registry) reuse command.php's endpoints. RBAC: 'command'.
// ─────────────────────────────────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) session_start();
include_once __DIR__ . '/connection.php';
require_once __DIR__ . '/access_control.php';
require_once __DIR__ . '/nm_widgets.php';
require_once __DIR__ . '/nm_chrome.php';
include __DIR__ . '/check.php';
if (!checkAccess($conn, 'command')) { header('Location: /denied_access.php?page=command'); exit; }
require_once __DIR__ . '/logger.php';
log_user_action($conn, 'view_page', 'widgets.php');
if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$CSRF = $_SESSION['csrf_token'];
$IS_ADMIN = ($_SESSION['role'] ?? '') === 'admin';
nm_widgets_ensure($conn);
include __DIR__ . '/header.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Widget Studio | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="/nm_widgetkit.js"></script>
<style>
<?= nm_chrome_css() ?>
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; overflow-x:hidden; }
.ws-wrap{ max-width:1200px; margin:0 auto; padding:18px 20px 50px; }
.ws-head{ display:flex; align-items:center; gap:12px; margin-bottom:6px; }
.ws-head h1{ font-size:22px; margin:0; font-weight:800; }
.ws-head i{ color:#4da3ff; } .ws-sub{ color:#8a929c; font-size:13px; margin:0 0 18px; }
.ws-cols{ display:grid; grid-template-columns:1.55fr 1fr; gap:18px; align-items:start; }
@media(max-width:980px){ .ws-cols{ grid-template-columns:1fr; } }
.glass{ background:rgba(255,255,255,0.07); backdrop-filter:blur(20px); border:1px solid rgba(255,255,255,0.13); border-radius:16px; padding:18px 20px; }
.glass h2{ font-size:13px; text-transform:uppercase; letter-spacing:1.2px; color:#4da3ff; margin:0 0 12px; display:flex; align-items:center; gap:8px; }
.ds{ border:1px solid rgba(255,255,255,.1); border-radius:10px; padding:9px 11px; margin-bottom:9px; }
.ds .id{ font-family:monospace; font-size:12.5px; color:#cfe4ff; font-weight:700; }
.ds .perm{ float:right; font-size:9.5px; background:rgba(77,163,255,.16); color:#bcd; border-radius:10px; padding:1px 8px; text-transform:uppercase; }
.ds .desc{ color:#aab2bc; font-size:12px; margin:3px 0; }
.ds .fields{ color:#7c828c; font-size:10.5px; font-family:monospace; }
.ws-tip{ background:rgba(77,163,255,.07); border:1px solid rgba(77,163,255,.25); border-radius:10px; padding:10px 13px; font-size:12.5px; color:#bcd; margin-bottom:16px; }
.ws-tip a{ color:#7dd3fc; }
</style>
</head>
<body>
<div class="ws-wrap">
  <div class="ws-head"><i class="fa-solid fa-puzzle-piece fa-xl"></i><h1>Widget Studio</h1></div>
  <p class="ws-sub">Build, import, and manage widgets for your <a href="command.php" style="color:#4da3ff;">Command Center</a> — no code required.
     Browse ready-made ones in the <a href="widget_market.php" style="color:#4da3ff;">Marketplace</a>.</p>
  <div class="ws-tip"><i class="fa-solid fa-wand-magic-sparkles"></i> Tip: describe the widget you want to any AI using the prompt in the <a href="widget_sdk.php">SDK guide</a>, then paste the result into the <b>Import / AI</b> tab.</div>
  <div class="ws-cols">
    <div class="glass"><div id="studio"></div></div>
    <div class="glass"><h2><i class="fa-solid fa-database"></i> Available data sources</h2>
      <p class="wk-mut" style="margin-top:0;">Widgets read only these curated sources — each enforces its own permission. Map their fields in the builder.</p>
      <div id="ws-catalog"><div class="wk-empty">Loading…</div></div>
    </div>
  </div>
</div>

<script>
const CSRF=<?= json_encode($CSRF) ?>, CAN_GLOBAL=<?= $IS_ADMIN ? 'true':'false' ?>;
function toast(m){ let t=document.getElementById('ws-toast'); if(!t){ t=document.createElement('div'); t.id='ws-toast';
  t.style.cssText='position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#11151d;border:1px solid rgba(255,255,255,.14);border-left:4px solid #4da3ff;border-radius:10px;padding:11px 18px;font-size:13px;z-index:3000;color:#fff;'; document.body.appendChild(t); }
  t.textContent=m; t.style.opacity='1'; clearTimeout(t._h); t._h=setTimeout(()=>t.style.opacity='0',2400); }
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function renderCatalog(cat){ const box=document.getElementById('ws-catalog');
  const keys=Object.keys(cat||{}); box.innerHTML = keys.length? keys.map(k=>{ const s=cat[k];
    return `<div class="ds"><span class="perm">${esc(s.perm||'')}</span><div class="id">${esc(k)}</div>
      <div class="desc">${esc(s.desc||'')}</div><div class="fields">${(s.fields||[]).map(esc).join(' · ')}</div></div>`; }).join('')
    : '<div class="wk-empty">No sources available.</div>'; }
(async function(){
  let cat={}; try{ const r=await fetch('command.php?api=widgets_list').then(x=>x.json()); if(r&&r.ok) cat=r.catalog||{}; }catch(e){}
  NMWidgetKit.mountBuilder(document.getElementById('studio'), { catalog:cat, csrf:CSRF, base:'command.php', canGlobal:CAN_GLOBAL,
    toast, onSaved:(m)=>{ if(m) toast('Saved — it’s now in your Command Center'); } });
  renderCatalog(cat);
})();
</script>
</body></html>
