<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Router Monitor. The fleet view of every router-class device (MikroTik /
// Cisco / …), the analog of windows.php (Windows Monitor) and linux.php (Linux
// Monitor). Each card shows live reachability / latency / 24h uptime / incidents +
// the equipment photo, and opens the immersive per-device dossier (router_details.php,
// the analog of win_screen.php / linux_screen.php). RBAC: 'routers'.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_router.php');
include('logger.php');

if (!checkAccess($conn, 'routers')) { header('Location: /denied_access.php?page=routers'); exit; }

if (($_GET['api'] ?? '') === 'list') {
    if (function_exists('session_write_close')) @session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    try { echo json_encode(['ok'=>true, 'routers'=>nm_router_list($conn)]); }
    catch (\Throwable $e) { echo json_encode(['ok'=>false, 'error'=>$e->getMessage()]); }
    exit;
}

log_user_action($conn, 'view_page', 'routers.php');
$routers = nm_router_list($conn);
$focusNode = (int)($_GET['node'] ?? ($_GET['focus'] ?? 0));   // preselect a specific router (from net_mon, etc.)
$e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES);
include('header.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(12,16,26,.62); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cyan:#36e3d0; }
html{ background:#05080f; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#d4dce8; overflow-x:hidden; }
<?= nm_chrome_css() ?>
.rt{ max-width:1360px; margin:0 auto; padding:20px 20px 60px; }
.rt *{ box-sizing:border-box; }
.glass{ background:var(--glass); backdrop-filter:blur(13px); border:1px solid var(--border); border-radius:16px; }
.rt-head{ display:flex; align-items:center; gap:16px; padding:16px 20px; margin-bottom:18px; flex-wrap:wrap; }
.rt-title{ font-size:21px; font-weight:800; display:flex; align-items:center; gap:11px; }
.rt-title i{ color:var(--accent); }
.rt-kpis{ display:flex; gap:12px; margin-left:auto; flex-wrap:wrap; }
.rt-cc{ display:inline-flex; align-items:center; gap:9px; text-decoration:none; padding:11px 16px; border-radius:11px; font-size:13px; font-weight:600;
  color:#eafff9; background:linear-gradient(135deg, rgba(54,227,208,.18), rgba(77,163,255,.18)); border:1px solid rgba(54,227,208,.45); white-space:nowrap; }
.rt-cc:hover{ border-color:var(--cyan); box-shadow:0 0 22px rgba(54,227,208,.25); } .rt-cc i{ color:var(--cyan); }
.kpi{ text-align:center; background:rgba(255,255,255,.03); border:1px solid var(--border); border-radius:11px; padding:8px 15px; min-width:78px; }
.kpi .n{ font-size:20px; font-weight:800; line-height:1; } .kpi .l{ font-size:9px; color:#8b95a7; text-transform:uppercase; letter-spacing:.5px; margin-top:4px; }
.kpi .n.ok{ color:#5fe39a; } .kpi .n.crit{ color:#ff8b80; } .kpi .n.cyan{ color:var(--cyan); }
.grid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:16px; }
.rcard{ padding:0; overflow:hidden; display:flex; flex-direction:column; transition:border-color .15s, transform .15s; }
.rcard:hover{ border-color:rgba(77,163,255,.5); transform:translateY(-2px); }
.rc-top{ display:flex; gap:14px; padding:15px 16px; }
.rc-photo{ width:74px; height:60px; border-radius:9px; flex:none; overflow:hidden; border:1px solid rgba(255,255,255,.12);
  background:radial-gradient(60px 40px at 50% 30%, rgba(77,163,255,.16), rgba(6,10,20,.6)); display:flex; align-items:center; justify-content:center; }
.rc-photo img{ width:100%; height:100%; object-fit:cover; } .rc-photo i{ font-size:24px; color:var(--accent); opacity:.55; }
.rc-id{ flex:1; min-width:0; }
.rc-name{ font-weight:700; font-size:15px; display:flex; align-items:center; gap:8px; }
.rc-name .st{ width:9px; height:9px; border-radius:50%; flex:none; box-shadow:0 0 8px currentColor; }
.rc-sub{ font-size:12px; color:#8b95a7; margin-top:3px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.rc-model{ font-size:11px; color:#9fb0c4; margin-top:4px; }
.rc-vitals{ display:flex; gap:0; border-top:1px solid var(--border); }
.rc-vitals .v{ flex:1; text-align:center; padding:9px 4px; border-right:1px solid var(--border); }
.rc-vitals .v:last-child{ border-right:none; }
.rc-vitals .vn{ font-size:15px; font-weight:700; } .rc-vitals .vl{ font-size:9px; color:#8b95a7; text-transform:uppercase; letter-spacing:.4px; margin-top:2px; }
.vn.ok{ color:#5fe39a; } .vn.warn{ color:#ffce6b; } .vn.crit{ color:#ff8b80; } .vn.cyan{ color:var(--cyan); }
.rc-act{ display:flex; border-top:1px solid var(--border); }
.rc-act a{ flex:1; text-align:center; padding:11px; font-size:13px; color:#bcd8ff; text-decoration:none; display:flex; align-items:center; justify-content:center; gap:8px; border-right:1px solid var(--border); }
.rc-act a:last-child{ border-right:none; } .rc-act a:hover{ background:rgba(77,163,255,.1); color:#fff; }
.rc-badge{ font-size:9px; padding:2px 7px; border-radius:20px; background:rgba(77,163,255,.14); color:#9cc7ff; }
.empty{ text-align:center; color:#8b95a7; padding:60px 20px; }
.rcard.rc-focus{ border-color:var(--cyan); box-shadow:0 0 0 1px var(--cyan), 0 0 26px rgba(54,227,208,.45); animation:rcPulse 1.4s ease-out 2; }
@keyframes rcPulse{ 0%{ box-shadow:0 0 0 1px var(--cyan), 0 0 8px rgba(54,227,208,.25); } 50%{ box-shadow:0 0 0 1px var(--cyan), 0 0 30px rgba(54,227,208,.6); } 100%{ box-shadow:0 0 0 1px var(--cyan), 0 0 8px rgba(54,227,208,.25); } }
</style>

<div class="rt">
  <div class="rt-head glass">
    <div class="rt-title"><i class="fa-solid fa-route"></i> Router Monitor</div>
    <div class="rt-kpis" id="kpis">
      <div class="kpi"><div class="n cyan" id="k-total"><?= count($routers) ?></div><div class="l">Routers</div></div>
      <div class="kpi"><div class="n ok" id="k-up">—</div><div class="l">Online</div></div>
      <div class="kpi"><div class="n crit" id="k-down">—</div><div class="l">Down</div></div>
      <div class="kpi"><div class="n crit" id="k-inc">—</div><div class="l">Incidents</div></div>
    </div>
    <?php if (checkAccess($conn, 'router_center')): ?>
    <a class="rt-cc" href="router_command.php"><i class="fa-solid fa-satellite-dish"></i> Command Center</a>
    <?php endif; ?>
  </div>

  <div class="grid" id="grid">
    <?php if (!$routers): ?>
      <div class="empty" style="grid-column:1/-1"><i class="fa-solid fa-route" style="font-size:40px;opacity:.4"></i>
        <div style="margin-top:14px">No router-class devices yet.<br>Add a device with icon <b>MikroTik RouterOS</b> or <b>Cisco</b> in
        <a href="net_mon_config.php?tab=nodes" style="color:var(--accent)">Configuration → Nodes</a>.</div></div>
    <?php endif; ?>
  </div>
</div>

<script>
const esc = s => String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function stColor(up){ return up===true?'#2ecc71':(up===false?'#e74c3c':'#8b95a7'); }
function card(r){
  const up=r.up, col=stColor(up);
  const latC = r.latency==null?'':(r.latency>=100?'warn':(r.up?'cyan':'crit'));
  const u24C = r.uptime24==null?'':(r.uptime24>=99.5?'ok':(r.uptime24>=95?'warn':'crit'));
  const icon = r.mikrotik ? 'fa-dharmachakra' : (String(r.os_icon).toLowerCase()==='cisco'?'fa-network-wired':'fa-route');
  const model = esc(r.model || r.manufacturer || (r.hw_model? r.hw_model.slice(0,40):'') || '');
  return `<div class="glass rcard" id="rc-${r.id}">
    <div class="rc-top">
      <div class="rc-photo">${r.photo?`<img src="${esc(r.photo)}" alt="">`:`<i class="fa-solid ${icon}"></i>`}</div>
      <div class="rc-id">
        <div class="rc-name"><span class="st" style="color:${col}"></span> ${esc(r.name)} ${r.mikrotik?'<span class="rc-badge">MikroTik</span>':''}</div>
        <div class="rc-sub">${esc(r.ip||'—')}${r.grp?` · ${esc(r.grp)}`:''}</div>
        ${model?`<div class="rc-model"><i class="fa-solid fa-microchip" style="color:#6f8bb5"></i> ${model}</div>`:''}
      </div>
    </div>
    <div class="rc-vitals">
      <div class="v"><div class="vn ${up?'ok':(up===false?'crit':'')}">${up===true?'UP':(up===false?'DOWN':'—')}</div><div class="vl">State</div></div>
      <div class="v"><div class="vn ${latC}">${r.latency==null?'—':(Math.round(r.latency*10)/10)}</div><div class="vl">ms</div></div>
      <div class="v"><div class="vn ${u24C}">${r.uptime24==null?'—':r.uptime24}</div><div class="vl">24h %</div></div>
      <div class="v"><div class="vn ${r.incidents>0?'crit':'ok'}">${r.incidents||0}</div><div class="vl">Incidents</div></div>
    </div>
    <div class="rc-act">
      <a href="router_details.php?node=${r.id}"><i class="fa-solid fa-gauge-high"></i> Command Center</a>
      <a href="router_commander.php?node=${r.id}&host=${esc(r.ip)}" target="_blank"><i class="fa-solid fa-terminal"></i> Commander</a>
      ${r.mikrotik?`<a href="mtfw.php?node=${r.id}"><i class="fa-solid fa-shield-halved"></i> Device Manager</a>`:''}
    </div>
  </div>`;
}
function render(list){
  const g=document.getElementById('grid');
  if(!list.length) return; // keep server-rendered empty state
  g.innerHTML = list.map(card).join('');
  let up=0,down=0,inc=0; list.forEach(r=>{ if(r.up===true)up++; else if(r.up===false)down++; inc+=r.incidents||0; });
  document.getElementById('k-total').textContent=list.length;
  document.getElementById('k-up').textContent=up;
  document.getElementById('k-down').textContent=down;
  document.getElementById('k-inc').textContent=inc;
  focusRouter();
}
const FOCUS_ROUTER = <?= (int)$focusNode ?>;
let _focused = false;
function focusRouter(){
  if(!FOCUS_ROUTER || _focused) return;
  const el = document.getElementById('rc-'+FOCUS_ROUTER);
  if(!el) return;
  _focused = true;
  el.scrollIntoView({behavior:'smooth', block:'center'});
  el.classList.add('rc-focus');
}
async function load(){ try{ const d=await fetch('routers.php?api=list&_='+Date.now()).then(r=>r.json()); if(d&&d.ok) render(d.routers); }catch(e){} }
document.addEventListener('DOMContentLoaded', ()=>{ if(window.NMLoader) NMLoader.hide(); load(); setInterval(load, 15000); });
</script>
</body></html>
