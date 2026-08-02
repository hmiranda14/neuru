<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — WireGuard Connection (dedicated, isolated page).
// The toggle lived in net_mon_config.php's crowded n8n tab, where other page-load
// requests stalled the browser connection. Given its own clean page it works
// reliably (proven). Same engine (nm_wgconn.php); RBAC 'net_mon'.
// ─────────────────────────────────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) session_start();
require __DIR__ . '/connection.php';
require_once __DIR__ . '/access_control.php';

if (isset($_GET['api'])) {
    header('Content-Type: application/json; charset=utf-8');
    if (empty($_SESSION['username']) || !checkAccess($conn, 'net_mon')) { http_response_code(403); echo json_encode(['ok'=>false,'error'=>'unauthorized']); exit; }
    require_once __DIR__ . '/nm_wgconn.php';
    $a = $_GET['api'];
    if ($a === 'wg_status') { echo json_encode(['ok'=>true,'state'=>nm_wgconn_state($conn)]); exit; }
    if (function_exists('session_write_close')) @session_write_close();
    if ($a === 'wg_enroll')  { echo json_encode(nm_wgconn_enroll($conn)); exit; }
    if ($a === 'wg_disable') { echo json_encode(nm_wgconn_disable($conn)); exit; }
    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}

include('check.php');
if (!checkAccess($conn, 'net_mon')) { header('Location: /denied_access.php?page=net_mon'); exit; }
require_once __DIR__ . '/nm_chrome.php';
// NOTE: header.php is intentionally NOT included — its background polls (incident badge, etc.)
// are what stalled the browser connection in the crowded config page. This page stays isolated.
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>WireGuard Connection | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
<?= nm_chrome_css() ?>
:root{--glass:rgba(255,255,255,0.07);--border:rgba(255,255,255,0.13);--accent:#36e3d0;--up:#2ecc71;--down:#e74c3c;--mut:#8a909a;}
body{margin:0;font-family:'Segoe UI',Tahoma,sans-serif;background:#0b0e13;color:#fff;}
.wrap{max-width:760px;margin:0 auto;padding:22px;}
.topbar{display:flex;align-items:center;gap:14px;margin-bottom:20px;}
.back{color:#9aa3ad;text-decoration:none;font-size:13px;display:inline-flex;align-items:center;gap:7px;border:1px solid var(--border);padding:7px 12px;border-radius:8px;}
.back:hover{color:#fff;border-color:var(--accent);}
.card{background:var(--glass);border:1px solid var(--border);border-radius:16px;padding:24px;}
h1{font-size:18px;margin:0 0 4px;display:flex;align-items:center;gap:10px;color:var(--accent);}
.sub{color:var(--mut);font-size:12.5px;margin:0 0 18px;}
.desc{font-size:12.5px;color:#aeb6bf;line-height:1.6;background:rgba(54,227,208,.06);border:1px solid rgba(54,227,208,.18);border-radius:10px;padding:12px 14px;margin-bottom:20px;}
.row{display:flex;align-items:center;gap:16px;flex-wrap:wrap;}
.btn{padding:12px 20px;border-radius:10px;border:1px solid var(--border);background:rgba(255,255,255,.05);color:#dfe6ee;font-size:14px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:9px;}
.btn:hover{border-color:var(--accent);}.btn:disabled{opacity:.55;cursor:not-allowed;}
.btn.on{background:rgba(46,204,113,.16);border-color:var(--up);color:#8ff0b6;}
.btn.off{background:rgba(231,76,60,.14);border-color:var(--down);color:#f0b0a8;}
.state{font-size:14px;color:#aeb6bf;display:inline-flex;align-items:center;gap:8px;}
.dot{width:10px;height:10px;border-radius:50%;background:#666;display:inline-block;}
.dot.up{background:var(--up);box-shadow:0 0 8px var(--up);}
#msg{margin-top:16px;font-size:13px;min-height:20px;}
code{background:rgba(255,255,255,.08);padding:1px 6px;border-radius:5px;font-size:12px;}
</style></head>
<body>
<div class="wrap">
  <div class="topbar">
    <a class="back" href="net_mon_config.php?tab=integrations" onclick="if(window.opener){window.close();return false;}"><i class="fas fa-arrow-left"></i> <span id="backlbl">Config</span></a>
  </div>
  <div class="card">
    <h1><i class="fas fa-plug-circle-bolt"></i> NEURU WG Connection</h1>
    <p class="sub">Let hosted flows reach this NEURU behind NAT.</p>
    <div class="desc">
      Most installs sit behind NAT, so the hosted n8n can't deliver flow results back. Turn this <b>ON</b> and
      NEURU asks the Portal for a private <b>WireGuard</b> tunnel — no port-forwarding, no firewall rules. One
      switch. Off by default. Requires the WireGuard sidecar container (ships with new installs; existing
      installs add it once).
    </div>
    <div class="row">
      <button id="btn" class="btn" onclick="toggle()"><i class="fas fa-power-off"></i> <span id="lbl">Enable connection</span></button>
      <span class="state"><span id="dot" class="dot"></span> <span id="state">checking…</span></span>
    </div>
    <div id="msg"></div>
  </div>
</div>
<script>
function esc(s){return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
let ON=false;
function render(st){
  ON = (st && st.status==='on');
  const up = ON && st && st.link_up;                 // truly up = intent ON *and* wg0 present in our netns
  const dot=document.getElementById('dot'), state=document.getElementById('state');
  const b=document.getElementById('btn'), l=document.getElementById('lbl');
  if(ON && up){
    dot.className='dot up'; dot.style.background=''; dot.style.boxShadow='';
    state.innerHTML='Connected — tunnel IP <b>'+esc(st.ip||'')+'</b>';
  } else if(ON && !up){
    // config written + Portal enrolled, but the interface isn't up → the WireGuard sidecar isn't running here
    dot.className='dot'; dot.style.background='#e0a559'; dot.style.boxShadow='0 0 8px #e0a559';
    state.innerHTML='Enrolled (IP <b>'+esc(st.ip||'')+'</b>) — but the tunnel isn\'t up yet';
  } else {
    dot.className='dot'; dot.style.background=''; dot.style.boxShadow='';
    state.innerHTML='Off'+(st&&st.last_err?(' — <span style="color:#e08a8a">'+esc(st.last_err)+'</span>'):'');
  }
  b.className = 'btn '+(ON?'off':'on'); l.textContent = ON ? 'Disable connection' : 'Enable connection';
  let warn='';
  if(st && st.writable===false) warn='<span style="color:#e0a559">⚠ The <code>wg/</code> folder isn\'t writable by www-data — enabling will fail until it is.</span>';
  else if(ON && !up) warn='<span style="color:#e0a559">⚠ Tunnel config is written and the Portal enrolled this NEURU, but the WireGuard interface <code>wg0</code> isn\'t up. That means the <code>neuru-wg</code> sidecar container isn\'t running here — expected on a dev box without it. On a standard NEURU install the sidecar brings it up automatically.</span>';
  document.getElementById('msg').innerHTML=warn;
}
async function status(){ const r=await fetch('wg_connection.php?api=wg_status',{cache:'no-store'}).then(r=>r.json()).catch(()=>null); if(r&&r.ok) render(r.state); }
async function toggle(){
  const b=document.getElementById('btn'), m=document.getElementById('msg'); b.disabled=true;
  const enabling=!ON;
  m.style.color='#8a929c'; m.innerHTML='<i class="fas fa-circle-notch fa-spin"></i> '+(enabling?'Requesting tunnel from the Portal…':'Disabling…');
  try{
    const r=await fetch('wg_connection.php?api='+(enabling?'wg_enroll':'wg_disable'),{cache:'no-store'}).then(r=>r.json());
    b.disabled=false;
    if(r.ok){ m.style.color='#8ff0b6'; m.innerHTML= enabling ? ('<i class="fas fa-check"></i> Enrolled — tunnel IP <b>'+esc(r.ip||'')+'</b>. Verifying the link…') : 'Disabled.'; }
    else { m.style.color='#f0b0a8'; m.innerHTML='<i class="fas fa-triangle-exclamation"></i> '+esc(r.error||'Failed'); }
  }catch(e){ b.disabled=false; m.style.color='#f0b0a8'; m.innerHTML='<i class="fas fa-triangle-exclamation"></i> request failed'; }
  status();
}
if(window.opener){var _bl=document.getElementById('backlbl'); if(_bl)_bl.textContent='Close';}
status();
</script>
</body></html>
