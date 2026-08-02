<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Cisco ASA / Firewall (F2). RBAC: 'cisco_asa'. Engine: nm_cisco.php.
// Security cockpit for Cisco ASA firewalls: connection load, remote-access + IPsec
// VPN, failover (active/standby), CPU/RAM trend. SNMP-only in F2; per-session VPN
// world-map + ACL-deny→Immunity arrive in F2.5 (SSH). See docs/NEURU_CISCO_SUITE_PLAN.md.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_cisco.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'cisco_asa')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=cisco_asa'); exit;
}
nm_cisco_ensure($conn);

function asa_series($conn, int $nid, string $type, string $key, int $mins=120): array {
    $out = [];
    try {
        $st = $conn->prepare("SELECT UNIX_TIMESTAMP(recorded_at) t, value v FROM nm_device_stats
                              WHERE node_id=? AND metric_type=? AND metric_key=? AND recorded_at > (NOW() - INTERVAL ? MINUTE)
                              ORDER BY recorded_at");
        $st->bind_param('issi', $nid, $type, $key, $mins); $st->execute();
        $res = $st->get_result();
        while ($x = $res->fetch_assoc()) $out[] = [(int)$x['t'], (float)$x['v']];
        $st->close();
    } catch (\Throwable $e) {}
    return $out;
}
function asa_firewalls($conn): array {
    $out = [];
    foreach (nm_cisco_nodes($conn) as $n) {
        if (($n['cisco_class'] ?? '') !== 'firewall') continue;
        $out[] = ['id'=>(int)$n['id'],'name'=>$n['display_name'],'ip'=>$n['ip_address'],'hw'=>$n['hw_model']];
    }
    return $out;
}

if ($api !== '') {
    if (function_exists('session_write_close')) @session_write_close();
    header('Content-Type: application/json; charset=utf-8');

    if ($api === 'firewalls') { echo json_encode(['ok'=>true,'firewalls'=>asa_firewalls($conn)]); exit; }

    if ($api === 'device') {
        $nid = (int)($_GET['id'] ?? 0);
        $n = null;
        foreach (nm_cisco_nodes($conn) as $x) { if ((int)$x['id']===$nid) { $n=$x; break; } }
        if (!$n) { echo json_encode(['ok'=>false,'error'=>'not a cisco node']); exit; }
        echo json_encode([
            'ok'=>true,
            'node'=>['id'=>$nid,'name'=>$n['display_name'],'ip'=>$n['ip_address'],'hw'=>$n['hw_model']],
            'status'=>nm_cisco_asa_status($conn, $nid),
            'cpu'=>nm_cisco_latest_metric($conn,$nid,'cpu'),
            'mem'=>nm_cisco_latest_metric($conn,$nid,'memory'),
            'conn_series'=>asa_series($conn,$nid,'cisco_conn','current'),
            'vpn_series'=>asa_series($conn,$nid,'cisco_vpn','ra_sessions'),
        ]); exit;
    }

    if ($api === 'repoll') { $nid=(int)($_GET['id']??0)?:null; echo json_encode(['ok'=>true] + nm_cisco_poll_now($conn,$nid)); exit; }
    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}

log_user_action($conn, 'view_page', 'cisco_asa.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cisco ASA | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cisco:#00bceb; --asa:#ff5a6a; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.14; }
.wrap{ max-width:1360px; margin:0 auto; padding:18px 20px 44px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.btn{ background:rgba(255,90,106,.13); border:1px solid rgba(255,90,106,.4); color:#ffc2c9; border-radius:9px; padding:8px 14px; font-size:13px; cursor:pointer; }
.btn:hover{ background:rgba(255,90,106,.24); } .btn.ghost{ background:transparent; border-color:var(--border); color:#aab; } .btn.sm{ padding:3px 9px; font-size:11px; }
.muted{ color:#7c828c; font-size:12px; } .mono{ font-family:monospace; }
.sel{ background:#1b2129; color:#e6e9ee; border:1px solid var(--border); border-radius:8px; padding:8px 11px; font-size:13px; }
.gauges{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:14px; margin-bottom:16px; }
.gauge{ padding:16px; text-align:center; } .gauge svg{ width:120px; height:120px; }
.gauge .big{ font-size:26px; font-weight:800; } .gauge .cap{ font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; margin-top:4px; }
.gauge .sub{ font-size:11px; color:#8a909a; margin-top:2px; }
.cols{ display:grid; grid-template-columns:1fr 1fr; gap:16px; } @media(max-width:900px){ .cols{ grid-template-columns:1fr; } }
.unit{ display:flex; align-items:center; gap:12px; padding:12px 14px; border:1px solid var(--border); border-radius:12px; margin-bottom:10px; }
.unit .role{ font-size:13px; font-weight:700; } .unit .badge{ margin-left:auto; font-size:11px; font-weight:800; text-transform:uppercase; padding:4px 12px; border-radius:20px; }
.badge.active{ background:rgba(46,204,113,.18); color:#8fe6b4;} .badge.standby{ background:rgba(77,163,255,.18); color:#a9d0ff;} .badge.failed{ background:rgba(231,76,60,.2); color:#f2a49b;} .badge.unknown{ background:rgba(255,255,255,.08); color:#9aa1ab;}
.sec{ font-size:12px; text-transform:uppercase; letter-spacing:.6px; color:#ffb3ba; margin:0 0 10px; font-weight:700; }
.spark{ width:100%; height:44px; }
.kv{ display:flex; justify-content:space-between; font-size:12.5px; padding:5px 0; border-bottom:1px solid rgba(255,255,255,.05); } .kv b{ font-weight:700; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fa-solid fa-shield-halved"></i> Cisco ASA Firewall', '',
    'Connections · VPN · Failover', 'fa-solid fa-shield-halved',
    '<select id="fwsel" class="sel" onchange="pick(this.value)"></select>
     <button class="btn ghost sm" onclick="repoll(this)"><i class="fas fa-rotate"></i> Re-poll</button>'); ?>

<div id="empty" class="glass card" style="display:none;">
  <div class="muted"><i class="fas fa-circle-info"></i> No Cisco <b>ASA / firewall</b> detected. A node is treated as a firewall
  when its model/name matches ASA / Firepower / FTD. Once discovered, its metrics appear within 5&nbsp;min
  (<span class="mono">cron_cisco.php</span>).</div>
</div>

<div id="live" style="display:none;">
  <div class="gauges" id="gauges"></div>
  <div class="cols">
    <div class="glass card" style="margin:0;">
      <div class="sec"><i class="fas fa-code-branch"></i> Failover</div>
      <div id="failover"><span class="muted">—</span></div>
    </div>
    <div class="glass card" style="margin:0;">
      <div class="sec"><i class="fas fa-user-lock"></i> VPN</div>
      <div id="vpn"><span class="muted">—</span></div>
    </div>
  </div>
  <div class="glass card">
    <div class="sec"><i class="fas fa-chart-line"></i> Connection load (2h)</div>
    <svg class="spark" id="sparkConn" viewBox="0 0 600 44" preserveAspectRatio="none"></svg>
  </div>
  <div class="glass card" id="threatbox">
    <div class="sec"><i class="fas fa-triangle-exclamation"></i> Threat feed (ACL denies)</div>
    <div class="muted">ACL-deny hits and one-click <a href="immunity.php">Collective Immunity</a> blocking arrive in
      <b>F2.5</b> — they need SSH <span class="mono">show access-list</span> (the ASA exposes no SNMP OID for
      per-rule hit counts). This card lights up once the ASA has SSH credentials configured.</div>
  </div>
</div>

<script>
let FW=[], CUR=0, TIMER=null;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function num(v){ return v==null?'—':(+v).toLocaleString(); }
function ring(pct,color,big,cap,sub){
  pct=Math.max(0,Math.min(100,pct||0)); const r=52,c=2*Math.PI*r,off=c*(1-pct/100);
  return `<div class="glass gauge"><svg viewBox="0 0 120 120">
    <circle cx="60" cy="60" r="${r}" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="9"/>
    <circle cx="60" cy="60" r="${r}" fill="none" stroke="${color}" stroke-width="9" stroke-linecap="round"
      stroke-dasharray="${c}" stroke-dashoffset="${off}" transform="rotate(-90 60 60)"/>
    <text x="60" y="58" text-anchor="middle" fill="#e6e9ee" font-size="22" font-weight="800">${big}</text>
    <text x="60" y="76" text-anchor="middle" fill="#8a909a" font-size="10">${sub||''}</text>
  </svg><div class="cap">${cap}</div></div>`;
}

async function boot(){
  const r=await fetch('cisco_asa.php?api=firewalls').then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok) return; FW=r.firewalls;
  const sel=document.getElementById('fwsel');
  if(!FW.length){ document.getElementById('empty').style.display='block'; sel.style.display='none'; return; }
  sel.innerHTML=FW.map(f=>`<option value="${f.id}">${esc(f.name)} — ${esc(f.hw||'ASA')}</option>`).join('');
  document.getElementById('live').style.display='block'; pick(FW[0].id);
}
function pick(id){ CUR=+id; if(TIMER)clearInterval(TIMER); load(); TIMER=setInterval(load,8000); }

async function load(){
  const r=await fetch('cisco_asa.php?api=device&id='+CUR).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok) return;
  const s=r.status||{};
  const connPct = (s.conn_peak&&s.conn_current)? (s.conn_current/s.conn_peak*100) : 0;
  const raPct = (s.ra_max&&s.ra_sessions)? (s.ra_sessions/s.ra_max*100) : 0;
  document.getElementById('gauges').innerHTML=
    ring(connPct,'#ff5a6a', num(s.conn_current), 'Connections', 'peak '+num(s.conn_peak))+
    ring(raPct,'#00bceb', num(s.ra_sessions), 'RA VPN', (s.ra_max?('/ '+num(s.ra_max)):'sessions'))+
    ring(s.ipsec_tunnels?100:0,'#9b59b6', num(s.ipsec_tunnels), 'IPsec tunnels', num(s.ipsec_ike)+' IKE')+
    ring(r.cpu||0,(r.cpu>85?'#e74c3c':(r.cpu>70?'#f39c12':'#2ecc71')), (r.cpu!=null?Math.round(r.cpu)+'%':'—'), 'CPU', '')+
    ring(r.mem||0,(r.mem>90?'#e74c3c':(r.mem>80?'#f39c12':'#2ecc71')), (r.mem!=null?Math.round(r.mem)+'%':'—'), 'Memory', '');
  renderFailover(s);
  renderVpn(s);
  spark('sparkConn', r.conn_series||[], '#ff5a6a');
}
function renderFailover(s){
  const box=document.getElementById('failover');
  if(!s.failover_detail && !s.failover_state){ box.innerHTML='<span class="muted">Standalone — no failover pair reported.</span>'; return; }
  const st=(s.failover_state||'unknown');
  box.innerHTML=`<div class="unit">
      <i class="fas fa-server" style="color:var(--asa)"></i>
      <div><div class="role">${esc((s.failover_role||'unit').toUpperCase())} (this device)</div>
        <div class="muted">${esc(s.failover_detail||'')}</div></div>
      <span class="badge ${['active','standby','failed'].includes(st)?st:'unknown'}">${esc(st)}</span>
    </div>`;
}
function renderVpn(s){
  document.getElementById('vpn').innerHTML=
    `<div class="kv"><span>Remote-access sessions</span><b>${num(s.ra_sessions)}</b></div>
     <div class="kv"><span>Remote-access users</span><b>${num(s.ra_users)}</b></div>
     <div class="kv"><span>Max supported</span><b>${num(s.ra_max)}</b></div>
     <div class="kv"><span>IPsec tunnels</span><b>${num(s.ipsec_tunnels)}</b></div>
     <div class="kv"><span>IKE tunnels</span><b>${num(s.ipsec_ike)}</b></div>
     <div class="muted" style="margin-top:8px">Per-user session geo-map (world view) lands in F2.5 (SSH <span class="mono">show vpn-sessiondb</span>).</div>`;
}
function spark(id, series, color){
  const svg=document.getElementById(id); if(!svg) return;
  if(!series.length){ svg.innerHTML='<text x="10" y="26" fill="#7c828c" font-size="12">no samples yet</text>'; return; }
  const xs=series.map(p=>p[0]), ys=series.map(p=>p[1]);
  const x0=Math.min(...xs),x1=Math.max(...xs),y1=Math.max(...ys,1);
  const W=600,H=44; const pts=series.map(p=>{ const x=x1>x0?((p[0]-x0)/(x1-x0))*W:0; const y=H-(p[1]/y1)*(H-6)-3; return x.toFixed(1)+','+y.toFixed(1); }).join(' ');
  svg.innerHTML=`<polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2"/>`;
}
async function repoll(btn){ const o=btn.innerHTML; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i>'; btn.disabled=true;
  await fetch('cisco_asa.php?api=repoll&id='+CUR).then(r=>r.json()).catch(()=>null); btn.innerHTML=o; btn.disabled=false; load(); }
boot();
</script>
</body></html>
