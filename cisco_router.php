<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Cisco Routers (F3). RBAC: 'cisco_router'. Engine: nm_cisco.php.
// Control-plane cockpit for Cisco routers: BGP / OSPF / HSRP neighbor state, IP SLA
// probes (latency/reachability), CPU/RAM. Complements the Routing Command Center
// (L3 fabric/topology). SNMP-only in F3; QoS depth is a later refinement.
// See docs/NEURU_CISCO_SUITE_PLAN.md (F3).
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_cisco.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'cisco_router')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=cisco_router'); exit;
}
nm_cisco_ensure($conn);

function crt_routers($conn): array {
    $out = [];
    foreach (nm_cisco_nodes($conn) as $n) {
        if (($n['cisco_class'] ?? '') !== 'router') continue;
        $out[] = ['id'=>(int)$n['id'],'name'=>$n['display_name'],'ip'=>$n['ip_address'],'hw'=>$n['hw_model']];
    }
    return $out;
}

if ($api !== '') {
    if (function_exists('session_write_close')) @session_write_close();
    header('Content-Type: application/json; charset=utf-8');

    if ($api === 'routers') { echo json_encode(['ok'=>true,'routers'=>crt_routers($conn)]); exit; }

    if ($api === 'device') {
        $nid = (int)($_GET['id'] ?? 0);
        $n = null;
        foreach (nm_cisco_nodes($conn) as $x) { if ((int)$x['id']===$nid) { $n=$x; break; } }
        if (!$n) { echo json_encode(['ok'=>false,'error'=>'not a cisco node']); exit; }
        $routing = nm_cisco_routing_list($conn, $nid);
        $g = ['bgp'=>[], 'ospf'=>[], 'hsrp'=>[]];
        foreach ($routing as $r) { $p=$r['proto']; if (isset($g[$p])) $g[$p][]=$r; }
        echo json_encode([
            'ok'=>true,
            'node'=>['id'=>$nid,'name'=>$n['display_name'],'ip'=>$n['ip_address'],'hw'=>$n['hw_model']],
            'bgp'=>$g['bgp'], 'ospf'=>$g['ospf'], 'hsrp'=>$g['hsrp'],
            'ipsla'=>nm_cisco_ipsla_list($conn, $nid),
            'cpu'=>nm_cisco_latest_metric($conn,$nid,'cpu'),
            'mem'=>nm_cisco_latest_metric($conn,$nid,'memory'),
        ]); exit;
    }

    if ($api === 'repoll') { $nid=(int)($_GET['id']??0)?:null; echo json_encode(['ok'=>true] + nm_cisco_poll_now($conn,$nid)); exit; }
    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}

log_user_action($conn, 'view_page', 'cisco_router.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cisco Routers | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cisco:#00bceb; --rtr:#7aa2ff; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.14; }
.wrap{ max-width:1360px; margin:0 auto; padding:18px 20px 44px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.btn{ background:rgba(122,162,255,.14); border:1px solid rgba(122,162,255,.4); color:#cfe0ff; border-radius:9px; padding:8px 14px; font-size:13px; cursor:pointer; }
.btn:hover{ background:rgba(122,162,255,.25); } .btn.ghost{ background:transparent; border-color:var(--border); color:#aab; } .btn.sm{ padding:3px 9px; font-size:11px; }
.muted{ color:#7c828c; font-size:12px; } .mono{ font-family:monospace; }
.sel{ background:#1b2129; color:#e6e9ee; border:1px solid var(--border); border-radius:8px; padding:8px 11px; font-size:13px; }
.stats{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:14px; }
.stat{ padding:12px 16px; } .stat .n{ font-size:24px; font-weight:800; line-height:1; } .stat .l{ font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; margin-top:4px; }
.stat .n.ok{ color:var(--ok);} .stat .n.warn{ color:var(--warn);} .stat .n.rtr{ color:var(--rtr);}
.cols{ display:grid; grid-template-columns:1fr 1fr; gap:16px; } @media(max-width:900px){ .cols{ grid-template-columns:1fr; } }
.sec{ font-size:12px; text-transform:uppercase; letter-spacing:.6px; color:#aec6ff; margin:0 0 10px; font-weight:700; }
table{ width:100%; border-collapse:collapse; font-size:12.5px; } th{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; padding:6px 8px; border-bottom:1px solid var(--border);} td{ padding:6px 8px; border-bottom:1px solid rgba(255,255,255,.05);}
.b{ font-size:10px; font-weight:800; text-transform:uppercase; padding:2px 8px; border-radius:20px; }
.b.up,.b.established,.b.full,.b.active,.b.ok{ background:rgba(46,204,113,.16); color:#8fe6b4;}
.b.standby,.b.twoWay{ background:rgba(77,163,255,.16); color:#a9d0ff;}
.b.idle,.b.down,.b.timeout,.b.init,.b.listen,.b.speak,.b.learn,.b.connect,.b.active2{ background:rgba(243,156,18,.16); color:#f3c37b;}
.b.overThreshold,.b.disconnected,.b.dropped{ background:rgba(231,76,60,.18); color:#f2a49b;}
.b.unknown{ background:rgba(255,255,255,.08); color:#9aa1ab;}
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fa-solid fa-route"></i> Cisco Routers', '',
    'BGP · OSPF · HSRP · IP SLA', 'fa-solid fa-route',
    '<select id="rsel" class="sel" onchange="pick(this.value)"></select>
     <a class="btn ghost sm" href="routing_command.php"><i class="fas fa-diagram-project"></i> Routing Command Center</a>
     <button class="btn ghost sm" onclick="repoll(this)"><i class="fas fa-rotate"></i> Re-poll</button>'); ?>

<div id="empty" class="glass card" style="display:none;">
  <div class="muted"><i class="fas fa-circle-info"></i> No Cisco <b>router</b> detected. Cisco nodes classify as routers by default
  (ISR/ASR/IOS). The L3 forwarding fabric across all routers lives in the
  <a href="routing_command.php">Routing Command Center</a>.</div>
</div>

<div id="live" style="display:none;">
  <div class="stats" id="stats"></div>
  <div class="cols">
    <div class="glass card" style="margin:0;">
      <div class="sec"><i class="fas fa-share-nodes"></i> BGP neighbors</div>
      <div id="bgp"></div>
    </div>
    <div class="glass card" style="margin:0;">
      <div class="sec"><i class="fas fa-circle-nodes"></i> OSPF neighbors</div>
      <div id="ospf"></div>
    </div>
  </div>
  <div class="cols">
    <div class="glass card" style="margin:0;">
      <div class="sec"><i class="fas fa-code-branch"></i> HSRP groups</div>
      <div id="hsrp"></div>
    </div>
    <div class="glass card" style="margin:0;">
      <div class="sec"><i class="fas fa-stopwatch"></i> IP SLA</div>
      <div id="ipsla"></div>
    </div>
  </div>
</div>

<script>
let RT=[], CUR=0, TIMER=null;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function bcls(s){ s=(s||'unknown'); return ['up','established','full','active','ok','standby','twoWay','idle','down','timeout','init','listen','speak','learn','connect','overThreshold','disconnected','dropped'].includes(s)?s:'unknown'; }
function badge(s){ return `<span class="b ${bcls(s)}">${esc(s||'?')}</span>`; }
function dur(s){ if(s==null)return '—'; s=+s; if(s<60)return s+'s'; if(s<3600)return Math.floor(s/60)+'m'; if(s<86400)return Math.floor(s/3600)+'h'; return Math.floor(s/86400)+'d'; }

async function boot(){
  const r=await fetch('cisco_router.php?api=routers').then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok) return; RT=r.routers;
  const sel=document.getElementById('rsel');
  if(!RT.length){ document.getElementById('empty').style.display='block'; sel.style.display='none'; return; }
  sel.innerHTML=RT.map(x=>`<option value="${x.id}">${esc(x.name)} — ${esc(x.hw||'router')}</option>`).join('');
  document.getElementById('live').style.display='block'; pick(RT[0].id);
}
function pick(id){ CUR=+id; if(TIMER)clearInterval(TIMER); load(); TIMER=setInterval(load,8000); }

async function load(){
  const r=await fetch('cisco_router.php?api=device&id='+CUR).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok) return;
  const bgpUp=r.bgp.filter(x=>x.state==='established').length;
  const ospfUp=r.ospf.filter(x=>x.state==='full').length;
  const hsrpAct=r.hsrp.filter(x=>x.state==='active').length;
  const slaOk=r.ipsla.filter(x=>x.sense==='ok').length;
  document.getElementById('stats').innerHTML=[
    ['n rtr',r.bgp.length,'BGP peers'],
    ['n '+(bgpUp<r.bgp.length?'warn':'ok'),bgpUp,'BGP established'],
    ['n ok',ospfUp,'OSPF full'],
    ['n rtr',hsrpAct,'HSRP active'],
    ['n '+(slaOk<r.ipsla.length?'warn':'ok'),slaOk+'/'+r.ipsla.length,'IP SLA ok'],
    ['n',(r.cpu!=null?Math.round(r.cpu)+'%':'—'),'CPU'],
    ['n',(r.mem!=null?Math.round(r.mem)+'%':'—'),'Memory'],
  ].map(c=>`<div class="glass stat"><div class="${c[0]}">${c[1]}</div><div class="l">${c[2]}</div></div>`).join('');

  document.getElementById('bgp').innerHTML = r.bgp.length ?
    `<table><thead><tr><th>Neighbor</th><th>Remote AS</th><th>State</th><th>Uptime</th></tr></thead><tbody>`+
    r.bgp.map(x=>`<tr><td class="mono">${esc(x.peer)}</td><td>${esc((x.info||'').replace('AS ',''))}</td><td>${badge(x.state)}</td><td>${dur(x.uptime_secs)}</td></tr>`).join('')+
    `</tbody></table>` : '<span class="muted">No BGP peers reported.</span>';

  document.getElementById('ospf').innerHTML = r.ospf.length ?
    `<table><thead><tr><th>Neighbor</th><th>Router ID</th><th>State</th></tr></thead><tbody>`+
    r.ospf.map(x=>`<tr><td class="mono">${esc(x.peer)}</td><td class="mono">${esc((x.info||'').replace('RID ',''))}</td><td>${badge(x.state)}</td></tr>`).join('')+
    `</tbody></table>` : '<span class="muted">No OSPF neighbors reported.</span>';

  document.getElementById('hsrp').innerHTML = r.hsrp.length ?
    `<table><thead><tr><th>If / Group</th><th>Virtual IP</th><th>State</th></tr></thead><tbody>`+
    r.hsrp.map(x=>`<tr><td class="mono">${esc(x.peer)}</td><td class="mono">${esc((x.info||'').replace('vip=',''))}</td><td>${badge(x.state)}</td></tr>`).join('')+
    `</tbody></table>` : '<span class="muted">No HSRP groups reported.</span>';

  document.getElementById('ipsla').innerHTML = r.ipsla.length ?
    `<table><thead><tr><th>#</th><th>Tag</th><th>RTT</th><th>Result</th></tr></thead><tbody>`+
    r.ipsla.map(x=>`<tr><td>${x.oper_index}</td><td>${esc(x.tag||'')}</td><td>${x.rtt_ms!=null?x.rtt_ms+' ms':'—'}</td><td>${badge(x.sense)}</td></tr>`).join('')+
    `</tbody></table>` : '<span class="muted">No IP SLA operations configured.</span>';
}
async function repoll(btn){ const o=btn.innerHTML; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i>'; btn.disabled=true;
  await fetch('cisco_router.php?api=repoll&id='+CUR).then(r=>r.json()).catch(()=>null); btn.innerHTML=o; btn.disabled=false; load(); }
boot();
</script>
</body></html>
