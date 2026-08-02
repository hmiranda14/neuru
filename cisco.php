<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Cisco Fleet (F0 hub). RBAC: 'cisco'. Engine: nm_cisco.php.
// Unified overview of every Cisco device: health gauges (reuses nm_device_stats),
// environmental sensors + CDP neighbors (nm_cisco_env / nm_cisco_neighbors), the
// active collection pillars (SNMP/NetFlow/Syslog), and deep links into the
// Router / Config / Troubleshoot modules. The specialised WebGL pages
// (cisco_switch/asa/router) land in later phases — see docs/NEURU_CISCO_SUITE_PLAN.md.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_cisco.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'cisco')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=cisco'); exit;
}
nm_cisco_ensure($conn);

// ── helpers ──────────────────────────────────────────────────────────────────
function cisco_last_seen($conn, int $nid): ?int {
    try {
        $st = $conn->prepare("SELECT UNIX_TIMESTAMP(MAX(recorded_at)) FROM nm_device_stats WHERE node_id=?");
        $st->bind_param('i', $nid); $st->execute(); $st->bind_result($t); $ok=$st->fetch(); $st->close();
        return $ok && $t ? (int)$t : null;
    } catch (\Throwable $e) { return null; }
}
function cisco_iface_summary($conn, int $nid): array {
    $tot = 0; $up = 0;
    try {
        $st = $conn->prepare("SELECT COUNT(*) FROM nm_interfaces WHERE node_id=? AND COALESCE(is_dummy,0)=0");
        $st->bind_param('i', $nid); $st->execute(); $st->bind_result($tot); $st->fetch(); $st->close();
    } catch (\Throwable $e) {}
    try {
        // latest oper_status per port
        $st = $conn->prepare("SELECT COUNT(*) FROM (
                SELECT ps.port_id, ps.oper_status
                FROM nm_port_stats ps
                JOIN (SELECT port_id, MAX(recorded_at) mx FROM nm_port_stats WHERE node_id=? GROUP BY port_id) t
                  ON t.port_id=ps.port_id AND t.mx=ps.recorded_at
                WHERE ps.node_id=? ) z WHERE z.oper_status=1");
        $st->bind_param('ii', $nid, $nid); $st->execute(); $st->bind_result($up); $st->fetch(); $st->close();
    } catch (\Throwable $e) {}
    return ['total'=>(int)$tot, 'up'=>(int)$up];
}
function cisco_recent_syslog($conn, string $ip, int $limit = 12): array {
    $out = [];
    if ($ip === '') return $out;
    try {
        $st = $conn->prepare("SELECT received_at,severity,tag,message FROM nm_syslog
                              WHERE host_ip=? ORDER BY received_at DESC LIMIT ?");
        $st->bind_param('si', $ip, $limit); $st->execute();
        $res = $st->get_result();
        while ($x = $res->fetch_assoc()) $out[] = $x;
        $st->close();
    } catch (\Throwable $e) {}
    return $out;
}
function cisco_pillars($conn): array {
    $p = ['snmp'=>true, 'netflow'=>false, 'syslog'=>false, 'telemetry'=>false];
    try {
        $r = $conn->query("SELECT COUNT(*) c FROM nm_syslog WHERE received_at > (NOW() - INTERVAL 1 DAY)");
        if ($r && ($x=$r->fetch_assoc())) $p['syslog'] = ((int)$x['c'] > 0);
    } catch (\Throwable $e) {}
    try {
        $r = $conn->query("SELECT COUNT(*) c FROM information_schema.TABLES
                           WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_netflow'");
        if ($r && ($x=$r->fetch_assoc()) && (int)$x['c']>0) {
            // existence probe only — never COUNT(*) a multi-million-row flow table
            $r2 = $conn->query("SELECT 1 FROM nm_netflow LIMIT 1");
            if ($r2) $p['netflow'] = ($r2->num_rows > 0);
        }
    } catch (\Throwable $e) {}
    return $p;
}

// ── JSON APIs ────────────────────────────────────────────────────────────────
if ($api !== '') {
    if (function_exists('session_write_close')) @session_write_close();
    header('Content-Type: application/json; charset=utf-8');

    if ($api === 'fleet') {
        $nodes = nm_cisco_nodes($conn);
        $now = time(); $out = [];
        $agg = ['total'=>0,'online'=>0,'switch'=>0,'router'=>0,'firewall'=>0,'wlc'=>0,'generic'=>0,'env_alerts'=>0,'neighbors'=>0];
        foreach ($nodes as $n) {
            $nid = (int)$n['id'];
            $cls = $n['cisco_class'];
            $seen = cisco_last_seen($conn, $nid);
            $online = ($seen !== null && ($now - $seen) < 600);
            $cpu = nm_cisco_latest_metric($conn, $nid, 'cpu');
            $mem = nm_cisco_latest_metric($conn, $nid, 'memory');
            $env = nm_cisco_env_worst($conn, $nid);
            $nb  = count(nm_cisco_neighbors($conn, $nid));
            $agg['total']++; $agg[$cls] = ($agg[$cls] ?? 0) + 1;
            if ($online) $agg['online']++;
            if (in_array($env, ['warning','critical','shutdown','notFunctioning'], true)) $agg['env_alerts']++;
            $agg['neighbors'] += $nb;
            $out[] = [
                'id'=>$nid, 'name'=>$n['display_name'], 'ip'=>$n['ip_address'],
                'class'=>$cls, 'class_label'=>nm_cisco_class_label($cls),
                'hw'=>$n['hw_model'], 'location'=>$n['location'],
                'online'=>$online, 'age'=>($seen!==null ? $now-$seen : null),
                'cpu'=>$cpu, 'mem'=>$mem, 'env'=>$env, 'neighbors'=>$nb,
                'caps'=>$n['caps'],
            ];
        }
        echo json_encode(['ok'=>true, 'agg'=>$agg, 'nodes'=>$out, 'pillars'=>cisco_pillars($conn)]); exit;
    }

    if ($api === 'device') {
        $nid = (int)($_GET['id'] ?? 0);
        $n = null;
        foreach (nm_cisco_nodes($conn) as $x) { if ((int)$x['id'] === $nid) { $n = $x; break; } }
        if (!$n) { echo json_encode(['ok'=>false,'error'=>'not a cisco node']); exit; }
        echo json_encode([
            'ok'=>true,
            'node'=>['id'=>$nid,'name'=>$n['display_name'],'ip'=>$n['ip_address'],
                     'class'=>$n['cisco_class'],'class_label'=>nm_cisco_class_label($n['cisco_class']),
                     'hw'=>$n['hw_model'],'caps'=>$n['caps']],
            'env'=>nm_cisco_env_list($conn, $nid),
            'neighbors'=>nm_cisco_neighbors($conn, $nid),
            'ifaces'=>cisco_iface_summary($conn, $nid),
            'syslog'=>cisco_recent_syslog($conn, (string)$n['ip_address']),
        ]); exit;
    }

    if ($api === 'repoll') {
        $nid = (int)($_GET['id'] ?? 0) ?: null;
        $s = nm_cisco_poll_now($conn, $nid);
        echo json_encode(['ok'=>true] + $s); exit;
    }

    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}

log_user_action($conn, 'view_page', 'cisco.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cisco Fleet | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cisco:#00bceb; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.16; }
.wrap{ max-width:1360px; margin:0 auto; padding:18px 20px 44px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.btn{ background:rgba(0,188,235,.14); border:1px solid rgba(0,188,235,.4); color:#bfeefb; border-radius:9px; padding:8px 14px; font-size:13px; cursor:pointer; }
.btn:hover{ background:rgba(0,188,235,.25); } .btn.ghost{ background:transparent; border-color:var(--border); color:#aab; } .btn.sm{ padding:3px 9px; font-size:11px; }
.muted{ color:#7c828c; font-size:12px; } .mono{ font-family:monospace; }
/* stat rail */
.stats{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:14px; }
.stat{ padding:14px 16px; } .stat .n{ font-size:30px; font-weight:800; line-height:1; }
.stat .l{ font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; margin-top:5px; }
.stat .n.cisco{ color:var(--cisco); } .stat .n.ok{ color:var(--ok);} .stat .n.warn{ color:var(--warn);}
/* pillars */
.pillars{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
.pill{ display:inline-flex; align-items:center; gap:7px; font-size:12px; padding:6px 12px; border-radius:20px; border:1px solid var(--border); background:rgba(255,255,255,.04); }
.pill .dot{ width:8px; height:8px; border-radius:50%; background:#4a5058; } .pill.on .dot{ background:var(--ok); box-shadow:0 0 7px var(--ok);} .pill.off{ opacity:.55; }
.pill.plan{ border-style:dashed; opacity:.6; }
/* device grid */
.grid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:14px; }
.dcard{ padding:15px 16px; cursor:pointer; transition:transform .15s, border-color .15s; position:relative; overflow:hidden; }
.dcard:hover{ transform:translateY(-3px); border-color:rgba(0,188,235,.45); }
.dcard.active{ border-color:var(--cisco); box-shadow:0 0 0 1px rgba(0,188,235,.35) inset; }
.dcard .hd{ display:flex; align-items:flex-start; gap:10px; }
.dcard .nm{ font-size:16px; font-weight:800; } .dcard .ip{ font-size:11px; color:#8a909a; }
.badge{ font-size:9.5px; font-weight:800; text-transform:uppercase; letter-spacing:.4px; padding:3px 9px; border-radius:20px; background:rgba(0,188,235,.16); color:#8fe4f6; white-space:nowrap; }
.badge.switch{ background:rgba(46,204,113,.16); color:#8fe6b4;} .badge.router{ background:rgba(77,163,255,.16); color:#a9d0ff;}
.badge.firewall{ background:rgba(231,76,60,.16); color:#f2a49b;} .badge.wlc{ background:rgba(155,89,182,.18); color:#d3aee6;}
.stcircle{ width:9px; height:9px; border-radius:50%; display:inline-block; margin-right:5px; }
.on{ background:var(--ok); box-shadow:0 0 7px var(--ok);} .off{ background:var(--crit); box-shadow:0 0 7px var(--crit);}
.gauges{ display:grid; grid-template-columns:1fr 1fr; gap:12px; margin:12px 0 8px; }
.g .lab{ font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; display:flex; justify-content:space-between; }
.g .v{ font-size:19px; font-weight:800; margin:1px 0 4px; }
.bar{ height:7px; border-radius:6px; background:rgba(255,255,255,.08); overflow:hidden; } .bar>i{ display:block; height:100%; border-radius:6px; transition:width .5s; }
.chips{ display:flex; gap:6px; flex-wrap:wrap; margin-top:6px; }
.chip{ font-size:10.5px; padding:3px 8px; border-radius:20px; border:1px solid var(--border); color:#aeb4bd; }
.chip.warn{ border-color:rgba(243,156,18,.5); color:#f3c37b;} .chip.crit{ border-color:rgba(231,76,60,.5); color:#f2a49b;} .chip.ok{ border-color:rgba(46,204,113,.4); color:#9fe3bd;}
.links{ display:flex; gap:8px; margin-top:11px; flex-wrap:wrap; }
/* drawer */
.drawer-bg{ position:fixed; inset:0; background:rgba(0,0,0,.55); z-index:80; display:none; }
.drawer{ position:fixed; top:0; right:0; height:100%; width:560px; max-width:96vw; background:#0c1015; border-left:1px solid var(--border); z-index:81; transform:translateX(100%); transition:transform .28s; overflow:auto; padding:20px 22px; }
.drawer.open{ transform:translateX(0); }
table{ width:100%; border-collapse:collapse; font-size:12.5px; }
th{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; padding:6px 8px; border-bottom:1px solid var(--border); }
td{ padding:6px 8px; border-bottom:1px solid rgba(255,255,255,.05); vertical-align:top; }
.sec{ font-size:12px; text-transform:uppercase; letter-spacing:.6px; color:#8fe4f6; margin:18px 0 8px; font-weight:700; }
.sev{ font-weight:700; } .sev0,.sev1,.sev2,.sev3{ color:var(--crit);} .sev4{ color:var(--warn);} .sev5{ color:#cbd3dd;} .sev6,.sev7{ color:#7c828c;}
.est{ font-size:10px; font-weight:800; text-transform:uppercase; padding:2px 7px; border-radius:20px; }
.est.normal{ background:rgba(46,204,113,.16); color:#8fe6b4;} .est.warning{ background:rgba(243,156,18,.18); color:#f3c37b;}
.est.critical,.est.shutdown,.est.notFunctioning{ background:rgba(231,76,60,.18); color:#f2a49b;}
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fa-solid fa-network-wired"></i> Cisco Fleet', '',
    'Unified Cisco monitoring — SNMP · NetFlow · Syslog', 'fa-solid fa-network-wired',
    '<button class="btn ghost sm" onclick="repoll(0,this)"><i class="fas fa-rotate"></i> Re-poll all</button>'); ?>

<div class="glass card" style="padding:11px 16px;"><div class="muted"><i class="fas fa-circle-info"></i>
  Health (CPU/RAM/interfaces) comes from the standard SNMP poller; <b>environmental sensors</b> and
  <b>CDP neighbors</b> come from the Cisco collector (<span class="mono">cron_cisco.php</span>, every 5&nbsp;min).
  Specialised switch / ASA / router command centers arrive in later phases.</div></div>

<div class="stats" id="stats"></div>

<div class="glass card" style="padding:12px 16px;">
  <div class="muted" style="margin-bottom:8px;"><i class="fas fa-layer-group"></i> Active collection pillars</div>
  <div class="pillars" id="pillars"><span class="muted">Loading…</span></div>
</div>

<div class="grid" id="grid"><div class="muted">Loading Cisco devices…</div></div>

<div class="drawer-bg" id="dbg" onclick="closeDrawer()"></div>
<div class="drawer glass" id="drawer"></div>

<script>
let FLEET=[], SEL=0;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function clr(v,a,b){ v=+v; return v>=b?'var(--crit)':(v>=a?'var(--warn)':'var(--ok)'); }
function age(s){ if(s==null)return 'never'; s=+s; if(s<60)return s+'s'; if(s<3600)return Math.floor(s/60)+'m'; if(s<86400)return Math.floor(s/3600)+'h'; return Math.floor(s/86400)+'d'; }
function pct(v){ return v==null?'—':(Math.round(v*10)/10)+'%'; }

async function load(){
  const r=await fetch('cisco.php?api=fleet').then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok){ document.getElementById('grid').innerHTML='<div class="muted">Failed to load.</div>'; return; }
  FLEET=r.nodes; renderStats(r.agg); renderPillars(r.pillars); renderGrid();
}
function renderStats(a){
  const cells=[
    ['n cisco',a.total,'Cisco devices'],
    ['n ok',a.online,'Online'],
    ['n',a.switch||0,'Switches'],
    ['n',a.router||0,'Routers'],
    ['n',a.firewall||0,'ASA / FW'],
    ['n '+(a.env_alerts?'warn':''),a.env_alerts,'Env alerts'],
    ['n',a.neighbors,'CDP neighbors'],
  ];
  document.getElementById('stats').innerHTML=cells.map(c=>
    `<div class="glass stat"><div class="${c[0]}" data-t="${c[1]}">0</div><div class="l">${c[2]}</div></div>`).join('');
  document.querySelectorAll('.stat .n').forEach(el=>{
    const t=+el.dataset.t||0; let i=0; const step=Math.max(1,Math.ceil(t/24));
    const iv=setInterval(()=>{ i+=step; if(i>=t){i=t;clearInterval(iv);} el.textContent=i; },22);
  });
}
function renderPillars(p){
  const defs=[['snmp','SNMP','fa-satellite-dish'],['netflow','NetFlow','fa-chart-area'],
              ['syslog','Syslog','fa-scroll'],['telemetry','Streaming Telemetry','fa-tower-broadcast']];
  document.getElementById('pillars').innerHTML=defs.map(d=>{
    const on=!!p[d[0]]; const plan=d[0]==='telemetry';
    return `<span class="pill ${plan?'plan':(on?'on':'off')}"><span class="dot"></span>
      <i class="fas ${d[2]}"></i> ${d[1]} ${plan?'<span class="muted">· planned</span>':(on?'':'<span class="muted">· idle</span>')}</span>`;
  }).join('');
}
function renderGrid(){
  const g=document.getElementById('grid');
  if(!FLEET.length){ g.innerHTML='<div class="glass card muted">No Cisco devices found. Nodes are detected as Cisco automatically (SNMP enterprise OID .1.3.6.1.4.1.9 or a Cisco sysDescr).</div>'; return; }
  g.innerHTML=FLEET.map(n=>{
    const cpu=n.cpu, mem=n.mem;
    const envChip = n.env ? `<span class="chip ${n.env==='normal'?'ok':(n.env==='warning'?'warn':'crit')}"><i class="fas fa-temperature-half"></i> ${esc(n.env)}</span>` : '';
    const nbChip  = n.neighbors ? `<span class="chip"><i class="fas fa-diagram-project"></i> ${n.neighbors} CDP</span>` : '';
    return `<div class="glass dcard ${n.id==SEL?'active':''}" onclick="openDrawer(${n.id})">
      <div class="hd">
        <div style="flex:1;min-width:0;">
          <div class="nm"><span class="stcircle ${n.online?'on':'off'}"></span>${esc(n.name)}</div>
          <div class="ip">${esc(n.ip||'')} · ${esc(n.hw||'')||'Cisco'} · seen ${age(n.age)} ago</div>
        </div>
        <span class="badge ${n.class}">${esc(n.class_label)}</span>
      </div>
      <div class="gauges">
        <div class="g"><div class="lab"><span>CPU</span><span>${pct(cpu)}</span></div>
          <div class="v">${pct(cpu)}</div><div class="bar"><i style="width:${Math.min(100,cpu||0)}%;background:${clr(cpu||0,70,90)}"></i></div></div>
        <div class="g"><div class="lab"><span>Memory</span><span>${pct(mem)}</span></div>
          <div class="v">${pct(mem)}</div><div class="bar"><i style="width:${Math.min(100,mem||0)}%;background:${clr(mem||0,80,92)}"></i></div></div>
      </div>
      <div class="chips">${envChip}${nbChip}</div>
      <div class="links" onclick="event.stopPropagation()">
        <a class="btn sm ghost" href="router_details.php?node=${n.id}"><i class="fas fa-gauge-high"></i> Details</a>
        <a class="btn sm ghost" href="config_mgr.php?node=${n.id}"><i class="fas fa-file-code"></i> Config</a>
        <a class="btn sm ghost" href="troubleshoot.php?node=${n.id}"><i class="fas fa-wrench"></i> Troubleshoot</a>
      </div>
    </div>`;
  }).join('');
}

async function openDrawer(id){
  SEL=id; renderGrid();
  const d=document.getElementById('drawer'); const bg=document.getElementById('dbg');
  d.innerHTML='<div class="muted">Loading…</div>'; d.classList.add('open'); bg.style.display='block';
  const r=await fetch('cisco.php?api=device&id='+id).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok){ d.innerHTML='<div class="muted">Failed to load device.</div>'; return; }
  const n=r.node;
  const env=r.env.map(e=>`<tr><td>${esc(e.kind)}</td><td>${esc(e.sensor)}</td>
      <td>${e.value!=null?esc(e.value)+(e.unit?(' '+esc(e.unit)):''):'—'}</td>
      <td>${e.state?`<span class="est ${esc(e.state)}">${esc(e.state)}</span>`:'—'}</td></tr>`).join('')
      || '<tr><td colspan="4" class="muted">No environmental sensors reported (normal for controllers / small switches).</td></tr>';
  const nb=r.neighbors.map(x=>`<tr><td>${esc(x.local_if||'')}</td>
      <td>${x.matched_node_id?`<a href="router_details.php?node=${x.matched_node_id}">${esc(x.neighbor_name)}</a>`:esc(x.neighbor_name)}</td>
      <td>${esc(x.remote_if||'')}</td><td>${esc(x.platform||'')}</td><td class="mono">${esc(x.neighbor_ip||'')}</td></tr>`).join('')
      || '<tr><td colspan="5" class="muted">No CDP neighbors discovered.</td></tr>';
  const sl=r.syslog.map(s=>`<tr><td class="mono">${esc((s.received_at||'').slice(5,16))}</td>
      <td class="sev sev${s.severity==null?5:s.severity}">${s.severity==null?'—':s.severity}</td>
      <td>${esc(s.tag||'')}</td><td>${esc((s.message||'').slice(0,90))}</td></tr>`).join('')
      || '<tr><td colspan="4" class="muted">No recent syslog from this device.</td></tr>';
  d.innerHTML=`
    <div style="display:flex;align-items:center;gap:10px;">
      <div style="flex:1;"><div style="font-size:19px;font-weight:800;">${esc(n.name)}</div>
        <div class="muted">${esc(n.ip||'')} · ${esc(n.class_label)} · ${esc(n.hw||'')||'Cisco'}</div></div>
      <button class="btn sm ghost" onclick="repoll(${n.id},this)"><i class="fas fa-rotate"></i> Re-poll</button>
      <button class="btn sm ghost" onclick="closeDrawer()">✕</button>
    </div>
    <div style="margin-top:8px;font-size:12px;color:#8a909a;">Interfaces: <b style="color:#cbd3dd">${r.ifaces.up}/${r.ifaces.total}</b> up</div>
    <div class="sec"><i class="fas fa-temperature-half"></i> Environmental</div>
    <table><thead><tr><th>Kind</th><th>Sensor</th><th>Value</th><th>State</th></tr></thead><tbody>${env}</tbody></table>
    <div class="sec"><i class="fas fa-diagram-project"></i> CDP Neighbors</div>
    <table><thead><tr><th>Local</th><th>Neighbor</th><th>Remote</th><th>Platform</th><th>IP</th></tr></thead><tbody>${nb}</tbody></table>
    <div class="sec"><i class="fas fa-scroll"></i> Recent Syslog</div>
    <table><thead><tr><th>Time</th><th>Sev</th><th>Tag</th><th>Message</th></tr></thead><tbody>${sl}</tbody></table>`;
}
function closeDrawer(){ document.getElementById('drawer').classList.remove('open'); document.getElementById('dbg').style.display='none'; SEL=0; renderGrid(); }

async function repoll(id,btn){
  const old=btn.innerHTML; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i>'; btn.disabled=true;
  await fetch('cisco.php?api=repoll'+(id?('&id='+id):'')).then(r=>r.json()).catch(()=>null);
  btn.innerHTML=old; btn.disabled=false;
  if(id) openDrawer(id); else load();
}
load();
setInterval(load, 30000);
</script>
</body></html>
