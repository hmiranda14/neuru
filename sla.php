<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — SLA Live Center. Per-node availability tracked LIVE with the SRE
// error-budget model + an outage↔incident timeline. Complements reports.php
// (which does the periodic email report); this is the always-on cockpit.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
include('logger.php');
require_once('nm_sla.php');
@require_once('nm_tz.php');

$api = $_GET['api'] ?? '';
$allowed = checkAccess($conn, 'sla_live') || checkAccess($conn, 'reports');
if (!$allowed) { if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'err'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=sla'); exit; }
@$conn->query("INSERT IGNORE INTO role_profiles (role_name,button_key,enabled) VALUES ('admin','sla_live',1)");
if (session_status() === PHP_SESSION_ACTIVE) @session_write_close();   // SLA scans read-only → don't hold the lock

$range = in_array(($_GET['range'] ?? '7d'), ['24h','7d','30d'], true) ? $_GET['range'] : '7d';

if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    $mins = nm_sla_mins($range);
    $S = nm_sla_settings($conn); $target = (float)$S['target'];

    if ($api === 'live') {
        $rows = nm_sla_all($conn, $mins, $target);
        $up=0;$down=0;$avg=0;$breach=0;$consumed=0;$allowedB=0;$worst=null;
        foreach ($rows as &$r) {
            $r['budget'] = nm_sla_error_budget((float)$r['uptime'], $target, $mins);
            if ($r['last']==='up') $up++; else $down++;
            $avg += $r['uptime']; if (!$r['meets']) $breach++;
            $consumed += $r['budget']['consumed_min']; $allowedB += $r['budget']['allowed_min'];
            if ($worst===null || $r['uptime'] < $worst['uptime']) $worst = ['name'=>$r['display_name'],'uptime'=>$r['uptime'],'id'=>$r['id']];
        }
        unset($r);
        echo json_encode(['ok'=>true,'range'=>$range,'target'=>$target,'nodes'=>$rows,
            'stats'=>['count'=>count($rows),'up'=>$up,'down'=>$down,'breaching'=>$breach,
                      'avg'=>$rows?round($avg/count($rows),3):100,'worst'=>$worst,
                      'budget_burn'=>$allowedB>0?min(100,round($consumed/$allowedB*100,1)):0]]);
        exit;
    }

    if ($api === 'node') {
        $nid = (int)($_GET['node'] ?? 0);
        $nr = $conn->query("SELECT id,display_name,ip_address,monitor_type,os_icon FROM nm_nodes WHERE id=$nid LIMIT 1");
        $node = $nr ? $nr->fetch_assoc() : null;
        if (!$node) { echo json_encode(['ok'=>false,'err'=>'Unknown node']); exit; }
        $a = nm_sla_node($conn, $node, $mins);
        $budget = nm_sla_error_budget((float)($a['uptime'] ?? 100), $target, $mins);
        $episodes = nm_sla_outage_episodes($conn, $node, $mins);
        $incs = [];
        if ($conn->query("SHOW TABLES LIKE 'nm_incidents'")->num_rows) {
            $r = $conn->query("SELECT id,title,severity,status,UNIX_TIMESTAMP(opened_at) opened, UNIX_TIMESTAMP(resolved_at) resolved
                               FROM nm_incidents WHERE root_node_id=$nid AND opened_at >= (NOW() - INTERVAL $mins MINUTE)
                               ORDER BY opened_at DESC LIMIT 40");
            while ($r && $x=$r->fetch_assoc()) $incs[] = $x;
        }
        $errlog = 0;
        if (!empty($node['ip_address']) && $conn->query("SHOW TABLES LIKE 'nm_syslog'")->num_rows) {
            $st=$conn->prepare("SELECT COUNT(*) c FROM nm_syslog WHERE host_ip=? AND severity<=3 AND received_at >= (NOW() - INTERVAL $mins MINUTE)");
            $st->bind_param('s',$node['ip_address']); $st->execute(); $rs=$st->get_result();
            if ($rs && ($x=$rs->fetch_assoc())) $errlog=(int)$x['c']; $st->close();
        }
        echo json_encode(['ok'=>true,'node'=>$node,'sla'=>$a,'budget'=>$budget,'target'=>$target,
            'window'=>['from'=>time()-$mins*60,'to'=>time(),'mins'=>$mins],
            'episodes'=>$episodes,'incidents'=>$incs,'err_logs'=>$errlog,
            'meets'=>(($a['uptime']??0) >= $target)]);
        exit;
    }
    echo json_encode(['ok'=>false,'err'=>'unknown api']); exit;
}

log_user_action($conn, 'view_page', 'sla.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SLA Live Center | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" media="print" onload="this.media='all'">
<noscript><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"></noscript>
<?= function_exists('nm_tz_js') ? nm_tz_js() : '' ?>
<style>
:root{ --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --glass:rgba(255,255,255,.055); --border:rgba(255,255,255,.13); }
html{ background:#05080f; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; color:#e7ecf3; background:transparent!important; }
.wrap{ max-width:1500px; margin:0 auto; padding:22px 20px 70px; }
h1{ font-size:22px; display:flex; align-items:center; gap:12px; margin:0; }
h1 .sub{ font-size:12px; color:#8a93a3; font-weight:400; }
.live{ display:inline-flex;align-items:center;gap:6px;font-size:10px;font-weight:800;letter-spacing:1px;color:var(--ok);border:1px solid rgba(46,204,113,.4);border-radius:20px;padding:3px 10px;margin-left:8px; }
.live .d{ width:7px;height:7px;border-radius:50%;background:var(--ok);animation:blink 1.4s infinite; } @keyframes blink{50%{opacity:.25}}
.top{ display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:16px; }
.ranges{ margin-left:auto;display:flex;gap:6px; } .rbtn{ background:var(--glass);border:1px solid var(--border);color:#bcc8d6;padding:7px 14px;border-radius:9px;font-size:12.5px;cursor:pointer; }
.rbtn.on{ border-color:var(--accent);color:#fff;background:rgba(77,163,255,.14); }
.kpis{ display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px; }
.kpi{ background:var(--glass);border:1px solid var(--border);border-radius:14px;padding:14px 16px; }
.kpi .n{ font-size:26px;font-weight:800; } .kpi .l{ font-size:11px;color:#8a93a3;text-transform:uppercase;letter-spacing:.5px; }
.grid{ display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:15px; }
.card{ background:var(--glass);border:1px solid var(--border);border-radius:16px;padding:16px;cursor:pointer;transition:.15s;position:relative;overflow:hidden; }
.card:hover{ border-color:var(--accent);transform:translateY(-2px); }
.card.breach{ border-color:rgba(231,76,60,.5); } .card.breach::after{ content:'';position:absolute;inset:0;background:radial-gradient(120% 90% at 100% 0%,rgba(231,76,60,.10),transparent);pointer-events:none; }
.card-h{ display:flex;align-items:center;gap:10px;margin-bottom:6px; }
.card-h .nm{ font-weight:700;font-size:14.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis; }
.st-dot{ width:9px;height:9px;border-radius:50%;flex-shrink:0; } .st-dot.up{ background:var(--ok);box-shadow:0 0 7px var(--ok); } .st-dot.down{ background:var(--crit);box-shadow:0 0 7px var(--crit);animation:blink 1.1s infinite; }
.ring-wrap{ display:flex;align-items:center;gap:14px;margin:6px 0 10px; }
.ring{ width:96px;height:96px;flex-shrink:0; }
.ring .pct{ font-size:19px;font-weight:800; } .ring .tgt{ font-size:9px;fill:#8a93a3; }
.mini{ flex:1;font-size:12px; } .mini .r{ display:flex;justify-content:space-between;padding:2px 0;color:#aeb8c4; } .mini .r b{ color:#e7ecf3; }
.bud{ margin-top:4px; } .bud .lab{ display:flex;justify-content:space-between;font-size:10.5px;color:#8a93a3;margin-bottom:3px; }
.bud .bar{ height:8px;border-radius:5px;background:rgba(255,255,255,.09);overflow:hidden; } .bud .fill{ height:100%;border-radius:5px;transition:width .6s; }
.badge{ position:absolute;top:13px;right:14px;font-size:10px;font-weight:800;padding:3px 9px;border-radius:20px; }
.badge.ok{ color:var(--ok);background:rgba(46,204,113,.14); } .badge.no{ color:var(--crit);background:rgba(231,76,60,.16); }
/* drawer */
.drawer-ov{ position:fixed;inset:0;z-index:1000;background:rgba(3,6,12,.7);backdrop-filter:blur(6px);display:none; } .drawer-ov.show{ display:block; }
.drawer{ position:fixed;top:0;right:0;height:100%;width:min(640px,96vw);background:linear-gradient(200deg,#0c1320,#0a0f1a);border-left:1px solid rgba(77,163,255,.3);box-shadow:-20px 0 60px rgba(0,0,0,.6);z-index:1001;transform:translateX(100%);transition:transform .28s;overflow:auto; }
.drawer.show{ transform:translateX(0); }
.dh{ display:flex;align-items:center;gap:12px;padding:20px 22px;border-bottom:1px solid rgba(255,255,255,.08); }
.dh .x{ margin-left:auto;cursor:pointer;color:#8a93a3;font-size:20px; } .dh .x:hover{ color:#fff; }
.db{ padding:20px 22px; }
.tl{ position:relative;height:46px;background:rgba(46,204,113,.10);border:1px solid rgba(46,204,113,.25);border-radius:9px;margin:10px 0 6px;overflow:hidden; }
.tl .out{ position:absolute;top:0;bottom:0;background:linear-gradient(180deg,#e74c3c,#a3271d);opacity:.85; } .tl .out:hover{ opacity:1; }
.tl .inc{ position:absolute;top:-3px;width:2px;height:52px; } .tl .inc i{ position:absolute;top:-11px;left:-5px;font-size:11px; }
.tlx{ display:flex;justify-content:space-between;font-size:10px;color:#667;margin-bottom:14px; }
.epi,.inc-row{ display:flex;gap:10px;font-size:12.5px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05); }
.sev{ font-weight:700; } .mono{ font-family:Consolas,monospace;color:#9fb0c4; }
.sec-t{ font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#5a6472;margin:18px 0 6px; }
.jump{ display:inline-flex;align-items:center;gap:7px;background:rgba(77,163,255,.12);border:1px solid rgba(77,163,255,.4);color:#9cc7ff;padding:6px 12px;border-radius:8px;font-size:12px;text-decoration:none;margin-right:8px; }
.jump:hover{ background:rgba(77,163,255,.22);color:#fff; }
.spin{ width:15px;height:15px;border:2px solid rgba(255,255,255,.2);border-top-color:var(--accent);border-radius:50%;display:inline-block;animation:sp .7s linear infinite;vertical-align:middle;} @keyframes sp{to{transform:rotate(360deg)}}
.empty{ text-align:center;color:#5a6472;padding:60px 20px; } .empty i{ font-size:44px;display:block;margin-bottom:12px;color:var(--accent); }
</style>
</head>
<body>
<?php include('header.php'); ?>
<div class="wrap">
  <div class="top">
    <h1><i class="fas fa-heart-pulse" style="color:var(--accent);"></i> SLA Live Center
      <span class="sub">per-node availability · error budget · outage↔incident timeline</span>
      <span class="live"><span class="d"></span> LIVE</span></h1>
    <div class="ranges" id="ranges">
      <button class="rbtn" data-r="24h" onclick="setRange('24h')">24h</button>
      <button class="rbtn on" data-r="7d" onclick="setRange('7d')">7 days</button>
      <button class="rbtn" data-r="30d" onclick="setRange('30d')">30 days</button>
    </div>
  </div>
  <div class="kpis" id="kpis"></div>
  <div id="grid"><div class="empty"><span class="spin"></span></div></div>
</div>

<div class="drawer-ov" id="dov" onclick="closeNode()"></div>
<div class="drawer" id="drawer"></div>

<script>
let RANGE='<?= $range ?>', TARGET=99.9, tmr=null;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function tsFmt(t){ return window.nmLocal?nmLocal(t,true):new Date(t*1000).toISOString().slice(0,16).replace('T',' '); }
function dur(m){ m=+m||0; if(m>=1440)return (m/1440).toFixed(1)+'d'; if(m>=60)return (m/60).toFixed(1)+'h'; return (Math.round(m*10)/10)+'m'; }
const uCol=(u,t)=> u>=t?'var(--ok)':(u>=t-0.5?'var(--warn)':'var(--crit)');

function ring(pct,target,col){
  const R=42,C=2*Math.PI*R, off=C*(1-Math.min(100,Math.max(0,pct))/100);
  return `<svg class="ring" viewBox="0 0 100 100">
    <circle cx="50" cy="50" r="${R}" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="8"/>
    <circle cx="50" cy="50" r="${R}" fill="none" stroke="${col}" stroke-width="8" stroke-linecap="round"
      stroke-dasharray="${C}" stroke-dashoffset="${off}" transform="rotate(-90 50 50)" style="transition:stroke-dashoffset .7s"/>
    <text class="pct" x="50" y="49" text-anchor="middle" dominant-baseline="middle" fill="${col}">${(+pct).toFixed(2)}%</text>
    <text class="tgt" x="50" y="64" text-anchor="middle">SLA ${target}%</text></svg>`;
}
async function load(){
  const r=await fetch('sla.php?api=live&range='+RANGE+'&_='+Date.now()).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok){ document.getElementById('grid').innerHTML='<div class="empty">Could not load SLA data.</div>'; return; }
  TARGET=r.target;
  const s=r.stats;
  document.getElementById('kpis').innerHTML=
    `<div class="kpi"><div class="n" style="color:${uCol(s.avg,TARGET)}">${s.avg}%</div><div class="l">avg uptime</div></div>
     <div class="kpi"><div class="n" style="color:var(--ok)">${s.up}</div><div class="l">up now</div></div>
     <div class="kpi"><div class="n" style="color:${s.down?'var(--crit)':'var(--ok)'}">${s.down}</div><div class="l">down now</div></div>
     <div class="kpi"><div class="n" style="color:${s.breaching?'var(--crit)':'var(--ok)'}">${s.breaching}</div><div class="l">breaching SLA</div></div>
     <div class="kpi"><div class="n" style="color:${s.budget_burn>100?'var(--crit)':(s.budget_burn>70?'var(--warn)':'var(--ok)')}">${s.budget_burn}%</div><div class="l">error budget burned</div></div>
     <div class="kpi"><div class="n" style="font-size:15px;color:var(--warn)">${s.worst?esc(s.worst.name):'—'}</div><div class="l">worst node ${s.worst?('· '+s.worst.uptime+'%'):''}</div></div>`;
  const g=r.nodes||[];
  if(!g.length){ document.getElementById('grid').innerHTML='<div class="empty"><i class="fas fa-heart-pulse"></i>No SLA data yet — availability builds from ping/SNMP history.</div>'; return; }
  document.getElementById('grid').innerHTML='<div class="grid">'+g.map(cardHTML).join('')+'</div>';
}
function cardHTML(n){
  const col=uCol(n.uptime,TARGET), b=n.budget;
  const burn=Math.min(100,b.burn_pct), bcol=b.exhausted?'var(--crit)':(b.burn_pct>70?'var(--warn)':'var(--ok)');
  return `<div class="card ${n.meets?'':'breach'}" onclick="openNode(${n.id})">
    <span class="badge ${n.meets?'ok':'no'}">${n.meets?'MEETS':'BREACH'}</span>
    <div class="card-h"><span class="st-dot ${n.last}"></span><span class="nm">${esc(n.display_name)}</span></div>
    <div class="ring-wrap">${ring(n.uptime,TARGET,col)}
      <div class="mini">
        <div class="r"><span>Downtime</span><b>${dur(b.consumed_min)}</b></div>
        <div class="r"><span>Outages</span><b>${n.outages}</b></div>
        <div class="r"><span>State</span><b style="color:${n.last==='up'?'var(--ok)':'var(--crit)'}">${n.last.toUpperCase()}</b></div>
      </div></div>
    <div class="bud"><div class="lab"><span>Error budget</span><span style="color:${bcol}">${b.exhausted?('over by '+dur(-b.remaining_min)):(dur(b.remaining_min)+' left')}</span></div>
      <div class="bar"><div class="fill" style="width:${burn}%;background:${bcol}"></div></div></div>
  </div>`;
}
async function openNode(id){
  document.getElementById('dov').classList.add('show'); document.getElementById('drawer').classList.add('show');
  document.getElementById('drawer').innerHTML='<div class="db" style="padding-top:60px;text-align:center;"><span class="spin"></span> loading…</div>';
  const r=await fetch('sla.php?api=node&node='+id+'&range='+RANGE+'&_='+Date.now()).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok){ document.getElementById('drawer').innerHTML='<div class="db">Could not load node.</div>'; return; }
  const n=r.node, a=r.sla, b=r.budget, col=uCol(a.uptime||0,r.target), w=r.window;
  const span=(w.to-w.from)||1;
  // timeline: outages (red) + incident markers over the window
  const outs=(r.episodes||[]).map(e=>{ const l=Math.max(0,(e.start-w.from)/span*100), wd=Math.max(0.6,(e.end-e.start)/span*100);
    return `<div class="out" style="left:${l}%;width:${Math.min(100-l,wd)}%" title="${esc(tsFmt(e.start))} → ${esc(tsFmt(e.end))} · ${dur(e.dur)}${e.ongoing?' (ongoing)':''}"></div>`;}).join('');
  const sevCol={critical:'#e74c3c',warning:'#f39c12',info:'#4da3ff'};
  const incMarks=(r.incidents||[]).map(x=>{ const l=Math.max(0,Math.min(100,(x.opened-w.from)/span*100));
    return `<div class="inc" style="left:${l}%;background:${sevCol[x.severity]||'#889'}"><i class="fas fa-bolt" style="color:${sevCol[x.severity]||'#889'}" title="${esc(x.title)}"></i></div>`;}).join('');
  document.getElementById('drawer').innerHTML=`
    <div class="dh">${ring(a.uptime||0,r.target,col)}
      <div><div style="font-size:18px;font-weight:700;">${esc(n.display_name)}</div>
        <div class="mono" style="font-size:12px;">${esc(n.ip_address||'')} · ${esc(n.monitor_type||'')}</div>
        <div style="margin-top:4px;"><span class="badge ${r.meets?'ok':'no'}" style="position:static;">${r.meets?'MEETS SLA':'BREACHING SLA'}</span></div></div>
      <i class="fas fa-xmark x" onclick="closeNode()"></i></div>
    <div class="db">
      <div class="kpis" style="grid-template-columns:repeat(4,1fr);">
        <div class="kpi"><div class="n" style="font-size:19px;color:${col}">${(a.uptime||0)}%</div><div class="l">uptime</div></div>
        <div class="kpi"><div class="n" style="font-size:19px;">${dur(b.consumed_min)}</div><div class="l">downtime</div></div>
        <div class="kpi"><div class="n" style="font-size:19px;">${a.outages||0}</div><div class="l">outages</div></div>
        <div class="kpi"><div class="n" style="font-size:19px;color:${r.err_logs?'var(--warn)':'var(--ok)'}">${r.err_logs}</div><div class="l">error logs</div></div>
      </div>
      <div class="sec-t">Error budget (${r.target}% over ${RANGE})</div>
      <div class="bud"><div class="lab"><span>${dur(b.consumed_min)} used of ${dur(b.allowed_min)}</span>
        <span style="color:${b.exhausted?'var(--crit)':(b.burn_pct>70?'var(--warn)':'var(--ok)')}">${b.exhausted?('exhausted — over by '+dur(-b.remaining_min)):(dur(b.remaining_min)+' remaining · '+b.burn_pct+'% burned')}</span></div>
        <div class="bar" style="height:11px;"><div class="fill" style="width:${Math.min(100,b.burn_pct)}%;background:${b.exhausted?'var(--crit)':(b.burn_pct>70?'var(--warn)':'var(--ok)')}"></div></div></div>
      <div class="sec-t">Availability timeline — <span style="color:var(--crit);">outages</span> &amp; <span style="color:var(--accent);">incidents</span></div>
      <div class="tl">${outs}${incMarks}</div>
      <div class="tlx"><span>${esc(tsFmt(w.from))}</span><span>now</span></div>
      <div style="margin:10px 0 4px;">
        <a class="jump" href="troubleshoot.php?node=${n.id}"><i class="fas fa-stethoscope"></i> Troubleshoot</a>
        <a class="jump" href="timetravel.php"><i class="fas fa-clock-rotate-left"></i> Time-Travel</a>
        <a class="jump" href="incidents.php"><i class="fas fa-triangle-exclamation"></i> Incidents</a></div>
      ${(r.incidents&&r.incidents.length)?`<div class="sec-t">Incidents in window (${r.incidents.length})</div>`+r.incidents.map(x=>`
        <div class="inc-row"><span class="sev" style="color:${sevCol[x.severity]||'#889'};min-width:60px;">${esc(x.severity)}</span>
          <span style="flex:1;">${esc(x.title)}</span><span class="mono" style="white-space:nowrap;">${esc(tsFmt(x.opened))}</span></div>`).join(''):'<div class="sec-t">Incidents in window</div><div style="color:#5a6472;font-size:12.5px;">None — clean window.</div>'}
      ${(r.episodes&&r.episodes.length)?`<div class="sec-t">Outage episodes (${r.episodes.length})</div>`+r.episodes.slice(0,20).map(e=>`
        <div class="epi"><span class="mono" style="flex:1;">${esc(tsFmt(e.start))} → ${e.ongoing?'<b style="color:var(--crit)">ongoing</b>':esc(tsFmt(e.end))}</span><b>${dur(e.dur)}</b></div>`).join(''):''}
    </div>`;
}
function closeNode(){ document.getElementById('dov').classList.remove('show'); document.getElementById('drawer').classList.remove('show'); }
document.addEventListener('keydown',e=>{ if(e.key==='Escape') closeNode(); });
function setRange(r){ RANGE=r; document.querySelectorAll('#ranges .rbtn').forEach(b=>b.classList.toggle('on',b.dataset.r===r)); load(); }
function tick(){ if(!document.hidden) load(); }
load(); tmr=setInterval(tick,15000);
</script>
</body>
</html>
