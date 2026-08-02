<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Incident Command. Shows correlated incidents (root cause + impact +
// signal timeline) from nm_incidents.php. Gated by permission key 'incidents'.
// ─────────────────────────────────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) session_start();
include_once __DIR__ . '/connection.php';
require_once __DIR__ . '/access_control.php';
require_once __DIR__ . '/nm_incidents.php';
require_once __DIR__ . '/nm_chrome.php';

if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$CSRF = $_SESSION['csrf_token'];

if (isset($_GET['api']) || isset($_POST['api'])) {
    header('Content-Type: application/json');
    if (empty($_SESSION['username']) || !checkAccess($conn, 'incidents')) {
        http_response_code(403); echo json_encode(['ok'=>false,'err'=>'Unauthorized']); exit;
    }
    $api = $_GET['api'] ?? $_POST['api'];
    $isPost = ($_SERVER['REQUEST_METHOD'] === 'POST');
    if ($isPost && (($_POST['csrf'] ?? '') !== $_SESSION['csrf_token'])) {
        http_response_code(400); echo json_encode(['ok'=>false,'err'=>'Invalid CSRF']); exit;
    }
    try {
        switch ($api) {
        case 'list': {
            $rows = nm_inc_list($conn, $_GET['status'] ?? 'active', 200);
            $crit = 0; $warn = 0; $active = 0;
            foreach ($rows as $r) { if (in_array($r['status'],['open','acknowledged'],true)) { $active++;
                if ($r['severity']==='critical') $crit++; elseif ($r['severity']==='warning') $warn++; } }
            echo json_encode(['ok'=>true,'incidents'=>$rows,'stats'=>['critical'=>$crit,'warning'=>$warn,'active'=>$active]]);
            break;
        }
        case 'get':
            $inc = nm_inc_get($conn, (int)($_GET['id'] ?? 0));
            echo json_encode($inc ? ['ok'=>true,'incident'=>$inc] : ['ok'=>false,'err'=>'Not found']);
            break;
        case 'set_status':
            if (!$isPost) { echo json_encode(['ok'=>false,'err'=>'POST only']); break; }
            nm_inc_set_status($conn, (int)($_POST['id'] ?? 0), $_POST['status'] ?? '', $_SESSION['username'] ?? '');
            echo json_encode(['ok'=>true]);
            break;
        case 'accept_schema': {
            // "I made this schema change — it's expected." Approve the drift events at the SOURCE so
            // they stop raising signals, then resolve the incident (it won't reopen once signals are gone).
            if (!$isPost) { echo json_encode(['ok'=>false,'err'=>'POST only']); break; }
            require_once __DIR__ . '/nm_dbmon.php';
            $iid = (int)($_POST['id'] ?? 0); $by = $_SESSION['username'] ?? '';
            $tids = []; $sr = $conn->query("SELECT fingerprint FROM nm_incident_signals WHERE incident_id=$iid");
            while ($sr && $x = $sr->fetch_assoc()) if (preg_match('#^db:(\d+):drift:#', (string)$x['fingerprint'], $m)) $tids[(int)$m[1]] = 1;
            $n = 0; foreach (array_keys($tids) as $tid) $n += nm_db_schema_accept($conn, $tid, $by);
            if ($iid) nm_inc_set_status($conn, $iid, 'resolved', $by);
            echo json_encode(['ok'=>true,'accepted'=>$n,'targets'=>count($tids)]);
            break;
        }
        case 'run':
            echo json_encode(['ok'=>true] + nm_inc_correlate($conn));
            break;
        default:
            http_response_code(400); echo json_encode(['ok'=>false,'err'=>'Unknown']);
        }
    } catch (\Throwable $e) { http_response_code(500); echo json_encode(['ok'=>false,'err'=>$e->getMessage()]); }
    exit;
}

include('check.php');
if (!checkAccess($conn, 'incidents')) { header('Location: /denied_access.php?page=incidents'); exit; }
include('header.php');
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incidents | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
<?= nm_chrome_css() ?>
:root{--glass:rgba(255,255,255,0.07);--border:rgba(255,255,255,0.13);--accent:#4da3ff;--up:#2ecc71;--down:#e74c3c;--warn:#f39c12;--mut:#8a909a;}
body{margin:0;font-family:'Segoe UI',Tahoma,sans-serif;background:#000;color:#fff;overflow-x:hidden;}
.wrap{max-width:1500px;margin:0 auto;padding:18px 22px 60px;}
.glass-card{background:var(--glass);backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:16px;padding:18px 20px;margin-bottom:18px;}
.bento{display:grid;grid-template-columns:repeat(4,1fr);gap:13px;margin-bottom:18px;}
@media(max-width:800px){.bento{grid-template-columns:repeat(2,1fr);}}
.kpi{background:var(--glass);border:1px solid var(--border);border-radius:14px;padding:15px 18px;}
.kpi .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--mut);}
.kpi .val{font-size:30px;font-weight:800;margin-top:3px;}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px;}
.seg{display:inline-flex;border:1px solid var(--border);border-radius:9px;overflow:hidden;}
.seg button{background:transparent;border:none;color:var(--mut);padding:7px 14px;font-size:12px;font-weight:700;cursor:pointer;}
.seg button.on{background:var(--accent);color:#000;}
.btn{padding:7px 13px;border-radius:8px;border:1px solid var(--border);background:rgba(255,255,255,.05);color:#cfd3da;font-size:12px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:7px;text-decoration:none;}
.btn:hover{border-color:var(--accent);color:#fff;}
.btn-ok{background:rgba(46,204,113,.15);border-color:var(--up);color:var(--up);} .btn-ok:hover{background:var(--up);color:#000;}
.btn-sm{padding:5px 10px;font-size:11px;}
.inc{border:1px solid var(--border);border-left-width:4px;border-radius:14px;margin-bottom:12px;background:rgba(255,255,255,.025);overflow:hidden;}
.inc.crit{border-left-color:var(--down);} .inc.warn{border-left-color:var(--warn);} .inc.info{border-left-color:var(--accent);}
.inc.ackd{opacity:.78;} .inc.resolved{opacity:.5;}
.inc-head{display:flex;align-items:center;gap:14px;padding:13px 16px;cursor:pointer;}
.sev-badge{font-size:10px;font-weight:800;text-transform:uppercase;padding:3px 9px;border-radius:6px;white-space:nowrap;}
.sev-badge.crit{background:rgba(231,76,60,.2);color:#ff6b6b;} .sev-badge.warn{background:rgba(243,156,18,.2);color:#f5b73d;} .sev-badge.info{background:rgba(77,163,255,.2);color:#7fc0ff;}
.inc-title{font-weight:700;font-size:14.5px;}
.inc-meta{font-size:11.5px;color:var(--mut);margin-top:2px;display:flex;gap:12px;flex-wrap:wrap;}
.rootcause{background:rgba(231,76,60,.12);border:1px solid rgba(231,76,60,.3);color:#ff9b8f;border-radius:7px;padding:2px 9px;font-size:11px;font-weight:600;}
.src-badge{font-size:9.5px;font-weight:700;text-transform:uppercase;padding:1px 7px;border-radius:5px;letter-spacing:.4px;}
.s-node_down{background:rgba(231,76,60,.2);color:#ff6b6b;} .s-config{background:rgba(243,156,18,.18);color:#f5b73d;}
.s-latency{background:rgba(77,163,255,.18);color:#7fc0ff;} .s-container{background:rgba(13,183,237,.18);color:#56c7ed;}
.s-netflow{background:rgba(155,89,182,.18);color:#c49be0;} .s-container_net{background:rgba(13,183,237,.14);color:#56c7ed;} .s-ai{background:rgba(155,89,182,.16);color:#c49be0;}
.status-pill2{font-size:10px;font-weight:700;padding:2px 9px;border-radius:6px;text-transform:uppercase;}
.st-open{background:rgba(231,76,60,.15);color:#ff8a7d;} .st-acknowledged{background:rgba(243,156,18,.15);color:#f5b73d;} .st-resolved{background:rgba(46,204,113,.15);color:#2ecc71;}
.st-muted{background:rgba(138,144,154,.18);color:#aab2bc;}
.inc.muted{opacity:.55;} .inc.muted .inc-title::after{content:' · IGNORED';color:#8a909a;font-weight:600;font-size:11px;}
.btn-mute:hover{border-color:#8a909a;color:#cfd3da;background:rgba(138,144,154,.12);}
.inc-body{padding:0 16px 14px 16px;display:none;}
.inc.expanded .inc-body{display:block;}
.signal{display:flex;align-items:flex-start;gap:11px;padding:9px 0;border-top:1px solid rgba(255,255,255,.06);font-size:12.5px;}
.signal.cleared{opacity:.45;}
.signal a.s-link{color:var(--accent);text-decoration:none;font-size:11px;white-space:nowrap;}
.mut{color:var(--mut);} .mono{font-family:ui-monospace,monospace;}
.empty{text-align:center;color:var(--mut);padding:40px;}
#toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(120%);background:#11151d;border:1px solid var(--border);border-left:4px solid var(--accent);border-radius:10px;padding:12px 18px;font-size:13px;z-index:2000;transition:.3s;}
#toast.show{transform:translateX(-50%) translateY(0);}
</style>
</head>
<body>
<div class="wrap">
<?php nm_page_header('Incident', 'Command', 'Correlated Operations', 'fa-solid fa-triangle-exclamation'); ?>

<div class="bento">
  <div class="kpi"><div class="lbl">Critical</div><div class="val" style="color:var(--down)" id="k-crit">—</div></div>
  <div class="kpi"><div class="lbl">Warning</div><div class="val" style="color:var(--warn)" id="k-warn">—</div></div>
  <div class="kpi"><div class="lbl">Active Incidents</div><div class="val" id="k-active">—</div></div>
  <div class="kpi"><div class="lbl">Signals Correlated</div><div class="val" style="color:var(--accent)" id="k-sig">—</div></div>
</div>

<div class="toolbar">
  <div class="seg" id="status-seg">
    <button data-s="active" class="on">Active</button>
    <button data-s="resolved">Resolved</button>
    <button data-s="muted">Ignored</button>
    <button data-s="all">All</button>
  </div>
  <span class="mut" style="font-size:11.5px;">Alerts from every module, correlated into incidents with a probable root cause &amp; impact.</span>
  <a class="btn btn-sm" style="margin-left:auto;" href="notify_admin.php"><i class="fa-solid fa-bell"></i> Notifications &amp; Escalation</a>
  <button class="btn btn-sm" onclick="runNow()"><i class="fa-solid fa-bolt"></i> Re-correlate now</button>
</div>

<div id="inc-list"><div class="empty">Loading…</div></div>
</div>

<div id="toast"></div>
<script>
const CSRF=<?= json_encode($CSRF) ?>;
let STATUS='active', _open={};
function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2400);}
const sevCls=s=>({critical:'crit',warning:'warn',info:'info'}[s]||'info');
function ago(ts){ if(!ts) return ''; const d=(Date.now()-new Date(ts.replace(' ','T')+'Z').getTime())/1000;  /* ts is UTC */
  if(d<60)return Math.round(d)+'s'; if(d<3600)return Math.round(d/60)+'m'; if(d<86400)return Math.round(d/3600)+'h'; return Math.round(d/86400)+'d'; }

async function load(){
  let d; try{ d=await fetch('incidents.php?api=list&status='+STATUS).then(r=>r.json()); }catch(e){ return; }
  if(!d.ok) return;
  document.getElementById('k-crit').textContent=d.stats.critical;
  document.getElementById('k-warn').textContent=d.stats.warning;
  document.getElementById('k-active').textContent=d.stats.active;
  document.getElementById('k-sig').textContent=d.incidents.reduce((a,i)=>a+(+i.signal_count||0),0);
  const box=document.getElementById('inc-list');
  if(!d.incidents.length){ box.innerHTML='<div class="empty"><i class="fa-solid fa-circle-check" style="font-size:30px;color:var(--up);display:block;margin-bottom:10px;"></i>No incidents — all clear.</div>'; return; }
  box.innerHTML=d.incidents.map(i=>{
    const sc=sevCls(i.severity), exp=_open[i.id]?'expanded':'';
    const ackd=i.status==='acknowledged'?'ackd':(i.status==='resolved'?'resolved':(i.status==='muted'?'muted':''));
    const impact=i.impact && i.impact_count>1 ? `<span><i class="fa-solid fa-bullseye"></i> impact: ${esc(i.impact)}</span>`:'';
    return `<div class="inc ${sc} ${ackd}" data-id="${i.id}">
      <div class="inc-head" onclick="toggle(${i.id})">
        <span class="sev-badge ${sc}">${esc(i.severity)}</span>
        <div style="flex:1;min-width:0;">
          <div class="inc-title">${esc(i.title)}</div>
          <div class="inc-meta">
            ${i.root_source?`<span class="rootcause">root: ${esc(i.root_source)}${i.root_entity?(' · '+esc(i.root_entity)):''}</span>`:''}
            ${i.root_host?`<span class="rootcause" style="background:rgba(240,169,44,.16);color:#f0c674;"><i class="fa-solid fa-server"></i> ${esc(i.root_host)}</span>`:''}
            <span><i class="fa-solid fa-wave-square"></i> ${i.signal_count} signal${i.signal_count!=1?'s':''}</span>
            ${impact}
            <span title="Opened ${esc(i.opened_at||'')} · last activity ${esc(i.last_activity||i.updated_at||'')} (UTC)"><i class="fa-regular fa-clock"></i> ${i.last_activity?('last seen '+ago(i.last_activity)+' · '):''}${ago(i.opened_at)} old</span>
          </div>
        </div>
        <span class="status-pill2 st-${esc(i.status)}">${esc(i.status)}</span>
        <div onclick="event.stopPropagation();" style="display:flex;gap:6px;">
          ${i.status==='muted'
            ? `<button class="btn btn-sm" onclick="setSt(${i.id},'open')" title="Stop ignoring — show new occurrences again"><i class="fa-solid fa-bell"></i> Un-ignore</button>`
            : `${+i.schema_drift>0?`<button class="btn btn-sm btn-ok" onclick="acceptSchema(${i.id})" title="I made this schema change — accept it as the new baseline so it stops alerting"><i class="fa-solid fa-clipboard-check"></i> Accept schema</button>`:''}
               ${i.status!=='acknowledged'&&i.status!=='resolved'?`<button class="btn btn-sm" onclick="setSt(${i.id},'acknowledged')" title="Acknowledge — I'm on it"><i class="fa-solid fa-eye"></i></button>`:''}
               ${i.status!=='resolved'?`<button class="btn btn-sm btn-ok" onclick="setSt(${i.id},'resolved')" title="Resolve"><i class="fa-solid fa-check"></i></button>`:`<button class="btn btn-sm" onclick="setSt(${i.id},'open')" title="Reopen"><i class="fa-solid fa-rotate-left"></i></button>`}
               <button class="btn btn-sm btn-mute" onclick="setSt(${i.id},'muted')" title="Ignore this recurring incident — only NEW ones will surface"><i class="fa-solid fa-bell-slash"></i></button>`}
        </div>
      </div>
      <div class="inc-body" id="body-${i.id}"><div class="mut" style="padding:8px 0;">Loading signals…</div></div>
    </div>`;
  }).join('');
  Object.keys(_open).forEach(id=>{ if(_open[id]) loadSignals(+id); });
}
async function toggle(id){
  _open[id]=!_open[id];
  const el=document.querySelector('.inc[data-id="'+id+'"]'); if(el) el.classList.toggle('expanded',_open[id]);
  if(_open[id]) loadSignals(id);
}
async function loadSignals(id){
  const d=await fetch('incidents.php?api=get&id='+id).then(r=>r.json()).catch(()=>({ok:false}));
  const body=document.getElementById('body-'+id); if(!body||!d.ok) return;
  const sigs=d.incident.signals||[];
  body.innerHTML='<div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--mut);margin:6px 0;">Correlated signals (timeline)</div>'+
    sigs.map(s=>`<div class="signal ${s.status==='cleared'?'cleared':''}">
      <span class="src-badge s-${esc(s.source)}">${esc(s.source.replace('_',' '))}</span>
      <div style="flex:1;min-width:0;">
        <div>${esc(s.title)}</div>
        <div class="mut" style="font-size:10.5px;margin-top:2px;">first ${esc((window.nmLocal?nmLocal(s.first_seen):(s.first_seen||'')).slice(5,16))} · last ${esc((window.nmLocal?nmLocal(s.last_seen):(s.last_seen||'')).slice(5,16))}${s.status==='cleared'?' · CLEARED':''}</div>
      </div>
      ${s.link?`<a class="s-link" href="${esc(s.link)}"><i class="fa-solid fa-arrow-up-right-from-square"></i> view</a>`:''}
    </div>`).join('') || '<div class="mut">No signals.</div>';
}
async function setSt(id,status){
  const fd=new FormData(); fd.append('api','set_status'); fd.append('csrf',CSRF); fd.append('id',id); fd.append('status',status);
  await fetch('incidents.php?api=set_status',{method:'POST',body:fd});
  toast(status==='resolved'?'Resolved':status==='acknowledged'?'Acknowledged':status==='muted'?'Ignored — recurrences hidden until un-ignored':'Reopened'); load();
}
async function acceptSchema(id){
  if(!confirm('Accept the current schema as the expected baseline?\n\nThis marks the detected schema change as approved (you made it on purpose) so it stops raising this incident. NEURU keeps watching for FUTURE changes.')) return;
  const fd=new FormData(); fd.append('api','accept_schema'); fd.append('csrf',CSRF); fd.append('id',id);
  const r=await fetch('incidents.php?api=accept_schema',{method:'POST',body:fd}).then(r=>r.json()).catch(()=>({ok:false}));
  toast(r.ok?('Schema accepted — '+(r.accepted||0)+' change event(s) approved. It won’t alert again.'):'Could not accept schema'); load();
}
async function runNow(){ toast('Correlating…'); await fetch('incidents.php?api=run').then(r=>r.json()).catch(()=>{}); load(); }
document.querySelectorAll('#status-seg button').forEach(b=>b.addEventListener('click',()=>{
  document.querySelectorAll('#status-seg button').forEach(x=>x.classList.remove('on')); b.classList.add('on'); STATUS=b.dataset.s; load();
}));
load();
setInterval(()=>{ if(!document.hidden) load(); }, 15000);
document.addEventListener('visibilitychange',()=>{ if(!document.hidden) load(); });
</script>
</body></html>
