<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — L2 Switch Ports. Monitors TP-Link "Easy Smart" switches that have no
// SNMP / no syslog by scraping their web UI. RBAC: 'l2switch'. Engine: nm_tplink.php
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_tplink.php');
include('logger.php');

$api = $_GET['api'] ?? '';
$act = $_POST['action'] ?? '';
if (!checkAccess($conn, 'l2switch')) {
    if ($api || $act) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=l2switch'); exit;
}
nm_tp_ensure($conn);

// ── write actions ─────────────────────────────────────────────────────────────
if ($act !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if ($act === 'save') {
        $r = nm_tp_switch_save($conn, $_POST);
        log_user_action($conn,'l2switch_save','switch '.($_POST['host'] ?? ''));
        echo json_encode($r); exit;
    }
    if ($act === 'delete') {
        nm_tp_switch_delete($conn, (int)($_POST['id'] ?? 0));
        log_user_action($conn,'l2switch_delete','id '.($_POST['id'] ?? ''));
        echo json_encode(['ok'=>true]); exit;
    }
    if ($act === 'test') {
        $pw = (string)($_POST['password'] ?? '');
        if ($pw === '' && !empty($_POST['id'])) { $s = nm_tp_switch_get($conn,(int)$_POST['id']); $pw = $s ? nm_secret_decrypt($s['pass_enc']) : ''; }
        $res = nm_tp_fetch(trim((string)($_POST['host']??'')), (int)($_POST['port']??80), trim((string)($_POST['username']??'admin')), $pw);
        echo json_encode($res['ok'] ? ['ok'=>true,'ports'=>count($res['ports'])] : ['ok'=>false,'error'=>$res['error']]); exit;
    }
    if ($act === 'ack') {
        nm_tp_event_ack($conn, (int)($_POST['sw'] ?? 0), (int)($_POST['id'] ?? 0));
        echo json_encode(['ok'=>true]); exit;
    }
    if ($act === 'poll') {
        $sw = nm_tp_switch_get($conn, (int)($_POST['sw'] ?? 0));
        echo json_encode($sw ? nm_tp_poll_one($conn,$sw) : ['ok'=>false,'error'=>'no switch']); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'unknown action']); exit;
}

// ── read API ──────────────────────────────────────────────────────────────────
if ($api === 'spark') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok'=>true,'points'=>nm_tp_spark($conn,(int)($_GET['sw']??0),(int)($_GET['port']??0),180)]); exit;
}
if ($api === 'data') {
    header('Content-Type: application/json; charset=utf-8');
    $switches = nm_tp_switches($conn);
    $sid = (int)($_GET['sw'] ?? 0);
    if (!$sid && $switches) $sid = (int)$switches[0]['id'];
    $sel = $sid ? nm_tp_switch_get($conn, $sid) : null;

    // auto-poll if the selected switch is stale (>90s) — keeps the view live
    // even between cron ticks, without hammering the switch.
    $polled = null;
    if ($sel && (int)$sel['enabled']) {
        $stale = empty($sel['last_poll']) || (strtotime($sel['last_poll']) < time() - 90);
        if ($stale) { $polled = nm_tp_poll_one($conn, $sel); $sel = nm_tp_switch_get($conn, $sid); }
    }
    $ports = $sid ? nm_tp_ports_view($conn, $sid) : [];
    $up = 0; $down = 0; $err = 0;
    foreach ($ports as $p) { if ($p['enabled']) { $p['link_code'] ? $up++ : $down++; } if ($p['tx_err_pps']+$p['rx_err_pps']>0) $err++; }
    $swout = array_map(fn($s)=>[
        'id'=>(int)$s['id'],'name'=>$s['name'],'host'=>$s['host'],'port'=>(int)$s['port'],
        'username'=>$s['username'],'model'=>$s['model'],'enabled'=>(int)$s['enabled'],
        'err_threshold_pps'=>(float)$s['err_threshold_pps'],
        'last_status'=>$s['last_status'],'last_error'=>$s['last_error'],
        'last_poll'=>$s['last_poll'] ? nm_local($s['last_poll']) : null,
    ], $switches);
    echo json_encode(['ok'=>true,'switches'=>$swout,'sel'=>$sid,'ports'=>$ports,
        'up'=>$up,'down'=>$down,'err_ports'=>$err,
        'status'=>$sel['last_status']??'','last_error'=>$sel['last_error']??'',
        'last_poll'=>($sel && $sel['last_poll'])?nm_local($sel['last_poll']):null,
        'events'=>$sid?nm_tp_events($conn,$sid,40):[], 'polled'=>$polled]); exit;
}

log_user_action($conn,'view_page','l2switch.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Unmanaged Switches | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.18; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 40px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.bar{ display:flex; flex-wrap:wrap; gap:12px; align-items:center; margin-bottom:16px; }
.bar select,.bar input,.bar button{ font-family:inherit; }
select.sw{ background:rgba(255,255,255,.06); color:#e6e9ee; border:1px solid var(--border); border-radius:9px; padding:8px 12px; font-size:13px; }
.kpis{ display:flex; gap:12px; flex-wrap:wrap; margin-left:auto; }
.kpi{ padding:8px 16px; text-align:center; border-radius:11px; } .kpi .n{ font-size:22px; font-weight:800; line-height:1; } .kpi .l{ font-size:10px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; margin-top:3px;}
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:8px 14px; font-size:13px; cursor:pointer; }
.btn:hover{ background:rgba(77,163,255,.25); } .btn.ghost{ background:transparent; border-color:var(--border); color:#aab; }
table.ports{ width:100%; border-collapse:collapse; font-size:13px; }
table.ports th{ text-align:left; font-size:10.5px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; padding:8px 10px; border-bottom:1px solid var(--border); }
table.ports td{ padding:9px 10px; border-bottom:1px solid rgba(255,255,255,.05); vertical-align:middle; }
table.ports tr.down td{ opacity:.5; } table.ports tr.dis td{ opacity:.32; }
.dot{ display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:7px; vertical-align:middle; }
.pill{ display:inline-block; font-size:11px; font-weight:700; padding:2px 9px; border-radius:20px; }
.pill.up{ background:rgba(46,204,113,.14); color:#7fe0a3; } .pill.down{ background:rgba(231,76,60,.14); color:#f0a59d; }
.pill.dis{ background:rgba(255,255,255,.06); color:#8a909a; }
.spd{ font-size:11px; color:#9aa; } .num{ font-variant-numeric:tabular-nums; } .err{ color:#f0a59d; font-weight:700; } .zero{ color:#5b626c; }
.spark{ vertical-align:middle; }
.events .ev{ display:flex; gap:10px; align-items:flex-start; padding:9px 4px; border-bottom:1px solid rgba(255,255,255,.05); font-size:12.5px; }
.events .ev .i{ width:20px; text-align:center; } .events .ev .d{ flex:1; } .events .ev .t{ color:#7c828c; font-size:11px; }
.sev-crit{ color:#f0a59d; } .sev-warn{ color:#f0c674; } .sev-info{ color:#9fbfe0; }
.muted{ color:#7c828c; font-size:12px; }
.cols{ display:grid; grid-template-columns:1fr 360px; gap:16px; } @media(max-width:980px){ .cols{ grid-template-columns:1fr; } }
.modal-bg{ position:fixed; inset:0; background:rgba(0,0,0,.6); z-index:90; display:none; align-items:flex-start; justify-content:center; padding-top:6vh; }
.modal{ width:460px; max-width:94vw; padding:20px 22px; } .modal h3{ margin:0 0 14px; font-size:15px; }
.modal label{ display:block; font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; margin:11px 0 4px; }
.modal input{ width:100%; background:rgba(255,255,255,.06); color:#e6e9ee; border:1px solid var(--border); border-radius:8px; padding:9px 11px; font-size:13px; }
.modal .row{ display:flex; gap:10px; } .modal .row>div{ flex:1; }
.modal .actions{ display:flex; gap:10px; justify-content:flex-end; margin-top:18px; align-items:center; }
.note{ font-size:11.5px; color:#8a909a; margin-top:6px; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-ethernet"></i>Unmanaged Switches', '', 'L2 · Easy Smart', 'fa-solid fa-ethernet',
    '<button class="refresh-btn" onclick="load(true)"><i class="fas fa-rotate"></i> Poll now</button>'); ?>

<div class="bar">
  <select class="sw" id="swsel" onchange="selSwitch(this.value)"></select>
  <button class="btn ghost" onclick="openForm(0)"><i class="fas fa-plus"></i> Add switch</button>
  <button class="btn ghost" id="editbtn" onclick="openForm(sel)" style="display:none;"><i class="fas fa-pen"></i> Edit</button>
  <span class="muted" id="pollinfo"></span>
  <div class="kpis">
    <div class="glass kpi"><div class="n" id="k-up" style="color:var(--ok)">—</div><div class="l">Links up</div></div>
    <div class="glass kpi"><div class="n" id="k-down" style="color:#9aa">—</div><div class="l">Down</div></div>
    <div class="glass kpi"><div class="n" id="k-err" style="color:var(--crit)">—</div><div class="l">Err ports</div></div>
  </div>
</div>

<div class="glass card" style="padding:11px 16px;" id="banner">
  <div class="muted"><i class="fas fa-circle-info"></i> Easy Smart switches expose <b style="color:#cfd3da">packet counters</b>, not bytes — so rates are shown as <b>packets/sec</b> (pps), not Mbps. NEURU also flags <b>link flaps</b> and rising <b>bad-packet</b> counts (cabling/duplex faults).</div>
</div>

<div class="cols">
  <div class="glass card">
    <table class="ports"><thead><tr>
      <th>Port</th><th>Status</th><th>Link</th><th>Tx pps</th><th>Rx pps</th><th>Errors</th><th>Trend (tx/rx)</th><th>Total pkts (tx/rx)</th>
    </tr></thead><tbody id="ports"><tr><td colspan="8" class="muted">Loading…</td></tr></tbody></table>
  </div>
  <div class="glass card events">
    <h3 style="margin:0 0 6px; font-size:12px; color:var(--accent); text-transform:uppercase; letter-spacing:1px;">Events
      <button class="btn ghost" style="float:right; padding:3px 9px; font-size:11px;" onclick="ackAll()">Ack all</button></h3>
    <div id="events"><div class="muted">—</div></div>
  </div>
</div>
</div>

<!-- add/edit switch modal -->
<div class="modal-bg" id="formbg">
  <div class="glass modal">
    <h3 id="formtitle">Add switch</h3>
    <input type="hidden" id="f_id">
    <label>Name</label><input id="f_name" placeholder="Core Switch">
    <div class="row">
      <div><label>Host / IP</label><input id="f_host" placeholder="192.168.0.252"></div>
      <div style="max-width:90px;"><label>Port</label><input id="f_port" value="80"></div>
    </div>
    <div class="row">
      <div><label>Username</label><input id="f_user" value="admin"></div>
      <div><label>Model (optional)</label><input id="f_model" placeholder="TL-SG108E"></div>
    </div>
    <label>Password <span style="text-transform:none;color:#6b7280;" id="pwhint"></span></label><input id="f_pass" type="password" placeholder="••••••••">
    <div class="row">
      <div><label>Bad-pkt alert threshold (pps)</label><input id="f_thr" value="1"></div>
      <div><label>Enabled</label><select id="f_en" class="sw" style="width:100%;"><option value="1">Yes</option><option value="0">No</option></select></div>
    </div>
    <p class="note">Password is stored encrypted (AES-256-GCM) at rest. Leave blank when editing to keep the current one.</p>
    <div class="actions">
      <span class="muted" id="formmsg" style="margin-right:auto;"></span>
      <button class="btn ghost" id="delbtn" onclick="delSwitch()" style="display:none;color:#f0a59d;border-color:rgba(231,76,60,.4);">Delete</button>
      <button class="btn ghost" onclick="testForm()">Test</button>
      <button class="btn ghost" onclick="closeForm()">Cancel</button>
      <button class="btn" onclick="saveForm()">Save</button>
    </div>
  </div>
</div>

<script>
let sel = 0, switches = [];
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function fmtN(n){ n=+n||0; return n>=1e9?(n/1e9).toFixed(2)+'G':n>=1e6?(n/1e6).toFixed(2)+'M':n>=1e3?(n/1e3).toFixed(1)+'k':n.toFixed(0); }
function pps(v){ v=+v||0; return v<0.05?'<span class="zero">0</span>':'<span class="num">'+(v>=1000?(v/1000).toFixed(1)+'k':v.toFixed(1))+'</span>'; }

async function load(force){
  const r = await fetch('l2switch.php?api=data&sw='+sel).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok){ document.getElementById('ports').innerHTML='<tr><td colspan="8" class="muted">No data.</td></tr>'; return; }
  switches = r.switches; sel = r.sel||0;
  const ss = document.getElementById('swsel');
  ss.innerHTML = switches.length ? switches.map(s=>`<option value="${s.id}" ${s.id==sel?'selected':''}>${esc(s.name)} — ${esc(s.host)}${s.enabled?'':' (disabled)'}</option>`).join('')
                                 : '<option value="0">No switches configured</option>';
  document.getElementById('editbtn').style.display = sel?'inline-block':'none';

  document.getElementById('k-up').textContent = r.up;
  document.getElementById('k-down').textContent = r.down;
  document.getElementById('k-err').textContent = r.err_ports;
  const pi = document.getElementById('pollinfo');
  if(!switches.length){ pi.textContent=''; document.getElementById('ports').innerHTML='<tr><td colspan="8" class="muted">Add a switch to begin (the TL-SG108E you saw, for example).</td></tr>'; document.getElementById('events').innerHTML='<div class="muted">—</div>'; return; }
  if(r.status==='error'){ pi.innerHTML='<span class="err"><i class="fas fa-triangle-exclamation"></i> '+esc(r.last_error)+'</span>'; }
  else pi.innerHTML = r.last_poll ? ('Last poll '+esc(r.last_poll)) : 'Not polled yet';

  document.getElementById('ports').innerHTML = r.ports.length ? r.ports.map(p=>{
    const dis = !p.enabled, up = p.link_code>0;
    const cls = dis?'dis':(up?'':'down');
    const stat = dis?'<span class="pill dis">Disabled</span>':(up?'<span class="pill up">Up</span>':'<span class="pill down">Down</span>');
    const errpps = (p.tx_err_pps+p.rx_err_pps);
    const errcell = (p.tx_bad+p.rx_bad)>0
        ? `<span class="${errpps>0?'err':''}">${fmtN(p.tx_bad)} / ${fmtN(p.rx_bad)}</span>${errpps>0?` <span class="err">(+${errpps.toFixed(1)}/s)</span>`:''}`
        : '<span class="zero">0 / 0</span>';
    return `<tr class="${cls}">
      <td><b>${p.port}</b></td>
      <td>${stat}</td>
      <td>${up?'<span class="dot" style="background:var(--ok)"></span>':'<span class="dot" style="background:#555"></span>'}${esc(p.link)}</td>
      <td>${pps(p.tx_pps)}</td><td>${pps(p.rx_pps)}</td>
      <td>${errcell}</td>
      <td><span class="spark" id="sp-${p.port}"></span></td>
      <td class="num spd">${fmtN(p.tx_good)} / ${fmtN(p.rx_good)}</td>
    </tr>`;
  }).join('') : '<tr><td colspan="8" class="muted">No port data — try Poll now.</td></tr>';
  r.ports.forEach(p=>{ if(p.link_code>0) drawSpark(p.port); });

  document.getElementById('events').innerHTML = r.events.length ? r.events.map(e=>{
    const ic = {link_down:'fa-link-slash',link_up:'fa-link',link_change:'fa-arrows-rotate',errors:'fa-triangle-exclamation'}[e.kind]||'fa-circle';
    return `<div class="ev ${e.acked==1?'':''}" style="${e.acked==1?'opacity:.45':''}">
      <div class="i sev-${e.severity}"><i class="fas ${ic}"></i></div>
      <div class="d"><div>${esc(e.detail)}</div><div class="t">${esc(e.ts)}${e.acked==1?' · acked':''}</div></div>
      ${e.acked==1?'':`<button class="btn ghost" style="padding:2px 8px;font-size:11px;" onclick="ack(${e.id})">✓</button>`}
    </div>`;
  }).join('') : '<div class="muted">No events. Link flaps and bad-packet spikes will appear here.</div>';
}

async function drawSpark(port){
  const el = document.getElementById('sp-'+port); if(!el) return;
  const r = await fetch('l2switch.php?api=spark&sw='+sel+'&port='+port).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok||r.points.length<2){ el.innerHTML='<span class="zero">·</span>'; return; }
  const w=110,h=22; const tx=r.points.map(p=>p.tx), rx=r.points.map(p=>p.rx);
  const mx=Math.max(1,...tx,...rx);
  const line=(arr,col)=>{ const pts=arr.map((v,i)=>`${(i/(arr.length-1))*w},${h-(v/mx)*(h-2)-1}`).join(' '); return `<polyline points="${pts}" fill="none" stroke="${col}" stroke-width="1.3"/>`; };
  el.innerHTML=`<svg width="${w}" height="${h}">${line(rx,'#4da3ff')}${line(tx,'#2ecc71')}</svg>`;
}

function selSwitch(v){ sel=+v; load(); }
async function ack(id){ await fetch('l2switch.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'action=ack&sw='+sel+'&id='+id}); load(); }
async function ackAll(){ await fetch('l2switch.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'action=ack&sw='+sel+'&id=0'}); load(); }

// ── form ──
function openForm(id){
  const s = switches.find(x=>x.id==id);
  document.getElementById('formtitle').textContent = s?'Edit switch':'Add switch';
  document.getElementById('f_id').value = s?s.id:'';
  document.getElementById('f_name').value = s?s.name:'';
  document.getElementById('f_host').value = s?s.host:'';
  document.getElementById('f_port').value = s?s.port:80;
  document.getElementById('f_user').value = s?s.username:'admin';
  document.getElementById('f_model').value = s?s.model:'';
  document.getElementById('f_thr').value = s?s.err_threshold_pps:1;
  document.getElementById('f_en').value = s?String(s.enabled):'1';
  document.getElementById('f_pass').value = '';
  document.getElementById('pwhint').textContent = s?'(leave blank = unchanged)':'';
  document.getElementById('delbtn').style.display = s?'inline-block':'none';
  document.getElementById('formmsg').textContent='';
  document.getElementById('formbg').style.display='flex';
}
function closeForm(){ document.getElementById('formbg').style.display='none'; }
function formBody(extra){
  const p=new URLSearchParams();
  p.set('id',document.getElementById('f_id').value);
  p.set('name',document.getElementById('f_name').value);
  p.set('host',document.getElementById('f_host').value);
  p.set('port',document.getElementById('f_port').value);
  p.set('username',document.getElementById('f_user').value);
  p.set('model',document.getElementById('f_model').value);
  p.set('password',document.getElementById('f_pass').value);
  p.set('err_threshold_pps',document.getElementById('f_thr').value);
  p.set('enabled',document.getElementById('f_en').value);
  for(const k in extra) p.set(k,extra[k]);
  return p.toString();
}
async function testForm(){
  const m=document.getElementById('formmsg'); m.style.color='#9aa'; m.textContent='Testing…';
  const r=await fetch('l2switch.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:formBody({action:'test'})}).then(r=>r.json()).catch(()=>null);
  if(r&&r.ok){ m.style.color='var(--ok)'; m.textContent='✓ Connected — '+r.ports+' ports'; }
  else { m.style.color='var(--crit)'; m.textContent='✗ '+(r?r.error:'failed'); }
}
async function saveForm(){
  const m=document.getElementById('formmsg'); m.style.color='#9aa'; m.textContent='Saving…';
  const r=await fetch('l2switch.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:formBody({action:'save'})}).then(r=>r.json()).catch(()=>null);
  if(r&&r.ok){ sel=r.id||sel; closeForm(); load(true); }
  else { m.style.color='var(--crit)'; m.textContent='✗ '+(r?r.error:'failed'); }
}
async function delSwitch(){
  if(!confirm('Delete this switch and its history?')) return;
  await fetch('l2switch.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:formBody({action:'delete'})});
  sel=0; closeForm(); load();
}

load();
setInterval(load, 15000);
</script>
</body></html>
