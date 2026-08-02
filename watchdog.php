<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Service Watchdog (unified). One cockpit for EVERY watched service across
// all Linux + Windows hosts: live state, arm/disarm auto-restart, restart-now,
// restart history, and an on-demand fleet sweep (the same check the crons run every
// couple of minutes — read state over SSH and auto-restart any ARMED service found
// stopped, 5-min backoff, all audited). Reuses nm_linuxhost.php + nm_winhost.php
// verbatim (no new tables/logic). RBAC: 'watchdog'.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_linuxhost.php');
require_once('nm_winhost.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'watchdog')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=watchdog'); exit;
}
// seed the perm for admin the first time (some pages have no engine ensure)
@$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','watchdog',1 FROM DUAL
    WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='watchdog')");
$uid = (int)($_SESSION['UID'] ?? 0) ?: null;

// ── helpers: normalize a watched-service row from either OS ───────────────────
function wd_row(string $os, array $h, array $w): array {
    $state = strtolower(trim((string)($w['last_state'] ?? '')));
    $up = ($state !== '') && (strpos($state, 'run') !== false || strpos($state, 'active') !== false);
    return [
        'os'      => $os,
        'id'      => (int)$w['id'],
        'host_id' => (int)$h['id'],
        'host'    => (string)($h['name'] ?? ('host'.$h['id'])),
        'host_ip' => (string)($h['host_ip'] ?? ($h['node_ip'] ?? '')),
        'service' => (string)$w['service_name'],
        'display' => (string)(($w['display_name'] ?? '') !== '' ? $w['display_name'] : $w['service_name']),
        'state'   => (string)($w['last_state'] ?? ''),
        'up'      => $up ? 1 : 0,
        'known'   => $state !== '' ? 1 : 0,
        'auto'    => (int)($w['auto_restart'] ?? 0),
        'restarts'=> (int)($w['restart_count'] ?? 0),
        'checked_age'    => isset($w['checked_age']) && $w['checked_age'] !== null ? (int)$w['checked_age'] : null,
        'last_action_at' => $w['last_action_at'] ?? null,
    ];
}
function wd_collect($conn): array {
    $rows = [];
    foreach (nm_lx_hosts($conn)  as $h) foreach (nm_lx_watches($conn,  (int)$h['id']) as $w) $rows[] = wd_row('linux',   $h, $w);
    foreach (nm_win_hosts($conn) as $h) foreach (nm_win_watches($conn, (int)$h['id']) as $w) $rows[] = wd_row('windows', $h, $w);
    // stable sort: down first, then host, then service
    usort($rows, fn($a,$b) => [$a['known']&&!$a['up']?0:1, strtolower($a['host']), strtolower($a['display'])]
                          <=> [$b['known']&&!$b['up']?0:1, strtolower($b['host']), strtolower($b['display'])]);
    return $rows;
}
function wd_kpi(array $rows): array {
    $armed=$down=$restarts=0;
    foreach ($rows as $r){ $armed+=$r['auto']?1:0; $down+= ($r['known']&&!$r['up'])?1:0; $restarts+=$r['restarts']; }
    return ['total'=>count($rows), 'armed'=>$armed, 'down'=>$down, 'restarts'=>$restarts];
}
function wd_hosts($conn): array {
    $out = [];
    foreach (nm_lx_hosts($conn)  as $h) $out[] = ['os'=>'linux',   'id'=>(int)$h['id'], 'name'=>(string)$h['name'], 'ip'=>(string)($h['host_ip']??$h['node_ip']??'')];
    foreach (nm_win_hosts($conn) as $h) $out[] = ['os'=>'windows', 'id'=>(int)$h['id'], 'name'=>(string)$h['name'], 'ip'=>(string)($h['host_ip']??'')];
    return $out;
}

// ── API ──────────────────────────────────────────────────────────────────────
if ($api !== '') {
    if (function_exists('session_write_close')) @session_write_close();   // sweep/restart hit SSH
    header('Content-Type: application/json; charset=utf-8');
    $body = json_decode(file_get_contents('php://input'), true) ?: $_POST;
    $os   = ($body['os'] ?? $_GET['os'] ?? '') === 'windows' ? 'windows' : 'linux';
    try {
        if ($api === 'list')  { $rows = wd_collect($conn); echo json_encode(['ok'=>true,'rows'=>$rows,'kpi'=>wd_kpi($rows)]); exit; }
        if ($api === 'hosts') { echo json_encode(['ok'=>true,'hosts'=>wd_hosts($conn)]); exit; }

        if ($api === 'services') {   // live service list for the picked host (over SSH)
            $hid = (int)($body['host_id'] ?? $_GET['host_id'] ?? 0);
            if ($os === 'windows') { $h = nm_win_host($conn,$hid); $r = $h ? nm_win_services_live($conn,$h) : ['ok'=>false,'error'=>'host not found']; }
            else                   { $h = nm_lx_host($conn,$hid);  $r = $h ? nm_lx_services_live($conn,$h)  : ['ok'=>false,'error'=>'host not found']; }
            echo json_encode($r); exit;
        }

        if ($api === 'add') {
            $hid = (int)($body['host_id'] ?? 0);
            $f = ['service_name'=>(string)($body['service_name']??''), 'display_name'=>(string)($body['display_name']??''), 'auto_restart'=>!empty($body['auto_restart'])];
            $r = $os==='windows' ? nm_win_watch_add($conn,$hid,$f,$uid) : nm_lx_watch_add($conn,$hid,$f,$uid);
            log_user_action($conn,'watchdog_add',$os.':'.$hid.':'.$f['service_name']); echo json_encode($r); exit;
        }
        if ($api === 'toggle') {
            $id = (int)($body['id'] ?? 0); $f = ['auto_restart'=>!empty($body['auto_restart'])];
            $r = $os==='windows' ? nm_win_watch_update($conn,$id,$f) : nm_lx_watch_update($conn,$id,$f);
            echo json_encode($r); exit;
        }
        if ($api === 'remove') {
            $id = (int)($body['id'] ?? 0);
            $r = $os==='windows' ? nm_win_watch_delete($conn,$id) : nm_lx_watch_delete($conn,$id);
            echo json_encode($r); exit;
        }
        if ($api === 'restart') {
            $hid = (int)($body['host_id'] ?? 0); $svc = (string)($body['service_name'] ?? '');
            $r = $os==='windows' ? nm_win_service_action_by_id($conn,$hid,$svc,'restart',$uid)
                                 : nm_lx_service_action_by_id($conn,$hid,$svc,'restart',$uid);
            log_user_action($conn,'watchdog_restart',$os.':'.$hid.':'.$svc); echo json_encode($r); exit;
        }
        if ($api === 'sweep') {
            // run the same check the crons run, across every host; auto-restarts armed+stopped services
            $checked=$acted=$hok=$hfail=0; $errs=[];
            foreach (nm_lx_hosts($conn) as $h)  { $r=nm_lx_watch_check($conn,$h);  if(!empty($r['ok'])){$hok++;$checked+=(int)($r['checked']??0);$acted+=(int)($r['acted']??0);} else {$hfail++; if(!empty($r['error']))$errs[]=$h['name'].': '.$r['error'];} }
            foreach (nm_win_hosts($conn) as $h) { $r=nm_win_watch_check($conn,$h); if(!empty($r['ok'])){$hok++;$checked+=(int)($r['checked']??0);$acted+=(int)($r['acted']??0);} else {$hfail++; if(!empty($r['error']))$errs[]=$h['name'].': '.$r['error'];} }
            $rows = wd_collect($conn);
            echo json_encode(['ok'=>true,'checked'=>$checked,'acted'=>$acted,'hosts_ok'=>$hok,'hosts_fail'=>$hfail,'errors'=>array_slice($errs,0,6),'rows'=>$rows,'kpi'=>wd_kpi($rows)]); exit;
        }
        echo json_encode(['ok'=>false,'error'=>'unknown api']);
    } catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>$e->getMessage()]); }
    exit;
}

log_user_action($conn,'view_page','watchdog.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(12,16,26,.6); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ee66e; --warn:#f0a92c; --crit:#ff5a5a; --cyan:#36e3d0; }
html{ background:#05080f; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#d4dce8; }
<?= nm_chrome_css() ?>
.wd{ max-width:1240px; margin:0 auto; padding:18px 20px 60px; }
.wd *{ box-sizing:border-box; }
.glass{ background:var(--glass); backdrop-filter:blur(13px); border:1px solid var(--border); border-radius:14px; }
.bar{ display:flex; align-items:center; gap:13px; padding:13px 18px; margin-bottom:16px; flex-wrap:wrap; }
.title{ font-size:19px; font-weight:800; display:flex; align-items:center; gap:11px; } .title i{ color:#36e3d0; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:9px 14px; font-size:13px; cursor:pointer; }
.btn:hover{ border-color:var(--accent); color:#fff; } .btn.g{ background:linear-gradient(135deg,#36e3d0,#4da3ff); border:none; color:#04121a; font-weight:700; }
.btn.sm{ padding:6px 9px; font-size:12px; } .btn.danger{ border-color:rgba(255,90,90,.45); color:#ff9b91; }
.btn:disabled{ opacity:.55; cursor:default; }
.kpis{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:16px; }
.kpi{ padding:14px 16px; } .kpi .n{ font-size:26px; font-weight:800; } .kpi .l{ font-size:10.5px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; margin-top:2px; }
.card{ padding:4px 6px; }
table{ width:100%; border-collapse:collapse; font-size:13px; }
th{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; padding:10px 12px; border-bottom:1px solid var(--border); }
td{ padding:10px 12px; border-bottom:1px solid rgba(255,255,255,.05); vertical-align:middle; }
tr:hover td{ background:rgba(77,163,255,.05); }
.host{ display:flex; align-items:center; gap:9px; } .host i{ font-size:15px; color:#9fb2c8; width:16px; text-align:center; }
.host .ip{ font-family:monospace; font-size:10.5px; color:#7c8698; }
.svc b{ color:#eaf1ff; } .svc .sn{ font-family:monospace; font-size:10.5px; color:#7c8698; }
.dot{ width:9px; height:9px; border-radius:50%; display:inline-block; margin-right:7px; box-shadow:0 0 8px currentColor; }
.st-up{ color:#2ee66e; } .st-down{ color:#ff5a5a; } .st-unk{ color:#7c8698; }
.toggle{ position:relative; width:38px; height:20px; border-radius:20px; background:rgba(255,255,255,.12); cursor:pointer; transition:.15s; border:1px solid var(--border); }
.toggle.on{ background:rgba(46,230,110,.35); border-color:rgba(46,230,110,.6); }
.toggle i{ position:absolute; top:1.5px; left:2px; width:15px; height:15px; border-radius:50%; background:#cfd6e0; transition:.15s; }
.toggle.on i{ left:20px; background:#8ff0b6; }
.rc{ font-variant-numeric:tabular-nums; font-weight:700; } .muted{ color:#8a909a; font-size:12px; } .dim{ color:#6f7a8c; }
.acts{ display:flex; gap:5px; justify-content:flex-end; }
.tg{ width:28px; height:28px; display:inline-flex; align-items:center; justify-content:center; border-radius:7px; cursor:pointer; color:#9fb2c8; border:1px solid transparent; }
.tg:hover{ background:rgba(255,255,255,.08); color:#fff; } .tg.danger:hover{ color:#ff9b91; }
.pill{ font-size:9.5px; font-weight:800; text-transform:uppercase; padding:2px 7px; border-radius:20px; letter-spacing:.4px; }
.pill.armed{ background:rgba(46,230,110,.16); color:#8ff0b6; } .pill.manual{ background:rgba(255,255,255,.08); color:#aeb8c7; }
.empty{ text-align:center; color:#6f7a8c; padding:56px 20px; } .empty i{ font-size:42px; display:block; margin-bottom:14px; color:#2a4a5e; }
.modal{ position:fixed; inset:0; z-index:70; background:rgba(3,5,12,.72); backdrop-filter:blur(4px); display:none; align-items:center; justify-content:center; padding:24px; }
.mcard{ width:460px; max-width:96vw; background:rgba(9,13,24,.98); border:1px solid var(--border); border-radius:16px; padding:22px 24px; }
label{ display:block; font-size:10.5px; text-transform:uppercase; letter-spacing:.4px; color:#8b95a7; margin:12px 0 5px; }
.inp{ width:100%; background:rgba(0,0,0,.35); border:1px solid var(--border); color:#e6edf7; border-radius:9px; padding:9px 11px; font-size:13px; }
#msg{ font-size:12.5px; }
</style>

<?php include('header.php'); ?>
<div class="wd">
  <div class="bar glass">
    <div class="title"><i class="fa-solid fa-shield-heart"></i> Service Watchdog</div>
    <span class="muted" id="sub">every watched service, all hosts</span>
    <span style="flex:1"></span>
    <span id="msg" class="muted"></span>
    <button class="btn" id="sweepb" onclick="sweep()"><i class="fa-solid fa-satellite-dish"></i> Sweep now</button>
    <button class="btn g" onclick="openAdd()"><i class="fa-solid fa-plus"></i> Watch a service</button>
  </div>

  <div class="kpis">
    <div class="glass kpi"><div class="n" id="k-total">—</div><div class="l">watched services</div></div>
    <div class="glass kpi"><div class="n" id="k-armed" style="color:var(--ok)">—</div><div class="l">auto-restart armed</div></div>
    <div class="glass kpi"><div class="n" id="k-down" style="color:var(--crit)">—</div><div class="l">currently down</div></div>
    <div class="glass kpi"><div class="n" id="k-restarts" style="color:var(--cyan)">—</div><div class="l">total restarts</div></div>
  </div>

  <div class="glass card">
    <table>
      <thead><tr><th>Host</th><th>Service</th><th>State</th><th>Auto-restart</th><th style="text-align:center">Restarts</th><th>Last checked</th><th></th></tr></thead>
      <tbody id="rows"><tr><td colspan="7" class="muted" style="padding:20px">Loading…</td></tr></tbody>
    </table>
  </div>
  <div class="muted" style="margin-top:12px;font-size:11.5px"><i class="fa-solid fa-circle-info"></i>
    State + last-checked come from the automatic sweep (crons run it every ~2 min). <b>Auto-restart</b> armed = NEURU
    starts the service over SSH when it's found stopped (5-min backoff, all audited). Use <b>Sweep now</b> to refresh live.
  </div>
</div>

<div class="modal" id="add-modal"><div class="mcard">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;"><h3 style="margin:0;font-size:16px;">Watch a service</h3><span style="flex:1"></span><i class="fa-solid fa-xmark" style="cursor:pointer;color:#9aa3af" onclick="closeAdd()"></i></div>
  <div class="muted" style="font-size:12px">Add a service to keep an eye on. Arm auto-restart and NEURU will bring it back if it goes down.</div>
  <label>Host</label><select class="inp" id="a-host" onchange="loadServices()"></select>
  <label>Service <span class="dim" id="svc-cap" style="text-transform:none">(pick from the host's live services)</span></label>
  <select class="inp" id="a-svc-sel" onchange="onSvcPick()"><option value="">select a host first</option></select>
  <input class="inp" id="a-svc-manual" placeholder="exact service name (e.g. nginx / Spooler)" style="display:none;margin-top:7px">
  <label>Display name <span class="dim" style="text-transform:none">(optional)</span></label><input class="inp" id="a-disp" placeholder="friendly label">
  <label style="display:flex;align-items:center;gap:9px;margin-top:14px;text-transform:none;letter-spacing:0;font-size:13px;color:#d4dce8;cursor:pointer">
    <input type="checkbox" id="a-auto"> Arm auto-restart now</label>
  <div style="display:flex;gap:9px;margin-top:18px;justify-content:flex-end">
    <button class="btn" onclick="closeAdd()">Cancel</button>
    <button class="btn g" id="a-save" onclick="saveAdd()"><i class="fa-solid fa-plus"></i> Add</button>
  </div>
  <div id="a-msg" style="margin-top:10px;font-size:12px;color:#ff9b91"></div>
</div></div>

<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let ROWS=[], HOSTS=[], polling=null;
function msg(t,c){ const m=document.getElementById('msg'); m.textContent=t||''; m.style.color=c||'#8a909a'; }
async function jget(u){ return fetch(u).then(r=>r.json()).catch(()=>null); }
async function jpost(api,obj){ return fetch('watchdog.php?api='+api,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj||{})}).then(r=>r.json()).catch(()=>({ok:false,error:'request failed'})); }

function osIcon(os){ return os==='windows'?'fa-brands fa-windows':'fa-brands fa-linux'; }
function relAge(s){ if(s==null)return '<span class="dim">never</span>'; s=+s; if(s<60)return s+'s ago'; if(s<3600)return Math.floor(s/60)+'m ago'; if(s<86400)return Math.floor(s/3600)+'h ago'; return Math.floor(s/86400)+'d ago'; }
function stateCell(r){ if(!r.known) return '<span class="st-unk"><span class="dot" style="background:#7c8698"></span>unknown</span>';
  return r.up? '<span class="st-up"><span class="dot" style="background:#2ee66e"></span>running</span>'
             : '<span class="st-down"><span class="dot" style="background:#ff5a5a"></span>'+esc(r.state||'stopped')+'</span>'; }

function render(){
  const tb=document.getElementById('rows');
  if(!ROWS.length){ tb.innerHTML='<tr><td colspan="7"><div class="empty"><i class="fa-solid fa-shield-heart"></i>No services watched yet.<br><span class="muted">Click <b>Watch a service</b>, or add hosts in Linux / Windows Monitor first.</span></div></td></tr>'; return; }
  tb.innerHTML=ROWS.map((r,i)=>`<tr>
    <td><div class="host"><i class="${osIcon(r.os)}"></i><div><div>${esc(r.host)}</div><div class="ip">${esc(r.host_ip||'')}</div></div></div></td>
    <td class="svc"><b>${esc(r.display)}</b>${r.display!==r.service?`<div class="sn">${esc(r.service)}</div>`:''}</td>
    <td>${stateCell(r)}</td>
    <td><div style="display:flex;align-items:center;gap:9px"><div class="toggle ${r.auto?'on':''}" title="${r.auto?'Disarm':'Arm'} auto-restart" onclick="toggle(${i})"><i></i></div><span class="pill ${r.auto?'armed':'manual'}">${r.auto?'armed':'manual'}</span></div></td>
    <td style="text-align:center"><span class="rc">${r.restarts}</span></td>
    <td class="muted">${relAge(r.checked_age)}</td>
    <td><div class="acts">
      <span class="tg" title="Restart now (over SSH)" onclick="restart(${i})"><i class="fa-solid fa-rotate-right"></i></span>
      <span class="tg danger" title="Stop watching" onclick="remove(${i})"><i class="fa-solid fa-trash"></i></span>
    </div></td></tr>`).join('');
}
function setKpi(k){ document.getElementById('k-total').textContent=k.total; document.getElementById('k-armed').textContent=k.armed;
  document.getElementById('k-down').textContent=k.down; document.getElementById('k-restarts').textContent=k.restarts;
  document.getElementById('k-down').style.color=k.down>0?'#ff5a5a':'#2ee66e'; }

async function load(){ const d=await jget('watchdog.php?api=list&_='+Date.now()); if(!d||!d.ok)return; ROWS=d.rows||[]; setKpi(d.kpi); render(); }
async function sweep(){ const b=document.getElementById('sweepb'); b.disabled=true; b.innerHTML='<i class="fa-solid fa-spinner fa-spin"></i> Sweeping…'; msg('Reading live states over SSH…');
  const d=await jpost('sweep',{});
  b.disabled=false; b.innerHTML='<i class="fa-solid fa-satellite-dish"></i> Sweep now';
  if(!d||!d.ok){ msg('Sweep failed','#ff9b91'); return; }
  ROWS=d.rows||[]; setKpi(d.kpi); render();
  let t=`Swept ${d.hosts_ok} host(s) · ${d.checked} checked`+(d.acted?` · ⚡ ${d.acted} auto-restarted`:'')+(d.hosts_fail?` · ${d.hosts_fail} unreachable`:'');
  msg(t, d.acted?'#8ff0b6':'#8a909a');
}
async function toggle(i){ const r=ROWS[i]; const nv=r.auto?0:1;
  if(nv && !confirm('Arm auto-restart for “'+r.display+'” on '+r.host+'?\n\nNEURU will START it over SSH whenever it is found stopped (max once / 5 min). Every action is audited.')) return;
  const d=await jpost('toggle',{os:r.os,id:r.id,auto_restart:nv}); if(d&&d.ok){ r.auto=nv; render(); setKpi(kpiFromRows()); } else msg((d&&d.error)||'failed','#ff9b91'); }
async function restart(i){ const r=ROWS[i]; if(!confirm('Restart “'+r.display+'” on '+r.host+' now (over SSH)?'))return;
  msg('Restarting '+r.display+'…'); const d=await jpost('restart',{os:r.os,host_id:r.host_id,service_name:r.service});
  if(d&&d.ok){ msg('✓ Restarted '+r.display,'#8ff0b6'); setTimeout(load,600); } else msg('✗ '+((d&&d.error)||'failed'),'#ff9b91'); }
async function remove(i){ const r=ROWS[i]; if(!confirm('Stop watching “'+r.display+'” on '+r.host+'?\n\n(The service itself is not touched.)'))return;
  const d=await jpost('remove',{os:r.os,id:r.id}); if(d&&d.ok) load(); else msg((d&&d.error)||'failed','#ff9b91'); }
function kpiFromRows(){ let armed=0,down=0,rs=0; ROWS.forEach(r=>{armed+=r.auto?1:0; down+=(r.known&&!r.up)?1:0; rs+=r.restarts;}); return {total:ROWS.length,armed,down,restarts:rs}; }

// ── add ──
let SVCS=[];
async function openAdd(){ document.getElementById('a-msg').textContent=''; document.getElementById('a-disp').value=''; document.getElementById('a-auto').checked=false;
  const man=document.getElementById('a-svc-manual'); man.style.display='none'; man.value='';
  if(!HOSTS.length){ const d=await jget('watchdog.php?api=hosts'); HOSTS=(d&&d.hosts)||[]; }
  const sel=document.getElementById('a-host');
  if(!HOSTS.length){ document.getElementById('a-msg').innerHTML='No hosts yet — add a Linux or Windows host first (Monitoring → Linux/Windows Monitor).'; }
  sel.innerHTML=HOSTS.map((h,i)=>`<option value="${i}">${h.os==='windows'?'🪟':'🐧'} ${esc(h.name)}${h.ip?' — '+esc(h.ip):''}</option>`).join('');
  document.getElementById('add-modal').style.display='flex';
  loadServices();
}
const svcUp=s=>/run/i.test(String(s.State||''));
async function loadServices(){
  const h=HOSTS[+document.getElementById('a-host').value];
  const sel=document.getElementById('a-svc-sel'), man=document.getElementById('a-svc-manual'), cap=document.getElementById('svc-cap');
  SVCS=[]; man.style.display='none'; man.value=''; sel.style.display='block';
  if(!h){ sel.innerHTML='<option value="">select a host first</option>'; return; }
  sel.innerHTML='<option value="">⏳ loading services over SSH…</option>'; sel.disabled=true; cap.textContent='(reading '+esc(h.name)+' over SSH…)';
  const d=await jpost('services',{os:h.os,host_id:h.id});
  sel.disabled=false;
  if(!d||!d.ok||!(d.services&&d.services.length)){
    sel.style.display='none'; man.style.display='block'; man.focus();
    cap.innerHTML='<span style="color:#f0a92c">couldn\'t list services'+(d&&d.error?' ('+esc(d.error)+')':'')+' — type the exact name</span>';
    return;
  }
  SVCS=d.services.slice();
  SVCS.sort((a,b)=>(svcUp(a)-svcUp(b)) || String(a.DisplayName||a.Name).localeCompare(String(b.DisplayName||b.Name)));  // stopped first
  sel.innerHTML='<option value="">— pick a service —</option>'+SVCS.map((s,i)=>{
    const st=String(s.State||'?'), tail=(s.DisplayName&&s.DisplayName!==s.Name)?' ('+esc(s.Name)+')':'';
    return `<option value="${i}"${svcUp(s)?'':' data-down="1"'}>${svcUp(s)?'':'● '}${esc(s.DisplayName||s.Name)} — ${esc(st)}${tail}</option>`;
  }).join('')+'<option value="__manual">✎ type manually…</option>';
  cap.textContent='('+SVCS.length+' services · stopped listed first)';
}
function onSvcPick(){ const v=document.getElementById('a-svc-sel').value, man=document.getElementById('a-svc-manual');
  if(v==='__manual'){ man.style.display='block'; man.value=''; man.focus(); return; }
  man.style.display='none';
  const s=SVCS[+v]; if(s){ const disp=document.getElementById('a-disp'); if(!disp.value) disp.value=s.DisplayName||s.Name; }
}
function closeAdd(){ document.getElementById('add-modal').style.display='none'; }
async function saveAdd(){ const h=HOSTS[+document.getElementById('a-host').value]; if(!h){ document.getElementById('a-msg').textContent='Pick a host'; return; }
  const man=document.getElementById('a-svc-manual'); let svc='';
  if(man.style.display!=='none' && man.value.trim()) svc=man.value.trim();
  else { const s=SVCS[+document.getElementById('a-svc-sel').value]; svc=s?s.Name:''; }
  if(!svc){ document.getElementById('a-msg').textContent='Pick or type a service'; return; }
  const b=document.getElementById('a-save'); b.disabled=true;
  const d=await jpost('add',{os:h.os,host_id:h.id,service_name:svc,display_name:document.getElementById('a-disp').value.trim(),auto_restart:document.getElementById('a-auto').checked?1:0});
  b.disabled=false;
  if(d&&d.ok){ closeAdd(); load(); } else document.getElementById('a-msg').textContent=(d&&d.error)||'failed';
}

load(); polling=setInterval(load, 12000);
window.addEventListener('DOMContentLoaded',()=>{ if(window.NMLoader)NMLoader.hide(); });
</script>
</body></html>
