<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Autonomous Self-Healing console. Configure playbooks (off/armed/auto),
// review proposed actions, approve or revert. SAFETY: everything ships OFF; auto
// actions are time-boxed (auto-revert). RBAC: 'heal'. Engine: nm_heal.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_heal.php');
if (is_file(__DIR__.'/nm_decoy.php')) require_once('nm_decoy.php');   // to flag events whose IP is being diverted
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'heal')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=heal'); exit;
}
nm_heal_ensure($conn);
$canConfig = nm_can($conn,'net_mon_config');

if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    $body = json_decode(file_get_contents('php://input'), true) ?? $_POST;
    if ($api === 'data') {
        // resolve each event's reporter → node name + whether that device is a healing
        // (firewall) enforcement point, so the list can flag "router not enabled for healing".
        $nodeByIp=[]; $nodeByHost=[];
        if($nr=$conn->query("SELECT display_name,ip_address,hostname FROM nm_nodes")){
            while($x=$nr->fetch_assoc()){ if(!empty($x['ip_address']))$nodeByIp[$x['ip_address']]=$x['display_name'];
                if(!empty($x['hostname']))$nodeByHost[strtolower($x['hostname'])]=$x['display_name']; }
        }
        // ALL managed routers/firewalls (config devices) — lets us tell a passive SENSOR
        // (a server/Pi-hole that merely LOGGED the attack) apart from a ROUTER that could
        // enforce a block but isn't enabled. Enabled ones = actual enforcement points.
        $devByName=[]; $devByIp=[];
        try {   // best-effort: mysqli is in EXCEPTION mode — a missing table must not 500 the data api
            if($dr=$conn->query("SELECT name,host_ip FROM nm_config_devices")){
                while($x=$dr->fetch_assoc()){ $devByName[strtolower($x['name'])]=1; if(!empty($x['host_ip']))$devByIp[$x['host_ip']]=1; }
            }
        } catch (\Throwable $e) { /* config manager not provisioned → treat all reporters as sensors */ }
        $fwNames=[]; $fwIps=[]; $fwList=[];
        foreach(nm_imm_firewall_targets($conn) as $d){ $fwList[]=$d['name']; $fwNames[strtolower($d['name'])]=1; if(!empty($d['host_ip']))$fwIps[$d['host_ip']]=1; }
        // Role of the device that SAW the threat:
        //   enforced   → it's an enabled firewall enforcement point (block lands at the source) ✅
        //   router_off → it's a managed router/firewall but NOT enabled for healing (enable it to block at source)
        //   sensor     → a server / Pi-hole / host that only logged it (never expected to block — the firewall does)
        //   none       → unknown reporter
        $resolve=function($rb)use($nodeByIp,$nodeByHost,$fwNames,$fwIps,$devByName,$devByIp){
            $rb=(string)$rb; if($rb==='') return ['name'=>'','role'=>'none'];
            $rip=''; if(preg_match('/(\d{1,3}(?:\.\d{1,3}){3})/',$rb,$m))$rip=$m[1];
            $rhost=trim(preg_replace('/\s*\(.*$/','',$rb));
            // HOSTNAME-first (an IP can collide when two nodes share it — e.g. a Pi-hole on
            // the same host), then fall back to IP, then the raw string.
            $name=($rhost!==''&&isset($nodeByHost[strtolower($rhost)]))?$nodeByHost[strtolower($rhost)]
                 :(($rip!==''&&isset($nodeByIp[$rip]))?$nodeByIp[$rip]:($rhost!==''?$rhost:$rb));
            $ln=strtolower($name);
            $isFw     = isset($fwNames[$ln]) || ($rip!==''&&isset($fwIps[$rip]));
            $isRouter = isset($devByName[$ln]) || isset($devByName[strtolower($rhost)]) || ($rip!==''&&isset($devByIp[$rip]));
            $role = $isFw ? 'enforced' : ($isRouter ? 'router_off' : 'sensor');
            return ['name'=>$name,'role'=>$role];
        };
        // IPs currently being diverted into a honeypot (Deception Grid) → flag matching events, so
        // the operator sees an IP is being deceived (not just healed/blocked).
        $divertedIps=[];
        if($conn->query("SHOW TABLES LIKE 'nm_decoy_diversions'")->num_rows){
            $dr=$conn->query("SELECT DISTINCT src_ip FROM nm_decoy_diversions WHERE status='active'");
            while($dr&&$x=$dr->fetch_assoc())$divertedIps[$x['src_ip']]=1;
        }
        $ev = array_map(function($e)use($resolve,$divertedIps){ $rep=$resolve($e['reported_by']??'');
            return [
            'id'=>(int)$e['id'],'pb'=>$e['pb_key'],'indicator'=>$e['indicator'],'kind'=>$e['kind'],'action'=>$e['action'],
            'status'=>$e['status'],'detail'=>$e['trigger_detail'],'report'=>$e['report'],'revert_at'=>$e['revert_at'],'detected_at'=>$e['detected_at'],
            'reported_name'=>$rep['name'],'reported_role'=>$rep['role'],
            'reported_enforced'=>($rep['role']==='enforced'),
            'diverted'=>isset($divertedIps[$e['indicator']])?1:0,
        ]; }, nm_heal_events($conn,150));
        echo json_encode(['ok'=>true,'playbooks'=>nm_heal_playbooks($conn),'events'=>$ev,'counts'=>nm_heal_counts($conn),
            'enforce_points'=>$fwList]); exit;
    }
    if ($api === 'evidence') { echo json_encode(nm_heal_evidence($conn,(int)($_GET['id']??0))); exit; }
    if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
    if ($api === 'approve')  { echo json_encode(nm_heal_act($conn,(int)($body['id']??0))); exit; }   // approve+act a proposed event
    if ($api === 'revert')   { echo json_encode(nm_heal_revert($conn,(int)($body['id']??0))); exit; }
    if ($api === 'dismiss')  { nm_heal_dismiss($conn,(int)($body['id']??0)); echo json_encode(['ok'=>true]); exit; }
    if ($api === 'divert') {   // send this event's IP to the Deception Grid (divert to a honeypot)
        if (!function_exists('nm_decoy_quick_divert')) { echo json_encode(['ok'=>false,'error'=>'Deception module unavailable']); exit; }
        if (!checkAccess($conn,'deception')) { echo json_encode(['ok'=>false,'error'=>'You lack the deception permission']); exit; }
        $uid = (int)($_SESSION['UID'] ?? 0);
        $e = nm_heal_event($conn, (int)($body['id']??0));
        if (!$e) { echo json_encode(['ok'=>false,'error'=>'Event not found']); exit; }
        $ip = (string)$e['indicator'];
        if (!filter_var($ip, FILTER_VALIDATE_IP)) { echo json_encode(['ok'=>false,'error'=>'Only IP events can be diverted (a dst-nat needs an IP).']); exit; }
        if (function_exists('session_write_close')) @session_write_close();   // SSH to the router ahead
        echo json_encode(nm_decoy_quick_divert($conn, $ip, $uid)); exit;
    }
    if ($api === 'run')      { echo json_encode(['ok'=>true]+nm_heal_run($conn)); exit; }
    if (!$canConfig) { echo json_encode(['ok'=>false,'error'=>'Configuration access required']); exit; }
    if ($api === 'save_pb') {
        nm_heal_pb_save($conn,(string)($body['pb_key']??''),(string)($body['mode']??'off'),(int)($body['auto_revert_min']??15),(int)($body['threshold']??0));
        nm_audit($conn,'heal.playbook.save',['details'=>['pb'=>$body['pb_key']??'','mode'=>$body['mode']??'']]);
        echo json_encode(['ok'=>true]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'Unknown endpoint']); exit;
}
$counts=nm_heal_counts($conn);
$fwTargets=count(nm_imm_firewall_targets($conn));
log_user_action($conn,'view_page','heal.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Self-Healing | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --heal:#16c79a; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.18; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 40px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; } .card h3{ margin:0 0 12px; font-size:12px; color:var(--accent); text-transform:uppercase; letter-spacing:1px; }
.safety{ background:rgba(243,156,18,.08); border:1px solid rgba(243,156,18,.35); color:#f0c674; border-radius:12px; padding:13px 16px; margin-bottom:16px; font-size:12.5px; line-height:1.6; }
.kpis{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-bottom:16px; }
.kpi{ padding:14px 16px; } .kpi .n{ font-size:26px; font-weight:800; } .kpi .l{ font-size:11px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; }
.pb{ border:1px solid var(--border); border-radius:10px; padding:12px 14px; margin-bottom:10px; }
.pb .t{ display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap; }
.pb .nm{ font-weight:700; } .pb .meta{ font-size:11px; color:#8a909a; margin-top:2px; }
.mode{ font-size:9px; font-weight:800; padding:3px 9px; border-radius:6px; text-transform:uppercase; }
.m-off{ background:rgba(138,144,154,.18); color:#8a909a;} .m-armed{ background:rgba(243,156,18,.18); color:var(--warn);} .m-auto{ background:rgba(231,76,60,.18); color:var(--crit);}
.inp,select{ background:rgba(0,0,0,.4); border:1px solid var(--border); color:#eee; border-radius:8px; padding:7px 9px; font-size:12px; }
.btn{ background:rgba(255,255,255,.06); border:1px solid var(--border); color:#cfd3da; padding:8px 12px; border-radius:8px; cursor:pointer; font-size:12px; display:inline-flex; gap:6px; align-items:center; }
.btn:hover{ background:rgba(255,255,255,.13); color:#fff; } .btn.go{ background:rgba(22,199,154,.18); border-color:var(--heal); color:#6fe3c4;} .btn.go:hover{ background:var(--heal); color:#04140e;}
.btn.danger:hover{ border-color:var(--crit); color:var(--crit);} .row{ display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.ev{ border:1px solid var(--border); border-left-width:4px; border-radius:10px; padding:11px 14px; margin-bottom:9px; }
.ev.active{ border-left-color:var(--crit); background:rgba(231,76,60,.06);} .ev.proposed{ border-left-color:var(--warn); background:rgba(243,156,18,.05);} .ev.reverted{ border-left-color:var(--ok);} .ev.failed{ border-left-color:#888;} .ev.dismissed{ opacity:.5;}
.est{ font-size:9px; font-weight:800; padding:2px 8px; border-radius:5px; text-transform:uppercase; }
.e-active{ background:rgba(231,76,60,.18); color:var(--crit);} .e-proposed{ background:rgba(243,156,18,.18); color:var(--warn);} .e-reverted{ background:rgba(46,204,113,.16); color:var(--ok);} .e-failed{ background:rgba(138,144,154,.18); color:#8a909a;} .e-dismissed{ background:rgba(138,144,154,.12); color:#777;}
.muted{ color:#7c828c; font-size:12px; } .mono{ font-family:Consolas,monospace; }
.btn.why{ border-color:rgba(77,163,255,.4); color:#9fc7f5; } .btn.why:hover{ background:rgba(77,163,255,.15); color:#fff; }
#hl-modal{ position:fixed; inset:0; z-index:6000; display:none; align-items:center; justify-content:center; background:rgba(2,4,8,.68); backdrop-filter:blur(3px); }
#hl-modal.show{ display:flex; }
.hl-card{ width:min(640px,95%); max-height:88%; display:flex; flex-direction:column; background:rgba(12,17,26,.98); border:1px solid rgba(77,163,255,.3); border-radius:14px; box-shadow:0 24px 70px rgba(0,0,0,.7); }
.hl-h{ display:flex; align-items:center; gap:10px; padding:13px 16px; border-bottom:1px solid var(--border); font-weight:700; color:#fff; }
.hl-h .ti{ flex:1; min-width:0; } .hl-h .x{ cursor:pointer; color:#8a909a; font-size:18px; } .hl-h .x:hover{ color:#f0a59d; }
.hl-b{ overflow:auto; padding:14px 16px; font-size:13px; line-height:1.55; }
.hl-kv{ display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:8px; margin-bottom:12px; }
.hl-kv > div{ background:rgba(255,255,255,.04); border:1px solid var(--border); border-radius:9px; padding:8px 10px; }
.hl-kv .k{ font-size:9.5px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; }
.hl-kv .v{ font-size:15px; font-weight:700; margin-top:2px; word-break:break-word; }
.hl-sub{ font-size:10.5px; text-transform:uppercase; letter-spacing:.5px; color:#8a929c; margin:13px 0 6px; display:flex; align-items:center; gap:7px; }
.hl-chip{ display:inline-block; font-family:Consolas,monospace; font-size:11px; background:rgba(77,163,255,.12); border:1px solid rgba(77,163,255,.25); color:#bcd8f5; padding:2px 7px; border-radius:6px; margin:0 4px 4px 0; }
.hl-log{ font-family:Consolas,monospace; font-size:11px; color:#cdd4dd; padding:5px 8px; border:1px solid var(--border); border-left:3px solid var(--crit); border-radius:6px; margin-bottom:5px; white-space:normal; word-break:break-word; }
.hl-log .t{ color:#7c828c; }
.hl-verdict{ border-radius:10px; padding:10px 12px; margin-bottom:12px; font-size:12.5px; line-height:1.55; }
.v-real{ background:rgba(231,76,60,.1); border:1px solid rgba(231,76,60,.35); color:#f0b3ac; }
.v-thin{ background:rgba(243,156,18,.08); border:1px solid rgba(243,156,18,.3); color:#f0c674; }
/* detection→enforcement explainer + tabs + filters + pager */
.hl-explain{ display:flex; gap:9px; align-items:flex-start; font-size:11.5px; line-height:1.5; color:#9aa3ad; background:rgba(77,163,255,.06); border:1px solid rgba(77,163,255,.18); border-radius:9px; padding:9px 12px; margin-bottom:12px; }
.hl-explain i{ color:#5b9ae0; margin-top:2px; }
.hl-tabs{ display:flex; gap:6px; flex-wrap:wrap; margin-bottom:10px; }
.hl-tab{ background:rgba(255,255,255,.03); border:1px solid var(--border); color:#aeb4bd; border-radius:9px; padding:7px 12px; font-size:12px; font-weight:600; cursor:pointer; display:inline-flex; align-items:center; gap:7px; }
.hl-tab:hover{ color:#fff; border-color:rgba(77,163,255,.4); }
.hl-tab.active{ background:rgba(77,163,255,.15); border-color:var(--accent); color:#cfe4ff; }
.hl-tab .cnt{ font-size:10px; background:rgba(255,255,255,.1); border-radius:20px; padding:1px 7px; min-width:12px; text-align:center; }
.hl-tab.active .cnt{ background:rgba(77,163,255,.3); color:#fff; }
.hl-filters{ display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:12px; }
.hl-search{ position:relative; flex:1; min-width:180px; }
.hl-search i{ position:absolute; left:10px; top:50%; transform:translateY(-50%); color:#6b7280; font-size:11px; }
.hl-search input{ width:100%; box-sizing:border-box; background:rgba(0,0,0,.4); border:1px solid var(--border); color:#eee; border-radius:8px; padding:7px 9px 7px 28px; font-size:12px; }
.hl-count{ margin-left:auto; }
.hl-heal{ margin-top:5px; font-size:11.5px; display:flex; align-items:center; gap:6px; }
.hl-heal.ok{ color:#16c79a; } .hl-heal.warn{ color:#f0a559; } .hl-heal.bad{ color:#e88; } .hl-heal.info{ color:#8fb8e8; }
.hl-pager{ display:flex; align-items:center; justify-content:center; gap:14px; margin-top:10px; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-robot"></i>Self-Healing', '', 'Autonomous Response', 'fa-solid fa-robot',
    '<button class="refresh-btn" onclick="runNow(this)"><i class="fas fa-radar"></i> Run now</button>'); ?>

<div class="safety">
  <b><i class="fas fa-shield-halved"></i> Safety model.</b> Every playbook ships <b>OFF</b>. <b>Armed</b> = detect &amp; propose (you approve each action). <b>Autonomous</b> = act immediately, then <b>auto-revert</b> after the timer so a wrong action self-heals — and you can revert manually anytime. Block actions use your <?= $fwTargets ?> configured firewall target<?= $fwTargets==1?'':'s' ?> (Collective Immunity).
</div>

<div class="kpis">
  <div class="glass kpi"><div class="n" style="color:var(--crit)" id="k-active"><?= (int)$counts['active'] ?></div><div class="l">Active healings</div></div>
  <div class="glass kpi"><div class="n" style="color:var(--warn)" id="k-proposed"><?= (int)$counts['proposed'] ?></div><div class="l">Awaiting approval</div></div>
  <div class="glass kpi"><div class="n" id="k-pb">—</div><div class="l">Playbooks enabled</div></div>
</div>

<div class="glass card">
  <h3><i class="fas fa-book-medical"></i> Playbooks</h3>
  <div id="pb-list"><div class="muted">Loading…</div></div>
</div>

<div class="glass card">
  <h3><i class="fas fa-heart-pulse"></i> Healing events</h3>
  <div class="hl-explain">
    <i class="fas fa-circle-info"></i>
    <span>Threats are detected from your devices' <b>logs</b> (a <b>sensor</b> — often the victim server or a router). The block is then <b>enforced</b> where it can stop traffic: an <b>IP</b> block goes to your firewall <a href="immunity.php">enforcement points ↗</a>; a malicious <b>domain</b> goes to every enabled <b>Pi-hole</b>. The sensor and the enforcer are usually <b>different devices — that's normal.</b></span>
  </div>
  <!-- status tabs -->
  <div class="hl-tabs" id="hl-tabs">
    <button class="hl-tab active" data-tab="actionable">Actionable <span class="cnt" id="tc-actionable">0</span></button>
    <button class="hl-tab" data-tab="attention">Needs a router <span class="cnt" id="tc-attention">0</span></button>
    <button class="hl-tab" data-tab="active">Active <span class="cnt" id="tc-active">0</span></button>
    <button class="hl-tab" data-tab="all">All <span class="cnt" id="tc-all">0</span></button>
  </div>
  <!-- filters -->
  <div class="hl-filters">
    <div class="hl-search"><i class="fas fa-magnifying-glass"></i><input id="f-q" type="text" placeholder="Search IP, sensor, detail…" oninput="applyFilters()"></div>
    <select id="f-type" class="inp" onchange="applyFilters()"><option value="">All detectors</option></select>
    <select id="f-status" class="inp" onchange="applyFilters()">
      <option value="">Any status</option><option value="proposed">Proposed</option><option value="active">Active</option><option value="dismissed">Dismissed</option></select>
    <span class="hl-count muted" id="f-count"></span>
  </div>
  <div id="empty" class="muted" style="display:none;padding:8px;">No events match. When a detector fires, proposed/active healings appear here. 🛡️</div>
  <div id="ev-list"></div>
  <div id="hl-pager" class="hl-pager" style="display:none;">
    <button class="btn" id="pg-prev" onclick="pageDelta(-1)"><i class="fas fa-chevron-left"></i></button>
    <span class="muted" id="pg-info"></span>
    <button class="btn" id="pg-next" onclick="pageDelta(1)"><i class="fas fa-chevron-right"></i></button>
  </div>
</div>
</div>

<div id="hl-modal"><div class="hl-card">
  <div class="hl-h"><span class="ti" id="hl-title">Evidence</span><span class="x" onclick="hlClose()"><i class="fas fa-xmark"></i></span></div>
  <div class="hl-b" id="hl-body"></div>
</div></div>

<script>
const CAN=<?= $canConfig?'true':'false' ?>;
let EVENTS={}, ENFORCE=[], ALL_EVENTS=[], CUR_TAB='actionable', PAGE=0; const PAGE_SIZE=25;
const PB_LABEL={portscan:'Port-scan source',ntp_amp:'NTP amplification',l2_loop:'L2 loop / storm',
  ssh_bruteforce:'SSH/RDP brute-force',internal_scan:'Internal host scanning',crypto_mining:'Crypto-mining traffic',
  flood_dos:'SYN/UDP flood (DoS)',web_attack:'Web attack (SQLi/RCE/scanner)'};
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
async function post(api,obj){ return fetch('heal.php?api='+api,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj||{})}).then(r=>r.json()).catch(()=>({ok:false,error:'failed'})); }
function revIn(at){ if(!at)return''; const ms=new Date(String(at).replace(' ','T')+'Z')-Date.now(); if(ms<=0)return'reverting…'; return 'auto-revert in '+Math.ceil(ms/60000)+'m'; }
async function load(){
  const r=await fetch('heal.php?api=data').then(r=>r.json()).catch(()=>null); if(!r||!r.ok)return;
  document.getElementById('k-active').textContent=r.counts.active||0;
  document.getElementById('k-proposed').textContent=r.counts.proposed||0;
  document.getElementById('k-pb').textContent=r.playbooks.filter(p=>p.mode!=='off').length;
  // playbooks
  document.getElementById('pb-list').innerHTML=r.playbooks.map(p=>`<div class="pb"><div class="t">
    <div><span class="nm">${esc(p.name)}</span> <span class="mode m-${p.mode}">${p.mode}</span>
      <div class="meta">detector: ${esc(p.detector)} · action: <b>${esc(p.action)}</b></div></div>
    <div class="row">
      <select class="inp" id="m-${p.pb_key}" ${CAN?'':'disabled'}>${['off','armed','auto'].map(m=>`<option ${p.mode===m?'selected':''}>${m}</option>`).join('')}</select>
      <span class="muted">revert</span><input class="inp" id="rv-${p.pb_key}" value="${p.auto_revert_min}" style="width:54px;" ${CAN?'':'disabled'}><span class="muted">min</span>
      <span class="muted">thr</span><input class="inp" id="th-${p.pb_key}" value="${p.threshold}" style="width:54px;" ${CAN?'':'disabled'}>
      ${CAN?`<button class="btn" onclick="savePb('${p.pb_key}',this)"><i class="fas fa-save"></i></button>`:''}
    </div></div></div>`).join('');
  // events — keep the full set; tabs/filters/pagination render a slice
  EVENTS={}; ENFORCE=r.enforce_points||[]; ALL_EVENTS=r.events||[]; ALL_EVENTS.forEach(e=>EVENTS[e.id]=e);
  // populate detector filter once
  const ft=document.getElementById('f-type');
  if(ft.options.length<=1){ const kinds=[...new Set(ALL_EVENTS.map(e=>e.pb))];
    kinds.forEach(k=>{ const o=document.createElement('option'); o.value=k; o.textContent=PB_LABEL[k]||k; ft.appendChild(o); }); }
  applyFilters();
}
// Which tab an event belongs to. 'attention' = healing can't land at the source yet
// (no firewall enforcement point, or the device that saw it is a router that isn't enabled).
function evTab(e){
  if(e.action==='block_ip'){
    if(!ENFORCE.length) return 'attention';
    if(e.reported_role==='router_off') return 'attention';
  }
  return 'actionable';
}
function tabMatch(e,tab){
  if(tab==='all') return true;
  if(tab==='active') return e.status==='active';
  if(tab==='attention') return evTab(e)==='attention';
  // actionable = ready to act (proposed/active) and healing will land somewhere sensible
  return evTab(e)==='actionable' && (e.status==='proposed'||e.status==='active');
}
function updateTabCounts(){
  ['actionable','attention','active','all'].forEach(t=>{
    const n=ALL_EVENTS.filter(e=>tabMatch(e,t)).length;
    const el=document.getElementById('tc-'+t); if(el) el.textContent=n;
  });
}
function filteredEvents(){
  const q=(document.getElementById('f-q').value||'').toLowerCase().trim();
  const ty=document.getElementById('f-type').value; const stt=document.getElementById('f-status').value;
  return ALL_EVENTS.filter(e=>{
    if(!tabMatch(e,CUR_TAB)) return false;
    if(ty && e.pb!==ty) return false;
    if(stt && e.status!==stt) return false;
    if(q){ const hay=((e.indicator||'')+' '+(e.reported_name||'')+' '+(e.detail||'')+' '+(PB_LABEL[e.pb]||e.pb||'')).toLowerCase(); if(!hay.includes(q)) return false; }
    return true;
  });
}
// per-event healing verdict — honest: sensor (who logged it) ≠ enforcer (the firewall)
function healLine(e){
  if(e.action!=='block_ip') return '';
  if(!ENFORCE.length) return `<div class="hl-heal bad"><i class="fas fa-triangle-exclamation"></i> No firewall enforcement point configured — approving won't block anywhere. <a href="immunity.php">Add one in Immunity ↗</a></div>`;
  if(e.reported_role==='enforced') return `<div class="hl-heal ok"><i class="fas fa-check"></i> Blocks at the source on <b>${esc(e.reported_name)}</b> (an enforcement point).</div>`;
  if(e.reported_role==='router_off') return `<div class="hl-heal warn"><i class="fas fa-triangle-exclamation"></i> Seen by router <b>${esc(e.reported_name)}</b> — not enabled for healing. Block will apply on <b>${ENFORCE.map(esc).join(', ')}</b>; <a href="immunity.php">enable ${esc(e.reported_name)} ↗</a> to block right where the traffic is.</div>`;
  return `<div class="hl-heal info"><i class="fas fa-shield-halved"></i> Blocks on <b>${ENFORCE.map(esc).join(', ')}</b>. Seen by ${esc(e.reported_name||'a sensor')} — a sensor, not a firewall; that's expected.</div>`;
}
function render(){
  updateTabCounts();
  const list=filteredEvents();
  const ev=document.getElementById('ev-list'), em=document.getElementById('empty'), pg=document.getElementById('hl-pager');
  document.getElementById('f-count').textContent=list.length?(list.length+' event'+(list.length===1?'':'s')):'';
  if(!list.length){ ev.innerHTML=''; em.style.display='block'; pg.style.display='none'; return; }
  em.style.display='none';
  const pages=Math.max(1,Math.ceil(list.length/PAGE_SIZE));
  if(PAGE>=pages) PAGE=pages-1; if(PAGE<0) PAGE=0;
  const slice=list.slice(PAGE*PAGE_SIZE,(PAGE+1)*PAGE_SIZE);
  ev.innerHTML=slice.map(e=>{
    let btns=`<button class="btn why" onclick="showEvidence(${e.id})"><i class="fas fa-magnifying-glass"></i> Why?</button> `;
    if(e.status==='proposed') btns+=`<button class="btn go" onclick="approve(${e.id},this)"><i class="fas fa-check"></i> Approve &amp; act</button> ${e.action==='block_ip'?(e.diverted?`<a class="btn" href="deception.php" title="This IP is being diverted — open Deception Grid to watch/promote it" style="text-decoration:none;color:#d9c8ff;border-color:rgba(155,107,255,.5);"><i class="fas fa-mask"></i> Diverted ↗</a> `:`<button class="btn" onclick="divert(${e.id},this)" title="Divert this IP to a honeypot instead of blocking (Deception Grid)"><i class="fas fa-mask"></i> Divert</button> `):''}<button class="btn" onclick="dismiss(${e.id})">Dismiss</button>`;
    else if(e.status==='active') btns+=`<button class="btn danger" onclick="revert(${e.id})"><i class="fas fa-rotate-left"></i> Revert now</button>`;
    return `<div class="ev ${e.status}"><div class="row" style="justify-content:space-between;">
      <div><span class="est e-${e.status}">${e.status}</span>${e.diverted?` <span class="est" style="background:rgba(155,107,255,.18);color:#d9c8ff;" title="This IP is being diverted into a honeypot (Deception Grid)">🎭 diverted</span>`:''} <b>${esc(PB_LABEL[e.pb]||e.pb)}</b> → <span class="mono">${esc(e.indicator)}</span>${e.reported_name?` <span class="muted" style="font-size:11px;"><i class="fas fa-satellite-dish" style="opacity:.6"></i> seen by ${esc(e.reported_name)}</span>`:''}</div>
      <div>${btns}</div></div>
      <div class="muted" style="margin-top:4px;">${esc(e.detail||'')}</div>
      ${healLine(e)}
      ${e.report?`<div style="margin-top:4px;font-size:12.5px;color:#bfe7d8;"><i class="fas fa-robot"></i> ${esc(e.report)}</div>`:''}
      ${e.status==='active'&&e.revert_at?`<div class="muted" style="margin-top:3px;">⏱ ${revIn(e.revert_at)}</div>`:''}
    </div>`;
  }).join('');
  if(pages>1){ pg.style.display='flex'; document.getElementById('pg-info').textContent=`Page ${PAGE+1} of ${pages}`;
    document.getElementById('pg-prev').disabled=PAGE===0; document.getElementById('pg-next').disabled=PAGE>=pages-1; }
  else pg.style.display='none';
}
function applyFilters(){ PAGE=0; render(); }
function pageDelta(d){ PAGE+=d; render(); }
document.querySelectorAll('.hl-tab').forEach(t=>t.addEventListener('click',()=>{
  document.querySelectorAll('.hl-tab').forEach(x=>x.classList.remove('active')); t.classList.add('active');
  CUR_TAB=t.getAttribute('data-tab'); PAGE=0; render();
}));
async function savePb(k,btn){ btn.disabled=true;
  const mode=document.getElementById('m-'+k).value;
  if(mode==='auto' && !confirm('AUTONOMOUS mode: this playbook will act on its own (with auto-revert). Enable?')){ btn.disabled=false; document.getElementById('m-'+k).value='armed'; return; }
  const r=await post('save_pb',{pb_key:k,mode,auto_revert_min:document.getElementById('rv-'+k).value,threshold:document.getElementById('th-'+k).value});
  btn.disabled=false; load(); }
async function approve(id,btn){
  const e=EVENTS[id]||{};
  if(e.action==='block_ip'){
    if(!ENFORCE.length){ if(!confirm('No firewall enforcement point is configured.\n\nApproving will NOT block anywhere. Add a router in Collective Immunity → enforcement points first.\n\nApprove anyway?')) return; }
    else if(e.reported_role==='router_off'){
      if(!confirm('Heads up: this was seen by router "'+(e.reported_name||'another router')+'", which isn\'t enabled for healing.\n\nThe block WILL be applied on: '+ENFORCE.join(', ')+'.\nThat stops it if this traffic passes through those firewall(s). To also block right at the source, enable "'+(e.reported_name||'that router')+'" in Immunity → enforcement points.\n\nApprove the block now?')) return;
    }
  }
  btn.disabled=true; const r=await post('approve',{id}); btn.disabled=false;
  if(!r.ok)alert(r.error||r.report||'Failed'); else if(r.report) alert(r.report); load();
}
async function revert(id){ if(!confirm('Revert this action now?'))return; const r=await post('revert',{id}); if(!r.ok)alert(r.error||'Failed'); load(); }
async function dismiss(id){ await post('dismiss',{id}); load(); }
async function divert(id,btn){
  if(!confirm('Divert this IP into a honeypot (Deception Grid) instead of blocking?\n\nAdds a time-boxed dst-nat on your border router — auto-reverts on the TTL. The attacker is watched instead of blocked.')) return;
  if(btn){ btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i>'; }
  const r=await post('divert',{id});
  if(r.ok) alert('Diverted to honeypot (auto-reverts in '+(r.ttl_min||30)+'m). Watch it in Deception Grid.');
  else alert(r.error||'Divert failed');
  load();
}
async function runNow(btn){ btn.disabled=true; const r=await post('run',{}); btn.disabled=false; alert(r.ok?`Detection ran: ${r.proposed} new event(s), ${r.auto_acted} auto-acted, ${r.auto_reverted} auto-reverted.`:'Failed'); load(); }

/* ── Evidence popup — the raw facts behind a detection ── */
function hlClose(){ document.getElementById('hl-modal').classList.remove('show'); }
document.addEventListener('keydown',e=>{ if(e.key==='Escape') hlClose(); });
document.getElementById('hl-modal').addEventListener('click',e=>{ if(e.target.id==='hl-modal') hlClose(); });
function fLocal(s){ return s?(window.nmLocal?nmLocal(s):s):'—'; }
async function showEvidence(id){
  document.getElementById('hl-title').innerHTML='<i class="fas fa-spinner fa-spin"></i> Loading evidence…';
  document.getElementById('hl-body').innerHTML='<div class="muted">…</div>';
  document.getElementById('hl-modal').classList.add('show');
  let r; try{ r=await fetch('heal.php?api=evidence&id='+id).then(x=>x.json()); }catch(e){ r=null; }
  if(!r||!r.ok){ document.getElementById('hl-body').innerHTML='<div class="muted">Could not load evidence.</div>'; return; }
  const ev=r.evidence||{}; const g=r.geo; const nf=r.netflow||[];
  const loc = g ? (g.private?'Private / internal address':((g.city?g.city+', ':'')+(g.country||'')+(g.asn?' · '+g.asn:''))) : 'Location unknown';
  // verdict: real if the firewall logged it (many ports) OR NetFlow shows the traffic
  const isPortscan = r.pb==='portscan';
  const logReal = (ev.lines>0) && (!isPortscan || (ev.ports&&ev.ports.length>=2));
  const real = logReal || nf.length>0;
  const capt = ev.captured_at ? String(ev.captured_at).replace('T',' ').slice(0,16) : '';
  const atDetect = ev.source==='snapshot';
  // recurrence: is the same indicator STILL logging right now? (independent of the frozen proof)
  const rec = (ev.live_lines>0)
    ? `<span style="color:#ff8f87"><i class="fas fa-circle" style="font-size:7px;vertical-align:middle"></i> Still active — ${ev.live_lines} event(s) in the last 30&nbsp;min.</span>`
    : `<span style="color:#9aa6b4"><i class="fas fa-clock"></i> Not seen in the last 30&nbsp;min (aged out or stopped — normal for an older proposal). The proof above is what triggered it.</span>`;
  const proof = ev.lines>0
    ? `Your firewall logged <b>${ev.lines}</b> matching drop event(s)${atDetect&&capt?` <b>captured at detection</b> (${esc(capt)})`:` in the last ${ev.window_min} min`}${ev.ports&&ev.ports.length?` across <b>${ev.ports.length}</b> distinct ports`:''}${ev.targets&&ev.targets.length?` → target <span class="mono">${esc(ev.targets[0])}</span>`:''}.`
    : (nf.length>0 ? `NetFlow recorded <b>${nf.length}</b> live conversation(s) for this host.` : '');
  const verdict = real
    ? `<div class="hl-verdict v-real"><b><i class="fas fa-triangle-exclamation"></i> Looks real.</b> ${proof} This is recorded activity, not a guess.<div style="margin-top:6px;font-size:12px">${rec}</div></div>`
    : `<div class="hl-verdict v-thin"><b><i class="fas fa-circle-question"></i> Thin evidence.</b> ${ev.captured_at?`Nothing was captured even at detection time — likely a one-off.`:`No firewall logs were preserved for this (older event, pre-snapshot). It may have aged out.`} Safe to dismiss if it doesn't recur.</div>`;
  document.getElementById('hl-title').innerHTML=`<i class="fas fa-shield-virus" style="color:var(--crit)"></i> ${esc(PB_LABEL[r.pb]||r.pb)} <span class="mono" style="font-weight:400">${esc(r.indicator)}</span>`;
  let h=verdict;
  h+=`<div class="hl-kv">
      <div><div class="k">Where it is</div><div class="v" style="font-size:13px">${esc(loc)}</div></div>
      ${r.rdns?`<div><div class="k">Reverse DNS</div><div class="v" style="font-size:12px;font-family:Consolas,monospace">${esc(r.rdns)}</div></div>`:''}
      <div><div class="k">Reported by</div><div class="v" style="font-size:13px" title="${esc((ev.devices||[]).join(', '))}">${(r.reported_names&&r.reported_names.length)?esc(r.reported_names.join(', ')):(ev.devices&&ev.devices.length?esc(ev.devices.join(', ')):'—')}</div></div>
      ${ev.targets&&ev.targets.length?`<div><div class="k">Target</div><div class="v" style="font-size:12px;font-family:Consolas,monospace">${esc(ev.targets.join(', '))}</div></div>`:''}
      <div><div class="k">Drop events</div><div class="v">${ev.lines||0}</div></div>
      ${ev.first?`<div><div class="k">Window</div><div class="v" style="font-size:11px">${esc(fLocal(ev.first))}<br>→ ${esc(fLocal(ev.last))}</div></div>`:''}
    </div>`;
  h+=`<div class="muted" style="margin-bottom:8px;"><b>What it would do:</b> action <span class="mono">${esc(r.action)}</span>. ${r.status==='active'?'Currently APPLIED'+(r.revert_at?` · ${revIn(r.revert_at)}`:''):(r.status==='proposed'?'Proposed — awaiting your approval.':esc(r.status))}</div>`;
  // Which firewall(s) the block lands on — and a warning if the device that SAW it isn't one of them
  if(r.action==='block_ip'){
    const pts=r.enforce_points||[];
    if(!pts.length){
      h+=`<div class="hl-verdict v-thin" style="margin-top:0;"><b><i class="fas fa-triangle-exclamation"></i> No firewall enforcement points configured.</b> Approving this won't block anywhere. Configure routers in <a href="immunity.php">Collective Immunity → Detection &amp; targets ↗</a>.</div>`;
    } else {
      const ev0=EVENTS[id]||{}; const role=ev0.reported_role||'';
      const routerOff = role==='router_off';   // saw it on a router that isn't enabled
      const chipCss = routerOff
        ? 'background:rgba(243,156,18,.12);border-color:rgba(243,156,18,.35);color:#f0c674;'
        : 'background:rgba(22,199,154,.12);border-color:rgba(22,199,154,.3);color:#7fe3c4;';
      h+=`<div class="hl-sub"><i class="fas fa-shield-halved"></i> Block is enforced on</div><div>${pts.map(p=>`<span class="hl-chip" style="${chipCss}">${esc(p)}</span>`).join('')}</div>`;
      if(routerOff){
        h+=`<div class="hl-verdict v-thin" style="margin-top:8px;"><b><i class="fas fa-triangle-exclamation"></i> Blocks on the firewall(s) above — enable the source router for source-blocking.</b> This was seen by <b>${esc((r.reported_names||[]).join(', ')||'another router')}</b>, a managed router that isn't enabled for healing. The block still applies on the enforcement point(s) above and stops the traffic <i>if it passes through them</i>. To block it right where it enters, enable that router under <a href="immunity.php">Immunity → enforcement points ↗</a>.</div>`;
      } else if(role==='sensor'){
        h+=`<div class="muted" style="margin-top:6px;font-size:11.5px;"><i class="fas fa-circle-info"></i> Seen by <b>${esc((r.reported_names||[]).join(', ')||'a sensor')}</b> — a server/host that logged the attack, not a firewall. That's expected: sensors detect, firewalls enforce. A domain threat would instead deploy to your Pi-holes.</div>`;
      }
    }
  }
  if(ev.ports&&ev.ports.length){
    h+=`<div class="hl-sub"><i class="fas fa-bullseye"></i> Distinct ports hit (${ev.ports.length})</div><div>${ev.ports.slice(0,60).map(p=>`<span class="hl-chip">${p}</span>`).join('')}${ev.ports.length>60?' …':''}</div>`;
  }
  if(nf.length){
    h+=`<div class="hl-sub"><i class="fas fa-chart-area"></i> Live NetFlow for this host (last 10m)</div>`;
    h+=nf.map(f=>`<div class="hl-log" style="border-left-color:var(--accent);"><span class="mono">→ ${esc(f.dst)}:${f.port}</span> · <b>${f.mbps}</b> Mbps · ${f.pkts} pkts</div>`).join('');
  }
  h+=`<div class="hl-sub"><i class="fas fa-file-lines"></i> Raw firewall log lines (${(ev.samples||[]).length} of ${ev.lines||0})</div>`;
  h+= (ev.samples&&ev.samples.length)? ev.samples.map(s=>`<div class="hl-log"><span class="t">${esc(fLocal(s.at))} · ${esc(s.dev||'')}</span><br>${esc(s.msg)}</div>`).join('') : '<div class="muted">No raw log lines captured in the window.</div>';
  h+=`<div class="muted" style="margin-top:10px;font-size:11px;">Source: NEURU syslog (your devices\\' own drop/deny logs). For a permanent block use <a href="immunity.php">Collective Immunity ↗</a>.</div>`;
  document.getElementById('hl-body').innerHTML=h;
}
load(); setInterval(load, 20000);
</script>
</body></html>
