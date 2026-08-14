<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU Utilities — UI + control-plane HTTP surface. RBAC: 'utilities'.
// Two request classes:
//   • AGENT API (token header, NO session): enroll / desired / report — the util-agent
//     pulls desired-state + reports. Handled first, before the session gate.
//   • UI (session + checkAccess): page + nodes/node read APIs + config write actions.
// Engine: nm_utilities.php
// ─────────────────────────────────────────────────────────────────────────────
include('connection.php');
require_once('nm_utilities.php');
nm_util_ensure($conn);

$api = $_GET['api'] ?? '';
$hdrTok = $_SERVER['HTTP_X_NEURU_UTIL_TOKEN'] ?? '';

// ── AGENT API (token-authenticated, no session) ──────────────────────────────
if ($hdrTok !== '' || in_array($api, ['enroll','desired','report'], true)) {
    header('Content-Type: application/json; charset=utf-8');
    if (!nm_util_verify($conn, $hdrTok)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'bad token']); exit; }
    $body = json_decode(file_get_contents('php://input'), true);
    if (!is_array($body)) $body = [];
    $uidStr = substr(preg_replace('/[^A-Za-z0-9._:-]/','',(string)($body['uid'] ?? '')),0,64);
    if ($api === 'enroll') {
        echo json_encode(nm_util_register($conn, $uidStr, (string)($body['hostname'] ?? ''), $body)); exit;
    }
    // resolve node by uid for desired/report
    $nid = 0;
    if ($uidStr !== '') { $q=$conn->prepare("SELECT id FROM nm_util_nodes WHERE uid=? LIMIT 1"); $q->bind_param('s',$uidStr); $q->execute();
        if ($row=$q->get_result()->fetch_assoc()) $nid=(int)$row['id']; $q->close(); }
    if (!$nid) { echo json_encode(['ok'=>false,'error'=>'not enrolled']); exit; }
    if ($api === 'desired') { echo json_encode(nm_util_desired($conn, $nid)); exit; }
    if ($api === 'report')  { echo json_encode(nm_util_report($conn, $nid, $body)); exit; }
    echo json_encode(['ok'=>false,'error'=>'unknown agent api']); exit;
}

// ── UI (session-gated) ───────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
require_once('access_control.php');
require_once('nm_chrome.php');
include('logger.php');
if (!checkAccess($conn, 'utilities')) {
    if ($api || ($_POST['action'] ?? '')) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=utilities'); exit;
}
if (function_exists('session_write_close')) @session_write_close();
$uid = (int)($_SESSION['user_id'] ?? 0) ?: null;

$act = $_POST['action'] ?? '';
if ($act !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if ($act === 'set_service') {
        $cfg = json_decode((string)($_POST['config'] ?? '{}'), true) ?: [];
        echo json_encode(nm_util_set_service($conn, (int)($_POST['node_id']??0), (string)($_POST['service']??''), (int)($_POST['enabled']??0), $cfg, $uid)); exit;
    }
    if ($act === 'rotate_token') { echo json_encode(['ok'=>true,'token'=>nm_util_token_rotate($conn)]); exit; }
    if ($act === 'delete_node')  { echo json_encode(nm_util_delete($conn, (int)($_POST['node_id']??0))); exit; }
    if ($act === 'rename_node')  {
        $nid=(int)($_POST['node_id']??0); $name=substr(trim((string)($_POST['name']??'')),0,120);
        if ($nid && $name!==''){ $st=$conn->prepare("UPDATE nm_util_nodes SET name=? WHERE id=?"); $st->bind_param('si',$name,$nid); $st->execute(); }
        echo json_encode(['ok'=>true]); exit;
    }
    if ($act === 'ztp_stage') {
        $vars=['dns'=>(string)($_POST['dns']??''),'ntp'=>(string)($_POST['ntp']??''),'extra'=>(string)($_POST['extra']??'')];
        echo json_encode(nm_util_ztp_stage($conn,(int)($_POST['node_id']??0),(string)($_POST['mac']??''),(string)($_POST['vendor']??'mikrotik'),(string)($_POST['hostname']??''),$vars,$uid)); exit;
    }
    if ($act === 'cmd') {   // queue a wol / iperf / tcp_test / udp_test task for the agent
        $args=json_decode((string)($_POST['args']??'{}'),true) ?: [];
        echo json_encode(nm_util_cmd_queue($conn,(int)($_POST['node_id']??0),(string)($_POST['cmd']??''),$args,$uid)); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'unknown action']); exit;
}
if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if ($api === 'nodes') { echo json_encode(['ok'=>true,'nodes'=>nm_util_nodes($conn),'token'=>nm_util_token_ensure($conn)]); exit; }
    if ($api === 'node') {
        $nid=(int)($_GET['id']??0); $n=nm_util_node($conn,$nid);
        if (!$n) { echo json_encode(['ok'=>false,'error'=>'not found']); exit; }
        echo json_encode(['ok'=>true,'node'=>$n,'services'=>nm_util_node_services($conn,$nid),
            'files'=>nm_util_files($conn,$nid),'events'=>nm_util_events($conn,$nid,60)]); exit;
    }
    if ($api === 'ztp') {
        $vendors=[]; foreach (nm_util_ztp_vendors() as $k=>$v) $vendors[]=['key'=>$k,'label'=>$v['label']];
        echo json_encode(['ok'=>true,'jobs'=>nm_util_ztp_list($conn,(int)($_GET['id']??0)),
            'candidates'=>nm_util_ztp_candidates($conn),'vendors'=>$vendors]); exit;
    }
    if ($api === 'commands') { echo json_encode(['ok'=>true,'commands'=>nm_util_commands_list($conn,(int)($_GET['id']??0),40)]); exit; }
    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}

log_user_action($conn,'view_page','utilities.php');
$NEURU_BASE = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off' ? 'https' : 'http').'://'.($_SERVER['HTTP_HOST'] ?? 'YOUR-NEURU-HOST');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NEURU Utilities</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --purple:#9d6dff; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.16; }
.wrap{ max-width:1280px; margin:0 auto; padding:18px 20px 48px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:8px 14px; font-size:13px; cursor:pointer; }
.btn:hover{ background:rgba(77,163,255,.25); } .btn.ghost{ background:transparent; border-color:var(--border); color:#aab; }
.btn.sm{ padding:3px 10px; font-size:11px; } .btn.danger{ border-color:rgba(231,76,60,.5); color:#ff9c8f; background:rgba(231,76,60,.12); }
.tabs{ display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap; }
.tab{ background:rgba(255,255,255,.05); border:1px solid var(--border); color:#aab; padding:9px 18px; border-radius:10px; cursor:pointer; font-size:13px; font-weight:600; }
.tab.active{ background:rgba(77,163,255,.15); border-color:var(--accent); color:var(--accent); }
.tp{ display:none; } .tp.active{ display:block; }
.hosts{ display:grid; grid-template-columns:repeat(auto-fill,minmax(300px,1fr)); gap:14px; }
.host{ padding:15px 16px; cursor:pointer; } .host.active{ border-color:var(--accent); }
.host .nm{ font-size:16px; font-weight:800; } .host .meta{ font-size:11px; color:#8a909a; margin:3px 0 8px; }
.dot{ display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:6px; }
.dot.on{ background:var(--ok); box-shadow:0 0 8px var(--ok); } .dot.off{ background:#666; }
.muted{ color:#7c828c; font-size:12px; } .mono{ font-family:monospace; }
.svc{ border:1px solid var(--border); border-radius:12px; padding:14px 16px; margin-bottom:12px; background:rgba(255,255,255,.03); }
.svc.on{ border-color:rgba(46,204,113,.4); }
.svc-head{ display:flex; align-items:center; gap:12px; }
.svc-head .ic{ width:38px; height:38px; border-radius:10px; background:rgba(77,163,255,.12); display:flex; align-items:center; justify-content:center; color:var(--accent); font-size:16px; }
.svc-title{ font-size:14.5px; font-weight:700; } .svc-sub{ font-size:11.5px; color:#8a909a; }
.state{ font-size:10px; font-weight:700; padding:2px 8px; border-radius:20px; }
.state.running{ background:rgba(46,204,113,.14); color:#7fe0a3; } .state.stopped{ background:rgba(150,150,160,.14); color:#bcc; }
.state.error{ background:rgba(231,76,60,.16); color:#ff9c8f; }
.switch{ position:relative; width:44px; height:24px; flex:0 0 auto; }
.switch input{ opacity:0; width:0; height:0; } .slider{ position:absolute; inset:0; background:#444; border-radius:24px; cursor:pointer; transition:.2s; }
.slider:before{ content:""; position:absolute; height:18px; width:18px; left:3px; top:3px; background:#fff; border-radius:50%; transition:.2s; }
input:checked+.slider{ background:var(--ok); } input:checked+.slider:before{ transform:translateX(20px); }
.cfg{ margin-top:12px; padding-top:12px; border-top:1px solid var(--border); display:none; }
.cfg.show{ display:block; } .cfg .fld{ margin-bottom:9px; } .cfg label{ display:block; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; margin-bottom:3px; }
.cfg input,.cfg select,.cfg textarea{ width:100%; background:rgba(255,255,255,.06); color:#e6e9ee; border:1px solid var(--border); border-radius:8px; padding:8px 10px; font-size:13px; }
.cfg textarea{ min-height:60px; font-family:monospace; font-size:11px; }
/* Global control styling so NOTHING falls back to the white browser default */
.wrap input:not([type=checkbox]):not([type=radio]), .wrap select, .wrap textarea{
  background:rgba(255,255,255,.05); color:#e6e9ee; border:1px solid var(--border);
  border-radius:8px; padding:8px 11px; font-size:13px; font-family:inherit; }
.wrap input:focus, .wrap select:focus, .wrap textarea:focus{ outline:none; border-color:var(--accent); box-shadow:0 0 0 2px rgba(77,163,255,.18); }
.wrap input::placeholder, .wrap textarea::placeholder{ color:#6a727d; }
.wrap input[type=number]{ -moz-appearance:textfield; }
select,option{ background:#1b2129 !important; color:#e6e9ee; }
/* Tools console */
.tool{ border:1px solid var(--border); border-radius:12px; padding:16px; background:linear-gradient(160deg,rgba(77,163,255,.05),rgba(255,255,255,.02)); }
.tool-h{ display:flex; align-items:center; gap:10px; font-size:14px; font-weight:700; margin-bottom:12px; }
.tool-h .ic{ width:34px; height:34px; border-radius:9px; background:rgba(77,163,255,.12); display:flex; align-items:center; justify-content:center; color:var(--accent); }
.tool .lbl{ font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; margin:0 0 4px; display:block; }
.tool .grid2{ display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:10px; }
.tool .go{ margin-top:12px; width:100%; justify-content:center; display:flex; align-items:center; gap:7px; }
.tool .res{ margin-top:12px; min-height:20px; font-size:12.5px; padding:8px 10px; border-radius:8px; background:rgba(0,0,0,.25); border:1px solid rgba(255,255,255,.06); }
.field label{ font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; margin:0 0 4px; display:block; }
.field input,.field select{ width:100%; }
table{ width:100%; border-collapse:collapse; font-size:12.5px; } th{ text-align:left; font-size:10px; text-transform:uppercase; color:#8a909a; padding:7px 9px; border-bottom:1px solid var(--border); } td{ padding:7px 9px; border-bottom:1px solid rgba(255,255,255,.05); }
.modal-bg{ position:fixed; inset:0; background:rgba(0,0,0,.6); z-index:90; display:none; align-items:flex-start; justify-content:center; padding-top:6vh; }
.modal{ width:640px; max-width:94vw; padding:22px 24px; } pre{ background:rgba(0,0,0,.5); border:1px solid var(--border); border-radius:10px; padding:14px; overflow:auto; font-size:11.5px; color:#cfe4ff; }
.chip{ padding:4px 11px; border-radius:20px; font-size:11.5px; font-weight:700; border:1px solid var(--border); }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-toolbox"></i>NEURU Utilities', '', 'Rescue & provisioning stack', 'fa-solid fa-toolbox',
    '<button class="refresh-btn" onclick="loadNodes()"><i class="fas fa-rotate"></i> Refresh</button>'); ?>

<div class="tabs">
  <div class="tab active" data-t="hosts" onclick="showTab('hosts')"><i class="fas fa-server"></i> Hosts</div>
  <div class="tab" data-t="ztp" onclick="showTab('ztp');loadZtp()"><i class="fas fa-diagram-project"></i> Zero-Touch Provisioning</div>
  <div class="tab" data-t="tools" onclick="showTab('tools');fillToolHosts()"><i class="fas fa-screwdriver-wrench"></i> Tools</div>
  <div class="tab" data-t="deploy" onclick="showTab('deploy');loadDeploy()"><i class="fas fa-rocket"></i> Deploy</div>
</div>

<div id="tp-hosts" class="tp active">
  <div class="hosts" id="hosts"><div class="muted">Loading…</div></div>
  <div class="glass card" id="detail" style="display:none;margin-top:16px;">
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:6px;">
      <h3 style="margin:0;font-size:16px;" id="d-name"></h3>
      <span class="muted mono" id="d-meta"></span>
      <span style="flex:1"></span>
      <button class="btn ghost sm" onclick="renameNode()"><i class="fas fa-pen"></i> Rename</button>
      <button class="btn danger sm" onclick="deleteNode()"><i class="fas fa-trash"></i> Remove</button>
    </div>
    <div class="muted" style="margin-bottom:12px;font-size:12px;">Flip a service on and set its options — the host reconfigures itself within ~20s. You never touch the box.</div>
    <div id="services"></div>
    <details style="margin-top:10px;"><summary class="muted" style="cursor:pointer;">File store &amp; recent events</summary>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:12px;">
        <div><h4 style="font-size:12px;color:var(--accent);margin:0 0 6px;">Files</h4><div id="d-files" class="muted">—</div></div>
        <div><h4 style="font-size:12px;color:var(--accent);margin:0 0 6px;">Events</h4><div id="d-events" class="muted">—</div></div>
      </div>
    </details>
  </div>
</div>

<!-- ── ZERO-TOUCH PROVISIONING ─────────────────────────────────────────────── -->
<div id="tp-ztp" class="tp"><div class="glass card">
  <h3 style="margin:0 0 6px;">Zero-Touch Provisioning</h3>
  <p class="muted" style="margin:0 0 14px;">Generate a per-device bootstrap config and stage it on a utility host — the device pulls it on first boot (via TFTP/HTTP or PXE). MACs are pulled straight from your <b>IPAM DHCP leases</b>.</p>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px 18px;">
    <div class="field"><label>Utility host</label><select id="z-host" onchange="loadZtp()"></select></div>
    <div class="field"><label>Device (from DHCP leases)</label><select id="z-mac"></select></div>
    <div class="field"><label>Vendor</label><select id="z-vendor"></select></div>
    <div class="field"><label>Hostname</label><input id="z-host-name" placeholder="SW-EDGE-01"></div>
    <div class="field"><label>DNS</label><input id="z-dns" placeholder="192.168.0.1"></div>
    <div class="field"><label>NTP</label><input id="z-ntp" placeholder="pool.ntp.org"></div>
  </div>
  <div class="field" style="margin-top:16px;"><label>Extra config (raw, vendor syntax)</label>
  <textarea id="z-extra" style="width:100%;min-height:60px;font-family:monospace;font-size:11.5px;"></textarea></div>
  <div style="margin-top:10px;"><button class="btn" onclick="stageZtp()"><i class="fas fa-wand-magic-sparkles"></i> Stage config</button> <span class="muted" id="z-msg"></span></div>
  <div id="z-preview" style="margin-top:12px;"></div>
  <h4 style="font-size:13px;color:var(--accent);margin:18px 0 6px;">Staged provisioning jobs</h4>
  <div id="z-jobs" class="muted">—</div>
</div></div>

<!-- ── TOOLS ───────────────────────────────────────────────────────────────── -->
<div id="tp-tools" class="tp"><div class="glass card">
  <div style="display:flex;gap:12px;align-items:center;margin-bottom:16px;flex-wrap:wrap;">
    <div class="field" style="min-width:240px;"><label>Run from host</label><select id="t-host"></select></div>
    <span class="muted" style="font-size:11.5px;align-self:flex-end;padding-bottom:8px;"><i class="fas fa-circle-info"></i> Tasks run on the utility host and report back within ~20s.</span>
  </div>
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px;">
    <div class="tool">
      <div class="tool-h"><span class="ic"><i class="fas fa-gauge-high"></i></span> iPerf3 bandwidth</div>
      <div class="field"><label>Target host (iPerf server)</label><input id="ip-target" placeholder="192.168.0.30"></div>
      <div class="grid2">
        <div class="field"><label>Port</label><input id="ip-port" type="number" value="5201"></div>
        <div class="field"><label>Duration (s)</label><input id="ip-dur" type="number" value="5"></div>
      </div>
      <button class="btn go" onclick="runCmd('iperf',{target:val('ip-target'),port:+val('ip-port'),duration:+val('ip-dur')})"><i class="fas fa-play"></i> Run test</button>
      <div class="res muted" id="res-iperf">Ready.</div>
    </div>
    <div class="tool">
      <div class="tool-h"><span class="ic"><i class="fas fa-plug-circle-check"></i></span> Connectivity test</div>
      <div class="field"><label>Host</label><input id="tc-host" placeholder="192.168.0.1"></div>
      <div class="grid2">
        <div class="field"><label>Port</label><input id="tc-port" type="number" placeholder="443"></div>
        <div class="field"><label>Protocol</label><select id="tc-proto"><option value="tcp_test">TCP</option><option value="udp_test">UDP</option></select></div>
      </div>
      <button class="btn go" onclick="runCmd(val('tc-proto'),{host:val('tc-host'),port:+val('tc-port')},'res-conn')"><i class="fas fa-play"></i> Test</button>
      <div class="res muted" id="res-conn">Ready.</div>
    </div>
    <div class="tool">
      <div class="tool-h"><span class="ic"><i class="fas fa-power-off"></i></span> Wake-on-LAN</div>
      <div class="field"><label>Target MAC address</label><input id="wol-mac" placeholder="AA:BB:CC:DD:EE:FF"></div>
      <div class="grid2" style="visibility:hidden;height:0;margin:0;"></div>
      <button class="btn go" onclick="runCmd('wol',{mac:val('wol-mac')})"><i class="fas fa-bolt"></i> Send magic packet</button>
      <div class="res muted" id="res-wol">Ready.</div>
    </div>
  </div>
</div></div>

<div id="tp-deploy" class="tp"><div class="glass card">
  <h3 style="margin:0 0 6px;">Deploy a utility host</h3>
  <p class="muted" style="margin:0 0 12px;">Run this on any Docker host on your network. It enrols with NEURU and appears under <b>Hosts</b> — then you turn services on/off from here. Nothing to configure on the box.</p>
  <div style="display:flex;gap:10px;align-items:center;margin-bottom:10px;">
    <span class="chip">Enrolment token</span><span class="mono" id="tok" style="color:#7fe0a3;"></span>
    <button class="btn ghost sm" onclick="copyTok()"><i class="fas fa-copy"></i> Copy</button>
    <button class="btn ghost sm" onclick="rotateTok()"><i class="fas fa-rotate"></i> Rotate (revokes all)</button>
  </div>
  <pre id="compose"></pre>
  <p class="muted" style="font-size:11.5px;">Prefer 1-click? Use Containers → Portainer to deploy <span class="mono">ghcr.io/hmiranda14/neuru-utilities:latest</span> with these env vars (host networking).</p>
</div></div>
</div>

<script>
let NODES=[], SEL=0, TOKEN='', NODE=null;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function showTab(t){ document.querySelectorAll('.tp').forEach(p=>p.classList.remove('active')); document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));
  document.getElementById('tp-'+t).classList.add('active'); document.querySelector('.tab[data-t="'+t+'"]').classList.add('active'); }
async function post(body){ return fetch('utilities.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body}).then(r=>r.json()).catch(()=>null); }

async function loadNodes(){
  const r=await fetch('utilities.php?api=nodes').then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok)return; NODES=r.nodes; TOKEN=r.token;
  document.getElementById('hosts').innerHTML = NODES.length? NODES.map(n=>`
    <div class="glass host ${n.id==SEL?'active':''}" onclick="selNode(${n.id})">
      <div class="nm"><span class="dot ${n.online?'on':'off'}"></span>${esc(n.name)}</div>
      <div class="meta">${esc(n.ip_address||'')}${n.arch?' · '+esc(n.arch):''}${n.agent_version?' · v'+esc(n.agent_version):''}</div>
      <div><span class="chip">${n.svc_on} service${n.svc_on!=1?'s':''} on</span>
        <span class="chip" style="color:${n.online?'#7fe0a3':'#999'}">${n.online?'online':'offline'}</span></div>
    </div>`).join('')
    : '<div class="glass card muted">No utility hosts yet. Go to <b>Deploy</b> to add one.</div>';
}
async function selNode(id){ SEL=id; loadNodes();
  const r=await fetch('utilities.php?api=node&id='+id).then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok)return; NODE=r;
  document.getElementById('detail').style.display='block';
  document.getElementById('d-name').textContent=r.node.name;
  document.getElementById('d-meta').textContent=(r.node.ip_address||'')+' · rev '+r.node.applied_rev+'/'+r.node.desired_rev;
  document.getElementById('services').innerHTML = r.services.map(svcCard).join('');
  document.getElementById('d-files').innerHTML = r.files.length? '<table><tbody>'+r.files.slice(0,50).map(f=>`<tr><td class="mono">${esc(f.path)}</td><td class="muted">${(f.size/1024|0)} KB</td><td><span class="chip">${esc(f.kind)}</span></td></tr>`).join('')+'</tbody></table>' : '<span class="muted">no files reported</span>';
  document.getElementById('d-events').innerHTML = r.events.length? '<table><tbody>'+r.events.slice(0,30).map(e=>`<tr><td>${esc(e.type)}</td><td class="muted">${esc(e.service||'')}</td><td class="mono">${esc(e.ref||'')}</td><td class="muted">${esc(String(e.created_at).slice(5,16))}</td></tr>`).join('')+'</tbody></table>' : '<span class="muted">no events</span>';
}
function fieldInput(svc,f,val){
  const id=`f_${svc}_${f.key}`;
  if(f.type==='bool') return `<label class="switch" style="width:44px;"><input type="checkbox" id="${id}" ${val?'checked':''}><span class="slider"></span></label>`;
  if(f.type==='textarea') return `<textarea id="${id}">${esc(val||'')}</textarea>`;
  if(f.type==='select') return `<select id="${id}">`+(f.options||[]).map(o=>`<option ${o==val?'selected':''}>${esc(o)}</option>`).join('')+`</select>`;
  const t=f.type==='number'?'number':(f.type==='secret'?'password':'text');
  return `<input id="${id}" type="${t}" value="${esc(val==null?'':val)}" ${f.type==='secret'?'placeholder="•••••• (unchanged)"':''}>`;
}
function svcCard(s){
  const fields = s.fields.map(f=>`<div class="fld"><label>${esc(f.label)}</label>${fieldInput(s.service,f,s.config[f.key])}</div>`).join('');
  return `<div class="svc ${s.enabled?'on':''}" id="svc-${s.service}">
    <div class="svc-head">
      <div class="ic"><i class="fas ${s.icon}"></i></div>
      <div style="flex:1;min-width:0;">
        <div class="svc-title">${esc(s.label)} <span class="muted" style="font-weight:400;font-size:11px;">${esc(s.port)}</span>
          ${s.enabled?`<span class="state ${esc(s.state)}">${esc(s.state)}</span>`:''}
          ${s.last_error?`<span class="state error" title="${esc(s.last_error)}">err</span>`:''}</div>
        <div class="svc-sub">${esc(s.desc)}</div>
      </div>
      <label class="switch"><input type="checkbox" ${s.enabled?'checked':''} onchange="toggleSvc('${s.service}',this.checked)"><span class="slider"></span></label>
      <button class="btn ghost sm" onclick="document.getElementById('cfg-${s.service}').classList.toggle('show')"><i class="fas fa-sliders"></i></button>
    </div>
    <div class="cfg ${s.enabled?'show':''}" id="cfg-${s.service}">${fields}
      <button class="btn sm" style="margin-top:8px;" onclick="saveSvc('${s.service}')"><i class="fas fa-check"></i> Save & apply</button>
      <span class="muted" id="msg-${s.service}" style="margin-left:8px;"></span>
    </div>
  </div>`;
}
function collectCfg(s){
  const out={}; s.fields.forEach(f=>{ const el=document.getElementById(`f_${s.service}_${f.key}`); if(!el)return;
    out[f.key]= f.type==='bool'? (el.checked?1:0) : el.value; }); return out;
}
async function toggleSvc(service,on){
  const s=NODE.services.find(x=>x.service===service);
  const r=await post(new URLSearchParams({action:'set_service',node_id:SEL,service,enabled:on?1:0,config:JSON.stringify(collectCfg(s))}));
  if(r&&r.ok) selNode(SEL);
}
async function saveSvc(service){
  const s=NODE.services.find(x=>x.service===service);
  const en=document.querySelector(`#svc-${service} .svc-head input[type=checkbox]`).checked;
  const m=document.getElementById('msg-'+service); m.textContent='saving…';
  const r=await post(new URLSearchParams({action:'set_service',node_id:SEL,service,enabled:en?1:0,config:JSON.stringify(collectCfg(s))}));
  m.innerHTML = r&&r.ok? '<span style="color:var(--ok)">saved · applying…</span>' : '<span style="color:var(--crit)">failed</span>';
  setTimeout(()=>selNode(SEL),1500);
}
async function renameNode(){ const name=prompt('Host name:',NODE.node.name); if(!name)return; await post(new URLSearchParams({action:'rename_node',node_id:SEL,name})); loadNodes(); selNode(SEL); }
async function deleteNode(){ if(!confirm('Remove this utility host from NEURU? (the container keeps running until you stop it)'))return; await post(new URLSearchParams({action:'delete_node',node_id:SEL})); document.getElementById('detail').style.display='none'; SEL=0; loadNodes(); }

// Deploy tab
function composeText(){
  return `services:
  neuru-utilities:
    image: ghcr.io/hmiranda14/neuru-utilities:latest
    container_name: neuru-utilities
    restart: unless-stopped
    network_mode: host
    environment:
      NEURU_URL: "<?= htmlspecialchars($NEURU_BASE) ?>"
      UTIL_TOKEN: "${TOKEN}"
      # VERIFY_TLS: "0"   # uncomment if NEURU uses a self-signed cert
    volumes:
      - neuru_utils_store:/srv/neuru-utils
volumes:
  neuru_utils_store:`;
}
// ── ZTP ──────────────────────────────────────────────────────────────────────
function hostOptions(sel){ return NODES.map(n=>`<option value="${n.id}" ${n.id==sel?'selected':''}>${esc(n.name)}</option>`).join(''); }
async function loadZtp(){
  if(!NODES.length) await loadNodes();
  const hs=document.getElementById('z-host'); if(!hs.value) hs.innerHTML=hostOptions(SEL||(NODES[0]&&NODES[0].id));
  const nid=+hs.value||SEL||(NODES[0]&&NODES[0].id); if(!nid){document.getElementById('z-jobs').textContent='No utility hosts yet.';return;}
  const r=await fetch('utilities.php?api=ztp&id='+nid).then(r=>r.json()).catch(()=>null); if(!r||!r.ok)return;
  document.getElementById('z-vendor').innerHTML=r.vendors.map(v=>`<option value="${v.key}">${esc(v.label)}</option>`).join('');
  document.getElementById('z-mac').innerHTML='<option value="">— pick or type a MAC —</option>'+r.candidates.map(c=>`<option value="${esc(c.mac)}">${esc(c.mac)} · ${esc(c.ip_address||'')} ${esc(c.hostname||'')}</option>`).join('');
  document.getElementById('z-mac').onchange=function(){ const o=r.candidates.find(c=>c.mac===this.value); if(o&&o.hostname&&!val('z-host-name')) document.getElementById('z-host-name').value=o.hostname; };
  document.getElementById('z-jobs').innerHTML = r.jobs.length? '<table><thead><tr><th>MAC</th><th>Vendor</th><th>Hostname</th><th>Fetch path</th><th>State</th></tr></thead><tbody>'+
    r.jobs.map(j=>`<tr><td class="mono">${esc(j.mac)}</td><td>${esc(j.vendor)}</td><td>${esc(j.hostname||'')}</td><td class="mono">${esc(j.rendered_path||'')}</td>
      <td><span class="state ${j.state==='served'?'running':'stopped'}">${esc(j.state)}</span></td></tr>`).join('')+'</tbody></table>'
    : '<span class="muted">No staged jobs yet.</span>';
}
async function stageZtp(){
  const nid=+val('z-host'); const mac=val('z-mac')||prompt('MAC address:',''); if(!mac)return;
  const m=document.getElementById('z-msg'); m.textContent='staging…';
  const r=await post(new URLSearchParams({action:'ztp_stage',node_id:nid,mac,vendor:val('z-vendor'),hostname:val('z-host-name'),dns:val('z-dns'),ntp:val('z-ntp'),extra:val('z-extra')}));
  if(r&&r.ok){ m.innerHTML='<span style="color:var(--ok)">staged → '+esc(r.path)+'</span>';
    document.getElementById('z-preview').innerHTML='<div class="muted" style="font-size:11px;">Device fetches: <b class="mono">http://&lt;host&gt;:8080/'+esc(r.path)+'</b> (or via TFTP/PXE)</div><pre>'+esc(r.preview)+'</pre>';
    loadZtp(); }
  else m.innerHTML='<span style="color:var(--crit)">'+(r?esc(r.error):'failed')+'</span>';
}
// ── Tools (command channel) ──────────────────────────────────────────────────
function val(id){ return document.getElementById(id).value.trim(); }
function fillToolHosts(){ if(!NODES.length){loadNodes().then(fillToolHosts);return;} document.getElementById('t-host').innerHTML=hostOptions(SEL||(NODES[0]&&NODES[0].id)); }
async function runCmd(cmd,args,boxId){
  const nid=+val('t-host'); boxId=boxId||('res-'+cmd);
  if(!nid){ const b=document.getElementById(boxId); if(b) b.innerHTML='<span style="color:var(--warn)">pick a host first</span>'; return; }
  const box=document.getElementById(boxId); if(box) box.innerHTML='<i class="fas fa-spinner fa-spin"></i> queued — running on host…';
  const r=await post(new URLSearchParams({action:'cmd',node_id:nid,cmd,args:JSON.stringify(args)}));
  if(!r||!r.ok){ if(box) box.innerHTML='<span style="color:var(--crit)">queue failed</span>'; return; }
  pollCmd(nid,r.id,cmd,0,boxId);
}
async function pollCmd(nid,id,cmd,tries,boxId){
  const box=document.getElementById(boxId||('res-'+cmd));
  const r=await fetch('utilities.php?api=commands&id='+nid).then(r=>r.json()).catch(()=>null);
  const c=r&&r.commands&&r.commands.find(x=>x.id==id);
  if(c&&(c.status==='done'||c.status==='error')){
    const res=c.result_json?JSON.parse(c.result_json):{};
    let txt;
    if(cmd==='iperf') txt=res.mbps!=null?`<span style="color:var(--ok)">${res.mbps} Mbps</span>`:`<span style="color:var(--crit)">${esc(res.error||'failed')}</span>`;
    else if(cmd==='wol') txt=res.sent?'<span style="color:var(--ok)">magic packet sent</span>':`<span style="color:var(--crit)">${esc(res.error||'failed')}</span>`;
    else txt=res.open?`<span style="color:var(--ok)">open · ${res.ms} ms</span>`:(res.sent?`<span style="color:var(--ok)">sent${res.replied?' · replied':''}</span>`:`<span style="color:var(--crit)">${esc(res.error||'closed')}</span>`);
    if(box) box.innerHTML=txt; return;
  }
  if(tries>15){ if(box) box.innerHTML='<span class="muted">no response (host offline?)</span>'; return; }
  setTimeout(()=>pollCmd(nid,id,cmd,tries+1,boxId),2000);
}
function loadDeploy(){ document.getElementById('tok').textContent=TOKEN||'(loading…)'; document.getElementById('compose').textContent=composeText(); }
function copyTok(){ navigator.clipboard.writeText(TOKEN); }
async function rotateTok(){ if(!confirm('Rotate the token? Every existing utility host will need the new token to keep talking to NEURU.'))return;
  const r=await post(new URLSearchParams({action:'rotate_token'})); if(r&&r.ok){ TOKEN=r.token; loadDeploy(); } }

loadNodes();
</script>
</body></html>
