<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Router Commander: index (session list + new session + webhook config).
// AI-over-SSH troubleshooting for routers (Python CLI) and linux boxes (n8n bash).
// RBAC: 'router_commander'. See nm_rcflow.php for the engine.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_rcflow.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'router_commander')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=router_commander'); exit;
}
nm_rc_ensure($conn);
if (function_exists('session_write_close')) @session_write_close(); // free session lock before slow SSH/n8n I/O (prevents whole-portal freeze)

$uid = (int)($_SESSION['UID'] ?? 0);
$canConfig = nm_can($conn, 'net_mon_config');

// ── JSON API ─────────────────────────────────────────────────────────────────
if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    $body = json_decode(file_get_contents('php://input'), true) ?? $_POST;

    if ($api === 'create') {
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $problem = trim((string)($body['problem'] ?? ''));
        if ($problem === '') { echo json_encode(['ok'=>false,'error'=>'Describe the problem first.']); exit; }

        $target = (string)($body['target'] ?? 'manual');
        $kind='manual'; $ref=null; $name=''; $host=''; $vendor='generic'; $cred=0;

        if (strpos($target,'device:')===0) {
            $did=(int)substr($target,7);
            $d=$conn->query("SELECT * FROM nm_config_devices WHERE id={$did} LIMIT 1"); $d=$d?$d->fetch_assoc():null;
            if(!$d){ echo json_encode(['ok'=>false,'error'=>'Device not found']); exit; }
            $kind='device'; $ref=$did; $name=$d['name']; $host=$d['host_ip']; $vendor=$d['vendor_key']; $cred=(int)($d['ssh_cred_id']??0);
        } elseif (strpos($target,'node:')===0) {
            $nid=(int)substr($target,5);
            $n=$conn->query("SELECT * FROM nm_nodes WHERE id={$nid} LIMIT 1"); $n=$n?$n->fetch_assoc():null;
            if(!$n){ echo json_encode(['ok'=>false,'error'=>'Node not found']); exit; }
            $kind='node'; $ref=$nid; $name=$n['display_name']; $host=$n['ip_address']; $vendor=nm_cm_guess_vendor($n['os_icon']??''); $cred=(int)($n['ssh_cred_id']??0);
        } else {
            $host=trim((string)($body['host'] ?? '')); $name=trim((string)($body['name'] ?? '')) ?: $host;
            $vendor=trim((string)($body['vendor_key'] ?? 'generic')) ?: 'generic'; $cred=(int)($body['ssh_cred_id'] ?? 0);
            if($host===''){ echo json_encode(['ok'=>false,'error'=>'Host/IP required for a manual target.']); exit; }
        }

        $treq = (string)($body['transport'] ?? 'auto');
        $transport = in_array($treq,['linux','cli','windows'],true) ? $treq : nm_rc_auto_transport($vendor);

        $title = substr($problem, 0, 200);
        $st=$conn->prepare("INSERT INTO nm_rc_sessions (target_kind,target_ref,name,host,vendor_key,transport,ssh_cred_id,title,problem,status,created_by)
                            VALUES (?,?,?,?,?,?,?,?,?, 'open', ?)");
        $credN = $cred ?: null;
        $st->bind_param('sissssissi', $kind,$ref,$name,$host,$vendor,$transport,$credN,$title,$problem,$uid);
        $st->execute(); $sid=$conn->insert_id; $st->close();

        nm_rc_log($conn,$sid,'user',$problem);
        nm_rc_log($conn,$sid,'info',"Session started for {$name} ({$host}) — ".($transport==='linux'?'Linux / n8n bash SSH':($transport==='windows'?'Windows / PowerShell over SSH':'Router CLI / Python SSH')).'.');
        nm_audit($conn,'router.session.start',['target_type'=>'rc_session','target_id'=>$sid,'details'=>['host'=>$host,'vendor'=>$vendor,'transport'=>$transport]]);

        // Auto-launch the first AI turn (best-effort).
        $sess=nm_rc_session($conn,$sid);
        if (nm_rc_setting($conn,'rc_suggest_url','') !== '') {
            nm_rc_log($conn,$sid,'info','Asked the AI to analyze and propose a fix');
            nm_rc_send($conn,$sess,['mode'=>'suggest','message'=>'Analyze the problem described and propose the single next command to run.']);
        }
        echo json_encode(['ok'=>true,'id'=>$sid]); exit;
    }

    if ($api === 'delete') {
        $sid=(int)($body['id'] ?? 0);
        $s=nm_rc_session($conn,$sid); if(!$s){ echo json_encode(['ok'=>false,'error'=>'Not found']); exit; }
        $delKb = !empty($body['delete_kb']);
        $kbId=(int)($s['kb_id']??0);
        if ($kbId>0 && !$delKb) {
            $chk=$conn->query("SELECT id FROM container_kb WHERE id={$kbId} LIMIT 1");
            if ($chk && $chk->num_rows>0) { echo json_encode(['ok'=>false,'kb_referenced'=>true,'error'=>'This session has a saved KB entry. Confirm whether to delete it too.']); exit; }
        }
        if ($kbId>0 && $delKb) $conn->query("DELETE FROM container_kb WHERE id={$kbId}");
        $conn->query("DELETE FROM nm_rc_logs WHERE session_id={$sid}");
        $conn->query("DELETE FROM nm_rc_sessions WHERE id={$sid}");
        nm_audit($conn,'router.session.delete',['target_type'=>'rc_session','target_id'=>$sid]);
        echo json_encode(['ok'=>true,'kb_deleted'=>($kbId>0&&$delKb)]); exit;
    }

    if ($api === 'save_settings') {
        if (!$canConfig) { echo json_encode(['ok'=>false,'error'=>'Not allowed']); exit; }
        $set=function($k,$v)use($conn){ $st=$conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)"); $st->bind_param('ss',$k,$v); $st->execute(); $st->close(); };
        $set('rc_suggest_url', trim((string)($body['rc_suggest_url'] ?? '')));
        $set('rc_execute_url', trim((string)($body['rc_execute_url'] ?? '')));
        nm_audit($conn,'router.settings.save',['target_type'=>'settings']);
        echo json_encode(['ok'=>true]); exit;
    }

    echo json_encode(['ok'=>false,'error'=>'Unknown endpoint']); exit;
}

// ── Page data ────────────────────────────────────────────────────────────────
$vendors = nm_cm_vendors($conn);
$creds=[]; $cr=$conn->query("SELECT id,name,username,auth_type,is_default, (secret_enc IS NOT NULL AND secret_enc<>'') AS has_secret FROM nm_ssh_credentials ORDER BY is_default DESC,name");
while($cr && $x=$cr->fetch_assoc()) $creds[]=$x;
$devices=[]; $dr=$conn->query("SELECT id,name,host_ip,vendor_key,ssh_cred_id FROM nm_config_devices WHERE enabled=1 ORDER BY name");
while($dr && $x=$dr->fetch_assoc()) $devices[]=$x;
$nodes=[]; $nr=$conn->query("SELECT id,display_name,ip_address,os_icon,ssh_cred_id FROM nm_nodes WHERE ip_address IS NOT NULL AND ip_address<>'' ORDER BY display_name LIMIT 500");
while($nr && $x=$nr->fetch_assoc()) $nodes[]=$x;
$sessions=[]; $sr=$conn->query("SELECT id,name,host,vendor_key,transport,status,kb_id,title,updated_at FROM nm_rc_sessions ORDER BY updated_at DESC LIMIT 200");
while($sr && $x=$sr->fetch_assoc()) $sessions[]=$x;

$rc_suggest = nm_rc_setting($conn,'rc_suggest_url','');
$rc_execute = nm_rc_setting($conn,'rc_execute_url','');
$configured = ($rc_suggest !== '');
log_user_action($conn,'view_page','router_commander.php');

function rc_tabs($active){
    nm_module_tabs([
        ['icon'=>'fas fa-list','label'=>'Sessions','href'=>'router_commander.php','active'=>($active==='index')],
    ]);
}
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Adv. Solution Commander | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ai:#9b59b6; --ok:#2ecc71; --warn:#f39c12; --stop:#e74c3c; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.2; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 40px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; } .card h3{ margin:0 0 12px; font-size:12px; color:var(--accent); text-transform:uppercase; letter-spacing:1px; }
.grid2{ display:grid; grid-template-columns:1fr 1fr; gap:16px; } @media(max-width:900px){ .grid2{ grid-template-columns:1fr; } }
label{ display:block; font-size:11px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; margin:10px 0 4px; }
.inp,select,textarea{ width:100%; background:rgba(0,0,0,.4); border:1px solid var(--border); color:#eee; border-radius:9px; padding:9px 11px; font-size:13px; font-family:inherit; }
textarea{ resize:vertical; min-height:74px; }
.btn{ background:rgba(255,255,255,.06); border:1px solid var(--border); color:#cfd3da; padding:9px 14px; border-radius:9px; cursor:pointer; font-size:13px; display:inline-flex; gap:8px; align-items:center; }
.btn:hover{ background:rgba(255,255,255,.13); color:#fff; }
.btn.ai{ background:rgba(155,89,182,.18); border-color:var(--ai); color:#c08fd6; } .btn.ai:hover{ background:var(--ai); color:#fff; }
.row{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
table{ width:100%; border-collapse:collapse; font-size:13px; }
th,td{ text-align:left; padding:9px 10px; border-bottom:1px solid rgba(255,255,255,.07); }
th{ color:#7c828c; font-size:11px; text-transform:uppercase; letter-spacing:.5px; }
.badge{ font-size:9.5px; font-weight:700; padding:2px 8px; border-radius:5px; text-transform:uppercase; }
.b-open{ background:rgba(46,204,113,.16); color:var(--ok);} .b-res{ background:rgba(77,163,255,.16); color:var(--accent);} .b-aba{ background:rgba(138,144,154,.16); color:#8a909a;}
.tp{ font-size:9.5px; font-weight:700; padding:2px 7px; border-radius:5px; }
.tp-cli{ background:rgba(243,156,18,.16); color:var(--warn); } .tp-linux{ background:rgba(13,183,237,.16); color:#0db7ed; } .tp-win{ background:rgba(0,120,212,.18); color:#7fc1ff; }
.warnbox{ background:rgba(243,156,18,.1); border:1px solid rgba(243,156,18,.3); color:#f0c674; border-radius:10px; padding:12px 14px; margin-bottom:14px; font-size:12.5px; }
.muted{ color:#7c828c; font-size:12px; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php
nm_page_header('<i class="fas fa-network-wired"></i>Adv. Solution Commander', '', 'Device Operations', 'fa-solid fa-network-wired',
    '<a class="refresh-btn" href="config_mgr.php"><i class="fas fa-file-shield"></i> Config Manager</a>');
rc_tabs('index');
?>

<?php if (!$configured): ?>
<div class="warnbox"><b>Not configured yet.</b> Set the <b>rc_suggest_url</b> (AI analysis) webhook in <a href="net_mon_config.php?tab=integrations">Config → Integrations &amp; AI → Adv. Solution Commander</a> before starting a session. The <b>rc_execute_url</b> is only needed for Linux targets (routers run over the portal's Python SSH and need no webhook).</div>
<?php endif; ?>

<div class="grid2">
  <!-- New session -->
  <div class="glass card">
    <h3><i class="fas fa-plus"></i> New troubleshooting session</h3>
    <label>Target</label>
    <select class="inp" id="target" onchange="onTarget()">
      <optgroup label="Config Manager devices">
        <?php foreach($devices as $d): ?>
        <option value="device:<?= (int)$d['id'] ?>" data-vendor="<?= htmlspecialchars($d['vendor_key']) ?>" data-cred="<?= (int)($d['ssh_cred_id']??0) ?>">
          <?= htmlspecialchars($d['name'].' — '.$d['host_ip'].' ('.$d['vendor_key'].')') ?></option>
        <?php endforeach; ?>
      </optgroup>
      <optgroup label="Monitored nodes">
        <?php foreach($nodes as $n): ?>
        <option value="node:<?= (int)$n['id'] ?>" data-vendor="<?= htmlspecialchars(nm_cm_guess_vendor($n['os_icon']??'')) ?>" data-cred="<?= (int)($n['ssh_cred_id']??0) ?>">
          <?= htmlspecialchars($n['display_name'].' — '.$n['ip_address']) ?></option>
        <?php endforeach; ?>
      </optgroup>
      <option value="manual">✎ Manual entry…</option>
    </select>

    <div id="manualWrap" style="display:none;">
      <div class="grid2" style="gap:10px;">
        <div><label>Name</label><input class="inp" id="m_name" placeholder="core-router"></div>
        <div><label>Host / IP</label><input class="inp" id="m_host" placeholder="192.168.0.1"></div>
      </div>
    </div>

    <div class="grid2" style="gap:10px;">
      <div><label>Brand / OS</label>
        <select class="inp" id="vendor">
          <?php foreach($vendors as $v): ?><option value="<?= htmlspecialchars($v['vendor_key']) ?>"><?= htmlspecialchars($v['label']) ?></option><?php endforeach; ?>
          <option value="windows">Windows (PowerShell)</option>
        </select>
      </div>
      <div><label>SSH credential</label>
        <select class="inp" id="cred">
          <option value="0">Default credential</option>
          <?php foreach($creds as $c): ?><option value="<?= (int)$c['id'] ?>"><?= htmlspecialchars($c['name'].' ('.$c['username'].')'.($c['has_secret']?'':' ⚠ no secret')) ?></option><?php endforeach; ?>
        </select>
      </div>
    </div>

    <label>Transport</label>
    <select class="inp" id="transport">
      <option value="auto">Auto (by brand) — recommended</option>
      <option value="cli">Force Router CLI (Python SSH)</option>
      <option value="linux">Force Linux (n8n bash SSH)</option>
      <option value="windows">Force Windows (PowerShell over SSH)</option>
    </select>
    <div class="muted" id="tpHint" style="margin-top:5px;"></div>

    <label>Problem</label>
    <textarea id="problem" placeholder="Describe what's wrong (e.g. 'BGP session to upstream is down', 'high CPU on the edge router', 'interface ether3 flapping')…"></textarea>

    <div class="row" style="margin-top:12px;">
      <button class="btn ai" onclick="createSession(this)"><i class="fas fa-wand-magic-sparkles"></i> Start &amp; ask AI</button>
      <span class="muted" id="createMsg"></span>
    </div>
  </div>

  <!-- How it works + integration status (webhooks now live in Config) -->
  <div class="glass card">
    <h3><i class="fas fa-circle-info"></i> How it works</h3>
    <div class="muted" style="line-height:1.7;">
      • <b>Router</b> (MikroTik, Cisco, Juniper…) → the portal runs each command over <b>Python SSH</b> (brand-aware), then n8n only does the AI analysis.<br>
      • <b>Linux box</b> → n8n runs the command over <b>bash SSH</b> and posts the output back.<br>
      • <b>Windows</b> → the portal runs each command as <b>PowerShell over SSH</b> (needs OpenSSH on the box — see the Windows Monitor for setup); n8n only does the AI analysis.<br>
      Every command is approved by you; destructive commands are flagged.
    </div>
    <div style="border-top:1px solid var(--border); margin:14px 0 12px;"></div>
    <h3 style="margin-bottom:8px;"><i class="fas fa-plug"></i> n8n webhooks</h3>
    <div class="row" style="gap:8px;">
      <span class="tp <?= $rc_suggest!==''?'tp-linux':'tp-cli' ?>"><?= $rc_suggest!==''?'rc_suggest ✓':'rc_suggest — not set' ?></span>
      <span class="tp <?= $rc_execute!==''?'tp-linux':'tp-cli' ?>"><?= $rc_execute!==''?'rc_execute ✓':'rc_execute — not set' ?></span>
    </div>
    <div class="muted" style="margin-top:10px;">Configure these in <a href="net_mon_config.php?tab=integrations">Config → Integrations &amp; AI → Adv. Solution Commander</a>.</div>
  </div>
</div>

<!-- Sessions -->
<div class="glass card">
  <h3><i class="fas fa-list"></i> Sessions</h3>
  <?php if(!$sessions): ?><div class="muted">No sessions yet. Start one above.</div>
  <?php else: ?>
  <table>
    <thead><tr><th>Target</th><th>Brand</th><th>Transport</th><th>Status</th><th>Problem</th><th></th></tr></thead>
    <tbody>
    <?php foreach($sessions as $s):
        $bcls=$s['status']==='open'?'b-open':($s['status']==='resolved'?'b-res':'b-aba'); ?>
      <tr>
        <td><a href="router_fix.php?id=<?= (int)$s['id'] ?>"><b><?= htmlspecialchars($s['name']) ?></b></a><br><span class="muted"><?= htmlspecialchars($s['host']) ?></span></td>
        <td><?= htmlspecialchars($s['vendor_key']) ?></td>
        <td><span class="tp <?= $s['transport']==='cli'?'tp-cli':($s['transport']==='windows'?'tp-win':'tp-linux') ?>"><?= $s['transport']==='cli'?'Router CLI':($s['transport']==='windows'?'Windows PS':'Linux bash') ?></span></td>
        <td><span class="badge <?= $bcls ?>"><?= htmlspecialchars($s['status']) ?></span><?= $s['kb_id']?' <span class="badge b-res" title="Saved to KB">📚 KB</span>':'' ?></td>
        <td class="muted" style="max-width:340px;"><?= htmlspecialchars(mb_substr($s['title'],0,90)) ?></td>
        <td class="row" style="justify-content:flex-end;">
          <a class="btn" href="router_fix.php?id=<?= (int)$s['id'] ?>"><i class="fas fa-terminal"></i> Open</a>
          <button class="btn" onclick="delSession(<?= (int)$s['id'] ?>,this)"><i class="fas fa-trash"></i></button>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  <?php endif; ?>
</div>

</div>
<script>
const VEND_AUTO = {linux:'linux',generic:'linux'};  // everything else → cli
function autoTransport(v){ if(v==='windows') return 'windows'; return (v==='linux'||v==='generic') ? 'linux' : 'cli'; }
function onTarget(){
    const sel=document.getElementById('target'); const opt=sel.options[sel.selectedIndex];
    const manual = sel.value==='manual';
    document.getElementById('manualWrap').style.display = manual?'block':'none';
    if(!manual){
        const v=opt.getAttribute('data-vendor')||'generic'; const c=opt.getAttribute('data-cred')||'0';
        document.getElementById('vendor').value=v;
        const cs=document.getElementById('cred'); if([...cs.options].some(o=>o.value===c)) cs.value=c;
    }
    updateHint();
}
function updateHint(){
    const tp=document.getElementById('transport').value; const v=document.getElementById('vendor').value;
    const eff = tp==='auto'?autoTransport(v):tp;
    document.getElementById('tpHint').textContent = eff==='cli'
        ? 'Router CLI → commands run over the portal Python SSH (n8n never SSHes the router).'
        : (eff==='windows'
        ? 'Windows → commands run as PowerShell over SSH from the portal (n8n only does the AI). Needs OpenSSH on the box.'
        : 'Linux → commands run by n8n over bash SSH (needs rc_execute_url).');
}
document.getElementById('transport').addEventListener('change',updateHint);
document.getElementById('vendor').addEventListener('change',updateHint);
async function post(api,obj){ return fetch('router_commander.php?api='+api,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj||{})}).then(r=>r.json()).catch(()=>({ok:false,error:'failed'})); }
async function createSession(btn){
    const sel=document.getElementById('target');
    const payload={ target:sel.value, vendor_key:document.getElementById('vendor').value,
        ssh_cred_id:+document.getElementById('cred').value, transport:document.getElementById('transport').value,
        problem:document.getElementById('problem').value,
        name:document.getElementById('m_name')?.value||'', host:document.getElementById('m_host')?.value||'' };
    if(!payload.problem.trim()){ document.getElementById('createMsg').textContent='Describe the problem first.'; return; }
    btn.disabled=true; document.getElementById('createMsg').textContent='Starting…';
    const r=await post('create',payload); btn.disabled=false;
    if(r.ok){ location.href='router_fix.php?id='+r.id; } else { document.getElementById('createMsg').textContent=r.error||'Failed'; }
}
async function delSession(id,btn){
    if(!confirm('Delete this session?'))return;
    let r=await post('delete',{id});
    if(!r.ok && r.kb_referenced){ if(confirm('This session has a saved KB entry. Delete the KB entry too?\n\nOK = delete KB + session · Cancel = keep session')){ r=await post('delete',{id,delete_kb:1}); } else return; }
    if(r.ok){ btn.closest('tr').remove(); } else alert(r.error||'Failed');
}
onTarget();
// Deep-link preselect: router_commander.php?node=<id>&vendor=windows  (or ?host=<ip>&vendor=windows)
// Optional ?problem=<urlencoded text> prefills the PROBLEM box (used by log_mon.php's
// "Troubleshoot in Solution Center" — drops the selected log lines straight in).
(function(){
  const PRE={ node:<?= (int)($_GET['node']??0) ?>, host:<?= json_encode((string)($_GET['host']??'')) ?>,
              vendor:<?= json_encode(preg_replace('/[^a-zA-Z0-9_]/','',(string)($_GET['vendor']??''))) ?>,
              problem:<?= json_encode((string)($_GET['problem']??'')) ?> };
  if(!PRE.node && !PRE.host && !PRE.problem) return;
  const sel=document.getElementById('target');
  if(PRE.node){ const val='node:'+PRE.node; if([...sel.options].some(o=>o.value===val)){ sel.value=val; onTarget(); } }   // onTarget derives vendor+transport from the node
  else if(PRE.host){ sel.value='manual'; onTarget(); const mh=document.getElementById('m_host'); if(mh) mh.value=PRE.host;
    const mn=document.getElementById('m_name'); if(mn&&!mn.value) mn.value=PRE.host; }
  // explicit ?vendor= overrides whatever the node's os_icon guessed (so the link is reliable)
  if(PRE.vendor){ const ven=document.getElementById('vendor'); if([...ven.options].some(o=>o.value===PRE.vendor)) ven.value=PRE.vendor;
    if(PRE.vendor==='windows') document.getElementById('transport').value='windows'; }
  const pb=document.getElementById('problem');
  if(PRE.problem && pb){ pb.value=PRE.problem; }
  updateHint();
  const card=document.querySelector('.glass.card'); if(card) card.scrollIntoView({behavior:'smooth',block:'start'});
  if(pb){ pb.focus(); if(PRE.problem){ pb.setSelectionRange(pb.value.length, pb.value.length); pb.scrollTop=pb.scrollHeight; } }
})();
</script>
</body></html>
