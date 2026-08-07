<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Updates (Site Configuration). Check the NEURU License Portal for new
// releases your license entitles you to, download + cryptographically verify them
// (SHA-256 + Ed25519 against the embedded portal public key), and apply with a
// backup + rollback. Engine: nm_update.php. Admin-only.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_update.php');
require_once('nm_audit.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'update')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=update'); exit;
}
$isAdmin = (($_SESSION['role'] ?? '') === 'admin');
nm_update_ensure_dir();

if ($api !== '') {
    if (function_exists('session_write_close')) @session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    $body = json_decode(file_get_contents('php://input'), true) ?: $_POST;
    $needAdmin = function() use ($isAdmin){ if(!$isAdmin){ echo json_encode(['ok'=>false,'error'=>'admin only']); exit; } };
    try {
        if ($api === 'status') {
            $staged = nm_update_staged($conn);
            echo json_encode(['ok'=>true,
                'version'   => nm_update_current_version($conn),
                'channel'   => nm_update_channel($conn),
                'policy'    => nm_update_policy($conn),
                'api_url'   => rtrim(nm_lic_api_base($conn), '/'),
                'activated' => (bool)(nm_lic_row($conn)['license_key'] ?? ''),
                'last_check'=> nm_update_get($conn, 'update_last_check', ''),
                'last'      => nm_update_last($conn),
                'staged'    => $staged ? ['version'=>$staged['version'],'sha256'=>$staged['sha256'],'size'=>$staged['size'] ?? null,'at'=>$staged['at'] ?? null] : null,
                'can_web_apply' => nm_update_can_apply_in_web(),
                'reboot_pending'=> nm_update_reboot_pending($conn),
                'history'   => nm_update_history($conn),
            ]); exit;
        }
        if ($api === 'check') { echo json_encode(nm_update_check($conn)); exit; }
        if ($api === 'set_channel') { $needAdmin(); $c = ($body['channel'] ?? 'stable')==='beta'?'beta':'stable'; nm_update_set($conn,'update_channel',$c); nm_audit_safe($conn,'update.channel',['channel'=>$c]); echo json_encode(['ok'=>true,'channel'=>$c]); exit; }
        if ($api === 'set_policy')  { $needAdmin(); $p = in_array($body['policy']??'',['manual','notify','auto'],true)?$body['policy']:'manual'; nm_update_set($conn,'update_policy',$p); nm_audit_safe($conn,'update.policy',['policy'=>$p]); echo json_encode(['ok'=>true,'policy'=>$p]); exit; }
        if ($api === 'download')    { $needAdmin(); echo json_encode(nm_update_download($conn, (string)($body['version'] ?? ''))); exit; }
        if ($api === 'clear')       { $needAdmin(); nm_update_clear_staged($conn); echo json_encode(['ok'=>true]); exit; }
        if ($api === 'apply')       { $needAdmin(); echo json_encode(nm_update_apply($conn, !empty($body['dry_run']))); exit; }
        echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
    } catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>$e->getMessage()]); exit; }
}

include('header.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
html{background:#05080f} body{margin:0;font-family:'Segoe UI',Tahoma,sans-serif;background:transparent!important;color:#d4dce8}
<?= nm_chrome_css() ?>
.up{max-width:960px;margin:0 auto;padding:20px 22px 60px}
.glass{background:rgba(12,16,26,.62);backdrop-filter:blur(13px);border:1px solid rgba(255,255,255,.12);border-radius:14px}
.bar{display:flex;align-items:center;gap:12px;padding:14px 18px;margin-bottom:16px}
.title{font-size:19px;font-weight:800;display:flex;align-items:center;gap:11px}.title i{color:#36e3d0}
.card{padding:20px 22px;margin-bottom:16px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-top:6px}
.kv{background:rgba(0,0,0,.25);border:1px solid rgba(255,255,255,.08);border-radius:11px;padding:12px 14px}
.kv .l{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:#7f93af}.kv .v{font-size:16px;font-weight:700;color:#e6edf7;margin-top:3px;word-break:break-word}
label{display:block;font-size:10.5px;text-transform:uppercase;letter-spacing:.4px;color:#8b95a7;margin:14px 0 6px}
.sel{background:rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.12);color:#e6edf7;border-radius:9px;padding:9px 12px;font-size:13px;font-family:inherit}
.mono{font-family:Consolas,monospace}
.btn{display:inline-flex;align-items:center;gap:8px;background:rgba(77,163,255,.14);border:1px solid rgba(77,163,255,.4);color:#cfe4ff;border-radius:9px;padding:10px 16px;font-size:13px;cursor:pointer;font-weight:600}
.btn:hover{border-color:#4da3ff;color:#fff}.btn.g{background:linear-gradient(135deg,#36e3d0,#4da3ff);border:none;color:#04121a;font-weight:700}.btn.warn{background:linear-gradient(135deg,#f0a92c,#ff8a3d);border:none;color:#1a1206;font-weight:700}.btn.danger{border-color:rgba(255,90,90,.45);color:#ff9b91}.btn:disabled{opacity:.5;cursor:not-allowed}
.muted{color:#8a97ab;font-size:13px}.hint{font-size:12px;color:#7f93af;margin-top:6px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.note{background:rgba(77,163,255,.06);border:1px solid rgba(77,163,255,.22);border-radius:11px;padding:12px 14px;font-size:12.5px;color:#a8c4e8;margin-top:14px}
.pill{font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.5px;padding:3px 10px;border-radius:20px}
.pill.ok{background:rgba(46,230,110,.14);border:1px solid rgba(46,230,110,.4);color:#8ff0b6}
.pill.up{background:rgba(240,169,44,.14);border:1px solid rgba(240,169,44,.45);color:#ffd98a}
.pill.beta{background:rgba(168,132,255,.16);border:1px solid rgba(168,132,255,.45);color:#d3c0ff}
.verify{display:flex;align-items:center;gap:8px;font-size:12.5px;color:#8ff0b6;margin-top:8px}
pre.notes{background:rgba(0,0,0,.3);border:1px solid rgba(255,255,255,.08);border-radius:10px;padding:12px 14px;font-size:12.5px;color:#cdd6e2;white-space:pre-wrap;max-height:200px;overflow:auto}
table.hist{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:8px}
table.hist th{text-align:left;color:#7f93af;font-size:10px;text-transform:uppercase;padding:6px 8px}
table.hist td{padding:7px 8px;border-top:1px solid rgba(255,255,255,.06)}
</style>
<div class="up">
  <div class="bar glass">
    <div class="title"><i class="fa-solid fa-cloud-arrow-down"></i> Updates</div>
    <span class="muted mono" id="appv">—</span>
    <span style="flex:1"></span>
    <button class="btn g" id="btn-chk" onclick="chk()"><i class="fa-solid fa-magnifying-glass"></i> Check for updates</button>
  </div>

  <!-- prominent live status banner -->
  <div class="glass" id="status" style="display:none;padding:14px 18px;margin-bottom:16px;font-size:14px"></div>

  <!-- restart-required banner — shown after an update is applied, until the containers are restarted -->
  <div class="glass card" id="reboot" style="display:none;border:1px solid rgba(255,180,60,.4);background:rgba(255,170,40,.06);margin-bottom:16px"></div>

  <div class="glass card">
    <div class="grid2">
      <div class="kv"><div class="l">Installed version</div><div class="v mono" id="kv-ver">—</div></div>
      <div class="kv"><div class="l">Channel</div><div class="v" id="kv-chan">—</div></div>
      <div class="kv"><div class="l">Update policy</div><div class="v" id="kv-policy">—</div></div>
      <div class="kv"><div class="l">Last checked</div><div class="v" id="kv-last" style="font-size:13px">—</div></div>
    </div>
    <?php if ($isAdmin): ?>
    <div class="row" style="margin-top:16px">
      <div><label>Release channel</label>
        <select class="sel" id="sel-chan" onchange="setChan()">
          <option value="stable">Stable (recommended)</option>
          <option value="beta">Beta (early builds)</option>
        </select></div>
      <div><label>Update policy</label>
        <select class="sel" id="sel-policy" onchange="setPolicy()">
          <option value="manual">Manual — I check &amp; apply</option>
          <option value="notify">Notify — cron checks, banner me</option>
          <option value="auto">Auto — apply patches in maintenance</option>
        </select></div>
    </div>
    <?php endif; ?>
    <div class="note" id="apinote" style="display:none"></div>
  </div>

  <!-- update available / up to date -->
  <div class="glass card" id="avail" style="display:none"></div>

  <!-- staged (verified, ready to apply) -->
  <div class="glass card" id="staged" style="display:none"></div>

  <!-- history -->
  <div class="glass card">
    <div class="title" style="font-size:15px"><i class="fa-solid fa-clock-rotate-left"></i> Update history</div>
    <div id="hist"><div class="muted" style="margin-top:8px">No updates applied yet.</div></div>
  </div>
</div>

<script>
const IS_ADMIN = <?= $isAdmin ? 'true':'false' ?>;
const api = (a,b)=>fetch('update.php?api='+a,{method:b?'POST':'GET',headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):undefined}).then(r=>r.json());
const esc = s => (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const kb = n => n==null?'—':(n<1048576?Math.round(n/1024)+' KB':(n/1048576).toFixed(1)+' MB');
let LATEST = null;

// prominent status banner. kind: 'load' | 'ok' | 'err' | 'info' (true→ok, false→err for compat)
function note(msg, kind){
  if(kind===true) kind='ok'; if(kind===false) kind='err';
  const n=document.getElementById('status'); n.style.display='block';
  const map={load:['#bcd8ff','rgba(77,163,255,.10)','rgba(77,163,255,.3)','fa-circle-notch fa-spin'],
             ok:['#8ff0b6','rgba(46,230,110,.10)','rgba(46,230,110,.35)','fa-circle-check'],
             err:['#ffb0a8','rgba(255,90,90,.10)','rgba(255,90,90,.35)','fa-triangle-exclamation'],
             info:['#a8c4e8','rgba(77,163,255,.08)','rgba(77,163,255,.22)','fa-circle-info']}[kind||'info'];
  n.style.color=map[0]; n.style.background=map[1]; n.style.border='1px solid '+map[2];
  n.innerHTML='<i class="fa-solid '+map[3]+'" style="margin-right:9px"></i>'+esc(msg);
}

// Restart-required banner: an update's files are live but the containers haven't restarted, so the
// entrypoint hasn't re-run its self-heal AND the WireGuard sidecar hasn't reconnected the tunnel the
// Flows ride on. Order matters — neuru-wg shares neuru-web's netns → restart web first, then wg.
function rebootBanner(ver){
  const el=document.getElementById('reboot'); el.style.display='block';
  el.innerHTML = `<div class="title" style="font-size:15px;color:#ffd98a"><i class="fa-solid fa-power-off"></i> Restart required to finish v${esc(ver)}</div>
    <div class="muted" style="margin:8px 0 10px">The new files are live, but the <b>containers must be restarted</b> so the entrypoint re-runs its self-heal (cron permissions &amp; DB access) and the <b>WireGuard tunnel reconnects</b> — NEURU <b>Flows won't work until WG reconnects</b>.</div>
    <div style="margin-bottom:6px"><b>Order matters</b> — <span class="mono">neuru-wg</span> shares <span class="mono">neuru-web</span>'s network namespace, so restart <b>web first, then wg</b>:</div>
    <pre class="notes">1)  docker restart neuru-web     # app + entrypoint self-heal (crons / permissions)
2)  docker restart neuru-wg      # reconnects the WireGuard tunnel → Flows work again

# or, in one line (kept in order):
docker restart neuru-web && docker restart neuru-wg</pre>
    <div class="hint">Run on the host where NEURU's containers live. This notice clears itself once the containers have restarted.</div>`;
}

function render(s){
  document.getElementById('appv').textContent = 'v'+s.version;
  document.getElementById('kv-ver').textContent = s.version;
  document.getElementById('kv-chan').innerHTML = s.channel==='beta'?'<span class="pill beta">beta</span>':'stable';
  document.getElementById('kv-policy').textContent = s.policy;
  document.getElementById('kv-last').textContent = s.last_check ? new Date(s.last_check).toLocaleString() : 'never';
  if(IS_ADMIN){ document.getElementById('sel-chan').value=s.channel; document.getElementById('sel-policy').value=s.policy; }
  if(!s.activated){ note('Not activated — set your Portal URL & license key in Licensing first.',false); }
  // staged card
  const sd=document.getElementById('staged');
  if(s.staged){
    sd.style.display='block';
    sd.innerHTML = `<div class="title" style="font-size:15px"><i class="fa-solid fa-box-open" style="color:#ffd98a"></i> Verified build staged: v${esc(s.staged.version)}</div>
      <div class="verify"><i class="fa-solid fa-shield-halved"></i> SHA-256 + Ed25519 signature verified · ${kb(s.staged.size)}</div>
      <div class="row" style="margin-top:14px">
        ${IS_ADMIN?`<button class="btn warn" onclick="apply()"><i class="fa-solid fa-bolt"></i> Apply update</button>
        <button class="btn danger" onclick="clr()"><i class="fa-solid fa-trash"></i> Discard</button>`:'<span class="muted">Admin applies updates.</span>'}
      </div>
      ${s.can_web_apply?'':'<div class="note" style="margin-top:12px"><b>Hands-off:</b> the app dir isn\'t web-writable (normal for a bind-mount), so a background root task applies the update for you — <b>~1 minute, no command to run</b>.</div>'}`;
  } else sd.style.display='none';
  // history
  if(s.history && s.history.length){
    let h='<table class="hist"><tr><th>When</th><th>From → To</th><th>Result</th></tr>';
    s.history.forEach(x=>h+=`<tr><td class="muted">${new Date(x.at).toLocaleString()}</td><td class="mono">${esc(x.from)} → ${esc(x.to)}</td><td><span class="pill ${x.result==='applied'?'ok':'up'}">${esc(x.result)}</span></td></tr>`);
    document.getElementById('hist').innerHTML = h+'</table>';
  }
  // show cached last result
  if(s.last) showAvail(s.last, s.version);
  // restart-required banner (applied update awaiting a container restart)
  if(s.reboot_pending) rebootBanner(s.reboot_pending);
  else document.getElementById('reboot').style.display='none';
}

// numeric dotted-version compare: returns true if a > b (e.g. verGt('0.1.1.58','0.1.1.57'))
function verGt(a,b){ const pa=String(a==null?'':a).split('.').map(n=>parseInt(n,10)||0), pb=String(b==null?'':b).split('.').map(n=>parseInt(n,10)||0);
  for(let i=0;i<Math.max(pa.length,pb.length);i++){ const x=pa[i]||0,y=pb[i]||0; if(x!==y) return x>y; } return false; }

function showAvail(r, cur){
  const a=document.getElementById('avail'); a.style.display='block';
  // Guard against a STALE cached check: never offer an update to a version we're already on (or past).
  // After an in-place update the pre-update check result can linger ("available vX" for the version we
  // just installed) — only show Download when the offered version is strictly newer than installed.
  if(r.update_available && cur && !verGt(r.version, cur)){ r = {ok:true, update_available:false, latest:r.version}; }
  if(r.update_available){
    LATEST=r;
    a.innerHTML = `<div class="row"><span class="pill up"><i class="fa-solid fa-arrow-up"></i> Update available</span>
      <span style="font-size:20px;font-weight:800" class="mono">v${esc(r.version)}</span>
      ${r.channel==='beta'?'<span class="pill beta">beta</span>':''}</div>
      ${r.notes?`<label>Release notes</label><pre class="notes">${esc(r.notes)}</pre>`:''}
      <div class="muted" style="margin-top:8px">Size ${kb(r.size)} · SHA-256 <span class="mono">${esc((r.sha256||'').slice(0,20))}…</span></div>
      <div class="row" style="margin-top:14px">
        ${IS_ADMIN?`<button class="btn g" onclick="dl('${esc(r.version)}')"><i class="fa-solid fa-download"></i> Download &amp; verify</button>`:'<span class="muted">Admin downloads updates.</span>'}
      </div>`;
  } else {
    a.innerHTML = `<div class="row"><span class="pill ok"><i class="fa-solid fa-check"></i> Up to date</span>
      <span class="muted">You're running the latest build your license entitles you to${r.latest?` — latest available is <b class="mono">v${esc(r.latest)}</b>`:''}. Nothing to install.</span></div>
      <div class="hint">Tip: newer early builds may be on the <b>beta</b> channel — switch it above to include them.</div>`;
  }
}

async function load(){ const s=await api('status'); if(s.ok) render(s); }
async function chk(){
  const b=document.getElementById('btn-chk'), orig=b.innerHTML;
  b.disabled=true; b.innerHTML='<i class="fa-solid fa-circle-notch fa-spin"></i> Checking…';
  note('Contacting your license portal…','load');
  try{
    const r=await api('check');
    if(r.ok===false){ note((r.error||'Could not reach the portal.')+' — check Licensing (Portal URL + license key).','err'); }
    else if(r.update_available){ note('Update found — v'+r.version+' is available for your license. Review it below.','ok'); showAvail(r); }
    else if(r.note==='no_eligible_release'){ note('You are up to date — no newer '+(r.channel||'stable')+' build is available for your license.','ok'); showAvail(r, r.current); }
    else { note('You are up to date'+(r.latest?' (latest: v'+r.latest+')':'')+'.','ok'); showAvail(r, r.current); }
  }catch(e){ note('Check failed: '+e.message,'err'); }
  finally{ b.disabled=false; b.innerHTML=orig; load(); }
}
async function dl(v){ note('Downloading & verifying v'+v+'… (this can take a moment)',true); const r=await api('download',{version:v}); if(r.ok){ note('Downloaded & cryptographically verified ✓',true); load(); } else note(r.error||'download failed',false); }
async function apply(){ if(!confirm('Apply the staged update? A backup is taken first and the app is swapped in.')) return; note('Applying…',true); const r=await api('apply',{});
  if(r.scheduled){ note('Update verified — NEURU is applying it automatically in the background (~1 min). This page refreshes when it\'s done…','load'); pollApply(r.version,0); }
  else if(r.ok){ note('Applied ✓ '+(r.note||''),true); load(); }
  else if(r.need_script){ note('Manual apply required — run: '+r.command,false); }
  else note(r.error||'apply failed',false); }
// wait for the background root worker to finish: poll status until installed version == target
async function pollApply(target,tries){ const s=await api('status');
  if(s.ok && s.version===target){ note('Updated to v'+target+' ✓ — applied automatically.',true); render(s); return; }
  if(tries>40){ note('Still applying — it can take a minute or two on a slow disk. This page will keep checking.','info'); if(s.ok) render(s); setTimeout(()=>pollApply(target,tries+1),8000); return; }
  setTimeout(()=>pollApply(target,tries+1),5000); }
async function clr(){ if(!confirm('Discard the staged build?'))return; await api('clear',{}); note('Discarded.',true); load(); }
async function setChan(){ const v=document.getElementById('sel-chan').value; await api('set_channel',{channel:v}); note('Channel set to '+v,true); load(); }
async function setPolicy(){ const v=document.getElementById('sel-policy').value; await api('set_policy',{policy:v}); note('Policy set to '+v,true); }
load();
</script>
