<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Notification Center 2.0. Channels (16+ types), a Category×Channel
// subscription matrix, escalation ladder, maintenance windows, anti-flood
// (rate-limit / quiet hours), delivery log. Gated by permission 'incidents'.
// ─────────────────────────────────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) session_start();
include_once __DIR__ . '/connection.php';
require_once __DIR__ . '/access_control.php';
require_once __DIR__ . '/nm_notify.php';
require_once __DIR__ . '/nm_chrome.php';

nm_notify_ensure($conn);
if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$CSRF = $_SESSION['csrf_token'];

if (isset($_GET['api']) || isset($_POST['api'])) {
    header('Content-Type: application/json');
    if (empty($_SESSION['username']) || !checkAccess($conn, 'incidents')) { http_response_code(403); echo json_encode(['ok'=>false,'err'=>'Unauthorized']); exit; }
    $api = $_GET['api'] ?? $_POST['api'];
    $isPost = ($_SERVER['REQUEST_METHOD'] === 'POST');
    if ($isPost && (($_POST['csrf'] ?? '') !== $_SESSION['csrf_token'])) { http_response_code(400); echo json_encode(['ok'=>false,'err'=>'Invalid CSRF']); exit; }
    $set = function($k,$v) use ($conn){ $st=$conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=?"); $st->bind_param('sss',$k,$v,$v); $st->execute(); $st->close(); };
    try {
        switch ($api) {
        case 'bootstrap':
            echo json_encode(['ok'=>true,'csrf'=>$CSRF,'settings'=>nm_notify_settings($conn),
                'channels'=>nm_notify_channels2($conn), 'channel_types'=>nm_notify_channel_types(),
                'categories'=>nm_notify_categories(), 'routes'=>nm_notify_routes($conn),
                'health'=>nm_notify_channel_health($conn),
                'steps'=>nm_notify_steps($conn), 'maintenance'=>nm_maint_windows($conn),
                'log'=>nm_notify_log_recent($conn,80)]);
            break;
        case 'settings_save':
            if (!$isPost){ echo json_encode(['ok'=>false,'err'=>'POST']); break; }
            $set('notify_enabled', !empty($_POST['enabled'])?'1':'0');
            $set('notify_min_severity', in_array($_POST['min_severity']??'',['critical','warning','info'],true)?$_POST['min_severity']:'warning');
            $set('notify_resolve_notice', !empty($_POST['resolve_notice'])?'1':'0');
            echo json_encode(['ok'=>true]); break;
        case 'channel_save': {
            if (!$isPost){ echo json_encode(['ok'=>false,'err'=>'POST']); break; }
            $config = [];
            if (isset($_POST['config']) && is_array($_POST['config'])) $config = $_POST['config'];
            echo json_encode(nm_notify_channel_save2($conn,[
                'id'=>$_POST['id']??0,'name'=>$_POST['name']??'','type'=>$_POST['type']??'telegram',
                'config'=>$config,'min_severity'=>$_POST['min_severity']??'warning','enabled'=>!empty($_POST['enabled']),
                'rate_limit_sec'=>$_POST['rate_limit_sec']??0,'quiet_start'=>$_POST['quiet_start']??'','quiet_end'=>$_POST['quiet_end']??''])); break;
        }
        case 'channel_delete':
            if (!$isPost){ echo json_encode(['ok'=>false,'err'=>'POST']); break; }
            nm_notify_channel_delete($conn,(int)($_POST['id']??0)); echo json_encode(['ok'=>true]); break;
        case 'channel_test': {
            $r=nm_notify_test($conn,(int)($_GET['id']??0));
            echo json_encode($r['ok']?['ok'=>true]:['ok'=>false,'err'=>$r['err']??'failed']); break;
        }
        case 'route_set':
            if (!$isPost){ echo json_encode(['ok'=>false,'err'=>'POST']); break; }
            echo json_encode(nm_notify_route_set($conn, $_POST['category']??'', (int)($_POST['channel_id']??0),
                $_POST['min_severity']??'warning', $_POST['mode']??'immediate', !empty($_POST['enabled'])?1:0)); break;
        case 'event_test': {
            // fire a real event through the matrix (proves routing end-to-end)
            if (!$isPost){ echo json_encode(['ok'=>false,'err'=>'POST']); break; }
            $cat = $_POST['category'] ?? 'system'; $sev = $_POST['severity'] ?? 'warning';
            $r = nm_notify_event($conn,$cat,$sev,'Test: '.($_POST['title'] ?? ucfirst($cat).' notification'),
                'Manual test from the Notification Center',['entity'=>'manual-test']);
            echo json_encode($r); break;
        }
        case 'step_save':
            if (!$isPost){ echo json_encode(['ok'=>false,'err'=>'POST']); break; }
            echo json_encode(nm_notify_step_save($conn,['id'=>$_POST['id']??0,'step_order'=>$_POST['after_minutes']??0,'after_minutes'=>$_POST['after_minutes']??0,'channel_id'=>$_POST['channel_id']??0])); break;
        case 'step_delete':
            if (!$isPost){ echo json_encode(['ok'=>false,'err'=>'POST']); break; }
            nm_notify_step_delete($conn,(int)($_POST['id']??0)); echo json_encode(['ok'=>true]); break;
        case 'maint_save':
            if (!$isPost){ echo json_encode(['ok'=>false,'err'=>'POST']); break; }
            echo json_encode(nm_maint_save($conn,['id'=>$_POST['id']??0,'name'=>$_POST['name']??'','starts_at'=>$_POST['starts_at']??'','ends_at'=>$_POST['ends_at']??'','scope'=>$_POST['scope']??'all','scope_val'=>$_POST['scope_val']??'','enabled'=>!empty($_POST['enabled'])])); break;
        case 'maint_delete':
            if (!$isPost){ echo json_encode(['ok'=>false,'err'=>'POST']); break; }
            nm_maint_delete($conn,(int)($_POST['id']??0)); echo json_encode(['ok'=>true]); break;
        case 'run':
            echo json_encode(['ok'=>true] + nm_notify_process($conn) + nm_notify_digest_flush($conn)); break;
        default: http_response_code(400); echo json_encode(['ok'=>false,'err'=>'Unknown']);
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
<title>Notification Center | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
<?= nm_chrome_css() ?>
:root{--glass:rgba(255,255,255,0.07);--border:rgba(255,255,255,0.13);--accent:#4da3ff;--up:#2ecc71;--down:#e74c3c;--warn:#f39c12;--mut:#8a909a;}
body{margin:0;font-family:'Segoe UI',Tahoma,sans-serif;background:#000;color:#fff;overflow-x:hidden;}
.wrap{max-width:1400px;margin:0 auto;padding:18px 22px 60px;}
.glass-card{background:var(--glass);backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:16px;padding:18px 20px;margin-bottom:18px;}
h2{margin:0 0 14px;font-size:14px;color:var(--accent);display:flex;align-items:center;gap:9px;}
.btn{padding:7px 13px;border-radius:8px;border:1px solid var(--border);background:rgba(255,255,255,.05);color:#cfd3da;font-size:12px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:7px;text-decoration:none;}
.btn:hover{border-color:var(--accent);color:#fff;}
.btn-primary{background:rgba(77,163,255,.15);border-color:var(--accent);color:var(--accent);}
.btn-success{background:rgba(46,204,113,.15);border-color:var(--up);color:var(--up);}
.btn-danger{background:rgba(231,76,60,.12);border-color:var(--down);color:var(--down);}
.btn-sm{padding:5px 9px;font-size:11px;}
.form-input,.form-select{background:rgba(255,255,255,.07);border:1px solid var(--border);color:#fff;padding:8px 12px;border-radius:8px;font-size:13px;outline:none;box-sizing:border-box;}
.form-select{background:rgba(20,30,50,.95);}
table{width:100%;border-collapse:collapse;font-size:13px;}
th{text-align:left;color:var(--mut);font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.5px;padding:7px 9px;border-bottom:1px solid var(--border);}
td{padding:8px 9px;border-bottom:1px solid rgba(255,255,255,.05);}
.tag{font-size:10px;padding:2px 8px;border-radius:6px;font-weight:700;background:rgba(77,163,255,.16);color:#7fc0ff;}
.mut{color:var(--mut);} .mono{font-family:ui-monospace,monospace;font-size:11.5px;}
.ok{color:var(--up);} .bad{color:var(--down);} .warnc{color:var(--warn);}
.sw{position:relative;display:inline-block;width:42px;height:23px;}.sw input{opacity:0;width:0;height:0;}
.sw .sl{position:absolute;cursor:pointer;inset:0;background:#3a3f4b;border-radius:23px;transition:.25s;}.sw .sl::before{content:'';position:absolute;width:17px;height:17px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.25s;}
.sw input:checked+.sl{background:var(--up);}.sw input:checked+.sl::before{transform:translateX(19px);}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.72);backdrop-filter:blur(4px);display:none;align-items:flex-start;justify-content:center;z-index:1000;padding:40px 16px;overflow-y:auto;}
.modal-bg.show{display:flex;}.modal{background:#0d1119;border:1px solid var(--border);border-radius:16px;width:100%;max-width:560px;padding:22px 24px;}
.fld{display:flex;flex-direction:column;gap:5px;margin-bottom:12px;}.fld label{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--mut);}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:12px;}.modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:14px;}
.hidden{display:none!important;}
#toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(120%);background:#11151d;border:1px solid var(--border);border-left:4px solid var(--accent);border-radius:10px;padding:12px 18px;font-size:13px;z-index:2000;transition:.3s;max-width:80vw;}#toast.show{transform:translateX(-50%) translateY(0);}
.step{display:flex;align-items:center;gap:12px;padding:10px 12px;border:1px solid var(--border);border-radius:11px;margin-bottom:8px;background:rgba(255,255,255,.03);}
.step .num{width:26px;height:26px;border-radius:50%;background:rgba(77,163,255,.15);color:var(--accent);display:flex;align-items:center;justify-content:center;font-weight:800;font-size:12px;}
/* subscription matrix */
.matrix-wrap{overflow-x:auto;}
.matrix{border-collapse:separate;border-spacing:0;min-width:640px;}
.matrix th.cat{position:sticky;left:0;background:#0b0e15;z-index:2;text-align:left;min-width:200px;}
.matrix td.cat{position:sticky;left:0;background:#0b0e15;z-index:1;}
.matrix th{text-align:center;vertical-align:bottom;padding:8px 6px;}
.chhead{display:flex;flex-direction:column;align-items:center;gap:3px;font-size:10px;color:#cfd3da;}
.chhead i{font-size:15px;color:var(--accent);}
.catcell{display:flex;align-items:center;gap:9px;}
.catcell .ci{width:26px;height:26px;border-radius:7px;background:rgba(77,163,255,.12);display:flex;align-items:center;justify-content:center;color:var(--accent);font-size:12px;}
.catcell .cl{font-size:12.5px;font-weight:600;} .catcell .cg{font-size:9.5px;color:var(--mut);text-transform:uppercase;letter-spacing:.4px;}
.cellsub{display:flex;flex-direction:column;gap:4px;align-items:center;min-width:96px;}
.cellsub select{font-size:10px;padding:3px 4px;width:88px;background:rgba(20,30,50,.95);border:1px solid var(--border);color:#fff;border-radius:6px;}
.cellsub .offlbl{font-size:9.5px;color:var(--mut);}
.grp-row td{background:rgba(255,255,255,.02);font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--mut);font-weight:700;padding:6px 9px;}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;}
.hint{font-size:11px;color:var(--mut);margin-top:8px;}
</style>
</head>
<body>
<div class="wrap">
<?php nm_page_header('Notification Center', '', 'Route every signal, everywhere', 'fa-solid fa-bell'); ?>
<?php nm_module_tabs([
    ['icon'=>'fa-solid fa-table-cells-large','label'=>'Subscriptions','href'=>'#matrix','active'=>true],
    ['icon'=>'fa-solid fa-tower-broadcast','label'=>'Channels','href'=>'#channels','active'=>false],
    ['icon'=>'fa-solid fa-arrow-up-right-dots','label'=>'Escalation','href'=>'#escalation','active'=>false],
    ['icon'=>'fa-solid fa-screwdriver-wrench','label'=>'Maintenance','href'=>'#maintenance','active'=>false],
    ['icon'=>'fa-solid fa-list-check','label'=>'Delivery Log','href'=>'#log','active'=>false],
]); ?>

<!-- global toggle bar -->
<div class="glass-card" style="display:flex;align-items:center;gap:18px;flex-wrap:wrap;">
  <label style="display:flex;align-items:center;gap:9px;"><span class="sw"><input type="checkbox" id="g-enabled"><span class="sl"></span></span><b style="font-size:13px;">Notifications ON</b></label>
  <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:#aaa;">Global floor
    <select class="form-select" id="g-minsev"><option value="critical">Critical only</option><option value="warning">Warning+</option><option value="info">Everything</option></select></label>
  <label style="display:flex;align-items:center;gap:9px;"><span class="sw"><input type="checkbox" id="g-resolve"><span class="sl"></span></span><span style="font-size:12px;color:#aaa;">Send "resolved" notice</span></label>
  <button class="btn btn-success btn-sm" style="margin-left:auto;" onclick="saveSettings()"><i class="fa-solid fa-floppy-disk"></i> Save</button>
  <button class="btn btn-sm" onclick="runNow()" title="Run correlation + delivery now"><i class="fa-solid fa-bolt"></i> Run now</button>
</div>

<!-- SUBSCRIPTIONS MATRIX -->
<section id="tab-matrix">
  <div class="glass-card">
    <h2><i class="fa-solid fa-table-cells-large"></i> Subscription matrix — what goes where</h2>
    <p class="mut" style="font-size:12px;margin:-8px 0 14px;">Each row is an <b>event category</b>; each column a <b>channel</b>. Pick a delivery mode + minimum severity per cell. <b>Now</b> = fire immediately · <b>Digest</b> = batch into a periodic summary · <b>Off</b> = don't send. Incidents always deliver immediately regardless of digest.</p>
    <div id="matrix-empty" class="mut" style="display:none;padding:14px;">Add a channel first (Channels tab), then subscribe categories here.</div>
    <div class="matrix-wrap"><table class="matrix" id="matrix-tbl"></table></div>
    <p class="hint"><i class="fa-solid fa-circle-info"></i> Smart defaults are pre-loaded: criticals (node/DB/site down, security, service) fire immediately; warnings are deduped; event-logs &amp; system news go to a digest.</p>
  </div>
</section>

<!-- CHANNELS -->
<section id="tab-channels" class="hidden">
  <div class="glass-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
      <h2 style="margin:0;"><i class="fa-solid fa-tower-broadcast"></i> Channels</h2>
      <button class="btn btn-primary btn-sm" onclick="chanModal()"><i class="fa-solid fa-plus"></i> Add channel</button>
    </div>
    <table><thead><tr><th>Name</th><th>Type</th><th>Health</th><th>Anti-flood</th><th>Min sev</th><th>On</th><th style="text-align:right;">Actions</th></tr></thead>
    <tbody id="chan-tbody"></tbody></table>
    <p class="hint"><i class="fa-solid fa-circle-info"></i> Supported: Telegram · Email · Slack · Discord · Teams · Mattermost · Google Chat · Gotify · ntfy · Pushover · PagerDuty · Opsgenie · Matrix · SMS/WhatsApp (Twilio) · generic webhook · n8n.</p>
  </div>
</section>

<!-- ESCALATION -->
<section id="tab-escalation" class="hidden">
  <div class="glass-card">
    <h2><i class="fa-solid fa-arrow-up-right-dots"></i> Escalation ladder</h2>
    <p class="mut" style="font-size:12px;margin:-8px 0 14px;">On top of the matrix (which fires immediately), the ladder <b>re-alerts</b> a channel if an incident is <b>still unacknowledged</b> after N minutes — PagerDuty-style. Acknowledging an incident stops it.</p>
    <div id="steps-list"></div>
    <div style="border-top:1px solid var(--border);margin-top:12px;padding-top:14px;display:flex;gap:10px;align-items:end;flex-wrap:wrap;">
      <div class="fld" style="margin:0;"><label>After (minutes)</label><input class="form-input" id="st-min" type="number" value="0" style="width:120px;"></div>
      <div class="fld" style="margin:0;flex:1;min-width:160px;"><label>Notify channel</label><select class="form-select" id="st-chan" style="width:100%;"></select></div>
      <button class="btn btn-success btn-sm" onclick="addStep()"><i class="fa-solid fa-plus"></i> Add step</button>
    </div>
  </div>
</section>

<!-- MAINTENANCE -->
<section id="tab-maintenance" class="hidden">
  <div class="glass-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
      <h2 style="margin:0;"><i class="fa-solid fa-screwdriver-wrench"></i> Maintenance windows</h2>
      <button class="btn btn-primary btn-sm" onclick="maintModal()"><i class="fa-solid fa-plus"></i> Add window</button>
    </div>
    <p class="mut" style="font-size:12px;margin:-4px 0 12px;">During an active window, matching events still correlate but <b>do not notify</b> (logged as suppressed).</p>
    <table><thead><tr><th>Name</th><th>Window</th><th>Scope</th><th>State</th><th style="text-align:right;">Actions</th></tr></thead>
    <tbody id="maint-tbody"></tbody></table>
  </div>
</section>

<!-- LOG -->
<section id="tab-log" class="hidden">
  <div class="glass-card">
    <h2><i class="fa-solid fa-list-check"></i> Delivery log</h2>
    <table><thead><tr><th>Time</th><th>Ref</th><th>Category</th><th>Channel</th><th>Event</th><th>Status</th><th>Detail</th></tr></thead>
    <tbody id="log-tbody"></tbody></table>
  </div>
</section>
</div>

<!-- channel modal -->
<div class="modal-bg" id="chan-modal"><div class="modal">
  <h3 id="cm-title">Add channel</h3><input type="hidden" id="cm-id">
  <div class="row2">
    <div class="fld"><label>Name</label><input class="form-input" id="cm-name" placeholder="Ops Telegram"></div>
    <div class="fld"><label>Type</label><select class="form-select" id="cm-type" onchange="renderChanFields()"></select></div>
  </div>
  <div id="cm-fields"></div>
  <div id="cm-note" class="hint" style="margin:-4px 0 12px;"></div>
  <div class="row2">
    <div class="fld"><label>Minimum severity</label><select class="form-select" id="cm-minsev"><option value="critical">Critical only</option><option value="warning">Warning+</option><option value="info">Everything</option></select></div>
    <div class="fld"><label>Rate-limit (sec, 0=off)</label><input class="form-input" id="cm-rate" type="number" value="0" placeholder="e.g. 300"></div>
  </div>
  <div class="row2">
    <div class="fld"><label>Quiet hours start (HH:MM)</label><input class="form-input" id="cm-qs" placeholder="22:00"></div>
    <div class="fld"><label>Quiet hours end (HH:MM)</label><input class="form-input" id="cm-qe" placeholder="07:00"></div>
  </div>
  <label style="display:flex;align-items:center;gap:9px;"><span class="sw"><input type="checkbox" id="cm-enabled" checked><span class="sl"></span></span><span style="font-size:12px;">Enabled</span></label>
  <div class="modal-actions"><button class="btn" onclick="closeM('chan-modal')">Cancel</button><button class="btn btn-success" onclick="saveChan()">Save</button></div>
</div></div>

<!-- maintenance modal -->
<div class="modal-bg" id="maint-modal"><div class="modal">
  <h3 id="mm-title">Add maintenance window</h3><input type="hidden" id="mm-id">
  <div class="fld"><label>Name</label><input class="form-input" id="mm-name" placeholder="Router firmware upgrade"></div>
  <div class="row2">
    <div class="fld"><label>Starts</label><input class="form-input" id="mm-start" type="datetime-local"></div>
    <div class="fld"><label>Ends</label><input class="form-input" id="mm-end" type="datetime-local"></div>
  </div>
  <div class="row2">
    <div class="fld"><label>Scope</label><select class="form-select" id="mm-scope"><option value="all">All events</option><option value="node">A node (id)</option><option value="source">A source/category</option></select></div>
    <div class="fld"><label>Scope value</label><input class="form-input" id="mm-scopeval" placeholder="node id or category"></div>
  </div>
  <label style="display:flex;align-items:center;gap:9px;"><span class="sw"><input type="checkbox" id="mm-enabled" checked><span class="sl"></span></span><span style="font-size:12px;">Enabled</span></label>
  <div class="modal-actions"><button class="btn" onclick="closeM('maint-modal')">Cancel</button><button class="btn btn-success" onclick="saveMaint()">Save</button></div>
</div></div>

<div id="toast"></div>
<script>
let CSRF='<?= $CSRF ?>', BOOT=null;
function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2800);}
function closeM(id){document.getElementById(id).classList.remove('show');}
async function api(action,data){ let opt={}; if(data){const fd=new FormData();fd.append('api',action);fd.append('csrf',CSRF);
    (function add(pre,o){for(const k in o){const key=pre?pre+'['+k+']':k; const v=o[k]; if(v&&typeof v==='object'&&!(v instanceof File))add(key,v); else fd.append(key,v);}})('',data);
    opt={method:'POST',body:fd};}
  const r=await fetch('notify_admin.php?api='+action,opt); const j=await r.json().catch(()=>({ok:false,err:'bad response'})); if(!r.ok||j.err){toast(j.err||('HTTP '+r.status));throw new Error(j.err);} return j; }
document.querySelectorAll('.nm-tab').forEach(t=>t.addEventListener('click',e=>{e.preventDefault();
  document.querySelectorAll('.nm-tab').forEach(x=>x.classList.remove('is-active'));t.classList.add('is-active');
  const id=t.getAttribute('href').slice(1); ['matrix','channels','escalation','maintenance','log'].forEach(s=>document.getElementById('tab-'+s).classList.toggle('hidden',s!==id)); }));

async function boot(){ BOOT=await api('bootstrap'); CSRF=BOOT.csrf;
  document.getElementById('g-enabled').checked=BOOT.settings.enabled;
  document.getElementById('g-minsev').value=BOOT.settings.min_severity;
  document.getElementById('g-resolve').checked=BOOT.settings.resolve_notice;
  fillTypeSelect(); renderMatrix(); renderChans(); renderSteps(); renderMaint(); renderLog();
}

// ---- subscription matrix ----
function routeFor(cat,cid){ return BOOT.routes.find(r=>r.category===cat && r.channel_id===cid); }
function renderMatrix(){
  const chs=BOOT.channels, cats=BOOT.categories;
  document.getElementById('matrix-empty').style.display = chs.length?'none':'block';
  const T=document.getElementById('matrix-tbl'); if(!chs.length){T.innerHTML='';return;}
  let head='<thead><tr><th class="cat">Category</th>'+chs.map(c=>{
    const ic=(BOOT.channel_types[c.type]||{}).icon||'fa-solid fa-bell';
    return `<th><div class="chhead"><i class="${ic}"></i>${esc(c.name)}</div></th>`;}).join('')+'</tr></thead>';
  // group categories
  const groups={}; for(const k in cats){const g=cats[k][2]; (groups[g]=groups[g]||[]).push(k);}
  let body='<tbody>';
  for(const g in groups){
    body+=`<tr class="grp-row"><td class="cat">${esc(g)}</td>${chs.map(()=>'<td></td>').join('')}</tr>`;
    for(const cat of groups[g]){ const m=cats[cat];
      body+=`<tr><td class="cat"><div class="catcell"><div class="ci"><i class="fa-solid ${esc(m[1])}"></i></div>`+
        `<div><div class="cl">${esc(m[0])}</div><div class="cg">${esc(cat)}</div></div></div></td>`;
      for(const c of chs){ const r=routeFor(cat,c.id);
        const mode=r&&r.enabled?r.mode:'off'; const sev=r?r.min_severity:m[3];
        body+=`<td><div class="cellsub">
          <select onchange="setRoute('${cat}',${c.id},this,'mode')">
            <option value="off"${mode==='off'?' selected':''}>Off</option>
            <option value="immediate"${mode==='immediate'?' selected':''}>Now</option>
            <option value="digest"${mode==='digest'?' selected':''}>Digest</option></select>
          <select onchange="setRoute('${cat}',${c.id},this,'sev')"${mode==='off'?' style="opacity:.4"':''}>
            <option value="critical"${sev==='critical'?' selected':''}>Critical</option>
            <option value="warning"${sev==='warning'?' selected':''}>Warning+</option>
            <option value="info"${sev==='info'?' selected':''}>Info+</option></select>
        </div></td>`;
      }
      body+='</tr>';
    }
  }
  T.innerHTML=head+body+'</tbody>';
}
async function setRoute(cat,cid,el,which){
  const cell=el.closest('.cellsub'); const sels=cell.querySelectorAll('select');
  const mode=sels[0].value, sev=sels[1].value;
  await api('route_set',{category:cat,channel_id:cid,mode:mode,min_severity:sev,enabled:mode==='off'?0:1});
  const r=routeFor(cat,cid);
  if(r){r.mode=mode;r.min_severity=sev;r.enabled=mode==='off'?0:1;} else BOOT.routes.push({category:cat,channel_id:cid,mode:mode,min_severity:sev,enabled:mode==='off'?0:1});
  sels[1].style.opacity=mode==='off'?'.4':'1'; toast('Route updated');
}

// ---- channels ----
function healthBadge(cid){ const h=(BOOT.health||{})[cid]; if(!h) return '<span class="mut">—</span>';
  if(h.fails>=3) return '<span class="bad"><span class="dot" style="background:var(--down)"></span>failing</span>';
  if(h.fails>0) return '<span class="warnc"><span class="dot" style="background:var(--warn)"></span>'+h.fails+' fail</span>';
  return '<span class="ok"><span class="dot" style="background:var(--up)"></span>ok</span>'; }
function renderChans(){
  const tb=document.getElementById('chan-tbody');
  tb.innerHTML = BOOT.channels.length ? BOOT.channels.map(c=>{
    const t=BOOT.channel_types[c.type]||{label:c.type,icon:'fa-solid fa-bell'};
    const af=[]; if(c.rate_limit_sec>0)af.push(c.rate_limit_sec+'s'); if(c.quiet_start&&c.quiet_end)af.push('quiet '+c.quiet_start+'-'+c.quiet_end);
    return `<tr>
    <td><b>${esc(c.name)}</b></td>
    <td><span class="tag"><i class="${t.icon}"></i> ${esc(t.label)}</span></td>
    <td>${healthBadge(c.id)}</td>
    <td class="mut" style="font-size:11px;">${af.length?esc(af.join(' · ')):'—'}</td>
    <td class="mut">${esc(c.min_severity)}</td>
    <td>${c.enabled?'<span class="ok">●</span>':'<span class="mut">○</span>'}</td>
    <td style="text-align:right;white-space:nowrap;">
      <button class="btn btn-sm" title="Send test" onclick="testChan(${c.id},this)"><i class="fa-solid fa-paper-plane"></i></button>
      <button class="btn btn-sm" title="Edit" onclick="chanModal(${c.id})"><i class="fa-solid fa-pen"></i></button>
      <button class="btn btn-sm btn-danger" title="Delete" onclick="delChan(${c.id},'${esc(c.name)}')"><i class="fa-solid fa-trash"></i></button></td></tr>`;}).join('')
    : '<tr><td colspan="7" class="mut" style="text-align:center;padding:18px;">No channels — add one.</td></tr>';
  const sel=document.getElementById('st-chan'); sel.innerHTML=BOOT.channels.map(c=>`<option value="${c.id}">${esc(c.name)} (${esc(c.type)})</option>`).join('');
}
function fillTypeSelect(){
  const sel=document.getElementById('cm-type'); const groups={};
  for(const k in BOOT.channel_types){const t=BOOT.channel_types[k];(groups[t.group]=groups[t.group]||[]).push([k,t.label]);}
  sel.innerHTML=Object.keys(groups).map(g=>`<optgroup label="${esc(g)}">`+groups[g].map(([k,l])=>`<option value="${k}">${esc(l)}</option>`).join('')+'</optgroup>').join('');
}
function renderChanFields(){
  const type=document.getElementById('cm-type').value; const t=BOOT.channel_types[type]||{fields:[]};
  const c=window._editChan; const box=document.getElementById('cm-fields');
  box.innerHTML=(t.fields||[]).map(f=>{ const [k,label,kind,ph,req]=f;
    const isSec=kind==='secret';
    const val=(c&&!isSec)?(c.config[k]||''):'';
    const has=(c&&isSec)?(c.flags['has_'+k]):false;
    return `<div class="fld"><label>${esc(label)}${req?' *':''}</label>
      <input class="form-input" data-cfg="${esc(k)}" type="${isSec?'password':'text'}" value="${esc(val)}"
        placeholder="${has?'•••• (unchanged)':esc(ph||'')}" ${isSec?'autocomplete="new-password"':''}></div>`;}).join('');
  document.getElementById('cm-note').textContent=t.note||'';
}
function chanModal(id){ const c=BOOT.channels.find(x=>x.id===id); window._editChan=c||null;
  document.getElementById('cm-id').value=id||''; document.getElementById('cm-title').textContent=id?'Edit channel':'Add channel';
  document.getElementById('cm-name').value=c?c.name:''; document.getElementById('cm-type').value=c?c.type:'telegram';
  document.getElementById('cm-minsev').value=c?c.min_severity:'warning';
  document.getElementById('cm-rate').value=c?c.rate_limit_sec:0;
  document.getElementById('cm-qs').value=c?c.quiet_start:''; document.getElementById('cm-qe').value=c?c.quiet_end:'';
  document.getElementById('cm-enabled').checked=c?c.enabled:true;
  renderChanFields(); document.getElementById('chan-modal').classList.add('show');
}
async function saveChan(){ const config={};
  document.querySelectorAll('#cm-fields [data-cfg]').forEach(i=>{ if(i.value!=='' || i.type!=='password') config[i.getAttribute('data-cfg')]=i.value; });
  await api('channel_save',{id:document.getElementById('cm-id').value,name:document.getElementById('cm-name').value.trim(),
    type:document.getElementById('cm-type').value,config:config,min_severity:document.getElementById('cm-minsev').value,
    rate_limit_sec:document.getElementById('cm-rate').value||0,quiet_start:document.getElementById('cm-qs').value.trim(),
    quiet_end:document.getElementById('cm-qe').value.trim(),enabled:document.getElementById('cm-enabled').checked?1:''});
  toast('Saved'); closeM('chan-modal'); boot(); }
async function delChan(id,name){ if(!confirm('Delete channel "'+name+'"? Its subscriptions are removed too.'))return; await api('channel_delete',{id}); toast('Deleted'); boot(); }
async function testChan(id,btn){ btn.innerHTML='<i class="fa-solid fa-circle-notch fa-spin"></i>'; const r=await fetch('notify_admin.php?api=channel_test&id='+id).then(r=>r.json()).catch(()=>({ok:false})); btn.innerHTML='<i class="fa-solid fa-paper-plane"></i>'; toast(r.ok?'Test sent ✓ — check the channel':('Test failed: '+(r.err||'?'))); }

// ---- steps ----
function renderSteps(){
  const box=document.getElementById('steps-list');
  box.innerHTML = BOOT.steps.length ? BOOT.steps.map((s,i)=>`<div class="step">
    <span class="num">${i+1}</span>
    <div style="flex:1;"><b>${s.after_minutes==0?'Immediately on open':('After '+s.after_minutes+' min if unacknowledged')}</b>
      <div class="mut" style="font-size:11.5px;">→ ${esc(s.channel_name||'(deleted channel)')} ${s.type?('· '+esc(s.type)):''}</div></div>
    <button class="btn btn-sm btn-danger" onclick="delStep(${s.id})"><i class="fa-solid fa-trash"></i></button></div>`).join('')
    : '<div class="mut" style="padding:10px;">No ladder steps. The matrix already fires immediately; add a step to <b>re-alert</b> unacked incidents later.</div>';
}
async function addStep(){ const ch=document.getElementById('st-chan').value; if(!ch){toast('Add a channel first');return;}
  await api('step_save',{after_minutes:document.getElementById('st-min').value,channel_id:ch}); toast('Step added'); boot(); }
async function delStep(id){ await api('step_delete',{id}); boot(); }

// ---- maintenance ----
function renderMaint(){
  document.getElementById('maint-tbody').innerHTML = BOOT.maintenance.length ? BOOT.maintenance.map(m=>`<tr>
    <td><b>${esc(m.name)}</b></td><td class="mono" style="font-size:11px;">${esc(m.starts_at)} → ${esc(m.ends_at)}</td>
    <td>${esc(m.scope)}${m.scope_val?(' : '+esc(m.scope_val)):''}</td>
    <td>${m.active==1?'<span class="tag" style="background:rgba(243,156,18,.2);color:#f39c12;">ACTIVE</span>':(m.enabled==1?'<span class="mut">scheduled</span>':'<span class="mut">off</span>')}</td>
    <td style="text-align:right;white-space:nowrap;"><button class="btn btn-sm" onclick="maintModal(${m.id})"><i class="fa-solid fa-pen"></i></button>
      <button class="btn btn-sm btn-danger" onclick="delMaint(${m.id})"><i class="fa-solid fa-trash"></i></button></td></tr>`).join('')
    : '<tr><td colspan="5" class="mut" style="text-align:center;padding:18px;">No maintenance windows.</td></tr>';
}
function maintModal(id){ const m=BOOT.maintenance.find(x=>x.id==id);
  document.getElementById('mm-id').value=id||''; document.getElementById('mm-title').textContent=id?'Edit window':'Add maintenance window';
  document.getElementById('mm-name').value=m?m.name:''; document.getElementById('mm-start').value=m?(m.starts_at||'').replace(' ','T').slice(0,16):'';
  document.getElementById('mm-end').value=m?(m.ends_at||'').replace(' ','T').slice(0,16):''; document.getElementById('mm-scope').value=m?m.scope:'all';
  document.getElementById('mm-scopeval').value=m?m.scope_val||'':''; document.getElementById('mm-enabled').checked=m?m.enabled==1:true;
  document.getElementById('maint-modal').classList.add('show');
}
async function saveMaint(){ await api('maint_save',{id:document.getElementById('mm-id').value,name:document.getElementById('mm-name').value.trim(),
  starts_at:document.getElementById('mm-start').value.replace('T',' '),ends_at:document.getElementById('mm-end').value.replace('T',' '),
  scope:document.getElementById('mm-scope').value,scope_val:document.getElementById('mm-scopeval').value.trim(),enabled:document.getElementById('mm-enabled').checked?1:''}); toast('Saved'); closeM('maint-modal'); boot(); }
async function delMaint(id){ if(!confirm('Delete this window?'))return; await api('maint_delete',{id}); boot(); }

// ---- log ----
function renderLog(){
  document.getElementById('log-tbody').innerHTML = BOOT.log.length ? BOOT.log.map(l=>`<tr>
    <td class="mono mut">${esc((window.nmLocal?nmLocal(l.sent_at):(l.sent_at||'')).slice(5,16))}</td>
    <td class="mono">${l.incident_id&&l.incident_id!='0'?('#'+esc(l.incident_id)):'<span class="mut">—</span>'}</td>
    <td class="mut" style="font-size:11px;">${esc(l.category||'-')}</td>
    <td>${esc(l.channel_name||'-')}</td><td><span class="tag">${esc(l.event)}</span></td>
    <td class="${l.status==='sent'?'ok':(l.status==='suppressed'?'mut':'bad')}">${esc(l.status)}</td>
    <td class="mut" style="font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis;">${esc(l.detail||'')}</td></tr>`).join('')
    : '<tr><td colspan="7" class="mut" style="text-align:center;padding:18px;">Nothing sent yet.</td></tr>';
}

async function saveSettings(){ await api('settings_save',{enabled:document.getElementById('g-enabled').checked?1:'',min_severity:document.getElementById('g-minsev').value,resolve_notice:document.getElementById('g-resolve').checked?1:''}); toast('Saved'); }
async function runNow(){ const r=await api('run'); toast('Sent '+(r.sent||0)+(r.digests_sent?(' · '+r.digests_sent+' digest'):'')+(r.suppressed?(' · '+r.suppressed+' suppressed'):'')); boot(); }

document.querySelectorAll('.modal-bg').forEach(m=>m.addEventListener('click',e=>{if(e.target===m)m.classList.remove('show');}));
boot();
</script>
</body></html>
