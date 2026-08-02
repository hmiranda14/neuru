<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Forensic AI Archaeologist UI. Recurring cross-domain coincidences
// ("ghosts in the machine"), statistical + AI-enriched. RBAC: 'archaeology'.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_archaeology.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'archaeology')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=archaeology'); exit;
}
nm_arch_ensure($conn);
if (function_exists('session_write_close')) @session_write_close(); // free session lock before slow SSH/n8n I/O (prevents whole-portal freeze)

$canConfig = nm_can($conn,'net_mon_config');

if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    $body = json_decode(file_get_contents('php://input'), true) ?? $_POST;
    $shape=fn($f)=>['id'=>(int)$f['id'],'title'=>$f['title'],'conf'=>(int)$f['confidence'],'support'=>(int)$f['support'],'lag'=>(float)$f['avg_lag_min'],
        'hypothesis'=>$f['hypothesis'],'fix'=>$f['suggested_fix'],'evidence'=>$f['evidence'],'source'=>$f['source'],'status'=>$f['status'],'updated_at'=>$f['updated_at']];
    if ($api === 'data') {
        echo json_encode(['ok'=>true,'findings'=>array_map($shape, nm_arch_list($conn)),
            'counts'=>nm_arch_counts($conn), 'last_run'=>nm_arch_setting($conn,'arch_last_run','')]); exit;
    }
    if ($api === 'dismissed') { echo json_encode(['ok'=>true,'findings'=>array_map($shape, nm_arch_dismissed($conn))]); exit; }
    if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
    if ($api === 'run')     { echo json_encode(['ok'=>true]+nm_arch_run($conn)); exit; }
    if ($api === 'ack')     { nm_arch_set_status($conn,(int)($body['id']??0),'ack'); echo json_encode(['ok'=>true]); exit; }
    if ($api === 'dismiss') { nm_arch_set_status($conn,(int)($body['id']??0),'dismissed'); echo json_encode(['ok'=>true]); exit; }
    if ($api === 'reopen')  { nm_arch_set_status($conn,(int)($body['id']??0),'open'); echo json_encode(['ok'=>true]); exit; }
    if ($api === 'save_settings') {
        if(!$canConfig){ echo json_encode(['ok'=>false,'error'=>'Not allowed']); exit; }
        $set=function($k,$v)use($conn){ $st=$conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)"); $st->bind_param('ss',$k,$v); $st->execute(); };
        $set('arch_webhook_url',trim((string)($body['arch_webhook_url']??'')));
        $set('arch_window_days',(string)max(1,(int)($body['arch_window_days']??7)));
        $set('arch_min_support',(string)max(2,(int)($body['arch_min_support']??3)));
        echo json_encode(['ok'=>true]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'Unknown endpoint']); exit;
}
$S=['url'=>nm_arch_setting($conn,'arch_webhook_url',''),'win'=>nm_arch_setting($conn,'arch_window_days','7'),'sup'=>nm_arch_setting($conn,'arch_min_support','3')];
log_user_action($conn,'view_page','archaeology.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Archaeologist | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --ai:#9b59b6; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.18; }
.wrap{ max-width:1200px; margin:0 auto; padding:18px 20px 40px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; } .card h3{ margin:0 0 12px; font-size:12px; color:var(--accent); text-transform:uppercase; letter-spacing:1px; }
.grid2{ display:grid; grid-template-columns:1.7fr 1fr; gap:16px; } @media(max-width:900px){ .grid2{ grid-template-columns:1fr; } }
.f{ border:1px solid var(--border); border-left-width:4px; border-radius:10px; padding:13px 15px; margin-bottom:11px; }
.f.ai{ border-left-color:var(--ai); background:rgba(155,89,182,.05);} .f.stat{ border-left-color:var(--accent);}
.f .t{ display:flex; justify-content:space-between; align-items:baseline; gap:10px; } .f .ti{ font-weight:700; font-size:13.5px; }
.src{ font-size:8.5px; font-weight:800; padding:2px 7px; border-radius:5px; text-transform:uppercase; } .s-ai{ background:rgba(155,89,182,.2); color:#c08fd6;} .s-stat{ background:rgba(77,163,255,.16); color:var(--accent);}
.bar{ height:6px; border-radius:4px; background:rgba(255,255,255,.08); overflow:hidden; margin:8px 0; } .bar>i{ display:block; height:100%; background:linear-gradient(90deg,#9b59b6,#4da3ff); }
.hyp{ font-size:12.5px; color:#cbb6e0; margin-top:6px; } .fix{ font-size:12.5px; color:#9fdcb6; margin-top:5px; }
.ev{ font-size:11px; color:#8a909a; font-family:Consolas,monospace; margin-top:6px; line-height:1.6; }
.btn{ background:rgba(255,255,255,.06); border:1px solid var(--border); color:#cfd3da; padding:6px 11px; border-radius:7px; cursor:pointer; font-size:11px; }
.btn:hover{ background:rgba(255,255,255,.13); color:#fff; }
.inp{ width:100%; background:rgba(0,0,0,.4); border:1px solid var(--border); color:#eee; border-radius:8px; padding:8px 10px; font-size:12.5px; }
label{ display:block; font-size:11px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; margin:10px 0 4px; }
.muted{ color:#7c828c; font-size:12px; }
.arch-meta{ display:flex; align-items:center; gap:14px; font-size:11.5px; margin:2px 0 12px; flex-wrap:wrap; }
.arch-link{ cursor:pointer; color:var(--accent); }
.arch-sec{ font-size:11px; text-transform:uppercase; letter-spacing:.6px; color:#8a909a; margin:14px 0 9px; cursor:pointer; user-select:none; display:flex; align-items:center; gap:7px; }
.pilln{ background:rgba(255,255,255,.1); border-radius:10px; padding:1px 7px; font-size:10px; color:#cfd3da; }
.f.ackd{ opacity:.6; }
.badge-ack{ font-size:8.5px; font-weight:800; padding:2px 7px; border-radius:5px; background:rgba(46,204,113,.18); color:#7fe0a3; text-transform:uppercase; }
.badge-dism{ font-size:8.5px; font-weight:800; padding:2px 7px; border-radius:5px; background:rgba(255,255,255,.1); color:#99a; text-transform:uppercase; }
.btn.ok{ border-color:rgba(46,204,113,.4); color:#7fe0a3; } .btn.ok:hover{ background:rgba(46,204,113,.15); color:#bff2d2; }
#arch-toast{ position:fixed; right:18px; bottom:18px; z-index:9999; display:flex; flex-direction:column; gap:8px; }
.toast{ background:rgba(20,26,38,.96); border:1px solid var(--border); border-left:3px solid var(--accent); border-radius:8px; padding:10px 14px; font-size:12.5px; color:#e6e9ee; box-shadow:0 8px 30px rgba(0,0,0,.5); animation:tin .22s ease; min-width:190px; display:flex; align-items:center; gap:6px; }
.toast.ok{ border-left-color:#2ecc71; } .toast.warn{ border-left-color:#f39c12; }
.toast .undo{ cursor:pointer; color:var(--accent); margin-left:auto; font-weight:600; }
@keyframes tin{ from{ transform:translateY(8px); opacity:0; } }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-magnifying-glass-chart"></i>AI Archaeologist', '', 'Ghosts in the Machine', 'fa-solid fa-magnifying-glass-chart',
    '<button class="refresh-btn" onclick="runNow(this)"><i class="fas fa-flask"></i> Analyze now</button>'); ?>

<div class="grid2">
  <div class="glass card">
    <h3><i class="fas fa-ghost"></i> Recurring cross-domain patterns</h3>
    <p class="muted" style="margin:0 0 10px;">Coincidences a human would never cross-reference — NEURU finds the statistics, the AI explains the <i>why</i>. Higher confidence = more recurring + consistent lag.</p>
    <div id="meta" class="arch-meta">
      <span id="m-counts" class="muted"></span>
      <span id="m-last" class="muted" title="Last analysis run"></span>
      <span style="flex:1;"></span>
      <a id="m-dism" class="arch-link" onclick="toggleDismissed()" style="display:none;"></a>
    </div>
    <div id="empty" class="muted" style="display:none;padding:8px;">No recurring patterns above threshold yet. NEURU needs a few overlapping events (config changes, incidents, alerts) within the window. Click <b>Analyze now</b> to mine the last <?= (int)$S['win'] ?> days. 🔬</div>
    <div id="list"><div class="muted">Loading…</div></div>
    <div id="ackwrap" style="display:none;">
      <div class="arch-sec" onclick="toggleAck()"><i class="fas fa-chevron-down" id="ack-caret"></i> Acknowledged <span id="ack-n" class="pilln"></span></div>
      <div id="acklist"></div>
    </div>
    <div id="dismwrap" style="display:none;">
      <div class="arch-sec" style="cursor:default;"><i class="fas fa-trash-can"></i> Dismissed <span class="muted" style="font-weight:400;text-transform:none;letter-spacing:0;">— reopen to bring any back</span></div>
      <div id="dismlist"><div class="muted">Loading…</div></div>
    </div>
  </div>
  <div class="glass card">
    <h3><i class="fas fa-robot"></i> AI enrichment (n8n)</h3>
    <div id="ai-status" class="muted" style="margin:0 0 8px;padding:8px 10px;border-radius:8px;background:rgba(255,255,255,.03);border:1px solid var(--border);font-size:12px;">…</div>
    <p class="muted" style="margin:0 0 8px;"><b>Optional.</b> With a webhook, the strongest candidates get an AI hypothesis + suggested fix. Without it you still get the raw statistical patterns (the <span class="src s-stat" style="font-size:8px;">STAT</span> findings on the left) — the page is fully functional without n8n.</p>
    <label>arch_webhook_url</label>
    <input class="inp" id="s-url" value="<?= htmlspecialchars($S['url']) ?>" placeholder="http://192.168.0.25:5678/webhook/archaeology-analyze" <?= $canConfig?'':'disabled' ?>>
    <div style="display:flex;gap:8px;"><div style="flex:1;"><label>Window (days)</label><input class="inp" id="s-win" value="<?= htmlspecialchars($S['win']) ?>" <?= $canConfig?'':'disabled' ?>></div>
      <div style="flex:1;"><label>Min support</label><input class="inp" id="s-sup" value="<?= htmlspecialchars($S['sup']) ?>" <?= $canConfig?'':'disabled' ?>></div></div>
    <?php if($canConfig): ?><div style="margin-top:10px;"><button class="btn" onclick="saveSettings(this)"><i class="fas fa-save"></i> Save</button> <span class="muted" id="s-msg"></span></div><?php endif; ?>
    <div class="muted" style="margin-top:12px;border-top:1px solid var(--border);padding-top:10px;line-height:1.6;">
      <b>n8n contract:</b> NEURU POSTs <code>{window_days, candidates:[…], findings_url}</code>. Your AI flow ranks/explains the candidates and POSTs <code>{findings:[{pattern_key,title,confidence,hypothesis,suggested_fix}]}</code> to <code>nm_archaeology_api.php?ep=findings</code> (X-NetMon-Token).
    </div>
  </div>
</div>
</div>
<script>
const CAN=<?= $canConfig?'true':'false' ?>;
const HAS_AI=<?= $S['url']!==''?'true':'false' ?>;
let ACK_OPEN=false, DISM_OPEN=false;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
async function post(api,obj){ return fetch('archaeology.php?api='+api,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj||{})}).then(r=>r.json()).catch(()=>({ok:false,error:'failed'})); }
function evHtml(j){ try{ const a=JSON.parse(j); if(!Array.isArray(a))return''; return a.slice(0,3).map(e=>`${esc(e.a||'')} → ${esc(e.b||'')} <span style="opacity:.7">(${esc(e.lag||'')} later${e.at?', '+esc(e.at):''})</span>`).join('<br>'); }catch(_){ return esc(j||''); } }
function ago(ts){ if(!ts) return 'never'; const d=(Date.now()-new Date(String(ts).replace(' ','T')).getTime())/1000; if(isNaN(d))return ts; if(d<60)return 'just now'; if(d<3600)return Math.floor(d/60)+'m ago'; if(d<86400)return Math.floor(d/3600)+'h ago'; return Math.floor(d/86400)+'d ago'; }
function toast(msg,kind,undoFn){ const w=document.getElementById('arch-toast'); const t=document.createElement('div'); t.className='toast '+(kind||'');
  t.innerHTML='<span>'+esc(msg)+'</span>'+(undoFn?'<span class="undo">Undo</span>':'');
  if(undoFn){ t.querySelector('.undo').addEventListener('click',()=>{ undoFn(); t.remove(); }); }
  w.appendChild(t); setTimeout(()=>{ t.style.transition='opacity .4s'; t.style.opacity='0'; setTimeout(()=>t.remove(),400); }, undoFn?6000:2400); }

function fBody(f){ return `<div class="t"><span class="ti">${esc(f.title)}</span><span class="src s-${f.source}">${f.source==='ai'?'AI':'stat'}</span></div>
    <div class="bar"><i style="width:${f.conf}%"></i></div>
    <div class="muted">confidence ${f.conf}% · ${f.support} occurrences · ~${f.lag}m lag</div>
    ${f.hypothesis?`<div class="hyp"><i class="fas fa-lightbulb"></i> ${esc(f.hypothesis)}</div>`:''}
    ${f.fix?`<div class="fix"><i class="fas fa-screwdriver-wrench"></i> ${esc(f.fix)}</div>`:''}
    ${f.evidence?`<div class="ev">${evHtml(f.evidence)}</div>`:''}`; }
function card(f,mode){ let acts;
  if(mode==='ack')       acts=`<span class="badge-ack">acknowledged</span> <button class="btn" onclick="act('reopen',${f.id})">Reopen</button> <button class="btn" onclick="act('dismiss',${f.id})">Dismiss</button>`;
  else if(mode==='dism') acts=`<span class="badge-dism">dismissed</span> <button class="btn ok" onclick="act('reopen',${f.id})"><i class="fas fa-rotate-left"></i> Reopen</button>`;
  else                   acts=`<button class="btn ok" onclick="act('ack',${f.id})"><i class="fas fa-check"></i> Acknowledge</button> <button class="btn" onclick="act('dismiss',${f.id})">Dismiss</button>`;
  return `<div class="f ${f.source}${(mode==='ack'||mode==='dism')?' ackd':''}">${fBody(f)}<div style="margin-top:9px;text-align:right;">${acts}</div></div>`; }

async function load(){
  const r=await fetch('archaeology.php?api=data').then(r=>r.json()).catch(()=>null); if(!r||!r.ok)return;
  const active=r.findings.filter(f=>f.status==='open'), acked=r.findings.filter(f=>f.status==='ack');
  const list=document.getElementById('list');
  list.innerHTML=active.map(f=>card(f,'open')).join('');
  document.getElementById('empty').style.display=(!active.length && !acked.length)?'block':'none';
  // acknowledged section (dimmed, collapsible)
  const aw=document.getElementById('ackwrap');
  if(acked.length){ aw.style.display='block'; document.getElementById('ack-n').textContent=acked.length;
    document.getElementById('acklist').innerHTML=acked.map(f=>card(f,'ack')).join('');
    document.getElementById('acklist').style.display=ACK_OPEN?'block':'none';
    document.getElementById('ack-caret').className='fas fa-chevron-'+(ACK_OPEN?'down':'right'); }
  else aw.style.display='none';
  // meta line
  const c=r.counts||{};
  document.getElementById('m-counts').innerHTML=`<b style="color:#cfd3da">${c.open||0}</b> active · <b style="color:#cfd3da">${c.ack||0}</b> ack`;
  document.getElementById('m-last').innerHTML=`· <i class="fas fa-clock"></i> analyzed ${ago(r.last_run)}`;
  const dl=document.getElementById('m-dism'); if((c.dismissed||0)>0){ dl.style.display='inline'; dl.textContent=(DISM_OPEN?'Hide':'Show')+` dismissed (${c.dismissed})`; } else { dl.style.display='none'; }
  if(DISM_OPEN) loadDismissed();
  // AI status
  const aiN=r.findings.filter(f=>f.source==='ai').length; const as=document.getElementById('ai-status');
  if(!HAS_AI){ as.style.borderLeft='3px solid #f39c12'; as.innerHTML='<i class="fas fa-plug-circle-xmark" style="color:#f39c12"></i> AI enrichment is <b>off</b> — no webhook set. Statistical mining still runs; findings show on the left. Add a webhook below to enable AI hypotheses.'; }
  else if(aiN>0){ as.style.borderLeft='3px solid #2ecc71'; as.innerHTML=`<i class="fas fa-circle-check" style="color:#2ecc71"></i> Webhook configured · <b>${aiN}</b> AI-enriched finding(s) received.`; }
  else { as.style.borderLeft='3px solid #4da3ff'; as.innerHTML='<i class="fas fa-hourglass-half" style="color:#4da3ff"></i> Webhook set, but <b>no AI findings yet</b>. NEURU only POSTs to n8n when <b>Analyze now</b> finds ≥1 candidate pattern — if you see no n8n execution, there were likely no candidates in the window (widen <i>Window</i> / lower <i>Min support</i>), or the URL/token is wrong.'; }
}

async function runNow(btn){ const o=btn.innerHTML; btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> Analyzing…';
  const r=await post('run',{}); btn.disabled=false; btn.innerHTML=o;
  if(!r.ok){ toast('Analysis failed','warn'); return; }
  toast(`Found ${r.candidates} pattern(s) · stored ${r.stored}`+(HAS_AI?(r.ai_shipped?' · shipped to n8n ✓':' · nothing to ship to n8n'):''), r.candidates?'ok':'');
  load(); }
async function act(a,id){ const r=await post(a,{id});
  if(!r.ok){ toast('Action failed'+(r.error?': '+r.error:''),'warn'); return; }
  const label={ack:'Acknowledged',dismiss:'Dismissed',reopen:'Reopened'}[a]||'Done';
  toast(label, 'ok', (a==='ack'||a==='dismiss')?(()=>act('reopen',id)):null);
  load(); }
function toggleAck(){ ACK_OPEN=!ACK_OPEN; load(); }
function toggleDismissed(){ DISM_OPEN=!DISM_OPEN; document.getElementById('dismwrap').style.display=DISM_OPEN?'block':'none'; load(); }
async function loadDismissed(){ const r=await fetch('archaeology.php?api=dismissed').then(r=>r.json()).catch(()=>null); const el=document.getElementById('dismlist');
  if(!r||!r.ok){ el.innerHTML='<div class="muted">Failed to load.</div>'; return; }
  el.innerHTML=r.findings.length?r.findings.map(f=>card(f,'dism')).join(''):'<div class="muted">Nothing dismissed.</div>'; }
async function saveSettings(btn){ btn.disabled=true; const r=await post('save_settings',{arch_webhook_url:document.getElementById('s-url').value,arch_window_days:document.getElementById('s-win').value,arch_min_support:document.getElementById('s-sup').value}); btn.disabled=false; document.getElementById('s-msg').textContent=r.ok?'Saved ✓':(r.error||'Failed'); if(r.ok) toast('Settings saved','ok'); }
load(); setInterval(load, 60000);
</script>
<div id="arch-toast"></div>
</body></html>
