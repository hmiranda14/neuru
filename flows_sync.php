<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Flows Sync (dedicated, ISOLATED page) with a PICKER.
// Isolated (no header.php) because on the crowded config page background polls stalled
// the browser connection. Two phases so the customer stays in control: (1) LIST the flows
// this install is entitled to — nothing is written; (2) the user PICKS which ones to sync
// and APPLIES only those. Engine: nm_n8n.php (nm_n8n_flows_fetch / nm_n8n_flows_apply). RBAC 'net_mon'.
// ─────────────────────────────────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) session_start();
require __DIR__ . '/connection.php';
require_once __DIR__ . '/access_control.php';

if (isset($_GET['api'])) {
    header('Content-Type: application/json; charset=utf-8');
    if (empty($_SESSION['username']) || !checkAccess($conn, 'net_mon')) { http_response_code(403); echo json_encode(['ok'=>false,'error'=>'unauthorized']); exit; }
    require_once __DIR__ . '/nm_n8n.php';
    if (function_exists('session_write_close')) @session_write_close();   // Portal round-trip ahead
    if (($_GET['api']) === 'list')  { echo json_encode(nm_n8n_flows_fetch($conn)); exit; }
    if (($_GET['api']) === 'apply') {
        $b = json_decode(file_get_contents('php://input'), true) ?: [];
        $slugs = array_values(array_filter(array_map('strval', (array)($b['slugs'] ?? [])), fn($s)=>$s!==''));
        $gw = !empty($b['gateway']);
        $models = is_array($b['models'] ?? null) ? $b['models'] : [];   // {slug: model}
        echo json_encode(nm_n8n_flows_apply($conn, $slugs, $gw, $models)); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}

include('check.php');
if (!checkAccess($conn, 'net_mon')) { header('Location: /denied_access.php?page=net_mon'); exit; }
require_once __DIR__ . '/nm_chrome.php';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sync Flows | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
<?= nm_chrome_css() ?>
:root{--glass:rgba(255,255,255,0.07);--border:rgba(255,255,255,0.13);--accent:#b07cd6;--up:#2ecc71;--down:#e74c3c;--mut:#8a909a;}
body{margin:0;font-family:'Segoe UI',Tahoma,sans-serif;background:#0b0e13;color:#fff;}
.wrap{max-width:680px;margin:0 auto;padding:22px;}
.topbar{display:flex;align-items:center;gap:14px;margin-bottom:16px;}
.back{color:#9aa3ad;text-decoration:none;font-size:13px;display:inline-flex;align-items:center;gap:7px;border:1px solid var(--border);padding:7px 12px;border-radius:8px;}
.back:hover{color:#fff;border-color:var(--accent);}
.card{background:var(--glass);border:1px solid var(--border);border-radius:16px;padding:22px;}
h1{font-size:18px;margin:0 0 4px;display:flex;align-items:center;gap:10px;color:var(--accent);}
.sub{color:var(--mut);font-size:12.5px;margin:0 0 14px;}
.bar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:10px 0;}
.chip{font-size:11px;color:#9aa3ad;border:1px solid var(--border);border-radius:20px;padding:3px 10px;}
.chip b{color:#cdd5df;}
.mini{font-size:11.5px;color:#8ea2c0;background:none;border:1px solid var(--border);border-radius:7px;padding:5px 10px;cursor:pointer;}
.mini:hover{border-color:var(--accent);color:#fff;}
.list{margin:12px 0;max-height:46vh;overflow:auto;border:1px solid var(--border);border-radius:10px;}
.row{display:flex;gap:10px;align-items:flex-start;padding:11px 13px;border-bottom:1px solid rgba(255,255,255,.06);}
.row:last-child{border-bottom:none;}
.row:hover{background:rgba(176,124,214,.05);}
.row input[type=checkbox]{margin-top:3px;width:16px;height:16px;accent-color:var(--accent);cursor:pointer;flex:0 0 auto;}
.rmeta{flex:1;min-width:0;}
.rname{font-size:13.5px;font-weight:600;color:#e8ecf1;}
.rname .tg{font-size:10px;font-weight:600;color:#c9a6e6;background:rgba(176,124,214,.14);border:1px solid rgba(176,124,214,.3);border-radius:5px;padding:1px 7px;margin-left:8px;vertical-align:middle;}
.rdesc{font-size:11.5px;color:#8a909a;margin-top:2px;}
.rwarn{font-size:11px;color:#e0c07a;margin-top:3px;}
.gwrow{display:flex;gap:10px;align-items:flex-start;padding:12px 13px;margin-top:12px;border:1px dashed rgba(54,227,208,.35);border-radius:10px;background:rgba(54,227,208,.05);}
.gwrow input[type=checkbox]{margin-top:3px;width:16px;height:16px;accent-color:#36e3d0;}
.btn{padding:11px 20px;border-radius:10px;border:1px solid var(--accent);background:rgba(176,124,214,.18);color:#efe0fb;font-size:14px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:9px;}
.btn:hover{filter:brightness(1.15);}.btn:disabled{opacity:.5;cursor:not-allowed;}
#msg{margin-top:14px;font-size:13px;min-height:20px;}
code{background:rgba(255,255,255,.08);padding:1px 6px;border-radius:5px;font-size:11px;}
.fmodel{flex:0 0 auto;align-self:center;background:rgba(0,0,0,.35);color:#cdd5df;border:1px solid var(--border);border-radius:7px;padding:5px 8px;font-size:11px;cursor:pointer;max-width:230px;}
.fmodel:hover{border-color:var(--accent);}
.pricenote{font-size:11.5px;color:#8ea2c0;background:rgba(126,209,139,.06);border:1px solid rgba(126,209,139,.2);border-radius:8px;padding:8px 12px;margin:10px 0;}
</style></head>
<body>
<div class="wrap">
  <div class="topbar">
    <a class="back" href="net_mon_config.php?tab=integrations" onclick="if(window.opener){window.close();return false;}"><i class="fas fa-arrow-left"></i> <span id="backlbl">Config</span></a>
  </div>
  <div class="card">
    <h1><i class="fas fa-arrows-rotate"></i> Sync my Flows</h1>
    <p class="sub">Pick which subscribed flows to wire into this NEURU. Nothing is applied until you press <b>Apply selected</b>.</p>
    <div class="bar" id="planbar"></div>
    <div class="bar" id="tools" style="display:none;">
      <button class="mini" onclick="pick(true)">Select all</button>
      <button class="mini" onclick="pick(false)">Select none</button>
      <span class="chip" id="count"></span>
    </div>
    <div id="list" class="list" style="display:none;"></div>
    <div id="gwbox"></div>
    <div style="margin-top:14px;">
      <button id="apply" class="btn" onclick="apply()" style="display:none;"><i class="fas fa-check"></i> Apply selected</button>
    </div>
    <div id="msg"></div>
  </div>
</div>
<script>
function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
let FLOWS=[], GWAVAIL=false, MODELS=[], DEFMODEL='gpt-4o';
const TIER={economy:'#7fd18b',balanced:'#8ea2c0',premium:'#e0a559'};
function priceStr(m){ return (m.price_in_1m!=null&&m.price_out_1m!=null) ? (' · $'+m.price_in_1m+' in / $'+m.price_out_1m+' out per 1M tok') : ''; }
function modelSelect(f){
  if(!MODELS.length) return '';
  const cur=f.model||DEFMODEL;
  const opts=MODELS.map(m=>'<option value="'+esc(m.id)+'"'+(m.id===cur?' selected':'')+'>'+esc(m.label)+priceStr(m)+'</option>').join('');
  return '<select class="fmodel" data-slug="'+esc(f.slug)+'" onclick="event.preventDefault();event.stopPropagation();" title="Model this flow is billed for — price shown is what YOU pay per 1M tokens (markup included)">'+opts+'</select>';
}
function updCount(){ const n=document.querySelectorAll('.fchk:checked').length; document.getElementById('count').innerHTML='<b>'+n+'</b> of '+FLOWS.length+' selected'; }
function pick(v){ document.querySelectorAll('.fchk').forEach(c=>c.checked=v); updCount(); }
async function load(){
  const m=document.getElementById('msg'); m.style.color='#b07cd6'; m.innerHTML='<i class="fas fa-circle-notch fa-spin"></i> Loading your flows from the Portal…';
  let r; const ctrl=new AbortController(); const to=setTimeout(()=>ctrl.abort(),25000);
  try{ r=await fetch('flows_sync.php?api=list',{cache:'no-store',signal:ctrl.signal}).then(x=>x.json()); }
  catch(e){ r={ok:false,error:(e&&e.name==='AbortError')?'Timed out after 25s — the Portal didn\'t respond.':'request failed'}; }
  finally{ clearTimeout(to); }
  if(!r || !r.ok){ m.style.color='#e0a559'; m.innerHTML='<i class="fas fa-triangle-exclamation"></i> '+esc((r&&r.error)||'load failed'); return; }
  FLOWS=r.flows||[]; GWAVAIL=!!r.gateway_available; MODELS=r.available_models||[]; DEFMODEL=r.default_model||'gpt-4o'; m.innerHTML='';
  document.getElementById('planbar').innerHTML =
    '<span class="chip">Plan <b>'+esc(r.plan||'—')+'</b></span><span class="chip">Status <b>'+esc(r.status||'—')+'</b></span><span class="chip"><b>'+FLOWS.length+'</b> flow(s) available</span>';
  if(MODELS.length){ document.getElementById('planbar').insertAdjacentHTML('afterend',
    '<div class="pricenote"><i class="fas fa-circle-info"></i> Pick a model per flow. Prices shown are <b>exactly what you pay</b> per 1M tokens (our markup is already included — nothing hidden). You\'re billed only for what each flow actually uses.</div>'); }
  if(!FLOWS.length){ document.getElementById('list').style.display='block'; document.getElementById('list').innerHTML='<div class="row"><div class="rmeta"><div class="rdesc">No flows on your subscription yet.</div></div></div>'; return; }
  const L=document.getElementById('list');
  L.innerHTML = FLOWS.map((f,i)=>{
    const warn = f.local_present ? ('<div class="rwarn">⚠ This module currently uses a local URL (<code>'+esc((f.local_url||'').slice(0,48))+'…</code>). Selecting replaces it with the hosted flow.</div>') : '';
    return '<label class="row"><input type="checkbox" class="fchk" data-slug="'+esc(f.slug)+'" '+(f.selected?'checked':'')+' onchange="updCount()">'
      + '<div class="rmeta"><div class="rname">'+esc(f.name)+'<span class="tg">'+esc(f.target)+'</span></div>'
      + (f.description?('<div class="rdesc">'+esc(f.description)+'</div>'):'')
      + warn + '</div>'+modelSelect(f)+'</label>';
  }).join('');
  L.style.display='block'; document.getElementById('tools').style.display='flex'; document.getElementById('apply').style.display='inline-flex';
  if(GWAVAIL){
    const gwOn = !r.gateway_local_present;  // pre-check only if not already configured
    document.getElementById('gwbox').innerHTML =
      '<label class="gwrow"><input type="checkbox" id="gwchk" '+(gwOn?'checked':'')+'>'
      +'<div class="rmeta"><div class="rname" style="color:#8ff0e6;"><i class="fas fa-bolt"></i> AI Gateway credentials</div>'
      +'<div class="rdesc">Auto-fill your metered connection key + gateway key'+(r.gateway_local_present?' (already configured — re-fill).':' so flows are billed to your prepaid credit.')+'</div></div></label>';
  }
  updCount();
}
async function apply(){
  const slugs=[...document.querySelectorAll('.fchk:checked')].map(c=>c.dataset.slug);
  const gwEl=document.getElementById('gwchk'); const gateway=!!(gwEl&&gwEl.checked);
  if(!slugs.length && !gateway){ const m=document.getElementById('msg'); m.style.color='#e0a559'; m.innerHTML='Pick at least one flow (or the AI Gateway) first.'; return; }
  const b=document.getElementById('apply'), m=document.getElementById('msg'); b.disabled=true;
  m.style.color='#b07cd6'; m.innerHTML='<i class="fas fa-circle-notch fa-spin"></i> Applying '+slugs.length+' selected flow(s)…';
  let r; const ctrl=new AbortController(); const to=setTimeout(()=>ctrl.abort(),25000);
  const models={}; document.querySelectorAll('.fmodel').forEach(s=>{ if(s.dataset.slug) models[s.dataset.slug]=s.value; });
  try{ r=await fetch('flows_sync.php?api=apply',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/json'},body:JSON.stringify({slugs,gateway,models}),signal:ctrl.signal}).then(x=>x.json()); }
  catch(e){ r={ok:false,error:(e&&e.name==='AbortError')?'Timed out after 25s.':'request failed'}; }
  finally{ clearTimeout(to); }
  b.disabled=false;
  if(r && r.ok){
    m.style.color='#8ff0b6';
    m.innerHTML='<i class="fas fa-check"></i> Applied <b>'+(r.applied||0)+'</b> flow(s)'
      +(r.routed?(' · wired <b>'+r.routed+'</b> module field(s)'):'')
      +(r.gateway?(' · AI Gateway <b>'+r.gateway+'</b> key(s)'):'')
      +'. <span style="color:#9aa3ad">Refresh the relevant module pages to see them live.</span>';
  } else { m.style.color='#e0a559'; m.innerHTML='<i class="fas fa-triangle-exclamation"></i> '+esc((r&&r.error)||'apply failed'); }
}
if(window.opener){var _bl=document.getElementById('backlbl'); if(_bl)_bl.textContent='Close';}
load();
</script>
</body></html>
