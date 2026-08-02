<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Deception Grid (F2 · Phase 1). Manage honeypots, and MANUALLY divert an
// attacker IP into a decoy via MikroTik dst-nat (time-boxed, auto-reverting), then
// promote to a fleet-wide Immunity block. OFF by default. Engine: nm_decoy.php.
// RBAC: 'deception'.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_decoy.php');
require_once('nm_nettools.php');   // nm_geo_badge() — country flag for attacker IPs
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'deception')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=deception'); exit;
}
nm_decoy_ensure($conn);
$uid = (int)($_SESSION['UID'] ?? $_SESSION['user_id'] ?? 0);

if ($api) {
    header('Content-Type: application/json; charset=utf-8');
    if (function_exists('session_write_close')) @session_write_close();   // release before SSH/Portainer

    if ($api === 'state') {
        $S = nm_decoy_settings($conn);
        // border node candidates (all nodes; MikroTik flagged)
        $nodes = [];
        $nr = $conn->query("SELECT id,display_name,ip_address,os_icon FROM nm_nodes ORDER BY display_name");
        while ($nr && $x=$nr->fetch_assoc()) { $x['is_mikrotik'] = stripos((string)$x['os_icon'],'mikrotik')!==false; $nodes[]=$x; }
        // portainer endpoints for deploy target
        $eps = [];
        $pcfg = nm_portainer_cfg($conn);
        if (nm_portainer_configured($pcfg)) foreach (nm_portainer_endpoint_map($pcfg) as $eid=>$e) $eps[] = ['id'=>$eid,'name'=>$e['name'],'ip'=>$e['ip'],'up'=>$e['up']];
        $pots = nm_decoy_pots($conn);
        $live = nm_decoy_pots_live($conn, $pots);
        foreach ($pots as &$p) { $l = $live[(int)$p['id']] ?? null; $p['live_state'] = $l['state'] ?? null; $p['live_status'] = $l['status'] ?? null; }
        unset($p);
        $divs = nm_decoy_diversions($conn);
        foreach ($divs as &$d) { $g = function_exists('nm_geo_badge') ? nm_geo_badge($conn, $d['src_ip'] ?? '') : null;   // attacker origin
            $d['geo'] = $g ? ['flag'=>$g['flag'],'country'=>$g['country'],'city'=>$g['city']] : null; }
        unset($d);
        echo json_encode(['ok'=>true,'settings'=>$S,'pots'=>$pots,'diversions'=>$divs,
                          'catalog'=>nm_decoy_catalog(),'nodes'=>$nodes,'endpoints'=>$eps,'portainer'=>nm_portainer_configured($pcfg)]);
        exit;
    }
    if ($api === 'settings_save') {
        foreach (['deception_enabled','deception_border_node_id','deception_ttl_min','deception_never_divert',
                  'deception_allow_internal','deception_auto','deception_classes','deception_promote_min_events'] as $k)
            if (isset($_POST[$k])) nm_decoy_set($conn, $k, (string)$_POST[$k]);
        if (function_exists('nm_audit')) nm_audit($conn,'deception.settings',['details'=>['by'=>$uid]]);
        echo json_encode(['ok'=>true,'settings'=>nm_decoy_settings($conn)]); exit;
    }
    if ($api === 'pot_save')   { echo json_encode(nm_decoy_pot_save($conn, $_POST, $uid)); exit; }
    if ($api === 'pot_deploy') { echo json_encode(nm_decoy_pot_deploy($conn, (int)($_POST['id']??0), $uid)); exit; }
    if ($api === 'pot_remove') { echo json_encode(nm_decoy_pot_remove($conn, (int)($_POST['id']??0))); exit; }
    if ($api === 'divert')     { echo json_encode(nm_decoy_divert($conn, $_POST, $uid)); exit; }
    if ($api === 'revert')     { echo json_encode(nm_decoy_revert($conn, (int)($_POST['id']??0), $uid)); exit; }
    if ($api === 'promote')    { echo json_encode(nm_decoy_promote($conn, (int)($_POST['id']??0), $uid)); exit; }
    if ($api === 'analyze')    { echo json_encode(nm_decoy_analyze($conn, (int)($_POST['id']??0))); exit; }
    if ($api === 'source_status') { echo json_encode(['ok'=>true,'disposition'=>nm_decoy_source_disposition($conn, trim((string)($_GET['ip']??'')))]); exit; }
    if ($api === 'events')     {
        $did = (int)($_GET['id']??0);
        // live-ingest the border firewall log (throttled ~8s) so Watch fills in near real time
        $lk = '_decoy_lastlog_'.$did;
        if (time() - (int)nm_decoy_setting($conn,$lk,'0') >= 8) { nm_decoy_ingest_border_log($conn,$did); nm_decoy_set($conn,$lk,(string)time()); }
        echo json_encode(['ok'=>true,'events'=>nm_decoy_events_for($conn, $did)]); exit;
    }
    if ($api === 'preview') {
        // dry preview of the EXACT divert command(s) for the configured border router's vendor
        $pot = nm_decoy_pot_get($conn, (int)($_GET['pot_id']??0));
        $S = nm_decoy_settings($conn);
        $vendor = ((int)($S['border_node_id']??0) > 0) ? nm_decoy_vendor_of($conn, (int)$S['border_node_id']) : 'mikrotik';
        $rd = nm_decoy_render_divert($vendor, [
            'src_ip'=>trim((string)($_GET['src_ip']??'<attacker>')),
            'pot_ip'=>$pot['host_ip']??'<pot-host>', 'pot_port'=>(int)($pot['listen_port']??0),
            'protocol'=>($_GET['protocol']??'tcp'), 'comment'=>NM_DECOY_TAG.'-<id>',
            'target_port'=>(int)($_GET['target_port']??0),
        ]);
        echo json_encode(['ok'=>true,'vendor'=>$vendor,'cmd'=>$rd['cmd'] ?? ('— '.($rd['error']??'unsupported vendor'))]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Deception Grid | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --purple:#9b6bff; --border:rgba(255,255,255,.12); }
*,*::before,*::after{ box-sizing:border-box; }
html{ background:#05060f; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#e6e9ee; }
<?= nm_chrome_css() ?>
.wrap{ max-width:1360px; margin:0 auto; padding:16px 20px 60px; }
.glass{ background:rgba(255,255,255,.05); backdrop-filter:blur(14px); border:1px solid var(--border); border-radius:14px; }
.muted{ color:#8a909a; font-size:12px; } .mono{ font-family:monospace; }
h1{ font-size:22px; margin:6px 0 2px; display:flex; align-items:center; gap:10px; } h1 i{ color:var(--purple); }
.sub{ color:#8a909a; font-size:13px; margin-bottom:14px; }
.banner{ border:1px solid rgba(243,181,44,.4); background:rgba(243,181,44,.08); border-radius:12px; padding:12px 16px; font-size:13px; margin-bottom:16px; color:#ffd479; }
.banner b{ color:#ffe6a8; }
.tabs{ display:flex; gap:6px; margin-bottom:16px; flex-wrap:wrap; }
.tab{ padding:9px 16px; border:1px solid var(--border); border-radius:10px; cursor:pointer; font-size:13px; color:#cfd6e0; background:rgba(255,255,255,.03); }
.tab.on{ border-color:var(--purple); color:#fff; background:rgba(155,107,255,.16); }
.card{ padding:16px 18px; margin-bottom:14px; }
.card h3{ margin:0 0 12px; font-size:15px; display:flex; align-items:center; gap:8px; }
label.f{ display:block; font-size:12px; color:#9aa3af; margin:10px 0 4px; }
input,select,textarea{ width:100%; background:rgba(10,16,28,.7); border:1px solid var(--border); border-radius:8px; color:#e6e9ee; padding:8px 10px; font-size:13px; font-family:inherit; }
textarea{ resize:vertical; min-height:56px; }
.row{ display:flex; gap:12px; flex-wrap:wrap; } .row>div{ flex:1; min-width:140px; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:8px 14px; font-size:13px; cursor:pointer; }
.btn:hover{ border-color:var(--accent); color:#fff; }
.btn.p{ background:rgba(155,107,255,.16); border-color:rgba(155,107,255,.5); color:#d9c8ff; }
.btn.ok{ background:rgba(46,204,113,.16); border-color:rgba(46,204,113,.5); color:#9af3c0; }
.btn.no{ background:rgba(231,76,60,.14); border-color:rgba(231,76,60,.5); color:#ffb3ab; }
.btn.sm{ padding:5px 10px; font-size:12px; }
table{ width:100%; border-collapse:collapse; font-size:12.5px; }
th,td{ text-align:left; padding:8px 10px; border-bottom:1px solid rgba(255,255,255,.07); }
th{ color:#8a909a; font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.5px; }
.badge{ font-size:10px; padding:2px 8px; border-radius:20px; background:rgba(255,255,255,.08); }
.badge.active{ background:rgba(46,204,113,.18); color:#7af3b0; } .badge.reverted{ background:rgba(255,255,255,.08); color:#aab; }
.badge.promoted{ background:rgba(155,107,255,.2); color:#d9c8ff; } .badge.failed{ background:rgba(231,76,60,.2); color:#ff9b91; }
.badge.deployed{ background:rgba(46,204,113,.18); color:#7af3b0; } .badge.draft{ background:rgba(243,181,44,.18); color:#ffd479; } .badge.error{ background:rgba(231,76,60,.2); color:#ff9b91; }
.switch{ display:inline-flex; align-items:center; gap:9px; font-size:13px; cursor:pointer; }
/* render the checkboxes as sliding toggle switches */
.switch input[type=checkbox]{ appearance:none; -webkit-appearance:none; width:40px; height:22px; border-radius:22px;
  background:rgba(255,255,255,.14); border:1px solid var(--border); position:relative; cursor:pointer; flex:none;
  transition:background .18s,border-color .18s; margin:0; }
.switch input[type=checkbox]::after{ content:''; position:absolute; top:2px; left:2px; width:16px; height:16px;
  border-radius:50%; background:#cfd6e0; transition:left .18s,background .18s; }
.switch input[type=checkbox]:checked{ background:rgba(155,107,255,.55); border-color:var(--purple); }
.switch input[type=checkbox]:checked::after{ left:20px; background:#fff; }
.switch input[type=checkbox]:focus-visible{ outline:2px solid var(--purple); outline-offset:2px; }
.pill{ display:inline-flex; align-items:center; gap:6px; font-size:12px; padding:4px 10px; border-radius:20px; border:1px solid var(--border); }
.pill.on{ border-color:var(--ok); color:#9af3c0; } .pill.off{ border-color:var(--crit); color:#ffb3ab; }
.pre{ background:#0a0f1c; border:1px solid var(--border); border-radius:8px; padding:10px 12px; font-family:monospace; font-size:11.5px; white-space:pre-wrap; word-break:break-all; color:#a9d5ff; }
#msg{ position:fixed; bottom:18px; left:50%; transform:translateX(-50%); z-index:50; padding:10px 18px; border-radius:10px; font-size:13px; display:none; }
#msg.ok{ background:rgba(46,204,113,.2); border:1px solid rgba(46,204,113,.5); color:#9af3c0; }
#msg.err{ background:rgba(231,76,60,.2); border:1px solid rgba(231,76,60,.5); color:#ffb3ab; }
.empty{ color:#6b7686; padding:14px 0; font-size:13px; }
</style>
</head>
<body>
<?php include('header.php'); ?>
<div class="wrap">
  <h1><i class="fa-solid fa-mask"></i> Deception Grid</h1>
  <div class="sub">Divert an attacker into a decoy instead of just banning them — watch their moves, then block them fleet-wide. Time-boxed &amp; auto-reverting.</div>
  <div class="banner"><i class="fa-solid fa-triangle-exclamation"></i> <b>Active defense — authorized internal networks only.</b>
    Deception reconfigures your border router's NAT for a single attacker IP. It is <b>OFF by default</b>, strictly scoped to one source, time-boxed with automatic revert, and fully audited. Autonomous mode (auto-divert) is opt-in in <b>Settings</b>.</div>

  <div class="tabs">
    <div class="tab on" data-t="pots"><i class="fa-solid fa-server"></i> Honeypots</div>
    <div class="tab" data-t="div"><i class="fa-solid fa-route"></i> Diversions</div>
    <div class="tab" data-t="set"><i class="fa-solid fa-sliders"></i> Settings</div>
  </div>

  <!-- HONEYPOTS -->
  <div class="tabc" id="t-pots">
    <div class="glass card">
      <h3><i class="fa-solid fa-plus"></i> Add / deploy a honeypot</h3>
      <div class="muted" style="margin-bottom:8px;">Low-interaction decoys only — never a clone of a real service. Deployed via Portainer.</div>
      <div class="row">
        <div><label class="f">Name</label><input id="p-name" placeholder="ssh-decoy-1"></div>
        <div><label class="f">Type</label><select id="p-kind"></select></div>
        <div><label class="f">Image</label><input id="p-image" placeholder="cowrie/cowrie:latest"></div>
      </div>
      <div class="row">
        <div><label class="f">Container port</label><input id="p-cport" type="number" value="2222"></div>
        <div><label class="f">Host (published) port</label><input id="p-lport" type="number" value="2222"></div>
        <div><label class="f">Portainer host</label><select id="p-eid"></select></div>
      </div>
      <div style="margin-top:12px;display:flex;gap:8px;"><button class="btn" onclick="savePot()">Save honeypot</button></div>
    </div>
    <div class="glass card">
      <h3><i class="fa-solid fa-server"></i> Honeypots</h3>
      <div id="pots-list"></div>
    </div>
  </div>

  <!-- DIVERSIONS -->
  <div class="tabc" id="t-div" style="display:none;">
    <div class="glass card">
      <h3><i class="fa-solid fa-route"></i> Manual divert</h3>
      <div class="row">
        <div><label class="f">Attacker source IP</label><input id="d-src" placeholder="203.0.113.66"><div id="d-status" style="font-size:11px;margin-top:4px;min-height:14px;"></div></div>
        <div><label class="f">Target port <span class="muted">(0 = any)</span></label><input id="d-port" type="number" value="0"></div>
        <div><label class="f">Protocol</label><select id="d-proto"><option>tcp</option><option>udp</option></select></div>
        <div><label class="f">Honeypot</label><select id="d-pot"></select></div>
      </div>
      <div style="margin-top:10px;"><span class="muted">NAT that will be applied on the border router:</span><div class="pre" id="d-preview" style="margin-top:6px;">—</div></div>
      <div style="margin-top:12px;display:flex;gap:8px;"><button class="btn no" onclick="doDivert()"><i class="fa-solid fa-mask"></i> Divert this IP</button></div>
    </div>
    <div class="glass card">
      <h3><i class="fa-solid fa-list"></i> Diversions</h3>
      <div id="div-list"></div>
    </div>
  </div>

  <!-- SETTINGS -->
  <div class="tabc" id="t-set" style="display:none;">
    <div class="glass card">
      <h3><i class="fa-solid fa-sliders"></i> Settings</h3>
      <label class="switch" style="margin:6px 0 4px;"><input type="checkbox" id="s-enabled"> <b>Master switch — deception enabled</b> <span class="pill off" id="s-enabled-pill">OFF</span></label>
      <div class="muted">While OFF, no divert can be applied. Everything below only takes effect when this is ON.</div>
      <div class="row" style="margin-top:8px;">
        <div><label class="f">Border MikroTik (where NAT is applied)</label><select id="s-border"></select></div>
        <div><label class="f">Auto-revert TTL (minutes)</label><input id="s-ttl" type="number" value="30"></div>
      </div>
      <label class="f">Never-divert allowlist <span class="muted">(comma-separated IPs / CIDRs — e.g. your admin IP, 192.168.0.0/16)</span></label>
      <textarea id="s-never" placeholder="192.168.0.10, 10.0.0.0/8"></textarea>
      <label class="switch" style="margin-top:10px;"><input type="checkbox" id="s-internal"> Allow diverting internal/private sources <span class="muted">(off by default — attackers are usually external)</span></label>
      <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border);">
        <label class="switch"><input type="checkbox" id="s-auto"> <b>🤖 Autonomous mode — auto-divert from Immunity detections</b></label>
        <div class="muted">When ON, NEURU auto-diverts newly-detected port-scan/brute-force IPs into a honeypot, lets the AI analyst judge them, and <b>auto-promotes to a fleet block</b> when the verdict is "promote" and enough events accumulate. Needs a deployed honeypot + the enabled deception-analyst webhook. All the same guards apply (external only, allowlist, one-per-IP).</div>
      </div>
      <div class="row" style="margin-top:8px;">
        <div><label class="f">Auto-divert classes <span class="muted">(Immunity threat sources)</span></label><input id="s-classes" value="portscan,bruteforce"></div>
        <div><label class="f">Auto-promote after N events</label><input id="s-promote" type="number" value="8"></div>
      </div>
      <div style="margin-top:12px;display:flex;gap:8px;"><button class="btn" onclick="saveSettings()">Save settings</button></div>
    </div>
  </div>
</div>

<!-- attacker theater -->
<div id="theater" style="display:none;position:fixed;inset:0;z-index:60;background:rgba(2,4,10,.72);backdrop-filter:blur(4px);">
  <div class="glass" style="position:absolute;top:6vh;left:50%;transform:translateX(-50%);width:760px;max-width:94vw;height:82vh;display:flex;flex-direction:column;">
    <div style="padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;">
      <i class="fa-solid fa-eye" style="color:var(--purple)"></i>
      <b>Attacker theater</b> <span class="mono" id="th-ip" style="color:#ffd479"></span>
      <span class="muted" id="th-count" style="margin-left:auto;"></span>
      <span style="cursor:pointer;color:#9aa3af;margin-left:12px;" onclick="closeTheater()"><i class="fa-solid fa-xmark"></i></span>
    </div>
    <div id="th-body" style="padding:12px 18px;overflow-y:auto;flex:1;font-family:monospace;font-size:12px;"></div>
    <div class="muted" style="padding:8px 18px;border-top:1px solid var(--border);">Live — what the attacker is doing inside the decoy. Feed events via <span class="mono">decoy_api.php?ep=event</span>.</div>
  </div>
</div>
<div id="msg"></div>
<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let ST={settings:{},pots:[],diversions:[],catalog:[],nodes:[],endpoints:[],portainer:false};
function toast(m,ok){ const e=document.getElementById('msg'); e.textContent=m; e.className=(ok?'ok':'err'); e.style.display='block'; setTimeout(()=>e.style.display='none',3200); }
async function api(a,body,method){ const o={method:method||'POST'}; if(body){ o.headers={'Content-Type':'application/x-www-form-urlencoded'}; o.body=new URLSearchParams(body).toString(); }
  return fetch('deception.php?api='+a,o).then(r=>r.json()); }

document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('on')); t.classList.add('on');
  ['pots','div','set'].forEach(k=>document.getElementById('t-'+k).style.display=(k===t.dataset.t?'block':'none'));
});

async function load(){
  const r=await api('state',null,'GET'); if(!r||!r.ok) return; ST=r;
  // catalog → type select
  const kind=document.getElementById('p-kind'); kind.innerHTML=ST.catalog.map((c,i)=>`<option value="${i}">${esc(c.label)}</option>`).join('');
  kind.onchange=()=>{ const c=ST.catalog[+kind.value]; if(c){ document.getElementById('p-image').value=c.image; document.getElementById('p-cport').value=c.cport; document.getElementById('p-lport').value=c.lport; } };
  // portainer endpoints
  const eid=document.getElementById('p-eid');
  eid.innerHTML = ST.portainer ? ST.endpoints.map(e=>`<option value="${e.id}">${esc(e.name)} (${esc(e.ip||'?')})${e.up?'':' — down'}</option>`).join('')
    : '<option value="0">Portainer not configured</option>';
  renderPots(); renderDiv(); renderSettings();
  // border + pot selects
  document.getElementById('s-border').innerHTML='<option value="0">— pick border router —</option>'+
    ST.nodes.map(n=>`<option value="${n.id}" ${ST.settings.border_node_id==n.id?'selected':''}>${esc(n.display_name)} ${n.is_mikrotik?'⭐':''} (${esc(n.ip_address||'')})</option>`).join('');
  const dpot=document.getElementById('d-pot');
  const dep=ST.pots.filter(p=>p.status==='deployed');
  dpot.innerHTML= dep.length? dep.map(p=>`<option value="${p.id}">${esc(p.name)} → ${esc(p.host_ip)}:${p.listen_port}</option>`).join('') : '<option value="0">— no deployed honeypot —</option>';
  updatePreview();
}
function renderPots(){
  const el=document.getElementById('pots-list');
  if(!ST.pots.length){ el.innerHTML='<div class="empty">No honeypots yet.</div>'; return; }
  el.innerHTML='<table><tr><th>Name</th><th>Type</th><th>Image</th><th>Host target</th><th>Status</th><th></th></tr>'+
    ST.pots.map(p=>`<tr><td><b>${esc(p.name)}</b></td><td>${esc(p.service_kind)}</td><td class="mono" style="font-size:11px">${esc(p.image)}</td>
      <td class="mono">${p.host_ip?esc(p.host_ip)+':'+p.listen_port:'—'}</td>
      <td><span class="badge ${esc(p.status)}">${esc(p.status)}</span>
        ${p.live_state?`<span class="badge ${p.live_state==='running'?'deployed':'error'}" title="${esc(p.live_status||'')}">${p.live_state==='running'?'▶ running':'⚠ '+esc(p.live_state)}</span>`:''}
        ${p.live_state&&p.live_state!=='running'?`<div class="muted" style="color:#ff9b91;font-size:10px">${esc(p.live_status||'')} — this image is crash-looping; use a turnkey one (Cowrie).</div>`:''}
        ${p.last_error?`<div class="muted" style="color:#ff9b91;font-size:10px">${esc(p.last_error)}</div>`:''}</td>
      <td style="white-space:nowrap;text-align:right;">
        <button class="btn ok sm" onclick="deployPot(${p.id})"><i class="fa-solid fa-rocket"></i> Deploy</button>
        <button class="btn no sm" onclick="removePot(${p.id})"><i class="fa-solid fa-trash"></i></button></td></tr>`).join('')+'</table>';
}
function renderDiv(){
  const el=document.getElementById('div-list');
  if(!ST.diversions.length){ el.innerHTML='<div class="empty">No diversions yet.</div>'; return; }
  el.innerHTML='<table><tr><th>Attacker</th><th>→ Honeypot</th><th>Border</th><th>Status</th><th>Started</th><th>Expires</th><th></th></tr>'+
    ST.diversions.map(d=>`<tr><td class="mono"><b>${esc(d.src_ip)}</b>${+d.target_port?(':'+d.target_port):''}${d.geo?`<div class="muted" style="font-family:initial;font-size:10px" title="${esc(d.geo.country)}${d.geo.city?' · '+esc(d.geo.city):''}">${d.geo.flag} ${esc(d.geo.country)}</div>`:''}</td>
      <td>${esc(d.pot_name||'?')} <span class="muted mono">${d.pot_ip?esc(d.pot_ip):''}</span></td>
      <td>${esc(d.border_name||('#'+d.border_node_id))}</td>
      <td><span class="badge ${esc(d.status)}">${esc(d.status)}</span>${d.detail?`<div class="muted" style="color:#ff9b91;font-size:10px">${esc(d.detail)}</div>`:''}
        ${d.ai_verdict?`<div class="muted" style="margin-top:3px"><span class="badge ${d.ai_verdict==='promote'?'promoted':(d.ai_verdict==='release'?'reverted':'active')}">🧠 ${esc(d.ai_verdict)} · ${d.ai_score}</span></div>${d.ai_summary?`<div class="muted" style="font-size:10px;max-width:280px">${esc(d.ai_summary)}</div>`:''}`:''}</td>
      <td class="muted">${esc(d.started_at||'')}</td><td class="muted">${d.status==='active'?esc(d.expires_at||''):'—'}</td>
      <td style="white-space:nowrap;text-align:right;">
        <button class="btn sm" onclick="watch(${d.id},'${esc(d.src_ip)}')" title="Live attacker theater"><i class="fa-solid fa-eye"></i> Watch</button>
        <button class="btn p sm" onclick="analyze(${d.id},this)" title="Ask the AI to analyze this attacker's behaviour"><i class="fa-solid fa-brain"></i> Analyze</button>
        ${d.status==='active'?
        `<button class="btn p sm" onclick="promote(${d.id})" title="Block this IP across the whole fleet"><i class="fa-solid fa-virus-slash"></i> Promote</button>
         <button class="btn sm" onclick="revert(${d.id})"><i class="fa-solid fa-rotate-left"></i> Revert</button>`:''}</td></tr>`).join('')+'</table>';
}
function renderSettings(){
  const s=ST.settings;
  const cb=document.getElementById('s-enabled'); cb.checked=!!s.enabled;
  document.getElementById('s-enabled-pill').className='pill '+(s.enabled?'on':'off'); document.getElementById('s-enabled-pill').textContent=s.enabled?'ON':'OFF';
  document.getElementById('s-ttl').value=s.ttl_min; document.getElementById('s-never').value=(s.never_divert||[]).join(', ');
  document.getElementById('s-internal').checked=!!s.allow_internal;
  document.getElementById('s-auto').checked=!!s.auto;
  document.getElementById('s-classes').value=(s.classes||[]).join(', ');
  document.getElementById('s-promote').value=s.promote_min_events;
}
document.getElementById('s-enabled').onchange=e=>{ const on=e.target.checked;
  document.getElementById('s-enabled-pill').className='pill '+(on?'on':'off'); document.getElementById('s-enabled-pill').textContent=on?'ON':'OFF'; };

async function savePot(){
  const b={name:val('p-name'),service_kind:ST.catalog[+document.getElementById('p-kind').value]?.kind||'generic',
    image:val('p-image'),container_port:val('p-cport'),listen_port:val('p-lport'),portainer_endpoint_id:val('p-eid')};
  const r=await api('pot_save',b); if(r.ok){ toast('Honeypot saved',1); document.getElementById('p-name').value=''; load(); } else toast(r.error||'error',0);
}
async function deployPot(id){ toast('Deploying…',1); const r=await api('pot_deploy',{id}); if(r.ok) toast('Deployed at '+r.host_ip+':'+r.listen_port,1); else toast(r.error||'deploy failed',0); load(); }
async function removePot(id){ if(!confirm('Remove this honeypot record?')) return; await api('pot_remove',{id}); load(); }

async function doDivert(){
  const b={src_ip:val('d-src'),target_port:val('d-port'),protocol:val('d-proto'),pot_id:val('d-pot')};
  if(!confirm('Divert '+b.src_ip+' into the honeypot?\n\nThis adds a dst-nat rule on the border router (auto-reverts after the TTL).')) return;
  const r=await api('divert',b); if(r.ok) toast('Diverted (auto-reverts in '+r.ttl_min+'m)',1); else toast(r.error||'divert failed',0); load();
}
async function revert(id){ const r=await api('revert',{id}); if(r.ok) toast('Reverted',1); else toast(r.error||'error',0); load(); }
async function promote(id){ if(!confirm('Block this IP across ALL Pi-holes + firewalls (Collective Immunity) and revert the decoy?')) return;
  const r=await api('promote',{id}); if(r.ok) toast('Promoted to fleet block',1); else toast(r.error||'error',0); load(); }
let _thId=0, _thTimer=null;
function watch(id,ip){ _thId=id; document.getElementById('th-ip').textContent=ip||''; document.getElementById('theater').style.display='block';
  pollTheater(); clearInterval(_thTimer); _thTimer=setInterval(pollTheater,3000); }
function closeTheater(){ document.getElementById('theater').style.display='none'; clearInterval(_thTimer); _thId=0; }
async function pollTheater(){ if(!_thId) return;
  const r=await fetch('deception.php?api=events&id='+_thId).then(x=>x.json()).catch(()=>null); if(!r||!r.ok) return;
  const ev=r.events||[]; document.getElementById('th-count').textContent=ev.length+' event(s)';
  const body=document.getElementById('th-body');
  body.innerHTML= ev.length? ev.map(e=>{
    const c={login:'#ff9b91',cmd:'#7fd3ff',http:'#a9d5ff',scan:'#ffd479',payload:'#ff9b91'}[e.kind]||'#cfd6e0';
    return `<div style="padding:5px 0;border-bottom:1px solid rgba(255,255,255,.05)"><span class="muted">${esc(e.ts||'')}</span> <span style="color:${c}">[${esc(e.kind)}]</span> ${esc(e.data||'')}</div>`;
  }).join('') : '<div class="muted" style="padding:14px 0">No events captured yet. When the attacker touches the honeypot (or you POST to decoy_api.php), they appear here live.</div>';
}
async function analyze(id){ toast('Asking the AI…',1); const r=await api('analyze',{id});
  if(r.ok){ const a=r.analysis||{}; toast('AI verdict: '+(a.verdict||'?')+' ('+(a.threat_score??a.score??'?')+')',1); }
  else toast(r.error||'analyze failed',0); load(); }
async function saveSettings(){
  const b={deception_enabled:document.getElementById('s-enabled').checked?'1':'0',
    deception_border_node_id:val('s-border'), deception_ttl_min:val('s-ttl'),
    deception_never_divert:val('s-never'), deception_allow_internal:document.getElementById('s-internal').checked?'1':'0',
    deception_auto:document.getElementById('s-auto').checked?'1':'0',
    deception_classes:val('s-classes'), deception_promote_min_events:val('s-promote')};
  const r=await api('settings_save',b); if(r.ok){ toast('Settings saved',1); load(); } else toast('error',0);
}
function val(id){ return document.getElementById(id).value; }
['d-src','d-port','d-proto','d-pot'].forEach(id=>document.addEventListener('input',e=>{ if(e.target.id===id) updatePreview(); }));
let _srcT=null;
document.addEventListener('input',e=>{ if(e.target.id!=='d-src') return; clearTimeout(_srcT); _srcT=setTimeout(checkSource,400); });
async function checkSource(){
  const ip=val('d-src').trim(); const el=document.getElementById('d-status');
  if(!ip){ el.textContent=''; return; }
  const r=await fetch('deception.php?api=source_status&ip='+encodeURIComponent(ip)).then(x=>x.json()).catch(()=>null);
  if(!r||!r.ok){ el.textContent=''; return; }
  const d=r.disposition;
  // border-path warning: a dst-nat only intercepts traffic through the router we manage
  let border='';
  if(d.seen_on){
    border = d.on_border
      ? '<div style="color:#7af3b0">📍 Seen on your border router ('+esc(d.seen_on)+') — NAT will intercept it.</div>'
      : '<div style="color:#ffd479">⚠️ Seen on <b>'+esc(d.seen_on)+'</b>, not your border router — the NAT you inject may NOT intercept this traffic (it must transit the managed router).</div>';
  }
  if(d.blocked){ const by=d.blocked.by==='immunity'?'Collective Immunity':'Self-Healing'; el.innerHTML='<span style="color:#ff9b91">⛔ Already BLOCKED by '+by+' — diverting will be refused (a block already stops it).</span>'+border; }
  else if(d.diverted){ el.innerHTML='<span style="color:#ffd479">↻ Already being diverted (id '+d.diverted+').</span>'+border; }
  else{ el.innerHTML='<span style="color:#7af3b0">✓ Clear — no other module is acting on this IP.</span>'+border; }
}
async function updatePreview(){
  const pot=val('d-pot'); if(!pot||pot==='0'){ document.getElementById('d-preview').textContent='— deploy a honeypot first —'; return; }
  const q=new URLSearchParams({src_ip:val('d-src')||'<attacker>',target_port:val('d-port')||'0',protocol:val('d-proto'),pot_id:pot});
  const r=await fetch('deception.php?api=preview&'+q).then(x=>x.json()); document.getElementById('d-preview').textContent=r.cmd||'—';
}
load();
</script>
</body></html>
