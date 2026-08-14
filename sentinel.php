<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU Sentinel Engine — Command Center (HUD). Non-intrusive threat interception.
// Agent API (token, no session): enroll / desired / report — the neuru-sentinel
// sensor pulls the matrix + reports wire hits. UI (session + 'sentinel' RBAC):
// the cyberpunk HUD (SPECTRE matrix, live threats, quarantine, sensors, deploy).
// Engine: nm_sentinel.php
// ─────────────────────────────────────────────────────────────────────────────
include('connection.php');
require_once('nm_sentinel.php');
nm_sentinel_ensure($conn);

$api = $_GET['api'] ?? '';
$hdrTok = $_SERVER['HTTP_X_NEURU_SENTINEL_TOKEN'] ?? '';

// ── AGENT API (token) ────────────────────────────────────────────────────────
if ($hdrTok !== '' || in_array($api,['enroll','desired','report'],true)) {
    header('Content-Type: application/json; charset=utf-8');
    if (!nm_sentinel_verify($conn,$hdrTok)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'bad token']); exit; }
    $body = json_decode(file_get_contents('php://input'), true); if (!is_array($body)) $body=[];
    $uidStr = substr(preg_replace('/[^A-Za-z0-9._:-]/','',(string)($body['uid']??'')),0,64);
    if ($api==='enroll') { echo json_encode(nm_sentinel_register($conn,$uidStr,(string)($body['hostname']??''),$body)); exit; }
    $nid=0; if ($uidStr!==''){ $q=$conn->prepare("SELECT id FROM nm_sentinel_nodes WHERE uid=? LIMIT 1"); $q->bind_param('s',$uidStr); $q->execute(); if($row=$q->get_result()->fetch_assoc()) $nid=(int)$row['id']; $q->close(); }
    if (!$nid) { echo json_encode(['ok'=>false,'error'=>'not enrolled']); exit; }
    if ($api==='desired') { echo json_encode(nm_sentinel_desired($conn,$body)); exit; }
    if ($api==='report')  { echo json_encode(nm_sentinel_report($conn,$nid,$body)); exit; }
    echo json_encode(['ok'=>false,'error'=>'unknown agent api']); exit;
}

// ── UI (session) ─────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
require_once('access_control.php');
require_once('nm_chrome.php');
include('logger.php');
if (!checkAccess($conn,'sentinel')) {
    if ($api || ($_POST['action']??'')) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=sentinel'); exit;
}
if (function_exists('session_write_close')) @session_write_close();
$uid = (int)($_SESSION['user_id'] ?? 0) ?: null;
if (is_file(__DIR__.'/nm_nettools.php')) require_once __DIR__.'/nm_nettools.php';   // nm_geo_badge (GeoIP flags; optional)

$act = $_POST['action'] ?? '';
if ($act !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if ($act==='toggle')      { nm_sentinel_cfg_set($conn,(string)$_POST['key'],(string)$_POST['val']); echo json_encode(['ok'=>true]); exit; }
    if ($act==='refresh')     { @set_time_limit(90); echo json_encode(nm_sentinel_refresh_feeds($conn)); exit; }
    if ($act==='quarantine')  { @set_time_limit(60); echo json_encode(nm_sentinel_quarantine($conn,(string)($_POST['ip']??''),'manual',$uid)); exit; }
    if ($act==='release')     { @set_time_limit(60); echo json_encode(nm_sentinel_release($conn,(string)($_POST['ip']??''),$uid)); exit; }
    if ($act==='rotate_token'){ echo json_encode(['ok'=>true,'token'=>nm_sentinel_token_rotate($conn)]); exit; }
    if ($act==='add_indicator'){
        $ind=trim((string)($_POST['indicator']??'')); if($ind==='') { echo json_encode(['ok'=>false,'error'=>'empty']); exit; }
        $kind = filter_var($ind,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)?'ip':(preg_match('/^[a-z0-9.\-]+\.[a-z]{2,}$/i',$ind)?'domain':'');
        if(!$kind){ echo json_encode(['ok'=>false,'error'=>'enter a valid IPv4 or domain']); exit; }
        $ok=nm_sentinel_intel_add($conn,strtolower($ind),$kind,'manual',(string)($_POST['category']??'manual'),99);
        if(function_exists('nm_audit')){ try{ nm_audit($conn,'sentinel.intel_add',['target_type'=>'indicator','target_id'=>$ind]); }catch(\Throwable $e){} }
        echo json_encode(['ok'=>true,'kind'=>$kind,'added'=>$ok]); exit;
    }
    if ($act==='mirror')      { @set_time_limit(40); echo json_encode(nm_sentinel_mirror($conn,(int)($_POST['router']??0),(string)($_POST['sensor_ip']??''),($_POST['enable']??'0')==='1',$uid)); exit; }
    if ($act==='router_probe'){ @set_time_limit(40); echo json_encode(nm_sentinel_router_probe($conn,(int)($_POST['router']??0))); exit; }
    if ($act==='deploy_router'){ @set_time_limit(180); echo json_encode(nm_sentinel_deploy_router($conn,(int)($_POST['router']??0),$uid,(string)($_POST['storage']??'')?:null)); exit; }
    if ($act==='remove_router'){ @set_time_limit(90); echo json_encode(nm_sentinel_remove_router_container($conn,(int)($_POST['router']??0),$uid)); exit; }
    echo json_encode(['ok'=>false,'error'=>'unknown action']); exit;
}
if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if ($api==='data') {
        $hits = nm_sentinel_hits_list($conn,60);
        if (function_exists('nm_geo_badge')) foreach ($hits as &$h) { if ($h['kind']==='ip') { try { $h['geo']=nm_geo_badge($h['remote_indicator']); } catch(\Throwable $e){} } } unset($h);
        echo json_encode(['ok'=>true,'stats'=>nm_sentinel_stats($conn),'cfg'=>nm_sentinel_cfg($conn),
            'hits'=>$hits,'quarantine'=>nm_sentinel_quarantine_list($conn),'sensors'=>nm_sentinel_sensors($conn),
            'routers'=>nm_sentinel_mirror_routers($conn),'feeds'=>nm_sentinel_feeds_info($conn),'token'=>nm_sentinel_token_ensure($conn)]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}

log_user_action($conn,'view_page','sentinel.php');
$NEURU_BASE = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off'?'https':'http').'://'.($_SERVER['HTTP_HOST'] ?? 'YOUR-NEURU-HOST');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NEURU Sentinel | Threat Interception</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.05); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --neon:#ff2d6b; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#04070d; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.12; }
.wrap{ max-width:1280px; margin:0 auto; padding:18px 20px 48px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:8px 14px; font-size:13px; cursor:pointer; }
.btn:hover{ background:rgba(77,163,255,.25); } .btn.sm{ padding:4px 10px; font-size:11px; } .btn.ghost{ background:transparent; border-color:var(--border); color:#aab; }
.btn.danger{ border-color:rgba(255,45,107,.5); color:#ff9cbb; background:rgba(255,45,107,.12); }
.stats{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:18px; }
.stat{ padding:16px; text-align:center; position:relative; overflow:hidden; }
.stat .v{ font-size:30px; font-weight:800; line-height:1; } .stat .l{ font-size:11px; color:#8a909a; margin-top:6px; text-transform:uppercase; letter-spacing:.6px; }
.stat.threat .v{ color:var(--neon); text-shadow:0 0 18px rgba(255,45,107,.5); }
.mods{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
.mod{ display:flex; align-items:center; gap:8px; border:1px solid var(--border); border-radius:10px; padding:8px 12px; font-size:12.5px; }
.mod b{ font-weight:700; } .switch{ position:relative; width:40px; height:22px; } .switch input{ opacity:0; width:0; height:0; }
.slider{ position:absolute; inset:0; background:#444; border-radius:22px; cursor:pointer; transition:.2s; } .slider:before{ content:""; position:absolute; height:16px; width:16px; left:3px; top:3px; background:#fff; border-radius:50%; transition:.2s; }
input:checked+.slider{ background:var(--ok); } input:checked+.slider:before{ transform:translateX(18px); }
table{ width:100%; border-collapse:collapse; font-size:12.5px; } th{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; padding:7px 9px; border-bottom:1px solid var(--border); } td{ padding:7px 9px; border-bottom:1px solid rgba(255,255,255,.05); }
.mono{ font-family:monospace; } .muted{ color:#7c828c; font-size:12px; }
.pill{ font-size:10px; font-weight:700; padding:2px 8px; border-radius:20px; }
.a-alert{ background:rgba(243,156,18,.14); color:#f0c674; } .a-blocked{ background:rgba(46,204,113,.14); color:#7fe0a3; } .a-quarantined{ background:rgba(255,45,107,.16); color:#ff9cbb; }
h3{ font-size:14px; margin:0 0 10px; color:var(--accent); display:flex; align-items:center; gap:8px; }
pre{ background:rgba(0,0,0,.5); border:1px solid var(--border); border-radius:10px; padding:12px; overflow:auto; font-size:11px; color:#cfe4ff; }
.cols{ display:grid; grid-template-columns:1.6fr 1fr; gap:16px; } @media(max-width:900px){ .cols{ grid-template-columns:1fr; } }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-shield-halved"></i>NEURU Sentinel', '', 'Non-intrusive threat interception · out-of-band', 'fa-solid fa-shield-halved',
    '<button class="refresh-btn" onclick="howItWorks()"><i class="fas fa-circle-question"></i> How it works</button> <button class="refresh-btn" onclick="refreshFeeds(this)"><i class="fas fa-satellite-dish"></i> Refresh intel</button> <button class="refresh-btn" onclick="load()"><i class="fas fa-rotate"></i> Refresh</button>'); ?>

<div class="stats" id="stats"></div>

<div class="glass card">
  <h3><i class="fas fa-brain"></i> Threat intelligence <span class="muted" id="intel-age" style="font-weight:400;font-size:11px;margin-left:6px;"></span></h3>
  <div style="display:flex;gap:20px;flex-wrap:wrap;align-items:flex-start;">
    <div style="flex:1;min-width:260px;">
      <div id="feeds" class="muted">—</div>
    </div>
    <div style="flex:1;min-width:260px;border-left:1px solid var(--border);padding-left:20px;">
      <div class="muted" style="font-size:11.5px;margin-bottom:6px;"><i class="fas fa-plus"></i> Add your own indicator (IP or domain) to the matrix:</div>
      <div style="display:flex;gap:8px;">
        <input id="ind" placeholder="1.2.3.4  or  bad-domain.ru" style="flex:1;background:rgba(255,255,255,.05);color:#e6e9ee;border:1px solid var(--border);border-radius:8px;padding:8px 11px;font-size:13px;">
        <button class="btn" onclick="addInd()"><i class="fas fa-plus"></i> Add</button>
      </div>
      <div class="muted" id="ind-msg" style="font-size:11.5px;margin-top:6px;min-height:14px;"></div>
    </div>
  </div>
</div>

<div class="glass card">
  <h3><i class="fas fa-sliders"></i> Defense modules</h3>
  <div class="mods" id="mods"></div>
</div>

<div class="cols">
  <div class="glass card">
    <h3><i class="fas fa-radiation"></i> Live threat interceptions</h3>
    <div id="hits" class="muted">Loading…</div>
  </div>
  <div>
    <div class="glass card">
      <h3><i class="fas fa-box"></i> Quarantined hosts</h3>
      <div id="quar" class="muted">—</div>
    </div>
    <div class="glass card">
      <h3><i class="fas fa-microchip"></i> Sensor agents</h3>
      <div id="sensors" class="muted">—</div>
      <div id="mirror" style="margin-top:12px;"></div>
      <details style="margin-top:10px;"><summary class="muted" style="cursor:pointer;"><i class="fas fa-rocket"></i> Deploy a sensor (neuru-sentinel)</summary>
        <div style="margin-top:8px;"><span class="muted">Token:</span> <span class="mono" id="tok" style="color:#7fe0a3;"></span>
          <button class="btn ghost sm" onclick="copyTok()">copy</button></div>
        <pre id="compose"></pre>
        <div class="muted" style="font-size:11px;">Or 1-click via Containers → Portainer (image <span class="mono">ghcr.io/hmiranda14/neuru-sentinel:latest</span>, host networking).</div>
      </details>
    </div>
  </div>
</div>
</div>

<!-- How it works modal -->
<div id="hiw" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;align-items:flex-start;justify-content:center;padding:5vh 16px;overflow:auto;" onclick="if(event.target===this)this.style.display='none'">
  <div class="glass" style="max-width:760px;width:100%;padding:26px 30px;">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;"><i class="fas fa-shield-halved" style="color:var(--accent);font-size:20px;"></i><h2 style="margin:0;">How NEURU Sentinel works</h2><span style="flex:1"></span><button class="btn ghost sm" onclick="document.getElementById('hiw').style.display='none'">✕</button></div>
    <p class="muted" style="margin:0 0 16px;">Maximum threat mitigation at lightspeed — <b>without touching the TLS payload</b>. Out-of-band + real-time orchestration on Layer 3/4 and DNS. Zero added latency, never breaks SSL pinning / IoT / gaming.</p>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">
      <div class="glass" style="padding:14px 16px;"><div style="font-weight:700;color:var(--accent);"><i class="fas fa-database"></i> ① SPECTRE</div><div class="muted" style="font-size:12.5px;margin-top:5px;">A live reputation matrix of known-bad IPs/domains (C2, ransomware, botnets, malware). Ingested hourly from free feeds — <b>Abuse.ch Feodo Tracker</b> (C2 IPs) + <b>URLhaus</b> (malware hosts). Add your own indicators too.</div></div>
      <div class="glass" style="padding:14px 16px;"><div style="font-weight:700;color:var(--accent);"><i class="fas fa-wave-square"></i> ② Correlation</div><div class="muted" style="font-size:12.5px;margin-top:5px;">NEURU cross-checks live <b>NetFlow</b> flows (from your routers) + sensor DNS against the matrix. If a local host talks to / resolves something bad → a threat is intercepted. No proxy, no decryption.</div></div>
      <div class="glass" style="padding:14px 16px;"><div style="font-weight:700;color:var(--ok);"><i class="fas fa-shield-virus"></i> ③ VECTOR-SHIELD</div><div class="muted" style="font-size:12.5px;margin-top:5px;">Auto-blocks the bad indicator by fanning it out to your <b>Pi-hole / AdGuard / firewalls</b> (via Collective Immunity) — a sinkhole before it enters the network. CDNs/platforms are allowlisted (no false blocks).</div></div>
      <div class="glass" style="padding:14px 16px;"><div style="font-weight:700;color:var(--neon);"><i class="fas fa-box"></i> ④ NEURO-ISOLATION</div><div class="muted" style="font-size:12.5px;margin-top:5px;">On a confirmed positive, NEURU can quarantine the infected host on its <b>gateway router over SSH</b> (drop-list) — 1-click Release when clean. Opt-in (Auto-isolate toggle).</div></div>
    </div>
    <div style="margin-top:16px;padding:14px 16px;border:1px solid var(--border);border-radius:10px;">
      <div style="font-weight:700;margin-bottom:6px;"><i class="fas fa-microchip"></i> The sensor (optional)</div>
      <div class="muted" style="font-size:12.5px;line-height:1.6;">SPECTRE + NetFlow already protect you <b>server-side, no container needed</b>. The <b>neuru-sentinel</b> sensor adds wire-level DNS visibility. A switched LAN only shows a sensor its own host's traffic — so you can <b>mirror</b> a router's DNS to a sensor (SSH, by IP) or <b>deploy the sensor inside the MikroTik</b> itself (best vantage: the router sees everything). Detection only — the blocking stays with NEURU.</div>
    </div>
    <div style="margin-top:14px;font-size:11.5px;color:#8a909a;"><b>Flow:</b> feeds → matrix → correlate NetFlow/DNS → intercept → block (Pi-hole/AdGuard/FW) → optional quarantine → 1-click release. <b>Latency added: 0 ms.</b></div>
  </div>
</div>

<script>
let TOKEN='';
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
async function post(b){ return fetch('sentinel.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b}).then(r=>r.json()).catch(()=>null); }
const MODS=[['spectre','SPECTRE','Threat-intel matrix'],['vector','VECTOR-SHIELD','Sinkhole / auto-block'],['pulse','PULSE-CHECK','Wire hash inspection'],
            ['auto_block','Auto-block','Block bad indicators'],['auto_isolate','Auto-isolate','Quarantine infected host']];
function statTile(v,l,cls){ return `<div class="glass stat ${cls||''}"><div class="v">${v}</div><div class="l">${l}</div></div>`; }
function load(){ fetch('sentinel.php?api=data').then(r=>r.json()).then(render).catch(()=>{}); }
function render(r){
  if(!r||!r.ok)return; TOKEN=r.token;
  const s=r.stats;
  const fmt=n=>n>=1e6?(n/1e6).toFixed(1)+'M':(n>=1e3?(n/1e3).toFixed(1)+'K':n);
  document.getElementById('stats').innerHTML =
    statTile(s.matrix.toLocaleString(),'Threat matrix')+
    statTile(fmt(s.scanned||0),'Scanned (DNS+flows)')+
    statTile(s.hits_24h,'Threats 24h','threat')+
    statTile(s.neutralized,'Neutralized')+
    statTile(s.quarantined,'Quarantined')+
    statTile(s.sensors_on+'/'+s.sensors,'Sensors online')+
    statTile(s.feed_age==null?'—':(s.feed_age<90?'fresh':(s.feed_age<1440?s.feed_age+'m':Math.floor(s.feed_age/1440)+'d')),'Intel age');
  // feeds detail + intel freshness
  const f=r.feeds||{};
  document.getElementById('intel-age').innerHTML = f.refreshed_at? `· updated ${esc(f.refreshed_at)} · refreshes ${esc(f.refresh_every)}${f.next_auto?' · next auto ~'+esc(f.next_auto):''}` : '· not refreshed yet';
  document.getElementById('feeds').innerHTML = (f.sources&&f.sources.length)?
    '<div style="font-size:12px;">'+f.sources.map(x=>`<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.05);">
      <span><i class="fas fa-satellite-dish" style="opacity:.6"></i> ${esc(x.source)}</span><b>${(+x.n).toLocaleString()}</b></div>`).join('')+
      `<div style="margin-top:8px;color:#8a909a;font-size:11px;">${s.matrix_ip.toLocaleString()} IPs · ${s.matrix_dom.toLocaleString()} domains · scanned ${fmt(s.scanned||0)}, detected ${s.detected||0}</div></div>`
    : '<span class="muted">No feeds loaded yet. Click “Refresh intel”.</span>';
  document.getElementById('mods').innerHTML = MODS.map(m=>{
    const on=(r.cfg[m[0]]==='1');
    return `<div class="mod"><label class="switch"><input type="checkbox" ${on?'checked':''} onchange="toggle('${m[0]}',this.checked)"><span class="slider"></span></label>
      <span><b>${m[1]}</b><br><span class="muted" style="font-size:10.5px">${m[2]}</span></span></div>`;
  }).join('');
  document.getElementById('hits').innerHTML = r.hits.length? '<table><thead><tr><th>When</th><th>Local host</th><th>Threat</th><th>Cat</th><th>Action</th></tr></thead><tbody>'+
    r.hits.map(h=>`<tr><td class="muted">${esc(String(h.created_at).slice(5,16))}</td><td class="mono">${esc(h.local_ip||'—')}</td>
      <td class="mono" style="color:var(--neon)">${h.geo?h.geo+' ':''}${esc(h.remote_indicator)}</td><td>${esc(h.category)}</td>
      <td><span class="pill a-${esc(h.action)}">${esc(h.action)}</span>${h.local_ip&&h.action!=='quarantined'?` <button class="btn danger sm" onclick="quar('${esc(h.local_ip)}')">isolate</button>`:''}</td></tr>`).join('')+'</tbody></table>'
    : '<div style="color:var(--ok);padding:8px;"><i class="fas fa-circle-check"></i> No threats intercepted. Network clean.</div>';
  document.getElementById('quar').innerHTML = r.quarantine.length? '<table><tbody>'+r.quarantine.map(q=>`<tr>
      <td class="mono" style="color:var(--neon)">${esc(q.local_ip)}</td><td class="muted" style="font-size:11px">${esc(q.gw||'')}</td>
      <td><button class="btn sm" onclick="release('${esc(q.local_ip)}')"><i class="fas fa-unlock"></i> Release</button></td></tr>`).join('')+'</tbody></table>'
    : '<span class="muted">None isolated.</span>';
  document.getElementById('sensors').innerHTML = r.sensors.length? r.sensors.map(x=>`<div style="display:flex;gap:8px;align-items:center;margin-bottom:5px;">
      <span style="width:8px;height:8px;border-radius:50%;background:${x.online?'var(--ok)':'#555'};box-shadow:${x.online?'0 0 7px var(--ok)':'none'}"></span>
      <span style="flex:1">${esc(x.name)} <span class="muted mono">${esc(x.ip_address||'')}</span></span>
      <span class="muted" style="font-size:11px">${(+x.neutralized||0)} caught</span></div>`).join('')
    : '<span class="muted">No sensors deployed. Deploy one below (optional — SPECTRE+NetFlow already protect you server-side).</span>';
  // Traffic mirror — point a router's DNS stream at a sensor so it sees the whole network
  const sens = r.sensors||[]; const rts = r.routers||[];
  const sensOpts = sens.map(x=>`<option value="${esc(x.ip_address||'')}">${esc(x.name)} (${esc(x.ip_address||'')})</option>`).join('');
  document.getElementById('mirror').innerHTML = rts.length? '<div class="muted" style="font-size:11px;margin-bottom:6px;"><i class="fas fa-clone"></i> Mirror a router\'s DNS traffic to a sensor (so one sensor sees the whole LAN, no SPAN cable):</div>'+
    rts.map(rt=>{
      const on = rt.mirror_to && rt.mirror_to!=='';
      const inRtr = rt.container_ip && rt.container_ip!=='';
      let right;
      if (inRtr) right = `<span class="pill a-blocked">sensor on router @${esc(rt.container_ip)}</span><button class="btn danger sm" onclick="rmRouter(${rt.id})">remove</button>`;
      else if (on) right = `<span class="pill a-blocked">mirror → ${esc(rt.mirror_to)}</span><button class="btn ghost sm" onclick="mirror(${rt.id},'',0)">stop</button>`;
      else right = `<button class="btn sm" onclick="deployRouter(${rt.id})" title="Run the sensor as a container INSIDE this router (sees all traffic)"><i class="fas fa-microchip"></i> deploy on router</button>`
             + (sens.length? ` <select class="mono" id="ms-${rt.id}" style="background:#1b2129;color:#e6e9ee;border:1px solid var(--border);border-radius:7px;padding:4px 7px;font-size:11px;">${sensOpts}</select><button class="btn ghost sm" onclick="mirror(${rt.id},document.getElementById('ms-${rt.id}').value,1)" title="Or mirror to an external sensor"><i class="fas fa-clone"></i> mirror</button>` : '');
      return `<div style="display:flex;gap:6px;align-items:center;margin-bottom:6px;font-size:12px;flex-wrap:wrap;">
        <span style="flex:1;min-width:130px"><i class="fas fa-route" style="opacity:.6"></i> ${esc(rt.display_name)}</span>${right}</div>`;
    }).join('')
    : '';
  document.getElementById('tok').textContent=TOKEN;
  document.getElementById('compose').textContent=composeText();
}
async function mirror(router,ip,enable){
  if(enable && !ip){ alert('pick a sensor'); return; }
  if(enable && !confirm('Stream this router\'s DNS traffic to '+ip+'? (low bandwidth, reversible)'))return;
  const r=await post(new URLSearchParams({action:'mirror',router,sensor_ip:ip,enable:enable?'1':'0'}));
  if(r&&r.ok) load(); else alert(r?r.error:'failed');
}
async function deployRouter(router){
  const m=document.getElementById('mirror'); const busy=document.createElement('div'); busy.className='muted'; busy.innerHTML='<i class="fas fa-spinner fa-spin"></i> probing router…'; m.prepend(busy);
  const p=await post(new URLSearchParams({action:'router_probe',router})); busy.remove();
  if(!p||!p.ok){ alert(p?p.error:'probe failed'); return; }
  if(!p.has_container){ alert('This router doesn\'t have the RouterOS container package/device-mode enabled.'); return; }
  let storage=p.storage;
  const opts=p.storage_options||[];
  if(opts.length>1){ storage=prompt('Install on which storage? Options: '+opts.join(', '), p.storage); if(storage===null)return; }
  if(!confirm(`Deploy the NEURU Sentinel sensor as a container INSIDE ${p.router}?\n\n• container IP: ${p.free_ip}\n• storage: ${storage}\n• the router will stream all DNS to it\n\nAdditive & reversible (won't touch other containers). The image (~1-2 min) pulls on the router.`))return;
  const bd=document.createElement('div'); bd.className='muted'; bd.innerHTML='<i class="fas fa-spinner fa-spin"></i> deploying on router (pulling image, ~1-2 min)…'; m.prepend(bd);
  const r=await post(new URLSearchParams({action:'deploy_router',router,storage})); bd.remove();
  if(r&&r.ok){ alert('✅ Deployed on '+r.router+' @'+r.container_ip+'.\n'+(r.note||'')+'\n\n'+(r.log||[]).join('\n')); load(); }
  else alert(r?('Deploy failed: '+r.error):'failed');
}
async function rmRouter(router){ if(!confirm('Remove the sensor container from this router? (Pi-hole and other containers are untouched)'))return;
  const r=await post(new URLSearchParams({action:'remove_router',router})); if(r&&r.ok)load(); else alert(r?r.error:'failed'); }
function composeText(){ return `services:
  neuru-sentinel:
    image: ghcr.io/hmiranda14/neuru-sentinel:latest
    container_name: neuru-sentinel
    restart: unless-stopped
    network_mode: host        # packet/DNS capture needs host net
    cap_add: ["NET_ADMIN","NET_RAW"]
    environment:
      NEURU_URL: "<?= htmlspecialchars($NEURU_BASE) ?>"
      SENTINEL_TOKEN: "${TOKEN}"
      # VERIFY_TLS: "0"`; }
function copyTok(){ navigator.clipboard.writeText(TOKEN); }
async function toggle(k,v){ await post(new URLSearchParams({action:'toggle',key:k,val:v?'1':'0'})); }
async function quar(ip){ if(!confirm('Isolate '+ip+' on its gateway router? Its traffic will be dropped until you release it.'))return;
  const r=await post(new URLSearchParams({action:'quarantine',ip})); if(r&&r.ok){load();} else alert(r?r.error:'failed'); }
async function release(ip){ const r=await post(new URLSearchParams({action:'release',ip})); if(r&&r.ok)load(); else alert(r?r.error:'failed'); }
async function refreshFeeds(btn){ if(btn){btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> refreshing…';}
  const r=await post(new URLSearchParams({action:'refresh'}));
  if(btn){btn.disabled=false; btn.innerHTML='<i class="fas fa-satellite-dish"></i> Refresh intel';} if(r&&r.ok) load(); }
async function addInd(){
  const v=document.getElementById('ind').value.trim(); const m=document.getElementById('ind-msg'); if(!v){m.textContent='enter an IP or domain';return;}
  const r=await post(new URLSearchParams({action:'add_indicator',indicator:v}));
  if(r&&r.ok){ m.innerHTML='<span style="color:var(--ok)">✓ added '+esc(v)+' ('+esc(r.kind)+') to the matrix — sensors sync it within a poll</span>'; document.getElementById('ind').value=''; load(); }
  else m.innerHTML='<span style="color:var(--crit)">'+(r?esc(r.error):'failed')+'</span>';
}
function howItWorks(){ document.getElementById('hiw').style.display='flex'; }
load(); setInterval(load, 30000);
</script>
</body></html>
