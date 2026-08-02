<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Shadow IT Discovery UI. Behavior-fingerprinted NetFlow → likely
// unauthorized VPN/mesh tunnels & crypto-mining. Review → allowlist / dismiss /
// block (hand off to Collective Immunity). RBAC: 'shadowit'. Engine: nm_shadowit.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_shadowit.php');
require_once('nm_nettools.php');   // nm_geo_badge() — country flag for external endpoints
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'shadowit')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=shadowit'); exit;
}
nm_si_ensure($conn);
$canConfig = nm_can($conn,'net_mon_config');

if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    $body = json_decode(file_get_contents('php://input'), true) ?? $_POST;
    if ($api === 'data') {
        // IP → friendly node/router name (so the user knows WHICH device & who reported it)
        $NAME=[]; if($nr=$conn->query("SELECT ip_address,display_name FROM nm_nodes WHERE ip_address<>''")){ while($x=$nr->fetch_assoc()) $NAME[$x['ip_address']]=$x['display_name']; }
        $resolve=function($ip)use($NAME){ $ip=trim($ip); return ($ip!=='' && isset($NAME[$ip])) ? ($NAME[$ip].' ('.$ip.')') : $ip; };
        $reporters=function($exp)use($resolve){ $exp=trim((string)$exp); if($exp==='') return []; return array_map($resolve, array_filter(array_map('trim', explode(',', $exp)))); };
        $rows=array_map(fn($f)=>['id'=>(int)$f['id'],'src'=>$f['src_ip'],'dst'=>$f['dst_ip'],'proto'=>(int)$f['protocol'],'port'=>(int)$f['app_port'],
            'class'=>$f['classification'],'conf'=>(int)$f['confidence'],'evidence'=>$f['evidence'],'mbps'=>(float)$f['mbps'],'status'=>$f['status'],'hits'=>(int)$f['hits'],'last_seen'=>$f['last_seen'],
            'src_name'=>$resolve($f['src_ip']), 'reporters'=>$reporters($f['exporter'] ?? ''),
            'geo'=>(($g=nm_geo_badge($conn,$f['dst_ip']))?['flag'=>$g['flag'],'country'=>$g['country'],'city'=>$g['city']]:null)], nm_si_list($conn));
        echo json_encode(['ok'=>true,'findings'=>$rows,'counts'=>nm_si_counts($conn)]); exit;
    }
    if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
    if ($api === 'scan')    { echo json_encode(['ok'=>true]+nm_si_scan($conn)); exit; }
    if ($api === 'ack')     { nm_si_set_status($conn,(int)($body['id']??0),'acknowledged'); echo json_encode(['ok'=>true]); exit; }
    if ($api === 'dismiss') { nm_si_set_status($conn,(int)($body['id']??0),'dismissed'); echo json_encode(['ok'=>true]); exit; }
    if ($api === 'allow')   { nm_si_set_status($conn,(int)($body['id']??0),'allowlisted'); echo json_encode(['ok'=>true]); exit; }
    if ($api === 'block') {
        // hand off the external endpoint to Collective Immunity (block on firewalls)
        if (!is_file(__DIR__.'/nm_immunity.php')) { echo json_encode(['ok'=>false,'error'=>'Immunity not available']); exit; }
        require_once __DIR__.'/nm_immunity.php';
        $id=(int)($body['id']??0); $f=$conn->query("SELECT * FROM nm_shadowit_findings WHERE id={$id} LIMIT 1"); $f=$f?$f->fetch_assoc():null;
        if(!$f){ echo json_encode(['ok'=>false,'error'=>'not found']); exit; }
        $ext = !_si_internal($f['src_ip']) ? $f['src_ip'] : (!_si_internal($f['dst_ip']) ? $f['dst_ip'] : $f['dst_ip']);
        $t=nm_imm_add_threat($conn,$ext,'ip','shadowit','high','Shadow IT '.$f['classification'].': '.$f['evidence'],(int)($_SESSION['UID']??0));
        $v=!empty($t['ok'])?nm_imm_vaccinate($conn,(int)$t['id']):['ok'=>false];
        nm_si_set_status($conn,$id,'acknowledged');
        echo json_encode(['ok'=>true,'blocked'=>$ext,'vaccine'=>$v]); exit;
    }
    if ($api === 'save_settings') {
        if(!$canConfig){ echo json_encode(['ok'=>false,'error'=>'Not allowed']); exit; }
        $set=function($k,$v)use($conn){ $st=$conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)"); $st->bind_param('ss',$k,$v); $st->execute(); };
        $set('si_window_min',(string)max(5,(int)($body['si_window_min']??30)));
        $set('si_allowlist',substr((string)($body['si_allowlist']??''),0,2000));
        echo json_encode(['ok'=>true]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'Unknown endpoint']); exit;
}
$counts=nm_si_counts($conn);
$S=['win'=>nm_si_setting($conn,'si_window_min','30'),'allow'=>nm_si_setting($conn,'si_allowlist','')];
log_user_action($conn,'view_page','shadowit.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shadow IT | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --vpn:#9b59b6; --mine:#e67e22; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.18; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 40px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; } .card h3{ margin:0 0 12px; font-size:12px; color:var(--accent); text-transform:uppercase; letter-spacing:1px; }
.kpis{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-bottom:16px; }
.kpi{ padding:14px 16px; text-align:center; } .kpi .n{ font-size:26px; font-weight:800; } .kpi .l{ font-size:11px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; }
.grid2{ display:grid; grid-template-columns:1.7fr 1fr; gap:16px; } @media(max-width:900px){ .grid2{ grid-template-columns:1fr; } }
table{ width:100%; border-collapse:collapse; font-size:13px; } th,td{ text-align:left; padding:9px 10px; border-bottom:1px solid rgba(255,255,255,.07); vertical-align:middle; }
#tbl thead th{ position:sticky; top:0; z-index:2; background:#0c111a; box-shadow:0 1px 0 rgba(255,255,255,.10); }
th{ color:#7c828c; font-size:11px; text-transform:uppercase; letter-spacing:.5px; }
.b{ font-size:9px; font-weight:800; padding:2px 8px; border-radius:5px; text-transform:uppercase; }
.c-vpn{ background:rgba(155,89,182,.18); color:#c08fd6;} .c-mining{ background:rgba(230,126,34,.18); color:#f0a868;} .c-tunnel{ background:rgba(243,156,18,.18); color:var(--warn);}
.conf{ font-weight:800; } .muted{ color:#7c828c; font-size:12px; } .mono{ font-family:Consolas,monospace; font-size:12px; }
.btn{ background:rgba(255,255,255,.06); border:1px solid var(--border); color:#cfd3da; padding:6px 10px; border-radius:7px; cursor:pointer; font-size:11px; display:inline-flex; gap:5px; align-items:center; }
.btn:hover{ background:rgba(255,255,255,.13); color:#fff; } .btn.danger:hover{ border-color:var(--crit); color:var(--crit);} .btn.ok:hover{ border-color:var(--ok); color:var(--ok);}
.inp,textarea{ width:100%; background:rgba(0,0,0,.4); border:1px solid var(--border); color:#eee; border-radius:8px; padding:8px 10px; font-size:12.5px; font-family:inherit; } textarea{ font-family:Consolas,monospace; min-height:90px; }
label{ display:block; font-size:11px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; margin:10px 0 4px; }
.si-row:hover{ background:rgba(255,255,255,.04); }
.si-detail{ display:none; } .si-detail.open{ display:table-row; }
.si-exp{ padding:13px 15px; background:rgba(0,0,0,.28); border:1px solid var(--border); border-radius:10px; margin:2px 0 8px; font-size:13px; line-height:1.55; }
.si-row.open .fa-chevron-down,.si-detail.open{ }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-user-secret"></i>Shadow IT', '', 'Blind Traffic Fingerprinting', 'fa-solid fa-user-secret',
    '<button class="refresh-btn" onclick="scan(this)"><i class="fas fa-radar"></i> Scan now</button>'); ?>

<!-- Plain-English explainer (collapsible) -->
<div class="glass card" id="howto" style="border-left:3px solid var(--accent);">
  <div style="display:flex;align-items:center;gap:10px;cursor:pointer;" onclick="var b=document.getElementById('howto-body');b.style.display=b.style.display==='none'?'block':'none';">
    <i class="fas fa-circle-question" style="color:var(--accent);font-size:16px;"></i>
    <b style="font-size:13px;">What is Shadow IT — and how does this page work?</b>
    <span class="muted" style="margin-left:auto;font-size:11px;">click to expand/collapse</span>
  </div>
  <div id="howto-body" style="margin-top:12px;font-size:13px;line-height:1.65;color:#c5ccd6;">
    <p style="margin:0 0 10px;"><b>“Shadow IT”</b> = software/connections on your network that <b>nobody approved</b> — e.g. a staff laptop running a personal VPN, a mesh tunnel (Tailscale) that bypasses your firewall, or malware quietly <b>crypto-mining</b>. It's risky because it opens backdoors and hides traffic from your controls.</p>
    <p style="margin:0 0 10px;"><b>How NEURU finds it:</b> it does NOT read your traffic content (it can't — it's encrypted). Instead it looks at <b>NetFlow metadata</b> (who talked to whom, on what port, how big the packets, how long, how persistent) and <b>fingerprints the behavior</b>. So every finding is a <b>“likely”</b> classification, not decrypted proof — <b>confirm before you block.</b></p>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-top:6px;">
      <div style="background:rgba(231,76,60,.08);border:1px solid rgba(231,76,60,.3);border-radius:10px;padding:10px;"><b style="color:#ff9c91;"><i class="fas fa-coins"></i> Crypto-mining</b><br><span class="muted" style="font-size:12px;">Persistent connections to a known mining pool → malware/unauthorized miner stealing CPU & power.</span></div>
      <div style="background:rgba(243,156,18,.08);border:1px solid rgba(243,156,18,.3);border-radius:10px;padding:10px;"><b style="color:#f3c879;"><i class="fas fa-shield-halved"></i> VPN / mesh tunnel</b><br><span class="muted" style="font-size:12px;">WireGuard/Tailscale/OpenVPN signature out to the internet → may bypass firewall &amp; open a backdoor.</span></div>
      <div style="background:rgba(77,163,255,.08);border:1px solid rgba(77,163,255,.3);border-radius:10px;padding:10px;"><b style="color:#9ec5ff;"><i class="fas fa-right-left"></i> Long-lived tunnel</b><br><span class="muted" style="font-size:12px;">Unusually long, high-volume link to an external host on an odd port → tunnel, sync, or data exfil.</span></div>
    </div>
    <p style="margin:10px 0 0;"><b>Flow direction:</b> each row reads <code>your device → external endpoint</code>. <b>What to do</b> is shown on every finding (click <i class="fas fa-chevron-down"></i> on a row). In short: <b style="color:#9af3c0;">Allowlist</b> if it's authorized (it stops alerting), <b style="color:#ff9c91;">Block</b> to push the external IP to every firewall via Collective Immunity, or <b>Dismiss</b> to set aside.</p>
  </div>
</div>

<div class="kpis">
  <div class="glass kpi"><div class="n" style="color:var(--warn)" id="k-new"><?= (int)$counts['new'] ?></div><div class="l">New findings</div></div>
  <div class="glass kpi"><div class="n" style="color:var(--vpn)" id="k-vpn">—</div><div class="l">VPN / tunnels</div></div>
  <div class="glass kpi"><div class="n" style="color:var(--mine)" id="k-mine">—</div><div class="l">Crypto-mining</div></div>
</div>

<div class="grid2">
  <div class="glass card">
    <h3><i class="fas fa-fingerprint"></i> Flagged flows <span class="muted" style="text-transform:none;letter-spacing:0;">— behavior, not payload</span></h3>
    <div id="empty" class="muted" style="display:none;padding:8px;">No shadow traffic detected. Clean. 🕵️</div>
    <div style="overflow:auto;max-height:62vh;"><table id="tbl"><thead><tr><th></th><th>What we detected</th><th>Likelihood</th><th>Your device → External</th><th style="text-align:right;">Actions</th></tr></thead>
      <tbody id="tb"><tr><td colspan="5" class="muted" style="text-align:center;padding:16px;">Loading…</td></tr></tbody></table></div>
  </div>
  <div class="glass card">
    <h3><i class="fas fa-gear"></i> Detection</h3>
    <p class="muted" style="margin:0 0 8px;">NetFlow is metadata — these are <b>likely</b> classifications by behavior (port/size/persistence), not decrypted proof.</p>
    <label>Scan window (minutes)</label>
    <input class="inp" id="s-win" value="<?= htmlspecialchars($S['win']) ?>" <?= $canConfig?'':'disabled' ?>>
    <label>Allowlist <span class="muted">(authorized — IP or IP:port, comma/newline)</span></label>
    <textarea class="inp" id="s-allow" placeholder="67.203.215.235&#10;70.45.23.154:51820" <?= $canConfig?'':'disabled' ?>><?= htmlspecialchars($S['allow']) ?></textarea>
    <?php if($canConfig): ?><div style="margin-top:10px;"><button class="btn" onclick="saveSettings(this)"><i class="fas fa-save"></i> Save</button> <span class="muted" id="s-msg"></span></div><?php endif; ?>
    <div class="muted" style="margin-top:12px;line-height:1.6;border-top:1px solid var(--border);padding-top:10px;">
      <b>Tip:</b> your authorized WireGuard endpoints will appear here — hit <b>Allowlist</b> on them so they stop alerting. <b>Block</b> hands the external IP to Collective Immunity.
    </div>
  </div>
</div>
</div>
<script>
const CAN=<?= $canConfig?'true':'false' ?>;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
async function post(api,obj){ return fetch('shadowit.php?api='+api,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj||{})}).then(r=>r.json()).catch(()=>({ok:false,error:'failed'})); }
const PROTO={6:'tcp',17:'udp',1:'icmp'};
// Plain-English meaning + REAL recommended actions per classification
const CLS={
  mining:{label:'Likely crypto-mining',icon:'fa-coins',color:'#e74c3c',
    what:'A device is making persistent connections to a known cryptocurrency mining pool. This is almost always malware or an unauthorized miner — it steals CPU/GPU and electricity and may signal a compromised host.',
    todo:['Identify the device (the left IP) and who/what owns it.','On that host, find &amp; kill the miner: check Task Manager / <code>top</code> for high-CPU processes, plus Startup items &amp; scheduled tasks.','Hit <b>Block</b> → pushes the pool IP to every firewall so no device can reach it.','Run a full AV/EDR scan and rotate that user’s credentials.']},
  vpn:{label:'Unauthorized VPN / mesh tunnel',icon:'fa-shield-halved',color:'#f39c12',
    what:'A device is running a VPN or mesh-VPN client (WireGuard, Tailscale, OpenVPN…) out to the internet. If it wasn’t approved, it can bypass your firewall/monitoring and open a backdoor into the LAN.',
    todo:['Ask the device owner: is this an approved remote-access tool?','If <b>authorized</b> → hit <b>Allowlist</b> (it stops alerting).','If <b>NOT</b> → <b>Block</b> the endpoint and remove the VPN client from the host.','Tighten firewall egress rules so only sanctioned devices can open tunnels.']},
  tunnel:{label:'Long-lived external tunnel',icon:'fa-right-left',color:'#4da3ff',
    what:'A device holds an unusually long-lived, high-volume connection to an external host on a non-standard port. Could be a legitimate backup/sync — or a tunnel used for data exfiltration.',
    todo:['Identify the device and the destination (right IP) — trace/geolocate it to see where it goes.','If it’s a known backup/sync service → <b>Allowlist</b>.','If unknown/suspicious → <b>Block</b> and investigate the host for unexpected software.']},
};
function clsInfo(c){ return CLS[c]||{label:c,icon:'fa-question',color:'#888',what:'Unclassified behavior flagged by NetFlow fingerprinting.',todo:['Investigate the device and destination.']}; }
function load(){ return _load(); }
async function _load(){
  const r=await fetch('shadowit.php?api=data').then(r=>r.json()).catch(()=>null); if(!r||!r.ok)return;
  document.getElementById('k-new').textContent=(r.counts.new||0);
  document.getElementById('k-vpn').textContent=r.findings.filter(f=>f.class==='vpn'||f.class==='tunnel').length;
  document.getElementById('k-mine').textContent=r.findings.filter(f=>f.class==='mining').length;
  const tb=document.getElementById('tb');
  if(!r.findings.length){ document.getElementById('tbl').style.display='none'; document.getElementById('empty').style.display='block'; return; }
  document.getElementById('tbl').style.display=''; document.getElementById('empty').style.display='none';
  tb.innerHTML=r.findings.map(f=>{ const ci=clsInfo(f.class);
    const conf=f.conf>=80?{t:'High',c:'var(--crit)'}:f.conf>=60?{t:'Medium',c:'var(--warn)'}:{t:'Low',c:'#9aa'};
    return `<tr class="si-row" onclick="document.getElementById('d-${f.id}').classList.toggle('open')" style="cursor:pointer;">
      <td style="text-align:center;width:26px;"><i class="fas fa-chevron-down" style="color:#667;font-size:11px;"></i></td>
      <td><span style="color:${ci.color};font-weight:700;"><i class="fas ${ci.icon}"></i> ${ci.label}</span>
          <div class="muted" style="font-size:11px;">${PROTO[f.proto]||f.proto}/${f.port}${f.hits>1?' · seen ×'+f.hits:''}</div></td>
      <td><span style="color:${conf.c};font-weight:700;">${conf.t}</span> <span class="muted">(${f.conf}%)</span></td>
      <td class="mono">${esc(f.src_name||f.src)} <span style="color:#667;">→</span> ${esc(f.dst)}${f.geo?` <span class="muted" style="font-family:initial;" title="${esc(f.geo.country)}${f.geo.city?' · '+esc(f.geo.city):''}">${f.geo.flag} ${esc(f.geo.country)}</span>`:''}
        <div class="muted" style="font-size:11px;">${f.mbps} Mbps${(f.reporters&&f.reporters.length)?` · <i class="fas fa-satellite-dish" style="color:#4da3ff"></i> via ${esc(f.reporters[0])}${f.reporters.length>1?' +'+(f.reporters.length-1):''}`:''}</div></td>
      <td style="white-space:nowrap;text-align:right;" onclick="event.stopPropagation();">
        <button class="btn ok" onclick="act('allow',${f.id})" title="It's authorized — stop alerting"><i class="fas fa-check"></i> Allow</button>
        <button class="btn danger" onclick="block(${f.id},this)" title="Block the external IP on every firewall (Collective Immunity)"><i class="fas fa-ban"></i> Block</button>
        <button class="btn" onclick="act('dismiss',${f.id})" title="Set aside"><i class="fas fa-xmark"></i></button>
      </td></tr>
      <tr class="si-detail" id="d-${f.id}"><td colspan="5"><div class="si-exp">
        <div><b style="color:${ci.color};"><i class="fas ${ci.icon}"></i> What this means</b><div style="margin-top:4px;color:#c5ccd6;">${ci.what}</div></div>
        <div style="margin-top:11px;"><b style="color:#9af3c0;"><i class="fas fa-list-check"></i> What to do</b>
          <ol style="margin:5px 0 0;padding-left:20px;color:#c5ccd6;line-height:1.75;">${ci.todo.map(x=>'<li>'+x+'</li>').join('')}</ol></div>
        <div style="margin-top:11px;color:#c5ccd6;"><b style="color:#9ec5ff;"><i class="fas fa-satellite-dish"></i> Where this was seen (so you know if you can act)</b>
          <div style="margin-top:4px;">${(f.reporters&&f.reporters.length)
              ? 'Reported by the NetFlow exporter(s): <b>'+f.reporters.map(esc).join('</b>, <b>')+'</b>. The block enforces on the router(s) that actually see this traffic — if a reporter above is one of your firewalls, <b>Block</b> will stop it at the source. Source device: <b>'+esc(f.src_name||f.src)+'</b>.'
              : 'No exporter recorded for this flow (older finding — run <b>Scan now</b> to refresh). Source device: <b>'+esc(f.src_name||f.src)+'</b>.'}</div></div>
        <div style="margin-top:11px;color:#8a909a;font-size:12px;"><b>Why we flagged it (NetFlow evidence):</b> ${esc(f.evidence)}</div>
      </div></td></tr>`; }).join('');
}
async function scan(btn){ btn.disabled=true; const r=await post('scan',{}); btn.disabled=false; alert(r.ok?`Scanned ${r.scanned} conversations → ${r.flagged} flagged (${r.new} new).`:'Failed'); load(); }
async function act(a,id){ await post(a,{id}); load(); }
async function block(id,btn){ if(!confirm('Block the external endpoint via Collective Immunity (fan-out to firewalls)?'))return; btn.disabled=true; const r=await post('block',{id}); btn.disabled=false; alert(r.ok?('Blocked '+r.blocked+' → '+((r.vaccine&&r.vaccine.distributed)||0)+' firewall(s).'):(r.error||'Failed')); load(); }
async function saveSettings(btn){ btn.disabled=true; const r=await post('save_settings',{si_window_min:document.getElementById('s-win').value,si_allowlist:document.getElementById('s-allow').value}); btn.disabled=false; document.getElementById('s-msg').textContent=r.ok?'Saved ✓':(r.error||'Failed'); }
load(); setInterval(load, 30000);
</script>
</body></html>
