<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — IPAM / Single Source of Truth UI. RBAC: 'ipam'. Engine: nm_ipam.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_ipam.php');
include('logger.php');

$api = $_GET['api'] ?? '';
$act = $_POST['action'] ?? '';
if (!checkAccess($conn, 'ipam')) {
    if ($api || $act) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=ipam'); exit;
}
nm_ipam_ensure($conn);
$uid = (int)($_SESSION['user_id'] ?? 0) ?: null;
// Release the PHP session lock before any slow work (sweep spawn, per-IP ping, SSH DHCP
// pull) so one IPAM request never freezes the user's other tabs. We've read all we need.
if (function_exists('session_write_close')) @session_write_close();

// ── write actions ─────────────────────────────────────────────────────────────
if ($act !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if ($act === 'subnet_add')    { echo json_encode(nm_ipam_subnet_add($conn, $_POST, $uid)); log_user_action($conn,'ipam_subnet_add',$_POST['cidr']??''); exit; }
    if ($act === 'subnet_update') { echo json_encode(nm_ipam_subnet_update($conn, (int)($_POST['id']??0), $_POST)); exit; }
    if ($act === 'subnet_delete') { echo json_encode(nm_ipam_subnet_delete($conn, (int)($_POST['id']??0))); exit; }
    if ($act === 'reserve')       { echo json_encode(nm_ipam_reserve($conn, (int)($_POST['subnet_id']??0), trim((string)($_POST['ip']??'')) ?: null, $_POST, $uid)); exit; }
    if ($act === 'release')       { echo json_encode(nm_ipam_release($conn, (int)($_POST['id']??0))); exit; }
    if ($act === 'import')        { echo json_encode(['ok'=>true,'imported'=>nm_ipam_import_discovery($conn,$uid)]); exit; }
    if ($act === 'detect')        { echo json_encode(nm_ipam_detect_all($conn,$uid)); log_user_action($conn,'ipam_detect_all',''); exit; }
    if ($act === 'iface_sweep')   { @set_time_limit(600); echo json_encode(nm_ipam_iface_sweep($conn,$uid)); log_user_action($conn,'ipam_iface_sweep',''); exit; }
    // On-demand sweep: launch the scanner detached (the UI polls api=live_status), so the
    // request returns instantly and a /24 sweep runs in the background.
    if ($act === 'sweep') {
        $sid = (int)($_POST['subnet_id'] ?? 0);
        if (!$sid || !nm_ipam_subnet($conn, $sid)) { echo json_encode(['ok'=>false,'error'=>'bad subnet']); exit; }
        $py = is_file('/opt/netmon-venv/bin/python3') ? '/opt/netmon-venv/bin/python3' : (trim((string)@shell_exec('command -v python3')) ?: 'python3');
        $script = __DIR__.'/scripts/nm_ipam_scan.py';
        $log = sys_get_temp_dir().'/nm_ipam_scan.log';
        @exec('nohup '.escapeshellarg($py).' '.escapeshellarg($script).' '.$sid.' >> '.escapeshellarg($log).' 2>&1 &');
        log_user_action($conn,'ipam_sweep',(string)$sid);
        echo json_encode(['ok'=>true,'started'=>true,'subnet_id'=>$sid]); exit;
    }
    // Single-IP liveness check (on-demand ping).
    if ($act === 'ping') {
        $ip = trim((string)($_POST['ip'] ?? ''));
        echo json_encode(['ok'=>true,'ip'=>$ip] + nm_ipam_ping($ip)); exit;
    }
    // Pull DHCP servers/pools + leases over SSH (one node, or all router/linux candidates).
    if ($act === 'dhcp_pull') {
        @set_time_limit(180);   // a multi-router pull over SSH can take a while; session is already closed
        $node = ($_POST['node_id'] ?? '') !== '' ? (int)$_POST['node_id'] : 0;
        echo json_encode($node ? nm_ipam_dhcp_pull($conn,$node,$uid) : nm_ipam_dhcp_pull_all($conn,$uid)); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'unknown action']); exit;
}

// ── read API ──────────────────────────────────────────────────────────────────
if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if ($api === 'subnets') {
        $out = [];
        foreach (nm_ipam_subnets($conn) as $s) {
            try { $s['util'] = nm_ipam_utilization($conn, (int)$s['id']); }
            catch (\Throwable $e) { $s['util'] = ['total'=>0,'used'=>0,'free'=>0,'pct'=>0]; }
            $out[] = $s;
        }
        echo json_encode(['ok'=>true,'subnets'=>$out]); exit;
    }
    if ($api === 'util')      { echo json_encode(['ok'=>true,'util'=>nm_ipam_utilization($conn,(int)($_GET['id']??0))]); exit; }
    if ($api === 'next_free') { echo json_encode(['ok'=>true,'ip'=>nm_ipam_next_free($conn,(int)($_GET['id']??0))]); exit; }
    if ($api === 'used') {
        $sn = nm_ipam_subnet($conn,(int)($_GET['id']??0));
        $used = $sn ? nm_ipam_used_ips($conn,$sn) : [];
        $rows = []; foreach ($used as $ip=>$m) { $m['ip']=$ip; $rows[]=$m; }
        usort($rows, fn($a,$b)=>ip2long($a['ip'])<=>ip2long($b['ip']));
        echo json_encode(['ok'=>true,'used'=>$rows,'next'=>nm_ipam_next_free($conn,(int)($_GET['id']??0))]); exit;
    }
    if ($api === 'allocations') { echo json_encode(['ok'=>true,'allocations'=>nm_ipam_allocations($conn, ($_GET['subnet']??'')!==''?(int)$_GET['subnet']:null)]); exit; }
    if ($api === 'conflicts')   { echo json_encode(['ok'=>true,'conflicts'=>nm_ipam_conflicts($conn)]); exit; }
    // The Address Map: every host address in a subnet, categorized (managed/wg/dhcp/discovered/free/…).
    if ($api === 'map') {
        try { echo json_encode(nm_ipam_map($conn,(int)($_GET['id']??0))); }
        catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>'map failed']); }
        exit;
    }
    // Live sweep status (running/done) for the poll loop.
    if ($api === 'live_status') {
        $sid = (int)($_GET['id']??0);
        $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='ipam_scan_status_".$sid."' LIMIT 1");
        $st = $r && ($x=$r->fetch_row()) ? (string)$x[0] : '';
        $cnt = (int)($conn->query("SELECT COUNT(*) FROM nm_ipam_live WHERE subnet_id=".$sid)->fetch_row()[0] ?? 0);
        echo json_encode(['ok'=>true,'status'=>$st,'live'=>$cnt]); exit;
    }
    // DHCP servers + pools + leases (+ pullable candidate devices).
    if ($api === 'dhcp') {
        $sid = ($_GET['subnet']??'')!==''?(int)$_GET['subnet']:null;
        $cands = array_map(fn($c)=>['id'=>$c['id'],'name'=>$c['display_name'],'ip'=>$c['ip_address'],'kind'=>$c['kind']], nm_ipam_dhcp_candidates($conn));
        echo json_encode(['ok'=>true,'servers'=>nm_ipam_dhcp_servers($conn,$sid),'leases'=>nm_ipam_leases($conn,$sid),'candidates'=>$cands]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}

log_user_action($conn,'view_page','ipam.php');
$nodes = [];
$nr = $conn->query("SELECT id,display_name,ip_address FROM nm_nodes ORDER BY display_name LIMIT 1000");
while ($nr && ($x=$nr->fetch_assoc())) $nodes[] = $x;
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IP Address Mgmt | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.18; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 40px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:8px 14px; font-size:13px; cursor:pointer; }
.btn:hover{ background:rgba(77,163,255,.25); } .btn.ghost{ background:transparent; border-color:var(--border); color:#aab; }
.btn.sm{ padding:3px 9px; font-size:11px; }
.subnets{ display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:14px; }
.sn{ padding:14px 16px; cursor:pointer; } .sn.active{ border-color:var(--accent); }
.sn .cidr{ font-size:16px; font-weight:800; } .sn .meta{ font-size:11px; color:#8a909a; margin:3px 0 10px; }
.bar{ height:16px; border-radius:8px; background:rgba(255,255,255,.07); overflow:hidden; border:1px solid rgba(255,255,255,.08); position:relative; }
.bar>i{ display:block; height:100%; }
.bar .lbl{ position:absolute; inset:0; display:flex; align-items:center; justify-content:center; font-size:10px; font-weight:700; }
table{ width:100%; border-collapse:collapse; font-size:12.5px; }
th{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; padding:7px 9px; border-bottom:1px solid var(--border); }
td{ padding:7px 9px; border-bottom:1px solid rgba(255,255,255,.05); }
.pill{ display:inline-block; font-size:10px; font-weight:700; padding:2px 8px; border-radius:20px; }
.s-node,.s-managed{ background:rgba(46,204,113,.14); color:#7fe0a3; } .s-wg{ background:rgba(77,163,255,.14); color:#bcd; }
.s-iface{ background:rgba(155,155,170,.14); color:#bcc; } .s-alloc,.s-reserved{ background:rgba(243,156,18,.14); color:#f0c674; }
.s-dhcp{ background:rgba(157,109,255,.16); color:#c9b0ff; } .s-discovered{ background:rgba(120,130,145,.18); color:#c2cad6; }
.s-conflict{ background:rgba(231,76,60,.16); color:#ff9c8f; }
.muted{ color:#7c828c; font-size:12px; } .mono{ font-family:monospace; }
/* ── Address Map ─────────────────────────────────────────────────────────── */
.chips{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px; }
.chip{ padding:5px 12px; border-radius:20px; font-size:12px; font-weight:700; border:1px solid var(--border); }
.legend{ display:flex; gap:14px; flex-wrap:wrap; margin:6px 0 14px; font-size:11px; color:#9aa3ad; }
.legend span{ display:inline-flex; align-items:center; gap:6px; }
.legend i{ width:12px; height:12px; border-radius:3px; display:inline-block; }
.ipgrid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(30px,1fr)); gap:4px; }
.ipc{ aspect-ratio:1; border-radius:5px; border:1px solid rgba(255,255,255,.08); cursor:pointer; display:flex; align-items:center; justify-content:center; font-size:9px; color:rgba(255,255,255,.55); transition:transform .08s, box-shadow .08s; position:relative; }
.ipc:hover{ transform:scale(1.18); z-index:5; box-shadow:0 0 0 2px var(--accent); color:#fff; }
.ipc.sel{ box-shadow:0 0 0 2px #fff; }
.c-free{ background:rgba(255,255,255,.04); } .c-managed{ background:rgba(46,204,113,.55); }
.c-wg{ background:rgba(77,163,255,.6); } .c-reserved{ background:rgba(243,156,18,.6); }
.c-dhcp{ background:rgba(157,109,255,.62); } .c-discovered{ background:rgba(150,160,175,.5); }
.c-conflict{ background:rgba(231,76,60,.75); } .c-gw{ background:rgba(46,204,113,.9); border-color:#7fffb0; }
.c-net,.c-bcast{ background:rgba(255,255,255,.02); color:rgba(255,255,255,.25); border-style:dashed; }
.cell-detail{ margin-top:14px; padding:14px 16px; display:none; }
.cell-detail.on{ display:block; }
.tabs{ display:flex; gap:8px; margin-bottom:16px; }
.tab{ background:rgba(255,255,255,.05); border:1px solid var(--border); color:#aab; padding:9px 18px; border-radius:10px; cursor:pointer; font-size:13px; font-weight:600; }
.tab.active{ background:rgba(77,163,255,.15); border-color:var(--accent); color:var(--accent); }
.tp{ display:none; } .tp.active{ display:block; }
.modal-bg{ position:fixed; inset:0; background:rgba(0,0,0,.6); z-index:90; display:none; align-items:flex-start; justify-content:center; padding-top:7vh; }
.modal{ width:440px; max-width:94vw; padding:20px 22px; } .modal h3{ margin:0 0 14px; }
.modal label{ display:block; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; margin:10px 0 4px; }
.modal input,.modal select{ width:100%; background:rgba(255,255,255,.06); color:#e6e9ee; border:1px solid var(--border); border-radius:8px; padding:9px 11px; font-size:13px; }
.row{ display:flex; gap:10px; } .row>div{ flex:1; }
.actions{ display:flex; gap:10px; justify-content:flex-end; margin-top:18px; align-items:center; }
/* dropdowns: native options were dark-on-dark — force readable, solid background */
select, .modal select{ background:#1b2129 !important; color:#e6e9ee; }
option{ background:#1b2129; color:#e6e9ee; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-sitemap"></i>IP Address Mgmt', '', 'Single Source of Truth', 'fa-solid fa-sitemap',
    '<button class="refresh-btn" onclick="loadAll()"><i class="fas fa-rotate"></i> Refresh</button>'); ?>

<div class="tabs">
  <div class="tab active" data-t="subnets" onclick="showTab('subnets')"><i class="fas fa-network-wired"></i> Subnets</div>
  <div class="tab" data-t="map" onclick="showTab('map');ensureMap()"><i class="fas fa-border-all"></i> Address Map</div>
  <div class="tab" data-t="dhcp" onclick="showTab('dhcp');loadDhcp()"><i class="fas fa-server"></i> DHCP</div>
  <div class="tab" data-t="alloc" onclick="showTab('alloc');loadAlloc()"><i class="fas fa-list-check"></i> Allocations</div>
  <div class="tab" data-t="conf" onclick="showTab('conf');loadConf()"><i class="fas fa-triangle-exclamation"></i> Conflicts</div>
</div>

<div id="tp-subnets" class="tp active">
  <div style="margin-bottom:14px;display:flex;gap:8px;flex-wrap:wrap;">
    <button class="btn" onclick="detectNodes(event)" title="Instant — reads nodes, WireGuard tunnels/peers and DHCP pools you already have"><i class="fas fa-wand-magic-sparkles"></i> Detect subnets</button>
    <button class="btn" onclick="fullSweep(event)" title="Pulls every interface's real IP+mask from your devices over SSH/SNMP — catches WireGuard/VPN/VLAN/container subnets with the ACTUAL mask"><i class="fas fa-satellite-dish"></i> Full sweep</button>
    <button class="btn ghost" onclick="openSubnet()"><i class="fas fa-plus"></i> Add subnet</button>
    <button class="btn ghost" onclick="importDisc(event)"><i class="fas fa-file-import"></i> Import discovery ranges</button>
    <span class="muted" id="imp-msg" style="align-self:center;"></span>
  </div>
  <div class="subnets" id="subnets"><div class="muted">Loading…</div></div>
  <div class="glass card" id="detail" style="display:none;margin-top:16px;">
    <h3 style="margin:0 0 4px;font-size:14px;" id="d-cidr"></h3>
    <div style="display:flex;gap:8px;margin:8px 0 12px;">
      <button class="btn sm" onclick="reservePrompt()"><i class="fas fa-plus"></i> Reserve IP</button>
      <span class="muted" id="d-next"></span>
    </div>
    <table><thead><tr><th>IP</th><th>Source</th><th>Label</th><th>Status</th><th></th></tr></thead>
    <tbody id="d-used"></tbody></table>
  </div>
</div>

<!-- ── ADDRESS MAP ─────────────────────────────────────────────────────────── -->
<div id="tp-map" class="tp">
  <div class="glass card">
    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px;">
      <select id="map-sel" onchange="loadMap(this.value)" style="min-width:220px;"></select>
      <button class="btn" id="sweep-btn" onclick="sweep()"><i class="fas fa-satellite-dish"></i> Sweep now</button>
      <span class="muted" id="sweep-msg"></span>
      <span style="flex:1"></span>
      <span class="muted" id="map-scanhint" style="font-size:11px;"></span>
    </div>
    <div id="map-body"><div class="muted">Pick a subnet to see its live address map.</div></div>
  </div>
</div>

<!-- ── DHCP ────────────────────────────────────────────────────────────────── -->
<div id="tp-dhcp" class="tp">
  <div class="glass card">
    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:8px;">
      <button class="btn" id="dhcp-btn" onclick="dhcpPull('')"><i class="fas fa-download"></i> Pull DHCP from routers</button>
      <select id="dhcp-node" style="min-width:200px;"><option value="">— all detected DHCP-capable devices —</option></select>
      <span class="muted" id="dhcp-msg"></span>
    </div>
    <div class="muted" style="margin-bottom:12px;font-size:11.5px;">Reads DHCP pools + leases over SSH from your managed routers (MikroTik / Cisco / Linux). Leases mark which addresses the DHCP server has actually handed out (IP&nbsp;↔&nbsp;MAC&nbsp;↔&nbsp;hostname) so they show as occupied on the Address Map.</div>
    <h3 style="font-size:13px;color:var(--accent);margin:6px 0;">Served pools</h3>
    <div id="dhcp-servers" class="muted">Loading…</div>
    <h3 style="font-size:13px;color:var(--accent);margin:18px 0 6px;">Active leases</h3>
    <div id="dhcp-leases" class="muted"></div>
  </div>
</div>

<div id="tp-alloc" class="tp"><div class="glass card">
  <table><thead><tr><th>IP</th><th>Subnet</th><th>Source</th><th>Status</th><th>Host/Label</th><th>Created</th><th></th></tr></thead>
  <tbody id="alloc-body"><tr><td colspan="7" class="muted">Loading…</td></tr></tbody></table>
</div></div>

<div id="tp-conf" class="tp"><div class="glass card">
  <div class="muted" style="margin-bottom:10px;">IPs claimed by more than one source — overlaps between polled nodes, WireGuard peers, and reservations.</div>
  <div id="conf-body" class="muted">Loading…</div>
</div></div>
</div>

<!-- subnet modal -->
<div class="modal-bg" id="snbg"><div class="glass modal">
  <h3>Add subnet</h3>
  <label>CIDR (e.g. 10.8.0.0/24)</label><input id="sn-cidr" placeholder="10.8.0.0/24">
  <div class="row">
    <div><label>Kind</label><select id="sn-kind"><option value="lan">LAN</option><option value="wireguard">WireGuard</option><option value="mgmt">Mgmt</option><option value="dmz">DMZ</option></select></div>
    <div><label>VLAN (optional)</label><input id="sn-vlan" type="number"></div>
  </div>
  <label>Gateway IP (optional)</label><input id="sn-gw" placeholder="10.8.0.1">
  <label>Description</label><input id="sn-desc">
  <div class="actions"><span class="muted" id="sn-msg" style="margin-right:auto;"></span>
    <button class="btn ghost" onclick="closeM('snbg')">Cancel</button><button class="btn" onclick="saveSubnet()">Save</button></div>
</div></div>

<script>
let SUBS=[], SEL=0;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function showTab(t){ document.querySelectorAll('.tp').forEach(p=>p.classList.remove('active')); document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));
  document.getElementById('tp-'+t).classList.add('active'); document.querySelector('.tab[data-t="'+t+'"]').classList.add('active'); }
function closeM(id){ document.getElementById(id).style.display='none'; }
function barColor(p){ return p>=90?'var(--crit)':p>=70?'var(--warn)':'var(--ok)'; }

async function loadAll(){
  const r=await fetch('ipam.php?api=subnets').then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok)return; SUBS=r.subnets;
  document.getElementById('subnets').innerHTML = SUBS.length? SUBS.map(s=>{
    const u=s.util; return `<div class="glass sn ${s.id==SEL?'active':''}" onclick="selSub(${s.id})">
      <div class="cidr">${esc(s.cidr)} <span class="pill s-${s.kind=='wireguard'?'wg':'node'}" style="font-size:9px;">${esc(s.kind)}</span></div>
      <div class="meta">${s.gateway_name?'<i class="fas fa-server" style="opacity:.7"></i> '+esc(s.gateway_name)+' ':''}${esc(s.description||'')}${s.vlan_id?' · VLAN '+s.vlan_id:''}${s.gateway_ip?' · gw '+esc(s.gateway_ip):''}</div>
      <div class="bar"><i style="width:${u.pct}%;background:${barColor(u.pct)};"></i><div class="lbl">${u.used}/${u.total} used · ${u.pct}%</div></div>
    </div>`; }).join('') : '<div class="muted">No subnets. Add one or import your discovery ranges.</div>';
  if(document.getElementById('map-sel')) fillMapSel();
}
async function selSub(id){ SEL=id; loadAll();
  const r=await fetch('ipam.php?api=used&id='+id).then(r=>r.json()).catch(()=>null);
  const s=SUBS.find(x=>x.id==id); if(!s)return;
  document.getElementById('detail').style.display='block';
  document.getElementById('d-cidr').textContent=s.cidr+' — allocations & live usage';
  document.getElementById('d-next').innerHTML = r&&r.next? 'Next free: <b class="mono" style="color:var(--ok)">'+esc(r.next)+'</b>' : '<span style="color:var(--crit)">subnet full</span>';
  document.getElementById('d-used').innerHTML = (r&&r.used&&r.used.length)? r.used.map(u=>`<tr>
    <td class="mono">${esc(u.ip)}</td><td><span class="pill s-${esc(u.source)}">${esc(u.source)}</span></td>
    <td>${esc(u.label||'')}</td><td>${esc(u.status||'')}</td>
    <td>${u.source=='alloc'?`<button class="btn ghost sm" onclick="release(${u.ref_id})">release</button>`:''}</td></tr>`).join('')
    : '<tr><td colspan="5" class="muted">No used addresses in this subnet.</td></tr>';
}
function openSubnet(){ ['sn-cidr','sn-vlan','sn-gw','sn-desc'].forEach(i=>document.getElementById(i).value=''); document.getElementById('sn-msg').textContent=''; document.getElementById('snbg').style.display='flex'; }
async function saveSubnet(){
  const body=new URLSearchParams({action:'subnet_add',cidr:gv('sn-cidr'),kind:gv('sn-kind'),vlan_id:gv('sn-vlan'),gateway_ip:gv('sn-gw'),description:gv('sn-desc')});
  const r=await post(body); if(r&&r.ok){ closeM('snbg'); loadAll(); } else document.getElementById('sn-msg').innerHTML='<span style="color:var(--crit)">'+(r?esc(r.error):'failed')+'</span>';
}
async function reservePrompt(){
  const ip=prompt('IP to reserve (blank = next free):',''); if(ip===null)return;
  const r=await post(new URLSearchParams({action:'reserve',subnet_id:SEL,ip:ip,hostname:prompt('Hostname/label (optional):','')||''}));
  if(r&&r.ok) selSub(SEL); else alert(r?r.error:'failed');
}
async function release(id){ if(!confirm('Release this allocation?'))return; await post(new URLSearchParams({action:'release',id:id})); selSub(SEL); loadAlloc(); }
function bySrc(o){ const b=o&&o.by_source||{}; const k=Object.keys(b); return k.length? ' ('+k.map(s=>b[s]+' '+s).join(', ')+')' : ''; }
async function detectNodes(ev){
  const btn=ev&&ev.target?ev.target.closest('button'):null; if(btn) btn.disabled=true;
  const m=document.getElementById('imp-msg'); m.innerHTML='<i class="fas fa-spinner fa-spin"></i> reading nodes, WireGuard &amp; DHCP…';
  const r=await post(new URLSearchParams({action:'detect'}));
  m.innerHTML = r&&r.ok ? ('<span style="color:var(--ok)">+ '+r.added+' new subnet(s)'+esc(bySrc(r))+'</span>') : ('<span style="color:var(--crit)">detect failed</span>');
  if(btn) btn.disabled=false; loadAll();
}
async function fullSweep(ev){
  const btn=ev&&ev.target?ev.target.closest('button'):null; if(btn) btn.disabled=true;
  const m=document.getElementById('imp-msg'); m.innerHTML='<i class="fas fa-spinner fa-spin"></i> sweeping every device interface over SSH/SNMP… (can take a minute)';
  const r=await post(new URLSearchParams({action:'iface_sweep'}));
  m.innerHTML = r&&r.ok ? ('<span style="color:var(--ok)">swept '+r.scanned+' device(s) · + '+r.added+' new subnet(s)'+esc(bySrc(r))+'</span>') : ('<span style="color:var(--crit)">sweep failed</span>');
  if(btn) btn.disabled=false; loadAll();
}
async function importDisc(ev){
  const btn=ev&&ev.target?ev.target.closest('button'):null; if(btn){btn.disabled=true;}
  const m=document.getElementById('imp-msg'); m.textContent='Importing…';
  const r=await post(new URLSearchParams({action:'import'}));
  m.textContent = r&&r.ok ? ('Imported '+r.imported+' subnet(s)') : ('Import failed'+(r&&r.error_id?' ('+r.error_id+')':''));
  if(btn) btn.disabled=false;
  loadAll();
}
async function loadAlloc(){
  const r=await fetch('ipam.php?api=allocations').then(r=>r.json()).catch(()=>null);
  document.getElementById('alloc-body').innerHTML = (r&&r.allocations&&r.allocations.length)? r.allocations.map(a=>`<tr>
    <td class="mono">${esc(a.ip_address)}</td><td class="mono">${esc(a.cidr)}</td><td><span class="pill s-${a.source=='wireguard'?'wg':'alloc'}">${esc(a.source)}</span></td>
    <td>${esc(a.status)}</td><td>${esc(a.hostname||'')}</td><td class="muted">${esc(a.created_at||'')}</td>
    <td><button class="btn ghost sm" onclick="release(${a.id})">release</button></td></tr>`).join('')
    : '<tr><td colspan="7" class="muted">No active allocations.</td></tr>';
}
async function loadConf(){
  const r=await fetch('ipam.php?api=conflicts').then(r=>r.json()).catch(()=>null);
  const c=r&&r.conflicts||[];
  document.getElementById('conf-body').innerHTML = c.length? '<table><thead><tr><th>Subnet</th><th>IP</th><th>Claimed by</th></tr></thead><tbody>'+
    c.map(x=>`<tr><td class="mono">${esc(x.subnet)}</td><td class="mono" style="color:var(--crit)">${esc(x.ip)}</td>
      <td>${x.claims.map(cl=>`<span class="pill s-${cl.source=='wireguard'||cl.source=='wg'?'wg':(cl.source=='node'?'node':'alloc')}">${esc(cl.source)}: ${esc(cl.label||cl.ref_id)}</span>`).join(' ')}</td></tr>`).join('')+
    '</tbody></table>' : '<div style="color:var(--ok)"><i class="fas fa-circle-check"></i> No IP conflicts detected.</div>';
}
// ── Address Map ──────────────────────────────────────────────────────────────
let MAPSEL=0, MAP=null, SWEEPING=false, CELLS=[];
const CATLABEL={managed:'Managed node',wg:'WireGuard',reserved:'Reserved',dhcp:'DHCP lease',discovered:'Discovered (unmanaged)',conflict:'Conflict',free:'Free',gw:'Gateway',net:'Network',bcast:'Broadcast'};
function fillMapSel(){
  const sel=document.getElementById('map-sel');
  sel.innerHTML = SUBS.map(s=>`<option value="${s.id}" ${s.id==MAPSEL?'selected':''}>${esc(s.cidr)}${s.description?' — '+esc(s.description):''}</option>`).join('')
    || '<option value="">No subnets</option>';
}
async function ensureMap(){ if(!SUBS.length) await loadAll(); fillMapSel();
  if(!MAPSEL && SUBS.length) MAPSEL=SUBS[0].id;
  if(MAPSEL) loadMap(MAPSEL); }
async function loadMap(id){ MAPSEL=+id||MAPSEL; if(!MAPSEL)return;
  document.getElementById('map-body').innerHTML='<div class="muted">Loading map…</div>';
  const r=await fetch('ipam.php?api=map&id='+MAPSEL).then(r=>r.json()).catch(()=>null);
  MAP=r; renderMap(r); refreshScanHint();
}
function statChip(n,label,cls){ return `<span class="chip s-${cls}">${n} ${label}</span>`; }
function renderMap(r){
  const b=document.getElementById('map-body');
  if(!r||!r.ok){ b.innerHTML='<div class="muted">'+(r&&r.error||'Map unavailable (IPv6 or error).')+'</div>'; return; }
  const s=r.stats, freePct=s.total?Math.round((s.total-s.managed-s.wg-s.reserved-s.dhcp-s.discovered-s.conflict)*100/s.total):0;
  let html = '<div class="chips">'
    + statChip(s.managed,'managed','managed') + statChip(s.dhcp,'DHCP','dhcp')
    + statChip(s.discovered,'in the air','discovered') + statChip(s.reserved,'reserved','reserved')
    + statChip(s.wg,'wireguard','wg') + (s.conflict?statChip(s.conflict,'conflict','conflict'):'')
    + `<span class="chip" style="background:rgba(255,255,255,.05);color:#cfe">${s.free} free / ${s.total} usable</span>`
    + '</div>';
  html += '<div class="legend">'
    + '<span><i class="c-managed"></i>Managed</span><span><i class="c-dhcp"></i>DHCP lease</span>'
    + '<span><i class="c-discovered"></i>In the air</span><span><i class="c-reserved"></i>Reserved</span>'
    + '<span><i class="c-wg"></i>WireGuard</span><span><i class="c-gw"></i>Gateway</span>'
    + '<span><i class="c-conflict"></i>Conflict</span><span><i class="c-free"></i>Free</span></div>';
  CELLS = r.cells;
  if(r.grid){
    html += '<div class="ipgrid" id="ipgrid">'+ r.cells.map((c,i)=>{
      const last=c.ip.split('.').pop();
      const tip=esc(c.ip)+' · '+(CATLABEL[c.cat]||c.cat)+(c.host?' · '+esc(c.host):'')+(c.label?' · '+esc(c.label):'');
      return `<div class="ipc c-${c.cat}" title="${tip}" data-ip="${esc(c.ip)}" data-cat="${c.cat}" onclick="selCellIdx(${i})">${last}</div>`;
    }).join('') + '</div>';
  } else {
    html += `<div class="muted" style="margin-bottom:8px;">Subnet too large to draw the full grid (${r.span} addresses > ${r.cap}). Showing occupied addresses only.</div>`;
    html += '<table><thead><tr><th>IP</th><th>Type</th><th>Host / label</th><th>MAC</th><th></th></tr></thead><tbody>'
      + r.cells.map((c,i)=>`<tr><td class="mono">${esc(c.ip)}</td><td><span class="pill s-${c.cat}">${CATLABEL[c.cat]||c.cat}</span></td>
        <td>${esc(c.host||c.label||'')}</td><td class="mono">${esc(c.mac||'')}</td>
        <td><button class="btn ghost sm" onclick="selCellIdx(${i})">details</button></td></tr>`).join('')
      + '</tbody></table>';
  }
  html += '<div class="glass cell-detail" id="cell-detail"></div>';
  b.innerHTML=html;
}
function selCellIdx(i){ if(CELLS[i]) selCell(CELLS[i]); }
function selCell(c){
  document.querySelectorAll('.ipc.sel').forEach(e=>e.classList.remove('sel'));
  const el=document.querySelector('.ipc[data-ip="'+c.ip+'"]'); if(el) el.classList.add('sel');
  const d=document.getElementById('cell-detail'); d.classList.add('on');
  const canReserve=(c.cat==='free'||c.cat==='discovered'), node=NODEBYIP[c.ip];
  d.innerHTML = `<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
      <b class="mono" style="font-size:16px;">${esc(c.ip)}</b>
      <span class="pill s-${c.cat}">${CATLABEL[c.cat]||c.cat}</span>
      ${c.host?'<span class="muted">host: '+esc(c.host)+'</span>':''}
      ${c.mac?'<span class="muted mono">'+esc(c.mac)+'</span>':''}
      ${c.seen?'<span class="muted">seen '+esc(String(c.seen).slice(0,16))+'</span>':''}
    </div>
    <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap;">
      <button class="btn sm" onclick="pingCell('${esc(c.ip)}')"><i class="fas fa-satellite-dish"></i> Ping now</button>
      ${canReserve?`<button class="btn sm" onclick="reserveIp('${esc(c.ip)}')"><i class="fas fa-lock"></i> Reserve</button>`:''}
      ${node?`<a class="btn ghost sm" href="router_details.php?node=${node.id}"><i class="fas fa-arrow-up-right-from-square"></i> Open ${esc(node.display_name)}</a>`:''}
      <span id="ping-res" class="muted" style="align-self:center;"></span>
    </div>`;
}
async function pingCell(ip){
  const el=document.getElementById('ping-res'); if(el) el.textContent='pinging…';
  const r=await post(new URLSearchParams({action:'ping',ip})); if(!el)return;
  el.innerHTML = r&&r.alive ? `<span style="color:var(--ok)"><i class="fas fa-check"></i> alive${r.rtt!=null?' · '+r.rtt+' ms':''}</span>`
                            : '<span style="color:var(--crit)"><i class="fas fa-xmark"></i> no reply</span>';
}
async function reserveIp(ip){
  const label=prompt('Reserve '+ip+' — hostname/label (optional):',''); if(label===null)return;
  const r=await post(new URLSearchParams({action:'reserve',subnet_id:MAPSEL,ip,hostname:label||''}));
  if(r&&r.ok){ loadMap(MAPSEL); } else alert(r?r.error:'failed');
}
async function sweep(){
  if(SWEEPING||!MAPSEL)return; SWEEPING=true;
  const btn=document.getElementById('sweep-btn'), m=document.getElementById('sweep-msg');
  btn.disabled=true; m.innerHTML='<i class="fas fa-spinner fa-spin"></i> sweeping subnet…';
  await post(new URLSearchParams({action:'sweep',subnet_id:MAPSEL}));
  pollSweep(MAPSEL,0);
}
async function pollSweep(id,tries){
  const m=document.getElementById('sweep-msg');
  const r=await fetch('ipam.php?api=live_status&id='+id).then(r=>r.json()).catch(()=>null);
  const st=r&&r.status||'';
  if(st.startsWith('done')||st.startsWith('skipped')||tries>60){
    SWEEPING=false; document.getElementById('sweep-btn').disabled=false;
    const parts=st.split(':'); const alive=st.startsWith('done')?parts[1]:'?';
    m.innerHTML = st.startsWith('skipped')?'<span style="color:var(--warn)">subnet too large to sweep</span>'
                 :`<span style="color:var(--ok)"><i class="fas fa-check"></i> ${alive} live host(s)</span>`;
    if(id==MAPSEL) loadMap(id);
    return;
  }
  setTimeout(()=>pollSweep(id,tries+1),2000);
}
async function refreshScanHint(){
  if(!MAPSEL)return;
  const r=await fetch('ipam.php?api=live_status&id='+MAPSEL).then(r=>r.json()).catch(()=>null);
  const h=document.getElementById('map-scanhint'); if(!h||!r)return;
  const st=r.status||''; const when=st.split(':').slice(-2).join(':');
  h.textContent = r.live? (r.live+' hosts last seen'+(st.startsWith('done')?' · swept '+when.slice(0,16):'')) : 'never swept — run Sweep now';
}
// ── DHCP ─────────────────────────────────────────────────────────────────────
async function loadDhcp(){
  const r=await fetch('ipam.php?api=dhcp').then(r=>r.json()).catch(()=>null);
  const sv=document.getElementById('dhcp-servers'), lz=document.getElementById('dhcp-leases'), nsel=document.getElementById('dhcp-node');
  if(!r||!r.ok){ sv.textContent='Load failed'; return; }
  nsel.innerHTML='<option value="">— all detected DHCP-capable devices —</option>'+
    (r.candidates||[]).map(c=>`<option value="${c.id}">${esc(c.name)} (${esc(c.ip)}) · ${esc(c.kind)}</option>`).join('');
  sv.innerHTML = (r.servers&&r.servers.length)? '<table><thead><tr><th>Pool</th><th>Range</th><th>Gateway</th><th>DNS</th><th>Lease</th><th>Server</th><th>Seen</th></tr></thead><tbody>'+
    r.servers.map(s=>`<tr><td>${esc(s.pool_name||'')}</td><td class="mono">${esc(s.range_start||'')}${s.range_end?' – '+esc(s.range_end):''}</td>
      <td class="mono">${esc(s.gateway||'')}</td><td class="mono">${esc(s.dns||'')}</td><td>${esc(s.lease_time||'')}</td>
      <td class="mono">${esc(s.node_name||s.server_ip||'')}</td><td class="muted">${esc(String(s.last_seen||'').slice(0,16))}</td></tr>`).join('')+'</tbody></table>'
    : '<div class="muted">No DHCP servers pulled yet. Click “Pull DHCP from routers”.</div>';
  // Group leases BY router/server so each DHCP server is its own clear section
  // (otherwise a router with few leases gets buried under a busier one).
  const nameByIp={}; (r.servers||[]).forEach(s=>{ if(s.server_ip) nameByIp[s.server_ip]=s.node_name||s.server_ip; });
  (r.candidates||[]).forEach(c=>{ if(c.ip&&!nameByIp[c.ip]) nameByIp[c.ip]=c.name; });
  if(!r.leases||!r.leases.length){ lz.innerHTML='<div class="muted">No leases yet. Click “Pull DHCP from routers”.</div>'; return; }
  const groups={}; r.leases.forEach(l=>{ const k=l.server_ip||'?'; (groups[k]=groups[k]||[]).push(l); });
  lz.innerHTML = Object.keys(groups).sort().map(srv=>{
    const rows=groups[srv];
    return `<div style="margin-bottom:16px;">
      <div style="display:flex;align-items:center;gap:8px;margin:4px 0 6px;font-size:12.5px;font-weight:700;color:#cfe4ff;">
        <i class="fas fa-server" style="color:var(--accent)"></i> ${esc(nameByIp[srv]||srv)}
        <span class="mono muted" style="font-weight:400;">${esc(srv)}</span>
        <span class="pill s-dhcp">${rows.length} lease${rows.length!=1?'s':''}</span>
      </div>
      <table><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>State</th><th>Type</th></tr></thead><tbody>`+
      rows.map(l=>`<tr><td class="mono">${esc(l.ip_address)}</td><td class="mono">${esc(l.mac||'')}</td><td>${esc(l.hostname||'')}</td>
        <td>${esc(l.state||'')}</td><td>${l.is_static==1?'<span class="pill s-reserved">static</span>':'<span class="pill s-dhcp">dynamic</span>'}</td></tr>`).join('')+
      '</tbody></table></div>';
  }).join('');
}
async function dhcpPull(nodeId){
  const btn=document.getElementById('dhcp-btn'), m=document.getElementById('dhcp-msg');
  const node=document.getElementById('dhcp-node').value;
  btn.disabled=true; m.innerHTML='<i class="fas fa-spinner fa-spin"></i> pulling over SSH…';
  const r=await post(new URLSearchParams({action:'dhcp_pull',node_id:node}));
  btn.disabled=false;
  if(r&&r.ok){
    let msg=`<span style="color:var(--ok)"><i class="fas fa-check"></i> ${r.servers||0} pool(s), ${r.leases||0} lease(s)`;
    if(r.devices!=null) msg+=` from ${r.devices} router(s)`;
    msg+='</span>';
    const extra=[];
    if(r.no_dhcp) extra.push(r.no_dhcp+' w/o DHCP');
    if(r.unreachable&&r.unreachable.length) extra.push(r.unreachable.length+' unreachable: '+r.unreachable.join(', '));
    if(extra.length) msg+=' <span class="muted">('+extra.join(' · ')+')</span>';
    m.innerHTML=msg; loadDhcp();
  }
  else m.innerHTML='<span style="color:var(--crit)">'+(r?esc(r.error||'failed'):'failed')+'</span>';
}

function gv(id){ return document.getElementById(id).value; }
async function post(body){ return fetch('ipam.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body}).then(r=>r.json()).catch(()=>null); }
let NODEBYIP={};
<?php foreach($nodes as $n){ if(!empty($n['ip_address'])) echo "NODEBYIP[".json_encode($n['ip_address'])."]=".json_encode(['id'=>(int)$n['id'],'display_name'=>$n['display_name']]).";\n"; } ?>
loadAll();
</script>
</body></html>
