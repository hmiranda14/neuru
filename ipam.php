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

// ── write actions ─────────────────────────────────────────────────────────────
if ($act !== '') {
    header('Content-Type: application/json; charset=utf-8');
    if ($act === 'subnet_add')    { echo json_encode(nm_ipam_subnet_add($conn, $_POST, $uid)); log_user_action($conn,'ipam_subnet_add',$_POST['cidr']??''); exit; }
    if ($act === 'subnet_update') { echo json_encode(nm_ipam_subnet_update($conn, (int)($_POST['id']??0), $_POST)); exit; }
    if ($act === 'subnet_delete') { echo json_encode(nm_ipam_subnet_delete($conn, (int)($_POST['id']??0))); exit; }
    if ($act === 'reserve')       { echo json_encode(nm_ipam_reserve($conn, (int)($_POST['subnet_id']??0), trim((string)($_POST['ip']??'')) ?: null, $_POST, $uid)); exit; }
    if ($act === 'release')       { echo json_encode(nm_ipam_release($conn, (int)($_POST['id']??0))); exit; }
    if ($act === 'import')        { echo json_encode(['ok'=>true,'imported'=>nm_ipam_import_discovery($conn,$uid)]); exit; }
    if ($act === 'detect')        { echo json_encode(['ok'=>true,'imported'=>nm_ipam_detect_from_nodes($conn,$uid)]); log_user_action($conn,'ipam_detect_nodes',''); exit; }
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
.s-node{ background:rgba(46,204,113,.14); color:#7fe0a3; } .s-wg{ background:rgba(77,163,255,.14); color:#bcd; }
.s-iface{ background:rgba(155,155,170,.14); color:#bcc; } .s-alloc{ background:rgba(243,156,18,.14); color:#f0c674; }
.muted{ color:#7c828c; font-size:12px; } .mono{ font-family:monospace; }
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
  <div class="tab" data-t="alloc" onclick="showTab('alloc');loadAlloc()"><i class="fas fa-list-check"></i> Allocations</div>
  <div class="tab" data-t="conf" onclick="showTab('conf');loadConf()"><i class="fas fa-triangle-exclamation"></i> Conflicts</div>
</div>

<div id="tp-subnets" class="tp active">
  <div style="margin-bottom:14px;display:flex;gap:8px;">
    <button class="btn" onclick="detectNodes(event)"><i class="fas fa-wand-magic-sparkles"></i> Detect from nodes</button>
    <button class="btn ghost" onclick="openSubnet()"><i class="fas fa-plus"></i> Add subnet</button>
    <button class="btn ghost" onclick="importDisc(event)"><i class="fas fa-file-import"></i> Import discovery subnets</button>
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
      <div class="meta">${esc(s.description||'')}${s.vlan_id?' · VLAN '+s.vlan_id:''}${s.gateway_ip?' · gw '+esc(s.gateway_ip):''}</div>
      <div class="bar"><i style="width:${u.pct}%;background:${barColor(u.pct)};"></i><div class="lbl">${u.used}/${u.total} used · ${u.pct}%</div></div>
    </div>`; }).join('') : '<div class="muted">No subnets. Add one or import your discovery ranges.</div>';
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
async function detectNodes(ev){
  const btn=ev&&ev.target?ev.target.closest('button'):null; if(btn) btn.disabled=true;
  const m=document.getElementById('imp-msg'); m.textContent='Scanning node IPs…';
  const r=await post(new URLSearchParams({action:'detect'}));
  m.textContent = r&&r.ok ? ('Detected '+r.imported+' subnet(s) from node IPs') : ('Detect failed'+(r&&r.error_id?' ('+r.error_id+')':''));
  if(btn) btn.disabled=false;
  loadAll();
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
function gv(id){ return document.getElementById(id).value; }
async function post(body){ return fetch('ipam.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body}).then(r=>r.json()).catch(()=>null); }
loadAll();
</script>
</body></html>
