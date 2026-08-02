<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — NS Lookup (Net Tools). Resolves DNS records (A/AAAA/MX/NS/TXT/CNAME/
// SOA/PTR/ANY) for a host or IP, shell-free via PHP's resolver. RBAC:
// 'nettools_lookup'. Engine: nm_nettools.php (nm_nt_nslookup).
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_nettools.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'nettools_lookup')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=nettools_lookup'); exit;
}
nm_nt_ensure($conn);
$EMBED = (($_GET['embed'] ?? '') === '1');   // Commander overlay → strip chrome + autostart from ?target

if ($api === 'lookup') {
    header('Content-Type: application/json; charset=utf-8');
    $target = $_GET['target'] ?? '';
    $type   = $_GET['type'] ?? 'A';
    log_user_action($conn, 'nettools_lookup', $target.' '.$type);
    echo json_encode(nm_nt_nslookup($conn, $target, $type));
    exit;
}

log_user_action($conn,'view_page','netlookup.php');
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NS Lookup | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; }
*,*::before,*::after{ box-sizing:border-box; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
.wrap{ max-width:1100px; margin:0 auto; padding:18px 20px 40px; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.bar{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:16px; }
input.t{ background:#1b2129; color:#e6e9ee; border:1px solid var(--border); border-radius:9px; padding:10px 14px; font-size:14px; min-width:280px; font-family:monospace; }
select.t{ background:#1b2129; color:#e6e9ee; border:1px solid var(--border); border-radius:9px; padding:10px 12px; font-size:14px; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:10px 16px; font-size:13px; cursor:pointer; }
.btn:hover{ background:rgba(77,163,255,.25); }
table{ width:100%; border-collapse:collapse; font-size:13px; }
th{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; padding:8px; border-bottom:1px solid var(--border); }
td{ padding:8px; border-bottom:1px solid rgba(255,255,255,.05); vertical-align:top; }
.mono{ font-family:monospace; } .muted{ color:#7c828c; font-size:12px; }
.rt{ display:inline-block; min-width:48px; text-align:center; font-size:11px; font-weight:700; padding:2px 8px; border-radius:12px; background:rgba(77,163,255,.16); color:#bcd; }
<?= nm_chrome_css() ?>
body.embed{ background:transparent !important; padding-top:0 !important; } body.embed #nm-topbar,body.embed #bg-video,body.embed video{ display:none !important; } body.embed .wrap{ padding:8px 12px 12px !important; max-width:none !important; }
</style></head><body class="<?= $EMBED?'embed':'' ?>">
<?php include('header.php'); ?>
<div class="wrap">
<?php if(!$EMBED) nm_page_header('<i class="fas fa-magnifying-glass-location"></i>NS Lookup', '', 'Net Tools · DNS resolver', 'fa-solid fa-magnifying-glass-location',''); ?>

<div class="bar">
  <input class="t" id="target" placeholder="host or IP (e.g. cloudflare.com / 1.1.1.1)" value="cloudflare.com" onkeydown="if(event.key==='Enter')lookup()">
  <select class="t" id="rtype">
    <option>A</option><option>AAAA</option><option>MX</option><option>NS</option>
    <option>TXT</option><option>CNAME</option><option>SOA</option><option>PTR</option><option>ANY</option>
  </select>
  <button class="btn" id="go" onclick="lookup()"><i class="fas fa-play"></i> Lookup</button>
  <span class="muted" id="status">Resolves DNS records. IP input does a reverse (PTR) lookup.</span>
</div>

<div class="glass card"><table><thead><tr><th style="width:90px;">Type</th><th>Value</th><th style="width:90px;">TTL</th></tr></thead>
  <tbody id="rows"><tr><td colspan="3" class="muted">Run a lookup to see records.</td></tr></tbody></table></div>
</div>
<script>
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
async function lookup(){
  const t=document.getElementById('target').value.trim(); if(!t)return;
  const ty=document.getElementById('rtype').value;
  const st=document.getElementById('status'); st.innerHTML='<i class="fas fa-spinner fa-spin"></i> Resolving '+esc(t)+'…';
  document.getElementById('go').disabled=true;
  document.getElementById('rows').innerHTML='<tr><td colspan="3" class="muted">Resolving…</td></tr>';
  const r=await fetch('netlookup.php?api=lookup&target='+encodeURIComponent(t)+'&type='+encodeURIComponent(ty)).then(r=>r.json()).catch(()=>null);
  document.getElementById('go').disabled=false;
  if(!r||!r.ok){ st.innerHTML='<span style="color:var(--crit)">✗ '+(r?esc(r.error):'lookup failed')+'</span>'; document.getElementById('rows').innerHTML='<tr><td colspan="3" class="muted">No records.</td></tr>'; return; }
  const recs=r.records||[];
  st.innerHTML = recs.length? '<span style="color:var(--ok)">✓ '+recs.length+' record'+(recs.length>1?'s':'')+' for '+esc(r.target)+' ('+esc(r.type)+')</span>'
                            : '<span style="color:var(--warn)">No '+esc(r.type)+' records for '+esc(r.target)+'</span>';
  document.getElementById('rows').innerHTML = recs.length? recs.map(x=>
    `<tr><td><span class="rt">${esc(x.type)}</span></td><td class="mono" style="word-break:break-all;">${esc(x.value)}</td><td class="muted">${x.ttl!=null?esc(x.ttl):'—'}</td></tr>`
  ).join('') : '<tr><td colspan="3" class="muted">No records.</td></tr>';
}
</script>
<script>window.addEventListener("DOMContentLoaded",function(){var q=new URLSearchParams(location.search),tg=q.get("target");if(tg){var i=document.getElementById("target");if(i){i.value=tg;}if(q.get("autostart")==="1"){var f=window.trace||window.start||window.lookup||window.run;if(f)setTimeout(f,350);}}});</script>
</body></html>
