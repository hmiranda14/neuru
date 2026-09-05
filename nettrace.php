<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Traceroute + GeoIP world map (Net Tools). Traces the path to a target
// (via ping TTL-stepping — no traceroute binary) and plots each geolocated hop on
// a world map with inter-hop latency. RBAC: 'nettools_trace'. Engine: nm_nettools.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once __DIR__.'/nm_maptiles.php';   // shared keyless basemap (CARTO now needs a key)
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_nettools.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'nettools_trace')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=nettools_trace'); exit;
}
nm_nt_ensure($conn);
$EMBED = (($_GET['embed'] ?? '') === '1');   // Commander overlay → strip chrome + autostart from ?target

if ($api === 'trace') {
    header('Content-Type: application/json; charset=utf-8');
    $target = nm_nt_valid_target($_GET['target'] ?? '');
    if (!$target) { echo json_encode(['ok'=>false,'error'=>'Invalid target (IP or hostname only)']); exit; }
    @set_time_limit(120);
    log_user_action($conn, 'nettools_trace', $target);
    $maxhops = max(5, min(30, (int)($_GET['maxhops'] ?? 30)));
    echo json_encode(['ok'=>true] + nm_nt_traceroute($conn, $target, $maxhops));
    exit;
}

log_user_action($conn,'view_page','nettrace.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Traceroute Map | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<script src="/leaflet.min.js"></script>
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; }
*,*::before,*::after{ box-sizing:border-box; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.15; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 40px; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.bar{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:16px; }
input.t{ background:#1b2129; color:#e6e9ee; border:1px solid var(--border); border-radius:9px; padding:10px 14px; font-size:14px; min-width:280px; font-family:monospace; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:10px 16px; font-size:13px; cursor:pointer; }
.btn:hover{ background:rgba(77,163,255,.25); }
.cols{ display:grid; grid-template-columns:1fr 1.3fr; gap:16px; } @media(max-width:980px){ .cols{ grid-template-columns:1fr; } }
#map{ height:520px; border-radius:14px; } .leaflet-container{ background:#0a0f1a; }
table{ width:100%; border-collapse:collapse; font-size:12.5px; }
th{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.5px; color:#8a909a; padding:7px 8px; border-bottom:1px solid var(--border); }
td{ padding:7px 8px; border-bottom:1px solid rgba(255,255,255,.05); } tr.fin td{ background:rgba(46,204,113,.06); }
.mono{ font-family:monospace; } .muted{ color:#7c828c; font-size:12px; } .pin{ color:#4da3ff; font-weight:700; }
.hopnum{ display:inline-flex;width:20px;height:20px;border-radius:50%;background:rgba(77,163,255,.2);align-items:center;justify-content:center;font-size:10px;font-weight:700; }
<?= nm_chrome_css() ?>
body.embed{ background:transparent !important; padding-top:0 !important; } body.embed #nm-topbar,body.embed #bg-video,body.embed video{ display:none !important; } body.embed .wrap{ padding:8px 12px 12px !important; max-width:none !important; }
</style></head><body class="<?= $EMBED?'embed':'' ?>">
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php if(!$EMBED) nm_page_header('<i class="fas fa-route"></i>Traceroute Map', '', 'Net Tools · GeoIP path', 'fa-solid fa-route',''); ?>

<div class="bar">
  <input class="t" id="target" placeholder="host or IP (e.g. 1.1.1.1)" value="1.1.1.1" onkeydown="if(event.key==='Enter')trace()">
  <button class="btn" id="go" onclick="trace()"><i class="fas fa-play"></i> Trace</button>
  <span class="muted" id="status">Traces the path hop-by-hop and maps each public hop. May take ~15–30s.</span>
</div>

<div class="cols">
  <div class="glass card"><table><thead><tr><th>#</th><th>IP</th><th>RTT</th><th>Location</th><th>ASN</th></tr></thead>
    <tbody id="hops"><tr><td colspan="5" class="muted">Run a trace to see the path.</td></tr></tbody></table></div>
  <div class="glass card" style="padding:8px;"><div id="map"></div></div>
</div>
</div>
<script>
let map, layer;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function initMap(){
  map=L.map('map',{worldCopyJump:true}).setView([20,0],2);
  <?= nm_map_tile_js($conn) ?>.addTo(map);
  layer=L.layerGroup().addTo(map);
}
async function trace(){
  const t=document.getElementById('target').value.trim(); if(!t)return;
  const st=document.getElementById('status'); st.innerHTML='<i class="fas fa-spinner fa-spin"></i> Tracing '+esc(t)+'… (hop by hop)';
  document.getElementById('go').disabled=true;
  document.getElementById('hops').innerHTML='<tr><td colspan="5" class="muted">Tracing…</td></tr>';
  const r=await fetch('nettrace.php?api=trace&target='+encodeURIComponent(t)).then(r=>r.json()).catch(()=>null);
  document.getElementById('go').disabled=false;
  if(!r||!r.ok){ st.innerHTML='<span style="color:var(--crit)">✗ '+(r?esc(r.error):'trace failed')+'</span>'; return; }
  st.innerHTML = r.reached? '<span style="color:var(--ok)">✓ Reached '+esc(t)+' in '+r.hops.length+' hops</span>' : '<span style="color:var(--warn)">Stopped after '+r.hops.length+' hops (target not reached)</span>';
  document.getElementById('hops').innerHTML = r.hops.map(h=>{
    const g=h.geo; const loc = !g?'—':(g.private?'<span class="muted">private</span>':esc((g.city?g.city+', ':'')+(g.country||'')));
    const asn = g&&!g.private?esc(g.asn||''):'';
    return `<tr class="${h.final?'fin':''}"><td><span class="hopnum">${h.ttl}</span></td><td class="mono">${h.ip?esc(h.ip):'<span class="muted">* no reply</span>'}</td>
      <td>${h.rtt!=null?h.rtt+' ms':'—'}</td><td>${loc}</td><td class="muted" style="font-size:10px;">${asn}</td></tr>`;
  }).join('');
  // map
  layer.clearLayers();
  const pts=[]; let prev=null;
  r.hops.forEach(h=>{ const g=h.geo; if(!g||g.private||g.lat==null)return;
    const ll=[g.lat,g.lon]; pts.push(ll);
    L.circleMarker(ll,{radius:7,color:h.final?'#2ecc71':'#4da3ff',fillColor:h.final?'#2ecc71':'#4da3ff',fillOpacity:.85,weight:2})
      .bindPopup('<b>Hop '+h.ttl+'</b><br>'+esc(h.ip)+'<br>'+esc((g.city?g.city+', ':'')+(g.country||''))+'<br>'+esc(g.asn||'')+'<br>'+(h.rtt!=null?h.rtt+' ms':'')).addTo(layer);
    if(prev) L.polyline([prev,ll],{color:'#4da3ff',weight:2,opacity:.6,dashArray:'4,6'}).addTo(layer);
    prev=ll;
  });
  if(pts.length) map.fitBounds(pts,{padding:[40,40],maxZoom:6});
}
initMap();
</script>
<script>window.addEventListener("DOMContentLoaded",function(){var q=new URLSearchParams(location.search),tg=q.get("target");if(tg){var i=document.getElementById("target");if(i){i.value=tg;}if(q.get("autostart")==="1"){var f=window.trace||window.start||window.lookup||window.run;if(f)setTimeout(f,350);}}});</script>
</body></html>
