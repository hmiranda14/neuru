<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Weather-Aware Routing UI. Threatened field nodes, active weather
// alerts, node geo management, n8n weather poll config. RBAC: 'weather'.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once __DIR__.'/nm_maptiles.php';   // shared keyless basemap (CARTO now needs a key)
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_weather.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'weather')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=weather'); exit;
}
nm_wx_ensure($conn);
if (function_exists('session_write_close')) @session_write_close(); // free session lock before slow SSH/n8n I/O (prevents whole-portal freeze)

$canConfig = nm_can($conn,'net_mon_config');

if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    $body = json_decode(file_get_contents('php://input'), true) ?? $_POST;
    if ($api === 'data') {
        echo json_encode(['ok'=>true,'threatened'=>nm_wx_threatened($conn),'alerts'=>nm_wx_active_alerts($conn),'counts'=>nm_wx_counts($conn),'geo'=>nm_wx_nodes_geo($conn)]); exit;
    }
    if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
    if ($api === 'poll') { echo json_encode(nm_wx_poll($conn)); exit; }
    if (!$canConfig) { echo json_encode(['ok'=>false,'error'=>'Configuration access required']); exit; }
    if ($api === 'set_geo') {
        $nid=(int)($body['node_id']??0); if(!$nid){ echo json_encode(['ok'=>false,'error'=>'node']); exit; }
        if(isset($body['delete'])){ nm_wx_del_geo($conn,$nid); echo json_encode(['ok'=>true]); exit; }
        nm_wx_set_geo($conn,$nid,(float)($body['lat']??0),(float)($body['lon']??0),(string)($body['link_type']??'fiber'));
        echo json_encode(['ok'=>true]); exit;
    }
    if ($api === 'save_settings') {
        $st=$conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES('wx_poll_url',?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
        $u=trim((string)($body['wx_poll_url']??'')); $st->bind_param('s',$u); $st->execute();
        echo json_encode(['ok'=>true]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'Unknown endpoint']); exit;
}
$nodes=[]; $nr=$conn->query("SELECT id,display_name FROM nm_nodes ORDER BY display_name"); while($nr&&$x=$nr->fetch_assoc()) $nodes[]=$x;
$geo=[]; foreach(nm_wx_nodes_geo($conn) as $g) $geo[$g['id']]=$g;
$wxurl=nm_wx_setting($conn,'wx_poll_url','');
log_user_action($conn,'view_page','weather.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<script src="/leaflet.min.js"></script>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Weather Routing | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --extreme:#c0392b; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.18; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 40px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; } .card h3{ margin:0 0 12px; font-size:12px; color:var(--accent); text-transform:uppercase; letter-spacing:1px; }
.kpis{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-bottom:16px; }
.kpi{ padding:14px 16px; text-align:center; } .kpi .n{ font-size:26px; font-weight:800; } .kpi .l{ font-size:11px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; }
.grid2{ display:grid; grid-template-columns:1fr 1fr; gap:16px; } @media(max-width:900px){ .grid2{ grid-template-columns:1fr; } }
.th{ border:1px solid var(--border); border-left-width:4px; border-radius:10px; padding:12px 14px; margin-bottom:10px; }
.th.extreme{ border-left-color:var(--extreme); background:rgba(192,57,43,.08);} .th.severe{ border-left-color:var(--crit); background:rgba(231,76,60,.06);} .th.moderate{ border-left-color:var(--warn);} .th.minor{ border-left-color:var(--accent);}
.sev{ font-size:9px; font-weight:800; padding:2px 8px; border-radius:5px; text-transform:uppercase; }
.sv-extreme{ background:rgba(192,57,43,.25); color:#ff8a7a;} .sv-severe{ background:rgba(231,76,60,.2); color:#f0a59d;} .sv-moderate{ background:rgba(243,156,18,.2); color:var(--warn);} .sv-minor{ background:rgba(77,163,255,.18); color:var(--accent);}
.lt{ font-size:9px; padding:2px 7px; border-radius:5px; background:rgba(255,255,255,.08); color:#aab; }
table{ width:100%; border-collapse:collapse; font-size:12.5px; } th,td{ text-align:left; padding:7px 8px; border-bottom:1px solid rgba(255,255,255,.07); }
th{ color:#7c828c; font-size:10.5px; text-transform:uppercase; }
.inp,select{ background:rgba(0,0,0,.4); border:1px solid var(--border); color:#eee; border-radius:7px; padding:6px 8px; font-size:12px; }
.btn{ background:rgba(255,255,255,.06); border:1px solid var(--border); color:#cfd3da; padding:6px 11px; border-radius:7px; cursor:pointer; font-size:11.5px; }
.btn:hover{ background:rgba(255,255,255,.13); color:#fff; } .muted{ color:#7c828c; font-size:12px; }
label{ display:block; font-size:11px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; margin:10px 0 4px; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-hurricane"></i>Weather Routing', '', 'Climate-Aware NOC', 'fa-solid fa-hurricane',
    '<button class="refresh-btn" onclick="pollNow(this)"><i class="fas fa-cloud-bolt"></i> Poll weather</button>'); ?>

<div class="kpis">
  <div class="glass kpi"><div class="n" style="color:var(--crit)" id="k-threat">—</div><div class="l">Threatened nodes</div></div>
  <div class="glass kpi"><div class="n" style="color:var(--warn)" id="k-alerts">—</div><div class="l">Active alerts</div></div>
  <div class="glass kpi"><div class="n" id="k-geo">—</div><div class="l">Geolocated nodes</div></div>
</div>

<div class="glass card" style="margin-bottom:16px;">
  <h3><i class="fas fa-earth-americas"></i> Live weather map <span class="muted" style="text-transform:none;letter-spacing:0;">— your geolocated nodes, colored by weather threat</span></h3>
  <div id="wx-map" style="width:100%;height:420px;border-radius:12px;overflow:hidden;"></div>
  <div class="muted" style="margin-top:8px;font-size:11.5px;">🟢 clear · 🟡 advisory/watch · 🟠 warning · 🔴 severe/extreme — set node coordinates below to place them.</div>
</div>

<div class="grid2">
  <div class="glass card">
    <h3><i class="fas fa-triangle-exclamation"></i> Threatened field nodes</h3>
    <div id="th-empty" class="muted" style="display:none;padding:8px;">No nodes under weather threat. Clear skies. ☀️</div>
    <div id="threatened"><div class="muted">Loading…</div></div>
  </div>
  <div>
    <div class="glass card">
      <h3><i class="fas fa-cloud-showers-heavy"></i> Active weather alerts</h3>
      <div id="alerts"><div class="muted">Loading…</div></div>
    </div>
    <div class="glass card">
      <h3><i class="fas fa-plug"></i> n8n weather poll</h3>
      <label>wx_poll_url</label>
      <input class="inp" style="width:100%;" id="s-url" value="<?= htmlspecialchars($wxurl) ?>" placeholder="http://192.168.0.25:5678/webhook/weather-poll" <?= $canConfig?'':'disabled' ?>>
      <?php if($canConfig): ?><div style="margin-top:8px;"><button class="btn" onclick="saveUrl(this)"><i class="fas fa-save"></i> Save</button> <span class="muted" id="s-msg"></span></div><?php endif; ?>
      <div class="muted" style="margin-top:10px;line-height:1.6;">NEURU POSTs <code>{nodes:[{id,lat,lon,link_type}], alerts_url}</code>. n8n queries a weather API (NWS <code>api.weather.gov</code> — free, covers PR) per point and POSTs <code>{alerts:[{node_id,event,severity,headline,expires}]}</code> back to <code>nm_weather_api.php?ep=alerts</code>.</div>
    </div>
  </div>
</div>

<?php if($canConfig): ?>
<div class="glass card">
  <h3><i class="fas fa-location-dot"></i> Node geolocation <span class="muted" style="text-transform:none;letter-spacing:0;">— set lat/lon + link type so weather can be matched</span></h3>
  <div style="overflow-x:auto;"><table><thead><tr><th>Node</th><th>Lat</th><th>Lon</th><th>Link type</th><th></th></tr></thead><tbody>
    <?php foreach($nodes as $n): $g=$geo[(int)$n['id']]??null; ?>
    <tr data-node="<?= (int)$n['id'] ?>">
      <td><?= htmlspecialchars($n['display_name']) ?></td>
      <td><input class="inp g-lat" style="width:90px;" value="<?= $g?htmlspecialchars($g['lat']):'' ?>" placeholder="18.46"></td>
      <td><input class="inp g-lon" style="width:90px;" value="<?= $g?htmlspecialchars($g['lon']):'' ?>" placeholder="-66.10"></td>
      <td><select class="inp g-lt"><?php foreach(['fiber','microwave','satellite','copper'] as $lt): ?><option <?= ($g&&$g['link_type']===$lt)?'selected':'' ?>><?= $lt ?></option><?php endforeach; ?></select></td>
      <td><button class="btn" onclick="saveGeo(<?= (int)$n['id'] ?>,this)"><i class="fas fa-save"></i></button> <?= $g?'<button class="btn" onclick="delGeo('.(int)$n['id'].')"><i class="fas fa-trash"></i></button>':'' ?></td>
    </tr>
    <?php endforeach; ?>
  </tbody></table></div>
</div>
<?php endif; ?>
</div>
<script>
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
async function post(api,obj){ return fetch('weather.php?api='+api,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj||{})}).then(r=>r.json()).catch(()=>({ok:false,error:'failed'})); }
async function load(){
  const r=await fetch('weather.php?api=data').then(r=>r.json()).catch(()=>null); if(!r||!r.ok)return;
  document.getElementById('k-threat').textContent=r.counts.threatened; document.getElementById('k-alerts').textContent=r.counts.alerts; document.getElementById('k-geo').textContent=r.counts.geo_nodes;
  const te=document.getElementById('threatened'), tem=document.getElementById('th-empty');
  if(!r.threatened.length){ te.innerHTML=''; tem.style.display='block'; } else { tem.style.display='none';
    te.innerHTML=r.threatened.map(t=>`<div class="th ${t.severity}">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;"><span><span class="sev sv-${t.severity}">${t.severity}</span> <b>${esc(t.name)}</b> <span class="lt">${esc(t.link_type)}</span>${t.rain_fade?' <span class="sev sv-severe">rain-fade</span>':''}</span></div>
      <div class="muted" style="margin-top:5px;">${esc(t.event)}${t.headline?' — '+esc(t.headline):''}</div>
      <div style="margin-top:6px;font-size:12.5px;color:#f0c674;"><i class="fas fa-route"></i> ${esc(t.advice)}</div></div>`).join(''); }
  const al=document.getElementById('alerts');
  al.innerHTML = r.alerts.length ? r.alerts.map(a=>`<div class="th ${a.severity}" style="border-left-width:3px;"><span class="sev sv-${a.severity}">${a.severity}</span> <b>${esc(a.event)}</b> <span class="muted">· ${a.nodes} node(s)</span>${a.headline?`<div class="muted" style="margin-top:3px;">${esc(a.headline)}</div>`:''}</div>`).join('') : '<div class="muted">No active weather alerts.</div>';
  renderMap(r);
}
// ── Live weather map ──────────────────────────────────────────────────────────
let WXMAP=null, WXLAYER=null;
function sevColor(s){ s=(s||'').toLowerCase(); if(s==='extreme'||s==='severe')return '#e74c3c'; if(s==='warning')return '#e67e22'; if(s==='watch'||s==='advisory'||s==='moderate'||s==='minor')return '#f39c12'; return '#2ecc71'; }
function renderMap(r){
  const host=document.getElementById('wx-map'); if(!host||!window.L) return;
  if(!WXMAP){ WXMAP=L.map('wx-map',{worldCopyJump:true,zoomControl:true,attributionControl:false,preferCanvas:true}).setView([18.4,-66.1],7);
    <?= nm_map_tile_js($conn) ?>.addTo(WXMAP); WXLAYER=L.layerGroup().addTo(WXMAP); }
  WXLAYER.clearLayers();
  const threat={}; (r.threatened||[]).forEach(t=>{ threat[t.node_id]=t; });
  const geo=(r.geo||[]).filter(g=>g.lat!=null&&g.lon!=null); const pts=[];
  geo.forEach(g=>{ const t=threat[g.id]; const col=sevColor(t&&t.severity); const rad=t?9:6;
    const m=L.circleMarker([+g.lat,+g.lon],{radius:rad,color:col,weight:2,fillColor:col,fillOpacity:t?0.75:0.5});
    const pop=`<b>${esc(g.name)}</b><br>${esc(g.link_type||'')}` + (t?`<br><span style="color:${col}">${esc(t.severity)} · ${esc(t.event)}</span>${t.headline?'<br>'+esc(t.headline):''}`:'<br>clear');
    m.bindPopup(pop); m.addTo(WXLAYER); pts.push([+g.lat,+g.lon]);
    if(t){ L.circleMarker([+g.lat,+g.lon],{radius:rad+7,color:col,weight:1,opacity:0.5,fill:false}).addTo(WXLAYER); }  // threat halo
  });
  if(pts.length){ try{ WXMAP.fitBounds(pts,{padding:[40,40],maxZoom:11}); }catch(e){} }
  setTimeout(()=>WXMAP.invalidateSize(),120);
}
async function pollNow(btn){ btn.disabled=true; const r=await post('poll',{}); btn.disabled=false; alert(r.ok?'Weather poll triggered — alerts will arrive from n8n shortly.':(r.err||'wx_poll_url not configured')); setTimeout(load,3000); }
async function saveGeo(id,btn){ const tr=btn.closest('tr'); btn.disabled=true; const r=await post('set_geo',{node_id:id,lat:tr.querySelector('.g-lat').value,lon:tr.querySelector('.g-lon').value,link_type:tr.querySelector('.g-lt').value}); btn.disabled=false; load(); }
async function delGeo(id){ if(!confirm('Remove geolocation?'))return; await post('set_geo',{node_id:id,delete:1}); location.reload(); }
async function saveUrl(btn){ btn.disabled=true; const r=await post('save_settings',{wx_poll_url:document.getElementById('s-url').value}); btn.disabled=false; document.getElementById('s-msg').textContent=r.ok?'Saved ✓':'Failed'; }
load(); setInterval(load, 30000);
</script>
</body></html>
