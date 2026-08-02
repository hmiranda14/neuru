<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Pi-hole monitoring. Server-side proxy to the Pi-hole v6 REST API
// (password stays encrypted server-side) + a NEURU-styled dashboard & live log.
// Gated by permission key 'pihole'.
// ─────────────────────────────────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) session_start();
include_once __DIR__ . '/connection.php';
require_once __DIR__ . '/access_control.php';
require_once __DIR__ . '/nm_pihole.php';
require_once __DIR__ . '/nm_chrome.php';

// ── JSON proxy API (whitelisted paths only) ──────────────────────────────────
if (isset($_GET['api'])) {
    header('Content-Type: application/json');
    if (empty($_SESSION['username']) || !checkAccess($conn, 'pihole')) {
        http_response_code(403); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit;
    }
    session_write_close();

    // friendly name → [pihole path, allowed passthrough query params]
    $MAP = [
        'summary'     => ['stats/summary', []],
        'history'     => ['history', []],
        'query_types' => ['stats/query_types', []],
        'top_domains' => ['stats/top_domains', ['blocked','count']],
        'top_clients' => ['stats/top_clients', ['blocked','count']],
        'upstreams'   => ['stats/upstreams', []],
        'system'      => ['info/system', []],
        'version'     => ['info/version', []],
        'devices'     => ['network/devices', ['max_devices','max_addresses']],
        'queries'     => ['queries', ['length','from','until','domain','client','upstream','type','status','cursor']],
        'dnslog'      => ['logs/dnsmasq', ['nextID']],
    ];
    $name = $_GET['api'];
    if (!isset($MAP[$name])) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Unknown endpoint']); exit; }
    [$path, $allowed] = $MAP[$name];
    $q = [];
    foreach ($allowed as $k) if (isset($_GET[$k]) && $_GET[$k] !== '') $q[$k] = $_GET[$k];

    // which Pi-hole — explicit ?server=ID, else the first enabled one
    $sid = (int)($_GET['server'] ?? 0) ?: nm_ph_default_id($conn);
    if (!$sid) { echo json_encode(['ok'=>false,'error'=>'No Pi-hole configured']); exit; }

    $r = nm_ph_call($conn, $sid, $path, $q);
    if (!$r['ok']) { echo json_encode(['ok'=>false,'error'=>$r['error'] ?? 'failed']); exit; }
    echo json_encode(['ok'=>true,'data'=>$r['data']]);
    exit;
}

// ── HTML page ────────────────────────────────────────────────────────────────
include('check.php');
if (!checkAccess($conn, 'pihole')) { header('Location: /denied_access.php?page=pihole'); exit; }
$PH_SERVERS = nm_ph_servers($conn, true);   // enabled servers for the selector
include('header.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pi-hole | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="/chart.umd.min.js"></script>
<script src="/chartjs-adapter-date-fns.bundle.min.js"></script>
<style>
<?= nm_chrome_css() ?>
:root{--glass:rgba(255,255,255,0.07);--border:rgba(255,255,255,0.13);--accent:#4da3ff;--up:#2ecc71;--down:#e74c3c;--warn:#f39c12;--mut:#8a909a;--ph:#f60d1a;}
body{margin:0;font-family:'Segoe UI',Tahoma,sans-serif;background:#000;color:#fff;overflow-x:hidden;}
.wrap{max-width:1600px;margin:0 auto;padding:18px 22px 60px;}
.glass-card{background:var(--glass);backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:16px;padding:18px 20px;margin-bottom:18px;}
h2{margin:0 0 14px;font-size:14px;color:var(--accent);display:flex;align-items:center;gap:9px;}
.bento{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px;}
.kpi{background:var(--glass);border:1px solid var(--border);border-radius:16px;padding:16px 18px;position:relative;overflow:hidden;}
.kpi .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--mut);}
.kpi .val{font-size:30px;font-weight:800;margin-top:4px;}
.kpi .sub{font-size:11px;color:var(--mut);margin-top:2px;}
.kpi.accent .val{color:var(--accent);} .kpi.block .val{color:var(--ph);} .kpi.ok .val{color:var(--up);} .kpi.warn .val{color:var(--warn);}
.grid2{display:grid;grid-template-columns:1.4fr 1fr;gap:16px;}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;}
@media(max-width:1000px){.bento{grid-template-columns:repeat(2,1fr);}.grid2,.grid3{grid-template-columns:1fr;}}
table{width:100%;border-collapse:collapse;font-size:12.5px;}
th{text-align:left;color:var(--mut);font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.6px;padding:7px 9px;border-bottom:1px solid var(--border);}
td{padding:6px 9px;border-bottom:1px solid rgba(255,255,255,.05);}
tr:hover td{background:rgba(255,255,255,.025);}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;}
.bar{height:6px;border-radius:4px;background:rgba(255,255,255,.07);overflow:hidden;margin-top:4px;}
.bar i{display:block;height:100%;background:var(--accent);}
.bar.blk i{background:var(--ph);}
.tag{font-size:10px;padding:2px 8px;border-radius:6px;font-weight:700;text-transform:uppercase;}
.t-block{background:rgba(246,13,26,.16);color:#ff6b6b;} .t-ok{background:rgba(46,204,113,.16);color:#2ecc71;}
.t-cache{background:rgba(77,163,255,.16);color:#7fc0ff;} .t-fwd{background:rgba(243,156,18,.16);color:#f5b73d;}
.mut{color:var(--mut);} .hidden{display:none!important;}
.disabled-note{background:rgba(243,156,18,.1);border:1px solid rgba(243,156,18,.4);color:#f5b73d;border-radius:12px;padding:20px;text-align:center;}
.live-dot{width:8px;height:8px;border-radius:50%;background:var(--up);display:inline-block;animation:nmpulse 2s infinite;}
.qrow td{font-size:12px;}
</style>
</head>
<body>
<div class="wrap">
<?php nm_page_header('Pi-hole', 'DNS', 'Network-wide Ad Blocking', 'fa-solid fa-shield-halved'); ?>

<?php if (empty($PH_SERVERS)): ?>
  <div class="disabled-note">
    <i class="fa-solid fa-triangle-exclamation" style="font-size:24px;display:block;margin-bottom:8px;"></i>
    No Pi-hole is configured. Add one (or more) in
    <a href="net_mon_config.php?tab=integrations" style="color:#f5b73d;">Config → Integrations → Pi-hole</a> and enable it.
  </div>
<?php else: ?>

<div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:8px;">
  <?php nm_module_tabs([
      ['icon'=>'fa-solid fa-gauge-high','label'=>'Overview','href'=>'#overview','active'=>true],
      ['icon'=>'fa-solid fa-list','label'=>'Live Queries','href'=>'#live','active'=>false],
      ['icon'=>'fa-solid fa-network-wired','label'=>'Clients & Upstreams','href'=>'#clients','active'=>false],
  ]); ?>
  <?php if (count($PH_SERVERS) > 1): ?>
  <label style="margin-left:auto;display:flex;align-items:center;gap:7px;font-size:12px;color:var(--mut);">
    <i class="fa-solid fa-server" style="color:var(--ph);"></i> Pi-hole
    <select id="ph-server" style="background:rgba(20,30,50,.95);border:1px solid var(--border);color:#fff;padding:6px 11px;border-radius:8px;font-size:12.5px;outline:none;">
      <?php foreach ($PH_SERVERS as $s): ?>
      <option value="<?= (int)$s['id'] ?>"><?= htmlspecialchars($s['name']) ?> · <?= htmlspecialchars(preg_replace('#^https?://#','',$s['url'])) ?></option>
      <?php endforeach; ?>
    </select>
  </label>
  <?php endif; ?>
</div>

<!-- ════ OVERVIEW ════ -->
<section id="tab-overview">
  <div class="bento">
    <div class="kpi accent"><div class="lbl">Total Queries (24h)</div><div class="val" id="k-total">—</div><div class="sub" id="k-total-sub"></div></div>
    <div class="kpi block"><div class="lbl">Queries Blocked</div><div class="val" id="k-blocked">—</div><div class="sub" id="k-blocked-sub"></div></div>
    <div class="kpi warn"><div class="lbl">Percent Blocked</div><div class="val" id="k-pct">—</div><div class="sub">of all DNS queries</div></div>
    <div class="kpi ok"><div class="lbl">Domains on Blocklist</div><div class="val" id="k-gravity">—</div><div class="sub" id="k-clients-sub"></div></div>
  </div>

  <div class="grid2">
    <div class="glass-card"><h2><i class="fa-solid fa-chart-area"></i> Queries over 24 hours</h2>
      <div style="height:240px;"><canvas id="histChart"></canvas></div></div>
    <div class="glass-card"><h2><i class="fa-solid fa-chart-pie"></i> Query Types</h2>
      <div id="qtypes"><div class="mut" style="padding:14px;">Loading…</div></div></div>
  </div>

  <div class="grid3" style="margin-top:16px;">
    <div class="glass-card"><h2><i class="fa-solid fa-globe"></i> Top Permitted Domains</h2>
      <table><tbody id="top-permit"><tr><td class="mut">Loading…</td></tr></tbody></table></div>
    <div class="glass-card"><h2 style="color:var(--ph);"><i class="fa-solid fa-ban"></i> Top Blocked Domains</h2>
      <table><tbody id="top-block"><tr><td class="mut">Loading…</td></tr></tbody></table></div>
    <div class="glass-card"><h2><i class="fa-solid fa-desktop"></i> Top Clients</h2>
      <table><tbody id="top-clients"><tr><td class="mut">Loading…</td></tr></tbody></table></div>
  </div>
</section>

<!-- ════ LIVE ════ -->
<section id="tab-live" class="hidden">
  <div class="glass-card">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:10px;">
      <h2 style="margin:0;"><span class="live-dot"></span> Live DNS Queries</h2>
      <label class="mut" style="font-size:12px;"><input type="checkbox" id="live-auto" checked> Auto-refresh (3s)</label>
    </div>
    <div style="overflow-x:auto;max-height:62vh;">
      <table>
        <thead><tr><th>Time</th><th>Domain</th><th>Client</th><th>Type</th><th>Status</th><th>Upstream</th></tr></thead>
        <tbody id="live-tbody"><tr><td colspan="6" class="mut" style="padding:20px;text-align:center;">Loading…</td></tr></tbody>
      </table>
    </div>
  </div>
</section>

<!-- ════ CLIENTS & UPSTREAMS ════ -->
<section id="tab-clients" class="hidden">
  <div class="grid2">
    <div class="glass-card"><h2><i class="fa-solid fa-server"></i> Upstream Servers</h2>
      <table><tbody id="upstreams"><tr><td class="mut">Loading…</td></tr></tbody></table></div>
    <div class="glass-card"><h2><i class="fa-solid fa-network-wired"></i> System</h2>
      <div id="sysinfo" class="mut">Loading…</div></div>
  </div>
</section>

<?php endif; ?>
</div>

<script>
const ENABLED = <?= !empty($PH_SERVERS) ? 'true':'false' ?>;
let SERVER = <?= !empty($PH_SERVERS) ? (int)$PH_SERVERS[0]['id'] : 0 ?>;
function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function nfmt(n){ return (n==null||isNaN(n))?'—':(+n).toLocaleString(); }
async function api(name,q){ let u='pihole.php?api='+name+'&server='+SERVER+(q?('&'+q):''); const r=await fetch(u).then(r=>r.json()).catch(()=>({ok:false,error:'fetch failed'}));
  if(!r.ok){ throw new Error(r.error||'error'); } return r.data; }

if (ENABLED) {
  // server selector → reload everything for the picked Pi-hole
  const _ss=document.getElementById('ph-server');
  if(_ss) _ss.addEventListener('change',e=>{ SERVER=+e.target.value; loadOverview(); if(!document.getElementById('tab-clients').classList.contains('hidden')) loadClients(); });
  // tabs
  document.querySelectorAll('.nm-tab').forEach(t=>t.addEventListener('click',e=>{
    e.preventDefault();
    document.querySelectorAll('.nm-tab').forEach(x=>x.classList.remove('is-active')); t.classList.add('is-active');
    const id=t.getAttribute('href').slice(1);
    ['overview','live','clients'].forEach(s=>document.getElementById('tab-'+s).classList.toggle('hidden',s!==id));
    if(id==='live') startLive(); else stopLive();
    if(id==='clients') loadClients();
  }));

  let histChart=null;
  async function loadOverview(){
    try{
      const s=await api('summary');
      const q=s.queries||{}, g=s.gravity||{}, cl=s.clients||{};
      document.getElementById('k-total').textContent=nfmt(q.total);
      document.getElementById('k-total-sub').textContent=(cl.active!=null?cl.active+' active clients':'');
      document.getElementById('k-blocked').textContent=nfmt(q.blocked);
      const pct=q.percent_blocked!=null?(+q.percent_blocked).toFixed(1):'—';
      document.getElementById('k-blocked-sub').textContent=(q.forwarded!=null?nfmt(q.forwarded)+' forwarded':'');
      document.getElementById('k-pct').textContent=pct==='—'?'—':(pct+'%');
      document.getElementById('k-gravity').textContent=nfmt(g.domains_being_blocked);
      document.getElementById('k-clients-sub').textContent=(cl.total!=null?cl.total+' clients seen':'');
    }catch(e){ document.getElementById('k-total').textContent='err'; }

    // history chart
    try{
      const h=(await api('history')).history||[];
      const labels=h.map(p=>new Date((p.timestamp||0)*1000));
      const total=h.map(p=>p.total||0);
      const blocked=h.map(p=>p.blocked||0);
      const ctx=document.getElementById('histChart').getContext('2d');
      const g1=ctx.createLinearGradient(0,0,0,240); g1.addColorStop(0,'rgba(77,163,255,.35)'); g1.addColorStop(1,'rgba(77,163,255,0)');
      const g2=ctx.createLinearGradient(0,0,0,240); g2.addColorStop(0,'rgba(246,13,26,.35)'); g2.addColorStop(1,'rgba(246,13,26,0)');
      if(histChart) histChart.destroy();
      histChart=new Chart(ctx,{type:'line',data:{labels,datasets:[
          {label:'Queries',data:total,borderColor:'#4da3ff',backgroundColor:g1,borderWidth:2,pointRadius:0,fill:true,tension:.35},
          {label:'Blocked',data:blocked,borderColor:'#f60d1a',backgroundColor:g2,borderWidth:2,pointRadius:0,fill:true,tension:.35}]},
        options:{responsive:true,maintainAspectRatio:false,animation:false,interaction:{mode:'index',intersect:false},
          plugins:{legend:{labels:{color:'#9aa',boxWidth:12,font:{size:11}}}},
          scales:{x:{type:'time',time:{unit:'hour'},ticks:{color:'#666',maxTicksLimit:8},grid:{color:'rgba(255,255,255,.04)'}},
                  y:{beginAtZero:true,ticks:{color:'#666'},grid:{color:'rgba(255,255,255,.04)'}}}}});
    }catch(e){}

    // query types
    try{
      const t=(await api('query_types')).types||{};
      const ent=Object.entries(t).filter(([k,v])=>v>0).sort((a,b)=>b[1]-a[1]);
      const max=Math.max(1,...ent.map(e=>e[1]));
      document.getElementById('qtypes').innerHTML=ent.map(([k,v])=>`
        <div style="margin-bottom:9px;"><div style="display:flex;justify-content:space-between;font-size:12px;">
          <b>${esc(k)}</b><span class="mut">${nfmt(v)}</span></div>
          <div class="bar"><i style="width:${Math.round(v/max*100)}%"></i></div></div>`).join('')||'<div class="mut">No data</div>';
    }catch(e){}

    // top lists
    topList('top_domains','top-permit',false);
    topList('top_domains','top-block',true);
    topClients();
  }
  async function topList(ep,elId,blocked){
    try{ const d=await api(ep,'blocked='+(blocked?'true':'false')+'&count=10');
      const arr=d.domains||[]; const max=Math.max(1,...arr.map(x=>x.count));
      document.getElementById(elId).innerHTML=arr.map(x=>`<tr><td style="max-width:170px;overflow:hidden;text-overflow:ellipsis;"><span class="mono">${esc(x.domain)}</span>
        <div class="bar ${blocked?'blk':''}"><i style="width:${Math.round(x.count/max*100)}%"></i></div></td>
        <td style="text-align:right;white-space:nowrap;">${nfmt(x.count)}</td></tr>`).join('')||'<tr><td class="mut">No data</td></tr>';
    }catch(e){ document.getElementById(elId).innerHTML='<tr><td class="mut">'+esc(e.message)+'</td></tr>'; }
  }
  async function topClients(){
    try{ const d=await api('top_clients','count=10'); const arr=d.clients||[]; const max=Math.max(1,...arr.map(x=>x.count));
      document.getElementById('top-clients').innerHTML=arr.map(x=>`<tr><td><b>${esc(x.name||x.ip)}</b><div class="mut mono" style="font-size:10px;">${esc(x.ip||'')}</div>
        <div class="bar"><i style="width:${Math.round(x.count/max*100)}%"></i></div></td>
        <td style="text-align:right;">${nfmt(x.count)}</td></tr>`).join('')||'<tr><td class="mut">No data</td></tr>';
    }catch(e){}
  }

  // ── Live queries ──
  let liveTimer=null;
  const STATUS={GRAVITY:['t-block','blocked'],DENYLIST:['t-block','denied'],REGEX_DENY:['t-block','regex'],
    FORWARDED:['t-fwd','forwarded'],CACHE:['t-cache','cached'],
    GRAVITY_CNAME:['t-block','blocked'],SPECIAL_DOMAIN:['t-block','special'],RETRIED:['t-fwd','retried']};
  async function pollLive(){
    try{ const d=await api('queries','length=100'); const qs=d.queries||[];
      document.getElementById('live-tbody').innerHTML=qs.map(q=>{
        const stRaw=(q.status||'').toUpperCase(); const m=STATUS[stRaw]||(stRaw.includes('BLACK')||stRaw.includes('DENY')||stRaw.includes('GRAVITY')?['t-block','blocked']:['t-ok','ok']);
        const t=new Date((q.time||0)*1000).toLocaleTimeString();
        const up=q.upstream||(m[1]==='cached'?'cache':(m[1]==='blocked'?'—':''));
        return `<tr class="qrow"><td class="mono mut">${t}</td>
          <td class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;">${esc(q.domain)}</td>
          <td class="mono">${esc((q.client&&(q.client.name||q.client.ip))||q.client||'')}</td>
          <td>${esc(q.type||'')}</td>
          <td><span class="tag ${m[0]}">${esc(m[1])}</span></td>
          <td class="mut mono">${esc(up)}</td></tr>`;
      }).join('')||'<tr><td colspan="6" class="mut" style="text-align:center;padding:18px;">No queries.</td></tr>';
    }catch(e){ document.getElementById('live-tbody').innerHTML='<tr><td colspan="6" class="mut" style="text-align:center;padding:18px;">'+esc(e.message)+'</td></tr>'; }
  }
  function startLive(){ pollLive(); clearInterval(liveTimer);
    liveTimer=setInterval(()=>{ if(document.getElementById('live-auto').checked && !document.hidden) pollLive(); },3000); }
  function stopLive(){ clearInterval(liveTimer); liveTimer=null; }

  // ── Clients & upstreams ──
  async function loadClients(){
    try{ const d=await api('upstreams'); const arr=d.upstreams||[]; const max=Math.max(1,...arr.map(x=>x.count));
      document.getElementById('upstreams').innerHTML=arr.map(x=>`<tr><td><b>${esc(x.name||x.ip||'cache')}</b>
        <div class="mut mono" style="font-size:10px;">${esc(x.ip||'')}${x.port&&x.port>0?(':'+x.port):''}</div>
        <div class="bar"><i style="width:${Math.round((x.count||0)/max*100)}%"></i></div></td>
        <td style="text-align:right;">${nfmt(x.count)}</td></tr>`).join('')||'<tr><td class="mut">No data</td></tr>';
    }catch(e){ document.getElementById('upstreams').innerHTML='<tr><td class="mut">'+esc(e.message)+'</td></tr>'; }
    try{ const s=await api('system'); const sy=s.system||s;
      const mem=sy.memory&&sy.memory.ram?sy.memory.ram:null; const up=sy.uptime!=null?sy.uptime:null;
      const load=sy['%cpu']!=null?sy['%cpu']:(sy.cpu&&sy.cpu.load&&sy.cpu.load.raw?sy.cpu.load.raw[0]:null);
      document.getElementById('sysinfo').innerHTML=`<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;color:#cfd3da;font-size:13px;">
        ${up!=null?`<div><div class="mut" style="font-size:10px;">UPTIME</div>${Math.floor(up/86400)}d ${Math.floor(up%86400/3600)}h</div>`:''}
        ${mem?`<div><div class="mut" style="font-size:10px;">MEMORY USED</div>${(mem['%used']!=null?(+mem['%used']).toFixed(1)+'%':'—')}</div>`:''}
        ${load!=null?`<div><div class="mut" style="font-size:10px;">CPU LOAD</div>${(+load).toFixed(2)}</div>`:''}
      </div>`;
    }catch(e){ document.getElementById('sysinfo').textContent=e.message; }
  }

  loadOverview();
  setInterval(()=>{ if(!document.hidden && !document.getElementById('tab-overview').classList.contains('hidden')) loadOverview(); }, 30000);
  document.addEventListener('visibilitychange',()=>{ if(document.hidden) stopLive(); else if(!document.getElementById('tab-live').classList.contains('hidden')) startLive(); });
}
</script>
</body>
</html>
