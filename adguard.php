<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — AdGuard Home monitoring. Server-side proxy to the AdGuard /control/*
// REST API (credentials stay encrypted server-side) + a NEURU-styled dashboard &
// live query log. Mirrors pihole.php. Gated by permission key 'adguard'.
// ─────────────────────────────────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) session_start();
include_once __DIR__ . '/connection.php';
require_once __DIR__ . '/access_control.php';
require_once __DIR__ . '/nm_adguard.php';
require_once __DIR__ . '/nm_chrome.php';

// ── JSON proxy API (whitelisted /control paths only) ─────────────────────────
if (isset($_GET['api'])) {
    header('Content-Type: application/json');
    if (empty($_SESSION['username']) || !checkAccess($conn, 'adguard')) {
        http_response_code(403); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit;
    }
    session_write_close();

    // friendly name → [AdGuard control path, allowed passthrough query params]
    $MAP = [
        'status'    => ['status', []],
        'stats'     => ['stats', []],
        'filtering' => ['filtering/status', []],
        'querylog'  => ['querylog', ['limit','search','response_status','older_than']],
        'clients'   => ['clients', []],
    ];
    $name = $_GET['api'];
    if (!isset($MAP[$name])) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Unknown endpoint']); exit; }
    [$path, $allowed] = $MAP[$name];
    $q = [];
    foreach ($allowed as $k) if (isset($_GET[$k]) && $_GET[$k] !== '') $q[$k] = $_GET[$k];

    $sid = (int)($_GET['server'] ?? 0) ?: nm_ag_default_id($conn);
    if (!$sid) { echo json_encode(['ok'=>false,'error'=>'No AdGuard configured']); exit; }

    $r = nm_ag_call($conn, $sid, $path, $q);
    if (!$r['ok']) { echo json_encode(['ok'=>false,'error'=>$r['error'] ?? 'failed']); exit; }
    echo json_encode(['ok'=>true,'data'=>$r['data']]);
    exit;
}

// ── HTML page ────────────────────────────────────────────────────────────────
include('check.php');
if (!checkAccess($conn, 'adguard')) { header('Location: /denied_access.php?page=adguard'); exit; }
$AG_SERVERS = nm_ag_servers($conn, true);
include('header.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AdGuard Home | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="/chart.umd.min.js"></script>
<script src="/chartjs-adapter-date-fns.bundle.min.js"></script>
<style>
<?= nm_chrome_css() ?>
:root{--glass:rgba(255,255,255,0.07);--border:rgba(255,255,255,0.13);--accent:#4da3ff;--up:#2ecc71;--down:#e74c3c;--warn:#f39c12;--mut:#8a909a;--ag:#67b279;}
body{margin:0;font-family:'Segoe UI',Tahoma,sans-serif;background:#000;color:#fff;overflow-x:hidden;}
.wrap{max-width:1600px;margin:0 auto;padding:18px 22px 60px;}
.glass-card{background:var(--glass);backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:16px;padding:18px 20px;margin-bottom:18px;}
h2{margin:0 0 14px;font-size:14px;color:var(--accent);display:flex;align-items:center;gap:9px;}
.bento{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px;}
.kpi{background:var(--glass);border:1px solid var(--border);border-radius:16px;padding:16px 18px;position:relative;overflow:hidden;}
.kpi .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--mut);}
.kpi .val{font-size:30px;font-weight:800;margin-top:4px;}
.kpi .sub{font-size:11px;color:var(--mut);margin-top:2px;}
.kpi.accent .val{color:var(--accent);} .kpi.block .val{color:var(--down);} .kpi.ok .val{color:var(--up);} .kpi.warn .val{color:var(--warn);}
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
.bar.blk i{background:var(--down);}
.tag{font-size:10px;padding:2px 8px;border-radius:6px;font-weight:700;text-transform:uppercase;}
.t-block{background:rgba(231,76,60,.16);color:#ff6b6b;} .t-ok{background:rgba(46,204,113,.16);color:#2ecc71;}
.t-cache{background:rgba(77,163,255,.16);color:#7fc0ff;} .t-fwd{background:rgba(243,156,18,.16);color:#f5b73d;}
.t-rw{background:rgba(168,132,255,.16);color:#c3a6ff;}
.mut{color:var(--mut);} .hidden{display:none!important;}
.disabled-note{background:rgba(243,156,18,.1);border:1px solid rgba(243,156,18,.4);color:#f5b73d;border-radius:12px;padding:20px;text-align:center;}
.live-dot{width:8px;height:8px;border-radius:50%;background:var(--up);display:inline-block;animation:nmpulse 2s infinite;}
.qrow td{font-size:12px;}
</style>
</head>
<body>
<div class="wrap">
<?php nm_page_header('AdGuard Home', 'DNS', 'Network-wide Ad Blocking', 'fa-solid fa-shield-cat'); ?>

<?php if (empty($AG_SERVERS)): ?>
  <div class="disabled-note">
    <i class="fa-solid fa-triangle-exclamation" style="font-size:24px;display:block;margin-bottom:8px;"></i>
    No AdGuard Home is configured. Add one (or more) in
    <a href="net_mon_config.php?tab=integrations" style="color:#f5b73d;">Config → Integrations → AdGuard Home</a> and enable it.
  </div>
<?php else: ?>

<div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:8px;">
  <?php nm_module_tabs([
      ['icon'=>'fa-solid fa-gauge-high','label'=>'Overview','href'=>'#overview','active'=>true],
      ['icon'=>'fa-solid fa-list','label'=>'Live Queries','href'=>'#live','active'=>false],
      ['icon'=>'fa-solid fa-network-wired','label'=>'Clients & Upstreams','href'=>'#clients','active'=>false],
  ]); ?>
  <?php if (count($AG_SERVERS) > 1): ?>
  <label style="margin-left:auto;display:flex;align-items:center;gap:7px;font-size:12px;color:var(--mut);">
    <i class="fa-solid fa-server" style="color:var(--ag);"></i> AdGuard
    <select id="ag-server" style="background:rgba(20,30,50,.95);border:1px solid var(--border);color:#fff;padding:6px 11px;border-radius:8px;font-size:12.5px;outline:none;">
      <?php foreach ($AG_SERVERS as $s): ?>
      <option value="<?= (int)$s['id'] ?>"><?= htmlspecialchars($s['name']) ?> · <?= htmlspecialchars(preg_replace('#^https?://#','',$s['url'])) ?></option>
      <?php endforeach; ?>
    </select>
  </label>
  <?php endif; ?>
</div>

<!-- ════ OVERVIEW ════ -->
<section id="tab-overview">
  <div class="bento">
    <div class="kpi accent"><div class="lbl">DNS Queries</div><div class="val" id="k-total">—</div><div class="sub" id="k-total-sub"></div></div>
    <div class="kpi block"><div class="lbl">Queries Blocked</div><div class="val" id="k-blocked">—</div><div class="sub" id="k-blocked-sub"></div></div>
    <div class="kpi warn"><div class="lbl">Percent Blocked</div><div class="val" id="k-pct">—</div><div class="sub">of all DNS queries</div></div>
    <div class="kpi ok"><div class="lbl">Rules in Blocklists</div><div class="val" id="k-gravity">—</div><div class="sub" id="k-prot-sub"></div></div>
  </div>

  <div class="grid2">
    <div class="glass-card"><h2><i class="fa-solid fa-chart-area"></i> Queries over time</h2>
      <div style="height:240px;"><canvas id="histChart"></canvas></div></div>
    <div class="glass-card"><h2><i class="fa-solid fa-gauge"></i> At a glance</h2>
      <div id="glance"><div class="mut" style="padding:14px;">Loading…</div></div></div>
  </div>

  <div class="grid3" style="margin-top:16px;">
    <div class="glass-card"><h2><i class="fa-solid fa-globe"></i> Top Queried Domains</h2>
      <table><tbody id="top-permit"><tr><td class="mut">Loading…</td></tr></tbody></table></div>
    <div class="glass-card"><h2 style="color:var(--down);"><i class="fa-solid fa-ban"></i> Top Blocked Domains</h2>
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
    <div class="glass-card"><h2><i class="fa-solid fa-server"></i> Top Upstreams</h2>
      <table><tbody id="upstreams"><tr><td class="mut">Loading…</td></tr></tbody></table></div>
    <div class="glass-card"><h2><i class="fa-solid fa-network-wired"></i> Server</h2>
      <div id="sysinfo" class="mut">Loading…</div></div>
  </div>
</section>

<?php endif; ?>
</div>

<script>
const ENABLED = <?= !empty($AG_SERVERS) ? 'true':'false' ?>;
let SERVER = <?= !empty($AG_SERVERS) ? (int)$AG_SERVERS[0]['id'] : 0 ?>;
function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function nfmt(n){ return (n==null||isNaN(n))?'—':(+n).toLocaleString(); }
// AdGuard top_* arrays are [{ "domain": count }, …] — pull the single [key,val] pair.
function kv(o){ const e=Object.entries(o||{}); return e.length?e[0]:['',0]; }
async function api(name,q){ let u='adguard.php?api='+name+'&server='+SERVER+(q?('&'+q):''); const r=await fetch(u).then(r=>r.json()).catch(()=>({ok:false,error:'fetch failed'}));
  if(!r.ok){ throw new Error(r.error||'error'); } return r.data; }

if (ENABLED) {
  const _ss=document.getElementById('ag-server');
  if(_ss) _ss.addEventListener('change',e=>{ SERVER=+e.target.value; loadOverview(); if(!document.getElementById('tab-clients').classList.contains('hidden')) loadClients(); });
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
    let stats={};
    try{
      stats=await api('stats');
      const total=stats.num_dns_queries||0, blocked=(stats.num_blocked_filtering||0)+(stats.num_replaced_safebrowsing||0)+(stats.num_replaced_parental||0);
      document.getElementById('k-total').textContent=nfmt(total);
      document.getElementById('k-total-sub').textContent=(stats.time_units?('last '+(stats.dns_queries?stats.dns_queries.length:'')+' '+stats.time_units):'');
      document.getElementById('k-blocked').textContent=nfmt(blocked);
      document.getElementById('k-blocked-sub').textContent=(stats.avg_processing_time!=null?((stats.avg_processing_time*1000).toFixed(1)+' ms avg'):'');
      const pct=total>0?(blocked/total*100):0;
      document.getElementById('k-pct').textContent=(total>0?pct.toFixed(1)+'%':'—');
    }catch(e){ document.getElementById('k-total').textContent='err'; document.getElementById('k-total-sub').textContent=e.message; }

    // blocklist size + protection (filtering/status + status)
    try{
      const f=await api('filtering');
      const rules=(f.filters||[]).filter(x=>x.enabled).reduce((a,x)=>a+(x.rules_count||0),0);
      document.getElementById('k-gravity').textContent=nfmt(rules);
      document.getElementById('k-gravity').textContent=nfmt(rules);
    }catch(e){}
    try{
      const st=await api('status');
      document.getElementById('k-prot-sub').textContent=(st.protection_enabled===false?'⚠ protection OFF':'protection on')+(st.version?(' · '+st.version):'');
    }catch(e){}

    // history chart from stats.dns_queries[] / blocked_filtering[]
    try{
      const q=stats.dns_queries||[], b=stats.blocked_filtering||[];
      const unit=stats.time_units==='days'?86400000:3600000;
      const now=Date.now(); const n=q.length;
      const labels=q.map((_,i)=>new Date(now-(n-1-i)*unit));
      const ctx=document.getElementById('histChart').getContext('2d');
      const g1=ctx.createLinearGradient(0,0,0,240); g1.addColorStop(0,'rgba(77,163,255,.35)'); g1.addColorStop(1,'rgba(77,163,255,0)');
      const g2=ctx.createLinearGradient(0,0,0,240); g2.addColorStop(0,'rgba(231,76,60,.35)'); g2.addColorStop(1,'rgba(231,76,60,0)');
      if(histChart) histChart.destroy();
      histChart=new Chart(ctx,{type:'line',data:{labels,datasets:[
          {label:'Queries',data:q,borderColor:'#4da3ff',backgroundColor:g1,borderWidth:2,pointRadius:0,fill:true,tension:.35},
          {label:'Blocked',data:b,borderColor:'#e74c3c',backgroundColor:g2,borderWidth:2,pointRadius:0,fill:true,tension:.35}]},
        options:{responsive:true,maintainAspectRatio:false,animation:false,interaction:{mode:'index',intersect:false},
          plugins:{legend:{labels:{color:'#9aa',boxWidth:12,font:{size:11}}}},
          scales:{x:{type:'time',time:{unit:stats.time_units==='days'?'day':'hour'},ticks:{color:'#666',maxTicksLimit:8},grid:{color:'rgba(255,255,255,.04)'}},
                  y:{beginAtZero:true,ticks:{color:'#666'},grid:{color:'rgba(255,255,255,.04)'}}}}});
    }catch(e){}

    // at-a-glance
    try{
      const total=stats.num_dns_queries||0;
      const rows=[
        ['Total queries', nfmt(total)],
        ['Blocked by filters', nfmt(stats.num_blocked_filtering||0)],
        ['Blocked (safe browsing)', nfmt(stats.num_replaced_safebrowsing||0)],
        ['Blocked (parental)', nfmt(stats.num_replaced_parental||0)],
        ['Avg processing', (stats.avg_processing_time!=null?((stats.avg_processing_time*1000).toFixed(2)+' ms'):'—')],
      ];
      document.getElementById('glance').innerHTML=rows.map(r=>`<div style="display:flex;justify-content:space-between;padding:7px 2px;border-bottom:1px solid rgba(255,255,255,.05);font-size:13px;">
        <span class="mut">${esc(r[0])}</span><b>${r[1]}</b></div>`).join('');
    }catch(e){}

    // top lists (from the same stats payload)
    renderTop('top-permit', stats.top_queried_domains, false);
    renderTop('top-block',  stats.top_blocked_domains, true);
    renderClients(stats.top_clients);
  }
  function renderTop(elId, arr, blocked){
    arr=arr||[]; const pairs=arr.map(kv); const max=Math.max(1,...pairs.map(p=>+p[1]||0));
    document.getElementById(elId).innerHTML=pairs.map(p=>`<tr><td style="max-width:170px;overflow:hidden;text-overflow:ellipsis;"><span class="mono">${esc(p[0])}</span>
      <div class="bar ${blocked?'blk':''}"><i style="width:${Math.round((+p[1]||0)/max*100)}%"></i></div></td>
      <td style="text-align:right;white-space:nowrap;">${nfmt(p[1])}</td></tr>`).join('')||'<tr><td class="mut">No data</td></tr>';
  }
  function renderClients(arr){
    arr=arr||[]; const pairs=arr.map(kv); const max=Math.max(1,...pairs.map(p=>+p[1]||0));
    document.getElementById('top-clients').innerHTML=pairs.map(p=>`<tr><td><b class="mono">${esc(p[0])}</b>
      <div class="bar"><i style="width:${Math.round((+p[1]||0)/max*100)}%"></i></div></td>
      <td style="text-align:right;">${nfmt(p[1])}</td></tr>`).join('')||'<tr><td class="mut">No data</td></tr>';
  }

  // ── Live queries (AdGuard querylog) ──
  let liveTimer=null;
  function classify(q){
    const r=(q.reason||'');
    if(q.cached) return ['t-cache','cached'];
    if(r.indexOf('Rewritten')===0) return ['t-rw','rewritten'];
    if(r.indexOf('Filtered')===0 || r==='FilteredBlackList') return ['t-block', r.replace('Filtered','').replace(/([A-Z])/g,' $1').trim().toLowerCase()||'blocked'];
    return ['t-ok','allowed'];
  }
  async function pollLive(){
    try{ const d=await api('querylog','limit=100'); const qs=d.data||[];
      document.getElementById('live-tbody').innerHTML=qs.map(q=>{
        const m=classify(q);
        const t=q.time?new Date(q.time).toLocaleTimeString():'';
        const host=(q.question&&(q.question.name||q.question.host))||''; const typ=(q.question&&q.question.type)||'';
        const up=q.upstream||(m[1]==='cached'?'cache':(m[0]==='t-block'?'—':''));
        return `<tr class="qrow"><td class="mono mut">${esc(t)}</td>
          <td class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;">${esc(host)}</td>
          <td class="mono">${esc(q.client||'')}</td>
          <td>${esc(typ)}</td>
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
    try{ const s=await api('stats'); const arr=(s.top_upstreams_responses||[]).map(kv); const max=Math.max(1,...arr.map(p=>+p[1]||0));
      document.getElementById('upstreams').innerHTML=arr.map(p=>`<tr><td><b class="mono">${esc(p[0]||'cache')}</b>
        <div class="bar"><i style="width:${Math.round((+p[1]||0)/max*100)}%"></i></div></td>
        <td style="text-align:right;">${nfmt(p[1])}</td></tr>`).join('')||'<tr><td class="mut">No data</td></tr>';
    }catch(e){ document.getElementById('upstreams').innerHTML='<tr><td class="mut">'+esc(e.message)+'</td></tr>'; }
    try{ const st=await api('status');
      document.getElementById('sysinfo').innerHTML=`<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;color:#cfd3da;font-size:13px;">
        <div><div class="mut" style="font-size:10px;">VERSION</div>${esc(st.version||'—')}</div>
        <div><div class="mut" style="font-size:10px;">PROTECTION</div>${st.protection_enabled===false?'<span style="color:var(--warn)">OFF</span>':'<span style="color:var(--up)">on</span>'}</div>
        <div><div class="mut" style="font-size:10px;">RUNNING</div>${st.running?'yes':'no'}</div>
        <div><div class="mut" style="font-size:10px;">DNS PORT</div>${esc((st.dns_port!=null?st.dns_port:'53'))}</div>
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
