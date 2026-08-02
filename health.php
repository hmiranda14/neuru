<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Predictive Link & Hardware Health UI. Proactive degradation forecasts
// for optical fiber (SFP DOM) and ethernet/copper (error-rate trends).
// RBAC: 'health'. Engine: nm_health.php. Collector: scripts/nm_health.py.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_health.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'health')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=health'); exit;
}
nm_health_ensure($conn);
$canConfig = nm_can($conn, 'net_mon_config');

if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    $body = json_decode(file_get_contents('php://input'), true) ?? $_POST;
    $metas = nm_health_metrics();

    if ($api === 'data') {
        $sev = $_GET['sev'] ?? '';
        $rows = nm_health_list($conn, $sev==='crit'?'crit':'');
        $excluded=nm_health_excluded($conn);
        $rows = array_values(array_filter($rows, fn($p)=>!isset($excluded[(int)$p['node_id'].'|'.$p['entity']])));
        $nodeNames=[]; $nr=$conn->query("SELECT id,display_name FROM nm_nodes"); while($nr&&$x=$nr->fetch_assoc()) $nodeNames[(int)$x['id']]=$x['display_name'];
        $out=array_map(function($p)use($metas,$nodeNames){
            $m=$metas[$p['metric']]??['label'=>$p['metric'],'unit'=>''];
            return ['id'=>(int)$p['id'],'node'=>$nodeNames[(int)$p['node_id']]??('node '.$p['node_id']),'node_id'=>(int)$p['node_id'],
                'entity'=>$p['entity'],'metric'=>$p['metric'],'metric_label'=>$m['label'],'unit'=>$m['unit'],'kind'=>$p['kind'],
                'severity'=>$p['severity'],'current'=>$p['current_val']===null?null:round((float)$p['current_val'],3),
                'threshold'=>(float)$p['threshold'],'slope'=>round((float)$p['slope_per_day'],4),
                'eta'=>$p['eta_days']===null?null:(float)$p['eta_days'],'samples'=>(int)$p['samples'],'detail'=>$p['detail'],'updated_at'=>$p['updated_at']];
        }, $rows);
        $lc=$conn->query("SELECT MAX(recorded_at) m FROM nm_health_samples"); $last=$lc?($lc->fetch_assoc()['m']):null;
        echo json_encode(['ok'=>true,'predictions'=>$out,'counts'=>nm_health_counts($conn),'last_collect'=>$last]); exit;
    }
    if ($api === 'links') {
        // Latest value per (node, interface, metric) for ethernet — the coverage view.
        $latest=$conn->query("SELECT s.node_id, s.entity, s.metric, s.value, s.recorded_at
            FROM nm_health_samples s
            JOIN (SELECT node_id,entity,metric,MAX(id) mid FROM nm_health_samples WHERE kind='eth' GROUP BY node_id,entity,metric) l ON l.mid=s.id");
        $nodeNames=[]; $nr=$conn->query("SELECT id,display_name FROM nm_nodes"); while($nr&&$x=$nr->fetch_assoc()) $nodeNames[(int)$x['id']]=$x['display_name'];
        $map=[];
        while($latest && $x=$latest->fetch_assoc()){
            $k=$x['node_id'].'|'.$x['entity'];
            if(!isset($map[$k])) $map[$k]=['node_id'=>(int)$x['node_id'],'entity'=>$x['entity'],'metrics'=>[],'at'=>$x['recorded_at']];
            $map[$k]['metrics'][$x['metric']]=round((float)$x['value'],4);
            if($x['recorded_at']>$map[$k]['at']) $map[$k]['at']=$x['recorded_at'];
        }
        $excluded=nm_health_excluded($conn);
        $out=[]; $muted=[];
        foreach($map as $row){
            $info=['node'=>$nodeNames[$row['node_id']]??('node '.$row['node_id']),'node_id'=>$row['node_id'],
                'entity'=>$row['entity'],'metrics'=>$row['metrics'],'at'=>$row['at']];
            if(isset($excluded[$row['node_id'].'|'.$row['entity']])){ $muted[]=$info; continue; }
            $sev='ok';
            foreach($row['metrics'] as $m=>$v){ $meta=$metas[$m]??null; if(!$meta)continue;
                if($v>=$meta['crit']) $sev='crit'; elseif($sev!=='crit' && $v>=$meta['warn']) $sev='warn'; }
            $info['severity']=$sev; $out[]=$info;
        }
        usort($out, fn($a,$b)=>[['ok'=>0,'warn'=>1,'crit'=>2][$b['severity']], $a['node']] <=> [['ok'=>0,'warn'=>1,'crit'=>2][$a['severity']], $b['node']]);
        echo json_encode(['ok'=>true,'links'=>$out,'count'=>count($out),'muted'=>$muted,'can_config'=>$canConfig]); exit;
    }
    if ($api === 'series') {
        $node=(int)($_GET['node']??0); $entity=(string)($_GET['entity']??''); $metric=(string)($_GET['metric']??'');
        $win=(int)nm_health_setting($conn,'health_window_days','7') ?: 7;
        $st=$conn->prepare("SELECT UNIX_TIMESTAMP(recorded_at) t, value v FROM nm_health_samples WHERE node_id=? AND entity=? AND metric=? AND recorded_at>=DATE_SUB(NOW(),INTERVAL ? DAY) ORDER BY recorded_at ASC");
        $st->bind_param('issi',$node,$entity,$metric,$win); $st->execute(); $r=$st->get_result();
        $pts=[]; while($x=$r->fetch_assoc()) $pts[]=['t'=>(int)$x['t'],'v'=>$x['v']===null?null:(float)$x['v']]; $st->close();
        $m=$metas[$metric]??['unit'=>'','warn'=>null,'crit'=>null];
        echo json_encode(['ok'=>true,'points'=>$pts,'unit'=>$m['unit'],'warn'=>$m['warn']??null,'crit'=>$m['crit']??null]); exit;
    }
    if ($api === 'evaluate') {
        $res=nm_health_evaluate($conn); echo json_encode(['ok'=>true]+$res); exit;
    }
    if ($api === 'oid_list') {
        $rows=[]; $r=$conn->query("SELECT o.*, n.display_name node_name FROM nm_health_optical_oids o LEFT JOIN nm_nodes n ON n.id=o.node_id ORDER BY o.node_id IS NULL DESC, o.vendor_key, o.metric");
        while($r&&$x=$r->fetch_assoc()) $rows[]=$x;
        echo json_encode(['ok'=>true,'oids'=>$rows]); exit;
    }
    if (!$canConfig) { echo json_encode(['ok'=>false,'error'=>'Configuration access required']); exit; }
    if ($api === 'link_exclude' || $api === 'link_include') {
        $node=(int)($body['node_id']??0); $entity=trim((string)($body['entity']??''));
        if(!$node || $entity===''){ echo json_encode(['ok'=>false,'error'=>'node_id and entity required']); exit; }
        if($api==='link_exclude') nm_health_exclude_add($conn,$node,$entity);
        else nm_health_exclude_remove($conn,$node,$entity);
        echo json_encode(['ok'=>true]); exit;
    }
    if ($api === 'oid_toggle') {
        $id=(int)($body['id']??0); $en=!empty($body['enabled'])?1:0;
        $st=$conn->prepare("UPDATE nm_health_optical_oids SET enabled=? WHERE id=?"); $st->bind_param('ii',$en,$id); $st->execute();
        echo json_encode(['ok'=>true]); exit;
    }
    if ($api === 'oid_save') {
        $id=(int)($body['id']??0); $vk=substr(trim((string)($body['vendor_key']??'generic')),0,40)?:'generic';
        $node=(int)($body['node_id']??0); $nodeN=$node?:null;
        $label=substr(trim((string)($body['label']??'')),0,80); $metric=substr(trim((string)($body['metric']??'rx_dbm')),0,24);
        $oid=substr(trim((string)($body['oid']??'')),0,160); $scale=(float)($body['scale']??1) ?: 1;
        if($oid===''){ echo json_encode(['ok'=>false,'error'=>'OID required']); exit; }
        if($id){ $st=$conn->prepare("UPDATE nm_health_optical_oids SET vendor_key=?,node_id=?,label=?,metric=?,oid=?,scale=? WHERE id=?");
            $st->bind_param('sissddi',$vk,$nodeN,$label,$metric,$oid,$scale,$id); }
        else { $st=$conn->prepare("INSERT INTO nm_health_optical_oids (vendor_key,node_id,label,metric,oid,scale,enabled) VALUES (?,?,?,?,?,?,1)");
            $st->bind_param('sissdd',$vk,$nodeN,$label,$metric,$oid,$scale); }
        $st->execute(); echo json_encode(['ok'=>true]); exit;
    }
    if ($api === 'oid_delete') {
        $id=(int)($body['id']??0); $conn->query("DELETE FROM nm_health_optical_oids WHERE id={$id}"); echo json_encode(['ok'=>true]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'Unknown endpoint']); exit;
}

$counts = nm_health_counts($conn);
$nodes=[]; $nr=$conn->query("SELECT id,display_name FROM nm_nodes ORDER BY display_name"); while($nr&&$x=$nr->fetch_assoc()) $nodes[]=$x;
log_user_action($conn,'view_page','health.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Predictive Health | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --opt:#9b59b6; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.2; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 40px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; } .card h3{ margin:0 0 12px; font-size:12px; color:var(--accent); text-transform:uppercase; letter-spacing:1px; }
.kpis{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:16px; } @media(max-width:760px){ .kpis{ grid-template-columns:repeat(2,1fr); } }
.kpi{ padding:14px 16px; } .kpi .n{ font-size:26px; font-weight:800; } .kpi .l{ font-size:11px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; }
.btn{ background:rgba(255,255,255,.06); border:1px solid var(--border); color:#cfd3da; padding:8px 13px; border-radius:9px; cursor:pointer; font-size:12px; display:inline-flex; gap:7px; align-items:center; }
.btn:hover{ background:rgba(255,255,255,.13); color:#fff; }
table{ width:100%; border-collapse:collapse; font-size:13px; }
th,td{ text-align:left; padding:10px; border-bottom:1px solid rgba(255,255,255,.07); vertical-align:middle; }
th{ color:#7c828c; font-size:11px; text-transform:uppercase; letter-spacing:.5px; }
.sev{ font-size:9.5px; font-weight:800; padding:3px 9px; border-radius:6px; text-transform:uppercase; }
.s-crit{ background:rgba(231,76,60,.16); color:var(--crit); } .s-warn{ background:rgba(243,156,18,.16); color:var(--warn); }
.kind{ font-size:9px; font-weight:700; padding:2px 7px; border-radius:5px; }
.k-optical{ background:rgba(155,89,182,.16); color:#c08fd6; } .k-eth{ background:rgba(13,183,237,.16); color:#0db7ed; }
.eta{ font-weight:800; } .eta.soon{ color:var(--crit); } .eta.mid{ color:var(--warn); }
.muted{ color:#7c828c; font-size:12px; }
.spark{ display:block; }
.tabs{ display:flex; gap:8px; margin-bottom:16px; } .tab{ background:rgba(255,255,255,.05); border:1px solid var(--border); color:#aaa; padding:7px 15px; border-radius:8px; cursor:pointer; font-size:12px; font-weight:600; }
.tab.active{ background:var(--accent); color:#000; border-color:transparent; }
.pane{ display:none; } .pane.active{ display:block; }
.inp,select{ background:rgba(0,0,0,.4); border:1px solid var(--border); color:#eee; border-radius:8px; padding:8px 10px; font-size:12.5px; }
.detail{ color:#cdd2d8; font-size:12.5px; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-heart-pulse"></i>Predictive Health', '', 'Proactive Degradation', 'fa-solid fa-heart-pulse',
    '<button class="refresh-btn" onclick="runEval(this)"><i class="fas fa-rotate"></i> Re-evaluate</button>'); ?>

<div class="tabs">
  <div class="tab active" data-pane="forecasts" onclick="showPane('forecasts')"><i class="fas fa-triangle-exclamation"></i> Forecasts</div>
  <div class="tab" data-pane="links" onclick="showPane('links');loadLinks()"><i class="fas fa-ethernet"></i> Monitored Links</div>
  <div class="tab" data-pane="optical" onclick="showPane('optical');loadOids()"><i class="fas fa-wave-square"></i> Optical DOM setup</div>
</div>

<div class="pane active" id="pane-forecasts">
  <div class="kpis">
    <div class="glass kpi"><div class="n" style="color:var(--crit)" id="k-crit"><?= (int)$counts['crit'] ?></div><div class="l">Critical — act now</div></div>
    <div class="glass kpi"><div class="n" style="color:var(--warn)" id="k-warn"><?= (int)$counts['warn'] ?></div><div class="l">Warning — watch</div></div>
    <div class="glass kpi"><div class="n" id="k-series">—</div><div class="l">Series monitored</div></div>
    <div class="glass kpi"><div class="n" style="font-size:14px;font-weight:600;color:#8fd" id="k-last">—</div><div class="l">Last collected</div></div>
  </div>

  <div class="glass card">
    <h3><i class="fas fa-clock-rotate-left"></i> Degradation forecasts <span class="muted" style="text-transform:none;letter-spacing:0;">— sorted by soonest failure</span></h3>
    <div id="empty" class="muted" style="display:none;padding:10px;">No degradation detected. Links/SFPs trending healthy. 🎉 <span style="display:block;margin-top:6px;">(Needs a few days of samples to forecast. The collector runs every ~5 min.)</span></div>
    <div style="overflow-x:auto;"><table id="tbl"><thead><tr>
      <th>Sev</th><th>Type</th><th>Device / Interface</th><th>Metric</th><th>Now → Critical</th><th>Trend</th><th>Fails in</th>
    </tr></thead><tbody id="tb"><tr><td colspan="7" class="muted" style="text-align:center;padding:18px;">Loading…</td></tr></tbody></table></div>
  </div>
</div>

<div class="pane" id="pane-links">
  <div class="glass card">
    <h3><i class="fas fa-ethernet"></i> Monitored links <span class="muted" style="text-transform:none;letter-spacing:0;">— every interface watched for error/CRC/discard trends (ethernet works automatically, no setup)</span></h3>
    <p class="muted" style="margin:0 0 12px;">Healthy links show <b style="color:var(--ok)">0/s</b> — that's good. A link only appears in <b>Forecasts</b> when its error rate starts trending up. This is the full coverage list.</p>
    <div style="overflow-x:auto;"><table><thead><tr>
      <th>Status</th><th>Device / Interface</th><th>Rx err/s</th><th>Tx err/s</th><th>CRC/FCS/s</th><th>Discards/s</th><th>Last</th><th></th>
    </tr></thead><tbody id="lk-tb"><tr><td colspan="8" class="muted" style="text-align:center;padding:18px;">Loading…</td></tr></tbody></table></div>
  </div>
  <div class="glass card" id="muted-card" style="display:none;">
    <h3><i class="fas fa-volume-xmark"></i> Muted links <span class="muted" style="text-transform:none;letter-spacing:0;">— excluded from health alarms (e.g. devices that report garbage counters)</span></h3>
    <div style="overflow-x:auto;"><table><thead><tr>
      <th>Device / Interface</th><th>Last reading</th><th></th>
    </tr></thead><tbody id="muted-tb"></tbody></table></div>
  </div>
</div>

<div class="pane" id="pane-optical">
  <div class="glass card">
    <h3><i class="fas fa-wave-square"></i> Optical DOM / DDM OIDs</h3>
    <p class="muted" style="margin:0 0 12px;">Ethernet error trends work out of the box. For <b>optical</b> (SFP Rx/Tx power, temperature, bias, voltage), enable the OID rows that match your gear — they're vendor-specific. Seeded templates are <b>disabled</b> until you verify and turn them on. Per-node rows override.</p>
    <?php if($canConfig): ?><div class="row" style="margin-bottom:12px;"><button class="btn" onclick="oidForm()"><i class="fas fa-plus"></i> Add OID</button></div>
    <div id="oid-form" class="glass" style="display:none;padding:12px;margin-bottom:12px;border-radius:10px;">
      <input type="hidden" id="o-id" value="0">
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px;">
        <div><label class="muted">Node</label><select class="inp" id="o-node" style="width:100%;"><option value="0">All (by vendor)</option><?php foreach($nodes as $n): ?><option value="<?= (int)$n['id'] ?>"><?= htmlspecialchars($n['display_name']) ?></option><?php endforeach; ?></select></div>
        <div><label class="muted">Vendor</label><select class="inp" id="o-vendor" style="width:100%;"><option value="generic">generic</option><option value="entity_sensor">entity_sensor</option><option value="mikrotik">mikrotik</option><option value="cisco">cisco</option></select></div>
        <div><label class="muted">Metric</label><select class="inp" id="o-metric" style="width:100%;"><option value="rx_dbm">rx_dbm</option><option value="tx_dbm">tx_dbm</option><option value="temp_c">temp_c</option><option value="bias_ma">bias_ma</option><option value="volt_v">volt_v</option></select></div>
        <div><label class="muted">Scale</label><input class="inp" id="o-scale" value="1" style="width:100%;"></div>
      </div>
      <div style="margin-top:8px;"><label class="muted">Label</label><input class="inp" id="o-label" placeholder="e.g. MikroTik SFP Rx" style="width:100%;"></div>
      <div style="margin-top:8px;"><label class="muted">OID (base — walked as a subtree)</label><input class="inp" id="o-oid" placeholder=".1.3.6.1.4.1.14988.1.1.19.1.1.7" style="width:100%;font-family:monospace;"></div>
      <div style="display:flex;gap:8px;margin-top:10px;"><button class="btn" onclick="oidSave()"><i class="fas fa-save"></i> Save &amp; enable</button><button class="btn" onclick="document.getElementById('oid-form').style.display='none'">Cancel</button></div>
    </div><?php endif; ?>
    <div style="overflow-x:auto;"><table><thead><tr><th>On</th><th>Scope</th><th>Vendor</th><th>Metric</th><th>Label</th><th>OID</th><th>Scale</th><?php if($canConfig): ?><th></th><?php endif; ?></tr></thead>
      <tbody id="oid-tb"><tr><td colspan="8" class="muted" style="text-align:center;padding:14px;">Loading…</td></tr></tbody></table></div>
  </div>
</div>

</div>
<script>
const CAN_CONFIG=<?= $canConfig?'true':'false' ?>;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function showPane(p){ document.querySelectorAll('.pane').forEach(x=>x.classList.remove('active')); document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active')); document.getElementById('pane-'+p).classList.add('active'); document.querySelector(`.tab[data-pane="${p}"]`).classList.add('active'); }
async function post(api,obj){ return fetch('health.php?api='+api,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj||{})}).then(r=>r.json()).catch(()=>({ok:false})); }

function etaCls(d){ if(d==null) return ''; if(d<=14) return 'soon'; if(d<=45) return 'mid'; return ''; }
function fmtEta(d){ if(d==null) return '<span class="muted">trend only</span>'; if(d<1) return '<span class="eta soon">&lt;1 day</span>'; return `<span class="eta ${etaCls(d)}">~${d} days</span>`; }
async function sparkline(td,p){
    const r=await fetch(`health.php?api=series&node=${p.node_id}&entity=${encodeURIComponent(p.entity)}&metric=${encodeURIComponent(p.metric)}`).then(r=>r.json()).catch(()=>null);
    if(!r||!r.ok||!r.points.length){ td.textContent='—'; return; }
    const vs=r.points.map(x=>x.v).filter(v=>v!=null); if(!vs.length){td.textContent='—';return;}
    const w=120,h=28,mn=Math.min(...vs),mx=Math.max(...vs),rg=(mx-mn)||1;
    const pts=r.points.filter(x=>x.v!=null).map((x,i,a)=>`${(i/(a.length-1||1))*w},${h-((x.v-mn)/rg)*(h-4)-2}`).join(' ');
    const col=p.severity==='crit'?'#e74c3c':(p.severity==='warn'?'#f39c12':'#4da3ff');
    td.innerHTML=`<svg class="spark" width="${w}" height="${h}"><polyline points="${pts}" fill="none" stroke="${col}" stroke-width="1.6"/></svg>`;
}
async function load(){
    const r=await fetch('health.php?api=data').then(r=>r.json()).catch(()=>null);
    if(!r||!r.ok) return;
    document.getElementById('k-crit').textContent=r.counts.crit||0;
    document.getElementById('k-warn').textContent=r.counts.warn||0;
    document.getElementById('k-last').textContent=r.last_collect?(window.nmLocal?nmLocal(r.last_collect,true):r.last_collect):'never';
    const tb=document.getElementById('tb'), empty=document.getElementById('empty');
    if(!r.predictions.length){ document.getElementById('tbl').style.display='none'; empty.style.display='block'; document.getElementById('k-series').textContent='0'; return; }
    document.getElementById('tbl').style.display=''; empty.style.display='none';
    document.getElementById('k-series').textContent=r.predictions.length;
    tb.innerHTML='';
    r.predictions.forEach(p=>{
        const tr=document.createElement('tr');
        const arrow = p.slope>0?'▲':(p.slope<0?'▼':'·');
        tr.innerHTML=`<td><span class="sev s-${p.severity}">${p.severity}</span></td>
            <td><span class="kind k-${p.kind}">${p.kind==='optical'?'OPTICAL':'ETHERNET'}</span></td>
            <td><b>${esc(p.node)}</b><br><span class="muted">${esc(p.entity)}</span></td>
            <td>${esc(p.metric_label)}</td>
            <td>${p.current==null?'—':p.current} → <b>${p.threshold}</b> <span class="muted">${esc(p.unit)}</span></td>
            <td class="spk"></td>
            <td>${fmtEta(p.eta)}<br><span class="muted">${arrow} ${p.slope>=0?'+':''}${p.slope}/day</span></td>`;
        tb.appendChild(tr);
        sparkline(tr.querySelector('.spk'),p);
    });
}
async function runEval(btn){ if(btn)btn.disabled=true; const r=await post('evaluate',{}); if(btn)btn.disabled=false; load(); }

function cellRate(v){ if(v==null) return '<span class="muted">—</span>'; if(v<=0) return '<span style="color:var(--ok)">0/s</span>'; const c=v>=5?'var(--crit)':(v>=0.5?'var(--warn)':'#cdd2d8'); return `<span style="color:${c};font-weight:${v>=0.5?'700':'400'}">${v}/s</span>`; }
async function loadLinks(){
    const r=await fetch('health.php?api=links').then(r=>r.json()).catch(()=>null); const tb=document.getElementById('lk-tb');
    if(!r||!r.ok){ tb.innerHTML='<tr><td colspan="8" class="muted" style="text-align:center;">Error.</td></tr>'; return; }
    if(!r.links.length){ tb.innerHTML='<tr><td colspan="8" class="muted" style="text-align:center;padding:18px;">No samples yet — the collector runs every ~5 min. Check back shortly.</td></tr>'; return; }
    const cc=!!r.can_config;
    tb.innerHTML=r.links.map(l=>{
        const m=l.metrics||{};
        const dot=l.severity==='crit'?'var(--crit)':(l.severity==='warn'?'var(--warn)':'var(--ok)');
        const lbl=l.severity==='ok'?'Healthy':(l.severity==='warn'?'Watch':'Degrading');
        const ekey=`${l.node_id}|${encodeURIComponent(l.entity)}`;
        const muteBtn=cc?`<td style="text-align:right;"><button class="btn btn-sm" title="Mute this link — stop it from alarming (use for devices that report garbage counters)" style="padding:3px 9px;font-size:11px;border-color:#555;color:#aaa;" onclick="muteLink(${l.node_id},'${esc(l.entity).replace(/'/g,"\\'")}')"><i class="fas fa-volume-xmark"></i> Mute</button></td>`:'<td></td>';
        return `<tr>
          <td><span style="color:${dot};font-weight:700;">● ${lbl}</span></td>
          <td><b>${esc(l.node)}</b><br><span class="muted">${esc(l.entity)}</span></td>
          <td>${cellRate(m.in_err_rate)}</td><td>${cellRate(m.out_err_rate)}</td>
          <td>${cellRate(m.fcs_rate)}</td><td>${cellRate(m.discard_rate)}</td>
          <td class="muted" style="font-size:11px;">${esc(window.nmLocal?nmLocal(l.at,true):(l.at||''))}</td>
          ${muteBtn}</tr>`;
    }).join('');
    // muted links section
    const mcard=document.getElementById('muted-card'), mtb=document.getElementById('muted-tb');
    const muted=r.muted||[];
    if(!muted.length){ mcard.style.display='none'; }
    else {
        mcard.style.display='block';
        mtb.innerHTML=muted.map(l=>{
            const m=l.metrics||{};
            const reads=Object.keys(m).map(k=>`${k.replace('_rate','').replace('_',' ')}: ${m[k]}/s`).join(' · ')||'—';
            const restore=cc?`<button class="btn btn-sm" style="padding:3px 9px;font-size:11px;" onclick="unmuteLink(${l.node_id},'${esc(l.entity).replace(/'/g,"\\'")}')"><i class="fas fa-volume-high"></i> Restore</button>`:'';
            return `<tr><td><b>${esc(l.node)}</b><br><span class="muted">${esc(l.entity)}</span></td>
              <td class="muted" style="font-size:11px;">${esc(reads)}</td>
              <td style="text-align:right;">${restore}</td></tr>`;
        }).join('');
    }
}
async function muteLink(node,entity){
    if(!confirm('Mute this link?\n\nIt will be excluded from Predictive Health alarms and the Forecasts list. Use this for interfaces that report bogus counter values.')) return;
    const r=await post('link_exclude',{node_id:node,entity:entity});
    if(r&&r.ok){ loadLinks(); load(); } else alert((r&&r.error)||'Failed — needs Configuration access.');
}
async function unmuteLink(node,entity){
    const r=await post('link_include',{node_id:node,entity:entity});
    if(r&&r.ok){ loadLinks(); load(); } else alert((r&&r.error)||'Failed.');
}
async function loadOids(){
    const r=await fetch('health.php?api=oid_list').then(r=>r.json()).catch(()=>null); const tb=document.getElementById('oid-tb');
    if(!r||!r.ok){ tb.innerHTML='<tr><td colspan="8" class="muted">Error.</td></tr>'; return; }
    tb.innerHTML = r.oids.map(o=>`<tr>
        <td><input type="checkbox" ${o.enabled==1?'checked':''} ${CAN_CONFIG?'':'disabled'} onchange="oidToggle(${o.id},this.checked)"></td>
        <td>${o.node_id?esc(o.node_name||('node '+o.node_id)):'<span class="muted">All</span>'}</td>
        <td>${esc(o.vendor_key)}</td><td>${esc(o.metric)}</td><td>${esc(o.label)}</td>
        <td class="muted" style="font-family:monospace;font-size:11px;">${esc(o.oid)}</td><td>${o.scale}</td>
        ${CAN_CONFIG?`<td style="white-space:nowrap;"><button class="btn" onclick='oidForm(${JSON.stringify(o)})'><i class="fas fa-pen"></i></button> <button class="btn" onclick="oidDel(${o.id})"><i class="fas fa-trash"></i></button></td>`:''}
    </tr>`).join('') || '<tr><td colspan="8" class="muted" style="text-align:center;">No OIDs.</td></tr>';
}
function oidForm(o){ o=o||{}; document.getElementById('oid-form').style.display='block';
    document.getElementById('o-id').value=o.id||0; document.getElementById('o-node').value=o.node_id||0;
    document.getElementById('o-vendor').value=o.vendor_key||'generic'; document.getElementById('o-metric').value=o.metric||'rx_dbm';
    document.getElementById('o-scale').value=o.scale||1; document.getElementById('o-label').value=o.label||''; document.getElementById('o-oid').value=o.oid||''; }
async function oidSave(){ const b={id:+document.getElementById('o-id').value,node_id:+document.getElementById('o-node').value,vendor_key:document.getElementById('o-vendor').value,metric:document.getElementById('o-metric').value,scale:document.getElementById('o-scale').value,label:document.getElementById('o-label').value,oid:document.getElementById('o-oid').value};
    const r=await post('oid_save',b); if(r.ok){ document.getElementById('oid-form').style.display='none'; loadOids(); } else alert(r.error||'Failed'); }
async function oidToggle(id,en){ await post('oid_toggle',{id,enabled:en}); }
async function oidDel(id){ if(!confirm('Delete this OID?'))return; await post('oid_delete',{id}); loadOids(); }
load(); setInterval(load, 60000);
</script>
</body></html>
