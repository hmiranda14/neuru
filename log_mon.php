<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — Intelligent Log Monitoring. Per-device log viewer backed by Graylog,
// pulled live server-side (token never leaves the server). Foundation for the AI
// log-RCA copilot (fires the n8n `log-rca` webhook when configured).
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');

include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_graylog.php');
require_once('nm_n8n.php');
include('logger.php');

$api = $_GET['api'] ?? '';

// Active log source: NEURU native syslog by default; 'graylog' only if chosen.
function nm_log_source($conn): string {
    $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='log_source' LIMIT 1");
    $v = $r && ($x = $r->fetch_row()) ? $x[0] : 'syslog';
    return $v === 'graylog' ? 'graylog' : 'syslog';
}

if (!checkAccess($conn, 'log_mon')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'err'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=log_mon'); exit;
}

// ── API endpoints ─────────────────────────────────────────────────────────────
if (function_exists('session_write_close')) @session_write_close(); // free session lock before slow SSH/n8n I/O (prevents whole-portal freeze)
if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    $node_id = (int)($_GET['node'] ?? 0);
    $node = null;
    if ($node_id) {
        $r = $conn->query("SELECT id, display_name, ip_address, COALESCE(graylog_source,'') graylog_source
                           FROM nm_nodes WHERE id={$node_id} LIMIT 1");
        $node = $r ? $r->fetch_assoc() : null;
    }

    if ($api === 'logs') {
        if (!$node) { echo json_encode(['ok'=>false,'err'=>'Unknown device']); exit; }
        $rangeMap = ['15m'=>900,'1h'=>3600,'6h'=>21600,'24h'=>86400,'7d'=>604800];
        $range = $rangeMap[$_GET['range'] ?? '1h'] ?? 3600;
        $q   = trim($_GET['q'] ?? '');
        $lvl = $_GET['level'] ?? 'all';
        $lvlMap = ['err'=>3, 'warn'=>4, 'info'=>6];
        $source = nm_log_source($conn);   // 'syslog' (default) | 'graylog'

        // ── Optional: Graylog ──────────────────────────────────────────────────
        if ($source === 'graylog') {
            $cfg = nm_graylog_get($conn);
            if (empty($cfg['enabled']) || $cfg['url']==='' || $cfg['token']==='') {
                echo json_encode(['ok'=>false,'err'=>'Graylog is selected but not configured/enabled','need_config'=>true]); exit;
            }
            $query = nm_graylog_source_query($node);
            if ($q !== '') $query .= ' AND message:' . json_encode($q);
            if (isset($lvlMap[$lvl])) $query .= ' AND level:<=' . $lvlMap[$lvl];
            [$code, $res, $err] = nm_graylog_search($cfg, $query, $range, 200);
            if ($err) { echo json_encode(['ok'=>false,'err'=>$err,'code'=>$code,'query'=>$query]); exit; }
            echo json_encode(['ok'=>true,'messages'=>$res['messages'],'total'=>$res['total'],'source'=>'graylog','query'=>$query]);
            exit;
        }

        // ── Default: NEURU native syslog (nm_syslog) ───────────────────────────
        if ($conn->query("SHOW TABLES LIKE 'nm_syslog'")->num_rows === 0) {
            echo json_encode(['ok'=>true,'messages'=>[],'total'=>0,'source'=>'syslog','no_data'=>'syslog']); exit;
        }
        $ip = (string)$node['ip_address'];
        $srcId = trim((string)$node['graylog_source']);     // reused as the optional hostname match
        $name = (string)$node['display_name'];
        $where = "received_at >= (UTC_TIMESTAMP() - INTERVAL ? SECOND) AND (host_ip=? OR hostname=? OR hostname=?)";
        $types = 'isss'; $args = [$range, $ip, ($srcId !== '' ? $srcId : $name), $name];
        if (isset($lvlMap[$lvl])) { $where .= " AND severity IS NOT NULL AND severity <= ?"; $types.='i'; $args[]=$lvlMap[$lvl]; }
        if ($q !== '') { $where .= " AND message LIKE ?"; $types.='s'; $args[]='%'.$q.'%'; }
        // total
        $ct = $conn->prepare("SELECT COUNT(*) c FROM nm_syslog WHERE $where");
        $ct->bind_param($types, ...$args); $ct->execute(); $total = (int)$ct->get_result()->fetch_assoc()['c'];
        // page
        $sql = "SELECT DATE_FORMAT(received_at,'%Y-%m-%dT%H:%i:%S') timestamp, severity `level`,
                       COALESCE(NULLIF(hostname,''),host_ip) source,
                       CASE WHEN tag<>'' THEN CONCAT(tag,': ',message) ELSE message END message
                FROM nm_syslog WHERE $where ORDER BY received_at DESC LIMIT 300";
        $st = $conn->prepare($sql); $st->bind_param($types, ...$args); $st->execute();
        $msgs = $st->get_result()->fetch_all(MYSQLI_ASSOC);
        foreach ($msgs as &$m) $m['level'] = ($m['level'] === null ? null : (int)$m['level']);
        echo json_encode(['ok'=>true,'messages'=>$msgs,'total'=>$total,'source'=>'syslog']);
        exit;
    }

    if ($api === 'set_source') {
        if (!$node) { echo json_encode(['ok'=>false,'err'=>'Unknown device']); exit; }
        $b = json_decode(file_get_contents('php://input'), true) ?? [];
        $src = substr(trim($b['source'] ?? ''), 0, 255);
        $st = $conn->prepare("UPDATE nm_nodes SET graylog_source=? WHERE id=?");
        $st->bind_param('si', $src, $node_id); $st->execute();
        echo json_encode(['ok'=>true]);
        exit;
    }

    // Fire the AI log-RCA n8n flow for this device (foundation hook).
    if ($api === 'ai_rca') {
        if (!$node) { echo json_encode(['ok'=>false,'err'=>'Unknown device']); exit; }
        $cfg = nm_graylog_get($conn);
        $logs = [];
        if (!empty($cfg['enabled'])) {
            [, $res, ] = nm_graylog_search($cfg, nm_graylog_source_query($node), 3600, 80);
            $logs = $res['messages'] ?? [];
        }
        [$hcode, $resp, $herr] = nm_n8n_call($conn, 'log-rca', [
            'event'   => 'log_rca_request',
            'node'    => ['id'=>$node['id'],'name'=>$node['display_name'],'ip'=>$node['ip_address']],
            'logs'    => $logs,
        ]);
        if ($herr) { echo json_encode(['ok'=>false,'err'=>$herr,'hint'=>'Add an enabled n8n webhook with slug "log-rca" in Config → Integrations & AI']); exit; }
        echo json_encode(['ok'=>true,'result'=>$resp]);
        exit;
    }

    echo json_encode(['ok'=>false,'err'=>'Unknown endpoint']);
    exit;
}

// ── Page load ─────────────────────────────────────────────────────────────────
$gl = nm_graylog_get($conn);
$active_src = nm_log_source($conn);   // 'syslog' (default) | 'graylog'
$nodes = $conn->query("SELECT id, display_name, ip_address, os_icon, COALESCE(graylog_source,'') graylog_source
                       FROM nm_nodes ORDER BY display_name")->fetch_all(MYSQLI_ASSOC);
$sel = (int)($_GET['node'] ?? ($nodes[0]['id'] ?? 0));
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';

include('header.php');
log_user_action($conn, 'view_page', 'log_mon.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Log Monitoring | SG-PR Console</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.07); --border:rgba(255,255,255,.12); --accent:#4da3ff; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#fff; overflow-x:hidden; }
#bg-video{ position:fixed; top:0; left:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.3; }
.page-wrap{ display:flex; min-height:100vh; }
.sidebar{ width:250px; flex-shrink:0; background:rgba(0,0,0,.6); border-right:1px solid var(--border); padding:14px 0; overflow-y:auto; }
.main-area{ flex:1; padding:18px 20px; overflow-x:hidden; min-width:0; }
.sb-title{ font-size:10px; font-weight:700; letter-spacing:2px; color:#555; text-transform:uppercase; padding:0 16px 8px; }
.node-item{ padding:9px 16px; cursor:pointer; border-left:3px solid transparent; display:flex; align-items:center; gap:8px; }
.node-item:hover{ background:rgba(255,255,255,.05); border-left-color:var(--accent); }
.node-item.active{ background:rgba(77,163,255,.12); border-left-color:var(--accent); }
.node-item .nn{ font-size:13px; font-weight:600; } .node-item .ni{ font-size:11px; color:#555; }
.lh-head{ display:flex; align-items:center; gap:14px; flex-wrap:wrap; margin-bottom:14px; }
.lh-title{ font-size:22px; font-weight:700; } .lh-title span{ font-weight:300; color:#aaa; font-size:15px; display:block; }
.ctrl-bar{ display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:14px; }
.ctrl-bar input,.ctrl-bar select{ background:rgba(0,0,0,.4); border:1px solid var(--border); color:#ddd; border-radius:7px; padding:7px 10px; font-size:12px; }
.ctrl-bar input[type=text]{ flex:1; min-width:180px; }
.btn{ background:rgba(77,163,255,.18); border:1px solid var(--accent); color:var(--accent); padding:7px 12px; border-radius:8px; cursor:pointer; font-size:12px; display:inline-flex; gap:7px; align-items:center; text-decoration:none; }
.btn:hover{ background:var(--accent); color:#000; }
.btn.ai{ background:rgba(155,89,182,.18); border-color:#9b59b6; color:#c08fd6; }
.btn.ai:hover{ background:#9b59b6; color:#fff; }
.glass-card{ background:var(--glass); backdrop-filter:blur(18px); border:1px solid var(--border); border-radius:14px; padding:0; overflow:hidden; }
.range-btn{ background:rgba(255,255,255,.05); border:1px solid var(--border); color:#aaa; padding:6px 11px; border-radius:6px; cursor:pointer; font-size:12px; font-weight:600; }
.range-btn.active,.range-btn:hover{ background:rgba(77,163,255,.22); color:var(--accent); border-color:var(--accent); }
.log-table{ width:100%; border-collapse:collapse; font-family:'Consolas','Monaco',monospace; font-size:12px; }
.log-table th{ position:sticky; top:0; background:#0c0f14; color:#666; font-size:9.5px; text-transform:uppercase; letter-spacing:1px; padding:8px 10px; text-align:left; border-bottom:1px solid var(--border); }
.log-table td{ padding:6px 10px; border-bottom:1px solid rgba(255,255,255,.04); vertical-align:top; }
.log-table tr:hover td{ background:rgba(255,255,255,.03); }
.log-msg{ color:#cfd3da; white-space:pre-wrap; word-break:break-word; }
.lvl{ font-weight:700; font-size:10px; padding:2px 7px; border-radius:4px; white-space:nowrap; }
.lvl-0,.lvl-1,.lvl-2{ background:rgba(231,76,60,.18); color:#ff6b5e; }     /* emerg/alert/crit */
.lvl-3{ background:rgba(231,76,60,.14); color:#e74c3c; }                    /* error */
.lvl-4{ background:rgba(243,156,18,.16); color:#f39c12; }                   /* warning */
.lvl-5,.lvl-6{ background:rgba(77,163,255,.14); color:#4da3ff; }            /* notice/info */
.lvl-7{ background:rgba(255,255,255,.06); color:#888; }                     /* debug */
.lvl-x{ background:rgba(255,255,255,.06); color:#888; }
.ts{ color:#5a6472; white-space:nowrap; } .src{ color:#7fae6f; white-space:nowrap; }
.empty{ text-align:center; color:#667; padding:50px 20px; }
.empty i{ font-size:34px; color:#333; display:block; margin-bottom:12px; }
.src-edit{ display:flex; gap:6px; align-items:center; font-size:11px; color:#778; }
.src-edit input{ background:rgba(0,0,0,.4); border:1px solid var(--border); color:#bb9; border-radius:6px; padding:4px 8px; font-size:11px; font-family:monospace; min-width:200px; }
#ai-panel{ display:none; background:rgba(155,89,182,.08); border:1px solid rgba(155,89,182,.3); border-radius:12px; padding:14px 16px; margin-bottom:14px; }
.spinner{ width:13px; height:13px; border:2px solid rgba(255,255,255,.2); border-top-color:var(--accent); border-radius:50%; display:inline-block; animation:spin .7s linear infinite; }
@keyframes spin{ to{ transform:rotate(360deg);} }
@media(max-width:900px){ .page-wrap{ flex-direction:column;} .sidebar{ width:100%; border-right:none; border-bottom:1px solid var(--border);} }
</style>
</head>
<body>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>

<div class="page-wrap">
<nav class="sidebar">
    <div class="sb-title">Devices</div>
    <?php foreach ($nodes as $n): ?>
    <div class="node-item <?= (int)$n['id']===$sel?'active':'' ?>" onclick="selectNode(<?= (int)$n['id'] ?>)">
        <i class="fas fa-<?= $n['os_icon']==='mikrotik'?'network-wired':($n['os_icon']==='cisco'?'server':($n['os_icon']==='ping'?'satellite-dish':'desktop')) ?>" style="color:var(--accent);font-size:11px;"></i>
        <div><div class="nn"><?= htmlspecialchars($n['display_name']) ?></div><div class="ni"><?= htmlspecialchars($n['ip_address']) ?></div></div>
    </div>
    <?php endforeach; ?>
    <?php if (empty($nodes)): ?><div class="empty" style="padding:20px;"><i class="fas fa-server"></i>No devices.</div><?php endif; ?>
</nav>

<div class="main-area">
    <div class="lh-head">
        <div class="lh-title"><span><i class="fas fa-file-lines" style="color:var(--accent)"></i> Log Monitoring</span>
            <span id="dev-name" style="font-size:18px;font-weight:700;color:#fff;">—</span></div>
        <div style="margin-left:auto;display:flex;gap:8px;align-items:center;">
            <span id="gl-badge" style="font-size:11px;color:#666;"></span>
            <button class="btn ai" onclick="aiRca()" title="Ask AI to analyse these logs (fires the n8n log-rca flow)"><i class="fas fa-wand-magic-sparkles"></i> AI Analyze</button>
        </div>
    </div>

    <?php if ($active_src === 'graylog' && (empty($gl['enabled']) || $gl['url']==='')): ?>
    <div class="glass-card" style="padding:30px;text-align:center;margin-bottom:14px;">
        <div class="empty"><i class="fas fa-plug-circle-xmark"></i>
            <div style="font-size:15px;color:#aaa;">Graylog is the selected source but isn't connected.</div>
            <div style="font-size:12px;color:#666;margin-top:6px;">Configure it (or switch back to the NEURU syslog server) in
                <a href="net_mon_config.php?tab=integrations" style="color:var(--accent);">Config → Integrations &amp; AI</a>.</div>
        </div>
    </div>
    <?php endif; ?>

    <div id="ai-panel"></div>

    <div class="ctrl-bar">
        <input type="text" id="q" placeholder="Search message text…" onkeydown="if(event.key==='Enter')loadLogs()">
        <select id="level">
            <option value="all">All levels</option>
            <option value="err">Error and worse (≤3)</option>
            <option value="warn">Warning and worse (≤4)</option>
            <option value="info">Info and worse (≤6)</option>
        </select>
        <?php foreach (['15m'=>'15m','1h'=>'1H','6h'=>'6H','24h'=>'24H','7d'=>'7D'] as $v=>$l): ?>
        <button class="range-btn <?= $v==='1h'?'active':'' ?>" data-range="<?= $v ?>" onclick="setRange('<?= $v ?>')"><?= $l ?></button>
        <?php endforeach; ?>
        <button class="btn" onclick="loadLogs()"><i class="fas fa-rotate"></i> Refresh</button>
        <label style="font-size:11px;color:#888;display:flex;gap:5px;align-items:center;"><input type="checkbox" id="auto" onchange="toggleAuto()"> Auto</label>
    </div>

    <div class="src-edit" style="margin-bottom:12px;">
        <i class="fas fa-filter"></i> Source match <span style="color:#556;font-size:11px;">(hostname; blank = match by IP/name)</span>:
        <input type="text" id="src" placeholder="(auto: IP / name)">
        <button class="btn" style="padding:4px 9px;" onclick="saveSource()"><i class="fas fa-floppy-disk"></i> Save</button>
        <span id="src-msg" style="color:#2ecc71;"></span>
        <span id="result-count" style="margin-left:auto;color:#556;"></span>
    </div>

    <!-- Selection action bar (shows when ≥1 log line is checked) -->
    <div id="sel-bar" style="display:none;align-items:center;gap:12px;margin-bottom:10px;padding:9px 14px;
         background:rgba(155,89,255,.12);border:1px solid rgba(155,89,255,.4);border-radius:10px;">
        <span style="color:#b388ff;font-weight:700;"><i class="fas fa-list-check"></i> <span id="sel-count">0</span> line(s) selected</span>
        <button class="btn" style="background:rgba(155,89,255,.22);border-color:rgba(155,89,255,.55);color:#d3b8ff;"
                onclick="troubleshootSel()" title="Open the Solution Center with this device preselected and these log lines dropped into the problem box">
            <i class="fas fa-wand-magic-sparkles"></i> Troubleshoot in Solution Center
        </button>
        <button class="btn" style="padding:4px 9px;" onclick="clearSel()"><i class="fas fa-xmark"></i> Clear</button>
    </div>

    <div class="glass-card">
        <div style="max-height:calc(100vh - 280px);overflow-y:auto;">
            <table class="log-table">
                <thead><tr>
                    <th style="width:34px;text-align:center;"><input type="checkbox" id="sel-all" onchange="selAll(this)" title="Select all"></th>
                    <th style="width:160px;">Time</th><th style="width:70px;">Level</th><th style="width:150px;">Source</th><th>Message</th>
                </tr></thead>
                <tbody id="log-body"><tr><td colspan="5" class="empty"><i class="fas fa-hourglass-half"></i>Select a device.</td></tr></tbody>
            </table>
        </div>
    </div>
</div>
</div>

<script>
const NODES = <?= json_encode(array_map(fn($n)=>['id'=>(int)$n['id'],'name'=>$n['display_name'],'ip'=>$n['ip_address'],'source'=>$n['graylog_source']], $nodes)) ?>;
<?php
  // node → Command Center deep-link (Windows/Linux) so the log header name is clickable, preselected
  $CC = []; $winMap = []; $lxMap = [];
  try { $r=$conn->query("SELECT node_id, MIN(id) hid FROM nm_win_hosts WHERE node_id IS NOT NULL GROUP BY node_id"); while($r&&$x=$r->fetch_assoc()) $winMap[(int)$x['node_id']]=(int)$x['hid']; } catch (\Throwable $e) {}
  try { $r=$conn->query("SELECT node_id, MIN(id) hid FROM nm_lx_hosts WHERE node_id IS NOT NULL GROUP BY node_id"); while($r&&$x=$r->fetch_assoc()) $lxMap[(int)$x['node_id']]=(int)$x['hid']; } catch (\Throwable $e) {}
  foreach ($nodes as $n) { $id=(int)$n['id'];
    if (isset($winMap[$id]))     $CC[$id]=['url'=>'win_screen.php?host='.$winMap[$id],   'label'=>'Windows Command Center'];
    elseif (isset($lxMap[$id]))  $CC[$id]=['url'=>'linux_screen.php?host='.$lxMap[$id], 'label'=>'Linux Command Center'];
  }
?>
const CC = <?= json_encode($CC) ?>;
const GL_ON = <?= (!empty($gl['enabled']) && $gl['url']!=='') ? 'true':'false' ?>;
const LOG_SOURCE = <?= json_encode($active_src) ?>;   // 'syslog' (default) | 'graylog'
let nodeId = <?= $sel ?>, range = '1h', autoTimer = null;
let LAST_MSGS = [];   // the currently-rendered log rows (for checkbox selection)

function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
const LVLNAME = {0:'EMERG',1:'ALERT',2:'CRIT',3:'ERROR',4:'WARN',5:'NOTICE',6:'INFO',7:'DEBUG'};

function selectNode(id){
    nodeId=id;
    document.querySelectorAll('.node-item').forEach(e=>e.classList.remove('active'));
    const el=document.querySelector(`[onclick="selectNode(${id})"]`); if(el)el.classList.add('active');
    const n=NODES.find(x=>x.id===id);
    const dn=document.getElementById('dev-name'), cc=CC[id];
    if(n&&cc){ dn.innerHTML='<a href="'+cc.url+'" style="color:#fff;text-decoration:none;border-bottom:1px dashed #4da3ff" title="Open '+cc.label+' (this device preselected)">'+n.name.replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))+' <i class="fas fa-arrow-up-right-from-square" style="font-size:12px;color:#4da3ff"></i></a>'; }
    else dn.textContent = n?n.name:'—';
    document.getElementById('src').value = n?(n.source||''):'';
    document.getElementById('src').placeholder = n?('(auto: '+n.ip+' / '+n.name+')'):'';
    document.getElementById('ai-panel').style.display='none';
    history.replaceState(null,'','log_mon.php?node='+id);
    loadLogs();
}
function setRange(r){ range=r; document.querySelectorAll('.range-btn').forEach(b=>b.classList.toggle('active',b.dataset.range===r)); loadLogs(); }

async function loadLogs(){
    const tb=document.getElementById('log-body');
    clearSel();
    if(LOG_SOURCE==='graylog' && !GL_ON){ tb.innerHTML='<tr><td colspan="5" class="empty"><i class="fas fa-plug-circle-xmark"></i>Graylog selected but not connected.</td></tr>'; return; }
    if(!nodeId){ return; }
    tb.innerHTML='<tr><td colspan="5" class="empty"><span class="spinner"></span> Loading logs…</td></tr>';
    const q=encodeURIComponent(document.getElementById('q').value.trim());
    const lvl=document.getElementById('level').value;
    try{
        const r=await fetch(`log_mon.php?api=logs&node=${nodeId}&range=${range}&q=${q}&level=${lvl}&_=${Date.now()}`).then(r=>r.json());
        if(!r.ok){
            tb.innerHTML=`<tr><td colspan="5" class="empty"><i class="fas fa-triangle-exclamation"></i>${esc(r.err||'Error')}${r.need_config?'<br><a href="net_mon_config.php?tab=integrations" style="color:var(--accent)">Configure Graylog</a>':''}</td></tr>`;
            document.getElementById('result-count').textContent=''; return;
        }
        const M=r.messages||[]; LAST_MSGS=M;
        document.getElementById('result-count').textContent = `${r.total} match${r.total===1?'':'es'}`;
        document.getElementById('gl-badge').innerHTML = (r.source==='graylog')
            ? '<i class="fas fa-circle" style="color:#2ecc71;font-size:7px;"></i> Graylog live'
            : '<i class="fas fa-circle" style="color:#0db7ed;font-size:7px;"></i> NEURU syslog';
        if(!M.length){ tb.innerHTML='<tr><td colspan="5" class="empty"><i class="fas fa-inbox"></i>No log entries for this device in this window.</td></tr>'; return; }
        tb.innerHTML=M.map((m,i)=>{
            const lv=(m.level==null)?'x':m.level;
            const lname=(m.level==null)?'—':(LVLNAME[m.level]||m.level);
            const ts=(m.timestamp||'').replace('T',' ').replace(/\.\d+Z?$/,'').replace('Z','');
            return `<tr>
                <td style="text-align:center;"><input type="checkbox" class="logsel" data-idx="${i}" onchange="updSel()"></td>
                <td class="ts">${esc(ts)}</td>
                <td><span class="lvl lvl-${lv}">${esc(lname)}</span></td>
                <td class="src">${esc(m.source||'')}</td>
                <td class="log-msg">${esc(m.message||'')}</td></tr>`;
        }).join('');
    }catch(e){ tb.innerHTML='<tr><td colspan="5" class="empty"><i class="fas fa-triangle-exclamation"></i>Request failed.</td></tr>'; }
}

// ─── Multi-line selection → Solution Center ──────────────────────────────────
function updSel(){
    const checked=document.querySelectorAll('.logsel:checked');
    const bar=document.getElementById('sel-bar');
    document.getElementById('sel-count').textContent=checked.length;
    bar.style.display = checked.length ? 'flex' : 'none';
    const all=document.querySelectorAll('.logsel');
    const sa=document.getElementById('sel-all');
    if(sa) sa.checked = all.length>0 && checked.length===all.length;
}
function selAll(cb){ document.querySelectorAll('.logsel').forEach(c=>c.checked=cb.checked); updSel(); }
function clearSel(){ document.querySelectorAll('.logsel,#sel-all').forEach(c=>c.checked=false); const b=document.getElementById('sel-bar'); if(b) b.style.display='none'; const sc=document.getElementById('sel-count'); if(sc) sc.textContent='0'; }

function troubleshootSel(){
    const idx=[...document.querySelectorAll('.logsel:checked')].map(c=>+c.dataset.idx);
    if(!idx.length) return;
    const n=NODES.find(x=>x.id===nodeId);
    const lines=idx.map(i=>{
        const m=LAST_MSGS[i]; if(!m) return '';
        const lname=(m.level==null)?'':(LVLNAME[m.level]||m.level);
        const ts=(m.timestamp||'').replace('T',' ').replace(/\.\d+Z?$/,'').replace('Z','');
        return `[${ts}] ${lname?lname+' ':''}${m.source?m.source+': ':''}${m.message||''}`.trim();
    }).filter(Boolean);
    let text = `Investigate these ${lines.length} log line(s) from ${n?n.name:('node '+nodeId)}${n&&n.ip?(' ('+n.ip+')'):''}:\n\n` + lines.join('\n');
    // Keep the deep-link URL within safe limits (Apache ~8KB). Truncate gracefully if huge.
    const MAX=6000;
    if(text.length>MAX){ text = text.slice(0,MAX) + `\n… (${lines.length} lines truncated for length)`; }
    const url='router_commander.php?node='+encodeURIComponent(nodeId)+'&problem='+encodeURIComponent(text);
    location.href=url;
}

async function saveSource(){
    const src=document.getElementById('src').value.trim();
    await fetch('log_mon.php?api=set_source&node='+nodeId,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:src})});
    const n=NODES.find(x=>x.id===nodeId); if(n)n.source=src;
    const m=document.getElementById('src-msg'); m.textContent='Saved'; setTimeout(()=>m.textContent='',2000);
    loadLogs();
}
function toggleAuto(){ if(document.getElementById('auto').checked){ autoTimer=setInterval(loadLogs,15000); } else { clearInterval(autoTimer); autoTimer=null; } }

async function aiRca(){
    const p=document.getElementById('ai-panel'); p.style.display='block';
    p.innerHTML='<span class="spinner"></span> Asking the AI to analyse recent logs…';
    try{
        const r=await fetch('log_mon.php?api=ai_rca&node='+nodeId).then(r=>r.json());
        if(!r.ok){ p.innerHTML=`<b style="color:#c08fd6;"><i class="fas fa-robot"></i> AI Analyze</b><br><span style="color:#e74c3c;">${esc(r.err||'failed')}</span>${r.hint?`<br><span style="color:#888;font-size:12px;">${esc(r.hint)}</span>`:''}`; return; }
        let out=r.result;
        if(out && typeof out==='object') out = out.summary || out.message || out.text || JSON.stringify(out,null,2);
        p.innerHTML=`<b style="color:#c08fd6;"><i class="fas fa-wand-magic-sparkles"></i> AI Root-Cause Analysis</b>
            <div style="margin-top:8px;white-space:pre-wrap;color:#dcd;font-size:13px;line-height:1.5;">${esc(out)}</div>`;
    }catch(e){ p.innerHTML='<span style="color:#e74c3c;">AI request failed.</span>'; }
}

selectNode(nodeId || (NODES[0]&&NODES[0].id));
</script>
</body>
</html>
