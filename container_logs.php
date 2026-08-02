<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — Containers: log viewer. Reads container_logs (pushed by the n8n log
// collector via nm_containers_api.php?ep=logs). Filter + incremental tail.
// RBAC: 'containers'.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'containers')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=containers'); exit;
}

if ($api === 'data') {
    header('Content-Type: application/json; charset=utf-8');
    $where = [];
    if (!empty($_GET['container'])) $where[] = "container_id='".$conn->real_escape_string($_GET['container'])."'";
    if (in_array($_GET['stream'] ?? '', ['stdout','stderr'], true)) $where[] = "stream='".$conn->real_escape_string($_GET['stream'])."'";
    if (!empty($_GET['q'])) { $q=$conn->real_escape_string($_GET['q']); $where[] = "message LIKE '%$q%'"; }
    if (!empty($_GET['from'])) $where[] = "(log_ts >= '".$conn->real_escape_string($_GET['from'])." 00:00:00' OR created_at >= '".$conn->real_escape_string($_GET['from'])." 00:00:00')";
    if (!empty($_GET['to']))   $where[] = "(log_ts <= '".$conn->real_escape_string($_GET['to'])." 23:59:59' OR created_at <= '".$conn->real_escape_string($_GET['to'])." 23:59:59')";
    $after = (int)($_GET['after'] ?? 0);
    $limit = max(1, min(1000, (int)($_GET['limit'] ?? 300)));
    if ($after > 0) {
        $w = $where ? (' AND '.implode(' AND ',$where)) : '';
        $sql = "SELECT id,container_name,stream,log_ts,message FROM container_logs WHERE id>{$after}{$w} ORDER BY id ASC LIMIT {$limit}";
        $rows = $conn->query($sql)->fetch_all(MYSQLI_ASSOC);
    } else {
        $w = $where ? ('WHERE '.implode(' AND ',$where)) : '';
        $sql = "SELECT id,container_name,stream,log_ts,message FROM container_logs {$w} ORDER BY id DESC LIMIT {$limit}";
        $rows = array_reverse($conn->query($sql)->fetch_all(MYSQLI_ASSOC));
    }
    $max = 0; foreach ($rows as $r) $max = max($max, (int)$r['id']);
    echo json_encode(['ok'=>true,'lines'=>array_map(fn($r)=>['id'=>(int)$r['id'],'name'=>$r['container_name'],'stream'=>$r['stream'],'ts'=>$r['log_ts'],'message'=>$r['message']], $rows), 'max_id'=>$max ?: $after]);
    exit;
}

// Distinct sources for the picker
$sources = [];
$sr = $conn->query("SELECT container_name, container_id, MAX(id) last_id, COUNT(*) line_count
                    FROM container_logs GROUP BY container_id, container_name ORDER BY line_count DESC LIMIT 200");
while ($sr && $row = $sr->fetch_assoc()) $sources[] = $row;

$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
log_user_action($conn, 'view_page', 'container_logs.php');
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><title>Container Logs | SG-PR Console</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --docker:#0db7ed; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.22; }
.wrap{ max-width:1300px; margin:0 auto; padding:18px 20px 40px; } a{ color:var(--accent); text-decoration:none; }
.ctr-head{ display:flex; align-items:center; gap:14px; flex-wrap:wrap; margin-bottom:14px; }
.ctr-head h1{ margin:0; font-size:22px; font-weight:700; } .ctr-head h1 i{ color:var(--docker); }
.ctr-subnav{ display:flex; gap:4px; flex-wrap:wrap; margin-bottom:16px; border-bottom:1px solid var(--border); }
.ctr-subtab{ padding:8px 14px; font-size:13px; color:#9aa; border-bottom:2px solid transparent; display:inline-flex; gap:7px; align-items:center; }
.ctr-subtab:hover{ color:#fff; } .ctr-subtab.is-active{ color:var(--docker); border-bottom-color:var(--docker); font-weight:600; }
.filters{ display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:12px; }
select,input[type=text],input[type=date]{ background:rgba(0,0,0,.4); border:1px solid var(--border); color:#ddd; border-radius:8px; padding:7px 10px; font-size:12px; outline:none; }
input[type=text]{ flex:1; min-width:180px; }
.fbtn{ background:rgba(255,255,255,.05); border:1px solid var(--border); color:#aaa; padding:6px 11px; border-radius:7px; cursor:pointer; font-size:12px; }
.fbtn:hover{ background:rgba(77,163,255,.18); color:var(--accent); border-color:var(--accent); }
.term{ background:rgba(0,0,0,.55); border:1px solid var(--border); border-radius:12px; padding:12px 14px; height:calc(100vh - 250px); min-height:340px; overflow-y:auto; font-family:Consolas,Monaco,monospace; font-size:12px; line-height:1.5; }
.ll{ display:flex; gap:10px; padding:1px 0; white-space:pre-wrap; word-break:break-word; }
.ll-ts{ color:#5a6472; flex-shrink:0; } .ll-name{ color:#7fae6f; flex-shrink:0; } .ll-msg{ color:#cdd2d8; } .ll.is-err .ll-msg{ color:#e9978f; }
.empty{ text-align:center; color:#667; padding:50px 20px; } .empty i{ font-size:34px; color:#333; display:block; margin-bottom:12px; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
    <?php nm_page_header('Containers', '', 'Live Logs', 'fa-brands fa-docker',
        '<label style="display:flex;gap:7px;align-items:center;font-size:12px;color:#aaa;cursor:pointer;"><input type="checkbox" id="live" checked> Live tail</label>'
        .'<button class="fbtn" onclick="document.getElementById(\'term\').innerHTML=\'\';">Clear</button>'); ?>
    <?php nm_container_tabs('logs'); ?>
    <div class="filters">
        <select id="container" onchange="reload()">
            <option value="">All containers</option>
            <?php foreach ($sources as $s): ?>
            <option value="<?= htmlspecialchars($s['container_id']) ?>"><?= htmlspecialchars($s['container_name'] ?: substr($s['container_id'],0,12)) ?> (<?= (int)$s['line_count'] ?>)</option>
            <?php endforeach; ?>
        </select>
        <select id="stream" onchange="reload()"><option value="">stdout+stderr</option><option value="stdout">stdout</option><option value="stderr">stderr</option></select>
        <input type="text" id="q" placeholder="grep message…" onkeydown="if(event.key==='Enter')reload()">
        <input type="date" id="from"><input type="date" id="to">
        <button class="fbtn" onclick="reload()"><i class="fas fa-filter"></i> Apply</button>
    </div>
    <?php if (!$sources): ?>
    <div class="term empty"><i class="fas fa-file-lines"></i>
        <div>No logs yet. The n8n <b>log collector</b> flow pushes them to <code>?ep=logs</code>.</div></div>
    <?php else: ?>
    <div class="term" id="term"><div style="color:#556;">Loading…</div></div>
    <?php endif ?>
</div>
<script>
let after=0, showName=true, timer=null;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function params(){ const p=new URLSearchParams();
    const c=document.getElementById('container').value; if(c)p.set('container',c);
    const s=document.getElementById('stream').value; if(s)p.set('stream',s);
    const q=document.getElementById('q').value.trim(); if(q)p.set('q',q);
    const f=document.getElementById('from').value; if(f)p.set('from',f);
    const t=document.getElementById('to').value; if(t)p.set('to',t);
    return p; }
function reload(){ after=0; const t=document.getElementById('term'); if(t)t.innerHTML=''; showName=!document.getElementById('container').value; tail(true); }
async function tail(initial){
    const term=document.getElementById('term'); if(!term) return;
    const p=params(); p.set('limit', initial?'500':'300'); if(after)p.set('after',after);
    try{ const r=await fetch('container_logs.php?api=data&'+p.toString()+'&_='+Date.now()).then(r=>r.json());
        if(!r.ok) return;
        const near = term.scrollTop+term.clientHeight >= term.scrollHeight-40;
        if(initial) term.innerHTML='';
        (r.lines||[]).forEach(l=>{ const d=document.createElement('div'); d.className='ll'+(l.stream==='stderr'?' is-err':'');
            const ts=(l.ts||'').replace('T',' ').slice(5,19);
            d.innerHTML=`<span class="ll-ts">${esc(ts)}</span>${showName?`<span class="ll-name">${esc(l.name||'')}</span>`:''}<span class="ll-msg">${esc(l.message)}</span>`;
            term.appendChild(d); });
        if(initial && !(r.lines||[]).length) term.innerHTML='<div style="color:#556;">No lines match.</div>';
        if(r.max_id) after=r.max_id;
        while(term.childNodes.length>5000) term.removeChild(term.firstChild);
        if(near||initial) term.scrollTop=term.scrollHeight;
    }catch(e){}
}
document.getElementById('live')?.addEventListener('change',e=>{ if(e.target.checked){timer=setInterval(()=>{ if(!document.hidden) tail(false); },5000);}else{clearInterval(timer);} });
<?php if ($sources): ?>reload(); timer=setInterval(()=>{ if(!document.hidden && document.getElementById('live').checked) tail(false); },5000);<?php endif ?>
</script>
</body></html>
