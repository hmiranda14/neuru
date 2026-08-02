<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — Containers: Solution Commander. Human-in-the-loop AI fix over SSH.
// The AI proposes one command at a time; the user approves; n8n runs it and
// streams output back via nm_containers_api.php (fix_log/fix_proposal/fix_continue/
// fix_result). Portal is stateless toward n8n: full transcript sent every AI turn.
// RBAC: 'containers'.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_n8n.php');
require_once('nm_secrets.php');
require_once('nm_solutionkb.php');
require_once('nm_portainer.php');
require_once('nm_chrome.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'containers')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=containers'); exit;
}
require_once('nm_fixflow.php');   // shared fix-flow logic (also used by the n8n callback)
// thin aliases so the rest of this page reads unchanged
function cs($conn,$k,$d=''){ return nm_fix_setting($conn,$k,$d); }
function incident_row($conn,$id){ return nm_fix_incident($conn,$id); }
function fix_log($conn,$id,$level,$line){ nm_fix_log($conn,$id,$level,$line); }
function build_transcript($conn,$id){ return nm_fix_transcript($conn,$id); }
function send_fix_flow($conn,$inc,array $extra){ return nm_fix_send($conn,$inc,$extra); }
// Visually separate a fresh "Ask AI" run from a previous attempt that already ran
// (or failed) — without wiping the history. No divider on a truly fresh incident.
function fix_session_divider($conn,$id){
    $r=$conn->query("SELECT COUNT(*) c FROM container_fix_logs WHERE incident_id=".(int)$id." AND level IN ('cmd','error','done')");
    $n=$r?(int)$r->fetch_assoc()['c']:0;
    if($n>0) nm_fix_log($conn,$id,'divider','New fix session · '.date('M j, H:i'));
}

// ── API ───────────────────────────────────────────────────────────────────────
if (function_exists('session_write_close')) @session_write_close(); // free session lock before slow SSH/n8n I/O (prevents whole-portal freeze)
if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    $id = (int)($_GET['id'] ?? ($_POST['id'] ?? 0));
    $inc = incident_row($conn,$id);
    if (!$inc) { echo json_encode(['ok'=>false,'error'=>'Incident not found']); exit; }
    $body = json_decode(file_get_contents('php://input'), true) ?? $_POST;

    if ($api === 'data') {
        $after=(int)($_GET['after'] ?? 0);
        $lr=$conn->query("SELECT id,level,line,created_at FROM container_fix_logs WHERE incident_id={$id} AND id>{$after} AND level NOT IN ('proposal','proposal-ack') ORDER BY id ASC LIMIT 800");
        $lines=$lr?$lr->fetch_all(MYSQLI_ASSOC):[]; $max=$after; foreach($lines as $l) $max=max($max,(int)$l['id']);
        // proposal: latest 'proposal' only if newer than latest 'proposal-ack'
        $pp=$conn->query("SELECT id,line FROM container_fix_logs WHERE incident_id={$id} AND level='proposal' ORDER BY id DESC LIMIT 1");
        $prop=null; if($pp && $pr=$pp->fetch_assoc()){
            $ack=$conn->query("SELECT MAX(id) m FROM container_fix_logs WHERE incident_id={$id} AND level='proposal-ack'");
            $ackId=$ack?(int)$ack->fetch_assoc()['m']:0;
            if((int)$pr['id']>$ackId){ $j=json_decode($pr['line'],true)?:[]; $prop=['id'=>(int)$pr['id'],'command'=>$j['command']??'','rationale'=>$j['rationale']??'','risky'=>(bool)($j['risky']??false)]; }
        }
        $fr=$conn->query("SELECT fix_status,status FROM container_incidents WHERE id={$id}")->fetch_assoc();
        echo json_encode(['ok'=>true,'fix_status'=>$fr['fix_status'],'status'=>$fr['status'],
            'lines'=>array_map(fn($l)=>['id'=>(int)$l['id'],'level'=>$l['level'],'line'=>$l['line'],'at'=>$l['created_at']],$lines),'max_id'=>$max,'proposal'=>$prop]);
        exit;
    }

    if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }

    if ($api === 'start') {
        $conn->query("DELETE FROM container_fix_logs WHERE incident_id={$id}");
        fix_log($conn,$id,'info','Fix session requested — handing the incident to the AI…');
        $r=send_fix_flow($conn,$inc,['mode'=>'fix']);
        $conn->query("UPDATE container_incidents SET fix_status='running', fix_started_at=NOW(), fix_finished_at=NULL WHERE id={$id}");
        nm_audit($conn,'incident.fix_start',['target_type'=>'container_incident','target_id'=>$id]);
        echo json_encode(['ok'=>$r['ok'],'error'=>$r['err'] ?: null]); exit;
    }
    if ($api === 'reset') {
        $conn->query("DELETE FROM container_fix_logs WHERE incident_id={$id}");
        $conn->query("UPDATE container_incidents SET fix_status='none', fix_started_at=NULL, fix_finished_at=NULL WHERE id={$id}");
        fix_log($conn,$id,'info',"Session reset — transcript cleared. Start over with 'Ask AI for a fix', or type a message below.");
        nm_audit($conn,'incident.fix_reset',['target_type'=>'container_incident','target_id'=>$id]);
        echo json_encode(['ok'=>true]); exit;
    }
    if ($api === 'suggest') {
        fix_session_divider($conn,$id);
        fix_log($conn,$id,'info','Asked the AI to analyze and propose a fix');
        $r=send_fix_flow($conn,$inc,['mode'=>'suggest','message'=>'Analyze the session so far and propose the single next command to run.']);
        echo json_encode(['ok'=>$r['ok'],'error'=>$r['err'] ?: null]); exit;
    }
    if ($api === 'message') {
        $msg=trim((string)($body['message'] ?? '')); if($msg==='') { echo json_encode(['ok'=>false,'error'=>'Empty']); exit; }
        fix_log($conn,$id,'user',$msg);
        $r=send_fix_flow($conn,$inc,['mode'=>'chat','message'=>$msg]);
        echo json_encode(['ok'=>$r['ok'],'error'=>$r['err'] ?: null]); exit;
    }
    if ($api === 'command') {
        $cmd=trim((string)($body['command'] ?? '')); if($cmd==='') { echo json_encode(['ok'=>false,'error'=>'Empty']); exit; }
        if (!empty($body['ack'])) fix_log($conn,$id,'proposal-ack','approved');
        fix_log($conn,$id,'cmd','$ '.$cmd);
        // Run the command NATIVELY from NEURU (on the LAN) — the hosted n8n SSH node can't reach a
        // private Docker host over the WireGuard callback tunnel. Then loop the AI on the new output.
        $ex=nm_fix_exec_native($conn,$inc,$cmd);
        nm_audit($conn,'incident.fix_command',['target_type'=>'container_incident','target_id'=>$id,'details'=>['cmd'=>mb_substr($cmd,0,200),'rc'=>$ex['rc']??null]]);
        if ($ex['ok']) { $c=nm_fix_continue($conn,$id); echo json_encode(['ok'=>true,'error'=>$c['error']??null]); }
        else           { echo json_encode(['ok'=>false,'error'=>'Command could not run — see transcript.']); }
        exit;
    }
    if ($api === 'dismiss') {
        fix_log($conn,$id,'proposal-ack','dismissed');
        echo json_encode(['ok'=>true]); exit;
    }
    if ($api === 'save_kb') {
        $note=trim((string)($body['note'] ?? ''));
        $kbId=nm_kb_capture($conn,['subject'=>$inc['container_name'],'severity'=>$inc['severity'],'error'=>$inc['error_text'],
            'summary'=>$inc['ai_summary'],'resolution'=>nm_kb_build_resolution($conn,$id,$note,(string)$inc['ai_solution']),'transcript'=>build_transcript($conn,$id),
            'source'=>'manual','incident_id'=>$id]);
        nm_audit($conn,'incident.fix_savekb',['target_type'=>'container_incident','target_id'=>$id]);
        echo json_encode(['ok'=>(bool)$kbId,'kb_id'=>$kbId]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'Unknown endpoint']); exit;
}

// ── Page ──────────────────────────────────────────────────────────────────────
$id = (int)($_GET['id'] ?? 0);
$inc = incident_row($conn,$id);
// Resolve the real Docker HOST (server) this container runs on, from endpoint_id → Portainer
// endpoint name + ip, and backfill host_ip so troubleshooting isn't blind.
$srvName = ''; $srvIp = '';
if ($inc) {
    $pcfg = nm_portainer_cfg($conn);
    if (nm_portainer_configured($pcfg)) {
        $ep = nm_portainer_endpoint_map($pcfg)[(int)$inc['endpoint_id']] ?? null;
        if ($ep) { $srvName = (string)$ep['name']; $srvIp = (string)$ep['ip'];
            if (empty($inc['host_ip']) && $srvIp !== '') { $conn->query("UPDATE container_incidents SET host_ip='".$conn->real_escape_string($srvIp)."' WHERE id=".(int)$id); $inc['host_ip']=$srvIp; } }
    }
    $srvName = $srvName ?: (string)($inc['host'] ?: ''); $srvIp = $srvIp ?: (string)($inc['host_ip'] ?: '');
}
$configured = cs($conn,'fix_webhook_url','') !== '';
$suggestConfigured = cs($conn,'fix_suggest_url','') !== '';
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
log_user_action($conn, 'view_page', 'container_fix.php');
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><title>Solution Commander | SG-PR Console</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --docker:#0db7ed; --ai:#9b59b6; --ok:#2ecc71; --warn:#f39c12; --stop:#e74c3c; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.2; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 30px; } a{ color:var(--accent); text-decoration:none; }
.ctr-head{ display:flex; align-items:center; gap:12px; flex-wrap:wrap; margin-bottom:12px; }
.ctr-head h1{ margin:0; font-size:20px; font-weight:700; } .ctr-head h1 i{ color:var(--ai); }
.subnav{ display:flex; gap:4px; margin-bottom:14px; border-bottom:1px solid var(--border); }
.subnav a{ padding:7px 13px; font-size:13px; color:#9aa; border-bottom:2px solid transparent; }
.subnav a.is-active{ color:var(--ai); border-bottom-color:var(--ai); font-weight:600; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:12px; }
.grid{ display:grid; grid-template-columns:340px 1fr; gap:16px; } @media(max-width:980px){ .grid{ grid-template-columns:1fr; } }
.card{ padding:14px 16px; margin-bottom:14px; } .card h3{ margin:0 0 10px; font-size:12px; color:var(--accent); text-transform:uppercase; letter-spacing:1px; }
.dl{ display:grid; grid-template-columns:auto 1fr; gap:5px 12px; font-size:12px; } .dl dt{ color:#7c828c; } .dl dd{ margin:0; color:#dfe3e8; word-break:break-word; }
.btn{ background:rgba(255,255,255,.06); border:1px solid var(--border); color:#cfd3da; padding:7px 12px; border-radius:8px; cursor:pointer; font-size:12px; display:inline-flex; gap:7px; align-items:center; width:100%; justify-content:center; margin-bottom:7px; }
.btn:hover{ background:rgba(255,255,255,.13); color:#fff; }
.btn.ai{ background:rgba(155,89,182,.18); border-color:var(--ai); color:#c08fd6; } .btn.ai:hover{ background:var(--ai); color:#fff; }
.btn.ok{ } .btn.ok:hover{ border-color:var(--ok); color:var(--ok);} .btn.danger:hover{ border-color:var(--stop); color:var(--stop);}
.term{ background:rgba(0,0,0,.62); border:1px solid var(--border); border-radius:12px; height:calc(100vh - 320px); min-height:380px; overflow-y:auto; padding:14px 16px; font-family:Consolas,Monaco,monospace; font-size:12.5px; line-height:1.55; }
.cv-info{ color:#667; font-style:italic; } .cv-user{ color:#8fd; } .cv-ai{ color:#cbb6e0; } .cv-cmd{ color:#7fd1ff; } .cv-out{ color:#cdd2d8; white-space:pre-wrap; } .cv-error{ color:#e9978f; white-space:pre-wrap; } .cv-done{ color:var(--ok); font-weight:600; }
.cv-line{ padding:2px 0; white-space:pre-wrap; word-break:break-word; }
.cv-divider{ color:#8a909a; text-align:center; border-top:1px dashed var(--border); margin:12px 0 6px; padding-top:9px; font-size:10.5px; text-transform:uppercase; letter-spacing:1.5px; }
.cv-divider::before{ content:'──  '; } .cv-divider::after{ content:'  ──'; }
.cv-user::before{ content:'You: '; color:#5aa; } .cv-ai::before{ content:'AI: '; color:#a88bc0; }
.prop{ border:1px solid rgba(155,89,182,.4); background:rgba(155,89,182,.08); border-radius:10px; padding:12px 14px; margin-bottom:12px; }
.prop.is-risky{ border-color:rgba(231,76,60,.5); background:rgba(231,76,60,.08); }
.prop .rt{ font-size:11px; color:#c08fd6; text-transform:uppercase; letter-spacing:1px; margin-bottom:6px; }
.prop textarea{ width:100%; background:rgba(0,0,0,.5); border:1px solid var(--border); color:#7fd1ff; border-radius:8px; padding:8px 10px; font-family:Consolas,monospace; font-size:13px; resize:vertical; }
.prop .rat{ font-size:12px; color:#aab; margin:8px 0; }
.composer{ display:flex; gap:8px; margin-top:12px; }
.composer textarea{ flex:1; background:rgba(0,0,0,.4); border:1px solid var(--border); color:#eee; border-radius:10px; padding:9px 11px; font-size:13px; resize:none; max-height:120px; }
.composer button{ background:var(--ai); border:none; color:#fff; width:46px; border-radius:10px; cursor:pointer; }
.badge{ font-size:9.5px; font-weight:700; padding:2px 8px; border-radius:5px; text-transform:uppercase; }
.b-run{ background:rgba(46,204,113,.16); color:var(--ok);} .b-none{ background:rgba(138,144,154,.16); color:#8a909a;} .b-fail{ background:rgba(231,76,60,.16); color:var(--stop);}
.warnbox{ background:rgba(243,156,18,.1); border:1px solid rgba(243,156,18,.3); color:#f0c674; border-radius:10px; padding:12px 14px; margin-bottom:14px; font-size:12.5px; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php if (!$inc): ?>
    <?php nm_page_header('<i class="fas fa-wand-magic-sparkles"></i>Solution Commander', '', 'Container Operations', 'fa-brands fa-docker'); ?>
    <?php nm_container_tabs('fix'); ?>
    <?php
    // Landing (no incident chosen): show every OPEN incident to pick and troubleshoot,
    // each with the real Docker host it runs on — so this tab is never a dead end.
    $openList = $conn->query("SELECT id,endpoint_id,host,host_ip,container_name,severity,error_text,status,last_seen,fix_status
                              FROM container_incidents WHERE status IN('open','analyzing','acknowledged')
                              ORDER BY FIELD(severity,'critical','warning','info'), last_seen DESC LIMIT 80");
    $pcfg = nm_portainer_cfg($conn); $emap = nm_portainer_configured($pcfg) ? nm_portainer_endpoint_map($pcfg) : [];
    ?>
    <div class="glass card">
      <h3 style="margin-top:0;"><i class="fas fa-list-check"></i> Open incidents — pick one to troubleshoot</h3>
      <?php if (!$openList || !$openList->num_rows): ?>
        <div style="color:#8a93a3;padding:10px;"><i class="fas fa-circle-check" style="color:#2ecc71;"></i> No open container incidents right now. <a href="container_errors.php">Go to Error Watch →</a></div>
      <?php else: while ($x = $openList->fetch_assoc()):
        $srv = $emap[(int)$x['endpoint_id']]['name'] ?? ($x['host'] ?: '?');
        $sc  = $x['severity']==='critical'?'#e74c3c':($x['severity']==='warning'?'#f39c12':'#4da3ff'); ?>
        <a class="cfx-row" href="container_fix.php?id=<?= (int)$x['id'] ?>" style="display:flex;gap:12px;align-items:center;padding:11px 8px;border-bottom:1px solid rgba(255,255,255,.06);color:#dfe3e8;">
          <span style="color:<?= $sc ?>;font-weight:800;font-size:10.5px;min-width:64px;letter-spacing:.5px;"><?= htmlspecialchars(strtoupper($x['severity'])) ?></span>
          <span style="flex:1;min-width:0;">
            <b><?= htmlspecialchars($x['container_name']) ?></b>
            <span style="color:#7fb0e8;font-size:12px;">· <i class="fas fa-server"></i> <?= htmlspecialchars($srv) ?></span>
            <span class="statusb s-<?= htmlspecialchars($x['status']) ?>" style="font-size:10px;margin-left:6px;"><?= htmlspecialchars($x['status']) ?></span>
            <div style="color:#9aa;font-size:11.5px;font-family:Consolas,monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px;"><?= htmlspecialchars(mb_substr($x['error_text'],0,120)) ?></div>
          </span>
          <span style="color:#667;font-size:11px;white-space:nowrap;"><?= htmlspecialchars(substr((string)$x['last_seen'],5,11)) ?></span>
          <i class="fas fa-wand-magic-sparkles" style="color:var(--ai);"></i>
        </a>
      <?php endwhile; endif; ?>
      <div id="cfx-pager" style="display:none;align-items:center;justify-content:center;gap:12px;padding:12px;color:#9aa3af;font-size:13px;">
        <button class="fbtn" onclick="cfxPg(-1)">◀ Prev</button><span id="cfx-pageinfo"></span><button class="fbtn" onclick="cfxPg(1)">Next ▶</button>
      </div>
      <script>
      (function(){ var rows=[].slice.call(document.querySelectorAll('.cfx-row')); if(rows.length<=10) return;
        var per=10, pg=0, pages=Math.ceil(rows.length/per), bar=document.getElementById('cfx-pager'), info=document.getElementById('cfx-pageinfo');
        function draw(){ if(pg>=pages)pg=pages-1; if(pg<0)pg=0; rows.forEach(function(r,i){ r.style.display=(i>=pg*per&&i<pg*per+per)?'flex':'none'; }); info.innerHTML='Page <b style="color:#e6e9ee">'+(pg+1)+'</b> / '+pages+' · '+rows.length+' incidents'; bar.style.display='flex'; }
        window.cfxPg=function(d){ pg+=d; draw(); }; draw();
      })();
      </script>
    </div>
<?php else: $bcls=$inc['fix_status']==='running'?'b-run':($inc['fix_status']==='failed'?'b-fail':'b-none'); ?>
    <?php nm_page_header('<i class="fas fa-wand-magic-sparkles"></i>Solution Commander', '', 'Container Operations', 'fa-brands fa-docker',
        '<span class="badge '.$bcls.'" id="fix-state">'.htmlspecialchars($inc['fix_status']).'</span>'
        .'<a class="refresh-btn" href="container_errors.php">← Error Watch</a>'); ?>
    <?php nm_container_tabs('fix'); ?>

    <?php if (!$configured && !$suggestConfigured): ?>
    <div class="warnbox"><i class="fas fa-triangle-exclamation"></i> No fix webhooks configured yet — set
        <code>fix_suggest_url</code> + <code>fix_webhook_url</code> in
        <a href="net_mon_config.php?tab=containers">Config → Containers</a>.</div>
    <?php endif ?>

    <div class="grid" data-id="<?= $id ?>">
        <!-- LEFT: meta + tools + proposal -->
        <div>
            <div class="glass card">
                <h3>Incident #<?= $id ?></h3>
                <div class="dl">
                    <dt>Container</dt><dd><?= htmlspecialchars($inc['container_name']) ?></dd>
                    <dt>Server</dt><dd><i class="fas fa-server" style="color:#4da3ff;"></i> <?= htmlspecialchars($srvName ?: '—') ?></dd>
                    <dt>SSH target</dt><dd><?= $srvIp ? htmlspecialchars($srvIp) : '<span style="color:#e08a3a;">— (no host IP resolved)</span>' ?></dd>
                    <dt>Severity</dt><dd><?= htmlspecialchars($inc['severity']) ?></dd>
                </div>
                <div style="margin-top:10px;font-size:11.5px;color:#9aa;background:rgba(231,76,60,.07);border:1px solid rgba(231,76,60,.2);border-radius:8px;padding:8px 10px;font-family:Consolas,monospace;max-height:120px;overflow:auto;"><?= htmlspecialchars(mb_substr($inc['error_text'],0,600)) ?></div>
            </div>
            <div class="glass card">
                <h3>Tools</h3>
                <button class="btn ai" onclick="fixAct('suggest',this)"><i class="fas fa-wand-magic-sparkles"></i> Ask AI for a fix</button>
                <button class="btn" onclick="fixAct('start',this)" title="Hand the whole incident to the autonomous fix flow"><i class="fas fa-robot"></i> Auto-fix (n8n drives)</button>
                <button class="btn ok" onclick="saveKb()"><i class="fas fa-floppy-disk"></i> Save to Knowledge Base</button>
                <button class="btn danger" onclick="resetFix()"><i class="fas fa-broom"></i> Reset session</button>
                <div style="margin-top:10px;">
                    <label style="font-size:10px;color:#888;text-transform:uppercase;letter-spacing:1px;">Manual command</label>
                    <div style="display:flex;gap:6px;margin-top:4px;">
                        <input id="manual-cmd" placeholder="$ command…" style="flex:1;background:rgba(0,0,0,.5);border:1px solid var(--border);color:#7fd1ff;border-radius:8px;padding:7px 9px;font-family:Consolas,monospace;font-size:12px;">
                        <button class="btn" style="width:auto;margin:0;" onclick="runManual()"><i class="fas fa-play"></i></button>
                    </div>
                </div>
            </div>
            <div id="prop-panel"></div>
        </div>

        <!-- RIGHT: terminal + composer -->
        <div>
            <div class="term" id="term"><div class="cv-line cv-info">Loading session…</div></div>
            <div class="composer">
                <textarea id="chat" rows="1" placeholder="Message the AI… (Enter to send, Shift+Enter newline)"
                    onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMsg();}"></textarea>
                <button onclick="sendMsg()"><i class="fas fa-paper-plane"></i></button>
            </div>
        </div>
    </div>
<?php endif ?>
</div>

<?php if ($inc): ?>
<script>
const ID=<?= $id ?>; let after=0, lastPropId=0;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
const term=document.getElementById('term');
function addLine(l){
    const d=document.createElement('div'); d.className='cv-line cv-'+l.level;
    let t=l.line; if(l.level==='cmd'&&!t.startsWith('$ ')) t='$ '+t;
    d.textContent=t; term.appendChild(d);
}
async function poll(){
    try{ const r=await fetch(`container_fix.php?api=data&id=${ID}&after=${after}&_=${Date.now()}`).then(r=>r.json());
        if(!r.ok) return;
        const near=term.scrollTop+term.clientHeight>=term.scrollHeight-50;
        if(after===0) term.innerHTML='';
        (r.lines||[]).forEach(addLine);
        if(r.max_id) after=r.max_id;
        if(!term.childNodes.length) term.innerHTML='<div class="cv-line cv-info">No session yet — click "Ask AI for a fix" or type a message.</div>';
        while(term.childNodes.length>4000) term.removeChild(term.firstChild);
        if(near) term.scrollTop=term.scrollHeight;
        const fs=document.getElementById('fix-state'); if(fs){ fs.textContent=r.fix_status; fs.className='badge '+(r.fix_status==='running'?'b-run':r.fix_status==='failed'?'b-fail':'b-none'); }
        renderProposal(r.proposal);
    }catch(e){}
}
function renderProposal(p){
    const panel=document.getElementById('prop-panel');
    if(!p){ if(lastPropId&&!document.querySelector('.prop')) {} panel.innerHTML=''; lastPropId=0; return; }
    if(p.id===lastPropId && document.querySelector('.prop')) return;  // don't overwrite user's edits
    lastPropId=p.id;
    panel.innerHTML=`<div class="prop ${p.risky?'is-risky':''}">
        <div class="rt"><i class="fas fa-wand-magic-sparkles"></i> AI proposes ${p.risky?'· ⚠ risky':''}</div>
        ${p.rationale?`<div class="rat">${esc(p.rationale)}</div>`:''}
        <textarea id="prop-cmd" rows="2">${esc(p.command)}</textarea>
        <div style="display:flex;gap:7px;margin-top:9px;">
            <button class="btn ok" style="width:auto;margin:0;" onclick="approveProp()"><i class="fas fa-check"></i> Approve & run</button>
            <button class="btn danger" style="width:auto;margin:0;" onclick="dismissProp()"><i class="fas fa-xmark"></i> Reject</button>
        </div></div>`;
}
async function post(api,bodyObj){ return fetch(`container_fix.php?api=${api}&id=${ID}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(bodyObj||{})}).then(r=>r.json()).catch(()=>({ok:false,error:'failed'})); }
async function fixAct(api,btn){ if(btn){btn.disabled=true;} const r=await post(api,{}); if(btn)btn.disabled=false; if(!r.ok&&r.error) alert(r.error); poll(); }
async function approveProp(){ const cmd=document.getElementById('prop-cmd').value.trim(); if(!cmd)return;
    document.getElementById('prop-panel').innerHTML=''; lastPropId=0;
    const r=await post('command',{command:cmd,ack:1}); if(!r.ok&&r.error)alert(r.error); poll(); }
async function dismissProp(){ document.getElementById('prop-panel').innerHTML=''; lastPropId=0; await post('dismiss',{}); poll(); }
async function runManual(){ const el=document.getElementById('manual-cmd'); const cmd=el.value.trim(); if(!cmd)return; el.value='';
    const r=await post('command',{command:cmd}); if(!r.ok&&r.error)alert(r.error); poll(); }
async function sendMsg(){ const el=document.getElementById('chat'); const m=el.value.trim(); if(!m)return; el.value='';
    const r=await post('message',{message:m}); if(!r.ok&&r.error)alert(r.error); poll(); }
async function resetFix(){ if(!confirm('Reset the session? Transcript is cleared (no AI contact).'))return; await post('reset',{}); after=0; lastPropId=0; document.getElementById('prop-panel').innerHTML=''; poll(); }
async function saveKb(){ const note=prompt('Resolution note for the KB (optional):')||''; const r=await post('save_kb',{note}); alert(r.ok?'Saved to Knowledge Base.':'Save failed (KB disabled or no data).'); }
poll(); setInterval(()=>{ if(!document.hidden) poll(); },2500);
</script>
<?php endif ?>
</body></html>
