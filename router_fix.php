<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Router Commander: session console. AI proposes ONE command at a time;
// the human approves; it runs over the right transport (router→Python SSH,
// linux→n8n bash SSH); output feeds the next AI turn. Destructive commands are
// flagged; "Explain" gives a dry-run explanation without running anything.
// RBAC: 'router_commander'. Engine: nm_rcflow.php. Callbacks: nm_router_api.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_rcflow.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'router_commander')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=router_commander'); exit;
}
nm_rc_ensure($conn);

// ── API ──────────────────────────────────────────────────────────────────────
if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    $id   = (int)($_GET['id'] ?? ($_POST['id'] ?? 0));
    $sess = nm_rc_session($conn,$id);
    if (!$sess) { echo json_encode(['ok'=>false,'error'=>'Session not found']); exit; }
    $body = json_decode(file_get_contents('php://input'), true) ?? $_POST;

    if ($api === 'data') {
        $after=(int)($_GET['after'] ?? 0);
        $lr=$conn->query("SELECT id,level,line,created_at FROM nm_rc_logs WHERE session_id={$id} AND id>{$after} AND level NOT IN ('proposal','proposal-ack') ORDER BY id ASC LIMIT 800");
        $lines=$lr?$lr->fetch_all(MYSQLI_ASSOC):[]; $max=$after; foreach($lines as $l) $max=max($max,(int)$l['id']);
        $pp=$conn->query("SELECT id,line FROM nm_rc_logs WHERE session_id={$id} AND level='proposal' ORDER BY id DESC LIMIT 1");
        $prop=null;
        if($pp && $pr=$pp->fetch_assoc()){
            $ack=$conn->query("SELECT MAX(id) m FROM nm_rc_logs WHERE session_id={$id} AND level='proposal-ack'");
            $ackId=$ack?(int)$ack->fetch_assoc()['m']:0;
            if((int)$pr['id']>$ackId){
                $j=json_decode($pr['line'],true)?:[]; $cmd=$j['command']??'';
                $risk=nm_rc_risk_assess($cmd,(string)$sess['vendor_key']);
                $prop=['id'=>(int)$pr['id'],'command'=>$cmd,'rationale'=>$j['rationale']??'','risky'=>(bool)($j['risky']??false)||$risk['risky'],'risk'=>$risk];
            }
        }
        echo json_encode(['ok'=>true,'status'=>$sess['status'],'transport'=>$sess['transport'],
            'lines'=>array_map(fn($l)=>['id'=>(int)$l['id'],'level'=>$l['level'],'line'=>$l['line'],'at'=>$l['created_at']],$lines),
            'max_id'=>$max,'proposal'=>$prop]);
        exit;
    }

    if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }

    if ($api === 'suggest') {
        // session divider if a prior run exists
        $c=$conn->query("SELECT COUNT(*) c FROM nm_rc_logs WHERE session_id={$id} AND level IN ('cmd','error','done')");
        if($c && (int)$c->fetch_assoc()['c']>0) nm_rc_log($conn,$id,'divider','New session · '.date('M j, H:i'));
        nm_rc_log($conn,$id,'info','Asked the AI to analyze and propose a fix');
        $r=nm_rc_send($conn,$sess,['mode'=>'suggest','message'=>'Analyze the session so far and propose the single next command to run.']);
        echo json_encode(['ok'=>$r['ok'],'error'=>$r['err'] ?: null]); exit;
    }
    if ($api === 'message') {
        $msg=trim((string)($body['message'] ?? '')); if($msg===''){ echo json_encode(['ok'=>false,'error'=>'Empty']); exit; }
        nm_rc_log($conn,$id,'user',$msg);
        $r=nm_rc_send($conn,$sess,['mode'=>'chat','message'=>$msg]);
        echo json_encode(['ok'=>$r['ok'],'error'=>$r['err'] ?: null]); exit;
    }
    if ($api === 'command') {
        $cmd=trim((string)($body['command'] ?? '')); if($cmd===''){ echo json_encode(['ok'=>false,'error'=>'Empty']); exit; }
        $risk=nm_rc_risk_assess($cmd,(string)$sess['vendor_key']);
        if ($risk['severity']==='destructive' && empty($body['confirm'])) {
            echo json_encode(['ok'=>false,'needs_confirm'=>true,'risk'=>$risk]); exit;
        }
        if (!empty($body['ack'])) nm_rc_log($conn,$id,'proposal-ack','approved');
        if ($risk['severity']==='destructive') nm_rc_log($conn,$id,'info','⚠ Destructive command approved: '.implode('; ',$risk['reasons']));
        nm_rc_log($conn,$id,'cmd','$ '.$cmd);
        $r=nm_rc_send($conn,$sess,['mode'=>'command','command'=>$cmd]);
        nm_audit($conn,'router.command',['target_type'=>'rc_session','target_id'=>$id,'details'=>['cmd'=>mb_substr($cmd,0,200),'risk'=>$risk['severity']]]);
        echo json_encode(['ok'=>$r['ok'],'error'=>($r['err']??null) ?: null]); exit;
    }
    if ($api === 'explain') {
        $cmd=trim((string)($body['command'] ?? '')); if($cmd===''){ echo json_encode(['ok'=>false,'error'=>'Empty']); exit; }
        $risk=nm_rc_risk_assess($cmd,(string)$sess['vendor_key']);
        nm_rc_log($conn,$id,'info','🔎 Dry-run — explaining (not running): '.$cmd);
        if ($risk['reasons']) nm_rc_log($conn,$id,'info','⚠ Local risk check ['.$risk['severity'].']: '.implode('; ',$risk['reasons']).' → affects: '.implode('; ',$risk['affects']));
        $vlabel = (nm_cm_vendor($conn,(string)$sess['vendor_key'])['label'] ?? $sess['vendor_key']);
        $r=nm_rc_send($conn,$sess,['mode'=>'explain','message'=>"Explain exactly what this command does on a {$vlabel} device over SSH, step by step and briefly. If it is destructive or changes state, warn clearly WHAT it changes and WHAT it could affect. DO NOT propose or run anything. Command:\n".$cmd]);
        echo json_encode(['ok'=>$r['ok'],'error'=>$r['err'] ?: null,'risk'=>$risk]); exit;
    }
    if ($api === 'dismiss') {
        nm_rc_log($conn,$id,'proposal-ack','dismissed');
        echo json_encode(['ok'=>true]); exit;
    }
    if ($api === 'reset') {
        $conn->query("DELETE FROM nm_rc_logs WHERE session_id={$id}");
        $conn->query("UPDATE nm_rc_sessions SET status='open' WHERE id={$id}");
        nm_rc_log($conn,$id,'user',(string)$sess['problem']);
        nm_rc_log($conn,$id,'info',"Session reset — transcript cleared. Same problem, fresh start.");
        nm_audit($conn,'router.session.reset',['target_type'=>'rc_session','target_id'=>$id]);
        echo json_encode(['ok'=>true]); exit;
    }
    if ($api === 'save_kb') {
        $note=trim((string)($body['note'] ?? ''));
        $kbId=nm_kb_capture($conn,['subject'=>$sess['name'],'severity'=>'','error'=>$sess['problem'] ?: $sess['title'],
            'summary'=>$sess['title'],'resolution'=>nm_rc_build_resolution($conn,$id,$note),'transcript'=>nm_rc_transcript($conn,$id),
            'source'=>'router']);
        if($kbId) $conn->query("UPDATE nm_rc_sessions SET kb_id=".(int)$kbId." WHERE id={$id}");
        nm_audit($conn,'router.kb.save',['target_type'=>'rc_session','target_id'=>$id]);
        echo json_encode(['ok'=>(bool)$kbId,'kb_id'=>$kbId]); exit;
    }
    if ($api === 'close') {
        $action=($body['action'] ?? '')==='resolve'?'resolve':'abandon';
        $note=trim((string)($body['note'] ?? ''));
        if($note!=='') nm_rc_log($conn,$id,'done',($action==='resolve'?'✓ ':'✗ ').$note);
        $kbId=0;
        if($action==='resolve'){
            $kbId=nm_kb_capture($conn,['subject'=>$sess['name'],'severity'=>'','error'=>$sess['problem'] ?: $sess['title'],
                'summary'=>$sess['title'],'resolution'=>nm_rc_build_resolution($conn,$id,$note),'transcript'=>nm_rc_transcript($conn,$id),'source'=>'router']);
            $conn->query("UPDATE nm_rc_sessions SET status='resolved'".($kbId?(", kb_id=".(int)$kbId):'')." WHERE id={$id}");
        } else {
            $conn->query("UPDATE nm_rc_sessions SET status='abandoned' WHERE id={$id}");
        }
        nm_audit($conn,'router.session.'.($action==='resolve'?'resolved':'abandoned'),['target_type'=>'rc_session','target_id'=>$id]);
        echo json_encode(['ok'=>true,'kb_saved'=>(bool)$kbId]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'Unknown endpoint']); exit;
}

// ── Page ──────────────────────────────────────────────────────────────────────
$id = (int)($_GET['id'] ?? 0);
$sess = nm_rc_session($conn,$id);
$vlabel = $sess ? (nm_cm_vendor($conn,(string)$sess['vendor_key'])['label'] ?? $sess['vendor_key']) : '';
$suggestConfigured = nm_rc_setting($conn,'rc_suggest_url','') !== '';
$execConfigured = nm_rc_setting($conn,'rc_execute_url','') !== '';
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
log_user_action($conn,'view_page','router_fix.php');
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Adv. Solution Commander | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ai:#9b59b6; --ok:#2ecc71; --warn:#f39c12; --stop:#e74c3c; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.2; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 30px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:12px; }
.grid{ display:grid; grid-template-columns:340px 1fr; gap:16px; } @media(max-width:980px){ .grid{ grid-template-columns:1fr; } }
.card{ padding:14px 16px; margin-bottom:14px; } .card h3{ margin:0 0 10px; font-size:12px; color:var(--accent); text-transform:uppercase; letter-spacing:1px; }
.dl{ display:grid; grid-template-columns:auto 1fr; gap:5px 12px; font-size:12px; } .dl dt{ color:#7c828c; } .dl dd{ margin:0; color:#dfe3e8; word-break:break-word; }
.btn{ background:rgba(255,255,255,.06); border:1px solid var(--border); color:#cfd3da; padding:7px 12px; border-radius:8px; cursor:pointer; font-size:12px; display:inline-flex; gap:7px; align-items:center; width:100%; justify-content:center; margin-bottom:7px; }
.btn:hover{ background:rgba(255,255,255,.13); color:#fff; }
.btn.ai{ background:rgba(155,89,182,.18); border-color:var(--ai); color:#c08fd6; } .btn.ai:hover{ background:var(--ai); color:#fff; }
.btn.ok:hover{ border-color:var(--ok); color:var(--ok);} .btn.danger:hover{ border-color:var(--stop); color:var(--stop);}
.tp{ font-size:9.5px; font-weight:700; padding:2px 7px; border-radius:5px; }
.tp-cli{ background:rgba(243,156,18,.16); color:var(--warn);} .tp-linux{ background:rgba(13,183,237,.16); color:#0db7ed;} .tp-win{ background:rgba(0,120,212,.18); color:#7fc1ff;}
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
.riskbox{ border-radius:8px; padding:9px 11px; margin:8px 0; font-size:12px; }
.risk-destructive{ background:rgba(231,76,60,.12); border:1px solid rgba(231,76,60,.45); color:#f0a59d; }
.risk-caution{ background:rgba(243,156,18,.1); border:1px solid rgba(243,156,18,.35); color:#f0c674; }
.composer{ display:flex; gap:8px; margin-top:12px; }
.composer textarea{ flex:1; background:rgba(0,0,0,.4); border:1px solid var(--border); color:#eee; border-radius:10px; padding:9px 11px; font-size:13px; resize:none; max-height:120px; }
.composer button{ background:var(--ai); border:none; color:#fff; width:46px; border-radius:10px; cursor:pointer; }
.busy{ display:none; align-items:center; gap:9px; background:rgba(155,89,182,.14); border:1px solid rgba(155,89,182,.4); color:#c9a9e0; border-radius:9px; padding:7px 12px; margin-bottom:10px; font-size:12px; }
.spin{ width:13px; height:13px; border:2px solid rgba(201,169,224,.35); border-top-color:#c08fd6; border-radius:50%; animation:rcspin .7s linear infinite; display:inline-block; }
@keyframes rcspin{ to{ transform:rotate(360deg); } }
.manual{ display:flex; gap:8px; margin-top:10px; }
.manual input{ flex:1; background:rgba(0,0,0,.4); border:1px solid var(--border); color:#7fd1ff; border-radius:8px; padding:8px 10px; font-family:Consolas,monospace; font-size:12.5px; }
.manual button{ width:auto; margin:0; }
.badge{ font-size:9.5px; font-weight:700; padding:2px 8px; border-radius:5px; text-transform:uppercase; }
.b-open{ background:rgba(46,204,113,.16); color:var(--ok);} .b-res{ background:rgba(77,163,255,.16); color:var(--accent);} .b-aba{ background:rgba(138,144,154,.16); color:#8a909a;}
.warnbox{ background:rgba(243,156,18,.1); border:1px solid rgba(243,156,18,.3); color:#f0c674; border-radius:10px; padding:12px 14px; margin-bottom:14px; font-size:12.5px; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php if(!$sess): ?>
  <?php nm_page_header('<i class="fas fa-network-wired"></i>Adv. Solution Commander','','Device Operations','fa-solid fa-network-wired'); ?>
  <div class="glass card">Session not found. <a href="router_commander.php">← Back to sessions</a></div>
<?php else: $bcls=$sess['status']==='open'?'b-open':($sess['status']==='resolved'?'b-res':'b-aba'); ?>
  <?php nm_page_header('<i class="fas fa-network-wired"></i>Adv. Solution Commander','','Device Operations','fa-solid fa-network-wired',
    '<span class="badge '.$bcls.'" id="rc-state">'.htmlspecialchars($sess['status']).'</span>'
    .'<a class="refresh-btn" href="router_commander.php">← Sessions</a>'); ?>

  <?php if(!$suggestConfigured): ?><div class="warnbox"><b>rc_suggest_url not set.</b> Configure it in <a href="router_commander.php">Adv. Solution Commander → n8n webhooks</a> or the AI cannot respond.</div><?php endif; ?>
  <?php if($sess['transport']==='linux' && !$execConfigured): ?><div class="warnbox"><b>Linux target but rc_execute_url not set.</b> n8n cannot run bash commands until you configure it.</div><?php endif; ?>

  <div class="grid">
    <div>
      <div class="glass card">
        <h3><i class="fas fa-server"></i> Target</h3>
        <dl class="dl">
          <dt>Name</dt><dd><?= htmlspecialchars($sess['name']) ?></dd>
          <dt>Host</dt><dd><?= htmlspecialchars($sess['host']) ?></dd>
          <dt>Brand</dt><dd><?= htmlspecialchars($vlabel) ?></dd>
          <dt>Transport</dt><dd><span class="tp <?= $sess['transport']==='cli'?'tp-cli':($sess['transport']==='windows'?'tp-win':'tp-linux') ?>"><?= $sess['transport']==='cli'?'Router CLI · Python SSH':($sess['transport']==='windows'?'Windows · PowerShell over SSH':'Linux · n8n bash SSH') ?></span></dd>
        </dl>
      </div>
      <div class="glass card">
        <h3><i class="fas fa-bolt"></i> Actions</h3>
        <button class="btn ai" onclick="fixAct('suggest',this)"><i class="fas fa-wand-magic-sparkles"></i> Ask AI for a fix</button>
        <button class="btn ok" onclick="resolveSess()"><i class="fas fa-circle-check"></i> Resolve</button>
        <button class="btn" onclick="saveKb()"><i class="fas fa-book"></i> Save to KB</button>
        <button class="btn danger" onclick="abandonSess()"><i class="fas fa-ban"></i> Abandon</button>
        <button class="btn danger" onclick="resetSess()"><i class="fas fa-rotate-left"></i> Reset session</button>
      </div>
      <div id="prop-panel"></div>
    </div>
    <div>
      <div id="rc-busy" class="busy"><span class="spin"></span> <span id="rc-busy-txt">Working…</span></div>
      <div class="term" id="term"><div class="cv-line cv-info">Loading session…</div></div>
      <div class="manual">
        <input id="manual-cmd" placeholder="Type a command to run manually…" onkeydown="if(event.key==='Enter'){event.preventDefault();runManual();}">
        <button class="btn" style="width:auto;" onclick="explainManual()"><i class="fas fa-magnifying-glass"></i> Explain</button>
        <button class="btn ok" style="width:auto;" onclick="runManual()"><i class="fas fa-play"></i> Run</button>
      </div>
      <div class="composer">
        <textarea id="chat" rows="1" placeholder="Message the AI… (Enter to send, Shift+Enter newline)"
          onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMsg();}"></textarea>
        <button onclick="sendMsg()"><i class="fas fa-paper-plane"></i></button>
      </div>
    </div>
  </div>
<?php endif ?>
</div>

<?php if($sess): ?>
<script>
const ID=<?= $id ?>; const TRANSPORT=<?= json_encode($sess['transport']) ?>;
let after=0, lastPropId=0, lastId=0, polling=false, busyT=null;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
const term=document.getElementById('term');
function addLine(l){ const d=document.createElement('div'); d.className='cv-line cv-'+l.level; let t=l.line; if(l.level==='cmd'&&!t.startsWith('$ ')) t='$ '+t; d.textContent=t; term.appendChild(d); }
function busy(t){ const b=document.getElementById('rc-busy'); if(!b)return; document.getElementById('rc-busy-txt').textContent=t||'Working…'; b.style.display='inline-flex'; clearTimeout(busyT); busyT=setTimeout(unbusy,90000); }
function unbusy(){ const b=document.getElementById('rc-busy'); if(b) b.style.display='none'; clearTimeout(busyT); }
async function poll(){
    if(polling) return; polling=true;
    try{ const r=await fetch(`router_fix.php?api=data&id=${ID}&after=${after}&_=${Date.now()}`).then(r=>r.json());
        if(!r.ok) return;
        const near=term.scrollTop+term.clientHeight>=term.scrollHeight-50;
        if(after===0){ term.innerHTML=''; lastId=0; }
        let added=false;
        (r.lines||[]).forEach(l=>{ if(l.id>lastId){ addLine(l); lastId=l.id; added=true; } });   // dedup by id — kills the poll race
        if(r.max_id) after=r.max_id;
        if(!term.childNodes.length) term.innerHTML='<div class="cv-line cv-info">No session yet — click "Ask AI for a fix" or type a command.</div>';
        while(term.childNodes.length>4000) term.removeChild(term.firstChild);
        if(near) term.scrollTop=term.scrollHeight;
        const fs=document.getElementById('rc-state'); if(fs){ fs.textContent=r.status; fs.className='badge '+(r.status==='open'?'b-open':r.status==='resolved'?'b-res':'b-aba'); }
        renderProposal(r.proposal);
        if(added) unbusy();   // content arrived → stop the spinner
    }catch(e){} finally{ polling=false; }
}
function riskHtml(rk){
    if(!rk||rk.severity==='safe') return '';
    const cls=rk.severity==='destructive'?'risk-destructive':'risk-caution';
    const icon=rk.severity==='destructive'?'⛔ DESTRUCTIVE':'⚠ Caution';
    let h=`<div class="riskbox ${cls}"><b>${icon}</b>`;
    if(rk.reasons&&rk.reasons.length) h+='<br>'+rk.reasons.map(esc).join('; ');
    if(rk.affects&&rk.affects.length) h+='<br><span style="opacity:.85">Could affect: '+rk.affects.map(esc).join('; ')+'</span>';
    h+='</div>'; return h;
}
let curRisk=null;
function renderProposal(p){
    const panel=document.getElementById('prop-panel');
    if(!p){ panel.innerHTML=''; lastPropId=0; curRisk=null; return; }
    if(p.id===lastPropId && document.querySelector('.prop')) return;
    lastPropId=p.id; curRisk=p.risk||null;
    panel.innerHTML=`<div class="glass card prop ${p.risky?'is-risky':''}">
        <div class="rt"><i class="fas fa-wand-magic-sparkles"></i> AI proposes ${p.risky?'· ⚠ review':''}</div>
        ${p.rationale?`<div class="rat">${esc(p.rationale)}</div>`:''}
        <textarea id="prop-cmd" rows="2">${esc(p.command)}</textarea>
        ${riskHtml(p.risk)}
        <div style="display:flex;gap:7px;margin-top:9px;flex-wrap:wrap;">
            <button class="btn ok" style="width:auto;margin:0;" onclick="approveProp()"><i class="fas fa-check"></i> Approve &amp; run</button>
            <button class="btn" style="width:auto;margin:0;" onclick="explainProp()"><i class="fas fa-magnifying-glass"></i> Explain</button>
            <button class="btn danger" style="width:auto;margin:0;" onclick="dismissProp()"><i class="fas fa-xmark"></i> Reject</button>
        </div></div>`;
}
async function post(api,obj){ return fetch(`router_fix.php?api=${api}&id=${ID}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj||{})}).then(r=>r.json()).catch(()=>({ok:false,error:'failed'})); }
async function fixAct(api,btn){ if(btn)btn.disabled=true; busy('AI is thinking…'); const r=await post(api,{}); if(btn)btn.disabled=false; if(!r.ok){ unbusy(); if(r.error)alert(r.error); } poll(); }
function confirmRisk(rk){
    if(!rk||rk.severity!=='destructive') return true;
    return confirm('⛔ DESTRUCTIVE COMMAND\n\n'+(rk.reasons||[]).join('\n')+'\n\nCould affect:\n'+(rk.affects||[]).join('\n')+'\n\nRun it anyway?');
}
async function approveProp(){
    const cmd=document.getElementById('prop-cmd').value.trim(); if(!cmd)return;
    if(!confirmRisk(curRisk)) return;
    document.getElementById('prop-panel').innerHTML=''; lastPropId=0;
    busy(TRANSPORT==='cli'?'Running command on the device…':'Running command…');
    const r=await post('command',{command:cmd,ack:1,confirm:1}); if(!r.ok){ unbusy(); if(r.error)alert(r.error); } poll();
}
async function explainProp(){ const cmd=document.getElementById('prop-cmd').value.trim(); if(!cmd)return; busy('Explaining…'); const r=await post('explain',{command:cmd}); if(!r.ok){ unbusy(); if(r.error)alert(r.error); } poll(); }
async function dismissProp(){ document.getElementById('prop-panel').innerHTML=''; lastPropId=0; await post('dismiss',{}); poll(); }
async function runManual(){
    const el=document.getElementById('manual-cmd'); const cmd=el.value.trim(); if(!cmd)return;
    busy(TRANSPORT==='cli'?'Running command on the device…':'Running command…');
    let r=await post('command',{command:cmd});
    if(!r.ok && r.needs_confirm){ unbusy(); if(!confirmRisk(r.risk)) return; busy('Running command…'); r=await post('command',{command:cmd,confirm:1}); }
    if(!r.ok){ unbusy(); if(r.error)alert(r.error); } else el.value=''; poll();
}
async function explainManual(){ const el=document.getElementById('manual-cmd'); const cmd=el.value.trim(); if(!cmd)return; busy('Explaining…'); const r=await post('explain',{command:cmd}); if(!r.ok){ unbusy(); if(r.error)alert(r.error); } poll(); }
async function sendMsg(){ const el=document.getElementById('chat'); const m=el.value.trim(); if(!m)return; el.value=''; busy('AI is thinking…'); const r=await post('message',{message:m}); if(!r.ok){ unbusy(); if(r.error)alert(r.error); } poll(); }
async function resetSess(){ if(!confirm('Reset the session? Transcript is cleared (no AI contact).'))return; await post('reset',{}); after=0; lastPropId=0; document.getElementById('prop-panel').innerHTML=''; poll(); }
async function saveKb(){ const note=prompt('Resolution note for the KB (optional):')||''; const r=await post('save_kb',{note}); alert(r.ok?'Saved to Knowledge Base.':'Save failed (KB disabled or no data).'); }
async function resolveSess(){ const note=prompt('Resolution note (what fixed it):')||''; const r=await post('close',{action:'resolve',note}); if(r.ok){ alert('Marked resolved'+(r.kb_saved?' and saved to KB.':'.')); location.href='router_commander.php'; } }
async function abandonSess(){ if(!confirm('Abandon this session?'))return; const note=prompt('Reason (optional):')||''; const r=await post('close',{action:'abandon',note}); if(r.ok) location.href='router_commander.php'; }
poll(); setInterval(()=>{ if(!document.hidden) poll(); },2500);
</script>
<?php endif ?>
</body></html>
