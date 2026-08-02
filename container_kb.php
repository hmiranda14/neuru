<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — Containers: Knowledge Base browser. Lists container_kb (captured fixes),
// re-vectorize / delete. RBAC: 'containers'.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_solutionkb.php');
require_once('nm_chrome.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'containers')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=containers'); exit;
}
function kbs($conn,$k,$d=''){ $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; }

if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    $b = json_decode(file_get_contents('php://input'), true) ?? $_POST;
    if ($api === 'revectorize') {
        $kid=(int)($b['id'] ?? 0); if(!$kid){ echo json_encode(['ok'=>false,'error'=>'bad id']); exit; }
        if(kbs($conn,'kb_ingest_url','')===''){ echo json_encode(['ok'=>false,'error'=>'No kb_ingest_url']); exit; }
        $ok=nm_kb_push($conn,$kid);
        echo json_encode(['ok'=>$ok,'error'=>$ok?null:'Push failed']); exit;
    }
    if ($api === 'delete') {
        $kid=(int)($b['id'] ?? 0); if($kid){ $conn->query("DELETE FROM container_kb WHERE id={$kid}"); nm_audit($conn,'kb.delete',['target_type'=>'container_kb','target_id'=>$kid]); }
        echo json_encode(['ok'=>true]); exit;
    }
    if ($api === 'bulk_delete') {
        // all=true → delete EVERYTHING matching the current search filter (not just the 200 shown);
        // otherwise delete the explicitly selected ids. n8n prunes its own vector store separately.
        if (!empty($b['all'])) {
            $qq = trim((string)($b['q'] ?? '')); $w='';
            if ($qq!=='') { $e=$conn->real_escape_string($qq); $w="WHERE container_name LIKE '%$e%' OR error_text LIKE '%$e%' OR summary LIKE '%$e%'"; }
            $conn->query("DELETE FROM container_kb {$w}"); $n=$conn->affected_rows;
            nm_audit($conn,'kb.bulk_delete',['details'=>['all'=>true,'q'=>$qq,'deleted'=>$n]]);
            echo json_encode(['ok'=>true,'deleted'=>$n]); exit;
        }
        $ids = array_values(array_filter(array_map('intval',(array)($b['ids']??[])), fn($x)=>$x>0));
        if(!$ids){ echo json_encode(['ok'=>false,'error'=>'No entries selected']); exit; }
        $ids = array_slice($ids,0,2000); $in=implode(',',$ids);
        $conn->query("DELETE FROM container_kb WHERE id IN ({$in})"); $n=$conn->affected_rows;
        nm_audit($conn,'kb.bulk_delete',['details'=>['selected'=>count($ids),'deleted'=>$n]]);
        echo json_encode(['ok'=>true,'deleted'=>$n]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'Unknown']); exit;
}

$q = trim($_GET['q'] ?? '');
$where = '';
if ($q !== '') { $e=$conn->real_escape_string($q); $where="WHERE container_name LIKE '%$e%' OR error_text LIKE '%$e%' OR summary LIKE '%$e%'"; }
$entries = $conn->query("SELECT * FROM container_kb {$where} ORDER BY id DESC LIMIT 200")->fetch_all(MYSQLI_ASSOC);
$matchTotal = (int)$conn->query("SELECT COUNT(*) c FROM container_kb {$where}")->fetch_assoc()['c'];   // all rows matching the current search (for "Delete all")
$stats = ['total'=>0,'vectorized'=>0,'pending'=>0];
$sr = $conn->query("SELECT COUNT(*) t, SUM(vectorized_at IS NOT NULL) v FROM container_kb")->fetch_assoc();
$stats['total']=(int)$sr['t']; $stats['vectorized']=(int)$sr['v']; $stats['pending']=$stats['total']-$stats['vectorized'];
$kbEnabled = kbs($conn,'kb_enabled','1')!=='0';
$ingestConfigured = kbs($conn,'kb_ingest_url','')!=='';
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
log_user_action($conn, 'view_page', 'container_kb.php');
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><title>Container Knowledge Base | SG-PR Console</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --docker:#0db7ed; --ok:#2ecc71; --warn:#f39c12; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.22; }
.wrap{ max-width:1100px; margin:0 auto; padding:18px 20px 50px; } a{ color:var(--accent); text-decoration:none; }
.ctr-head{ display:flex; align-items:center; gap:14px; flex-wrap:wrap; margin-bottom:14px; }
.ctr-head h1{ margin:0; font-size:22px; font-weight:700; } .ctr-head h1 i{ color:var(--docker); }
.subnav{ display:flex; gap:4px; flex-wrap:wrap; margin-bottom:16px; border-bottom:1px solid var(--border); }
.subnav a{ padding:8px 13px; font-size:13px; color:#9aa; border-bottom:2px solid transparent; }
.subnav a.is-active{ color:var(--docker); border-bottom-color:var(--docker); font-weight:600; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.stat-grid{ display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:12px; margin-bottom:16px; }
.stat{ padding:12px 16px; } .stat .n{ font-size:23px; font-weight:800; } .stat .l{ font-size:10px; text-transform:uppercase; letter-spacing:1px; color:#888; margin-top:3px; }
.stat .n.ok{ color:var(--ok);} .stat .n.warn{ color:var(--warn);}
.searchbar{ display:flex; gap:8px; margin-bottom:16px; } input[type=text]{ flex:1; background:rgba(0,0,0,.4); border:1px solid var(--border); color:#ddd; border-radius:8px; padding:8px 12px; font-size:13px; }
.fbtn{ background:rgba(255,255,255,.05); border:1px solid var(--border); color:#aaa; padding:7px 14px; border-radius:8px; cursor:pointer; font-size:12px; }
.kb{ padding:14px 16px; margin-bottom:12px; }
.kb .top{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
.kb .name{ font-weight:700; font-size:14px; } .kb .meta{ font-size:11px; color:#7c828c; margin-left:auto; }
.vb{ font-size:9.5px; font-weight:700; padding:2px 8px; border-radius:5px; text-transform:uppercase; }
.vb.ok{ background:rgba(46,204,113,.16); color:var(--ok);} .vb.pend{ background:rgba(243,156,18,.16); color:var(--warn);}
.errbox{ background:rgba(231,76,60,.06); border:1px solid rgba(231,76,60,.18); border-radius:8px; padding:8px 11px; font-family:Consolas,monospace; font-size:11px; color:#e0a59f; margin-top:9px; white-space:pre-wrap; max-height:90px; overflow:auto; }
details.res{ margin-top:8px; } details.res summary{ cursor:pointer; color:#9bd; font-size:12px; }
.res pre{ background:rgba(0,0,0,.4); border:1px solid var(--border); border-radius:8px; padding:10px; font-size:11.5px; color:#bce; white-space:pre-wrap; margin:6px 0 0; }
.acts{ display:flex; gap:7px; margin-top:10px; }
.act{ background:rgba(255,255,255,.05); border:1px solid var(--border); color:#bbb; padding:5px 11px; border-radius:7px; cursor:pointer; font-size:11px; }
.act:hover{ background:rgba(255,255,255,.12); color:#fff; } .act.del:hover{ border-color:#e74c3c; color:#e74c3c; }
.empty{ text-align:center; color:#667; padding:50px 20px; } .empty i{ font-size:38px; color:#333; display:block; margin-bottom:12px; }
.kbchk{ width:16px; height:16px; accent-color:var(--accent); cursor:pointer; flex:0 0 auto; }
#kbbulk{ display:flex; align-items:center; gap:12px; flex-wrap:wrap; padding:10px 14px; margin-bottom:14px; }
#kbbulk .selall{ display:flex; align-items:center; gap:8px; font-size:12.5px; color:#cdd3db; cursor:pointer; user-select:none; }
#kbbulk .selall input{ width:16px; height:16px; accent-color:var(--accent); cursor:pointer; }
#kbbulk .selcount{ font-size:12px; color:#8a93a0; }
#kbbulk .act[disabled]{ opacity:.4; pointer-events:none; }
.act.arm{ border-color:#e74c3c!important; color:#e74c3c!important; background:rgba(231,76,60,.12)!important; }
#nm-toast{ position:fixed; right:20px; bottom:20px; z-index:9999; display:flex; flex-direction:column; gap:8px; pointer-events:none; }
.nm-toast{ background:rgba(20,28,44,.96); border:1px solid var(--border); border-left:3px solid var(--ok); color:#e6ecf7; padding:11px 15px; border-radius:10px; font-size:13px; box-shadow:0 8px 30px rgba(0,0,0,.5); max-width:340px; opacity:0; transform:translateY(8px); transition:opacity .25s, transform .25s; }
.nm-toast.show{ opacity:1; transform:none; } .nm-toast.err{ border-left-color:#e74c3c; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
    <?php nm_page_header('<i class="fas fa-book"></i>Knowledge Base', '', 'Container Operations', 'fa-brands fa-docker',
        '<span class="header-meta" style="color:'.($kbEnabled?'#2ecc71':'#888').';"><i class="fas fa-circle" style="font-size:7px;"></i> Recall '.($kbEnabled?'on':'off').'</span>'); ?>
    <?php nm_container_tabs('knowledge'); ?>
    <div class="stat-grid">
        <div class="glass stat"><div class="n"><?= $stats['total'] ?></div><div class="l">Total</div></div>
        <div class="glass stat"><div class="n ok"><?= $stats['vectorized'] ?></div><div class="l">Vectorized</div></div>
        <div class="glass stat"><div class="n warn"><?= $stats['pending'] ?></div><div class="l">Pending</div></div>
    </div>
    <form class="searchbar" method="get">
        <input type="text" name="q" value="<?= htmlspecialchars($q) ?>" placeholder="Search container / error / summary…">
        <button class="fbtn" type="submit"><i class="fas fa-search"></i></button>
        <?php if ($q): ?><a class="fbtn" href="container_kb.php">Clear</a><?php endif ?>
    </form>
    <?php if (!$entries): ?>
    <div class="glass empty"><i class="fas fa-book"></i>
        <div>No knowledge yet. Resolve a fix or click <b>Save to Knowledge Base</b> in the Solution Commander.</div></div>
    <?php else: ?>
    <div id="kbbulk" class="glass">
        <label class="selall"><input type="checkbox" id="selAll" onclick="toggleAll(this.checked)"> Select all shown (<span id="selAllN">0</span>)</label>
        <span class="selcount" id="selCount">0 selected</span>
        <span style="flex:1"></span>
        <button class="act del" id="btnDelSel" onclick="armOrRun(this,()=>bulkDelete('sel'))" disabled><i class="fas fa-trash"></i> Delete selected</button>
        <button class="act del" id="btnDelAll" onclick="armOrRun(this,()=>bulkDelete('all'))"><i class="fas fa-trash-can"></i> Delete all<?= $q!=='' ? ' matching' : '' ?> (<?= $matchTotal ?>)</button>
    </div>
    <?php foreach ($entries as $e): $vec=$e['vectorized_at']!==null; ?>
    <div class="glass kb" data-id="<?= (int)$e['id'] ?>">
        <div class="top">
            <input type="checkbox" class="kbchk" data-id="<?= (int)$e['id'] ?>" onclick="toggleSel(<?= (int)$e['id'] ?>,this.checked)">
            <span class="name"><?= htmlspecialchars($e['container_name'] ?: 'unknown') ?></span>
            <?php if ($e['severity']): ?><span class="vb pend" style="background:rgba(231,76,60,.14);color:#e74c3c;"><?= htmlspecialchars($e['severity']) ?></span><?php endif ?>
            <span class="vb <?= $vec?'ok':'pend' ?>"><?= $vec?'vectorized':'pending' ?></span>
            <span class="meta">reuse ×<?= (int)$e['reuse_count'] ?> · <?= htmlspecialchars(function_exists('nm_local') ? nm_local($e['updated_at'],'Y-m-d H:i') : substr($e['updated_at'],0,16)) ?><?php if($vec): ?> · vec <?= htmlspecialchars(function_exists('nm_local') ? nm_local($e['vectorized_at'],'H:i') : substr($e['vectorized_at'],11,5)) ?><?php endif ?> · <?= htmlspecialchars($e['source']) ?></span>
        </div>
        <?php if ($e['summary']): ?><div style="font-size:13px;color:#cdd;margin-top:8px;"><?= htmlspecialchars($e['summary']) ?></div><?php endif ?>
        <?php if ($e['error_text']): ?><div class="errbox"><?= htmlspecialchars(mb_substr($e['error_text'],0,400)) ?></div><?php endif ?>
        <?php if ($e['resolution']): ?><details class="res"><summary>Resolution</summary><pre><?= htmlspecialchars($e['resolution']) ?></pre></details><?php endif ?>
        <div class="acts">
            <?php if ($e['incident_id']): ?><a class="act" href="container_fix.php?id=<?= (int)$e['incident_id'] ?>"><i class="fas fa-up-right-from-square"></i> Incident</a><?php endif ?>
            <button class="act" onclick="revec(<?= (int)$e['id'] ?>,this)"<?= $ingestConfigured?'':' disabled title="Set kb_ingest_url"' ?>><i class="fas fa-rotate"></i> Re-vectorize</button>
            <button class="act del" onclick="delKb(<?= (int)$e['id'] ?>)"><i class="fas fa-trash"></i></button>
        </div>
    </div>
    <?php endforeach; endif ?>
</div>
<script>
async function revec(id,btn){ btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> sending';
    const r=await fetch('container_kb.php?api=revectorize',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}).then(r=>r.json()).catch(()=>({ok:false}));
    btn.innerHTML=r.ok?'<i class="fas fa-check"></i> sent':'<i class="fas fa-rotate"></i> Re-vectorize'; if(!r.ok&&r.error)alert(r.error); setTimeout(()=>btn.disabled=false,1500); }
async function delKb(id){ if(!confirm('Delete this KB entry? (n8n prunes its vector store separately)'))return;
    await fetch('container_kb.php?api=delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});
    document.querySelector(`.kb[data-id="${id}"]`)?.remove(); selIds.delete(String(id)); updateBulk(); }

// ── bulk select + delete ───────────────────────────────────────────────────
const selIds=new Set();
function toast(msg,isErr){ let box=document.getElementById('nm-toast'); if(!box){ box=document.createElement('div'); box.id='nm-toast'; document.body.appendChild(box); }
    const t=document.createElement('div'); t.className='nm-toast'+(isErr?' err':''); t.textContent=msg; box.appendChild(t);
    requestAnimationFrame(()=>t.classList.add('show')); setTimeout(()=>{ t.classList.remove('show'); setTimeout(()=>t.remove(),300); },4000); }
function toggleSel(id,on){ if(on) selIds.add(String(id)); else selIds.delete(String(id)); updateBulk(); }
function toggleAll(on){ document.querySelectorAll('.kbchk').forEach(c=>{ c.checked=on; if(on) selIds.add(c.dataset.id); else selIds.delete(c.dataset.id); }); updateBulk(); }
function updateBulk(){ const total=document.querySelectorAll('.kbchk').length; const n=selIds.size;
    const an=document.getElementById('selAllN'); if(an) an.textContent=total;
    const sc=document.getElementById('selCount'); if(sc) sc.textContent=n+' selected';
    const bs=document.getElementById('btnDelSel'); if(bs) bs.disabled=n===0;
    const sa=document.getElementById('selAll'); if(sa){ sa.checked=n>0&&n===total; sa.indeterminate=n>0&&n<total; } }
// destructive → arm on first click, run on the second (dialog-free, can't be silently blocked)
function armOrRun(btn,run){ if(btn.dataset.armed==='1'){ btn.dataset.armed=''; btn.classList.remove('arm'); clearTimeout(btn._t); run(); return; }
    const o=btn.innerHTML; btn.dataset.armed='1'; btn.classList.add('arm'); btn.innerHTML='<i class="fas fa-triangle-exclamation"></i> Click again to confirm';
    clearTimeout(btn._t); btn._t=setTimeout(()=>{ btn.dataset.armed=''; btn.classList.remove('arm'); btn.innerHTML=o; },3500); }
async function bulkDelete(mode){
    let body;
    if(mode==='all'){ body={all:true,q:<?= json_encode($q) ?>}; }
    else { const ids=[...selIds]; if(!ids.length){ toast('Select at least one entry first.',true); return; } body={ids}; }
    let r; try{ r=await fetch('container_kb.php?api=bulk_delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(x=>x.json()); }catch(e){ r={ok:false,error:'network/parse error'}; }
    if(!r||!r.ok){ toast('Delete failed: '+((r&&r.error)||'unknown'),true); return; }
    toast('🗑️ Deleted '+r.deleted+' KB entr'+(r.deleted===1?'y':'ies')+'.');
    setTimeout(()=>location.reload(),700);
}
updateBulk();
</script>
</body></html>
