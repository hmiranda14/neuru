<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Support module. Open & follow up support tickets and file bug reports
// (with this install's version + recent errors + diagnostics auto-attached) to the
// NEURU License Portal. Empathy-first: a real person answers, and you can track it
// right here or from your portal account. RBAC: 'support'. Engine: nm_support.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_support.php');
require_once('nm_audit.php');
include('logger.php');

if (!checkAccess($conn, 'support')) { header('Location: /denied_access.php?page=support'); exit; }

$e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
$CATS = ['support'=>'Support / question','bug'=>'Bug report','claim'=>'Claim / issue','billing'=>'Billing','feature'=>'Feature request','other'=>'Other'];
$PRIS = ['low'=>'Low','normal'=>'Normal','high'=>'High','urgent'=>'Urgent'];
$STMAP = ['open'=>'Open','pending'=>'Awaiting you','answered'=>'Answered','resolved'=>'Resolved','closed'=>'Closed'];
$flash = null; $flashType = 'ok';
$ready = nm_sup_ready($conn);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $do = $_POST['do'] ?? '';
    if ($do === 'new') {
        $r = nm_sup_create($conn, ['subject'=>$_POST['subject']??'', 'body'=>$_POST['body']??'', 'category'=>$_POST['category']??'support', 'priority'=>$_POST['priority']??'normal']);
        if (!empty($r['ok'])) { nm_audit($conn, 'support.open', ['ticket'=>(int)$r['ticket_id']]); header('Location: support.php?ticket='.(int)$r['ticket_id'].'&sent=1'); exit; }
        $flash = $r['error']; $flashType = 'err';
    } elseif ($do === 'bug') {
        $r = nm_sup_bug_report($conn, ($_POST['subject'] ?? '') !== '' ? $_POST['subject'] : 'Bug report from my NEURU', $_POST['body']??'', $_POST['priority']??'high', !empty($_POST['attach']), (string)($_POST['screenshot'] ?? ''));
        if (!empty($r['ok'])) { nm_audit($conn, 'support.bug', ['ticket'=>(int)$r['ticket_id']]); header('Location: support.php?ticket='.(int)$r['ticket_id'].'&sent=1'); exit; }
        $flash = $r['error']; $flashType = 'err';
    } elseif ($do === 'reply') {
        $tid = (int)($_POST['ticket_id'] ?? 0);
        $r = nm_sup_reply($conn, $tid, (string)($_POST['body'] ?? ''));
        if (!empty($r['ok'])) { header('Location: support.php?ticket='.$tid.'&sent=1'); exit; }
        $flash = $r['error']; $flashType = 'err';
    }
}
if (isset($_GET['sent'])) { $flash = 'Sent — a real person on our team will get back to you. 💙'; $flashType = 'ok'; }

$viewTid = (int)($_GET['ticket'] ?? 0);
$thread = null; $tickets = [];
if ($ready) {
    if ($viewTid > 0) { $g = nm_sup_get($conn, $viewTid); if (!empty($g['ok'])) $thread = $g; else { $flash = $g['error']; $flashType = 'err'; } }
    else { $l = nm_sup_list($conn); if (!empty($l['ok'])) $tickets = $l['tickets'] ?? []; else { $flash = $l['error']; $flashType = 'err'; } }
}
$diag = $ready ? nm_sup_diagnostics($conn) : [];
$errPreview = $ready ? nm_sup_recent_errors($conn, 12) : '';

include('header.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(12,16,26,.62); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; }
html{ background:#05080f; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent!important; color:#d4dce8; overflow-x:hidden; }
<?= nm_chrome_css() ?>
.sup{ max-width:1120px; margin:0 auto; padding:22px 20px 60px; }
.sup *{ box-sizing:border-box; }
.glass{ background:var(--glass); backdrop-filter:blur(13px); border:1px solid var(--border); border-radius:16px; }
.hero{ padding:24px 26px; margin-bottom:18px; }
.hero h1{ margin:0; font-size:26px; font-weight:800; display:flex; align-items:center; gap:12px; }
.hero p{ color:#8b95a7; font-size:14px; margin:8px 0 0; }
.grid{ display:grid; grid-template-columns:1.15fr .85fr; gap:18px; align-items:start; } @media(max-width:900px){ .grid{ grid-template-columns:1fr; } }
.card{ padding:20px; }
.ctitle{ font-size:16px; font-weight:700; display:flex; align-items:center; gap:9px; margin-bottom:14px; }
.fld{ margin-bottom:13px; } .fld label{ display:block; font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:#8b95a7; margin-bottom:5px; }
.fld input,.fld select,.fld textarea{ width:100%; background:rgba(255,255,255,.05); border:1px solid var(--border); border-radius:9px; color:#e6edf7; padding:10px 12px; font-size:14px; font-family:inherit; }
.fld input:focus,.fld textarea:focus,.fld select:focus{ outline:none; border-color:var(--accent); }
.row2{ display:flex; gap:10px; } .row2 .fld{ flex:1; }
.btn{ background:linear-gradient(135deg,#4da3ff,#6a5cff); border:none; color:#fff; border-radius:10px; padding:11px 18px; font-size:14px; font-weight:600; cursor:pointer; }
.btn.ghost{ background:transparent; border:1px solid var(--border); color:#bcd8ff; } .btn:hover{ filter:brightness(1.08); }
.tabs{ display:flex; gap:8px; margin-bottom:16px; } .tab{ padding:8px 16px; border-radius:10px; border:1px solid var(--border); color:#bcd8ff; cursor:pointer; font-size:13.5px; font-weight:600; background:transparent; }
.tab.on{ background:rgba(77,163,255,.16); border-color:rgba(77,163,255,.5); color:#dbeaff; }
.flash{ padding:12px 15px; border-radius:11px; margin-bottom:16px; font-size:13.5px; display:flex; gap:9px; align-items:center; }
.flash.ok{ background:rgba(46,204,113,.14); border:1px solid rgba(46,204,113,.4); color:#8fe6b4; } .flash.err{ background:rgba(231,76,60,.14); border:1px solid rgba(231,76,60,.4); color:#ff9d92; }
.tk{ display:block; text-decoration:none; color:inherit; padding:11px 13px; border:1px solid var(--border); border-radius:11px; margin-bottom:9px; }
.tk:hover{ border-color:rgba(77,163,255,.4); } .tk .s{ font-weight:600; font-size:13.5px; } .tk .m{ color:#8b95a7; font-size:11.5px; margin-top:3px; }
.pill{ font-size:11px; padding:3px 9px; border-radius:20px; background:rgba(255,255,255,.06); border:1px solid var(--border); color:#c7d0de; }
.pill.new{ background:rgba(46,204,113,.16); color:#8fe6b4; border-color:rgba(46,204,113,.4); }
.msgs{ display:flex; flex-direction:column; gap:12px; margin:16px 0; }
.bub{ max-width:82%; border-radius:12px; padding:11px 14px; font-size:13.5px; line-height:1.55; white-space:pre-wrap; }
.bub.me{ align-self:flex-end; background:rgba(77,163,255,.12); border:1px solid rgba(77,163,255,.25); }
.bub.them{ align-self:flex-start; background:rgba(84,240,200,.08); border:1px solid rgba(84,240,200,.28); }
.bub .who{ font-size:11px; color:#8b95a7; margin-bottom:4px; }
.bub pre{ font-size:11px; max-height:280px; overflow:auto; white-space:pre-wrap; margin:0; color:#cdd6e2; }
.diag{ font-size:11.5px; color:#8b95a7; background:rgba(255,255,255,.03); border:1px solid var(--border); border-radius:9px; padding:10px 12px; margin-top:10px; }
.muted{ color:#8b95a7; } .hint{ font-size:11.5px; color:#6f7a8c; margin-top:8px; }
</style>

<div class="sup">
  <div class="hero glass">
    <h1><i class="fa-solid fa-life-ring" style="color:#54f0c8"></i> Support &amp; bug reports</h1>
    <p>Open a ticket or report a bug — we auto-attach your NEURU version, recent errors &amp; a health snapshot so we can help you <b>fast</b>. Track everything here or in your portal account. We're customer-obsessed. 💙</p>
  </div>

  <?php if ($flash): ?><div class="flash <?= $flashType ?>"><i class="fa-solid fa-<?= $flashType==='ok'?'circle-check':'triangle-exclamation' ?>"></i><div><?= $e($flash) ?></div></div><?php endif; ?>

  <?php if (!$ready): ?>
    <div class="glass card">
      <div class="ctitle"><i class="fa-solid fa-key" style="color:#f39c12"></i> Activate to open tickets</div>
      <p class="muted" style="font-size:13.5px;margin:0">Support tickets link to your portal account via your license key. Activate your license first — then come back here.</p>
      <a class="btn" href="license.php" style="display:inline-block;margin-top:14px;text-decoration:none"><i class="fa-solid fa-id-badge"></i> Go to License</a>
    </div>

  <?php elseif ($thread && !empty($thread['ticket'])): $t = $thread['ticket']; ?>
    <a href="support.php" class="muted" style="text-decoration:none;font-size:13px"><i class="fa-solid fa-arrow-left"></i> All tickets</a>
    <div class="glass card" style="margin-top:12px">
      <div style="display:flex;gap:9px;align-items:center;flex-wrap:wrap">
        <div class="ctitle" style="margin:0">#<?= (int)$t['id'] ?> · <?= $e($t['subject']) ?></div>
        <span class="pill"><?= $e($CATS[$t['category']] ?? $t['category']) ?></span>
        <span class="pill"><?= $e($STMAP[$t['status']] ?? $t['status']) ?></span>
      </div>
      <div class="msgs">
        <?php foreach (($thread['messages'] ?? []) as $m): $me = ($m['author']??'')==='customer'; ?>
          <div class="bub <?= $me?'me':'them' ?>">
            <div class="who"><?= $me?'You':(($m['author']??'')==='staff'?'🎧 NEURU Support':'System') ?> · <?= $e(substr((string)($m['at']??''),0,16)) ?><?= ($m['kind']??'message')!=='message'?(' · <b>'.$e($m['kind']).'</b>'):'' ?></div>
            <?php if (($m['kind']??'message')==='message'): ?><?= nl2br($e($m['body']??'')) ?><?php else: ?><pre><?= $e(mb_substr((string)($m['body']??''),0,20000)) ?></pre><?php endif; ?>
          </div>
        <?php endforeach; ?>
      </div>
      <?php if (($t['status']??'') !== 'closed'): ?>
      <form method="post">
        <input type="hidden" name="do" value="reply"><input type="hidden" name="ticket_id" value="<?= (int)$t['id'] ?>">
        <div class="fld"><textarea name="body" rows="3" placeholder="Reply to our team…" required></textarea></div>
        <button class="btn"><i class="fa-solid fa-paper-plane"></i> Send reply</button>
      </form>
      <?php else: ?><div class="muted" style="font-size:13px">This ticket is closed — open a new one anytime.</div><?php endif; ?>
    </div>

  <?php else: ?>
    <div class="grid">
      <div class="glass card">
        <div class="tabs"><button class="tab on" data-t="ask" type="button">Open a ticket</button><button class="tab" data-t="bug" type="button">Report a bug</button></div>

        <form method="post" id="pane-ask">
          <input type="hidden" name="do" value="new">
          <div class="fld"><label>Subject</label><input name="subject" maxlength="200" required placeholder="Brief summary of your question or issue"></div>
          <div class="row2">
            <div class="fld"><label>Category</label><select name="category"><?php foreach ($CATS as $k=>$v): if($k==='bug') continue; ?><option value="<?= $k ?>"><?= $e($v) ?></option><?php endforeach; ?></select></div>
            <div class="fld"><label>Priority</label><select name="priority"><?php foreach ($PRIS as $k=>$v): ?><option value="<?= $k ?>" <?= $k==='normal'?'selected':'' ?>><?= $e($v) ?></option><?php endforeach; ?></select></div>
          </div>
          <div class="fld"><label>How can we help?</label><textarea name="body" rows="5" required placeholder="The more detail, the faster we can help you."></textarea></div>
          <button class="btn"><i class="fa-solid fa-paper-plane"></i> Open ticket</button>
        </form>

        <form method="post" id="pane-bug" style="display:none">
          <input type="hidden" name="do" value="bug">
          <div class="fld"><label>What went wrong?</label><input name="subject" maxlength="200" required placeholder="e.g. Poller crashes after the last update"></div>
          <div class="fld"><label>Priority</label><select name="priority"><?php foreach ($PRIS as $k=>$v): ?><option value="<?= $k ?>" <?= $k==='high'?'selected':'' ?>><?= $e($v) ?></option><?php endforeach; ?></select></div>
          <div class="fld"><label>Describe the bug</label><textarea name="body" rows="5" required placeholder="What did you do, what happened, what did you expect?"></textarea></div>
          <label style="display:flex;gap:9px;align-items:center;font-size:13px;color:#c7d0de;margin-bottom:12px"><input type="checkbox" name="attach" value="1" checked> Attach my recent errors &amp; diagnostics (recommended)</label>
          <div class="fld">
            <label>Screenshot <span class="muted" style="font-weight:400">(optional — a picture helps us a lot)</span></label>
            <input type="file" id="bug-shot" accept="image/png,image/jpeg,image/webp">
            <input type="hidden" name="screenshot" id="bug-shot-data">
            <div id="bug-shot-prev" style="margin-top:8px;display:none">
              <img id="bug-shot-img" style="max-width:100%;max-height:200px;border-radius:8px;border:1px solid var(--border);display:block">
              <div style="display:flex;gap:10px;align-items:center;margin-top:5px"><span class="muted" id="bug-shot-meta" style="font-size:11px"></span><a href="#" id="bug-shot-clear" style="font-size:11px;color:#e0736b">remove</a></div>
            </div>
          </div>
          <div class="diag"><b style="color:#c7d0de">Auto-attached:</b> NEURU <?= $e($diag['neuru_version']??'?') ?> · PHP <?= $e($diag['php']??'?') ?> · <?= (int)($diag['nodes']??0) ?> nodes · <?= (int)($diag['open_incidents']??0) ?> open incidents<?php if($errPreview!==''): ?><br><span class="muted">+ last errors from your NEURU log</span><?php endif; ?></div>
          <button class="btn" style="margin-top:12px"><i class="fa-solid fa-bug"></i> Send bug report</button>
          <div class="hint"><i class="fa-solid fa-shield-halved"></i> We only send what you see above — your version, recent error lines &amp; counts. No secrets, no config.</div>
          <script>
          (function(){
            var inp=document.getElementById('bug-shot'), hid=document.getElementById('bug-shot-data'),
                prev=document.getElementById('bug-shot-prev'), img=document.getElementById('bug-shot-img'),
                meta=document.getElementById('bug-shot-meta'), clr=document.getElementById('bug-shot-clear');
            if(!inp) return;
            inp.addEventListener('change', function(){
              var f=inp.files&&inp.files[0]; if(!f) return;
              if(!/^image\//.test(f.type)){ alert('Please choose an image file.'); inp.value=''; return; }
              var fr=new FileReader();
              fr.onload=function(){
                var im=new Image();
                im.onload=function(){
                  // downscale to keep the payload small (a raw screenshot can be several MB)
                  var max=1600, w=im.width, h=im.height;
                  if(w>max||h>max){ var s=Math.min(max/w,max/h); w=Math.round(w*s); h=Math.round(h*s); }
                  var c=document.createElement('canvas'); c.width=w; c.height=h;
                  c.getContext('2d').drawImage(im,0,0,w,h);
                  var uri=c.toDataURL('image/jpeg',0.82);
                  hid.value=uri; img.src=uri; prev.style.display='';
                  meta.textContent=Math.round(uri.length/1024)+' KB · '+w+'×'+h;
                };
                im.onerror=function(){ alert('Could not read that image.'); inp.value=''; };
                im.src=fr.result;
              };
              fr.readAsDataURL(f);
            });
            clr.addEventListener('click', function(e){ e.preventDefault(); inp.value=''; hid.value=''; prev.style.display='none'; });
          })();
          </script>
        </form>
      </div>

      <div class="glass card">
        <div class="ctitle"><i class="fa-solid fa-inbox" style="color:#4da3ff"></i> Your tickets</div>
        <?php if (!$tickets): ?><div class="muted" style="font-size:13px">No tickets yet — open one or report a bug on the left. We're glad to help.</div>
        <?php else: foreach ($tickets as $t): ?>
          <a class="tk" href="support.php?ticket=<?= (int)$t['id'] ?>">
            <div style="display:flex;gap:8px;align-items:center"><span class="s" style="flex:1"><?= $e($t['subject']) ?></span>
              <?php if (!empty($t['unread'])): ?><span class="pill new">new reply</span><?php endif; ?>
              <span class="pill"><?= $e($STMAP[$t['status']] ?? $t['status']) ?></span></div>
            <div class="m">#<?= (int)$t['id'] ?> · <?= $e($CATS[$t['category']] ?? $t['category']) ?> · updated <?= $e(substr((string)($t['updated_at']??''),0,16)) ?></div>
          </a>
        <?php endforeach; endif; ?>
      </div>
    </div>
  <?php endif; ?>
</div>

<script>
document.querySelectorAll('.tab').forEach(b=>b.addEventListener('click',()=>{
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('on')); b.classList.add('on');
  var t=b.getAttribute('data-t');
  document.getElementById('pane-ask').style.display = t==='ask'?'':'none';
  document.getElementById('pane-bug').style.display = t==='bug'?'':'none';
}));
document.addEventListener('DOMContentLoaded',()=>{ if(window.NMLoader) NMLoader.hide(); });
</script>
</body></html>
