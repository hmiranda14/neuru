<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU Data Vault — the cockpit. Keep the database from growing forever, take &
// restore backups, clean up or start fresh — from one place. Tabs: Skyline (live
// size + forecast), Retention (per-category sliders w/ INSTANT freed-space preview),
// Backups (forge/schedule/download/restore), Cleanup (one-shot + reclaim + molt),
// Autopilot (keep under N GB). RBAC 'vault'. Engines: nm_vault.php + nm_vault_backup.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_vault.php');
require_once('nm_vault_backup.php');
require_once('nm_audit.php');
include('logger.php');

if (!checkAccess($conn, 'vault')) { header('Location: /denied_access.php?page=vault'); exit; }
if (function_exists('session_write_close')) session_write_close();

$e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
function nm_v_by() { return function_exists('nm_current_user') ? (nm_current_user()['username'] ?? 'admin') : 'admin'; }

// ── API ───────────────────────────────────────────────────────────────────────
if (isset($_GET['api'])) {
    $api = $_GET['api'];
    // download streams a file (not JSON)
    if ($api === 'backup_download') {
        $b = nm_vault_backup_get($conn, (int)($_GET['id'] ?? 0));
        if (!$b || empty($b['path']) || !is_file($b['path'])) { http_response_code(404); exit('not found'); }
        nm_audit($conn, 'vault.backup_download', ['id' => (int)$b['id']]);
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($b['filename'] ?: $b['path']) . '"');
        header('Content-Length: ' . filesize($b['path']));
        header('Cache-Control: no-store');
        readfile($b['path']); exit;
    }
    header('Content-Type: application/json; charset=utf-8');
    $POST = $_SERVER['REQUEST_METHOD'] === 'POST';
    try {
        switch ($api) {
            case 'stats': {
                $s = nm_vault_stats_cached($conn, isset($_GET['fresh']) ? 0 : 600);
                $f = nm_vault_forecast($conn);
                // slim payload for the UI
                $cats = [];
                foreach ($s['categories'] as $k => $c) {
                    $cats[$k] = ['label'=>$c['label'],'icon'=>$c['icon'],'keep_days'=>$c['keep_days'],'enabled'=>$c['enabled'],
                        'rows'=>$c['rows'],'bytes'=>$c['bytes'],'oldest'=>$c['oldest'],'min_ts'=>$c['min_ts']??null,'max_ts'=>$c['max_ts']??time(),
                        'freeable_bytes'=>$c['freeable_bytes'],'freeable_rows'=>$c['freeable_rows'],
                        'lean'=>$c['lean'],'balanced'=>$c['balanced'],'compliance'=>$c['compliance'],'setting_key'=>$c['setting_key']];
                }
                echo json_encode(['ok'=>true,'total_bytes'=>$s['total_bytes'],'freeable_bytes'=>$s['freeable_bytes'],
                    'freeable_rows'=>$s['freeable_rows'],'cached'=>$s['cached']??false,'categories'=>$cats,'forecast'=>$f,
                    'preset'=>nm_vault_get($conn,'vault_preset',''),
                    'autopilot'=>['on'=>(int)nm_vault_get($conn,'vault_autopilot',0),'budget_gb'=>(float)nm_vault_get($conn,'vault_size_budget_gb',0),'reclaim'=>(int)nm_vault_get($conn,'vault_autopilot_reclaim',0)],
                    'schedule'=>['freq'=>(int)nm_vault_get($conn,'vault_backup_freq_days',0),'kind'=>nm_vault_get($conn,'vault_backup_kind','full'),'target'=>nm_vault_get($conn,'vault_backup_target','local'),'keep'=>(int)nm_vault_get($conn,'vault_backup_keep',7)]]);
                exit;
            }
            case 'set_retention': {
                if (!$POST) throw new Exception('POST');
                $cat=(string)($_POST['category']??''); $days=(int)($_POST['days']??30);
                $en = isset($_POST['enabled']) ? (int)$_POST['enabled'] : null;
                $ok = nm_vault_set_retention($conn,$cat,$days,$en);
                if ($ok) nm_audit($conn,'vault.set_retention',['category'=>$cat,'days'=>$days]);
                echo json_encode(['ok'=>$ok]); exit;
            }
            case 'preset': {
                if (!$POST) throw new Exception('POST');
                $ok = nm_vault_apply_preset($conn,(string)($_POST['preset']??''));
                if ($ok) nm_audit($conn,'vault.preset',['preset'=>$_POST['preset']??'']);
                echo json_encode(['ok'=>$ok]); exit;
            }
            case 'prune': {
                if (!$POST) throw new Exception('POST');
                $cat = $_POST['category']??null; $cat = $cat!==''?$cat:null;
                $r = nm_vault_prune($conn,['category'=>$cat,'max_seconds'=>25]);
                nm_audit($conn,'vault.prune',['category'=>$cat,'freed'=>$r['freed_rows']]);
                nm_vault_stats_cached($conn,0,true);
                echo json_encode(['ok'=>true]+$r); exit;
            }
            case 'cleanup': {
                if (!$POST) throw new Exception('POST');
                $cat=$_POST['category']??null; $cat=$cat!==''?$cat:null; $days=(int)($_POST['days']??30); $dry=!empty($_POST['dry']);
                $r=nm_vault_cleanup_older($conn,$cat,$days,$dry);
                if(!$dry){ nm_audit($conn,'vault.cleanup',['category'=>$cat,'days'=>$days,'freed'=>$r['freed_rows']]); nm_vault_stats_cached($conn,0,true); }
                echo json_encode(['ok'=>true]+$r); exit;
            }
            case 'reclaim': {
                if (!$POST) throw new Exception('POST');
                $cat=(string)($_POST['category']??''); $cats=nm_vault_categories();
                $tbls = $cat && isset($cats[$cat]) ? array_keys($cats[$cat][6]) : [];
                if (!$tbls) throw new Exception('pick a category');
                $r=nm_vault_reclaim($conn,$tbls); nm_audit($conn,'vault.reclaim',['category'=>$cat]);
                nm_vault_stats_cached($conn,0,true);
                echo json_encode(['ok'=>true]+$r); exit;
            }
            case 'molt': {
                if (!$POST) throw new Exception('POST');
                if (($_POST['confirm']??'')!=='MOLT') throw new Exception('type MOLT to confirm');
                $safety = nm_vault_backup_create($conn,'full',['auto'=>true,'by'=>nm_v_by(),'note'=>'pre-molt safety']);
                $r = nm_vault_molt($conn);
                nm_audit($conn,'vault.molt',['tables'=>count($r['truncated'])]);
                nm_vault_stats_cached($conn,0,true);
                echo json_encode(['ok'=>true,'safety_backup'=>$safety['id']??null,'truncated'=>count($r['truncated']),'errors'=>$r['errors']]); exit;
            }
            case 'autopilot_save': {
                if (!$POST) throw new Exception('POST');
                nm_vault_set($conn,'vault_size_budget_gb',(float)($_POST['budget_gb']??0));
                nm_vault_set($conn,'vault_autopilot',!empty($_POST['on'])?1:0);
                nm_vault_set($conn,'vault_autopilot_reclaim',!empty($_POST['reclaim'])?1:0);
                nm_audit($conn,'vault.autopilot_save',['budget'=>$_POST['budget_gb']??0,'on'=>!empty($_POST['on'])]);
                echo json_encode(['ok'=>true]); exit;
            }
            case 'autopilot_run': {
                if (!$POST) throw new Exception('POST');
                $r=nm_vault_autopilot($conn, 15);   // short inline budget — the rest finishes on the hourly cron
                nm_vault_stats_cached($conn,0,true);
                echo json_encode(['ok'=>true]+$r); exit;
            }
            case 'backups': echo json_encode(['ok'=>true,'backups'=>nm_vault_backup_list($conn,60)]); exit;
            case 'backup_create': {
                if (!$POST) throw new Exception('POST');
                $kind=(string)($_POST['kind']??'full'); $cats=$_POST['categories']??[]; if(is_string($cats))$cats=array_filter(explode(',',$cats));
                $r=nm_vault_backup_create($conn,$kind,['categories'=>$cats,'target'=>$_POST['target']??'local','passphrase'=>$_POST['passphrase']??'','note'=>$_POST['note']??'','by'=>nm_v_by()]);
                nm_audit($conn,'vault.backup_create',['kind'=>$kind,'target'=>$_POST['target']??'local']);
                echo json_encode($r); exit;
            }
            case 'backup_delete': {
                if (!$POST) throw new Exception('POST');
                $ok=nm_vault_backup_delete($conn,(int)($_POST['id']??0)); nm_audit($conn,'vault.backup_delete',['id'=>(int)($_POST['id']??0)]);
                echo json_encode(['ok'=>$ok]); exit;
            }
            case 'backup_restore': {
                if (!$POST) throw new Exception('POST');
                $r=nm_vault_restore($conn,(int)($_POST['id']??0),['passphrase'=>$_POST['passphrase']??'','restore_secret'=>!empty($_POST['restore_secret']),'skip_users'=>!empty($_POST['skip_users'])]);
                nm_audit($conn,'vault.restore',['id'=>(int)($_POST['id']??0),'ok'=>!empty($r['ok'])]);
                echo json_encode($r); exit;
            }
            case 'schedule_save': {
                if (!$POST) throw new Exception('POST');
                nm_vault_set($conn,'vault_backup_freq_days',(int)($_POST['freq']??0));
                nm_vault_set($conn,'vault_backup_kind',(string)($_POST['kind']??'full'));
                nm_vault_set($conn,'vault_backup_target',(string)($_POST['target']??'local'));
                nm_vault_set($conn,'vault_backup_keep',max(1,(int)($_POST['keep']??7)));
                nm_audit($conn,'vault.schedule_save',[]);
                echo json_encode(['ok'=>true]); exit;
            }
            case 'targets_save': {
                if (!$POST) throw new Exception('POST');
                foreach(['vault_s3_bucket','vault_s3_region','vault_s3_key','vault_s3_endpoint','vault_webdav_url','vault_webdav_user'] as $k) if(isset($_POST[$k])) nm_vault_set($conn,$k,$_POST[$k]);
                // secrets: encrypt if possible
                foreach(['vault_s3_secret'=>'s3','vault_webdav_pass'=>'dav'] as $k=>$_) if(!empty($_POST[$k])){ $v=$_POST[$k]; if(function_exists('nm_secret_encrypt')){$enc=@nm_secret_encrypt($v); if($enc)$v=$enc;} nm_vault_set($conn,$k,$v); }
                nm_audit($conn,'vault.targets_save',[]);
                echo json_encode(['ok'=>true]); exit;
            }
        }
        throw new Exception('unknown api');
    } catch (\Throwable $ex) { echo json_encode(['ok'=>false,'error'=>$ex->getMessage()]); exit; }
}

require_once('nm_chrome.php');
include('header.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="three.min.js"></script>
<script src="three-orbitcontrols.js"></script>
<style>
:root{ --glass:rgba(12,16,26,.62); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --dna:#9b6bff; --cyan:#22d3ee; }
html{ background:#05080f; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent!important; color:#d4dce8; overflow-x:hidden; }
<?= nm_chrome_css() ?>
.vlt{ max-width:1200px; margin:0 auto; padding:20px 18px 70px; }
.vlt *{ box-sizing:border-box; }
.glass{ background:var(--glass); backdrop-filter:blur(13px); border:1px solid var(--border); border-radius:16px; }
.hd{ display:flex; align-items:center; gap:13px; margin-bottom:4px; }
.hd i{ font-size:26px; color:var(--dna); } .hd h1{ font-size:22px; margin:0; font-weight:700; }
.sub{ color:#8a93a6; font-size:12.5px; margin:0 0 16px; }
.tabs{ display:flex; gap:6px; margin-bottom:16px; flex-wrap:wrap; }
.tabs button{ background:rgba(255,255,255,.04); border:1px solid var(--border); color:#aab4c2; border-radius:10px; padding:9px 15px; font-size:13px; cursor:pointer; display:flex; align-items:center; gap:7px; }
.tabs button.on{ background:rgba(124,77,255,.18); border-color:rgba(124,77,255,.5); color:#fff; }
.pane{ display:none; } .pane.on{ display:block; }
.kpis{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:16px; }
.kpi{ padding:15px 17px; } .kpi .l{ font-size:10px; text-transform:uppercase; letter-spacing:.6px; color:#8a93a6; }
.kpi .v{ font-size:24px; font-weight:800; margin-top:5px; } .kpi .v small{ font-size:13px; font-weight:500; color:#8a93a6; }
.kpi .v.warn{ color:#ffcf87; } .kpi .v.crit{ color:#ff9b91; } .kpi .v.ok{ color:#7af3b0; }
#skyline{ width:100%; height:340px; border-radius:14px; overflow:hidden; position:relative; background:radial-gradient(ellipse at 50% 120%,rgba(77,163,255,.08),transparent 70%); }
#skyline:fullscreen{ height:100vh; width:100vw; border-radius:0; background:transparent; }
#skyline:fullscreen::backdrop{ background:#05080f; }
.legend{ display:flex; flex-wrap:wrap; gap:9px; margin-top:10px; font-size:11px; color:#c3ccd8; }
.legend span{ display:flex; align-items:center; gap:5px; } .legend i{ width:10px; height:10px; border-radius:3px; display:inline-block; }
.cat{ padding:14px 16px; margin-bottom:11px; }
.cat .top{ display:flex; align-items:center; gap:11px; }
.cat .ic{ width:34px; height:34px; border-radius:9px; display:grid; place-items:center; font-size:15px; }
.cat .nm{ font-weight:700; font-size:14px; } .cat .meta{ font-size:11px; color:#8a93a6; margin-top:2px; }
.cat .sp{ flex:1; }
.cat .keep{ text-align:right; font-size:12px; color:#c3ccd8; min-width:120px; }
.cat .keep b{ color:#fff; font-size:15px; }
.slider{ width:100%; margin:12px 0 4px; accent-color:var(--accent); }
.free{ font-size:12px; color:#8a93a6; } .free b{ color:#ffcf87; }
.presets{ display:flex; gap:8px; margin-bottom:14px; flex-wrap:wrap; }
.btn{ background:linear-gradient(135deg,#7c4dff,#4da3ff); border:none; color:#fff; border-radius:10px; padding:10px 16px; font-size:13px; font-weight:600; cursor:pointer; display:inline-flex; align-items:center; gap:7px; }
.btn.ghost{ background:transparent; border:1px solid var(--border); color:#cfe4ff; } .btn.ghost:hover{ border-color:var(--accent); }
.btn.warn{ background:linear-gradient(135deg,#f39c12,#e67e22); } .btn.danger{ background:linear-gradient(135deg,#e74c3c,#c0392b); }
.btn.sm{ padding:6px 11px; font-size:12px; } .btn:disabled{ opacity:.5; cursor:default; }
.flash{ padding:11px 14px; border-radius:10px; margin:12px 0; font-size:13px; border:1px solid; display:none; }
.flash.ok{ background:rgba(46,204,113,.12); border-color:rgba(46,204,113,.4); color:#8ef0b8; display:block; }
.flash.crit{ background:rgba(231,76,60,.12); border-color:rgba(231,76,60,.4); color:#ff9b91; display:block; }
.field{ margin-bottom:11px; } .field label{ display:block; font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:#8a93a6; margin-bottom:5px; }
.field input,.field select{ width:100%; background:rgba(255,255,255,.05); border:1px solid var(--border); border-radius:9px; color:#e6e9ee; padding:9px 11px; font-size:13px; }
.field select option{ background:#0d1526; }
.row{ display:flex; gap:12px; flex-wrap:wrap; } .row .field{ flex:1; min-width:170px; }
.cap{ display:flex; align-items:center; gap:12px; padding:12px 14px; margin-bottom:9px; border-radius:11px; background:rgba(255,255,255,.03); border:1px solid var(--border); }
.cap .cr{ width:38px; height:38px; border-radius:9px; display:grid; place-items:center; font-size:16px; background:linear-gradient(135deg,rgba(124,77,255,.3),rgba(34,211,238,.2)); }
.cap.enc .cr{ background:linear-gradient(135deg,rgba(243,156,18,.3),rgba(231,76,60,.2)); }
.cap .nm{ font-weight:600; font-size:13px; } .cap .meta{ font-size:11px; color:#8a93a6; }
.cap .st{ font-size:10px; padding:2px 8px; border-radius:20px; text-transform:uppercase; letter-spacing:.4px; }
.cap .st.done{ background:rgba(46,204,113,.18); color:#7af3b0; } .cap .st.running,.cap .st.queued{ background:rgba(243,156,18,.18); color:#ffd479; } .cap .st.failed{ background:rgba(231,76,60,.2); color:#ff9b91; }
.note{ font-size:11.5px; color:#7a8291; line-height:1.55; margin-top:9px; } .note.warn{ color:#ffcf87; }
.danger-zone{ border:1px solid rgba(231,76,60,.3); border-radius:13px; padding:16px; margin-top:14px; background:rgba(231,76,60,.04); }
h2.sec{ font-size:14px; margin:0 0 4px; display:flex; align-items:center; gap:8px; }
.card{ padding:18px; margin-bottom:16px; }
</style>

<div class="vlt">
  <div class="hd"><i class="fa-solid fa-vault"></i><h1>Data Vault</h1></div>
  <p class="sub">Keep your database lean, back it up, restore it, or start fresh — all in one place. Telemetry that ages out is pruned automatically; your configuration is never touched.</p>
  <div id="flash" class="flash"></div>

  <div class="tabs">
    <button class="on" data-t="skyline"><i class="fa-solid fa-city"></i> Skyline</button>
    <button data-t="retention"><i class="fa-solid fa-sliders"></i> Retention</button>
    <button data-t="backups"><i class="fa-solid fa-box-archive"></i> Backups</button>
    <button data-t="cleanup"><i class="fa-solid fa-broom"></i> Cleanup</button>
    <button data-t="autopilot"><i class="fa-solid fa-wand-magic-sparkles"></i> Autopilot</button>
  </div>

  <!-- SKYLINE -->
  <div class="pane on" id="p-skyline">
    <div class="kpis">
      <div class="kpi glass"><div class="l">Database size</div><div class="v" id="k-size">—</div></div>
      <div class="kpi glass"><div class="l">Growth / day</div><div class="v" id="k-growth">—</div></div>
      <div class="kpi glass"><div class="l">Reclaimable now</div><div class="v ok" id="k-free">—</div></div>
      <div class="kpi glass"><div class="l" id="k-fc-l">Forecast</div><div class="v" id="k-fc">—</div></div>
    </div>
    <div class="glass card">
      <h2 class="sec"><i class="fa-solid fa-city" style="color:var(--cyan)"></i> Data Skyline <span style="font-weight:400;color:#8a93a6;font-size:11px">— each tower is a data category; height = disk size. Drag to orbit.</span>
        <button class="btn ghost" style="margin-left:auto;padding:6px 11px;font-size:12px" onclick="NMVault.skyFull()"><i class="fa-solid fa-expand"></i> Fullscreen</button></h2>
      <div id="skyline"></div>
      <div class="legend" id="legend"></div>
    </div>
  </div>

  <!-- RETENTION -->
  <div class="pane" id="p-retention">
    <div class="glass card">
      <h2 class="sec"><i class="fa-solid fa-wand-sparkles" style="color:var(--dna)"></i> Presets</h2>
      <p class="note">One click sets sensible retention across every category. <b>Balanced</b> is recommended.</p>
      <div class="presets">
        <button class="btn ghost" onclick="applyPreset('lean')">🍃 Lean — smallest</button>
        <button class="btn" onclick="applyPreset('balanced')">⚖️ Balanced — recommended</button>
        <button class="btn ghost" onclick="applyPreset('compliance')">🗄️ Compliance — keep long</button>
      </div>
      <div id="preview-banner" class="flash" style="background:rgba(77,163,255,.1);border-color:rgba(77,163,255,.4);color:#bcd9ff;display:none"></div>
      <div style="display:flex;gap:10px;margin-top:6px;flex-wrap:wrap">
        <button class="btn" onclick="applyRetention()"><i class="fa-solid fa-check"></i> Apply changes</button>
        <button class="btn warn" onclick="pruneNow(null)"><i class="fa-solid fa-broom"></i> Apply &amp; clean now</button>
      </div>
    </div>
    <div id="cats"></div>
  </div>

  <!-- BACKUPS -->
  <div class="pane" id="p-backups">
    <div class="glass card">
      <h2 class="sec"><i class="fa-solid fa-hammer" style="color:var(--cyan)"></i> Forge a backup</h2>
      <div class="row">
        <div class="field"><label>Kind</label><select id="bk-kind" onchange="bkKindChange()">
          <option value="config">Config only — instant, tiny (settings/nodes/creds)</option>
          <option value="data">Selected data — chosen categories</option>
          <option value="full" selected>Full database — everything</option></select></div>
        <div class="field"><label>Destination</label><select id="bk-target">
          <option value="local">Local — download here</option>
          <option value="portal">Offsite → NEURU Portal</option>
          <option value="s3">Offsite → S3</option>
          <option value="webdav">Offsite → WebDAV</option></select></div>
      </div>
      <div class="field" id="bk-cats-wrap" style="display:none"><label>Categories (for “Selected data”)</label><div id="bk-cats" style="display:flex;flex-wrap:wrap;gap:6px"></div></div>
      <div class="row">
        <div class="field"><label>Passphrase (optional — encrypts config backups)</label><input type="password" id="bk-pass" autocomplete="new-password" placeholder="leave blank = unencrypted"></div>
        <div class="field"><label>Note</label><input type="text" id="bk-note" placeholder="e.g. before big change"></div>
      </div>
      <button class="btn" onclick="forgeBackup()"><i class="fa-solid fa-box-archive"></i> Forge backup</button>
      <p class="note warn"><i class="fa-solid fa-triangle-exclamation"></i> Backups can contain credentials + the secret key. Keep local downloads private, or set a passphrase / use encrypted offsite.</p>
    </div>
    <div class="glass card">
      <h2 class="sec"><i class="fa-solid fa-clock-rotate-left"></i> Scheduled auto-backups</h2>
      <div class="row">
        <div class="field"><label>Every (days, 0 = off)</label><input type="number" id="sc-freq" min="0" max="90" value="0"></div>
        <div class="field"><label>Kind</label><select id="sc-kind"><option value="config">Config</option><option value="full" selected>Full</option></select></div>
        <div class="field"><label>Destination</label><select id="sc-target"><option value="local">Local</option><option value="portal">Portal</option><option value="s3">S3</option><option value="webdav">WebDAV</option></select></div>
        <div class="field"><label>Keep newest</label><input type="number" id="sc-keep" min="1" max="60" value="7"></div>
      </div>
      <button class="btn ghost sm" onclick="saveSchedule()"><i class="fa-solid fa-floppy-disk"></i> Save schedule</button>
    </div>
    <div class="glass card">
      <h2 class="sec"><i class="fa-solid fa-vault"></i> The Vault</h2>
      <div id="vault-list"><div class="note">Loading…</div></div>
    </div>
  </div>

  <!-- CLEANUP -->
  <div class="pane" id="p-cleanup">
    <div class="glass card">
      <h2 class="sec"><i class="fa-solid fa-broom" style="color:var(--warn)"></i> One-shot cleanup</h2>
      <p class="note">Delete data older than a chosen age, once (does not change your retention policy).</p>
      <div class="row">
        <div class="field"><label>Category</label><select id="cl-cat"><option value="">All categories</option></select></div>
        <div class="field"><label>Older than (days)</label><input type="number" id="cl-days" min="1" value="30"></div>
      </div>
      <button class="btn ghost sm" onclick="cleanup(true)"><i class="fa-solid fa-magnifying-glass"></i> Preview</button>
      <button class="btn warn sm" onclick="cleanup(false)"><i class="fa-solid fa-broom"></i> Delete now</button>
      <div id="cl-out" class="note"></div>
    </div>
    <div class="glass card">
      <h2 class="sec"><i class="fa-solid fa-compress" style="color:var(--cyan)"></i> Reclaim disk</h2>
      <p class="note">Deleting rows frees space for reuse but doesn’t return it to the disk until you optimize the table. This rebuilds a category’s tables to shrink the files — it briefly locks them, so do it off-peak.</p>
      <div class="row"><div class="field"><label>Category</label><select id="rc-cat"></select></div></div>
      <button class="btn ghost sm" onclick="reclaim()"><i class="fa-solid fa-compress"></i> Reclaim now</button>
      <div id="rc-out" class="note"></div>
    </div>
    <div class="danger-zone">
      <h2 class="sec" style="color:#ff9b91"><i class="fa-solid fa-skull-crossbones"></i> Start Over (Molt)</h2>
      <p class="note warn">Wipes <b>telemetry</b> (stats, syslog, netflow, logs, samples…) and instantly reclaims the disk — but <b>keeps your configuration</b> (nodes, integrations, users, credentials, dashboards) <b>and your audit + security trail</b>. A full safety backup is taken automatically first. The organism sheds its old data and starts fresh.</p>
      <div class="row"><div class="field" style="max-width:220px"><label>Type MOLT to confirm</label><input type="text" id="molt-c" placeholder="MOLT"></div></div>
      <button class="btn danger sm" onclick="molt()"><i class="fa-solid fa-skull-crossbones"></i> Molt — start fresh</button>
      <div id="molt-out" class="note"></div>
    </div>
  </div>

  <!-- AUTOPILOT -->
  <div class="pane" id="p-autopilot">
    <div class="glass card">
      <h2 class="sec"><i class="fa-solid fa-wand-magic-sparkles" style="color:var(--dna)"></i> Size-Budget Autopilot</h2>
      <p class="note">Set one number — a size budget — and NEURU keeps the database under it automatically. Each night it projects growth and, if over budget, trims the oldest / biggest telemetry first (never below each category’s safety floor). Set it and forget it.</p>
      <div class="row">
        <div class="field"><label>Keep database under (GB, 0 = off)</label><input type="number" id="ap-budget" min="0" step="0.5" value="0"></div>
        <div class="field"><label>Autopilot</label><select id="ap-on"><option value="0">Off</option><option value="1">On</option></select></div>
        <div class="field"><label>Reclaim disk after trimming</label><select id="ap-reclaim"><option value="0">No (cap growth)</option><option value="1">Yes (OPTIMIZE — heavier)</option></select></div>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <button class="btn" onclick="saveAutopilot()"><i class="fa-solid fa-floppy-disk"></i> Save</button>
        <button class="btn ghost" onclick="runAutopilot()"><i class="fa-solid fa-play"></i> Run once now</button>
      </div>
      <div id="ap-out" class="note"></div>
    </div>
    <div class="glass card">
      <h2 class="sec"><i class="fa-solid fa-cloud"></i> Offsite destinations</h2>
      <p class="note">Configure S3 or WebDAV so backups (and autopilot / scheduled ones) can be pushed off-box. Secrets are stored encrypted.</p>
      <div class="row">
        <div class="field"><label>S3 bucket</label><input id="t-s3-bucket" placeholder="my-neuru-backups"></div>
        <div class="field"><label>S3 region</label><input id="t-s3-region" placeholder="us-east-1"></div>
      </div>
      <div class="row">
        <div class="field"><label>S3 access key</label><input id="t-s3-key"></div>
        <div class="field"><label>S3 secret key</label><input id="t-s3-secret" type="password" autocomplete="new-password" placeholder="stored encrypted"></div>
        <div class="field"><label>S3 endpoint (optional — MinIO/R2/Wasabi)</label><input id="t-s3-endpoint" placeholder="blank = AWS"></div>
      </div>
      <div class="row">
        <div class="field"><label>WebDAV URL</label><input id="t-dav-url" placeholder="https://dav.example.com/neuru"></div>
        <div class="field"><label>WebDAV user</label><input id="t-dav-user"></div>
        <div class="field"><label>WebDAV password</label><input id="t-dav-pass" type="password" autocomplete="new-password" placeholder="stored encrypted"></div>
      </div>
      <button class="btn ghost sm" onclick="saveTargets()"><i class="fa-solid fa-floppy-disk"></i> Save destinations</button>
    </div>
  </div>
</div>

<script src="/vault.js?v=1"></script>
<script>
document.addEventListener('DOMContentLoaded',()=>{ if(window.NMLoader) NMLoader.keep(); NMVault.init(); });
</script>
</body></html>
