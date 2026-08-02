<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — first-run Setup Wizard. Standalone (does NOT include connection.php, so
// it works against an empty/uninitialized DB). Guides a fresh install through:
//   1) Initialize database (import install/neuru-install.sql)
//   2) Set the admin password
//   3) Point integrations (n8n, Portainer) + timezone
//   4) Finish → login
// Locks itself once nm_settings.setup_complete = '1'.
// ─────────────────────────────────────────────────────────────────────────────
session_start();
error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);
ob_start();   // buffer stray output so header('Location') redirects can never be broken by a warning

// DB target — same defaults as connection.php (override via env if you customized compose)
$DB_HOST = getenv('NM_DB_HOST') ?: 'db';
$DB_NAME = getenv('NM_DB_NAME') ?: 'netmon';
$DB_USER = getenv('NM_DB_USER') ?: 'sisuser';
$DB_PASS = getenv('NM_DB_PASS') ?: 'sispass';
$SQL_FILE = __DIR__ . '/install/neuru-install.sql';

function db_connect($host,$user,$pass,$name=''){ $c=@new mysqli($host,$user,$pass,$name); return ($c && !$c->connect_error) ? $c : null; }
function tbl_exists($c,$t){ if(!$c) return false; $r=@$c->query("SHOW TABLES LIKE '".$c->real_escape_string($t)."'"); return $r && $r->num_rows>0; }
function setting($c,$k){ if(!$c) return null; $r=@$c->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$c->real_escape_string($k)."' LIMIT 1"); return ($r&&$r->num_rows)?$r->fetch_assoc()['setting_val']:null; }
function set_setting($c,$k,$v){ if(!$c) return; $st=@$c->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES (?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)"); if(!$st) return; $st->bind_param('ss',$k,$v); @$st->execute(); $st->close(); }
function finish_redirect(){ // bulletproof: header redirect if possible, ALWAYS a meta-refresh + link fallback (no blank page)
    if (!headers_sent()) header('Location: /index.php?setup=done');
    echo '<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=/index.php?setup=done">'
       . '<body style="margin:0;background:radial-gradient(1200px 700px at 50% -10%,rgba(40,70,140,.35),transparent 70%),#05060f;color:#e6e9ee;font-family:\'Segoe UI\',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh">'
       . '<div style="text-align:center"><div style="font-size:44px">✅</div><h2 style="margin:10px 0">Setup complete</h2>'
       . '<p style="color:#9aa3ad">Redirecting to login…</p><p><a style="color:#4da3ff;text-decoration:none;font-weight:600" href="/index.php?setup=done">Continue to login →</a></p></div></body>';
    exit;
}

$conn = db_connect($DB_HOST,$DB_USER,$DB_PASS,$DB_NAME);
$dbReachable = ($conn !== null) || (db_connect($DB_HOST,$DB_USER,$DB_PASS) !== null);
$initialized = $conn && tbl_exists($conn,'users') && tbl_exists($conn,'nm_settings');

// already done? lock the wizard.
if ($initialized && setting($conn,'setup_complete') === '1') {
    header('Location: /index.php'); exit;
}

$msg=''; $err=''; $action = $_POST['action'] ?? '';

// ── ACTION: initialize DB (import the install SQL) ───────────────────────────
if ($action === 'init') {
    if (!$dbReachable) { $err = "Can't reach MySQL at '{$DB_HOST}'. Is the db container up? (docker compose ps)"; }
    elseif (!is_file($SQL_FILE)) { $err = "Missing install/neuru-install.sql in the app folder."; }
    else {
        // ensure the database exists (in case compose didn't create it)
        $root = db_connect($DB_HOST,$DB_USER,$DB_PASS);
        if ($root) { @$root->query("CREATE DATABASE IF NOT EXISTS `".$root->real_escape_string($DB_NAME)."` CHARACTER SET utf8mb4"); }
        // import via the mysql client (handles the full dump syntax reliably)
        $cmd = sprintf('mysql -h%s -u%s -p%s %s < %s 2>&1',
            escapeshellarg($DB_HOST), escapeshellarg($DB_USER), escapeshellarg($DB_PASS),
            escapeshellarg($DB_NAME), escapeshellarg($SQL_FILE));
        $out=[]; $rc=1; @exec($cmd,$out,$rc);
        if ($rc !== 0) {
            // fallback: import in-PHP via multi_query
            $c = db_connect($DB_HOST,$DB_USER,$DB_PASS,$DB_NAME);
            if ($c && ($sql=@file_get_contents($SQL_FILE))!==false) {
                if (@$c->multi_query($sql)) { do {} while ($c->more_results() && $c->next_result()); }
                $rc = $c->error ? 1 : 0; if ($c->error) $err = 'Import error: '.$c->error;
            } else { $err = 'Import failed: '.implode("\n",array_slice($out,-4)); }
        }
        if ($rc === 0 && !$err) {
            $conn = db_connect($DB_HOST,$DB_USER,$DB_PASS,$DB_NAME); $initialized = true;
            // Backfill anything newer than the base SQL — new tables' columns, indexes, and (critically)
            // the RBAC perms for modules added after v1 (mtfw, port scanner, wireguard, ipam, routing…).
            // Idempotent + wrapped so a partial failure never blocks setup.
            $upd = null;
            if ($conn && is_file(__DIR__ . '/install/apply_updates.php')) {
                try { require_once __DIR__ . '/install/apply_updates.php';
                    if (function_exists('nm_apply_updates')) $upd = nm_apply_updates($conn);
                } catch (\Throwable $e) { /* base SQL already made the schema; this is a bonus pass */ }
            }
            $msg = 'Database initialized ✓' . ($upd ? " — {$upd['tables_after']} tables, {$upd['ok']} modules ensured" : '');
        }
    }
}

// ── ACTION: save admin password + integrations, then finish ──────────────────
if ($action === 'finish' && $initialized) {
    $pw  = (string)($_POST['admin_pw'] ?? '');
    $tz  = trim((string)($_POST['timezone'] ?? 'America/Puerto_Rico'));
    $n8n = trim((string)($_POST['n8n_url'] ?? ''));
    $tok = trim((string)($_POST['n8n_token'] ?? ''));
    $por = trim((string)($_POST['portainer_url'] ?? ''));
    if ($pw !== '') {
        if (strlen($pw) < 6) { $err='Admin password must be at least 6 characters.'; }
        else { try { $h=password_hash($pw,PASSWORD_DEFAULT); $st=$conn->prepare("UPDATE users SET PASSWORD=? WHERE USERNAME='admin'"); $st->bind_param('s',$h); $st->execute(); $st->close(); }
               catch (\Throwable $e) { $err='Could not set the admin password: '.$e->getMessage(); } }
    }
    if (!$err) {
        if ($tz!=='')  set_setting($conn,'app_timezone',$tz);
        if ($n8n!=='') set_setting($conn,'n8n_base_url',$n8n);
        if ($tok!=='') set_setting($conn,'n8n_inbound_token',$tok);
        if ($por!=='') set_setting($conn,'portainer_url',$por);
        set_setting($conn,'setup_complete','1');
        finish_redirect();
    }
}

// current values for the form
$curTz  = $initialized ? (setting($conn,'app_timezone') ?: 'America/Puerto_Rico') : 'America/Puerto_Rico';
$curN8n = $initialized ? (setting($conn,'n8n_base_url') ?: '') : '';
$curTok = $initialized ? (setting($conn,'n8n_inbound_token') ?: '') : '';
$curPor = $initialized ? (setting($conn,'portainer_url') ?: '') : '';
$e = fn($s)=>htmlspecialchars((string)$s,ENT_QUOTES);
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NEURU · Setup</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
*,*::before,*::after{box-sizing:border-box}
body{margin:0;min-height:100vh;font-family:'Segoe UI',Tahoma,sans-serif;color:#e6e9ee;
  background:radial-gradient(1200px 700px at 50% -10%,rgba(40,70,140,.35),transparent 70%),#05060f;
  display:flex;align-items:center;justify-content:center;padding:30px 16px;}
.card{width:640px;max-width:96vw;background:rgba(255,255,255,.05);backdrop-filter:blur(16px);
  border:1px solid rgba(255,255,255,.12);border-radius:18px;padding:30px 34px;box-shadow:0 24px 70px rgba(0,0,0,.5)}
.brand{font-size:26px;font-weight:800;letter-spacing:1px;background:linear-gradient(90deg,#4da3ff,#9b6bff);-webkit-background-clip:text;background-clip:text;color:transparent;display:flex;align-items:center;gap:12px}
.brand i{color:#4da3ff;-webkit-text-fill-color:#4da3ff}
.sub{color:#8a909a;font-size:13px;margin:4px 0 20px}
.steps{display:flex;gap:8px;margin-bottom:22px}
.step{flex:1;height:5px;border-radius:5px;background:rgba(255,255,255,.1)}
.step.on{background:linear-gradient(90deg,#4da3ff,#9b6bff)}
h2{font-size:17px;margin:0 0 6px;display:flex;align-items:center;gap:9px}
.muted{color:#8a909a;font-size:13px;line-height:1.55}
label{display:block;font-size:12px;color:#9aa3af;margin:14px 0 5px}
input{width:100%;background:rgba(10,16,28,.7);border:1px solid rgba(255,255,255,.14);border-radius:9px;color:#e6e9ee;padding:10px 12px;font-size:14px;font-family:inherit}
.row{display:flex;gap:12px}.row>div{flex:1}
.btn{background:rgba(77,163,255,.16);border:1px solid rgba(77,163,255,.5);color:#cfe4ff;border-radius:10px;padding:11px 20px;font-size:14px;cursor:pointer;font-weight:600}
.btn:hover{border-color:#4da3ff;color:#fff}
.btn.go{background:linear-gradient(90deg,rgba(77,163,255,.25),rgba(155,107,255,.25));border-color:rgba(155,107,255,.6)}
.ok{color:#7af3b0}.bad{color:#ff9b91}
.note{background:rgba(46,204,113,.1);border:1px solid rgba(46,204,113,.4);border-radius:10px;padding:10px 14px;font-size:13px;margin:14px 0;color:#9af3c0}
.warn{background:rgba(231,76,60,.1);border:1px solid rgba(231,76,60,.4);border-radius:10px;padding:10px 14px;font-size:13px;margin:14px 0;color:#ffb3ab}
.chk{font-size:13px;color:#cfd6e0;margin:6px 0;display:flex;align-items:center;gap:9px}
.chk i.ok{color:#2ee6a0}.chk i.no{color:#f0a559}
.foot{margin-top:22px;display:flex;justify-content:space-between;align-items:center}
a.skip{color:#8a909a;font-size:13px;text-decoration:none}a.skip:hover{color:#cfd6e0}
code{background:rgba(0,0,0,.35);padding:1px 6px;border-radius:5px;font-size:12px;color:#a9d5ff}
</style></head>
<body>
<div class="card">
  <div class="brand"><i class="fa-solid fa-satellite-dish"></i> NEURU</div>
  <div class="sub">Neural Network Monitor — first-run setup</div>
  <div class="steps">
    <div class="step <?= !$initialized?'on':'on' ?>"></div>
    <div class="step <?= $initialized?'on':'' ?>"></div>
    <div class="step <?= $initialized?'on':'' ?>"></div>
  </div>

  <?php if($msg): ?><div class="note"><i class="fa-solid fa-check"></i> <?= $e($msg) ?></div><?php endif; ?>
  <?php if($err): ?><div class="warn"><i class="fa-solid fa-triangle-exclamation"></i> <?= $e($err) ?></div><?php endif; ?>

  <?php if(!$initialized): ?>
    <!-- STEP 1 — initialize -->
    <h2><i class="fa-solid fa-database"></i> Step 1 · Initialize the database</h2>
    <p class="muted">This creates all 125 tables and pre-loads the configuration (webhooks, widgets, templates, RBAC) — everything <b>disabled</b> and secrets blank, so nothing fires until you turn it on. A default admin is seeded, then a schema-sync pass ensures every module (firewall, packet tracer, WireGuard, IPAM, routing…) is fully wired.</p>
    <div class="chk"><i class="fa-solid <?= $dbReachable?'fa-circle-check ok':'fa-circle-xmark no' ?>"></i> MySQL at <code><?= $e($DB_HOST) ?></code> <?= $dbReachable?'reachable':'NOT reachable — start the db container first' ?></div>
    <div class="chk"><i class="fa-solid <?= is_file($SQL_FILE)?'fa-circle-check ok':'fa-circle-xmark no' ?>"></i> Install file <code>install/neuru-install.sql</code> present</div>
    <form method="post" class="foot">
      <input type="hidden" name="action" value="init">
      <span class="muted">Default login after this: <b>admin</b> / <b>admin@1.one</b></span>
      <button class="btn go" <?= (!$dbReachable||!is_file($SQL_FILE))?'disabled':'' ?>><i class="fa-solid fa-bolt"></i> Initialize</button>
    </form>
  <?php else: ?>
    <!-- STEP 2+3 — configure -->
    <h2><i class="fa-solid fa-sliders"></i> Step 2 · Secure &amp; configure</h2>
    <p class="muted">The database is ready with everything pre-loaded (disabled). Set your admin password and point NEURU at your services. You can change all of this later in <b>Config → Integrations</b>.</p>
    <form method="post">
      <input type="hidden" name="action" value="finish">
      <label>New admin password <span class="muted">(leave blank to keep <code>admin@1.one</code>)</span></label>
      <input type="password" name="admin_pw" placeholder="••••••••" autocomplete="new-password">
      <div class="row">
        <div><label>Display timezone</label><input name="timezone" value="<?= $e($curTz) ?>"></div>
        <div><label>Portainer URL <span class="muted">(optional)</span></label><input name="portainer_url" value="<?= $e($curPor) ?>" placeholder="https://portainer:9443"></div>
      </div>
      <div class="row">
        <div><label>n8n base URL <span class="muted">(optional)</span></label><input name="n8n_url" value="<?= $e($curN8n) ?>" placeholder="http://n8n:5678"></div>
        <div><label>n8n inbound token <span class="muted">(for crons/callbacks)</span></label><input name="n8n_token" value="<?= $e($curTok) ?>" placeholder="auto-kept from seed"></div>
      </div>
      <div class="note" style="margin-top:16px;"><i class="fa-solid fa-circle-info"></i> Secrets (SSH keys, Pi-hole/SMTP passwords, Telegram token, API keys) are per-install and were left blank — add them in <b>Config → Integrations</b> after you log in.</div>
      <div class="foot">
        <a class="skip" href="/index.php">Skip — go to login</a>
        <button class="btn go"><i class="fa-solid fa-flag-checkered"></i> Finish setup</button>
      </div>
    </form>
  <?php endif; ?>
</div>
</body></html>
