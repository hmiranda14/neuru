<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Save Configuration. Export EVERYTHING you configured to a single
// `config.neuru` file, and restore it later (same box or a fresh install).
// Telemetry (stats/syslog/netflow/logs) is intentionally excluded — it is not
// configuration and regenerates itself. Optional passphrase encrypts the file
// (it contains the per-install secret key + encrypted credentials). RBAC:
// 'config_backup'. Engine: nm_config_io.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_config_io.php');
require_once('nm_audit.php');
include('logger.php');

if (!checkAccess($conn, 'config_backup')) { header('Location: /denied_access.php?page=config_backup'); exit; }
if (function_exists('session_write_close')) session_write_close();   // free the session lock before heavy DB I/O

$e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');

// ── EXPORT: stream the download BEFORE any HTML ───────────────────────────────
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && ($_POST['do'] ?? '') === 'export') {
    $pass = (string)($_POST['passphrase'] ?? '');
    $withSecret = !empty($_POST['include_secret']);
    try {
        $data  = nm_cfg_build($conn, $withSecret);
        $bytes = nm_cfg_pack($data, $pass);
        $sum   = nm_cfg_summary($data);
        nm_audit($conn, 'config.export', ['tables'=>$sum['table_count'], 'rows'=>$sum['row_count'], 'encrypted'=>$pass!=='', 'secret'=>$withSecret]);
        $fn = 'config-' . gmdate('Ymd-His') . '.neuru';
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $fn . '"');
        header('Content-Length: ' . strlen($bytes));
        header('Cache-Control: no-store');
        echo $bytes;
        exit;
    } catch (\Throwable $ex) {
        $flash = 'Export failed: ' . $ex->getMessage(); $flashType = 'crit';
    }
}

// ── INSPECT / RESTORE ─────────────────────────────────────────────────────────
$preview = null; $report = null; $flash = $flash ?? null; $flashType = $flashType ?? 'ok';
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && in_array(($_POST['do'] ?? ''), ['inspect','restore'], true)) {
    $do   = $_POST['do'];
    $pass = (string)($_POST['passphrase'] ?? '');
    if (empty($_FILES['file']['tmp_name']) || !is_uploaded_file($_FILES['file']['tmp_name'])) {
        $flash = 'Choose a .neuru file first.'; $flashType = 'crit';
    } else {
        $bytes = (string)@file_get_contents($_FILES['file']['tmp_name']);
        try {
            $data = nm_cfg_unpack($bytes, $pass);
            $sum  = nm_cfg_summary($data);
            if ($do === 'inspect') {
                $preview = ['meta'=>$data, 'sum'=>$sum];
            } else {
                if (empty($_POST['confirm'])) {
                    $flash = 'Tick the confirmation box — Restore overwrites your current configuration.'; $flashType = 'crit';
                    $preview = ['meta'=>$data, 'sum'=>$sum];
                } else {
                    $snap = nm_cfg_safety_snapshot($conn);   // undo point BEFORE we touch anything
                    $res  = nm_cfg_import($conn, $data, [
                        'restore_secret' => !empty($_POST['restore_secret']),
                        'skip_users'     => !empty($_POST['skip_users']),
                    ]);
                    if (!empty($res['ok'])) {
                        nm_audit($conn, 'config.restore', ['tables'=>count($res['report']['restored']), 'secret'=>$res['report']['secret'], 'from_version'=>$data['neuru_version']??'?']);
                        $report = ['res'=>$res, 'snap'=>$snap, 'meta'=>$data, 'sum'=>$sum];
                        $flash = 'Configuration restored. Reload the portal to see everything applied.'; $flashType = 'ok';
                    } else {
                        $flash = 'Restore failed (nothing changed — rolled back): ' . ($res['error'] ?? '?'); $flashType = 'crit';
                    }
                }
            }
        } catch (\Throwable $ex) {
            $flash = $ex->getMessage(); $flashType = 'crit';
        }
    }
}

require_once('nm_chrome.php');
include('header.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(12,16,26,.62); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --dna:#9b6bff; }
html{ background:#05080f; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent!important; color:#d4dce8; overflow-x:hidden; }
<?= nm_chrome_css() ?>
.cfg{ max-width:980px; margin:0 auto; padding:22px 20px 60px; }
.cfg *{ box-sizing:border-box; }
.glass{ background:var(--glass); backdrop-filter:blur(13px); border:1px solid var(--border); border-radius:16px; }
.hd{ display:flex; align-items:center; gap:13px; margin-bottom:6px; }
.hd i{ font-size:26px; color:var(--dna); }
.hd h1{ font-size:22px; margin:0; font-weight:700; letter-spacing:.3px; }
.sub{ color:#8a93a6; font-size:13px; margin:0 0 20px; line-height:1.5; }
.card{ padding:20px 22px; margin-bottom:18px; }
.card h2{ font-size:15px; margin:0 0 4px; display:flex; align-items:center; gap:9px; }
.card .cd{ color:#8a93a6; font-size:12.5px; margin:0 0 15px; line-height:1.5; }
.row{ display:flex; gap:12px; flex-wrap:wrap; align-items:flex-end; }
.fld{ flex:1; min-width:210px; } .fld label{ display:block; font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:#8a93a6; margin-bottom:5px; }
.fld input[type=text],.fld input[type=password],.fld input[type=file]{ width:100%; background:rgba(255,255,255,.05); border:1px solid var(--border); border-radius:9px; color:#e6e9ee; padding:10px 12px; font-size:13px; }
.chk{ display:flex; align-items:center; gap:8px; font-size:13px; color:#c3ccd8; margin:9px 0; cursor:pointer; }
.chk input{ width:16px; height:16px; accent-color:var(--accent); }
.btn{ background:linear-gradient(135deg,#7c4dff,#4da3ff); border:none; color:#fff; border-radius:10px; padding:11px 18px; font-size:13.5px; font-weight:600; cursor:pointer; display:inline-flex; align-items:center; gap:8px; }
.btn.ghost{ background:transparent; border:1px solid var(--border); color:#cfe4ff; } .btn.ghost:hover{ border-color:var(--accent); }
.btn.danger{ background:linear-gradient(135deg,#e74c3c,#c0392b); }
.flash{ padding:12px 15px; border-radius:11px; margin-bottom:16px; font-size:13px; border:1px solid; }
.flash.ok{ background:rgba(46,204,113,.12); border-color:rgba(46,204,113,.4); color:#8ef0b8; }
.flash.crit{ background:rgba(231,76,60,.12); border-color:rgba(231,76,60,.4); color:#ff9b91; }
.note{ font-size:11.5px; color:#7a8291; margin-top:11px; line-height:1.55; }
.note.warn{ color:#ffcf87; }
.tags{ display:flex; flex-wrap:wrap; gap:6px; margin-top:12px; max-height:190px; overflow:auto; padding-right:4px; }
.tag{ font-family:monospace; font-size:11px; background:rgba(255,255,255,.05); border:1px solid var(--border); border-radius:6px; padding:3px 8px; color:#b9c4d4; }
.tag b{ color:#7af3b0; font-weight:700; }
.meta{ display:flex; gap:22px; flex-wrap:wrap; font-size:12.5px; color:#c3ccd8; margin:6px 0 4px; }
.meta b{ color:#fff; }
.divider{ height:1px; background:var(--border); margin:16px 0; }
</style>

<div class="cfg">
  <div class="hd"><i class="fa-solid fa-floppy-disk"></i><h1>Save Configuration</h1></div>
  <p class="sub">Export <b>every setting</b> in this NEURU — nodes, interfaces, links, integrations, credentials, notification routing, RBAC roles &amp; users, dashboards, thresholds and feature configs — into one portable <code>config.neuru</code> file, and restore it later on this box or a fresh install. Live telemetry (stats, syslog, NetFlow, logs) is excluded on purpose: it isn’t configuration and rebuilds itself.</p>

  <?php if ($flash): ?><div class="flash <?= $e($flashType) ?>"><?= $e($flash) ?></div><?php endif; ?>

  <!-- EXPORT -->
  <form method="post" class="glass card">
    <input type="hidden" name="do" value="export">
    <h2><i class="fa-solid fa-download" style="color:var(--ok)"></i> Export configuration</h2>
    <p class="cd">Downloads a single <code>.neuru</code> file. Set a passphrase to encrypt it — recommended, since the file contains this install’s secret key and encrypted credentials.</p>
    <div class="row">
      <div class="fld"><label>Passphrase (optional — encrypts the file)</label><input type="password" name="passphrase" placeholder="leave blank for an unencrypted file" autocomplete="new-password"></div>
      <button class="btn" type="submit"><i class="fa-solid fa-floppy-disk"></i> Download config.neuru</button>
    </div>
    <label class="chk"><input type="checkbox" name="include_secret" value="1" checked> Include the per-install secret key (needed to decrypt saved credentials on restore)</label>
    <p class="note warn"><i class="fa-solid fa-triangle-exclamation"></i> Keep this file safe — with the secret key included it can decrypt every stored password, token and API key. Store it somewhere private, or always set a passphrase.</p>
  </form>

  <!-- RESTORE -->
  <form method="post" class="glass card" enctype="multipart/form-data">
    <h2><i class="fa-solid fa-upload" style="color:var(--accent)"></i> Restore / inspect a config.neuru</h2>
    <p class="cd">Upload a file to <b>Inspect</b> it (no changes) or <b>Restore</b> it. Restore replaces the matching configuration tables — a safety snapshot of your current config is written first so it can be undone.</p>
    <div class="row">
      <div class="fld"><label>Config file (.neuru)</label><input type="file" name="file" accept=".neuru,application/octet-stream" required></div>
      <div class="fld"><label>Passphrase (if the file is encrypted)</label><input type="password" name="passphrase" autocomplete="new-password"></div>
    </div>
    <label class="chk"><input type="checkbox" name="restore_secret" value="1" checked> Restore the secret key from the file (so its credentials decrypt)</label>
    <label class="chk"><input type="checkbox" name="skip_users" value="1"> Keep my current users &amp; roles (don’t overwrite logins — safer on a live box)</label>
    <div class="divider"></div>
    <label class="chk"><input type="checkbox" name="confirm" value="1"> I understand <b>Restore</b> overwrites my current configuration with this file’s.</label>
    <div class="row" style="margin-top:6px">
      <button class="btn ghost" type="submit" name="do" value="inspect"><i class="fa-solid fa-magnifying-glass"></i> Inspect (no changes)</button>
      <button class="btn danger" type="submit" name="do" value="restore" onclick="return confirm('Restore this configuration? Your current settings will be replaced (a safety snapshot is saved first).');"><i class="fa-solid fa-rotate-left"></i> Restore now</button>
    </div>
  </form>

  <?php if ($preview): $m=$preview['meta']; $s=$preview['sum']; ?>
  <div class="glass card">
    <h2><i class="fa-solid fa-magnifying-glass" style="color:var(--warn)"></i> File contents</h2>
    <div class="meta">
      <span>NEURU version: <b><?= $e($m['neuru_version']??'?') ?></b></span>
      <span>Exported: <b><?= $e($m['exported_at']??'?') ?></b></span>
      <span>From host: <b><?= $e($m['host']??'?') ?></b></span>
      <span>Tables: <b><?= (int)$s['table_count'] ?></b></span>
      <span>Rows: <b><?= (int)$s['row_count'] ?></b></span>
      <span>Secret key: <b><?= $s['has_secret']?'included':'not included' ?></b></span>
    </div>
    <div class="tags">
      <?php foreach ($s['tables'] as $t=>$n): ?><span class="tag"><?= $e($t) ?> <b><?= (int)$n ?></b></span><?php endforeach; ?>
    </div>
    <p class="note">Nothing has been changed. To apply this file, tick the confirmation box above and click <b>Restore now</b>.</p>
  </div>
  <?php endif; ?>

  <?php if ($report): $rep=$report['res']['report']; ?>
  <div class="glass card">
    <h2><i class="fa-solid fa-circle-check" style="color:var(--ok)"></i> Restore complete</h2>
    <div class="meta">
      <span>Tables restored: <b><?= count($rep['restored']) ?></b></span>
      <span>Rows: <b><?= array_sum($rep['restored']) ?></b></span>
      <span>Skipped: <b><?= count($rep['skipped']) ?></b></span>
      <span>Secret key: <b><?= $e($rep['secret']) ?></b></span>
    </div>
    <?php if ($report['snap']): ?><p class="note">Safety snapshot of your previous config saved to <code><?= $e(str_replace(__DIR__.'/','',$report['snap'])) ?></code> (server-side, protected).</p><?php endif; ?>
    <?php if ($rep['skipped']): ?><p class="note">Skipped: <?php foreach($rep['skipped'] as $t=>$why) echo $e($t).' ('.$e($why).') '; ?></p><?php endif; ?>
    <p class="note warn"><i class="fa-solid fa-triangle-exclamation"></i> If you restored users/roles, your current login may have changed — you may need to sign in again with the restored credentials.</p>
    <a class="btn" href="net_mon.php" style="margin-top:12px;text-decoration:none"><i class="fa-solid fa-house"></i> Reload portal</a>
  </div>
  <?php endif; ?>
</div>

<script>
document.addEventListener('DOMContentLoaded',()=>{ if(window.NMLoader) NMLoader.hide(); });
</script>
</body></html>
