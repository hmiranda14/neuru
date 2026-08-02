<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — My Profile (self-service). Any authenticated user can edit their own
// name/email/phone/title, upload a profile photo, and change their password.
// NOT role-gated (a user always manages their own account); role & username are
// read-only. Uses $_SESSION['UID'] (canonical). Reuses nm_media.php for the avatar.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_profile.php');
require_once('nm_media.php');
require_once('nm_2fa.php');
include('logger.php');

$uid = (int)($_SESSION['UID'] ?? 0);
if (!$uid) { header('Location: /index.php'); exit; }
nm_user_meta_ensure($conn);

// Abort an unfinished 2FA enrollment (the secret isn't active yet).
if (isset($_GET['tfa_cancel'])) { $conn->query("UPDATE users SET totp_secret=NULL WHERE UID=$uid AND totp_enabled=0"); header('Location: user_profile.php'); exit; }

// ── POST handlers ───────────────────────────────────────────────────────────
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $act = $_POST['action'] ?? '';
    $cur = nm_user_get($conn, $uid);

    if ($act === 'save_profile' && $cur) {
        $name  = substr(trim($_POST['name'] ?? ''), 0, 100);
        $email = substr(trim($_POST['email'] ?? ''), 0, 50);
        $phone = substr(trim($_POST['phone'] ?? ''), 0, 40) ?: null;
        $title = substr(trim($_POST['title'] ?? ''), 0, 120) ?: null;
        if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $_SESSION['pf_err'] = 'That email address is not valid.';
        } else {
            $st = $conn->prepare("UPDATE users SET name=?, email=?, phone=?, title=? WHERE UID=?");
            $st->bind_param('ssssi', $name, $email, $phone, $title, $uid); $st->execute();
            // avatar (optional)
            if (!empty($_FILES['avatar']['name'])) {
                $up = nm_media_store_image($_FILES['avatar'], 'avatars', 'avatar'.$uid, 5242880);
                if (!empty($up['ok'])) {
                    $old = $cur['avatar_path'] ?? null;
                    $ps = $conn->prepare("UPDATE users SET avatar_path=? WHERE UID=?"); $ps->bind_param('si', $up['path'], $uid); $ps->execute();
                    nm_media_delete($old);
                } else { $_SESSION['pf_err'] = 'Photo not saved: ' . ($up['error'] ?? 'unknown'); }
            } elseif (!empty($_POST['remove_avatar']) && !empty($cur['avatar_path'])) {
                $conn->query("UPDATE users SET avatar_path=NULL WHERE UID=$uid");
                nm_media_delete($cur['avatar_path']);
            }
            $_SESSION['email'] = $email;   // keep the live session copy in sync
            if (empty($_SESSION['pf_err'])) $_SESSION['pf_msg'] = 'Profile updated.';
            if (function_exists('nm_audit')) { try { nm_audit($conn, 'profile.save', ['target_type'=>'user','target_id'=>$uid]); } catch (\Throwable $e) {} }
        }
        header('Location: user_profile.php'); exit;
    }

    if ($act === 'change_password' && $cur) {
        $c0 = (string)($_POST['current_password'] ?? '');
        $n1 = (string)($_POST['new_password'] ?? '');
        $n2 = (string)($_POST['confirm_password'] ?? '');
        $hash = (string)($cur['PASSWORD'] ?? '');
        $ok = $hash !== '' && (password_verify($c0, $hash) || (strlen($hash) === 32 && md5($c0) === $hash)); // bcrypt or legacy md5
        if (!$ok)                     $_SESSION['pf_err'] = 'Current password is incorrect.';
        elseif (strlen($n1) < 8)      $_SESSION['pf_err'] = 'New password must be at least 8 characters.';
        elseif ($n1 !== $n2)          $_SESSION['pf_err'] = 'New passwords do not match.';
        else {
            $nh = password_hash($n1, PASSWORD_DEFAULT);
            $st = $conn->prepare("UPDATE users SET PASSWORD=? WHERE UID=?"); $st->bind_param('si', $nh, $uid); $st->execute();
            $_SESSION['pf_msg'] = 'Password changed.';
            if (function_exists('nm_audit')) { try { nm_audit($conn, 'profile.password', ['target_type'=>'user','target_id'=>$uid]); } catch (\Throwable $e) {} }
        }
        header('Location: user_profile.php'); exit;
    }

    // ── Two-Factor Authentication (TOTP) ──────────────────────────────────────
    if ($act === '2fa_begin' && $cur) {
        nm_2fa_begin($conn, $uid, (string)($cur['USERNAME'] ?? ('user' . $uid)));   // stores secret, enabled=0
        header('Location: user_profile.php#twofa'); exit;
    }
    if ($act === '2fa_cancel') {   // abort an unfinished enrollment (secret not yet active)
        $conn->query("UPDATE users SET totp_secret=NULL WHERE UID=$uid AND totp_enabled=0");
        header('Location: user_profile.php#twofa'); exit;
    }
    if ($act === '2fa_confirm') {
        $r = nm_2fa_confirm($conn, $uid, (string)($_POST['code'] ?? ''));
        if (!empty($r['ok'])) { $_SESSION['pf_2fa_backup'] = $r['backup_codes']; $_SESSION['pf_msg'] = 'Two-factor authentication is ON. Save your backup codes below — you won\'t see them again.'; }
        else $_SESSION['pf_err'] = $r['error'] ?? '2FA could not be turned on.';
        header('Location: user_profile.php#twofa'); exit;
    }
    if ($act === '2fa_disable') {
        $r = nm_2fa_disable($conn, $uid, (string)($_POST['code'] ?? ''));
        $_SESSION[!empty($r['ok']) ? 'pf_msg' : 'pf_err'] = !empty($r['ok']) ? 'Two-factor authentication turned off.' : ($r['error'] ?? 'Could not disable 2FA.');
        header('Location: user_profile.php#twofa'); exit;
    }
    if ($act === '2fa_regen') {
        $r = nm_2fa_regen_backup($conn, $uid, (string)($_POST['code'] ?? ''));
        if (!empty($r['ok'])) { $_SESSION['pf_2fa_backup'] = $r['backup_codes']; $_SESSION['pf_msg'] = 'New backup codes generated — the old ones no longer work.'; }
        else $_SESSION['pf_err'] = $r['error'] ?? 'Could not regenerate backup codes.';
        header('Location: user_profile.php#twofa'); exit;
    }
}

$u = nm_user_get($conn, $uid);
// 2FA state for the render
$tfa = nm_2fa_status($conn, $uid);
$tfaBackup = $_SESSION['pf_2fa_backup'] ?? null; unset($_SESSION['pf_2fa_backup']);
$tfaBackupCount = $tfa['enabled'] ? nm_2fa_backup_count($conn, $uid) : 0;
$tfaSecret = ''; $tfaUri = '';
if (!$tfa['enabled'] && $tfa['has_secret']) {   // enrollment in progress → render the QR
    $tfaSecret = nm_2fa_secret($conn, $uid);
    if ($tfaSecret !== '') $tfaUri = nm_2fa_uri($tfaSecret, (string)($u['USERNAME'] ?? ('user' . $uid)));
}
$avatar = nm_user_avatar_url($u);
$msg = $_SESSION['pf_msg'] ?? null; $err = $_SESSION['pf_err'] ?? null;
unset($_SESSION['pf_msg'], $_SESSION['pf_err']);
$e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES);
$initial = strtoupper(substr(trim((string)($u['name'] ?: $u['USERNAME'])), 0, 1)) ?: '?';
include('header.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(12,16,26,.62); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --purple:#c084fc; }
html{ background:#05080f; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#d4dce8; overflow-x:hidden; }
<?= nm_chrome_css() ?>
.up{ max-width:1080px; margin:0 auto; padding:22px 20px 60px; }
.up *{ box-sizing:border-box; }
.glass{ background:var(--glass); backdrop-filter:blur(13px); border:1px solid var(--border); border-radius:16px; }
.up-hero{ display:flex; gap:22px; align-items:center; padding:22px; margin-bottom:18px; flex-wrap:wrap; }
.av{ width:118px; height:118px; border-radius:50%; flex:none; position:relative; overflow:hidden;
  border:2px solid rgba(77,163,255,.4); box-shadow:0 0 0 6px rgba(77,163,255,.06), 0 10px 30px rgba(0,0,0,.45);
  display:flex; align-items:center; justify-content:center; background:radial-gradient(circle at 50% 35%, rgba(77,163,255,.25), rgba(10,14,22,.7)); }
.av img{ width:100%; height:100%; object-fit:cover; }
.av .ini{ font-size:46px; font-weight:800; color:#cfe0ff; }
.up-idc{ flex:1; min-width:240px; }
.up-name{ font-size:26px; font-weight:800; display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
.rolechip{ font-size:12px; font-weight:700; padding:4px 12px; border-radius:20px; background:rgba(192,132,252,.16); color:#d3b3ff; border:1px solid rgba(192,132,252,.4); text-transform:capitalize; }
.up-sub{ color:#8b95a7; font-size:13px; margin-top:6px; display:flex; gap:16px; flex-wrap:wrap; }
.up-sub b{ color:#c7d0de; font-weight:600; }
.grid{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }
@media(max-width:840px){ .grid{ grid-template-columns:1fr; } }
.card{ padding:20px; }
.ctitle{ font-size:13px; text-transform:uppercase; letter-spacing:.8px; color:#9db4d6; display:flex; align-items:center; gap:9px; margin-bottom:16px; }
.fld{ margin-bottom:14px; }
.fld label{ display:block; font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:#8b95a7; margin-bottom:5px; }
.fld input{ width:100%; background:rgba(255,255,255,.05); border:1px solid var(--border); border-radius:9px; color:#e6edf7; padding:10px 12px; font-size:14px; }
.fld input:focus{ outline:none; border-color:var(--accent); background:rgba(77,163,255,.06); }
.fld input:disabled{ color:#8b95a7; background:rgba(255,255,255,.02); }
.row2{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }
.btn{ background:linear-gradient(135deg,#4da3ff,#6a5cff); border:none; color:#fff; border-radius:10px; padding:11px 18px; font-size:14px; font-weight:600; cursor:pointer; }
.btn.ghost{ background:transparent; border:1px solid var(--border); color:#bcd8ff; }
.btn:hover{ filter:brightness(1.08); }
.flash{ padding:11px 15px; border-radius:11px; margin-bottom:16px; font-size:13.5px; display:flex; align-items:center; gap:9px; }
.flash.ok{ background:rgba(46,204,113,.14); border:1px solid rgba(46,204,113,.4); color:#8fe6b4; }
.flash.err{ background:rgba(231,76,60,.14); border:1px solid rgba(231,76,60,.4); color:#ff9d92; }
.avatar-edit{ display:flex; align-items:center; gap:12px; flex-wrap:wrap; margin-bottom:6px; }
.avatar-edit input[type=file]{ font-size:12px; color:#aeb8c7; }
.hint{ font-size:11.5px; color:#6f7a8c; margin-top:6px; }
.muted{ color:#8b95a7; }
</style>

<div class="up">
  <div class="up-hero glass">
    <div class="av"><?php if ($avatar): ?><img src="<?= $e($avatar) ?>" alt="avatar"><?php else: ?><span class="ini"><?= $e($initial) ?></span><?php endif; ?></div>
    <div class="up-idc">
      <div class="up-name"><?= $e($u['name'] ?: $u['USERNAME']) ?> <span class="rolechip"><i class="fa-solid fa-user-shield"></i> <?= $e($u['role']) ?></span></div>
      <div class="up-sub">
        <span>@<b><?= $e($u['USERNAME']) ?></b></span>
        <?php if (!empty($u['title'])): ?><span><b><?= $e($u['title']) ?></b></span><?php endif; ?>
        <?php if (!empty($u['email'])): ?><span><i class="fa-solid fa-envelope"></i> <b><?= $e($u['email']) ?></b></span><?php endif; ?>
        <?php if (!empty($u['last_login'])): ?><span class="muted">last login <?= $e($u['last_login']) ?></span><?php endif; ?>
      </div>
    </div>
  </div>

  <?php if ($msg): ?><div class="flash ok"><i class="fa-solid fa-circle-check"></i> <?= $e($msg) ?></div><?php endif; ?>
  <?php if ($err): ?><div class="flash err"><i class="fa-solid fa-triangle-exclamation"></i> <?= $e($err) ?></div><?php endif; ?>

  <div class="grid">
    <!-- Profile -->
    <form class="glass card" method="post" enctype="multipart/form-data">
      <input type="hidden" name="action" value="save_profile">
      <div class="ctitle"><i class="fa-solid fa-id-badge" style="color:var(--accent)"></i> Profile</div>
      <div class="fld">
        <label>Profile photo</label>
        <div class="avatar-edit">
          <input type="file" name="avatar" accept="image/png,image/jpeg,image/gif,image/webp">
          <?php if ($avatar): ?><label class="muted" style="font-size:12px;cursor:pointer"><input type="checkbox" name="remove_avatar" value="1"> remove</label><?php endif; ?>
        </div>
        <div class="hint">JPG / PNG / WebP, up to 5 MB. Shown in the top bar.</div>
      </div>
      <div class="fld"><label>Display name</label><input type="text" name="name" value="<?= $e($u['name']) ?>" placeholder="Your name"></div>
      <div class="row2">
        <div class="fld"><label>Email</label><input type="email" name="email" value="<?= $e($u['email']) ?>" placeholder="you@example.com"></div>
        <div class="fld"><label>Phone</label><input type="text" name="phone" value="<?= $e($u['phone'] ?? '') ?>" placeholder="+1 787…"></div>
      </div>
      <div class="fld"><label>Title / Role description</label><input type="text" name="title" value="<?= $e($u['title'] ?? '') ?>" placeholder="Network Operations Engineer"></div>
      <div class="row2">
        <div class="fld"><label>Username (read-only)</label><input type="text" value="<?= $e($u['USERNAME']) ?>" disabled></div>
        <div class="fld"><label>Access role (read-only)</label><input type="text" value="<?= $e($u['role']) ?>" disabled></div>
      </div>
      <button class="btn" type="submit"><i class="fa-solid fa-floppy-disk"></i> Save profile</button>
    </form>

    <!-- Password -->
    <form class="glass card" method="post" autocomplete="off">
      <input type="hidden" name="action" value="change_password">
      <div class="ctitle"><i class="fa-solid fa-key" style="color:var(--purple)"></i> Change password</div>
      <div class="fld"><label>Current password</label><input type="password" name="current_password" autocomplete="current-password" required></div>
      <div class="fld"><label>New password</label><input type="password" name="new_password" autocomplete="new-password" minlength="8" required></div>
      <div class="fld"><label>Confirm new password</label><input type="password" name="confirm_password" autocomplete="new-password" minlength="8" required></div>
      <div class="hint" style="margin-bottom:14px">Minimum 8 characters. You stay logged in after changing it.</div>
      <button class="btn ghost" type="submit"><i class="fa-solid fa-lock"></i> Update password</button>
      <?php if (checkAccess($conn, 'user_admin')): ?>
      <div class="hint" style="margin-top:16px;border-top:1px dashed var(--border);padding-top:12px">
        <i class="fa-solid fa-user-shield"></i> Manage other users &amp; roles in <a href="access_admin.php" style="color:var(--accent)">Access Control</a>.
      </div>
      <?php endif; ?>
    </form>
  </div>

  <!-- Two-Factor Authentication -->
  <div class="glass card" id="twofa" style="margin-top:18px">
    <div class="ctitle"><i class="fa-solid fa-shield-halved" style="color:#36e3d0"></i> Two-Factor Authentication (2FA) <span style="font-size:11px;color:#8b95a7;text-transform:none;letter-spacing:0;margin-left:6px">optional · TOTP</span></div>

    <?php if ($tfa['enabled']): ?>
      <div class="flash ok" style="margin-bottom:14px"><i class="fa-solid fa-circle-check"></i> 2FA is <b>ON</b> — you'll enter a code from your authenticator app when you sign in. Backup codes remaining: <b><?= (int)$tfaBackupCount ?></b>.</div>
      <?php if ($tfaBackup): ?>
        <div class="fld"><label>Your backup codes — save these now (each works once, if you lose your phone)</label>
          <div style="font-family:Consolas,monospace;background:#070b14;border:1px solid var(--border);border-radius:9px;padding:14px;columns:2;font-size:15px;letter-spacing:1px;color:#8ee6da">
            <?php foreach ($tfaBackup as $bc): ?><div><?= $e($bc) ?></div><?php endforeach; ?>
          </div>
          <div class="hint">Keep them in a password manager. They're the only way in if your authenticator is unavailable.</div>
        </div>
      <?php endif; ?>
      <div class="row2" style="margin-top:6px">
        <form method="post" onsubmit="return confirm('Turn 2FA OFF for your account?')">
          <input type="hidden" name="action" value="2fa_disable">
          <div class="fld"><label>Turn OFF — enter a current code to confirm</label><input type="text" name="code" autocomplete="off" placeholder="123456 or a backup code" required></div>
          <button class="btn ghost" type="submit"><i class="fa-solid fa-toggle-off"></i> Disable 2FA</button>
        </form>
        <form method="post">
          <input type="hidden" name="action" value="2fa_regen">
          <div class="fld"><label>New backup codes — enter a current code</label><input type="text" name="code" autocomplete="off" placeholder="123456 or a backup code" required></div>
          <button class="btn ghost" type="submit"><i class="fa-solid fa-rotate"></i> Regenerate backup codes</button>
        </form>
      </div>

    <?php elseif ($tfa['has_secret'] && $tfaUri !== ''): ?>
      <div class="muted" style="margin-bottom:14px">Scan this with any authenticator app — <b>Google Authenticator</b>, Microsoft Authenticator, Authy, 1Password, Bitwarden, FreeOTP or Aegis — then enter the 6-digit code to finish.</div>
      <div style="display:flex;gap:26px;flex-wrap:wrap;align-items:flex-start">
        <div id="tfa-qr" style="background:#fff;padding:10px;border-radius:10px;line-height:0"></div>
        <div style="flex:1;min-width:250px">
          <div class="fld"><label>Or type this key into the app manually</label><input type="text" value="<?= $e($tfaSecret) ?>" readonly onclick="this.select()" style="font-family:Consolas,monospace;letter-spacing:1px"></div>
          <form method="post">
            <input type="hidden" name="action" value="2fa_confirm">
            <div class="fld"><label>Enter the 6-digit code from your app</label><input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" required style="letter-spacing:4px;text-align:center;font-size:19px"></div>
            <button class="btn" type="submit"><i class="fa-solid fa-check"></i> Verify &amp; turn on 2FA</button>
            <a href="user_profile.php?tfa_cancel=1" class="btn ghost" style="text-decoration:none;margin-left:8px">Cancel</a>
          </form>
        </div>
      </div>
      <script src="qrcode.min.js"></script>
      <script>try{ new QRCode(document.getElementById('tfa-qr'), { text: <?= json_encode($tfaUri) ?>, width:186, height:186, correctLevel: QRCode.CorrectLevel.M }); }catch(e){ document.getElementById('tfa-qr').innerHTML='<div style="color:#333;padding:20px;font-size:12px">QR unavailable — use the manual key</div>'; }</script>

    <?php else: ?>
      <div class="muted" style="margin-bottom:16px">Add a second layer of security. After your password, you'll enter a 6-digit code from an authenticator app on your phone. It's <b>optional</b> and you can turn it off anytime.</div>
      <form method="post"><input type="hidden" name="action" value="2fa_begin">
        <button class="btn" type="submit"><i class="fa-solid fa-shield-halved"></i> Enable 2FA</button>
      </form>
    <?php endif; ?>
  </div>
</div>
<script>document.addEventListener('DOMContentLoaded',()=>{ if(window.NMLoader) NMLoader.hide(); });</script>
</body></html>
