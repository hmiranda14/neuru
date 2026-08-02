<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!empty($_SESSION['username'])) {
    header('Location: home.php');
    exit;
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Abort a pending 2FA challenge → back to a clean sign-in.
if (isset($_GET['cancel2fa'])) { unset($_SESSION['pending_2fa']); header('Location: index.php'); exit; }

include('login.php');
require_once __DIR__ . '/nm_chrome.php';   // NEURU brand mark

header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NEURU — Neural Network Monitor</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0f172a;
            --card: rgba(255,255,255,0.07);
            --border: rgba(255,255,255,0.12);
            --accent: #38bdf8;
            --text: #f1f5f9;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background: radial-gradient(circle at 20% 20%, #16243d 0%, #0b1220 55%, #060a12 100%);
            font-family: 'Inter', sans-serif;
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .login-wrap {
            width: 100%;
            max-width: 420px;
            position: relative;
            z-index: 1;
        }
        .login-header {
            text-align: center;
            margin-bottom: 32px;
        }
        .login-header .brand-hero {
            margin-bottom: 14px;
            filter: drop-shadow(0 0 18px rgba(77,163,255,0.45));
        }
        .login-header h1 {
            font-size: 2.6rem;
            font-weight: 800;
            letter-spacing: 6px;
            margin-left: 6px; /* optical centering vs the letter-spacing */
        }
        .login-header p {
            font-size: 0.72rem;
            margin-top: 10px;
        }
        <?= nm_brand_css() ?>
        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 32px;
            backdrop-filter: blur(12px);
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        }
        label {
            display: block;
            font-size: 0.85rem;
            font-weight: 600;
            margin-bottom: 6px;
            opacity: 0.8;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px 14px;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
            border-radius: 10px;
            color: #fff;
            font-size: 0.95rem;
            margin-bottom: 18px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(56,189,248,0.15);
        }
        input[type="submit"] {
            width: 100%;
            padding: 13px;
            background: linear-gradient(135deg, #0369a1, #1e3a5f);
            color: #fff;
            border: none;
            border-radius: 10px;
            font-size: 0.95rem;
            font-weight: 700;
            cursor: pointer;
            letter-spacing: 0.5px;
            transition: filter 0.2s, transform 0.15s;
        }
        input[type="submit"]:hover {
            filter: brightness(1.15);
            transform: translateY(-1px);
        }
        .error-box {
            background: rgba(239,68,68,0.12);
            border-left: 3px solid #ef4444;
            color: #fca5a5;
            padding: 10px 14px;
            border-radius: 8px;
            margin-bottom: 18px;
            font-size: 0.88rem;
        }
    </style>
</head>
<body>

<div class="login-wrap">
    <div class="login-header">
        <div class="brand-hero"><?= nm_logo_svg(58) ?></div>
        <h1 class="neuru-word">NEURU</h1>
        <p class="neuru-tag">Neural Network Monitor</p>
    </div>

    <div class="card">
        <?php if (!empty($show_2fa)): ?>
        <!-- STEP 2 — two-factor code -->
        <form method="post" action="">
            <?php if (!empty($error)): ?>
                <div class="error-box"><i class="fas fa-exclamation-circle"></i> <?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <div style="text-align:center;margin:2px 0 14px">
                <i class="fas fa-shield-halved" style="font-size:30px;color:#36e3d0"></i>
                <div style="font-size:14px;color:#cbd5e1;margin-top:8px">Enter the 6-digit code from your authenticator app.</div>
            </div>
            <label for="totp_code">Authentication code</label>
            <input name="totp_code" id="totp_code" type="text" inputmode="numeric" autocomplete="one-time-code"
                   pattern="[0-9A-Za-z\- ]*" required placeholder="123456  ·  or a backup code" style="text-align:center;letter-spacing:3px;font-size:18px">
            <input type="submit" name="verify_2fa" value="Verify">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <div style="text-align:center;margin-top:12px;font-size:12px"><a href="index.php?cancel2fa=1" style="color:#8aa2c4">← Back to sign in</a> · lost your device? use a <b>backup code</b></div>
        </form>
        <?php else: ?>
        <form method="post" action="">
            <?php if (!empty($error)): ?>
                <div class="error-box"><i class="fas fa-exclamation-circle"></i> <?= htmlspecialchars($error) ?></div>
            <?php endif; ?>

            <label for="username">Username</label>
            <input name="username" type="text" id="username" required autocomplete="username" placeholder="Enter username">

            <label for="password">Password</label>
            <input name="password" type="password" id="password" required autocomplete="current-password" placeholder="••••••••">

            <input type="submit" name="submit" value="Sign In">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
        </form>
        <?php endif; ?>
    </div>
</div>

<script src="nm_netbg.js"></script>
<script>
    document.addEventListener("DOMContentLoaded", function () {
        var f = document.getElementById("totp_code") || document.getElementById("username");
        if (f) f.focus();
        if (window.NMNetBG) NMNetBG.init({ color: '#38bdf8', density: 1.05, mouseDist: 195, linkDist: 150 });
    });
</script>
</body>
</html>
