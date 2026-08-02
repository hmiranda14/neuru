<?php
// Access-denied page. Shown when a logged-in user lacks permission for a page.
// The denial itself is audit-logged in access_control.php (checkAccess).
if (session_status() === PHP_SESSION_NONE) session_start();
http_response_code(403);
$page = preg_replace('/[^a-zA-Z0-9_.-]/', '', $_GET['page'] ?? '');
$user = $_SESSION['username'] ?? null;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Access Denied — NetMon</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <style>
        body { margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#0f1117; color:#e6e8eb;
               display:flex; align-items:center; justify-content:center; min-height:100vh; }
        .card { background:#171a21; border:1px solid #262b36; border-radius:14px; padding:40px 44px;
                max-width:440px; text-align:center; box-shadow:0 10px 40px rgba(0,0,0,.4); }
        .icon { font-size:46px; color:#e74c3c; margin-bottom:14px; }
        h1 { font-size:20px; margin:0 0 10px; }
        p { color:#9aa0a6; font-size:14px; line-height:1.5; margin:0 0 22px; }
        code { color:#f0b860; background:rgba(240,184,96,.08); padding:1px 6px; border-radius:4px; }
        a.btn { display:inline-flex; align-items:center; gap:8px; background:rgba(77,163,255,.15);
                border:1px solid #4da3ff; color:#4da3ff; padding:10px 20px; border-radius:9px;
                text-decoration:none; font-weight:600; font-size:13px; }
        a.btn:hover { background:#4da3ff; color:#0f1117; }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon"><i class="fas fa-ban"></i></div>
        <h1>Access Denied</h1>
        <p>
            <?php if ($user): ?>
                Your account does not have permission to access
                <?= $page ? "<code>" . htmlspecialchars($page) . "</code>" : "this page" ?>.
                Contact an administrator if you believe this is a mistake.
            <?php else: ?>
                You must be signed in to view this page.
            <?php endif ?>
        </p>
        <a class="btn" href="<?= $user ? 'net_mon.php' : 'index.php' ?>">
            <i class="fas fa-arrow-left"></i> <?= $user ? 'Back to Dashboard' : 'Sign in' ?>
        </a>
    </div>
</body>
</html>
