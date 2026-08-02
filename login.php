<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

include("connection-users.php");
require_once __DIR__ . '/nm_audit.php';
require_once __DIR__ . '/nm_2fa.php';

$error = "";
$show_2fa = !empty($_SESSION['pending_2fa']);   // index.php renders the code prompt when set

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['totp_code']) && !empty($_SESSION['pending_2fa'])) {
    // ── STEP 2: the 2FA code (password was already verified this session) ──────
    $p = $_SESSION['pending_2fa'];
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "Invalid CSRF token.";
    } elseif (time() - (int)$p['at'] > 300) {
        unset($_SESSION['pending_2fa']); $show_2fa = false;
        $error = "Verification timed out — please log in again.";
    } elseif (nm_2fa_login_verify($conn2, (int)$p['uid'], (string)($_POST['totp_code'] ?? ''))) {
        $_SESSION['username'] = $p['username']; $_SESSION['role'] = $p['role'];
        $_SESSION['UID'] = (int)$p['uid'];      $_SESSION['email'] = $p['email'];
        unset($_SESSION['pending_2fa']);
        $ll = $conn2->prepare("UPDATE users SET last_login = NOW() WHERE UID = ?");
        $ll->bind_param("i", $_SESSION['UID']); $ll->execute(); $ll->close();
        _logLogin($conn2, $p['username'], 'login_success', '2FA verified');
        nm_audit($conn2, 'auth.login', ['username'=>$p['username'],'role'=>$p['role'],
            'target_type'=>'user','target_id'=>(int)$p['uid'],'details'=>['twofa'=>true]]);
        session_regenerate_id(true);
        header("Location: " . ($p['role'] === 'dashboard' ? 'geomap.php' : 'home.php')); exit;
    } else {
        $error = "Invalid authentication code."; $show_2fa = true;
        _logLogin($conn2, $p['username'], 'login_failure', '2FA code invalid');
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "Invalid CSRF token.";
        _logLogin($conn2, $_POST['username'] ?? 'unknown', 'login_failure', 'CSRF token mismatch');
        nm_audit($conn2, 'auth.login', ['username' => $_POST['username'] ?? 'unknown', 'status' => 'failure',
            'target_type' => 'user', 'details' => ['reason' => 'csrf_mismatch']]);
    } elseif (empty($_POST["username"]) || empty($_POST["password"])) {
        $error = "Both fields are required.";
    } else {
        $username    = $_POST['username'];
        $raw_password = $_POST['password'];

        $stmt = $conn2->prepare("SELECT UID, PASSWORD, role, email FROM users WHERE USERNAME = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($user = $result->fetch_assoc()) {
            $stored_hash   = $user['PASSWORD'];
            $authenticated = false;
            $needs_migration = false;

            if (strpos($stored_hash, '$2y$') === 0) {
                if (password_verify($raw_password, $stored_hash)) {
                    $authenticated = true;
                }
            } elseif ($stored_hash === md5($raw_password)) {
                $authenticated = true;
                $needs_migration = true;
            }

            if ($authenticated) {
                if ($needs_migration) {
                    $new_hash = password_hash($raw_password, PASSWORD_DEFAULT);
                    $upd = $conn2->prepare("UPDATE users SET PASSWORD = ? WHERE UID = ?");
                    $upd->bind_param("si", $new_hash, $user['UID']);
                    $upd->execute();
                    $upd->close();
                }

                // ── 2FA gate: if this user turned on 2FA, DON'T complete login yet — stash a
                // short-lived pending state; index.php shows the code prompt (STEP 2 above). ──
                if (nm_2fa_status($conn2, (int)$user['UID'])['enabled']) {
                    $_SESSION['pending_2fa'] = ['uid'=>(int)$user['UID'], 'at'=>time(),
                        'username'=>$username, 'role'=>$user['role'], 'email'=>strtolower(trim($user['email']))];
                    $show_2fa = true;
                    _logLogin($conn2, $username, 'login_2fa_prompt', 'Password OK — awaiting 2FA code');
                    // fall through (no redirect) → the outer $stmt->close() runs, then the login
                    // page renders the 2FA form. (Do NOT close $stmt here — double close = 500.)
                } else {

                $_SESSION['username'] = $username;
                $_SESSION['role']     = $user['role'];
                $_SESSION['UID']      = $user['UID'];
                $_SESSION['email']    = strtolower(trim($user['email']));

                // Stamp last login for the Access Control console.
                $ll = $conn2->prepare("UPDATE users SET last_login = NOW() WHERE UID = ?");
                $ll->bind_param("i", $user['UID']);
                $ll->execute();
                $ll->close();

                _logLogin($conn2, $username, 'login_success', 'Authenticated' . ($needs_migration ? ' & migrated' : ''));
                nm_audit($conn2, 'auth.login', [
                    'username'    => $username,
                    'role'        => $user['role'],
                    'target_type' => 'user',
                    'target_id'   => $user['UID'],
                    'details'     => $needs_migration ? ['migrated' => true] : null,
                ]);
                session_regenerate_id(true);

                // Role-aware landing: the read-only 'dashboard' role goes straight to
                // the NOC geo wall; everyone else to the futuristic Command Deck launchpad.
                $land = ($user['role'] === 'dashboard') ? 'geomap.php' : 'home.php';
                header("Location: " . $land);
                exit;
                }   // ← close the 2FA-gate else (non-2FA full-login path)
            } else {
                $error = "Incorrect username or password.";
                _logLogin($conn2, $username, 'login_failure', 'Invalid password');
                nm_audit($conn2, 'auth.login', ['username' => $username, 'status' => 'failure',
                    'target_type' => 'user', 'details' => ['reason' => 'invalid_password']]);
            }
        } else {
            $error = "Incorrect username or password.";
            _logLogin($conn2, $username ?? '', 'login_failure', 'User not found');
            nm_audit($conn2, 'auth.login', ['username' => $username ?? '', 'status' => 'failure',
                'target_type' => 'user', 'details' => ['reason' => 'user_not_found']]);
        }
        $stmt->close();
    }
}

function _logLogin($conn, $username, $actionType, $details = '') {
    $ip    = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $stmt  = $conn->prepare("INSERT INTO user_action_log (username,action_type,action_details,ip_address,user_agent) VALUES (?,?,?,?,?)");
    $stmt->bind_param("sssss", $username, $actionType, $details, $ip, $agent);
    $stmt->execute();
    $stmt->close();
}
?>
