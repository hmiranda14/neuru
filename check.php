<?php
include('connection-users.php');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ── Federation SSO: a slave serving its NATIVE dashboard to the master's embed.
// A valid short-lived HMAC token authorizes THIS request read-only (no login). Must
// run BEFORE the login gate (otherwise the redirect to index.php breaks the iframe).
if (isset($_GET['fed_sig'], $_GET['fed_site'], $_GET['fed_exp'])) {
    require_once __DIR__ . '/connection.php';         // netmon DB (nm_cluster tables)
    require_once __DIR__ . '/nm_fed_auth.php';
    $__fed = nm_fed_request_auth($conn);
    // SCOPE: a valid token authorizes ONLY the embeddable device-dashboard scripts (allowlist),
    // never the whole portal — so it can't be replayed against e.g. config_mgr's snapshot api
    // (which returns device running-configs with secrets). Anything else → normal RBAC / denied.
    if ($__fed && nm_fed_page_allowed()) {
        $GLOBALS['_NM_FED']   = $__fed;
        $_SESSION['username'] = $_SESSION['username'] ?? ('fedview@' . $__fed['site']);
        $_SESSION['role']     = 'dashboard';           // read-only role
        $login_user = $_SESSION['username']; $User_email = '';
        return;                                        // authorized embed — skip login gate + page-view audit
    }
    // invalid/expired token in an EMBED → don't bounce to the frame-denied login page
    // (that triggers the browser's "can't display, another site embedded it" error). Show
    // a clear, frameable message instead.
    if (!empty($_GET['embed'])) {
        http_response_code(403);
        echo '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
           . '<body style="margin:0;font-family:Segoe UI,Tahoma,sans-serif;background:#05080f;color:#cfe0f5;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center">'
           . '<div style="max-width:440px;padding:26px"><div style="font-size:36px;margin-bottom:10px">🔒</div>'
           . '<h2 style="margin:.2em 0;color:#fff;font-weight:700">Embedded view not authorized</h2>'
           . '<p style="color:#8aa2c4;font-size:13.5px;line-height:1.65">The federation token is invalid or expired, or this site isn’t running the federation SSO update yet.<br><br>'
           . 'On the master use <b>Open in tab ↗</b>, or reopen the device to mint a fresh token.</p></div></body>';
        exit;
    }
    // otherwise fall through to the normal login gate
}

if (!isset($_SESSION['username'])) {
    header("Location: index.php");
    exit;
}

$user_check = $_SESSION['username'];
$stmt = $conn2->prepare("SELECT role FROM users WHERE USERNAME = ?");
$stmt->bind_param("s", $user_check);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    session_destroy();
    header("Location: index.php");
    exit;
}

$row = $result->fetch_assoc();
$stmt->close();

// Keep the session role in sync with the DB so role changes (and the permissions
// they unlock) take effect on the next page load — no re-login required.
// Per-user overrides are always resolved live from the DB.
$_SESSION['role'] = $row['role'];

$login_user = $_SESSION['username'];
$User_email = $_SESSION['email'] ?? '';

// ── Audit: record this page view (skipped automatically for AJAX endpoints that
//    return before including check.php) ──────────────────────────────────────
require_once __DIR__ . '/nm_audit.php';
nm_audit($conn2, 'page.view', [
    'target_type' => 'page',
    'target_id'   => basename($_SERVER['SCRIPT_NAME'] ?? 'unknown'),
]);
?>
