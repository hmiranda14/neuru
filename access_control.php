<?php
require_once __DIR__ . '/nm_audit.php';
require_once __DIR__ . '/nm_access.php';

// Self-heal RBAC: ensure the owner ('admin') role has a grant row for EVERY catalog permission,
// so a gated page added by a product UPDATE is immediately visible to the owner WITHOUT having to
// open Access Control first. Previously nm_access_ensure() ran only inside access_admin.php, so
// newly-shipped pages (e.g. Stream Decks) stayed hidden until then. It's idempotent + guarded
// (runs its backfill once per request, only INSERTs missing admin grants, never revokes). Best-effort.
if (isset($conn) && ($conn instanceof mysqli) && function_exists('nm_access_ensure')) {
    try { nm_access_ensure($conn); } catch (\Throwable $e) { /* never block a page on RBAC self-heal */ }
}

// ── Federated embed bootstrap (runs on include, BEFORE any page's inline ?api= guard) ──
// A slave page fetched inside the master's Remote Console iframe carries fed_sig/site/exp
// but NO cookie session (browsers block 3rd-party cookies in an iframe). check.php sets up
// _NM_FED for the HTML render — but a page's inline `?api=` data-endpoints run FIRST (they
// exit before check.php is ever included). Without this early bootstrap those GET data-apis
// 403 on an empty session, so the embedded widgets (NetFlow data, alert thresholds, Data
// Core, …) render EMPTY on the master while working fine on the site itself. Here we
// validate the signed token once — allowlisted scripts + GET only — and grant the same
// read-only fed session so those GET apis authorize. Writes (POST) are never granted.
if (empty($GLOBALS['_NM_FED'])
    && isset($_GET['fed_sig'], $_GET['fed_site'], $_GET['fed_exp'])
    && (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET')
    && isset($conn) && ($conn instanceof mysqli)) {
    if (!function_exists('nm_fed_request_auth')) { $__f = __DIR__ . '/nm_fed_auth.php'; if (is_file($__f)) require_once $__f; }
    if (function_exists('nm_fed_request_auth') && function_exists('nm_fed_page_allowed') && nm_fed_page_allowed()) {
        $__fed = nm_fed_request_auth($conn);
        if ($__fed) {
            if (session_status() === PHP_SESSION_NONE) @session_start();
            $GLOBALS['_NM_FED'] = $__fed;
            if (empty($_SESSION['username'])) $_SESSION['username'] = 'fedview@' . $__fed['site'];
        }
    }
}

// Page-handler gate. Resolves ROLE default + per-user override (see nm_access.php)
// and audits a denial. Signature unchanged — every existing page keeps working.
function checkAccess($conn, $buttonKey) {
    // Federated read-only embed (a slave's native dashboard shown on the master via a
    // valid HMAC token — set in check.php). GET only → the page + its data-apis render;
    // any write (POST) falls through and is denied. See nm_fed_auth.php.
    if (!empty($GLOBALS['_NM_FED']) && (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET')) return true;
    $role    = $_SESSION['role'] ?? 'guest';
    $uid     = (int)($_SESSION['UID'] ?? 0);
    $allowed = nm_user_can($conn, $uid, $role, $buttonKey);

    if (!$allowed) {
        nm_audit($conn, 'access.denied', [
            'status'      => 'denied',
            'target_type' => 'page',
            'target_id'   => $buttonKey,
            'details'     => ['role' => $role, 'uid' => $uid],
        ]);
    }
    return $allowed;
}
?>
