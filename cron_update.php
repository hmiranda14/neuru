<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — update cron. Runs on a schedule (e.g. daily). Honors the update policy:
//   manual → does nothing (operator checks from the Updates page)
//   notify → checks the portal; if an update is available, raises a banner/alert
//   auto   → checks + downloads & VERIFIES the build into staging (ready to apply).
//            (Extracting files is left to the operator/root helper for safety —
//             never auto-swaps the running app from a cron.)
// Run:  php cron_update.php     (or via the HTTP cron with X-NetMon-Token)
// ─────────────────────────────────────────────────────────────────────────────
if (php_sapi_name() !== 'cli') {
    // allow the same HTTP-cron token pattern the rest of NEURU uses
    require_once __DIR__ . '/connection.php';
    $tok = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $want = '';
    try { $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='n8n_inbound_token' LIMIT 1"); if ($r && $r->num_rows) $want = (string)$r->fetch_assoc()['setting_val']; } catch (\Throwable $e) {}
    if ($want === '' || !hash_equals($want, (string)$tok)) { http_response_code(403); echo 'forbidden'; exit; }
    header('Content-Type: application/json');
} else {
    require_once __DIR__ . '/connection.php';
}
require_once __DIR__ . '/nm_update.php';

$out = ['ok' => true, 'ran' => false];
$policy = nm_update_policy($conn);
if ($policy === 'manual') { $out['policy'] = 'manual'; $out['note'] = 'nothing to do'; echo json_encode($out); exit; }

$out['ran'] = true; $out['policy'] = $policy;
$res = nm_update_check($conn);
$out['check'] = $res;

if (!empty($res['update_available'])) {
    $ver = $res['version'];
    nm_update_set($conn, 'update_available_banner', $ver);        // header/UI can surface this
    nm_audit_safe($conn, 'update.available', ['version' => $ver, 'channel' => $res['channel'] ?? 'stable']);
    // best-effort notification through NEURU's alert pipeline, if present
    if (function_exists('nm_notify_send')) {
        try { nm_notify_send($conn, 'NEURU update available', "Version {$ver} is available for your license. Open Updates to review and apply.", 'info'); } catch (\Throwable $e) {}
    }
    if ($policy === 'auto') {
        // download + cryptographically verify into staging (does NOT extract)
        $dl = nm_update_download($conn, $ver);
        $out['download'] = $dl;
        if (!empty($dl['ok'])) nm_audit_safe($conn, 'update.auto_staged', ['version' => $ver]);
    }
} else {
    nm_update_set($conn, 'update_available_banner', '');
}
echo json_encode($out);
