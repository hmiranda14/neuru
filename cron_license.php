<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — license heartbeat cron. Revalidates this install against the NEURU
// License Portal on a schedule so the cached token stays fresh and the free tier
// keeps its "never expires" guarantee (a free license never lapses as long as it
// heartbeats). Reports the current node count for soft node-limit tracking.
//
// Safe & best-effort: if the install has never been activated, or the portal is
// unreachable, it does nothing harmful — the existing token keeps working within
// its grace window. No secrets are touched, so this runs fine from CLI or HTTP.
// Run:  php cron_license.php     (or via HTTP cron with X-NetMon-Token)
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/connection.php';
if (php_sapi_name() !== 'cli') {
    $tok = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $want = '';
    try { $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='n8n_inbound_token' LIMIT 1"); if ($r && $r->num_rows) $want = (string)$r->fetch_assoc()['setting_val']; } catch (\Throwable $e) {}
    if ($want === '' || !hash_equals($want, (string)$tok)) { http_response_code(403); echo 'forbidden'; exit; }
    header('Content-Type: application/json');
}
require_once __DIR__ . '/nm_license.php';

$out = ['ok' => true, 'ran' => false];
try {
    nm_lic_ensure($conn);
    $row = nm_lic_row($conn);
    // Nothing to heartbeat if never activated, or no portal configured.
    if (!$row || empty($row['license_key']) || nm_lic_api_base($conn) === '') {
        $out['note'] = 'not_activated_or_no_portal';
        echo json_encode($out); exit;
    }
    $out['ran'] = true;
    $res = nm_lic_validate($conn);
    $out['result'] = ['ok' => !empty($res['ok'])];
    if (!empty($res['warning'])) $out['result']['warning'] = $res['warning'];
    if (empty($res['ok']) && !empty($res['error'])) $out['result']['error'] = $res['error'];

    // Best-effort: keep the customer's subscribed hosted flows wired (webhook URLs) up to date.
    // No-op if the Portal hasn't shipped /v1/flows/sync or the license has no subscription.
    try {
        require_once __DIR__ . '/nm_n8n.php';
        if (function_exists('nm_n8n_flows_sync')) {
            $fs = nm_n8n_flows_sync($conn);
            $out['flows'] = !empty($fs['ok'])
                ? ['ok' => true, 'applied' => $fs['applied'] ?? 0, 'disabled' => $fs['disabled'] ?? 0]
                : ['ok' => false, 'skip' => $fs['error'] ?? 'n/a'];
        }
    } catch (\Throwable $e) { $out['flows'] = ['ok' => false, 'skip' => $e->getMessage()]; }
} catch (\Throwable $e) {
    $out['ok'] = false; $out['error'] = $e->getMessage();
}
echo json_encode($out);
