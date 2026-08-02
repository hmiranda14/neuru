<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Support client. Lets the operator open/track support tickets and file
// bug reports WITH this install's version + recent errors + diagnostics, straight
// to the NEURU License Portal (/v1/support/*), so we can troubleshoot fast.
// Transport + auth reuse the license client (nm_lic_http + the stored license key).
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_license.php';   // nm_lic_api_base(), nm_lic_http(), nm_lic_app_version()

if (!function_exists('nm_sup_call')) {

    function nm_sup_key($conn): string {
        try { $r = $conn->query("SELECT license_key FROM nm_license WHERE id=1"); $x = $r ? $r->fetch_assoc() : null; return trim((string)($x['license_key'] ?? '')); }
        catch (\Throwable $e) { return ''; }
    }
    function nm_sup_ready($conn): bool { return nm_sup_key($conn) !== '' && nm_lic_api_base($conn) !== ''; }

    // POST /v1/support/<ep> with {license_key, …}. Returns ['ok'=>bool, …json, 'error'=>?].
    function nm_sup_call($conn, string $ep, array $body): array {
        $base = nm_lic_api_base($conn); if ($base === '') return ['ok' => false, 'error' => 'The License Portal URL is not configured.'];
        $key  = nm_sup_key($conn);      if ($key === '')  return ['ok' => false, 'error' => 'Activate your NEURU license first (Site Configuration → License) so we can link your tickets to your account.'];
        $r = nm_lic_http($base . '/v1/support/' . $ep, array_merge(['license_key' => $key], $body));
        if (empty($r['ok'])) return ['ok' => false, 'error' => ($r['json']['error'] ?? $r['error'] ?? 'request failed') . (isset($r['code']) ? ' (HTTP ' . $r['code'] . ')' : '')];
        return array_merge(['ok' => true], is_array($r['json'] ?? null) ? $r['json'] : []);
    }

    function nm_sup_list($conn): array  { return nm_sup_call($conn, 'list', []); }
    function nm_sup_get($conn, int $id): array   { return nm_sup_call($conn, 'get', ['ticket_id' => $id]); }
    function nm_sup_reply($conn, int $id, string $body): array { return nm_sup_call($conn, 'reply', ['ticket_id' => $id, 'body' => $body]); }

    // Open a ticket. Always stamps this install's version; optionally attaches errors/diagnostics.
    function nm_sup_create($conn, array $in): array {
        $in['neuru_version'] = nm_lic_app_version($conn);
        return nm_sup_call($conn, 'create', $in);
    }

    // ── troubleshooting payload builders ────────────────────────────────────────
    // Tail of the app error log (logs/nm_error.log) — the errors NEURU has detected.
    function nm_sup_recent_errors($conn, int $lines = 60): string {
        $f = __DIR__ . '/logs/nm_error.log';
        if (!is_file($f)) return '';
        $rows = @file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        $tail = implode("\n", array_slice($rows, -max(1, $lines)));
        // scrub query strings from logged URLs (a token/secret could ride in ?param=…) before sending
        return preg_replace('/(\S+\.php)\?\S*/i', '$1?…', $tail);
    }
    // Tail the last N lines of any readable log file, scrubbing query strings (may carry a token).
    function nm_sup_tail_file(string $path, int $lines = 80): string {
        if (!is_file($path) || !is_readable($path)) return '';
        $rows = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        $tail = implode("\n", array_slice($rows, -max(1, $lines)));
        return preg_replace('/(\S+\.php)\?\S*/i', '$1?…', $tail);
    }
    // A RICH health snapshot — the more high-signal context we ship, the faster we diagnose.
    function nm_sup_diagnostics($conn): array {
        $d = ['neuru_version' => nm_lic_app_version($conn), 'php' => PHP_VERSION,
              'os' => php_uname('s') . ' ' . php_uname('r') . ' ' . php_uname('m'), 'at' => date('c'),
              'php_memory_limit' => ini_get('memory_limit'),
              'ext' => implode(',', array_values(array_intersect(['pdo_mysql','mysqli','curl','gd','sodium','openssl','zip'], get_loaded_extensions()))),
              'secret_key' => is_file(__DIR__ . '/.nm_secret.key') ? 'present' : 'MISSING (secrets will not persist!)'];
        $one = function ($sql) use ($conn) { try { $r = $conn->query($sql); return $r ? $r->fetch_assoc() : null; } catch (\Throwable $e) { return null; } };
        if ($x = $one("SELECT COUNT(*) c FROM nm_nodes"))                                    $d['nodes'] = (int)$x['c'];
        if ($x = $one("SELECT COUNT(*) c FROM nm_alert_state WHERE entity_type='node' AND state='down'")) $d['nodes_down'] = (int)$x['c'];
        if ($x = $one("SELECT COUNT(*) c FROM nm_incidents WHERE status IN('open','acknowledged')")) $d['open_incidents'] = (int)$x['c'];
        if ($x = $one("SELECT tier,status FROM nm_license WHERE id=1"))                      $d['license'] = ($x['tier'] ?? '?') . '/' . ($x['status'] ?? '?');
        // disk headroom on the app partition — a full disk is a top silent-failure cause
        $free = @disk_free_space(__DIR__); $tot = @disk_total_space(__DIR__);
        if ($free && $tot) $d['disk'] = round($free / 1073741824, 1) . ' GB free / ' . round($tot / 1073741824, 1) . ' GB';
        // cron heartbeats (a stalled cron is the #1 "why did X stop" issue) — show age, not raw ts
        $hb = []; foreach (['deck_cron_last' => 'streamdeck', 'flows_synced_at' => 'flows_sync'] as $k => $lbl) {
            if ($x = $one("SELECT TIMESTAMPDIFF(MINUTE, setting_val, NOW()) m FROM nm_settings WHERE setting_key='$k'")) if ($x['m'] !== null) $hb[$lbl] = (int)$x['m'] . 'm ago';
        }
        if ($hb) $d['cron_heartbeats'] = $hb;
        return $d;
    }
    // A short human-readable list of what's currently wrong (open incidents) — instant context.
    function nm_sup_recent_incidents($conn, int $n = 15): string {
        try {
            $r = $conn->query("SELECT severity,status,title,opened_at FROM nm_incidents WHERE status IN('open','acknowledged') ORDER BY FIELD(severity,'critical','warning','info'), opened_at DESC LIMIT " . (int)$n);
            if (!$r || !$r->num_rows) return '';
            $out = [];
            while ($x = $r->fetch_assoc()) $out[] = strtoupper($x['severity'] ?? '?') . " [" . ($x['status'] ?? '?') . "] " . ($x['title'] ?? '') . "  (" . substr((string)$x['opened_at'], 0, 16) . ")";
            return implode("\n", $out);
        } catch (\Throwable $e) { return ''; }
    }
    // Bundle a full bug report: message + version + rich diagnostics + errors + open-incident context
    // + (optional) a screenshot the operator attached (a data:image/… URI, downscaled client-side).
    function nm_sup_bug_report($conn, string $subject, string $body, string $priority = 'high', bool $includeErrors = true, string $screenshot = ''): array {
        $payload = ['subject' => $subject, 'body' => $body, 'category' => 'bug', 'priority' => $priority,
                    'diagnostics' => nm_sup_diagnostics($conn)];
        $atts = [];
        if ($includeErrors) {
            $err = nm_sup_recent_errors($conn, 150); if ($err !== '') $payload['log'] = $err;
            $inc = nm_sup_recent_incidents($conn);   if ($inc !== '') $atts[] = ['kind' => 'log', 'body' => "OPEN INCIDENTS (what NEURU currently sees wrong):\n" . $inc];
            // extra readable logs if the container exposes them (best-effort; scrubbed)
            foreach (['/var/log/apache2/error.log', __DIR__ . '/logs/nm_cron.log'] as $lf) {
                $t = nm_sup_tail_file($lf, 60); if ($t !== '') $atts[] = ['kind' => 'log', 'body' => basename($lf) . ":\n" . $t];
            }
        }
        // Screenshot: only a real image data-URI, size-capped (the Portal stores it in MEDIUMTEXT and
        // renders it as an <img>). Client already downscales; this is the server-side safety cap.
        if ($screenshot !== '' && strncmp($screenshot, 'data:image/', 11) === 0 && strlen($screenshot) < 6_000_000) {
            $payload['screenshot'] = $screenshot;
        }
        if ($atts) $payload['attachments'] = $atts;
        return nm_sup_create($conn, $payload);
    }
}
