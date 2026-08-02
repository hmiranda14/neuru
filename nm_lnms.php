<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — LibreNMS integration config, stored in the DB (nm_settings), NOT a
// file in the web root. Keeps it writable by www-data and out of the web path.
// Keys: lnms_url, lnms_token, lnms_enabled.
// ─────────────────────────────────────────────────────────────────────────────

if (!function_exists('nm_lnms_save')) {

    function nm_lnms_save($conn, array $cfg): bool {
        if (!($conn instanceof mysqli)) return false;
        $rows = [
            'lnms_url'     => rtrim(trim((string)($cfg['url'] ?? '')), '/'),
            'lnms_token'   => trim((string)($cfg['token'] ?? '')),
            'lnms_enabled' => !empty($cfg['enabled']) ? '1' : '0',
        ];
        $st = $conn->prepare(
            "INSERT INTO nm_settings (setting_key, setting_val) VALUES (?, ?)
             ON DUPLICATE KEY UPDATE setting_val = VALUES(setting_val)"
        );
        if (!$st) return false;
        foreach ($rows as $k => $v) { $st->bind_param('ss', $k, $v); $st->execute(); }
        $st->close();
        return true;
    }

    function nm_lnms_get($conn): array {
        // Default: disabled, no server (do NOT hardcode any host here).
        $cfg = ['url' => '', 'token' => '', 'enabled' => false];
        if (!($conn instanceof mysqli)) return $cfg;

        $have = false;
        $res = @$conn->query(
            "SELECT setting_key, setting_val FROM nm_settings
             WHERE setting_key IN ('lnms_url','lnms_token','lnms_enabled')"
        );
        if ($res) while ($r = $res->fetch_assoc()) {
            $have = true;
            switch ($r['setting_key']) {
                case 'lnms_url':     $cfg['url']     = $r['setting_val']; break;
                case 'lnms_token':   $cfg['token']   = $r['setting_val']; break;
                case 'lnms_enabled': $cfg['enabled'] = (bool)(int)$r['setting_val']; break;
            }
        }

        // One-time migration from the legacy web-root file, if DB has nothing yet.
        if (!$have) {
            $legacy = __DIR__ . '/librenms_config.json';
            if (is_file($legacy)) {
                $j = json_decode(@file_get_contents($legacy), true);
                if (is_array($j)) {
                    $cfg['url']     = $j['url']   ?? '';
                    $cfg['token']   = $j['token'] ?? '';
                    $cfg['enabled'] = !empty($j['enabled']);
                    nm_lnms_save($conn, $cfg);
                }
            }
        }
        return $cfg;
    }
}
