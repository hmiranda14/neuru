<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — Graylog integration. Config lives in the DB (nm_settings), like the
// LibreNMS helper. Keys: graylog_url, graylog_token, graylog_enabled.
// Auth: Graylog access tokens use HTTP Basic where username=<token>, password
// is the literal "token".  All calls send X-Requested-By + Accept: json.
// ─────────────────────────────────────────────────────────────────────────────

if (!function_exists('nm_graylog_get')) {

    function nm_graylog_save($conn, array $cfg): bool {
        if (!($conn instanceof mysqli)) return false;
        $rows = [
            'graylog_url'     => rtrim(trim((string)($cfg['url'] ?? '')), '/'),
            'graylog_token'   => trim((string)($cfg['token'] ?? '')),
            'graylog_enabled' => !empty($cfg['enabled']) ? '1' : '0',
        ];
        $st = $conn->prepare("INSERT INTO nm_settings (setting_key, setting_val) VALUES (?, ?)
                              ON DUPLICATE KEY UPDATE setting_val = VALUES(setting_val)");
        if (!$st) return false;
        foreach ($rows as $k => $v) { $st->bind_param('ss', $k, $v); $st->execute(); }
        $st->close();
        return true;
    }

    function nm_graylog_get($conn): array {
        $cfg = ['url' => '', 'token' => '', 'enabled' => false];
        if (!($conn instanceof mysqli)) return $cfg;
        $res = @$conn->query("SELECT setting_key, setting_val FROM nm_settings
                              WHERE setting_key IN ('graylog_url','graylog_token','graylog_enabled')");
        if ($res) while ($r = $res->fetch_assoc()) {
            switch ($r['setting_key']) {
                case 'graylog_url':     $cfg['url']     = $r['setting_val']; break;
                case 'graylog_token':   $cfg['token']   = $r['setting_val']; break;
                case 'graylog_enabled': $cfg['enabled'] = (bool)(int)$r['setting_val']; break;
            }
        }
        return $cfg;
    }

    // Low-level GET against the Graylog REST API. Returns [httpcode, decoded|null, err].
    function nm_graylog_api($cfg, string $path, array $query = []): array {
        $base = rtrim($cfg['url'] ?? '', '/');
        $tok  = $cfg['token'] ?? '';
        if ($base === '' || $tok === '') return [0, null, 'Graylog URL/token not configured'];
        $url = $base . $path . ($query ? ('?' . http_build_query($query)) : '');
        $ch  = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 4,
            CURLOPT_TIMEOUT        => 12,
            CURLOPT_USERPWD        => $tok . ':token',          // token auth
            CURLOPT_HTTPHEADER     => ['Accept: application/json', 'X-Requested-By: netmon'],
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
        ]);
        $body = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $cerr = curl_error($ch);
        curl_close($ch);
        if ($body === false) return [0, null, $cerr ?: 'Connection failed'];
        $json = json_decode($body, true);
        return [$code, $json, $code >= 400 ? ('HTTP ' . $code) : null];
    }

    // Build the Graylog query for a node: match its source(s). Graylog's `source`
    // field is typically the device hostname or IP. We OR the configured source,
    // the node IP, and the display name so it works out of the box.
    function nm_graylog_source_query($node): string {
        $terms = [];
        foreach (['graylog_source', 'ip_address', 'display_name'] as $f) {
            $v = trim((string)($node[$f] ?? ''));
            if ($v !== '') $terms[] = 'source:"' . str_replace('"', '', $v) . '"';
        }
        $terms = array_values(array_unique($terms));
        return $terms ? '(' . implode(' OR ', $terms) . ')' : '*';
    }

    // Relative universal search. $rangeSec seconds back from now.
    // Returns [httpcode, ['messages'=>[...], 'total'=>n], err].
    function nm_graylog_search($cfg, string $query, int $rangeSec, int $limit = 150): array {
        [$code, $json, $err] = nm_graylog_api($cfg, '/api/search/universal/relative', [
            'query' => $query ?: '*',
            'range' => $rangeSec,
            'limit' => $limit,
            'sort'  => 'timestamp:desc',
            'fields'=> 'timestamp,source,message,level,facility,application_name',
        ]);
        if ($err) return [$code, null, $err];
        $msgs = [];
        foreach (($json['messages'] ?? []) as $m) {
            $mm = $m['message'] ?? $m;
            // Normalise syslog severity to 0..7; anything outside (e.g. MikroTik's
            // -1 "unknown") becomes null so the UI shows a neutral badge.
            $lvl = isset($mm['level']) && $mm['level'] !== '' ? (int)$mm['level'] : null;
            if ($lvl !== null && ($lvl < 0 || $lvl > 7)) $lvl = null;
            $msgs[] = [
                'timestamp' => $mm['timestamp']   ?? '',
                'source'    => $mm['source']       ?? '',
                'level'     => $lvl,
                'facility'  => $mm['facility']     ?? ($mm['application_name'] ?? ''),
                'message'   => $mm['message']      ?? '',
            ];
        }
        return [$code, ['messages' => $msgs, 'total' => (int)($json['total_results'] ?? count($msgs))], null];
    }
}
