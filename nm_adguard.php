<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — AdGuard Home REST API client (server-side proxy), MULTI-INSTANCE.
//
//   Mirrors nm_pihole.php so AdGuard Home behaves like "another Pi-hole" across
//   NEURU (monitoring dashboard + Collective Immunity fan-out). Each instance is a
//   row in nm_adguard_servers (name, url, username, encrypted password, verify_tls,
//   enabled). AdGuard auth = HTTP Basic with the web-UI username/password (NO api
//   key, NO session — /control/* accepts Basic directly), so this is stateless and
//   simpler than the Pi-hole v6 sid dance. The browser never talks to AdGuard
//   directly — adguard.php proxies through here so credentials stay server-side and
//   we sidestep CORS, self-signed certs and the portal CSP.
//
//   API surface used:  GET /control/status · /control/stats · /control/querylog ·
//   /control/filtering/status   ·   POST /control/filtering/set_rules · /control/protection
// ─────────────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/nm_secrets.php';

// ── Schema ───────────────────────────────────────────────────────────────────
if (!function_exists('nm_ag_ensure')) {
    function nm_ag_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        if (!($conn instanceof mysqli)) return;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_adguard_servers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(80) NOT NULL DEFAULT 'AdGuard Home',
            url VARCHAR(255) NOT NULL,
            username VARCHAR(120) NOT NULL DEFAULT '',
            password_enc MEDIUMTEXT,
            verify_tls TINYINT(1) NOT NULL DEFAULT 0,
            enabled TINYINT(1) NOT NULL DEFAULT 1,
            sort_order INT NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    }
}

// ── Server CRUD ──────────────────────────────────────────────────────────────
if (!function_exists('nm_ag_servers')) {
    // List servers (no secrets) for the UI. has_pw = the stored password decrypts.
    function nm_ag_servers($conn, bool $onlyEnabled = false): array {
        nm_ag_ensure($conn);
        $out = [];
        $w = $onlyEnabled ? "WHERE enabled=1" : "";
        $r = $conn->query("SELECT id,name,url,username,verify_tls,enabled,password_enc FROM nm_adguard_servers $w ORDER BY sort_order, id");
        while ($r && $x = $r->fetch_assoc()) {
            $out[] = ['id'=>(int)$x['id'], 'name'=>$x['name'], 'url'=>$x['url'], 'username'=>$x['username'],
                'verify'=>(int)$x['verify_tls']===1, 'enabled'=>(int)$x['enabled']===1,
                'has_pw'=>trim((string)nm_secret_decrypt($x['password_enc'])) !== ''];
        }
        return $out;
    }
    // Full server row incl. decrypted password (internal use).
    function nm_ag_get_server($conn, int $id): ?array {
        nm_ag_ensure($conn);
        $st = $conn->prepare("SELECT * FROM nm_adguard_servers WHERE id=? LIMIT 1");
        $st->bind_param('i', $id); $st->execute();
        $x = $st->get_result()->fetch_assoc(); $st->close();
        if (!$x) return null;
        $x['password'] = nm_secret_decrypt($x['password_enc']);
        $x['url'] = rtrim($x['url'], '/');
        $x['verify'] = (int)$x['verify_tls'] === 1;
        return $x;
    }
    function nm_ag_default_id($conn): int {
        nm_ag_ensure($conn);
        $r = $conn->query("SELECT id FROM nm_adguard_servers WHERE enabled=1 ORDER BY sort_order, id LIMIT 1");
        return $r && ($x = $r->fetch_row()) ? (int)$x[0] : 0;
    }
    function nm_ag_enabled($conn): bool { return nm_ag_default_id($conn) > 0; }

    function nm_ag_server_save($conn, array $d): array {
        nm_ag_ensure($conn);
        $id   = (int)($d['id'] ?? 0);
        $name = trim($d['name'] ?? '') ?: 'AdGuard Home';
        $url  = rtrim(trim($d['url'] ?? ''), '/');
        $user = trim($d['username'] ?? '');
        $ver  = !empty($d['verify']) ? 1 : 0;
        $en   = !empty($d['enabled']) ? 1 : 0;
        $pw   = (string)($d['password'] ?? '');
        if ($url === '') return ['ok'=>false, 'err'=>'URL is required'];
        if ($id) {
            if ($pw !== '') {
                $enc = nm_secret_encrypt($pw);
                $st = $conn->prepare("UPDATE nm_adguard_servers SET name=?,url=?,username=?,password_enc=?,verify_tls=?,enabled=? WHERE id=?");
                $st->bind_param('ssssiii', $name, $url, $user, $enc, $ver, $en, $id);
            } else {
                $st = $conn->prepare("UPDATE nm_adguard_servers SET name=?,url=?,username=?,verify_tls=?,enabled=? WHERE id=?");
                $st->bind_param('sssiii', $name, $url, $user, $ver, $en, $id);
            }
            $st->execute(); $st->close();
        } else {
            $enc = $pw !== '' ? nm_secret_encrypt($pw) : '';
            $st = $conn->prepare("INSERT INTO nm_adguard_servers (name,url,username,password_enc,verify_tls,enabled) VALUES (?,?,?,?,?,?)");
            $st->bind_param('ssssii', $name, $url, $user, $enc, $ver, $en); $st->execute(); $id = $st->insert_id; $st->close();
        }
        return ['ok'=>true, 'id'=>$id];
    }
    function nm_ag_server_delete($conn, int $id): void {
        nm_ag_ensure($conn);
        $st = $conn->prepare("DELETE FROM nm_adguard_servers WHERE id=?");
        $st->bind_param('i', $id); $st->execute(); $st->close();
    }
}

// ── Low-level curl (HTTP Basic) against /control/* ───────────────────────────
if (!function_exists('nm_ag_call')) {
    // GET. Returns ['ok'=>bool,'data'=>mixed] | ['ok'=>false,'error'=>...,'code'=>int].
    function nm_ag_call($conn, int $id, string $path, array $query = []): array {
        $S = nm_ag_get_server($conn, $id);
        if (!$S) return ['ok'=>false, 'error'=>'No such AdGuard'];
        if (!$S['enabled']) return ['ok'=>false, 'error'=>'This AdGuard is disabled'];
        if ($S['url'] === '') return ['ok'=>false, 'error'=>'AdGuard URL not configured'];

        $url = $S['url'] . '/control/' . ltrim($path, '/');
        if ($query) $url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($query);
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
            CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
            CURLOPT_USERPWD => $S['username'] . ':' . $S['password'],
            CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_TIMEOUT => 20,
            CURLOPT_SSL_VERIFYPEER => $S['verify'], CURLOPT_SSL_VERIFYHOST => $S['verify'] ? 2 : 0,
        ]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $cerr = curl_error($ch);
        curl_close($ch);

        if ($body === false || $code === 0) return ['ok'=>false, 'error'=>'AdGuard unreachable: '.($cerr ?: 'failed')];
        if ($code === 401 || $code === 403) return ['ok'=>false, 'code'=>$code, 'error'=>'Auth failed (HTTP '.$code.') — check username/password'];
        $j = json_decode($body, true);
        if ($code < 200 || $code >= 300) {
            $msg = is_string($j) ? $j : ((is_array($j) && isset($j['message'])) ? $j['message'] : (trim((string)$body) ?: ('HTTP '.$code)));
            return ['ok'=>false, 'code'=>$code, 'error'=>$msg];
        }
        return ['ok'=>true, 'data'=>$j];
    }

    // WRITE (POST/PUT/DELETE) with a JSON body.
    function nm_ag_write($conn, int $id, string $method, string $path, array $payload = []): array {
        $S = nm_ag_get_server($conn, $id);
        if (!$S) return ['ok'=>false, 'error'=>'No such AdGuard'];
        if (!$S['enabled']) return ['ok'=>false, 'error'=>'This AdGuard is disabled'];
        if ($S['url'] === '') return ['ok'=>false, 'error'=>'AdGuard URL not configured'];

        $ch = curl_init($S['url'] . '/control/' . ltrim($path, '/'));
        $opt = [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_HTTPHEADER => ['Accept: application/json', 'Content-Type: application/json'],
            CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
            CURLOPT_USERPWD => $S['username'] . ':' . $S['password'],
            CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_TIMEOUT => 20,
            CURLOPT_SSL_VERIFYPEER => $S['verify'], CURLOPT_SSL_VERIFYHOST => $S['verify'] ? 2 : 0,
        ];
        if ($payload || in_array(strtoupper($method), ['POST','PUT'], true)) $opt[CURLOPT_POSTFIELDS] = json_encode($payload);
        curl_setopt_array($ch, $opt);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $cerr = curl_error($ch);
        curl_close($ch);

        if ($body === false || $code === 0) return ['ok'=>false, 'error'=>'AdGuard unreachable: '.($cerr ?: 'failed')];
        if ($code === 401 || $code === 403) return ['ok'=>false, 'code'=>$code, 'error'=>'Auth failed (HTTP '.$code.') — check username/password'];
        $j = json_decode($body, true);
        if ($code < 200 || $code >= 300) {
            $msg = is_string($j) ? $j : ((is_array($j) && isset($j['message'])) ? $j['message'] : (trim((string)$body) ?: ('HTTP '.$code)));
            return ['ok'=>false, 'code'=>$code, 'error'=>$msg];
        }
        return ['ok'=>true, 'data'=>$j];
    }
}

// ── Block / unblock a domain via AdGuard user-rules (Collective Immunity) ─────
if (!function_exists('nm_ag_add_deny')) {
    // Build the AdGuard user-rule for a domain. 'exact' → ||domain^ (domain + subdomains).
    function nm_ag_rule_for(string $domain, string $kind = 'exact'): string {
        $domain = trim($domain);
        if ($kind === 'regex') return '/' . trim($domain, '/') . '/';
        $domain = preg_replace('#^https?://#i', '', $domain);   // tolerate a pasted URL
        $domain = ltrim($domain, '*.');
        $domain = preg_replace('#[/^].*$#', '', $domain);        // host only
        return '||' . $domain . '^';
    }
    // Read the current user_rules, append the block if missing, push the full set.
    // Idempotent: an already-present rule returns existed=true with no write.
    function nm_ag_add_deny($conn, int $id, string $domain, string $kind = 'exact', string $comment = 'NEURU collective-immunity'): array {
        $rule = nm_ag_rule_for($domain, $kind);
        $st = nm_ag_call($conn, $id, 'filtering/status');
        if (!$st['ok']) return $st;
        $rules = (isset($st['data']['user_rules']) && is_array($st['data']['user_rules'])) ? $st['data']['user_rules'] : [];
        if (in_array($rule, $rules, true)) return ['ok'=>true, 'existed'=>true];
        $rules[] = $rule;
        $r = nm_ag_write($conn, $id, 'POST', 'filtering/set_rules', ['rules'=>array_values($rules)]);
        return $r['ok'] ? ['ok'=>true, 'rule'=>$rule] : $r;
    }
    function nm_ag_remove_deny($conn, int $id, string $domain, string $kind = 'exact'): array {
        $rule = nm_ag_rule_for($domain, $kind);
        $st = nm_ag_call($conn, $id, 'filtering/status');
        if (!$st['ok']) return $st;
        $rules = (isset($st['data']['user_rules']) && is_array($st['data']['user_rules'])) ? $st['data']['user_rules'] : [];
        if (!in_array($rule, $rules, true)) return ['ok'=>true, 'absent'=>true];
        $rules = array_values(array_filter($rules, function($r) use ($rule){ return $r !== $rule; }));
        return nm_ag_write($conn, $id, 'POST', 'filtering/set_rules', ['rules'=>$rules]);
    }

    // Connectivity + auth probe. Returns version + protection state.
    function nm_ag_test($conn, int $id): array {
        $v = nm_ag_call($conn, $id, 'status');
        if (!$v['ok']) return $v;
        return ['ok'=>true, 'version'=>$v['data']['version'] ?? null, 'protection'=>$v['data']['protection_enabled'] ?? null];
    }
}
