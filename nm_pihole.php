<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Pi-hole v6 REST API client (server-side proxy), MULTI-INSTANCE.
//
//   Each Pi-hole is a row in nm_pihole_servers (name, url, encrypted password,
//   verify_tls, enabled, cached sid). Pi-hole v6 auth = POST /api/auth {password}
//   → session.sid, sent as the `sid:` header on every call; the sid is cached per
//   server (Pi-hole limits concurrent sessions). The browser never talks to
//   Pi-hole directly — pihole.php proxies through here so passwords stay
//   server-side and we sidestep CORS, the self-signed cert, and the portal CSP.
//
//   Legacy single-instance settings (pihole_url/pihole_password_enc/…) are
//   auto-migrated into a first row by nm_ph_ensure().
// ─────────────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/nm_secrets.php';

// ── Schema + one-time migration from the old single-instance settings ────────
if (!function_exists('nm_ph_ensure')) {
    function nm_ph_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        if (!($conn instanceof mysqli)) return;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_pihole_servers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(80) NOT NULL DEFAULT 'Pi-hole',
            url VARCHAR(255) NOT NULL,
            password_enc MEDIUMTEXT,
            verify_tls TINYINT(1) NOT NULL DEFAULT 0,
            enabled TINYINT(1) NOT NULL DEFAULT 1,
            sort_order INT NOT NULL DEFAULT 0,
            sid VARCHAR(80) DEFAULT NULL,
            sid_exp INT NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // migrate the legacy single instance, once, if the table is still empty
        $r = $conn->query("SELECT COUNT(*) c FROM nm_pihole_servers");
        if ($r && (int)$r->fetch_assoc()['c'] === 0) {
            $g = function($k,$d='') use ($conn){ $s=$conn->prepare("SELECT setting_val FROM nm_settings WHERE setting_key=? LIMIT 1");
                $s->bind_param('s',$k); $s->execute(); $x=$s->get_result()->fetch_row(); $s->close(); return $x?(string)$x[0]:$d; };
            $url = rtrim($g('pihole_url',''), '/');
            if ($url !== '') {
                $enc = $g('pihole_password_enc','');
                $ver = $g('pihole_verify_tls','0') === '1' ? 1 : 0;
                $en  = $g('pihole_enabled','0') === '1' ? 1 : 0;
                $name = 'Pi-hole 1';
                $st = $conn->prepare("INSERT INTO nm_pihole_servers (name,url,password_enc,verify_tls,enabled) VALUES (?,?,?,?,?)");
                $st->bind_param('sssii', $name, $url, $enc, $ver, $en); $st->execute(); $st->close();
            }
        }
    }
}

// ── Server CRUD ──────────────────────────────────────────────────────────────
if (!function_exists('nm_ph_servers')) {
    // List servers (no secrets) for the UI. has_pw = the stored password decrypts.
    function nm_ph_servers($conn, bool $onlyEnabled = false): array {
        nm_ph_ensure($conn);
        $out = [];
        $w = $onlyEnabled ? "WHERE enabled=1" : "";
        $r = $conn->query("SELECT id,name,url,verify_tls,enabled,password_enc FROM nm_pihole_servers $w ORDER BY sort_order, id");
        while ($r && $x = $r->fetch_assoc()) {
            $out[] = ['id'=>(int)$x['id'], 'name'=>$x['name'], 'url'=>$x['url'],
                'verify'=>(int)$x['verify_tls']===1, 'enabled'=>(int)$x['enabled']===1,
                'has_pw'=>trim((string)nm_secret_decrypt($x['password_enc'])) !== ''];
        }
        return $out;
    }
    // Full server row incl. decrypted password (internal use).
    function nm_ph_get_server($conn, int $id): ?array {
        nm_ph_ensure($conn);
        $st = $conn->prepare("SELECT * FROM nm_pihole_servers WHERE id=? LIMIT 1");
        $st->bind_param('i', $id); $st->execute();
        $x = $st->get_result()->fetch_assoc(); $st->close();
        if (!$x) return null;
        $x['password'] = nm_secret_decrypt($x['password_enc']);
        $x['url'] = rtrim($x['url'], '/');
        $x['verify'] = (int)$x['verify_tls'] === 1;
        return $x;
    }
    function nm_ph_default_id($conn): int {
        nm_ph_ensure($conn);
        $r = $conn->query("SELECT id FROM nm_pihole_servers WHERE enabled=1 ORDER BY sort_order, id LIMIT 1");
        return $r && ($x = $r->fetch_row()) ? (int)$x[0] : 0;
    }
    function nm_ph_enabled($conn): bool { return nm_ph_default_id($conn) > 0; }

    function nm_ph_server_save($conn, array $d): array {
        nm_ph_ensure($conn);
        $id   = (int)($d['id'] ?? 0);
        $name = trim($d['name'] ?? '') ?: 'Pi-hole';
        $url  = rtrim(trim($d['url'] ?? ''), '/');
        $ver  = !empty($d['verify']) ? 1 : 0;
        $en   = !empty($d['enabled']) ? 1 : 0;
        $pw   = (string)($d['password'] ?? '');
        if ($url === '') return ['ok'=>false, 'err'=>'URL is required'];
        if ($id) {
            if ($pw !== '') {
                $enc = nm_secret_encrypt($pw);
                $st = $conn->prepare("UPDATE nm_pihole_servers SET name=?,url=?,password_enc=?,verify_tls=?,enabled=?,sid=NULL,sid_exp=0 WHERE id=?");
                $st->bind_param('sssiii', $name, $url, $enc, $ver, $en, $id);
            } else {
                $st = $conn->prepare("UPDATE nm_pihole_servers SET name=?,url=?,verify_tls=?,enabled=?,sid=NULL,sid_exp=0 WHERE id=?");
                $st->bind_param('ssiii', $name, $url, $ver, $en, $id);
            }
            $st->execute(); $st->close();
        } else {
            $enc = $pw !== '' ? nm_secret_encrypt($pw) : '';
            $st = $conn->prepare("INSERT INTO nm_pihole_servers (name,url,password_enc,verify_tls,enabled) VALUES (?,?,?,?,?)");
            $st->bind_param('sssii', $name, $url, $enc, $ver, $en); $st->execute(); $id = $st->insert_id; $st->close();
        }
        return ['ok'=>true, 'id'=>$id];
    }
    function nm_ph_server_delete($conn, int $id): void {
        nm_ph_ensure($conn);
        $st = $conn->prepare("DELETE FROM nm_pihole_servers WHERE id=?");
        $st->bind_param('i', $id); $st->execute(); $st->close();
    }
}

// ── Authenticate (cached sid per server) ─────────────────────────────────────
if (!function_exists('nm_ph_auth')) {
    function nm_ph_auth($conn, int $id, bool $force = false): array {
        $S = nm_ph_get_server($conn, $id);
        if (!$S) return ['ok'=>false, 'error'=>'No such Pi-hole'];
        if ($S['url'] === '') return ['ok'=>false, 'error'=>'Pi-hole URL not configured'];

        if (!$force && $S['sid'] && (int)$S['sid_exp'] > time() + 5) {
            return ['ok'=>true, 'sid'=>$S['sid']];
        }
        $ch = curl_init($S['url'] . '/api/auth');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode(['password' => $S['password']]),
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json'],
            CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_TIMEOUT => 12,
            CURLOPT_SSL_VERIFYPEER => $S['verify'], CURLOPT_SSL_VERIFYHOST => $S['verify'] ? 2 : 0,
        ]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $cerr = curl_error($ch);
        curl_close($ch);

        if ($body === false || $code === 0) return ['ok'=>false, 'error'=>'Cannot reach Pi-hole: '.($cerr ?: 'connection failed')];
        $j = json_decode($body, true);
        $sess = $j['session'] ?? null;
        if (!is_array($sess) || empty($sess['valid']) || empty($sess['sid'])) {
            return ['ok'=>false, 'error'=>'Auth failed: '.($sess['message'] ?? ('HTTP '.$code))];
        }
        $sid = $sess['sid'];
        $exp = time() + max(60, (int)($sess['validity'] ?? 300) - 30);
        $st = $conn->prepare("UPDATE nm_pihole_servers SET sid=?, sid_exp=? WHERE id=?");
        $st->bind_param('sii', $sid, $exp, $id); $st->execute(); $st->close();
        return ['ok'=>true, 'sid'=>$sid];
    }
}

// ── Generic GET against a server's API (auto-auth + one 401 retry) ───────────
if (!function_exists('nm_ph_call')) {
    function nm_ph_call($conn, int $id, string $path, array $query = [], bool $retry = true): array {
        $S = nm_ph_get_server($conn, $id);
        if (!$S) return ['ok'=>false, 'error'=>'No such Pi-hole'];
        if (!$S['enabled']) return ['ok'=>false, 'error'=>'This Pi-hole is disabled'];
        if ($S['url'] === '') return ['ok'=>false, 'error'=>'Pi-hole URL not configured'];

        $auth = nm_ph_auth($conn, $id);
        if (!$auth['ok']) return $auth;
        $sid = $auth['sid'];

        $url = $S['url'] . '/api/' . ltrim($path, '/');
        if ($query) $url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($query);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Accept: application/json', 'sid: '.$sid, 'X-FTL-SID: '.$sid],
            CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_TIMEOUT => 20,
            CURLOPT_SSL_VERIFYPEER => $S['verify'], CURLOPT_SSL_VERIFYHOST => $S['verify'] ? 2 : 0,
        ]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $cerr = curl_error($ch);
        curl_close($ch);

        if ($body === false || $code === 0) return ['ok'=>false, 'error'=>'Pi-hole unreachable: '.($cerr ?: 'failed')];
        if ($code === 401 && $retry) { nm_ph_auth($conn, $id, true); return nm_ph_call($conn, $id, $path, $query, false); }
        $j = json_decode($body, true);
        if ($code < 200 || $code >= 300) {
            return ['ok'=>false, 'error'=>(is_array($j) && isset($j['error']['message'])) ? $j['error']['message'] : ('HTTP '.$code), 'code'=>$code];
        }
        return ['ok'=>true, 'data'=>$j];
    }

    // ── WRITE proxy (Pi-hole v6): POST/DELETE with the cached sid + JSON body ──
    function nm_ph_write($conn, int $id, string $method, string $path, array $payload = [], bool $retry = true): array {
        $S = nm_ph_get_server($conn, $id);
        if (!$S) return ['ok'=>false, 'error'=>'No such Pi-hole'];
        if (!$S['enabled']) return ['ok'=>false, 'error'=>'This Pi-hole is disabled'];
        if ($S['url'] === '') return ['ok'=>false, 'error'=>'Pi-hole URL not configured'];
        $auth = nm_ph_auth($conn, $id);
        if (!$auth['ok']) return $auth;
        $sid = $auth['sid'];

        $ch = curl_init($S['url'] . '/api/' . ltrim($path, '/'));
        $opt = [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_HTTPHEADER => ['Accept: application/json', 'Content-Type: application/json', 'sid: '.$sid, 'X-FTL-SID: '.$sid],
            CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_TIMEOUT => 20,
            CURLOPT_SSL_VERIFYPEER => $S['verify'], CURLOPT_SSL_VERIFYHOST => $S['verify'] ? 2 : 0,
        ];
        if ($payload || in_array(strtoupper($method), ['POST','PUT'], true)) $opt[CURLOPT_POSTFIELDS] = json_encode($payload);
        curl_setopt_array($ch, $opt);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $cerr = curl_error($ch);
        curl_close($ch);

        if ($body === false || $code === 0) return ['ok'=>false, 'error'=>'Pi-hole unreachable: '.($cerr ?: 'failed')];
        if ($code === 401 && $retry) { nm_ph_auth($conn, $id, true); return nm_ph_write($conn, $id, $method, $path, $payload, false); }
        $j = json_decode($body, true);
        if ($code < 200 || $code >= 300) {
            return ['ok'=>false, 'code'=>$code, 'error'=>(is_array($j) && isset($j['error']['message'])) ? $j['error']['message'] : ('HTTP '.$code)];
        }
        return ['ok'=>true, 'data'=>$j];
    }

    // Add a deny-list entry. $kind = 'exact' | 'regex'. Idempotent (already-exists = ok).
    // We CHECK FIRST and skip the POST when the entry already exists — otherwise Pi-hole
    // attempts a duplicate INSERT and logs a noisy "UNIQUE constraint failed: domainlist"
    // SQLite error every time (cosmetically alarming even though the block is fine).
    function nm_ph_add_deny($conn, int $id, string $domain, string $kind = 'exact', string $comment = 'NEURU collective-immunity'): array {
        $kind = $kind === 'regex' ? 'regex' : 'exact';
        // GET the specific entry (Pi-hole v6: 200 + {domains:[…]} if present, 404 if not).
        $chk = nm_ph_call($conn, $id, 'domains/deny/'.$kind.'/'.rawurlencode($domain));
        if (!empty($chk['ok']) && !empty($chk['data']['domains']) && is_array($chk['data']['domains']) && count($chk['data']['domains']) > 0) {
            return ['ok'=>true, 'existed'=>true];   // already blocked → no INSERT, no Pi-hole error
        }
        $r = nm_ph_write($conn, $id, 'POST', 'domains/deny/'.$kind, ['domain'=>$domain, 'comment'=>$comment, 'enabled'=>true]);
        // safety net for a race / API variance: treat duplicate as success
        if (!$r['ok'] && (($r['code'] ?? 0) === 409 || stripos($r['error'] ?? '', 'exist') !== false || stripos($r['error'] ?? '', 'duplicate') !== false || stripos($r['error'] ?? '', 'unique') !== false)) {
            return ['ok'=>true, 'existed'=>true];
        }
        return $r;
    }
    function nm_ph_remove_deny($conn, int $id, string $domain, string $kind = 'exact'): array {
        $kind = $kind === 'regex' ? 'regex' : 'exact';
        $r = nm_ph_write($conn, $id, 'DELETE', 'domains/deny/'.$kind.'/'.rawurlencode($domain));
        if (!$r['ok'] && (($r['code'] ?? 0) === 404)) return ['ok'=>true, 'absent'=>true];
        return $r;
    }

    function nm_ph_test($conn, int $id): array {
        $a = nm_ph_auth($conn, $id, true);
        if (!$a['ok']) return $a;
        $v = nm_ph_call($conn, $id, 'info/version');
        if (!$v['ok']) return $v;
        $ver = $v['data']['version']['core']['local']['version'] ?? ($v['data']['version'] ?? null);
        return ['ok'=>true, 'version'=>$ver];
    }
}
