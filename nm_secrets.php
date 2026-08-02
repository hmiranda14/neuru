<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — secret encryption at rest (AES-256-GCM). Used for SSH credentials the
// portal stores for self-heal remediation. The key lives in a dotfile that the
// .htaccess denies over HTTP (`^\.` rule) and is NOT in the DB, so a DB dump alone
// can't decrypt the secrets. (For even stronger separation, move the key into
// nm_config.php which is www-data-only — the user's call.)
//
//   nm_secret_encrypt($plain) → "enc:v1:<base64(iv|tag|cipher)>"
//   nm_secret_decrypt($blob)  → plaintext (or '' on failure / empty)
// ─────────────────────────────────────────────────────────────────────────────

if (!function_exists('nm_secret_encrypt')) {

    function _nm_secret_key(): string {
        static $key = null;
        if ($key !== null) return $key;
        $path = __DIR__ . '/.nm_secret.key';
        if (is_file($path)) {
            $raw = trim((string)@file_get_contents($path));
            $key = $raw !== '' ? base64_decode($raw) : '';
        }
        if (empty($key) || strlen($key) !== 32) {
            // Generate once. Best-effort write (web root may be read-only for www-data);
            // if it can't persist, fall back to a deterministic-but-warned key so the
            // app still runs (admin should create the file manually then).
            $new = random_bytes(32);
            if (@file_put_contents($path, base64_encode($new)) !== false) { @chmod($path, 0644); $key = $new; }
            else { $key = $key ?: ''; }   // leave empty → callers treat as "no crypto configured"
            if (empty($key)) $key = $new;  // in-memory only this request
        }
        return $key;
    }

    function nm_secret_encrypt(string $plain): string {
        if ($plain === '') return '';
        $key = _nm_secret_key();
        $iv  = random_bytes(12);
        $tag = '';
        $ct  = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($ct === false) return '';
        return 'enc:v1:' . base64_encode($iv . $tag . $ct);
    }

    function nm_secret_decrypt(?string $blob): string {
        $blob = (string)$blob;
        if ($blob === '') return '';
        if (strpos($blob, 'enc:v1:') !== 0) return $blob;   // legacy/plaintext passthrough
        $raw = base64_decode(substr($blob, 7), true);
        if ($raw === false || strlen($raw) < 29) return '';
        $iv  = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $ct  = substr($raw, 28);
        $pt  = openssl_decrypt($ct, 'aes-256-gcm', _nm_secret_key(), OPENSSL_RAW_DATA, $iv, $tag);
        return $pt === false ? '' : $pt;
    }

    // Resolve the SSH credential for a node: its own ssh_cred_id, else the default
    // credential. Returns a ready-to-use array for the n8n SSH node, or null.
    //   { host, port, username, auth_type, password|private_key, cred_name }
    function nm_ssh_resolve($conn, int $node_id): ?array {
        if (!($conn instanceof mysqli) || !$node_id) return null;
        $nr = $conn->query("SELECT ip_address, ssh_cred_id FROM nm_nodes WHERE id={$node_id} LIMIT 1");
        $node = $nr ? $nr->fetch_assoc() : null;
        if (!$node) return null;
        $cid = (int)($node['ssh_cred_id'] ?? 0);
        if ($cid) $cr = $conn->query("SELECT * FROM nm_ssh_credentials WHERE id={$cid} LIMIT 1");
        else      $cr = $conn->query("SELECT * FROM nm_ssh_credentials WHERE is_default=1 ORDER BY id LIMIT 1");
        $cred = $cr ? $cr->fetch_assoc() : null;
        if (!$cred) return null;
        $secret = nm_secret_decrypt($cred['secret_enc']);
        $out = [
            'host'      => $node['ip_address'],
            'port'      => (int)($cred['port'] ?: 22),
            'username'  => $cred['username'],
            'auth_type' => $cred['auth_type'],
            'cred_name' => $cred['name'],
        ];
        if ($cred['auth_type'] === 'key') $out['private_key'] = $secret;
        else                              $out['password']    = $secret;
        return $out;
    }

    // Resolve the SSH credential for a Docker host IP (Containers self-heal): the
    // host's own assignment (nm_ssh_host_creds) → else the default credential.
    //   { host, port, username, auth_type, password|private_key, cred_name }
    function nm_ssh_resolve_host($conn, string $hostIp): ?array {
        if (!($conn instanceof mysqli)) return null;
        $cid = 0;
        if ($hostIp !== '' && $conn->query("SHOW TABLES LIKE 'nm_ssh_host_creds'")->num_rows > 0) {
            $st = $conn->prepare("SELECT cred_id FROM nm_ssh_host_creds WHERE host=? LIMIT 1");
            $st->bind_param('s', $hostIp); $st->execute();
            if ($r = $st->get_result()->fetch_assoc()) $cid = (int)$r['cred_id'];
        }
        if ($cid) $cr = $conn->query("SELECT * FROM nm_ssh_credentials WHERE id={$cid} LIMIT 1");
        else      $cr = $conn->query("SELECT * FROM nm_ssh_credentials WHERE is_default=1 ORDER BY id LIMIT 1");
        $cred = $cr ? $cr->fetch_assoc() : null;
        if (!$cred) return null;
        $secret = nm_secret_decrypt($cred['secret_enc']);
        $out = ['host'=>$hostIp, 'port'=>(int)($cred['port'] ?: 22), 'username'=>$cred['username'],
                'auth_type'=>$cred['auth_type'], 'cred_name'=>$cred['name']];
        if ($cred['auth_type'] === 'key') $out['private_key'] = $secret; else $out['password'] = $secret;
        return $out;
    }

    // The default SSH credential (decrypted), with a caller-supplied host. Used by
    // the Containers self-heal where the SSH target is a Docker host, not an nm_node.
    //   { host, port, username, auth_type, password|private_key, cred_name }
    function nm_ssh_default($conn, string $host = ''): ?array {
        if (!($conn instanceof mysqli)) return null;
        if ($conn->query("SHOW TABLES LIKE 'nm_ssh_credentials'")->num_rows === 0) return null;
        $cr = $conn->query("SELECT * FROM nm_ssh_credentials WHERE is_default=1 ORDER BY id LIMIT 1");
        $cred = $cr ? $cr->fetch_assoc() : null;
        if (!$cred) return null;
        $secret = nm_secret_decrypt($cred['secret_enc']);
        $out = ['host'=>$host, 'port'=>(int)($cred['port'] ?: 22), 'username'=>$cred['username'],
                'auth_type'=>$cred['auth_type'], 'cred_name'=>$cred['name']];
        if ($cred['auth_type'] === 'key') $out['private_key'] = $secret; else $out['password'] = $secret;
        return $out;
    }
}
