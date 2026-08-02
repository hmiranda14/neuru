<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — minimal dependency-free SMTP client (any provider).
//
//   PHP's mail() needs a local MTA, which the container doesn't have. This speaks
//   SMTP directly over a socket: AUTH LOGIN + STARTTLS (587) or implicit SSL (465),
//   so it works with Gmail, Office365, SendGrid, Mailgun, your own server, etc.
//
//   Settings (nm_settings): smtp_enabled, smtp_host, smtp_port, smtp_secure
//   (tls|ssl|none), smtp_user, smtp_pass_enc (AES), smtp_from, smtp_from_name.
//   Gmail: host smtp.gmail.com, port 587, secure tls, user = your address,
//   pass = a Google **App Password** (not your login password).
// ─────────────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/nm_secrets.php';

if (!function_exists('nm_smtp_settings')) {
    function nm_smtp_settings($conn): array {
        $d = ['smtp_enabled'=>'0','smtp_host'=>'','smtp_port'=>'587','smtp_secure'=>'tls',
              'smtp_user'=>'','smtp_pass_enc'=>'','smtp_from'=>'','smtp_from_name'=>'NEURU'];
        $keys = "'" . implode("','", array_keys($d)) . "'";
        if ($r = $conn->query("SELECT setting_key,setting_val FROM nm_settings WHERE setting_key IN ($keys)"))
            while ($x = $r->fetch_assoc()) $d[$x['setting_key']] = $x['setting_val'];
        $secure = in_array($d['smtp_secure'], ['tls','ssl','none'], true) ? $d['smtp_secure'] : 'tls';
        return [
            'enabled' => $d['smtp_enabled'] === '1',
            'host'    => trim($d['smtp_host']),
            'port'    => (int)$d['smtp_port'] ?: 587,
            'secure'  => $secure,
            'user'    => trim($d['smtp_user']),
            'pass'    => nm_secret_decrypt($d['smtp_pass_enc']),
            'has_pass'=> trim($d['smtp_pass_enc']) !== '',
            'from'    => trim($d['smtp_from']) ?: trim($d['smtp_user']),
            'from_name' => trim($d['smtp_from_name']) ?: 'NEURU',
        ];
    }

    // Read one SMTP reply (handles multi-line) and check the code.
    function _smtp_read($fp): array {
        $resp = '';
        while (($line = fgets($fp, 600)) !== false) {
            $resp .= $line;
            // last line of a reply has a space at position 3 ("250 ok"), continuations use "-"
            if (strlen($line) >= 4 && $line[3] === ' ') break;
        }
        return [(int)substr($resp, 0, 3), trim($resp)];
    }
    function _smtp_cmd($fp, ?string $cmd, $expect, ?string &$err): bool {
        if ($cmd !== null) fwrite($fp, $cmd . "\r\n");
        [$code, $resp] = _smtp_read($fp);
        $ok = in_array($code, (array)$expect, true);
        if (!$ok) { $err = 'SMTP error: ' . $resp; }
        return $ok;
    }

    // Send one plain-text email. Returns true on success; $err carries the reason.
    function nm_smtp_send($conn, string $to, string $subject, string $body, ?string &$err = null, ?array $override = null, ?string $contentType = null): bool {
        $s = $override ?? nm_smtp_settings($conn);
        if ($s['host'] === '') { $err = 'SMTP host not configured'; return false; }
        $host = $s['host']; $port = (int)$s['port']; $secure = $s['secure'];
        $ctx = stream_context_create(['ssl' => ['verify_peer'=>false, 'verify_peer_name'=>false, 'allow_self_signed'=>true]]);
        $remote = ($secure === 'ssl' ? 'ssl://' : 'tcp://') . $host . ':' . $port;
        $fp = @stream_socket_client($remote, $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $ctx);
        if (!$fp) { $err = "Cannot connect to {$host}:{$port} — {$errstr}"; return false; }
        stream_set_timeout($fp, 15);

        $ehlo = 'EHLO ' . (gethostname() ?: 'neuru');
        try {
            if (!_smtp_cmd($fp, null, [220], $err)) { fclose($fp); return false; }              // greeting
            if (!_smtp_cmd($fp, $ehlo, [250], $err)) { fclose($fp); return false; }

            if ($secure === 'tls') {
                if (!_smtp_cmd($fp, 'STARTTLS', [220], $err)) { fclose($fp); return false; }
                $crypto = STREAM_CRYPTO_METHOD_TLS_CLIENT;
                if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT')) $crypto |= STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT;
                if (!@stream_socket_enable_crypto($fp, true, $crypto)) { $err = 'STARTTLS negotiation failed'; fclose($fp); return false; }
                if (!_smtp_cmd($fp, $ehlo, [250], $err)) { fclose($fp); return false; }          // re-EHLO after TLS
            }

            if ($s['user'] !== '') {
                if (!_smtp_cmd($fp, 'AUTH LOGIN', [334], $err)) { fclose($fp); return false; }
                if (!_smtp_cmd($fp, base64_encode($s['user']), [334], $err)) { fclose($fp); return false; }
                if (!_smtp_cmd($fp, base64_encode($s['pass']), [235], $err)) { fclose($fp); return false; }  // 235 = auth ok
            }

            $from = $s['from'];
            if (!_smtp_cmd($fp, 'MAIL FROM:<' . $from . '>', [250], $err)) { fclose($fp); return false; }
            if (!_smtp_cmd($fp, 'RCPT TO:<' . $to . '>', [250, 251], $err)) { fclose($fp); return false; }
            if (!_smtp_cmd($fp, 'DATA', [354], $err)) { fclose($fp); return false; }

            $subjEnc = preg_match('/[^\x20-\x7E]/', $subject) ? '=?UTF-8?B?' . base64_encode($subject) . '?=' : $subject;
            $fromHdr = ($s['from_name'] !== '' ? '=?UTF-8?B?' . base64_encode($s['from_name']) . '?= ' : '') . '<' . $from . '>';
            $ct = $contentType ?: 'text/plain; charset=UTF-8';
            $isMultipart = stripos($ct, 'multipart/') === 0;
            $headers = [
                'Date: ' . date('r'),
                'From: ' . $fromHdr,
                'To: <' . $to . '>',
                'Subject: ' . $subjEnc,
                'MIME-Version: 1.0',
                'Content-Type: ' . $ct,
            ];
            if (!$isMultipart) $headers[] = 'Content-Transfer-Encoding: 8bit';
            $headers[] = 'X-Mailer: NEURU';
            // dot-stuffing for lines beginning with "."
            $bodyOut = preg_replace('/^\./m', '..', str_replace(["\r\n", "\r", "\n"], "\r\n", $body));
            fwrite($fp, implode("\r\n", $headers) . "\r\n\r\n" . $bodyOut . "\r\n.\r\n");
            if (!_smtp_cmd($fp, null, [250], $err)) { fclose($fp); return false; }                 // accept

            _smtp_cmd($fp, 'QUIT', [221], $err);
            fclose($fp);
            $err = null;
            return true;
        } catch (\Throwable $e) {
            $err = $e->getMessage();
            if (is_resource($fp)) fclose($fp);
            return false;
        }
    }
}
