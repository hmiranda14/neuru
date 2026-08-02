<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Two-Factor Authentication (TOTP, RFC 6238). OPTIONAL, per-user, opt-in
// from the user profile. Standard TOTP (SHA-1, 6 digits, 30s) → works with ANY
// authenticator app: Google Authenticator, Microsoft Authenticator, Authy, 1Password,
// Bitwarden, FreeOTP, Aegis, etc. The shared secret is stored ENCRYPTED (per-install
// key via nm_secret_encrypt) on the `users` row; recovery via one-time backup codes
// (stored hashed). Nothing here runs unless a user turns it on.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_secrets.php';

if (!function_exists('nm_2fa_ensure')) {

    define('NM_2FA_ISSUER', 'NEURU');
    define('NM_2FA_PERIOD', 30);
    define('NM_2FA_DIGITS', 6);

    // Guarded schema: 2FA columns on the users table (mysqli is in EXCEPTION mode → check first).
    function nm_2fa_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        try {
            $cols = [];
            $r = $conn->query("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users'");
            while ($r && $x = $r->fetch_assoc()) $cols[strtolower($x['COLUMN_NAME'])] = 1;
            if (!isset($cols['totp_secret']))  $conn->query("ALTER TABLE users ADD COLUMN totp_secret TEXT NULL");
            if (!isset($cols['totp_enabled'])) $conn->query("ALTER TABLE users ADD COLUMN totp_enabled TINYINT NOT NULL DEFAULT 0");
            if (!isset($cols['totp_backup']))  $conn->query("ALTER TABLE users ADD COLUMN totp_backup TEXT NULL");
        } catch (\Throwable $e) { /* best-effort */ }
    }

    // ── base32 (RFC 4648, no padding) ───────────────────────────────────────────
    function nm_2fa_b32_encode(string $bin): string {
        $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $out = ''; $bits = 0; $val = 0;
        for ($i = 0, $n = strlen($bin); $i < $n; $i++) {
            $val = ($val << 8) | ord($bin[$i]); $bits += 8;
            while ($bits >= 5) { $bits -= 5; $out .= $alpha[($val >> $bits) & 31]; }
        }
        if ($bits > 0) $out .= $alpha[($val << (5 - $bits)) & 31];
        return $out;
    }
    function nm_2fa_b32_decode(string $b32): string {
        $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $b32 = strtoupper(preg_replace('/[^A-Z2-7]/', '', $b32));
        $bits = 0; $val = 0; $out = '';
        for ($i = 0, $n = strlen($b32); $i < $n; $i++) {
            $val = ($val << 5) | strpos($alpha, $b32[$i]); $bits += 5;
            if ($bits >= 8) { $bits -= 8; $out .= chr(($val >> $bits) & 0xFF); }
        }
        return $out;
    }

    // A fresh random secret (base32, 160-bit) for a new enrollment.
    function nm_2fa_gen_secret(): string { return nm_2fa_b32_encode(random_bytes(20)); }

    // otpauth:// URI the authenticator app imports (label = issuer:account).
    function nm_2fa_uri(string $secret, string $account): string {
        $label = rawurlencode(NM_2FA_ISSUER . ':' . $account);
        $q = http_build_query([
            'secret'    => $secret,
            'issuer'    => NM_2FA_ISSUER,
            'algorithm' => 'SHA1',
            'digits'    => NM_2FA_DIGITS,
            'period'    => NM_2FA_PERIOD,
        ]);
        return "otpauth://totp/$label?$q";
    }

    // The 6-digit code for a given secret + time slice (RFC 6238 / HOTP dynamic truncation).
    function nm_2fa_code(string $secret, int $slice): string {
        $key = nm_2fa_b32_decode($secret);
        $bin = pack('N*', 0) . pack('N*', $slice);            // 8-byte big-endian counter
        $h   = hash_hmac('sha1', $bin, $key, true);
        $off = ord($h[strlen($h) - 1]) & 0x0F;
        $num = ((ord($h[$off]) & 0x7F) << 24) | ((ord($h[$off + 1]) & 0xFF) << 16)
             | ((ord($h[$off + 2]) & 0xFF) << 8) | (ord($h[$off + 3]) & 0xFF);
        return str_pad((string)($num % (10 ** NM_2FA_DIGITS)), NM_2FA_DIGITS, '0', STR_PAD_LEFT);
    }
    // Verify a code within ±$window periods (clock drift tolerance). Constant-time compare.
    function nm_2fa_verify(string $secret, string $code, int $window = 1): bool {
        $code = preg_replace('/\D/', '', $code);
        if (strlen($code) !== NM_2FA_DIGITS) return false;
        $slice = (int) floor(time() / NM_2FA_PERIOD);
        for ($i = -$window; $i <= $window; $i++) {
            if (hash_equals(nm_2fa_code($secret, $slice + $i), $code)) return true;
        }
        return false;
    }

    // ── per-user state ──────────────────────────────────────────────────────────
    function nm_2fa_status($conn, int $uid): array {
        nm_2fa_ensure($conn);
        try {
            $st = $conn->prepare("SELECT totp_enabled, totp_secret FROM users WHERE UID=? LIMIT 1");
            $st->bind_param('i', $uid); $st->execute();
            $row = $st->get_result()->fetch_assoc(); $st->close();
            return ['enabled' => (int)($row['totp_enabled'] ?? 0) === 1, 'has_secret' => !empty($row['totp_secret'])];
        } catch (\Throwable $e) { return ['enabled' => false, 'has_secret' => false]; }
    }
    function nm_2fa_secret($conn, int $uid): string {
        nm_2fa_ensure($conn);
        try {
            $st = $conn->prepare("SELECT totp_secret FROM users WHERE UID=? LIMIT 1");
            $st->bind_param('i', $uid); $st->execute();
            $row = $st->get_result()->fetch_assoc(); $st->close();
            $enc = (string)($row['totp_secret'] ?? '');
            return $enc === '' ? '' : nm_secret_decrypt($enc);
        } catch (\Throwable $e) { return ''; }
    }

    // Start enrollment: store a fresh (encrypted) secret with enabled=0, return secret+uri for the QR.
    function nm_2fa_begin($conn, int $uid, string $account): array {
        nm_2fa_ensure($conn);
        $secret = nm_2fa_gen_secret();
        $enc = nm_secret_encrypt($secret);
        $st = $conn->prepare("UPDATE users SET totp_secret=?, totp_enabled=0 WHERE UID=?");
        $st->bind_param('si', $enc, $uid); $st->execute(); $st->close();
        return ['secret' => $secret, 'uri' => nm_2fa_uri($secret, $account)];
    }
    // Confirm enrollment: the code must match the pending secret → enable + issue backup codes.
    function nm_2fa_confirm($conn, int $uid, string $code): array {
        $secret = nm_2fa_secret($conn, $uid);
        if ($secret === '') return ['ok' => false, 'error' => 'No enrollment in progress — start again.'];
        if (!nm_2fa_verify($secret, $code)) return ['ok' => false, 'error' => 'That code is wrong or expired. Check your app clock and try again.'];
        [$plain, $stored] = nm_2fa_backup_gen();
        $st = $conn->prepare("UPDATE users SET totp_enabled=1, totp_backup=? WHERE UID=?");
        $st->bind_param('si', $stored, $uid); $st->execute(); $st->close();
        if (function_exists('nm_audit')) { try { nm_audit($conn, 'auth.2fa.enable', ['target_type'=>'user','target_id'=>$uid]); } catch (\Throwable $e) {} }
        return ['ok' => true, 'backup_codes' => $plain];
    }
    // Disable: require a valid current code (TOTP or a backup code) — never let a hijacked session
    // silently turn off 2FA. Clears the secret + backup codes.
    function nm_2fa_disable($conn, int $uid, string $code): array {
        if (!nm_2fa_login_verify($conn, $uid, $code)) return ['ok' => false, 'error' => 'Enter a valid code to turn 2FA off.'];
        $conn->query("UPDATE users SET totp_enabled=0, totp_secret=NULL, totp_backup=NULL WHERE UID=" . (int)$uid);
        if (function_exists('nm_audit')) { try { nm_audit($conn, 'auth.2fa.disable', ['target_type'=>'user','target_id'=>$uid]); } catch (\Throwable $e) {} }
        return ['ok' => true];
    }
    // Regenerate backup codes (invalidates the old ones). Requires a valid code.
    function nm_2fa_regen_backup($conn, int $uid, string $code): array {
        if (!nm_2fa_login_verify($conn, $uid, $code)) return ['ok' => false, 'error' => 'Enter a valid code first.'];
        [$plain, $stored] = nm_2fa_backup_gen();
        $st = $conn->prepare("UPDATE users SET totp_backup=? WHERE UID=?");
        $st->bind_param('si', $stored, $uid); $st->execute(); $st->close();
        return ['ok' => true, 'backup_codes' => $plain];
    }

    // ── backup (recovery) codes — 10 × "XXXX-XXXX", stored hashed, one-time use ──
    function nm_2fa_backup_gen(int $n = 10): array {
        $alpha = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';   // no ambiguous 0/O/1/I
        $plain = []; $hashes = [];
        for ($i = 0; $i < $n; $i++) {
            $c = '';
            for ($j = 0; $j < 8; $j++) { if ($j === 4) $c .= '-'; $c .= $alpha[random_int(0, strlen($alpha) - 1)]; }
            $plain[] = $c;
            $hashes[] = password_hash($c, PASSWORD_DEFAULT);
        }
        return [$plain, json_encode($hashes)];
    }
    // Consume a backup code (one-time). Returns true + removes it from the stored set.
    function nm_2fa_backup_consume($conn, int $uid, string $code): bool {
        $code = strtoupper(trim($code));
        try {
            $st = $conn->prepare("SELECT totp_backup FROM users WHERE UID=? LIMIT 1");
            $st->bind_param('i', $uid); $st->execute();
            $row = $st->get_result()->fetch_assoc(); $st->close();
            $hashes = json_decode((string)($row['totp_backup'] ?? '[]'), true);
            if (!is_array($hashes)) return false;
            foreach ($hashes as $k => $h) {
                if (is_string($h) && password_verify($code, $h)) {
                    unset($hashes[$k]);
                    $left = json_encode(array_values($hashes));
                    $u = $conn->prepare("UPDATE users SET totp_backup=? WHERE UID=?");
                    $u->bind_param('si', $left, $uid); $u->execute(); $u->close();
                    return true;
                }
            }
        } catch (\Throwable $e) {}
        return false;
    }

    // The one call the LOGIN uses: accept a TOTP code OR a backup code for this user.
    function nm_2fa_login_verify($conn, int $uid, string $code): bool {
        $code = trim($code);
        // backup codes contain a dash / letters; TOTP is 6 digits
        if (preg_match('/^\d{6}$/', preg_replace('/\s/', '', $code))) {
            $secret = nm_2fa_secret($conn, $uid);
            if ($secret !== '' && nm_2fa_verify($secret, $code)) return true;
        }
        return nm_2fa_backup_consume($conn, $uid, $code);
    }

    function nm_2fa_backup_count($conn, int $uid): int {
        try {
            $st = $conn->prepare("SELECT totp_backup FROM users WHERE UID=? LIMIT 1");
            $st->bind_param('i', $uid); $st->execute();
            $row = $st->get_result()->fetch_assoc(); $st->close();
            $h = json_decode((string)($row['totp_backup'] ?? '[]'), true);
            return is_array($h) ? count($h) : 0;
        } catch (\Throwable $e) { return 0; }
    }
}
