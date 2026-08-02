<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — user profile engine (self-service account page + header avatar).
//  · nm_user_meta_ensure() adds avatar_path / phone to `users` (guarded, flag-gated).
//  · nm_user_get() / nm_user_avatar_url() feed both user_profile.php and the header.
// The users table uses UPPERCASE keys (UID, USERNAME, PASSWORD); the canonical
// session uid is $_SESSION['UID']. Reuses nm_media.php for the avatar upload.
// ─────────────────────────────────────────────────────────────────────────────

if (!function_exists('nm_user_meta_ensure')) {

    function nm_user_meta_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        try {
            $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='nm_usermeta_schema' LIMIT 1");
            if ($r && $r->num_rows) return;
        } catch (\Throwable $e) { /* fall through */ }
        try {
            $have = [];
            $c = $conn->query("SELECT COLUMN_NAME FROM information_schema.COLUMNS
                               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users'");
            while ($c && $x = $c->fetch_assoc()) $have[strtolower($x['COLUMN_NAME'])] = true;
            $cols = ['avatar_path' => "VARCHAR(255) NULL", 'phone' => "VARCHAR(40) NULL", 'title' => "VARCHAR(120) NULL"];
            foreach ($cols as $col => $ddl) {
                if (!isset($have[strtolower($col)])) {
                    try { $conn->query("ALTER TABLE users ADD COLUMN `$col` $ddl"); } catch (\Throwable $e) {}
                }
            }
            try { $conn->query("INSERT INTO nm_settings(setting_key,setting_val) VALUES('nm_usermeta_schema','1')
                                ON DUPLICATE KEY UPDATE setting_val='1'"); } catch (\Throwable $e) {}
        } catch (\Throwable $e) {}
    }

    function nm_user_get($conn, int $uid): ?array {
        if (!($conn instanceof mysqli) || !$uid) return null;
        nm_user_meta_ensure($conn);
        try {
            $st = $conn->prepare("SELECT * FROM users WHERE UID=? LIMIT 1");
            $st->bind_param('i', $uid); $st->execute();
            $r = $st->get_result()->fetch_assoc();
            return $r ?: null;
        } catch (\Throwable $e) { return null; }
    }

    // Web path for a user's avatar, or null. Accepts a users row.
    function nm_user_avatar_url(?array $row): ?string {
        if (!$row) return null;
        $p = trim((string)($row['avatar_path'] ?? ''));
        if ($p === '') return null;
        $abs = __DIR__ . '/' . ltrim($p, '/');
        return is_file($abs) ? $p : null;
    }

    // Lightweight avatar lookup for the header (avoids SELECT * every page).
    function nm_user_avatar_for($conn, int $uid): ?string {
        if (!($conn instanceof mysqli) || !$uid) return null;
        nm_user_meta_ensure($conn);
        try {
            $st = $conn->prepare("SELECT avatar_path FROM users WHERE UID=? LIMIT 1");
            $st->bind_param('i', $uid); $st->execute();
            $row = $st->get_result()->fetch_assoc();
            return nm_user_avatar_url($row);
        } catch (\Throwable $e) { return null; }
    }
}
