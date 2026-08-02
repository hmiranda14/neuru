<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — resolve (and auto-seed) the n8n inbound token. Prints the token to stdout.
// Used by scripts/nm_cron.sh so scheduled jobs ALWAYS authenticate to localhost —
// no <YOUR_CRON_TOKEN> placeholder to fill, and a fresh install just works. If no
// token exists yet, it generates + stores one (plaintext in nm_settings; that's how
// nm_n8n_get reads it, so it round-trips with what the cron endpoints compare).
// ─────────────────────────────────────────────────────────────────────────────
if (PHP_SAPI !== 'cli') { http_response_code(403); exit; }   // never serve this over HTTP
chdir(__DIR__ . '/..');
require __DIR__ . '/../connection.php';
require __DIR__ . '/../nm_n8n.php';
try {
    $tok = (string)(nm_n8n_get($conn)['inbound_token'] ?? '');
    if ($tok === '') {
        $tok = 'nmn8n_' . bin2hex(random_bytes(24));
        nm_n8n_set($conn, 'n8n_inbound_token', $tok);
    }
    echo $tok;
} catch (\Throwable $e) { /* print nothing → the wrapper skips this tick harmlessly */ }
