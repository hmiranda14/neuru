<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU Backup Vault — take / schedule / download / restore database backups.
// Three kinds:
//   • config  — instant, pure-PHP, reuses config.neuru (nm_config_io.php). Tiny/portable.
//   • data    — selected categories' telemetry tables (mysqldump of those tables).
//   • full    — the whole database (mysqldump).
// data/full run via `mysqldump` (shipped in the image) streamed to gzip; because a full
// dump can take minutes, they are QUEUED and executed by a DETACHED runner (or the cron),
// so the web request never blocks/times out. Targets are pluggable: local (download),
// Portal (/v1/backup), S3, WebDAV. Companion engine to nm_vault.php. RBAC perm 'vault'.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_config_io.php';

if (!function_exists('nm_vault_backup_ensure')) {
    function nm_vault_backup_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        try {
            $conn->query("CREATE TABLE IF NOT EXISTS nm_vault_backups (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                kind VARCHAR(12) NOT NULL DEFAULT 'full',        /* config|data|full */
                scope_json TEXT NULL,                            /* categories, options */
                filename VARCHAR(255) NULL,
                path VARCHAR(512) NULL,
                size_bytes BIGINT NOT NULL DEFAULT 0,
                sha256 CHAR(64) NULL,
                encrypted TINYINT(1) NOT NULL DEFAULT 0,
                target VARCHAR(16) NOT NULL DEFAULT 'local',     /* local|portal|s3|webdav */
                remote_ref VARCHAR(512) NULL,
                status VARCHAR(12) NOT NULL DEFAULT 'queued',    /* queued|running|done|failed */
                auto TINYINT(1) NOT NULL DEFAULT 0,
                note VARCHAR(255) NULL,
                error VARCHAR(512) NULL,
                created_by VARCHAR(64) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                finished_at DATETIME NULL,
                KEY (status), KEY (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        } catch (\Throwable $e) {}
    }
}

// backups live in the app bind-mount (persists) — deny-all .htaccess (they hold DB data).
if (!function_exists('nm_vault_backup_dir')) {
    function nm_vault_backup_dir(): string {
        $d = __DIR__ . '/backups';
        if (!is_dir($d)) { @mkdir($d, 0775, true); }
        $h = $d . '/.htaccess';
        if (!is_file($h)) @file_put_contents($h, "Require all denied\n<IfModule !mod_authz_core.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n");
        return $d;
    }
    function nm_vault_db_creds(): array {
        global $host, $username, $password, $dbname;
        return ['host' => $host ?? 'db', 'user' => $username ?? 'sisuser',
                'pass' => $password ?? 'sispass', 'db' => $dbname ?? 'netmon'];
    }
}

// list / get / delete
if (!function_exists('nm_vault_backup_list')) {
    function nm_vault_backup_list($conn, int $limit = 50): array {
        nm_vault_backup_ensure($conn); $out = [];
        try { $r = $conn->query("SELECT * FROM nm_vault_backups ORDER BY id DESC LIMIT " . (int)$limit);
            while ($r && $x = $r->fetch_assoc()) $out[] = $x; } catch (\Throwable $e) {}
        return $out;
    }
    function nm_vault_backup_get($conn, int $id): ?array {
        try { $r = $conn->query("SELECT * FROM nm_vault_backups WHERE id=" . (int)$id);
            return $r ? ($r->fetch_assoc() ?: null) : null; } catch (\Throwable $e) { return null; }
    }
    function nm_vault_backup_delete($conn, int $id): bool {
        $b = nm_vault_backup_get($conn, $id); if (!$b) return false;
        if (!empty($b['path']) && is_file($b['path'])) @unlink($b['path']);
        try { $conn->query("DELETE FROM nm_vault_backups WHERE id=" . (int)$id); return true; } catch (\Throwable $e) { return false; }
    }
}

// ── create a backup (config = inline/instant; data/full = queued + detached runner) ─
if (!function_exists('nm_vault_backup_create')) {
    function nm_vault_backup_create($conn, string $kind, array $opts = []): array {
        nm_vault_backup_ensure($conn);
        $kind = in_array($kind, ['config', 'data', 'full'], true) ? $kind : 'full';
        $target = (string)($opts['target'] ?? 'local');
        if (!in_array($target, ['local','portal','s3','webdav'], true)) $target = 'local';
        $scope = json_encode(['categories' => $opts['categories'] ?? [], 'target' => $target,
                              'encrypt' => !empty($opts['passphrase'])]);
        $by = $opts['by'] ?? (function_exists('nm_current_user') ? (nm_current_user()['username'] ?? 'system') : 'system');
        $auto = !empty($opts['auto']) ? 1 : 0;
        $note = substr((string)($opts['note'] ?? ''), 0, 240);
        try {
            $st = $conn->prepare("INSERT INTO nm_vault_backups (kind,scope_json,target,status,auto,note,created_by) VALUES (?,?,?,?,?,?,?)");
            $status = 'queued'; $st->bind_param('ssssiss', $kind, $scope, $target, $status, $auto, $note, $by);
            $st->execute(); $id = $st->insert_id; $st->close();
        } catch (\Throwable $e) { return ['ok' => false, 'error' => $e->getMessage()]; }

        if ($kind === 'config') {   // instant, pure PHP
            $r = nm_vault_backup_run($conn, (int)$id, $opts['passphrase'] ?? '');
            return ['ok' => !empty($r['ok']), 'id' => (int)$id, 'inline' => true] + $r;
        }
        // data/full → run detached so the web request returns immediately
        $pass = (string)($opts['passphrase'] ?? '');
        $runner = __DIR__ . '/nm_vault_runjob.php';
        if (is_file($runner) && function_exists('exec')) {
            $penv = $pass !== '' ? 'NMV_PASS=' . escapeshellarg($pass) . ' ' : '';
            @exec($penv . 'nohup php ' . escapeshellarg($runner) . ' ' . (int)$id . ' >/dev/null 2>&1 &');
        }
        return ['ok' => true, 'id' => (int)$id, 'queued' => true];
    }
}

// ── run one backup job (called inline for config, detached/cron for data/full) ─
if (!function_exists('nm_vault_backup_run')) {
    function nm_vault_backup_run($conn, int $id, string $passphrase = ''): array {
        nm_vault_backup_ensure($conn);
        $b = nm_vault_backup_get($conn, $id); if (!$b) return ['ok' => false, 'error' => 'no such job'];
        // atomic claim — only ONE worker (detached runner OR cron) may transition queued→running,
        // so the two can't both mysqldump the same job.
        try {
            $conn->query("UPDATE nm_vault_backups SET status='running' WHERE id=" . (int)$id . " AND status='queued'");
            if ($conn->affected_rows === 0) {
                $b2 = nm_vault_backup_get($conn, $id);
                if ($b2 && in_array($b2['status'], ['running', 'done'], true)) return ['ok' => false, 'error' => 'already claimed'];
                $conn->query("UPDATE nm_vault_backups SET status='running' WHERE id=" . (int)$id);  // retry a failed job
            }
        } catch (\Throwable $e) {}
        $dir = nm_vault_backup_dir();
        $ts = gmdate('Ymd-His'); $ok = false; $err = ''; $path = ''; $fn = ''; $enc = 0;
        try {
            if ($b['kind'] === 'config') {
                $fn = "neuru-config-$ts.neuru";
                $path = "$dir/$fn";
                $data = nm_cfg_build($conn, true);
                $bytes = nm_cfg_pack($data, $passphrase);
                if (@file_put_contents($path, $bytes) === false) throw new \RuntimeException('write failed (backups/ perms)');
                $enc = $passphrase !== '' ? 1 : 0; $ok = true;
            } else {
                if (!nm_vault_has_mysqldump()) throw new \RuntimeException('mysqldump not available in this container');
                $fn = ($b['kind'] === 'full' ? "neuru-full-$ts.sql.gz" : "neuru-data-$ts.sql.gz");
                $path = "$dir/$fn";
                $tables = [];
                if ($b['kind'] === 'data') {
                    $scope = json_decode($b['scope_json'] ?? '{}', true) ?: [];
                    $cats = nm_vault_categories();
                    foreach (($scope['categories'] ?? []) as $cat) if (isset($cats[$cat])) foreach ($cats[$cat][6] as $t => $_) $tables[] = $t;
                    if (!$tables) throw new \RuntimeException('no categories selected');
                }
                nm_vault_mysqldump($path, $tables);
                $ok = is_file($path) && filesize($path) > 0;
                if (!$ok) throw new \RuntimeException('dump produced no output');
            }
            $size = is_file($path) ? filesize($path) : 0;
            $sha = $size ? hash_file('sha256', $path) : null;
            // push to remote target if requested
            $remoteRef = null;
            if ($b['target'] !== 'local') { $pr = nm_vault_target_push($conn, $b['target'], $path, $fn, $b);
                if (empty($pr['ok'])) { $err = 'stored locally; offsite push failed: ' . ($pr['error'] ?? '?'); } else $remoteRef = $pr['ref'] ?? null; }
            $st = $conn->prepare("UPDATE nm_vault_backups SET status='done', filename=?, path=?, size_bytes=?, sha256=?, encrypted=?, remote_ref=?, error=?, finished_at=NOW() WHERE id=?");
            $errN = $err ?: null; $st->bind_param('ssisissi', $fn, $path, $size, $sha, $enc, $remoteRef, $errN, $id); $st->execute(); $st->close();
            return ['ok' => true, 'file' => $fn, 'size' => $size];
        } catch (\Throwable $e) {
            $err = $e->getMessage();
            try { $st = $conn->prepare("UPDATE nm_vault_backups SET status='failed', error=?, finished_at=NOW() WHERE id=?");
                $st->bind_param('si', $err, $id); $st->execute(); $st->close(); } catch (\Throwable $e2) {}
            if ($path && is_file($path)) @unlink($path);
            return ['ok' => false, 'error' => $err];
        }
    }
    function nm_vault_has_mysqldump(): bool {
        static $h = null; if ($h !== null) return $h;
        $out = []; @exec('command -v mysqldump 2>/dev/null', $out); $h = !empty($out);
        return $h;
    }
    function nm_vault_has_mysql(): bool {
        static $h = null; if ($h !== null) return $h;
        $out = []; @exec('command -v mysql 2>/dev/null', $out); $h = !empty($out);
        return $h;
    }
    function nm_vault_mysqldump(string $path, array $tables = []): void {
        $c = nm_vault_db_creds();
        $args = ['-h', $c['host'], '-u', $c['user'], '--single-transaction', '--quick', '--no-tablespaces', '--skip-lock-tables', $c['db']];
        foreach ($tables as $t) $args[] = $t;
        $inner = 'mysqldump';
        foreach ($args as $a) $inner .= ' ' . escapeshellarg($a);
        $inner .= ' | gzip > ' . escapeshellarg($path);
        // Run under bash with `pipefail` so a mysqldump failure (lost DB connection, table
        // read error, OOM) FAILS the whole pipeline — otherwise gzip exits 0 and we'd mark a
        // truncated/corrupt dump as "done". Password via MYSQL_PWD env (never on the cmdline).
        putenv('MYSQL_PWD=' . $c['pass']);
        @exec('bash -c ' . escapeshellarg('set -o pipefail; ' . $inner) . ' 2>/dev/null', $o, $rc);
        putenv('MYSQL_PWD');
        if ($rc !== 0) { if (is_file($path)) @unlink($path); throw new \RuntimeException('mysqldump failed (exit ' . $rc . ')'); }
    }
}

// ── target drivers (offsite) ──────────────────────────────────────────────────
if (!function_exists('nm_vault_target_push')) {
    function nm_vault_target_push($conn, string $target, string $file, string $name, array $b): array {
        if (!is_file($file)) return ['ok' => false, 'error' => 'file missing'];
        switch ($target) {
            case 'portal':  return nm_vault_push_portal($conn, $file, $name, $b);
            case 's3':      return nm_vault_push_s3($conn, $file, $name);
            case 'webdav':  return nm_vault_push_webdav($conn, $file, $name);
            default:        return ['ok' => true, 'ref' => null];   // local
        }
    }
    // Portal: POST to {api_base}/v1/backup with the license key (endpoint is planned Portal-side).
    function nm_vault_push_portal($conn, string $file, string $name, array $b): array {
        if (!function_exists('nm_lic_api_base')) return ['ok' => false, 'error' => 'license client unavailable'];
        $base = nm_lic_api_base($conn); if ($base === '') return ['ok' => false, 'error' => 'portal not configured'];
        $key = ''; try { $key = (string)($conn->query("SELECT license_key FROM nm_license WHERE id=1")->fetch_assoc()['license_key'] ?? ''); } catch (\Throwable $e) {}
        $ch = curl_init($base . '/v1/backup');
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_POST => true, CURLOPT_TIMEOUT => 900,
            CURLOPT_HTTPHEADER => ['X-License-Key: ' . $key, 'X-Backup-Name: ' . $name, 'Content-Type: application/octet-stream'],
            CURLOPT_INFILE => fopen($file, 'rb'), CURLOPT_UPLOAD => true, CURLOPT_INFILESIZE => filesize($file)]);
        $res = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
        if ($code === 200 || $code === 201) return ['ok' => true, 'ref' => 'portal:' . $name];
        if ($code === 404) return ['ok' => false, 'error' => 'Portal /v1/backup not available yet'];
        return ['ok' => false, 'error' => 'portal HTTP ' . $code];
    }
    // S3: pure-PHP SigV4 PUT (no aws-sdk / no new extension). Config in vault settings.
    function nm_vault_push_s3($conn, string $file, string $name): array {
        $g = fn($k) => (string)nm_vault_get($conn, $k, '');
        $bucket = $g('vault_s3_bucket'); $region = $g('vault_s3_region') ?: 'us-east-1';
        $ak = $g('vault_s3_key'); $sk = nm_vault_secret_get($conn, 'vault_s3_secret');
        $endpoint = $g('vault_s3_endpoint');   // optional (S3-compatible: MinIO/R2/Wasabi)
        if (!$bucket || !$ak || !$sk) return ['ok' => false, 'error' => 'S3 not configured'];
        $host = $endpoint ?: "$bucket.s3.$region.amazonaws.com";
        $host = preg_replace('#^https?://#', '', $host);
        $key = 'neuru-backups/' . $name;
        $hash = hash_file('sha256', $file);   // stream-hash the file (no full-file load into memory)
        $r = nm_vault_s3_put($host, $region, $ak, $sk, $key, $file, $hash);
        return $r['ok'] ? ['ok' => true, 'ref' => "s3://$bucket/$key"] : $r;
    }
    // WebDAV: simple authenticated PUT.
    function nm_vault_push_webdav($conn, string $file, string $name): array {
        $g = fn($k) => (string)nm_vault_get($conn, $k, '');
        $urlBase = rtrim($g('vault_webdav_url'), '/'); $user = $g('vault_webdav_user'); $pass = nm_vault_secret_get($conn, 'vault_webdav_pass');
        if (!$urlBase) return ['ok' => false, 'error' => 'WebDAV not configured'];
        $ch = curl_init($urlBase . '/' . rawurlencode($name));
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_CUSTOMREQUEST => 'PUT', CURLOPT_TIMEOUT => 900,
            CURLOPT_UPLOAD => true, CURLOPT_INFILE => fopen($file, 'rb'), CURLOPT_INFILESIZE => filesize($file)]);
        if ($user) curl_setopt($ch, CURLOPT_USERPWD, "$user:$pass");
        curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
        return ($code >= 200 && $code < 300) ? ['ok' => true, 'ref' => "webdav:$name"] : ['ok' => false, 'error' => 'WebDAV HTTP ' . $code];
    }
    // secrets (S3 secret / webdav pass) stored encrypted if nm_secret is available
    function nm_vault_secret_get($conn, string $k): string {
        $v = (string)nm_vault_get($conn, $k, '');
        if ($v !== '' && function_exists('nm_secret_decrypt')) { $d = @nm_secret_decrypt($v); if ($d !== false && $d !== null) return $d; }
        return $v;
    }
    // minimal AWS SigV4 PUT — STREAMS the file (never loads it into memory), hash precomputed via hash_file
    function nm_vault_s3_put(string $host, string $region, string $ak, string $sk, string $key, string $file, string $hash): array {
        $service = 's3'; $now = gmdate('Ymd\THis\Z'); $date = gmdate('Ymd');
        $uri = '/' . str_replace('%2F', '/', rawurlencode($key));
        $canHeaders = "host:$host\nx-amz-content-sha256:$hash\nx-amz-date:$now\n";
        $signed = 'host;x-amz-content-sha256;x-amz-date';
        $canReq = "PUT\n$uri\n\n$canHeaders\n$signed\n$hash";
        $scope = "$date/$region/$service/aws4_request";
        $sts = "AWS4-HMAC-SHA256\n$now\n$scope\n" . hash('sha256', $canReq);
        $kDate = hash_hmac('sha256', $date, 'AWS4' . $sk, true);
        $kReg = hash_hmac('sha256', $region, $kDate, true);
        $kSvc = hash_hmac('sha256', $service, $kReg, true);
        $kSig = hash_hmac('sha256', 'aws4_request', $kSvc, true);
        $sig = hash_hmac('sha256', $sts, $kSig);
        $auth = "AWS4-HMAC-SHA256 Credential=$ak/$scope, SignedHeaders=$signed, Signature=$sig";
        $ch = curl_init("https://$host$uri");
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_UPLOAD => true, CURLOPT_CUSTOMREQUEST => 'PUT',
            CURLOPT_INFILE => fopen($file, 'rb'), CURLOPT_INFILESIZE => filesize($file), CURLOPT_TIMEOUT => 900,
            CURLOPT_HTTPHEADER => ["Host: $host", "x-amz-date: $now", "x-amz-content-sha256: $hash", "Authorization: $auth"]]);
        curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); $e = curl_error($ch); curl_close($ch);
        return ($code >= 200 && $code < 300) ? ['ok' => true] : ['ok' => false, 'error' => "S3 HTTP $code $e"];
    }
}

// ── cron tick: finish queued jobs, run due auto-backups, rotate old ones ───────
if (!function_exists('nm_vault_backup_tick')) {
    function nm_vault_backup_tick($conn): array {
        nm_vault_backup_ensure($conn);
        $out = ['ran' => [], 'scheduled' => null, 'rotated' => 0];
        // 1) finish any queued jobs the detached runner missed
        try { $r = $conn->query("SELECT id FROM nm_vault_backups WHERE status='queued' ORDER BY id ASC LIMIT 3");
            while ($r && $x = $r->fetch_row()) { nm_vault_backup_run($conn, (int)$x[0]); $out['ran'][] = (int)$x[0]; } } catch (\Throwable $e) {}
        // 2) scheduled auto-backup (frequency in days; 0=off)
        $freq = (int)nm_vault_get($conn, 'vault_backup_freq_days', 0);
        if ($freq > 0) {
            $last = (int)nm_vault_get($conn, 'vault_backup_last', 0);
            if (time() - $last >= $freq * 86400 - 300) {
                $kind = (string)nm_vault_get($conn, 'vault_backup_kind', 'full');
                $target = (string)nm_vault_get($conn, 'vault_backup_target', 'local');
                $res = nm_vault_backup_create($conn, $kind, ['target' => $target, 'auto' => true, 'by' => 'scheduler', 'note' => 'scheduled']);
                nm_vault_set($conn, 'vault_backup_last', time());
                $out['scheduled'] = $res;
            }
        }
        // 3) rotate: keep the newest N successful backups (per kind), delete older files+rows
        $keep = max(1, (int)nm_vault_get($conn, 'vault_backup_keep', 7));
        foreach (['config','data','full'] as $k) {
            try { $r = $conn->query("SELECT id FROM nm_vault_backups WHERE kind='$k' AND status='done' ORDER BY id DESC");
                $i = 0; while ($r && $x = $r->fetch_row()) { $i++; if ($i > $keep) { nm_vault_backup_delete($conn, (int)$x[0]); $out['rotated']++; } } } catch (\Throwable $e) {}
        }
        return $out;
    }
}

// ── restore (guarded) — config via nm_cfg_import; data/full via `mysql < dump` ─
if (!function_exists('nm_vault_restore')) {
    function nm_vault_restore($conn, int $id, array $opts = []): array {
        $b = nm_vault_backup_get($conn, $id); if (!$b || $b['status'] !== 'done') return ['ok' => false, 'error' => 'backup not available'];
        if (empty($b['path']) || !is_file($b['path'])) return ['ok' => false, 'error' => 'backup file missing (offsite-only backups must be downloaded first)'];
        // safety backup of the CURRENT state first
        $safety = nm_vault_backup_create($conn, $b['kind'] === 'config' ? 'config' : 'full', ['auto' => true, 'by' => 'pre-restore', 'note' => 'auto pre-restore safety']);
        try {
            if ($b['kind'] === 'config') {
                $bytes = (string)file_get_contents($b['path']);
                $data = nm_cfg_unpack($bytes, (string)($opts['passphrase'] ?? ''));
                $res = nm_cfg_import($conn, $data, ['restore_secret' => !empty($opts['restore_secret']), 'skip_users' => !empty($opts['skip_users'])]);
                return ['ok' => !empty($res['ok']), 'kind' => 'config', 'safety' => $safety['id'] ?? null] + $res;
            }
            if (!nm_vault_has_mysql()) return ['ok' => false, 'error' => 'mysql client not available'];
            $c = nm_vault_db_creds();
            // pipefail so a corrupt/truncated .sql.gz (gunzip failure) FAILS the restore instead of
            // silently importing a partial stream and reporting success.
            $inner = 'gunzip -c ' . escapeshellarg($b['path'])
                   . ' | mysql -h ' . escapeshellarg($c['host']) . ' -u ' . escapeshellarg($c['user']) . ' ' . escapeshellarg($c['db']);
            putenv('MYSQL_PWD=' . $c['pass']);
            @exec('bash -c ' . escapeshellarg('set -o pipefail; ' . $inner) . ' 2>/dev/null', $o, $rc);
            putenv('MYSQL_PWD');
            if ($rc !== 0) return ['ok' => false, 'error' => 'restore failed (exit ' . $rc . ')', 'safety' => $safety['id'] ?? null];
            return ['ok' => true, 'kind' => $b['kind'], 'safety' => $safety['id'] ?? null];
        } catch (\Throwable $e) { return ['ok' => false, 'error' => $e->getMessage(), 'safety' => $safety['id'] ?? null]; }
    }
}
