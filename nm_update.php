<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Self-Update engine. Talks to the NEURU License Portal's update feed,
// downloads the entitled release, and cryptographically verifies it (SHA-256 +
// Ed25519 signature against the SAME embedded public key used for licensing) BEFORE
// anything touches disk. Applying is deliberately conservative: verified builds are
// staged, and the actual file-swap happens with a backup + post-apply health check
// and auto-rollback. If the web user can't write the app dir (bind-mount), the apply
// is handed to a privileged helper (scripts/nm_apply_update.sh).
//
// Reuses nm_license.php: NM_LIC_PUBKEY_B64, nm_lic_api_base(), nm_lic_row(),
// nm_lic_app_version(). Nothing here needs the private key.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_license.php';

if (!function_exists('nm_update_dir')) {

    function nm_update_dir(): string { return __DIR__ . '/updates'; }
    function nm_update_ensure_dir(): void {
        $d = nm_update_dir();
        foreach ([$d, "$d/staging", "$d/backups"] as $p) { if (!is_dir($p)) @mkdir($p, 0775, true); @chmod($p, 0775); }
    }

    // ── settings (nm_settings key/val) ──────────────────────────────────────────
    function nm_update_get($conn, string $k, ?string $def = null): ?string {
        try {
            $st = $conn->prepare("SELECT setting_val FROM nm_settings WHERE setting_key=? LIMIT 1");
            $st->bind_param('s', $k); $st->execute();
            $r = $st->get_result()->fetch_assoc();
            return $r ? (string)$r['setting_val'] : $def;
        } catch (\Throwable $e) { return $def; }
    }
    function nm_update_set($conn, string $k, string $v): void {
        try {
            $st = $conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES (?,?)
                                  ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
            $st->bind_param('ss', $k, $v); $st->execute();
        } catch (\Throwable $e) { /* best-effort */ }
    }

    function nm_update_channel($conn): string { return nm_update_get($conn, 'update_channel', 'stable') === 'beta' ? 'beta' : 'stable'; }
    function nm_update_policy($conn): string  { $p = nm_update_get($conn, 'update_policy', 'manual'); return in_array($p, ['manual','notify','auto'], true) ? $p : 'manual'; }
    function nm_update_current_version($conn): string { return nm_lic_app_version($conn); }

    // ── HTTP helpers (curl) ─────────────────────────────────────────────────────
    function nm_update_http_get(string $url): array {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>25, CURLOPT_FOLLOWLOCATION=>true,
            CURLOPT_SSL_VERIFYPEER=>true, CURLOPT_USERAGENT=>'NEURU-Updater']);
        $body = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $err = curl_error($ch); curl_close($ch);
        if ($body === false) return ['ok'=>false, 'error'=>$err ?: 'request failed'];
        $json = json_decode((string)$body, true);
        return ['ok'=>$code<400, 'code'=>$code, 'json'=>is_array($json)?$json:null, 'raw'=>$body, 'error'=>$code>=400?('http_'.$code):null];
    }
    // Download to a file, capturing X-NEURU-* response headers.
    function nm_update_http_download(string $url, string $dest): array {
        $fp = @fopen($dest, 'wb');
        if (!$fp) return ['ok'=>false, 'error'=>'cannot write staging file — the web user cannot write updates/staging/ (normal on a bind-mount). Fix once as root: chown -R www-data updates && chmod -R 775 updates (0.1.1.5+ does this automatically on container start).'];
        $headers = [];
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_FILE=>$fp, CURLOPT_TIMEOUT=>600, CURLOPT_FOLLOWLOCATION=>true,
            CURLOPT_SSL_VERIFYPEER=>true, CURLOPT_USERAGENT=>'NEURU-Updater',
            CURLOPT_HEADERFUNCTION=>function($c,$h) use (&$headers){ $p=explode(':',$h,2); if(count($p)===2) $headers[strtolower(trim($p[0]))]=trim($p[1]); return strlen($h); }]);
        $ok = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $err = curl_error($ch); curl_close($ch); fclose($fp);
        if (!$ok || $code >= 400) { @unlink($dest); return ['ok'=>false, 'error'=>$err ?: ('http_'.$code)]; }
        return ['ok'=>true, 'headers'=>$headers, 'code'=>$code];
    }

    // ── signature verification (Ed25519 over "version:sha256") ──────────────────
    function nm_update_verify_sig(string $version, string $sha256, string $sigB64): bool {
        if (!function_exists('sodium_crypto_sign_verify_detached')) return false;
        $sig = base64_decode($sigB64, true);
        if ($sig === false || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES) return false;
        $pk = base64_decode(NM_LIC_PUBKEY_B64);
        try { return sodium_crypto_sign_verify_detached($sig, $version . ':' . $sha256, $pk); }
        catch (\Throwable $e) { return false; }
    }

    // ── check for updates ───────────────────────────────────────────────────────
    function nm_update_check($conn): array {
        $base = rtrim(nm_lic_api_base($conn), '/');
        if ($base === '') return ['ok'=>false, 'error'=>'license_api_url not configured (activate a license first)'];
        $row = nm_lic_row($conn); $key = $row['license_key'] ?? '';
        if ($key === '') return ['ok'=>false, 'error'=>'not activated — no license key'];
        $cur = nm_update_current_version($conn); $chan = nm_update_channel($conn);
        $url = $base . '/v1/updates/check?license_key=' . urlencode($key) . '&current_version=' . urlencode($cur) . '&channel=' . urlencode($chan);
        $r = nm_update_http_get($url);
        nm_update_set($conn, 'update_last_check', date('c'));
        if (empty($r['json'])) return ['ok'=>false, 'error'=>$r['error'] ?? 'no response from portal'];
        // Cache a SLIM copy — release notes can be KB-sized and overflow nm_settings.setting_val on
        // older installs (VARCHAR(500) + STRICT sql_mode → the cache write throws, gets swallowed, and
        // the Updates page keeps rendering the STALE previous result: shows "up to date" with no
        // Download button even though a signed new build IS available). The card only needs the
        // availability + download coordinates; the notes come from the live check. Keep the FULL notes
        // in the returned value so a fresh check still displays them.
        $slim = $r['json']; unset($slim['notes'], $slim['release_notes']);
        try { nm_update_set($conn, 'update_last_result', json_encode($slim)); } catch (\Throwable $e) {}
        return $r['json'] + ['ok'=>true, 'current'=>$cur, 'channel'=>$chan];
    }
    // last cached check result (for banners / cron), without hitting the network
    function nm_update_last($conn): ?array {
        $j = nm_update_get($conn, 'update_last_result', ''); $d = $j ? json_decode($j, true) : null;
        return is_array($d) ? $d : null;
    }

    // ── download + verify → staging (SAFE: never modifies the app) ──────────────
    function nm_update_download($conn, string $version): array {
        nm_update_ensure_dir();
        $base = rtrim(nm_lic_api_base($conn), '/'); $row = nm_lic_row($conn); $key = $row['license_key'] ?? '';
        if ($base === '' || $key === '') return ['ok'=>false, 'error'=>'not configured/activated'];
        if (!preg_match('/^\d+(\.\d+){1,3}(-[A-Za-z0-9.]+)?$/', $version)) return ['ok'=>false, 'error'=>'bad version'];
        $chan = nm_update_channel($conn);
        $url  = $base . '/v1/pull?license_key=' . urlencode($key) . '&version=' . urlencode($version) . '&channel=' . urlencode($chan);
        $dest = nm_update_dir() . '/staging/neuru-' . $version . '.tar.gz';
        $res  = nm_update_http_download($url, $dest);
        if (!$res['ok']) return ['ok'=>false, 'error'=>'download failed: ' . ($res['error'] ?? '?')];
        $localSha = hash_file('sha256', $dest);
        $sha = strtolower($res['headers']['x-neuru-sha256'] ?? '');
        $sig = $res['headers']['x-neuru-signature'] ?? '';
        if ($sha !== '' && $localSha !== $sha) { @unlink($dest); return ['ok'=>false, 'error'=>'SHA-256 mismatch — download corrupt or tampered']; }
        if ($sig === '') { @unlink($dest); return ['ok'=>false, 'error'=>'no signature from portal — refusing unverified update']; }
        if (!nm_update_verify_sig($version, $localSha, $sig)) { @unlink($dest); return ['ok'=>false, 'error'=>'signature INVALID — this build was not signed by your portal. Refusing.']; }
        @file_put_contents($dest . '.sig', $sig);   // sidecar so the root applier can re-verify independently
        nm_update_set($conn, 'update_staged', json_encode(['version'=>$version, 'file'=>basename($dest), 'sha256'=>$localSha, 'size'=>filesize($dest), 'at'=>date('c')]));
        nm_audit_safe($conn, 'update.staged', ['version'=>$version, 'sha256'=>$localSha]);
        return ['ok'=>true, 'version'=>$version, 'sha256'=>$localSha, 'size'=>filesize($dest), 'file'=>$dest];
    }

    // currently staged (verified) build, or null
    function nm_update_staged($conn): ?array {
        $j = nm_update_get($conn, 'update_staged', ''); $d = $j ? json_decode($j, true) : null;
        if (!is_array($d)) return null;
        $p = nm_update_dir() . '/staging/' . basename($d['file'] ?? '');
        if (!is_file($p)) return null;
        $d['path'] = $p; return $d;
    }
    function nm_update_clear_staged($conn): void {
        $st = nm_update_staged($conn); if ($st && is_file($st['path'])) @unlink($st['path']);
        nm_update_set($conn, 'update_staged', '');
    }

    // ── apply ───────────────────────────────────────────────────────────────────
    // Web-side apply attempt: only if the app dir is writable AND we can archive.
    // Otherwise returns need_script=true and the operator runs the privileged helper.
    function nm_update_can_apply_in_web(): bool {
        return is_writable(__DIR__) && (class_exists('PharData') || nm_update_have_tar());
    }
    function nm_update_have_tar(): bool {
        if (!function_exists('exec')) return false;
        @exec('command -v tar', $o, $rc); return $rc === 0;
    }
    // Files/dirs that must NEVER be overwritten by an update (local state + secrets).
    function nm_update_preserve(): array {
        return ['connection.php', '.nm_secret.key', '.nm_secret.key.pub', 'uploads', 'logs', 'updates', '.env', 'net_mon_config_local.php'];
    }
    function nm_update_apply($conn, bool $dryRun = false): array {
        $st = nm_update_staged($conn);
        if (!$st) return ['ok'=>false, 'error'=>'nothing staged — download & verify an update first'];
        if (!nm_update_can_apply_in_web()) {
            // The web user can't write the bind-mounted app dir, so a ROOT worker finishes the job:
            // drop updates/PENDING (a plain file it reads without MySQL) → the /etc/cron.d/neuru-apply
            // watcher applies it within ~1 min. Fully hands-off — no manual `docker exec` needed.
            nm_update_set($conn, 'update_pending', json_encode(['version'=>$st['version'], 'file'=>$st['file'], 'sha256'=>$st['sha256'], 'at'=>date('c')]));
            @file_put_contents(nm_update_dir() . '/PENDING', "file={$st['file']}\nversion={$st['version']}\nsha256={$st['sha256']}\n");
            return ['ok'=>true, 'scheduled'=>true, 'version'=>$st['version'],
                'note'=>'Update verified — NEURU is applying it automatically in the background (about a minute). This page refreshes when it\'s done.',
                // fallback only: shown if the auto-apply watcher somehow isn't running.
                'command'=>'docker exec -u root <neuru-web-container> bash /var/www/html/netmon/scripts/nm_apply_update.sh'];
        }
        $app = __DIR__; $old = nm_update_current_version($conn); $ver = $st['version'];
        // 1. backup (best-effort full app snapshot, minus volatile dirs)
        $backup = nm_update_dir() . '/backups/backup-' . $old . '-' . date('Ymd-His') . '.tar.gz';
        $bk = nm_update_archive_app($app, $backup);
        if (!$bk['ok']) return ['ok'=>false, 'error'=>'backup failed: ' . $bk['error'] . ' (aborting — no changes made)'];
        if ($dryRun) return ['ok'=>true, 'dry_run'=>true, 'version'=>$ver, 'backup'=>basename($backup), 'note'=>'backup created; extract skipped'];
        // 2. extract staged build into a temp dir
        $tmp = nm_update_dir() . '/staging/_extract_' . bin2hex(random_bytes(3));
        @mkdir($tmp, 0775, true);
        $ex = nm_update_extract($st['path'], $tmp);
        if (!$ex['ok']) { nm_update_rmrf($tmp); return ['ok'=>false, 'error'=>'extract failed: ' . $ex['error']]; }
        $srcRoot = nm_update_find_app_root($tmp);
        // 3. copy new files over the app, preserving local state
        $mg = nm_update_merge($srcRoot, $app, nm_update_preserve());
        nm_update_rmrf($tmp);
        // 3b. ATOMIC guard: if ANY file failed to copy, the app is now half-old/half-new → ROLL BACK.
        if (!empty($mg['failed'])) {
            nm_update_restore_backup($app, $backup);
            nm_update_record_history($conn, $old, $ver, 'rolled_back');
            return ['ok'=>false, 'rolled_back'=>true,
                'error'=>'merge failed on ' . count($mg['failed']) . ' file(s) (e.g. ' . implode(', ', array_slice($mg['failed'], 0, 3)) . ') — rolled back to ' . $old . '.'];
        }
        $copied = $mg['copied'];
        // clear the OPcache so the new code is live immediately (this runs in the web SAPI → resets its cache)
        if (function_exists('opcache_reset')) @opcache_reset();
        // 3c. POST-APPLY HEALTH CHECK: VERSION landed + load-bearing files parse. If not → ROLL BACK.
        $hc = nm_update_health_check($app, $ver);
        if (!$hc['ok']) {
            nm_update_restore_backup($app, $backup);
            nm_update_record_history($conn, $old, $ver, 'rolled_back');
            nm_audit_safe($conn, 'update.rolled_back', ['from'=>$old, 'to'=>$ver, 'reason'=>$hc['error']]);
            return ['ok'=>false, 'rolled_back'=>true,
                'error'=>'post-apply health check failed (' . $hc['error'] . ') — rolled back to ' . $old . '.'];
        }
        // 4. run a migration hook if the release ships one
        if (is_file($app . '/install/migrate.php')) { try { include $app . '/install/migrate.php'; } catch (\Throwable $e) {} }
        // 5. record new version + history, clear staged
        nm_update_record_history($conn, $old, $ver, 'applied');
        nm_update_set($conn, 'update_staged', '');
        nm_update_set($conn, 'update_pending', '');
        // Clear the last check result so the Updates page doesn't render a STALE "update available"
        // for the version we JUST installed (the pre-update check cached "vX available"; without this
        // the card shows a phantom update to the current version until the next manual check).
        nm_update_set($conn, 'update_last_result', '');
        nm_audit_safe($conn, 'update.applied', ['from'=>$old, 'to'=>$ver, 'files'=>$copied]);
        return ['ok'=>true, 'version'=>$ver, 'from'=>$old, 'files'=>$copied, 'backup'=>basename($backup),
                'note'=>'Update applied + health-checked. Verify the app, then remove old backups from updates/backups/ when happy.'];
    }

    // archive helpers (PharData preferred; tar fallback)
    function nm_update_archive_app(string $app, string $dest): array {
        $exclude = nm_update_preserve();
        if (nm_update_have_tar()) {
            $args = '';
            foreach ($exclude as $e) $args .= ' --exclude=' . escapeshellarg('./' . $e);
            @exec('cd ' . escapeshellarg($app) . ' && tar czf ' . escapeshellarg($dest) . $args . ' . 2>&1', $o, $rc);
            return $rc === 0 ? ['ok'=>true] : ['ok'=>false, 'error'=>'tar rc=' . $rc];
        }
        try {
            $tar = substr($dest, 0, -3); // .tar
            $phar = new PharData($tar);
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($app, FilesystemIterator::SKIP_DOTS));
            foreach ($it as $f) {
                $rel = ltrim(str_replace($app, '', $f->getPathname()), '/');
                $top = explode('/', $rel)[0];
                if (in_array($top, $exclude, true)) continue;
                if ($f->isFile()) $phar->addFile($f->getPathname(), $rel);
            }
            $phar->compress(Phar::GZ); @unlink($tar);
            return ['ok'=>true];
        } catch (\Throwable $e) { return ['ok'=>false, 'error'=>$e->getMessage()]; }
    }
    function nm_update_extract(string $tgz, string $to): array {
        if (nm_update_have_tar()) {
            @exec('tar xzf ' . escapeshellarg($tgz) . ' -C ' . escapeshellarg($to) . ' 2>&1', $o, $rc);
            return $rc === 0 ? ['ok'=>true] : ['ok'=>false, 'error'=>'tar rc=' . $rc];
        }
        try { $p = new PharData($tgz); $p->extractTo($to, null, true); return ['ok'=>true]; }
        catch (\Throwable $e) { return ['ok'=>false, 'error'=>$e->getMessage()]; }
    }
    // A release tarball may contain the files at root or under a top folder (e.g. netmon/).
    function nm_update_find_app_root(string $dir): string {
        if (is_file($dir . '/index.php') || is_file($dir . '/net_mon.php') || is_file($dir . '/nm_license.php')) return $dir;
        foreach (glob($dir . '/*', GLOB_ONLYDIR) ?: [] as $d)
            if (is_file($d . '/nm_license.php') || is_file($d . '/net_mon.php')) return $d;
        return $dir;
    }
    // Returns ['copied'=>int, 'failed'=>string[]]. A non-empty 'failed' means the app is now a
    // half-old/half-new mix → the caller rolls back (U2).
    function nm_update_merge(string $src, string $dst, array $preserve): array {
        $n = 0; $failed = [];
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
        foreach ($it as $f) {
            $rel = ltrim(str_replace($src, '', $f->getPathname()), '/');
            $top = explode('/', $rel)[0];
            if (in_array($top, $preserve, true)) continue;
            $target = $dst . '/' . $rel;
            if ($f->isDir()) { if (!is_dir($target)) @mkdir($target, 0775, true); }
            else { @mkdir(dirname($target), 0775, true); if (@copy($f->getPathname(), $target)) $n++; else $failed[] = $rel; }
        }
        return ['copied'=>$n, 'failed'=>$failed];
    }

    // ── U2: post-apply health check + rollback ──────────────────────────────────
    // The new build must (a) have landed the expected VERSION and (b) parse its load-bearing PHP
    // files. Catches a corrupt/partial build before it goes live. php -l is used only if a CLI php
    // is available; otherwise the VERSION check still guards "did the update actually apply".
    function nm_update_have_php_cli(): bool {
        static $has = null; if ($has !== null) return $has;
        @exec('php -v 2>/dev/null', $o, $rc); return $has = ($rc === 0);
    }
    function nm_update_health_check(string $app, string $ver): array {
        $vf = @trim((string)@file_get_contents($app . '/VERSION'));
        if ($vf !== $ver) return ['ok'=>false, 'error'=>"VERSION is '$vf', expected '$ver'"];
        if (nm_update_have_php_cli()) {
            foreach (['connection.php','nm_license.php','nm_update.php','header.php','home.php'] as $crit) {
                $p = $app . '/' . $crit; if (!is_file($p)) continue;
                $o = []; @exec('php -l ' . escapeshellarg($p) . ' 2>&1', $o, $rc);
                if ($rc !== 0) return ['ok'=>false, 'error'=>"syntax error in $crit"];
            }
        }
        return ['ok'=>true];
    }
    // Restore the app from a backup tarball (the snapshot taken before the merge). The backup is a
    // full app archive (entries relative to $app), so extracting it into $app overlays the old files
    // back over the new ones — reverting the update. Volatile/preserved dirs were never archived.
    function nm_update_restore_backup(string $app, string $backup): array {
        if (!is_file($backup)) return ['ok'=>false, 'error'=>'backup missing'];
        $r = nm_update_extract($backup, $app);
        if (function_exists('opcache_reset')) @opcache_reset();
        return $r;
    }
    function nm_update_rmrf(string $p): void {
        if (!is_dir($p)) { @unlink($p); return; }
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($p, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) { $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname()); }
        @rmdir($p);
    }

    // ── history ─────────────────────────────────────────────────────────────────
    function nm_update_record_history($conn, string $from, string $to, string $result): void {
        $j = nm_update_get($conn, 'update_history', '[]'); $h = json_decode($j, true); if (!is_array($h)) $h = [];
        array_unshift($h, ['from'=>$from, 'to'=>$to, 'result'=>$result, 'at'=>date('c')]);
        $h = array_slice($h, 0, 30);
        nm_update_set($conn, 'update_history', json_encode($h));
    }

    // Returns the version of an applied update that still needs a CONTAINER RESTART, or '' if none.
    // A self-update copies files only — it does NOT restart the container, so the entrypoint hasn't
    // re-run its self-heal (cron perms / DB access) and the WireGuard sidecar hasn't reconnected the
    // tunnel that NEURU Flows ride on. We detect the pending restart by comparing the last 'applied'
    // update time to the entrypoint's boot marker: applied AFTER the last boot (or no boot marker yet)
    // ⇒ restart still pending. Only container-managed installs (bind-mount → web can't self-write the
    // app dir) are affected; a bare/dev install that CAN write in-place has no container to restart.
    function nm_update_reboot_pending($conn): string {
        if (nm_update_can_apply_in_web()) return '';
        $h = json_decode(nm_update_get($conn, 'update_history', '[]'), true);
        if (!is_array($h)) return '';
        $applied = null;
        foreach ($h as $e) { if (($e['result'] ?? '') === 'applied') { $applied = $e; break; } }  // newest-first
        if (!$applied) return '';
        $boot = (string) nm_update_get($conn, 'entrypoint_booted_at', '');
        if ($boot === '' || strtotime((string)($applied['at'] ?? '')) > strtotime($boot)) {
            return (string)($applied['to'] ?? '');
        }
        return '';
    }
    function nm_update_history($conn): array { $h = json_decode(nm_update_get($conn, 'update_history', '[]'), true); return is_array($h) ? $h : []; }

    // audit shim (nm_audit if present)
    function nm_audit_safe($conn, string $ev, array $meta = []): void {
        if (function_exists('nm_audit')) { try { nm_audit($conn, $ev, $meta); } catch (\Throwable $e) {} }
    }
}
