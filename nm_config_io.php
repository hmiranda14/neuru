<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Configuration export/import engine ("Save Configuration" → config.neuru).
// Captures EVERYTHING an admin configured — settings, nodes, interfaces, links,
// integrations, credentials (encrypted), notification routing, RBAC (roles/users),
// dashboards, thresholds, feature configs — and can restore it later on the same or
// a fresh install. TELEMETRY (stats/samples/syslog/netflow/audit/logs) is excluded:
// it is not "configuration", it regenerates itself, and it would bloat the file to GBs.
//
// The optional passphrase encrypts the whole file (libsodium secretbox + Argon2id KDF)
// so the export — which contains the per-install secret key + encrypted credentials —
// is safe at rest. RBAC perm: 'config_backup'. mysqli is in EXCEPTION mode → every
// write is guarded; import runs inside a FK-checks-off transaction so a bad file rolls
// back cleanly and never half-restores.
// ─────────────────────────────────────────────────────────────────────────────

if (!defined('NM_CFG_MAGIC')) define('NM_CFG_MAGIC', 'NEURU-CONFIG');
if (!defined('NM_CFG_FORMAT')) define('NM_CFG_FORMAT', 1);

// ── Telemetry / runtime tables — NEVER part of a config export ────────────────
// (rotating stats, samples, logs, events, caches, derived data, per-tenant portal
//  tables). Everything NOT here — and not matching the backstop pattern below — is
//  treated as configuration and exported in full.
if (!function_exists('nm_cfg_data_tables')) {
    function nm_cfg_data_tables(): array {
        return [
            // raw telemetry / time-series
            'nm_device_stats','nm_health_samples','nm_latency_samples','nm_db_samples','nm_bio_samples',
            'nm_gpu_stats','nm_port_stats','nm_ping_stats','nm_rt_samples','nm_tplink_samples',
            'nm_wg_peer_traffic','nm_cluster_dev_history','nm_cluster_rollups','nm_ai_baselines','nm_db_repl',
            'container_net_samples','container_logs',
            // logs / events / audit
            'nm_audit_log','nm_poller_log','nm_notify_log','nm_wg_apply_log','nm_rc_logs','nm_rc_sessions',
            'nm_aip_events','nm_aip_sessions','nm_aip_actions','nm_lx_events','nm_lx_actions',
            'nm_win_events','nm_win_actions','nm_heal_events','nm_wear_history','nm_tplink_events',
            'nm_decoy_events','nm_threat_actions','container_fix_logs','container_incidents',
            'activity_log','user_action_log',
            // incidents / alerts / findings / insights (generated, not configured)
            'nm_incidents','nm_incident_signals','nm_latency_alerts','nm_netflow_alerts','nm_netalert_alerts',
            'nm_weather_alerts','nm_ai_insights','nm_shadowit_findings','nm_archaeology_findings',
            'nm_health_predictions','nm_health_counters','nm_cluster_incidents',
            // caches / snapshots / transient state / queues / pending approvals
            'nm_geoip_cache','nm_dbobs_cache','nm_mtfw_snapshots','nm_config_snapshots','nm_routing_snapshots',
            'nm_db_schema_snap','nm_db_schema_drift','nm_config_changes','nm_alert_state','nm_if_counters',
            'nm_gpu_proc','nm_discovery_candidates','nm_decoy_diversions','nm_lx_health','nm_win_health',
            'nm_mtfw_pending','nm_cisco_orch_pending','nm_aip_tg_approvals','nm_bio_tg_approvals',
            'nm_bio_synthetic','nm_cluster_outbox','nm_cluster_commands','nm_cluster_cmd_delivery',
            'nm_netflow_flows','nm_syslog',
            // discovered (not admin-set) — repopulates from polling
            'nm_cisco_env','nm_cisco_ports','nm_cisco_vlans','nm_cisco_routing','nm_cisco_ipsla',
            'nm_cisco_neighbors','nm_cisco_status','nm_cisco_config',
            // per-install identity (license key + machine fingerprint) — NOT portable config;
            // a restore on another box must keep that box's own licensing, not the source's.
            'nm_license',
        ];
    }
}

// Backstop pattern so tables added by FUTURE features that are clearly telemetry are
// auto-excluded even if someone forgets to list them above.
if (!function_exists('nm_cfg_is_data_table')) {
    function nm_cfg_is_data_table(string $t): bool {
        if (in_array($t, nm_cfg_data_tables(), true)) return true;
        if (strncmp($t, 'lic_', 4) === 0) return true;   // License-Portal tables — not a NEURU install's config
        return (bool)preg_match(
            '/(_stats$|_samples$|_log$|_logs$|_events$|_history$|_cache$|_snapshots?$|_traffic$|_flows$|syslog|heartbeat|device_stats)/i',
            $t
        );
    }
}

// All configuration tables present in THIS database (deny-list driven → future-proof).
if (!function_exists('nm_cfg_config_tables')) {
    function nm_cfg_config_tables($conn): array {
        $out = [];
        $db = $conn->query('SELECT DATABASE()')->fetch_row()[0];
        $st = $conn->prepare("SELECT TABLE_NAME FROM information_schema.TABLES
                              WHERE TABLE_SCHEMA=? AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME");
        $st->bind_param('s', $db); $st->execute();
        $r = $st->get_result();
        while ($x = $r->fetch_row()) { if (!nm_cfg_is_data_table($x[0])) $out[] = $x[0]; }
        $st->close();
        return $out;
    }
}

// ── binary-safe cell encoding (VARBINARY / non-UTF8 → {"__b64__":…}) ───────────
if (!function_exists('nm_cfg_enc_cell')) {
    function nm_cfg_enc_cell($v) {
        if ($v === null) return null;
        if (is_string($v) && $v !== '' && !mb_check_encoding($v, 'UTF-8')) return ['__b64__' => base64_encode($v)];
        return $v;
    }
    function nm_cfg_dec_cell($v) {
        if (is_array($v) && isset($v['__b64__'])) return base64_decode($v['__b64__']);
        return $v;
    }
}

// ── the per-install secret key (so encrypted credentials restore faithfully) ──
if (!function_exists('nm_cfg_secret_path')) {
    function nm_cfg_secret_path(): string { return __DIR__ . '/.nm_secret.key'; }
}

// ── build the full config payload (array, pre-serialization) ──────────────────
if (!function_exists('nm_cfg_build')) {
    function nm_cfg_build($conn, bool $include_secret = true): array {
        $tables = nm_cfg_config_tables($conn);
        $ver = @trim((string)@file_get_contents(__DIR__ . '/VERSION')) ?: 'unknown';
        $out = [
            'magic'        => NM_CFG_MAGIC,
            'format'       => NM_CFG_FORMAT,
            'neuru_version'=> $ver,
            'exported_at'  => gmdate('Y-m-d\TH:i:s\Z'),
            'host'         => $_SERVER['HTTP_HOST'] ?? gethostname(),
            'tables'       => [],
            'secret_key'   => null,
        ];
        foreach ($tables as $t) {
            try {
                $res = $conn->query("SELECT * FROM `$t`");
                if ($res === false) continue;
                $cols = [];
                foreach ($res->fetch_fields() as $f) $cols[] = $f->name;
                $rows = [];
                while ($row = $res->fetch_assoc()) {
                    $enc = [];
                    foreach ($row as $k => $v) $enc[$k] = nm_cfg_enc_cell($v);
                    $rows[] = $enc;
                }
                $res->free();
                $out['tables'][$t] = ['columns' => $cols, 'rows' => $rows];
            } catch (\Throwable $e) { /* skip a table we can't read; never abort the whole export */ }
        }
        if ($include_secret) {
            $kp = nm_cfg_secret_path();
            if (is_readable($kp)) { $raw = (string)@file_get_contents($kp); if ($raw !== '') $out['secret_key'] = base64_encode($raw); }
        }
        return $out;
    }
}

// ── summary for the UI (counts, no payload) ───────────────────────────────────
if (!function_exists('nm_cfg_summary')) {
    function nm_cfg_summary(array $data): array {
        $tables = $data['tables'] ?? [];
        $rowsum = 0; $list = [];
        foreach ($tables as $t => $td) { $n = count($td['rows'] ?? []); $rowsum += $n; $list[$t] = $n; }
        arsort($list);
        return ['table_count' => count($tables), 'row_count' => $rowsum,
                'has_secret' => !empty($data['secret_key']), 'tables' => $list];
    }
}

// ── pack: array → file bytes (gzip, optional passphrase encryption) ───────────
if (!function_exists('nm_cfg_pack')) {
    function nm_cfg_pack(array $data, string $passphrase = ''): string {
        $inner = gzencode(json_encode($data, JSON_UNESCAPED_SLASHES), 6);
        if ($passphrase !== '') {
            $salt  = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
            $key   = sodium_crypto_pwhash(SODIUM_CRYPTO_SECRETBOX_KEYBYTES, $passphrase, $salt,
                        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE);
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $cipher= sodium_crypto_secretbox($inner, $nonce, $key);
            sodium_memzero($key); sodium_memzero($passphrase);
            $env = ['magic'=>NM_CFG_MAGIC,'format'=>NM_CFG_FORMAT,'enc'=>true,'kdf'=>'argon2id',
                    'salt'=>base64_encode($salt),'nonce'=>base64_encode($nonce),'cipher'=>base64_encode($cipher)];
        } else {
            $env = ['magic'=>NM_CFG_MAGIC,'format'=>NM_CFG_FORMAT,'enc'=>false,'gz'=>true,
                    'blob'=>base64_encode($inner)];
        }
        return json_encode($env, JSON_UNESCAPED_SLASHES);
    }
}

// ── unpack: file bytes → payload array (throws on bad magic / wrong passphrase) ─
if (!function_exists('nm_cfg_unpack')) {
    function nm_cfg_unpack(string $bytes, string $passphrase = ''): array {
        $env = json_decode(trim($bytes), true);
        if (!is_array($env) || ($env['magic'] ?? '') !== NM_CFG_MAGIC) throw new \RuntimeException('Not a NEURU config file.');
        if ((int)($env['format'] ?? 0) > NM_CFG_FORMAT) throw new \RuntimeException('File is from a newer NEURU — update first.');
        if (!empty($env['enc'])) {
            if ($passphrase === '') throw new \RuntimeException('This config file is encrypted — a passphrase is required.');
            $salt = base64_decode($env['salt']); $nonce = base64_decode($env['nonce']); $cipher = base64_decode($env['cipher']);
            $key  = sodium_crypto_pwhash(SODIUM_CRYPTO_SECRETBOX_KEYBYTES, $passphrase, $salt,
                        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE);
            $inner = sodium_crypto_secretbox_open($cipher, $nonce, $key);
            sodium_memzero($key); sodium_memzero($passphrase);
            if ($inner === false) throw new \RuntimeException('Wrong passphrase or corrupted file.');
        } else {
            $inner = base64_decode($env['blob'] ?? '');
        }
        $json = @gzdecode($inner);
        if ($json === false) $json = $inner;                 // tolerate a non-gzipped body
        $data = json_decode($json, true);
        if (!is_array($data) || ($data['magic'] ?? '') !== NM_CFG_MAGIC) throw new \RuntimeException('Corrupted config payload.');
        return $data;
    }
}

// ── write a safety snapshot of the CURRENT config to logs/ (deny-all) before an import ─
if (!function_exists('nm_cfg_safety_snapshot')) {
    function nm_cfg_safety_snapshot($conn): ?string {
        try {
            $dir = __DIR__ . '/logs/config-backups';
            if (!is_dir($dir)) @mkdir($dir, 0775, true);
            if (!is_dir($dir) || !is_writable($dir)) return null;
            $f = $dir . '/pre-restore-' . gmdate('Ymd-His') . '.neuru';
            @file_put_contents($f, nm_cfg_pack(nm_cfg_build($conn, true), ''));
            return is_file($f) ? $f : null;
        } catch (\Throwable $e) { return null; }
    }
}

// ── the restore ───────────────────────────────────────────────────────────────
// $opts: restore_secret(bool), skip_users(bool) — skip the users/role_profiles/perms
// tables so an import can't lock the current operator out of a live box.
if (!function_exists('nm_cfg_import')) {
    function nm_cfg_import($conn, array $data, array $opts = []): array {
        $restoreSecret = $opts['restore_secret'] ?? true;
        $skipUsers     = $opts['skip_users'] ?? false;
        $userTables    = ['users','role_profiles','nm_user_perms'];
        $report = ['restored'=>[], 'skipped'=>[], 'secret'=>'untouched', 'errors'=>[]];

        // current DB tables + their real columns (schema-drift resilient)
        $dbCols = [];
        $db = $conn->query('SELECT DATABASE()')->fetch_row()[0];
        $r = $conn->query("SELECT TABLE_NAME, COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='" . $conn->real_escape_string($db) . "'");
        while ($x = $r->fetch_row()) { $dbCols[$x[0]][$x[1]] = true; }

        $conn->begin_transaction();
        try {
            $conn->query('SET FOREIGN_KEY_CHECKS=0');
            foreach (($data['tables'] ?? []) as $t => $td) {
                if (!isset($dbCols[$t])) { $report['skipped'][$t] = 'not in this install'; continue; }
                if ($skipUsers && in_array($t, $userTables, true)) { $report['skipped'][$t] = 'user table (kept)'; continue; }
                // columns that exist in BOTH the file and the live table
                $cols = array_values(array_filter($td['columns'] ?? [], fn($c) => isset($dbCols[$t][$c])));
                if (!$cols) { $report['skipped'][$t] = 'no matching columns'; continue; }
                $conn->query("DELETE FROM `$t`");
                if (!empty($td['rows'])) {
                    $ph = '(' . implode(',', array_fill(0, count($cols), '?')) . ')';
                    $sql = "INSERT INTO `$t` (`" . implode('`,`', $cols) . "`) VALUES $ph";
                    $st = $conn->prepare($sql);
                    foreach ($td['rows'] as $row) {
                        $vals = [];
                        foreach ($cols as $c) $vals[] = array_key_exists($c, $row) ? nm_cfg_dec_cell($row[$c]) : null;
                        $types = str_repeat('s', count($vals));
                        $st->bind_param($types, ...$vals);
                        $st->execute();
                    }
                    $st->close();
                }
                $report['restored'][$t] = count($td['rows'] ?? []);
            }
            $conn->query('SET FOREIGN_KEY_CHECKS=1');
            $conn->commit();
        } catch (\Throwable $e) {
            $conn->rollback();
            try { $conn->query('SET FOREIGN_KEY_CHECKS=1'); } catch (\Throwable $e2) {}
            return ['ok'=>false, 'error'=>$e->getMessage(), 'report'=>$report];
        }

        // secret key AFTER the data commit (so credentials decrypt post-restore)
        if ($restoreSecret && !empty($data['secret_key'])) {
            try {
                $kp = nm_cfg_secret_path();
                if (is_file($kp)) @copy($kp, $kp . '.bak-' . gmdate('Ymd-His'));
                $raw = base64_decode($data['secret_key']);
                if ($raw !== '' && @file_put_contents($kp, $raw) !== false) { @chmod($kp, 0644); $report['secret'] = 'restored'; }
                else $report['secret'] = 'write failed (check .nm_secret.key perms)';
            } catch (\Throwable $e) { $report['secret'] = 'error: ' . $e->getMessage(); }
        }
        return ['ok'=>true, 'report'=>$report];
    }
}
