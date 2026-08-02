<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU Data Vault — database size control (retention + cleanup + molt + autopilot).
// The single source of truth for "how many days of each kind of data do we keep",
// which was previously scattered across ~6 files + Python daemons. This engine:
//   • catalogs every telemetry table (category, timestamp column, size, growth),
//   • enforces per-category retention with CHUNKED deletes (never locks the poller),
//   • WRITES THROUGH to the legacy daemon settings (syslog/netflow/poller/health)
//     so the existing collectors honor the same policy,
//   • previews freed space INSTANTLY (interpolation over indexed MIN/MAX ts),
//   • reclaims real disk (OPTIMIZE — a plain DELETE does NOT return .ibd space),
//   • molts (wipe telemetry, keep config) and self-manages to a size budget (autopilot).
// Companion: nm_vault_backup.php (Backup Vault). Cockpit: vault.php. Cron: cron_vault.php.
// Constraints honored: mysqli EXCEPTION mode → every op guarded; canonical UTC storage
// → cutoffs use UTC_TIMESTAMP(). RBAC perm: 'vault'.
// ─────────────────────────────────────────────────────────────────────────────

if (!defined('NM_VAULT_PRESETS')) define('NM_VAULT_PRESETS', 'lean,balanced,compliance');

// ── the managed-telemetry catalog ────────────────────────────────────────────
// category => [label, icon, setting_key(legacy daemon nm_settings key or null),
//              lean, balanced, compliance (default keep-days per preset),
//              tables => [ table => ts_col|'auto' ]]
if (!function_exists('nm_vault_categories')) {
    function nm_vault_categories(): array {
        return [
            'syslog'    => ['Syslog', 'fa-file-lines', 'syslog_retention_days', 7, 30, 365,
                            ['nm_syslog' => 'received_at']],
            'netflow'   => ['NetFlow', 'fa-chart-area', 'netflow_retention_days', 3, 14, 180,
                            ['nm_netflow_flows' => 'bucket', 'nm_netflow_alerts' => 'opened_at']],
            'devstats'  => ['Device & Port Stats', 'fa-gauge-high', 'retention_days', 7, 30, 180,
                            ['nm_device_stats' => 'recorded_at', 'nm_port_stats' => 'recorded_at']],
            'latency'   => ['Latency & Ping', 'fa-wave-square', null, 7, 30, 180,
                            ['nm_ping_stats' => 'recorded_at', 'nm_latency_samples' => 'sampled_at',
                             'nm_latency_alerts' => 'opened_at', 'nm_rt_samples' => 'auto']],
            'health'    => ['Predictive Health', 'fa-heart-pulse', 'health_retention_days', 10, 30, 180,
                            ['nm_health_samples' => 'recorded_at']],
            'events'    => ['Events & Logs', 'fa-list-ul', null, 5, 14, 90,
                            ['nm_lx_events' => 'created_at', 'nm_win_events' => 'created_at',
                             'container_logs' => 'log_ts', 'container_net_samples' => 'sampled_at',
                             'nm_rc_logs' => 'created_at', 'nm_poller_log' => 'auto',
                             'nm_notify_log' => 'auto', 'nm_aip_events' => 'created_at',
                             'nm_aip_sessions' => 'created_at', 'nm_heal_events' => 'auto',
                             'nm_wear_history' => 'recorded_at', 'nm_tplink_events' => 'auto']],
            'audit'     => ['Audit Trail', 'fa-clipboard-list', null, 30, 90, 730,
                            ['nm_audit_log' => 'ts']],
            'wireguard' => ['WireGuard Traffic', 'fa-shield-halved', null, 7, 30, 180,
                            ['nm_wg_peer_traffic' => 'ts']],
            'biosphere' => ['Service Biosphere', 'fa-circle-nodes', 'bio_sample_days', 5, 14, 90,
                            ['nm_bio_samples' => 'ts']],
            'datacore'  => ['Data Core', 'fa-database', null, 5, 14, 90,
                            ['nm_db_samples' => 'sampled_at', 'nm_db_repl' => 'auto', 'nm_dbobs_cache' => 'ts']],
            'gpu'       => ['GPU Telemetry', 'fa-microchip', null, 7, 30, 180,
                            ['nm_gpu_stats' => 'sampled_at']],
            'tplink'    => ['L2 Switch Samples', 'fa-ethernet', null, 5, 14, 90,
                            ['nm_tplink_samples' => 'ts']],
            'cluster'   => ['Federation History', 'fa-sitemap', null, 10, 30, 180,
                            ['nm_cluster_dev_history' => 'recorded_at', 'nm_cluster_rollups' => 'auto']],
            'security'  => ['Security Events', 'fa-user-shield', null, 30, 60, 730,
                            ['nm_decoy_events' => 'ts', 'nm_threat_actions' => 'auto']],
            'snapshots' => ['Config Snapshots', 'fa-camera', null, 30, 90, 365,
                            ['nm_mtfw_snapshots' => 'taken_at', 'nm_config_snapshots' => 'captured_at',
                             'nm_routing_snapshots' => 'taken_at']],
            'caches'    => ['Caches', 'fa-box-archive', null, 7, 30, 90,
                            ['nm_geoip_cache' => 'auto']],
        ];
    }
}

// ── schema + seed ─────────────────────────────────────────────────────────────
if (!function_exists('nm_vault_ensure')) {
    function nm_vault_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        if (!($conn instanceof mysqli)) return;
        try {
            $conn->query("CREATE TABLE IF NOT EXISTS nm_retention_policy (
                category VARCHAR(32) NOT NULL PRIMARY KEY,
                keep_days INT NOT NULL DEFAULT 30,
                enabled TINYINT(1) NOT NULL DEFAULT 1,
                last_pruned DATETIME NULL,
                last_freed_rows BIGINT NOT NULL DEFAULT 0,
                last_freed_bytes BIGINT NOT NULL DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
            $conn->query("CREATE TABLE IF NOT EXISTS nm_vault_size_history (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                sampled_at DATETIME NOT NULL,
                total_bytes BIGINT NOT NULL,
                KEY (sampled_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
            // seed each category: prefer an existing legacy daemon value, else the Balanced default
            foreach (nm_vault_categories() as $cat => $c) {
                $seed = (int)$c[4];                                  // balanced default
                if (!empty($c[2])) {                                 // legacy daemon setting present?
                    $r = $conn->query("SELECT setting_val v FROM nm_settings WHERE setting_key='" . $conn->real_escape_string($c[2]) . "'");
                    if ($r && ($x = $r->fetch_assoc()) && is_numeric($x['v'])) $seed = max(1, (int)$x['v']);
                }
                $st = $conn->prepare("INSERT IGNORE INTO nm_retention_policy (category,keep_days,enabled) VALUES (?,?,1)");
                $st->bind_param('si', $cat, $seed); $st->execute(); $st->close();
            }
        } catch (\Throwable $e) { /* best-effort */ }
    }
}

// ── setting helpers (vault-scoped) ────────────────────────────────────────────
if (!function_exists('nm_vault_get')) {
    function nm_vault_get($conn, string $k, $def = null) {
        try { $r = $conn->query("SELECT setting_val v FROM nm_settings WHERE setting_key='" . $conn->real_escape_string($k) . "'");
            if ($r && ($x = $r->fetch_assoc())) return $x['v']; } catch (\Throwable $e) {}
        return $def;
    }
    function nm_vault_set($conn, string $k, $v): void {
        try { $st = $conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES (?,?)
                                    ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
            $vs = (string)$v; $st->bind_param('ss', $k, $vs); $st->execute(); $st->close();
        } catch (\Throwable $e) {}
    }
}

// ── resolve a table's timestamp column (catalog map, else first datetime col) ─
if (!function_exists('nm_vault_ts_col')) {
    function nm_vault_ts_col($conn, string $table, string $hint = 'auto'): ?string {
        static $cache = [];
        if ($hint !== 'auto' && $hint !== '') return $hint;
        if (isset($cache[$table])) return $cache[$table] ?: null;
        $col = null;
        try {
            $db = $conn->query('SELECT DATABASE()')->fetch_row()[0];
            $st = $conn->prepare("SELECT COLUMN_NAME FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=? AND TABLE_NAME=? AND DATA_TYPE IN ('datetime','timestamp')
                ORDER BY FIELD(COLUMN_NAME,'received_at','recorded_at','sampled_at','ts','created_at',
                    'ran_at','log_ts','opened_at','taken_at','captured_at','bucket') DESC, ORDINAL_POSITION ASC
                LIMIT 1");
            $st->bind_param('ss', $db, $table); $st->execute();
            $r = $st->get_result(); if ($x = $r->fetch_row()) $col = $x[0]; $st->close();
        } catch (\Throwable $e) {}
        $cache[$table] = $col ?: '';
        return $col;
    }
}

// ── per-table physical size (information_schema; one cached query) ─────────────
if (!function_exists('nm_vault_table_sizes')) {
    function nm_vault_table_sizes($conn, bool $fresh = false): array {
        static $c = null; if ($c !== null && !$fresh) return $c; $c = [];
        try {
            $db = $conn->query('SELECT DATABASE()')->fetch_row()[0];
            $r = $conn->query("SELECT TABLE_NAME t, TABLE_ROWS rr, DATA_LENGTH+INDEX_LENGTH b
                               FROM information_schema.TABLES WHERE TABLE_SCHEMA='" . $conn->real_escape_string($db) . "'");
            while ($r && $x = $r->fetch_assoc()) $c[$x['t']] = ['rows' => (int)$x['rr'], 'bytes' => (int)$x['b']];
        } catch (\Throwable $e) {}
        return $c;
    }
}

// ── total DB size + budget/forecast ───────────────────────────────────────────
if (!function_exists('nm_vault_db_bytes')) {
    function nm_vault_db_bytes($conn): int {
        $t = 0; foreach (nm_vault_table_sizes($conn) as $s) $t += $s['bytes']; return $t;
    }
}

// ── policy rows (category => keep_days,enabled,last_*) ─────────────────────────
if (!function_exists('nm_vault_policies')) {
    function nm_vault_policies($conn): array {
        nm_vault_ensure($conn); $out = [];
        try { $r = $conn->query("SELECT * FROM nm_retention_policy");
            while ($r && $x = $r->fetch_assoc()) $out[$x['category']] = $x; } catch (\Throwable $e) {}
        return $out;
    }
}

// ── the big one: per-category stats + INSTANT freeable estimate ───────────────
// freeable rows are interpolated from indexed MIN/MAX(ts) + approx table_rows —
// no full scan, ~1ms per table. Precise deletion happens in nm_vault_prune().
if (!function_exists('nm_vault_stats')) {
    function nm_vault_stats($conn, array $override_days = []): array {
        nm_vault_ensure($conn);
        $sizes = nm_vault_table_sizes($conn);
        $pol   = nm_vault_policies($conn);
        $cats  = nm_vault_categories();
        $out = ['categories' => [], 'total_bytes' => nm_vault_db_bytes($conn),
                'freeable_bytes' => 0, 'freeable_rows' => 0];
        foreach ($cats as $cat => $c) {
            $keep = isset($override_days[$cat]) ? max(1, (int)$override_days[$cat])
                    : (int)($pol[$cat]['keep_days'] ?? $c[4]);
            $enabled = (int)($pol[$cat]['enabled'] ?? 1);
            $catBytes = 0; $catRows = 0; $frRows = 0; $frBytes = 0; $oldest = null; $tbls = [];
            foreach ($c[6] as $table => $tsHint) {
                if (!isset($sizes[$table])) continue;
                $rows = $sizes[$table]['rows']; $bytes = $sizes[$table]['bytes'];
                $catBytes += $bytes; $catRows += $rows;
                $col = nm_vault_ts_col($conn, $table, $tsHint);
                $tOld = null; $fr = 0; $frB = 0;
                if ($col && $rows > 0) {
                    try {
                        $mm = $conn->query("SELECT MIN(`$col`) a, MAX(`$col`) b FROM `$table`")->fetch_assoc();
                        $min = $mm['a'] ?? null; $max = $mm['b'] ?? null; $tOld = $min;
                        if ($min && $max) {
                            $minT = strtotime($min.' UTC'); $maxT = strtotime($max.' UTC');
                            $cut  = time() - $keep * 86400;   // approx; precise on prune (UTC_TIMESTAMP)
                            $span = max(1, $maxT - $minT);
                            $frac = $cut <= $minT ? 0 : ($cut >= $maxT ? 1 : ($cut - $minT) / $span);
                            $fr   = (int)round($rows * $frac);
                            $avg  = $rows > 0 ? $bytes / $rows : 0;
                            $frB  = (int)round($fr * $avg);
                        }
                    } catch (\Throwable $e) {}
                }
                if ($tOld && (!$oldest || $tOld < $oldest)) $oldest = $tOld;
                $frRows += $fr; $frBytes += $frB;
                $tbls[$table] = ['rows' => $rows, 'bytes' => $bytes, 'ts_col' => $col, 'oldest' => $tOld, 'freeable_rows' => $fr];
            }
            $out['categories'][$cat] = [
                'label' => $c[0], 'icon' => $c[1], 'setting_key' => $c[2],
                'lean' => $c[3], 'balanced' => $c[4], 'compliance' => $c[5],
                'keep_days' => $keep, 'enabled' => $enabled,
                'bytes' => $catBytes, 'rows' => $catRows, 'oldest' => $oldest,
                'freeable_rows' => $frRows, 'freeable_bytes' => $frBytes,
                'last_pruned' => $pol[$cat]['last_pruned'] ?? null, 'tables' => $tbls,
            ];
            $out['freeable_bytes'] += $frBytes; $out['freeable_rows'] += $frRows;
        }
        return $out;
    }
}

// ── cached stats (MIN/MAX over ~30 tables ≈ 2s; cache for instant page loads) ─
// Also emits per-category min_ts/max_ts/rows/bytes so the cockpit slider can recompute
// "freeable" entirely in the browser (zero round-trips while dragging).
if (!function_exists('nm_vault_stats_cached')) {
    function nm_vault_stats_cached($conn, int $maxAgeSec = 600, bool $force = false): array {
        if (!$force) {
            $at = (int)nm_vault_get($conn, 'vault_stats_at', 0);
            $js = nm_vault_get($conn, 'vault_stats_json', '');
            if ($js && (time() - $at) < $maxAgeSec) { $d = json_decode($js, true); if (is_array($d)) { $d['cached'] = true; return $d; } }
        }
        $s = nm_vault_stats($conn);
        // attach min/max epoch per category for client-side interpolation
        foreach ($s['categories'] as $cat => &$c) {
            $minT = null; $maxT = null;
            foreach ($c['tables'] as $t => $td) {
                if (!empty($td['oldest'])) { $e = strtotime($td['oldest'].' UTC'); if ($minT === null || $e < $minT) $minT = $e; }
            }
            // recompute a category max from the same MIN/MAX we already have per table isn't stored;
            // approximate max as "now" (data is live) — good enough for slider interpolation.
            $c['min_ts'] = $minT; $c['max_ts'] = time();
        }
        unset($c);
        try { nm_vault_set($conn, 'vault_stats_json', json_encode($s)); nm_vault_set($conn, 'vault_stats_at', time()); } catch (\Throwable $e) {}
        $s['cached'] = false;
        return $s;
    }
}

// ── set a category's retention (+ write through to the legacy daemon setting) ─
if (!function_exists('nm_vault_set_retention')) {
    function nm_vault_set_retention($conn, string $category, int $days, ?int $enabled = null): bool {
        nm_vault_ensure($conn);
        $cats = nm_vault_categories(); if (!isset($cats[$category])) return false;
        $days = max(1, min(3650, $days));
        try {
            if ($enabled === null) {
                $st = $conn->prepare("UPDATE nm_retention_policy SET keep_days=? WHERE category=?");
                $st->bind_param('is', $days, $category);
            } else {
                $en = $enabled ? 1 : 0;
                $st = $conn->prepare("UPDATE nm_retention_policy SET keep_days=?, enabled=? WHERE category=?");
                $st->bind_param('iis', $days, $en, $category);
            }
            $st->execute(); $st->close();
            // write-through so nm_syslog.py / nm_netflow.py / nm_poller.py / health honor it
            if (!empty($cats[$category][2])) nm_vault_set($conn, $cats[$category][2], $days);
            return true;
        } catch (\Throwable $e) { return false; }
    }
}
if (!function_exists('nm_vault_apply_preset')) {
    function nm_vault_apply_preset($conn, string $preset): bool {
        $i = ['lean' => 3, 'balanced' => 4, 'compliance' => 5][$preset] ?? null;
        if ($i === null) return false;
        foreach (nm_vault_categories() as $cat => $c) nm_vault_set_retention($conn, $cat, (int)$c[$i]);
        nm_vault_set($conn, 'vault_preset', $preset);
        return true;
    }
}

// ── the enforced prune — CHUNKED, never a giant lock ──────────────────────────
// $opts: category(null=all), dry(bool), chunk(rows/batch), max_seconds(overall budget)
if (!function_exists('nm_vault_prune')) {
    function nm_vault_prune($conn, array $opts = []): array {
        nm_vault_ensure($conn);
        $only  = $opts['category'] ?? null;
        $dry   = !empty($opts['dry']);
        $chunk = max(500, min(50000, (int)($opts['chunk'] ?? 5000)));
        $deadline = microtime(true) + max(5, (int)($opts['max_seconds'] ?? 300));
        $pol  = nm_vault_policies($conn);
        $rep  = ['freed_rows' => 0, 'freed_bytes_est' => 0, 'tables' => [], 'dry' => $dry, 'stopped_early' => false];
        $sizes = nm_vault_table_sizes($conn);
        foreach (nm_vault_categories() as $cat => $c) {
            if ($only && $cat !== $only) continue;
            if (empty($pol[$cat]['enabled'])) continue;
            $keep = (int)($pol[$cat]['keep_days'] ?? $c[4]);
            $catFreed = 0;
            foreach ($c[6] as $table => $tsHint) {
                if (!isset($sizes[$table])) continue;
                $col = nm_vault_ts_col($conn, $table, $tsHint); if (!$col) continue;
                $avg = $sizes[$table]['rows'] > 0 ? $sizes[$table]['bytes'] / $sizes[$table]['rows'] : 0;
                $tblFreed = 0;
                try {
                    if ($dry) {
                        $q = $conn->query("SELECT COUNT(*) c FROM `$table` WHERE `$col` < (UTC_TIMESTAMP() - INTERVAL $keep DAY)");
                        $tblFreed = (int)($q ? $q->fetch_assoc()['c'] : 0);
                    } else {
                        do {
                            $conn->query("DELETE FROM `$table` WHERE `$col` < (UTC_TIMESTAMP() - INTERVAL $keep DAY) LIMIT $chunk");
                            $aff = $conn->affected_rows; $tblFreed += $aff;
                            if ($aff >= $chunk) usleep(60000);   // 60ms breather → never starve the poller
                        } while ($aff >= $chunk && microtime(true) < $deadline);
                    }
                } catch (\Throwable $e) { $rep['tables'][$table] = 'error: ' . $e->getMessage(); continue; }
                if ($tblFreed > 0) {
                    $rep['tables'][$table] = $tblFreed;
                    $rep['freed_rows'] += $tblFreed; $catFreed += $tblFreed;
                    $rep['freed_bytes_est'] += (int)round($tblFreed * $avg);
                }
                if (microtime(true) >= $deadline) { $rep['stopped_early'] = true; break; }
            }
            if (!$dry && $catFreed > 0) {
                try { $st = $conn->prepare("UPDATE nm_retention_policy SET last_pruned=NOW(), last_freed_rows=?, last_freed_bytes=? WHERE category=?");
                    $fb = (int)round($catFreed * 1); $st->bind_param('iis', $catFreed, $fb, $cat); $st->execute(); $st->close(); } catch (\Throwable $e) {}
            }
            if ($rep['stopped_early']) break;
        }
        return $rep;
    }
}

// ── reclaim real disk (OPTIMIZE — DELETE alone doesn't shrink the .ibd) ───────
if (!function_exists('nm_vault_reclaim')) {
    function nm_vault_reclaim($conn, array $tables): array {
        $rep = ['tables' => []];
        $before = nm_vault_table_sizes($conn);
        foreach ($tables as $t) {
            if (!isset($before[$t])) { $rep['tables'][$t] = 'unknown'; continue; }
            try { $conn->query("OPTIMIZE TABLE `$t`"); $rep['tables'][$t] = 'optimized'; }
            catch (\Throwable $e) { $rep['tables'][$t] = 'error: ' . $e->getMessage(); }
        }
        return $rep;
    }
}

// ── one-shot cleanup: delete older than N days (a category or all) ────────────
if (!function_exists('nm_vault_cleanup_older')) {
    function nm_vault_cleanup_older($conn, ?string $category, int $days, bool $dry = false): array {
        $days = max(1, min(3650, $days));   // never 0 — that would wipe the whole category (use Molt for that)
        // temporarily treat as a prune with an explicit keep window (don't persist policy)
        $sizes = nm_vault_table_sizes($conn); $rep = ['freed_rows' => 0, 'tables' => [], 'dry' => $dry];
        foreach (nm_vault_categories() as $cat => $c) {
            if ($category && $cat !== $category) continue;
            foreach ($c[6] as $table => $tsHint) {
                if (!isset($sizes[$table])) continue;
                $col = nm_vault_ts_col($conn, $table, $tsHint); if (!$col) continue;
                try {
                    if ($dry) { $q = $conn->query("SELECT COUNT(*) c FROM `$table` WHERE `$col` < (UTC_TIMESTAMP() - INTERVAL $days DAY)");
                        $rep['tables'][$table] = (int)($q ? $q->fetch_assoc()['c'] : 0); $rep['freed_rows'] += $rep['tables'][$table]; }
                    else { $n = 0; do { $conn->query("DELETE FROM `$table` WHERE `$col` < (UTC_TIMESTAMP() - INTERVAL $days DAY) LIMIT 5000");
                        $a = $conn->affected_rows; $n += $a; if ($a >= 5000) usleep(60000); } while ($a >= 5000);
                        if ($n) { $rep['tables'][$table] = $n; $rep['freed_rows'] += $n; } }
                } catch (\Throwable $e) { $rep['tables'][$table] = 'error'; }
            }
        }
        return $rep;
    }
}

// ── MOLT: wipe ALL telemetry, KEEP config (fast TRUNCATE → reclaims disk) ──────
// The caller MUST take a backup first (page/cron orchestrates via nm_vault_backup).
if (!function_exists('nm_vault_molt')) {
    function nm_vault_molt($conn): array {
        $rep = ['truncated' => [], 'errors' => [], 'kept' => ['audit','security']];
        $sizes = nm_vault_table_sizes($conn);
        foreach (nm_vault_categories() as $cat => $c) {
            if (in_array($cat, ['audit','security'], true)) continue;   // preserve the audit + security trail through a molt
            foreach ($c[6] as $table => $_) {
                if (!isset($sizes[$table])) continue;
                try { $conn->query("TRUNCATE TABLE `$table`"); $rep['truncated'][] = $table; }
                catch (\Throwable $e) {
                    // TRUNCATE can fail under FK; fall back to a delete
                    try { $conn->query("DELETE FROM `$table`"); $rep['truncated'][] = $table . ' (deleted)'; }
                    catch (\Throwable $e2) { $rep['errors'][$table] = $e2->getMessage(); }
                }
            }
        }
        return $rep;
    }
}

// ── size history + growth/day + forecast to a budget ──────────────────────────
if (!function_exists('nm_vault_record_size')) {
    function nm_vault_record_size($conn): void {
        nm_vault_ensure($conn);
        try { $b = nm_vault_db_bytes($conn);
            $st = $conn->prepare("INSERT INTO nm_vault_size_history (sampled_at,total_bytes) VALUES (NOW(),?)");
            $st->bind_param('i', $b); $st->execute(); $st->close();
            $conn->query("DELETE FROM nm_vault_size_history WHERE sampled_at < (NOW() - INTERVAL 180 DAY)");
        } catch (\Throwable $e) {}
    }
    function nm_vault_growth_per_day($conn): float {
        try {
            $r = $conn->query("SELECT total_bytes b, sampled_at s FROM nm_vault_size_history ORDER BY id ASC LIMIT 1");
            $first = $r ? $r->fetch_assoc() : null;
            if ($first) {
                $days = max(0.5, (time() - strtotime($first['s'].' UTC')) / 86400);
                $delta = nm_vault_db_bytes($conn) - (int)$first['b'];
                if ($days >= 1) return $delta / $days;
            }
        } catch (\Throwable $e) {}
        // fallback: estimate from last-24h ingestion across managed tables
        $bytesDay = 0; $sizes = nm_vault_table_sizes($conn);
        foreach (nm_vault_categories() as $c) foreach ($c[6] as $t => $hint) {
            if (!isset($sizes[$t]) || $sizes[$t]['rows'] < 1) continue;
            $col = nm_vault_ts_col($conn, $t, $hint); if (!$col) continue;
            try { $q = $conn->query("SELECT COUNT(*) c FROM `$t` WHERE `$col` > (UTC_TIMESTAMP() - INTERVAL 1 DAY)");
                $n = (int)($q ? $q->fetch_assoc()['c'] : 0); $avg = $sizes[$t]['bytes'] / $sizes[$t]['rows'];
                $bytesDay += $n * $avg; } catch (\Throwable $e) {}
        }
        return (float)$bytesDay;
    }
    function nm_vault_forecast($conn): array {
        $cur = nm_vault_db_bytes($conn);
        $g   = nm_vault_growth_per_day($conn);
        $budgetGb = (float)nm_vault_get($conn, 'vault_size_budget_gb', 0);
        $budget = $budgetGb > 0 ? (int)round($budgetGb * 1073741824) : 0;
        $daysToBudget = ($budget > 0 && $g > 0 && $cur < $budget) ? ($budget - $cur) / $g : null;
        return ['current_bytes' => $cur, 'growth_per_day' => $g, 'budget_bytes' => $budget,
                'over_budget' => $budget > 0 && $cur > $budget,
                'days_to_budget' => $daysToBudget !== null ? round($daysToBudget, 1) : null,
                'projected_30d' => $cur + $g * 30];
    }
}

// ── Size-Budget Autopilot: keep the DB under vault_size_budget_gb automatically ─
// Nightly (cron): if over budget, step retention DOWN on the biggest categories
// (respecting a per-category floor) and prune, until under budget or floors reached.
if (!function_exists('nm_vault_autopilot')) {
    function nm_vault_autopilot($conn, int $maxSeconds = 200): array {
        nm_vault_ensure($conn);
        $on = (int)nm_vault_get($conn, 'vault_autopilot', 0);
        $budgetGb = (float)nm_vault_get($conn, 'vault_size_budget_gb', 0);
        if (!$on || $budgetGb <= 0) return ['ran' => false, 'reason' => 'disabled'];
        $budget = (int)round($budgetGb * 1073741824);
        $reclaim = (int)nm_vault_get($conn, 'vault_autopilot_reclaim', 0);   // OPTIMIZE to truly shrink .ibd
        $cats = nm_vault_categories();
        // Drive the STEADY-STATE footprint (total − freeable_at_retention) under budget — this responds
        // monotonically to retention changes and is independent of InnoDB's lazy allocated size, so we
        // never over-trim. Decide all retention values first, then prune once (+optional reclaim).
        // snapshot base stats ONCE (the expensive MIN/MAX queries), then interpolate freeable
        // for candidate retention values purely in memory — no re-querying inside the loop.
        $base = nm_vault_stats($conn);
        $now = time();
        $freeAt = function(array $s, int $days) use ($now): int {
            $fb = 0;
            foreach ($s['tables'] as $td) {
                if (empty($td['oldest']) || $td['rows'] < 1) continue;
                $minT = strtotime($td['oldest'].' UTC'); $span = max(1, $now - $minT);
                $cut = $now - $days * 86400;
                $frac = $cut <= $minT ? 0 : ($cut >= $now ? 1 : ($cut - $minT) / $span);
                $avg = $td['bytes'] / max(1, $td['rows']);
                $fb += (int)round($td['rows'] * $frac * $avg);
            }
            return $fb;
        };
        $keepNow = []; foreach ($base['categories'] as $cat => $s) $keepNow[$cat] = (int)$s['keep_days'];
        $override = []; $actions = []; $guard = 0;
        while ($guard++ < 60) {
            $footprint = $base['total_bytes'];
            foreach ($base['categories'] as $cat => $s) $footprint -= $freeAt($s, $override[$cat] ?? $keepNow[$cat]);
            if ($footprint <= $budget) break;
            $best = null; $bestBytes = -1;
            foreach ($base['categories'] as $cat => $s) {
                if (!$s['enabled']) continue;
                $floor = (int)$cats[$cat][3];               // lean = floor
                if (($override[$cat] ?? $keepNow[$cat]) <= $floor) continue;
                if ($s['bytes'] > $bestBytes) { $bestBytes = $s['bytes']; $best = $cat; }
            }
            if ($best === null) { $actions[] = 'all categories at their floor — cannot trim further'; break; }
            $cur = $override[$best] ?? $keepNow[$best];
            $override[$best] = max((int)$cats[$best][3], (int)floor($cur * 0.7) - 1);
        }
        // apply the decided retention + one prune pass
        foreach ($override as $cat => $days) { nm_vault_set_retention($conn, $cat, $days); $actions[] = "$cat → {$days}d"; }
        $pr = ['freed_rows' => 0];
        if ($override) {
            $pr = nm_vault_prune($conn, ['max_seconds' => $maxSeconds]);
            if ($reclaim) { $tbls = []; foreach (array_keys($override) as $cat) foreach ($cats[$cat][6] as $t => $_) $tbls[] = $t;
                            nm_vault_reclaim($conn, $tbls); }
        }
        nm_vault_table_sizes($conn, true);
        $fc = nm_vault_forecast($conn);
        return ['ran' => true, 'changed' => count($override), 'actions' => $actions,
                'freed_rows' => $pr['freed_rows'], 'over_budget' => $fc['over_budget'],
                'current_bytes' => $fc['current_bytes'], 'budget_bytes' => $budget, 'reclaim' => (bool)$reclaim];
    }
}
