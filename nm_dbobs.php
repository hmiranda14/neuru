<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Data Core Observatory engine (holographic DB twin). A THIN assembler over
// nm_dbmon.php: for every configured database it gathers vitals (probe), live pressure
// (slow/locks/procs), replication health, the table I/O heatmap (the "galaxy"), top-query
// no-index count, and pending AI advice — into ONE 3D scene payload. Read-mostly.
//
// Constraints: live DB connects are heavy, so the whole scene is cached in nm_dbobs_cache for a
// few seconds (best-effort). Each target is assembled inside its own try/catch so one dead/slow
// DB never takes down the scene. RBAC perm: 'dbobs'. Secrets decrypt under www-data (page/cron).
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_dbobs_ensure')) {

require_once __DIR__ . '/nm_dbmon.php';

function nm_dbobs_ensure($conn): void {
    static $done = false; if ($done) return; $done = true;
    // dedicated cache row (nm_settings.setting_val may be short on some installs; MEDIUMTEXT here is safe)
    $conn->query("CREATE TABLE IF NOT EXISTS nm_dbobs_cache (
        id TINYINT PRIMARY KEY, payload MEDIUMTEXT NULL, ts INT NOT NULL DEFAULT 0
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $conn->query("INSERT IGNORE INTO role_profiles (role_name, button_key, enabled) VALUES ('admin','dbobs',1)");
}

function nm_dbobs_settings($conn): array {
    $get = function($k, $d) use ($conn) {
        $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='" . $conn->real_escape_string($k) . "' LIMIT 1");
        if ($r && $r->num_rows) { $v = $r->fetch_assoc()['setting_val']; if ($v !== '' && $v !== null) return $v; }
        return $d;
    };
    return [
        'poll_sec'   => max(3, (int)$get('dbobs_poll_sec', '6')),
        'cache_sec'  => max(2, (int)$get('dbobs_cache_sec', '5')),
        'top_tables' => max(6, min(140, (int)$get('dbobs_top_tables', '54'))),
    ];
}

// health level per DB → reactor color (every level maps to a TRUE condition)
function nm_dbobs_level(array $db): string {
    if (empty($db['ok']))                                   return 'critical';   // unreachable
    if (($db['locks'] ?? 0) > 0)                            return 'critical';   // a query frozen behind a lock
    $sat = $db['vitals']['saturation'] ?? null;
    $repl = $db['repl'] ?? null;
    $replBad = $repl && !empty($repl['is_replica']) && (empty($repl['io']) || empty($repl['sql']));
    if (($db['slow'] ?? 0) >= 3 || ($sat !== null && $sat >= 90) || $replBad) return 'sick';
    $behind = ($repl && $repl['behind'] !== null) ? (int)$repl['behind'] : 0;
    if (($db['slow'] ?? 0) >= 1 || ($sat !== null && $sat >= 70) || ($db['no_index'] ?? 0) > 0 || $behind > 30) return 'stressed';
    return 'healthy';
}

// live assembly (no cache) — one reactor per DB + replication conduits
function nm_dbobs_build($conn): array {
    $set = nm_dbobs_settings($conn);
    $out = ['ok' => true, 'ts' => date('Y-m-d H:i:s'), 'dbs' => [], 'links' => []];
    $targets = nm_db_targets($conn);
    $byId = []; foreach ($targets as $t) $byId[(int)$t['id']] = $t;

    foreach ($targets as $t) {
        if (empty($t['enabled'])) continue;
        $id = (int)$t['id'];
        $db = ['id' => $id, 'name' => $t['display_name'], 'engine' => $t['engine'], 'role' => $t['role'] ?? 'standalone',
               'host' => $t['host'], 'status' => 'unknown', 'ok' => 0, 'vitals' => [], 'top_tables' => [],
               'slow' => 0, 'locks' => 0, 'procs' => 0, 'no_index' => 0, 'queries' => 0, 'advice' => 0, 'drift' => 0, 'repl' => null];
        try {
            $full = nm_db_target($conn, $id);
            if (($full['transport'] ?? 'direct') === 'direct') {
                $caps = nm_db_transport_caps($full['engine']);
                if (!$caps['direct']) throw new \RuntimeException($caps['direct_reason']);
            }
            $mon = nm_db_monitor($conn, $full);
            $p = $mon->probe();
            if (!empty($p['ok'])) {
                $db['ok'] = 1; $db['status'] = 'ok';
                $conns = (int)($p['connections'] ?? 0); $max = (int)($p['max_connections'] ?? 0);
                $db['vitals'] = ['version' => (string)($p['version'] ?? ''), 'uptime_s' => (int)($p['uptime_s'] ?? 0),
                    'connections' => $conns, 'max_connections' => $max, 'saturation' => $max > 0 ? round($conns / $max * 100, 1) : null,
                    'threads_running' => (int)($p['threads_running'] ?? 0),
                    'db_bytes' => isset($p['db_bytes']) ? (float)$p['db_bytes'] : null,
                    'db_count' => isset($p['db_count']) ? (int)$p['db_count'] : null];
            }
            try { $lv = $mon->live(); $db['slow'] = count($lv['slow'] ?? []); $db['locks'] = count($lv['locks'] ?? []); $db['procs'] = count($lv['processlist'] ?? []); } catch (\Throwable $e) {}
            try { $rp = $mon->replication(); $db['repl'] = ['is_replica' => !empty($rp['is_replica']), 'io' => !empty($rp['io_running']),
                    'sql' => !empty($rp['sql_running']), 'behind' => $rp['seconds_behind'] ?? null, 'replicas' => $rp['replicas_connected'] ?? null,
                    'err' => mb_substr((string)($rp['last_error'] ?? ''), 0, 160)]; } catch (\Throwable $e) {}
            try { $tq = $mon->topQueries(); $ni = 0; foreach (($tq['queries'] ?? []) as $q) if (!empty($q['no_index'])) $ni++; $db['no_index'] = $ni; $db['queries'] = count($tq['queries'] ?? []); } catch (\Throwable $e) {}
            try { $hm = $mon->heatmap(); $tb = $hm['tables'] ?? [];
                usort($tb, fn($a, $b) => (($b['reads'] + $b['writes']) <=> ($a['reads'] + $a['writes'])));
                $db['top_tables'] = array_map(fn($x) => ['name' => $x['name'], 'reads' => (float)$x['reads'], 'writes' => (float)$x['writes'],
                    'rows' => (int)$x['rows'], 'bytes' => (float)$x['bytes']], array_slice($tb, 0, $set['top_tables']));
            } catch (\Throwable $e) {}
            try { $db['advice'] = count(nm_db_advice_list($conn, $id, 'proposed')); } catch (\Throwable $e) {}
            try { $dr = $conn->query("SELECT COUNT(*) c FROM nm_db_schema_drift WHERE target_id=$id AND detected_at > (NOW()-INTERVAL 7 DAY)"); if ($dr) $db['drift'] = (int)$dr->fetch_assoc()['c']; } catch (\Throwable $e) {}
        } catch (\Throwable $e) {
            $db['status'] = (($t['last_status'] ?? '') === 'ok') ? 'stale' : 'error';
            $db['error'] = mb_substr($e->getMessage(), 0, 160);
        }
        $db['level'] = nm_dbobs_level($db);
        // reactor viz knobs — all from REAL vitals
        $tr = $db['vitals']['threads_running'] ?? 0; $sat = $db['vitals']['saturation'] ?? null;
        $bytes = $db['vitals']['db_bytes'] ?? null;
        // Core scale grows with on-disk size on a log scale (1 MB→0, ~1 TB→1) so a
        // tiny DB and a huge DB are visibly different reactors, without dwarfing anything.
        $sizeScale = $bytes !== null && $bytes > 0
            ? max(0, min(1, (log10($bytes) - 6) / 6)) : 0;
        $db['viz'] = [
            'pulse'  => min(1, $tr / 12 + ($db['slow'] ?? 0) * 0.12),          // core beats faster under running/slow load
            'load'   => $sat !== null ? min(1, $sat / 100) : 0,                // connection-pool ring fill
            'slow'   => min(1, ($db['slow'] ?? 0) / 6),                        // red comet frequency
            'frozen' => ($db['locks'] ?? 0) > 0 ? 1 : 0,                       // lock → icy crackle
            'size'   => round($sizeScale, 3),                                  // core radius (on-disk size, log-scaled)
            'down'   => empty($db['ok']) ? 1 : 0,
        ];
        $out['dbs'][] = $db;
        // replication conduit master → this replica
        if (($t['role'] ?? '') === 'replica' && !empty($t['replica_of']) && isset($byId[(int)$t['replica_of']])) {
            $out['links'][] = ['from' => (int)$t['replica_of'], 'to' => $id,
                'behind' => $db['repl']['behind'] ?? null, 'io' => $db['repl']['io'] ?? true, 'sql' => $db['repl']['sql'] ?? true];
        }
    }
    // fleet rollup for the HUD
    $conns = 0; $slow = 0; $locks = 0; $up = 0; $down = 0; $replOk = 0; $replBad = 0;
    foreach ($out['dbs'] as $d) {
        if ($d['ok']) $up++; else $down++;
        $conns += (int)($d['vitals']['connections'] ?? 0);
        $slow += (int)($d['slow'] ?? 0); $locks += (int)($d['locks'] ?? 0);
        if (!empty($d['repl']['is_replica'])) { if (!empty($d['repl']['io']) && !empty($d['repl']['sql'])) $replOk++; else $replBad++; }
    }
    $out['hud'] = ['dbs' => count($out['dbs']), 'up' => $up, 'down' => $down, 'connections' => $conns,
                   'slow' => $slow, 'locks' => $locks, 'repl_ok' => $replOk, 'repl_bad' => $replBad];
    return $out;
}

// cached scene (multiple viewers / fast polls share one live build)
function nm_dbobs_scene($conn, bool $force = false): array {
    nm_dbobs_ensure($conn);
    $set = nm_dbobs_settings($conn);
    if (!$force) {
        try {
            $r = $conn->query("SELECT payload, ts FROM nm_dbobs_cache WHERE id=1 LIMIT 1");
            if ($r && $r->num_rows) { $row = $r->fetch_assoc();
                if ((time() - (int)$row['ts']) < $set['cache_sec'] && $row['payload']) {
                    $j = json_decode($row['payload'], true);
                    if (is_array($j)) { $j['cached'] = true; return $j; }
                } }
        } catch (\Throwable $e) {}
    }
    $scene = nm_dbobs_build($conn);
    try {
        $j = json_encode($scene); $now = time();
        $st = $conn->prepare("INSERT INTO nm_dbobs_cache (id,payload,ts) VALUES (1,?,?)
                              ON DUPLICATE KEY UPDATE payload=VALUES(payload), ts=VALUES(ts)");
        $st->bind_param('si', $j, $now); $st->execute(); $st->close();
    } catch (\Throwable $e) { /* best-effort cache — never let it abort the live scene */ }
    return $scene;
}

// per-DB dossier (click a reactor) — reuses the Data Core monitor for a live drill-down
function nm_dbobs_detail($conn, int $id): array {
    nm_dbobs_ensure($conn);
    $t = nm_db_target($conn, $id);
    if (!$t) return ['ok' => false, 'error' => 'database not found'];
    $out = ['ok' => true, 'db' => ['id' => $id, 'name' => $t['display_name'], 'engine' => $t['engine'], 'role' => $t['role'] ?? 'standalone',
            'host' => $t['host'], 'transport' => $t['transport'] ?? 'direct'], 'ts' => date('Y-m-d H:i:s')];
    try {
        if (($t['transport'] ?? 'direct') === 'direct') { $caps = nm_db_transport_caps($t['engine']); if (!$caps['direct']) throw new \RuntimeException($caps['direct_reason']); }
        $mon = nm_db_monitor($conn, $t);
        $p = $mon->probe();
        $out['probe'] = $p;
        try { $lv = $mon->live(); $out['processlist'] = array_slice($lv['processlist'] ?? [], 0, 12);
            $out['slow'] = array_slice($lv['slow'] ?? [], 0, 10); $out['locks'] = $lv['locks'] ?? []; } catch (\Throwable $e) {}
        try { $out['replication'] = $mon->replication(); } catch (\Throwable $e) {}
        try { $tq = $mon->topQueries(); $out['top_queries'] = array_slice($tq['queries'] ?? [], 0, 8); } catch (\Throwable $e) {}
        try { $hm = $mon->heatmap(); $tb = $hm['tables'] ?? []; usort($tb, fn($a, $b) => (($b['reads'] + $b['writes']) <=> ($a['reads'] + $a['writes']))); $out['top_tables'] = array_slice($tb, 0, 12); } catch (\Throwable $e) {}
    } catch (\Throwable $e) { $out['error'] = mb_substr($e->getMessage(), 0, 200); }
    try { $out['advice'] = nm_db_advice_list($conn, $id, 'proposed'); } catch (\Throwable $e) { $out['advice'] = []; }
    // sparkline trend from stored samples (cron_dbmon)
    $trend = [];
    $r = $conn->query("SELECT connections, threads_running, slow, blocked FROM nm_db_samples WHERE target_id=$id ORDER BY id DESC LIMIT 60");
    while ($r && $x = $r->fetch_assoc()) $trend[] = $x;
    $out['trend'] = array_reverse($trend);
    return $out;
}

} // end function_exists guard
