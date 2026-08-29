<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Incident Correlation Engine (AIOps).
//
//   The portal's alerts live siloed in many tables (node-down, container errors,
//   config drift, NetFlow bandwidth, Smokeping latency, container-net, AI
//   insights). This engine COLLECTS them all as normalized "signals", then
//   CORRELATES them into a small number of INCIDENTS:
//     • signals on the same node (and its downstream dependents via
//       nm_nodes.gateway_node_id) fold into ONE incident;
//     • each incident gets a probable ROOT CAUSE (priority heuristic — a node
//       being down outranks the latency/bandwidth/container symptoms it causes)
//       and an IMPACT (the affected entities);
//     • lifecycle: open → acknowledged → resolved, auto-resolving when every
//       signal clears.
//
//   Turns "50 alerts" into "1 incident: CORE-ROUTER down — 6 related signals".
//   Driven every minute by cron_incidents.php.
// ─────────────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/nm_audit.php';
if (is_file(__DIR__ . '/nm_maintenance.php')) require_once __DIR__ . '/nm_maintenance.php';

if (!function_exists('nm_inc_ensure')) {
    function nm_inc_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        if (!($conn instanceof mysqli)) return;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_incidents (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            corr_key VARCHAR(120) NOT NULL UNIQUE,
            title VARCHAR(255) NOT NULL,
            severity VARCHAR(10) NOT NULL DEFAULT 'warning',
            status VARCHAR(14) NOT NULL DEFAULT 'open',     -- open | acknowledged | resolved
            root_source VARCHAR(20) DEFAULT NULL,
            root_entity VARCHAR(160) DEFAULT NULL,
            root_host VARCHAR(160) DEFAULT NULL,
            root_node_id INT DEFAULT NULL,
            signal_count INT NOT NULL DEFAULT 0,
            impact_count INT NOT NULL DEFAULT 0,
            impact TEXT,
            opened_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            acked_by VARCHAR(60) DEFAULT NULL,
            acked_at DATETIME DEFAULT NULL,
            resolved_at DATETIME DEFAULT NULL,
            KEY idx_status (status), KEY idx_sev (severity)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_incident_signals (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            incident_id BIGINT NOT NULL,
            fingerprint VARCHAR(160) NOT NULL UNIQUE,
            source VARCHAR(20) NOT NULL,
            severity VARCHAR(10) NOT NULL,
            entity VARCHAR(160) DEFAULT NULL,
            node_id INT DEFAULT NULL,
            title VARCHAR(400) DEFAULT NULL,
            detail TEXT,
            link VARCHAR(200) DEFAULT NULL,
            status VARCHAR(10) NOT NULL DEFAULT 'active',    -- active | cleared
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            cleared_at DATETIME DEFAULT NULL,
            KEY idx_inc (incident_id), KEY idx_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // 'muted' incidents (ignored recurring ones): keep who/when. Idempotent add.
        foreach (['muted_by'=>"muted_by VARCHAR(60) DEFAULT NULL", 'muted_at'=>"muted_at DATETIME DEFAULT NULL", 'root_host'=>"root_host VARCHAR(160) DEFAULT NULL AFTER root_entity"] as $c=>$ddl) {
            $r = $conn->query("SHOW COLUMNS FROM nm_incidents LIKE '{$c}'");
            if (!$r || $r->num_rows === 0) @$conn->query("ALTER TABLE nm_incidents ADD COLUMN {$ddl}");
        }
    }

    function nm_inc_norm_sev(?string $s): string {
        $s = strtolower(trim((string)$s));
        if (in_array($s, ['critical','crit','fatal','error','failed','down','emergency','alert'], true)) return 'critical';
        if (in_array($s, ['warning','warn','high'], true)) return 'warning';
        return $s === 'critical' ? 'critical' : ($s === 'info' ? 'info' : 'warning');
    }
    function _inc_sev_rank($s){ return ['critical'=>3,'warning'=>2,'info'=>1][$s] ?? 1; }

    // Make any source-provided text (container logs, DB errors, AI summaries — arbitrary charsets)
    // SAFE to store. A byte-truncated multi-byte char or mojibake byte would make MySQL reject the
    // whole row with "Incorrect string value" → which used to THROW mid-correlate and skip the
    // auto-resolve step at the end → incidents never cleared → ZOMBIE "still down" for weeks. So:
    // (1) drop invalid/half UTF-8 sequences, (2) char-safe truncate (never split a multi-byte char).
    function nm_inc_clean($s, int $max = 2000): string {
        $s = (string)$s;
        $c = @iconv('UTF-8', 'UTF-8//IGNORE', $s);
        if ($c !== false) $s = $c;
        return function_exists('mb_substr') ? mb_substr($s, 0, $max, 'UTF-8') : substr($s, 0, $max);
    }
}

// ── Collect normalized signals from every source ─────────────────────────────
if (!function_exists('nm_inc_collect')) {
    function nm_inc_collect($conn): array {
        $sig = [];
        $now = date('Y-m-d H:i:s');
        // node id resolver by IP (cached)
        static $ipMap = null; static $nameByIp = null;
        if ($ipMap === null) {
            $ipMap = []; $nameByIp = [];
            $r = $conn->query("SELECT id, ip_address, display_name FROM nm_nodes");
            while ($r && $x = $r->fetch_assoc()) if ($x['ip_address'] !== '') { $ipMap[$x['ip_address']] = (int)$x['id']; $nameByIp[$x['ip_address']] = $x['display_name']; }
        }
        $byIp = fn($ip) => $ipMap[$ip] ?? null;
        // Host label for container/config incidents: the monitored-node name if we know it, else the raw host IP —
        // so "g-alloy-alloy-1" always shows WHICH host it's failing on.
        $hostOf = fn($ip) => ($ip === null || $ip === '') ? null : ((($nameByIp[$ip] ?? '') !== '') ? $nameByIp[$ip] : $ip);

        // 1) NODE DOWN — strongest root-cause signal (latest ping is_up=0, fresh)
        try {
            $r = $conn->query("SELECT p.node_id, n.display_name, n.ip_address
                FROM nm_ping_stats p
                JOIN (SELECT node_id, MAX(recorded_at) mx FROM nm_ping_stats GROUP BY node_id) last
                  ON last.node_id=p.node_id AND last.mx=p.recorded_at
                JOIN nm_nodes n ON n.id=p.node_id
                WHERE p.is_up=0 AND p.recorded_at >= (NOW() - INTERVAL 10 MINUTE)");
            while ($r && $x = $r->fetch_assoc()) $sig[] = ['source'=>'node_down','severity'=>'critical',
                'entity'=>$x['display_name'], 'node_id'=>(int)$x['node_id'],
                'title'=>$x['display_name'].' is unreachable (ICMP down)', 'detail'=>'No ping reply from '.$x['ip_address'],
                'fingerprint'=>'node_down:'.$x['node_id'], 'first_seen'=>$now, 'last_seen'=>$now,
                'link'=>'live_ping.php?node='.$x['node_id']];
        } catch (\Throwable $e) {}

        // 2) Container incidents — only ACTIVELY-recurring ones (last_seen recent), hard-capped.
        // Without the recency window + LIMIT this pulled EVERY open container_incident (15k+ on a busy
        // Portainer) as a signal EVERY run → the correlation upserted 15k rows/minute, blew past the
        // cron timeout, and never reached the auto-resolve pass → node/container incidents stuck "open"
        // for days even after the error stopped. An error not seen in 6h is not an active incident;
        // it drops off here (its container_incident row still lives out its own 48h TTL for history).
        try {
            $r = $conn->query("SELECT id,container_name,host_ip,severity,error_text,ai_summary,status,first_seen,last_seen
                FROM container_incidents WHERE status IN ('analyzing','open','acknowledged')
                  AND last_seen >= (NOW() - INTERVAL 6 HOUR)
                ORDER BY last_seen DESC LIMIT 400");
            while ($r && $x = $r->fetch_assoc()) { $chost = $hostOf($x['host_ip']); $sig[] = ['source'=>'container','severity'=>nm_inc_norm_sev($x['severity']),
                'entity'=>$x['container_name'], 'node_id'=>$byIp($x['host_ip']), 'host'=>$chost,
                'title'=>$x['container_name'].($chost ? ' @ '.$chost : '').': '.nm_inc_clean($x['ai_summary'] ?: $x['error_text'],120),
                'detail'=>$x['error_text'], 'fingerprint'=>'container:'.$x['id'],
                'first_seen'=>$x['first_seen'] ?: $now, 'last_seen'=>$x['last_seen'] ?: $now,
                'link'=>'container_errors.php?focus='.$x['id']]; }
        } catch (\Throwable $e) {}

        // 3) Router config drift
        try {
            $r = $conn->query("SELECT c.id,c.added,c.removed,c.detected_at,d.name,d.host_ip
                FROM nm_config_changes c JOIN nm_config_devices d ON d.id=c.device_id WHERE c.status='open'");
            while ($r && $x = $r->fetch_assoc()) $sig[] = ['source'=>'config','severity'=>'warning',
                'entity'=>$x['name'], 'node_id'=>$byIp($x['host_ip']), 'host'=>$hostOf($x['host_ip']),
                'title'=>'Config changed: '.$x['name'].' (+'.$x['added'].'/-'.$x['removed'].')',
                'detail'=>'Running-config drift detected', 'fingerprint'=>'config:'.$x['id'],
                'first_seen'=>$x['detected_at'], 'last_seen'=>$x['detected_at'], 'link'=>'config_mgr.php?focus='.$x['id']];
        } catch (\Throwable $e) {}

        // 4) Smokeping latency
        try {
            $r = $conn->query("SELECT a.id,a.node_id,a.severity,a.metric,a.value,a.threshold,a.opened_at,n.display_name
                FROM nm_latency_alerts a JOIN nm_nodes n ON n.id=a.node_id WHERE a.state='open'");
            while ($r && $x = $r->fetch_assoc()) $sig[] = ['source'=>'latency','severity'=>nm_inc_norm_sev($x['severity']),
                'entity'=>$x['display_name'], 'node_id'=>(int)$x['node_id'],
                'title'=>'High '.$x['metric'].' on '.$x['display_name'].' ('.round((float)$x['value'],1).' ≥ '.round((float)$x['threshold'],1).')',
                'detail'=>'Latency threshold breach', 'fingerprint'=>'latency:'.$x['id'],
                'first_seen'=>$x['opened_at'], 'last_seen'=>$x['opened_at'], 'link'=>'net_mon_stats.php?node='.$x['node_id']];
        } catch (\Throwable $e) {}

        // 5) NetFlow bandwidth (network-wide / per-app)
        try {
            $r = $conn->query("SELECT id,scope,severity,value_mbps,threshold_mbps,opened_at FROM nm_netflow_alerts WHERE status='open'");
            if (!function_exists('nm_nf_scope_talkers')) { try { require_once __DIR__.'/nm_netflow.php'; } catch (\Throwable $e) {} }
            while ($r && $x = $r->fetch_assoc()) {
                $tk = []; try { if (function_exists('nm_nf_scope_talkers')) $tk = nm_nf_scope_talkers($conn, (string)$x['scope'], 10, 4); } catch (\Throwable $e) {}
                $tline = $tk ? nm_nf_talkers_line($conn, $tk) : '';
                $ttop  = $tk ? (' - top ' . $tk[0]['src'] . ' -> ' . $tk[0]['dst'] . ':' . $tk[0]['port']) : '';
                $sig[] = ['source'=>'netflow','severity'=>nm_inc_norm_sev($x['severity']),
                    'entity'=>$x['scope'], 'node_id'=>null,
                    'title'=>'High bandwidth: '.$x['scope'].' ('.round((float)$x['value_mbps'],1).' Mbps)'.$ttop,
                    'detail'=> $tline !== '' ? ('Top talkers (last 10m, '.$x['scope'].'): '.$tline) : 'NetFlow bandwidth anomaly',
                    'fingerprint'=>'netflow:'.$x['id'],
                    'first_seen'=>$x['opened_at'], 'last_seen'=>$x['opened_at'], 'link'=>'netflow.php'];
            }
        } catch (\Throwable $e) {}

        // 6) Container network alerts
        try {
            $r = $conn->query("SELECT id,container_name,severity,metric,value,threshold,opened_at FROM nm_netalert_alerts WHERE state='open'");
            while ($r && $x = $r->fetch_assoc()) $sig[] = ['source'=>'container_net','severity'=>nm_inc_norm_sev($x['severity']),
                'entity'=>$x['container_name'], 'node_id'=>null,
                'title'=>'Container traffic: '.$x['container_name'].' '.$x['metric'].' '.round((float)$x['value'],1),
                'detail'=>'Container network threshold breach', 'fingerprint'=>'cnet:'.$x['id'],
                'first_seen'=>$x['opened_at'], 'last_seen'=>$x['opened_at'], 'link'=>'containers.php?view=network'];
        } catch (\Throwable $e) {}

        // 7) AI insights — only those at/above the configured minimum severity may open an
        //    incident (info-level findings like "recently rebooted" must NOT arm incidents).
        $minSev = 'warning';
        if ($sr = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='thr_incident_min_sev' LIMIT 1")) {
            if ($sx = $sr->fetch_row()) { $v = strtolower(trim((string)$sx[0])); if (in_array($v, ['info','warning','critical'], true)) $minSev = $v; }
        }
        $sevSql = $minSev === 'critical' ? "severity='critical'"
                : ($minSev === 'warning' ? "severity IN ('warning','critical')" : "1");
        try {
            // defensive cap: AI insights are expired by nm_ai_expire_stale(), but never let a runaway
            // backlog flood the correlation (the container source taught us this the hard way).
            // Exclude 'fsp_unmapped' — those are NOC↔FSP integration notices (a node has no
            // FSP identity), NOT device anomalies. Correlating them would loop: the notice
            // becomes an incident that itself opens an FSP ticket about "couldn't open a ticket".
            $r = $conn->query("SELECT id,node_id,kind,severity,title,body,created_at FROM nm_ai_insights WHERE status IN ('open','acknowledged') AND kind<>'fsp_unmapped' AND {$sevSql} ORDER BY id DESC LIMIT 800");
            while ($r && $x = $r->fetch_assoc()) $sig[] = ['source'=>'ai','severity'=>nm_inc_norm_sev($x['severity']),
                'entity'=>null, 'node_id'=>$x['node_id'] ? (int)$x['node_id'] : null, '_kind'=>$x['kind'],
                'title'=>$x['title'], 'detail'=>$x['body'], 'fingerprint'=>'ai:'.$x['id'],
                'first_seen'=>$x['created_at'], 'last_seen'=>$x['created_at'],
                // deep-link straight to THIS insight (focus highlights it; node filters the list)
                'link'=>'ai_insights.php?focus='.(int)$x['id'].($x['node_id'] ? '&node='.(int)$x['node_id'] : '')];
        } catch (\Throwable $e) {}

        // 8) Database (Data Core) — DB unreachable (critical) + schema drift (warning).
        //    Lock/slow are intermittent → shown live on the radar, NOT auto-incidented (avoid noise).
        try {
            if ($conn->query("SHOW TABLES LIKE 'nm_db_targets'")->num_rows) {
                $r = $conn->query("SELECT id,display_name,node_id,last_status,last_error,last_checked FROM nm_db_targets WHERE enabled=1");
                while ($r && $x = $r->fetch_assoc()) {
                    $nid = $x['node_id'] ? (int)$x['node_id'] : null;
                    if ($x['last_status'] === 'error' && $x['last_checked'] && strtotime($x['last_checked']) > time() - 600) {
                        $sig[] = ['source'=>'database','severity'=>'critical','entity'=>$x['display_name'],'node_id'=>$nid,
                            'title'=>'Database unreachable: '.$x['display_name'], 'detail'=>nm_inc_clean($x['last_error'],300),
                            'fingerprint'=>'db:'.$x['id'].':down','first_seen'=>$now,'last_seen'=>$now,'link'=>'dbmon.php?target='.(int)$x['id']];
                    }
                }
                if ($conn->query("SHOW TABLES LIKE 'nm_db_schema_drift'")->num_rows) {
                    $r = $conn->query("SELECT d.id,d.target_id,d.summary,d.detected_at,t.display_name,t.node_id
                                       FROM nm_db_schema_drift d JOIN nm_db_targets t ON t.id=d.target_id
                                       WHERE d.detected_at > (NOW() - INTERVAL 24 HOUR) AND d.acknowledged_at IS NULL");
                    while ($r && $x = $r->fetch_assoc()) $sig[] = ['source'=>'database','severity'=>'warning',
                        'entity'=>$x['display_name'],'node_id'=>$x['node_id']?(int)$x['node_id']:null,
                        'title'=>'Schema changed: '.$x['display_name'].' ('.$x['summary'].')','detail'=>'Schema drift detected by Data Core',
                        'fingerprint'=>'db:'.$x['target_id'].':drift:'.$x['id'],'first_seen'=>$x['detected_at'],'last_seen'=>$x['detected_at'],
                        'link'=>'dbmon.php?target='.(int)$x['target_id']];
                }
                // replication health — latest nm_db_repl per replica: stopped thread (critical) or high lag (warn/crit)
                if ($conn->query("SHOW TABLES LIKE 'nm_db_repl'")->num_rows) {
                    $lagCrit = 300;
                    if ($lr=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='db_repl_lag_crit' LIMIT 1")) if($lx=$lr->fetch_row()){ $lv=(int)$lx[0]; if($lv>0)$lagCrit=$lv; }
                    $r = $conn->query("SELECT rp.target_id, rp.io_running, rp.sql_running, rp.seconds_behind, rp.last_error, t.display_name, t.node_id
                                       FROM nm_db_repl rp
                                       JOIN (SELECT target_id, MAX(id) mx FROM nm_db_repl GROUP BY target_id) last ON last.target_id=rp.target_id AND last.mx=rp.id
                                       JOIN nm_db_targets t ON t.id=rp.target_id AND t.enabled=1 AND t.role='replica'
                                       WHERE rp.sampled_at > (NOW() - INTERVAL 10 MINUTE)");
                    while ($r && $x = $r->fetch_assoc()) {
                        $nid = $x['node_id']?(int)$x['node_id']:null;
                        if (!(int)$x['io_running'] || !(int)$x['sql_running']) {
                            $sig[] = ['source'=>'database','severity'=>'critical','entity'=>$x['display_name'],'node_id'=>$nid,
                                'title'=>'Replication STOPPED on '.$x['display_name'].' ('.((int)$x['io_running']?'':'IO ').((int)$x['sql_running']?'':'SQL ').'thread down)',
                                'detail'=>nm_inc_clean($x['last_error'],300) ?: 'A replication thread is not running.',
                                'fingerprint'=>'db:'.$x['target_id'].':repl_stopped','first_seen'=>$now,'last_seen'=>$now,'link'=>'dbmon.php?target='.(int)$x['target_id']];
                        } elseif ($x['seconds_behind']!==null && (int)$x['seconds_behind'] >= $lagCrit) {
                            $sig[] = ['source'=>'database','severity'=>'warning','entity'=>$x['display_name'],'node_id'=>$nid,
                                'title'=>'Replication lag on '.$x['display_name'].' ('.(int)$x['seconds_behind'].'s behind)',
                                'detail'=>'Replica is falling behind its source.',
                                'fingerprint'=>'db:'.$x['target_id'].':repl_lag','first_seen'=>$now,'last_seen'=>$now,'link'=>'dbmon.php?target='.(int)$x['target_id']];
                        }
                    }
                }
            }
        } catch (\Throwable $e) {}

        // MAINTENANCE — drop every node-attached signal for a node in maintenance (planned downtime =
        // no alerts, no incidents). Network-wide signals (no node_id) are untouched. One clean choke
        // point instead of a filter on each source query.
        try {
            $maint = function_exists('nm_maint_active_ids') ? nm_maint_active_ids($conn) : [];
            if ($maint) $sig = array_values(array_filter($sig, fn($s) => empty($s['node_id']) || !isset($maint[(int)$s['node_id']])));
        } catch (\Throwable $e) {}

        return $sig;
    }
}

// ── Topology: walk up gateway chain to a currently-down ancestor ─────────────
if (!function_exists('nm_inc_root_node')) {
    function nm_inc_root_node($conn, ?int $nodeId, array $downSet): ?int {
        if (!$nodeId) return null;
        if (isset($downSet[$nodeId])) return $nodeId;     // the node itself is the root
        static $gw = null;
        if ($gw === null) { $gw = []; $r = $conn->query("SELECT id,gateway_node_id FROM nm_nodes");
            while ($r && $x = $r->fetch_assoc()) $gw[(int)$x['id']] = $x['gateway_node_id'] ? (int)$x['gateway_node_id'] : null; }
        $cur = $nodeId; $seen = [];
        for ($i = 0; $i < 12; $i++) {
            $up = $gw[$cur] ?? null;
            if (!$up || isset($seen[$up])) break;
            if (isset($downSet[$up])) return $up;          // a down upstream is the root cause
            $seen[$up] = 1; $cur = $up;
        }
        return $nodeId;
    }
}

// ── Topic family: keep DISTINCT problem classes in separate incidents ────────
// A loss/latency problem and a CPU/memory problem on the same host are different
// issues and must NOT share one incident (they were being conflated under the
// highest-priority signal's title). Each signal maps to exactly one topic family;
// the correlation key carries the topic so topics never merge — while connectivity
// signals still roll downstream nodes up to a down upstream WITHIN connectivity.
if (!function_exists('nm_inc_topic')) {
    function nm_inc_topic(array $s): string {
        switch ($s['source']) {
            case 'node_down': case 'latency':       return 'connectivity';
            case 'config':                          return 'config';
            case 'database':                        return 'database';
            case 'netflow': case 'container_net':   return 'traffic';
            case 'container':                       return 'container';
        }
        // AI insights (source=ai): classify by kind, then by title keywords.
        $hay = strtolower(trim((string)($s['_kind'] ?? '')) . ' ' . (string)($s['title'] ?? ''));
        if (preg_match('/\b(cpu|processor|load|proc|mem|memory|ram|swap)\b/', $hay))      return 'compute';
        if (preg_match('/\b(disk|storage|volume|filesystem|partition|inode)\b/', $hay))   return 'storage';
        if (preg_match('/(latenc|loss|ping|reachab|jitter|rtt|unreach|down)/', $hay))     return 'connectivity';
        if (preg_match('/(interface|iface|\bport\b|ethernet|error rate|errors|flap)/', $hay)) return 'interface';
        if (preg_match('/(bandwidth|traffic|throughput|flow)/', $hay))                    return 'traffic';
        return 'anomaly';
    }
}

// ── Expire stale AI insights so views stay CONSISTENT with reality ───────────
// AI insights are point-in-time observations: n8n posts a fresh one (new hour-stamped
// correlation_key) every cycle a condition persists. So an OPEN insight older than the
// TTL describes a window that has already passed → auto-resolve it, otherwise it keeps
// an incident armed long after the device recovered (the troubleshoot wizard reads LIVE
// state and would say "healthy" while the stale insight still shows red — exactly the
// inconsistency this removes). Acknowledged insights are left alone (a human owns them);
// remediation proposals are kept (they are actionable, not alarms). TTL: nm_settings
// 'ai_insight_ttl_hours' (default 6, clamped 1..168).
if (!function_exists('nm_ai_expire_stale')) {
    function nm_ai_expire_stale($conn): int {
        $ttl = 6;
        if ($r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='ai_insight_ttl_hours' LIMIT 1")) {
            if ($x = $r->fetch_row()) { $v = (int)$x[0]; if ($v > 0) $ttl = $v; }
        }
        $ttl = max(1, min(168, $ttl));
        @$conn->query("UPDATE nm_ai_insights SET status='resolved'
                       WHERE status='open' AND kind<>'remediation'
                         AND created_at < (NOW() - INTERVAL {$ttl} HOUR)");
        return $conn->affected_rows;
    }

    // Age out STALE point-in-time incidents — one-off log errors / config drift that never recurred.
    // These are EVENTS, not ongoing conditions: they fire once and their source row stays 'open' forever,
    // so nm_inc_collect keeps re-feeding them with their ORIGINAL date → the incident shows a scary
    // "15d/29d old" and never auto-resolves. cron_container_logs advances last_seen on EVERY recurrence
    // (ON DUPLICATE KEY UPDATE last_seen=GREATEST(...)), so a last_seen that has NOT advanced within the
    // TTL means the problem stopped → safe to resolve. Ongoing errors keep advancing → untouched.
    function nm_inc_expire_stale_events($conn): int {
        $ttl = 48;   // hours of no recurrence before a point-in-time incident auto-resolves
        if ($r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='incident_stale_hours' LIMIT 1")) {
            if ($x = $r->fetch_row()) { $v = (int)$x[0]; if ($v > 0) $ttl = $v; }
        }
        $ttl = max(1, min(720, $ttl));
        $n = 0;
        try { @$conn->query("UPDATE container_incidents SET status='resolved', resolved_at=NOW()
                             WHERE status IN ('analyzing','open','acknowledged')
                               AND COALESCE(last_seen, first_seen) < (NOW() - INTERVAL {$ttl} HOUR)");
              $n += $conn->affected_rows; } catch (\Throwable $e) {}
        try { @$conn->query("UPDATE nm_config_changes SET status='resolved'
                             WHERE status='open' AND detected_at < (NOW() - INTERVAL {$ttl} HOUR)");
              $n += $conn->affected_rows; } catch (\Throwable $e) {}
        return $n;
    }
}

// ── Correlate signals → incidents (the engine tick) ──────────────────────────
if (!function_exists('nm_inc_correlate')) {
    function nm_inc_correlate($conn): array {
        nm_inc_ensure($conn);
        nm_ai_expire_stale($conn);          // age out point-in-time AI insights first → consistent incidents
        nm_inc_expire_stale_events($conn);  // age out stale one-off log-errors / config-drift (no "15d old" zombies)
        $now = date('Y-m-d H:i:s');
        $PRIO = ['node_down'=>100,'config'=>70,'infra'=>60,'database'=>55,'latency'=>45,'container'=>40,'container_net'=>38,'netflow'=>35,'ai'=>25];

        $signals = nm_inc_collect($conn);
        $downSet = [];
        foreach ($signals as $s) if ($s['source'] === 'node_down') $downSet[$s['node_id']] = 1;

        // group into incidents by correlation key (node/topology + TOPIC family, so a
        // loss incident and a cpu incident on the same host stay separate)
        $groups = [];
        foreach ($signals as $s) {
            $topic = nm_inc_topic($s);
            if (!empty($s['node_id'])) {
                $root = nm_inc_root_node($conn, (int)$s['node_id'], $downSet);
                $key = 'node:'.$root.':'.$topic;
                $s['_root_node'] = $root;
            } else {
                $key = $s['source'].':'.($s['entity'] ?? 'network').':'.$topic;   // network-wide signals stand alone
                $s['_root_node'] = null;
            }
            $s['_topic'] = $topic;
            $groups[$key][] = $s;
        }

        $opened = 0; $updated = 0; $resolved = 0;
        $seenKeys = [];
        foreach ($groups as $key => $sigs) {
            $seenKeys[$key] = 1;   // mark seen FIRST: even if this group's write hiccups, its signal IS
                                   // present → the incident must NOT be auto-resolved by the pass below.
          try {
            $incId = 0;
            // root cause = highest-priority signal
            usort($sigs, fn($a,$b)=>($PRIO[$b['source']]??0) <=> ($PRIO[$a['source']]??0));
            $root = $sigs[0];
            $sev = 'info'; foreach ($sigs as $s) if (_inc_sev_rank($s['severity']) > _inc_sev_rank($sev)) $sev = $s['severity'];
            $entities = []; foreach ($sigs as $s) if (!empty($s['entity'])) $entities[$s['entity']] = 1;
            $impact = array_keys($entities);
            $title = nm_inc_clean($root['source']==='node_down'
                ? ($root['entity'].' down'.(count($sigs)>1 ? ' — '.(count($sigs)-1).' related signal'.(count($sigs)>2?'s':'') : ''))
                : $root['title'], 255);

            // upsert incident by corr_key
            $ir = $conn->query("SELECT id,status,acked_at,muted_at,resolved_at FROM nm_incidents WHERE corr_key='".$conn->real_escape_string($key)."' LIMIT 1");
            $existing = $ir ? $ir->fetch_assoc() : null;
            $impactStr  = nm_inc_clean(implode(', ', array_slice($impact, 0, 30)), 1000);
            $rootNodeId = $root['_root_node'] ?? ($root['node_id'] ?? null);
            $rootEntity = nm_inc_clean($root['entity'] ?? '', 255);
            $rootHost   = isset($root['host']) && $root['host'] !== null ? nm_inc_clean($root['host'], 255) : null;
            if ($existing) {
                $incId = (int)$existing['id'];
                // ── STALE-RECURRENCE GATE ────────────────────────────────────────────────
                // A signal must only (re)activate/reopen an incident if it genuinely happened
                // AFTER the operator's last action (ack/mute) or after it auto-resolved — i.e.
                // its last_seen is newer than that stamp. Event-based sources (container errors,
                // config drift, …) keep a FIXED last_seen for the single occurrence and linger in
                // the correlation lookback window for hours; without this gate, acknowledging such
                // an incident was futile — the very next correlation pass re-activated the SAME old
                // signal (ON DUPLICATE KEY … status='active') and the incident "kept appearing"
                // even though nothing new had happened. Continuously-refreshed conditions (a node
                // that is STILL down stamps last_seen=$now every pass) pass the gate naturally, so
                // an ack on a genuinely-ongoing problem still holds it visible. Only what did NOT
                // recur since the operator acted is suppressed → it drops off the active board and
                // auto-resolves; a real fresh occurrence reopens it as before.
                $curStatus = $existing['status'];
                $refTime = null;
                if     ($curStatus === 'acknowledged') $refTime = $existing['acked_at']    ?? null;
                elseif ($curStatus === 'muted')        $refTime = $existing['muted_at']    ?? null;
                elseif ($curStatus === 'resolved')     $refTime = $existing['resolved_at'] ?? null;
                if ($refTime) {
                    $refTs = strtotime((string)$refTime);
                    $freshAfterRef = false;
                    foreach ($sigs as $s) {
                        $ls = strtotime((string)($s['last_seen'] ?: $now));
                        if ($ls !== false && $refTs !== false && $ls > $refTs) { $freshAfterRef = true; break; }
                    }
                    if (!$freshAfterRef) {
                        // Same occurrence the operator already handled — do NOT resurrect its signals
                        // and do NOT keep it on the active board. Drop it from "seen" so the
                        // auto-resolve pass closes an acknowledged/muted one; a resolved one just
                        // stays resolved (no flap back to open on the stale signal).
                        unset($seenKeys[$key]);
                        continue;
                    }
                }
                $newStatus = $existing['status'] === 'resolved' ? 'open' : $existing['status']; // reopen if it had cleared
                if ($existing['status'] === 'resolved') $opened++; else $updated++;
                $st = $conn->prepare("UPDATE nm_incidents SET title=?,severity=?,status=?,root_source=?,root_entity=?,root_host=?,root_node_id=?,signal_count=?,impact_count=?,impact=?,updated_at=?,resolved_at=NULL WHERE id=?");
                $cnt = count($sigs); $impc = count($impact);
                $st->bind_param('ssssssiiissi', $title,$sev,$newStatus,$root['source'],$rootEntity,$rootHost,$rootNodeId,$cnt,$impc,$impactStr,$now,$incId);
                $st->execute(); $st->close();
            } else {
                $st = $conn->prepare("INSERT INTO nm_incidents (corr_key,title,severity,status,root_source,root_entity,root_host,root_node_id,signal_count,impact_count,impact,opened_at,updated_at)
                                      VALUES (?,?,?,'open',?,?,?,?,?,?,?,?,?)");
                $cnt = count($sigs); $impc = count($impact);
                $st->bind_param('ssssssiiisss', $key,$title,$sev,$root['source'],$rootEntity,$rootHost,$rootNodeId,$cnt,$impc,$impactStr,$now,$now);
                $st->execute(); $incId = $st->insert_id; $st->close();
                $opened++;
            }

            // upsert this incident's signals + clear ones no longer present
            $fps = [];
            foreach ($sigs as $s) {
                $fps[$s['fingerprint']] = 1;
                try {
                    $u = $conn->prepare("INSERT INTO nm_incident_signals (incident_id,fingerprint,source,severity,entity,node_id,title,detail,link,status,first_seen,last_seen)
                                         VALUES (?,?,?,?,?,?,?,?,?,'active',?,?)
                                         ON DUPLICATE KEY UPDATE incident_id=VALUES(incident_id),severity=VALUES(severity),title=VALUES(title),detail=VALUES(detail),link=VALUES(link),status='active',last_seen=VALUES(last_seen),cleared_at=NULL");
                    $nid      = !empty($s['node_id']) ? (int)$s['node_id'] : null;   // null → SQL NULL
                    $entity   = nm_inc_clean($s['entity'] ?? '', 255); if ($entity === '') $entity = null;
                    $sigTitle = nm_inc_clean($s['title'] ?? '', 255);
                    $det      = nm_inc_clean($s['detail'] ?? '', 2000);
                    $fs       = $s['first_seen'] ?: $now;
                    $ls       = $s['last_seen']  ?: $now;
                    $u->bind_param('issssisssss', $incId, $s['fingerprint'], $s['source'], $s['severity'], $entity, $nid, $sigTitle, $det, $s['link'], $fs, $ls);
                    $u->execute(); $u->close();
                } catch (\Throwable $e) {
                    // A single poisoned signal (bad encoding, oversize, …) must NEVER abort the whole
                    // correlation — that is exactly what used to skip the auto-resolve pass below and
                    // leave incidents stuck "open" for weeks. Skip it and keep going.
                }
            }
            // clear signals attached to this incident that weren't seen now
            $inList = "'" . implode("','", array_map([$conn,'real_escape_string'], array_keys($fps))) . "'";
            if ($incId) $conn->query("UPDATE nm_incident_signals SET status='cleared', cleared_at='$now'
                          WHERE incident_id=$incId AND status='active' AND fingerprint NOT IN ($inList)");
          } catch (\Throwable $e) {
            // Never let one bad group abort the whole correlation — the auto-resolve pass MUST run.
          }
        }

        // auto-resolve incidents whose corr_key wasn't seen this round (all signals gone).
        // Exclude root_source='cluster' — those are federated incidents managed by nm_cluster_sync_incidents,
        // not by this local signal correlation (otherwise it would resolve them every run).
        $orr = $conn->query("SELECT id,corr_key FROM nm_incidents WHERE status IN ('open','acknowledged') AND root_source<>'cluster'");
        $toResolve = [];
        while ($orr && $x = $orr->fetch_assoc()) if (!isset($seenKeys[$x['corr_key']])) $toResolve[] = (int)$x['id'];
        foreach ($toResolve as $iid) {
            $conn->query("UPDATE nm_incident_signals SET status='cleared', cleared_at='$now' WHERE incident_id=$iid AND status='active'");
            $conn->query("UPDATE nm_incidents SET status='resolved', resolved_at='$now', updated_at='$now' WHERE id=$iid");
            $resolved++;
        }
        return ['signals'=>count($signals), 'incidents'=>count($groups), 'opened'=>$opened, 'updated'=>$updated, 'resolved'=>$resolved];
    }
}

// ── Queries for the UI / dashboard ───────────────────────────────────────────
if (!function_exists('nm_inc_list')) {
    function nm_inc_list($conn, string $status = 'active', int $limit = 100): array {
        nm_inc_ensure($conn);
        $w = $status === 'all' ? '' : ($status === 'active' ? "WHERE status IN ('open','acknowledged')" : "WHERE status='".$conn->real_escape_string($status)."'");
        $out = [];
        $r = $conn->query("SELECT i.*, (SELECT MAX(s.last_seen) FROM nm_incident_signals s WHERE s.incident_id=i.id AND s.status='active') AS last_activity,
                           (SELECT COUNT(*) FROM nm_incident_signals s WHERE s.incident_id=i.id AND s.status='active' AND s.fingerprint LIKE 'db:%:drift:%') AS schema_drift
                           FROM nm_incidents i $w ORDER BY FIELD(i.severity,'critical','warning','info'), (i.status='open') DESC, i.updated_at DESC LIMIT $limit");
        while ($r && $x = $r->fetch_assoc()) $out[] = $x;
        return $out;
    }
    function nm_inc_get($conn, int $id): ?array {
        nm_inc_ensure($conn);
        $r = $conn->query("SELECT * FROM nm_incidents WHERE id=$id LIMIT 1");
        $inc = $r ? $r->fetch_assoc() : null;
        if (!$inc) return null;
        $sigs = [];
        $sr = $conn->query("SELECT * FROM nm_incident_signals WHERE incident_id=$id ORDER BY status='active' DESC, last_seen DESC");
        while ($sr && $x = $sr->fetch_assoc()) $sigs[] = $x;
        $inc['signals'] = $sigs;
        return $inc;
    }
    function nm_inc_set_status($conn, int $id, string $status, string $by = ''): void {
        nm_inc_ensure($conn);
        if (!in_array($status, ['open','acknowledged','resolved','muted'], true)) return;
        $now = date('Y-m-d H:i:s');
        if ($status === 'muted') {
            // Ignore this recurring incident. Because the correlation upsert only
            // REOPENS 'resolved' incidents, a 'muted' one stays muted across recurrences
            // (won't reappear in the active list and won't notify) until un-muted.
            $st = $conn->prepare("UPDATE nm_incidents SET status='muted', muted_by=?, muted_at=?, updated_at=? WHERE id=?");
            $st->bind_param('sssi', $by, $now, $now, $id);
        } elseif ($status === 'acknowledged') {
            $st = $conn->prepare("UPDATE nm_incidents SET status='acknowledged', acked_by=?, acked_at=?, updated_at=? WHERE id=?");
            $st->bind_param('sssi', $by, $now, $now, $id);
        } elseif ($status === 'resolved') {
            $conn->query("UPDATE nm_incident_signals SET status='cleared', cleared_at='$now' WHERE incident_id=$id AND status='active'");
            $st = $conn->prepare("UPDATE nm_incidents SET status='resolved', resolved_at=?, updated_at=? WHERE id=?");
            $st->bind_param('ssi', $now, $now, $id);
        } else {
            $st = $conn->prepare("UPDATE nm_incidents SET status='open', resolved_at=NULL, updated_at=? WHERE id=?");
            $st->bind_param('si', $now, $id);
        }
        $st->execute(); $st->close();
        nm_audit($conn, 'incident.'.$status, ['target_type'=>'incident','target_id'=>$id]);
    }
    function nm_inc_open_count($conn): int {
        nm_inc_ensure($conn);
        $r = $conn->query("SELECT COUNT(*) c FROM nm_incidents WHERE status IN ('open','acknowledged')");
        return $r ? (int)$r->fetch_assoc()['c'] : 0;
    }
}
