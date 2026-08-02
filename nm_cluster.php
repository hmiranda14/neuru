<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Distributed Federation (Master ⇄ Slave), Phase 1.
//
// Turns any NEURU install into part of a multi-site cluster WITHOUT forking the
// codebase — the role is pure configuration (standalone | master | slave):
//   • SLAVE  — every ~30s builds a compact SITE ROLLUP (node up/down, incidents,
//     KPIs) and PUSHES it to the master over HTTPS with a per-site token. If the
//     master is unreachable it BUFFERS to a local MySQL outbox and flushes (oldest
//     first, ack-and-delete) on reconnect. Raw telemetry stays local to each site.
//   • MASTER — INGESTS rollups (token-authenticated), keeps each site's latest
//     state + a short history, and serves a federated overview filtered by a
//     visibility policy (which role sees which sites).
//
// NEURU-native by design: HTTP push (reuses the curl→token cron pattern, no
// WebSocket/gRPC daemon — CSP + non-persisted binaries), MySQL everywhere (no
// SQLite/pgvector), secrets via nm_secret_encrypt, RBAC via 'federation', audited.
// RBAC perm: 'federation'.  Engine for federation.php / cluster_ingest.php / cron_cluster.php.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_cluster_ensure')) {
    require_once __DIR__ . '/nm_secrets.php';

    function nm_cluster_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        // MASTER: registry of known sites (holds the latest rollup denormalized + the auth token)
        $conn->query("CREATE TABLE IF NOT EXISTS nm_cluster_sites (
            id INT AUTO_INCREMENT PRIMARY KEY,
            site_slug VARCHAR(50) NOT NULL,
            name VARCHAR(120) NOT NULL,
            endpoint_url VARCHAR(255) DEFAULT NULL,
            token_enc TEXT DEFAULT NULL,
            enabled TINYINT(1) NOT NULL DEFAULT 1,
            last_seen DATETIME DEFAULT NULL,
            captured_at DATETIME DEFAULT NULL,
            node_total INT DEFAULT 0, node_up INT DEFAULT 0, node_down INT DEFAULT 0, node_degraded INT DEFAULT 0,
            inc_open INT DEFAULT 0, inc_crit INT DEFAULT 0,
            last_payload MEDIUMTEXT DEFAULT NULL,
            created_by INT DEFAULT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_slug (site_slug)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // MASTER: short rollup history (for trends); pruned by the cron
        $conn->query("CREATE TABLE IF NOT EXISTS nm_cluster_rollups (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            site_slug VARCHAR(50) NOT NULL,
            captured_at DATETIME NOT NULL,
            received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            node_total INT DEFAULT 0, node_up INT DEFAULT 0, node_down INT DEFAULT 0, node_degraded INT DEFAULT 0,
            inc_open INT DEFAULT 0, inc_crit INT DEFAULT 0,
            KEY idx_site_time (site_slug, received_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // MASTER: visibility policy — which ROLE can see which site ('*' = all sites)
        $conn->query("CREATE TABLE IF NOT EXISTS nm_cluster_visibility (
            role_name VARCHAR(50) NOT NULL,
            site_slug VARCHAR(50) NOT NULL,
            PRIMARY KEY (role_name, site_slug)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // SLAVE: offline outbox (buffers rollups while the master is unreachable)
        $conn->query("CREATE TABLE IF NOT EXISTS nm_cluster_outbox (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            captured_at DATETIME NOT NULL,
            payload MEDIUMTEXT NOT NULL,
            attempts INT NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // F2: site geo coordinates for the federated Geo Wall (guarded — mysqli is in exception mode)
        foreach ([['lat',"lat DOUBLE DEFAULT NULL"], ['lon',"lon DOUBLE DEFAULT NULL"]] as $c) {
            try {
                $has = $conn->query("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_cluster_sites' AND COLUMN_NAME='" . $c[0] . "' LIMIT 1");
                if ($has && !$has->num_rows) $conn->query("ALTER TABLE nm_cluster_sites ADD COLUMN " . $c[1]);
            } catch (\Throwable $e) {}
        }
        // F2: federated incident feed (replaced per-site on each ingest)
        $conn->query("CREATE TABLE IF NOT EXISTS nm_cluster_incidents (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            site_slug VARCHAR(50) NOT NULL,
            ext_id INT DEFAULT NULL,
            title VARCHAR(255) NOT NULL,
            severity VARCHAR(10) NOT NULL DEFAULT 'warning',
            node_name VARCHAR(120) DEFAULT NULL,
            age_s INT DEFAULT NULL,
            received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            KEY idx_site (site_slug)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // F3: cluster command queue (fleet-wide security actions, pull-delivered to slaves)
        $conn->query("CREATE TABLE IF NOT EXISTS nm_cluster_commands (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            type VARCHAR(24) NOT NULL,
            payload TEXT DEFAULT NULL,
            summary VARCHAR(200) DEFAULT NULL,
            created_by INT DEFAULT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_cluster_cmd_delivery (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            command_id BIGINT NOT NULL,
            site_slug VARCHAR(50) NOT NULL,
            status VARCHAR(10) NOT NULL DEFAULT 'pending',   -- pending | done | failed
            detail VARCHAR(255) DEFAULT NULL,
            acted_at DATETIME DEFAULT NULL,
            UNIQUE KEY uk_cmd_site (command_id, site_slug),
            KEY idx_site_status (site_slug, status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // MASTER accumulates a per-remote-device time-series FROM the minutely snapshots it
        // already receives (no extra push) → real graphs on the master's device dashboard.
        $conn->query("CREATE TABLE IF NOT EXISTS nm_cluster_dev_history (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            site_slug VARCHAR(50) NOT NULL,
            remote_id INT NOT NULL,
            recorded_at DATETIME NOT NULL,
            cpu TINYINT UNSIGNED DEFAULT NULL,
            ram TINYINT UNSIGNED DEFAULT NULL,
            disk TINYINT UNSIGNED DEFAULT NULL,
            st VARCHAR(20) DEFAULT NULL,
            UNIQUE KEY uk_pt (site_slug, remote_id, recorded_at),
            KEY idx_dev (site_slug, remote_id, recorded_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','federation',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='federation')");
    }

    // ── settings (nm_settings) ───────────────────────────────────────────────
    function nm_cluster_setting($conn, string $k, ?string $default = null): ?string {
        $r = @$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='" . $conn->real_escape_string($k) . "' LIMIT 1");
        return ($r && $r->num_rows) ? (string)$r->fetch_assoc()['setting_val'] : $default;
    }
    function nm_cluster_set($conn, string $k, string $v): void {
        $st = $conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES (?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
        $st->bind_param('ss', $k, $v); $st->execute();
    }
    function nm_cluster_cfg($conn): array {
        nm_cluster_ensure($conn);
        $role = nm_cluster_setting($conn, 'cluster_role', 'standalone');
        if (!in_array($role, ['standalone','master','slave'], true)) $role = 'standalone';
        return [
            'role'       => $role,
            'site_slug'  => (string)nm_cluster_setting($conn, 'cluster_site_slug', ''),
            'site_name'  => (string)nm_cluster_setting($conn, 'cluster_site_name', ''),
            'master_url' => rtrim((string)nm_cluster_setting($conn, 'cluster_master_url', ''), '/'),
            'has_token'  => nm_cluster_setting($conn, 'cluster_site_token_enc', '') !== '',
        ];
    }
    function nm_cluster_gen_token(): string { return bin2hex(random_bytes(24)); }
    function nm_cluster_slugify(string $s): string { $s = strtolower(preg_replace('/[^a-zA-Z0-9_-]+/', '-', trim($s))); return substr(trim($s, '-'), 0, 50); }

    // the slave's own token (used to authenticate TO the master) — stored encrypted
    function nm_cluster_my_token_set($conn, string $plain): void { nm_cluster_set($conn, 'cluster_site_token_enc', nm_secret_encrypt($plain)); }
    function nm_cluster_my_token_get($conn): string { $b = nm_cluster_setting($conn, 'cluster_site_token_enc', ''); return $b ? nm_secret_decrypt($b) : ''; }

    // ── SLAVE: compact per-node inventory snapshot for the federated device view ─
    // status + a few RECENT basic metrics (cpu/ram/disk/uptime), rounded and capped
    // so the whole list rides inside the rollup payload (≤256KB ingest cap). This is
    // NOT live replication — it's the latest known snapshot, refreshed every push.
    // Best-effort: any query failure yields nulls, never breaks the rollup.
    function nm_cluster_node_snapshot($conn, int $cap = 400): array {
        $out = ['list'=>[], 'total'=>0, 'capped'=>false];
        try {
            if (!function_exists('nm_node_kind')) { $f = __DIR__ . '/nm_nodemeta.php'; if (is_file($f)) require_once $f; }
            $has = fn($t) => (bool)(@$conn->query("SHOW TABLES LIKE '" . $conn->real_escape_string($t) . "'")->num_rows);
            $status = [];
            if ($has('nm_alert_state') && ($r = @$conn->query("SELECT entity_id,last_status FROM nm_alert_state WHERE entity_type='node'")))
                while ($x = $r->fetch_assoc()) $status[(int)$x['entity_id']] = (string)$x['last_status'];
            // node_id → adopted win/linux host id, so the deep-link can target the immersive Command Center
            $winH = $lxH = [];
            if ($has('nm_win_hosts') && ($r = @$conn->query("SELECT node_id, MIN(id) hid FROM nm_win_hosts WHERE node_id IS NOT NULL GROUP BY node_id"))) while ($x = $r->fetch_assoc()) $winH[(int)$x['node_id']] = (int)$x['hid'];
            if ($has('nm_lx_hosts')  && ($r = @$conn->query("SELECT node_id, MIN(id) hid FROM nm_lx_hosts  WHERE node_id IS NOT NULL GROUP BY node_id"))) while ($x = $r->fetch_assoc()) $lxH[(int)$x['node_id']]  = (int)$x['hid'];
            $lat = function($sql) use ($conn) { $m = []; try { $r = @$conn->query($sql); while ($r && ($x = $r->fetch_assoc())) $m[(int)$x['node_id']] = $x['value']; } catch (\Throwable $e) {} return $m; };
            $cpu = $disk = $upt = $ramMem = $ramAvail = $ramTotal = [];
            if ($has('nm_device_stats')) {
                $W = "recorded_at > (NOW() - INTERVAL 30 MINUTE)";
                // cpu% — prefer the clean 'avg' key, else the most recent cpu reading
                $cpu = $lat("SELECT node_id,value FROM (SELECT node_id,value,ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY (metric_key='avg') DESC, recorded_at DESC) rn FROM nm_device_stats WHERE metric_type='cpu' AND $W) q WHERE rn=1");
                // disk% — worst (max) mount per node
                $disk = $lat("SELECT s.node_id, MAX(s.value) value FROM nm_device_stats s JOIN (SELECT node_id nid, MAX(recorded_at) mx FROM nm_device_stats WHERE metric_type='storage' AND $W GROUP BY node_id) t ON s.node_id=t.nid AND s.recorded_at=t.mx WHERE s.metric_type='storage' GROUP BY s.node_id");
                $upt = $lat("SELECT node_id,value FROM (SELECT node_id,value,ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY recorded_at DESC) rn FROM nm_device_stats WHERE metric_type='uptime' AND $W) q WHERE rn=1");
                // ram% — Windows 'memory/Physical memory' is already %used; else compute from ram Available/Total (KB)
                $ramMem   = $lat("SELECT node_id,value FROM (SELECT node_id,value,ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY recorded_at DESC) rn FROM nm_device_stats WHERE metric_type='memory' AND metric_key='Physical memory' AND $W) q WHERE rn=1");
                $ramAvail = $lat("SELECT node_id,value FROM (SELECT node_id,value,ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY recorded_at DESC) rn FROM nm_device_stats WHERE metric_type='ram' AND metric_key='RAM Available' AND $W) q WHERE rn=1");
                $ramTotal = $lat("SELECT node_id,value FROM (SELECT node_id,value,ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY recorded_at DESC) rn FROM nm_device_stats WHERE metric_type='ram' AND metric_key='RAM Total' AND $W) q WHERE rn=1");
            }
            $q = @$conn->query("SELECT * FROM nm_nodes ORDER BY display_name");
            $n = 0;
            while ($q && ($x = $q->fetch_assoc())) {
                $out['total']++;
                if ($n >= $cap) { $out['capped'] = true; continue; }
                $n++;
                $id = (int)$x['id'];
                $ram = null;
                if (isset($ramMem[$id]))                          $ram = (float)$ramMem[$id];
                elseif (isset($ramAvail[$id], $ramTotal[$id]) && (float)$ramTotal[$id] > 0) $ram = (1 - (float)$ramAvail[$id] / (float)$ramTotal[$id]) * 100;
                $cc = function_exists('nm_node_cc') ? nm_node_cc($x, $winH[$id] ?? null, $lxH[$id] ?? null) : ['url'=>"router_details.php?node=$id",'label'=>'Details'];
                $out['list'][] = [
                    'id'   => $id,
                    'name' => (string)$x['display_name'],
                    'ip'   => (string)($x['ip_address'] ?? ''),
                    'kind' => function_exists('nm_node_kind') ? nm_node_kind($x) : 'snmp',
                    'st'   => $status[$id] ?? 'up',
                    'cpu'  => isset($cpu[$id])  ? (int)round(max(0, min(100, (float)$cpu[$id])))  : null,
                    'ram'  => $ram !== null      ? (int)round(max(0, min(100, $ram))) : null,
                    'disk' => isset($disk[$id]) ? (int)round(max(0, min(100, (float)$disk[$id]))) : null,
                    'up'   => isset($upt[$id])  ? (int)$upt[$id] : null,
                    'open' => (string)($cc['url'] ?? ''),          // relative dest on the slave portal (deep-link)
                    'olbl' => (string)($cc['label'] ?? 'Details'),
                ];
            }
        } catch (\Throwable $e) { /* best-effort — never break the rollup */ }
        return $out;
    }

    // ── SLAVE: build a compact site rollup (mirrors home.php ?api=vitals) ─────
    function nm_cluster_build_rollup($conn): array {
        nm_cluster_ensure($conn);
        $has = fn($t) => (bool)(@$conn->query("SHOW TABLES LIKE '" . $conn->real_escape_string($t) . "'")->num_rows);
        $one = function($sql) use ($conn) { $r = @$conn->query($sql); return $r ? $r->fetch_assoc() : null; };
        $total = (int)($one("SELECT COUNT(*) c FROM nm_nodes")['c'] ?? 0);
        $down = $degraded = 0;
        if ($has('nm_alert_state') && ($r = @$conn->query("SELECT last_status,COUNT(*) c FROM nm_alert_state WHERE entity_type='node' AND last_status IN('down','degraded','lowerlayerdown','notpresent','testing') GROUP BY last_status")))
            while ($x = $r->fetch_assoc()) { if ($x['last_status'] === 'degraded') $degraded += (int)$x['c']; else $down += (int)$x['c']; }
        $up = max(0, $total - $down - $degraded);
        $incOpen = $incCrit = 0;
        if ($has('nm_incidents')) {
            $incOpen = (int)($one("SELECT COUNT(*) c FROM nm_incidents WHERE status IN('open','acknowledged')")['c'] ?? 0);
            $incCrit = (int)($one("SELECT COUNT(*) c FROM nm_incidents WHERE status IN('open','acknowledged') AND severity='critical'")['c'] ?? 0);
        }
        // F2: a few recent open incidents so the master can render a federated feed
        $top = [];
        if ($has('nm_incidents') && ($r = @$conn->query(
            "SELECT i.id, i.title, i.severity, TIMESTAMPDIFF(SECOND,i.opened_at,NOW()) age_s, n.display_name node
             FROM nm_incidents i LEFT JOIN nm_nodes n ON n.id=i.root_node_id
             WHERE i.status IN('open','acknowledged')
             ORDER BY FIELD(i.severity,'critical','warning','info','low'), i.opened_at DESC LIMIT 12")))
            while ($x = $r->fetch_assoc()) $top[] = ['id'=>(int)$x['id'],'title'=>(string)$x['title'],'severity'=>(string)$x['severity'],'age_s'=>(int)$x['age_s'],'node'=>(string)($x['node'] ?? '')];
        $cfg = nm_cluster_cfg($conn);
        $snap = nm_cluster_node_snapshot($conn);
        return [
            'v'           => 1,
            'site'        => $cfg['site_slug'],
            'name'        => $cfg['site_name'] ?: $cfg['site_slug'],
            'captured_at' => gmdate('Y-m-d H:i:s'),   // UTC — master stores canonical
            'nodes'       => ['total'=>$total, 'up'=>$up, 'down'=>$down, 'degraded'=>$degraded],
            'incidents'   => ['open'=>$incOpen, 'critical'=>$incCrit],
            'top_incidents' => $top,
            'devices'     => $snap['list'],           // F2: compact per-node inventory + basic metrics
            'dev_capped'  => $snap['capped'],
        ];
    }

    // POST a JSON payload to the master's ingest endpoint. Returns ['ok','code','error'].
    function nm_cluster_http_post(string $url, string $site, string $token, array $payload, int $timeout = 12, bool $verify = true): array {
        if ($url === '' || !function_exists('curl_init')) return ['ok'=>false, 'code'=>0, 'error'=>'no url/curl'];
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($payload),
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-Cluster-Site: ' . $site, 'X-Cluster-Token: ' . $token],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => min(6, $timeout),
            CURLOPT_SSL_VERIFYPEER => $verify,          // AUDIT-FIX: verify by default (cluster_ssl_verify=0 to disable for self-signed)
            CURLOPT_SSL_VERIFYHOST => $verify ? 2 : 0,
        ]);
        $body = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $err = curl_error($ch); curl_close($ch);
        $ok = ($code >= 200 && $code < 300);
        return ['ok'=>$ok, 'code'=>$code, 'error'=>$ok ? '' : ($err ?: ('HTTP ' . $code)), 'body'=>$body];
    }

    // SLAVE main tick: build a rollup, try to push it; on failure buffer it; on success flush the outbox.
    function nm_cluster_push($conn): array {
        $cfg = nm_cluster_cfg($conn);
        if ($cfg['role'] !== 'slave') return ['ok'=>false, 'error'=>'not a slave'];
        if ($cfg['site_slug'] === '' || $cfg['master_url'] === '') return ['ok'=>false, 'error'=>'slave not configured (site slug + master URL required)'];
        $token = nm_cluster_my_token_get($conn);
        if ($token === '') return ['ok'=>false, 'error'=>'no cluster token set'];
        $rollup = nm_cluster_build_rollup($conn);
        $url = $cfg['master_url'] . '/cluster_ingest.php';
        $verify = nm_cluster_ssl_verify($conn);
        $r = nm_cluster_http_post($url, $cfg['site_slug'], $token, $rollup, 12, $verify);
        if ($r['ok']) {
            $flushed = nm_cluster_flush_outbox($conn, $url, $cfg['site_slug'], $token, $verify);
            $applied = nm_cluster_run_commands($conn, $r, $url, $cfg['site_slug'], $token, $verify);   // F3: apply fleet-wide commands
            nm_cluster_set($conn, 'cluster_last_push_ok', gmdate('Y-m-d H:i:s'));
            nm_cluster_set($conn, 'cluster_last_push_err', '');   // clear stale error once we're pushing OK
            return ['ok'=>true, 'mode'=>'online', 'flushed'=>$flushed, 'commands_applied'=>$applied];
        }
        // The master ANSWERED but rejected us — this is a config error, not an outage. Do NOT buffer
        // (the rollup would 401 forever); surface a clear, actionable message instead.
        $code = (int)($r['code'] ?? 0);
        nm_cluster_set($conn, 'cluster_last_push_err', gmdate('Y-m-d H:i:s') . ' HTTP' . $code . ' ' . substr($r['error'], 0, 100));
        if ($code === 401) return ['ok'=>false, 'mode'=>'auth', 'code'=>401, 'error'=>"master rejected the TOKEN (401). The cluster token here doesn't match the one on the master for this site. On the master → Sites → reset this site's token, copy it, and paste it here."];
        if ($code === 403) return ['ok'=>false, 'mode'=>'auth', 'code'=>403, 'error'=>"master doesn't know this site (403). The Site slug here must exactly match a registered site on the master (and it must be Enabled)."];
        if ($code === 409) return ['ok'=>false, 'mode'=>'auth', 'code'=>409, 'error'=>"the Master URL points to an install that is NOT a master (409). Set that install's role to Master, or fix the Master URL here."];
        if ($code >= 400 && $code < 500) return ['ok'=>false, 'mode'=>'rejected', 'code'=>$code, 'error'=>"master rejected the push (HTTP $code): " . $r['error']];
        // connection failure (code 0 / timeout) or server error (5xx) → transient → buffer + retry later
        $st = $conn->prepare("INSERT INTO nm_cluster_outbox (captured_at,payload) VALUES (?,?)");
        $cap = $rollup['captured_at']; $pl = json_encode($rollup);
        $st->bind_param('ss', $cap, $pl); $st->execute();
        return ['ok'=>false, 'mode'=>'offline', 'code'=>$code, 'buffered'=>1, 'error'=>$r['error']];
    }

    // F3 SLAVE: apply any commands the master returned, then ack them back. At-least-once +
    // idempotent (Immunity de-dups), so a lost ack just re-delivers + re-applies harmlessly.
    function nm_cluster_run_commands($conn, array $resp, string $url, string $site, string $token, bool $verify = true): int {
        $body = json_decode((string)($resp['body'] ?? ''), true);
        $cmds = (is_array($body) && !empty($body['commands'])) ? $body['commands'] : [];
        if (!$cmds) return 0;
        $acks = [];
        foreach ($cmds as $cmd) {
            if (!is_array($cmd)) continue;
            $ap = nm_cluster_apply_command($conn, $cmd);
            $acks[] = ['id'=>(int)($cmd['id'] ?? 0), 'ok'=>!empty($ap['ok']) ? 1 : 0, 'detail'=>substr((string)($ap['detail'] ?? ''), 0, 200)];
        }
        if ($acks) nm_cluster_http_post($url, $site, $token, ['acks'=>$acks], 15, $verify);
        return count($acks);
    }
    // Flush buffered rollups oldest-first, ack-and-delete (safe: only delete rows the master accepted).
    function nm_cluster_flush_outbox($conn, string $url, string $site, string $token, bool $verify = true): int {
        $sent = 0;
        while (true) {
            $r = @$conn->query("SELECT id,payload FROM nm_cluster_outbox ORDER BY id ASC LIMIT 40");
            if (!$r || !$r->num_rows) break;
            $ids = []; $batch = [];
            while ($x = $r->fetch_assoc()) { $ids[] = (int)$x['id']; $d = json_decode($x['payload'], true); if (is_array($d)) $batch[] = $d; }
            if (!$batch) { $conn->query("DELETE FROM nm_cluster_outbox WHERE id IN (" . implode(',', array_map('intval', $ids)) . ")"); continue; }
            $res = nm_cluster_http_post($url, $site, $token, ['batch'=>$batch], 20, $verify);
            if (!$res['ok']) { $conn->query("UPDATE nm_cluster_outbox SET attempts=attempts+1 WHERE id IN (" . implode(',', array_map('intval', $ids)) . ")"); break; }
            $conn->query("DELETE FROM nm_cluster_outbox WHERE id IN (" . implode(',', array_map('intval', $ids)) . ")");   // ack → delete
            $sent += count($batch);
            if (count($ids) < 40) break;
        }
        return $sent;
    }

    // ── MASTER: ingest a rollup (or a {batch:[...]}). Token-authenticated. ────
    // Returns ['ok','error','http'] — the endpoint maps http to the response code.
    function nm_cluster_ingest($conn, string $site, string $token, array $body): array {
        nm_cluster_ensure($conn);
        $site = nm_cluster_slugify($site);
        if ($site === '' || $token === '') return ['ok'=>false, 'http'=>400, 'error'=>'missing site/token'];
        $s = @$conn->query("SELECT * FROM nm_cluster_sites WHERE site_slug='" . $conn->real_escape_string($site) . "' LIMIT 1");
        $row = ($s && $s->num_rows) ? $s->fetch_assoc() : null;
        if (!$row || !(int)$row['enabled']) return ['ok'=>false, 'http'=>403, 'error'=>'unknown or disabled site'];
        $want = $row['token_enc'] ? nm_secret_decrypt($row['token_enc']) : '';
        if ($want === '' || !hash_equals($want, $token)) return ['ok'=>false, 'http'=>401, 'error'=>'bad token'];

        // F3: a slave can POST {acks:[…]} to confirm executed commands (no rollup).
        if (isset($body['acks']) && is_array($body['acks'])) {
            foreach ($body['acks'] as $a) { if (!is_array($a)) continue; nm_cluster_cmd_ack($conn, $site, (int)($a['id'] ?? 0), !empty($a['ok']), (string)($a['detail'] ?? '')); }
            return ['ok'=>true, 'http'=>200, 'acked'=>count($body['acks']), 'commands'=>nm_cluster_cmd_pending_for($conn, $site)];
        }

        $rollups = isset($body['batch']) && is_array($body['batch']) ? $body['batch'] : [$body];
        $stored = 0; $lastInc = null;
        foreach ($rollups as $r) {
            if (!is_array($r)) continue;
            if (isset($r['top_incidents']) && is_array($r['top_incidents'])) $lastInc = $r['top_incidents'];   // latest wins
            $n = $r['nodes'] ?? []; $i = $r['incidents'] ?? [];
            $nt=(int)($n['total']??0); $nu=(int)($n['up']??0); $nd=(int)($n['down']??0); $ng=(int)($n['degraded']??0);
            $io=(int)($i['open']??0); $ic=(int)($i['critical']??0);
            $cap = preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', (string)($r['captured_at']??'')) ? $r['captured_at'] : gmdate('Y-m-d H:i:s');
            $name = substr((string)($r['name'] ?? $row['name']), 0, 120);
            try {
                $st = $conn->prepare("INSERT INTO nm_cluster_rollups (site_slug,captured_at,node_total,node_up,node_down,node_degraded,inc_open,inc_crit) VALUES (?,?,?,?,?,?,?,?)");
                $st->bind_param('ssiiiiii', $site,$cap,$nt,$nu,$nd,$ng,$io,$ic); $st->execute();
            } catch (\Throwable $e) {}
            // latest wins for the denormalized row
            $st2 = $conn->prepare("UPDATE nm_cluster_sites SET name=?, last_seen=UTC_TIMESTAMP(), captured_at=?, node_total=?,node_up=?,node_down=?,node_degraded=?,inc_open=?,inc_crit=?, last_payload=? WHERE site_slug=?");
            $plj = json_encode($r);
            $st2->bind_param('ssiiiiiiss', $name,$cap,$nt,$nu,$nd,$ng,$io,$ic,$plj,$site); $st2->execute();
            // accumulate the per-device time-series (one point per rollup; unique key dedupes batch/replays)
            if (isset($r['devices']) && is_array($r['devices'])) {
                try {
                    $hi = $conn->prepare("INSERT IGNORE INTO nm_cluster_dev_history (site_slug,remote_id,recorded_at,cpu,ram,disk,st) VALUES (?,?,?,?,?,?,?)");
                    foreach ($r['devices'] as $d) {
                        if (!is_array($d)) continue;
                        $rid=(int)($d['id']??0); if($rid<=0) continue;
                        $cpu=isset($d['cpu'])&&$d['cpu']!==null?(int)$d['cpu']:null;
                        $ram=isset($d['ram'])&&$d['ram']!==null?(int)$d['ram']:null;
                        $dsk=isset($d['disk'])&&$d['disk']!==null?(int)$d['disk']:null;
                        $stt=substr((string)($d['st']??''),0,20);
                        $hi->bind_param('sisiiis', $site,$rid,$cap,$cpu,$ram,$dsk,$stt); $hi->execute();
                    }
                } catch (\Throwable $e) { /* best-effort: history is a bonus, never break ingest */ }
            }
            $stored++;
        }
        // replace the site's federated incident feed with the latest snapshot
        if ($lastInc !== null) {
            $conn->query("DELETE FROM nm_cluster_incidents WHERE site_slug='" . $conn->real_escape_string($site) . "'");
            $ins = $conn->prepare("INSERT INTO nm_cluster_incidents (site_slug,ext_id,title,severity,node_name,age_s) VALUES (?,?,?,?,?,?)");
            foreach (array_slice($lastInc, 0, 12) as $ti) {
                if (!is_array($ti)) continue;
                $eid=(int)($ti['id']??0); $ttl=substr((string)($ti['title']??''),0,255); $sev=substr((string)($ti['severity']??'warning'),0,10); $nn=substr((string)($ti['node']??''),0,120); $ag=(int)($ti['age_s']??0);
                $ins->bind_param('sisssi', $site,$eid,$ttl,$sev,$nn,$ag); $ins->execute();
            }
        }
        return ['ok'=>true, 'http'=>200, 'stored'=>$stored, 'commands'=>nm_cluster_cmd_pending_for($conn, $site)];
    }

    // ── MASTER: read the fleet + visibility ──────────────────────────────────
    // status: online (<90s), stale (<10m), offline (older / never)
    function nm_cluster_sites($conn): array {
        nm_cluster_ensure($conn);
        $out = [];
        $r = @$conn->query("SELECT *, TIMESTAMPDIFF(SECOND,last_seen,UTC_TIMESTAMP()) age FROM nm_cluster_sites ORDER BY name");
        while ($r && ($x = $r->fetch_assoc())) {
            $age = $x['last_seen'] !== null ? (int)$x['age'] : null;
            $status = $age === null ? 'never' : ($age < 90 ? 'online' : ($age < 600 ? 'stale' : 'offline'));
            $out[] = [
                'id'=>(int)$x['id'], 'site'=>$x['site_slug'], 'name'=>$x['name'], 'endpoint'=>$x['endpoint_url'],
                'enabled'=>(int)$x['enabled'], 'has_token'=>!empty($x['token_enc']),
                'lat'=>isset($x['lat'])&&$x['lat']!==null?(float)$x['lat']:null, 'lon'=>isset($x['lon'])&&$x['lon']!==null?(float)$x['lon']:null,
                'age'=>$age, 'status'=>$status, 'captured_at'=>$x['captured_at'], 'last_seen'=>$x['last_seen'],
                'nodes'=>['total'=>(int)$x['node_total'],'up'=>(int)$x['node_up'],'down'=>(int)$x['node_down'],'degraded'=>(int)$x['node_degraded']],
                'incidents'=>['open'=>(int)$x['inc_open'],'critical'=>(int)$x['inc_crit']],
            ];
        }
        return $out;
    }
    // Filter the fleet by a viewer's role. admin sees all; a role sees '*' or its listed sites.
    function nm_cluster_sites_visible($conn, string $role): array {
        $sites = nm_cluster_sites($conn);
        if ($role === 'admin') return $sites;
        $allow = []; $all = false;
        $r = @$conn->query("SELECT site_slug FROM nm_cluster_visibility WHERE role_name='" . $conn->real_escape_string($role) . "'");
        while ($r && ($x = $r->fetch_assoc())) { if ($x['site_slug'] === '*') $all = true; else $allow[$x['site_slug']] = true; }
        if ($all) return $sites;
        return array_values(array_filter($sites, fn($s) => isset($allow[$s['site']])));
    }
    // ── MASTER: federated device inventory (per remote site, tagged by origin) ──
    // Decodes each visible site's stored rollup payload and returns its compact
    // device snapshot grouped by site. $includeSelf=false drops the master's OWN
    // site (net_mon.php strip → only REMOTE devices, since locals show natively).
    function nm_cluster_fed_devices($conn, string $role, bool $includeSelf = true): array {
        nm_cluster_ensure($conn);
        $cfg  = nm_cluster_cfg($conn);
        $self = (string)($cfg['site_slug'] ?? '');
        $out  = [];
        foreach (nm_cluster_sites_visible($conn, $role) as $s) {
            $isSelf = ($s['site'] === $self);
            if (!$includeSelf && $isSelf) continue;
            $row = @$conn->query("SELECT last_payload FROM nm_cluster_sites WHERE site_slug='" . $conn->real_escape_string($s['site']) . "' LIMIT 1");
            $pl  = ($row && $row->num_rows) ? json_decode((string)($row->fetch_assoc()['last_payload'] ?? ''), true) : null;
            $devs = (is_array($pl) && isset($pl['devices']) && is_array($pl['devices'])) ? $pl['devices'] : [];
            $out[] = [
                'site'    => $s['site'],
                'name'    => $s['name'],
                'status'  => $s['status'],   // online | stale | offline | never
                'age'     => $s['age'],
                'is_self' => $isSelf,
                'capped'  => is_array($pl) ? !empty($pl['dev_capped']) : false,
                'devices' => array_values($devs),
            ];
        }
        return $out;
    }
    // One remote device: its snapshot meta + the master-accumulated history + deep-link.
    // Visibility-gated (role must be allowed to see the origin site). Returns null if denied/missing.
    function nm_cluster_fed_device($conn, string $role, string $siteSlug, int $rid, int $hours = 24): ?array {
        nm_cluster_ensure($conn);
        $siteSlug = nm_cluster_slugify($siteSlug);
        $site = null;
        foreach (nm_cluster_sites_visible($conn, $role) as $s) if ($s['site'] === $siteSlug) { $site = $s; break; }
        if (!$site) return null;   // not visible to this role, or unknown
        $row = @$conn->query("SELECT last_payload FROM nm_cluster_sites WHERE site_slug='" . $conn->real_escape_string($siteSlug) . "' LIMIT 1");
        $pl  = ($row && $row->num_rows) ? json_decode((string)($row->fetch_assoc()['last_payload'] ?? ''), true) : null;
        $dev = null;
        if (is_array($pl) && isset($pl['devices']) && is_array($pl['devices']))
            foreach ($pl['devices'] as $d) if (is_array($d) && (int)($d['id'] ?? 0) === $rid) { $dev = $d; break; }
        if (!$dev) return null;
        $hours = max(1, min(168, $hours));
        $hist = [];
        $st = $conn->prepare("SELECT recorded_at, cpu, ram, disk, st FROM nm_cluster_dev_history WHERE site_slug=? AND remote_id=? AND recorded_at > (UTC_TIMESTAMP() - INTERVAL ? HOUR) ORDER BY recorded_at ASC LIMIT 2000");
        $st->bind_param('sii', $siteSlug, $rid, $hours); $st->execute();
        $rs = $st->get_result();
        while ($rs && ($x = $rs->fetch_assoc())) $hist[] = [
            't'=>$x['recorded_at'],
            'cpu'=>$x['cpu']!==null?(int)$x['cpu']:null, 'ram'=>$x['ram']!==null?(int)$x['ram']:null,
            'disk'=>$x['disk']!==null?(int)$x['disk']:null, 'st'=>$x['st'],
        ];
        $ep   = rtrim((string)($site['endpoint'] ?? ''), '/');
        $open = (string)($dev['open'] ?? '');
        $isSelf = ($siteSlug === (string)(nm_cluster_cfg($conn)['site_slug'] ?? ''));
        // master's OWN device → same-portal relative link (no endpoint_url needed); remote → prefix the site URL
        $link = $open === '' ? '' : ($isSelf ? $open : ($ep !== '' ? $ep . '/' . ltrim($open, '/') : ''));
        // embed_url = the SAME native page, but signed for a no-login read-only iframe (SSO).
        // self → relative (same origin); remote → HMAC-signed via nm_fed_master_embed_url.
        $embed = '';
        if ($open !== '') {
            if ($isSelf) { $embed = $open . (strpos($open, '?') !== false ? '&' : '?') . 'embed=1'; }
            else {
                if (!function_exists('nm_fed_master_embed_url')) { $ff = __DIR__ . '/nm_fed_auth.php'; if (is_file($ff)) require_once $ff; }
                $embed = function_exists('nm_fed_master_embed_url') ? nm_fed_master_embed_url($conn, $siteSlug, $open) : '';
            }
        }
        return [
            'site'      => ['slug'=>$siteSlug, 'name'=>$site['name'], 'status'=>$site['status'], 'age'=>$site['age'], 'endpoint'=>$ep, 'is_self'=>$isSelf],
            'device'    => $dev,
            'history'   => $hist,
            'deeplink'  => $link,                // open the native page in a new tab (normal login)
            'embed_url' => $embed,               // signed no-login read-only URL for the iframe (SSO)
            'olabel'    => (string)($dev['olbl'] ?? 'Open on site'),
        ];
    }
    // Keep the MASTER's OWN site row fresh WHILE someone is viewing the dashboard, so it
    // never reads "stale" against itself just because the background cron lagged or isn't
    // installed. Throttled (skips if the row is younger than $minAge). Master-only, cheap.
    function nm_cluster_self_refresh($conn, int $minAge = 25): void {
        try {
            $cfg = nm_cluster_cfg($conn);
            if (($cfg['role'] ?? '') !== 'master') return;
            $slug = (string)($cfg['site_slug'] ?? ''); if ($slug === '') return;
            $r = @$conn->query("SELECT TIMESTAMPDIFF(SECOND,last_seen,UTC_TIMESTAMP()) age FROM nm_cluster_sites WHERE site_slug='" . $conn->real_escape_string($slug) . "' LIMIT 1");
            $age = ($r && $r->num_rows) ? $r->fetch_assoc()['age'] : null;
            if ($age === null || (int)$age >= $minAge) nm_cluster_self_ingest($conn);
        } catch (\Throwable $e) { /* best-effort */ }
    }
    function nm_cluster_site_upsert($conn, array $f, ?int $uid): array {
        nm_cluster_ensure($conn);
        $slug = nm_cluster_slugify((string)($f['site_slug'] ?? ''));
        $name = substr(trim((string)($f['name'] ?? $slug)), 0, 120);
        if ($slug === '' || $name === '') return ['ok'=>false, 'error'=>'slug + name required'];
        $ep   = substr(trim((string)($f['endpoint_url'] ?? '')), 0, 255) ?: null;
        $en   = (int)!empty($f['enabled']);
        $lat  = ($f['lat'] ?? '') !== '' && is_numeric($f['lat']) ? (float)$f['lat'] : null;
        $lon  = ($f['lon'] ?? '') !== '' && is_numeric($f['lon']) ? (float)$f['lon'] : null;
        $id   = (int)($f['id'] ?? 0);
        // Re-save of an existing slug (even with id=0) is an EDIT — never re-mint its token.
        if (!$id) {
            $ex = $conn->query("SELECT id FROM nm_cluster_sites WHERE site_slug='" . $conn->real_escape_string($slug) . "' LIMIT 1");
            if ($ex && ($exr = $ex->fetch_assoc())) $id = (int)$exr['id'];
        }
        if ($id) {
            $st = $conn->prepare("UPDATE nm_cluster_sites SET name=?, endpoint_url=?, enabled=?, lat=?, lon=? WHERE id=?");
            $st->bind_param('ssiddi', $name, $ep, $en, $lat, $lon, $id); $st->execute();
            if (function_exists('nm_audit')) nm_audit($conn, 'cluster.site_save', ['target_type'=>'cluster_site', 'target_id'=>$slug]);
            return ['ok'=>true, 'id'=>$id];   // no 'token' → existing site, token untouched
        }
        // Brand-new site: mint the token ONCE here and return the plaintext so the UI can
        // show it. No second reset call (that was the source of the "shown ≠ stored" mismatch).
        $tokPlain = ((string)($f['token'] ?? '')) !== '' ? (string)$f['token'] : nm_cluster_gen_token();
        $st = $conn->prepare("INSERT INTO nm_cluster_sites (site_slug,name,endpoint_url,token_enc,enabled,lat,lon,created_by) VALUES (?,?,?,?,?,?,?,?)");
        $tokEnc = nm_secret_encrypt($tokPlain);
        $st->bind_param('ssssiddi', $slug, $name, $ep, $tokEnc, $en, $lat, $lon, $uid); $st->execute();
        $id = (int)$conn->insert_id;
        if (function_exists('nm_audit')) nm_audit($conn, 'cluster.site_save', ['target_type'=>'cluster_site', 'target_id'=>$slug]);
        return ['ok'=>true, 'id'=>$id, 'token'=>$tokPlain, 'created'=>true];
    }
    function nm_cluster_site_token_reset($conn, int $id): array {
        nm_cluster_ensure($conn);
        $tok = nm_cluster_gen_token();
        $st = $conn->prepare("UPDATE nm_cluster_sites SET token_enc=? WHERE id=?"); $enc = nm_secret_encrypt($tok);
        $st->bind_param('si', $enc, $id); $st->execute();
        if (function_exists('nm_audit')) nm_audit($conn, 'cluster.token_reset', ['target_type'=>'cluster_site', 'target_id'=>$id]);
        return ['ok'=>true, 'token'=>$tok];   // shown once — operator copies to the slave
    }

    // ── One-paste enrollment ─────────────────────────────────────────────────────
    // MASTER: pack {master_url, slug, token} of a registered site into ONE code the
    // operator pastes on the slave — no more copying 3 fields / slug typos / 401s.
    function nm_cluster_enroll_code($conn, int $siteId, string $masterUrl): array {
        $s = @$conn->query("SELECT site_slug,token_enc FROM nm_cluster_sites WHERE id=" . (int)$siteId . " LIMIT 1");
        $row = $s ? $s->fetch_assoc() : null;
        if (!$row) return ['ok'=>false, 'error'=>'site not found'];
        $tok = $row['token_enc'] ? nm_secret_decrypt($row['token_enc']) : '';
        if ($tok === '') return ['ok'=>false, 'error'=>'this site has no token yet — save it first'];
        $masterUrl = rtrim(trim($masterUrl), '/');
        if (!preg_match('#^https?://#i', $masterUrl)) return ['ok'=>false, 'error'=>'master URL must start with http:// or https://'];
        $payload = ['v'=>1, 'm'=>$masterUrl, 's'=>$row['site_slug'], 't'=>$tok];
        $code = 'NEURU1.' . rtrim(strtr(base64_encode((string)json_encode($payload)), '+/', '-_'), '=');
        return ['ok'=>true, 'code'=>$code, 'slug'=>$row['site_slug'], 'master'=>$masterUrl];
    }
    // SLAVE: paste the code → configure role/slug/master/token in one shot, then live-verify.
    function nm_cluster_enroll_apply($conn, string $code): array {
        $code = trim($code);
        if (strpos($code, 'NEURU1.') !== 0) return ['ok'=>false, 'error'=>'not a valid NEURU enrollment code'];
        $b = substr($code, 7); $b = strtr($b, '-_', '+/'); $p = strlen($b) % 4; if ($p) $b .= str_repeat('=', 4 - $p);
        $j = json_decode((string)base64_decode($b), true);
        if (!is_array($j) || empty($j['m']) || empty($j['s']) || empty($j['t'])) return ['ok'=>false, 'error'=>'corrupt enrollment code'];
        if (!preg_match('#^https?://#i', (string)$j['m'])) return ['ok'=>false, 'error'=>'enrollment code has a bad master URL'];
        $slug = nm_cluster_slugify((string)$j['s']);
        nm_cluster_set($conn, 'cluster_role', 'slave');
        nm_cluster_set($conn, 'cluster_site_slug', $slug);
        if (nm_cluster_setting($conn, 'cluster_site_name', '') === '') nm_cluster_set($conn, 'cluster_site_name', $slug);
        nm_cluster_set($conn, 'cluster_master_url', rtrim((string)$j['m'], '/'));
        nm_cluster_my_token_set($conn, (string)$j['t']);   // web context → encrypts with the readable key
        if (function_exists('nm_audit')) nm_audit($conn, 'cluster.enroll', ['slug'=>$slug, 'master'=>$j['m']]);
        return ['ok'=>true, 'slug'=>$slug, 'master'=>rtrim((string)$j['m'], '/'), 'probe'=>nm_cluster_probe_master($conn)];
    }

    // ── Live diagnostics ─────────────────────────────────────────────────────────
    // SLAVE: hit the master's ingest with a no-op {acks:[]} (doesn't store a rollup) and
    // translate the HTTP code into a plain-language verdict — the automated "curl replay".
    function nm_cluster_probe_master($conn): array {
        $cfg = nm_cluster_cfg($conn);
        if ($cfg['role'] !== 'slave')  return ['ok'=>false, 'code'=>0, 'reason'=>'this install is not a slave'];
        if ($cfg['master_url'] === '') return ['ok'=>false, 'code'=>0, 'reason'=>'no Master URL is set'];
        $token = nm_cluster_my_token_get($conn);
        if ($token === '') return ['ok'=>false, 'code'=>0, 'reason'=>'no cluster token is set'];
        $verify = function_exists('nm_cluster_ssl_verify') ? nm_cluster_ssl_verify($conn) : true;
        $r = nm_cluster_http_post($cfg['master_url'] . '/cluster_ingest.php', $cfg['site_slug'], $token, ['acks'=>[]], 10, $verify);
        $code = (int)($r['code'] ?? 0);
        $reason = [
            200 => 'connected & authenticated',
            401 => "token mismatch — the master's token for slug '{$cfg['site_slug']}' differs from this slave's. Re-enroll, or reset the token on the master and paste the new one.",
            403 => "the master has no enabled site with slug '{$cfg['site_slug']}'. The slave's slug must EXACTLY match a registered site on the master.",
            409 => 'the Master URL points to an install whose role is not Master.',
            0   => "can't reach the Master URL ({$cfg['master_url']}) — network / port / firewall.",
        ][$code] ?? ("unexpected HTTP $code" . (!empty($r['error']) ? ' · ' . $r['error'] : ''));
        return ['ok'=>($code >= 200 && $code < 300), 'code'=>$code, 'reason'=>$reason, 'master'=>$cfg['master_url'], 'slug'=>$cfg['site_slug']];
    }

    // Full health checklist for the Federation page (green/red per prerequisite + a fix hint).
    // Runs in the WEB (www-data) request, so the secret-key round-trip reflects the real ingest context.
    function nm_cluster_health($conn): array {
        $cfg = nm_cluster_cfg($conn);
        $checks = [];
        $add = function($key,$label,$status,$detail,$fix='') use (&$checks){ $checks[] = compact('key','label','status','detail','fix'); };

        // 1) secret key readable HERE (the #1 silent-401 cause) — encrypt then decrypt a probe
        $pb = 'nmhealth-probe';
        $rt = function_exists('nm_secret_decrypt') ? nm_secret_decrypt(nm_secret_encrypt($pb)) : $pb;
        if ($rt === $pb) $add('secret','Secret key (.nm_secret.key)','ok','Encrypted secrets decrypt correctly in the web context.');
        else $add('secret','Secret key (.nm_secret.key)','fail','www-data cannot read the key → EVERY stored secret (cluster/n8n/SSH/Pi-hole…) fails to decrypt, causing silent 401s.','On the host as root: chown www-data:www-data netmon/.nm_secret.key && chmod 644 netmon/.nm_secret.key, then restart the container.');

        // 2) role
        if ($cfg['role'] === 'standalone') $add('role','Cluster role','warn','Standalone — not part of a cluster yet.','Choose Master or Slave in Setup (or paste an enrollment code to become a slave).');
        else $add('role','Cluster role','ok','Role = ' . $cfg['role'] . '.');

        // 3) inbound token (gates ALL crons) — read nm_settings DIRECTLY (same value the cron
        //    endpoints compare), so the check doesn't depend on nm_n8n.php being loaded here.
        $intok = '';
        try { $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='n8n_inbound_token' LIMIT 1"); if ($r && $r->num_rows) $intok = (string)($r->fetch_assoc()['setting_val'] ?? ''); } catch (\Throwable $e) {}
        if ($intok === '') $add('inbound','Cron auth token','fail','No inbound token → every scheduled job (federation push, NetFlow, incidents, health) silently 401s and does nothing.','Generate one in Site Config → n8n (Rotate). 0.1.1.7+ auto-seeds it and the cron reads it at runtime.');
        else $add('inbound','Cron auth token','ok','Set — crons can authenticate to localhost.');

        if ($cfg['role'] === 'slave') {
            if ($cfg['master_url'] === '') $add('master_url','Master URL','fail','Not set — the slave has nowhere to push.','Set it in Setup, or paste an enrollment code.');
            else $add('master_url','Master URL','ok',$cfg['master_url']);
            if (empty($cfg['has_token'])) $add('token','Cluster token','fail','No cluster token — the master rejects pushes.','Paste the master site token, or use an enrollment code.');
            else $add('token','Cluster token','ok','Set.');
            if ($cfg['master_url'] !== '' && !empty($cfg['has_token'])) {
                $p = nm_cluster_probe_master($conn);
                $add('reach','Master connection (LIVE test)', $p['ok'] ? 'ok' : 'fail', $p['reason']);
            }
            $lok = (string)nm_cluster_setting($conn,'cluster_last_push_ok',''); $lerr = (string)nm_cluster_setting($conn,'cluster_last_push_err','');
            // Only surface an error that's MORE RECENT than the last success (else it's stale noise).
            $showErr = '';
            if ($lerr !== '' && preg_match('/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/', $lerr, $mm)) {
                if ($lok === '' || strtotime($mm[1] . ' UTC') > strtotime($lok . ' UTC')) $showErr = $lerr;
            }
            if ($lok !== '') { $age = time() - (int)strtotime($lok . ' UTC'); $st = $age < 120 ? 'ok' : ($age < 900 ? 'warn' : 'fail');
                $add('push','Last successful push', $st, '≈' . max(0,(int)round($age/60)) . ' min ago' . ($showErr ? ' · newer error: ' . $showErr : ''), $st==='ok' ? '' : 'The push cron may not be running every minute — confirm cron is up (0.1.1.8+ resolves the token at runtime).');
            } else $add('push','Last successful push','warn','None recorded yet.', $showErr ? ('last error: ' . $showErr) : 'Use Setup → Test push once.');
        }

        if ($cfg['role'] === 'master') {
            $self = $cfg['site_slug']; $never = []; $online = 0; $total = 0;
            foreach (nm_cluster_sites($conn) as $s) {
                if (($s['site'] ?? '') === $self) continue; $total++;
                if (($s['status'] ?? '') === 'never') $never[] = $s['site'];
                elseif (($s['status'] ?? '') === 'online') $online++;
            }
            $add('sites','Registered slaves', $never ? 'warn' : 'ok', $total . ' slave(s), ' . $online . ' online' . ($never ? '; never reported: ' . implode(', ', $never) : ''), $never ? 'A "never reported" site almost always means the SLAVE\'s slug ≠ the registered slug (or it hasn\'t pushed yet). Verify the slave\'s slug matches exactly.' : '');
        }

        $fails = 0; foreach ($checks as $c) if ($c['status'] === 'fail') $fails++;
        return ['role'=>$cfg['role'], 'ok'=>($fails === 0), 'fails'=>$fails, 'checks'=>$checks];
    }

    function nm_cluster_site_delete($conn, int $id): array {
        nm_cluster_ensure($conn);
        $slugRow = @$conn->query("SELECT site_slug FROM nm_cluster_sites WHERE id=" . (int)$id . " LIMIT 1");
        $slug = ($slugRow && $slugRow->num_rows) ? $slugRow->fetch_assoc()['site_slug'] : '';
        $conn->query("DELETE FROM nm_cluster_sites WHERE id=" . (int)$id);
        if ($slug !== '') { $e = $conn->real_escape_string($slug);
            $conn->query("DELETE FROM nm_cluster_rollups WHERE site_slug='$e'");
            $conn->query("DELETE FROM nm_cluster_visibility WHERE site_slug='$e'");
            $conn->query("DELETE FROM nm_cluster_incidents WHERE site_slug='$e'");           // AUDIT-FIX
            $conn->query("DELETE FROM nm_cluster_cmd_delivery WHERE site_slug='$e'");         // AUDIT-FIX (no orphan deliveries)
            $conn->query("DELETE FROM nm_cluster_dev_history WHERE site_slug='$e'");          // no orphan device history
        }
        if (function_exists('nm_audit')) nm_audit($conn, 'cluster.site_delete', ['target_type'=>'cluster_site','target_id'=>$slug]);
        return ['ok'=>true];
    }

    // ── MASTER: visibility policy (role → sites) ─────────────────────────────
    function nm_cluster_visibility_all($conn): array {
        nm_cluster_ensure($conn); $out = [];
        $r = @$conn->query("SELECT role_name, site_slug FROM nm_cluster_visibility ORDER BY role_name, site_slug");
        while ($r && ($x = $r->fetch_assoc())) $out[$x['role_name']][] = $x['site_slug'];
        return $out;
    }
    function nm_cluster_visibility_set($conn, string $role, array $sites): array {
        nm_cluster_ensure($conn);
        $role = substr(trim($role), 0, 50); if ($role === '') return ['ok'=>false, 'error'=>'role required'];
        $conn->query("DELETE FROM nm_cluster_visibility WHERE role_name='" . $conn->real_escape_string($role) . "'");
        $st = $conn->prepare("INSERT IGNORE INTO nm_cluster_visibility (role_name,site_slug) VALUES (?,?)");
        foreach ($sites as $s) { $s = ($s === '*') ? '*' : nm_cluster_slugify((string)$s); if ($s === '') continue; $st->bind_param('ss', $role, $s); $st->execute(); }
        if (function_exists('nm_audit')) nm_audit($conn, 'cluster.visibility_set', ['target_type'=>'role', 'target_id'=>$role, 'details'=>['sites'=>$sites]]);
        return ['ok'=>true];
    }
    // The MASTER is also a site — fold its own local rollup into the registry so it
    // appears in its own federated overview (local, no token/HTTP).
    function nm_cluster_self_ingest($conn): array {
        $cfg = nm_cluster_cfg($conn);
        if ($cfg['role'] !== 'master') return ['ok'=>false, 'error'=>'not master'];
        $slug = $cfg['site_slug'] !== '' ? nm_cluster_slugify($cfg['site_slug']) : 'master';
        $name = $cfg['site_name'] ?: 'HQ (this master)';
        $conn->query("INSERT IGNORE INTO nm_cluster_sites (site_slug,name,enabled) VALUES ('" . $conn->real_escape_string($slug) . "','" . $conn->real_escape_string($name) . "',1)");
        $r = nm_cluster_build_rollup($conn); $r['site'] = $slug; $r['name'] = $name;
        $n = $r['nodes']; $i = $r['incidents']; $cap = $r['captured_at']; $plj = json_encode($r);
        $nt=$n['total'];$nu=$n['up'];$nd=$n['down'];$ng=$n['degraded'];$io=$i['open'];$ic=$i['critical'];
        $st = $conn->prepare("UPDATE nm_cluster_sites SET name=?, last_seen=UTC_TIMESTAMP(), captured_at=?, node_total=?,node_up=?,node_down=?,node_degraded=?,inc_open=?,inc_crit=?, last_payload=? WHERE site_slug=?");
        $st->bind_param('ssiiiiiiss', $name,$cap,$nt,$nu,$nd,$ng,$io,$ic,$plj,$slug); $st->execute();
        // the master's own incidents into the federated feed
        $conn->query("DELETE FROM nm_cluster_incidents WHERE site_slug='" . $conn->real_escape_string($slug) . "'");
        if (!empty($r['top_incidents']) && is_array($r['top_incidents'])) {
            $ins = $conn->prepare("INSERT INTO nm_cluster_incidents (site_slug,ext_id,title,severity,node_name,age_s) VALUES (?,?,?,?,?,?)");
            foreach (array_slice($r['top_incidents'], 0, 12) as $ti) {
                if (!is_array($ti)) continue;
                $eid=(int)($ti['id']??0); $ttl=substr((string)($ti['title']??''),0,255); $sev=substr((string)($ti['severity']??'warning'),0,10); $nn=substr((string)($ti['node']??''),0,120); $ag=(int)($ti['age_s']??0);
                $ins->bind_param('sisssi', $slug,$eid,$ttl,$sev,$nn,$ag); $ins->execute();
            }
        }
        return ['ok'=>true, 'site'=>$slug];
    }
    // F2: everything the federated Geo Wall needs, filtered by the viewer's role.
    function nm_cluster_wall($conn, string $role): array {
        $sites = nm_cluster_sites_visible($conn, $role);
        $slugs = array_map(fn($s) => $s['site'], $sites);
        $incidents = [];
        if ($slugs) {
            $in = implode(',', array_map(fn($s) => "'" . $conn->real_escape_string($s) . "'", $slugs));
            $r = @$conn->query("SELECT c.site_slug, c.title, c.severity, c.node_name, c.age_s, s.name site_name
                FROM nm_cluster_incidents c JOIN nm_cluster_sites s ON s.site_slug=c.site_slug
                WHERE c.site_slug IN ($in)
                ORDER BY FIELD(c.severity,'critical','warning','info','low'), c.age_s ASC LIMIT 60");
            while ($r && ($x = $r->fetch_assoc())) $incidents[] = [
                'site'=>$x['site_slug'], 'site_name'=>$x['site_name'], 'title'=>$x['title'],
                'severity'=>$x['severity'], 'node'=>$x['node_name'], 'age_s'=>(int)$x['age_s'],
            ];
        }
        return ['sites'=>$sites, 'incidents'=>$incidents];
    }
    function nm_cluster_prune($conn, int $days = 14): void {
        nm_cluster_ensure($conn);
        $d = max(1, $days);
        @$conn->query("DELETE FROM nm_cluster_rollups WHERE received_at < (UTC_TIMESTAMP() - INTERVAL $d DAY) LIMIT 20000");
        // AUDIT-FIX (capacity): prune fully-delivered commands older than $days (command + its deliveries)
        $ids = [];
        $r = @$conn->query("SELECT c.id FROM nm_cluster_commands c
            WHERE c.created_at < (UTC_TIMESTAMP() - INTERVAL $d DAY)
              AND NOT EXISTS (SELECT 1 FROM nm_cluster_cmd_delivery p WHERE p.command_id=c.id AND p.status='pending') LIMIT 5000");
        while ($r && ($x = $r->fetch_row())) $ids[] = (int)$x[0];
        if ($ids) { $in = implode(',', $ids); @$conn->query("DELETE FROM nm_cluster_cmd_delivery WHERE command_id IN ($in)"); @$conn->query("DELETE FROM nm_cluster_commands WHERE id IN ($in)"); }
        // orphan deliveries (command already gone) — multi-table DELETE can't take LIMIT
        @$conn->query("DELETE d FROM nm_cluster_cmd_delivery d LEFT JOIN nm_cluster_commands c ON c.id=d.command_id WHERE c.id IS NULL");
        // per-device history — keep 7 days (independent of the rollup window)
        @$conn->query("DELETE FROM nm_cluster_dev_history WHERE recorded_at < (UTC_TIMESTAMP() - INTERVAL 7 DAY) LIMIT 50000");
    }
    // Per-install SSL policy for cluster HTTP (default VERIFY ON; set cluster_ssl_verify=0 for self-signed).
    function nm_cluster_ssl_verify($conn): bool { return nm_cluster_setting($conn, 'cluster_ssl_verify', '1') !== '0'; }

    // ── Federated incidents → the CENTRAL notification pipeline ──────────────
    // The master mirrors cluster events as REAL incidents (root_source='cluster') so the
    // existing nm_notify_process notifies them (channels + maintenance window) AND they show
    // in the incident desk — never a side-channel. Upsert by a stable corr_key (idempotent).
    function nm_cluster_emit_incident($conn, string $key, string $title, string $sev, string $entity): void {
        if (!function_exists('nm_inc_ensure')) { $f = __DIR__.'/nm_incidents.php'; if (is_file($f)) require_once $f; }
        if (function_exists('nm_inc_ensure')) nm_inc_ensure($conn);   // robustness: table may not exist yet on a fresh master
        $key = substr($key,0,120); $title = substr($title,0,255); $entity = substr($entity,0,160);
        $sev = in_array($sev,['critical','warning','info'],true) ? $sev : 'warning';
        try {
            $st = $conn->prepare("INSERT INTO nm_incidents (corr_key,title,severity,status,root_source,root_entity,root_node_id,signal_count,impact_count,impact,opened_at,updated_at)
                VALUES (?,?,?,'open','cluster',?,NULL,1,0,'',NOW(),NOW())
                ON DUPLICATE KEY UPDATE title=VALUES(title), severity=VALUES(severity), updated_at=NOW(),
                    status=IF(status='resolved','open',status), resolved_at=IF(status='resolved',NULL,resolved_at)");
            $st->bind_param('ssss',$key,$title,$sev,$entity); $st->execute();
        } catch (\Throwable $e) {}
    }
    // Master cron: reconcile cluster incidents — open for offline sites + mirrored site-criticals,
    // resolve the ones whose condition cleared. Notification is done by the existing notify cron.
    function nm_cluster_sync_incidents($conn): array {
        nm_cluster_ensure($conn);
        $cfg = nm_cluster_cfg($conn);
        if ($cfg['role'] !== 'master') return ['ok'=>false,'note'=>'not master'];
        // The master's OWN site is skipped — its incidents are already local incidents (avoid duplicating them as "[HQ] …").
        $self = $cfg['site_slug'] !== '' ? nm_cluster_slugify($cfg['site_slug']) : 'master';
        $selfEsc = $conn->real_escape_string($self);
        $active = [];
        foreach (nm_cluster_sites($conn) as $s) {
            if ($s['site'] === $self) continue;
            if ($s['status'] === 'offline') {   // was seen, now silent >10min → alarm (not 'never'/'stale' to avoid flapping)
                $k = 'cluster:down:' . $s['site']; $active[$k] = 1;
                nm_cluster_emit_incident($conn, $k, 'Site ' . $s['name'] . ' is offline (no check-in)', 'critical', $s['name']);
            }
        }
        $r = @$conn->query("SELECT c.site_slug, c.ext_id, c.title, s.name FROM nm_cluster_incidents c
            JOIN nm_cluster_sites s ON s.site_slug=c.site_slug WHERE c.severity='critical' AND c.site_slug<>'$selfEsc' LIMIT 100");
        while ($r && ($x = $r->fetch_assoc())) {
            $k = 'cluster:inc:' . $x['site_slug'] . ':' . (int)$x['ext_id']; $active[$k] = 1;
            nm_cluster_emit_incident($conn, $k, '[' . $x['name'] . '] ' . $x['title'], 'critical', $x['name']);
        }
        // resolve cluster incidents no longer active (site recovered / incident cleared at source)
        $now = gmdate('Y-m-d H:i:s'); $resolved = 0;
        $orr = @$conn->query("SELECT id, corr_key FROM nm_incidents WHERE status IN ('open','acknowledged') AND root_source='cluster'");
        while ($orr && ($x = $orr->fetch_assoc())) if (!isset($active[$x['corr_key']])) {
            $conn->query("UPDATE nm_incidents SET status='resolved', resolved_at='$now', updated_at='$now' WHERE id=" . (int)$x['id']); $resolved++;
        }
        return ['ok'=>true, 'active'=>count($active), 'resolved'=>$resolved];
    }

    // ── F3: fleet-wide command queue (Cluster Immunity, etc.) ────────────────
    // Queue a command for a set of sites ('*' = every enabled site, including the
    // master's own). Delivery is per-site (pending → done/failed on ack).
    function nm_cluster_cmd_enqueue($conn, string $type, array $payload, array $sites, ?int $uid): array {
        nm_cluster_ensure($conn);
        $type = substr(trim($type), 0, 24); if ($type === '') return ['ok'=>false,'error'=>'no type'];
        // resolve targets
        $targets = [];
        if (in_array('*', $sites, true)) {
            $r = @$conn->query("SELECT site_slug FROM nm_cluster_sites WHERE enabled=1");
            while ($r && ($x = $r->fetch_row())) $targets[$x[0]] = true;
            // always include the master's own site (its self-row may not exist until its first cron tick)
            $cfg = nm_cluster_cfg($conn);
            if ($cfg['role'] === 'master') $targets[$cfg['site_slug'] !== '' ? nm_cluster_slugify($cfg['site_slug']) : 'master'] = true;
        } else foreach ($sites as $s) { $s = nm_cluster_slugify((string)$s); if ($s !== '') $targets[$s] = true; }
        if (!$targets) return ['ok'=>false,'error'=>'no target sites'];
        $summary = substr((string)($payload['summary'] ?? ($payload['indicator'] ?? $type)), 0, 200);
        $pl = json_encode($payload);
        $st = $conn->prepare("INSERT INTO nm_cluster_commands (type,payload,summary,created_by) VALUES (?,?,?,?)");
        $st->bind_param('sssi', $type, $pl, $summary, $uid); $st->execute();
        $cid = $conn->insert_id;
        $del = $conn->prepare("INSERT IGNORE INTO nm_cluster_cmd_delivery (command_id,site_slug,status) VALUES (?,?,'pending')");
        foreach (array_keys($targets) as $s) { $del->bind_param('is', $cid, $s); $del->execute(); }
        if (function_exists('nm_audit')) nm_audit($conn, 'cluster.cmd_enqueue', ['target_type'=>$type,'target_id'=>$summary,'details'=>['sites'=>array_keys($targets)]]);
        return ['ok'=>true,'id'=>$cid,'targets'=>count($targets)];
    }
    // Commands still pending for a given site (delivered in the ingest response).
    function nm_cluster_cmd_pending_for($conn, string $site): array {
        nm_cluster_ensure($conn);
        $site = nm_cluster_slugify($site); if ($site === '') return [];
        $out = [];
        $r = @$conn->query("SELECT c.id, c.type, c.payload FROM nm_cluster_cmd_delivery d
            JOIN nm_cluster_commands c ON c.id=d.command_id
            WHERE d.site_slug='" . $conn->real_escape_string($site) . "' AND d.status='pending' ORDER BY c.id ASC LIMIT 20");
        while ($r && ($x = $r->fetch_assoc())) $out[] = ['id'=>(int)$x['id'],'type'=>$x['type'],'payload'=>json_decode($x['payload'], true) ?: []];
        return $out;
    }
    function nm_cluster_cmd_ack($conn, string $site, int $cmdId, bool $ok, string $detail = ''): void {
        nm_cluster_ensure($conn);
        $st = $conn->prepare("UPDATE nm_cluster_cmd_delivery SET status=?, detail=?, acted_at=UTC_TIMESTAMP() WHERE command_id=? AND site_slug=?");
        $s = $ok ? 'done' : 'failed'; $d = substr($detail, 0, 255);
        $st->bind_param('ssis', $s, $d, $cmdId, $site); $st->execute();
    }
    // Recent commands + aggregated per-site delivery, for the UI.
    function nm_cluster_cmd_list($conn, int $limit = 30): array {
        nm_cluster_ensure($conn);
        $out = [];
        $r = @$conn->query("SELECT c.*,
            (SELECT COUNT(*) FROM nm_cluster_cmd_delivery d WHERE d.command_id=c.id) total,
            (SELECT COUNT(*) FROM nm_cluster_cmd_delivery d WHERE d.command_id=c.id AND d.status='done') done,
            (SELECT COUNT(*) FROM nm_cluster_cmd_delivery d WHERE d.command_id=c.id AND d.status='failed') failed,
            TIMESTAMPDIFF(SECOND,c.created_at,UTC_TIMESTAMP()) age
            FROM nm_cluster_commands c ORDER BY c.id DESC LIMIT " . max(1,$limit));
        while ($r && ($x = $r->fetch_assoc())) {
            $p = json_decode($x['payload'], true) ?: [];
            $out[] = ['id'=>(int)$x['id'],'type'=>$x['type'],'summary'=>$x['summary'],'payload'=>$p,
                'total'=>(int)$x['total'],'done'=>(int)$x['done'],'failed'=>(int)$x['failed'],
                'pending'=>(int)$x['total']-(int)$x['done']-(int)$x['failed'],'age'=>(int)$x['age']];
        }
        return $out;
    }
    // Apply a command LOCALLY (slave, or the master for its own site). Idempotent.
    function nm_cluster_apply_command($conn, array $cmd): array {
        $type = (string)($cmd['type'] ?? ''); $p = (array)($cmd['payload'] ?? []);
        if ($type === 'block_ip' || $type === 'block') {
            $ind = trim((string)($p['indicator'] ?? '')); if ($ind === '') return ['ok'=>false,'detail'=>'empty indicator'];
            $itype = in_array(($p['ind_type'] ?? 'ip'), ['ip','domain','regex'], true) ? $p['ind_type'] : 'ip';
            if (!function_exists('nm_imm_add_threat')) { $f = __DIR__ . '/nm_immunity.php'; if (is_file($f)) require_once $f; }
            if (!function_exists('nm_imm_add_threat')) return ['ok'=>false,'detail'=>'immunity engine not available'];
            $r = nm_imm_add_threat($conn, $ind, $itype, 'cluster', (string)($p['severity'] ?? 'high'), (string)($p['reason'] ?? 'cluster block'), null, 'cluster');
            if (empty($r['ok'])) return ['ok'=>false,'detail'=>$r['error'] ?? 'add_threat failed'];
            $v = nm_imm_vaccinate($conn, (int)$r['id']);
            return ['ok'=>!empty($v['ok']), 'detail'=>!empty($v['ok']) ? ('blocked ' . $ind . (isset($v['applied'])?(' ('.$v['applied'].' targets)'):'')) : ($v['error'] ?? 'vaccinate failed')];
        }
        // ── F3 Phase-3: remote OPERATIONAL actions, enqueued from the master's Remote Console.
        // Each runs the SAME vetted engine an operator uses locally, under this site's own
        // privilege, and returns a short result echoed back to the master via the ack. Every
        // handler is best-effort (loads its engine if the cron context hasn't) + idempotent.
        if ($type === 'poll_now') {
            $nid = (int)($p['node_id'] ?? 0);
            if ($nid <= 0) return ['ok'=>false,'detail'=>'missing node id'];
            $chk = @$conn->query("SELECT display_name FROM nm_nodes WHERE id=$nid LIMIT 1");
            if (!$chk || !$chk->num_rows) return ['ok'=>false,'detail'=>'unknown node #'.$nid];
            if (!defined('VENV_PYTHON') || !defined('SCRIPTS_DIR')) { $f = __DIR__.'/nm_config.php'; if (is_file($f)) require_once $f; }
            if (!defined('VENV_PYTHON') || !defined('SCRIPTS_DIR')) return ['ok'=>false,'detail'=>'poller not configured on this site'];
            $py = escapeshellarg(VENV_PYTHON); $scr = escapeshellarg(SCRIPTS_DIR.'/nm_poller.py');
            $out = @shell_exec("timeout 45 $py $scr --node ".escapeshellarg((string)$nid)." 2>&1");
            $ran = ($out !== null && strpos((string)$out, 'Poll complete') !== false);
            $verd = '';
            if (function_exists('nm_node_live_verdict')) { $v = nm_node_live_verdict($conn, $nid); $verd = ' · '.($v['state'] ?? '').(($v['detail'] ?? '')!==''?(' · '.$v['detail']):''); }
            return ['ok'=>$ran, 'detail'=>substr($ran ? ('re-polled'.$verd) : 'poll did not complete', 0, 240)];
        }
        if ($type === 'svc_restart') {
            $kind = ($p['kind'] ?? '')==='windows' ? 'windows' : (($p['kind'] ?? '')==='linux' ? 'linux' : '');
            $svc  = trim((string)($p['service'] ?? ''));
            $nid  = (int)($p['node_id'] ?? 0);
            $hid  = (int)($p['host_id'] ?? 0);
            if ($svc === '' || !$kind) return ['ok'=>false,'detail'=>'missing service or kind'];
            if ($kind === 'windows') {
                if (!function_exists('nm_win_service_action_by_id')) { $f = __DIR__.'/nm_winhost.php'; if (is_file($f)) require_once $f; }
                if (!function_exists('nm_win_service_action_by_id')) return ['ok'=>false,'detail'=>'windows engine unavailable'];
                if ($hid <= 0 && $nid > 0) { $r = @$conn->query("SELECT MIN(id) hid FROM nm_win_hosts WHERE node_id=$nid"); $hid = $r ? (int)($r->fetch_assoc()['hid'] ?? 0) : 0; }
                if ($hid <= 0) return ['ok'=>false,'detail'=>'no Windows host mapped to node #'.$nid];
                $a = nm_win_service_action_by_id($conn, $hid, $svc, 'restart', null);
            } else {
                if (!function_exists('nm_lx_service_action_by_id')) { $f = __DIR__.'/nm_linuxhost.php'; if (is_file($f)) require_once $f; }
                if (!function_exists('nm_lx_service_action_by_id')) return ['ok'=>false,'detail'=>'linux engine unavailable'];
                if ($hid <= 0 && $nid > 0) { $r = @$conn->query("SELECT MIN(id) hid FROM nm_lx_hosts WHERE node_id=$nid"); $hid = $r ? (int)($r->fetch_assoc()['hid'] ?? 0) : 0; }
                if ($hid <= 0) return ['ok'=>false,'detail'=>'no Linux host mapped to node #'.$nid];
                $a = nm_lx_service_action_by_id($conn, $hid, $svc, 'restart', null);
            }
            $ok = !empty($a['ok']);
            return ['ok'=>$ok, 'detail'=>substr((string)($a['detail'] ?? $a['error'] ?? ($ok?'restarted':'failed')), 0, 240)];
        }
        if ($type === 'maintenance') {
            $mins = max(1, min(1440, (int)($p['minutes'] ?? 30)));
            $name = substr(trim((string)($p['name'] ?? '')) ?: 'Remote maintenance', 0, 80);
            if (!function_exists('nm_maint_save')) { $f = __DIR__.'/nm_notify.php'; if (is_file($f)) require_once $f; }
            if (!function_exists('nm_maint_save')) return ['ok'=>false,'detail'=>'notify engine unavailable'];
            // Use the DB clock (same basis the maintenance gate checks NOW() against) → tz-safe.
            $b = @$conn->query("SELECT NOW() s, (NOW()+INTERVAL $mins MINUTE) e"); $b = $b ? $b->fetch_assoc() : null;
            if (!$b) return ['ok'=>false,'detail'=>'clock query failed'];
            $r = nm_maint_save($conn, ['name'=>$name,'starts_at'=>$b['s'],'ends_at'=>$b['e'],'scope'=>'all','enabled'=>1]);
            return ['ok'=>!empty($r['ok']), 'detail'=>!empty($r['ok']) ? ('maintenance window '.$mins.'min · alerts silenced till '.$b['e']) : ((string)($r['err'] ?? 'failed'))];
        }
        return ['ok'=>false,'detail'=>'unknown command type: ' . $type];
    }
    // ── Cluster Time-Travel: replay the whole cluster over the rollup history ──
    function nm_cluster_tt_range($conn): array {
        nm_cluster_ensure($conn);
        $r = @$conn->query("SELECT UNIX_TIMESTAMP(MIN(received_at)) mn, UNIX_TIMESTAMP(MAX(received_at)) mx FROM nm_cluster_rollups");
        $x = $r ? $r->fetch_assoc() : null;
        return ['min'=>(int)($x['mn'] ?? 0), 'max'=>(int)($x['mx'] ?? 0)];
    }
    // Each visible site's state as of unix time $at (nearest rollup ≤ $at). Status is relative to
    // that instant: a >10min gap since the last rollup at $at = the site was offline back then.
    function nm_cluster_tt_at($conn, int $at, string $role): array {
        nm_cluster_ensure($conn);
        $at = (int)$at; $out = [];
        foreach (nm_cluster_sites_visible($conn, $role) as $s) {
            $slug = $conn->real_escape_string($s['site']);
            $r = @$conn->query("SELECT node_total,node_up,node_down,node_degraded,inc_open,inc_crit, UNIX_TIMESTAMP(received_at) ts
                FROM nm_cluster_rollups WHERE site_slug='$slug' AND received_at <= FROM_UNIXTIME($at) ORDER BY received_at DESC LIMIT 1");
            $x = $r ? $r->fetch_assoc() : null;
            if ($x) { $gap = $at - (int)$x['ts']; $st = $gap > 600 ? 'offline' : ($gap > 150 ? 'stale' : 'online');
                $out[] = ['site'=>$s['site'],'name'=>$s['name'],'lat'=>$s['lat'],'lon'=>$s['lon'],'status'=>$st,'gap'=>$gap,
                    'nodes'=>['total'=>(int)$x['node_total'],'up'=>(int)$x['node_up'],'down'=>(int)$x['node_down'],'degraded'=>(int)$x['node_degraded']],
                    'incidents'=>['open'=>(int)$x['inc_open'],'critical'=>(int)$x['inc_crit']]];
            } else {
                $out[] = ['site'=>$s['site'],'name'=>$s['name'],'lat'=>$s['lat'],'lon'=>$s['lon'],'status'=>'never','gap'=>null,
                    'nodes'=>['total'=>0,'up'=>0,'down'=>0,'degraded'=>0],'incidents'=>['open'=>0,'critical'=>0]];
            }
        }
        return $out;
    }
    // The MASTER applies commands targeting its OWN site locally (it's a site too), then marks them done.
    function nm_cluster_master_apply_own($conn): int {
        $cfg = nm_cluster_cfg($conn);
        if ($cfg['role'] !== 'master') return 0;
        $slug = $cfg['site_slug'] !== '' ? nm_cluster_slugify($cfg['site_slug']) : 'master';
        $n = 0;
        foreach (nm_cluster_cmd_pending_for($conn, $slug) as $cmd) {
            $ap = nm_cluster_apply_command($conn, $cmd);
            nm_cluster_cmd_ack($conn, $slug, (int)$cmd['id'], !empty($ap['ok']), (string)($ap['detail'] ?? ''));
            $n++;
        }
        return $n;
    }
}
