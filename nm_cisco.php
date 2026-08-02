<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Cisco Suite engine (F0 foundation).
//   · Detection / capability model for Cisco devices (switch|router|firewall|wlc).
//   · Guarded schema for Cisco-specific facts (env sensors + CDP/LLDP neighbors).
//   · Ingest helpers (replace-per-device) used by cron_cisco.php.
//   · Read accessors used by cisco.php (fleet hub).
//
// Time-series (CPU/mem/interfaces) are NOT duplicated here — those already flow
// through the generic poller into nm_device_stats / nm_port_stats. This engine only
// owns the Cisco-specific extras the generic path can't express (per-sensor state,
// neighbor adjacencies). mysqli is in EXCEPTION mode → every ALTER/CREATE is guarded
// and every non-critical write is best-effort (try/catch).
//
// See docs/NEURU_CISCO_SUITE_PLAN.md for the full blueprint.
// ─────────────────────────────────────────────────────────────────────────────

if (!function_exists('nm_cisco_ensure')) {

    // Bump whenever the CREATE list OR the admin grant list changes, so existing
    // installs re-run the migration (v1=env+neighbors, v2=+ports/vlans, v3=+cisco_switch grant,
    // v4=+nm_asa_status + cisco_asa grant, v5=+nm_cisco_routing/ipsla + cisco_router grant,
    // v6=+nm_cisco_config + nm_cisco_orch_pending + cisco_orch grant).
    if (!defined('NM_CISCO_SCHEMA_VER')) define('NM_CISCO_SCHEMA_VER', '6');

    // Schema + RBAC bootstrap. Called only from the Cisco pages + cron (not hot).
    function nm_cisco_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;

        // RBAC grants run EVERY call (cheap, idempotent) — NOT behind the schema-version
        // gate, so a newly-added Cisco page's nav item appears even when the schema is
        // already current. (Gating grants behind the version flag silently dropped new
        // grants on installs already at that version — a bug that bit cisco_switch/cisco_asa.)
        foreach (['cisco','cisco_switch','cisco_asa','cisco_router','cisco_orch'] as $pk) {
            try {
                $st = $conn->prepare("INSERT INTO role_profiles (role_name,button_key,enabled)
                                      VALUES ('admin',?,1) ON DUPLICATE KEY UPDATE enabled=enabled");
                $st->bind_param('s', $pk); $st->execute(); $st->close();
            } catch (\Throwable $e) { /* best-effort */ }
        }

        // Expensive DDL stays version-gated.
        try {
            $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='nm_cisco_schema' LIMIT 1");
            if ($r && ($x = $r->fetch_assoc()) && (string)$x['setting_val'] === NM_CISCO_SCHEMA_VER) return; // up to date
        } catch (\Throwable $e) { /* nm_settings may be absent on a bare install */ }

        try {
            $conn->query("CREATE TABLE IF NOT EXISTS nm_cisco_env (
                id INT NOT NULL AUTO_INCREMENT,
                node_id INT NOT NULL,
                kind VARCHAR(16) NOT NULL,            /* temp|fan|psu|volt|other */
                sensor VARCHAR(160) NOT NULL,
                value DECIMAL(12,2) DEFAULT NULL,
                unit VARCHAR(16) DEFAULT NULL,
                state VARCHAR(20) DEFAULT NULL,       /* normal|warning|critical|shutdown|notPresent|notFunctioning */
                threshold DECIMAL(12,2) DEFAULT NULL,
                updated_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                UNIQUE KEY uk_env (node_id, kind, sensor),
                KEY idx_node (node_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $conn->query("CREATE TABLE IF NOT EXISTS nm_cisco_neighbors (
                id INT NOT NULL AUTO_INCREMENT,
                node_id INT NOT NULL,
                proto VARCHAR(8) NOT NULL DEFAULT 'cdp',   /* cdp|lldp */
                local_if VARCHAR(120) DEFAULT NULL,
                neighbor_name VARCHAR(200) DEFAULT NULL,
                neighbor_ip VARCHAR(45) DEFAULT NULL,
                remote_if VARCHAR(120) DEFAULT NULL,
                platform VARCHAR(200) DEFAULT NULL,
                capabilities VARCHAR(120) DEFAULT NULL,
                matched_node_id INT DEFAULT NULL,           /* resolved to an nm_nodes.id if we know it */
                updated_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                UNIQUE KEY uk_nb (node_id, local_if, neighbor_name),
                KEY idx_node (node_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            // F1 — switch front-panel: per-port facts (traffic stays in nm_port_stats).
            $conn->query("CREATE TABLE IF NOT EXISTS nm_cisco_ports (
                id INT NOT NULL AUTO_INCREMENT,
                node_id INT NOT NULL,
                if_index INT NOT NULL,
                if_name VARCHAR(120) DEFAULT NULL,
                admin_status VARCHAR(12) DEFAULT NULL,   /* up|down|testing */
                oper_status VARCHAR(12) DEFAULT NULL,     /* up|down|dormant|... */
                speed_mbps INT DEFAULT NULL,
                duplex VARCHAR(8) DEFAULT NULL,           /* full|half|unknown */
                vlan INT DEFAULT NULL,
                if_type INT DEFAULT NULL,                 /* IANAifType (6=ethernet) */
                poe_status VARCHAR(16) DEFAULT NULL,      /* delivering|searching|disabled|fault|off */
                poe_watts DECIMAL(7,2) DEFAULT NULL,
                updated_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                UNIQUE KEY uk_port (node_id, if_index),
                KEY idx_node (node_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $conn->query("CREATE TABLE IF NOT EXISTS nm_cisco_vlans (
                id INT NOT NULL AUTO_INCREMENT,
                node_id INT NOT NULL,
                vlan_id INT NOT NULL,
                name VARCHAR(120) DEFAULT NULL,
                state VARCHAR(16) DEFAULT NULL,
                port_count INT DEFAULT 0,
                updated_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                UNIQUE KEY uk_vlan (node_id, vlan_id),
                KEY idx_node (node_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            // F2 — ASA firewall status (one row per device, upserted).
            $conn->query("CREATE TABLE IF NOT EXISTS nm_asa_status (
                node_id INT NOT NULL,
                conn_current BIGINT DEFAULT NULL,
                conn_peak BIGINT DEFAULT NULL,
                xlate_current BIGINT DEFAULT NULL,
                ra_sessions INT DEFAULT NULL,
                ra_users INT DEFAULT NULL,
                ra_max INT DEFAULT NULL,
                ipsec_ike INT DEFAULT NULL,
                ipsec_tunnels INT DEFAULT NULL,
                failover_role VARCHAR(16) DEFAULT NULL,
                failover_state VARCHAR(16) DEFAULT NULL,
                failover_detail VARCHAR(255) DEFAULT NULL,
                updated_at DATETIME NOT NULL,
                PRIMARY KEY (node_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            // F3 — router control-plane: BGP/OSPF/HSRP peers (unified) + IP SLA operations.
            $conn->query("CREATE TABLE IF NOT EXISTS nm_cisco_routing (
                id INT NOT NULL AUTO_INCREMENT,
                node_id INT NOT NULL,
                proto VARCHAR(8) NOT NULL,            /* bgp|ospf|hsrp */
                peer VARCHAR(64) NOT NULL,            /* neighbor IP, or if/group for hsrp */
                state VARCHAR(20) DEFAULT NULL,
                info VARCHAR(120) DEFAULT NULL,       /* remote AS / router-id / vip=... */
                uptime_secs BIGINT DEFAULT NULL,
                updated_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                UNIQUE KEY uk_route (node_id, proto, peer),
                KEY idx_node (node_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $conn->query("CREATE TABLE IF NOT EXISTS nm_cisco_ipsla (
                id INT NOT NULL AUTO_INCREMENT,
                node_id INT NOT NULL,
                oper_index INT NOT NULL,
                tag VARCHAR(120) DEFAULT NULL,
                rtt_ms INT DEFAULT NULL,
                sense VARCHAR(20) DEFAULT NULL,       /* ok|timeout|overThreshold|... */
                updated_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                UNIQUE KEY uk_sla (node_id, oper_index),
                KEY idx_node (node_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            // F4 — Orchestrator: config version history + armed Safe-Apply (commit-confirm) ledger.
            $conn->query("CREATE TABLE IF NOT EXISTS nm_cisco_config (
                id INT NOT NULL AUTO_INCREMENT,
                node_id INT NOT NULL,
                version INT NOT NULL,
                sha256 CHAR(64) DEFAULT NULL,
                config_text MEDIUMTEXT,
                added INT DEFAULT 0,
                removed INT DEFAULT 0,
                captured_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                KEY idx_node_ver (node_id, version)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $conn->query("CREATE TABLE IF NOT EXISTS nm_cisco_orch_pending (
                token VARCHAR(40) NOT NULL,
                node_id INT NOT NULL,
                platform VARCHAR(12) DEFAULT NULL,
                method VARCHAR(12) DEFAULT NULL,     /* reload|commit|checkpoint */
                keep_cmds MEDIUMTEXT,
                revert_cmds MEDIUMTEXT,
                window_min INT DEFAULT NULL,
                status VARCHAR(12) DEFAULT 'armed',  /* armed|kept|reverted|expired */
                created_at DATETIME NOT NULL,
                created_by INT DEFAULT NULL,
                PRIMARY KEY (token),
                KEY idx_node (node_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
            $schema_ok = true;
        } catch (\Throwable $e) { $schema_ok = false; /* never let a schema probe take down a page */ }

        // ONLY advance the version flag if every CREATE succeeded — otherwise a swallowed
        // CREATE error would lock the migration out forever (flag past, table missing).
        if (!empty($schema_ok)) {
            try {
                $ver = NM_CISCO_SCHEMA_VER;
                $conn->query("INSERT INTO nm_settings(setting_key,setting_val) VALUES('nm_cisco_schema','$ver')
                              ON DUPLICATE KEY UPDATE setting_val='$ver'");
            } catch (\Throwable $e) {}
        }
    }

    // ── Detection / capabilities ────────────────────────────────────────────

    function nm_cisco_is_cisco(array $n): bool {
        $os = strtolower(trim((string)($n['os_icon'] ?? '')));
        if ($os === 'cisco') return true;
        $hw = strtolower((string)($n['hw_model'] ?? ''));
        return (strpos($hw, 'cisco') !== false) || (strpos($hw, ' ios') !== false)
            || (strpos($hw, 'catalyst') !== false) || (strpos($hw, 'nexus') !== false)
            || (strpos($hw, 'asa') !== false);
    }

    // Best-effort device class from hw_model / sysDescr (stored in hw_model).
    function nm_cisco_class(array $n): string {
        $hw = strtolower((string)($n['hw_model'] ?? ''));
        $nm = strtolower((string)($n['display_name'] ?? ''));
        $s  = $hw . ' ' . $nm;
        if (strpos($s, 'asa') !== false || strpos($s, 'firepower') !== false || strpos($s, 'ftd') !== false) return 'firewall';
        if (strpos($s, 'catalyst') !== false || strpos($s, 'nexus') !== false || strpos($s, 'switch') !== false
            || strpos($hw, 'ws-c') !== false || strpos($hw, 'c9') !== false) return 'switch';
        if (strpos($s, 'aironet') !== false || strpos($s, 'aireos') !== false || strpos($s, 'controller') !== false
            || strpos($s, 'wlc') !== false || strpos($s, 'mobility') !== false) return 'wlc';
        if (strpos($s, 'isr') !== false || strpos($s, 'asr') !== false || strpos($s, 'router') !== false
            || strpos($hw, 'cisco') !== false) return 'router';
        return 'generic';
    }

    // Capability map — each page/poller asks instead of hardcoding.
    function nm_cisco_caps(array $n): array {
        $c = nm_cisco_class($n);
        return [
            'class'    => $c,
            'env'      => in_array($c, ['switch','router','firewall'], true),
            'cdp'      => in_array($c, ['switch','router'], true),
            'poe'      => $c === 'switch',
            'stack'    => $c === 'switch',
            'vlan'     => $c === 'switch',
            'stp'      => $c === 'switch',
            'bgp'      => $c === 'router',
            'ospf'     => $c === 'router',
            'hsrp'     => in_array($c, ['router','switch'], true),
            'ipsla'    => $c === 'router',
            'vpn'      => $c === 'firewall',
            'failover' => $c === 'firewall',
            'wireless' => $c === 'wlc',
        ];
    }

    function nm_cisco_class_label(string $c): string {
        return [
            'switch'   => 'Switch',
            'router'   => 'Router',
            'firewall' => 'ASA / Firewall',
            'wlc'      => 'Wireless Controller',
            'generic'  => 'Cisco Device',
        ][$c] ?? 'Cisco Device';
    }

    // ── Fleet / device reads ─────────────────────────────────────────────────

    // All Cisco nodes with basic identity + capability class.
    function nm_cisco_nodes($conn): array {
        $out = [];
        try {
            $r = $conn->query("SELECT id, display_name, ip_address, hostname, os_icon, hw_model,
                                      location, monitor_type, snmp_community, snmp_version
                               FROM nm_nodes ORDER BY display_name");
            while ($r && $x = $r->fetch_assoc()) {
                if (!nm_cisco_is_cisco($x)) continue;
                $x['cisco_class'] = nm_cisco_class($x);
                $x['caps']        = nm_cisco_caps($x);
                $out[] = $x;
            }
        } catch (\Throwable $e) {}
        return $out;
    }

    // Latest value for a nm_device_stats metric (e.g. type='cpu' key='avg').
    function nm_cisco_latest_metric($conn, int $node_id, string $type, ?string $key = null): ?float {
        try {
            if ($key !== null) {
                $st = $conn->prepare("SELECT value FROM nm_device_stats
                                      WHERE node_id=? AND metric_type=? AND metric_key=?
                                      ORDER BY recorded_at DESC LIMIT 1");
                $st->bind_param('iss', $node_id, $type, $key);
            } else {
                $st = $conn->prepare("SELECT value FROM nm_device_stats
                                      WHERE node_id=? AND metric_type=?
                                      ORDER BY recorded_at DESC LIMIT 1");
                $st->bind_param('is', $node_id, $type);
            }
            $st->execute(); $st->bind_result($v); $ok = $st->fetch(); $st->close();
            return $ok ? (float)$v : null;
        } catch (\Throwable $e) { return null; }
    }

    function nm_cisco_env_list($conn, int $node_id): array {
        $out = [];
        try {
            $st = $conn->prepare("SELECT kind,sensor,value,unit,state,threshold,updated_at
                                  FROM nm_cisco_env WHERE node_id=? ORDER BY kind,sensor");
            $st->bind_param('i', $node_id); $st->execute();
            $res = $st->get_result();
            while ($x = $res->fetch_assoc()) $out[] = $x;
            $st->close();
        } catch (\Throwable $e) {}
        return $out;
    }

    // Worst env state for a node → for the fleet card badge.
    function nm_cisco_env_worst($conn, int $node_id): string {
        $rank = ['critical'=>4,'shutdown'=>4,'notFunctioning'=>3,'warning'=>2,'normal'=>1];
        $worst = ''; $wr = 0;
        foreach (nm_cisco_env_list($conn, $node_id) as $e) {
            $s = (string)($e['state'] ?? '');
            $r = $rank[$s] ?? 0;
            if ($r > $wr) { $wr = $r; $worst = $s; }
        }
        return $worst;
    }

    function nm_cisco_neighbors($conn, int $node_id): array {
        $out = [];
        try {
            $st = $conn->prepare("SELECT proto,local_if,neighbor_name,neighbor_ip,remote_if,platform,capabilities,matched_node_id,updated_at
                                  FROM nm_cisco_neighbors WHERE node_id=? ORDER BY local_if");
            $st->bind_param('i', $node_id); $st->execute();
            $res = $st->get_result();
            while ($x = $res->fetch_assoc()) $out[] = $x;
            $st->close();
        } catch (\Throwable $e) {}
        return $out;
    }

    // ── Active poll (env + CDP) via the Python collector ─────────────────────
    // Shells scripts/nm_cisco_poll.py for the Cisco fleet (or one node) and ingests.
    // Shared by cron_cisco.php and cisco.php?api=repoll. Returns a summary array.
    function nm_cisco_poll_now($conn, ?int $only_node = null): array {
        $targets = [];
        foreach (nm_cisco_nodes($conn) as $n) {
            if ($only_node !== null && (int)$n['id'] !== $only_node) continue;
            $ip   = trim((string)($n['ip_address'] ?? ''));
            $comm = trim((string)($n['snmp_community'] ?? ''));
            $ver  = (string)($n['snmp_version'] ?? 'v2c');
            if ($ip === '' || $comm === '') continue;
            if (($n['monitor_type'] ?? 'snmp') === 'ping') continue;
            if ($ver === 'v3') continue; // collector supports v1/v2c only
            $caps = $n['caps'] ?? nm_cisco_caps($n);
            $mods = [];
            if (!empty($caps['env'])) $mods[] = 'env';
            if (!empty($caps['cdp'])) $mods[] = 'cdp';
            if (($caps['class'] ?? '') === 'switch') $mods[] = 'switch';
            if (($caps['class'] ?? '') === 'firewall') $mods[] = 'asa';
            if (($caps['class'] ?? '') === 'router') $mods[] = 'router';
            if (!$mods) $mods = ['env','cdp'];
            $targets[] = ['node_id'=>(int)$n['id'], 'ip'=>$ip, 'comm'=>$comm, 'ver'=>$ver, 'mods'=>$mods];
        }
        $summary = ['targets'=>count($targets), 'env'=>0, 'neighbors'=>0, 'errors'=>0];
        if (!$targets) return $summary;

        $scr   = __DIR__ . '/scripts/nm_cisco_poll.py';
        $descr = [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']];
        $out   = '';
        $proc  = @proc_open(['/usr/bin/python3', $scr], $descr, $pipes);
        if (is_resource($proc)) {
            fwrite($pipes[0], json_encode(['targets'=>$targets])); fclose($pipes[0]);
            $out = stream_get_contents($pipes[1]); fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($proc);
        }
        $data = json_decode($out, true);
        if (is_array($data)) {
            foreach ($data as $nid => $d) {
                $nid = (int)$nid;
                if (empty($d['ok'])) { $summary['errors']++; continue; } // total timeout → keep last-known
                // device responded → ingest (even empty arrays clear stale rows)
                $summary['env']       += nm_cisco_ingest_env($conn, $nid, is_array($d['env'] ?? null) ? $d['env'] : []);
                $summary['neighbors'] += nm_cisco_ingest_neighbors($conn, $nid, is_array($d['neighbors'] ?? null) ? $d['neighbors'] : []);
                if (isset($d['ports']))   $summary['ports'] = ($summary['ports'] ?? 0) + nm_cisco_ingest_ports($conn, $nid, is_array($d['ports']) ? $d['ports'] : []);
                if (isset($d['vlans']))   $summary['vlans'] = ($summary['vlans'] ?? 0) + nm_cisco_ingest_vlans($conn, $nid, is_array($d['vlans']) ? $d['vlans'] : []);
                if (isset($d['asa']))    { if (nm_cisco_ingest_asa($conn, $nid, is_array($d['asa']) ? $d['asa'] : [])) $summary['asa'] = ($summary['asa'] ?? 0) + 1; }
                if (isset($d['routing'])) $summary['routing'] = ($summary['routing'] ?? 0) + nm_cisco_ingest_routing($conn, $nid, is_array($d['routing']) ? $d['routing'] : []);
                if (isset($d['ipsla']))   $summary['ipsla'] = ($summary['ipsla'] ?? 0) + nm_cisco_ingest_ipsla($conn, $nid, is_array($d['ipsla']) ? $d['ipsla'] : []);
            }
        }
        return $summary;
    }

    // ── Ingest (replace-per-device, best-effort) ─────────────────────────────

    // $rows: [ ['kind'=>'temp','sensor'=>'Chassis','value'=>41,'unit'=>'C','state'=>'normal','threshold'=>75], ... ]
    function nm_cisco_ingest_env($conn, int $node_id, array $rows): int {
        $now = gmdate('Y-m-d H:i:s'); $n = 0;
        try { $conn->begin_transaction(); } catch (\Throwable $e) {}
        try {
            $del = $conn->prepare("DELETE FROM nm_cisco_env WHERE node_id=?");
            $del->bind_param('i', $node_id); $del->execute(); $del->close();

            $ins = $conn->prepare("INSERT INTO nm_cisco_env
                (node_id,kind,sensor,value,unit,state,threshold,updated_at)
                VALUES (?,?,?,?,?,?,?,?)
                ON DUPLICATE KEY UPDATE value=VALUES(value),unit=VALUES(unit),
                    state=VALUES(state),threshold=VALUES(threshold),updated_at=VALUES(updated_at)");
            foreach ($rows as $r) {
                $kind   = substr((string)($r['kind'] ?? 'other'), 0, 16);
                $sensor = substr((string)($r['sensor'] ?? ''), 0, 160);
                if ($sensor === '') continue;
                $value  = isset($r['value']) && $r['value'] !== '' ? (float)$r['value'] : null;
                $unit   = isset($r['unit']) ? substr((string)$r['unit'], 0, 16) : null;
                $state  = isset($r['state']) ? substr((string)$r['state'], 0, 20) : null;
                $thr    = isset($r['threshold']) && $r['threshold'] !== '' ? (float)$r['threshold'] : null;
                $ins->bind_param('issdssds', $node_id, $kind, $sensor, $value, $unit, $state, $thr, $now);
                $ins->execute(); $n++;

                // Numeric env values also flow into the time-series for Predictive Health.
                if ($value !== null && in_array($kind, ['temp','volt'], true)) {
                    try {
                        $mt = 'cisco_env';
                        $mk = substr($kind.':'.$sensor, 0, 200);
                        $ts = $conn->prepare("INSERT INTO nm_device_stats (node_id,recorded_at,metric_type,metric_key,value)
                                              VALUES (?,?,?,?,?)");
                        $rec = date('Y-m-d H:i:s');
                        $ts->bind_param('isssd', $node_id, $rec, $mt, $mk, $value);
                        $ts->execute(); $ts->close();
                    } catch (\Throwable $e) {}
                }
            }
            $ins->close();
            try { $conn->commit(); } catch (\Throwable $e) {}
        } catch (\Throwable $e) {
            try { $conn->rollback(); } catch (\Throwable $e2) {}
        }
        return $n;
    }

    // $rows: [ ['local_if'=>'Gi1/0/1','neighbor_name'=>'SW2','neighbor_ip'=>'10.0.0.2',
    //          'remote_if'=>'Gi1/0/24','platform'=>'WS-C2960','proto'=>'cdp'], ... ]
    function nm_cisco_ingest_neighbors($conn, int $node_id, array $rows): int {
        $now = gmdate('Y-m-d H:i:s'); $n = 0;
        // Build an IP→node_id map once so we can resolve adjacencies we already monitor.
        $ipmap = [];
        try {
            $r = $conn->query("SELECT id, ip_address FROM nm_nodes WHERE ip_address IS NOT NULL AND ip_address<>''");
            while ($r && $x = $r->fetch_assoc()) $ipmap[$x['ip_address']] = (int)$x['id'];
        } catch (\Throwable $e) {}

        try { $conn->begin_transaction(); } catch (\Throwable $e) {}
        try {
            $del = $conn->prepare("DELETE FROM nm_cisco_neighbors WHERE node_id=?");
            $del->bind_param('i', $node_id); $del->execute(); $del->close();

            $ins = $conn->prepare("INSERT INTO nm_cisco_neighbors
                (node_id,proto,local_if,neighbor_name,neighbor_ip,remote_if,platform,capabilities,matched_node_id,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                ON DUPLICATE KEY UPDATE neighbor_ip=VALUES(neighbor_ip),remote_if=VALUES(remote_if),
                    platform=VALUES(platform),capabilities=VALUES(capabilities),
                    matched_node_id=VALUES(matched_node_id),updated_at=VALUES(updated_at)");
            foreach ($rows as $r) {
                $proto = substr((string)($r['proto'] ?? 'cdp'), 0, 8);
                $lif   = isset($r['local_if']) ? substr((string)$r['local_if'], 0, 120) : null;
                $nn    = isset($r['neighbor_name']) ? substr((string)$r['neighbor_name'], 0, 200) : '';
                if ($nn === '') continue;
                $nip   = isset($r['neighbor_ip']) ? substr((string)$r['neighbor_ip'], 0, 45) : null;
                $rif   = isset($r['remote_if']) ? substr((string)$r['remote_if'], 0, 120) : null;
                $plat  = isset($r['platform']) ? substr((string)$r['platform'], 0, 200) : null;
                $caps  = isset($r['capabilities']) ? substr((string)$r['capabilities'], 0, 120) : null;
                $match = ($nip !== null && isset($ipmap[$nip])) ? $ipmap[$nip] : null;
                $ins->bind_param('isssssssis', $node_id, $proto, $lif, $nn, $nip, $rif, $plat, $caps, $match, $now);
                $ins->execute(); $n++;
            }
            $ins->close();
            try { $conn->commit(); } catch (\Throwable $e) {}
        } catch (\Throwable $e) {
            try { $conn->rollback(); } catch (\Throwable $e2) {}
        }
        return $n;
    }

    // $rows: [ ['if_index'=>1,'if_name'=>'Gi1/0/1','admin_status'=>'up','oper_status'=>'up',
    //          'speed_mbps'=>1000,'duplex'=>'full','vlan'=>10,'if_type'=>6,
    //          'poe_status'=>'delivering','poe_watts'=>6.4], ... ]
    function nm_cisco_ingest_ports($conn, int $node_id, array $rows): int {
        $now = gmdate('Y-m-d H:i:s'); $n = 0;
        try { $conn->begin_transaction(); } catch (\Throwable $e) {}
        try {
            $del = $conn->prepare("DELETE FROM nm_cisco_ports WHERE node_id=?");
            $del->bind_param('i', $node_id); $del->execute(); $del->close();

            $ins = $conn->prepare("INSERT INTO nm_cisco_ports
                (node_id,if_index,if_name,admin_status,oper_status,speed_mbps,duplex,vlan,if_type,poe_status,poe_watts,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON DUPLICATE KEY UPDATE if_name=VALUES(if_name),admin_status=VALUES(admin_status),
                    oper_status=VALUES(oper_status),speed_mbps=VALUES(speed_mbps),duplex=VALUES(duplex),
                    vlan=VALUES(vlan),if_type=VALUES(if_type),poe_status=VALUES(poe_status),
                    poe_watts=VALUES(poe_watts),updated_at=VALUES(updated_at)");
            foreach ($rows as $r) {
                $ifx = (int)($r['if_index'] ?? 0);
                if ($ifx <= 0) continue;
                $nm  = isset($r['if_name']) ? substr((string)$r['if_name'], 0, 120) : null;
                $ad  = isset($r['admin_status']) ? substr((string)$r['admin_status'], 0, 12) : null;
                $op  = isset($r['oper_status']) ? substr((string)$r['oper_status'], 0, 12) : null;
                $sp  = isset($r['speed_mbps']) && $r['speed_mbps'] !== '' ? (int)$r['speed_mbps'] : null;
                $dx  = isset($r['duplex']) ? substr((string)$r['duplex'], 0, 8) : null;
                $vl  = isset($r['vlan']) && $r['vlan'] !== '' ? (int)$r['vlan'] : null;
                $ty  = isset($r['if_type']) && $r['if_type'] !== '' ? (int)$r['if_type'] : null;
                $pst = isset($r['poe_status']) ? substr((string)$r['poe_status'], 0, 16) : null;
                $pw  = isset($r['poe_watts']) && $r['poe_watts'] !== '' ? (float)$r['poe_watts'] : null;
                // types: node_id i, if_index i, if_name s, admin s, oper s, speed i,
                //        duplex s, vlan i, if_type i, poe_status s, poe_watts d, updated_at s
                $ins->bind_param('iisssisiisds', $node_id, $ifx, $nm, $ad, $op, $sp, $dx, $vl, $ty, $pst, $pw, $now);
                $ins->execute(); $n++;
            }
            $ins->close();
            try { $conn->commit(); } catch (\Throwable $e) {}
        } catch (\Throwable $e) {
            try { $conn->rollback(); } catch (\Throwable $e2) {}
        }
        return $n;
    }

    // $rows: [ ['vlan_id'=>10,'name'=>'DATA','state'=>'active','port_count'=>4], ... ]
    function nm_cisco_ingest_vlans($conn, int $node_id, array $rows): int {
        $now = gmdate('Y-m-d H:i:s'); $n = 0;
        try { $conn->begin_transaction(); } catch (\Throwable $e) {}
        try {
            $del = $conn->prepare("DELETE FROM nm_cisco_vlans WHERE node_id=?");
            $del->bind_param('i', $node_id); $del->execute(); $del->close();

            $ins = $conn->prepare("INSERT INTO nm_cisco_vlans (node_id,vlan_id,name,state,port_count,updated_at)
                VALUES (?,?,?,?,?,?)
                ON DUPLICATE KEY UPDATE name=VALUES(name),state=VALUES(state),
                    port_count=VALUES(port_count),updated_at=VALUES(updated_at)");
            foreach ($rows as $r) {
                $vid = (int)($r['vlan_id'] ?? 0);
                if ($vid <= 0) continue;
                $nm  = isset($r['name']) ? substr((string)$r['name'], 0, 120) : null;
                $stt = isset($r['state']) ? substr((string)$r['state'], 0, 16) : null;
                $pc  = (int)($r['port_count'] ?? 0);
                $ins->bind_param('iissis', $node_id, $vid, $nm, $stt, $pc, $now);
                $ins->execute(); $n++;
            }
            $ins->close();
            try { $conn->commit(); } catch (\Throwable $e) {}
        } catch (\Throwable $e) {
            try { $conn->rollback(); } catch (\Throwable $e2) {}
        }
        return $n;
    }

    // Ports with live traffic joined from nm_port_stats (latest sample per port).
    function nm_cisco_ports_list($conn, int $node_id): array {
        $out = [];
        try {
            $st = $conn->prepare("SELECT if_index,if_name,admin_status,oper_status,speed_mbps,duplex,vlan,if_type,poe_status,poe_watts
                                  FROM nm_cisco_ports WHERE node_id=? ORDER BY if_index");
            $st->bind_param('i', $node_id); $st->execute();
            $res = $st->get_result();
            while ($x = $res->fetch_assoc()) $out[(int)$x['if_index']] = $x;
            $st->close();
        } catch (\Throwable $e) { return array_values($out); }

        // overlay live traffic: latest nm_port_stats per interface, keyed by if_index via nm_interfaces
        try {
            $st = $conn->prepare("SELECT i.if_index, ps.in_rate, ps.out_rate, ps.if_speed, ps.in_util, ps.out_util
                FROM nm_interfaces i
                JOIN nm_port_stats ps ON ps.port_id=i.id
                JOIN (SELECT port_id, MAX(recorded_at) mx FROM nm_port_stats WHERE node_id=? GROUP BY port_id) t
                  ON t.port_id=ps.port_id AND t.mx=ps.recorded_at
                WHERE i.node_id=?");
            $st->bind_param('ii', $node_id, $node_id); $st->execute();
            $res = $st->get_result();
            while ($x = $res->fetch_assoc()) {
                $ifx = (int)$x['if_index'];
                if (isset($out[$ifx])) {
                    $out[$ifx]['in_rate']  = (float)$x['in_rate'];
                    $out[$ifx]['out_rate'] = (float)$x['out_rate'];
                    $out[$ifx]['in_util']  = $x['in_util'] !== null ? (float)$x['in_util'] : null;
                    $out[$ifx]['out_util'] = $x['out_util'] !== null ? (float)$x['out_util'] : null;
                }
            }
            $st->close();
        } catch (\Throwable $e) {}
        return array_values($out);
    }

    function nm_cisco_vlans_list($conn, int $node_id): array {
        $out = [];
        try {
            $st = $conn->prepare("SELECT vlan_id,name,state,port_count FROM nm_cisco_vlans WHERE node_id=? ORDER BY vlan_id");
            $st->bind_param('i', $node_id); $st->execute();
            $res = $st->get_result();
            while ($x = $res->fetch_assoc()) $out[] = $x;
            $st->close();
        } catch (\Throwable $e) {}
        return $out;
    }

    // ── ASA (F2) ─────────────────────────────────────────────────────────────
    // $a: scalar map from collect_asa: conn_current, conn_peak, xlate_current,
    //     ra_sessions, ra_users, ra_max, ipsec_ike, ipsec_tunnels,
    //     failover_role, failover_state, failover_detail. Missing keys → NULL.
    function nm_cisco_ingest_asa($conn, int $node_id, array $a): bool {
        if (!$a) return false;
        $now = gmdate('Y-m-d H:i:s');
        $iv = function($k) use ($a) { return isset($a[$k]) && $a[$k] !== '' ? (int)$a[$k] : null; };
        $sv = function($k) use ($a) { return isset($a[$k]) && $a[$k] !== '' ? substr((string)$a[$k],0,255) : null; };
        $cc=$iv('conn_current'); $cp=$iv('conn_peak'); $xc=$iv('xlate_current');
        $rs=$iv('ra_sessions'); $ru=$iv('ra_users'); $rm=$iv('ra_max');
        $ik=$iv('ipsec_ike'); $it=$iv('ipsec_tunnels');
        $fr=$sv('failover_role'); $fs=$sv('failover_state'); $fd=$sv('failover_detail');
        try {
            $st = $conn->prepare("INSERT INTO nm_asa_status
                (node_id,conn_current,conn_peak,xlate_current,ra_sessions,ra_users,ra_max,
                 ipsec_ike,ipsec_tunnels,failover_role,failover_state,failover_detail,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON DUPLICATE KEY UPDATE conn_current=VALUES(conn_current),conn_peak=VALUES(conn_peak),
                    xlate_current=VALUES(xlate_current),ra_sessions=VALUES(ra_sessions),ra_users=VALUES(ra_users),
                    ra_max=VALUES(ra_max),ipsec_ike=VALUES(ipsec_ike),ipsec_tunnels=VALUES(ipsec_tunnels),
                    failover_role=VALUES(failover_role),failover_state=VALUES(failover_state),
                    failover_detail=VALUES(failover_detail),updated_at=VALUES(updated_at)");
            // 9 ints (node_id + 8 scalars) + 4 strings (role,state,detail,updated_at) = 13
            $st->bind_param('iiiiiiiiissss', $node_id, $cc, $cp, $xc, $rs, $ru, $rm, $ik, $it, $fr, $fs, $fd, $now);
            $st->execute(); $st->close();
        } catch (\Throwable $e) { return false; }

        // trends → nm_device_stats
        $rec = date('Y-m-d H:i:s');
        $push = function($type,$key,$val) use ($conn,$node_id,$rec) {
            if ($val === null) return;
            try { $st=$conn->prepare("INSERT INTO nm_device_stats (node_id,recorded_at,metric_type,metric_key,value) VALUES (?,?,?,?,?)");
                  $v=(float)$val; $st->bind_param('isssd',$node_id,$rec,$type,$key,$v); $st->execute(); $st->close(); } catch (\Throwable $e) {}
        };
        $push('cisco_conn','current',$cc); $push('cisco_conn','xlate',$xc);
        $push('cisco_vpn','ra_sessions',$rs); $push('cisco_vpn','ipsec',$it);
        return true;
    }

    function nm_cisco_asa_status($conn, int $node_id): ?array {
        try {
            $st = $conn->prepare("SELECT conn_current,conn_peak,xlate_current,ra_sessions,ra_users,ra_max,
                                         ipsec_ike,ipsec_tunnels,failover_role,failover_state,failover_detail,updated_at
                                  FROM nm_asa_status WHERE node_id=?");
            $st->bind_param('i', $node_id); $st->execute();
            $res = $st->get_result(); $row = $res->fetch_assoc(); $st->close();
            return $row ?: null;
        } catch (\Throwable $e) { return null; }
    }

    // ── Router control-plane (F3) ────────────────────────────────────────────
    // $rows: [ ['proto'=>'bgp','peer'=>'10.0.0.2','state'=>'established','info'=>'AS 65002','uptime_secs'=>86400], ... ]
    function nm_cisco_ingest_routing($conn, int $node_id, array $rows): int {
        $now = gmdate('Y-m-d H:i:s'); $n = 0;
        try { $conn->begin_transaction(); } catch (\Throwable $e) {}
        try {
            $del = $conn->prepare("DELETE FROM nm_cisco_routing WHERE node_id=?");
            $del->bind_param('i', $node_id); $del->execute(); $del->close();

            $ins = $conn->prepare("INSERT INTO nm_cisco_routing (node_id,proto,peer,state,info,uptime_secs,updated_at)
                VALUES (?,?,?,?,?,?,?)
                ON DUPLICATE KEY UPDATE state=VALUES(state),info=VALUES(info),
                    uptime_secs=VALUES(uptime_secs),updated_at=VALUES(updated_at)");
            foreach ($rows as $r) {
                $proto = substr((string)($r['proto'] ?? ''), 0, 8);
                $peer  = substr((string)($r['peer'] ?? ''), 0, 64);
                if ($proto === '' || $peer === '') continue;
                $state = isset($r['state']) ? substr((string)$r['state'], 0, 20) : null;
                $info  = isset($r['info']) ? substr((string)$r['info'], 0, 120) : null;
                $up    = isset($r['uptime_secs']) && $r['uptime_secs'] !== '' ? (int)$r['uptime_secs'] : null;
                // types: node_id i, proto s, peer s, state s, info s, uptime i, updated_at s
                $ins->bind_param('issssis', $node_id, $proto, $peer, $state, $info, $up, $now);
                $ins->execute(); $n++;
            }
            $ins->close();
            try { $conn->commit(); } catch (\Throwable $e) {}
        } catch (\Throwable $e) { try { $conn->rollback(); } catch (\Throwable $e2) {} }
        return $n;
    }

    // $rows: [ ['oper_index'=>1,'tag'=>'DC-PING','rtt_ms'=>12,'sense'=>'ok'], ... ]
    function nm_cisco_ingest_ipsla($conn, int $node_id, array $rows): int {
        $now = gmdate('Y-m-d H:i:s'); $n = 0;
        try { $conn->begin_transaction(); } catch (\Throwable $e) {}
        try {
            $del = $conn->prepare("DELETE FROM nm_cisco_ipsla WHERE node_id=?");
            $del->bind_param('i', $node_id); $del->execute(); $del->close();

            $ins = $conn->prepare("INSERT INTO nm_cisco_ipsla (node_id,oper_index,tag,rtt_ms,sense,updated_at)
                VALUES (?,?,?,?,?,?)
                ON DUPLICATE KEY UPDATE tag=VALUES(tag),rtt_ms=VALUES(rtt_ms),
                    sense=VALUES(sense),updated_at=VALUES(updated_at)");
            foreach ($rows as $r) {
                $oi = (int)($r['oper_index'] ?? 0);
                if ($oi <= 0) continue;
                $tag  = isset($r['tag']) ? substr((string)$r['tag'], 0, 120) : null;
                $rtt  = isset($r['rtt_ms']) && $r['rtt_ms'] !== '' ? (int)$r['rtt_ms'] : null;
                $sen  = isset($r['sense']) ? substr((string)$r['sense'], 0, 20) : null;
                // types: node_id i, oper_index i, tag s, rtt i, sense s, updated_at s
                $ins->bind_param('iisiss', $node_id, $oi, $tag, $rtt, $sen, $now);
                $ins->execute(); $n++;

                if ($rtt !== null) {
                    try { $st=$conn->prepare("INSERT INTO nm_device_stats (node_id,recorded_at,metric_type,metric_key,value) VALUES (?,?,?,?,?)");
                        $rec=date('Y-m-d H:i:s'); $mt='cisco_ipsla'; $mk=substr('rtt:'.($tag?:$oi),0,200); $v=(float)$rtt;
                        $st->bind_param('isssd',$node_id,$rec,$mt,$mk,$v); $st->execute(); $st->close(); } catch (\Throwable $e) {}
                }
            }
            $ins->close();
            try { $conn->commit(); } catch (\Throwable $e) {}
        } catch (\Throwable $e) { try { $conn->rollback(); } catch (\Throwable $e2) {} }
        return $n;
    }

    function nm_cisco_routing_list($conn, int $node_id, ?string $proto = null): array {
        $out = [];
        try {
            if ($proto !== null) {
                $st = $conn->prepare("SELECT proto,peer,state,info,uptime_secs FROM nm_cisco_routing
                                      WHERE node_id=? AND proto=? ORDER BY peer");
                $st->bind_param('is', $node_id, $proto);
            } else {
                $st = $conn->prepare("SELECT proto,peer,state,info,uptime_secs FROM nm_cisco_routing
                                      WHERE node_id=? ORDER BY proto,peer");
                $st->bind_param('i', $node_id);
            }
            $st->execute(); $res = $st->get_result();
            while ($x = $res->fetch_assoc()) $out[] = $x;
            $st->close();
        } catch (\Throwable $e) {}
        return $out;
    }

    function nm_cisco_ipsla_list($conn, int $node_id): array {
        $out = [];
        try {
            $st = $conn->prepare("SELECT oper_index,tag,rtt_ms,sense FROM nm_cisco_ipsla WHERE node_id=? ORDER BY oper_index");
            $st->bind_param('i', $node_id); $st->execute();
            $res = $st->get_result();
            while ($x = $res->fetch_assoc()) $out[] = $x;
            $st->close();
        } catch (\Throwable $e) {}
        return $out;
    }
}
