<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — NetFlow Traffic Analyzer engine (SolarWinds NTA-style).
//
//   The heavy lifting (receiving high-rate UDP flow exports, parsing v5/v9/IPFIX,
//   aggregating) is done by the Python collector scripts/nm_netflow.py, which
//   writes bounded per-minute top-N aggregates into nm_netflow_flows. This PHP
//   side only QUERIES those aggregates for the UI + evaluates bandwidth alerts.
//
//   Bandwidth from a per-minute byte total:  mbps = bytes * 8 / 60 / 1e6.
// ─────────────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/nm_audit.php';

// ── Schema (idempotent; also created by the collector on startup) ────────────
if (!function_exists('nm_nf_ensure')) {
    function nm_nf_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        if (!($conn instanceof mysqli)) return;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_netflow_flows (
            bucket DATETIME NOT NULL,
            exporter VARCHAR(45) NOT NULL,
            src_ip VARCHAR(45) NOT NULL,
            dst_ip VARCHAR(45) NOT NULL,
            src_port INT UNSIGNED NOT NULL DEFAULT 0,
            dst_port INT UNSIGNED NOT NULL DEFAULT 0,
            protocol TINYINT UNSIGNED NOT NULL DEFAULT 0,
            app_port INT UNSIGNED NOT NULL DEFAULT 0,
            bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
            packets BIGINT UNSIGNED NOT NULL DEFAULT 0,
            flows INT UNSIGNED NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket, exporter, src_ip, dst_ip, src_port, dst_port, protocol),
            KEY idx_bucket (bucket),
            KEY idx_app (bucket, app_port, protocol),
            KEY idx_src (bucket, src_ip),
            KEY idx_dst (bucket, dst_ip)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $conn->query("CREATE TABLE IF NOT EXISTS nm_netflow_thresholds (
            scope_key VARCHAR(60) NOT NULL PRIMARY KEY,   -- '__global__' | app label
            warn_mbps DOUBLE DEFAULT NULL,
            crit_mbps DOUBLE DEFAULT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // seed a sane global default if empty
        $r = $conn->query("SELECT COUNT(*) c FROM nm_netflow_thresholds");
        if ($r && (int)$r->fetch_assoc()['c'] === 0) {
            $conn->query("INSERT INTO nm_netflow_thresholds (scope_key,warn_mbps,crit_mbps) VALUES ('__global__',50,100)");
        }

        $conn->query("CREATE TABLE IF NOT EXISTS nm_netflow_alerts (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            scope VARCHAR(60) NOT NULL,            -- app label
            kind VARCHAR(16) NOT NULL DEFAULT 'app',
            severity VARCHAR(10) NOT NULL,         -- warning | critical
            value_mbps DOUBLE NOT NULL,
            threshold_mbps DOUBLE NOT NULL,
            baseline_mbps DOUBLE DEFAULT NULL,
            status VARCHAR(10) NOT NULL DEFAULT 'open',
            opened_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            cleared_at DATETIME DEFAULT NULL,
            KEY idx_status (status), KEY idx_scope (scope)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    }
}

// ── Settings ─────────────────────────────────────────────────────────────────
if (!function_exists('nm_nf_settings')) {
    function nm_nf_settings($conn): array {
        $d = ['netflow_enabled'=>'0','netflow_port'=>'2055','netflow_retention_days'=>'7',
              'netflow_sampling'=>'1','netflow_topn'=>'300','netflow_alert_url'=>'',
              'netflow_baseline_mult'=>'4'];
        $keys = "'" . implode("','", array_keys($d)) . "'";
        if ($r = $conn->query("SELECT setting_key,setting_val FROM nm_settings WHERE setting_key IN ($keys)")) {
            while ($x = $r->fetch_assoc()) $d[$x['setting_key']] = $x['setting_val'];
        }
        return [
            'enabled'        => $d['netflow_enabled'] === '1',
            'port'           => (int)$d['netflow_port'] ?: 2055,
            'retention_days' => max(1, (int)$d['netflow_retention_days']),
            'sampling'       => max(1, (int)$d['netflow_sampling']),
            'topn'           => max(50, (int)$d['netflow_topn']),
            'alert_url'      => $d['netflow_alert_url'],
            'baseline_mult'  => max(2, (float)$d['netflow_baseline_mult']),
        ];
    }
}

// ── Application / protocol naming ────────────────────────────────────────────
if (!function_exists('nm_nf_app_name')) {
    function nm_nf_port_map(): array {
        static $m = null;
        if ($m !== null) return $m;
        return $m = [
            20=>'FTP-DATA',21=>'FTP',22=>'SSH',23=>'Telnet',25=>'SMTP',43=>'WHOIS',49=>'TACACS',
            53=>'DNS',67=>'DHCP',68=>'DHCP',69=>'TFTP',80=>'HTTP',88=>'Kerberos',110=>'POP3',
            111=>'RPC',119=>'NNTP',123=>'NTP',135=>'MS-RPC',137=>'NetBIOS',138=>'NetBIOS',139=>'NetBIOS',
            143=>'IMAP',161=>'SNMP',162=>'SNMP-Trap',179=>'BGP',389=>'LDAP',443=>'HTTPS',445=>'SMB',
            465=>'SMTPS',500=>'IPsec-IKE',514=>'Syslog',515=>'LPD',520=>'RIP',587=>'SMTP',623=>'IPMI',
            636=>'LDAPS',993=>'IMAPS',995=>'POP3S',1080=>'SOCKS',1194=>'OpenVPN',1433=>'MSSQL',
            1521=>'Oracle',1701=>'L2TP',1723=>'PPTP',1812=>'RADIUS',1813=>'RADIUS',1900=>'SSDP',
            2049=>'NFS',2055=>'NetFlow',2082=>'cPanel',2083=>'cPanel',2222=>'SSH-alt',3128=>'Proxy',
            3306=>'MySQL',3389=>'RDP',3478=>'STUN/TURN',4500=>'IPsec-NAT',4739=>'IPFIX',5060=>'SIP',
            5061=>'SIP-TLS',5222=>'XMPP',5353=>'mDNS',5355=>'LLMNR',5432=>'PostgreSQL',5900=>'VNC',
            5938=>'TeamViewer',6343=>'sFlow',6379=>'Redis',6443=>'Kubernetes',8000=>'HTTP-alt',
            8080=>'HTTP-Proxy',8443=>'HTTPS-alt',8883=>'MQTT-TLS',9000=>'HTTP-alt',9090=>'HTTP-alt',
            9100=>'Printer',9200=>'Elasticsearch',27017=>'MongoDB',51820=>'WireGuard',
        ];
    }
    function nm_nf_proto_name(int $p): string {
        static $m = [1=>'ICMP',2=>'IGMP',6=>'TCP',17=>'UDP',41=>'IPv6',47=>'GRE',50=>'ESP',51=>'AH',
                     58=>'ICMPv6',89=>'OSPF',103=>'PIM',112=>'VRRP',132=>'SCTP'];
        return $m[$p] ?? ('proto-' . $p);
    }
    // Friendly app label for a (service-port, protocol) pair.
    function nm_nf_app_name(int $appPort, int $proto): string {
        $map = nm_nf_port_map();
        if ($appPort > 0 && isset($map[$appPort])) return $map[$appPort];
        $pn = nm_nf_proto_name($proto);
        if ($appPort > 0) return $pn . '/' . $appPort;
        return $pn;
    }
}

// Top src->dst talkers behind a NetFlow bandwidth alert scope (app label) over the recent window,
// so 'High bandwidth: HTTPS' becomes 'who is talking to whom'. Read-only, index-backed, bounded.
if (!function_exists('nm_nf_scope_talkers')) {
    function nm_nf_scope_talkers($conn, string $scope, int $winMin = 10, int $limit = 4): array {
        $scope = trim($scope);
        $ports = [];
        foreach (nm_nf_port_map() as $pp => $lab) { if (strcasecmp($lab, $scope) === 0) $ports[] = (int)$pp; }
        $where = 'bucket >= (NOW() - INTERVAL ' . max(1, (int)$winMin) . ' MINUTE)';
        if ($ports) { $where .= ' AND app_port IN (' . implode(',', $ports) . ')'; }
        elseif (preg_match('#/(\d+)$#', $scope, $m)) { $where .= ' AND app_port = ' . (int)$m[1]; }
        $limit = max(1, min(20, $limit)); $sec = max(60, $winMin * 60); $out = [];
        try {
            $r = $conn->query("SELECT src_ip, dst_ip, app_port, protocol, MAX(bb) peak, SUM(bb) tot FROM (
                                 SELECT src_ip, dst_ip, app_port, protocol, bucket, SUM(bytes) bb
                                 FROM nm_netflow_flows WHERE $where
                                 GROUP BY src_ip, dst_ip, app_port, protocol, bucket) q
                               GROUP BY src_ip, dst_ip, app_port, protocol
                               ORDER BY tot DESC LIMIT $limit");
            while ($r && $x = $r->fetch_assoc()) $out[] = [
                'src' => $x['src_ip'], 'dst' => $x['dst_ip'], 'port' => (int)$x['app_port'],
                'proto' => nm_nf_proto_name((int)$x['protocol']),
                'mbps' => round(((float)$x['peak'] * 8) / 60 / 1e6, 2),
            ];
        } catch (\Throwable $e) {}
        return $out;
    }
    // One human-readable line of the top talkers, with a GeoIP flag for the public side when available.
    function nm_nf_talkers_line($conn, array $talkers): string {
        if (!function_exists('nm_geo_badge')) { try { require_once __DIR__ . '/nm_nettools.php'; } catch (\Throwable $e) {} }
        $parts = [];
        foreach ($talkers as $t) {
            $geo = '';
            if (function_exists('nm_geo_badge')) { foreach ([$t['dst'], $t['src']] as $ip) {
                try { $b = nm_geo_badge($conn, $ip); } catch (\Throwable $e) { $b = null; }
                if ($b) { $geo = ' (' . trim(($b['cc'] ?? '') . ' ' . ($b['country'] ?? '')) . ')'; break; } } }
            $parts[] = $t['src'] . ' -> ' . $t['dst'] . ':' . $t['port'] . ' ' . $t['mbps'] . ' Mbps' . $geo;
        }
        return implode('  |  ', $parts);
    }
}

// ── Time-window helper ───────────────────────────────────────────────────────
if (!function_exists('nm_nf_window')) {
    // Returns [minutes, bucket_seconds] for a range key.
    function nm_nf_window(string $range): array {
        switch ($range) {
            case '15m': return [15,   60];
            case '1h':  return [60,   60];
            case '6h':  return [360,  300];
            case '24h': return [1440, 600];
            case '7d':  return [10080,3600];
            default:    return [60,   60];
        }
    }
    function nm_nf_minutes(string $range): int { return nm_nf_window($range)[0]; }
}

// ── Queries for the UI ───────────────────────────────────────────────────────
if (!function_exists('nm_nf_summary')) {
    function _nf_where($conn, int $mins, string $exporter = ''): array {
        $w = "bucket >= (NOW() - INTERVAL {$mins} MINUTE)";
        if ($exporter !== '') $w .= " AND exporter='" . $conn->real_escape_string($exporter) . "'";
        return [$w, $mins];
    }

    function nm_nf_summary($conn, int $mins, string $exporter = ''): array {
        nm_nf_ensure($conn);
        [$w] = _nf_where($conn, $mins, $exporter);
        $r = $conn->query("SELECT COALESCE(SUM(bytes),0) b, COALESCE(SUM(packets),0) p, COALESCE(SUM(flows),0) f,
                                  COUNT(DISTINCT src_ip) talkers, COUNT(DISTINCT exporter) exporters
                           FROM nm_netflow_flows WHERE $w");
        $x = $r ? $r->fetch_assoc() : [];
        $secs = max(1, $mins * 60);
        return [
            'bytes'   => (float)($x['b'] ?? 0),
            'packets' => (float)($x['p'] ?? 0),
            'flows'   => (int)($x['f'] ?? 0),
            'talkers' => (int)($x['talkers'] ?? 0),
            'exporters'=>(int)($x['exporters'] ?? 0),
            'avg_mbps'=> (float)($x['b'] ?? 0) * 8 / $secs / 1e6,
        ];
    }

    function nm_nf_timeseries($conn, string $range, string $exporter = ''): array {
        nm_nf_ensure($conn);
        [$mins, $bsec] = nm_nf_window($range);
        [$w] = _nf_where($conn, $mins, $exporter);
        // bucket to the chosen granularity
        $grp = "FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(bucket)/{$bsec})*{$bsec})";
        $out = [];
        $r = $conn->query("SELECT UNIX_TIMESTAMP($grp) t, SUM(bytes) b FROM nm_netflow_flows
                           WHERE $w GROUP BY t ORDER BY t");
        while ($r && $x = $r->fetch_assoc()) {
            $out[] = ['t'=>(int)$x['t'], 'mbps'=>(float)$x['b'] * 8 / $bsec / 1e6];
        }
        return $out;
    }

    function nm_nf_top_talkers($conn, int $mins, string $dir = 'src', string $exporter = '', int $limit = 12): array {
        nm_nf_ensure($conn);
        [$w] = _nf_where($conn, $mins, $exporter);
        $col = $dir === 'dst' ? 'dst_ip' : 'src_ip';
        $secs = max(1, $mins * 60); $out = [];
        $r = $conn->query("SELECT $col ip, SUM(bytes) b, SUM(packets) p, SUM(flows) f
                           FROM nm_netflow_flows WHERE $w GROUP BY $col ORDER BY b DESC LIMIT $limit");
        while ($r && $x = $r->fetch_assoc()) $out[] = ['ip'=>$x['ip'], 'bytes'=>(float)$x['b'],
            'mbps'=>(float)$x['b']*8/$secs/1e6, 'flows'=>(int)$x['f']];
        return $out;
    }

    function nm_nf_top_apps($conn, int $mins, string $exporter = '', int $limit = 12): array {
        nm_nf_ensure($conn);
        [$w] = _nf_where($conn, $mins, $exporter);
        $secs = max(1, $mins * 60); $out = [];
        $r = $conn->query("SELECT app_port, protocol, SUM(bytes) b, SUM(flows) f
                           FROM nm_netflow_flows WHERE $w GROUP BY app_port, protocol ORDER BY b DESC LIMIT $limit");
        while ($r && $x = $r->fetch_assoc()) $out[] = [
            'app'   => nm_nf_app_name((int)$x['app_port'], (int)$x['protocol']),
            'port'  => (int)$x['app_port'], 'proto'=>(int)$x['protocol'],
            'bytes' => (float)$x['b'], 'mbps'=>(float)$x['b']*8/$secs/1e6, 'flows'=>(int)$x['f']];
        return $out;
    }

    function nm_nf_top_protocols($conn, int $mins, string $exporter = '', int $limit = 8): array {
        nm_nf_ensure($conn);
        [$w] = _nf_where($conn, $mins, $exporter);
        $secs = max(1, $mins * 60); $out = [];
        $r = $conn->query("SELECT protocol, SUM(bytes) b FROM nm_netflow_flows WHERE $w GROUP BY protocol ORDER BY b DESC LIMIT $limit");
        while ($r && $x = $r->fetch_assoc()) $out[] = ['proto'=>nm_nf_proto_name((int)$x['protocol']),
            'num'=>(int)$x['protocol'], 'bytes'=>(float)$x['b'], 'mbps'=>(float)$x['b']*8/$secs/1e6];
        return $out;
    }

    function nm_nf_top_conversations($conn, int $mins, string $exporter = '', int $limit = 20): array {
        nm_nf_ensure($conn);
        [$w] = _nf_where($conn, $mins, $exporter);
        $secs = max(1, $mins * 60); $out = [];
        $r = $conn->query("SELECT src_ip, dst_ip, app_port, protocol, SUM(bytes) b, SUM(packets) p, SUM(flows) f
                           FROM nm_netflow_flows WHERE $w GROUP BY src_ip, dst_ip, app_port, protocol ORDER BY b DESC LIMIT $limit");
        while ($r && $x = $r->fetch_assoc()) $out[] = [
            'src'=>$x['src_ip'], 'dst'=>$x['dst_ip'],
            'app'=>nm_nf_app_name((int)$x['app_port'], (int)$x['protocol']),
            'bytes'=>(float)$x['b'], 'mbps'=>(float)$x['b']*8/$secs/1e6, 'flows'=>(int)$x['f']];
        return $out;
    }

    // Directional flows for the Flow Explorer: each row is src → dst : app, so the
    // direction/path is explicit. Optional host filter (out = host is source,
    // in = host is destination, both = either side).
    function nm_nf_flows($conn, int $mins, string $exporter = '', string $host = '', string $dir = 'both', int $limit = 150): array {
        nm_nf_ensure($conn);
        [$w] = _nf_where($conn, $mins, $exporter);
        $host = trim($host);
        if ($host !== '') {
            $h = $conn->real_escape_string($host);
            if     ($dir === 'out') $w .= " AND src_ip='$h'";
            elseif ($dir === 'in')  $w .= " AND dst_ip='$h'";
            else                    $w .= " AND (src_ip='$h' OR dst_ip='$h')";
        }
        $secs = max(1, $mins * 60); $out = [];
        $r = $conn->query("SELECT src_ip, dst_ip, app_port, protocol,
                                  SUM(bytes) b, SUM(packets) p, SUM(flows) f
                           FROM nm_netflow_flows WHERE $w
                           GROUP BY src_ip, dst_ip, app_port, protocol ORDER BY b DESC LIMIT $limit");
        while ($r && $x = $r->fetch_assoc()) $out[] = [
            'src'=>$x['src_ip'], 'dst'=>$x['dst_ip'],
            'app'=>nm_nf_app_name((int)$x['app_port'], (int)$x['protocol']),
            'port'=>(int)$x['app_port'], 'proto'=>nm_nf_proto_name((int)$x['protocol']),
            'bytes'=>(float)$x['b'], 'mbps'=>(float)$x['b']*8/$secs/1e6,
            'packets'=>(int)$x['p'], 'flows'=>(int)$x['f'],
        ];
        return $out;
    }

    // Node/edge graph for the directional traffic map. Edges are aggregated
    // src → dst (summing all apps); nodes carry in/out bandwidth so the busiest /
    // most-connected node visually pops (= the one to look at when troubleshooting).
    function nm_nf_flow_graph($conn, int $mins, string $exporter = '', string $host = '', int $limit = 80): array {
        nm_nf_ensure($conn);
        [$w] = _nf_where($conn, $mins, $exporter);
        $host = trim($host);
        if ($host !== '') {
            $h = $conn->real_escape_string($host);
            $w .= " AND (src_ip='$h' OR dst_ip='$h')";
        }
        $secs = max(1, $mins * 60);
        $edges = []; $nodes = [];
        $r = $conn->query("SELECT src_ip, dst_ip, SUM(bytes) b, SUM(flows) f,
                                  SUBSTRING_INDEX(GROUP_CONCAT(app_port ORDER BY bytes DESC),',',1) top_app,
                                  SUBSTRING_INDEX(GROUP_CONCAT(protocol ORDER BY bytes DESC),',',1) top_proto
                           FROM nm_netflow_flows WHERE $w
                           GROUP BY src_ip, dst_ip ORDER BY b DESC LIMIT $limit");
        while ($r && $x = $r->fetch_assoc()) {
            $mbps = (float)$x['b'] * 8 / $secs / 1e6;
            $edges[] = ['src'=>$x['src_ip'], 'dst'=>$x['dst_ip'], 'mbps'=>$mbps,
                        'app'=>nm_nf_app_name((int)$x['top_app'], (int)$x['top_proto']), 'flows'=>(int)$x['f']];
            foreach ([['src_ip','out'], ['dst_ip','in']] as $nd) {
                $ip = $x[$nd[0]];
                if (!isset($nodes[$ip])) $nodes[$ip] = ['id'=>$ip, 'in'=>0, 'out'=>0, 'deg'=>0];
                $nodes[$ip][$nd[1]] += $mbps;
                $nodes[$ip]['deg']++;
            }
        }
        return ['nodes'=>array_values($nodes), 'edges'=>$edges, 'host'=>$host];
    }

    function nm_nf_exporters($conn): array {
        nm_nf_ensure($conn);
        $out = [];
        $r = $conn->query("SELECT exporter, MAX(bucket) last_seen FROM nm_netflow_flows
                           WHERE bucket >= (NOW() - INTERVAL 24 HOUR) GROUP BY exporter ORDER BY exporter");
        while ($r && $x = $r->fetch_assoc()) $out[] = $x;
        return $out;
    }

    function nm_nf_status($conn): array {
        $keys = "'netflow_stat_last','netflow_stat_packets','netflow_stat_flows','netflow_stat_exporters','netflow_stat_dropped'";
        $s = [];
        if ($r = $conn->query("SELECT setting_key,setting_val FROM nm_settings WHERE setting_key IN ($keys)")) {
            while ($x = $r->fetch_assoc()) $s[$x['setting_key']] = $x['setting_val'];
        }
        $last = $s['netflow_stat_last'] ?? null;
        $age = null;
        if ($last) { $age = time() - (int)$last; }
        return [
            'last_flush_ts' => $last ? (int)$last : null,
            'age_sec'       => $age,
            'alive'         => ($age !== null && $age < 180),
            'packets'       => (int)($s['netflow_stat_packets'] ?? 0),
            'flows'         => (int)($s['netflow_stat_flows'] ?? 0),
            'exporters'     => (int)($s['netflow_stat_exporters'] ?? 0),
            'dropped'       => (int)($s['netflow_stat_dropped'] ?? 0),
        ];
    }
}

// ── Bandwidth alerting (per-app thresholds + baseline anomaly) ───────────────
if (!function_exists('nm_nf_thresholds')) {
    function nm_nf_thresholds($conn): array {
        nm_nf_ensure($conn);
        $out = ['global'=>['warn_mbps'=>'','crit_mbps'=>''], 'apps'=>[]];
        $r = $conn->query("SELECT scope_key,warn_mbps,crit_mbps FROM nm_netflow_thresholds");
        while ($r && $x = $r->fetch_assoc()) {
            $row = ['warn_mbps'=>$x['warn_mbps'], 'crit_mbps'=>$x['crit_mbps']];
            if ($x['scope_key'] === '__global__') $out['global'] = $row;
            else $out['apps'][$x['scope_key']] = $row;
        }
        return $out;
    }
    function nm_nf_threshold_save($conn, string $scope, $warn, $crit): void {
        nm_nf_ensure($conn);
        $warn = ($warn === '' || $warn === null) ? null : (float)$warn;
        $crit = ($crit === '' || $crit === null) ? null : (float)$crit;
        if ($scope !== '__global__' && $warn === null && $crit === null) {
            $st = $conn->prepare("DELETE FROM nm_netflow_thresholds WHERE scope_key=?");
            $st->bind_param('s', $scope); $st->execute(); $st->close(); return;
        }
        $st = $conn->prepare("INSERT INTO nm_netflow_thresholds (scope_key,warn_mbps,crit_mbps) VALUES (?,?,?)
                              ON DUPLICATE KEY UPDATE warn_mbps=VALUES(warn_mbps), crit_mbps=VALUES(crit_mbps)");
        $st->bind_param('sdd', $scope, $warn, $crit); $st->execute(); $st->close();
    }

    // Evaluate per-app bandwidth over the last few minutes against thresholds +
    // a rolling baseline; open/clear alerts. Returns a small summary.
    function nm_nf_eval_alerts($conn, int $evalMins = 5): array {
        nm_nf_ensure($conn);
        $S   = nm_nf_settings($conn);
        $thr = nm_nf_thresholds($conn);
        $gw  = $thr['global']['warn_mbps'] !== '' ? (float)$thr['global']['warn_mbps'] : null;
        $gc  = $thr['global']['crit_mbps'] !== '' ? (float)$thr['global']['crit_mbps'] : null;
        $mult = $S['baseline_mult'];

        // current per-app Mbps over the eval window
        $secs = $evalMins * 60;
        $cur = [];
        $r = $conn->query("SELECT app_port, protocol, SUM(bytes) b FROM nm_netflow_flows
                           WHERE bucket >= (NOW() - INTERVAL {$evalMins} MINUTE) GROUP BY app_port, protocol");
        while ($r && $x = $r->fetch_assoc()) {
            $label = nm_nf_app_name((int)$x['app_port'], (int)$x['protocol']);
            $mbps  = (float)$x['b'] * 8 / $secs / 1e6;
            $cur[$label] = ['mbps'=>($cur[$label]['mbps'] ?? 0) + $mbps,
                            'port'=>(int)$x['app_port'], 'proto'=>(int)$x['protocol']];
        }
        // baseline: avg per-app Mbps over the past 24h (excluding the eval window)
        $base = [];
        $r = $conn->query("SELECT app_port, protocol, SUM(bytes) b FROM nm_netflow_flows
                           WHERE bucket >= (NOW() - INTERVAL 24 HOUR) AND bucket < (NOW() - INTERVAL {$evalMins} MINUTE)
                           GROUP BY app_port, protocol");
        while ($r && $x = $r->fetch_assoc()) {
            $label = nm_nf_app_name((int)$x['app_port'], (int)$x['protocol']);
            $secs2 = max(1, 24*3600 - $secs);
            $base[$label] = ($base[$label] ?? 0) + (float)$x['b'] * 8 / $secs2 / 1e6;
        }

        $now = date('Y-m-d H:i:s');
        $open = [];
        $r = $conn->query("SELECT id,scope,severity FROM nm_netflow_alerts WHERE status='open'");
        while ($r && $x = $r->fetch_assoc()) $open[$x['scope']] = $x;

        $opened = 0; $cleared = 0;
        foreach ($cur as $label => $c) {
            $mbps = $c['mbps'];
            $perW = $thr['apps'][$label]['warn_mbps'] ?? null; $perW = ($perW !== null && $perW !== '') ? (float)$perW : $gw;
            $perC = $thr['apps'][$label]['crit_mbps'] ?? null; $perC = ($perC !== null && $perC !== '') ? (float)$perC : $gc;
            $baseMbps = $base[$label] ?? null;
            $anom = ($baseMbps !== null && $baseMbps >= 1 && $mbps >= $baseMbps * $mult && $mbps >= 5);

            $sev = null;
            if ($perC !== null && $mbps >= $perC) $sev = 'critical';
            elseif ($perW !== null && $mbps >= $perW) $sev = 'warning';
            elseif ($anom) $sev = 'warning';
            if ($sev === null) continue;

            $thrUsed = $sev === 'critical' ? ($perC ?? 0) : ($perW ?? ($baseMbps !== null ? $baseMbps * $mult : 0));
            if (isset($open[$label])) {
                $id = (int)$open[$label]['id'];
                $st = $conn->prepare("UPDATE nm_netflow_alerts SET severity=?, value_mbps=?, threshold_mbps=?, baseline_mbps=?, updated_at=? WHERE id=?");
                $st->bind_param('sdddsi', $sev, $mbps, $thrUsed, $baseMbps, $now, $id); $st->execute(); $st->close();
                unset($open[$label]);
            } else {
                $kind = 'app';
                $q = $conn->prepare("INSERT INTO nm_netflow_alerts (scope,kind,severity,value_mbps,threshold_mbps,baseline_mbps,status,opened_at,updated_at)
                                     VALUES (?,?,?,?,?,?,'open',?,?)");
                $q->bind_param('sssdddss', $label, $kind, $sev, $mbps, $thrUsed, $baseMbps, $now, $now);
                $q->execute(); $q->close();
                $opened++;
                nm_nf_notify($conn, $label, $sev, $mbps, $thrUsed);
            }
        }
        // anything still in $open had no breach this round → clear
        foreach ($open as $label => $a) {
            $id = (int)$a['id'];
            $conn->query("UPDATE nm_netflow_alerts SET status='cleared', cleared_at='$now', updated_at='$now' WHERE id=$id");
            $cleared++;
        }
        return ['opened'=>$opened, 'cleared'=>$cleared, 'apps'=>count($cur)];
    }

    function nm_nf_open_alerts($conn, int $limit = 25): array {
        nm_nf_ensure($conn);
        $out = [];
        $r = $conn->query("SELECT id,scope,severity,value_mbps,threshold_mbps,baseline_mbps,opened_at
                           FROM nm_netflow_alerts WHERE status='open' ORDER BY value_mbps DESC LIMIT $limit");
        while ($r && $x = $r->fetch_assoc()) $out[] = $x;
        return $out;
    }
    function nm_nf_open_count($conn): int {
        nm_nf_ensure($conn);
        $r = $conn->query("SELECT COUNT(*) c FROM nm_netflow_alerts WHERE status='open'");
        return $r ? (int)$r->fetch_assoc()['c'] : 0;
    }

    function nm_nf_notify($conn, string $scope, string $sev, float $mbps, float $thr): void {
        $S = nm_nf_settings($conn);
        if (trim($S['alert_url']) === '') return;
        // Site-wide notification gate: honor maintenance windows ('all' or source 'netflow').
        if (!function_exists('nm_notify_maint_active')) @require_once __DIR__ . '/nm_notify.php';
        if (function_exists('nm_notify_maint_active') && nm_notify_maint_active($conn, null, 'netflow')) return;
        $_pl = ['type'=>'netflow_bandwidth','app'=>$scope,'severity'=>$sev,
            'mbps'=>round($mbps,2),'threshold_mbps'=>round($thr,2),'ts'=>date('c')];
        if (!function_exists('nm_n8n_neuru_stamp') && is_file(__DIR__.'/nm_n8n.php')) require_once __DIR__.'/nm_n8n.php';
        if (function_exists('nm_n8n_neuru_stamp')) $_pl = nm_n8n_neuru_stamp($conn, $_pl, (string)($S['alert_url'] ?? ''));  // hosted-flow gatecheck
        $payload = json_encode($_pl);
        $tok = '';
        if ($t = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='n8n_inbound_token' LIMIT 1")) {
            $tok = ($x = $t->fetch_row()) ? $x[0] : '';
        }
        $ch = curl_init($S['alert_url']);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>$payload,
            CURLOPT_CONNECTTIMEOUT=>4, CURLOPT_TIMEOUT=>10, CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_SSL_VERIFYHOST=>false,
            CURLOPT_HTTPHEADER=>['Content-Type: application/json','X-NetMon-Token: '.$tok]]);
        curl_exec($ch); curl_close($ch);
    }
}
