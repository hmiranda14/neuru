<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Router / device detail engine (backs router_details.php).
//  · nm_router_node()        one node row + asset fields + classified kind
//  · nm_router_db_snapshot() FAST, DB-only: interfaces, latency/loss trend, uptime%,
//                            open incidents, latest health metrics — renders instantly.
//  · nm_router_live_probe()  OPTIONAL live enrichment over SSH. MikroTik (RouterOS) gets
//                            a single key=value script → identity, resources, counts,
//                            interfaces, addresses. Non-MikroTik / no-cred → graceful skip.
// Reuses nm_ssh_resolve (nm_secrets.php) + nm_cm_ssh_fetch (nm_confmgr.php). Secrets
// decrypt under www-data only, so the live probe runs in the web request, never CLI cron.
// ─────────────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/nm_nodemeta.php';

if (!function_exists('nm_router_node')) {

    function nm_router_node($conn, int $id): ?array {
        if (!($conn instanceof mysqli) || !$id) return null;
        nm_node_meta_ensure($conn);
        $r = $conn->query("SELECT n.*, g.name grp_name, g.color grp_color
                           FROM nm_nodes n LEFT JOIN nm_groups g ON g.id=n.group_id
                           WHERE n.id=" . (int)$id . " LIMIT 1");
        $n = $r ? $r->fetch_assoc() : null;
        if (!$n) return null;
        $n['kind'] = nm_node_kind($n);
        $n['photo_url'] = nm_node_photo_url($n);
        return $n;
    }

    // Everything we already know from polling — no SSH, milliseconds.
    function nm_router_db_snapshot($conn, array $node): array {
        $id = (int)$node['id'];
        $out = ['interfaces'=>[], 'latency'=>null, 'trend'=>[], 'uptime24'=>null, 'incidents'=>[], 'metrics'=>[]];

        // configured interfaces (from the poller / LibreNMS sync)
        try {
            $r = $conn->query("SELECT if_name, if_alias, display_name, if_ip_address, if_index, show_graph
                               FROM nm_interfaces WHERE node_id=$id ORDER BY sort_order, if_index");
            while ($r && $x = $r->fetch_assoc()) $out['interfaces'][] = $x;
        } catch (\Throwable $e) {}

        // latest reachability + latency, plus a short trend for the sparkline
        try {
            $r = $conn->query("SELECT is_up, latency_ms, packet_loss, recorded_at
                               FROM nm_ping_stats WHERE node_id=$id ORDER BY id DESC LIMIT 1");
            if ($r && ($x = $r->fetch_assoc())) $out['latency'] = $x;
            $r = $conn->query("SELECT latency_ms, is_up, packet_loss, recorded_at
                               FROM nm_ping_stats WHERE node_id=$id ORDER BY id DESC LIMIT 60");
            $t = []; while ($r && $x = $r->fetch_assoc()) $t[] = $x;
            $out['trend'] = array_reverse($t);
        } catch (\Throwable $e) {}

        // 24h availability from ping history
        try {
            $r = $conn->query("SELECT SUM(is_up=1) up, COUNT(*) tot
                               FROM nm_ping_stats WHERE node_id=$id AND recorded_at > (NOW() - INTERVAL 24 HOUR)");
            if ($r && ($x = $r->fetch_assoc()) && (int)$x['tot'] > 0)
                $out['uptime24'] = round((int)$x['up'] / (int)$x['tot'] * 100, 2);
        } catch (\Throwable $e) {}

        // open incidents rooted on this node
        try {
            $r = $conn->query("SELECT id, title, severity, status, opened_at, signal_count, impact_count
                               FROM nm_incidents WHERE root_node_id=$id AND status IN ('open','acknowledged')
                               ORDER BY FIELD(severity,'critical','high','medium','low','info'), opened_at DESC LIMIT 20");
            while ($r && $x = $r->fetch_assoc()) $out['incidents'][] = $x;
        } catch (\Throwable $e) {}

        // latest value for each polled health metric (cpu/mem/uptime/… if the poller stored any)
        try {
            $r = $conn->query("SELECT s.metric, s.entity, s.value, s.recorded_at
                               FROM nm_health_samples s
                               JOIN (SELECT metric, MAX(id) mid FROM nm_health_samples WHERE node_id=$id GROUP BY metric) t
                                 ON t.mid=s.id");
            while ($r && $x = $r->fetch_assoc()) $out['metrics'][$x['metric']] = $x;
        } catch (\Throwable $e) {}

        return $out;
    }

    // ── RouterOS live probe ─────────────────────────────────────────────────────
    // One SSH exec of a key=value script. Empty output = failure in nm_cm_ssh_fetch,
    // so the script always emits lines and a trailing NM_END sentinel.
    function nm_router_routeros_script(): string {
        $L = [];
        $g = function(string $key, string $path) { return ":do { :put (\"$key=\" . [$path]) } on-error={}"; };
        $L[] = $g('name',      '/system identity get name');
        $L[] = $g('uptime',    '/system resource get uptime');
        $L[] = $g('version',   '/system resource get version');
        $L[] = $g('buildtime', '/system resource get build-time');
        $L[] = $g('board',     '/system resource get board-name');
        $L[] = $g('platform',  '/system resource get platform');
        $L[] = $g('arch',      '/system resource get architecture-name');
        $L[] = $g('cpu',       '/system resource get cpu');
        $L[] = $g('cpuload',   '/system resource get cpu-load');
        $L[] = $g('cpucount',  '/system resource get cpu-count');
        $L[] = $g('cpufreq',   '/system resource get cpu-frequency');
        $L[] = $g('freemem',   '/system resource get free-memory');
        $L[] = $g('totalmem',  '/system resource get total-memory');
        $L[] = $g('freehdd',   '/system resource get free-hdd-space');
        $L[] = $g('totalhdd',  '/system resource get total-hdd-space');
        $L[] = $g('model',     '/system routerboard get model');
        $L[] = $g('serial',    '/system routerboard get serial-number');
        $L[] = $g('firmware',  '/system routerboard get current-firmware-version');
        $L[] = $g('firmwareUpg','/system routerboard get upgrade-firmware');
        $L[] = $g('temp',      '/system health get temperature');
        $L[] = $g('voltage',   '/system health get voltage');
        $L[] = $g('psu1',      '/system health get psu1-state');
        $L[] = $g('routes',    ':len [/ip route find]');
        $L[] = $g('addresses', ':len [/ip address find]');
        $L[] = $g('leases',    ':len [/ip dhcp-server lease find]');
        $L[] = $g('leasesBound',':len [/ip dhcp-server lease find where status=bound]');
        $L[] = $g('fwfilter',  ':len [/ip firewall filter find]');
        $L[] = $g('fwnat',     ':len [/ip firewall nat find]');
        $L[] = $g('fwaddr',    ':len [/ip firewall address-list find]');
        $L[] = $g('wifi',      ':len [/interface wireless registration-table find]');
        $L[] = $g('capsman',   ':len [/caps-man registration-table find]');
        $L[] = $g('pppactive', ':len [/ppp active find]');
        $L[] = $g('users',     ':len [/user find]');
        $L[] = $g('activeUsers',':len [/user active find]');
        $L[] = $g('neighbors', ':len [/ip neighbor find]');
        // interfaces: name|type|running|disabled|rx-byte|tx-byte|comment
        $L[] = ':do { :foreach i in=[/interface find] do={ :put ("if|" . [/interface get $i name] . "|" . [/interface get $i type] . "|" . [/interface get $i running] . "|" . [/interface get $i disabled] . "|" . [/interface get $i rx-byte] . "|" . [/interface get $i tx-byte] . "|" . [/interface get $i comment]) } } on-error={}';
        // ip addresses: address|interface
        $L[] = ':do { :foreach a in=[/ip address find] do={ :put ("addr|" . [/ip address get $a address] . "|" . [/ip address get $a interface]) } } on-error={}';
        $L[] = ':put "NM_END"';
        return implode('; ', $L);
    }

    // Minimal, maximally-compatible probe: only menus/props present on EVERY RouterOS
    // (no wireless / caps-man / routerboard / health) so it can't be aborted by a missing
    // package. Used as a fallback when the rich script returns nothing.
    function nm_router_routeros_script_min(): string {
        $L = [];
        $p = fn($k, $path) => ":put (\"$k=\" . [$path])";
        foreach ([
            'name'=>'/system identity get name', 'uptime'=>'/system resource get uptime',
            'version'=>'/system resource get version', 'board'=>'/system resource get board-name',
            'platform'=>'/system resource get platform', 'arch'=>'/system resource get architecture-name',
            'cpu'=>'/system resource get cpu', 'cpuload'=>'/system resource get cpu-load',
            'cpucount'=>'/system resource get cpu-count', 'cpufreq'=>'/system resource get cpu-frequency',
            'freemem'=>'/system resource get free-memory', 'totalmem'=>'/system resource get total-memory',
            'freehdd'=>'/system resource get free-hdd-space', 'totalhdd'=>'/system resource get total-hdd-space',
            'routes'=>':len [/ip route find]', 'addresses'=>':len [/ip address find]',
            'fwfilter'=>':len [/ip firewall filter find]', 'fwnat'=>':len [/ip firewall nat find]',
            'leases'=>':len [/ip dhcp-server lease find]', 'neighbors'=>':len [/ip neighbor find]',
        ] as $k => $path) $L[] = $p($k, $path);
        $L[] = ':foreach i in=[/interface find] do={ :put ("if|" . [/interface get $i name] . "|" . [/interface get $i type] . "|" . [/interface get $i running] . "|" . [/interface get $i disabled] . "|" . [/interface get $i rx-byte] . "|" . [/interface get $i tx-byte] . "|" . [/interface get $i comment]) }';
        $L[] = ':foreach a in=[/ip address find] do={ :put ("addr|" . [/ip address get $a address] . "|" . [/ip address get $a interface]) }';
        $L[] = ':put "NM_END"';
        return implode('; ', $L);
    }

    function nm_router_parse_routeros(string $raw): array {
        $kv = []; $ifaces = []; $addrs = [];
        foreach (preg_split('/\r?\n/', $raw) as $line) {
            $line = trim($line);
            if ($line === '' || $line === 'NM_END') continue;
            if (strpos($line, 'if|') === 0) {
                $p = explode('|', $line);
                $ifaces[] = ['name'=>$p[1]??'', 'type'=>$p[2]??'', 'running'=>($p[3]??'')==='true',
                             'disabled'=>($p[4]??'')==='true', 'rx'=>(float)($p[5]??0), 'tx'=>(float)($p[6]??0), 'comment'=>$p[7]??''];
            } elseif (strpos($line, 'addr|') === 0) {
                $p = explode('|', $line);
                $addrs[] = ['address'=>$p[1]??'', 'interface'=>$p[2]??''];
            } elseif (strpos($line, '=') !== false) {
                [$k, $v] = explode('=', $line, 2);
                $kv[trim($k)] = trim($v);
            }
        }
        return ['kv'=>$kv, 'interfaces'=>$ifaces, 'addresses'=>$addrs];
    }

    // Live enrichment. Returns ['ok','vendor','error','data'=>{identity,resources,counts,interfaces,addresses}].
    function nm_router_live_probe($conn, array $node): array {
        $kind = nm_node_kind($node);
        if ($kind !== 'router') return ['ok'=>false, 'error'=>'live probe only for router devices', 'vendor'=>$kind];
        if (empty($node['ip_address'])) return ['ok'=>false, 'error'=>'node has no IP', 'vendor'=>'mikrotik'];

        $os = strtolower((string)($node['os_icon'] ?? ''));
        $isMikrotik = in_array($os, ['mikrotik','routeros'], true);
        if (!$isMikrotik) return ['ok'=>false, 'error'=>'live probe currently supports MikroTik RouterOS only ('.$os.' shows monitored data below)', 'vendor'=>$os];

        if (!function_exists('nm_cm_ssh_fetch')) { require_once __DIR__ . '/nm_confmgr.php'; }
        $ssh = nm_ssh_resolve($conn, (int)$node['id']);
        if (!$ssh) return ['ok'=>false, 'error'=>'no SSH credential resolved — set one in Config → Devices', 'vendor'=>'mikrotik'];
        if (empty($ssh['username']) || (empty($ssh['password']) && empty($ssh['private_key'])))
            return ['ok'=>false, 'error'=>'SSH credential incomplete (username/secret)', 'vendor'=>'mikrotik'];

        $fetch = nm_cm_ssh_fetch($ssh, nm_router_routeros_script(), 30);
        if (empty($fetch['ok'])) return ['ok'=>false, 'error'=>$fetch['error'] ?? 'SSH probe failed', 'vendor'=>'mikrotik'];

        $p = nm_router_parse_routeros((string)$fetch['config']);
        $kv = $p['kv'];
        // The full script references /interface wireless + /caps-man; on a router WITHOUT those
        // packages (e.g. an RB5009) RouterOS aborts the whole script → no output. Retry with a
        // minimal script that only touches menus present on EVERY RouterOS.
        if (!$kv && !$p['interfaces']) {
            $f2 = nm_cm_ssh_fetch($ssh, nm_router_routeros_script_min(), 25);
            if (!empty($f2['ok'])) { $p2 = nm_router_parse_routeros((string)$f2['config']);
                if ($p2['kv'] || $p2['interfaces']) { $p = $p2; $kv = $p['kv']; } }
        }
        if (!$kv && !$p['interfaces']) return ['ok'=>false, 'error'=>'router returned no parseable data', 'vendor'=>'mikrotik'];

        $num = fn($k) => isset($kv[$k]) && is_numeric($kv[$k]) ? (float)$kv[$k] : null;
        $totalmem = $num('totalmem'); $freemem = $num('freemem');
        $totalhdd = $num('totalhdd'); $freehdd = $num('freehdd');
        $data = [
            'identity' => [
                'name' => $kv['name'] ?? null, 'model' => $kv['model'] ?? null, 'serial' => $kv['serial'] ?? null,
                'board' => $kv['board'] ?? null, 'platform' => $kv['platform'] ?? null, 'arch' => $kv['arch'] ?? null,
                'version' => $kv['version'] ?? null, 'firmware' => $kv['firmware'] ?? null,
                'firmware_upgrade' => $kv['firmwareUpg'] ?? null, 'build' => $kv['buildtime'] ?? null,
                'uptime' => $kv['uptime'] ?? null,
            ],
            'resources' => [
                'cpu' => $kv['cpu'] ?? null, 'cpu_load' => $num('cpuload'), 'cpu_count' => $num('cpucount'),
                'cpu_freq' => $num('cpufreq'),
                'mem_total' => $totalmem, 'mem_free' => $freemem,
                'mem_used_pct' => ($totalmem && $totalmem > 0) ? round(($totalmem - (float)$freemem) / $totalmem * 100, 1) : null,
                'hdd_total' => $totalhdd, 'hdd_free' => $freehdd,
                'hdd_used_pct' => ($totalhdd && $totalhdd > 0) ? round(($totalhdd - (float)$freehdd) / $totalhdd * 100, 1) : null,
                'temp' => $num('temp'), 'voltage' => $num('voltage'), 'psu1' => $kv['psu1'] ?? null,
            ],
            'counts' => [
                'routes' => $num('routes'), 'addresses' => $num('addresses'),
                'leases' => $num('leases'), 'leases_bound' => $num('leasesBound'),
                'fw_filter' => $num('fwfilter'), 'fw_nat' => $num('fwnat'), 'fw_addrlist' => $num('fwaddr'),
                'wifi_clients' => $num('wifi'), 'capsman_clients' => $num('capsman'),
                'ppp_active' => $num('pppactive'), 'neighbors' => $num('neighbors'),
                'users' => $num('users'), 'active_users' => $num('activeUsers'),
            ],
            'interfaces' => $p['interfaces'],
            'addresses'  => $p['addresses'],
        ];
        return ['ok'=>true, 'vendor'=>'mikrotik', 'data'=>$data];
    }

    // List every router-kind node with quick vitals — backs the Router Monitor page
    // (routers.php), the analog of windows.php / linux.php.
    function nm_router_list($conn): array {
        nm_node_meta_ensure($conn);
        $out = [];
        $r = $conn->query("SELECT n.*, g.name grp_name, g.color grp_color
                           FROM nm_nodes n LEFT JOIN nm_groups g ON g.id=n.group_id
                           ORDER BY g.sort_order, n.display_name");
        while ($r && $n = $r->fetch_assoc()) {
            if (nm_node_kind($n) !== 'router') continue;
            $id = (int)$n['id'];
            $up = null; $lat = null; $loss = null;
            if ($pq = $conn->query("SELECT is_up, latency_ms, packet_loss FROM nm_ping_stats WHERE node_id=$id ORDER BY id DESC LIMIT 1")) {
                if ($x = $pq->fetch_assoc()) { $up = ((int)$x['is_up'] === 1); $lat = $x['latency_ms']; $loss = $x['packet_loss']; }
            }
            $inc = 0;
            if ($iq = $conn->query("SELECT COUNT(*) c FROM nm_incidents WHERE root_node_id=$id AND status IN('open','acknowledged')")) {
                $inc = (int)(($iq->fetch_assoc()['c']) ?? 0);
            }
            $up24 = null;
            if ($aq = $conn->query("SELECT SUM(is_up=1) u, COUNT(*) t FROM nm_ping_stats WHERE node_id=$id AND recorded_at > (NOW()-INTERVAL 24 HOUR)")) {
                if (($ax = $aq->fetch_assoc()) && (int)$ax['t'] > 0) $up24 = round((int)$ax['u'] / (int)$ax['t'] * 100, 1);
            }
            $out[] = [
                'id' => $id, 'name' => $n['display_name'], 'ip' => $n['ip_address'], 'os_icon' => $n['os_icon'],
                'manufacturer' => $n['manufacturer'] ?? null, 'model' => $n['model'] ?? null,
                'hw_model' => $n['hw_model'] ?? null, 'photo' => nm_node_photo_url($n),
                'grp' => $n['grp_name'] ?? null, 'grp_color' => $n['grp_color'] ?? null,
                'up' => $up, 'latency' => $lat !== null ? (float)$lat : null, 'loss' => $loss !== null ? (float)$loss : null,
                'incidents' => $inc, 'uptime24' => $up24,
                'mikrotik' => in_array(strtolower((string)$n['os_icon']), ['mikrotik','routeros'], true),
            ];
        }
        return $out;
    }

    // ── Live per-interface THROUGHPUT (for the WebGL traffic hologram) ───────────
    // RouterOS one-shot: read all counters, :delay 1s, read again → PHP computes bps.
    // Cheap enough to poll every ~8-10s from the page for moving flows.
    function nm_router_traffic_script(): string {
        return implode('; ', [
            ':foreach i in=[/interface find] do={ :put ("s1|" . [/interface get $i name] . "|" . [/interface get $i rx-byte] . "|" . [/interface get $i tx-byte]) }',
            ':delay 1s',
            ':foreach i in=[/interface find] do={ :put ("s2|" . [/interface get $i name] . "|" . [/interface get $i running] . "|" . [/interface get $i disabled] . "|" . [/interface get $i type] . "|" . [/interface get $i rx-byte] . "|" . [/interface get $i tx-byte]) }',
            ':put "NM_END"',
        ]);
    }
    function nm_router_traffic_probe($conn, array $node): array {
        if (nm_node_kind($node) !== 'router') return ['ok'=>false, 'error'=>'not a router'];
        $os = strtolower((string)($node['os_icon'] ?? ''));
        if (!in_array($os, ['mikrotik','routeros'], true)) return ['ok'=>false, 'error'=>'live traffic supports MikroTik only'];
        if (!function_exists('nm_cm_ssh_fetch')) require_once __DIR__ . '/nm_confmgr.php';
        $ssh = nm_ssh_resolve($conn, (int)$node['id']);
        if (!$ssh || empty($ssh['username']) || (empty($ssh['password']) && empty($ssh['private_key'])))
            return ['ok'=>false, 'error'=>'no SSH credential'];
        $fetch = nm_cm_ssh_fetch($ssh, nm_router_traffic_script(), 20);
        if (empty($fetch['ok'])) return ['ok'=>false, 'error'=>$fetch['error'] ?? 'probe failed'];

        $s1 = []; $meta = [];
        foreach (preg_split('/\r?\n/', (string)$fetch['config']) as $ln) {
            $ln = trim($ln); if ($ln === '' || $ln === 'NM_END') continue;
            $p = explode('|', $ln);
            if (($p[0] ?? '') === 's1') { $s1[$p[1] ?? ''] = ['rx'=>(float)($p[2] ?? 0), 'tx'=>(float)($p[3] ?? 0)]; }
            elseif (($p[0] ?? '') === 's2') { $meta[$p[1] ?? ''] = ['running'=>($p[2] ?? '')==='true', 'disabled'=>($p[3] ?? '')==='true',
                'type'=>$p[4] ?? '', 'rx'=>(float)($p[5] ?? 0), 'tx'=>(float)($p[6] ?? 0)]; }
        }
        $ifs = []; $totRx = 0; $totTx = 0;
        foreach ($meta as $nm => $m) {
            $a = $s1[$nm] ?? null; if (!$a) continue;
            $rxbps = max(0, ($m['rx'] - $a['rx'])) * 8;   // ~1s window (bytes→bits)
            $txbps = max(0, ($m['tx'] - $a['tx'])) * 8;
            $totRx += $rxbps; $totTx += $txbps;
            $ifs[] = ['name'=>$nm, 'type'=>$m['type'], 'running'=>$m['running'], 'disabled'=>$m['disabled'],
                      'rx_bps'=>round($rxbps), 'tx_bps'=>round($txbps)];
        }
        usort($ifs, fn($a,$b)=>($b['rx_bps']+$b['tx_bps']) <=> ($a['rx_bps']+$a['tx_bps']));
        return ['ok'=>true, 'interfaces'=>$ifs, 'total_rx_bps'=>round($totRx), 'total_tx_bps'=>round($totTx)];
    }

    // Live traffic if SSH works; else fall back to the poller's CONFIGURED interfaces (no live
    // rates) so a router without an SSH credential still shows its ports instead of nothing.
    function nm_router_traffic_or_config($conn, array $node): array {
        $t = nm_router_traffic_probe($conn, $node);
        if (!empty($t['ok'])) { $t['live'] = true; return $t; }
        $snap = nm_router_db_snapshot($conn, $node);
        $ifs = [];
        foreach ($snap['interfaces'] as $i) $ifs[] = ['name'=>($i['display_name'] ?: $i['if_name']), 'type'=>'',
            'running'=>true, 'disabled'=>false, 'rx_bps'=>0, 'tx_bps'=>0];
        if (!$ifs) return $t;   // nothing polled either → keep the original error
        return ['ok'=>true, 'live'=>false, 'error'=>$t['error'] ?? 'no live SSH',
                'interfaces'=>$ifs, 'total_rx_bps'=>0, 'total_tx_bps'=>0];
    }

    // NetFlow slice for this router (if it's an exporter) — top apps + talkers by its IP.
    function nm_router_netflow($conn, array $node, int $mins = 60): array {
        if (!is_file(__DIR__ . '/nm_netflow.php')) return ['ok'=>false];
        require_once __DIR__ . '/nm_netflow.php';
        $ip = (string)($node['ip_address'] ?? ''); if ($ip === '') return ['ok'=>false];
        try {
            $apps = function_exists('nm_nf_top_apps') ? nm_nf_top_apps($conn, $mins, $ip, 8) : [];
            $tk   = function_exists('nm_nf_top_talkers') ? nm_nf_top_talkers($conn, $mins, 'dst', $ip, 8) : [];
            if (!$apps && !$tk) return ['ok'=>false];
            return ['ok'=>true, 'apps'=>$apps, 'talkers'=>$tk];
        } catch (\Throwable $e) { return ['ok'=>false]; }
    }

    // Real NetFlow conversations for this router, split inbound vs outbound, geo-tagged —
    // powers the "click an interface → watch traffic fly to its destinations" view.
    function nm_router_flows($conn, array $node, int $mins = 30): array {
        if (!is_file(__DIR__ . '/nm_netflow.php')) return ['ok'=>false, 'error'=>'netflow not available'];
        require_once __DIR__ . '/nm_netflow.php';
        if (!function_exists('nm_geo_badge')) @require_once __DIR__ . '/nm_nettools.php';
        $ip = (string)($node['ip_address'] ?? ''); if ($ip === '') return ['ok'=>false];
        $priv = function($x){ return function_exists('nm_nt_is_private') ? nm_nt_is_private($x)
            : (bool)preg_match('/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|f[cde])/i', (string)$x); };
        $geo  = function($x) use ($conn){ return function_exists('nm_geo_badge') ? nm_geo_badge($conn, $x) : null; };
        try {
            // 1) If the router IS a NetFlow exporter → its FORWARDED traffic (all it routes).
            $conv = function_exists('nm_nf_top_conversations') ? nm_nf_top_conversations($conn, $mins, $ip, 60) : [];
            $participant = false;
            // 2) Else fall back to flows where this router's IP is a participant (src/dst),
            //    as seen by ANY exporter — so non-exporting routers still show their conversations.
            if (!$conv) {
                $esc = $conn->real_escape_string($ip); $m = max(1, (int)$mins); $secs = $m * 60;
                $r = $conn->query("SELECT src_ip, dst_ip, app_port, protocol, SUM(bytes) b, SUM(flows) f
                    FROM nm_netflow_flows WHERE bucket >= (NOW() - INTERVAL {$m} MINUTE) AND (src_ip='{$esc}' OR dst_ip='{$esc}')
                    GROUP BY src_ip, dst_ip, app_port, protocol ORDER BY b DESC LIMIT 60");
                while ($r && $x = $r->fetch_assoc()) $conv[] = ['src'=>$x['src_ip'], 'dst'=>$x['dst_ip'],
                    'app'=>function_exists('nm_nf_app_name')?nm_nf_app_name((int)$x['app_port'],(int)$x['protocol']):('port '.$x['app_port']),
                    'bytes'=>(float)$x['b'], 'mbps'=>(float)$x['b']*8/$secs/1e6, 'flows'=>(int)$x['f']];
                $participant = true;
                if (!$conv) return ['ok'=>false, 'error'=>'no NetFlow seen for this router. Enable Traffic-Flow export to the collector, or it must transit an exporter.'];
            }
            $out = []; $in = [];
            foreach ($conv as $c) {
                $src = (string)$c['src']; $dst = (string)$c['dst'];
                // exact direction when the router itself is an endpoint; else infer from public side
                if     ($src === $ip)     { $remote = $dst; $inbound = false; }
                elseif ($dst === $ip)     { $remote = $src; $inbound = true;  }
                elseif (!$priv($dst))     { $remote = $dst; $inbound = false; }
                elseif (!$priv($src))     { $remote = $src; $inbound = true;  }
                else                      { $remote = $dst; $inbound = false; }
                $ext = !$priv($remote); $g = $ext ? $geo($remote) : null;
                $entry = ['ip'=>$remote, 'peer'=>($remote===$dst?$src:$dst), 'app'=>$c['app'], 'mbps'=>round((float)$c['mbps'],3),
                          'bytes'=>(float)$c['bytes'], 'flag'=>$g['flag'] ?? '', 'country'=>$g['country'] ?? ($ext?'':'LAN'), 'ext'=>$ext?1:0];
                if ($inbound) $in[] = $entry; else $out[] = $entry;
            }
            return ['ok'=>true, 'mode'=>$participant?'participant':'exporter',
                    'outbound'=>array_slice($out,0,18), 'inbound'=>array_slice($in,0,18),
                    'out_total'=>count($out), 'in_total'=>count($in)];
        } catch (\Throwable $e) { return ['ok'=>false, 'error'=>$e->getMessage()]; }
    }

    // Pretty helpers shared with the page.
    function nm_router_bytes(?float $b): string {
        if ($b === null) return '—';
        $u = ['B','KB','MB','GB','TB','PB']; $i = 0; $b = (float)$b;
        while ($b >= 1024 && $i < count($u)-1) { $b /= 1024; $i++; }
        return round($b, $b < 10 && $i > 0 ? 1 : 0) . ' ' . $u[$i];
    }
}
