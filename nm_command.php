<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Command Center engine.
//
// Powers command.php: the interactive, in-portal sibling of the read-only NOC
// Geo Wall (geomap.php). It REUSES nm_geomap.php's payload VERBATIM for the map
// (geo coords, incidents, down, top-traffic, NetFlow talkers, WG peers, containers)
// and only adds:
//   • per-user HUD widget layout persistence  (nm_dash_layout)
//   • a few extra widget data sources that the kiosk doesn't surface:
//       - per-interface top traffic        (nm_port_stats ∪ nm_interfaces)
//       - Smokeping latency snapshot        (nm_sp_* / nm_latency_samples)
//       - Pi-hole top domains/clients       (nm_ph_* proxy, cached 30s)
//       - live syslog tail                  (nm_syslog)
//
// RBAC perm: 'command'.  No cron — browser-polled, like the kiosk.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_cmd_ensure')) {
    require_once __DIR__ . '/nm_geomap.php';     // map payload (reused verbatim)

    function nm_cmd_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        nm_geomap_ensure($conn);                 // geo coords + 'geomap' perm + dashboard role
        $conn->query("CREATE TABLE IF NOT EXISTS nm_dash_layout (
            uid INT PRIMARY KEY,
            layout LONGTEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // admins get the Command Center by default.
        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','command',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='command')");
    }

    // ── Per-user HUD layout (which widgets are on, position, collapsed) ─────────
    function nm_cmd_layout_get($conn, int $uid): ?array {
        nm_cmd_ensure($conn);
        $st = $conn->prepare("SELECT layout FROM nm_dash_layout WHERE uid=?");
        $st->bind_param('i', $uid); $st->execute();
        $r = $st->get_result()->fetch_assoc();
        if (!$r || $r['layout'] === null || $r['layout'] === '') return null;
        $d = json_decode($r['layout'], true);
        return is_array($d) ? $d : null;
    }
    function nm_cmd_layout_set($conn, int $uid, array $layout): array {
        nm_cmd_ensure($conn);
        $json = json_encode($layout, JSON_UNESCAPED_SLASHES);
        if ($json === false || strlen($json) > 65000) return ['ok'=>false,'error'=>'Layout too large'];
        $st = $conn->prepare("INSERT INTO nm_dash_layout (uid,layout) VALUES (?,?)
            ON DUPLICATE KEY UPDATE layout=VALUES(layout)");
        $st->bind_param('is', $uid, $json); $st->execute();
        return ['ok'=>true];
    }

    // ── Per-INTERFACE top traffic (kiosk's nm_geomap_top_traffic is per-NODE) ──
    function nm_cmd_top_interfaces($conn, int $limit = 12): array {
        $out = [];
        if (!$conn->query("SHOW TABLES LIKE 'nm_port_stats'")->num_rows) return $out;
        $limit = max(1, min(40, $limit));
        $r = $conn->query("SELECT n.display_name node, n.ip_address ip,
                COALESCE(NULLIF(i.display_name,''), i.if_name) iface,
                ps.in_rate, ps.out_rate
            FROM nm_port_stats ps
            JOIN (SELECT node_id,port_id,MAX(recorded_at) mx FROM nm_port_stats GROUP BY node_id,port_id) lp
              ON ps.node_id=lp.node_id AND ps.port_id=lp.port_id AND ps.recorded_at=lp.mx
            JOIN nm_interfaces i ON i.id=ps.port_id AND i.node_id=ps.node_id
            JOIN nm_nodes n ON n.id=ps.node_id
            ORDER BY (COALESCE(ps.in_rate,0)+COALESCE(ps.out_rate,0)) DESC LIMIT {$limit}");
        while ($r && ($x = $r->fetch_assoc())) $out[] = [
            'node'=>$x['node'],'ip'=>$x['ip'],'iface'=>$x['iface'] ?: '—',
            'in_rate'=>(float)$x['in_rate'],'out_rate'=>(float)$x['out_rate'],
            'total'=>(float)$x['in_rate']+(float)$x['out_rate']];
        return $out;
    }

    // ── Smokeping latency snapshot: per-node latest RTT + tiny spark series ─────
    function nm_cmd_smokeping($conn, int $limit = 12): array {
        if (!function_exists('nm_sp_spark_all')) { @require_once __DIR__ . '/nm_smokeping.php'; }
        if (!$conn->query("SHOW TABLES LIKE 'nm_latency_samples'")->num_rows) return [];
        $spark = function_exists('nm_sp_spark_all') ? nm_sp_spark_all($conn, 1, 40) : [];
        $names = [];
        $r = $conn->query("SELECT id, display_name FROM nm_nodes");
        while ($r && ($x = $r->fetch_assoc())) $names[(int)$x['id']] = $x['display_name'];
        $out = [];
        foreach ($spark as $nid => $series) {
            $vals = array_values(array_filter($series, fn($v)=>$v!==null));
            if (!$vals) continue;
            $last = end($vals);
            $out[] = ['node_id'=>(int)$nid,'name'=>$names[$nid] ?? ('node '.$nid),
                'rtt'=>round((float)$last,1),'avg'=>round(array_sum($vals)/count($vals),1),
                'spark'=>array_map(fn($v)=>$v===null?null:round((float)$v,1), array_slice($series,-40))];
        }
        usort($out, fn($a,$b)=>$b['rtt']<=>$a['rtt']);   // worst first
        return array_slice($out, 0, max(1,min(30,$limit)));
    }

    // ── Pi-hole: top queried domains + top clients + summary (cached 30s) ──────
    function nm_cmd_pihole($conn): array {
        if (!function_exists('nm_ph_default_id')) { @require_once __DIR__ . '/nm_pihole.php'; }
        if (!function_exists('nm_ph_default_id')) return ['ok'=>false];
        $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='command_ph_cache' LIMIT 1");
        if ($r && ($x = $r->fetch_row())) { $d = json_decode($x[0], true); if (is_array($d) && (time()-($d['t']??0) < 30)) return $d['v']; }
        $out = ['ok'=>false,'queries'=>[],'clients'=>[],'blocked_pct'=>null,'total'=>null,'blocked'=>null];
        $id = nm_ph_default_id($conn);
        if ($id > 0) {
            $dom = nm_ph_call($conn, $id, 'stats/top_domains', ['blocked'=>'false','count'=>8]);
            if ($dom['ok'] && isset($dom['data']['domains'])) {
                foreach ($dom['data']['domains'] as $d) $out['queries'][] = ['name'=>$d['domain'] ?? '', 'count'=>(int)($d['count'] ?? 0)];
                $out['ok'] = true;
            }
            $cli = nm_ph_call($conn, $id, 'stats/top_clients', ['count'=>8]);
            if ($cli['ok'] && isset($cli['data']['clients'])) {
                foreach ($cli['data']['clients'] as $c) $out['clients'][] = ['name'=>($c['name'] ?: $c['ip']) ?? '', 'ip'=>$c['ip'] ?? '', 'count'=>(int)($c['count'] ?? 0)];
            }
            $sum = nm_ph_call($conn, $id, 'stats/summary', []);
            if ($sum['ok'] && isset($sum['data']['queries'])) {
                $q = $sum['data']['queries'];
                $out['total']   = (int)($q['total'] ?? 0);
                $out['blocked'] = (int)($q['blocked'] ?? 0);
                $out['blocked_pct'] = isset($q['percent_blocked']) ? round((float)$q['percent_blocked'],1) : null;
            }
        }
        // Cache write is NON-critical — never let it (e.g. "Data too long", mysqli exception mode)
        // abort the whole dashboard payload build. Best-effort.
        try {
            $conn->query("INSERT INTO nm_settings (setting_key,setting_val) VALUES ('command_ph_cache','".$conn->real_escape_string(json_encode(['t'=>time(),'v'=>$out]))."')
                ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
        } catch (\Throwable $e) { /* cache miss is fine; live data already computed */ }
        return $out;
    }

    // ── Container LIST (names + state + host) for the filterable widget ────────
    // Reuses the same Portainer connection as nm_geomap_containers. Cached 30s.
    function nm_cmd_container_list($conn, int $cap = 300): array {
        $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='command_cont_list' LIMIT 1");
        if ($r && ($x = $r->fetch_row())) { $d = json_decode($x[0], true); if (is_array($d) && (time()-($d['t']??0) < 30)) return $d['v']; }
        if (!function_exists('nm_portainer_cfg')) { @require_once __DIR__ . '/nm_portainer.php'; }
        $out = ['ok'=>false,'hosts'=>[],'items'=>[]];
        if (function_exists('nm_portainer_cfg')) {
            $cfg = nm_portainer_cfg($conn);
            if (nm_portainer_configured($cfg)) {
                $eR = nm_portainer_endpoints($cfg);
                if ($eR['ok']) {
                    $hosts = [];
                    foreach ((array)$eR['data'] as $e) {
                        $eid = (int)($e['Id'] ?? 0); if (!$eid) continue;
                        $host = (string)($e['Name'] ?? ('endpoint '.$eid)); $hosts[] = $host;
                        $cR = nm_portainer_containers($cfg, $eid, true);
                        if (!$cR['ok']) continue;
                        foreach ((array)$cR['data'] as $c) {
                            $nm = (isset($c['Names']) && is_array($c['Names'])) ? ltrim((string)($c['Names'][0] ?? ''), '/') : '';
                            $out['items'][] = ['name'=>$nm ?: '(unnamed)','state'=>strtolower((string)($c['State'] ?? '')),
                                'host'=>$host,'image'=>(string)($c['Image'] ?? ''),
                                'cid'=>(string)($c['Id'] ?? ''),'eid'=>$eid,'status'=>(string)($c['Status'] ?? '')];
                            if (count($out['items']) >= $cap) break 2;
                        }
                    }
                    $out['hosts'] = array_values(array_unique($hosts));
                    $out['ok'] = true;
                    usort($out['items'], fn($a,$b)=>[$a['state']!=='running',$a['host'],$a['name']] <=> [$b['state']!=='running',$b['host'],$b['name']]);
                }
            }
        }
        // Best-effort cache write — a failed cache (too-long/exception) must never take down the
        // live dashboard (?api=dash). The data above is already built; caching is just a 30s bonus.
        try {
            $conn->query("INSERT INTO nm_settings (setting_key,setting_val) VALUES ('command_cont_list','".$conn->real_escape_string(json_encode(['t'=>time(),'v'=>$out]))."')
                ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
        } catch (\Throwable $e) { /* non-critical */ }
        return $out;
    }

    // ── Live syslog tail (most recent, severity-tagged) ────────────────────────
    function nm_cmd_syslog($conn, int $limit = 25): array {
        $out = [];
        if (!$conn->query("SHOW TABLES LIKE 'nm_syslog'")->num_rows) return $out;
        $limit = max(1, min(80, $limit));
        $r = $conn->query("SELECT received_at, hostname, host_ip, severity, tag, message
            FROM nm_syslog ORDER BY received_at DESC, id DESC LIMIT {$limit}");
        while ($r && ($x = $r->fetch_assoc())) $out[] = [
            'at'=>$x['received_at'],'host'=>$x['hostname'] ?: $x['host_ip'],'ip'=>$x['host_ip'],
            'sev'=>(int)$x['severity'],'tag'=>$x['tag'],
            'msg'=>mb_substr((string)$x['message'],0,180)];
        return $out;
    }

    // Detail for a clicked syslog line: the originating node (matched by IP, else
    // hostname) + its live status, plus the recent FULL log tail for that host.
    function nm_cmd_syslog_detail($conn, string $host, string $ip, int $limit = 40): array {
        nm_cmd_ensure($conn);
        $limit = max(1, min(120, $limit));
        if (!$conn->query("SHOW TABLES LIKE 'nm_syslog'")->num_rows) return ['ok'=>false,'error'=>'No syslog table'];
        $ipEsc = $conn->real_escape_string($ip); $hEsc = $conn->real_escape_string($host);
        // match a node by IP first (most reliable), else by display_name
        $node = null;
        $cond = $ip !== '' ? "ip_address='{$ipEsc}'" : ($host !== '' ? "display_name='{$hEsc}'" : '0');
        $nr = $conn->query("SELECT id, display_name, ip_address, os_icon, COALESCE(monitor_type,'snmp') monitor_type
            FROM nm_nodes WHERE {$cond} LIMIT 1");
        if ($nr && ($n = $nr->fetch_assoc())) {
            $node = ['id'=>(int)$n['id'],'name'=>$n['display_name'],'ip'=>$n['ip_address'],
                     'os_icon'=>$n['os_icon'],'monitor_type'=>$n['monitor_type'],'status'=>'unknown'];
            $pr = $conn->query("SELECT is_up FROM nm_ping_stats WHERE node_id=".(int)$n['id']." ORDER BY id DESC LIMIT 1");
            if ($pr && ($p = $pr->fetch_row())) $node['status'] = $p[0] ? 'up' : 'down';
        }
        // recent full logs for this host (by IP or hostname)
        $where = [];
        if ($ip !== '')   $where[] = "host_ip='{$ipEsc}'";
        if ($host !== '') $where[] = "hostname='{$hEsc}'";
        $w = $where ? '(' . implode(' OR ', $where) . ')' : '1=0';
        $logs = []; $sev = ['err'=>0,'warn'=>0,'info'=>0];
        $r = $conn->query("SELECT received_at, severity, tag, message FROM nm_syslog
            WHERE {$w} ORDER BY received_at DESC, id DESC LIMIT {$limit}");
        while ($r && ($x = $r->fetch_assoc())) {
            $s = (int)$x['severity'];
            if ($s <= 3) $sev['err']++; elseif ($s === 4) $sev['warn']++; else $sev['info']++;
            $logs[] = ['at'=>$x['received_at'],'sev'=>$s,'tag'=>$x['tag'],'msg'=>mb_substr((string)$x['message'],0,1200)];
        }
        return ['ok'=>true,'node'=>$node,'host'=>$host,'ip'=>$ip,'sev'=>$sev,'logs'=>$logs];
    }

    // The consolidated Command Center poll: kiosk map payload + interactive extras.
    // The topo itself is still pulled by the page from net_mon_map.php?api=topo.
    function nm_cmd_payload($conn, array $want = []): array {
        nm_cmd_ensure($conn);
        $base = nm_geomap_payload($conn);
        $all = empty($want);
        $extra = [];
        if ($all || in_array('top_if',  $want, true)) $extra['top_if']  = nm_cmd_top_interfaces($conn);
        if ($all || in_array('smoke',   $want, true)) $extra['smoke']   = nm_cmd_smokeping($conn);
        if ($all || in_array('pihole',  $want, true)) $extra['pihole']  = nm_cmd_pihole($conn);
        if ($all || in_array('syslog',  $want, true)) $extra['syslog']  = nm_cmd_syslog($conn);
        if ($all || in_array('cont',    $want, true)) $extra['cont_list'] = nm_cmd_container_list($conn);
        return $base + $extra;
    }
}
