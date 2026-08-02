<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Geo Map (NOC video-wall) engine.
//
// The kiosk page (geomap.php) reuses net_mon_map.php?api=topo VERBATIM for the
// nodes + links + traffic (same connectors/logic), and this engine supplies the
// geographic overlay + side widgets:
//   • node coordinates (extends nm_node_geo from Weather with city/country)
//   • incidents needing attention, nodes down, top-traffic, container summary,
//     NetFlow top-talkers (geolocated for the map arcs).
//
// Also defines the read-only 'dashboard' role (lands straight on geomap.php).
// RBAC perm: 'geomap'.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_geomap_ensure')) {
    require_once __DIR__ . '/nm_nettools.php';   // nm_nt_geoip (cached) for NetFlow + auto-locate
    @require_once __DIR__ . '/nm_portainer.php'; // container summary (nm_portainer_cfg/endpoints/containers)

    function nm_geomap_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        // nm_node_geo already exists (Weather). Extend it; create if Weather never ran.
        $conn->query("CREATE TABLE IF NOT EXISTS nm_node_geo (
            node_id INT PRIMARY KEY, lat DOUBLE NOT NULL, lon DOUBLE NOT NULL,
            link_type VARCHAR(16) DEFAULT 'fiber',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        foreach (['city'=>"city VARCHAR(80) DEFAULT NULL", 'country'=>"country VARCHAR(80) DEFAULT NULL"] as $c=>$ddl) {
            $r = $conn->query("SHOW COLUMNS FROM nm_node_geo LIKE '{$c}'");
            if (!$r || $r->num_rows === 0) @$conn->query("ALTER TABLE nm_node_geo ADD COLUMN {$ddl}");
        }
        // perms: admin sees geomap; the read-only 'dashboard' role sees ONLY geomap + the topo it consumes.
        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','geomap',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='geomap')");
        foreach (['geomap','net_mon_map'] as $k) {
            @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'dashboard','{$k}',1 FROM DUAL
                WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='dashboard' AND button_key='{$k}')");
        }
    }

    // Upsert coordinates for a node (extends Weather's nm_wx_set_geo with city/country).
    function nm_geomap_set_geo($conn, int $nodeId, float $lat, float $lon, ?string $city, ?string $country, string $linkType = 'fiber'): array {
        nm_geomap_ensure($conn);
        $linkType = in_array($linkType, ['fiber','microwave','satellite','copper'], true) ? $linkType : 'fiber';
        $city = $city !== null ? substr(trim($city),0,80) : null;
        $country = $country !== null ? substr(trim($country),0,80) : null;
        $st = $conn->prepare("INSERT INTO nm_node_geo (node_id,lat,lon,city,country,link_type) VALUES (?,?,?,?,?,?)
            ON DUPLICATE KEY UPDATE lat=VALUES(lat),lon=VALUES(lon),city=VALUES(city),country=VALUES(country),link_type=VALUES(link_type)");
        $st->bind_param('iddsss', $nodeId,$lat,$lon,$city,$country,$linkType);
        $st->execute();
        return ['ok'=>true];
    }
    function nm_geomap_del_geo($conn, int $nodeId): void { $conn->query("DELETE FROM nm_node_geo WHERE node_id=".(int)$nodeId); }

    // node_id => {lat,lon,city,country,link_type,name,ip}
    function nm_geomap_geo_map($conn): array {
        nm_geomap_ensure($conn);
        $out = [];
        $r = $conn->query("SELECT g.node_id,g.lat,g.lon,g.city,g.country,g.link_type,n.display_name name,n.ip_address ip
            FROM nm_node_geo g JOIN nm_nodes n ON n.id=g.node_id");
        while ($r && ($x = $r->fetch_assoc())) $out[(int)$x['node_id']] = [
            'id'=>(int)$x['node_id'],'lat'=>(float)$x['lat'],'lon'=>(float)$x['lon'],
            'city'=>$x['city'],'country'=>$x['country'],'link_type'=>$x['link_type'],'name'=>$x['name'],'ip'=>$x['ip']];
        return $out;
    }

    // Incidents needing attention (open/acknowledged), severity-ordered.
    function nm_geomap_incidents($conn, int $limit = 12): array {
        $out = [];
        if (!$conn->query("SHOW TABLES LIKE 'nm_incidents'")->num_rows) return $out;
        $limit = max(1, min(50, $limit));
        $r = $conn->query("SELECT id,title,severity,status,root_entity,root_node_id,impact_count,opened_at,updated_at
            FROM nm_incidents WHERE status IN ('open','acknowledged')
            ORDER BY FIELD(severity,'critical','warning','info'),(status='open') DESC, updated_at DESC LIMIT {$limit}");
        while ($r && ($x = $r->fetch_assoc())) $out[] = $x;
        return $out;
    }

    // Nodes currently down (latest ping is_up=0 within 15 min).
    function nm_geomap_down($conn): array {
        $out = [];
        if (!$conn->query("SHOW TABLES LIKE 'nm_ping_stats'")->num_rows) return $out;
        $r = $conn->query("SELECT p.node_id, n.display_name name, n.ip_address ip
            FROM nm_ping_stats p
            JOIN (SELECT node_id, MAX(recorded_at) mx FROM nm_ping_stats GROUP BY node_id) last
              ON last.node_id=p.node_id AND last.mx=p.recorded_at
            JOIN nm_nodes n ON n.id=p.node_id
            WHERE p.is_up=0 AND p.recorded_at >= (NOW() - INTERVAL 15 MINUTE)
            ORDER BY n.display_name");
        while ($r && ($x = $r->fetch_assoc())) $out[] = $x;
        return $out;
    }

    // Top traffic nodes by latest port-stat in+out (Mbps-ish rate sum).
    function nm_geomap_top_traffic($conn, int $limit = 10): array {
        $out = [];
        if (!$conn->query("SHOW TABLES LIKE 'nm_port_stats'")->num_rows) return $out;
        $limit = max(1, min(30, $limit));
        $r = $conn->query("SELECT n.id, n.display_name name, n.ip_address ip,
                SUM(ps.in_rate) in_rate, SUM(ps.out_rate) out_rate
            FROM nm_port_stats ps
            JOIN (SELECT node_id,port_id,MAX(recorded_at) mx FROM nm_port_stats GROUP BY node_id,port_id) lp
              ON ps.node_id=lp.node_id AND ps.port_id=lp.port_id AND ps.recorded_at=lp.mx
            JOIN nm_nodes n ON n.id=ps.node_id
            GROUP BY n.id ORDER BY (SUM(ps.in_rate)+SUM(ps.out_rate)) DESC LIMIT {$limit}");
        while ($r && ($x = $r->fetch_assoc())) $out[] = ['id'=>(int)$x['id'],'name'=>$x['name'],'ip'=>$x['ip'],
            'in_rate'=>(float)$x['in_rate'],'out_rate'=>(float)$x['out_rate'],'total'=>(float)$x['in_rate']+(float)$x['out_rate']];
        return $out;
    }

    // NetFlow top talkers (last N min) with cached GeoIP (for the map arcs).
    function nm_geomap_netflow($conn, int $limit = 20, int $mins = 10): array {
        $out = [];
        if (!$conn->query("SHOW TABLES LIKE 'nm_netflow_flows'")->num_rows) return $out;
        $limit = max(1, min(40, $limit)); $mins = max(1, min(120, $mins));
        $r = $conn->query("SELECT src_ip ip, SUM(bytes) b, SUM(flows) f
            FROM nm_netflow_flows WHERE bucket >= (NOW() - INTERVAL {$mins} MINUTE)
            GROUP BY src_ip ORDER BY b DESC LIMIT {$limit}");
        $secs = $mins * 60;
        while ($r && ($x = $r->fetch_assoc())) {
            $mbps = $secs ? round(((float)$x['b'] * 8) / $secs / 1e6, 2) : 0;
            $geo = nm_nt_geoip($conn, $x['ip']);
            $g = ($geo && empty($geo['private'])) ? ['lat'=>$geo['lat'],'lon'=>$geo['lon'],'city'=>$geo['city']??'','country'=>$geo['country']??'','asn'=>$geo['asn']??''] : null;
            $out[] = ['ip'=>$x['ip'],'mbps'=>$mbps,'flows'=>(int)$x['f'],'geo'=>$g];
        }
        return $out;
    }

    // Connected WireGuard peers, geolocated by their CURRENT public endpoint IP.
    // Each carries its server's node (the tunnel origin) so the wall can draw a
    // line from the WG router to where the peer is dialing in from.
    function nm_geomap_wgpeers($conn): array {
        if (!$conn->query("SHOW TABLES LIKE 'nm_wg_peers'")->num_rows) return [];
        $out = [];
        $r = $conn->query("SELECT p.name, p.endpoint, p.address_ip, p.rx_bytes, p.tx_bytes,
                s.node_id srv_node, s.name srv_name, s.iface_name
            FROM nm_wg_peers p JOIN nm_wg_servers s ON s.id=p.server_id
            WHERE p.connected=1 AND p.endpoint IS NOT NULL AND p.endpoint<>''");
        while ($r && ($x = $r->fetch_assoc())) {
            $ep = trim((string)$x['endpoint']);
            if (!filter_var($ep, FILTER_VALIDATE_IP)) continue;
            $geo = nm_nt_geoip($conn, $ep);
            if (!$geo || !empty($geo['private'])) continue;   // need a public endpoint to place it
            $out[] = [
                'name'      => $x['name'],
                'endpoint'  => $ep,
                'tunnel_ip' => $x['address_ip'],
                'iface'     => $x['iface_name'],
                'srv_node'  => (int)$x['srv_node'],
                'srv_name'  => $x['srv_name'],
                'geo'       => ['lat'=>$geo['lat'],'lon'=>$geo['lon'],'city'=>$geo['city']??'','country'=>$geo['country']??''],
            ];
        }
        return $out;
    }

    // Container summary (live Portainer), cached 45s so the kiosk poll stays fast.
    function nm_geomap_containers($conn): array {
        $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='geomap_cont_cache' LIMIT 1");
        if ($r && ($x = $r->fetch_row())) { $d = json_decode($x[0], true); if (is_array($d) && (time() - ($d['t'] ?? 0) < 45)) return $d['v']; }
        $sum = ['total'=>0,'running'=>0,'exited'=>0,'other'=>0,'ok'=>false];
        if (function_exists('nm_portainer_cfg')) {
            $cfg = nm_portainer_cfg($conn);
            if (nm_portainer_configured($cfg)) {
                $eR = nm_portainer_endpoints($cfg);
                if ($eR['ok']) {
                    foreach ((array)$eR['data'] as $e) {
                        $eid = (int)($e['Id'] ?? 0); if (!$eid) continue;
                        $cR = nm_portainer_containers($cfg, $eid, true);
                        if (!$cR['ok']) continue;
                        foreach ((array)$cR['data'] as $c) {
                            $sum['total']++; $st = strtolower($c['State'] ?? '');
                            if ($st === 'running') $sum['running']++; elseif ($st === 'exited') $sum['exited']++; else $sum['other']++;
                        }
                    }
                    $sum['ok'] = true;
                }
            }
        }
        // Best-effort cache write — must never crash the Geo Wall / Command Center payload if the
        // blob is oversized or MySQL throws (mysqli exception mode). The live data is already built.
        try {
            $conn->query("INSERT INTO nm_settings (setting_key,setting_val) VALUES ('geomap_cont_cache','".$conn->real_escape_string(json_encode(['t'=>time(),'v'=>$sum]))."')
                ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
        } catch (\Throwable $e) { /* non-critical */ }
        return $sum;
    }

    // The consolidated kiosk overlay payload (everything except the topo, which the
    // page pulls from net_mon_map.php?api=topo).
    function nm_geomap_payload($conn): array {
        nm_geomap_ensure($conn);
        $geo = nm_geomap_geo_map($conn);
        // origin = centroid of LOCAL (private-IP) nodes — anchor for NetFlow arcs.
        // Excludes public nodes (e.g. an 8.8.8.8 internet check) that would skew it.
        $olat = $olon = 0; $n = 0;
        foreach ($geo as $g) {
            $priv = $g['ip'] && filter_var($g['ip'], FILTER_VALIDATE_IP) &&
                    !filter_var($g['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
            if ($priv) { $olat += $g['lat']; $olon += $g['lon']; $n++; }
        }
        if (!$n) { foreach ($geo as $g) { $olat += $g['lat']; $olon += $g['lon']; $n++; } }
        $origin = $n ? ['lat'=>$olat/$n,'lon'=>$olon/$n] : null;
        return [
            'ts'        => date('c'),
            'geo'       => $geo,
            'origin'    => $origin,
            'incidents' => nm_geomap_incidents($conn),
            'down'      => nm_geomap_down($conn),
            'top'       => nm_geomap_top_traffic($conn),
            'netflow'   => nm_geomap_netflow($conn),
            'wgpeers'   => nm_geomap_wgpeers($conn),
            'containers'=> nm_geomap_containers($conn),
        ];
    }
}
