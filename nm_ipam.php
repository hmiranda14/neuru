<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — IPAM / Single Source of Truth (thin layer over the live inventory).
//
// This is NOT a second device inventory. It adds two things on top of what the
// portal already knows:
//   • a SUBNET registry (CIDR + metadata + utilization), and
//   • an ALLOCATION ledger (reservations) for IPs not yet tied to a polled node
//     — e.g. WireGuard peers, planned devices.
// The authoritative "which IPs are in use" answer is computed at runtime as a
// UNION of nm_nodes.ip_address ∪ nm_interfaces.if_ip_address ∪ nm_wg_peers.address_ip
// ∪ active allocations — so there is never a duplicate source of truth.
//
// IPv4 is fully supported (range scan for next-free). IPv6 subnets are registered
// and tracked but next-free scan is skipped (address space too large to enumerate).
//
// RBAC perm: 'ipam'. Engine for ipam.php + cron_ipam.php.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_ipam_ensure')) {

    function nm_ipam_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_ipam_subnets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            cidr VARCHAR(43) NOT NULL,
            network_addr VARBINARY(16) NOT NULL,
            prefix_len TINYINT UNSIGNED NOT NULL,
            family TINYINT UNSIGNED NOT NULL DEFAULT 4,
            description VARCHAR(200) DEFAULT NULL,
            vlan_id INT DEFAULT NULL,
            gateway_ip VARCHAR(45) DEFAULT NULL,
            gateway_node_id INT DEFAULT NULL,
            group_id INT DEFAULT NULL,
            kind VARCHAR(12) NOT NULL DEFAULT 'lan',
            is_managed TINYINT(1) NOT NULL DEFAULT 1,
            created_by INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_cidr (cidr),
            KEY idx_group (group_id),
            KEY idx_net (network_addr, prefix_len)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $conn->query("CREATE TABLE IF NOT EXISTS nm_ipam_allocations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            subnet_id INT NOT NULL,
            ip_address VARCHAR(45) NOT NULL,
            ip_bin VARBINARY(16) NOT NULL,
            status VARCHAR(10) NOT NULL DEFAULT 'reserved',
            source VARCHAR(12) NOT NULL DEFAULT 'manual',
            node_id INT DEFAULT NULL,
            wg_peer_id INT DEFAULT NULL,
            hostname VARCHAR(120) DEFAULT NULL,
            description VARCHAR(200) DEFAULT NULL,
            created_by INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            released_at DATETIME DEFAULT NULL,
            UNIQUE KEY uk_subnet_ip (subnet_id, ip_address),
            KEY idx_status (status),
            KEY idx_ipbin (ip_bin)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // ── Discovered live occupancy (the "in the air" hosts) ───────────────────
        // Filled by nm_ipam_scan.py (ping/SNMP sweep) + on-demand sweep. These are IPs
        // that ANSWER on the wire but are NOT managed nodes — so the free count stops
        // lying. is_managed is a denormalized cache (matches a node/iface at scan time).
        $conn->query("CREATE TABLE IF NOT EXISTS nm_ipam_live (
            id INT AUTO_INCREMENT PRIMARY KEY,
            subnet_id INT NOT NULL,
            ip_address VARCHAR(45) NOT NULL,
            ip_bin VARBINARY(16) NOT NULL,
            mac VARCHAR(17) DEFAULT NULL,
            hostname VARCHAR(255) DEFAULT NULL,
            method VARCHAR(12) NOT NULL DEFAULT 'ping',
            rtt_ms FLOAT DEFAULT NULL,
            is_managed TINYINT(1) NOT NULL DEFAULT 0,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen  DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_subnet_ip (subnet_id, ip_address),
            KEY idx_last (last_seen),
            KEY idx_ipbin (ip_bin)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // ── Detected DHCP servers + their served pools/ranges ────────────────────
        $conn->query("CREATE TABLE IF NOT EXISTS nm_ipam_dhcp_servers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            subnet_id INT DEFAULT NULL,
            server_ip VARCHAR(45) DEFAULT NULL,
            server_node_id INT DEFAULT NULL,
            source VARCHAR(16) NOT NULL DEFAULT 'ssh',
            pool_name VARCHAR(120) DEFAULT NULL,
            range_start VARCHAR(45) DEFAULT NULL,
            range_end VARCHAR(45) DEFAULT NULL,
            gateway VARCHAR(45) DEFAULT NULL,
            dns VARCHAR(255) DEFAULT NULL,
            lease_time VARCHAR(40) DEFAULT NULL,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_srv_pool (server_ip, pool_name),
            KEY idx_subnet (subnet_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // ── DHCP leases (IP ↔ MAC ↔ hostname), pulled from the DHCP server ───────
        $conn->query("CREATE TABLE IF NOT EXISTS nm_ipam_leases (
            id INT AUTO_INCREMENT PRIMARY KEY,
            subnet_id INT DEFAULT NULL,
            ip_address VARCHAR(45) NOT NULL,
            ip_bin VARBINARY(16) DEFAULT NULL,
            mac VARCHAR(17) DEFAULT NULL,
            hostname VARCHAR(255) DEFAULT NULL,
            server_ip VARCHAR(45) DEFAULT NULL,
            state VARCHAR(20) DEFAULT 'bound',
            is_static TINYINT(1) NOT NULL DEFAULT 0,
            expires DATETIME DEFAULT NULL,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_ip_mac (ip_address, mac),
            KEY idx_subnet (subnet_id),
            KEY idx_ipbin (ip_bin)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // gw_priority: how sure we are about the subnet's owning-device (gateway) — a higher-
        // confidence source (DHCP gateway match) overwrites a weaker one (any router on the subnet).
        // Guarded ALTER (mysqli is in exception mode → an unguarded ALTER would throw on re-run).
        $hasCol = $conn->query("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_ipam_subnets' AND COLUMN_NAME='gw_priority'");
        if ($hasCol && $hasCol->num_rows === 0) { try { $conn->query("ALTER TABLE nm_ipam_subnets ADD COLUMN gw_priority TINYINT DEFAULT 0"); } catch (\Throwable $e) {} }

        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','ipam',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='ipam')");
    }

    // ── CIDR / address math (IPv4 primary) ───────────────────────────────────
    // Returns: ['ok','cidr','net','prefix','family','first','last','count','net_long','bcast_long'] (longs for v4 only)
    function nm_ipam_parse_cidr(string $cidr): ?array {
        $cidr = trim($cidr);
        if (strpos($cidr, '/') === false) return null;
        [$ip, $pfx] = explode('/', $cidr, 2);
        $ip = trim($ip); $pfx = (int)$pfx;
        $packed = @inet_pton($ip);
        if ($packed === false) return null;
        $family = (strlen($packed) === 4) ? 4 : 6;
        if ($family === 4) {
            if ($pfx < 0 || $pfx > 32) return null;
            $ipL  = ip2long($ip) & 0xFFFFFFFF;
            $mask = $pfx === 0 ? 0 : ((0xFFFFFFFF << (32 - $pfx)) & 0xFFFFFFFF);
            $net  = $ipL & $mask;
            $bcast= $net | (~$mask & 0xFFFFFFFF);
            $count= $pfx >= 31 ? (1 << (32 - $pfx)) : ($bcast - $net + 1);
            // usable host range (exclude network + broadcast for /<=30)
            $first= $pfx <= 30 ? $net + 1 : $net;
            $last = $pfx <= 30 ? $bcast - 1 : $bcast;
            return ['ok'=>true,'cidr'=>long2ip($net).'/'.$pfx,'net'=>long2ip($net),'prefix'=>$pfx,'family'=>4,
                    'first'=>long2ip($first),'last'=>long2ip($last),'count'=>$count,
                    'net_long'=>$net,'bcast_long'=>$bcast,'net_bin'=>inet_pton(long2ip($net))];
        }
        if ($pfx < 0 || $pfx > 128) return null;
        return ['ok'=>true,'cidr'=>$ip.'/'.$pfx,'net'=>$ip,'prefix'=>$pfx,'family'=>6,
                'first'=>$ip,'last'=>$ip,'count'=>0,'net_long'=>null,'bcast_long'=>null,'net_bin'=>$packed];
    }

    function nm_ipam_in_subnet(string $ip, array $sn): bool {
        if ($sn['family'] !== 4) return false;               // v6 membership not scanned
        $p = @inet_pton($ip);
        if ($p === false || strlen($p) !== 4) return false;
        $l = ip2long($ip) & 0xFFFFFFFF;
        return $l >= $sn['net_long'] && $l <= $sn['bcast_long'];
    }

    // ── Subnet CRUD ───────────────────────────────────────────────────────────
    function nm_ipam_subnet_add($conn, array $f, ?int $uid): array {
        nm_ipam_ensure($conn);
        $p = nm_ipam_parse_cidr((string)($f['cidr'] ?? ''));
        if (!$p) return ['ok'=>false,'error'=>'Invalid CIDR'];
        $cidr = $p['cidr']; $netbin = $p['net_bin']; $pfx = $p['prefix']; $fam = $p['family'];
        $desc = substr(trim((string)($f['description'] ?? '')), 0, 200);
        $vlan = ($f['vlan_id'] ?? '') !== '' ? (int)$f['vlan_id'] : null;
        $gw   = substr(trim((string)($f['gateway_ip'] ?? '')), 0, 45) ?: null;
        $gwn  = ($f['gateway_node_id'] ?? '') !== '' ? (int)$f['gateway_node_id'] : null;
        $grp  = ($f['group_id'] ?? '') !== '' ? (int)$f['group_id'] : null;
        $kind = in_array(($f['kind'] ?? 'lan'), ['lan','wireguard','mgmt','dmz'], true) ? $f['kind'] : 'lan';
        $st = $conn->prepare("INSERT INTO nm_ipam_subnets (cidr,network_addr,prefix_len,family,description,vlan_id,gateway_ip,gateway_node_id,group_id,kind,created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON DUPLICATE KEY UPDATE description=VALUES(description),vlan_id=VALUES(vlan_id),gateway_ip=VALUES(gateway_ip),
                gateway_node_id=VALUES(gateway_node_id),group_id=VALUES(group_id),kind=VALUES(kind)");
        // cidr s, network_addr s(blob), prefix i, family i, desc s, vlan i, gw s, gwn i, grp i, kind s, uid i
        $st->bind_param('ssiisisiisi', $cidr,$netbin,$pfx,$fam,$desc,$vlan,$gw,$gwn,$grp,$kind,$uid);
        $st->execute();
        $id = $conn->insert_id ?: (int)($conn->query("SELECT id FROM nm_ipam_subnets WHERE cidr='".$conn->real_escape_string($cidr)."'")->fetch_row()[0] ?? 0);
        return ['ok'=>true,'id'=>$id,'cidr'=>$cidr];
    }
    function nm_ipam_subnet_update($conn, int $id, array $f): array {
        nm_ipam_ensure($conn);
        $desc = substr(trim((string)($f['description'] ?? '')), 0, 200);
        $vlan = ($f['vlan_id'] ?? '') !== '' ? (int)$f['vlan_id'] : null;
        $gw   = substr(trim((string)($f['gateway_ip'] ?? '')), 0, 45) ?: null;
        $kind = in_array(($f['kind'] ?? 'lan'), ['lan','wireguard','mgmt','dmz'], true) ? $f['kind'] : 'lan';
        $st = $conn->prepare("UPDATE nm_ipam_subnets SET description=?,vlan_id=?,gateway_ip=?,kind=? WHERE id=?");
        $st->bind_param('sissi', $desc,$vlan,$gw,$kind,$id);
        $st->execute();
        return ['ok'=>true];
    }
    function nm_ipam_subnet_delete($conn, int $id): array {
        nm_ipam_ensure($conn);
        $r = $conn->query("SELECT COUNT(*) FROM nm_ipam_allocations WHERE subnet_id={$id} AND status<>'released'");
        if ($r && (int)$r->fetch_row()[0] > 0) return ['ok'=>false,'error'=>'Subnet has active allocations — release them first'];
        $conn->query("DELETE FROM nm_ipam_subnets WHERE id={$id}");
        $conn->query("DELETE FROM nm_ipam_allocations WHERE subnet_id={$id}");
        return ['ok'=>true];
    }
    function nm_ipam_subnets($conn, ?int $group_id = null): array {
        nm_ipam_ensure($conn);
        $w = $group_id !== null ? "WHERE s.group_id=".(int)$group_id : '';
        // NOTE: never SELECT network_addr (VARBINARY) — json_encode() fails on binary
        // (invalid UTF-8) and returns false → empty response → UI stuck on "Loading…".
        // gateway_name = the owning device (router) so the UI can show where the subnet comes from.
        $out = []; $r = $conn->query("SELECT s.id,s.cidr,s.prefix_len,s.family,s.description,s.vlan_id,s.gateway_ip,s.gateway_node_id,s.group_id,s.kind,s.is_managed,s.created_by,s.created_at, n.display_name AS gateway_name
            FROM nm_ipam_subnets s LEFT JOIN nm_nodes n ON n.id=s.gateway_node_id $w ORDER BY s.family, s.prefix_len, s.cidr");
        while ($r && ($x = $r->fetch_assoc())) $out[] = $x;
        return $out;
    }
    function nm_ipam_subnet($conn, int $id): ?array {
        nm_ipam_ensure($conn);
        $r = $conn->query("SELECT * FROM nm_ipam_subnets WHERE id={$id} LIMIT 1");
        return $r ? ($r->fetch_assoc() ?: null) : null;
    }

    // ── SSoT: every IP the portal currently knows is live, within this subnet ──
    // Returns map: ['10.8.0.5' => ['source'=>'node|iface|wg|alloc','ref_id'=>N,'label'=>..,'status'=>..], ...]
    function nm_ipam_used_ips($conn, array $subnet): array {
        $sn = nm_ipam_parse_cidr($subnet['cidr']);
        if (!$sn) return [];
        $used = [];
        $add = function(string $ip, string $src, $ref, string $label, string $status='allocated') use (&$used, $sn) {
            $ip = trim($ip); if ($ip === '') return;
            if (!nm_ipam_in_subnet($ip, $sn)) return;
            if (!isset($used[$ip])) $used[$ip] = ['source'=>$src,'ref_id'=>$ref,'label'=>$label,'status'=>$status];
        };
        // 1) polled nodes
        $r = $conn->query("SELECT id,ip_address,display_name FROM nm_nodes WHERE ip_address IS NOT NULL AND ip_address<>''");
        while ($r && ($x = $r->fetch_assoc())) $add($x['ip_address'],'node',(int)$x['id'],$x['display_name']);
        // 2) interface IPs
        if ($conn->query("SHOW TABLES LIKE 'nm_interfaces'")->num_rows) {
            $r = $conn->query("SELECT node_id,if_ip_address,if_name FROM nm_interfaces WHERE if_ip_address IS NOT NULL AND if_ip_address<>''");
            while ($r && ($x = $r->fetch_assoc())) $add($x['if_ip_address'],'iface',(int)$x['node_id'],$x['if_name'] ?: 'iface');
        }
        // 3) WireGuard peers + server tunnel addresses (the server's own IP must
        //    never be handed to a peer)
        if ($conn->query("SHOW TABLES LIKE 'nm_wg_peers'")->num_rows) {
            $r = $conn->query("SELECT id,address_ip,name FROM nm_wg_peers WHERE address_ip IS NOT NULL AND address_ip<>''");
            while ($r && ($x = $r->fetch_assoc())) $add($x['address_ip'],'wg',(int)$x['id'],$x['name'] ?: 'peer');
        }
        if ($conn->query("SHOW TABLES LIKE 'nm_wg_servers'")->num_rows) {
            $r = $conn->query("SELECT id,address_cidr,name FROM nm_wg_servers WHERE address_cidr IS NOT NULL AND address_cidr<>''");
            while ($r && ($x = $r->fetch_assoc())) $add(explode('/',$x['address_cidr'])[0],'wg',(int)$x['id'],($x['name'] ?: 'server').' (gw)');
        }
        // 4) active allocations
        $r = $conn->query("SELECT id,ip_address,hostname,status,source FROM nm_ipam_allocations WHERE subnet_id=".(int)$subnet['id']." AND status<>'released'");
        while ($r && ($x = $r->fetch_assoc())) $add($x['ip_address'],'alloc',(int)$x['id'],$x['hostname'] ?: $x['source'],$x['status']);
        // 5) DHCP leases (IP ↔ MAC ↔ host) — occupied by the DHCP server
        if ($conn->query("SHOW TABLES LIKE 'nm_ipam_leases'")->num_rows) {
            $r = $conn->query("SELECT ip_address,mac,hostname FROM nm_ipam_leases WHERE subnet_id=".(int)$subnet['id']." OR subnet_id IS NULL");
            while ($r && ($x = $r->fetch_assoc())) $add($x['ip_address'],'dhcp',null,$x['hostname'] ?: ($x['mac'] ?: 'lease'));
        }
        // 6) discovered-but-unmanaged live hosts (the "in the air" devices) — seen on the
        //    wire recently but not a managed node. THIS is what makes free truthful.
        if ($conn->query("SHOW TABLES LIKE 'nm_ipam_live'")->num_rows) {
            $r = $conn->query("SELECT ip_address,mac,hostname FROM nm_ipam_live WHERE subnet_id=".(int)$subnet['id']." AND is_managed=0 AND last_seen > (NOW() - INTERVAL 7 DAY)");
            while ($r && ($x = $r->fetch_assoc())) $add($x['ip_address'],'discovered',null,$x['hostname'] ?: ($x['mac'] ?: 'live host'));
        }
        return $used;
    }

    function nm_ipam_utilization($conn, int $subnet_id): array {
        $sn = nm_ipam_subnet($conn, $subnet_id);
        if (!$sn) return ['total'=>0,'used'=>0,'free'=>0,'pct'=>0];
        $p = nm_ipam_parse_cidr($sn['cidr']);
        $used = nm_ipam_used_ips($conn, $sn);
        $usable = ($p && $p['family']===4) ? max(1, ($p['prefix'] <= 30 ? $p['count'] - 2 : $p['count'])) : 0;
        $u = count($used);
        return ['total'=>$usable,'used'=>$u,'free'=>max(0,$usable-$u),'pct'=>$usable? (int)round($u*100/$usable):0,
                'cidr'=>$sn['cidr'],'first'=>$p['first']??'','last'=>$p['last']??''];
    }

    // First free usable host address (string) or null. Skips network/bcast/gateway + every used IP.
    function nm_ipam_next_free($conn, int $subnet_id, array $opts = []): ?string {
        $sn = nm_ipam_subnet($conn, $subnet_id);
        if (!$sn) return null;
        $p = nm_ipam_parse_cidr($sn['cidr']);
        if (!$p || $p['family'] !== 4) return null;          // v6 not scanned
        $used = nm_ipam_used_ips($conn, $sn);
        $skip = [];
        foreach ($used as $ip => $_) $skip[ip2long($ip) & 0xFFFFFFFF] = true;
        if (!empty($sn['gateway_ip'])) { $g = ip2long($sn['gateway_ip']); if ($g !== false) $skip[$g & 0xFFFFFFFF] = true; }
        $start = ip2long($p['first']) & 0xFFFFFFFF;
        $end   = ip2long($p['last'])  & 0xFFFFFFFF;
        $end   = min($end, $start + 200000);   // cap the scan so a huge subnet (/8…) can never hang a request
        for ($l = $start; $l <= $end; $l++) {
            if (!isset($skip[$l])) return long2ip($l);
        }
        return null;
    }

    // Reserve an IP (or next-free if $ip null). Atomic on UNIQUE(subnet_id,ip_address).
    // $meta: ['source','node_id','wg_peer_id','hostname','description']
    function nm_ipam_reserve($conn, int $subnet_id, ?string $ip, array $meta, ?int $uid): array {
        nm_ipam_ensure($conn);
        $src   = in_array(($meta['source'] ?? 'manual'), ['manual','wireguard','discovery'], true) ? $meta['source'] : 'manual';
        $node  = ($meta['node_id'] ?? null) !== null ? (int)$meta['node_id'] : null;
        $peer  = ($meta['wg_peer_id'] ?? null) !== null ? (int)$meta['wg_peer_id'] : null;
        $host  = substr(trim((string)($meta['hostname'] ?? '')), 0, 120) ?: null;
        $desc  = substr(trim((string)($meta['description'] ?? '')), 0, 200) ?: null;
        $status= in_array(($meta['status'] ?? 'reserved'), ['reserved','allocated'], true) ? $meta['status'] : 'reserved';

        // up to 5 tries to dodge a race when $ip is auto-picked
        for ($try = 0; $try < 5; $try++) {
            $cand = $ip ?: nm_ipam_next_free($conn, $subnet_id);
            if (!$cand) return ['ok'=>false,'error'=>'No free address in subnet'];
            $bin = @inet_pton($cand); if ($bin === false) return ['ok'=>false,'error'=>'Invalid IP'];
            $st = $conn->prepare("INSERT INTO nm_ipam_allocations (subnet_id,ip_address,ip_bin,status,source,node_id,wg_peer_id,hostname,description,created_by)
                VALUES (?,?,?,?,?,?,?,?,?,?)");
            // subnet i, ip s, bin s(blob), status s, source s, node i, peer i, host s, desc s, uid i
            $st->bind_param('issssiissi', $subnet_id,$cand,$bin,$status,$src,$node,$peer,$host,$desc,$uid);
            try {
                if ($st->execute()) return ['ok'=>true,'id'=>$conn->insert_id,'ip'=>$cand];
            } catch (\Throwable $e) {
                if ($ip) return ['ok'=>false,'error'=>'IP already reserved'];  // explicit IP taken → don't retry
                // auto-pick collided → loop and try the next free
            }
        }
        return ['ok'=>false,'error'=>'Could not reserve (contention)'];
    }
    function nm_ipam_release($conn, int $alloc_id): array {
        nm_ipam_ensure($conn);
        $conn->query("UPDATE nm_ipam_allocations SET status='released', released_at=NOW() WHERE id=".(int)$alloc_id);
        return ['ok'=>true];
    }
    function nm_ipam_release_peer($conn, int $peer_id): void {
        $conn->query("UPDATE nm_ipam_allocations SET status='released', released_at=NOW() WHERE wg_peer_id=".(int)$peer_id." AND status<>'released'");
    }
    function nm_ipam_allocations($conn, ?int $subnet_id = null): array {
        nm_ipam_ensure($conn);
        $w = $subnet_id !== null ? "WHERE a.subnet_id=".(int)$subnet_id." AND a.status<>'released'" : "WHERE a.status<>'released'";
        $out = [];
        // exclude a.ip_bin (VARBINARY) — see nm_ipam_subnets note about json_encode + binary
        $r = $conn->query("SELECT a.id,a.subnet_id,a.ip_address,a.status,a.source,a.node_id,a.wg_peer_id,a.hostname,a.description,a.created_by,a.created_at,a.released_at, s.cidr FROM nm_ipam_allocations a JOIN nm_ipam_subnets s ON s.id=a.subnet_id $w ORDER BY a.ip_bin");
        while ($r && ($x = $r->fetch_assoc())) $out[] = $x;
        return $out;
    }

    // Conflicts: same IP claimed by >1 live source, or an allocation outside its subnet range.
    function nm_ipam_conflicts($conn, ?int $subnet_id = null): array {
        nm_ipam_ensure($conn);
        $subnets = $subnet_id !== null ? array_filter([nm_ipam_subnet($conn, $subnet_id)]) : nm_ipam_subnets($conn);
        $conflicts = [];
        foreach ($subnets as $sn) {
            if ((int)$sn['family'] !== 4) continue;
            $p = nm_ipam_parse_cidr($sn['cidr']); if (!$p) continue;
            // collect every claim per IP (allow duplicates here to detect collisions)
            $claims = [];
            $push = function($ip,$src,$ref,$label) use (&$claims,$p) {
                $ip = trim($ip); if ($ip==='' || !nm_ipam_in_subnet($ip,$p)) return;
                $claims[$ip][] = ['source'=>$src,'ref_id'=>$ref,'label'=>$label];
            };
            $r = $conn->query("SELECT id,ip_address,display_name FROM nm_nodes WHERE ip_address<>''");
            while ($r && ($x=$r->fetch_assoc())) $push($x['ip_address'],'node',(int)$x['id'],$x['display_name']);
            if ($conn->query("SHOW TABLES LIKE 'nm_wg_peers'")->num_rows) {
                $r = $conn->query("SELECT id,address_ip,name FROM nm_wg_peers WHERE address_ip<>''");
                while ($r && ($x=$r->fetch_assoc())) $push($x['address_ip'],'wg',(int)$x['id'],$x['name']);
            }
            // only STANDALONE reservations count as independent claims — an allocation
            // already backing a peer/node is bookkeeping for that same entity, not a conflict.
            $r = $conn->query("SELECT id,ip_address,hostname FROM nm_ipam_allocations WHERE subnet_id=".(int)$sn['id']." AND status<>'released' AND wg_peer_id IS NULL AND node_id IS NULL");
            while ($r && ($x=$r->fetch_assoc())) $push($x['ip_address'],'alloc',(int)$x['id'],$x['hostname']);
            foreach ($claims as $ip => $cs) {
                if (count($cs) > 1) $conflicts[] = ['subnet'=>$sn['cidr'],'ip'=>$ip,'claims'=>$cs];
            }
        }
        return $conflicts;
    }

    // ── Universal subnet discovery ───────────────────────────────────────────
    // Netmask (dotted or /prefix or bare number) → prefix length, or null.
    function nm_ipam_mask_to_prefix($mask): ?int {
        $mask = trim((string)$mask); if ($mask === '') return null;
        if ($mask[0] === '/') $mask = substr($mask, 1);
        if (ctype_digit($mask)) { $p = (int)$mask; return ($p >= 0 && $p <= 32) ? $p : null; }
        $l = @ip2long($mask); if ($l === false) return null;
        $bin = sprintf('%032b', $l & 0xFFFFFFFF);
        if (!preg_match('/^1*0*$/', $bin)) return null;      // not a contiguous mask
        return substr_count($bin, '1');
    }
    // Should this network be auto-registered? Only PRIVATE (RFC1918) + CGNAT (100.64/10) —
    // this is what makes it universal & pollution-free: a monitored box's PUBLIC IP (a VPS
    // WAN, 8.8.8.8, TEST-NET 192.0.2/24, etc.) must NEVER become "your subnet". Legit
    // VPN/WireGuard/container subnets are private, so they all pass. ($src kept for callers.)
    function nm_ipam_is_registerable(string $net, string $src = ''): bool {
        $l = @ip2long($net); if ($l === false) return false; $l &= 0xFFFFFFFF;
        $in = fn($a,$b)=> ($l & $b) === (($a & 0xFFFFFFFF) & $b);
        return $in(ip2long('10.0.0.0'),0xFF000000)        // 10.0.0.0/8
            || $in(ip2long('172.16.0.0'),0xFFF00000)      // 172.16.0.0/12 (incl. Docker 172.17-31)
            || $in(ip2long('192.168.0.0'),0xFFFF0000)     // 192.168.0.0/16
            || $in(ip2long('100.64.0.0'),0xFFC00000);     // 100.64.0.0/10 CGNAT (Tailscale-style VPNs)
    }

    // Comprehensive, NO-network subnet detection from every IP-bearing table NEURU already
    // has: monitored nodes (+mask), WireGuard tunnels + peer allowed_ips (VPN subnets!),
    // interface IPs, DHCP pools, active leases, and live-swept hosts. Universal: guards every
    // table so it works on any install. Returns ['ok','added','by_source'].
    function nm_ipam_detect_all($conn, ?int $uid = null): array {
        nm_ipam_ensure($conn);
        $seen = []; $by = []; $n = 0;
        foreach (nm_ipam_subnets($conn) as $s) { $p = nm_ipam_parse_cidr($s['cidr']); if ($p) $seen[$p['cidr']] = 1; }   // don't re-count existing
        $add = function(string $cidr, string $src, string $descr) use ($conn,$uid,&$seen,&$n,&$by) {
            $p = nm_ipam_parse_cidr($cidr); if (!$p || $p['family'] !== 4) return;
            if ($p['prefix'] >= 31) return;                          // host / point-to-point
            if (!nm_ipam_is_registerable($p['net'], $src)) return;
            if (isset($seen[$p['cidr']])) return; $seen[$p['cidr']] = 1;
            $kind = $src === 'wireguard' ? 'wireguard' : 'lan';
            $r = nm_ipam_subnet_add($conn, ['cidr'=>$p['cidr'],'kind'=>$kind,'description'=>$descr], $uid);
            if ($r['ok']) { $n++; $by[$src] = ($by[$src] ?? 0) + 1; }
        };
        // helper: bare IP with no mask → assume /24 (best-effort; the full sweep corrects with real masks)
        $add24 = function(string $ip, string $src, string $descr) use ($add) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) $add($ip.'/24', $src, $descr);
        };

        // 1) monitored nodes (ip + real mask). If the node is a router, stamp it as the subnet's gateway.
        require_once __DIR__.'/nm_nodemeta.php';
        $r = $conn->query("SELECT id,display_name,ip_address,subnet_mask,os_icon,monitor_type FROM nm_nodes WHERE ip_address IS NOT NULL AND ip_address<>''");
        while ($r && ($x = $r->fetch_assoc())) {
            $ip = trim((string)$x['ip_address']); if (!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)) continue;
            $pfx = nm_ipam_mask_to_prefix($x['subnet_mask']); $pfx = $pfx===null ? 24 : $pfx;
            $cidr = $ip.'/'.$pfx;
            $isRouter = function_exists('nm_node_kind') && nm_node_kind($x) === 'router';
            $add($cidr, 'node', ($isRouter?'LAN behind ':'From node ').$x['display_name']);
            $pp = nm_ipam_parse_cidr($cidr);
            if ($pp) nm_ipam_subnet_set_gateway($conn, $cidr, $ip, (int)$x['id'],
                ($isRouter?'LAN behind ':'Seen on ').$x['display_name'], nm_ipam_gw_priority($conn,$pp,$ip,$isRouter));
        }
        // 2) WireGuard tunnels (server address_cidr) — trusted, any range
        if ($conn->query("SHOW TABLES LIKE 'nm_wg_servers'")->num_rows) {
            $r = $conn->query("SELECT address_cidr FROM nm_wg_servers WHERE address_cidr IS NOT NULL AND address_cidr<>''");
            while ($r && ($x = $r->fetch_row())) $add($x[0], 'wireguard', 'Auto-detected from WireGuard tunnel');
        }
        // 3) WireGuard peer allowed_ips (the LAN/VPN subnets routed behind each peer)
        if ($conn->query("SHOW TABLES LIKE 'nm_wg_peers'")->num_rows) {
            $r = $conn->query("SELECT allowed_ips FROM nm_wg_peers WHERE allowed_ips IS NOT NULL AND allowed_ips<>''");
            while ($r && ($x = $r->fetch_row())) foreach (preg_split('/[,\s]+/', (string)$x[0], -1, PREG_SPLIT_NO_EMPTY) as $c)
                $add($c, 'wireguard', 'Auto-detected from WireGuard peer route');
        }
        // 4) DHCP pools (range_start → /24; DHCP scopes are ~always /24 LANs)
        if ($conn->query("SHOW TABLES LIKE 'nm_ipam_dhcp_servers'")->num_rows) {
            $r = $conn->query("SELECT range_start FROM nm_ipam_dhcp_servers WHERE range_start IS NOT NULL AND range_start<>''");
            while ($r && ($x = $r->fetch_row())) $add24(trim((string)$x[0]), 'dhcp', 'Auto-detected from DHCP pool');
        }
        // NOTE: interface IPs, DHCP leases and live-swept hosts are intentionally NOT guessed
        // as /24 here — their real subnet mask is unknown, so the "Full sweep" (nm_ipam_iface_sweep)
        // discovers them with the ACTUAL mask (Docker /16, point-to-point /30, VLAN /23…) instead
        // of polluting IPAM with overlapping /24 guesses.
        if ($uid !== null && function_exists('log_user_action')) @log_user_action($conn,'ipam_detect_all',(string)$n);
        return ['ok'=>true,'added'=>$n,'by_source'=>$by];
    }

    // Confidence that $ip on this subnet is the OWNING device (gateway):
    //   90 = matches the subnet's DHCP-server gateway (definitive)
    //   60 = router whose IP is a canonical gateway host (.1 / .254)
    //   50 = any router on the subnet · 30 = host at .1/.254 · 10 = any host
    function nm_ipam_gw_priority($conn, array $p, ?string $ip, bool $isRouter): int {
        if (!$ip || !filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)) return $isRouter ? 40 : 5;
        // DHCP gateway match?
        if ($conn->query("SHOW TABLES LIKE 'nm_ipam_dhcp_servers'")->num_rows) {
            $q = $conn->query("SELECT gateway FROM nm_ipam_dhcp_servers WHERE gateway='".$conn->real_escape_string($ip)."' LIMIT 1");
            if ($q && $q->num_rows) return 90;
        }
        $last = (int)substr(strrchr($ip,'.'),1);
        $gwlike = ($last === 1 || $last === 254);
        if ($isRouter) return $gwlike ? 60 : 50;
        return $gwlike ? 30 : 10;
    }

    // Stamp a subnet's owning device (gateway) so the card shows WHERE it comes from. Uses a
    // persisted gw_priority so a higher-confidence source (DHCP gateway) always beats a weaker
    // one (a random router/AP on the subnet), regardless of scan order or separate button clicks.
    // Upgrades an auto/generic description; never clobbers a user-set one.
    function nm_ipam_subnet_set_gateway($conn, string $cidr, ?string $ip, ?int $node_id, string $descr, int $priority): void {
        $p = nm_ipam_parse_cidr($cidr); if (!$p) return;
        $row = $conn->query("SELECT id,gateway_node_id,description,gw_priority FROM nm_ipam_subnets WHERE cidr='".$conn->real_escape_string($p['cidr'])."' LIMIT 1");
        $s = $row ? $row->fetch_assoc() : null; if (!$s) return;
        if (!empty($s['gateway_node_id']) && $priority <= (int)($s['gw_priority'] ?? 0)) return;   // keep the stronger owner
        $cur = (string)($s['description'] ?? '');
        $auto = ($cur === '' || strpos($cur,'Auto-detected')!==false || strpos($cur,'Interface subnet')!==false
                 || strpos($cur,'Discovered')!==false || strpos($cur,'LAN behind')!==false
                 || strpos($cur,'Seen on')!==false || strpos($cur,'From node')!==false || strpos($cur,'On ')===0);
        $newDesc = $auto ? $descr : $cur;
        $gi = ($ip && filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)) ? $ip : null;
        $nid = $node_id ?: null;
        $st = $conn->prepare("UPDATE nm_ipam_subnets SET gateway_ip=COALESCE(?,gateway_ip), gateway_node_id=?, description=?, gw_priority=? WHERE id=".(int)$s['id']);
        $st->bind_param('sisi', $gi, $nid, $newDesc, $priority); $st->execute(); $st->close();
    }

    // Shared registration: normalize a CIDR, filter to private, dedupe, register. Returns 1 if new.
    function nm_ipam_register_cidr($conn, string $cidr, string $src, string $descr, ?int $uid, array &$seen, array &$by): int {
        $p = nm_ipam_parse_cidr($cidr); if (!$p || $p['family'] !== 4) return 0;
        if ($p['prefix'] >= 31) return 0;
        if (!nm_ipam_is_registerable($p['net'])) return 0;
        if (isset($seen[$p['cidr']])) return 0; $seen[$p['cidr']] = 1;
        $kind = $src === 'wireguard' ? 'wireguard' : 'lan';
        $r = nm_ipam_subnet_add($conn, ['cidr'=>$p['cidr'],'kind'=>$kind,'description'=>$descr], $uid);
        if ($r['ok']) { $by[$src] = ($by[$src] ?? 0) + 1; return 1; }
        return 0;
    }

    // ── FULL SWEEP: pull EVERY interface's real IP+mask from monitored devices ──
    // SNMP ipAddrTable (universal) + SSH for routers/linux (MikroTik/Cisco/Linux) → the
    // authoritative connected subnets, incl. WireGuard/VPN/VLAN interfaces that aren't in
    // nm_interfaces. Real masks (not the /24 guess). Slow-ish (network) → run with the
    // session lock already released. Returns ['ok','added','scanned','by_source'].
    function nm_ipam_iface_sweep($conn, ?int $uid = null, ?int $node_id = null): array {
        nm_ipam_ensure($conn);
        require_once __DIR__.'/nm_secrets.php';
        require_once __DIR__.'/nm_confmgr.php';
        require_once __DIR__.'/nm_nodemeta.php';
        $seen = []; foreach (nm_ipam_subnets($conn) as $s) { $p=nm_ipam_parse_cidr($s['cidr']); if ($p) $seen[$p['cidr']]=1; }
        $n = 0; $by = []; $scanned = 0;
        $reg = function(string $cidr, string $src, string $descr) use ($conn,$uid,&$seen,&$by,&$n) {
            $n += nm_ipam_register_cidr($conn,$cidr,$src,$descr,$uid,$seen,$by);
        };
        $w = $node_id ? "WHERE id=".(int)$node_id : "WHERE ip_address IS NOT NULL AND ip_address<>''";
        $rs = $conn->query("SELECT id,display_name,ip_address,os_icon,monitor_type,snmp_community,snmp_version,ssh_cred_id FROM nm_nodes $w");
        $nodes = []; while ($rs && ($x=$rs->fetch_assoc())) $nodes[] = $x;

        foreach ($nodes as $node) {
            $ip = trim((string)$node['ip_address']); if (!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)) continue;
            $scanned++;
            $kind = nm_node_kind($node); $os = strtolower((string)$node['os_icon']);
            $got = false; $isRouter = ($kind === 'router');
            $stamp = function(array $pair, string $src) use ($conn,$node,$reg,$isRouter) {
                $reg($pair['cidr'], $src, 'On '.$node['display_name']);
                $p = nm_ipam_parse_cidr($pair['cidr']); if (!$p) return;
                $prio = nm_ipam_gw_priority($conn, $p, $pair['ip'] ?? null, $isRouter);
                nm_ipam_subnet_set_gateway($conn, $pair['cidr'], $pair['ip'] ?? null, (int)$node['id'],
                    ($isRouter?'LAN behind ':'Seen on ').$node['display_name'], $prio);
            };
            // 1) SSH interface pull for routers/linux (real masks, catches WG interfaces)
            if (!empty($node['ssh_cred_id']) && in_array($kind,['router','linux'],true) && nm_ipam_ssh_open($ip, 22)) {
                $ssh = nm_ssh_resolve($conn, (int)$node['id']);
                if ($ssh) foreach (nm_ipam_ssh_iface_cidrs($ssh, $os, $kind) as $pair) { $stamp($pair, 'ssh'); $got = true; }
            }
            // 2) SNMP ipAddrTable (universal fallback / non-SSH devices)
            if (!$got && $node['snmp_community']) {
                foreach (nm_ipam_snmp_iface_cidrs($ip, (string)$node['snmp_community'], (string)($node['snmp_version']?:'v2c')) as $pair)
                    $stamp($pair, 'interface');
            }
        }
        if ($uid !== null && function_exists('log_user_action')) @log_user_action($conn,'ipam_iface_sweep',(string)$n);
        return ['ok'=>true,'added'=>$n,'scanned'=>$scanned,'by_source'=>$by];
    }

    // SNMP ipAddrTable → [['cidr'=>..,'ip'=>..], …] (ipAdEntNetMask walk; the IP is the device's
    // interface address = the gateway candidate for that subnet). Short timeout.
    function nm_ipam_snmp_iface_cidrs(string $ip, string $community, string $ver): array {
        $v = ($ver === 'v1') ? '1' : '2c';
        $bin = ($v==='1') ? '/usr/bin/snmpwalk' : '/usr/bin/snmpbulkwalk';
        $out = []; $rc = 1;
        @exec(escapeshellarg($bin).' -v'.$v.' -c '.escapeshellarg($community).' -Oqn -t 3 -r 1 '.escapeshellarg($ip).' .1.3.6.1.2.1.4.20.1.3 2>/dev/null', $out, $rc);
        $res = [];
        foreach ($out as $line) {
            // .1.3.6.1.2.1.4.20.1.3.<ip> <netmask>
            if (!preg_match('/\.4\.20\.1\.3\.(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/', $line, $m)) continue;
            $pfx = nm_ipam_mask_to_prefix($m[2]); if ($pfx === null) continue;
            $res[] = ['cidr'=>$m[1].'/'.$pfx, 'ip'=>$m[1]];
        }
        return $res;
    }

    // SSH interface addresses per vendor → [['cidr'=>..,'ip'=>..], …] (real masks + the device's
    // own address on the subnet = gateway). Cisco connected-routes give the network only (no ip).
    function nm_ipam_ssh_iface_cidrs(array $ssh, string $os, string $kind): array {
        $res = [];
        if ($kind === 'router' && in_array($os,['mikrotik','routeros','router'],true)) {
            $r = nm_cm_ssh_fetch($ssh, '/ip address print terse; :put "NM_OK"', 12);
            if ($r['ok']) foreach (preg_split('/\r?\n/', (string)$r['config']) as $ln)
                if (preg_match('/address=(\d+\.\d+\.\d+\.\d+)\/(\d+)/', $ln, $m)) $res[] = ['cidr'=>$m[1].'/'.$m[2],'ip'=>$m[1]];
        } elseif ($kind === 'router') {   // Cisco-ish: connected routes (network only)
            $r = nm_cm_ssh_fetch($ssh, 'show ip route connected', 12);
            if ($r['ok']) foreach (preg_split('/\r?\n/', (string)$r['config']) as $ln)
                if (preg_match('/(\d+\.\d+\.\d+\.\d+\/\d+)\s+is directly connected/', $ln, $m)) $res[] = ['cidr'=>$m[1],'ip'=>null];
        } else {   // linux
            $r = nm_cm_ssh_fetch($ssh, "ip -o -4 addr show 2>/dev/null || /sbin/ip -o -4 addr show", 12);
            if ($r['ok']) foreach (preg_split('/\r?\n/', (string)$r['config']) as $ln)
                if (preg_match('/\binet\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)/', $ln, $m)) $res[] = ['cidr'=>$m[1].'/'.$m[2],'ip'=>$m[1]];
        }
        return $res;
    }

    // Derive subnets from the IPs of monitored nodes (ip_address + subnet_mask).
    // This is what makes IPAM "just work" — it reads the inventory you already have.
    // Only private/RFC1918 ranges are added (skips public IPs like 8.8.8.8).
    function nm_ipam_detect_from_nodes($conn, ?int $uid = null): int {
        nm_ipam_ensure($conn);
        $n = 0; $seen = [];
        $r = $conn->query("SELECT ip_address,subnet_mask FROM nm_nodes WHERE ip_address IS NOT NULL AND ip_address<>''");
        while ($r && ($x = $r->fetch_assoc())) {
            $ip = trim((string)$x['ip_address']);
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) continue;
            // skip public / reserved (keep only private LAN ranges)
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4|FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE)) continue;
            $mask = trim((string)$x['subnet_mask']); if ($mask === '') $mask = '/24';
            if ($mask[0] !== '/') $mask = '/'.ltrim($mask, '/');
            $p = nm_ipam_parse_cidr($ip.$mask);
            if (!$p || $p['family'] !== 4) continue;
            if ($p['prefix'] >= 31) continue;   // skip single-host (/32) and point-to-point (/31) — not real LANs
            if (isset($seen[$p['cidr']])) continue;
            $seen[$p['cidr']] = 1;
            $res = nm_ipam_subnet_add($conn, ['cidr'=>$p['cidr'],'kind'=>'lan','description'=>'Auto-detected from node IPs'], $uid);
            if ($res['ok']) $n++;
        }
        return $n;
    }

    // Pre-populate subnets from the existing discovery_subnets setting (idempotent).
    function nm_ipam_import_discovery($conn, ?int $uid = null): int {
        nm_ipam_ensure($conn);
        $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='discovery_subnets' LIMIT 1");
        $raw = $r && ($x=$r->fetch_row()) ? (string)$x[0] : '';
        if (trim($raw) === '') return 0;
        $n = 0;
        foreach (preg_split('/[,\s]+/', $raw, -1, PREG_SPLIT_NO_EMPTY) as $c) {
            $res = nm_ipam_subnet_add($conn, ['cidr'=>$c,'description'=>'Imported from discovery','kind'=>'lan'], $uid);
            if ($res['ok']) $n++;
        }
        return $n;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LIVE OCCUPANCY (sweep results) + ADDRESS MAP + PING + DHCP
    // ─────────────────────────────────────────────────────────────────────────

    // Which registered subnet contains this IP (or null).
    function nm_ipam_subnet_of($conn, string $ip): ?int {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return null;
        foreach (nm_ipam_subnets($conn) as $s) {
            $p = nm_ipam_parse_cidr($s['cidr']);
            if ($p && nm_ipam_in_subnet($ip, $p)) return (int)$s['id'];
        }
        return null;
    }

    // Single-shot ICMP ping. Returns ['alive'=>bool,'rtt'=>float|null].
    function nm_ipam_ping(string $ip, int $count = 1, int $wait = 1): array {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return ['alive'=>false,'rtt'=>null,'error'=>'bad ip'];
        $c = max(1, min(4, $count)); $w = max(1, min(3, $wait));
        $out = [];$rc = 1;
        @exec('/usr/bin/ping -c '.$c.' -W '.$w.' -n '.escapeshellarg($ip).' 2>/dev/null', $out, $rc);
        $txt = implode("\n", $out);
        $alive = ($rc === 0) && preg_match('/(\d+)\s+received/', $txt, $m) && (int)$m[1] > 0;
        $rtt = null;
        if ($alive && preg_match('#=\s*[\d.]+/([\d.]+)/#', $txt, $mm)) $rtt = round((float)$mm[1], 2);
        return ['alive'=>$alive,'rtt'=>$rtt];
    }

    // Upsert one discovered live host into nm_ipam_live. $m: mac,hostname,method,rtt_ms,is_managed
    function nm_ipam_live_upsert($conn, int $subnet_id, string $ip, array $m = []): void {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return;
        $bin = inet_pton($ip);
        $mac = isset($m['mac']) ? substr((string)$m['mac'],0,17) : null;
        $host= isset($m['hostname']) ? substr((string)$m['hostname'],0,255) : null;
        $meth= in_array(($m['method'] ?? 'ping'), ['ping','snmp','dhcp','arp','probe'], true) ? $m['method'] : 'ping';
        $rtt = isset($m['rtt_ms']) && $m['rtt_ms'] !== null ? (float)$m['rtt_ms'] : null;
        $mgd = !empty($m['is_managed']) ? 1 : 0;
        $st = $conn->prepare("INSERT INTO nm_ipam_live (subnet_id,ip_address,ip_bin,mac,hostname,method,rtt_ms,is_managed,first_seen,last_seen)
            VALUES (?,?,?,?,?,?,?,?,NOW(),NOW())
            ON DUPLICATE KEY UPDATE mac=COALESCE(VALUES(mac),mac), hostname=COALESCE(VALUES(hostname),hostname),
                method=VALUES(method), rtt_ms=VALUES(rtt_ms), is_managed=VALUES(is_managed), last_seen=NOW()");
        $st->bind_param('isssssdi', $subnet_id,$ip,$bin,$mac,$host,$meth,$rtt,$mgd);
        $st->execute();
    }

    function nm_ipam_live_list($conn, int $subnet_id): array {
        nm_ipam_ensure($conn);
        $out = []; $r = $conn->query("SELECT ip_address,mac,hostname,method,rtt_ms,is_managed,last_seen FROM nm_ipam_live WHERE subnet_id=".(int)$subnet_id." ORDER BY ip_bin");
        while ($r && ($x = $r->fetch_assoc())) $out[] = $x;
        return $out;
    }

    // Recompute is_managed on live rows for a subnet (an IP is "managed" if it matches a
    // monitored node or interface). Keeps free truthful after nodes are added/removed.
    function nm_ipam_live_reconcile($conn, int $subnet_id): void {
        $conn->query("UPDATE nm_ipam_live SET is_managed=0 WHERE subnet_id=".(int)$subnet_id);
        $conn->query("UPDATE nm_ipam_live l JOIN nm_nodes n ON n.ip_address=l.ip_address SET l.is_managed=1 WHERE l.subnet_id=".(int)$subnet_id);
        if ($conn->query("SHOW TABLES LIKE 'nm_interfaces'")->num_rows)
            $conn->query("UPDATE nm_ipam_live l JOIN nm_interfaces i ON i.if_ip_address=l.ip_address SET l.is_managed=1 WHERE l.subnet_id=".(int)$subnet_id);
    }

    // ── The ADDRESS MAP: every host address in the subnet, categorized. ─────────
    // Returns ['ok','cidr','grid'(bool),'cells'=>[{ip,cat,label,src,mac,host,seen}],
    //          'stats'=>{...},'gateway','network','broadcast','first','last'].
    // cat ∈ net|gw|bcast|managed|wg|reserved|dhcp|discovered|conflict|free
    function nm_ipam_map($conn, int $subnet_id): array {
        $sn = nm_ipam_subnet($conn, $subnet_id);
        if (!$sn) return ['ok'=>false,'error'=>'subnet not found'];
        $p = nm_ipam_parse_cidr($sn['cidr']);
        if (!$p || $p['family'] !== 4) return ['ok'=>false,'error'=>'IPv6 map not supported'];
        nm_ipam_live_reconcile($conn, $subnet_id);
        $used = nm_ipam_used_ips($conn, $sn);                 // ip => [source,label,status,...]

        // enrich maps: mac/host/last_seen from live + leases
        $meta = [];
        if ($conn->query("SHOW TABLES LIKE 'nm_ipam_live'")->num_rows) {
            $r = $conn->query("SELECT ip_address,mac,hostname,method,last_seen FROM nm_ipam_live WHERE subnet_id=".(int)$subnet_id);
            while ($r && ($x=$r->fetch_assoc())) $meta[$x['ip_address']] = ['mac'=>$x['mac'],'host'=>$x['hostname'],'seen'=>$x['last_seen']];
        }
        if ($conn->query("SHOW TABLES LIKE 'nm_ipam_leases'")->num_rows) {
            $r = $conn->query("SELECT ip_address,mac,hostname,last_seen FROM nm_ipam_leases WHERE subnet_id=".(int)$subnet_id." OR subnet_id IS NULL");
            while ($r && ($x=$r->fetch_assoc())) { $ip=$x['ip_address']; $meta[$ip]['mac']=$meta[$ip]['mac']??$x['mac']; $meta[$ip]['host']=$meta[$ip]['host']??$x['hostname']; $meta[$ip]['seen']=$meta[$ip]['seen']??$x['last_seen']; }
        }

        // conflicts (IPs claimed by >1 live source)
        $conf = [];
        foreach (nm_ipam_conflicts($conn, $subnet_id) as $c) $conf[$c['ip']] = true;

        $gwLong = !empty($sn['gateway_ip']) ? (ip2long($sn['gateway_ip']) & 0xFFFFFFFF) : null;
        $netLong = $p['net_long']; $bcastLong = $p['bcast_long'];
        $start = ip2long($p['first']) & 0xFFFFFFFF;
        $end   = ip2long($p['last'])  & 0xFFFFFFFF;

        $src2cat = ['node'=>'managed','iface'=>'managed','wg'=>'wg','alloc'=>'reserved','dhcp'=>'dhcp','discovered'=>'discovered'];
        $stats = ['total'=>0,'managed'=>0,'wg'=>0,'reserved'=>0,'dhcp'=>0,'discovered'=>0,'free'=>0,'conflict'=>0];

        // Cap the rendered grid so a huge subnet can't blow the payload/DOM.
        $span = ($p['prefix'] <= 30) ? ($bcastLong - $netLong + 1) : ($bcastLong - $netLong + 1);
        $GRID_CAP = 8192;
        $grid = $span <= $GRID_CAP;

        $cells = [];
        $emit = function(int $l) use (&$cells,&$stats,$used,$meta,$conf,$gwLong,$netLong,$bcastLong,$grid,$src2cat) {
            $ip = long2ip($l);
            $cat = 'free'; $label = ''; $src = '';
            if ($l === $netLong)         { $cat='net';  $label='Network'; }
            elseif ($l === $bcastLong)   { $cat='bcast';$label='Broadcast'; }
            elseif ($gwLong !== null && $l === $gwLong) { $cat='gw'; $label = ($used[$ip]['label'] ?? 'Gateway'); $src = $used[$ip]['source'] ?? 'gw'; }
            elseif (isset($conf[$ip]))   { $cat='conflict'; $label = $used[$ip]['label'] ?? 'Conflict'; $src = $used[$ip]['source'] ?? ''; }
            elseif (isset($used[$ip]))   { $src = $used[$ip]['source']; $cat = $src2cat[$src] ?? 'reserved'; $label = $used[$ip]['label'] ?? ''; }
            // stats
            if     ($cat==='managed')    $stats['managed']++;
            elseif ($cat==='wg')         $stats['wg']++;
            elseif ($cat==='reserved')   $stats['reserved']++;
            elseif ($cat==='dhcp')       $stats['dhcp']++;
            elseif ($cat==='discovered') $stats['discovered']++;
            elseif ($cat==='conflict')   $stats['conflict']++;
            elseif ($cat==='free')       $stats['free']++;
            if (!in_array($cat,['net','bcast'],true)) $stats['total']++;
            if (!$grid && $cat==='free') return;          // list mode: only occupied
            $cell = ['ip'=>$ip,'cat'=>$cat];
            if ($label!=='') $cell['label']=$label;
            if ($src!=='')   $cell['src']=$src;
            $mm = $meta[$ip] ?? null;
            if ($mm){ if(!empty($mm['mac']))$cell['mac']=$mm['mac']; if(!empty($mm['host']))$cell['host']=$mm['host']; if(!empty($mm['seen']))$cell['seen']=$mm['seen']; }
            $cells[] = $cell;
        };
        // include network + broadcast as structural cells in grid mode
        if ($grid) { for ($l=$netLong; $l<=$bcastLong; $l++) $emit($l); }
        else       { for ($l=$start;  $l<=$end;       $l++) $emit($l); }

        return ['ok'=>true,'cidr'=>$sn['cidr'],'grid'=>$grid,'cap'=>$GRID_CAP,'span'=>$span,
                'gateway'=>$sn['gateway_ip'] ?: null,'network'=>$p['net'],'broadcast'=>long2ip($bcastLong),
                'first'=>$p['first'],'last'=>$p['last'],'stats'=>$stats,'cells'=>$cells];
    }

    // ── DHCP: pull servers/pools + leases from a managed device over SSH ────────
    // Quick TCP reachability check (used to skip non-SSH devices fast during a pull_all).
    function nm_ipam_ssh_open(string $host, int $port = 22, float $timeout = 2.0): bool {
        if ($host === '') return false;
        $errno = 0; $errstr = '';
        $fp = @fsockopen($host, $port ?: 22, $errno, $errstr, $timeout);
        if ($fp) { fclose($fp); return true; }
        return false;
    }

    function nm_ipam_dhcp_candidates($conn): array {
        // routers + linux boxes with SSH creds are the ones that can run a DHCP server
        require_once __DIR__.'/nm_nodemeta.php';   // nm_node_kind — load it or every node reads as 'snmp'
        $out = [];
        $r = $conn->query("SELECT id,display_name,ip_address,os_icon,monitor_type,ssh_cred_id FROM nm_nodes WHERE ssh_cred_id IS NOT NULL AND ssh_cred_id<>0 ORDER BY display_name");
        while ($r && ($x=$r->fetch_assoc())) {
            $kind = function_exists('nm_node_kind') ? nm_node_kind($x) : 'snmp';
            if (in_array($kind, ['router','linux'], true)) { $x['kind']=$kind; $out[]=$x; }
        }
        return $out;
    }

    function nm_ipam_dhcp_pull($conn, int $node_id, ?int $uid = null): array {
        nm_ipam_ensure($conn);
        require_once __DIR__.'/nm_secrets.php';
        require_once __DIR__.'/nm_confmgr.php';
        require_once __DIR__.'/nm_nodemeta.php';
        $nr = $conn->query("SELECT id,display_name,ip_address,os_icon,monitor_type FROM nm_nodes WHERE id=".(int)$node_id." LIMIT 1");
        $node = $nr ? $nr->fetch_assoc() : null;
        if (!$node) return ['ok'=>false,'error'=>'node not found'];
        $ssh = nm_ssh_resolve($conn, $node_id);
        if (!$ssh) return ['ok'=>false,'error'=>'no SSH credential for this node'];
        $kind = nm_node_kind($node);
        $os   = strtolower((string)$node['os_icon']);
        $srvIp= (string)$node['ip_address'];

        // Fast SSH-reachability pre-check (TCP :22, ~2s). Without this a device that isn't
        // SSH-listening (a locked-down AP, a box that pings but has no sshd) would burn the
        // full SSH timeout — and across many candidates a web pull_all would blow PHP's
        // max_execution_time and return partial results (only the first router shows up).
        if (!nm_ipam_ssh_open((string)($ssh['host'] ?? $srvIp), (int)($ssh['port'] ?? 22)))
            return ['ok'=>false,'error'=>'SSH port not reachable','unreachable'=>true];

        $servers = []; $leases = [];
        if ($kind === 'router' && in_array($os, ['mikrotik','routeros','router'], true)) {
            [$servers,$leases] = nm_ipam_dhcp_parse_mikrotik($ssh, $srvIp);
        } elseif ($kind === 'router') {   // treat other routers as Cisco-IOS style
            [$servers,$leases] = nm_ipam_dhcp_parse_cisco($ssh, $srvIp);
        } else {                          // linux
            [$servers,$leases] = nm_ipam_dhcp_parse_linux($ssh, $srvIp);
        }
        if ($servers === null) return ['ok'=>false,'error'=>'SSH unreachable / auth failed','unreachable'=>true];
        if (!$servers && !$leases) return ['ok'=>true,'node'=>$node['display_name'],'servers'=>0,'leases'=>0,'empty'=>true];

        $ns=0;$nl=0;
        foreach ($servers as $s) {
            $sub = $s['range_start'] ? nm_ipam_subnet_of($conn, $s['range_start']) : null;
            $st = $conn->prepare("INSERT INTO nm_ipam_dhcp_servers (subnet_id,server_ip,server_node_id,source,pool_name,range_start,range_end,gateway,dns,lease_time,last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?,NOW())
                ON DUPLICATE KEY UPDATE subnet_id=VALUES(subnet_id),range_start=VALUES(range_start),range_end=VALUES(range_end),
                    gateway=VALUES(gateway),dns=VALUES(dns),lease_time=VALUES(lease_time),server_node_id=VALUES(server_node_id),last_seen=NOW()");
            $src='ssh-'.$os;
            $st->bind_param('isisssssss', $sub,$srvIp,$node_id,$src,$s['pool_name'],$s['range_start'],$s['range_end'],$s['gateway'],$s['dns'],$s['lease_time']);
            $st->execute(); $ns++;
        }
        foreach ($leases as $lz) {
            $sub = nm_ipam_subnet_of($conn, $lz['ip']);
            $bin = filter_var($lz['ip'],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4) ? inet_pton($lz['ip']) : null;
            $mac = substr((string)($lz['mac']??''),0,17) ?: null;
            $host= substr((string)($lz['hostname']??''),0,255) ?: null;
            $state=substr((string)($lz['state']??'bound'),0,20);
            $isst=!empty($lz['is_static'])?1:0;
            $st = $conn->prepare("INSERT INTO nm_ipam_leases (subnet_id,ip_address,ip_bin,mac,hostname,server_ip,state,is_static,last_seen)
                VALUES (?,?,?,?,?,?,?,?,NOW())
                ON DUPLICATE KEY UPDATE subnet_id=VALUES(subnet_id),hostname=COALESCE(VALUES(hostname),hostname),
                    server_ip=VALUES(server_ip),state=VALUES(state),is_static=VALUES(is_static),last_seen=NOW()");
            $st->bind_param('issssssi', $sub,$lz['ip'],$bin,$mac,$host,$srvIp,$state,$isst);
            $st->execute(); $nl++;
        }
        if ($uid !== null && function_exists('log_user_action')) @log_user_action($conn,'ipam_dhcp_pull',$node['display_name']);
        return ['ok'=>true,'node'=>$node['display_name'],'servers'=>$ns,'leases'=>$nl];
    }

    function nm_ipam_dhcp_pull_all($conn, ?int $uid = null): array {
        // devices = routers that actually served DHCP; no_dhcp = reachable but no DHCP (benign);
        // unreachable = SSH couldn't connect (the only real "error" worth surfacing).
        $tot=['ok'=>true,'devices'=>0,'servers'=>0,'leases'=>0,'no_dhcp'=>0,'unreachable'=>[],'errors'=>[]];
        foreach (nm_ipam_dhcp_candidates($conn) as $c) {
            $r = nm_ipam_dhcp_pull($conn, (int)$c['id'], $uid);
            if (!empty($r['ok'])) {
                if (!empty($r['empty'])) { $tot['no_dhcp']++; }
                else { $tot['devices']++; $tot['servers']+=$r['servers']; $tot['leases']+=$r['leases']; }
            } elseif (!empty($r['unreachable'])) {
                $tot['unreachable'][] = $c['display_name'];
            } else {
                $tot['errors'][] = $c['display_name'].': '.($r['error'] ?? 'failed');
            }
        }
        return $tot;
    }

    // MikroTik RouterOS DHCP. Returns [servers[], leases[]] or [null,null] on failure.
    function nm_ipam_dhcp_parse_mikrotik(array $ssh, string $srvIp): array {
        $kv = function(string $line): array { $o=[]; if(preg_match_all('/([a-z0-9\-]+)=("[^"]*"|\S+)/i',$line,$mm,PREG_SET_ORDER)) foreach($mm as $m){ $o[strtolower($m[1])]=trim($m[2],'"'); } return $o; };
        $get = function(string $cmd) use ($ssh){ $r = nm_cm_ssh_fetch($ssh, $cmd.'; :put "NM_OK"', 12); return $r['ok'] ? (string)$r['config'] : null; };
        $srvRaw = $get('/ip dhcp-server print terse');
        if ($srvRaw === null) return [null,null];
        $poolRaw = (string)$get('/ip pool print terse');
        $netRaw  = (string)$get('/ip dhcp-server network print terse');
        $leaseRaw= (string)$get('/ip dhcp-server lease print terse');

        // pools: name => "start-end[,start-end]"
        $pools = [];
        foreach (preg_split('/\r?\n/',$poolRaw) as $ln){ $f=$kv($ln); if(!empty($f['name'])&&!empty($f['ranges'])) $pools[$f['name']]=$f['ranges']; }
        // networks: address(cidr) => [gateway,dns]
        $nets = [];
        foreach (preg_split('/\r?\n/',$netRaw) as $ln){ $f=$kv($ln); if(!empty($f['address'])) $nets[$f['address']]=['gw'=>$f['gateway']??'','dns'=>$f['dns-server']??'']; }
        $servers=[];
        foreach (preg_split('/\r?\n/',$srvRaw) as $ln){
            $f=$kv($ln); if(empty($f['name'])) continue;
            $rng = $pools[$f['address-pool'] ?? ''] ?? '';
            $start=$end='';
            if ($rng!==''){ $first=explode(',',$rng)[0]; $pp=explode('-',$first); $start=trim($pp[0]??''); $end=trim($pp[1]??$start); }
            // match a network row for gw/dns (best-effort: first net whose gw is in the pool's /24)
            $gw=$dns=''; foreach($nets as $addr=>$gd){ if($start!=='' && strpos($addr, substr($start,0,strrpos($start,'.')))!==false){ $gw=$gd['gw']; $dns=$gd['dns']; break; } }
            $servers[]=['pool_name'=>$f['name'],'range_start'=>$start,'range_end'=>$end,'gateway'=>$gw,'dns'=>$dns,'lease_time'=>$f['lease-time']??''];
        }
        $leases=[];
        foreach (preg_split('/\r?\n/',$leaseRaw) as $ln){
            if(trim($ln)==='' || strpos($ln,'NM_OK')!==false) continue;
            $f=$kv($ln); if(empty($f['address'])) continue;
            $isDyn = (bool)preg_match('/^\s*\d+\s+[A-Z]*D/',$ln);   // 'D' flag = dynamic
            $leases[]=['ip'=>$f['address'],'mac'=>$f['mac-address']??'','hostname'=>$f['host-name']??'',
                       'state'=>$f['status']??'bound','is_static'=>$isDyn?0:1];
        }
        return [$servers,$leases];
    }

    // Cisco IOS DHCP (best-effort).
    function nm_ipam_dhcp_parse_cisco(array $ssh, string $srvIp): array {
        $r = nm_cm_ssh_fetch($ssh, 'show ip dhcp pool', 12);
        if (!$r['ok']) return [null,null];
        $poolRaw = (string)$r['config'];
        $rb = nm_cm_ssh_fetch($ssh, 'show ip dhcp binding', 12);
        $bindRaw = $rb['ok'] ? (string)$rb['config'] : '';
        $servers=[]; $cur=null;
        foreach (preg_split('/\r?\n/',$poolRaw) as $ln){
            if(preg_match('/^Pool\s+(\S+)/i',$ln,$m)){ if($cur)$servers[]=$cur; $cur=['pool_name'=>$m[1],'range_start'=>'','range_end'=>'','gateway'=>'','dns'=>'','lease_time'=>'']; }
            elseif($cur && preg_match('/(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)/',$ln,$m)){ $cur['range_start']=$m[1]; $cur['range_end']=$m[2]; }
        }
        if($cur)$servers[]=$cur;
        $leases=[];
        foreach (preg_split('/\r?\n/',$bindRaw) as $ln){
            if(preg_match('/^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\.:]{11,})/',$ln,$m))
                $leases[]=['ip'=>$m[1],'mac'=>$m[2],'hostname'=>'','state'=>'bound','is_static'=>0];
        }
        return [$servers ?: [],$leases];
    }

    // Linux dnsmasq / isc-dhcp (best-effort — reads the lease file + config ranges).
    function nm_ipam_dhcp_parse_linux(array $ssh, string $srvIp): array {
        $r = nm_cm_ssh_fetch($ssh,
            'cat /var/lib/misc/dnsmasq.leases 2>/dev/null; echo "---ISC---"; cat /var/lib/dhcp/dhcpd.leases 2>/dev/null | grep -E "lease |hardware|client-hostname" ; echo "---RANGE---"; grep -rhE "^\\s*dhcp-range|^\\s*range " /etc/dnsmasq.conf /etc/dnsmasq.d/ /etc/dhcp/dhcpd.conf 2>/dev/null',
            20);
        if (!$r['ok']) return [null,null];
        $txt = (string)$r['config'];
        [$leasePart,$rest] = array_pad(explode('---ISC---',$txt,2),2,'');
        [$iscPart,$rangePart] = array_pad(explode('---RANGE---',$rest,2),2,'');
        $leases=[];
        // dnsmasq: <expiry> <mac> <ip> <hostname> <clientid>
        foreach (preg_split('/\r?\n/',$leasePart) as $ln){
            $c=preg_split('/\s+/',trim($ln));
            if(count($c)>=4 && filter_var($c[2],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4))
                $leases[]=['ip'=>$c[2],'mac'=>$c[1],'hostname'=>($c[3]==='*'?'':$c[3]),'state'=>'bound','is_static'=>0];
        }
        $servers=[];
        foreach (preg_split('/\r?\n/',$rangePart) as $ln){
            if(preg_match('/(\d+\.\d+\.\d+\.\d+)[\s,]+(\d+\.\d+\.\d+\.\d+)/',$ln,$m))
                $servers[]=['pool_name'=>'dnsmasq','range_start'=>$m[1],'range_end'=>$m[2],'gateway'=>'','dns'=>'','lease_time'=>''];
        }
        // SSH connected (r ok) — an empty result just means "no DHCP server here", which is
        // benign, NOT a failure. Return empty arrays (not null) so the caller can tell the two apart.
        return [$servers,$leases];
    }

    function nm_ipam_dhcp_servers($conn, ?int $subnet_id = null): array {
        nm_ipam_ensure($conn);
        $w = $subnet_id !== null ? "WHERE subnet_id=".(int)$subnet_id : '';
        $out=[]; $r=$conn->query("SELECT s.*, n.display_name AS node_name FROM nm_ipam_dhcp_servers s LEFT JOIN nm_nodes n ON n.id=s.server_node_id $w ORDER BY server_ip, pool_name");
        while ($r && ($x=$r->fetch_assoc())) $out[]=$x;
        return $out;
    }
    function nm_ipam_leases($conn, ?int $subnet_id = null): array {
        nm_ipam_ensure($conn);
        $w = $subnet_id !== null ? "WHERE subnet_id=".(int)$subnet_id : '';
        $out=[]; $r=$conn->query("SELECT ip_address,mac,hostname,server_ip,state,is_static,last_seen FROM nm_ipam_leases $w ORDER BY ip_bin");
        while ($r && ($x=$r->fetch_assoc())) $out[]=$x;
        return $out;
    }
}
