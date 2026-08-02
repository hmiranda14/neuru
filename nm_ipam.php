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
        $w = $group_id !== null ? "WHERE group_id=".(int)$group_id : '';
        // NOTE: never SELECT network_addr (VARBINARY) — json_encode() fails on binary
        // (invalid UTF-8) and returns false → empty response → UI stuck on "Loading…".
        $out = []; $r = $conn->query("SELECT id,cidr,prefix_len,family,description,vlan_id,gateway_ip,gateway_node_id,group_id,kind,is_managed,created_by,created_at FROM nm_ipam_subnets $w ORDER BY family, prefix_len, cidr");
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
}
