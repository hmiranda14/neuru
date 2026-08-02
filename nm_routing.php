<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Routing engine (backs routing_command.php, the Routing Command Center).
// Pulls each router's routing table (RouterOS via SSH; connected-subnets fallback for
// any other brand), resolves every route's gateway to the OWNING router by matching
// interface IPs → reconstructs the real L3 forwarding fabric. Also: longest-prefix
// path simulation, snapshot/diff (route drift/flap), and loop detection.
// Reuses nm_router.php SSH plumbing + nm_interfaces. RBAC: 'routing_center'.
// ─────────────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/nm_router.php';

if (!function_exists('nm_routing_ensure')) {

    function nm_routing_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        try {
            $conn->query("CREATE TABLE IF NOT EXISTS nm_routing_snapshots (
                id INT AUTO_INCREMENT PRIMARY KEY,
                node_id INT NOT NULL,
                taken_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                route_count INT NOT NULL DEFAULT 0,
                routes_json MEDIUMTEXT NULL,
                KEY idx_node (node_id, taken_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
            // Live route fetch is SSH-per-router (slow). This caches the full route set so the
            // AI Commander's reachability tool answers fast (voice can't wait 30s/hop).
            $conn->query("CREATE TABLE IF NOT EXISTS nm_routing_cache (
                node_id INT NOT NULL PRIMARY KEY,
                fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                source VARCHAR(24) NULL,
                routes_json MEDIUMTEXT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        } catch (\Throwable $e) {}
    }

    // Cached route fetch: return stored routes if younger than $ttl seconds, else fetch live + store.
    function nm_routing_cache_get($conn, int $nodeId, int $ttl): ?array {
        try { $st = $conn->prepare("SELECT source, routes_json FROM nm_routing_cache WHERE node_id=? AND fetched_at > (NOW() - INTERVAL ? SECOND)");
              $st->bind_param('ii', $nodeId, $ttl); $st->execute(); $r = $st->get_result()->fetch_assoc(); $st->close();
              if ($r) { $rt = json_decode((string)$r['routes_json'], true); if (is_array($rt)) return ['ok'=>true,'source'=>$r['source'],'routes'=>$rt,'cached'=>true]; }
        } catch (\Throwable $e) {}
        return null;
    }
    function nm_routing_cache_put($conn, int $nodeId, array $fetched): void {
        try { $src = (string)($fetched['source'] ?? ''); $j = json_encode($fetched['routes'] ?? []);
              $st = $conn->prepare("INSERT INTO nm_routing_cache (node_id, source, routes_json) VALUES (?,?,?)
                                    ON DUPLICATE KEY UPDATE fetched_at=NOW(), source=VALUES(source), routes_json=VALUES(routes_json)");
              $st->bind_param('iss', $nodeId, $src, $j); $st->execute(); $st->close(); } catch (\Throwable $e) {}
    }

    // ── IP helpers (IPv4) ───────────────────────────────────────────────────────
    function nm_routing_ip2long(string $ip): ?int { $l = ip2long(trim($ip)); return $l === false ? null : ($l & 0xFFFFFFFF); }
    function nm_routing_is_ip(string $s): bool { return (bool)filter_var(trim($s), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4); }
    function nm_routing_in_cidr(string $ip, int $net, int $prefix): bool {
        $i = nm_routing_ip2long($ip); if ($i === null) return false;
        if ($prefix <= 0) return true; if ($prefix >= 32) return $i === $net;
        $mask = (~((1 << (32 - $prefix)) - 1)) & 0xFFFFFFFF; return ($i & $mask) === ($net & $mask);
    }

    // ── RouterOS route fetch ────────────────────────────────────────────────────
    // Capped foreach → one delimited line per route. Only version-safe properties.
    function nm_routing_routeros_script(int $cap = 600): string {
        return ':local c 0; :foreach r in=[/ip route find] do={ :if ($c < ' . (int)$cap . ') do={ '
            . ':do { :put ("rt|" . [/ip route get $r dst-address] . "|" . [/ip route get $r gateway] . "|" '
            . '. [/ip route get $r distance] . "|" . [/ip route get $r active] . "|" . [/ip route get $r dynamic] . "|" '
            . '. [/ip route get $r blackhole] . "|" . [/ip route get $r pref-src]) } on-error={}; :set c ($c + 1) } }; '
            . ':put ("count|" . [:len [/ip route find]]); :put "NM_END"';
    }

    function nm_routing_parse_routeros(string $raw): array {
        $routes = []; $total = 0;
        foreach (preg_split('/\r?\n/', $raw) as $ln) {
            $ln = trim($ln); if ($ln === '' || $ln === 'NM_END') continue;
            if (strpos($ln, 'count|') === 0) { $total = (int)substr($ln, 6); continue; }
            if (strpos($ln, 'rt|') !== 0) continue;
            $p = explode('|', $ln);
            $dst = $p[1] ?? ''; if ($dst === '') continue;
            $gwRaw = trim($p[2] ?? ''); $dist = (int)($p[3] ?? 0);
            $active = ($p[4] ?? '') === 'true'; $dynamic = ($p[5] ?? '') === 'true';
            $black = ($p[6] ?? '') === 'true'; $prefsrc = trim($p[7] ?? '');
            // ECMP: gateway may be comma-separated → one normalized route per gateway
            foreach (($gwRaw === '' ? [''] : explode(',', $gwRaw)) as $gw1) {
                $routes[] = nm_routing_normalize($dst, trim($gw1), $dist, $active, $dynamic, $black, $prefsrc);
            }
        }
        return ['routes' => $routes, 'total' => $total ?: count($routes)];
    }

    // Normalize one route into the canonical shape used everywhere.
    function nm_routing_normalize(string $dst, string $gw, int $dist, bool $active, bool $dynamic, bool $black, string $prefsrc): array {
        // dst = "net/prefix" or bare host
        $net = $dst; $prefix = 32;
        if (strpos($dst, '/') !== false) { [$net, $pfx] = explode('/', $dst, 2); $prefix = (int)$pfx; }
        $gwIp = null; $gwIface = null;
        $g = $gw;
        if (strpos($g, '%') !== false) { [$g, $gwIface] = explode('%', $g, 2); }   // "1.2.3.4%ether1"
        $g = trim($g);
        if ($g !== '' && nm_routing_is_ip($g)) $gwIp = $g;
        elseif ($g !== '') $gwIface = $g;                                           // gateway is an interface
        $isDefault = ($net === '0.0.0.0' && $prefix === 0);
        $protocol = $black ? 'blackhole' : ($gwIface && !$gwIp ? 'connected' : ($dynamic ? 'dynamic' : 'static'));
        if ($dist === 0 && $protocol === 'static') $protocol = 'connected';
        return ['dst' => ($net . '/' . $prefix), 'net' => $net, 'prefix' => $prefix,
                'gw' => $gw, 'gw_ip' => $gwIp, 'gw_iface' => $gwIface,
                'protocol' => $protocol, 'distance' => $dist, 'active' => $active,
                'is_default' => $isDefault, 'pref_src' => $prefsrc];
    }

    // Universal fallback: connected subnets from polled interface IPs (any brand, no SSH).
    // We lack the prefix from nm_interfaces (bare IPs) → assume /24 for a visual leaf.
    function nm_routing_connected_from_ifaces($conn, array $node): array {
        $routes = []; $id = (int)$node['id'];
        $r = $conn->query("SELECT if_name, if_ip_address FROM nm_interfaces WHERE node_id=$id AND if_ip_address IS NOT NULL AND if_ip_address<>''");
        while ($r && $x = $r->fetch_assoc()) {
            $ip = trim($x['if_ip_address']); if (!nm_routing_is_ip($ip)) continue;
            $l = nm_routing_ip2long($ip); $netl = $l & 0xFFFFFF00; $net = long2ip($netl);
            $routes[] = nm_routing_normalize($net . '/24', $x['if_name'], 0, true, true, false, $ip);
        }
        return $routes;
    }

    // Fetch + normalize one router's routes. RouterOS SSH (rich) → else connected-only.
    function nm_routing_fetch($conn, array $node, int $cacheTtl = 0): array {
        $nodeId = (int)($node['id'] ?? 0);
        if ($cacheTtl > 0 && $nodeId) { $c = nm_routing_cache_get($conn, $nodeId, $cacheTtl); if ($c) return $c; }
        $os = strtolower((string)($node['os_icon'] ?? ''));
        $out = null;
        if (in_array($os, ['mikrotik','routeros'], true)) {
            if (!function_exists('nm_cm_ssh_fetch')) require_once __DIR__ . '/nm_confmgr.php';
            $ssh = nm_ssh_resolve($conn, $nodeId);
            if ($ssh && !empty($ssh['username']) && (!empty($ssh['password']) || !empty($ssh['private_key']))) {
                $f = nm_cm_ssh_fetch($ssh, nm_routing_routeros_script(), 30);
                if (!empty($f['ok'])) {
                    $p = nm_routing_parse_routeros((string)$f['config']);
                    if ($p['routes']) $out = ['ok'=>true, 'source'=>'routeros', 'routes'=>$p['routes'],
                        'truncated'=>($p['total'] > count($p['routes'])), 'total'=>$p['total']];
                }
                // fall through to connected-only on failure
            }
        }
        if ($out === null) {
            $conn2 = nm_routing_connected_from_ifaces($conn, $node);
            $out = ['ok'=>(bool)$conn2, 'source'=>($conn2?'interfaces':'none'), 'routes'=>$conn2,
                    'truncated'=>false, 'total'=>count($conn2), 'error'=> $conn2 ? '' : 'no route source (no SSH / no interfaces)'];
        }
        if ($cacheTtl > 0 && $nodeId && !empty($out['ok']) && !empty($out['routes'])) nm_routing_cache_put($conn, $nodeId, $out);
        return $out;
    }

    // Map every router-owned IP → {node,name} for gateway→router resolution.
    function nm_routing_owner_map($conn): array {
        $map = [];
        $r = $conn->query("SELECT id, display_name, ip_address FROM nm_nodes WHERE ip_address IS NOT NULL AND ip_address<>''");
        while ($r && $x = $r->fetch_assoc()) { $ip = trim($x['ip_address']); if ($ip !== '') $map[$ip] = ['node'=>(int)$x['id'],'name'=>$x['display_name']]; }
        $r = $conn->query("SELECT n.id, n.display_name, i.if_ip_address FROM nm_interfaces i JOIN nm_nodes n ON n.id=i.node_id
                           WHERE i.if_ip_address IS NOT NULL AND i.if_ip_address<>''");
        while ($r && $x = $r->fetch_assoc()) { $ip = trim($x['if_ip_address']); if ($ip !== '' && !isset($map[$ip])) $map[$ip] = ['node'=>(int)$x['id'],'name'=>$x['display_name']]; }
        return $map;
    }

    // ── The L3 topology / forwarding fabric ─────────────────────────────────────
    function nm_routing_topology($conn, ?array $nodeIds = null): array {
        nm_routing_ensure($conn);
        $routers = nm_router_list($conn);
        if ($nodeIds) $routers = array_values(array_filter($routers, fn($r)=>in_array((int)$r['id'], $nodeIds, true)));
        $owner = nm_routing_owner_map($conn);

        $out = ['routers'=>[], 'subnets'=>[], 'links'=>[], 'internet'=>false, 'stats'=>['routes'=>0,'by_proto'=>[]]];
        $subIdx = [];  // cidr → subnet node index
        foreach ($routers as $r) {
            $nid = (int)$r['id']; $node = nm_router_node($conn, $nid); if (!$node) continue;
            $f = nm_routing_fetch($conn, $node);
            $routes = $f['routes'] ?? [];
            $byProto = ['connected'=>0,'static'=>0,'dynamic'=>0,'blackhole'=>0]; $defaults = [];
            $seenLink = [];
            foreach ($routes as $rt) {
                $out['stats']['routes']++; $pr = $rt['protocol']; $byProto[$pr] = ($byProto[$pr] ?? 0) + 1;
                $out['stats']['by_proto'][$pr] = ($out['stats']['by_proto'][$pr] ?? 0) + 1;
                if ($rt['is_default']) $defaults[] = $rt['gw'];

                if ($rt['protocol'] === 'connected') {
                    // connected subnet → leaf node + link
                    $cidr = $rt['dst']; if (!isset($subIdx[$cidr])) { $subIdx[$cidr] = count($out['subnets']);
                        $out['subnets'][] = ['cidr'=>$cidr, 'net'=>$rt['net'], 'prefix'=>$rt['prefix'], 'owners'=>[]]; }
                    if (!in_array($nid, $out['subnets'][$subIdx[$cidr]]['owners'], true)) $out['subnets'][$subIdx[$cidr]]['owners'][] = $nid;
                    $lk = "$nid>s:$cidr"; if (!isset($seenLink[$lk])) { $seenLink[$lk]=1;
                        $out['links'][] = ['from'=>$nid, 'to'=>"s:$cidr", 'kind'=>'subnet', 'protocol'=>'connected', 'dst'=>$cidr, 'gw'=>$rt['gw']]; }
                    continue;
                }
                // routed: resolve gateway → owning router?
                $ownRouter = ($rt['gw_ip'] && isset($owner[$rt['gw_ip']])) ? $owner[$rt['gw_ip']]['node'] : null;
                if ($ownRouter && $ownRouter !== $nid) {
                    $lk = "$nid>r:$ownRouter:$pr"; if (!isset($seenLink[$lk])) { $seenLink[$lk]=1;
                        $out['links'][] = ['from'=>$nid, 'to'=>"r:$ownRouter", 'kind'=>'router', 'protocol'=>$pr, 'dst'=>$rt['dst'], 'gw'=>$rt['gw']]; }
                } elseif ($rt['is_default'] || ($rt['gw_ip'] && !nm_routing_is_private($rt['gw_ip']))) {
                    $out['internet'] = true;
                    $lk = "$nid>net:$pr"; if (!isset($seenLink[$lk])) { $seenLink[$lk]=1;
                        $out['links'][] = ['from'=>$nid, 'to'=>'net', 'kind'=>'internet', 'protocol'=>$pr, 'dst'=>$rt['dst'], 'gw'=>$rt['gw']]; }
                }
                // (private gateway that isn't a known router → unresolved; skipped from graph, still counted)
            }
            $out['routers'][] = ['id'=>$nid, 'name'=>$r['name'], 'ip'=>$r['ip'], 'up'=>$r['up'], 'incidents'=>$r['incidents'],
                'mikrotik'=>$r['mikrotik'], 'route_count'=>count($routes), 'by_proto'=>$byProto, 'defaults'=>$defaults,
                'source'=>$f['source'], 'truncated'=>!empty($f['truncated'])];
        }
        // inbound transit: who routes through me (reverse of router→router links)
        $inbound = [];
        foreach ($out['links'] as $l) if ($l['kind'] === 'router') { $to = (int)substr($l['to'], 2); $inbound[$to][] = $l['from']; }
        foreach ($out['routers'] as &$rr) $rr['transit_from'] = array_values(array_unique($inbound[$rr['id']] ?? []));
        unset($rr);
        return $out;
    }
    function nm_routing_is_private(string $ip): bool {
        return nm_routing_is_ip($ip) && !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    // ── Longest-prefix path simulation ──────────────────────────────────────────
    function nm_routing_lpm(array $routes, string $destIp): ?array {
        $best = null; $bestPfx = -1;
        foreach ($routes as $rt) {
            if (!empty($rt['is_default'])) { if ($best === null) { $best = $rt; $bestPfx = -1; } continue; }
            if (nm_routing_in_cidr($destIp, nm_routing_ip2long($rt['net']) ?? 0, $rt['prefix'])) {
                if ($rt['prefix'] > $bestPfx) { $best = $rt; $bestPfx = $rt['prefix']; }
            }
        }
        // default only wins if nothing more specific matched
        if ($best !== null && $bestPfx === -1) { foreach ($routes as $rt) if (!empty($rt['is_default'])) { $best = $rt; break; } }
        return $best;
    }
    function nm_routing_path($conn, int $fromNodeId, string $destIp, int $maxHops = 12, int $cacheTtl = 0): array {
        if (!nm_routing_is_ip($destIp)) return ['ok'=>false, 'error'=>'invalid destination IP'];
        $owner = nm_routing_owner_map($conn);
        $hops = []; $visited = []; $cur = $fromNodeId; $outcome = 'no-route';
        for ($h = 0; $h < $maxHops; $h++) {
            if (isset($visited[$cur])) { $outcome = 'loop'; break; }
            $visited[$cur] = true;
            $node = nm_router_node($conn, $cur); if (!$node) { $outcome='no-route'; break; }
            $routes = nm_routing_fetch($conn, $node, $cacheTtl)['routes'] ?? [];
            $rt = nm_routing_lpm($routes, $destIp);
            $hop = ['node'=>$cur, 'name'=>$node['display_name'], 'route'=>$rt ? $rt['dst'] : null,
                    'protocol'=>$rt['protocol'] ?? null, 'gw'=>$rt['gw'] ?? null];
            if (!$rt) { $hops[] = $hop; $outcome='no-route'; break; }
            if ($rt['protocol'] === 'connected') { $hop['outcome']='delivered'; $hops[]=$hop; $outcome='delivered'; break; }
            if ($rt['protocol'] === 'blackhole') { $hop['outcome']='blackhole'; $hops[]=$hop; $outcome='blackhole'; break; }
            $next = ($rt['gw_ip'] && isset($owner[$rt['gw_ip']])) ? $owner[$rt['gw_ip']]['node'] : null;
            if ($next && $next !== $cur) { $hop['next']=$next; $hops[]=$hop; $cur=$next; continue; }
            // gateway not a known router → internet exit (public) or unresolved
            $hop['outcome'] = ($rt['is_default'] || ($rt['gw_ip'] && !nm_routing_is_private($rt['gw_ip']))) ? 'internet' : 'unresolved';
            $hops[] = $hop; $outcome = $hop['outcome']; break;
        }
        if (count($hops) >= $maxHops && !in_array($outcome, ['delivered','internet','blackhole','loop','no-route'], true)) $outcome = 'maxhops';
        return ['ok'=>true, 'dest'=>$destIp, 'from'=>$fromNodeId, 'outcome'=>$outcome, 'hops'=>$hops];
    }

    // ── Snapshot / drift ────────────────────────────────────────────────────────
    function nm_routing_snapshot_save($conn, int $nodeId, array $routes): void {
        nm_routing_ensure($conn);
        try {
            $keys = array_map(fn($r)=>$r['dst'].'>'.$r['gw'], $routes); sort($keys);
            $json = json_encode($keys); $cnt = count($routes);
            $st = $conn->prepare("INSERT INTO nm_routing_snapshots (node_id, route_count, routes_json) VALUES (?,?,?)");
            $st->bind_param('iis', $nodeId, $cnt, $json); $st->execute();
            // keep last ~20 per node
            $conn->query("DELETE FROM nm_routing_snapshots WHERE node_id=$nodeId AND id NOT IN
                          (SELECT id FROM (SELECT id FROM nm_routing_snapshots WHERE node_id=$nodeId ORDER BY id DESC LIMIT 20) t)");
        } catch (\Throwable $e) {}
    }
    function nm_routing_diff($conn, int $nodeId, array $currentRoutes): array {
        nm_routing_ensure($conn);
        $cur = array_map(fn($r)=>$r['dst'].'>'.$r['gw'], $currentRoutes); sort($cur);
        $prev = [];
        try { $r = $conn->query("SELECT routes_json FROM nm_routing_snapshots WHERE node_id=$nodeId ORDER BY id DESC LIMIT 1");
            if ($r && ($x=$r->fetch_assoc())) $prev = json_decode($x['routes_json'], true) ?: []; } catch (\Throwable $e) {}
        return ['added'=>array_values(array_diff($cur, $prev)), 'removed'=>array_values(array_diff($prev, $cur)), 'had_prev'=>(bool)$prev];
    }

    // ── Loop detection (router→router edges) ────────────────────────────────────
    function nm_routing_detect_loops(array $topology): array {
        $adj = []; foreach ($topology['links'] as $l) if ($l['kind']==='router') { $to=(int)substr($l['to'],2); $adj[$l['from']][]=$to; }
        $loops = []; $names = []; foreach ($topology['routers'] as $r) $names[$r['id']]=$r['name'];
        // colors: 0=white(unseen) 1=gray(on stack) 2=black(done)
        $color=[]; $stack=[];
        $dfs = function($u) use (&$dfs,&$adj,&$color,&$stack,&$loops,$names){
            $color[$u]=1; $stack[]=$u;
            foreach ($adj[$u] ?? [] as $v) {
                if (($color[$v] ?? 0)===1) { $i=array_search($v,$stack,true); if($i!==false){ $cyc=array_slice($stack,$i); $cyc[]=$v; $loops[]=array_map(fn($n)=>['id'=>$n,'name'=>$names[$n]??('#'.$n)],$cyc); } }
                elseif (($color[$v] ?? 0)===0) $dfs($v);
            }
            array_pop($stack); $color[$u]=2;
        };
        foreach ($adj as $u=>$_) if (($color[$u] ?? 0)===0) $dfs($u);
        return $loops;
    }
}
