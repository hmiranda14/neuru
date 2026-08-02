<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — WireGuard Universal Orchestrator.
//
// One web UI to provision WireGuard servers + peers across three target types and
// push the config remotely, REUSING the portal's existing infrastructure:
//   • keys      → PHP sodium (X25519 + WireGuard clamping) — no `wg` binary needed
//   • secrets   → nm_secret_encrypt/decrypt (AES-256-GCM, .nm_secret.key)
//   • SSH apply → nm_cm_ssh_fetch (paramiko) with creds from nm_ssh_credentials
//   • Docker    → nm_portainer_container_create (the new Portainer write path)
//   • IP alloc  → nm_ipam_next_free + nm_ipam_reserve (collision-free peer IPs)
//
// Targets: mikrotik (RouterOS v7 CLI), docker (wg0.conf bind-mount + Portainer),
//          linux (wg-quick wg0.conf). Apply supports a DRY-RUN that renders the
//          exact commands without touching the device.
//
// Secret-dependent ops (key render, apply) run in the WEB request only (www-data
// can decrypt; CLI cannot). Crons here touch non-secret data only (handshakes).
//
// RBAC perm: 'wireguard'. Engine for wireguard.php.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_wg_ensure')) {
    require_once __DIR__ . '/nm_secrets.php';
    require_once __DIR__ . '/nm_confmgr.php';     // nm_cm_ssh_fetch, nm_cm_resolve_ssh, nm_cm_guess_vendor
    require_once __DIR__ . '/nm_portainer.php';   // nm_portainer_cfg, nm_portainer_container_create
    require_once __DIR__ . '/nm_ipam.php';        // nm_ipam_next_free, nm_ipam_reserve, nm_ipam_release_peer
    require_once __DIR__ . '/nm_nettools.php';    // nm_geo_badge / nm_geo_flag (peer endpoint country flag)

    function nm_wg_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_wg_servers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(80) NOT NULL,
            target_type VARCHAR(12) NOT NULL,
            node_id INT DEFAULT NULL,
            host_ip VARCHAR(45) DEFAULT NULL,
            portainer_endpoint_id INT DEFAULT NULL,
            container_name VARCHAR(80) DEFAULT NULL,
            iface_name VARCHAR(32) NOT NULL DEFAULT 'wg0',
            listen_port INT NOT NULL DEFAULT 51820,
            vpn_subnet_id INT DEFAULT NULL,
            address_cidr VARCHAR(43) NOT NULL,
            endpoint_host VARCHAR(120) DEFAULT NULL,
            public_key VARCHAR(60) DEFAULT NULL,
            privkey_enc TEXT DEFAULT NULL,
            dns_servers VARCHAR(120) DEFAULT NULL,
            default_allowed VARCHAR(200) DEFAULT '0.0.0.0/0',
            status VARCHAR(12) NOT NULL DEFAULT 'draft',
            last_apply DATETIME DEFAULT NULL,
            last_error VARCHAR(300) DEFAULT NULL,
            created_by INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            KEY idx_node (node_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $conn->query("CREATE TABLE IF NOT EXISTS nm_wg_peers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            server_id INT NOT NULL,
            name VARCHAR(80) NOT NULL,
            public_key VARCHAR(60) DEFAULT NULL,
            privkey_enc TEXT DEFAULT NULL,
            preshared_enc TEXT DEFAULT NULL,
            address_ip VARCHAR(45) NOT NULL,
            allocation_id INT DEFAULT NULL,
            allowed_ips VARCHAR(200) NOT NULL DEFAULT '',
            keepalive INT DEFAULT 25,
            enabled TINYINT(1) NOT NULL DEFAULT 1,
            status VARCHAR(12) NOT NULL DEFAULT 'draft',
            last_handshake DATETIME DEFAULT NULL,
            created_by INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_srv_addr (server_id, address_ip),
            KEY idx_server (server_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $conn->query("CREATE TABLE IF NOT EXISTS nm_wg_apply_log (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            server_id INT NOT NULL,
            peer_id INT DEFAULT NULL,
            action VARCHAR(20) NOT NULL,
            target_type VARCHAR(12) NOT NULL,
            ok TINYINT(1) NOT NULL DEFAULT 0,
            detail TEXT DEFAULT NULL,
            created_by INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            KEY idx_server (server_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // adopt-existing support (idempotent column adds — MySQL has no ADD COLUMN IF NOT EXISTS)
        _nm_wg_col($conn,'nm_wg_servers','adopted',"adopted TINYINT(1) NOT NULL DEFAULT 0");
        _nm_wg_col($conn,'nm_wg_peers','origin',"origin VARCHAR(10) NOT NULL DEFAULT 'managed'");
        // live peer stats (handshake/traffic) — populated by the stats poller
        _nm_wg_col($conn,'nm_wg_peers','rx_bytes',"rx_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0");
        _nm_wg_col($conn,'nm_wg_peers','tx_bytes',"tx_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0");
        _nm_wg_col($conn,'nm_wg_peers','endpoint',"endpoint VARCHAR(60) DEFAULT NULL");
        _nm_wg_col($conn,'nm_wg_peers','connected',"connected TINYINT(1) NOT NULL DEFAULT 0");
        _nm_wg_col($conn,'nm_wg_peers','stats_at',"stats_at DATETIME DEFAULT NULL");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_wg_peer_traffic (
            peer_id INT NOT NULL,
            ts DATETIME NOT NULL,
            rx_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
            tx_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
            rx_rate DOUBLE NOT NULL DEFAULT 0,
            tx_rate DOUBLE NOT NULL DEFAULT 0,
            PRIMARY KEY (peer_id, ts),
            KEY idx_peer (peer_id, ts)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','wireguard',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='wireguard')");
    }
    function _nm_wg_col($conn, string $table, string $col, string $ddl): void {
        $r = $conn->query("SHOW COLUMNS FROM {$table} LIKE '".$conn->real_escape_string($col)."'");
        if (!$r || $r->num_rows === 0) @$conn->query("ALTER TABLE {$table} ADD COLUMN {$ddl}");
    }

    // ── Key generation (sodium X25519 + WireGuard clamping → byte-exact w/ `wg`) ──
    function _nm_wg_clamp(string $priv): string {
        $priv[0]  = chr(ord($priv[0])  & 248);
        $priv[31] = chr((ord($priv[31]) & 127) | 64);
        return $priv;
    }
    function nm_wg_genkeys(): array {
        $priv = _nm_wg_clamp(random_bytes(32));
        $pub  = sodium_crypto_scalarmult_base($priv);
        return ['private'=>base64_encode($priv),'public'=>base64_encode($pub),'method'=>'sodium'];
    }
    function nm_wg_pubkey_from_priv(string $priv_b64): ?string {
        $priv = base64_decode($priv_b64, true);
        if ($priv === false || strlen($priv) !== 32) return null;
        return base64_encode(sodium_crypto_scalarmult_base(_nm_wg_clamp($priv)));
    }
    function nm_wg_genpsk(): string { return base64_encode(random_bytes(32)); }
    function nm_wg_valid_key(string $b64): bool {
        $r = base64_decode($b64, true); return $r !== false && strlen($r) === 32;
    }

    // ── Server CRUD ───────────────────────────────────────────────────────────
    function nm_wg_server_add($conn, array $f, ?int $uid): array {
        nm_wg_ensure($conn);
        $name = substr(trim((string)($f['name'] ?? '')), 0, 80) ?: 'wg-server';
        $tt   = in_array(($f['target_type'] ?? ''), ['mikrotik','docker','linux'], true) ? $f['target_type'] : 'linux';
        $node = ($f['node_id'] ?? '') !== '' ? (int)$f['node_id'] : null;
        $hip  = substr(trim((string)($f['host_ip'] ?? '')), 0, 45) ?: null;
        $peid = ($f['portainer_endpoint_id'] ?? '') !== '' ? (int)$f['portainer_endpoint_id'] : null;
        $cname= substr(trim((string)($f['container_name'] ?? '')), 0, 80) ?: null;
        $ifn  = substr(preg_replace('/[^a-zA-Z0-9_-]/','',(string)($f['iface_name'] ?? 'wg0')), 0, 32) ?: 'wg0';
        $port = max(1, min(65535, (int)($f['listen_port'] ?? 51820)));
        $vsub = ($f['vpn_subnet_id'] ?? '') !== '' ? (int)$f['vpn_subnet_id'] : null;
        $addr = substr(trim((string)($f['address_cidr'] ?? '')), 0, 43);
        $ep   = substr(trim((string)($f['endpoint_host'] ?? '')), 0, 120) ?: null;
        $dns  = substr(trim((string)($f['dns_servers'] ?? '')), 0, 120) ?: null;
        $dall = substr(trim((string)($f['default_allowed'] ?? '0.0.0.0/0')), 0, 200) ?: '0.0.0.0/0';
        if ($addr === '' || strpos($addr,'/') === false) return ['ok'=>false,'error'=>'Server tunnel address (CIDR, e.g. 10.8.0.1/24) is required'];

        // keys: auto-generate, or accept a supplied private key
        $supplied = trim((string)($f['private_key'] ?? ''));
        if ($supplied !== '') {
            if (!nm_wg_valid_key($supplied)) return ['ok'=>false,'error'=>'Supplied private key is not valid base64 (32 bytes)'];
            $pub = nm_wg_pubkey_from_priv($supplied); $priv = $supplied;
        } else {
            $k = nm_wg_genkeys(); $priv = $k['private']; $pub = $k['public'];
        }
        $enc = nm_secret_encrypt($priv);

        $st = $conn->prepare("INSERT INTO nm_wg_servers
            (name,target_type,node_id,host_ip,portainer_endpoint_id,container_name,iface_name,listen_port,vpn_subnet_id,address_cidr,endpoint_host,public_key,privkey_enc,dns_servers,default_allowed,status,created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'draft',?)");
        // name s,target_type s,node i,host s,peid i,cname s,ifn s,port i,vsub i,addr s,ep s,pub s,enc s,dns s,dall s,uid i
        $st->bind_param('ssisissiissssssi',
            $name,$tt,$node,$hip,$peid,$cname,$ifn,$port,$vsub,$addr,$ep,$pub,$enc,$dns,$dall,$uid);
        $st->execute();
        return ['ok'=>true,'id'=>$conn->insert_id,'public_key'=>$pub];
    }
    function nm_wg_server_update($conn, int $id, array $f): array {
        nm_wg_ensure($conn);
        $port = max(1, min(65535, (int)($f['listen_port'] ?? 51820)));
        $ep   = substr(trim((string)($f['endpoint_host'] ?? '')), 0, 120) ?: null;
        $dns  = substr(trim((string)($f['dns_servers'] ?? '')), 0, 120) ?: null;
        $dall = substr(trim((string)($f['default_allowed'] ?? '0.0.0.0/0')), 0, 200) ?: '0.0.0.0/0';
        $st = $conn->prepare("UPDATE nm_wg_servers SET listen_port=?,endpoint_host=?,dns_servers=?,default_allowed=? WHERE id=?");
        $st->bind_param('isssi', $port,$ep,$dns,$dall,$id);
        $st->execute();
        return ['ok'=>true];
    }
    function nm_wg_server($conn, int $id, bool $withSecret = false): ?array {
        nm_wg_ensure($conn);
        $r = $conn->query("SELECT * FROM nm_wg_servers WHERE id={$id} LIMIT 1");
        $s = $r ? $r->fetch_assoc() : null;
        if (!$s) return null;
        if ($withSecret) $s['private_key'] = nm_secret_decrypt($s['privkey_enc'] ?? '');
        unset($s['privkey_enc']);
        return $s;
    }
    function nm_wg_servers($conn): array {
        nm_wg_ensure($conn);
        $out = [];
        $r = $conn->query("SELECT id,name,target_type,node_id,host_ip,portainer_endpoint_id,container_name,iface_name,listen_port,vpn_subnet_id,address_cidr,endpoint_host,public_key,dns_servers,default_allowed,status,adopted,last_apply,last_error,
            (SELECT COUNT(*) FROM nm_wg_peers p WHERE p.server_id=nm_wg_servers.id) peer_count
            FROM nm_wg_servers ORDER BY name,id");
        while ($r && ($x = $r->fetch_assoc())) $out[] = $x;
        return $out;
    }
    function nm_wg_server_delete($conn, int $id, bool $wipe = false, ?int $uid = null): array {
        nm_wg_ensure($conn);
        $wiped = null;
        if ($wipe) $wiped = nm_wg_revert($conn, $id, $uid);  // remove interface/firewall/routes/peers from device first
        $r = $conn->query("SELECT id FROM nm_wg_peers WHERE server_id={$id}");
        while ($r && ($x = $r->fetch_row())) nm_ipam_release_peer($conn, (int)$x[0]);
        $conn->query("DELETE FROM nm_wg_peers WHERE server_id={$id}");
        $conn->query("DELETE FROM nm_wg_servers WHERE id={$id}");
        return ['ok'=>true,'wiped'=>($wiped===null?null:!empty($wiped['ok'])),'wipe_error'=>($wiped && empty($wiped['ok'])?(string)($wiped['error']??$wiped['detail']??''):'')];
    }

    // ── Peer CRUD (auto IP allocation via IPAM) ───────────────────────────────
    function nm_wg_peer_add($conn, int $server_id, array $f, ?int $uid): array {
        nm_wg_ensure($conn);
        $srv = nm_wg_server($conn, $server_id);
        if (!$srv) return ['ok'=>false,'error'=>'Server not found'];
        $name = substr(trim((string)($f['name'] ?? '')), 0, 80) ?: 'peer';
        $keep = max(0, min(65535, (int)($f['keepalive'] ?? 25)));
        $allowed = substr(trim((string)($f['allowed_ips'] ?? '')), 0, 200);  // routes pushed to the peer's tunnel (server side)

        // IP: from IPAM next-free if the server has a VPN subnet, else explicit.
        $allocId = null; $ip = trim((string)($f['address_ip'] ?? ''));
        if (!empty($srv['vpn_subnet_id'])) {
            $res = nm_ipam_reserve($conn, (int)$srv['vpn_subnet_id'], $ip ?: null,
                ['source'=>'wireguard','hostname'=>$name,'status'=>'allocated','description'=>'WG peer'], $uid);
            if (!$res['ok']) return ['ok'=>false,'error'=>'IPAM: '.$res['error']];
            $ip = $res['ip']; $allocId = (int)$res['id'];
        } elseif ($ip === '') {
            return ['ok'=>false,'error'=>'No VPN subnet on server — provide an explicit peer IP'];
        }

        // keys: portal-generated keypair (default) or supplied public key (no private stored)
        $privEnc = null; $psk = null; $pskEnc = null;
        $suppliedPub = trim((string)($f['public_key'] ?? ''));
        if ($suppliedPub !== '') {
            if (!nm_wg_valid_key($suppliedPub)) { if($allocId) nm_ipam_release($conn,$allocId); return ['ok'=>false,'error'=>'Supplied public key invalid']; }
            $pub = $suppliedPub;
        } else {
            $k = nm_wg_genkeys(); $pub = $k['public']; $privEnc = nm_secret_encrypt($k['private']);
        }
        if (!empty($f['use_psk'])) { $psk = nm_wg_genpsk(); $pskEnc = nm_secret_encrypt($psk); }

        $st = $conn->prepare("INSERT INTO nm_wg_peers
            (server_id,name,public_key,privkey_enc,preshared_enc,address_ip,allocation_id,allowed_ips,keepalive,enabled,status,created_by)
            VALUES (?,?,?,?,?,?,?,?,?,1,'draft',?)");
        $st->bind_param('isssssisii', $server_id,$name,$pub,$privEnc,$pskEnc,$ip,$allocId,$allowed,$keep,$uid);
        try {
            $st->execute();
        } catch (\Throwable $e) {
            if ($allocId) nm_ipam_release($conn, $allocId);
            return ['ok'=>false,'error'=>'Peer IP already used on this server'];
        }
        $pid = $conn->insert_id;
        if ($allocId) $conn->query("UPDATE nm_ipam_allocations SET wg_peer_id={$pid} WHERE id={$allocId}");
        return ['ok'=>true,'id'=>$pid,'ip'=>$ip,'public_key'=>$pub];
    }
    function nm_wg_peer($conn, int $peer_id, bool $withSecret = false): ?array {
        $r = $conn->query("SELECT * FROM nm_wg_peers WHERE id=".(int)$peer_id." LIMIT 1");
        $p = $r ? $r->fetch_assoc() : null;
        if (!$p) return null;
        if ($withSecret) { $p['private_key'] = nm_secret_decrypt($p['privkey_enc'] ?? ''); $p['psk'] = nm_secret_decrypt($p['preshared_enc'] ?? ''); }
        unset($p['privkey_enc'], $p['preshared_enc']);
        return $p;
    }
    function nm_wg_peers($conn, int $server_id): array {
        nm_wg_ensure($conn);
        nm_wg_backfill_names($conn);   // adopt real names for same-key peers imported without a comment
        $out = [];
        $r = $conn->query("SELECT id,server_id,name,public_key,(preshared_enc IS NOT NULL) has_psk,(privkey_enc IS NOT NULL) has_priv,origin,address_ip,allowed_ips,keepalive,enabled,status,
            rx_bytes,tx_bytes,endpoint,connected,stats_at,
            CASE WHEN last_handshake IS NULL THEN NULL ELSE TIMESTAMPDIFF(SECOND,last_handshake,NOW()) END AS hs_ago
            FROM nm_wg_peers WHERE server_id=".(int)$server_id." ORDER BY id");
        while ($r && ($x = $r->fetch_assoc())) {
            // Country flag for the peer's live endpoint (skips private/CGNAT → shows a LAN chip in the UI).
            $x['endpoint_flag'] = ''; $x['endpoint_cc'] = ''; $x['endpoint_country'] = '';
            $eip = nm_wg_endpoint_ip($x['endpoint'] ?? '');
            if ($eip !== null && function_exists('nm_geo_badge')) {
                $b = nm_geo_badge($conn, $eip);
                if ($b) { $x['endpoint_flag']=$b['flag']; $x['endpoint_cc']=$b['cc']; $x['endpoint_country']=$b['country']; }
            }
            $x['endpoint_private'] = ($eip !== null && $x['endpoint_flag'] === '') ? 1 : 0;
            $out[] = $x;
        }
        return $out;
    }
    // Extract a bare IP from a stored endpoint ("1.2.3.4", "1.2.3.4:51820", "[::1]:51820", "ip%zone").
    function nm_wg_endpoint_ip(?string $ep): ?string {
        $ep = trim((string)$ep);
        if ($ep === '') return null;
        $ep = preg_replace('/%.*$/', '', $ep);                       // strip zone id
        if (preg_match('/^\[([0-9a-fA-F:]+)\]:\d+$/', $ep, $m)) $ep = $m[1];        // [v6]:port
        elseif (preg_match('/^([0-9.]+):\d+$/', $ep, $m)) $ep = $m[1];              // v4:port
        return filter_var($ep, FILTER_VALIDATE_IP) ? $ep : null;
    }
    // Sanitize a RouterOS peer comment for use as a NEURU peer name (strip control chars, cap 80).
    function nm_wg_clean_name(string $s): string {
        $s = preg_replace('/[\x00-\x1F\x7F]/', ' ', $s);            // drop control chars / newlines
        return substr(trim(preg_replace('/\s+/', ' ', $s)), 0, 80);
    }
    // A peer name we generated ourselves (no real identity) vs one from a router comment / operator.
    function nm_wg_name_is_auto(?string $n): bool {
        $n = (string)$n; return $n === '' || strncmp($n, 'imported-', 9) === 0;
    }
    // The SAME public key can be registered on several servers (e.g. a client peered to two
    // routers). If one copy has a real name (router comment / operator) and another is still
    // auto ('imported-xxxx'), adopt the real name for the auto one — so EVERY surface
    // (WireGuard page, Command Center wall) shows the human name for that identity.
    function nm_wg_backfill_names($conn): int {
        try {
            $conn->query(
                "UPDATE nm_wg_peers a
                 JOIN nm_wg_peers b
                   ON b.public_key = a.public_key AND b.id <> a.id
                  AND b.name <> '' AND b.name NOT LIKE 'imported-%'
                 SET a.name = b.name
                 WHERE a.name = '' OR a.name LIKE 'imported-%'");
            return $conn->affected_rows;
        } catch (\Throwable $e) { return 0; }
    }
    // Remove a SINGLE peer (and any LAN route we added for it) from the live device, leaving
    // the rest of the interface untouched. MikroTik by public-key; linux via `wg set … remove`.
    function nm_wg_peer_remove_device($conn, int $peer_id, ?int $uid = null): array {
        nm_wg_ensure($conn);
        $peer = nm_wg_peer($conn, $peer_id);
        if (!$peer) return ['ok'=>false,'error'=>'peer not found'];
        $sid = (int)$peer['server_id'];
        $srv = nm_wg_server($conn, $sid);
        if (!$srv) return ['ok'=>false,'error'=>'server not found'];
        $tt = $srv['target_type'];
        if ($tt === 'docker') return ['ok'=>false,'error'=>'docker peers live in the conf — re-apply the server'];
        $ssh = nm_wg_resolve_ssh($conn, $srv);
        if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'No SSH credential resolved'];
        $if = $srv['iface_name']; $pub = (string)$peer['public_key'];
        if ($tt === 'mikrotik') {
            $cmd = ':do { /interface/wireguard/peers remove [find where public-key="'.$pub.'"] } on-error={}; '
                 . ':do { /ip/route remove [find where comment="NEURU rt '.$if.' '.$peer['name'].'"] } on-error={}; :put "NEURU_OK"';
        } else {
            $cmd = 'wg set '.$if.' peer '.$pub.' remove; wg-quick save '.$if.' 2>/dev/null; echo NEURU_OK';
        }
        $res = nm_cm_ssh_fetch($ssh, $cmd, 30);
        $ok  = $res['ok'] && strpos((string)($res['config'] ?? ''), 'NEURU_OK') !== false;
        $detail = $res['ok'] ? (string)$res['config'] : (string)($res['error'] ?? 'ssh failed');
        nm_wg_log($conn, $sid, $peer_id, 'remove_peer', $tt, $ok, $detail, $uid);
        return ['ok'=>$ok,'detail'=>$detail];
    }

    function nm_wg_peer_delete($conn, int $peer_id, bool $wipe = false, ?int $uid = null): array {
        nm_wg_ensure($conn);
        $wiped = null;
        if ($wipe) $wiped = nm_wg_peer_remove_device($conn, $peer_id, $uid);  // pull from device BEFORE we lose its public-key
        nm_ipam_release_peer($conn, $peer_id);
        $conn->query("DELETE FROM nm_wg_peers WHERE id=".(int)$peer_id);
        return ['ok'=>true,'wiped'=>($wiped===null?null:!empty($wiped['ok'])),'wipe_error'=>($wiped && empty($wiped['ok'])?(string)($wiped['error']??$wiped['detail']??''):'')];
    }

    // ── Discover existing WireGuard on a MONITORED node (so the user can adopt
    //    an interface + add peers, instead of always building greenfield) ──────
    function _nm_wg_mtval(string $line, string $key): string {
        if (preg_match('/(?:^|\s)'.preg_quote($key,'/').'=("([^"]*)"|(\S+))/', $line, $m))
            return ($m[2] ?? '') !== '' ? $m[2] : ($m[3] ?? '');
        return '';
    }
    function nm_wg_parse_mikrotik(string $out): array {
        $ifaces = []; $peers = []; $addrs = [];
        foreach (preg_split('/\r?\n/', $out) as $line) {
            $t = trim($line);
            if ($t === '' || strpos($t, ':put') !== false) continue;
            if (strpos($t,'name=')!==false && strpos($t,'public-key=')!==false && strpos($t,'interface=')===false) {
                $name = _nm_wg_mtval($t,'name');
                if ($name !== '') $ifaces[$name] = ['name'=>$name,'listen_port'=>(int)_nm_wg_mtval($t,'listen-port'),
                    'public_key'=>_nm_wg_mtval($t,'public-key'),'address'=>'','peers'=>[]];
            } elseif (strpos($t,'interface=')!==false && strpos($t,'public-key=')!==false) {
                $peers[] = ['interface'=>_nm_wg_mtval($t,'interface'),'public_key'=>_nm_wg_mtval($t,'public-key'),'allowed'=>_nm_wg_mtval($t,'allowed-address'),'comment'=>_nm_wg_mtval($t,'comment')];
            } elseif (strpos($t,'address=')!==false && strpos($t,'interface=')!==false && strpos($t,'public-key=')===false) {
                $addrs[] = ['interface'=>_nm_wg_mtval($t,'interface'),'address'=>_nm_wg_mtval($t,'address')];
            }
        }
        foreach ($peers as $p) if (isset($ifaces[$p['interface']])) $ifaces[$p['interface']]['peers'][] = $p;
        foreach ($addrs as $a) if (isset($ifaces[$a['interface']]) && $ifaces[$a['interface']]['address']==='') $ifaces[$a['interface']]['address'] = $a['address'];
        return array_values($ifaces);
    }
    function nm_wg_parse_linux(string $out): array {
        $parts = preg_split('/^NM_END_WG\s*$/m', $out);
        $dump = $parts[0] ?? ''; $addr = $parts[1] ?? '';
        $ifaces = [];
        foreach (preg_split('/\r?\n/', $dump) as $line) {
            if (trim($line) === '') continue;
            $f = explode("\t", $line);
            if (count($f) === 5) { $ifaces[$f[0]] = ['name'=>$f[0],'listen_port'=>(int)$f[3],'public_key'=>$f[2],'address'=>'','peers'=>[]]; continue; }
            if (count($f) >= 8 && isset($ifaces[$f[0]])) $ifaces[$f[0]]['peers'][] = ['interface'=>$f[0],'public_key'=>$f[1],'allowed'=>$f[4]];
        }
        foreach (preg_split('/\r?\n/', $addr) as $line) {
            if (preg_match('/^\d+:\s+(\S+)\s+inet\s+([0-9.]+\/\d+)/', $line, $m) && isset($ifaces[$m[1]]) && $ifaces[$m[1]]['address']==='')
                $ifaces[$m[1]]['address'] = $m[2];
        }
        return array_values($ifaces);
    }
    function nm_wg_discover($conn, int $node_id): array {
        nm_wg_ensure($conn);
        $nr = $conn->query("SELECT id,display_name,ip_address,os_icon FROM nm_nodes WHERE id=".(int)$node_id." LIMIT 1");
        $node = $nr ? $nr->fetch_assoc() : null;
        if (!$node) return ['ok'=>false,'error'=>'Node not found'];
        $ssh = nm_ssh_resolve($conn, $node_id);
        if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'No SSH credential for '.$node['display_name'].' (assign one in Config → Credentials)'];
        $isMt = (nm_cm_guess_vendor($node['os_icon'] ?? '') === 'mikrotik');

        // IMPORTANT: use SINGLE-LINE exec_command per query. RouterOS returns empty
        // through paramiko's invoke_shell (the multi-line path) but works perfectly
        // via exec_command — same path Config Manager uses for `export`. An "empty
        // output" reply just means that query had no rows (e.g. no peers yet).
        $run = function (string $cmd) use ($ssh): array {
            $r = nm_cm_ssh_fetch($ssh, $cmd, 20);
            if ($r['ok']) return ['ok'=>true,'out'=>(string)$r['config']];
            if (stripos((string)($r['error'] ?? ''), 'empty output') !== false) return ['ok'=>true,'out'=>''];
            return ['ok'=>false,'error'=>$r['error']];
        };

        if ($isMt) {
            $a = $run('/interface/wireguard print terse');
            if (!$a['ok']) return ['ok'=>false,'error'=>$a['error']];   // genuine SSH/auth/timeout failure
            $b = $run('/interface/wireguard/peers print terse');
            $c = $run('/ip/address print terse');
            $ifaces = nm_wg_parse_mikrotik($a['out']."\n".($b['out'] ?? '')."\n".($c['out'] ?? ''));
        } else {
            $a = $run('wg show all dump 2>/dev/null');
            if (!$a['ok']) return ['ok'=>false,'error'=>$a['error']];
            $c = $run('ip -4 -o addr show 2>/dev/null');
            $ifaces = nm_wg_parse_linux($a['out']."\nNM_END_WG\n".($c['out'] ?? ''));
        }
        return ['ok'=>true,'target_type'=>$isMt?'mikrotik':'linux',
                'node'=>['id'=>(int)$node['id'],'name'=>$node['display_name'],'ip'=>$node['ip_address']],
                'interfaces'=>$ifaces];
    }

    // Adopt a discovered interface as a managed server (public key only — no private
    // key needed to ADD peers). Optionally import the peers already on the device.
    function nm_wg_adopt($conn, int $node_id, array $f, ?int $uid): array {
        nm_wg_ensure($conn);
        $disc = nm_wg_discover($conn, $node_id);
        if (!$disc['ok']) return $disc;
        $ifname = (string)($f['iface_name'] ?? '');
        $chosen = null;
        foreach ($disc['interfaces'] as $i) if ($i['name'] === $ifname) { $chosen = $i; break; }
        if (!$chosen) return ['ok'=>false,'error'=>'Interface '.$ifname.' not found on device'];

        // duplicate guard
        $dup = $conn->query("SELECT id FROM nm_wg_servers WHERE node_id=".(int)$node_id." AND iface_name='".$conn->real_escape_string($ifname)."' LIMIT 1");
        if ($dup && $dup->num_rows) return ['ok'=>false,'error'=>'This interface is already adopted (server id '.$dup->fetch_row()[0].')'];

        $name = substr(trim((string)($f['name'] ?? ($disc['node']['name'].' / '.$ifname))), 0, 80);
        $addr = trim((string)($f['address_cidr'] ?? '')) ?: ($chosen['address'] ?: '');
        $vsub = ($f['vpn_subnet_id'] ?? '') !== '' ? (int)$f['vpn_subnet_id'] : null;
        $ep   = substr(trim((string)($f['endpoint_host'] ?? '')), 0, 120) ?: $disc['node']['ip'];
        $tt   = $disc['target_type'];
        $host = $disc['node']['ip'];
        $port = (int)$chosen['listen_port'];
        $pub  = (string)$chosen['public_key'];

        $st = $conn->prepare("INSERT INTO nm_wg_servers
            (name,target_type,node_id,host_ip,iface_name,listen_port,vpn_subnet_id,address_cidr,endpoint_host,public_key,status,adopted,created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,'applied',1,?)");
        // name s,tt s,node i,host s,if s,port i,vsub i,addr s,ep s,pub s,uid i
        $st->bind_param('ssisiiisssi', $name,$tt,$node_id,$host,$ifname,$port,$vsub,$addr,$ep,$pub,$uid);
        $st->execute();
        $svId = $conn->insert_id;

        if ($vsub && $addr !== '') @nm_ipam_reserve($conn, $vsub, explode('/',$addr)[0],
            ['source'=>'wireguard','hostname'=>$name.' (gw)','status'=>'allocated'], $uid);

        $imported = 0;
        if (!empty($f['import_peers'])) {
            foreach ($chosen['peers'] as $pp) {
                $pip = explode('/', trim((string)$pp['allowed']))[0];
                if ($pip === '' || !filter_var($pip, FILTER_VALIDATE_IP)) continue;   // need a usable IP for the unique key
                // Prefer the router's ;;; comment as the real peer name; fall back to a key stub.
                $cmt = nm_wg_clean_name((string)($pp['comment'] ?? ''));
                $pname = $cmt !== '' ? $cmt
                       : 'imported-'.substr(preg_replace('/[^a-zA-Z0-9]/','',(string)$pp['public_key']), 0, 8);
                $emptyAllowed = '';
                $st2 = $conn->prepare("INSERT INTO nm_wg_peers (server_id,name,public_key,address_ip,allowed_ips,enabled,status,origin,created_by)
                    VALUES (?,?,?,?,?,1,'applied','imported',?)");
                $st2->bind_param('issssi', $svId,$pname,$pp['public_key'],$pip,$emptyAllowed,$uid);
                try { $st2->execute(); $imported++;
                    if ($vsub) @nm_ipam_reserve($conn,$vsub,$pip,['source'=>'wireguard','wg_peer_id'=>$conn->insert_id,'hostname'=>$pname,'status'=>'allocated'],$uid);
                } catch (\Throwable $e) {}
            }
        }
        return ['ok'=>true,'id'=>$svId,'imported'=>$imported,'interface'=>$ifname,'public_key'=>$pub];
    }

    // ── Renderers (pure string builders) ──────────────────────────────────────
    function _nm_wg_ip(string $cidr): string { return explode('/', $cidr, 2)[0]; }

    // Build a clean RouterOS allowed-address list: "<peer-ip>/32[,extra/prefix,…]".
    // Normalizes so a blank IP or a bare/space-padded "allowed IPs" value can't produce
    // an invalid prefix (the cause of "invalid or unexpected prefix length value").
    function _nm_wg_allowed_address(string $ip, string $allowed): string {
        $parts = [];
        $ip = trim(preg_replace('#/.*$#', '', trim($ip)));       // bare host IP (drop any prefix)
        if ($ip !== '') $parts[] = $ip . (strpos($ip, ':') !== false ? '/128' : '/32');
        foreach (preg_split('/[,\s]+/', (string)$allowed) as $a) {  // split on commas AND spaces
            $a = trim($a); if ($a === '') continue;
            if (strpos($a, '/') === false) $a .= (strpos($a, ':') !== false ? '/128' : '/32'); // bare IP → host route
            $parts[] = $a;
        }
        return implode(',', $parts);
    }

    // The LAN/host networks reachable BEHIND a peer (its "Extra AllowedIPs"). These need
    // an explicit `/ip route … gateway=<wg-iface>` on RouterOS v7 — unlike wg-quick, ROS does
    // NOT auto-create routes from allowed-address, so without this a site-to-site tunnel comes
    // up but the remote LAN is unreachable. The peer's own /32 tunnel IP is already covered by
    // the connected route from `/ip address`, so it is NOT routed here.
    function _nm_wg_peer_routes(array $p): array {
        $out = [];
        foreach (preg_split('/[,\s]+/', (string)($p['allowed_ips'] ?? '')) as $a) {
            $a = trim($a); if ($a === '') continue;
            if (strpos($a, '/') === false) $a .= (strpos($a, ':') !== false ? '/128' : '/32');
            $out[] = $a;
        }
        return $out;
    }

    // MikroTik RouterOS v7+ CLI — READABLE render (dry-run preview / teaching). The actual
    // provisioning is sent via nm_wg_mikrotik_apply_cmd() (idempotent one-liner).
    function nm_wg_render_mikrotik(array $srv, array $peers): string {
        $if = $srv['iface_name']; $L = "\n";
        $adopted = !empty($srv['adopted']);
        $out  = "# NEURU WireGuard — {$srv['name']} (RouterOS v7)".($adopted ? "  [adopted: add peers only]" : "").$L;
        if (!$adopted) {
            // greenfield: create the interface, its address and the firewall opening
            $out .= "/interface/wireguard$L";
            $out .= "add name={$if} listen-port={$srv['listen_port']} private-key=\"{$srv['private_key']}\" comment=\"NEURU\"$L";
            $out .= "/ip/address$L";
            $out .= "add address={$srv['address_cidr']} interface={$if}$L";
            // place-before=0 → land the accept ABOVE any default drop in the input chain,
            // otherwise the WireGuard UDP handshake is blocked and the tunnel never forms.
            $out .= "/ip/firewall/filter$L";
            $out .= "add chain=input protocol=udp dst-port={$srv['listen_port']} action=accept comment=\"NEURU wg {$if}\" place-before=0$L";
        }
        $out .= "/interface/wireguard/peers$L";
        foreach ($peers as $p) {
            if (!$p['enabled']) continue;
            $aa = _nm_wg_allowed_address((string)$p['address_ip'], (string)($p['allowed_ips'] ?? ''));
            $line = "add interface={$if} public-key=\"{$p['public_key']}\" allowed-address={$aa}";
            if (!empty($p['psk'])) $line .= " preshared-key=\"{$p['psk']}\"";
            if ((int)$p['keepalive'] > 0) $line .= " persistent-keepalive={$p['keepalive']}s";
            $line .= " comment=\"{$p['name']}\"";
            $out .= $line.$L;
        }
        // static routes for the LAN(s) behind each peer (site-to-site reachability)
        $routes = [];
        foreach ($peers as $p) {
            if (!$p['enabled']) continue;
            foreach (_nm_wg_peer_routes($p) as $dst)
                $routes[] = "add dst-address={$dst} gateway={$if} comment=\"NEURU rt {$if} {$p['name']}\"";
        }
        if ($routes) $out .= "/ip/route$L".implode($L, $routes).$L;
        return $out;
    }

    // Idempotent one-line RouterOS command (what we ACTUALLY send over SSH). Re-runnable:
    // ensures the interface (no flap), adds the address/firewall only if missing, and
    // remove-then-adds every peer + route so a second apply never errors on duplicates.
    function nm_wg_mikrotik_apply_cmd(array $srv, array $peers): string {
        $if = $srv['iface_name']; $adopted = !empty($srv['adopted']); $c = [];
        if (!$adopted) {
            $pk = $srv['private_key']; $lp = (int)$srv['listen_port']; $addr = (string)$srv['address_cidr'];
            $c[] = ':if ([:len [/interface/wireguard find where name="'.$if.'"]]=0) do={ /interface/wireguard add name="'.$if.'" listen-port='.$lp.' private-key="'.$pk.'" comment="NEURU" } else={ /interface/wireguard set [find where name="'.$if.'"] listen-port='.$lp.' private-key="'.$pk.'" }';
            if ($addr !== '')
                $c[] = ':if ([:len [/ip/address find where interface="'.$if.'" and address="'.$addr.'"]]=0) do={ /ip/address add address="'.$addr.'" interface="'.$if.'" }';
            $c[] = ':do { /ip/firewall/filter remove [find where comment="NEURU wg '.$if.'"] } on-error={}';
            $c[] = '/ip/firewall/filter add chain=input protocol=udp dst-port='.$lp.' action=accept comment="NEURU wg '.$if.'" place-before=0';
        }
        foreach ($peers as $p) {
            if (!$p['enabled']) continue;
            $pub = $p['public_key'];
            $aa  = _nm_wg_allowed_address((string)$p['address_ip'], (string)($p['allowed_ips'] ?? ''));
            if ($aa === '') continue;
            $add = '/interface/wireguard/peers add interface="'.$if.'" public-key="'.$pub.'" allowed-address='.$aa;
            if (!empty($p['psk']))        $add .= ' preshared-key="'.$p['psk'].'"';
            if ((int)$p['keepalive'] > 0) $add .= ' persistent-keepalive='.$p['keepalive'].'s';
            $add .= ' comment="'.$p['name'].'"';
            $c[] = ':do { /interface/wireguard/peers remove [find where public-key="'.$pub.'"] } on-error={}';
            $c[] = $add;
        }
        // refresh NEURU-owned routes for this interface
        $c[] = ':do { /ip/route remove [find where comment~"NEURU rt '.$if.'"] } on-error={}';
        foreach ($peers as $p) {
            if (!$p['enabled']) continue;
            foreach (_nm_wg_peer_routes($p) as $dst)
                $c[] = '/ip/route add dst-address='.$dst.' gateway="'.$if.'" comment="NEURU rt '.$if.' '.$p['name'].'"';
        }
        $c[] = ':put "NEURU_OK"';
        return implode('; ', $c);
    }

    // The exact inverse of an apply — removes everything NEURU provisioned so the operator
    // can roll back. Saved to the apply log on every apply, and run by nm_wg_revert().
    function nm_wg_mikrotik_undo_cmd(array $srv, array $peers): string {
        $if = $srv['iface_name']; $adopted = !empty($srv['adopted']); $c = [];
        $c[] = ':do { /ip/route remove [find where comment~"NEURU rt '.$if.'"] } on-error={}';
        foreach ($peers as $p) {
            $pub = (string)$p['public_key']; if ($pub === '') continue;
            $c[] = ':do { /interface/wireguard/peers remove [find where public-key="'.$pub.'"] } on-error={}';
        }
        if (!$adopted) {
            $c[] = ':do { /ip/firewall/filter remove [find where comment="NEURU wg '.$if.'"] } on-error={}';
            $c[] = ':do { /ip/address remove [find where interface="'.$if.'"] } on-error={}';
            $c[] = ':do { /interface/wireguard remove [find where name="'.$if.'"] } on-error={}';
        }
        $c[] = ':put "NEURU_OK"';
        return implode('; ', $c);
    }

    // Linux/VyOS undo (wg-quick). Greenfield → down + remove conf; adopted → drop our peers only.
    function nm_wg_linux_undo_cmd(array $srv, array $peers): string {
        $if = $srv['iface_name'];
        if (!empty($srv['adopted'])) {
            $c = [];
            foreach ($peers as $p) { if (($p['public_key'] ?? '') === '') continue; $c[] = 'wg set '.$if.' peer '.$p['public_key'].' remove'; }
            $c[] = 'wg-quick save '.$if.' 2>/dev/null; echo NEURU_OK';
            return implode('; ', $c);
        }
        return 'wg-quick down '.$if.' 2>/dev/null; rm -f /etc/wireguard/'.$if.'.conf; echo NEURU_OK';
    }

    // Turn the pretty multi-line RouterOS render (path-line + add-line, console style)
    // into a single-line, full-path, ';'-separated command. RouterOS over SSH only runs
    // reliably as ONE exec command (`ssh rb "cmd1; cmd2; …"`); a multi-line script forces
    // the SSH helper into interactive-shell mode, which RouterOS doesn't drain → empty output.
    function nm_wg_mikrotik_exec_cmd(string $config): string {
        $path = ''; $cmds = [];
        foreach (preg_split('/\r?\n/', $config) as $line) {
            $t = trim($line);
            if ($t === '' || $t[0] === '#') continue;     // skip blanks + comments
            if ($t[0] === '/') { $path = $t; continue; }   // path-context line
            $cmds[] = ($path !== '' ? $path.' ' : '').$t;  // prepend path → full command
        }
        $cmds[] = ':put "NEURU_OK"';                        // non-empty reply marker
        return implode('; ', $cmds);
    }

    // Server-side wg0.conf (wg-quick / docker). $srv needs decrypted 'private_key',
    // each peer may carry 'psk'.
    function nm_wg_render_wg0_conf(array $srv, array $peers, bool $nat = true): string {
        $L = "\n";
        $out  = "[Interface]$L";
        $out .= "Address = {$srv['address_cidr']}$L";
        $out .= "ListenPort = {$srv['listen_port']}$L";
        $out .= "PrivateKey = {$srv['private_key']}$L";
        if ($nat) {
            $out .= "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE$L";
            $out .= "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE$L";
        }
        foreach ($peers as $p) {
            if (!$p['enabled']) continue;
            $out .= $L."# {$p['name']}$L[Peer]$L";
            $out .= "PublicKey = {$p['public_key']}$L";
            if (!empty($p['psk'])) $out .= "PresharedKey = {$p['psk']}$L";
            $aa = $p['address_ip'].'/32';
            if (!empty($p['allowed_ips'])) $aa .= ', '.$p['allowed_ips'];
            $out .= "AllowedIPs = {$aa}$L";
        }
        return $out;
    }

    // Single-peer CLIENT config (the QR payload). $srv needs 'public_key'; $peer needs decrypted 'private_key' + 'psk'.
    function nm_wg_render_peer_conf(array $srv, array $peer): string {
        $L = "\n";
        // Public endpoint the CLIENT dials. Never fall back to the tunnel IP (it's the VPN
        // inside-address — useless for a remote peer). Prefer the configured public endpoint,
        // then the device's host IP, else a loud placeholder so the operator sets it.
        $endpoint = $srv['endpoint_host'] ?: ($srv['host_ip'] ?: 'SET-PUBLIC-ENDPOINT-IN-SERVER');
        $allowed  = $srv['default_allowed'] ?: '0.0.0.0/0';
        $out  = "[Interface]$L";
        $out .= "PrivateKey = ".($peer['private_key'] ?? 'REPLACE_WITH_PEER_PRIVATE_KEY').$L;
        $out .= "Address = {$peer['address_ip']}/32$L";
        if (!empty($srv['dns_servers'])) $out .= "DNS = {$srv['dns_servers']}$L";
        $out .= $L."[Peer]$L";
        $out .= "PublicKey = {$srv['public_key']}$L";
        if (!empty($peer['psk'])) $out .= "PresharedKey = {$peer['psk']}$L";
        $out .= "Endpoint = {$endpoint}:{$srv['listen_port']}$L";
        $out .= "AllowedIPs = {$allowed}$L";
        if ((int)($peer['keepalive'] ?? 25) > 0) $out .= "PersistentKeepalive = {$peer['keepalive']}$L";
        return $out;
    }

    // wg-quick "wg set" script — adds peers to an ALREADY-RUNNING linux interface
    // (used when adopting an existing wg-quick tunnel; doesn't rewrite wg0.conf).
    function nm_wg_render_linux_peers(array $srv, array $peers): string {
        $if = $srv['iface_name']; $L = "\n";
        $out = "# NEURU WireGuard — add peers to existing {$if}$L";
        foreach ($peers as $p) {
            if (!$p['enabled']) continue;
            $aa = $p['address_ip'].'/32';
            if (!empty($p['allowed_ips'])) $aa .= ','.$p['allowed_ips'];
            $line = "wg set {$if} peer {$p['public_key']} allowed-ips {$aa}";
            if ((int)$p['keepalive'] > 0) $line .= " persistent-keepalive {$p['keepalive']}";
            $out .= $line.$L;
        }
        $out .= "wg-quick save {$if}$L";
        return $out;
    }

    // Dispatch: returns ['fmt'=>'routeros|conf|shell','filename'=>..,'config'=>..]
    function nm_wg_render(array $srv, array $peers): array {
        // adopted servers only push peers WE manage (imported ones already live on the device)
        if (!empty($srv['adopted']))
            $peers = array_values(array_filter($peers, fn($p) => ($p['origin'] ?? 'managed') === 'managed'));
        if (($srv['target_type'] ?? '') === 'mikrotik')
            return ['fmt'=>'routeros','filename'=>$srv['iface_name'].'.rsc','config'=>nm_wg_render_mikrotik($srv,$peers)];
        if (!empty($srv['adopted']))
            return ['fmt'=>'shell','filename'=>$srv['iface_name'].'-peers.sh','config'=>nm_wg_render_linux_peers($srv,$peers)];
        return ['fmt'=>'conf','filename'=>$srv['iface_name'].'.conf','config'=>nm_wg_render_wg0_conf($srv,$peers)];
    }

    // Load server + peers WITH secrets, ready for rendering/apply (web context only).
    function nm_wg_bundle($conn, int $server_id): ?array {
        $srv = nm_wg_server($conn, $server_id, true);
        if (!$srv) return null;
        $peers = [];
        $r = $conn->query("SELECT * FROM nm_wg_peers WHERE server_id=".(int)$server_id." ORDER BY id");
        while ($r && ($x = $r->fetch_assoc())) {
            $x['psk'] = nm_secret_decrypt($x['preshared_enc'] ?? '');
            unset($x['privkey_enc'], $x['preshared_enc']);
            $peers[] = $x;
        }
        return ['server'=>$srv,'peers'=>$peers];
    }

    // ── Apply (SSH for mikrotik/linux, Portainer for docker), with dry-run ────
    function nm_wg_resolve_ssh($conn, array $srv): ?array {
        if (!empty($srv['node_id'])) return nm_ssh_resolve($conn, (int)$srv['node_id']);
        if (!empty($srv['host_ip'])) return nm_cm_resolve_ssh($conn, ['host_ip'=>$srv['host_ip'],'ssh_cred_id'=>0]);
        return null;
    }

    function nm_wg_apply($conn, int $server_id, bool $dry = false, ?int $uid = null): array {
        nm_wg_ensure($conn);
        $b = nm_wg_bundle($conn, $server_id);
        if (!$b) return ['ok'=>false,'error'=>'Server not found'];
        $srv = $b['server']; $peers = $b['peers']; $tt = $srv['target_type'];
        $render = nm_wg_render($srv, $peers);

        if ($tt === 'docker') return nm_wg_apply_docker($conn, $server_id, $srv, $render['config'], $dry, $uid);

        // build the provisioning command (mikrotik CLI / linux wg-quick)
        $execCmd = null;   // what we actually SEND over SSH (defaults to $cmd below)
        if ($tt === 'mikrotik') {
            // $cmd = readable multi-line (for the dry-run display); $execCmd = the single
            // idempotent exec line RouterOS actually runs (re-appliable, avoids the broken
            // interactive path AND duplicate-object errors on a second apply).
            $cmd     = $render['config']."\n:put \"NEURU_OK\"";
            $execCmd = nm_wg_mikrotik_apply_cmd($srv, $peers);
        } elseif (!empty($srv['adopted'])) {
            // adopted linux tunnel — just add our peers to the running interface, don't rewrite its conf
            $cmd = $render['config']."\necho NEURU_OK";
        } else {
            $conf = $render['config'];
            $path = '/etc/wireguard/'.$srv['iface_name'].'.conf';
            $cmd  = "umask 077; mkdir -p /etc/wireguard; cat > {$path} <<'NEURU_WG_EOF'\n{$conf}\nNEURU_WG_EOF\n"
                  . "wg-quick down {$srv['iface_name']} 2>/dev/null; wg-quick up {$srv['iface_name']} && echo NEURU_OK";
        }

        // dry-run renders the exact commands WITHOUT needing credentials or touching the device
        if ($dry) {
            nm_wg_log($conn, $server_id, null, 'dry_run', $tt, true, $cmd, $uid);
            return ['ok'=>true,'dry'=>true,'target'=>$tt,'command'=>$cmd];
        }

        // live apply → resolve SSH
        $ssh = nm_wg_resolve_ssh($conn, $srv);
        if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'No SSH credential resolved for this server (set node SSH cred or default)'];
        $res = nm_cm_ssh_fetch($ssh, $execCmd ?? $cmd, 40);
        $ok  = $res['ok'] && strpos((string)($res['config'] ?? ''), 'NEURU_OK') !== false;
        $detail = $res['ok'] ? (string)$res['config'] : (string)($res['error'] ?? 'ssh failed');
        nm_wg_log($conn, $server_id, null, 'apply_server', $tt, $ok, $detail, $uid);
        $conn->query("UPDATE nm_wg_servers SET last_apply=NOW(), status='".($ok?'applied':'error')."', last_error=".($ok?'NULL':"'".$conn->real_escape_string(substr($detail,0,290))."'")." WHERE id={$server_id}");
        if ($ok) {
            $conn->query("UPDATE nm_wg_peers SET status='applied' WHERE server_id={$server_id} AND enabled=1");
            // SAVE what was done + the exact rollback, so the operator can audit/revert.
            nm_wg_log($conn, $server_id, null, 'apply_cmd', $tt, true, (string)$execCmd, $uid);
            $undo = $tt === 'mikrotik' ? nm_wg_mikrotik_undo_cmd($srv, $peers) : nm_wg_linux_undo_cmd($srv, $peers);
            nm_wg_log($conn, $server_id, null, 'revert_cmd', $tt, true, $undo, $uid);
        }
        return ['ok'=>$ok,'target'=>$tt,'detail'=>$detail];
    }

    // Push a SINGLE peer to the live device (so adding a peer provisions it immediately —
    // not just stored as draft). MikroTik: idempotent add (drop same public-key first, then
    // add) via one exec line. linux/docker: peers live in the conf → re-apply the server.
    function nm_wg_apply_peer($conn, int $peer_id, ?int $uid = null): array {
        nm_wg_ensure($conn);
        $peer = nm_wg_peer($conn, $peer_id, true);  // need psk (if any)
        if (!$peer) return ['ok'=>false,'error'=>'peer not found'];
        $sid = (int)$peer['server_id'];
        $srv = nm_wg_server($conn, $sid);
        if (!$srv) return ['ok'=>false,'error'=>'server not found'];
        $tt = $srv['target_type'];
        if ($tt !== 'mikrotik') {
            // wg-quick/docker hold peers in the config file → full re-apply rewrites it
            return nm_wg_apply($conn, $sid, false, $uid);
        }
        $ssh = nm_wg_resolve_ssh($conn, $srv);
        if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'No SSH credential resolved for this server'];
        $if = $srv['iface_name']; $pub = $peer['public_key'];
        $aa = _nm_wg_allowed_address((string)$peer['address_ip'], (string)($peer['allowed_ips'] ?? ''));
        if ($aa === '') return ['ok'=>false,'error'=>'peer has no valid address — cannot build allowed-address'];
        $add = "/interface/wireguard/peers add interface={$if} public-key=\"{$pub}\" allowed-address={$aa}";
        if (!empty($peer['psk']))            $add .= " preshared-key=\"{$peer['psk']}\"";
        if ((int)$peer['keepalive'] > 0)     $add .= " persistent-keepalive={$peer['keepalive']}s";
        $add .= " comment=\"{$peer['name']}\"";
        // idempotent: remove any existing peer with this public-key, then add. Single exec line.
        $parts = [':do { /interface/wireguard/peers remove [find where public-key="'.$pub.'"] } on-error={}', $add];
        // static route(s) to any LAN behind this peer (site-to-site) — ROS won't auto-add them
        $parts[] = ':do { /ip/route remove [find where comment="NEURU rt '.$if.' '.$peer['name'].'"] } on-error={}';
        foreach (_nm_wg_peer_routes($peer) as $dst)
            $parts[] = '/ip/route add dst-address='.$dst.' gateway="'.$if.'" comment="NEURU rt '.$if.' '.$peer['name'].'"';
        $parts[] = ':put "NEURU_OK"';
        $cmd = implode('; ', $parts);
        $res = nm_cm_ssh_fetch($ssh, $cmd, 30);
        $ok  = $res['ok'] && strpos((string)($res['config'] ?? ''), 'NEURU_OK') !== false;
        $detail = $res['ok'] ? (string)$res['config'] : (string)($res['error'] ?? 'ssh failed');
        nm_wg_log($conn, $sid, $peer_id, 'apply_peer', $tt, $ok, $detail, $uid);
        if ($ok) {
            $conn->query("UPDATE nm_wg_peers SET status='applied' WHERE id=".(int)$peer_id);
            nm_wg_log($conn, $sid, $peer_id, 'apply_cmd', $tt, true, $cmd, $uid);
            // saved per-peer rollback
            $undo = [':do { /interface/wireguard/peers remove [find where public-key="'.$pub.'"] } on-error={}',
                     ':do { /ip/route remove [find where comment="NEURU rt '.$if.' '.$peer['name'].'"] } on-error={}', ':put "NEURU_OK"'];
            nm_wg_log($conn, $sid, $peer_id, 'revert_cmd', $tt, true, implode('; ', $undo), $uid);
        }
        return ['ok'=>$ok,'target'=>$tt,'detail'=>$detail];
    }

    // Roll back everything NEURU provisioned for a server (peers + routes, and for greenfield
    // the firewall rule / address / interface). MikroTik + linux/VyOS over SSH.
    function nm_wg_revert($conn, int $server_id, ?int $uid = null): array {
        nm_wg_ensure($conn);
        $b = nm_wg_bundle($conn, $server_id);
        if (!$b) return ['ok'=>false,'error'=>'Server not found'];
        $srv = $b['server']; $peers = $b['peers']; $tt = $srv['target_type'];
        if ($tt === 'docker')
            return ['ok'=>false,'error'=>'Automated revert is not available for Docker targets — remove the container in Portainer.'];
        $undo = $tt === 'mikrotik' ? nm_wg_mikrotik_undo_cmd($srv, $peers) : nm_wg_linux_undo_cmd($srv, $peers);
        $ssh = nm_wg_resolve_ssh($conn, $srv);
        if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'No SSH credential resolved for this server'];
        $res = nm_cm_ssh_fetch($ssh, $undo, 40);
        $ok  = $res['ok'] && strpos((string)($res['config'] ?? ''), 'NEURU_OK') !== false;
        $detail = $res['ok'] ? (string)$res['config'] : (string)($res['error'] ?? 'ssh failed');
        nm_wg_log($conn, $server_id, null, 'revert_run', $tt, $ok, $detail, $uid);
        if ($ok) {
            $conn->query("UPDATE nm_wg_servers SET status='draft', last_error=NULL, last_apply=NOW() WHERE id={$server_id}");
            $conn->query("UPDATE nm_wg_peers SET status='draft' WHERE server_id={$server_id}");
        }
        return ['ok'=>$ok,'target'=>$tt,'detail'=>$detail];
    }

    function nm_wg_apply_docker($conn, int $server_id, array $srv, string $wg0conf, bool $dry, ?int $uid): array {
        $eid  = (int)($srv['portainer_endpoint_id'] ?? 0);
        $host = $srv['host_ip'] ?: '';
        $name = $srv['container_name'] ?: ('wg-'.$srv['iface_name']);
        $dir  = '/opt/neuru-wg/'.$name;
        $writeCmd = "mkdir -p {$dir} && cat > {$dir}/wg0.conf <<'NEURU_WG_EOF'\n{$wg0conf}\nNEURU_WG_EOF\necho NEURU_OK";

        if ($dry) {
            $plan = "# 1) write {$dir}/wg0.conf on host {$host} via SSH:\n{$writeCmd}\n\n"
                  . "# 2) Portainer create+start container '{$name}' (endpoint {$eid}):\n"
                  . "#    image=ghcr.io/wg-easy/wg-easy or linuxserver/wireguard\n"
                  . "#    binds=[{$dir}:/etc/wireguard]  caps=[NET_ADMIN,SYS_MODULE]  sysctl net.ipv4.ip_forward=1  ports=51820/udp:{$srv['listen_port']}";
            nm_wg_log($conn, $server_id, null, 'dry_run', 'docker', true, $plan, $uid);
            return ['ok'=>true,'dry'=>true,'target'=>'docker','command'=>$plan];
        }
        if ($eid <= 0 || $host === '') return ['ok'=>false,'error'=>'Docker target needs portainer_endpoint_id + host_ip'];

        // 1) write the config file to the host via SSH (default credential)
        $ssh = nm_cm_resolve_ssh($conn, ['host_ip'=>$host,'ssh_cred_id'=>0]);
        if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'No SSH credential for Docker host '.$host];
        $w = nm_cm_ssh_fetch($ssh, $writeCmd, 30);
        if (!$w['ok'] || strpos((string)($w['config'] ?? ''), 'NEURU_OK') === false) {
            nm_wg_log($conn, $server_id, null, 'docker_deploy', 'docker', false, 'config write failed: '.($w['error'] ?? ''), $uid);
            return ['ok'=>false,'error'=>'Failed to write wg0.conf to host: '.($w['error'] ?? '')];
        }
        // 2) create + start the container via Portainer
        $cfg = nm_portainer_cfg($conn);
        $spec = [
            'name'  => $name,
            'image' => $srv['container_name'] && strpos((string)$srv['container_name'],'/')!==false ? $srv['container_name'] : 'ghcr.io/wg-easy/wg-easy:latest',
            'env'   => [],
            'ports' => ['51820/udp'=>(string)$srv['listen_port']],
            'caps'  => ['NET_ADMIN','SYS_MODULE'],
            'sysctls'=> ['net.ipv4.ip_forward'=>'1'],
            'binds' => [$dir.':/etc/wireguard'],
            'restart'=> 'unless-stopped',
        ];
        $r = nm_portainer_container_create($cfg, $eid, $spec);
        $ok = $r['ok'];
        nm_wg_log($conn, $server_id, null, 'docker_deploy', 'docker', $ok, $ok ? ('container '.($r['data']['Id'] ?? '')) : ('portainer: '.$r['error']), $uid);
        $conn->query("UPDATE nm_wg_servers SET last_apply=NOW(), status='".($ok?'applied':'error')."', container_name='".$conn->real_escape_string($name)."', last_error=".($ok?'NULL':"'".$conn->real_escape_string(substr($r['error'],0,290))."'")." WHERE id={$server_id}");
        return ['ok'=>$ok,'target'=>'docker','detail'=>$ok?'deployed':$r['error']];
    }

    function nm_wg_log($conn, int $sid, ?int $pid, string $action, string $ttype, bool $ok, string $detail, ?int $uid): void {
        $okI = $ok ? 1 : 0;
        $st = $conn->prepare("INSERT INTO nm_wg_apply_log (server_id,peer_id,action,target_type,ok,detail,created_by) VALUES (?,?,?,?,?,?,?)");
        // server_id i,peer_id i,action s,target_type s,ok i,detail s,created_by i
        $st->bind_param('iissisi', $sid,$pid,$action,$ttype,$okI,$detail,$uid);
        $st->execute();
    }
    function nm_wg_logs($conn, int $server_id, int $limit = 30): array {
        $limit = max(1, min(200, $limit));
        $out = [];
        $r = $conn->query("SELECT * FROM nm_wg_apply_log WHERE server_id=".(int)$server_id." ORDER BY id DESC LIMIT {$limit}");
        while ($r && ($x = $r->fetch_assoc())) $out[] = $x;
        return $out;
    }

    // ── Live peer monitoring: poll handshake + traffic per peer over SSH ──────
    function nm_wg_setting($conn, string $k, $d) {
        $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1");
        return $r && ($x = $r->fetch_row()) ? $x[0] : $d;
    }
    // RouterOS last-handshake duration "[Nw][Nd]HH:MM:SS" → seconds ('' = never → null)
    function nm_wg_dur_to_secs(string $s): ?int {
        $s = trim($s);
        if ($s === '' || stripos($s, 'never') !== false) return null;
        $secs = 0;
        if (preg_match('/(\d+)w/', $s, $m)) $secs += (int)$m[1] * 604800;
        if (preg_match('/(\d+)d/', $s, $m)) $secs += (int)$m[1] * 86400;
        $rest = preg_replace('/^\s*(\d+w)?(\d+d)?/', '', $s);
        if (preg_match('/(?:(\d+):)?(\d+):(\d+)/', $rest, $m)) $secs += ((int)($m[1] ?: 0)) * 3600 + (int)$m[2] * 60 + (int)$m[3];
        return $secs;
    }

    function nm_wg_poll_stats($conn, array $srv): array {
        nm_wg_ensure($conn);
        $sid = (int)$srv['id'];
        $ssh = nm_wg_resolve_ssh($conn, $srv);
        if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'No SSH credential'];
        $now = time();
        $stats = [];   // public_key => ['rx','tx','age','endpoint']

        if (($srv['target_type'] ?? '') === 'mikrotik') {
            // comment is emitted LAST — it may itself contain ';', so the parser re-joins the tail.
            $script = ':foreach i in=[/interface/wireguard/peers find] do={:put ('
                . '[/interface/wireguard/peers get $i public-key].";".'
                . '[/interface/wireguard/peers get $i last-handshake].";".'
                . '[/interface/wireguard/peers get $i rx].";".'
                . '[/interface/wireguard/peers get $i tx].";".'
                . '[/interface/wireguard/peers get $i current-endpoint-address].";".'
                . '[/interface/wireguard/peers get $i comment])}';
            $r = nm_cm_ssh_fetch($ssh, $script, 25);
            if (!$r['ok'] && stripos((string)$r['error'], 'empty') === false) return ['ok'=>false,'error'=>$r['error']];
            foreach (preg_split('/\r?\n/', (string)($r['config'] ?? '')) as $ln) {
                $ln = trim($ln); if ($ln === '' || strpos($ln, ';') === false) continue;
                $f = explode(';', $ln);
                if (count($f) < 4 || !nm_wg_valid_key($f[0])) continue;
                $stats[$f[0]] = ['rx'=>(int)$f[2],'tx'=>(int)$f[3],'age'=>nm_wg_dur_to_secs($f[1]),
                                 'endpoint'=>$f[4] ?? '','comment'=>nm_wg_clean_name(implode(';', array_slice($f, 5)))];
            }
        } else {
            $iface = preg_replace('/[^a-zA-Z0-9_-]/', '', (string)$srv['iface_name']);
            $r = nm_cm_ssh_fetch($ssh, "wg show ".escapeshellarg($iface)." dump 2>/dev/null", 20);
            if (!$r['ok'] && stripos((string)$r['error'], 'empty') === false) return ['ok'=>false,'error'=>$r['error']];
            foreach (preg_split('/\r?\n/', (string)($r['config'] ?? '')) as $ln) {
                $f = explode("\t", $ln);
                if (count($f) < 8) continue;   // peer lines have 8 fields; interface line has 4
                $hs = (int)$f[4];
                $stats[$f[0]] = ['rx'=>(int)$f[5],'tx'=>(int)$f[6],'age'=>($hs > 0 ? $now - $hs : null),
                                 'endpoint'=>($f[2] === '(none)' ? '' : $f[2])];
            }
        }

        $connSecs = max(30, (int)nm_wg_setting($conn, 'wg_connected_secs', 180));
        $updated = 0;
        $ins = $conn->prepare("INSERT INTO nm_wg_peer_traffic (peer_id,ts,rx_bytes,tx_bytes,rx_rate,tx_rate) VALUES (?,NOW(),?,?,?,?)
                               ON DUPLICATE KEY UPDATE rx_bytes=VALUES(rx_bytes)");
        $pr = $conn->query("SELECT id,name,origin,public_key,rx_bytes,tx_bytes,stats_at FROM nm_wg_peers WHERE server_id={$sid}");
        while ($pr && ($p = $pr->fetch_assoc())) {
            $pk = $p['public_key'];
            if (!isset($stats[$pk])) continue;
            $s = $stats[$pk];
            // Adopt the router's ;;; comment as the real name — but never clobber a name the
            // operator typed in NEURU (only auto-generated 'imported-*' / empty names get updated).
            $cmt = (string)($s['comment'] ?? '');
            if ($cmt !== '') {
                $cur = (string)$p['name'];
                $auto = ($cur === '' || ($p['origin'] ?? '') === 'imported' || strncmp($cur, 'imported-', 9) === 0);
                if ($auto && $cmt !== $cur) {
                    $st = $conn->prepare("UPDATE nm_wg_peers SET name=? WHERE id=?");
                    $st->bind_param('si', $cmt, $p['id']); $st->execute();
                }
            }
            $connected = ($s['age'] !== null && $s['age'] <= $connSecs) ? 1 : 0;
            $rxr = $txr = 0.0;
            if (!empty($p['stats_at'])) {
                $dt = $now - strtotime($p['stats_at']);
                if ($dt > 0) {
                    if ($s['rx'] >= (int)$p['rx_bytes']) $rxr = ($s['rx'] - (int)$p['rx_bytes']) / $dt;
                    if ($s['tx'] >= (int)$p['tx_bytes']) $txr = ($s['tx'] - (int)$p['tx_bytes']) / $dt;
                }
            }
            $hsSql = $s['age'] !== null ? "DATE_SUB(NOW(), INTERVAL ".(int)$s['age']." SECOND)" : "last_handshake";
            $ep = "'".$conn->real_escape_string(substr((string)$s['endpoint'], 0, 60))."'";
            $rx = (int)$s['rx']; $tx = (int)$s['tx']; $pid = (int)$p['id'];
            $conn->query("UPDATE nm_wg_peers SET rx_bytes={$rx},tx_bytes={$tx},endpoint={$ep},connected={$connected},last_handshake={$hsSql},stats_at=NOW() WHERE id={$pid}");
            $ins->bind_param('iiidd', $pid, $rx, $tx, $rxr, $txr);
            $ins->execute();
            $updated++;
        }
        nm_wg_backfill_names($conn);   // cross-server name adoption for same-key peers
        return ['ok'=>true,'server'=>$srv['name'],'peers'=>$updated,'seen'=>count($stats)];
    }

    function nm_wg_poll_all_stats($conn): array {
        nm_wg_ensure($conn);
        $out = [];
        $r = $conn->query("SELECT * FROM nm_wg_servers WHERE target_type IN ('mikrotik','linux')");
        while ($r && ($x = $r->fetch_assoc())) $out[] = nm_wg_poll_stats($conn, $x);
        return $out;
    }
    function nm_wg_traffic_prune($conn, int $days = 14): void {
        $conn->query("DELETE FROM nm_wg_peer_traffic WHERE ts < (NOW() - INTERVAL ".max(1,$days)." DAY)");
    }
    function nm_wg_peer_traffic($conn, int $peer_id, int $mins = 1440): array {
        $out = [];
        $r = $conn->query("SELECT ts,rx_rate,tx_rate FROM nm_wg_peer_traffic WHERE peer_id=".(int)$peer_id."
            AND ts >= (NOW() - INTERVAL ".max(5,$mins)." MINUTE) ORDER BY ts");
        while ($r && ($x = $r->fetch_assoc())) $out[] = ['t'=>$x['ts'],'rx'=>round((float)$x['rx_rate'],1),'tx'=>round((float)$x['tx_rate'],1)];
        return $out;
    }
}
