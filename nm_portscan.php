<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Port Scanner engine (Net Tools). On-demand TCP connect scan of any
// monitored node or any user-entered IP/hostname. Pure PHP (stream sockets) —
// NO nmap/masscan binary needed (none are on the container). Async connect +
// stream_select so a chunk of "filtered" ports shares ONE timeout window.
//
// SAFETY: strict target validation (reuse nm_nt_valid_target), a hard port cap,
// and a public-IP guard — a public target must be explicitly confirmed by the
// operator (prevents accidentally scanning the open internet). RBAC: the caller
// (portscan.php) gates on 'nettools_portscan'. Every scan is nm_audit'd there.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_ps_presets')) {
    require_once __DIR__ . '/nm_nettools.php';   // nm_nt_valid_target, nm_nt_is_private

    // Named port sets the UI offers. Kept small & meaningful; "wellknown" is the
    // heaviest (1-1024) but still ~10s over SSE thanks to chunked async connect.
    function nm_ps_presets(): array {
        return [
            'top20' => ['label'=>'Top 20', 'ports'=>[21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]],
            'top100'=> ['label'=>'Top 100','ports'=>nm_ps_top100()],
            'web'   => ['label'=>'Web / proxy','ports'=>[80,81,443,591,2082,2083,2086,2087,2095,2096,3000,4443,5000,7001,8000,8008,8080,8081,8088,8443,8888,9000,9090,9443]],
            'db'    => ['label'=>'Databases','ports'=>[1433,1521,3306,5432,5984,6379,7000,7199,8086,9042,9200,11211,27017,27018,28015,50000]],
            'remote'=> ['label'=>'Remote / mgmt','ports'=>[22,23,443,902,2222,3389,5000,5900,5901,5985,5986,8006,8291,9090,10000]],
            'well'  => ['label'=>'Well-known (1-1024)','ports'=>range(1,1024)],
            'reg'   => ['label'=>'Registered (1-49151)','ports'=>range(1,49151)],
            'full'  => ['label'=>'FULL (1-65535)','ports'=>range(1,65535)],
        ];
    }
    function nm_ps_top100(): array {
        return [7,20,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,
            427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,
            1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,
            5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,
            8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157];
    }

    // A friendly service name for common ports (display only).
    function nm_ps_service(int $p): string {
        static $m = [21=>'ftp',22=>'ssh',23=>'telnet',25=>'smtp',53=>'dns',67=>'dhcp',69=>'tftp',80=>'http',
            81=>'http-alt',88=>'kerberos',110=>'pop3',111=>'rpcbind',123=>'ntp',135=>'msrpc',137=>'netbios',
            139=>'netbios',143=>'imap',161=>'snmp',179=>'bgp',389=>'ldap',443=>'https',445=>'smb',465=>'smtps',
            514=>'syslog',515=>'printer',587=>'submission',631=>'ipp',636=>'ldaps',873=>'rsync',990=>'ftps',
            993=>'imaps',995=>'pop3s',1080=>'socks',1194=>'openvpn',1433=>'mssql',1521=>'oracle',1723=>'pptp',
            1883=>'mqtt',2049=>'nfs',2082=>'cpanel',2083=>'cpanel-ssl',2222=>'ssh-alt',3000=>'grafana',
            3128=>'squid',3306=>'mysql',3389=>'rdp',5000=>'upnp',5060=>'sip',5432=>'postgres',5601=>'kibana',
            5666=>'nrpe',5900=>'vnc',5985=>'winrm',5986=>'winrm-ssl',6379=>'redis',8000=>'http-alt',
            8006=>'proxmox',8008=>'http-alt',8080=>'http-proxy',8086=>'influxdb',8088=>'http-alt',8090=>'http-alt',
            8291=>'winbox',8443=>'https-alt',8888=>'http-alt',9000=>'php-fpm',9090=>'prometheus',9100=>'node-exp',
            9200=>'elastic',9443=>'https-alt',10000=>'webmin',11211=>'memcached',27017=>'mongodb',51820=>'wireguard'];
        return $m[$p] ?? '';
    }

    // Parse a ports string ("22,80,443,8000-8100") into a unique, sorted, capped
    // list of ints. Returns [] on garbage. Cap protects the box + keeps SSE snappy.
    function nm_ps_parse_ports(string $s, int $cap = 2048): array {
        $out = [];
        foreach (preg_split('/[,\s]+/', trim($s), -1, PREG_SPLIT_NO_EMPTY) as $tok) {
            if (preg_match('/^(\d{1,5})-(\d{1,5})$/', $tok, $m)) {
                $a = (int)$m[1]; $b = (int)$m[2]; if ($a > $b) [$a,$b] = [$b,$a];
                for ($p = max(1,$a); $p <= min(65535,$b); $p++) { $out[$p] = true; if (count($out) >= $cap) break 2; }
            } elseif (preg_match('/^\d{1,5}$/', $tok)) {
                $p = (int)$tok; if ($p >= 1 && $p <= 65535) $out[$p] = true;
            }
            if (count($out) >= $cap) break;
        }
        $ports = array_map('intval', array_keys($out)); sort($ports);
        return array_slice($ports, 0, $cap);
    }

    // Resolve + safety-vet a target. Returns ['ok','ip','host','private','error'].
    // A public IP requires $confirm=true (accidental-internet-scan guard).
    function nm_ps_resolve($conn, string $target, bool $confirm = false): array {
        $t = nm_nt_valid_target($target);
        if (!$t) return ['ok'=>false,'error'=>'Invalid target (must be an IP or hostname)'];
        // resolve hostname → IPv4 (gethostbyname is safe, no shell)
        $ip = filter_var($t, FILTER_VALIDATE_IP) ? $t : gethostbyname($t);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok'=>false,'error'=>"Could not resolve '{$t}'"];
        // hard blocks — never scan these
        if (in_array($ip, ['0.0.0.0','255.255.255.255'], true)) return ['ok'=>false,'error'=>'Refused: reserved address'];
        if (preg_match('/^(22[4-9]|23[0-9])\./', $ip)) return ['ok'=>false,'error'=>'Refused: multicast address'];
        $private = nm_nt_is_private($ip);
        if (!$private && !$confirm) return ['ok'=>false,'error'=>'confirm_public','ip'=>$ip,'host'=>$t];
        return ['ok'=>true,'ip'=>$ip,'host'=>$t,'private'=>$private];
    }

    // Scan ONE chunk of ports concurrently via async connect + select.
    // Returns [port => 'open'|'closed'|'filtered'].  $timeout is per-chunk wall clock.
    function nm_ps_scan_chunk(string $ip, array $ports, float $timeout = 1.2): array {
        $res = []; $socks = [];
        foreach ($ports as $p) {
            $errno = 0; $errstr = '';
            $fp = @stream_socket_client("tcp://{$ip}:{$p}", $errno, $errstr, $timeout,
                  STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_CONNECT);
            if ($fp) { @stream_set_blocking($fp, false); $socks[$p] = $fp; }
            else     { $res[$p] = 'closed'; }   // immediate local refusal
        }
        $deadline = microtime(true) + $timeout;
        while ($socks && microtime(true) < $deadline) {
            $r = null; $w = array_values($socks); $e = array_values($socks);
            $left = $deadline - microtime(true); if ($left <= 0) break;
            $sec = (int)$left; $usec = (int)(($left - $sec) * 1e6);
            $n = @stream_select($r, $w, $e, $sec, $usec);
            if ($n === false) break;
            if ($n <= 0) continue;
            foreach ($w as $fp) {
                $p = array_search($fp, $socks, true); if ($p === false) continue;
                // Writable + a live peer name ⇒ the 3-way handshake completed (open).
                // Writable with no peer (RST) ⇒ refused (closed).
                $res[$p] = (@stream_socket_get_name($fp, true) !== false) ? 'open' : 'closed';
                @fclose($fp); unset($socks[$p]);
            }
            foreach ($e as $fp) {
                $p = array_search($fp, $socks, true); if ($p === false) continue;
                $res[$p] = 'closed'; @fclose($fp); unset($socks[$p]);
            }
        }
        // Anything still pending never answered → filtered (dropped by a firewall).
        foreach ($socks as $p => $fp) { $res[$p] = 'filtered'; @fclose($fp); }
        return $res;
    }
}
