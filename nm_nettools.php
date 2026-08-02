<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Net Tools engine (Live Ping, Traceroute+GeoIP, Netstat).
//
// PERSISTENCE-SAFE: needs NO extra binaries (the container only ships `ping`):
//   • traceroute → `ping` with incrementing TTL, parsing "Time to live exceeded"
//   • netstat    → parse /proc/net/{tcp,tcp6,udp,udp6} directly (no `ss`)
//   • GeoIP      → ip-api.com (free, no key) cached in MySQL (no licensed DB file)
//
// SECURITY: every target is validated as a clean IP/hostname (rejecting anything
// starting with '-' to stop ping option-injection), and ALL commands run through
// proc_open with ARRAY argv — never a shell string — so OS command injection is
// structurally impossible.
//
// RBAC perms: nettools_ping | nettools_trace | nettools_netstat.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_nt_valid_target')) {

    function nm_nt_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_geoip_cache (
            ip VARCHAR(45) PRIMARY KEY,
            lat DOUBLE DEFAULT NULL, lon DOUBLE DEFAULT NULL,
            city VARCHAR(80) DEFAULT NULL, country VARCHAR(80) DEFAULT NULL,
            country_code VARCHAR(2) DEFAULT NULL,
            asn VARCHAR(140) DEFAULT NULL,
            fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // add country_code to pre-existing caches (mysqli is in EXCEPTION mode → probe first)
        try {
            $c = $conn->query("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
                               AND TABLE_NAME='nm_geoip_cache' AND COLUMN_NAME='country_code' LIMIT 1");
            if ($c && !$c->num_rows) $conn->query("ALTER TABLE nm_geoip_cache ADD COLUMN country_code VARCHAR(2) DEFAULT NULL AFTER country");
        } catch (\Throwable $e) {}
        foreach (['nettools_ping','nettools_trace','nettools_netstat','nettools_lookup','nettools_portscan'] as $k) {
            @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','{$k}',1 FROM DUAL
                WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='{$k}')");
        }
    }

    // Strict target validation — returns the clean target or null. Rejects leading
    // '-' (option injection) and anything that isn't a valid IP or DNS hostname.
    function nm_nt_valid_target(string $s): ?string {
        $s = trim($s);
        if ($s === '' || strlen($s) > 255 || $s[0] === '-') return null;
        if (filter_var($s, FILTER_VALIDATE_IP)) return $s;
        if (preg_match('/^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/', $s)) return $s;
        return null;
    }

    function nm_nt_is_private(string $ip): bool {
        // true for RFC1918 / loopback / link-local / reserved (we don't GeoIP these)
        return filter_var($ip, FILTER_VALIDATE_IP) &&
               !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    // Run argv (no shell) with a wall-clock timeout. Returns stdout.
    function nm_nt_run(array $cmd, float $timeout = 5.0): string {
        $proc = @proc_open($cmd, [1=>['pipe','w'], 2=>['pipe','w']], $pipes);
        if (!is_resource($proc)) return '';
        stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false);
        $out = ''; $deadline = microtime(true) + $timeout;
        while (microtime(true) < $deadline) {
            $chunk = stream_get_contents($pipes[1]); if ($chunk !== false) $out .= $chunk;
            if (!proc_get_status($proc)['running']) break;
            usleep(40000);
        }
        $chunk = stream_get_contents($pipes[1]); if ($chunk !== false) $out .= $chunk;
        if (proc_get_status($proc)['running']) proc_terminate($proc);
        @fclose($pipes[1]); @fclose($pipes[2]); @proc_close($proc);
        return $out;
    }

    // ── GeoIP (cached) ────────────────────────────────────────────────────────
    function nm_nt_geoip($conn, string $ip): ?array {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return null;
        if (nm_nt_is_private($ip)) return ['private'=>true];
        nm_nt_ensure($conn);
        $esc = $conn->real_escape_string($ip);
        $r = $conn->query("SELECT lat,lon,city,country,country_code,asn FROM nm_geoip_cache WHERE ip='{$esc}' AND fetched_at > (NOW()-INTERVAL 30 DAY) LIMIT 1");
        if ($r && ($x = $r->fetch_assoc())) {
            // self-heal rows cached before country_code existed: if it has a country but no
            // code, fall through and re-fetch once so the flag can render.
            $needsCc = (($x['country'] ?? '') !== '' && ($x['country_code'] ?? '') === '');
            if (!$needsCc) { $x['lat']=(float)$x['lat']; $x['lon']=(float)$x['lon']; return $x; }
        }
        $ctx = stream_context_create(['http'=>['timeout'=>3,'header'=>'User-Agent: NEURU-NOC']]);
        $j = @file_get_contents("http://ip-api.com/json/".urlencode($ip)."?fields=status,country,countryCode,city,lat,lon,as,query", false, $ctx);
        $d = $j ? json_decode($j, true) : null;
        if (!$d || ($d['status'] ?? '') !== 'success') return null;
        $row = ['lat'=>(float)$d['lat'],'lon'=>(float)$d['lon'],'city'=>(string)($d['city']??''),'country'=>(string)($d['country']??''),'country_code'=>(string)($d['countryCode']??''),'asn'=>(string)($d['as']??'')];
        $st = $conn->prepare("INSERT INTO nm_geoip_cache (ip,lat,lon,city,country,country_code,asn,fetched_at) VALUES (?,?,?,?,?,?,?,NOW())
            ON DUPLICATE KEY UPDATE lat=VALUES(lat),lon=VALUES(lon),city=VALUES(city),country=VALUES(country),country_code=VALUES(country_code),asn=VALUES(asn),fetched_at=NOW()");
        $st->bind_param('sddssss', $ip, $row['lat'], $row['lon'], $row['city'], $row['country'], $row['country_code'], $row['asn']);
        $st->execute();
        return $row;
    }

    // ISO2 country code → flag emoji ('DE' → 🇩🇪). '' for bad input.
    function nm_geo_flag(?string $cc): string {
        $cc = strtoupper(trim((string)$cc));
        if (strlen($cc) !== 2 || !ctype_alpha($cc)) return '';
        return mb_chr(0x1F1E6 + ord($cc[0]) - 65) . mb_chr(0x1F1E6 + ord($cc[1]) - 65);
    }

    // Reusable "where is this IP" badge for any UI surface showing external/attacker IPs.
    // Returns ['country','cc','flag','city','asn'] or NULL for private/invalid IPs (skip badge).
    function nm_geo_badge($conn, ?string $ip): ?array {
        if (!$ip) return null; $ip = trim($ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return null;
        if (nm_nt_is_private($ip)) return null;                 // no country for internal IPs
        $g = nm_nt_geoip($conn, $ip);
        if (!$g || !empty($g['private']) || empty($g['country'])) return null;
        $cc = (string)($g['country_code'] ?? '');
        return ['country'=>(string)$g['country'], 'cc'=>$cc, 'flag'=>nm_geo_flag($cc),
                'city'=>(string)($g['city'] ?? ''), 'asn'=>(string)($g['asn'] ?? '')];
    }

    // ── Traceroute via ping TTL-stepping (no traceroute binary) ───────────────
    // Per-hop RTT is the wall-clock of the probe (approximate but good for the map).
    function nm_nt_traceroute($conn, string $target, int $maxhops = 30): array {
        $maxhops = max(1, min(40, $maxhops));
        $targetIp = filter_var($target, FILTER_VALIDATE_IP) ? $target : null;
        $hops = []; $seenFinal = false;
        for ($ttl = 1; $ttl <= $maxhops; $ttl++) {
            $t0 = microtime(true);
            $out = nm_nt_run(['ping','-c','1','-W','2','-n','-t',(string)$ttl,$target], 3.5);
            $rttWall = round((microtime(true) - $t0) * 1000, 1);
            $hop = ['ttl'=>$ttl,'ip'=>null,'rtt'=>null,'final'=>false,'geo'=>null];
            if (preg_match('/icmp_seq=\d+ ttl=\d+ time=([\d.]+)\s*ms.*?from ([0-9.]+)/is', $out, $m)) {
                // final reply (target reached)
                $hop['ip'] = $m[2]; $hop['rtt'] = (float)$m[1]; $hop['final'] = true;
            } elseif (preg_match('/(\d+) bytes from ([0-9.]+):.*time=([\d.]+)/s', $out, $m)) {
                $hop['ip'] = $m[2]; $hop['rtt'] = (float)$m[3]; $hop['final'] = true;
            } elseif (preg_match('/[Ff]rom ([0-9.]+).*?[Tt]ime to live exceeded/s', $out, $m)) {
                $hop['ip'] = $m[1]; $hop['rtt'] = $rttWall;   // intermediate hop, approx RTT
            } elseif (preg_match('/[Ff]rom ([0-9.]+)/', $out, $m)) {
                $hop['ip'] = $m[1]; $hop['rtt'] = $rttWall;
            }
            if ($hop['ip']) $hop['geo'] = nm_nt_geoip($conn, $hop['ip']);
            $hops[] = $hop;
            if ($hop['final']) { $seenFinal = true; break; }
            if ($targetIp && $hop['ip'] === $targetIp) break;
        }
        return ['target'=>$target,'reached'=>$seenFinal,'hops'=>$hops];
    }

    // ── Netstat via /proc/net (no `ss`/`netstat` binary) ──────────────────────
    function _nm_nt_hexaddr(string $h, bool $v6): array {
        [$addr, $port] = array_pad(explode(':', $h, 2), 2, '0');
        $port = hexdec($port);
        if (!$v6) {
            // little-endian 32-bit
            $b = str_split($addr, 2);
            if (count($b) < 4) return ['?', $port];
            return [hexdec($b[3]).'.'.hexdec($b[2]).'.'.hexdec($b[1]).'.'.hexdec($b[0]), $port];
        }
        // IPv6: 32 hex chars, 4 little-endian 32-bit words
        if (strlen($addr) < 32) return ['::', $port];
        $words = str_split($addr, 8); $parts = [];
        foreach ($words as $w) { $le = $w[6].$w[7].$w[4].$w[5].$w[2].$w[3].$w[0].$w[1]; $parts[] = substr($le,0,4).':'.substr($le,4,4); }
        $ip = implode(':', $parts);
        return [@inet_ntop(@inet_pton($ip) ?: '') ?: $ip, $port];
    }
    function _nm_nt_state(int $st): string {
        return [1=>'ESTABLISHED',2=>'SYN_SENT',3=>'SYN_RECV',4=>'FIN_WAIT1',5=>'FIN_WAIT2',6=>'TIME_WAIT',
                7=>'CLOSE',8=>'CLOSE_WAIT',9=>'LAST_ACK',10=>'LISTEN',11=>'CLOSING'][$st] ?? ('S'.$st);
    }
    // ── DNS lookup (nslookup-style) — shell-free via PHP's resolver ───────────
    // type ∈ A AAAA MX NS TXT CNAME SOA PTR ANY. PTR/IP input → reverse lookup.
    function nm_nt_nslookup($conn, string $target, string $type = 'A'): array {
        $t = nm_nt_valid_target($target);
        if (!$t) return ['ok'=>false,'error'=>'Invalid target (IP or hostname only)'];
        $type = strtoupper(trim($type));
        $allowed = ['A','AAAA','MX','NS','TXT','CNAME','SOA','PTR','ANY'];
        if (!in_array($type, $allowed, true)) $type = 'A';
        $isIp = (bool)filter_var($t, FILTER_VALIDATE_IP);

        // IP input (or explicit PTR) → reverse DNS only
        if ($isIp || $type === 'PTR') {
            if (!$isIp) return ['ok'=>false,'error'=>'PTR needs an IP address'];
            $h = @gethostbyaddr($t);
            $recs = ($h && $h !== $t) ? [['type'=>'PTR','value'=>$h,'ttl'=>null,'host'=>$t]] : [];
            return ['ok'=>true,'target'=>$t,'type'=>'PTR','records'=>$recs];
        }
        $map = ['A'=>DNS_A,'AAAA'=>DNS_AAAA,'MX'=>DNS_MX,'NS'=>DNS_NS,'TXT'=>DNS_TXT,
                'CNAME'=>DNS_CNAME,'SOA'=>DNS_SOA,'ANY'=>DNS_ALL];
        $recs = @dns_get_record($t, $map[$type] ?? DNS_A);
        if ($recs === false) return ['ok'=>false,'error'=>'Lookup failed (no resolver answer)'];
        $out = [];
        foreach ($recs as $r) {
            $rt = $r['type'] ?? $type;
            if ($rt === 'MX')        $val = (isset($r['pri'])?$r['pri'].' ':'').($r['target'] ?? '');
            elseif ($rt === 'SOA')   $val = ($r['mname'] ?? '').' '.($r['rname'] ?? '').' serial '.($r['serial'] ?? '');
            elseif ($rt === 'TXT')   $val = $r['txt'] ?? '';
            elseif ($rt === 'AAAA')  $val = $r['ipv6'] ?? '';
            elseif ($rt === 'A')     $val = $r['ip'] ?? '';
            else                     $val = $r['target'] ?? ($r['ip'] ?? ($r['ipv6'] ?? ''));
            $out[] = ['type'=>$rt,'value'=>(string)$val,'ttl'=>$r['ttl'] ?? null,'host'=>$r['host'] ?? $t];
        }
        return ['ok'=>true,'target'=>$t,'type'=>$type,'records'=>$out];
    }

    function nm_nt_netstat(): array {
        $conns = [];
        foreach (['tcp'=>['/proc/net/tcp',false],'tcp6'=>['/proc/net/tcp6',true],
                  'udp'=>['/proc/net/udp',false],'udp6'=>['/proc/net/udp6',true]] as $proto=>$spec) {
            $lines = @file($spec[0]); if (!$lines) continue;
            foreach (array_slice($lines, 1) as $ln) {
                $c = preg_split('/\s+/', trim($ln));
                if (count($c) < 4) continue;
                [$la,$lp] = _nm_nt_hexaddr($c[1], $spec[1]);
                [$ra,$rp] = _nm_nt_hexaddr($c[2], $spec[1]);
                $st = _nm_nt_state(hexdec($c[3]));
                if (strpos($proto,'udp')===0 && $st !== 'ESTABLISHED' && $rp === 0) $st = 'OPEN';
                $conns[] = ['proto'=>$proto,'laddr'=>$la,'lport'=>$lp,'raddr'=>$ra,'rport'=>$rp,'state'=>$st];
            }
        }
        return $conns;
    }
    // Aggregate for the UI: by state, and remote-peer edges (drop loopback/listen).
    function nm_nt_netstat_summary(): array {
        return nm_nt_aggregate(nm_nt_netstat());
    }
    // Aggregate a raw connection list (local OR remote) into the UI shape.
    function nm_nt_aggregate(array $all): array {
        $byState = []; $edges = []; $listen = [];
        foreach ($all as $c) {
            $byState[$c['state']] = ($byState[$c['state']] ?? 0) + 1;
            if ($c['state'] === 'LISTEN' || ($c['state']==='OPEN' && $c['raddr']==='0.0.0.0')) {
                $listen[] = ['proto'=>$c['proto'],'port'=>$c['lport']];
                continue;
            }
            $r = $c['raddr'];
            if ($r === '0.0.0.0' || $r === '::' || strpos($r,'127.')===0 || $r==='::1' || $r==='?') continue;
            $key = $r.'|'.$c['rport'];
            if (!isset($edges[$key])) $edges[$key] = ['raddr'=>$r,'rport'=>$c['rport'],'proto'=>$c['proto'],'count'=>0,'states'=>[]];
            $edges[$key]['count']++;
            $edges[$key]['states'][$c['state']] = true;
        }
        // unique listening ports
        $lp = []; foreach ($listen as $l) $lp[$l['proto'].'/'.$l['port']] = $l;
        $edges = array_values($edges);
        foreach ($edges as &$e) $e['states'] = implode(',', array_keys($e['states']));
        usort($edges, fn($a,$b)=>$b['count']<=>$a['count']);
        return ['total'=>count($all),'by_state'=>$byState,'listen'=>array_values($lp),'edges'=>$edges];
    }

    // ── Remote netstat over SSH (real Windows/Linux servers) ───────────────────
    // Reuses the agentless host modules: Linux runs `ss -tuna`, Windows runs
    // Get-NetTCPConnection/Get-NetUDPEndpoint (PowerShell) — both parsed into the
    // SAME connection shape as the local /proc reader, then aggregated identically.
    function _nm_nt_split_addr(string $ap): array {
        // "1.2.3.4:443" | "[::1]:22" | "[::]:*" | "*:*" → [addr, port]
        $ap = trim($ap);
        if ($ap === '') return ['?', 0];
        if ($ap[0] === '[') {                                  // bracketed IPv6
            $rb = strrpos($ap, ']');
            $addr = substr($ap, 1, $rb - 1);
            $port = ltrim(substr($ap, $rb + 1), ':');
        } else {
            $p = strrpos($ap, ':');
            if ($p === false) return [$ap, 0];
            $addr = substr($ap, 0, $p);
            $port = substr($ap, $p + 1);
        }
        if ($addr === '' || $addr === '*') $addr = '0.0.0.0';
        $port = ($port === '*' || $port === '') ? 0 : (int)$port;
        return [$addr, $port];
    }
    function _nm_nt_norm_state(string $s): string {
        $s = strtoupper(trim($s));
        $map = ['ESTAB'=>'ESTABLISHED','ESTABLISHED'=>'ESTABLISHED','LISTEN'=>'LISTEN','LISTENING'=>'LISTEN',
                'TIME-WAIT'=>'TIME_WAIT','TIME_WAIT'=>'TIME_WAIT','TIMEWAIT'=>'TIME_WAIT',
                'CLOSE-WAIT'=>'CLOSE_WAIT','CLOSE_WAIT'=>'CLOSE_WAIT','CLOSEWAIT'=>'CLOSE_WAIT',
                'SYN-SENT'=>'SYN_SENT','SYN-RECV'=>'SYN_RECV','FIN-WAIT-1'=>'FIN_WAIT','FIN-WAIT-2'=>'FIN_WAIT',
                'UNCONN'=>'OPEN','BOUND'=>'OPEN','OPEN'=>'OPEN'];
        return $map[$s] ?? $s;
    }
    // Parse Linux `ss -tuna` text → conn rows.
    function _nm_nt_parse_ss(string $txt): array {
        $rows = [];
        foreach (preg_split('/\r?\n/', $txt) as $ln) {
            $ln = trim($ln); if ($ln === '') continue;
            $f = preg_split('/\s+/', $ln);
            if (count($f) < 5) continue;
            if (strcasecmp($f[0], 'Netid') === 0 || strcasecmp($f[1], 'State') === 0) continue;  // header
            $proto = strtolower($f[0]);                          // tcp | udp
            $state = _nm_nt_norm_state($f[1]);
            // local & peer are the LAST two address columns (robust against extra cols)
            $peer  = array_pop($f);
            $local = array_pop($f);
            [$la, $lp] = _nm_nt_split_addr($local);
            [$ra, $rp] = _nm_nt_split_addr($peer);
            if (strpos($proto,'udp')===0 && $state!=='ESTABLISHED' && $rp===0) $state='OPEN';
            $rows[] = ['proto'=>$proto,'laddr'=>$la,'lport'=>$lp,'raddr'=>$ra,'rport'=>$rp,'state'=>$state];
        }
        return $rows;
    }
    // Parse Windows Get-NetTCPConnection/Get-NetUDPEndpoint JSON → conn rows.
    function _nm_nt_parse_win(string $json): array {
        $json = trim($json);
        // Strip any banner/prompt lines the Windows SSH shell may prepend before the JSON
        // (consistent with nm_win_parse_events — a stray line otherwise breaks json_decode).
        $p = strpos($json, '{'); $b = strpos($json, '[');
        $s = ($p === false) ? $b : (($b === false) ? $p : min($p, $b));
        if ($s !== false && $s > 0) $json = substr($json, $s);
        $d = json_decode($json, true);
        if (!is_array($d)) return [];
        $rows = [];
        foreach (['tcp','udp'] as $proto) {
            $list = $d[$proto] ?? [];
            if (isset($list['lp']) || isset($list['la'])) $list = [$list];   // single object → wrap
            foreach ((array)$list as $c) {
                if (!is_array($c)) continue;
                $rows[] = [
                    'proto'=>$proto,
                    'laddr'=>(string)($c['la'] ?? '0.0.0.0'),'lport'=>(int)($c['lp'] ?? 0),
                    'raddr'=>(string)($c['ra'] ?? '0.0.0.0'),'rport'=>(int)($c['rp'] ?? 0),
                    'state'=>_nm_nt_norm_state((string)($c['st'] ?? ($proto==='udp'?'OPEN':''))),
                ];
            }
        }
        return $rows;
    }
    // Main entry: target = 'win:<host_id>' | 'lx:<host_id>'. Returns summary + meta or error.
    function nm_nt_netstat_remote($conn, string $target): array {
        if (preg_match('/^lx:(\d+)$/', $target, $m)) {
            require_once __DIR__ . '/nm_linuxhost.php';
            $h = nm_lx_host($conn, (int)$m[1]);
            if (!$h) return ['ok'=>false,'error'=>'Unknown Linux host'];
            $ssh = nm_lx_resolve_ssh($conn, $h);
            if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'No SSH credential resolved for this host'];
            $res = nm_lx_sh($ssh, 'ss -tuna 2>/dev/null || netstat -tuna 2>/dev/null', 25);
            if (empty($res['ok'])) return ['ok'=>false,'error'=>'SSH failed: '.substr((string)($res['error']??''),0,180),'down'=>true];
            $all = _nm_nt_parse_ss((string)$res['config']);
            return ['ok'=>true,'host'=>$h['name'],'kind'=>'linux','ip'=>$h['host_ip']] + nm_nt_aggregate($all);
        }
        if (preg_match('/^win:(\d+)$/', $target, $m)) {
            require_once __DIR__ . '/nm_winhost.php';
            $h = nm_win_host($conn, (int)$m[1]);
            if (!$h) return ['ok'=>false,'error'=>'Unknown Windows host'];
            $ssh = nm_win_resolve_ssh($conn, $h);
            if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'No SSH credential resolved for this host'];
            // The whole script is wrapped in cmd double-quotes (powershell -Command "..."), so it MUST
            // use SINGLE quotes internally — double quotes here collide with the wrapper and the command
            // silently fails (this is exactly why Windows netstat was returning nothing). Mirrors
            // _nm_win_events_ps, which uses single quotes for the same reason.
            $ps = '$ErrorActionPreference=\'SilentlyContinue\';'
                . '$t=Get-NetTCPConnection|ForEach-Object{[pscustomobject]@{p=\'tcp\';la=[string]$_.LocalAddress;lp=$_.LocalPort;ra=[string]$_.RemoteAddress;rp=$_.RemotePort;st=[string]$_.State}};'
                . '$u=Get-NetUDPEndpoint|ForEach-Object{[pscustomobject]@{p=\'udp\';la=[string]$_.LocalAddress;lp=$_.LocalPort;ra=\'0.0.0.0\';rp=0;st=\'OPEN\'}};'
                . '@{tcp=@($t);udp=@($u)}|ConvertTo-Json -Compress -Depth 4';
            $res = nm_win_ps($ssh, $ps, 45);
            if (empty($res['ok'])) return ['ok'=>false,'error'=>'PowerShell/SSH failed: '.substr((string)($res['error']??''),0,180),'down'=>true];
            $all = _nm_nt_parse_win((string)$res['config']);
            return ['ok'=>true,'host'=>$h['name'],'kind'=>'windows','ip'=>$h['host_ip']] + nm_nt_aggregate($all);
        }
        return ['ok'=>false,'error'=>'Invalid target'];
    }
}
