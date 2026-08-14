<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU Sentinel Engine — non-intrusive, out-of-band threat interception.
// An ORCHESTRATION layer (zero duplication) that stitches together what NEURU
// already does, plus one genuinely new capability: live cyber-threat-intel.
//
//   SPECTRE        — threat-intel feed ingestion → in-DB reputation matrix (NEW)
//   correlation    — match live NetFlow flows against the matrix (reuse nm_netflow_flows)
//   VECTOR-SHIELD  — auto-block bad indicators (REUSE nm_immunity fan-out to Pi-hole/AdGuard/FW)
//   NEURO-ISOLATION— quarantine an infected LOCAL host on its gateway router over SSH
//                    (REUSE nm_cm_ssh_fetch + the IPAM gateway_node_id we already resolve)
//   sensor agents  — the neuru-sentinel container (wire DNS/flow capture) enrols + pulls the
//                    matrix + reports hits (same token/desired/report model as neuru-utilities)
//
// RBAC perm: 'sentinel'. Engine for sentinel.php + cron_sentinel.php + sentinel-agent.py.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_sentinel_ensure')) {

    function nm_sentinel_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;

        // SPECTRE reputation matrix
        $conn->query("CREATE TABLE IF NOT EXISTS nm_sentinel_intel (
            id INT AUTO_INCREMENT PRIMARY KEY,
            indicator VARCHAR(255) NOT NULL,
            kind VARCHAR(8) NOT NULL DEFAULT 'ip',      -- ip | domain | cidr
            ip_bin VARBINARY(16) DEFAULT NULL,
            source VARCHAR(32) NOT NULL DEFAULT 'feed',
            category VARCHAR(32) DEFAULT 'malware',
            confidence TINYINT DEFAULT 80,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen  DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_ind (indicator, kind),
            KEY idx_kind (kind), KEY idx_ipbin (ip_bin), KEY idx_seen (last_seen)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Confirmed threat hits (a local host talked to / resolved a bad indicator)
        $conn->query("CREATE TABLE IF NOT EXISTS nm_sentinel_hits (
            id INT AUTO_INCREMENT PRIMARY KEY,
            local_ip VARCHAR(45) DEFAULT NULL,
            remote_indicator VARCHAR(255) NOT NULL,
            kind VARCHAR(8) NOT NULL DEFAULT 'ip',
            module VARCHAR(16) NOT NULL DEFAULT 'spectre',   -- spectre | pulse | vector
            category VARCHAR(32) DEFAULT 'malware',
            source VARCHAR(32) DEFAULT 'netflow',
            detail VARCHAR(255) DEFAULT NULL,
            action VARCHAR(16) DEFAULT 'alert',              -- alert | blocked | quarantined
            node_id INT DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            KEY idx_time (created_at), KEY idx_local (local_ip)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // NEURO-ISOLATION quarantine ledger
        $conn->query("CREATE TABLE IF NOT EXISTS nm_sentinel_quarantine (
            id INT AUTO_INCREMENT PRIMARY KEY,
            local_ip VARCHAR(45) NOT NULL,
            mac VARCHAR(17) DEFAULT NULL,
            gateway_node_id INT DEFAULT NULL,
            method VARCHAR(16) DEFAULT 'address-list',
            reason VARCHAR(255) DEFAULT NULL,
            state VARCHAR(12) NOT NULL DEFAULT 'active',      -- active | released | failed
            by_uid INT DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            released_at DATETIME DEFAULT NULL,
            UNIQUE KEY uk_ip (local_ip)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Sensor agents (the neuru-sentinel containers) — same shape as nm_util_nodes
        $conn->query("CREATE TABLE IF NOT EXISTS nm_sentinel_nodes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            uid VARCHAR(64) NOT NULL,
            name VARCHAR(120) NOT NULL,
            ip_address VARCHAR(64) DEFAULT NULL,
            arch VARCHAR(16) DEFAULT NULL,
            agent_version VARCHAR(32) DEFAULT NULL,
            status VARCHAR(12) NOT NULL DEFAULT 'new',
            seen_dns BIGINT DEFAULT 0,
            seen_flows BIGINT DEFAULT 0,
            neutralized BIGINT DEFAULT 0,
            last_seen DATETIME DEFAULT NULL,
            enrolled_by INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_uid (uid)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','sentinel',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='sentinel')");
    }

    // ── Settings (modules on/off, auto-response) ───────────────────────────────
    function nm_sentinel_cfg($conn): array {
        nm_sentinel_ensure($conn);
        $d = ['enabled'=>'1','spectre'=>'1','vector'=>'1','pulse'=>'0','auto_block'=>'1','auto_isolate'=>'0',
              'sinkhole'=>'immunity','feeds_feodo'=>'1','feeds_urlhaus'=>'1'];
        $r = $conn->query("SELECT setting_key,setting_val FROM nm_settings WHERE setting_key LIKE 'sentinel_%'");
        while ($r && ($x=$r->fetch_assoc())) $d[substr($x['setting_key'],9)] = $x['setting_val'];
        return $d;
    }
    function nm_sentinel_cfg_set($conn, string $k, string $v): void {
        $key = 'sentinel_'.preg_replace('/[^a-z0-9_]/','',$k);
        $st = $conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
        $st->bind_param('ss',$key,$v); $st->execute(); $st->close();
    }

    // ── SPECTRE: threat-intel feed ingestion (free, no API key) ────────────────
    function nm_sentinel_fetch(string $url, int $timeout=20): ?string {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>$timeout, CURLOPT_FOLLOWLOCATION=>true,
            CURLOPT_USERAGENT=>'NEURU-Sentinel/1.0', CURLOPT_SSL_VERIFYPEER=>true]);
        $out = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
        return ($out !== false && $code >= 200 && $code < 400) ? $out : null;
    }
    function nm_sentinel_intel_add($conn, string $indicator, string $kind, string $source, string $category='malware', int $conf=80): bool {
        $indicator = trim($indicator); if ($indicator==='') return false;
        $bin = ($kind==='ip' && filter_var($indicator,FILTER_VALIDATE_IP)) ? inet_pton($indicator) : null;
        $st = $conn->prepare("INSERT INTO nm_sentinel_intel (indicator,kind,ip_bin,source,category,confidence,first_seen,last_seen)
            VALUES (?,?,?,?,?,?,NOW(),NOW()) ON DUPLICATE KEY UPDATE source=VALUES(source),category=VALUES(category),confidence=VALUES(confidence),last_seen=NOW()");
        $st->bind_param('sssssi',$indicator,$kind,$bin,$source,$category,$conf); $st->execute(); $n=$st->affected_rows; $st->close();
        return $n > 0;
    }
    function nm_sentinel_refresh_feeds($conn): array {
        nm_sentinel_ensure($conn);
        $cfg = nm_sentinel_cfg($conn);
        $added = ['feodo'=>0,'urlhaus'=>0]; $prune = 0;
        // Feodo Tracker — C2 server IPs (ransomware/botnet)
        if ($cfg['feeds_feodo'] !== '0') {
            $txt = nm_sentinel_fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.txt');
            if ($txt !== null) foreach (preg_split('/\r?\n/',$txt) as $ln) {
                $ln = trim($ln); if ($ln==='' || $ln[0]==='#') continue;
                if (filter_var($ln,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4) && nm_sentinel_intel_add($conn,$ln,'ip','feodo','c2',95)) $added['feodo']++;
            }
        }
        // URLhaus — active malware distribution hostnames. CRITICAL false-positive guard:
        // malware is often HOSTED on shared platforms (github, cloudflare, CDNs, pastebin…),
        // so the DOMAIN isn't malicious — only the specific URL. Reuse Collective Immunity's
        // safe-domain allowlist so we never flag/block a legit platform (that would break the LAN).
        if ($cfg['feeds_urlhaus'] !== '0') {
            require_once __DIR__.'/nm_immunity.php';
            $txt = nm_sentinel_fetch('https://urlhaus.abuse.ch/downloads/text_online/');
            if ($txt !== null) { $seen=[]; foreach (preg_split('/\r?\n/',$txt) as $ln) {
                $ln = trim($ln); if ($ln==='' || $ln[0]==='#') continue;
                $host = parse_url($ln, PHP_URL_HOST); if (!$host || isset($seen[$host])) continue; $seen[$host]=1;
                if (filter_var($host,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)) { if (nm_sentinel_intel_add($conn,$host,'ip','urlhaus','malware',85)) $added['urlhaus']++; }
                else if (preg_match('/^[a-z0-9.\-]+\.[a-z]{2,}$/i',$host)) {
                    if (function_exists('nm_imm_is_safe_domain') && nm_imm_is_safe_domain($conn,$host)) continue;   // skip CDNs/platforms
                    if (nm_sentinel_intel_add($conn,strtolower($host),'domain','urlhaus','malware',85)) $added['urlhaus']++;
                }
            } }
        }
        // prune stale indicators (feeds rotate) — keep 14 days
        try { $conn->query("DELETE FROM nm_sentinel_intel WHERE last_seen < (NOW() - INTERVAL 14 DAY)"); $prune = $conn->affected_rows; } catch (\Throwable $e) {}
        nm_sentinel_cfg_set($conn, 'feeds_last', (string)time());   // stamp so the UI shows a fresh "updated" time (manual + cron)
        return ['ok'=>true,'added'=>$added,'pruned'=>$prune,'matrix'=>(int)($conn->query("SELECT COUNT(*) FROM nm_sentinel_intel")->fetch_row()[0] ?? 0)];
    }

    // ── Matching ───────────────────────────────────────────────────────────────
    function nm_sentinel_match_ip($conn, string $ip): ?array {
        if (!filter_var($ip,FILTER_VALIDATE_IP)) return null;
        $bin = inet_pton($ip);
        $st = $conn->prepare("SELECT indicator,source,category,confidence FROM nm_sentinel_intel WHERE kind='ip' AND ip_bin=? LIMIT 1");
        $st->bind_param('s',$bin); $st->execute(); $r=$st->get_result()->fetch_assoc(); $st->close();
        return $r ?: null;
    }
    function nm_sentinel_match_domain($conn, string $d): ?array {
        $d = strtolower(trim($d)); if ($d==='') return null;
        // exact + parent-domain match (sub.bad.com matches bad.com)
        $parts = explode('.', $d); $cands = [];
        for ($i=0; $i<count($parts)-1; $i++) $cands[] = implode('.', array_slice($parts,$i));
        if (!$cands) return null;
        $in = implode(',', array_fill(0,count($cands),'?'));
        $st = $conn->prepare("SELECT indicator,source,category,confidence FROM nm_sentinel_intel WHERE kind='domain' AND indicator IN ($in) LIMIT 1");
        $st->bind_param(str_repeat('s',count($cands)), ...$cands); $st->execute(); $r=$st->get_result()->fetch_assoc(); $st->close();
        return $r ?: null;
    }

    // ── VECTOR-SHIELD: block a bad indicator by feeding the Collective Immunity
    //    fan-out (Pi-hole / AdGuard / firewalls) — NO duplication of that machinery. ─
    function nm_sentinel_block($conn, string $indicator, string $kind, string $detail, ?int $uid=null): bool {
        if (!function_exists('nm_imm_add_threat')) { require_once __DIR__.'/nm_immunity.php'; }
        if (!function_exists('nm_imm_add_threat')) return false;
        $type = $kind==='ip' ? 'ip' : 'domain';
        $r = nm_imm_add_threat($conn, $indicator, $type, 'sentinel', 'high', $detail, $uid, 'SPECTRE');
        if (!empty($r['ok']) && !empty($r['id']) && function_exists('nm_imm_vaccinate')) { try { nm_imm_vaccinate($conn, (int)$r['id'], false); } catch (\Throwable $e) {} }
        return !empty($r['ok']);
    }

    // ── NEURO-ISOLATION: quarantine an infected LOCAL host on its gateway router.
    //    Uses the IPAM gateway_node_id (the router that owns the host's subnet) → SSH →
    //    drop-address-list. Reuses nm_cm_ssh_fetch + nm_ssh_resolve (no new SSH plumbing). ─
    function nm_sentinel_host_gateway($conn, string $ip): array {
        // find the subnet that contains $ip → its gateway_node_id (from the IPAM sweep work)
        if (!$conn->query("SHOW TABLES LIKE 'nm_ipam_subnets'")->num_rows) return ['node_id'=>null];
        require_once __DIR__.'/nm_ipam.php';
        $best = null;
        foreach ($conn->query("SELECT id,cidr,gateway_node_id FROM nm_ipam_subnets WHERE gateway_node_id IS NOT NULL") as $s) {
            $p = nm_ipam_parse_cidr($s['cidr']); if ($p && nm_ipam_in_subnet($ip,$p)) { $best = (int)$s['gateway_node_id']; break; }
        }
        return ['node_id'=>$best];
    }
    function nm_sentinel_quarantine($conn, string $ip, string $reason='', ?int $uid=null): array {
        nm_sentinel_ensure($conn);
        if (!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)) return ['ok'=>false,'error'=>'bad ip'];
        require_once __DIR__.'/nm_secrets.php'; require_once __DIR__.'/nm_confmgr.php'; require_once __DIR__.'/nm_nodemeta.php';
        $gw = nm_sentinel_host_gateway($conn, $ip); $nid = $gw['node_id'];
        if (!$nid) return ['ok'=>false,'error'=>'no managed gateway found for this host\'s subnet'];
        $ssh = nm_ssh_resolve($conn, $nid); if (!$ssh) return ['ok'=>false,'error'=>'gateway has no SSH credential'];
        $nr = $conn->query("SELECT display_name,os_icon FROM nm_nodes WHERE id=".(int)$nid." LIMIT 1"); $node = $nr?$nr->fetch_assoc():[];
        $os = strtolower((string)($node['os_icon'] ?? ''));
        $ok=false;
        if (strpos($os,'mikrotik')!==false || strpos($os,'routeros')!==false) {
            // MikroTik: drop-list + a forward drop rule (idempotent). Anti-lockout: never touches mgmt.
            $cmd = '/ip firewall address-list add list=NEURU-QUARANTINE address='.$ip.' comment="NEURU Sentinel" ; '
                 . ':if ([:len [/ip firewall filter find where comment="NEURU-QUARANTINE"]] = 0) do={ /ip firewall filter add chain=forward src-address-list=NEURU-QUARANTINE action=drop comment="NEURU-QUARANTINE" place-before=0 } ; :put "NM_OK"';
            $r = nm_cm_ssh_fetch($ssh, $cmd, 20); $ok = !empty($r['ok']);
        } else {
            return ['ok'=>false,'error'=>'quarantine not yet supported for this gateway vendor ('.$os.')'];
        }
        if (!$ok) return ['ok'=>false,'error'=>'SSH quarantine command failed'];
        $st = $conn->prepare("INSERT INTO nm_sentinel_quarantine (local_ip,gateway_node_id,reason,state,by_uid)
            VALUES (?,?,?, 'active', ?) ON DUPLICATE KEY UPDATE gateway_node_id=VALUES(gateway_node_id),reason=VALUES(reason),state='active',released_at=NULL,created_at=NOW(),by_uid=VALUES(by_uid)");
        $rs = substr($reason,0,255); $st->bind_param('sisi',$ip,$nid,$rs,$uid); $st->execute(); $st->close();
        if (function_exists('nm_audit')) { try { nm_audit($conn,'sentinel.quarantine',['target_type'=>'host','target_id'=>$ip]); } catch (\Throwable $e) {} }
        if (function_exists('nm_notify_process')) { /* alerting reuses the standard pipeline elsewhere */ }
        return ['ok'=>true,'gateway'=>$node['display_name'] ?? '','ip'=>$ip];
    }
    function nm_sentinel_release($conn, string $ip, ?int $uid=null): array {
        nm_sentinel_ensure($conn);
        $r = $conn->query("SELECT gateway_node_id FROM nm_sentinel_quarantine WHERE local_ip='".$conn->real_escape_string($ip)."' AND state='active' LIMIT 1");
        $row = $r?$r->fetch_assoc():null; if (!$row) return ['ok'=>false,'error'=>'not quarantined'];
        require_once __DIR__.'/nm_secrets.php'; require_once __DIR__.'/nm_confmgr.php';
        $ssh = nm_ssh_resolve($conn, (int)$row['gateway_node_id']);
        if ($ssh) { nm_cm_ssh_fetch($ssh, '/ip firewall address-list remove [find list=NEURU-QUARANTINE address='.$ip.'] ; :put "NM_OK"', 20); }
        $conn->query("UPDATE nm_sentinel_quarantine SET state='released', released_at=NOW() WHERE local_ip='".$conn->real_escape_string($ip)."'");
        if (function_exists('nm_audit')) { try { nm_audit($conn,'sentinel.release',['target_type'=>'host','target_id'=>$ip]); } catch (\Throwable $e) {} }
        return ['ok'=>true];
    }

    // ── Record a hit + run the configured auto-response ────────────────────────
    function nm_sentinel_hit($conn, array $h): void {
        nm_sentinel_ensure($conn);
        // Belt-and-suspenders false-positive guard: never record/block a hit on an allowlisted
        // platform/CDN domain, even if a stale matrix entry or agent slipped one through.
        if (($h['kind'] ?? 'ip')==='domain') { require_once __DIR__.'/nm_immunity.php';
            if (function_exists('nm_imm_is_safe_domain') && nm_imm_is_safe_domain($conn,(string)$h['remote_indicator'])) return; }
        $cfg = nm_sentinel_cfg($conn);
        $action = 'alert';
        // VECTOR-SHIELD auto-block the bad indicator (Pi-hole/AdGuard/FW via immunity)
        if (($cfg['auto_block'] ?? '1') !== '0' && nm_sentinel_block($conn, $h['remote_indicator'], $h['kind'] ?? 'ip', 'SPECTRE hit from '.($h['local_ip']??'?'))) $action = 'blocked';
        // NEURO-ISOLATION auto-quarantine the infected local host (opt-in)
        if (($cfg['auto_isolate'] ?? '0') === '1' && !empty($h['local_ip'])) {
            $q = nm_sentinel_quarantine($conn, $h['local_ip'], 'auto: talked to '.$h['remote_indicator']);
            if (!empty($q['ok'])) $action = 'quarantined';
        }
        $st = $conn->prepare("INSERT INTO nm_sentinel_hits (local_ip,remote_indicator,kind,module,category,source,detail,action,node_id)
            VALUES (?,?,?,?,?,?,?,?,?)");
        $li=$h['local_ip']??null; $ri=$h['remote_indicator']; $k=$h['kind']??'ip'; $mod=$h['module']??'spectre';
        $cat=$h['category']??'malware'; $src=$h['source']??'netflow'; $det=substr($h['detail']??'',0,255); $nid=$h['node_id']??null;
        $st->bind_param('ssssssssi',$li,$ri,$k,$mod,$cat,$src,$det,$action,$nid); $st->execute(); $st->close();
    }

    // ── Correlate recent NetFlow flows against the matrix (SPECTRE, reuse netflow) ─
    function nm_sentinel_scan_flows($conn, int $winMin=5): array {
        nm_sentinel_ensure($conn);
        if (!$conn->query("SHOW TABLES LIKE 'nm_netflow_flows'")->num_rows) return ['ok'=>true,'hits'=>0,'note'=>'no netflow'];
        // recent distinct external dst IPs talked to by local hosts
        $sql = "SELECT f.src_ip, f.dst_ip FROM nm_netflow_flows f
                JOIN nm_sentinel_intel i ON i.kind='ip' AND i.ip_bin = INET6_ATON(f.dst_ip)
                WHERE f.bucket >= (NOW() - INTERVAL ? MINUTE)
                GROUP BY f.src_ip, f.dst_ip LIMIT 200";
        $hits=0;
        if ($st = $conn->prepare($sql)) {
            $st->bind_param('i',$winMin); $st->execute(); $res=$st->get_result();
            while ($res && ($x=$res->fetch_assoc())) {
                // avoid duplicate hits within the window
                $dup = $conn->query("SELECT 1 FROM nm_sentinel_hits WHERE local_ip='".$conn->real_escape_string($x['src_ip'])."' AND remote_indicator='".$conn->real_escape_string($x['dst_ip'])."' AND created_at > (NOW() - INTERVAL 30 MINUTE) LIMIT 1");
                if ($dup && $dup->num_rows) continue;
                nm_sentinel_hit($conn, ['local_ip'=>$x['src_ip'],'remote_indicator'=>$x['dst_ip'],'kind'=>'ip','module'=>'spectre','source'=>'netflow','detail'=>'NetFlow: '.$x['src_ip'].' → '.$x['dst_ip']]);
                $hits++;
            }
            $st->close();
        }
        return ['ok'=>true,'hits'=>$hits];
    }

    // ── Traffic Mirror: point a router's sniffer stream at a sensor (SSH) ──────
    // MikroTik /tool sniffer streams matching packets (TZSP) to the sensor's IP, so ONE
    // sensor sees the whole network's DNS without a physical SPAN cable. Fully dynamic
    // (by IP) and reversible. Reuses NEURU's existing SSH to the router. MikroTik today;
    // other vendors (Cisco ERSPAN, …) are future.
    function nm_sentinel_mirror_routers($conn): array {
        require_once __DIR__.'/nm_nodemeta.php';
        $out=[]; $r=$conn->query("SELECT id,display_name,ip_address,os_icon FROM nm_nodes WHERE ssh_cred_id IS NOT NULL AND ssh_cred_id<>0 ORDER BY display_name");
        while ($r && ($x=$r->fetch_assoc())) {
            $os=strtolower((string)$x['os_icon']);
            if (strpos($os,'mikrotik')!==false || strpos($os,'routeros')!==false) {
                $st = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='sentinel_mirror_".(int)$x['id']."' LIMIT 1");
                $x['mirror_to'] = $st && ($v=$st->fetch_row()) ? (string)$v[0] : '';
                $ct = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='sentinel_router_container_".(int)$x['id']."' LIMIT 1");
                $x['container_ip'] = $ct && ($v=$ct->fetch_row()) ? (string)$v[0] : '';
                $out[]=$x;
            }
        }
        return $out;
    }
    function nm_sentinel_mirror($conn, int $routerNodeId, string $sensorIp, bool $enable, ?int $uid=null): array {
        nm_sentinel_ensure($conn);
        require_once __DIR__.'/nm_secrets.php'; require_once __DIR__.'/nm_confmgr.php'; require_once __DIR__.'/nm_nodemeta.php';
        $nr=$conn->query("SELECT display_name,os_icon FROM nm_nodes WHERE id=".(int)$routerNodeId." LIMIT 1"); $node=$nr?$nr->fetch_assoc():null;
        if (!$node) return ['ok'=>false,'error'=>'router not found'];
        $os=strtolower((string)$node['os_icon']);
        if (strpos($os,'mikrotik')===false && strpos($os,'routeros')===false) return ['ok'=>false,'error'=>'mirror currently supported on MikroTik only'];
        $ssh=nm_ssh_resolve($conn,$routerNodeId); if (!$ssh) return ['ok'=>false,'error'=>'router has no SSH credential'];
        if ($enable) {
            if (!filter_var($sensorIp,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)) return ['ok'=>false,'error'=>'bad sensor IP'];
            // stream only DNS (udp/53) as TZSP to the sensor — low bandwidth, high value
            $cmd = '/tool sniffer set streaming-enabled=yes streaming-server='.$sensorIp.' filter-stream=yes filter-ip-protocol=udp filter-port=dns ; /tool sniffer start ; :put "NM_OK"';
        } else {
            $cmd = '/tool sniffer stop ; /tool sniffer set streaming-enabled=no ; :put "NM_OK"';
        }
        $r = nm_cm_ssh_fetch($ssh, $cmd, 20);
        if (empty($r['ok'])) return ['ok'=>false,'error'=>'SSH mirror command failed: '.($r['error']??'')];
        nm_sentinel_cfg_set($conn, 'mirror_'.$routerNodeId, $enable ? $sensorIp : '');
        if (function_exists('nm_audit')) { try { nm_audit($conn,'sentinel.mirror',['target_type'=>'node','target_id'=>$routerNodeId,'details'=>['to'=>$enable?$sensorIp:'off']]); } catch (\Throwable $e) {} }
        return ['ok'=>true,'router'=>$node['display_name'],'streaming_to'=>$enable?$sensorIp:null];
    }

    // ── Deploy the sensor AS A CONTAINER on the MikroTik itself (RouterOS 7.4+ /container).
    //    Running on the router is the ultimate vantage point: the router sees ALL forwarded
    //    traffic, and its sniffer streams it to the container locally (near-zero overhead).
    //    Purely ADDITIVE + idempotent — detects the existing container network/storage (so it
    //    works on any RouterOS container setup) and NEVER touches other containers (e.g. Pi-hole). ─
    function nm_sentinel_rtr_ssh($conn, int $routerNodeId): array {
        require_once __DIR__.'/nm_secrets.php'; require_once __DIR__.'/nm_confmgr.php'; require_once __DIR__.'/nm_nodemeta.php';
        $nr=$conn->query("SELECT display_name,os_icon FROM nm_nodes WHERE id=".(int)$routerNodeId." LIMIT 1"); $node=$nr?$nr->fetch_assoc():null;
        if (!$node) return ['ok'=>false,'error'=>'router not found'];
        $os=strtolower((string)$node['os_icon']);
        if (strpos($os,'mikrotik')===false && strpos($os,'routeros')===false) return ['ok'=>false,'error'=>'router-container deploy supported on MikroTik only'];
        $ssh=nm_ssh_resolve($conn,$routerNodeId); if (!$ssh) return ['ok'=>false,'error'=>'router has no SSH credential'];
        return ['ok'=>true,'ssh'=>$ssh,'name'=>$node['display_name']];
    }
    function nm_sentinel_rtr_run($ssh, string $cmd, int $t=25): array {
        $r = nm_cm_ssh_fetch($ssh, $cmd.' ; :put "NM_END"', $t);
        if (empty($r['ok'])) return ['ok'=>false,'out'=>'','err'=>$r['error']??''];
        return ['ok'=>true,'out'=>trim(str_replace('NM_END','',(string)$r['config']))];
    }
    // Inspect what the router offers (container network + storage) — the detection that makes it universal.
    function nm_sentinel_router_probe($conn, int $routerNodeId): array {
        $x = nm_sentinel_rtr_ssh($conn,$routerNodeId); if (empty($x['ok'])) return $x;
        $ssh=$x['ssh'];
        $pkg = nm_sentinel_rtr_run($ssh, '/system/package/print where name~"container"');
        $has_container = stripos($pkg['out'] ?? '', 'container') !== false;
        // existing container veth → borrow its subnet/gateway/bridge
        $veth = nm_sentinel_rtr_run($ssh, ':foreach v in=[/interface/veth/find] do={ :put ([/interface/veth/get $v name].",".[/interface/veth/get $v address].",".[/interface/veth/get $v gateway]) }');
        $subnet=$gw=''; $usedIps=[];
        foreach (preg_split('/\r?\n/',$veth['out'] ?? '') as $ln){ $p=explode(',',$ln); if(count($p)>=3 && strpos($p[1],'/')!==false){ $usedIps[]=explode('/',$p[1])[0]; if(!$subnet){ $subnet=$p[1]; $gw=$p[2]; } } }
        // storage: first mounted disk slot (for root-dir)
        $disk = nm_sentinel_rtr_run($ssh, ':foreach d in=[/disk/find where slot!=""] do={ :put [/disk/get $d slot] }');
        $slots = array_values(array_filter(array_map('trim', preg_split('/\r?\n/',$disk['out'] ?? '')), fn($s)=>$s!=='' && stripos($s,'swap')===false));
        // pick a free IP in the container subnet
        $freeIp='';
        if ($subnet && strpos($subnet,'/')!==false){ [$net,$pfx]=explode('/',$subnet); $base=preg_replace('/\.\d+$/','',$net);
            for($i=11;$i<=250;$i++){ $cand="$base.$i"; if($cand!==$gw && !in_array($cand,$usedIps,true)){ $freeIp=$cand; break; } } }
        // is the sentinel container already there?
        $exists = nm_sentinel_rtr_run($ssh, ':put [:len [/container/find where interface="neuru-sentinel"]]');
        return ['ok'=>true,'router'=>$x['name'],'has_container'=>$has_container,'subnet'=>$subnet,'gateway'=>$gw,
                'free_ip'=>$freeIp,'prefix'=>$subnet?explode('/',$subnet)[1]:'24',
                'storage'=>$slots[0]??'','storage_options'=>array_values($slots),
                'installed'=>trim($exists['out'] ?? '0')!=='0'];
    }
    function nm_sentinel_deploy_router($conn, int $routerNodeId, ?int $uid=null, ?string $storage=null): array {
        @set_time_limit(180);
        $probe = nm_sentinel_router_probe($conn,$routerNodeId); if (empty($probe['ok'])) return $probe;
        if (!$probe['has_container']) return ['ok'=>false,'error'=>'the RouterOS "container" package/device-mode is not enabled on this device'];
        if (!$probe['storage'])      return ['ok'=>false,'error'=>'no mounted storage (USB/NVMe) found for the container root-dir'];
        if (!$probe['free_ip'])      return ['ok'=>false,'error'=>'could not find a container network — set up one container (e.g. Pi-hole) first, or a veth+bridge'];
        // storage: use the operator's choice if it's one of the detected slots, else the default
        $store = ($storage && in_array($storage,$probe['storage_options'],true)) ? $storage : $probe['storage'];
        $x = nm_sentinel_rtr_ssh($conn,$routerNodeId); $ssh=$x['ssh'];
        $ip=$probe['free_ip']; $pfx=$probe['prefix']; $gw=$probe['gateway'];
        // find the bridge the existing container veth is a port of (to attach ours to the same net)
        $br = nm_sentinel_rtr_run($ssh, ':local b ""; :foreach p in=[/interface/bridge/port/find] do={ :local i [/interface/bridge/port/get $p interface]; :if ([/interface/find where name=$i type=veth]!="") do={ :set b [/interface/bridge/port/get $p bridge] } }; :put $b');
        $bridge = trim($br['out'] ?? ''); if ($bridge==='') $bridge='br-docker';
        // NEURU endpoint + token for the container envs
        require_once __DIR__.'/nm_agent.php';
        $scheme=(!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off')?'https':'http';
        $host=$_SERVER['HTTP_HOST'] ?? 'YOUR-NEURU-HOST'; $url=$scheme.'://'.$host;
        $tok=nm_sentinel_token_ensure($conn);
        $vtls=(function_exists('nm_agent_selfsigned_likely') && nm_agent_selfsigned_likely($scheme,$host))?'0':'1';
        $log=[];
        $step=function($cmd,$label) use($ssh,&$log){ $r=nm_sentinel_rtr_run($ssh,$cmd,60); $log[]=$label.': '.($r['ok']?'ok':('ERR '.($r['err']??''))); return $r; };
        // 1) veth (idempotent) + attach to the container bridge
        $step('/interface/veth/add name=neuru-sentinel address='.$ip.'/'.$pfx.' gateway='.$gw, 'create veth');
        $step('/interface/bridge/port/add bridge='.$bridge.' interface=neuru-sentinel', 'attach veth to '.$bridge);
        // 2) NAT so the container can reach NEURU (mirror existing container connectivity; idempotent by comment)
        $step(':if ([:len [/ip/firewall/nat/find comment="neuru-container-nat"]]=0) do={ /ip/firewall/nat/add chain=srcnat action=masquerade src-address='.$ip.' comment="neuru-container-nat" }', 'nat');
        // 3) envs
        $step('/container/envs/remove [find where list=neuru-sentinel]', 'clear envs');
        $step('/container/envs/add list=neuru-sentinel key=NEURU_URL value="'.$url.'"', 'env NEURU_URL');
        $step('/container/envs/add list=neuru-sentinel key=SENTINEL_TOKEN value="'.$tok.'"', 'env TOKEN');
        $step('/container/envs/add list=neuru-sentinel key=VERIFY_TLS value="'.$vtls.'"', 'env VERIFY_TLS');
        $step('/container/envs/add list=neuru-sentinel key=POLL_SECONDS value="60"', 'env POLL');   // fast threat response
        // 4) add the container (skip if already present) + start
        if (!$probe['installed']) {
            $step('/container/add remote-image=ghcr.io/hmiranda14/neuru-sentinel:latest interface=neuru-sentinel root-dir='.$store.'/neuru-sentinel envlist=neuru-sentinel start-on-boot=yes logging=yes', 'add container (pulling image…)');
        } else { $log[]='container: already present (reusing)'; }
        $step('/container/start [find where interface=neuru-sentinel]', 'start container');
        // 5) point the router sniffer (DNS) at the local container → it sees ALL forwarded DNS
        nm_sentinel_mirror($conn, $routerNodeId, $ip, true, $uid);
        $log[]='mirror: router DNS → '.$ip;
        nm_sentinel_cfg_set($conn, 'router_container_'.$routerNodeId, $ip);
        if (function_exists('nm_audit')) { try { nm_audit($conn,'sentinel.deploy_router',['target_type'=>'node','target_id'=>$routerNodeId]); } catch (\Throwable $e) {} }
        return ['ok'=>true,'router'=>$probe['router'],'container_ip'=>$ip,'bridge'=>$bridge,'storage'=>$store,'log'=>$log,
                'note'=>'Image is pulling on the router (~1-2 min). It will enrol + appear under Sensor agents.'];
    }
    function nm_sentinel_remove_router_container($conn, int $routerNodeId, ?int $uid=null): array {
        $x = nm_sentinel_rtr_ssh($conn,$routerNodeId); if (empty($x['ok'])) return $x; $ssh=$x['ssh'];
        nm_sentinel_mirror($conn,$routerNodeId,'',false,$uid);
        nm_sentinel_rtr_run($ssh, '/container/stop [find where interface=neuru-sentinel] ; :delay 2s ; /container/remove [find where interface=neuru-sentinel]', 60);
        nm_sentinel_rtr_run($ssh, '/interface/bridge/port/remove [find where interface=neuru-sentinel] ; /interface/veth/remove [find where name=neuru-sentinel] ; /container/envs/remove [find where list=neuru-sentinel] ; /ip/firewall/nat/remove [find where comment="neuru-container-nat"]', 30);
        nm_sentinel_cfg_set($conn,'router_container_'.$routerNodeId,'');
        return ['ok'=>true];
    }

    // ── Sensor-agent enrolment / desired-state / report (neuru-utilities model) ──
    function nm_sentinel_token($conn): string {
        try { $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='sentinel_token' LIMIT 1"); if ($r && ($x=$r->fetch_assoc())) return (string)$x['setting_val']; } catch (\Throwable $e) {}
        return '';
    }
    function nm_sentinel_token_ensure($conn): string { $t=nm_sentinel_token($conn); return $t!==''?$t:nm_sentinel_token_rotate($conn); }
    function nm_sentinel_token_rotate($conn): string {
        $tok='neu_snt_'.bin2hex(random_bytes(24));
        try { $st=$conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES('sentinel_token',?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)"); $st->bind_param('s',$tok); $st->execute(); $st->close(); } catch (\Throwable $e) { return ''; }
        return $tok;
    }
    function nm_sentinel_verify($conn, ?string $p): bool { $p=(string)$p; $s=nm_sentinel_token($conn); return $p!=='' && $s!=='' && hash_equals($s,$p); }
    function nm_sentinel_register($conn, string $uid, string $host, array $meta=[]): array {
        nm_sentinel_ensure($conn);
        $uid=substr(preg_replace('/[^A-Za-z0-9._:-]/','',$uid),0,64); if ($uid==='') return ['ok'=>false,'error'=>'missing uid'];
        $name=substr(trim($host!==''?$host:$uid),0,120);
        $ip=substr(preg_replace('/[^0-9a-fA-F.:]/','',(string)($meta['ip']??'')),0,64) ?: null;
        $arch=substr((string)($meta['arch']??''),0,16) ?: null; $ver=substr((string)($meta['agent_version']??''),0,32) ?: null;
        $eby=isset($meta['enrolled_by'])?(int)$meta['enrolled_by']:null;
        $st=$conn->prepare("INSERT INTO nm_sentinel_nodes (uid,name,ip_address,arch,agent_version,status,last_seen,enrolled_by)
            VALUES (?,?,?,?,?, 'online', NOW(), ?) ON DUPLICATE KEY UPDATE name=VALUES(name),ip_address=VALUES(ip_address),arch=VALUES(arch),agent_version=VALUES(agent_version),status='online',last_seen=NOW()");
        $st->bind_param('sssssi',$uid,$name,$ip,$arch,$ver,$eby); $st->execute(); $st->close();
        $nid=0; $q=$conn->prepare("SELECT id FROM nm_sentinel_nodes WHERE uid=? LIMIT 1"); $q->bind_param('s',$uid); $q->execute();
        if ($row=$q->get_result()->fetch_assoc()) $nid=(int)$row['id']; $q->close();
        return ['ok'=>true,'node_id'=>$nid];
    }
    // Desired-state + the compact reputation matrix the agent matches against.
    function nm_sentinel_desired($conn, array $meta=[]): array {
        nm_sentinel_ensure($conn); $cfg=nm_sentinel_cfg($conn);
        $ips=[]; $doms=[];
        $r=$conn->query("SELECT indicator,kind FROM nm_sentinel_intel ORDER BY last_seen DESC LIMIT 50000");
        while ($r && ($x=$r->fetch_assoc())) { if ($x['kind']==='ip') $ips[]=$x['indicator']; elseif ($x['kind']==='domain') $doms[]=$x['indicator']; }
        return ['ok'=>true,'modules'=>['spectre'=>$cfg['spectre'],'vector'=>$cfg['vector'],'pulse'=>$cfg['pulse']],
                'sinkhole'=>$cfg['sinkhole'],'auto_isolate'=>$cfg['auto_isolate'],
                // rev = MAX(id)+COUNT so it changes on BOTH adds AND deletes (a pure MAX(id) wouldn't
                // drop when we prune a false positive → the agent would keep a stale matrix).
                'matrix_rev'=>(int)($conn->query("SELECT COALESCE(MAX(id),0)+COUNT(*) FROM nm_sentinel_intel")->fetch_row()[0] ?? 0),
                'ips'=>$ips,'domains'=>$doms];
    }
    // Agent reports DNS/flow hits it saw on the wire.
    function nm_sentinel_report($conn, int $node_id, array $p): array {
        nm_sentinel_ensure($conn);
        $conn->query("UPDATE nm_sentinel_nodes SET status='online',last_seen=NOW(),seen_dns=seen_dns+".(int)($p['seen_dns']??0).",seen_flows=seen_flows+".(int)($p['seen_flows']??0)." WHERE id=".(int)$node_id);
        $n=0;
        foreach (array_slice($p['hits'] ?? [], 0, 500) as $h) {
            $ind = trim((string)($h['indicator'] ?? '')); if ($ind==='') continue;
            $kind = ($h['kind'] ?? 'ip')==='domain'?'domain':'ip';
            nm_sentinel_hit($conn, ['local_ip'=>substr((string)($h['local_ip']??''),0,45) ?: null,'remote_indicator'=>substr($ind,0,255),
                'kind'=>$kind,'module'=>substr((string)($h['module']??'spectre'),0,16),'source'=>'sensor','detail'=>substr((string)($h['detail']??''),0,255),'node_id'=>$node_id]);
            $n++;
        }
        if ($n) $conn->query("UPDATE nm_sentinel_nodes SET neutralized=neutralized+".$n." WHERE id=".(int)$node_id);
        return ['ok'=>true,'recorded'=>$n];
    }

    // ── Read helpers for the HUD ───────────────────────────────────────────────
    function nm_sentinel_stats($conn): array {
        nm_sentinel_ensure($conn);
        $one = fn($q)=> (int)($conn->query($q)->fetch_row()[0] ?? 0);
        return [
            'matrix'      => $one("SELECT COUNT(*) FROM nm_sentinel_intel"),
            'matrix_ip'   => $one("SELECT COUNT(*) FROM nm_sentinel_intel WHERE kind='ip'"),
            'matrix_dom'  => $one("SELECT COUNT(*) FROM nm_sentinel_intel WHERE kind='domain'"),
            'hits_24h'    => $one("SELECT COUNT(*) FROM nm_sentinel_hits WHERE created_at > (NOW()-INTERVAL 24 HOUR)"),
            'neutralized' => $one("SELECT COUNT(*) FROM nm_sentinel_hits WHERE action IN ('blocked','quarantined')"),
            'quarantined' => $one("SELECT COUNT(*) FROM nm_sentinel_quarantine WHERE state='active'"),
            'sensors'     => $one("SELECT COUNT(*) FROM nm_sentinel_nodes"),
            'sensors_on'  => $one("SELECT COUNT(*) FROM nm_sentinel_nodes WHERE last_seen > (NOW()-INTERVAL 3 MINUTE)"),
            'feed_age'    => (function() use($conn){ $r=$conn->query("SELECT TIMESTAMPDIFF(MINUTE,MAX(last_seen),NOW()) FROM nm_sentinel_intel"); $v=$r?$r->fetch_row()[0]:null; return $v===null?null:(int)$v; })(),
            // total traffic the sensors have SCANNED (DNS + flows) vs what was DETECTED (hits)
            'scanned'     => (int)($conn->query("SELECT COALESCE(SUM(seen_dns+seen_flows),0) FROM nm_sentinel_nodes")->fetch_row()[0] ?? 0),
            'scanned_dns' => (int)($conn->query("SELECT COALESCE(SUM(seen_dns),0) FROM nm_sentinel_nodes")->fetch_row()[0] ?? 0),
            'detected'    => (int)($conn->query("SELECT COUNT(*) FROM nm_sentinel_hits")->fetch_row()[0] ?? 0),
        ];
    }
    // Feed sources breakdown + last-refresh time (for the freshness detail / how-it-works).
    function nm_sentinel_feeds_info($conn): array {
        nm_sentinel_ensure($conn);
        $src=[]; $r=$conn->query("SELECT source,COUNT(*) n,MAX(last_seen) seen FROM nm_sentinel_intel GROUP BY source ORDER BY n DESC");
        while ($r && ($x=$r->fetch_assoc())) $src[]=['source'=>$x['source'],'n'=>(int)$x['n'],'seen'=>$x['seen']];
        $last=0; $lr=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='sentinel_feeds_last' LIMIT 1");
        if ($lr && ($v=$lr->fetch_row())) $last=(int)$v[0];
        return ['sources'=>$src,'refreshed_at'=>$last?date('Y-m-d H:i',$last):null,'refresh_every'=>'hourly (auto) · manual anytime',
                'next_auto'=>$last?date('H:i',$last+3600):null];
    }
    function nm_sentinel_hits_list($conn, int $limit=60): array {
        nm_sentinel_ensure($conn); $limit=max(1,min(500,$limit));
        $out=[]; $r=$conn->query("SELECT local_ip,remote_indicator,kind,module,category,action,detail,created_at FROM nm_sentinel_hits ORDER BY id DESC LIMIT ".$limit);
        while ($r && ($x=$r->fetch_assoc())) $out[]=$x;
        return $out;
    }
    function nm_sentinel_quarantine_list($conn): array {
        nm_sentinel_ensure($conn);
        $out=[]; $r=$conn->query("SELECT q.local_ip,q.mac,q.reason,q.state,q.created_at,n.display_name gw FROM nm_sentinel_quarantine q LEFT JOIN nm_nodes n ON n.id=q.gateway_node_id WHERE q.state='active' ORDER BY q.created_at DESC");
        while ($r && ($x=$r->fetch_assoc())) $out[]=$x;
        return $out;
    }
    function nm_sentinel_sensors($conn): array {
        nm_sentinel_ensure($conn);
        $out=[]; $r=$conn->query("SELECT uid,name,ip_address,arch,agent_version,seen_dns,seen_flows,neutralized,last_seen FROM nm_sentinel_nodes ORDER BY name");
        // online window = 2× the 300s poll + jitter, so a normally-polling sensor never flaps to offline.
        while ($r && ($x=$r->fetch_assoc())) { $x['online']=($x['last_seen'] && strtotime($x['last_seen'])>time()-660)?1:0; $out[]=$x; }
        return $out;
    }
}
