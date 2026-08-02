<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Shadow IT Discovery via blind NetFlow behavior fingerprinting.
//
// NetFlow is METADATA (no payload) so we can't read true entropy — instead we
// fingerprint by BEHAVIOR: protocol, port-vs-behavior, average packet size
// (bytes/packets), persistence (distinct minute-buckets), volume and symmetry.
// Flags likely unauthorized VPN/mesh tunnels (WireGuard/Tailscale/OpenVPN) and
// crypto-mining without decrypting anything. Findings are ADVISORY (review →
// optionally hand off to Collective Immunity to block). RBAC: 'shadowit'.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_audit.php';

if (!function_exists('nm_si_scan')) {

    function nm_si_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        static $done=false; if($done) return; $done=true;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_shadowit_findings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            src_ip VARCHAR(45) NOT NULL, dst_ip VARCHAR(45) NOT NULL,
            protocol TINYINT UNSIGNED NOT NULL DEFAULT 0, app_port INT UNSIGNED NOT NULL DEFAULT 0,
            classification VARCHAR(16) NOT NULL, confidence INT NOT NULL DEFAULT 0,
            evidence VARCHAR(400) DEFAULT NULL, mbps DOUBLE DEFAULT 0,
            status VARCHAR(12) NOT NULL DEFAULT 'new',   -- new | acknowledged | dismissed | allowlisted
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP, last_seen DATETIME DEFAULT CURRENT_TIMESTAMP, hits INT DEFAULT 1,
            UNIQUE KEY uniq_f (src_ip,dst_ip,protocol,app_port), KEY idx_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // exporter = the router/device that REPORTED the flow (NetFlow source). Guarded ALTER.
        $c=$conn->query("SELECT COUNT(*) c FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_shadowit_findings' AND COLUMN_NAME='exporter'");
        if ($c && (int)$c->fetch_assoc()['c']===0) $conn->query("ALTER TABLE nm_shadowit_findings ADD COLUMN exporter VARCHAR(255) DEFAULT NULL");
        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','shadowit',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='shadowit')");
    }
    function nm_si_setting($conn,$k,$d){ $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; }
    function _si_internal($ip){ return (bool)preg_match('/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|f[cd])/i',$ip); }

    // Behavioral classifier for one aggregated conversation.
    function nm_si_classify(array $f): ?array {
        $proto=(int)$f['protocol']; $port=(int)$f['app_port'];
        $b=(float)$f['b']; $p=max(1,(float)$f['p']); $buckets=(int)$f['buckets'];
        $avgPkt = $b/$p;
        $goodUDP = [53,67,68,123,137,138,161,162,500,4500,514,520,1701,1812,1813,1900,5060,5061,5353,69,33434,
            2055,2056,4739,6343,9995,9996,             // NetFlow/sFlow/IPFIX exporters
            3478,3479,3480,3481,3482,3483,             // STUN/TURN (Teams/Zoom/WebRTC media)
            16384,16385,16386,16387,8801,8802,         // RTP / Zoom media
            4501];                                     // IPsec NAT-T variant
        $vpnPorts= [51820=>'WireGuard',13231=>'WireGuard',41641=>'Tailscale',3478=>'Tailscale/STUN',1194=>'OpenVPN',1197=>'OpenVPN',1723=>'PPTP'];
        $minePorts=[3333,4444,5555,6666,7777,8888,9999,14433,14444,45560,45700,3032,5700,8008,3357,17777,20535,5730];

        // Crypto-mining: TCP to a known stratum/pool port, internal→external, persistent.
        if ($proto===6 && in_array($port,$minePorts,true) && _si_internal($f['src_ip']) && !_si_internal($f['dst_ip']) && $buckets>=3) {
            return ['type'=>'mining','conf'=>min(95,70+$buckets),'reason'=>"TCP to mining-pool port $port, persistent ($buckets min), out to external"];
        }
        // VPN/mesh tunnel: UDP on a non-standard high port, persistent, tunnel-like packet size.
        if ($proto===17 && $port>=1024 && !in_array($port,$goodUDP,true) && $buckets>=4) {
            $hint = $vpnPorts[$port] ?? null;
            $sizeHit = ($avgPkt>=400 && $avgPkt<=1500);   // tunnels carry near-MTU payloads
            $conf = 55 + ($hint?25:0) + ($sizeHit?12:0) + min(8,$buckets);
            if ($conf>=60) return ['type'=>'vpn','conf'=>min(98,$conf),'reason'=>($hint?"$hint signature on UDP/$port":"unclassified UDP/$port tunnel").", avg pkt ".round($avgPkt)."B, persistent ($buckets min)"];
        }
        // Suspicious persistent non-web TCP to a single external host (possible C2 / hidden service).
        if ($proto===6 && $port>0 && !in_array($port,[80,443,22,25,110,143,465,587,993,995,3306,5432,8080,8443],true)
            && _si_internal($f['src_ip']) && !_si_internal($f['dst_ip']) && $buckets>=6 && $b>5_000_000) {
            return ['type'=>'tunnel','conf'=>min(80,45+$buckets),'reason'=>"long-lived TCP/$port to external ($buckets min, ".round($b/1e6)."MB)"];
        }
        return null;
    }

    // Backfill the exporter (reporting router) for findings that don't have one yet, looking
    // across ALL retained NetFlow (not just the scan window) so OLD findings get it too.
    function nm_si_backfill_exporters($conn): int {
        nm_si_ensure($conn);
        if (!$conn->query("SHOW TABLES LIKE 'nm_netflow_flows'")->num_rows) return 0;
        $rs=$conn->query("SELECT id,src_ip,dst_ip,protocol,app_port FROM nm_shadowit_findings
                          WHERE (exporter IS NULL OR exporter='') AND status IN('new','acknowledged') LIMIT 400");
        if(!$rs) return 0; $rows=$rs->fetch_all(MYSQLI_ASSOC); $n=0;
        foreach($rows as $f){
            $q=$conn->prepare("SELECT SUBSTRING_INDEX(GROUP_CONCAT(DISTINCT exporter ORDER BY exporter SEPARATOR ','),',',4) ex
                               FROM nm_netflow_flows WHERE src_ip=? AND dst_ip=? AND protocol=? AND app_port=? AND exporter<>''");
            $pr=(int)$f['protocol']; $po=(int)$f['app_port'];
            $q->bind_param('ssii',$f['src_ip'],$f['dst_ip'],$pr,$po); $q->execute();
            $ex=(string)($q->get_result()->fetch_assoc()['ex'] ?? ''); $q->close();
            if($ex!==''){ $u=$conn->prepare("UPDATE nm_shadowit_findings SET exporter=? WHERE id=?"); $fid=(int)$f['id']; $u->bind_param('si',$ex,$fid); $u->execute(); $u->close(); $n++; }
        }
        return $n;
    }

    // Scan recent NetFlow, classify, upsert findings. Returns ['scanned','flagged','new'].
    function nm_si_scan($conn): array {
        nm_si_ensure($conn);
        nm_si_backfill_exporters($conn);   // fill 'reported by' for any finding missing it
        if (!$conn->query("SHOW TABLES LIKE 'nm_netflow_flows'")->num_rows) return ['scanned'=>0,'flagged'=>0,'new'=>0];
        $win = (int)nm_si_setting($conn,'si_window_min','30') ?: 30;
        // allowlist: comma list of "ip" or "ip:port" to never flag
        $allow = array_filter(array_map('trim', explode(',', (string)nm_si_setting($conn,'si_allowlist',''))));
        $allowSet = array_flip($allow);
        $r=$conn->query("SELECT src_ip,dst_ip,protocol,app_port, SUM(bytes) b, SUM(packets) p, COUNT(DISTINCT bucket) buckets,
                SUBSTRING_INDEX(GROUP_CONCAT(DISTINCT exporter ORDER BY exporter SEPARATOR ','),',',4) exporters
            FROM nm_netflow_flows WHERE bucket>=DATE_SUB(NOW(),INTERVAL {$win} MINUTE) AND app_port>0
            GROUP BY src_ip,dst_ip,protocol,app_port HAVING b>200000 ORDER BY b DESC LIMIT 500");
        $scanned=0;$flagged=0;$new=0; $now=date('Y-m-d H:i:s');
        while($r&&$f=$r->fetch_assoc()){
            $scanned++;
            if(isset($allowSet[$f['src_ip']])||isset($allowSet[$f['dst_ip']])||isset($allowSet[$f['src_ip'].':'.$f['app_port']])) continue;
            $c=nm_si_classify($f); if(!$c) continue;
            $flagged++;
            $mbps=round(((float)$f['b']*8)/($win*60)/1e6,3);
            $ex=$conn->prepare("SELECT id,status FROM nm_shadowit_findings WHERE src_ip=? AND dst_ip=? AND protocol=? AND app_port=? LIMIT 1");
            $pr=(int)$f['protocol']; $po=(int)$f['app_port']; $ex->bind_param('ssii',$f['src_ip'],$f['dst_ip'],$pr,$po); $ex->execute();
            $exporters = substr((string)($f['exporters'] ?? ''), 0, 255);
            if($row=$ex->get_result()->fetch_assoc()){
                if($row['status']==='allowlisted'||$row['status']==='dismissed') continue;
                $up=$conn->prepare("UPDATE nm_shadowit_findings SET hits=hits+1,last_seen=?,confidence=?,mbps=?,exporter=? WHERE id=?");
                $cf=(int)$c['conf']; $rid=(int)$row['id']; $up->bind_param('sidsi',$now,$cf,$mbps,$exporters,$rid); $up->execute();
            } else {
                $st=$conn->prepare("INSERT INTO nm_shadowit_findings (src_ip,dst_ip,protocol,app_port,classification,confidence,evidence,mbps,exporter,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?)");
                $cls=$c['type']; $cf=(int)$c['conf']; $rs=substr($c['reason'],0,400);
                $st->bind_param('ssiisisdsss',$f['src_ip'],$f['dst_ip'],$pr,$po,$cls,$cf,$rs,$mbps,$exporters,$now,$now); $st->execute(); $new++;
            }
        }
        return ['scanned'=>$scanned,'flagged'=>$flagged,'new'=>$new];
    }

    function nm_si_list($conn): array { nm_si_ensure($conn); $o=[]; $r=$conn->query("SELECT * FROM nm_shadowit_findings WHERE status IN('new','acknowledged') ORDER BY FIELD(status,'new','acknowledged'), confidence DESC, last_seen DESC LIMIT 300"); while($r&&$x=$r->fetch_assoc())$o[]=$x; return $o; }
    function nm_si_set_status($conn,int $id,string $s){ $s=in_array($s,['new','acknowledged','dismissed','allowlisted'],true)?$s:'new'; $st=$conn->prepare("UPDATE nm_shadowit_findings SET status=? WHERE id=?"); $st->bind_param('si',$s,$id); $st->execute(); }
    function nm_si_counts($conn): array { nm_si_ensure($conn); $o=['new'=>0,'acknowledged'=>0]; $r=$conn->query("SELECT status,COUNT(*) c FROM nm_shadowit_findings WHERE status IN('new','acknowledged') GROUP BY status"); while($r&&$x=$r->fetch_assoc())$o[$x['status']]=(int)$x['c']; return $o; }
}
