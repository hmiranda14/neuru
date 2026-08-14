<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU Utilities — control-plane engine.
//
// A deployable "neuru-utilities" host (single Docker container, supervisord +
// util-agent) runs a stack of rescue/provisioning services (TFTP, SFTP, HTTP
// firmware, NTP, iPerf3, syslog relay, File Browser…). The DEFINING idea: every
// service is configured CENTRALLY here — NEURU holds the desired-state, the agent
// PULLS it and reconciles the box to match. NEURU is the only writer → no drift,
// never SSH into the utility host.
//
// Mirrors the neuru-agent model: shared enrolment token, outbound-only pull,
// idempotent register. RBAC perm: 'utilities'. Engine for utilities.php + util-agent.py.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_util_ensure')) {

    function nm_util_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;

        $conn->query("CREATE TABLE IF NOT EXISTS nm_util_nodes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            uid VARCHAR(64) NOT NULL,
            name VARCHAR(120) NOT NULL,
            ip_address VARCHAR(64) DEFAULT NULL,
            arch VARCHAR(16) DEFAULT NULL,
            agent_version VARCHAR(32) DEFAULT NULL,
            os VARCHAR(64) DEFAULT NULL,
            status VARCHAR(12) NOT NULL DEFAULT 'new',
            desired_rev INT NOT NULL DEFAULT 0,
            applied_rev INT NOT NULL DEFAULT 0,
            files_rev INT NOT NULL DEFAULT 0,
            last_seen DATETIME DEFAULT NULL,
            enrolled_by INT DEFAULT NULL,
            group_id INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_uid (uid),
            KEY idx_seen (last_seen)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Per-node, per-service desired config + applied state. config_json is validated
        // against the service's schema (nm_util_catalog). desired_rev bumps on every save;
        // the agent reports applied_rev + runtime state.
        $conn->query("CREATE TABLE IF NOT EXISTS nm_util_services (
            id INT AUTO_INCREMENT PRIMARY KEY,
            node_id INT NOT NULL,
            service VARCHAR(24) NOT NULL,
            enabled TINYINT(1) NOT NULL DEFAULT 0,
            config_json MEDIUMTEXT DEFAULT NULL,
            state VARCHAR(16) NOT NULL DEFAULT 'stopped',
            last_error VARCHAR(255) DEFAULT NULL,
            version VARCHAR(48) DEFAULT NULL,
            updated_by INT DEFAULT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uk_node_svc (node_id, service),
            KEY idx_node (node_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // File-store index (what the agent reports living under /srv/neuru-utils).
        $conn->query("CREATE TABLE IF NOT EXISTS nm_util_files (
            id INT AUTO_INCREMENT PRIMARY KEY,
            node_id INT NOT NULL,
            path VARCHAR(512) NOT NULL,
            size BIGINT DEFAULT 0,
            sha256 CHAR(64) DEFAULT NULL,
            mtime DATETIME DEFAULT NULL,
            kind VARCHAR(12) DEFAULT 'other',
            seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_node_path (node_id, path),
            KEY idx_node (node_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Telemetry / audit stream from the agent (tftp grabs, iperf runs, traps, logins…).
        $conn->query("CREATE TABLE IF NOT EXISTS nm_util_events (
            id INT AUTO_INCREMENT PRIMARY KEY,
            node_id INT NOT NULL,
            service VARCHAR(24) DEFAULT NULL,
            type VARCHAR(24) NOT NULL,
            ref VARCHAR(120) DEFAULT NULL,
            detail_json TEXT DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            KEY idx_node_time (node_id, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Command/task channel (NEURU → agent): WoL, iperf client run, TCP/UDP connectivity
        // test, write a file into the store (used to stage ZTP configs). The agent picks up
        // pending commands in its desired-pull and posts results back in its report.
        $conn->query("CREATE TABLE IF NOT EXISTS nm_util_commands (
            id INT AUTO_INCREMENT PRIMARY KEY,
            node_id INT NOT NULL,
            cmd VARCHAR(24) NOT NULL,
            args_json TEXT DEFAULT NULL,
            status VARCHAR(10) NOT NULL DEFAULT 'pending',
            result_json MEDIUMTEXT DEFAULT NULL,
            created_by INT DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            done_at DATETIME DEFAULT NULL,
            KEY idx_node_status (node_id, status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Zero-Touch Provisioning jobs — a per-MAC bootstrap config staged on a utility
        // host's file store and served via TFTP/HTTP. Keyed off the IPAM DHCP lease MAC↔IP.
        $conn->query("CREATE TABLE IF NOT EXISTS nm_util_ztp (
            id INT AUTO_INCREMENT PRIMARY KEY,
            node_id INT NOT NULL,
            mac VARCHAR(17) NOT NULL,
            vendor VARCHAR(24) NOT NULL DEFAULT 'mikrotik',
            hostname VARCHAR(120) DEFAULT NULL,
            rendered_path VARCHAR(255) DEFAULT NULL,
            state VARCHAR(12) NOT NULL DEFAULT 'pending',
            created_by INT DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            served_at DATETIME DEFAULT NULL,
            UNIQUE KEY uk_node_mac (node_id, mac)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','utilities',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='utilities')");
    }

    // ── Service catalog — the single source of truth for what a utility host can run
    //    and which knobs NEURU exposes as a config form. The agent renders each
    //    service's real config from these fields. Field types: text|bool|number|
    //    secret|textarea|select. 'secret' values are encrypted at rest (nm_secret_*). ─
    function nm_util_catalog(): array {
        return [
            'filebrowser' => [
                'label'=>'File Browser', 'cat'=>'files', 'icon'=>'fa-folder-open', 'port'=>'8088/tcp',
                'desc'=>'Web file manager (Google-Drive style) over the shared store — drag-drop firmware/scripts from the browser.',
                'fields'=>[
                    ['key'=>'port','label'=>'Web port','type'=>'number','default'=>8088],
                    ['key'=>'admin_user','label'=>'Admin user','type'=>'text','default'=>'admin'],
                    ['key'=>'admin_pass','label'=>'Admin password','type'=>'secret','default'=>''],
                ],
            ],
            'tftp' => [
                'label'=>'TFTP', 'cat'=>'files', 'icon'=>'fa-download', 'port'=>'69/udp',
                'desc'=>'Firmware/config push-pull for legacy & network gear (Cisco/MikroTik). Ties into Config Manager + ZTP.',
                'fields'=>[
                    ['key'=>'root','label'=>'Root directory','type'=>'text','default'=>'/srv/neuru-utils/tftp'],
                    ['key'=>'writable','label'=>'Allow uploads (writable)','type'=>'bool','default'=>false],
                    ['key'=>'allow','label'=>'Allow subnets (CSV, blank = any)','type'=>'text','default'=>''],
                ],
            ],
            'sftp' => [
                'label'=>'SFTP', 'cat'=>'files', 'icon'=>'fa-lock', 'port'=>'2222/tcp',
                'desc'=>'Secure file drop for modern backups. A backup-vault target for gear that supports SFTP.',
                'fields'=>[
                    ['key'=>'port','label'=>'SFTP port','type'=>'number','default'=>2222],
                    ['key'=>'username','label'=>'Username','type'=>'text','default'=>'neuru'],
                    ['key'=>'password','label'=>'Password','type'=>'secret','default'=>''],
                    ['key'=>'pubkey','label'=>'Authorized public key (optional)','type'=>'textarea','default'=>''],
                    ['key'=>'root','label'=>'Chroot directory','type'=>'text','default'=>'/srv/neuru-utils'],
                ],
            ],
            'ftp' => [
                'label'=>'FTP / FTPS', 'cat'=>'files', 'icon'=>'fa-file-arrow-up', 'port'=>'21/tcp',
                'desc'=>'Classic FTP for legacy PBX/switches/IP-cameras that only dump backups over plain FTP. Optional TLS.',
                'fields'=>[
                    ['key'=>'username','label'=>'Username','type'=>'text','default'=>'neuru'],
                    ['key'=>'password','label'=>'Password','type'=>'secret','default'=>''],
                    ['key'=>'root','label'=>'Root directory','type'=>'text','default'=>'/srv/neuru-utils/backups'],
                    ['key'=>'tls','label'=>'Require TLS (FTPS)','type'=>'bool','default'=>false],
                    ['key'=>'pasv_min','label'=>'Passive port min','type'=>'number','default'=>21000],
                    ['key'=>'pasv_max','label'=>'Passive port max','type'=>'number','default'=>21010],
                ],
            ],
            'http' => [
                'label'=>'HTTP / WebDAV firmware', 'cat'=>'files', 'icon'=>'fa-globe', 'port'=>'8080/tcp',
                'desc'=>'Static file server for firmware images (.bin/.iso/.tar). Modern switches (Aruba/UBNT/Juniper) pull over HTTP(S).',
                'fields'=>[
                    ['key'=>'port','label'=>'HTTP port','type'=>'number','default'=>8080],
                    ['key'=>'root','label'=>'Root directory','type'=>'text','default'=>'/srv/neuru-utils/firmware'],
                    ['key'=>'autoindex','label'=>'Directory listing','type'=>'bool','default'=>true],
                    ['key'=>'webdav','label'=>'Enable WebDAV (upload)','type'=>'bool','default'=>false],
                ],
            ],
            'ntp' => [
                'label'=>'NTP (time)', 'cat'=>'net', 'icon'=>'fa-clock', 'port'=>'123/udp',
                'desc'=>'Local time source for isolated gear. Fixes the clock-drift that corrupts NEURU log/incident timestamps.',
                'fields'=>[
                    ['key'=>'upstreams','label'=>'Upstream servers (CSV)','type'=>'text','default'=>'pool.ntp.org'],
                    ['key'=>'allow','label'=>'Serve subnets (CSV)','type'=>'text','default'=>'0.0.0.0/0'],
                    ['key'=>'local_stratum','label'=>'Local stratum (if isolated)','type'=>'number','default'=>10],
                ],
            ],
            'iperf3' => [
                'label'=>'iPerf3', 'cat'=>'diag', 'icon'=>'fa-gauge-high', 'port'=>'5201/tcp',
                'desc'=>'Bandwidth/throughput test server. NEURU launches tests between nodes/sites and graphs the result.',
                'fields'=>[
                    ['key'=>'port','label'=>'Port','type'=>'number','default'=>5201],
                ],
            ],
            'syslog' => [
                'label'=>'Syslog / trap relay', 'cat'=>'logs', 'icon'=>'fa-scroll', 'port'=>'514/udp',
                'desc'=>'Receives syslog + SNMP traps, rotates locally for audit, and forwards filtered into NEURU’s pipeline.',
                'fields'=>[
                    ['key'=>'udp','label'=>'Listen UDP/514','type'=>'bool','default'=>true],
                    ['key'=>'tcp','label'=>'Listen TCP/514','type'=>'bool','default'=>false],
                    ['key'=>'retention_days','label'=>'Local retention (days)','type'=>'number','default'=>14],
                    ['key'=>'forward','label'=>'Forward to NEURU syslog','type'=>'bool','default'=>true],
                    ['key'=>'filter','label'=>'Forward filter (severity ≤)','type'=>'select','default'=>'warning',
                     'options'=>['emerg','alert','crit','err','warning','notice','info','debug']],
                ],
            ],
            'dnsmasq' => [
                'label'=>'DNS / DHCP-proxy / PXE', 'cat'=>'provision', 'icon'=>'fa-diagram-project', 'port'=>'53,67,69/udp',
                'desc'=>'Local DNS + proxyDHCP + PXE/iPXE boot for Zero-Touch Provisioning. proxyDHCP mode NEVER hands out addresses — it only tells PXE clients where to boot, so it is safe next to your production DHCP.',
                'fields'=>[
                    ['key'=>'dns','label'=>'Local DNS resolver','type'=>'bool','default'=>false],
                    ['key'=>'dns_upstream','label'=>'DNS upstream (CSV)','type'=>'text','default'=>'1.1.1.1,8.8.8.8'],
                    ['key'=>'domain','label'=>'Local domain','type'=>'text','default'=>'lan'],
                    ['key'=>'proxydhcp','label'=>'proxyDHCP + PXE (boot only, no IP hand-out)','type'=>'bool','default'=>true],
                    ['key'=>'proxy_subnet','label'=>'PXE subnet (e.g. 192.168.0.0)','type'=>'text','default'=>''],
                    ['key'=>'tftp_root','label'=>'Boot/TFTP root','type'=>'text','default'=>'/srv/neuru-utils/tftp'],
                    ['key'=>'ipxe','label'=>'Chainload iPXE (needs undionly.kpxe/ipxe.efi in TFTP root)','type'=>'bool','default'=>true],
                    ['key'=>'boot_menu','label'=>'iPXE boot menu (raw, one entry per line: label|url)','type'=>'textarea',
                     'default'=>"Ubuntu Live|http://\${next-server}:8080/images/ubuntu.ipxe\nProxmox|http://\${next-server}:8080/images/proxmox.ipxe\nClonezilla|http://\${next-server}:8080/images/clonezilla.ipxe"],
                ],
            ],
            'listeners' => [
                'label'=>'Test listeners', 'cat'=>'diag', 'icon'=>'fa-plug', 'port'=>'custom',
                'desc'=>'Dummy TCP/UDP echo listeners on ports you choose — targets to validate firewall rules, NATs and ACLs from anywhere.',
                'fields'=>[
                    ['key'=>'tcp_ports','label'=>'TCP ports (CSV)','type'=>'text','default'=>'9000,9001'],
                    ['key'=>'udp_ports','label'=>'UDP ports (CSV)','type'=>'text','default'=>'9002'],
                    ['key'=>'banner','label'=>'Reply banner','type'=>'text','default'=>'NEURU-UTIL-OK'],
                ],
            ],
        ];
    }

    // Merge defaults with a saved config so the agent always gets a complete object.
    function nm_util_service_defaults(string $service): array {
        $cat = nm_util_catalog();
        $out = [];
        foreach (($cat[$service]['fields'] ?? []) as $f) $out[$f['key']] = $f['default'];
        return $out;
    }

    // ── Shared enrolment token (rotate = revoke all utility hosts) ─────────────
    function nm_util_token($conn): string {
        try { $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='util_token' LIMIT 1");
            if ($r && ($x=$r->fetch_assoc())) return (string)$x['setting_val']; } catch (\Throwable $e) {}
        return '';
    }
    function nm_util_token_ensure($conn): string {
        $t = nm_util_token($conn);
        return $t !== '' ? $t : nm_util_token_rotate($conn);
    }
    function nm_util_token_rotate($conn): string {
        $tok = 'neu_utl_' . bin2hex(random_bytes(24));
        try { $st = $conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES('util_token',?)
                ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
            $st->bind_param('s',$tok); $st->execute(); $st->close(); } catch (\Throwable $e) { return ''; }
        if (function_exists('nm_audit')) { try { nm_audit($conn,'utilities.token.rotate',['target_type'=>'utilities']); } catch (\Throwable $e) {} }
        return $tok;
    }
    function nm_util_verify($conn, ?string $presented): bool {
        $presented = (string)$presented; if ($presented==='') return false;
        $stored = nm_util_token($conn); if ($stored==='') return false;
        return hash_equals($stored, $presented);
    }

    // ── Register / upsert a utility host (idempotent by uid) → node_id ─────────
    function nm_util_register($conn, string $uid, string $hostname, array $meta = []): array {
        nm_util_ensure($conn);
        $uid  = substr(preg_replace('/[^A-Za-z0-9._:-]/','',$uid),0,64);
        if ($uid==='') return ['ok'=>false,'error'=>'missing uid'];
        $name = substr(trim($hostname!=='' ? $hostname : $uid),0,120);
        $ip   = substr(preg_replace('/[^0-9a-fA-F.:]/','',(string)($meta['ip'] ?? '')),0,64) ?: null;
        $arch = substr((string)($meta['arch'] ?? ''),0,16) ?: null;
        $ver  = substr((string)($meta['agent_version'] ?? ''),0,32) ?: null;
        $os   = substr((string)($meta['os'] ?? ''),0,64) ?: null;
        $eby  = isset($meta['enrolled_by']) ? (int)$meta['enrolled_by'] : null;

        $st = $conn->prepare("INSERT INTO nm_util_nodes (uid,name,ip_address,arch,agent_version,os,status,last_seen,enrolled_by)
            VALUES (?,?,?,?,?,?, 'online', NOW(), ?)
            ON DUPLICATE KEY UPDATE name=VALUES(name), ip_address=VALUES(ip_address), arch=VALUES(arch),
                agent_version=VALUES(agent_version), os=VALUES(os), status='online', last_seen=NOW()");
        $st->bind_param('ssssssi', $uid,$name,$ip,$arch,$ver,$os,$eby);
        $st->execute(); $st->close();
        $nid = 0;
        $q = $conn->prepare("SELECT id FROM nm_util_nodes WHERE uid=? LIMIT 1");
        $q->bind_param('s',$uid); $q->execute();
        if ($row=$q->get_result()->fetch_assoc()) $nid=(int)$row['id']; $q->close();
        if (function_exists('nm_audit')) { try { nm_audit($conn,'utilities.enroll',['target_type'=>'utilities','target_id'=>$name]); } catch (\Throwable $e) {} }
        return ['ok'=>true,'node_id'=>$nid];
    }

    function nm_util_nodes($conn): array {
        nm_util_ensure($conn);
        $out=[]; $r=$conn->query("SELECT * FROM nm_util_nodes ORDER BY name");
        while ($r && ($x=$r->fetch_assoc())) {
            $x['svc_on'] = (int)($conn->query("SELECT COUNT(*) FROM nm_util_services WHERE node_id=".(int)$x['id']." AND enabled=1")->fetch_row()[0] ?? 0);
            $x['online'] = ($x['last_seen'] && (strtotime($x['last_seen']) > time()-180)) ? 1 : 0;
            $out[]=$x;
        }
        return $out;
    }
    function nm_util_node($conn, int $id): ?array {
        nm_util_ensure($conn);
        $r=$conn->query("SELECT * FROM nm_util_nodes WHERE id=".(int)$id." LIMIT 1");
        return $r ? ($r->fetch_assoc() ?: null) : null;
    }

    // Per-node services merged with the catalog (for the UI): every catalog service,
    // with its saved enabled/config (or defaults) + runtime state.
    function nm_util_node_services($conn, int $node_id): array {
        nm_util_ensure($conn);
        $saved=[]; $r=$conn->query("SELECT service,enabled,config_json,state,last_error,version FROM nm_util_services WHERE node_id=".(int)$node_id);
        while ($r && ($x=$r->fetch_assoc())) $saved[$x['service']]=$x;
        $out=[];
        foreach (nm_util_catalog() as $key=>$meta) {
            $s = $saved[$key] ?? null;
            $cfg = $s && $s['config_json'] ? json_decode($s['config_json'],true) : [];
            if (!is_array($cfg)) $cfg=[];
            $cfg = array_merge(nm_util_service_defaults($key), $cfg);
            // never leak raw secrets to the UI — mask them
            foreach (($meta['fields'] ?? []) as $f) if ($f['type']==='secret' && !empty($cfg[$f['key']])) $cfg[$f['key']]='••••••';
            $out[]=[
                'service'=>$key,'label'=>$meta['label'],'cat'=>$meta['cat'],'icon'=>$meta['icon'],
                'port'=>$meta['port'],'desc'=>$meta['desc'],'fields'=>$meta['fields'],
                'enabled'=>$s ? (int)$s['enabled'] : 0,
                'config'=>$cfg,
                'state'=>$s['state'] ?? 'stopped','last_error'=>$s['last_error'] ?? null,'version'=>$s['version'] ?? null,
            ];
        }
        return $out;
    }

    // UI writes desired state for one service. Secrets: '••••••' means "keep existing".
    function nm_util_set_service($conn, int $node_id, string $service, int $enabled, array $config, ?int $uid=null): array {
        nm_util_ensure($conn);
        $cat = nm_util_catalog();
        if (!isset($cat[$service])) return ['ok'=>false,'error'=>'unknown service'];
        require_once __DIR__.'/nm_secrets.php';
        // load existing config to preserve unchanged secrets
        $prev=[]; $r=$conn->query("SELECT config_json FROM nm_util_services WHERE node_id=".(int)$node_id." AND service='".$conn->real_escape_string($service)."' LIMIT 1");
        if ($r && ($x=$r->fetch_assoc()) && $x['config_json']) { $prev=json_decode($x['config_json'],true) ?: []; }
        $clean=[];
        foreach ($cat[$service]['fields'] as $f) {
            $k=$f['key']; $v=$config[$k] ?? $f['default'];
            switch ($f['type']) {
                case 'bool':   $clean[$k]=(int)(!!$v && $v!=='false' && $v!=='0'); break;
                case 'number': $clean[$k]=(int)$v; break;
                case 'secret':
                    if ($v==='••••••' || $v==='') { $clean[$k]=$prev[$k] ?? ''; }   // keep existing
                    else { $clean[$k]=nm_secret_encrypt((string)$v); }
                    break;
                default: $clean[$k]=substr((string)$v,0,4096);
            }
        }
        $json=json_encode($clean);
        $st=$conn->prepare("INSERT INTO nm_util_services (node_id,service,enabled,config_json,updated_by)
            VALUES (?,?,?,?,?) ON DUPLICATE KEY UPDATE enabled=VALUES(enabled),config_json=VALUES(config_json),updated_by=VALUES(updated_by)");
        $st->bind_param('isisi',$node_id,$service,$enabled,$json,$uid); $st->execute(); $st->close();
        $conn->query("UPDATE nm_util_nodes SET desired_rev=desired_rev+1 WHERE id=".(int)$node_id);
        if (function_exists('nm_audit')) { try { nm_audit($conn,'utilities.config',['target_type'=>'utilities','target_id'=>$service]); } catch (\Throwable $e) {} }
        return ['ok'=>true];
    }

    // ── Agent-facing: the desired-state the util-agent pulls + reconciles to. ──
    // Secrets are DECRYPTED here (sent only over TLS to an enrolled, token-authed agent).
    function nm_util_desired($conn, int $node_id): array {
        nm_util_ensure($conn);
        require_once __DIR__.'/nm_secrets.php';
        $node = nm_util_node($conn,$node_id);
        if (!$node) return ['ok'=>false,'error'=>'unknown node'];
        $cat = nm_util_catalog();
        $services=[];
        $r=$conn->query("SELECT service,enabled,config_json FROM nm_util_services WHERE node_id=".(int)$node_id);
        while ($r && ($x=$r->fetch_assoc())) {
            $key=$x['service']; if (!isset($cat[$key])) continue;
            $cfg = $x['config_json'] ? (json_decode($x['config_json'],true) ?: []) : [];
            $cfg = array_merge(nm_util_service_defaults($key),$cfg);
            foreach ($cat[$key]['fields'] as $f) if ($f['type']==='secret' && !empty($cfg[$f['key']])) $cfg[$f['key']]=nm_secret_decrypt($cfg[$f['key']]);
            $services[$key]=['enabled'=>(int)$x['enabled'],'config'=>$cfg];
        }
        return ['ok'=>true,'rev'=>(int)$node['desired_rev'],'node'=>['id'=>$node_id,'name'=>$node['name']],
                'services'=>$services,'commands'=>nm_util_cmd_pending($conn,$node_id)];
    }

    // ── Agent-facing: status/telemetry/manifest report. ───────────────────────
    function nm_util_report($conn, int $node_id, array $p): array {
        nm_util_ensure($conn);
        // liveness + applied rev
        $arev = isset($p['applied_rev']) ? (int)$p['applied_rev'] : null;
        if ($arev !== null) $conn->query("UPDATE nm_util_nodes SET applied_rev=".$arev.", status='online', last_seen=NOW() WHERE id=".(int)$node_id);
        else                $conn->query("UPDATE nm_util_nodes SET status='online', last_seen=NOW() WHERE id=".(int)$node_id);
        // per-service runtime state
        foreach (($p['services'] ?? []) as $svc=>$st) {
            $svc=substr(preg_replace('/[^a-z0-9_]/','',(string)$svc),0,24); if ($svc==='') continue;
            $state=substr((string)($st['state'] ?? 'unknown'),0,16);
            $err  =isset($st['error'])? substr((string)$st['error'],0,255):null;
            $ver  =isset($st['version'])? substr((string)$st['version'],0,48):null;
            $q=$conn->prepare("UPDATE nm_util_services SET state=?,last_error=?,version=? WHERE node_id=? AND service=?");
            $q->bind_param('sssis',$state,$err,$ver,$node_id,$svc); $q->execute(); $q->close();
        }
        // file manifest (replace)
        if (isset($p['files']) && is_array($p['files'])) {
            $conn->query("DELETE FROM nm_util_files WHERE node_id=".(int)$node_id);
            $ins=$conn->prepare("INSERT INTO nm_util_files (node_id,path,size,sha256,mtime,kind) VALUES (?,?,?,?,?,?)");
            foreach (array_slice($p['files'],0,5000) as $f) {
                $path=substr((string)($f['path'] ?? ''),0,512); if ($path==='') continue;
                $size=(int)($f['size'] ?? 0); $sha=substr((string)($f['sha256'] ?? ''),0,64) ?: null;
                $mt=isset($f['mtime'])? date('Y-m-d H:i:s',(int)$f['mtime']):null;
                $kind=substr((string)($f['kind'] ?? 'other'),0,12);
                $ins->bind_param('isisss',$node_id,$path,$size,$sha,$mt,$kind); $ins->execute();
            }
            $ins->close();
            $conn->query("UPDATE nm_util_nodes SET files_rev=files_rev+1 WHERE id=".(int)$node_id);
        }
        // telemetry events (append) + ZTP grab detection
        if (isset($p['events']) && is_array($p['events'])) {
            $ins=$conn->prepare("INSERT INTO nm_util_events (node_id,service,type,ref,detail_json) VALUES (?,?,?,?,?)");
            foreach (array_slice($p['events'],0,500) as $e) {
                $svc=substr((string)($e['service'] ?? ''),0,24) ?: null;
                $type=substr((string)($e['type'] ?? 'event'),0,24);
                $ref=substr((string)($e['ref'] ?? ''),0,120) ?: null;
                $det=isset($e['detail'])? substr(json_encode($e['detail'],JSON_UNESCAPED_SLASHES),0,2000):null;
                $ins->bind_param('issss',$node_id,$svc,$type,$ref,$det); $ins->execute();
                // a TFTP/HTTP grab of a ztp/ file → mark that ZTP job served
                if ($type==='grab' && $det && strpos($det,'ztp/')!==false) {
                    @$conn->query("UPDATE nm_util_ztp SET state='served', served_at=NOW() WHERE node_id=".(int)$node_id." AND state<>'served' AND rendered_path IS NOT NULL AND '".$conn->real_escape_string($det)."' LIKE CONCAT('%',rendered_path,'%')");
                }
            }
            $ins->close();
        }
        // command results (agent executed queued tasks)
        if (isset($p['command_results']) && is_array($p['command_results'])) nm_util_cmd_result($conn, $p['command_results']);
        return ['ok'=>true];
    }

    function nm_util_files($conn, int $node_id): array {
        nm_util_ensure($conn);
        $out=[]; $r=$conn->query("SELECT path,size,sha256,mtime,kind FROM nm_util_files WHERE node_id=".(int)$node_id." ORDER BY path");
        while ($r && ($x=$r->fetch_assoc())) $out[]=$x;
        return $out;
    }
    function nm_util_events($conn, int $node_id, int $limit=100): array {
        nm_util_ensure($conn);
        $limit=max(1,min(1000,$limit));
        $out=[]; $r=$conn->query("SELECT service,type,ref,detail_json,created_at FROM nm_util_events WHERE node_id=".(int)$node_id." ORDER BY id DESC LIMIT ".$limit);
        while ($r && ($x=$r->fetch_assoc())) $out[]=$x;
        return $out;
    }
    function nm_util_delete($conn, int $node_id): array {
        nm_util_ensure($conn);
        foreach (['nm_util_services','nm_util_files','nm_util_events','nm_util_commands','nm_util_ztp'] as $t) $conn->query("DELETE FROM $t WHERE node_id=".(int)$node_id);
        $conn->query("DELETE FROM nm_util_nodes WHERE id=".(int)$node_id);
        return ['ok'=>true];
    }

    // ─────────────────────────────────────────────────────────────────────────
    // COMMAND / TASK CHANNEL (NEURU → agent): wol | iperf | tcp_test | udp_test | write_file
    // ─────────────────────────────────────────────────────────────────────────
    function nm_util_cmd_queue($conn, int $node_id, string $cmd, array $args=[], ?int $uid=null): array {
        nm_util_ensure($conn);
        $allow=['wol','iperf','tcp_test','udp_test','write_file'];
        if (!in_array($cmd,$allow,true)) return ['ok'=>false,'error'=>'unknown command'];
        $aj=json_encode($args);
        $st=$conn->prepare("INSERT INTO nm_util_commands (node_id,cmd,args_json,created_by) VALUES (?,?,?,?)");
        $st->bind_param('issi',$node_id,$cmd,$aj,$uid); $st->execute(); $id=(int)$conn->insert_id; $st->close();
        return ['ok'=>true,'id'=>$id];
    }
    // Pending commands for the agent (marks them 'sent' so they aren't handed out twice).
    function nm_util_cmd_pending($conn, int $node_id): array {
        $out=[]; $r=$conn->query("SELECT id,cmd,args_json FROM nm_util_commands WHERE node_id=".(int)$node_id." AND status='pending' ORDER BY id LIMIT 20");
        while ($r && ($x=$r->fetch_assoc())) $out[]=['id'=>(int)$x['id'],'cmd'=>$x['cmd'],'args'=>json_decode($x['args_json'],true) ?: []];
        if ($out) { $ids=implode(',',array_map(fn($c)=>$c['id'],$out)); $conn->query("UPDATE nm_util_commands SET status='sent' WHERE id IN ($ids)"); }
        return $out;
    }
    function nm_util_cmd_result($conn, array $results): void {
        foreach ($results as $r) {
            $id=(int)($r['id'] ?? 0); if (!$id) continue;
            $status=in_array(($r['status'] ?? 'done'),['done','error'],true)? $r['status']:'done';
            $res=substr(json_encode($r['result'] ?? null),0,60000);
            $st=$conn->prepare("UPDATE nm_util_commands SET status=?,result_json=?,done_at=NOW() WHERE id=?");
            $st->bind_param('ssi',$status,$res,$id); $st->execute(); $st->close();
        }
    }
    function nm_util_commands_list($conn, int $node_id, int $limit=40): array {
        nm_util_ensure($conn); $limit=max(1,min(200,$limit));
        $out=[]; $r=$conn->query("SELECT id,cmd,args_json,status,result_json,created_at,done_at FROM nm_util_commands WHERE node_id=".(int)$node_id." ORDER BY id DESC LIMIT ".$limit);
        while ($r && ($x=$r->fetch_assoc())) $out[]=$x;
        return $out;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZERO-TOUCH PROVISIONING — per-MAC bootstrap configs served via TFTP/HTTP.
    // ─────────────────────────────────────────────────────────────────────────
    function nm_util_ztp_vendors(): array {
        return [
            'mikrotik' => ['label'=>'MikroTik (RouterOS .rsc)','ext'=>'rsc',
                'template'=>"# NEURU ZTP — {{hostname}} ({{mac}})\n/system identity set name=\"{{hostname}}\"\n/ip dns set servers={{dns}}\n/system ntp client set enabled=yes primary-ntp={{ntp}}\n/system note set show-at-login=no note=\"Provisioned by NEURU\"\n{{extra}}\n"],
            'cisco' => ['label'=>'Cisco IOS','ext'=>'cfg',
                'template'=>"! NEURU ZTP — {{hostname}} ({{mac}})\nhostname {{hostname}}\nip name-server {{dns}}\nntp server {{ntp}}\n{{extra}}\nend\n"],
            'generic' => ['label'=>'Generic / notes','ext'=>'txt',
                'template'=>"# NEURU ZTP bootstrap for {{hostname}} ({{mac}})\nDNS={{dns}}\nNTP={{ntp}}\n{{extra}}\n"],
        ];
    }
    function nm_util_ztp_render(string $vendor, array $vars): string {
        $v=nm_util_ztp_vendors(); $t=($v[$vendor]['template'] ?? $v['generic']['template']);
        foreach (['hostname','mac','dns','ntp','extra'] as $k) $t=str_replace('{{'.$k.'}}', (string)($vars[$k] ?? ''), $t);
        return $t;
    }
    // Stage a ZTP config: render → queue a write_file command (agent drops it in ztp/) →
    // upsert the ztp job. When the device grabs the file, the agent's grab event flips it 'served'.
    function nm_util_ztp_stage($conn, int $node_id, string $mac, string $vendor, string $hostname, array $vars=[], ?int $uid=null): array {
        nm_util_ensure($conn);
        $mac = strtoupper(trim($mac));
        if (!preg_match('/^([0-9A-F]{2}[:\-]){5}[0-9A-F]{2}$/',$mac)) return ['ok'=>false,'error'=>'invalid MAC'];
        $vend = nm_util_ztp_vendors(); if (!isset($vend[$vendor])) $vendor='generic';
        $vars['mac']=$mac; $vars['hostname']=$hostname ?: 'device-'.substr(str_replace([':','-'],'',$mac),-6);
        $vars['dns'] = $vars['dns'] ?? '1.1.1.1';
        $vars['ntp'] = $vars['ntp'] ?? 'pool.ntp.org';
        $content = nm_util_ztp_render($vendor, $vars);
        $base = strtolower(str_replace([':','-'],'',$mac)).'.'.$vend[$vendor]['ext'];
        $urlpath  = 'ztp/'.$base;              // how the device fetches it (URL path / TFTP path)
        $diskpath = 'firmware/'.$urlpath;      // on-disk under the HTTP firmware root (served + grab-audited)
        // queue the file write to the agent
        nm_util_cmd_queue($conn,$node_id,'write_file',['path'=>$diskpath,'content'=>$content],$uid);
        $st=$conn->prepare("INSERT INTO nm_util_ztp (node_id,mac,vendor,hostname,rendered_path,state,created_by)
            VALUES (?,?,?,?,?, 'pending', ?)
            ON DUPLICATE KEY UPDATE vendor=VALUES(vendor),hostname=VALUES(hostname),rendered_path=VALUES(rendered_path),state='pending',served_at=NULL,created_by=VALUES(created_by)");
        $st->bind_param('issssi',$node_id,$mac,$vendor,$vars['hostname'],$urlpath,$uid); $st->execute(); $st->close();
        if (function_exists('nm_audit')) { try { nm_audit($conn,'utilities.ztp.stage',['target_type'=>'utilities','target_id'=>$mac]); } catch (\Throwable $e) {} }
        return ['ok'=>true,'path'=>$urlpath,'preview'=>$content];
    }
    function nm_util_ztp_list($conn, int $node_id): array {
        nm_util_ensure($conn);
        $out=[]; $r=$conn->query("SELECT id,mac,vendor,hostname,rendered_path,state,created_at,served_at FROM nm_util_ztp WHERE node_id=".(int)$node_id." ORDER BY id DESC");
        while ($r && ($x=$r->fetch_assoc())) $out[]=$x;
        return $out;
    }
    // Candidate MACs for the ZTP wizard, pulled straight from the IPAM DHCP leases
    // (MAC↔IP↔hostname) — the killer tie-in.
    function nm_util_ztp_candidates($conn): array {
        if (!$conn->query("SHOW TABLES LIKE 'nm_ipam_leases'")->num_rows) return [];
        $out=[]; $r=$conn->query("SELECT DISTINCT mac,hostname,ip_address FROM nm_ipam_leases WHERE mac IS NOT NULL AND mac<>'' ORDER BY ip_address");
        while ($r && ($x=$r->fetch_assoc())) $out[]=$x;
        return $out;
    }
}
