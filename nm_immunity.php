<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Collective Immunity engine ("the vaccine"). A threat seen at ONE node
// (malicious domain in a Pi-hole query log, a port-scanning source IP in syslog,
// or a manual indicator) is turned into a block rule and FANNED OUT instantly to
// EVERY Pi-hole (DNS deny list, v6 write API) and firewall (SSH address-list /
// iptables). If one node is hit, the rest become immune automatically.
//
//   nm_imm_add_threat()  — register/dedup an indicator (status 'pending')
//   nm_imm_vaccinate()   — distribute the block to all Pi-holes / firewalls
//   nm_imm_revoke()      — pull the block back everywhere
//   nm_imm_detect_*()    — auto-discover threats from syslog / Pi-hole queries
//
// Page gate = permission key 'immunity'. Reuses [[netmon-pihole]] write proxy +
// [[netmon-config-manager]] Python SSH for the firewall push.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_pihole.php';
require_once __DIR__ . '/nm_confmgr.php';   // nm_cm_resolve_ssh + nm_cm_ssh_fetch + vendors
require_once __DIR__ . '/nm_audit.php';

if (!function_exists('nm_imm_vaccinate')) {

    function nm_imm_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        static $done=false; if($done) return; $done=true;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_threats (
            id INT AUTO_INCREMENT PRIMARY KEY,
            indicator VARCHAR(255) NOT NULL,
            ind_type VARCHAR(8) NOT NULL DEFAULT 'domain',   -- domain | regex | ip
            severity VARCHAR(8) NOT NULL DEFAULT 'high',
            source VARCHAR(40) NOT NULL DEFAULT 'manual',     -- manual | portscan | dns | feed
            detail VARCHAR(400) DEFAULT NULL,
            hits INT NOT NULL DEFAULT 1,
            status VARCHAR(10) NOT NULL DEFAULT 'pending',     -- pending | active | revoked | dismissed
            distributed_ok INT NOT NULL DEFAULT 0,
            distributed_fail INT NOT NULL DEFAULT 0,
            first_seen DATETIME DEFAULT NULL,
            last_seen DATETIME DEFAULT NULL,
            vaccinated_at DATETIME DEFAULT NULL,
            created_by INT DEFAULT NULL,
            UNIQUE KEY uniq_ind (indicator, ind_type),
            KEY idx_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_threat_actions (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            threat_id INT NOT NULL,
            target_type VARCHAR(10) NOT NULL,   -- pihole | firewall
            target_id INT DEFAULT NULL,
            target_name VARCHAR(120) DEFAULT NULL,
            status VARCHAR(10) NOT NULL,         -- ok | existed | failed
            detail VARCHAR(300) DEFAULT NULL,
            acted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            KEY idx_threat (threat_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        try { $conn->query("INSERT INTO role_profiles (role_name,button_key,enabled)
            SELECT 'admin','immunity',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='immunity')"); } catch (\Throwable $e) {}
        // which device(s) reported the threat (syslog source) — added 2026-06-25 so an
        // operator with multiple firewalls knows WHERE it was seen vs where the block lands.
        // (mysqli is in exception mode, so '@' won't swallow a duplicate-column error → guard.)
        $c=$conn->query("SHOW COLUMNS FROM nm_threats LIKE 'reported_by'");
        if ($c && $c->num_rows===0) $conn->query("ALTER TABLE nm_threats ADD COLUMN reported_by VARCHAR(200) DEFAULT NULL");
    }

    function nm_imm_setting($conn,$k,$d){ $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; }

    function nm_imm_get($conn,int $id){ $r=$conn->query("SELECT * FROM nm_threats WHERE id=".(int)$id." LIMIT 1"); return $r?$r->fetch_assoc():null; }

    // Register an indicator (dedup). Returns ['id','new'=>bool].
    function nm_imm_add_threat($conn, string $indicator, string $type='domain', string $source='manual', string $severity='high', string $detail='', ?int $uid=null, string $reportedBy=''): array {
        nm_imm_ensure($conn);
        $indicator = trim($indicator);
        $type = in_array($type,['domain','regex','ip'],true)?$type:'domain';
        if ($indicator==='') return ['ok'=>false,'error'=>'empty indicator'];
        $reportedBy = substr(trim($reportedBy),0,200);
        $ex = $conn->prepare("SELECT id FROM nm_threats WHERE indicator=? AND ind_type=? LIMIT 1");
        $ex->bind_param('ss',$indicator,$type); $ex->execute();
        if ($row=$ex->get_result()->fetch_assoc()) {
            $id=(int)$row['id'];
            if ($reportedBy!=='') { $u=$conn->prepare("UPDATE nm_threats SET hits=hits+1, last_seen=NOW(), reported_by=? WHERE id=?"); $u->bind_param('si',$reportedBy,$id); $u->execute(); }
            else $conn->query("UPDATE nm_threats SET hits=hits+1, last_seen=NOW() WHERE id={$id}");
            return ['ok'=>true,'id'=>$id,'new'=>false];
        }
        $st=$conn->prepare("INSERT INTO nm_threats (indicator,ind_type,severity,source,detail,reported_by,hits,status,first_seen,last_seen,created_by)
                            VALUES (?,?,?,?,?,?,1,'pending',NOW(),NOW(),?)");
        $st->bind_param('ssssssi',$indicator,$type,$severity,$source,$detail,$reportedBy,$uid);
        $st->execute(); return ['ok'=>true,'id'=>$conn->insert_id,'new'=>true];
    }

    function nm_imm_log_action($conn,$tid,$ttype,$tid2,$tname,$status,$detail){
        try {   // best-effort audit row — must NEVER abort the live SSH fan-out (mysqli throws in exception mode)
            $st=$conn->prepare("INSERT INTO nm_threat_actions (threat_id,target_type,target_id,target_name,status,detail) VALUES (?,?,?,?,?,?)");
            $tn=substr((string)$tname,0,120); $d=substr((string)$detail,0,300);   // fit VARCHAR(120)/(…) — a long device name would else throw "Data too long"
            $st->bind_param('isisss',$tid,$ttype,$tid2,$tn,$status,$d); $st->execute(); $st->close();
        } catch (\Throwable $e) {}
    }

    // Firewall enforcement targets = the Config-Manager devices the user designates.
    function nm_imm_firewall_targets($conn): array {
        $ids = array_filter(array_map('intval', explode(',', (string)nm_imm_setting($conn,'imm_fw_device_ids',''))));
        if (!$ids) return [];
        $in = implode(',', $ids);
        $out=[]; $r=$conn->query("SELECT id,name,host_ip,vendor_key,ssh_cred_id FROM nm_config_devices WHERE id IN ({$in})");
        while($r&&$x=$r->fetch_assoc()) $out[]=$x;
        return $out;
    }

    // Per-brand firewall block/unblock command (always prints NEURU_OK so the SSH
    // primitive sees non-empty output even when the rule command is silent).
    function nm_imm_fw_cmd(string $vendor, string $ip, bool $remove): string {
        $ip = preg_replace('/[^0-9a-fA-F.:\/]/','',$ip);
        if ($vendor === 'mikrotik') {
            return $remove
              ? ':do { /ip/firewall/address-list/remove [find where list=NEURU-BLOCK and address='.$ip.'] } on-error={}; :put NEURU_OK'
              : ':do { /ip/firewall/address-list/add list=NEURU-BLOCK address='.$ip.' comment=NEURU } on-error={}; :put NEURU_OK';
        }
        // linux / generic — iptables (idempotent)
        return $remove
          ? 'iptables -D INPUT -s '.$ip.' -j DROP 2>/dev/null; echo NEURU_OK'
          : '(iptables -C INPUT -s '.$ip.' -j DROP 2>/dev/null || iptables -I INPUT -s '.$ip.' -j DROP) ; echo NEURU_OK';
    }

    function nm_imm_push_firewall($conn, array $dev, string $ip, bool $remove=false): array {
        $ssh = nm_cm_resolve_ssh($conn, $dev);
        if (!$ssh) return ['ok'=>false,'detail'=>'no SSH credential'];
        $cmd = nm_imm_fw_cmd((string)$dev['vendor_key'], $ip, $remove);
        $res = nm_cm_ssh_fetch($ssh, $cmd, 25);
        $out = (string)($res['config'] ?? '');
        $ok  = strpos($out,'NEURU_OK')!==false;
        return ['ok'=>$ok, 'detail'=> $ok ? trim(str_replace('NEURU_OK','',$out)) ?: 'applied' : ($res['error'] ?? 'failed')];
    }

    // ── The vaccine: distribute the block to every Pi-hole / firewall ────────
    function nm_imm_vaccinate($conn, int $threatId): array {
        nm_imm_ensure($conn);
        $t = nm_imm_get($conn,$threatId); if(!$t) return ['ok'=>false,'error'=>'Threat not found'];
        $conn->query("DELETE FROM nm_threat_actions WHERE threat_id={$threatId}");
        $type=$t['ind_type']; $ind=$t['indicator']; $okc=0;$failc=0;
        if ($type==='domain' || $type==='regex') {
            $kind = $type==='regex'?'regex':'exact';
            foreach (nm_ph_servers($conn,true) as $S) {
                $r = nm_ph_add_deny($conn,(int)$S['id'],$ind,$kind,'NEURU immunity ['.$t['source'].']');
                $stt = $r['ok'] ? (($r['existed']??false)?'existed':'ok') : 'failed';
                nm_imm_log_action($conn,$threatId,'pihole',(int)$S['id'],$S['name'],$stt, $r['ok']?'deny added':($r['error']??''));
                if($r['ok'])$okc++; else $failc++;
            }
        } else { // ip → firewalls
            foreach (nm_imm_firewall_targets($conn) as $dev) {
                $r = nm_imm_push_firewall($conn,$dev,$ind,false);
                nm_imm_log_action($conn,$threatId,'firewall',(int)$dev['id'],$dev['name'], $r['ok']?'ok':'failed', $r['detail']??'');
                if($r['ok'])$okc++; else $failc++;
            }
        }
        try { $conn->query("UPDATE nm_threats SET status='active', distributed_ok={$okc}, distributed_fail={$failc}, vaccinated_at=NOW() WHERE id={$threatId}"); } catch (\Throwable $e) {}
        try { nm_audit($conn,'immunity.vaccinate',['target_type'=>'threat','target_id'=>$threatId,'details'=>['indicator'=>$ind,'type'=>$type,'ok'=>$okc,'fail'=>$failc]]); } catch (\Throwable $e) {}
        // Notification Center: a fleet-wide block is a security event.
        if (!function_exists('nm_notify_event')) { @include_once __DIR__.'/nm_notify.php'; }
        if (function_exists('nm_notify_event')) {
            $sev = (($t['severity']??'')==='high') ? 'critical' : 'warning';
            @nm_notify_event($conn,'security',$sev,"Threat blocked fleet-wide: {$ind}",
                "Type {$type} · distributed to {$okc} node(s)".($failc?" · {$failc} failed":"")." · source ".($t['source']??'manual'),
                ['entity'=>$ind,'source'=>'immunity']);
        }
        return ['ok'=>true,'distributed'=>$okc,'failed'=>$failc];
    }

    // Pull the block back everywhere.
    function nm_imm_revoke($conn, int $threatId): array {
        $t = nm_imm_get($conn,$threatId); if(!$t) return ['ok'=>false,'error'=>'Threat not found'];
        $type=$t['ind_type']; $ind=$t['indicator'];
        if ($type==='domain' || $type==='regex') {
            $kind = $type==='regex'?'regex':'exact';
            foreach (nm_ph_servers($conn,true) as $S) { try { nm_ph_remove_deny($conn,(int)$S['id'],$ind,$kind); } catch (\Throwable $e) {} }
        } else {
            foreach (nm_imm_firewall_targets($conn) as $dev) { try { nm_imm_push_firewall($conn,$dev,$ind,true); } catch (\Throwable $e) {} }
        }
        // always mark it revoked even if a target was unreachable (never leave it stuck 'active')
        try { $conn->query("DELETE FROM nm_threat_actions WHERE threat_id={$threatId}"); } catch (\Throwable $e) {}
        try { $conn->query("UPDATE nm_threats SET status='revoked', distributed_ok=0, distributed_fail=0 WHERE id={$threatId}"); } catch (\Throwable $e) {}
        try { nm_audit($conn,'immunity.revoke',['target_type'=>'threat','target_id'=>$threatId,'details'=>['indicator'=>$ind]]); } catch (\Throwable $e) {}
        return ['ok'=>true];
    }

    function nm_imm_set_status($conn,int $threatId,string $status){
        $status = in_array($status,['pending','dismissed','active'],true)?$status:'pending';
        $st=$conn->prepare("UPDATE nm_threats SET status=? WHERE id=?"); $st->bind_param('si',$status,$threatId); $st->execute();
    }

    function nm_imm_list($conn): array {
        nm_imm_ensure($conn);
        // PENDING first: they're the actionable ones (need vaccination). With active accumulating past
        // the row cap, an active-first order silently pushed every pending threat off the end of the
        // LIMIT → the list + "Pending" filter showed 0 despite many awaiting review. Cap raised too.
        $rows=[]; $r=$conn->query("SELECT * FROM nm_threats ORDER BY FIELD(status,'pending','active','revoked','dismissed'), last_seen DESC LIMIT 1000");
        while($r&&$x=$r->fetch_assoc()) $rows[]=$x;
        return $rows;
    }
    function nm_imm_actions($conn,int $threatId): array {
        $rows=[]; $st=$conn->prepare("SELECT * FROM nm_threat_actions WHERE threat_id=? ORDER BY id DESC LIMIT 100");
        $st->bind_param('i',$threatId); $st->execute(); $r=$st->get_result(); while($x=$r->fetch_assoc()) $rows[]=$x;
        return $rows;
    }
    function nm_imm_counts($conn): array {
        nm_imm_ensure($conn);
        $o=['active'=>0,'pending'=>0]; $r=$conn->query("SELECT status,COUNT(*) c FROM nm_threats WHERE status IN('active','pending') GROUP BY status");
        while($r&&$x=$r->fetch_assoc()) $o[$x['status']]=(int)$x['c'];
        return $o;
    }

    // ── Detection: port scans from syslog ────────────────────────────────────
    // Looks at recent firewall-style drop/deny syslog lines, extracts src→dst:port
    // and flags a source IP that hit many distinct destination ports.
    function nm_imm_detect_portscan($conn): array {
        $win  = (int)nm_imm_setting($conn,'imm_portscan_window','10') ?: 10;
        $minP = (int)nm_imm_setting($conn,'imm_portscan_ports','10') ?: 10;
        $found=[];
        if (!$conn->query("SHOW TABLES LIKE 'nm_syslog'")->num_rows) return $found;
        $r=$conn->query("SELECT hostname, host_ip, message FROM nm_syslog WHERE received_at>=DATE_SUB(NOW(),INTERVAL {$win} MINUTE)
            AND (message LIKE '%drop%' OR message LIKE '%deny%' OR message LIKE '%DROP%' OR message LIKE '%reject%') LIMIT 20000");
        $map=[]; $rep=[]; $tgt=[]; // src ip → set of dst ports / reporting devices / targets
        while($r&&$x=$r->fetch_assoc()){
            if (preg_match('/(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s*->\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d+)/', $x['message'], $m)) {
                $src=$m[1]; $map[$src][$m[4]]=1; $tgt[$src][$m[3]]=1;
                $h=trim((string)$x['hostname']); $hip=trim((string)$x['host_ip']);
                // label as "hostname (ip)" so it's unambiguous which device — and so the
                // enforcement-point cross-check can match on either the name or the IP.
                $dev = $h!=='' ? ($hip!=='' && stripos($h,$hip)===false ? $h.' ('.$hip.')' : $h) : $hip;
                if($dev!==''){ $rep[$src][$dev]=($rep[$src][$dev]??0)+1; }
            }
        }
        foreach($map as $src=>$ports){
            if (count($ports) < $minP) continue;
            $devs=$rep[$src]??[]; arsort($devs); $devList=array_slice(array_keys($devs),0,3);
            $found[] = ['ip'=>$src,'ports'=>count($ports),
                'reported_by'=>implode(', ',$devList),
                'target'=>$tgt[$src]?array_key_first($tgt[$src]):''];
        }
        return $found;
    }

    // ── Detection: malicious DNS from a Pi-hole's recent queries ──────────────
    // Matches queried domains against the admin's threat regex list (one per line).
    function nm_imm_detect_dns($conn): array {
        $raw = trim((string)nm_imm_setting($conn,'imm_dns_patterns',''));
        if ($raw==='') return [];
        $pats=[]; foreach(preg_split('/\r?\n/',$raw) as $p){ $p=trim($p); if($p!=='' && $p[0]!=='#') $pats[]=$p; }
        if (!$pats) return [];
        $id = nm_ph_default_id($conn); if(!$id) return [];
        $q = nm_ph_call($conn,$id,'queries',['length'=>2000]);
        if (empty($q['ok'])) return [];
        $rows = $q['data']['queries'] ?? [];
        $hit=[];
        foreach($rows as $qr){
            $dom = strtolower((string)($qr['domain'] ?? '')); if($dom==='') continue;
            foreach($pats as $p){
                $rx = '~'.str_replace('~','\~',$p).'~i';
                if (@preg_match($rx,$dom)) { $hit[$dom]=true; break; }
            }
        }
        return array_keys($hit);
    }
}
