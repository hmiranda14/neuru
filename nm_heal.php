<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Autonomous Self-Healing orchestrator. Detect → (propose|act) → REVERT.
//
// SAFETY FIRST. Each playbook has a mode:
//   off        — nothing (default)
//   armed      — detect + create a PROPOSED action; a human approves it
//   autonomous — act immediately, then AUTO-REVERT after auto_revert_min minutes
//                (so a wrong action self-heals) — manual revert always available.
//
// Detectors: port-scan (syslog, reuses Immunity), NTP amplification (NetFlow),
// L2 loop / broadcast storm (syslog). Actions are REVERSIBLE and time-boxed:
//   block_ip      — firewall address-list / iptables (reuses [[netmon-immunity]] push)
//   isolate_port  — shut the offending interface over SSH (reuses Router Commander)
//
// Page gate = permission key 'heal'.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_immunity.php';   // firewall push + portscan detector
require_once __DIR__ . '/nm_confmgr.php';    // nm_cm_ssh_fetch
require_once __DIR__ . '/nm_secrets.php';     // nm_ssh_resolve
require_once __DIR__ . '/nm_audit.php';

if (!function_exists('nm_heal_run')) {

    function nm_heal_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        static $done=false; if($done) return; $done=true;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_heal_playbooks (
            pb_key VARCHAR(24) PRIMARY KEY,
            name VARCHAR(80) NOT NULL,
            detector VARCHAR(24) NOT NULL,
            action VARCHAR(24) NOT NULL,
            mode VARCHAR(10) NOT NULL DEFAULT 'off',     -- off | armed | auto
            auto_revert_min INT NOT NULL DEFAULT 15,
            threshold INT NOT NULL DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_heal_events (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            pb_key VARCHAR(24) NOT NULL,
            indicator VARCHAR(120) NOT NULL,
            kind VARCHAR(8) NOT NULL DEFAULT 'ip',       -- ip | port
            trigger_detail VARCHAR(400) DEFAULT NULL,
            action VARCHAR(24) NOT NULL DEFAULT 'none',
            status VARCHAR(10) NOT NULL DEFAULT 'proposed', -- proposed|active|reverted|failed|dismissed
            report VARCHAR(600) DEFAULT NULL,
            revert_at DATETIME DEFAULT NULL,
            detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            acted_at DATETIME DEFAULT NULL,
            reverted_at DATETIME DEFAULT NULL,
            KEY idx_status (status), KEY idx_ind (indicator)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // Seed the playbooks once (all OFF — safe).
        $r=$conn->query("SELECT COUNT(*) c FROM nm_heal_playbooks");
        if ($r && (int)$r->fetch_assoc()['c']===0) {
            $seed=[
                ['portscan','Port-scan source','portscan','block_ip',15,10],
                ['ntp_amp','NTP amplification','ntp_amp','block_ip',20,50],
                ['l2_loop','L2 loop / broadcast storm','l2_loop','isolate_port',10,0],
            ];
            $st=$conn->prepare("INSERT INTO nm_heal_playbooks (pb_key,name,detector,action,mode,auto_revert_min,threshold) VALUES (?,?,?,?,'off',?,?)");
            foreach($seed as $s){ $st->bind_param('ssssii',$s[0],$s[1],$s[2],$s[3],$s[4],$s[5]); $st->execute(); }
            $st->close();
        }
        // Idempotently add newer playbooks to existing installs (INSERT IGNORE on the
        // pb_key PK — never disturbs a playbook the operator already configured). All OFF.
        $more=[
            ['ssh_bruteforce','SSH/RDP brute-force','ssh_bruteforce','block_ip',30,8],
            ['internal_scan','Internal host scanning (lateral)','internal_scan','block_ip',15,10],
            ['crypto_mining','Crypto-mining traffic','crypto_mining','block_ip',60,1],
            ['flood_dos','SYN/UDP flood (DoS)','flood','block_ip',15,800],
            ['web_attack','Web attack (SQLi/RCE/scanner)','web_attack','block_ip',30,5],
        ];
        $st=$conn->prepare("INSERT IGNORE INTO nm_heal_playbooks (pb_key,name,detector,action,mode,auto_revert_min,threshold) VALUES (?,?,?,?,'off',?,?)");
        foreach($more as $s){ $st->bind_param('ssssii',$s[0],$s[1],$s[2],$s[3],$s[4],$s[5]); $st->execute(); }
        $st->close();
        // which device reported the event (syslog source) — for "router not enabled for healing" UX.
        // (mysqli is in exception mode → '@' won't swallow a duplicate-column error → guard.)
        $cc=$conn->query("SHOW COLUMNS FROM nm_heal_events LIKE 'reported_by'");
        if ($cc && $cc->num_rows===0) $conn->query("ALTER TABLE nm_heal_events ADD COLUMN reported_by VARCHAR(200) DEFAULT NULL");
        $cc=$conn->query("SHOW COLUMNS FROM nm_heal_events LIKE 'evidence_json'");   // frozen proof captured AT detection
        if ($cc && $cc->num_rows===0) $conn->query("ALTER TABLE nm_heal_events ADD COLUMN evidence_json MEDIUMTEXT DEFAULT NULL");
        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled)
            SELECT 'admin','heal',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='heal')");
    }

    function nm_heal_setting($conn,$k,$d){ $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; }
    function nm_heal_playbooks($conn): array { nm_heal_ensure($conn); $o=[]; $r=$conn->query("SELECT * FROM nm_heal_playbooks ORDER BY name"); while($r&&$x=$r->fetch_assoc())$o[]=$x; return $o; }
    function nm_heal_pb($conn,$k){ $st=$conn->prepare("SELECT * FROM nm_heal_playbooks WHERE pb_key=? LIMIT 1"); $st->bind_param('s',$k); $st->execute(); return $st->get_result()->fetch_assoc()?:null; }
    function nm_heal_pb_save($conn,$k,$mode,$revert,$threshold){
        $mode=in_array($mode,['off','armed','auto'],true)?$mode:'off';
        $st=$conn->prepare("UPDATE nm_heal_playbooks SET mode=?,auto_revert_min=?,threshold=? WHERE pb_key=?");
        $rv=max(1,(int)$revert); $th=max(0,(int)$threshold); $st->bind_param('siis',$mode,$rv,$th,$k); $st->execute();
    }
    function nm_heal_event($conn,$id){ $r=$conn->query("SELECT * FROM nm_heal_events WHERE id=".(int)$id." LIMIT 1"); return $r?$r->fetch_assoc():null; }
    function nm_heal_events($conn,int $limit=200): array { nm_heal_ensure($conn); $o=[]; $r=$conn->query("SELECT * FROM nm_heal_events ORDER BY FIELD(status,'active','proposed','failed','reverted','dismissed'), id DESC LIMIT ".(int)$limit); while($r&&$x=$r->fetch_assoc())$o[]=$x; return $o; }

    // Create an event (dedup: skip if an active/proposed event for the same indicator exists).
    function nm_heal_event_add($conn,$pbKey,$indicator,$kind,$detail,$action,$reportedBy=''){
        $ex=$conn->prepare("SELECT id FROM nm_heal_events WHERE indicator=? AND status IN('proposed','active') LIMIT 1");
        $ex->bind_param('s',$indicator); $ex->execute();
        if($row=$ex->get_result()->fetch_assoc()) return ['id'=>(int)$row['id'],'new'=>false];
        $rb=substr((string)$reportedBy,0,200);
        $st=$conn->prepare("INSERT INTO nm_heal_events (pb_key,indicator,kind,trigger_detail,action,reported_by,status) VALUES (?,?,?,?,?,?, 'proposed')");
        $d=substr((string)$detail,0,400); $st->bind_param('ssssss',$pbKey,$indicator,$kind,$d,$action,$rb); $st->execute();
        $id=(int)$conn->insert_id;
        // FREEZE the firewall-log evidence NOW — at detection the syslog/flows are fresh, so review
        // later shows the ACTUAL proof that triggered this, not an empty live re-query after the log
        // rotated. This is the whole basis for trusting an autonomous decision.
        if (function_exists('nm_heal_gather_evidence')) {
            $snap = nm_heal_gather_evidence($conn, (string)$indicator, 60);
            $snap['captured_at'] = date('Y-m-d H:i:s');
            $conn->query("UPDATE nm_heal_events SET evidence_json='".$conn->real_escape_string(json_encode($snap))."' WHERE id={$id}");
        }
        return ['id'=>$id,'new'=>true];
    }

    // ── Reversible actions ───────────────────────────────────────────────────
    function nm_heal_do_block_ip($conn,string $ip,bool $remove): array {
        $okc=0;$failc=0;$names=[];
        foreach(nm_imm_firewall_targets($conn) as $dev){ $r=nm_imm_push_firewall($conn,$dev,$ip,$remove); if(!empty($r['ok'])){$okc++;$names[]=$dev['name'];} else $failc++; }
        return ['ok'=>($okc>0),'count'=>$okc,'fail'=>$failc,'targets'=>$names];
    }
    // indicator "nodeId:ifname" → SSH shut/unshut the interface.
    function nm_heal_do_isolate_port($conn,string $indicator,bool $remove): array {
        if(strpos($indicator,':')===false) return ['ok'=>false,'detail'=>'need node:iface'];
        [$nid,$ifn]=explode(':',$indicator,2); $nid=(int)$nid;
        $ssh=function_exists('nm_ssh_resolve')?nm_ssh_resolve($conn,$nid):null;
        if(!$ssh) return ['ok'=>false,'detail'=>'no SSH credential for node'];
        // brand from node os_icon → vendor
        $os=''; $r=$conn->query("SELECT os_icon FROM nm_nodes WHERE id={$nid} LIMIT 1"); if($r&&$x=$r->fetch_row())$os=$x[0];
        $vendor=function_exists('nm_cm_guess_vendor')?nm_cm_guess_vendor($os):'generic';
        $ifn=preg_replace('/[^A-Za-z0-9_.\-\/ ]/','',$ifn);
        if($vendor==='mikrotik') $cmd=':do { /interface set [find name="'.$ifn.'"] disabled='.($remove?'no':'yes').' } on-error={}; :put NEURU_OK';
        else                     $cmd='ip link set "'.$ifn.'" '.($remove?'up':'down').' 2>/dev/null; echo NEURU_OK';
        $res=nm_cm_ssh_fetch($ssh,$cmd,25);
        $ok=strpos((string)($res['config']??''),'NEURU_OK')!==false;
        return ['ok'=>$ok,'detail'=>$ok?($remove?'interface re-enabled':'interface disabled'):($res['error']??'failed')];
    }

    // Execute the event's action; arm the auto-revert timer.
    function nm_heal_act($conn,int $eventId): array {
        nm_heal_ensure($conn);
        $e=nm_heal_event($conn,$eventId); if(!$e) return ['ok'=>false,'error'=>'event not found'];
        if($e['status']==='active') return ['ok'=>true,'already'=>true];
        $pb=nm_heal_pb($conn,$e['pb_key']); $revertMin=$pb?(int)$pb['auto_revert_min']:15;
        $action=$e['action']; $ind=$e['indicator']; $report=''; $ok=false;
        if($action==='block_ip'){ $r=nm_heal_do_block_ip($conn,$ind,false); $ok=$r['ok'];
            $where = !empty($r['targets']) ? implode(', ',$r['targets']) : 'no firewall enforcement points configured';
            $report='Blocked '.$ind.' on '.$where.($r['fail']?(' ('.$r['fail'].' failed)'):'').'. Auto-revert in '.$revertMin.' min.'; }
        elseif($action==='isolate_port'){ $r=nm_heal_do_isolate_port($conn,$ind,false); $ok=$r['ok']; $report='Isolate port '.$ind.': '.$r['detail'].'. Auto-revert in '.$revertMin.' min.'; }
        else { $report='No automatic action for this playbook.'; $ok=true; }
        $status=$ok?'active':'failed';
        $revertAt=$ok && $action!=='none' ? date('Y-m-d H:i:s', time()+$revertMin*60) : null;
        $st=$conn->prepare("UPDATE nm_heal_events SET status=?, report=?, acted_at=NOW(), revert_at=? WHERE id=?");
        $rp=substr($report,0,600); $st->bind_param('sssi',$status,$rp,$revertAt,$eventId); $st->execute();
        nm_audit($conn,'heal.act',['target_type'=>'heal_event','target_id'=>$eventId,'details'=>['action'=>$action,'indicator'=>$ind,'ok'=>$ok]]);
        return ['ok'=>$ok,'report'=>$report];
    }

    // Undo the action.
    function nm_heal_revert($conn,int $eventId): array {
        $e=nm_heal_event($conn,$eventId); if(!$e) return ['ok'=>false,'error'=>'event not found'];
        if($e['action']==='block_ip')      @nm_heal_do_block_ip($conn,$e['indicator'],true);
        elseif($e['action']==='isolate_port') @nm_heal_do_isolate_port($conn,$e['indicator'],true);
        $conn->query("UPDATE nm_heal_events SET status='reverted', reverted_at=NOW() WHERE id=".(int)$eventId);
        nm_audit($conn,'heal.revert',['target_type'=>'heal_event','target_id'=>$eventId]);
        return ['ok'=>true];
    }
    function nm_heal_dismiss($conn,int $eventId){ $conn->query("UPDATE nm_heal_events SET status='dismissed' WHERE id=".(int)$eventId); }

    // Auto-revert anything whose timer expired.
    function nm_heal_auto_revert($conn): int {
        nm_heal_ensure($conn); $n=0;
        $r=$conn->query("SELECT id FROM nm_heal_events WHERE status='active' AND revert_at IS NOT NULL AND revert_at<=NOW()");
        $ids=[]; while($r&&$x=$r->fetch_row())$ids[]=(int)$x[0];
        foreach($ids as $id){ nm_heal_revert($conn,$id); $n++; }
        return $n;
    }

    // ── Detectors ────────────────────────────────────────────────────────────
    function nm_heal_det_portscan($conn,$pb): array {
        // reuse Immunity's syslog port-scan parser (it already returns reported_by + target)
        $out=[]; $min=max(2,(int)$pb['threshold']);
        foreach(nm_imm_detect_portscan($conn) as $p){
            if($p['ports']<$min) continue;
            $dev=$p['reported_by']??''; $tgt=$p['target']??'';
            $detail='Port scan — '.$p['ports'].' distinct ports'.($tgt?(' → '.$tgt):'').($dev?(' · seen by '.$dev):'');
            $out[]=['indicator'=>$p['ip'],'kind'=>'ip','detail'=>$detail,'reported_by'=>$dev];
        }
        return $out;
    }

    // ── Evidence: the raw facts behind an event so an operator can judge real-vs-false ──
    // Gather the raw firewall-log (nm_syslog) + NetFlow evidence for an indicator over $win minutes.
    // Called BOTH at detection (to freeze the proof) and at review (to check for recurrence).
    function nm_heal_gather_evidence($conn, string $ind, int $win=30): array {
        $ip = preg_match('/^\d{1,3}(?:\.\d{1,3}){3}$/',$ind) ? $ind : '';
        $needle = $ip ?: trim(preg_replace('/\s.*$/','',$ind));
        $ports=[]; $devs=[]; $targets=[]; $samples=[]; $n=0; $first=null; $last=null;
        if($needle!=='' && $conn->query("SHOW TABLES LIKE 'nm_syslog'")->num_rows){
            $esc=$conn->real_escape_string($needle);
            $r=$conn->query("SELECT received_at,hostname,host_ip,message FROM nm_syslog
                WHERE received_at>=DATE_SUB(NOW(),INTERVAL ".(int)$win." MINUTE) AND message LIKE '%{$esc}%'
                ORDER BY received_at DESC LIMIT 800");
            while($r&&$x=$r->fetch_assoc()){
                $n++; if($last===null)$last=$x['received_at']; $first=$x['received_at'];
                $dev=$x['hostname']?:$x['host_ip']; if($dev)$devs[$dev]=($devs[$dev]??0)+1;
                if($ip && preg_match('/'.preg_quote($ip,'/').':(\d+)\s*->\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d+)/',$x['message'],$m)){
                    $targets[$m[2]]=($targets[$m[2]]??0)+1; $ports[(int)$m[3]]=1; }
                if(count($samples)<12) $samples[]=['at'=>$x['received_at'],'dev'=>$dev,'msg'=>mb_substr((string)$x['message'],0,220)];
            }
            arsort($devs); arsort($targets);
        }
        $pl=array_map('intval',array_keys($ports)); sort($pl);
        $nf=[];
        if($ip!=='' && $conn->query("SHOW TABLES LIKE 'nm_netflow_flows'")->num_rows){
            $escip=$conn->real_escape_string($ip);
            $r=$conn->query("SELECT dst_ip, app_port, protocol, SUM(bytes) b, SUM(packets) p FROM nm_netflow_flows
                WHERE (src_ip='$escip' OR dst_ip='$escip') AND bucket>=DATE_SUB(NOW(),INTERVAL 10 MINUTE)
                GROUP BY dst_ip,app_port,protocol ORDER BY b DESC LIMIT 8");
            while($r&&$x=$r->fetch_assoc()) $nf[]=['dst'=>$x['dst_ip'],'port'=>(int)$x['app_port'],
                'mbps'=>round(((float)$x['b']*8)/600/1e6,3),'pkts'=>(int)$x['p']];
        }
        return ['lines'=>$n,'first'=>$first,'last'=>$last,'window_min'=>$win,
            'devices'=>array_keys($devs),'targets'=>array_keys($targets),'ports'=>$pl,'samples'=>$samples,'netflow'=>$nf];
    }

    // Returns GeoIP/rDNS for IP indicators + the syslog drop-log evidence (which device
    // reported it, the scanned target(s), distinct ports hit, and sample lines).
    function nm_heal_evidence($conn,int $eventId): array {
        $e=nm_heal_event($conn,$eventId); if(!$e) return ['ok'=>false,'error'=>'event not found'];
        $ind=(string)$e['indicator'];
        $ip = preg_match('/^\d{1,3}(?:\.\d{1,3}){3}$/',$ind) ? $ind : '';
        $geo=null; $rdns=null;
        if($ip){ @require_once __DIR__.'/nm_nettools.php';
            if(function_exists('nm_nt_geoip')){ $g=nm_nt_geoip($conn,$ip); $geo=($g&&empty($g['private']))?$g:($g?['private'=>true]:null); }
            $rd=@gethostbyaddr($ip); if($rd && $rd!==$ip) $rdns=$rd;
        }
        // PROOF = the evidence FROZEN at detection (evidence_json). Only fall back to a live gather for
        // legacy events that predate snapshots. Always ALSO gather live → is this still happening now?
        $snap = !empty($e['evidence_json']) ? json_decode((string)$e['evidence_json'], true) : null;
        $live = nm_heal_gather_evidence($conn, $ind, 30);
        $useSnap = ($snap && (int)($snap['lines'] ?? 0) > 0);
        $EV = $useSnap ? $snap : $live;
        $nf        = $EV['netflow'] ?? [];
        $rawDevs   = $EV['devices'] ?? [];
        $pl        = array_map('intval', $EV['ports'] ?? []);
        $targetsK  = $EV['targets'] ?? [];
        $samples   = $EV['samples'] ?? [];
        $n = (int)($EV['lines'] ?? 0); $first = $EV['first'] ?? null; $last = $EV['last'] ?? null; $win = (int)($EV['window_min'] ?? 30);
        $evSource   = $useSnap ? 'snapshot' : ((int)$live['lines'] > 0 ? 'live' : 'none');
        $capturedAt = $snap['captured_at'] ?? null;
        $liveLines  = (int)$live['lines'];
        // Resolve the raw syslog reporters ("x86 (10.10.0.1)") to the NEURU node NAME the
        // user knows, by matching ip/hostname against nm_nodes.
        $nodeByIp=[]; $nodeByHost=[];
        if($nr=$conn->query("SELECT display_name,ip_address,hostname FROM nm_nodes")){
            while($x=$nr->fetch_assoc()){ if(!empty($x['ip_address']))$nodeByIp[$x['ip_address']]=$x['display_name'];
                if(!empty($x['hostname']))$nodeByHost[strtolower($x['hostname'])]=$x['display_name']; }
        }
        $repNames=[]; $repEnforced=false;
        // firewall enforcement points the block actually lands on
        $fwNames=[]; $fwIps=[]; $fwList=[];
        foreach(nm_imm_firewall_targets($conn) as $d){ $fwList[]=$d['name']; $fwNames[strtolower($d['name'])]=1; if(!empty($d['host_ip']))$fwIps[$d['host_ip']]=1; }
        foreach($rawDevs as $rd){
            $rip=''; if(preg_match('/(\d{1,3}(?:\.\d{1,3}){3})/',$rd,$mm))$rip=$mm[1];
            $rhost=trim(preg_replace('/\s*\(.*$/','',$rd));
            $nm = ($rip!==''&&isset($nodeByIp[$rip]))?$nodeByIp[$rip] : (($rhost!==''&&isset($nodeByHost[strtolower($rhost)]))?$nodeByHost[strtolower($rhost)] : $rd);
            $repNames[]=$nm;
            if((isset($fwNames[strtolower($nm)])) || ($rip!==''&&isset($fwIps[$rip]))) $repEnforced=true;
        }
        return ['ok'=>true,'indicator'=>$ind,'kind'=>$e['kind'],'pb'=>$e['pb_key'],'action'=>$e['action'],
            'status'=>$e['status'],'detail'=>$e['trigger_detail'],'report'=>$e['report'],
            'detected_at'=>$e['detected_at'],'acted_at'=>$e['acted_at']??null,'revert_at'=>$e['revert_at'],
            'geo'=>$geo,'rdns'=>$rdns,'netflow'=>$nf,
            'reported_names'=>$repNames,'reported_enforced'=>$repEnforced,
            'enforce_points'=>$fwList,'is_ip'=>($ip!==''),
            'evidence'=>['lines'=>$n,'first'=>$first,'last'=>$last,'window_min'=>$win,
                'source'=>$evSource,'captured_at'=>$capturedAt,'live_lines'=>$liveLines,
                'devices'=>$rawDevs,'reported_names'=>$repNames,'targets'=>$targetsK,'ports'=>$pl,'samples'=>$samples]];
    }
    function nm_heal_det_ntp($conn,$pb): array {
        // NetFlow: external IPs with abnormal UDP/123 (NTP) byte volume in recent buckets.
        $out=[]; if(!$conn->query("SHOW TABLES LIKE 'nm_netflow_flows'")->num_rows) return $out;
        $thrMbps=max(1,(int)$pb['threshold']);
        $r=$conn->query("SELECT ip, SUM(b) tot FROM (
              SELECT dst_ip ip, bytes b FROM nm_netflow_flows WHERE bucket>=DATE_SUB(NOW(),INTERVAL 5 MINUTE) AND protocol=17 AND app_port=123
              UNION ALL
              SELECT src_ip ip, bytes b FROM nm_netflow_flows WHERE bucket>=DATE_SUB(NOW(),INTERVAL 5 MINUTE) AND protocol=17 AND app_port=123
            ) t GROUP BY ip ORDER BY tot DESC LIMIT 20");
        while($r&&$x=$r->fetch_assoc()){
            $mbps=($x['tot']*8)/300/1e6;   // over the 5-min window
            $ip=$x['ip'];
            if($mbps>=$thrMbps && !preg_match('/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/',$ip))
                $out[]=['indicator'=>$ip,'kind'=>'ip','detail'=>'NTP amplification — '.round($mbps,1).' Mbps UDP/123'];
        }
        return $out;
    }
    function nm_heal_det_l2loop($conn,$pb): array {
        $out=[]; if(!$conn->query("SHOW TABLES LIKE 'nm_syslog'")->num_rows) return $out;
        $r=$conn->query("SELECT hostname,host_ip,message FROM nm_syslog WHERE received_at>=DATE_SUB(NOW(),INTERVAL 5 MINUTE)
            AND (message LIKE '%loop detected%' OR message LIKE '%broadcast storm%' OR message LIKE '%storm control%'
                 OR message LIKE '%mac % flap%' OR message LIKE '%MAC flapping%' OR message LIKE '%moved from%to%') LIMIT 200");
        $seen=[];
        while($r&&$x=$r->fetch_assoc()){
            $host=$x['hostname']?:$x['host_ip']; if(isset($seen[$host]))continue; $seen[$host]=1;
            // try to extract an interface name
            $if=''; if(preg_match('/\b(ether\d+|sfp\d+|eth\d+|Gi\d+\/\d+|port\s*\d+|bridge\d*)\b/i',$x['message'],$m)) $if=$m[1];
            $out[]=['indicator'=>$host.($if?(' '.$if):''),'kind'=>'port','detail'=>'L2 loop/storm on '.$host.($if?(" ($if)"):'').' — '.substr($x['message'],0,120)];
        }
        return $out;
    }

    // label a syslog reporter as "hostname (ip)" so it's unambiguous + cross-checkable
    function nm_heal_dev_label($host,$hip): string {
        $h=trim((string)$host); $i=trim((string)$hip);
        return $h!=='' ? ($i!=='' && stripos($h,$i)===false ? $h.' ('.$i.')' : $h) : $i;
    }
    // helper: is this an RFC1918 / loopback (internal) address?
    function nm_heal_is_internal(string $ip): bool {
        return (bool)preg_match('/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/',$ip);
    }

    // ── SSH/RDP brute-force: repeated failed logins from one source (syslog) ──────
    function nm_heal_det_ssh_bruteforce($conn,$pb): array {
        $out=[]; if(!$conn->query("SHOW TABLES LIKE 'nm_syslog'")->num_rows) return $out;
        $win=10; $min=max(3,(int)$pb['threshold']);
        $r=$conn->query("SELECT hostname,host_ip,message FROM nm_syslog WHERE received_at>=DATE_SUB(NOW(),INTERVAL {$win} MINUTE)
            AND (message LIKE '%Failed password%' OR message LIKE '%authentication failure%' OR message LIKE '%login failure%'
                 OR message LIKE '%invalid user%' OR message LIKE '%failed login%' OR message LIKE '%Invalid login%'
                 OR message LIKE '%auth fail%' OR message LIKE '%bad password%') LIMIT 20000");
        $cnt=[]; $rep=[];
        while($r&&$x=$r->fetch_assoc()){
            $ip='';
            if(preg_match('/from\s+(\d{1,3}(?:\.\d{1,3}){3})/i',$x['message'],$m)) $ip=$m[1];
            elseif(preg_match('/(\d{1,3}(?:\.\d{1,3}){3})/',$x['message'],$m)) $ip=$m[1];
            if($ip==='' || $ip==='127.0.0.1') continue;
            $cnt[$ip]=($cnt[$ip]??0)+1;
            $dev=nm_heal_dev_label($x['hostname']??'',$x['host_ip']??''); if($dev!=='') $rep[$ip][$dev]=($rep[$ip][$dev]??0)+1;
        }
        foreach($cnt as $ip=>$c){ if($c<$min) continue; $devs=$rep[$ip]??[]; arsort($devs); $dev=$devs?array_key_first($devs):'';
            $out[]=['indicator'=>$ip,'kind'=>'ip','detail'=>'Brute-force — '.$c.' failed logins in '.$win.'m'.($dev?(' · seen by '.$dev):''),'reported_by'=>$dev]; }
        return $out;
    }

    // ── Internal host scanning: an INSIDE host hitting many ports (lateral move) ──
    function nm_heal_det_internal_scan($conn,$pb): array {
        $out=[]; if(!$conn->query("SHOW TABLES LIKE 'nm_syslog'")->num_rows) return $out;
        $win=10; $min=max(5,(int)$pb['threshold']);
        $r=$conn->query("SELECT hostname,host_ip,message FROM nm_syslog WHERE received_at>=DATE_SUB(NOW(),INTERVAL {$win} MINUTE)
            AND (message LIKE '%drop%' OR message LIKE '%deny%' OR message LIKE '%reject%') LIMIT 20000");
        $map=[]; $rep=[];
        while($r&&$x=$r->fetch_assoc()){
            if(preg_match('/(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s*->\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d+)/',$x['message'],$m)){
                if(!nm_heal_is_internal($m[1])) continue;   // INSIDE source only
                $map[$m[1]][$m[4]]=1;
                $dev=nm_heal_dev_label($x['hostname']??'',$x['host_ip']??''); if($dev!=='') $rep[$m[1]][$dev]=($rep[$m[1]][$dev]??0)+1;
            }
        }
        foreach($map as $src=>$ports){ if(count($ports)<$min) continue;
            $devs=$rep[$src]??[]; arsort($devs); $dev=$devs?array_key_first($devs):'';
            $out[]=['indicator'=>$src,'kind'=>'ip','detail'=>'Internal host scanning — '.count($ports).' distinct ports (possible compromise / lateral movement)'.($dev?(' · seen by '.$dev):''),'reported_by'=>$dev]; }
        return $out;
    }

    // ── Crypto-mining: flows to known mining-pool ports (NetFlow) ─────────────────
    function nm_heal_det_crypto_mining($conn,$pb): array {
        $out=[]; if(!$conn->query("SHOW TABLES LIKE 'nm_netflow_flows'")->num_rows) return $out;
        $minMB=max(0.05,(float)$pb['threshold']?:1);   // threshold = min MB over 5m
        $ports='3333,3334,4444,5555,5556,7777,8333,9999,14444,45560,45700,1080'; // common pools/proxies
        $r=$conn->query("SELECT src_ip, dst_ip, app_port, SUM(bytes) b FROM nm_netflow_flows
            WHERE bucket>=DATE_SUB(NOW(),INTERVAL 5 MINUTE) AND app_port IN ($ports)
            GROUP BY src_ip,dst_ip,app_port HAVING b >= ".($minMB*1e6)." ORDER BY b DESC LIMIT 20");
        $seen=[];
        while($r&&$x=$r->fetch_assoc()){
            $ext = nm_heal_is_internal($x['dst_ip']) ? $x['src_ip'] : $x['dst_ip'];   // block the external peer
            $int = nm_heal_is_internal($x['dst_ip']) ? $x['dst_ip'] : $x['src_ip'];
            if(nm_heal_is_internal($ext) || isset($seen[$ext])) continue; $seen[$ext]=1;
            $out[]=['indicator'=>$ext,'kind'=>'ip','detail'=>'Crypto-mining pattern — '.$int.' ↔ '.$ext.':'.(int)$x['app_port'].' ('.round($x['b']/1e6,1).' MB/5m)'];
        }
        return $out;
    }

    // ── SYN/UDP flood (DoS): one external source at very high packet rate ─────────
    function nm_heal_det_flood($conn,$pb): array {
        $out=[]; if(!$conn->query("SHOW TABLES LIKE 'nm_netflow_flows'")->num_rows) return $out;
        $minPps=max(200,(int)$pb['threshold']);
        $r=$conn->query("SELECT src_ip, dst_ip, app_port, SUM(packets) p FROM nm_netflow_flows
            WHERE bucket>=DATE_SUB(NOW(),INTERVAL 2 MINUTE)
            GROUP BY src_ip,dst_ip,app_port ORDER BY p DESC LIMIT 12");
        while($r&&$x=$r->fetch_assoc()){
            $pps=(float)$x['p']/120.0;
            if($pps<$minPps || nm_heal_is_internal($x['src_ip'])) continue;
            $out[]=['indicator'=>$x['src_ip'],'kind'=>'ip','detail'=>'Possible flood/DoS — '.round($pps).' pkt/s → '.$x['dst_ip'].':'.(int)$x['app_port']];
        }
        return $out;
    }

    // ── Web attack: SQLi / path-traversal / RCE / scanner signatures (syslog) ─────
    function nm_heal_det_web_attack($conn,$pb): array {
        $out=[]; if(!$conn->query("SHOW TABLES LIKE 'nm_syslog'")->num_rows) return $out;
        $win=10; $min=max(3,(int)$pb['threshold']);
        $r=$conn->query("SELECT hostname,host_ip,message FROM nm_syslog WHERE received_at>=DATE_SUB(NOW(),INTERVAL {$win} MINUTE)
            AND (message LIKE '%union select%' OR message LIKE '%../../%' OR message LIKE '%/etc/passwd%'
                 OR message LIKE '%<script%' OR message LIKE '%base64_decode%' OR message LIKE '%wget %'
                 OR message LIKE '%curl %' OR message LIKE '%/bin/sh%' OR message LIKE '%cmd.exe%'
                 OR message LIKE '%sqlmap%' OR message LIKE '%nikto%' OR message LIKE '%nmap%'
                 OR message LIKE '%phpunit%' OR message LIKE '%/.env%' OR message LIKE '%xmlrpc.php%') LIMIT 20000");
        $cnt=[]; $rep=[];
        while($r&&$x=$r->fetch_assoc()){
            $ip=''; if(preg_match('/(\d{1,3}(?:\.\d{1,3}){3})/',$x['message'],$m)) $ip=$m[1];
            if($ip==='' || nm_heal_is_internal($ip)) continue;
            $cnt[$ip]=($cnt[$ip]??0)+1;
            $dev=nm_heal_dev_label($x['hostname']??'',$x['host_ip']??''); if($dev!=='') $rep[$ip][$dev]=($rep[$ip][$dev]??0)+1;
        }
        foreach($cnt as $ip=>$c){ if($c<$min) continue; $devs=$rep[$ip]??[]; arsort($devs); $dev=$devs?array_key_first($devs):'';
            $out[]=['indicator'=>$ip,'kind'=>'ip','detail'=>'Web attack signatures — '.$c.' hits (SQLi/traversal/RCE/scanner) in '.$win.'m'.($dev?(' · seen by '.$dev):''),'reported_by'=>$dev]; }
        return $out;
    }

    // ── The tick: run enabled playbooks ──────────────────────────────────────
    function nm_heal_run($conn): array {
        nm_heal_ensure($conn);
        $proposed=0;$acted=0;$reverted=nm_heal_auto_revert($conn);
        foreach(nm_heal_playbooks($conn) as $pb){
            if($pb['mode']==='off') continue;
            $det = 'nm_heal_det_'.$pb['detector'];
            if(!function_exists($det)) continue;
            foreach($det($conn,$pb) as $f){
                $ev = nm_heal_event_add($conn,$pb['pb_key'],$f['indicator'],$f['kind'],$f['detail'],$pb['action'],$f['reported_by']??'');
                if(empty($ev['new'])) continue;
                $proposed++;
                if($pb['mode']==='auto'){ $r=nm_heal_act($conn,(int)$ev['id']); if(!empty($r['ok']))$acted++; }
            }
        }
        return ['proposed'=>$proposed,'auto_acted'=>$acted,'auto_reverted'=>$reverted];
    }
    function nm_heal_counts($conn): array {
        nm_heal_ensure($conn); $o=['active'=>0,'proposed'=>0];
        $r=$conn->query("SELECT status,COUNT(*) c FROM nm_heal_events WHERE status IN('active','proposed') GROUP BY status");
        while($r&&$x=$r->fetch_assoc())$o[$x['status']]=(int)$x['c'];
        return $o;
    }
}
