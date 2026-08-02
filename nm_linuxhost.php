<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Linux host monitoring engine (agentless, over SSH). Exact mirror of
// nm_winhost.php but for Linux boxes: the data-COLLECTION layer runs native bash
// (journalctl / free / df / ps / ss / systemctl / sensors) via nm_cm_ssh_fetch
// instead of PowerShell. Everything returns the SAME normalized shape as the
// Windows engine so the UI (linux.php / linux_screen.php) is identical.
//
// GRAFANA ALLOY READY: each gather function (nm_lx_diagnose / nm_lx_poll_health)
// calls a private `_nm_lx_gather_*_ssh()` collector. To switch to Alloy/Prometheus
// later, add `_nm_lx_gather_*_alloy()` returning the SAME array and flip the source
// (setting `linux_source` = 'ssh'|'alloy'); the page/JSON contract never changes.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_confmgr.php';   // nm_cm_ssh_fetch + nm_cm_resolve_ssh
require_once __DIR__ . '/nm_secrets.php';   // nm_ssh_resolve / nm_secret_decrypt

if (!function_exists('nm_lx_ensure')) {

    function nm_lx_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_lx_hosts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(120) NOT NULL,
            node_id INT NULL, host_ip VARCHAR(64) NULL,
            enabled TINYINT(1) DEFAULT 1,
            status VARCHAR(16) DEFAULT 'new', last_error VARCHAR(255) NULL,
            os_caption VARCHAR(160) NULL,
            last_event_poll DATETIME NULL, last_health_poll DATETIME NULL,
            created_by INT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_lx_events (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            host_id INT NOT NULL, record_id BIGINT NOT NULL,
            log_name VARCHAR(60) NULL, event_id INT NULL, level TINYINT NULL,
            provider VARCHAR(160) NULL, message TEXT NULL,
            created_at DATETIME NULL, ingested_at DATETIME NULL,
            UNIQUE KEY uk_ev (host_id, record_id), INDEX idx_h (host_id, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_lx_health (
            host_id INT PRIMARY KEY, data MEDIUMTEXT NULL, sampled_at DATETIME NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_lx_watch (
            id INT AUTO_INCREMENT PRIMARY KEY,
            host_id INT NOT NULL, service_name VARCHAR(160) NOT NULL, display_name VARCHAR(200) NULL,
            auto_restart TINYINT(1) DEFAULT 0, last_state VARCHAR(20) NULL, last_checked DATETIME NULL,
            restart_count INT DEFAULT 0, last_action_at DATETIME NULL, last_restart_at DATETIME NULL,
            UNIQUE KEY uk_w (host_id, service_name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_lx_actions (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            host_id INT NOT NULL, service_name VARCHAR(160) NULL, action VARCHAR(30) NULL,
            ok TINYINT(1) NULL, detail VARCHAR(400) NULL, uid INT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // RBAC: seed 'linux' perm for admin (idempotent), mirrors the 'windows' perm.
        // role_profiles columns are role_name/button_key/enabled (NOT role/perm_key/allowed).
        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','linux',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='linux')");
        // Per-host data source (Phase 3): 'ssh' (default) or 'alloy' (Grafana Alloy scrape).
        // Guarded ALTER (mysqli is in EXCEPTION mode → must check before adding).
        foreach (['source'=>"VARCHAR(8) NOT NULL DEFAULT 'ssh'", 'alloy_url'=>"VARCHAR(255) NULL"] as $col=>$def) {
            $c=$conn->query("SELECT COUNT(*) c FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_lx_hosts' AND COLUMN_NAME='$col'");
            if ($c && (int)$c->fetch_assoc()['c']===0) $conn->query("ALTER TABLE nm_lx_hosts ADD COLUMN $col $def");
        }
    }
    // Read a global setting (nm_settings) with a default — used for Alloy defaults.
    function _nm_lx_setting($conn,string $k,string $def): string { $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return ($r && ($x=$r->fetch_assoc()) && $x['setting_val']!==null && $x['setting_val']!=='')?$x['setting_val']:$def; }
    function _nm_lx_err($conn,$hid,$msg){
        $down=(bool)preg_match('/unable to connect|connect failed|errno none|timed out|timeout|no route|refused|unreachable|host is down|network is unreachable|could not resolve|name or service not known|connection reset/i',$msg);
        $st=$down?'down':'error'; $cl=$down?'Host unreachable — appears DOWN (powered off or no network)':$msg;
        $m=$conn->real_escape_string(substr($cl,0,250)); $conn->query("UPDATE nm_lx_hosts SET status='$st', last_error='$m' WHERE id=".(int)$hid); }

    // ── Hosts CRUD ────────────────────────────────────────────────────────────
    function nm_lx_hosts($conn): array {
        nm_lx_ensure($conn); $out=[];
        $r=$conn->query("SELECT h.*, n.display_name node_name, n.ip_address node_ip,
                (SELECT COUNT(*) FROM nm_lx_events e WHERE e.host_id=h.id) event_count,
                (SELECT COUNT(*) FROM nm_lx_events e WHERE e.host_id=h.id AND e.level<=2 AND e.created_at>(UTC_TIMESTAMP()-INTERVAL 24 HOUR)) err24
            FROM nm_lx_hosts h LEFT JOIN nm_nodes n ON n.id=h.node_id ORDER BY h.name");
        while($r && ($x=$r->fetch_assoc())) $out[]=$x; return $out;
    }
    function nm_lx_host($conn,int $id): ?array { nm_lx_ensure($conn);
        $r=$conn->query("SELECT * FROM nm_lx_hosts WHERE id=".(int)$id." LIMIT 1"); return $r?($r->fetch_assoc()?:null):null; }
    function _nm_lx_src($v){ return ($v==='alloy')?'alloy':'ssh'; }
    function nm_lx_host_add($conn, array $f, ?int $uid): array { nm_lx_ensure($conn);
        $name=substr(trim((string)($f['name']??'')),0,120); if($name==='')return['ok'=>false,'error'=>'Name required'];
        $nid=($f['node_id']??'')!==''?(int)$f['node_id']:null; $ip=substr(trim((string)($f['host_ip']??'')),0,64)?:null;
        if(!$nid && !$ip) return['ok'=>false,'error'=>'Pick a node or enter a host IP'];
        $src=_nm_lx_src($f['source']??'ssh'); $au=substr(trim((string)($f['alloy_url']??'')),0,255)?:null;
        $st=$conn->prepare("INSERT INTO nm_lx_hosts (name,node_id,host_ip,source,alloy_url,enabled,created_by) VALUES (?,?,?,?,?,1,?)");
        $st->bind_param('sisssi',$name,$nid,$ip,$src,$au,$uid); $st->execute(); return['ok'=>true,'id'=>$conn->insert_id]; }
    function nm_lx_host_update($conn,int $id,array $f): array { nm_lx_ensure($conn);
        $name=substr(trim((string)($f['name']??'')),0,120); $nid=($f['node_id']??'')!==''?(int)$f['node_id']:null; $ip=substr(trim((string)($f['host_ip']??'')),0,64)?:null;
        $src=_nm_lx_src($f['source']??'ssh'); $au=substr(trim((string)($f['alloy_url']??'')),0,255)?:null;
        $st=$conn->prepare("UPDATE nm_lx_hosts SET name=?,node_id=?,host_ip=?,source=?,alloy_url=? WHERE id=?");
        $st->bind_param('sisssi',$name,$nid,$ip,$src,$au,$id); $st->execute(); return['ok'=>true]; }
    function nm_lx_host_delete($conn,int $id): array { nm_lx_ensure($conn);
        $conn->query("DELETE FROM nm_lx_events WHERE host_id=".(int)$id); $conn->query("DELETE FROM nm_lx_health WHERE host_id=".(int)$id);
        $conn->query("DELETE FROM nm_lx_watch WHERE host_id=".(int)$id); $conn->query("DELETE FROM nm_lx_hosts WHERE id=".(int)$id); return['ok'=>true]; }

    function nm_lx_resolve_ssh($conn, array $h): ?array {
        if (!empty($h['node_id'])) { $r=nm_ssh_resolve($conn,(int)$h['node_id']); if($r)return $r; }
        if (!empty($h['host_ip'])) return nm_cm_resolve_ssh($conn, ['host_ip'=>$h['host_ip'],'ssh_cred_id'=>0]);
        return null;
    }
    // Run a bash command over SSH (Linux default shell is sh/bash → no wrapper, unlike
    // Windows PowerShell). Single-line commands use exec_command (clean) per nm_cm_ssh_fetch.
    function nm_lx_sh($ssh, string $cmd, int $timeout=30): array { return nm_cm_ssh_fetch($ssh, $cmd, $timeout); }
    // Pull the first JSON value out of shell output (skip any banner).
    function _nm_lx_json(string $raw){ $raw=trim($raw); $p=strpos($raw,'['); $b=strpos($raw,'{');
        $s=($p===false)?$b:(($b===false)?$p:min($p,$b)); if($s===false)return null; return json_decode(substr($raw,$s),true); }

    // ── Event Log (journalctl) ────────────────────────────────────────────────
    // journald priority 0-4 → our level (1=crit,2=err,3=warn) to match Windows.
    function _nm_lx_events_cmd(int $mins, int $max): string {
        $mins=max(1,min(1440,$mins)); $max=max(1,min(500,$max));
        // -o json: one JSON object per line; we keep only emerg..warning.
        // Trailing sentinel guarantees NON-EMPTY stdout: a healthy quiet box with no recent
        // priority-0..4 entries returns nothing → nm_cm_ssh_fetch would (wrongly) call that an
        // "empty output" SSH failure. The parser ignores any line not starting with '{'.
        return "journalctl -p 0..4 --since '-{$mins}min' -o json --no-pager -n {$max} 2>/dev/null; echo __NM_LX_END__";
    }
    function nm_lx_parse_events(string $raw): array {
        $out=[]; foreach(preg_split('/\r?\n/',trim($raw)) as $line){ $line=trim($line); if($line===''||$line[0]!=='{')continue;
            $j=json_decode($line,true); if(!is_array($j))continue;
            $pri=isset($j['PRIORITY'])?(int)$j['PRIORITY']:6; $lvl=$pri<=2?1:($pri==3?2:3);
            $us=isset($j['__REALTIME_TIMESTAMP'])?(float)$j['__REALTIME_TIMESTAMP']:0;
            $rec=isset($j['__SEQNUM'])?(int)$j['__SEQNUM']:( $us?(int)($us):crc32($j['__CURSOR']??$line) );
            $msg=$j['MESSAGE']??''; if(is_array($msg))$msg=implode(' ',array_map('chr',$msg)); // byte-array msgs
            $out[]=['r'=>$rec,'t'=>$us?gmdate('Y-m-d H:i:s',(int)($us/1e6)):gmdate('Y-m-d H:i:s'),
                'lg'=>substr((string)($j['SYSLOG_FACILITY']??'journal'),0,60),'id'=>0,'lv'=>$lvl,
                'p'=>substr((string)($j['SYSLOG_IDENTIFIER']??$j['_COMM']??'system'),0,160),'m'=>preg_replace('/\s+/',' ',(string)$msg)];
        } return $out;
    }
    function nm_lx_poll_events($conn, array $h): array {
        nm_lx_ensure($conn); $hid=(int)$h['id']; $ssh=nm_lx_resolve_ssh($conn,$h);
        if(!$ssh||empty($ssh['username'])){ _nm_lx_err($conn,$hid,'No SSH credential resolved'); return['ok'=>false,'error'=>'no ssh']; }
        $mins=30; if(!empty($h['last_event_poll'])){ $age=time()-strtotime($h['last_event_poll'].' UTC'); $mins=max(2,min(1440,(int)ceil($age/60)+2)); }
        $res=nm_lx_sh($ssh,_nm_lx_events_cmd($mins,300),35);
        if(!$res['ok']){ _nm_lx_err($conn,$hid,'journalctl/SSH failed: '.substr((string)($res['error']??''),0,160)); return['ok'=>false,'error'=>'ssh failed']; }
        $rows=nm_lx_parse_events((string)$res['config']); $now=gmdate('Y-m-d H:i:s'); $ins=0;
        $st=$conn->prepare("INSERT IGNORE INTO nm_lx_events (host_id,record_id,log_name,event_id,level,provider,message,created_at,ingested_at) VALUES (?,?,?,?,?,?,?,?,?)");
        foreach($rows as $e){ $rid=(int)($e['r']??0); $lg=substr((string)($e['lg']??''),0,60); $eid=(int)($e['id']??0); $lv=(int)($e['lv']??3);
            $pv=substr((string)($e['p']??''),0,160); $msg=substr((string)($e['m']??''),0,8000); $ca=substr((string)($e['t']??$now),0,19);
            $st->bind_param('iisiissss',$hid,$rid,$lg,$eid,$lv,$pv,$msg,$ca,$now); if($st->execute()&&$conn->affected_rows>0)$ins++; }
        $conn->query("UPDATE nm_lx_hosts SET status='ok', last_error=NULL, last_event_poll='$now' WHERE id=$hid");
        return['ok'=>true,'fetched'=>count($rows),'new'=>$ins];
    }
    function nm_lx_events($conn,int $host_id=0,array $f=[]): array { nm_lx_ensure($conn);
        $w=[]; if($host_id)$w[]="e.host_id=".(int)$host_id;
        if(($f['lv']??'')!=='' && in_array($f['lv'],['1','2','3']))$w[]="e.level=".(int)$f['lv'];
        if(($f['q']??'')!==''){ $q=$conn->real_escape_string($f['q']); $w[]="(e.message LIKE '%$q%' OR e.provider LIKE '%$q%')"; }
        $wc=$w?('WHERE '.implode(' AND ',$w)):''; $lim=max(1,min(500,(int)($f['limit']??200)));
        $out=[]; $r=$conn->query("SELECT e.*, h.name host_name, TIMESTAMPDIFF(SECOND,e.created_at,UTC_TIMESTAMP()) age
            FROM nm_lx_events e JOIN nm_lx_hosts h ON h.id=e.host_id $wc ORDER BY e.created_at DESC LIMIT $lim");
        while($r && ($x=$r->fetch_assoc()))$out[]=$x; return $out; }
    function nm_lx_event_summary($conn,int $host_id=0): array { nm_lx_ensure($conn);
        $w=$host_id?"host_id=".(int)$host_id." AND ":""; $out=['crit'=>0,'err'=>0,'warn'=>0];
        $r=$conn->query("SELECT level,COUNT(*) c FROM nm_lx_events WHERE {$w}created_at>(UTC_TIMESTAMP()-INTERVAL 24 HOUR) GROUP BY level");
        while($r && ($x=$r->fetch_assoc())){ $lv=(int)$x['level']; if($lv==1)$out['crit']=(int)$x['c']; elseif($lv==2)$out['err']=(int)$x['c']; elseif($lv==3)$out['warn']=(int)$x['c']; }
        return $out; }

    // ── Health snapshot (one bash command → line-prefixed text → normalized array) ──
    function _nm_lx_health_cmd(): string {
        // NOTE: use printf (sh `echo` does NOT interpret \t) and `sort -k3` (no -t"\t",
        // which sh reads as a literal 2-char tab). awk's printf already emits real tabs.
        $c=[];
        $c[]='printf "OS\t%s\t%s\t%s\n" "$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")" "$(uname -r)" "$(hostname)"';
        $c[]='printf "BOOT\t%s\n" "$(awk \'{print int($1)}\' /proc/uptime)"';
        $c[]='awk \'/^MemTotal/{t=$2}/^MemAvailable/{a=$2}END{printf "MEM\t%d\t%d\n",t,a}\' /proc/meminfo';
        $c[]='printf "CORES\t%s\n" "$(nproc)"';
        $c[]='printf "LOAD\t%s\n" "$(cut -d" " -f1-3 /proc/loadavg)"';
        $c[]='df -P -B1 -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs 2>/dev/null | awk \'NR>1{gsub(/%/,"",$5); print "DISK\t"$6"\t"$2"\t"$4"\t"$5}\'';
        // SMART (smartctl), best-effort, needs root
        $c[]='command -v smartctl >/dev/null && for d in $(lsblk -dno NAME,TYPE 2>/dev/null | awk \'$2=="disk"{print $1}\'); do h=$(smartctl -H /dev/$d 2>/dev/null | grep -iE "overall-health|test result" | awk -F: \'{gsub(/ /,"",$2);print $2}\'); [ -n "$h" ] && printf "PDISK\t%s\t%s\n" "$d" "$h"; done';
        // services (systemd)
        $c[]='if command -v systemctl >/dev/null; then printf "SVC\t%s\t%s\n" "$(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | wc -l)" "$(systemctl list-units --type=service --no-legend --no-pager 2>/dev/null | wc -l)"; systemctl list-units --type=service --state=failed --no-legend --no-pager 2>/dev/null | awk \'{print "FAILSVC\t"$1}\'; fi';
        // pending package updates (apt/dnf), best-effort
        $c[]='if command -v apt-get >/dev/null; then u=$(apt-get -s upgrade 2>/dev/null | grep -c ^Inst); printf "UPD\t%s\n" "$u"; elif command -v dnf >/dev/null; then u=$(dnf -q check-update 2>/dev/null | grep -c .); printf "UPD\t%s\n" "$u"; fi';
        // firewall
        $c[]='if command -v ufw >/dev/null; then printf "FW\tufw\t%s\n" "$(ufw status 2>/dev/null | head -1 | grep -qi active && echo on || echo off)"; elif command -v firewall-cmd >/dev/null; then printf "FW\tfirewalld\t%s\n" "$(firewall-cmd --state 2>/dev/null | grep -qi running && echo on || echo off)"; fi';
        // top processes
        $c[]='ps -eo comm=,rss= --sort=-rss 2>/dev/null | awk \'{m[$1]+=$2}END{for(k in m)print "PMEM\t"k"\t"m[k]}\' | sort -k3,3 -rn | head -6';
        $c[]='ps -eo comm=,pcpu= --sort=-pcpu 2>/dev/null | awk \'{c[$1]+=$2}END{for(k in c)print "PCPU\t"k"\t"c[k]}\' | sort -k3,3 -rn | head -6';
        return implode('; ',$c);
    }
    function _nm_lx_parse_kv(string $raw): array {
        $d=['disks'=>[],'pdisks'=>[],'svc_stopped_auto'=>[],'proc_mem'=>[],'proc_cpu'=>[]];
        foreach(preg_split('/\r?\n/',trim($raw)) as $line){ if($line==='')continue; $p=explode("\t",$line);
            switch($p[0]){
                case 'OS': $d['os']=$p[1]??''; $d['osver']=$p[2]??''; $d['host']=$p[3]??''; break;
                case 'BOOT': $d['boot']=isset($p[1])?gmdate('c',time()-(int)$p[1]):null; break;
                case 'MEM': $t=(int)($p[1]??0); $a=(int)($p[2]??0); $d['mem_total']=(int)round($t/1024); $d['mem_free']=(int)round($a/1024); break;
                case 'CORES': $d['cores']=(int)($p[1]??0); break;
                case 'LOAD': $d['load']=$p[1]??''; break;
                case 'DISK': $d['disks'][]=['id'=>$p[1]??'','size'=>round(((float)($p[2]??0))/1073741824,1),'free'=>round(((float)($p[3]??0))/1073741824,1),'pct'=>(int)($p[4]??0)]; break;
                case 'PDISK': $d['pdisks'][]=['name'=>$p[1]??'','health'=>(stripos($p[2]??'','PASS')!==false||stripos($p[2]??'','OK')!==false)?'Healthy':($p[2]??'?'),'media'=>'']; break;
                case 'SVC': $d['svc_running']=(int)($p[1]??0); $d['svc_total']=(int)($p[2]??0); break;
                case 'FAILSVC': $d['svc_stopped_auto'][]=['name'=>$p[1]??'','disp'=>$p[1]??'','state'=>'failed']; break;
                case 'UPD': $d['updates']=(int)($p[1]??0); break;
                case 'FW': $d['firewall']=[['name'=>$p[1]??'fw','on'=>(($p[2]??'')==='on')]]; break;
                case 'PMEM': $d['proc_mem'][]=['name'=>$p[1]??'','mb'=>(int)round(((float)($p[2]??0))/1024)]; break;
                case 'PCPU': $d['proc_cpu'][]=['name'=>$p[1]??'','cpu'=>round((float)($p[2]??0),0),'mb'=>0]; break;
            }
        } return $d;
    }
    function nm_lx_poll_health($conn, array $h): array {
        nm_lx_ensure($conn); $hid=(int)$h['id']; $ssh=nm_lx_resolve_ssh($conn,$h);
        if(!$ssh||empty($ssh['username'])){ _nm_lx_err($conn,$hid,'No SSH credential resolved'); return['ok'=>false,'error'=>'no ssh']; }
        $res=nm_lx_sh($ssh,_nm_lx_health_cmd(),45);
        if(!$res['ok']){ _nm_lx_err($conn,$hid,'health SSH failed: '.substr((string)($res['error']??''),0,160)); return['ok'=>false,'error'=>'ssh failed']; }
        $data=_nm_lx_parse_kv((string)$res['config']); if(empty($data['os'])&&empty($data['mem_total'])){ _nm_lx_err($conn,$hid,'health: no data'); return['ok'=>false,'error'=>'no data']; }
        $now=gmdate('Y-m-d H:i:s'); $je=$conn->real_escape_string(json_encode($data));
        $conn->query("INSERT INTO nm_lx_health (host_id,data,sampled_at) VALUES ($hid,'$je','$now') ON DUPLICATE KEY UPDATE data=VALUES(data),sampled_at=VALUES(sampled_at)");
        if(!empty($data['os']))$conn->query("UPDATE nm_lx_hosts SET os_caption='".$conn->real_escape_string(substr((string)$data['os'],0,160))."', last_health_poll='$now', status='ok', last_error=NULL WHERE id=$hid");
        else $conn->query("UPDATE nm_lx_hosts SET last_health_poll='$now' WHERE id=$hid");
        return['ok'=>true,'sections'=>array_keys($data)];
    }
    function nm_lx_health_get($conn,int $host_id): array { nm_lx_ensure($conn);
        $r=$conn->query("SELECT data,sampled_at,TIMESTAMPDIFF(SECOND,sampled_at,UTC_TIMESTAMP()) age FROM nm_lx_health WHERE host_id=".(int)$host_id." LIMIT 1");
        $x=$r?$r->fetch_assoc():null; if(!$x)return['ok'=>true,'has'=>false];
        $d=json_decode((string)$x['data'],true); return['ok'=>true,'has'=>is_array($d),'data'=>is_array($d)?$d:null,'sampled_at'=>$x['sampled_at'],'age'=>(int)$x['age']]; }

    // ── Live diagnostics ("what is eating this box") ──────────────────────────
    function _nm_lx_diag_cmd(): string {
        $c=[];
        // two-sample CPU% + net rate
        $c[]='S1=$(awk \'/^cpu /{i=$5;t=0;for(x=2;x<=NF;x++)t+=$x;print t,i}\' /proc/stat)';
        $c[]='R1=$(awk -F"[: ]+" \'/:/&&$0!~/lo:/{r+=$3;t+=$11}END{print r+0,t+0}\' /proc/net/dev)';
        $c[]='sleep 0.6';
        $c[]='S2=$(awk \'/^cpu /{i=$5;t=0;for(x=2;x<=NF;x++)t+=$x;print t,i}\' /proc/stat)';
        $c[]='R2=$(awk -F"[: ]+" \'/:/&&$0!~/lo:/{r+=$3;t+=$11}END{print r+0,t+0}\' /proc/net/dev)';
        // mawk-safe: a ternary as a printf arg prints nothing in mawk (Ubuntu/Debian default).
        $c[]='echo "$S1 $S2" | awk \'{dt=$3-$1;di=$4-$2;p=0;if(dt>0)p=100*(dt-di)/dt;printf "CPU\t%.0f\n",p}\'';
        $c[]='echo "$R1 $R2" | awk \'{rx=($3-$1)/0.6;tx=($4-$2)/0.6;if(rx<0)rx=0;if(tx<0)tx=0;printf "NET\t%.0f\t%.0f\n",rx,tx}\'';
        $c[]='printf "HOST\t%s\t%s\n" "$(hostname)" "$(nproc)"';
        $c[]='awk \'/^MemTotal/{t=$2}/^MemAvailable/{a=$2}END{printf "MEM\t%d\t%d\n",t,a}\' /proc/meminfo';
        $c[]='df -P -B1 -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs 2>/dev/null | awk \'NR>1{gsub(/%/,"",$5); print "DISK\t"$6"\t"$2"\t"$4"\t"$5}\'';
        $c[]='ps -eo comm=,rss= --sort=-rss 2>/dev/null | awk \'{m[$1]+=$2;n[$1]++}END{for(k in m)print "PMEM\t"k"\t"m[k]"\t"n[k]}\' | sort -k3,3 -rn | head -10';
        $c[]='ps -eo comm=,pcpu= --sort=-pcpu 2>/dev/null | awk \'{c[$1]+=$2}END{for(k in c)if(c[k]>0)print "PCPU\t"k"\t"c[k]}\' | sort -k3,3 -rn | head -8';
        // network talkers (ss with process needs root; degrade to plain count)
        $c[]='command -v ss >/dev/null && ss -tnpH state established 2>/dev/null | grep -oP \'(?<=\\(\\(")[^"]+\' | sort | uniq -c | sort -rn | head -8 | awk \'{print "CONN\t"$2"\t"$1}\'';
        // sensors (lm-sensors, raw -u = ASCII, easy to parse)
        $c[]='command -v sensors >/dev/null && sensors -u 2>/dev/null | awk \'/^[A-Za-z].*:$/{n=$0;sub(/:$/,"",n)} /_input:/{v=$2+0; if($1~/^temp/)print "TEMP\t"n"\t"v; else if($1~/^fan/)print "FAN\t"n"\t"v; else if($1~/^in[0-9]/)print "SENS\tVoltage\t"n"\t"v; else if($1~/^power/)print "SENS\tPower\t"n"\t"v}\'';
        return implode('; ',$c);
    }
    function _nm_lx_gather_diag_ssh($ssh): array {
        $res=nm_lx_sh($ssh,_nm_lx_diag_cmd(),55);
        if(!$res['ok'])return['ok'=>false,'error'=>'SSH/bash failed: '.substr((string)($res['error']??''),0,200)];
        $d=['top_mem'=>[],'top_cpu'=>[],'disks'=>[],'net_conn'=>[],'fans'=>[],'temps'=>[],'sensors'=>[],'sensor_src'=>'','sensor_types'=>[]];
        $haveSens=false;
        foreach(preg_split('/\r?\n/',trim((string)$res['config'])) as $line){ if($line==='')continue; $p=explode("\t",$line);
            switch($p[0]){
                case 'HOST': $d['host']=$p[1]??''; $d['cores']=(int)($p[2]??0); break;
                case 'CPU': $d['cpu']=(int)($p[1]??0); break;
                case 'MEM': $t=(int)($p[1]??0); $a=(int)($p[2]??0); $d['mem_total']=(int)round($t/1024); $d['mem_free']=(int)round($a/1024); $d['mem_used']=$d['mem_total']-$d['mem_free']; $d['mem_pct']=$t?round(($t-$a)/$t*100,1):0; break;
                case 'NET': $d['net_rx']=round(((float)($p[1]??0))/1024,1); $d['net_tx']=round(((float)($p[2]??0))/1024,1); break;
                case 'DISK': $d['disks'][]=['id'=>$p[1]??'','size'=>round(((float)($p[2]??0))/1073741824,1),'free'=>round(((float)($p[3]??0))/1073741824,1),'pct'=>(int)($p[4]??0)]; break;
                case 'PMEM': $d['top_mem'][]=['name'=>$p[1]??'','mb'=>(int)round(((float)($p[2]??0))/1024),'inst'=>(int)($p[3]??1),'pct'=>0]; break;
                case 'PCPU': $d['top_cpu'][]=['name'=>$p[1]??'','pct'=>round((float)($p[2]??0),1),'mb'=>0]; break;
                case 'CONN': $d['net_conn'][]=['name'=>$p[1]??'','conns'=>(int)($p[2]??0)]; break;
                case 'TEMP': $d['temps'][]=['name'=>$p[1]??'','c'=>round((float)($p[2]??0),1)]; $d['sensors'][]=['type'=>'Temperature','name'=>$p[1]??'','val'=>round((float)($p[2]??0),1)]; $haveSens=true; break;
                case 'FAN': $d['fans'][]=['name'=>$p[1]??'','rpm'=>(int)($p[2]??0)]; $d['sensors'][]=['type'=>'Fan','name'=>$p[1]??'','val'=>(int)($p[2]??0)]; $haveSens=true; break;
                case 'SENS': $d['sensors'][]=['type'=>$p[1]??'','name'=>$p[2]??'','val'=>round((float)($p[3]??0),2)]; $haveSens=true; break;
            }
        }
        if($haveSens)$d['sensor_src']='lm-sensors';
        // sensor_types summary (mirror Windows)
        $tc=[]; foreach($d['sensors'] as $s){ $tc[$s['type']]=($tc[$s['type']]??0)+1; } foreach($tc as $tt=>$n)$d['sensor_types'][]=['type'=>$tt,'n'=>$n];
        return['ok'=>true,'data'=>$d];
    }
    function nm_lx_diagnose($conn, array $h): array {
        nm_lx_ensure($conn);
        // PER-HOST source: 'alloy' → scrape that box's Grafana Alloy; else SSH bash.
        if (($h['source'] ?? 'ssh') === 'alloy') {
            $g = _nm_lx_gather_diag_alloy($conn, $h);
        } else {
            $ssh=nm_lx_resolve_ssh($conn,$h);
            if(!$ssh||empty($ssh['username']))return['ok'=>false,'error'=>'No SSH credential resolved (assign the node an SSH cred or set a default).'];
            $g=_nm_lx_gather_diag_ssh($ssh);
        }
        if(empty($g['ok']))return $g;
        return['ok'=>true,'data'=>$g['data'],'host'=>$h['name']??''];
    }

    // ── Grafana Alloy collector (Phase 3) ─────────────────────────────────────
    // Reads each box's Alloy /metrics (Prometheus text exposition of node_exporter /
    // unix-exporter metrics) over HTTP and maps to the SAME diag shape as SSH. System-
    // level only (node_exporter has no per-process) → top consumers/kill still need SSH.
    function nm_lx_alloy_url($conn, array $h): string {
        $port=_nm_lx_setting($conn,'alloy_port','9100'); $path=_nm_lx_setting($conn,'alloy_path','/metrics');
        if ($path==='' || $path[0]!=='/') $path='/'.$path;
        // explicit per-host URL: normalize (add scheme + append /metrics path if missing)
        $u = trim((string)($h['alloy_url'] ?? ''));
        if ($u!=='') {
            if (!preg_match('#^https?://#i',$u)) $u='http://'.$u;
            $pp=parse_url($u); if (empty($pp['path']) || $pp['path']==='/') $u=rtrim($u,'/').$path;
            return $u;
        }
        $ip = trim((string)($h['host_ip'] ?? ''));
        if ($ip==='' && !empty($h['node_id'])) { $r=$conn->query("SELECT ip_address FROM nm_nodes WHERE id=".(int)$h['node_id']." LIMIT 1"); if($r && ($x=$r->fetch_assoc())) $ip=(string)$x['ip_address']; }
        return 'http://'.$ip.':'.$port.$path;
    }
    function _nm_lx_alloy_fetch(string $url, int $timeout=8): ?string {
        if (!function_exists('curl_init')) return null;
        $ch=curl_init($url); curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_CONNECTTIMEOUT=>4,CURLOPT_TIMEOUT=>$timeout,CURLOPT_SSL_VERIFYPEER=>false]);
        $r=curl_exec($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
        return ($r!==false && $code>=200 && $code<300)?$r:null;
    }
    // Extract all series of an EXACT metric from Prometheus text → [['labels'=>[],'val'=>float],…]
    function _nm_lx_prom(string $text, string $metric): array {
        $out=[]; $len=strlen($metric);
        foreach(explode("\n",$text) as $ln){ if($ln===''||$ln[0]==='#')continue;
            if(strncmp($ln,$metric,$len)!==0)continue; $c=$ln[$len]??''; if($c!=='{' && $c!==' ')continue;
            if($c==='{'){ $rb=strpos($ln,'} '); if($rb===false){$rb=strrpos($ln,'}');} $lbl=substr($ln,$len+1,$rb-$len-1); $val=(float)trim(substr($ln,$rb+1)); }
            else { $lbl=''; $val=(float)trim(substr($ln,$len+1)); }
            $labels=[]; if($lbl!==''){ preg_match_all('/(\w+)="([^"]*)"/',$lbl,$mm,PREG_SET_ORDER); foreach($mm as $m)$labels[$m[1]]=$m[2]; }
            $out[]=['labels'=>$labels,'val'=>$val];
        } return $out;
    }
    function _nm_lx_gather_diag_alloy($conn, array $h): array {
        $url=nm_lx_alloy_url($conn,$h);
        $t1=_nm_lx_alloy_fetch($url); if($t1===null)return['ok'=>false,'error'=>'Grafana Alloy unreachable at '.$url.' — check the box is up, port 12345 open, and the metrics path.'];
        if(strpos($t1,'node_cpu_seconds_total')===false && strpos($t1,'node_memory_')===false)
            return['ok'=>false,'error'=>'Alloy is reachable but exposes no node_* metrics at '.$url.'. Enable the unix/node exporter (Site Config → Grafana Alloy has the config snippet).','raw'=>substr($t1,0,180)];
        usleep(600000); $t2=_nm_lx_alloy_fetch($url); if($t2===null)$t2=$t1;
        $d=['top_mem'=>[],'top_cpu'=>[],'disks'=>[],'net_conn'=>[],'fans'=>[],'temps'=>[],'sensors'=>[],'sensor_src'=>'','sensor_types'=>[],'via'=>'alloy',
            'alloy_note'=>'Live system metrics via Grafana Alloy. Per-process top consumers + kill need SSH (node-exporter is system-level).'];
        $d['host']=$h['name']??'';
        $g1=function($m)use($t1){ $r=_nm_lx_prom($t1,$m); return $r?(float)$r[0]['val']:0; };  // single-value getter
        // CPU overall + PER-CORE (delta idle vs total per cpu) — matches the Windows LOAD panel
        $c1=_nm_lx_prom($t1,'node_cpu_seconds_total'); $c2=_nm_lx_prom($t2,'node_cpu_seconds_total');
        $agg=function($rows){ $o=[]; foreach($rows as $s){ $cpu=$s['labels']['cpu']??'?'; if(!isset($o[$cpu]))$o[$cpu]=['t'=>0,'i'=>0]; $o[$cpu]['t']+=$s['val']; if(($s['labels']['mode']??'')==='idle')$o[$cpu]['i']+=$s['val']; } return $o; };
        $a1=$agg($c1); $a2=$agg($c2); $tot1=0;$idle1=0;$tot2=0;$idle2=0; $d['cpu_cores']=[];
        foreach($a1 as $cpu=>$v){ $t2v=$a2[$cpu]['t']??$v['t']; $i2v=$a2[$cpu]['i']??$v['i']; $ct=$t2v-$v['t']; $ci=$i2v-$v['i']; $tot1+=$v['t']; $idle1+=$v['i']; $tot2+=$t2v; $idle2+=$i2v; $d['cpu_cores'][]=['core'=>$cpu,'pct'=>$ct>0?round(100*($ct-$ci)/$ct,1):0]; }
        usort($d['cpu_cores'],function($x,$y){ return (int)$x['core']-(int)$y['core']; });
        $dt=$tot2-$tot1;$di=$idle2-$idle1; $d['cpu']=$dt>0?(int)round(100*($dt-$di)/$dt):0; $d['cores']=count($a1)?count($a1):null;
        $d['load']=round($g1('node_load1'),2).' '.round($g1('node_load5'),2).' '.round($g1('node_load15'),2);
        $d['procs_running']=(int)$g1('node_procs_running'); $d['procs_blocked']=(int)$g1('node_procs_blocked');
        $bt=$g1('node_boot_time_seconds'); if($bt>0)$d['boot']=gmdate('c',(int)$bt);
        // memory + breakdown (used / cached / buffers / swap)
        $T=$g1('node_memory_MemTotal_bytes'); $A=$g1('node_memory_MemAvailable_bytes');
        $d['mem_total']=(int)round($T/1048576); $d['mem_free']=(int)round($A/1048576); $d['mem_used']=$d['mem_total']-$d['mem_free']; $d['mem_pct']=$T?round(($T-$A)/$T*100,1):0;
        $d['mem_cached']=(int)round($g1('node_memory_Cached_bytes')/1048576); $d['mem_buffers']=(int)round($g1('node_memory_Buffers_bytes')/1048576);
        $swT=$g1('node_memory_SwapTotal_bytes'); $swF=$g1('node_memory_SwapFree_bytes'); $d['swap_total']=(int)round($swT/1048576); $d['swap_used']=(int)round(max(0,$swT-$swF)/1048576);
        // disks
        $av=[]; foreach(_nm_lx_prom($t1,'node_filesystem_avail_bytes') as $s)$av[$s['labels']['mountpoint']??'']=$s['val'];
        $skip=['tmpfs','devtmpfs','overlay','squashfs','efivarfs','ramfs','autofs'];
        foreach(_nm_lx_prom($t1,'node_filesystem_size_bytes') as $s){ $fs=$s['labels']['fstype']??''; $mp=$s['labels']['mountpoint']??''; if($mp===''||in_array($fs,$skip,true))continue; $sz=$s['val']; $fr=$av[$mp]??0; $u=$sz-$fr; $d['disks'][]=['id'=>$mp,'size'=>round($sz/1073741824,1),'free'=>round($fr/1073741824,1),'pct'=>$sz?(int)round($u/$sz*100):0]; }
        // network rate (sum non-lo, two samples → KB/s)
        $sumN=function($t,$metric){ $x=0; foreach(_nm_lx_prom($t,$metric) as $s){ if(($s['labels']['device']??'')!=='lo')$x+=$s['val']; } return $x; };
        $d['net_rx']=round(max(0,$sumN($t2,'node_network_receive_bytes_total')-$sumN($t1,'node_network_receive_bytes_total'))/0.6/1024,1);
        $d['net_tx']=round(max(0,$sumN($t2,'node_network_transmit_bytes_total')-$sumN($t1,'node_network_transmit_bytes_total'))/0.6/1024,1);
        // per-interface rates (KB/s) — the Alloy equivalent of "top talkers"
        $ifx=function($t,$m){ $o=[]; foreach(_nm_lx_prom($t,$m) as $s){ $dv=$s['labels']['device']??''; if($dv&&$dv!=='lo')$o[$dv]=$s['val']; } return $o; };
        $r1=$ifx($t1,'node_network_receive_bytes_total');$r2=$ifx($t2,'node_network_receive_bytes_total');
        $x1=$ifx($t1,'node_network_transmit_bytes_total');$x2=$ifx($t2,'node_network_transmit_bytes_total');
        $d['net_ifaces']=[]; foreach($r1 as $dv=>$v){ $rx=round(max(0,(($r2[$dv]??$v)-$v))/0.6/1024,1); $tx=round(max(0,(($x2[$dv]??($x1[$dv]??0))-($x1[$dv]??0)))/0.6/1024,1); $d['net_ifaces'][]=['name'=>$dv,'rx'=>$rx,'tx'=>$tx]; }
        usort($d['net_ifaces'],function($p,$q){ return ($q['rx']+$q['tx'])<=>($p['rx']+$p['tx']); }); $d['net_ifaces']=array_slice($d['net_ifaces'],0,6);
        // sensors (hwmon)
        foreach(_nm_lx_prom($t1,'node_hwmon_temp_celsius') as $s){ $n=trim(($s['labels']['chip']??'').' '.($s['labels']['sensor']??'')); $d['temps'][]=['name'=>$n,'c'=>round($s['val'],1)]; $d['sensors'][]=['type'=>'Temperature','name'=>$n,'val'=>round($s['val'],1)]; }
        foreach(_nm_lx_prom($t1,'node_hwmon_fan_rpm') as $s){ $n=trim(($s['labels']['chip']??'').' '.($s['labels']['sensor']??'')); $d['fans'][]=['name'=>$n,'rpm'=>(int)$s['val']]; $d['sensors'][]=['type'=>'Fan','name'=>$n,'val'=>(int)$s['val']]; }
        if($d['temps']||$d['fans'])$d['sensor_src']='Alloy node-exporter';
        $tc=[]; foreach($d['sensors'] as $s)$tc[$s['type']]=($tc[$s['type']]??0)+1; foreach($tc as $tt=>$n)$d['sensor_types'][]=['type'=>$tt,'n'=>$n];
        return['ok'=>true,'data'=>$d];
    }

    // ── Service watchdog (systemd) ────────────────────────────────────────────
    function _nm_lx_svc_ok(string $n): bool { return (bool)preg_match('/^[A-Za-z0-9@._:-]{1,160}$/',$n); }
    function _nm_lx_svc_protected(string $n): bool { static $p=['ssh','sshd','systemd','systemd-journald','systemd-logind','dbus','init']; $b=preg_replace('/\.service$/','',strtolower(trim($n))); return in_array($b,$p,true); }
    function nm_lx_watches($conn,int $host_id): array { nm_lx_ensure($conn); $out=[];
        $r=$conn->query("SELECT *, TIMESTAMPDIFF(SECOND,last_checked,UTC_TIMESTAMP()) checked_age FROM nm_lx_watch WHERE host_id=".(int)$host_id." ORDER BY display_name,service_name");
        while($r && ($x=$r->fetch_assoc()))$out[]=$x; return $out; }
    function nm_lx_watch_add($conn,int $host_id,array $f,?int $uid): array { nm_lx_ensure($conn);
        $svc=trim((string)($f['service_name']??'')); if(!_nm_lx_svc_ok($svc))return['ok'=>false,'error'=>'Invalid service name'];
        $disp=substr(trim((string)($f['display_name']??$svc)),0,200); $auto=(int)!empty($f['auto_restart']);
        $st=$conn->prepare("INSERT INTO nm_lx_watch (host_id,service_name,display_name,auto_restart) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE display_name=VALUES(display_name),auto_restart=VALUES(auto_restart)");
        $st->bind_param('issi',$host_id,$svc,$disp,$auto); $st->execute(); return['ok'=>true]; }
    function nm_lx_watch_update($conn,int $id,array $f): array { nm_lx_ensure($conn); $auto=(int)!empty($f['auto_restart']);
        $st=$conn->prepare("UPDATE nm_lx_watch SET auto_restart=? WHERE id=?"); $st->bind_param('ii',$auto,$id); $st->execute(); return['ok'=>true]; }
    function nm_lx_watch_delete($conn,int $id): array { nm_lx_ensure($conn); $conn->query("DELETE FROM nm_lx_watch WHERE id=".(int)$id); return['ok'=>true]; }
    function nm_lx_action_log($conn,int $hid,string $svc,string $action,bool $ok,string $detail,?int $uid): void { nm_lx_ensure($conn);
        $st=$conn->prepare("INSERT INTO nm_lx_actions (host_id,service_name,action,ok,detail,uid) VALUES (?,?,?,?,?,?)"); $o=$ok?1:0; $dt=substr($detail,0,400);
        $st->bind_param('issisi',$hid,$svc,$action,$o,$dt,$uid); $st->execute(); }
    function nm_lx_actions_recent($conn,int $host_id,int $limit=30): array { nm_lx_ensure($conn); $out=[];
        $r=$conn->query("SELECT * FROM nm_lx_actions WHERE host_id=".(int)$host_id." ORDER BY id DESC LIMIT ".(int)$limit); while($r && ($x=$r->fetch_assoc()))$out[]=$x; return $out; }
    function nm_lx_services_live($conn, array $h): array { nm_lx_ensure($conn); $ssh=nm_lx_resolve_ssh($conn,$h); if(!$ssh)return['ok'=>false,'error'=>'no ssh'];
        $res=nm_lx_sh($ssh,'systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null | awk \'{print $1"\t"$3"\t"$4}\' | head -400',35);
        if(!$res['ok'])return['ok'=>false,'error'=>$res['error']??'ssh failed']; $svcs=[];
        foreach(preg_split('/\r?\n/',trim((string)$res['config'])) as $l){ if($l==='')continue; $p=explode("\t",$l); $svcs[]=['Name'=>$p[0]??'','DisplayName'=>$p[0]??'','State'=>($p[2]??'')==='running'?'Running':($p[1]??'')]; }
        return['ok'=>true,'services'=>$svcs]; }
    function nm_lx_service_action($conn, array $h, string $svc, string $action, ?int $uid): array { nm_lx_ensure($conn); $hid=(int)$h['id'];
        if(!_nm_lx_svc_ok($svc)){ return['ok'=>false,'error'=>'Invalid service name']; }
        if(_nm_lx_svc_protected($svc)){ return['ok'=>false,'error'=>'Refusing to act on a protected service ('.$svc.')']; }
        $act=in_array($action,['start','restart','stop'],true)?$action:'restart';
        $ssh=nm_lx_resolve_ssh($conn,$h); if(!$ssh){ nm_lx_action_log($conn,$hid,$svc,$act,false,'no ssh',$uid); return['ok'=>false,'error'=>'no ssh']; }
        $res=nm_lx_sh($ssh,'sudo -n systemctl '.$act.' '.escapeshellarg($svc).' 2>&1; systemctl is-active '.escapeshellarg($svc).' 2>/dev/null',40);
        $out=trim((string)($res['config']??'')); $ok=($res['ok']??false) && (strpos($out,'active')!==false);
        nm_lx_action_log($conn,$hid,$svc,$act,$ok,$ok?('now '.$out):substr($out?:'failed',0,160),$uid);
        return $ok?['ok'=>true]:['ok'=>false,'error'=>($out?:'Action failed (needs an SSH account with sudo systemctl rights).')]; }
    function nm_lx_service_action_by_id($conn,int $host_id,string $svc,string $action,?int $uid): array { $h=nm_lx_host($conn,$host_id); return $h?nm_lx_service_action($conn,$h,$svc,$action,$uid):['ok'=>false,'error'=>'no host']; }
    function nm_lx_watch_check($conn, array $h): array { nm_lx_ensure($conn); $hid=(int)$h['id']; $ws=nm_lx_watches($conn,$hid); if(!$ws)return['ok'=>true,'checked'=>0];
        $ssh=nm_lx_resolve_ssh($conn,$h); if(!$ssh)return['ok'=>false,'error'=>'no ssh']; $now=gmdate('Y-m-d H:i:s'); $chk=0;
        foreach($ws as $w){ $svc=$w['service_name']; if(!_nm_lx_svc_ok($svc))continue;
            $res=nm_lx_sh($ssh,'systemctl is-active '.escapeshellarg($svc).' 2>/dev/null',20); $state=trim((string)($res['config']??'')); if($state==='')$state='unknown'; $chk++;
            $prev=(string)($w['last_state']??''); $downNow=($state!=='unknown' && $state!=='active'); $wasUp=($prev===''||$prev==='active');
            $conn->query("UPDATE nm_lx_watch SET last_state='".$conn->real_escape_string(substr($state,0,20))."', last_checked='$now' WHERE id=".(int)$w['id']);
            if($w['auto_restart'] && $state!=='active'){ $bk=$w['last_restart_at']?(time()-strtotime($w['last_restart_at'].' UTC')):99999;
                if($bk>=300){ $r=nm_lx_service_action($conn,$h,$svc,'restart',null); $conn->query("UPDATE nm_lx_watch SET restart_count=restart_count+1, last_action_at='$now', last_restart_at='$now' WHERE id=".(int)$w['id']); } }
            if($downNow && $wasUp){ if(!function_exists('nm_notify_event')){@include_once __DIR__.'/nm_notify.php';}
                if(function_exists('nm_notify_event')){ $hn=$h['hostname']??$h['display_name']??$h['name']??('host#'.$hid);
                    @nm_notify_event($conn,'service','warning',"Service {$svc} is {$state} on {$hn}",
                        ($w['auto_restart']?'Watchdog auto-restart attempted.':'This service is not armed for auto-restart.'),
                        ['node_id'=>($h['node_id']??null),'entity'=>$svc,'source'=>'watchdog']); } }
        } return['ok'=>true,'checked'=>$chk]; }

    // ── Kill a process (by name) — destructive, audited, injection-safe ────────
    function _nm_lx_proc_protected(string $n): bool { static $p=['init','systemd','kthreadd','sshd','ssh','dbus-daemon','systemd-journald','systemd-logind']; return in_array(strtolower(trim($n)),$p,true); }
    function nm_lx_kill_process($conn, array $h, string $name, ?int $uid): array { nm_lx_ensure($conn); $name=trim($name); $hid=(int)$h['id'];
        if(!preg_match('/^[A-Za-z0-9 ._:@+-]{1,80}$/',$name))return['ok'=>false,'error'=>'Invalid process name'];
        if(_nm_lx_proc_protected($name))return['ok'=>false,'error'=>'Refusing to kill a protected process ('.$name.')'];
        $ssh=nm_lx_resolve_ssh($conn,$h); if(!$ssh)return['ok'=>false,'error'=>'No SSH credential resolved.'];
        // count then SIGTERM by exact comm; name is allowlisted so escapeshellarg is belt-and-suspenders
        $q=escapeshellarg($name);
        $res=nm_lx_sh($ssh,'n=$(pgrep -xc '.$q.' 2>/dev/null||echo 0); pkill -TERM -x '.$q.' 2>/dev/null; echo "KILLED $n"',30);
        $out=trim((string)($res['config']??'')); $n=0; if(preg_match('/KILLED\s+(\d+)/',$out,$mm))$n=(int)$mm[1];
        $ok=($res['ok']??false); nm_lx_action_log($conn,$hid,$name,'kill',$ok,$ok?('killed '.$n.' proc(s)'):'ssh failed',$uid);
        return $ok?['ok'=>true,'killed'=>$n]:['ok'=>false,'error'=>'SSH failed']; }

    // ── Cron orchestration + prune ────────────────────────────────────────────
    function nm_lx_poll_all($conn): array { nm_lx_ensure($conn); $r=$conn->query("SELECT * FROM nm_lx_hosts WHERE enabled=1"); $hs=[]; while($r && ($x=$r->fetch_assoc()))$hs[]=$x;
        $ev=0;$he=0;$wc=0; foreach($hs as $h){ $a=nm_lx_poll_events($conn,$h); if(!empty($a['ok']))$ev++; $b=nm_lx_poll_health($conn,$h); if(!empty($b['ok']))$he++; $c=nm_lx_watch_check($conn,$h); if(!empty($c['ok']))$wc++; }
        nm_lx_prune($conn); return['ok'=>true,'hosts'=>count($hs),'events_ok'=>$ev,'health_ok'=>$he,'watch_ok'=>$wc]; }
    function nm_lx_prune($conn,int $days=30): void { nm_lx_ensure($conn); $d=max(1,$days); $conn->query("DELETE FROM nm_lx_events WHERE created_at < (UTC_TIMESTAMP() - INTERVAL $d DAY)"); $conn->query("DELETE FROM nm_lx_actions WHERE created_at < (UTC_TIMESTAMP() - INTERVAL $d DAY)"); }
}
