<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Forensic AI Archaeologist. Async background miner for "ghosts in the
// machine": non-obvious RECURRING cross-domain temporal coincidences a human
// would never cross-reference (e.g. "container GC at 02:00 → switch microloop").
//
// NEURU does the heavy lifting (assembles typed anomaly events across domains and
// computes pairwise lag co-occurrence → CANDIDATES). The n8n AI flow turns the
// strongest candidates into a narrative hypothesis + suggested fix. Works
// standalone too (statistical candidates shown even without n8n). RBAC: 'archaeology'.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_n8n.php';
require_once __DIR__ . '/nm_audit.php';

if (!function_exists('nm_arch_run')) {

    function nm_arch_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        static $done=false; if($done) return; $done=true;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_archaeology_findings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            pattern_key VARCHAR(64) NOT NULL,
            title VARCHAR(255) NOT NULL,
            confidence INT NOT NULL DEFAULT 0,
            support INT NOT NULL DEFAULT 0,
            avg_lag_min DOUBLE DEFAULT 0,
            hypothesis TEXT, evidence TEXT, suggested_fix TEXT,
            source VARCHAR(8) NOT NULL DEFAULT 'stat',   -- stat | ai
            status VARCHAR(12) NOT NULL DEFAULT 'open',    -- open | ack | dismissed
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_pat (pattern_key), KEY idx_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','archaeology',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='archaeology')");
    }
    function nm_arch_setting($conn,$k,$d){ $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; }

    // Collect typed anomaly events (5-min bucketed) across domains.
    function nm_arch_events($conn, int $days): array {
        $E=[]; $W="DATE_SUB(NOW(),INTERVAL {$days} DAY)";
        $push=function($t,$ent,$when,$detail='') use(&$E){ $E[]=['type'=>$t,'entity'=>$ent,'t'=>strtotime($when),'detail'=>$detail]; };
        $names=[]; if($r=$conn->query("SELECT id,display_name FROM nm_nodes")) while($x=$r->fetch_assoc()) $names[(int)$x['id']]=$x['display_name'];
        // node down (one per node per 5-min bucket)
        if($r=$conn->query("SELECT node_id, MIN(recorded_at) w FROM nm_ping_stats WHERE is_up=0 AND recorded_at>=$W GROUP BY node_id, UNIX_TIMESTAMP(recorded_at) DIV 300"))
            while($x=$r->fetch_assoc()) $push('node_down',$names[(int)$x['node_id']]??('node'.$x['node_id']),$x['w']);
        // syslog error bursts
        if($conn->query("SHOW TABLES LIKE 'nm_syslog'")->num_rows && ($r=$conn->query("SELECT hostname h, MIN(host_ip) hip, MIN(received_at) w, COUNT(*) c FROM nm_syslog WHERE severity<=3 AND received_at>=$W GROUP BY hostname, UNIX_TIMESTAMP(received_at) DIV 300 HAVING c>=5")))
            while($x=$r->fetch_assoc()) $push('syslog_error',$x['h']?:$x['hip'],$x['w'],$x['c'].' errors');
        // container errors
        if($conn->query("SHOW TABLES LIKE 'container_incidents'")->num_rows && ($r=$conn->query("SELECT container_name n, first_seen w FROM container_incidents WHERE first_seen>=$W")))
            while($x=$r->fetch_assoc()) $push('container_error',$x['n'],$x['w']);
        // cpu spikes
        if($r=$conn->query("SELECT node_id, MIN(recorded_at) w FROM nm_device_stats WHERE metric_type='cpu' AND metric_key='avg' AND value>=85 AND recorded_at>=$W GROUP BY node_id, UNIX_TIMESTAMP(recorded_at) DIV 300"))
            while($x=$r->fetch_assoc()) $push('cpu_spike',$names[(int)$x['node_id']]??('node'.$x['node_id']),$x['w']);
        // config changes
        if($conn->query("SHOW TABLES LIKE 'nm_config_changes'")->num_rows && ($r=$conn->query("SELECT d.name n, c.detected_at w FROM nm_config_changes c JOIN nm_config_devices d ON d.id=c.device_id WHERE c.detected_at>=$W")))
            while($x=$r->fetch_assoc()) $push('config_change',$x['n'],$x['w']);
        // health degradation onsets
        if($conn->query("SHOW TABLES LIKE 'nm_health_predictions'")->num_rows && ($r=$conn->query("SELECT entity n, first_seen w FROM nm_health_predictions WHERE first_seen>=$W")))
            while($x=$r->fetch_assoc()) $push('degradation',$x['n'],$x['w']);
        usort($E, fn($a,$b)=>$a['t']<=>$b['t']);
        return array_slice($E, 0, 6000);
    }

    // Pairwise lag co-occurrence: A often followed by B within [60s, lagMax].
    function nm_arch_candidates($conn, int $days=7): array {
        $E=nm_arch_events($conn,$days);
        $lagMax = (int)nm_arch_setting($conn,'arch_lag_max_min','15')*60 ?: 900;
        $pairs=[]; $typeCount=[];
        foreach($E as $e) $typeCount[$e['type']]=($typeCount[$e['type']]??0)+1;
        $n=count($E);
        for($i=0;$i<$n;$i++){ $a=$E[$i];
            for($j=$i+1;$j<$n;$j++){ $b=$E[$j]; $dt=$b['t']-$a['t']; if($dt<60) continue; if($dt>$lagMax) break;
                if($a['type']===$b['type']) continue;
                $k=$a['type'].'→'.$b['type'];
                if(!isset($pairs[$k])) $pairs[$k]=['a'=>$a['type'],'b'=>$b['type'],'n'=>0,'lagsum'=>0,'ex'=>[]];
                $pairs[$k]['n']++; $pairs[$k]['lagsum']+=$dt;
                if(count($pairs[$k]['ex'])<4) $pairs[$k]['ex'][]=['a'=>$a['entity'],'at'=>date('Y-m-d H:i',$a['t']),'b'=>$b['entity'],'bt'=>date('Y-m-d H:i',$b['t']),'lag'=>round($dt/60).'m','detail'=>$a['detail']];
            }
        }
        $minSupport=(int)nm_arch_setting($conn,'arch_min_support','3') ?: 3;
        $out=[];
        foreach($pairs as $k=>$p){ if($p['n']<$minSupport) continue;
            $base=max(1,$typeCount[$p['a']]); $strength=$p['n']/$base;       // fraction of A events followed by B
            $conf=(int)min(95, round($strength*70 + min(25,$p['n']*3)));
            $out[]=['key'=>$k,'a'=>$p['a'],'b'=>$p['b'],'support'=>$p['n'],'avg_lag_min'=>round($p['lagsum']/$p['n']/60,1),'confidence'=>$conf,'examples'=>$p['ex']];
        }
        usort($out, fn($x,$y)=>[$y['confidence'],$y['support']]<=>[$x['confidence'],$x['support']]);
        return array_slice($out,0,30);
    }

    // Assemble candidates → store as statistical findings → (optional) ship to n8n AI for narrative.
    function nm_arch_run($conn): array {
        nm_arch_ensure($conn);
        $days=(int)nm_arch_setting($conn,'arch_window_days','7') ?: 7;
        $cands=nm_arch_candidates($conn,$days);
        $stored=0;
        foreach($cands as $c){
            $label=str_replace('_',' ',$c['a']).' → '.str_replace('_',' ',$c['b']);
            $title=ucfirst($label)." recurs ({$c['support']}× , ~{$c['avg_lag_min']}m lag)";
            $ev=json_encode($c['examples']);
            $st=$conn->prepare("INSERT INTO nm_archaeology_findings (pattern_key,title,confidence,support,avg_lag_min,evidence,source,status,updated_at)
                VALUES (?,?,?,?,?,?,'stat','open',NOW())
                ON DUPLICATE KEY UPDATE title=VALUES(title),confidence=VALUES(confidence),support=VALUES(support),avg_lag_min=VALUES(avg_lag_min),evidence=VALUES(evidence),updated_at=NOW(),status=IF(status='dismissed','dismissed','open')");
            $cf=(int)$c['confidence']; $sp=(int)$c['support']; $lg=(float)$c['avg_lag_min'];
            $st->bind_param('ssiids',$c['key'],$title,$cf,$sp,$lg,$ev); $st->execute(); $stored++;
        }
        // optional AI enrichment
        $url=nm_arch_setting($conn,'arch_webhook_url','');
        $shipped=false;
        if($url!=='' && $cands && function_exists('curl_init')){
            $cfg=nm_n8n_get($conn); $base=function_exists('nm_n8n_callback_base')?nm_n8n_callback_base($conn,$url):(((!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http').'://'.($_SERVER['HTTP_HOST']??'localhost'));  // per-flow: hosted→tunnel, local→LAN
            $payload=['window_days'=>$days,'candidates'=>$cands,'findings_url'=>$base.'/nm_archaeology_api.php?ep=findings'];
            if(function_exists('nm_n8n_neuru_stamp'))$payload=nm_n8n_neuru_stamp($conn,$payload,$url,'archaeology-analyze');  // gatecheck + per-flow model
            $ch=curl_init($url);
            curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>json_encode($payload),CURLOPT_CONNECTTIMEOUT=>4,CURLOPT_TIMEOUT=>20,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_SSL_VERIFYHOST=>false,CURLOPT_HTTPHEADER=>['Content-Type: application/json','X-NetMon-Token: '.$cfg['inbound_token']]]);
            curl_exec($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch); $shipped=($code>=200&&$code<300);
        }
        // stamp last-run so the UI can show "analyzed X ago" (weekly cron + on-demand both hit this)
        try { $conn->query("INSERT INTO nm_settings(setting_key,setting_val) VALUES('arch_last_run',NOW())
                            ON DUPLICATE KEY UPDATE setting_val=NOW()"); } catch (\Throwable $e) {}
        return ['candidates'=>count($cands),'stored'=>$stored,'ai_shipped'=>$shipped];
    }

    function nm_arch_list($conn): array { nm_arch_ensure($conn); $o=[]; $r=$conn->query("SELECT * FROM nm_archaeology_findings WHERE status IN('open','ack') ORDER BY FIELD(status,'open','ack'), FIELD(source,'ai','stat'), confidence DESC, support DESC LIMIT 100"); while($r&&$x=$r->fetch_assoc())$o[]=$x; return $o; }
    function nm_arch_set_status($conn,int $id,string $s){ $s=in_array($s,['open','ack','dismissed'],true)?$s:'open'; $st=$conn->prepare("UPDATE nm_archaeology_findings SET status=? WHERE id=?"); $st->bind_param('si',$s,$id); $st->execute(); }
    // Status counts for the header pills.
    function nm_arch_counts($conn): array { nm_arch_ensure($conn); $c=['open'=>0,'ack'=>0,'dismissed'=>0];
        $r=$conn->query("SELECT status, COUNT(*) n FROM nm_archaeology_findings GROUP BY status"); while($r&&$x=$r->fetch_assoc()) $c[$x['status']]=(int)$x['n']; return $c; }
    // Dismissed findings for the review panel — dismissal must be reversible, not a black hole.
    function nm_arch_dismissed($conn): array { nm_arch_ensure($conn); $o=[];
        $r=$conn->query("SELECT * FROM nm_archaeology_findings WHERE status='dismissed' ORDER BY updated_at DESC LIMIT 100"); while($r&&$x=$r->fetch_assoc())$o[]=$x; return $o; }
}
