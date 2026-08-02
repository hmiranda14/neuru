<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Technical-Debt & Wear engine. A per-node "Stress Index" (0–100) from
// chronic-aging signals NEURU already collects: power-cycles (uptime resets),
// sustained CPU, memory pressure, link instability (ping flaps), traffic load,
// and degradation history. Shown as an RPG-style HP bar + a replacement hint.
// (Acute degradation = Predictive Health; this is the chronic "wear" view.)
// Page gate = permission key 'wear'.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_audit.php';

if (!function_exists('nm_wear_compute')) {

    function nm_wear_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        static $done=false; if($done) return; $done=true;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_wear_history (
            node_id INT NOT NULL, recorded_at DATE NOT NULL, stress INT NOT NULL DEFAULT 0,
            PRIMARY KEY (node_id, recorded_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','wear',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='wear')");
    }
    function nm_wear_setting($conn,$k,$d){ $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; }
    function _wclamp($x,$a,$b){ return max($a,min($b,$x)); }

    // Compute the wear/stress index for every node over the window (days).
    function nm_wear_compute($conn, int $days=30): array {
        nm_wear_ensure($conn);
        $nodes=[]; $nr=$conn->query("SELECT id,display_name,ip_address,os_icon,hw_model FROM nm_nodes ORDER BY display_name");
        while($nr&&$x=$nr->fetch_assoc()) $nodes[(int)$x['id']]=['id'=>(int)$x['id'],'name'=>$x['display_name'],'ip'=>$x['ip_address'],'model'=>$x['hw_model'],
            'reboots'=>0,'uptime_days'=>null,'cpu_avg'=>null,'cpu_hi'=>0,'mem_avg'=>null,'flaps'=>0,'preds'=>0,'load'=>null];

        // ── power-cycles: count uptime-value drops per node ──
        $r=$conn->query("SELECT node_id, value, recorded_at FROM nm_device_stats WHERE metric_type='uptime' AND recorded_at>=DATE_SUB(NOW(),INTERVAL {$days} DAY) ORDER BY node_id, recorded_at");
        $prev=[]; $lastUp=[];
        while($r&&$x=$r->fetch_assoc()){ $n=(int)$x['node_id']; $v=(float)$x['value'];
            if(isset($prev[$n]) && $v < $prev[$n]-60 && $v < $prev[$n]*0.9) { if(isset($nodes[$n])) $nodes[$n]['reboots']++; }
            $prev[$n]=$v; $lastUp[$n]=$v; }
        foreach($lastUp as $n=>$v){ if(isset($nodes[$n])) $nodes[$n]['uptime_days']=round($v/86400,1); }  // poller stores seconds

        // ── CPU: avg + % of samples over 80% ──
        $r=$conn->query("SELECT node_id, AVG(value) av, AVG(value>=80)*100 hi FROM nm_device_stats WHERE metric_type='cpu' AND metric_key='avg' AND recorded_at>=DATE_SUB(NOW(),INTERVAL {$days} DAY) GROUP BY node_id");
        while($r&&$x=$r->fetch_assoc()){ $n=(int)$x['node_id']; if(isset($nodes[$n])){ $nodes[$n]['cpu_avg']=round((float)$x['av'],1); $nodes[$n]['cpu_hi']=round((float)$x['hi'],1); } }

        // ── Memory pressure: latest ram/memory % per node ──
        $r=$conn->query("SELECT node_id, AVG(value) av FROM nm_device_stats WHERE metric_type IN('ram','memory') AND metric_key IN('used_pct','percent','usage','used') AND recorded_at>=DATE_SUB(NOW(),INTERVAL {$days} DAY) GROUP BY node_id");
        while($r&&$x=$r->fetch_assoc()){ $n=(int)$x['node_id']; if(isset($nodes[$n])) $nodes[$n]['mem_avg']=round((float)$x['av'],1); }

        // ── Link instability: ping up/down transitions (flaps) ──
        $r=$conn->query("SELECT node_id, is_up FROM nm_ping_stats WHERE recorded_at>=DATE_SUB(NOW(),INTERVAL {$days} DAY) ORDER BY node_id, recorded_at");
        $pl=[]; while($r&&$x=$r->fetch_assoc()){ $n=(int)$x['node_id']; $u=(int)$x['is_up']; if(isset($pl[$n]) && $pl[$n]!==$u && isset($nodes[$n])) $nodes[$n]['flaps']++; $pl[$n]=$u; }

        // ── Degradation history: open health predictions per node ──
        if($conn->query("SHOW TABLES LIKE 'nm_health_predictions'")->num_rows){
            $r=$conn->query("SELECT node_id, COUNT(*) c FROM nm_health_predictions WHERE status='open' AND severity IN('warn','crit') GROUP BY node_id");
            while($r&&$x=$r->fetch_assoc()){ $n=(int)$x['node_id']; if(isset($nodes[$n])) $nodes[$n]['preds']=(int)$x['c']; }
        }
        // ── Traffic load proxy: avg utilization across the node's ports ──
        $r=$conn->query("SELECT node_id, AVG(GREATEST(COALESCE(in_util,0),COALESCE(out_util,0))) u FROM nm_port_stats WHERE recorded_at>=DATE_SUB(NOW(),INTERVAL {$days} DAY) GROUP BY node_id");
        while($r&&$x=$r->fetch_assoc()){ $n=(int)$x['node_id']; if(isset($nodes[$n])) $nodes[$n]['load']=round((float)$x['u'],1); }

        // ── Score ──
        $out=[];
        foreach($nodes as $n){
            $s = 0; $factors=[];
            $rb = (int)$n['reboots']; $cp = min(35,$rb*10); $s+=$cp; if($rb>0)$factors[]="$rb power-cycle".($rb>1?'s':'')." (+$cp)";
            $ca = $n['cpu_avg']!==null?(float)$n['cpu_avg']:0; $chi=(float)$n['cpu_hi'];
            $cpuPts = round(_wclamp($ca,0,100)*0.12 + $chi*0.15); $s+=$cpuPts; if($cpuPts>2)$factors[]="CPU avg ".round($ca)."% / ".round($chi)."% hot (+$cpuPts)";
            $ma = $n['mem_avg']!==null?(float)$n['mem_avg']:0; $mPts=round(_wclamp($ma,0,100)*0.12); $s+=$mPts; if($mPts>3)$factors[]="memory ".round($ma)."% (+$mPts)";
            $fl=(int)$n['flaps']; $fPts=min(20,$fl*2); $s+=$fPts; if($fl>0)$factors[]="$fl link flap".($fl>1?'s':'')." (+$fPts)";
            $pd=(int)$n['preds']; $pPts=min(20,$pd*10); $s+=$pPts; if($pd>0)$factors[]="$pd degradation alert".($pd>1?'s':'')." (+$pPts)";
            $ld = $n['load']!==null?(float)$n['load']:0; $lPts=round(_wclamp($ld,0,100)*0.05); $s+=$lPts; if($lPts>2)$factors[]="sustained load ".round($ld)."% (+$lPts)";
            $stress = (int)_wclamp($s,0,100); $health=100-$stress;
            $rec = $stress>=85?'Critical wear — schedule hardware replacement this quarter.'
                 :($stress>=65?'High stress — plan replacement / investigate the drivers.'
                 :($stress>=40?'Moderate wear — keep an eye on it.':'Healthy — no action needed.'));
            $out[]=$n + ['stress'=>$stress,'health'=>$health,'factors'=>$factors,'recommendation'=>$rec];
        }
        usort($out, fn($a,$b)=>$b['stress']<=>$a['stress']);
        return $out;
    }

    // Daily snapshot for the trend sparkline.
    function nm_wear_snapshot($conn): int {
        nm_wear_ensure($conn); $n=0; $today=date('Y-m-d');
        foreach(nm_wear_compute($conn,30) as $w){
            $st=$conn->prepare("INSERT INTO nm_wear_history (node_id,recorded_at,stress) VALUES (?,?,?) ON DUPLICATE KEY UPDATE stress=VALUES(stress)");
            $st->bind_param('isi',$w['id'],$today,$w['stress']); $st->execute(); $n++;
        }
        return $n;
    }
    function nm_wear_trend($conn,int $nodeId,int $days=30): array {
        $o=[]; $st=$conn->prepare("SELECT recorded_at,stress FROM nm_wear_history WHERE node_id=? AND recorded_at>=DATE_SUB(CURDATE(),INTERVAL ? DAY) ORDER BY recorded_at");
        $st->bind_param('ii',$nodeId,$days); $st->execute(); $r=$st->get_result(); while($x=$r->fetch_assoc()) $o[]=(int)$x['stress'];
        return $o;
    }
}
