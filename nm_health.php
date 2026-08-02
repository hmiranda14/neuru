<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Predictive Link & Hardware Health engine.
//
//   Proactive (not reactive) degradation forecasting for BOTH:
//     · OPTICAL fiber (SFP DOM/DDM): Rx/Tx power dBm, laser bias mA, temp °C, Vcc
//     · ETHERNET / copper: error-counter RATES (Rx/Tx errors, discards, CRC/FCS)
//
//   The Python collector (scripts/nm_health.py) samples these per node+interface
//   into nm_health_samples. This engine fits a least-squares trend over a window
//   and predicts WHEN a metric will cross its critical threshold — e.g. "the SFP
//   Rx power on Node X is dropping 0.4 dBm/day and will hit −18 dBm in ~11 days —
//   schedule field maintenance". Same linear-regression idea as nm_sla.php's
//   capacity forecast, generalized to any health metric + direction.
//
//   Page gate = permission key 'health'.  See also [[netmon-sla]] nm_cap_forecast.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_audit.php';

if (!function_exists('nm_health_ensure')) {

    // ── Metric catalog: label, unit, kind, trend direction, thresholds ───────
    // dir 'fall' = degrades as it drops (optical power); 'rise' = degrades as it
    // climbs (errors, temperature). 'crit'/'warn' are the thresholds we forecast to.
    function nm_health_metrics(): array {
        return [
            'rx_dbm'       => ['label'=>'Optical Rx power','unit'=>'dBm','kind'=>'optical','dir'=>'fall','warn'=>-14,'crit'=>-18],
            'tx_dbm'       => ['label'=>'Optical Tx power','unit'=>'dBm','kind'=>'optical','dir'=>'fall','warn'=>-8,'crit'=>-11],
            'temp_c'       => ['label'=>'SFP temperature','unit'=>'°C','kind'=>'optical','dir'=>'rise','warn'=>70,'crit'=>80],
            'bias_ma'      => ['label'=>'Laser bias current','unit'=>'mA','kind'=>'optical','dir'=>'rise','warn'=>11,'crit'=>13],
            'volt_v'       => ['label'=>'SFP supply voltage','unit'=>'V','kind'=>'optical','dir'=>'rise','warn'=>3.6,'crit'=>3.8],
            'in_err_rate'  => ['label'=>'Rx error rate','unit'=>'err/s','kind'=>'eth','dir'=>'rise','warn'=>0.5,'crit'=>5],
            'out_err_rate' => ['label'=>'Tx error rate','unit'=>'err/s','kind'=>'eth','dir'=>'rise','warn'=>0.5,'crit'=>5],
            'fcs_rate'     => ['label'=>'CRC/FCS error rate','unit'=>'err/s','kind'=>'eth','dir'=>'rise','warn'=>0.5,'crit'=>5],
            'discard_rate' => ['label'=>'Discard rate','unit'=>'pkt/s','kind'=>'eth','dir'=>'rise','warn'=>1,'crit'=>20],
        ];
    }
    function nm_health_metric($m): ?array { $a=nm_health_metrics(); return $a[$m]??null; }

    function nm_health_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        static $done=false; if($done) return; $done=true;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_health_samples (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            node_id INT NOT NULL,
            kind VARCHAR(12) NOT NULL DEFAULT 'eth',
            entity VARCHAR(120) NOT NULL,
            metric VARCHAR(24) NOT NULL,
            value DOUBLE DEFAULT NULL,
            recorded_at DATETIME NOT NULL,
            KEY idx_series (node_id, entity, metric, recorded_at),
            KEY idx_time (recorded_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_health_predictions (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            node_id INT NOT NULL,
            entity VARCHAR(120) NOT NULL,
            metric VARCHAR(24) NOT NULL,
            kind VARCHAR(12) NOT NULL DEFAULT 'eth',
            severity VARCHAR(8) NOT NULL DEFAULT 'ok',
            direction VARCHAR(4) NOT NULL DEFAULT 'rise',
            current_val DOUBLE DEFAULT NULL,
            threshold DOUBLE DEFAULT NULL,
            slope_per_day DOUBLE DEFAULT NULL,
            eta_days DOUBLE DEFAULT NULL,
            samples INT DEFAULT 0,
            detail VARCHAR(400) DEFAULT NULL,
            status VARCHAR(10) NOT NULL DEFAULT 'open',
            first_seen DATETIME DEFAULT NULL,
            updated_at DATETIME DEFAULT NULL,
            UNIQUE KEY uniq_series (node_id, entity, metric),
            KEY idx_status (status, severity)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // Make sure the admin role can reach the page (idempotent).
        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled)
            SELECT 'admin','health',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='health')");
        // Per-node / per-vendor optical OID config for the collector.
        $conn->query("CREATE TABLE IF NOT EXISTS nm_health_optical_oids (
            id INT AUTO_INCREMENT PRIMARY KEY,
            vendor_key VARCHAR(40) NOT NULL DEFAULT 'generic',
            node_id INT DEFAULT NULL,
            label VARCHAR(80) NOT NULL DEFAULT '',
            metric VARCHAR(24) NOT NULL,
            oid VARCHAR(160) NOT NULL,
            scale DOUBLE NOT NULL DEFAULT 1,
            enabled TINYINT(1) NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            KEY idx_vendor (vendor_key), KEY idx_node (node_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // Seed common SFP DOM OID templates (disabled by default — the user enables
        // the ones that match their gear). ENTITY-SENSOR is generic; vendors vary.
        $r=$conn->query("SELECT COUNT(*) c FROM nm_health_optical_oids");
        if ($r && (int)$r->fetch_assoc()['c']===0) {
            $seed = [
                // vendor, label, metric, oid (base — collector walks the subtree), scale
                ['entity_sensor','ENTITY-SENSOR entPhySensorValue','rx_dbm','.1.3.6.1.2.1.99.1.1.1.4',1],
                ['mikrotik','MikroTik SFP Rx power (×0.01 dBm? verify)','rx_dbm','.1.3.6.1.4.1.14988.1.1.19.1.1.7',0.01],
                ['mikrotik','MikroTik SFP Tx power','tx_dbm','.1.3.6.1.4.1.14988.1.1.19.1.1.8',0.01],
                ['mikrotik','MikroTik SFP temperature','temp_c','.1.3.6.1.4.1.14988.1.1.19.1.1.3',0.001],
                ['mikrotik','MikroTik SFP Tx bias','bias_ma','.1.3.6.1.4.1.14988.1.1.19.1.1.6',0.001],
                ['mikrotik','MikroTik SFP supply voltage','volt_v','.1.3.6.1.4.1.14988.1.1.19.1.1.5',0.001],
                ['cisco','Cisco entSensorValue (DOM)','rx_dbm','.1.3.6.1.4.1.9.9.91.1.1.1.1.4',1],
            ];
            $st=$conn->prepare("INSERT INTO nm_health_optical_oids (vendor_key,label,metric,oid,scale,enabled) VALUES (?,?,?,?,?,0)");
            foreach($seed as $s){ $st->bind_param('sssds',$s[0],$s[1],$s[2],$s[3],$s[4]); $st->execute(); }
            $st->close();
        }
    }

    function nm_health_setting($conn,$k,$d){ $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; }

    // ── Excluded links — operator-muted interfaces that report garbage counters ──
    // Some devices (e.g. certain Cisco APs) put a packet/octet counter in the error
    // OID, so a link "degrades" forever. The plausibility ceiling in nm_health.py drops
    // the worst spikes; this lets an operator permanently mute a specific node+interface.
    // Stored in nm_settings.health_exclude as a JSON array of "node_id|entity" keys.
    function nm_health_excluded($conn): array {
        $j=nm_health_setting($conn,'health_exclude','[]'); $a=json_decode((string)$j,true);
        if(!is_array($a)) return [];
        $set=[]; foreach($a as $k){ if(is_string($k)) $set[$k]=1; } return $set;
    }
    function nm_health_exclude_save($conn,array $set): void {
        $list=array_values(array_keys($set));
        $val=$conn->real_escape_string(json_encode($list));
        $conn->query("INSERT INTO nm_settings (setting_key,setting_val) VALUES ('health_exclude','$val')
            ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
    }
    function nm_health_exclude_add($conn,int $node,string $entity): void {
        $set=nm_health_excluded($conn); $set[$node.'|'.$entity]=1; nm_health_exclude_save($conn,$set);
        // drop any open prediction + samples for the muted link so it stops alarming now
        $st=$conn->prepare("UPDATE nm_health_predictions SET status='cleared',severity='ok',updated_at=NOW() WHERE node_id=? AND entity=?");
        $st->bind_param('is',$node,$entity); $st->execute(); $st->close();
    }
    function nm_health_exclude_remove($conn,int $node,string $entity): void {
        $set=nm_health_excluded($conn); unset($set[$node.'|'.$entity]); nm_health_exclude_save($conn,$set);
    }

    // ── Generic least-squares forecaster ─────────────────────────────────────
    // $series = [[hoursAgoFloat (x), value (y)], …] where x increases with time.
    // Returns slope/day, recent current value, and ETA-days to $threshold given the
    // degradation $dir ('rise'|'fall'). eta=null if not trending toward failure.
    function nm_health_forecast(array $series, float $threshold, string $dir): array {
        $n=count($series);
        if($n<3) return ['n'=>$n,'slope_day'=>0.0,'current'=>null,'eta'=>null,'span_days'=>0.0];
        // ── Winsorize y to [p05,p95] so a lone spike/dropout can't fake a trend ──
        // (a real degradation is a rising/falling BASELINE — many points move, so the
        //  percentiles move with it; only isolated outliers get clipped.)
        $ys=array_map(fn($p)=>$p[1],$series); sort($ys);
        $pct=function(float $q) use ($ys,$n){ return $ys[max(0,min($n-1,(int)round($q*($n-1))))]; };
        $lo=$pct(0.05); $hi=$pct(0.95);
        $sx=$sy=$sxx=$sxy=0.0;
        foreach($series as $p){ $x=$p[0]; $y=max($lo,min($p[1],$hi)); $sx+=$x;$sy+=$y;$sxx+=$x*$x;$sxy+=$x*$y; }
        $den=$n*$sxx-$sx*$sx;
        $slopeH = $den!=0 ? ($n*$sxy-$sx*$sy)/$den : 0.0;   // per hour (on winsorized data)
        $slopeDay=$slopeH*24;
        // current = MEDIAN of the most-recent ~20% of points (a mean is skewed by one spike)
        $tail=max(3,(int)round($n*0.2)); $recent=array_slice($series,-$tail);
        $rv=array_map(fn($p)=>$p[1],$recent); sort($rv); $m=count($rv);
        $cur = ($m%2) ? $rv[intdiv($m,2)] : ($rv[(int)($m/2)-1]+$rv[(int)($m/2)])/2.0;
        // Need a real span of history before trusting an ETA — don't forecast weeks from a
        // day or two of data. Below the floor we still report current/slope but eta=null.
        $spanDays=($series[$n-1][0]-$series[0][0])/24.0;
        $minSpan=2.0;
        $eta=null;
        if($spanDays>=$minSpan){
            if($dir==='rise' && $slopeDay>1e-6 && $cur<$threshold)  $eta=round(($threshold-$cur)/$slopeDay,1);
            if($dir==='fall' && $slopeDay<-1e-6 && $cur>$threshold) $eta=round(($cur-$threshold)/(-$slopeDay),1);
            if($eta!==null && $eta>3650) $eta=null;   // >10y out = effectively flat, not a forecast
        }
        return ['n'=>$n,'slope_day'=>round($slopeDay,4),'current'=>round($cur,3),'eta'=>$eta,'span_days'=>round($spanDays,2)];
    }

    // Pull a metric series for one (node,entity,metric) over the window (days).
    function nm_health_series($conn,int $node,string $entity,string $metric,int $windowDays): array {
        $st=$conn->prepare("SELECT UNIX_TIMESTAMP(recorded_at) t, value v FROM nm_health_samples
            WHERE node_id=? AND entity=? AND metric=? AND recorded_at>=DATE_SUB(NOW(),INTERVAL ? DAY) AND value IS NOT NULL
            ORDER BY recorded_at ASC");
        $st->bind_param('issi',$node,$entity,$metric,$windowDays); $st->execute();
        $r=$st->get_result(); $rows=[]; while($x=$r->fetch_assoc()) $rows[]=$x; $st->close();
        if(!$rows) return [];
        $t0=(float)$rows[0]['t'];
        $out=[]; foreach($rows as $x){ $out[]=[((float)$x['t']-$t0)/3600.0, (float)$x['v']]; }
        return $out;
    }

    // ── The evaluation pass: forecast every series, upsert predictions ───────
    // Returns ['scanned','warn','crit','new_crit'=>[...]]. Run from cron_health.php.
    function nm_health_evaluate($conn): array {
        nm_health_ensure($conn);
        $window = (int)nm_health_setting($conn,'health_window_days','7') ?: 7;
        $minN   = (int)nm_health_setting($conn,'health_min_samples','12') ?: 12;
        $etaWarn= (float)nm_health_setting($conn,'health_eta_warn_days','45') ?: 45;
        $etaCrit= (float)nm_health_setting($conn,'health_eta_crit_days','14') ?: 14;
        $metas=nm_health_metrics();
        $nodeNames=[]; $nr=$conn->query("SELECT id,display_name FROM nm_nodes"); while($nr&&$x=$nr->fetch_assoc()) $nodeNames[(int)$x['id']]=$x['display_name'];

        // distinct active series in the window
        $series=$conn->query("SELECT DISTINCT node_id,entity,metric FROM nm_health_samples
            WHERE recorded_at>=DATE_SUB(NOW(),INTERVAL {$window} DAY)");
        $excluded=nm_health_excluded($conn);
        $scanned=0;$warn=0;$crit=0;$newCrit=[]; $now=date('Y-m-d H:i:s');
        while($series && $s=$series->fetch_assoc()){
            $node=(int)$s['node_id']; $entity=$s['entity']; $metric=$s['metric'];
            if(isset($excluded[$node.'|'.$entity])) continue;   // operator-muted link
            $meta=$metas[$metric]??null; if(!$meta) continue;
            $data=nm_health_series($conn,$node,$entity,$metric,$window);
            if(count($data)<$minN) continue;
            $scanned++;
            $f=nm_health_forecast($data,(float)$meta['crit'],$meta['dir']);
            $cur=$f['current']; $eta=$f['eta'];
            // severity: already past crit threshold OR forecast to cross it soon.
            $pastCrit = $meta['dir']==='rise' ? ($cur>=$meta['crit']) : ($cur<=$meta['crit']);
            $pastWarn = $meta['dir']==='rise' ? ($cur>=$meta['warn']) : ($cur<=$meta['warn']);
            $sev='ok';
            if($pastCrit || ($eta!==null && $eta<=$etaCrit)) $sev='crit';
            elseif($pastWarn || ($eta!==null && $eta<=$etaWarn)) $sev='warn';

            // build a human detail line
            $nn=$nodeNames[$node]??("node ".$node);
            if($eta!==null){
                $detail=sprintf('%s on %s %s is %s %.3f→%g %s at %s%g/day — reaches critical in ~%g days.',
                    $meta['label'],$nn,$entity,($meta['dir']==='fall'?'dropping':'rising'),
                    $cur,$meta['crit'],$meta['unit'],($f['slope_day']>=0?'+':''),$f['slope_day'],$eta);
            } else {
                $detail=sprintf('%s on %s %s = %g %s (trend %s%g/day).',
                    $meta['label'],$nn,$entity,$cur,$meta['unit'],($f['slope_day']>=0?'+':''),$f['slope_day']);
            }

            // was it crit before?
            $prevSev='';
            $pg=$conn->prepare("SELECT severity FROM nm_health_predictions WHERE node_id=? AND entity=? AND metric=? LIMIT 1");
            $pg->bind_param('iss',$node,$entity,$metric); $pg->execute();
            if($pr=$pg->get_result()->fetch_assoc()) $prevSev=$pr['severity']; $pg->close();

            $etaVal = $eta===null ? null : $eta;
            $st=$conn->prepare("INSERT INTO nm_health_predictions
                (node_id,entity,metric,kind,severity,direction,current_val,threshold,slope_per_day,eta_days,samples,detail,status,first_seen,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'open', ?, ?)
                ON DUPLICATE KEY UPDATE severity=VALUES(severity),current_val=VALUES(current_val),threshold=VALUES(threshold),
                  slope_per_day=VALUES(slope_per_day),eta_days=VALUES(eta_days),samples=VALUES(samples),detail=VALUES(detail),
                  status='open',updated_at=VALUES(updated_at)");
            $kind=$meta['kind']; $thr=(float)$meta['crit']; $slope=$f['slope_day']; $npts=$f['n'];
            $st->bind_param('isssssddddisss',$node,$entity,$metric,$kind,$sev,$meta['dir'],$cur,$thr,$slope,$etaVal,$npts,$detail,$now,$now);
            $st->execute(); $st->close();

            if($sev==='crit'){ $crit++; if($prevSev!=='crit') $newCrit[]=['node'=>$nn,'entity'=>$entity,'metric'=>$metric,'detail'=>$detail]; }
            elseif($sev==='warn'){ $warn++; }
            else { // recovered → mark cleared
                $cl=$conn->prepare("UPDATE nm_health_predictions SET status='cleared',severity='ok',updated_at=? WHERE node_id=? AND entity=? AND metric=?");
                $cl->bind_param('siss',$now,$node,$entity,$metric); $cl->execute(); $cl->close();
            }
        }
        // retention prune on samples
        $ret=(int)nm_health_setting($conn,'health_retention_days','45') ?: 45;
        $conn->query("DELETE FROM nm_health_samples WHERE recorded_at < DATE_SUB(NOW(),INTERVAL {$ret} DAY)");
        // Notification Center: each newly-critical forecast is a predictive alert.
        if ($newCrit) {
            if (!function_exists('nm_notify_event')) { @include_once __DIR__.'/nm_notify.php'; }
            if (function_exists('nm_notify_event')) foreach ($newCrit as $nc) {
                @nm_notify_event($conn,'predictive','critical',
                    "Predicted failure: {$nc['metric']} on {$nc['node']} {$nc['entity']}",
                    $nc['detail'], ['entity'=>$nc['node'].' · '.$nc['entity'],'source'=>'health']);
            }
        }
        return ['scanned'=>$scanned,'warn'=>$warn,'crit'=>$crit,'new_crit'=>$newCrit];
    }

    // Open predictions for the UI / dashboard, worst first.
    function nm_health_list($conn,string $sev=''): array {
        nm_health_ensure($conn);
        $w="status='open' AND severity IN ('warn','crit')";
        if($sev==='crit') $w="status='open' AND severity='crit'";
        $rows=[]; $r=$conn->query("SELECT * FROM nm_health_predictions WHERE {$w}
            ORDER BY FIELD(severity,'crit','warn') , (eta_days IS NULL), eta_days ASC, ABS(slope_per_day) DESC LIMIT 200");
        while($r&&$x=$r->fetch_assoc()) $rows[]=$x;
        return $rows;
    }
    function nm_health_counts($conn): array {
        nm_health_ensure($conn);
        $out=['crit'=>0,'warn'=>0];
        $r=$conn->query("SELECT severity,COUNT(*) c FROM nm_health_predictions WHERE status='open' AND severity IN('warn','crit') GROUP BY severity");
        while($r&&$x=$r->fetch_assoc()) $out[$x['severity']]=(int)$x['c'];
        return $out;
    }
}
