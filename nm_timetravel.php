<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Time-Travel engine. Reconstructs "what did the network look like at
// minute T" from the historical time-series NEURU already keeps:
//   nm_ping_stats (~1min) · nm_port_stats/nm_device_stats (~5min) ·
//   nm_netflow_flows (1min top-N) · nm_syslog · nm_incidents.
//
// nm_tt_snapshot($conn,$at) returns the full state at $at (node up/down + CPU,
// link load, top NetFlow talkers, incidents open at T, syslog burst). Drag the
// slider on timetravel.php and every panel re-renders to that instant.
// Page gate = permission key 'timetravel'.
// ─────────────────────────────────────────────────────────────────────────────

if (!function_exists('nm_tt_snapshot')) {

    function nm_tt_ensure_perm($conn): void {
        if (!($conn instanceof mysqli)) return;
        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled)
            SELECT 'admin','timetravel',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='timetravel')");
        // Perf: the snapshot's "latest CPU per node" query filters by metric_type+metric_key+time
        // but the default index leads with node_id → full index scan of 1.25M rows (~7s).
        // This covering index (metric_type,metric_key,recorded_at,node_id) makes it instant.
        // Guarded so it self-heals on a fresh DB; runs once (cheap information_schema check).
        try {
            $c = $conn->query("SELECT 1 FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_device_stats' AND INDEX_NAME='idx_metric_time' LIMIT 1");
            if (!$c || $c->num_rows === 0)
                @$conn->query("ALTER TABLE nm_device_stats ADD INDEX idx_metric_time (metric_type, metric_key, recorded_at, node_id)");
        } catch (\Throwable $e) {}
    }

    // Safe timestamp: parse anything, re-emit canonical 'Y-m-d H:i:s' (kills injection).
    function nm_tt_ts($raw): string {
        $t = is_numeric($raw) ? (int)$raw : strtotime((string)$raw);
        if (!$t) $t = time();
        return date('Y-m-d H:i:s', $t);
    }

    // Available data span for the slider bounds.
    function nm_tt_range($conn): array {
        $r=$conn->query("SELECT UNIX_TIMESTAMP(MIN(recorded_at)) mn, UNIX_TIMESTAMP(MAX(recorded_at)) mx FROM nm_ping_stats");
        $x=$r?$r->fetch_assoc():null;
        $max = $x && $x['mx'] ? (int)$x['mx'] : time();
        $min = $x && $x['mn'] ? (int)$x['mn'] : ($max-86400);
        // never offer more than 30 days back even if data is older
        $floor = $max - 30*86400;
        if ($min < $floor) $min = $floor;
        return ['min'=>$min,'max'=>$max];
    }

    function _tt_port_name(int $svc): string {
        static $m=[20=>'ftp',21=>'ftp',22=>'ssh',23=>'telnet',25=>'smtp',53=>'dns',67=>'dhcp',68=>'dhcp',
            80=>'http',110=>'pop3',123=>'ntp',143=>'imap',161=>'snmp',179=>'bgp',443=>'https',445=>'smb',
            465=>'smtps',500=>'ipsec',514=>'syslog',587=>'smtp',993=>'imaps',995=>'pop3s',1194=>'openvpn',
            1701=>'l2tp',1812=>'radius',3306=>'mysql',3389=>'rdp',5060=>'sip',5061=>'sip-tls',5432=>'postgres',
            5678=>'n8n',8080=>'http-alt',8443=>'https-alt',51820=>'wireguard',13231=>'wireguard'];
        return $m[$svc] ?? ($svc?('port '.$svc):'other');
    }
    function _tt_proto(int $p): string { return [1=>'icmp',6=>'tcp',17=>'udp',47=>'gre',50=>'esp'][$p] ?? ('p'.$p); }

    // The full snapshot at $at.
    function nm_tt_snapshot($conn, string $atRaw): array {
        $at = nm_tt_ts($atRaw);
        $look = 15; // minutes back to find the "latest sample at/before T"
        $nodes=[]; $nr=$conn->query("SELECT id,display_name,ip_address FROM nm_nodes ORDER BY display_name");
        while($nr&&$x=$nr->fetch_assoc()) $nodes[(int)$x['id']]=['id'=>(int)$x['id'],'name'=>$x['display_name'],'ip'=>$x['ip_address'],'state'=>'unknown','latency'=>null,'loss'=>null,'cpu'=>null];

        // ── Node up/down (+latency) — latest ping at/before T within lookback ──
        $r=$conn->query("SELECT p.node_id, p.is_up, p.latency_ms, p.packet_loss FROM nm_ping_stats p
            JOIN (SELECT node_id, MAX(recorded_at) mx FROM nm_ping_stats
                  WHERE recorded_at<='{$at}' AND recorded_at>=DATE_SUB('{$at}',INTERVAL {$look} MINUTE)
                  GROUP BY node_id) l ON l.node_id=p.node_id AND l.mx=p.recorded_at");
        while($r&&$x=$r->fetch_assoc()){ $id=(int)$x['node_id']; if(isset($nodes[$id])){
            $nodes[$id]['state']=((int)$x['is_up']===1)?'up':'down'; $nodes[$id]['latency']=$x['latency_ms']!==null?(float)$x['latency_ms']:null; $nodes[$id]['loss']=$x['packet_loss']!==null?(float)$x['packet_loss']:null; } }

        // ── CPU — latest cpu/avg at/before T ──
        $r=$conn->query("SELECT d.node_id, d.value FROM nm_device_stats d
            JOIN (SELECT node_id, MAX(recorded_at) mx FROM nm_device_stats
                  WHERE metric_type='cpu' AND metric_key='avg' AND recorded_at<='{$at}' AND recorded_at>=DATE_SUB('{$at}',INTERVAL {$look} MINUTE)
                  GROUP BY node_id) l ON l.node_id=d.node_id AND l.mx=d.recorded_at AND d.metric_type='cpu' AND d.metric_key='avg'");
        while($r&&$x=$r->fetch_assoc()){ $id=(int)$x['node_id']; if(isset($nodes[$id])) $nodes[$id]['cpu']=round((float)$x['value'],1); }

        // SNMP-only nodes (no ping): a fresh port sample at/before T means they were reachable.
        $r=$conn->query("SELECT DISTINCT node_id FROM nm_port_stats WHERE recorded_at<='{$at}' AND recorded_at>=DATE_SUB('{$at}',INTERVAL {$look} MINUTE)");
        while($r&&$x=$r->fetch_assoc()){ $id=(int)$x['node_id']; if(isset($nodes[$id]) && $nodes[$id]['state']==='unknown') $nodes[$id]['state']='up'; }

        $up=$down=$unk=0; foreach($nodes as $n){ if($n['state']==='up')$up++; elseif($n['state']==='down')$down++; else $unk++; }

        // ── Top links by utilization at/before T ──
        $links=[];
        $r=$conn->query("SELECT s.node_id, s.port_id, s.in_rate, s.out_rate, s.in_util, s.out_util, s.oper_status, i.if_name
            FROM nm_port_stats s
            JOIN (SELECT port_id, MAX(recorded_at) mx FROM nm_port_stats
                  WHERE recorded_at<='{$at}' AND recorded_at>=DATE_SUB('{$at}',INTERVAL {$look} MINUTE)
                  GROUP BY port_id) l ON l.port_id=s.port_id AND l.mx=s.recorded_at
            LEFT JOIN nm_interfaces i ON i.id=s.port_id
            ORDER BY GREATEST(COALESCE(s.in_util,0),COALESCE(s.out_util,0)) DESC, (s.in_rate+s.out_rate) DESC LIMIT 30");
        while($r&&$x=$r->fetch_assoc()){ $id=(int)$x['node_id'];
            $links[]=['node'=>$nodes[$id]['name']??('node '.$id),'iface'=>$x['if_name']?:('port '.$x['port_id']),
                'in_mbps'=>round(($x['in_rate']*8)/1e6,2),'out_mbps'=>round(($x['out_rate']*8)/1e6,2),
                'in_util'=>$x['in_util']!==null?(float)$x['in_util']:null,'out_util'=>$x['out_util']!==null?(float)$x['out_util']:null,
                'oper'=>$x['oper_status']]; }

        // ── NetFlow top talkers — nearest minute bucket <= T (within 2 min) ──
        $flows=[]; $nfBucket=null; $nfTotalMbps=0;
        $b=$conn->query("SELECT MAX(bucket) mb FROM nm_netflow_flows WHERE bucket<='{$at}' AND bucket>=DATE_SUB('{$at}',INTERVAL 2 MINUTE)");
        if($b && ($bx=$b->fetch_assoc()) && $bx['mb']){
            $nfBucket=$bx['mb']; $bkt=$conn->real_escape_string($nfBucket);
            $r=$conn->query("SELECT src_ip,dst_ip,app_port,protocol,SUM(bytes) b,SUM(packets) p FROM nm_netflow_flows
                WHERE bucket='{$bkt}' GROUP BY src_ip,dst_ip,app_port,protocol ORDER BY b DESC LIMIT 15");
            while($r&&$x=$r->fetch_assoc()){ $mbps=round(($x['b']*8)/60/1e6,3);
                $flows[]=['src'=>$x['src_ip'],'dst'=>$x['dst_ip'],'app'=>_tt_port_name((int)$x['app_port']),
                    'proto'=>_tt_proto((int)$x['protocol']),'mbps'=>$mbps,'pkts'=>(int)$x['p']]; }
            $t=$conn->query("SELECT SUM(bytes) b FROM nm_netflow_flows WHERE bucket='{$bkt}'");
            if($t && ($tx=$t->fetch_assoc())) $nfTotalMbps=round(($tx['b']*8)/60/1e6,2);
        }

        // ── Incidents open at T ──
        $incs=[];
        if($conn->query("SHOW TABLES LIKE 'nm_incidents'")->num_rows){
            $r=$conn->query("SELECT title,severity,impact,impact_count,opened_at,resolved_at FROM nm_incidents
                WHERE opened_at<='{$at}' AND (resolved_at IS NULL OR resolved_at>='{$at}')
                ORDER BY FIELD(severity,'critical','warning','info'), opened_at DESC LIMIT 50");
            while($r&&$x=$r->fetch_assoc()) $incs[]=['title'=>$x['title'],'severity'=>$x['severity'],'impact'=>$x['impact'],'impact_count'=>(int)$x['impact_count'],'opened_at'=>$x['opened_at']];
        }

        // ── Syslog burst around T (last 60s) ──
        $syslog=['rate'=>0,'errors'=>0,'lines'=>[]];
        if($conn->query("SHOW TABLES LIKE 'nm_syslog'")->num_rows){
            $r=$conn->query("SELECT COUNT(*) c, SUM(severity<=3) e FROM nm_syslog WHERE received_at>DATE_SUB('{$at}',INTERVAL 60 SECOND) AND received_at<='{$at}'");
            if($r&&($x=$r->fetch_assoc())){ $syslog['rate']=(int)$x['c']; $syslog['errors']=(int)$x['e']; }
            $r=$conn->query("SELECT received_at,hostname,host_ip,severity,tag,message FROM nm_syslog
                WHERE received_at<='{$at}' AND received_at>DATE_SUB('{$at}',INTERVAL 5 MINUTE) ORDER BY received_at DESC LIMIT 12");
            while($r&&$x=$r->fetch_assoc()) $syslog['lines'][]=['at'=>$x['received_at'],'host'=>$x['hostname']?:$x['host_ip'],'sev'=>(int)$x['severity'],'tag'=>$x['tag'],'msg'=>mb_substr((string)$x['message'],0,160)];
        }

        return [
            'at'=>$at,
            'summary'=>['up'=>$up,'down'=>$down,'unknown'=>$unk,'incidents'=>count($incs),'syslog_rate'=>$syslog['rate'],'nf_mbps'=>$nfTotalMbps],
            'nodes'=>array_values($nodes),
            'links'=>$links,
            'netflow'=>['bucket'=>$nfBucket,'total_mbps'=>$nfTotalMbps,'flows'=>$flows],
            'incidents'=>$incs,
            'syslog'=>$syslog,
        ];
    }
}
