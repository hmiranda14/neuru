<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Network Sonar. The NOC's see-and-hear scope: pick a target (the whole
// network or one node), watch a live radar of every node, see traffic against your
// own bandwidth/latency thresholds, get plain-English "what broke & why" diagnostics,
// and HEAR it all as a generative soundscape (Web Audio). RBAC: 'sonify'.
//   ?api=pulse[&node=ID] → live telemetry + radar nodes + diagnostics
//   ?api=cfg (GET) / POST → bandwidth/latency/error thresholds (persisted)
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'sonify')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=sonify'); exit;
}
@$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','sonify',1 FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='sonify')");

// ── threshold config (persisted in nm_settings.sonar_cfg) ─────────────────────
function sonar_cfg($conn): array {
    $def = ['bw_warn'=>100,'bw_crit'=>500,'lat_warn'=>80,'lat_crit'=>200,'err_warn'=>1,'err_crit'=>5];
    $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='sonar_cfg' LIMIT 1");
    if ($r && ($x=$r->fetch_row())) { $d=json_decode($x[0],true); if(is_array($d)) return array_merge($def,$d); }
    return $def;
}
if ($api === 'cfg') {
    header('Content-Type: application/json; charset=utf-8');
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $c = sonar_cfg($conn); $in = $_POST;
        foreach (['bw_warn','bw_crit','lat_warn','lat_crit','err_warn','err_crit'] as $k)
            if (isset($in[$k]) && is_numeric($in[$k])) $c[$k] = max(0, (float)$in[$k]);
        $conn->query("INSERT INTO nm_settings (setting_key,setting_val) VALUES ('sonar_cfg','".$conn->real_escape_string(json_encode($c))."')
            ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
        echo json_encode(['ok'=>true,'cfg'=>$c]); exit;
    }
    echo json_encode(['ok'=>true,'cfg'=>sonar_cfg($conn)]); exit;
}

if ($api === 'pulse') {
    header('Content-Type: application/json; charset=utf-8');
    $node = (int)($_GET['node'] ?? 0);                 // 0 = whole network
    $cfg  = sonar_cfg($conn);
    $nodeFilter = $node > 0 ? " AND s.node_id={$node} " : '';

    // bandwidth (Mbps) — latest per port, optionally one node
    $mbps = 0;
    if ($r=$conn->query("SELECT SUM(s.in_rate+s.out_rate) bps FROM nm_port_stats s
        JOIN (SELECT port_id,node_id,MAX(recorded_at) mx FROM nm_port_stats WHERE recorded_at>=DATE_SUB(NOW(),INTERVAL 10 MINUTE) GROUP BY port_id,node_id) l
        ON l.port_id=s.port_id AND l.mx=s.recorded_at WHERE 1 {$nodeFilter}")) { if($x=$r->fetch_assoc()) $mbps=round(((float)$x['bps']*8)/1e6,2); }

    // cpu
    $cpu = 0;
    $cpuF = $node>0 ? " AND d.node_id={$node} " : '';
    if ($r=$conn->query("SELECT AVG(d.value) v FROM nm_device_stats d
        JOIN (SELECT node_id,MAX(recorded_at) mx FROM nm_device_stats WHERE metric_type='cpu' AND metric_key='avg' AND recorded_at>=DATE_SUB(NOW(),INTERVAL 15 MINUTE) GROUP BY node_id) l
        ON l.node_id=d.node_id AND l.mx=d.recorded_at AND d.metric_type='cpu' AND d.metric_key='avg' WHERE 1 {$cpuF}")) { if($x=$r->fetch_assoc()) $cpu=round((float)$x['v'],1); }

    // errors/s
    $err = 0;
    if ($conn->query("SHOW TABLES LIKE 'nm_health_samples'")->num_rows) {
        if ($r=$conn->query("SELECT AVG(value) v FROM nm_health_samples WHERE kind='eth' AND metric IN('in_err_rate','out_err_rate','fcs_rate','discard_rate') AND recorded_at>=DATE_SUB(NOW(),INTERVAL 15 MINUTE)")) { if($x=$r->fetch_assoc()) $err=round((float)$x['v'],3); }
    }

    // GPU (AI servers) — peak utilization / hottest temp / fullest VRAM across targets
    $gpu=0; $gpuTemp=0; $gpuVram=0; $gpuName=''; $gpuHas=false;
    if ($conn->query("SHOW TABLES LIKE 'nm_gpu_stats'")->num_rows) {
        $gnf = $node>0 ? " AND t.node_id={$node} " : '';
        if ($r=$conn->query("SELECT g.name gname, t.name tname, s.util_pct u, s.temp_c tmp,
                100*s.mem_used_mb/NULLIF(s.mem_total_mb,0) vramp
            FROM nm_gpu_stats s
            JOIN (SELECT gpu_id,MAX(id) mid FROM nm_gpu_stats WHERE sampled_at>=DATE_SUB(NOW(),INTERVAL 10 MINUTE) GROUP BY gpu_id) l ON l.mid=s.id
            JOIN nm_gpu g ON g.id=s.gpu_id
            JOIN nm_gpu_targets t ON t.id=g.target_id
            WHERE t.enabled=1 {$gnf}")) {
            while($x=$r->fetch_assoc()){ $gpuHas=true; $u=(float)$x['u'];
                if($u>=$gpu){ $gpu=$u; $gpuName=$x['tname'].' · '.$x['gname']; }
                if((float)$x['tmp']>$gpuTemp) $gpuTemp=(float)$x['tmp'];
                if($x['vramp']!==null && (float)$x['vramp']>$gpuVram) $gpuVram=(float)$x['vramp'];
            }
        }
        $gpu=round($gpu); $gpuTemp=round($gpuTemp); $gpuVram=round($gpuVram);
    }

    // per-node radar: latest ping status + latency
    $nodes = []; $up=0; $down=0; $latSum=0; $latN=0; $downList=[];
    // nodes that are clearly ALIVE because they're reporting SNMP/port stats — used so
    // SNMP-only (non-pinged) nodes show green instead of grey "unknown".
    $alive = [];
    if ($r=$conn->query("SELECT DISTINCT node_id FROM nm_port_stats WHERE recorded_at>=DATE_SUB(NOW(),INTERVAL 20 MINUTE)")) while($x=$r->fetch_row()) $alive[(int)$x[0]]=1;
    if ($conn->query("SHOW TABLES LIKE 'nm_device_stats'")->num_rows && ($r=$conn->query("SELECT DISTINCT node_id FROM nm_device_stats WHERE recorded_at>=DATE_SUB(NOW(),INTERVAL 20 MINUTE)"))) while($x=$r->fetch_row()) $alive[(int)$x[0]]=1;
    $nf = $node>0 ? " WHERE n.id={$node} " : '';
    if ($r=$conn->query("SELECT n.id, n.display_name name, n.ip_address ip, p.is_up, p.latency_ms lat
        FROM nm_nodes n
        LEFT JOIN (SELECT s.node_id, s.is_up, s.latency_ms FROM nm_ping_stats s
            JOIN (SELECT node_id,MAX(id) mid FROM nm_ping_stats GROUP BY node_id) l ON l.node_id=s.node_id AND l.mid=s.id) p
          ON p.node_id=n.id {$nf} ORDER BY n.display_name LIMIT 60")) {
        while($x=$r->fetch_assoc()){
            $st = $x['is_up']===null ? 'unknown' : ((int)$x['is_up']===1 ? 'up':'down');
            if($st==='unknown' && isset($alive[(int)$x['id']])) $st='up';   // reporting stats → alive
            if($st==='up'){ $up++; if($x['lat']!==null){ $latSum+=(float)$x['lat']; $latN++; } }
            elseif($st==='down'){ $down++; $downList[]=['name'=>$x['name'],'ip'=>$x['ip']]; }
            $nodes[] = ['id'=>(int)$x['id'],'name'=>$x['name'],'status'=>$st,'lat'=>$x['lat']!==null?round((float)$x['lat'],1):null];
        }
    }
    $latency = $latN ? round($latSum/$latN,1) : 0;

    $inc=0; $thr=0;
    if ($conn->query("SHOW TABLES LIKE 'nm_incidents'")->num_rows) { if($r=$conn->query("SELECT COUNT(*) FROM nm_incidents WHERE status IN('open','acknowledged')")) $inc=(int)$r->fetch_row()[0]; }
    // Only PENDING threats need attention — 'active' means the vaccine is live (already blocked),
    // 'dismissed'/'revoked' are handled. Counting 'active' here falsely alarmed on handled threats.
    if ($conn->query("SHOW TABLES LIKE 'nm_threats'")->num_rows) { if($r=$conn->query("SELECT COUNT(*) FROM nm_threats WHERE status='pending'")) $thr=(int)$r->fetch_row()[0]; }

    // ── WHO is using the bandwidth — from NetFlow (real attributed traffic) ─────
    $talkers = []; $apps = []; $nf_mbps = 0;
    if ($conn->query("SHOW TABLES LIKE 'nm_netflow_flows'")->num_rows) {
        @require_once __DIR__ . '/nm_netflow.php';
        if (function_exists('nm_nf_top_talkers')) { $talkers = nm_nf_top_talkers($conn, 10, 'src', '', 8); $apps = nm_nf_top_apps($conn, 10, '', 6); }
        if ($r=$conn->query("SELECT SUM(bytes) b FROM nm_netflow_flows WHERE bucket>=DATE_SUB(NOW(),INTERVAL 10 MINUTE)")) { if($x=$r->fetch_assoc()) $nf_mbps=round(((float)$x['b']*8)/600/1e6,2); }
    }

    // ── DIAGNOSTICS: what's wrong + why it could break + what to check ──────────
    $dg = [];
    if ($down > 0) {
        $names = implode(', ', array_slice(array_map(fn($n)=>$n['name'], $downList),0,5)) . ($down>5?'…':'');
        $dg[] = ['level'=>'crit','icon'=>'fa-plug-circle-xmark','title'=>"{$down} node".($down>1?'s':'')." DOWN",
            'detail'=>"Unreachable by ICMP: {$names}.",
            'causes'=>['Power loss or device crash','Upstream/uplink or switch-port failure','Recent config change or firmware','Cable / fibre / SFP fault','Firewall or ACL blocking ICMP'],
            'checks'=>['Ping its gateway & a neighbour to localise','Console / out-of-band access','Review recent config diffs (Config Manager)','Check the upstream interface & PoE','Power & environmental']];
    }
    if ($cfg['bw_crit']>0 && $mbps >= $cfg['bw_crit']) {
        $dg[] = ['level'=>'crit','icon'=>'fa-gauge-high','title'=>"Bandwidth saturation — {$mbps} Mb/s",
            'detail'=>"Throughput is at/over your critical threshold ({$cfg['bw_crit']} Mb/s).",
            'causes'=>['DDoS or scan / traffic flood','Backup / replication / large transfer','Broadcast or routing-loop storm','Mis-sized link or QoS misconfig','Malware / exfiltration'],
            'checks'=>['NetFlow → Top Talkers & Top Apps','Per-interface utilisation','Recent changes / new hosts','Shadow IT & Immunity for anomalies']];
    } elseif ($cfg['bw_warn']>0 && $mbps >= $cfg['bw_warn']) {
        $dg[] = ['level'=>'warn','icon'=>'fa-gauge','title'=>"High bandwidth — {$mbps} Mb/s",
            'detail'=>"Above warning threshold ({$cfg['bw_warn']} Mb/s). Trending toward saturation.",
            'causes'=>['Heavy but legitimate transfer','Growing user load','New service or replication'],
            'checks'=>['NetFlow top talkers','Watch the trend on the traffic graph']];
    }
    if ($cfg['lat_crit']>0 && $latency >= $cfg['lat_crit']) {
        $dg[] = ['level'=>'crit','icon'=>'fa-stopwatch','title'=>"High latency — {$latency} ms",
            'detail'=>"Average RTT is at/over critical ({$cfg['lat_crit']} ms).",
            'causes'=>['Link congestion / buffer bloat','Routing flap or sub-optimal path','Upstream / ISP degradation','Duplex mismatch or errored link','Overloaded device CPU'],
            'checks'=>['Traceroute to the target (Net Tools)','Smokeping / Predictive Health trend','Interface error counters','Device CPU & memory']];
    } elseif ($cfg['lat_warn']>0 && $latency >= $cfg['lat_warn']) {
        $dg[] = ['level'=>'warn','icon'=>'fa-stopwatch','title'=>"Elevated latency — {$latency} ms",
            'detail'=>"Above warning threshold ({$cfg['lat_warn']} ms).",
            'causes'=>['Rising congestion','Path change','Early link degradation'],
            'checks'=>['Smokeping history','Traceroute for a path change']];
    }
    if ($cfg['err_crit']>0 && $err >= $cfg['err_crit']) {
        $dg[] = ['level'=>'crit','icon'=>'fa-bolt','title'=>"Interface errors — {$err}/s",
            'detail'=>"Error/discard rate at/over critical ({$cfg['err_crit']}/s). Frames are being dropped.",
            'causes'=>['Bad cable / connector / patch','Failing or dirty SFP / optic','Duplex or speed mismatch','Failing switch port / ASIC','EMI or marginal fibre'],
            'checks'=>['Predictive Health (SFP DOM, error trend)','Swap cable / SFP on the worst port','Lock speed/duplex','Move to a known-good port']];
    } elseif ($cfg['err_warn']>0 && $err >= $cfg['err_warn']) {
        $dg[] = ['level'=>'warn','icon'=>'fa-bolt','title'=>"Rising errors — {$err}/s",
            'detail'=>"Above warning threshold ({$cfg['err_warn']}/s).",
            'causes'=>['Marginal cable / SFP','Early port degradation'],
            'checks'=>['Interface error counters','Predictive Health forecast']];
    }
    if ($cpu >= 90) $dg[] = ['level'=>'warn','icon'=>'fa-microchip','title'=>"High CPU — {$cpu}%",
        'detail'=>"Device CPU is heavily loaded; control-plane and latency may suffer.",
        'causes'=>['Routing/ARP churn','Process or attack (e.g. CPU-bound ACL)','Undersized device'],
        'checks'=>['Top processes on the device','Recent topology/route changes']];
    if ($gpuHas && $gpuTemp >= 85) $dg[] = ['level'=>$gpuTemp>=90?'crit':'warn','icon'=>'fa-fire-flame-curved','title'=>"GPU hot — {$gpuTemp}°C",
        'detail'=>"{$gpuName} is running hot.",
        'causes'=>['Heavy sustained inference load','Poor case airflow / dust build-up','Fan failure or a soft fan curve','High ambient temperature'],
        'checks'=>['Open the AI / GPU Monitor for per-GPU detail','Check fans & airflow','Lower batch size / concurrent models']];
    if ($gpuHas && $gpuVram >= 92) $dg[] = ['level'=>$gpuVram>=98?'crit':'warn','icon'=>'fa-memory','title'=>"GPU VRAM almost full — {$gpuVram}%",
        'detail'=>"{$gpuName} VRAM is nearly exhausted — the next model may not fit or may spill to system RAM.",
        'causes'=>['A large model is loaded','Multiple models kept resident','Context window / batch too large'],
        'checks'=>['Open the AI / GPU Monitor → see the loaded model','Unload idle Ollama models','Use a smaller quantization']];
    if ($thr > 0) $dg[] = ['level'=>'warn','icon'=>'fa-skull-crossbones','title'=>"{$thr} pending threat".($thr>1?'s':''),
        'detail'=>"Collective Immunity has {$thr} threat".($thr>1?'s':'')." awaiting review/vaccination (vaccinated &amp; dismissed ones are not counted).",'causes'=>['Port scan / malicious DNS / intrusion'],'checks'=>['Open Collective Immunity to review & vaccinate']];
    if ($inc > 0) $dg[] = ['level'=>'info','icon'=>'fa-triangle-exclamation','title'=>"{$inc} open incident".($inc>1?'s':''),
        'detail'=>"Correlated incidents are open.",'causes'=>[],'checks'=>['Open Incident Command for root cause & impact']];
    if (!$dg) $dg[] = ['level'=>'ok','icon'=>'fa-circle-check','title'=>'All nominal',
        'detail'=>'No nodes down, traffic/latency/errors within thresholds, no open incidents.','causes'=>[],'checks'=>[]];

    // attach actionable deep-links (keyed by the diagnostic's icon) + an 'incidents' loader key
    $linksByIcon = [
        'fa-plug-circle-xmark'=>[['Network Map','net_mon_map.php','fa-diagram-project'],['Live Ping','netping.php','fa-tower-broadcast'],['Traceroute','nettrace.php','fa-route'],['Config Manager','config_mgr.php','fa-code-branch']],
        'fa-gauge-high'=>[['NetFlow Analyzer','netflow.php','fa-chart-area'],['Shadow IT','shadowit.php','fa-user-secret'],['Immunity','immunity.php','fa-shield-virus']],
        'fa-gauge'=>[['NetFlow Analyzer','netflow.php','fa-chart-area']],
        'fa-stopwatch'=>[['Traceroute','nettrace.php','fa-route'],['Smokeping','smokeping.php','fa-wave-square'],['Predictive Health','health.php','fa-heart-pulse']],
        'fa-bolt'=>[['Predictive Health','health.php','fa-heart-pulse'],['Statistics','net_mon_stats.php','fa-chart-bar']],
        'fa-microchip'=>[['Statistics','net_mon_stats.php','fa-chart-bar']],
        'fa-fire-flame-curved'=>[['AI / GPU Monitor','gpu.php','fa-microchip'],['Statistics','net_mon_stats.php','fa-chart-bar']],
        'fa-memory'=>[['AI / GPU Monitor','gpu.php','fa-microchip']],
        'fa-skull-crossbones'=>[['Collective Immunity','immunity.php','fa-shield-virus']],
        'fa-triangle-exclamation'=>[['Incident Command','incidents.php','fa-triangle-exclamation']],
    ];
    foreach ($dg as &$d) {
        $d['links'] = array_map(fn($l)=>['label'=>$l[0],'href'=>$l[1],'icon'=>$l[2]], $linksByIcon[$d['icon']] ?? []);
        $d['key']   = $d['icon']==='fa-triangle-exclamation' ? 'incidents' : '';
    } unset($d);

    echo json_encode(['ok'=>true,'ts'=>date('H:i:s'),'node'=>$node,
        'mbps'=>$mbps,'cpu'=>$cpu,'err'=>$err,'latency'=>$latency,
        'up'=>$up,'down'=>$down,'incidents'=>$inc,'threats'=>$thr,
        'gpu'=>$gpu,'gpu_temp'=>$gpuTemp,'gpu_vram'=>$gpuVram,'gpu_name'=>$gpuName,'gpu_has'=>$gpuHas?1:0,
        'nodes'=>$nodes,'downList'=>$downList,'cfg'=>$cfg,'diagnostics'=>$dg,
        'talkers'=>$talkers,'apps'=>$apps,'nf_mbps'=>$nf_mbps]); exit;
}

// ── WHO is this IP? instant drill-down: GeoIP + rDNS + where it's going ───────
if ($api === 'who') {
    header('Content-Type: application/json; charset=utf-8');
    $ip = preg_replace('/[^0-9a-fA-F:.]/', '', $_GET['ip'] ?? '');
    if ($ip === '') { echo json_encode(['ok'=>false]); exit; }
    @require_once __DIR__ . '/nm_nettools.php';
    $geo = function_exists('nm_nt_geoip') ? nm_nt_geoip($conn, $ip) : null;
    $rdns = @gethostbyaddr($ip); if ($rdns === $ip) $rdns = null;
    $esc = $conn->real_escape_string($ip); $secs = 600; $total = 0; $dests = []; $apps = [];
    if ($conn->query("SHOW TABLES LIKE 'nm_netflow_flows'")->num_rows) {
        if ($r=$conn->query("SELECT SUM(bytes) b FROM nm_netflow_flows WHERE src_ip='$esc' AND bucket>=DATE_SUB(NOW(),INTERVAL 10 MINUTE)")) { if($x=$r->fetch_assoc()) $total=round(((float)$x['b']*8)/$secs/1e6,2); }
        if ($r=$conn->query("SELECT dst_ip ip, SUM(bytes) b, SUM(flows) f FROM nm_netflow_flows WHERE src_ip='$esc' AND bucket>=DATE_SUB(NOW(),INTERVAL 10 MINUTE) GROUP BY dst_ip ORDER BY b DESC LIMIT 6")) while($x=$r->fetch_assoc()) $dests[]=['ip'=>$x['ip'],'mbps'=>round(((float)$x['b']*8)/$secs/1e6,2),'flows'=>(int)$x['f']];
        @require_once __DIR__ . '/nm_netflow.php';
        if ($r=$conn->query("SELECT app_port,protocol,SUM(bytes) b FROM nm_netflow_flows WHERE src_ip='$esc' AND bucket>=DATE_SUB(NOW(),INTERVAL 10 MINUTE) GROUP BY app_port,protocol ORDER BY b DESC LIMIT 6")) while($x=$r->fetch_assoc()) $apps[]=['app'=>(function_exists('nm_nf_app_name')?nm_nf_app_name((int)$x['app_port'],(int)$x['protocol']):(string)$x['app_port']),'mbps'=>round(((float)$x['b']*8)/$secs/1e6,2)];
    }
    echo json_encode(['ok'=>true,'ip'=>$ip,'rdns'=>$rdns,
        'geo'=>($geo && empty($geo['private'])) ? $geo : ($geo ? ['private'=>true] : null),
        'total'=>$total,'dests'=>$dests,'apps'=>$apps]); exit;
}

// ── shared node-state resolver (same alive logic as ?api=pulse) ───────────────
function sonar_node_states($conn, int $node): array {
    $alive = [];
    if ($r=$conn->query("SELECT DISTINCT node_id FROM nm_port_stats WHERE recorded_at>=DATE_SUB(NOW(),INTERVAL 20 MINUTE)")) while($x=$r->fetch_row()) $alive[(int)$x[0]]=1;
    if ($conn->query("SHOW TABLES LIKE 'nm_device_stats'")->num_rows && ($r=$conn->query("SELECT DISTINCT node_id FROM nm_device_stats WHERE recorded_at>=DATE_SUB(NOW(),INTERVAL 20 MINUTE)"))) while($x=$r->fetch_row()) $alive[(int)$x[0]]=1;
    $nf = $node>0 ? " WHERE n.id={$node} " : '';
    $nodes = [];
    if ($r=$conn->query("SELECT n.id, n.display_name name, n.ip_address ip, p.is_up, p.latency_ms lat
        FROM nm_nodes n
        LEFT JOIN (SELECT s.node_id, s.is_up, s.latency_ms FROM nm_ping_stats s
            JOIN (SELECT node_id,MAX(id) mid FROM nm_ping_stats GROUP BY node_id) l ON l.node_id=s.node_id AND l.mid=s.id) p
          ON p.node_id=n.id {$nf} ORDER BY n.display_name")) {
        while($x=$r->fetch_assoc()){
            $st = $x['is_up']===null ? 'unknown' : ((int)$x['is_up']===1 ? 'up':'down');
            if($st==='unknown' && isset($alive[(int)$x['id']])) $st='up';
            $nodes[] = ['id'=>(int)$x['id'],'name'=>$x['name'],'ip'=>$x['ip'],'status'=>$st,'lat'=>$x['lat']!==null?round((float)$x['lat'],1):null];
        }
    }
    return $nodes;
}

// ── per-metric drill-down: click a KPI → what's behind that number ────────────
if ($api === 'metric') {
    header('Content-Type: application/json; charset=utf-8');
    $m    = preg_replace('/[^a-z]/','', $_GET['m'] ?? '');
    $node = (int)($_GET['node'] ?? 0);
    $cfg  = sonar_cfg($conn);
    $nodeFilter = $node>0 ? " AND ps.node_id={$node} " : '';
    $items=[]; $title=''; $icon='fa-circle-info'; $color='#4da3ff'; $summary=''; $note=''; $links=[];
    $errLbl = ['in_err_rate'=>'RX errors','out_err_rate'=>'TX errors','fcs_rate'=>'FCS errors','discard_rate'=>'discards'];

    if ($m === 'mbps') {
        $title='Bandwidth — interface breakdown'; $icon='fa-gauge-high'; $color='#4da3ff';
        if ($r=$conn->query("SELECT n.display_name node, COALESCE(NULLIF(i.display_name,''),i.if_name) iface, ps.in_rate ir, ps.out_rate orr
            FROM nm_port_stats ps
            JOIN (SELECT node_id,port_id,MAX(recorded_at) mx FROM nm_port_stats WHERE recorded_at>=DATE_SUB(NOW(),INTERVAL 10 MINUTE) GROUP BY node_id,port_id) lp
              ON ps.node_id=lp.node_id AND ps.port_id=lp.port_id AND ps.recorded_at=lp.mx
            JOIN nm_interfaces i ON i.id=ps.port_id AND i.node_id=ps.node_id
            JOIN nm_nodes n ON n.id=ps.node_id
            WHERE 1 {$nodeFilter} ORDER BY (COALESCE(ps.in_rate,0)+COALESCE(ps.out_rate,0)) DESC LIMIT 18")) {
            while($x=$r->fetch_assoc()){ $in=round(((float)$x['ir']*8)/1e6,2); $out=round(((float)$x['orr']*8)/1e6,2); $tot=round($in+$out,2);
                $items[]=['main'=>($x['iface']?:'—'),'sub'=>$x['node'].' · ↓'.$in.' ↑'.$out,'val'=>$tot,'unit'=>'Mb/s']; }
        }
        $summary='Top monitored interfaces by current throughput (last 10 min).';
        $note='This is the aggregate the headline KPI sums — each transit hop counts its own copy of a flow, so the total runs higher than real link traffic. For who & what, use “Who’s using it” below.';
        $links=[['NetFlow Analyzer','netflow.php','fa-chart-area'],['Shadow IT','shadowit.php','fa-user-secret']];
    } elseif ($m === 'lat') {
        $title='Latency — per node (RTT)'; $icon='fa-stopwatch'; $color='#36e3d0';
        $lw=(float)$cfg['lat_warn']; $lc=(float)$cfg['lat_crit'];
        $ns=array_filter(sonar_node_states($conn,$node), fn($n)=>$n['status']!=='down' && $n['lat']!==null);
        usort($ns, fn($a,$b)=>$b['lat']<=>$a['lat']);
        foreach(array_slice($ns,0,25) as $n){ $c=$n['lat']>=$lc?'#e74c3c':($n['lat']>=$lw?'#f39c12':'#2ecc71');
            $items[]=['main'=>$n['name'],'sub'=>$n['ip'],'val'=>$n['lat'],'unit'=>'ms','valColor'=>$c]; }
        $summary=count($ns).' nodes responding · warn ≥'.$lw.'ms · crit ≥'.$lc.'ms (highest first).';
        $links=[['Smokeping','smokeping.php','fa-wave-square'],['Traceroute','nettrace.php','fa-route'],['Predictive Health','health.php','fa-heart-pulse']];
    } elseif ($m === 'err') {
        $title='Interface errors — per port'; $icon='fa-bolt'; $color='#f39c12';
        if ($conn->query("SHOW TABLES LIKE 'nm_health_samples'")->num_rows) {
            $nf2 = $node>0 ? " AND h.node_id={$node} " : '';
            if ($r=$conn->query("SELECT n.display_name node, h.entity, h.metric, h.value
                FROM nm_health_samples h
                JOIN (SELECT node_id,entity,metric,MAX(recorded_at) mx FROM nm_health_samples WHERE kind='eth' AND metric IN('in_err_rate','out_err_rate','fcs_rate','discard_rate') AND recorded_at>=DATE_SUB(NOW(),INTERVAL 30 MINUTE) GROUP BY node_id,entity,metric) l
                  ON l.node_id=h.node_id AND l.entity=h.entity AND l.metric=h.metric AND l.mx=h.recorded_at
                JOIN nm_nodes n ON n.id=h.node_id
                WHERE h.value>0 {$nf2} ORDER BY h.value DESC LIMIT 25")) {
                while($x=$r->fetch_assoc()){ $v=round((float)$x['value'],3); $c=$v>=(float)$cfg['err_crit']?'#e74c3c':($v>=(float)$cfg['err_warn']?'#f39c12':'#9aa3ad');
                    $items[]=['main'=>$x['entity'].' — '.($errLbl[$x['metric']]??$x['metric']),'sub'=>$x['node'],'val'=>$v,'unit'=>'/s','valColor'=>$c]; }
            }
        }
        $summary='Latest non-zero error/discard rate per interface (last 30 min).';
        $note='Sustained non-zero rates point to a bad cable or connector, a dirty/failing SFP, or a duplex/speed mismatch. Try swapping the cable/optic on the worst port.';
        $links=[['Predictive Health','health.php','fa-heart-pulse'],['Statistics','net_mon_stats.php','fa-chart-bar']];
    } elseif ($m === 'cpu') {
        $title='CPU load — per device'; $icon='fa-microchip'; $color='#36e3d0';
        $nf3 = $node>0 ? " AND d.node_id={$node} " : '';
        if ($r=$conn->query("SELECT n.display_name node, n.ip_address ip, d.value
            FROM nm_device_stats d
            JOIN (SELECT node_id,MAX(recorded_at) mx FROM nm_device_stats WHERE metric_type='cpu' AND metric_key='avg' AND recorded_at>=DATE_SUB(NOW(),INTERVAL 15 MINUTE) GROUP BY node_id) l
              ON l.node_id=d.node_id AND l.mx=d.recorded_at AND d.metric_type='cpu' AND d.metric_key='avg'
            JOIN nm_nodes n ON n.id=d.node_id WHERE 1 {$nf3} ORDER BY d.value DESC LIMIT 25")) {
            while($x=$r->fetch_assoc()){ $v=round((float)$x['value'],1); $c=$v>=90?'#e74c3c':($v>=70?'#f39c12':'#2ecc71');
                $items[]=['main'=>$x['node'],'sub'=>$x['ip'],'val'=>$v,'unit'=>'%','valColor'=>$c]; }
        }
        $summary='Latest CPU per reporting device (last 15 min, highest first).';
        $note='Above ~90% the control-plane, routing and latency can suffer. Check top processes and recent topology/route changes on the hottest device.';
        $links=[['Statistics','net_mon_stats.php','fa-chart-bar']];
    } elseif ($m === 'up' || $m === 'down') {
        $down = $m==='down';
        $title = $down ? 'Nodes down' : 'Nodes up'; $icon = $down ? 'fa-plug-circle-xmark' : 'fa-circle-check'; $color = $down ? '#e74c3c' : '#2ecc71';
        foreach (sonar_node_states($conn,$node) as $n) {
            if ($down ? $n['status']==='down' : $n['status']==='up') {
                $items[] = $down
                    ? ['main'=>$n['name'],'sub'=>$n['ip'],'val'=>'DOWN','unit'=>'','valColor'=>'#e74c3c']
                    : ['main'=>$n['name'],'sub'=>$n['ip'],'val'=>($n['lat']!==null?$n['lat']:'—'),'unit'=>($n['lat']!==null?'ms':''),'valColor'=>'#2ecc71'];
            }
        }
        $summary = $down ? (count($items).' node'.(count($items)==1?'':'s').' unreachable by ICMP.') : (count($items).' nodes reachable / reporting.');
        if ($down && !$items) $note='No nodes are down — everything is reachable. 🎉';
        $links = $down
            ? [['Network Map','net_mon_map.php','fa-diagram-project'],['Live Ping','netping.php','fa-tower-broadcast'],['Config Manager','config_mgr.php','fa-code-branch']]
            : [['Network Map','net_mon_map.php','fa-diagram-project']];
    } elseif ($m === 'thr') {
        $title='Pending threats'; $icon='fa-skull-crossbones'; $color='#e74c3c';
        if ($conn->query("SHOW TABLES LIKE 'nm_threats'")->num_rows) {
            if ($r=$conn->query("SELECT indicator, ind_type, severity, source, hits, detail FROM nm_threats WHERE status='pending' ORDER BY hits DESC, last_seen DESC LIMIT 40")) {
                while($x=$r->fetch_assoc()){ $isip=$x['ind_type']==='ip';
                    $pc = $x['severity']==='high'?'#e74c3c':(($x['severity']==='med'||$x['severity']==='medium')?'#f39c12':'#4da3ff');
                    $items[]=['main'=>$x['indicator'],'sub'=>strtoupper($x['ind_type']).' · '.$x['source'].($x['detail']?(' · '.$x['detail']):''),
                        'val'=>(int)$x['hits'],'unit'=>'hits','pill'=>$x['severity'],'pillColor'=>$pc,'clickIp'=>($isip?$x['indicator']:null)]; }
            }
        }
        $summary=count($items).' pending indicator'.(count($items)==1?'':'s').' from Collective Immunity (vaccinated &amp; dismissed excluded).';
        $note='Click an IP to see who & where it is. Vaccinate from Collective Immunity to fan-out the block to every Pi-hole and firewall.';
        $links=[['Collective Immunity','immunity.php','fa-shield-virus']];
    } elseif ($m === 'gpu') {
        $title='GPU load — AI servers'; $icon='fa-microchip'; $color='#76b900';
        if ($conn->query("SHOW TABLES LIKE 'nm_gpu_stats'")->num_rows) {
            $gnf = $node>0 ? " AND t.node_id={$node} " : '';
            if ($r=$conn->query("SELECT t.id tid, t.name tname, g.name gname, g.gpu_index gi,
                    s.util_pct u, s.mem_used_mb mu, s.mem_total_mb mt, s.temp_c tmp, s.power_w pw
                FROM nm_gpu_stats s
                JOIN (SELECT gpu_id,MAX(id) mid FROM nm_gpu_stats GROUP BY gpu_id) l ON l.mid=s.id
                JOIN nm_gpu g ON g.id=s.gpu_id
                JOIN nm_gpu_targets t ON t.id=g.target_id
                WHERE t.enabled=1 {$gnf} ORDER BY s.util_pct DESC LIMIT 25")) {
                while($x=$r->fetch_assoc()){
                    $u=round((float)$x['u']); $vp = (float)$x['mt']>0 ? round(100*(float)$x['mu']/(float)$x['mt']) : null;
                    $c = $u>=90?'#e74c3c':($u>=70?'#f39c12':'#2ecc71');
                    $sub = $x['tname'].' · VRAM '.($vp!==null?$vp.'%':'—').($x['tmp']!==null?' · '.round((float)$x['tmp']).'°C':'').($x['pw']!==null?' · '.round((float)$x['pw']).'W':'');
                    $items[]=['main'=>($x['gname']?:('GPU'.$x['gi'])),'sub'=>$sub,'val'=>$u,'unit'=>'%','valColor'=>$c];
                }
            }
            // loaded models (whole network, or the selected node's target)
            $mq = $node>0
                ? "SELECT mo.name, mo.vram_mb FROM nm_gpu_models mo JOIN nm_gpu_targets t ON t.id=mo.target_id WHERE t.node_id={$node} ORDER BY mo.vram_mb DESC LIMIT 8"
                : "SELECT name, vram_mb FROM nm_gpu_models ORDER BY vram_mb DESC LIMIT 8";
            if ($r=$conn->query($mq)) while($x=$r->fetch_assoc()){
                $items[]=['main'=>'▸ '.$x['name'],'sub'=>'Ollama model loaded in VRAM','val'=>($x['vram_mb']>=1024?round($x['vram_mb']/1024,1).'G':$x['vram_mb'].'M'),'unit'=>'VRAM','valColor'=>'#76b900'];
            }
        }
        $summary = $items ? 'Live GPU utilization per device, plus any model currently resident in VRAM.' : 'No GPU data — add an AI server in the GPU Monitor.';
        $note='High utilization is normal during inference. The signals that matter are sustained heat and VRAM saturation (the next model may not fit).';
        $links=[['AI / GPU Monitor','gpu.php','fa-microchip'],['Statistics','net_mon_stats.php','fa-chart-bar']];
    } else {
        echo json_encode(['ok'=>false,'error'=>'unknown metric']); exit;
    }
    echo json_encode(['ok'=>true,'title'=>$title,'icon'=>$icon,'color'=>$color,'summary'=>$summary,'note'=>$note,
        'items'=>$items,'links'=>array_map(fn($l)=>['label'=>$l[0],'href'=>$l[1],'icon'=>$l[2]],$links)]); exit;
}

log_user_action($conn,'view_page','sonify.php');
// node list for the target selector
$NODES = [];
if ($r=$conn->query("SELECT id, display_name FROM nm_nodes ORDER BY display_name")) while($x=$r->fetch_assoc()) $NODES[]=$x;
// is there any GPU/AI server to monitor? (controls the GPU KPI tile)
$HAS_GPU = $conn->query("SHOW TABLES LIKE 'nm_gpu_targets'")->num_rows
    && ($gr=$conn->query("SELECT 1 FROM nm_gpu_targets WHERE enabled=1 LIMIT 1")) && $gr->num_rows>0;
$CFG = sonar_cfg($conn);
include('header.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Sonar | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
<?= nm_chrome_css() ?>
:root{ --glass:rgba(255,255,255,.055); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cyan:#36e3d0; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; overflow-x:hidden; }
a{ color:var(--accent); text-decoration:none; }
.wrap{ max-width:1320px; margin:0 auto; padding:16px 20px 50px; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:16px; }
.card{ padding:16px 18px; margin-bottom:16px; }
.bar{ display:flex; align-items:center; gap:12px; flex-wrap:wrap; margin-bottom:16px; }
.sel,.in{ background:#1b2129; color:#e6e9ee; border:1px solid var(--border); border-radius:9px; padding:9px 12px; font-size:13px; }
.bigbtn{ font-size:14px; font-weight:700; padding:11px 22px; border-radius:30px; cursor:pointer; border:1px solid var(--accent); background:rgba(77,163,255,.15); color:var(--accent); display:inline-flex; gap:9px; align-items:center; }
.bigbtn.on{ background:var(--crit); border-color:var(--crit); color:#fff; }
.statepill{ font-weight:800; letter-spacing:2px; text-transform:uppercase; font-size:13px; padding:6px 14px; border-radius:20px; border:1px solid var(--border); }
.grid{ display:grid; grid-template-columns:1.15fr 1fr; gap:16px; align-items:start; } @media(max-width:980px){ .grid{ grid-template-columns:1fr; } }
.col{ display:flex; flex-direction:column; gap:16px; }
h3{ margin:0 0 12px; font-size:12px; color:var(--accent); text-transform:uppercase; letter-spacing:1.2px; display:flex; align-items:center; gap:8px; }
#radar{ width:100%; height:360px; display:block; } #scope-wrap{ position:relative; }
.kpis{ display:grid; grid-template-columns:repeat(4,1fr); gap:10px; } .kpi{ text-align:center; padding:11px 8px; border-radius:10px; }
.kpi.click{ cursor:pointer; transition:background .15s, box-shadow .15s; } .kpi.click:hover{ background:rgba(77,163,255,.09); box-shadow:inset 0 0 0 1px rgba(77,163,255,.25); }
.kpi .n{ font-size:21px; font-weight:800; } .kpi .l{ font-size:9.5px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; margin-top:2px; }
#traffic{ width:100%; height:140px; display:block; }
.dg{ border:1px solid var(--border); border-left-width:4px; border-radius:10px; padding:11px 13px; margin-bottom:10px; }
.dg.crit{ border-left-color:var(--crit); background:rgba(231,76,60,.06); } .dg.warn{ border-left-color:var(--warn); background:rgba(243,156,18,.05); }
.dg.info{ border-left-color:var(--accent); } .dg.ok{ border-left-color:var(--ok); background:rgba(46,204,113,.05); }
.dg .t{ font-weight:700; display:flex; align-items:center; gap:9px; font-size:13.5px; } .dg .d{ color:#aab2bc; font-size:12.5px; margin:5px 0 0; }
.dg .sub{ margin:8px 0 0; } .dg .sub b{ font-size:10.5px; text-transform:uppercase; letter-spacing:.5px; color:#8a929c; }
.dg .sub ul{ margin:3px 0 0; padding-left:18px; } .dg .sub li{ font-size:12px; color:#cdd4dd; line-height:1.5; }
.dgcrit{color:#f0a59d}.dgwarn{color:#f0c674}.dginfo{color:#9fbfe0}.dgok{color:#9fe0b0}
.thgrid{ display:grid; grid-template-columns:1fr 1fr; gap:10px 14px; } .thgrid label{ display:flex; flex-direction:column; gap:4px; font-size:11px; color:#8a929c; font-weight:600; }
.muted{ color:#7c828c; font-size:12px; } .legend{ font-size:12.5px; color:#aab; line-height:1.85; } .legend b{ color:#cfd3da; }
.dot{ width:9px;height:9px;border-radius:50%;display:inline-block; }
.bsave{ background:rgba(46,204,113,.14); border:1px solid rgba(46,204,113,.4); color:#7fe0a3; border-radius:8px; padding:8px 14px; cursor:pointer; font-size:12.5px; font-weight:700; }
.dg{ cursor:default; } .dg.click{ cursor:pointer; } .dg.click:hover{ border-color:var(--accent); }
#snr-modal{ position:fixed; inset:0; z-index:4000; display:none; align-items:center; justify-content:center; background:rgba(2,4,8,.66); backdrop-filter:blur(3px); }
#snr-modal.show{ display:flex; }
.snr-card{ width:min(580px,94%); max-height:86%; display:flex; flex-direction:column; background:rgba(12,17,26,.98); border:1px solid rgba(77,163,255,.3); border-radius:14px; box-shadow:0 24px 70px rgba(0,0,0,.7); }
.snr-h{ display:flex; align-items:center; gap:10px; padding:13px 16px; border-bottom:1px solid var(--border); font-weight:700; color:#fff; }
.snr-h #snr-title{ flex:1; min-width:0; } .snr-h .x{ cursor:pointer; color:#8a909a; } .snr-h .x:hover{ color:#f0a59d; }
.snr-b{ overflow:auto; padding:14px 16px; font-size:13px; line-height:1.55; }
.snr-act{ display:flex; gap:8px; flex-wrap:wrap; margin:6px 0 4px; }
.snr-act a, .snr-act .lnk{ display:inline-flex; align-items:center; gap:6px; font-size:12px; font-weight:600; color:#cfd6df; background:var(--glass); border:1px solid var(--border); padding:7px 12px; border-radius:8px; text-decoration:none; cursor:pointer; }
.snr-act a:hover, .snr-act .lnk:hover{ border-color:var(--accent); color:#fff; }
.snr-sub{ margin-top:10px; } .snr-sub b{ font-size:10.5px; text-transform:uppercase; letter-spacing:.5px; color:#8a929c; display:flex; align-items:center; gap:7px; }
.snr-sub ul{ margin:4px 0 0; padding-left:20px; } .snr-sub li{ font-size:12.5px; color:#cdd4dd; line-height:1.6; }
.snr-inc{ border:1px solid var(--border); border-left-width:4px; border-radius:9px; padding:9px 11px; margin-bottom:8px; cursor:pointer; }
.snr-inc:hover{ border-color:var(--accent); } .snr-inc .it{ font-weight:600; } .snr-inc .im{ color:#9aa3ad; font-size:11px; margin-top:3px; }
.snr-pill{ font-size:10px; font-weight:700; padding:2px 8px; border-radius:6px; text-transform:uppercase; }
.who-row{ display:flex; align-items:center; gap:9px; padding:5px 2px; border-bottom:1px solid rgba(255,255,255,.05); font-size:12.5px; cursor:pointer; }
.who-row:last-child{ border-bottom:none; } .who-row:hover{ color:#fff; }
.who-bar{ flex:1; height:6px; background:rgba(255,255,255,.08); border-radius:5px; overflow:hidden; } .who-bar>i{ display:block; height:100%; background:linear-gradient(90deg,#36e3d0,#4da3ff); }
.mono{ font-family:monospace; }
</style>
</head>
<body>
<div class="wrap">
<?php nm_page_header('<i class="fa-solid fa-satellite-dish"></i>Network Sonar', '', 'See & hear your network', 'fa-solid fa-satellite-dish'); ?>

<div class="bar glass card" style="margin-bottom:16px;">
  <span class="muted"><i class="fa-solid fa-crosshairs"></i> Target</span>
  <select class="sel" id="target" onchange="retarget()">
    <option value="0">Whole network</option>
    <?php foreach($NODES as $n): ?><option value="<?= (int)$n['id'] ?>"><?= htmlspecialchars($n['display_name']) ?></option><?php endforeach; ?>
  </select>
  <button class="bigbtn" id="toggle" onclick="toggle()"><i class="fa-solid fa-satellite-dish" id="ticon"></i> <span id="tlabel">Start sonar</span></button>
  <span class="muted"><i class="fa-solid fa-volume-low"></i></span>
  <input type="range" id="vol" min="0" max="100" value="55" style="width:150px;accent-color:var(--accent);" oninput="setVol(this.value)">
  <span class="muted" id="mute-note">muted until started</span>
  <span style="margin-left:auto;"></span>
  <span class="statepill" id="state" style="color:var(--ok)">STANDBY</span>
  <span class="muted" id="ts"></span>
</div>

<div class="grid">
  <!-- LEFT: scope + traffic -->
  <div class="col">
    <div class="glass card">
      <h3><i class="fa-solid fa-circle-nodes"></i> Sonar scope <span class="muted" id="scope-cnt" style="margin-left:auto;letter-spacing:0;text-transform:none;"></span></h3>
      <div id="scope-wrap"><canvas id="radar"></canvas></div>
      <div class="muted" style="margin-top:6px;"><span class="dot" style="background:var(--ok)"></span> up &nbsp; <span class="dot" style="background:var(--warn)"></span> high latency &nbsp; <span class="dot" style="background:var(--crit)"></span> down &nbsp; · distance from centre = how far from healthy</div>
    </div>
    <div class="glass card">
      <h3><i class="fa-solid fa-wave-square"></i> Live traffic <span class="muted" id="bw-now" style="margin-left:auto;letter-spacing:0;text-transform:none;"></span></h3>
      <canvas id="traffic"></canvas>
      <div class="muted" style="margin-top:4px;">Interface aggregate (in+out across all monitored ports — counts each hop). Dashed lines = warn/crit thresholds. <b>Attributed traffic & who's responsible is below ↓</b></div>
    </div>
    <div class="glass card">
      <h3><i class="fa-solid fa-users-viewfinder"></i> Who's using it <span class="muted" id="nf-total" style="margin-left:auto;letter-spacing:0;text-transform:none;">—</span></h3>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;" id="who-grid">
        <div><div class="muted" style="margin-bottom:6px;font-size:11px;text-transform:uppercase;letter-spacing:.5px;">Top talkers (source)</div><div id="talkers"><div class="muted">—</div></div></div>
        <div><div class="muted" style="margin-bottom:6px;font-size:11px;text-transform:uppercase;letter-spacing:.5px;">Top applications</div><div id="apps"><div class="muted">—</div></div></div>
      </div>
      <div class="muted" style="margin-top:8px;">Real attributed traffic from <b>NetFlow</b>. <b>Click a talker</b> to see where it's going & what it's running.</div>
    </div>
    <div class="glass card kpis">
      <div class="kpi click" onclick="showMetric('mbps')" title="Per-interface breakdown of the aggregate"><div class="n" style="color:var(--accent)" id="k-mbps">—</div><div class="l">Mb/s (iface agg) ›</div></div>
      <div class="kpi click" onclick="showMetric('lat')" title="Per-node round-trip time"><div class="n" style="color:var(--cyan)" id="k-lat">—</div><div class="l">Latency ms ›</div></div>
      <div class="kpi click" onclick="showMetric('err')" title="Which interfaces are erroring"><div class="n" style="color:var(--warn)" id="k-err">—</div><div class="l">Errors/s ›</div></div>
      <div class="kpi click" onclick="showMetric('cpu')" title="Per-device CPU load"><div class="n" id="k-cpu">—</div><div class="l">CPU % ›</div></div>
      <?php if ($HAS_GPU): ?>
      <div class="kpi click" onclick="showMetric('gpu')" title="GPU load on AI servers + loaded model"><div class="n" style="color:#76b900" id="k-gpu">—</div><div class="l">GPU % ›</div></div>
      <?php endif; ?>
      <div class="kpi click" onclick="showMetric('up')" title="Which nodes are up"><div class="n" style="color:var(--ok)" id="k-up">—</div><div class="l">Up ›</div></div>
      <div class="kpi click" onclick="showMetric('down')" title="Which nodes are down"><div class="n" style="color:var(--crit)" id="k-down">—</div><div class="l">Down ›</div></div>
      <div class="kpi click" onclick="showIncidentsList()" title="View open incidents"><div class="n" style="color:var(--warn)" id="k-inc">—</div><div class="l">Incidents ›</div></div>
      <div class="kpi click" onclick="showMetric('thr')" title="PENDING Collective-Immunity threats (vaccinated/dismissed excluded)"><div class="n" style="color:var(--crit)" id="k-thr">—</div><div class="l">Threats ›</div></div>
    </div>
  </div>

  <!-- RIGHT: diagnostics + thresholds + legend -->
  <div class="col">
    <div class="glass card">
      <h3><i class="fa-solid fa-stethoscope"></i> Diagnostics — what the sonar detects</h3>
      <div id="diag"><div class="muted">Start the sonar to scan.</div></div>
    </div>
    <div class="glass card">
      <h3><i class="fa-solid fa-sliders"></i> Thresholds</h3>
      <div class="thgrid">
        <label>Bandwidth warn (Mb/s) <input class="in" id="c-bw_warn" type="number" min="0" value="<?= (float)$CFG['bw_warn'] ?>"></label>
        <label>Bandwidth crit (Mb/s) <input class="in" id="c-bw_crit" type="number" min="0" value="<?= (float)$CFG['bw_crit'] ?>"></label>
        <label>Latency warn (ms) <input class="in" id="c-lat_warn" type="number" min="0" value="<?= (float)$CFG['lat_warn'] ?>"></label>
        <label>Latency crit (ms) <input class="in" id="c-lat_crit" type="number" min="0" value="<?= (float)$CFG['lat_crit'] ?>"></label>
        <label>Errors warn (/s) <input class="in" id="c-err_warn" type="number" min="0" step="0.1" value="<?= (float)$CFG['err_warn'] ?>"></label>
        <label>Errors crit (/s) <input class="in" id="c-err_crit" type="number" min="0" step="0.1" value="<?= (float)$CFG['err_crit'] ?>"></label>
      </div>
      <div style="margin-top:12px;"><button class="bsave" onclick="saveCfg()"><i class="fa-solid fa-floppy-disk"></i> Save thresholds</button> <span class="muted" id="cfg-msg"></span></div>
    </div>
    <div class="glass card">
      <h3><i class="fa-solid fa-ear-listen"></i> What you're hearing</h3>
      <div class="legend">
        🎵 <b>Drone</b> — calm baseline; the network is breathing.<br>
        💓 <b>Pulse tempo</b> — faster with <b>traffic</b>.<br>
        🎸 <b>Dissonance / fuzz</b> — grows with <b>errors</b>.<br>
        ✨ <b>Brightness</b> — opens with <b>CPU &amp; GPU</b> load.<br>
        🔔 <b>Bells</b> — open <b>incidents / threats</b>.<br>
        🌑 <b>Low groan</b> — a node is <b>down</b>.
      </div>
    </div>
  </div>
</div>
</div>

<div id="snr-modal"><div class="snr-card">
  <div class="snr-h"><span id="snr-title">Details</span><span class="x" onclick="closeModal()"><i class="fa-solid fa-xmark"></i></span></div>
  <div class="snr-b" id="snr-body"></div>
</div></div>

<script>
let AC=null, master=null, nodes=null, playing=false, pollT=null, alertT=null, TARGET=0;
let CFG=<?= json_encode($CFG) ?>, RNODES=[], bwHist=[], sweep=0, lastPulse=null;
const vEl=id=>document.getElementById(id);
const clamp=(x,a,b)=>Math.max(a,Math.min(b,x));
let mbpsPeak=20;

/* ── Audio engine (unchanged core) ── */
function buildGraph(){
  AC=new (window.AudioContext||window.webkitAudioContext)();
  master=AC.createGain(); master.gain.value=(+vEl('vol').value)/100*0.5; master.connect(AC.destination);
  const comp=AC.createDynamicsCompressor(); comp.threshold.value=-18; comp.ratio.value=4; comp.connect(master);
  const lp=AC.createBiquadFilter(); lp.type='lowpass'; lp.frequency.value=900; lp.Q.value=0.6; lp.connect(comp);
  const shaper=AC.createWaveShaper(); shaper.curve=makeCurve(0); shaper.oversample='2x';
  const wet=AC.createGain(); wet.gain.value=0; const dry=AC.createGain(); dry.gain.value=1; shaper.connect(wet); wet.connect(lp); dry.connect(lp);
  const droneGain=AC.createGain(); droneGain.gain.value=0; droneGain.connect(shaper); droneGain.connect(dry);
  [110.0,130.81,164.81].forEach((f,i)=>{ const o=AC.createOscillator(); o.type=i===0?'sine':'triangle'; o.frequency.value=f; const g=AC.createGain(); g.gain.value=0.22; o.connect(g); g.connect(droneGain); o.start(); });
  const disO=AC.createOscillator(); disO.type='sawtooth'; disO.frequency.value=116.54; const disG=AC.createGain(); disG.gain.value=0; disO.connect(disG); disG.connect(droneGain); disO.start();
  const grO=AC.createOscillator(); grO.type='sine'; grO.frequency.value=55; const grG=AC.createGain(); grG.gain.value=0; grO.connect(grG); grG.connect(dry); grO.start();
  const lfo=AC.createOscillator(); lfo.type='sine'; lfo.frequency.value=0.9; const lfoG=AC.createGain(); lfoG.gain.value=0.08; lfo.connect(lfoG); lfoG.connect(droneGain.gain); lfo.start();
  nodes={lp,shaper,wet,dry,droneGain,disG,grG,lfo,disO}; droneGain.gain.setTargetAtTime(0.5,AC.currentTime,1.2);
}
function makeCurve(a){ const n=256,c=new Float32Array(n),k=a*100; for(let i=0;i<n;i++){ const x=i*2/n-1; c[i]=(1+k)*x/(1+k*Math.abs(x)); } return c; }
function bell(low){ if(!AC||!playing) return; const t=AC.currentTime; const o=AC.createOscillator(); o.type='sine'; o.frequency.value=low?330:880; const g=AC.createGain(); g.gain.value=0; o.connect(g); g.connect(nodes.dry); g.gain.setValueAtTime(0,t); g.gain.linearRampToValueAtTime(0.18,t+0.01); g.gain.exponentialRampToValueAtTime(0.0001,t+1.1); o.start(t); o.stop(t+1.2); }

/* ── Apply a pulse: audio + all the visuals ── */
function apply(d){
  lastPulse=d; CFG=d.cfg||CFG; RNODES=d.nodes||[];
  // ── visuals (run even before audio is started? only when playing we poll) ──
  vEl('k-mbps').textContent=d.mbps; vEl('k-lat').textContent=d.latency; vEl('k-err').textContent=d.err; vEl('k-cpu').textContent=d.cpu;
  vEl('k-up').textContent=d.up; vEl('k-down').textContent=d.down; vEl('k-inc').textContent=d.incidents; vEl('k-thr').textContent=d.threats;
  { const gk=document.getElementById('k-gpu'); if(gk){ gk.textContent=d.gpu_has?d.gpu:'—'; gk.style.color=(d.gpu>=90?'var(--crit)':(d.gpu>=70?'var(--warn)':'#76b900')); } }
  vEl('ts').textContent='⟳ '+d.ts; vEl('scope-cnt').textContent=RNODES.length+' nodes'; vEl('bw-now').textContent=d.mbps+' Mb/s';
  bwHist.push(d.mbps); if(bwHist.length>80) bwHist.shift(); drawTraffic();
  vEl('nf-total').textContent = (d.nf_mbps!=null ? d.nf_mbps+' Mb/s attributed · '+((d.talkers||[]).length)+' talkers' : '—');
  renderTalkers(d.talkers||[]); renderApps(d.apps||[]);
  renderDiag(d.diagnostics||[]);
  const worst=(d.diagnostics||[]).reduce((a,x)=>Math.max(a,{ok:0,info:1,warn:2,crit:3}[x.level]||0),0);
  const S=[['STANDBY','var(--ok)'],['NOMINAL','var(--ok)'],['ELEVATED','var(--warn)'],['CRITICAL','var(--crit)']][playing?Math.max(1,worst):0];
  const sp=vEl('state'); sp.textContent=playing?S[0]:'STANDBY'; sp.style.color=S[1];
  // ── audio mapping ──
  if(!playing||!AC) return;
  const t=AC.currentTime;
  mbpsPeak=Math.max(mbpsPeak*0.995,d.mbps,5); const load=clamp(d.mbps/mbpsPeak,0,1);
  const err=clamp(d.err/Math.max(1,CFG.err_crit),0,1), cpu=clamp(d.cpu/100,0,1), alerts=(d.incidents||0)+(d.threats||0);
  // GPU load folds into brightness too — you can hear an inference box working
  const gpu=clamp((d.gpu||0)/100,0,1), compute=Math.max(cpu,gpu*0.85);
  nodes.lfo.frequency.setTargetAtTime(0.7+load*3.2,t,0.5);
  nodes.lp.frequency.setTargetAtTime(500+compute*4500+load*1500,t,0.6);
  nodes.disG.gain.setTargetAtTime(err*0.18,t,0.8); nodes.shaper.curve=makeCurve(err);
  nodes.wet.gain.setTargetAtTime(err*0.6,t,0.8); nodes.dry.gain.setTargetAtTime(1-err*0.5,t,0.8);
  nodes.grG.gain.setTargetAtTime(d.down>0?clamp(d.down*0.06,0,0.25):0,t,0.7);
  clearInterval(alertT); alertT=null; if(alerts>0){ const every=clamp(8000/alerts,1200,8000); alertT=setInterval(()=>bell(d.down>0),every); }
}

/* ── Sonar radar ── */
const rc=vEl('radar'), rctx=rc.getContext('2d');
function fitRadar(){ const w=rc.parentElement.clientWidth; rc.width=w; rc.height=360; }
function nodeHealth(n){ if(n.status==='down')return 1; if(n.status==='unknown')return .6; const lw=CFG.lat_warn||80,lc=CFG.lat_crit||200; if(n.lat==null)return .15; if(n.lat>=lc)return .9; if(n.lat>=lw)return .55; return clamp(n.lat/lc,0,.4); }
function nodeColor(n){ if(n.status==='down')return '#e74c3c'; if(n.status==='unknown')return '#8a909a'; const h=nodeHealth(n); return h>=.55?'#f39c12':'#2ecc71'; }
function drawRadar(){
  const W=rc.width,H=rc.height,cx=W/2,cy=H/2,R=Math.min(W,H)/2-14;
  rctx.clearRect(0,0,W,H);
  // rings
  rctx.strokeStyle='rgba(77,163,255,.14)'; rctx.lineWidth=1;
  for(let i=1;i<=4;i++){ rctx.beginPath(); rctx.arc(cx,cy,R*i/4,0,7); rctx.stroke(); }
  rctx.beginPath(); rctx.moveTo(cx-R,cy); rctx.lineTo(cx+R,cy); rctx.moveTo(cx,cy-R); rctx.lineTo(cx,cy+R); rctx.stroke();
  // sweep
  if(playing){ sweep=(sweep+0.012)%(Math.PI*2);
    const g=rctx.createRadialGradient(cx,cy,0,cx,cy,R); g.addColorStop(0,'rgba(54,227,208,.18)'); g.addColorStop(1,'rgba(54,227,208,0)');
    rctx.save(); rctx.beginPath(); rctx.moveTo(cx,cy); rctx.arc(cx,cy,R,sweep-0.5,sweep); rctx.closePath(); rctx.fillStyle=g; rctx.fill(); rctx.restore();
    rctx.strokeStyle='rgba(54,227,208,.5)'; rctx.beginPath(); rctx.moveTo(cx,cy); rctx.lineTo(cx+Math.cos(sweep)*R,cy+Math.sin(sweep)*R); rctx.stroke();
  }
  // blips — angle by index, radius by (un)health
  const N=RNODES.length||1;
  RNODES.forEach((n,i)=>{ const a=(i/N)*Math.PI*2 - Math.PI/2; const rr=18+nodeHealth(n)*(R-22);
    const x=cx+Math.cos(a)*rr, y=cy+Math.sin(a)*rr, col=nodeColor(n);
    const lit = playing && Math.abs(((sweep-a+Math.PI*3)%(Math.PI*2))-Math.PI) > Math.PI-0.45;
    const blink = n.status==='down' ? (0.5+0.5*Math.sin(Date.now()/300)) : 1;
    rctx.globalAlpha=(lit?1:0.62)*blink; rctx.fillStyle=col;
    rctx.beginPath(); rctx.arc(x,y,n.status==='down'?5:4,0,7); rctx.fill();
    if(lit||n.status==='down'){ rctx.globalAlpha=0.25*blink; rctx.beginPath(); rctx.arc(x,y,10,0,7); rctx.fill(); }
    rctx.globalAlpha=1;
    if(N<=24||n.status!=='up'){ rctx.fillStyle='rgba(220,228,236,.8)'; rctx.font='9px Segoe UI'; rctx.textAlign='center'; rctx.fillText(n.name||'',x,y-8); }
  });
  rctx.fillStyle='#2ecc71'; rctx.globalAlpha=.9; rctx.beginPath(); rctx.arc(cx,cy,3,0,7); rctx.fill(); rctx.globalAlpha=1;
  requestAnimationFrame(drawRadar);
}

/* ── Live traffic chart ── */
const tc=vEl('traffic'), tctx=tc.getContext('2d');
function fitTraffic(){ tc.width=tc.parentElement.clientWidth; tc.height=140; }
function drawTraffic(){
  const W=tc.width,H=tc.height; tctx.clearRect(0,0,W,H);
  const mx=Math.max(CFG.bw_crit*1.1||1, ...bwHist, 1);
  const y=v=>H-6-(v/mx)*(H-16);
  // threshold lines
  [['bw_warn','#f39c12'],['bw_crit','#e74c3c']].forEach(([k,c])=>{ if(CFG[k]>0&&CFG[k]<=mx){ tctx.strokeStyle=c; tctx.globalAlpha=.5; tctx.setLineDash([4,4]); tctx.beginPath(); tctx.moveTo(0,y(CFG[k])); tctx.lineTo(W,y(CFG[k])); tctx.stroke(); tctx.setLineDash([]); tctx.globalAlpha=1; } });
  if(bwHist.length<2){ requestAnimationFrameOnce(); return; }
  const step=W/Math.max(1,bwHist.length-1);
  tctx.beginPath(); tctx.moveTo(0,y(bwHist[0])); bwHist.forEach((v,i)=>tctx.lineTo(i*step,y(v)));
  tctx.lineTo((bwHist.length-1)*step,H); tctx.lineTo(0,H); tctx.closePath();
  const g=tctx.createLinearGradient(0,0,0,H); g.addColorStop(0,'rgba(77,163,255,.35)'); g.addColorStop(1,'rgba(77,163,255,0)'); tctx.fillStyle=g; tctx.fill();
  tctx.beginPath(); tctx.moveTo(0,y(bwHist[0])); bwHist.forEach((v,i)=>tctx.lineTo(i*step,y(v))); tctx.strokeStyle='#4da3ff'; tctx.lineWidth=2; tctx.stroke();
}
function requestAnimationFrameOnce(){}

/* ── Diagnostics ── */
let DIAG=[];
function renderDiag(dg){ DIAG=dg;
  vEl('diag').innerHTML = dg.map((x,i)=>{ const cls=x.level, clickable=x.level!=='ok';
    const sub=(arr,label)=> (arr&&arr.length)?`<div class="sub"><b>${label}</b><ul>${arr.map(s=>`<li>${esc(s)}</li>`).join('')}</ul></div>`:'';
    return `<div class="dg ${cls} ${clickable?'click':''}" ${clickable?`onclick="showDiag(${i})"`:''}><div class="t dg${cls}"><i class="fa-solid ${x.icon}"></i> ${esc(x.title)}${clickable?'<i class="fa-solid fa-chevron-right" style="margin-left:auto;font-size:10px;color:#5b6470;"></i>':''}</div>
      <div class="d">${esc(x.detail)}</div>${sub(x.causes,'Likely causes')}${sub(x.checks,'What to check')}</div>`; }).join('');
}
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

/* ── Who's using the bandwidth (NetFlow) ── */
function renderTalkers(arr){ const mx=Math.max(0.01,...arr.map(t=>t.mbps||0));
  vEl('talkers').innerHTML = arr.length? arr.map(t=>`<div class="who-row" onclick="showWho('${esc(t.ip)}')" title="Who is ${esc(t.ip)}?">
     <span class="mono" style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(t.ip)}</span>
     <div class="who-bar"><i style="width:${Math.round((t.mbps||0)/mx*100)}%"></i></div>
     <span class="mono" style="width:58px;text-align:right;">${(t.mbps||0).toFixed(2)}</span></div>`).join('')
   : '<div class="muted">No NetFlow data — enable NetFlow export to see talkers.</div>'; }
function renderApps(arr){ const mx=Math.max(0.01,...arr.map(t=>t.mbps||0));
  vEl('apps').innerHTML = arr.length? arr.map(t=>`<div class="who-row" style="cursor:default;">
     <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(t.app)}</span>
     <div class="who-bar"><i style="width:${Math.round((t.mbps||0)/mx*100)}%"></i></div>
     <span class="mono" style="width:58px;text-align:right;">${(t.mbps||0).toFixed(2)}</span></div>`).join('')
   : '<div class="muted">No NetFlow data.</div>'; }
async function showWho(ip){ openModal('<i class="fa-solid fa-spinner fa-spin"></i> Looking up '+esc(ip)+'…','<div class="muted">…</div>');
  let r; try{ r=await fetch('sonify.php?api=who&ip='+encodeURIComponent(ip)).then(x=>x.json()); }catch(e){ r=null; }
  if(!r||!r.ok){ vEl('snr-body').innerHTML='<div class="muted">Lookup failed.</div>'; return; }
  const g=r.geo, loc = g ? (g.private?'Private / internal address':((g.city?g.city+', ':'')+(g.country||'')+(g.asn?' · '+g.asn:''))) : 'Location unknown';
  vEl('snr-title').innerHTML=`<i class="fa-solid fa-magnifying-glass-location" style="color:var(--cyan)"></i> ${esc(ip)}`;
  const row=(label,mbps,clickIp)=>`<div class="snr-inc" style="border-left-color:#36e3d0;${clickIp?'':'cursor:default;'}" ${clickIp?`onclick="showWho('${esc(clickIp)}')"`:''}><div style="display:flex;gap:8px;align-items:center;"><span class="mono" style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(label)}</span><span class="mono" style="color:#cfe4ff;">${(mbps||0).toFixed(2)} Mb/s</span></div></div>`;
  vEl('snr-body').innerHTML=`
    <div class="snr-act" style="margin-top:0;"><span class="lnk" style="cursor:default;"><i class="fa-solid fa-location-dot"></i> ${esc(loc)}</span>
      ${r.rdns?`<span class="lnk" style="cursor:default;"><i class="fa-solid fa-tag"></i> ${esc(r.rdns)}</span>`:''}
      <span class="lnk" style="cursor:default;"><i class="fa-solid fa-gauge"></i> ${(r.total||0).toFixed(2)} Mb/s total</span></div>
    <div class="snr-sub"><b><i class="fa-solid fa-arrow-right-arrow-left"></i> Where it's going</b></div>
    ${(r.dests||[]).length? r.dests.map(d=>row(d.ip,d.mbps,d.ip)).join('') : '<div class="muted">No destination data.</div>'}
    <div class="snr-sub"><b><i class="fa-solid fa-layer-group"></i> What it's running</b></div>
    ${(r.apps||[]).length? r.apps.map(a=>row(a.app,a.mbps,null)).join('') : '<div class="muted">No app data.</div>'}
    <div class="snr-act"><a href="nettrace.php?target=${encodeURIComponent(ip)}" target="_blank"><i class="fa-solid fa-route"></i> Traceroute</a>
      <a href="netflow.php?host=${encodeURIComponent(ip)}" target="_blank"><i class="fa-solid fa-chart-area"></i> Open in NetFlow</a></div>`;
}

/* ── Detail popups (diagnostics + incidents, AJAX) ── */
function openModal(title,html){ vEl('snr-title').innerHTML=title; vEl('snr-body').innerHTML=html; vEl('snr-modal').classList.add('show'); }
function closeModal(){ vEl('snr-modal').classList.remove('show'); }
function sevCol(s){ s=(s||'').toLowerCase(); return (s==='critical'||s==='crit')?'#e74c3c':(s==='warning'||s==='warn')?'#f39c12':'#4da3ff'; }
function showDiag(i){ const d=DIAG[i]; if(!d) return;
  const col={crit:'#e74c3c',warn:'#f39c12',info:'#4da3ff',ok:'#2ecc71'}[d.level]||'#4da3ff';
  const sub=(arr,label,ic)=>(arr&&arr.length)?`<div class="snr-sub"><b><i class="fa-solid ${ic}"></i> ${label}</b><ul>${arr.map(s=>`<li>${esc(s)}</li>`).join('')}</ul></div>`:'';
  const links=(d.links||[]).map(l=>`<a href="${esc(l.href)}" target="_blank"><i class="fa-solid ${esc(l.icon)}"></i> ${esc(l.label)}</a>`).join('');
  openModal(`<i class="fa-solid ${d.icon}" style="color:${col}"></i> ${esc(d.title)}`,
    `<div style="color:#cdd4dd;">${esc(d.detail)}</div>${sub(d.causes,'Likely causes','fa-circle-question')}${sub(d.checks,'What to check','fa-list-check')}
     ${links?`<div class="snr-sub"><b><i class="fa-solid fa-arrow-up-right-from-square"></i> Act on it — jump to</b></div><div class="snr-act">${links}</div>`:''}
     ${d.key==='incidents'?'<div class="snr-sub"><b><i class="fa-solid fa-triangle-exclamation"></i> Open incidents</b></div><div id="snr-inc-list"><div class="muted">Loading…</div></div>':''}`);
  if(d.key==='incidents') loadIncidents(vEl('snr-inc-list'));
}
function showIncidentsList(){ openModal('<i class="fa-solid fa-triangle-exclamation" style="color:var(--warn)"></i> Open incidents','<div id="snr-inc-list"><div class="muted">Loading…</div></div>'); loadIncidents(vEl('snr-inc-list')); }
/* ── KPI metric drill-down (generic list popup) ── */
async function showMetric(m){ openModal('<i class="fa-solid fa-spinner fa-spin"></i> Loading…','<div class="muted">…</div>');
  let r; try{ r=await fetch('sonify.php?api=metric&m='+m+'&node='+TARGET+'&_='+Date.now()).then(x=>x.json()); }catch(e){ r=null; }
  if(!r||!r.ok){ vEl('snr-body').innerHTML='<div class="muted">Could not load details.</div>'; return; }
  vEl('snr-title').innerHTML=`<i class="fa-solid ${r.icon}" style="color:${r.color}"></i> ${esc(r.title)}`;
  const rows=(r.items||[]).map(it=>{
    const bl=it.valColor||r.color;
    const attr = it.clickIp ? `onclick="showWho('${esc(it.clickIp)}')" style="cursor:pointer;border-left-color:${bl};"` : `style="cursor:default;border-left-color:${bl};"`;
    const pill = it.pill ? `<span class="snr-pill" style="background:${it.pillColor}22;color:${it.pillColor};">${esc(it.pill)}</span>` : '';
    return `<div class="snr-inc" ${attr}><div style="display:flex;gap:8px;align-items:center;">${pill}
      <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><b>${esc(it.main)}</b>${it.sub?` <span class="muted" style="font-size:11px;">${esc(it.sub)}</span>`:''}</span>
      <span class="mono" style="color:${bl};white-space:nowrap;">${esc(it.val)}${it.unit?' '+esc(it.unit):''}</span></div></div>`; }).join('');
  const links=(r.links||[]).map(l=>`<a href="${esc(l.href)}" target="_blank"><i class="fa-solid ${esc(l.icon)}"></i> ${esc(l.label)}</a>`).join('');
  vEl('snr-body').innerHTML = `${r.summary?`<div class="muted" style="margin-bottom:10px;">${esc(r.summary)}</div>`:''}
     ${rows||'<div class="muted">Nothing to show right now.</div>'}
     ${r.note?`<div class="muted" style="margin-top:12px;font-size:11.5px;line-height:1.6;">${esc(r.note)}</div>`:''}
     ${links?`<div class="snr-act" style="margin-top:12px;">${links}</div>`:''}`;
}
async function loadIncidents(box){ if(!box) return; let r; try{ r=await fetch('incidents.php?api=list&status=active').then(x=>x.json()); }catch(e){ r=null; }
  if(!r||!r.ok){ box.innerHTML='<div class="muted">Incident details need Incident-command access.</div>'; return; }
  const inc=r.incidents||[]; box.innerHTML = inc.length? inc.map(i=>{ const c=sevCol(i.severity);
    return `<div class="snr-inc" style="border-left-color:${c};" onclick="showIncident(${i.id})"><div style="display:flex;gap:8px;align-items:center;"><span class="snr-pill" style="background:${c}22;color:${c};">${esc(i.severity)}</span><span class="it" style="flex:1;min-width:0;">${esc(i.title)}</span><span class="snr-pill" style="background:rgba(255,255,255,.06);color:#9aa3ad;">${esc(i.status)}</span></div>
      <div class="im">${esc(i.root_entity||'')} · impact ${i.impact_count||0} · ${esc((window.nmLocal?nmLocal(i.opened_at):(i.opened_at||'').replace('T',' ')).slice(5,16))}</div></div>`; }).join('')
    : '<div class="muted">No open incidents right now. 🎉</div>'; }
async function showIncident(id){ openModal('<i class="fa-solid fa-spinner fa-spin"></i> Loading…','<div class="muted">…</div>');
  let r; try{ r=await fetch('incidents.php?api=get&id='+id).then(x=>x.json()); }catch(e){ r=null; }
  if(!r||!r.ok){ vEl('snr-body').innerHTML='<div class="muted">Could not load incident.</div>'; return; }
  const i=r.incident, c=sevCol(i.severity);
  vEl('snr-title').innerHTML=`<span class="snr-pill" style="background:${c}22;color:${c};">${esc(i.severity)}</span> ${esc(i.title)}`;
  const sigs=(i.signals||[]).map(s=>`<div class="snr-inc" style="border-left-color:${sevCol(s.severity)};cursor:default;"><div style="display:flex;gap:8px;"><span class="snr-pill" style="background:${sevCol(s.severity)}22;color:${sevCol(s.severity)};">${esc(s.source||'')}</span><b style="flex:1;">${esc(s.title||s.entity||'')}</b></div>${s.detail?`<div class="im">${esc(String(s.detail).slice(0,300))}</div>`:''}</div>`).join('')||'<div class="muted">No signals.</div>';
  vEl('snr-body').innerHTML=`<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;"><span class="snr-pill" style="background:${c}18;color:${c};">${esc(i.status)}</span>${i.root_source?`<span class="snr-pill" style="background:rgba(255,255,255,.06);color:#cdd4dd;">root: ${esc(i.root_source)}${i.root_entity?' · '+esc(i.root_entity):''}</span>`:''}<span class="snr-pill" style="background:rgba(255,255,255,.06);color:#9aa3ad;">${i.signal_count||0} signals</span></div>
    <div class="muted" style="font-size:11.5px;margin-bottom:10px;">opened ${esc((i.opened_at||'').replace('T',' '))} · updated ${esc((i.updated_at||'').replace('T',' '))}</div>
    <div class="snr-act"><span class="lnk" onclick="showIncidentsList()"><i class="fa-solid fa-arrow-left"></i> All incidents</span><a href="incidents.php" target="_blank"><i class="fa-solid fa-up-right-from-square"></i> Open in Incidents</a></div>
    <div class="snr-sub"><b>Signals</b></div>${sigs}`;
}
document.addEventListener('keydown',e=>{ if(e.key==='Escape') closeModal(); });
document.getElementById('snr-modal').addEventListener('click',e=>{ if(e.target.id==='snr-modal') closeModal(); });

/* ── poll / control ── */
async function poll(){ try{ const d=await fetch('sonify.php?api=pulse&node='+TARGET+'&_='+Date.now()).then(r=>r.json()); if(d.ok) apply(d); }catch(e){} }
function retarget(){ TARGET=+vEl('target').value; bwHist=[]; poll(); }
function toggle(){ playing?stop():start(); }
async function start(){ if(!AC) buildGraph(); if(AC.state==='suspended') await AC.resume();
  playing=true; vEl('toggle').classList.add('on'); vEl('ticon').className='fa-solid fa-stop'; vEl('tlabel').textContent='Stop sonar'; vEl('mute-note').textContent='live';
  poll(); pollT=setInterval(poll,4000); }
function stop(){ playing=false; clearInterval(pollT); clearInterval(alertT);
  if(nodes) nodes.droneGain.gain.setTargetAtTime(0.0001,AC.currentTime,0.6);
  vEl('toggle').classList.remove('on'); vEl('ticon').className='fa-solid fa-satellite-dish'; vEl('tlabel').textContent='Start sonar'; vEl('mute-note').textContent='paused';
  vEl('state').textContent='STANDBY'; vEl('state').style.color='var(--ok)'; }
function setVol(v){ if(master&&AC) master.gain.setTargetAtTime(v/100*0.5,AC.currentTime,0.1); }
async function saveCfg(){ const fd=new FormData(); ['bw_warn','bw_crit','lat_warn','lat_crit','err_warn','err_crit'].forEach(k=>fd.append(k,vEl('c-'+k).value));
  const r=await fetch('sonify.php?api=cfg',{method:'POST',body:fd}).then(x=>x.json()).catch(()=>null);
  if(r&&r.ok){ CFG=r.cfg; vEl('cfg-msg').textContent='✓ saved'; setTimeout(()=>vEl('cfg-msg').textContent='',1800); drawTraffic(); } }

window.addEventListener('resize',()=>{ fitRadar(); fitTraffic(); drawTraffic(); });
fitRadar(); fitTraffic(); drawRadar(); poll();   // one passive scan so the scope isn't empty before Start
</script>
</body></html>
