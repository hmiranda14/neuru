<?php
require_once __DIR__ . '/nm_config.php';
// ─── Stats AJAX endpoints (before any output) ─────────────────────────────────
if (isset($_GET['api'])) {
    header('Content-Type: application/json; charset=utf-8');
    if (session_status() === PHP_SESSION_NONE) session_start();
    if (empty($_SESSION['username'])) { echo json_encode(['err'=>'Unauthorized']); exit; }
    include_once('connection.php');
    // Release the session lock BEFORE any slow work (esp. the 45s Python poll in poll_now, and the
    // heavy stats queries) so one request can't freeze this user's other tabs / the auto-refresh.
    if (function_exists('session_write_close')) session_write_close();

    $node_id = (int)($_GET['node_id'] ?? 0);
    $port_id = (int)($_GET['port_id'] ?? 0);

    // ── Parse time range ──────────────────────────────────────────────────────
    $range     = $_GET['range']    ?? '24h';
    $date_from = trim($_GET['from'] ?? '');
    $date_to   = trim($_GET['to']   ?? '');
    $hours_map = ['1h'=>1,'6h'=>6,'12h'=>12,'24h'=>24,'7d'=>168,'30d'=>720];

    if ($date_from && $date_to) {
        $from_dt  = $date_from . ' 00:00:00';
        $to_dt    = $date_to   . ' 23:59:59';
        $span_hrs = max(1, (strtotime($to_dt) - strtotime($from_dt)) / 3600);
    } else {
        // Use MySQL server time so the range matches stored timestamps (avoids PHP/MySQL timezone mismatch)
        $hrs = $hours_map[$range] ?? 24;
        $dtr = $conn->query("SELECT DATE_FORMAT(NOW(),'%Y-%m-%d %H:%i:%S') t, DATE_FORMAT(DATE_SUB(NOW(), INTERVAL $hrs HOUR),'%Y-%m-%d %H:%i:%S') f")->fetch_assoc();
        $to_dt    = $dtr['t'];
        $from_dt  = $dtr['f'];
        $span_hrs = $hrs;
    }

    // Auto-group interval based on span (determines chart resolution)
    // With 5-min polling: 24h = 288 pts, 7d = 336 pts (6h buckets), 30d = 30 pts (daily)
    if      ($span_hrs <= 24)  $grp_expr = "DATE_FORMAT(recorded_at,'%Y-%m-%d %H:%i:00')";   // per-minute (≤24h)
    elseif  ($span_hrs <= 168) $grp_expr = "DATE_FORMAT(DATE_SUB(recorded_at, INTERVAL MINUTE(recorded_at)%360 MINUTE),'%Y-%m-%d %H:%i:00')"; // 6h buckets (≤7d)
    else                       $grp_expr = "DATE_FORMAT(recorded_at,'%Y-%m-%d 00:00:00')";   // daily (30d)

    switch ($_GET['api']) {

        // ── On-demand single-node poll (the "Poll now" button) ───────────────
        case 'poll_now':
            if (!$node_id) { echo json_encode(['err'=>'Missing node_id']); exit; }
            $py  = escapeshellarg(VENV_PYTHON);
            $scr = escapeshellarg(SCRIPTS_DIR . '/nm_poller.py');
            $out = shell_exec("timeout 45 $py $scr --node " . escapeshellarg((string)$node_id) . " 2>&1");
            $ran = ($out !== null && strpos($out, 'Poll complete') !== false);
            $v = nm_node_live_verdict($conn, $node_id);   // true state, not just "it ran"
            echo json_encode(['ok'=>$ran, 'state'=>$v['state'], 'detail'=>$v['detail']]);
            break;

        // ── Port traffic ─────────────────────────────────────────────────────
        case 'port_traffic':
            if (!$port_id) { echo json_encode(['err'=>'Missing port_id']); exit; }
            $sql = "SELECT
                        DATE_FORMAT(MIN(recorded_at),'%Y-%m-%dT%H:%i:%S') ts,
                        ROUND(AVG(in_rate))  in_avg,
                        ROUND(AVG(out_rate)) out_avg,
                        ROUND(MAX(in_rate))  in_peak,
                        ROUND(MAX(out_rate)) out_peak,
                        AVG(in_util)         in_util,
                        AVG(out_util)        out_util,
                        MIN(if_speed)        if_speed,
                        GROUP_CONCAT(DISTINCT oper_status) oper
                    FROM nm_port_stats
                    WHERE port_id=? AND recorded_at BETWEEN ? AND ?
                    GROUP BY {$grp_expr}
                    ORDER BY ts";
            $st = $conn->prepare($sql);
            $st->bind_param('iss', $port_id, $from_dt, $to_dt);
            $st->execute();
            $rows = $st->get_result()->fetch_all(MYSQLI_ASSOC);

            // 95th percentile calculation
            $in_vals = array_column($rows, 'in_avg');
            $out_vals= array_column($rows, 'out_avg');
            sort($in_vals);  sort($out_vals);
            $p95 = function($a) { if(!$a) return 0; $i=ceil(count($a)*0.95)-1; return $a[$i]; };

            // Summary stats
            $sum_in  = $in_vals  ? array_sum($in_vals)/count($in_vals)   : 0;
            $sum_out = $out_vals ? array_sum($out_vals)/count($out_vals) : 0;

            echo json_encode([
                'rows'       => $rows,
                'p95_in'     => $p95($in_vals),
                'p95_out'    => $p95($out_vals),
                'avg_in'     => round($sum_in),
                'avg_out'    => round($sum_out),
                'peak_in'    => $in_vals  ? max($in_vals)  : 0,
                'peak_out'   => $out_vals ? max($out_vals) : 0,
                'from'       => $from_dt,
                'to'         => $to_dt,
            ]);
            break;

        // ── Device CPU / Memory / Disk / Temp / Uptime ───────────────────────
        case 'device_metrics':
            if (!$node_id) { echo json_encode(['err'=>'Missing node_id']); exit; }
            $type = in_array($_GET['type']??'', ['cpu','memory','storage','temperature','uptime','custom'])
                  ? $_GET['type'] : 'cpu';

            // Time-series data grouped by computed interval (adapts to selected range)
            $sql = "SELECT
                        DATE_FORMAT(MIN(recorded_at),'%Y-%m-%dT%H:%i:%S') ts,
                        metric_key,
                        ROUND(AVG(value),2) val
                    FROM nm_device_stats
                    WHERE node_id=? AND metric_type=? AND recorded_at BETWEEN ? AND ?
                    GROUP BY {$grp_expr}, metric_key
                    ORDER BY ts, metric_key";
            $st = $conn->prepare($sql);
            $st->bind_param('isss', $node_id, $type, $from_dt, $to_dt);
            $st->execute();
            $raw = $st->get_result()->fetch_all(MYSQLI_ASSOC);

            // Per-key aggregate stats (for the Min/Max/Cur legend table)
            $agg_sql = "SELECT
                            metric_key,
                            ROUND(MIN(value),2)  min_val,
                            ROUND(MAX(value),2)  max_val,
                            ROUND(AVG(value),2)  avg_val
                        FROM nm_device_stats
                        WHERE node_id=? AND metric_type=? AND recorded_at BETWEEN ? AND ?
                        GROUP BY metric_key
                        ORDER BY metric_key";
            $ast = $conn->prepare($agg_sql);
            $ast->bind_param('isss', $node_id, $type, $from_dt, $to_dt);
            $ast->execute();
            $agg_rows = $ast->get_result()->fetch_all(MYSQLI_ASSOC);

            // Latest (current) value + raw_value per key
            $cur_sql = "SELECT d.metric_key, ROUND(d.value,2) cur_val, d.raw_value
                        FROM nm_device_stats d
                        INNER JOIN (
                            SELECT metric_key, MAX(recorded_at) max_ts
                            FROM nm_device_stats
                            WHERE node_id=? AND metric_type=?
                            GROUP BY metric_key
                        ) latest ON d.metric_key=latest.metric_key AND d.recorded_at=latest.max_ts
                        WHERE d.node_id=? AND d.metric_type=?";
            $cst = $conn->prepare($cur_sql);
            $cst->bind_param('isis', $node_id, $type, $node_id, $type);
            $cst->execute();
            $cur_rows = $cst->get_result()->fetch_all(MYSQLI_ASSOC);

            // Build stats map keyed by metric_key
            $stats = [];
            foreach ($agg_rows as $a) {
                $stats[$a['metric_key']] = ['min'=>(float)$a['min_val'],'max'=>(float)$a['max_val'],'avg'=>(float)$a['avg_val'],'cur'=>null,'raw'=>null];
            }
            foreach ($cur_rows as $c) {
                if (isset($stats[$c['metric_key']])) {
                    $stats[$c['metric_key']]['cur'] = (float)$c['cur_val'];
                    $stats[$c['metric_key']]['raw'] = $c['raw_value'] !== null ? (float)$c['raw_value'] : null;
                }
            }

            // Pivot time-series by metric_key
            $keys    = array_values(array_unique(array_column($raw, 'metric_key')));
            $times   = array_values(array_unique(array_column($raw, 'ts')));
            $indexed = [];
            foreach ($raw as $r) $indexed[$r['ts']][$r['metric_key']] = $r['val'];

            echo json_encode(['keys'=>$keys,'times'=>$times,'data'=>$indexed,'stats'=>$stats,'from'=>$from_dt,'to'=>$to_dt]);
            break;

        // ── Learned baselines (Zero-Threshold engine) for the expected-band overlay ─
        // Returns per metric_key → { hour_of_week: {mean,stdev,samples} } so the chart
        // can draw the "normal" envelope aligned to each point's hour-of-week.
        case 'baselines':
            if (!$node_id) { echo json_encode(['err'=>'Missing node_id']); exit; }
            if ($conn->query("SHOW TABLES LIKE 'nm_ai_baselines'")->num_rows === 0) { echo json_encode(['ok'=>true,'baselines'=>[]]); exit; }
            $type = in_array($_GET['type']??'', ['cpu','memory','storage','temperature','uptime','custom']) ? $_GET['type'] : 'cpu';
            $st = $conn->prepare("SELECT metric_key, hour_of_week, mean, stdev, samples
                                  FROM nm_ai_baselines WHERE node_id=? AND metric_type=?");
            $st->bind_param('is', $node_id, $type); $st->execute();
            $bl = [];
            $res = $st->get_result();
            while ($r = $res->fetch_assoc()) {
                $bl[$r['metric_key']][(int)$r['hour_of_week']] = [
                    'mean'=>(float)$r['mean'], 'stdev'=>(float)$r['stdev'], 'samples'=>(int)$r['samples']];
            }
            echo json_encode(['ok'=>true,'baselines'=>$bl]);
            break;

        // ── Ping history (latency + availability over time, for ping-only nodes) ──
        case 'ping_history':
            if (!$node_id) { echo json_encode(['err'=>'Missing node_id']); exit; }
            $sql = "SELECT DATE_FORMAT(MIN(recorded_at),'%Y-%m-%dT%H:%i:%S') ts,
                           ROUND(AVG(latency_ms),2) lat,
                           ROUND(AVG(is_up)*100,1)  avail
                    FROM nm_ping_stats
                    WHERE node_id=? AND recorded_at BETWEEN ? AND ?
                    GROUP BY {$grp_expr} ORDER BY ts";
            $st = $conn->prepare($sql);
            $st->bind_param('iss', $node_id, $from_dt, $to_dt);
            $st->execute();
            $rows = $st->get_result()->fetch_all(MYSQLI_ASSOC);
            $times = []; $lat = []; $avail = [];
            foreach ($rows as $r) {
                $times[] = $r['ts'];
                // null latency where the node was down so the line shows a gap
                $lat[]   = ($r['avail'] > 0 && $r['lat'] !== null) ? (float)$r['lat'] : null;
                $avail[] = (float)$r['avail'];
            }
            $ov = $conn->prepare("SELECT ROUND(AVG(is_up)*100,2) availability,
                                         ROUND(AVG(latency_ms),2) avg_lat,
                                         ROUND(MIN(latency_ms),2) min_lat,
                                         ROUND(MAX(latency_ms),2) max_lat,
                                         ROUND(AVG(packet_loss),1) loss, COUNT(*) n
                                  FROM nm_ping_stats WHERE node_id=? AND recorded_at BETWEEN ? AND ?");
            $ov->bind_param('iss', $node_id, $from_dt, $to_dt);
            $ov->execute();
            $sum = $ov->get_result()->fetch_assoc();
            echo json_encode(['times'=>$times, 'latency'=>$lat, 'avail'=>$avail, 'summary'=>$sum]);
            break;

        // ── Smokeping latency (from nm_latency_samples, any node tied by IP) ───
        case 'smoke_history':
            if (!$node_id) { echo json_encode(['err'=>'Missing node_id']); exit; }
            if ($conn->query("SHOW TABLES LIKE 'nm_latency_samples'")->num_rows === 0) { echo json_encode(['times'=>[],'rtt'=>[],'loss'=>[],'summary'=>null]); break; }
            $gs  = str_replace('recorded_at', 'sampled_at', $grp_expr);
            $sql = "SELECT DATE_FORMAT(MIN(sampled_at),'%Y-%m-%dT%H:%i:%S') ts,
                           ROUND(AVG(rtt_ms),3) rtt, ROUND(AVG(loss),2) loss
                    FROM nm_latency_samples
                    WHERE node_id=? AND sampled_at BETWEEN ? AND ?
                    GROUP BY {$gs} ORDER BY ts";
            $st = $conn->prepare($sql);
            $st->bind_param('iss', $node_id, $from_dt, $to_dt); $st->execute();
            $rows = $st->get_result()->fetch_all(MYSQLI_ASSOC);
            $times = []; $rtt = []; $loss = [];
            foreach ($rows as $r) {
                $times[] = $r['ts'];
                $rtt[]   = $r['rtt']  !== null ? (float)$r['rtt']  : null;
                $loss[]  = $r['loss'] !== null ? (float)$r['loss'] : null;
            }
            $ov = $conn->prepare("SELECT ROUND(AVG(rtt_ms),2) avg_lat, ROUND(MIN(rtt_ms),2) min_lat,
                                         ROUND(MAX(rtt_ms),2) max_lat, ROUND(AVG(loss),2) avg_loss,
                                         ROUND(MAX(loss),1) max_loss, COUNT(*) n
                                  FROM nm_latency_samples WHERE node_id=? AND sampled_at BETWEEN ? AND ?");
            $ov->bind_param('iss', $node_id, $from_dt, $to_dt); $ov->execute();
            $sum = $ov->get_result()->fetch_assoc();
            echo json_encode(['times'=>$times, 'rtt'=>$rtt, 'loss'=>$loss, 'summary'=>$sum]);
            break;

        // ── Device summary (latest snapshot per metric) ───────────────────────
        case 'device_summary':
            if (!$node_id) { echo json_encode(['err'=>'Missing node_id']); exit; }
            // latest sample per (metric_type, metric_key). Join on MAX(recorded_at) — NOT MAX(id) —
            // so the (node_id,metric_type,metric_key,recorded_at) index does a loose scan (was ~3s→0.2s).
            $sql = "SELECT d.metric_type, d.metric_key, d.value
                    FROM nm_device_stats d
                    INNER JOIN (
                          SELECT metric_type, metric_key, MAX(recorded_at) max_ts
                          FROM nm_device_stats
                          WHERE node_id=? GROUP BY metric_type, metric_key
                    ) latest ON d.metric_type=latest.metric_type
                            AND d.metric_key=latest.metric_key
                            AND d.recorded_at=latest.max_ts
                    WHERE d.node_id=?
                    ORDER BY d.metric_type, d.metric_key";
            $st = $conn->prepare($sql);
            $st->bind_param('ii', $node_id, $node_id);
            $st->execute();
            $rows = $st->get_result()->fetch_all(MYSQLI_ASSOC);
            $out = [];
            foreach ($rows as $r) $out[$r['metric_type']][$r['metric_key']] = (float)$r['value'];
            echo json_encode($out);
            break;

        // ── List nodes with port info ─────────────────────────────────────────
        case 'nodes':
            $sql = "SELECT n.id node_id, n.display_name, n.ip_address, n.os_icon,
                           i.id port_id, i.display_name iface_name
                    FROM nm_nodes n
                    LEFT JOIN nm_interfaces i ON i.node_id=n.id AND i.show_graph=1
                    ORDER BY n.display_name, i.sort_order";
            $res = $conn->query($sql);
            $nodes = [];
            while ($r=$res->fetch_assoc()) {
                $nid = $r['node_id'];
                if (!isset($nodes[$nid])) {
                    $nodes[$nid] = ['node_id'=>$nid,'name'=>$r['display_name'],
                                    'ip'=>$r['ip_address'],'icon'=>$r['os_icon'],'ports'=>[]];
                }
                if ($r['port_id']) {
                    $nodes[$nid]['ports'][] = ['port_id'=>$r['port_id'],'name'=>$r['iface_name']];
                }
            }
            echo json_encode(['nodes'=>array_values($nodes)]);
            break;

        // ── GPU telemetry (only for nodes registered as a GPU target) ─────────
        case 'gpu_stats':
            if (!$node_id) { echo json_encode(['err'=>'Missing node_id']); exit; }
            $tg = $conn->prepare("SELECT id,name,ollama_url FROM nm_gpu_targets WHERE node_id=? AND enabled=1 LIMIT 1");
            $tg->bind_param('i', $node_id); $tg->execute();
            $target = $tg->get_result()->fetch_assoc();
            if (!$target) { echo json_encode(['has_gpu'=>false]); break; }
            $tid = (int)$target['id'];
            $gs  = str_replace('recorded_at', 'sampled_at', $grp_expr);
            $sql = "SELECT DATE_FORMAT(MIN(s.sampled_at),'%Y-%m-%dT%H:%i:%S') ts,
                           ROUND(AVG(s.util_pct),1) util,
                           ROUND(AVG(100*s.mem_used_mb/NULLIF(s.mem_total_mb,0)),1) vram,
                           ROUND(AVG(s.temp_c),1) temp,
                           ROUND(AVG(s.power_w),0) power
                    FROM nm_gpu_stats s JOIN nm_gpu g ON g.id=s.gpu_id
                    WHERE g.target_id=? AND s.sampled_at BETWEEN ? AND ?
                    GROUP BY {$gs} ORDER BY ts";
            $st = $conn->prepare($sql); $st->bind_param('iss', $tid, $from_dt, $to_dt); $st->execute();
            $rows = $st->get_result()->fetch_all(MYSQLI_ASSOC);
            $times=[]; $util=[]; $vram=[]; $temp=[]; $power=[];
            foreach ($rows as $r) {
                $times[]=$r['ts'];
                $util[] =$r['util'] !==null?(float)$r['util'] :null;
                $vram[] =$r['vram'] !==null?(float)$r['vram'] :null;
                $temp[] =$r['temp'] !==null?(float)$r['temp'] :null;
                $power[]=$r['power']!==null?(float)$r['power']:null;
            }
            $gpus = [];
            $gr = $conn->query("SELECT id,gpu_index,name,memory_total_mb FROM nm_gpu WHERE target_id=$tid ORDER BY gpu_index");
            while ($gr && ($g=$gr->fetch_assoc())) {
                $gid=(int)$g['id'];
                $lr=$conn->query("SELECT util_pct,mem_used_mb,mem_total_mb,temp_c,power_w FROM nm_gpu_stats WHERE gpu_id=$gid ORDER BY id DESC LIMIT 1");
                $g['latest']=$lr?($lr->fetch_assoc()?:null):null;
                $gpus[]=$g;
            }
            $models=[];
            $mr=$conn->query("SELECT name,vram_mb FROM nm_gpu_models WHERE target_id=$tid ORDER BY vram_mb DESC");
            while ($mr && ($m=$mr->fetch_assoc())) $models[]=$m;
            echo json_encode(['has_gpu'=>true,'target_id'=>$tid,'name'=>$target['name'],
                'times'=>$times,'util'=>$util,'vram'=>$vram,'temp'=>$temp,'power'=>$power,
                'gpus'=>$gpus,'models'=>$models]);
            break;

        // ── Poller recent log ─────────────────────────────────────────────────
        case 'poller_log':
            $r = $conn->query("SELECT * FROM nm_poller_log ORDER BY ran_at DESC LIMIT 20");
            echo json_encode(['log'=> $r ? $r->fetch_all(MYSQLI_ASSOC) : []]);
            break;

        default:
            echo json_encode(['err'=>'Unknown endpoint']);
    }
    exit;
}

// ─── Normal page load ────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
include('logger.php');
if (!checkAccess($conn,'net_mon')) { header("Location: /denied_access.php?page=net_mon_stats"); exit; }
if (function_exists('session_write_close')) session_write_close();   // no slow work should hold the session lock

// Pre-load node list for sidebar
$nodes_res = $conn->query("SELECT n.id node_id, n.display_name, n.ip_address, n.os_icon,
                                   COALESCE(n.monitor_type,'snmp') monitor_type,
                                   i.id port_id, i.display_name iface_name, i.id iface_id
                            FROM nm_nodes n
                            LEFT JOIN nm_interfaces i ON i.node_id=n.id AND i.show_graph=1
                            ORDER BY n.display_name, i.sort_order");
$all_nodes = [];
while ($r = $nodes_res->fetch_assoc()) {
    $nid = $r['node_id'];
    if (!isset($all_nodes[$nid])) {
        $all_nodes[$nid] = ['node_id'=>$nid,'name'=>$r['display_name'],
                            'ip'=>$r['ip_address'],'icon'=>$r['os_icon'],
                            'monitor_type'=>$r['monitor_type'],'ports'=>[]];
    }
    if ($r['port_id']) {
        $all_nodes[$nid]['ports'][] = ['port_id'=>$r['port_id'],'name'=>$r['iface_name'],'iface_id'=>$r['iface_id']];
    }
}

// Default selections from URL
$sel_node_id = (int)($_GET['node']??( reset($all_nodes)['node_id'] ?? 0 ));
$sel_port_id = (int)($_GET['port']??(
    !empty($all_nodes[$sel_node_id]['ports']) ? $all_nodes[$sel_node_id]['ports'][0]['port_id'] : 0
));
$sel_range = in_array($_GET['range']??'', ['1h','6h','12h','24h','7d','30d']) ? $_GET['range'] : '24h';

// Check if poller has any data
$has_data = false;
if ($conn->query("SHOW TABLES LIKE 'nm_port_stats'")->num_rows > 0) {
    // existence check only — a COUNT(*) full-scans the whole table as it grows (we just need "any data?")
    $has_data = ($conn->query("SELECT 1 FROM nm_port_stats LIMIT 1")->num_rows > 0);
}

$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
include('header.php');
log_user_action($conn, 'view_page', 'net_mon_stats.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Statistics | SG-PR Console</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<!-- Chart.js + Date adapter (served locally) -->
<script src="/chart.umd.min.js"></script>
<script src="/chartjs-adapter-date-fns.bundle.min.js"></script>
<script src="/chartjs-plugin-zoom.min.js"></script><!-- mouse-wheel zoom (self-hosted; CSP) -->
<style>
:root {
    --glass: rgba(255,255,255,0.07);
    --glass2: rgba(255,255,255,0.04);
    --border: rgba(255,255,255,0.12);
    --accent: #4da3ff;
    --green:  #2ecc71;
    --yellow: #f39c12;
    --red:    #e74c3c;
    --purple: #9b59b6;
    --teal:   #1abc9c;
    --down:   #e74c3c;
}
*, *::before, *::after { box-sizing: border-box; }
body { margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#fff; overflow-x:hidden; }
#bg-video { position:fixed; top:0; left:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.3; }

/* ── Layout ── */
.page-wrap  { display:flex; gap:0; min-height:100vh; }
.sidebar    { width:260px; flex-shrink:0; background:rgba(0,0,0,.6); border-right:1px solid var(--border);
              display:flex; flex-direction:column; padding:16px 0; overflow-y:auto; }
.main-area  { flex:1; padding:20px; overflow-x:hidden; }

/* ── Sidebar ── */
.sidebar-title { font-size:10px; font-weight:700; letter-spacing:2px; color:#555; text-transform:uppercase;
                 padding:0 16px 8px; margin-top:8px; }
.node-item    { padding:8px 16px; cursor:pointer; border-left:3px solid transparent;
                transition:.15s; display:flex; align-items:center; gap:6px; }
.node-item:hover { background:rgba(255,255,255,.05); border-left-color:var(--accent); }
.node-item.active { background:rgba(77,163,255,.1); border-left-color:var(--accent); }
.node-item .node-name { font-size:13px; font-weight:600; }
.node-item .node-ip   { font-size:11px; color:#555; }
.node-chevron { font-size:9px; color:#444; transition:transform .2s ease; flex-shrink:0;
                padding:3px; margin-left:auto; }
.node-group.open .node-chevron { transform:rotate(90deg); color:#888; }
.port-list    { overflow:hidden; max-height:0; transition:max-height .25s ease; }
.node-group.open .port-list { max-height:600px; }
.port-item    { padding:5px 16px 5px 32px; cursor:pointer; font-size:12px; color:#888;
                border-left:3px solid transparent; transition:.15s; }
.port-item:hover  { color:#fff; background:rgba(255,255,255,.03); }
.port-item.active { color:var(--accent); border-left-color:var(--accent); }

/* ── Header ── */
.stats-header { display:flex; align-items:center; gap:15px; flex-wrap:wrap; margin-bottom:20px; }
.stats-title  { font-size:24px; font-weight:700; flex:1; }
.stats-title span { font-weight:300; color:#aaa; font-size:16px; display:block; }

/* ── Range selector ── */
.range-bar    { display:flex; gap:4px; align-items:center; flex-wrap:wrap; }
.range-btn    { background:var(--glass2); border:1px solid var(--border); color:#aaa;
                padding:5px 14px; border-radius:6px; cursor:pointer; font-size:12px; font-weight:600;
                transition:.15s; }
.range-btn:hover  { background:rgba(77,163,255,.15); color:#fff; border-color:var(--accent); }
.range-btn.active { background:rgba(77,163,255,.25); color:var(--accent); border-color:var(--accent); }
.range-sep    { width:1px; height:20px; background:var(--border); margin:0 4px; }
.custom-range { display:flex; gap:6px; align-items:center; }
.custom-range input[type=date] {
    background:var(--glass2); border:1px solid var(--border); color:#ccc; border-radius:6px;
    padding:4px 10px; font-size:12px; outline:none;
}
.custom-range input[type=date]:focus { border-color:var(--accent); }
.custom-range button { padding:5px 12px; font-size:12px; }

/* ── Glass card ── */
.glass-card   { background:var(--glass); backdrop-filter:blur(20px); border:1px solid var(--border);
                border-radius:14px; padding:18px 20px; }
.card-title   { font-size:11px; text-transform:uppercase; letter-spacing:1.5px; color:#666;
                margin-bottom:12px; display:flex; align-items:center; gap:8px; }
.card-title i { color:var(--accent); }

/* ── Summary stat pills ── */
.stat-grid    { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:10px; margin-bottom:20px; }
.stat-pill    { background:var(--glass2); border:1px solid var(--border); border-radius:10px; padding:12px 14px; }
.stat-pill .lbl { font-size:10px; color:#555; text-transform:uppercase; letter-spacing:1px; }
.stat-pill .val { font-size:18px; font-weight:700; margin-top:3px; }
.stat-pill .sub { font-size:10px; color:#555; margin-top:1px; }
.color-in  { color:#4da3ff; }
.color-out { color:#9b59b6; }
.color-cpu { color:#2ecc71; }
.color-mem { color:#f39c12; }
.color-disk{ color:#1abc9c; }
.color-temp{ color:#e74c3c; }

/* ── Chart containers ── */
.chart-grid   { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
.chart-full   { grid-column:span 2; }
.chart-wrap   { position:relative; height:220px; }
.chart-wrap.tall { height:280px; }

/* ── No data ── */
.no-data { display:flex; flex-direction:column; align-items:center; justify-content:center;
           gap:10px; padding:40px; color:#555; text-align:center; }
.no-data i { font-size:36px; }

/* ── Loading spinner ── */
.spinner { display:inline-block; width:16px; height:16px; border:2px solid rgba(255,255,255,.2);
           border-top-color:#fff; border-radius:50%; animation:spin .7s linear infinite; }
@keyframes spin { to { transform:rotate(360deg); } }

/* ── Poller status badge ── */
.poller-badge { display:inline-flex; align-items:center; gap:6px; padding:4px 12px;
                border-radius:20px; font-size:11px; font-weight:600; }
.poller-ok  { background:rgba(46,204,113,.15); color:var(--green); border:1px solid var(--green); }
.poller-warn{ background:rgba(243,156,18,.15);  color:var(--yellow);border:1px solid var(--yellow);}
.poller-off { background:rgba(255,255,255,.05); color:#555;         border:1px solid #333; }

/* ── Interface table (port overview) ── */
.port-stats-table { width:100%; border-collapse:collapse; font-size:12px; }
.port-stats-table th { color:#555; font-size:10px; text-transform:uppercase; letter-spacing:1px;
                        padding:6px 10px; border-bottom:1px solid var(--border); text-align:left; }
.port-stats-table td { padding:8px 10px; border-bottom:1px solid rgba(255,255,255,.04); }
.port-stats-table tr:hover td { background:rgba(255,255,255,.03); }
.badge-up { background:rgba(46,204,113,.2); color:#2ecc71; padding:2px 8px; border-radius:10px; font-size:10px; }
.badge-dn { background:rgba(231,76,60,.2);  color:#e74c3c;  padding:2px 8px; border-radius:10px; font-size:10px; }

/* ── Min/Max/Cur legend table (LibreNMS style) ── */
.metric-legend { margin-top:12px; border-top:1px solid rgba(255,255,255,.06); padding-top:10px; }
.metric-legend table { width:100%; border-collapse:collapse; font-size:11px; font-family:'Consolas',monospace; }
.metric-legend th { color:#444; font-size:9px; text-transform:uppercase; letter-spacing:1px;
                    padding:3px 8px; text-align:right; font-weight:600; }
.metric-legend th:first-child, .metric-legend th:nth-child(2) { text-align:left; }
.metric-legend td { padding:3px 8px; text-align:right; color:#888; }
.metric-legend td:first-child { width:16px; padding-right:4px; }
.metric-legend td:nth-child(2){ text-align:left; color:#ccc; min-width:140px; max-width:200px;
                                 white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.metric-legend tr:hover td { background:rgba(255,255,255,.03); color:#fff; }
.metric-legend .cur-val { color:#fff; font-weight:700; }
.metric-legend .raw-val { color:#555; font-size:10px; }
.color-swatch { display:inline-block; width:12px; height:12px; border-radius:2px; }

/* ── Traffic legend ── */
.traffic-legend { display:flex; gap:20px; flex-wrap:wrap; margin-top:10px; font-size:11px;
                  border-top:1px solid rgba(255,255,255,.06); padding-top:10px; }
.tleg-col { flex:1; min-width:120px; }
.tleg-col .tleg-header { color:#666; font-size:9px; text-transform:uppercase; letter-spacing:1px;
                          margin-bottom:6px; display:flex; align-items:center; gap:6px; }
.tleg-row { display:flex; justify-content:space-between; padding:2px 0; color:#888; }
.tleg-row .tleg-key { color:#aaa; }
.tleg-row .tleg-val { color:#fff; font-weight:600; font-family:'Consolas',monospace; }

/* ── Responsive ── */
@media(max-width:900px) {
    .page-wrap { flex-direction:column; }
    .sidebar   { width:100%; border-right:none; border-bottom:1px solid var(--border); flex-direction:row; overflow-x:auto; padding:8px; }
    .sidebar-title { display:none; }
    .chart-grid { grid-template-columns:1fr; }
    .chart-full { grid-column:span 1; }
}
</style>
</head>
<body>
<video autoplay muted loop playsinline id="bg-video">
    <source src="/videos/<?= $videoFile ?>" type="video/mp4">
</video>

<div class="page-wrap">

<!-- ── Sidebar ──────────────────────────────────────────────────────────────── -->
<nav class="sidebar" id="sidebar">
    <div class="sidebar-title">Monitored Nodes</div>
    <?php foreach ($all_nodes as $n): ?>
    <div class="node-group <?= $n['node_id']===$sel_node_id?'open':'' ?>" id="ng-<?= $n['node_id'] ?>">
    <div class="node-item <?= $n['node_id']===$sel_node_id?'active':'' ?>"
         onclick="selectNode(<?= $n['node_id'] ?>)">
        <i class="fas fa-<?= $n['icon']==='mikrotik'?'network-wired':($n['icon']==='cisco'?'server':'desktop') ?>"
           style="color:var(--accent);font-size:11px;flex-shrink:0;"></i>
        <div>
            <div class="node-name"><?= htmlspecialchars($n['name']) ?></div>
            <div class="node-ip"><?= htmlspecialchars($n['ip']) ?></div>
        </div>
        <?php if (!empty($n['ports'])): ?>
        <i class="fas fa-chevron-right node-chevron" onclick="togglePorts(<?= $n['node_id'] ?>,event)"></i>
        <?php endif ?>
    </div>
    <div class="port-list" id="pl-<?= $n['node_id'] ?>">
    <?php foreach ($n['ports'] as $p): ?>
    <div class="port-item <?= ($n['node_id']===$sel_node_id && (int)$p['port_id']===$sel_port_id)?'active':'' ?>"
         id="pi-<?= $p['port_id'] ?>"
         onclick="selectPort(<?= $n['node_id'] ?>,<?= $p['port_id'] ?>)">
        <i class="fas fa-ethernet" style="margin-right:5px;font-size:10px;"></i>
        <?= htmlspecialchars($p['name']) ?>
    </div>
    <?php endforeach ?>
    </div>
    </div>
    <?php endforeach ?>

    <?php if (empty($all_nodes)): ?>
    <div class="no-data" style="padding:20px;">
        <i class="fas fa-server"></i>
        <div style="font-size:12px;">No nodes configured.<br>Go to <a href="net_mon_config.php" style="color:var(--accent);">NM Config</a></div>
    </div>
    <?php endif ?>
</nav>

<!-- ── Main area ─────────────────────────────────────────────────────────────── -->
<div class="main-area">

<!-- Header -->
<div class="stats-header">
    <div class="stats-title">
        <span><i class="fas fa-chart-area" style="color:var(--accent);margin-right:8px;"></i>Network Statistics</span>
        <span id="current-device-name" style="font-size:18px;font-weight:700;">
            <?= htmlspecialchars($all_nodes[$sel_node_id]['name'] ?? 'No device selected') ?>
        </span>
    </div>

    <!-- Poller status -->
    <div id="poller-status-badge" class="poller-badge poller-off">
        <i class="fas fa-circle-dot"></i> <span>Checking poller…</span>
    </div>

    <!-- Range selector -->
    <div class="range-bar">
        <?php foreach (['1h'=>'1H','6h'=>'6H','12h'=>'12H','24h'=>'24H','7d'=>'7D','30d'=>'30D'] as $v=>$l): ?>
        <button class="range-btn <?= $sel_range===$v?'active':'' ?>"
                onclick="setRange('<?= $v ?>')"><?= $l ?></button>
        <?php endforeach ?>
        <div class="range-sep"></div>
        <div class="custom-range">
            <input type="date" id="date-from" max="<?= date('Y-m-d') ?>">
            <span style="color:#555;font-size:12px;">→</span>
            <input type="date" id="date-to"   max="<?= date('Y-m-d') ?>">
            <button class="range-btn" onclick="applyCustomRange()"><i class="fas fa-filter"></i> Go</button>
        </div>
        <div class="range-sep"></div>
        <button class="range-btn" id="poll-now-btn" onclick="statsPollNow(this)"
                style="background:rgba(77,163,255,.15);border-color:rgba(77,163,255,.4);color:#4da3ff;"
                title="Force a fresh SNMP poll of this device, then reload the charts">
            <i class="fas fa-rotate"></i> <span class="pn-lbl">Poll now</span>
        </button>
    </div>
</div>

<?php if (!$has_data): ?>
<!-- ── No data state ─────────────────────────────────────────────────────── -->
<div class="glass-card" style="margin-bottom:20px;">
    <div class="no-data">
        <i class="fas fa-database" style="color:#333;"></i>
        <div style="font-size:16px;color:#aaa;">No statistics collected yet</div>
        <div style="font-size:12px;color:#555;max-width:500px;">
            The statistics poller hasn't run yet. Set it up in
            <a href="net_mon_config.php?tab=poller" style="color:var(--accent);">NM Configuration → Poller</a>
            or run it manually:
        </div>
        <code style="background:rgba(0,0,0,.5);padding:8px 16px;border-radius:6px;font-size:12px;color:#4da3ff;">
            <?= VENV_PYTHON ?> <?= SCRIPTS_DIR ?>/nm_poller.py
        </code>
    </div>
</div>
<?php endif ?>

<?php if (!empty($all_nodes)): ?>

<!-- ── Device Summary Pills ──────────────────────────────────────────────── -->
<div class="stat-grid" id="summary-pills">
    <div class="stat-pill">
        <div class="lbl"><i class="fas fa-microchip"></i> CPU (avg)</div>
        <div class="val color-cpu" id="sum-cpu">—</div>
        <div class="sub">Latest reading</div>
    </div>
    <div class="stat-pill">
        <div class="lbl"><i class="fas fa-memory"></i> Memory</div>
        <div class="val color-mem" id="sum-mem">—</div>
        <div class="sub">Latest reading</div>
    </div>
    <div class="stat-pill">
        <div class="lbl"><i class="fas fa-hdd"></i> Disk</div>
        <div class="val color-disk" id="sum-disk">—</div>
        <div class="sub">Primary volume</div>
    </div>
    <div class="stat-pill">
        <div class="lbl"><i class="fas fa-temperature-half"></i> Temperature</div>
        <div class="val color-temp" id="sum-temp">—</div>
        <div class="sub">Latest sensor</div>
    </div>
    <div class="stat-pill">
        <div class="lbl"><i class="fas fa-clock"></i> Uptime</div>
        <div class="val" id="sum-uptime" style="font-size:14px;color:#aaa;">—</div>
        <div class="sub">Device uptime</div>
    </div>
    <div class="stat-pill">
        <div class="lbl"><i class="fas fa-ethernet"></i> Port</div>
        <div class="val color-in" id="sum-port-name" style="font-size:13px;">—</div>
        <div class="sub" id="sum-port-speed">Select interface below</div>
    </div>
</div>

<!-- ── Port traffic summary pills ────────────────────────────────────────── -->
<div class="stat-grid" id="traffic-pills" style="display:none;">
    <div class="stat-pill">
        <div class="lbl color-in"><i class="fas fa-arrow-down"></i> IN Average</div>
        <div class="val color-in" id="tsum-in-avg">—</div>
    </div>
    <div class="stat-pill">
        <div class="lbl color-out"><i class="fas fa-arrow-up"></i> OUT Average</div>
        <div class="val color-out" id="tsum-out-avg">—</div>
    </div>
    <div class="stat-pill">
        <div class="lbl color-in"><i class="fas fa-bolt"></i> IN Peak</div>
        <div class="val color-in" id="tsum-in-peak">—</div>
    </div>
    <div class="stat-pill">
        <div class="lbl color-out"><i class="fas fa-bolt"></i> OUT Peak</div>
        <div class="val color-out" id="tsum-out-peak">—</div>
    </div>
    <div class="stat-pill">
        <div class="lbl" style="color:#aaa;"><i class="fas fa-percent"></i> 95th% IN</div>
        <div class="val color-in" id="tsum-p95-in">—</div>
        <div class="sub">Industry standard billing metric</div>
    </div>
    <div class="stat-pill">
        <div class="lbl" style="color:#aaa;"><i class="fas fa-percent"></i> 95th% OUT</div>
        <div class="val color-out" id="tsum-p95-out">—</div>
        <div class="sub">Industry standard billing metric</div>
    </div>
</div>

<!-- ── Charts grid ────────────────────────────────────────────────────────── -->
<div class="chart-grid">

    <!-- Ping latency / availability (ping-only nodes, full width) -->
    <div class="glass-card chart-full" id="ping-card" style="display:none;">
        <div class="card-title">
            <i class="fas fa-satellite-dish"></i>
            ICMP Reachability — latency &amp; availability
            <span id="ping-loading" style="margin-left:8px;"></span>
        </div>
        <div class="stat-grid" id="ping-pills" style="margin-bottom:14px;">
            <div class="stat-pill"><div class="lbl"><i class="fas fa-percent"></i> Availability</div>
                <div class="val" id="psum-avail" style="color:#2ecc71;">—</div><div class="sub">Up % in range</div></div>
            <div class="stat-pill"><div class="lbl"><i class="fas fa-stopwatch"></i> Avg latency</div>
                <div class="val color-in" id="psum-avg">—</div><div class="sub">Mean RTT</div></div>
            <div class="stat-pill"><div class="lbl"><i class="fas fa-bolt"></i> Min / Max</div>
                <div class="val" id="psum-minmax" style="font-size:14px;color:#aaa;">—</div><div class="sub">RTT range</div></div>
            <div class="stat-pill"><div class="lbl"><i class="fas fa-triangle-exclamation"></i> Packet loss</div>
                <div class="val" id="psum-loss" style="color:#e74c3c;">—</div><div class="sub">Avg loss</div></div>
        </div>
        <div class="chart-wrap tall" id="ping-wrap">
            <div class="no-data" id="ping-no-data" style="display:none;">
                <i class="fas fa-satellite-dish"></i><div>No ping data for this period</div></div>
            <canvas id="chart-ping" style="display:none;"></canvas>
        </div>
    </div>

    <!-- Smokeping latency (any node tied to Smokeping by IP, full width) -->
    <div class="glass-card chart-full" id="smoke-card" style="display:none;">
        <div class="card-title">
            <i class="fas fa-wave-square" style="color:#0db7ed;"></i>
            Smokeping Latency — RTT &amp; packet loss
            <span id="smoke-loading" style="margin-left:8px;"></span>
            <a href="smokeping.php" style="margin-left:auto;font-size:11px;color:#667;text-decoration:none;font-weight:400;">Smokeping →</a>
        </div>
        <div class="stat-grid" id="smoke-pills" style="margin-bottom:14px;">
            <div class="stat-pill"><div class="lbl"><i class="fas fa-stopwatch"></i> Avg latency</div>
                <div class="val color-in" id="ssum-avg">—</div><div class="sub">Median RTT</div></div>
            <div class="stat-pill"><div class="lbl"><i class="fas fa-bolt"></i> Min / Max</div>
                <div class="val" id="ssum-minmax" style="font-size:14px;color:#aaa;">—</div><div class="sub">RTT range</div></div>
            <div class="stat-pill"><div class="lbl"><i class="fas fa-triangle-exclamation"></i> Packet loss</div>
                <div class="val" id="ssum-loss" style="color:#e74c3c;">—</div><div class="sub">Avg / peak lost</div></div>
            <div class="stat-pill"><div class="lbl"><i class="fas fa-database"></i> Samples</div>
                <div class="val" id="ssum-n" style="color:#aaa;">—</div><div class="sub">In range</div></div>
        </div>
        <div class="chart-wrap tall" id="smoke-wrap">
            <div class="no-data" id="smoke-no-data" style="display:none;">
                <i class="fas fa-wave-square"></i><div>No Smokeping data for this node/period</div></div>
            <canvas id="chart-smoke" style="display:none;"></canvas>
        </div>
    </div>

    <!-- Interface Traffic (full width) -->
    <div class="glass-card chart-full" id="traffic-card">
        <div class="card-title">
            <i class="fas fa-chart-area"></i>
            Interface Traffic — <span id="chart-port-label">Select a port</span>
            <span id="traffic-loading" style="margin-left:8px;"></span>
        </div>
        <div class="chart-wrap tall" id="traffic-wrap">
            <div class="no-data" id="traffic-no-data">
                <i class="fas fa-ethernet"></i>
                <div>Select an interface from the left panel</div>
            </div>
            <canvas id="chart-traffic" style="display:none;"></canvas>
        </div>
        <div id="traffic-legend"></div>
    </div>

    <!-- CPU -->
    <div class="glass-card">
        <div class="card-title"><i class="fas fa-microchip"></i> CPU Utilization
            <span id="cpu-loading" style="margin-left:8px;"></span></div>
        <div class="chart-wrap">
            <div class="no-data" id="cpu-no-data" style="display:none;">
                <i class="fas fa-microchip"></i><div>No CPU data</div></div>
            <canvas id="chart-cpu"></canvas>
        </div>
        <div id="legend-cpu" class="metric-legend" style="display:none;"></div>
    </div>

    <!-- Memory -->
    <div class="glass-card">
        <div class="card-title"><i class="fas fa-memory"></i> Memory Utilization
            <span id="mem-loading" style="margin-left:8px;"></span></div>
        <div class="chart-wrap">
            <div class="no-data" id="mem-no-data" style="display:none;">
                <i class="fas fa-memory"></i><div>No memory data</div></div>
            <canvas id="chart-mem"></canvas>
        </div>
        <div id="legend-mem" class="metric-legend" style="display:none;"></div>
    </div>

    <!-- Disk -->
    <div class="glass-card">
        <div class="card-title"><i class="fas fa-hdd"></i> Storage Utilization
            <span id="disk-loading" style="margin-left:8px;"></span></div>
        <div class="chart-wrap">
            <div class="no-data" id="disk-no-data" style="display:none;">
                <i class="fas fa-hdd"></i><div>No storage data</div></div>
            <canvas id="chart-disk"></canvas>
        </div>
        <div id="legend-disk" class="metric-legend" style="display:none;"></div>
    </div>

    <!-- Temperature -->
    <div class="glass-card">
        <div class="card-title"><i class="fas fa-temperature-half"></i> Temperature (°C)
            <span id="temp-loading" style="margin-left:8px;"></span></div>
        <div class="chart-wrap">
            <div class="no-data" id="temp-no-data" style="display:none;">
                <i class="fas fa-temperature-half"></i><div>No sensor data</div></div>
            <canvas id="chart-temp"></canvas>
        </div>
        <div id="legend-temp" class="metric-legend" style="display:none;"></div>
    </div>

    <!-- Custom Sensors (fan speed, voltage, custom OIDs) -->
    <div class="glass-card" id="custom-sensors-card" style="display:none;">
        <div class="card-title"><i class="fas fa-sliders"></i> Custom Sensors
            <span id="custom-loading" style="margin-left:8px;"></span></div>
        <div class="chart-wrap">
            <div class="no-data" id="custom-no-data" style="display:none;">
                <i class="fas fa-sliders"></i><div>No custom sensor data</div></div>
            <canvas id="chart-custom"></canvas>
        </div>
        <div id="legend-custom" class="metric-legend" style="display:none;"></div>
    </div>

    <!-- GPU telemetry (only when this node is a registered GPU target) -->
    <div class="glass-card" id="gpu-card" style="display:none;">
        <div class="card-title"><i class="fas fa-microchip" style="color:#76b900;"></i> GPU
            <span id="gpu-live" style="margin-left:10px;font-size:12px;color:#9aa;font-weight:400;"></span>
            <a id="gpu-link" href="gpu.php" style="float:right;font-size:12px;">Open GPU dashboard <i class="fas fa-arrow-up-right-from-square"></i></a>
        </div>
        <div id="gpu-models" style="margin:2px 0 8px;"></div>
        <div class="chart-wrap"><canvas id="chart-gpu"></canvas></div>
    </div>

</div><!-- /chart-grid -->

<?php else: ?>
<div class="glass-card">
    <div class="no-data">
        <i class="fas fa-server"></i>
        <div>No monitored nodes configured.</div>
        <a href="net_mon_config.php" class="range-btn" style="margin-top:8px;">
            <i class="fas fa-sliders"></i> Go to Configuration
        </a>
    </div>
</div>
<?php endif ?>

</div><!-- /main-area -->
</div><!-- /page-wrap -->

<script>
// ─── State ────────────────────────────────────────────────────────────────────
let _nodeId  = <?= $sel_node_id ?>;
let _portId  = <?= $sel_port_id ?>;
let _range   = '<?= $sel_range ?>';
let _fromDt  = '';
let _toDt    = '';

const NODES  = <?= json_encode(array_values($all_nodes)) ?>;

// Chart instances
let _charts  = {};

// ─── Chart.js global defaults ─────────────────────────────────────────────────
Chart.defaults.color          = '#666';
Chart.defaults.borderColor    = 'rgba(255,255,255,0.08)';
Chart.defaults.font.family    = "'Segoe UI', Tahoma, sans-serif";
Chart.defaults.font.size      = 11;
// Enable mouse-wheel zoom (+ pinch/pan) on the time-series charts. Scroll to zoom the time axis,
// drag to pan, double-click a chart to reset.
if (window.ChartZoom) { try { Chart.register(window.ChartZoom.default || window.ChartZoom); } catch(e){} }

// ─── Color palettes ───────────────────────────────────────────────────────────
const PALETTE = ['#4da3ff','#9b59b6','#2ecc71','#f39c12','#1abc9c','#e74c3c','#3498db','#e67e22'];

function mkGradient(ctx, color) {
    const g = ctx.createLinearGradient(0, 0, 0, ctx.canvas.height);
    const hex = color.replace('#','');
    const r = parseInt(hex.substr(0,2),16), gv = parseInt(hex.substr(2,2),16), b = parseInt(hex.substr(4,2),16);
    g.addColorStop(0,   `rgba(${r},${gv},${b},0.35)`);
    g.addColorStop(0.6, `rgba(${r},${gv},${b},0.08)`);
    g.addColorStop(1,   `rgba(${r},${gv},${b},0.0)`);
    return g;
}

// ─── Shared chart options ─────────────────────────────────────────────────────
function timeChartOpts(yLabel, yFmt, tooltipFmt) {
    return {
        responsive:         true,
        maintainAspectRatio:false,
        interaction: { mode:'index', intersect:false },
        plugins: {
            legend: {
                labels: { color:'#aaa', boxWidth:12, padding:16, font:{size:11} }
            },
            tooltip: {
                backgroundColor: 'rgba(10,10,20,0.92)',
                borderColor:     'rgba(255,255,255,0.15)',
                borderWidth:     1,
                padding:         10,
                callbacks: { label: tooltipFmt }
            }
        },
        scales: {
            x: {
                type:  'time',
                time:  { tooltipFormat:'MMM d, HH:mm', displayFormats:{
                    minute:'HH:mm', hour:'MMM d HH:mm', day:'MMM d', week:'MMM d' }},
                grid:  { color:'rgba(255,255,255,0.04)' },
                ticks: { color:'#555', maxTicksLimit:10 }
            },
            y: {
                beginAtZero: true,
                grid:  { color:'rgba(255,255,255,0.04)' },
                ticks: { color:'#555', callback: yFmt },
                title: { display:!!yLabel, text:yLabel, color:'#555', font:{size:10} }
            }
        },
        animation: { duration:600 }
    };
}

// ─── Format helpers ───────────────────────────────────────────────────────────
function fmtBps(bps) {
    if (bps === null || bps === undefined) return '-';
    bps = +bps;
    if (bps >= 1e9)  return (bps/1e9).toFixed(2)  + ' Gbps';
    if (bps >= 1e6)  return (bps/1e6).toFixed(2)  + ' Mbps';
    if (bps >= 1e3)  return (bps/1e3).toFixed(1)  + ' Kbps';
    return bps.toFixed(0) + ' bps';
}
function fmtBytes(bps) {
    if (bps === null || bps === undefined) return '-';
    bps = +bps;
    if (bps >= 1e9)  return (bps/1e9).toFixed(2)  + ' GB/s';
    if (bps >= 1e6)  return (bps/1e6).toFixed(2)  + ' MB/s';
    if (bps >= 1e3)  return (bps/1e3).toFixed(1)  + ' KB/s';
    return bps.toFixed(0) + ' B/s';
}
function fmtPct(v)  { return (+v).toFixed(1) + '%'; }
function fmtUptime(secs) {
    secs = Math.floor(+secs);
    const d = Math.floor(secs/86400), h = Math.floor((secs%86400)/3600), m = Math.floor((secs%3600)/60);
    return `${d}d ${h}h ${m}m`;
}

// ─── Destroy + recreate chart helper ─────────────────────────────────────────
function makeChart(id, type, data, opts) {
    if (_charts[id]) { _charts[id].destroy(); delete _charts[id]; }
    const canvas = document.getElementById(id);
    if (!canvas) return;
    canvas.style.display = 'block';
    // wheel-zoom + pinch + drag-pan on the time axis (injected here so every chart gets it)
    if (window.ChartZoom) {
        opts = opts || {}; opts.plugins = opts.plugins || {};
        if (!opts.plugins.zoom) opts.plugins.zoom = {
            zoom: { wheel:{enabled:true}, pinch:{enabled:true}, mode:'x' },
            pan:  { enabled:true, mode:'x' },
            limits:{ x:{minRange: 60000} }   // don't zoom tighter than ~1 minute
        };
    }
    _charts[id] = new Chart(canvas.getContext('2d'), { type, data, options: opts });
    canvas.ondblclick = () => { try { _charts[id] && _charts[id].resetZoom(); } catch(e){} };   // double-click to reset zoom
    return _charts[id];
}

function showNoData(id, show) {
    const el = document.getElementById(id);
    if (el) el.style.display = show ? 'flex' : 'none';
    const ca = document.getElementById(id.replace('-no-data','chart-').replace('no-data',''));
    // handled per-chart
}

function setLoading(id, on) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = on ? '<span class="spinner"></span>' : '';
}

// ─── Legend table renderers ───────────────────────────────────────────────────

function fmtRaw(bytes) {
    if (bytes === null || bytes === undefined) return '';
    bytes = +bytes;
    if (bytes >= 1e12) return (bytes/1e12).toFixed(2)+' TiB';
    if (bytes >= 1e9)  return (bytes/1e9).toFixed(2) +' GiB';
    if (bytes >= 1e6)  return (bytes/1e6).toFixed(2) +' MiB';
    if (bytes >= 1e3)  return (bytes/1e3).toFixed(1) +' KiB';
    return bytes+' B';
}

// Renders a Min/Max/Cur table like LibreNMS under a metric chart
// stats = { key: {min, max, avg, cur, raw}, ... }
// keys  = ordered array of keys
// palette = color array indexed by key position
function renderMetricLegend(containerId, keys, stats, palette, valFmt) {
    const el = document.getElementById(containerId);
    if (!el || !keys.length) return;

    const filteredKeys = keys.filter(k => k !== 'avg');
    if (!filteredKeys.length) return;

    const rows = filteredKeys.map((key, i) => {
        const s     = stats[key] || {};
        const color = palette[i % palette.length];
        const cur   = s.cur !== null && s.cur !== undefined ? valFmt(s.cur) : '—';
        const min   = s.min !== null && s.min !== undefined ? valFmt(s.min) : '—';
        const max   = s.max !== null && s.max !== undefined ? valFmt(s.max) : '—';
        const raw   = s.raw !== null && s.raw !== undefined ? fmtRaw(s.raw)  : '';
        return `<tr>
            <td><span class="color-swatch" style="background:${color};"></span></td>
            <td title="${escHtml(key)}">${escHtml(key)}</td>
            <td>${min}</td>
            <td>${max}</td>
            <td class="cur-val">${cur}</td>
            <td class="raw-val">${raw}</td>
        </tr>`;
    }).join('');

    el.innerHTML = `<table>
        <thead><tr>
            <th colspan="2">Metric</th>
            <th>Min</th><th>Max</th><th>Current</th><th>Value</th>
        </tr></thead>
        <tbody>${rows}</tbody>
    </table>`;
    el.style.display = 'block';
}

// Traffic legend: side-by-side IN / OUT columns
function renderTrafficLegend(containerId, r) {
    const el = document.getElementById(containerId);
    if (!el || !r) return;

    const mkRow = (label, val) =>
        `<div class="tleg-row"><span class="tleg-key">${label}</span><span class="tleg-val">${val}</span></div>`;

    el.innerHTML = `<div class="traffic-legend">
        <div class="tleg-col">
            <div class="tleg-header"><span class="color-swatch" style="background:#4da3ff;"></span> ↓ IN (bytes/sec → bps)</div>
            ${mkRow('Min',     fmtBps((+r.rows.reduce((a,x)=>Math.min(a,+x.in_avg), Infinity))*8))}
            ${mkRow('Avg',     fmtBps(r.avg_in*8))}
            ${mkRow('Max',     fmtBps(r.peak_in*8))}
            ${mkRow('95th %',  fmtBps(r.p95_in*8))}
        </div>
        <div class="tleg-col">
            <div class="tleg-header"><span class="color-swatch" style="background:#9b59b6;"></span> ↑ OUT (bytes/sec → bps)</div>
            ${mkRow('Min',     fmtBps((+r.rows.reduce((a,x)=>Math.min(a,+x.out_avg), Infinity))*8))}
            ${mkRow('Avg',     fmtBps(r.avg_out*8))}
            ${mkRow('Max',     fmtBps(r.peak_out*8))}
            ${mkRow('95th %',  fmtBps(r.p95_out*8))}
        </div>
    </div>`;
}

function escHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ─── Traffic chart ────────────────────────────────────────────────────────────
async function loadTrafficChart() {
    if (!_portId) return;
    setLoading('traffic-loading', true);
    document.getElementById('traffic-no-data').style.display = 'none';
    document.getElementById('chart-traffic').style.display   = 'none';

    const url = buildUrl('port_traffic', { port_id: _portId });
    const r   = await fetchApi(url);
    setLoading('traffic-loading', false);

    if (!r || !r.rows || !r.rows.length) {
        document.getElementById('traffic-no-data').style.display = 'flex';
        document.getElementById('traffic-no-data').innerHTML =
            '<i class="fas fa-ethernet"></i><div>No traffic data for this period</div>';
        document.getElementById('traffic-pills').style.display = 'none';
        return;
    }

    const labels  = r.rows.map(d => window.nmAxisTs ? nmAxisTs(d.ts) : d.ts);   // x-axis in app timezone
    const inData  = r.rows.map(d => (+d.in_avg)  * 8);   // bytes→bits
    const outData = r.rows.map(d => (+d.out_avg) * 8);

    const canvas  = document.getElementById('chart-traffic');
    const ctx     = canvas.getContext('2d');
    const opts    = timeChartOpts('', v => fmtBps(v), ctx => fmtBps(ctx.parsed.y));

    // Add second Y axis for utilization %
    opts.scales.y1 = {
        type:'linear', position:'right', min:0, max:100, display: inData.some(v => v>0),
        grid:{ drawOnChartArea:false },
        ticks:{ color:'#444', callback: v => v+'%' }
    };

    makeChart('chart-traffic', 'line', {
        labels,
        datasets: [
            {
                label:           '↓ IN',
                data:            inData,
                borderColor:     '#4da3ff',
                backgroundColor: ctx2 => mkGradient(ctx2.chart.ctx, '#4da3ff'),
                borderWidth:     2,
                pointRadius:     0,
                tension:         0.4,
                fill:            true,
            },
            {
                label:           '↑ OUT',
                data:            outData,
                borderColor:     '#9b59b6',
                backgroundColor: ctx2 => mkGradient(ctx2.chart.ctx, '#9b59b6'),
                borderWidth:     2,
                pointRadius:     0,
                tension:         0.4,
                fill:            true,
            },
        ]
    }, opts);

    // Update traffic summary pills
    document.getElementById('traffic-pills').style.display = 'grid';
    document.getElementById('tsum-in-avg').textContent    = fmtBps(r.avg_in  * 8);
    document.getElementById('tsum-out-avg').textContent   = fmtBps(r.avg_out * 8);
    document.getElementById('tsum-in-peak').textContent   = fmtBps(r.peak_in * 8);
    document.getElementById('tsum-out-peak').textContent  = fmtBps(r.peak_out* 8);
    document.getElementById('tsum-p95-in').textContent    = fmtBps(r.p95_in  * 8);
    document.getElementById('tsum-p95-out').textContent   = fmtBps(r.p95_out * 8);

    // Min/Max/Cur traffic legend table
    renderTrafficLegend('traffic-legend', r);
}

// ─── Device metric chart (CPU / Memory / Disk / Temp) ─────────────────────────
async function loadMetricChart(type, chartId, noDataId, loadingId, colorIdx, yFmt, band) {
    if (!_nodeId) return;
    setLoading(loadingId, true);

    const url = buildUrl('device_metrics', { node_id: _nodeId, type });
    const r   = await fetchApi(url);
    setLoading(loadingId, false);

    const noDataEl = document.getElementById(noDataId);
    const canvas   = document.getElementById(chartId);

    if (!r || !r.times || !r.times.length) {
        if (noDataEl) noDataEl.style.display = 'flex';
        if (canvas)   canvas.style.display   = 'none';
        return;
    }
    if (noDataEl) noDataEl.style.display = 'none';
    if (canvas)   canvas.style.display   = 'block';

    // ── Select which keys to display ─────────────────────────────────────────
    let keys;
    if (type === 'cpu') {
        // CPU Idle belongs to custom sensors — including it inflates the Y axis
        // to 100% making actual usage (1-3%) invisible at the bottom.
        // For truly massive servers (>20 cores) show avg only; otherwise show per-core.
        const coreKeys = r.keys.filter(k => /^(cpu\d+|core_\d+)$/.test(k));
        if (coreKeys.length > 20) {
            keys = ['avg'];  // avg only for >20-core servers
        } else if (coreKeys.length > 0) {
            keys = coreKeys; // per-core for ≤20 cores (MikroTik, HP EliteDesk)
        } else {
            keys = r.keys.filter(k => k !== 'avg' && k !== 'CPU Idle');
        }
    } else {
        keys = r.keys.filter(k => k !== 'avg');
    }

    const rawTimes= r.times;                                                    // UTC keys (for data + baseline lookup)
    const labels  = rawTimes.map(ts => window.nmAxisTs ? nmAxisTs(ts) : ts);    // x-axis in app timezone
    const datasets= keys.map((key, i) => {
        const color = PALETTE[(colorIdx + i) % PALETTE.length];
        return {
            label:           key,
            data:            rawTimes.map(ts => r.data[ts]?.[key] ?? null),
            borderColor:     color,
            backgroundColor: ctx => mkGradient(ctx.chart.ctx, color),
            borderWidth:     1.5,
            pointRadius:     0,
            tension:         0.4,
            fill:            keys.length === 1,
            spanGaps:        true,
        };
    });

    if (!datasets.length) {
        if (noDataEl) noDataEl.style.display = 'flex';
        if (canvas)   canvas.style.display   = 'none';
        return;
    }

    const opts = timeChartOpts('', yFmt, ctx => yFmt(ctx.parsed.y));
    // Storage values can be very small (<1%) — let Chart.js auto-scale the Y axis
    if (type === 'storage') opts.scales.y.beginAtZero = false;

    // ── Zero-Threshold "expected" band overlay (learned baselines) ───────────
    if (band) {
        try {
            const bl = await fetchApi(buildUrl('baselines', { node_id:_nodeId, type }));
            const B  = (bl && bl.baselines && !Array.isArray(bl.baselines)) ? bl.baselines : {};
            let bk = B['avg'] ? 'avg' : (keys.find(k => B[k]) || Object.keys(B)[0] || null);
            if (bk) {
                const how = ts => { const d = new Date(ts); return ((d.getDay()+6)%7)*24 + d.getHours(); };
                const mean=[], up=[], lo=[];
                rawTimes.forEach(ts => {
                    const b = B[bk][how(ts)];
                    if (b && b.samples >= 20) { mean.push(b.mean); up.push(b.mean + 2*b.stdev); lo.push(Math.max(0, b.mean - 2*b.stdev)); }
                    else { mean.push(null); up.push(null); lo.push(null); }
                });
                if (mean.some(v => v !== null)) {
                    const idxUpper = datasets.length + 1;   // mean at len, upper at len+1
                    datasets.push({ label:'Expected', data:mean, borderColor:'rgba(255,255,255,.4)',
                        borderWidth:1, borderDash:[5,4], pointRadius:0, fill:false, tension:.3, spanGaps:true });
                    datasets.push({ label:'_bandHi', data:up, borderColor:'rgba(46,204,113,0)', borderWidth:0,
                        pointRadius:0, fill:false, spanGaps:true, _band:true });
                    datasets.push({ label:'_bandLo', data:lo, borderColor:'rgba(46,204,113,0)', borderWidth:0,
                        pointRadius:0, spanGaps:true, _band:true,
                        fill:{ target:idxUpper, above:'rgba(46,204,113,.12)', below:'rgba(46,204,113,.12)' } });
                    opts.plugins.legend.labels.filter = (it, data) => !data.datasets[it.datasetIndex]._band;
                    opts.plugins.tooltip.filter = (it) => !it.dataset._band;
                }
            }
        } catch(e) {}
    }

    makeChart(chartId, 'line', { labels, datasets }, opts);

    // Render Min/Max/Cur legend table
    const legendId = 'legend-' + chartId.replace('chart-','');
    if (r.stats && Object.keys(r.stats).length) {
        renderMetricLegend(legendId, keys, r.stats, PALETTE.slice(colorIdx), yFmt);
    }
}

// ─── Device summary pills ─────────────────────────────────────────────────────
async function loadSummary() {
    if (!_nodeId) return;
    const r = await fetchApi(buildUrl('device_summary', { node_id: _nodeId }));
    if (!r) return;

    // CPU
    if (r.cpu) {
        const avg = r.cpu['avg'] ?? Object.values(r.cpu)[0] ?? null;
        document.getElementById('sum-cpu').textContent = avg !== null ? fmtPct(avg) : '—';
    }
    // Memory
    if (r.memory) {
        const v = Object.values(r.memory)[0] ?? null;
        document.getElementById('sum-mem').textContent = v !== null ? fmtPct(v) : '—';
    }
    // Disk
    if (r.storage) {
        const v = Object.values(r.storage)[0] ?? null;
        document.getElementById('sum-disk').textContent = v !== null ? fmtPct(v) : '—';
    }
    // Temperature
    if (r.temperature) {
        const v = Object.values(r.temperature)[0] ?? null;
        document.getElementById('sum-temp').textContent = v !== null ? (+v).toFixed(1)+'°C' : '—';
    }
    // Uptime
    if (r.uptime?.seconds !== undefined) {
        document.getElementById('sum-uptime').textContent = fmtUptime(r.uptime.seconds);
    }
}

// ─── Poller status ────────────────────────────────────────────────────────────
async function checkPollerStatus() {
    const r  = await fetchApi('net_mon_stats.php?api=poller_log');
    const el = document.getElementById('poller-status-badge');
    if (!r || !r.log?.length) {
        el.className = 'poller-badge poller-off';
        el.innerHTML = '<i class="fas fa-circle-dot"></i> <span>Poller not yet run</span>';
        return;
    }
    const last   = r.log[0];
    const mins   = Math.floor((Date.now() - new Date(last.ran_at).getTime()) / 60000);
    const stale  = mins > 15;
    el.className = 'poller-badge ' + (last.status==='ok' && !stale ? 'poller-ok' : 'poller-warn');
    el.innerHTML = `<i class="fas fa-circle-dot"></i>
        <span>Last poll ${mins < 1 ? 'just now' : mins+'m ago'} · ${last.ports_polled} ports</span>`;
}

// ─── API fetch helper ─────────────────────────────────────────────────────────
async function fetchApi(url) {
    try {
        const r = await fetch(url, { credentials:'same-origin' });
        return await r.json();
    } catch(e) {
        console.error('fetch error', url, e);
        return null;
    }
}

function buildUrl(api, extra={}) {
    const p = new URLSearchParams({ api, range: _range });
    if (_fromDt) p.set('from', _fromDt);
    if (_toDt)   p.set('to',   _toDt);
    Object.entries(extra).forEach(([k,v]) => p.set(k,v));
    return 'net_mon_stats.php?' + p.toString();
}

// ─── Custom sensors chart (fan speed, voltage, custom OIDs) ──────────────────
async function loadCustomSensors() {
    if (!_nodeId) return;
    setLoading('custom-loading', true);
    const url = buildUrl('device_metrics', { node_id: _nodeId, type: 'custom' });
    const r   = await fetchApi(url);
    setLoading('custom-loading', false);

    const card    = document.getElementById('custom-sensors-card');
    const noDataEl= document.getElementById('custom-no-data');
    const canvas  = document.getElementById('chart-custom');

    if (!r || !r.times || !r.times.length) {
        if (card) card.style.display = 'none';  // hide entirely if no custom sensors
        return;
    }
    if (card) card.style.display = 'block';
    if (noDataEl) noDataEl.style.display = 'none';
    if (canvas)   canvas.style.display   = 'block';

    const keys    = r.keys;
    const rawTimes= r.times;                                                    // UTC keys (for data lookup)
    const labels  = rawTimes.map(ts => window.nmAxisTs ? nmAxisTs(ts) : ts);    // x-axis in app timezone
    // Use raw values (not %) — scale axis to whatever the sensor provides
    const datasets = keys.map((key, i) => {
        const color = PALETTE[(6 + i) % PALETTE.length];
        return {
            label:           key,
            data:            rawTimes.map(ts => r.data[ts]?.[key] ?? null),
            borderColor:     color,
            backgroundColor: ctx => mkGradient(ctx.chart.ctx, color),
            borderWidth:     1.5, pointRadius: 0, tension: 0.4, fill: keys.length === 1,
        };
    });

    const opts = timeChartOpts('', v => (+v).toFixed(1), ctx => (+ctx.parsed.y).toFixed(1));
    makeChart('chart-custom', 'line', { labels, datasets }, opts);
    if (r.stats && Object.keys(r.stats).length)
        renderMetricLegend('legend-custom', keys, r.stats, PALETTE.slice(6), v => (+v).toFixed(1));
}

// ─── Ping latency / availability chart (ping-only nodes) ──────────────────────
function isPingNode(nid) {
    const n = NODES.find(x => x.node_id === nid);
    return !!(n && n.monitor_type === 'ping');
}
// Show ping card for ping nodes, SNMP cards for everything else.
function applyNodeMode() {
    const ping = isPingNode(_nodeId);
    const card = document.getElementById('ping-card');
    if (card) card.style.display = ping ? 'block' : 'none';
    const snmpIds = ['summary-pills','traffic-pills','traffic-card'];
    snmpIds.forEach(id => { const el = document.getElementById(id);
        if (el) el.style.display = ping ? 'none' : (id==='traffic-pills' ? el.style.display : ''); });
    if (ping) document.getElementById('traffic-pills').style.display = 'none';
    // metric cards (cpu/mem/disk/temp/custom) — hide for ping nodes
    ['chart-cpu','chart-mem','chart-disk','chart-temp'].forEach(cid => {
        const c = document.getElementById(cid)?.closest('.glass-card');
        if (c) c.style.display = ping ? 'none' : '';
    });
    if (ping) { const cs = document.getElementById('custom-sensors-card'); if (cs) cs.style.display='none'; }
}
async function loadPingChart() {
    if (!_nodeId) return;
    setLoading('ping-loading', true);
    const r = await fetchApi(buildUrl('ping_history', { node_id: _nodeId }));
    setLoading('ping-loading', false);
    const noData = document.getElementById('ping-no-data');
    const canvas = document.getElementById('chart-ping');
    if (!r || !r.times || !r.times.length) {
        if (noData) noData.style.display = 'flex';
        if (canvas) canvas.style.display = 'none';
        ['psum-avail','psum-avg','psum-minmax','psum-loss'].forEach(id=>{const e=document.getElementById(id);if(e)e.textContent='—';});
        return;
    }
    if (noData) noData.style.display = 'none';
    if (canvas) canvas.style.display = 'block';

    const opts = timeChartOpts('ms', v => v+' ms', ctx => ctx.dataset.yAxisID==='y1'
        ? (+ctx.parsed.y).toFixed(0)+'% up' : (+ctx.parsed.y).toFixed(1)+' ms');
    opts.scales.y1 = { type:'linear', position:'right', min:0, max:100, grid:{ drawOnChartArea:false },
        ticks:{ color:'#444', callback:v=>v+'%' } };

    makeChart('chart-ping', 'line', {
        labels: r.times,
        datasets: [
            { label:'Latency (ms)', data:r.latency, yAxisID:'y',
              borderColor:'#4da3ff', backgroundColor:ctx=>mkGradient(ctx.chart.ctx,'#4da3ff'),
              borderWidth:2, pointRadius:0, tension:0.35, fill:true, spanGaps:false },
            { label:'Availability (%)', data:r.avail, yAxisID:'y1',
              borderColor:'#2ecc71', backgroundColor:'rgba(46,204,113,0.06)',
              borderWidth:1, pointRadius:0, tension:0.2, fill:true, stepped:true },
        ]
    }, opts);

    const s = r.summary || {};
    const el = (id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v;};
    el('psum-avail', s.availability!=null ? (+s.availability).toFixed(1)+'%' : '—');
    el('psum-avg',   s.avg_lat!=null ? (+s.avg_lat).toFixed(1)+' ms' : '—');
    el('psum-minmax',(s.min_lat!=null?(+s.min_lat).toFixed(0):'—')+' / '+(s.max_lat!=null?(+s.max_lat).toFixed(0):'—')+' ms');
    el('psum-loss',  s.loss!=null ? (+s.loss).toFixed(1)+'%' : '—');
}

// ─── Smokeping latency chart (any node tied to Smokeping by IP) ───────────────
async function loadSmokeChart() {
    if (!_nodeId) return;
    setLoading('smoke-loading', true);
    const r = await fetchApi(buildUrl('smoke_history', { node_id: _nodeId }));
    setLoading('smoke-loading', false);
    const card = document.getElementById('smoke-card');
    const canvas = document.getElementById('chart-smoke');
    const hasData = r && r.rtt && r.rtt.some(v => v != null);
    if (!hasData) { if (card) card.style.display = 'none'; return; }   // hide for nodes Smokeping doesn't cover
    if (card) card.style.display = 'block';
    document.getElementById('smoke-no-data').style.display = 'none';
    if (canvas) canvas.style.display = 'block';

    const opts = timeChartOpts('ms', v => v + ' ms', ctx => ctx.dataset.yAxisID === 'y1'
        ? (+ctx.parsed.y).toFixed(1) + ' lost' : (+ctx.parsed.y).toFixed(2) + ' ms');
    opts.scales.y1 = { type:'linear', position:'right', min:0, grid:{ drawOnChartArea:false },
        ticks:{ color:'#a55', callback:v=>v } };

    makeChart('chart-smoke', 'line', {
        labels: r.times,
        datasets: [
            { label:'RTT (ms)', data:r.rtt, yAxisID:'y',
              borderColor:'#0db7ed', backgroundColor:ctx=>mkGradient(ctx.chart.ctx,'#0db7ed'),
              borderWidth:2, pointRadius:0, tension:0.35, fill:true, spanGaps:false },
            { label:'Loss (pings)', data:r.loss, yAxisID:'y1',
              borderColor:'#e74c3c', backgroundColor:'rgba(231,76,60,0.08)',
              borderWidth:1, pointRadius:0, tension:0.2, fill:true, stepped:true },
        ]
    }, opts);

    const s = r.summary || {};
    const el = (id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v;};
    el('ssum-avg',    s.avg_lat!=null ? (+s.avg_lat).toFixed(2)+' ms' : '—');
    el('ssum-minmax', (s.min_lat!=null?(+s.min_lat).toFixed(1):'—')+' / '+(s.max_lat!=null?(+s.max_lat).toFixed(1):'—')+' ms');
    el('ssum-loss',   (s.avg_loss!=null?(+s.avg_loss).toFixed(1):'—')+' / '+(s.max_loss!=null?(+s.max_loss).toFixed(0):'—'));
    el('ssum-n',      s.n!=null ? s.n : '—');
}

// ─── Load everything for current state ────────────────────────────────────────
async function loadAll() {
    applyNodeMode();
    loadSmokeChart();   // independent of node type — shows only if the node has Smokeping data
    if (isPingNode(_nodeId)) {
        await Promise.all([ loadPingChart(), checkPollerStatus() ]);
        return;
    }
    await Promise.all([
        loadSummary(),
        loadTrafficChart(),
        loadMetricChart('cpu',         'chart-cpu',  'cpu-no-data',  'cpu-loading',  2, v => v.toFixed(1)+'%', true),
        loadMetricChart('memory',      'chart-mem',  'mem-no-data',  'mem-loading',  3, v => v.toFixed(1)+'%', true),
        loadMetricChart('storage',     'chart-disk', 'disk-no-data', 'disk-loading', 4, v => v.toFixed(1)+'%'),
        loadMetricChart('temperature', 'chart-temp', 'temp-no-data', 'temp-loading', 5, v => (+v).toFixed(1)+'°C'),
        loadCustomSensors(),
        loadGpuCard(),
        checkPollerStatus(),
    ]);
}

// ─── "Poll now": force a fresh poll of the selected node, then reload charts ───
async function statsPollNow(btn) {
    if (!_nodeId) { return; }
    if (!btn || btn.disabled) return;
    const lbl  = btn.querySelector('.pn-lbl');
    const icon = btn.querySelector('i');
    const orig = lbl ? lbl.textContent : '';
    btn.disabled = true; btn.style.opacity = '.75';
    if (icon) icon.classList.add('fa-spin');
    if (lbl)  lbl.textContent = 'Polling…';
    try {
        const r = await fetch('net_mon_stats.php?api=poll_now&node_id=' + encodeURIComponent(_nodeId) + '&_t=' + Date.now(), {credentials:'same-origin'});
        const d = await r.json().catch(()=>null);
        if (d && d.ok) {
            if (lbl) lbl.textContent = 'Loading data…';
            await loadAll();
            const map = { up:['● UP','#2ecc71'], degraded:['⚠ REACHABLE · SNMP STALE','#f39c12'], down:['● DOWN','#e74c3c'] };
            const m = map[d.state] || ['Updated','#4da3ff'];
            if (lbl) lbl.textContent = m[0];
            btn.style.color = m[1]; btn.style.borderColor = m[1];
            btn.title = (d.detail || '') + (d.state==='degraded' ? ' — device answers ping; only SNMP/telemetry is stale (not down).' : '');
        } else {
            if (lbl) lbl.textContent = 'Failed';
        }
    } catch(e) {
        if (lbl) lbl.textContent = 'Failed';
    } finally {
        if (icon) icon.classList.remove('fa-spin');
        setTimeout(() => { btn.disabled = false; btn.style.opacity = ''; btn.style.color=''; btn.style.borderColor=''; if (lbl) lbl.textContent = orig; }, 3200);
    }
}

// ─── GPU telemetry card (shown only for nodes registered as a GPU target) ─────
async function loadGpuCard() {
    const card = document.getElementById('gpu-card'); if (!card) return;
    if (!_nodeId) { card.style.display = 'none'; return; }
    const r = await fetchApi(buildUrl('gpu_stats', { node_id: _nodeId }));
    if (!r || !r.has_gpu) { card.style.display = 'none'; return; }
    const e = s => (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
    const mb = v => { v=+v||0; return v>=1024?(v/1024).toFixed(1)+'GB':v+'MB'; };
    card.style.display = 'block';
    document.getElementById('gpu-link').href = 'gpu.php?target=' + r.target_id;
    const live = (r.gpus||[]).map(g => { const s=g.latest||{}; const mp=s.mem_total_mb>0?Math.round(100*s.mem_used_mb/s.mem_total_mb):'—';
        return `${e(g.name||('GPU'+g.gpu_index))}: ${Math.round(s.util_pct||0)}% util · ${mp}% VRAM${s.temp_c!=null?' · '+Math.round(s.temp_c)+'°C':''}`; }).join('   |   ');
    document.getElementById('gpu-live').textContent = live;
    const mods = r.models||[];
    document.getElementById('gpu-models').innerHTML = mods.length
        ? ('<span style="font-size:11px;color:#8a909a;">Loaded model(s): </span>'+mods.map(m=>`<span style="font-size:11px;background:rgba(118,185,0,.14);border:1px solid rgba(118,185,0,.3);color:#cfe9a3;border-radius:12px;padding:2px 9px;margin-right:5px;">${e(m.name)}${m.vram_mb?' ('+mb(m.vram_mb)+')':''}</span>`).join(''))
        : '';
    const opts = timeChartOpts('', v=>v, ctx=>ctx.parsed.y);
    if (!r.times || !r.times.length) { makeChart('chart-gpu','line',{labels:[],datasets:[]},opts); return; }
    const labels = r.times.map(ts => window.nmAxisTs ? nmAxisTs(ts) : ts);
    const ds = [
        {label:'GPU util %', data:r.util, borderColor:'#76b900', backgroundColor:ctx=>mkGradient(ctx.chart.ctx,'#76b900'), borderWidth:1.5, pointRadius:0, tension:0.4, fill:true, spanGaps:true},
        {label:'VRAM %',     data:r.vram, borderColor:'#4da3ff', borderWidth:1.3, pointRadius:0, tension:0.4, fill:false, spanGaps:true},
        {label:'Temp °C',    data:r.temp, borderColor:'#f39c12', borderWidth:1.3, pointRadius:0, tension:0.4, fill:false, spanGaps:true},
    ];
    makeChart('chart-gpu','line',{labels,datasets:ds},opts);
}

// ─── Navigation ───────────────────────────────────────────────────────────────
function togglePorts(nid, e) {
    e.stopPropagation();
    const grp = document.getElementById('ng-' + nid);
    if (grp) grp.classList.toggle('open');
}

function selectNode(nid) {
    _nodeId = nid;
    _portId = 0;
    const node = NODES.find(n => n.node_id === nid);
    if (node && node.ports.length) _portId = node.ports[0].port_id;

    // Update sidebar active states
    document.querySelectorAll('.node-item').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.port-item').forEach(el => el.classList.remove('active'));
    const nodeEl = document.querySelector(`[onclick="selectNode(${nid})"]`);
    if (nodeEl) nodeEl.classList.add('active');
    if (_portId) {
        const portEl = document.getElementById('pi-'+_portId);
        if (portEl) portEl.classList.add('active');
    }

    // Auto-expand selected device's port list
    document.querySelectorAll('.node-group').forEach(g => g.classList.remove('open'));
    const grp = document.getElementById('ng-' + nid);
    if (grp) grp.classList.add('open');

    // Update header label
    if (node) document.getElementById('current-device-name').textContent = node.name;
    updatePortLabel();
    history.replaceState(null,'',`net_mon_stats.php?node=${_nodeId}&port=${_portId}&range=${_range}`);
    loadAll();
}

function selectPort(nid, pid) {
    if (nid !== _nodeId) selectNode(nid);
    _portId = pid;
    document.querySelectorAll('.port-item').forEach(el => el.classList.remove('active'));
    const el = document.getElementById('pi-'+pid);
    if (el) el.classList.add('active');
    updatePortLabel();

    // Update port summary pill
    const node = NODES.find(n => n.node_id === nid);
    const port = node?.ports.find(p => p.port_id === pid);
    if (port) {
        document.getElementById('sum-port-name').textContent  = port.name;
        document.getElementById('sum-port-speed').textContent = 'Selected for monitoring';
    }
    history.replaceState(null,'',`net_mon_stats.php?node=${_nodeId}&port=${_portId}&range=${_range}`);
    loadTrafficChart();
}

function updatePortLabel() {
    const node = NODES.find(n => n.node_id === _nodeId);
    const port = node?.ports.find(p => p.port_id === _portId);
    document.getElementById('chart-port-label').textContent = port ? port.name : 'Select a port';
}

// ─── Range controls ───────────────────────────────────────────────────────────
function setRange(r) {
    _range  = r;
    _fromDt = '';
    _toDt   = '';
    document.querySelectorAll('.range-btn').forEach(b => {
        b.classList.toggle('active', b.textContent.trim().toLowerCase() === r.toLowerCase() ||
                            b.getAttribute('onclick') === `setRange('${r}')`);
    });
    history.replaceState(null,'',`net_mon_stats.php?node=${_nodeId}&port=${_portId}&range=${_range}`);
    loadAll();
}

function applyCustomRange() {
    const f = document.getElementById('date-from').value;
    const t = document.getElementById('date-to').value;
    if (!f || !t) { alert('Select both From and To dates'); return; }
    if (f > t)    { alert('From date must be before To date'); return; }
    _fromDt = f;
    _toDt   = t;
    document.querySelectorAll('.range-btn[onclick^="setRange"]').forEach(b => b.classList.remove('active'));
    loadAll();
}

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    updatePortLabel();
    if (_nodeId) loadAll();

    // Restore date inputs if we have custom range
    if (_fromDt) document.getElementById('date-from').value = _fromDt.split(' ')[0];
    if (_toDt)   document.getElementById('date-to').value   = _toDt.split(' ')[0];

    // Set initial port label in summary
    const node = NODES.find(n => n.node_id === _nodeId);
    const port = node?.ports.find(p => p.port_id === _portId);
    if (port) {
        document.getElementById('sum-port-name').textContent  = port.name;
        document.getElementById('sum-port-speed').textContent = 'Selected for monitoring';
    }
});
</script>
</body>
</html>
