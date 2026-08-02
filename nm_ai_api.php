<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — AI READ API. Token-guarded, read-only data access for n8n AI flows so
// they never need raw DB credentials. Machine-to-machine: authenticated by the
// shared inbound token in the `X-NetMon-Token` header (same token as the ingest
// endpoint; generate/rotate in Config → Integrations & AI).
//
//   GET nm_ai_api.php?resource=<r>&...   (header: X-NetMon-Token: <token>)
//
// Resources:
//   nodes                                  → inventory (incl. gateway/subnet for topology)
//   topology                               → nodes + nm_links + gateway edges (for blast-radius)
//   metrics?node_id=&type=&range=          → nm_device_stats timeseries (cpu/memory/…)
//   ports?node_id=&range=                  → nm_port_stats timeseries (in/out rates)
//   ping?node_id=&range=                   → nm_ping_stats timeseries
//   logs?node_id=&range=&q=&level=         → Graylog search for a device
//   insights?status=&severity=             → current nm_ai_insights
//
// range tokens: 15m,1h,6h,24h,7d,14d,30d (default 24h). Or explicit from=&to= (Y-m-d H:i:s).
// ─────────────────────────────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
date_default_timezone_set('America/Puerto_Rico');

require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/nm_n8n.php';
require_once __DIR__ . '/nm_graylog.php';

// ── AuthN ─────────────────────────────────────────────────────────────────────
$hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
if (!nm_n8n_verify_inbound($conn, $hdr)) {
    http_response_code(401);
    echo json_encode(['ok'=>false,'err'=>'Unauthorized — bad or missing X-NetMon-Token']);
    exit;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function range_window(): array {
    // Returns [from, to] as 'Y-m-d H:i:s'. Explicit from/to win; else range token.
    $to = $_GET['to'] ?? date('Y-m-d H:i:s');
    if (!empty($_GET['from'])) return [substr($_GET['from'],0,19), substr($to,0,19)];
    $map = ['15m'=>900,'1h'=>3600,'6h'=>21600,'24h'=>86400,'7d'=>604800,'14d'=>1209600,'30d'=>2592000];
    $sec = $map[$_GET['range'] ?? '24h'] ?? 86400;
    return [date('Y-m-d H:i:s', time() - $sec), date('Y-m-d H:i:s')];
}
$node_id = (int)($_GET['node_id'] ?? 0);
$resource = $_GET['resource'] ?? '';

// ── Resources ─────────────────────────────────────────────────────────────────
switch ($resource) {

    case 'nodes': {
        $r = $conn->query("SELECT n.id, n.display_name name, n.ip_address ip, n.os_icon,
                                  COALESCE(n.monitor_type,'snmp') monitor_type,
                                  n.subnet_mask, n.gateway_node_id, n.gateway_iface_id,
                                  COALESCE(n.graylog_source,'') graylog_source,
                                  g.name grp
                           FROM nm_nodes n LEFT JOIN nm_groups g ON g.id=n.group_id
                           ORDER BY n.id");
        echo json_encode(['ok'=>true,'nodes'=>$r?$r->fetch_all(MYSQLI_ASSOC):[]]);
        break;
    }

    case 'topology': {
        $nodes = $conn->query("SELECT id, display_name name, ip_address ip, os_icon,
                                      COALESCE(monitor_type,'snmp') monitor_type,
                                      subnet_mask, gateway_node_id
                               FROM nm_nodes ORDER BY id")->fetch_all(MYSQLI_ASSOC);
        $links = $conn->query("SELECT a_node_id, a_iface_id, z_node_id, z_iface_id, traffic_side, label
                               FROM nm_links WHERE enabled=1")->fetch_all(MYSQLI_ASSOC);
        // gateway edges (explicit per-node uplinks) help blast-radius find the origin
        $gw = [];
        foreach ($nodes as $n) if (!empty($n['gateway_node_id'])) $gw[] = ['node_id'=>(int)$n['id'],'gateway_node_id'=>(int)$n['gateway_node_id']];
        // interface IPs (subnet inference)
        $ifaces = $conn->query("SELECT node_id, id iface_id, if_name, display_name, if_ip_address
                                FROM nm_interfaces WHERE if_ip_address IS NOT NULL AND if_ip_address<>''")->fetch_all(MYSQLI_ASSOC);
        echo json_encode(['ok'=>true,'nodes'=>$nodes,'links'=>$links,'gateways'=>$gw,'interfaces'=>$ifaces]);
        break;
    }

    case 'metrics': {
        if (!$node_id) { echo json_encode(['ok'=>false,'err'=>'node_id required']); break; }
        [$from,$to] = range_window();
        $type = preg_replace('/[^a-z_]/','', strtolower($_GET['type'] ?? ''));   // cpu|memory|storage|temperature|custom|uptime
        $typeClause = $type !== '' ? "AND metric_type='".$conn->real_escape_string($type)."'" : '';
        $st = $conn->prepare("SELECT recorded_at, metric_type, metric_key, value, raw_value
                              FROM nm_device_stats
                              WHERE node_id=? AND recorded_at BETWEEN ? AND ? {$typeClause}
                              ORDER BY recorded_at");
        $st->bind_param('iss', $node_id, $from, $to); $st->execute();
        echo json_encode(['ok'=>true,'from'=>$from,'to'=>$to,'series'=>$st->get_result()->fetch_all(MYSQLI_ASSOC)]);
        break;
    }

    case 'ports': {
        if (!$node_id) { echo json_encode(['ok'=>false,'err'=>'node_id required']); break; }
        [$from,$to] = range_window();
        $st = $conn->prepare("SELECT ps.recorded_at, ps.port_id, i.if_name, i.display_name iname,
                                     ps.in_rate, ps.out_rate, ps.in_util, ps.out_util, ps.oper_status, ps.if_speed
                              FROM nm_port_stats ps JOIN nm_interfaces i ON i.id=ps.port_id
                              WHERE ps.node_id=? AND ps.recorded_at BETWEEN ? AND ?
                              ORDER BY ps.port_id, ps.recorded_at");
        $st->bind_param('iss', $node_id, $from, $to); $st->execute();
        echo json_encode(['ok'=>true,'from'=>$from,'to'=>$to,'series'=>$st->get_result()->fetch_all(MYSQLI_ASSOC)]);
        break;
    }

    case 'ping': {
        if (!$node_id) { echo json_encode(['ok'=>false,'err'=>'node_id required']); break; }
        [$from,$to] = range_window();
        $st = $conn->prepare("SELECT recorded_at, is_up, latency_ms, packet_loss
                              FROM nm_ping_stats WHERE node_id=? AND recorded_at BETWEEN ? AND ?
                              ORDER BY recorded_at");
        $st->bind_param('iss', $node_id, $from, $to); $st->execute();
        echo json_encode(['ok'=>true,'from'=>$from,'to'=>$to,'series'=>$st->get_result()->fetch_all(MYSQLI_ASSOC)]);
        break;
    }

    case 'logs': {
        if (!$node_id) { echo json_encode(['ok'=>false,'err'=>'node_id required']); break; }
        $cfg = nm_graylog_get($conn);
        if (empty($cfg['enabled'])) { echo json_encode(['ok'=>false,'err'=>'Graylog disabled']); break; }
        $nr = $conn->query("SELECT id, display_name, ip_address, COALESCE(graylog_source,'') graylog_source
                            FROM nm_nodes WHERE id={$node_id} LIMIT 1");
        $node = $nr ? $nr->fetch_assoc() : null;
        if (!$node) { echo json_encode(['ok'=>false,'err'=>'Unknown node']); break; }
        $rangeMap = ['15m'=>900,'1h'=>3600,'6h'=>21600,'24h'=>86400,'7d'=>604800];
        $sec = $rangeMap[$_GET['range'] ?? '1h'] ?? 3600;
        $query = nm_graylog_source_query($node);
        $q = trim($_GET['q'] ?? ''); if ($q !== '') $query .= ' AND message:' . json_encode($q);
        $lvlMap = ['err'=>3,'warn'=>4,'info'=>6]; $lvl = $_GET['level'] ?? 'all';
        if (isset($lvlMap[$lvl])) $query .= ' AND level:<=' . $lvlMap[$lvl];
        [$code,$res,$err] = nm_graylog_search($cfg, $query, $sec, (int)($_GET['limit'] ?? 200));
        if ($err) { echo json_encode(['ok'=>false,'err'=>$err,'code'=>$code]); break; }
        echo json_encode(['ok'=>true,'query'=>$query,'total'=>$res['total'],'messages'=>$res['messages']]);
        break;
    }

    case 'baselines': {
        // Learned "normal" bands (per node+metric+hour-of-week). The detect flow reads
        // the row for the current hour_of_week and compares the latest reading.
        $where = [];
        if ($node_id) $where[] = "node_id={$node_id}";
        foreach (['metric_type','metric_key'] as $f) {
            if (isset($_GET[$f]) && $_GET[$f] !== '') $where[] = "{$f}='".$conn->real_escape_string($_GET[$f])."'";
        }
        if (isset($_GET['hour_of_week']) && $_GET['hour_of_week'] !== '')
            $where[] = "hour_of_week=" . (int)$_GET['hour_of_week'];
        $w = $where ? ('WHERE '.implode(' AND ',$where)) : '';
        $r = $conn->query("SELECT node_id,metric_type,metric_key,hour_of_week,mean,stdev,samples,updated_at
                           FROM nm_ai_baselines {$w} ORDER BY node_id,metric_type,metric_key,hour_of_week");
        echo json_encode(['ok'=>true,'baselines'=>$r?$r->fetch_all(MYSQLI_ASSOC):[]]);
        break;
    }

    case 'insights': {
        $where = [];
        $status = $_GET['status'] ?? 'active';
        if ($status === 'active')  $where[] = "status IN ('open','acknowledged','suppressed')";
        elseif ($status !== 'all') $where[] = "status='".$conn->real_escape_string($status)."'";
        $sev = $_GET['severity'] ?? 'all';
        if (in_array($sev,['critical','warning','info'],true)) $where[] = "severity='".$conn->real_escape_string($sev)."'";
        if ($node_id) $where[] = "node_id={$node_id}";
        $w = $where ? ('WHERE '.implode(' AND ',$where)) : '';
        $r = $conn->query("SELECT id,node_id,kind,severity,title,body,data,source,status,correlation_key,created_at
                           FROM nm_ai_insights {$w} ORDER BY created_at DESC LIMIT 500");
        echo json_encode(['ok'=>true,'insights'=>$r?$r->fetch_all(MYSQLI_ASSOC):[]]);
        break;
    }

    default:
        echo json_encode(['ok'=>false,'err'=>'Unknown resource',
            'resources'=>['nodes','topology','metrics','ports','ping','logs','insights']]);
}
