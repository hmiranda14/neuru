<?php
// ─── Realtime API: live SNMP counter delta → instantaneous per-interface rates (bytes/s) ──
// Same engine as traffic_viewer's realtime (nm_rt_sample.py + nm_rt_samples), so the map's
// "⚡ Real-Time" mode gets true ~2s live traffic instead of the 2-min cron snapshot.
if (isset($_GET['api']) && $_GET['api'] === 'rt') {
    header('Content-Type: application/json; charset=utf-8');
    if (session_status() === PHP_SESSION_NONE) session_start();
    if (empty($_SESSION['username'])) { echo json_encode(['err'=>'Unauthorized']); exit; }
    include_once('connection.php');
    if (function_exists('session_write_close')) @session_write_close();
    try { $conn->query("CREATE TABLE IF NOT EXISTS nm_rt_samples (pid INT PRIMARY KEY, in_oct BIGINT UNSIGNED, out_oct BIGINT UNSIGNED,
        ie BIGINT UNSIGNED, oe BIGINT UNSIGNED, idc BIGINT UNSIGNED, odc BIGINT UNSIGNED, ts DOUBLE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); } catch (\Throwable $e) {}
    $pids = array_slice(array_values(array_filter(array_map('intval', explode(',', (string)($_GET['pids'] ?? ''))))), 0, 64);
    if (!$pids) { echo json_encode(['ok'=>true,'rt'=>[]]); exit; }
    $inList = implode(',', $pids);
    $targets = [];
    if ($r = $conn->query("SELECT i.id pid, n.ip_address ip, n.snmp_community comm, n.snmp_version ver, i.if_index idx
                           FROM nm_interfaces i JOIN nm_nodes n ON n.id=i.node_id
                           WHERE i.id IN ($inList) AND i.if_index>0 AND COALESCE(n.snmp_community,'')<>'' AND n.snmp_version IN('v1','v2c')")) {
        while ($x = $r->fetch_assoc()) $targets[] = ['pid'=>(int)$x['pid'],'ip'=>$x['ip'],'comm'=>$x['comm'],'ver'=>$x['ver'],'idx'=>(int)$x['idx']];
    }
    if (!$targets) { echo json_encode(['ok'=>true,'rt'=>[],'note'=>'no SNMP v1/v2c interfaces']); exit; }
    $py = is_file('/opt/netmon-venv/bin/python3') ? '/opt/netmon-venv/bin/python3' : 'python3';
    $cur = []; $spec = [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];
    if (function_exists('proc_open') && ($proc = @proc_open([$py, __DIR__.'/scripts/nm_rt_sample.py'], $spec, $pipes))) {
        fwrite($pipes[0], json_encode(['targets'=>$targets])); fclose($pipes[0]);
        $o = stream_get_contents($pipes[1]); fclose($pipes[1]); @fclose($pipes[2]); @proc_close($proc);
        $cur = json_decode((string)$o, true) ?: [];
    }
    $prev = [];
    if ($pr = $conn->query("SELECT * FROM nm_rt_samples WHERE pid IN ($inList)")) while ($x=$pr->fetch_assoc()) $prev[(int)$x['pid']] = $x;
    $now = microtime(true); $rt = [];
    $up = $conn->prepare("INSERT INTO nm_rt_samples (pid,in_oct,out_oct,ie,oe,idc,odc,ts) VALUES (?,?,?,?,?,?,?,?)
        ON DUPLICATE KEY UPDATE in_oct=VALUES(in_oct),out_oct=VALUES(out_oct),ie=VALUES(ie),oe=VALUES(oe),idc=VALUES(idc),odc=VALUES(odc),ts=VALUES(ts)");
    foreach ($cur as $pidS=>$c) {
        $pid=(int)$pidS; if (empty($c['ok'])) continue;
        $p=$prev[$pid]??null; $dt=$p?($now-(float)$p['ts']):0;
        if ($p && $dt>0.15 && $dt<30) {
            $din=(float)$c['in']-(float)$p['in_oct']; $dout=(float)$c['out']-(float)$p['out_oct'];
            $rt[$pid]=['in'=>$din>=0?round($din/$dt):null, 'out'=>$dout>=0?round($dout/$dt):null];   // bytes/s (matches the map)
        }
        $up->bind_param('iddddddd', $pid, $c['in'],$c['out'],$c['ie'],$c['oe'],$c['id'],$c['od'], $now);
        try { $up->execute(); } catch (\Throwable $e) {}
    }
    echo json_encode(['ok'=>true,'rt'=>$rt]);
    exit;
}

// ─── API: topology + live data ────────────────────────────────────────────────
if (isset($_GET['api']) && $_GET['api'] === 'topo') {
    header('Content-Type: application/json; charset=utf-8');
    if (session_status() === PHP_SESSION_NONE) session_start();
    if (empty($_SESSION['username'])) { echo json_encode(['err'=>'Unauthorized']); exit; }
    include_once('connection.php');
    // Release the session lock before the heavy topology queries — this endpoint is polled every
    // few seconds (map, command center, hologram) and holding the lock serialises every other
    // request from the same user (e.g. the hologram node-dossier fetch would block behind it).
    if (function_exists('session_write_close')) @session_write_close();

    // All nodes with group info
    $nodes_raw = [];
    $nr = $conn->query("
        SELECT n.id, n.display_name name, n.ip_address ip, n.os_icon icon,
               COALESCE(n.subnet_mask,'/24') subnet,
               n.gateway_node_id, n.gateway_iface_id, COALESCE(n.monitor_type,'snmp') monitor_type,
               COALESCE(g.name,'OTHER') grp,
               COALESCE(g.color,'#4da3ff') grp_color
        FROM nm_nodes n
        LEFT JOIN nm_groups g ON g.id = n.group_id
        ORDER BY n.sort_order, n.id
    ");
    while ($r = $nr->fetch_assoc()) $nodes_raw[] = $r;

    // Latest device stats per node (cpu, memory, uptime) — metric_key-agnostic so
    // any OID template works (MikroTik 'avg'/'main memory', Cisco 'CPU Utilization', …)
    $stats_raw = [];
    $sr = $conn->query("
        SELECT s.node_id, s.metric_type, s.metric_key, s.value
        FROM nm_device_stats s
        INNER JOIN (
            SELECT node_id, metric_type, MAX(recorded_at) max_ts
            FROM nm_device_stats
            WHERE metric_type IN ('cpu','memory','uptime')
            GROUP BY node_id, metric_type
        ) lx ON s.node_id=lx.node_id AND s.metric_type=lx.metric_type AND s.recorded_at=lx.max_ts
        ORDER BY s.node_id, s.metric_type
    ");
    while ($r = $sr->fetch_assoc()) {
        $stats_raw[(int)$r['node_id']][$r['metric_type']][] = ['k' => $r['metric_key'], 'v' => (float)$r['value']];
    }
    $stats = [];
    foreach ($stats_raw as $nid => $byType) {
        if (!empty($byType['cpu'])) {                       // prefer 'avg', else mean of rows
            $avg = null;
            foreach ($byType['cpu'] as $row) if ($row['k'] === 'avg') { $avg = $row['v']; break; }
            if ($avg === null) { $vals = array_column($byType['cpu'], 'v'); $avg = $vals ? array_sum($vals) / count($vals) : null; }
            $stats[$nid]['cpu'] = $avg;
        }
        if (!empty($byType['memory'])) $stats[$nid]['memory'] = max(array_column($byType['memory'], 'v'));
        if (!empty($byType['uptime'])) {
            $u = null;
            foreach ($byType['uptime'] as $row) if ($row['k'] === 'seconds') { $u = $row['v']; break; }
            $stats[$nid]['uptime'] = $u ?? $byType['uptime'][0]['v'];
        }
    }

    // Latest port stats per node
    $ports = [];
    $pr = $conn->query("
        SELECT ps.node_id, ps.port_id, ps.in_rate, ps.out_rate, ps.oper_status,
               i.if_name, i.display_name iname, i.if_ip_address
        FROM nm_port_stats ps
        JOIN nm_interfaces i ON i.id=ps.port_id AND i.node_id=ps.node_id
        INNER JOIN (
            SELECT node_id, port_id, MAX(recorded_at) max_ts
            FROM nm_port_stats GROUP BY node_id, port_id
        ) lp ON ps.node_id=lp.node_id AND ps.port_id=lp.port_id AND ps.recorded_at=lp.max_ts
        ORDER BY ps.node_id, i.sort_order
    ");
    while ($r = $pr->fetch_assoc()) {
        $nid = (int)$r['node_id'];
        $pid = (int)$r['port_id'];
        if (!isset($ports[$nid][$pid])) $ports[$nid][$pid] = $r;
    }

    // Latest ping result per ping-only node (for status + latency on the map)
    $ping_latest = [];
    $pl = $conn->query("
        SELECT ps.node_id, ps.is_up, ps.latency_ms, ps.recorded_at,
               TIMESTAMPDIFF(SECOND, ps.recorded_at, NOW()) age
        FROM nm_ping_stats ps
        INNER JOIN (SELECT node_id, MAX(id) mid FROM nm_ping_stats GROUP BY node_id) lx
          ON ps.node_id = lx.node_id AND ps.id = lx.mid
    ");
    if ($pl) while ($r = $pl->fetch_assoc()) $ping_latest[(int)$r['node_id']] = $r;

    // Authoritative per-node verdict from the alert engine (handles ICMP-filtered Windows
    // hosts, frozen iface oper, etc.). When present it OVERRIDES the port/ping-derived guess.
    $NM_STATE = [];
    $asr = $conn->query("SELECT node_id, last_status FROM nm_alert_state WHERE entity_type='node'");
    if ($asr) while ($r = $asr->fetch_assoc()) $NM_STATE[(int)$r['node_id']] = $r['last_status'];

    // Build node objects
    $nodes = [];
    foreach ($nodes_raw as $n) {
        $nid  = (int)$n['id'];
        $np   = array_values($ports[$nid] ?? []);
        $t_in = array_sum(array_column($np, 'in_rate'));
        $t_out= array_sum(array_column($np, 'out_rate'));
        $any_up = false;
        foreach ($np as $p) if (strtolower($p['oper_status']) === 'up') { $any_up = true; break; }

        // Status: ping-only nodes come from nm_ping_stats; SNMP nodes from port oper.
        $is_ping  = ($n['monitor_type'] ?? 'snmp') === 'ping';
        $ping_lat = null;
        if ($is_ping) {
            $pp = $ping_latest[$nid] ?? null;
            $fresh = $pp && (int)$pp['age'] <= 600;
            $status = ($pp && (int)$pp['is_up'] === 1 && $fresh) ? 'up' : ($pp ? 'down' : 'unknown');
            if ($pp) $ping_lat = $pp['latency_ms'];
        } else {
            $status = empty($np) ? 'unknown' : ($any_up ? 'up' : 'down');
        }

        // The alert engine is authoritative when it has tracked this node — trust it over a
        // frozen/oper-down port or an ICMP-filtered Windows box (fixes false "down" on AI-SERVER).
        $as = $NM_STATE[$nid] ?? null;
        if ($as !== null) {
            if (in_array($as, ['down','lowerlayerdown','notpresent','testing'], true)) $status = 'down';
            elseif ($as === 'degraded') $status = 'degraded';   // reachable, telemetry stale
            else $status = 'up';
        }

        $ip    = $n['ip'] ?? '';
        $mask  = (int)ltrim($n['subnet'], '/');
        $parts = explode('.', $ip);
        $net_key = ($mask >= 24 && count($parts) === 4)
            ? "{$parts[0]}.{$parts[1]}.{$parts[2]}.0{$n['subnet']}"
            : $ip.$n['subnet'];

        $nodes[] = [
            'id'        => $nid,
            'name'      => $n['name'],
            'ip'        => $ip,
            'subnet'    => $n['subnet'],
            'net_key'   => $net_key,
            'icon'      => $n['icon'],
            'grp'       => $n['grp'],
            'grp_color' => $n['grp_color'],
            'status'    => $status,
            'is_ping'   => $is_ping,
            'latency'   => $ping_lat,
            // cast to real numbers — mysqli returns numeric columns as STRINGS, and a JSON string
            // has no .toFixed() in JS, which threw in showDetail() and left the detail panel blank
            // for any node that had CPU/RAM stats (looked "random"; ping-only nodes were null→safe).
            'cpu'       => isset($stats[$nid]['cpu'])    ? (float)$stats[$nid]['cpu']    : null,
            'memory'    => isset($stats[$nid]['memory']) ? (float)$stats[$nid]['memory'] : null,
            'uptime'    => isset($stats[$nid]['uptime']) ? (float)$stats[$nid]['uptime'] : null,
            'total_in'  => $t_in,
            'total_out' => $t_out,
            'gateway'   => (int)($n['gateway_node_id'] ?? 0),
            'gateway_if'=> (int)($n['gateway_iface_id'] ?? 0),
            'ports'     => $np,
        ];
    }

    // Fetch interface IPs for multi-subnet router support, plus an id→{name,ip} map
    // (all monitored interfaces, even those without stats/IP) for manual-link labels.
    $iface_subnets = [];
    $ifmeta = [];
    $ir = $conn->query("
        SELECT i.id, i.node_id, i.if_name, i.display_name, i.if_ip_address
        FROM nm_interfaces i WHERE i.show_graph = 1 OR i.is_dummy = 1
    ");
    if ($ir) while ($r = $ir->fetch_assoc()) {
        $nid  = (int)$r['node_id'];
        $ifip = $r['if_ip_address'];
        $ifmeta[$nid][(int)$r['id']] = ['name' => $r['display_name'] ?: $r['if_name'], 'ip' => $ifip ?: ''];
        if ($ifip) {
            $ifpts = explode('.', $ifip);
            if (count($ifpts) === 4) {
                $iface_subnets[$nid][] = "{$ifpts[0]}.{$ifpts[1]}.{$ifpts[2]}.0/24";
            }
        }
    }

    // Infer topology links — each node joins its primary subnet; routers also join interface subnets
    $subnet_groups = [];
    foreach ($nodes as $n) {
        $nid = $n['id'];
        $subnet_groups[$n['net_key']][] = $nid;
        foreach ($iface_subnets[$nid] ?? [] as $ifkey) {
            if ($ifkey !== $n['net_key'] && !in_array($nid, $subnet_groups[$ifkey] ?? [])) {
                $subnet_groups[$ifkey][] = $nid;
            }
        }
    }

    // Resolve which interface on a node sits in a given /24 subnet (name+ip+rates).
    $find_iface = function ($node_id, $subnet24) use ($ports) {
        foreach ($ports[$node_id] ?? [] as $pid => $p) {
            $ip = $p['if_ip_address'] ?? '';
            if (!$ip) continue;
            $o = explode('.', $ip);
            if (count($o) === 4 && "{$o[0]}.{$o[1]}.{$o[2]}.0/24" === $subnet24) {
                return ['name' => $p['iname'] ?: $p['if_name'], 'ip' => $ip, 'pid' => (int)$pid,
                        'in_rate' => (float)$p['in_rate'], 'out_rate' => (float)$p['out_rate']];
            }
        }
        return null;
    };

    $links = [];
    $seen  = [];
    $node_ids_set = array_column($nodes, null, 'id');

    // User-suppressed auto connections (Config → Connections → Remove). Keyed by
    // normalised "min-max" node-id pair. Only auto links (gateway/subnet) honour
    // this; explicit nm_links are managed directly via their own delete.
    $hidden = [];
    $hr = $conn->query("SELECT a_node_id, z_node_id FROM nm_link_hidden");
    if ($hr) while ($h = $hr->fetch_assoc()) {
        $a = (int)$h['a_node_id']; $z = (int)$h['z_node_id'];
        $hidden[min($a,$z).'-'.max($a,$z)] = true;
    }

    // Resolve an interface (real or dummy) → {name, ip, in_rate, out_rate}.
    $resolve_if = function ($node_id, $iface_id) use ($ifmeta, $ports) {
        $iface_id = (int)$iface_id;
        if (!$iface_id) return null;
        $meta = $ifmeta[$node_id][$iface_id] ?? null;
        if (!$meta) return null;
        $rate = $ports[$node_id][$iface_id] ?? null;
        return ['name' => $meta['name'], 'ip' => $meta['ip'], 'pid' => $iface_id,
                'in_rate' => (float)($rate['in_rate'] ?? 0), 'out_rate' => (float)($rate['out_rate'] ?? 0)];
    };

    // ── Explicit connections (nm_links) — the richest, highest-precedence model.
    // Each end may pin an interface (real or dummy); traffic comes from the chosen
    // side's interface. Edited in Config → Connections. "The Dude"-style wiring.
    $lr = $conn->query("SELECT id,a_node_id,a_iface_id,z_node_id,z_iface_id,traffic_side,label FROM nm_links WHERE enabled=1");
    if ($lr) while ($lk = $lr->fetch_assoc()) {
        $a = (int)$lk['a_node_id']; $z = (int)$lk['z_node_id'];
        if ($a === $z || !isset($node_ids_set[$a]) || !isset($node_ids_set[$z])) continue;
        $a_if = $resolve_if($a, $lk['a_iface_id']);
        $z_if = $resolve_if($z, $lk['z_iface_id']);
        // Traffic from the chosen side's interface (else that node's totals).
        $tside = $lk['traffic_side'] === 'a' ? $a_if : $z_if;
        if ($tside) { $in = $tside['in_rate']; $out = $tside['out_rate']; }
        else {
            $sn = $lk['traffic_side'] === 'a' ? $a : $z;
            $np = array_values($ports[$sn] ?? []);
            $in = array_sum(array_column($np, 'in_rate')); $out = array_sum(array_column($np, 'out_rate'));
        }
        $pk = min($a,$z).'-'.max($a,$z);
        $seen[$pk] = true;
        $links[] = [
            'source' => $a, 'target' => $z, 'in_rate' => $in, 'out_rate' => $out,
            'subnet' => 'link', 'manual' => true, 'label' => $lk['label'] ?: null,
            'kind' => 'explicit', 'link_id' => (int)$lk['id'], 'pair' => $pk,
            'src_if' => $a_if ? ['name'=>$a_if['name'],'ip'=>$a_if['ip'],'pid'=>$a_if['pid']??null] : null,
            'tgt_if' => $z_if ? ['name'=>$z_if['name'],'ip'=>$z_if['ip'],'pid'=>$z_if['pid']??null] : null,
        ];
    }

    // Explicit user-defined links FIRST (they take precedence over auto inference):
    // node.gateway_node_id → target node, editable per node (Config → Edit node →
    // Gateway + Uplink Interface). Lets cross-subnet nodes (e.g. a ping/internet
    // check) be wired to an uplink, and pins the exact interface on the link.
    $node_ids_set = array_column($nodes, null, 'id');
    foreach ($nodes as $n) {
        $gw = (int)($n['gateway'] ?? 0);
        if (!$gw || $gw === $n['id'] || !isset($node_ids_set[$gw])) continue;
        $key = min($gw, $n['id']) . '-' . max($gw, $n['id']);
        if (isset($seen[$key])) continue;
        $seen[$key] = true;
        if (isset($hidden[$key])) continue;   // user removed this auto connection

        // Target-side uplink interface: the one the user picked (label even if it has
        // no IP/stats yet). Traffic from that interface when available.
        $tgt_if = null; $in = 0; $out = 0;
        $gwif = (int)($n['gateway_if'] ?? 0);
        if ($gwif && isset($ifmeta[$n['id']][$gwif])) {
            $m = $ifmeta[$n['id']][$gwif];
            $tgt_if = ['name' => $m['name'], 'ip' => $m['ip'], 'pid' => $gwif];
            if (isset($ports[$n['id']][$gwif])) {
                $in  = (float)$ports[$n['id']][$gwif]['in_rate'];
                $out = (float)$ports[$n['id']][$gwif]['out_rate'];
            }
        } else {
            // No explicit uplink picked → auto-resolve the target's interface in its
            // own subnet (same as auto links), else fall back to node totals.
            $auto = $find_iface($n['id'], $node_ids_set[$n['id']]['net_key'] ?? '');
            if ($auto) {
                $tgt_if = ['name' => $auto['name'], 'ip' => $auto['ip'], 'pid' => $auto['pid'] ?? null];
                $in = $auto['in_rate']; $out = $auto['out_rate'];
            } else {
                $np  = array_values($ports[$n['id']] ?? []);
                $in  = array_sum(array_column($np, 'in_rate'));
                $out = array_sum(array_column($np, 'out_rate'));
            }
        }
        // Gateway-side interface: the gateway's interface in the target's subnet.
        $src_if = $find_iface($gw, $node_ids_set[$n['id']]['net_key'] ?? '');

        $links[] = [
            'source'   => $gw,
            'target'   => $n['id'],
            'in_rate'  => $in,
            'out_rate' => $out,
            'subnet'   => 'manual',
            'manual'   => true,
            'kind'     => 'gateway',
            'pair'     => $key,
            'src_if'   => $src_if ? ['name' => $src_if['name'], 'ip' => $src_if['ip'], 'pid' => $src_if['pid'] ?? null] : null,
            'tgt_if'   => $tgt_if,
        ];
    }

    foreach ($subnet_groups as $net => $node_ids) {
        if (count($node_ids) < 2) continue;
        // Router = network gear icon (mikrotik/routeros/cisco), else lowest id
        $router_id = null;
        foreach ($nodes as $n) {
            if (in_array($n['id'], $node_ids) && in_array($n['icon'], ['routeros','mikrotik','cisco'], true))
                { $router_id = $n['id']; break; }
        }
        if (!$router_id) $router_id = min($node_ids);

        foreach ($node_ids as $nid) {
            if ($nid === $router_id) continue;
            $key = min($router_id,$nid).'-'.max($router_id,$nid);
            if (isset($seen[$key])) continue;
            $seen[$key] = true;
            if (isset($hidden[$key])) continue;   // user removed this auto connection

            // Connecting interface on each end (the one whose IP is in this subnet).
            $src_if = $find_iface($router_id, $net);
            $tgt_if = $find_iface($nid, $net);
            // Link traffic = the connecting interface with the most traffic (the
            // router side usually reports real counters; e.g. AireOS APs report 0).
            $in = 0; $out = 0;
            foreach (array_filter([$src_if, $tgt_if]) as $c) {
                if (($c['in_rate'] + $c['out_rate']) > ($in + $out)) { $in = $c['in_rate']; $out = $c['out_rate']; }
            }
            if (!$src_if && !$tgt_if) {   // fallback: target totals
                $np = array_values($ports[$nid] ?? []);
                $in = array_sum(array_column($np, 'in_rate'));
                $out = array_sum(array_column($np, 'out_rate'));
            }
            $links[] = [
                'source'   => $router_id,
                'target'   => $nid,
                'in_rate'  => $in,
                'out_rate' => $out,
                'subnet'   => $net,
                'kind'     => 'subnet',
                'pair'     => $key,
                'src_if'   => $src_if ? ['name' => $src_if['name'], 'ip' => $src_if['ip'], 'pid' => $src_if['pid'] ?? null] : null,
                'tgt_if'   => $tgt_if ? ['name' => $tgt_if['name'], 'ip' => $tgt_if['ip'], 'pid' => $tgt_if['pid'] ?? null] : null,
            ];
        }
    }

    echo json_encode(['nodes'=>$nodes,'links'=>$links,'ts'=>date('Y-m-d H:i:s')]);
    exit;
}

// ─── API: real-time poll-on-demand (Live mode) ────────────────────────────────
// Runs the actual ICMP + SNMP pollers NOW so the map reflects live data instead of
// the last cron snapshot. Each poller still writes nm_*_stats, so history keeps
// accumulating. `timeout` caps each so an unreachable device can't hang the request.
if (isset($_GET['api']) && $_GET['api'] === 'poll_now') {
    header('Content-Type: application/json; charset=utf-8');
    if (session_status() === PHP_SESSION_NONE) session_start();
    if (empty($_SESSION['username'])) { echo json_encode(['ok'=>false,'err'=>'Unauthorized']); exit; }
    require_once __DIR__ . '/nm_config.php';
    $py   = escapeshellarg(VENV_PYTHON);
    $ping = escapeshellarg(SCRIPTS_DIR . '/nm_ping.py');
    $snmp = escapeshellarg(SCRIPTS_DIR . '/nm_poller.py');
    $t0   = microtime(true);
    shell_exec("timeout 20 $py $ping 2>&1");
    shell_exec("timeout 75 $py $snmp 2>&1");
    echo json_encode(['ok'=>true, 'took'=>round(microtime(true)-$t0,1)]);
    exit;
}

// ─── Normal page load ────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
include('logger.php');
if (!checkAccess($conn,'net_mon')) { header("Location: /denied_access.php?page=net_mon_map"); exit; }

$videoFile = !empty($_SESSION['user_bgsite_video'])
    ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';

include('header.php');
log_user_action($conn, 'view_page', 'net_mon_map.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Map | SG-PR Console</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root {
    --glass:   rgba(255,255,255,0.07);
    --glass2:  rgba(255,255,255,0.04);
    --border:  rgba(255,255,255,0.12);
    --accent:  #4da3ff;
    --green:   #2ecc71;
    --yellow:  #f39c12;
    --red:     #e74c3c;
}
*{ box-sizing:border-box; margin:0; padding:0; }
#bg-video{ position:fixed;top:0;left:0;min-width:100%;min-height:100%;z-index:-1;object-fit:cover;opacity:.2; }
body{ background:#06080f; color:#e0e0e0; font-family:'Segoe UI',sans-serif; overflow:hidden; height:100vh; }

/* ── Layout ─────────────────────────────────────────────────────────────── */
#map-wrap{ display:flex; flex-direction:column; height:100vh; }
#map-wrap:fullscreen{ width:100vw; height:100vh; background:transparent; }
#map-wrap:fullscreen::backdrop{ background:#05080f; }

#map-toolbar{
    display:flex; align-items:center; gap:8px; padding:7px 16px;
    background:rgba(0,0,0,.75); border-bottom:1px solid var(--border);
    backdrop-filter:blur(12px); flex-shrink:0; z-index:10; flex-wrap:wrap;
}
.tb-title{ font-size:14px; font-weight:700; color:#e0e0e0; margin-right:6px; }
.tb-title i{ color:var(--accent); margin-right:6px; }
.tb-sep{ width:1px; height:20px; background:var(--border); margin:0 2px; }
.tb-btn{
    background:var(--glass); border:1px solid var(--border); color:#aaa;
    padding:4px 11px; border-radius:6px; cursor:pointer; font-size:12px;
    transition:.15s; display:inline-flex; align-items:center; gap:5px;
}
.tb-btn:hover{ background:rgba(77,163,255,.18); color:#fff; border-color:var(--accent); }
.tb-btn.on{ background:rgba(77,163,255,.22); color:var(--accent); border-color:var(--accent); }
#tb-countdown{ font-size:11px; color:#444; min-width:85px; }
#tb-ts{ font-size:10px; color:#444; margin-left:auto; }
#tb-stats{ font-size:10px; color:#555; display:flex; gap:10px; }
.tb-stat{ display:flex; align-items:center; gap:4px; }
.tb-stat-dot{ width:8px;height:8px;border-radius:50%; }

/* ── Canvas ─────────────────────────────────────────────────────────────── */
#map-canvas{ position:relative; flex:1; overflow:hidden; }
#map-svg{ width:100%; height:100%; cursor:grab; }
#map-svg:active{ cursor:grabbing; }

/* ── SVG elements ───────────────────────────────────────────────────────── */
.hull-path{
    fill:rgba(77,163,255,.04); stroke:rgba(77,163,255,.14);
    stroke-width:1.5; stroke-dasharray:6 4; pointer-events:none;
}
.hull-label{
    font-size:10px; fill:rgba(77,163,255,.35);
    font-family:'Segoe UI',sans-serif; pointer-events:none;
}
.link-base{ stroke:rgba(255,255,255,.13); fill:none; stroke-linecap:round; pointer-events:none; }
.link-flow-in{ fill:none; stroke:#4da3ff; stroke-dasharray:7 5; stroke-linecap:round; pointer-events:none; }
.link-flow-out{ fill:none; stroke:#2ecc71; stroke-dasharray:7 5; stroke-linecap:round; pointer-events:none; }
.link-lbl{
    font-size:9px; fill:#555; font-family:'Segoe UI',sans-serif;
    pointer-events:none; text-anchor:middle;
}
.link-if{
    font-size:8.5px; fill:#6b94c4; font-family:ui-monospace,Menlo,Consolas,monospace;
    pointer-events:none; text-anchor:middle;
}
.node-grp{ cursor:pointer; }
.node-icon{
    font-family:"Font Awesome 6 Free"; font-weight:900;
    text-anchor:middle; dominant-baseline:central;
    pointer-events:none;
}
.node-name-lbl{
    font-size:11px; font-weight:600; fill:#e0e0e0;
    text-anchor:middle; pointer-events:none; font-family:'Segoe UI',sans-serif;
}
.node-ip-lbl{
    font-size:9px; fill:#555;
    text-anchor:middle; pointer-events:none; font-family:'Segoe UI',sans-serif;
}
@keyframes pulse-ring{ 0%,100%{opacity:.7;r:attr(r)}  50%{opacity:.1} }
.status-pulse{ animation:blink 1.8s ease-in-out infinite; }
@keyframes blink{ 0%,100%{opacity:1} 50%{opacity:.35} }

/* ── Detail panel ───────────────────────────────────────────────────────── */
#detail-panel{
    position:absolute; right:0; top:0; bottom:0; width:290px;
    background:rgba(6,8,15,.94); border-left:1px solid var(--border);
    backdrop-filter:blur(20px); transform:translateX(100%);
    transition:transform .22s ease; z-index:20; overflow-y:auto; padding:18px 16px 24px;
}
#detail-panel.open{ transform:translateX(0); }
#dp-close{
    position:absolute; top:10px; right:12px;
    background:none; border:none; color:#444; cursor:pointer; font-size:15px;
}
#dp-close:hover{ color:#ccc; }
.dp-name{ font-size:15px; font-weight:700; line-height:1.2; margin-bottom:2px; }
.dp-ip{ font-size:11px; color:#555; margin-bottom:10px; }
.dp-badge{
    display:inline-flex; align-items:center; gap:5px;
    font-size:11px; padding:2px 9px; border-radius:10px; margin-bottom:14px;
}
.badge-up  { background:rgba(46,204,113,.15); color:var(--green); border:1px solid var(--green); }
.badge-down{ background:rgba(231,76,60,.15);  color:var(--red);   border:1px solid var(--red); }
.badge-deg{ background:rgba(243,156,18,.15); color:#f39c12; border:1px solid #f39c12; }
.badge-unk { background:rgba(255,255,255,.06); color:#666; border:1px solid #333; }
.dp-section{ margin-bottom:16px; }
.dp-sec-title{
    font-size:9px; letter-spacing:1.5px; text-transform:uppercase;
    color:#444; margin-bottom:8px;
}
.dp-bar-row{ margin-bottom:8px; }
.dp-bar-labels{ display:flex; justify-content:space-between; font-size:10px; color:#777; margin-bottom:3px; }
.dp-bar{ height:5px; background:rgba(255,255,255,.07); border-radius:3px; overflow:hidden; }
.dp-bar-fill{ height:100%; border-radius:3px; transition:width .4s; }
.dp-port{
    display:flex; justify-content:space-between; align-items:center;
    padding:5px 0; border-bottom:1px solid rgba(255,255,255,.04); font-size:10px;
}
.dp-port:last-child{ border:none; }
.dp-port-name{ color:#999; max-width:110px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.dp-port-rates{ text-align:right; line-height:1.5; }
.rate-in { color:var(--accent); }
.rate-out{ color:var(--green); }
.dp-total{ display:flex; gap:14px; margin-top:4px; }
.dp-total .rate-in, .dp-total .rate-out{ font-size:13px; font-weight:700; }
.dp-meta{ font-size:10px; color:#444; margin-top:6px; }
.dp-link{
    display:block; margin-top:16px; padding:8px; text-align:center;
    background:rgba(77,163,255,.12); border:1px solid rgba(77,163,255,.4);
    color:var(--accent); border-radius:8px; text-decoration:none;
    font-size:12px; font-weight:600; transition:.15s;
}
.dp-link:hover{ background:rgba(77,163,255,.25); }

/* ── Legend ─────────────────────────────────────────────────────────────── */
#map-legend{
    position:absolute; bottom:14px; left:14px;
    background:rgba(6,8,15,.88); border:1px solid var(--border);
    border-radius:10px; padding:10px 16px; font-size:10px;
    backdrop-filter:blur(10px); display:flex; flex-wrap:wrap; gap:12px 18px;
    max-width:420px; pointer-events:none;
}
.leg-item{ display:flex; align-items:center; gap:6px; color:#666; }
.leg-dot { width:9px; height:9px; border-radius:50%; flex-shrink:0; }
.leg-line{ width:22px; height:2px; flex-shrink:0; }

/* ── Tooltip ─────────────────────────────────────────────────────────────── */
#map-tip{
    position:absolute; pointer-events:none;
    background:rgba(6,8,15,.97); border:1px solid var(--border);
    border-radius:8px; padding:8px 12px; font-size:10px; color:#ccc;
    display:none; z-index:30; backdrop-filter:blur(10px); white-space:nowrap;
    line-height:1.6;
}
</style>
</head>
<body>
<video autoplay muted loop playsinline id="bg-video">
    <source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4">
</video>

<div id="map-wrap">
<!-- ── Toolbar ─────────────────────────────────────────────────────────── -->
<div id="map-toolbar">
    <span class="tb-title"><i class="fas fa-project-diagram"></i> Network Map</span>
    <div class="tb-sep"></div>
    <button class="tb-btn on" id="btn-view1" onclick="setView('fabric')" title="Map View 1 — futuristic 3D fabric: glowing nodes grouped by subnet, live traffic conduits, orbit to explore"><i class="fas fa-cube"></i> Map View 1</button>
    <button class="tb-btn" id="btn-viewC" onclick="setView('force')" title="Classic view — free-floating force-directed topology"><i class="fas fa-diagram-project"></i> Classic</button>
    <button class="tb-btn on" id="btn-orbit" onclick="toggleOrbit()" title="Orbit — the scene auto-rotates so the spheres feel alive. Click to pin it static."><i class="fas fa-arrows-rotate"></i> Orbit</button>
    <button class="tb-btn" id="btn-fs" onclick="toggleMapFs()" title="Fullscreen"><i class="fas fa-expand"></i> Fullscreen</button>
    <div class="tb-sep"></div>
    <button class="tb-btn" onclick="fitView()" title="Fit all nodes in view"><i class="fas fa-expand-arrows-alt"></i> Fit</button>
    <button class="tb-btn" onclick="zoomIn()"><i class="fas fa-plus"></i></button>
    <button class="tb-btn" onclick="zoomOut()"><i class="fas fa-minus"></i></button>
    <div class="tb-sep"></div>
    <button class="tb-btn" id="btn-refresh" onclick="doRefresh()"><i class="fas fa-sync-alt"></i> Refresh</button>
    <button class="tb-btn" id="btn-live" onclick="toggleLive()" title="Live mode: poll devices in real time on every refresh (SNMP + ICMP), instead of reading the last cron snapshot"><i class="fas fa-bolt"></i> Live</button>
    <button class="tb-btn" id="btn-rt" onclick="toggleRt()" title="⚡ REAL-TIME: live SNMP counter sampling every 2s → true instantaneous link speeds (like the Traffic Viewer). SNMP v1/v2c interfaces."><i class="fas fa-gauge-high"></i> ⚡ Real-Time</button>
    <span id="tb-countdown"></span>
    <div class="tb-sep"></div>
    <button class="tb-btn on"  id="btn-labels"   onclick="toggleLabels()"><i class="fas fa-tag"></i> Labels</button>
    <button class="tb-btn on"  id="btn-traffic"  onclick="toggleTraffic()"><i class="fas fa-wave-square"></i> Traffic</button>
    <button class="tb-btn on"  id="btn-legend"   onclick="toggleLegend()"><i class="fas fa-circle-info"></i> Legend</button>
    <div class="tb-sep"></div>
    <div id="tb-stats"></div>
    <span id="tb-ts"></span>
</div>

<!-- ── Map canvas ──────────────────────────────────────────────────────── -->
<div id="map-canvas">
    <canvas id="fab-canvas" style="position:absolute;inset:0;display:none;z-index:1;"></canvas>
    <svg id="map-svg">
        <defs>
            <filter id="glow" x="-60%" y="-60%" width="220%" height="220%">
                <feGaussianBlur stdDeviation="5" result="b"/>
                <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
            <filter id="glow-sm" x="-40%" y="-40%" width="180%" height="180%">
                <feGaussianBlur stdDeviation="2.5" result="b"/>
                <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
        </defs>
        <g id="zoom-g">
            <g id="hull-g"></g>
            <g id="link-g"></g>
            <g id="node-g"></g>
        </g>
    </svg>
    <div id="map-tip"></div>

    <!-- Detail panel -->
    <div id="detail-panel">
        <button id="dp-close" onclick="closeDetail()"><i class="fas fa-times"></i></button>
        <div id="dp-content"></div>
    </div>

    <!-- Legend -->
    <div id="map-legend">
        <div class="leg-item"><div class="leg-dot" style="background:#4da3ff;box-shadow:0 0 5px #4da3ff"></div>Router</div>
        <div class="leg-item"><div class="leg-dot" style="background:#2ecc71;box-shadow:0 0 5px #2ecc71"></div>Server / Device</div>
        <div class="leg-item"><div class="leg-dot" style="background:#2ecc71"></div>Up</div>
        <div class="leg-item"><div class="leg-dot" style="background:#e74c3c"></div>Down</div>
        <div class="leg-item"><div class="leg-dot" style="background:#555"></div>Unknown</div>
        <div class="leg-item"><div class="leg-line" style="background:linear-gradient(90deg,rgba(77,163,255,.2),#4da3ff)"></div>↓ Inbound</div>
        <div class="leg-item"><div class="leg-line" style="background:linear-gradient(90deg,rgba(46,204,113,.2),#2ecc71)"></div>↑ Outbound</div>
        <div class="leg-item" style="color:#555">CPU arc = load %</div>
    </div>
</div><!-- /map-canvas -->
</div><!-- /map-wrap -->

<script src="/d3.v7.min.js"></script>
<script src="/three.min.js"></script>
<script src="/three-orbitcontrols.js"></script>
<script src="/net_mon_map_fab.js"></script>
<script>
// ─── Config ───────────────────────────────────────────────────────────────────
const REFRESH_SEC  = 30;
const BASE_R       = 30;          // node radius (non-router)
const ROUTER_R     = 38;          // router radius
const ICON_UNICODE = {
    routeros: '',  // fa-network-wired
    linux:    '',  // fa-server
    windows:  '',  // fa-windows
    cisco:    '',  // fa-server
    generic:  '',  // fa-desktop
};
const STATUS_C = { up:'#2ecc71', down:'#e74c3c', degraded:'#f39c12', unknown:'#555' };

// ─── State ────────────────────────────────────────────────────────────────────
let svg, zoomG, zoomBeh, sim;
let nodeData = [], linkData = [];
let selectedId  = null;
let showLabels  = true;
let showTraffic = true;
let animFrame   = null, animStart = null;
let countdown   = REFRESH_SEC, cdTimer = null;
let liveMode    = false;
let rtMode      = false, rtTimer = null;   // ⚡ real-time 2s SNMP link sampling
let VIEW        = (function(){ try{ return localStorage.getItem('nmmap_view')||'fabric'; }catch(e){ return 'fabric'; } })();  // 'fabric' (Map View 1 — WebGL, default) | 'force' (Classic SVG)
let _dOpen      = 0;   // timestamp of the last detail-panel open — suppresses the svg click-to-close race

// ─── Init SVG ─────────────────────────────────────────────────────────────────
function initSVG() {
    svg  = d3.select('#map-svg');
    zoomG = d3.select('#zoom-g');
    zoomBeh = d3.zoom().scaleExtent([0.15, 5])
        .on('zoom', e => zoomG.attr('transform', e.transform));
    svg.call(zoomBeh);
    svg.on('click', (e) => {
        if (Date.now() - _dOpen < 350) return;                     // a node was just clicked → don't close it
        if (e.target.closest && e.target.closest('.node-grp')) return;
        closeDetail();
    });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function W(){ return document.getElementById('map-canvas').clientWidth; }
function H(){ return document.getElementById('map-canvas').clientHeight; }

function fmtBps(b) {
    if (!b || b===0) return '0 B/s';
    const u=['B/s','KB/s','MB/s','GB/s'];
    let i=0; while(b>=1024&&i<3){b/=1024;i++;}
    return b.toFixed(1)+' '+u[i];
}
function fmtUp(s) {
    if (!s) return '–';
    s=Math.floor(s);
    const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60);
    return d>0?`${d}d ${h}h`:h>0?`${h}h ${m}m`:`${m}m`;
}
function nr(d){ return d.icon==='routeros' ? ROUTER_R : BASE_R; }
function nc(d){ return d.grp_color || '#4da3ff'; }
function sc(d){ return STATUS_C[d.status] || STATUS_C.unknown; }
function linkW(r){ return r>0 ? Math.min(7, 1.2 + Math.log10(r+1)*1.4) : 1; }

// ─── Subnet hull ──────────────────────────────────────────────────────────────
function renderHulls(nodes) {
    const grps = d3.group(nodes, d => d.net_key||'default');
    const hg = d3.select('#hull-g');

    hg.selectAll('path.hull-path').data([...grps.entries()], d=>d[0])
        .join('path').attr('class','hull-path')
        .attr('d', ([, gs]) => {
            let pts = gs.map(n=>[n.x||0,n.y||0]);
            if (pts.length===1) {
                const [cx,cy]=pts[0];
                pts=[[cx-80,cy-80],[cx+80,cy-80],[cx+80,cy+80],[cx-80,cy+80]];
            } else if (pts.length===2) {
                const p=70;
                pts=[...pts,[pts[0][0]-p,pts[0][1]-p],[pts[0][0]+p,pts[0][1]+p],
                             [pts[1][0]-p,pts[1][1]-p],[pts[1][0]+p,pts[1][1]+p]];
            }
            const hull = d3.polygonHull(pts); if(!hull) return '';
            const c = d3.polygonCentroid(hull);
            const ex = hull.map(p=>{
                const dx=p[0]-c[0],dy=p[1]-c[1],len=Math.sqrt(dx*dx+dy*dy)||1,pad=65;
                return [p[0]+dx/len*pad, p[1]+dy/len*pad];
            });
            return 'M'+ex.map(p=>p.join(',')).join('L')+'Z';
        });

    hg.selectAll('text.hull-label').data([...grps.entries()], d=>d[0])
        .join('text').attr('class','hull-label').attr('text-anchor','middle')
        .attr('x', ([,g]) => d3.mean(g, n=>n.x||0))
        .attr('y', ([,g]) => d3.min(g, n=>n.y||0) - 75)
        .text(([k]) => k);
}

// ─── Links ────────────────────────────────────────────────────────────────────
function renderLinks(links) {
    const lg = d3.select('#link-g');
    const grp = lg.selectAll('g.lk').data(links, d=>`${d.source?.id||d.source}-${d.target?.id||d.target}`);

    const enter = grp.enter().append('g').attr('class','lk');
    enter.append('line').attr('class','link-base');
    enter.append('line').attr('class','link-flow-in');
    enter.append('line').attr('class','link-flow-out');
    enter.append('text').attr('class','link-lbl');
    enter.append('text').attr('class','link-if link-if-src');
    enter.append('text').attr('class','link-if link-if-tgt');
    grp.exit().remove();

    const all = lg.selectAll('g.lk');

    function lx(d,which){ return which==='x1'?d.source.x:d.target.x; }
    function ly(d,which){ return which==='y1'?d.source.y:d.target.y; }

    all.select('.link-base')
        .attr('stroke-width', d=>Math.max(2, linkW(Math.max(d.in_rate||0,d.out_rate||0))+2))
        .attr('x1',d=>d.source.x||0).attr('y1',d=>d.source.y||0)
        .attr('x2',d=>d.target.x||0).attr('y2',d=>d.target.y||0);

    all.select('.link-flow-in')
        .attr('stroke-width', d=>linkW(d.in_rate||0))
        .attr('stroke-opacity', d=>showTraffic&&d.in_rate>0?0.85:0)
        .attr('x1',d=>d.source.x||0).attr('y1',d=>d.source.y||0)
        .attr('x2',d=>d.target.x||0).attr('y2',d=>d.target.y||0);

    all.select('.link-flow-out')
        .attr('stroke-width', d=>linkW(d.out_rate||0))
        .attr('stroke-opacity', d=>showTraffic&&d.out_rate>0?0.85:0)
        .attr('x1',d=>d.source.x||0).attr('y1',d=>d.source.y||0)
        .attr('x2',d=>d.target.x||0).attr('y2',d=>d.target.y||0);

    all.select('.link-lbl')
        .attr('x', d=>((d.source.x||0)+(d.target.x||0))/2)
        .attr('y', d=>((d.source.y||0)+(d.target.y||0))/2 - 7)
        .attr('opacity', showTraffic?1:0)
        .text(d => {
            const i=d.in_rate||0, o=d.out_rate||0;
            return (i||o) ? `↓${fmtBps(i)} ↑${fmtBps(o)}` : '';
        });

    // Per-end interface + IP labels (which interface connects to where)
    const lerp = (a,b,t)=> (a||0)+((b||0)-(a||0))*t;
    all.select('.link-if-src')
        .attr('x', d=>lerp(d.source.x, d.target.x, 0.24))
        .attr('y', d=>lerp(d.source.y, d.target.y, 0.24) + 11)
        .attr('opacity', showLabels?1:0)
        .text(d => d.src_if ? `${d.src_if.name} · ${d.src_if.ip}` : '');
    all.select('.link-if-tgt')
        .attr('x', d=>lerp(d.source.x, d.target.x, 0.76))
        .attr('y', d=>lerp(d.source.y, d.target.y, 0.76) + 11)
        .attr('opacity', showLabels?1:0)
        .text(d => d.tgt_if ? `${d.tgt_if.name} · ${d.tgt_if.ip}` : '');
}

// ─── Nodes ────────────────────────────────────────────────────────────────────
function renderNodes(nodes) {
    const ng = d3.select('#node-g');
    const grp = ng.selectAll('g.node-grp').data(nodes, d=>d.id);

    const enter = grp.enter().append('g').attr('class','node-grp')
        .on('mouseover', (e,d)=>showTip(e,d))
        .on('mousemove', moveTip)
        .on('mouseout', hideTip)
        // Single gesture handler: pin on mousedown (so the node stays under the
        // cursor and the sim keeps ticking → drag works), and treat a press that
        // didn't move as a click → open the drawer. This is reliable for every node
        // regardless of clustering/movement, unlike a separate native click.
        .call(d3.drag()
            .clickDistance(10)
            .on('start',(e,d)=>{ if(!e.active) sim.alphaTarget(.3).restart(); d.fx=d.x; d.fy=d.y; d._sx=e.x; d._sy=e.y; })
            .on('drag', (e,d)=>{ d.fx=e.x; d.fy=e.y; })
            .on('end',  (e,d)=>{
                if(!e.active) sim.alphaTarget(0);
                const moved = Math.hypot(e.x-(d._sx ?? e.x), e.y-(d._sy ?? e.y)) > 6;
                if(!moved){ d.fx=null; d.fy=null; showDetail(d); }
            }));

    enter.append('path').attr('class','cpu-arc');          // CPU progress ring
    enter.append('circle').attr('class','nd-glow');        // outer glow
    enter.append('circle').attr('class','nd-ring');        // status ring
    enter.append('circle').attr('class','nd-bg');          // fill
    enter.append('text').attr('class','node-icon');        // FA icon
    enter.append('text').attr('class','node-name-lbl');    // name
    enter.append('text').attr('class','node-ip-lbl');      // ip
    enter.append('circle').attr('class','nd-status');      // status dot

    grp.exit().remove();
    const all = ng.selectAll('g.node-grp');

    all.attr('transform', d=>`translate(${d.x||0},${d.y||0})`);

    // CPU arc (partial circle showing cpu%)
    all.select('.cpu-arc').attr('fill', d=>nc(d)).attr('opacity',.5)
        .attr('d', d=>{
            const r=nr(d), cpu=d.cpu??0;
            return d3.arc()
                .innerRadius(r+2).outerRadius(r+8)
                .startAngle(-Math.PI/2)
                .endAngle(-Math.PI/2 + 2*Math.PI*(Math.min(100,cpu)/100))();
        });

    // Outer glow
    all.select('.nd-glow')
        .attr('r', d=>nr(d)+12).attr('fill','none')
        .attr('stroke', d=>nc(d)).attr('stroke-width',10).attr('opacity',.1);

    // Status ring
    all.select('.nd-ring')
        .attr('r', d=>nr(d)+2).attr('fill','none')
        .attr('stroke', d=>sc(d)).attr('stroke-width',2);

    // Background fill
    all.select('.nd-bg').attr('r', d=>nr(d))
        .attr('fill', d=>{ const c=d3.color(nc(d)); if(c){c.opacity=.18;} return c?c.formatRgb():'rgba(77,163,255,.18)'; })
        .attr('stroke', d=>nc(d)).attr('stroke-width',1)
        .attr('filter', d=>d.icon==='routeros'?'url(#glow)':'url(#glow-sm)');

    // Icon
    all.select('.node-icon')
        .attr('fill', d=>nc(d)).attr('font-size', d=>d.icon==='routeros'?19:16)
        .text(d=>ICON_UNICODE[d.icon]||ICON_UNICODE.generic);

    // Labels (toggle-able)
    all.select('.node-name-lbl')
        .attr('y', d=>nr(d)+14)
        .attr('opacity', showLabels?1:0)
        .text(d=>d.name.length>17?d.name.slice(0,15)+'…':d.name);

    all.select('.node-ip-lbl')
        .attr('y', d=>nr(d)+25)
        .attr('opacity', showLabels?1:0)
        .text(d=>d.ip);

    // Status dot (pulsing when active traffic)
    all.select('.nd-status')
        .attr('r', 5).attr('cx', d=>nr(d)+1).attr('cy', d=>-nr(d)-1)
        .attr('fill', d=>sc(d)).attr('stroke','#06080f').attr('stroke-width',1.5)
        .classed('status-pulse', d=>d.status==='up'&&(d.total_in||0)+(d.total_out||0)>2000);
}

// ─── Traffic animation (rAF loop) ────────────────────────────────────────────
function startAnim() {
    if (animFrame) cancelAnimationFrame(animFrame);
    animStart = null;
    function frame(ts) {
        if (!animStart) animStart = ts;
        const el = ts - animStart;
        d3.selectAll('.link-flow-in').each(function(d){
            const r=d.in_rate||0; if(!r) return;
            const spd=Math.max(120, 2800/Math.log10(r+2));
            this.style.strokeDashoffset = (-(el/spd)*12)%12;
        });
        d3.selectAll('.link-flow-out').each(function(d){
            const r=d.out_rate||0; if(!r) return;
            const spd=Math.max(120, 2800/Math.log10(r+2));
            this.style.strokeDashoffset = ((el/spd)*12)%12;
        });
        animFrame = requestAnimationFrame(frame);
    }
    animFrame = requestAnimationFrame(frame);
}

// ─── Tooltip ──────────────────────────────────────────────────────────────────
function showTip(e,d){
    const tip=document.getElementById('map-tip');
    tip.innerHTML=`<b>${d.name}</b><br>${d.ip}<br>`
        +(d.cpu!=null?`CPU: ${d.cpu.toFixed(1)}%  `:'')
        +(d.memory!=null?`Mem: ${d.memory.toFixed(1)}%`:'')
        +`<br><span style="color:#4da3ff">↓${fmtBps(d.total_in)}</span>`
        +`&nbsp;<span style="color:#2ecc71">↑${fmtBps(d.total_out)}</span>`;
    tip.style.display='block';
    moveTip(e);
}
function moveTip(e){
    const tip=document.getElementById('map-tip');
    tip.style.left=(e.offsetX+14)+'px'; tip.style.top=(e.offsetY-8)+'px';
}
function hideTip(){ document.getElementById('map-tip').style.display='none'; }

// ─── Detail panel ─────────────────────────────────────────────────────────────
function showDetail(d){
    _dOpen = Date.now();                                   // guard against the svg click-to-close race
    const panel = document.getElementById('detail-panel');
    const content = document.getElementById('dp-content');
    try {
        selectedId = d.id;
        const esc = s => String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
        const num = v => (v==null||v==='')?null:(isNaN(+v)?null:(+v));   // mysqli sends numbers as strings — always coerce
        const cpu=num(d.cpu), mem=num(d.memory);
        const cpuC = (cpu??0)>80?'#e74c3c':(cpu??0)>50?'#f39c12':'#2ecc71';
        const memC = (mem??0)>85?'#e74c3c':(mem??0)>60?'#f39c12':'#4da3ff';
        const st = String(d.status||'unknown');
        const badge = st==='up'?'badge-up':(st==='down'?'badge-down':(st==='degraded'?'badge-deg':'badge-unk'));
        const ports = Array.isArray(d.ports)?d.ports:[];
        const portsHtml = ports.length ? ports.map(p=>`
            <div class="dp-port">
                <span class="dp-port-name"><i class="fas fa-ethernet" style="color:#333;margin-right:4px"></i>${esc(p.iname||p.if_name||'port')}</span>
                <span class="dp-port-rates">
                    <span class="rate-in">↓${fmtBps(num(p.in_rate)||0)}</span>
                    <span style="color:#222;margin:0 3px">|</span>
                    <span class="rate-out">↑${fmtBps(num(p.out_rate)||0)}</span>
                </span>
            </div>`).join('') : '<div style="font-size:10px;color:#444">No interface data</div>';

        content.innerHTML=`
            <div class="dp-name">${esc(d.name||('Node #'+d.id))}</div>
            <div class="dp-ip"><i class="fas fa-network-wired" style="color:#333;margin-right:4px"></i>${esc(d.ip||'—')}&nbsp;${esc(d.subnet||'')}</div>
            <span class="dp-badge ${badge}"><i class="fas fa-circle" style="font-size:7px"></i> ${st.toUpperCase()}</span>

            <div class="dp-section">
                <div class="dp-sec-title"><i class="fas fa-microchip"></i> Performance</div>
                <div class="dp-bar-row">
                    <div class="dp-bar-labels"><span>CPU</span><span>${cpu!=null?cpu.toFixed(1)+'%':'–'}</span></div>
                    <div class="dp-bar"><div class="dp-bar-fill" style="width:${Math.min(100,cpu??0)}%;background:${cpuC}"></div></div>
                </div>
                <div class="dp-bar-row">
                    <div class="dp-bar-labels"><span>Memory</span><span>${mem!=null?mem.toFixed(1)+'%':'–'}</span></div>
                    <div class="dp-bar"><div class="dp-bar-fill" style="width:${Math.min(100,mem??0)}%;background:${memC}"></div></div>
                </div>
                <div class="dp-meta"><i class="fas fa-clock" style="margin-right:3px"></i>Uptime: ${fmtUp(d.uptime)}</div>
            </div>

            <div class="dp-section">
                <div class="dp-sec-title"><i class="fas fa-ethernet"></i> Interfaces</div>
                ${portsHtml}
            </div>

            <div class="dp-section">
                <div class="dp-sec-title"><i class="fas fa-arrow-right-arrow-left"></i> Current Traffic</div>
                <div class="dp-total">
                    <div class="rate-in">↓ ${fmtBps(num(d.total_in)||0)}</div>
                    <div class="rate-out">↑ ${fmtBps(num(d.total_out)||0)}</div>
                </div>
            </div>

            <a class="dp-link" href="net_mon_stats.php?node=${d.id}"><i class="fas fa-chart-area"></i> View Statistics</a>`;
    } catch(err){
        console.error('showDetail error:', err, d);
        content.innerHTML = `<div class="dp-name">${(d&&d.name)||'Node'}</div><div style="padding:12px;color:#9aa3ad;font-size:12px">${(d&&d.ip)||''}<br>Detail render error (logged) — basic info only.</div>`;
    }
    panel.classList.add('open');                          // ALWAYS open, even if the content build threw
}
function closeDetail(){
    selectedId=null;
    document.getElementById('detail-panel').classList.remove('open');
}

// ─── Toolbar stats bar ────────────────────────────────────────────────────────
function updateStatsBar(nodes){
    const up  = nodes.filter(n=>n.status==='up').length;
    const down= nodes.filter(n=>n.status==='down').length;
    const unk = nodes.filter(n=>n.status==='unknown').length;
    document.getElementById('tb-stats').innerHTML=
        `<span class="tb-stat"><span class="tb-stat-dot" style="background:#2ecc71"></span>${up} Up</span>`+
        (down?`<span class="tb-stat"><span class="tb-stat-dot" style="background:#e74c3c"></span>${down} Down</span>`:'')+
        (unk ?`<span class="tb-stat"><span class="tb-stat-dot" style="background:#555"></span>${unk} Unknown</span>`:'')+
        `<span class="tb-stat" style="color:#444">Nodes:${nodes.length}</span>`;
}

// ─── Render ───────────────────────────────────────────────────────────────────
function renderGraph(data){
    nodeData = data.nodes;
    document.getElementById('tb-ts').textContent = 'Updated: '+(data.ts||'–');
    updateStatsBar(nodeData);

    const byId = new Map(nodeData.map(n=>[n.id,n]));

    // Resolve links (preserve existing positions across refreshes)
    const resolved = (data.links||[]).map(l=>({
        ...l,
        source: typeof l.source==='object' ? byId.get(l.source.id)||l.source : byId.get(l.source),
        target: typeof l.target==='object' ? byId.get(l.target.id)||l.target : byId.get(l.target),
    })).filter(l=>l.source&&l.target);
    linkData = resolved;

    if (!sim) {
        // Pin router to canvas center before simulation starts (no ongoing force, just initial pos)
        nodeData.forEach(n => {
            if (n.icon === 'routeros') { n.x = W()/2; n.y = H()/2; n.fx = W()/2; n.fy = H()/2; }
        });

        sim = d3.forceSimulation(nodeData)
            .force('link',    d3.forceLink(resolved).id(d=>d.id).distance(170).strength(.5))
            .force('charge',  d3.forceManyBody().strength(-500))
            .force('center',  d3.forceCenter(W()/2, H()/2))
            .force('collide', d3.forceCollide(BASE_R+55))
            .on('tick', tick)
            .on('end', () => {
                // Unpin router after simulation settles so it becomes draggable
                nodeData.forEach(n => { if (n.icon === 'routeros' && n.fx !== undefined) { n.fx = null; n.fy = null; } });
            });
        if (VIEW === 'force') {
            // Calm-on-load: seed positions on a ring + PRE-SETTLE the layout synchronously (off first
            // paint) so the map appears already-organized instead of an animated "spaghetti" untangle.
            (function preSettle(){
                const N=Math.max(1,nodeData.length), cx=W()/2, cy=H()/2, rad=Math.min(cx,cy)*0.72;
                nodeData.forEach((n,i)=>{ if(n.fx==null){ n.x=cx+rad*Math.cos(2*Math.PI*i/N); n.y=cy+rad*Math.sin(2*Math.PI*i/N); } });
                sim.stop();
                for(let i=0;i<300;i++) sim.tick();
                nodeData.forEach(n => { if (n.icon === 'routeros') { n.fx = null; n.fy = null; } });
                tick();
            })();
        } else { sim.stop(); }   // fabric view → SVG idle, NMFab renders
    } else {
        // Subsequent refresh: carry over positions
        const old = new Map(sim.nodes().map(n=>[n.id,{x:n.x,y:n.y,vx:n.vx,vy:n.vy,fx:n.fx,fy:n.fy}]));
        nodeData.forEach(n=>{ const o=old.get(n.id); if(o) Object.assign(n,o); });
        sim.nodes(nodeData);
        sim.force('link').links(resolved);
        if (VIEW === 'force') sim.alpha(.2).restart(); else sim.stop();
    }

    applyView();
    updateViewButtons();
    startAnim();
}

// Dispatch: WebGL fabric (Map View 1) vs Classic SVG. Falls back to SVG if WebGL is unavailable.
function fabOK(){ return VIEW==='fabric' && window.NMFab && NMFab.ready(); }
function applyView(){
    const svg=document.getElementById('map-svg');
    if(fabOK()){
        if(svg) svg.style.display='none';
        NMFab.render(nodeData, linkData); NMFab.show();
        if(NMFab.setSpin) NMFab.setSpin(ORBIT);   // apply the saved orbit/static preference
    } else {
        if(window.NMFab) NMFab.hide();
        if(svg) svg.style.display='';
        tick();
    }
}
function updateViewButtons(){
    const g=document.getElementById('btn-view1'), c=document.getElementById('btn-viewC');
    if(g) g.classList.toggle('on', VIEW==='fabric');
    if(c) c.classList.toggle('on', VIEW==='force');
}
// Orbit (auto-rotate) ↔ Static for Map View 1. Default = orbiting; persisted per user.
let ORBIT = (function(){ try{ return localStorage.getItem('nmmap_orbit')!=='0'; }catch(e){ return true; } })();
function toggleOrbit(){
    ORBIT=!ORBIT; try{ localStorage.setItem('nmmap_orbit', ORBIT?'1':'0'); }catch(e){}
    if(window.NMFab && NMFab.setSpin) NMFab.setSpin(ORBIT);
    const b=document.getElementById('btn-orbit');
    if(b){ b.classList.toggle('on', ORBIT); b.innerHTML='<i class="fas fa-arrows-rotate"></i> '+(ORBIT?'Orbit':'Static'); }
}
(function(){ const b=document.getElementById('btn-orbit'); if(b && !ORBIT){ b.classList.remove('on'); b.innerHTML='<i class="fas fa-arrows-rotate"></i> Static'; } })();
function setView(v){
    if(v===VIEW) { updateViewButtons(); return; }
    VIEW=v; try{ localStorage.setItem('nmmap_view',v); }catch(e){}
    updateViewButtons();
    if(v==='fabric'){ applyView(); setTimeout(()=>{ if(window.NMFab) NMFab.resize(); },60); }
    else {
        if(window.NMFab) NMFab.hide();
        const svg=document.getElementById('map-svg'); if(svg) svg.style.display='';
        if(sim){ nodeData.forEach(n=>{ if(n.icon!=='routeros'){ n.fx=null; n.fy=null; } }); sim.alpha(.7).restart(); }
        setTimeout(fitView,1100);
    }
}

function tick(){
    renderHulls(nodeData);
    renderLinks(linkData);
    renderNodes(nodeData);
}

// ─── Zoom controls ────────────────────────────────────────────────────────────
function fitView(){
    if (fabOK()){ if(window.NMFab && NMFab.reframe) NMFab.reframe(); return; }   // fabric → re-center the 3D camera
    if (!nodeData.length) return;
    const xs=nodeData.map(n=>n.x||0), ys=nodeData.map(n=>n.y||0);
    const x0=Math.min(...xs)-90, x1=Math.max(...xs)+90;
    const y0=Math.min(...ys)-90, y1=Math.max(...ys)+90;
    const sc=Math.min(.95, Math.min(W()/(x1-x0), H()/(y1-y0)));
    const tx=(W()-sc*(x0+x1))/2, ty=(H()-sc*(y0+y1))/2;
    svg.transition().duration(650)
        .call(zoomBeh.transform, d3.zoomIdentity.translate(tx,ty).scale(sc));
}
function zoomIn() { svg.transition().duration(280).call(zoomBeh.scaleBy,1.4); }
function zoomOut(){ svg.transition().duration(280).call(zoomBeh.scaleBy,0.72); }

// ─── Toggle controls ──────────────────────────────────────────────────────────
function toggleLabels(){
    showLabels=!showLabels;
    document.getElementById('btn-labels').classList.toggle('on',showLabels);
    d3.selectAll('.node-name-lbl,.node-ip-lbl,.link-if').attr('opacity',showLabels?1:0);
}
function toggleTraffic(){
    showTraffic=!showTraffic;
    document.getElementById('btn-traffic').classList.toggle('on',showTraffic);
    renderLinks(linkData);
    if(window.NMFab && NMFab.setTraffic) NMFab.setTraffic(showTraffic);   // fabric: show/hide interface + speed labels
}
function toggleLegend(){
    const leg=document.getElementById('map-legend');
    const vis=leg.style.display!=='none';
    leg.style.display=vis?'none':'flex';
    document.getElementById('btn-legend').classList.toggle('on',!vis);
}

// ─── Refresh loop ─────────────────────────────────────────────────────────────
function startCountdown(){
    clearInterval(cdTimer);
    countdown=REFRESH_SEC;
    cdTimer=setInterval(()=>{
        countdown--;
        document.getElementById('tb-countdown').textContent=`Refresh in ${countdown}s`;
        if(countdown<=0) doRefresh();
    },1000);
    document.getElementById('tb-countdown').textContent=`Refresh in ${countdown}s`;
}

// Live mode: poll devices in real time on every refresh instead of reading the
// last cron snapshot. Heavier (does actual SNMP/ICMP), so the loop paces itself —
// the next countdown only starts once the poll+render finishes.
function toggleLive(){
    liveMode=!liveMode;
    document.getElementById('btn-live').classList.toggle('on',liveMode);
    if(liveMode) doRefresh();
}
// ⚡ REAL-TIME: sample the link interfaces live via SNMP every 2s (true instantaneous rates,
// same engine as the Traffic Viewer) and overlay them on the map without a full topology reload.
function toggleRt(){
    rtMode=!rtMode;
    document.getElementById('btn-rt').classList.toggle('on',rtMode);
    if(rtMode){ clearInterval(rtTimer); rtTimer=setInterval(rtPoll,2000); rtPoll(); }
    else { clearInterval(rtTimer); rtTimer=null; document.getElementById('tb-ts').textContent='Realtime off'; doRefresh(); }
}
async function rtPoll(){
    if(!rtMode || !linkData || !linkData.length) return;
    const pidMap=new Map();                       // interface pid → [links driven by it]
    linkData.forEach(l=>{ const p=(l.tgt_if&&l.tgt_if.pid)||(l.src_if&&l.src_if.pid)||0;
        if(p){ l._pid=p; if(!pidMap.has(p))pidMap.set(p,[]); pidMap.get(p).push(l); } });
    const pids=[...pidMap.keys()]; if(!pids.length){ document.getElementById('tb-ts').textContent='⚡ no SNMP interfaces on links'; return; }
    let d=null; try{ d=await fetch('net_mon_map.php?api=rt&pids='+pids.join(',')+'&_='+Date.now()).then(r=>r.json()); }catch(e){ return; }
    if(!d||!d.ok||!d.rt) return;
    let any=false;
    pidMap.forEach((ls,pid)=>{ const r=d.rt[pid]; if(r){ ls.forEach(l=>{ if(r.in!=null)l.in_rate=r.in; if(r.out!=null)l.out_rate=r.out; }); any=true; } });
    if(any){
        if(fabOK() && window.NMFab){ NMFab.updateLinks(linkData); }
        else { renderLinks(linkData); }
        updateStatsBar(nodeData);
    }
    const t=new Date(); document.getElementById('tb-ts').textContent='⚡ Live '+t.toLocaleTimeString();
}

async function doRefresh(){
    const btn=document.getElementById('btn-refresh');
    try {
        if(liveMode){
            btn.innerHTML='<i class="fas fa-bolt fa-fade"></i> Polling…';
            try{ await fetch('net_mon_map.php?api=poll_now&_='+Date.now()); }catch(e){}
        }
        btn.innerHTML='<i class="fas fa-sync-alt fa-spin"></i> Loading…';
        const res=await fetch('net_mon_map.php?api=topo&_='+Date.now());
        const data=await res.json();
        if(data.err){ console.error(data.err); return; }
        renderGraph(data);
        // Refresh detail panel if open
        if(selectedId!==null){
            const fresh=data.nodes.find(n=>n.id===selectedId);
            if(fresh) showDetail(fresh);
        }
    } catch(e){ console.error('Fetch failed',e); }
    finally{
        btn.innerHTML='<i class="fas fa-sync-alt"></i> Refresh';
        startCountdown();
    }
}

// ─── Bootstrap ────────────────────────────────────────────────────────────────
initSVG();
if(window.NMFab){ NMFab.init(document.getElementById('map-canvas'), document.getElementById('fab-canvas'), showDetail); }
// Fullscreen the whole map (carries the particle background into the fullscreen element)
function toggleMapFs(){ const el=document.getElementById('map-wrap'); if(!el) return;
  if(document.fullscreenElement){ document.exitFullscreen(); return; }
  Promise.resolve((el.requestFullscreen||el.webkitRequestFullscreen||function(){}).call(el))
    .then(()=>{ const bg=document.getElementById('nm-netbg'); if(bg) el.appendChild(bg); }).catch(()=>{}); }
document.addEventListener('fullscreenchange',()=>{
  if(!document.fullscreenElement){ const bg=document.getElementById('nm-netbg'); if(bg && bg.parentNode!==document.body) document.body.appendChild(bg); }
  const b=document.getElementById('btn-fs'); if(b) b.classList.toggle('on', !!document.fullscreenElement);
  setTimeout(()=>{ if(window.NMFab) NMFab.resize(); if(typeof fitView==='function') fitView(); },140);
});
doRefresh().then(()=>{ setTimeout(fitView,1800); });
</script>
</body>
</html>
