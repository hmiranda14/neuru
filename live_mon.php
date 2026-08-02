<?php
// Live interface monitor — fully independent (no LibreNMS required)
// Native URL:  ?node=<nm_node_id>&iface=<nm_interface_id>
// Legacy URL:  ?device=<lnms_device_id>&port=<lnms_port_id>  (auto-translated)

date_default_timezone_set('America/Puerto_Rico');

include('check.php');
include('connection.php');
require_once('access_control.php');
include('logger.php');

function fmt_rate($bps) {
    if ($bps === null || $bps === '') return '—';
    $bps = (float)$bps;
    if ($bps >= 1_000_000_000) return number_format($bps / 1_000_000_000, 2) . ' GB/s';
    if ($bps >= 1_000_000)     return number_format($bps / 1_000_000,     2) . ' MB/s';
    if ($bps >= 1_000)         return number_format($bps / 1_000,         1) . ' KB/s';
    return number_format($bps, 0) . ' B/s';
}

// ── Resolve IDs ───────────────────────────────────────────────────────────────
// Accept native ?node&iface or legacy LibreNMS ?device&port
$nm_node_id  = max(0, (int)($_GET['node']  ?? 0));
$nm_iface_id = max(0, (int)($_GET['iface'] ?? 0));

if (!$nm_node_id && isset($_GET['device'])) {
    $dev_id = (int)$_GET['device'];
    $r = $conn->query("SELECT id FROM nm_nodes WHERE lnms_device_id={$dev_id} LIMIT 1");
    if ($r && ($row = $r->fetch_assoc())) $nm_node_id = (int)$row['id'];
}
if (!$nm_iface_id && isset($_GET['port'])) {
    $lnms_pid = (int)$_GET['port'];
    if ($nm_node_id) {
        $r = $conn->query("SELECT id FROM nm_interfaces
            WHERE node_id={$nm_node_id} AND (lnms_port_id={$lnms_pid} OR id={$lnms_pid}) LIMIT 1");
        if ($r && ($row = $r->fetch_assoc())) $nm_iface_id = (int)$row['id'];
    }
}

$is_ajax = isset($_GET['ajax']);
$is_poll = (($_GET['api'] ?? '') === 'poll_port');

if (!checkAccess($conn, 'net_mon')) {
    if ($is_ajax || $is_poll) {
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Access denied']);
        exit;
    }
    header('Location: /denied_access.php?page=live_mon');
    exit;
}

session_write_close();

// ── AJAX: return last polled stats from DB ────────────────────────────────────
if ($is_ajax) {
    header('Content-Type: application/json');
    if (!$nm_node_id || !$nm_iface_id) {
        echo json_encode(['status' => 'error', 'message' => 'Invalid node/iface']);
        exit;
    }
    $r = $conn->query("SELECT in_rate, out_rate, oper_status, if_speed, recorded_at
        FROM nm_port_stats
        WHERE node_id={$nm_node_id} AND port_id={$nm_iface_id}
        ORDER BY recorded_at DESC LIMIT 1");
    $row = $r ? $r->fetch_assoc() : null;
    echo json_encode([
        'status' => 'ok',
        'data'   => [
            'in_rate'        => (int)($row['in_rate']    ?? 0),
            'out_rate'       => (int)($row['out_rate']   ?? 0),
            'oper'           => $row['oper_status']      ?? 'unknown',
            'speed'          => (int)($row['if_speed']   ?? 0),
            'in_rate_human'  => fmt_rate($row['in_rate']  ?? 0),
            'out_rate_human' => fmt_rate($row['out_rate'] ?? 0),
            'updated_at'     => $row['recorded_at']      ?? '—',
        ],
    ]);
    exit;
}

// ── SNMP live poll: read counters, compute rate, write to DB ──────────────────
if ($is_poll) {
    header('Content-Type: application/json');
    if (!$nm_node_id || !$nm_iface_id) {
        echo json_encode(['ok' => false, 'err' => 'Invalid node/iface params']); exit;
    }

    // Load node SNMP config
    $nr   = $conn->query("SELECT ip_address, snmp_community, snmp_version FROM nm_nodes WHERE id={$nm_node_id} LIMIT 1");
    $node = $nr ? $nr->fetch_assoc() : null;
    if (!$node || !$node['ip_address'] || !$node['snmp_community']) {
        echo json_encode(['ok' => false, 'err' => 'Node has no SNMP credentials configured']); exit;
    }

    // Load interface (need if_index)
    $ir    = $conn->query("SELECT if_name, display_name, if_index FROM nm_interfaces WHERE id={$nm_iface_id} AND node_id={$nm_node_id} LIMIT 1");
    $iface = $ir ? $ir->fetch_assoc() : null;
    if (!$iface || !$iface['if_index']) {
        echo json_encode(['ok' => false, 'err' => 'Interface has no if_index — run SNMP discovery in Config → Interfaces']); exit;
    }

    $now  = $conn->query("SELECT DATE_FORMAT(NOW(),'%Y-%m-%d %H:%i:%S') t")->fetch_assoc()['t'];
    $ip   = preg_replace('/[^0-9a-fA-F.:]/', '', $node['ip_address']);
    $comm = escapeshellarg($node['snmp_community']);
    $ver  = ($node['snmp_version'] === 'v1') ? '1' : '2c';
    $idx  = (int)$iface['if_index'];

    // Read 64-bit HC octets (ifHCInOctets / ifHCOutOctets)
    $oid_in  = ".1.3.6.1.2.1.31.1.1.1.6.{$idx}";
    $oid_out = ".1.3.6.1.2.1.31.1.1.1.10.{$idx}";
    $raw_in  = $raw_out = null;
    $use32   = false;

    $out = shell_exec("/usr/bin/snmpget -v{$ver} -c {$comm} -Oqv -t 2 -r 1 {$ip} {$oid_in} {$oid_out} 2>/dev/null") ?? '';
    $lines = array_values(array_filter(explode("\n", trim($out)), 'strlen'));
    if (count($lines) >= 2 && is_numeric(trim($lines[0])) && is_numeric(trim($lines[1]))) {
        $raw_in  = (float)trim($lines[0]);
        $raw_out = (float)trim($lines[1]);
    } else {
        // Fallback: 32-bit ifInOctets / ifOutOctets
        $oid_in  = ".1.3.6.1.2.1.2.2.1.10.{$idx}";
        $oid_out = ".1.3.6.1.2.1.2.2.1.16.{$idx}";
        $out = shell_exec("/usr/bin/snmpget -v{$ver} -c {$comm} -Oqv -t 2 -r 1 {$ip} {$oid_in} {$oid_out} 2>/dev/null") ?? '';
        $lines = array_values(array_filter(explode("\n", trim($out)), 'strlen'));
        if (count($lines) >= 2 && is_numeric(trim($lines[0])) && is_numeric(trim($lines[1]))) {
            $raw_in  = (float)trim($lines[0]);
            $raw_out = (float)trim($lines[1]);
            $use32   = true;
        }
    }

    // Read oper status (ifOperStatus) and speed (ifSpeed)
    $st_out  = shell_exec("/usr/bin/snmpget -v{$ver} -c {$comm} -Oqv -t 2 -r 1 {$ip} .1.3.6.1.2.1.2.2.1.8.{$idx} .1.3.6.1.2.1.2.2.1.5.{$idx} 2>/dev/null") ?? '';
    $st_vals = array_values(array_filter(explode("\n", trim($st_out)), 'strlen'));
    $oper    = ((int)($st_vals[0] ?? 2) === 1) ? 'up' : 'down';
    $speed   = (int)($st_vals[1] ?? 0);

    $in_rate  = 0;
    $out_rate = 0;
    $in_util  = $out_util = null;
    $source   = 'cached';

    if ($raw_in !== null && $raw_out !== null) {
        $source = $use32 ? 'snmp32' : 'snmp';

        // Load previous counter snapshot from nm_if_counters
        $pr   = $conn->query("SELECT in_octets, out_octets, polled_at FROM nm_if_counters WHERE node_id={$nm_node_id} AND if_index={$idx} LIMIT 1");
        $prev = $pr ? $pr->fetch_assoc() : null;

        if ($prev) {
            $elapsed = max(1, strtotime($now) - strtotime($prev['polled_at']));
            if ($use32) {
                $d_in  = fmod($raw_in  - (float)$prev['in_octets']  + 4294967296.0, 4294967296.0);
                $d_out = fmod($raw_out - (float)$prev['out_octets'] + 4294967296.0, 4294967296.0);
            } else {
                $d_in  = max(0, $raw_in  - (float)$prev['in_octets']);
                $d_out = max(0, $raw_out - (float)$prev['out_octets']);
            }
            // Sanity: skip if > 100 Gbps for elapsed period
            $max_sane = 100e9 * $elapsed / 8;
            if ($d_in  > $max_sane) $d_in  = 0;
            if ($d_out > $max_sane) $d_out = 0;

            $in_rate  = (int)round($d_in  / $elapsed);
            $out_rate = (int)round($d_out / $elapsed);
            if ($speed > 0) {
                $in_util  = round($in_rate  * 8 / $speed * 100, 2);
                $out_util = round($out_rate * 8 / $speed * 100, 2);
            }
        }

        // Upsert counter snapshot
        $ri = sprintf('%.0f', $raw_in);
        $ro = sprintf('%.0f', $raw_out);
        $conn->query("INSERT INTO nm_if_counters (node_id, if_index, in_octets, out_octets, polled_at)
            VALUES ({$nm_node_id}, {$idx}, {$ri}, {$ro}, '{$now}')
            ON DUPLICATE KEY UPDATE in_octets={$ri}, out_octets={$ro}, polled_at='{$now}'");
    } else {
        // SNMP unreachable — serve last known rates from DB
        $lr   = $conn->query("SELECT in_rate, out_rate, oper_status, if_speed FROM nm_port_stats
            WHERE node_id={$nm_node_id} AND port_id={$nm_iface_id}
            ORDER BY recorded_at DESC LIMIT 1");
        $last = $lr ? $lr->fetch_assoc() : null;
        if ($last) {
            $in_rate  = (int)$last['in_rate'];
            $out_rate = (int)$last['out_rate'];
            $oper     = $last['oper_status'] ?? $oper;
            if (!$speed) $speed = (int)$last['if_speed'];
        }
    }

    // Write to nm_port_stats
    $iu    = is_null($in_util)  ? 'NULL' : (float)$in_util;
    $ou    = is_null($out_util) ? 'NULL' : (float)$out_util;
    $oper_s = $conn->real_escape_string($oper);
    $conn->query("INSERT INTO nm_port_stats
        (node_id, port_id, recorded_at, in_rate, out_rate, in_util, out_util, oper_status, if_speed)
        VALUES ({$nm_node_id}, {$nm_iface_id}, '{$now}', {$in_rate}, {$out_rate},
                {$iu}, {$ou}, '{$oper_s}', {$speed})");

    echo json_encode([
        'ok'             => true,
        'source'         => $source,
        'in_rate'        => $in_rate,
        'out_rate'       => $out_rate,
        'in_rate_human'  => fmt_rate($in_rate),
        'out_rate_human' => fmt_rate($out_rate),
        'oper'           => $oper,
        'speed'          => $speed,
        'updated_at'     => date('Y-m-d H:i:s'),   // UTC; JS converts to app tz
        'wrote_db'       => true,
    ]);
    exit;
}

// ── Page load: read device + interface from our DB ────────────────────────────
$node = $iface = $last_stats = null;
if ($nm_node_id) {
    $nr   = $conn->query("SELECT id, display_name, ip_address, os_icon FROM nm_nodes WHERE id={$nm_node_id} LIMIT 1");
    $node = $nr ? $nr->fetch_assoc() : null;
}
if ($nm_node_id && $nm_iface_id) {
    $ir    = $conn->query("SELECT id, if_name, display_name, if_index FROM nm_interfaces WHERE id={$nm_iface_id} AND node_id={$nm_node_id} LIMIT 1");
    $iface = $ir ? $ir->fetch_assoc() : null;
    $lr    = $conn->query("SELECT in_rate, out_rate, oper_status, if_speed, recorded_at FROM nm_port_stats
        WHERE node_id={$nm_node_id} AND port_id={$nm_iface_id} ORDER BY recorded_at DESC LIMIT 1");
    $last_stats = $lr ? $lr->fetch_assoc() : null;
}

// Build a node/interface picker for the no-selection state (works without LibreNMS)
$pick_nodes = [];
if (!$nm_node_id || !$nm_iface_id) {
    $pr = $conn->query(
        "SELECT n.id node_id, n.display_name node_name, n.ip_address,
                i.id iface_id, i.if_name, i.display_name iface_disp, i.if_index
         FROM nm_nodes n
         JOIN nm_interfaces i ON i.node_id = n.id
         WHERE i.show_graph = 1 AND i.is_dummy = 0 AND i.if_index IS NOT NULL AND i.if_index > 0
         ORDER BY n.display_name, i.sort_order, i.if_index");
    if ($pr) while ($row = $pr->fetch_assoc()) {
        $nid = (int)$row['node_id'];
        if (!isset($pick_nodes[$nid])) {
            $pick_nodes[$nid] = ['name' => $row['node_name'], 'ip' => $row['ip_address'], 'ifaces' => []];
        }
        $pick_nodes[$nid]['ifaces'][] = $row;
    }
}

$host    = $node  ? htmlspecialchars($node['display_name'])  : ('Node #' . $nm_node_id);
$if_name = $iface ? htmlspecialchars($iface['display_name'] ?: $iface['if_name']) : ('Iface #' . $nm_iface_id);
$ip_addr = htmlspecialchars($node['ip_address'] ?? '');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';

include('header.php');
log_user_action($conn, 'view_page', 'live_mon.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Live Interface Monitor</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <script src="/chart.umd.min.js"></script>
    <script src="/chartjs-adapter-date-fns.bundle.min.js"></script>
    <style>
        :root {
            --glass:  rgba(255,255,255,0.08);
            --border: rgba(255,255,255,0.15);
            --accent: #4da3ff;
            --up:     #2ecc71;
            --down:   #e74c3c;
            --warn:   #f39c12;
        }
        body { margin:0; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; background:#000; color:#fff; overflow-x:hidden; }
        #bg-video { position:fixed; top:0; left:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:0.35; }
        .page-wrapper { max-width:1500px; margin:0 auto; padding:20px; box-sizing:border-box; }
        .glass-card { background:var(--glass); backdrop-filter:blur(20px); border:1px solid var(--border); border-radius:15px; padding:18px; }
        .top-row { display:grid; grid-template-columns:1fr auto; gap:12px; align-items:center; margin-bottom:14px; }
        .title { margin:0; font-size:22px; letter-spacing:-0.4px; }
        .sub { font-size:12px; color:#9aa0a6; margin-top:4px; }
        .btn { background:rgba(77,163,255,0.18); border:1px solid var(--accent); color:var(--accent); padding:8px 12px; border-radius:8px; cursor:pointer; font-size:12px; text-decoration:none; display:inline-flex; gap:8px; align-items:center; }
        .btn:hover { background:var(--accent); color:#000; }

        .stat-grid { display:grid; grid-template-columns:repeat(6,1fr); gap:10px; margin:12px 0 14px; }
        .stat { background:rgba(255,255,255,0.05); border:1px solid var(--border); border-radius:10px; padding:10px; }
        .lbl { font-size:10px; text-transform:uppercase; letter-spacing:1px; color:#8a8a8a; margin-bottom:5px; }
        .val { font-size:15px; font-weight:700; }

        .range-bar { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:10px; }
        .range-btn { font-size:11px; padding:4px 10px; border-radius:6px; background:rgba(255,255,255,0.08); border:1px solid rgba(255,255,255,0.15); color:#aaa; cursor:pointer; }
        .range-btn.active, .range-btn:hover { background:var(--accent); color:#000; border-color:transparent; }

        .graph-wrap { border:1px solid var(--border); border-radius:12px; overflow:hidden; background:rgba(0,0,0,0.35); }
        .graph-head { display:flex; justify-content:space-between; align-items:center; padding:8px 12px; border-bottom:1px solid var(--border); font-size:11px; color:#aaa; flex-wrap:wrap; gap:6px; }
        .chart-area { position:relative; height:240px; padding:8px; }
        .legend-row { padding:8px 14px; font-size:11px; color:#777; border-top:1px solid rgba(255,255,255,.06); display:flex; gap:18px; flex-wrap:wrap; min-height:30px; }

        .poll-bar { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:10px; }
        .poll-label { font-size:10px; text-transform:uppercase; letter-spacing:.8px; color:#555; }
        .live-dot { width:7px; height:7px; border-radius:50%; background:#2ecc71; display:inline-block; animation:pulse 1.5s infinite; }
        @keyframes pulse { 0%,100%{box-shadow:0 0 0 0 rgba(46,204,113,.7)} 50%{box-shadow:0 0 0 6px rgba(46,204,113,0)} }

        .ok { color:var(--up); }
        .bad { color:var(--down); }
        .warn { color:var(--warn); }
        .src-badge { font-size:10px; padding:1px 6px; border-radius:4px; font-family:monospace; }
        .src-snmp { background:rgba(46,204,113,.15); color:var(--up); }
        .src-cached { background:rgba(255,255,255,.06); color:#666; }

        @media(max-width:1000px) { .stat-grid { grid-template-columns:repeat(3,1fr); } }
        @media(max-width:680px) { .top-row { grid-template-columns:1fr; } .stat-grid { grid-template-columns:repeat(2,1fr); } .title { font-size:18px; } }
    </style>
</head>
<body>
<video autoplay muted loop playsinline id="bg-video">
    <source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4">
</video>

<div class="page-wrapper">
    <div class="glass-card">
        <div class="top-row">
            <div>
                <h1 class="title"><i class="fas fa-satellite-dish" style="color:var(--accent);"></i> Live Interface Monitor</h1>
                <div class="sub">
                    <i class="fas fa-server" style="color:var(--accent);font-size:10px;"></i>
                    <?= $host ?>
                    <?php if ($ip_addr): ?><span style="color:#666;font-family:monospace;font-size:10px;margin-left:4px;">(<?= $ip_addr ?>)</span><?php endif ?>
                    &nbsp;·&nbsp;
                    <i class="fas fa-ethernet" style="color:var(--accent);font-size:10px;"></i>
                    <?= $if_name ?>
                </div>
            </div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
                <?php if ($nm_node_id && $nm_iface_id): ?>
                <a class="btn" href="net_mon_stats.php?node=<?= $nm_node_id ?>&port=<?= $nm_iface_id ?>" target="_blank"
                   style="background:rgba(46,204,113,.12);border-color:rgba(46,204,113,.5);color:#2ecc71;">
                    <i class="fas fa-chart-area"></i> Statistics
                </a>
                <?php endif ?>
                <a class="btn" href="net_mon.php"><i class="fas fa-arrow-left"></i> Dashboard</a>
            </div>
        </div>

        <?php if (!$nm_node_id || !$nm_iface_id): ?>
        <?php if (empty($pick_nodes)): ?>
        <div style="padding:20px;text-align:center;color:#888;">
            <i class="fas fa-exclamation-triangle" style="color:var(--warn);font-size:32px;display:block;margin-bottom:12px;"></i>
            No interfaces are available to monitor yet.<br>
            Add a node and run SNMP discovery in
            <a href="net_mon_config.php?tab=nodes" style="color:var(--accent);">Configuration</a>.
        </div>
        <?php else: ?>
        <div style="padding:6px 4px 4px;">
            <div style="font-size:13px;color:#9aa0a6;margin-bottom:14px;">
                <i class="fas fa-hand-pointer" style="color:var(--accent);"></i>
                Pick an interface to monitor live (SNMP — no LibreNMS required):
            </div>
            <?php foreach ($pick_nodes as $pnid => $pn): ?>
            <div class="glass-card" style="margin-bottom:12px;padding:14px;">
                <div style="font-weight:700;font-size:14px;margin-bottom:10px;">
                    <i class="fas fa-server" style="color:var(--accent);"></i>
                    <?= htmlspecialchars($pn['name']) ?>
                    <?php if ($pn['ip']): ?><span style="color:#666;font-family:monospace;font-size:11px;margin-left:6px;">(<?= htmlspecialchars($pn['ip']) ?>)</span><?php endif ?>
                    <span style="color:#666;font-size:11px;font-weight:400;margin-left:6px;"><?= count($pn['ifaces']) ?> interfaces</span>
                </div>
                <div style="display:flex;flex-wrap:wrap;gap:8px;">
                    <?php foreach ($pn['ifaces'] as $pf): ?>
                    <a class="btn" href="live_mon.php?node=<?= (int)$pf['node_id'] ?>&iface=<?= (int)$pf['iface_id'] ?>"
                       style="font-size:12px;">
                        <i class="fas fa-ethernet" style="font-size:10px;"></i>
                        <?= htmlspecialchars($pf['iface_disp'] ?: $pf['if_name']) ?>
                    </a>
                    <?php endforeach ?>
                </div>
            </div>
            <?php endforeach ?>
        </div>
        <?php endif ?>

        <?php elseif (!$node): ?>
        <div style="padding:20px;color:var(--down);">
            <i class="fas fa-exclamation-triangle"></i>
            Node #<?= $nm_node_id ?> not found in the database.
            <a href="net_mon_config.php?tab=nodes" style="color:var(--accent);margin-left:8px;">Check node configuration</a>
        </div>

        <?php elseif (!$iface): ?>
        <div style="padding:20px;color:var(--warn);">
            <i class="fas fa-ethernet"></i>
            Interface #<?= $nm_iface_id ?> not found for this node.
            <a href="net_mon_config.php?tab=interfaces" style="color:var(--accent);margin-left:8px;">Manage interfaces</a>
        </div>

        <?php elseif (!$iface['if_index']): ?>
        <div style="padding:20px;color:var(--warn);">
            <i class="fas fa-exclamation-triangle"></i>
            Interface <?= $if_name ?> has no <code>if_index</code> — live polling requires SNMP discovery.
            <a href="net_mon_config.php?tab=interfaces" style="color:var(--accent);margin-left:8px;">Run discovery</a>
        </div>

        <?php else: ?>
        <div class="stat-grid">
            <div class="stat">
                <div class="lbl">In Rate</div>
                <div class="val ok" id="in-rate"><?= fmt_rate($last_stats['in_rate'] ?? 0) ?></div>
            </div>
            <div class="stat">
                <div class="lbl">Out Rate</div>
                <div class="val" style="color:var(--accent);" id="out-rate"><?= fmt_rate($last_stats['out_rate'] ?? 0) ?></div>
            </div>
            <div class="stat">
                <div class="lbl">In Util%</div>
                <div class="val" id="in-util">—</div>
            </div>
            <div class="stat">
                <div class="lbl">Out Util%</div>
                <div class="val" id="out-util">—</div>
            </div>
            <div class="stat">
                <div class="lbl">Status</div>
                <div class="val <?= ($last_stats['oper_status']??'') === 'up' ? 'ok' : 'warn' ?>" id="oper-st">
                    <?= htmlspecialchars($last_stats['oper_status'] ?? 'unknown') ?>
                </div>
            </div>
            <div class="stat">
                <div class="lbl">Speed</div>
                <div class="val" id="if-speed">
                    <?php
                    $sp = (float)($last_stats['if_speed'] ?? 0);
                    echo $sp > 0 ? number_format($sp / 1_000_000, 0) . ' Mbps' : '—';
                    ?>
                </div>
            </div>
        </div>

        <!-- Poll interval + history range controls -->
        <div class="poll-bar">
            <span class="live-dot"></span>
            <span class="poll-label">SNMP poll:</span>
            <?php foreach([5=>'5s',10=>'10s',30=>'30s',60=>'60s'] as $sec=>$lbl): ?>
            <button class="range-btn <?= $sec===10?'active':'' ?>" data-poll="<?= $sec ?>"><?= $lbl ?></button>
            <?php endforeach ?>
            <span style="width:1px;height:16px;background:rgba(255,255,255,.1);margin:0 4px;"></span>
            <span class="poll-label">History:</span>
            <?php foreach(['1h'=>'1H','6h'=>'6H','24h'=>'1D','7d'=>'7D','30d'=>'30D'] as $r=>$lbl): ?>
            <button class="range-btn <?= $r==='1h'?'active':'' ?>" data-range="<?= $r ?>"><?= $lbl ?></button>
            <?php endforeach ?>
            <span id="poll-status" style="margin-left:auto;font-size:10px;color:#555;"></span>
        </div>

        <!-- Traffic history chart -->
        <div class="graph-wrap">
            <div class="graph-head">
                <span><i class="fas fa-chart-area" style="color:var(--accent);"></i>
                    <?= $if_name ?> — Traffic History
                </span>
                <span id="graph-ts" style="font-size:10px;color:#555;"></span>
            </div>
            <div class="chart-area"><canvas id="live-chart"></canvas></div>
            <div class="legend-row" id="chart-legend"></div>
        </div>
        <?php endif ?>

    </div>
</div>

<?php if ($nm_node_id && $nm_iface_id && $node && $iface && $iface['if_index']): ?>
<script>
const nodeId   = <?= (int)$nm_node_id  ?>;
const ifaceId  = <?= (int)$nm_iface_id ?>;
let currentRange   = '1h';
let pollInterval   = 10;
let pollTimer      = null;
let liveChart      = null;
let pollCountdown  = 0;
let countdownTimer = null;

function fmtBps(v) {
    if (!v && v !== 0) return '—';
    v = Math.abs(+v);
    if (v >= 1e9) return (v/1e9).toFixed(2)+' GB/s';
    if (v >= 1e6) return (v/1e6).toFixed(2)+' MB/s';
    if (v >= 1e3) return (v/1e3).toFixed(1)+' KB/s';
    return v.toFixed(0)+' B/s';
}

function setStatusClass(el, val) {
    if (!el) return;
    el.classList.remove('ok','bad','warn');
    const v = (val||'').toLowerCase();
    if (v==='up') el.classList.add('ok');
    else if (v==='down') el.classList.add('bad');
    else el.classList.add('warn');
}

function mkGrad(ctx, hex, a) {
    const g = ctx.createLinearGradient(0, 0, 0, ctx.canvas.height || 240);
    const rv=parseInt(hex.slice(1,3),16), gv=parseInt(hex.slice(3,5),16), bv=parseInt(hex.slice(5,7),16);
    g.addColorStop(0, `rgba(${rv},${gv},${bv},${a||0.3})`);
    g.addColorStop(1, `rgba(${rv},${gv},${bv},0)`);
    return g;
}

function buildChart(rows) {
    const canvas = document.getElementById('live-chart');
    if (!canvas) return;
    const ctx    = canvas.getContext('2d');
    const labels  = rows.map(r => window.nmAxisTs ? nmAxisTs(r.ts) : r.ts);   // x-axis in app timezone
    const inData  = rows.map(r => +r.in_avg  || 0);
    const outData = rows.map(r => +r.out_avg || 0);
    const inFill  = mkGrad(ctx, '#4da3ff');
    const outFill = mkGrad(ctx, '#2ecc71');

    if (liveChart) {
        liveChart.data.labels              = labels;
        liveChart.data.datasets[0].data   = inData;
        liveChart.data.datasets[1].data   = outData;
        liveChart.data.datasets[0].backgroundColor = inFill;
        liveChart.data.datasets[1].backgroundColor = outFill;
        liveChart.update('none');
        return;
    }

    liveChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [
                { label:'In',  data:inData,  borderColor:'#4da3ff', borderWidth:1.5, backgroundColor:inFill,  fill:true, tension:0.3, pointRadius:0 },
                { label:'Out', data:outData, borderColor:'#2ecc71', borderWidth:1.5, backgroundColor:outFill, fill:true, tension:0.3, pointRadius:0 },
            ]
        },
        options: {
            responsive:true, maintainAspectRatio:false, animation:false,
            plugins:{
                legend:{display:false},
                tooltip:{
                    mode:'index', intersect:false,
                    backgroundColor:'rgba(0,0,0,.85)', titleColor:'#aaa', bodyColor:'#fff',
                    padding:8, borderColor:'rgba(255,255,255,.1)', borderWidth:1,
                    callbacks:{ label: c => ' '+c.dataset.label+': '+fmtBps(c.parsed.y) }
                }
            },
            scales:{
                x:{ type:'time',
                    time:{tooltipFormat:'MMM d HH:mm',displayFormats:{minute:'HH:mm',hour:'HH:mm',day:'MMM d'}},
                    grid:{color:'rgba(255,255,255,.04)'}, ticks:{color:'#555',maxTicksLimit:7,font:{size:10}} },
                y:{ beginAtZero:true,
                    grid:{color:'rgba(255,255,255,.04)'},
                    ticks:{color:'#555',font:{size:10}, callback:v=>fmtBps(v)} }
            }
        }
    });
}

function refreshChart() {
    const tsEl  = document.getElementById('graph-ts');
    const legEl = document.getElementById('chart-legend');
    if (tsEl) tsEl.textContent = 'Loading…';
    fetch(`net_mon_stats.php?api=port_traffic&node_id=${nodeId}&port_id=${ifaceId}&range=${currentRange}`, {credentials:'same-origin'})
    .then(r=>r.json()).then(d => {
        if (!d.rows?.length) {
            if (tsEl) tsEl.textContent = 'No DB data yet — waiting for next poll cycle';
            return;
        }
        buildChart(d.rows);
        if (tsEl) tsEl.textContent = 'Updated ' + (window.nmClockS ? nmClockS(Math.floor(Date.now()/1000)) : new Date().toLocaleTimeString());
        if (legEl) legEl.innerHTML =
            `<span style="color:#4da3ff;">↓ In</span>  Avg:${fmtBps(d.avg_in)} Peak:${fmtBps(d.peak_in)} 95th:${fmtBps(d.p95_in)}` +
            `&nbsp;&nbsp;<span style="color:#2ecc71;">↑ Out</span> Avg:${fmtBps(d.avg_out)} Peak:${fmtBps(d.peak_out)} 95th:${fmtBps(d.p95_out)}`;
    }).catch(()=>{ if(tsEl) tsEl.textContent='Chart load error'; });
}

function pollLive() {
    const stEl = document.getElementById('poll-status');
    fetch(`live_mon.php?api=poll_port&node=${nodeId}&iface=${ifaceId}&_t=${Date.now()}`,
          {cache:'no-store', credentials:'same-origin'})
    .then(r=>r.json()).then(j => {
        if (!j.ok) { if(stEl) stEl.textContent='Error: '+(j.err||'?'); return; }

        const el = id => document.getElementById(id);
        if (el('in-rate'))    el('in-rate').textContent  = j.in_rate_human  || '—';
        if (el('out-rate'))   el('out-rate').textContent = j.out_rate_human || '—';
        if (el('oper-st'))    el('oper-st').textContent  = j.oper   || 'unknown';
        const spd = +(j.speed||0);
        if (el('if-speed'))   el('if-speed').textContent  = spd > 0 ? Math.round(spd/1e6)+' Mbps' : '—';
        setStatusClass(el('oper-st'), j.oper);

        // Utilization
        if (spd > 0) {
            const inU  = Math.min(100, +(j.in_rate  || 0) * 8 / spd * 100).toFixed(1);
            const outU = Math.min(100, +(j.out_rate || 0) * 8 / spd * 100).toFixed(1);
            if (el('in-util'))  el('in-util').textContent  = inU  + '%';
            if (el('out-util')) el('out-util').textContent = outU + '%';
        }

        const srcMap = {snmp:'⚡ SNMP', snmp32:'⚡ SNMP 32-bit', cached:'○ cached'};
        const srcStr = srcMap[j.source] || j.source;
        if (stEl) stEl.textContent = `● ${srcStr} · ${window.nmTimeStr ? nmTimeStr(j.updated_at) : j.updated_at}`;

        refreshChart();
        startCountdown();
    }).catch(()=>{ if(stEl) stEl.textContent='Network error'; });
}

function startCountdown() {
    clearInterval(countdownTimer);
    pollCountdown = pollInterval;
    const stEl = document.getElementById('poll-status');
    countdownTimer = setInterval(() => {
        pollCountdown--;
        if (pollCountdown <= 0) { clearInterval(countdownTimer); return; }
        const base = stEl?.textContent.split(' ·')[0] || '';
        if (stEl) stEl.textContent = base + ' · next ' + pollCountdown + 's';
    }, 1000);
}

function startPolling() {
    clearInterval(pollTimer);
    clearInterval(countdownTimer);
    pollLive();
    pollTimer = setInterval(pollLive, pollInterval * 1000);
}

document.querySelectorAll('.poll-bar [data-poll]').forEach(btn => {
    btn.addEventListener('click', () => {
        pollInterval = parseInt(btn.dataset.poll, 10) || 10;
        document.querySelectorAll('.poll-bar [data-poll]').forEach(b=>b.classList.remove('active'));
        btn.classList.add('active');
        startPolling();
    });
});

document.querySelectorAll('.poll-bar [data-range]').forEach(btn => {
    btn.addEventListener('click', () => {
        currentRange = btn.dataset.range || '1h';
        document.querySelectorAll('.poll-bar [data-range]').forEach(b=>b.classList.remove('active'));
        btn.classList.add('active');
        refreshChart();
    });
});

refreshChart();
startPolling();
</script>
<?php endif ?>
</body>
</html>
