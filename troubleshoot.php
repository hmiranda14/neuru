<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Troubleshooting Wizard (troubleshoot.php?node=<id>)
// A guided, real-time, step-by-step diagnostic console for ONE node. It does NOT
// reinvent data: it assembles the existing engines (live verdict, smokeping
// history, device_stats, syslog, win/linux SSH diagnose) into a single narrative
// and wraps every step in plain-English KNOWLEDGE (what it means · likely causes ·
// what to check next) so an operator has everything to troubleshoot a node on hand.
// Reached from the "Investigate" menu (ai_insights.php) and incident drill-downs.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');

include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_n8n.php');
require_once('nm_secrets.php');
include('logger.php');
require_once('nm_config.php');        // nm_node_live_verdict(), VENV_PYTHON, SCRIPTS_DIR
require_once('nm_tz.php');            // nm_tz_js()
@require_once('nm_smokeping.php');    // nm_sp_history()
@require_once('nm_winhost.php');      // nm_win_host/health_get/diagnose
@require_once('nm_linuxhost.php');    // nm_lx_host/health_get/diagnose

$api  = $_GET['api'] ?? '';
// Dedicated perm 'troubleshoot'; fall back to the perms an operator already uses to
// reach this page, so the drill-down works out of the box (a denied user has neither).
$allowed = checkAccess($conn, 'troubleshoot') || checkAccess($conn, 'incidents')
        || checkAccess($conn, 'ai_insights') || checkAccess($conn, 'net_mon');
if (!$allowed) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'err'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=troubleshoot'); exit;
}
// Seed the dedicated perm for admin so it appears grantable (idempotent).
@$conn->query("INSERT IGNORE INTO role_profiles (role_name,button_key,enabled) VALUES ('admin','troubleshoot',1)");

$NODE = (int)($_GET['node'] ?? 0);

// ── Resolve node + its capabilities (type, SSH host mapping) ──────────────────
function ts_node($conn, int $id): ?array {
    $r = $conn->query("SELECT id, display_name, ip_address, hostname, os_icon,
                              COALESCE(monitor_type,'snmp') monitor_type, location, hw_model
                       FROM nm_nodes WHERE id={$id} LIMIT 1");
    return $r ? ($r->fetch_assoc() ?: null) : null;
}
function ts_caps($conn, array $n): array {
    $os = strtolower($n['os_icon'] ?? '');
    $mt = $n['monitor_type'] ?? 'snmp';
    $kind = $mt === 'ping' ? 'ping' : ($os === 'windows' ? 'windows' : ($os === 'linux' ? 'linux'
          : (in_array($os, ['mikrotik','cisco','router'], true) ? 'router' : 'snmp')));
    $winId = null; $lxId = null;
    if ($kind === 'windows' && $conn->query("SHOW TABLES LIKE 'nm_win_hosts'")->num_rows) {
        $q = $conn->query("SELECT MIN(id) hid FROM nm_win_hosts WHERE node_id=".(int)$n['id']);
        if ($q && ($x=$q->fetch_assoc())) $winId = $x['hid'] ? (int)$x['hid'] : null;
    }
    if ($kind === 'linux' && $conn->query("SHOW TABLES LIKE 'nm_lx_hosts'")->num_rows) {
        $q = $conn->query("SELECT MIN(id) hid FROM nm_lx_hosts WHERE node_id=".(int)$n['id']);
        if ($q && ($x=$q->fetch_assoc())) $lxId = $x['hid'] ? (int)$x['hid'] : null;
    }
    return ['kind'=>$kind, 'win_host_id'=>$winId, 'lx_host_id'=>$lxId,
            'can_ssh'=>($winId || $lxId), 'is_ping'=>($mt==='ping')];
}

// ── Knowledge base: plain-English guidance per diagnostic topic ───────────────
function ts_kb(string $topic): array {
    $KB = [
      'reach' => [
        'meaning' => 'Whether the device answers at all (ICMP ping) and whether its management/telemetry plane (SNMP/agent) is alive. This is the first thing to confirm — everything else depends on it.',
        'causes'  => ['Device powered off / crashed / rebooting','Upstream link or gateway down (whole path lost)','Firewall/ACL dropping ICMP (device up but silent to ping)','Wrong/changed IP address'],
        'next'    => ['If SNMP is fresh but ping fails → it is alive; ICMP is just filtered (not an outage)','If both fail → check the upstream device and physical/power','Run a Traceroute to see where the path breaks'],
      ],
      'latency' => [
        'meaning' => 'Round-trip time and packet loss to the device over time (Smokeping). Loss and latency spikes explain "slow"/"flaky" complaints that a simple up/down check misses.',
        'causes'  => ['Saturated/congested WAN or LAN link','Bad cable, failing SFP, or duplex mismatch','Wi-Fi interference (for wireless paths)','Upstream ISP/peering problem'],
        'next'    => ['Sustained loss > a few % → inspect the interface error counters (Predictive Health)','Latency rising with traffic → check bandwidth (NetFlow)','Compare against other nodes on the same path to localize it'],
      ],
      'telemetry' => [
        'meaning' => 'How fresh the polled data is. Stale telemetry means we are flying blind on this device even if it is up — the dashboard numbers below may be old.',
        'causes'  => ['SNMP service stopped / community changed','Poller overloaded or cron not running','ACL now blocking the poller','Device asleep (printers) or in a reduced-power state'],
        'next'    => ['Use "Poll now" to force a fresh read','If it stays stale but pings → fix SNMP/agent on the device','If the poller is behind for many nodes → check the cron/host'],
      ],
      'resources' => [
        'meaning' => 'CPU, memory and disk pressure. Exhausted resources cause dropped packets, slow responses, failed services and crashes.',
        'causes'  => ['A runaway process or memory leak','Undersized device for current load','Backup/AV/indexing job running','Disk full → services cannot write'],
        'next'    => ['High CPU/mem → run the Deep Diagnose below to see the exact offending process','Disk near full → clear logs / expand the volume','Recurring → consider capacity upgrade'],
      ],
      'logs' => [
        'meaning' => 'The most recent syslog lines from this device, newest first. Errors/warnings here are the device telling you in its own words what is wrong.',
        'causes'  => ['Service crashes / restarts','Interface flaps, auth failures, hardware faults','Config errors after a change'],
        'next'    => ['Match a log burst to the time the problem started','Open the full Device Log for context and search','Feed a confusing log to AI Analyze for a plain-English read'],
      ],
      'diagnose' => [
        'meaning' => 'A live, on-demand SSH probe of the box right now — exactly what is consuming CPU, memory and network this second (processes aggregated by name). Nothing is installed; it is a point-in-time snapshot.',
        'causes'  => ['One process pinning a core or leaking memory','Too many connections / runaway service','A stopped critical service'],
        'next'    => ['Identify the top offender, then open the Command Center to act (restart/kill) with full context','If a watched service is stopped → restart it','Re-run after acting to confirm recovery'],
      ],
      'findings' => [
        'meaning' => 'Open incidents and AI insights already raised for this node — the system has likely correlated the symptoms and may already propose a fix.',
        'causes'  => [],
        'next'    => ['Apply or review any proposed remediation','Acknowledge what you are working so others see it','Resolve once the underlying cause is fixed'],
      ],
      'database' => [
        'meaning' => 'Databases (Data Core) running on this node — their reachability, connection saturation, lock waits, slow queries and any recent schema drift. A saturated or locked DB makes the apps on top of it slow or hang even when the host looks fine.',
        'causes'  => ['Connection pool exhausted (near max_connections)','Lock contention / a blocking transaction','A slow query doing a full table scan','Schema changed unexpectedly (drift) breaking queries'],
        'next'    => ['Open Data Core for the live Deadlock Radar + CRUD Heatmap','Kill a blocking/runaway session from the radar','Review schema drift if queries broke after a change'],
      ],
    ];
    return $KB[$topic] ?? ['meaning'=>'','causes'=>[],'next'=>[]];
}

// ─────────────────────────────────────────────────────────────────────────────
//  API — each diagnostic step is fetched independently (real-time "talking")
// ─────────────────────────────────────────────────────────────────────────────
if (function_exists('session_write_close')) @session_write_close(); // free session lock before slow SSH/n8n I/O (prevents whole-portal freeze)
if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    $n = $NODE ? ts_node($conn, $NODE) : null;
    if (!$n) { echo json_encode(['ok'=>false,'err'=>'Unknown node']); exit; }
    $caps = ts_caps($conn, $n);

    if ($api === 'overview') {
        $v = nm_node_live_verdict($conn, $NODE);
        // open incidents + insight counts for this node
        $inc = 0; $ins = 0;
        if ($r=$conn->query("SELECT COUNT(*) c FROM nm_incidents WHERE root_node_id={$NODE} AND status IN ('open','acknowledged')")) $inc=(int)($r->fetch_assoc()['c']??0);
        if ($r=$conn->query("SELECT COUNT(*) c FROM nm_ai_insights WHERE node_id={$NODE} AND status IN ('open','acknowledged')")) $ins=(int)($r->fetch_assoc()['c']??0);
        echo json_encode(['ok'=>true,'node'=>$n,'caps'=>$caps,'verdict'=>$v,'open_incidents'=>$inc,'open_insights'=>$ins]);
        exit;
    }

    if ($api === 'reach') {
        $v = nm_node_live_verdict($conn, $NODE);
        $samples = [];
        if ($r=$conn->query("SELECT is_up, latency_ms, packet_loss, UNIX_TIMESTAMP(recorded_at) ts
                             FROM nm_ping_stats WHERE node_id={$NODE} ORDER BY id DESC LIMIT 30")) {
            while ($x=$r->fetch_assoc()) $samples[] = ['up'=>(int)$x['is_up'],'rtt'=>$x['latency_ms']!==null?(float)$x['latency_ms']:null,'loss'=>$x['packet_loss']!==null?(float)$x['packet_loss']:null,'t'=>(int)$x['ts']];
        }
        $samples = array_reverse($samples);
        $st = $v['state']==='down' ? 'crit' : ($v['state']==='degraded' ? 'warn' : 'ok');
        // ping up but flagged down elsewhere → still call it reachable here
        if ($v['ping_up'] === true && $st==='crit') $st='warn';
        echo json_encode(['ok'=>true,'verdict'=>$v,'samples'=>$samples,'status'=>$st]);
        exit;
    }

    if ($api === 'latency') {
        $hist = function_exists('nm_sp_history') ? nm_sp_history($conn, $NODE, 6) : [];
        $rtts = array_values(array_filter(array_map(fn($p)=>$p['rtt'], $hist), fn($x)=>$x!==null));
        $loss = array_values(array_filter(array_map(fn($p)=>$p['loss'], $hist), fn($x)=>$x!==null));
        $cur  = $hist ? end($hist) : null;
        $avgR = $rtts ? round(array_sum($rtts)/count($rtts),1) : null;
        $maxR = $rtts ? round(max($rtts),1) : null;
        $maxL = $loss ? round(max($loss),1) : null;
        $curL = $cur && $cur['loss']!==null ? round((float)$cur['loss'],1) : null;
        $curR = $cur && $cur['rtt']!==null ? round((float)$cur['rtt'],1) : null;
        $st = 'ok';
        if ($maxL!==null && $maxL >= 10) $st='crit'; elseif (($curL!==null && $curL>=2) || ($maxL!==null && $maxL>=2)) $st='warn';
        if ($curR!==null && $avgR!==null && $avgR>0 && $curR > $avgR*2 && $st==='ok') $st='warn';
        echo json_encode(['ok'=>true,'has'=>(bool)$hist,'series'=>$hist,'cur_rtt'=>$curR,'cur_loss'=>$curL,'avg_rtt'=>$avgR,'max_rtt'=>$maxR,'max_loss'=>$maxL,'status'=>$st]);
        exit;
    }

    if ($api === 'telemetry') {
        $v = nm_node_live_verdict($conn, $NODE);
        $age = $v['snmp_age_min'];
        $st = $caps['is_ping'] ? 'ok' : ($age===null ? 'warn' : ($age>11 ? 'crit' : 'ok'));
        echo json_encode(['ok'=>true,'is_ping'=>$caps['is_ping'],'snmp_age_min'=>$age,'detail'=>$v['detail'],'status'=>$st]);
        exit;
    }

    if ($api === 'poll') {   // POST — force a fresh single-node poll
        $py = defined('VENV_PYTHON') ? VENV_PYTHON : 'python3';
        $sc = defined('SCRIPTS_DIR') ? SCRIPTS_DIR : (__DIR__.'/scripts');
        @shell_exec(escapeshellcmd($py).' '.escapeshellarg($sc.'/nm_poller.py').' --node '.(int)$NODE.' 2>&1');
        $v = nm_node_live_verdict($conn, $NODE);
        echo json_encode(['ok'=>true,'verdict'=>$v]);
        exit;
    }

    if ($api === 'resources') {
        // Uniform CPU/mem/storage from the latest nm_device_stats snapshot (SNMP nodes).
        $gauges = []; $age = null;
        $mr = $conn->query("SELECT MAX(recorded_at) mx, TIMESTAMPDIFF(MINUTE,MAX(recorded_at),NOW()) age FROM nm_device_stats WHERE node_id={$NODE}");
        $mx = $mr ? $mr->fetch_assoc() : null;
        if ($mx && $mx['mx']) {
            $age = $mx['age']!==null ? (int)$mx['age'] : null;
            $cpu=[]; $mem=null; $disks=[];
            $r = $conn->query("SELECT metric_type,metric_key,value FROM nm_device_stats
                               WHERE node_id={$NODE} AND recorded_at='".$conn->real_escape_string($mx['mx'])."'");
            while ($r && $x=$r->fetch_assoc()) {
                $v=(float)$x['value'];
                if ($x['metric_type']==='cpu' && $x['metric_key']!=='avg') $cpu[]=$v;
                elseif ($x['metric_type']==='memory') $mem = $mem===null ? $v : max($mem,$v);
                elseif ($x['metric_type']==='storage') $disks[]=['k'=>ucwords($x['metric_key']),'v'=>$v];
            }
            if ($cpu) $gauges[]=['label'=>'CPU','pct'=>round(array_sum($cpu)/count($cpu)),'warn'=>80,'crit'=>92];
            if ($mem!==null) $gauges[]=['label'=>'Memory','pct'=>round($mem),'warn'=>80,'crit'=>92];
            foreach (array_slice($disks,0,4) as $d) $gauges[]=['label'=>'Disk '.$d['k'],'pct'=>round($d['v']),'warn'=>85,'crit'=>95];
        }
        $st='ok'; foreach ($gauges as $g){ if ($g['pct']>=$g['crit']) $st='crit'; elseif ($g['pct']>=$g['warn'] && $st!=='crit') $st='warn'; }
        echo json_encode(['ok'=>true,'has'=>(bool)$gauges,'gauges'=>$gauges,'age_min'=>$age,
                          'ssh_hint'=>($caps['can_ssh'] && !$gauges),'status'=>$st]);
        exit;
    }

    if ($api === 'logs') {
        $ip = $n['ip_address'] ?? '';
        $rows = [];
        if ($ip !== '') {
            $st = $conn->prepare("SELECT received_at, severity, tag, message FROM nm_syslog
                                  WHERE host_ip=? ORDER BY received_at DESC LIMIT 25");
            $st->bind_param('s',$ip); $st->execute(); $res=$st->get_result();
            while ($x=$res->fetch_assoc()) $rows[]=$x; $st->close();
        }
        $errs=0; foreach ($rows as $r2){ if ((int)($r2['severity']??7) <= 4) $errs++; }
        echo json_encode(['ok'=>true,'rows'=>$rows,'err_count'=>$errs,'status'=>($errs>0?'warn':'ok')]);
        exit;
    }

    if ($api === 'diagnose') {   // live SSH deep-dive (win/linux only)
        if ($caps['kind']==='windows' && $caps['win_host_id'] && function_exists('nm_win_diagnose')) {
            $h = nm_win_host($conn,(int)$caps['win_host_id']);
            $d = $h ? nm_win_diagnose($conn,$h) : ['ok'=>false,'error'=>'host not found'];
        } elseif ($caps['kind']==='linux' && $caps['lx_host_id'] && function_exists('nm_lx_diagnose')) {
            $h = nm_lx_host($conn,(int)$caps['lx_host_id']);
            $d = $h ? nm_lx_diagnose($conn,$h) : ['ok'=>false,'error'=>'host not found'];
        } else {
            echo json_encode(['ok'=>false,'skip'=>true,'err'=>'Live SSH diagnose is available only for Windows/Linux hosts with a credential.']); exit;
        }
        $d['kind'] = $caps['kind'];
        echo json_encode($d);
        exit;
    }

    if ($api === 'findings') {
        $incs=[]; $inss=[];
        if ($r=$conn->query("SELECT id,title,severity,status,root_source FROM nm_incidents
                             WHERE root_node_id={$NODE} AND status IN ('open','acknowledged')
                             ORDER BY FIELD(severity,'critical','warning','info'), id DESC LIMIT 20")) while($x=$r->fetch_assoc()) $incs[]=$x;
        if ($r=$conn->query("SELECT id,title,severity,status,kind FROM nm_ai_insights
                             WHERE node_id={$NODE} AND status IN ('open','acknowledged')
                             ORDER BY FIELD(severity,'critical','warning','info'), id DESC LIMIT 20")) while($x=$r->fetch_assoc()) $inss[]=$x;
        echo json_encode(['ok'=>true,'incidents'=>$incs,'insights'=>$inss,'status'=>($incs||$inss?'warn':'ok')]);
        exit;
    }

    if ($api === 'database') {
        $dbs = [];
        if ($conn->query("SHOW TABLES LIKE 'nm_db_targets'")->num_rows) {
            $r = $conn->query("SELECT id,display_name,engine,transport,last_status,last_error,last_version FROM nm_db_targets WHERE node_id={$NODE} AND enabled=1 ORDER BY display_name");
            while ($r && ($x=$r->fetch_assoc())) {
                $s = $conn->query("SELECT connections,max_connections,threads_running,blocked,slow FROM nm_db_samples WHERE target_id=".(int)$x['id']." ORDER BY id DESC LIMIT 1");
                $x['sample'] = $s ? ($s->fetch_assoc() ?: null) : null;
                $dr = $conn->query("SELECT COUNT(*) c FROM nm_db_schema_drift WHERE target_id=".(int)$x['id']." AND detected_at > (NOW()-INTERVAL 24 HOUR)");
                $x['drift_24h'] = $dr ? (int)($dr->fetch_assoc()['c'] ?? 0) : 0;
                $dbs[] = $x;
            }
        }
        $bad = 0; foreach ($dbs as $d) { if ($d['last_status']==='error') $bad++; $sm=$d['sample']??null; if ($sm && ((int)$sm['blocked']>0)) $bad++; }
        echo json_encode(['ok'=>true,'dbs'=>$dbs,'status'=>(!$dbs?'skip':($bad?'warn':'ok'))]);
        exit;
    }

    echo json_encode(['ok'=>false,'err'=>'unknown api']); exit;
}

// ── Page render ───────────────────────────────────────────────────────────────
$node = $NODE ? ts_node($conn, $NODE) : null;
$caps = $node ? ts_caps($conn, $node) : null;
$hasDb = 0;
if ($node && $conn->query("SHOW TABLES LIKE 'nm_db_targets'")->num_rows) {
    $dr = $conn->query("SELECT COUNT(*) c FROM nm_db_targets WHERE node_id={$NODE} AND enabled=1");
    $hasDb = $dr ? (int)($dr->fetch_assoc()['c'] ?? 0) : 0;
}
log_user_action($conn, 'view_page', 'troubleshoot.php'.($NODE?('?node='.$NODE):''));

// knowledge JSON for the client
$KB_JSON = json_encode([
  'reach'=>ts_kb('reach'),'latency'=>ts_kb('latency'),'telemetry'=>ts_kb('telemetry'),
  'resources'=>ts_kb('resources'),'logs'=>ts_kb('logs'),'diagnose'=>ts_kb('diagnose'),'findings'=>ts_kb('findings'),'database'=>ts_kb('database'),
], JSON_UNESCAPED_SLASHES);

// node picker (if no node chosen)
$ALL = [];
$r=$conn->query("SELECT id,display_name,ip_address FROM nm_nodes ORDER BY display_name"); while($r && $x=$r->fetch_assoc()) $ALL[]=$x;
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Troubleshoot <?= $node ? htmlspecialchars($node['display_name']) : '' ?> | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" media="print" onload="this.media='all'">
<noscript><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"></noscript>
<?= nm_tz_js() ?>
<style>
:root{ --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.13); }
html{ background:#05080f; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; color:#e7ecf3; background:transparent!important; }
.wrap{ max-width:1080px; margin:0 auto; padding:22px 20px 70px; }
a{ color:var(--accent); text-decoration:none; }
.top{ display:flex; align-items:center; gap:14px; flex-wrap:wrap; margin-bottom:6px; }
.top h1{ font-size:21px; margin:0; display:flex; align-items:center; gap:11px; }
.top h1 .sub{ font-size:12px; color:#8a93a3; font-weight:400; }
.idbar{ display:flex; align-items:center; gap:12px; flex-wrap:wrap; background:var(--glass); border:1px solid var(--border);
  border-radius:14px; padding:13px 17px; margin:12px 0 18px; }
.idbar .nm{ font-size:17px; font-weight:700; } .idbar .ip{ font-family:monospace; color:#9fb0c4; font-size:13px; }
.tbadge{ font-size:10px; font-weight:700; letter-spacing:.5px; text-transform:uppercase; padding:3px 9px; border-radius:6px;
  border:1px solid var(--border); color:#bcd; }
.statepill{ margin-left:auto; display:flex; align-items:center; gap:9px; font-weight:700; font-size:14px; padding:7px 15px; border-radius:30px; border:1px solid; }
.statepill.up{ color:var(--ok); border-color:rgba(46,204,113,.5); background:rgba(46,204,113,.1); }
.statepill.degraded{ color:var(--warn); border-color:rgba(243,156,18,.5); background:rgba(243,156,18,.1); }
.statepill.down{ color:var(--crit); border-color:rgba(231,76,60,.5); background:rgba(231,76,60,.1); }
.statepill .dot{ width:10px; height:10px; border-radius:50%; background:currentColor; box-shadow:0 0 10px currentColor; }
.statepill.down .dot, .statepill.degraded .dot{ animation:blink 1.1s infinite; }
@keyframes blink{ 50%{ opacity:.25; } }
.jump{ display:flex; gap:9px; flex-wrap:wrap; margin-bottom:20px; }
.jbtn{ display:inline-flex; align-items:center; gap:8px; background:var(--glass); border:1px solid var(--border); color:#cdd8e6;
  padding:8px 13px; border-radius:9px; font-size:12.5px; cursor:pointer; }
.jbtn:hover{ border-color:var(--accent); color:#fff; }
.jbtn i{ color:var(--accent); }
.verdict{ border-radius:15px; padding:18px 20px; margin-bottom:22px; border:1px solid; display:none; }
.verdict.ok{ background:rgba(46,204,113,.08); border-color:rgba(46,204,113,.4); }
.verdict.warn{ background:rgba(243,156,18,.08); border-color:rgba(243,156,18,.4); }
.verdict.crit{ background:rgba(231,76,60,.09); border-color:rgba(231,76,60,.45); }
.verdict h2{ margin:0 0 6px; font-size:16px; display:flex; align-items:center; gap:10px; }
.verdict p{ margin:4px 0; font-size:13.5px; color:#d4dde8; line-height:1.6; }
.step{ background:var(--glass); border:1px solid var(--border); border-radius:15px; margin-bottom:15px; overflow:hidden; transition:border-color .3s; }
.step.run{ border-color:rgba(77,163,255,.55); }
.step.ok{ border-left:4px solid var(--ok); } .step.warn{ border-left:4px solid var(--warn); } .step.crit{ border-left:4px solid var(--crit); }
.step-h{ display:flex; align-items:center; gap:13px; padding:15px 18px; }
.step-ic{ width:34px; height:34px; border-radius:9px; display:flex; align-items:center; justify-content:center; font-size:15px;
  background:rgba(255,255,255,.06); color:#9fb0c4; flex-shrink:0; }
.step.ok .step-ic{ color:var(--ok); } .step.warn .step-ic{ color:var(--warn); } .step.crit .step-ic{ color:var(--crit); }
.step.run .step-ic{ color:var(--accent); }
.step-t{ font-size:15px; font-weight:700; } .step-s{ font-size:12px; color:#8a93a3; margin-top:2px; }
.step-badge{ margin-left:auto; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.5px; padding:4px 11px; border-radius:20px; }
.b-ok{ color:var(--ok); background:rgba(46,204,113,.12); } .b-warn{ color:var(--warn); background:rgba(243,156,18,.14); }
.b-crit{ color:var(--crit); background:rgba(231,76,60,.14); } .b-run{ color:var(--accent); background:rgba(77,163,255,.14); }
.b-skip{ color:#778; background:rgba(255,255,255,.06); }
.step-body{ padding:0 18px 17px; }
.metrics{ display:flex; gap:18px; flex-wrap:wrap; margin-bottom:12px; }
.metric{ min-width:96px; } .metric .v{ font-size:22px; font-weight:700; } .metric .k{ font-size:11px; color:#8a93a3; }
.gauge{ margin:9px 0; } .gauge .lbl{ display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px; color:#bcc8d6; }
.gauge .bar{ height:7px; border-radius:4px; background:rgba(255,255,255,.09); overflow:hidden; }
.gauge .fill{ height:100%; border-radius:4px; transition:width .7s ease; }
.spark{ display:flex; align-items:flex-end; gap:2px; height:40px; margin:8px 0; }
.spark i{ flex:1; border-radius:2px 2px 0 0; min-height:2px; background:var(--accent); opacity:.85; }
.spark i.dn{ background:var(--crit); }
table.lg{ width:100%; border-collapse:collapse; font-size:12px; }
table.lg td{ padding:5px 7px; border-bottom:1px solid rgba(255,255,255,.05); vertical-align:top; }
table.lg .sev{ font-weight:700; white-space:nowrap; } .mono{ font-family:Consolas,monospace; }
.kb{ margin-top:13px; border:1px dashed rgba(77,163,255,.3); background:rgba(77,163,255,.05); border-radius:11px; padding:12px 14px; }
.kb h4{ margin:0 0 7px; font-size:11px; letter-spacing:1px; text-transform:uppercase; color:#7fb0e8; display:flex; align-items:center; gap:7px; }
.kb p{ margin:0 0 8px; font-size:13px; color:#d2dbe6; line-height:1.6; }
.kb .cols{ display:flex; gap:22px; flex-wrap:wrap; }
.kb .col{ flex:1; min-width:210px; } .kb .col b{ font-size:11.5px; color:#9fb0c4; text-transform:uppercase; letter-spacing:.5px; }
.kb ul{ margin:5px 0 0; padding-left:17px; } .kb li{ font-size:12.5px; color:#c4cfdb; margin-bottom:4px; line-height:1.5; }
.act{ display:inline-flex; align-items:center; gap:8px; background:rgba(77,163,255,.12); border:1px solid rgba(77,163,255,.4);
  color:#9cc7ff; padding:7px 13px; border-radius:9px; font-size:12.5px; cursor:pointer; margin-top:4px; }
.act:hover{ background:rgba(77,163,255,.22); color:#fff; }
.muted{ color:#8a93a3; font-size:12.5px; }
.spin{ width:15px; height:15px; border:2px solid rgba(255,255,255,.2); border-top-color:var(--accent); border-radius:50%; display:inline-block; animation:sp .7s linear infinite; vertical-align:middle; }
@keyframes sp{ to{ transform:rotate(360deg);} }
.picker{ background:var(--glass); border:1px solid var(--border); border-radius:15px; padding:26px; text-align:center; }
.picker select{ background:#0d1422; color:#e7ecf3; border:1px solid var(--border); border-radius:9px; padding:10px 14px; font-size:14px; min-width:280px; }
</style>
</head>
<body>
<?php include('header.php'); ?>
<div class="wrap">
  <div class="top">
    <h1><i class="fas fa-stethoscope" style="color:var(--accent);"></i> Troubleshooting Wizard
        <span class="sub">guided, real-time, one node at a time</span></h1>
  </div>

<?php if (!$node): ?>
  <div class="picker">
    <div style="font-size:15px; margin-bottom:14px;">Pick a device to troubleshoot:</div>
    <select onchange="if(this.value)location.href='troubleshoot.php?node='+this.value">
      <option value="">— select a node —</option>
      <?php foreach ($ALL as $a): ?>
        <option value="<?= (int)$a['id'] ?>"><?= htmlspecialchars($a['display_name']) ?> · <?= htmlspecialchars($a['ip_address']) ?></option>
      <?php endforeach; ?>
    </select>
    <div class="muted" style="margin-top:14px;">Tip: reach this preselected from any <b>AI Insight</b> (Investigate ▾) or <b>incident</b>.</div>
  </div>
<?php else: ?>

  <div class="idbar">
    <span class="nm" id="id-name"><?= htmlspecialchars($node['display_name']) ?></span>
    <span class="ip"><?= htmlspecialchars($node['ip_address']) ?></span>
    <span class="tbadge"><?= strtoupper($caps['kind']) ?></span>
    <?php if ($node['location']): ?><span class="muted"><i class="fas fa-map-marker-alt"></i> <?= htmlspecialchars($node['location']) ?></span><?php endif; ?>
    <span class="statepill" id="state-pill"><span class="dot"></span><span id="state-txt">checking…</span></span>
    <select title="Switch device" style="margin-left:auto;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.15);border-radius:8px;color:#dfe3e8;padding:7px 10px;font-size:12.5px;max-width:260px;"
            onchange="if(this.value)location.href='troubleshoot.php?node='+this.value">
      <option value="">↔ Switch device…</option>
      <?php foreach ($ALL as $a): ?>
        <option value="<?= (int)$a['id'] ?>" <?= (int)$a['id']===$NODE?'selected':'' ?>><?= htmlspecialchars($a['display_name']) ?> · <?= htmlspecialchars($a['ip_address']) ?></option>
      <?php endforeach; ?>
    </select>
  </div>

  <div class="jump" id="jump"></div>

  <div class="verdict" id="verdict"></div>

  <div id="steps"></div>

  <div style="text-align:center; margin-top:18px;">
    <button class="act" onclick="runAll()"><i class="fas fa-rotate"></i> Re-run all checks</button>
  </div>
<?php endif; ?>
</div>

<?php if ($node): ?>
<script>
const NODE=<?= (int)$NODE ?>;
const CAPS=<?= json_encode($caps) ?>;
const KB=<?= $KB_JSON ?>;
const HAS_DB=<?= (int)$hasDb ?>;
const R={};   // collected results for the final verdict
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function gj(u,opt){ return fetch(u+(u.includes('?')?'&':'?')+'_='+Date.now(),opt).then(r=>r.json()).catch(()=>({ok:false})); }
const clr=(p,w,c)=> p>=c?'var(--crit)':(p>=w?'var(--warn)':'var(--ok)');

// ── Quick-jump buttons (context-aware) ──
function buildJump(){
  const n=NODE; let h='';
  h+=`<button class="jbtn" onclick="location.href='log_mon.php?node=${n}'"><i class="fas fa-file-lines"></i> Device Log</button>`;
  h+=`<button class="jbtn" onclick="location.href='net_mon_stats.php?node=${n}'"><i class="fas fa-chart-line"></i> Node Status</button>`;
  if(CAPS.kind==='windows'&&CAPS.win_host_id) h+=`<button class="jbtn" onclick="location.href='windows.php?host=${CAPS.win_host_id}'"><i class="fab fa-windows"></i> Command Center</button>`;
  else if(CAPS.kind==='linux'&&CAPS.lx_host_id) h+=`<button class="jbtn" onclick="location.href='linux.php?host=${CAPS.lx_host_id}'"><i class="fab fa-linux"></i> Command Center</button>`;
  h+=`<button class="jbtn" onclick="location.href='smokeping.php?node=${n}'"><i class="fas fa-wave-square"></i> Smokeping</button>`;
  h+=`<button class="jbtn" onclick="location.href='nettrace.php?host=${esc('<?= htmlspecialchars($node['ip_address'],ENT_QUOTES) ?>')}'"><i class="fas fa-route"></i> Traceroute</button>`;
  h+=`<button class="jbtn" onclick="location.href='ai_insights.php?node=${n}'"><i class="fas fa-wand-magic-sparkles"></i> AI Insights</button>`;
  if(HAS_DB) h+=`<button class="jbtn" onclick="location.href='dbmon.php'"><i class="fas fa-database"></i> Data Core</button>`;
  document.getElementById('jump').innerHTML=h;
}

// ── Knowledge panel ──
function kbBlock(topic){
  const k=KB[topic]; if(!k) return '';
  const causes=(k.causes&&k.causes.length)?`<div class="col"><b>Likely causes</b><ul>${k.causes.map(c=>`<li>${esc(c)}</li>`).join('')}</ul></div>`:'';
  const next=(k.next&&k.next.length)?`<div class="col"><b>What to check next</b><ul>${k.next.map(c=>`<li>${esc(c)}</li>`).join('')}</ul></div>`:'';
  return `<div class="kb"><h4><i class="fas fa-graduation-cap"></i> What this means</h4>
    <p>${esc(k.meaning)}</p><div class="cols">${causes}${next}</div></div>`;
}

// ── Step scaffolding ──
const STEPS=[
  {key:'reach',     ic:'fa-tower-broadcast', t:'1 · Reachability',         s:'Is the device answering?'},
  {key:'latency',   ic:'fa-wave-square',     t:'2 · Latency & packet loss', s:'Path quality over the last 6h'},
  {key:'telemetry', ic:'fa-satellite-dish',  t:'3 · Telemetry freshness',   s:'Is our data current?'},
  {key:'resources', ic:'fa-microchip',       t:'4 · Resource health',       s:'CPU · memory · disk pressure'},
  {key:'logs',      ic:'fa-list',            t:'5 · Recent device logs',    s:'What the device is reporting'},
  {key:'diagnose',  ic:'fa-stethoscope',     t:'6 · Live deep diagnose',    s:'What is eating CPU/mem right now (SSH)'},
  ...(HAS_DB?[{key:'database', ic:'fa-database', t:'7 · Databases (Data Core)', s:'DB health · locks · slow · schema drift'}]:[]),
  {key:'findings',  ic:'fa-layer-group',     t:(HAS_DB?'8':'7')+' · Open incidents & AI',   s:'Already-correlated findings + fixes'},
];
function scaffold(){
  document.getElementById('steps').innerHTML = STEPS.map(s=>`
    <div class="step" id="st-${s.key}">
      <div class="step-h"><div class="step-ic"><i class="fas ${s.ic}"></i></div>
        <div><div class="step-t">${s.t}</div><div class="step-s">${s.s}</div></div>
        <span class="step-badge b-run" id="bd-${s.key}">idle</span></div>
      <div class="step-body" id="bo-${s.key}"></div>
    </div>`).join('');
}
function setBadge(key,st,txt){
  const el=document.getElementById('st-'+key), bd=document.getElementById('bd-'+key);
  el.classList.remove('run','ok','warn','crit'); el.classList.add(st);
  bd.className='step-badge '+({run:'b-run',ok:'b-ok',warn:'b-warn',crit:'b-crit',skip:'b-skip'}[st]||'b-run');
  bd.textContent=txt||st;
}
function running(key){ setBadge(key,'run','probing'); document.getElementById('bo-'+key).innerHTML='<span class="spin"></span> <span class="muted">'+ runMsg(key) +'</span>'; }
function runMsg(key){ return {reach:'sending probes…',latency:'reading latency history…',telemetry:'checking poll freshness…',resources:'reading resource counters…',logs:'pulling recent syslog…',diagnose:'opening SSH session to the box…',database:'querying Data Core…',findings:'gathering correlated findings…'}[key]||'working…'; }

// ── Renderers per step ──
function renderReach(d){
  R.reach=d; if(!d.ok){ setBadge('reach','warn','no data'); document.getElementById('bo-reach').innerHTML='<div class="muted">No ping data yet.</div>'+kbBlock('reach'); return; }
  const v=d.verdict, sm=d.samples||[];
  const bars = sm.length ? `<div class="spark">${sm.map(x=>{ const h=x.up? Math.max(8,Math.min(40,(x.rtt||5))) :40; return `<i class="${x.up?'':'dn'}" style="height:${h}px" title="${x.up?(x.rtt!=null?x.rtt+'ms':'up'):'no reply'}"></i>`;}).join('')}</div>` : '';
  const txt = v.ping_up===false ? 'No ICMP reply' : ('Replying'+(v.detail?(' — '+esc(v.detail)):''));
  document.getElementById('bo-reach').innerHTML=
    `<div class="metrics"><div class="metric"><div class="v" style="color:${d.status==='ok'?'var(--ok)':(d.status==='warn'?'var(--warn)':'var(--crit)')}">${v.ping_up===false?'DOWN':(v.state==='down'?'DOWN':(v.state==='degraded'?'DEGRADED':'UP'))}</div><div class="k">${esc(txt)}</div></div></div>${bars}<div class="muted">last ${sm.length} ICMP probes (red = no reply)</div>`+kbBlock('reach');
  setBadge('reach',d.status, d.status==='ok'?'reachable':(d.status==='warn'?'flapping/filtered':'unreachable'));
}
function renderLatency(d){
  R.latency=d;
  if(!d.ok||!d.has){ setBadge('latency','skip','no samples'); document.getElementById('bo-latency').innerHTML='<div class="muted">No Smokeping samples for this node yet. <a href="smokeping.php?node='+NODE+'">Set it up →</a></div>'+kbBlock('latency'); return; }
  const m=`<div class="metrics">
    <div class="metric"><div class="v" style="color:${clr(d.cur_loss||0,2,10)}">${d.cur_loss==null?'—':d.cur_loss+'%'}</div><div class="k">current loss</div></div>
    <div class="metric"><div class="v">${d.cur_rtt==null?'—':d.cur_rtt+' ms'}</div><div class="k">current RTT</div></div>
    <div class="metric"><div class="v">${d.avg_rtt==null?'—':d.avg_rtt+' ms'}</div><div class="k">avg (6h)</div></div>
    <div class="metric"><div class="v" style="color:${clr(d.max_loss||0,2,10)}">${d.max_loss==null?'—':d.max_loss+'%'}</div><div class="k">peak loss</div></div></div>`;
  document.getElementById('bo-latency').innerHTML=m+kbBlock('latency');
  setBadge('latency',d.status, d.status==='ok'?'healthy':(d.status==='warn'?'jitter/loss':'high loss'));
}
function renderTelemetry(d){
  R.telemetry=d;
  let body;
  if(d.is_ping){ body=`<div class="muted">Ping-only node — no SNMP/agent telemetry to age. Reachability (step 1) is the signal.</div>`; setBadge('telemetry','ok','n/a (ping)'); }
  else { const a=d.snmp_age_min; const txt=a==null?'never polled':(a<=11?('fresh — '+a+' min ago'):('STALE — '+a+' min ago'));
    body=`<div class="metrics"><div class="metric"><div class="v" style="color:${a==null?'var(--warn)':(a>11?'var(--crit)':'var(--ok)')}">${a==null?'—':a+'m'}</div><div class="k">${esc(txt)}</div></div></div>
      <button class="act" onclick="pollNow(this)"><i class="fas fa-bolt"></i> Poll now</button> <span id="poll-res" class="muted"></span>`;
    setBadge('telemetry',d.status, d.status==='ok'?'fresh':(d.status==='crit'?'stale':'unknown')); }
  document.getElementById('bo-telemetry').innerHTML=body+kbBlock('telemetry');
}
async function pollNow(btn){
  btn.disabled=true; btn.innerHTML='<span class="spin"></span> polling…';
  const d=await gj('troubleshoot.php?api=poll&node='+NODE,{method:'POST'});
  btn.disabled=false; btn.innerHTML='<i class="fas fa-bolt"></i> Poll now';
  document.getElementById('poll-res').textContent = d.ok ? ('→ '+(d.verdict.detail||'done')) : 'poll failed';
  step('telemetry'); step('reach');
}
function renderResources(d){
  R.resources=d;
  if(!d.ok||!d.has){
    const hint = d.ssh_hint ? 'No SNMP resource counters — use <b>Live deep diagnose</b> (step 6) for live CPU/mem over SSH.' : 'No resource data available for this node.';
    setBadge('resources','skip','no counters'); document.getElementById('bo-resources').innerHTML='<div class="muted">'+hint+'</div>'+kbBlock('resources'); return;
  }
  const g=d.gauges.map(x=>`<div class="gauge"><div class="lbl"><span>${esc(x.label)}</span><span style="color:${clr(x.pct,x.warn,x.crit)}">${x.pct}%</span></div>
     <div class="bar"><div class="fill" style="width:${Math.min(100,x.pct)}%;background:${clr(x.pct,x.warn,x.crit)}"></div></div></div>`).join('');
  document.getElementById('bo-resources').innerHTML=g+(d.age_min!=null?`<div class="muted" style="margin-top:6px;">snapshot ${d.age_min} min old</div>`:'')+kbBlock('resources');
  setBadge('resources',d.status, d.status==='ok'?'healthy':(d.status==='warn'?'elevated':'critical'));
}
function renderLogs(d){
  R.logs=d;
  if(!d.ok||!(d.rows&&d.rows.length)){ setBadge('logs','ok','quiet'); document.getElementById('bo-logs').innerHTML='<div class="muted">No recent syslog from this device.</div>'+kbBlock('logs'); return; }
  const SEV={0:'#e74c3c',1:'#e74c3c',2:'#e74c3c',3:'#e74c3c',4:'#f39c12',5:'#4da3ff',6:'#8a93a3',7:'#667'};
  const SN={0:'emerg',1:'alert',2:'crit',3:'err',4:'warn',5:'notice',6:'info',7:'debug'};
  const rows=d.rows.slice(0,12).map(r=>`<tr><td class="mono" style="color:#8a93a3;white-space:nowrap;">${esc((r.received_at||'').slice(5,16))}</td>
     <td class="sev" style="color:${SEV[r.severity]||'#889'}">${SN[r.severity]||r.severity}</td>
     <td class="mono" style="color:#9fb0c4;">${esc(r.tag||'')}</td><td>${esc((r.message||'').slice(0,160))}</td></tr>`).join('');
  document.getElementById('bo-logs').innerHTML=`<table class="lg">${rows}</table>
     <a class="muted" href="log_mon.php?node=${NODE}" style="display:inline-block;margin-top:8px;">Open full Device Log →</a>`+kbBlock('logs');
  setBadge('logs',d.status, d.err_count>0?(d.err_count+' errors'):'quiet');
}
function renderDiagnose(d){
  R.diagnose=d;
  if(d.skip){ setBadge('diagnose','skip','n/a'); document.getElementById('bo-diagnose').innerHTML='<div class="muted">'+esc(d.err)+'</div>'+kbBlock('diagnose'); return; }
  if(!d.ok){ setBadge('diagnose','warn','unavailable'); document.getElementById('bo-diagnose').innerHTML='<div class="muted">Could not run the live probe: '+esc(d.error||'unknown')+'</div>'+kbBlock('diagnose'); return; }
  const x=d.data||{};
  const cpu=(x.cpu!=null)?x.cpu:null;
  const memTot=+x.mem_total||0, memFree=+x.mem_free||0, memUsed=memTot-memFree, memPct=memTot?Math.round(memUsed/memTot*100):null;
  // top processes (both win & linux diag expose name/cpu/mb arrays under various keys)
  const procs = x.procs || x.top_mem || x.processes || x.top || [];
  const prows = Array.isArray(procs)&&procs.length ? `<table class="lg"><tr><td><b>Process</b></td><td><b>CPU</b></td><td><b>Mem</b></td></tr>${
     procs.slice(0,6).map(p=>`<tr><td>${esc(p.name||p.Name||'?')}</td><td class="mono">${p.cpu!=null?esc(p.cpu)+ (CAPS.kind==='linux'?'s':'%') :'—'}</td><td class="mono">${p.mb!=null?esc(p.mb)+' MB':'—'}</td></tr>`).join('')}</table>` : '';
  let m='<div class="metrics">';
  if(cpu!=null) m+=`<div class="metric"><div class="v" style="color:${clr(cpu,70,90)}">${cpu}%</div><div class="k">CPU now</div></div>`;
  if(memPct!=null) m+=`<div class="metric"><div class="v" style="color:${clr(memPct,75,90)}">${memPct}%</div><div class="k">Memory now</div></div>`;
  if(x.load) m+=`<div class="metric"><div class="v">${esc(x.load)}</div><div class="k">load 1/5/15</div></div>`;
  m+='</div>';
  let st='ok'; if((cpu!=null&&cpu>=90)||(memPct!=null&&memPct>=90)) st='crit'; else if((cpu!=null&&cpu>=70)||(memPct!=null&&memPct>=80)) st='warn';
  const cc = CAPS.win_host_id?`windows.php?host=${CAPS.win_host_id}`:(CAPS.lx_host_id?`linux.php?host=${CAPS.lx_host_id}`:null);
  document.getElementById('bo-diagnose').innerHTML=m+prows+(cc?`<a class="muted" href="${cc}" style="display:inline-block;margin-top:9px;">Open full Command Center to act (restart/kill) →</a>`:'')+kbBlock('diagnose');
  setBadge('diagnose',st, st==='ok'?'healthy':(st==='warn'?'elevated':'pegged'));
}
function renderFindings(d){
  R.findings=d;
  const inc=(d.incidents||[]), ins=(d.insights||[]);
  if(!inc.length&&!ins.length){ setBadge('findings','ok','none open'); document.getElementById('bo-findings').innerHTML='<div class="muted">No open incidents or AI insights for this node — nothing correlated against it right now.</div>'+kbBlock('findings'); return; }
  const sevc={critical:'var(--crit)',warning:'var(--warn)',info:'var(--accent)'};
  const row=(o,isInc)=>`<tr><td class="sev" style="color:${sevc[o.severity]||'#889'}">${esc(o.severity)}</td>
     <td>${esc(o.title)}</td><td class="mono" style="color:#8a93a3;">${esc(isInc?(o.root_source||''):(o.kind||''))}</td></tr>`;
  let h='';
  if(inc.length) h+=`<div style="font-size:12px;color:#9fb0c4;margin:2px 0 5px;"><i class="fas fa-triangle-exclamation"></i> ${inc.length} open incident(s)</div><table class="lg">${inc.map(o=>row(o,true)).join('')}</table>`;
  if(ins.length) h+=`<div style="font-size:12px;color:#9fb0c4;margin:11px 0 5px;"><i class="fas fa-wand-magic-sparkles"></i> ${ins.length} AI insight(s)</div><table class="lg">${ins.map(o=>row(o,false)).join('')}</table>`;
  h+=`<a class="muted" href="ai_insights.php?node=${NODE}" style="display:inline-block;margin-top:9px;">Review & apply fixes in AI Insights →</a>`;
  document.getElementById('bo-findings').innerHTML=h+kbBlock('findings');
  setBadge('findings','warn',(inc.length+ins.length)+' open');
}
function renderDatabase(d){
  R.database=d;
  if(!d.ok||!(d.dbs&&d.dbs.length)){ setBadge('database','skip','none'); document.getElementById('bo-database').innerHTML='<div class="muted">No databases linked to this node.</div>'+kbBlock('database'); return; }
  const rows=d.dbs.map(db=>{
    const sm=db.sample||{}, used=+sm.connections||0,max=+sm.max_connections||0,pct=max?Math.round(used/max*100):0;
    const stc=db.last_status==='ok'?'var(--ok)':(db.last_status==='error'?'var(--crit)':'#889');
    const flags=[]; if((+sm.blocked)>0)flags.push(`<span style="color:var(--crit);">${sm.blocked} lock waits</span>`);
    if((+sm.slow)>0)flags.push(`<span style="color:var(--warn);">${sm.slow} slow</span>`);
    if((+db.drift_24h)>0)flags.push(`<span style="color:#c08fd6;">${db.drift_24h} schema change(s)</span>`);
    return `<div style="border:1px solid var(--border);border-radius:11px;padding:11px 13px;margin-bottom:9px;">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;">
        <b>${esc(db.display_name)}</b> <span class="muted">${esc(db.engine)} · ${esc(db.transport)}</span>
        <span style="color:${stc};font-weight:700;margin-left:auto;">${esc((db.last_status||'unknown').toUpperCase())}</span></div>
      ${db.last_error?`<div style="color:var(--crit);font-size:12px;margin-top:4px;">${esc(db.last_error.slice(0,120))}</div>`:''}
      ${db.sample?`<div style="font-size:12.5px;margin-top:6px;color:#bcc8d6;">conns ${used}/${max||'?'} (${pct}%) · running ${esc(sm.threads_running||0)} ${flags.length?(' · '+flags.join(' · ')):''}</div>`:''}
    </div>`;
  }).join('');
  document.getElementById('bo-database').innerHTML=rows+`<a class="muted" href="dbmon.php" style="display:inline-block;margin-top:4px;">Open Data Core — Deadlock Radar &amp; CRUD Heatmap →</a>`+kbBlock('database');
  setBadge('database', d.status==='ok'?'ok':'warn', d.status==='ok'?'healthy':'attention');
}
const RENDER={reach:renderReach,latency:renderLatency,telemetry:renderTelemetry,resources:renderResources,logs:renderLogs,diagnose:renderDiagnose,findings:renderFindings,database:renderDatabase};

async function step(key){
  running(key);
  const d=await gj('troubleshoot.php?api='+key+'&node='+NODE);
  RENDER[key](d);
}

// ── Overview (header state pill) ──
async function loadOverview(){
  const d=await gj('troubleshoot.php?api=overview&node='+NODE);
  if(!d.ok) return;
  const v=d.verdict, p=document.getElementById('state-pill');
  p.className='statepill '+v.state;
  document.getElementById('state-txt').textContent = v.state.toUpperCase()+(v.detail?(' · '+v.detail):'');
}

// ── Final verdict synthesis ──
function synth(){
  const v=document.getElementById('verdict'); let st='ok', title='', body=[];
  const re=R.reach, la=R.latency, te=R.telemetry, rs=R.resources, di=R.diagnose, fi=R.findings;
  if(re && re.verdict && (re.verdict.state==='down' || re.verdict.ping_up===false) && !(te&&te.snmp_age_min!=null&&te.snmp_age_min<=11)){
    st='crit'; title='Device appears DOWN'; body.push('No ICMP reply and no fresh telemetry — treat as an outage. Check power and the upstream device/link, then run a Traceroute to find where the path breaks.');
  } else if(la && la.status==='crit'){
    st='crit'; title='Connectivity problem — high packet loss'; body.push('Sustained loss to this node ('+(la.max_loss)+'% peak). The device is reachable but the path is dropping packets — inspect interface error counters and the link/cabling, and check bandwidth on the path.');
  } else if(rs && rs.status==='crit'){
    st='crit'; title='Resource exhaustion'; body.push('CPU/memory/disk is critically high. Use the Live deep diagnose to find the offending process, then act from the Command Center.');
  } else if(di && (document.getElementById('st-diagnose').classList.contains('crit'))){
    st='crit'; title='A process is pegging this box'; body.push('The live SSH probe shows CPU/memory pinned. See the top processes above and act from the Command Center.');
  } else if(te && te.status==='crit'){
    st='warn'; title='Telemetry is stale — but the device pings'; body.push('We are not getting fresh SNMP/agent data, so the numbers may be old. The device itself looks reachable. Fix SNMP/the agent or use Poll now; this is NOT an outage.');
  } else if((la&&la.status==='warn')||(rs&&rs.status==='warn')){
    st='warn'; title='Minor degradation'; body.push('Some jitter/loss or elevated resources, nothing critical. Worth watching; check the warning steps above.');
  } else {
    st='ok'; title='Healthy — no problem found'; body.push('Reachable, fresh telemetry, normal latency and resources, no open critical findings. If a user still reports an issue, check the application layer or a specific service in the Command Center.');
  }
  if(fi && ((fi.incidents&&fi.incidents.length)||(fi.insights&&fi.insights.length))) body.push('There are open incidents/AI insights for this node (step 7) — the system may already propose a fix.');
  const ic = st==='crit'?'fa-circle-exclamation':(st==='warn'?'fa-triangle-exclamation':'fa-circle-check');
  v.className='verdict '+st; v.style.display='block';
  v.innerHTML=`<h2><i class="fas ${ic}"></i> ${esc(title)}</h2>${body.map(b=>`<p>${esc(b)}</p>`).join('')}`;
  v.scrollIntoView({behavior:'smooth',block:'nearest'});
}

async function runAll(){
  document.getElementById('verdict').style.display='none';
  scaffold(); buildJump(); loadOverview();
  for(const s of STEPS){ await step(s.key); }
  synth();
}
runAll();
</script>
<?php endif; ?>
</body>
</html>
