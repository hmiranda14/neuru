<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — Containers console (Phase 1: live monitoring via Portainer).
// Views: overview | detail | stats | volumes  (?view=). Lifecycle actions + live
// polling. All Portainer access is server-side (nm_portainer.php); the API key
// never reaches the browser. RBAC: 'containers'.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');

include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_portainer.php');
require_once('nm_ctr_templates.php');
require_once('nm_router_ctr.php');   // MikroTik native /container deploy targets
require_once('nm_chrome.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'containers')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=containers'); exit;
}

$cfg = nm_portainer_cfg($conn);

// ── Shared helpers ────────────────────────────────────────────────────────────
function ctr_endpoints($cfg): array {
    $e = nm_portainer_endpoints($cfg);
    return $e['ok'] ? nm_portainer_norm_endpoints($e['data']) : [];
}
function ctr_pick(array $endpoints, $req): int {
    $req = (int)$req;
    foreach ($endpoints as $e) if ($e['id'] === $req) return $req;
    foreach ($endpoints as $e) if ($e['up']) return $e['id'];      // first UP
    return $endpoints[0]['id'] ?? 0;
}
function ctr_state_rank(string $s): int {
    return ['running'=>0,'restarting'=>1,'paused'=>2,'created'=>3,'exited'=>4,'dead'=>5][$s] ?? 6;
}
function ctr_overview($cfg, int $eid): array {
    // Fast pre-flight: ask Portainer's OWN db whether this environment is up (instant) so we
    // never hang ~30s proxying to a dead Docker daemon when a host is down.
    $ep = nm_portainer_endpoint($cfg, $eid);
    if ($ep['ok'] && isset($ep['data']['Status']) && (int)$ep['data']['Status'] !== 1)
        return [[], nm_portainer_summarize([]), null, 'Host is down — Portainer cannot reach this Docker environment right now.'];
    $r = nm_portainer_containers($cfg, $eid, true);
    if (!$r['ok']) return [[], nm_portainer_summarize([]), null, $r['error']];
    $list = array_map('nm_portainer_norm_container', (array)$r['data']);
    usort($list, fn($a,$b) => [ctr_state_rank($a['state']),$a['name']] <=> [ctr_state_rank($b['state']),$b['name']]);
    $eng = nm_portainer_engine_info($cfg, $eid);
    return [$list, nm_portainer_summarize($list), $eng['ok'] ? nm_portainer_engine($eng['data']) : null, ''];
}
// Compact inspect normalizer (Phase 1 detail view).
function ctr_norm_inspect($d): array {
    $st = $d['State'] ?? []; $cfgc = $d['Config'] ?? []; $hc = $d['HostConfig'] ?? [];
    $health = $st['Health']['Status'] ?? '';
    $hlog = [];
    foreach (array_slice($st['Health']['Log'] ?? [], -5) as $h)
        $hlog[] = ['at'=>$h['Start'] ?? '', 'code'=>$h['ExitCode'] ?? '', 'out'=>mb_substr(trim($h['Output'] ?? ''),0,300)];
    $mounts = [];
    foreach (($d['Mounts'] ?? []) as $m) $mounts[] = [
        'type'=>$m['Type'] ?? '', 'name'=>$m['Name'] ?? '', 'source'=>$m['Source'] ?? '',
        'dest'=>$m['Destination'] ?? '', 'rw'=>($m['RW'] ?? true)];
    $networks = [];
    foreach (($d['NetworkSettings']['Networks'] ?? []) as $nn=>$nv) $networks[] = [
        'name'=>$nn, 'ip'=>$nv['IPAddress'] ?? '', 'gateway'=>$nv['Gateway'] ?? '', 'mac'=>$nv['MacAddress'] ?? ''];
    // env, redacting secrets
    $env = [];
    foreach (($cfgc['Env'] ?? []) as $e) {
        $p = explode('=', $e, 2); $k = $p[0]; $v = $p[1] ?? '';
        if (preg_match('/PASS|SECRET|TOKEN|_KEY|APIKEY|API_KEY|CREDENTIAL|PWD|PRIVATE/i', $k)) $v = '••••••••';
        $env[] = ['k'=>$k, 'v'=>$v];
    }
    $name = ltrim($d['Name'] ?? '', '/');
    return [
        'id'=>$d['Id'] ?? '', 'name'=>$name, 'image'=>$cfgc['Image'] ?? ($d['Image'] ?? ''),
        'platform'=>$d['Platform'] ?? '', 'state'=>strtolower($st['Status'] ?? ''),
        'running'=>(bool)($st['Running'] ?? false), 'paused'=>(bool)($st['Paused'] ?? false),
        'restarting'=>(bool)($st['Restarting'] ?? false), 'oom_killed'=>(bool)($st['OOMKilled'] ?? false),
        'pid'=>(int)($st['Pid'] ?? 0), 'exit_code'=>(int)($st['ExitCode'] ?? 0), 'state_error'=>$st['Error'] ?? '',
        'created'=>$d['Created'] ?? '', 'started_at'=>$st['StartedAt'] ?? '', 'finished_at'=>$st['FinishedAt'] ?? '',
        'restart_count'=>(int)($d['RestartCount'] ?? 0), 'restart_policy'=>$hc['RestartPolicy']['Name'] ?? '',
        'health'=>$health, 'health_log'=>$hlog,
        'mem_limit'=>(int)($hc['Memory'] ?? 0), 'command'=>implode(' ', (array)($cfgc['Cmd'] ?? [])),
        'workdir'=>$cfgc['WorkingDir'] ?? '', 'hostname'=>$cfgc['Hostname'] ?? '', 'user'=>$cfgc['User'] ?? '',
        'network_mode'=>$hc['NetworkMode'] ?? '', 'privileged'=>(bool)($hc['Privileged'] ?? false),
        'size_rw'=>(int)($d['SizeRw'] ?? 0), 'size_root'=>(int)($d['SizeRootFs'] ?? 0),
        'mounts'=>$mounts, 'networks'=>$networks, 'env'=>$env,
        'labels'=>$cfgc['Labels'] ?? [], 'stack'=>($cfgc['Labels']['com.docker.compose.project'] ?? ''),
    ];
}
function ctr_norm_volumes($df): array {
    $rows = []; $sum = ['total'=>0,'used'=>0,'unused'=>0,'reclaimable'=>0];
    foreach (($df['Volumes'] ?? []) as $v) {
        $refs = (int)($v['UsageData']['RefCount'] ?? -1);
        $size = (int)($v['UsageData']['Size'] ?? -1);
        $inUse = $refs > 0;
        $rows[] = [
            'name'=>$v['Name'] ?? '', 'driver'=>$v['Driver'] ?? '', 'mountpoint'=>$v['Mountpoint'] ?? '',
            'created'=>$v['CreatedAt'] ?? '', 'refcount'=>$refs, 'size'=>$size, 'in_use'=>$inUse,
            'stack'=>$v['Labels']['com.docker.compose.project'] ?? '',
        ];
        $sum['total']++; $inUse ? $sum['used']++ : $sum['unused']++;
        if (!$inUse && $size > 0) $sum['reclaimable'] += $size;
    }
    usort($rows, fn($a,$b)=>[$a['in_use']?0:1,$a['name']]<=>[$b['in_use']?0:1,$b['name']]);
    return [$rows, $sum];
}

// Normalize Docker networks for the Network view.
function ctr_norm_networks($data): array {
    $rows = [];
    foreach ((array)$data as $n) {
        $subnets = [];
        foreach (($n['IPAM']['Config'] ?? []) as $c) if (!empty($c['Subnet'])) $subnets[] = $c['Subnet'];
        $rows[] = [
            'name'=>$n['Name'] ?? '', 'driver'=>$n['Driver'] ?? '', 'scope'=>$n['Scope'] ?? '',
            'id'=>substr($n['Id'] ?? '', 0, 12), 'internal'=>!empty($n['Internal']),
            'containers'=>is_array($n['Containers'] ?? null) ? count($n['Containers']) : 0,
            'subnet'=>implode(', ', $subnets) ?: '—',
        ];
    }
    usort($rows, fn($a,$b)=>[$b['containers'],$a['name']]<=>[$a['containers'],$b['name']]);
    return $rows;
}

// Container network sampling/history lives in the shared include (also used by the
// background recorder cron_netstats.php). Thin aliases keep the call sites here tidy.
require_once __DIR__ . '/nm_netstats.php';
function ctr_net_ensure($conn): void { nm_netstats_ensure($conn); }
function ctr_net_sample($conn, $cfg, int $eid): array { return nm_netstats_sample($conn, $cfg, $eid); }

// ── API ───────────────────────────────────────────────────────────────────────
if ($api !== '') {
    // Release the session lock immediately — these endpoints make slow upstream
    // Portainer calls (esp. net_sample loops every running container); holding the
    // lock would serialize and freeze every other portal request behind it.
    if (function_exists('session_write_close')) session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    if (!nm_portainer_configured($cfg)) { echo json_encode(['ok'=>false,'error'=>'Portainer not configured','code'=>503]); exit; }
    $eid = (int)($_GET['endpoint'] ?? 0);

    if ($api === 'data') {
        if (!$eid) { echo json_encode(['ok'=>false,'error'=>'No endpoint']); exit; }
        [$list,$sum,$eng,$err] = ctr_overview($cfg, $eid);
        if ($err) { echo json_encode(['ok'=>false,'error'=>$err]); exit; }
        echo json_encode(['ok'=>true,'containers'=>$list,'summary'=>$sum,'engine'=>$eng,'fetched_at'=>date('H:i:s')]);
        exit;
    }

    // ── Container templates + one-click deploy ──
    if ($api === 'endpoints') {
        $eps = ctr_endpoints($cfg);
        // Also offer MikroTik routers as native deploy targets (RouterOS /container over SSH).
        // Encoded with a NEGATIVE id so the deploy handler routes them to the SSH path.
        foreach (nm_rctr_targets($conn) as $t) $eps[] = ['id'=>-(int)$t['id'],'name'=>$t['display_name'].' — MikroTik','kind'=>'mikrotik','up'=>true];
        echo json_encode(['ok'=>true,'endpoints'=>$eps]); exit;
    }
    if ($api === 'templates') { echo json_encode(['ok'=>true,'templates'=>nm_ctr_templates($conn)]); exit; }
    if ($api === 'image_search') {
        $q = trim((string)($_GET['q'] ?? ''));
        if (strlen($q) < 2) { echo json_encode(['ok'=>true,'images'=>[]]); exit; }
        $ch = curl_init('https://hub.docker.com/v2/search/repositories/?page_size=8&query=' . rawurlencode($q));
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>6, CURLOPT_CONNECTTIMEOUT=>4, CURLOPT_USERAGENT=>'NEURU']);
        $resp = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
        $out = [];
        if ($resp && $code >= 200 && $code < 300) {
            $j = json_decode($resp, true);
            foreach (($j['results'] ?? []) as $r) {
                $name = (string)($r['repo_name'] ?? ''); if ($name === '') continue;
                if (!empty($r['is_official'])) $name = preg_replace('#^library/#', '', $name);
                $out[] = ['name'=>$name, 'desc'=>substr((string)($r['short_description'] ?? ''), 0, 90),
                          'stars'=>(int)($r['star_count'] ?? 0), 'official'=>!empty($r['is_official'])];
            }
        }
        echo json_encode(['ok'=>true, 'images'=>$out, 'err'=>($code>=200&&$code<300)?'':('Docker Hub unreachable (HTTP '.$code.')')]); exit;
    }
    if ($api === 'template_save') {
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $b = json_decode(file_get_contents('php://input'), true) ?? [];
        echo json_encode(nm_ctr_template_save($conn, $b, (int)($_SESSION['UID'] ?? 0))); exit;
    }
    if ($api === 'template_delete') {
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $b = json_decode(file_get_contents('php://input'), true) ?? [];
        echo json_encode(nm_ctr_template_delete($conn, (int)($b['id'] ?? 0))); exit;
    }
    if ($api === 'deploy') {
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $b = json_decode(file_get_contents('php://input'), true) ?? [];
        $target = (int)($b['endpoint'] ?? $eid);
        if ($target < 0) {   // MikroTik router → native /container deploy over SSH
            $spec = ['image'=>(string)($b['image'] ?? ''),'name'=>(string)($b['name'] ?? ''),
                     'env'=>array_values((array)($b['env'] ?? [])),'storage'=>(string)($b['storage'] ?? '')];
            $r = nm_rctr_deploy($conn, -$target, $spec, (int)($_SESSION['UID'] ?? 0));
            echo json_encode(['ok'=>(bool)($r['ok']??false),'error'=>$r['error']??'','router'=>$r['router']??'','note'=>$r['note']??'','log'=>$r['log']??[]]); exit;
        }
        $r = nm_ctr_deploy($conn, $cfg, $target, $b, (int)($_SESSION['UID'] ?? 0));
        echo json_encode(['ok'=>(bool)($r['ok']??false),'error'=>$r['error']??'','status'=>$r['status']??0,'id'=>(($r['data']['Id']??'')) ]); exit;
    }

    if ($api === 'box_ready') {
        // Live first-boot progress for a freshly-deployed NEURU-in-a-Box: server-side proxy to
        // the new instance's /ready.php (browser can't cross-origin to it). LAN-only by design
        // (SSRF guard: private/CGNAT hosts only) — this is an internal NOC tool.
        $u = trim((string)($_GET['url'] ?? ''));
        $p = @parse_url($u); $h = strtolower((string)($p['host'] ?? ''));
        $priv = preg_match('/^(10\.|192\.168\.|127\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|169\.254\.)/', $h)
             || filter_var($h, FILTER_VALIDATE_IP) === false; // allow private IPs + LAN hostnames
        if ($h === '' || !$priv) { echo json_encode(['ok'=>false,'stage'=>'bad-target']); exit; }
        $base = ($p['scheme'] ?? 'http').'://'.$h.(isset($p['port'])?(':'.$p['port']):'');
        $ch = curl_init($base.'/ready.php');
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>5, CURLOPT_CONNECTTIMEOUT=>4,
            CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_SSL_VERIFYHOST=>0, CURLOPT_USERAGENT=>'NEURU']);
        $resp = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
        $j = $resp ? json_decode($resp, true) : null;
        if (is_array($j)) { $j['http']=$code; echo json_encode($j); }
        else echo json_encode(['ok'=>false,'stage'=>$code?('http-'.$code):'unreachable','http'=>$code]);
        exit;
    }

    if ($api === 'action') {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $cid = trim($_POST['container'] ?? '');
        $act = strtolower(trim($_POST['action'] ?? ''));
        $nm  = trim($_POST['name'] ?? '');
        if (!$eid || $cid === '' || !in_array($act, NM_PORTAINER_ACTIONS, true)) { echo json_encode(['ok'=>false,'error'=>'Bad request']); exit; }
        $r = nm_portainer_container_action($cfg, $eid, $cid, $act);
        nm_audit($conn, 'container.'.$act, ['target_type'=>'container','target_id'=>$nm ?: $cid,
            'details'=>['endpoint'=>$eid,'ok'=>$r['ok'],'status'=>$r['status']]]);
        echo json_encode(['ok'=>$r['ok'],'message'=>$r['ok'] ? ucfirst($act).'ed' : $r['error']]);
        exit;
    }

    if ($api === 'container_remove') {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $cid   = trim($_POST['container'] ?? '');
        $nm    = trim($_POST['name'] ?? '');
        $force = !empty($_POST['force']);
        $vols  = !empty($_POST['volumes']);
        if (!$eid || $cid === '') { echo json_encode(['ok'=>false,'error'=>'Bad request']); exit; }
        $r = nm_portainer_container_remove($cfg, $eid, $cid, $force, $vols);
        nm_audit($conn, 'container.remove', ['target_type'=>'container','target_id'=>$nm ?: $cid,
            'details'=>['endpoint'=>$eid,'force'=>$force,'volumes'=>$vols,'ok'=>$r['ok'],'status'=>$r['status']]]);
        echo json_encode(['ok'=>$r['ok'],'message'=>$r['ok'] ? 'Container removed' : ($r['error'] ?: 'Remove failed'),'status'=>$r['status']]);
        exit;
    }

    if ($api === 'detail_data') {
        $cid = trim($_GET['container'] ?? '');
        if (!$eid || $cid === '') { echo json_encode(['ok'=>false,'error'=>'No container']); exit; }
        $insp = nm_portainer_container_inspect($cfg, $eid, $cid, true);
        if (!$insp['ok']) { echo json_encode(['ok'=>false,'error'=>$insp['error']]); exit; }
        $detail = ctr_norm_inspect($insp['data']);
        $stats = null;
        if ($detail['running']) { $s = nm_portainer_container_stats($cfg, $eid, $cid); if ($s['ok']) $stats = nm_portainer_norm_stats($s['data']); }
        echo json_encode(['ok'=>true,'detail'=>$detail,'stats'=>$stats,'at'=>date('H:i:s')]);
        exit;
    }

    if ($api === 'stats_data') {
        $cid = trim($_GET['container'] ?? '');
        if (!$eid || $cid === '') { echo json_encode(['ok'=>false,'error'=>'No container']); exit; }
        $s = nm_portainer_container_stats($cfg, $eid, $cid);
        if (!$s['ok']) { echo json_encode(['ok'=>false,'error'=>$s['error']]); exit; }
        echo json_encode(['ok'=>true,'stats'=>nm_portainer_norm_stats($s['data']),'at'=>date('H:i:s')]);
        exit;
    }

    if ($api === 'images_data') {
        if (!$eid) { echo json_encode(['ok'=>false,'error'=>'No endpoint']); exit; }
        $df = nm_portainer_system_df($cfg, $eid);
        if (!$df['ok']) { echo json_encode(['ok'=>false,'error'=>$df['error']]); exit; }
        [$rows,$sum] = nm_portainer_norm_images($df['data']);
        echo json_encode(['ok'=>true,'images'=>$rows,'summary'=>$sum,'at'=>date('H:i:s')]);
        exit;
    }

    if ($api === 'images_prune') {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $all = ($_POST['scope'] ?? 'dangling') === 'all';
        $r = nm_portainer_images_prune($cfg, $eid, $all);
        $freed = is_array($r['data']) ? (int)($r['data']['SpaceReclaimed'] ?? 0) : 0;
        $deleted = is_array($r['data']) ? count($r['data']['ImagesDeleted'] ?? []) : 0;
        nm_audit($conn, 'container.images_prune', ['target_type'=>'docker','target_id'=>'endpoint:'.$eid,
            'details'=>['scope'=>$all?'all-unused':'dangling','freed'=>$freed,'deleted'=>$deleted,'ok'=>$r['ok']]]);
        echo json_encode(['ok'=>$r['ok'],'message'=>$r['ok'] ? "Pruned {$deleted} image layer(s), freed ".ctr_bytes($freed) : $r['error'],'freed'=>$freed]);
        exit;
    }

    if ($api === 'image_remove') {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $id = trim($_POST['image'] ?? ''); $force = ($_POST['force'] ?? '') === '1';
        if (!$eid || $id === '') { echo json_encode(['ok'=>false,'error'=>'Bad request']); exit; }
        $r = nm_portainer_image_remove($cfg, $eid, $id, $force);
        nm_audit($conn, 'container.image_remove', ['target_type'=>'docker_image','target_id'=>$id,
            'details'=>['endpoint'=>$eid,'force'=>$force,'ok'=>$r['ok'],'status'=>$r['status']]]);
        echo json_encode(['ok'=>$r['ok'],'message'=>$r['ok'] ? 'Image removed' : $r['error']]);
        exit;
    }

    if ($api === 'net_sample') {
        if (!$eid) { echo json_encode(['ok'=>false,'error'=>'No endpoint']); exit; }
        [$rows,$err] = ctr_net_sample($conn, $cfg, $eid);
        if ($err) { echo json_encode(['ok'=>false,'error'=>$err]); exit; }
        $top = nm_netstats_top($conn, $eid, 1, 8);   // last-hour top talkers (persisted-history payoff)
        echo json_encode(['ok'=>true,'rows'=>$rows,'top1h'=>$top,'at'=>date('H:i:s')]);
        exit;
    }

    // Per-container traffic history from our DB (RX/TX rate over time) — own charts.
    if ($api === 'net_history') {
        $cid = trim($_GET['container'] ?? '');
        if ($cid === '') { echo json_encode(['ok'=>false,'error'=>'No container']); exit; }
        if ($conn->query("SHOW TABLES LIKE 'container_net_samples'")->num_rows === 0) { echo json_encode(['ok'=>true,'times'=>[],'rx'=>[],'tx'=>[]]); exit; }
        $hours = max(1, min(720, (int)($_GET['hours'] ?? 6)));
        if     ($hours <= 6)  $grp = "DATE_FORMAT(sampled_at,'%Y-%m-%d %H:%i:00')";   // per-minute
        elseif ($hours <= 48) $grp = "DATE_FORMAT(DATE_SUB(sampled_at, INTERVAL MINUTE(sampled_at)%5 MINUTE),'%Y-%m-%d %H:%i:00')";  // 5-min
        else                  $grp = "DATE_FORMAT(sampled_at,'%Y-%m-%d %H:00:00')";   // hourly
        $sql = "SELECT DATE_FORMAT(MIN(sampled_at),'%Y-%m-%dT%H:%i:%S') t,
                       ROUND(AVG(rx_rate)) rx, ROUND(AVG(tx_rate)) tx
                FROM container_net_samples
                WHERE container_id=? AND endpoint_id=? AND sampled_at >= (UTC_TIMESTAMP() - INTERVAL ? HOUR)
                GROUP BY {$grp} ORDER BY t";
        $st = $conn->prepare($sql); $st->bind_param('sii', $cid, $eid, $hours); $st->execute();
        $rows = $st->get_result()->fetch_all(MYSQLI_ASSOC);
        $times=[]; $rx=[]; $tx=[];
        foreach ($rows as $r) { $times[]=$r['t']; $rx[]=(float)$r['rx']; $tx[]=(float)$r['tx']; }
        $ov = $conn->prepare("SELECT ROUND(AVG(rx_rate)) arx, ROUND(AVG(tx_rate)) atx, ROUND(MAX(rx_rate)) prx, ROUND(MAX(tx_rate)) ptx,
                              (MAX(rx_bytes)-MIN(rx_bytes)) drx, (MAX(tx_bytes)-MIN(tx_bytes)) dtx, COUNT(*) n
                              FROM container_net_samples WHERE container_id=? AND endpoint_id=? AND sampled_at >= (UTC_TIMESTAMP() - INTERVAL ? HOUR)");
        $ov->bind_param('sii', $cid, $eid, $hours); $ov->execute(); $sum = $ov->get_result()->fetch_assoc();
        echo json_encode(['ok'=>true,'times'=>$times,'rx'=>$rx,'tx'=>$tx,'summary'=>$sum]);
        exit;
    }

    // ── Container-network alerts (mirror of the Smokeping latency alerts) ──────
    if ($api === 'netalerts')        { echo json_encode(['ok'=>true] + nm_netalert_active($conn)); exit; }
    if ($api === 'netthresholds_get'){ echo json_encode(['ok'=>true] + nm_netalert_thresholds($conn)); exit; }
    if ($api === 'neteval')          { echo json_encode(nm_netalert_eval($conn)); exit; }
    if ($api === 'netthresholds_save') {
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
        $key = trim($_POST['scope'] ?? '');
        if ($key === '') { echo json_encode(['ok'=>false,'error'=>'scope required']); exit; }
        $empty = trim($_POST['rx_warn']??'')==='' && trim($_POST['rx_crit']??'')==='' && trim($_POST['tx_warn']??'')==='' && trim($_POST['tx_crit']??'');
        if ($empty && $key !== '__global__') nm_netalert_threshold_clear($conn, $key);
        else nm_netalert_threshold_save($conn, $key, ['rx_warn'=>$_POST['rx_warn']??'','rx_crit'=>$_POST['rx_crit']??'','tx_warn'=>$_POST['tx_warn']??'','tx_crit'=>$_POST['tx_crit']??'']);
        nm_audit($conn, 'container.netthreshold_save', ['target_type'=>'container','target_id'=>$key,'details'=>['cleared'=>($empty && $key!=='__global__')]]);
        echo json_encode(['ok'=>true,'cleared'=>($empty && $key!=='__global__')]);
        exit;
    }

    echo json_encode(['ok'=>false,'error'=>'Unknown endpoint']);
    exit;
}

// ── Page load ─────────────────────────────────────────────────────────────────
$configured = nm_portainer_configured($cfg);
$view = in_array($_GET['view'] ?? '', ['overview','detail','stats','volumes','images','network']) ? $_GET['view'] : 'overview';
$endpoints = $configured ? ctr_endpoints($cfg) : [];
$selected  = $endpoints ? ctr_pick($endpoints, $_GET['endpoint'] ?? 0) : 0;

$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
include('header.php');
log_user_action($conn, 'view_page', 'containers.php');
// Selecting a host is a full page navigation that preloads its data below via slow Portainer
// calls. Release the session lock FIRST so a down host can't freeze every other portal page
// while this one waits (the pre-flight in ctr_overview already fast-fails a known-down host).
if (function_exists('session_write_close')) session_write_close();

// Preload view-specific data (server-rendered first paint; JS keeps it live)
$ov_containers = $ov_summary = $ov_engine = null; $ov_err = '';
$siblings = []; $detail = null; $dstats = null; $sel_cid = trim($_GET['container'] ?? '');
$vol_rows = []; $vol_sum = null; $vol_err = '';
$run_list = [];
$img_rows = []; $img_sum = null; $img_err = '';
$net_list = []; $net_err = '';
if ($configured && $selected) {
    if ($view === 'overview') {
        [$ov_containers,$ov_summary,$ov_engine,$ov_err] = ctr_overview($cfg, $selected);
    } elseif ($view === 'detail') {
        $cr = nm_portainer_containers($cfg, $selected, true);
        foreach (($cr['ok'] ? (array)$cr['data'] : []) as $c) { $n = nm_portainer_norm_container($c); $siblings[] = ['cid'=>$n['cid'],'name'=>$n['name'],'state'=>$n['state']]; }
        usort($siblings, fn($a,$b)=>[ctr_state_rank($a['state']),$a['name']]<=>[ctr_state_rank($b['state']),$b['name']]);
        if ($sel_cid === '' && $siblings) $sel_cid = $siblings[0]['cid'];
        if ($sel_cid) {
            $insp = nm_portainer_container_inspect($cfg, $selected, $sel_cid, true);
            if ($insp['ok']) { $detail = ctr_norm_inspect($insp['data']);
                if ($detail['running']) { $s = nm_portainer_container_stats($cfg, $selected, $sel_cid); if ($s['ok']) $dstats = nm_portainer_norm_stats($s['data']); } }
            else $ov_err = $insp['error'];
        }
    } elseif ($view === 'stats') {
        $cr = nm_portainer_containers($cfg, $selected, true);
        foreach (($cr['ok'] ? (array)$cr['data'] : []) as $c) { $n = nm_portainer_norm_container($c); if ($n['state']==='running') $run_list[] = ['cid'=>$n['cid'],'name'=>$n['name']]; }
        if ($sel_cid === '' && $run_list) $sel_cid = $run_list[0]['cid'];
    } elseif ($view === 'volumes') {
        $df = nm_portainer_system_df($cfg, $selected);
        if ($df['ok']) [$vol_rows,$vol_sum] = ctr_norm_volumes($df['data']); else $vol_err = $df['error'];
    } elseif ($view === 'images') {
        $df = nm_portainer_system_df($cfg, $selected);
        if ($df['ok']) [$img_rows,$img_sum] = nm_portainer_norm_images($df['data']); else $img_err = $df['error'];
    } elseif ($view === 'network') {
        ctr_net_ensure($conn);
        $nw = nm_portainer_networks($cfg, $selected);
        if ($nw['ok']) $net_list = ctr_norm_networks($nw['data']); else $net_err = $nw['error'];
    }
}
function ctr_bytes($b){ $b=(float)$b; if($b<=0)return '—'; $u=['B','KB','MB','GB','TB']; $i=0; while($b>=1024&&$i<4){$b/=1024;$i++;} return round($b, $i?1:0).' '.$u[$i]; }
function ctr_dot($state){ return ['running'=>'ok','restarting'=>'warn','paused'=>'idle','exited'=>'stop','dead'=>'stop','created'=>'idle'][$state] ?? 'idle'; }
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Containers | SG-PR Console</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --docker:#0db7ed;
       --ok:#2ecc71; --warn:#f39c12; --stop:#e74c3c; --idle:#8a909a; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.25; }
.wrap{ max-width:1400px; margin:0 auto; padding:18px 20px 60px; }
a{ color:var(--accent); text-decoration:none; }
.ctr-head{ display:flex; align-items:center; gap:14px; flex-wrap:wrap; margin-bottom:14px; }
.ctr-head h1{ margin:0; font-size:22px; font-weight:700; } .ctr-head h1 i{ color:var(--docker); }
.ctr-subnav{ display:flex; gap:4px; flex-wrap:wrap; margin-bottom:16px; border-bottom:1px solid var(--border); }
.ctr-subtab{ padding:8px 14px; font-size:13px; color:#9aa; border-bottom:2px solid transparent; cursor:pointer; display:inline-flex; gap:7px; align-items:center; }
.ctr-subtab:hover{ color:#fff; } .ctr-subtab.is-active{ color:var(--docker); border-bottom-color:var(--docker); font-weight:600; }
.ctr-subtab .soon{ font-size:8px; background:rgba(255,255,255,.1); color:#888; padding:1px 5px; border-radius:8px; text-transform:uppercase; }
.envbar{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:14px; }
select,input[type=text]{ background:rgba(0,0,0,.4); border:1px solid var(--border); color:#ddd; border-radius:8px; padding:7px 11px; font-size:13px; outline:none; }
select:focus,input:focus{ border-color:var(--accent); }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.stat-grid{ display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:12px; margin-bottom:16px; }
.stat{ padding:13px 16px; } .stat .n{ font-size:24px; font-weight:800; } .stat .l{ font-size:10px; text-transform:uppercase; letter-spacing:1px; color:#888; margin-top:3px; }
.stat .n.ok{ color:var(--ok);} .stat .n.warn{ color:var(--warn);} .stat .n.stop{ color:var(--stop);} .stat .n.idle{ color:var(--idle);}
table{ width:100%; border-collapse:collapse; font-size:13px; }
th{ text-align:left; padding:9px 12px; font-size:10px; text-transform:uppercase; letter-spacing:1px; color:#7c828c; border-bottom:1px solid var(--border); }
td{ padding:9px 12px; border-bottom:1px solid rgba(255,255,255,.05); }
tr:hover td{ background:rgba(255,255,255,.03); }
.dot{ width:9px; height:9px; border-radius:50%; display:inline-block; margin-right:7px; vertical-align:middle; }
.dot.ok{ background:var(--ok);} .dot.warn{ background:var(--warn);} .dot.stop{ background:var(--stop);} .dot.idle{ background:var(--idle);}
.cname{ font-weight:600; } .cimg{ color:#7c828c; font-size:11px; font-family:monospace; }
.btn{ background:rgba(255,255,255,.06); border:1px solid var(--border); color:#cfd3da; padding:5px 10px; border-radius:7px; cursor:pointer; font-size:11px; display:inline-flex; gap:5px; align-items:center; }
.btn:hover{ background:rgba(255,255,255,.13); color:#fff; }
.btn.go:hover{ border-color:var(--ok); color:var(--ok);} .btn.stop:hover{ border-color:var(--stop); color:var(--stop);} .btn.warn:hover{ border-color:var(--warn); color:var(--warn);}
.empty{ text-align:center; color:#667; padding:50px 20px; } .empty i{ font-size:40px; color:#333; display:block; margin-bottom:12px; }
.ctr-error{ background:rgba(231,76,60,.1); border:1px solid rgba(231,76,60,.3); color:#e88; border-radius:12px; padding:14px 18px; margin-bottom:14px; }
.chips{ display:flex; gap:10px; flex-wrap:wrap; margin-bottom:14px; }
.chip{ padding:8px 12px; } .chip .n{ font-size:18px; font-weight:700; } .chip .l{ font-size:10px; color:#888; text-transform:uppercase; letter-spacing:1px; }
.cards2{ display:grid; grid-template-columns:1fr 1fr; gap:18px; margin-bottom:18px; } @media(max-width:900px){ .cards2{ grid-template-columns:1fr; } }
.card{ padding:16px 18px; } .card h3{ margin:0 0 12px; font-size:13px; color:var(--accent); text-transform:uppercase; letter-spacing:1px; }
.dl{ display:grid; grid-template-columns:auto 1fr; gap:6px 14px; font-size:12.5px; } .dl dt{ color:#7c828c; } .dl dd{ margin:0; color:#dfe3e8; word-break:break-word; }
.badge{ font-size:10px; font-weight:700; padding:2px 8px; border-radius:6px; text-transform:uppercase; }
.b-run{ background:rgba(46,204,113,.16); color:var(--ok);} .b-stop{ background:rgba(231,76,60,.16); color:var(--stop);} .b-idle{ background:rgba(138,144,154,.16); color:var(--idle);}
canvas{ width:100%; height:200px; }
.metric-chip{ padding:11px 14px; } .metric-chip .n{ font-size:19px; font-weight:700; } .metric-chip .l{ font-size:10px; color:#888; text-transform:uppercase; }
.mono{ font-family:Consolas,monospace; font-size:11.5px; }
.spin-dot{ width:13px; height:13px; border:2px solid rgba(255,255,255,.2); border-top-color:var(--accent); border-radius:50%; display:inline-block; animation:csp .7s linear infinite; vertical-align:middle; } @keyframes csp{ to{ transform:rotate(360deg);} }
.net-spark{ display:block; }
.b-crit{ background:rgba(231,76,60,.18); color:var(--stop);} .b-warn{ background:rgba(243,156,18,.18); color:var(--warn);}
.al-row{ display:flex; align-items:center; gap:12px; padding:9px 4px; border-bottom:1px solid rgba(255,255,255,.05); font-size:13px; } .al-row:last-child{ border-bottom:0; }
.modal-bg{ position:fixed; inset:0; background:rgba(0,0,0,.6); display:none; align-items:center; justify-content:center; z-index:2000; } .modal-bg.show{ display:flex; }
.modal{ background:#0f1722; border:1px solid var(--border); border-radius:14px; padding:20px 22px; width:390px; max-width:92vw; }
.modal h3{ margin:0 0 4px; font-size:15px; color:#fff; text-transform:none; letter-spacing:0; } .modal .sub{ font-size:11px; color:#7c828c; margin-bottom:14px; }
.modal label{ font-size:11px; color:#9aa; display:block; margin-bottom:4px; } .modal input{ width:100%; background:rgba(0,0,0,.4); border:1px solid var(--border); color:#ddd; border-radius:8px; padding:8px 10px; font-size:13px; }
/* ── Deploy wizard (futuristic) ── */
.deploy-btn{ display:inline-flex;align-items:center;gap:8px;background:linear-gradient(100deg,rgba(58,160,255,.22),rgba(54,227,208,.14));border:1px solid rgba(58,160,255,.55);color:#9fdcff;padding:8px 16px;border-radius:10px;font-size:13px;font-weight:700;cursor:pointer;white-space:nowrap;box-shadow:0 0 14px rgba(58,160,255,.18); }
.deploy-btn:hover{ background:linear-gradient(100deg,rgba(58,160,255,.4),rgba(54,227,208,.28));color:#fff;box-shadow:0 0 22px rgba(58,160,255,.35); }
.dpl-ov{ position:fixed;inset:0;z-index:1000;background:rgba(3,6,12,.78);backdrop-filter:blur(7px);display:none;align-items:flex-start;justify-content:center;padding:5vh 16px;overflow:auto; }
.dpl-ov.show{ display:flex; }
.dpl{ width:100%;max-width:880px;background:linear-gradient(160deg,#0c1320,#0a0f1a);border:1px solid rgba(58,160,255,.35);border-radius:18px;box-shadow:0 24px 70px rgba(0,0,0,.6),0 0 50px rgba(58,160,255,.12);overflow:hidden; }
.dpl-h{ display:flex;align-items:center;gap:12px;padding:18px 22px;border-bottom:1px solid rgba(255,255,255,.08);background:radial-gradient(120% 100% at 0% 0%,rgba(58,160,255,.12),transparent); }
.dpl-h .rk{ font-size:22px;color:#4da3ff; } .dpl-h h2{ margin:0;font-size:18px; } .dpl-h .x{ margin-left:auto;cursor:pointer;color:#8a93a3;font-size:20px; } .dpl-h .x:hover{ color:#fff; }
.dpl-steps{ display:flex;gap:6px;padding:14px 22px 0; }
.dpl-steps .st{ flex:1;height:4px;border-radius:3px;background:rgba(255,255,255,.1); } .dpl-steps .st.on{ background:linear-gradient(90deg,#4da3ff,#36e3d0); }
.dpl-body{ padding:18px 22px 22px;min-height:300px; }
.dpl-grid{ display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:11px; }
.tpl{ background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:13px;padding:14px;cursor:pointer;transition:.15s;position:relative; }
.tpl:hover{ border-color:#4da3ff;transform:translateY(-2px);background:rgba(77,163,255,.08); }
.tpl .ic{ font-size:24px;color:#6cb4ff;margin-bottom:8px; } .tpl .nm{ font-weight:700;font-size:13.5px; } .tpl .im{ font-size:10.5px;color:#7c828c;font-family:monospace;margin-top:3px;word-break:break-all; }
.tpl .cat{ position:absolute;top:9px;right:9px;font-size:8.5px;text-transform:uppercase;letter-spacing:.5px;color:#8a93a3;background:rgba(255,255,255,.06);padding:2px 6px;border-radius:5px; }
.tpl .del{ position:absolute;top:7px;right:7px;color:#e74c3c;display:none; } .tpl:hover .del.show{ display:inline; }
.dpl-cat{ font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#5a6472;margin:14px 0 7px; }
.dplf label{ font-size:11px;color:#9fb0c4;display:block;margin:0 0 4px; } .dplf input,.dplf select{ width:100%;background:rgba(0,0,0,.4);border:1px solid var(--border);color:#e7ecf3;border-radius:8px;padding:8px 10px;font-size:13px;box-sizing:border-box; }
.dpl-row{ display:flex;gap:8px;margin-bottom:8px; } .dpl-row input{ flex:1; } .dpl-row .rm{ background:rgba(231,76,60,.12);border:1px solid rgba(231,76,60,.4);color:#ff9b8f;border-radius:8px;padding:0 11px;cursor:pointer; }
.addbtn{ background:transparent;border:1px dashed var(--border);color:#9fb0c4;border-radius:8px;padding:6px 11px;font-size:12px;cursor:pointer; } .addbtn:hover{ border-color:#4da3ff;color:#fff; }
.dpl-foot{ display:flex;gap:10px;align-items:center;padding:16px 22px;border-top:1px solid rgba(255,255,255,.08); }
.dpl-foot .gobtn{ background:linear-gradient(100deg,#3aa0ff,#36e3d0);color:#04243f;border:none;border-radius:10px;padding:11px 22px;font-size:14px;font-weight:800;cursor:pointer; } .dpl-foot .gobtn:disabled{ opacity:.5;cursor:default; }
.dpl-foot .ghost{ background:transparent;border:1px solid var(--border);color:#bcc8d6;border-radius:10px;padding:10px 16px;cursor:pointer; }
.dpl-log{ font-family:Consolas,monospace;font-size:12.5px;background:rgba(0,0,0,.5);border:1px solid rgba(255,255,255,.1);border-radius:10px;padding:14px;min-height:160px; }
.dpl-log .ln{ padding:3px 0;color:#bcc8d6; } .dpl-log .ln.ok{ color:#2ecc71; } .dpl-log .ln.err{ color:#e74c3c; } .dpl-log .ln .sp{ color:#4da3ff; }
.imgdd{ display:none;position:absolute;left:0;right:0;top:100%;z-index:30;margin-top:3px;background:#0d1422;border:1px solid var(--border);border-radius:10px;max-height:240px;overflow:auto;box-shadow:0 14px 36px rgba(0,0,0,.55); }
.imgdd .imi{ padding:8px 11px;cursor:pointer;border-bottom:1px solid rgba(255,255,255,.05); } .imgdd .imi:hover{ background:rgba(77,163,255,.12); }
.imgdd .imi b{ font-size:13px;color:#e7ecf3; } .imgdd .imi .off{ font-size:9px;color:#2ecc71;border:1px solid rgba(46,204,113,.4);border-radius:4px;padding:0 5px;margin-left:7px; }
.imgdd .imi .st{ float:right;font-size:11px;color:#f0a93a; } .imgdd .imi .ds{ font-size:11px;color:#8a93a3;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis; }
<?= nm_chrome_css() ?>
</style>
</head>
<body>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>

<div class="wrap">
    <?php
    $envq = $selected ? ('&endpoint='.$selected) : '';
    $meta = ($configured && $ov_engine)
        ? '<span class="header-meta">'.htmlspecialchars($ov_engine['name']).' · Docker '.htmlspecialchars($ov_engine['version']).' · '.(int)$ov_engine['cpus'].' CPU · '.ctr_bytes($ov_engine['memory']).'</span>'
        : '';
    $right = $meta
        . '<span id="clock" style="font-size:11px;color:#667;"></span>'
        . '<label class="refresh-btn" style="cursor:pointer;"><input type="checkbox" id="auto" checked style="margin:0;"> Live</label>';
    nm_page_header('<i class="fab fa-docker"></i>Containers', '', 'Container Operations', 'fa-brands fa-docker', $right);
    ?>

    <!-- subnav -->
    <?php nm_container_tabs($view, $envq); ?>

<?php if (!$configured): ?>
    <div class="glass empty"><i class="fab fa-docker"></i>
        <div style="font-size:16px;color:#aaa;">Portainer isn't connected yet.</div>
        <div style="font-size:12px;color:#667;margin-top:6px;">Add your server in
            <a href="net_mon_config.php?tab=containers">Config → Containers</a>.</div></div>
<?php else: ?>

    <!-- environment selector -->
    <div class="envbar">
        <i class="fas fa-server" style="color:#667;"></i>
        <select id="env" onchange="location.href='containers.php?view=<?= $view ?>&endpoint='+this.value<?= $sel_cid?"+'&container=".htmlspecialchars($sel_cid,ENT_QUOTES)."'":'' ?>">
            <?php foreach ($endpoints as $e): ?>
            <option value="<?= $e['id'] ?>" <?= $e['id']===$selected?'selected':'' ?>><?= htmlspecialchars($e['name']) ?><?= $e['up']?'':' (down)' ?></option>
            <?php endforeach; ?>
        </select>
        <?php if (in_array($view,['detail','stats'])): ?>
        <i class="fas fa-cube" style="color:#667;margin-left:6px;"></i>
        <select id="cont" onchange="location.href='containers.php?view=<?= $view ?>&endpoint=<?= $selected ?>&container='+encodeURIComponent(this.value)">
            <?php foreach (($view==='detail'?$siblings:$run_list) as $s): ?>
            <option value="<?= htmlspecialchars($s['cid']) ?>" <?= $s['cid']===$sel_cid?'selected':'' ?>><?= htmlspecialchars($s['name']) ?><?= $view==='detail'&&isset($s['state'])?' · '.$s['state']:'' ?></option>
            <?php endforeach; ?>
        </select>
        <?php endif ?>
        <button class="deploy-btn" style="margin-left:auto;" onclick="deployOpen()"><i class="fas fa-rocket"></i> Deploy container</button>
    </div>

    <?php if ($ov_err): ?><div class="ctr-error"><i class="fas fa-triangle-exclamation"></i> <?= htmlspecialchars($ov_err) ?></div><?php endif ?>

    <?php // ─────────── OVERVIEW ─────────── ?>
    <?php if ($view === 'overview'): ?>
    <div class="stat-grid" id="summary" data-endpoint="<?= $selected ?>">
        <?php foreach (['total'=>['','Total'],'running'=>['ok','Running'],'stopped'=>['stop','Stopped'],'paused'=>['idle','Paused'],'restarting'=>['warn','Restarting'],'unhealthy'=>['warn','Unhealthy']] as $k=>$m): ?>
        <div class="glass stat"><div class="n <?= $m[0] ?>" data-k="<?= $k ?>"><?= (int)($ov_summary[$k] ?? 0) ?></div><div class="l"><?= $m[1] ?></div></div>
        <?php endforeach; ?>
    </div>
    <div class="glass" style="overflow:hidden;">
        <table><thead><tr><th>Container</th><th>State</th><th>Status</th><th>Stack</th><th>Ports</th><th style="text-align:right;">Actions</th></tr></thead>
        <tbody id="ctbody">
        <?php if (!$ov_containers): ?>
            <tr><td colspan="6" class="empty" style="padding:30px;"><i class="fab fa-docker"></i>No containers.</td></tr>
        <?php else: foreach ($ov_containers as $c):
            $ports = implode(' ', array_slice($c['ports'],0,3)) . (count($c['ports'])>3 ? ' +'.(count($c['ports'])-3) : '');
            $acts = '';
            if ($c['state']==='running')      $btns = [['pause','Pause','warn','fa-pause'],['restart','Restart','','fa-rotate'],['stop','Stop','stop','fa-stop'],['kill','Kill','stop','fa-skull']];
            elseif ($c['state']==='paused')   $btns = [['unpause','Resume','go','fa-play'],['stop','Stop','stop','fa-stop']];
            else                              $btns = [['start','Start','go','fa-play'],['restart','Restart','','fa-rotate']];
            foreach ($btns as $b) $acts .= '<button class="btn '.$b[2].'" onclick="ctrAct(\''.$c['cid'].'\',\''.$b[0].'\',\''.htmlspecialchars($c['name'],ENT_QUOTES).'\')"><i class="fas '.$b[3].'"></i> '.$b[1].'</button> ';
            $acts .= '<button class="btn stop" title="Remove container" onclick="ctrRemove(\''.$c['cid'].'\',\''.htmlspecialchars($c['name'],ENT_QUOTES).'\','.($c['state']==='running'?1:0).')"><i class="fas fa-trash"></i> Remove</button> ';
        ?>
            <tr><td><span class="dot <?= ctr_dot($c['state']) ?>"></span>
                <a class="cname" href="containers.php?view=detail&endpoint=<?= $selected ?>&container=<?= urlencode($c['cid']) ?>"><?= htmlspecialchars($c['name']) ?></a>
                <div class="cimg"><?= htmlspecialchars($c['image']) ?></div></td>
                <td><?= htmlspecialchars($c['state']) ?></td><td style="color:#9aa;"><?= htmlspecialchars($c['status']) ?></td>
                <td style="color:#9aa;"><?= htmlspecialchars($c['stack'] ?: '—') ?></td>
                <td class="mono" style="font-size:10.5px;color:#778;"><?= htmlspecialchars($ports ?: '—') ?></td>
                <td style="text-align:right;white-space:nowrap;"><?= $acts ?></td></tr>
        <?php endforeach; endif ?>
        </tbody></table>
    </div>

    <?php // ─────────── DETAIL ─────────── ?>
    <?php elseif ($view === 'detail'): ?>
        <?php if (!$detail): ?>
        <div class="glass empty"><i class="fas fa-cube"></i><div>No container selected.</div></div>
        <?php else: $bcls = $detail['running']?'b-run':($detail['paused']?'b-idle':'b-stop'); ?>
        <div id="dwrap" data-endpoint="<?= $selected ?>" data-cid="<?= htmlspecialchars($detail['id']) ?>">
        <div class="ctr-head" style="margin-bottom:18px;">
            <span class="dot <?= ctr_dot($detail['state']) ?>" style="width:13px;height:13px;"></span>
            <span style="font-size:18px;font-weight:700;"><?= htmlspecialchars($detail['name']) ?></span>
            <span class="badge <?= $bcls ?>" id="d-state"><?= htmlspecialchars($detail['state'] ?: 'unknown') ?></span>
            <?php if ($detail['health']): ?><span class="badge <?= $detail['health']==='healthy'?'b-run':'b-stop' ?>"><?= htmlspecialchars($detail['health']) ?></span><?php endif ?>
            <span class="cimg" style="margin-left:6px;"><?= htmlspecialchars($detail['image']) ?></span>
        </div>
        <!-- live metric tiles -->
        <div class="stat-grid">
            <div class="glass metric-chip"><div class="n" data-m="cpu"><?= $dstats?round($dstats['cpu_pct'],1).'%':'—' ?></div><div class="l">CPU</div></div>
            <div class="glass metric-chip"><div class="n" data-m="mem"><?= $dstats?round($dstats['mem_pct'],1).'%':'—' ?></div><div class="l">Memory</div></div>
            <div class="glass metric-chip"><div class="n mono" data-m="memb" style="font-size:14px;"><?= $dstats?ctr_bytes($dstats['mem_used_b']).' / '.ctr_bytes($dstats['mem_limit']):'—' ?></div><div class="l">Mem used</div></div>
            <div class="glass metric-chip"><div class="n mono" data-m="net" style="font-size:14px;"><?= $dstats?'↓'.ctr_bytes($dstats['net_rx']).' ↑'.ctr_bytes($dstats['net_tx']):'—' ?></div><div class="l">Network</div></div>
            <div class="glass metric-chip"><div class="n" data-m="pids"><?= $dstats?(int)$dstats['pids']:'—' ?></div><div class="l">PIDs</div></div>
        </div>
        <div class="cards2">
            <div class="glass card"><h3>Runtime & Resources</h3><div class="dl">
                <dt>Image</dt><dd class="mono"><?= htmlspecialchars($detail['image']) ?></dd>
                <dt>Command</dt><dd class="mono"><?= htmlspecialchars($detail['command'] ?: '—') ?></dd>
                <dt>Restart policy</dt><dd><?= htmlspecialchars($detail['restart_policy'] ?: '—') ?> (count <?= $detail['restart_count'] ?>)</dd>
                <dt>Mem limit</dt><dd><?= $detail['mem_limit']?ctr_bytes($detail['mem_limit']):'unlimited' ?></dd>
                <dt>Network mode</dt><dd><?= htmlspecialchars($detail['network_mode'] ?: '—') ?></dd>
                <dt>Privileged</dt><dd><?= $detail['privileged']?'<span style="color:var(--warn)">yes</span>':'no' ?></dd>
                <dt>PID / exit</dt><dd><?= $detail['pid'] ?> / <?= $detail['exit_code'] ?><?= $detail['oom_killed']?' <span style="color:var(--stop)">OOM-killed</span>':'' ?></dd>
                <dt>Disk (rw/root)</dt><dd><?= ctr_bytes($detail['size_rw']) ?> / <?= ctr_bytes($detail['size_root']) ?></dd>
            </div></div>
            <div class="glass card"><h3>Networking</h3>
                <?php if ($detail['networks']): ?><div class="dl">
                <?php foreach ($detail['networks'] as $n): ?>
                    <dt><?= htmlspecialchars($n['name']) ?></dt><dd class="mono"><?= htmlspecialchars($n['ip'] ?: '—') ?><?= $n['gateway']?' → '.htmlspecialchars($n['gateway']):'' ?></dd>
                <?php endforeach; ?></div><?php else: ?><div style="color:#667;font-size:12px;">No networks.</div><?php endif ?>
                <h3 style="margin-top:16px;">Mounts</h3>
                <?php if ($detail['mounts']): ?><div class="mono" style="font-size:11px;color:#9aa;">
                <?php foreach ($detail['mounts'] as $m): ?><div><?= htmlspecialchars($m['name'] ?: $m['source']) ?> → <?= htmlspecialchars($m['dest']) ?> <?= $m['rw']?'':'(ro)' ?></div><?php endforeach; ?>
                </div><?php else: ?><div style="color:#667;font-size:12px;">No mounts.</div><?php endif ?>
            </div>
        </div>
        <?php if ($detail['env']): ?>
        <div class="glass card" style="margin-top:14px;"><h3>Environment <span style="color:#556;font-weight:400;text-transform:none;">(secrets redacted)</span></h3>
            <div class="mono" style="font-size:11px;color:#9aa;columns:2;column-gap:24px;">
            <?php foreach ($detail['env'] as $e): ?><div><span style="color:#7fb">​<?= htmlspecialchars($e['k']) ?></span>=<?= htmlspecialchars($e['v']) ?></div><?php endforeach; ?>
            </div></div>
        <?php endif ?>
        </div>
        <?php endif ?>

    <?php // ─────────── STATS ─────────── ?>
    <?php elseif ($view === 'stats'): ?>
        <?php if (!$sel_cid): ?><div class="glass empty"><i class="fas fa-chart-line"></i><div>No running containers to chart.</div></div>
        <?php else: ?>
        <div id="swrap" data-endpoint="<?= $selected ?>" data-cid="<?= htmlspecialchars($sel_cid) ?>">
        <div class="chips">
            <div class="glass chip"><div class="n" data-m="cpu" style="color:var(--accent)">—</div><div class="l">CPU %</div></div>
            <div class="glass chip"><div class="n" data-m="mem" style="color:#9b59b6">—</div><div class="l">Mem %</div></div>
            <div class="glass chip"><div class="n mono" data-m="memb" style="font-size:14px;">—</div><div class="l">Mem used</div></div>
            <div class="glass chip"><div class="n mono" data-m="rx" style="font-size:14px;">—</div><div class="l">Net RX</div></div>
            <div class="glass chip"><div class="n mono" data-m="tx" style="font-size:14px;">—</div><div class="l">Net TX</div></div>
            <div class="glass chip"><div class="n" data-m="pids">—</div><div class="l">PIDs</div></div>
        </div>
        <div class="cards2">
            <div class="glass card"><h3>CPU %</h3><canvas id="chart-cpu"></canvas></div>
            <div class="glass card"><h3>Memory %</h3><canvas id="chart-mem"></canvas></div>
        </div>
        </div>
        <?php endif ?>

    <?php // ─────────── VOLUMES ─────────── ?>
    <?php elseif ($view === 'volumes'): ?>
        <?php if ($vol_err): ?><div class="ctr-error"><i class="fas fa-triangle-exclamation"></i> <?= htmlspecialchars($vol_err) ?></div><?php endif ?>
        <div class="stat-grid">
            <div class="glass stat"><div class="n"><?= (int)($vol_sum['total'] ?? 0) ?></div><div class="l">Total</div></div>
            <div class="glass stat"><div class="n ok"><?= (int)($vol_sum['used'] ?? 0) ?></div><div class="l">In use</div></div>
            <div class="glass stat"><div class="n idle"><?= (int)($vol_sum['unused'] ?? 0) ?></div><div class="l">Unused</div></div>
            <div class="glass stat"><div class="n warn"><?= ctr_bytes($vol_sum['reclaimable'] ?? 0) ?></div><div class="l">Reclaimable</div></div>
        </div>
        <div class="glass" style="overflow:hidden;">
            <table><thead><tr><th></th><th>Name</th><th>Driver</th><th>Size</th><th>Refs</th><th>Stack</th><th>Mountpoint</th></tr></thead><tbody>
            <?php if (!$vol_rows): ?><tr><td colspan="7" class="empty" style="padding:30px;"><i class="fas fa-hard-drive"></i>No volumes.</td></tr>
            <?php else: foreach ($vol_rows as $v): ?>
            <tr><td><span class="dot <?= $v['in_use']?'ok':'idle' ?>"></span></td>
                <td class="cname" style="word-break:break-all;"><?= htmlspecialchars($v['name']) ?></td>
                <td style="color:#9aa;"><?= htmlspecialchars($v['driver']) ?></td>
                <td><?= $v['size']>=0?ctr_bytes($v['size']):'—' ?></td>
                <td><?= $v['refcount']>=0?$v['refcount']:'—' ?></td>
                <td style="color:#9aa;"><?= htmlspecialchars($v['stack'] ?: '—') ?></td>
                <td class="mono" style="color:#778;font-size:10.5px;word-break:break-all;"><?= htmlspecialchars($v['mountpoint']) ?></td></tr>
            <?php endforeach; endif ?>
            </tbody></table>
        </div>

    <?php // ─────────── IMAGES ─────────── ?>
    <?php elseif ($view === 'images'): ?>
        <?php if ($img_err): ?><div class="ctr-error"><i class="fas fa-triangle-exclamation"></i> <?= htmlspecialchars($img_err) ?></div><?php endif ?>
        <div class="stat-grid" id="img-stats">
            <div class="glass stat"><div class="n" data-k="total"><?= (int)($img_sum['total'] ?? 0) ?></div><div class="l">Images</div></div>
            <div class="glass stat"><div class="n ok" data-k="in_use"><?= (int)($img_sum['in_use'] ?? 0) ?></div><div class="l">In use</div></div>
            <div class="glass stat"><div class="n idle" data-k="unused"><?= (int)($img_sum['unused'] ?? 0) ?></div><div class="l">Unused</div></div>
            <div class="glass stat"><div class="n warn" data-k="dangling"><?= (int)($img_sum['dangling'] ?? 0) ?></div><div class="l">Dangling</div></div>
            <div class="glass stat"><div class="n warn" data-k="reclaimable"><?= ctr_bytes($img_sum['reclaimable'] ?? 0) ?></div><div class="l">Reclaimable</div></div>
        </div>
        <div class="chips" style="margin-bottom:14px;">
            <button class="btn warn" onclick="imgPrune('dangling')"><i class="fas fa-broom"></i> Prune dangling</button>
            <button class="btn stop" onclick="imgPrune('all')"><i class="fas fa-trash-can"></i> Prune all unused</button>
            <span id="img-msg" style="font-size:12px;color:#9aa;align-self:center;"></span>
        </div>
        <div class="glass" style="overflow:hidden;">
            <table><thead><tr><th></th><th>Image</th><th>Size</th><th>Reclaimable</th><th>Used by</th><th>Created</th><th></th></tr></thead>
            <tbody id="img-tbody">
            <?php if (!$img_rows): ?><tr><td colspan="7" class="empty" style="padding:30px;"><i class="fab fa-docker"></i>No images.</td></tr>
            <?php else: foreach ($img_rows as $im): ?>
            <tr data-id="<?= htmlspecialchars($im['id']) ?>">
                <td><span class="dot <?= $im['in_use']?'ok':($im['dangling']?'stop':'idle') ?>"></span></td>
                <td class="cname" style="word-break:break-all;"><?= htmlspecialchars($im['name']) ?>
                    <?php if (count($im['tags'])>1): ?><span class="cimg"> +<?= count($im['tags'])-1 ?> tag(s)</span><?php endif ?>
                    <?php if ($im['dangling']): ?><span class="badge b-stop">dangling</span><?php endif ?></td>
                <td><?= ctr_bytes($im['size']) ?></td>
                <td style="color:<?= $im['in_use']?'#667':'var(--warn)' ?>;"><?= $im['in_use']?'—':ctr_bytes($im['reclaim']) ?></td>
                <td><?= $im['containers']<0 ? '<span style="color:#667">?</span>' : ($im['containers']>0 ? '<span style="color:var(--ok)">'.$im['containers'].'</span>' : '<span style="color:#778">0</span>') ?></td>
                <td style="color:#9aa;"><?= $im['created']?date('Y-m-d',$im['created']):'—' ?></td>
                <td style="text-align:right;"><button class="btn stop" title="Remove image" onclick="imgRemove(this,'<?= htmlspecialchars($im['id']) ?>',<?= $im['in_use']?'true':'false' ?>)"><i class="fas fa-xmark"></i></button></td></tr>
            <?php endforeach; endif ?>
            </tbody></table>
        </div>
        <div style="font-size:11px;color:#667;margin-top:10px;"><i class="fas fa-circle-info"></i> “Prune dangling” removes only untagged layers (safe). “Prune all unused” removes every image not referenced by a container. In-use images are protected.</div>

    <?php // ─────────── NETWORK ─────────── ?>
    <?php elseif ($view === 'network'): ?>
        <?php if ($net_err): ?><div class="ctr-error"><i class="fas fa-triangle-exclamation"></i> <?= htmlspecialchars($net_err) ?></div><?php endif ?>
        <div class="chips" id="net-chips">
            <div class="glass chip"><div class="n" data-k="count">—</div><div class="l">Running</div></div>
            <div class="glass chip"><div class="n mono" data-k="rx" style="color:var(--accent);font-size:16px;">—</div><div class="l">Total RX/s</div></div>
            <div class="glass chip"><div class="n mono" data-k="tx" style="color:#9b59b6;font-size:16px;">—</div><div class="l">Total TX/s</div></div>
            <span id="net-msg" style="font-size:11px;color:#667;align-self:center;"></span>
        </div>

        <!-- Active container-network alerts -->
        <div class="glass card" id="netalerts-card" style="display:none;border-left:4px solid var(--stop);margin-top:6px;">
            <h3 style="display:flex;justify-content:space-between;align-items:center;">
                <span><i class="fas fa-bell"></i> Traffic Alerts <span id="na-count" class="badge" style="margin-left:6px;"></span></span>
                <span style="font-size:11px;color:#667;text-transform:none;font-weight:400;">per-container ⚙ below · defaults via “Alert defaults”</span>
            </h3>
            <div id="netalerts-body"></div>
        </div>

        <div class="cards2" style="margin-top:6px;">
            <div class="glass card" style="grid-column:1 / -1;">
                <h3 style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
                    <span><i class="fas fa-gauge-high"></i> Live throughput — top talkers <span style="color:#667;text-transform:none;font-weight:400;font-size:11px;">(click a container for its traffic history)</span></span>
                    <button class="btn" onclick="editNetThresh('__global__','Global defaults')"><i class="fas fa-bell"></i> Alert defaults</button>
                </h3>
                <table><thead><tr><th>#</th><th>Container</th><th>RX/s</th><th>TX/s</th><th>Total RX</th><th>Total TX</th><th>Trend</th><th></th></tr></thead>
                <tbody id="net-tbody"><tr><td colspan="8" class="empty" style="padding:24px;"><span class="spin-dot"></span> Sampling…</td></tr></tbody></table>
            </div>
        </div>

        <!-- Per-container traffic history (from container_net_samples) -->
        <div class="cards2" id="net-chart-card" style="display:none;">
            <div class="glass card" style="grid-column:1 / -1;">
                <h3 style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
                    <span><i class="fas fa-chart-area"></i> <span id="nc-title">Traffic</span> <span id="nc-stats" style="color:#9aa;text-transform:none;font-weight:400;font-size:11px;"></span></span>
                    <span id="nc-range">
                        <button class="btn nc-r" data-h="1" onclick="setNetRange(1,this)">1h</button>
                        <button class="btn nc-r" data-h="6" onclick="setNetRange(6,this)" style="border-color:var(--accent);color:var(--accent);">6h</button>
                        <button class="btn nc-r" data-h="24" onclick="setNetRange(24,this)">24h</button>
                        <button class="btn nc-r" data-h="168" onclick="setNetRange(168,this)">7d</button>
                    </span>
                </h3>
                <canvas id="chart-net" style="width:100%;height:240px;"></canvas>
            </div>
        </div>
        <div class="cards2">
            <div class="glass card">
                <h3><i class="fas fa-clock-rotate-left"></i> Top talkers — last hour</h3>
                <table><thead><tr><th>Container</th><th>Avg</th><th>Peak</th><th>RX (1h)</th><th>TX (1h)</th></tr></thead>
                <tbody id="net-top1h"><tr><td colspan="5" style="color:#667;padding:18px;font-size:12px;">Building history… keep this open to accumulate trends.</td></tr></tbody></table>
            </div>
            <div class="glass card">
                <h3><i class="fas fa-diagram-project"></i> Docker networks</h3>
                <table><thead><tr><th>Name</th><th>Driver</th><th>Scope</th><th>Subnet</th><th>Cont.</th></tr></thead><tbody>
                <?php if (!$net_list): ?><tr><td colspan="5" style="color:#667;padding:18px;font-size:12px;">No networks.</td></tr>
                <?php else: foreach ($net_list as $nw): ?>
                <tr><td class="cname"><?= htmlspecialchars($nw['name']) ?><?= $nw['internal']?' <span class="cimg">internal</span>':'' ?></td>
                    <td style="color:#9aa;"><?= htmlspecialchars($nw['driver']) ?></td>
                    <td style="color:#9aa;"><?= htmlspecialchars($nw['scope']) ?></td>
                    <td class="mono" style="font-size:11px;color:#9aa;"><?= htmlspecialchars($nw['subnet']) ?></td>
                    <td><?= $nw['containers']>0?'<span style="color:var(--ok)">'.$nw['containers'].'</span>':'<span style="color:#778">0</span>' ?></td></tr>
                <?php endforeach; endif ?>
                </tbody></table>
            </div>
        </div>
    <?php endif ?>

<?php endif ?>
</div>

<script>
const VIEW='<?= $view ?>', ENDPOINT=<?= (int)$selected ?>, CSRF='';
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function bytes(b){ b=+b||0; if(b<=0)return '—'; const u=['B','KB','MB','GB','TB']; let i=0; while(b>=1024&&i<4){b/=1024;i++;} return (i?b.toFixed(1):Math.round(b))+' '+u[i]; }
function dotFor(s){ return ({running:'ok',restarting:'warn',paused:'idle',exited:'stop',dead:'stop',created:'idle'})[s]||'idle'; }
let _auto=true, _hidden=false;
document.getElementById('auto')?.addEventListener('change',e=>{_auto=e.target.checked;});
document.addEventListener('visibilitychange',()=>{_hidden=document.hidden;});
const clk=document.getElementById('clock'); setInterval(()=>{ if(clk) clk.textContent=new Date().toLocaleTimeString(); },1000);

// actions that mutate
async function ctrAct(cid,act,name){
    if((act==='stop'||act==='kill')&&!confirm(act.toUpperCase()+' '+name+'?')) return;
    const fd=new FormData(); fd.append('container',cid); fd.append('action',act); fd.append('name',name||'');
    const r=await fetch('containers.php?api=action&endpoint='+ENDPOINT,{method:'POST',body:fd}).then(r=>r.json()).catch(()=>({ok:false,error:'failed'}));
    if(!r.ok) alert(r.error||'Action failed');
    setTimeout(refreshOverview,700);
}
// Remove (uninstall) a container — confirm modal with force (running) + delete-volumes options.
function ctrRemove(cid,name,running){
    const ov=document.createElement('div');
    ov.className='ctr-rm-ov';
    ov.style.cssText='position:fixed;inset:0;background:rgba(4,8,16,.72);backdrop-filter:blur(4px);z-index:9999;display:flex;align-items:center;justify-content:center;';
    ov.innerHTML=`<div class="glass" style="max-width:440px;width:92%;padding:22px 24px;border:1px solid rgba(255,90,90,.4);box-shadow:0 0 40px rgba(255,60,60,.18);">
        <h3 style="margin:0 0 6px;color:#ff8f8f;display:flex;align-items:center;gap:9px;"><i class="fas fa-trash"></i> Remove container</h3>
        <p style="margin:0 0 14px;font-size:13px;color:#c7d0dc;">This permanently deletes <b style="color:#fff;">${esc(name)}</b> from the host. The image is kept — you can redeploy it. This cannot be undone.</p>
        ${running?`<label style="display:flex;gap:9px;align-items:flex-start;font-size:12.5px;color:#ffcaca;margin-bottom:10px;cursor:pointer;"><input type="checkbox" id="rm-force" style="margin-top:2px;"><span><b>Force-remove</b> — this container is <b>running</b>. Required to remove it (Docker will stop &amp; delete it).</span></label>`:''}
        <label style="display:flex;gap:9px;align-items:flex-start;font-size:12.5px;color:#aeb8c6;margin-bottom:16px;cursor:pointer;"><input type="checkbox" id="rm-vols" style="margin-top:2px;"><span>Also delete its <b>anonymous volumes</b> (named/bind volumes are never touched).</span></label>
        <div style="display:flex;gap:10px;justify-content:flex-end;">
            <button class="btn" onclick="this.closest('.ctr-rm-ov').remove()">Cancel</button>
            <button class="btn stop" id="rm-go"><i class="fas fa-trash"></i> Remove</button>
        </div>
        <div id="rm-msg" style="margin-top:10px;font-size:12px;color:#ff8f8f;"></div></div>`;
    document.body.appendChild(ov);
    ov.addEventListener('click',e=>{ if(e.target===ov) ov.remove(); });
    ov.querySelector('#rm-go').onclick=async function(){
        const force=running?(ov.querySelector('#rm-force')?.checked?1:0):0;
        if(running&&!force){ ov.querySelector('#rm-msg').textContent='Tick “Force-remove” to delete a running container.'; return; }
        const vols=ov.querySelector('#rm-vols').checked?1:0;
        this.disabled=true; this.innerHTML='<i class="fas fa-spinner fa-spin"></i> Removing…';
        const fd=new FormData(); fd.append('container',cid); fd.append('name',name||''); fd.append('force',force); fd.append('volumes',vols);
        const r=await fetch('containers.php?api=container_remove&endpoint='+ENDPOINT,{method:'POST',body:fd}).then(r=>r.json()).catch(()=>({ok:false,error:'failed'}));
        if(r.ok){ ov.remove(); setTimeout(refreshOverview,600); }
        else { this.disabled=false; this.innerHTML='<i class="fas fa-trash"></i> Remove'; ov.querySelector('#rm-msg').textContent=r.error||'Remove failed'; }
    };
}
function actionsFor(c){
    const b=(act,lbl,cls,ic)=>`<button class="btn ${cls}" onclick="ctrAct('${c.cid}','${act}','${esc(c.name)}')"><i class="fas ${ic}"></i> ${lbl}</button>`;
    const rm=`<button class="btn stop" title="Remove container" onclick="ctrRemove('${c.cid}','${esc(c.name)}',${c.state==='running'?1:0})"><i class="fas fa-trash"></i> Remove</button>`;
    if(c.state==='running') return b('pause','Pause','warn','fa-pause')+b('restart','Restart','','fa-rotate')+b('stop','Stop','stop','fa-stop')+b('kill','Kill','stop','fa-skull')+rm;
    if(c.state==='paused')  return b('unpause','Resume','go','fa-play')+b('stop','Stop','stop','fa-stop')+rm;
    return b('start','Start','go','fa-play')+b('restart','Restart','','fa-rotate')+rm;
}
function rowHtml(c){
    const ports=(c.ports||[]).slice(0,3).join(' ')+((c.ports||[]).length>3?' +'+((c.ports.length)-3):'');
    return `<tr><td><span class="dot ${dotFor(c.state)}"></span>
        <a class="cname" href="containers.php?view=detail&endpoint=${ENDPOINT}&container=${encodeURIComponent(c.cid)}">${esc(c.name)}</a>
        <div class="cimg">${esc(c.image)}</div></td>
        <td>${esc(c.state)}</td><td style="color:#9aa;">${esc(c.status)}</td>
        <td style="color:#9aa;">${esc(c.stack||'—')}</td><td class="mono" style="font-size:10.5px;color:#778;">${esc(ports||'—')}</td>
        <td style="text-align:right;white-space:nowrap;">${actionsFor(c)}</td></tr>`;
}
async function refreshOverview(){
    if(VIEW!=='overview'||!ENDPOINT) return;
    try{ const r=await fetch('containers.php?api=data&endpoint='+ENDPOINT+'&_='+Date.now()).then(r=>r.json());
        if(!r.ok) return;
        document.querySelectorAll('#summary .n[data-k]').forEach(el=>{ el.textContent=r.summary[el.dataset.k]??0; });
        document.getElementById('ctbody').innerHTML=(r.containers||[]).map(rowHtml).join('') ||
            '<tr><td colspan="6" class="empty" style="padding:30px;"><i class="fab fa-docker"></i>No containers.</td></tr>';
    }catch(e){}
}
async function refreshDetail(){
    const w=document.getElementById('dwrap'); if(!w) return;
    try{ const r=await fetch(`containers.php?api=detail_data&endpoint=${ENDPOINT}&container=${encodeURIComponent(w.dataset.cid)}&_=`+Date.now()).then(r=>r.json());
        if(!r.ok||!r.detail) return; const d=r.detail, s=r.stats;
        const stEl=document.getElementById('d-state'); if(stEl) stEl.textContent=d.state||'unknown';
        const set=(m,v)=>{ const el=w.querySelector(`[data-m="${m}"]`); if(el) el.textContent=v; };
        if(s){ set('cpu',(+s.cpu_pct).toFixed(1)+'%'); set('mem',(+s.mem_pct).toFixed(1)+'%');
            set('memb',bytes(s.mem_used_b)+' / '+bytes(s.mem_limit)); set('net','↓'+bytes(s.net_rx)+' ↑'+bytes(s.net_tx)); set('pids',s.pids); }
    }catch(e){}
}

// ── dependency-free line chart ───────────────────────────────────────────────
function makeChart(canvas, color){
    const ctx=canvas.getContext('2d'), data=[], MAX=60;
    const fmt=v=>(v<10?(+v).toFixed(1):Math.round(v))+'%';
    function draw(){ const dpr=devicePixelRatio, w=canvas.width=canvas.clientWidth*dpr, h=canvas.height=200*dpr;
        ctx.clearRect(0,0,w,h);
        const top=Math.max(10,Math.max(...data,1)*1.2), pad=8*dpr, padL=38*dpr;
        const X=i=>padL+(w-padL-pad)*i/(MAX-1), Y=v=>h-pad-(h-2*pad)*Math.min(v,top)/top;
        // gridlines + Y-axis % labels
        ctx.lineWidth=1*dpr; ctx.font=(10*dpr)+'px Consolas,monospace'; ctx.textBaseline='middle'; ctx.textAlign='right';
        for(let g=0;g<=4;g++){ const y=pad+(h-2*pad)*g/4;
            ctx.strokeStyle='rgba(255,255,255,.06)'; ctx.beginPath(); ctx.moveTo(padL,y); ctx.lineTo(w-pad,y); ctx.stroke();
            ctx.fillStyle='rgba(255,255,255,.4)'; ctx.fillText(fmt(top*(4-g)/4), padL-5*dpr, y); }
        if(data.length<2) return;
        const grad=ctx.createLinearGradient(0,0,0,h); grad.addColorStop(0,color+'55'); grad.addColorStop(1,color+'00');
        ctx.lineWidth=2*dpr; ctx.beginPath(); data.forEach((v,i)=>{ const x=X(i), y=Y(v); i?ctx.lineTo(x,y):ctx.moveTo(x,y); });
        ctx.strokeStyle=color; ctx.stroke();
        ctx.lineTo(X(data.length-1),h-pad); ctx.lineTo(X(0),h-pad); ctx.closePath(); ctx.fillStyle=grad; ctx.fill();
        // latest-value marker + readout
        const lv=data[data.length-1], lx=X(data.length-1), ly=Y(lv), label=fmt(lv);
        ctx.fillStyle=color; ctx.beginPath(); ctx.arc(lx,ly,3*dpr,0,Math.PI*2); ctx.fill();
        ctx.font='bold '+(13*dpr)+'px Consolas,monospace'; ctx.textBaseline='top'; ctx.textAlign='right';
        const tw=ctx.measureText(label).width;
        ctx.fillStyle='rgba(8,12,20,.6)'; ctx.fillRect(w-pad-tw-6*dpr, pad, tw+6*dpr, 18*dpr);
        ctx.fillStyle=color; ctx.fillText(label, w-pad-3*dpr, pad+3*dpr);
    }
    return { push(v){ data.push(+v||0); if(data.length>MAX) data.shift(); draw(); }, reset(){ data.length=0; draw(); }, draw };
}
let cpuChart=null, memChart=null;
async function refreshStats(){
    const w=document.getElementById('swrap'); if(!w) return;
    try{ const r=await fetch(`containers.php?api=stats_data&endpoint=${ENDPOINT}&container=${encodeURIComponent(w.dataset.cid)}&_=`+Date.now()).then(r=>r.json());
        if(!r.ok) return; const s=r.stats;
        const set=(m,v)=>{ const el=w.querySelector(`[data-m="${m}"]`); if(el) el.textContent=v; };
        set('cpu',(+s.cpu_pct).toFixed(1)+'%'); set('mem',(+s.mem_pct).toFixed(1)+'%'); set('memb',bytes(s.mem_used_b));
        set('rx',bytes(s.net_rx)); set('tx',bytes(s.net_tx)); set('pids',s.pids);
        cpuChart&&cpuChart.push(s.cpu_pct); memChart&&memChart.push(s.mem_pct);
    }catch(e){}
}

// ── IMAGES: cleanup ───────────────────────────────────────────────────────────
function rate(bps){ bps=+bps||0; if(bps<1) return '0'; const u=['B/s','KB/s','MB/s','GB/s']; let i=0; while(bps>=1024&&i<3){bps/=1024;i++;} return (i?bps.toFixed(1):Math.round(bps))+' '+u[i]; }
async function imgPrune(scope){
    const msg=scope==='all'
        ? 'Prune ALL unused images (every image not used by a running/stopped container)?\nThis cannot be undone.'
        : 'Prune dangling (untagged) image layers? This is safe.';
    if(!confirm(msg)) return;
    const m=document.getElementById('img-msg'); if(m) m.textContent='Pruning…';
    const fd=new FormData(); fd.append('scope',scope);
    const r=await fetch('containers.php?api=images_prune&endpoint='+ENDPOINT,{method:'POST',body:fd}).then(r=>r.json()).catch(()=>({ok:false,error:'failed'}));
    if(m) m.textContent=r.message||(r.ok?'Done':r.error);
    refreshImages();
}
async function imgRemove(btn,id,inUse){
    if(inUse && !confirm('This image is IN USE by a container. Force-remove anyway?')) return;
    if(!inUse && !confirm('Remove this image?')) return;
    const fd=new FormData(); fd.append('image',id); if(inUse) fd.append('force','1');
    btn.disabled=true; btn.innerHTML='<span class="spin-dot"></span>';
    const r=await fetch('containers.php?api=image_remove&endpoint='+ENDPOINT,{method:'POST',body:fd}).then(r=>r.json()).catch(()=>({ok:false,error:'failed'}));
    const m=document.getElementById('img-msg'); if(m) m.textContent=r.message||(r.ok?'Removed':r.error);
    if(r.ok){ const tr=btn.closest('tr'); if(tr) tr.remove(); refreshImages(); } else { btn.disabled=false; btn.innerHTML='<i class="fas fa-xmark"></i>'; }
}
async function refreshImages(){
    if(VIEW!=='images'||!ENDPOINT) return;
    try{ const r=await fetch('containers.php?api=images_data&endpoint='+ENDPOINT+'&_='+Date.now()).then(r=>r.json());
        if(!r.ok) return;
        const set=(k,v)=>{ const el=document.querySelector(`#img-stats .n[data-k="${k}"]`); if(el) el.textContent=v; };
        set('total',r.summary.total); set('in_use',r.summary.in_use); set('unused',r.summary.unused);
        set('dangling',r.summary.dangling); set('reclaimable',bytes(r.summary.reclaimable));
        const tb=document.getElementById('img-tbody'); if(!tb) return;
        if(!r.images.length){ tb.innerHTML='<tr><td colspan="7" class="empty" style="padding:30px;"><i class="fab fa-docker"></i>No images.</td></tr>'; return; }
        tb.innerHTML=r.images.map(im=>{
            const dot=im.in_use?'ok':(im.dangling?'stop':'idle');
            const used=im.containers<0?'<span style="color:#667">?</span>':(im.containers>0?`<span style="color:var(--ok)">${im.containers}</span>`:'<span style="color:#778">0</span>');
            const created=im.created?new Date(im.created*1000).toISOString().slice(0,10):'—';
            return `<tr data-id="${esc(im.id)}"><td><span class="dot ${dot}"></span></td>
                <td class="cname" style="word-break:break-all;">${esc(im.name)}${im.dangling?' <span class="badge b-stop">dangling</span>':''}</td>
                <td>${bytes(im.size)}</td><td style="color:${im.in_use?'#667':'var(--warn)'};">${im.in_use?'—':bytes(im.reclaim)}</td>
                <td>${used}</td><td style="color:#9aa;">${created}</td>
                <td style="text-align:right;"><button class="btn stop" onclick="imgRemove(this,'${esc(im.id)}',${im.in_use})"><i class="fas fa-xmark"></i></button></td></tr>`;
        }).join('');
    }catch(e){}
}

// ── NETWORK: live throughput + persisted top-talkers ──────────────────────────
const _netSeries={};   // cid → rolling [total rate]
function netSpark(canvas, series){
    const dpr=devicePixelRatio, w=canvas.width=canvas.clientWidth*dpr, h=canvas.height=26*dpr, ctx=canvas.getContext('2d');
    ctx.clearRect(0,0,w,h); if(series.length<2) return;
    const max=Math.max(...series,1), n=series.length;
    ctx.beginPath(); series.forEach((v,i)=>{ const x=(w)*i/(n-1), y=h-2*dpr-(h-4*dpr)*Math.min(v,max)/max; i?ctx.lineTo(x,y):ctx.moveTo(x,y); });
    ctx.strokeStyle='#4da3ff'; ctx.lineWidth=1.4*dpr; ctx.stroke();
}
let _netBusy=false;
async function refreshNetwork(){
    if(VIEW!=='network'||!ENDPOINT||_netBusy) return;   // never let polls stack
    _netBusy=true;
    const mb=document.getElementById('net-msg'); if(mb && !mb.textContent) mb.textContent='sampling…';
    try{ const r=await fetch('containers.php?api=net_sample&endpoint='+ENDPOINT+'&_='+Date.now()).then(r=>r.json());
        if(!r.ok){ const m=document.getElementById('net-msg'); if(m) m.textContent=r.error||'error'; return; }
        const rows=r.rows||[]; let trx=0,ttx=0;
        rows.forEach(x=>{ trx+=x.rx_rate; ttx+=x.tx_rate; const s=_netSeries[x.cid]||(_netSeries[x.cid]=[]); s.push(x.rx_rate+x.tx_rate); if(s.length>40)s.shift(); });
        const set=(k,v)=>{ const el=document.querySelector(`#net-chips .n[data-k="${k}"]`); if(el) el.textContent=v; };
        set('count',rows.length); set('rx',rate(trx)); set('tx',rate(ttx));
        const m=document.getElementById('net-msg'); if(m) m.textContent='updated '+(r.at||'');
        const tb=document.getElementById('net-tbody');
        if(tb){ if(!rows.length){ tb.innerHTML='<tr><td colspan="8" class="empty" style="padding:24px;">No running containers.</td></tr>'; }
            else { tb.innerHTML=rows.map((x,i)=>`<tr><td style="color:#778;">${i+1}</td>
                <td><a href="#" class="cname" style="cursor:pointer;" onclick="showNetChart('${esc(x.cid)}','${esc(x.name)}');return false;" title="Traffic history">${esc(x.name)}</a></td>
                <td class="mono" style="color:var(--accent);">${rate(x.rx_rate)}</td>
                <td class="mono" style="color:#c08fd6;">${rate(x.tx_rate)}</td>
                <td class="mono" style="color:#9aa;font-size:11px;">${bytes(x.rx)}</td>
                <td class="mono" style="color:#9aa;font-size:11px;">${bytes(x.tx)}</td>
                <td style="width:120px;"><canvas class="net-spark" data-cid="${esc(x.cid)}" style="width:110px;height:26px;"></canvas></td>
                <td style="text-align:right;white-space:nowrap;">
                    <button class="btn" title="Alert thresholds for this container" onclick="editNetThresh('${esc(x.cid)}','${esc(x.name)}')"><i class="fas fa-gear"></i></button>
                    <button class="btn" title="Traffic chart" onclick="showNetChart('${esc(x.cid)}','${esc(x.name)}')"><i class="fas fa-chart-line"></i></button></td></tr>`).join('');
                document.querySelectorAll('.net-spark').forEach(cv=>netSpark(cv,_netSeries[cv.dataset.cid]||[]));
            }
        }
        const t1=document.getElementById('net-top1h'); const top=r.top1h||[];
        if(t1){ t1.innerHTML = top.length ? top.map(x=>`<tr><td class="cname">${esc(x.name)}</td>
            <td class="mono" style="color:var(--accent);">${rate(x.avg)}</td>
            <td class="mono" style="color:var(--warn);">${rate(x.peak)}</td>
            <td class="mono" style="color:#9aa;font-size:11px;">${bytes(x.rx)}</td>
            <td class="mono" style="color:#9aa;font-size:11px;">${bytes(x.tx)}</td></tr>`).join('')
            : '<tr><td colspan="5" style="color:#667;padding:18px;font-size:12px;">Building history… keep this open to accumulate trends.</td></tr>';
        }
    }catch(e){ const m=document.getElementById('net-msg'); if(m) m.textContent='sample failed (retrying)'; }
    finally{ _netBusy=false; }   // always release, even on the early error-return
}

// ── per-container traffic history chart (from our DB) ─────────────────────────
let _ncCid='', _ncName='', _ncHours=6;
function ncTime(ts,hours){ const d=new Date(ts.replace(' ','T')+'Z'); return hours<=24 ? d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}) : (d.getMonth()+1)+'/'+d.getDate(); }
function setNetRange(h,btn){ _ncHours=h; document.querySelectorAll('#nc-range .nc-r').forEach(b=>b.style.cssText=''); if(btn) btn.style.cssText='border-color:var(--accent);color:var(--accent);'; if(_ncCid) showNetChart(_ncCid,_ncName); }
async function showNetChart(cid,name){
    _ncCid=cid; _ncName=name||cid.slice(0,12);
    const card=document.getElementById('net-chart-card'); card.style.display='';
    document.getElementById('nc-title').textContent=_ncName+' — traffic';
    document.getElementById('nc-stats').textContent='loading…';
    card.scrollIntoView({behavior:'smooth',block:'nearest'});
    try{ const r=await fetch(`containers.php?api=net_history&endpoint=${ENDPOINT}&container=${encodeURIComponent(cid)}&hours=${_ncHours}&_=`+Date.now()).then(r=>r.json());
        if(!r.ok){ document.getElementById('nc-stats').textContent=r.error||'failed'; return; }
        renderNetChart(r);
    }catch(e){ document.getElementById('nc-stats').textContent='request failed'; }
}
function renderNetChart(r){
    const cv=document.getElementById('chart-net'), dpr=devicePixelRatio;
    const w=cv.width=cv.clientWidth*dpr, h=cv.height=240*dpr, ctx=cv.getContext('2d');
    ctx.clearRect(0,0,w,h);
    const padL=58*dpr, padR=10*dpr, padT=12*dpr, padB=22*dpr;
    const times=r.times||[], rx=r.rx||[], tx=r.tx||[], s=r.summary||{};
    const st=document.getElementById('nc-stats');
    if(times.length<2){ st.textContent='no history yet (the recorder cron fills this; needs a few samples)'; ctx.fillStyle='#667'; ctx.font=(13*dpr)+'px sans-serif'; ctx.fillText('No data in range',padL,h/2); return; }
    st.innerHTML=`avg ↓${rate(s.arx)} ↑${rate(s.atx)} · peak ↓${rate(s.prx)} ↑${rate(s.ptx)} · ${s.n} pts`;
    const mx=Math.max(Math.max(...rx),Math.max(...tx),1)*1.2;
    const X=i=>padL+(w-padL-padR)*i/(times.length-1), Y=v=>h-padB-(h-padT-padB)*Math.min(v,mx)/mx;
    // grid + y labels (rate)
    ctx.font=(10*dpr)+'px Consolas,monospace'; ctx.textBaseline='middle'; ctx.textAlign='right';
    for(let g=0;g<=4;g++){ const y=padT+(h-padT-padB)*g/4; ctx.strokeStyle='rgba(255,255,255,.06)'; ctx.beginPath(); ctx.moveTo(padL,y); ctx.lineTo(w-padR,y); ctx.stroke();
        ctx.fillStyle='rgba(255,255,255,.4)'; ctx.fillText(rate(mx*(4-g)/4), padL-5*dpr, y); }
    const line=(data,color)=>{ ctx.beginPath(); data.forEach((v,i)=>{ const x=X(i),y=Y(v); i?ctx.lineTo(x,y):ctx.moveTo(x,y); }); ctx.strokeStyle=color; ctx.lineWidth=1.8*dpr; ctx.stroke(); };
    line(rx,'#4da3ff');   // RX
    line(tx,'#c08fd6');   // TX
    // x labels
    ctx.fillStyle='rgba(255,255,255,.45)'; ctx.textAlign='center'; ctx.textBaseline='top';
    [0,.5,1].forEach(f=>{ const i=Math.round((times.length-1)*f); ctx.fillText(ncTime(times[i],_ncHours), padL+(w-padL-padR)*f, h-padB+5*dpr); });
    // legend
    ctx.textAlign='left'; ctx.textBaseline='middle'; ctx.font=(11*dpr)+'px sans-serif';
    ctx.fillStyle='#4da3ff'; ctx.fillText('● RX', w-padR-110*dpr, padT+6*dpr);
    ctx.fillStyle='#c08fd6'; ctx.fillText('● TX', w-padR-60*dpr, padT+6*dpr);
}
window.addEventListener('resize',()=>{ if(_ncCid && VIEW==='network') showNetChart(_ncCid,_ncName); });

// ── container-network alerts (mirror of Smokeping) ────────────────────────────
function naStr(a){ const v=rate(a.value); const th=rate(a.threshold); return `${a.metric.toUpperCase()} ${v} ≥ ${th}`; }
async function loadNetAlerts(){
    try{ const r=await fetch('containers.php?api=netalerts&_='+Date.now()).then(r=>r.json());
        const card=document.getElementById('netalerts-card'), body=document.getElementById('netalerts-body'), cnt=document.getElementById('na-count');
        if(!card) return;
        const open=(r.ok&&r.open)?r.open:[];
        if(!open.length){ card.style.display='none'; return; }
        card.style.display='block';
        const crit=open.filter(a=>a.severity==='crit').length;
        card.style.borderLeftColor=crit?'var(--stop)':'var(--warn)';
        cnt.className='badge '+(crit?'b-crit':'b-warn'); cnt.textContent=open.length+(crit?(' · '+crit+' crit'):'');
        body.innerHTML=open.map(a=>`<div class="al-row">
            <span class="badge ${a.severity==='crit'?'b-crit':'b-warn'}">${a.severity}</span>
            <b style="min-width:170px;">${esc(a.container_name)}</b>
            <span class="mono" style="color:${a.severity==='crit'?'var(--stop)':'var(--warn)'};">${naStr(a)}</span>
            <span style="margin-left:auto;color:#667;font-size:11px;">since ${esc((window.nmLocal?nmLocal(a.opened_at):(a.opened_at||'')).slice(5,16))}</span>
            <button class="btn" onclick="showNetChart('${esc(a.container_id)}','${esc(a.container_name)}')"><i class="fas fa-chart-line"></i></button></div>`).join('');
    }catch(e){}
}
let _naThr={global:{},containers:{}};
async function ensureNaThr(){ if(Object.keys(_naThr.global).length) return; try{ const r=await fetch('containers.php?api=netthresholds_get').then(r=>r.json()); if(r.ok) _naThr={global:r.global||{},containers:r.containers||{}}; }catch(e){} }
function _mb(v){ return (v==null||v==='')?'':(+v); }   // stored already in MB/s
async function editNetThresh(cid,name){
    await ensureNaThr();
    const t=(cid==='__global__')?_naThr.global:(_naThr.containers[cid]||{}), g=_naThr.global;
    document.getElementById('nt-node').textContent=name; document.getElementById('nt-id').value=cid;
    const isG=(cid==='__global__');
    document.getElementById('nt-sub').textContent=isG?'These are the global defaults (MB/s). RX/TX rate.':'Leave all blank to use the global defaults. Values in MB/s.';
    const set=(el,v,gv)=>{ const e=document.getElementById(el); e.value=_mb(v); e.placeholder=isG?'':('global '+(gv==null?'—':gv)); };
    set('nt-rw',t.rx_warn,g.rx_warn); set('nt-rc',t.rx_crit,g.rx_crit); set('nt-tw',t.tx_warn,g.tx_warn); set('nt-tc',t.tx_crit,g.tx_crit);
    document.getElementById('nt-msg').textContent=''; document.getElementById('nt-modal').classList.add('show');
}
function closeNetThresh(){ document.getElementById('nt-modal').classList.remove('show'); }
async function saveNetThresh(){
    const id=document.getElementById('nt-id').value, m=document.getElementById('nt-msg');
    const fd=new FormData(); fd.append('scope',id);
    fd.append('rx_warn',document.getElementById('nt-rw').value.trim());
    fd.append('rx_crit',document.getElementById('nt-rc').value.trim());
    fd.append('tx_warn',document.getElementById('nt-tw').value.trim());
    fd.append('tx_crit',document.getElementById('nt-tc').value.trim());
    m.innerHTML='<span class="spin-dot"></span> saving…';
    const r=await fetch('containers.php?api=netthresholds_save',{method:'POST',body:fd}).then(r=>r.json()).catch(()=>({ok:false}));
    if(r.ok){ _naThr={global:{},containers:{}}; await fetch('containers.php?api=neteval'); m.textContent=r.cleared?'Cleared (using global)':'Saved'; setTimeout(()=>{closeNetThresh();loadNetAlerts();},700); }
    else m.textContent=r.error||'failed';
}
document.getElementById('nt-modal')?.addEventListener('click',e=>{ if(e.target.id==='nt-modal') closeNetThresh(); });

// ── poll loop ────────────────────────────────────────────────────────────────
function tick(){ if(_auto && !_hidden){ if(VIEW==='overview')refreshOverview(); else if(VIEW==='detail')refreshDetail(); else if(VIEW==='stats')refreshStats(); else if(VIEW==='images')refreshImages(); else if(VIEW==='network')refreshNetwork(); } }
if(VIEW==='stats'){ const cc=document.getElementById('chart-cpu'), mc=document.getElementById('chart-mem');
    if(cc){ cpuChart=makeChart(cc,'#4da3ff'); memChart=makeChart(mc,'#9b59b6'); window.addEventListener('resize',()=>{cpuChart.draw();memChart.draw();}); refreshStats(); } }
if(VIEW==='network'){ refreshNetwork(); loadNetAlerts(); setInterval(loadNetAlerts, 30000); }
setInterval(tick, (VIEW==='overview')?10000:(VIEW==='network'?8000:(VIEW==='images'?15000:2500)));

// ─────────────────────────── Deploy wizard ───────────────────────────
let DPL={tpl:null,templates:[],endpoints:[],host:ENDPOINT,ports:[],env:[],vols:[]};
function deployStep(n){ ['ds1','ds2','ds3'].forEach((id,i)=>document.getElementById(id).classList.toggle('on',i<n)); }
async function deployOpen(){
  document.getElementById('dpl-ov').classList.add('show');
  DPL.host=ENDPOINT;
  // load the Docker hosts so the operator can choose WHERE to deploy (right inside the wizard)
  const e=await fetch('containers.php?api=endpoints&_='+Date.now()).then(r=>r.json()).catch(()=>null);
  DPL.endpoints=(e&&e.endpoints)||[];
  if(DPL.endpoints.length && !DPL.endpoints.some(x=>String(x.id)===String(DPL.host))) DPL.host=DPL.endpoints[0].id;
  updHostLabel();
  loadTemplates();
}
function updHostLabel(){
  const ep=DPL.endpoints.find(x=>String(x.id)===String(DPL.host));
  document.getElementById('dpl-host').textContent='Target host: '+(ep?ep.name+(ep.up?'':' (down)'):('endpoint '+DPL.host));
}
function onHostChange(){ DPL.host=document.getElementById('dp-host').value; updHostLabel(); }
function deployClose(){ document.getElementById('dpl-ov').classList.remove('show'); }
async function loadTemplates(){
  deployStep(1); document.getElementById('dpl-title').textContent='Choose a template';
  document.getElementById('dpl-body').innerHTML='<div style="text-align:center;padding:42px;color:#667;"><i class="fas fa-circle-notch fa-spin"></i> loading library…</div>';
  document.getElementById('dpl-foot').innerHTML='';
  const r=await fetch('containers.php?api=templates&_='+Date.now()).then(r=>r.json()).catch(()=>null);
  DPL.templates=(r&&r.templates)||[]; renderTemplates();
}
function renderTemplates(){
  const T=DPL.templates, cats={}; T.forEach(t=>{ (cats[t.category]=cats[t.category]||[]).push(t); });
  let h=`<div class="dpl-grid"><div class="tpl" style="border-style:dashed;text-align:center;" onclick="pickTpl(null)"><div class="ic"><i class="fas fa-pen-to-square"></i></div><div class="nm">Custom / blank</div><div class="im">start from scratch</div></div></div>`;
  Object.keys(cats).sort().forEach(c=>{ h+=`<div class="dpl-cat">${esc(c)}</div><div class="dpl-grid">`+cats[c].map(t=>`
      <div class="tpl" onclick="pickTpl(${t.id})">
        ${(+t.is_builtin===0)?`<i class="fas fa-trash del show" title="Delete custom" onclick="event.stopPropagation();delTpl(${t.id})"></i>`:`<span class="cat">${esc(t.category)}</span>`}
        <div class="ic"><i class="${esc(t.icon||'fa-solid fa-cube')}"></i></div>
        <div class="nm">${esc(t.name)}</div><div class="im">${esc(t.image)}</div></div>`).join('')+`</div>`; });
  document.getElementById('dpl-body').innerHTML=h; document.getElementById('dpl-foot').innerHTML='';
}
function pickTpl(id){
  const t=(id!=null)?DPL.templates.find(x=>String(x.id)===String(id)):null; DPL.tpl=t;
  DPL.ports=t?Object.entries(t.ports||{}).map(([c,hp])=>({container:c,host:String(hp)})):[];
  DPL.env=t?(t.env||[]).slice():[]; DPL.vols=t?(t.volumes||[]).slice():[];
  configForm();
}
function configForm(){
  deployStep(2); const t=DPL.tpl;
  document.getElementById('dpl-title').textContent=t?('Configure: '+t.name):'Configure container';
  const sug=t?t.name.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,''):'';
  const hostOpts=(DPL.endpoints||[]).map(e=>`<option value="${e.id}" ${String(e.id)===String(DPL.host)?'selected':''}>${esc(e.name)}${e.up?'':' — down'}</option>`).join('')||`<option value="${ENDPOINT}">current host</option>`;
  const isAgent=!!(t&&t.autofill);
  const agentNote=isAgent?`<div style="margin:0 0 14px;padding:11px 14px;border:1px solid rgba(126,231,135,.35);background:rgba(126,231,135,.09);border-radius:10px;font-size:12.5px;color:#bfe9c6;">
      <i class="fas fa-wand-magic-sparkles" style="color:#7ee787;"></i> <b>Pre-configured.</b> The endpoint URL and enrollment token below are already filled in from this NEURU. Just pick the host and click <b>Deploy</b> — the agent will self-register within ~30s and appear in the Linux Monitor. It reads the host's <code>/proc</code>,<code>/sys</code> and Docker socket (all read-only) and uses host networking, so no port mapping is needed.
    </div>`:'';
  document.getElementById('dpl-body').innerHTML=`<div class="dplf">
    ${agentNote}
    <div class="dpl-row" style="gap:12px;margin-bottom:12px;">
      <div style="flex:1;"><label><i class="fas fa-server" style="color:#4da3ff;"></i> Deploy to host</label><select id="dp-host" onchange="onHostChange()">${hostOpts}</select></div>
    </div>
    <div class="dpl-row" style="gap:12px;">
      <div style="flex:1;"><label>Container name</label><input id="dp-name" placeholder="my-app" value="${esc(sug)}"></div>
      <div style="flex:2;position:relative;"><label>Image <span style="color:#667;">(search Docker Hub or type)</span></label>
        <input id="dp-image" placeholder="search e.g. nginx, postgres…" value="${esc(t?t.image:'')}" autocomplete="off" oninput="imgSearch(this.value)" onfocus="imgSearch(this.value)" onblur="setTimeout(()=>{const d=document.getElementById('dp-imgdd');if(d)d.style.display='none';},200)">
        <div id="dp-imgdd" class="imgdd"></div></div>
      <div style="width:150px;"><label>Restart</label><select id="dp-restart">${['unless-stopped','always','on-failure','no'].map(x=>`<option ${((t&&t.restart===x)||(!t&&x==='unless-stopped'))?'selected':''}>${x}</option>`).join('')}</select></div>
    </div>
    ${isAgent?'':`<label style="margin-top:8px;">Port mappings <span style="color:#667;">(host : container)</span></label><div id="dp-ports"></div><button class="addbtn" onclick="addPort()">+ port</button>`}
    <label style="margin-top:12px;">Environment variables${isAgent?' <span style="color:#7ee787;">(auto-filled)</span>':''}</label><div id="dp-env"></div><button class="addbtn" onclick="addEnv()">+ variable</button>
    <label style="margin-top:12px;">Volumes <span style="color:#667;">(/host : /container)</span></label><div id="dp-vols"></div><button class="addbtn" onclick="addVol()">+ volume</button>
  </div>`;
  renderRows();
  document.getElementById('dpl-foot').innerHTML=`<button class="ghost" onclick="loadTemplates()"><i class="fas fa-arrow-left"></i> Back</button>
    <button class="ghost" onclick="saveTpl()"><i class="fas fa-floppy-disk"></i> Save as template</button>
    <button class="gobtn" style="margin-left:auto;" onclick="doDeploy()"><i class="fas fa-rocket"></i> Deploy</button>`;
}
function renderRows(){
  const none='<div style="color:#667;font-size:12px;margin-bottom:6px;">none</div>';
  const pe=document.getElementById('dp-ports');
  if(pe) pe.innerHTML=DPL.ports.map((p,i)=>`<div class="dpl-row"><input value="${esc(p.host)}" oninput="DPL.ports[${i}].host=this.value" placeholder="8080"><span style="align-self:center;color:#667;">:</span><input value="${esc(p.container)}" oninput="DPL.ports[${i}].container=this.value" placeholder="80/tcp"><button class="rm" onclick="DPL.ports.splice(${i},1);renderRows()">×</button></div>`).join('')||none;
  document.getElementById('dp-env').innerHTML=DPL.env.map((e,i)=>`<div class="dpl-row"><input value="${esc(e)}" oninput="DPL.env[${i}]=this.value" placeholder="KEY=value"><button class="rm" onclick="DPL.env.splice(${i},1);renderRows()">×</button></div>`).join('')||none;
  document.getElementById('dp-vols').innerHTML=DPL.vols.map((v,i)=>`<div class="dpl-row"><input value="${esc(v)}" oninput="DPL.vols[${i}]=this.value" placeholder="/srv/app:/data"><button class="rm" onclick="DPL.vols.splice(${i},1);renderRows()">×</button></div>`).join('')||none;
}
let imgT=null;
function imgSearch(q){
  clearTimeout(imgT); const dd=document.getElementById('dp-imgdd'); if(!dd) return;
  if((q||'').trim().length<2){ dd.style.display='none'; return; }
  imgT=setTimeout(async()=>{
    const r=await fetch('containers.php?api=image_search&q='+encodeURIComponent(q.trim())+'&_='+Date.now()).then(r=>r.json()).catch(()=>null);
    const L=(r&&r.images)||[]; if(!L.length){ dd.style.display='none'; return; }
    dd.innerHTML=L.map(x=>`<div class="imi" onmousedown="pickImage('${esc(x.name)}')"><b>${esc(x.name)}</b>${x.official?'<span class="off">official</span>':''}<span class="st">★ ${x.stars}</span><div class="ds">${esc(x.desc||'')}</div></div>`).join('');
    dd.style.display='block';
  },300);
}
function pickImage(n){ const el=document.getElementById('dp-image'); el.value=n.includes(':')?n:(n+':latest'); const dd=document.getElementById('dp-imgdd'); if(dd)dd.style.display='none'; }
function addPort(){ DPL.ports.push({host:'',container:''}); renderRows(); }
function addEnv(){ DPL.env.push(''); renderRows(); }
function addVol(){ DPL.vols.push(''); renderRows(); }
function curSpec(){ return { endpoint:(+DPL.host)||ENDPOINT, name:document.getElementById('dp-name').value.trim(), image:document.getElementById('dp-image').value.trim(),
  restart:document.getElementById('dp-restart').value, ports:DPL.ports.filter(p=>p.host&&p.container), env:DPL.env.filter(Boolean), volumes:DPL.vols.filter(Boolean),
  tpl:(DPL.tpl?DPL.tpl.id:0) }; }
async function doDeploy(){
  const s=curSpec(); if(!s.image){ alert('Image is required'); return; }
  deployStep(3); document.getElementById('dpl-title').textContent='Deploying…'; document.getElementById('dpl-foot').innerHTML='';
  document.getElementById('dpl-body').innerHTML=`<div class="dpl-log" id="dlog">
    <div class="ln"><span class="sp">▸</span> ${esc(document.getElementById('dpl-host').textContent)}</div>
    <div class="ln"><span class="sp">▸</span> image: <b>${esc(s.image)}</b>${s.name?(' · name: <b>'+esc(s.name)+'</b>'):''}</div>
    <div class="ln" id="dl-pull"><i class="fas fa-circle-notch fa-spin"></i> pulling image · creating · starting … (first pull can take a minute)</div></div>`;
  const r=await fetch('containers.php?api=deploy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(s)}).then(r=>r.json()).catch(()=>({ok:false,error:'request failed / timeout'}));
  const dlog=document.getElementById('dlog'); const pull=document.getElementById('dl-pull');
  if(r.ok){ pull.innerHTML='<span class="sp">▸</span> image ready · container created · starting';
    dlog.innerHTML+=`<div class="ln ok"><i class="fas fa-circle-check"></i> Deployed &amp; started${s.name?(' as <b>'+esc(s.name)+'</b>'):''} ✓</div>`;
    // NEURU-in-a-Box: first boot (DB init + schema import) takes ~1-2 min → live progress via ready.php
    if(/neuru-box/.test(s.image)){
      const guess=(String(r.router||'').match(/\d+\.\d+\.\d+\.\d+/)||[''])[0];
      dlog.innerHTML+=`<div class="ln" style="margin-top:8px;color:#9aa;">This is a full NEURU instance — first boot initializes the database &amp; imports the schema (~1-2 min). Enter its address to watch it come up:</div>
        <div class="ln" style="display:flex;gap:6px;align-items:center;margin-top:4px;">
          <input id="box-url" value="${guess?('http://'+guess):'http://'}" style="flex:1;background:#0b0f14;border:1px solid #2a3340;color:#cfe;border-radius:6px;padding:6px 8px;font-size:12px;">
          <button class="gobtn" onclick="boxWatch()"><i class="fas fa-satellite-dish"></i> Watch boot</button></div>
        <div id="box-stage" style="margin-top:8px;"></div>`;
    }
    document.getElementById('dpl-foot').innerHTML=`<button class="gobtn" style="margin-left:auto;" onclick="location.href='containers.php?view=overview&endpoint='+(DPL.host||ENDPOINT)"><i class="fas fa-arrow-right"></i> View containers</button>`;
    if(/neuru-box/.test(s.image)){ setTimeout(boxWatch,1500); }
  } else { pull.innerHTML='<span class="sp">▸</span> attempted: pull · create · start';
    dlog.innerHTML+=`<div class="ln err"><i class="fas fa-circle-xmark"></i> ${esc(r.error||('failed (HTTP '+(r.status||'?')+')'))}</div>`;
    document.getElementById('dpl-foot').innerHTML=`<button class="ghost" onclick="configForm()"><i class="fas fa-arrow-left"></i> Back to config</button>`;
  }
}
let BOXW=null;
function boxWatch(){
  const el=document.getElementById('box-stage'), inp=document.getElementById('box-url');
  if(!el||!inp) return; const url=inp.value.trim(); if(!/^https?:\/\/.+/.test(url)){ el.innerHTML='<span style="color:#f7a;">Enter the new NEURU\'s http(s) address</span>'; return; }
  const steps=[['starting-database','Booting database'],['importing-schema','Importing schema (114 tables)'],['db-up','Database up'],['ready','NEURU is up']];
  if(BOXW) clearInterval(BOXW);
  const tick=async()=>{
    const j=await fetch('containers.php?api=box_ready&url='+encodeURIComponent(url)+'&_='+Date.now()).then(r=>r.json()).catch(()=>({stage:'unreachable'}));
    const st=j.stage||'starting'; const idx=steps.findIndex(x=>x[0]===st);
    const rows=steps.map((x,i)=>{ const done=(st==='ready')||(idx>=0&&i<idx); const cur=(x[0]===st);
      return `<div class="ln ${done?'ok':''}" style="opacity:${(done||cur)?1:.45};"><i class="fas ${done?'fa-circle-check':(cur?'fa-circle-notch fa-spin':'fa-circle')}"></i> ${x[1]}</div>`; }).join('');
    el.innerHTML=rows + (j.ok?`<div class="ln ok" style="margin-top:6px;"><i class="fas fa-arrow-right"></i> <a href="${url}" target="_blank" style="color:#7ee787;">Open ${esc(url)}</a>${j.version?(' · v'+esc(j.version)):''}</div>`
      : `<div class="ln" style="color:#7c828c;margin-top:6px;">${st==='unreachable'?'waiting for the container to answer…':('stage: '+esc(st))}</div>`);
    if(j.ok){ clearInterval(BOXW); BOXW=null; }
  };
  tick(); BOXW=setInterval(tick,4000);
}
async function saveTpl(){
  const s=curSpec(); const nm=prompt('Save as template — name:', s.name||(DPL.tpl?(DPL.tpl.name+' (copy)'):'My template')); if(!nm) return;
  const ports={}; s.ports.forEach(p=>ports[p.container]=p.host);
  const body={name:nm,category:'Custom',image:s.image,icon:(DPL.tpl?DPL.tpl.icon:'fa-solid fa-cube'),ports,env:s.env,volumes:s.volumes,restart:s.restart};
  const r=await fetch('containers.php?api=template_save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(r=>r.json()).catch(()=>({ok:false}));
  alert(r.ok?'Template saved ✓ (find it under Custom)':('Could not save: '+(r.error||'')));
}
async function delTpl(id){ if(!confirm('Delete this custom template?'))return;
  const r=await fetch('containers.php?api=template_delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}).then(r=>r.json()).catch(()=>({ok:false}));
  if(r.ok) loadTemplates(); else alert(r.error||'Could not delete'); }
</script>

<!-- Per-container traffic alert thresholds modal -->
<div class="modal-bg" id="nt-modal">
  <div class="modal">
    <h3><i class="fas fa-bell"></i> Traffic thresholds — <span id="nt-node">container</span></h3>
    <div class="sub" id="nt-sub">Leave all blank to use the global defaults. Values in MB/s.</div>
    <input type="hidden" id="nt-id">
    <div style="display:flex;gap:10px;margin-bottom:10px;">
      <div style="flex:1;"><label>RX warn (MB/s)</label><input type="number" step="0.1" id="nt-rw" placeholder="global"></div>
      <div style="flex:1;"><label>RX crit (MB/s)</label><input type="number" step="0.1" id="nt-rc" placeholder="global"></div>
    </div>
    <div style="display:flex;gap:10px;margin-bottom:16px;">
      <div style="flex:1;"><label>TX warn (MB/s)</label><input type="number" step="0.1" id="nt-tw" placeholder="global"></div>
      <div style="flex:1;"><label>TX crit (MB/s)</label><input type="number" step="0.1" id="nt-tc" placeholder="global"></div>
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end;">
      <button class="btn" onclick="closeNetThresh()">Cancel</button>
      <button class="btn go" onclick="saveNetThresh()"><i class="fas fa-floppy-disk"></i> Save</button>
    </div>
    <div id="nt-msg" style="font-size:11px;color:#9aa;margin-top:8px;text-align:right;"></div>
  </div>
</div>

<!-- ── Deploy wizard ── -->
<div class="dpl-ov" id="dpl-ov" onclick="if(event.target.id==='dpl-ov')deployClose()">
  <div class="dpl">
    <div class="dpl-h"><i class="fas fa-rocket rk"></i><div><h2 id="dpl-title">Deploy a container</h2><div style="font-size:11px;color:#7c828c;" id="dpl-host"></div></div><i class="fas fa-xmark x" onclick="deployClose()"></i></div>
    <div class="dpl-steps"><div class="st on" id="ds1"></div><div class="st" id="ds2"></div><div class="st" id="ds3"></div></div>
    <div class="dpl-body" id="dpl-body"></div>
    <div class="dpl-foot" id="dpl-foot"></div>
  </div>
</div>
</body>
</html>
