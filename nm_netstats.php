<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — container network sampling (persisted history). Shared by the live
// Network view (containers.php) and the background recorder (cron_netstats.php)
// so per-container RX/TX rates accumulate in `container_net_samples` 24/7, not
// only while someone has the tab open. HTTP-denied via .htaccess.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_portainer.php';
require_once __DIR__ . '/nm_n8n.php';        // shared token (for alert notify webhook)

if (!function_exists('nm_netstats_sample')) {

    function nm_netstats_ensure($conn): void {
        $conn->query("CREATE TABLE IF NOT EXISTS container_net_samples (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            endpoint_id INT NOT NULL,
            container_id VARCHAR(64) NOT NULL,
            container_name VARCHAR(128) NOT NULL,
            rx_bytes BIGINT NOT NULL DEFAULT 0,
            tx_bytes BIGINT NOT NULL DEFAULT 0,
            rx_rate DOUBLE NOT NULL DEFAULT 0,
            tx_rate DOUBLE NOT NULL DEFAULT 0,
            sampled_at DATETIME NOT NULL,
            INDEX idx_ct (endpoint_id, container_id, id),
            INDEX idx_time (sampled_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    }

    // Sample every running container's net counters on $eid, diff vs the last
    // stored sample to get bytes/sec, persist, prune >$retainHours. Returns
    // [rows(desc by total rate), error]. Bounded by an 18s wall-clock budget and a
    // one-shot stats call (instant counters, no CPU-delta wait).
    function nm_netstats_sample($conn, $cfg, int $eid, int $retainHours = 24): array {
        nm_netstats_ensure($conn);
        $r = nm_portainer_containers($cfg, $eid, false);   // all=0 → running only
        if (!$r['ok']) return [[], $r['error']];
        $now = time(); $rows = []; $deadline = microtime(true) + 18;
        $sel = $conn->prepare("SELECT rx_bytes,tx_bytes,UNIX_TIMESTAMP(sampled_at) ts FROM container_net_samples WHERE endpoint_id=? AND container_id=? ORDER BY id DESC LIMIT 1");
        $ins = $conn->prepare("INSERT INTO container_net_samples (endpoint_id,container_id,container_name,rx_bytes,tx_bytes,rx_rate,tx_rate,sampled_at) VALUES (?,?,?,?,?,?,?,FROM_UNIXTIME(?))");
        foreach ((array)$r['data'] as $c) {
            if (microtime(true) > $deadline) break;
            $n = nm_portainer_norm_container($c); $cid = $n['cid']; if ($cid === '') continue;
            $s = nm_portainer_container_stats($cfg, $eid, $cid, 6, true); if (!$s['ok']) continue;
            $st = nm_portainer_norm_stats($s['data']);
            $rx = (int)$st['net_rx']; $tx = (int)$st['net_tx']; $rxR = 0.0; $txR = 0.0;
            $sel->bind_param('is', $eid, $cid); $sel->execute(); $prev = $sel->get_result()->fetch_assoc();
            if ($prev) { $dt = max(1, $now - (int)$prev['ts']);
                $drx = $rx - (int)$prev['rx_bytes']; $dtx = $tx - (int)$prev['tx_bytes'];
                if ($drx >= 0) $rxR = $drx / $dt; if ($dtx >= 0) $txR = $dtx / $dt; }
            $ins->bind_param('issiiddi', $eid, $cid, $n['name'], $rx, $tx, $rxR, $txR, $now); $ins->execute();
            $rows[] = ['cid'=>$cid,'name'=>$n['name'],'rx'=>$rx,'tx'=>$tx,'rx_rate'=>$rxR,'tx_rate'=>$txR];
        }
        usort($rows, fn($a,$b)=>($b['rx_rate']+$b['tx_rate'])<=>($a['rx_rate']+$a['tx_rate']));
        $conn->query("DELETE FROM container_net_samples WHERE sampled_at < (NOW() - INTERVAL ".max(1,(int)$retainHours)." HOUR)");
        try { nm_netalert_eval($conn); } catch (\Throwable $e) { /* alerts are best-effort */ }
        return [$rows, ''];
    }

    // Top talkers aggregated over the last $hours (the persisted-history payoff).
    // $eid<=0 → across ALL endpoints (for the dashboard widget). Best-effort: a
    // missing table just yields []. Returns rows desc by avg total rate.
    function nm_netstats_top($conn, int $eid = 0, int $hours = 1, int $limit = 8): array {
        $out = [];
        $where = $eid > 0 ? "endpoint_id=".(int)$eid." AND " : "";
        try {
            $q = $conn->query("SELECT container_name, container_id, MAX(endpoint_id) endpoint_id,
                               AVG(rx_rate+tx_rate) avgr, MAX(rx_rate+tx_rate) maxr,
                               (MAX(rx_bytes)-MIN(rx_bytes)) drx, (MAX(tx_bytes)-MIN(tx_bytes)) dtx
                               FROM container_net_samples
                               WHERE {$where}sampled_at > (NOW() - INTERVAL ".max(1,(int)$hours)." HOUR)
                               GROUP BY container_id, container_name ORDER BY avgr DESC LIMIT ".max(1,(int)$limit));
            if ($q) while ($x = $q->fetch_assoc()) $out[] = ['name'=>$x['container_name'],
                'cid'=>$x['container_id'], 'endpoint'=>(int)$x['endpoint_id'],
                'avg'=>(float)$x['avgr'],'peak'=>(float)$x['maxr'],'rx'=>max(0,(int)$x['drx']),'tx'=>max(0,(int)$x['dtx'])];
        } catch (\Throwable $e) { $out = []; }
        return $out;
    }

    // ── Container-network alerts (mirror of the Smokeping latency alerts) ──────
    // Thresholds are in MB/s (friendly); rates are stored in bytes/sec.
    function nm_netalert_ensure($conn): void {
        $conn->query("CREATE TABLE IF NOT EXISTS nm_netalert_thresholds (
            scope_key VARCHAR(64) PRIMARY KEY,        /* '__global__' or a container_id */
            rx_warn DOUBLE NULL, rx_crit DOUBLE NULL, tx_warn DOUBLE NULL, tx_crit DOUBLE NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_netalert_alerts (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            container_id VARCHAR(64) NOT NULL, container_name VARCHAR(128) NOT NULL,
            severity VARCHAR(8) NOT NULL, metric VARCHAR(8) NOT NULL,
            value DOUBLE NULL, threshold DOUBLE NULL, state VARCHAR(8) NOT NULL DEFAULT 'open',
            opened_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, cleared_at DATETIME NULL,
            INDEX idx_cont_state (container_id, state), INDEX idx_state_time (state, opened_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("INSERT IGNORE INTO nm_netalert_thresholds (scope_key,rx_warn,rx_crit,tx_warn,tx_crit) VALUES ('__global__',10,50,10,50)");
    }
    function nm_netalert_thresholds($conn): array {
        nm_netalert_ensure($conn);
        $g = ['rx_warn'=>10,'rx_crit'=>50,'tx_warn'=>10,'tx_crit'=>50]; $c = [];
        $r = $conn->query("SELECT * FROM nm_netalert_thresholds");
        while ($r && $x = $r->fetch_assoc()) {
            $row = ['rx_warn'=>$x['rx_warn'],'rx_crit'=>$x['rx_crit'],'tx_warn'=>$x['tx_warn'],'tx_crit'=>$x['tx_crit']];
            if ($x['scope_key'] === '__global__') $g = $row; else $c[$x['scope_key']] = $row;
        }
        return ['global'=>$g, 'containers'=>$c];
    }
    function nm_netalert_threshold_save($conn, $key, array $t): void {
        nm_netalert_ensure($conn);
        $f = fn($k) => (isset($t[$k]) && $t[$k] !== '' && is_numeric($t[$k])) ? (float)$t[$k] : null;
        $rw=$f('rx_warn'); $rc=$f('rx_crit'); $tw=$f('tx_warn'); $tc=$f('tx_crit');
        $st = $conn->prepare("INSERT INTO nm_netalert_thresholds (scope_key,rx_warn,rx_crit,tx_warn,tx_crit) VALUES (?,?,?,?,?)
                              ON DUPLICATE KEY UPDATE rx_warn=VALUES(rx_warn),rx_crit=VALUES(rx_crit),tx_warn=VALUES(tx_warn),tx_crit=VALUES(tx_crit)");
        $st->bind_param('sdddd', $key, $rw, $rc, $tw, $tc); $st->execute();
    }
    function nm_netalert_threshold_clear($conn, $key): void {
        if ($key !== '__global__') { $st = $conn->prepare("DELETE FROM nm_netalert_thresholds WHERE scope_key=?"); $st->bind_param('s', $key); $st->execute(); }
    }
    function _nm_net_sev(array $vals, $warn, $crit): int {
        $vals = array_filter($vals, fn($v) => $v !== null); if (!$vals) return 0;
        if ($crit !== null && $crit !== '' && count(array_filter($vals, fn($v) => $v >= (float)$crit)) === count($vals)) return 2;
        if ($warn !== null && $warn !== '' && count(array_filter($vals, fn($v) => $v >= (float)$warn)) === count($vals)) return 1;
        return 0;
    }
    // Evaluate the latest samples vs thresholds; open/clear/escalate one alert per container.
    function nm_netalert_eval($conn): array {
        nm_netalert_ensure($conn);
        $get = function($k,$d='') use($conn){ $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; };
        if ($get('netalert_enabled','1') === '0') return ['ok'=>true,'skipped'=>'disabled'];
        $sustain = max(1, min(10, (int)($get('netalert_sustain','2') ?: 2)));
        $url = trim($get('netalert_url',''));
        $thr = nm_netalert_thresholds($conn); $glob = $thr['global']; $sevName = [0=>'ok',1=>'warn',2=>'crit'];
        $MB = 1048576.0; $opened=0; $cleared=0; $changed=0;
        $cres = $conn->query("SELECT container_id, MAX(container_name) nm FROM container_net_samples WHERE sampled_at > (NOW() - INTERVAL 2 HOUR) GROUP BY container_id");
        while ($cres && $cr = $cres->fetch_assoc()) {
            $cid = $cr['container_id']; $nm = $cr['nm']; $cidEsc = $conn->real_escape_string($cid);
            $t = $thr['containers'][$cid] ?? $glob;
            $sres = $conn->query("SELECT rx_rate,tx_rate FROM container_net_samples WHERE container_id='{$cidEsc}' ORDER BY id DESC LIMIT {$sustain}");
            $rx=[]; $tx=[]; $lrx=null; $ltx=null;
            while ($sres && $sx = $sres->fetch_assoc()) { $rv=(float)$sx['rx_rate']/$MB; $tv=(float)$sx['tx_rate']/$MB; $rx[]=$rv; $tx[]=$tv; if($lrx===null)$lrx=$rv; if($ltx===null)$ltx=$tv; }
            if (!$rx) continue;
            $rxSev = _nm_net_sev($rx,$t['rx_warn'],$t['rx_crit']);
            $txSev = _nm_net_sev($tx,$t['tx_warn'],$t['tx_crit']);
            if ($rxSev >= $txSev) { $sev=$rxSev; $metric='rx'; $val=$lrx*$MB; $thv=($rxSev===2?$t['rx_crit']:$t['rx_warn']); }
            else { $sev=$txSev; $metric='tx'; $val=$ltx*$MB; $thv=($txSev===2?$t['tx_crit']:$t['tx_warn']); }
            $thvB = ($thv !== null && $thv !== '') ? (float)$thv*$MB : null;
            $or = $conn->query("SELECT id,severity FROM nm_netalert_alerts WHERE container_id='{$cidEsc}' AND state='open' ORDER BY id DESC LIMIT 1");
            $open = $or ? $or->fetch_assoc() : null;
            if ($sev === 0) { if ($open) { $conn->query("UPDATE nm_netalert_alerts SET state='cleared',cleared_at=NOW(),updated_at=NOW() WHERE id=".(int)$open['id']); $cleared++; nm_netalert_notify($conn,$url,'clear',$cid,$nm,$open['severity'],$metric,$val,$thvB); } }
            elseif (!$open) { $sn=$sevName[$sev]; $st=$conn->prepare("INSERT INTO nm_netalert_alerts (container_id,container_name,severity,metric,value,threshold,state,opened_at,updated_at) VALUES (?,?,?,?,?,?, 'open',NOW(),NOW())"); $st->bind_param('ssssdd',$cid,$nm,$sn,$metric,$val,$thvB); $st->execute(); $opened++; nm_netalert_notify($conn,$url,'open',$cid,$nm,$sn,$metric,$val,$thvB); }
            else { $sn=$sevName[$sev]; $st=$conn->prepare("UPDATE nm_netalert_alerts SET severity=?,metric=?,value=?,threshold=?,updated_at=NOW() WHERE id=?"); $oid=(int)$open['id']; $st->bind_param('ssddi',$sn,$metric,$val,$thvB,$oid); $st->execute(); if($open['severity']!==$sn){ $changed++; nm_netalert_notify($conn,$url,($sn==='crit'?'escalate':'change'),$cid,$nm,$sn,$metric,$val,$thvB); } }
        }
        return ['ok'=>true,'opened'=>$opened,'cleared'=>$cleared,'changed'=>$changed];
    }
    function nm_netalert_notify($conn, $url, $event, $cid, $nm, $sev, $metric, $val, $thv): void {
        if ($url === '' || !function_exists('curl_init')) return;
        // Site-wide notification gate: honor maintenance windows ('all' or source 'netstats').
        if (!function_exists('nm_notify_maint_active')) @require_once __DIR__ . '/nm_notify.php';
        if (function_exists('nm_notify_maint_active') && nm_notify_maint_active($conn, null, 'netstats')) return;
        $cfg = nm_n8n_get($conn);
        $payload = ['event'=>$event,'kind'=>'container_net','container_id'=>$cid,'container'=>$nm,'severity'=>$sev,
            'metric'=>$metric,'value'=>$val,'threshold'=>$thv,'unit'=>'B/s','at'=>date('c')];
        $ch=curl_init($url); curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>json_encode($payload),
            CURLOPT_CONNECTTIMEOUT=>4,CURLOPT_TIMEOUT=>10,CURLOPT_SSL_VERIFYPEER=>false,
            CURLOPT_HTTPHEADER=>['Content-Type: application/json','X-NetMon-Token: '.$cfg['inbound_token']]]); curl_exec($ch); curl_close($ch);
    }
    function nm_netalert_active($conn, $recentHours = 24): array {
        nm_netalert_ensure($conn);
        $open=[]; $recent=[];
        $r=$conn->query("SELECT * FROM nm_netalert_alerts WHERE state='open' ORDER BY FIELD(severity,'crit','warn'), opened_at DESC");
        while($r && $x=$r->fetch_assoc()) $open[]=$x;
        $r=$conn->query("SELECT * FROM nm_netalert_alerts WHERE state='cleared' AND cleared_at > (NOW() - INTERVAL ".(int)$recentHours." HOUR) ORDER BY cleared_at DESC LIMIT 20");
        while($r && $x=$r->fetch_assoc()) $recent[]=$x;
        return ['open'=>$open,'recent'=>$recent];
    }
}
