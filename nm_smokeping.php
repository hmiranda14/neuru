<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Smokeping data layer. Smokeping does the latency polling (FPing→RRD);
// NEURU pulls those samples via the n8n SSH flow (rrdtool fetch) and stores them
// in its OWN table (nm_latency_samples) so the portal owns the history and renders
// its own charts — no Smokeping page embed needed. Shared by smokeping.php (UI +
// history API) and cron_smokeping.php (background recorder). HTTP-denied.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_secrets.php';   // nm_ssh_resolve_host
require_once __DIR__ . '/nm_n8n.php';       // shared inbound token
require_once __DIR__ . '/nm_confmgr.php';   // nm_cm_ssh_fetch — direct SSH to the host (native, no n8n)

if (!function_exists('nm_sp_record')) {

    function nm_sp_settings($conn): array {
        $g = function ($k, $d = '') use ($conn) {
            $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1");
            return $r && ($x = $r->fetch_row()) ? $x[0] : $d;
        };
        return [
            'url'           => $g('smokeping_url', ''),
            'enabled'       => $g('smokeping_enabled', '0') === '1',
            'host_ip'       => $g('smokeping_host_ip', ''),
            'container'     => $g('smokeping_container', '') ?: 'smokeping',
            'targets_path'  => $g('smokeping_targets_path', '') ?: '/config/Targets',
            'manage_url'    => $g('smokeping_manage_url', ''),
            'reload_cmd'    => $g('smokeping_reload_cmd', ''),
            'data_path'     => $g('smokeping_data_path', '') ?: '/data',
            'section'       => 'NEURU',
            'retention_days'=> (int)($g('smokeping_retention_days', '90') ?: 90),
        ];
    }

    function nm_sp_valid_path($s) { return (bool)preg_match('#^[A-Za-z0-9_./-]{1,200}$#', (string)$s); }
    function nm_sp_valid_host($s) { return (bool)preg_match('/^[A-Za-z0-9_.:-]{1,100}$/', (string)$s); }

    // NEURU nodes ⇒ Smokeping targets (tied by IP). Stable key from display name.
    function nm_sp_node_targets($conn): array {
        $rows = []; $seen = [];
        $r = $conn->query("SELECT id, display_name, ip_address, COALESCE(monitor_type,'snmp') mt FROM nm_nodes WHERE ip_address IS NOT NULL AND ip_address<>'' ORDER BY display_name");
        while ($r && $x = $r->fetch_assoc()) {
            $ip = trim($x['ip_address']);
            if ($ip === '' || !nm_sp_valid_host($ip)) continue;
            $key = preg_replace('/_+/', '_', trim(preg_replace('/[^A-Za-z0-9_]/', '_', $x['display_name']), '_'));
            if ($key === '') $key = 'node' . $x['id'];
            if (isset($seen[$key])) $key .= '_' . $x['id'];
            $seen[$key] = 1;
            $rows[] = ['id'=>(int)$x['id'], 'name'=>$x['display_name'], 'ip'=>$ip, 'key'=>$key, 'mt'=>$x['mt']];
        }
        return $rows;
    }

    // POST a host command to the n8n manage webhook (SSH-runs it). Sends a complete
    // ssh{} (resolved + validated) so the dynamic SSH never falls back to localhost.
    function nm_sp_call_manage($conn, array $SP, string $action, string $command): array {
        if (trim($SP['manage_url']) === '') return ['ok'=>false,'error'=>'No manage webhook configured'];
        if (trim($SP['host_ip']) === '')    return ['ok'=>false,'error'=>'No Docker host IP configured'];
        $ssh = nm_ssh_resolve_host($conn, $SP['host_ip']);
        if (!$ssh) return ['ok'=>false,'error'=>'No SSH credential for host '.$SP['host_ip']];
        $ssh['host'] = $SP['host_ip']; $ssh['port'] = (int)($ssh['port'] ?? 22) ?: 22;
        if (empty($ssh['username']) || (empty($ssh['password']) && empty($ssh['private_key'])))
            return ['ok'=>false,'error'=>'SSH credential for '.$SP['host_ip'].' is incomplete'];
        $cfg = nm_n8n_get($conn);
        $payload = ['action'=>$action,'command'=>$command,'host_ip'=>$SP['host_ip'],'container'=>$SP['container'],
            'targets_path'=>$SP['targets_path'],'ssh'=>$ssh,'ssh_user'=>$ssh['username'],
            'ssh_password'=>$ssh['password'] ?? '','ssh_port'=>$ssh['port'],'ssh_host'=>$SP['host_ip']];
        if(function_exists('nm_n8n_neuru_stamp'))$payload=nm_n8n_neuru_stamp($conn,$payload,$SP['manage_url']);  // hosted-flow gatecheck
        $ch = curl_init($SP['manage_url']);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>json_encode($payload),
            CURLOPT_CONNECTTIMEOUT=>5, CURLOPT_TIMEOUT=>45, CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_SSL_VERIFYHOST=>false,
            CURLOPT_HTTPHEADER=>['Content-Type: application/json','X-NetMon-Token: '.$cfg['inbound_token']]]);
        $body = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $cerr = curl_error($ch); curl_close($ch);
        if ($body === false || $code === 0) return ['ok'=>false,'error'=>'Cannot reach manage webhook: '.($cerr ?: 'connection failed')];
        if ($code < 200 || $code >= 300) return ['ok'=>false,'error'=>"Webhook HTTP {$code}"];
        $j = json_decode($body, true);
        if (!is_array($j)) return ['ok'=>true,'stdout'=>(string)$body,'stderr'=>''];
        return ['ok'=>($j['ok'] ?? true), 'stdout'=>(string)($j['stdout'] ?? ($j['output'] ?? '')), 'stderr'=>(string)($j['stderr'] ?? '')];
    }

    // Native host exec for the recorder — DIRECT SSH only (Smokeping runs on a host NEURU can reach;
    // n8n is no longer used for Smokeping). Returns ['ok','stdout','stderr'].
    function nm_sp_run($conn, array $SP, string $action, string $command): array {
        if (!function_exists('nm_cm_ssh_fetch') || !function_exists('nm_ssh_resolve_host') || trim((string)$SP['host_ip']) === '')
            return ['ok'=>false,'error'=>'Smokeping host IP / SSH not configured'];
        $ssh = nm_ssh_resolve_host($conn, $SP['host_ip']);
        if (!$ssh || empty($ssh['username']) || (empty($ssh['password']) && empty($ssh['private_key'])))
            return ['ok'=>false,'error'=>'No complete SSH credential for host '.$SP['host_ip'].' (Config → SSH Credentials)'];
        $ssh['host'] = $SP['host_ip']; $ssh['port'] = (int)($ssh['port'] ?? 22) ?: 22;
        $r = nm_cm_ssh_fetch($ssh, $command . "\necho NMSPEND", 35);
        if (empty($r['ok'])) return ['ok'=>false,'error'=>$r['error'] ?? 'SSH failed'];
        // strip the interactive shell's echoed command + terminal escapes; keep from the first @@@ block
        $out = preg_replace('/\x1b\[[0-9;?]*[A-Za-z]/', '', (string)($r['config'] ?? ''));
        $p = strpos($out, '@@@'); if ($p !== false) $out = substr($out, $p);
        return ['ok'=>true,'stdout'=>$out,'stderr'=>''];
    }

    function nm_sp_ensure($conn): void {
        $conn->query("CREATE TABLE IF NOT EXISTS nm_latency_samples (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            node_id INT NOT NULL,
            target_key VARCHAR(64) NOT NULL,
            rtt_ms DOUBLE NULL,
            loss DOUBLE NULL,
            sampled_at DATETIME NOT NULL,
            UNIQUE KEY uniq_node_ts (node_id, sampled_at),
            INDEX idx_time (sampled_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    }

    // Parse `rrdtool fetch` dump (blocks prefixed @@@<key>). Smokeping FPing DS:
    // uptime, loss, median, ping1..N. Returns [ key => [ [ts,rtt_ms,loss], ... ] ].
    function nm_sp_parse_fetch($text): array {
        $out = [];
        foreach (preg_split('/^@@@/m', (string)$text) as $blk) {
            $blk = rtrim($blk); if (trim($blk) === '') continue;
            $lines = preg_split('/\r?\n/', $blk);
            $key = trim(array_shift($lines)); if ($key === '') continue;
            $hdr = null; $rows = [];
            foreach ($lines as $ln) {
                $ln = rtrim($ln); if (trim($ln) === '') continue;
                if (preg_match('/^(\d+):\s*(.+)$/', $ln, $m)) {
                    if (!$hdr) continue;
                    $vals = preg_split('/\s+/', trim($m[2]));
                    $mi = $hdr['median']; $li = $hdr['loss'];
                    $med = ($mi !== null && isset($vals[$mi])) ? $vals[$mi] : null;
                    $los = ($li !== null && isset($vals[$li])) ? $vals[$li] : null;
                    $rtt = (is_numeric($med)) ? round((float)$med * 1000, 3) : null;     // s→ms, NaN→null
                    $rows[] = [(int)$m[1], $rtt, (is_numeric($los) ? (float)$los : null)];
                } elseif ($hdr === null && preg_match('/[a-zA-Z]/', $ln)) {
                    $names = preg_split('/\s+/', trim($ln)); $flip = array_flip($names);
                    $hdr = ['median'=>$flip['median'] ?? null, 'loss'=>$flip['loss'] ?? null];
                }
            }
            if ($rows) $out[$key] = $rows;
        }
        return $out;
    }

    // Pull the last $hours of samples from every NEURU RRD and store new rows.
    // Idempotent (INSERT IGNORE on node_id+sampled_at). Returns counts/errors.
    function nm_sp_record($conn, array $SP = null, int $hours = 2): array {
        if ($SP === null) $SP = nm_sp_settings($conn);
        if (!$SP['enabled']) return ['ok'=>false,'error'=>'Smokeping disabled'];
        if (trim($SP['host_ip']) === '') return ['ok'=>false,'error'=>'Smokeping host IP not configured (Config → Integrations → Smokeping)'];
        nm_sp_ensure($conn);
        $dir = rtrim($SP['data_path'], '/') . '/' . $SP['section'];
        if (!nm_sp_valid_path($dir)) return ['ok'=>false,'error'=>'Invalid data path'];
        // map target key → node id
        $keyToNode = [];
        foreach (nm_sp_node_targets($conn) as $nd) $keyToNode[$nd['key']] = $nd['id'];

        $hours = max(1, min(168, $hours));
        $cmd = "docker exec " . escapeshellarg($SP['container']) . " sh -c "
             . escapeshellarg('D=' . escapeshellarg($dir)
                 . '; for f in "$D"/*.rrd; do [ -e "$f" ] || continue; n=$(basename "$f" .rrd); echo "@@@$n"; rrdtool fetch "$f" AVERAGE -s now-' . ($hours * 3600) . ' -e now 2>/dev/null; done');
        $r = nm_sp_run($conn, $SP, 'fetch', $cmd);
        if (!$r['ok']) return ['ok'=>false,'error'=>$r['error'] ?? 'fetch failed','stderr'=>$r['stderr'] ?? ''];

        $parsed = nm_sp_parse_fetch($r['stdout']);
        $ins = $conn->prepare("INSERT IGNORE INTO nm_latency_samples (node_id,target_key,rtt_ms,loss,sampled_at) VALUES (?,?,?,?,FROM_UNIXTIME(?))");
        $n = 0; $targets = 0;
        foreach ($parsed as $key => $rows) {
            $nid = $keyToNode[$key] ?? 0; if (!$nid) continue;   // only tied-to-node targets
            $targets++;
            foreach ($rows as $row) {
                [$ts, $rtt, $loss] = $row;
                if ($rtt === null && $loss === null) continue;     // skip empty (future) buckets
                $ins->bind_param('isddi', $nid, $key, $rtt, $loss, $ts);
                $ins->execute(); $n += $ins->affected_rows > 0 ? 1 : 0;
            }
        }
        $conn->query("DELETE FROM nm_latency_samples WHERE sampled_at < (NOW() - INTERVAL ".max(1,(int)$SP['retention_days'])." DAY)");
        $ev = nm_sp_eval_alerts($conn, $SP);   // evaluate thresholds on the fresh data
        return ['ok'=>true, 'inserted'=>$n, 'targets'=>$targets, 'alerts'=>$ev];
    }

    // Compact last-$hours RTT series per node, for the row sparklines (one query).
    function nm_sp_spark_all($conn, int $hours = 1, int $cap = 60): array {
        nm_sp_ensure($conn);
        $hours = max(1, min(72, $hours));
        $r = $conn->query("SELECT node_id, rtt_ms FROM nm_latency_samples
                           WHERE sampled_at > (NOW() - INTERVAL {$hours} HOUR) ORDER BY node_id, sampled_at ASC");
        $out = [];
        while ($r && $x = $r->fetch_assoc()) { $out[(int)$x['node_id']][] = $x['rtt_ms']!==null ? (float)$x['rtt_ms'] : null; }
        foreach ($out as $k => $arr) if (count($arr) > $cap) $out[$k] = array_slice($arr, -$cap);
        return $out;
    }

    // ── Latency alerts ────────────────────────────────────────────────────────
    function nm_sp_alert_ensure($conn): void {
        $conn->query("CREATE TABLE IF NOT EXISTS nm_latency_thresholds (
            node_id INT PRIMARY KEY,            /* 0 = global default; >0 = per-node override */
            rtt_warn DOUBLE NULL, rtt_crit DOUBLE NULL,
            loss_warn DOUBLE NULL, loss_crit DOUBLE NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_latency_alerts (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            node_id INT NOT NULL, severity VARCHAR(8) NOT NULL, metric VARCHAR(8) NOT NULL,
            value DOUBLE NULL, threshold DOUBLE NULL, state VARCHAR(8) NOT NULL DEFAULT 'open',
            opened_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, cleared_at DATETIME NULL,
            INDEX idx_node_state (node_id, state), INDEX idx_state_time (state, opened_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // seed sensible global defaults once: warn 120ms / crit 300ms, loss warn 5% / crit 15%
        // (1% loss was far too sensitive — most paths blip ≥1% and fired constant false alarms)
        $conn->query("INSERT IGNORE INTO nm_latency_thresholds (node_id,rtt_warn,rtt_crit,loss_warn,loss_crit) VALUES (0,120,300,5,15)");
    }

    // [global => {...}, nodes => {id:{...}}]. Effective(node) = its row else global.
    function nm_sp_thresholds($conn): array {
        nm_sp_alert_ensure($conn);
        $g = ['rtt_warn'=>120,'rtt_crit'=>300,'loss_warn'=>5,'loss_crit'=>15]; $nodes = [];
        $r = $conn->query("SELECT * FROM nm_latency_thresholds");
        while ($r && $x = $r->fetch_assoc()) {
            $row = ['rtt_warn'=>$x['rtt_warn'],'rtt_crit'=>$x['rtt_crit'],'loss_warn'=>$x['loss_warn'],'loss_crit'=>$x['loss_crit']];
            if ((int)$x['node_id'] === 0) $g = $row; else $nodes[(int)$x['node_id']] = $row;
        }
        return ['global'=>$g, 'nodes'=>$nodes];
    }
    function nm_sp_threshold_save($conn, int $nodeId, array $t): void {
        nm_sp_alert_ensure($conn);
        $f = fn($k) => (isset($t[$k]) && $t[$k] !== '' && is_numeric($t[$k])) ? (float)$t[$k] : null;
        $rw=$f('rtt_warn'); $rc=$f('rtt_crit'); $lw=$f('loss_warn'); $lc=$f('loss_crit');
        $st = $conn->prepare("INSERT INTO nm_latency_thresholds (node_id,rtt_warn,rtt_crit,loss_warn,loss_crit)
                              VALUES (?,?,?,?,?) ON DUPLICATE KEY UPDATE rtt_warn=VALUES(rtt_warn),rtt_crit=VALUES(rtt_crit),loss_warn=VALUES(loss_warn),loss_crit=VALUES(loss_crit)");
        $st->bind_param('idddd', $nodeId, $rw, $rc, $lw, $lc); $st->execute();
    }
    function nm_sp_threshold_clear($conn, int $nodeId): void {
        if ($nodeId > 0) { $st=$conn->prepare("DELETE FROM nm_latency_thresholds WHERE node_id=?"); $st->bind_param('i',$nodeId); $st->execute(); }
    }

    // sustained severity for a metric: 2(crit) if last-N all ≥ crit, 1(warn) if all ≥ warn, else 0.
    function _nm_sp_sev(array $vals, $warn, $crit): int {
        $vals = array_filter($vals, fn($v) => $v !== null);
        if (!$vals) return 0;
        if ($crit !== null && $crit !== '' && count(array_filter($vals, fn($v) => $v >= (float)$crit)) === count($vals)) return 2;
        if ($warn !== null && $warn !== '' && count(array_filter($vals, fn($v) => $v >= (float)$warn)) === count($vals)) return 1;
        return 0;
    }

    // Evaluate the latest samples against thresholds; open/clear/escalate alerts.
    // Best-effort notify to smokeping_alert_url on open/clear/escalate.
    function nm_sp_eval_alerts($conn, array $SP = null): array {
        if ($SP === null) $SP = nm_sp_settings($conn);
        nm_sp_alert_ensure($conn);
        $get = function($k,$d='') use($conn){ $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; };
        if ($get('smokeping_alerts_enabled','1') === '0') {
            // Feature disabled → don't OPEN new alerts, but still CLEAR any that are already open.
            // Returning early here (the old behavior) froze every open alert in 'open' FOREVER — a stuck
            // alert keeps regenerating its incident even after the user acks/deletes it. Auto-heal instead.
            $conn->query("UPDATE nm_latency_alerts SET state='cleared', cleared_at=NOW(), updated_at=NOW() WHERE state='open'");
            return ['ok'=>true,'skipped'=>'disabled','cleared_open'=>$conn->affected_rows];
        }
        $sustain = max(1, min(10, (int)($get('smokeping_alert_sustain','2') ?: 2)));
        $notifyUrl = trim($get('smokeping_alert_url',''));

        $thr = nm_sp_thresholds($conn); $glob = $thr['global'];
        $sevName = [0=>'ok',1=>'warn',2=>'crit'];
        $opened = 0; $cleared = 0; $changed = 0;

        $nodesRes = $conn->query("SELECT DISTINCT node_id FROM nm_latency_samples WHERE sampled_at > (NOW() - INTERVAL 2 HOUR)");
        while ($nodesRes && $nr = $nodesRes->fetch_assoc()) {
            $nid = (int)$nr['node_id'];
            $t = $thr['nodes'][$nid] ?? $glob;
            $sres = $conn->query("SELECT rtt_ms, loss FROM nm_latency_samples WHERE node_id={$nid} ORDER BY id DESC LIMIT {$sustain}");
            $rtts = []; $loss = []; $latestR = null; $latestL = null;
            while ($sres && $sx = $sres->fetch_assoc()) {
                $rv = $sx['rtt_ms']!==null?(float)$sx['rtt_ms']:null; $lv = $sx['loss']!==null?(float)$sx['loss']:null;
                $rtts[] = $rv; $loss[] = $lv; if ($latestR===null) $latestR=$rv; if ($latestL===null) $latestL=$lv;
            }
            if (!$rtts) continue;
            $rttSev = _nm_sp_sev($rtts, $t['rtt_warn'], $t['rtt_crit']);
            $lossSev = _nm_sp_sev($loss, $t['loss_warn'], $t['loss_crit']);
            if ($rttSev >= $lossSev) { $sev=$rttSev; $metric='rtt'; $val=$latestR; $thv=($rttSev===2?$t['rtt_crit']:$t['rtt_warn']); }
            else { $sev=$lossSev; $metric='loss'; $val=$latestL; $thv=($lossSev===2?$t['loss_crit']:$t['loss_warn']); }

            $or = $conn->query("SELECT id, severity FROM nm_latency_alerts WHERE node_id={$nid} AND state='open' ORDER BY id DESC LIMIT 1");
            $open = $or ? $or->fetch_assoc() : null;

            if ($sev === 0) {
                if ($open) { $conn->query("UPDATE nm_latency_alerts SET state='cleared', cleared_at=NOW(), updated_at=NOW() WHERE id=".(int)$open['id']);
                    $cleared++; nm_sp_notify($conn,$notifyUrl,'clear',$nid,$open['severity'],$metric,$val,$thv); }
            } elseif (!$open) {
                $sn=$sevName[$sev]; $st=$conn->prepare("INSERT INTO nm_latency_alerts (node_id,severity,metric,value,threshold,state,opened_at,updated_at) VALUES (?,?,?,?,?, 'open', NOW(), NOW())");
                $st->bind_param('issdd',$nid,$sn,$metric,$val,$thv); $st->execute();
                $opened++; nm_sp_notify($conn,$notifyUrl,'open',$nid,$sn,$metric,$val,$thv);
            } else {
                $sn=$sevName[$sev];
                $st=$conn->prepare("UPDATE nm_latency_alerts SET severity=?, metric=?, value=?, threshold=?, updated_at=NOW() WHERE id=?");
                $oid=(int)$open['id']; $st->bind_param('ssddi',$sn,$metric,$val,$thv,$oid); $st->execute();
                if ($open['severity'] !== $sn) { $changed++; nm_sp_notify($conn,$notifyUrl,($sn==='crit'?'escalate':'change'),$nid,$sn,$metric,$val,$thv); }
            }
        }
        return ['ok'=>true,'opened'=>$opened,'cleared'=>$cleared,'changed'=>$changed];
    }

    function nm_sp_notify($conn, string $url, string $event, int $nid, string $sev, string $metric, $val, $thv): void {
        if ($url === '' || !function_exists('curl_init')) return;
        // Site-wide notification gate: honor maintenance windows (this node, or 'all'/'smokeping').
        if (!function_exists('nm_notify_maint_active')) @require_once __DIR__ . '/nm_notify.php';
        if (function_exists('nm_notify_maint_active') && nm_notify_maint_active($conn, $nid, 'smokeping')) return;
        $nm = ''; $r=$conn->query("SELECT display_name,ip_address FROM nm_nodes WHERE id={$nid} LIMIT 1"); if($r&&$x=$r->fetch_assoc()){ $nm=$x['display_name']; $ip=$x['ip_address']; }
        $cfg = nm_n8n_get($conn);
        $payload = ['event'=>$event,'kind'=>'latency','node_id'=>$nid,'node'=>$nm,'ip'=>$ip??'','severity'=>$sev,
            'metric'=>$metric,'value'=>$val,'threshold'=>$thv,'unit'=>($metric==='rtt'?'ms':'loss'),'at'=>date('c')];
        if(function_exists('nm_n8n_neuru_stamp'))$payload=nm_n8n_neuru_stamp($conn,$payload,$url);  // hosted-flow gatecheck
        $ch=curl_init($url);
        curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>json_encode($payload),
            CURLOPT_CONNECTTIMEOUT=>4,CURLOPT_TIMEOUT=>10,CURLOPT_SSL_VERIFYPEER=>false,
            CURLOPT_HTTPHEADER=>['Content-Type: application/json','X-NetMon-Token: '.$cfg['inbound_token']]]);
        curl_exec($ch); curl_close($ch);
    }

    // Active (open) alerts + recently cleared, joined with node info, for the UI.
    function nm_sp_alerts($conn, int $recentHours = 24): array {
        nm_sp_alert_ensure($conn);
        $open = []; $recent = [];
        $r = $conn->query("SELECT a.*, n.display_name, n.ip_address FROM nm_latency_alerts a JOIN nm_nodes n ON n.id=a.node_id
                           WHERE a.state='open' ORDER BY FIELD(a.severity,'crit','warn') , a.opened_at DESC");
        while ($r && $x = $r->fetch_assoc()) $open[] = $x;
        $r = $conn->query("SELECT a.*, n.display_name, n.ip_address FROM nm_latency_alerts a JOIN nm_nodes n ON n.id=a.node_id
                           WHERE a.state='cleared' AND a.cleared_at > (NOW() - INTERVAL {$recentHours} HOUR) ORDER BY a.cleared_at DESC LIMIT 20");
        while ($r && $x = $r->fetch_assoc()) $recent[] = $x;
        return ['open'=>$open, 'recent'=>$recent];
    }

    // History for one node (for NEURU's own chart). Returns rows asc by time.
    function nm_sp_history($conn, int $nodeId, int $hours = 24): array {
        nm_sp_ensure($conn);
        $hours = max(1, min(720, $hours));
        $out = [];
        $st = $conn->prepare("SELECT UNIX_TIMESTAMP(sampled_at) ts, rtt_ms, loss FROM nm_latency_samples
                              WHERE node_id=? AND sampled_at > (NOW() - INTERVAL {$hours} HOUR) ORDER BY sampled_at ASC");
        $st->bind_param('i', $nodeId); $st->execute(); $res = $st->get_result();
        // Insert a null marker wherever the recorder was down for a while, so the
        // chart breaks the line into an HONEST gap instead of drawing a flat bridge
        // across hours of missing samples. 900s = 3× the 5-min recorder cadence.
        $GAP = 900; $prev = null;
        while ($x = $res->fetch_assoc()) {
            $ts = (int)$x['ts'];
            if ($prev !== null && ($ts - $prev) > $GAP) {
                $out[] = ['t'=>$prev + 300, 'rtt'=>null, 'loss'=>null];
            }
            $out[] = ['t'=>$ts, 'rtt'=>($x['rtt_ms']!==null?(float)$x['rtt_ms']:null), 'loss'=>($x['loss']!==null?(float)$x['loss']:null)];
            $prev = $ts;
        }
        return $out;
    }
}
