<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Windows-over-SSH suite (shared foundation + Phase 1: Event Log feed).
//
// Windows 10/11 / Server 2019+ ship OpenSSH Server; NEURU reuses its SSH primitive
// (nm_cm_ssh_fetch) to run PowerShell agentlessly — no agent, no WinRM, no SNMP.
// Windows boxes have NO native syslog, so pulling the Event Log here is the single
// biggest observability gap-filler. Later phases (host health, service watchdog,
// AI commander) reuse this same registry + nm_win_ps() runner.
//
// Secrets (SSH creds) decrypt only as www-data → polling runs in the web request
// (cron_winhost.php curls localhost). RBAC perm: 'windows'. UI: windows.php.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_win_ensure')) {
    require_once __DIR__ . '/nm_secrets.php';
    require_once __DIR__ . '/nm_confmgr.php';   // nm_cm_ssh_fetch, nm_cm_resolve_ssh

    function nm_win_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        if (!($conn instanceof mysqli)) return;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_win_hosts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(120) NOT NULL,
            node_id INT DEFAULT NULL,
            host_ip VARCHAR(64) DEFAULT NULL,
            os_caption VARCHAR(160) DEFAULT NULL,
            enabled TINYINT DEFAULT 1,
            status VARCHAR(16) DEFAULT 'new',
            last_event_poll DATETIME DEFAULT NULL,
            last_health_poll DATETIME DEFAULT NULL,
            last_error VARCHAR(300) DEFAULT NULL,
            created_by INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_win_events (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            host_id INT NOT NULL,
            record_id BIGINT DEFAULT NULL,
            log_name VARCHAR(60) DEFAULT NULL,
            event_id INT DEFAULT NULL,
            level TINYINT DEFAULT NULL,
            provider VARCHAR(160) DEFAULT NULL,
            message TEXT,
            created_at DATETIME DEFAULT NULL,
            ingested_at DATETIME DEFAULT NULL,
            UNIQUE KEY uq_evt (host_id, log_name, record_id),
            KEY k_host_time (host_id, created_at),
            KEY k_level (level)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Phase 2: latest host-health snapshot (one JSON blob per host).
        $conn->query("CREATE TABLE IF NOT EXISTS nm_win_health (
            host_id INT PRIMARY KEY,
            data LONGTEXT,
            sampled_at DATETIME DEFAULT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Phase 3: service watchdog — services NEURU keeps an eye on (+ optional auto-restart).
        $conn->query("CREATE TABLE IF NOT EXISTS nm_win_watch (
            id INT AUTO_INCREMENT PRIMARY KEY,
            host_id INT NOT NULL,
            service_name VARCHAR(120) NOT NULL,
            display_name VARCHAR(200) DEFAULT NULL,
            auto_restart TINYINT DEFAULT 0,
            enabled TINYINT DEFAULT 1,
            last_state VARCHAR(20) DEFAULT NULL,
            last_checked DATETIME DEFAULT NULL,
            last_action_at DATETIME DEFAULT NULL,
            restart_count INT DEFAULT 0,
            created_by INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_watch (host_id, service_name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_win_actions (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            host_id INT NOT NULL,
            service_name VARCHAR(120) DEFAULT NULL,
            action VARCHAR(20) DEFAULT NULL,
            ok TINYINT DEFAULT 0,
            detail VARCHAR(400) DEFAULT NULL,
            created_by INT DEFAULT NULL,
            created_at DATETIME DEFAULT NULL,
            KEY k_host (host_id, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','windows',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='windows')");
    }

    // ── Hosts CRUD ────────────────────────────────────────────────────────────
    function nm_win_hosts($conn): array {
        nm_win_ensure($conn);
        $out = [];
        $r = $conn->query("SELECT h.*, n.display_name node_name,
            (SELECT COUNT(*) FROM nm_win_events e WHERE e.host_id=h.id) event_count,
            (SELECT COUNT(*) FROM nm_win_events e WHERE e.host_id=h.id AND e.level<=2 AND e.created_at >= (UTC_TIMESTAMP() - INTERVAL 24 HOUR)) err24
            FROM nm_win_hosts h LEFT JOIN nm_nodes n ON n.id=h.node_id ORDER BY h.name");
        while ($r && ($x=$r->fetch_assoc())) $out[] = $x;
        return $out;
    }
    function nm_win_host($conn, int $id): ?array {
        $r = $conn->query("SELECT * FROM nm_win_hosts WHERE id=".(int)$id." LIMIT 1");
        return $r ? ($r->fetch_assoc() ?: null) : null;
    }
    function nm_win_host_add($conn, array $f, ?int $uid): array {
        nm_win_ensure($conn);
        $name = substr(trim((string)($f['name'] ?? '')), 0, 120);
        if ($name === '') return ['ok'=>false,'error'=>'Name is required'];
        $node = (int)($f['node_id'] ?? 0) ?: null;
        $host = substr(trim((string)($f['host_ip'] ?? '')), 0, 64) ?: null;
        if (!$node && !$host) return ['ok'=>false,'error'=>'Pick a monitored node or enter a host IP (for SSH)'];
        $st = $conn->prepare("INSERT INTO nm_win_hosts (name,node_id,host_ip,created_by) VALUES (?,?,?,?)");
        $st->bind_param('sisi', $name,$node,$host,$uid);
        $st->execute();
        return ['ok'=>true,'id'=>$conn->insert_id];
    }
    function nm_win_host_update($conn, int $id, array $f): array {
        nm_win_ensure($conn);
        $h = nm_win_host($conn, $id); if (!$h) return ['ok'=>false,'error'=>'not found'];
        $name = substr(trim((string)($f['name'] ?? $h['name'])), 0, 120) ?: $h['name'];
        $node = array_key_exists('node_id',$f) ? ((int)$f['node_id'] ?: null) : $h['node_id'];
        $host = array_key_exists('host_ip',$f) ? (substr(trim((string)$f['host_ip']),0,64) ?: null) : $h['host_ip'];
        $en   = array_key_exists('enabled',$f) ? (int)!empty($f['enabled']) : (int)$h['enabled'];
        $st = $conn->prepare("UPDATE nm_win_hosts SET name=?,node_id=?,host_ip=?,enabled=? WHERE id=?");
        $st->bind_param('sisii', $name,$node,$host,$en,$id);
        $st->execute();
        return ['ok'=>true];
    }
    function nm_win_host_delete($conn, int $id): array {
        nm_win_ensure($conn);
        $conn->query("DELETE FROM nm_win_events WHERE host_id=".(int)$id);
        $conn->query("DELETE FROM nm_win_hosts WHERE id=".(int)$id);
        return ['ok'=>true];
    }

    function nm_win_resolve_ssh($conn, array $h): ?array {
        if (!empty($h['node_id'])) return nm_ssh_resolve($conn, (int)$h['node_id']);
        if (!empty($h['host_ip'])) return nm_cm_resolve_ssh($conn, ['host_ip'=>$h['host_ip'],'ssh_cred_id'=>0]);
        return null;
    }

    // Run a PowerShell ONE-LINER over SSH. The Windows OpenSSH default shell is cmd.exe,
    // so we invoke `powershell -Command "<script>"`. Script must be single-line (the SSH
    // helper switches to the broken interactive path for multi-line) and use SINGLE quotes
    // internally (the whole thing is wrapped in cmd double-quotes).
    function nm_win_ps($ssh, string $script, int $timeout = 30): array {
        $cmd = 'powershell -NoProfile -NonInteractive -Command "' . $script . '"';
        return nm_cm_ssh_fetch($ssh, $cmd, $timeout);
    }

    // ── Phase 1: Event Log ────────────────────────────────────────────────────
    // Pull Critical(1)/Error(2)/Warning(3) from System+Application since the last poll.
    function _nm_win_events_ps(int $mins, int $max): string {
        $mins = max(1, min(1440, $mins)); $max = max(1, min(500, $max));
        // Note: \' is a literal single-quote in this PHP single-quoted string; \\s -> \s for the PS regex.
        return '$ErrorActionPreference=\'SilentlyContinue\'; '
             . '$e=Get-WinEvent -FilterHashtable @{LogName=\'System\',\'Application\'; Level=1,2,3; StartTime=(Get-Date).AddMinutes(-'.$mins.')} -MaxEvents '.$max.'; '
             . 'if($e){ $e | Select-Object '
             . '@{n=\'r\';e={$_.RecordId}},'
             . '@{n=\'t\';e={$_.TimeCreated.ToUniversalTime().ToString(\'o\')}},'
             . '@{n=\'lg\';e={$_.LogName}},'
             . '@{n=\'id\';e={$_.Id}},'
             . '@{n=\'lv\';e={$_.Level}},'
             . '@{n=\'p\';e={$_.ProviderName}},'
             . '@{n=\'m\';e={($_.Message -replace \'\\s+\',\' \')}} '
             . '| ConvertTo-Json -Compress -Depth 3 } else { \'[]\' }';
    }
    function nm_win_parse_events(string $json): array {
        $json = trim($json);
        // Strip any stray banner lines the shell might prepend before the JSON.
        $p = strpos($json, '['); $b = strpos($json, '{');
        $s = ($p === false) ? $b : (($b === false) ? $p : min($p, $b));
        if ($s !== false && $s > 0) $json = substr($json, $s);
        $d = json_decode($json, true);
        if (!is_array($d)) return [];
        if (isset($d['r']) || isset($d['id']) || isset($d['lg'])) $d = [$d];   // single object → wrap
        return $d;
    }
    function nm_win_poll_events($conn, array $h): array {
        nm_win_ensure($conn);
        $hid = (int)$h['id'];
        $ssh = nm_win_resolve_ssh($conn, $h);
        if (!$ssh || empty($ssh['username'])) { _nm_win_err($conn,$hid,'No SSH credential resolved (set the node SSH cred or a default)'); return ['ok'=>false,'error'=>'no ssh']; }
        $mins = 30;
        if (!empty($h['last_event_poll'])) { $age = time() - strtotime($h['last_event_poll'].' UTC'); $mins = max(2, min(1440, (int)ceil($age/60) + 2)); }
        $res = nm_win_ps($ssh, _nm_win_events_ps($mins, 300), 35);
        if (!$res['ok']) { _nm_win_err($conn,$hid,'PowerShell/SSH failed: '.substr((string)($res['error'] ?? ''),0,160)); return ['ok'=>false,'error'=>'ssh failed']; }
        $rows = nm_win_parse_events((string)$res['config']);
        $now = gmdate('Y-m-d H:i:s'); $ins = 0;
        $st = $conn->prepare("INSERT IGNORE INTO nm_win_events (host_id,record_id,log_name,event_id,level,provider,message,created_at,ingested_at)
            VALUES (?,?,?,?,?,?,?,?,?)");
        foreach ($rows as $e) {
            $rid = (int)($e['r'] ?? 0);
            $lg  = substr((string)($e['lg'] ?? ''),0,60);
            $eid = (int)($e['id'] ?? 0);
            $lv  = (int)($e['lv'] ?? 0);
            $pv  = substr((string)($e['p'] ?? ''),0,160);
            $msg = substr(trim((string)($e['m'] ?? '')),0,2000);
            $ct  = !empty($e['t']) ? gmdate('Y-m-d H:i:s', strtotime((string)$e['t'])) : $now;
            $st->bind_param('iisiissss', $hid,$rid,$lg,$eid,$lv,$pv,$msg,$ct,$now);
            $st->execute();
            $ins += $st->affected_rows > 0 ? 1 : 0;
        }
        $conn->query("UPDATE nm_win_hosts SET status='ok', last_event_poll='$now', last_error=NULL WHERE id=$hid");
        return ['ok'=>true,'fetched'=>count($rows),'new'=>$ins];
    }
    function _nm_win_err($conn, int $hid, string $msg): void {
        // A connection-level failure = the box is unreachable → show DOWN, not a cryptic error.
        // (Auth / no-credential / config problems stay 'error' with the real message.)
        $down  = (bool)preg_match('/unable to connect|connect failed|errno none|timed out|timeout|no route|refused|unreachable|host is down|network is unreachable|could not resolve|name or service not known|connection reset/i', $msg);
        $status= $down ? 'down' : 'error';
        $clean = $down ? 'Host unreachable — appears DOWN (powered off or no network)' : $msg;
        $e = $conn->real_escape_string(substr($clean,0,290));
        $conn->query("UPDATE nm_win_hosts SET status='$status', last_event_poll='".gmdate('Y-m-d H:i:s')."', last_error='$e' WHERE id=$hid");
    }
    function nm_win_poll_all($conn): array {
        nm_win_ensure($conn);
        $res = []; $hs = [];
        $r = $conn->query("SELECT * FROM nm_win_hosts WHERE enabled=1");
        while ($r && ($x=$r->fetch_assoc())) $hs[] = $x;
        foreach ($hs as $h) {
            $res[$h['id']] = nm_win_poll_events($conn, $h);
            // health is heavier → refresh at most ~every 10 min per host
            $stale = empty($h['last_health_poll']) || (time() - strtotime($h['last_health_poll'].' UTC')) > 600;
            if ($stale) nm_win_poll_health($conn, $h);
            // service watchdog — only does SSH work if the host has enabled watches
            $wc = nm_win_watch_check($conn, $h);
            if (!empty($wc['checked'])) $res[$h['id']]['watch'] = $wc;
        }
        return $res;
    }

    // ── Reads for the UI ──────────────────────────────────────────────────────
    function nm_win_events($conn, int $host_id = 0, array $f = []): array {
        nm_win_ensure($conn);
        $w = [];
        if ($host_id > 0) $w[] = "host_id=".(int)$host_id;
        if (!empty($f['level'])) { $lv=(int)$f['level']; $w[] = "level".($f['level']=='warn'?">=3":"<=".$lv); }
        if (isset($f['lv']) && $f['lv'] !== '' && is_numeric($f['lv'])) $w[] = "level=".(int)$f['lv'];
        if (!empty($f['log']))   $w[] = "log_name='".$conn->real_escape_string($f['log'])."'";
        if (!empty($f['q'])) { $q=$conn->real_escape_string($f['q']); $w[] = "(message LIKE '%$q%' OR provider LIKE '%$q%' OR event_id LIKE '%$q%')"; }
        $where = $w ? ('WHERE '.implode(' AND ',$w)) : '';
        $limit = max(1, min(500, (int)($f['limit'] ?? 200)));
        $out = [];
        $r = $conn->query("SELECT e.*, h.name host_name, TIMESTAMPDIFF(SECOND,e.created_at,UTC_TIMESTAMP()) age
            FROM nm_win_events e JOIN nm_win_hosts h ON h.id=e.host_id $where ORDER BY e.created_at DESC, e.id DESC LIMIT $limit");
        while ($r && ($x=$r->fetch_assoc())) $out[] = $x;
        return $out;
    }
    function nm_win_event_summary($conn, int $host_id = 0): array {
        nm_win_ensure($conn);
        $f = $host_id>0 ? "WHERE host_id=$host_id AND " : "WHERE ";
        $out = ['crit'=>0,'err'=>0,'warn'=>0];
        $r = $conn->query("SELECT level, COUNT(*) c FROM nm_win_events {$f} created_at >= (UTC_TIMESTAMP() - INTERVAL 24 HOUR) GROUP BY level");
        while ($r && ($x=$r->fetch_assoc())) {
            $lv=(int)$x['level']; if($lv==1)$out['crit']=(int)$x['c']; elseif($lv==2)$out['err']=(int)$x['c']; elseif($lv==3)$out['warn']=(int)$x['c'];
        }
        return $out;
    }
    // ── Phase 2: Host health snapshot ────────────────────────────────────────
    // ONE PowerShell one-liner (statements ';'-joined) → a single JSON object. Each
    // optional cmdlet is try/catch-wrapped so one missing feature can't void the snapshot.
    // No backslashes anywhere (keeps the cmd-double-quote/PS-single-quote escaping clean).
    function _nm_win_health_ps(): string {
        $s = [];
        $s[] = '$ErrorActionPreference=\'SilentlyContinue\'';
        $s[] = '$o=@{}';
        $s[] = '$os=Get-CimInstance Win32_OperatingSystem';
        $s[] = '$o.host=$env:COMPUTERNAME';
        $s[] = '$o.os=$os.Caption';
        $s[] = '$o.osver=$os.Version';
        $s[] = 'try { $o.boot=$os.LastBootUpTime.ToUniversalTime().ToString(\'o\') } catch {}';
        $s[] = '$o.mem_total=[math]::Round($os.TotalVisibleMemorySize/1024)';
        $s[] = '$o.mem_free=[math]::Round($os.FreePhysicalMemory/1024)';
        $s[] = '$o.cpu=[int]((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)';
        $s[] = '$o.disks=@(Get-CimInstance Win32_LogicalDisk -Filter \'DriveType=3\' | ForEach-Object { @{id=$_.DeviceID; size=[math]::Round($_.Size/1GB,1); free=[math]::Round($_.FreeSpace/1GB,1)} })';
        $s[] = 'try { $o.pdisks=@(Get-PhysicalDisk | ForEach-Object { @{name=$_.FriendlyName; media=$_.MediaType; health=$_.HealthStatus; op=$_.OperationalStatus} }) } catch {}';
        $s[] = '$svc=Get-CimInstance Win32_Service';
        $s[] = '$o.svc_total=@($svc).Count';
        $s[] = '$o.svc_running=@($svc | Where-Object {$_.State -eq \'Running\'}).Count';
        $s[] = '$o.svc_stopped_auto=@($svc | Where-Object {$_.StartMode -eq \'Auto\' -and $_.State -ne \'Running\'} | ForEach-Object { @{name=$_.Name; disp=$_.DisplayName; state=$_.State} })';
        $s[] = '$o.proc_cpu=@(Get-Process | Sort-Object CPU -Descending | Select-Object -First 6 | ForEach-Object { @{name=$_.ProcessName; cpu=[math]::Round([double]$_.CPU,0); mb=[math]::Round($_.WorkingSet64/1MB,0)} })';
        $s[] = '$o.proc_mem=@(Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 6 | ForEach-Object { @{name=$_.ProcessName; mb=[math]::Round($_.WorkingSet64/1MB,0)} })';
        $s[] = 'try { $hf=Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1; if($hf){ $o.last_hotfix=$hf.HotFixID; $o.last_hotfix_at=($hf.InstalledOn).ToString(\'yyyy-MM-dd\') } } catch {}';
        $s[] = 'try { $d=Get-MpComputerStatus; $o.defender=@{av=[bool]$d.AntivirusEnabled; rt=[bool]$d.RealTimeProtectionEnabled; sig=$d.AntivirusSignatureLastUpdated.ToUniversalTime().ToString(\'o\')} } catch {}';
        $s[] = 'try { $o.firewall=@(Get-NetFirewallProfile | ForEach-Object { @{name=$_.Name; on=[bool]$_.Enabled} }) } catch {}';
        $s[] = '$o | ConvertTo-Json -Depth 4 -Compress';
        return implode('; ', $s);
    }
    function nm_win_poll_health($conn, array $h): array {
        nm_win_ensure($conn);
        $hid = (int)$h['id'];
        $ssh = nm_win_resolve_ssh($conn, $h);
        if (!$ssh || empty($ssh['username'])) { _nm_win_err($conn,$hid,'No SSH credential resolved'); return ['ok'=>false,'error'=>'no ssh']; }
        $res = nm_win_ps($ssh, _nm_win_health_ps(), 45);
        if (!$res['ok']) { _nm_win_err($conn,$hid,'health PowerShell/SSH failed: '.substr((string)($res['error'] ?? ''),0,160)); return ['ok'=>false,'error'=>'ssh failed']; }
        // isolate the JSON object the script printed
        $raw = (string)$res['config']; $b = strpos($raw, '{');
        if ($b === false) { _nm_win_err($conn,$hid,'health: no JSON returned'); return ['ok'=>false,'error'=>'no json']; }
        $json = substr($raw, $b);
        $data = json_decode($json, true);
        if (!is_array($data)) { _nm_win_err($conn,$hid,'health: bad JSON'); return ['ok'=>false,'error'=>'bad json']; }
        $now = gmdate('Y-m-d H:i:s'); $je = $conn->real_escape_string($json);
        $conn->query("INSERT INTO nm_win_health (host_id,data,sampled_at) VALUES ($hid,'$je','$now')
            ON DUPLICATE KEY UPDATE data=VALUES(data),sampled_at=VALUES(sampled_at)");
        // capture OS caption onto the host row (one-time/refresh)
        if (!empty($data['os'])) $conn->query("UPDATE nm_win_hosts SET os_caption='".$conn->real_escape_string(substr((string)$data['os'],0,160))."', last_health_poll='$now' WHERE id=$hid");
        else $conn->query("UPDATE nm_win_hosts SET last_health_poll='$now' WHERE id=$hid");
        return ['ok'=>true,'sections'=>array_keys($data)];
    }
    function nm_win_health_get($conn, int $host_id): array {
        nm_win_ensure($conn);
        $r = $conn->query("SELECT data, sampled_at, TIMESTAMPDIFF(SECOND,sampled_at,UTC_TIMESTAMP()) age FROM nm_win_health WHERE host_id=".(int)$host_id." LIMIT 1");
        $x = $r ? $r->fetch_assoc() : null;
        if (!$x) return ['ok'=>true,'has'=>false];
        $d = json_decode((string)$x['data'], true);
        return ['ok'=>true,'has'=>is_array($d),'data'=>is_array($d)?$d:null,'sampled_at'=>$x['sampled_at'],'age'=>(int)$x['age']];
    }

    // ── Live System Diagnostics ("what is eating this box") ───────────────────
    // One on-demand PowerShell one-liner that takes a 0.7s two-sample snapshot so it
    // can report LIVE per-process CPU% and network throughput (not just cumulative).
    // Aggregates processes by name (so chrome's 30 PIDs become one row), and returns
    // a single JSON object: memory, cpu, top mem/cpu consumers, net rate + TCP talkers,
    // disks. Every fragile cmdlet is try/catch-wrapped. No backslashes (escaping clean).
    function _nm_win_diag_ps(): string {
        $s = [];
        $s[] = '$ErrorActionPreference=\'SilentlyContinue\'';
        $s[] = '$o=@{}';
        $s[] = '$os=Get-CimInstance Win32_OperatingSystem';
        $s[] = '$cs=Get-CimInstance Win32_ComputerSystem';
        $s[] = '$cores=[int]$cs.NumberOfLogicalProcessors';
        $s[] = 'if($cores -lt 1){$cores=1}';
        $s[] = '$o.host=$env:COMPUTERNAME';
        $s[] = '$o.cores=$cores';
        $s[] = '$o.cpu=[int]((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)';
        $s[] = '$mt=[math]::Round($os.TotalVisibleMemorySize/1024)';
        $s[] = '$mf=[math]::Round($os.FreePhysicalMemory/1024)';
        $s[] = '$o.mem_total=$mt';
        $s[] = '$o.mem_free=$mf';
        $s[] = '$o.mem_used=$mt-$mf';
        $s[] = '$o.mem_pct=if($mt){[math]::Round((($mt-$mf)/$mt)*100,1)}else{0}';
        $s[] = '$o.commit_total=[math]::Round($os.TotalVirtualMemorySize/1024)';
        $s[] = '$o.commit_used=[math]::Round(($os.TotalVirtualMemorySize-$os.FreeVirtualMemory)/1024)';
        // sample 1 — cpu seconds per PID + cumulative net bytes
        $s[] = '$c1=@{}';
        $s[] = 'foreach($p in Get-Process){ $c1[$p.Id]=[double]$p.CPU }';
        $s[] = '$nr1=0;$ns1=0';
        $s[] = 'try{ $sx=Get-NetAdapterStatistics; $nr1=($sx|Measure-Object -Property ReceivedBytes -Sum).Sum; $ns1=($sx|Measure-Object -Property SentBytes -Sum).Sum }catch{}';
        $s[] = '$t1=Get-Date';
        $s[] = 'Start-Sleep -Milliseconds 700';
        $s[] = '$dt=((Get-Date)-$t1).TotalSeconds';
        $s[] = 'if($dt -le 0){$dt=0.7}';
        // sample 2 — aggregate processes by name; cpu% = delta cpu-seconds / interval / cores
        $s[] = '$agg=@{}';
        $s[] = 'foreach($p in Get-Process){ $n=$p.ProcessName; if(-not $agg.ContainsKey($n)){ $agg[$n]=@{name=$n;ws=[double]0;cpu=[double]0;inst=0} }; $a=$agg[$n]; $a.ws+=$p.WorkingSet64; $a.inst++; $pc=$c1[$p.Id]; if($pc -eq $null){$pc=0}; $d=([double]$p.CPU-$pc); if($d -gt 0){$a.cpu+=$d} }';
        $s[] = '$rows=@($agg.Values | ForEach-Object { $_.mb=[math]::Round($_.ws/1MB,0); $_.pct=[math]::Round((($_.cpu/$dt)/$cores)*100,1); $_ })';
        $s[] = '$o.top_mem=@($rows | Sort-Object ws -Descending | Select-Object -First 10 | ForEach-Object { @{name=$_.name;mb=$_.mb;inst=$_.inst;pct=$_.pct} })';
        $s[] = '$o.top_cpu=@($rows | Where-Object {$_.pct -gt 0} | Sort-Object pct -Descending | Select-Object -First 8 | ForEach-Object { @{name=$_.name;pct=$_.pct;mb=$_.mb} })';
        // net throughput (KB/s) over the interval
        $s[] = 'try{ $sy=Get-NetAdapterStatistics; $nr2=($sy|Measure-Object -Property ReceivedBytes -Sum).Sum; $ns2=($sy|Measure-Object -Property SentBytes -Sum).Sum; $o.net_rx=[math]::Round(((($nr2-$nr1)/$dt))/1KB,1); $o.net_tx=[math]::Round(((($ns2-$ns1)/$dt))/1KB,1) }catch{}';
        // top processes by established TCP connections (network talkers)
        $s[] = 'try{ $o.net_conn=@(Get-NetTCPConnection -State Established | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { $op=$_.Name; $pn=(Get-Process -Id $op -ErrorAction SilentlyContinue).ProcessName; @{name=$pn;conns=$_.Count} }) }catch{}';
        // disk capacity per fixed volume
        $s[] = '$o.disks=@(Get-CimInstance Win32_LogicalDisk -Filter \'DriveType=3\' | ForEach-Object { $u=$_.Size-$_.FreeSpace; @{id=$_.DeviceID;size=[math]::Round($_.Size/1GB,1);free=[math]::Round($_.FreeSpace/1GB,1);pct=if($_.Size){[math]::Round(($u/$_.Size)*100,0)}else{0}} })';
        // Fans + temps. Windows has no native fan-RPM API, so prefer the LibreHardwareMonitor /
        // OpenHardwareMonitor WMI namespace (if that helper runs); fall back to Win32_Fan (rarely
        // populated) and ACPI thermal-zone temps. sensor_src tells the UI where the data came from.
        // MERGE every available namespace (LHM AND OHM — they often expose different sensors:
        // LHM the CPU/mobo, OHM the GPU) and capture EVERY sensor type (Voltage/Clock/Load/Power/
        // Control/…), not just fans+temps. Dedup by type|name (first source wins), preserve order,
        // soft-cap at 300. fans/temps are derived from the full set for their dedicated panel.
        $s[] = '$o.fans=@(); $o.temps=@(); $o.sensors=@(); $o.sensor_src=\'\'; $o.sensor_types=@()';
        $s[] = '$sH=[ordered]@{}; $typH=@{}; $srcs=@()';
        $s[] = 'foreach($nsx in @(\'root/LibreHardwareMonitor\',\'root/OpenHardwareMonitor\')){ try{ $sens=Get-CimInstance -Namespace $nsx -ClassName Sensor -ErrorAction Stop; if(-not $sens){continue}; $srcs+=($nsx -replace \'root/\',\'\'); foreach($x in $sens){ $st=[string]$x.SensorType; if(-not $st){continue}; if($typH.ContainsKey($st)){$typH[$st]++}else{$typH[$st]=1}; $nm=[string]$x.Name; $key=$st+\'|\'+$nm; if(-not $sH.Contains($key) -and $sH.Count -lt 300){ $sH[$key]=@{type=$st;name=$nm;val=[math]::Round([double]$x.Value,2)} } } }catch{} }';
        $s[] = '$o.sensor_src=($srcs -join \'+\'); $o.sensors=@($sH.Values); $o.sensor_types=@($typH.Keys | ForEach-Object { @{type=[string]$_;n=$typH[$_]} })';
        $s[] = '$o.fans=@($o.sensors | Where-Object {$_.type -eq \'Fan\'} | ForEach-Object { @{name=$_.name;rpm=[int]$_.val} })';
        $s[] = '$o.temps=@($o.sensors | Where-Object {$_.type -eq \'Temperature\'} | ForEach-Object { @{name=$_.name;c=$_.val} })';
        // HWiNFO (Pro, or free within its 12h shared-memory window) exposes root/HWiNFO with a
        // different schema — filter by Unit (RPM / *C; degree char avoided for clean SSH transport).
        $s[] = 'if(@($o.fans).Count -eq 0 -and @($o.temps).Count -eq 0){ try{ $hw=Get-CimInstance -Namespace root/HWiNFO -ClassName Sensor -ErrorAction Stop; if($hw){ $o.sensor_src=\'HWiNFO\'; $o.fans=@($hw | Where-Object {$_.Unit -eq \'RPM\'} | ForEach-Object { $nm=$_.LabelUser; if(-not $nm){$nm=$_.LabelOrig}; @{name=[string]$nm;rpm=[int]$_.Value} }); $o.temps=@($hw | Where-Object {$_.Unit -like \'*C\'} | ForEach-Object { $nm=$_.LabelUser; if(-not $nm){$nm=$_.LabelOrig}; @{name=[string]$nm;c=[math]::Round([double]$_.Value,1)} }) } }catch{} }';
        $s[] = 'if(@($o.fans).Count -eq 0){ try{ $o.fans=@(Get-CimInstance Win32_Fan -ErrorAction Stop | Where-Object {$_.DesiredSpeed -gt 0} | ForEach-Object { @{name=[string]$_.DeviceID;rpm=[int]$_.DesiredSpeed} }); if(@($o.fans).Count -gt 0 -and -not $o.sensor_src){ $o.sensor_src=\'Win32_Fan\' } }catch{} }';
        $s[] = 'if(@($o.temps).Count -eq 0){ try{ $i=0; $o.temps=@(Get-CimInstance -Namespace root/WMI -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop | ForEach-Object { $i++; @{name=(\'Thermal zone \'+$i);c=[math]::Round((($_.CurrentTemperature/10)-273.15),1)} }); if(@($o.temps).Count -gt 0 -and -not $o.sensor_src){ $o.sensor_src=\'ACPI\' } }catch{} }';
        $s[] = '$o | ConvertTo-Json -Depth 5 -Compress';
        return implode('; ', $s);
    }
    // Run the live diagnostic snapshot over SSH. On-demand only (not stored) — it is a
    // point-in-time troubleshooting probe. Returns ['ok'=>true,'data'=>{...}].
    function nm_win_diagnose($conn, array $h): array {
        nm_win_ensure($conn);
        $ssh = nm_win_resolve_ssh($conn, $h);
        if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'No SSH credential resolved (set the node SSH cred or a default).'];
        $res = nm_win_ps($ssh, _nm_win_diag_ps(), 55);
        if (!$res['ok']) return ['ok'=>false,'error'=>'PowerShell/SSH failed: '.substr((string)($res['error'] ?? ''),0,200)];
        $data = _nm_win_json((string)$res['config']);
        if (!is_array($data)) return ['ok'=>false,'error'=>'Host returned no/invalid JSON.','raw'=>substr(trim((string)$res['config']),0,300)];
        return ['ok'=>true,'data'=>$data,'host'=>$h['name'] ?? ''];
    }
    // Force-kill every process with this base name (Stop-Process -Name kills all PIDs of
    // that name — matches the by-name aggregation in the diagnostics view). Destructive +
    // audited. The name is allowlist-validated (so it can never inject into the PowerShell)
    // and a set of crash-critical OS processes is refused outright.
    function _nm_win_proc_protected(string $name): bool {
        static $p = ['idle','system','registry','memory compression','csrss','wininit','winlogon',
                     'services','lsass','lsaiso','smss','svchost','fontdrvhost','dwm','wudfhost','sshd'];
        return in_array(strtolower(trim($name)), $p, true);
    }
    function nm_win_kill_process($conn, array $h, string $name, ?int $uid): array {
        nm_win_ensure($conn);
        $name = trim($name);
        if (!preg_match('/^[A-Za-z0-9 ._()+#@-]{1,80}$/', $name)) return ['ok'=>false,'error'=>'Invalid process name.'];
        if (_nm_win_proc_protected($name)) return ['ok'=>false,'error'=>'Refusing to kill a protected system process ('.$name.').'];
        $ssh = nm_win_resolve_ssh($conn, $h);
        if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'No SSH credential resolved.'];
        $hid = (int)$h['id'];
        // name is allowlisted to [A-Za-z0-9 ._()+#@-] → safe to embed in PS single quotes.
        $ps = '$ErrorActionPreference=\'Stop\'; try{ $p=@(Get-Process -Name \''.$name.'\' -ErrorAction Stop); $c=$p.Count; $p | Stop-Process -Force -ErrorAction Stop; (@{ok=$true;killed=$c} | ConvertTo-Json -Compress) }catch{ (@{ok=$false;err=($_.Exception.Message)} | ConvertTo-Json -Compress) }';
        $res = nm_win_ps($ssh, $ps, 30);
        if (!$res['ok']) { nm_win_action_log($conn,$hid,$name,'kill',false,'SSH/PowerShell failed',$uid); return ['ok'=>false,'error'=>'SSH/PowerShell failed.']; }
        $d = _nm_win_json((string)$res['config']);
        $ok = is_array($d) && !empty($d['ok']);
        $detail = $ok ? ('killed '.(int)($d['killed'] ?? 0).' instance(s)') : ('error: '.substr((string)($d['err'] ?? 'unknown'),0,160));
        nm_win_action_log($conn,$hid,$name,'kill',$ok,$detail,$uid);
        return $ok ? ['ok'=>true,'killed'=>(int)($d['killed'] ?? 0)] : ['ok'=>false,'error'=>(string)($d['err'] ?? 'Kill failed (likely access denied — needs an admin SSH account).')];
    }

    // ── Phase 3: Service watchdog + self-heal ────────────────────────────────
    // Windows service short-names are alphanumeric+._- ; enforce it so a name can never
    // inject into the PowerShell command we build.
    function _nm_win_svc_ok(string $name): bool { return (bool)preg_match('/^[A-Za-z0-9._-]{1,120}$/', $name); }
    // Pull the first JSON array/object out of shell output (skip any banner) → PHP value.
    function _nm_win_json(string $raw) {
        $raw = trim($raw);
        $p = strpos($raw, '['); $b = strpos($raw, '{');
        $s = ($p === false) ? $b : (($b === false) ? $p : min($p, $b));
        if ($s === false) return null;
        return json_decode(substr($raw, $s), true);
    }

    function nm_win_watches($conn, int $host_id): array {
        nm_win_ensure($conn);
        $out = [];
        $r = $conn->query("SELECT *, TIMESTAMPDIFF(SECOND,last_checked,UTC_TIMESTAMP()) checked_age FROM nm_win_watch WHERE host_id=".(int)$host_id." ORDER BY display_name, service_name");
        while ($r && ($x=$r->fetch_assoc())) $out[] = $x;
        return $out;
    }
    function nm_win_watch_add($conn, int $host_id, array $f, ?int $uid): array {
        nm_win_ensure($conn);
        $svc = trim((string)($f['service_name'] ?? ''));
        if (!_nm_win_svc_ok($svc)) return ['ok'=>false,'error'=>'Invalid service name (letters, digits, . _ - only)'];
        $disp = substr(trim((string)($f['display_name'] ?? $svc)), 0, 200);
        $auto = (int)!empty($f['auto_restart']);
        $st = $conn->prepare("INSERT INTO nm_win_watch (host_id,service_name,display_name,auto_restart,created_by) VALUES (?,?,?,?,?)
            ON DUPLICATE KEY UPDATE display_name=VALUES(display_name),auto_restart=VALUES(auto_restart),enabled=1");
        $st->bind_param('issii', $host_id,$svc,$disp,$auto,$uid);
        $st->execute();
        return ['ok'=>true];
    }
    function nm_win_watch_update($conn, int $id, array $f): array {
        nm_win_ensure($conn);
        $r = $conn->query("SELECT * FROM nm_win_watch WHERE id=".(int)$id." LIMIT 1");
        $w = $r ? $r->fetch_assoc() : null; if (!$w) return ['ok'=>false,'error'=>'not found'];
        $auto = array_key_exists('auto_restart',$f) ? (int)!empty($f['auto_restart']) : (int)$w['auto_restart'];
        $en   = array_key_exists('enabled',$f) ? (int)!empty($f['enabled']) : (int)$w['enabled'];
        $conn->query("UPDATE nm_win_watch SET auto_restart=$auto, enabled=$en WHERE id=".(int)$id);
        return ['ok'=>true];
    }
    function nm_win_watch_delete($conn, int $id): array {
        nm_win_ensure($conn);
        $conn->query("DELETE FROM nm_win_watch WHERE id=".(int)$id);
        return ['ok'=>true];
    }
    function nm_win_action_log($conn, int $hid, string $svc, string $action, bool $ok, string $detail, ?int $uid): void {
        $okI = $ok ? 1 : 0; $now = gmdate('Y-m-d H:i:s'); $d = substr($detail,0,390);
        $st = $conn->prepare("INSERT INTO nm_win_actions (host_id,service_name,action,ok,detail,created_by,created_at) VALUES (?,?,?,?,?,?,?)");
        $st->bind_param('ississs', $hid,$svc,$action,$okI,$d,$uid,$now);
        $st->execute();
    }
    function nm_win_actions_recent($conn, int $host_id, int $limit = 30): array {
        nm_win_ensure($conn);
        $limit = max(1, min(200, $limit));
        $w = $host_id>0 ? "WHERE host_id=".(int)$host_id : "";
        $out = [];
        $r = $conn->query("SELECT a.*, h.name host_name, TIMESTAMPDIFF(SECOND,a.created_at,UTC_TIMESTAMP()) age FROM nm_win_actions a JOIN nm_win_hosts h ON h.id=a.host_id $w ORDER BY a.id DESC LIMIT $limit");
        while ($r && ($x=$r->fetch_assoc())) $out[] = $x;
        return $out;
    }

    // Live list of ALL services on a host (for the picker). Read-only SSH.
    function nm_win_services_live($conn, array $h): array {
        $ssh = nm_win_resolve_ssh($conn, $h);
        if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'No SSH credential resolved'];
        $ps = 'Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode | Sort-Object DisplayName | ConvertTo-Json -Compress';
        $res = nm_win_ps($ssh, $ps, 35);
        if (!$res['ok']) return ['ok'=>false,'error'=>'query failed'];
        $d = _nm_win_json((string)$res['config']);
        if (is_array($d) && isset($d['Name'])) $d = [$d];
        return ['ok'=>true,'services'=>is_array($d)?$d:[]];
    }

    // Start or restart a service over SSH (operator action OR watchdog). Audited.
    function nm_win_service_action($conn, array $h, string $svc, string $action, ?int $uid): array {
        if (!_nm_win_svc_ok($svc)) return ['ok'=>false,'error'=>'invalid service name'];
        $ssh = nm_win_resolve_ssh($conn, $h);
        if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'No SSH credential resolved'];
        $inner = $action === 'restart' ? "Restart-Service -Name '$svc' -Force -ErrorAction Stop" : "Start-Service -Name '$svc' -ErrorAction Stop";
        $ps = "try { $inner; 'NEURU_OK' } catch { 'NEURU_ERR:' + \$_.Exception.Message }";
        $res = nm_win_ps($ssh, $ps, 45);
        $out = (string)($res['config'] ?? '');
        $ok  = $res['ok'] && strpos($out, 'NEURU_OK') !== false;
        $detail = $ok ? ($action.'ed ok') : (preg_match('/NEURU_ERR:(.+)/s',$out,$m) ? trim($m[1]) : (string)($res['error'] ?? 'failed'));
        nm_win_action_log($conn, (int)$h['id'], $svc, $action, $ok, $detail, $uid);
        return ['ok'=>$ok,'detail'=>substr($detail,0,300)];
    }
    function nm_win_service_action_by_id($conn, int $host_id, string $svc, string $action, ?int $uid): array {
        $h = nm_win_host($conn, $host_id); if (!$h) return ['ok'=>false,'error'=>'no host'];
        return nm_win_service_action($conn, $h, $svc, in_array($action,['start','restart'])?$action:'start', $uid);
    }

    // The watchdog sweep: read watched-service states; auto-restart any that are stopped
    // (auto_restart=1) with a 5-min backoff so it never loops. Safety: auto_restart is OFF
    // by default — a watch only acts once you explicitly arm it.
    function nm_win_watch_check($conn, array $h): array {
        $hid = (int)$h['id'];
        $ws = [];
        $r = $conn->query("SELECT * FROM nm_win_watch WHERE host_id=$hid AND enabled=1");
        while ($r && ($x=$r->fetch_assoc())) $ws[] = $x;
        if (!$ws) return ['ok'=>true,'checked'=>0,'acted'=>0];
        $ssh = nm_win_resolve_ssh($conn, $h);
        if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'no ssh'];
        $list = implode(',', array_map(fn($w)=>"'".$w['service_name']."'", $ws));   // names are sanitized on add
        $ps = "Get-Service -Name $list -ErrorAction SilentlyContinue | Select-Object @{n='n';e={\$_.Name}},@{n='s';e={[string]\$_.Status}} | ConvertTo-Json -Compress";
        $res = nm_win_ps($ssh, $ps, 30);
        if (!$res['ok']) return ['ok'=>false,'error'=>'ssh failed'];
        $d = _nm_win_json((string)$res['config']);
        if (is_array($d) && isset($d['n'])) $d = [$d];
        $states = [];
        if (is_array($d)) foreach ($d as $row) if (isset($row['n'])) $states[strtolower((string)$row['n'])] = (string)$row['s'];
        $now = gmdate('Y-m-d H:i:s'); $acted = 0;
        foreach ($ws as $w) {
            $st = $states[strtolower($w['service_name'])] ?? 'Unknown';
            $prev = (string)($w['last_state'] ?? '');
            $downNow = ($st !== 'Unknown' && strcasecmp($st,'Running') !== 0);
            $wasRunning = ($prev === '' || strcasecmp($prev,'Running') === 0);
            $conn->query("UPDATE nm_win_watch SET last_state='".$conn->real_escape_string($st)."', last_checked='$now' WHERE id=".(int)$w['id']);
            if ((int)$w['auto_restart'] === 1 && $st !== 'Unknown' && strcasecmp($st,'Running') !== 0) {
                $back = empty($w['last_action_at']) || (time() - strtotime($w['last_action_at'].' UTC')) > 300;
                if ($back) {
                    nm_win_service_action($conn, $h, $w['service_name'], 'start', null);  // auto = no uid (system)
                    $conn->query("UPDATE nm_win_watch SET last_action_at='$now', restart_count=restart_count+1 WHERE id=".(int)$w['id']);
                    $acted++;
                }
            }
            // Notification Center: only on the running→down transition (no per-tick spam).
            if ($downNow && $wasRunning) {
                if (!function_exists('nm_notify_event')) { @include_once __DIR__.'/nm_notify.php'; }
                if (function_exists('nm_notify_event')) {
                    $hn = $h['hostname'] ?? $h['display_name'] ?? $h['name'] ?? ('host#'.$hid);
                    @nm_notify_event($conn,'service','warning',
                        "Service {$w['service_name']} is {$st} on {$hn}",
                        ((int)$w['auto_restart']===1?'Watchdog auto-restart attempted.':'This service is not armed for auto-restart.'),
                        ['node_id'=>($h['node_id']??null),'entity'=>$w['service_name'],'source'=>'watchdog']);
                }
            }
        }
        return ['ok'=>true,'checked'=>count($ws),'acted'=>$acted];
    }

    function nm_win_prune($conn, int $days = 30): void {
        nm_win_ensure($conn);
        $days = max(1, min(365, $days));
        $conn->query("DELETE FROM nm_win_events WHERE ingested_at < (UTC_TIMESTAMP() - INTERVAL $days DAY)");
        $conn->query("DELETE FROM nm_win_actions WHERE created_at < (UTC_TIMESTAMP() - INTERVAL $days DAY)");
    }
}
