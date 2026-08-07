<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — AI / GPU Server Monitor (engine).
//
// GPUs have NO native SNMP OID for utilization, so — like the industry standard
// (nvidia-smi/NVML, dcgm, LibreNMS' SNMP-extend) — we run the vendor CLI over SSH
// and parse it. Agentless: reuses NEURU's SSH primitive (nm_cm_ssh_fetch).
//   • Nvidia  → nvidia-smi  (util/VRAM/temp/power/clocks + per-process VRAM)
//   • AMD     → rocm-smi --json
//   • Generic → Windows PowerShell GPU performance counters (vendor-agnostic)
// AI-aware layer: polls the Ollama API (/api/ps over SSH-localhost, so it works
// even when Ollama binds 127.0.0.1) to correlate GPU load with the loaded model.
//
// Secrets (SSH creds) decrypt only as www-data → polling runs in the web request
// (cron_gpu.php curls localhost). RBAC perm: 'gpu'. UI: gpu.php.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_gpu_ensure')) {
    require_once __DIR__ . '/nm_secrets.php';
    require_once __DIR__ . '/nm_confmgr.php';   // nm_cm_ssh_fetch, nm_cm_resolve_ssh

    function nm_gpu_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        if (!($conn instanceof mysqli)) return;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_gpu_targets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(120) NOT NULL,
            node_id INT DEFAULT NULL,
            host_ip VARCHAR(64) DEFAULT NULL,
            ollama_url VARCHAR(200) DEFAULT NULL,
            vendor VARCHAR(16) DEFAULT NULL,
            temp_warn INT DEFAULT 85,
            vram_warn INT DEFAULT 90,
            enabled TINYINT DEFAULT 1,
            status VARCHAR(16) DEFAULT 'new',
            last_poll DATETIME DEFAULT NULL,
            last_error VARCHAR(300) DEFAULT NULL,
            created_by INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_gpu (
            id INT AUTO_INCREMENT PRIMARY KEY,
            target_id INT NOT NULL,
            gpu_index INT NOT NULL,
            uuid VARCHAR(80) DEFAULT NULL,
            name VARCHAR(160) DEFAULT NULL,
            vendor VARCHAR(16) DEFAULT NULL,
            memory_total_mb INT DEFAULT NULL,
            driver_version VARCHAR(40) DEFAULT NULL,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT NULL,
            UNIQUE KEY uq_gpu (target_id, gpu_index)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_gpu_stats (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            gpu_id INT NOT NULL,
            util_pct FLOAT DEFAULT NULL,
            mem_util_pct FLOAT DEFAULT NULL,
            mem_used_mb INT DEFAULT NULL,
            mem_total_mb INT DEFAULT NULL,
            temp_c FLOAT DEFAULT NULL,
            power_w FLOAT DEFAULT NULL,
            power_limit_w FLOAT DEFAULT NULL,
            fan_pct FLOAT DEFAULT NULL,
            clock_sm_mhz INT DEFAULT NULL,
            sampled_at DATETIME NOT NULL,
            KEY k_gpu_time (gpu_id, sampled_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_gpu_proc (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            gpu_id INT NOT NULL,
            pid INT DEFAULT NULL,
            used_mb INT DEFAULT NULL,
            name VARCHAR(200) DEFAULT NULL,
            sampled_at DATETIME NOT NULL,
            KEY k_gpu (gpu_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_gpu_models (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            target_id INT NOT NULL,
            name VARCHAR(160) DEFAULT NULL,
            size_mb INT DEFAULT NULL,
            vram_mb INT DEFAULT NULL,
            expires_at DATETIME DEFAULT NULL,
            sampled_at DATETIME NOT NULL,
            KEY k_t (target_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','gpu',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='gpu')");

        // AI/LLM columns (guarded — mysqli is in exception mode, a blind ALTER would fatal)
        _nm_gpu_col($conn,'nm_gpu_targets','ollama_version',"ollama_version VARCHAR(40) DEFAULT NULL");
        _nm_gpu_col($conn,'nm_gpu_targets','ollama_ok',"ollama_ok TINYINT DEFAULT NULL");
        _nm_gpu_col($conn,'nm_gpu_models','running',"running TINYINT DEFAULT 0");
        _nm_gpu_col($conn,'nm_gpu_models','family',"family VARCHAR(80) DEFAULT NULL");
        _nm_gpu_col($conn,'nm_gpu_models','params',"params VARCHAR(40) DEFAULT NULL");
        _nm_gpu_col($conn,'nm_gpu_models','quant',"quant VARCHAR(40) DEFAULT NULL");
        _nm_gpu_col($conn,'nm_gpu_models','modified_at',"modified_at DATETIME DEFAULT NULL");
    }
    function _nm_gpu_col($conn, string $table, string $col, string $ddl): void {
        try { $r = $conn->query("SHOW COLUMNS FROM `$table` LIKE '".$conn->real_escape_string($col)."'");
              if ($r && $r->num_rows === 0) $conn->query("ALTER TABLE `$table` ADD COLUMN $ddl");
        } catch (\Throwable $e) { /* best-effort */ }
    }

    // numeric SQL literal or NULL (nvidia prints "[N/A]" / "[Not Supported]" for
    // unsupported sensors — those must land as NULL, never 0).
    function _nm_gpu_num($v) {
        if ($v === null) return 'NULL';
        $v = trim((string)$v);
        if ($v === '' || !is_numeric($v)) return 'NULL';
        return 0 + $v;
    }

    // ── Targets CRUD ──────────────────────────────────────────────────────────
    function nm_gpu_targets($conn): array {
        nm_gpu_ensure($conn);
        $out = [];
        $r = $conn->query("SELECT t.*, n.display_name node_name,
            (SELECT COUNT(*) FROM nm_gpu g WHERE g.target_id=t.id) gpu_count
            FROM nm_gpu_targets t LEFT JOIN nm_nodes n ON n.id=t.node_id ORDER BY t.name");
        while ($r && ($x = $r->fetch_assoc())) $out[] = $x;
        return $out;
    }
    function nm_gpu_target($conn, int $id): ?array {
        $r = $conn->query("SELECT * FROM nm_gpu_targets WHERE id=".(int)$id." LIMIT 1");
        return $r ? ($r->fetch_assoc() ?: null) : null;
    }
    function nm_gpu_target_add($conn, array $f, ?int $uid): array {
        nm_gpu_ensure($conn);
        $name = substr(trim((string)($f['name'] ?? '')), 0, 120);
        if ($name === '') return ['ok'=>false,'error'=>'Name is required'];
        $node = (int)($f['node_id'] ?? 0) ?: null;
        $host = substr(trim((string)($f['host_ip'] ?? '')), 0, 64) ?: null;
        if (!$node && !$host) return ['ok'=>false,'error'=>'Pick a monitored node or enter a host IP (for SSH)'];
        $oll  = substr(trim((string)($f['ollama_url'] ?? '')), 0, 200) ?: null;
        $tw   = max(0, min(150, (int)($f['temp_warn'] ?? 85)));
        $vw   = max(1, min(100, (int)($f['vram_warn'] ?? 90)));
        $st = $conn->prepare("INSERT INTO nm_gpu_targets (name,node_id,host_ip,ollama_url,temp_warn,vram_warn,created_by) VALUES (?,?,?,?,?,?,?)");
        $st->bind_param('sissiii', $name,$node,$host,$oll,$tw,$vw,$uid);
        $st->execute();
        return ['ok'=>true,'id'=>$conn->insert_id];
    }
    function nm_gpu_target_update($conn, int $id, array $f): array {
        nm_gpu_ensure($conn);
        $t = nm_gpu_target($conn, $id); if (!$t) return ['ok'=>false,'error'=>'not found'];
        $name = substr(trim((string)($f['name'] ?? $t['name'])), 0, 120) ?: $t['name'];
        $node = array_key_exists('node_id',$f) ? ((int)$f['node_id'] ?: null) : $t['node_id'];
        $host = array_key_exists('host_ip',$f) ? (substr(trim((string)$f['host_ip']),0,64) ?: null) : $t['host_ip'];
        $oll  = array_key_exists('ollama_url',$f) ? (substr(trim((string)$f['ollama_url']),0,200) ?: null) : $t['ollama_url'];
        $tw   = array_key_exists('temp_warn',$f) ? max(0,min(150,(int)$f['temp_warn'])) : (int)$t['temp_warn'];
        $vw   = array_key_exists('vram_warn',$f) ? max(1,min(100,(int)$f['vram_warn'])) : (int)$t['vram_warn'];
        $en   = array_key_exists('enabled',$f) ? (int)!empty($f['enabled']) : (int)$t['enabled'];
        $st = $conn->prepare("UPDATE nm_gpu_targets SET name=?,node_id=?,host_ip=?,ollama_url=?,temp_warn=?,vram_warn=?,enabled=? WHERE id=?");
        $st->bind_param('sissiiii', $name,$node,$host,$oll,$tw,$vw,$en,$id);
        $st->execute();
        return ['ok'=>true];
    }
    function nm_gpu_target_delete($conn, int $id): array {
        nm_gpu_ensure($conn);
        $gids = [];
        $r = $conn->query("SELECT id FROM nm_gpu WHERE target_id=".(int)$id);
        while ($r && ($x=$r->fetch_row())) $gids[] = (int)$x[0];
        if ($gids) { $in = implode(',',$gids); $conn->query("DELETE FROM nm_gpu_stats WHERE gpu_id IN ($in)"); $conn->query("DELETE FROM nm_gpu_proc WHERE gpu_id IN ($in)"); }
        $conn->query("DELETE FROM nm_gpu_models WHERE target_id=".(int)$id);
        $conn->query("DELETE FROM nm_gpu WHERE target_id=".(int)$id);
        $conn->query("DELETE FROM nm_gpu_targets WHERE id=".(int)$id);
        return ['ok'=>true];
    }

    function nm_gpu_resolve_ssh($conn, array $t): ?array {
        if (!empty($t['node_id'])) return nm_ssh_resolve($conn, (int)$t['node_id']);
        if (!empty($t['host_ip'])) return nm_cm_resolve_ssh($conn, ['host_ip'=>$t['host_ip'],'ssh_cred_id'=>0]);
        return null;
    }

    // ── Vendor CLI command strings (single-line → SSH exec mode on cmd.exe & bash) ─
    function nm_gpu_cmd_nvidia(): string {
        return 'nvidia-smi --query-gpu=index,uuid,name,utilization.gpu,utilization.memory,memory.total,memory.used,'
             . 'temperature.gpu,power.draw,enforced.power.limit,fan.speed,clocks.sm,driver_version '
             . '--format=csv,noheader,nounits';
    }
    function nm_gpu_cmd_nvidia_apps(): string {
        return 'nvidia-smi --query-compute-apps=gpu_uuid,pid,used_memory,process_name --format=csv,noheader,nounits';
    }
    function nm_gpu_cmd_amd(): string {
        return 'rocm-smi --showuse --showmemuse --showtemp --showpower --showmeminfo vram --json';
    }
    function nm_gpu_cmd_winperf(): string {
        // vendor-agnostic Windows fallback (same data the Task Manager shows)
        return 'powershell -NoProfile -Command "$u=((Get-Counter \'\\GPU Engine(*)\\Utilization Percentage\' -EA SilentlyContinue).CounterSamples|Measure-Object CookedValue -Sum).Sum; $m=((Get-Counter \'\\GPU Process Memory(*)\\Dedicated Usage\' -EA SilentlyContinue).CounterSamples|Measure-Object CookedValue -Sum).Sum; if($u -eq $null){$u=0}; if($m -eq $null){$m=0}; Write-Output (\'GEN;\'+[math]::Round([math]::Min($u,100),1)+\';\'+[math]::Round($m/1MB,0))"';
    }

    // ── Parsers (pure) ────────────────────────────────────────────────────────
    function nm_gpu_parse_nvidia(string $csv): array {
        $gpus = [];
        foreach (preg_split('/\r?\n/', $csv) as $line) {
            $line = trim($line);
            if ($line === '' || stripos($line, 'NEURU') !== false) continue;
            if (strpos($line, ',') === false) continue;
            $c = array_map('trim', explode(',', $line));
            if (count($c) < 13 || !is_numeric($c[0])) continue;
            $gpus[] = [
                'gpu_index'=>(int)$c[0], 'uuid'=>$c[1], 'name'=>$c[2], 'vendor'=>'nvidia',
                'util_pct'=>$c[3], 'mem_util_pct'=>$c[4], 'mem_total_mb'=>$c[5], 'mem_used_mb'=>$c[6],
                'temp_c'=>$c[7], 'power_w'=>$c[8], 'power_limit_w'=>$c[9], 'fan_pct'=>$c[10],
                'clock_sm_mhz'=>$c[11], 'driver_version'=>$c[12],
            ];
        }
        return $gpus;
    }
    function nm_gpu_parse_nvidia_apps(string $csv): array {
        $byUuid = [];
        foreach (preg_split('/\r?\n/', $csv) as $line) {
            $line = trim($line);
            if ($line === '' || strpos($line, ',') === false) continue;
            $c = explode(',', $line, 4);
            if (count($c) < 4) continue;
            $uuid = trim($c[0]);
            $byUuid[$uuid][] = ['pid'=>(int)trim($c[1]), 'used_mb'=>(int)trim($c[2]), 'name'=>trim($c[3])];
        }
        return $byUuid;   // gpu_uuid → [ {pid,used_mb,name}, … ]
    }
    function nm_gpu_parse_amd(string $json): array {
        $d = json_decode($json, true);
        if (!is_array($d)) return [];
        $gpus = []; $idx = 0;
        foreach ($d as $card => $fields) {
            if (stripos((string)$card, 'card') !== 0 || !is_array($fields)) continue;
            $get = function(array $needles) use ($fields) {
                foreach ($fields as $k=>$v) { foreach ($needles as $n) if (stripos($k,$n)!==false) return $v; }
                return null;
            };
            $vramTot = $get(['VRAM Total Memory']); $vramUse = $get(['VRAM Total Used']);
            $gpus[] = [
                'gpu_index'=>(int)preg_replace('/\D/','',(string)$card) ?: $idx,
                'uuid'=>$get(['Unique ID','Serial']) ?: ('amd-'.$idx), 'name'=>$get(['Card series','Card model','Device Name']) ?: 'AMD GPU',
                'vendor'=>'amd',
                'util_pct'=>$get(['GPU use (%)','GPU Utilization']),
                'mem_util_pct'=>$get(['GPU memory use (%)','GPU Memory Allocated']),
                'mem_total_mb'=>$vramTot!==null ? round(((float)$vramTot)/1048576) : null,
                'mem_used_mb'=>$vramUse!==null ? round(((float)$vramUse)/1048576) : null,
                'temp_c'=>$get(['Temperature (Sensor edge)','Temperature (Sensor junction)','Temperature']),
                'power_w'=>$get(['Average Graphics Package Power','Current Socket Graphics Package Power','Power']),
                'power_limit_w'=>$get(['Max Graphics Package Power']),
                'fan_pct'=>$get(['Fan speed (%)']),
                'clock_sm_mhz'=>null, 'driver_version'=>$get(['Driver version']),
            ];
            $idx++;
        }
        return $gpus;
    }
    function nm_gpu_parse_winperf(string $out): array {
        foreach (preg_split('/\r?\n/', $out) as $line) {
            $line = trim($line);
            if (stripos($line, 'GEN;') !== 0) continue;
            $c = explode(';', $line);
            if (count($c) < 3) continue;
            return [[
                'gpu_index'=>0, 'uuid'=>'win-gpu0', 'name'=>'GPU (Windows counters)', 'vendor'=>'generic',
                'util_pct'=>$c[1], 'mem_util_pct'=>null, 'mem_total_mb'=>null, 'mem_used_mb'=>$c[2],
                'temp_c'=>null, 'power_w'=>null, 'power_limit_w'=>null, 'fan_pct'=>null,
                'clock_sm_mhz'=>null, 'driver_version'=>null,
            ]];
        }
        return [];
    }
    // /api/ps → models RUNNING (loaded in VRAM) right now. Keyed by name.
    function nm_gpu_parse_ollama(string $json): array {
        $d = json_decode($json, true);
        if (!is_array($d) || empty($d['models'])) return [];
        $out = [];
        foreach ($d['models'] as $m) {
            $exp = null;
            if (!empty($m['expires_at'])) { $ts = strtotime($m['expires_at']); if ($ts) $exp = gmdate('Y-m-d H:i:s', $ts); }
            $out[substr((string)($m['name'] ?? $m['model'] ?? '?'),0,160)] = [
                'vram_mb'=>isset($m['size_vram']) ? round(((float)$m['size_vram'])/1048576) : null,
                'expires_at'=>$exp,
            ];
        }
        return $out;
    }
    // /api/tags → the INSTALLED model library (always populated once models are pulled,
    // even when nothing is loaded). This is what makes the AI panel show something at rest.
    function nm_gpu_parse_ollama_tags(string $json): array {
        $d = json_decode($json, true);
        if (!is_array($d) || empty($d['models'])) return [];
        $out = [];
        foreach ($d['models'] as $m) {
            $det = is_array($m['details'] ?? null) ? $m['details'] : [];
            $mod = null;
            if (!empty($m['modified_at'])) { $ts = strtotime($m['modified_at']); if ($ts) $mod = gmdate('Y-m-d H:i:s', $ts); }
            $out[] = [
                'name'=>substr((string)($m['name'] ?? $m['model'] ?? '?'),0,160),
                'size_mb'=>isset($m['size']) ? round(((float)$m['size'])/1048576) : null,
                'family'=>substr((string)($det['family'] ?? ''),0,80) ?: null,
                'params'=>substr((string)($det['parameter_size'] ?? ''),0,40) ?: null,
                'quant'=>substr((string)($det['quantization_level'] ?? ''),0,40) ?: null,
                'modified_at'=>$mod,
            ];
        }
        return $out;
    }
    function nm_gpu_parse_ollama_version(string $json): string {
        $d = json_decode($json, true);
        return is_array($d) ? substr((string)($d['version'] ?? ''),0,40) : '';
    }

    // ── Poll one target (web context — SSH creds decrypt as www-data) ─────────
    function nm_gpu_poll_target($conn, array $t): array {
        nm_gpu_ensure($conn);
        $tid = (int)$t['id'];
        $ssh = nm_gpu_resolve_ssh($conn, $t);
        if (!$ssh || empty($ssh['username'])) { _nm_gpu_target_err($conn,$tid,'No SSH credential resolved (set the node SSH cred or a default)'); return ['ok'=>false,'error'=>'no ssh']; }

        // vendor cascade: known vendor → one probe; unknown → nvidia, amd, generic
        $order = !empty($t['vendor']) ? [$t['vendor']] : ['nvidia','amd','generic'];
        $vendor = null; $gpus = []; $appsByUuid = [];
        foreach ($order as $v) {
            $cmd = $v==='nvidia' ? nm_gpu_cmd_nvidia() : ($v==='amd' ? nm_gpu_cmd_amd() : nm_gpu_cmd_winperf());
            $res = nm_cm_ssh_fetch($ssh, $cmd, 25);
            if (!$res['ok']) continue;
            $parsed = $v==='nvidia' ? nm_gpu_parse_nvidia($res['config'])
                    : ($v==='amd' ? nm_gpu_parse_amd($res['config']) : nm_gpu_parse_winperf($res['config']));
            if ($parsed) { $vendor=$v; $gpus=$parsed; break; }
        }
        if (!$vendor || !$gpus) { _nm_gpu_target_err($conn,$tid,'No GPU detected (nvidia-smi / rocm-smi / GPU counters all returned nothing)'); return ['ok'=>false,'error'=>'no gpu']; }

        if ($vendor === 'nvidia') {
            $ra = nm_cm_ssh_fetch($ssh, nm_gpu_cmd_nvidia_apps(), 20);
            if ($ra['ok']) $appsByUuid = nm_gpu_parse_nvidia_apps($ra['config']);
        }

        // persist GPUs + a stats sample each
        $now = gmdate('Y-m-d H:i:s');
        foreach ($gpus as $g) {
            $idx=(int)$g['gpu_index']; $uuid=$conn->real_escape_string((string)$g['uuid']);
            $name=$conn->real_escape_string((string)$g['name']); $ven=$conn->real_escape_string($vendor);
            $drv=$conn->real_escape_string((string)($g['driver_version'] ?? '')); $mt=_nm_gpu_num($g['mem_total_mb']);
            $conn->query("INSERT INTO nm_gpu (target_id,gpu_index,uuid,name,vendor,memory_total_mb,driver_version,last_seen)
                VALUES ($tid,$idx,'$uuid','$name','$ven',$mt,'$drv','$now')
                ON DUPLICATE KEY UPDATE uuid=VALUES(uuid),name=VALUES(name),vendor=VALUES(vendor),
                memory_total_mb=VALUES(memory_total_mb),driver_version=VALUES(driver_version),last_seen=VALUES(last_seen)");
            $gr = $conn->query("SELECT id FROM nm_gpu WHERE target_id=$tid AND gpu_index=$idx LIMIT 1");
            $gid = $gr ? (int)($gr->fetch_row()[0] ?? 0) : 0;
            if (!$gid) continue;
            $conn->query("INSERT INTO nm_gpu_stats (gpu_id,util_pct,mem_util_pct,mem_used_mb,mem_total_mb,temp_c,power_w,power_limit_w,fan_pct,clock_sm_mhz,sampled_at)
                VALUES ($gid,"._nm_gpu_num($g['util_pct']).","._nm_gpu_num($g['mem_util_pct']).","._nm_gpu_num($g['mem_used_mb']).","._nm_gpu_num($g['mem_total_mb']).","
                ._nm_gpu_num($g['temp_c']).","._nm_gpu_num($g['power_w']).","._nm_gpu_num($g['power_limit_w']).","._nm_gpu_num($g['fan_pct']).","._nm_gpu_num($g['clock_sm_mhz']).",'$now')");
            // refresh the per-process VRAM table for this GPU
            $conn->query("DELETE FROM nm_gpu_proc WHERE gpu_id=$gid");
            $procs = $appsByUuid[(string)$g['uuid']] ?? [];
            foreach ($procs as $p) {
                $pn=$conn->real_escape_string(substr((string)$p['name'],0,200));
                $conn->query("INSERT INTO nm_gpu_proc (gpu_id,pid,used_mb,name,sampled_at) VALUES ($gid,".(int)$p['pid'].",".(int)$p['used_mb'].",'$pn','$now')");
            }
        }

        // ── AI-aware: full Ollama/LLM monitor — installed library (/api/tags) + running
        //    models (/api/ps) + version. /api/ps alone is EMPTY when idle, so the library
        //    is what makes the AI panel always show something. Reached over SSH so it works
        //    whether Ollama binds 127.0.0.1 or a LAN IP.
        $oll = trim((string)($t['ollama_url'] ?? ''));
        $ollVer = ''; $ollOk = 0;
        if ($oll !== '') {
            $url = rtrim($oll,'/');
            if (!preg_match('#^https?://#i',$url)) $url='http://'.$url;
            $C = fn($path) => nm_cm_ssh_fetch($ssh, 'curl -s --max-time 5 '.$url.$path, 15);
            $rv = $C('/api/version'); if ($rv['ok']) { $ollVer = nm_gpu_parse_ollama_version($rv['config']); }
            $rt = $C('/api/tags');                                  // installed library
            $rp = $C('/api/ps');                                    // running now
            $installed = $rt['ok'] ? nm_gpu_parse_ollama_tags($rt['config']) : [];
            $running   = $rp['ok'] ? nm_gpu_parse_ollama($rp['config']) : [];   // name => {vram_mb,expires_at}
            $ollOk = ($rv['ok'] || $rt['ok'] || $rp['ok']) ? 1 : 0;
            $conn->query("DELETE FROM nm_gpu_models WHERE target_id=$tid");
            // any running model not present in the library (rare) still gets a row
            $seen = [];
            foreach ($installed as $m) {
                $nm=(string)$m['name']; $seen[$nm]=1; $run=isset($running[$nm]);
                $vram = $run ? $running[$nm]['vram_mb'] : null;
                $exp  = $run && $running[$nm]['expires_at'] ? "'".$conn->real_escape_string($running[$nm]['expires_at'])."'" : 'NULL';
                $mod  = $m['modified_at'] ? "'".$conn->real_escape_string($m['modified_at'])."'" : 'NULL';
                $conn->query("INSERT INTO nm_gpu_models (target_id,name,size_mb,vram_mb,running,family,params,quant,expires_at,modified_at,sampled_at)
                    VALUES ($tid,'".$conn->real_escape_string($nm)."',"._nm_gpu_num($m['size_mb']).","._nm_gpu_num($vram).",".($run?1:0).",".
                    "'".$conn->real_escape_string((string)$m['family'])."','".$conn->real_escape_string((string)$m['params'])."','".$conn->real_escape_string((string)$m['quant'])."',$exp,$mod,'$now')");
            }
            foreach ($running as $nm=>$rm) {
                if (isset($seen[$nm])) continue;
                $exp = $rm['expires_at'] ? "'".$conn->real_escape_string($rm['expires_at'])."'" : 'NULL';
                $conn->query("INSERT INTO nm_gpu_models (target_id,name,vram_mb,running,expires_at,sampled_at)
                    VALUES ($tid,'".$conn->real_escape_string((string)$nm)."',"._nm_gpu_num($rm['vram_mb']).",1,$exp,'$now')");
            }
        }

        $venEsc = $conn->real_escape_string($vendor); $verEsc = $conn->real_escape_string($ollVer);
        $conn->query("UPDATE nm_gpu_targets SET vendor='$venEsc', ollama_version=".($oll!==''?"'$verEsc'":"ollama_version").", ollama_ok=".($oll!==''?$ollOk:"ollama_ok").", status='ok', last_poll='$now', last_error=NULL WHERE id=$tid");
        return ['ok'=>true,'vendor'=>$vendor,'gpus'=>count($gpus),'ollama'=>$oll!==''?($ollOk?'ok':'unreachable'):'off'];
    }
    function _nm_gpu_target_err($conn, int $tid, string $msg): void {
        $e = $conn->real_escape_string(substr($msg,0,290));
        $conn->query("UPDATE nm_gpu_targets SET status='error', last_poll='".gmdate('Y-m-d H:i:s')."', last_error='$e' WHERE id=$tid");
    }
    function nm_gpu_poll_all($conn): array {
        nm_gpu_ensure($conn);
        $res = [];
        $r = $conn->query("SELECT * FROM nm_gpu_targets WHERE enabled=1");
        $ts = []; while ($r && ($x=$r->fetch_assoc())) $ts[]=$x;
        // Skip targets whose linked node is in MAINTENANCE — no SSH/GPU data gathered while paused.
        if (!function_exists('nm_maint_active_ids') && is_file(__DIR__.'/nm_maintenance.php')) require_once __DIR__.'/nm_maintenance.php';
        if (function_exists('nm_maint_active_ids')) { $mnt=nm_maint_active_ids($conn);
            if ($mnt) $ts=array_values(array_filter($ts, fn($t)=>empty($t['node_id'])||!isset($mnt[(int)$t['node_id']]))); }
        foreach ($ts as $t) $res[$t['id']] = nm_gpu_poll_target($conn, $t);
        return $res;
    }

    // ── Read helpers for the UI ───────────────────────────────────────────────
    function nm_gpu_list($conn, int $target_id): array {
        nm_gpu_ensure($conn);
        $out = [];
        $r = $conn->query("SELECT * FROM nm_gpu WHERE target_id=".(int)$target_id." ORDER BY gpu_index");
        while ($r && ($g = $r->fetch_assoc())) {
            $gid = (int)$g['id'];
            $sr = $conn->query("SELECT *, TIMESTAMPDIFF(SECOND,sampled_at,UTC_TIMESTAMP()) age FROM nm_gpu_stats WHERE gpu_id=$gid ORDER BY id DESC LIMIT 1");
            $g['latest'] = $sr ? ($sr->fetch_assoc() ?: null) : null;
            $pr = $conn->query("SELECT pid,used_mb,name FROM nm_gpu_proc WHERE gpu_id=$gid ORDER BY used_mb DESC");
            $g['procs'] = []; while ($pr && ($p=$pr->fetch_assoc())) $g['procs'][]=$p;
            $out[] = $g;
        }
        return $out;
    }
    function nm_gpu_series($conn, int $gpu_id, int $mins = 60): array {
        $mins = max(5, min(1440, $mins));
        $out = [];
        $r = $conn->query("SELECT util_pct,mem_util_pct,mem_used_mb,temp_c,power_w,sampled_at
            FROM nm_gpu_stats WHERE gpu_id=".(int)$gpu_id." AND sampled_at >= (UTC_TIMESTAMP() - INTERVAL $mins MINUTE) ORDER BY id");
        while ($r && ($x=$r->fetch_assoc())) $out[] = $x;
        return $out;
    }
    function nm_gpu_models($conn, int $target_id): array {
        $out = [];
        $r = $conn->query("SELECT name,size_mb,vram_mb,running,family,params,quant,expires_at,modified_at
            FROM nm_gpu_models WHERE target_id=".(int)$target_id." ORDER BY running DESC, vram_mb DESC, size_mb DESC");
        while ($r && ($x=$r->fetch_assoc())) $out[] = $x;
        return $out;
    }
    // Ollama/LLM status for a target: reachability, version, running vs installed counts + total library size.
    function nm_gpu_ai_status($conn, int $target_id): array {
        $t = nm_gpu_target($conn, $target_id);
        $url = $t ? trim((string)($t['ollama_url'] ?? '')) : '';
        if ($url === '') return ['enabled'=>false];
        $run=0; $inst=0; $sz=0.0;
        if ($r=$conn->query("SELECT COUNT(*) c, SUM(running) r, SUM(size_mb) s FROM nm_gpu_models WHERE target_id=".(int)$target_id)) {
            if ($x=$r->fetch_assoc()) { $inst=(int)$x['c']; $run=(int)$x['r']; $sz=(float)$x['s']; }
        }
        return ['enabled'=>true,'url'=>$url,'ok'=>(int)($t['ollama_ok'] ?? 0)===1,
            'version'=>(string)($t['ollama_version'] ?? ''),'installed'=>$inst,'running'=>$run,'library_mb'=>round($sz)];
    }
    function nm_gpu_prune($conn, int $days = 14): void {
        nm_gpu_ensure($conn);
        $days = max(1, min(365, $days));
        $conn->query("DELETE FROM nm_gpu_stats WHERE sampled_at < (UTC_TIMESTAMP() - INTERVAL $days DAY)");
    }
}
