<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Router Configuration Manager engine (SolarWinds NCM-style).
//
//   Flow:  cron_config.php (daily)  ─▶  nm_cm_backup_all()
//            └▶ per device: nm_cm_backup_device()
//                 └▶ nm_n8n_call('config-backup', {host, command, ssh{}})   [n8n SSHes the
//                      router, runs the brand command, returns the running config]
//                 └▶ nm_cm_store(): normalize → hash → diff vs last version →
//                      store new snapshot + change event (if changed) → alert.
//
//   Storage model (versioned, change-only):
//     nm_config_vendors    brand → command + volatile-line filters (editable)
//     nm_config_devices    what to back up (host, vendor, ssh cred, schedule state)
//     nm_config_snapshots  one row PER DISTINCT VERSION (dedup by sha256)
//     nm_config_changes    one row per detected drift (unified diff + ack state)
//
//   Everything funnels through the shared n8n token (nm_n8n.php) and the encrypted
//   SSH credential store (nm_secrets.php). Page gate = permission key 'config_mgr'.
// ─────────────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/nm_secrets.php';
require_once __DIR__ . '/nm_n8n.php';
require_once __DIR__ . '/nm_audit.php';

// ── Schema + vendor seed ─────────────────────────────────────────────────────
if (!function_exists('nm_cm_ensure')) {
    function nm_cm_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        static $done = false; if ($done) return; $done = true;

        $conn->query("CREATE TABLE IF NOT EXISTS nm_config_vendors (
            vendor_key  VARCHAR(40) PRIMARY KEY,
            label       VARCHAR(80) NOT NULL,
            command     VARCHAR(255) NOT NULL,
            ignore_regex TEXT,
            enabled     TINYINT(1) NOT NULL DEFAULT 1
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $conn->query("CREATE TABLE IF NOT EXISTS nm_config_devices (
            id INT AUTO_INCREMENT PRIMARY KEY,
            node_id INT DEFAULT NULL,
            name VARCHAR(120) NOT NULL,
            host_ip VARCHAR(64) NOT NULL,
            vendor_key VARCHAR(40) NOT NULL,
            command_override VARCHAR(255) DEFAULT NULL,
            ssh_cred_id INT DEFAULT NULL,
            enabled TINYINT(1) NOT NULL DEFAULT 1,
            last_backup_at DATETIME DEFAULT NULL,
            last_status VARCHAR(16) NOT NULL DEFAULT 'never',
            last_error VARCHAR(400) DEFAULT NULL,
            last_hash CHAR(64) DEFAULT NULL,
            last_snapshot_id BIGINT DEFAULT NULL,
            versions INT NOT NULL DEFAULT 0,
            created_by INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            KEY idx_enabled (enabled)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $conn->query("CREATE TABLE IF NOT EXISTS nm_config_snapshots (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            device_id INT NOT NULL,
            captured_at DATETIME NOT NULL,
            sha256 CHAR(64) NOT NULL,
            size_bytes INT NOT NULL DEFAULT 0,
            line_count INT NOT NULL DEFAULT 0,
            source VARCHAR(12) NOT NULL DEFAULT 'cron',
            config_text MEDIUMTEXT,
            KEY idx_dev_time (device_id, captured_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $conn->query("CREATE TABLE IF NOT EXISTS nm_config_changes (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            device_id INT NOT NULL,
            snapshot_id BIGINT NOT NULL,
            prev_snapshot_id BIGINT DEFAULT NULL,
            detected_at DATETIME NOT NULL,
            added INT NOT NULL DEFAULT 0,
            removed INT NOT NULL DEFAULT 0,
            diff_text MEDIUMTEXT,
            status VARCHAR(14) NOT NULL DEFAULT 'open',
            acked_by VARCHAR(60) DEFAULT NULL,
            acked_at DATETIME DEFAULT NULL,
            KEY idx_dev (device_id), KEY idx_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Seed the common brands once.
        $r = $conn->query("SELECT COUNT(*) c FROM nm_config_vendors");
        if ($r && (int)$r->fetch_assoc()['c'] === 0) {
            $seed = [
                ['mikrotik','MikroTik RouterOS','export',                          "^# .* by RouterOS\n^# model = "],
                ['cisco_ios','Cisco IOS / IOS-XE',"terminal length 0\nshow running-config", "^Building configuration\n^Current configuration : \\d+ bytes\n^! Last configuration change\n^! NVRAM config last updated\n^ntp clock-period"],
                ['cisco_asa','Cisco ASA',"terminal pager 0\nshow running-config",  "^: Saved\n^: Written by \n^: Hardware:\n^Cryptochecksum:"],
                ['cisco_nxos','Cisco NX-OS',"terminal length 0\nshow running-config", "^!Time:\n^!Running configuration last done at:\n^!Startup config saved at:"],
                ['juniper','Juniper JunOS','show configuration | display set | no-more', "^## Last commit:"],
                ['arista','Arista EOS',"terminal length 0\nshow running-config",    "^! device:\n^! boot system"],
                ['fortinet','Fortinet FortiOS','show full-configuration',          "^#conf_file_ver=\n^#buildno=\n^#global_vdom="],
                ['paloalto','Palo Alto PAN-OS','set cli pager off\nshow config running', ""],
                ['edgeos','Ubiquiti EdgeOS','show configuration commands',         ""],
                ['hp_aruba','HP / Aruba',"no page\nshow running-config",           "^Startup configuration\n^; hpStackId"],
                ['linux','Linux (generic)','cat /etc/network/interfaces 2>/dev/null; ip a', ""],
                ['generic','Generic / custom','',                                  ""],
            ];
            $st = $conn->prepare("INSERT INTO nm_config_vendors (vendor_key,label,command,ignore_regex,enabled) VALUES (?,?,?,?,1)");
            foreach ($seed as $s) { $st->bind_param('ssss',$s[0],$s[1],$s[2],$s[3]); $st->execute(); }
            $st->close();
        }
    }
}

// ── Vendor helpers ───────────────────────────────────────────────────────────
if (!function_exists('nm_cm_vendors')) {
    function nm_cm_vendors($conn): array {
        nm_cm_ensure($conn);
        $out = [];
        $r = $conn->query("SELECT vendor_key,label,command,ignore_regex,enabled FROM nm_config_vendors ORDER BY label");
        while ($r && $x = $r->fetch_assoc()) $out[] = $x;
        return $out;
    }
    function nm_cm_vendor($conn, string $key): ?array {
        nm_cm_ensure($conn);
        $st = $conn->prepare("SELECT vendor_key,label,command,ignore_regex,enabled FROM nm_config_vendors WHERE vendor_key=? LIMIT 1");
        $st->bind_param('s',$key); $st->execute();
        $row = $st->get_result()->fetch_assoc(); $st->close();
        return $row ?: null;
    }
    // Map an nm_nodes os_icon to a sensible default vendor_key.
    function nm_cm_guess_vendor(?string $osIcon): string {
        switch (strtolower((string)$osIcon)) {
            case 'routeros': case 'mikrotik': return 'mikrotik';
            case 'cisco':    return 'cisco_ios';
            case 'arista':   return 'arista';
            case 'juniper':  return 'juniper';
            case 'fortinet': case 'fortigate': return 'fortinet';
            case 'linux':    return 'linux';
            case 'windows':  case 'win': case 'microsoft': case 'windows-server': return 'windows';
            default:         return 'generic';
        }
    }
}

// ── Normalization + diff ─────────────────────────────────────────────────────
if (!function_exists('nm_cm_normalize')) {
    // Strip volatile lines (per-vendor regexes), normalize EOL + trailing space.
    // Returns the cleaned text used for hashing/diffing (so timestamps etc. don't
    // register as spurious config drift).
    function nm_cm_normalize(string $text, ?string $ignoreRegex): string {
        $text = str_replace(["\r\n", "\r"], "\n", $text);
        $patterns = [];
        foreach (preg_split('/\n+/', (string)$ignoreRegex) as $p) {
            $p = trim($p);
            if ($p !== '') $patterns[] = '/' . str_replace('/', '\/', $p) . '/';
        }
        $lines = explode("\n", $text);
        $kept = [];
        foreach ($lines as $ln) {
            $ln = rtrim($ln);
            $skip = false;
            foreach ($patterns as $rx) { if (@preg_match($rx, $ln)) { $skip = true; break; } }
            if (!$skip) $kept[] = $ln;
        }
        // drop leading/trailing blank lines
        while ($kept && $kept[0] === '') array_shift($kept);
        while ($kept && end($kept) === '') array_pop($kept);
        return implode("\n", $kept);
    }

    // Unified diff via the system `diff` (accurate, handles big configs). Returns
    // ['diff'=>unified text, 'added'=>int, 'removed'=>int]. PHP fallback if no diff.
    function nm_cm_diff(string $old, string $new): array {
        $fa = tempnam(sys_get_temp_dir(), 'cm_a_');
        $fb = tempnam(sys_get_temp_dir(), 'cm_b_');
        file_put_contents($fa, $old . "\n");
        file_put_contents($fb, $new . "\n");
        $cmd = 'diff -u ' . escapeshellarg($fa) . ' ' . escapeshellarg($fb) . ' 2>/dev/null';
        $diff = (string)shell_exec($cmd);
        @unlink($fa); @unlink($fb);

        if ($diff === '') {
            // identical, or diff missing → fall back to a crude line compare
            if ($old === $new) return ['diff'=>'', 'added'=>0, 'removed'=>0];
        }
        // strip the two file-header lines (--- /tmp/..  +++ /tmp/..)
        $lines = explode("\n", $diff);
        $clean = []; $added = 0; $removed = 0;
        foreach ($lines as $l) {
            if (strpos($l, '--- ') === 0 || strpos($l, '+++ ') === 0) continue;
            if ($l !== '' && $l[0] === '+') $added++;
            elseif ($l !== '' && $l[0] === '-') $removed++;
            $clean[] = $l;
        }
        return ['diff'=>trim(implode("\n", $clean)), 'added'=>$added, 'removed'=>$removed];
    }
}

// ── SSH resolution for a config device ───────────────────────────────────────
if (!function_exists('nm_cm_resolve_ssh')) {
    // Resolve the SSH credential bound to a device (by ssh_cred_id, else default).
    // Returns ['host','port','username','auth_type', 'password'|'private_key'] or null.
    function nm_cm_resolve_ssh($conn, array $dev): ?array {
        $cid = (int)($dev['ssh_cred_id'] ?? 0);
        if ($cid) $cr = $conn->query("SELECT * FROM nm_ssh_credentials WHERE id={$cid} LIMIT 1");
        else      $cr = $conn->query("SELECT * FROM nm_ssh_credentials WHERE is_default=1 ORDER BY id LIMIT 1");
        $cred = $cr ? $cr->fetch_assoc() : null;
        if (!$cred) return null;
        $secret = nm_secret_decrypt($cred['secret_enc']);
        $out = [
            'host'      => $dev['host_ip'],
            'port'      => (int)($cred['port'] ?: 22) ?: 22,
            'username'  => $cred['username'],
            'auth_type' => $cred['auth_type'],
            'cred_name' => $cred['name'],
        ];
        if ($cred['auth_type'] === 'key') $out['private_key'] = $secret; else $out['password'] = $secret;
        return $out;
    }
}

// ── Store a fetched config: normalize, dedup, diff, alert ─────────────────────
if (!function_exists('nm_cm_store')) {
    function nm_cm_store($conn, int $deviceId, string $rawConfig, string $source = 'cron'): array {
        nm_cm_ensure($conn);
        $dr = $conn->query("SELECT * FROM nm_config_devices WHERE id={$deviceId} LIMIT 1");
        $dev = $dr ? $dr->fetch_assoc() : null;
        if (!$dev) return ['ok'=>false, 'error'=>'Device not found'];

        $vendor = nm_cm_vendor($conn, $dev['vendor_key']);
        $norm   = nm_cm_normalize($rawConfig, $vendor['ignore_regex'] ?? '');
        if (trim($norm) === '') return ['ok'=>false, 'error'=>'Empty config returned'];

        $hash  = hash('sha256', $norm);
        $lines = substr_count($norm, "\n") + 1;
        $size  = strlen($norm);
        $now   = date('Y-m-d H:i:s');

        // unchanged → just stamp last_backup_at, no new version
        if (!empty($dev['last_hash']) && $dev['last_hash'] === $hash) {
            $u = $conn->prepare("UPDATE nm_config_devices SET last_backup_at=?, last_status='ok', last_error=NULL WHERE id=?");
            $u->bind_param('si', $now, $deviceId); $u->execute(); $u->close();
            return ['ok'=>true, 'changed'=>false, 'status'=>'unchanged'];
        }

        // changed (or first capture) → store a new snapshot
        $ins = $conn->prepare("INSERT INTO nm_config_snapshots (device_id,captured_at,sha256,size_bytes,line_count,source,config_text)
                               VALUES (?,?,?,?,?,?,?)");
        $ins->bind_param('issiiss', $deviceId, $now, $hash, $size, $lines, $source, $norm);
        $ins->execute(); $snapId = $ins->insert_id; $ins->close();

        $isFirst = empty($dev['last_snapshot_id']);
        $changeId = null; $added = 0; $removed = 0;
        if (!$isFirst) {
            $pr = $conn->query("SELECT config_text FROM nm_config_snapshots WHERE id=".(int)$dev['last_snapshot_id']." LIMIT 1");
            $prevText = $pr && ($x=$pr->fetch_assoc()) ? (string)$x['config_text'] : '';
            $d = nm_cm_diff($prevText, $norm);
            $added = $d['added']; $removed = $d['removed'];
            $c = $conn->prepare("INSERT INTO nm_config_changes (device_id,snapshot_id,prev_snapshot_id,detected_at,added,removed,diff_text,status)
                                 VALUES (?,?,?,?,?,?,?,'open')");
            $prevId = (int)$dev['last_snapshot_id'];
            $c->bind_param('iiisiss', $deviceId, $snapId, $prevId, $now, $added, $removed, $d['diff']);
            $c->execute(); $changeId = $c->insert_id; $c->close();

            nm_audit($conn, 'config.drift', ['target_type'=>'config_device','target_id'=>$deviceId,
                'status'=>'failure', 'details'=>['device'=>$dev['name'],'host'=>$dev['host_ip'],'added'=>$added,'removed'=>$removed]]);
        }

        $u = $conn->prepare("UPDATE nm_config_devices
                             SET last_backup_at=?, last_status='ok', last_error=NULL, last_hash=?, last_snapshot_id=?, versions=versions+1
                             WHERE id=?");
        $u->bind_param('ssii', $now, $hash, $snapId, $deviceId); $u->execute(); $u->close();

        return ['ok'=>true, 'changed'=>!$isFirst, 'first'=>$isFirst,
                'snapshot_id'=>$snapId, 'change_id'=>$changeId, 'added'=>$added, 'removed'=>$removed,
                'status'=>$isFirst ? 'baseline' : 'changed'];
    }

    // Record a failed backup attempt on the device row.
    function nm_cm_fail($conn, int $deviceId, string $err): void {
        $now = date('Y-m-d H:i:s'); $err = substr($err, 0, 390);
        $u = $conn->prepare("UPDATE nm_config_devices SET last_backup_at=?, last_status='failed', last_error=? WHERE id=?");
        $u->bind_param('ssi', $now, $err, $deviceId); $u->execute(); $u->close();
        nm_audit($conn, 'config.backup', ['status'=>'error','target_type'=>'config_device','target_id'=>$deviceId,
            'details'=>['error'=>$err]]);
    }
}

// ── SSH fetch primitive ──────────────────────────────────────────────────────
// Runs scripts/nm_ssh_fetch.py (paramiko) with the resolved credentials in the
// ENVIRONMENT (never argv → no leak in `ps`). This replaces the n8n SSH step,
// which kept failing because n8n drove the device as a shell. PHP still resolves
// the (decrypted) credential — only the SSH execution moved to Python.
if (!function_exists('nm_cm_ssh_fetch')) {
    function nm_cm_ssh_fetch(array $ssh, string $command, int $timeout = 25): array {
        $py = '/opt/netmon-venv/bin/python3';
        if (!is_file($py)) $py = trim((string)@shell_exec('command -v python3')) ?: 'python3';
        $script = __DIR__ . '/scripts/nm_ssh_fetch.py';
        if (!is_file($script)) return ['ok'=>false, 'error'=>'ssh fetch helper missing'];

        $env = [
            'NM_SSH_HOST'    => (string)($ssh['host'] ?? ''),
            'NM_SSH_PORT'    => (string)((int)($ssh['port'] ?? 22) ?: 22),
            'NM_SSH_USER'    => (string)($ssh['username'] ?? ''),
            'NM_SSH_PASS'    => (string)($ssh['password'] ?? ''),
            'NM_SSH_KEY'     => (string)($ssh['private_key'] ?? ''),
            'NM_SSH_CMD'     => $command,
            'NM_SSH_TIMEOUT' => (string)$timeout,
            'NM_PYLIBS'      => (is_dir('/home/neuru/netmon-pylibs')?'/home/neuru/netmon-pylibs':'/home/hmiranda/netmon-pylibs'),
            'PATH'           => '/usr/bin:/bin:/usr/local/bin',
            'HOME'           => '/tmp',
            'LANG'           => 'C.UTF-8',
        ];
        $desc = [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']];
        $proc = @proc_open([$py, $script], $desc, $pipes, null, $env);
        if (!is_resource($proc)) return ['ok'=>false, 'error'=>'cannot start ssh helper'];
        fclose($pipes[0]);
        $out = stream_get_contents($pipes[1]); fclose($pipes[1]);
        $err = stream_get_contents($pipes[2]); fclose($pipes[2]);
        $code = proc_close($proc);

        if ($code !== 0)            return ['ok'=>false, 'error'=>trim($err) ?: ('ssh exit '.$code)];
        if (trim((string)$out)==='') return ['ok'=>false, 'error'=>trim($err) ?: 'empty config returned'];
        return ['ok'=>true, 'config'=>$out];
    }
}

// ── Backup one device (Python SSH fetch → NEURU normalize/diff/version/alert) ──
if (!function_exists('nm_cm_backup_device')) {
    function nm_cm_backup_device($conn, array $dev, string $source = 'cron'): array {
        nm_cm_ensure($conn);
        $vendor  = nm_cm_vendor($conn, $dev['vendor_key']);
        $command = trim($dev['command_override'] ?? '') !== '' ? $dev['command_override'] : ($vendor['command'] ?? '');
        if (trim((string)$command) === '') { nm_cm_fail($conn, (int)$dev['id'], 'No command defined for vendor '.$dev['vendor_key']); return ['ok'=>false,'error'=>'No command for vendor']; }

        $ssh = nm_cm_resolve_ssh($conn, $dev);
        if (!$ssh) { nm_cm_fail($conn, (int)$dev['id'], 'No SSH credential resolved'); return ['ok'=>false,'error'=>'No SSH credential']; }
        if (empty($ssh['username']) || (empty($ssh['password']) && empty($ssh['private_key']))) {
            nm_cm_fail($conn, (int)$dev['id'], 'SSH credential incomplete (empty username or secret)');
            return ['ok'=>false,'error'=>'SSH credential incomplete'];
        }

        // Cisco devices need an INTERACTIVE fetch: IOS/ASA/NX-OS may require `enable`
        // (privileged exec), and AireOS controllers do a SECOND User:/Password: login
        // inside the shell. Route Cisco vendors through nm_cisco_ssh.py (auto-detects
        // AireOS from the User: prompt); every other vendor keeps the plain exec fetch.
        $vk = (string)($dev['vendor_key'] ?? '');
        if (strncmp($vk, 'cisco', 5) === 0 && is_file(__DIR__ . '/nm_cisco_orch.php')) {
            require_once __DIR__ . '/nm_cisco_orch.php';
        }
        if (strncmp($vk, 'cisco', 5) === 0 && function_exists('nm_cisco_ssh_run')) {
            $platform = ['cisco_asa'=>'asa', 'cisco_nxos'=>'nxos'][$vk] ?? 'ios';
            $showCmd = '';
            foreach (preg_split('/\r?\n/', (string)$command) as $ln) {
                $ln = trim($ln); if (stripos($ln, 'show ') === 0) $showCmd = $ln;
            }
            $fetch = nm_cisco_ssh_run($ssh, $platform, $showCmd);
        } else {
            $fetch = nm_cm_ssh_fetch($ssh, $command);
        }
        if (!$fetch['ok']) { nm_cm_fail($conn, (int)$dev['id'], $fetch['error']); return ['ok'=>false,'error'=>$fetch['error']]; }

        $res = nm_cm_store($conn, (int)$dev['id'], (string)$fetch['config'], $source);
        if (!$res['ok']) nm_cm_fail($conn, (int)$dev['id'], $res['error'] ?? 'store failed');
        return $res;
    }

    // Back up every enabled device. Returns a run summary.
    function nm_cm_backup_all($conn, string $source = 'cron'): array {
        nm_cm_ensure($conn);
        $sum = ['total'=>0,'ok'=>0,'changed'=>0,'baseline'=>0,'failed'=>0,'devices'=>[]];
        $r = $conn->query("SELECT * FROM nm_config_devices WHERE enabled=1 ORDER BY id");
        while ($r && $dev = $r->fetch_assoc()) {
            $sum['total']++;
            $res = nm_cm_backup_device($conn, $dev, $source);
            if (!empty($res['ok'])) {
                $sum['ok']++;
                if (!empty($res['changed'])) $sum['changed']++;
                if (!empty($res['first']))   $sum['baseline']++;
            } else {
                $sum['failed']++;
            }
            $sum['devices'][] = ['id'=>(int)$dev['id'],'name'=>$dev['name'],
                'result'=>!empty($res['ok']) ? ($res['status'] ?? 'ok') : ('FAIL: '.($res['error'] ?? '?'))];
        }
        return $sum;
    }
}

// ── Dashboard / queries ──────────────────────────────────────────────────────
if (!function_exists('nm_cm_open_changes')) {
    // Open drift events for the dashboard alert injector.
    function nm_cm_open_changes($conn, int $limit = 25): array {
        nm_cm_ensure($conn);
        $limit = max(1, min(100, $limit));
        $out = [];
        $r = $conn->query("SELECT c.id, c.device_id, c.detected_at, c.added, c.removed,
                                  d.name, d.host_ip, d.vendor_key
                           FROM nm_config_changes c JOIN nm_config_devices d ON d.id=c.device_id
                           WHERE c.status='open' ORDER BY c.detected_at DESC LIMIT {$limit}");
        while ($r && $x = $r->fetch_assoc()) $out[] = $x;
        return $out;
    }
    function nm_cm_open_change_count($conn): int {
        nm_cm_ensure($conn);
        $r = $conn->query("SELECT COUNT(*) c FROM nm_config_changes WHERE status='open'");
        return $r ? (int)$r->fetch_assoc()['c'] : 0;
    }
}
