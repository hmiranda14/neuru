<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — AI Copilot engine ("NetAIObot"). A full autonomous Observe→Think→Act
// agent that runs ONLY on operator-SELECTED devices, with three autonomy tiers
// (observe | copilot | autopilot) and a hard destructive-action guard.
//
// Trust model (reuses [[nm_n8n.php]]):
//   OUTBOUND  portal → n8n : nm_n8n_call($conn,'aiopilot', payload)  (the AI brain)
//   INBOUND   n8n → portal : aiopilot_api.php?ep=...  (X-NetMon-Token verified)
//
// The portal NEVER lets the LLM touch the network directly — n8n proposes a TOOL
// call, the portal validates risk + autonomy tier, then the PORTAL executes via
// existing vetted primitives (Portainer / Immunity / SSH). Every step is logged to
// nm_aip_events so the command center shows what the bot does 100% of the time.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_aip_ensure')) {

    require_once __DIR__ . '/nm_n8n.php';

    define('NM_AIP_MODES', ['observe', 'copilot', 'autopilot']);
    // Risk tiers per action tool. low = safe/non-destructive, medium = service-level,
    // high = destructive/architectural (always needs approval unless explicitly allowed).
    define('NM_AIP_RISK', ['low', 'medium', 'high']);

    function nm_aip_ensure($conn): void {
        $conn->query("CREATE TABLE IF NOT EXISTS nm_aip_devices (
            id INT AUTO_INCREMENT PRIMARY KEY,
            node_id INT NOT NULL UNIQUE,
            enabled TINYINT DEFAULT 1,
            autonomy_mode VARCHAR(12) DEFAULT 'observe',   /* observe | copilot | autopilot */
            allow_destructive TINYINT DEFAULT 0,           /* even in autopilot, high-risk needs this */
            added_by INT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $conn->query("CREATE TABLE IF NOT EXISTS nm_aip_sessions (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            node_id INT NOT NULL,
            trigger_kind VARCHAR(16) DEFAULT 'manual',     /* manual | cron | alert */
            status VARCHAR(20) DEFAULT 'active',           /* active|awaiting_approval|resolved|failed|idle */
            title VARCHAR(220) DEFAULT '',
            summary TEXT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX(node_id), INDEX(status), INDEX(created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $conn->query("CREATE TABLE IF NOT EXISTS nm_aip_events (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            session_id BIGINT NOT NULL,
            node_id INT NOT NULL,
            phase VARCHAR(12) NOT NULL,                    /* observe|think|act|result|system|error */
            title VARCHAR(240) DEFAULT '',
            body MEDIUMTEXT NULL,
            data MEDIUMTEXT NULL,                          /* JSON */
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX(session_id), INDEX(node_id), INDEX(created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $conn->query("CREATE TABLE IF NOT EXISTS nm_aip_actions (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            session_id BIGINT NOT NULL,
            node_id INT NOT NULL,
            tool VARCHAR(64) NOT NULL,
            args MEDIUMTEXT NULL,                          /* JSON */
            risk VARCHAR(8) DEFAULT 'high',
            reason TEXT NULL,                              /* why the AI wants this */
            status VARCHAR(16) DEFAULT 'proposed',         /* proposed|approved|denied|executing|done|failed|auto */
            result MEDIUMTEXT NULL,
            proposed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            decided_at DATETIME NULL,
            decided_by INT NULL,
            executed_at DATETIME NULL,
            INDEX(session_id), INDEX(status), INDEX(node_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // allow_commands: per-device opt-in to AUTO-run high-risk shell commands (ssh_command)
        // in autopilot. Guarded ALTER (mysqli is in exception mode — never let it throw).
        $c = $conn->query("SELECT COUNT(*) c FROM INFORMATION_SCHEMA.COLUMNS
                           WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_aip_devices' AND COLUMN_NAME='allow_commands'");
        if ($c && (int)$c->fetch_assoc()['c'] === 0)
            $conn->query("ALTER TABLE nm_aip_devices ADD COLUMN allow_commands TINYINT DEFAULT 0");

        // telegram_approve: per-device opt-in — when an action needs approval, ALSO push it to
        // Telegram with Approve/Deny buttons and let the operator decide from their phone. This
        // does NOT change the autonomy gate (auto vs manual) — it only adds a delivery channel for
        // the SAME approval the portal already asks for. Guarded ALTER (mysqli exception mode).
        $c = $conn->query("SELECT COUNT(*) c FROM INFORMATION_SCHEMA.COLUMNS
                           WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_aip_devices' AND COLUMN_NAME='telegram_approve'");
        if ($c && (int)$c->fetch_assoc()['c'] === 0)
            $conn->query("ALTER TABLE nm_aip_devices ADD COLUMN telegram_approve TINYINT DEFAULT 0");

        // Pending Telegram approval requests — one row per action we've pushed to Telegram, so the
        // poller can (a) validate the callback token, (b) confirm the chat, (c) edit the right
        // message after a decision. Cleared once the action is decided.
        $conn->query("CREATE TABLE IF NOT EXISTS nm_aip_tg_approvals (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            action_id BIGINT NOT NULL,
            chat_id VARCHAR(40) NOT NULL,
            message_id BIGINT NULL,
            token VARCHAR(24) NOT NULL,
            status VARCHAR(12) DEFAULT 'pending',          /* pending | approved | denied | expired */
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            decided_at DATETIME NULL,
            UNIQUE KEY uq_action (action_id), INDEX(status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // RBAC seed (role_profiles map — role_name/button_key/enabled)
        $conn->query("INSERT IGNORE INTO role_profiles (role_name, button_key, enabled) VALUES ('admin','aiopilot',1)");

        // Seed the outbound n8n webhook slug 'aiopilot' (disabled until the operator pastes
        // the URL in Config → Integrations) so nm_n8n_call('aiopilot') has a row to resolve.
        if ($conn->query("SHOW TABLES LIKE 'nm_n8n_webhooks'")->num_rows) {
            $conn->query("INSERT IGNORE INTO nm_n8n_webhooks (name,slug,url,method,description,enabled)
                          VALUES ('AI Copilot (NetAIObot)','aiopilot','','POST','NetAIObot ReAct brain — receives full device context + tool catalog, runs the Observe→Think→Act loop, calls back aiopilot_api.php.',0)");
        }
    }

    // ── Global tuning (token budget + pacing) — nm_settings keys, safe defaults ──
    function nm_aip_setting($conn, string $key, string $def): string {
        $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='" . $conn->real_escape_string($key) . "' LIMIT 1");
        if ($r && $r->num_rows) { $v = $r->fetch_assoc()['setting_val']; if ($v !== '' && $v !== null) return (string)$v; }
        return $def;
    }
    // ── MASTER KILL SWITCH ──────────────────────────────────────────────────────
    // One toggle stops everything: dispatch refuses, the cron pacer skips, and the n8n
    // 'aiopilot' webhook row is flipped disabled too (so nothing reaches the brain).
    function nm_aip_enabled($conn): bool {
        return nm_aip_setting($conn, 'aip_enabled', '1') === '1';
    }
    function nm_aip_set_enabled($conn, bool $on, ?int $uid = null): bool {
        nm_aip_setting_set($conn, 'aip_enabled', $on ? '1' : '0');
        // mirror onto the outbound webhook so external triggers stop too
        $conn->query("UPDATE nm_n8n_webhooks SET enabled=" . ($on ? 1 : 0) . " WHERE slug='aiopilot'");
        if ($on) {
            // resuming: clear any sessions we parked so the queue isn't stuck
            $conn->query("UPDATE nm_aip_sessions SET status='idle' WHERE status='active' AND updated_at < (NOW() - INTERVAL 1 MINUTE)");
        } else {
            // stopping: drop the pending queue + close active turns so nothing fires after off
            $conn->query("UPDATE nm_aip_sessions SET status='idle' WHERE status IN ('queued','active')");
        }
        if (function_exists('nm_audit')) nm_audit($conn, 'aiopilot.master.' . ($on ? 'on' : 'off'), ['details'=>['by'=>$uid]]);
        return true;
    }

    function nm_aip_setting_set($conn, string $key, string $val): bool {
        if (!in_array($key, ['aip_compact','aip_max_concurrent','aip_min_gap_sec','aip_per_run_cap','aip_enabled'], true)) return false;
        $st = $conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES (?,?)
                              ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
        $st->bind_param('ss', $key, $val); $ok = $st->execute(); $st->close();
        return $ok;
    }
    function nm_aip_settings($conn): array {
        return [
            'compact'        => nm_aip_setting($conn, 'aip_compact', '1') === '1',  // trim context → fewer tokens
            'max_concurrent' => max(1, (int)nm_aip_setting($conn, 'aip_max_concurrent', '2')),
            'min_gap_sec'    => max(0, (int)nm_aip_setting($conn, 'aip_min_gap_sec', '15')),
            'per_run_cap'    => max(1, (int)nm_aip_setting($conn, 'aip_per_run_cap', '3')),
        ];
    }

    // Shrink the context to the essentials — the single biggest lever on tokens-per-minute.
    // Keeps everything diagnostic but drops history arrays / noise and caps list sizes.
    function nm_aip_compact_ctx(array $ctx): array {
        if (isset($ctx['ping']))       $ctx['ping'] = array_slice($ctx['ping'], 0, 3);
        if (isset($ctx['health'])) {                                   // latest value only, key metrics first
            $keep = [];
            foreach ($ctx['health'] as $h) { unset($h['history']); $keep[] = ['k'=>($h['type'].':'.$h['key']),'v'=>$h['latest']]; }
            $ctx['health'] = array_slice($keep, 0, 20);
        }
        if (isset($ctx['syslog'])) {                                   // errors/warnings first, cap 15
            $sl = $ctx['syslog'];
            usort($sl, fn($a,$b)=>(int)($a['severity']??7) <=> (int)($b['severity']??7));
            $ctx['syslog'] = array_map(fn($r)=>['t'=>$r['received_at'],'sev'=>$r['severity'],'msg'=>mb_substr((string)$r['message'],0,160)], array_slice($sl, 0, 15));
        }
        if (isset($ctx['interfaces']))                                 // drop timestamps; keep the row
            $ctx['interfaces'] = array_map(fn($i)=>['name'=>$i['display_name']?:$i['if_name'],'in'=>$i['in_rate'],'out'=>$i['out_rate'],'oper'=>$i['oper_status']], array_slice($ctx['interfaces'], 0, 12));
        if (isset($ctx['containers'])) {                               // only the broken ones + a count
            $bad = array_values(array_filter($ctx['containers'], fn($c)=>!empty($c['problem'])));
            $ctx['containers'] = ['total'=>count($ctx['containers']), 'problems'=>array_slice($bad, 0, 12)];
        }
        if (isset($ctx['gpu']))         $ctx['gpu'] = array_slice($ctx['gpu'], 0, 2);
        if (isset($ctx['open_insights'])) $ctx['open_insights'] = array_slice($ctx['open_insights'], 0, 10);
        return $ctx;
    }

    // ── Device selection / autonomy ───────────────────────────────────────────
    function nm_aip_devices($conn): array {
        nm_aip_ensure($conn);
        $out = [];
        $r = $conn->query("SELECT d.*, n.display_name, n.ip_address, n.os_icon
                           FROM nm_aip_devices d JOIN nm_nodes n ON n.id=d.node_id
                           ORDER BY n.display_name");
        while ($r && $x = $r->fetch_assoc()) $out[] = $x;
        return $out;
    }
    function nm_aip_device($conn, int $node_id): ?array {
        nm_aip_ensure($conn);
        $st = $conn->prepare("SELECT * FROM nm_aip_devices WHERE node_id=? LIMIT 1");
        $st->bind_param('i', $node_id); $st->execute();
        $row = $st->get_result()->fetch_assoc(); $st->close();
        return $row ?: null;
    }
    function nm_aip_device_set($conn, int $node_id, string $mode, int $enabled, int $destructive, ?int $uid, int $commands = 0, int $telegram = 0): array {
        nm_aip_ensure($conn);
        if (!in_array($mode, NM_AIP_MODES, true)) $mode = 'observe';
        $st = $conn->prepare("INSERT INTO nm_aip_devices (node_id,enabled,autonomy_mode,allow_destructive,allow_commands,telegram_approve,added_by)
                              VALUES (?,?,?,?,?,?,?)
                              ON DUPLICATE KEY UPDATE enabled=VALUES(enabled), autonomy_mode=VALUES(autonomy_mode),
                                                      allow_destructive=VALUES(allow_destructive), allow_commands=VALUES(allow_commands),
                                                      telegram_approve=VALUES(telegram_approve)");
        $st->bind_param('iisiiii', $node_id, $enabled, $mode, $destructive, $commands, $telegram, $uid);
        $ok = $st->execute(); $st->close();
        if (function_exists('nm_audit')) nm_audit($conn, 'aiopilot.device.set',
            ['target_type'=>'node','target_id'=>$node_id,'details'=>['mode'=>$mode,'enabled'=>$enabled,'destructive'=>$destructive,'commands'=>$commands,'telegram'=>$telegram]]);
        return ['ok'=>$ok];
    }
    function nm_aip_device_remove($conn, int $node_id): array {
        nm_aip_ensure($conn);
        $conn->query("DELETE FROM nm_aip_devices WHERE node_id=" . (int)$node_id);
        return ['ok'=>true];
    }

    // ── Autonomy gate: may this (mode, risk, destructive-allowed) auto-execute? ──
    function nm_aip_can_auto(string $mode, string $risk, int $allow_destructive, int $allow_commands = 0): bool {
        if ($mode === 'observe') return false;                 // observe NEVER acts
        if ($mode === 'copilot') return false;                 // copilot always proposes
        // autopilot:
        if ($risk === 'low')    return true;
        if ($risk === 'medium') return (bool)$allow_destructive; // medium auto only if operator opted in
        return (bool)$allow_commands;                           // high (ssh) auto ONLY if explicitly allowed
    }

    // ── TOOL REGISTRY (sent to the AI so it knows its eyes & hands) ─────────────
    function nm_aip_tools(): array {
        return [
            // READ / OBSERVE tools (always safe; the AI may call freely)
            ['name'=>'get_full_context','kind'=>'read','risk'=>'low','desc'=>'Re-pull every metric/log for the device.','params'=>[]],
            ['name'=>'ping_host','kind'=>'read','risk'=>'low','desc'=>'ICMP ping an IP.','params'=>['ip']],
            ['name'=>'read_logs','kind'=>'read','risk'=>'low','desc'=>'Last syslog lines for the device.','params'=>['limit']],
            ['name'=>'get_health','kind'=>'read','risk'=>'low','desc'=>'CPU/MEM/disk/uptime history.','params'=>[]],
            ['name'=>'get_netflow_top','kind'=>'read','risk'=>'low','desc'=>'Top talkers / flows seen for this host.','params'=>['limit']],
            ['name'=>'get_interfaces','kind'=>'read','risk'=>'low','desc'=>'Interface list + live rates + oper status.','params'=>[]],
            // ACTION tools (gated by risk + autonomy tier)
            ['name'=>'ssh_command','kind'=>'act','risk'=>'high','desc'=>'Run ONE shell/CLI command on the device over SSH (vetted, non-interactive).','params'=>['command']],
            ['name'=>'restart_service','kind'=>'act','risk'=>'medium','desc'=>'systemctl restart <service> (Linux) over SSH.','params'=>['service']],
            ['name'=>'block_ip','kind'=>'act','risk'=>'medium','desc'=>'Block a malicious IP fleet-wide via Collective Immunity.','params'=>['ip','reason']],
            ['name'=>'flush_dns','kind'=>'act','risk'=>'low','desc'=>'Flush DNS cache on the device (router/linux) over SSH.','params'=>[]],
            ['name'=>'clear_logs_rotate','kind'=>'act','risk'=>'low','desc'=>'Rotate/clear oversized log files when disk is high (Linux) over SSH.','params'=>['path']],
        ];
    }

    // ── Docker awareness: map a node → its Portainer endpoint (host that runs its containers).
    // Cached per request. Returns the endpoint id, or 0 if this node is not a Docker host.
    function nm_aip_node_endpoint($conn, array $node): int {
        static $cache = [];
        $ip = (string)($node['ip_address'] ?? '');
        if ($ip === '') return 0;
        if (array_key_exists($ip, $cache)) return $cache[$ip];
        if (!function_exists('nm_portainer_cfg') && is_file(__DIR__ . '/nm_portainer.php')) require_once __DIR__ . '/nm_portainer.php';
        if (!function_exists('nm_portainer_cfg')) return $cache[$ip] = 0;
        $cfg = nm_portainer_cfg($conn);
        if (!nm_portainer_configured($cfg)) return $cache[$ip] = 0;
        $eps = nm_portainer_endpoints($cfg);
        if (empty($eps['ok'])) return $cache[$ip] = 0;
        foreach (array_slice(nm_portainer_norm_endpoints($eps['data']), 0, 25) as $e) {
            $hip = nm_portainer_host_ip($cfg, (int)$e['id'], (string)$e['name']);
            if ($hip !== '' && $hip === $ip) return $cache[$ip] = (int)$e['id'];
        }
        return $cache[$ip] = 0;
    }

    // ── DEVICE CAPABILITIES: what kind it is + what the AI may actually DO ───────
    // Structural only (no secret decrypt) so it's identical from CLI cron and web.
    function nm_aip_capabilities($conn, array $node): array {
        $os = strtolower((string)($node['os_icon'] ?? 'generic'));
        $mt = strtolower((string)($node['monitor_type'] ?? 'snmp'));
        if ($mt === 'ping')                                   $kind = 'ping';
        elseif (in_array($os, ['mikrotik','cisco','routeros','router','juniper','arista'], true)) $kind = 'router';
        elseif ($os === 'windows')                            $kind = 'windows';
        elseif ($os === 'linux')                              $kind = 'linux';
        else                                                  $kind = 'snmp';   // generic SNMP host

        // can_ssh is decided by DEVICE TYPE first — NOT by whether a credential exists.
        // (A printer / generic-SNMP host may have a default cred assigned because the cred
        //  picker has no "None", but it is NOT an SSH device.) Only the SSH-managed kinds —
        //  router, windows, linux — can take shell actions, and only if a credential exists.
        $sshKinds = ['router','windows','linux'];
        $hasCred  = ((int)($node['ssh_cred_id'] ?? 0) > 0);
        if (!$hasCred && $conn->query("SHOW TABLES LIKE 'nm_ssh_credentials'")->num_rows) {
            $d = $conn->query("SELECT id FROM nm_ssh_credentials WHERE is_default=1 LIMIT 1");
            $hasCred = ($d && $d->num_rows > 0);
        }
        $can_ssh   = in_array($kind, $sshKinds, true) && $hasCred;
        $transport = $kind === 'windows' ? 'powershell' : ($kind === 'router' ? 'router-cli' : 'bash');

        // Is this node a Docker host? (a Portainer endpoint maps to its IP). NetAIObot only
        // OBSERVES containers — it does NOT act on them; container troubleshooting is owned by
        // the dedicated Containers module / Solution Commander (containers.php).
        $eid = nm_aip_node_endpoint($conn, $node);
        $is_docker = $eid > 0;

        // tools valid for THIS device (host/network level — NO container actions here)
        $acts = ['block_ip'];                                  // network-level, host-agnostic (Immunity)
        if ($can_ssh) {
            $acts[] = 'ssh_command'; $acts[] = 'flush_dns';
            if ($kind === 'linux') { $acts[] = 'restart_service'; $acts[] = 'clear_logs_rotate'; }
        }
        $cap = ['kind'=>$kind, 'os'=>$os, 'monitor_type'=>$mt,
                'can_ssh'=>$can_ssh, 'can_snmp'=>($mt !== 'ping'), 'ssh_transport'=>$transport,
                'is_docker_host'=>$is_docker, 'portainer_endpoint'=>$eid,
                'has_credential'=>$hasCred, 'allowed_actions'=>array_values(array_unique($acts))];
        if ($is_docker) $cap['container_help'] = 'For container-level problems, do NOT fix them here — hand off to the Containers module / Solution Commander at containers.php (it has a dedicated AI container-fix desk).';
        // KNOWLEDGE INJECTION — per-OS rules so the AI doesn't issue nonsense commands
        // (e.g. treating a ps/top thread name as a systemd service).
        $cap['guidance'] = match ($kind) {
            'linux'   => 'Linux/systemd host. systemd SERVICE names come from `systemctl list-units --type=service` — they are NOT the process/thread names you see in ps/top. "MainThread", "python", "java", "node", "mysqld"(process) are processes/threads, NOT services. Before restart_service, get the real unit name (e.g. mysql.service, nginx, docker) via `systemctl list-units`. Note: "available RAM low" on Linux is usually just kernel page-cache, not a real leak — check MemAvailable / `free -h`, do not panic-restart. Use sudo for systemctl. One non-interactive command per ssh_command.',
            'windows' => 'Windows host. Use PowerShell. SERVICE names come from `Get-Service` (short Name) — NOT process/Task-Manager image names. The portal already wraps commands in `powershell -NonInteractive`; do not add it. Use Get-* cmdlets to inspect.',
            'router'  => 'Network router. Use vendor CLI syntax ONLY (RouterOS: /interface, /ip, /system; Cisco IOS: show/conf t). NO bash, NO systemctl. Prefer read-only show commands.',
            'ping'    => 'PING-ONLY device — no shell at all. Only network-level actions (block_ip).',
            default   => 'SNMP-only device (printer/appliance) — no shell. Observe via SNMP/syslog; only network-level actions.',
        };
        return $cap;
    }

    // Validate a proposed action against device capabilities (the HARD guard).
    function nm_aip_validate_action($conn, int $node_id, string $tool): array {
        $node = $conn->query("SELECT id,display_name,os_icon,COALESCE(monitor_type,'snmp') monitor_type,ssh_cred_id FROM nm_nodes WHERE id=" . (int)$node_id . " LIMIT 1");
        $node = $node ? $node->fetch_assoc() : null;
        if (!$node) return ['ok'=>false,'error'=>'unknown node'];
        $cap = nm_aip_capabilities($conn, $node);
        $sshTools = ['ssh_command','restart_service','flush_dns','clear_logs_rotate'];
        if (in_array($tool, $sshTools, true) && !$cap['can_ssh']) {
            if ($cap['kind'] === 'ping')
                return ['ok'=>false,'error'=>"'$tool' rejected: {$node['display_name']} is a PING-ONLY device — no shell/SSH exists. Use a network-level action (e.g. block_ip) instead."];
            if (in_array($cap['kind'], ['snmp','generic'], true))
                return ['ok'=>false,'error'=>"'$tool' rejected: {$node['display_name']} is an SNMP-only device (a printer/appliance), NOT an SSH host — even if a credential is assigned. Observe via SNMP/syslog and use network-level actions only."];
            return ['ok'=>false,'error'=>"'$tool' rejected: no usable SSH credential for {$node['display_name']} (kind={$cap['kind']})."];
        }
        if ($tool === 'restart_service' && $cap['kind'] !== 'linux')
            return ['ok'=>false,'error'=>"'restart_service' is Linux-only; {$node['display_name']} is {$cap['kind']}."];
        // Container/Docker actions are OUT OF SCOPE for NetAIObot → point to the Containers module.
        if (preg_match('/container|docker|compose|portainer/i', $tool))
            return ['ok'=>false,'error'=>"NetAIObot does not act on containers. For container issues use the Containers module / Solution Commander (containers.php), which has a dedicated AI container-fix desk."];
        if (!in_array($tool, $cap['allowed_actions'], true) && in_array($tool, ['ssh_command','restart_service','flush_dns','clear_logs_rotate','block_ip'], true))
            return ['ok'=>false,'error'=>"'$tool' is not available for {$node['display_name']} ({$cap['kind']})."];
        return ['ok'=>true,'cap'=>$cap];
    }

    // When NetAIObot resolves an issue, close the loop: resolve the device's open insights.
    function nm_aip_resolve_node_insights($conn, int $node_id, int $session_id = 0): int {
        if ($conn->query("SHOW TABLES LIKE 'nm_ai_insights'")->num_rows === 0) return 0;
        $r = $conn->query("UPDATE nm_ai_insights SET status='resolved'
                           WHERE node_id=" . (int)$node_id . " AND status IN ('open','acknowledged')");
        $n = $conn->affected_rows;
        if ($n > 0 && $session_id) nm_aip_event($conn, $session_id, $node_id, 'system',
            "Closed $n pending insight(s)", 'NetAIObot resolved the situation and cleared the open alerts for this device.');
        return (int)$n;
    }

    // ── CONTEXT GATHERER: send the AI the information ───────────────────────────
    // $compact null = use the global setting; true/false forces. Compact ≈ 5-8× fewer tokens.
    function nm_aip_gather_context($conn, int $node_id, ?bool $compact = null): array {
        nm_aip_ensure($conn);
        $ctx = ['node_id'=>$node_id, 'gathered_at'=>date('c')];

        // Node identity
        $n = $conn->query("SELECT id,display_name,ip_address,os_icon,hw_model,location,snmp_version,
                                  hostname,COALESCE(monitor_type,'snmp') monitor_type,ssh_cred_id
                           FROM nm_nodes WHERE id=" . (int)$node_id . " LIMIT 1");
        $node = $n ? $n->fetch_assoc() : null;
        if (!$node) return ['error'=>'unknown node'];
        $ctx['node'] = $node;

        // Device type + what the AI is actually ALLOWED to do here (ping-only ⇒ no SSH!)
        $ctx['capabilities'] = nm_aip_capabilities($conn, $node);

        // Authoritative reachability verdict (up|degraded|down) — reuse the helper
        if (function_exists('nm_node_live_verdict')) $ctx['verdict'] = nm_node_live_verdict($conn, $node_id);

        // Recent ICMP
        $p = $conn->query("SELECT is_up,latency_ms,packet_loss,recorded_at FROM nm_ping_stats
                           WHERE node_id=" . (int)$node_id . " ORDER BY id DESC LIMIT 12");
        $ctx['ping'] = $p ? $p->fetch_all(MYSQLI_ASSOC) : [];

        // Health metrics (cpu/mem/disk/uptime/custom) — latest per key + short history
        $h = $conn->query("SELECT metric_type,metric_key,value,recorded_at FROM nm_device_stats
                           WHERE node_id=" . (int)$node_id . " AND recorded_at > (NOW() - INTERVAL 2 HOUR)
                           ORDER BY recorded_at DESC LIMIT 400");
        $health = [];
        while ($h && $row = $h->fetch_assoc()) {
            $k = $row['metric_type'] . ':' . $row['metric_key'];
            if (!isset($health[$k])) $health[$k] = ['type'=>$row['metric_type'],'key'=>$row['metric_key'],'latest'=>$row['value'],'at'=>$row['recorded_at'],'history'=>[]];
            if (count($health[$k]['history']) < 12) $health[$k]['history'][] = (float)$row['value'];
        }
        $ctx['health'] = array_values($health);

        // Interfaces + latest rates/oper. The correlated MAX is scoped to THIS node's few
        // interfaces (not a derived table over the whole nm_port_stats) so it rides the
        // idx_port_time(port_id,recorded_at) index — milliseconds, not a full-table scan.
        $ifq = $conn->query("SELECT i.id,i.if_name,i.display_name,i.if_index,
                                   ps.in_rate,ps.out_rate,ps.oper_status,ps.recorded_at
                            FROM nm_interfaces i
                            LEFT JOIN nm_port_stats ps
                                   ON ps.port_id=i.id
                                  AND ps.recorded_at=(SELECT MAX(x.recorded_at) FROM nm_port_stats x WHERE x.port_id=i.id)
                            WHERE i.node_id=" . (int)$node_id . " AND i.show_graph=1");
        $ctx['interfaces'] = $ifq ? $ifq->fetch_all(MYSQLI_ASSOC) : [];

        // Alert state + open insights
        $as = $conn->query("SELECT last_status,updated_at FROM nm_alert_state WHERE entity_type='node' AND entity_id=" . (int)$node_id . " LIMIT 1");
        $ctx['alert_state'] = $as ? $as->fetch_assoc() : null;
        $ins = $conn->query("SELECT id,title,severity,status,created_at FROM nm_ai_insights
                             WHERE node_id=" . (int)$node_id . " AND status IN ('open','acknowledged')
                             ORDER BY FIELD(severity,'critical','warning','info'), created_at DESC LIMIT 20");
        $ctx['open_insights'] = $ins ? $ins->fetch_all(MYSQLI_ASSOC) : [];

        // Syslog tail. nm_syslog has millions of rows; an `OR hostname` defeats the
        // idx_host_time(host_ip,…) index → full scan (was ~21s). Query by the INDEXED
        // host_ip first; only fall back to hostname (time-bounded) if that found nothing.
        if ($conn->query("SHOW TABLES LIKE 'nm_syslog'")->num_rows) {
            $ip = $conn->real_escape_string((string)$node['ip_address']);
            $sl = $conn->query("SELECT received_at,severity,tag,message FROM nm_syslog
                                WHERE host_ip='$ip' ORDER BY received_at DESC LIMIT 60");
            $ctx['syslog'] = $sl ? $sl->fetch_all(MYSQLI_ASSOC) : [];
        }

        // NetFlow top talkers for this IP. Real table is nm_netflow_flows (bucket datetime,
        // src_ip/dst_ip/app_port/protocol/bytes/packets) — time-bounded so it rides idx_src/idx_dst.
        if ($conn->query("SHOW TABLES LIKE 'nm_netflow_flows'")->num_rows) {
            $ip = $conn->real_escape_string((string)$node['ip_address']);
            $nf = $conn->query("SELECT src_ip,dst_ip,app_port,protocol,SUM(bytes) bytes,SUM(packets) packets
                                FROM nm_netflow_flows
                                WHERE bucket > (NOW()-INTERVAL 30 MINUTE) AND (src_ip='$ip' OR dst_ip='$ip')
                                GROUP BY src_ip,dst_ip,app_port,protocol ORDER BY bytes DESC LIMIT 15");
            $ctx['netflow_top'] = $nf ? $nf->fetch_all(MYSQLI_ASSOC) : [];
        }

        // GPU telemetry (optional) — stats join nm_gpu (per-GPU) → target. Wrapped: schema
        // drift must never crash the whole gather.
        if ($conn->query("SHOW TABLES LIKE 'nm_gpu_targets'")->num_rows) {
            try {
                $g = $conn->query("SELECT id FROM nm_gpu_targets WHERE node_id=" . (int)$node_id . " AND enabled=1 LIMIT 1");
                if ($g && $g->num_rows) { $tid = (int)$g->fetch_assoc()['id'];
                    $gs = $conn->query("SELECT g.gpu_index, s.util_pct, s.mem_used_mb, s.mem_total_mb, s.temp_c, s.power_w, s.sampled_at
                                        FROM nm_gpu_stats s JOIN nm_gpu g ON g.id=s.gpu_id
                                        WHERE g.target_id=$tid ORDER BY s.id DESC LIMIT 8");
                    $ctx['gpu'] = $gs ? $gs->fetch_all(MYSQLI_ASSOC) : [];
                }
            } catch (\Throwable $e) { /* skip GPU on schema drift */ }
        }

        // Docker containers running ON THIS HOST (so the AI can tell a log/event is a container
        // issue and act via the right Portainer endpoint — no SSH needed for container ops).
        $eid = (int)($ctx['capabilities']['portainer_endpoint'] ?? 0);
        if ($eid > 0 && function_exists('nm_portainer_cfg')) {
            $cfg = nm_portainer_cfg($conn);
            $cl = nm_portainer_containers($cfg, $eid, true);
            if (!empty($cl['ok'])) {
                $list = array_map('nm_portainer_norm_container', (array)$cl['data']);
                // keep it tight: name/state/status/image/stack + flag the unhealthy/exited ones
                $ctx['containers'] = array_map(fn($c)=>[
                    'name'=>$c['name'],'state'=>$c['state'],'status'=>$c['status'],
                    'image'=>$c['image'],'stack'=>$c['stack'],
                    'problem'=>(stripos($c['state'],'run')===false || stripos($c['status'],'unhealthy')!==false || stripos($c['status'],'restarting')!==false),
                ], array_slice($list, 0, 60));
                $ctx['docker_endpoint'] = $eid;
            }
            // recent container incidents from the AI incident desk (DB), best-effort
            if ($conn->query("SHOW TABLES LIKE 'container_incidents'")->num_rows) {
                try {
                    $ci = $conn->query("SELECT container_name,severity,status,ai_summary,error_text,occurrences,last_seen
                                        FROM container_incidents
                                        WHERE endpoint_id=$eid AND status NOT IN ('resolved','closed','ignored')
                                        ORDER BY last_seen DESC LIMIT 15");
                    if ($ci) $ctx['container_incidents'] = $ci->fetch_all(MYSQLI_ASSOC);
                } catch (\Throwable $e) { /* schema drift — skip */ }
            }
        }

        // Predictive health forecast (optional) — wrapped against schema drift
        if ($conn->query("SHOW TABLES LIKE 'nm_health_forecast'")->num_rows) {
            try {
                $hf = $conn->query("SELECT metric,severity,fail_eta,detail FROM nm_health_forecast
                                    WHERE node_id=" . (int)$node_id . " ORDER BY created_at DESC LIMIT 10");
                $ctx['predictive'] = $hf ? $hf->fetch_all(MYSQLI_ASSOC) : [];
            } catch (\Throwable $e) { /* skip predictive on schema drift */ }
        }

        // Recent ACTION history (last 24h) so the AI sees what's already been tried and does
        // NOT keep repeating the same fix — `count`≥3 means the circuit breaker will block auto.
        $ra = $conn->query("SELECT tool, args, COUNT(*) count, MAX(executed_at) last
                            FROM nm_aip_actions WHERE node_id=" . (int)$node_id . "
                            AND status='done' AND proposed_at > (NOW() - INTERVAL 24 HOUR)
                            GROUP BY tool, args ORDER BY count DESC LIMIT 10");
        if ($ra && $ra->num_rows) {
            $ctx['recent_actions'] = $ra->fetch_all(MYSQLI_ASSOC);
            $rep = array_filter($ctx['recent_actions'], fn($a)=>(int)$a['count'] >= 3);
            if ($rep) $ctx['recurring_warning'] = 'You have ALREADY applied some fixes 3+ times in 24h (see recent_actions). They are NOT working — STOP repeating them and DIAGNOSE the root cause instead.';
        }

        if ($compact === null) $compact = nm_aip_settings($conn)['compact'];
        if ($compact) $ctx = nm_aip_compact_ctx($ctx);
        return $ctx;
    }

    // ── Sessions & events (the live transcript the command center renders) ──────
    function nm_aip_session_start($conn, int $node_id, string $trigger = 'manual', string $title = ''): int {
        nm_aip_ensure($conn);
        $st = $conn->prepare("INSERT INTO nm_aip_sessions (node_id,trigger_kind,status,title) VALUES (?,?,'active',?)");
        $st->bind_param('iss', $node_id, $trigger, $title); $st->execute();
        $id = $st->insert_id; $st->close();
        return (int)$id;
    }
    // Resolve a node's display name (cached per-request).
    function nm_aip_node_name($conn, int $node_id): string {
        static $cache = [];
        if (isset($cache[$node_id])) return $cache[$node_id];
        $r = $conn->query("SELECT display_name FROM nm_nodes WHERE id=" . (int)$node_id . " LIMIT 1");
        $n = ($r && $r->num_rows) ? (string)$r->fetch_assoc()['display_name'] : '';
        return $cache[$node_id] = $n;
    }
    function nm_aip_event($conn, int $session_id, int $node_id, string $phase, string $title, string $body = '', $data = null): int {
        nm_aip_ensure($conn);
        // ENFORCE the subject node in EVERY log line: if the title doesn't already name the device,
        // prefix it. This makes "who is this about" unambiguous for any action/observation — the
        // portal events AND the free-form ones the n8n brain writes (which sometimes omit the node).
        if ($node_id > 0) {
            $nm = nm_aip_node_name($conn, $node_id);
            if ($nm !== '' && stripos($title, $nm) === false) $title = $nm . ' · ' . $title;
        }
        $j = $data === null ? null : json_encode($data);
        $st = $conn->prepare("INSERT INTO nm_aip_events (session_id,node_id,phase,title,body,data) VALUES (?,?,?,?,?,?)");
        $st->bind_param('iissss', $session_id, $node_id, $phase, $title, $body, $j); $st->execute();
        $id = $st->insert_id; $st->close();
        return (int)$id;
    }
    function nm_aip_session_set($conn, int $session_id, string $status, ?string $summary = null): void {
        if ($summary === null) {
            $st = $conn->prepare("UPDATE nm_aip_sessions SET status=? WHERE id=?");
            $st->bind_param('si', $status, $session_id);
        } else {
            $st = $conn->prepare("UPDATE nm_aip_sessions SET status=?, summary=? WHERE id=?");
            $st->bind_param('ssi', $status, $summary, $session_id);
        }
        $st->execute(); $st->close();
    }

    // ── Queue + paced promoter (covers ALL devices without blowing tokens/min) ──
    // Instead of firing every concerned device at once (→ TPM spike), we ENQUEUE sessions
    // and a pacer promotes them a few at a time, capped by max_concurrent active AI
    // conversations and spaced by min_gap_sec. Over successive cron ticks the whole fleet
    // is covered, but only N talk to the LLM at any moment.
    function nm_aip_enqueue($conn, int $node_id, string $trigger = 'cron', string $title = ''): int {
        nm_aip_ensure($conn);
        // skip if this node already has an open/queued session
        $b = $conn->query("SELECT id FROM nm_aip_sessions WHERE node_id=" . (int)$node_id . "
                           AND status IN ('queued','active','awaiting_approval') LIMIT 1");
        if ($b && $b->num_rows) return 0;
        $st = $conn->prepare("INSERT INTO nm_aip_sessions (node_id,trigger_kind,status,title) VALUES (?,?,'queued',?)");
        $st->bind_param('iss', $node_id, $trigger, $title); $st->execute();
        $id = (int)$st->insert_id; $st->close();
        return $id;
    }
    function nm_aip_queue_depth($conn): int {
        $r = $conn->query("SELECT COUNT(*) c FROM nm_aip_sessions WHERE status='queued'");
        return $r ? (int)$r->fetch_assoc()['c'] : 0;
    }
    // ── Reaper: self-heal sessions that show "active/awaiting" but aren't doing anything ───────
    // Two stuck cases the operator sees as a wrong "N active" counter with nothing happening:
    //   1) an 'active' session whose n8n turn died (never called back) — no new events for $mins.
    //   2) an 'awaiting_approval' session with NO live proposed action — unclickable, hangs forever.
    // Both are idled. Cheap (two indexed UPDATEs) so it's safe to call from the cron AND the feed.
    // Returns the number of sessions reaped. $mins is generous enough not to kill a legit in-flight
    // turn (LLM steps write events in seconds, not minutes).
    function nm_aip_reap_stale($conn, int $mins = 6): int {
        nm_aip_ensure($conn);
        $mins = max(2, $mins);
        $conn->query("UPDATE nm_aip_sessions s SET s.status='idle', s.summary=COALESCE(s.summary,'Auto-closed: no AI activity (stalled turn).')
                      WHERE s.status='active'
                      AND COALESCE((SELECT MAX(e.created_at) FROM nm_aip_events e WHERE e.session_id=s.id), s.created_at) < (NOW() - INTERVAL $mins MINUTE)");
        $n = $conn->affected_rows;
        $conn->query("UPDATE nm_aip_sessions s SET s.status='idle', s.summary=COALESCE(s.summary,'Auto-closed: approval request had no live action.')
                      WHERE s.status='awaiting_approval'
                      AND NOT EXISTS (SELECT 1 FROM nm_aip_actions a WHERE a.session_id=s.id AND a.status='proposed')");
        $n += $conn->affected_rows;
        return $n;
    }

    // Promote queued → dispatched, rate-limited. Cron-only (it sleeps between dispatches).
    function nm_aip_pace($conn): array {
        $cfg = nm_aip_settings($conn);
        nm_aip_reap_stale($conn, 8);   // free slots held by dead turns before promoting new ones
        $act = (int)$conn->query("SELECT COUNT(*) c FROM nm_aip_sessions WHERE status='active'")->fetch_assoc()['c'];
        $slots = min($cfg['per_run_cap'], $cfg['max_concurrent'] - $act);
        if ($slots <= 0) return ['promoted'=>0, 'active'=>$act, 'queued'=>nm_aip_queue_depth($conn), 'reason'=>'at capacity'];
        $q = $conn->query("SELECT id,node_id FROM nm_aip_sessions WHERE status='queued' ORDER BY id ASC LIMIT " . (int)$slots);
        $rows = $q ? $q->fetch_all(MYSQLI_ASSOC) : [];
        $n = 0;
        foreach ($rows as $i => $r) {
            if ($i > 0 && $cfg['min_gap_sec'] > 0) sleep(min(30, $cfg['min_gap_sec']));   // space the LLM I/O
            $conn->query("UPDATE nm_aip_sessions SET status='active' WHERE id=" . (int)$r['id']);
            nm_aip_dispatch($conn, (int)$r['id'], (int)$r['node_id'], 'queued');
            $n++;
        }
        return ['promoted'=>$n, 'active'=>$act, 'queued'=>nm_aip_queue_depth($conn)];
    }

    // ── Dispatch a turn to the AI brain (n8n) ──────────────────────────────────
    // Sends the full context + tool catalog + recent transcript. The n8n flow runs
    // the ReAct loop and calls back into aiopilot_api.php with think/act/result.
    function nm_aip_dispatch($conn, int $session_id, int $node_id, string $trigger = 'cron'): array {
        nm_aip_ensure($conn);
        if (!nm_aip_enabled($conn)) return ['ok'=>false,'error'=>'AI Copilot is OFF (master switch)'];
        $dev = nm_aip_device($conn, $node_id);
        if (!$dev || !$dev['enabled']) return ['ok'=>false,'error'=>'device not enabled for AI Copilot'];
        $ctx = nm_aip_gather_context($conn, $node_id);

        // recent transcript (so the AI keeps continuity within a session). Compact mode keeps
        // it short (token budget); titles only for older steps.
        $cfg = nm_aip_settings($conn);
        $hlim = $cfg['compact'] ? 6 : 20;
        $ev = $conn->query("SELECT phase,title," . ($cfg['compact'] ? "LEFT(body,200) body" : "body") . ",created_at FROM nm_aip_events
                            WHERE session_id=" . (int)$session_id . " ORDER BY id DESC LIMIT " . $hlim);
        $hist = $ev ? array_reverse($ev->fetch_all(MYSQLI_ASSOC)) : [];

        nm_aip_event($conn, $session_id, $node_id, 'observe', 'Gathered telemetry',
            'Pulled full context for ' . ($ctx['node']['display_name'] ?? "node $node_id") . ' and handed it to NetAIObot.',
            ['metrics'=>count($ctx['health'] ?? []), 'insights'=>count($ctx['open_insights'] ?? []),
             'syslog'=>count($ctx['syslog'] ?? []), 'ifaces'=>count($ctx['interfaces'] ?? [])]);

        $payload = [
            'session_id'   => $session_id,
            'node_id'      => $node_id,
            'trigger'      => $trigger,
            'autonomy'     => $dev['autonomy_mode'],
            'allow_destructive' => (int)$dev['allow_destructive'],
            'bot'          => 'NetAIObot',
            'context'      => $ctx,
            'tools'        => nm_aip_tools(),
            'history'      => $hist,
            'callback'     => [
                'think'   => 'aiopilot_api.php?ep=think',
                'act'     => 'aiopilot_api.php?ep=propose',
                'observe' => 'aiopilot_api.php?ep=tool',
                'finish'  => 'aiopilot_api.php?ep=finish',
            ],
        ];
        // NON-BLOCKING: NetAIObot's n8n flow does its work asynchronously and reports back via
        // aiopilot_api.php callbacks, so we DON'T wait for the whole ReAct loop. Use a short
        // timeout: if the webhook just accepted the POST (slow/no immediate response) that's a
        // SUCCESS ("dispatched, working async"); only a genuine connect failure is an error.
        [$code, $resp, $err] = nm_n8n_call($conn, 'aiopilot', $payload, 8);
        $isTimeout = $err && (stripos($err, 'timed out') !== false || stripos($err, 'timeout') !== false);
        if ($err && !$isTimeout) {
            nm_aip_event($conn, $session_id, $node_id, 'error', 'AI brain unreachable', (string)$err);
            nm_aip_session_set($conn, $session_id, 'failed');
            return ['ok'=>false,'error'=>$err,'code'=>$code];
        }
        if ($isTimeout) {
            nm_aip_event($conn, $session_id, $node_id, 'system', 'Dispatched to NetAIObot',
                'Handed off to the AI brain — working asynchronously; results will stream in as they happen.');
        }
        return ['ok'=>true,'code'=>$code,'resp'=>$resp,'async'=>$isTimeout];
    }

    // The node a session is bound to (authoritative — the LLM must not pick nodes).
    function nm_aip_session_node($conn, int $session_id): int {
        if ($session_id <= 0) return 0;
        $r = $conn->query("SELECT node_id FROM nm_aip_sessions WHERE id=" . (int)$session_id . " LIMIT 1");
        return ($r && $r->num_rows) ? (int)$r->fetch_assoc()['node_id'] : 0;
    }

    // ── READ tool runner (the AI's "eyes" — always safe, returns data) ─────────
    // Hardened for weak/local LLMs (qwen etc.): tolerates hallucinated/no-op tools and
    // never returns a silent [] that the model can misread as "no data".
    function nm_aip_run_tool($conn, int $node_id, string $tool, array $args): array {
        nm_aip_ensure($conn);
        $tool = strtolower(trim($tool));

        // benign no-ops some models emit instead of finishing — accept gracefully
        if (in_array($tool, ['do_nothing','none','noop','no_op','wait','skip','idle',''], true))
            return ['ok'=>true,'noop'=>true,'data'=>['note'=>'No action taken (no-op). If the device looks healthy, call finish with status:resolved or idle.']];

        // every read tool needs a real node; surface a clear error (not silent empty)
        $valid = $conn->query("SELECT id FROM nm_nodes WHERE id=" . (int)$node_id . " LIMIT 1");
        if (!$valid || !$valid->num_rows)
            return ['ok'=>false,'error'=>"unknown node_id ($node_id). Do NOT pass node_id — the session already targets one device."];

        switch ($tool) {
            case 'get_full_context': return ['ok'=>true,'data'=>nm_aip_gather_context($conn, $node_id)];
            case 'get_health':
            case 'get_interfaces':
                $c = nm_aip_gather_context($conn, $node_id);
                return ['ok'=>true,'data'=>$tool==='get_health' ? ($c['health']??[]) : ($c['interfaces']??[])];
            case 'read_logs':
                $c = nm_aip_gather_context($conn, $node_id);
                return ['ok'=>true,'data'=>array_slice($c['syslog']??[], 0, (int)($args['limit'] ?? 40))];
            case 'get_netflow_top':
                $c = nm_aip_gather_context($conn, $node_id);
                return ['ok'=>true,'data'=>array_slice($c['netflow_top']??[], 0, (int)($args['limit'] ?? 15))];
            case 'ping_host':
                $ip = preg_replace('/[^0-9a-fA-F:.]/', '', (string)($args['ip'] ?? ''));
                if ($ip === '') return ['ok'=>false,'error'=>'bad ip'];
                $out = shell_exec('ping -c2 -W2 ' . escapeshellarg($ip) . ' 2>&1');
                return ['ok'=>true,'data'=>['raw'=>$out, 'reachable'=>(strpos((string)$out,' 0% packet loss')!==false || strpos((string)$out,'bytes from')!==false)]];
        }
        // If it's a known ACTION tool, tell the model to use ep=propose, not ep=tool.
        if (in_array($tool, ['ssh_command','restart_service','flush_dns','clear_logs_rotate','block_ip'], true))
            return ['ok'=>false,'error'=>"'$tool' is an ACTION — call it via ep=propose (with risk+reason), not ep=tool."];
        $names = implode(', ', array_map(fn($t)=>$t['name'], array_filter(nm_aip_tools(), fn($t)=>$t['kind']==='read')));
        return ['ok'=>false,'error'=>"unknown tool '$tool'. Valid read tools: $names. Or call ep=finish if done."];
    }

    // Does this action CHANGE STATE? The circuit breaker only blocks repeated *mutating* fixes
    // (restart/kill/rm…). Read-only diagnostics (ps/top/free/df/cat/ss/show…) must be allowed to
    // repeat freely — the bot needs to keep observing; blocking them just forces pointless approvals.
    function nm_aip_is_mutating(string $tool, array $args): bool {
        if ($tool !== 'ssh_command') return true;          // restart_service/container/block_ip/flush_dns/clear_logs = state-changing
        $c = ' ' . strtolower(trim((string)($args['command'] ?? ''))) . ' ';
        $mut = [' rm ','reboot','shutdown','halt','poweroff','mkfs',' dd ','kill','pkill','killall','truncate',
                'chmod','chown','chattr','restart','reload','disable',' enable',' mask','iptables','nft ',
                'systemctl stop','systemctl start','service ',' del ',' delete ',' add ',' reset','format','wipe',
                '/system','/interface','/ip ','remove-','set-','stop-','new-','/dev/sd','>>'];
        foreach ($mut as $m) if (strpos($c, $m) !== false) return true;
        if (preg_match('#>\s*/(?!dev/null)#', $c)) return true;   // redirect that writes a real file
        return false;                                            // pure inspection → not mutating
    }

    // ── CIRCUIT BREAKER: how many times this exact fix already ran recently ─────
    // Persistent (survives sessions). Same node + tool + args, successfully executed.
    function nm_aip_recurrence($conn, int $node_id, string $tool, array $args, int $hours = 24): int {
        $aj = json_encode($args);
        $st = $conn->prepare("SELECT COUNT(*) c FROM nm_aip_actions
                              WHERE node_id=? AND tool=? AND args=? AND status='done'
                              AND proposed_at > (NOW() - INTERVAL ? HOUR)");
        $st->bind_param('issi', $node_id, $tool, $aj, $hours);
        $st->execute(); $c = (int)$st->get_result()->fetch_assoc()['c']; $st->close();
        return $c;
    }
    // Raise/refresh a 'recurring_issue' insight (the temporary fix isn't solving root cause).
    function nm_aip_recurring_insight($conn, int $node_id, string $tool, array $args, int $count): void {
        if ($conn->query("SHOW TABLES LIKE 'nm_ai_insights'")->num_rows === 0) return;
        $nmq = $conn->query("SELECT display_name FROM nm_nodes WHERE id=" . (int)$node_id . " LIMIT 1");
        $nm  = ($nmq && $nmq->num_rows) ? $nmq->fetch_assoc()['display_name'] : "node $node_id";
        $ck  = 'aip_recurring:' . $node_id . ':' . $tool . ':' . substr(md5(json_encode($args)), 0, 10);
        $title = "Recurring fix not resolving root cause: $tool on $nm";
        $body  = "NetAIObot applied '$tool' {$count}× in 24h on $nm but the problem keeps returning. "
               . "A temporary fix is masking the real cause — needs root-cause investigation, not another repeat.";
        try {
            $e = $conn->query("SELECT id FROM nm_ai_insights WHERE correlation_key='" . $conn->real_escape_string($ck) . "' AND status IN ('open','acknowledged') LIMIT 1");
            if ($e && $e->num_rows) {
                $id = (int)$e->fetch_assoc()['id'];
                $st = $conn->prepare("UPDATE nm_ai_insights SET body=?, severity='warning' WHERE id=?");
                $st->bind_param('si', $body, $id); $st->execute(); $st->close();
            } else {
                $data = json_encode(['tool'=>$tool,'args'=>$args,'count'=>$count]);
                $kind='recurring_issue'; $sev='warning'; $src='aiopilot'; $stt='open';
                $st = $conn->prepare("INSERT INTO nm_ai_insights (node_id,kind,severity,title,body,data,source,status,correlation_key)
                                      VALUES (?,?,?,?,?,?,?,?,?)");
                $st->bind_param('issssssss', $node_id, $kind, $sev, $title, $body, $data, $src, $stt, $ck);
                $st->execute(); $st->close();
            }
        } catch (\Throwable $e) { /* schema drift — skip */ }
    }

    // ── Propose an action (gated). Auto-executes if the tier allows. ───────────
    function nm_aip_propose_action($conn, int $session_id, int $node_id, string $tool, array $args, string $risk, string $reason): array {
        nm_aip_ensure($conn);
        if (!in_array($risk, NM_AIP_RISK, true)) $risk = 'high';

        // HARD GUARD: reject actions the device can't support (e.g. SSH on a ping-only box)
        // BEFORE creating a pending action — and tell the AI why so it picks another path.
        $val = nm_aip_validate_action($conn, $node_id, $tool);
        if (empty($val['ok'])) {
            nm_aip_event($conn, $session_id, $node_id, 'error', 'Action rejected: ' . $tool, (string)$val['error'],
                ['tool'=>$tool,'args'=>$args,'rejected'=>true]);
            return ['ok'=>false,'error'=>$val['error'],'rejected'=>true];
        }

        $dev = nm_aip_device($conn, $node_id);
        $mode = $dev['autonomy_mode'] ?? 'observe';
        $auto = nm_aip_can_auto($mode, $risk, (int)($dev['allow_destructive'] ?? 0), (int)($dev['allow_commands'] ?? 0));

        // CIRCUIT BREAKER: if this EXACT fix already ran ≥3× in 24h, the problem keeps coming
        // back — stop auto-repeating a band-aid. Force human-in-the-loop (even autopilot), raise
        // a recurring_issue insight, and flag the reason so the AI pivots to root-cause diagnosis.
        $rec = nm_aip_recurrence($conn, $node_id, $tool, $args, 24);
        if ($rec >= 3 && nm_aip_is_mutating($tool, $args)) {
            if ($auto) nm_aip_event($conn, $session_id, $node_id, 'system', 'Circuit breaker tripped: ' . $tool,
                "This fix already ran {$rec}× in 24h and the issue returned — auto-execution blocked; needs human approval + root-cause.");
            $auto = false;                                  // force approval regardless of tier
            nm_aip_recurring_insight($conn, $node_id, $tool, $args, $rec + 1);
            $reason = "[RECURRING ×{$rec}] " . $reason . " — this exact fix keeps being applied but the problem returns; investigate the ROOT CAUSE instead of repeating it.";
        }

        $aj = json_encode($args);
        $status = $auto ? 'approved' : 'proposed';
        $st = $conn->prepare("INSERT INTO nm_aip_actions (session_id,node_id,tool,args,risk,reason,status)
                              VALUES (?,?,?,?,?,?,?)");
        $st->bind_param('iisssss', $session_id, $node_id, $tool, $aj, $risk, $reason, $status);
        $st->execute(); $aid = (int)$st->insert_id; $st->close();

        nm_aip_event($conn, $session_id, $node_id, 'act',
            ($auto ? 'Auto-action queued: ' : 'Proposed action: ') . $tool,
            $reason, ['action_id'=>$aid,'tool'=>$tool,'args'=>$args,'risk'=>$risk,'auto'=>$auto]);

        if ($auto) {
            return nm_aip_execute_action($conn, $aid, null, true);
        }
        // needs a human — flip session + notify
        nm_aip_session_set($conn, $session_id, 'awaiting_approval');
        if (function_exists('nm_notify_send')) {
            // best-effort push; ignore failures
            @nm_notify_send($conn, [], ['title'=>"NetAIObot needs approval: $tool",'body'=>$reason], 'aiopilot.approval');
        }
        // Two-way Telegram approval: if this device opted in, push the proposed command +
        // explanation to Telegram with Approve/Deny buttons so the operator can decide from their
        // phone. The reply is handled by nm_aip_tg_poll() (cron_aip_telegram.php).
        $tgSent = false;
        if (!empty($dev['telegram_approve'])) {
            $tg = nm_aip_tg_notify_action($conn, $aid);
            $tgSent = !empty($tg['ok']);
        }
        return ['ok'=>true,'action_id'=>$aid,'status'=>'proposed','needs_approval'=>true,
                'telegram'=>$tgSent, 'recurrence'=>$rec, 'recurring'=>($rec >= 3)];
    }

    // ── Execute an approved/auto action via vetted primitives ──────────────────
    function nm_aip_execute_action($conn, int $action_id, ?int $by = null, bool $auto = false): array {
        nm_aip_ensure($conn);
        $a = $conn->query("SELECT * FROM nm_aip_actions WHERE id=" . (int)$action_id . " LIMIT 1");
        $a = $a ? $a->fetch_assoc() : null;
        if (!$a) return ['ok'=>false,'error'=>'action not found'];
        if (in_array($a['status'], ['done','denied','executing'], true)) return ['ok'=>false,'error'=>'already '.$a['status']];

        $conn->query("UPDATE nm_aip_actions SET status='executing', decided_at=NOW(), decided_by=" . ($by===null?'NULL':(int)$by) . " WHERE id=" . (int)$action_id);
        $args = json_decode((string)$a['args'], true) ?: [];
        $node_id = (int)$a['node_id']; $sid = (int)$a['session_id']; $tool = $a['tool'];
        $res = nm_aip_do($conn, $node_id, $tool, $args);

        $ok = !empty($res['ok']);
        $detail = $ok ? (is_string($res['data'] ?? null) ? $res['data'] : json_encode($res['data'] ?? $res)) : (string)($res['error'] ?? 'failed');
        $detail = substr($detail, 0, 4000);
        $newst = $ok ? 'done' : 'failed';
        $st = $conn->prepare("UPDATE nm_aip_actions SET status=?, result=?, executed_at=NOW() WHERE id=?");
        $st->bind_param('ssi', $newst, $detail, $action_id); $st->execute(); $st->close();

        // show the ACTUAL command that ran on the device, then its output (red in the UI)
        $cmdShown = $tool === 'ssh_command' ? (string)($args['command'] ?? '')
                  : trim($tool . ' ' . ($args ? json_encode($args) : ''));
        $rbody = ($cmdShown !== '' ? '$ ' . $cmdShown . "\n\n" : '') . $detail;
        nm_aip_event($conn, $sid, $node_id, 'result',
            ($ok ? '⚡ Executed: ' : '⚡ Execution FAILED: ') . $tool, $rbody,
            ['action_id'=>$action_id,'ok'=>$ok,'auto'=>$auto,'executed'=>true,'cmd'=>$cmdShown]);
        if (function_exists('nm_audit')) nm_audit($conn, 'aiopilot.action.execute',
            ['target_type'=>'node','target_id'=>$node_id,'details'=>['tool'=>$tool,'ok'=>$ok,'auto'=>$auto,'by'=>$by]]);
        // A MANUALLY-approved action runs OUTSIDE the n8n turn (operator clicked Approve), so the
        // ReAct loop is paused. Resume it: re-dispatch a continuation turn so the AI sees the
        // result and finishes (or proposes the next step) — otherwise the session hangs forever
        // on "verifying". Auto actions run INSIDE the turn, so the flow already continues.
        if (!$auto) {
            nm_aip_session_set($conn, $sid, 'active');
            if (nm_aip_enabled($conn)) nm_aip_dispatch($conn, $sid, $node_id, 'continue');
        }
        return ['ok'=>$ok,'action_id'=>$action_id,'result'=>$detail];
    }

    // ── Deny a proposed action (shared by the portal API and the Telegram poller) ─
    function nm_aip_deny_action($conn, int $action_id, ?int $by = null, string $note = ''): array {
        nm_aip_ensure($conn);
        $a = $conn->query("SELECT session_id,node_id,tool,status FROM nm_aip_actions WHERE id=" . (int)$action_id . " LIMIT 1");
        $a = $a ? $a->fetch_assoc() : null;
        if (!$a) return ['ok'=>false,'error'=>'action not found'];
        if ($a['status'] !== 'proposed') return ['ok'=>false,'error'=>'already '.$a['status']];
        $byS = ($by === null ? 'NULL' : (int)$by);
        $conn->query("UPDATE nm_aip_actions SET status='denied', decided_at=NOW(), decided_by=$byS WHERE id=" . (int)$action_id . " AND status='proposed'");
        nm_aip_event($conn, (int)$a['session_id'], (int)$a['node_id'], 'system',
            'DENIED action: ' . $a['tool'], $note !== '' ? $note : 'Taking manual control.');
        // Deny = the operator is taking manual control → CLOSE the session. Leaving it 'active'
        // (with nothing re-dispatched) is exactly what made it hang as a phantom "active" with no
        // activity. If the operator wants the bot to try again, they Run it again.
        nm_aip_session_set($conn, (int)$a['session_id'], 'resolved', 'Operator denied the proposed action — manual control taken.');
        if (function_exists('nm_audit')) nm_audit($conn, 'aiopilot.action.deny',
            ['target_type'=>'node','target_id'=>(int)$a['node_id'],'details'=>['action_id'=>$action_id,'by'=>$by]]);
        return ['ok'=>true];
    }

    // ── Two-way Telegram approvals ─────────────────────────────────────────────
    // Reuses the SAME bot configured in Notifications (notify_admin.php) — no new secret to store.
    // Sends the proposed command + explanation with inline Approve/Deny buttons; a cron poller
    // (cron_aip_telegram.php → nm_aip_tg_poll) reads the operator's tap and approves/denies the
    // exact same action the portal is asking about.

    // Resolve the first ENABLED telegram notification channel → ['token'=>..,'chat'=>..] or null.
    function nm_aip_tg_channel($conn): ?array {
        if (!function_exists('nm_notify_channels') && is_file(__DIR__ . '/nm_notify.php')) require_once __DIR__ . '/nm_notify.php';
        if (!function_exists('nm_notify_channels')) return null;
        foreach (nm_notify_channels($conn, true) as $c) {
            if (($c['type'] ?? '') !== 'telegram') continue;
            $full = nm_notify_channel_get($conn, (int)$c['id']);
            $tok = trim((string)($full['secret'] ?? ''));
            $chat = trim((string)($full['target'] ?? ''));
            if ($tok !== '' && $chat !== '') return ['token'=>$tok, 'chat'=>$chat, 'channel'=>$full['name'] ?? 'Telegram'];
        }
        return null;
    }

    // Low-level Telegram Bot API call (JSON). Best-effort; never throws.
    function nm_aip_tg_api(string $token, string $method, array $params): array {
        $url = "https://api.telegram.org/bot{$token}/{$method}";
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_POST=>true,
            CURLOPT_POSTFIELDS => json_encode($params), CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            CURLOPT_CONNECTTIMEOUT=>5, CURLOPT_TIMEOUT=>35,
            CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_SSL_VERIFYHOST=>false]);
        $resp = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $err = curl_error($ch); curl_close($ch);
        if ($resp === false) return ['ok'=>false,'error'=>$err ?: 'connection failed'];
        $j = json_decode($resp, true);
        if (!is_array($j)) return ['ok'=>false,'error'=>'bad response','code'=>$code];
        if (empty($j['ok'])) return ['ok'=>false,'error'=>$j['description'] ?? ('HTTP '.$code),'code'=>$code];
        return ['ok'=>true,'result'=>$j['result'] ?? null];
    }

    // Human-readable one-liner of what the AI wants to run (command for ssh, else tool+args).
    function nm_aip_action_cmd_preview(array $a): string {
        $args = json_decode((string)($a['args'] ?? ''), true) ?: [];
        if (($a['tool'] ?? '') === 'ssh_command') return (string)($args['command'] ?? '');
        return trim(($a['tool'] ?? '') . ' ' . ($args ? json_encode($args) : ''));
    }

    // Push a proposed action to Telegram with Approve/Deny buttons. Records the pending request.
    function nm_aip_tg_notify_action($conn, int $action_id): array {
        nm_aip_ensure($conn);
        $tg = nm_aip_tg_channel($conn);
        if (!$tg) return ['ok'=>false,'error'=>'no enabled Telegram channel configured'];
        $a = $conn->query("SELECT a.*, n.display_name, n.ip_address FROM nm_aip_actions a
                           JOIN nm_nodes n ON n.id=a.node_id WHERE a.id=" . (int)$action_id . " LIMIT 1");
        $a = $a ? $a->fetch_assoc() : null;
        if (!$a) return ['ok'=>false,'error'=>'action not found'];

        // secure token binds the button to THIS action; validated on callback.
        $token = substr(bin2hex(random_bytes(8)), 0, 12);
        $risk  = strtoupper((string)$a['risk']);
        $emoji = ['LOW'=>'🟢','MEDIUM'=>'🟠','HIGH'=>'🔴'][$risk] ?? '⚪';
        $cmd   = nm_aip_action_cmd_preview($a);
        $reason = trim((string)$a['reason']);
        $lines = [
            "🤖 *NetAIObot needs your approval*",
            "",
            "*Device:* " . nm_aip_tg_esc($a['display_name']) . " (" . nm_aip_tg_esc($a['ip_address']) . ")",
            "*Action:* " . nm_aip_tg_esc($a['tool']) . "   {$emoji} " . nm_aip_tg_esc($risk) . " risk",
        ];
        if ($cmd !== '')   $lines[] = "*Command:*\n```\n" . nm_aip_tg_esc(mb_substr($cmd, 0, 600)) . "\n```";
        if ($reason !== '') $lines[] = "*Why:* " . nm_aip_tg_esc(mb_substr($reason, 0, 700));
        $lines[] = "";
        $lines[] = "_Approve to run it now, or Deny to keep manual control._";
        $text = implode("\n", $lines);

        $kb = ['inline_keyboard'=>[[
            ['text'=>'✅ Approve & run', 'callback_data'=>"aip:{$action_id}:{$token}:a"],
            ['text'=>'🚫 Deny',          'callback_data'=>"aip:{$action_id}:{$token}:d"],
        ]]];
        $r = nm_aip_tg_api($tg['token'], 'sendMessage', [
            'chat_id'=>$tg['chat'], 'text'=>$text, 'parse_mode'=>'Markdown',
            'disable_web_page_preview'=>true, 'reply_markup'=>$kb]);
        if (empty($r['ok'])) {
            // fallback: retry without markdown (a stray char can break Markdown parsing)
            $r = nm_aip_tg_api($tg['token'], 'sendMessage', [
                'chat_id'=>$tg['chat'], 'text'=>preg_replace('/[*_`]/', '', $text),
                'disable_web_page_preview'=>true, 'reply_markup'=>$kb]);
        }
        if (empty($r['ok'])) return ['ok'=>false,'error'=>$r['error'] ?? 'send failed'];
        $mid = (int)($r['result']['message_id'] ?? 0);

        $chat = (string)$tg['chat'];
        $st = $conn->prepare("INSERT INTO nm_aip_tg_approvals (action_id,chat_id,message_id,token,status)
                              VALUES (?,?,?,?,'pending')
                              ON DUPLICATE KEY UPDATE chat_id=VALUES(chat_id), message_id=VALUES(message_id),
                                                      token=VALUES(token), status='pending', created_at=NOW(), decided_at=NULL");
        $st->bind_param('isis', $action_id, $chat, $mid, $token); $st->execute(); $st->close();
        return ['ok'=>true,'message_id'=>$mid];
    }

    // Escape text destined for Telegram Markdown code/plain segments (light touch).
    function nm_aip_tg_esc(string $s): string { return str_replace(['`'], ["'"], $s); }

    // When a decision is made in the PORTAL, close out any pending Telegram request for the same
    // action: edit the message (remove buttons, show verdict) + mark it resolved so a later tap is
    // rejected as "already decided". Best-effort — no-op if there was no Telegram push.
    function nm_aip_tg_close($conn, int $action_id, string $status, string $verdictLine): void {
        nm_aip_ensure($conn);
        $p = $conn->query("SELECT * FROM nm_aip_tg_approvals WHERE action_id=" . (int)$action_id . " AND status='pending' LIMIT 1");
        $p = $p ? $p->fetch_assoc() : null;
        if (!$p) return;
        $conn->query("UPDATE nm_aip_tg_approvals SET status='" . $conn->real_escape_string($status) . "', decided_at=NOW() WHERE action_id=" . (int)$action_id);
        $tg = nm_aip_tg_channel($conn);
        if ($tg) nm_aip_tg_edit_decided($conn, $tg['token'], (string)$p['chat_id'], (int)$p['message_id'], $action_id, $verdictLine);
    }

    // ── The poller: read Telegram button taps and apply the decision ───────────
    // Runs in a WEB request (www-data) so the encrypted bot token decrypts. Uses getUpdates with a
    // persisted offset (nm_settings key 'aip_tg_offset'). Validates the callback token AND the chat
    // id before acting, so only the configured operator chat can approve.
    function nm_aip_tg_poll($conn, int $longpoll = 0): array {
        nm_aip_ensure($conn);
        $tg = nm_aip_tg_channel($conn);
        if (!$tg) return ['ok'=>false,'error'=>'no telegram channel','processed'=>0];

        $offRow = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='aip_tg_offset' LIMIT 1");
        $offset = ($offRow && $offRow->num_rows) ? (int)$offRow->fetch_assoc()['setting_val'] : 0;

        $params = ['timeout'=>max(0, min(50, $longpoll)), 'allowed_updates'=>['callback_query']];
        if ($offset > 0) $params['offset'] = $offset + 1;
        $r = nm_aip_tg_api($tg['token'], 'getUpdates', $params);
        if (empty($r['ok'])) return ['ok'=>false,'error'=>$r['error'] ?? 'getUpdates failed','processed'=>0];

        $updates = $r['result'] ?? [];
        $processed = 0; $maxId = $offset;
        foreach ($updates as $u) {
            $uid = (int)($u['update_id'] ?? 0);
            if ($uid > $maxId) $maxId = $uid;
            $cb = $u['callback_query'] ?? null;
            if (!$cb) continue;
            $data = (string)($cb['data'] ?? '');
            $cbId = (string)($cb['id'] ?? '');
            $chatId = (string)($cb['message']['chat']['id'] ?? '');
            $msgId  = (int)($cb['message']['message_id'] ?? 0);
            $who    = trim(((string)($cb['from']['first_name'] ?? '')) . ' ' . ((string)($cb['from']['username'] ? '@'.$cb['from']['username'] : '')));

            // only accept taps from the configured chat
            if ($chatId !== '' && (string)$tg['chat'] !== '' && $chatId !== (string)$tg['chat']) {
                nm_aip_tg_api($tg['token'], 'answerCallbackQuery', ['callback_query_id'=>$cbId, 'text'=>'Not authorized.']);
                continue;
            }
            // Service Biosphere "⚡ Auto-Tune" approvals ride the SAME bot/poller (a second getUpdates
            // poller would steal each other's updates via the shared offset). Dispatch bio: here.
            if (strpos($data, 'bio:') === 0) {
                if (is_file(__DIR__ . '/nm_biosphere.php')) require_once __DIR__ . '/nm_biosphere.php';
                if (function_exists('nm_bio_tg_callback')) { nm_bio_tg_callback($conn, $tg, $cb, $data); $processed++; }
                else nm_aip_tg_api($tg['token'], 'answerCallbackQuery', ['callback_query_id'=>$cbId]);
                continue;
            }
            // NEURU Commander V2 approvals ride the SAME bot/poller (shared offset). Dispatch ap2: here.
            if (strpos($data, 'ap2:') === 0) {
                if (is_file(__DIR__ . '/nm_autopilotv2.php')) require_once __DIR__ . '/nm_autopilotv2.php';
                if (function_exists('nm_ap2_tg_callback')) { nm_ap2_tg_callback($conn, $tg, $cb, $data); $processed++; }
                else nm_aip_tg_api($tg['token'], 'answerCallbackQuery', ['callback_query_id'=>$cbId]);
                continue;
            }
            if (strpos($data, 'aip:') !== 0) { nm_aip_tg_api($tg['token'], 'answerCallbackQuery', ['callback_query_id'=>$cbId]); continue; }
            $parts = explode(':', $data);       // aip : <aid> : <token> : a|d
            if (count($parts) < 4) { nm_aip_tg_api($tg['token'], 'answerCallbackQuery', ['callback_query_id'=>$cbId]); continue; }
            $aid = (int)$parts[1]; $tok = $parts[2]; $verdict = $parts[3];

            $pend = $conn->query("SELECT * FROM nm_aip_tg_approvals WHERE action_id=$aid LIMIT 1");
            $pend = $pend ? $pend->fetch_assoc() : null;
            $processed++;

            if (!$pend || !hash_equals((string)$pend['token'], (string)$tok)) {
                nm_aip_tg_api($tg['token'], 'answerCallbackQuery', ['callback_query_id'=>$cbId, 'text'=>'This request expired.']);
                continue;
            }
            if ($pend['status'] !== 'pending') {
                nm_aip_tg_api($tg['token'], 'answerCallbackQuery', ['callback_query_id'=>$cbId, 'text'=>'Already ' . $pend['status'] . '.']);
                continue;
            }

            $note = 'via Telegram' . ($who !== '' ? " ({$who})" : '');
            if ($verdict === 'a') {
                $res = nm_aip_execute_action($conn, $aid, null, false);
                $ok = !empty($res['ok']);
                $conn->query("UPDATE nm_aip_tg_approvals SET status='approved', decided_at=NOW() WHERE action_id=$aid");
                nm_aip_tg_api($tg['token'], 'answerCallbackQuery', ['callback_query_id'=>$cbId, 'text'=>$ok ? '✅ Approved — running.' : '⚠️ Approved but execution failed.']);
                nm_aip_tg_edit_decided($conn, $tg['token'], $chatId, $msgId, $aid, $ok ? "✅ *Approved &amp; executed* {$note}" : "⚠️ *Approved — execution failed* {$note}");
            } else {
                nm_aip_deny_action($conn, $aid, null, "Denied {$note}.");
                $conn->query("UPDATE nm_aip_tg_approvals SET status='denied', decided_at=NOW() WHERE action_id=$aid");
                nm_aip_tg_api($tg['token'], 'answerCallbackQuery', ['callback_query_id'=>$cbId, 'text'=>'🚫 Denied — manual control.']);
                nm_aip_tg_edit_decided($conn, $tg['token'], $chatId, $msgId, $aid, "🚫 *Denied* {$note}");
            }
        }

        if ($maxId > $offset) {
            $mv = (string)$maxId;
            $st = $conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES ('aip_tg_offset',?)
                                  ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
            $st->bind_param('s', $mv); $st->execute(); $st->close();
        }
        return ['ok'=>true,'processed'=>$processed,'updates'=>count($updates)];
    }

    // Opportunistic, self-throttled, single-flight Telegram drain — called from the aiopilot feed
    // so a Telegram Approve/Deny reflects in the portal within seconds (closing the race where a
    // card lingers "proposed" until the 1-min cron runs and another operator could act on it).
    //   • Only polls when there is ≥1 OUTSTANDING telegram approval (else it's a no-op — no wasted
    //     Telegram calls once everything is decided).
    //   • Throttled by nm_settings 'aip_tg_poll_at' so many open browsers don't hammer Telegram.
    //   • Serialized with GET_LOCK so concurrent requests never double-consume getUpdates (which
    //     would skip/duplicate updates via the shared offset).
    function nm_aip_tg_poll_feed($conn, int $minGapSec = 4): array {
        nm_aip_ensure($conn);
        // cheap guard: anything pending at all? (check BOTH v1 aiopilot AND v2 Commander approval queues —
        // nm_aip_tg_poll drains both via its aip:/ap2: branches, so fire the fast drain for either)
        $p = $conn->query("SELECT 1 FROM nm_aip_tg_approvals WHERE status='pending' LIMIT 1");
        $hasV1 = $p && $p->num_rows;
        $hasV2 = false; try { $p2 = $conn->query("SELECT 1 FROM nm_ap2_tg_approvals WHERE status='pending' LIMIT 1"); $hasV2 = $p2 && $p2->num_rows; } catch (\Throwable $e) {}
        if (!$hasV1 && !$hasV2) return ['ok'=>true,'skipped'=>'none pending'];

        $now = time();
        $atR = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='aip_tg_poll_at' LIMIT 1");
        $at  = ($atR && $atR->num_rows) ? (int)$atR->fetch_assoc()['setting_val'] : 0;
        if ($now - $at < max(1, $minGapSec)) return ['ok'=>true,'skipped'=>'throttled'];

        // single-flight: only one request polls at a time; others move on instantly.
        $lk = $conn->query("SELECT GET_LOCK('nm_aip_tg_poll', 0) g");
        $got = $lk ? (int)$lk->fetch_assoc()['g'] : 0;
        if ($got !== 1) return ['ok'=>true,'skipped'=>'locked'];
        try {
            $nowS = (string)$now;
            $st = $conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES ('aip_tg_poll_at',?)
                                  ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
            $st->bind_param('s', $nowS); $st->execute(); $st->close();
            $res = nm_aip_tg_poll($conn, 0);   // non-blocking (timeout=0)
        } finally {
            $conn->query("SELECT RELEASE_LOCK('nm_aip_tg_poll')");
        }
        return $res;
    }

    // Edit the original approval message to show the resolved decision (buttons removed).
    function nm_aip_tg_edit_decided($conn, string $token, string $chatId, int $msgId, int $aid, string $verdictLine): void {
        if ($msgId <= 0 || $chatId === '') return;
        // append the verdict under the original text; strip buttons.
        nm_aip_tg_api($token, 'editMessageReplyMarkup', ['chat_id'=>$chatId, 'message_id'=>$msgId, 'reply_markup'=>['inline_keyboard'=>[]]]);
        $a = $conn->query("SELECT a.tool, n.display_name FROM nm_aip_actions a JOIN nm_nodes n ON n.id=a.node_id WHERE a.id=$aid LIMIT 1");
        $a = $a ? $a->fetch_assoc() : null;
        $head = $a ? ("🤖 " . nm_aip_tg_esc($a['display_name']) . " · " . nm_aip_tg_esc($a['tool'])) : "🤖 NetAIObot action";
        nm_aip_tg_api($token, 'editMessageText', [
            'chat_id'=>$chatId, 'message_id'=>$msgId, 'parse_mode'=>'Markdown',
            'text'=>$head . "\n\n" . $verdictLine]);
    }

    // ── The hands: map an action tool to a vetted primitive ────────────────────
    function nm_aip_do($conn, int $node_id, string $tool, array $args): array {
        $node = $conn->query("SELECT id,display_name,ip_address,os_icon,ssh_cred_id FROM nm_nodes WHERE id=" . (int)$node_id . " LIMIT 1");
        $node = $node ? $node->fetch_assoc() : null;
        if (!$node) return ['ok'=>false,'error'=>'unknown node'];

        switch ($tool) {
            case 'block_ip':
                if (!function_exists('nm_imm_add_threat') && is_file(__DIR__ . '/nm_immunity.php')) require_once __DIR__ . '/nm_immunity.php';
                if (!function_exists('nm_imm_add_threat')) return ['ok'=>false,'error'=>'Immunity module unavailable'];
                $ip = preg_replace('/[^0-9a-fA-F:.]/', '', (string)($args['ip'] ?? ''));
                if ($ip === '') return ['ok'=>false,'error'=>'bad ip'];
                $t = nm_imm_add_threat($conn, $ip, 'ip', 'aiopilot', 'high', (string)($args['reason'] ?? 'NetAIObot auto-block'));
                if (!empty($t['ok']) && !empty($t['id']) && function_exists('nm_imm_vaccinate')) {
                    $v = nm_imm_vaccinate($conn, (int)$t['id']);
                    return ['ok'=>true,'data'=>['blocked'=>$ip,'vaccinate'=>$v]];
                }
                return ['ok'=>!empty($t['ok']),'data'=>$t];

            case 'ssh_command':
            case 'restart_service':
            case 'flush_dns':
            case 'clear_logs_rotate':
                // Defense-in-depth: re-validate device type at execution time (never SSH a
                // ping-only / SNMP-only device even if something slipped past the proposer).
                $cap = nm_aip_capabilities($conn, $node);
                if (!$cap['can_ssh']) return ['ok'=>false,'error'=>"refused: {$node['display_name']} is a {$cap['kind']} device, not SSH-capable"];
                // Build the concrete shell command, then run it over SSH via the proven primitive.
                $cmd = nm_aip_build_cmd($tool, $args, $node);
                if ($cmd === null) return ['ok'=>false,'error'=>'could not build command'];
                return nm_aip_ssh($conn, $node, $cmd);
        }
        return ['ok'=>false,'error'=>"unknown action tool: $tool"];
    }

    function nm_aip_build_cmd(string $tool, array $args, array $node): ?string {
        $isWin = ($node['os_icon'] ?? '') === 'windows';
        switch ($tool) {
            case 'ssh_command':
                $c = trim((string)($args['command'] ?? ''));
                return $c === '' ? null : $c;
            case 'restart_service':
                $svc = preg_replace('/[^A-Za-z0-9._@-]/', '', (string)($args['service'] ?? ''));
                if ($svc === '') return null;
                if ($isWin)
                    // PRE-FLIGHT: only restart if it's a REAL service; else list real ones (don't run a doomed cmd).
                    return 'if (Get-Service -Name \'' . $svc . '\' -ErrorAction SilentlyContinue) { '
                         . 'Restart-Service -Name \'' . $svc . '\' -Force; Write-Output "restarted ' . $svc . '" } '
                         . 'else { Write-Output "NO SUCH SERVICE ' . $svc . ' - use the service short name from Get-Service, NOT a process/Task-Manager name. Services:"; '
                         . '(Get-Service | Select-Object -First 40 -ExpandProperty Name) -join ", " }';
                // Linux PRE-FLIGHT: confirm the systemd unit exists FIRST. If not (e.g. the AI passed a
                // ps/top thread name like "MainThread"), DON'T attempt the restart — return the real
                // running-service list so the AI self-corrects. This blocks doomed/wrong commands.
                return 'if systemctl cat ' . $svc . ' >/dev/null 2>&1 || systemctl list-unit-files --no-legend \'' . $svc . '.service\' 2>/dev/null | grep -q .; then '
                     . 'sudo systemctl restart ' . $svc . ' 2>&1; '
                     . 'if systemctl is-active --quiet ' . $svc . '; then echo "' . $svc . ' restarted and active"; else echo "' . $svc . ' FAILED to start after restart"; exit 1; fi; '
                     . 'else echo "NO SUCH SERVICE ' . $svc . ' - that is likely a process/thread name (e.g. MainThread), NOT a systemd unit. Real running services:"; '
                     . 'systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk \'{print $1}\' | head -40; exit 1; fi';
            case 'flush_dns':
                if ($isWin) return "Clear-DnsClientCache";
                if (($node['os_icon'] ?? '') === 'mikrotik') return "/ip dns cache flush";
                // Linux: NOT every host runs systemd-resolved. Detect the actual resolver and use
                // the right command, with fallbacks; if the host caches nothing, report a BENIGN
                // success (no local cache to flush is not a failure). Always exits 0 + prints a line.
                return 'if systemctl is-active --quiet systemd-resolved 2>/dev/null; then '
                     . '(sudo resolvectl flush-caches 2>/dev/null || sudo systemd-resolve --flush-caches 2>/dev/null); echo "flushed: systemd-resolved"; '
                     . 'elif command -v nscd >/dev/null 2>&1; then sudo nscd -i hosts 2>/dev/null; echo "flushed: nscd"; '
                     . 'elif systemctl is-active --quiet dnsmasq 2>/dev/null; then sudo systemctl restart dnsmasq 2>/dev/null; echo "flushed: dnsmasq restarted"; '
                     . 'elif systemctl is-active --quiet named 2>/dev/null || systemctl is-active --quiet bind9 2>/dev/null; then sudo rndc flush 2>/dev/null; echo "flushed: bind/named"; '
                     . 'else echo "no local DNS cache to flush (host does not cache DNS) - OK"; fi';
            case 'clear_logs_rotate':
                $path = preg_replace('/[^A-Za-z0-9._\/-]/', '', (string)($args['path'] ?? '/var/log'));
                if ($path === '') $path = '/var/log';
                // truncate oversized *.log files, then ALWAYS print a summary line (so "nothing to
                // rotate" reads as success, not an empty-output SSH error). Also vacuum journald.
                // Single-quoted PHP strings keep the shell $c literal (no PHP interpolation).
                return 'c=$(sudo find ' . $path . ' -type f -name \'*.log\' -size +200M 2>/dev/null | wc -l); '
                     . 'sudo find ' . $path . ' -type f -name \'*.log\' -size +200M -exec truncate -s 0 {} + 2>/dev/null; '
                     . 'sudo journalctl --vacuum-size=200M 2>/dev/null | tail -1; '
                     . 'echo "rotated $c oversized log file(s) in ' . $path . '"';
        }
        return null;
    }

    // Resolve creds + run one command over SSH (reuses nm_cm_ssh_fetch / resolvers).
    function nm_aip_ssh($conn, array $node, string $cmd): array {
        require_once __DIR__ . '/nm_confmgr.php';
        require_once __DIR__ . '/nm_secrets.php';
        $ssh = null;
        if (function_exists('nm_ssh_resolve') && !empty($node['id'])) $ssh = nm_ssh_resolve($conn, (int)$node['id']);
        if ((!$ssh || empty($ssh['username'])) && function_exists('nm_ssh_resolve_host') && !empty($node['ip_address'])) $ssh = nm_ssh_resolve_host($conn, (string)$node['ip_address']);
        if ((!$ssh || empty($ssh['username'])) && function_exists('nm_ssh_default')) $ssh = nm_ssh_default($conn, (string)($node['ip_address'] ?? ''));
        if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'no SSH credential resolved for this device'];
        $isWin = ($node['os_icon'] ?? '') === 'windows';
        $run = $isWin ? ('powershell -NoProfile -NonInteractive -Command "' . str_replace('"', '\"', $cmd) . '"') : $cmd;
        $r = nm_cm_ssh_fetch($ssh, $run, 40);
        if (empty($r['ok'])) {
            $e = (string)($r['error'] ?? '');
            // A command that ran fine but printed nothing (e.g. nothing to truncate) is NOT a
            // failure — nm_cm_ssh_fetch flags empty stdout as 'empty config returned'. Treat it
            // as benign success so zero-output actions don't read as SSH errors.
            if ($e === '' || stripos($e, 'empty config') !== false)
                return ['ok'=>true,'data'=>'(command completed — no output)'];
            return ['ok'=>false,'error'=>'SSH failed: ' . substr($e, 0, 180)];
        }
        return ['ok'=>true,'data'=>substr((string)$r['config'], 0, 4000)];
    }
}
