<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Remote Agent backend (neuru-agent).
//
// A lightweight container on a remote Linux box PUSHES telemetry to NEURU over
// outbound HTTPS (firewall/NAT/CGNAT-friendly — NEURU never connects INTO the box).
// The agent authenticates with a shared enrollment token, auto-registers by a stable
// agent UID, and POSTs the SAME health JSON shape the SSH Linux Monitor produces →
// the data lands in the EXISTING tables (nm_nodes + nm_lx_hosts source='agent' +
// nm_lx_health + a ping_stats heartbeat) so it renders in linux.php / net_mon with
// ZERO new UI. Stateless (no persistent socket) → scales to thousands of agents like
// the cron endpoints do. Remote actions ride back on each POST's response (command
// queue), so no WebSocket is needed.
//
//   nm_agent_ensure($conn)                         — settings/columns (guarded)
//   nm_agent_token($conn) / nm_agent_token_rotate  — the shared enrollment token
//   nm_agent_verify($conn, $presented)             — constant-time token check
//   nm_agent_register($conn, $uid, $host, $meta)   — upsert node+lx_host → [node_id, host_id]
//   nm_agent_ingest($conn, $host_id, $node_id, $health, $containers) — store telemetry
//   nm_agent_list($conn)                           — registered agents (for the UI)
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_agent_ensure')) {

    require_once __DIR__ . '/nm_audit.php';

    function nm_agent_ensure($conn): void {
        try {
            // Per-agent identity: reuse nm_lx_hosts (source='agent') + add an agent_uid column so a
            // re-registering container maps back to the SAME host (idempotent enrolment).
            $have = [];
            $r = $conn->query("SELECT COLUMN_NAME FROM information_schema.COLUMNS
                               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_lx_hosts' AND COLUMN_NAME IN ('agent_uid','agent_version','agent_last_seen')");
            while ($r && $x = $r->fetch_assoc()) $have[$x['COLUMN_NAME']] = 1;
            $add = [];
            if (!isset($have['agent_uid']))       $add[] = "ADD COLUMN agent_uid VARCHAR(64) NULL";
            if (!isset($have['agent_version']))   $add[] = "ADD COLUMN agent_version VARCHAR(32) NULL";
            if (!isset($have['agent_last_seen'])) $add[] = "ADD COLUMN agent_last_seen DATETIME NULL";
            if ($add) {
                try { $conn->query("ALTER TABLE nm_lx_hosts " . implode(', ', $add)); } catch (\Throwable $e) {}
                try { $conn->query("CREATE INDEX idx_lx_agent_uid ON nm_lx_hosts (agent_uid)"); } catch (\Throwable $e) {}
            }
        } catch (\Throwable $e) { /* nm_lx_hosts is created by nm_linuxhost.php's nm_lx_ensure() */ }
    }

    // Self-hosted NEURU almost always runs a self-signed cert on an IP:port (nm_https_setup.sh).
    // An agent verifying TLS would reject it → we auto-set NEURU_VERIFY_TLS=0 for those endpoints.
    function nm_agent_selfsigned_likely(string $scheme, string $host): bool {
        if (strtolower($scheme) !== 'https') return false;   // http → no TLS to verify
        $h = preg_replace('/:\d+$/', '', trim($host));       // strip :port
        $h = trim($h, '[]');                                 // strip IPv6 brackets
        if ($h === 'localhost' || substr($h, -6) === '.local') return true;
        if (preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $h)) return true;   // IPv4 literal
        if (strpos($h, ':') !== false) return true;                     // IPv6 literal
        return false;   // a real domain → assume a valid cert, keep verification on
    }

    // ── Shared enrolment token (stored in nm_settings; rotate = revoke all agents) ──
    function nm_agent_token($conn): string {
        try {
            $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='agent_token' LIMIT 1");
            if ($r && ($x = $r->fetch_assoc())) return (string)$x['setting_val'];
        } catch (\Throwable $e) {}
        return '';
    }
    function nm_agent_token_rotate($conn): string {
        $tok = 'neu_agt_' . bin2hex(random_bytes(24));
        try {
            $st = $conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES('agent_token',?)
                                  ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
            $st->bind_param('s', $tok); $st->execute(); $st->close();
        } catch (\Throwable $e) { return ''; }
        if (function_exists('nm_audit')) { try { nm_audit($conn, 'agent.token.rotate', ['target_type'=>'agent']); } catch (\Throwable $e) {} }
        return $tok;
    }
    function nm_agent_verify($conn, ?string $presented): bool {
        $presented = (string)$presented;
        if ($presented === '') return false;
        $stored = nm_agent_token($conn);
        if ($stored === '') return false;
        return hash_equals($stored, $presented);
    }

    // ── Register / upsert an agent host (idempotent by agent_uid) → [node_id, host_id] ──
    function nm_agent_register($conn, string $uid, string $hostname, array $meta = []): array {
        if (function_exists('nm_lx_ensure')) nm_lx_ensure($conn);
        nm_agent_ensure($conn);
        $uid  = substr(preg_replace('/[^A-Za-z0-9._:-]/', '', $uid), 0, 64);
        $name = substr(trim($hostname !== '' ? $hostname : ($uid ?: 'agent')), 0, 120);
        $ip   = substr(preg_replace('/[^0-9a-fA-F.:]/', '', (string)($meta['ip'] ?? '')), 0, 64) ?: null;
        $ver  = substr((string)($meta['agent_version'] ?? ''), 0, 32);
        if ($uid === '') return ['ok'=>false, 'error'=>'missing agent uid'];

        // Existing agent host?
        $hid = 0; $nodeId = 0;
        try {
            $st = $conn->prepare("SELECT id, node_id FROM nm_lx_hosts WHERE agent_uid=? LIMIT 1");
            $st->bind_param('s', $uid); $st->execute();
            if ($row = $st->get_result()->fetch_assoc()) { $hid = (int)$row['id']; $nodeId = (int)$row['node_id']; }
            $st->close();
        } catch (\Throwable $e) {}

        // Ensure a backing nm_nodes row (monitor_type='agent' → the pollers SKIP it; it self-reports).
        if (!$nodeId) {
            try {
                if ($ip) {   // reuse an existing node with the same management IP if the operator already added it
                    $q = $conn->prepare("SELECT id FROM nm_nodes WHERE ip_address=? LIMIT 1");
                    $q->bind_param('s', $ip); $q->execute();
                    if ($nr = $q->get_result()->fetch_assoc()) $nodeId = (int)$nr['id'];
                    $q->close();
                }
            } catch (\Throwable $e) {}
        }
        if (!$nodeId) {
            try {
                $os = 'linux';
                $st = $conn->prepare("INSERT INTO nm_nodes (display_name, ip_address, monitor_type, os_icon) VALUES (?,?, 'agent', ?)");
                $st->bind_param('sss', $name, $ip, $os); $st->execute(); $nodeId = (int)$conn->insert_id; $st->close();
            } catch (\Throwable $e) { /* fall through — host can exist without a node */ }
        } else {
            // make sure the node is flagged agent-managed so the SNMP/ping pollers don't touch it
            try { $conn->query("UPDATE nm_nodes SET monitor_type='agent' WHERE id=".(int)$nodeId." AND COALESCE(monitor_type,'')<>'agent'"); } catch (\Throwable $e) {}
        }

        // ADOPTION (universal, prevents duplicate cards for ANY user/topology): attach this registration
        // to an EXISTING Linux-Monitor card for the same box instead of creating a twin. Priority:
        //   (1) a card the operator pre-designated as "NEURU Agent" (source='agent', not yet claimed);
        //   (2) the SINGLE existing card for this node → upgrade it to Agent, and if it was SSH keep
        //       pulling journal events (hybrid) so nothing is lost.
        // Only when the box has NO card at all do we create a fresh one (below).
        if (!$hid && $nodeId) {
            try {
                $st = $conn->prepare("SELECT id FROM nm_lx_hosts WHERE node_id=? AND source='agent' AND (agent_uid IS NULL OR agent_uid='') ORDER BY id LIMIT 1");
                $st->bind_param('i', $nodeId); $st->execute();
                if ($row = $st->get_result()->fetch_assoc()) {
                    $hid = (int)$row['id'];
                    $c2 = $conn->prepare("UPDATE nm_lx_hosts SET agent_uid=? WHERE id=?"); $c2->bind_param('si', $uid, $hid); $c2->execute(); $c2->close();
                }
                $st->close();
            } catch (\Throwable $e) {}
            if (!$hid) {   // (2) exactly one existing card for this node → adopt + hybrid-preserve events
                try {
                    $cr = $conn->query("SELECT COUNT(*) c FROM nm_lx_hosts WHERE node_id=".(int)$nodeId);
                    if ($cr && (int)$cr->fetch_assoc()['c'] === 1) {
                        $ex = $conn->query("SELECT id, source FROM nm_lx_hosts WHERE node_id=".(int)$nodeId." LIMIT 1")->fetch_assoc();
                        $hid = (int)$ex['id'];
                        $keepEvents = (($ex['source'] ?? '') === 'ssh') ? 1 : 0;   // SSH host → keep journal events as hybrid
                        $c2 = $conn->prepare("UPDATE nm_lx_hosts SET source='agent', agent_uid=?, agent_ssh_events=GREATEST(agent_ssh_events, ?) WHERE id=?");
                        $c2->bind_param('sii', $uid, $keepEvents, $hid); $c2->execute(); $c2->close();
                    }
                } catch (\Throwable $e) {}
            }
        }

        $now = gmdate('Y-m-d H:i:s');
        if ($hid) {
            // RE-REGISTER of an EXISTING card: touch ONLY agent bookkeeping. NEVER overwrite name/source/
            // node — those are the operator's to control (else an agent restart would undo a rename or a
            // switch back to SSH/Grafana). The card's `source` is the single source of truth for how NEURU
            // collects; a dormant agent (source≠'agent') simply gets ignored at ingest.
            try {
                if ($ver !== '') {
                    $st = $conn->prepare("UPDATE nm_lx_hosts SET agent_version=?, agent_last_seen=? WHERE id=?");
                    $st->bind_param('ssi', $ver, $now, $hid);
                } else {
                    $st = $conn->prepare("UPDATE nm_lx_hosts SET agent_last_seen=? WHERE id=?");
                    $st->bind_param('si', $now, $hid);
                }
                $st->execute(); $st->close();
            } catch (\Throwable $e) {}
        } else {
            try {
                //          name  node_id  host_ip  agent_uid  agent_version  agent_last_seen
                //          s     i        s        s          s              s
                // created_by is an INT user id → left NULL for agent-created hosts.
                $st = $conn->prepare("INSERT INTO nm_lx_hosts (name, node_id, host_ip, source, enabled, agent_uid, agent_version, agent_last_seen)
                                      VALUES (?,?,?, 'agent', 1, ?, ?, ?)");
                $st->bind_param('sissss', $name, $nodeId, $ip, $uid, $ver, $now);
                $st->execute(); $st->close();
            } catch (\Throwable $e) {}
        }

        // Re-read the host id (covers the fresh insert)
        if (!$hid) {
            try {
                $st = $conn->prepare("SELECT id FROM nm_lx_hosts WHERE agent_uid=? LIMIT 1");
                $st->bind_param('s', $uid); $st->execute();
                if ($row = $st->get_result()->fetch_assoc()) $hid = (int)$row['id'];
                $st->close();
            } catch (\Throwable $e) {}
        }
        if (!$hid) return ['ok'=>false, 'error'=>'could not register host'];
        if (function_exists('nm_audit')) { try { nm_audit($conn, 'agent.register', ['target_type'=>'agent','target_id'=>$hid,'details'=>['uid'=>$uid,'host'=>$name]]); } catch (\Throwable $e) {} }
        return ['ok'=>true, 'host_id'=>$hid, 'node_id'=>$nodeId, 'name'=>$name];
    }

    // ── Lean lookup by uid (ingest hot-path) → [host_id, node_id, source] or null ──
    // Match by uid ALONE (not source) so a running agent always maps to ITS card and never spawns a
    // duplicate — even when the operator has (temporarily) set the card to SSH/Grafana. The `source`
    // it returns lets ingest decide whether to actually store (dormant when source≠'agent').
    function nm_agent_resolve($conn, string $uid): ?array {
        $uid = substr(preg_replace('/[^A-Za-z0-9._:-]/', '', $uid), 0, 64);
        if ($uid === '') return null;
        try {
            $st = $conn->prepare("SELECT id, node_id, source FROM nm_lx_hosts WHERE agent_uid=? LIMIT 1");
            $st->bind_param('s', $uid); $st->execute();
            $row = $st->get_result()->fetch_assoc(); $st->close();
            if ($row) return ['host_id'=>(int)$row['id'], 'node_id'=>(int)$row['node_id'], 'source'=>(string)$row['source']];
        } catch (\Throwable $e) {}
        return null;
    }

    // ── Store a telemetry batch: health JSON (nm_lx_health) + heartbeat (nm_ping_stats) ──
    // Bridge the agent's per-interface traffic (net_ifaces: KB/s rx/tx) into nm_port_stats — the SAME
    // table SNMP + Grafana Alloy write to — so agent nodes show INTERFACE TRAFFIC uniformly (net_mon_stats,
    // traffic viewer, cards). AGENT-ONLY: SSH/Alloy nodes already have their own port_stats writer, so this
    // is NEVER called for them (no double-write). Reuses the existing nm_interfaces port_id when the name
    // already exists (e.g. enp0s31f6 → its port). in_rate/out_rate are BYTES/s → rx(KB/s)×1024. Best-effort.
    function nm_agent_bridge_ifaces($conn, int $node_id, array $h): void {
        if ($node_id <= 0 || empty($h['net_ifaces']) || !is_array($h['net_ifaces'])) return;
        try {
            $now = gmdate('Y-m-d H:i:s');
            $sel = $conn->prepare("SELECT id FROM nm_interfaces WHERE node_id=? AND if_name=? LIMIT 1");
            $ins = $conn->prepare("INSERT INTO nm_interfaces (node_id, if_name, display_name, show_graph) VALUES (?,?,?,1)");
            $ps  = $conn->prepare("INSERT INTO nm_port_stats (node_id, port_id, recorded_at, in_rate, out_rate, oper_status) VALUES (?,?,?,?,?,'up')");
            if (!$sel || !$ps) return;
            foreach ($h['net_ifaces'] as $if) {
                if (!is_array($if) || empty($if['name'])) continue;
                $name = substr((string)$if['name'], 0, 190);
                $inB  = (float)($if['rx'] ?? 0) * 1024.0;   // agent KB/s → nm_port_stats bytes/s
                $outB = (float)($if['tx'] ?? 0) * 1024.0;
                $sel->bind_param('is', $node_id, $name); $sel->execute(); $row = $sel->get_result()->fetch_row();
                if ($row) { $pid = (int)$row[0]; }
                elseif ($ins) { $ins->bind_param('iss', $node_id, $name, $name); try { $ins->execute(); } catch (\Throwable $e) { continue; } $pid = (int)$ins->insert_id; }
                else { continue; }
                if ($pid <= 0) continue;
                $ps->bind_param('iisdd', $node_id, $pid, $now, $inB, $outB); $ps->execute();
            }
            $sel->close(); if ($ins) $ins->close(); $ps->close();
        } catch (\Throwable $e) {}
    }
    function nm_agent_ingest($conn, int $host_id, int $node_id, array $health, array $containers = []): array {
        if (function_exists('nm_lx_ensure')) nm_lx_ensure($conn);
        // Respect the operator's choice: if this card is NOT set to 'agent' (they switched it to SSH/
        // Grafana), the agent is DORMANT — accept the POST but store nothing, so the chosen source owns
        // the card. Flipping it back to Agent resumes instantly (no re-deploy needed).
        try {
            $sr = $conn->query("SELECT source FROM nm_lx_hosts WHERE id=".(int)$host_id." LIMIT 1");
            if ($sr && ($sx = $sr->fetch_assoc()) && ($sx['source'] ?? '') !== 'agent')
                return ['ok'=>true, 'dormant'=>true, 'reason'=>'card source is '.($sx['source'] ?? '?')];
        } catch (\Throwable $e) {}
        $now = gmdate('Y-m-d H:i:s');
        // Attach container stats (a section the SSH path doesn't have — the UI can grow into it).
        if ($containers) $health['containers'] = array_slice($containers, 0, 200);
        $health['_src'] = 'agent';
        try {
            $je = json_encode($health);
            $st = $conn->prepare("INSERT INTO nm_lx_health (host_id, data, sampled_at) VALUES (?,?,?)
                                  ON DUPLICATE KEY UPDATE data=VALUES(data), sampled_at=VALUES(sampled_at)");
            $st->bind_param('iss', $host_id, $je, $now); $st->execute(); $st->close();
        } catch (\Throwable $e) { return ['ok'=>false, 'error'=>'health store failed']; }

        // Host bookkeeping + os caption
        try {
            $os = substr((string)($health['os'] ?? ($health['host'] ?? '')), 0, 160);
            if ($os !== '') { $st = $conn->prepare("UPDATE nm_lx_hosts SET os_caption=?, last_health_poll=?, agent_last_seen=?, status='ok', last_error=NULL WHERE id=?");
                              $st->bind_param('sssi', $os, $now, $now, $host_id); $st->execute(); $st->close(); }
            else            { $conn->query("UPDATE nm_lx_hosts SET last_health_poll='$now', agent_last_seen='$now', status='ok' WHERE id=".(int)$host_id); }
        } catch (\Throwable $e) {}

        // Heartbeat: the POST itself proves the box is UP → a ping sample keeps net_mon + SLA + the
        // down-detection honest (no reply for N intervals → the engine flags it down). Latency-equiv =
        // the agent-side RTT if it sent one, else null.
        if ($node_id > 0) {
            try {
                $lat = isset($health['agent_rtt_ms']) ? (float)$health['agent_rtt_ms'] : null;
                $st = $conn->prepare("INSERT INTO nm_ping_stats (node_id, recorded_at, is_up, latency_ms, packet_loss) VALUES (?,?,1,?,0)");
                $st->bind_param('isd', $node_id, $now, $lat); $st->execute(); $st->close();
            } catch (\Throwable $e) {}
        }
        // uniform metrics: bridge the agent health into nm_device_stats so agent nodes show CPU / Memory /
        // storage / uptime EVERYWHERE (server cards, dashboard, stats) — the same table SNMP writes to.
        if ($node_id > 0 && function_exists('nm_lx_bridge_device_stats')) nm_lx_bridge_device_stats($conn, $node_id, $health);
        if ($node_id > 0) nm_agent_bridge_ifaces($conn, $node_id, $health);   // interface traffic → nm_port_stats
        return ['ok'=>true, 'stored'=>true];
    }

    // ── Command channel (Phase 3) ────────────────────────────────────────────
    // NEURU never connects INTO an agent box; instead it QUEUES a command and the
    // agent drains it on its next ingest POST's response. A queued command lives in
    // nm_agent_cmds until the agent acknowledges it (status: queued → sent → done/failed).
    function nm_agent_cmds_ensure($conn): void {
        try {
            $conn->query("CREATE TABLE IF NOT EXISTS nm_agent_cmds (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                host_id INT NOT NULL,
                cmd VARCHAR(40) NOT NULL,
                args MEDIUMTEXT NULL,
                status VARCHAR(12) NOT NULL DEFAULT 'queued',
                result MEDIUMTEXT NULL,
                created_by INT NULL,
                created_at DATETIME NOT NULL,
                sent_at DATETIME NULL,
                done_at DATETIME NULL,
                KEY idx_host_status (host_id, status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        } catch (\Throwable $e) {}
    }
    // Queue a command for a host (returns command id or 0).
    function nm_agent_enqueue($conn, int $host_id, string $cmd, array $args = [], ?int $by = null): int {
        nm_agent_cmds_ensure($conn);
        $cmd = substr(preg_replace('/[^a-z0-9_.-]/', '', strtolower($cmd)), 0, 40);
        if ($cmd === '' || $host_id <= 0) return 0;
        $now = gmdate('Y-m-d H:i:s'); $ja = json_encode($args);
        try {
            $st = $conn->prepare("INSERT INTO nm_agent_cmds (host_id, cmd, args, status, created_by, created_at) VALUES (?,?,?, 'queued', ?, ?)");
            $st->bind_param('issis', $host_id, $cmd, $ja, $by, $now); $st->execute();
            $id = (int)$conn->insert_id; $st->close();
            if (function_exists('nm_audit')) { try { nm_audit($conn, 'agent.cmd.enqueue', ['target_type'=>'agent','target_id'=>$host_id,'details'=>['cmd'=>$cmd]]); } catch (\Throwable $e) {} }
            return $id;
        } catch (\Throwable $e) { return 0; }
    }
    // Drain queued commands for a host (called on ingest); marks them 'sent'.
    function nm_agent_take_commands($conn, int $host_id): array {
        nm_agent_cmds_ensure($conn);
        $out = [];
        try {
            $r = $conn->query("SELECT id, cmd, args FROM nm_agent_cmds WHERE host_id=".(int)$host_id." AND status='queued' ORDER BY id LIMIT 20");
            while ($r && $x = $r->fetch_assoc()) $out[] = ['id'=>(int)$x['id'], 'cmd'=>$x['cmd'], 'args'=>json_decode((string)$x['args'], true) ?: []];
            if ($out) {
                $ids = implode(',', array_map(fn($c)=>(int)$c['id'], $out));
                $conn->query("UPDATE nm_agent_cmds SET status='sent', sent_at=UTC_TIMESTAMP() WHERE id IN ($ids)");
            }
        } catch (\Throwable $e) {}
        return $out;
    }
    // Record an agent's ack/result for previously-sent commands.
    function nm_agent_ack($conn, array $acks): void {
        if (!$acks) return;
        nm_agent_cmds_ensure($conn);
        foreach ($acks as $a) {
            $id = (int)($a['id'] ?? 0); if ($id <= 0) continue;
            $ok = !empty($a['ok']); $res = substr((string)($a['result'] ?? ''), 0, 4000);
            try {
                $st = $conn->prepare("UPDATE nm_agent_cmds SET status=?, result=?, done_at=UTC_TIMESTAMP() WHERE id=?");
                $status = $ok ? 'done' : 'failed';
                $st->bind_param('ssi', $status, $res, $id); $st->execute(); $st->close();
            } catch (\Throwable $e) {}
        }
    }

    function nm_agent_list($conn): array {
        nm_agent_ensure($conn);
        $out = [];
        try {
            // IP: prefer the host's own host_ip, else fall back to the linked node's IP (agent cards
            // adopted from a pre-existing node often have an empty host_ip but the node carries the IP).
            $r = $conn->query("SELECT h.id, h.name,
                               COALESCE(NULLIF(h.host_ip,''), n.ip_address) host_ip, h.node_id,
                               h.agent_uid, h.agent_version, h.agent_last_seen,
                               TIMESTAMPDIFF(SECOND, h.agent_last_seen, UTC_TIMESTAMP()) age, h.status
                               FROM nm_lx_hosts h LEFT JOIN nm_nodes n ON n.id=h.node_id
                               WHERE h.source='agent' ORDER BY h.agent_last_seen DESC");
            while ($r && $x = $r->fetch_assoc()) $out[] = $x;
        } catch (\Throwable $e) {}
        return $out;
    }
}
