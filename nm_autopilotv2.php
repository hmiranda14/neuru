<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — AI Commander V2.0 ENGINE (autopilotv2).  PARALLEL to the frozen v1
// (nm_aiopilot.php) — separate tables (nm_ap2_*), separate n8n slug (autopilot-v2).
// This file is the SIGNAL BUS + rules/dedup + fleet cache foundation (P1). Sessions,
// dispatch and the risk gate build on top. Plan: docs/AUTOPILOT_V2_PLAN.md.
// ─────────────────────────────────────────────────────────────────────────────
// Reuse the FROZEN v1's proven, read-only safety + executor + context helpers
// (nm_aip_capabilities/validate_action/can_auto/gather_context/do/ssh/build_cmd) — we
// never modify v1, we only CALL its pure functions and keep our own bookkeeping in nm_ap2_*.
require_once __DIR__ . '/nm_n8n.php';
if (is_file(__DIR__ . '/nm_portainer.php')) require_once __DIR__ . '/nm_portainer.php';
if (is_file(__DIR__ . '/nm_aiopilot.php'))  require_once __DIR__ . '/nm_aiopilot.php';

if (!function_exists('nm_ap2_ensure')) {

// ── schema ───────────────────────────────────────────────────────────────────
function nm_ap2_ensure($conn): void {
    if (!($conn instanceof mysqli)) return;
    $t = [
    "CREATE TABLE IF NOT EXISTS nm_ap2_channels (
        channel_key VARCHAR(40) PRIMARY KEY,
        enabled TINYINT(1) NOT NULL DEFAULT 1,
        min_severity VARCHAR(12) NOT NULL DEFAULT 'warning',
        act_mode ENUM('aware','propose','auto') NOT NULL DEFAULT 'propose',
        config JSON NULL,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    "CREATE TABLE IF NOT EXISTS nm_ap2_signals (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        fingerprint CHAR(40) NOT NULL,
        channel VARCHAR(40) NOT NULL,
        sig_type VARCHAR(40) NOT NULL,
        target_kind ENUM('node','container','fleet') NOT NULL DEFAULT 'node',
        node_id INT NULL,
        container_id VARCHAR(64) NULL,
        name VARCHAR(191) NULL,
        severity VARCHAR(12) NOT NULL DEFAULT 'info',
        title VARCHAR(255) NULL,
        detail TEXT NULL,
        status ENUM('new','investigating','proposed','acted','resolved','ignored','stale') NOT NULL DEFAULT 'new',
        session_id BIGINT UNSIGNED NULL,
        seen_count INT NOT NULL DEFAULT 1,
        first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_fp_open (fingerprint, status),
        KEY idx_status (status), KEY idx_node (node_id), KEY idx_chan (channel)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    "CREATE TABLE IF NOT EXISTS nm_ap2_rules (
        id INT AUTO_INCREMENT PRIMARY KEY,
        match_type ENUM('fingerprint','channel_type','node','regex') NOT NULL DEFAULT 'channel_type',
        match_val VARCHAR(255) NOT NULL,
        policy ENUM('ignore','auto_ack','auto_fix','always_ask') NOT NULL DEFAULT 'ignore',
        note VARCHAR(255) NULL,
        created_by VARCHAR(60) NULL,
        active TINYINT(1) NOT NULL DEFAULT 1,
        hits INT NOT NULL DEFAULT 0,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    "CREATE TABLE IF NOT EXISTS nm_ap2_sessions (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        node_id INT NULL,
        signal_id BIGINT UNSIGNED NULL,
        status ENUM('queued','active','awaiting_approval','done','error','idle') NOT NULL DEFAULT 'queued',
        trigger_kind VARCHAR(40) NULL,
        autonomy ENUM('observe','copilot','autopilot') NOT NULL DEFAULT 'observe',
        summary VARCHAR(255) NULL,
        confidence TINYINT NULL,
        started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        KEY idx_status (status), KEY idx_node (node_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    "CREATE TABLE IF NOT EXISTS nm_ap2_events (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        session_id BIGINT UNSIGNED NULL,
        node_id INT NULL,
        phase ENUM('observe','think','tool','act','result','narrate','error') NOT NULL DEFAULT 'think',
        body TEXT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY idx_sess (session_id), KEY idx_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    "CREATE TABLE IF NOT EXISTS nm_ap2_actions (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        session_id BIGINT UNSIGNED NULL,
        signal_id BIGINT UNSIGNED NULL,
        node_id INT NULL,
        tool VARCHAR(40) NOT NULL,
        args VARCHAR(255) NULL,
        args_hash CHAR(32) NULL,
        risk ENUM('low','medium','high') NOT NULL DEFAULT 'low',
        status ENUM('proposed','approved','denied','done','failed','executing') NOT NULL DEFAULT 'proposed',
        auto TINYINT(1) NOT NULL DEFAULT 0,
        result TEXT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY idx_sess (session_id), KEY idx_dedup (node_id, tool, args_hash, status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    "CREATE TABLE IF NOT EXISTS nm_ap2_devices (
        node_id INT PRIMARY KEY,
        enabled TINYINT(1) NOT NULL DEFAULT 1,
        autonomy_mode ENUM('observe','copilot','autopilot') NOT NULL DEFAULT 'observe',
        allow_destructive TINYINT(1) NOT NULL DEFAULT 0,
        allow_commands TINYINT(1) NOT NULL DEFAULT 0,
        telegram_approve TINYINT(1) NOT NULL DEFAULT 0,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    "CREATE TABLE IF NOT EXISTS nm_ap2_fleet (
        node_id INT PRIMARY KEY,
        name VARCHAR(191) NULL, ip VARCHAR(64) NULL, kind VARCHAR(24) NULL,
        endpoint_id INT NULL, containers JSON NULL,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    "CREATE TABLE IF NOT EXISTS nm_ap2_chat (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        role ENUM('user','bot') NOT NULL,
        message TEXT NULL,
        command JSON NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    // every tool NEURU runs (chat/voice/session) → drives the futuristic live 'tool activity' cockpit panel
    "CREATE TABLE IF NOT EXISTS nm_ap2_tool_events (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        channel VARCHAR(16) NOT NULL DEFAULT 'live',
        tool VARCHAR(48) NOT NULL,
        args_json JSON NULL,
        ok TINYINT(1) NOT NULL DEFAULT 1,
        status VARCHAR(10) NOT NULL DEFAULT 'done',
        summary VARCHAR(255) NULL,
        data_json MEDIUMTEXT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        KEY idx_created (id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    // VOICE narration queue — ALERTS path only. A queue (not a live push) is what lets narration wait while the
    // operator is talking (no-interrupt) and be dropped if the alert already auto-resolved. See docs/AUTOPILOT_V2_VOICE_NARRATION_PLAN.md
    "CREATE TABLE IF NOT EXISTS nm_ap2_voice_queue (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        kind ENUM('investigate','found','clean','proposed') NOT NULL DEFAULT 'found',
        signal_id BIGINT UNSIGNED NULL,
        node_id INT NULL,
        text VARCHAR(300) NOT NULL,
        status ENUM('pending','speaking','spoken','dropped') NOT NULL DEFAULT 'pending',
        claimed_at TIMESTAMP NULL DEFAULT NULL,
        spoken_at TIMESTAMP NULL DEFAULT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_sig_kind (signal_id, kind),
        KEY idx_status (status, id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    ];
    foreach ($t as $sql) { try { $conn->query($sql); } catch (\Throwable $e) {} }
    // migrate existing installs: add the 'executing' state used by the execute-action single-flight CAS (guarded
    // so it only ALTERs once, per the repo rule — never blind ALTER).
    try { $r = $conn->query("SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_ap2_actions' AND COLUMN_NAME='status'");
          if ($r && ($ct=$r->fetch_row()) && strpos((string)$ct[0],'executing')===false)
              $conn->query("ALTER TABLE nm_ap2_actions MODIFY status ENUM('proposed','approved','denied','done','failed','executing') NOT NULL DEFAULT 'proposed'"); } catch (\Throwable $e) {}
    // index the column the SSE stream filters on every 1.5s (WHERE updated_at > NOW()-3min) — guarded add-once.
    try { $r = $conn->query("SELECT 1 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_ap2_sessions' AND INDEX_NAME='idx_updated' LIMIT 1");
          if ($r && !$r->num_rows) $conn->query("ALTER TABLE nm_ap2_sessions ADD INDEX idx_updated (updated_at)"); } catch (\Throwable $e) {}
    // migrate: the tool-activity 'running' state (spinner while a slow tool executes)
    try { $r = $conn->query("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_ap2_tool_events' AND COLUMN_NAME='status' LIMIT 1");
          if ($r && !$r->num_rows) $conn->query("ALTER TABLE nm_ap2_tool_events ADD COLUMN status VARCHAR(10) NOT NULL DEFAULT 'done', ADD COLUMN updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"); } catch (\Throwable $e) {}
    // seed the default channels (source → default behaviour). Idempotent.
    $seed = [
        ['nodes_down',      1, 'warning',  'propose'],  // nm_alert_state node down/degraded
        ['nodes_findings',  1, 'warning',  'propose'],  // nm_ai_insights critical/warning
        ['containers_inc',  1, 'warning',  'propose'],  // container_incidents
        ['containers_err',  0, 'warning',  'aware'],    // container_errors/logs (new in v2, opt-in)
        ['events_syslog',   0, 'critical', 'aware'],    // nm_syslog patterns
        ['events_threats',  1, 'warning',  'aware'],    // nm_threats (Immunity)
        ['predictive',      1, 'warning',  'aware'],    // nm_health_forecast
        ['events_iface',    0, 'warning',  'aware'],    // interface flaps
        ['heal',            1, 'warning',  'propose'],  // nm_heal_events proposed → propose heal_apply
        ['deception',       1, 'warning',  'propose'],  // nm_decoy honeypot hits → propose immunize the attacker
        ['incidents',       1, 'warning',  'propose'],  // nm_incidents correlated (latency/loss/config) not covered by another channel
    ];
    foreach ($seed as [$k, $en, $sev, $mode]) {
        try { $st = $conn->prepare("INSERT IGNORE INTO nm_ap2_channels (channel_key,enabled,min_severity,act_mode) VALUES (?,?,?,?)");
              $st->bind_param('siss', $k, $en, $sev, $mode); $st->execute(); $st->close(); } catch (\Throwable $e) {}
    }
    try { $conn->query("INSERT IGNORE INTO role_profiles (role_name,button_key,enabled) VALUES ('admin','autopilotv2',1)"); } catch (\Throwable $e) {}
    // seed the outbound webhook placeholders (disabled until a URL is pasted or Flows-Sync fills it)
    foreach ([['autopilot-v2','NEURU Commander (brain)'],['autopilot-v2-chat','NEURU Commander (chat)']] as $w) {
        try { $st=$conn->prepare("INSERT IGNORE INTO nm_n8n_webhooks (name,slug,url,method,description,enabled,source) VALUES (?,?,'','POST','NEURU Commander — autopilotv2',0,'manual')");
              $st->bind_param('ss',$w[1],$w[0]); $st->execute(); $st->close(); } catch (\Throwable $e) {}
    }
}

// ── settings (nm_settings ap2_* namespace) ───────────────────────────────────
function nm_ap2_get($conn, string $k, string $d = ''): string {
    try { $st = $conn->prepare("SELECT setting_val FROM nm_settings WHERE setting_key=? LIMIT 1");
          $st->bind_param('s', $k); $st->execute(); $r = $st->get_result()->fetch_row(); $st->close();
          return $r ? (string)$r[0] : $d; } catch (\Throwable $e) { return $d; }
}
function nm_ap2_set($conn, string $k, string $v): void {
    try { $st = $conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES (?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
          $st->bind_param('ss', $k, $v); $st->execute(); $st->close(); } catch (\Throwable $e) {}
}
function nm_ap2_enabled($conn): bool { return nm_ap2_get($conn, 'ap2_enabled', '0') === '1'; }   // master switch, OFF by default (experiment)

// ── VOICE NARRATION of autonomous investigations (opt-in; ALERTS ONLY — never the direct conversation) ──
// Narration requires BOTH the autonomous master switch AND the opt-in narrate flag. Default OFF (VAPI minutes
// cost money). The customer turns it on/off freely. See docs/AUTOPILOT_V2_VOICE_NARRATION_PLAN.md.
function nm_ap2_voice_on($conn): bool {
    return nm_ap2_enabled($conn) && nm_ap2_get($conn, 'ap2_autonomous_voice', '0') === '1';
}
// Build a SHORT, COMPLETE spoken line: "{name}: {one full sentence}." Strips the abstract preambles the brain
// likes, then keeps ONE complete sentence so VAPI never speaks a mid-word fragment (no "…", no entrecorte).
// ALERTS path only — the direct conversation never uses this.
function nm_ap2_voice_terse(string $name, string $text, int $cap = 160): string {
    $t = trim(preg_replace('/\s+/u', ' ', $text));
    // strip STACKED abstract preambles ("La señal indica que se ha realizado…") — loop until stable.
    $pre = '/^(la\s+se[nñ]al\s+indica\s+que|la\s+informaci[oó]n\s+(proporcionada\s+)?muestra\s+que|el\s+incidente\s+indica\s+que|se\s+ha\s+(realizado|detectado)[^,.]*[,.]?|como\s+parte\s+de[^,.]*[,.]?|adem[aá]s[,]?)\s*/iu';
    for ($k = 0; $k < 4; $k++) { $n = preg_replace($pre, '', (string)$t); if ($n === $t) break; $t = trim($n); }
    $t = trim($t);
    if ($t === '') $t = 'revisado';
    // ONE COMPLETE SENTENCE: cut at the first . ! ? so the utterance always finishes cleanly.
    if (preg_match('/^(.+?[.!?])(?:\s|$)/u', $t, $mm)) $t = trim($mm[1]);
    // if that single sentence is still very long, cut at the last WORD boundary before the cap (never mid-word).
    $len = function_exists('mb_strlen') ? mb_strlen($t) : strlen($t);
    if ($len > $cap) {
        $cut = function_exists('mb_substr') ? mb_substr($t, 0, $cap) : substr($t, 0, $cap);
        $sp  = function_exists('mb_strrpos') ? mb_strrpos($cut, ' ') : strrpos($cut, ' ');
        if ($sp !== false && $sp > 24) $cut = function_exists('mb_substr') ? mb_substr($cut, 0, $sp) : substr($cut, 0, $sp);
        $t = rtrim($cut, " ,;:—-·");
    }
    // guarantee a terminal punctuation so it sounds finished (not cut off)
    if (!preg_match('/[.!?]$/u', $t)) $t .= '.';
    return $name !== '' ? ($name . ': ' . $t) : $t;
}
// Enqueue one milestone line. Best-effort; dedups per (signal,kind) via the UNIQUE key (one line per milestone).
function nm_ap2_voice_enqueue($conn, string $kind, ?int $signal_id, ?int $node_id, string $text): void {
    if (!in_array($kind, ['investigate', 'found', 'clean', 'proposed'], true)) return;
    $text = trim($text); if ($text === '') return;
    if (function_exists('mb_substr') && mb_strlen($text) > 300) $text = mb_substr($text, 0, 300);
    try {
        $st = $conn->prepare("INSERT IGNORE INTO nm_ap2_voice_queue (kind,signal_id,node_id,text) VALUES (?,?,?,?)");
        $st->bind_param('siis', $kind, $signal_id, $node_id, $text); $st->execute(); $st->close();
    } catch (\Throwable $e) {}
    // light prune so the table never grows unbounded (keep it best-effort, cheap, occasional)
    if (rand(1, 25) === 1) { try { $conn->query("DELETE FROM nm_ap2_voice_queue WHERE status IN('spoken','dropped') AND created_at < (NOW() - INTERVAL 2 DAY)"); } catch (\Throwable $e) {} }
}
// Claim the oldest PENDING line for speaking (single-flight: only one drainer wins). Reverts stale claims (a tab
// that grabbed a line then died). Drops 'investigate' lines whose alert already closed (no ghost narration).
function nm_ap2_voice_drain($conn): ?array {
    nm_ap2_ensure($conn);
    try { $conn->query("UPDATE nm_ap2_voice_queue SET status='pending', claimed_at=NULL WHERE status='speaking' AND claimed_at < (NOW() - INTERVAL 30 SECOND)"); } catch (\Throwable $e) {}
    for ($i = 0; $i < 4; $i++) {
        $row = null;
        try { $q = $conn->query("SELECT id,kind,signal_id,node_id,text FROM nm_ap2_voice_queue WHERE status='pending' ORDER BY id ASC LIMIT 1");
              $row = $q ? $q->fetch_assoc() : null; } catch (\Throwable $e) { return null; }
        if (!$row) return null;
        $id = (int)$row['id'];
        $won = false; try { $conn->query("UPDATE nm_ap2_voice_queue SET status='speaking', claimed_at=NOW() WHERE id=$id AND status='pending'"); $won = $conn->affected_rows > 0; } catch (\Throwable $e) {}
        if (!$won) continue;   // lost the race → next
        if ($row['kind'] === 'investigate' && $row['signal_id']) {   // ghost check: alert already resolved?
            $open = true; try { $q = $conn->query("SELECT 1 FROM nm_ap2_signals WHERE id=" . (int)$row['signal_id'] . " AND status IN('new','investigating','proposed','acted') LIMIT 1"); $open = ($q && $q->num_rows > 0); } catch (\Throwable $e) {}
            if (!$open) { try { $conn->query("UPDATE nm_ap2_voice_queue SET status='dropped' WHERE id=$id"); } catch (\Throwable $e) {} continue; }
        }
        return ['id' => $id, 'kind' => (string)$row['kind'], 'text' => (string)$row['text']];
    }
    return null;
}
function nm_ap2_voice_spoken($conn, int $id): void {
    try { $conn->query("UPDATE nm_ap2_voice_queue SET status='spoken', spoken_at=NOW() WHERE id=" . (int)$id); } catch (\Throwable $e) {}
}

// ── fingerprint: the stable identity of a distinct issue ─────────────────────
function nm_ap2_fp(string $channel, string $target, string $type, string $key): string {
    return sha1($channel . '|' . $target . '|' . $type . '|' . $key);
}

// ── learned rules: return the winning policy for a signal, or '' ─────────────
function nm_ap2_rule_for($conn, array $sig): string {
    try {
        $r = $conn->query("SELECT id,match_type,match_val,policy FROM nm_ap2_rules WHERE active=1");
        if (!$r) return '';
        $hay = strtolower(($sig['channel'] ?? '') . ':' . ($sig['sig_type'] ?? '') . ' ' . ($sig['title'] ?? '') . ' ' . ($sig['detail'] ?? ''));
        while ($x = $r->fetch_assoc()) {
            $mt = $x['match_type']; $mv = (string)$x['match_val']; $hit = false;
            if ($mt === 'fingerprint')       $hit = ($mv === ($sig['fingerprint'] ?? ''));
            elseif ($mt === 'channel_type')   $hit = ($mv === (($sig['channel'] ?? '') . ':' . ($sig['sig_type'] ?? '')));
            elseif ($mt === 'node')           $hit = ((int)$mv === (int)($sig['node_id'] ?? 0));
            elseif ($mt === 'regex')          { $ob=ini_set('pcre.backtrack_limit','100000'); $hit = @preg_match('/' . str_replace('/', '\/', $mv) . '/i', $hay) === 1; if($ob!==false) ini_set('pcre.backtrack_limit',$ob); }   // cap backtracking → a catastrophic operator pattern fails fast instead of pinning CPU
            if ($hit) { $conn->query("UPDATE nm_ap2_rules SET hits=hits+1 WHERE id=" . (int)$x['id']); return $x['policy']; }
        }
    } catch (\Throwable $e) {}
    return '';
}

// ── channels helper ──────────────────────────────────────────────────────────
function nm_ap2_channels($conn): array {
    $o = [];
    try { $r = $conn->query("SELECT channel_key,enabled,min_severity,act_mode FROM nm_ap2_channels");
          while ($r && $x = $r->fetch_assoc()) $o[$x['channel_key']] = $x; } catch (\Throwable $e) {}
    return $o;
}
function _ap2_sev_ok(string $have, string $min): bool {
    $rank = ['info' => 0, 'warning' => 1, 'warn' => 1, 'degraded' => 1, 'critical' => 2, 'high' => 2, 'down' => 2];
    return ($rank[strtolower($have)] ?? 0) >= ($rank[strtolower($min)] ?? 1);
}

// ── upsert one normalized signal into the bus (dedup by fingerprint) ─────────
// Returns 'new' | 'seen' | 'ignored' (dropped by a rule).
function nm_ap2_push($conn, array $s): string {
    $fp = $s['fingerprint'];
    // an OPEN signal with this fp already? bump it.
    try {
        $q = $conn->prepare("SELECT id FROM nm_ap2_signals WHERE fingerprint=? AND status IN('new','investigating','proposed','acted') ORDER BY id DESC LIMIT 1");
        $q->bind_param('s', $fp); $q->execute(); $ex = $q->get_result()->fetch_row(); $q->close();
        if ($ex) { $conn->query("UPDATE nm_ap2_signals SET seen_count=seen_count+1, last_seen=NOW() WHERE id=" . (int)$ex[0]); return 'seen'; }
    } catch (\Throwable $e) {}
    // learned rule? an 'ignore' rule drops it BEFORE it ever reaches the brain.
    $policy = nm_ap2_rule_for($conn, $s);
    if ($policy === 'ignore') {
        try { $st = $conn->prepare("INSERT INTO nm_ap2_signals (fingerprint,channel,sig_type,target_kind,node_id,container_id,name,severity,title,detail,status) VALUES (?,?,?,?,?,?,?,?,?,?,'ignored')");
              $ci = $s['container_id'] ?? null; $ni = $s['node_id'] ?? null;
              $st->bind_param('ssssisssss', $fp, $s['channel'], $s['sig_type'], $s['target_kind'], $ni, $ci, $s['name'], $s['severity'], $s['title'], $s['detail']);
              $st->execute(); $st->close(); } catch (\Throwable $e) {}
        return 'ignored';
    }
    try {
        $st = $conn->prepare("INSERT INTO nm_ap2_signals (fingerprint,channel,sig_type,target_kind,node_id,container_id,name,severity,title,detail,status) VALUES (?,?,?,?,?,?,?,?,?,?,'new')");
        $ci = $s['container_id'] ?? null; $ni = $s['node_id'] ?? null;
        $st->bind_param('ssssisssss', $fp, $s['channel'], $s['sig_type'], $s['target_kind'], $ni, $ci, $s['name'], $s['severity'], $s['title'], $s['detail']);
        $st->execute(); $st->close();
    } catch (\Throwable $e) {}
    return 'new';
}

// ── THE SIGNAL BUS: normalize every enabled channel into nm_ap2_signals ──────
// Read-only against the source tables; safe to run every minute. Returns per-channel counts.
function nm_ap2_scan($conn): array {
    nm_ap2_ensure($conn);
    $ch = nm_ap2_channels($conn);
    $out = ['new' => 0, 'seen' => 0, 'ignored' => 0, 'channels' => []];
    $bump = function ($r) use (&$out) { $out[$r] = ($out[$r] ?? 0) + 1; };

    // AUTO-RESOLVE recovered nodes: a nodes_down signal whose node is no longer down leaves the queue on its
    // own — the queue always reflects reality (issues clear when the condition clears), no manual cleanup.
    try { $conn->query("DELETE FROM nm_ap2_signals
        WHERE channel='nodes_down' AND status IN('new','investigating','acted','proposed') AND node_id IS NOT NULL
          AND node_id NOT IN (SELECT node_id FROM nm_alert_state WHERE entity_type='node' AND last_status IN('down','degraded','lowerlayerdown','notpresent','testing'))"); } catch (\Throwable $e) {}

    // 1) nodes_down — nm_alert_state (node down/degraded)
    if (!empty($ch['nodes_down']['enabled'])) {
        $c = 0;
        try {
            $r = $conn->query("SELECT a.node_id, a.last_status, n.display_name
                FROM nm_alert_state a JOIN nm_nodes n ON n.id=a.node_id
                WHERE a.entity_type='node' AND a.last_status IN ('down','degraded','lowerlayerdown','notpresent','testing')");
            while ($r && $x = $r->fetch_assoc()) {
                $st = strtolower($x['last_status']);
                $sig = ['fingerprint' => nm_ap2_fp('nodes_down', 'node:' . $x['node_id'], 'node_' . $st, ''),
                        'channel' => 'nodes_down', 'sig_type' => 'node_' . $st, 'target_kind' => 'node',
                        'node_id' => (int)$x['node_id'], 'name' => $x['display_name'],
                        'severity' => ($st === 'down' ? 'critical' : 'warning'),
                        'title' => $x['display_name'] . ' is ' . $st, 'detail' => 'Node reported ' . $st . ' by monitoring.'];
                if (_ap2_sev_ok($sig['severity'], $ch['nodes_down']['min_severity'])) { $bump(nm_ap2_push($conn, $sig)); $c++; }
            }
        } catch (\Throwable $e) {}
        $out['channels']['nodes_down'] = $c;
    }
    // 2) nodes_findings — nm_ai_insights open/ack critical|warning (not remediations)
    if (!empty($ch['nodes_findings']['enabled'])) {
        $c = 0;
        try {
            $r = $conn->query("SELECT id,node_id,severity,title,correlation_key FROM nm_ai_insights
                WHERE status IN ('open','acknowledged') AND severity IN ('critical','warning') AND kind<>'remediation' ORDER BY id DESC LIMIT 200");
            while ($r && $x = $r->fetch_assoc()) {
                $key = $x['correlation_key'] ?: ('i' . $x['id']);
                $sig = ['fingerprint' => nm_ap2_fp('nodes_findings', 'node:' . (int)$x['node_id'], 'ai_finding', $key),
                        'channel' => 'nodes_findings', 'sig_type' => 'ai_finding', 'target_kind' => 'node',
                        'node_id' => $x['node_id'] !== null ? (int)$x['node_id'] : null, 'name' => null,
                        'severity' => $x['severity'], 'title' => substr((string)$x['title'], 0, 255), 'detail' => 'AI finding from the insight flows.'];
                if (_ap2_sev_ok($sig['severity'], $ch['nodes_findings']['min_severity'])) { $bump(nm_ap2_push($conn, $sig)); $c++; }
            }
        } catch (\Throwable $e) {}
        $out['channels']['nodes_findings'] = $c;
    }
    // 3) containers_inc — container_incidents (open)
    if (!empty($ch['containers_inc']['enabled'])) {
        $c = 0;
        try {
            $r = $conn->query("SELECT id,container_name,endpoint_id,severity,title FROM container_incidents
                WHERE status NOT IN ('resolved','closed','ignored') ORDER BY id DESC LIMIT 200");
            while ($r && $x = $r->fetch_assoc()) {
                $sev = strtolower((string)($x['severity'] ?? 'warning')); if ($sev === '') $sev = 'warning';
                $sig = ['fingerprint' => nm_ap2_fp('containers_inc', 'ctr:' . $x['container_name'], 'container_incident', (string)$x['id']),
                        'channel' => 'containers_inc', 'sig_type' => 'container_incident', 'target_kind' => 'container',
                        'node_id' => null, 'container_id' => (string)$x['container_name'], 'name' => (string)$x['container_name'],
                        'severity' => $sev, 'title' => substr((string)($x['title'] ?? ('Incident on ' . $x['container_name'])), 0, 255),
                        'detail' => 'Container incident (endpoint ' . (int)$x['endpoint_id'] . ').'];
                if (_ap2_sev_ok($sig['severity'], $ch['containers_inc']['min_severity'])) { $bump(nm_ap2_push($conn, $sig)); $c++; }
            }
        } catch (\Throwable $e) {}
        $out['channels']['containers_inc'] = $c;
    }
    // 4) events_threats — nm_threats active (Immunity)
    if (!empty($ch['events_threats']['enabled'])) {
        $c = 0;
        try {
            if ($conn->query("SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_threats' LIMIT 1")->num_rows) {
                // PENDING threats = detected but NOT blocked yet → actionable (NEURU proposes immunize). Active
                // ones are already handled. Auto-resolve any threat signal whose threat is no longer pending.
                try { $conn->query("DELETE FROM nm_ap2_signals WHERE channel='events_threats' AND status IN('new','investigating','acted','proposed') AND container_id NOT IN (SELECT CONCAT('threat:',id) FROM nm_threats WHERE status='pending')"); } catch (\Throwable $e) {}
                // BATCH so a backlog of hundreds of pending threats can't explode the queue: keep at most
                // ap2_threat_batch (default 5) OPEN threat signals; each scan just tops up the free slots with
                // the newest un-surfaced ones. As they're immunized/dismissed, the next batch flows in.
                $cap=(int)(nm_ap2_get($conn,'ap2_threat_batch','5')?:5);
                $open=0; try { $q=$conn->query("SELECT COUNT(*) c FROM nm_ap2_signals WHERE channel='events_threats' AND status IN('new','investigating','acted','proposed')"); $open=(int)($q?$q->fetch_assoc()['c']:0); } catch (\Throwable $e) {}
                $room=max(0,$cap-$open);
                if ($room>0) {
                $r = $conn->query("SELECT id,indicator,ind_type,severity FROM nm_threats WHERE status='pending' AND CONCAT('threat:',id) NOT IN (SELECT COALESCE(container_id,'') FROM nm_ap2_signals WHERE channel='events_threats') ORDER BY FIELD(severity,'high','medium','low'), id DESC LIMIT ".(int)$room);
                while ($r && $x = $r->fetch_assoc()) {
                    $tsev = strtolower((string)($x['severity'] ?? 'high'));   // immunity uses high|medium|low → map to info|warning|critical
                    $sev  = $tsev==='high' ? 'critical' : ($tsev==='low' ? 'info' : 'warning');
                    $cat  = (string)($x['ind_type'] ?? 'indicator');
                    $sig = ['fingerprint' => nm_ap2_fp('events_threats', 'threat:' . $x['id'], 'threat', $cat),
                            'channel' => 'events_threats', 'sig_type' => 'threat', 'target_kind' => 'fleet',
                            'node_id' => null, 'container_id' => 'threat:' . (int)$x['id'], 'name' => (string)$x['indicator'],
                            'severity' => $sev,
                            'title' => 'Threat to immunize: ' . $x['indicator'] . ' (' . $cat . ')',
                            'detail' => 'Collective Immunity ALREADY flagged this ' . $cat . ' (' . $x['indicator'] . ') as a threat — it is pending a block decision. Your job is to PROPOSE immunize(threat_id=' . (int)$x['id'] . ') so the OPERATOR can Approve/Deny it. You do NOT need to independently prove it is malicious — Immunity already detected it, and NOTHING executes without human approval, so proposing is safe. DEFAULT = propose. Only finish WITHOUT proposing if it is OBVIOUSLY a false-positive / known-good (e.g. 8.8.8.8, 1.1.1.1, cloudflare, a LAN gateway, your own domains).'];
                    if (_ap2_sev_ok($sig['severity'], $ch['events_threats']['min_severity'])) { $bump(nm_ap2_push($conn, $sig)); $c++; }
                }
                }
            }
        } catch (\Throwable $e) {}
        $out['channels']['events_threats'] = $c;
    }
    // 5) predictive — nm_health_forecast (fail_eta soon)
    if (!empty($ch['predictive']['enabled'])) {
        $c = 0;
        try {
            if ($conn->query("SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_health_predictions' LIMIT 1")->num_rows) {
                $r = $conn->query("SELECT node_id,metric,eta_days FROM nm_health_predictions WHERE status='open' AND eta_days IS NOT NULL AND eta_days <= 14 ORDER BY eta_days ASC LIMIT 100");
                while ($r && $x = $r->fetch_assoc()) {
                    $sig = ['fingerprint' => nm_ap2_fp('predictive', 'node:' . (int)$x['node_id'], 'predictive', (string)$x['metric']),
                            'channel' => 'predictive', 'sig_type' => 'predictive', 'target_kind' => 'node',
                            'node_id' => (int)$x['node_id'], 'name' => null, 'severity' => 'warning',
                            'title' => 'Predicted degradation: ' . $x['metric'] . ' (~' . (int)$x['eta_days'] . 'd)',
                            'detail' => 'Predictive Health forecast.'];
                    if (_ap2_sev_ok($sig['severity'], $ch['predictive']['min_severity'])) { $bump(nm_ap2_push($conn, $sig)); $c++; }
                }
            }
        } catch (\Throwable $e) {}
        $out['channels']['predictive'] = $c;
    }

    // 6) heal — nm_heal_events 'proposed' (a playbook detected an issue + staged an action, awaiting apply)
    if (!empty($ch['heal']['enabled'])) {
        $c = 0;
        try {
            if ($conn->query("SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_heal_events' LIMIT 1")->num_rows) {
                try { $conn->query("DELETE FROM nm_ap2_signals WHERE channel='heal' AND status IN('new','investigating','acted','proposed') AND container_id NOT IN (SELECT CONCAT('heal:',id) FROM nm_heal_events WHERE status='proposed')"); } catch (\Throwable $e) {}
                $cap=(int)(nm_ap2_get($conn,'ap2_heal_batch','5')?:5);
                $open=0; try { $q=$conn->query("SELECT COUNT(*) c FROM nm_ap2_signals WHERE channel='heal' AND status IN('new','investigating','acted','proposed')"); $open=(int)($q?$q->fetch_assoc()['c']:0); } catch (\Throwable $e) {}
                $room=max(0,$cap-$open);
                if ($room>0) {
                    $r=$conn->query("SELECT id,pb_key,indicator,trigger_detail,action FROM nm_heal_events WHERE status='proposed' AND CONCAT('heal:',id) NOT IN (SELECT COALESCE(container_id,'') FROM nm_ap2_signals WHERE channel='heal') ORDER BY id DESC LIMIT ".(int)$room);
                    while ($r && $x=$r->fetch_assoc()) {
                        $sig=['fingerprint'=>nm_ap2_fp('heal','heal:'.$x['id'],'heal',(string)$x['pb_key']),
                            'channel'=>'heal','sig_type'=>'heal','target_kind'=>'fleet','node_id'=>null,'container_id'=>'heal:'.(int)$x['id'],
                            'name'=>(string)$x['indicator'],'severity'=>'warning',
                            'title'=>'Heal proposed: '.$x['action'].' for '.$x['indicator'],
                            'detail'=>'Self-Healing ALREADY detected an issue ('.($x['trigger_detail']?:$x['pb_key']).') and STAGED the "'.$x['action'].'" fix (auto-reverts if it does not help). Your job is to PROPOSE heal_apply(event_id='.(int)$x['id'].') so the OPERATOR can Approve/Deny. You do NOT need to re-diagnose — the playbook detected it and nothing runs without approval. DEFAULT = propose. Only skip (finish) if the staged fix is clearly wrong for the described trigger.'];
                        if (_ap2_sev_ok($sig['severity'],$ch['heal']['min_severity'])) { $bump(nm_ap2_push($conn,$sig)); $c++; }
                    }
                }
            }
        } catch (\Throwable $e) {}
        $out['channels']['heal']=$c;
    }
    // 7) deception — nm_decoy_diversions 'active' (an attacker diverted into a honeypot; watch → promote/block)
    if (!empty($ch['deception']['enabled'])) {
        $c = 0;
        try {
            if ($conn->query("SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_decoy_diversions' LIMIT 1")->num_rows) {
                try { $conn->query("DELETE FROM nm_ap2_signals WHERE channel='deception' AND status IN('new','investigating','acted','proposed') AND container_id NOT IN (SELECT CONCAT('divert:',id) FROM nm_decoy_diversions WHERE status='active')"); } catch (\Throwable $e) {}
                $cap=(int)(nm_ap2_get($conn,'ap2_deception_batch','5')?:5);
                $open=0; try { $q=$conn->query("SELECT COUNT(*) c FROM nm_ap2_signals WHERE channel='deception' AND status IN('new','investigating','acted','proposed')"); $open=(int)($q?$q->fetch_assoc()['c']:0); } catch (\Throwable $e) {}
                $room=max(0,$cap-$open);
                if ($room>0) {
                    $r=$conn->query("SELECT d.id,d.src_ip,(SELECT COUNT(*) FROM nm_decoy_events e WHERE e.diversion_id=d.id) hits FROM nm_decoy_diversions d WHERE d.status='active' AND CONCAT('divert:',d.id) NOT IN (SELECT COALESCE(container_id,'') FROM nm_ap2_signals WHERE channel='deception') ORDER BY d.id DESC LIMIT ".(int)$room);
                    while ($r && $x=$r->fetch_assoc()) {
                        $hits=(int)$x['hits'];
                        $sig=['fingerprint'=>nm_ap2_fp('deception','divert:'.$x['id'],'deception',(string)$x['src_ip']),
                            'channel'=>'deception','sig_type'=>'deception','target_kind'=>'fleet','node_id'=>null,'container_id'=>'divert:'.(int)$x['id'],
                            'name'=>(string)$x['src_ip'],'severity'=>($hits>0?'critical':'warning'),
                            'title'=>'Attacker in honeypot: '.$x['src_ip'].' ('.$hits.' hits)',
                            'detail'=>'Deception Grid ALREADY diverted attacker '.$x['src_ip'].' into a decoy honeypot ('.$hits.' interaction(s) recorded) — this IP is already treated as hostile. Your job is to PROPOSE immunize(indicator="'.$x['src_ip'].'") to block it fleet-wide so the OPERATOR can Approve/Deny. You do NOT need to re-prove hostility — it was caught in the trap and nothing runs without approval. DEFAULT = propose.'];
                        if (_ap2_sev_ok($sig['severity'],$ch['deception']['min_severity'])) { $bump(nm_ap2_push($conn,$sig)); $c++; }
                    }
                }
            }
        } catch (\Throwable $e) {}
        $out['channels']['deception']=$c;
    }

    // N) incidents — the CORRELATED incident layer (nm_incidents): "High loss"/latency, config drift, and any
    //    correlated incident NOT already owned by a dedicated channel. node_down + container are excluded (their
    //    own channels cover them). This is what makes NEURU act on the incidents shown in Troubleshooting.
    if (!empty($ch['incidents']['enabled']) && $conn->query("SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_incidents' LIMIT 1")->num_rows) {
        $c = 0;
        // auto-resolve: drop signals whose incident closed (resolved/muted / no longer open) → two-way sync
        try { $conn->query("DELETE FROM nm_ap2_signals WHERE channel='incidents' AND status IN('new','investigating','acted','proposed')
              AND container_id NOT IN (SELECT CONCAT('inc:',corr_key) FROM nm_incidents WHERE status='open' AND resolved_at IS NULL AND muted_at IS NULL)"); } catch (\Throwable $e) {}
        try {
            $open = 0; $q = $conn->query("SELECT COUNT(*) c FROM nm_ap2_signals WHERE channel='incidents' AND status IN('new','investigating','acted','proposed')"); $open = (int)($q ? $q->fetch_assoc()['c'] : 0);
            $room = max(0, 6 - $open);   // batch cap so a backlog of open incidents doesn't flood the queue
            if ($room > 0) {
                $r = $conn->query("SELECT id,corr_key,root_source,root_entity,root_node_id,severity,title,impact_count
                    FROM nm_incidents WHERE status='open' AND resolved_at IS NULL AND muted_at IS NULL
                      AND root_source NOT IN ('node_down','container')
                      AND CONCAT('inc:',corr_key) NOT IN (SELECT COALESCE(container_id,'') FROM nm_ap2_signals WHERE channel='incidents')
                    ORDER BY FIELD(severity,'critical','warning','info'), opened_at DESC LIMIT " . (int)$room);
                while ($r && $x = $r->fetch_assoc()) {
                    $nid = $x['root_node_id'] !== null ? (int)$x['root_node_id'] : null;
                    $sig = ['fingerprint' => nm_ap2_fp('incidents', 'inc:' . $x['corr_key'], (string)$x['root_source'], ''),
                            'channel' => 'incidents', 'sig_type' => (string)($x['root_source'] ?: 'incident'),
                            'target_kind' => $nid ? 'node' : 'fleet', 'node_id' => $nid, 'container_id' => 'inc:' . $x['corr_key'],
                            'name' => (string)($x['root_entity'] ?: $x['title']), 'severity' => (string)$x['severity'],
                            'title' => (string)$x['title'],
                            'detail' => 'Correlated incident from Troubleshooting (root: ' . $x['root_source'] . ', ' . (int)$x['impact_count'] . ' impacted). Investigate the root cause and propose a fix if you find one.'];
                    if (_ap2_sev_ok($sig['severity'], $ch['incidents']['min_severity'])) { $bump(nm_ap2_push($conn, $sig)); $c++; }
                }
            }
        } catch (\Throwable $e) {}
        $out['channels']['incidents'] = $c;
    }

    // heartbeat
    nm_ap2_set($conn, 'ap2_last_scan', gmdate('Y-m-d H:i:s'));
    nm_ap2_set($conn, 'ap2_last_scan_stats', json_encode($out));
    return $out;
}

// ── fleet map cache (all nodes + their containers) ───────────────────────────
function nm_ap2_fleet_refresh($conn): int {
    nm_ap2_ensure($conn);
    $n = 0;
    $cfg = function_exists('nm_portainer_cfg') ? nm_portainer_cfg($conn) : [];
    $havePort = function_exists('nm_portainer_configured') && nm_portainer_configured($cfg);
    try {
        $r = $conn->query("SELECT id,display_name,ip_address FROM nm_nodes");
        while ($r && $x = $r->fetch_assoc()) {
            $eid = null; $ctrs = [];
            if ($havePort && function_exists('nm_aip_node_endpoint')) {
                // reuse v1's IP→endpoint resolver (read-only)
                $eid = @nm_aip_node_endpoint($conn, ['ip_address' => $x['ip_address']]);
                if ($eid && function_exists('nm_portainer_containers')) {
                    $cr = nm_portainer_containers($cfg, (int)$eid, false);
                    if (!empty($cr['ok'])) foreach (array_map('nm_portainer_norm_container', (array)$cr['data']) as $c)
                        $ctrs[] = ['name' => $c['name'] ?? '', 'state' => $c['state'] ?? ''];
                }
            }
            $cj = json_encode($ctrs);
            $st = $conn->prepare("INSERT INTO nm_ap2_fleet (node_id,name,ip,endpoint_id,containers) VALUES (?,?,?,?,?)
                ON DUPLICATE KEY UPDATE name=VALUES(name), ip=VALUES(ip), endpoint_id=VALUES(endpoint_id), containers=VALUES(containers)");
            $nid = (int)$x['id']; $eidv = $eid !== null ? (int)$eid : null;
            $st->bind_param('issis', $nid, $x['display_name'], $x['ip_address'], $eidv, $cj);
            $st->execute(); $st->close(); $n++;
        }
    } catch (\Throwable $e) {}
    return $n;
}

// ── V2 tool catalog (read + act; containers are first-class, unlike v1) ──────
function nm_ap2_tools(): array {
    return [
        ['name'=>'get_full_context','act'=>'read','desc'=>'Full telemetry for the target node.'],
        ['name'=>'get_fleet_map','act'=>'read','desc'=>'All nodes + the containers inside them.'],
        ['name'=>'ping_host','act'=>'read','args'=>['ip'],'desc'=>'ICMP probe a host.'],
        ['name'=>'read_logs','act'=>'read','args'=>['limit'],'desc'=>'Recent syslog for the node.'],
        ['name'=>'read_container_logs','act'=>'read','args'=>['container','limit'],'desc'=>'Recent logs of a container.'],
        ['name'=>'get_health','act'=>'read','desc'=>'CPU/RAM/disk + predictive.'],
        ['name'=>'get_interfaces','act'=>'read','desc'=>'Interface states + traffic.'],
        ['name'=>'get_netflow_top','act'=>'read','args'=>['limit'],'desc'=>'Top talkers.'],
        ['name'=>'reachability','act'=>'read','args'=>['src','dst'],'desc'=>'Simulate the forwarding path SRC→DST over the monitored routers\' real routing tables → reachable / unreachable + where it stops.'],
        ['name'=>'route_lookup','act'=>'read','args'=>['dst'],'desc'=>'Which routers have a route to DST (longest-prefix, gateway, protocol).'],
        ['name'=>'route_drift','act'=>'read','args'=>['node'],'desc'=>'Recent routing-table changes (added/removed routes) for a router.'],
        ['name'=>'database_report','act'=>'read','args'=>['db'],'desc'=>'Monitored DB status: metrics, replication lag, tuning advice, schema drift (no db = summary of all).'],
        ['name'=>'firewall_rules','act'=>'read','args'=>['node','table'],'desc'=>'MikroTik firewall ruleset (filter/nat/mangle).'],
        ['name'=>'firewall_check','act'=>'read','args'=>['node','src','dst'],'desc'=>'Does the firewall allow SRC→DST? A→B emulation (routing+NAT+firewall) → verdict + deciding rule.'],
        ['name'=>'firewall_drift','act'=>'read','args'=>['node','table'],'desc'=>'Firewall config drift (rules added/removed vs snapshot).'],
        ['name'=>'firewall_traffic','act'=>'read','args'=>['node'],'desc'=>'Live firewall connections (torch).'],
        ['name'=>'firewall_addrlists','act'=>'read','args'=>['node'],'desc'=>'Firewall address lists (blocked/whitelist).'],
        ['name'=>'connections','act'=>'read','args'=>['node'],'desc'=>'What is connected to a node (topology neighbors + iface/label).'],
        ['name'=>'blast_radius','act'=>'read','args'=>['node'],'desc'=>'If this node fails, which nodes + business services break (cascade).'],
        ['name'=>'search_kb','act'=>'read','args'=>['query'],'desc'=>'Search past resolutions (RAG).'],
        ['name'=>'ssh_command','act'=>'act','risk'=>'high','args'=>['command'],'desc'=>'Run a shell/PowerShell/RouterOS command.'],
        ['name'=>'restart_service','act'=>'act','risk'=>'medium','args'=>['service'],'desc'=>'Restart a service on the node.'],
        ['name'=>'restart_container','act'=>'act','risk'=>'medium','args'=>['container'],'desc'=>'Restart a container (Portainer).'],
        ['name'=>'block_ip','act'=>'act','risk'=>'medium','args'=>['ip','reason'],'desc'=>'Block an IP via Collective Immunity.'],
        ['name'=>'flush_dns','act'=>'act','risk'=>'low','desc'=>'Flush DNS cache.'],
        ['name'=>'clear_logs_rotate','act'=>'act','risk'=>'low','args'=>['path'],'desc'=>'Rotate/clear a log file.'],
        // domain actions (fleet-wide, not node-SSH) — go through the risk gate + Telegram approval
        ['name'=>'immunize','act'=>'act','risk'=>'medium','args'=>['threat_id','indicator'],'desc'=>'Block a threat across EVERY Pi-hole + firewall (fleet-wide). On a "Threat to immunize" signal pass threat_id; to block a raw attacker IP/domain (e.g. from a honeypot hit) pass indicator.'],
        ['name'=>'heal_apply','act'=>'act','risk'=>'medium','args'=>['event_id'],'desc'=>'Apply the Self-Healing playbook action for a proposed heal event (restart/block/etc. with auto-revert). Use on a "Heal proposed" signal; pass its event_id.'],
        ['name'=>'firewall_block_ip','act'=>'act','risk'=>'medium','args'=>['node','ip','reason'],'desc'=>'Block an IP on a MikroTik router by adding it to the NEURU-BLOCK address-list (a drop rule enforces it). Router-level block (vs immunize = fleet-wide). ALWAYS proposes → operator Approves/Denies.'],
        ['name'=>'firewall_apply','act'=>'act','risk'=>'high','args'=>['node','table','op','chain','action'],'desc'=>'Apply a firewall RULE change on a MikroTik (op=add|remove|enable|disable|set; table=filter|nat|mangle) with anti-lockout Safe-Apply (auto-rollback if it cuts SSH). For remove/enable/disable pass the rule number. ALWAYS proposes → operator Approves/Denies.'],
    ];
}

// ── per-device tier (defaults to observe = never acts) ───────────────────────
function nm_ap2_device($conn, int $node_id): array {
    $d = ['node_id'=>$node_id,'enabled'=>1,'autonomy_mode'=>'observe','allow_destructive'=>0,'allow_commands'=>0,'telegram_approve'=>0];
    try { $st=$conn->prepare("SELECT enabled,autonomy_mode,allow_destructive,allow_commands,telegram_approve FROM nm_ap2_devices WHERE node_id=? LIMIT 1");
          $st->bind_param('i',$node_id); $st->execute(); $r=$st->get_result()->fetch_assoc(); $st->close();
          if ($r) $d=array_merge($d,$r,['node_id'=>$node_id]); } catch (\Throwable $e) {}
    return $d;
}
function nm_ap2_device_set($conn, int $node_id, array $v): void {
    nm_ap2_ensure($conn);
    // MERGE onto the CURRENT row — the UI sends ONE field at a time; a full-column upsert would reset the
    // others (e.g. changing autonomy would wipe 'enabled' back to 0). Default a missing row to enabled=0
    // to match the cockpit's COALESCE(d.enabled,0) display.
    $cur = ['enabled'=>0,'autonomy_mode'=>'observe','allow_destructive'=>0,'allow_commands'=>0,'telegram_approve'=>0];
    try { $st=$conn->prepare("SELECT enabled,autonomy_mode,allow_destructive,allow_commands,telegram_approve FROM nm_ap2_devices WHERE node_id=? LIMIT 1");
          $st->bind_param('i',$node_id); $st->execute(); $r=$st->get_result()->fetch_assoc(); $st->close(); if ($r) $cur=$r; } catch (\Throwable $e) {}
    $m = array_merge($cur, $v);   // apply only the field(s) the caller actually changed
    $mode=in_array($m['autonomy_mode']??'observe',['observe','copilot','autopilot'],true)?$m['autonomy_mode']:'observe';
    $en=(int)!empty($m['enabled']); $ad=(int)!empty($m['allow_destructive']); $ac=(int)!empty($m['allow_commands']); $tg=(int)!empty($m['telegram_approve']);
    try { $st=$conn->prepare("INSERT INTO nm_ap2_devices (node_id,enabled,autonomy_mode,allow_destructive,allow_commands,telegram_approve) VALUES (?,?,?,?,?,?)
            ON DUPLICATE KEY UPDATE enabled=VALUES(enabled),autonomy_mode=VALUES(autonomy_mode),allow_destructive=VALUES(allow_destructive),allow_commands=VALUES(allow_commands),telegram_approve=VALUES(telegram_approve)");
          $st->bind_param('iisiii',$node_id,$en,$mode,$ad,$ac,$tg); $st->execute(); $st->close(); } catch (\Throwable $e) {}
}

// ── sessions / events ─────────────────────────────────────────────────────────
function nm_ap2_event($conn, ?int $sid, ?int $node, string $phase, string $body): int {
    try { $st=$conn->prepare("INSERT INTO nm_ap2_events (session_id,node_id,phase,body) VALUES (?,?,?,?)");
          $b=substr($body,0,4000); $st->bind_param('iiss',$sid,$node,$phase,$b); $st->execute(); $id=$st->insert_id; $st->close(); return $id; } catch (\Throwable $e) { return 0; }
}
function nm_ap2_session_set($conn, int $sid, array $f): void {
    $cols=[]; $vals=[]; $types='';
    foreach (['status'=>'s','summary'=>'s','confidence'=>'i'] as $k=>$t) if (array_key_exists($k,$f)) { $cols[]="$k=?"; $vals[]=$f[$k]; $types.=$t; }
    if (!$cols) return; $vals[]=$sid; $types.='i';
    try { $st=$conn->prepare("UPDATE nm_ap2_sessions SET ".implode(',',$cols)." WHERE id=?"); $st->bind_param($types,...$vals); $st->execute(); $st->close(); } catch (\Throwable $e) {}
}
function nm_ap2_session_node($conn, int $sid): int {
    try { $st=$conn->prepare("SELECT node_id FROM nm_ap2_sessions WHERE id=? LIMIT 1"); $st->bind_param('i',$sid); $st->execute(); $r=$st->get_result()->fetch_row(); $st->close(); return $r?(int)$r[0]:0; } catch (\Throwable $e) { return 0; }
}

// ── DISPATCH: turn a NEW signal into a session + call the metered brain ───────
function nm_ap2_dispatch($conn, int $signal_id, string $trigger='signal'): array {
    nm_ap2_ensure($conn);
    // autonomous triggers respect the master switch; a MANUAL Investigate/Rescan/chat must still reach the brain
    // even while autonomy is paused (matches the toggle's documented intent).
    $manual = in_array($trigger, ['manual','chat'], true);
    if (!$manual && !nm_ap2_enabled($conn)) return ['ok'=>false,'error'=>'ap2 disabled'];
    $sg = null;
    try { $st=$conn->prepare("SELECT * FROM nm_ap2_signals WHERE id=? LIMIT 1"); $st->bind_param('i',$signal_id); $st->execute(); $sg=$st->get_result()->fetch_assoc(); $st->close(); } catch (\Throwable $e) {}
    if (!$sg || $sg['status']!=='new') return ['ok'=>false,'error'=>'signal not new'];
    $node_id = $sg['node_id']!==null ? (int)$sg['node_id'] : null;
    $dev = $node_id ? nm_ap2_device($conn,$node_id) : ['autonomy_mode'=>'observe','allow_destructive'=>0,'allow_commands'=>0,'enabled'=>1];
    if ($node_id && empty($dev['enabled'])) return ['ok'=>false,'error'=>'device disabled'];
    // DOMAIN signals (fleet-wide: threats/heal/deception — no node, no per-node tier) run at 'copilot' so the
    // brain actually PROPOSES the domain action; it can never auto-run (nm_ap2_propose_action forces approval).
    if (($sg['target_kind'] ?? '') === 'fleet') $dev['autonomy_mode'] = 'copilot';
    // ATOMIC CLAIM: only ONE dispatcher wins the new→investigating transition (defeats the cron + "Scan now"
    // double-dispatch race that would fire the metered brain twice for the same signal).
    $claimed=false; try { $conn->query("UPDATE nm_ap2_signals SET status='investigating' WHERE id=$signal_id AND status='new'"); $claimed=$conn->affected_rows>0; } catch (\Throwable $e) {}
    if (!$claimed) return ['ok'=>false,'error'=>'already claimed'];
    // create the session, bind it to the claimed signal
    try {
        $st=$conn->prepare("INSERT INTO nm_ap2_sessions (node_id,signal_id,status,trigger_kind,autonomy) VALUES (?,?,'active',?,?)");
        $mode=$dev['autonomy_mode']; $st->bind_param('iiss',$node_id,$signal_id,$trigger,$mode); $st->execute(); $sid=$st->insert_id; $st->close();
    } catch (\Throwable $e) { try { $conn->query("UPDATE nm_ap2_signals SET status='new' WHERE id=$signal_id AND status='investigating'"); } catch (\Throwable $e2) {} return ['ok'=>false,'error'=>'session create failed']; }
    try { $conn->query("UPDATE nm_ap2_signals SET session_id=$sid WHERE id=$signal_id"); } catch (\Throwable $e) {}
    nm_ap2_event($conn,$sid,$node_id,'observe',($sg['name']?:'fleet').': '.$sg['title']);
    // VOICE: narrate the START only for pure-autonomous triggers (not manual/chat) + only when narration is on.
    if ($trigger==='signal' && nm_ap2_voice_on($conn)) { nm_ap2_voice_enqueue($conn,'investigate',$signal_id,$node_id,'Revisando '.($sg['name']?:'la flota').'.'); }

    // build context (reuse v1's rich gatherer when we have a node)
    $ctx = ($node_id && function_exists('nm_aip_gather_context')) ? nm_aip_gather_context($conn,$node_id,true) : [];
    $ctx['signal'] = ['channel'=>$sg['channel'],'type'=>$sg['sig_type'],'severity'=>$sg['severity'],'title'=>$sg['title'],'detail'=>$sg['detail'],
                      'target'=>['kind'=>$sg['target_kind'],'node_id'=>$node_id,'container_id'=>$sg['container_id'],'name'=>$sg['name']]];
    // fleet hint + recent actions on this node (anti-repeat)
    try { $fr=$conn->query("SELECT COUNT(*) n FROM nm_nodes"); $ctx['fleet_hint']['total_nodes']=(int)($fr?$fr->fetch_assoc()['n']:0); } catch (\Throwable $e) {}
    $recent=[]; try { $rr=$conn->query("SELECT tool,args,status,created_at FROM nm_ap2_actions WHERE node_id=".(int)$node_id." AND created_at>(NOW()-INTERVAL 24 HOUR) ORDER BY id DESC LIMIT 8");
                      while($rr && $x=$rr->fetch_assoc()) $recent[]=$x; } catch (\Throwable $e) {}
    $ctx['recent_actions']=$recent;
    // active rules the brain must honor
    $rules=[]; try { $rr=$conn->query("SELECT match_type,match_val,policy,note FROM nm_ap2_rules WHERE active=1 AND policy IN('always_ask','auto_fix')");
                     while($rr && $x=$rr->fetch_assoc()) $rules[]=$x; } catch (\Throwable $e) {}

    // callback base MUST be the tunnel IP for a HOSTED flow → pass the flow URL so nm_n8n_callback_base
    // detects 10.88.x and returns ai_public_base (else it falls back to $_SERVER/localhost in cron/CLI →
    // the flow would POST callbacks into its own container and NEURU never sees them).
    $flow_url = ''; try { $wh = nm_n8n_webhook_by_slug($conn, 'autopilot-v2'); $flow_url = (string)($wh['url'] ?? ''); } catch (\Throwable $e) {}
    $cb = function_exists('nm_n8n_callback_base') ? rtrim(nm_n8n_callback_base($conn, $flow_url),'/') : '';
    $api = $cb.'/autopilotv2_api.php';
    $payload = [
        'session_id'=>(string)$sid, 'fingerprint'=>$sg['fingerprint'],
        'signal'=>$ctx['signal'], 'autonomy'=>$dev['autonomy_mode'],
        'allow_destructive'=>(int)$dev['allow_destructive'], 'allow_commands'=>(int)$dev['allow_commands'],
        'bot'=>'NEURU', 'context'=>$ctx, 'tools'=>nm_ap2_tools(), 'rules'=>$rules, 'history'=>[],
        'callback'=>['think'=>"$api?ep=think",'tool'=>"$api?ep=tool",'propose'=>"$api?ep=propose",'finish'=>"$api?ep=finish",'narrate'=>"$api?ep=narrate"],
    ];
    // Books RAG — attach reference-book context for this signal (ADDITIVE; the flow uses docs_text if wired). Never breaks the brain.
    try { require_once __DIR__.'/nm_solutionkb.php';
        if (function_exists('nm_kb_search_books')) {
            $sig=$ctx['signal']??[]; $bq=trim((string)($sig['title']??'').' '.(string)($sig['summary']??$sig['text']??$sig['detail']??''));
            if ($bq==='') $bq=trim((string)($sig['kind']??'').' '.(string)($dev['kind']??''));
            if ($bq!==''){ $__bk=nm_kb_search_books($conn,$bq); $payload['docs']=$__bk; $payload['docs_text']=nm_kb_docs_context($__bk); }
        }
    } catch (\Throwable $e) {}
    // non-blocking: an 8s timeout means "dispatched, working async" — only a connect error fails.
    [$code,$resp,$err] = nm_n8n_call($conn,'autopilot-v2',$payload,8);
    if ($code===0 && $err && stripos($err,'timed out')===false) {
        nm_ap2_event($conn,$sid,$node_id,'error','dispatch failed: '.$err);
        nm_ap2_session_set($conn,$sid,['status'=>'error','summary'=>'dispatch failed']);
        try { $conn->query("UPDATE nm_ap2_signals SET status='new', session_id=NULL WHERE id=$signal_id"); } catch (\Throwable $e) {}   // uq_fp_open collision would 500 the scan endpoint
        return ['ok'=>false,'error'=>$err];
    }
    return ['ok'=>true,'session_id'=>$sid];
}

// ── READ-tool runner (the bot's "eyes") — reuses v1's data where possible ────
// ── ROUTING knowledge (reuses the Routing Command Center engine: real forwarding fabric) ──
// Route fetch is live SSH-per-router → we read through a 10-min cache so voice/chat answers fast.
function nm_ap2_routers($conn): array {
    $out = []; try { $r = $conn->query("SELECT id, display_name, ip_address, os_icon FROM nm_nodes WHERE LOWER(os_icon) IN ('mikrotik','routeros') ORDER BY id");
        while ($r && $x = $r->fetch_assoc()) $out[] = $x; } catch (\Throwable $e) {}
    return $out;
}
// "Can traffic get from SRC to DST?" — resolves the ingress router, then simulates the forwarding path.
function nm_ap2_reachability($conn, string $src, string $dst): array {
    if (!function_exists('nm_routing_path')) require_once __DIR__ . '/nm_routing.php';
    nm_routing_ensure($conn); $TTL = 600;
    $dstIp = trim($dst);
    if (!nm_routing_is_ip($dstIp)) { $nid = nm_ap2_resolve_node($conn, $dstIp); if ($nid) $dstIp = nm_ap2_node_ip($conn, $nid); }
    if (!nm_routing_is_ip($dstIp)) return ['ok'=>false,'error'=>"destination '$dst' is not a valid IPv4 or a known node"];
    $routers = nm_ap2_routers($conn);
    if (!$routers) return ['ok'=>false,'error'=>'no MikroTik/RouterOS routers are monitored — cannot simulate routing'];
    $fromId = 0; $note = ''; $srcT = trim($src);
    if ($srcT !== '') {
        $sid = nm_ap2_resolve_node($conn, $srcT);
        foreach ($routers as $rr) if ((int)$rr['id'] === $sid) { $fromId = $sid; $note = 'from '.$rr['display_name']; break; }
        if (!$fromId) {   // src is a host/IP → find the router whose CONNECTED subnet owns it (the ingress)
            $srcIp = nm_routing_is_ip($srcT) ? $srcT : ($sid ? nm_ap2_node_ip($conn, $sid) : '');
            if ($srcIp && nm_routing_is_ip($srcIp)) {
                foreach ($routers as $rr) { $node = nm_router_node($conn, (int)$rr['id']); if (!$node) continue;
                    foreach ((nm_routing_fetch($conn, $node, $TTL)['routes'] ?? []) as $rt) {
                        if (($rt['protocol'] ?? '') === 'connected' && !empty($rt['net']) && nm_routing_in_cidr($srcIp, (int)nm_routing_ip2long($rt['net']), (int)$rt['prefix'])) {
                            $fromId = (int)$rr['id']; $note = 'ingress '.$rr['display_name'].' (owns '.$rt['dst'].')'; break 2; } } }
            }
        }
    }
    if (!$fromId) { $fromId = (int)$routers[0]['id']; $note = 'assumed ingress '.$routers[0]['display_name']; }
    $path = nm_routing_path($conn, $fromId, $dstIp, 12, $TTL);
    $oc = $path['outcome'] ?? '?';
    $verdict = $oc === 'delivered' ? 'reachable' : ($oc === 'internet' ? 'reachable-via-internet-gateway' : 'unreachable');
    return ['ok'=>true,'data'=>['src'=>$srcT ?: '(default)','dst'=>$dstIp,'ingress'=>$note,'outcome'=>$oc,'verdict'=>$verdict,'hops'=>$path['hops'] ?? []]];
}
// Which routers hold a route to DST (longest-prefix match per router).
function nm_ap2_route_lookup($conn, string $dst): array {
    if (!function_exists('nm_routing_lpm')) require_once __DIR__ . '/nm_routing.php';
    nm_routing_ensure($conn); $TTL = 600;
    $dstIp = trim($dst);
    if (!nm_routing_is_ip($dstIp)) { $nid = nm_ap2_resolve_node($conn, $dstIp); if ($nid) $dstIp = nm_ap2_node_ip($conn, $nid); }
    if (!nm_routing_is_ip($dstIp)) return ['ok'=>false,'error'=>"'$dst' is not a valid IPv4 or a known node"];
    $rows = [];
    foreach (nm_ap2_routers($conn) as $rr) { $node = nm_router_node($conn, (int)$rr['id']); if (!$node) continue;
        $best = nm_routing_lpm(nm_routing_fetch($conn, $node, $TTL)['routes'] ?? [], $dstIp);
        $rows[] = ['router'=>$rr['display_name'],'match'=>$best ? $best['dst'] : null,
                   'via'=>$best ? ($best['gw_ip'] ?: $best['gw_iface']) : null,'protocol'=>$best ? $best['protocol'] : 'none']; }
    return ['ok'=>true,'data'=>['dst'=>$dstIp,'routers'=>$rows]];
}
// Recent routing-table churn for a router (added/removed routes vs the last snapshot).
function nm_ap2_route_drift($conn, int $nid): array {
    if (!function_exists('nm_routing_diff')) require_once __DIR__ . '/nm_routing.php';
    nm_routing_ensure($conn);
    $node = nm_router_node($conn, $nid); if (!$node) return ['ok'=>false,'error'=>'router not found'];
    $routes = nm_routing_fetch($conn, $node, 600)['routes'] ?? [];
    $d = nm_routing_diff($conn, $nid, $routes);
    return ['ok'=>true,'data'=>['node_id'=>$nid,'added'=>$d['added'],'removed'=>$d['removed'],'had_baseline'=>$d['had_prev']]];
}

// ── DATABASE knowledge (Data Core / DB Observatory): status + metrics + replication + advice ──
// No `db` given → a summary of ALL monitored databases; a name/id → the full report for that one.
function nm_ap2_db_report($conn, string $ref): array {
    if (!$conn->query("SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_db_targets' LIMIT 1")->num_rows)
        return ['ok'=>false,'error'=>'no database monitoring on this install'];
    $targets = [];
    try { $r=$conn->query("SELECT id,display_name,engine,node_id,host,port,db_name,role,enabled,last_status,last_error,last_version,last_checked FROM nm_db_targets WHERE enabled=1 ORDER BY display_name");
          while($r&&$x=$r->fetch_assoc()) $targets[]=$x; } catch(\Throwable $e){ return ['ok'=>false,'error'=>'db read failed']; }
    if (!$targets) return ['ok'=>false,'error'=>'no databases are being monitored'];
    $ref = trim($ref); $t = null;
    if ($ref!=='') foreach($targets as $x){ if ((string)$x['id']===$ref || strcasecmp((string)$x['display_name'],$ref)===0 || strcasecmp((string)($x['db_name']??''),$ref)===0 || stripos((string)$x['display_name'],$ref)!==false){ $t=$x; break; } }
    if (!$t) {   // summary of ALL
        return ['ok'=>true,'data'=>['databases'=>array_map(fn($x)=>[
            'name'=>$x['display_name'],'engine'=>$x['engine'],'role'=>$x['role'],'status'=>$x['last_status'] ?: 'unknown',
            'error'=>$x['last_error'],'checked'=>$x['last_checked']], $targets)]];
    }
    $tid=(int)$t['id']; $sample=null; $repl=null; $advice=[]; $drift=null;
    // guard: on installs missing these optional tables/columns, mysqli (exception mode) would throw + 500 the tool.
    try {
        $q1=$conn->query("SELECT connections,max_connections,threads_running,uptime_s,blocked,slow,sampled_at FROM nm_db_samples WHERE target_id=$tid ORDER BY id DESC LIMIT 1"); $sample=$q1?$q1->fetch_assoc():null;
        $q2=$conn->query("SELECT io_running,sql_running,seconds_behind,last_error,source_host,sampled_at FROM nm_db_repl WHERE target_id=$tid ORDER BY id DESC LIMIT 1"); $repl=$q2?$q2->fetch_assoc():null;
        $q3=$conn->query("SELECT kind,title,risk,benefit FROM nm_db_advice WHERE target_id=$tid AND status='proposed' ORDER BY id DESC LIMIT 8"); while($q3&&$x=$q3->fetch_assoc()) $advice[]=$x;
        $q4=$conn->query("SELECT summary,detected_at FROM nm_db_schema_drift WHERE target_id=$tid ORDER BY id DESC LIMIT 1"); $drift=$q4?$q4->fetch_assoc():null;
    } catch (\Throwable $e) {}
    return ['ok'=>true,'data'=>[
        'name'=>$t['display_name'],'engine'=>$t['engine'],'role'=>$t['role'],'host'=>$t['host'].':'.$t['port'],'db'=>$t['db_name'],
        'status'=>$t['last_status'] ?: 'unknown','error'=>$t['last_error'],'version'=>$t['last_version'],'last_checked'=>$t['last_checked'],
        'metrics'=>$sample,'replication'=>$repl,'open_advice'=>$advice,'schema_drift'=>$drift]];
}

// ── MIKROTIK FIREWALL knowledge (mtfw): ruleset, A→B trace (routing+NAT+firewall), drift, live traffic, address-lists ──
function nm_ap2_fw_node($conn, string $ref) {
    if (!function_exists('nm_mtfw_supported')) { @require_once __DIR__ . '/nm_mtfw.php'; }
    $nid = nm_ap2_resolve_node($conn, $ref); if (!$nid) return [null, 'router not found: ' . $ref];
    $node = function_exists('nm_router_node') ? nm_router_node($conn, $nid) : null;
    if (!$node) return [null, 'router not found'];
    if (!nm_mtfw_supported($node)) return [null, ($node['display_name'] ?? $ref) . ' is not a MikroTik router'];
    return [$node, ''];
}
function nm_ap2_firewall_rules($conn, string $ref, string $table = 'filter'): array {
    [$node, $err] = nm_ap2_fw_node($conn, $ref); if (!$node) return ['ok'=>false,'error'=>$err];
    if (!in_array($table, nm_mtfw_tables(), true)) $table = 'filter';
    $f = nm_mtfw_fetch($conn, $node, $table); if (empty($f['ok'])) return $f;
    $rules = [];
    foreach ($f['rules'] as $i => $r) $rules[] = ['n'=>$i, 'chain'=>$r['chain'] ?? '', 'action'=>$r['action'] ?? '',
        'disabled'=>!empty($r['props']['disabled']) || !empty($r['disabled']),
        'summary'=>function_exists('nm_mtfw_rule_summary') ? nm_mtfw_rule_summary($r) : (($r['chain'] ?? '') . ' ' . ($r['action'] ?? ''))];
    return ['ok'=>true,'data'=>['router'=>$node['display_name'],'table'=>$table,'count'=>count($rules),'rules'=>array_slice($rules, 0, 60)]];
}
function nm_ap2_firewall_check($conn, string $ref, array $pkt): array {
    [$node, $err] = nm_ap2_fw_node($conn, $ref); if (!$node) return ['ok'=>false,'error'=>$err];
    $r = nm_mtfw_route_emulate($conn, $node, $pkt); if (empty($r['ok'])) return $r;
    return ['ok'=>true,'data'=>['router'=>$node['display_name'],'src'=>$r['src'],'dst'=>$r['dst'],'verdict'=>$r['verdict'],
        'kind'=>$r['kind'],'routed'=>$r['routed'],'out_if'=>$r['out_if'],'next_hop'=>$r['next_hop'],
        'hints'=>$r['hints'] ?? [],'steps'=>array_slice($r['steps'] ?? [], 0, 12)]];
}
function nm_ap2_firewall_drift($conn, string $ref, string $table = 'filter'): array {
    [$node, $err] = nm_ap2_fw_node($conn, $ref); if (!$node) return ['ok'=>false,'error'=>$err];
    if (!in_array($table, nm_mtfw_tables(), true)) $table = 'filter';
    $f = nm_mtfw_fetch($conn, $node, $table); if (empty($f['ok'])) return $f;
    $d = nm_mtfw_drift($conn, (int)$node['id'], $table, $f['rules']);
    return ['ok'=>true,'data'=>['router'=>$node['display_name'],'table'=>$table] + (is_array($d) ? $d : ['drift'=>$d])];
}
function nm_ap2_firewall_torch($conn, string $ref, int $cap = 40): array {
    [$node, $err] = nm_ap2_fw_node($conn, $ref); if (!$node) return ['ok'=>false,'error'=>$err];
    $t = nm_mtfw_torch($conn, $node, [], $cap); if (empty($t['ok'])) return $t;
    return ['ok'=>true,'data'=>['router'=>$node['display_name'],'total'=>$t['total'] ?? 0,'shown'=>count($t['rows'] ?? []),'connections'=>array_slice($t['rows'] ?? [], 0, $cap)]];
}
function nm_ap2_firewall_addrlists($conn, string $ref): array {
    [$node, $err] = nm_ap2_fw_node($conn, $ref); if (!$node) return ['ok'=>false,'error'=>$err];
    $a = nm_mtfw_fetch_addrlists($conn, $node); if (empty($a['ok'])) return $a;
    return ['ok'=>true,'data'=>['router'=>$node['display_name']] + $a];
}

// ── TOPOLOGY knowledge: what's connected to a node + blast-radius if it fails (causal troubleshooting) ──
// Neighbors come from the same graph the map/Chaos use: explicit nm_links + gateway edges.
function nm_ap2_connections($conn, string $ref): array {
    if (!function_exists('nm_chaos_graph')) { @require_once __DIR__ . '/nm_chaos.php'; }
    $nid = nm_ap2_resolve_node($conn, $ref); if (!$nid) return ['ok'=>false,'error'=>'node not found: ' . $ref];
    $G = nm_chaos_graph($conn);
    $name = $G['names'][$nid] ?? ('node ' . $nid);
    $neighbors = [];
    foreach (array_keys($G['adj'][$nid] ?? []) as $mid) $neighbors[$mid] = ['id'=>(int)$mid,'name'=>$G['names'][$mid] ?? ('node ' . $mid),'via'=>'topology'];
    // enrich the explicit links with the interface + label the operator wired
    try { $r = $conn->query("SELECT l.a_node_id,l.z_node_id,l.label, ia.if_name a_if, iz.if_name z_if
            FROM nm_links l LEFT JOIN nm_interfaces ia ON ia.id=l.a_iface_id LEFT JOIN nm_interfaces iz ON iz.id=l.z_iface_id
            WHERE l.enabled=1 AND (l.a_node_id=$nid OR l.z_node_id=$nid)");
        while ($r && $x = $r->fetch_assoc()) { $isA = (int)$x['a_node_id'] === $nid; $other = $isA ? (int)$x['z_node_id'] : (int)$x['a_node_id'];
            if (isset($neighbors[$other])) { $neighbors[$other]['via'] = 'wired link'; $neighbors[$other]['label'] = $x['label'];
                $neighbors[$other]['local_iface'] = $isA ? $x['a_if'] : $x['z_if']; $neighbors[$other]['remote_iface'] = $isA ? $x['z_if'] : $x['a_if']; } } } catch (\Throwable $e) {}
    return ['ok'=>true,'data'=>['node'=>$name,'neighbor_count'=>count($neighbors),'neighbors'=>array_values($neighbors)]];
}
// "If this node fails, what breaks?" — reuses the Chaos Test cascade + business-service impact.
function nm_ap2_blast_radius($conn, string $ref): array {
    if (!function_exists('nm_chaos_simulate')) { @require_once __DIR__ . '/nm_chaos.php'; }
    $nid = nm_ap2_resolve_node($conn, $ref); if (!$nid) return ['ok'=>false,'error'=>'node not found: ' . $ref];
    $s = nm_chaos_simulate($conn, $nid);
    $svc = array_values(array_filter($s['services'] ?? [], fn($x) => ($x['impact'] ?? 0) > 0));
    return ['ok'=>true,'data'=>[
        'failed'=>$s['fail']['name'] ?? $ref, 'is_core_root'=>!empty($s['fail_is_root']),
        'affected_count'=>$s['blast_count'] ?? 0,
        'affected_nodes'=>array_map(fn($b)=>$b['name'], $s['blast'] ?? []),
        'services_impacted'=>array_map(fn($x)=>['name'=>$x['name'],'status'=>$x['status'],'impact_pct'=>$x['impact']], $svc)]];
}

// ── tool activity log (drives the futuristic 'live tool' cockpit panel) ──
function nm_ap2_tool_summary(string $tool, array $args, array $result): string {
    $d = is_array($result['data'] ?? null) ? $result['data'] : [];
    switch ($tool) {
        case 'reachability': return ($args['src'] ?: 'network') . ' → ' . ($d['dst'] ?? $args['dst'] ?? '?') . ' : ' . strtoupper((string)($d['verdict'] ?? (!empty($result['ok']) ? '?' : 'error')));
        case 'route_lookup': return 'routes to ' . ($d['dst'] ?? $args['dst'] ?? '?') . ' on ' . (is_array($d['routers'] ?? null) ? count($d['routers']) : 0) . ' router(s)';
        case 'locate_ip': return !empty($d['owner']) ? (($d['ip']??'IP').' → '.$d['owner']['node'].(!empty($d['owner']['interface'])?(' ('.$d['owner']['interface'].')'):'')) : (($d['ip']??'IP').' — not a monitored device IP');
        case 'route_drift':  return 'route drift +' . count($d['added'] ?? []) . ' / -' . count($d['removed'] ?? []);
        case 'run_show_command': return ($args['command'] ?? 'command') . ' @ node ' . ($d['node_id'] ?? $args['node'] ?? '?');
        case 'ping_host':    return 'ping ' . ($args['ip'] ?? '?');
        default: return $tool . (!empty($args) ? ' ' . substr(json_encode($args), 0, 60) : '');
    }
}
// Start a tool run → insert a 'running' row so the cockpit shows a spinner + "still working…" WHILE the
// (slow, SSH-bound) tool executes. mysqli autocommits, so a concurrent cockpit poll sees it immediately.
function nm_ap2_tool_log_start($conn, string $channel, string $tool, array $args): int {
    try { $aj = json_encode($args); $run = 'running'; $sum = 'running…';
        $st = $conn->prepare("INSERT INTO nm_ap2_tool_events (channel,tool,args_json,ok,status,summary) VALUES (?,?,?,0,?,?)");
        $st->bind_param('sssss', $channel, $tool, $aj, $run, $sum); $st->execute(); $id = (int)$st->insert_id; $st->close();
        return $id;
    } catch (\Throwable $e) { return 0; }
}
// Finish a started run → flip the SAME row to 'done' with the verdict + rich data the panel renders.
function nm_ap2_tool_log_finish($conn, int $id, string $channel, string $tool, array $args, array $result): void {
    if ($id <= 0) { nm_ap2_tool_log($conn, $channel, $tool, $args, $result); return; }   // start failed → one-shot
    try {
        $okI = !empty($result['ok']) ? 1 : 0; $done = 'done';
        $summary = substr(nm_ap2_tool_summary($tool, $args, $result), 0, 255);
        $dj = isset($result['data']) ? substr(json_encode($result['data']), 0, 12000) : null;
        $st = $conn->prepare("UPDATE nm_ap2_tool_events SET ok=?, status=?, summary=?, data_json=? WHERE id=?");
        $st->bind_param('isssi', $okI, $done, $summary, $dj, $id); $st->execute(); $st->close();
        $conn->query("DELETE FROM nm_ap2_tool_events WHERE id < (SELECT mx-300 FROM (SELECT MAX(id) mx FROM nm_ap2_tool_events) t)");
    } catch (\Throwable $e) {}
}
// One-shot (start+finish in a single 'done' row) — kept for callers that don't need the running state.
function nm_ap2_tool_log($conn, string $channel, string $tool, array $args, array $result): void {
    try {
        $okI = !empty($result['ok']) ? 1 : 0; $done = 'done';
        $summary = substr(nm_ap2_tool_summary($tool, $args, $result), 0, 255);
        $aj = json_encode($args);
        $dj = isset($result['data']) ? substr(json_encode($result['data']), 0, 12000) : null;
        $st = $conn->prepare("INSERT INTO nm_ap2_tool_events (channel,tool,args_json,ok,status,summary,data_json) VALUES (?,?,?,?,?,?,?)");
        $st->bind_param('sssisss', $channel, $tool, $aj, $okI, $done, $summary, $dj); $st->execute(); $st->close();
        $conn->query("DELETE FROM nm_ap2_tool_events WHERE id < (SELECT mx-300 FROM (SELECT MAX(id) mx FROM nm_ap2_tool_events) t)");
    } catch (\Throwable $e) {}
}

function nm_ap2_run_tool($conn, int $sid, string $tool, array $args): array {
    $node = nm_ap2_session_node($conn,$sid);
    switch ($tool) {
        case 'reachability':
            return nm_ap2_reachability($conn, (string)($args['src'] ?? ''), (string)($args['dst'] ?? ''));
        case 'route_lookup':
            return nm_ap2_route_lookup($conn, (string)($args['dst'] ?? ''));
        case 'route_drift':
            return nm_ap2_route_drift($conn, $node ?: nm_ap2_resolve_node($conn, _nm_ap2_arg_node($args)));
        case 'database_report':
            return nm_ap2_db_report($conn, (string)($args['db'] ?? ''));
        case 'firewall_rules':
            return nm_ap2_firewall_rules($conn, _nm_ap2_arg_node($args), (string)($args['table'] ?? 'filter'));
        case 'firewall_check':
            return nm_ap2_firewall_check($conn, _nm_ap2_arg_node($args), ['src'=>(string)($args['src'] ?? ''),'dst'=>(string)($args['dst'] ?? ''),'protocol'=>(string)($args['proto'] ?? ''),'dst-port'=>(string)($args['dport'] ?? '')]);
        case 'firewall_drift':
            return nm_ap2_firewall_drift($conn, _nm_ap2_arg_node($args), (string)($args['table'] ?? 'filter'));
        case 'firewall_traffic':
            return nm_ap2_firewall_torch($conn, _nm_ap2_arg_node($args), (int)($args['limit'] ?? 40));
        case 'firewall_addrlists':
            return nm_ap2_firewall_addrlists($conn, _nm_ap2_arg_node($args));
        case 'connections':
            return nm_ap2_connections($conn, _nm_ap2_arg_node($args));
        case 'blast_radius':
            return nm_ap2_blast_radius($conn, _nm_ap2_arg_node($args));
        case 'get_full_context': case 'get_health': case 'get_interfaces':
            return $node && function_exists('nm_aip_gather_context') ? ['ok'=>true,'data'=>nm_aip_gather_context($conn,$node,true)] : ['ok'=>true,'data'=>[]];
        case 'get_fleet_map':
            $rows=[]; try { $r=$conn->query("SELECT name,ip,kind,containers FROM nm_ap2_fleet"); while($r && $x=$r->fetch_assoc()){ $x['containers']=json_decode($x['containers']?:'[]',true); $rows[]=$x; } } catch (\Throwable $e) {}
            return ['ok'=>true,'data'=>['nodes'=>$rows]];
        case 'read_container_logs':
            $ctr=(string)($args['container']??''); $lim=max(1,min(200,(int)($args['limit']??50)));
            $rows=[]; try { $st=$conn->prepare("SELECT log_ts,stream,message FROM container_logs WHERE container_name=? ORDER BY id DESC LIMIT ?"); $st->bind_param('si',$ctr,$lim); $st->execute(); $r=$st->get_result(); while($x=$r->fetch_assoc())$rows[]=$x; $st->close(); } catch (\Throwable $e) {}
            return ['ok'=>true,'data'=>['container'=>$ctr,'lines'=>$rows]];
        case 'search_kb':
            if (function_exists('nm_kb_search')) return ['ok'=>true,'data'=>['matches'=>nm_kb_search($conn,(string)($args['query']??''))]];
            return ['ok'=>true,'data'=>['matches'=>[]]];
        default:
            // delegate the rest to v1's hardened read runner (ping_host/read_logs/get_netflow_top/…)
            if ($node && function_exists('nm_aip_run_tool')) {
                return nm_aip_run_tool($conn, (int)$node, $tool, $args);   // v1 expects int node_id
            }
            return ['ok'=>false,'error'=>"unknown read tool: $tool"];
    }
}

// ── ONE conversational exchange with NEURU (shared by the text cockpit AND voice) ──
// Runs the full chat ReAct: store the user turn, ship a live fleet snapshot + read-tool
// catalog + callback to the `autopilot-v2-chat` flow, get {reply, command}, optionally
// apply the command (text path only — guarded), store the bot turn. Voice (autopilotv2_vapi.php)
// and text (autopilotv2.php ep=chat) both call this so there is ONE brain + ONE memory.
//   $by            = who spoke ('operator' | 'voice' | username) — used when applying a command
//   $allowCommands = apply a returned structural command? true for text, false for voice (Phase A)
// Returns ['ok','reply','command','applied','error'].
function nm_ap2_chat_exchange($conn, string $msg, string $by = 'operator', bool $allowCommands = true): array {
    $msg = trim($msg);
    if ($msg === '') return ['ok' => false, 'reply' => '', 'command' => null, 'applied' => null, 'error' => 'empty'];
    // store the user turn (shared voice+text memory)
    try { $st = $conn->prepare("INSERT INTO nm_ap2_chat (role,message) VALUES ('user',?)"); $st->bind_param('s', $msg); $st->execute(); $st->close(); } catch (\Throwable $e) {}

    // LIVE fleet snapshot (never the empty cache). Deep questions → the flow calls the read-tools.
    $fleet = nm_ap2_fleet_snapshot($conn);
    $hist = []; try { $r = $conn->query("SELECT role,message FROM nm_ap2_chat WHERE message IS NOT NULL ORDER BY id DESC LIMIT 8"); while ($r && $x = $r->fetch_assoc()) $hist[] = ['role' => $x['role'] === 'bot' ? 'assistant' : 'user', 'content' => $x['message']]; $hist = array_reverse($hist); } catch (\Throwable $e) {}
    $watching = []; try { $r = $conn->query("SELECT channel_key FROM nm_ap2_channels WHERE enabled=1"); while ($r && $x = $r->fetch_assoc()) $watching[] = $x['channel_key']; } catch (\Throwable $e) {}
    $rules = []; try { $r = $conn->query("SELECT match_type,match_val,policy FROM nm_ap2_rules WHERE active=1 LIMIT 40"); while ($r && $x = $r->fetch_assoc()) $rules[] = $x; } catch (\Throwable $e) {}
    $inflight = 0; try { $r = $conn->query("SELECT COUNT(*) n FROM nm_ap2_sessions WHERE status IN('queued','active','awaiting_approval')"); $inflight = (int)($r ? $r->fetch_assoc()['n'] : 0); } catch (\Throwable $e) {}
    $chat_flow_url = ''; try { $wh = nm_n8n_webhook_by_slug($conn, 'autopilot-v2-chat'); $chat_flow_url = (string)($wh['url'] ?? ''); } catch (\Throwable $e) {}
    $cbase = function_exists('nm_n8n_callback_base') ? rtrim(nm_n8n_callback_base($conn, $chat_flow_url), '/') : '';
    // RECALL — inject what NEURU has already learned that's relevant to this question (so it never starts from zero)
    $mems = []; try { foreach (nm_ap2_mem_recall($conn, $msg, 6) as $m) $mems[] = ['kind'=>$m['kind'],'about'=>$m['scope'],'fact'=>($m['subject']!==''?($m['subject'].' — '):'').$m['content']]; } catch (\Throwable $e) {}
    $payload = ['message' => $msg, 'history' => $hist, 'fleet' => $fleet, 'memory' => $mems,
        'tools' => nm_ap2_chat_tools(),
        'callback' => ['tool' => $cbase . '/autopilotv2_api.php?ep=chat_tool'],
        'bot_state' => ['watching' => $watching, 'rules' => $rules, 'signals_in_flight' => $inflight, 'enabled' => nm_ap2_enabled($conn)]];
    // Books RAG — attach reference-book context for the user's question (ADDITIVE; flow uses docs_text if wired). Never breaks the chat.
    try { require_once __DIR__.'/nm_solutionkb.php';
        if (function_exists('nm_kb_search_books') && trim((string)$msg)!==''){ $__bk=nm_kb_search_books($conn,(string)$msg); $payload['docs']=$__bk; $payload['docs_text']=nm_kb_docs_context($__bk); }
    } catch (\Throwable $e) {}
    [$code, $resp, $err] = function_exists('nm_n8n_call') ? nm_n8n_call($conn, 'autopilot-v2-chat', $payload, 40) : [0, null, 'n8n unavailable'];
    $reply = ''; $command = null;
    if (is_array($resp)) { $reply = (string)($resp['reply'] ?? ''); $command = $resp['command'] ?? null; }
    if ($reply === '') $reply = $err ? ('NEURU could not reach its brain right now (' . $err . ').') : 'NEURU is thinking, but returned no reply.';
    $applied = null;
    // the reply is ALREADY computed — never let a secondary command-apply (unguarded helpers) 500 the chat + lose it
    if ($allowCommands && is_array($command) && !empty($command['op']) && function_exists('nm_ap2_chat_apply')) { try { $applied = nm_ap2_chat_apply($conn, $command, $by); } catch (\Throwable $e) { $applied = ['error'=>'apply_failed']; } }
    try { $st = $conn->prepare("INSERT INTO nm_ap2_chat (role,message,command) VALUES ('bot',?,?)"); $cj = $command ? json_encode($command) : null; $st->bind_param('ss', $reply, $cj); $st->execute(); $st->close(); } catch (\Throwable $e) {}
    // LEARN — persist facts the flow explicitly extracted, and catch a user correction as a high-confidence memory
    try {
        if (is_array($resp) && !empty($resp['learn']) && is_array($resp['learn'])) foreach ($resp['learn'] as $L) { if(!is_array($L)) continue;
            nm_ap2_mem_add($conn, (string)($L['kind']??'fact'), (string)($L['scope']??$L['about']??'general'), (string)($L['subject']??''), (string)($L['fact']??$L['content']??''), ['source'=>'flow','confidence'=>(float)($L['confidence']??0.75),'by'=>$by]); }
        if (preg_match('/\b(no,|en realidad|actually|est[aá]s? (mal|equivocad)|incorrecto|te equivocas|eso no( es)?|no es (as[ií]|cierto)|es falso|that\'?s (wrong|incorrect)|corrige|correcci[oó]n|recuerda( que)?|remember that|aprende que|que sepas que|ten en cuenta|para que sepas|apunta que|anota que|for the record)\b/iu', $msg)) {
            $ents = function_exists('_nm_ap2_mem_entities') ? _nm_ap2_mem_entities($msg) : [];
            nm_ap2_mem_add($conn, 'correction', (!empty($ents)?$ents[0]:'general'), mb_substr($msg,0,80), $msg, ['source'=>'user','confidence'=>0.9,'by'=>$by]);
        }
    } catch (\Throwable $e) {}
    return ['ok' => true, 'reply' => $reply, 'command' => $command, 'applied' => $applied, 'error' => '', 'memory_used' => count($mems)];
}

// ── CHAT read-tools (fleet-wide Q&A — NOT session-bound; the chat flow calls them via ep=chat_tool) ──
// These let NEURU's chat answer ANY question about ANY node: which nodes are up, a node's full vitals,
// interfaces/bandwidth, netflow top talkers, traffic by application, traffic by COUNTRY (GeoIP), anomalies.
// ─────────────────────────────────────────────────────────────────────────────
// NEURU MEMORY — the regenerative learning layer. Everything NEURU learns (network
// facts, corrections, preferences, observations) is stored here and recalled as
// CONTEXT before every answer, so it never starts from zero. Pure MySQL (FULLTEXT +
// exact entity match); no external vector store needed.
// ─────────────────────────────────────────────────────────────────────────────
function nm_ap2_mem_ensure($conn): void {
    static $done=false; if($done) return; $done=true;
    try { $conn->query("CREATE TABLE IF NOT EXISTS nm_ap2_memory (
        id INT AUTO_INCREMENT PRIMARY KEY,
        kind VARCHAR(24) NOT NULL DEFAULT 'fact',
        scope VARCHAR(120) NOT NULL DEFAULT 'general',
        subject VARCHAR(191) NOT NULL DEFAULT '',
        content TEXT,
        keywords VARCHAR(255) DEFAULT '',
        confidence FLOAT DEFAULT 0.7,
        source VARCHAR(24) DEFAULT 'chat',
        pinned TINYINT DEFAULT 0,
        superseded TINYINT DEFAULT 0,
        use_count INT DEFAULT 0,
        created_by VARCHAR(64) DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used DATETIME NULL,
        KEY k_scope (scope), KEY k_kind (kind),
        FULLTEXT KEY ft (subject, content, keywords)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); } catch (\Throwable $e) {}
    // schema-drift: an OLD table may lack the ft index → FULLTEXT recall would silently die forever. Add it if missing.
    try { $r=$conn->query("SHOW INDEX FROM nm_ap2_memory WHERE Key_name='ft'"); if($r && $r->num_rows===0) $conn->query("ALTER TABLE nm_ap2_memory ADD FULLTEXT ft (subject,content,keywords)"); } catch (\Throwable $e) {}
}
// soft retention: keep pinned + corrections forever; drop the least-useful (unused, low-confidence, oldest) above a cap.
function _nm_ap2_mem_prune($conn): void {
    try { $r=$conn->query("SELECT COUNT(*) n FROM nm_ap2_memory"); $n=(int)($r?$r->fetch_assoc()['n']:0);
        if($n>1200){ $del=$n-1000; $conn->query("DELETE FROM nm_ap2_memory WHERE pinned=0 AND kind<>'correction' ORDER BY (use_count>0) ASC, confidence ASC, created_at ASC LIMIT ".(int)$del); }
    } catch (\Throwable $e) {}
}
// pull the salient entities from a piece of text: IPs, node/router-ish tokens (WORD-01, sg-mikrotik), and long words
function _nm_ap2_mem_entities(string $t): array {
    $out=[]; if(preg_match_all('/\b\d{1,3}(?:\.\d{1,3}){3}\b/', $t, $m)) foreach($m[0] as $ip) $out[$ip]=1;
    if(preg_match_all('/\b[A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)+\b/', $t, $m)) foreach($m[0] as $tok){ if(strlen($tok)>=4) $out[strtolower($tok)]=1; }
    return array_keys($out);
}
function _nm_ap2_mem_keywords(string $t): string {
    $ents = _nm_ap2_mem_entities($t);
    $words=[]; if(preg_match_all('/[a-záéíóúñ]{4,}/iu', mb_strtolower($t), $m)){ $stop=['para'=>1,'como'=>1,'esta'=>1,'este'=>1,'pero'=>1,'porque'=>1,'cuando'=>1,'donde'=>1,'that'=>1,'this'=>1,'with'=>1,'from'=>1,'have'=>1,'about'=>1,'router'=>1,'nodo'=>1]; foreach($m[0] as $w){ if(!isset($stop[$w])) $words[$w]=1; } }
    return substr(implode(' ', array_slice(array_merge($ents, array_keys($words)), 0, 30)), 0, 255);
}
// store (or reinforce) one memory. Dedup by (scope, subject): an existing one is updated + its confidence nudged up.
function nm_ap2_mem_add($conn, string $kind, string $scope, string $subject, string $content, array $opts=[]): int {
    nm_ap2_mem_ensure($conn);
    $kind=substr(trim($kind)?:'fact',0,24); $scope=substr(trim($scope)?:'general',0,120);
    $subject=substr(trim($subject),0,191); $content=trim($content);
    if($content==='' && $subject==='') return 0;
    if($subject==='') $subject=substr($content,0,80);
    $kw=substr((string)($opts['keywords'] ?? _nm_ap2_mem_keywords($subject.' '.$content.' '.$scope)),0,255);
    $conf=(float)($opts['confidence'] ?? 0.7); $src=substr((string)($opts['source'] ?? 'chat'),0,24);
    $by=substr((string)($opts['by'] ?? ''),0,64); $pin=!empty($opts['pinned'])?1:0;
    try {
        $st=$conn->prepare("SELECT id,confidence,pinned FROM nm_ap2_memory WHERE scope=? AND subject=? AND superseded=0 LIMIT 1");
        $st->bind_param('ss',$scope,$subject); $st->execute(); $ex=$st->get_result()->fetch_assoc(); $st->close();
        if($ex){ $id=(int)$ex['id'];
            if(!empty($ex['pinned'])) return $id;   // a PINNED (curated) memory is never silently overwritten
            $nc=min(0.99, max($conf,(float)$ex['confidence'])+0.05);
            $u=$conn->prepare("UPDATE nm_ap2_memory SET content=?, keywords=?, confidence=?, source=?, created_at=NOW(), superseded=0 WHERE id=?");
            $u->bind_param('ssdsi',$content,$kw,$nc,$src,$id); $u->execute(); $u->close(); return $id; }
        $st=$conn->prepare("INSERT INTO nm_ap2_memory (kind,scope,subject,content,keywords,confidence,source,pinned,created_by) VALUES (?,?,?,?,?,?,?,?,?)");
        $st->bind_param('sssssdsis',$kind,$scope,$subject,$content,$kw,$conf,$src,$pin,$by); $st->execute(); $id=(int)$st->insert_id; $st->close();
        if($id % 40 === 0) _nm_ap2_mem_prune($conn);   // occasional soft retention sweep
        return $id;
    } catch (\Throwable $e) { return 0; }
}
// recall the most relevant memories for a query: pinned first, then exact entity(IP/node) matches, then FULLTEXT terms.
function nm_ap2_mem_recall($conn, string $query, int $limit=6): array {
    nm_ap2_mem_ensure($conn); $query=trim($query); if($query==='') return [];
    $out=[]; $seen=[];
    $push=function($rows) use(&$out,&$seen){ foreach($rows as $x){ $id=(int)$x['id']; if(!isset($seen[$id])){ $seen[$id]=1; $out[]=$x; } } };
    $cols="id,kind,scope,subject,content,confidence,source";
    try { $r=$conn->query("SELECT $cols FROM nm_ap2_memory WHERE pinned=1 AND superseded=0 ORDER BY created_at DESC LIMIT 4"); $rows=[]; while($r&&$x=$r->fetch_assoc())$rows[]=$x; $push($rows); } catch (\Throwable $e) {}
    // exact entity match (IPs, node tokens present in the question) — reliable for IPs (FULLTEXT tokenizes dots away)
    $ents=_nm_ap2_mem_entities($query);
    foreach(array_slice($ents,0,8) as $e){ try { $st=$conn->prepare("SELECT $cols FROM nm_ap2_memory WHERE superseded=0 AND (scope=? OR keywords LIKE CONCAT('%',?,'%')) ORDER BY confidence DESC, created_at DESC LIMIT 3");
        $st->bind_param('ss',$e,$e); $st->execute(); $rr=$st->get_result(); $rows=[]; while($rr&&$x=$rr->fetch_assoc())$rows[]=$x; $st->close(); $push($rows); } catch (\Throwable $e2) {} }
    // FULLTEXT on the free-text terms
    try { $st=$conn->prepare("SELECT $cols, MATCH(subject,content,keywords) AGAINST (? IN NATURAL LANGUAGE MODE) rel FROM nm_ap2_memory WHERE superseded=0 AND MATCH(subject,content,keywords) AGAINST (? IN NATURAL LANGUAGE MODE) ORDER BY rel DESC LIMIT 8");
        $st->bind_param('ss',$query,$query); $st->execute(); $rr=$st->get_result(); $rows=[]; while($rr&&$x=$rr->fetch_assoc())$rows[]=$x; $st->close(); $push($rows); } catch (\Throwable $e) {}
    $out=array_slice($out,0,$limit);
    if($out){ $ids=implode(',',array_map(fn($m)=>(int)$m['id'],$out)); try{ $conn->query("UPDATE nm_ap2_memory SET use_count=use_count+1, last_used=NOW() WHERE id IN($ids)"); }catch(\Throwable $e){} }
    return $out;
}
function nm_ap2_mem_list($conn, string $q='', int $limit=100): array {
    nm_ap2_mem_ensure($conn); $rows=[];
    try { if($q!==''){ $st=$conn->prepare("SELECT id,kind,scope,subject,content,keywords,confidence,source,pinned,use_count,created_at,last_used FROM nm_ap2_memory WHERE superseded=0 AND (subject LIKE CONCAT('%',?,'%') OR content LIKE CONCAT('%',?,'%') OR scope LIKE CONCAT('%',?,'%')) ORDER BY pinned DESC, created_at DESC LIMIT ?");
            $st->bind_param('sssi',$q,$q,$q,$limit); $st->execute(); $r=$st->get_result(); while($x=$r->fetch_assoc())$rows[]=$x; $st->close(); }
        else { $st=$conn->prepare("SELECT id,kind,scope,subject,content,keywords,confidence,source,pinned,use_count,created_at,last_used FROM nm_ap2_memory WHERE superseded=0 ORDER BY pinned DESC, created_at DESC LIMIT ?"); $st->bind_param('i',$limit); $st->execute(); $r=$st->get_result(); while($x=$r->fetch_assoc())$rows[]=$x; $st->close(); }
    } catch (\Throwable $e) {}
    return $rows;
}
function nm_ap2_mem_del($conn, int $id): void { nm_ap2_mem_ensure($conn); try { $st=$conn->prepare("DELETE FROM nm_ap2_memory WHERE id=?"); $st->bind_param('i',$id); $st->execute(); $st->close(); } catch (\Throwable $e) {} }
function nm_ap2_mem_pin($conn, int $id, int $pin): void { nm_ap2_mem_ensure($conn); try { $st=$conn->prepare("UPDATE nm_ap2_memory SET pinned=? WHERE id=?"); $st->bind_param('ii',$pin,$id); $st->execute(); $st->close(); } catch (\Throwable $e) {} }
function nm_ap2_mem_count($conn): int { nm_ap2_mem_ensure($conn); try { $r=$conn->query("SELECT COUNT(*) n FROM nm_ap2_memory WHERE superseded=0"); return (int)($r?$r->fetch_assoc()['n']:0); } catch (\Throwable $e) { return 0; } }

function nm_ap2_chat_tools(): array {
    return [
        ['name'=>'list_nodes','desc'=>'List fleet nodes with up/down status + ip. args:{filter:"up"|"down"|"all"}'],
        ['name'=>'node_report','desc'=>'Full live context for ONE node: vitals (cpu/mem/disk), interfaces, netflow, forecast, recent findings. args:{node:"name or id"}'],
        ['name'=>'node_xray','desc'=>'Open the SURGICAL X-RAY — a live 3D anatomy of ONE node (CPU=beating heart, memory, GPU, network, disk, thermals, processes, containers) in the cockpit, AND return its current vitals to describe. Use when the operator asks to "show/open the x-ray" of a node, or a specific subsystem like its CPU/memory/GPU. args:{node:"name or id", focus?:"cpu|memory|gpu|network|disk|processes|containers|thermals"}'],
        ['name'=>'close_xray','desc'=>'CLOSE any on-screen full-screen overlay if open — the X-Ray 3D anatomy OR the network topology MAP. Use when the operator says "close the screen", "close the x-ray", "cierra la pantalla", "ciérralo", "close it". No args.'],
        ['name'=>'show_topology','desc'=>'Open the interactive 3D NETWORK TOPOLOGY MAP on screen — all nodes interconnected. Use for "muéstrame el mapa/la topología de la red", "el mapa completo", a specific router ("el segmento del core router", "qué conecta al core router"), or a subnet ("muéstrame el segmento 192.168.2.0"). args:{scope?:"all | a router/node name | a subnet CIDR"}'],
        ['name'=>'show_traffic','desc'=>'Open the LIVE TRAFFIC view (laser-per-interface) for a node and optionally focus interface(s). Use for "muéstrame el tráfico en vivo de la interfaz 1 del core router", "el tráfico del core router", "las interfaces 1 y 3". args:{node:"device name", interface?:"an interface number/name, or several"}'],
        ['name'=>'show_containers','desc'=>'Open the 3D CONTAINERS layer on screen — every Docker container across every node. Use for "muéstrame los contenedores", "los contenedores del nodo X", "enséñame el contenedor mysql". Focuses the named node/container. args:{node?:"device name", container?:"a container name or image"}'],
        ['name'=>'container_report','desc'=>'Full detail of ONE container to answer any question about it: state/health, image, VOLUMES with sizes (flags the biggest / dangerous >2GB), partition size (writable layer + rootfs), live CPU/mem/net + net-traffic history. args:{node?:"device", container:"container name / image / id"}'],
        ['name'=>'set_autonomous','desc'=>'Turn NEURU AUTONOMOUS mode ON or OFF (the master switch — ON = NEURU auto-investigates signals). Use for "prende/enciende/apaga/pausa el modo autónomo", "go autonomous", "pausa NEURU". Do it + confirm in ONE short sentence. args:{action:"on|off"}'],
        ['name'=>'scan_fleet','desc'=>'Run a fleet SCAN now (sweep every node + pick up new signals). Use for "escanea ahora", "scan now", "barre la flota". Do it + confirm briefly. No args.'],
        ['name'=>'set_panel','desc'=>'SHOW or HIDE one of the cockpit side panels. Use when the operator asks to "show/open/hide/close the chat panel", "el panel de queue/cola/señales", "el panel de razonamiento/reasoning", "muéstrame el chat", etc. The panels are hidden by default. args:{panel:"chat|queue|reasoning", action:"show|hide"}'],
        ['name'=>'interfaces','desc'=>'Interfaces + per-interface bandwidth for a node. args:{node}'],
        ['name'=>'bandwidth_top','desc'=>'Top bandwidth talkers (IPs, Mbps) fleet-wide or for one node, with country. args:{node?,dir:"src"|"dst",limit?,minutes?}'],
        ['name'=>'traffic_by_app','desc'=>'Top applications/ports by bandwidth. args:{node?,limit?,minutes?}'],
        ['name'=>'traffic_by_country','desc'=>'Bandwidth aggregated by COUNTRY via GeoIP (answers "which country sends/receives most traffic"). args:{dir?,limit?,minutes?}'],
        ['name'=>'anomalies','desc'=>'Recent AI-insight anomalies + active threats (Immunity). args:{node?}'],
        ['name'=>'run_show_command','desc'=>'Run ONE read-only CLI command on a device over SSH and return its raw output (e.g. "sh flash", "show ip route", "/interface print", "ping 8.8.8.8"). READ-ONLY — config/write commands are refused. args:{node,command}'],
        ['name'=>'reachability','desc'=>'Simulate whether traffic can get from SRC to DST across the monitored routers/firewalls, hop-by-hop over their REAL routing tables. Answers "can host A reach IP B?". Returns a verdict (reachable / reachable-via-internet / unreachable), the path, and where it stops. args:{src?:"ip or router name",dst:"ip or node"}'],
        ['name'=>'route_lookup','desc'=>'For a destination IP, show which monitored routers have a matching route (longest-prefix), with the gateway + protocol per router. args:{dst:"ip or node"}'],
        ['name'=>'locate_ip','desc'=>'WHOSE IP is this? Given an IP, say if it belongs to a monitored device — a device management IP OR a ROUTER/DEVICE INTERFACE IP (with the interface name) — and which routers forward toward it. Use whenever an IP comes up ("¿a qué router pertenece/va esta IP?", "is X monitored?"). An interface IP IS monitored — never say it is not. args:{ip:"the IP address"}'],
        ['name'=>'route_drift','desc'=>'Recent routing-table changes (routes added/removed vs the last snapshot) for one router. args:{node}'],
        ['name'=>'database_report','desc'=>'Monitored DATABASES (Data Core): no db → summary of ALL (name/engine/up-or-error); a db name/id → that DB\'s status, live metrics (connections, threads running, blocked, slow), replication lag, open tuning advice, schema drift. args:{db?:"database name or id"}'],
        ['name'=>'firewall_rules','desc'=>'MikroTik FIREWALL ruleset for a router: every rule (chain, action, match, disabled) in a table. args:{node:"mikrotik", table?:"filter"|"nat"|"mangle"}'],
        ['name'=>'firewall_check','desc'=>'Does the MikroTik firewall ALLOW traffic from SRC to DST? Full A→B emulation through routing + NAT + firewall rules → verdict (ACCEPT/DROP/NO ROUTE), which rule decides, and hints. args:{node:"mikrotik", src:"ip", dst:"ip", proto?, dport?}'],
        ['name'=>'firewall_drift','desc'=>'Firewall config drift on a router: rules added/removed vs the last snapshot. args:{node:"mikrotik", table?}'],
        ['name'=>'firewall_traffic','desc'=>'LIVE firewall traffic (connection tracking / torch) on a router: active connections with proto, src/dst, bytes, rate. args:{node:"mikrotik", limit?}'],
        ['name'=>'firewall_addrlists','desc'=>'MikroTik firewall ADDRESS LISTS on a router (e.g. blocked/blacklist/whitelist entries). args:{node:"mikrotik"}'],
        ['name'=>'connections','desc'=>'What is CONNECTED to a node — its neighbors in the topology (wired nm_links + gateway edges), with the interface + label. Answers "what equipment is connected to the core router?". args:{node}'],
        ['name'=>'blast_radius','desc'=>'If a node FAILS, what breaks — the downstream cascade of nodes cut off + which business SERVICES are impacted (Chaos Test). Answers "if the core router goes down, what is affected?". args:{node}'],
    ];
}
// read-only guard for run_show_command — refuse writes / shell chaining; allow show/print/ping/etc.
function nm_ap2_cmd_is_readonly(string $cmd): bool {
    $c = strtolower(trim($cmd)); if ($c === '') return false;
    if (preg_match('#[;&|`><\n]|\$\(#', $c)) return false;   // no shell chaining / redirection / subshell / newline
    // hard deny-list — any write / exec / exfil / pivot verb anywhere (word-bounded) → refuse. Covers the
    // bypasses the audit found: reset-configuration, ip route flush, /tool fetch, /import, script run, etc.
    if (preg_match('/\b(set|unset|add|remove|delete|del|create|make|rename|move|reset|reboot|restart|start|stop|shutdown|halt|poweroff|reload|refresh|write|erase|wipe|format|copy|save|store|commit|apply|restore|rollback|revert|upgrade|downgrade|update|install|uninstall|deploy|clear|flush|purge|drop|truncate|fetch|import|source|load|run|exec|eval|call|invoke|script|schedule|job|enable|disable|activate|deactivate|password|passwd|secret|credential|key|token|user|useradd|userdel|adduser|deluser|chmod|chown|chgrp|chpasswd|rm|mv|cp|dd|mkfs|mount|umount|kill|killall|pkill|tee|wget|curl|scp|sftp|tftp|ftp|nc|ncat|telnet|nmap|socat|iptables|nft|modprobe|insmod|rmmod|sysctl|crontab|reg)\b/', $c)) return false;
    $verb = preg_split('/\s+/', $c)[0] ?? '';
    // MikroTik / RouterOS path commands: ONLY the read operations (writes already denied above).
    // ping/traceroute are read-only diagnostics (e.g. "/ping 8.8.8.8", "/tool traceroute 1.1.1.1").
    if ($verb !== '' && $verb[0] === '/')
        return (bool)preg_match('/\b(print|export|monitor|get|find|value|health|ping|traceroute)\b/', $c);
    // otherwise the FIRST verb must be an explicit read command (file-read verbs like cat/ls dropped → exfil)
    $ok = ['show','sh','display','dis','ping','traceroute','tracert','netstat','ss','arp','ifconfig','ipconfig',
           'ip','nslookup','dig','host','mtr','lldpctl','lldpcli','uptime','free','df','du','ps','top','vmstat',
           'iostat','uname','hostname','whoami','who','id','date','lsof','netsh','journalctl','dmesg','systemctl'];
    return in_array($verb, $ok, true);
}
// Normalize a name for fuzzy matching: number-words→digits (spoken "uno"/"one"→1), lowercase, alnum-only,
// strip leading zeros in digit runs ("01"→"1"). So "main server 1" and "MAIN-SERVER-01" both → "mainserver1".
function _nm_ap2_norm(string $s): string {
    $s = strtolower(trim($s));
    $w = ['zero'=>'0','cero'=>'0','one'=>'1','uno'=>'1','una'=>'1','two'=>'2','dos'=>'2','three'=>'3','tres'=>'3','four'=>'4','cuatro'=>'4','five'=>'5','cinco'=>'5','six'=>'6','seis'=>'6','seven'=>'7','siete'=>'7','eight'=>'8','ocho'=>'8','nine'=>'9','nueve'=>'9'];
    $s = preg_replace_callback('/\b(' . implode('|', array_keys($w)) . ')\b/u', fn($m) => $w[$m[1]], $s) ?? $s;   // /u null on bad UTF-8
    $s = preg_replace('/[^a-z0-9]+/', '', (string)$s);
    $s = preg_replace_callback('/\d+/', fn($m) => (string)(int)$m[0], $s);   // 01 → 1
    return $s;
}
// Resolve a node from an id / display name / ip / SPOKEN name ("main server 1", "core router", "sg mikrotik").
// Fuzzy + scored so voice/chat never fails on natural phrasing; returns 0 (not a wrong guess) if nothing is close.
// Pull the node NAME/ID from an LLM/VAPI tool-call, tolerant of whatever key the brain chose.
// Different models label the same field 'node' / 'name' / 'node_name' / 'device' / 'server' / 'router' /
// 'host' — reading only 'node' made every server come back "not found" the moment the model picked another
// key. Deliberately EXCLUDES 'ip'/'target'/'src'/'dst' so it never collides with firewall/net-tool semantics.
function _nm_ap2_arg_node(array $args): string {
    foreach (['node','node_name','nodename','device','device_name','router','server','host','hostname','machine','name'] as $k) {
        if (isset($args[$k]) && trim((string)$args[$k]) !== '') return trim((string)$args[$k]);
    }
    return '';
}
function nm_ap2_resolve_node($conn, $ref): int {
    $ref = trim((string)$ref); if ($ref === '') return 0;
    if (ctype_digit($ref)) return (int)$ref;                         // numeric id
    try { $st=$conn->prepare("SELECT id FROM nm_nodes WHERE display_name=? OR ip_address=? LIMIT 1"); $st->bind_param('ss',$ref,$ref); $st->execute(); $r=$st->get_result()->fetch_row(); $st->close(); if ($r) return (int)$r[0]; } catch (\Throwable $e) {}
    if (filter_var($ref, FILTER_VALIDATE_IP)) {
        // an INTERFACE IP belongs to a monitored router/device — resolve it to the owning node (was the "not monitored" bug)
        try { $st=$conn->prepare("SELECT node_id FROM nm_interfaces WHERE if_ip_address=? LIMIT 1"); $st->bind_param('s',$ref); $st->execute(); $r=$st->get_result()->fetch_row(); $st->close(); if ($r) return (int)$r[0]; } catch (\Throwable $e) {}
        return 0;                                                    // a truly unmonitored IP is NOT a node (don't mis-map)
    }
    $q = _nm_ap2_norm($ref); if ($q === '') return 0;
    // query tokens, dropping articles/prepositions that add noise ("el core router" → core, router)
    $stop = ['el'=>1,'la'=>1,'los'=>1,'las'=>1,'un'=>1,'the'=>1,'a'=>1,'an'=>1,'de'=>1,'del'=>1,'en'=>1,'on'=>1,'of'=>1,'mi'=>1,'my'=>1,'is'=>1,'para'=>1,'to'=>1,'and'=>1,'y'=>1];
    $qt = [];
    // dedupe CONSECUTIVE identical tokens so a misheard "web 1.1"/"1 1" ("web","1","1") collapses to "web","1" and still matches WEB-01
    foreach (preg_split('/[^a-z0-9]+/i', strtolower($ref)) as $raw) { $raw = trim($raw); if ($raw === '' || isset($stop[$raw])) continue; $t = _nm_ap2_norm($raw); if ($t !== '' && (empty($qt) || end($qt) !== $t)) $qt[] = $t; }
    $best = 0; $bestScore = 0.0;
    try { $r = $conn->query("SELECT id,display_name FROM nm_nodes");
        while ($r && $x = $r->fetch_assoc()) {
            $n = _nm_ap2_norm((string)$x['display_name']); if ($n === '') continue;
            $sc = 0.0;
            if ($n === $q) { return (int)$x['id']; }                                        // normalized exact → done
            elseif (strlen($q) >= 3 && strpos($n, $q) !== false) $sc = 0.80 + 0.15 * (strlen($q) / max(1, strlen($n)));
            elseif (strlen($n) >= 3 && strpos($q, $n) !== false) $sc = 0.75 + 0.15 * (strlen($n) / max(1, strlen($q)));
            elseif ($qt) {
                // Token match with a FUZZY fallback so VOICE mistranscriptions still resolve
                // ("corp" heard for "core", "mikrotic" for "mikrotik"…). Each query token scores
                // its best match against the node's tokens: substring = 1.0, else a close
                // Levenshtein match (≤2 edits AND ≥70% similar, len ≥4) counts at 0.9. This is
                // what lets the AI Commander understand a slightly-misheard node name again.
                $ntoks = array_filter(array_map('strtolower', preg_split('/[^a-z0-9]+/i', (string)$x['display_name'])));
                $acc = 0.0;
                foreach ($qt as $t) {
                    if ($t === '' || (strlen($t) < 2 && !ctype_digit($t))) continue;
                    $bt = 0.0;
                    if (strpos($n, $t) !== false) $bt = 1.0;                                   // token is a substring of the whole name
                    else foreach ($ntoks as $nk) {
                        if ($nk === '') continue;
                        if (strpos($nk,$t)!==false || strpos($t,$nk)!==false) { $bt = 1.0; break; }
                        $L = max(strlen($t), strlen($nk));
                        if ($L >= 4) { $lev = levenshtein($t,$nk); $sim = 1 - $lev/$L; if ($lev <= 2 && $sim >= 0.70 && $sim*0.9 > $bt) $bt = $sim*0.9; }
                    }
                    $acc += $bt;
                }
                if ($acc > 0) $sc = 0.64 * ($acc / count($qt));                                // all/most tokens present (fuzzy-aware)
            }
            if ($sc > $bestScore) { $bestScore = $sc; $best = (int)$x['id']; }
        } } catch (\Throwable $e) {}
    return $bestScore >= 0.5 ? $best : 0;                             // below 0.5 → not confident → 0 (never a wrong router)
}
function nm_ap2_node_ip($conn, int $nid): string {
    try { $st=$conn->prepare("SELECT ip_address FROM nm_nodes WHERE id=?"); $st->bind_param('i',$nid); $st->execute(); $r=$st->get_result()->fetch_row(); $st->close(); return (string)($r[0]??''); } catch (\Throwable $e) { return ''; }
}
// live fleet snapshot (name + ip + up/down) — used both as the chat's base context AND the list_nodes tool
function nm_ap2_fleet_snapshot($conn, string $filter='all'): array {
    $down=[]; try { $r=$conn->query("SELECT node_id,last_status FROM nm_alert_state WHERE entity_type='node' AND last_status IN('down','degraded','lowerlayerdown','notpresent','testing')"); while($r&&$x=$r->fetch_assoc()) $down[(int)$x['node_id']]=strtolower($x['last_status']); } catch (\Throwable $e) {}
    $rows=[]; try { $r=$conn->query("SELECT id,display_name,ip_address FROM nm_nodes ORDER BY display_name");
        while($r&&$x=$r->fetch_assoc()){ $st=$down[(int)$x['id']]??'up';
            if ($filter==='up' && $st!=='up') continue; if ($filter==='down' && $st==='up') continue;
            $rows[]=['id'=>(int)$x['id'],'name'=>$x['display_name'],'ip'=>$x['ip_address'],'status'=>$st]; } } catch (\Throwable $e) {}
    return $rows;
}
// A spoken "panel de chat" / "chat panel" / "la cola" / "el razonamiento" is a UI PANEL, not a node → map to a key.
function _nm_ap2_panel_ref(string $ref): string {
    $r = mb_strtolower($ref);
    if (preg_match('/(chat|conversaci|mensaj|\btalk\b)/u', $r)) return 'chat';
    if (preg_match('/(queue|kiu|quiu|keu|\bqiu\b|\bcue\b|cola|se[nñ]al|senal|signal|lista)/u', $r)) return 'queue';
    if (preg_match('/(razona|reasoning|\breason\b|pensam|think|l[oó]gic)/u', $r)) return 'reason';
    return '';
}
// If a node tool was handed a panel request (assistant not yet re-provisioned with set_panel), DO the panel action
// + return a friendly success so it speaks sensibly instead of "node not found". Only when no real node matched,
// OR the phrase explicitly says "panel"/"pantalla".
function _nm_ap2_node_is_panel($conn, string $ref, bool $noNode): ?array {
    if (!$noNode && !preg_match('/panel|pantalla/i', $ref)) return null;
    $pk = _nm_ap2_panel_ref($ref); if ($pk === '') return null;
    $nm = ['chat'=>'chat','queue'=>'signal queue','reason'=>'reasoning'][$pk] ?? $pk;
    // Do NOT touch panel state here — the cockpit's local voice handler already opened/closed it with the correct
    // show/hide intent (this tool only sees the panel NAME, not the verb, so writing state would fight it / re-open on
    // a "close"). This just gives the assistant a coherent reply instead of "node not found".
    return ['ok'=>true,'data'=>['is_panel'=>$nm,'note'=>'"'.$nm.'" is a UI panel (not a node); it is toggled directly on the operator\'s screen. Just acknowledge briefly ("listo") — do not say you cannot.']];
}
function nm_ap2_chat_run_tool($conn, string $tool, array $args): array {
    $tool = preg_replace('/[^a-z_]/','',strtolower($tool));
    // GLOBAL panel guard — ANY node-taking tool (node_report, node_xray, interfaces, run_show_command, route_lookup…)
    // handed a PANEL request ("panel de cola", "el chat"…) is a UI panel, not a node. Reply coherently so the assistant
    // NEVER says "node not found". The cockpit's local voice handler already toggled the panel with the right intent.
    $argNode = _nm_ap2_arg_node($args);
    if ($tool !== 'set_panel' && $argNode !== '') {
        $pan = _nm_ap2_node_is_panel($conn, $argNode, !nm_ap2_resolve_node($conn, $argNode));
        if ($pan) return $pan;
    }
    switch ($tool) {
        case 'list_nodes': {
            $f = in_array($args['filter']??'all',['up','down','all'],true)?$args['filter']:'all';
            $rows = nm_ap2_fleet_snapshot($conn,$f);
            return ['ok'=>true,'data'=>['count'=>count($rows),'nodes'=>$rows]];
        }
        case 'node_report': {
            $ref = _nm_ap2_arg_node($args);
            $nid = nm_ap2_resolve_node($conn,$ref); if (!$nid) return ['ok'=>false,'error'=>'node not found: '.($ref!==''?$ref:'(no node name given)')];
            return ['ok'=>true,'data'=>function_exists('nm_aip_gather_context')?nm_aip_gather_context($conn,$nid):['node_id'=>$nid]];
        }
        case 'locate_ip': {
            $ip = trim((string)($args['ip'] ?? $args['node'] ?? $args['dst'] ?? ''));
            if ($ip==='' || !filter_var($ip, FILTER_VALIDATE_IP)) return ['ok'=>false,'error'=>'need a valid IP address'];
            $out = ['ip'=>$ip, 'monitored'=>false, 'owner'=>null];
            // 1) is it a device's management IP?
            try { $st=$conn->prepare("SELECT id,display_name FROM nm_nodes WHERE ip_address=? LIMIT 1"); $st->bind_param('s',$ip); $st->execute(); $r=$st->get_result()->fetch_assoc(); $st->close();
                if($r){ $out['monitored']=true; $out['owner']=['node'=>$r['display_name'],'node_id'=>(int)$r['id'],'as'=>'device management IP']; } } catch (\Throwable $e) {}
            // 2) is it a monitored INTERFACE IP? (the case that used to fail)
            if(empty($out['owner'])){ try { $st=$conn->prepare("SELECT i.node_id,n.display_name,i.if_name,i.display_name dn FROM nm_interfaces i JOIN nm_nodes n ON n.id=i.node_id WHERE i.if_ip_address=? LIMIT 1"); $st->bind_param('s',$ip); $st->execute(); $r=$st->get_result()->fetch_assoc(); $st->close();
                if($r){ $iface=$r['dn']?:$r['if_name']; $out['monitored']=true; $out['owner']=['node'=>$r['display_name'],'node_id'=>(int)$r['node_id'],'interface'=>$iface,'as'=>'router/device interface IP']; } } catch (\Throwable $e) {} }
            // 3) which routers forward toward it (longest-prefix over their real routing tables) + connected-subnet owner
            try { $rl = nm_ap2_route_lookup($conn, $ip); if(!empty($rl['ok'])) $out['routing'] = $rl['data']['routers'] ?? []; } catch (\Throwable $e) {}
            // LEARN — remember whose IP this is so we never answer "not monitored" for it again
            if(!empty($out['owner'])){ $o=$out['owner']; $desc=$ip.' is '.($o['as']??'owned by').' of '.$o['node'].(!empty($o['interface'])?(' (interface '.$o['interface'].')'):'');
                try { nm_ap2_mem_add($conn,'topology',$ip,$ip.' → '.$o['node'],$desc,['source'=>'tool','confidence'=>0.9]); } catch (\Throwable $e) {} }
            return ['ok'=>true,'data'=>$out];
        }
        case 'node_xray': {
            $ref = _nm_ap2_arg_node($args);
            $nid = nm_ap2_resolve_node($conn,$ref); if (!$nid) return ['ok'=>false,'error'=>'node not found: '.($ref!==''?$ref:'(no node name given)')];
            $fk = preg_replace('/[^a-z]/','',strtolower((string)($args['focus']??$args['metric']??'')));
            $fmap = ['cpu'=>'cpu','processor'=>'cpu','heart'=>'cpu','load'=>'cpu','memory'=>'memory','mem'=>'memory','ram'=>'memory','gpu'=>'gpu','graphics'=>'gpu','vram'=>'gpu','network'=>'network','net'=>'network','traffic'=>'network','bandwidth'=>'network','disk'=>'disks','disks'=>'disks','storage'=>'disks','filesystem'=>'disks','process'=>'processes','processes'=>'processes','proc'=>'processes','container'=>'containers','containers'=>'containers','docker'=>'containers','temp'=>'sensors','temperature'=>'sensors','thermal'=>'sensors','thermals'=>'sensors','sensors'=>'sensors','heat'=>'sensors','overview'=>'core','status'=>'core','summary'=>'core'];
            $foc = $fmap[$fk] ?? '';
            $x = function_exists('nm_ap2_xray_full') ? nm_ap2_xray_full($conn,$nid) : ['ok'=>false];
            // signal the cockpit to OPEN the 3D anatomy (chat: reply-poll; voice: ui_poll)
            try { nm_ap2_set($conn,'ap2_ui_xray', json_encode(['action'=>'open','node_id'=>$nid,'name'=>$x['name']??'','focus'=>$foc,'ts'=>time()])); } catch (\Throwable $e){}
            // concise vitals for the LLM/voice to speak (not the heavy full payload)
            $sum = ['opened_xray'=>true,'node'=>$x['name']??'','ip'=>$x['ip']??'','kind'=>$x['kind']??'','state'=>$x['status']['state']??'unknown','focus'=>$foc?:'full anatomy'];
            if(isset($x['cpu']['pct'])) $sum['cpu_pct']=$x['cpu']['pct'];
            if(isset($x['memory']['pct'])) $sum['mem_pct']=$x['memory']['pct'];
            if(!empty($x['gpu'])) $sum['gpu']=array_map(fn($g)=>['name'=>$g['name'],'util'=>$g['util'],'temp'=>$g['temp']],$x['gpu']);
            if(!empty($x['network'])) $sum['net_rx_kbps']=$x['network']['rx_kbps']??null;
            if(!empty($x['disks'])) $sum['disks']=array_map(fn($d)=>['mount'=>$d['mount'],'pct'=>$d['pct']],array_slice($x['disks'],0,6));
            if(!empty($x['sensors']['max_temp'])) $sum['max_temp_c']=$x['sensors']['max_temp'];
            if(!empty($x['processes'])) $sum['top_processes']=array_slice(array_map(fn($p)=>$p['name'].' '.round((float)$p['cpu']).'%',$x['processes']),0,5);
            if(!empty($x['uptime_s'])) $sum['uptime_s']=$x['uptime_s'];
            return ['ok'=>true,'data'=>$sum];
        }
        case 'close_xray': {
            try { nm_ap2_set($conn,'ap2_ui_xray', json_encode(['action'=>'close','ts'=>time()])); } catch (\Throwable $e){}
            return ['ok'=>true,'data'=>['closed'=>true]];
        }
        case 'show_topology': {
            $sc = trim((string)($args['scope'] ?? $args['segment'] ?? $args['node'] ?? 'all'));
            try { nm_ap2_set($conn,'ap2_ui_xray', json_encode(['action'=>'topology','scope'=>$sc,'ts'=>time()])); } catch (\Throwable $e){}
            $t = function_exists('nm_ap2_topology') ? nm_ap2_topology($conn,$sc) : ['ok'=>false];
            return ['ok'=>true,'data'=>['opened_map'=>true,'scope'=>$t['scope']??$sc,'title'=>$t['title']??'','nodes'=>$t['count']??0,'links'=>$t['edge_count']??0,'note'=>'Topology map opened on screen — confirm in ONE short sentence.']];
        }
        case 'show_traffic': {
            $node = _nm_ap2_arg_node($args);
            $iface = trim((string)($args['interface'] ?? $args['iface'] ?? $args['port'] ?? ''));
            if($node==='') return ['ok'=>false,'error'=>'which node? name the device'];
            $t = function_exists('nm_ap2_traffic') ? nm_ap2_traffic($conn,$node,$iface) : ['ok'=>false];
            if(empty($t['ok'])) return $t;
            try { nm_ap2_set($conn,'ap2_ui_xray', json_encode(['action'=>'traffic','node'=>$node,'iface'=>$iface,'ts'=>time()])); } catch (\Throwable $e){}
            $sum=['opened_traffic'=>true,'node'=>$t['node'],'interfaces'=>$t['count']];
            $foc=[]; foreach(($t['interfaces']??[]) as $if){ if(in_array($if['id'],$t['focus']??[],true)) $foc[]=$if['name'].' ▾'.$if['in_mbps'].' ▴'.$if['out_mbps'].' Mbps'; }
            if($foc) $sum['focused']=$foc;
            $sum['note']='Live traffic opened on screen — confirm in ONE short sentence with the rate(s).';
            return ['ok'=>true,'data'=>$sum];
        }
        case 'show_containers': {
            $node = trim((string)($args['node'] ?? $args['device'] ?? $args['host'] ?? ''));
            $ctr  = trim((string)($args['container'] ?? $args['name'] ?? $args['cid'] ?? ''));
            $c = function_exists('nm_ap2_containers') ? nm_ap2_containers($conn,$node,$ctr) : ['ok'=>false];
            if(empty($c['ok'])) return $c;
            try { nm_ap2_set($conn,'ap2_ui_xray', json_encode(['action'=>'containers','node'=>$node,'container'=>$ctr,'ts'=>time()])); } catch (\Throwable $e){}
            $sum=['opened_containers'=>true,'node'=>$c['node'],'count'=>$c['count'],'running'=>$c['running']];
            $foc=[]; foreach(($c['containers']??[]) as $ct){ if(in_array($ct['n'],$c['focus']??[],true)) $foc[]=$ct['name'].' ('.$ct['state'].')'; }
            if($foc) $sum['focused']=array_slice($foc,0,12);
            $sum['note']='Containers layer opened on screen — confirm in ONE short sentence.';
            return ['ok'=>true,'data'=>$sum];
        }
        case 'container_report': {
            $node = trim((string)($args['node'] ?? $args['device'] ?? ''));
            $ctr  = trim((string)($args['container'] ?? $args['name'] ?? $args['cid'] ?? ''));
            if($node===''&&$ctr==='') return ['ok'=>false,'error'=>'name a node and/or a container'];
            $c = function_exists('nm_ap2_containers') ? nm_ap2_containers($conn,$node,$ctr) : ['ok'=>false];
            if(empty($c['ok'])) return $c;
            $list=$c['containers']??[]; $fo=$c['focus']??[]; $pick=null;
            if($fo){ foreach($list as $ct){ if($ct['n']===$fo[0]){ $pick=$ct; break; } } }
            if(!$pick && $list) $pick=$list[0];
            if(!$pick) return ['ok'=>false,'error'=>'no matching container'];
            $d = function_exists('nm_ap2_container_detail') ? nm_ap2_container_detail($conn,(int)$pick['endpoint_id'],(string)$pick['cid'],(string)$pick['node']) : ['ok'=>false];
            return empty($d['ok']) ? $d : ['ok'=>true,'data'=>$d['data']];
        }
        case 'set_panel': {
            $p = preg_replace('/[^a-z]/','',strtolower((string)($args['panel']??'')));
            $map = ['chat'=>'chat','talk'=>'chat','conversation'=>'chat','conversacion'=>'chat','messages'=>'chat','mensajes'=>'chat',
                    'queue'=>'queue','cola'=>'queue','signal'=>'queue','signals'=>'queue','senal'=>'queue','senales'=>'queue','list'=>'queue','lista'=>'queue',
                    'reasoning'=>'reason','reason'=>'reason','razonamiento'=>'reason','razona'=>'reason','thinking'=>'reason','logic'=>'reason','logica'=>'reason'];
            $pk = $map[$p] ?? ''; if($pk===''){ foreach($map as $kk=>$vv){ if($p!=='' && strpos($p,$kk)!==false){ $pk=$vv; break; } } }
            if($pk===''){ return ['ok'=>false,'error'=>'unknown panel (use chat, queue, or reasoning): '.($args['panel']??'')]; }
            $show = strtolower((string)($args['action']??'show'))!=='hide';
            try { nm_ap2_set($conn,'ap2_ui_xray', json_encode(['action'=>'panel','panel'=>$pk,'show'=>$show?1:0,'ts'=>time()])); } catch (\Throwable $e){}
            return ['ok'=>true,'data'=>['panel'=>$pk,'shown'=>$show,'note'=>'Done — confirm in ONE short sentence.']];
        }
        case 'set_autonomous': {
            $a = strtolower((string)($args['action']??'on'));
            $on = !in_array($a, ['off','disable','pause','pausar','stop','apagar'], true);
            // SECURITY: do NOT push this via the shared/global ui channel (it would flip OTHER operators' autonomy master
            // switch). The operator's own local voice handler toggles it for their session; here we only confirm.
            return ['ok'=>true,'data'=>['autonomous'=>$on,'note'=>'NEURU autonomous mode '.($on?'ON':'paused').' — confirm in ONE short sentence, do not ramble.']];
        }
        case 'scan_fleet': {
            // the operator's local voice handler runs the scan for their session — no global ui push (avoids fan-out/double-scan).
            return ['ok'=>true,'data'=>['scanning'=>true,'note'=>'Fleet scan started — confirm in ONE short sentence.']];
        }
        case 'interfaces': {
            $nid = nm_ap2_resolve_node($conn,(string)($args['node']??'')); if (!$nid) return ['ok'=>false,'error'=>'node not found'];
            return function_exists('nm_aip_run_tool')?nm_aip_run_tool($conn,$nid,'get_interfaces',[]):['ok'=>false,'error'=>'unavailable'];
        }
        case 'bandwidth_top': {
            require_once __DIR__.'/nm_netflow.php';
            $mins=max(1,min(1440,(int)($args['minutes']??60))); $dir=($args['dir']??'src')==='dst'?'dst':'src'; $lim=max(1,min(30,(int)($args['limit']??10)));
            $ex=''; if(!empty($args['node'])){ $nid=nm_ap2_resolve_node($conn,(string)$args['node']); if($nid) $ex=nm_ap2_node_ip($conn,$nid); }
            $tt=function_exists('nm_nf_top_talkers')?nm_nf_top_talkers($conn,$mins,$dir,$ex,$lim):[];
            if (function_exists('nm_geo_badge')) foreach($tt as &$t){ $g=@nm_geo_badge($conn,(string)($t['ip']??'')); if(is_array($g)&&!empty($g['country'])) $t['country']=$g['country']; }
            return ['ok'=>true,'data'=>['window_min'=>$mins,'dir'=>$dir,'talkers'=>$tt]];
        }
        case 'traffic_by_app': {
            require_once __DIR__.'/nm_netflow.php';
            $mins=max(1,min(1440,(int)($args['minutes']??60))); $lim=max(1,min(30,(int)($args['limit']??10)));
            $ex=''; if(!empty($args['node'])){ $nid=nm_ap2_resolve_node($conn,(string)$args['node']); if($nid) $ex=nm_ap2_node_ip($conn,$nid); }
            return ['ok'=>true,'data'=>['window_min'=>$mins,'apps'=>function_exists('nm_nf_top_apps')?nm_nf_top_apps($conn,$mins,$ex,$lim):[]]];
        }
        case 'traffic_by_country': {
            require_once __DIR__.'/nm_netflow.php'; @require_once __DIR__.'/nm_nettools.php';
            $mins=max(1,min(1440,(int)($args['minutes']??60))); $dir=($args['dir']??'dst')==='src'?'src':'dst';
            $tt=function_exists('nm_nf_top_talkers')?nm_nf_top_talkers($conn,$mins,$dir,'',80):[]; $agg=[];
            foreach($tt as $t){ $g=function_exists('nm_geo_badge')?@nm_geo_badge($conn,(string)($t['ip']??'')):null;
                $c=is_array($g)&&!empty($g['country'])?$g['country']:'LAN/Private';
                if(!isset($agg[$c])) $agg[$c]=['country'=>$c,'flag'=>is_array($g)?($g['flag']??''):'','bytes'=>0.0,'mbps'=>0.0];
                $agg[$c]['bytes']+=(float)($t['bytes']??0); $agg[$c]['mbps']+=(float)($t['mbps']??0); }
            $agg=array_values($agg); usort($agg,fn($a,$b)=>$b['bytes']<=>$a['bytes']);
            return ['ok'=>true,'data'=>['window_min'=>$mins,'dir'=>$dir,'by_country'=>array_slice($agg,0,max(1,min(30,(int)($args['limit']??12))))]];
        }
        case 'anomalies': {
            $node = !empty($args['node']) ? nm_ap2_resolve_node($conn,(string)$args['node']) : 0;
            $ins=[]; try { $q="SELECT node_id,severity,title,created_at FROM nm_ai_insights WHERE status IN('open','acknowledged') AND kind<>'remediation'".($node?" AND node_id=".$node:"")." ORDER BY id DESC LIMIT 20";
                $r=$conn->query($q); while($r&&$x=$r->fetch_assoc()) $ins[]=$x; } catch (\Throwable $e) {}
            $thr=[]; try { if($conn->query("SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_threats' LIMIT 1")->num_rows){
                $r=$conn->query("SELECT indicator,ind_type,severity,category,created_at FROM nm_threats WHERE status='active' ORDER BY id DESC LIMIT 20"); while($r&&$x=$r->fetch_assoc()) $thr[]=$x; } } catch (\Throwable $e) {}
            return ['ok'=>true,'data'=>['insights'=>$ins,'threats'=>$thr]];
        }
        case 'run_show_command': {
            $nid = nm_ap2_resolve_node($conn,(string)($args['node']??'')); if (!$nid) return ['ok'=>false,'error'=>'node not found: '.($args['node']??'')];
            $cmd = trim((string)($args['command']??''));
            if ($cmd==='') return ['ok'=>false,'error'=>'no command given'];
            if (!nm_ap2_cmd_is_readonly($cmd)) return ['ok'=>false,'error'=>'refused: only READ-ONLY commands (show/print/ping/get/…) are allowed from chat — config/write commands need the autonomous risk-gate.'];
            @require_once __DIR__.'/nm_confmgr.php'; @require_once __DIR__.'/nm_secrets.php';
            if (!function_exists('nm_ssh_resolve') || !function_exists('nm_cm_ssh_fetch')) return ['ok'=>false,'error'=>'SSH transport unavailable on this install'];
            $ssh = nm_ssh_resolve($conn,$nid);
            if (!$ssh) return ['ok'=>false,'error'=>'no SSH credentials configured for this node'];
            try { $r = nm_cm_ssh_fetch($ssh, $cmd, 20); } catch (\Throwable $e) { return ['ok'=>false,'error'=>'ssh error: '.$e->getMessage()]; }
            $out = is_array($r) ? ($r['config'] ?? $r['output'] ?? $r['data'] ?? '') : (string)$r;   // nm_cm_ssh_fetch returns output under 'config'
            $okc = is_array($r) ? !empty($r['ok']) : ($out!=='');
            // audit every remote command NEURU runs from chat
            if (function_exists('nm_audit')) { try { nm_audit($conn,'ap2_chat_show_command',['node_id'=>$nid,'command'=>$cmd,'ok'=>$okc]); } catch (\Throwable $e) {} }
            return ['ok'=>$okc,'data'=>['node_id'=>$nid,'command'=>$cmd,'output'=>substr((string)$out,0,6000)],'error'=>$okc?null:(is_array($r)?($r['error']??'no output / command failed'):'no output')];
        }
        case 'reachability':
            return nm_ap2_reachability($conn, (string)($args['src'] ?? ''), (string)($args['dst'] ?? ''));
        case 'route_lookup':
            return nm_ap2_route_lookup($conn, (string)($args['dst'] ?? ''));
        case 'route_drift': {
            $nid = nm_ap2_resolve_node($conn, (string)($args['node'] ?? '')); if (!$nid) return ['ok'=>false,'error'=>'router not found: '.($args['node']??'')];
            return nm_ap2_route_drift($conn, $nid);
        }
        case 'database_report':
            return nm_ap2_db_report($conn, (string)($args['db'] ?? ''));
        case 'firewall_rules':
            return nm_ap2_firewall_rules($conn, _nm_ap2_arg_node($args), (string)($args['table'] ?? 'filter'));
        case 'firewall_check':
            return nm_ap2_firewall_check($conn, _nm_ap2_arg_node($args), ['src'=>(string)($args['src'] ?? ''),'dst'=>(string)($args['dst'] ?? ''),'protocol'=>(string)($args['proto'] ?? ''),'dst-port'=>(string)($args['dport'] ?? '')]);
        case 'firewall_drift':
            return nm_ap2_firewall_drift($conn, _nm_ap2_arg_node($args), (string)($args['table'] ?? 'filter'));
        case 'firewall_traffic':
            return nm_ap2_firewall_torch($conn, _nm_ap2_arg_node($args), (int)($args['limit'] ?? 40));
        case 'firewall_addrlists':
            return nm_ap2_firewall_addrlists($conn, _nm_ap2_arg_node($args));
        case 'connections':
            return nm_ap2_connections($conn, _nm_ap2_arg_node($args));
        case 'blast_radius':
            return nm_ap2_blast_radius($conn, _nm_ap2_arg_node($args));
    }
    return ['ok'=>false,'error'=>"unknown chat tool: $tool"];
}

// ── circuit breaker (anti-repeat vs nm_ap2_actions) ──────────────────────────
function nm_ap2_recurrence($conn, int $node, string $tool, string $ahash): int {
    try { $st=$conn->prepare("SELECT COUNT(*) c FROM nm_ap2_actions WHERE node_id=? AND tool=? AND args_hash=? AND status='done' AND created_at>(NOW()-INTERVAL 24 HOUR)");
          $st->bind_param('iss',$node,$tool,$ahash); $st->execute(); $r=$st->get_result()->fetch_row(); $st->close(); return $r?(int)$r[0]:0; } catch (\Throwable $e) { return 0; }
}

// ── PROPOSE an action — reuse v1's HARD guard + autonomy gate, own bookkeeping ─
function nm_ap2_propose_action($conn, int $sid, string $tool, array $args, string $risk, string $reason, bool $forceApproval=false): array {
    $node = nm_ap2_session_node($conn,$sid);
    $dev = $node ? nm_ap2_device($conn,$node) : ['autonomy_mode'=>'observe','allow_destructive'=>0,'allow_commands'=>0];
    // DOMAIN actions (fleet-wide: immunize / heal_apply / divert) — no node-SSH validation; ALWAYS require
    // operator approval (never auto). This is what surfaces "¿immunize X?" as Approve/Deny in the cockpit + Telegram.
    if (in_array($tool, ['immunize','heal_apply','firewall_block_ip','firewall_apply'], true)) {  // domain actions → ALWAYS ask
        $ahash = md5(json_encode($args));
        $sigid=null; try { $q=$conn->query("SELECT signal_id FROM nm_ap2_sessions WHERE id=$sid"); $sigid=$q?(int)($q->fetch_row()[0]??0):null; } catch (\Throwable $e) {}
        $nn = $node ?: null; $aid=0;
        try { $st=$conn->prepare("INSERT INTO nm_ap2_actions (session_id,signal_id,node_id,tool,args,args_hash,risk,status,auto) VALUES (?,?,?,?,?,?,?, 'proposed', 0)");
            $aj=substr(json_encode($args),0,255);
            $st->bind_param('iiissss',$sid,$sigid,$nn,$tool,$aj,$ahash,$risk); $st->execute(); $aid=$st->insert_id; $st->close(); } catch (\Throwable $e) {}
        nm_ap2_event($conn,$sid,$node,'act','proposing '.$tool.' '.substr(json_encode($args),0,120).' — '.$reason);
        nm_ap2_session_set($conn,$sid,['status'=>'awaiting_approval']);
        if (function_exists('nm_notify_send')) { try { nm_notify_send($conn,'aiopilot','warning','NEURU proposes: '.$tool,$reason,[]); } catch (\Throwable $e) {} }
        $tgSent=false; if ($aid && function_exists('nm_aip_tg_channel') && nm_aip_tg_channel($conn)) { try { $t=nm_ap2_tg_notify_action($conn,$aid); $tgSent=!empty($t['ok']); } catch (\Throwable $e) {} }
        return ['ok'=>true,'status'=>'proposed','needs_approval'=>true,'telegram'=>$tgSent];
    }
    // v1 hard guard (rejects SSH on ping/SNMP, service on non-linux, etc.) — takes node_id + tool
    if (function_exists('nm_aip_validate_action') && $node) {
        $v = nm_aip_validate_action($conn,$node,$tool);
        if (empty($v['ok'])) { nm_ap2_event($conn,$sid,$node,'act',"rejected $tool: ".($v['error']??'invalid')); return ['ok'=>true,'status'=>'rejected','rejected'=>($v['error']??'invalid')]; }
    }
    $ahash = md5(json_encode($args));
    $rec = $node ? nm_ap2_recurrence($conn,$node,$tool,$ahash) : 0;
    // autonomy gate (reuse v1's exact matrix)
    $auto = ($forceApproval || !function_exists('nm_aip_can_auto')) ? false : nm_aip_can_auto($dev['autonomy_mode'],$risk,(int)$dev['allow_destructive'],(int)$dev['allow_commands']);
    $mutating = in_array($tool,['ssh_command','restart_service','restart_container','block_ip','clear_logs_rotate'],true);
    if ($rec>=3 && $mutating) { $auto=false; $reason='[RECURRING x'.$rec.'] '.$reason; }   // circuit breaker → force human
    $status = $auto?'approved':'proposed';
    $aid=0; try { $st=$conn->prepare("INSERT INTO nm_ap2_actions (session_id,signal_id,node_id,tool,args,args_hash,risk,status,auto) VALUES (?,?,?,?,?,?,?,?,?)");
        $sigid=null; try { $q=$conn->query("SELECT signal_id FROM nm_ap2_sessions WHERE id=$sid"); $sigid=$q?(int)($q->fetch_row()[0]??0):null; } catch (\Throwable $e) {}
        $aj=substr(json_encode($args),0,255); $au=$auto?1:0;
        $st->bind_param('iiisssssi',$sid,$sigid,$node,$tool,$aj,$ahash,$risk,$status,$au); $st->execute(); $aid=$st->insert_id; $st->close(); } catch (\Throwable $e) {}
    nm_ap2_event($conn,$sid,$node,'act',($auto?'auto-run ':'proposing ')."$tool ".substr(json_encode($args),0,120)." — $reason");
    if ($auto) { nm_ap2_execute_action($conn,$aid); return ['ok'=>true,'status'=>'approved','recurrence'=>$rec]; }
    nm_ap2_session_set($conn,$sid,['status'=>'awaiting_approval']);
    if (function_exists('nm_notify_send')) { try { nm_notify_send($conn,'aiopilot','warning','NEURU Commander proposes: '.$tool,$reason,['node_id'=>$node]); } catch (\Throwable $e) {} }
    // Two-way Telegram approval (exactly like the v1 aiopilot): if THIS device opted in, push the proposed
    // action to Telegram with Approve/Deny buttons; the reply is handled by the shared poller (nm_aip_tg_poll
    // → ap2: branch). The operator can also Approve/Deny in the cockpit Approvals tab.
    // SEND to Telegram when EITHER this device opted in OR the Telegram notification channel is enabled
    // install-wide → the Approvals panel and Telegram stay in SYNC whenever Telegram is on (and stay silent
    // on installs where Telegram isn't enabled, e.g. the other test boxes). The reply is handled by the
    // shared poller (cron_aip_telegram → nm_aip_tg_poll → ap2: branch).
    $tgSent=false;
    $tgOn = !empty($dev['telegram_approve']) || (function_exists('nm_aip_tg_channel') && nm_aip_tg_channel($conn));
    if ($tgOn && $aid) { try { $t=nm_ap2_tg_notify_action($conn,$aid); $tgSent=!empty($t['ok']); } catch (\Throwable $e) {} }
    return ['ok'=>true,'status'=>'proposed','needs_approval'=>true,'recurrence'=>$rec,'telegram'=>$tgSent];
}

// ── Telegram Approve/Deny for V2 proposed actions — mirrors v1 aiopilot, RIDES THE SAME bot + poller ──
// (a second getUpdates poller would steal updates via the shared offset; the poller dispatches ap2: to us).
function nm_ap2_tg_ensure($conn): void {
    try { $conn->query("CREATE TABLE IF NOT EXISTS nm_ap2_tg_approvals (
        action_id BIGINT UNSIGNED PRIMARY KEY, token VARCHAR(24) NOT NULL, chat_id VARCHAR(40) NULL,
        message_id BIGINT NULL, status ENUM('pending','approved','denied','expired') NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, decided_at TIMESTAMP NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); } catch (\Throwable $e) {}
}
function nm_ap2_tg_notify_action($conn, int $aid): array {
    if (!function_exists('nm_aip_tg_channel') || !function_exists('nm_aip_tg_api')) return ['ok'=>false,'error'=>'telegram unavailable'];
    nm_ap2_tg_ensure($conn);
    $tg = nm_aip_tg_channel($conn); if (!$tg) return ['ok'=>false,'error'=>'no enabled Telegram channel'];
    $a=null; try { $st=$conn->prepare("SELECT a.*, n.display_name, n.ip_address FROM nm_ap2_actions a LEFT JOIN nm_nodes n ON n.id=a.node_id WHERE a.id=? LIMIT 1"); $st->bind_param('i',$aid); $st->execute(); $a=$st->get_result()->fetch_assoc(); $st->close(); } catch (\Throwable $e) {}
    if (!$a) return ['ok'=>false,'error'=>'action not found'];
    $esc = fn($s) => function_exists('nm_aip_tg_esc') ? nm_aip_tg_esc((string)$s) : (string)$s;
    $token = substr(bin2hex(random_bytes(8)),0,12);
    $risk=strtoupper((string)$a['risk']); $emoji=['LOW'=>'🟢','MEDIUM'=>'🟠','HIGH'=>'🔴'][$risk]??'⚪';
    $argsArr = json_decode((string)$a['args'],true) ?: [];
    $cmd = $a['tool']==='ssh_command' ? (string)($argsArr['command']??'') : trim($a['tool'].' '.(string)$a['args']);
    $target = $a['display_name'] ? ($a['display_name'].' ('.$a['ip_address'].')') : 'Fleet-wide · all Pi-holes + firewalls';
    $lines=["🧠 *NEURU Commander needs your approval*","",
        "*Target:* ".$esc($target),
        "*Action:* ".$esc($a['tool'])."   {$emoji} ".$esc($risk)." risk"];
    if ($cmd!=='') $lines[]="*Command:*\n```\n".$esc(mb_substr($cmd,0,600))."\n```";
    $lines[]=""; $lines[]="_Approve to run it now, or Deny to keep manual control._";
    $text=implode("\n",$lines);
    $kb=['inline_keyboard'=>[[
        ['text'=>'✅ Approve & run','callback_data'=>"ap2:{$aid}:{$token}:a"],
        ['text'=>'🚫 Deny','callback_data'=>"ap2:{$aid}:{$token}:d"]]]];
    $r=nm_aip_tg_api($tg['token'],'sendMessage',['chat_id'=>$tg['chat'],'text'=>$text,'parse_mode'=>'Markdown','disable_web_page_preview'=>true,'reply_markup'=>$kb]);
    if (empty($r['ok'])) $r=nm_aip_tg_api($tg['token'],'sendMessage',['chat_id'=>$tg['chat'],'text'=>preg_replace('/[*_`]/','',$text),'disable_web_page_preview'=>true,'reply_markup'=>$kb]);
    $mid=$r['result']['message_id']??null; $chat=(string)$tg['chat'];
    try { $st=$conn->prepare("INSERT INTO nm_ap2_tg_approvals (action_id,token,chat_id,message_id,status) VALUES (?,?,?,?, 'pending') ON DUPLICATE KEY UPDATE token=VALUES(token),message_id=VALUES(message_id),status='pending'"); $st->bind_param('issi',$aid,$token,$chat,$mid); $st->execute(); $st->close(); } catch (\Throwable $e) {}
    return ['ok'=>!empty($r['ok'])];
}
function nm_ap2_tg_callback($conn, array $tg, array $cb, string $data): void {
    $cbId=(string)($cb['id']??''); $chatId=(string)($cb['message']['chat']['id']??''); $msgId=(int)($cb['message']['message_id']??0);
    $who=trim((string)(($cb['from']['username']??'')?:($cb['from']['first_name']??'')));
    $parts=explode(':',$data); if (count($parts)<4) { @nm_aip_tg_api($tg['token'],'answerCallbackQuery',['callback_query_id'=>$cbId]); return; }
    $aid=(int)$parts[1]; $tok=$parts[2]; $verdict=$parts[3];
    nm_ap2_tg_ensure($conn);
    $pend=null; try { $q=$conn->query("SELECT * FROM nm_ap2_tg_approvals WHERE action_id=$aid LIMIT 1"); $pend=$q?$q->fetch_assoc():null; } catch (\Throwable $e) {}
    if (!$pend || !hash_equals((string)$pend['token'],(string)$tok)) { @nm_aip_tg_api($tg['token'],'answerCallbackQuery',['callback_query_id'=>$cbId,'text'=>'This request expired.']); return; }
    if (($pend['status']??'')!=='pending') { @nm_aip_tg_api($tg['token'],'answerCallbackQuery',['callback_query_id'=>$cbId,'text'=>'Already '.$pend['status'].'.']); return; }
    $note='via Telegram'.($who!==''?" ({$who})":'');
    if ($verdict==='a') {
        // the action could have been cleared (dismissed / session reaped) between propose and tap → say "expired"
        $exists=false; try { $q=$conn->query("SELECT 1 FROM nm_ap2_actions WHERE id=$aid LIMIT 1"); $exists=$q&&$q->num_rows>0; } catch (\Throwable $e) {}
        if (!$exists) { @nm_aip_tg_api($tg['token'],'answerCallbackQuery',['callback_query_id'=>$cbId,'text'=>'This request expired.']);
            if (function_exists('nm_aip_tg_edit_decided')) @nm_aip_tg_edit_decided($conn,$tg['token'],$chatId,$msgId,$aid,"⌛ *Expired* — the proposal is no longer available {$note}");
            try { $conn->query("UPDATE nm_ap2_tg_approvals SET status='expired',decided_at=NOW() WHERE action_id=$aid"); } catch (\Throwable $e) {} return; }
        try { $conn->query("UPDATE nm_ap2_actions SET status='approved' WHERE id=$aid AND status='proposed'"); } catch (\Throwable $e) {}
        $res=nm_ap2_execute_action($conn,$aid); $ok=!empty($res['ok']);
        try { $conn->query("UPDATE nm_ap2_tg_approvals SET status='approved',decided_at=NOW() WHERE action_id=$aid"); } catch (\Throwable $e) {}
        @nm_aip_tg_api($tg['token'],'answerCallbackQuery',['callback_query_id'=>$cbId,'text'=>$ok?'✅ Approved — running.':'⚠️ Approved but execution failed.']);
        if (function_exists('nm_aip_tg_edit_decided')) @nm_aip_tg_edit_decided($conn,$tg['token'],$chatId,$msgId,$aid,$ok?"✅ *Approved &amp; executed* {$note}":"⚠️ *Approved — execution failed* {$note}");
    } else {
        try { $conn->query("UPDATE nm_ap2_actions SET status='denied' WHERE id=$aid AND status='proposed'"); } catch (\Throwable $e) {}
        try { $conn->query("UPDATE nm_ap2_tg_approvals SET status='denied',decided_at=NOW() WHERE action_id=$aid"); } catch (\Throwable $e) {}
        @nm_aip_tg_api($tg['token'],'answerCallbackQuery',['callback_query_id'=>$cbId,'text'=>'🚫 Denied — manual control.']);
        if (function_exists('nm_aip_tg_edit_decided')) @nm_aip_tg_edit_decided($conn,$tg['token'],$chatId,$msgId,$aid,"🚫 *Denied* {$note}");
    }
}

// ── EXECUTE an approved action — reuse v1's hands (nm_aip_do) ─────────────────
// ── domain-action engines (fleet-wide, not node-SSH) ─────────────────────────
function nm_ap2_do_immunize($conn, array $args): array {
    if (!function_exists('nm_imm_vaccinate')) { @require_once __DIR__.'/nm_immunity.php'; }
    if (!function_exists('nm_imm_vaccinate')) return ['ok'=>false,'output'=>'immunity engine unavailable'];
    $tid = (int)($args['threat_id'] ?? 0);
    $ind = trim((string)($args['indicator'] ?? ''));
    if (!$tid && $ind!=='') {
        try { $st=$conn->prepare("SELECT id FROM nm_threats WHERE indicator=? AND status IN('pending','active') ORDER BY id DESC LIMIT 1"); $st->bind_param('s',$ind); $st->execute(); $r=$st->get_result()->fetch_row(); $st->close(); if($r)$tid=(int)$r[0]; } catch (\Throwable $e) {}
        // brand-new indicator (e.g. an attacker IP from Deception) → register it as a threat, then block
        if (!$tid && function_exists('nm_imm_add_threat')) {
            $type = filter_var($ind, FILTER_VALIDATE_IP) ? 'ip' : 'domain';
            $a = nm_imm_add_threat($conn,$ind,$type,'neuru','high','Promoted by NEURU Commander');
            $tid = (int)($a['id'] ?? 0);
        }
    }
    if ($tid<=0) return ['ok'=>false,'output'=>'no threat/indicator to immunize'];
    $r = nm_imm_vaccinate($conn,$tid); $ok=!empty($r['ok']);
    return ['ok'=>$ok,'output'=>$ok ? ('Immunized threat #'.$tid.' — blocked across all Pi-holes + firewalls. '.substr(json_encode($r),0,300)) : (string)($r['error']??'vaccinate failed')];
}
function nm_ap2_do_heal($conn, array $args): array {
    if (!function_exists('nm_heal_act')) { @require_once __DIR__.'/nm_heal.php'; }
    $eid=(int)($args['event_id'] ?? $args['incident_id'] ?? 0);
    if ($eid<=0) return ['ok'=>false,'output'=>'no heal event id'];
    if (function_exists('nm_heal_act')) { $r=nm_heal_act($conn,$eid); return ['ok'=>!empty($r['ok']),'output'=>substr(json_encode($r),0,400)]; }
    return ['ok'=>false,'output'=>'heal engine unavailable'];
}
// Block an IP on a MikroTik by adding it to the NEURU-BLOCK address list (a drop rule already references it).
// Low lockout risk → persist immediately (safe=false); the operator already approved this action.
function nm_ap2_do_fw_block($conn, array $args): array {
    if (!function_exists('nm_mtfw_obj_apply')) { @require_once __DIR__ . '/nm_mtfw.php'; }
    if (!function_exists('nm_mtfw_obj_apply')) return ['ok'=>false,'output'=>'firewall engine unavailable'];
    $nid = nm_ap2_resolve_node($conn, (string)($args['node'] ?? $args['router'] ?? ''));
    $node = $nid ? nm_router_node($conn, $nid) : null;
    if (!$node || !nm_mtfw_supported($node)) return ['ok'=>false,'output'=>'not a MikroTik router'];
    $ip = trim((string)($args['ip'] ?? $args['address'] ?? '')); if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok'=>false,'output'=>'invalid IP: '.$ip];
    $list = trim((string)($args['list'] ?? 'NEURU-BLOCK')); if ($list==='') $list='NEURU-BLOCK';
    $data = ['list'=>$list, 'address'=>$ip, 'comment'=>'NEURU: '.substr((string)($args['reason'] ?? 'blocked by NEURU Commander'), 0, 80)];
    $r = nm_mtfw_obj_apply($conn, $node, 'addrlist', 'add', $data, false, 2);
    $ok = !empty($r['ok']);
    return ['ok'=>$ok, 'output'=>$ok ? ('Blocked '.$ip.' → address-list "'.$list.'" on '.$node['display_name'].' (a drop rule already enforces it).') : (string)($r['error'] ?? 'apply failed')];
}
// Apply a firewall RULE change with anti-lockout: Safe-Apply arms an auto-rollback; keep() confirms only if
// SSH still works — if the change locked NEURU out, keep fails and the router auto-reverts within the window.
function nm_ap2_do_fw_apply($conn, array $args): array {
    if (!function_exists('nm_mtfw_apply')) { @require_once __DIR__ . '/nm_mtfw.php'; }
    if (!function_exists('nm_mtfw_apply')) return ['ok'=>false,'output'=>'firewall engine unavailable'];
    $nid = nm_ap2_resolve_node($conn, (string)($args['node'] ?? ''));
    $node = $nid ? nm_router_node($conn, $nid) : null;
    if (!$node || !nm_mtfw_supported($node)) return ['ok'=>false,'output'=>'not a MikroTik router'];
    $tbl = (string)($args['table'] ?? 'filter'); $table = in_array($tbl, nm_mtfw_tables(), true) ? $tbl : 'filter';
    $opIn = (string)($args['op'] ?? ''); $op = in_array($opIn, ['add','set','remove','enable','disable'], true) ? $opIn : '';
    if ($op === '') return ['ok'=>false,'output'=>'op must be add/set/remove/enable/disable'];
    $data = $args; unset($data['node'], $data['router'], $data['table'], $data['op'], $data['reason']);
    $r = nm_mtfw_apply($conn, $node, $op, $table, $data, true, 2);
    if (empty($r['ok'])) return ['ok'=>false,'output'=>(string)($r['error'] ?? 'apply failed')];
    $token = (string)($r['token'] ?? '');
    if (!empty($r['safe']) && $token !== '') {
        $k = nm_mtfw_keep($conn, $node, $token);
        if (empty($k['ok'])) return ['ok'=>true,'output'=>$op.' on '.$node['display_name'].'/'.$table.' applied but could NOT be confirmed (SSH check failed) — the router will AUTO-ROLLBACK in '.($r['window']??2).' min (anti-lockout).'];
    }
    return ['ok'=>true,'output'=>$op.' on '.$node['display_name'].'/'.$table.' applied + confirmed (Safe-Apply). '.substr((string)($r['desc'] ?? ''), 0, 140)];
}
// Advance a signal OUT of 'proposed'/'investigating' once its action(s) reached a terminal state
// (done/denied/failed) and nothing is still pending. Without this a signal shows "AWAITING YOU"
// forever after its action already ran or was denied (the stuck-honeypot bug). Safe: only settles
// when there is at least one finished action and zero still-pending — never touches live proposals.
function nm_ap2_settle_signal($conn, int $sigid): void {
    if ($sigid <= 0) return;
    try {
        $q = $conn->query("SELECT
            COALESCE(SUM(status IN('proposed','approved','executing')),0) pend,
            COALESCE(SUM(status IN('done','denied','failed')),0) term
            FROM nm_ap2_actions WHERE signal_id=" . (int)$sigid);
        $row = $q ? $q->fetch_assoc() : null;
        if ($row && (int)$row['pend'] === 0 && (int)$row['term'] > 0) {
            $conn->query("UPDATE nm_ap2_signals SET status='acted' WHERE id=" . (int)$sigid . " AND status IN('proposed','investigating')");
        }
    } catch (\Throwable $e) {}
}

function nm_ap2_execute_action($conn, int $aid): array {
    // ATOMIC single-flight: only ONE caller can move an action out of 'approved'/'proposed' into 'executing'.
    // This defeats the double-execution race (cockpit Approve + Telegram tap at once) — the loser's CAS matches
    // 0 rows and returns without re-running the (already-run or denied) action.
    $claim = false;
    try { $conn->query("UPDATE nm_ap2_actions SET status='executing' WHERE id=".(int)$aid." AND status IN('approved','proposed')"); $claim = $conn->affected_rows > 0; } catch (\Throwable $e) {}
    if (!$claim) return ['ok'=>false,'error'=>'already handled'];
    $a=null; try { $st=$conn->prepare("SELECT * FROM nm_ap2_actions WHERE id=? LIMIT 1"); $st->bind_param('i',$aid); $st->execute(); $a=$st->get_result()->fetch_assoc(); $st->close(); } catch (\Throwable $e) {}
    if (!$a) return ['ok'=>false,'error'=>'no action'];
    $node=(int)$a['node_id'];
    $args=json_decode($a['args']?:'{}',true) ?: [];
    // DOMAIN actions (fleet-wide) run through their own engines, NOT node-SSH (nm_aip_do).
    if ($a['tool']==='immunize') { $res = nm_ap2_do_immunize($conn,$args); }
    elseif ($a['tool']==='heal_apply') { $res = nm_ap2_do_heal($conn,$args); }
    elseif ($a['tool']==='firewall_block_ip') { $res = nm_ap2_do_fw_block($conn,$args); }
    elseif ($a['tool']==='firewall_apply') { $res = nm_ap2_do_fw_apply($conn,$args); }
    else
    $res = ($node && function_exists('nm_aip_do')) ? nm_aip_do($conn,$node,$a['tool'],$args) : ['ok'=>false,'output'=>'executor unavailable'];
    $ok=!empty($res['ok']); $out=substr((string)($res['output']??($res['error']??'')),0,3000);
    try { $st=$conn->prepare("UPDATE nm_ap2_actions SET status=?, result=? WHERE id=?"); $stt=$ok?'done':'failed'; $st->bind_param('ssi',$stt,$out,$aid); $st->execute(); $st->close(); } catch (\Throwable $e) {}
    nm_ap2_event($conn,(int)$a['session_id'],$node,'result',($ok?'✓ ':'✗ ').$a['tool'].': '.$out);
    // once the action finished, clear its signal from "AWAITING YOU" (any path: cockpit/Telegram/auto)
    if (!empty($a['signal_id'])) nm_ap2_settle_signal($conn,(int)$a['signal_id']);
    if (function_exists('nm_audit')) { try { nm_audit($conn,'ap2.execute',['tool'=>$a['tool'],'node'=>$node,'ok'=>$ok]); } catch (\Throwable $e) {} }
    return ['ok'=>$ok,'output'=>$out];
}

// ── PACE: promote NEW signals into dispatched sessions (bounded) ─────────────
// "Scan now" SWEEP: proactively enqueue a health-check for EVERY selected (enabled) node that isn't already
// under investigation or already reviewed this round — so the operator gets a full sweep of the fleet they
// chose. Already-'acted' nodes are skipped here (use the per-node Rescan 🔍 to re-check one). Returns count.
function nm_ap2_sweep($conn): int {
    nm_ap2_ensure($conn);
    $nodes=[]; try { $r=$conn->query("SELECT d.node_id, n.display_name FROM nm_ap2_devices d JOIN nm_nodes n ON n.id=d.node_id WHERE d.enabled=1"); while($r&&$x=$r->fetch_assoc()) $nodes[]=$x; } catch (\Throwable $e) {}
    $skip=[]; try { $r=$conn->query("SELECT DISTINCT node_id FROM nm_ap2_signals WHERE status IN('new','investigating','acted','proposed') AND node_id IS NOT NULL"); while($r&&$x=$r->fetch_row())$skip[(int)$x[0]]=1; } catch (\Throwable $e) {}
    $created=0;
    foreach ($nodes as $nd) {
        $nid=(int)$nd['node_id']; if (isset($skip[$nid])) continue;
        $fp=nm_ap2_fp('manual','node:'.$nid,'health_scan','s'.floor(time()/300));   // one per node per 5-min bucket
        try {
            $chan='manual'; $typ='health_scan'; $sev='info'; $name=(string)$nd['display_name'];
            $title='Health scan of '.$name; $det='Operator "Scan now" fleet sweep.';
            $st=$conn->prepare("INSERT INTO nm_ap2_signals (fingerprint,channel,sig_type,target_kind,node_id,name,severity,title,detail,status) VALUES (?,?,?,'node',?,?,?,?,?, 'new')");
            $st->bind_param('sssissss',$fp,$chan,$typ,$nid,$name,$sev,$title,$det); $st->execute(); $created++; $st->close();
        } catch (\Throwable $e) {}   // dup fingerprint (already swept this bucket) → skip silently
    }
    return $created;
}
function nm_ap2_pace($conn, bool $force=false): array {
    nm_ap2_ensure($conn);
    if (!nm_ap2_enabled($conn)) return ['ok'=>true,'skipped'=>'disabled'];
    // SELF-HEAL: reap sessions stuck in 'active' (a flow that dispatched but never called finish) so they
    // don't hold concurrency slots + node locks forever. Runs on EVERY scan / manual "Scan now", so the
    // cockpit un-sticks itself even when the cron isn't installed. Their signals go back to 'new' to retry.
    try { $conn->query("UPDATE nm_ap2_sessions SET status='idle' WHERE status='active' AND updated_at < (NOW() - INTERVAL 15 MINUTE)"); } catch (\Throwable $e) {}
    // TWO-WAY SYNC cleanup: a proposed action whose signal is already resolved/gone (the operator handled the
    // threat/heal in its own page, or dismissed it) → cancel the action + expire its Telegram approval so a
    // stale tap says "already handled" instead of re-applying.
    try { $conn->query("UPDATE nm_ap2_actions a LEFT JOIN nm_ap2_signals s ON s.id=a.signal_id SET a.status='denied' WHERE a.status='proposed' AND (s.id IS NULL OR s.status IN('resolved','ignored'))"); } catch (\Throwable $e) {}
    try { $conn->query("UPDATE nm_ap2_tg_approvals t LEFT JOIN nm_ap2_actions a ON a.id=t.action_id SET t.status='expired' WHERE t.status='pending' AND (a.id IS NULL OR a.status<>'proposed')"); } catch (\Throwable $e) {}
    // SETTLE stuck 'proposed' signals: their action(s) already finished (done/denied/failed) with none
    // still pending → advance to 'acted' so they stop showing "AWAITING YOU" forever. Catch-all safety net
    // for any execution path that resolved an action without settling its signal (the stuck-honeypot bug).
    try { $conn->query("UPDATE nm_ap2_signals s SET s.status='acted'
        WHERE s.status='proposed'
          AND EXISTS (SELECT 1 FROM nm_ap2_actions a WHERE a.signal_id=s.id AND a.status IN('done','denied','failed'))
          AND NOT EXISTS (SELECT 1 FROM nm_ap2_actions a WHERE a.signal_id=s.id AND a.status IN('proposed','approved','executing'))"); } catch (\Throwable $e) {}
    // reconcile ORPHANED 'investigating' signals: session finished/reaped/gone but the signal never left
    // 'investigating' (e.g. finish hit a uq_fp_open collision). done→resolved, reaped→retry as 'new'.
    // Collision-safe (collapse sibling-fingerprint rows first) and per-row so one bad row can't block the rest.
    try {
        $orph=[]; $r=$conn->query("SELECT si.id, si.fingerprint, se.status ss FROM nm_ap2_signals si
            LEFT JOIN nm_ap2_sessions se ON se.id=si.session_id
            WHERE si.status='investigating' AND (se.id IS NULL OR se.status IN('done','idle','error'))");
        while ($r && $x=$r->fetch_assoc()) $orph[]=$x;
        foreach ($orph as $o) {
            $target = (($o['ss']??'')==='done') ? 'resolved' : 'new';
            $fpe=$conn->real_escape_string((string)$o['fingerprint']); $id=(int)$o['id'];
            try { $conn->query("DELETE FROM nm_ap2_signals WHERE fingerprint='$fpe' AND id<>$id AND status='$target'");
                  $conn->query("UPDATE nm_ap2_signals SET status='$target', session_id=NULL WHERE id=$id"); } catch (\Throwable $e) {}
        }
    } catch (\Throwable $e) {}
    $maxc=(int)(nm_ap2_get($conn,'ap2_max_concurrent','2')?:2);
    $cap =(int)(nm_ap2_get($conn,'ap2_per_run_cap','3')?:3);
    $active=0; try { $r=$conn->query("SELECT COUNT(*) c FROM nm_ap2_sessions WHERE status IN('active','awaiting_approval')"); $active=(int)($r?$r->fetch_assoc()['c']:0); } catch (\Throwable $e) {}
    $slots=max(0,min($cap,$maxc-$active)); $done=[];
    if ($slots<=0) return ['ok'=>true,'promoted'=>0,'active'=>$active];
    // oldest NEW signals whose node isn't already being handled
    // pace dispatches 'new' signals (from the bus OR the Scan-now sweep). Handled issues stay 'acted' (no
    // churn); a per-node Rescan re-opens a specific one. $force is kept for callers that want to ignore pacing.
    // respect the per-channel act_mode: 'aware' channels sit in the queue for VISIBILITY only — NEURU does not
    // spend an investigation on them. 'propose' + 'auto' channels get investigated (propose→approval / auto-fix).
    $ids=[]; try { $r=$conn->query("SELECT id,node_id FROM nm_ap2_signals WHERE status='new' AND channel NOT IN (SELECT channel_key FROM nm_ap2_channels WHERE act_mode='aware') ORDER BY (severity='critical') DESC, id ASC LIMIT ".(int)($slots*3));
        while($r && $x=$r->fetch_assoc()) $ids[]=$x; } catch (\Throwable $e) {}
    $busy=[]; try { $r=$conn->query("SELECT node_id FROM nm_ap2_sessions WHERE status IN('active','awaiting_approval') AND node_id IS NOT NULL"); while($r && $x=$r->fetch_row())$busy[(int)$x[0]]=1; } catch (\Throwable $e) {}
    // No per-node cooldown: churn is prevented at the SIGNAL level — an investigated issue becomes 'acted'
    // (per-fingerprint) and pace only dispatches 'new', so the same issue is never re-investigated, while a
    // genuinely NEW issue (even on a recently-seen node) IS picked up immediately. Keeps NEURU responsive.
    foreach ($ids as $row) {
        if ($slots<=0) break;
        $nid=$row['node_id']!==null?(int)$row['node_id']:0;
        if ($nid && isset($busy[$nid])) continue;         // one concurrent investigation per node
        $r=nm_ap2_dispatch($conn,(int)$row['id']);
        if (!empty($r['ok'])) { $done[]=(int)$row['id']; if($nid)$busy[$nid]=1; $slots--; }
    }
    return ['ok'=>true,'promoted'=>count($done),'active'=>$active];
}

// ─────────────────────────────────────────────────────────────────────────────
// FULL-SPECTRUM X-RAY — one node → a complete telemetry snapshot for the 3D anatomy.
// Combines the live SSH/PS host probe + GPU samples + SNMP interface stats + predictive
// health. Every source is guarded (missing table/host/module must never 500 the endpoint).
// ─────────────────────────────────────────────────────────────────────────────
function _nm_ap2_xr_num($v){ return is_numeric($v) ? (0+$v) : null; }

function _nm_ap2_xray_from_host(array $dd, array $hh, string $osType): array {
    $o = [];
    // CPU
    $cores = [];
    foreach (($dd['cpu_cores'] ?? []) as $c){ $p=_nm_ap2_xr_num($c['pct'] ?? null); if($p!==null) $cores[]=round($p,1); }
    $load = null;
    $ls = $dd['load'] ?? ($hh['load'] ?? null);
    if (is_string($ls) && $ls!==''){ $parts=preg_split('/\s+/',trim($ls)); $load=array_map('floatval',array_slice($parts,0,3)); }
    elseif (is_array($ls)) { $load=array_map('floatval',array_slice($ls,0,3)); }
    $cpuTemp=null;
    foreach (($dd['temps'] ?? []) as $t){ $nm=strtolower((string)($t['name']??'')); if(strpos($nm,'cpu')!==false||strpos($nm,'package')!==false||strpos($nm,'tctl')!==false){ $cpuTemp=_nm_ap2_xr_num($t['c']??null); break; } }
    $o['cpu'] = ['pct'=>_nm_ap2_xr_num($dd['cpu'] ?? null), 'cores'=>$cores, 'cores_count'=>(int)($dd['cores'] ?? $hh['cores'] ?? count($cores)), 'load'=>$load, 'temp'=>$cpuTemp];
    // MEMORY (MB)
    $mt=_nm_ap2_xr_num($dd['mem_total']??null); $mu=_nm_ap2_xr_num($dd['mem_used']??null);
    $swt=_nm_ap2_xr_num($dd['swap_total']??null); $swu=_nm_ap2_xr_num($dd['swap_used']??null);
    $o['memory'] = ['pct'=>_nm_ap2_xr_num($dd['mem_pct']??null),'used_mb'=>$mu,'total_mb'=>$mt,
        'cache_mb'=>_nm_ap2_xr_num($dd['mem_cached']??null),'buffers_mb'=>_nm_ap2_xr_num($dd['mem_buffers']??null),
        'swap_used_mb'=>$swu,'swap_total_mb'=>$swt,'swap_pct'=>($swt>0?round($swu/$swt*100,1):null),
        'commit_used_mb'=>_nm_ap2_xr_num($dd['commit_used']??null),'commit_total_mb'=>_nm_ap2_xr_num($dd['commit_total']??null)];
    // NETWORK (host totals in KB/s; per-iface if alloy)
    $ifs=[];
    foreach (($dd['net_ifaces'] ?? []) as $f){ $ifs[]=['name'=>(string)($f['name']??'if'),'rx'=>(float)($f['rx']??0),'tx'=>(float)($f['tx']??0),'up'=>true,'unit'=>'KB/s']; }
    $o['network'] = ['rx_kbps'=>_nm_ap2_xr_num($dd['net_rx']??null),'tx_kbps'=>_nm_ap2_xr_num($dd['net_tx']??null),'unit'=>'KB/s','ifaces'=>$ifs];
    // DISKS  (prefer the richer of probe vs health)
    $disks=[]; $src=(!empty($dd['disks'])?$dd['disks']:($hh['disks']??[]));
    foreach ($src as $d){ $sz=_nm_ap2_xr_num($d['size']??null); $fr=_nm_ap2_xr_num($d['free']??null);
        $disks[]=['mount'=>(string)($d['id']??$d['mount']??'/'),'total_gb'=>$sz,'free_gb'=>$fr,'pct'=>_nm_ap2_xr_num($d['pct']??null)]; }
    $o['disks']=$disks;
    // SENSORS
    $temps=[]; $maxT=null;
    foreach (($dd['temps'] ?? []) as $t){ $c=_nm_ap2_xr_num($t['c']??null); if($c===null)continue; $temps[]=['name'=>(string)($t['name']??'temp'),'c'=>$c]; if($maxT===null||$c>$maxT)$maxT=$c; }
    $fans=[]; foreach (($dd['fans'] ?? []) as $f){ $fans[]=['name'=>(string)($f['name']??'fan'),'rpm'=>_nm_ap2_xr_num($f['rpm']??null)]; }
    $o['sensors']=['max_temp'=>$maxT,'temps'=>array_slice($temps,0,10),'fans'=>array_slice($fans,0,6),'src'=>$dd['sensor_src']??null];
    // PROCESSES (merge top_cpu + top_mem)
    $procs=[];
    foreach (($dd['top_cpu']??[]) as $p){ $n=(string)($p['name']??''); if($n==='')continue; $procs[$n]=['name'=>$n,'cpu'=>(float)($p['pct']??$p['cpu']??0),'mem'=>(float)($p['mb']??0)]; }
    foreach (($dd['top_mem']??[]) as $p){ $n=(string)($p['name']??''); if($n==='')continue; if(!isset($procs[$n]))$procs[$n]=['name'=>$n,'cpu'=>0,'mem'=>0]; $procs[$n]['mem']=(float)($p['mb']??$p['mem']??0); }
    $procs=array_values($procs); usort($procs,fn($a,$b)=>($b['cpu']<=>$a['cpu'])?:($b['mem']<=>$a['mem']));
    $o['processes']=array_slice($procs,0,16);
    // OS + uptime
    $o['os']=(string)($hh['os']??$dd['os']??'');
    $boot=$hh['boot']??$dd['boot']??null;
    if ($boot){ $ts=is_numeric($boot)?(int)$boot:strtotime((string)$boot); if($ts) $o['uptime_s']=max(0, time()-$ts); }
    return $o;
}

function _nm_ap2_xray_from_snmp(mysqli $conn, int $nid): array {
    $o=['cpu'=>['pct'=>null,'cores'=>[],'cores_count'=>0,'load'=>null,'temp'=>null],'memory'=>['pct'=>null],'disks'=>[]];
    // latest value per metric_type from the EAV series
    $latest=function($mt) use($conn,$nid){ try{ $r=$conn->query("SELECT value FROM nm_device_stats WHERE node_id=$nid AND metric_type='".$conn->real_escape_string($mt)."' ORDER BY recorded_at DESC LIMIT 1"); if($r&&($x=$r->fetch_assoc())) return _nm_ap2_xr_num($x['value']); }catch(\Throwable $e){} return null; };
    $cpu=$latest('cpu'); if($cpu!==null) $o['cpu']['pct']=$cpu;
    $mem=$latest('memory'); if($mem===null)$mem=$latest('ram'); if($mem!==null) $o['memory']['pct']=$mem;
    $up=$latest('uptime'); if($up!==null) $o['uptime_s']=$up;
    // storage rows (one per mount) — grab the latest sample per metric_key
    try { $r=$conn->query("SELECT s.metric_key, s.value FROM nm_device_stats s JOIN (SELECT metric_key, MAX(recorded_at) mx FROM nm_device_stats WHERE node_id=$nid AND metric_type='storage' GROUP BY metric_key) t ON t.metric_key=s.metric_key AND t.mx=s.recorded_at WHERE s.node_id=$nid AND s.metric_type='storage' LIMIT 20");
        while($r&&$x=$r->fetch_assoc()){ $o['disks'][]=['mount'=>(string)$x['metric_key'],'total_gb'=>null,'free_gb'=>null,'pct'=>_nm_ap2_xr_num($x['value'])]; } } catch(\Throwable $e){}
    return $o;
}

function nm_ap2_xray_full(mysqli $conn, int $nid): array {
    @require_once __DIR__.'/nm_linuxhost.php'; @require_once __DIR__.'/nm_winhost.php';
    @require_once __DIR__.'/nm_nodemeta.php'; @require_once __DIR__.'/nm_gpu.php'; @require_once __DIR__.'/nm_config.php';
    $node=null;
    try{ $r=$conn->query("SELECT id,display_name,ip_address,hostname,os_icon FROM nm_nodes WHERE id=$nid LIMIT 1"); $node=$r?$r->fetch_assoc():null; }catch(\Throwable $e){}
    if(!$node) return ['ok'=>false,'error'=>'node not found'];
    $kind='snmp'; if(function_exists('nm_node_kind')){ try{ $kind=nm_node_kind($node); }catch(\Throwable $e){} }
    $verdict=['state'=>'unknown','detail'=>''];
    if(function_exists('nm_node_live_verdict')){ try{ $v=nm_node_live_verdict($conn,$nid); if(is_array($v)) $verdict=['state'=>$v['state']??'unknown','detail'=>$v['detail']??'']; }catch(\Throwable $e){} }
    $out=['ok'=>true,'node'=>$nid,'name'=>$node['display_name']?:('node '.$nid),'ip'=>$node['ip_address']??'','kind'=>$kind,
        'os'=>'','uptime_s'=>null,'status'=>$verdict,
        'cpu'=>null,'memory'=>null,'gpu'=>[],'network'=>null,'disks'=>[],'sensors'=>null,'processes'=>[],'containers'=>[],'health'=>[]];
    // ── host probe (linux → windows → snmp fallback) ──
    $lh=null;$wh=null;
    if(function_exists('nm_lx_hosts')){ try{ foreach(nm_lx_hosts($conn) as $x){ if((int)($x['node_id']??0)===$nid){ $lh=$x; break; } } }catch(\Throwable $e){} }
    if(!$lh && function_exists('nm_win_hosts')){ try{ foreach(nm_win_hosts($conn) as $x){ if((int)($x['node_id']??0)===$nid){ $wh=$x; break; } } }catch(\Throwable $e){} }
    if($lh){
        $d=null;
        try{ $ssh=function_exists('nm_lx_resolve_ssh')?nm_lx_resolve_ssh($conn,$lh):null;
            $d=($ssh && !empty($ssh['username']) && function_exists('_nm_lx_gather_diag_ssh')) ? _nm_lx_gather_diag_ssh($ssh) : (function_exists('nm_lx_diagnose')?nm_lx_diagnose($conn,$lh):null);
        }catch(\Throwable $e){}
        $dd=(is_array($d)&&!empty($d['ok']))?($d['data']??[]):[];
        $hh=[]; if(function_exists('nm_lx_health_get')){ try{ $hg=nm_lx_health_get($conn,(int)$lh['id']); if(!empty($hg['has'])) $hh=$hg['data']??[]; }catch(\Throwable $e){} }
        $out=array_replace($out, _nm_ap2_xray_from_host($dd,$hh,'linux')); $out['probe']='linux-ssh';
    } elseif($wh){
        $d=null; try{ $d=function_exists('nm_win_diagnose')?nm_win_diagnose($conn,$wh):null; }catch(\Throwable $e){}
        $dd=(is_array($d)&&!empty($d['ok']))?($d['data']??[]):[];
        $out=array_replace($out, _nm_ap2_xray_from_host($dd,[],'windows')); $out['probe']='windows-ps';
    } else {
        $out=array_replace($out, _nm_ap2_xray_from_snmp($conn,$nid)); $out['probe']='snmp';
    }
    // ── GPU (independent of host kind) ──
    if(function_exists('nm_gpu_targets') && function_exists('nm_gpu_list')){
        try{ foreach(nm_gpu_targets($conn) as $t){ if((int)($t['node_id']??0)!==$nid) continue;
            foreach(nm_gpu_list($conn,(int)$t['id']) as $g){ $l=$g['latest']??[];
                $out['gpu'][]=['name'=>(string)($g['name']??'GPU'),'util'=>(float)($l['util_pct']??0),
                    'mem_used'=>(float)($l['mem_used_mb']??0),'mem_total'=>(float)($l['mem_total_mb']??($g['memory_total_mb']??0)),
                    'temp'=>(float)($l['temp_c']??0),'power'=>(float)($l['power_w']??0),'fan'=>(float)($l['fan_pct']??0)]; }
            break; } }catch(\Throwable $e){}
    }
    // ── interfaces (SNMP live rates → network detail; also totals for routers) ──
    try{ $ifs=[];
        $q=$conn->query("SELECT i.if_name,i.display_name,ps.in_rate,ps.out_rate,ps.oper_status FROM nm_interfaces i LEFT JOIN nm_port_stats ps ON ps.port_id=i.id AND ps.recorded_at=(SELECT MAX(x.recorded_at) FROM nm_port_stats x WHERE x.port_id=i.id) WHERE i.node_id=$nid AND i.show_graph=1 ORDER BY i.sort_order LIMIT 24");
        while($q&&$row=$q->fetch_assoc()){ $st=(string)($row['oper_status']??''); $ifs[]=['name'=>(string)($row['display_name']?:$row['if_name']),'rx'=>round((float)($row['in_rate']??0)/1e6,3),'tx'=>round((float)($row['out_rate']??0)/1e6,3),'up'=>($st==='up'||$st==='1'),'unit'=>'Mb/s']; }
        if($ifs){ if(!$out['network']) $out['network']=['rx_kbps'=>null,'tx_kbps'=>null,'unit'=>'KB/s','ifaces'=>[]];
            if(empty($out['network']['ifaces'])) $out['network']['ifaces']=$ifs;
            if($out['network']['rx_kbps']===null){ $trx=0;$ttx=0; foreach($ifs as $f){ $trx+=$f['rx']; $ttx+=$f['tx']; } $out['network']['rx_kbps']=round($trx*125,1); $out['network']['tx_kbps']=round($ttx*125,1); } }   // Mb/s→KB/s approx
    }catch(\Throwable $e){}
    // ── containers (from the fleet snapshot cache) ──
    try{ $r=$conn->query("SELECT containers FROM nm_ap2_fleet WHERE name=(SELECT display_name FROM nm_nodes WHERE id=$nid) LIMIT 1");
        if($r&&($x=$r->fetch_assoc())){ $c=json_decode($x['containers']?:'[]',true); if(is_array($c)) $out['containers']=$c; } }catch(\Throwable $e){}
    // ── predictive health verdicts ──
    try{ $q=$conn->query("SELECT metric,severity,eta_days,detail FROM nm_health_predictions WHERE node_id=$nid AND status='open' AND severity IN('warn','crit') ORDER BY FIELD(severity,'crit','warn'), eta_days ASC LIMIT 8");
        while($q&&$row=$q->fetch_assoc()) $out['health'][]=['metric'=>$row['metric'],'severity'=>$row['severity'],'eta_days'=>_nm_ap2_xr_num($row['eta_days']),'detail'=>(string)$row['detail']]; }catch(\Throwable $e){}
    return $out;
}

// ─────────────────────────────────────────────────────────────────────────────
// TOPOLOGY MAP — the whole network as an interconnected graph (ALL nodes, not just
// gateways). scope='all' | a node/router name (that node + 2 hops) | a subnet CIDR.
// Reuses nm_chaos_graph (gateway + nm_links adjacency), nm_node_kind, nm_ipam.
// ─────────────────────────────────────────────────────────────────────────────
function nm_ap2_topology(mysqli $conn, string $scope='all'): array {
    @require_once __DIR__.'/nm_chaos.php'; @require_once __DIR__.'/nm_nodemeta.php'; @require_once __DIR__.'/nm_ipam.php';
    // node metadata (id,name,ip,kind,status)
    $meta=[];
    try { $r=$conn->query("SELECT id,display_name,ip_address,os_icon,monitor_type FROM nm_nodes");
        while($r&&$n=$r->fetch_assoc()){ $kind=function_exists('nm_node_kind')?nm_node_kind($n):'snmp';
            $meta[(int)$n['id']]=['id'=>(int)$n['id'],'name'=>$n['display_name'],'ip'=>$n['ip_address'],'kind'=>$kind,'router'=>($kind==='router'),'status'=>'up']; } } catch(\Throwable $e){}
    if(!$meta) return ['ok'=>false,'error'=>'no nodes'];
    try { $r=$conn->query("SELECT node_id,last_status FROM nm_alert_state WHERE entity_type='node' AND last_status IN('down','degraded','lowerlayerdown','notpresent','testing')");
        while($r&&$x=$r->fetch_assoc()){ $id=(int)$x['node_id']; if(isset($meta[$id])){ $meta[$id]['status']=(strtolower($x['last_status'])==='degraded'?'degraded':'down'); } } } catch(\Throwable $e){}
    // adjacency (ALL nodes) + explicit link labels
    $G=['adj'=>[],'gw'=>[]];  // nm_chaos_graph() runs raw SELECTs (nm_links/gateway_node_id) — guard for drifted installs (mysqli exception mode)
    if(function_exists('nm_chaos_graph')){ try { $G=nm_chaos_graph($conn); } catch(\Throwable $e){} }
    $adj=$G['adj']??[]; $gw=$G['gw']??[];
    $wired=[]; $linkLabel=[];
    try { $r=$conn->query("SELECT a_node_id,z_node_id,label FROM nm_links WHERE enabled=1");
        while($r&&$x=$r->fetch_assoc()){ $a=(int)$x['a_node_id']; $b=(int)$x['z_node_id']; $k=min($a,$b).'-'.max($a,$b); $wired[$k]=1; if(!empty($x['label']))$linkLabel[$k]=$x['label']; } } catch(\Throwable $e){}
    // scope → keep set
    $keep=null; $title='Full network topology'; $sc=trim($scope); $scLow=strtolower($sc);
    if($sc!=='' && !in_array($scLow,['all','todo','completo','full','red','network','todos'],true)){
        $isCidr = (bool)preg_match('#^\d{1,3}(\.\d{1,3}){1,3}(/\d{1,2})?$#',$sc);
        $nid = $isCidr ? 0 : nm_ap2_resolve_node($conn,$sc);
        if($nid && isset($meta[$nid])){
            $keep=[$nid=>1]; $frontier=[$nid]; $depth=0;
            while($frontier && $depth<2){ $next=[]; foreach($frontier as $f){ foreach(array_keys($adj[$f]??[]) as $nb){ if(!isset($keep[$nb])){ $keep[$nb]=1; $next[]=$nb; } } } $frontier=$next; $depth++; }
            $title=$meta[$nid]['name'].' + what connects to it';
        } elseif(function_exists('nm_ipam_parse_cidr')){
            $cidr=$sc; if(strpos($cidr,'/')===false) $cidr.='/24'; $snet=nm_ipam_parse_cidr($cidr);
            if(!empty($snet['ok'])){ $keep=[];
                foreach($meta as $id=>$m){ if(!empty($m['ip']) && function_exists('nm_ipam_in_subnet') && nm_ipam_in_subnet($m['ip'],$snet)) $keep[$id]=1; }
                try { $r=$conn->query("SELECT node_id,if_ip_address FROM nm_interfaces WHERE if_ip_address IS NOT NULL AND if_ip_address<>''");
                    while($r&&$x=$r->fetch_assoc()){ if(nm_ipam_in_subnet($x['if_ip_address'],$snet)){ $id=(int)$x['node_id']; if(isset($meta[$id]))$keep[$id]=1; } } } catch(\Throwable $e){}
                $title='Segment '.$cidr;
            }
        }
        if($keep!==null && !$keep) $keep=null;   // nothing matched → fall back to full map
    }
    // nodes + edges (filtered)
    $nodes=[]; foreach($meta as $id=>$m){ if($keep!==null && !isset($keep[$id])) continue; $nodes[]=$m; }
    $edges=[]; $seen=[];
    foreach($adj as $a=>$nbs){ $a=(int)$a; foreach(array_keys($nbs) as $b){ $b=(int)$b; if($a>=$b) continue;
        if($keep!==null && (!isset($keep[$a])||!isset($keep[$b]))) continue; if(!isset($meta[$a])||!isset($meta[$b])) continue;
        $k=$a.'-'.$b; if(isset($seen[$k]))continue; $seen[$k]=1;
        $type = isset($wired[$k]) ? 'wired' : ((($gw[$a]??null)==$b || ($gw[$b]??null)==$a) ? 'gateway' : 'wired');
        $edges[]=['a'=>$a,'b'=>$b,'type'=>$type,'label'=>$linkLabel[$k]??'']; } }
    return ['ok'=>true,'scope'=>$sc?:'all','title'=>$title,'count'=>count($nodes),'edge_count'=>count($edges),'nodes'=>array_values($nodes),'edges'=>$edges];
}

// ─────────────────────────────────────────────────────────────────────────────
// LIVE TRAFFIC — per-interface live rates for one node (drives the laser view, like
// traffic_viewer.php). Reuses nm_interfaces + latest nm_port_stats (in/out rate+util).
// ─────────────────────────────────────────────────────────────────────────────
function nm_ap2_traffic(mysqli $conn, string $nodeRef='', string $ifaceFilter=''): array {
    // ALWAYS return ALL monitored interfaces (fleet-wide); node/iface only choose what to FOCUS (nothing selected by default).
    $ifs=[]; $curNode=-1; $nn=0;
    try {
        $q=$conn->query("SELECT i.id,i.node_id,n.display_name AS node,i.if_name,i.display_name,i.if_index,ps.in_rate,ps.out_rate,ps.in_util,ps.out_util,ps.oper_status,ps.if_speed
            FROM nm_interfaces i JOIN nm_nodes n ON n.id=i.node_id
            LEFT JOIN nm_port_stats ps ON ps.port_id=i.id AND ps.recorded_at=(SELECT MAX(x.recorded_at) FROM nm_port_stats x WHERE x.port_id=i.id)
            WHERE i.show_graph=1 AND i.is_dummy=0 ORDER BY n.display_name, i.sort_order, i.if_index LIMIT 120");
        $idx=0;
        while($q&&$row=$q->fetch_assoc()){ $idx++; if((int)$row['node_id']!==$curNode){ $curNode=(int)$row['node_id']; $nn=0; } $nn++; $st=strtolower((string)($row['oper_status']??''));
            $ifs[]=['id'=>(int)$row['id'],'n'=>$idx,'nn'=>$nn,'node'=>(string)$row['node'],'node_id'=>(int)$row['node_id'],'name'=>(string)($row['display_name']?:$row['if_name']),'if_index'=>(int)($row['if_index']??0),
                'in_mbps'=>round((float)($row['in_rate']??0)/1e6,3),'out_mbps'=>round((float)($row['out_rate']??0)/1e6,3),
                'in_util'=>round((float)($row['in_util']??0),1),'out_util'=>round((float)($row['out_util']??0),1),
                'up'=>($st==='up'||$st==='1'),'speed_mbps'=>round((float)($row['if_speed']??0)/1e6,0)]; }
    }catch(\Throwable $e){}
    // FOCUS: a node ("del core router" → all its interfaces) and/or an interface number/name WITHIN that node.
    $focus=[]; $title='Live traffic — all monitored interfaces';
    $nr=trim($nodeRef); $fnid=0; $fname='';
    if($nr!=='' && !in_array(strtolower($nr), ['all','todo','todos','toda','todas','red','network','fleet','entera','completo'], true)){
        $fnid = nm_ap2_resolve_node($conn, $nr);
        if($fnid){ foreach($ifs as $if){ if($if['node_id']===$fnid){ $fname=$if['node']; break; } } }
    }
    $cands = $fnid ? array_values(array_filter($ifs, fn($i)=>$i['node_id']===$fnid)) : $ifs;
    $f=strtolower(trim($ifaceFilter));
    if($f!=='' && !in_array($f,['all','todas','todo','todas las interfaces'],true)){
        $w=['cero'=>'0','uno'=>'1','una'=>'1','dos'=>'2','tres'=>'3','cuatro'=>'4','cinco'=>'5','seis'=>'6','siete'=>'7','ocho'=>'8','nueve'=>'9','one'=>'1','two'=>'2','three'=>'3','four'=>'4','five'=>'5','six'=>'6','seven'=>'7','eight'=>'8','nine'=>'9'];
        $f2=preg_replace_callback('/\b('.implode('|',array_keys($w)).')\b/', fn($m)=>$w[$m[1]], $f);
        $key = $fnid ? 'nn' : 'n';   // "interface 1 of core-router" = that node's 1st; global "1" = the 1st shown
        if(preg_match_all('/\d+/', $f2, $nums)) foreach($nums[0] as $num){ $num=(int)$num; foreach($cands as $if){ if($if[$key]===$num){ $focus[]=$if['id']; } } }
        foreach($cands as $if){ $nl=strtolower($if['name']); foreach(preg_split('/[^a-z0-9]+/',$f2) as $tk){ if(strlen($tk)>=3 && strpos($nl,$tk)!==false){ $focus[]=$if['id']; } } }
        $focus=array_values(array_unique($focus));
    } elseif($fnid){ foreach($cands as $if) $focus[]=$if['id']; }   // node named, no interface → focus the WHOLE node
    if($fnid && $fname!=='') $title='Live traffic · focus: '.$fname;
    return ['ok'=>true,'node'=>$fnid?$fname:'all','node_id'=>$fnid,'title'=>$title,'count'=>count($ifs),'interfaces'=>$ifs,'focus'=>$focus];
}

// ═══════════════════════════════════════════════════════════════════════════════
// TROUBLESHOOTING INFERENCE ENGINE (deterministic) — decides "hay o no problema".
// 5 stages: fingerprint → symptom → standard test battery → correlate neighbors → verdict.
// READ-ONLY; reuses existing tools; NO UI side effects (uses nm_ap2_xray_full directly, never the
// node_xray tool which opens the overlay). The verdict is STRUCTURED (not LLM prose) → repeatable +
// terse + always concludes. See docs/AUTOPILOT_V2_VOICE_NARRATION_PLAN.md Part 2/3.
// ═══════════════════════════════════════════════════════════════════════════════

// Stage 2 — fingerprint: kind + vendor + role (reuses nm_node_kind + nm_cm_guess_vendor).
function nm_ap2_fingerprint($conn, int $node_id): array {
    $fp = ['node_id'=>$node_id,'name'=>'','ip'=>'','kind'=>'host','vendor'=>'generic','os'=>'','role'=>'host'];
    $row = null;
    try { $st=$conn->prepare("SELECT * FROM nm_nodes WHERE id=? LIMIT 1"); $st->bind_param('i',$node_id); $st->execute(); $row=$st->get_result()->fetch_assoc(); $st->close(); } catch (\Throwable $e) {}
    if (!$row) return $fp;
    $fp['name']=(string)($row['display_name']??''); $fp['ip']=(string)($row['ip_address']??''); $fp['os']=strtolower((string)($row['os_icon']??''));
    if (function_exists('nm_cm_guess_vendor')) { try { $v=nm_cm_guess_vendor($fp['os']); if(is_string($v)&&$v!=='') $fp['vendor']=strtolower($v); } catch (\Throwable $e) {} }
    // deterministic fallback (nm_confmgr loads lazily → guess_vendor may be absent on the first call) so a node's
    // vendor never flips between calls
    if ($fp['vendor']==='generic') { foreach(['mikrotik'=>'mikrotik','routeros'=>'mikrotik','cisco'=>'cisco','fortinet'=>'fortinet','fortigate'=>'fortinet','windows'=>'windows','linux'=>'linux','ubiquiti'=>'ubiquiti','aruba'=>'aruba','juniper'=>'juniper'] as $k=>$v){ if(strpos($fp['os'],$k)!==false){ $fp['vendor']=$v; break; } } }
    if (function_exists('nm_node_kind')) { try { $k=nm_node_kind($row); if(is_string($k)&&$k!=='') $fp['kind']=strtolower($k); } catch (\Throwable $e) {} }
    if (in_array($fp['os'],['mikrotik','routeros'],true) || strpos($fp['os'],'router')!==false) $fp['kind']='router';
    $role='host';
    if (in_array($fp['kind'],['router','switch','firewall'],true)) $role='core';
    else { try { $q=$conn->query("SELECT COUNT(*) c FROM nm_nodes WHERE gateway_node_id=".(int)$node_id); if($q && (int)($q->fetch_assoc()['c']??0)>0) $role='core'; } catch (\Throwable $e) {} }
    if ($role==='host' && (strpos($fp['os'],'windows')!==false || strpos($fp['os'],'linux')!==false)) $role='server';
    $fp['role']=$role;
    return $fp;
}

// Stage 1/2 — classify the symptom from a signal's words (or an explicit override string).
function nm_ap2_symptom(string $text): string {
    $t = ' '.strtolower($text).' ';
    if (preg_match('/\b(down|unreachable|no responde|ca[ií]d\w*|offline|timeout|sin conexi)/u',$t)) return 'node_down';
    if (preg_match('/\b(loss|p[eé]rdida|latenc\w*|jitter|rtt|bufferbloat)/u',$t)) return 'latency_loss';
    if (preg_match('/\b(util\w*|satur\w*|bandwidth|ancho de banda|congesti\w*|top ?talker)/u',$t)) return 'bandwidth';
    if (preg_match('/\b(bgp|ospf|route|ruta\w*|routing|flap\w*|\brib\b|\bmtu\b)/u',$t)) return 'routing';
    if (preg_match('/\b(cpu|ram|memor\w*|disk|disco|storage|almacen\w*|resource|recurso\w*|swap)/u',$t)) return 'resources';
    if (preg_match('/\b(config\w*|configuraci\w*|changed|cambi\w*)/u',$t)) return 'config';
    if (preg_match('/\b(threat|amenaza\w*|malicious|malicios\w*|attack|ataque|intrus\w*|honeypot)/u',$t)) return 'threat';
    return 'generic';
}

// Stage 3 — the standard test battery per symptom (ordered, non-destructive). 'xray_data' = direct data, no UI.
function nm_ap2_test_matrix(string $symptom, array $fp): array {
    $node = $fp['name']!=='' ? $fp['name'] : (string)$fp['node_id'];
    $ip   = $fp['ip'];
    switch ($symptom) {
        case 'node_down':    return [['reachability',['dst'=>$node]], ['blast_radius',['node'=>$node]]];
        case 'latency_loss': return [['interfaces',['node'=>$node]], ['reachability',['dst'=>$node]]];
        case 'bandwidth':    return [['bandwidth_top',['node'=>$node,'limit'=>5]], ['traffic_by_app',['node'=>$node,'limit'=>5]], ['interfaces',['node'=>$node]]];
        case 'routing':      return [['route_lookup',['dst'=>$ip?:$node]], ['route_drift',['node'=>$node]]];
        case 'resources':    return [['xray_data',[]]];
        case 'config':       return [['route_drift',['node'=>$node]], ['interfaces',['node'=>$node]]];
        case 'threat':       return [['anomalies',['node'=>$node]], ['connections',['node'=>$node]]];
        default:             return [['xray_data',[]], ['interfaces',['node'=>$node]]];  // generic health scan
    }
}

// run one battery test WITHOUT UI side effects; extract key metrics into &$m; return a terse per-test line.
function _nm_ap2_battery_run($conn, array $fp, string $tool, array $args, array &$m): array {
    $ok=false; $data=null;
    try {
        if ($tool==='xray_data') { $data = function_exists('nm_ap2_xray_full')?nm_ap2_xray_full($conn,(int)$fp['node_id']):null; $ok = is_array($data) && (isset($data['cpu'])||!empty($data['ok'])); }
        else { $r = nm_ap2_chat_run_tool($conn,$tool,$args); $ok=!empty($r['ok']); $data = $r['data'] ?? null; }
    } catch (\Throwable $e) { $ok=false; }
    $line = $tool.': '.($ok?'ok':'—');
    if (!$ok || !is_array($data)) return ['tool'=>$tool,'ok'=>$ok,'summary'=>$line];
    switch ($tool) {
        case 'reachability':
            $v = (string)($data['verdict'] ?? '?'); $m['reach_verdict']=$v; $line='reachability: '.$v; break;
        case 'xray_data':
            if(isset($data['cpu']['pct'])) $m['cpu']=(float)$data['cpu']['pct'];
            if(isset($data['memory']['pct'])) $m['mem']=(float)$data['memory']['pct'];
            if(!empty($data['disks'])){ $mx=0; $mnt=''; foreach($data['disks'] as $d){ if(isset($d['pct'])&&(float)$d['pct']>$mx){$mx=(float)$d['pct'];$mnt=(string)($d['mount']??'');} } if($mx){$m['disk']=$mx;$m['disk_mount']=$mnt;} }
            if(!empty($data['sensors']['max_temp'])) $m['temp']=(float)$data['sensors']['max_temp'];
            $line='recursos: CPU '.round($m['cpu']??0).'% · RAM '.round($m['mem']??0).'%'.(isset($m['disk'])?' · disco '.round($m['disk']).'%':''); break;
        case 'interfaces':
            $ifs = $data['interfaces'] ?? ($data['ports'] ?? ((is_array($data)&&isset($data[0]))?$data:[]));
            $down=0; $err=0; $tot=0;
            if(is_array($ifs)) foreach($ifs as $if){ if(!is_array($if))continue; $tot++;
                $stt=strtolower((string)($if['oper_status']??$if['status']??$if['oper']??'')); if($stt!==''&&strpos($stt,'up')===false&&$stt!=='1') $down++;
                $e=(int)($if['errors']??$if['in_errors']??0)+(int)($if['out_errors']??0)+(int)($if['drops']??0); if($e>0)$err++;
            }
            if($tot){ $m['ifaces']=$tot; $m['ifaces_down']=$down; $m['ifaces_err']=$err; }
            $line='interfaces: '.$tot.' ('.$down.' down'.($err?', '.$err.' con errores':'').')'; break;
        case 'bandwidth_top':
            $tt = $data['talkers'] ?? []; if(!empty($tt[0])){ $top=$tt[0]; $m['top_talker']=(string)($top['ip']??$top['host']??$top['name']??''); }
            $line='bandwidth: '.(isset($m['top_talker'])?('top '.$m['top_talker']):'sin datos'); break;
        case 'route_drift':
            $add=count($data['added']??[]); $rem=count($data['removed']??[]); $m['route_changes']=$add+$rem;
            $line='route_drift: '.($add+$rem===0?'sin cambios':($add.'+/'.$rem.'-')); break;
        case 'route_lookup':
            $rt = $data['routers'] ?? []; $has=0; foreach($rt as $x){ if(!empty($x['match'])) $has++; } $m['route_have']=$has; $m['route_total']=count($rt);
            $line='route_lookup: '.$has.'/'.count($rt).' con ruta'; break;
        case 'blast_radius':
            $m['dependents'] = (int)($data['affected_count'] ?? (is_array($data['affected_nodes'] ?? null) ? count($data['affected_nodes']) : 0));
            $line='blast_radius: '.$m['dependents'].' dependientes'; break;
        case 'anomalies':
            $ins=count($data['insights']??[]); $thr=count($data['threats']??[]); $m['anoms']=$ins+$thr;
            $line='anomalies: '.$ins.' insights, '.$thr.' amenazas'; break;
        case 'connections':
            $c = $data['connections'] ?? ($data['conns'] ?? []); $m['conns']=is_array($c)?count($c):0;
            $line='connections: '.$m['conns']; break;
    }
    return ['tool'=>$tool,'ok'=>$ok,'summary'=>$line];
}

function nm_ap2_run_battery($conn, array $fp, string $symptom): array {
    $tests=[]; $m=[];
    foreach (nm_ap2_test_matrix($symptom,$fp) as [$tool,$args]) { $tests[] = _nm_ap2_battery_run($conn,$fp,$tool,$args,$m); }
    return ['tests'=>$tests,'metrics'=>$m];
}

// Stage 4 — correlate with DIRECT neighbors: is an upstream neighbor down (root cause upstream vs local)?
function nm_ap2_correlate($conn, int $node_id): array {
    $neigh=[]; $upDown=false;
    try {
        $G = function_exists('nm_chaos_graph') ? nm_chaos_graph($conn) : ['adj'=>[],'names'=>[]];
        $adj = $G['adj'][$node_id] ?? []; $names=$G['names'] ?? [];
        $ids = array_slice(array_map('intval',array_keys((array)$adj)),0,8);
        if ($ids){
            $in=implode(',',array_map('intval',$ids)); $down=[];
            try { $q=$conn->query("SELECT node_id,last_status FROM nm_alert_state WHERE entity_type='node' AND node_id IN ($in) AND last_status IN('down','degraded','lowerlayerdown','notpresent')");
                  while($q && $x=$q->fetch_assoc()) $down[(int)$x['node_id']]=(string)$x['last_status']; } catch (\Throwable $e) {}
            foreach ($ids as $nid){ $stt=$down[$nid]??'up'; if(isset($down[$nid])) $upDown=true; $neigh[]=['id'=>$nid,'name'=>(string)($names[$nid]??('#'.$nid)),'status'=>$stt]; }
        }
    } catch (\Throwable $e) {}
    return ['neighbors'=>$neigh,'upstream_down'=>$upDown];
}

// Stage 5 — the deterministic STRUCTURED verdict. This decides "hay o no problema". Always concludes.
function nm_ap2_diag_report($conn, int $node_id, string $symptomHint='', string $signalText=''): array {
    nm_ap2_ensure($conn);
    if ($node_id<=0) return ['ok'=>false,'error'=>'no node'];
    $fp = nm_ap2_fingerprint($conn,$node_id);
    if ($fp['name']==='') return ['ok'=>false,'error'=>'node not found'];
    $valid=['node_down','latency_loss','bandwidth','routing','resources','config','threat','generic'];
    $symptom = strtolower(trim($symptomHint));
    if (!in_array($symptom,$valid,true)) $symptom = nm_ap2_symptom(($symptomHint!==''?$symptomHint.' ':'').($signalText!==''?$signalText:'health'));
    $bat = nm_ap2_run_battery($conn,$fp,$symptom);
    $m = $bat['metrics'];
    $cor = nm_ap2_correlate($conn,$node_id);
    $name = $fp['name'];

    // headline metric from the signal words (e.g. "util 90%", "loss 20 ≥ 15", "CPU 95%")
    $headline='';
    if ($signalText!=='' && preg_match('/(\d{1,3})\s*%/',$signalText,$mm)) $headline=$mm[1].'%';
    elseif ($signalText!=='' && preg_match('/(\d{1,3})\s*(?:≥|>=|de\s+p[eé]rdida|loss)/iu',$signalText,$mm)) $headline=$mm[1].'%';

    $status='inconclusive'; $finding='sin conclusión'; $evidence=''; $action='';
    switch ($symptom) {
        case 'node_down':
            $reach = (string)($m['reach_verdict'] ?? '');
            if ($reach!=='' && strpos($reach,'unreachable')!==false) {
                $up=''; foreach($cor['neighbors'] as $nb){ if($nb['status']!=='up'){ $up=$nb['name']; break; } }
                if ($up!==''){ $status='needs_action'; $finding='caído por '.$up.' (upstream)'; $evidence='unreachable; vecino '.$up.' down'; $action='revisar '.$up; }
                else { $status='problem'; $finding='caído (local, vecinos OK)'; $evidence='reachability=unreachable'; $action='revisar enlace/energía del nodo'; }
            } elseif ($reach!=='') { $status='ok'; $finding='responde'; $evidence='reachability='.$reach; }
            else { $status='inconclusive'; $finding='no se pudo simular alcance'; }
            break;
        case 'resources':
            $cpu=$m['cpu']??null; $mem=$m['mem']??null; $disk=$m['disk']??null;
            $worst=max((float)($cpu??0),(float)($mem??0),(float)($disk??0));
            $evidence='CPU '.round((float)($cpu??0)).'% · RAM '.round((float)($mem??0)).'%'.(isset($m['disk'])?' · disco '.round($disk).'%':'');
            if ($worst>=90){ $status='problem'; $what=($disk!==null&&$disk>=90)?'disco '.round($disk).'%':(($cpu!==null&&$cpu>=90)?'CPU '.round($cpu).'%':'RAM '.round((float)$mem).'%'); $finding=$what.' saturado'; $action='inspeccionar procesos'; }
            elseif ($cpu!==null||$mem!==null){ $status='ok'; $finding='recursos normales'; }
            else { $status='inconclusive'; $finding='sin telemetría de recursos'; }
            break;
        case 'latency_loss':
            if(isset($m['ifaces_err'])&&$m['ifaces_err']>0){ $status='problem'; $finding=($headline!==''?$headline.' pérdida, ':'').$m['ifaces_err'].' iface(s) con errores'; $evidence=$m['ifaces_err'].' ifaces con errores/drops'; $action='revisar duplex/speed y cableado'; }
            elseif($headline!==''){ $status='problem'; $finding=$headline.' de pérdida'; $evidence='loss='.$headline.(isset($m['reach_verdict'])?'; '.$m['reach_verdict']:''); $action='MTR/traceroute + errores de interfaz'; }
            else { $status='inconclusive'; $finding='sin evidencia de pérdida'; }
            break;
        case 'bandwidth':
            if(isset($m['top_talker'])&&$m['top_talker']!==''){ $status='problem'; $finding=($headline!==''?$headline.' util, ':'saturación, ').'top '.$m['top_talker']; $evidence='top talker '.$m['top_talker']; $action='revisar/limitar '.$m['top_talker']; }
            elseif($headline!==''){ $status='problem'; $finding=$headline.' de utilización'; $evidence='util='.$headline; }
            else { $status='inconclusive'; $finding='sin top talker visible'; }
            break;
        case 'routing':
            $chg=$m['route_changes']??null;
            if($chg!==null&&$chg>0){ $status='problem'; $finding=$chg.' cambio(s) de ruta'; $evidence='route_drift='.$chg; $action='verificar vecinos BGP/OSPF'; }
            elseif(isset($m['route_have'])&&$m['route_have']===0){ $status='problem'; $finding='sin ruta al destino'; $evidence='0/'.($m['route_total']??0).' routers con ruta'; $action='verificar RIB/MTU'; }
            else { $status='ok'; $finding='ruteo estable'; $evidence=(isset($m['route_have'])?$m['route_have'].' routers con ruta':'sin drift'); }
            break;
        case 'config':
            $chg=(int)($m['route_changes']??0);
            if($chg>0){ $status='problem'; $finding=$chg.' ruta(s) afectada(s) por el cambio'; $evidence='route_drift='.$chg; $action='revisar la config aplicada'; }
            else { $status='ok'; $finding='cambio de config sin impacto en ruteo'; $evidence='route_drift=0'; }
            break;
        case 'threat':
            $an=(int)($m['anoms']??0);
            if($an>0){ $status='needs_action'; $finding=$an.' indicador(es) activos'; $evidence=$an.' anomalías/amenazas'; $action='immunize / aislar'; }
            else { $status='ok'; $finding='sin indicadores activos'; }
            break;
        default: // generic health scan
            $cpu=$m['cpu']??null; $mem=$m['mem']??null; $disk=$m['disk']??null; $down=$m['ifaces_down']??null;
            $worst=max((float)($cpu??0),(float)($mem??0),(float)($disk??0));
            $evidence='CPU '.round((float)($cpu??0)).'% · RAM '.round((float)($mem??0)).'%'.($down!==null?' · '.$down.' iface(s) down':'');
            if($worst>=90 || ($down!==null&&$down>0)){ $status='problem'; $finding=($worst>=90?('recurso al '.round($worst).'%'):($down.' iface(s) down')); }
            elseif($cpu!==null||$mem!==null){ $status='ok'; $finding='sano'; }
            else { $status='inconclusive'; $finding='sin telemetría'; }
            break;
    }
    $spoken = $finding; if($status==='ok' && $evidence!=='') $spoken = $finding.' ('.$evidence.')';
    $line = nm_ap2_voice_terse($name, $spoken, 90);
    return ['ok'=>true,'data'=>[
        'node'=>$name,'node_id'=>$node_id,'fingerprint'=>$fp,'symptom'=>$symptom,
        'status'=>$status,'finding'=>$finding,'evidence'=>$evidence,'action'=>$action,
        'neighbors'=>$cor['neighbors'],'upstream_down'=>$cor['upstream_down'],
        'tests'=>$bat['tests'],'line'=>$line,
    ]];
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTAINERS LAYER — the 4th WebGL overlay (siblings: X-Ray/Topology/Traffic).
// ENDPOINT-CENTRIC: enumerate EVERY Portainer endpoint (every Docker host) so NO container is ever
// dropped just because its host isn't a monitored node. Each endpoint maps to the node whose IP matches
// its host IP; if none matches (e.g. the "local"/socket endpoint), it groups under the ENDPOINT NAME.
// Universal — works for any customer's setup. Deep detail fetched on FOCUS via nm_ap2_container_detail.
// ═══════════════════════════════════════════════════════════════════════════════
function nm_ap2_containers(mysqli $conn, string $nodeRef='', string $cidRef=''): array {
    if (!function_exists('nm_portainer_cfg')) return ['ok'=>false,'error'=>'container engine unavailable'];
    try {
        $cfg = nm_portainer_cfg($conn);
        if (!function_exists('nm_portainer_configured') || !nm_portainer_configured($cfg)) return ['ok'=>false,'error'=>'Portainer not configured'];
        // node-IP → {id,name} lookup + resolve the focus node (name/ip/id)
        $nodesByIp=[]; $fnid = $nodeRef!=='' ? nm_ap2_resolve_node($conn,$nodeRef) : 0; $fname='';
        $nr=$conn->query("SELECT id,display_name,ip_address FROM nm_nodes");
        while($nr && $nx=$nr->fetch_assoc()){ $ip=trim((string)$nx['ip_address']); if($ip!=='') $nodesByIp[$ip]=['id'=>(int)$nx['id'],'name'=>(string)$nx['display_name']]; if($fnid && (int)$nx['id']===$fnid) $fname=(string)$nx['display_name']; }
        // enumerate ALL Portainer endpoints (every Docker host) — this is what stops containers vanishing
        $epmap = function_exists('nm_portainer_endpoint_map') ? nm_portainer_endpoint_map($cfg) : [];
        if(!$epmap){ $er=nm_portainer_endpoints($cfg); if(!empty($er['ok'])) foreach(nm_portainer_norm_endpoints($er['data']) as $e){ $epmap[(int)$e['id']]=['name'=>$e['name'],'ip'=>nm_portainer_host_ip($cfg,(int)$e['id'],(string)$e['name']),'up'=>$e['up']]; } }
        $out=[];
        foreach($epmap as $eid=>$ep){ $eid=(int)$eid; $ehip=trim((string)($ep['ip']??''));
            // map endpoint → the monitored node with that host IP; else label by the endpoint name (e.g. "local")
            $mnid=0; $mname='';
            if($ehip!=='' && isset($nodesByIp[$ehip])){ $mnid=$nodesByIp[$ehip]['id']; $mname=$nodesByIp[$ehip]['name']; }
            if($mname===''){ $mname=($ep['name']!=='')?(string)$ep['name']:('endpoint '.$eid); $mnid=-$eid; }   // no node → group under endpoint name (synthetic id)
            $cr = nm_portainer_containers($cfg,$eid,true,10);
            if(empty($cr['ok'])) continue;
            $ctrs = array_map('nm_portainer_norm_container',(array)$cr['data']);
            if(!$ctrs) continue;
            if($fnid && $mnid===$fnid) $fname=$mname;
            // latest net rate per container for this endpoint (one query)
            $net=[]; try { $q=$conn->prepare("SELECT s.container_id cid, s.rx_rate rx, s.tx_rate tx FROM container_net_samples s JOIN (SELECT container_id, MAX(sampled_at) mx FROM container_net_samples WHERE endpoint_id=? GROUP BY container_id) t ON t.container_id=s.container_id AND t.mx=s.sampled_at WHERE s.endpoint_id=?");
                $q->bind_param('ii',$eid,$eid); $q->execute(); $rs=$q->get_result(); while($z=$rs->fetch_assoc()){ $net[$z['cid']]=['rx'=>(float)$z['rx'],'tx'=>(float)$z['tx']]; } $q->close(); } catch(\Throwable $e){}
            $nn=0;
            foreach($ctrs as $c){ $nn++; $cid=(string)$c['cid']; $short=substr($cid,0,12);
                $nrr = $net[$cid] ?? ($net[$short] ?? ['rx'=>0,'tx'=>0]);
                $out[] = ['node'=>$mname,'node_id'=>$mnid,'endpoint_id'=>$eid,'cid'=>$cid,'short'=>$short,
                    'name'=>$c['name'],'image'=>$c['image'],'state'=>$c['state'],'status'=>$c['status'],
                    'ports'=>$c['ports'],'stack'=>$c['stack'],'rx'=>$nrr['rx'],'tx'=>$nrr['tx'],'nn'=>$nn,'n'=>0];
                if(count($out)>=160) break;
            }
            if(count($out)>=160) break;
        }
        foreach($out as $i=>&$c){ $c['n']=$i+1; } unset($c);
        // focus: match by real node id OR by the node/endpoint LABEL string (covers the unmatched "local" group)
        $focus=[]; $lc=strtolower(trim($nodeRef));
        if($fnid || $nodeRef!==''){
            $cands=array_values(array_filter($out,function($c) use($fnid,$lc){ return ($fnid && $c['node_id']===$fnid) || ($lc!=='' && strpos(strtolower((string)$c['node']),$lc)!==false); }));
            if($cands){
                if($cidRef!==''){ $cl=strtolower($cidRef);
                    foreach($cands as $c){ if(strpos(strtolower($c['name']),$cl)!==false || strpos(strtolower($c['image']),$cl)!==false || strpos($c['cid'],$cidRef)===0) $focus[]=$c['n']; }
                    if(!$focus && preg_match('/\d+/', $cidRef, $mm)){ $num=(int)$mm[0]; foreach($cands as $c) if($c['nn']===$num) $focus[]=$c['n']; }
                }
                if(!$focus) foreach($cands as $c) $focus[]=$c['n'];   // whole node/endpoint
                if($fname==='') $fname=(string)$cands[0]['node'];
            }
        } elseif($cidRef!==''){ $cl=strtolower($cidRef);
            foreach($out as $c){ if(strpos(strtolower($c['name']),$cl)!==false) $focus[]=$c['n']; }
        }
        $title = $fname!=='' ? ('Containers · focus: '.$fname) : 'Fleet Containers';
        $run=0; foreach($out as $c) if($c['state']==='running') $run++;
        return ['ok'=>true,'node'=>$fname?:'all','node_id'=>$fnid,'title'=>$title,'count'=>count($out),'running'=>$run,'containers'=>$out,'focus'=>array_values(array_unique($focus))];
    } catch(\Throwable $e){ return ['ok'=>false,'error'=>'containers query failed']; }
}

// DEEP detail for ONE container (focus panel + the bot's Q&A): full inspect + volumes with SIZES (biggest /
// dangerous) + partition (SizeRw/SizeRootFs) + live stats + net-traffic history summary. Takes the ENDPOINT id
// directly (from the list) so it works even for containers whose host isn't a monitored node.
function nm_ap2_container_detail(mysqli $conn, int $endpoint_id, string $cid, string $nodeName=''): array {
    if (!function_exists('nm_portainer_cfg')) return ['ok'=>false,'error'=>'container engine unavailable'];
    if ($cid==='' || $endpoint_id<=0) return ['ok'=>false,'error'=>'need endpoint_id + container id'];
    try {
        $cfg = nm_portainer_cfg($conn);
        if (!nm_portainer_configured($cfg)) return ['ok'=>false,'error'=>'Portainer not configured'];
        $eid=$endpoint_id; $nname=$nodeName;
        $insp = nm_portainer_container_inspect($cfg,$eid,$cid,true);
        if(empty($insp['ok'])) return ['ok'=>false,'error'=>'inspect failed: '.($insp['error']??'?')];
        $d = $insp['data']; $cfgc=$d['Config']??[]; $stt=$d['State']??[]; $hc=$d['HostConfig']??[];
        $mounts=[]; foreach(($d['Mounts']??[]) as $m) $mounts[]=['type'=>$m['Type']??'','name'=>$m['Name']??'','source'=>$m['Source']??'','dest'=>$m['Destination']??'','rw'=>($m['RW']??true)];
        // volume SIZES from system/df → flag biggest + dangerous (>2GB or not in use)
        $vsize=[]; $bigVol=null; $dfr = nm_portainer_system_df($cfg,$eid);
        if(!empty($dfr['ok'])){ foreach(($dfr['data']['Volumes']??[]) as $v){ $vn=$v['Name']??''; $sz=(int)($v['UsageData']['Size']??-1); if($vn!==''){ $vsize[$vn]=$sz; } } }
        foreach($mounts as &$m){ if($m['name']!=='' && isset($vsize[$m['name']])){ $m['size']=$vsize[$m['name']]; $m['dangerous']=($vsize[$m['name']]>2*1073741824); if($bigVol===null || $vsize[$m['name']]>($bigVol['size']??-1)) $bigVol=['name'=>$m['name'],'size'=>$vsize[$m['name']],'dest'=>$m['dest']]; } } unset($m);
        $size_rw=(int)($d['SizeRw']??0); $size_root=(int)($d['SizeRootFs']??0);
        // live stats (cpu/mem/net) if running
        $stats=null; if(!empty($stt['Running'])){ $s=nm_portainer_container_stats($cfg,$eid,$cid,15,true); if(!empty($s['ok'])) $stats=nm_portainer_norm_stats($s['data']); }
        // net-traffic history summary (last 6h) from container_net_samples
        $nethist=null; try { $short=substr($cid,0,12);
            $q=$conn->prepare("SELECT ROUND(AVG(rx_rate)) arx, ROUND(AVG(tx_rate)) atx, ROUND(MAX(rx_rate)) prx, ROUND(MAX(tx_rate)) ptx, COUNT(*) n FROM container_net_samples WHERE endpoint_id=? AND container_id IN (?,?) AND sampled_at >= (UTC_TIMESTAMP() - INTERVAL 6 HOUR)");
            $q->bind_param('iss',$eid,$cid,$short); $q->execute(); $nethist=$q->get_result()->fetch_assoc(); $q->close(); } catch(\Throwable $e){}
        $name=ltrim($d['Name']??'','/');
        return ['ok'=>true,'data'=>[
            'node'=>$nname,'endpoint_id'=>$eid,'cid'=>$d['Id']??$cid,'name'=>$name,
            'image'=>$cfgc['Image']??($d['Image']??''),'state'=>strtolower($stt['Status']??''),
            'running'=>(bool)($stt['Running']??false),'health'=>$stt['Health']['Status']??'',
            'restart_count'=>(int)($d['RestartCount']??0),'started_at'=>$stt['StartedAt']??'','oom_killed'=>(bool)($stt['OOMKilled']??false),
            'command'=>implode(' ',(array)($cfgc['Cmd']??[])),'stack'=>($cfgc['Labels']['com.docker.compose.project']??''),
            'partition'=>['size_rw'=>$size_rw,'size_root'=>$size_root,'total'=>$size_rw+$size_root],
            'mounts'=>$mounts,'biggest_volume'=>$bigVol,'stats'=>$stats,'net_history'=>$nethist,
            'network_mode'=>$hc['NetworkMode']??'','privileged'=>(bool)($hc['Privileged']??false),
        ]];
    } catch(\Throwable $e){ return ['ok'=>false,'error'=>'detail failed']; }
}

} // function_exists guard
