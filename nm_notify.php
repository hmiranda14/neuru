<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Notification, escalation & on-call (Pillar 2).
//
//   Incidents (from nm_incidents.php) must REACH a human. This engine:
//     • Channels — where alerts go: n8n webhook, generic webhook, Telegram (Bot
//       API, direct), or email. Secrets encrypted at rest.
//     • Escalation ladder — ordered steps: step 0 fires immediately on open; later
//       steps fire only if the incident is STILL unacknowledged after their delay
//       (PagerDuty-lite). Acknowledging stops escalation.
//     • Maintenance windows — suppress notifications during planned changes.
//     • Dedup/log — each (incident, step) sends once per episode; full history.
//
//   Driven each minute from cron_incidents.php (right after correlation).
// ─────────────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/nm_secrets.php';
require_once __DIR__ . '/nm_audit.php';

if (!function_exists('nm_notify_ensure')) {
    function nm_notify_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        if (!($conn instanceof mysqli)) return;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_notify_channels (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(80) NOT NULL,
            type VARCHAR(16) NOT NULL DEFAULT 'n8n',     -- n8n | webhook | telegram | email
            target VARCHAR(500) NOT NULL,                 -- url | chat_id | email
            secret_enc MEDIUMTEXT,                        -- bot token / bearer (encrypted)
            min_severity VARCHAR(10) NOT NULL DEFAULT 'warning',
            enabled TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_notify_steps (
            id INT AUTO_INCREMENT PRIMARY KEY,
            step_order INT NOT NULL DEFAULT 0,
            after_minutes INT NOT NULL DEFAULT 0,          -- minutes after open (0 = immediate)
            channel_id INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            KEY idx_order (step_order)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_maintenance_windows (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(120) NOT NULL,
            starts_at DATETIME NOT NULL,
            ends_at DATETIME NOT NULL,
            scope VARCHAR(20) NOT NULL DEFAULT 'all',       -- all | node | source
            scope_val VARCHAR(120) DEFAULT NULL,
            enabled TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_notify_log (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            incident_id BIGINT NOT NULL,
            channel_id INT DEFAULT NULL,
            channel_name VARCHAR(80) DEFAULT NULL,
            step_order INT NOT NULL DEFAULT 0,
            event VARCHAR(20) NOT NULL DEFAULT 'open',       -- open | escalate | resolved | suppressed
            severity VARCHAR(10) DEFAULT NULL,
            status VARCHAR(16) NOT NULL DEFAULT 'sent',       -- sent | failed | suppressed
            detail VARCHAR(400) DEFAULT NULL,
            sent_at DATETIME NOT NULL,
            KEY idx_inc (incident_id), KEY idx_time (sent_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        nm_notify_ensure2($conn);   // Center 2.0: rich channels, routing matrix, digest
    }

    function nm_notify_settings($conn): array {
        $d = ['notify_enabled'=>'0','notify_min_severity'=>'warning','notify_resolve_notice'=>'1'];
        $keys = "'" . implode("','", array_keys($d)) . "'";
        if ($r = $conn->query("SELECT setting_key,setting_val FROM nm_settings WHERE setting_key IN ($keys)"))
            while ($x = $r->fetch_assoc()) $d[$x['setting_key']] = $x['setting_val'];
        return ['enabled'=>$d['notify_enabled']==='1', 'min_severity'=>$d['notify_min_severity'],
                'resolve_notice'=>$d['notify_resolve_notice']==='1'];
    }
    function _nf_sev_rank($s){ return ['critical'=>3,'warning'=>2,'info'=>1][$s] ?? 1; }
}

// ═════════════════════════════════════════════════════════════════════════════
// NOTIFICATION CENTER 2.0 — channel catalog · category taxonomy · routing matrix
//  · unified dispatcher · nm_notify_event() front door · digest · rate-limit.
// Everything below is additive; the legacy incident pipeline keeps working.
// ═════════════════════════════════════════════════════════════════════════════

// ── Catalog of every supported channel type + the fields each one needs ──────
if (!function_exists('nm_notify_channel_types')) {
    function nm_notify_channel_types(): array {
        // fields: [key, label, kind(text|secret|number), placeholder, required(bool)]
        return [
            'telegram'  => ['label'=>'Telegram','icon'=>'fa-brands fa-telegram','group'=>'Chat','fields'=>[
                ['token','Bot token','secret','123456:ABC-DEF…',true],['chat_id','Chat ID','text','-1001234567890',true]]],
            'email'     => ['label'=>'Email (SMTP)','icon'=>'fa-solid fa-envelope','group'=>'Email','fields'=>[
                ['to','Recipient email','text','ops@company.com',true]],'note'=>'Uses your SMTP settings (Config → SMTP).'],
            'slack'     => ['label'=>'Slack','icon'=>'fa-brands fa-slack','group'=>'Chat','fields'=>[
                ['webhook_url','Incoming webhook URL','text','https://hooks.slack.com/services/…',true]]],
            'discord'   => ['label'=>'Discord','icon'=>'fa-brands fa-discord','group'=>'Chat','fields'=>[
                ['webhook_url','Webhook URL','text','https://discord.com/api/webhooks/…',true]]],
            'teams'     => ['label'=>'Microsoft Teams','icon'=>'fa-brands fa-microsoft','group'=>'Chat','fields'=>[
                ['webhook_url','Incoming webhook URL','text','https://outlook.office.com/webhook/…',true]]],
            'mattermost'=> ['label'=>'Mattermost','icon'=>'fa-solid fa-comment','group'=>'Chat','fields'=>[
                ['webhook_url','Incoming webhook URL','text','https://mm.host/hooks/…',true]]],
            'googlechat'=> ['label'=>'Google Chat','icon'=>'fa-brands fa-google','group'=>'Chat','fields'=>[
                ['webhook_url','Space webhook URL','text','https://chat.googleapis.com/v1/spaces/…',true]]],
            'gotify'    => ['label'=>'Gotify (self-hosted)','icon'=>'fa-solid fa-bell','group'=>'Push','fields'=>[
                ['base_url','Server URL','text','https://gotify.host',true],['token','App token','secret','A…',true]]],
            'ntfy'      => ['label'=>'ntfy','icon'=>'fa-solid fa-tower-broadcast','group'=>'Push','fields'=>[
                ['base_url','Server URL','text','https://ntfy.sh',true],['topic','Topic','text','neuru-alerts',true],
                ['token','Access token (optional)','secret','tk_…',false]]],
            'pushover'  => ['label'=>'Pushover','icon'=>'fa-solid fa-mobile-screen','group'=>'Push','fields'=>[
                ['token','Application token','secret','a…',true],['user','User / group key','text','u…',true]]],
            'pagerduty' => ['label'=>'PagerDuty','icon'=>'fa-solid fa-triangle-exclamation','group'=>'On-call','fields'=>[
                ['routing_key','Events API v2 routing key','secret','R0…',true]]],
            'opsgenie'  => ['label'=>'Opsgenie','icon'=>'fa-solid fa-headset','group'=>'On-call','fields'=>[
                ['api_key','API key','secret','…',true],['region','Region (us / eu)','text','us',false]]],
            'matrix'    => ['label'=>'Matrix','icon'=>'fa-solid fa-hashtag','group'=>'Chat','fields'=>[
                ['homeserver','Homeserver URL','text','https://matrix.org',true],['room_id','Room ID','text','!abc:matrix.org',true],
                ['token','Access token','secret','syt_…',true]]],
            'twilio_sms'=> ['label'=>'SMS (Twilio)','icon'=>'fa-solid fa-sms','group'=>'SMS / Voice','fields'=>[
                ['sid','Account SID','text','AC…',true],['token','Auth token','secret','…',true],
                ['from','From number','text','+15550001111',true],['to','To number','text','+15552223333',true]]],
            'twilio_whatsapp'=> ['label'=>'WhatsApp (Twilio)','icon'=>'fa-brands fa-whatsapp','group'=>'SMS / Voice','fields'=>[
                ['sid','Account SID','text','AC…',true],['token','Auth token','secret','…',true],
                ['from','From (WA-enabled)','text','+14155238886',true],['to','To number','text','+15552223333',true]]],
            'webhook'   => ['label'=>'Generic webhook','icon'=>'fa-solid fa-code','group'=>'Custom','fields'=>[
                ['url','POST URL','text','https://hooks…',true],['bearer','Bearer token (optional)','secret','',false]]],
            'n8n'       => ['label'=>'n8n workflow','icon'=>'fa-solid fa-diagram-project','group'=>'Custom','fields'=>[
                ['url','n8n webhook URL','text','http://n8n:5678/webhook/neuru-notify',true]],
                'note'=>'POSTs JSON; NEURU adds the shared X-NetMon-Token. Route onward to anything in n8n.'],
        ];
    }
    // Which stored keys are secrets (encrypted at rest inside config_enc)
    function _nf_secret_keys(string $type): array {
        $out = [];
        foreach ((nm_notify_channel_types()[$type]['fields'] ?? []) as $f) if (($f[2] ?? '')==='secret') $out[] = $f[0];
        return $out;
    }
}

// ── Canonical event categories (what you can subscribe channels to) ──────────
if (!function_exists('nm_notify_categories')) {
    function nm_notify_categories(): array {
        // key => [label, icon, group, default severity]
        return [
            'node_down'  => ['Node / host down','fa-server','Availability','critical'],
            'iface_down' => ['Interface down','fa-ethernet','Availability','warning'],
            'database'   => ['Database unreachable','fa-database','Availability','critical'],
            'federation' => ['Site / cluster offline','fa-diagram-project','Availability','critical'],
            'service'    => ['Service failed / restarted','fa-gears','Availability','warning'],
            'latency'    => ['Latency / SLA breach','fa-gauge-high','Performance','warning'],
            'netflow'    => ['Bandwidth / traffic','fa-chart-area','Performance','warning'],
            'capacity'   => ['CPU / RAM / disk','fa-microchip','Performance','warning'],
            'gpu'        => ['GPU / AI compute','fa-bolt','Performance','warning'],
            'predictive' => ['Predictive health','fa-heart-pulse','AI / Ops','warning'],
            'ai_insight' => ['AI insight / anomaly','fa-brain','AI / Ops','warning'],
            'incident'   => ['Correlated incident','fa-triangle-exclamation','AI / Ops','warning'],
            'security'   => ['Security / threat','fa-shield-halved','Security','warning'],
            'config'     => ['Config change / drift','fa-file-code','Infrastructure','warning'],
            'container'  => ['Container health','fa-cube','Infrastructure','warning'],
            'event_log'  => ['Event log (Win/Linux/syslog)','fa-list','Infrastructure','info'],
            'system'     => ['NEURU system (update / license)','fa-gear','System','info'],
        ];
    }
    // Smart routing defaults seeded on first run: [category => [min_severity, mode]]
    function nm_notify_smart_defaults(): array {
        return [
            'node_down'=>['critical','immediate'], 'database'=>['critical','immediate'],
            'federation'=>['critical','immediate'], 'security'=>['warning','immediate'],
            'service'=>['warning','immediate'], 'iface_down'=>['warning','immediate'],
            'incident'=>['warning','immediate'], 'predictive'=>['warning','immediate'],
            'capacity'=>['warning','immediate'], 'latency'=>['warning','immediate'],
            'config'=>['warning','immediate'], 'netflow'=>['warning','immediate'],
            'ai_insight'=>['warning','immediate'], 'container'=>['warning','immediate'],
            'gpu'=>['warning','immediate'],
            'event_log'=>['warning','digest'], 'system'=>['info','digest'],
        ];
    }
    // Map a correlated incident (root_source + title) → a taxonomy category
    function nm_notify_incident_category(array $inc): string {
        $src = strtolower((string)($inc['root_source'] ?? ''));
        $title = strtolower((string)($inc['title'] ?? ''));
        if (strpos($title,'interface down')!==false || strpos($title,'iface')!==false) return 'iface_down';
        $map = ['node_down'=>'node_down','database'=>'database','cluster'=>'federation','config'=>'config',
                'latency'=>'latency','netflow'=>'netflow','container'=>'container','container_net'=>'container',
                'ai'=>'ai_insight','security'=>'security','immunity'=>'security'];
        return $map[$src] ?? 'incident';
    }
}

// ── v2 schema: extra channel cols + routing matrix + digest + smart seed ─────
if (!function_exists('nm_notify_ensure2')) {
    function _nf_has_col($conn, string $table, string $col): bool {
        try { $q = $conn->query("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='".$conn->real_escape_string($table)."' AND COLUMN_NAME='".$conn->real_escape_string($col)."' LIMIT 1");
              return $q && $q->fetch_row() ? true : false; } catch (\Throwable $e) { return true; }
    }
    function _nf_add_col($conn, string $table, string $col, string $ddl): void {
        if (!_nf_has_col($conn,$table,$col)) { try { $conn->query("ALTER TABLE $table ADD COLUMN $col $ddl"); } catch (\Throwable $e) {} }
    }
    function nm_notify_ensure2($conn): void {
        if (!($conn instanceof mysqli)) return;
        // richer channel config (multi-field types + anti-flood)
        _nf_add_col($conn,'nm_notify_channels','config_enc','MEDIUMTEXT NULL');
        _nf_add_col($conn,'nm_notify_channels','rate_limit_sec','INT NOT NULL DEFAULT 0');
        _nf_add_col($conn,'nm_notify_channels','quiet_start','VARCHAR(5) NULL');
        _nf_add_col($conn,'nm_notify_channels','quiet_end','VARCHAR(5) NULL');
        // log gets a category + dedup key + nullable incident (direct events have none)
        _nf_add_col($conn,'nm_notify_log','category','VARCHAR(32) NULL');
        _nf_add_col($conn,'nm_notify_log','dedup_key','VARCHAR(64) NULL');
        try { $conn->query("CREATE TABLE IF NOT EXISTS nm_notify_routes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            category VARCHAR(32) NOT NULL,
            channel_id INT NOT NULL,
            min_severity VARCHAR(10) NOT NULL DEFAULT 'warning',
            mode VARCHAR(10) NOT NULL DEFAULT 'immediate',     -- immediate | digest | off
            enabled TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_cat_ch (category,channel_id), KEY idx_cat (category)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); } catch (\Throwable $e) {}
        try { $conn->query("CREATE TABLE IF NOT EXISTS nm_notify_digest (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            channel_id INT NOT NULL,
            category VARCHAR(32) NOT NULL,
            severity VARCHAR(10) NOT NULL DEFAULT 'info',
            title VARCHAR(240) NOT NULL,
            body VARCHAR(600) DEFAULT NULL,
            created_at DATETIME NOT NULL,
            KEY idx_ch (channel_id), KEY idx_time (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); } catch (\Throwable $e) {}
        nm_notify_seed_defaults($conn);
    }
    // One-time: build the smart-default subscription matrix + guarantee an immediate step.
    function nm_notify_seed_defaults($conn): void {
        try {
            $f = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='notify_v2_seeded' LIMIT 1");
            if ($f && $f->fetch_row()) return;                       // already seeded
        } catch (\Throwable $e) { return; }
        try {
            // any enabled channels to seed toward? (prefer them all)
            $chs = [];
            $r = $conn->query("SELECT id FROM nm_notify_channels WHERE enabled=1 ORDER BY id");
            while ($r && $x=$r->fetch_row()) $chs[] = (int)$x[0];
            $rc = $conn->query("SELECT COUNT(*) FROM nm_notify_routes"); $have = $rc ? (int)($rc->fetch_row()[0] ?? 0) : 0;
            if ($have === 0 && $chs) {
                $sd = nm_notify_smart_defaults();
                foreach (array_keys(nm_notify_categories()) as $cat) {
                    [$sev,$mode] = $sd[$cat] ?? ['warning','immediate'];
                    foreach ($chs as $cid) {
                        $st = $conn->prepare("INSERT IGNORE INTO nm_notify_routes (category,channel_id,min_severity,mode,enabled) VALUES (?,?,?,?,1)");
                        $st->bind_param('siss',$cat,$cid,$sev,$mode); $st->execute(); $st->close();
                    }
                }
            }
            // guarantee an immediate (step 0) escalation step so incidents never wait
            $sc = $conn->query("SELECT COUNT(*) FROM nm_notify_steps WHERE after_minutes=0");
            $has0 = $sc ? (int)($sc->fetch_row()[0] ?? 0) : 1;
            if (!$has0 && $chs) {
                $st = $conn->prepare("INSERT INTO nm_notify_steps (step_order,after_minutes,channel_id) VALUES (0,0,?)");
                $cid=$chs[0]; $st->bind_param('i',$cid); $st->execute(); $st->close();
            }
        } catch (\Throwable $e) { /* seeding is best-effort */ }
        try { $st=$conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES('notify_v2_seeded','1') ON DUPLICATE KEY UPDATE setting_val='1'"); $st->execute(); $st->close(); } catch (\Throwable $e) {}
    }
}

// ── Channel Center 2.0: read/save with the config_enc blob ───────────────────
if (!function_exists('nm_notify_channel_config')) {
    // Decode the effective config for a channel row (merges new config_enc with
    // the legacy target/secret so the two pre-2.0 channels keep working).
    function nm_notify_channel_config(array $row): array {
        $cfg = [];
        $raw = trim((string)($row['config_enc'] ?? ''));
        if ($raw !== '') { $dec = nm_secret_decrypt($raw); $j = json_decode((string)$dec, true); if (is_array($j)) $cfg = $j; }
        $type = $row['type'] ?? '';
        // legacy fallback
        if ($type==='telegram') { $cfg += ['chat_id'=>$row['target']??'', 'token'=>nm_secret_decrypt($row['secret_enc']??'')]; }
        elseif ($type==='email') { $cfg += ['to'=>$row['target']??'']; }
        elseif ($type==='webhook') { $cfg += ['url'=>$row['target']??'', 'bearer'=>nm_secret_decrypt($row['secret_enc']??'')]; }
        elseif ($type==='n8n') { $cfg += ['url'=>$row['target']??'']; }
        return $cfg;
    }
    // Save/update a channel from a flat field map (config[key]=>value). Secret
    // fields left blank on edit keep their stored value.
    function nm_notify_channel_save2($conn, array $d): array {
        nm_notify_ensure($conn);
        $id   = (int)($d['id'] ?? 0);
        $name = trim($d['name'] ?? '') ?: 'Channel';
        $type = $d['type'] ?? 'telegram';
        $types = nm_notify_channel_types();
        if (!isset($types[$type])) return ['ok'=>false,'err'=>'Unknown channel type'];
        $sev  = in_array($d['min_severity'] ?? '', ['critical','warning','info'], true) ? $d['min_severity'] : 'warning';
        $en   = !empty($d['enabled']) ? 1 : 0;
        $rate = max(0,(int)($d['rate_limit_sec'] ?? 0));
        $qs = trim($d['quiet_start'] ?? ''); $qe = trim($d['quiet_end'] ?? '');
        $in   = is_array($d['config'] ?? null) ? $d['config'] : [];
        // start from existing config on edit so blank secrets are preserved
        $prev = [];
        if ($id) { $g = nm_notify_channel_get($conn,$id); if ($g) $prev = nm_notify_channel_config($g); }
        $cfg = $prev;
        foreach (($types[$type]['fields']) as $f) {
            $k=$f[0]; $isSecret=($f[2]==='secret'); $req=!empty($f[4]);
            $v = array_key_exists($k,$in) ? trim((string)$in[$k]) : '';
            if ($isSecret && $v==='') continue;         // keep prior secret
            if ($v!=='' || !$isSecret) $cfg[$k] = $v;
            if ($req && trim((string)($cfg[$k] ?? ''))==='') return ['ok'=>false,'err'=>$f[1].' is required'];
        }
        // legacy mirror so old readers still see something sensible
        $target = $cfg['chat_id'] ?? $cfg['to'] ?? $cfg['url'] ?? $cfg['webhook_url'] ?? $cfg['base_url'] ?? '';
        $enc = nm_secret_encrypt(json_encode($cfg));
        if ($id) {
            $st=$conn->prepare("UPDATE nm_notify_channels SET name=?,type=?,target=?,config_enc=?,min_severity=?,enabled=?,rate_limit_sec=?,quiet_start=?,quiet_end=? WHERE id=?");
            $st->bind_param('sssssiissi',$name,$type,$target,$enc,$sev,$en,$rate,$qs,$qe,$id); $st->execute(); $st->close();
        } else {
            $st=$conn->prepare("INSERT INTO nm_notify_channels (name,type,target,secret_enc,config_enc,min_severity,enabled,rate_limit_sec,quiet_start,quiet_end) VALUES (?,?,?,'',?,?,?,?,?,?)");
            $st->bind_param('sssssiiss',$name,$type,$target,$enc,$sev,$en,$rate,$qs,$qe); $st->execute(); $id=$st->insert_id; $st->close();
        }
        return ['ok'=>true,'id'=>$id];
    }
}

// ── Admin-safe channel list (secrets masked) + generic test send ─────────────
if (!function_exists('nm_notify_channels2')) {
    function nm_notify_channels2($conn): array {
        nm_notify_ensure($conn); $out=[]; $types=nm_notify_channel_types();
        $r=$conn->query("SELECT * FROM nm_notify_channels ORDER BY id");
        while ($r && $x=$r->fetch_assoc()) {
            $cfg=nm_notify_channel_config($x); $safe=[]; $flags=[];
            foreach (($types[$x['type']]['fields'] ?? []) as $f) {
                $k=$f[0];
                if (($f[2] ?? '')==='secret') $flags['has_'.$k]=trim((string)($cfg[$k]??''))!==''; // never expose the value
                else $safe[$k]=$cfg[$k] ?? '';
            }
            $out[]=['id'=>(int)$x['id'],'name'=>$x['name'],'type'=>$x['type'],'min_severity'=>$x['min_severity'],
                'enabled'=>(int)$x['enabled']===1,'rate_limit_sec'=>(int)($x['rate_limit_sec']??0),
                'quiet_start'=>(string)($x['quiet_start']??''),'quiet_end'=>(string)($x['quiet_end']??''),
                'config'=>$safe,'flags'=>$flags];
        }
        return $out;
    }
    function nm_notify_test($conn, int $cid): array {
        $full=nm_notify_channel_get($conn,$cid); if(!$full) return ['ok'=>false,'err'=>'no channel'];
        $msg=['title'=>'NEURU test notification',
              'text'=>"✅ NEURU test notification\nChannel: {$full['name']} ({$full['type']})\nIf you can read this, delivery is working.",
              'severity'=>'info','category'=>'system','payload'=>['event'=>'neuru.test','channel'=>$full['name']]];
        return nm_notify_dispatch($conn,$full,$msg);
    }
    // Per-channel health from the delivery log (consecutive trailing failures).
    function nm_notify_channel_health($conn): array {
        nm_notify_ensure($conn); $h=[];
        $r=$conn->query("SELECT channel_id,status FROM nm_notify_log WHERE channel_id IS NOT NULL AND status IN ('sent','failed') ORDER BY id DESC LIMIT 400");
        while ($r && $x=$r->fetch_assoc()) {
            $cid=(int)$x['channel_id'];
            if (!isset($h[$cid])) $h[$cid]=['fails'=>0,'done'=>false,'last'=>$x['status']];
            if ($h[$cid]['done']) continue;
            if ($x['status']==='failed') $h[$cid]['fails']++; else $h[$cid]['done']=true;
        }
        return $h;
    }
}

// ── Routing matrix CRUD ──────────────────────────────────────────────────────
if (!function_exists('nm_notify_routes')) {
    function nm_notify_routes($conn): array {
        nm_notify_ensure($conn); $out=[];
        $r=$conn->query("SELECT id,category,channel_id,min_severity,mode,enabled FROM nm_notify_routes");
        while($r&&$x=$r->fetch_assoc()){ $x['channel_id']=(int)$x['channel_id']; $x['enabled']=(int)$x['enabled']; $out[]=$x; }
        return $out;
    }
    // Upsert one cell of the matrix. mode 'off' (or enabled=0) disables the route.
    function nm_notify_route_set($conn, string $cat, int $cid, string $sev, string $mode, int $enabled): array {
        nm_notify_ensure($conn);
        if (!isset(nm_notify_categories()[$cat])) return ['ok'=>false,'err'=>'bad category'];
        $sev = in_array($sev,['critical','warning','info'],true)?$sev:'warning';
        $mode = in_array($mode,['immediate','digest','off'],true)?$mode:'immediate';
        if ($mode==='off') $enabled=0;
        $st=$conn->prepare("INSERT INTO nm_notify_routes (category,channel_id,min_severity,mode,enabled) VALUES (?,?,?,?,?)
                            ON DUPLICATE KEY UPDATE min_severity=VALUES(min_severity),mode=VALUES(mode),enabled=VALUES(enabled)");
        $st->bind_param('sissi',$cat,$cid,$sev,$mode,$enabled); $st->execute(); $st->close();
        return ['ok'=>true];
    }
    function nm_notify_routes_for($conn, string $cat): array {
        $out=[]; $st=$conn->prepare("SELECT channel_id,min_severity,mode FROM nm_notify_routes WHERE category=? AND enabled=1");
        $st->bind_param('s',$cat); $st->execute(); $rs=$st->get_result();
        while($rs&&$x=$rs->fetch_assoc()){ $x['channel_id']=(int)$x['channel_id']; $out[]=$x; } $st->close();
        return $out;
    }
}

// ── Channel CRUD ─────────────────────────────────────────────────────────────
if (!function_exists('nm_notify_channels')) {
    function nm_notify_channels($conn, bool $onlyEnabled = false): array {
        nm_notify_ensure($conn);
        $w = $onlyEnabled ? "WHERE enabled=1" : "";
        $out = [];
        $r = $conn->query("SELECT id,name,type,target,secret_enc,min_severity,enabled FROM nm_notify_channels $w ORDER BY id");
        while ($r && $x = $r->fetch_assoc()) {
            $out[] = ['id'=>(int)$x['id'],'name'=>$x['name'],'type'=>$x['type'],'target'=>$x['target'],
                'min_severity'=>$x['min_severity'],'enabled'=>(int)$x['enabled']===1,
                'has_secret'=>trim((string)nm_secret_decrypt($x['secret_enc']))!==''];
        }
        return $out;
    }
    function nm_notify_channel_get($conn, int $id): ?array {
        nm_notify_ensure($conn);
        $r = $conn->query("SELECT * FROM nm_notify_channels WHERE id=$id LIMIT 1");
        $x = $r ? $r->fetch_assoc() : null; if (!$x) return null;
        $x['secret'] = nm_secret_decrypt($x['secret_enc']); return $x;
    }
    function nm_notify_channel_save($conn, array $d): array {
        nm_notify_ensure($conn);
        $id = (int)($d['id'] ?? 0);
        $name = trim($d['name'] ?? '') ?: 'Channel';
        $type = in_array($d['type'] ?? '', ['n8n','webhook','telegram','email'], true) ? $d['type'] : 'n8n';
        $target = trim($d['target'] ?? '');
        $sev = in_array($d['min_severity'] ?? '', ['critical','warning','info'], true) ? $d['min_severity'] : 'warning';
        $en = !empty($d['enabled']) ? 1 : 0;
        $secret = (string)($d['secret'] ?? '');
        if ($target === '') return ['ok'=>false,'err'=>'Target (URL / chat id / email) is required'];
        if ($id) {
            if ($secret !== '') { $enc = nm_secret_encrypt($secret);
                $st = $conn->prepare("UPDATE nm_notify_channels SET name=?,type=?,target=?,secret_enc=?,min_severity=?,enabled=? WHERE id=?");
                $st->bind_param('sssssii',$name,$type,$target,$enc,$sev,$en,$id);
            } else {
                $st = $conn->prepare("UPDATE nm_notify_channels SET name=?,type=?,target=?,min_severity=?,enabled=? WHERE id=?");
                $st->bind_param('ssssii',$name,$type,$target,$sev,$en,$id);
            }
            $st->execute(); $st->close();
        } else {
            $enc = $secret !== '' ? nm_secret_encrypt($secret) : '';
            $st = $conn->prepare("INSERT INTO nm_notify_channels (name,type,target,secret_enc,min_severity,enabled) VALUES (?,?,?,?,?,?)");
            $st->bind_param('sssssi',$name,$type,$target,$enc,$sev,$en); $st->execute(); $id=$st->insert_id; $st->close();
        }
        return ['ok'=>true,'id'=>$id];
    }
    function nm_notify_channel_delete($conn, int $id): void {
        nm_notify_ensure($conn);
        $conn->query("DELETE FROM nm_notify_channels WHERE id=$id");
        $conn->query("DELETE FROM nm_notify_steps WHERE channel_id=$id");
    }
}

// ── Escalation ladder ────────────────────────────────────────────────────────
if (!function_exists('nm_notify_steps')) {
    function nm_notify_steps($conn): array {
        nm_notify_ensure($conn);
        $out = [];
        $r = $conn->query("SELECT s.id,s.step_order,s.after_minutes,s.channel_id,c.name channel_name,c.type
                           FROM nm_notify_steps s LEFT JOIN nm_notify_channels c ON c.id=s.channel_id
                           ORDER BY s.step_order, s.id");
        while ($r && $x = $r->fetch_assoc()) $out[] = $x;
        return $out;
    }
    function nm_notify_step_save($conn, array $d): array {
        nm_notify_ensure($conn);
        $ch = (int)($d['channel_id'] ?? 0); if (!$ch) return ['ok'=>false,'err'=>'Pick a channel'];
        $ord = (int)($d['step_order'] ?? 0);
        $mins = max(0, (int)($d['after_minutes'] ?? 0));
        $id = (int)($d['id'] ?? 0);
        if ($id) { $st=$conn->prepare("UPDATE nm_notify_steps SET step_order=?,after_minutes=?,channel_id=? WHERE id=?");
            $st->bind_param('iiii',$ord,$mins,$ch,$id); }
        else { $st=$conn->prepare("INSERT INTO nm_notify_steps (step_order,after_minutes,channel_id) VALUES (?,?,?)");
            $st->bind_param('iii',$ord,$mins,$ch); }
        $st->execute(); $st->close(); return ['ok'=>true];
    }
    function nm_notify_step_delete($conn, int $id): void { nm_notify_ensure($conn); $conn->query("DELETE FROM nm_notify_steps WHERE id=$id"); }
}

// ── Maintenance windows ──────────────────────────────────────────────────────
if (!function_exists('nm_maint_windows')) {
    function nm_maint_windows($conn): array {
        nm_notify_ensure($conn);
        $out = [];
        $r = $conn->query("SELECT *, (NOW() BETWEEN starts_at AND ends_at AND enabled=1) AS active FROM nm_maintenance_windows ORDER BY starts_at DESC");
        while ($r && $x = $r->fetch_assoc()) $out[] = $x;
        return $out;
    }
    function nm_maint_save($conn, array $d): array {
        nm_notify_ensure($conn);
        $id=(int)($d['id']??0); $name=trim($d['name']??'')?:'Maintenance';
        $s=trim($d['starts_at']??''); $e=trim($d['ends_at']??'');
        $scope=in_array($d['scope']??'',['all','node','source'],true)?$d['scope']:'all';
        $sv=trim($d['scope_val']??''); $en=!empty($d['enabled'])?1:0;
        if($s===''||$e==='') return ['ok'=>false,'err'=>'Start and end are required'];
        if($id){ $st=$conn->prepare("UPDATE nm_maintenance_windows SET name=?,starts_at=?,ends_at=?,scope=?,scope_val=?,enabled=? WHERE id=?");
            $st->bind_param('sssssii',$name,$s,$e,$scope,$sv,$en,$id); }
        else { $st=$conn->prepare("INSERT INTO nm_maintenance_windows (name,starts_at,ends_at,scope,scope_val,enabled) VALUES (?,?,?,?,?,?)");
            $st->bind_param('sssssi',$name,$s,$e,$scope,$sv,$en); }
        $st->execute(); $st->close(); return ['ok'=>true];
    }
    function nm_maint_delete($conn, int $id): void { nm_notify_ensure($conn); $conn->query("DELETE FROM nm_maintenance_windows WHERE id=$id"); }

    // Site-wide maintenance gate. EVERY alert path (incidents AND the per-module
    // webhook alerts in smokeping/netflow/netstats) calls this so a maintenance
    // window silences everything consistently. Pass a node id and/or a source tag.
    //  • scope 'all'    → suppresses every alert everywhere
    //  • scope 'node'   → suppresses alerts for that node id
    //  • scope 'source' → suppresses alerts tagged with that source (e.g. 'smokeping')
    function nm_notify_maint_active($conn, $nodeId = null, $source = null): bool {
        try {
            $r = $conn->query("SELECT scope,scope_val FROM nm_maintenance_windows
                               WHERE enabled=1 AND NOW() BETWEEN starts_at AND ends_at");
            while ($r && $x = $r->fetch_assoc()) {
                if ($x['scope'] === 'all') return true;
                if ($x['scope'] === 'node'   && $nodeId !== null && (string)$x['scope_val'] !== '' && (string)$x['scope_val'] === (string)$nodeId) return true;
                if ($x['scope'] === 'source' && $source !== null && $x['scope_val'] === $source) return true;
            }
        } catch (\Throwable $e) { /* table not provisioned yet → treat as not in maintenance */ }
        return false;
    }
    // Is this incident currently inside an active maintenance window?
    function nm_notify_in_maintenance($conn, array $inc): bool {
        return nm_notify_maint_active($conn, $inc['root_node_id'] ?? null, $inc['root_source'] ?? null);
    }
}

// ── Dispatch one notification to one channel ─────────────────────────────────
if (!function_exists('nm_notify_send')) {
    function nm_notify_msg(array $inc, string $event): array {
        $emoji = ['critical'=>'🔴','warning'=>'🟠','info'=>'🔵'][$inc['severity']] ?? '⚪';
        if ($event === 'resolved') $emoji = '✅';
        $base = (((!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http').'://'.($_SERVER['HTTP_HOST'] ?? 'localhost'));
        $url = $base . '/incidents.php';
        $title = $inc['title'];
        $lines = [
            "{$emoji} " . strtoupper($inc['severity']) . ($event==='resolved'?' — RESOLVED':($event==='escalate'?' — ESCALATED':'')) . " · {$title}",
        ];
        if (!empty($inc['root_source'])) $lines[] = "Root cause: {$inc['root_source']}" . (!empty($inc['root_entity'])?" · {$inc['root_entity']}":"");
        if (!empty($inc['impact']) && (int)($inc['impact_count']??0) > 1) $lines[] = "Impact: {$inc['impact']}";
        $lines[] = ($inc['signal_count'] ?? 0) . " correlated signal(s) · opened " . substr($inc['opened_at'] ?? '', 5, 11);
        $lines[] = $url;
        return ['text'=>implode("\n", $lines), 'url'=>$url,
            'payload'=>['event'=>'incident.'.$event, 'incident_id'=>(int)$inc['id'], 'title'=>$title,
                'severity'=>$inc['severity'], 'root_cause'=>$inc['root_source'] ?? null, 'root_entity'=>$inc['root_entity'] ?? null,
                'impact'=>$inc['impact'] ?? null, 'signal_count'=>(int)($inc['signal_count'] ?? 0),
                'opened_at'=>$inc['opened_at'] ?? null, 'url'=>$url]];
    }

    // Back-compat wrapper: build an incident message and hand it to the unified
    // dispatcher so incidents + direct events share one transport layer.
    function nm_notify_send($conn, array $ch, array $inc, string $event): array {
        $m = nm_notify_msg($inc, $event);
        $msg = ['title'=>$inc['title'] ?? 'NEURU', 'text'=>$m['text'], 'severity'=>$inc['severity'] ?? 'info',
                'url'=>$m['url'], 'category'=>nm_notify_incident_category($inc), 'event'=>$event, 'payload'=>$m['payload']];
        return nm_notify_dispatch($conn, $ch, $msg);
    }
    function _nf_post(string $url, array $body, array $headers, bool $json = false): array {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_POST=>true,
            CURLOPT_POSTFIELDS => $json ? json_encode($body) : $body,
            CURLOPT_HTTPHEADER => $headers, CURLOPT_CONNECTTIMEOUT=>5, CURLOPT_TIMEOUT=>12,
            CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_SSL_VERIFYHOST=>false]);
        $resp = curl_exec($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); $err=curl_error($ch); curl_close($ch);
        if ($resp === false || $code === 0) return ['ok'=>false,'err'=>$err ?: 'connection failed'];
        if ($code < 200 || $code >= 300) return ['ok'=>false,'err'=>'HTTP '.$code];
        return ['ok'=>true];
    }
    function _nf_log($conn, $incId, $ch, $step, $event, $sev, $status, $detail){
        $now = date('Y-m-d H:i:s'); $cid = $ch['id'] ?? null; $cname = $ch['name'] ?? null;
        $st = $conn->prepare("INSERT INTO nm_notify_log (incident_id,channel_id,channel_name,step_order,event,severity,status,detail,sent_at) VALUES (?,?,?,?,?,?,?,?,?)");
        $detail = substr((string)$detail,0,390);
        $st->bind_param('iisisssss', $incId,$cid,$cname,$step,$event,$sev,$status,$detail,$now); $st->execute(); $st->close();
    }
}

// ── Unified dispatcher — formats one message for any channel type ────────────
if (!function_exists('nm_notify_dispatch')) {
    function _nf_prio(string $sev, string $scheme) {
        $r = _nf_sev_rank($sev); // critical=3 warning=2 info=1
        switch ($scheme) {
            case 'gotify':   return [3=>8,2=>5,1=>2][$r] ?? 4;
            case 'pushover': return [3=>1,2=>0,1=>-1][$r] ?? 0;
            case 'ntfy':     return [3=>5,2=>4,1=>3][$r] ?? 3;
            case 'pd':       return [3=>'critical',2=>'warning',1=>'info'][$r] ?? 'warning';
            case 'opsgenie': return [3=>'P1',2=>'P3',1=>'P5'][$r] ?? 'P3';
        }
        return $r;
    }
    // General HTTP helper (any method / raw or form body / basic auth).
    function _nf_http(string $url, string $method, $body, array $headers = [], ?array $auth = null): array {
        $c = curl_init($url);
        $opt = [CURLOPT_RETURNTRANSFER=>true, CURLOPT_CUSTOMREQUEST=>$method, CURLOPT_HTTPHEADER=>$headers,
                CURLOPT_CONNECTTIMEOUT=>6, CURLOPT_TIMEOUT=>14, CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_SSL_VERIFYHOST=>false];
        if ($body !== null) $opt[CURLOPT_POSTFIELDS] = $body;
        if ($auth) { $opt[CURLOPT_USERPWD] = $auth[0].':'.$auth[1]; $opt[CURLOPT_HTTPAUTH] = CURLAUTH_BASIC; }
        curl_setopt_array($c, $opt);
        $resp = curl_exec($c); $code=(int)curl_getinfo($c,CURLINFO_HTTP_CODE); $err=curl_error($c); curl_close($c);
        if ($resp === false || $code === 0) return ['ok'=>false,'err'=>$err ?: 'connection failed'];
        if ($code < 200 || $code >= 300) return ['ok'=>false,'err'=>'HTTP '.$code.' '.substr((string)$resp,0,120)];
        return ['ok'=>true];
    }

    // $msg = [title, text, severity, url, category, payload?]
    function nm_notify_dispatch($conn, array $ch, array $msg): array {
        $type = $ch['type'] ?? '';
        $cfg  = nm_notify_channel_config($ch);
        $text = (string)($msg['text'] ?? $msg['title'] ?? 'NEURU notification');
        $sev  = $msg['severity'] ?? 'info';
        $title= (string)($msg['title'] ?? 'NEURU');
        try {
            switch ($type) {
            case 'telegram':
                if (($cfg['token']??'')==='' ) return ['ok'=>false,'err'=>'No bot token'];
                return _nf_post("https://api.telegram.org/bot{$cfg['token']}/sendMessage",
                    ['chat_id'=>$cfg['chat_id']??'', 'text'=>$text, 'disable_web_page_preview'=>true], []);
            case 'email':
                require_once __DIR__ . '/nm_smtp.php';
                $subj='[NEURU] '.strtoupper($sev).': '.$title; $e=null;
                $ok=nm_smtp_send($conn, $cfg['to']??'', $subj, $text, $e);
                return $ok?['ok'=>true]:['ok'=>false,'err'=>$e?:'SMTP send failed (configure SMTP in Config)'];
            case 'slack': case 'mattermost':
                return _nf_http($cfg['webhook_url']??'', 'POST', json_encode(['text'=>$text]), ['Content-Type: application/json']);
            case 'discord':
                return _nf_http($cfg['webhook_url']??'', 'POST', json_encode(['content'=>mb_substr($text,0,1900)]), ['Content-Type: application/json']);
            case 'googlechat':
                return _nf_http($cfg['webhook_url']??'', 'POST', json_encode(['text'=>$text]), ['Content-Type: application/json']);
            case 'teams':
                $card=['@type'=>'MessageCard','@context'=>'http://schema.org/extensions',
                       'themeColor'=>($sev==='critical'?'e74c3c':($sev==='warning'?'f39c12':'4da3ff')),
                       'summary'=>$title,'text'=>str_replace("\n","\n\n",$text)];
                return _nf_http($cfg['webhook_url']??'', 'POST', json_encode($card), ['Content-Type: application/json']);
            case 'gotify':
                $u=rtrim($cfg['base_url']??'','/')."/message?token=".rawurlencode($cfg['token']??'');
                return _nf_http($u,'POST',http_build_query(['title'=>$title,'message'=>$text,'priority'=>_nf_prio($sev,'gotify')]),
                    ['Content-Type: application/x-www-form-urlencoded']);
            case 'ntfy':
                $u=rtrim($cfg['base_url']??'https://ntfy.sh','/').'/'.rawurlencode($cfg['topic']??'');
                $h=['Title: '.$title,'Priority: '._nf_prio($sev,'ntfy')];
                if(($cfg['token']??'')!=='') $h[]='Authorization: Bearer '.$cfg['token'];
                return _nf_http($u,'POST',$text,$h);
            case 'pushover':
                return _nf_http('https://api.pushover.net/1/messages.json','POST',
                    http_build_query(['token'=>$cfg['token']??'','user'=>$cfg['user']??'','title'=>$title,'message'=>$text,'priority'=>_nf_prio($sev,'pushover')]),
                    ['Content-Type: application/x-www-form-urlencoded']);
            case 'pagerduty':
                $body=['routing_key'=>$cfg['routing_key']??'','event_action'=>'trigger',
                    'payload'=>['summary'=>mb_substr($title,0,1024),'source'=>'NEURU','severity'=>_nf_prio($sev,'pd'),'custom_details'=>['text'=>$text]]];
                return _nf_http('https://events.pagerduty.com/v2/enqueue','POST',json_encode($body),['Content-Type: application/json']);
            case 'opsgenie':
                $host=(strtolower($cfg['region']??'us')==='eu')?'https://api.eu.opsgenie.com':'https://api.opsgenie.com';
                return _nf_http($host.'/v2/alerts','POST',json_encode(['message'=>mb_substr($title,0,130),'description'=>$text,'priority'=>_nf_prio($sev,'opsgenie')]),
                    ['Content-Type: application/json','Authorization: GenieKey '.($cfg['api_key']??'')]);
            case 'matrix':
                $txn=(string)(int)(microtime(true)*1000).mt_rand(100,999);
                $u=rtrim($cfg['homeserver']??'','/')."/_matrix/client/r0/rooms/".rawurlencode($cfg['room_id']??'')."/send/m.room.message/".$txn."?access_token=".rawurlencode($cfg['token']??'');
                return _nf_http($u,'PUT',json_encode(['msgtype'=>'m.text','body'=>$text]),['Content-Type: application/json']);
            case 'twilio_sms': case 'twilio_whatsapp':
                $from=$cfg['from']??''; $to=$cfg['to']??'';
                if($type==='twilio_whatsapp'){ $from='whatsapp:'.$from; $to='whatsapp:'.$to; }
                $u="https://api.twilio.com/2010-04-01/Accounts/".rawurlencode($cfg['sid']??'')."/Messages.json";
                return _nf_http($u,'POST',http_build_query(['From'=>$from,'To'=>$to,'Body'=>mb_substr($text,0,1500)]),
                    ['Content-Type: application/x-www-form-urlencoded'], [$cfg['sid']??'', $cfg['token']??'']);
            case 'n8n':
                $headers=['Content-Type: application/json']; $tok='';
                if($t=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='n8n_inbound_token' LIMIT 1")) $tok=($x=$t->fetch_row())?$x[0]:'';
                if($tok) $headers[]='X-NetMon-Token: '.$tok;
                return _nf_http($cfg['url']??'','POST',json_encode($msg['payload'] ?? _nf_event_payload($msg)),$headers);
            case 'webhook':
                $headers=['Content-Type: application/json'];
                if(($cfg['bearer']??'')!=='') $headers[]='Authorization: Bearer '.$cfg['bearer'];
                return _nf_http($cfg['url']??'','POST',json_encode($msg['payload'] ?? _nf_event_payload($msg)),$headers);
            }
            return ['ok'=>false,'err'=>'unknown channel type: '.$type];
        } catch (\Throwable $e) { return ['ok'=>false,'err'=>$e->getMessage()]; }
    }
    function _nf_event_payload(array $msg): array {
        return ['event'=>'neuru.'.($msg['category']??'event'),'severity'=>$msg['severity']??'info',
                'title'=>$msg['title']??'','text'=>$msg['text']??'','category'=>$msg['category']??null,
                'url'=>$msg['url']??null,'meta'=>$msg['meta']??null];
    }
}

// ── nm_notify_event() — the ONE front door for every non-incident signal ─────
// Any subsystem (predictive health, immunity, service watchdog, capacity, event
// logs, GPU, system…) calls this; it applies maintenance + rate-limit + the
// routing matrix and delivers/queues. Best-effort: never throws to the caller.
if (!function_exists('nm_notify_event')) {
    function nm_notify_build_event_msg(string $cat, string $sev, string $title, string $body, array $meta): array {
        $emoji = ['critical'=>'🔴','warning'=>'🟠','info'=>'🔵'][$sev] ?? '⚪';
        $catLabel = nm_notify_categories()[$cat][0] ?? ucfirst($cat);
        $base = (((!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http').'://'.($_SERVER['HTTP_HOST'] ?? ($meta['host'] ?? 'localhost')));
        $url = $meta['url'] ?? ($base . '/' . ($meta['page'] ?? 'incidents.php'));
        $lines = ["{$emoji} ".strtoupper($sev)." · [{$catLabel}] {$title}"];
        if ($body!=='') $lines[] = $body;
        if (!empty($meta['entity'])) $lines[] = "Entity: ".$meta['entity'];
        $lines[] = $url;
        return ['title'=>$title,'text'=>implode("\n",$lines),'severity'=>$sev,'url'=>$url,'category'=>$cat,'meta'=>$meta];
    }
    function nm_notify_event($conn, string $category, string $severity, string $title, string $body = '', array $meta = []): array {
        try {
            if (!($conn instanceof mysqli)) return ['ok'=>false,'err'=>'no db'];
            nm_notify_ensure($conn);
            $S = nm_notify_settings($conn);
            if (!$S['enabled']) return ['ok'=>true,'skipped'=>'disabled'];
            if (!isset(nm_notify_categories()[$category])) $category = 'system';
            $severity = in_array($severity,['critical','warning','info'],true) ? $severity : 'info';
            // global maintenance gate
            if (nm_notify_maint_active($conn, $meta['node_id'] ?? null, $meta['source'] ?? $category))
                { return ['ok'=>true,'suppressed'=>'maintenance']; }
            $routes = nm_notify_routes_for($conn, $category);
            if (!$routes) return ['ok'=>true,'skipped'=>'no route for '.$category];
            $msg = nm_notify_build_event_msg($category,$severity,$title,$body,$meta);
            $dedup = substr(md5($category.'|'.$title.'|'.($meta['entity'] ?? '')),0,32);
            $sent=0; $queued=0; $suppressed=0;
            foreach ($routes as $rt) {
                if (_nf_sev_rank($severity) < _nf_sev_rank($rt['min_severity'])) continue;
                $full = nm_notify_channel_get($conn, (int)$rt['channel_id']);
                if (!$full || (int)$full['enabled']!==1) continue;
                if (_nf_sev_rank($severity) < _nf_sev_rank($full['min_severity'] ?? 'info')) continue;
                if (_nf_quiet_now($full)) { $rt['mode']='digest'; }         // quiet hours → hold for digest
                if (_nf_rate_limited($conn, (int)$rt['channel_id'], $dedup, (int)($full['rate_limit_sec'] ?? 0))) { $suppressed++; continue; }
                if (($rt['mode'] ?? 'immediate')==='digest') {
                    nm_notify_digest_enqueue($conn,(int)$rt['channel_id'],$category,$severity,$title,$body); $queued++;
                    continue;
                }
                $res = nm_notify_dispatch($conn, $full, $msg);
                _nf_log2($conn, 0, $full, $category, $severity, $res['ok']?'sent':'failed', $res['ok']?null:($res['err']??'?'), $dedup);
                if ($res['ok']) $sent++;
            }
            return ['ok'=>true,'sent'=>$sent,'queued'=>$queued,'suppressed'=>$suppressed];
        } catch (\Throwable $e) { return ['ok'=>false,'err'=>$e->getMessage()]; }
    }
    // event-aware log row (nullable incident, carries category + dedup)
    function _nf_log2($conn, $incId, $ch, $category, $sev, $status, $detail, $dedup){
        try {
            $now=date('Y-m-d H:i:s'); $cid=$ch['id']??null; $cname=$ch['name']??null; $detail=substr((string)$detail,0,390);
            // 9 placeholders: incident_id, channel_id, channel_name, severity, status, detail, sent_at, category, dedup_key
            $st=$conn->prepare("INSERT INTO nm_notify_log (incident_id,channel_id,channel_name,step_order,event,severity,status,detail,sent_at,category,dedup_key) VALUES (?,?,?,0,'event',?,?,?,?,?,?)");
            $st->bind_param('iisssssss', $incId,$cid,$cname,$sev,$status,$detail,$now,$category,$dedup);
            $st->execute(); $st->close();
        } catch (\Throwable $e) { return; }
    }
    function _nf_quiet_now(array $ch): bool {
        $s=trim((string)($ch['quiet_start']??'')); $e=trim((string)($ch['quiet_end']??''));
        if($s===''||$e==='') return false;
        $now=date('H:i');
        if($s<=$e) return ($now>=$s && $now<$e);          // same-day window
        return ($now>=$s || $now<$e);                      // overnight window
    }
    function _nf_rate_limited($conn, int $cid, string $dedup, int $window): bool {
        if($window<=0) return false;
        try {
            $st=$conn->prepare("SELECT 1 FROM nm_notify_log WHERE channel_id=? AND dedup_key=? AND status='sent' AND sent_at >= (NOW() - INTERVAL ? SECOND) LIMIT 1");
            $st->bind_param('isi',$cid,$dedup,$window); $st->execute(); $r=$st->get_result(); $hit=$r&&$r->fetch_row(); $st->close();
            return (bool)$hit;
        } catch (\Throwable $e) { return false; }
    }
}

// ── Digest queue (batches low-severity / quiet-hour events) ──────────────────
if (!function_exists('nm_notify_digest_enqueue')) {
    function nm_notify_digest_enqueue($conn,int $cid,string $cat,string $sev,string $title,string $body): void {
        try { $now=date('Y-m-d H:i:s'); $body=substr($body,0,590); $title=substr($title,0,238);
            $st=$conn->prepare("INSERT INTO nm_notify_digest (channel_id,category,severity,title,body,created_at) VALUES (?,?,?,?,?,?)");
            $st->bind_param('isssss',$cid,$cat,$sev,$title,$body,$now); $st->execute(); $st->close();
        } catch (\Throwable $e) {}
    }
    // Flush every channel's pending digest into one summary message. Called by cron_notify.php.
    function nm_notify_digest_flush($conn): array {
        nm_notify_ensure($conn); $sent=0;
        try {
            $ids=[]; $r=$conn->query("SELECT DISTINCT channel_id FROM nm_notify_digest");
            while($r&&$x=$r->fetch_row()) $ids[]=(int)$x[0];
            foreach($ids as $cid){
                $rows=[]; $q=$conn->query("SELECT category,severity,title,created_at FROM nm_notify_digest WHERE channel_id=$cid ORDER BY id ASC LIMIT 60");
                while($q&&$x=$q->fetch_assoc()) $rows[]=$x;
                if(!$rows) continue;
                $full=nm_notify_channel_get($conn,$cid);
                if($full && (int)$full['enabled']===1 && !_nf_quiet_now($full)){
                    $n=count($rows); $lines=["🗒️ NEURU digest · {$n} event(s)"];
                    foreach($rows as $rw){ $em=['critical'=>'🔴','warning'=>'🟠','info'=>'🔵'][$rw['severity']]??'⚪';
                        $lines[]="{$em} ".substr($rw['created_at'],11,5)." · {$rw['title']}"; }
                    $msg=['title'=>"NEURU digest · {$n} event(s)",'text'=>implode("\n",$lines),'severity'=>'info','category'=>'system'];
                    $res=nm_notify_dispatch($conn,$full,$msg);
                    _nf_log2($conn,0,$full,'system','info',$res['ok']?'sent':'failed',$res['ok']?"digest x{$n}":($res['err']??'?'),'digest');
                    if($res['ok']){ $sent++; $conn->query("DELETE FROM nm_notify_digest WHERE channel_id=$cid"); }
                } else if(!$full || (int)$full['enabled']!==1){
                    $conn->query("DELETE FROM nm_notify_digest WHERE channel_id=$cid"); // orphan cleanup
                }
            }
        } catch (\Throwable $e) {}
        return ['digests_sent'=>$sent];
    }
}

// ── The notification tick — called after correlation each minute ─────────────
if (!function_exists('nm_notify_process')) {
    function nm_notify_process($conn): array {
        nm_notify_ensure($conn);
        $S = nm_notify_settings($conn);
        if (!$S['enabled']) return ['skipped'=>'disabled'];
        $steps = nm_notify_steps($conn);            // legacy/escalation ladder (may be empty)
        $minRank = _nf_sev_rank($S['min_severity']);
        $channels = [];
        foreach (nm_notify_channels($conn, true) as $c) $channels[$c['id']] = $c;

        $sent = 0; $suppressed = 0;
        // 1) ACTIVE incidents → matrix (immediate, per category) + escalation ladder
        $r = $conn->query("SELECT * FROM nm_incidents WHERE status IN ('open','acknowledged')");
        while ($r && $inc = $r->fetch_assoc()) {
            if (_nf_sev_rank($inc['severity']) < $minRank) continue;
            $minutesOpen = (time() - strtotime($inc['opened_at'])) / 60;
            $inMaint = nm_notify_in_maintenance($conn, $inc);
            $category = nm_notify_incident_category($inc);

            // Build the delivery set. after=0 fires immediately (matrix routes for the
            // incident's category + any step-0), later steps re-alert if still unacked.
            $deliveries = [];  // key "cid:after" => ['cid'=>,'after'=>]
            foreach (nm_notify_routes_for($conn, $category) as $rt) {     // matrix = IMMEDIATE for incidents
                if (_nf_sev_rank($inc['severity']) < _nf_sev_rank($rt['min_severity'])) continue;
                $deliveries[$rt['channel_id'].':0'] = ['cid'=>(int)$rt['channel_id'],'after'=>0];
            }
            foreach ($steps as $stp) {                                    // legacy escalation ladder
                $k=(int)$stp['channel_id'].':'.(int)$stp['after_minutes'];
                $deliveries[$k] = ['cid'=>(int)$stp['channel_id'],'after'=>(int)$stp['after_minutes']];
            }

            foreach ($deliveries as $d) {
                $cid = $d['cid']; $after = $d['after']; $stepOrder = $after;
                if ($after > 0 && $inc['status'] === 'acknowledged') continue;
                if ($minutesOpen + 0.01 < $after) continue;
                // already SENT this episode? (only a successful send blocks — a prior
                // 'failed'/'suppressed' row does NOT, so transient failures retry next tick)
                $chk = $conn->query("SELECT 1 FROM nm_notify_log WHERE incident_id=".(int)$inc['id']."
                                     AND channel_id={$cid} AND step_order={$stepOrder} AND status='sent'
                                     AND sent_at >= '".$conn->real_escape_string($inc['opened_at'])."' LIMIT 1");
                if ($chk && $chk->fetch_row()) continue;

                $ch = $channels[$cid] ?? null;
                if (!$ch) continue;
                if (_nf_sev_rank($inc['severity']) < _nf_sev_rank($ch['min_severity'])) continue;

                if ($inMaint) { _nf_log($conn, $inc['id'], $ch, $stepOrder, 'suppressed', $inc['severity'], 'suppressed', 'maintenance window'); $suppressed++; continue; }

                $full = nm_notify_channel_get($conn, $cid);              // full row (config/secret)
                $event = $stepOrder === 0 ? 'open' : 'escalate';
                $res = nm_notify_send($conn, $full, $inc, $event);
                _nf_log($conn, $inc['id'], $ch, $stepOrder, $event, $inc['severity'], $res['ok']?'sent':'failed', $res['ok']?null:($res['err']??'?'));
                if ($res['ok']) $sent++;
            }
        }

        // 2) RESOLVED notice (once) for incidents resolved in the last 3 min that were notified
        if ($S['resolve_notice']) {
            $r = $conn->query("SELECT i.* FROM nm_incidents i
                WHERE i.status='resolved' AND i.resolved_at >= (NOW() - INTERVAL 3 MINUTE)
                  AND EXISTS (SELECT 1 FROM nm_notify_log l WHERE l.incident_id=i.id AND l.event IN ('open','escalate') AND l.status='sent')
                  AND NOT EXISTS (SELECT 1 FROM nm_notify_log l2 WHERE l2.incident_id=i.id AND l2.event='resolved')");
            while ($r && $inc = $r->fetch_assoc()) {
                // notify the distinct channels that were already alerted
                $cr = $conn->query("SELECT DISTINCT channel_id FROM nm_notify_log WHERE incident_id=".(int)$inc['id']." AND event IN ('open','escalate') AND status='sent' AND channel_id IS NOT NULL");
                while ($cr && $cx = $cr->fetch_assoc()) {
                    $full = nm_notify_channel_get($conn, (int)$cx['channel_id']);
                    if (!$full) continue;
                    $res = nm_notify_send($conn, $full, $inc, 'resolved');
                    _nf_log($conn, $inc['id'], ['id'=>$full['id'],'name'=>$full['name']], 0, 'resolved', $inc['severity'], $res['ok']?'sent':'failed', $res['ok']?null:($res['err']??'?'));
                    if ($res['ok']) $sent++;
                }
            }
        }
        return ['sent'=>$sent, 'suppressed'=>$suppressed];
    }

    function nm_notify_log_recent($conn, int $limit = 80): array {
        nm_notify_ensure($conn);
        $out = [];
        $r = $conn->query("SELECT * FROM nm_notify_log ORDER BY id DESC LIMIT $limit");
        while ($r && $x = $r->fetch_assoc()) $out[] = $x;
        return $out;
    }
}
