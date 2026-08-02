<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Zero-Day Deception Grid engine (F2 · Phase 1: safe manual core).
//
// A new RESPONSE MODE, not a parallel security module: instead of instantly banning
// an attacker IP (who then rotates), silently DIVERT that one source IP into a decoy
// honeypot via dynamic MikroTik dst-nat, so you can watch its techniques, then promote
// to a fleet-wide block through Collective Immunity — and auto-revert.
//
//   detect (Immunity, exists) → dst-nat divert (MikroTik via SSH) → observe (P2)
//   → promote to fleet block (Immunity, exists) → revert.
//
// SAFETY (mirrors Self-Healing): OFF by default · strict single-src scoping · mandatory
// TTL + auto-revert · never-divert allowlist · full audit · the PORTAL renders + applies
// vetted commands (the LLM never touches the router). Phase 1 = MANUAL divert/revert only.
//
// Reuses: nm_portainer_container_create (honeypot deploy), nm_cm_ssh_fetch + nm_ssh_resolve
// (MikroTik NAT over SSH), nm_imm_add_threat/vaccinate (fleet block), nm_audit, nm_notify.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_decoy_ensure')) {

    require_once __DIR__ . '/nm_secrets.php';
    require_once __DIR__ . '/nm_confmgr.php';     // nm_cm_ssh_fetch
    require_once __DIR__ . '/nm_portainer.php';   // nm_portainer_container_create
    require_once __DIR__ . '/nm_audit.php';

    define('NM_DECOY_TAG', 'NEURU-DECOY');        // MikroTik NAT comment prefix (removal key)

    function nm_decoy_ensure($conn): void {
        $conn->query("CREATE TABLE IF NOT EXISTS nm_decoy_pots (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(80) NOT NULL,
            service_kind VARCHAR(16) DEFAULT 'generic',    /* ssh | http | db | generic */
            image VARCHAR(160) NOT NULL,
            container_port INT DEFAULT 2222,               /* port the honeypot listens on INSIDE the container */
            listen_port INT DEFAULT 2222,                  /* published port on the Docker host → dst-nat target */
            portainer_endpoint_id INT DEFAULT 0,
            host_ip VARCHAR(45) DEFAULT '',
            container_id VARCHAR(80) DEFAULT '',
            container_name VARCHAR(120) DEFAULT '',
            status VARCHAR(12) DEFAULT 'draft',            /* draft | deployed | error */
            last_deploy DATETIME NULL,
            last_error VARCHAR(400) DEFAULT '',
            created_by INT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $conn->query("CREATE TABLE IF NOT EXISTS nm_decoy_diversions (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            src_ip VARCHAR(45) NOT NULL,
            target_port INT DEFAULT 0,                     /* service port the attacker was hitting (0 = any) */
            protocol VARCHAR(6) DEFAULT 'tcp',
            pot_id INT NOT NULL,
            border_node_id INT NOT NULL,
            nat_comment VARCHAR(64) DEFAULT '',
            threat_id INT DEFAULT 0,                       /* set once promoted to Immunity */
            status VARCHAR(12) DEFAULT 'active',           /* active | reverted | promoted | failed */
            source VARCHAR(16) DEFAULT 'manual',           /* manual | auto (P2) */
            detail VARCHAR(500) DEFAULT '',
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NULL,
            reverted_at DATETIME NULL,
            created_by INT NULL,
            INDEX(status), INDEX(src_ip), INDEX(expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $conn->query("CREATE TABLE IF NOT EXISTS nm_decoy_events (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            diversion_id BIGINT NOT NULL,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP,
            kind VARCHAR(16) DEFAULT 'hit',                /* login | cmd | http | scan | payload | hit */
            src_ip VARCHAR(45) DEFAULT '',
            data MEDIUMTEXT NULL,
            INDEX(diversion_id), INDEX(ts)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // seed safe defaults (all OFF) if missing
        foreach ([
            'deception_enabled'            => '0',
            'deception_border_node_id'     => '0',
            'deception_ttl_min'            => '30',
            'deception_never_divert'       => '',      // CSV of IPs / prefixes never to touch
            'deception_allow_internal'     => '0',      // divert RFC1918 sources? (default no)
            'deception_auto'               => '0',      // P2: auto-divert from Immunity detections
            'deception_classes'            => 'portscan,bruteforce',
            'deception_promote_min_events' => '8',
            'deception_openai'             => '0',
        ] as $k => $v) {
            $conn->query("INSERT IGNORE INTO nm_settings (setting_key,setting_val) VALUES ('".$conn->real_escape_string($k)."','".$conn->real_escape_string($v)."')");
        }
        $conn->query("INSERT IGNORE INTO role_profiles (role_name, button_key, enabled) VALUES ('admin','deception',1)");

        // AI verdict cache on a diversion (from the 'deception-analyst' n8n flow). Guarded ALTERs.
        foreach (['ai_verdict'=>"VARCHAR(16) DEFAULT ''", 'ai_score'=>'INT DEFAULT 0', 'ai_summary'=>"VARCHAR(600) DEFAULT ''", 'ai_at'=>'DATETIME NULL'] as $col=>$def) {
            $c = $conn->query("SELECT COUNT(*) c FROM INFORMATION_SCHEMA.COLUMNS
                               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_decoy_diversions' AND COLUMN_NAME='".$conn->real_escape_string($col)."'");
            if ($c && (int)$c->fetch_assoc()['c'] === 0) $conn->query("ALTER TABLE nm_decoy_diversions ADD COLUMN {$col} {$def}");
        }
        // Auto-register the outbound 'deception-analyst' webhook (disabled, empty URL) so it shows
        // up pre-listed in Config → Integrations with a self-explaining description. INSERT IGNORE =
        // never overwrites the operator's URL/enabled once they configure it. (webhook_save upserts
        // by slug, so editing/re-adding this row always works — never a "slug already exists" fail.)
        if ($conn->query("SHOW TABLES LIKE 'nm_n8n_webhooks'")->num_rows) {
            $conn->query("INSERT IGNORE INTO nm_n8n_webhooks (name,slug,url,method,description,enabled)
                          VALUES ('Deception Analyst','deception-analyst','','POST',
                          'Auto-added by NEURU (Deception Grid). To activate: paste your n8n URL http://<n8n>:5678/webhook/deception-analyst and tick Enabled. It analyses a diverted attacker and returns {threat_score,verdict,summary}. See docs/N8N_DECEPTION.md.',0)");
        }
    }

    // ── AI analysis: send a diversion + attacker context to the n8n 'deception-analyst' flow and
    //    cache its verdict. Reuses the nm_n8n trust model (token added outbound). ─────────────────
    function nm_decoy_analyze($conn, int $did): array {
        nm_decoy_ensure($conn);
        if (!function_exists('nm_n8n_call') && is_file(__DIR__.'/nm_n8n.php')) require_once __DIR__.'/nm_n8n.php';
        if (!function_exists('nm_n8n_call')) return ['ok'=>false,'error'=>'n8n integration unavailable'];
        $d = nm_decoy_diversions($conn, 200);
        $row = null; foreach ($d as $x) if ((int)$x['id'] === $did) { $row = $x; break; }
        if (!$row) return ['ok'=>false,'error'=>'diversion not found'];
        $src = (string)$row['src_ip']; $S = nm_decoy_settings($conn);

        // captured honeypot events
        $events = [];
        $er = $conn->query("SELECT ts,kind,LEFT(data,600) data FROM nm_decoy_events WHERE diversion_id=".(int)$did." ORDER BY id DESC LIMIT 40");
        while ($er && $e = $er->fetch_assoc()) $events[] = $e;

        // what the IP was doing (NetFlow, last 30m) — indexed
        $netflow = [];
        if ($conn->query("SHOW TABLES LIKE 'nm_netflow_flows'")->num_rows) {
            if (!function_exists('nm_nf_app_name') && is_file(__DIR__.'/nm_netflow.php')) require_once __DIR__.'/nm_netflow.php';
            $nf = $conn->prepare("SELECT app_port,protocol,SUM(bytes) b,SUM(flows) f FROM nm_netflow_flows
                                  WHERE bucket >= (NOW()-INTERVAL 30 MINUTE) AND (src_ip=? OR dst_ip=?)
                                  GROUP BY app_port,protocol ORDER BY b DESC LIMIT 10");
            if ($nf) { $nf->bind_param('ss',$src,$src); $nf->execute(); $rs=$nf->get_result();
                while ($rs && $r=$rs->fetch_assoc()) $netflow[] = [
                    'app'=>function_exists('nm_nf_app_name')?nm_nf_app_name((int)$r['app_port'],(int)$r['protocol']):('port '.(int)$r['app_port']),
                    'bytes'=>(int)$r['b'],'flows'=>(int)$r['f']]; $nf->close(); }
        }

        // recent syslog mentioning the IP (bounded so the big table stays fast)
        $syslog = [];
        $sl = $conn->prepare("SELECT received_at,severity,tag,LEFT(message,240) message FROM nm_syslog
                              WHERE received_at >= (NOW()-INTERVAL 3 HOUR) AND message LIKE ? ORDER BY id DESC LIMIT 15");
        if ($sl) { $like = '%'.$src.'%'; $sl->bind_param('s',$like); $sl->execute(); $rs=$sl->get_result();
            while ($rs && $r=$rs->fetch_assoc()) $syslog[] = $r; $sl->close(); }

        $payload = [
            'event' => 'deception.analyze',
            'diversion' => ['id'=>$did,'src_ip'=>$src,'target_port'=>(int)$row['target_port'],'protocol'=>$row['protocol'],
                            'pot_name'=>$row['pot_name'],'status'=>$row['status'],'started_at'=>$row['started_at'],'ttl_min'=>$S['ttl_min']],
            'attacker' => ['ip'=>$src,'is_private'=>!filter_var($src,FILTER_VALIDATE_IP,FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE)],
            'events' => $events, 'netflow' => $netflow, 'syslog' => $syslog,
            'context' => ['portal'=>'NEURU','promote_min_events'=>$S['promote_min_events']],
        ];
        [$code, $data, $err] = nm_n8n_call($conn, 'deception-analyst', $payload, 45);
        if ($err) return ['ok'=>false,'error'=>$err.' (register + enable the deception-analyst webhook in Config → Integrations)'];
        // Some n8n setups return the verdict as a JSON *string* (content-type text/plain) — decode defensively.
        if (is_string($data) && trim($data) !== '') { $tmp = json_decode($data, true); if (is_array($tmp)) $data = $tmp; }
        if (!is_array($data) || !$data) {
            // Reachable but produced nothing → the flow ran without returning the verdict (empty body).
            $msg = ($code >= 200 && $code < 300)
                ? 'The Deception Analyst flow responded ('.$code.') but returned no verdict. Re-import & ENABLE the latest "Deception Analyst" flow (NEURU Portal → n8n Flows) and make sure its final "Respond to Webhook" node returns the AI JSON (and the LLM/AI node isn\'t erroring).'
                : 'The Deception Analyst flow returned HTTP '.(int)$code.' — check it is imported & ACTIVE in your n8n.';
            return ['ok'=>false,'error'=>$msg,'http'=>(int)$code];
        }

        $verdict = substr((string)($data['verdict'] ?? ''), 0, 16);
        $score   = (int)($data['threat_score'] ?? $data['score'] ?? 0);
        $summary = substr((string)($data['summary'] ?? ''), 0, 590);
        $st = $conn->prepare("UPDATE nm_decoy_diversions SET ai_verdict=?, ai_score=?, ai_summary=?, ai_at=NOW() WHERE id=?");
        $st->bind_param('sisi', $verdict, $score, $summary, $did); $st->execute(); $st->close();
        if (function_exists('nm_audit')) nm_audit($conn,'deception.analyze',['details'=>['id'=>$did,'verdict'=>$verdict,'score'=>$score]]);
        return ['ok'=>true,'analysis'=>$data];
    }

    // ── settings ────────────────────────────────────────────────────────────────
    function nm_decoy_setting($conn, string $k, string $def): string {
        $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1");
        if ($r && $r->num_rows) { $v = $r->fetch_assoc()['setting_val']; if ($v !== null && $v !== '') return (string)$v; }
        return $def;
    }
    function nm_decoy_settings($conn): array {
        nm_decoy_ensure($conn);
        return [
            'enabled'            => nm_decoy_setting($conn,'deception_enabled','0')==='1',
            'border_node_id'     => (int)nm_decoy_setting($conn,'deception_border_node_id','0'),
            'ttl_min'            => max(2, (int)nm_decoy_setting($conn,'deception_ttl_min','30')),
            'never_divert'       => array_values(array_filter(array_map('trim', explode(',', nm_decoy_setting($conn,'deception_never_divert',''))))),
            'allow_internal'     => nm_decoy_setting($conn,'deception_allow_internal','0')==='1',
            'auto'               => nm_decoy_setting($conn,'deception_auto','0')==='1',
            'classes'            => array_values(array_filter(array_map('trim', explode(',', nm_decoy_setting($conn,'deception_classes','portscan,bruteforce'))))),
            'promote_min_events' => max(1, (int)nm_decoy_setting($conn,'deception_promote_min_events','8')),
            'openai'             => nm_decoy_setting($conn,'deception_openai','0')==='1',
        ];
    }
    function nm_decoy_set($conn, string $key, string $val): bool {
        $allow = ['deception_enabled','deception_border_node_id','deception_ttl_min','deception_never_divert',
                  'deception_allow_internal','deception_auto','deception_classes','deception_promote_min_events','deception_openai'];
        if (!in_array($key, $allow, true)) return false;
        $st = $conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES (?,?)
                              ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
        $st->bind_param('ss', $key, $val); $ok = $st->execute(); $st->close();
        return $ok;
    }

    // ── honeypot inventory ────────────────────────────────────────────────────────
    // Curated low-interaction images (never a clone of the real DB — that would risk real data).
    // Only TURNKEY images that run with no config file (so they don't crash-loop). OpenCanary was
    // dropped — it needs a mounted opencanary.conf or it exits 1 and restarts forever.
    function nm_decoy_catalog(): array {
        return [
            ['kind'=>'ssh',     'label'=>'SSH/Telnet honeypot (Cowrie) — turnkey', 'image'=>'cowrie/cowrie:latest',   'cport'=>2222, 'lport'=>2222],
            ['kind'=>'http',    'label'=>'HTTP decoy (whoami) — turnkey',          'image'=>'traefik/whoami:latest',  'cport'=>80,   'lport'=>8080],
            ['kind'=>'generic', 'label'=>'Telnet honeypot (Cowrie telnet) — turnkey','image'=>'cowrie/cowrie:latest', 'cport'=>2223, 'lport'=>2323],
        ];
    }
    function nm_decoy_pots($conn): array {
        nm_decoy_ensure($conn);
        $out = []; $r = $conn->query("SELECT * FROM nm_decoy_pots ORDER BY id DESC");
        while ($r && $x = $r->fetch_assoc()) $out[] = $x;
        return $out;
    }
    // Live container health from Portainer (so a crash-looping honeypot doesn't masquerade as
    // "deployed"). Returns pot_id => ['state'=>running|restarting|exited|…, 'status'=>text]. One
    // Portainer list call per distinct endpoint; best-effort (empty on any error/timeout).
    function nm_decoy_pots_live($conn, array $pots): array {
        $live = [];
        $cfg = nm_portainer_cfg($conn);
        if (!nm_portainer_configured($cfg)) return $live;
        $byEp = [];
        foreach ($pots as $p) { if (($p['status']??'')==='deployed' && (int)$p['portainer_endpoint_id']>0) $byEp[(int)$p['portainer_endpoint_id']][] = $p; }
        foreach ($byEp as $eid => $group) {
            $r = nm_portainer_containers($cfg, (int)$eid, true, 8);
            if (empty($r['ok']) || !is_array($r['data'])) continue;
            $byName = [];
            foreach ($r['data'] as $c) {
                foreach (($c['Names'] ?? []) as $n) $byName[ltrim($n,'/')] = $c;
                if (!empty($c['Id'])) $byName[substr($c['Id'],0,12)] = $c;
            }
            foreach ($group as $p) {
                $c = $byName[$p['container_name']] ?? ($byName[substr((string)$p['container_id'],0,12)] ?? null);
                if ($c) $live[(int)$p['id']] = ['state'=>(string)($c['State'] ?? '?'), 'status'=>(string)($c['Status'] ?? '')];
            }
        }
        return $live;
    }
    function nm_decoy_pot_get($conn, int $id): ?array {
        $r = $conn->query("SELECT * FROM nm_decoy_pots WHERE id=".(int)$id." LIMIT 1");
        return $r && $r->num_rows ? $r->fetch_assoc() : null;
    }
    function nm_decoy_pot_save($conn, array $d, ?int $uid): array {
        nm_decoy_ensure($conn);
        $name = trim((string)($d['name'] ?? '')); $image = trim((string)($d['image'] ?? ''));
        if ($name === '' || $image === '') return ['ok'=>false,'error'=>'name and image are required'];
        $kind = in_array($d['service_kind'] ?? '', ['ssh','http','db','generic'], true) ? $d['service_kind'] : 'generic';
        $cport = max(1, (int)($d['container_port'] ?? 2222));
        $lport = max(1, (int)($d['listen_port'] ?? $cport));
        $eid   = (int)($d['portainer_endpoint_id'] ?? 0);
        $id    = (int)($d['id'] ?? 0);
        if ($id > 0) {
            $st = $conn->prepare("UPDATE nm_decoy_pots SET name=?,service_kind=?,image=?,container_port=?,listen_port=?,portainer_endpoint_id=? WHERE id=?");
            $st->bind_param('sssiiii', $name,$kind,$image,$cport,$lport,$eid,$id);
        } else {
            $st = $conn->prepare("INSERT INTO nm_decoy_pots (name,service_kind,image,container_port,listen_port,portainer_endpoint_id,created_by)
                                  VALUES (?,?,?,?,?,?,?)");
            $st->bind_param('sssiiii', $name,$kind,$image,$cport,$lport,$eid,$uid);
        }
        $ok = $st->execute(); $newId = $id ?: (int)$st->insert_id; $st->close();
        if ($ok && function_exists('nm_audit')) nm_audit($conn,'deception.pot.save',['details'=>['id'=>$newId,'name'=>$name,'image'=>$image]]);
        return ['ok'=>$ok,'id'=>$newId];
    }
    function nm_decoy_pot_remove($conn, int $id): array {
        // best-effort: STOP the container first so a crash-looping honeypot doesn't keep restarting
        // after we drop the record (unless-stopped won't resurrect a manually stopped container).
        $pot = nm_decoy_pot_get($conn, $id);
        if ($pot && ($pot['container_id'] ?? '') !== '' && (int)$pot['portainer_endpoint_id'] > 0) {
            $cfg = nm_portainer_cfg($conn);
            if (nm_portainer_configured($cfg)) @nm_portainer_container_action($cfg, (int)$pot['portainer_endpoint_id'], (string)$pot['container_id'], 'stop');
        }
        $conn->query("DELETE FROM nm_decoy_pots WHERE id=".(int)$id);
        if (function_exists('nm_audit')) nm_audit($conn,'deception.pot.remove',['details'=>['id'=>$id]]);
        return ['ok'=>true];
    }
    // Deploy the honeypot container via Portainer, then record its host ip:published port.
    function nm_decoy_pot_deploy($conn, int $id, ?int $uid): array {
        $pot = nm_decoy_pot_get($conn, $id);
        if (!$pot) return ['ok'=>false,'error'=>'pot not found'];
        $cfg = nm_portainer_cfg($conn);
        if (!nm_portainer_configured($cfg)) return ['ok'=>false,'error'=>'Portainer is not configured (Config → Integrations)'];
        $eid = (int)$pot['portainer_endpoint_id'];
        if ($eid <= 0) return ['ok'=>false,'error'=>'pick a Portainer host (endpoint) for this honeypot'];

        $cname = 'neuru-decoy-'.$id;
        $spec = [
            'image'   => $pot['image'],
            'name'    => $cname,
            'ports'   => [ (int)$pot['container_port'] => (int)$pot['listen_port'] ],  // cport => hport
            'restart' => 'unless-stopped',
        ];
        $r = nm_portainer_container_create($cfg, $eid, $spec);
        if (empty($r['ok'])) {
            $err = substr((string)($r['error'] ?? 'deploy failed'), 0, 390);
            $conn->query("UPDATE nm_decoy_pots SET status='error', last_error='".$conn->real_escape_string($err)."', last_deploy=NOW() WHERE id=".(int)$id);
            return ['ok'=>false,'error'=>$err];
        }
        $cid = (string)($r['data']['Id'] ?? '');
        $hostIp = nm_portainer_host_ip($cfg, $eid);
        $st = $conn->prepare("UPDATE nm_decoy_pots SET status='deployed', container_id=?, container_name=?, host_ip=?, last_error='', last_deploy=NOW() WHERE id=?");
        $st->bind_param('sssi', $cid, $cname, $hostIp, $id); $st->execute(); $st->close();
        if (function_exists('nm_audit')) nm_audit($conn,'deception.pot.deploy',['details'=>['id'=>$id,'host_ip'=>$hostIp,'port'=>$pot['listen_port']]]);
        return ['ok'=>true,'host_ip'=>$hostIp,'listen_port'=>(int)$pot['listen_port'],'container_id'=>$cid];
    }

    // ── Vendor-universal firewall renderers (pure string builders, unit-testable) ──────────────────
    // A working divert needs BOTH, and ORDER matters:
    //   1) dst-nat the attacker's flow → honeypot, placed FIRST in the NAT chain so it wins over any
    //      existing NAT that would otherwise grab the traffic;
    //   2) an ALLOW filter rule for the diverted flow, placed FIRST in the filter chain so it is
    //      permitted ahead of any drop rule, WITH logging so the Watch theater has events.
    // Both are tagged with the diversion comment so revert removes exactly them. Everything is
    // per-vendor so this works beyond MikroTik (Cisco ASA now; TP-Link/TrendNet/etc. are pluggable).

    // Which firewall dialect does the border node speak? (os_icon / vendor / name heuristics)
    function nm_decoy_vendor_of($conn, int $borderNodeId): string {
        $r = $conn->query("SELECT display_name, COALESCE(os_icon,'') os_icon FROM nm_nodes WHERE id=".(int)$borderNodeId." LIMIT 1");
        $n = ($r && $r->num_rows) ? $r->fetch_assoc() : null;
        $hay = strtolower(($n['os_icon'] ?? '').' '.($n['display_name'] ?? ''));
        if (strpos($hay,'mikrotik')!==false || strpos($hay,'routeros')!==false) return 'mikrotik';
        if (strpos($hay,'asa')!==false || strpos($hay,'firepower')!==false)    return 'cisco_asa';
        if (strpos($hay,'tp-link')!==false || strpos($hay,'tplink')!==false)   return 'tplink';
        if (strpos($hay,'trendnet')!==false)                                   return 'trendnet';
        if (strpos($hay,'cisco')!==false || strpos($hay,' ios')!==false)       return 'cisco_ios';
        return 'generic';
    }

    // Build DIVERT command(s). $d: src_ip, pot_ip, pot_port, protocol, comment, target_port.
    // Returns ['ok'=>bool, 'cmd'=>string, 'error'=>?string]. A single SSH exec runs the whole thing.
    function nm_decoy_render_divert(string $vendor, array $d): array {
        $atk=$d['src_ip']; $pot=$d['pot_ip']; $pport=(int)$d['pot_port'];
        $proto=($d['protocol'] ?? 'tcp')==='udp'?'udp':'tcp'; $cmt=$d['comment']; $dport=(int)($d['target_port'] ?? 0);
        switch ($vendor) {
            case 'mikrotik': {
                $dp = $dport>0 ? " dst-port={$dport}" : '';
                $nat = "/ip firewall nat add chain=dstnat action=dst-nat protocol={$proto} src-address={$atk}{$dp}"
                     . " to-addresses={$pot} to-ports={$pport} comment=\"{$cmt}\" place-before=0";
                // forward ACCEPT (post-NAT dst is the honeypot) placed FIRST, with logging for Watch.
                $flt = "/ip firewall filter add chain=forward action=accept protocol={$proto} src-address={$atk}"
                     . " dst-address={$pot} dst-port={$pport} comment=\"{$cmt}\" log=yes log-prefix=\"{$cmt}\" place-before=0";
                return ['ok'=>true,'cmd'=>"{$nat} ; {$flt} ; :put \"NM_DECOY_OK\""];
            }
            case 'cisco_asa': {
                // ASA: object-based twice-NAT (attacker→honeypot) + an ACL permit at LINE 1 (first) + log.
                // Objects tagged with the comment id so removal is exact. WAN iface assumed 'outside'.
                $tag = preg_replace('/[^A-Za-z0-9_]/','_',$cmt);
                $l = [
                    "object network {$tag}_pot", " host {$pot}", "exit",
                    "object service {$tag}_svc", " service {$proto} destination eq {$pport}", "exit",
                    "nat (outside,any) 1 source static any any destination static any {$tag}_pot service {$tag}_svc {$tag}_svc",
                    "access-list outside_access_in line 1 extended permit {$proto} host {$atk} host {$pot} eq {$pport} log",
                ];
                return ['ok'=>true,'cmd'=>implode("\n",$l)];
            }
            default:
                return ['ok'=>false,'error'=>"Deception divert isn't wired for '{$vendor}' routers yet — supported: MikroTik (full) and Cisco ASA. TP-Link / TrendNet / others are pluggable next. Pick a supported border router in Settings."];
        }
    }
    // Build REVERT command(s) — remove exactly what divert added (by comment/tag).
    function nm_decoy_render_revert(string $vendor, string $comment, array $d = []): array {
        switch ($vendor) {
            case 'mikrotik':
                return ['ok'=>true,'cmd'=>"/ip firewall nat remove [find comment=\"{$comment}\"] ; /ip firewall filter remove [find comment=\"{$comment}\"] ; :put \"NM_DECOY_OK\""];
            case 'cisco_asa': {
                $tag=preg_replace('/[^A-Za-z0-9_]/','_',$comment);
                $atk=$d['src_ip']??''; $pot=$d['pot_ip']??''; $pport=(int)($d['pot_port']??0); $proto=($d['protocol']??'tcp')==='udp'?'udp':'tcp';
                $l=[];
                if($atk&&$pot) $l[]="no access-list outside_access_in extended permit {$proto} host {$atk} host {$pot} eq {$pport} log";
                $l[]="no nat (outside,any) 1 source static any any destination static any {$tag}_pot service {$tag}_svc {$tag}_svc";
                $l[]="no object service {$tag}_svc"; $l[]="no object network {$tag}_pot";
                return ['ok'=>true,'cmd'=>implode("\n",$l)];
            }
            default: return ['ok'=>false,'error'=>"revert not implemented for '{$vendor}'"];
        }
    }
    // Command whose output is the router's firewall log for this diversion (for the Watch theater),
    // or null if that vendor's log can't be read. Parsed by nm_decoy_parse_border_log().
    function nm_decoy_render_logread(string $vendor, string $comment): ?string {
        switch ($vendor) {
            case 'mikrotik': return "/log print where message~\"{$comment}\" ; :put \"NM_DECOY_OK\"";
            default: return null;
        }
    }

    // Apply a RouterOS command on the configured border node over SSH. Returns ['ok'=>,'out'|'error'].
    function nm_decoy_apply_border($conn, int $borderNodeId, string $cmd, int $timeout = 20): array {
        $ssh = nm_ssh_resolve($conn, $borderNodeId);
        if (!$ssh) return ['ok'=>false,'error'=>'no SSH credential resolves for the border node'];
        $r = nm_cm_ssh_fetch($ssh, $cmd, $timeout);
        if (empty($r['ok'])) return ['ok'=>false,'error'=>$r['error'] ?? 'ssh failed'];
        // strip the interactive shell's terminal escapes; the echoed command also contains the literal
        // ':put "NM_DECOY_OK"', so real success = a BARE "NM_DECOY_OK" line (the :put OUTPUT), not a substring.
        $out = preg_replace('/\x1b\[[0-9;?]*[A-Za-z]/', '', (string)($r['config'] ?? ''));
        if (preg_match('/^NM_DECOY_OK\s*$/m', $out)) return ['ok'=>true,'out'=>trim($out)];   // MikroTik sentinel
        // vendor error markers: RouterOS (failure/syntax/no such) + Cisco/ASA (ERROR:/%/invalid input)
        if (preg_match('/failure:|syntax error|expected |bad command|no such|(^|\n)\s*ERROR:|(^|\n)%|invalid input/i', $out))
            return ['ok'=>false,'error'=>trim($out)];
        return ['ok'=>true,'out'=>trim($out)];   // no explicit error (e.g. Cisco ASA, no sentinel) → assume ok
    }

    // ── Cross-module coordination: what is this IP's CURRENT disposition? ──────────
    // One source IP should have ONE disposition at a time. This reads (SQL-only, no cross-module
    // code deps) the three ledgers where an IP can be "acted on": diverted here, blocked by
    // Collective Immunity (nm_threats), or blocked by Self-Healing (nm_heal_events). Used to stop an
    // operator from diverting an IP another operator already blocked (and vice-versa via the sweep).
    // Identity of the configured border router (the ONLY device where NAT is applied).
    function nm_decoy_border_identity($conn): array {
        $bid = (int)nm_decoy_setting($conn,'deception_border_node_id','0');
        if ($bid <= 0) return ['id'=>0,'name'=>'','ip'=>''];
        $r = $conn->query("SELECT id,display_name,ip_address FROM nm_nodes WHERE id=$bid LIMIT 1");
        $n = ($r && $r->num_rows) ? $r->fetch_assoc() : null;
        return $n ? ['id'=>(int)$n['id'],'name'=>(string)$n['display_name'],'ip'=>(string)$n['ip_address']] : ['id'=>0,'name'=>'','ip'=>''];
    }
    // Does a threat's "reported_by" (e.g. "SG-MIKROTIK (192.168.10.1)") name the border router?
    // This is how we know the attacker's traffic actually transits the router we manage — a divert
    // (dst-nat) only intercepts traffic that passes through THAT router.
    function nm_decoy_reported_on_border(string $reportedBy, array $border): bool {
        if ($reportedBy === '') return false;
        if ($border['name'] !== '' && stripos($reportedBy, $border['name']) !== false) return true;
        if ($border['ip']   !== '' && strpos($reportedBy, $border['ip'])    !== false) return true;
        return false;
    }

    function nm_decoy_source_disposition($conn, string $ip): array {
        $out = ['diverted'=>null, 'blocked'=>null, 'clear'=>true, 'seen_on'=>'', 'on_border'=>null];
        $ipE = $conn->real_escape_string($ip);
        // where was this IP's malicious activity observed? (latest threat's reporting device)
        $sr = $conn->query("SELECT reported_by FROM nm_threats WHERE indicator='$ipE' AND ind_type='ip' AND reported_by<>'' ORDER BY id DESC LIMIT 1");
        if ($sr && $sr->num_rows) {
            $out['seen_on'] = (string)$sr->fetch_assoc()['reported_by'];
            $out['on_border'] = nm_decoy_reported_on_border($out['seen_on'], nm_decoy_border_identity($conn));
        }
        // diverted (this module)
        $r = $conn->query("SELECT id FROM nm_decoy_diversions WHERE src_ip='$ipE' AND status='active' ORDER BY id DESC LIMIT 1");
        if ($r && $r->num_rows) { $out['diverted'] = (int)$r->fetch_assoc()['id']; $out['clear'] = false; }
        // blocked by Immunity (nm_threats active)
        if ($conn->query("SHOW TABLES LIKE 'nm_threats'")->num_rows) {
            $r = $conn->query("SELECT id FROM nm_threats WHERE indicator='$ipE' AND ind_type='ip' AND status='active' LIMIT 1");
            if ($r && $r->num_rows) { $out['blocked'] = ['by'=>'immunity','id'=>(int)$r->fetch_assoc()['id']]; $out['clear'] = false; }
        }
        // blocked by Self-Healing (active block_ip event)
        if (!$out['blocked'] && $conn->query("SHOW TABLES LIKE 'nm_heal_events'")->num_rows) {
            $r = $conn->query("SELECT id FROM nm_heal_events WHERE indicator='$ipE' AND action='block_ip' AND status='active' LIMIT 1");
            if ($r && $r->num_rows) { $out['blocked'] = ['by'=>'heal','id'=>(int)$r->fetch_assoc()['id']]; $out['clear'] = false; }
        }
        return $out;
    }

    // ── the core: divert one attacker IP into a honeypot (MANUAL, Phase 1) ─────────
    function nm_decoy_divert($conn, array $o, ?int $uid, string $source = 'manual'): array {
        nm_decoy_ensure($conn);
        $S = nm_decoy_settings($conn);
        $src   = trim((string)($o['src_ip'] ?? ''));
        $potId = (int)($o['pot_id'] ?? 0);
        $dport = (int)($o['target_port'] ?? 0);
        $proto = ($o['protocol'] ?? 'tcp') === 'udp' ? 'udp' : 'tcp';

        // ── guards ──────────────────────────────────────────────────────────────
        if (!$S['enabled']) return ['ok'=>false,'error'=>'Deception is OFF (enable it in Settings first).'];
        if (!filter_var($src, FILTER_VALIDATE_IP)) return ['ok'=>false,'error'=>'invalid source IP'];
        if (in_array($src, $S['never_divert'], true)) return ['ok'=>false,'error'=>'that IP is on the never-divert allowlist'];
        foreach ($S['never_divert'] as $nd) { if ($nd !== '' && strpos($nd,'/')!==false && nm_decoy_ip_in_cidr($src,$nd)) return ['ok'=>false,'error'=>"source is within never-divert range {$nd}"]; }
        $isPrivate = !filter_var($src, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
        if ($isPrivate && !$S['allow_internal']) return ['ok'=>false,'error'=>'source is internal/private — enable "allow internal" only if you really mean to divert an inside host'];
        // ── cross-module coordination (checked early so the reason is clear) ──────────────────
        $disp = nm_decoy_source_disposition($conn, $src);
        if ($disp['diverted']) return ['ok'=>false,'error'=>'this IP is already being diverted (id '.$disp['diverted'].')'];
        if ($disp['blocked']) {
            $by = $disp['blocked']['by']==='immunity' ? 'Collective Immunity' : 'Self-Healing';
            return ['ok'=>false,'error'=>"this IP is already BLOCKED by {$by} — a block already stops it, so diverting would be ignored. Remove that block first if you want to deceive instead."];
        }
        $border = $S['border_node_id'];
        if ($border <= 0) return ['ok'=>false,'error'=>'set a border MikroTik in Settings first'];
        $pot = nm_decoy_pot_get($conn, $potId);
        if (!$pot) return ['ok'=>false,'error'=>'pick a honeypot'];
        if ($pot['status'] !== 'deployed' || $pot['host_ip']==='') return ['ok'=>false,'error'=>'that honeypot is not deployed yet'];

        // ── ledger row first (so the NAT comment can carry its id) ────────────────
        $st = $conn->prepare("INSERT INTO nm_decoy_diversions (src_ip,target_port,protocol,pot_id,border_node_id,status,source,created_by)
                              VALUES (?,?,?,?,?,'active',?,?)");
        $st->bind_param('siiiisi', $src,$dport,$proto,$potId,$border,$source,$uid); $st->execute();
        $did = (int)$st->insert_id; $st->close();
        $comment = NM_DECOY_TAG.'-'.$did;
        $ttlSql = "DATE_ADD(NOW(), INTERVAL ".(int)$S['ttl_min']." MINUTE)";
        $conn->query("UPDATE nm_decoy_diversions SET nat_comment='".$conn->real_escape_string($comment)."', expires_at=$ttlSql WHERE id=$did");

        // ── apply the divert (dst-nat FIRST + allow-filter FIRST + logging) on the border router ────
        $vendor = nm_decoy_vendor_of($conn, $border);
        $rd = nm_decoy_render_divert($vendor, [
            'src_ip'=>$src, 'pot_ip'=>$pot['host_ip'], 'pot_port'=>(int)$pot['listen_port'],
            'protocol'=>$proto, 'comment'=>$comment, 'target_port'=>$dport,
        ]);
        if (empty($rd['ok'])) {
            $conn->query("UPDATE nm_decoy_diversions SET status='failed', detail='".$conn->real_escape_string(substr((string)$rd['error'],0,480))."' WHERE id=$did");
            return ['ok'=>false,'error'=>$rd['error'],'diversion_id'=>$did];
        }
        $res = nm_decoy_apply_border($conn, $border, $rd['cmd'], 30);
        if (empty($res['ok'])) {
            $conn->query("UPDATE nm_decoy_diversions SET status='failed', detail='".$conn->real_escape_string(substr((string)$res['error'],0,480))."' WHERE id=$did");
            if (function_exists('nm_audit')) nm_audit($conn,'deception.divert.fail',['details'=>['id'=>$did,'src'=>$src,'err'=>$res['error']]]);
            return ['ok'=>false,'error'=>'NAT apply failed: '.$res['error'],'diversion_id'=>$did];
        }
        if (function_exists('nm_audit')) nm_audit($conn,'deception.divert',['target_type'=>'node','target_id'=>$border,'details'=>['id'=>$did,'src'=>$src,'pot'=>$potId,'ttl_min'=>$S['ttl_min']]]);
        return ['ok'=>true,'diversion_id'=>$did,'comment'=>$comment,'ttl_min'=>$S['ttl_min']];
    }

    // Revert a diversion: remove the NAT rule by comment, mark reverted.
    function nm_decoy_revert($conn, int $did, ?int $uid, string $newStatus = 'reverted'): array {
        nm_decoy_ensure($conn);
        $d = $conn->query("SELECT * FROM nm_decoy_diversions WHERE id=".(int)$did." LIMIT 1");
        $d = $d ? $d->fetch_assoc() : null;
        if (!$d) return ['ok'=>false,'error'=>'diversion not found'];
        if ($d['status'] !== 'active') return ['ok'=>false,'error'=>'not active ('.$d['status'].')'];
        $vendor = nm_decoy_vendor_of($conn, (int)$d['border_node_id']);
        $rpot   = nm_decoy_pot_get($conn, (int)$d['pot_id']);
        $rr = nm_decoy_render_revert($vendor, (string)$d['nat_comment'], [
            'src_ip'=>(string)$d['src_ip'], 'pot_ip'=>$rpot['host_ip'] ?? '', 'pot_port'=>(int)($rpot['listen_port'] ?? 0), 'protocol'=>(string)$d['protocol'],
        ]);
        if (empty($rr['ok'])) return ['ok'=>false,'error'=>$rr['error']];
        $res = nm_decoy_apply_border($conn, (int)$d['border_node_id'], $rr['cmd'], 30);
        if (empty($res['ok'])) return ['ok'=>false,'error'=>'NAT removal failed: '.$res['error']];
        $conn->query("UPDATE nm_decoy_diversions SET status='".$conn->real_escape_string($newStatus)."', reverted_at=NOW() WHERE id=".(int)$did);
        if (function_exists('nm_audit')) nm_audit($conn,'deception.revert',['details'=>['id'=>$did,'status'=>$newStatus]]);
        return ['ok'=>true];
    }

    // Promote: learned enough → block this IP across the WHOLE fleet via Collective Immunity,
    // then revert the NAT (the decoy's job is done). Reuses nm_imm_add_threat + nm_imm_vaccinate.
    function nm_decoy_promote($conn, int $did, ?int $uid): array {
        nm_decoy_ensure($conn);
        $d = $conn->query("SELECT * FROM nm_decoy_diversions WHERE id=".(int)$did." LIMIT 1");
        $d = $d ? $d->fetch_assoc() : null;
        if (!$d) return ['ok'=>false,'error'=>'diversion not found'];
        if (!function_exists('nm_imm_add_threat') && is_file(__DIR__.'/nm_immunity.php')) require_once __DIR__.'/nm_immunity.php';
        if (!function_exists('nm_imm_add_threat')) return ['ok'=>false,'error'=>'Immunity module unavailable'];
        $t = nm_imm_add_threat($conn, (string)$d['src_ip'], 'ip', 'deception', 'high',
             'Attacker behaviour captured in a NEURU honeypot (diversion #'.$did.').', $uid);
        $tid = (int)($t['id'] ?? 0);
        if (!empty($t['ok']) && $tid && function_exists('nm_imm_vaccinate')) nm_imm_vaccinate($conn, $tid);
        // best-effort revert of the NAT (mark promoted regardless of revert result)
        if ($d['status'] === 'active') nm_decoy_revert($conn, $did, $uid, 'promoted');
        else $conn->query("UPDATE nm_decoy_diversions SET status='promoted' WHERE id=".(int)$did);
        if ($tid) $conn->query("UPDATE nm_decoy_diversions SET threat_id=$tid WHERE id=".(int)$did);
        if (function_exists('nm_audit')) nm_audit($conn,'deception.promote',['details'=>['id'=>$did,'src'=>$d['src_ip'],'threat_id'=>$tid]]);
        return ['ok'=>true,'threat_id'=>$tid];
    }

    function nm_decoy_diversions($conn, int $limit = 60): array {
        nm_decoy_ensure($conn);
        $out = [];
        $r = $conn->query("SELECT dv.*, p.name pot_name, p.host_ip pot_ip, n.display_name border_name
                           FROM nm_decoy_diversions dv
                           LEFT JOIN nm_decoy_pots p ON p.id=dv.pot_id
                           LEFT JOIN nm_nodes n ON n.id=dv.border_node_id
                           ORDER BY dv.id DESC LIMIT ".(int)$limit);
        while ($r && $x = $r->fetch_assoc()) $out[] = $x;
        return $out;
    }

    // Cron: (1) auto-revert any active diversion past its TTL (mandatory safety net); (2) coordinate
    // across modules — if an active diversion's IP got BLOCKED elsewhere (Immunity/Heal) meanwhile,
    // end the deception (block supersedes divert) so the two never fight over one source.
    function nm_decoy_sweep($conn): array {
        nm_decoy_ensure($conn);
        $rev = 0; $superseded = 0; $errs = [];
        // (1) TTL-expired
        $r = $conn->query("SELECT id FROM nm_decoy_diversions WHERE status='active' AND expires_at IS NOT NULL AND expires_at < NOW()");
        $ids = []; while ($r && $x = $r->fetch_assoc()) $ids[] = (int)$x['id'];
        foreach ($ids as $id) { $res = nm_decoy_revert($conn, $id, null, 'reverted'); if (!empty($res['ok'])) $rev++; else $errs[] = $id.':'.$res['error']; }
        // (2) superseded by a block on the same IP
        $r = $conn->query("SELECT id, src_ip FROM nm_decoy_diversions WHERE status='active'");
        $rows = []; while ($r && $x = $r->fetch_assoc()) $rows[] = $x;
        foreach ($rows as $row) {
            $disp = nm_decoy_source_disposition($conn, (string)$row['src_ip']);
            if (!empty($disp['blocked'])) {
                $by = $disp['blocked']['by']==='immunity' ? 'Collective Immunity' : 'Self-Healing';
                $conn->query("UPDATE nm_decoy_diversions SET detail='superseded by ".$conn->real_escape_string($by)." block' WHERE id=".(int)$row['id']);
                $res = nm_decoy_revert($conn, (int)$row['id'], null, 'reverted');
                if (!empty($res['ok'])) { $superseded++; if (function_exists('nm_audit')) nm_audit($conn,'deception.superseded',['details'=>['id'=>$row['id'],'src'=>$row['src_ip'],'by'=>$by]]); }
                else $errs[] = $row['id'].':'.$res['error'];
            }
        }
        // (3) accrue Watch events from the border firewall log for still-active diversions
        $ing = 0;
        $ar = $conn->query("SELECT id FROM nm_decoy_diversions WHERE status='active' ORDER BY id DESC LIMIT 10");
        while ($ar && $x = $ar->fetch_assoc()) $ing += nm_decoy_ingest_border_log($conn, (int)$x['id']);
        return ['ok'=>true,'reverted'=>$rev,'superseded'=>$superseded,'ingested'=>$ing,'errors'=>$errs,'checked'=>count($ids)+count($rows)];
    }

    // One-click divert used by other pages (e.g. immunity.php's threat list): auto-pick the newest
    // deployed honeypot, then run the fully-guarded nm_decoy_divert. So an operator can deceive an
    // attacker straight from where they see the incident, without opening the Deception Grid.
    function nm_decoy_quick_divert($conn, string $src_ip, ?int $uid, int $target_port = 0): array {
        nm_decoy_ensure($conn);
        $pr = $conn->query("SELECT id FROM nm_decoy_pots WHERE status='deployed' ORDER BY id DESC LIMIT 1");
        if (!$pr || !$pr->num_rows) return ['ok'=>false,'error'=>'No deployed honeypot — deploy one in Deception Grid first.'];
        $potId = (int)$pr->fetch_assoc()['id'];
        return nm_decoy_divert($conn, ['src_ip'=>$src_ip,'pot_id'=>$potId,'target_port'=>$target_port,'protocol'=>'tcp'], $uid, 'manual');
    }

    function nm_decoy_events_for($conn, int $did, int $limit = 100): array {
        $out = [];
        $r = $conn->query("SELECT id,ts,kind,src_ip,LEFT(data,600) data FROM nm_decoy_events WHERE diversion_id=".(int)$did." ORDER BY id DESC LIMIT ".(int)$limit);
        while ($r && $x = $r->fetch_assoc()) $out[] = $x;
        return $out;
    }

    // Parse a border firewall-log dump (matched on the diversion's comment) into connection events.
    function nm_decoy_parse_border_log(string $out, string $comment): array {
        $ev = [];
        foreach (preg_split('/\r?\n/', $out) as $ln) {
            $ln = trim($ln);
            if ($ln === '' || strpos($ln, $comment) === false || strpos($ln, 'NM_DECOY_OK') !== false) continue;
            $src = '';
            if (preg_match('/(\d{1,3}(?:\.\d{1,3}){3}):\d+\s*->\s*\d{1,3}(?:\.\d{1,3}){3}:\d+/', $ln, $m)) $src = $m[1];
            elseif (preg_match('/(\d{1,3}(?:\.\d{1,3}){3})/', $ln, $m)) $src = $m[1];
            $ev[] = ['src_ip' => $src, 'data' => substr($ln, 0, 900)];
        }
        return $ev;
    }
    // Pull the border router's firewall log for an ACTIVE diversion → insert new connection events
    // (idempotent — dedup on the exact log line). This is how "Watch" fills even if the honeypot image
    // never phones home. Returns the number of NEW events inserted.
    function nm_decoy_ingest_border_log($conn, int $did): int {
        nm_decoy_ensure($conn);
        $r = $conn->query("SELECT id,src_ip,nat_comment,border_node_id,status FROM nm_decoy_diversions WHERE id=".(int)$did." AND status='active' LIMIT 1");
        $d = $r ? $r->fetch_assoc() : null; if (!$d) return 0;
        $vendor = nm_decoy_vendor_of($conn, (int)$d['border_node_id']);
        $logcmd = nm_decoy_render_logread($vendor, (string)$d['nat_comment']); if ($logcmd === null) return 0;
        $res = nm_decoy_apply_border($conn, (int)$d['border_node_id'], $logcmd, 20);
        if (empty($res['ok'])) return 0;
        $n = 0;
        $ins = $conn->prepare("INSERT INTO nm_decoy_events (diversion_id,kind,src_ip,data) VALUES (?,?,?,?)");
        $chk = $conn->prepare("SELECT 1 FROM nm_decoy_events WHERE diversion_id=? AND data=? LIMIT 1");
        $kind = 'connection';
        foreach (nm_decoy_parse_border_log((string)($res['out'] ?? ''), (string)$d['nat_comment']) as $e) {
            $chk->bind_param('is', $did, $e['data']); $chk->execute(); $chk->store_result(); $dup = $chk->num_rows > 0; $chk->free_result();
            if ($dup) continue;
            $ins->bind_param('isss', $did, $kind, $e['src_ip'], $e['data']); $ins->execute(); $n++;
        }
        $ins->close(); $chk->close();
        return $n;
    }

    // ── F2·P2: the autonomous loop (OFF unless deception_auto=1). Reuses Immunity's detection ─────
    // (nm_threats 'pending' from nm_imm_detect_portscan) as the trigger → divert → observe → let the
    // AI analyst judge → auto-promote to a fleet block when it says so. Called from cron_decoy.
    function nm_decoy_auto_tick($conn): array {
        nm_decoy_ensure($conn);
        $S = nm_decoy_settings($conn);
        if (!$S['enabled'] || !$S['auto']) return ['ok'=>true,'skipped'=>'auto off'];
        $out = ['ok'=>true,'diverted'=>0,'analyzed'=>0,'promoted'=>0];

        // pick a deployed honeypot (newest); skip the whole tick if none
        $potId = 0;
        $pr = $conn->query("SELECT id FROM nm_decoy_pots WHERE status='deployed' ORDER BY id DESC LIMIT 1");
        if ($pr && $pr->num_rows) $potId = (int)$pr->fetch_assoc()['id'];

        // 1) AUTO-DIVERT: recent PENDING threats (Immunity) whose class we deceive, capped per run.
        //    nm_decoy_divert re-checks every guard (enabled, allowlist, private, already blocked…).
        if ($potId > 0 && $S['classes'] && $conn->query("SHOW TABLES LIKE 'nm_threats'")->num_rows) {
            $inList = implode(',', array_map(fn($c)=>"'".$conn->real_escape_string($c)."'", $S['classes']));
            // CRITICAL: only auto-divert threats the BORDER router actually observed (reported_by
            // names it). A dst-nat only intercepts traffic transiting that router — a scan seen only
            // by another (unmanaged) router would get a useless NAT rule. If no border identity is
            // resolvable, skip auto-divert entirely (fail safe).
            $b = nm_decoy_border_identity($conn);
            $ors = [];
            if ($b['name'] !== '') $ors[] = "reported_by LIKE '%".$conn->real_escape_string($b['name'])."%'";
            if ($b['ip']   !== '') $ors[] = "reported_by LIKE '%".$conn->real_escape_string($b['ip'])."%'";
            if (!$ors) return $out;   // can't confirm the border → do nothing
            $borderClause = ' AND ('.implode(' OR ', $ors).')';
            $cand = $conn->query("SELECT indicator FROM nm_threats
                                  WHERE ind_type='ip' AND status='pending' AND source IN ($inList)
                                  AND first_seen >= (NOW() - INTERVAL 20 MINUTE) {$borderClause} ORDER BY id DESC LIMIT 8");
            $n = 0;
            while ($cand && $row = $cand->fetch_assoc()) {
                if ($n >= 3) break;   // gentle: at most 3 new diverts per minute
                $r = nm_decoy_divert($conn, ['src_ip'=>$row['indicator'],'pot_id'=>$potId,'target_port'=>0,'protocol'=>'tcp'], null, 'auto');
                if (!empty($r['ok'])) { $out['diverted']++; $n++; }
            }
        }

        // 2) AUTO-ANALYZE active diversions that have NEW events (only if the analyst webhook is on)
        $wh = function_exists('nm_n8n_webhook_by_slug') ? nm_n8n_webhook_by_slug($conn,'deception-analyst') : null;
        if ($wh && !empty($wh['enabled'])) {
            $av = $conn->query("SELECT dv.id, COUNT(e.id) ev FROM nm_decoy_diversions dv
                                JOIN nm_decoy_events e ON e.diversion_id=dv.id
                                WHERE dv.status='active'
                                  AND (dv.ai_at IS NULL OR EXISTS(SELECT 1 FROM nm_decoy_events e2 WHERE e2.diversion_id=dv.id AND e2.ts > dv.ai_at))
                                GROUP BY dv.id ORDER BY ev DESC LIMIT 3");
            $rows = []; while ($av && $x = $av->fetch_assoc()) $rows[] = $x;
            foreach ($rows as $x) {
                $res = nm_decoy_analyze($conn, (int)$x['id']);
                if (empty($res['ok'])) continue;
                $out['analyzed']++;
                // 3) AUTO-PROMOTE when the AI says 'promote' AND enough evidence accumulated
                if ((($res['analysis']['verdict'] ?? '') === 'promote') && (int)$x['ev'] >= $S['promote_min_events']) {
                    $p = nm_decoy_promote($conn, (int)$x['id'], null);
                    if (!empty($p['ok'])) { $out['promoted']++;
                        if (function_exists('nm_audit')) nm_audit($conn,'deception.auto_promote',['details'=>['id'=>$x['id'],'events'=>$x['ev']]]); }
                }
            }
        }
        return $out;
    }

    // small CIDR check (IPv4) for the never-divert allowlist
    function nm_decoy_ip_in_cidr(string $ip, string $cidr): bool {
        if (strpos($cidr,'/')===false) return $ip === $cidr;
        [$net,$bits] = explode('/', $cidr, 2); $bits=(int)$bits;
        $ipL = ip2long($ip); $netL = ip2long($net);
        if ($ipL===false || $netL===false || $bits<0 || $bits>32) return false;
        $mask = $bits===0 ? 0 : (~0 << (32-$bits)) & 0xFFFFFFFF;
        return ($ipL & $mask) === ($netL & $mask);
    }
}
