<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU NOC → NEURU FSP (Field Service Portal) integration.
//
// When a node has a problem, NOC opens a service ticket in FSP — automatically,
// exactly once — and closes it when the node recovers. The integration is ONE
// way: NOC calls FSP (outbound HTTPS + bearer token); FSP never calls back.
//
// Two independent flows, both driven from here:
//   • TICKETS   — POST /calls (open/join) + POST /calls/resolve (recovery).
//                 Driven off the incident lifecycle (nm_inc_correlate): every
//                 open node incident maps 1:1 to an FSP call, keyed by the
//                 incident's stable corr_key (→ dedupe_key). See nm_fsp_sync().
//   • INVENTORY — POST /assets (upsert on asset_tag, batch ≤200). Pushes NOC's
//                 nodes so FSP can resolve tickets by asset_serial. nm_fsp_push_inventory().
//
// Design rules taken straight from the FSP integration contract:
//   - dedupe_key identifies a FAULT, not an event → we reuse corr_key (stable,
//     no timestamps/counters). While a call with that key is open, further POSTs
//     JOIN it (occurrence++), they don't duplicate.
//   - Idempotency-Key identifies one HTTP request → stable per (fault, state) so
//     a timed-out retry replays the original answer (one ticket, never two).
//   - We only POST on STATE CHANGE (new open / occurrence bump / resolve) to stay
//     under the 120-req/min budget — dedupe on FSP's side collapses the rest.
//   - 422 "cannot identify" is NEVER dropped: the ticket is queued as 'unmapped'
//     and a NOC-side alert is raised. 401/403 stop the loop (config error).
//   - held (a tech already dispatched) counts as success — NOC stops managing it.
//
// This file is best-effort: nothing here may ever break the incident cron. All
// entry points are wrapped and gated on config; a disabled/unconfigured install
// is a no-op.
// ─────────────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/nm_secrets.php';

if (!function_exists('nm_fsp_ensure')) {

    // Local ticket-tracking table: one row per fault we've told FSP about. It is
    // the memory that lets us dedupe across cron ticks and restarts — the FSP
    // call number/id, the last occurrence state we reported, and lifecycle status.
    function nm_fsp_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        if (!($conn instanceof mysqli)) return;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_fsp_tickets (
            corr_key       VARCHAR(120) NOT NULL PRIMARY KEY,   -- 1:1 with nm_incidents.corr_key
            dedupe_key     VARCHAR(160) NOT NULL,               -- what we sent FSP (noc:<corr_key>)
            fsp_id         BIGINT DEFAULT NULL,                 -- FSP call id
            fsp_number     VARCHAR(40) DEFAULT NULL,            -- human number (CS…)
            node_id        INT DEFAULT NULL,
            status         VARCHAR(16) NOT NULL DEFAULT 'open', -- open|resolved|held|unmapped|error
            occurrences    INT NOT NULL DEFAULT 0,              -- as reported by FSP
            reported_sig   INT NOT NULL DEFAULT 0,              -- last signal_count we POSTed (state marker)
            reported_sev   VARCHAR(10) DEFAULT NULL,            -- last severity we POSTed
            escalated      TINYINT NOT NULL DEFAULT 0,
            resolved_by    VARCHAR(16) DEFAULT NULL,            -- asset_serial|site_code|site_id
            last_error     VARCHAR(255) DEFAULT NULL,
            correlation_id VARCHAR(48) DEFAULT NULL,            -- FSP correlation id of last failure
            opened_at      DATETIME DEFAULT NULL,
            updated_at     DATETIME DEFAULT NULL,
            resolved_at    DATETIME DEFAULT NULL,
            KEY idx_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // Per-node FSP site code (the retailer site a node lives at). mysqli is in
        // EXCEPTION mode → guard the ALTER with an existence check first (CLAUDE.md).
        try {
            $c = $conn->query("SHOW COLUMNS FROM nm_nodes LIKE 'fsp_site_code'");
            if (!$c || $c->num_rows === 0) $conn->query("ALTER TABLE nm_nodes ADD COLUMN fsp_site_code VARCHAR(60) DEFAULT NULL");
        } catch (\Throwable $e) { /* nm_nodes absent on a bare install — harmless */ }
    }

    // ── Config ────────────────────────────────────────────────────────────────
    // All settings live in nm_settings; the bearer token is encrypted at rest.
    function nm_fsp_cfg($conn): array {
        $keys = ['fsp_enabled','fsp_base_url','fsp_token','fsp_trigger_sev','fsp_caller_name',
                 'fsp_resolve_recovery','fsp_node_only','fsp_default_site_code',
                 'fsp_inventory_enabled','fsp_asset_prefix','fsp_last_error','fsp_status'];
        $in  = "'" . implode("','", $keys) . "'";
        $c   = [];
        if ($r = @$conn->query("SELECT setting_key,setting_val FROM nm_settings WHERE setting_key IN ($in)")) {
            while ($x = $r->fetch_assoc()) $c[$x['setting_key']] = $x['setting_val'];
        }
        $token = '';
        if (!empty($c['fsp_token'])) { try { $token = nm_secret_decrypt($c['fsp_token']); } catch (\Throwable $e) { $token = ''; } }
        $sev = trim((string)($c['fsp_trigger_sev'] ?? 'critical'));
        return [
            'enabled'          => ($c['fsp_enabled'] ?? '0') === '1',
            'base_url'         => rtrim((string)($c['fsp_base_url'] ?? ''), '/'),
            'token'            => $token,
            'trigger_sev'      => $sev === '' ? ['critical'] : array_map('trim', explode(',', strtolower($sev))),
            'caller_name'      => trim((string)($c['fsp_caller_name'] ?? '')) ?: 'NEURU NOC',
            'resolve_recovery' => ($c['fsp_resolve_recovery'] ?? '1') === '1',
            'node_only'        => ($c['fsp_node_only'] ?? '1') === '1',
            'default_site'     => trim((string)($c['fsp_default_site_code'] ?? '')),
            'inventory'        => ($c['fsp_inventory_enabled'] ?? '0') === '1',
            'asset_prefix'     => trim((string)($c['fsp_asset_prefix'] ?? '')) ?: 'NOC',
        ];
    }

    function nm_fsp_configured(array $cfg): bool {
        return $cfg['enabled'] && $cfg['base_url'] !== '' && $cfg['token'] !== '';
    }

    // ── Low-level HTTP ──────────────────────────────────────────────────────────
    // Returns [http_code, decoded_data_or_null, error_string, correlation_id, rate_remaining].
    // On the FSP envelope {ok:false,error:{…}} it surfaces the message + correlation_id.
    function nm_fsp_http(array $cfg, string $method, string $path, ?array $body = null, ?string $idem = null): array {
        $url = $cfg['base_url'] . '/' . ltrim($path, '/');
        $headers = ['Accept: application/json'];
        // /health and /openapi.json need no token; everything else is bearer-authed.
        if ($cfg['token'] !== '') $headers[] = 'Authorization: Bearer ' . $cfg['token'];
        if ($body !== null)       $headers[] = 'Content-Type: application/json';
        if ($idem !== null)       $headers[] = 'Idempotency-Key: ' . $idem;

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_CONNECTTIMEOUT => 6,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        if ($body !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body, JSON_UNESCAPED_SLASHES));

        $raw  = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $hlen = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $cerr = curl_error($ch);
        curl_close($ch);

        if ($raw === false) return [0, null, 'connection failed: ' . $cerr, null, null];

        $hblob = substr((string)$raw, 0, $hlen);
        $bblob = substr((string)$raw, $hlen);
        $rateRem = null;
        if (preg_match('/^RateLimit-Remaining:\s*(\d+)/mi', $hblob, $m)) $rateRem = (int)$m[1];

        $j = json_decode($bblob, true);
        if (!is_array($j)) return [$code, null, 'non-JSON reply (HTTP ' . $code . ')', null, $rateRem];

        if (!empty($j['ok'])) return [$code, $j['data'] ?? [], '', null, $rateRem];

        // Failure envelope
        $err  = $j['error']['message'] ?? ('HTTP ' . $code);
        $corr = $j['error']['correlation_id'] ?? null;
        $ecode= $j['error']['code'] ?? '';
        return [$code, null, ($ecode ? "[$ecode] " : '') . $err, $corr, $rateRem];
    }

    // ── Health / token probe (for the config "Test connection" button) ──────────
    function nm_fsp_test(array $cfg): array {
        if ($cfg['base_url'] === '') return ['ok'=>false, 'err'=>'Base URL is empty'];
        [$hc, $hd, $he] = nm_fsp_http($cfg, 'GET', 'health');
        if ($hc !== 200) return ['ok'=>false, 'err'=>'health check failed: ' . ($he ?: "HTTP $hc")];
        if ($cfg['token'] === '') return ['ok'=>true, 'health'=>$hd, 'scopes'=>[], 'note'=>'reachable; add a token to verify scopes'];
        [$mc, $md, $me] = nm_fsp_http($cfg, 'GET', 'me');
        if ($mc !== 200) return ['ok'=>false, 'err'=>'token check (/me) failed: ' . ($me ?: "HTTP $mc")];
        return ['ok'=>true, 'health'=>$hd, 'token'=>($md['token_name'] ?? $md['name'] ?? null),
                'acts_as'=>($md['acts_as'] ?? null), 'scopes'=>($md['scopes'] ?? []), 'me'=>$md];
    }

    // ── Identity: resolve a node → what FSP can key a ticket on ─────────────────
    // Priority: asset_serial (resolves machine AND site) > site_code > default site.
    function nm_fsp_identity($conn, ?int $nodeId, array $cfg): array {
        if ($nodeId) {
            if ($r = @$conn->query("SELECT serial_number, fsp_site_code FROM nm_nodes WHERE id=" . (int)$nodeId . " LIMIT 1")) {
                if ($x = $r->fetch_assoc()) {
                    $serial = trim((string)($x['serial_number'] ?? ''));
                    $site   = trim((string)($x['fsp_site_code'] ?? ''));
                    if ($serial !== '') return ['asset_serial' => $serial];
                    if ($site   !== '') return ['site_code'    => $site];
                }
            }
        }
        if ($cfg['default_site'] !== '') return ['site_code' => $cfg['default_site']];
        return [];  // nothing to resolve → caller marks unmapped
    }

    // dedupe_key = the incident's stable corr_key, namespaced. corr_key is already
    // a fault identity (node:<id>:<topic>) with no timestamp/counter — exactly what
    // §4 requires. Sanitise to the safe charset and cap length.
    function nm_fsp_dedupe_key(string $corrKey): string {
        $k = 'noc:' . strtolower($corrKey);
        $k = preg_replace('/[^a-z0-9:._\-]+/', '-', $k);
        return substr($k, 0, 160);
    }

    // Idempotency-Key: stable per (fault, occurrence-state) so a retry replays.
    function nm_fsp_idem(string $dedupeKey, string $marker): string {
        return 'noc-' . substr(sha1($dedupeKey), 0, 16) . '-' . $marker;
    }

    // Build a service-rep-readable symptom line from the incident row.
    function nm_fsp_problem_text(array $inc): string {
        $t = trim((string)($inc['title'] ?? 'Node problem'));
        $bits = [$t];
        $host = trim((string)($inc['root_host'] ?? $inc['root_entity'] ?? ''));
        if ($host !== '' && stripos($t, $host) === false) $bits[] = 'Device: ' . $host;
        $imp = trim((string)($inc['impact'] ?? ''));
        if ($imp !== '') $bits[] = 'Impact: ' . mb_substr($imp, 0, 300);
        $bits[] = 'Raised automatically by NEURU NOC.';
        return mb_substr(implode('. ', $bits), 0, 900);
    }

    // ── Open or join a ticket for one incident ──────────────────────────────────
    function nm_fsp_open($conn, array $cfg, array $inc, ?array $track): void {
        nm_fsp_ensure($conn);
        $corr   = (string)$inc['corr_key'];
        $nodeId = !empty($inc['root_node_id']) ? (int)$inc['root_node_id'] : null;
        $dk     = nm_fsp_dedupe_key($corr);
        $sig    = (int)($inc['signal_count'] ?? 1);
        $sev    = (string)($inc['severity'] ?? 'warning');

        // State marker: create=open; occurrence bumps as signal_count grows.
        $isNew   = !$track || in_array(($track['status'] ?? ''), ['resolved','unmapped',''], true);
        $marker  = $isNew ? 'open' : ('occ' . max(1, $sig));
        $idem    = nm_fsp_idem($dk, $marker);

        $ident = nm_fsp_identity($conn, $nodeId, $cfg);
        if (!$ident) {
            // §9: never drop — record as unmapped and raise a NOC-side alert once.
            nm_fsp_mark($conn, $corr, $dk, $nodeId, ['status'=>'unmapped',
                'last_error'=>'No asset_serial/site_code for this node — set a serial or FSP site code']);
            nm_fsp_unmapped_alert($conn, $inc);
            return;
        }

        $body = $ident + [
            'problem_text' => nm_fsp_problem_text($inc),
            'dedupe_key'   => $dk,
            'caller_name'  => $cfg['caller_name'],
            'source_id'    => 'incident-' . ($inc['id'] ?? ''),
        ];

        [$code, $data, $err, $corrId] = nm_fsp_http($cfg, 'POST', 'calls', $body, $idem);

        // A 409 means this Idempotency-Key was used earlier with a different body (the node's
        // identity/problem changed since the last attempt). Retry once with a fresh key — the
        // dedupe_key still guarantees the fault joins its existing call instead of duplicating.
        if ($code === 409) {
            try { $nonce = substr(bin2hex(random_bytes(4)), 0, 8); } catch (\Throwable $e) { $nonce = substr(sha1(uniqid('', true)), 0, 8); }
            [$code, $data, $err, $corrId] = nm_fsp_http($cfg, 'POST', 'calls', $body, $idem . '-' . $nonce);
        }

        if ($code === 200 || $code === 201) {
            nm_fsp_mark($conn, $corr, $dk, $nodeId, [
                'status'      => 'open',
                'fsp_id'      => $data['id'] ?? null,
                'fsp_number'  => $data['number'] ?? null,
                'occurrences' => (int)($data['occurrences'] ?? 0),
                'reported_sig'=> $sig,
                'reported_sev'=> $sev,
                'escalated'   => !empty($data['escalated']) ? 1 : 0,
                'resolved_by' => $data['resolved_by'] ?? null,
                'last_error'  => null,
                'correlation_id' => null,
                'opened_at'   => $isNew ? date('Y-m-d H:i:s') : ($track['opened_at'] ?? date('Y-m-d H:i:s')),
            ]);
            return;
        }
        // 422 identify failure → unmapped + alert (self-heal via inventory push is a follow-up)
        $status = ($code === 422) ? 'unmapped' : 'error';
        if ($status === 'unmapped') nm_fsp_unmapped_alert($conn, $inc);
        nm_fsp_mark($conn, $corr, $dk, $nodeId,
            ['status'=>$status, 'last_error'=>substr((string)$err,0,255), 'correlation_id'=>$corrId]);
        // 401/403 are install-wide config errors — surface globally so the loop stops spamming.
        if ($code === 401 || $code === 403) nm_fsp_set($conn, 'fsp_status', 'auth_error');
    }

    // ── Close a ticket on recovery ──────────────────────────────────────────────
    function nm_fsp_resolve($conn, array $cfg, array $track, string $reason): void {
        nm_fsp_ensure($conn);
        $dk = (string)$track['dedupe_key'];
        [$code, $data, $err, $corrId] = nm_fsp_http($cfg, 'POST', 'calls/resolve',
            ['dedupe_key'=>$dk, 'reason'=>mb_substr($reason,0,300)]);
        if ($code === 200) {
            // held = a tech was already dispatched → success, but stop managing it.
            $held = !empty($data['held']);
            nm_fsp_mark($conn, (string)$track['corr_key'], $dk, $track['node_id'] ?? null, [
                'status'      => $held ? 'held' : 'resolved',
                'resolved_at' => date('Y-m-d H:i:s'),
                'last_error'  => null,
                'correlation_id' => null,
            ]);
            return;
        }
        nm_fsp_mark($conn, (string)$track['corr_key'], $dk, $track['node_id'] ?? null,
            ['last_error'=>'resolve failed: ' . substr((string)$err,0,240), 'correlation_id'=>$corrId]);
        if ($code === 401 || $code === 403) nm_fsp_set($conn, 'fsp_status', 'auth_error');
    }

    // ── Tracking-table upsert ───────────────────────────────────────────────────
    function nm_fsp_mark($conn, string $corr, string $dk, ?int $nodeId, array $f): void {
        nm_fsp_ensure($conn);
        $cols = ['corr_key','dedupe_key','node_id','updated_at'];
        $now  = date('Y-m-d H:i:s');
        $vals = [$corr, $dk, $nodeId, $now];
        foreach (['status','fsp_id','fsp_number','occurrences','reported_sig','reported_sev',
                  'escalated','resolved_by','last_error','correlation_id','opened_at','resolved_at'] as $k) {
            if (array_key_exists($k, $f)) { $cols[] = $k; $vals[] = $f[$k]; }
        }
        $place = implode(',', array_fill(0, count($cols), '?'));
        $upd   = implode(',', array_map(fn($c) => "$c=VALUES($c)", array_filter($cols, fn($c)=>$c!=='corr_key')));
        $types = '';
        foreach ($vals as $v) $types .= is_int($v) ? 'i' : 's';
        try {
            $st = $conn->prepare("INSERT INTO nm_fsp_tickets (" . implode(',', $cols) . ") VALUES ($place)
                                  ON DUPLICATE KEY UPDATE $upd");
            $st->bind_param($types, ...$vals);
            $st->execute(); $st->close();
        } catch (\Throwable $e) { /* best-effort */ }
    }

    // Per-install salt for generated serials → globally unique across NOC installs.
    // Generated once, then stable forever (a changed salt would orphan prior serials).
    function nm_fsp_salt($conn): string {
        if ($r = @$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='fsp_serial_salt' LIMIT 1")) {
            if ($x = $r->fetch_row()) { $v = trim((string)$x[0]); if ($v !== '') return $v; }
        }
        try { $salt = substr(bin2hex(random_bytes(4)), 0, 6); } catch (\Throwable $e) { $salt = substr(sha1((string)($_SERVER['SERVER_ADDR'] ?? 'noc') . microtime()), 0, 6); }
        nm_fsp_set($conn, 'fsp_serial_salt', $salt);
        return $salt;
    }

    function nm_fsp_set($conn, string $key, string $val): void {
        try { $v = $conn->real_escape_string($val); $k = $conn->real_escape_string($key);
            $conn->query("INSERT INTO nm_settings(setting_key,setting_val) VALUES('$k','$v')
                          ON DUPLICATE KEY UPDATE setting_val='$v'"); } catch (\Throwable $e) {}
    }

    // Raise a NOC-side alert (once) that a node is unmapped in FSP, so a fault is
    // never silently swallowed. Uses nm_ai_insights if present; else audit log.
    function nm_fsp_unmapped_alert($conn, array $inc): void {
        $host = trim((string)($inc['root_host'] ?? $inc['root_entity'] ?? ('node ' . ($inc['root_node_id'] ?? '?'))));
        $key  = 'fsp-unmapped:' . ($inc['corr_key'] ?? $host);
        try {
            $conn->query("CREATE TABLE IF NOT EXISTS nm_ai_insights (id BIGINT AUTO_INCREMENT PRIMARY KEY) ENGINE=InnoDB");
        } catch (\Throwable $e) {}
        // De-dupe the NOC-side alert on its own key inside 24h.
        try {
            $ex = @$conn->query("SELECT id FROM nm_ai_insights WHERE kind='fsp_unmapped'
                                 AND title='" . $conn->real_escape_string($key) . "'
                                 AND status='open' AND created_at > (NOW()-INTERVAL 24 HOUR) LIMIT 1");
            if ($ex && $ex->num_rows) return;
        } catch (\Throwable $e) { return; }
        try {
            $nid = !empty($inc['root_node_id']) ? (int)$inc['root_node_id'] : null;
            $st = $conn->prepare("INSERT INTO nm_ai_insights (node_id,kind,severity,title,body,status,created_at)
                                  VALUES (?,?,?,?,?, 'open', NOW())");
            if ($st) {
                $sev='warning'; $kind='fsp_unmapped';
                $title=$key;
                $body="NEURU NOC could not open an FSP ticket for {$host}: FSP has no matching asset_serial or site_code. "
                    ."Set the node's serial number, or its FSP site code, in Config → Nodes — or enable inventory push so NOC creates the asset.";
                $st->bind_param('issss', $nid, $kind, $sev, $title, $body);
                $st->execute(); $st->close();
            }
        } catch (\Throwable $e) { /* table shape differs — skip, don't break the cron */ }
    }

    // ── The reconcile loop — called every incident cron tick (best-effort) ──────
    // Opens/updates FSP tickets for qualifying OPEN incidents; resolves tickets
    // whose incident is gone. Only POSTs on state change → stays under 120/min.
    function nm_fsp_sync($conn): array {
        $out = ['skipped'=>true];
        try {
            $cfg = nm_fsp_cfg($conn);
            if (!nm_fsp_configured($cfg)) return $out;
            nm_fsp_ensure($conn);

            // Load our current ticket memory keyed by corr_key.
            $tracks = [];
            if ($r = @$conn->query("SELECT * FROM nm_fsp_tickets")) {
                while ($x = $r->fetch_assoc()) $tracks[$x['corr_key']] = $x;
            }

            // Qualifying OPEN incidents: node-rooted (if node_only) + severity in trigger set.
            $sevIn = "'" . implode("','", array_map([$conn,'real_escape_string'], $cfg['trigger_sev'])) . "'";
            $nodeCond = $cfg['node_only'] ? ' AND root_node_id IS NOT NULL' : '';
            $sql = "SELECT id,corr_key,title,severity,status,root_node_id,root_host,root_entity,signal_count,impact
                    FROM nm_incidents
                    WHERE status IN ('open','acknowledged') AND severity IN ($sevIn){$nodeCond}";
            $open = [];
            if ($r = @$conn->query($sql)) while ($x = $r->fetch_assoc()) $open[$x['corr_key']] = $x;

            $opened=0; $updated=0; $resolved=0; $budget=40;  // per-tick POST cap (rate-limit guard)

            // Open new / bump occurrence on existing.
            foreach ($open as $corr => $inc) {
                if ($budget <= 0) break;
                $tr = $tracks[$corr] ?? null;
                $isNew = !$tr || in_array(($tr['status'] ?? ''), ['resolved','unmapped',''], true);
                $sigNow = (int)($inc['signal_count'] ?? 1);
                $bump   = $tr && ($tr['status'] ?? '') === 'open'
                          && ((int)($tr['reported_sig'] ?? 0) < $sigNow
                              || (string)($tr['reported_sev'] ?? '') !== (string)$inc['severity']);
                if ($isNew || $bump) {
                    nm_fsp_open($conn, $cfg, $inc, $tr);
                    $budget--;
                    $isNew ? $opened++ : $updated++;
                }
            }

            // Resolve on recovery: tracked tickets that are 'open' but whose incident
            // is no longer in the qualifying-open set → the node recovered.
            if ($cfg['resolve_recovery']) {
                foreach ($tracks as $corr => $tr) {
                    if ($budget <= 0) break;
                    if (($tr['status'] ?? '') !== 'open') continue;
                    if (isset($open[$corr])) continue;  // still open → leave it
                    nm_fsp_resolve($conn, $cfg, $tr, 'NOC incident cleared — node recovered');
                    $budget--; $resolved++;
                }
            }

            $out = ['skipped'=>false, 'opened'=>$opened, 'updated'=>$updated, 'resolved'=>$resolved];
        } catch (\Throwable $e) {
            $out = ['skipped'=>true, 'error'=>$e->getMessage()];
        }
        return $out;
    }

    // ── Inventory push — POST /assets (upsert on asset_tag, batch ≤200) ─────────
    // FULL sibling-sync: NOC and FSP hold the same record for every node. asset_tag
    // is stable per node (<prefix>-<id>) so a sweep converges, never clones. We send
    // EVERYTHING NOC can authoritatively know — name, serial, site, enriched location
    // (IP + place + city/country), real warranty, criticality — and BACK-FILL what NOC
    // was missing (a generated-but-unique serial, the default site code) into nm_nodes
    // so the two portals literally match. We do NOT fabricate commercial data (model_code
    // must pre-exist in FSP's catalogue; installed/purchase/barcode are human-owned in FSP).
    // Reads results[] and returns per-row rejects (a 201/200 is NOT enough — §8 trap).
    function nm_fsp_push_inventory($conn, ?array $cfg = null, int $limit = 0): array {
        $cfg = $cfg ?: nm_fsp_cfg($conn);
        if (!nm_fsp_configured($cfg)) return ['ok'=>false, 'err'=>'FSP not configured/enabled'];
        if (!$cfg['inventory'])       return ['ok'=>false, 'err'=>'Inventory push is disabled'];

        $nodes = [];
        $q = "SELECT n.id, n.display_name, n.hostname, n.ip_address, n.serial_number, n.manufacturer,
                     n.model, n.fsp_site_code, n.device_role, n.location, n.warranty_expiry,
                     g.city, g.country
              FROM nm_nodes n LEFT JOIN nm_node_geo g ON g.node_id=n.id
              ORDER BY n.id" . ($limit > 0 ? " LIMIT " . (int)$limit : "");
        if ($r = @$conn->query($q)) while ($x = $r->fetch_assoc()) $nodes[] = $x;
        if (!$nodes) return ['ok'=>true, 'created'=>0, 'updated'=>0, 'rejected'=>0, 'note'=>'no nodes'];

        $created=0; $updated=0; $rejected=0; $rejects=[]; $batchNo=0; $backfilled=0; $modelRetry=[];
        $salt = nm_fsp_salt($conn);
        // Per-invocation nonce for the Idempotency-Key. Each sweep (a Sync click or the daily
        // cron) is a NEW logical push → fresh key. A body-hash key looked clever but REPLAYS a
        // stale answer for 24h when the body is unchanged but FSP state changed (e.g. the site
        // was just created) — the exact "still rejected after I fixed FSP" trap. Retry-safety is
        // already guaranteed by the asset_tag upsert (a re-push updates, never duplicates), so
        // the key only needs to be unique per attempt.
        try { $runNonce = substr(bin2hex(random_bytes(5)), 0, 10); } catch (\Throwable $e) { $runNonce = substr(sha1(uniqid('', true)), 0, 10); }
        $today = date('Ymd');
        foreach (array_chunk($nodes, 200) as $chunk) {
            $batchNo++;
            $assets = [];
            foreach ($chunk as $n) {
                $id   = (int)$n['id'];
                $tag  = $cfg['asset_prefix'] . '-' . $id;            // STABLE identity
                $a = ['asset_tag' => $tag, 'status' => 'installed'];
                $name = trim((string)($n['display_name'] ?: $n['hostname'] ?: $n['ip_address']));
                if ($name !== '')                       $a['name'] = mb_substr($name, 0, 120);

                // Serial: prefer the real one; else generate a unique, stable, clearly-synthetic
                // one and PERSIST it back to NOC so both siblings carry the same value. The
                // generated serial is namespaced by a per-install salt (NOCGEN-<salt>-<id>) so
                // it is globally unique — two NEURU NOC installs pushing to ONE FSP never collide,
                // and it can't clash with stray test data. Empty OR the old unsalted NOCGEN-<id>
                // format is (re)generated; a REAL serial is never touched.
                $serial = trim((string)$n['serial_number']);
                if ($serial === '' || preg_match('/^NOCGEN-\d+$/', $serial)) {
                    $serial = 'NOCGEN-' . $salt . '-' . $id;
                    try { $conn->query("UPDATE nm_nodes SET serial_number='" . $conn->real_escape_string($serial) . "' WHERE id=$id AND (serial_number IS NULL OR serial_number='' OR serial_number REGEXP '^NOCGEN-[0-9]+$')"); $backfilled++; } catch (\Throwable $e) {}
                }
                $a['serial_number'] = $serial;

                // Site: per-node code, else the configured default — and persist the default
                // onto the node when it had none, so the Nodes form shows the same site.
                $site = trim((string)($n['fsp_site_code'] ?? ''));
                if ($site === '' && $cfg['default_site'] !== '') {
                    $site = $cfg['default_site'];
                    try { $conn->query("UPDATE nm_nodes SET fsp_site_code='" . $conn->real_escape_string($site) . "' WHERE id=$id AND (fsp_site_code IS NULL OR fsp_site_code='')"); } catch (\Throwable $e) {}
                }
                if ($site !== '') $a['site_code'] = $site;

                // Enriched location_detail: IP · place · city, country (free text — always safe).
                $locBits = [];
                if (trim((string)$n['ip_address']) !== '') $locBits[] = 'IP ' . trim((string)$n['ip_address']);
                if (trim((string)($n['location'] ?? '')) !== '') $locBits[] = trim((string)$n['location']);
                $place = trim(trim((string)($n['city'] ?? '')) . (trim((string)($n['country'] ?? '')) !== '' ? ', ' . trim((string)$n['country']) : ''), ', ');
                if ($place !== '') $locBits[] = $place;
                if ($locBits) $a['location_detail'] = mb_substr(implode(' · ', $locBits), 0, 200);

                // model_code: send the node's model string as a candidate — FSP fills the
                // asset's model + CATEGORY from it, but ONLY if that code exists in FSP's model
                // catalogue; an unknown code rejects the whole row. So we send it optimistically
                // and SELF-HEAL below: any row FSP rejects for the model is re-sent without it,
                // so the node still syncs (serial+site+location) and gains its model the moment
                // an operator catalogues it. purchase/installed/barcode stay human-owned in FSP.
                if (trim((string)($n['model'] ?? '')) !== '') $a['model_code'] = mb_substr(trim((string)$n['model']), 0, 80);

                // Real warranty only (never fabricated).
                if (preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)($n['warranty_expiry'] ?? ''))) $a['warranty_end_on'] = $n['warranty_expiry'];

                // Criticality from the node's role (safe enum): core network gear = critical.
                $role = strtolower((string)($n['device_role'] ?? ''));
                $a['criticality'] = preg_match('/(core|router|firewall|gateway|server)/', $role . ' ' . strtolower($name)) ? 'critical' : 'normal';

                $a['notes'] = 'Discovered by NEURU NOC';
                $assets[] = $a;
            }
            $assetByTag = []; foreach ($assets as $aa) $assetByTag[$aa['asset_tag']] = $aa;
            // Idempotency-Key: date + batch + body-hash. A genuine retry (identical body)
            // replays safely; a changed body (nodes changed, or a manual re-sync) gets a
            // fresh key instead of a spurious 409 — asset_tag upsert dedupes either way.
            $idem = 'sweep-' . $today . '-' . $batchNo . '-' . $runNonce;
            [$code, $data, $err, $corrId] = nm_fsp_http($cfg, 'POST', 'assets', ['assets'=>$assets], $idem);
            if ($code !== 200 && $code !== 201) {
                return ['ok'=>false, 'err'=>"batch $batchNo failed: " . ($err ?: "HTTP $code"),
                        'correlation_id'=>$corrId, 'created'=>$created, 'updated'=>$updated, 'rejected'=>$rejected];
            }
            $created += (int)($data['created'] ?? 0);
            $updated += (int)($data['updated'] ?? 0);
            foreach ((array)($data['results'] ?? []) as $row) {
                if (!empty($row['ok'])) continue;
                $tag = $row['asset_tag'] ?? '?';
                $reason = (string)($row['error'] ?? 'rejected');
                // Self-heal: an uncatalogued model must not sink the whole node. Re-send it
                // without model_code so serial+site+location still land; log the rest.
                if (preg_match('/no model has the code/i', $reason) && isset($assetByTag[$tag]['model_code'])) {
                    $s = $assetByTag[$tag]; unset($s['model_code']); $modelRetry[] = $s;
                } else {
                    $rejected++; $rejects[] = $tag . ': ' . $reason;
                }
            }
        }
        // Self-heal pass: rows rejected only for an uncatalogued model, re-sent without it.
        $modelRetry = $modelRetry ?? [];
        foreach (array_chunk($modelRetry, 200) as $ri => $chunk) {
            $idem = 'sweep-' . $today . '-nomodel-' . $ri . '-' . $runNonce;
            [$code, $data] = nm_fsp_http($cfg, 'POST', 'assets', ['assets'=>$chunk], $idem);
            if ($code !== 200 && $code !== 201) { foreach ($chunk as $c) { $rejected++; $rejects[] = $c['asset_tag'] . ': model-retry failed'; } continue; }
            $created += (int)($data['created'] ?? 0);
            $updated += (int)($data['updated'] ?? 0);
            foreach ((array)($data['results'] ?? []) as $row) {
                if (empty($row['ok'])) { $rejected++; $rejects[] = ($row['asset_tag'] ?? '?') . ': ' . ($row['error'] ?? 'rejected'); }
            }
        }
        $modeled = count($modelRetry);
        // Every reject is logged — a 201 with silent rejects is the trap §8 warns about.
        // A clean run clears the latch so a stale failure doesn't linger in the UI.
        nm_fsp_set($conn, 'fsp_last_error', $rejects ? ('inventory rejects: ' . implode(' | ', array_slice($rejects, 0, 20))) : '');
        return ['ok'=>true, 'created'=>$created, 'updated'=>$updated, 'rejected'=>$rejected,
                'backfilled'=>$backfilled, 'uncatalogued_models'=>$modeled, 'rejects'=>$rejects];
    }
}
