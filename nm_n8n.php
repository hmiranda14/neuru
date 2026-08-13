<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — n8n automation + AI integration layer.
//
// TWO directions of trust:
//   OUTBOUND (portal → n8n): the portal calls configured n8n webhooks (table
//     nm_n8n_webhooks) and/or the n8n REST API (n8n_base_url + n8n_api_key) to
//     kick off flows / AI interactions.
//   INBOUND  (n8n → portal): n8n calls back into the portal (e.g. nm_ai_ingest.php)
//     carrying the shared inbound token (n8n_inbound_token), which it presents in
//     the `X-NetMon-Token` header. We verify with hash_equals (constant-time).
//
// Settings keys: n8n_base_url, n8n_api_key, n8n_inbound_token.
// ─────────────────────────────────────────────────────────────────────────────

if (!function_exists('nm_n8n_get')) {

    function nm_n8n_get($conn): array {
        $cfg = ['base_url' => '', 'api_key' => '', 'inbound_token' => '', 'portal_base' => ''];
        if (!($conn instanceof mysqli)) return $cfg;
        $res = @$conn->query("SELECT setting_key, setting_val FROM nm_settings
                              WHERE setting_key IN ('n8n_base_url','n8n_api_key','n8n_inbound_token','n8n_portal_base')");
        if ($res) while ($r = $res->fetch_assoc()) {
            switch ($r['setting_key']) {
                case 'n8n_base_url':      $cfg['base_url']      = $r['setting_val']; break;
                case 'n8n_api_key':       $cfg['api_key']       = $r['setting_val']; break;
                case 'n8n_inbound_token': $cfg['inbound_token'] = $r['setting_val']; break;
                // Absolute base URL of THIS portal, reachable from the n8n container (n8n's own
                // 'localhost' is n8n, not us). Used for outbound-flow callbacks. e.g. http://192.168.0.25:8090
                case 'n8n_portal_base':   $cfg['portal_base']   = rtrim((string)$r['setting_val'], '/'); break;
            }
        }
        return $cfg;
    }

    function nm_n8n_set($conn, string $key, string $val): bool {
        if (!($conn instanceof mysqli)) return false;
        if (!in_array($key, ['n8n_base_url', 'n8n_api_key', 'n8n_inbound_token', 'n8n_portal_base'], true)) return false;
        $st = $conn->prepare("INSERT INTO nm_settings (setting_key, setting_val) VALUES (?, ?)
                              ON DUPLICATE KEY UPDATE setting_val = VALUES(setting_val)");
        if (!$st) return false;
        $st->bind_param('ss', $key, $val); $ok = $st->execute(); $st->close();
        return $ok;
    }

    // Generate (or rotate) the inbound token n8n uses to authenticate to the portal.
    function nm_n8n_new_token(): string {
        return 'nmn8n_' . bin2hex(random_bytes(24));   // 48 hex chars + prefix
    }

    // AI Gateway (NEURU AI Flows service) — the connection the customer pastes after
    // registering this install on the NEURU Portal. Empty vkey = not enrolled (no-op).
    function nm_n8n_ai_conn($conn): array {
        $out = ['vkey' => '', 'conn_key' => '', 'public_base' => ''];
        if (!($conn instanceof mysqli)) return $out;
        if ($r = @$conn->query("SELECT setting_key,setting_val FROM nm_settings WHERE setting_key IN ('ai_gateway_vkey','ai_conn_key','ai_public_base')")) {
            while ($x = $r->fetch_assoc()) {
                if     ($x['setting_key'] === 'ai_gateway_vkey') $out['vkey']        = (string)$x['setting_val'];
                elseif ($x['setting_key'] === 'ai_conn_key')     $out['conn_key']    = (string)$x['setting_val'];
                elseif ($x['setting_key'] === 'ai_public_base')  $out['public_base'] = (string)$x['setting_val'];
            }
        }
        return $out;
    }

    // ── Flows Sync (NEURU AI Flows) ──────────────────────────────────────────────
    // Pull the customer's SUBSCRIBED hosted flows from the Portal and wire them into
    // nm_n8n_webhooks (correct per-customer URLs + enabled state). The WG tunnel callback
    // is already handled separately (ai_public_base + _neuru.callback_base injection).
    // Contract: docs/NEURU_FLOWS_SYNC_CONTRACT.md. Additive / no-op until the Portal ships
    // /v1/flows/sync — a 404 or ok:false just returns a clean skip, never throws.
    function nm_n8n_flows_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        try {                                        // mysqli is in EXCEPTION mode — guard the ALTER
            $has = false;
            if ($r = $conn->query("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_n8n_webhooks' AND COLUMN_NAME='source' LIMIT 1"))
                $has = (bool)$r->fetch_row();
            if (!$has)
                $conn->query("ALTER TABLE nm_n8n_webhooks ADD COLUMN source ENUM('manual','portal') NOT NULL DEFAULT 'manual'");
        } catch (\Throwable $e) { /* best-effort */ }
    }

    // Flows whose URL ALSO lives in a per-feature nm_settings key (the module reads/curls that key
    // DIRECTLY, not via the central nm_n8n_webhooks registry). Sync must write BOTH so every module
    // lights up — not just the central registry. Map = slug => setting_key, code-verified against each
    // reader (see docs/NEURU_FLOWS_SYNC_CONTRACT.md §"multi-location"). EXCLUDED on purpose: webhook_url
    // (a chat-channel field inside the notify blob, not a flow), netalert_url (no slug / DB-only), and
    // all inbound callback URLs (built at call time). container-analyze is dual-path (registry + key).
    function nm_n8n_flow_targets(): array {
        return [
            'latency-alert'         => 'smokeping_alert_url',
            'netflow-alert'         => 'netflow_alert_url',
            'archaeology-analyze'   => 'arch_webhook_url',
            'container-fix-exec'    => 'fix_webhook_url',
            'container-fix-suggest' => 'fix_suggest_url',
            'kb-search'             => 'kb_search_url',
            'kb-ingest'             => 'kb_ingest_url',
            'kb-search-pgvector'    => 'kb_search_url',
            'kb-ingest-pgvector'    => 'kb_ingest_url',
            'books-search'          => 'books_search_url',
            'rc-suggest'            => 'rc_suggest_url',
            'rc-exec'               => 'rc_execute_url',
            'weather-poll'          => 'wx_poll_url',
            'container-analyze'     => 'error_watch_analyze_url',
            'container-remediate'   => 'error_watch_remediation_url',
        ];
    }

    // Friendly label for the UI: where a slug's URL lands (which module, or the central registry).
    function nm_n8n_flow_label(string $slug): string {
        static $m = [
            'latency-alert' => 'SmokePing · alerts',
            'netflow-alert' => 'NetFlow · alerts', 'archaeology-analyze' => 'AI Archaeologist',
            'container-fix-exec' => 'Solution Commander · SSH fix', 'container-fix-suggest' => 'Solution Commander · AI suggest',
            'kb-search' => 'Copilot KB · search', 'kb-ingest' => 'Copilot KB · ingest', 'books-search' => 'Books RAG',
            'rc-suggest' => 'Router Commander · AI', 'rc-exec' => 'Router Commander · exec',
            'weather-poll' => 'Weather routing', 'container-analyze' => 'Error-Watch · analyze',
            'container-remediate' => 'Error-Watch · remediate',
        ];
        return $m[$slug] ?? 'n8n registry';
    }

    // Low-level: ask the Portal for this install's flows. Returns ['ok','error','j'] (no DB writes).
    function _nm_n8n_flows_portal($conn): array {
        if (!($conn instanceof mysqli)) return ['ok' => false, 'error' => 'no db'];
        require_once __DIR__ . '/nm_license.php';    // nm_lic_api_base / nm_lic_row / nm_lic_fingerprint
        $base = function_exists('nm_lic_api_base') ? nm_lic_api_base($conn) : '';
        if ($base === '') return ['ok' => false, 'error' => 'Portal API URL not configured'];
        $row = function_exists('nm_lic_row') ? nm_lic_row($conn) : null;
        $lic = is_array($row) ? (string)($row['license_key'] ?? '') : '';
        $fp  = function_exists('nm_lic_fingerprint') ? nm_lic_fingerprint() : '';
        $ai  = nm_n8n_ai_conn($conn);
        $ver = is_file(__DIR__ . '/VERSION') ? trim((string)@file_get_contents(__DIR__ . '/VERSION')) : '';
        $body = json_encode([
            'license_key' => $lic, 'fingerprint' => $fp, 'conn_key' => $ai['conn_key'],
            'wg_ip'       => preg_replace('#^https?://#', '', $ai['public_base']),
            'public_base' => $ai['public_base'], 'product' => 'neuru', 'version' => $ver,
        ]);
        $ch = curl_init(rtrim($base, '/') . '/v1/flows/sync');
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'], CURLOPT_POSTFIELDS => $body,
            CURLOPT_CONNECTTIMEOUT => 6, CURLOPT_TIMEOUT => 20, CURLOPT_NOSIGNAL => true,
            CURLOPT_CONNECTTIMEOUT_MS => 6000, CURLOPT_TIMEOUT_MS => 20000,
            CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,
            CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => false]);
        $res = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $err = curl_error($ch); curl_close($ch);
        if ($res === false || $code === 0) return ['ok' => false, 'error' => $err ?: 'connection failed'];
        if ($code === 404)                 return ['ok' => false, 'error' => 'Flows sync is not available on the Portal yet.'];
        $j = json_decode($res, true);
        if (!is_array($j))     return ['ok' => false, 'error' => 'Unexpected response from the Portal.'];
        if (empty($j['ok']))   return ['ok' => false, 'error' => (string)($j['error'] ?? ('HTTP ' . $code))];
        return ['ok' => true, 'j' => $j];
    }

    // small nm_settings helpers (generic, mysqli-exception-safe)
    function _nm_set_get($conn, string $k, string $d = ''): string {
        if ($r = @$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='" . $conn->real_escape_string($k) . "' LIMIT 1"))
            if ($x = $r->fetch_row()) return (string)$x[0];
        return $d;
    }
    function _nm_set_put($conn, string $k, string $v): void {
        try { if ($s = $conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)")) {
            $s->bind_param('ss', $k, $v); $s->execute(); $s->close(); } } catch (\Throwable $e) {}
    }

    // PREVIEW (no writes): the flows this install is entitled to + where each one would land + whether a
    // LOCAL url already exists there. The UI shows this as a checklist so the customer PICKS what to sync
    // (nothing is applied until they choose). Pre-checks the flows they selected last time.
    function nm_n8n_flows_fetch($conn): array {
        $r = _nm_n8n_flows_portal($conn);
        if (empty($r['ok'])) return ['ok' => false, 'error' => $r['error'] ?? 'fetch failed'];
        $j = $r['j']; nm_n8n_flows_ensure($conn);
        $targets = nm_n8n_flow_targets();
        $sel = json_decode(_nm_set_get($conn, 'flows_selected', '[]'), true); if (!is_array($sel)) $sel = [];
        $selSet = array_flip(array_map('strval', $sel));
        // current per-feature key values (to warn "you already have a local URL here")
        $curVals = [];
        if ($targets) {
            $inList = "'" . implode("','", array_map([$conn, 'real_escape_string'], array_values($targets))) . "'";
            if ($cr = @$conn->query("SELECT setting_key,setting_val FROM nm_settings WHERE setting_key IN ($inList)"))
                while ($cx = $cr->fetch_assoc()) $curVals[$cx['setting_key']] = (string)$cx['setting_val'];
        }
        $out = [];
        foreach ((is_array($j['flows'] ?? null) ? $j['flows'] : []) as $f) {
            $slug = trim((string)($f['slug'] ?? '')); if ($slug === '') continue;
            $url  = (string)($f['url'] ?? '');        if ($url  === '') continue;
            $tk   = $targets[$slug] ?? '';
            $out[] = [
                'slug'          => $slug,
                'name'          => (string)($f['name'] ?? $slug),
                'description'   => (string)($f['description'] ?? ''),
                'category'      => (string)($f['category'] ?? ''),
                'active'        => !empty($f['active']),
                'target'        => nm_n8n_flow_label($slug),
                'module_key'    => $tk,
                'local_present' => ($tk !== '' && ($curVals[$tk] ?? '') !== ''),
                'local_url'     => $tk !== '' ? ($curVals[$tk] ?? '') : '',
                'selected'      => isset($selSet[$slug]),
                'model'         => nm_n8n_flow_model($conn, $slug),   // the model this flow is set to pay for
            ];
        }
        $gw = is_array($j['gateway'] ?? null) ? $j['gateway'] : [];
        return ['ok' => true, 'flows' => $out,
            'gateway_available'     => (!empty($gw['conn_key']) || !empty($gw['vkey'])),
            'gateway_local_present' => (_nm_set_get($conn, 'ai_conn_key') !== '' || _nm_set_get($conn, 'ai_gateway_vkey') !== ''),
            'available_models'      => (is_array($j['available_models'] ?? null) ? $j['available_models'] : []),
            'default_model'         => nm_n8n_flow_model($conn),
            'plan' => (string)($j['subscription']['plan'] ?? ''), 'status' => (string)($j['subscription']['status'] ?? '')];
    }

    // APPLY only the flows the customer CHOSE (+ optionally the AI Gateway creds). Explicit choice wins:
    // a selected flow's hosted URL is written to the registry AND its module key (overwriting whatever was
    // there — the user asked for it). Unpicked flows are left untouched. The selection is remembered so the
    // scheduled sync keeps exactly those fresh (and never "spreads" the ones you didn't pick).
    function nm_n8n_flows_apply($conn, array $slugs, bool $do_gateway = true, array $models = []): array {
        // remember the per-flow model choices (slug => model) so nm_n8n_call/readers inject _neuru.model
        if ($models) {
            $cur = json_decode(_nm_set_get($conn, 'ai_flow_models', '{}'), true); if (!is_array($cur)) $cur = [];
            foreach ($models as $slug => $m) { $slug = (string)$slug; $m = (string)$m; if ($slug !== '' && $m !== '') $cur[$slug] = $m; }
            _nm_set_put($conn, 'ai_flow_models', json_encode($cur));
        }
        $r = _nm_n8n_flows_portal($conn);
        if (empty($r['ok'])) return ['ok' => false, 'error' => $r['error'] ?? 'apply failed'];
        $j = $r['j']; nm_n8n_flows_ensure($conn);
        $targets = nm_n8n_flow_targets();
        $want = array_flip(array_map('strval', $slugs));

        $applied = 0; $routed = 0; $managedNow = []; $schedMap = [];
        $tset = $conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
        if ($up = $conn->prepare("INSERT INTO nm_n8n_webhooks (name,slug,url,method,description,enabled,source)
                VALUES (?,?,?,?,?,?, 'portal')
                ON DUPLICATE KEY UPDATE name=VALUES(name), url=VALUES(url), method=VALUES(method),
                description=VALUES(description), enabled=VALUES(enabled), source='portal'")) {
            foreach ((is_array($j['flows'] ?? null) ? $j['flows'] : []) as $f) {
                // Register a flow if the customer selected it OR it's a SYSTEM flow (Portal-flagged
                // background flows like anomaly-learn/detect that feed AI Insights) — those must land on
                // EVERY install, free, regardless of the picker/bundle, so the feature is universal.
                $slug = trim((string)($f['slug'] ?? '')); if ($slug === '' || (!isset($want[$slug]) && empty($f['system']))) continue;
                $url  = (string)($f['url'] ?? '');        if ($url  === '') continue;
                if (((int)($f['schedule_minutes'] ?? 0)) > 0) $schedMap[$slug] = (int)$f['schedule_minutes'];   // owner-set cadence → cron_flows.php fires it
                $name = (string)($f['name'] ?? $slug);
                $method = (strtoupper((string)($f['method'] ?? 'POST')) === 'GET') ? 'GET' : 'POST';
                $desc = (string)($f['description'] ?? '');
                $en   = 1;   // the user explicitly selected it → enable it
                $up->bind_param('sssssi', $name, $slug, $url, $method, $desc, $en);   // 6 params
                try { if ($up->execute()) $applied++; } catch (\Throwable $e) {}
                if ($tset && isset($targets[$slug])) {                 // route to the module's own key too
                    $tk = $targets[$slug];
                    $tset->bind_param('ss', $tk, $url);                // 2 params
                    try { if ($tset->execute()) { $routed++; $managedNow[$tk] = 1; } } catch (\Throwable $e) {}
                }
            }
            $up->close();
        }
        if ($tset) $tset->close();

        // F1 — consume the portal's revoked[] : disable any PORTAL-managed webhook + blank its module
        // key for flows the customer is no longer entitled to (downgrade / cancel / lost per-flow).
        // Only source='portal' rows are touched — the user's own manual webhooks are never disabled.
        $disabled = 0;
        $revoked = is_array($j['revoked'] ?? null) ? $j['revoked'] : [];
        if ($revoked) {
            $dis = $conn->prepare("UPDATE nm_n8n_webhooks SET enabled=0 WHERE slug=? AND source='portal' AND enabled=1");
            $bkk = $conn->prepare("UPDATE nm_settings SET setting_val='' WHERE setting_key=? AND setting_val<>''");
            foreach ($revoked as $rs) {
                $rs = trim((string)$rs); if ($rs === '' || isset($want[$rs])) continue;   // never disable one we just (re)applied
                if ($dis) { $dis->bind_param('s', $rs); try { if ($dis->execute() && $conn->affected_rows > 0) $disabled++; } catch (\Throwable $e) {} }
                if ($bkk && isset($targets[$rs])) { $tk = $targets[$rs]; $bkk->bind_param('s', $tk); try { $bkk->execute(); } catch (\Throwable $e) {} }
            }
            if ($dis) $dis->close(); if ($bkk) $bkk->close();
        }

        // merge the module keys we now manage into the tracked set
        $managed = json_decode(_nm_set_get($conn, 'ai_flow_managed_keys', '[]'), true); if (!is_array($managed)) $managed = [];
        foreach ($managed as $mk) $managedNow[(string)$mk] = 1;
        _nm_set_put($conn, 'ai_flow_managed_keys', json_encode(array_keys($managedNow)));

        if (!empty($j['n8n_base'])) { try { nm_n8n_set($conn, 'n8n_base_url', (string)$j['n8n_base']); } catch (\Throwable $e) {} }

        // AI Gateway creds (conn_key + vkey) — only if the customer opted in (do_gateway).
        $gwApplied = 0;
        if ($do_gateway) {
            $gw = is_array($j['gateway'] ?? null) ? $j['gateway'] : [];
            if (!empty($gw['conn_key']))    { _nm_set_put($conn, 'ai_conn_key',     (string)$gw['conn_key']); $gwApplied++; }
            if (!empty($gw['vkey']))        { _nm_set_put($conn, 'ai_gateway_vkey', (string)$gw['vkey']);     $gwApplied++; }
            if (!empty($gw['public_base'])) { _nm_set_put($conn, 'ai_public_base',  rtrim((string)$gw['public_base'], '/')); }
        }

        // remember the selection so the scheduled sync refreshes EXACTLY these (never spreads the rest)
        _nm_set_put($conn, 'flows_selected', json_encode(array_values(array_map('strval', $slugs))));
        _nm_set_put($conn, 'flow_schedule', json_encode($schedMap));   // {slug:minutes} for cron_flows.php (owner-set in the VIP)
        $sum = json_encode(['applied' => $applied, 'routed' => $routed, 'gateway' => $gwApplied,
            'disabled' => $disabled, 'selected' => count($slugs), 'at' => date('c'),
            'plan' => (string)($j['subscription']['plan'] ?? ''), 'status' => (string)($j['subscription']['status'] ?? '')]);
        _nm_set_put($conn, 'flows_synced', $sum);

        return ['ok' => true, 'applied' => $applied, 'routed' => $routed, 'gateway' => $gwApplied,
            'disabled' => $disabled, 'selected' => count($slugs), 'plan' => (string)($j['subscription']['plan'] ?? ''),
            'status' => (string)($j['subscription']['status'] ?? '')];
    }

    // CRON / on-demand entry point. A BUNDLE subscription entitles the customer to EVERY hosted flow,
    // so we wire them ALL straight from the Portal (official URLs) — nothing is ever left on a stale or
    // manual URL, and a flow the Portal adds later auto-adopts on the next sync. A per-flow (non-bundle)
    // customer keeps the explicit picker: apply exactly their selection, minus anything the Portal no
    // longer offers. If the Portal is unreachable, fall back to the last known selection (offline-safe).
    function nm_n8n_flows_sync($conn): array {
        if (!($conn instanceof mysqli)) return ['ok' => false, 'error' => 'no db'];
        $r = _nm_n8n_flows_portal($conn);
        if (!empty($r['ok'])) {
            $j       = $r['j'];
            $offered = array_values(array_filter(array_map(fn($f) => (string)($f['slug'] ?? ''), is_array($j['flows'] ?? null) ? $j['flows'] : [])));
            $bundle  = strtolower((string)($j['subscription']['plan'] ?? '')) === 'bundle';
            if ($bundle && $offered) return nm_n8n_flows_apply($conn, $offered, true);   // take EVERYTHING official
            $sel = json_decode(_nm_set_get($conn, 'flows_selected', '[]'), true);
            $keep = (is_array($sel) && $sel) ? array_values(array_intersect(array_map('strval', $sel), $offered)) : [];
            if ($keep) return nm_n8n_flows_apply($conn, $keep, true);
            return ['ok' => true, 'applied' => 0, 'note' => 'no entitled flows to apply'];
        }
        // Portal unreachable → refresh only what was last chosen (never auto-applies without prior consent).
        $sel = json_decode(_nm_set_get($conn, 'flows_selected', '[]'), true);
        if (!is_array($sel) || !$sel) return ['ok' => true, 'applied' => 0, 'note' => 'no flows selected yet'];
        return nm_n8n_flows_apply($conn, $sel, true);
    }

    // Constant-time check of an inbound token presented by n8n.
    function nm_n8n_verify_inbound($conn, ?string $presented): bool {
        $presented = (string)$presented;
        if ($presented === '') return false;
        $cfg = nm_n8n_get($conn);
        $stored = (string)$cfg['inbound_token'];
        if ($stored === '') return false;
        return hash_equals($stored, $presented);
    }

    function nm_n8n_webhooks($conn, bool $only_enabled = false): array {
        if (!($conn instanceof mysqli)) return [];
        $w = $only_enabled ? ' WHERE enabled=1' : '';
        $r = @$conn->query("SELECT id,name,slug,url,method,description,enabled FROM nm_n8n_webhooks{$w} ORDER BY name");
        return $r ? $r->fetch_all(MYSQLI_ASSOC) : [];
    }

    function nm_n8n_webhook_by_slug($conn, string $slug): ?array {
        if (!($conn instanceof mysqli)) return null;
        $st = $conn->prepare("SELECT id,name,slug,url,method,enabled FROM nm_n8n_webhooks WHERE slug=? LIMIT 1");
        $st->bind_param('s', $slug); $st->execute();
        $row = $st->get_result()->fetch_assoc(); $st->close();
        return $row ?: null;
    }

    // The _neuru block a hosted/shared Portal flow needs to (a) PASS its gatecheck (conn_key), (b) METER
    // the LLM to this customer (vkey), and (c) CALL BACK into THIS NEURU (callback_base + token). Empty if
    // this install isn't enrolled on the Portal (self-hosted → no _neuru, zero change). Reused by
    // nm_n8n_call AND — crucially — by every module that curls a hosted flow URL DIRECTLY (Router
    // Commander / Copilot KB / Archaeologist / SmokePing / NetFlow / Weather / Containers-fix …) so those
    // stop failing the gatecheck with {"ok":false,"reason":"unknown_connection"}.
    function nm_n8n_neuru_block($conn): array {
        $ai = nm_n8n_ai_conn($conn);
        if ($ai['vkey'] === '' && $ai['conn_key'] === '') return [];   // not enrolled → nothing
        $cfg = nm_n8n_get($conn);
        $cb = $ai['public_base'];
        if ($cb === '') {
            $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
            $cb = !empty($_SERVER['HTTP_HOST']) ? $scheme . '://' . $_SERVER['HTTP_HOST'] : '';
        }
        return [
            'conn_key'       => $ai['conn_key'],
            'vkey'           => $ai['vkey'],
            'callback_base'  => rtrim($cb, '/'),
            'callback_token' => (string)$cfg['inbound_token'],
        ];
    }
    // The LLM model this customer chose to PAY FOR on a given flow (they pick per-flow in the picker).
    // Stored as ai_flow_models = {slug: model}; falls back to ai_default_model, then gpt-4o-mini. The
    // hosted flow's model node reads it as {{ _neuru.model }}. Must be one of the Portal's available_models.
    // DEFAULT IS THE CHEAP MODEL ON PURPOSE: an unconfigured flow must never silently pass the priciest
    // model (gpt-4o ≈ 10× gpt-4o-mini). The customer's explicit per-flow / ai_default_model choice wins.
    function nm_n8n_flow_model($conn, string $slug = ''): string {
        $def = _nm_set_get($conn, 'ai_default_model', 'gpt-4o-mini'); if ($def === '') $def = 'gpt-4o-mini';
        if ($slug === '') return $def;
        $map = json_decode(_nm_set_get($conn, 'ai_flow_models', '{}'), true);
        return (is_array($map) && !empty($map[$slug])) ? (string)$map[$slug] : $def;
    }
    // Stamp a payload with the _neuru block (+ the per-flow model). Modules call this right before they
    // json_encode + curl a flow URL. Pass the flow URL so we ONLY stamp HOSTED flows (tunnel 10.88.x) — a
    // LOCAL n8n flow must get a clean payload (no metered creds). Pass the slug for the per-flow model.
    function nm_n8n_neuru_stamp($conn, array $payload, string $flow_url = '', string $slug = ''): array {
        if ($flow_url !== '' && !preg_match('#^https?://10\.88\.\d{1,3}\.\d{1,3}\b#', $flow_url)) return $payload;  // local n8n → clean
        $b = nm_n8n_neuru_block($conn);
        if ($b) {
            $b['model'] = nm_n8n_flow_model($conn, $slug);
            // Groundwork for per-flow spend attribution: expose the flow slug so a hosted flow can
            // forward it to LiteLLM as metadata/tags/user (spend_logs_metadata). Until the flow nodes
            // forward it, this is inert (unknown _neuru fields are ignored by flows). Portal reads it
            // from /spend/logs to break the ledger down BY FLOW instead of a bare "Metered usage".
            if ($slug !== '') $b['flow'] = $slug;
            $payload['_neuru'] = $b;
        }
        return $payload;
    }

    // The base URL a flow uses to CALL BACK into THIS NEURU with results (result_url/findings_url/…).
    // MUST be chosen PER-FLOW so BOTH options keep working:
    //   • HOSTED flow (its URL is on the WG tunnel subnet 10.88.x) → the hosted n8n can only reach us at
    //     our tunnel IP → use ai_public_base.
    //   • LOCAL n8n (a LAN URL) → it reaches us on the LAN → use n8n_portal_base or $_SERVER (browsed URL).
    // Pass the flow's own URL so we pick right. Omitting it falls back to the local/self-hosted base.
    function nm_n8n_callback_base($conn, string $flow_url = ''): string {
        $hosted = ($flow_url !== '' && preg_match('#^https?://10\.88\.\d{1,3}\.\d{1,3}\b#', $flow_url));
        if ($hosted) {
            $ai = nm_n8n_ai_conn($conn);
            if (!empty($ai['public_base'])) return rtrim((string)$ai['public_base'], '/');
        }
        $cfg = nm_n8n_get($conn);
        if (!empty($cfg['portal_base'])) return rtrim((string)$cfg['portal_base'], '/');
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        return (!empty($_SERVER['HTTP_HOST'])) ? $scheme . '://' . $_SERVER['HTTP_HOST'] : 'http://localhost';
    }

    // OUTBOUND: fire a configured webhook by slug with a JSON payload. The portal's
    // inbound token is also sent so the flow can call back authenticated.
    // Returns [httpcode, decoded|raw, err].
    function nm_n8n_call($conn, string $slug, array $payload = [], int $timeout = 25): array {
        $wh = nm_n8n_webhook_by_slug($conn, $slug);
        if (!$wh)              return [0, null, "Webhook '{$slug}' not found"];
        if (!$wh['enabled'])   return [0, null, "Webhook '{$slug}' is disabled"];
        $cfg = nm_n8n_get($conn);
        $payload['_netmon'] = ['ts' => date('c'), 'slug' => $slug];
        // AI Gateway (NEURU AI Flows): hand the hosted/shared flow the metered vkey + tenant conn_key +
        // callback coordinates (see nm_n8n_neuru_block). Per-flow: only when this webhook is a hosted URL.
        $payload = nm_n8n_neuru_stamp($conn, $payload, (string)($wh['url'] ?? ''), $slug);
        $method = strtoupper($wh['method'] ?: 'POST');
        $url = $wh['url'];
        $ch  = curl_init();
        $headers = ['Accept: application/json', 'X-NetMon-Token: ' . $cfg['inbound_token']];
        if ($method === 'POST') {
            $headers[] = 'Content-Type: application/json';
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
        } else {
            $url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($payload);
        }
        curl_setopt_array($ch, [
            CURLOPT_URL => $url, CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 4, CURLOPT_TIMEOUT => max(2, $timeout),
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => false,
        ]);
        $body = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $cerr = curl_error($ch);
        curl_close($ch);
        if ($body === false) return [0, null, $cerr ?: 'Connection failed'];
        $json = json_decode($body, true);
        return [$code, $json ?? $body, $code >= 400 ? ('HTTP ' . $code) : null];
    }
}
