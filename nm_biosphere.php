<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Service Biosphere engine (F: services as living organisms · Phase 1).
// Each monitored service (DNS / HTTP / SQL / SMTP) is probed over PHP sockets — no
// new binaries — and rendered as a living 3D cell whose membrane pulses/infects/
// sludges/freezes on REAL protocol vitals (the Hologram "truthful visuals" rule).
// Reuses: Data Core (nm_dbmon) for SQL, Pi-hole (nm_pihole) for DNS stats, and
// Immunity + incident correlation for the symbiosis/promote loop.
//
// Constraints honored: mysqli EXCEPTION mode → CREATE TABLE IF NOT EXISTS + guarded
// ALTERs + best-effort (try/catch) sample writes so one bad write never 500s a page.
// Secrets stay per-install (.nm_secret.key); crons run over HTTP as www-data so
// SQL/SSH creds decrypt. RBAC perm: 'biosphere'. Read-mostly; the LLM never executes.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_bio_ensure')) {

require_once __DIR__ . '/nm_dbmon.php';   // SQL metabolic probe reuses the Data Core monitor
// nm_pihole.php / nm_immunity.php are pulled in lazily inside the functions that need them.

// ── schema ───────────────────────────────────────────────────────────────────
function nm_bio_ensure($conn): void {
    static $done = false; if ($done) return; $done = true;

    $conn->query("CREATE TABLE IF NOT EXISTS nm_bio_services (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(120) NOT NULL,
        kind VARCHAR(16) NOT NULL DEFAULT 'http',      /* dns|http|sql|smtp|generic */
        target VARCHAR(255) NULL,                       /* host/ip or full URL      */
        port INT NULL,
        params TEXT NULL,                               /* JSON: probe_name,url,expect_code,match,ehlo… */
        db_target_id INT NULL,                          /* → nm_db_targets (sql)    */
        pihole_id INT NULL,                             /* → nm_pihole_servers (dns) */
        node_id INT NULL,                               /* → nm_nodes (location)     */
        enabled TINYINT NOT NULL DEFAULT 1,
        last_ok TINYINT NULL,
        last_level VARCHAR(12) NULL,
        last_checked DATETIME NULL,
        created_by INT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $conn->query("CREATE TABLE IF NOT EXISTS nm_bio_samples (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        service_id INT NOT NULL,
        ts DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        ok TINYINT NOT NULL DEFAULT 0,
        latency_ms DOUBLE NULL,
        err_rate DOUBLE NULL,
        throughput DOUBLE NULL,
        cache_hit DOUBLE NULL,
        score INT NULL,
        level VARCHAR(12) NULL,
        extra TEXT NULL,                                /* JSON kind-specific vitals */
        KEY k_svc_ts (service_id, ts)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $conn->query("CREATE TABLE IF NOT EXISTS nm_bio_links (
        id INT AUTO_INCREMENT PRIMARY KEY,
        from_service INT NOT NULL,
        to_service INT NOT NULL,
        kind VARCHAR(12) NOT NULL DEFAULT 'depends',    /* depends|feeds */
        source VARCHAR(12) NOT NULL DEFAULT 'manual',   /* manual|inferred|incident */
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY u_edge (from_service, to_service)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $conn->query("CREATE TABLE IF NOT EXISTS nm_bio_flags (
        id INT AUTO_INCREMENT PRIMARY KEY,
        service_id INT NULL,
        kind VARCHAR(24) NOT NULL,                      /* dga|slow_query|ux_break|deadlock|… */
        indicator VARCHAR(255) NULL,
        severity VARCHAR(12) NOT NULL DEFAULT 'medium',
        detail TEXT NULL,
        status VARCHAR(12) NOT NULL DEFAULT 'open',      /* open|resolved|promoted */
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // P3 — synthetic-persona journey results (headless browser runs in n8n; portal stores + visualizes)
    $conn->query("CREATE TABLE IF NOT EXISTS nm_bio_synthetic (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        service_id INT NOT NULL,
        ts DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        ok TINYINT NOT NULL DEFAULT 0,
        vct_ms DOUBLE NULL,                              /* Visual Completeness Time */
        total_ms DOUBLE NULL,
        steps_total INT NULL,
        steps_ok INT NULL,
        broken_step VARCHAR(160) NULL,
        console_errors INT NULL,
        screenshot MEDIUMTEXT NULL,                       /* optional data: URI thumbnail */
        detail TEXT NULL,                                 /* JSON: per-step [{name,ok,ms}] + notes */
        KEY k_svc_ts (service_id, ts)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // P2 — two-way Telegram approvals for SQL "Auto-Tune" (reuses the aiopilot bot + poller)
    $conn->query("CREATE TABLE IF NOT EXISTS nm_bio_tg_approvals (
        id INT AUTO_INCREMENT PRIMARY KEY,
        kind VARCHAR(16) NOT NULL DEFAULT 'autotune',
        ref_id INT NOT NULL,                             /* → nm_db_advice.id */
        service_id INT NULL,
        token VARCHAR(40) NOT NULL,
        chat_msg_id BIGINT NULL,
        detail VARCHAR(255) NULL,
        status VARCHAR(12) NOT NULL DEFAULT 'pending',    /* pending|approved|denied|expired */
        created_by INT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        decided_at DATETIME NULL,
        UNIQUE KEY u_ref (kind, ref_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Auto-register the outbound 'bio-dns-audit' webhook (disabled, empty URL) so it shows up
    // pre-listed in Config → Integrations & AI with a self-explaining description. INSERT IGNORE =
    // never overwrites the operator's URL/enabled once they configure it. ('db-advisor' is reused
    // from Data Core and is NOT re-seeded here.)
    $wh = $conn->query("SHOW TABLES LIKE 'nm_n8n_webhooks'");
    if ($wh && $wh->num_rows) {
        $conn->query("INSERT IGNORE INTO nm_n8n_webhooks (name,slug,url,method,description,enabled)
                      VALUES ('Biosphere DNS Audit','bio-dns-audit','','POST',
                      'Auto-added by NEURU (Service Biosphere). To activate: paste your n8n URL http://<n8n>:5678/webhook/bio-dns-audit and tick Enabled. It classifies unusual resolved domains and returns verdicts {domain,verdict,score,reason}; high scores auto-block via Collective Immunity. See docs/N8N_BIOSPHERE.md.',0)");
        $conn->query("INSERT IGNORE INTO nm_n8n_webhooks (name,slug,url,method,description,enabled)
                      VALUES ('Biosphere HTTP Synthetic','bio-http-synthetic','','POST',
                      'Auto-added by NEURU (Service Biosphere · P3). To activate: paste your n8n URL http://<n8n>:5678/webhook/bio-http-synthetic and tick Enabled. It runs a headless-browser journey (login+click+assert), measures Visual Completeness Time, and returns {ok,vct_ms,steps[],broken_step,screenshot}. See docs/N8N_BIOSPHERE.md.',0)");
    }

    // RBAC seed
    $conn->query("INSERT IGNORE INTO role_profiles (role_name, button_key, enabled) VALUES ('admin','biosphere',1)");
}

// ── settings (nm_settings key/val, best-effort) ──────────────────────────────
function nm_bio_settings($conn): array {
    $get = function($k, $d) use ($conn) {
        $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='" . $conn->real_escape_string($k) . "' LIMIT 1");
        if ($r && $r->num_rows) { $v = $r->fetch_assoc()['setting_val']; if ($v !== '' && $v !== null) return $v; }
        return $d;
    };
    return [
        'enabled'      => (int)$get('bio_enabled', '1'),
        'poll_sec'     => max(5,  (int)$get('bio_poll_sec', '20')),
        'sample_days'  => max(1,  (int)$get('bio_sample_days', '7')),
        'dns_audit'    => (int)$get('bio_dns_audit', '0'),
        'dns_limit'    => max(1, min(500, (int)$get('bio_dns_limit', '40'))), // domains per audit dispatch
        'dns_min'      => max(1, (int)$get('bio_dns_min', '30')),      // minutes between DNS audits
        'dga_promote'  => max(50, (int)$get('bio_dga_promote', '85')), // AI score ≥ → auto fleet-block
        'synthetic'    => (int)$get('bio_synthetic', '0'),             // P3: run headless journeys
        'synth_min'    => max(1,  (int)$get('bio_synth_min', '5')),    // minutes between journey runs
        'vct_warn'     => max(1,  (int)$get('bio_vct_warn', '2500')),  // ms VCT → UX stress
        'lat_warn'     => max(1,  (int)$get('bio_lat_warn', '120')),   // ms → membrane starts swelling
        'lat_crit'     => max(1,  (int)$get('bio_lat_crit', '400')),   // ms → sick
    ];
}
function nm_bio_set($conn, string $k, string $v): void {
    try {
        $st = $conn->prepare("INSERT INTO nm_settings (setting_key, setting_val) VALUES (?,?)
                              ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
        $st->bind_param('ss', $k, $v); $st->execute(); $st->close();
    } catch (\Throwable $e) { /* best-effort */ }
}

// ── service CRUD ──────────────────────────────────────────────────────────────
function nm_bio_services($conn, bool $onlyEnabled = false): array {
    nm_bio_ensure($conn);
    $out = [];
    $w = $onlyEnabled ? 'WHERE s.enabled=1' : '';
    $r = $conn->query("SELECT s.*, n.display_name node_name, n.ip_address node_ip
                       FROM nm_bio_services s LEFT JOIN nm_nodes n ON n.id=s.node_id
                       $w ORDER BY s.kind, s.name");
    while ($r && $x = $r->fetch_assoc()) {
        $x['params_arr'] = $x['params'] ? (json_decode($x['params'], true) ?: []) : [];
        $out[] = $x;
    }
    return $out;
}
function nm_bio_service($conn, int $id): ?array {
    nm_bio_ensure($conn);
    $r = $conn->query("SELECT * FROM nm_bio_services WHERE id=" . (int)$id . " LIMIT 1");
    $x = $r ? $r->fetch_assoc() : null;
    if ($x) $x['params_arr'] = $x['params'] ? (json_decode($x['params'], true) ?: []) : [];
    return $x ?: null;
}
function nm_bio_service_save($conn, array $d, ?int $uid = null): array {
    nm_bio_ensure($conn);
    $id     = (int)($d['id'] ?? 0);
    $name   = trim((string)($d['name'] ?? ''));
    $kind   = in_array($d['kind'] ?? '', ['dns','http','sql','smtp','generic'], true) ? $d['kind'] : 'http';
    if ($name === '') return ['ok' => false, 'error' => 'Name required'];
    $target = trim((string)($d['target'] ?? '')) ?: null;
    $port   = ($d['port'] ?? '') !== '' ? (int)$d['port'] : null;
    $dbt    = ($d['db_target_id'] ?? '') !== '' ? (int)$d['db_target_id'] : null;
    $phid   = ($d['pihole_id'] ?? '') !== '' ? (int)$d['pihole_id'] : null;
    $node   = ($d['node_id'] ?? '') !== '' ? (int)$d['node_id'] : null;
    $en     = !empty($d['enabled']) ? 1 : 0;
    $params = isset($d['params']) && is_array($d['params']) ? json_encode($d['params']) : (string)($d['params'] ?? '');
    if ($params === '') $params = null;
    if ($kind === 'sql' && !$dbt)    return ['ok' => false, 'error' => 'SQL service needs a Data Core target'];
    if ($kind !== 'sql' && !$target) return ['ok' => false, 'error' => 'Target host/URL required'];

    try {
        if ($id > 0) {
            $st = $conn->prepare("UPDATE nm_bio_services SET name=?,kind=?,target=?,port=?,params=?,
                                  db_target_id=?,pihole_id=?,node_id=?,enabled=? WHERE id=?");
            $st->bind_param('sssisiiiii', $name, $kind, $target, $port, $params, $dbt, $phid, $node, $en, $id);
            $st->execute(); $st->close();
        } else {
            $st = $conn->prepare("INSERT INTO nm_bio_services (name,kind,target,port,params,db_target_id,pihole_id,node_id,enabled,created_by)
                                  VALUES (?,?,?,?,?,?,?,?,?,?)");
            $st->bind_param('sssisiiiii', $name, $kind, $target, $port, $params, $dbt, $phid, $node, $en, $uid);
            $st->execute(); $id = $st->insert_id; $st->close();
        }
    } catch (\Throwable $e) { return ['ok' => false, 'error' => $e->getMessage()]; }
    return ['ok' => true, 'id' => $id];
}
function nm_bio_service_delete($conn, int $id): array {
    nm_bio_ensure($conn);
    try {
        $conn->query("DELETE FROM nm_bio_services WHERE id=" . (int)$id);
        $conn->query("DELETE FROM nm_bio_samples  WHERE service_id=" . (int)$id);
        $conn->query("DELETE FROM nm_bio_links     WHERE from_service=" . (int)$id . " OR to_service=" . (int)$id);
    } catch (\Throwable $e) { return ['ok' => false, 'error' => $e->getMessage()]; }
    return ['ok' => true];
}

// ─────────────────────────────────────────────────────────────────────────────
//  PROBES — pure, socket-based, no new binaries. Each returns a normalized sample:
//  ['ok','latency_ms','err_rate','throughput','cache_hit','extra'=>[…kind vitals]]
// ─────────────────────────────────────────────────────────────────────────────
function nm_bio_probe($conn, array $svc): array {
    switch ($svc['kind']) {
        case 'dns':  return nm_bio_probe_dns($conn, $svc);
        case 'http': return nm_bio_probe_http($svc);
        case 'sql':  return nm_bio_probe_sql($conn, $svc);
        case 'smtp': return nm_bio_probe_smtp($svc);
        default:     return nm_bio_probe_generic($svc);
    }
}

// DNS — craft a minimal A-record query, send UDP to target:53, measure resolution ms + rcode.
function nm_bio_probe_dns($conn, array $svc): array {
    $host = (string)$svc['target']; $port = (int)($svc['port'] ?: 53);
    $p    = $svc['params_arr'] ?? [];
    $name = trim((string)($p['probe_name'] ?? 'cloudflare.com')) ?: 'cloudflare.com';
    $r    = nm_bio_dns_query($host, $port, $name, 3.0);
    $extra = ['probe_name' => $name, 'rcode' => $r['rcode'], 'answers' => $r['answers']];

    // If linked to a Pi-hole, enrich with server-side cache-hit / block ratios (best-effort).
    $cacheHit = null;
    if (!empty($svc['pihole_id'])) {
        if (is_file(__DIR__ . '/nm_pihole.php')) require_once __DIR__ . '/nm_pihole.php';
        if (function_exists('nm_ph_call')) {
            try {
                $st = nm_ph_call($conn, (int)$svc['pihole_id'], 'stats/summary', []);
                if (!empty($st['ok']) && is_array($st['data'])) {
                    $q  = $st['data']['queries'] ?? [];
                    $tot = (float)($q['total'] ?? 0);
                    $ch  = (float)($q['cached'] ?? 0);
                    $bl  = (float)($q['blocked'] ?? 0);
                    if ($tot > 0) { $cacheHit = round($ch / $tot * 100, 1); $extra['blocked_pct'] = round($bl / $tot * 100, 1); }
                    $extra['pihole'] = true;
                }
            } catch (\Throwable $e) { /* Pi-hole optional */ }
        }
    }
    $ok = $r['ok'] && $r['rcode'] !== 2;   // SERVFAIL(2) = unhealthy; NXDOMAIN(3) still "responding"
    return ['ok' => $ok ? 1 : 0, 'latency_ms' => $r['ms'], 'err_rate' => $ok ? 0 : 1,
            'throughput' => $r['answers'], 'cache_hit' => $cacheHit, 'extra' => $extra];
}
// Raw DNS/UDP query builder+parser (A record). Returns ms + rcode + answer count.
function nm_bio_dns_query(string $host, int $port, string $name, float $timeout = 3.0): array {
    $out = ['ok' => false, 'ms' => null, 'rcode' => null, 'answers' => 0];
    if ($host === '') return $out;
    $qid = random_int(0, 0xFFFF);
    $q   = pack('n6', $qid, 0x0100, 1, 0, 0, 0);          // header: RD=1, 1 question
    foreach (explode('.', $name) as $lab) { $lab = substr($lab, 0, 63); $q .= chr(strlen($lab)) . $lab; }
    $q  .= "\x00" . pack('n2', 1, 1);                     // QTYPE=A, QCLASS=IN
    $t0  = microtime(true);
    $fp  = @fsockopen('udp://' . $host, $port, $errno, $errstr, $timeout);
    if (!$fp) { $out['ms'] = round((microtime(true) - $t0) * 1000, 1); return $out; }
    stream_set_timeout($fp, (int)$timeout, (int)(($timeout - (int)$timeout) * 1e6));
    @fwrite($fp, $q);
    $resp = @fread($fp, 2048);
    @fclose($fp);
    $out['ms'] = round((microtime(true) - $t0) * 1000, 1);
    if ($resp === false || strlen($resp) < 12) return $out;
    $h = unpack('nid/nflags/nqd/nan/nns/nar', substr($resp, 0, 12));
    if ((int)$h['id'] !== $qid) return $out;              // stray/spoofed packet
    $out['rcode']   = $h['flags'] & 0x000F;
    $out['answers'] = (int)$h['an'];
    $out['ok']      = true;                               // got a well-formed reply
    return $out;
}

// Human-readable reason for an HTTP status (esp. the Cloudflare 52x/530 family) so the
// Biosphere card explains WHY a service is down instead of a bare "code 530".
function nm_bio_http_reason(int $code, string $err = ''): string {
    if ($code === 0) return $err !== '' ? ('Unreachable — ' . $err) : 'Unreachable / no response';
    $cf = [520=>'Cloudflare 520: unknown origin error',521=>'Cloudflare 521: origin is down',522=>'Cloudflare 522: connection timed out',
           523=>'Cloudflare 523: origin unreachable',524=>'Cloudflare 524: origin timed out',525=>'Cloudflare 525: SSL handshake failed',
           526=>'Cloudflare 526: invalid origin certificate',530=>'Cloudflare 530: no working origin (DNS/tunnel) — the domain is on Cloudflare but nothing is serving it. Check the hostname/tunnel.'];
    if (isset($cf[$code])) return $cf[$code];
    $m = [400=>'Bad request',401=>'Unauthorized (auth required)',403=>'Forbidden (blocked)',404=>'Not found',408=>'Request timeout',
          429=>'Rate limited',500=>'Internal server error',502=>'Bad gateway',503=>'Service unavailable',504=>'Gateway timeout'];
    if (isset($m[$code])) return "HTTP $code — " . $m[$code];
    if ($code >= 200 && $code < 300) return "HTTP $code OK";
    if ($code >= 300 && $code < 400) return "HTTP $code redirect";
    if ($code >= 400 && $code < 500) return "HTTP $code client error";
    if ($code >= 500)               return "HTTP $code server error";
    return "HTTP $code";
}
// HTTP — cURL: status code, TTFB, total ms, size. err_rate = 1 when code≥400 or transport fail.
function nm_bio_probe_http(array $svc): array {
    $p   = $svc['params_arr'] ?? [];
    $url = trim((string)($p['url'] ?? ''));
    if ($url === '') {
        $host = (string)$svc['target']; $port = (int)($svc['port'] ?: 0);
        if (stripos($host, 'http://') === 0 || stripos($host, 'https://') === 0) $url = $host;
        else { $scheme = ($port === 443) ? 'https' : 'http'; $url = $scheme . '://' . $host . ($port && $port != 80 && $port != 443 ? ':' . $port : ''); }
    }
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_NOBODY => false, CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3, CURLOPT_TIMEOUT => 12, CURLOPT_CONNECTTIMEOUT => 6,
        CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_USERAGENT => 'NEURU-Biosphere/1.0', CURLOPT_ENCODING => '',
    ]);
    $body   = curl_exec($ch);
    $code   = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $total  = curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000;
    $ttfb   = curl_getinfo($ch, CURLINFO_STARTTRANSFER_TIME) * 1000;
    $size   = (float)curl_getinfo($ch, CURLINFO_SIZE_DOWNLOAD);
    $err    = curl_error($ch);
    curl_close($ch);
    $transportOk = ($body !== false && $code > 0);
    $expect = (int)($p['expect_code'] ?? 0);
    $codeOk = $expect ? ($code === $expect) : ($code >= 200 && $code < 400);
    $match  = trim((string)($p['match'] ?? ''));
    $matchOk = ($match === '' || ($body !== false && stripos((string)$body, $match) !== false));
    $ok = $transportOk && $codeOk && $matchOk;
    $extra = ['code' => $code, 'ttfb_ms' => round($ttfb, 1), 'size' => $size, 'reason' => nm_bio_http_reason($code, (string)$err)];
    if ($err) $extra['error'] = $err;
    if ($match !== '') $extra['match'] = $matchOk;
    // err class: 5xx/transport = server infection; 4xx = client infection; match miss = ux break
    $errRate = 0.0;
    if (!$transportOk || $code >= 500) $errRate = 1.0;
    elseif ($code >= 400)             $errRate = 0.6;
    elseif (!$matchOk)                $errRate = 0.4;
    return ['ok' => $ok ? 1 : 0, 'latency_ms' => round($total, 1), 'err_rate' => $errRate,
            'throughput' => $size, 'cache_hit' => null, 'extra' => $extra];
}

// SQL — REUSE Data Core: probe() + live() give connections/saturation/locks/slow → metabolic pressure.
function nm_bio_probe_sql($conn, array $svc): array {
    $tid = (int)($svc['db_target_id'] ?? 0);
    $extra = ['db_target_id' => $tid];
    if ($tid <= 0) return ['ok' => 0, 'latency_ms' => null, 'err_rate' => 1, 'throughput' => null, 'cache_hit' => null, 'extra' => $extra + ['error' => 'no target']];
    $tgt = function_exists('nm_db_target') ? nm_db_target($conn, $tid) : null;
    if (!$tgt) return ['ok' => 0, 'latency_ms' => null, 'err_rate' => 1, 'throughput' => null, 'cache_hit' => null, 'extra' => $extra + ['error' => 'target missing']];
    try {
        $mon = nm_db_monitor($conn, $tgt);
        $t0  = microtime(true);
        $p   = $mon->probe();
        $ms  = round((microtime(true) - $t0) * 1000, 1);
        if (empty($p['ok'])) throw new \RuntimeException($p['error'] ?? 'probe failed');
        $conns = (int)($p['connections'] ?? 0); $max = (int)($p['max_connections'] ?? 0);
        $sat   = $max > 0 ? round($conns / $max * 100, 1) : null;
        $tr    = (int)($p['threads_running'] ?? 0);
        $blocked = 0; $slow = 0;
        try { $lv = $mon->live(); $blocked = count($lv['locks'] ?? []); $slow = count($lv['slow'] ?? []); }
        catch (\Throwable $e) { /* live is bonus */ }
        $extra += ['version' => $p['version'] ?? '', 'connections' => $conns, 'max_connections' => $max,
                   'saturation' => $sat, 'threads_running' => $tr, 'blocked' => $blocked, 'slow' => $slow,
                   'engine' => $tgt['engine'] ?? ''];
        // metabolic err_rate: locks (frozen) dominate, then slow (sludge), then conn saturation
        $errRate = 0.0;
        if ($blocked > 0)      $errRate = 1.0;
        elseif ($slow > 0)     $errRate = min(0.8, 0.3 + $slow * 0.1);
        elseif ($sat !== null) $errRate = max(0.0, ($sat - 80) / 20 * 0.5);   // >80% conns → pressure
        return ['ok' => 1, 'latency_ms' => $ms, 'err_rate' => round($errRate, 3),
                'throughput' => $tr, 'cache_hit' => null, 'extra' => $extra];
    } catch (\Throwable $e) {
        return ['ok' => 0, 'latency_ms' => null, 'err_rate' => 1, 'throughput' => null, 'cache_hit' => null,
                'extra' => $extra + ['error' => $e->getMessage()]];
    }
}

// SMTP — socket connect + EHLO, measure banner ms + reachability.
function nm_bio_probe_smtp(array $svc): array {
    $host = (string)$svc['target']; $port = (int)($svc['port'] ?: 25);
    $t0 = microtime(true);
    $fp = @fsockopen($host, $port, $errno, $errstr, 6);
    if (!$fp) return ['ok' => 0, 'latency_ms' => round((microtime(true) - $t0) * 1000, 1), 'err_rate' => 1,
                      'throughput' => null, 'cache_hit' => null, 'extra' => ['error' => $errstr ?: 'connect failed']];
    stream_set_timeout($fp, 6);
    $banner = (string)@fgets($fp, 512);
    @fwrite($fp, "EHLO neuru.local\r\n");
    $ehlo = (string)@fgets($fp, 512);
    @fwrite($fp, "QUIT\r\n"); @fclose($fp);
    $ms = round((microtime(true) - $t0) * 1000, 1);
    $ok = (strpos($banner, '220') === 0);
    return ['ok' => $ok ? 1 : 0, 'latency_ms' => $ms, 'err_rate' => $ok ? 0 : 1, 'throughput' => null,
            'cache_hit' => null, 'extra' => ['banner' => trim(mb_substr($banner, 0, 120)), 'ehlo' => trim(mb_substr($ehlo, 0, 60))]];
}

// generic TCP reachability
function nm_bio_probe_generic(array $svc): array {
    $host = (string)$svc['target']; $port = (int)($svc['port'] ?: 80);
    $t0 = microtime(true);
    $fp = @fsockopen($host, $port, $errno, $errstr, 6);
    $ms = round((microtime(true) - $t0) * 1000, 1);
    if (!$fp) return ['ok' => 0, 'latency_ms' => $ms, 'err_rate' => 1, 'throughput' => null, 'cache_hit' => null, 'extra' => ['error' => $errstr ?: 'connect failed']];
    @fclose($fp);
    return ['ok' => 1, 'latency_ms' => $ms, 'err_rate' => 0, 'throughput' => null, 'cache_hit' => null, 'extra' => ['tcp' => 'open']];
}

// ── health scoring: sample → 0..100 + level(healthy|stressed|sick|critical) ────
function nm_bio_health(array $svc, array $sample, array $set): array {
    if (empty($sample['ok'])) return ['score' => 0, 'level' => 'critical'];
    $score = 100.0;
    $lat = $sample['latency_ms'];
    if ($lat !== null) {
        if ($lat >= $set['lat_crit'])      $score -= 45;
        elseif ($lat >= $set['lat_warn'])  $score -= 22 * (($lat - $set['lat_warn']) / max(1, $set['lat_crit'] - $set['lat_warn']));
    }
    $er = (float)($sample['err_rate'] ?? 0);
    $score -= $er * 55;                                   // infection eats health
    $score = max(0, min(100, (int)round($score)));
    $level = $score >= 80 ? 'healthy' : ($score >= 55 ? 'stressed' : ($score >= 25 ? 'sick' : 'critical'));
    return ['score' => $score, 'level' => $level];
}

// ── the poll (cron): probe each enabled service, store a sample, update service ─
function nm_bio_poll_all($conn, bool $force = false): array {
    nm_bio_ensure($conn);
    $set = nm_bio_settings($conn);
    $poll = (int)$set['poll_sec'];
    $res = [];
    foreach (nm_bio_services($conn, true) as $svc) {
        $sid = (int)$svc['id'];
        // The cron fires every minute, but a service is only re-PROBED once its last sample is older
        // than poll_sec — so POLL INTERVAL actually controls probe cadence (1440s ⇒ every 24 min).
        if (!$force && $poll > 60) {
            $due = $conn->query("SELECT 1 FROM nm_bio_samples WHERE service_id=$sid AND ts > (NOW() - INTERVAL $poll SECOND) LIMIT 1");
            if ($due && $due->num_rows) { $res[$sid] = 'throttled'; continue; }
        }
        try {
            $sm = nm_bio_probe($conn, $svc);
            $hp = nm_bio_health($svc, $sm, $set);
            $extra = isset($sm['extra']) ? json_encode($sm['extra']) : null;
            $sid = (int)$svc['id']; $ok = (int)$sm['ok'];
            $lat = $sm['latency_ms']; $er = $sm['err_rate']; $tp = $sm['throughput']; $chit = $sm['cache_hit'];
            $score = $hp['score']; $level = $hp['level'];
            try {
                $st = $conn->prepare("INSERT INTO nm_bio_samples (service_id,ok,latency_ms,err_rate,throughput,cache_hit,score,level,extra)
                                      VALUES (?,?,?,?,?,?,?,?,?)");
                $st->bind_param('iiddddiss', $sid, $ok, $lat, $er, $tp, $chit, $score, $level, $extra);
                $st->execute(); $st->close();
            } catch (\Throwable $e) { /* best-effort: never let a bad write abort the poll */ }
            try {
                $st = $conn->prepare("UPDATE nm_bio_services SET last_ok=?, last_level=?, last_checked=NOW() WHERE id=?");
                $st->bind_param('isi', $ok, $level, $sid); $st->execute(); $st->close();
            } catch (\Throwable $e) {}
            // P2: SQL cells raise (deduped) metabolic flags when they show real distress
            if ($svc['kind'] === 'sql' && $ok && !empty($sm['extra'])) { try { nm_bio_metabolic_flag($conn, $svc, $sm['extra']); } catch (\Throwable $e) {} }
            $res[$sid] = $level . ($ok ? '' : ' (down)');
        } catch (\Throwable $e) { $res[(int)$svc['id']] = 'error: ' . $e->getMessage(); }
    }
    return $res;
}
function nm_bio_prune($conn): int {
    nm_bio_ensure($conn);
    $days = nm_bio_settings($conn)['sample_days'];
    try { $conn->query("DELETE FROM nm_bio_samples WHERE ts < (NOW() - INTERVAL " . (int)$days . " DAY)"); return $conn->affected_rows; }
    catch (\Throwable $e) { return 0; }
}

// ── symbiosis edges: manual/inferred links + live incident hibernation ─────────
function nm_bio_links($conn): array {
    nm_bio_ensure($conn);
    $out = [];
    $r = $conn->query("SELECT from_service, to_service, kind, source FROM nm_bio_links");
    while ($r && $x = $r->fetch_assoc()) $out[] = ['from' => (int)$x['from_service'], 'to' => (int)$x['to_service'], 'kind' => $x['kind'], 'source' => $x['source']];
    return $out;
}
function nm_bio_link_save($conn, int $from, int $to, string $kind = 'depends'): array {
    nm_bio_ensure($conn);
    if ($from <= 0 || $to <= 0 || $from === $to) return ['ok' => false, 'error' => 'bad edge'];
    $kind = in_array($kind, ['depends','feeds'], true) ? $kind : 'depends';
    try {
        $st = $conn->prepare("INSERT INTO nm_bio_links (from_service,to_service,kind,source) VALUES (?,?,?, 'manual')
                              ON DUPLICATE KEY UPDATE kind=VALUES(kind)");
        $st->bind_param('iis', $from, $to, $kind); $st->execute(); $st->close();
    } catch (\Throwable $e) { return ['ok' => false, 'error' => $e->getMessage()]; }
    return ['ok' => true];
}
function nm_bio_link_delete($conn, int $from, int $to): array {
    nm_bio_ensure($conn);
    try { $st = $conn->prepare("DELETE FROM nm_bio_links WHERE from_service=? AND to_service=?");
        $st->bind_param('ii', $from, $to); $st->execute(); $st->close(); }
    catch (\Throwable $e) { return ['ok' => false, 'error' => $e->getMessage()]; }
    return ['ok' => true];
}

// ── the 3D scene payload ──────────────────────────────────────────────────────
// Each service → vitals + viz knobs the shader maps to: pulse (latency), infection
// (err_rate), sludge (sql slow/saturation), frozen (sql locks). All from REAL data.
function nm_bio_scene($conn): array {
    nm_bio_ensure($conn);
    $set = nm_bio_settings($conn);
    $svcs = nm_bio_services($conn, false);

    // latest sample per service
    $last = [];
    $r = $conn->query("SELECT s1.* FROM nm_bio_samples s1
                       JOIN (SELECT service_id, MAX(id) mid FROM nm_bio_samples GROUP BY service_id) t
                         ON t.mid=s1.id");
    while ($r && $x = $r->fetch_assoc()) $last[(int)$x['service_id']] = $x;

    // P3: latest synthetic-journey result per service (drives the ux / wireframe-clone knob)
    $synth = [];
    $sy = $conn->query("SELECT s1.service_id, s1.ok, s1.vct_ms, s1.steps_total, s1.steps_ok, s1.broken_step FROM nm_bio_synthetic s1
                        JOIN (SELECT service_id, MAX(id) mid FROM nm_bio_synthetic GROUP BY service_id) t ON t.mid=s1.id");
    while ($sy && $x = $sy->fetch_assoc()) $synth[(int)$x['service_id']] = $x;

    // recent vital samples per service → drives the orbiting "galaxy" of orbs around each cell
    // (each orb = one past probe: colour = health level, size = latency, alpha = recency). TRUE signal.
    $orbits = [];
    $ORB_MAX = 24;
    $or = $conn->query("SELECT service_id, ok, latency_ms, level FROM nm_bio_samples ORDER BY id DESC LIMIT 900");
    while ($or && $x = $or->fetch_assoc()) {
        $k = (int)$x['service_id'];
        if (!isset($orbits[$k])) $orbits[$k] = [];
        if (count($orbits[$k]) >= $ORB_MAX) continue;
        $orbits[$k][] = ['ok' => (int)$x['ok'], 'lat' => $x['latency_ms'] !== null ? (float)$x['latency_ms'] : null, 'level' => $x['level'] ?: 'unknown'];
    }

    // services with an open incident on their node → hibernation candidates (root/downstream)
    $incidentNodes = [];
    try {
        $ir = $conn->query("SELECT DISTINCT root_node_id FROM nm_incidents WHERE status IN ('open','acknowledged') AND root_node_id IS NOT NULL");
        while ($ir && $x = $ir->fetch_assoc()) $incidentNodes[(int)$x['root_node_id']] = true;
    } catch (\Throwable $e) {}

    $ICON = ['dns' => 'fa-globe', 'http' => 'fa-window-maximize', 'sql' => 'fa-database', 'smtp' => 'fa-envelope', 'generic' => 'fa-circle-nodes'];
    // Freshness: how long since the newest stored sample (any service) → lets the UI warn when
    // cron_biosphere.php isn't running (otherwise cells just sit grey/stale with no explanation).
    $freshAge = null;
    try {
        $fr = $conn->query("SELECT UNIX_TIMESTAMP(NOW()) - UNIX_TIMESTAMP(MAX(ts)) AS age FROM nm_bio_samples");
        if ($fr && ($fx = $fr->fetch_assoc()) && $fx['age'] !== null) $freshAge = (int)$fx['age'];
    } catch (\Throwable $e) {}
    $out = ['ok' => true, 'ts' => date('Y-m-d H:i:s'), 'poll_sec' => (int)$set['poll_sec'],
            'fresh_age' => $freshAge, 'services' => [], 'links' => []];

    foreach ($svcs as $s) {
        $sid = (int)$s['id'];
        $sm  = $last[$sid] ?? null;
        $extra = ($sm && $sm['extra']) ? (json_decode($sm['extra'], true) ?: []) : [];
        $ok   = $sm ? (int)$sm['ok'] : null;
        $lvl  = $sm['level'] ?? ($s['last_level'] ?: 'unknown');
        $score= $sm ? (int)$sm['score'] : null;
        $lat  = $sm && $sm['latency_ms'] !== null ? (float)$sm['latency_ms'] : null;
        $er   = $sm && $sm['err_rate'] !== null ? (float)$sm['err_rate'] : 0;

        // viz knobs 0..1 — honest mappings
        $pulse   = $lat !== null ? min(1, $lat / max(1, $set['lat_crit'])) : 0;   // 0 calm → 1 frantic swelling
        $infect  = max(0, min(1, $er));                                            // http 4xx/5xx surface patches
        $sludge  = 0; $frozen = 0;
        if ($s['kind'] === 'sql') {
            $blocked = (int)($extra['blocked'] ?? 0); $slow = (int)($extra['slow'] ?? 0);
            $sat = $extra['saturation'] ?? null;
            $frozen = $blocked > 0 ? 1 : 0;
            $sludge = min(1, $slow * 0.25 + (($sat !== null && $sat > 60) ? ($sat - 60) / 40 * 0.6 : 0));
        }
        // P3 ux knob (HTTP only): journey broke → wireframe clone splits off, scaled by how much broke
        $ux = 0; $syn = null;
        if ($s['kind'] === 'http' && isset($synth[$sid])) {
            $sy = $synth[$sid]; $stot = (int)$sy['steps_total']; $sokc = (int)$sy['steps_ok'];
            if ((int)$sy['ok'] === 0) $ux = $stot > 0 ? max(0.4, min(1, 1 - $sokc / $stot)) : 0.6;
            elseif ($sy['vct_ms'] !== null && (float)$sy['vct_ms'] >= $set['vct_warn']) $ux = 0.3;   // slow but complete
            $syn = ['ok' => (int)$sy['ok'], 'vct_ms' => $sy['vct_ms'] !== null ? (float)$sy['vct_ms'] : null,
                    'steps_ok' => $sokc, 'steps_total' => $stot, 'broken_step' => $sy['broken_step']];
        }
        $disabled = empty($s['enabled']);
        $hibernating = (!$disabled && $ok === 1 && !empty($s['node_id']) && isset($incidentNodes[(int)$s['node_id']])) ? 1 : 0;

        $out['services'][] = [
            'id' => $sid, 'name' => $s['name'], 'kind' => $s['kind'], 'icon' => $ICON[$s['kind']] ?? 'fa-circle-nodes',
            'target' => $s['target'], 'node_id' => $s['node_id'] ? (int)$s['node_id'] : null, 'node_name' => $s['node_name'],
            'enabled' => $disabled ? 0 : 1,
            'vitals' => [
                'ok' => $ok, 'score' => $score, 'level' => $lvl, 'latency_ms' => $lat, 'err_rate' => round($er, 3),
                'cache_hit' => $sm && $sm['cache_hit'] !== null ? (float)$sm['cache_hit'] : null,
                'checked' => $s['last_checked'],
            ],
            'extra' => $extra, 'synthetic' => $syn,
            'orbits' => array_reverse($orbits[$sid] ?? []),   // oldest→newest for a nice sweeping galaxy
            'viz' => ['pulse' => round($pulse, 3), 'infection' => round($infect, 3), 'sludge' => round($sludge, 3),
                      'frozen' => $frozen, 'hibernating' => $hibernating, 'disabled' => $disabled ? 1 : 0,
                      'ux' => round($ux, 3), 'wireframe' => $ux > 0 ? 1 : 0],
        ];
    }
    $out['links'] = nm_bio_links($conn);
    return $out;
}

// ── per-service dossier (detail drawer) ───────────────────────────────────────
function nm_bio_service_detail($conn, int $id): array {
    nm_bio_ensure($conn);
    $s = nm_bio_service($conn, $id);
    if (!$s) return ['ok' => false, 'error' => 'service not found'];
    $set = nm_bio_settings($conn);

    // recent samples (trend)
    $trend = [];
    $r = $conn->query("SELECT ts, ok, latency_ms, err_rate, score, level FROM nm_bio_samples
                       WHERE service_id=" . (int)$id . " ORDER BY id DESC LIMIT 60");
    while ($r && $x = $r->fetch_assoc()) $trend[] = $x;
    $trend = array_reverse($trend);

    // 24h availability from samples
    $avail = null;
    $av = $conn->query("SELECT AVG(ok)*100 pct FROM nm_bio_samples WHERE service_id=" . (int)$id . " AND ts >= (NOW()-INTERVAL 24 HOUR)");
    if ($av && $av->num_rows) { $x = $av->fetch_assoc(); $avail = $x['pct'] !== null ? round((float)$x['pct'], 2) : null; }

    $last = end($trend) ?: null;
    $lastExtra = [];
    $le = $conn->query("SELECT extra FROM nm_bio_samples WHERE service_id=" . (int)$id . " ORDER BY id DESC LIMIT 1");
    if ($le && $le->num_rows) { $e = $le->fetch_assoc()['extra']; if ($e) $lastExtra = json_decode($e, true) ?: []; }

    // SQL: pull top offending queries live (reuse Data Core) so the drawer can suggest a fix
    $topq = [];
    if ($s['kind'] === 'sql' && !empty($s['db_target_id'])) {
        try {
            $tgt = nm_db_target($conn, (int)$s['db_target_id']);
            if ($tgt) { $mon = nm_db_monitor($conn, $tgt); $tq = $mon->topQueries();
                if (!empty($tq['ok'])) $topq = array_slice($tq['queries'] ?? [], 0, 6); }
        } catch (\Throwable $e) {}
    }

    // open flags
    $flags = [];
    $fr = $conn->query("SELECT id,kind,indicator,severity,detail,status,created_at FROM nm_bio_flags
                        WHERE service_id=" . (int)$id . " AND status='open' ORDER BY id DESC LIMIT 10");
    while ($fr && $x = $fr->fetch_assoc()) $flags[] = $x;

    // P2: Data Core proposed advice for a SQL cell (drives the ⚡ Auto-Tune button)
    $advice = ($s['kind'] === 'sql') ? nm_bio_advice_for($conn, (int)$id) : [];

    // P3: synthetic-journey result + the editable journey definition (HTTP only)
    $synthetic = null; $journey = null;
    if ($s['kind'] === 'http') {
        $sl = nm_bio_synthetic_last($conn, (int)$id);
        if ($sl) $synthetic = ['ok' => (int)$sl['ok'], 'ts' => $sl['ts'], 'vct_ms' => $sl['vct_ms'], 'total_ms' => $sl['total_ms'],
                               'steps_total' => (int)$sl['steps_total'], 'steps_ok' => (int)$sl['steps_ok'], 'broken_step' => $sl['broken_step'],
                               'console_errors' => $sl['console_errors'], 'has_shot' => !empty($sl['screenshot']),
                               'steps' => $sl['detail_arr']['steps'] ?? []];
        $journey = nm_bio_journey_get($conn, (int)$id);
    }

    // symbiosis: what this service depends on / feeds
    $deps = []; $feeds = [];
    $dr = $conn->query("SELECT l.to_service id, s.name, s.kind, s.last_level FROM nm_bio_links l JOIN nm_bio_services s ON s.id=l.to_service WHERE l.from_service=" . (int)$id);
    while ($dr && $x = $dr->fetch_assoc()) $deps[] = $x;
    $fr2 = $conn->query("SELECT l.from_service id, s.name, s.kind, s.last_level FROM nm_bio_links l JOIN nm_bio_services s ON s.id=l.from_service WHERE l.to_service=" . (int)$id);
    while ($fr2 && $x = $fr2->fetch_assoc()) $feeds[] = $x;

    return ['ok' => true, 'service' => [
                'id' => (int)$s['id'], 'name' => $s['name'], 'kind' => $s['kind'], 'target' => $s['target'],
                'port' => $s['port'], 'node_id' => $s['node_id'], 'enabled' => (int)$s['enabled'],
                'db_target_id' => $s['db_target_id'], 'pihole_id' => $s['pihole_id'],
            ],
            'avail_24h' => $avail, 'last' => $last, 'extra' => $lastExtra, 'trend' => $trend,
            'top_queries' => $topq, 'flags' => $flags, 'advice' => $advice, 'synthetic' => $synthetic, 'journey' => $journey, 'deps' => $deps, 'feeds' => $feeds,
            'thresholds' => ['lat_warn' => $set['lat_warn'], 'lat_crit' => $set['lat_crit']],
            'ts' => date('Y-m-d H:i:s')];
}

// ── flags (AI/analyzer findings) + Immunity promote loop (used more in P2) ─────
function nm_bio_flag_add($conn, ?int $sid, string $kind, string $indicator, string $severity, string $detail): array {
    nm_bio_ensure($conn);
    try {
        $st = $conn->prepare("INSERT INTO nm_bio_flags (service_id,kind,indicator,severity,detail) VALUES (?,?,?,?,?)");
        $st->bind_param('issss', $sid, $kind, $indicator, $severity, $detail); $st->execute(); $id = $st->insert_id; $st->close();
    } catch (\Throwable $e) { return ['ok' => false, 'error' => $e->getMessage()]; }
    return ['ok' => true, 'id' => $id];
}
// promote a DGA/poison domain flag → Collective Immunity fleet block (closes the loop)
function nm_bio_flag_promote($conn, int $flagId, ?int $uid = null): array {
    nm_bio_ensure($conn);
    $r = $conn->query("SELECT * FROM nm_bio_flags WHERE id=" . (int)$flagId . " LIMIT 1");
    $f = $r ? $r->fetch_assoc() : null;
    if (!$f) return ['ok' => false, 'error' => 'flag not found'];
    if (trim((string)$f['indicator']) === '') return ['ok' => false, 'error' => 'no indicator to block'];
    if (is_file(__DIR__ . '/nm_immunity.php')) require_once __DIR__ . '/nm_immunity.php';
    if (!function_exists('nm_imm_add_threat')) return ['ok' => false, 'error' => 'immunity engine unavailable'];
    $type = filter_var($f['indicator'], FILTER_VALIDATE_IP) ? 'ip' : 'domain';
    $add = nm_imm_add_threat($conn, $f['indicator'], $type, 'dns', 'high', 'Biosphere: ' . $f['kind'] . ' — ' . (string)$f['detail'], $uid, 'biosphere');
    if (empty($add['ok'])) return ['ok' => false, 'error' => $add['error'] ?? 'threat add failed'];
    $vac = nm_imm_vaccinate($conn, (int)$add['id']);
    try { $conn->query("UPDATE nm_bio_flags SET status='promoted' WHERE id=" . (int)$flagId); } catch (\Throwable $e) {}
    return ['ok' => true, 'threat_id' => (int)$add['id'], 'distributed' => $vac['distributed'] ?? 0, 'failed' => $vac['failed'] ?? 0];
}

// ═════════════════════════════════════════════════════════════════════════════
//  P2 — THE INTELLIGENCE LAYER
//  (A) DNS DGA audit → flags → auto-promote to Collective Immunity (the antibody loop)
//  (B) SQL metabolic → reuse Data Core 'db-advisor' → Telegram "⚡ Auto-Tune" approval
//  The LLM only CLASSIFIES/SUGGESTS; the portal validates + acts. Whitelisted SQL only.
// ═════════════════════════════════════════════════════════════════════════════

// ── (A) DNS DGA / poison audit ────────────────────────────────────────────────
// Shannon entropy of the name minus its TLD — catches BOTH DGA (random registrable name) AND
// DNS-tunneling (random subdomain), since both make the non-TLD part look algorithmically generated.
function nm_bio_dom_entropy(string $dom): float {
    $parts = explode('.', strtolower($dom));
    if (count($parts) > 1) array_pop($parts);                    // drop the TLD
    $lab = preg_replace('/[^a-z0-9-]/', '', implode('', $parts)); // everything below the TLD, concatenated
    $n = strlen($lab);
    if ($n < 6) return 0.0;
    $H = 0.0; foreach (count_chars($lab, 1) as $cnt) { $p = $cnt / $n; $H -= $p * log($p, 2); }
    $digits = preg_match_all('/[0-9]/', $lab);
    return $H + ($digits / $n) * 2.0 + ($n >= 20 ? 1.0 : 0.0);   // long + digit-heavy boosts suspicion
}
// Candidate domains from Pi-hole-linked DNS services, ranked by entropy·log(freq), already-flagged dropped.
function nm_bio_dns_candidates($conn, int $limit = 40): array {
    nm_bio_ensure($conn);
    if (is_file(__DIR__ . '/nm_pihole.php')) require_once __DIR__ . '/nm_pihole.php';
    if (!function_exists('nm_ph_call')) return [];
    $freq = []; $svcBy = [];
    foreach (nm_bio_services($conn, true) as $s) {
        if ($s['kind'] !== 'dns' || empty($s['pihole_id'])) continue;
        try {
            $r = nm_ph_call($conn, (int)$s['pihole_id'], 'queries', ['length' => 2000]);
            if (empty($r['ok'])) continue;
            foreach (($r['data']['queries'] ?? []) as $q) {
                $dom = rtrim(strtolower(trim((string)($q['domain'] ?? ''))), '.');
                if ($dom === '') continue;
                $freq[$dom] = ($freq[$dom] ?? 0) + 1; $svcBy[$dom] = (int)$s['id'];
            }
        } catch (\Throwable $e) {}
    }
    if (!$freq) return [];
    $flagged = [];
    $fr = $conn->query("SELECT indicator FROM nm_bio_flags WHERE kind IN ('dga','tunneling','poison','malicious') AND status IN ('open','promoted')");
    while ($fr && $x = $fr->fetch_assoc()) $flagged[strtolower($x['indicator'])] = true;
    $cand = [];
    foreach ($freq as $dom => $c) {
        if (isset($flagged[$dom])) continue;
        $e = nm_bio_dom_entropy($dom);
        if ($e <= 0) continue;                              // skip obviously human domains
        $cand[] = ['domain' => $dom, 'count' => $c, 'service_id' => $svcBy[$dom], 'entropy' => $e];
    }
    usort($cand, fn($a, $b) => ($b['entropy'] * log(1 + $b['count'])) <=> ($a['entropy'] * log(1 + $a['count'])));
    return array_slice($cand, 0, $limit);
}
// Dispatch candidates to the n8n 'bio-dns-audit' flow (OpenAI). Sync verdicts stored immediately;
// async verdicts arrive via bio_api.php. High-confidence DGA auto-promotes to an Immunity block.
function nm_bio_dns_audit($conn): array {
    nm_bio_ensure($conn);
    $limit = nm_bio_settings($conn)['dns_limit'];
    $cand = nm_bio_dns_candidates($conn, $limit);
    if (!$cand) return ['ok' => true, 'candidates' => 0, 'flagged' => 0, 'note' => 'no candidate domains (need Pi-hole-linked DNS cells + query log)'];
    if (!function_exists('nm_n8n_call') && is_file(__DIR__ . '/nm_n8n.php')) require_once __DIR__ . '/nm_n8n.php';
    if (!function_exists('nm_n8n_call')) return ['ok' => false, 'error' => 'n8n not configured', 'candidates' => count($cand)];
    $cfg = function_exists('nm_n8n_get') ? nm_n8n_get($conn) : [];
    $payload = ['event' => 'bio_dns_audit', 'ts' => date('c'),
                'domains' => array_map(fn($c) => ['domain' => $c['domain'], 'count' => $c['count'], 'entropy' => round($c['entropy'], 2)], $cand),
                'callback' => (($cfg['portal_base'] ?? '') ?: 'http://localhost') . '/bio_api.php'];
    [$code, $json, $err] = nm_n8n_call($conn, 'bio-dns-audit', $payload, 25);
    $flagged = 0; $promoted = 0;
    $verdicts = is_array($json) ? ($json['verdicts'] ?? $json['results'] ?? (isset($json[0]) ? $json : [])) : [];
    foreach ((array)$verdicts as $v) { if (!is_array($v)) continue; $r = nm_bio_ingest_dns_verdict($conn, $v);
        if (!empty($r['flagged'])) $flagged++; if (!empty($r['promoted'])) $promoted++; }
    return ['ok' => ($code >= 200 && $code < 300), 'http' => $code, 'candidates' => count($cand), 'flagged' => $flagged, 'promoted' => $promoted,
            'note' => ($code >= 200 && $code < 300) ? 'Sent to bio-dns-audit; async verdicts (if any) land on bio_api.php.' : 'Register + ACTIVATE an n8n webhook with slug "bio-dns-audit".'];
}
// Cron wrapper: only dispatch a DNS audit every dns_min minutes (the cron fires every minute).
// The manual "Run DNS audit now" button calls nm_bio_dns_audit directly and always runs.
function nm_bio_dns_tick($conn): array {
    nm_bio_ensure($conn);
    $set = nm_bio_settings($conn);
    if (!$set['dns_audit']) return ['skipped' => 'disabled'];
    $min = (int)$set['dns_min'];
    $due = $conn->query("SELECT 1 FROM nm_settings WHERE setting_key='bio_dns_last' AND setting_val > (NOW() - INTERVAL $min MINUTE) LIMIT 1");
    if ($due && $due->num_rows) return ['skipped' => 'throttled', 'every_min' => $min];
    // stamp the run BEFORE dispatching (in DB time, matching the NOW() comparison) so a slow/failed
    // dispatch can't let two ticks overlap.
    $conn->query("INSERT INTO nm_settings (setting_key, setting_val) VALUES ('bio_dns_last', NOW())
                  ON DUPLICATE KEY UPDATE setting_val=NOW()");
    return nm_bio_dns_audit($conn);
}

// Shared verdict ingest (sync reply AND the bio_api.php async callback both call this).
function nm_bio_ingest_dns_verdict($conn, array $v): array {
    nm_bio_ensure($conn);
    $dom = rtrim(strtolower(trim((string)($v['domain'] ?? ''))), '.'); if ($dom === '') return ['flagged' => false];
    $verdict = strtolower((string)($v['verdict'] ?? 'benign'));
    if (!in_array($verdict, ['dga', 'tunneling', 'poison', 'malicious'], true)) return ['flagged' => false, 'benign' => true];
    $score = (float)($v['score'] ?? 0);
    $sev = ($score >= 80) ? 'high' : ($score >= 50 ? 'medium' : 'low');
    $sid = null; $sr = $conn->query("SELECT id FROM nm_bio_services WHERE kind='dns' ORDER BY id LIMIT 1");
    if ($sr && $sr->num_rows) $sid = (int)$sr->fetch_assoc()['id'];
    $detail = 'score ' . (int)$score . ' — ' . trim((string)($v['reason'] ?? ''));
    $ex = $conn->query("SELECT id,status FROM nm_bio_flags WHERE indicator='" . $conn->real_escape_string($dom) . "' AND kind IN ('dga','tunneling','poison','malicious') ORDER BY id DESC LIMIT 1");
    $exRow = $ex ? $ex->fetch_assoc() : null; $flagId = 0;
    if ($exRow) { if ($exRow['status'] === 'promoted') return ['flagged' => false, 'already' => true]; $flagId = (int)$exRow['id']; }
    else { $add = nm_bio_flag_add($conn, $sid, $verdict, $dom, $sev, $detail); $flagId = (int)($add['id'] ?? 0); }
    $out = ['flagged' => ($flagId > 0)];
    $set = nm_bio_settings($conn);
    if ($flagId > 0 && $score >= $set['dga_promote']) { $pr = nm_bio_flag_promote($conn, $flagId, null); $out['promoted'] = !empty($pr['ok']); }
    return $out;
}

// ── (B) SQL metabolic advisor + Telegram Auto-Tune ────────────────────────────
// Raise (deduped: one per service·kind·hour) flags when a SQL cell shows real distress.
function nm_bio_metabolic_flag($conn, array $svc, array $extra): void {
    $sid = (int)$svc['id'];
    $mk = function($kind, $sev, $detail) use ($conn, $sid) {
        $ex = $conn->query("SELECT id FROM nm_bio_flags WHERE service_id=$sid AND kind='" . $conn->real_escape_string($kind) . "' AND status='open' AND created_at > (NOW()-INTERVAL 1 HOUR) LIMIT 1");
        if ($ex && $ex->num_rows) return;
        nm_bio_flag_add($conn, $sid, $kind, '', $sev, $detail);
    };
    $blocked = (int)($extra['blocked'] ?? 0); $slow = (int)($extra['slow'] ?? 0); $sat = $extra['saturation'] ?? null;
    if ($blocked > 0)                     $mk('deadlock',   'high',   "$blocked blocking lock(s) — a query is frozen behind another. Investigate in Data Core.");
    elseif ($slow >= 2)                   $mk('slow_query', 'medium', "$slow slow queries running — metabolic sludge. ⚡ Auto-Tune can propose an index/optimize.");
    elseif ($sat !== null && $sat >= 90)  $mk('saturation', 'medium', "Connection pool {$sat}% saturated.");
}
// Trigger the EXISTING Data Core 'db-advisor' n8n flow for a SQL cell's target. It posts
// suggestions back to dbmon_api.php (stored in nm_db_advice) — we just engage it.
function nm_bio_sql_advise($conn, int $service_id): array {
    $s = nm_bio_service($conn, $service_id);
    if (!$s || $s['kind'] !== 'sql' || empty($s['db_target_id'])) return ['ok' => false, 'error' => 'not a SQL service'];
    $tid = (int)$s['db_target_id']; $t = function_exists('nm_db_target') ? nm_db_target($conn, $tid) : null;
    if (!$t) return ['ok' => false, 'error' => 'target missing'];
    if (!function_exists('nm_n8n_call') && is_file(__DIR__ . '/nm_n8n.php')) require_once __DIR__ . '/nm_n8n.php';
    if (!function_exists('nm_n8n_call')) return ['ok' => false, 'error' => 'n8n not configured'];
    try {
        $mon = nm_db_monitor($conn, $t); $tq = $mon->topQueries();
        $cfg = function_exists('nm_n8n_get') ? nm_n8n_get($conn) : [];
        $payload = ['event' => 'db_advise', 'source' => 'biosphere', 'target_id' => $tid, 'engine' => $t['engine'], 'db_name' => $t['db_name'],
                    'top_queries' => array_slice($tq['queries'] ?? [], 0, 25),
                    'callback' => (($cfg['portal_base'] ?? '') ?: 'http://localhost') . '/dbmon_api.php'];
        [$code, $json, $err] = nm_n8n_call($conn, 'db-advisor', $payload, 25);
        return ['ok' => ($code >= 200 && $code < 300), 'http' => $code, 'target_id' => $tid,
                'note' => ($code >= 200 && $code < 300) ? 'Advisor engaged — suggestions post back as they arrive.' : 'Register + ACTIVATE an n8n webhook with slug "db-advisor".'];
    } catch (\Throwable $e) { return ['ok' => false, 'error' => $e->getMessage()]; }
}
// Proposed Data Core advice for a SQL cell's target (reuse nm_db_advice_list).
function nm_bio_advice_for($conn, int $service_id): array {
    $s = nm_bio_service($conn, $service_id);
    if (!$s || empty($s['db_target_id']) || !function_exists('nm_db_advice_list')) return [];
    return nm_db_advice_list($conn, (int)$s['db_target_id'], 'proposed');
}
// escape for Telegram Markdown (v1)
function nm_bio_tg_md(string $s): string { return str_replace(['_', '*', '`', '['], ['\_', '\*', '\`', '\['], $s); }

// Send a Telegram "⚡ Auto-Tune" approval for a whitelisted advice item. Buttons carry a
// bio:<apId>:<token>:a|d payload — dispatched by the SHARED aiopilot poller (no getUpdates conflict).
function nm_bio_tg_send_autotune($conn, int $advice_id, ?int $uid = null): array {
    nm_bio_ensure($conn);
    if (!function_exists('nm_db_advice_allowed_sql')) return ['ok' => false, 'error' => 'Data Core unavailable'];
    $r = $conn->query("SELECT * FROM nm_db_advice WHERE id=" . (int)$advice_id . " LIMIT 1");
    $a = $r ? $r->fetch_assoc() : null;
    if (!$a) return ['ok' => false, 'error' => 'advice not found'];
    if ($a['status'] !== 'proposed') return ['ok' => false, 'error' => 'advice already ' . $a['status']];
    if (!nm_db_advice_allowed_sql((string)$a['kind'], (string)$a['ddl'])) return ['ok' => false, 'error' => 'Not auto-appliable (only CREATE INDEX / ANALYZE / OPTIMIZE / VACUUM). Apply it manually in Data Core.'];
    if (is_file(__DIR__ . '/nm_aiopilot.php')) require_once __DIR__ . '/nm_aiopilot.php';
    if (!function_exists('nm_aip_tg_channel')) return ['ok' => false, 'error' => 'Telegram engine unavailable'];
    $tg = nm_aip_tg_channel($conn);
    if (!$tg) return ['ok' => false, 'error' => 'No Telegram channel configured (add one in Notifications).'];
    $token = bin2hex(random_bytes(8)); $svcId = null; $det = mb_substr((string)$a['title'], 0, 200);
    try {
        $st = $conn->prepare("INSERT INTO nm_bio_tg_approvals (kind,ref_id,service_id,token,detail,status,created_by)
                              VALUES ('autotune',?,?,?,?, 'pending', ?)
                              ON DUPLICATE KEY UPDATE token=VALUES(token), status='pending', detail=VALUES(detail), decided_at=NULL, created_at=NOW()");
        $st->bind_param('iissi', $advice_id, $svcId, $token, $det, $uid); $st->execute(); $st->close();
    } catch (\Throwable $e) { return ['ok' => false, 'error' => $e->getMessage()]; }
    $apId = 0; $q = $conn->query("SELECT id FROM nm_bio_tg_approvals WHERE kind='autotune' AND ref_id=" . (int)$advice_id . " LIMIT 1");
    if ($q && $q->num_rows) $apId = (int)$q->fetch_assoc()['id'];
    $txt = "⚡ *Biosphere Auto-Tune*\n" . nm_bio_tg_md((string)$a['title'])
         . "\n\n`" . nm_bio_tg_md(mb_substr((string)$a['ddl'], 0, 300)) . "`\n\n_risk: " . nm_bio_tg_md((string)$a['risk'])
         . ' · benefit: ' . nm_bio_tg_md((string)$a['benefit']) . "_\nApprove to apply this DDL to the database.";
    $kb = ['inline_keyboard' => [[
        ['text' => '✅ Apply', 'callback_data' => "bio:$apId:$token:a"],
        ['text' => '🚫 Deny',  'callback_data' => "bio:$apId:$token:d"],
    ]]];
    $send = nm_aip_tg_api($tg['token'], 'sendMessage', ['chat_id' => $tg['chat'], 'text' => $txt, 'parse_mode' => 'Markdown', 'reply_markup' => $kb]);
    $msgId = (int)($send['result']['message_id'] ?? 0);
    if ($msgId) { try { $st = $conn->prepare("UPDATE nm_bio_tg_approvals SET chat_msg_id=? WHERE id=?"); $st->bind_param('ii', $msgId, $apId); $st->execute(); $st->close(); } catch (\Throwable $e) {} }
    return ['ok' => !empty($send['ok']), 'approval_id' => $apId, 'error' => $send['error'] ?? null];
}
// Callback handler invoked from the SHARED aiopilot poller for any `bio:` callback_data.
function nm_bio_tg_callback($conn, array $tg, array $cb, string $data): void {
    nm_bio_ensure($conn);
    if (!function_exists('nm_aip_tg_api')) return;
    $cbId = (string)($cb['id'] ?? ''); $chatId = (string)($cb['message']['chat']['id'] ?? '');
    $msgId = (int)($cb['message']['message_id'] ?? 0);
    $who = trim(((string)($cb['from']['first_name'] ?? '')) . ' ' . (($cb['from']['username'] ?? '') ? '@' . $cb['from']['username'] : ''));
    $ans = function($t = null) use ($tg, $cbId) { nm_aip_tg_api($tg['token'], 'answerCallbackQuery', array_filter(['callback_query_id' => $cbId, 'text' => $t])); };
    $parts = explode(':', $data);                           // bio:<apId>:<token>:a|d
    if (count($parts) < 4) { $ans(); return; }
    $apId = (int)$parts[1]; $tok = (string)$parts[2]; $verdict = (string)$parts[3];
    $r = $conn->query("SELECT * FROM nm_bio_tg_approvals WHERE id=$apId LIMIT 1");
    $ap = $r ? $r->fetch_assoc() : null;
    if (!$ap || !hash_equals((string)$ap['token'], $tok)) { $ans('This request expired.'); return; }
    if ($ap['status'] !== 'pending') { $ans('Already ' . $ap['status'] . '.'); return; }
    $note = 'via Telegram' . ($who !== '' ? " ($who)" : '');
    if ($verdict === 'a') {
        $res = function_exists('nm_db_apply_advice') ? nm_db_apply_advice($conn, (int)$ap['ref_id'], null) : ['ok' => false, 'error' => 'apply unavailable'];
        $ok = !empty($res['ok']);
        $conn->query("UPDATE nm_bio_tg_approvals SET status='approved', decided_at=NOW() WHERE id=$apId");
        $ans($ok ? '✅ Applied.' : '⚠️ Apply failed.');
        if ($msgId) nm_aip_tg_api($tg['token'], 'editMessageText', ['chat_id' => $chatId, 'message_id' => $msgId,
            'text' => ($ok ? "✅ *Auto-Tune applied* $note" : "⚠️ *Auto-Tune failed* $note") . (!empty($res['error']) ? "\n" . nm_bio_tg_md((string)$res['error']) : ''), 'parse_mode' => 'Markdown']);
    } else {
        $conn->query("UPDATE nm_bio_tg_approvals SET status='denied', decided_at=NOW() WHERE id=$apId");
        $ans('🚫 Denied.');
        if ($msgId) nm_aip_tg_api($tg['token'], 'editMessageText', ['chat_id' => $chatId, 'message_id' => $msgId, 'text' => "🚫 *Auto-Tune denied* $note", 'parse_mode' => 'Markdown']);
    }
}

// ── flags feed (antibody stream UI) ───────────────────────────────────────────
function nm_bio_flags_all($conn, string $status = 'open', int $limit = 60): array {
    nm_bio_ensure($conn);
    $st = in_array($status, ['open', 'promoted', 'resolved', 'all'], true) ? $status : 'open';
    $w = $st === 'all' ? '' : "WHERE f.status='" . $conn->real_escape_string($st) . "'";
    $out = []; $r = $conn->query("SELECT f.*, s.name svc_name, s.kind svc_kind FROM nm_bio_flags f
                                  LEFT JOIN nm_bio_services s ON s.id=f.service_id $w ORDER BY f.id DESC LIMIT " . (int)$limit);
    while ($r && $x = $r->fetch_assoc()) $out[] = $x;
    return $out;
}
function nm_bio_flag_resolve($conn, int $id): array {
    nm_bio_ensure($conn);
    try { $conn->query("UPDATE nm_bio_flags SET status='resolved' WHERE id=" . (int)$id); } catch (\Throwable $e) { return ['ok' => false, 'error' => $e->getMessage()]; }
    return ['ok' => true];
}

// ── Auto-Tune: APPLY directly + ANNOUNCE to channels ─────────────────────────
// The operator is IN the portal clicking the button → clicking IS the approval. Apply the
// whitelisted DDL right away, then broadcast a heads-up to every enabled notification channel
// (fire-and-forget). No self-approval round-trip — that pattern is only for the autonomous case.
function nm_bio_broadcast($conn, string $text, string $subject = 'NEURU Biosphere'): array {
    if (!function_exists('nm_notify_channels') && is_file(__DIR__ . '/nm_notify.php')) require_once __DIR__ . '/nm_notify.php';
    if (!function_exists('nm_notify_channels')) return ['sent' => 0, 'channels' => 0];
    if (is_file(__DIR__ . '/nm_secrets.php')) require_once __DIR__ . '/nm_secrets.php';
    $chs = nm_notify_channels($conn, true); $sent = 0;
    foreach ($chs as $c) {
        $full = function_exists('nm_notify_channel_get') ? nm_notify_channel_get($conn, (int)$c['id']) : null;
        if (!$full) continue;
        $secret = function_exists('nm_secret_decrypt') ? nm_secret_decrypt($full['secret_enc'] ?? '') : '';
        try {
            if ($full['type'] === 'telegram') {
                if ($secret === '' || !function_exists('_nf_post')) continue;
                $r = _nf_post("https://api.telegram.org/bot{$secret}/sendMessage", ['chat_id' => $full['target'], 'text' => $text, 'disable_web_page_preview' => true], []);
                if (!empty($r['ok'])) $sent++;
            } elseif ($full['type'] === 'email') {
                if (is_file(__DIR__ . '/nm_smtp.php')) require_once __DIR__ . '/nm_smtp.php';
                $e = null; if (function_exists('nm_smtp_send') && nm_smtp_send($conn, $full['target'], '[NEURU] ' . $subject, $text, $e)) $sent++;
            } elseif (($full['type'] === 'n8n' || $full['type'] === 'webhook') && function_exists('_nf_post')) {
                $headers = ['Content-Type: application/json'];
                if ($full['type'] === 'n8n') { $cfg = function_exists('nm_n8n_get') ? nm_n8n_get($conn) : []; if (!empty($cfg['inbound_token'])) $headers[] = 'X-NetMon-Token: ' . $cfg['inbound_token']; }
                $r = _nf_post($full['target'], ['event' => 'biosphere.autotune', 'text' => $text], $headers, true);
                if (!empty($r['ok'])) $sent++;
            }
        } catch (\Throwable $e) {}
    }
    return ['sent' => $sent, 'channels' => count($chs)];
}
function nm_bio_apply_advice($conn, int $advice_id, ?int $uid = null): array {
    nm_bio_ensure($conn);
    if (!function_exists('nm_db_apply_advice') || !function_exists('nm_db_advice_allowed_sql')) return ['ok' => false, 'error' => 'Data Core unavailable'];
    $r = $conn->query("SELECT * FROM nm_db_advice WHERE id=" . (int)$advice_id . " LIMIT 1");
    $a = $r ? $r->fetch_assoc() : null;
    if (!$a) return ['ok' => false, 'error' => 'advice not found'];
    if ($a['status'] !== 'proposed') return ['ok' => false, 'error' => 'advice already ' . $a['status']];
    if (!nm_db_advice_allowed_sql((string)$a['kind'], (string)$a['ddl'])) return ['ok' => false, 'error' => 'Not auto-appliable (only CREATE INDEX / ANALYZE / OPTIMIZE / VACUUM). Apply it manually in Data Core.'];
    $res = nm_db_apply_advice($conn, $advice_id, $uid);
    if (empty($res['ok'])) return ['ok' => false, 'error' => $res['error'] ?? 'apply failed'];
    // announce (best-effort) to enabled notification channels
    $tgt = '';
    $tr = $conn->query("SELECT dt.display_name FROM nm_db_advice ad JOIN nm_db_targets dt ON dt.id=ad.target_id WHERE ad.id=" . (int)$advice_id . " LIMIT 1");
    if ($tr && $tr->num_rows) $tgt = (string)$tr->fetch_assoc()['display_name'];
    $bc = ['sent' => 0, 'channels' => 0];
    try {
        $msg = "⚡ Biosphere Auto-Tune APPLIED\n" . (string)$a['title'] . "\nDB: " . ($tgt ?: ('target #' . $a['target_id'])) . "\n" . mb_substr((string)$a['ddl'], 0, 220);
        $bc = nm_bio_broadcast($conn, $msg, 'Biosphere Auto-Tune');
    } catch (\Throwable $e) {}
    return ['ok' => true, 'notified' => $bc['sent'], 'channels' => $bc['channels']];
}

// ═════════════════════════════════════════════════════════════════════════════
//  P3 — THE SYNTHETIC PERSONA
//  A headless-browser journey (login → click → assert) runs in n8n (bio-http-synthetic),
//  measures Visual Completeness Time (VCT) + per-step pass/fail. A broken journey splits a
//  "wireframe clone" off the HTTP cell — UX degradation shown DISTINCT from raw availability.
//  Journey + persona live in the service's params JSON; the login password is nm_secret-encrypted.
// ═════════════════════════════════════════════════════════════════════════════

// Read the journey (steps + persona) for a service. Never returns the plaintext password —
// only a has_password flag; the real secret is decrypted server-side at dispatch time.
function nm_bio_journey_get($conn, int $service_id): array {
    $s = nm_bio_service($conn, $service_id);
    $p = ($s && !empty($s['params_arr'])) ? $s['params_arr'] : [];
    $steps = is_array($p['journey'] ?? null) ? $p['journey'] : [];
    $per = is_array($p['persona'] ?? null) ? $p['persona'] : [];
    $persona = [
        'login_url'       => (string)($per['login_url'] ?? ''),
        'user_selector'   => (string)($per['user_selector'] ?? ''),
        'pass_selector'   => (string)($per['pass_selector'] ?? ''),
        'submit_selector' => (string)($per['submit_selector'] ?? ''),
        'username'        => (string)($per['username'] ?? ''),
        'has_password'    => !empty($per['password_enc']),
    ];
    return ['ok' => (bool)$s, 'steps' => $steps, 'persona' => $persona];
}
// Save the journey. Merges into params JSON (preserves probe_name/url/expect/match). A non-empty
// plaintext password is nm_secret-encrypted; a blank one keeps the stored secret.
function nm_bio_journey_save($conn, int $service_id, array $steps, array $persona): array {
    $s = nm_bio_service($conn, $service_id);
    if (!$s) return ['ok' => false, 'error' => 'service not found'];
    if ($s['kind'] !== 'http') return ['ok' => false, 'error' => 'journeys are HTTP-only'];
    $p = $s['params_arr'] ?: [];
    // sanitize steps
    $clean = [];
    foreach ($steps as $st) {
        if (!is_array($st)) continue;
        $type = in_array($st['type'] ?? '', ['goto','fill','click','expect','wait','expect_text'], true) ? $st['type'] : null;
        if (!$type) continue;
        $clean[] = ['type' => $type, 'selector' => trim((string)($st['selector'] ?? '')), 'value' => (string)($st['value'] ?? '')];
        if (count($clean) >= 30) break;
    }
    $p['journey'] = $clean;
    // persona
    $per = is_array($p['persona'] ?? null) ? $p['persona'] : [];
    foreach (['login_url','user_selector','pass_selector','submit_selector','username'] as $k) $per[$k] = trim((string)($persona[$k] ?? ($per[$k] ?? '')));
    $pw = (string)($persona['password'] ?? '');
    if ($pw !== '') {
        if (is_file(__DIR__ . '/nm_secrets.php')) require_once __DIR__ . '/nm_secrets.php';
        $per['password_enc'] = function_exists('nm_secret_encrypt') ? nm_secret_encrypt($pw) : $pw;
    }
    if (!empty($persona['clear_password'])) unset($per['password_enc']);
    $p['persona'] = $per;
    try {
        $json = json_encode($p);
        $st = $conn->prepare("UPDATE nm_bio_services SET params=? WHERE id=?");
        $st->bind_param('si', $json, $service_id); $st->execute(); $st->close();
    } catch (\Throwable $e) { return ['ok' => false, 'error' => $e->getMessage()]; }
    return ['ok' => true, 'steps' => count($clean)];
}
// Dispatch the journey to the n8n 'bio-http-synthetic' flow (headless browser). Sync result → ingest.
function nm_bio_synthetic_dispatch($conn, int $service_id): array {
    $s = nm_bio_service($conn, $service_id);
    if (!$s || $s['kind'] !== 'http') return ['ok' => false, 'error' => 'not an HTTP service'];
    $p = $s['params_arr'] ?: [];
    $url = trim((string)($p['url'] ?? '')) ?: (string)$s['target'];
    if ($url === '') return ['ok' => false, 'error' => 'no URL to journey'];
    $steps = is_array($p['journey'] ?? null) ? $p['journey'] : [];
    $per   = is_array($p['persona'] ?? null) ? $p['persona'] : [];
    // decrypt the login password server-side (www-data) for this dispatch only
    $pw = '';
    if (!empty($per['password_enc'])) { if (is_file(__DIR__ . '/nm_secrets.php')) require_once __DIR__ . '/nm_secrets.php';
        $pw = function_exists('nm_secret_decrypt') ? nm_secret_decrypt($per['password_enc']) : ''; }
    if (!function_exists('nm_n8n_call') && is_file(__DIR__ . '/nm_n8n.php')) require_once __DIR__ . '/nm_n8n.php';
    if (!function_exists('nm_n8n_call')) return ['ok' => false, 'error' => 'n8n not configured'];
    $cfg = function_exists('nm_n8n_get') ? nm_n8n_get($conn) : [];
    $payload = ['event' => 'bio_http_synthetic', 'service_id' => (int)$service_id, 'name' => $s['name'], 'url' => $url,
                'persona' => ['login_url' => (string)($per['login_url'] ?? ''), 'user_selector' => (string)($per['user_selector'] ?? ''),
                              'pass_selector' => (string)($per['pass_selector'] ?? ''), 'submit_selector' => (string)($per['submit_selector'] ?? ''),
                              'username' => (string)($per['username'] ?? ''), 'password' => $pw],
                'journey' => $steps,
                'callback' => (($cfg['portal_base'] ?? '') ?: 'http://localhost') . '/bio_api.php'];
    [$code, $json, $err] = nm_n8n_call($conn, 'bio-http-synthetic', $payload, 60);
    $ingested = false;
    if (is_array($json) && (isset($json['vct_ms']) || isset($json['steps']) || isset($json['ok']))) {
        nm_bio_ingest_synthetic($conn, $service_id, $json); $ingested = true;
    }
    return ['ok' => ($code >= 200 && $code < 300), 'http' => $code, 'ingested' => $ingested,
            'note' => ($code >= 200 && $code < 300) ? ($ingested ? 'Journey ran — result stored.' : 'Sent — async result will land on bio_api.php.') : 'Register + ACTIVATE an n8n webhook slug "bio-http-synthetic".'];
}
// Store a synthetic result (from the sync reply OR the bio_api.php async callback) + raise ux_break.
function nm_bio_ingest_synthetic($conn, int $service_id, array $r): array {
    nm_bio_ensure($conn);
    $steps = is_array($r['steps'] ?? null) ? $r['steps'] : [];
    $stotal = count($steps);
    $sok = 0; foreach ($steps as $st) if (!empty($st['ok'])) $sok++;
    $broken = '';
    foreach ($steps as $st) if (empty($st['ok'])) { $broken = (string)($st['name'] ?? $st['selector'] ?? 'step'); break; }
    if ($broken === '' && !empty($r['broken_step'])) $broken = (string)$r['broken_step'];
    $ok = array_key_exists('ok', $r) ? (int)(!empty($r['ok'])) : (int)($broken === '');
    $vct = isset($r['vct_ms']) ? (float)$r['vct_ms'] : null;
    $tot = isset($r['total_ms']) ? (float)$r['total_ms'] : null;
    $cerr = isset($r['console_errors']) ? (int)$r['console_errors'] : null;
    $shot = isset($r['screenshot']) && is_string($r['screenshot']) ? substr($r['screenshot'], 0, 400000) : null;
    $detail = json_encode(['steps' => $steps, 'notes' => (string)($r['notes'] ?? '')]);
    try {
        $st = $conn->prepare("INSERT INTO nm_bio_synthetic (service_id,ok,vct_ms,total_ms,steps_total,steps_ok,broken_step,console_errors,screenshot,detail)
                              VALUES (?,?,?,?,?,?,?,?,?,?)");
        $bk = ($broken !== '') ? $broken : null;
        $st->bind_param('iiddiisiss', $service_id, $ok, $vct, $tot, $stotal, $sok, $bk, $cerr, $shot, $detail);
        $st->execute(); $st->close();
    } catch (\Throwable $e) { return ['ok' => false, 'error' => $e->getMessage()]; }
    // raise a UX-break flag (deduped 1/hour) when the journey broke
    if (!$ok || $broken !== '') {
        $sid = (int)$service_id;
        $ex = $conn->query("SELECT id FROM nm_bio_flags WHERE service_id=$sid AND kind='ux_break' AND status='open' AND created_at > (NOW()-INTERVAL 1 HOUR) LIMIT 1");
        if (!($ex && $ex->num_rows)) nm_bio_flag_add($conn, $sid, 'ux_break', $broken, 'medium', "Synthetic journey broke at: " . ($broken ?: 'unknown step') . ". The rendered UX diverged from the healthy structure.");
    }
    // prune synthetic history to the sample window
    try { $days = nm_bio_settings($conn)['sample_days']; $conn->query("DELETE FROM nm_bio_synthetic WHERE ts < (NOW()-INTERVAL " . (int)$days . " DAY)"); } catch (\Throwable $e) {}
    return ['ok' => true, 'stored' => true, 'ux_ok' => (bool)$ok];
}
function nm_bio_synthetic_last($conn, int $service_id): ?array {
    nm_bio_ensure($conn);
    $r = $conn->query("SELECT * FROM nm_bio_synthetic WHERE service_id=" . (int)$service_id . " ORDER BY id DESC LIMIT 1");
    $x = $r ? $r->fetch_assoc() : null; if (!$x) return null;
    $x['detail_arr'] = $x['detail'] ? (json_decode($x['detail'], true) ?: []) : [];
    return $x;
}
// Cron: dispatch journeys for HTTP cells that have a journey/persona and are due (>= synth_min old).
function nm_bio_synthetic_tick($conn): array {
    nm_bio_ensure($conn);
    $set = nm_bio_settings($conn);
    if (!$set['synthetic']) return ['skipped' => true];
    $out = [];
    foreach (nm_bio_services($conn, true) as $s) {
        if ($s['kind'] !== 'http') continue;
        $p = $s['params_arr'] ?: [];
        $hasJourney = !empty($p['journey']) || !empty($p['persona']['login_url']);
        if (!$hasJourney) continue;
        $sid = (int)$s['id'];
        $due = $conn->query("SELECT 1 FROM nm_bio_synthetic WHERE service_id=$sid AND ts > (NOW()-INTERVAL " . (int)$set['synth_min'] . " MINUTE) LIMIT 1");
        if ($due && $due->num_rows) continue;                // ran recently
        $out[$sid] = nm_bio_synthetic_dispatch($conn, $sid);
    }
    return $out;
}

} // end function_exists guard
