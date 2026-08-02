<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — licensing CLIENT (product side). Talks to the NEURU License Server:
// activates this install, revalidates (heartbeat), caches a signed Ed25519 token,
// and gates paid/exclusive features by tier. The private signing key lives ONLY
// on the license authority; here we embed the PUBLIC key to VERIFY tokens.
//
// SAFETY: this is default-PERMISSIVE. Until an admin turns on enforcement
// (nm_settings 'license_enforce' = '1') NEURU behaves exactly as before — every
// feature stays on. Enforcement + a valid token are BOTH required before any gate
// says "no". This can never silently lock an operator out of a running NOC.
//
// Pair: licenseportal/ (the authority). Public key below = the base64 from
// licenseportal/scripts/generate-keys.php. Regenerate keys → update this constant.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_lic_ensure')) {

// Embedded PUBLIC verification key (base64 of the Ed25519 public key). Verify-only.
define('NM_LIC_PUBKEY_B64', 'EkLumcl8KN20yjGo4oauq4GsqlpAsM9DqrsTvDPrGuY=');

// Feature → minimum tier. This is the map that unlocks EXCLUSIVE paid features.
// Add a feature here + call nm_feature($conn,'key') on its page to make it paid.
// (Everything not listed is treated as 'free' / always available.)
function nm_lic_feature_matrix(): array {
    return [
        // pro-tier
        'ai_insights'    => 'pro',
        'predictive'     => 'pro',
        'wifi'           => 'pro',
        'mtfw'           => 'pro',
        'gpu'            => 'pro',
        // enterprise-tier
        'federation'     => 'enterprise',
        'remote_console' => 'enterprise',
        'selfheal'       => 'enterprise',
        'deception'      => 'enterprise',
        'aiopilot'       => 'enterprise',
        'immunity_fleet' => 'enterprise',
    ];
}
function nm_lic_tier_rank(string $tier): int {
    // perpetual owns pro-level features of its version ceiling → rank alongside pro
    $r = ['unlicensed'=>0, 'free'=>1, 'perpetual'=>2, 'pro'=>2, 'enterprise'=>3];
    return $r[strtolower($tier)] ?? 0;
}

// One-row state cache: the current license key + latest verified token + summary.
function nm_lic_ensure($conn): void {
    static $done = false; if ($done) return; $done = true;
    if (!($conn instanceof mysqli)) return;
    try {
        $conn->query("CREATE TABLE IF NOT EXISTS nm_license (
            id TINYINT UNSIGNED NOT NULL PRIMARY KEY DEFAULT 1,
            license_key VARCHAR(32) NULL,
            token TEXT NULL,
            tier VARCHAR(24) NOT NULL DEFAULT 'unlicensed',
            max_nodes INT NULL,
            status VARCHAR(24) NOT NULL DEFAULT 'unlicensed',
            fingerprint CHAR(64) NULL,
            grace_until DATETIME NULL,
            last_check DATETIME NULL,
            last_error VARCHAR(255) NULL,
            offline TINYINT(1) NOT NULL DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("INSERT IGNORE INTO nm_license (id,tier,status) VALUES (1,'unlicensed','unlicensed')");
        // Fingerprint-freeze migration: if this install was already activated (has a stored
        // fingerprint the portal knows) but has no frozen id file yet, adopt that fingerprint.
        // This auto-heals installs whose container was recreated after activation — they keep
        // their portal activation instead of flipping to a new (unknown) fingerprint.
        $idFile = __DIR__ . '/.nm_install_id';
        $cur = is_file($idFile) ? trim((string)@file_get_contents($idFile)) : '';
        if ($cur === '') {   // missing OR empty (entrypoint may pre-create it empty, www-data-owned)
            $r = $conn->query("SELECT fingerprint FROM nm_license WHERE id=1 AND fingerprint IS NOT NULL AND fingerprint<>''");
            $fp = $r ? (string)($r->fetch_assoc()['fingerprint'] ?? '') : '';
            if ($fp !== '') { @file_put_contents($idFile, $fp); @chmod($idFile, 0644); }
        }
    } catch (\Throwable $e) { /* best-effort */ }
}

// Stable machine fingerprint: sha256(machine-id | primary MAC | hostname).
function nm_lic_fingerprint(): string {
    // The fingerprint is FROZEN into a persistent file in the bind-mounted app dir. In
    // Docker the raw machine signals (machine-id, container MAC, hostname) all change when
    // the container is recreated (updates, reboots, compose edits) — which would silently
    // flip the fingerprint and de-activate a valid license. Freezing it keeps the identity
    // stable for the life of the install. nm_lic_ensure() seeds this file from the last
    // portal-known fingerprint for already-activated installs (see migration there).
    $idFile = __DIR__ . '/.nm_install_id';
    $v = is_file($idFile) ? trim((string)@file_get_contents($idFile)) : '';
    if ($v !== '') return $v;
    $mid = @trim((string)@file_get_contents('/etc/machine-id')) ?: @trim((string)@file_get_contents('/var/lib/dbus/machine-id'));
    $mac = '';
    foreach (glob('/sys/class/net/*/address') ?: [] as $f) { $a = trim((string)@file_get_contents($f));
        if ($a && $a !== '00:00:00:00:00:00' && strpos($f, '/lo/') === false) { $mac = $a; break; } }
    $host = gethostname() ?: '';
    $fp = hash('sha256', $mid . '|' . $mac . '|' . $host);
    @file_put_contents($idFile, $fp);   // freeze it → stable across container recreation
    @chmod($idFile, 0644);
    return $fp;
}

// EdDSA (Ed25519) token verify with the embedded public key. Returns claims|null.
function nm_lic_verify_token(string $token, bool $checkExp = true): ?array {
    if (!function_exists('sodium_crypto_sign_verify_detached')) return null;
    $parts = explode('.', $token); if (count($parts) !== 3) return null;
    $dec = function(string $s){ $s=strtr($s,'-_','+/'); $p=strlen($s)%4; if($p)$s.=str_repeat('=',4-$p); return (string)base64_decode($s); };
    $sig = $dec($parts[2]); if (strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES) return null;
    $pk = base64_decode(NM_LIC_PUBKEY_B64);
    try { if (!sodium_crypto_sign_verify_detached($sig, $parts[0].'.'.$parts[1], $pk)) return null; }
    catch (\Throwable $e) { return null; }
    $claims = json_decode($dec($parts[1]), true);
    if (!is_array($claims)) return null;
    if ($checkExp && isset($claims['exp']) && time() >= (int)$claims['exp']) {
        // token past exp — still valid within grace window (offline tolerance)
        if (!isset($claims['grace_until']) || time() >= (int)$claims['grace_until']) return null;
        $claims['_in_grace'] = true;
    }
    return $claims;
}

// Is enforcement turned on? (nm_settings license_enforce = '1'). Default OFF.
function nm_lic_enforced($conn): bool {
    if (!($conn instanceof mysqli)) return false;
    try { $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='license_enforce' LIMIT 1");
        return $r && $r->num_rows && (string)$r->fetch_assoc()['setting_val'] === '1'; }
    catch (\Throwable $e) { return false; }
}

// Current entitlement state: verified cached token → tier/max_nodes/status, else unlicensed.
function nm_lic_state($conn): array {
    nm_lic_ensure($conn);
    $out = ['tier'=>'unlicensed','max_nodes'=>null,'status'=>'unlicensed','valid'=>false,'in_grace'=>false,'license_key'=>null];
    try {
        $r = $conn->query("SELECT * FROM nm_license WHERE id=1 LIMIT 1");
        $row = $r ? $r->fetch_assoc() : null;
        if ($row) {
            $out['license_key'] = $row['license_key'] ? (substr($row['license_key'],0,10).'…') : null;
            $out['status'] = $row['status'] ?? 'unlicensed';
            if (!empty($row['token'])) {
                $c = nm_lic_verify_token((string)$row['token']);
                // L1 — bind the token to THIS machine + THIS key (only when enforcement is ON, so
                // default-permissive installs are unaffected). The portal signs `fp` (machine
                // fingerprint) and `lic` (license key) into the token; a token copied to another
                // install has a different local fingerprint → not trusted here. Constant-time.
                if ($c && nm_lic_enforced($conn)) {
                    $fpLocal = nm_lic_fingerprint();
                    $fpOk  = !isset($c['fp'])  || hash_equals((string)$c['fp'],  (string)$fpLocal);
                    $licOk = !isset($c['lic']) || empty($row['license_key']) || hash_equals((string)$c['lic'], (string)$row['license_key']);
                    if (!$fpOk || !$licOk) { $c = null; $out['status'] = 'fingerprint_mismatch'; }
                }
                if ($c) { $out['valid']=true; $out['tier']=(string)($c['tier']??'free'); $out['max_nodes']=$c['max_nodes']??null;
                    $out['in_grace']=!empty($c['_in_grace']); $out['status']=$out['in_grace']?'grace':'active'; }
            }
        }
    } catch (\Throwable $e) {}
    return $out;
}

// The effective tier NEURU should behave as RIGHT NOW.
//  • enforcement OFF → 'enterprise' (full product; nothing gated — current behavior)
//  • enforcement ON  → the verified token's tier (or 'free' if none/invalid)
function nm_lic_active_tier($conn): string {
    if (!nm_lic_enforced($conn)) return 'enterprise';
    $s = nm_lic_state($conn);
    return $s['valid'] ? $s['tier'] : 'free';
}

// THE GATE. Is $featureKey available under the current tier? Default-permissive.
function nm_feature($conn, string $featureKey): bool {
    $matrix = nm_lic_feature_matrix();
    $need = $matrix[$featureKey] ?? 'free';   // unlisted features are always free
    if ($need === 'free') return true;
    return nm_lic_tier_rank(nm_lic_active_tier($conn)) >= nm_lic_tier_rank($need);
}

// Convenience for a paid page: return true if allowed, else render an upsell + stop.
// (Wire this into future exclusive pages; do NOT retrofit onto existing free ones.)
function nm_feature_gate($conn, string $featureKey, string $label = 'This feature'): bool {
    if (nm_feature($conn, $featureKey)) return true;
    $need = ucfirst(nm_lic_feature_matrix()[$featureKey] ?? 'pro');
    if (!headers_sent()) header('Content-Type: text/html; charset=utf-8');
    echo '<div style="max-width:560px;margin:12vh auto;text-align:center;font-family:Segoe UI,sans-serif;color:#e6edf7">'
       . '<div style="font-size:46px;color:#36e3d0;margin-bottom:10px">&#128274;</div>'
       . '<h1 style="font-size:22px;margin:6px 0">'.htmlspecialchars($label).' is a '.$need.' feature</h1>'
       . '<p style="color:#8aa2c4;font-size:14px">Upgrade your NEURU license to unlock it. Your admin can manage licensing in Site Configuration.</p></div>';
    return false;
}

// ── license API client (talks to licenseportal /v1). Ready for Phase 4 API. ──
// The License Portal API base is SHIPPED WITH THE BUILD (updated via product updates,
// never by the end user — the license.php field is read-only). Change this one line when
// the portal URL changes and cut a release. A legacy DB setting is only a fallback if this
// is ever blanked.
if (!defined('NM_LIC_API_BASE')) define('NM_LIC_API_BASE', 'https://neurunetpr.com/api.php');
function nm_lic_api_base($conn): string {
    $u = defined('NM_LIC_API_BASE') ? (string)NM_LIC_API_BASE : '';
    if ($u === '' && $conn instanceof mysqli) { try { $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='license_api_url' LIMIT 1"); if($r&&$r->num_rows)$u=(string)$r->fetch_assoc()['setting_val']; } catch(\Throwable $e){} }
    return rtrim($u ?: '', '/');
}
function nm_lic_http($url, array $body): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_POST=>true, CURLOPT_TIMEOUT=>15,
        CURLOPT_HTTPHEADER=>['Content-Type: application/json'], CURLOPT_POSTFIELDS=>json_encode($body)]);
    $res = curl_exec($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); $err=curl_error($ch); curl_close($ch);
    if ($res === false) return ['ok'=>false,'error'=>$err ?: 'connection failed'];
    $j = json_decode((string)$res, true);
    return ['ok'=>$code>=200&&$code<300, 'code'=>$code, 'json'=>is_array($j)?$j:null, 'raw'=>$res];
}
// Activate this install with a license key (Phase 4 endpoint).
function nm_lic_activate($conn, string $licenseKey): array {
    nm_lic_ensure($conn);
    $base = nm_lic_api_base($conn); if ($base==='') return ['ok'=>false,'error'=>'license_api_url not configured'];
    $fp = nm_lic_fingerprint();
    $r = nm_lic_http($base.'/v1/activate', ['license_key'=>$licenseKey,'fingerprint'=>$fp,'hostname'=>gethostname(),'app_version'=>nm_lic_app_version($conn)]);
    if (!empty($r['ok']) && !empty($r['json']['token']) && nm_lic_verify_token($r['json']['token'])) {
        nm_lic_store($conn, $licenseKey, $r['json']['token'], $fp);
        return ['ok'=>true,'state'=>nm_lic_state($conn)];
    }
    return ['ok'=>false,'error'=>$r['json']['error'] ?? ('activation failed'.(isset($r['code'])?' (HTTP '.$r['code'].')':''))];
}
// Revalidate + report node count (Phase 4 heartbeat).
function nm_lic_validate($conn): array {
    nm_lic_ensure($conn);
    $base = nm_lic_api_base($conn); if ($base==='') return ['ok'=>false,'error'=>'not configured'];
    $row = $conn->query("SELECT license_key FROM nm_license WHERE id=1")->fetch_assoc();
    $key = $row['license_key'] ?? ''; if ($key==='') return ['ok'=>false,'error'=>'not activated'];
    $nodes = (int)($conn->query("SELECT COUNT(*) c FROM nm_nodes")->fetch_assoc()['c'] ?? 0);
    $r = nm_lic_http($base.'/v1/validate', ['license_key'=>$key,'fingerprint'=>nm_lic_fingerprint(),'node_count'=>$nodes,'app_version'=>nm_lic_app_version($conn)]);
    if (!empty($r['ok']) && !empty($r['json']['token']) && nm_lic_verify_token($r['json']['token'])) {
        nm_lic_store($conn, $key, $r['json']['token'], nm_lic_fingerprint());
        return ['ok'=>true,'warning'=>$r['json']['warning'] ?? null,'state'=>nm_lic_state($conn)];
    }
    // L2 — honor a DEFINITIVE server rejection: drop the cached token so the entitlement falls to
    // 'free' NOW (was: the paid token survived in-grace for ~14 days, making revocation toothless).
    // Only on a real reject (revoked/expired/not_activated/invalid_key, or HTTP 403/404/409). A
    // network/timeout/5xx error carries no such code → token is KEPT (offline fail-safe).
    $code   = (int)($r['code'] ?? 0);
    $reason = (string)($r['json']['error'] ?? '');
    $definitive = in_array($reason, ['revoked','expired','not_activated','invalid_key','deactivated','canceled'], true)
               || in_array($code, [403, 404, 409], true);
    if ($definitive) {
        try {
            $s = $reason ?: ('rejected_' . $code);
            $e = 'Portal rejected the license: ' . ($reason ?: ('HTTP ' . $code)) . ' — cached token cleared.';
            $st = $conn->prepare("UPDATE nm_license SET token=NULL, status=?, last_error=?, last_check=NOW() WHERE id=1");
            $st->bind_param('ss', $s, $e); $st->execute(); $st->close();
        } catch (\Throwable $ex) { /* best-effort */ }
    }
    return ['ok'=>false,'error'=>$reason ?: 'validate failed', 'definitive'=>$definitive];
}
function nm_lic_store($conn, string $key, string $token, string $fp): void {
    $c = nm_lic_verify_token($token) ?: [];
    $tier=(string)($c['tier']??'free'); $mx=isset($c['max_nodes'])?($c['max_nodes']===null?null:(int)$c['max_nodes']):null;
    $grace=isset($c['grace_until'])?date('Y-m-d H:i:s',(int)$c['grace_until']):null;
    $st=$conn->prepare("UPDATE nm_license SET license_key=?, token=?, tier=?, max_nodes=?, status='active', fingerprint=?, grace_until=?, last_check=NOW(), last_error=NULL WHERE id=1");
    $st->bind_param('sssiss',$key,$token,$tier,$mx,$fp,$grace); $st->execute();
}
function nm_lic_app_version($conn): string {
    if (defined('NEURU_VERSION')) return NEURU_VERSION;
    $vf = __DIR__ . '/VERSION';   // canonical single source (read when about.php isn't loaded, e.g. cron)
    if (is_file($vf)) { $v = trim((string)@file_get_contents($vf)); if ($v !== '') return $v; }
    return '0.1.1';
}

// Raw single-row license state (for the admin Licensing page).
function nm_lic_row($conn): ?array {
    nm_lic_ensure($conn);
    $r = @$conn->query("SELECT * FROM nm_license WHERE id=1 LIMIT 1");
    return $r ? ($r->fetch_assoc() ?: null) : null;
}

// Billing & Balance summary from the Portal (plan · next payment · AI credits remaining) for the
// customer's own transparency view. Resolves by license_key+fingerprint OR conn_key (AI-enrolled).
// Free/perpetual → subscription null (monthly balance $0). Never throws; returns ['ok'=>false,...] on error.
function nm_lic_billing($conn): array {
    $base = nm_lic_api_base($conn); if ($base === '') return ['ok'=>false,'error'=>'Portal API URL not configured'];
    $row = nm_lic_row($conn); $lk = is_array($row) ? (string)($row['license_key'] ?? '') : '';
    $ck = '';
    if ($conn instanceof mysqli) { try { $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='ai_conn_key' LIMIT 1"); if($r&&$r->num_rows)$ck=(string)$r->fetch_assoc()['setting_val']; } catch(\Throwable $e){} }
    if ($lk === '' && $ck === '') return ['ok'=>false,'error'=>'This install is not licensed yet'];
    $r = nm_lic_http($base.'/v1/billing', ['license_key'=>$lk, 'fingerprint'=>nm_lic_fingerprint(), 'conn_key'=>$ck, 'product'=>'neuru']);
    if (empty($r['ok']) || !is_array($r['json'] ?? null)) return ['ok'=>false,'error'=>($r['json']['error'] ?? ('Portal returned '.($r['code'] ?? 0)))];
    return $r['json'];
}
// Deactivate this install: free the portal activation slot + clear the local token.
function nm_lic_deactivate($conn): array {
    nm_lic_ensure($conn);
    $row = nm_lic_row($conn); $key = $row['license_key'] ?? '';
    $base = nm_lic_api_base($conn);
    if ($base !== '' && $key !== '') {
        nm_lic_http($base . '/v1/deactivate', ['license_key' => $key, 'fingerprint' => ($row['fingerprint'] ?? '') ?: nm_lic_fingerprint()]);
    }
    $conn->query("UPDATE nm_license SET token=NULL, tier='unlicensed', status='unlicensed', max_nodes=NULL, grace_until=NULL, license_key=NULL, last_error=NULL WHERE id=1");
    return ['ok' => true];
}
// Settings helpers (nm_settings).
function nm_lic_set_setting($conn, string $key, string $val): void {
    if (!($conn instanceof mysqli)) return;
    $st = $conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES (?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
    $st->bind_param('ss', $key, $val); $st->execute();
}

// ── Node-limit enforcement ───────────────────────────────────────────────────
// The effective node ceiling RIGHT NOW, or null = unlimited / not enforced.
//  • enforcement OFF                → null (unlimited; current behavior)
//  • enforcement ON + no valid token→ null (permissive — never lock out an install
//                                     that hasn't activated; free requires activation)
//  • enforcement ON + token         → the token's max_nodes (null = unlimited plan)
function nm_lic_node_limit($conn): ?int {
    if (!nm_lic_enforced($conn)) return null;
    $s = nm_lic_state($conn);
    if (empty($s['valid'])) return null;
    return $s['max_nodes'] === null ? null : (int)$s['max_nodes'];
}
function nm_lic_node_count($conn): int {
    if (!($conn instanceof mysqli)) return 0;
    try { $r = $conn->query("SELECT COUNT(*) c FROM nm_nodes"); return $r ? (int)($r->fetch_assoc()['c'] ?? 0) : 0; }
    catch (\Throwable $e) { return 0; }
}
// Can we add $n more nodes under the current license? Returns a structured verdict.
//   ['ok'=>bool,'limit'=>int|null,'current'=>int,'remaining'=>int|null]
function nm_lic_can_add_nodes($conn, int $n = 1): array {
    $limit = nm_lic_node_limit($conn);
    $cur   = nm_lic_node_count($conn);
    if ($limit === null) return ['ok'=>true,'limit'=>null,'current'=>$cur,'remaining'=>null];
    $ok = ($cur + max(1,$n)) <= $limit;
    return ['ok'=>$ok,'limit'=>$limit,'current'=>$cur,'remaining'=>max(0,$limit-$cur)];
}
// Human-friendly message when an add is blocked (reuse across node-add paths).
function nm_lic_node_block_msg(array $verdict): string {
    return 'License node limit reached — this NEURU license allows '
        . (int)$verdict['limit'] . ' node' . ((int)$verdict['limit']===1?'':'s')
        . ' and ' . (int)$verdict['current'] . ' are already configured. '
        . 'Upgrade your license in Site Configuration → Licensing, or turn off enforcement.';
}

// ── Badge state for the top-bar indicator (best-effort, cheap) ───────────────
// Returns ['tier','licensed'(bool),'label','color'] describing what to show.
function nm_lic_badge_state($conn): array {
    $s = nm_lic_state($conn);
    if (!empty($s['valid'])) {
        $tier = strtolower((string)($s['tier'] ?: 'free'));
        return ['tier'=>$tier, 'licensed'=>true,
                'label'=>ucfirst($tier), 'color'=>'#36e3d0', 'in_grace'=>!empty($s['in_grace'])];
    }
    return ['tier'=>'unlicensed', 'licensed'=>false,
            'label'=>'Unlicensed', 'color'=>'#f0a92c', 'in_grace'=>false];
}

} // end guard
