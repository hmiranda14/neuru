<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Stream Decks (stream_decks.php)
// Config + live WEB PREVIEW of a VSDinside / Elgato pad, plus the JSON/SSE API the
// on-PC plugin consumes. Brain: nm_deck.php. RBAC: 'stream_decks'.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
// NOTE: check.php (the login gate — it 302-redirects unauthenticated requests) is intentionally NOT
// included here. The token-authenticated ?api= endpoints below (the on-PC plugin has NO session cookie)
// MUST run before any login redirect. check.php is included later, only for the HTML page render.
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_deck.php');
include('logger.php');
if (session_status() === PHP_SESSION_NONE) @session_start();   // load an existing session so the in-portal UI's ?api= calls authenticate by RBAC

$api = $_GET['api'] ?? '';

// ── Plugin-facing endpoints authenticate by bearer TOKEN (no session); the in-portal
//    UI endpoints authenticate by RBAC session. Decide which gate applies. ───────────
$tokenEndpoints = ['telemetry', 'stream', 'action', 'knob', 'render', 'ping', 'plugin_download', 'plog', 'bind', 'binds', 'node_metrics'];
$isTokenCall = in_array($api, $tokenEndpoints, true);

function _deck_bearer(): string {
    $h = $_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['HTTP_X_NEURU_DECK'] ?? '');
    if (stripos($h, 'bearer ') === 0) $h = substr($h, 7);
    if ($h === '' && isset($_GET['token'])) $h = (string)$_GET['token'];
    return trim($h);
}

if ($api !== '') {
    header('Content-Type: application/json');
    if (function_exists('session_write_close')) @session_write_close();

    // CORS — the on-PC plugin fetches cross-origin (its WebView origin ≠ NEURU). Allow any origin + the
    // custom headers, and answer the preflight (OPTIONS, sent because of the custom/Content-Type headers).
    if ($isTokenCall) {
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, X-NEURU-DECK, X-NEURU-FMT, X-NEURU-BASE');
        header('Access-Control-Max-Age: 86400');
        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') { http_response_code(204); exit; }
    }

    // auth: token-facing endpoints accept the plugin's bearer token OR an in-portal RBAC session
    // (so the live preview can drive them too). Check the token FIRST so plugin polling never
    // audit-spams a session denial; fall back to checkAccess only when a session actually exists.
    $authed = false;
    if ($isTokenCall) {
        $want = nm_deck_token($conn, false); $bear = _deck_bearer();
        if ($want !== '' && $bear !== '' && hash_equals($want, $bear)) $authed = true;
        elseif (!empty($_SESSION['UID'])) $authed = checkAccess($conn, 'stream_decks');
    } else {
        $authed = checkAccess($conn, 'stream_decks');
    }
    if (!$authed) { http_response_code(403); echo json_encode(['ok' => false, 'error' => 'forbidden']); exit; }

    try {
        // ── plugin: ping / handshake ──
        if ($api === 'ping') {
            $cfg = nm_deck_config($conn);
            echo json_encode(['ok' => true, 'neuru' => 'stream-decks', 'model' => $cfg['model'], 'spec' => $cfg['spec'],
                'refresh' => $cfg['refresh'], 'profile' => $cfg['profile'], 'knobs' => $cfg['knobs'],
                'catalog' => nm_deck_action_catalog(), 'knob_catalog' => nm_deck_knob_catalog(),
                'rigs' => nm_deck_rigs($conn), 'nodes' => nm_deck_nodes($conn), 'default_rig' => $cfg['rig']]); exit;
        }
        // ── download the plugin as a .zip (PC pulls it during deploy; user can also grab it manually).
        //    ?base= present → inject defaults.json so the plugin auto-configures (zero typing). ──
        if ($api === 'plugin_download') {
            // fmt/base accepted via query (browser manual) OR header (auto-deploy — its cmd URL can't
            // carry '&', so the plugin cmd sends X-NEURU-FMT / X-NEURU-BASE headers instead).
            $fmt = (($_GET['fmt'] ?? '') === 'tar' || ($_SERVER['HTTP_X_NEURU_FMT'] ?? '') === 'tar') ? 'tar' : 'zip';
            $injBase = isset($_GET['base']) ? rtrim((string)$_GET['base'], '/') : rtrim((string)($_SERVER['HTTP_X_NEURU_BASE'] ?? ''), '/');
            $tmp = nm_deck_plugin_zip($injBase, $injBase !== '' ? nm_deck_token($conn, false) : '', $fmt);
            if (!$tmp || !is_file($tmp)) { http_response_code(500); echo json_encode(['ok' => false, 'error' => 'package build failed']); exit; }
            header('Content-Type: ' . ($fmt === 'tar' ? 'application/x-tar' : 'application/zip'));
            header('Content-Disposition: attachment; filename="com.neuru.noc.sdPlugin.' . $fmt . '"');
            header('Content-Length: ' . filesize($tmp));
            readfile($tmp); @unlink($tmp); exit;
        }
        // ── plugin/UI: render ONE key's face as SVG (what the device displays) ──
        if ($api === 'render') {
            header('Cache-Control: no-cache');
            $key = (string)($_GET['key'] ?? '');
            // per-tile target: &tgt=r5 (rig) | n12 (node) | noc/'' (whole NOC). Back-compat: &rig=N → rN.
            $tgt = (string)($_GET['tgt'] ?? '');
            if ($tgt === '' && isset($_GET['rig'])) $tgt = 'r' . (int)$_GET['rig'];
            // PNG is the reliable setImage format on Stream Dock (SVG data URIs are flaky). enc=datauri
            // returns the base64 data-URI as TEXT so the plugin can setImage it directly.
            $transparent = !empty($_GET['t']);   // touch bar / knob → transparent bg (blends with the pad wallpaper)
            try { $png = nm_deck_render_png($conn, $key, $tgt, $transparent); } catch (\Throwable $e) { $png = ''; }
            if ($png === '') {   // GD fallback → SVG (still valid for the web <img>)
                header('Content-Type: image/svg+xml'); echo nm_deck_render_svg($conn, $key, nm_deck_resolve_rig($conn, $tgt)); exit;
            }
            if (($_GET['enc'] ?? '') === 'datauri') {
                header('Content-Type: text/plain'); echo 'data:image/png;base64,' . base64_encode($png); exit;
            }
            header('Content-Type: image/png'); echo $png; exit;
        }
        // ── plugin debug log (diagnostic — app.js/PI report events here so we can see live behavior) ──
        if ($api === 'plog') {
            $m = substr(preg_replace('/[\r\n]+/', ' ', (string)($_GET['m'] ?? '')), 0, 300);
            @file_put_contents(__DIR__ . '/logs/deck_plog.log', gmdate('H:i:s') . ' ' . $m . "\n", FILE_APPEND | LOCK_EX);
            echo json_encode(['ok' => true]); exit;
        }
        // ── PI↔plugin BRIDGE: this Stream Dock build does NOT deliver setSettings/sendToPlugin to the
        //    plugin backend, so a live-added tile's key never reaches it. The PI records the context→key
        //    binding here; the plugin resolves keys from ?api=binds in its loop. ──
        if ($api === 'bind') {
            // MERGE bind fields: the PI sends key/tgt; the plugin sends col/row/ctrl (position) on willAppear.
            // Together they let the in-portal preview MIRROR the real device layout. key='' removes the bind.
            $ctx = substr((string)($_GET['ctx'] ?? ''), 0, 80);
            if ($ctx !== '') {
                $binds = json_decode(nm_deck_get($conn, 'deck_binds', ''), true); if (!is_array($binds)) $binds = [];
                $cur = $binds[$ctx] ?? []; if (is_string($cur)) $cur = ['k' => $cur]; if (!is_array($cur)) $cur = [];
                // off=1 → tile left the visible page (willDisappear): keep its data, just mark inactive so the
                // mirror follows the device's CURRENT page instead of stacking every page onto one grid.
                if (isset($_GET['off'])) { if (isset($binds[$ctx])) { $cur['a'] = 0; $binds[$ctx] = $cur; nm_deck_set($conn, 'deck_binds', json_encode($binds)); } echo json_encode(['ok' => true]); exit; }
                $cur['a'] = 1;   // any other bind report = this tile is on the visible page now
                if (isset($_GET['key'])) {
                    $k = substr((string)$_GET['key'], 0, 40);
                    if ($k === '') { unset($binds[$ctx]); nm_deck_set($conn, 'deck_binds', json_encode($binds)); echo json_encode(['ok' => true]); exit; }
                    $cur['k'] = $k;
                }
                if (isset($_GET['tgt']))  $cur['t']    = substr(preg_replace('/[^a-z0-9]/i', '', (string)$_GET['tgt']), 0, 12);
                if (isset($_GET['col']))  $cur['c']    = max(0, min(20, (int)$_GET['col']));
                if (isset($_GET['row']))  $cur['r']    = max(0, min(20, (int)$_GET['row']));
                if (isset($_GET['ctrl'])) $cur['ctrl'] = substr(preg_replace('/[^a-z]/i', '', (string)$_GET['ctrl']), 0, 20);
                $binds[$ctx] = $cur;
                if (count($binds) > 200) $binds = array_slice($binds, -200, null, true);
                nm_deck_set($conn, 'deck_binds', json_encode($binds));
            }
            echo json_encode(['ok' => true]); exit;
        }
        if ($api === 'binds') {
            $binds = json_decode(nm_deck_get($conn, 'deck_binds', ''), true);
            echo json_encode(['ok' => true, 'binds' => is_array($binds) && $binds ? $binds : (object)[]]); exit;
        }
        // the metric list a specific node offers (dynamic — device_stats/traffic/status), for the PI dropdown
        if ($api === 'node_metrics') {
            echo json_encode(['ok' => true, 'metrics' => nm_deck_node_metrics_list($conn, (int)($_GET['node'] ?? 0))]); exit;
        }
        // ── plugin/UI: live telemetry snapshot ──
        if ($api === 'telemetry') {
            $rig = isset($_GET['rig']) ? (int)$_GET['rig'] : null;
            echo json_encode(['ok' => true, 'snap' => nm_deck_telemetry($conn, $rig, isset($_GET['force']))]); exit;
        }
        // ── plugin/UI: realtime SSE telemetry stream ──
        if ($api === 'stream') {
            header('Content-Type: text/event-stream');
            header('Cache-Control: no-cache');
            header('X-Accel-Buffering: no');
            @set_time_limit(0); while (ob_get_level() > 0) @ob_end_flush(); @ini_set('zlib.output_compression', '0');
            $send = function ($ev, $data) { echo "event: {$ev}\ndata: " . json_encode($data) . "\n\n"; @ob_flush(); @flush(); };
            $rig = isset($_GET['rig']) ? (int)$_GET['rig'] : null;
            $cfg = nm_deck_config($conn);
            $start = time(); $tick = 0;
            while (!connection_aborted() && (time() - $start) < 280) {
                $send('telemetry', nm_deck_telemetry($conn, $rig, false));
                $tick++;
                // poll cadence: honor refresh but never hammer; SSE re-emits cached between SSH refreshes
                for ($i = 0; $i < max(3, min(30, $cfg['refresh'])); $i++) { if (connection_aborted()) break; sleep(1); }
            }
            $send('done', ['ts' => time()]); exit;
        }
        // ── plugin/UI: execute a bound action ──
        if ($api === 'action') {
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') { echo json_encode(['ok' => false, 'error' => 'POST required']); exit; }
            $b = json_decode(file_get_contents('php://input'), true) ?: [];
            $act = (string)($b['action'] ?? ($_GET['action'] ?? ''));
            // run on the tile's target rig (per-tile), else the default rig
            $rig = isset($b['tgt']) && $b['tgt'] !== '' ? nm_deck_resolve_rig($conn, (string)$b['tgt']) : (int)($b['rig'] ?? ($_GET['rig'] ?? nm_deck_config($conn)['rig']));
            $res = nm_deck_run_action($conn, $rig, $act, is_array($b['args'] ?? null) ? $b['args'] : []);
            nm_audit($conn, 'deck.action', ['details' => ['action' => $act, 'rig' => $rig, 'ok' => !empty($res['ok'])]]);
            echo json_encode(['ok' => !empty($res['ok'])] + $res); exit;
        }
        // ── plugin/UI: rotary-knob event (DialRotate / DialDown) ──
        if ($api === 'knob') {
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') { echo json_encode(['ok' => false, 'error' => 'POST required']); exit; }
            $b = json_decode(file_get_contents('php://input'), true) ?: [];
            $idx = (int)($b['knob'] ?? 0);
            $ticks = (int)($b['ticks'] ?? 0);
            $pressed = !empty($b['pressed']);
            $rig = (int)($b['rig'] ?? nm_deck_config($conn)['rig']);
            $res = nm_deck_run_knob($conn, $rig, $idx, $ticks, $pressed);
            echo json_encode(['ok' => !empty($res['ok'])] + $res); exit;
        }

        // ── UI (session-gated) endpoints ──
        if ($api === 'config') {
            $cfg = nm_deck_config($conn);
            require_once('nm_winhost.php');
            $rigs = [];
            try { foreach ((array)nm_win_hosts($conn) as $r) $rigs[] = ['id' => (int)$r['id'], 'name' => (string)($r['name'] ?? ('rig ' . $r['id']))]; } catch (\Throwable $e) {}
            $icons = [];
            foreach (array_keys(nm_deck_action_catalog()) as $k) { $ip = nm_deck_get($conn, 'deck_icon_' . $k, ''); if ($ip !== '') $icons[$k] = $ip; }
            echo json_encode(['ok' => true, 'cfg' => $cfg, 'models' => nm_deck_models(), 'catalog' => nm_deck_action_catalog(),
                'knob_catalog' => nm_deck_knob_catalog(), 'rigs' => $rigs, 'nodes' => nm_deck_nodes($conn), 'icons' => $icons, 'token' => nm_deck_token($conn, true),
                'endpoint' => (((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . '/stream_decks.php')]); exit;
        }
        if ($api === 'save') {
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') { echo json_encode(['ok' => false, 'error' => 'POST required']); exit; }
            $b = json_decode(file_get_contents('php://input'), true) ?: [];
            if (isset($b['model']) && isset(nm_deck_models()[$b['model']])) nm_deck_set($conn, 'deck_model', (string)$b['model']);
            if (isset($b['custom']) && is_array($b['custom'])) {
                foreach (['cols' => 'deck_custom_cols', 'rows' => 'deck_custom_rows', 'knobs' => 'deck_custom_knobs'] as $bk => $sk)
                    if (isset($b['custom'][$bk])) nm_deck_set($conn, $sk, (string)max(0, (int)$b['custom'][$bk]));
                if (array_key_exists('touch', $b['custom'])) nm_deck_set($conn, 'deck_custom_touch', !empty($b['custom']['touch']) ? '1' : '0');
            }
            if (array_key_exists('auto', $b))    nm_deck_set($conn, 'deck_automodel', !empty($b['auto']) ? '1' : '0');
            if (array_key_exists('rig', $b))     nm_deck_set($conn, 'deck_rig', (string)(int)$b['rig']);
            if (array_key_exists('refresh', $b)) nm_deck_set($conn, 'deck_refresh', (string)max(5, min(120, (int)$b['refresh'])));
            if (array_key_exists('plugins_dir', $b)) nm_deck_set($conn, 'deck_plugins_dir', substr(trim((string)$b['plugins_dir']), 0, 400));
            if (array_key_exists('plugin_base', $b)) nm_deck_set($conn, 'deck_plugin_base', rtrim(substr(trim((string)$b['plugin_base']), 0, 300), '/'));
            if (isset($b['knobs']) && is_array($b['knobs']))    nm_deck_set($conn, 'deck_knobs', json_encode(array_values($b['knobs'])));
            if (isset($b['model']) && isset($b['pages'])) nm_deck_set($conn, 'deck_pages_' . (string)$b['model'], (string)max(1, min(8, (int)$b['pages'])));
            if (isset($b['profile']) && is_array($b['profile']) && isset($b['model'])) {
                $pg = max(1, (int)($b['page'] ?? 1));
                $pk = $pg === 1 ? ('deck_profile_' . (string)$b['model']) : ('deck_profile_' . (string)$b['model'] . '_p' . $pg);
                nm_deck_set($conn, $pk, json_encode(array_values($b['profile'])));
            }
            nm_audit($conn, 'deck.save', ['details' => ['model' => $b['model'] ?? '', 'rig' => $b['rig'] ?? '']]);
            echo json_encode(['ok' => true]); exit;
        }
        if ($api === 'deploy') {
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') { echo json_encode(['ok' => false, 'error' => 'POST required']); exit; }
            $b = json_decode(file_get_contents('php://input'), true) ?: [];
            $rig = (int)($b['rig'] ?? nm_deck_config($conn)['rig']);
            $base = (string)($b['base'] ?? '');
            $res = nm_deck_deploy($conn, $rig, $base, nm_deck_token($conn, true));
            nm_audit($conn, 'deck.deploy', ['details' => ['rig' => $rig, 'ok' => !empty($res['ok'])]]);
            echo json_encode($res); exit;
        }
        if ($api === 'upload_icon') {   // per-catalog-key custom icon/background (session-gated)
            if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !isset($_FILES['icon'])) { echo json_encode(['ok' => false, 'error' => 'POST + file required']); exit; }
            $key = substr(preg_replace('/[^a-z0-9_]/i', '', (string)($_POST['key'] ?? '')), 0, 40);
            if ($key === '' || !isset(nm_deck_action_catalog()[$key])) { echo json_encode(['ok' => false, 'error' => 'valid key required']); exit; }
            require_once('nm_media.php');
            if (function_exists('nm_media_ensure_dir')) nm_media_ensure_dir('streamdecks');
            $r = function_exists('nm_media_store_image') ? nm_media_store_image($_FILES['icon'], 'streamdecks', 'deck', 3 * 1024 * 1024) : ['ok' => false, 'error' => 'uploader unavailable'];
            if (empty($r['ok'])) { echo json_encode(['ok' => false, 'error' => $r['error'] ?? 'upload failed']); exit; }
            $old = nm_deck_get($conn, 'deck_icon_' . $key, ''); if ($old !== '' && function_exists('nm_media_delete')) @nm_media_delete($old);
            nm_deck_set($conn, 'deck_icon_' . $key, $r['path']);
            nm_audit($conn, 'deck.icon', ['details' => ['key' => $key, 'act' => 'upload']]);
            echo json_encode(['ok' => true, 'key' => $key, 'path' => $r['path']]); exit;
        }
        if ($api === 'clear_icon') {
            $key = substr(preg_replace('/[^a-z0-9_]/i', '', (string)($_POST['key'] ?? ($_GET['key'] ?? ''))), 0, 40);
            $old = nm_deck_get($conn, 'deck_icon_' . $key, '');
            if ($old !== '') { require_once('nm_media.php'); if (function_exists('nm_media_delete')) @nm_media_delete($old); }
            nm_deck_set($conn, 'deck_icon_' . $key, '');
            echo json_encode(['ok' => true]); exit;
        }
        if ($api === 'rotate_token') {
            nm_deck_set($conn, 'deck_api_token', 'nvd_' . bin2hex(random_bytes(20)));
            nm_audit($conn, 'deck.rotate_token', []);
            echo json_encode(['ok' => true, 'token' => nm_deck_token($conn, false)]); exit;
        }
        echo json_encode(['ok' => false, 'error' => 'unknown endpoint']); exit;
    } catch (\Throwable $e) {
        http_response_code(500); echo json_encode(['ok' => false, 'error' => $e->getMessage()]); exit;
    }
}

// ── HTML page render: NOW enforce login (check.php) + RBAC, after the token ?api= handlers above ──
include('check.php');
if (!checkAccess($conn, 'stream_decks')) { header('Location: /denied_access.php?page=stream_decks'); exit; }
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
include('header.php');
log_user_action($conn, 'view_page', 'stream_decks.php');
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --sd-bg:#05070d; --sd-glass:rgba(9,14,26,.62); --sd-border:rgba(120,180,255,.16);
       --sd-accent:#4da3ff; --sd-cyan:#38e0ff; --sd-ok:#22e08a; --sd-warn:#ffb020; --sd-crit:#ff4d5e; --sd-na:#5a6472; }
body{ background:#04060c; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; }
.sd-wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 80px; color:#e6ecf5; }
.sd-head{ display:flex; align-items:center; gap:14px; flex-wrap:wrap; margin-bottom:6px; }
.sd-head h1{ margin:0; font-size:23px; font-weight:800; letter-spacing:.3px; }
.sd-head h1 i{ color:var(--sd-cyan); text-shadow:0 0 18px rgba(56,224,255,.5); }
.sd-sub{ color:#8a97ab; font-size:13px; margin:0 0 16px; }
.sd-grid{ display:grid; grid-template-columns:minmax(0,1fr) 340px; gap:20px; align-items:start; }
@media(max-width:920px){ .sd-grid{ grid-template-columns:1fr; } }
.sd-card{ background:var(--sd-glass); border:1px solid var(--sd-border); border-radius:16px; padding:16px 16px 18px;
          backdrop-filter:blur(14px); box-shadow:0 10px 40px rgba(0,10,30,.35); }
.sd-card h3{ margin:0 0 12px; font-size:13px; font-weight:700; text-transform:uppercase; letter-spacing:1.2px; color:#9fb2cc; display:flex; align-items:center; gap:8px; }
.sd-card h3 i{ color:var(--sd-accent); }
/* the physical-pad preview */
.pad{ background:linear-gradient(160deg,#0b0f1a,#070a12); border:1px solid #1b2740; border-radius:22px;
      padding:22px; box-shadow:inset 0 0 60px rgba(0,20,50,.5), 0 20px 60px rgba(0,0,0,.5); position:relative; overflow:hidden; }
.pad::before{ content:''; position:absolute; inset:0; background:radial-gradient(circle at 50% -10%, rgba(56,224,255,.10), transparent 60%); pointer-events:none; }
.pad-brand{ position:absolute; top:10px; right:16px; font-size:10px; letter-spacing:2px; color:#3d5578; font-weight:700; }
.keys{ display:grid; gap:12px; }
.key{ aspect-ratio:1/1; border-radius:12px; background:#0a1220; border:1px solid #1c2c48; display:flex; flex-direction:column;
      align-items:center; justify-content:center; gap:3px; cursor:pointer; position:relative; overflow:hidden; transition:.18s;
      box-shadow:inset 0 0 0 1px rgba(255,255,255,.02); }
.key:hover{ transform:translateY(-2px); border-color:var(--sd-accent); box-shadow:0 8px 22px rgba(77,163,255,.25); }
.key.sel{ outline:2px solid var(--sd-cyan); outline-offset:1px; }
.key .k-ic{ font-size:19px; }
.key .k-val{ font-size:20px; font-weight:800; line-height:1; }
.key .k-lb{ font-size:8.5px; text-transform:uppercase; letter-spacing:.6px; color:#8ea3c4; text-align:center; padding:0 3px; }
.key .k-unit{ font-size:10px; opacity:.7; }
.key.devkey{ padding:0; overflow:hidden; background:transparent; border:none; }
.key.devkey:hover{ transform:translateY(-2px); box-shadow:0 8px 22px rgba(77,163,255,.25); }
.k-svg{ width:100%; height:100%; object-fit:contain; display:block; }
.key.blank{ background:#080d16; border-style:dashed; border-color:#16223a; cursor:pointer; }
.key.blank .k-lb{ color:#3d5170; }
.key.st-ok{ background:linear-gradient(160deg,#08281c,#0a1220); border-color:rgba(34,224,138,.45); }
.key.st-ok .k-ic,.key.st-ok .k-val{ color:var(--sd-ok); }
.key.st-warn{ background:linear-gradient(160deg,#2a2408,#0a1220); border-color:rgba(255,176,32,.5); }
.key.st-warn .k-ic,.key.st-warn .k-val{ color:var(--sd-warn); }
.key.st-crit{ background:linear-gradient(160deg,#2e0a10,#0a1220); border-color:rgba(255,77,94,.6); animation:sdPulse 1.1s infinite; }
.key.st-crit .k-ic,.key.st-crit .k-val{ color:var(--sd-crit); }
.key.act .k-ic{ color:var(--sd-accent); } .key.nav .k-ic{ color:var(--sd-cyan); }
@keyframes sdPulse{ 0%,100%{ box-shadow:0 0 0 0 rgba(255,77,94,.5);} 50%{ box-shadow:0 0 22px 3px rgba(255,77,94,.55);} }
.knobs{ display:flex; gap:18px; justify-content:center; margin-top:16px; flex-wrap:wrap; }
.knob{ text-align:center; }
.knob .dial{ width:56px; height:56px; border-radius:50%; background:conic-gradient(var(--sd-accent) 0 30%, #16233c 30% 100%);
             border:2px solid #24344f; margin:0 auto 6px; position:relative; box-shadow:inset 0 0 12px rgba(0,0,0,.6); }
.knob .dial::after{ content:''; position:absolute; top:6px; left:50%; width:2px; height:12px; background:#cfe6ff; transform:translateX(-50%); border-radius:2px; }
.knob .kl{ font-size:9px; text-transform:uppercase; letter-spacing:.6px; color:#8ea3c4; }
.knob .kval{ font-size:10px; color:var(--sd-cyan); font-weight:700; min-height:12px; margin-top:2px; }
.knob .krow{ display:flex; gap:5px; justify-content:center; margin-top:5px; }
.kbtn{ width:24px; height:22px; border-radius:6px; background:#0d1a2e; border:1px solid #24344f; color:#bcd0ee; cursor:pointer; font-size:14px; line-height:1; }
.kbtn:hover{ border-color:var(--sd-accent); color:#fff; }
.dial.off{ opacity:.4; cursor:default; }
/* page bar (multi-page layouts) */
.pagebar{ display:flex; align-items:center; gap:6px; margin-bottom:12px; flex-wrap:wrap; }
.ppill{ min-width:30px; height:28px; padding:0 8px; border-radius:8px; background:#0c1830; border:1px solid #24344f; color:#9fb2cc; font-size:12px; font-weight:700; cursor:pointer; display:flex; align-items:center; justify-content:center; }
.ppill:hover{ border-color:var(--sd-accent); color:#fff; }
.ppill.on{ background:var(--sd-accent); border-color:var(--sd-accent); color:#04101f; }
.ppill.addp{ color:var(--sd-cyan); } .ppill.lbl{ background:transparent; border:none; color:#7f8faa; font-weight:600; cursor:default; min-width:auto; padding:0 2px; }
.tb-dots span{ cursor:pointer; }
/* wide LCD touch bar (N4/N4 Pro) — mirrors the real strip: status + live readouts + page dots */
.touchbar{ margin-top:16px; min-height:52px; border-radius:10px; background:linear-gradient(90deg,#081324,#0b1c33 55%,#081324); border:1px solid #1c2c48;
           display:flex; align-items:center; justify-content:space-between; gap:14px; padding:8px 16px; box-shadow:inset 0 0 22px rgba(0,20,50,.55); overflow:hidden; }
.tb-l{ display:flex; align-items:center; gap:14px; font-size:11px; }
.tb-stat{ font-weight:800; letter-spacing:1px; text-transform:uppercase; }
.tb-stat.ok{ color:var(--sd-ok); } .tb-stat.crit{ color:var(--sd-crit); }
.tb-read{ display:flex; align-items:center; gap:6px; color:#9fb6d6; }
.tb-read b{ color:#dbe9ff; font-weight:700; } .tb-read i{ color:var(--sd-cyan); }
.tb-dots{ display:flex; gap:6px; }
.tb-dots span{ width:16px; height:16px; border-radius:4px; background:#0e1d33; border:1px solid #24344f; font-size:9px; color:#5a7196; display:flex; align-items:center; justify-content:center; }
.tb-dots span.on{ background:var(--sd-accent); color:#04101f; border-color:var(--sd-accent); font-weight:700; }
.alarm-banner{ display:none; margin:0 0 12px; padding:10px 14px; border-radius:12px; background:linear-gradient(90deg,#2e0a10,#1a0508);
               border:1px solid var(--sd-crit); color:#ffd7db; font-weight:700; font-size:13px; align-items:center; gap:10px; }
.alarm-banner.on{ display:flex; animation:sdPulse 1.1s infinite; }
/* controls */
.fld{ margin-bottom:14px; } .fld label{ display:block; font-size:11px; text-transform:uppercase; letter-spacing:.8px; color:#8ea3c4; margin-bottom:5px; }
.sd-inp,.sd-sel{ width:100%; background:#0a1220; border:1px solid #1e2c46; color:#dbe6f5; border-radius:9px; padding:9px 10px; font-size:13px; }
.sd-inp:focus,.sd-sel:focus{ outline:none; border-color:var(--sd-accent); }
.row2{ display:flex; gap:10px; } .row2>*{ flex:1; }
.badge{ display:inline-flex; align-items:center; gap:5px; font-size:10px; font-weight:700; padding:2px 9px; border-radius:20px; }
.badge.auto{ background:rgba(34,224,138,.14); color:var(--sd-ok); border:1px solid rgba(34,224,138,.4); }
.badge.man{ background:rgba(255,176,32,.14); color:var(--sd-warn); border:1px solid rgba(255,176,32,.4); }
.sd-btn{ background:linear-gradient(135deg,var(--sd-accent),#2f6fd6); color:#fff; border:none; border-radius:9px; padding:9px 14px;
         font-size:13px; font-weight:700; cursor:pointer; display:inline-flex; align-items:center; gap:7px; }
.sd-btn.ghost{ background:transparent; border:1px solid var(--sd-border); color:#bcd0ee; }
.sd-btn:hover{ filter:brightness(1.1); }
.mono{ font-family:ui-monospace,Menlo,Consolas,monospace; font-size:11.5px; background:#070c15; border:1px solid #1a2740; border-radius:8px; padding:8px 10px; word-break:break-all; color:#9fe6ff; }
.pick-grid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(92px,1fr)); gap:8px; max-height:320px; overflow:auto; padding:2px; }
.pick{ background:#0a1220; border:1px solid #1e2c46; border-radius:9px; padding:9px 6px; text-align:center; cursor:pointer; font-size:10.5px; color:#bcd0ee; }
.pick:hover{ border-color:var(--sd-accent); color:#fff; } .pick i{ display:block; font-size:16px; margin-bottom:5px; color:var(--sd-accent); }
.pick.metric i{ color:var(--sd-cyan); } .pick.nav i{ color:#c58cff; }
.dlg{ position:fixed; inset:0; background:rgba(2,5,12,.72); display:none; align-items:center; justify-content:center; z-index:60; }
.dlg.on{ display:flex; } .dlg-box{ width:min(560px,92vw); max-height:86vh; overflow:auto; }
.hint{ font-size:11.5px; color:#7f8faa; line-height:1.5; }
.steps{ font-size:12.5px; color:#c2d2ea; line-height:1.7; padding-left:18px; } .steps code{ background:#0a1526; padding:1px 6px; border-radius:5px; color:#9fe6ff; }
.pc-state{ font-size:11px; padding:3px 8px; border-radius:20px; }
.pc-state.ok{ background:rgba(34,224,138,.14); color:var(--sd-ok);} .pc-state.bad{ background:rgba(255,77,94,.14); color:var(--sd-crit);} .pc-state.none{ background:rgba(90,100,114,.18); color:#8ea3c4;}
</style>

<div class="sd-wrap">
  <div class="sd-head">
    <h1><i class="fa-solid fa-grip"></i> Stream Decks</h1>
    <span id="modelBadge" class="badge auto"><i class="fa-solid fa-magnifying-glass"></i> detecting…</span>
    <span class="badge" style="background:rgba(34,224,138,.14);color:var(--sd-ok);border:1px solid rgba(34,224,138,.4)" title="Verified on VSDinside Stream Dock hardware. Elgato Stream Deck is protocol-compatible but not yet lab-verified."><i class="fa-solid fa-circle-check"></i> Tested: VSDinside</span>
    <span id="pcState" class="pc-state none">PC: —</span>
    <span style="flex:1"></span>
    <button class="sd-btn ghost" onclick="openSetup()"><i class="fa-solid fa-download"></i> Plugin & Setup</button>
  </div>
  <p class="sd-sub">Turn a <b>VSDinside Stream Dock</b> (or any Elgato-compatible pad) into a physical NOC — live telemetry, one-touch fixes, and knob controls, driven by NEURU over your LAN. The preview below <b>mirrors your real device</b>. <span style="color:#6f8">Verified on VSDinside Stream Dock hardware</span>; Elgato Stream Deck is protocol-compatible but not yet lab-verified.</p>

  <div id="alarm" class="alarm-banner"><i class="fa-solid fa-triangle-exclamation"></i> <span id="alarmTxt">CRITICAL STATE</span></div>

  <div class="sd-grid">
    <!-- LIVE PAD PREVIEW -->
    <div class="sd-card">
      <h3><i class="fa-solid fa-display"></i> Live Pad Preview <span id="rigName" style="margin-left:auto;font-weight:600;text-transform:none;letter-spacing:0;color:#8ea3c4;"></span></h3>
      <div id="pageBar" class="pagebar"></div>
      <div class="pad" id="pad">
        <div class="pad-brand" id="padBrand">NEURU · VSD</div>
        <div class="keys" id="keys"></div>
        <div class="touchbar" id="touchbar" style="display:none"></div>
        <div class="knobs" id="knobs"></div>
      </div>
      <div style="display:flex;align-items:center;gap:16px;margin-top:12px;flex-wrap:wrap">
        <label style="display:flex;align-items:center;gap:7px;font-size:12px;cursor:pointer;color:#bcd0ee"><input type="checkbox" id="mirror" style="width:auto" checked onchange="onMirror()"> <i class="fa-solid fa-satellite-dish" style="color:var(--sd-crit)"></i> Mirror my device (live)</label>
        <label style="display:flex;align-items:center;gap:7px;font-size:12px;cursor:pointer;color:#bcd0ee"><input type="checkbox" id="devMode" style="width:auto" onchange="renderPad()"> <i class="fa-solid fa-display"></i> Device render</label>
        <span class="hint" style="margin:0"><i class="fa-solid fa-hand-pointer"></i> Click a key to reassign · Green→Yellow→Red follows real thresholds · metrics = selected rig + whole NOC.</span>
      </div>
    </div>

    <!-- CONFIG -->
    <div>
      <div class="sd-card" style="margin-bottom:20px">
        <h3><i class="fa-solid fa-sliders"></i> Hardware</h3>
        <div class="fld">
          <label>Model <span id="autoState"></span></label>
          <select id="model" class="sd-sel" onchange="onModel()"></select>
        </div>
        <div class="fld" id="customBox" style="display:none">
          <label>Custom layout (any VSDinside unit)</label>
          <div class="row2"><input id="cCols" type="number" min="1" max="10" class="sd-inp" title="columns" onchange="save()"><input id="cRows" type="number" min="1" max="8" class="sd-inp" title="rows" onchange="save()"></div>
          <div class="row2" style="margin-top:8px;align-items:center"><input id="cKnobs" type="number" min="0" max="8" class="sd-inp" title="knobs" onchange="save()"><label style="display:flex;align-items:center;gap:6px;margin:0;flex:1;font-size:12px;cursor:pointer"><input type="checkbox" id="cTouch" style="width:auto" onchange="save()"> touch bar</label></div>
          <div class="hint" style="margin-top:6px">cols × rows = keys · set knobs &amp; touch to match your pad.</div>
        </div>
        <div class="fld" style="display:flex;align-items:center;gap:8px;">
          <input type="checkbox" id="auto" onchange="save()" style="width:auto"> <label style="margin:0;cursor:pointer" onclick="document.getElementById('auto').click()">Auto-detect on connect (fallback to manual)</label>
        </div>
        <div class="fld">
          <label>Monitored Rig (PC)</label>
          <select id="rig" class="sd-sel" onchange="save()"></select>
        </div>
        <div class="fld">
          <label>Telemetry refresh (seconds)</label>
          <input id="refresh" type="number" min="5" max="120" class="sd-inp" onchange="save()">
        </div>
      </div>

      <div class="sd-card" id="knobCard" style="margin-bottom:20px">
        <h3><i class="fa-solid fa-circle-notch"></i> Knob Assignments</h3>
        <div id="knobFields"></div>
      </div>

      <div class="sd-card">
        <h3><i class="fa-solid fa-plug"></i> Connection</h3>
        <p class="hint" style="margin-top:0">The on-PC plugin points at this NEURU endpoint with the token below.</p>
        <div class="fld"><label>Endpoint (this page)</label><div class="mono" id="endpoint">—</div></div>
        <div class="fld">
          <label>Plugin endpoint <span style="color:#ffb020;text-transform:none;letter-spacing:0">(HTTP — required)</span></label>
          <input id="plugbase" class="sd-inp" onchange="save()" placeholder="http://192.168.0.25:8090" autocomplete="off">
          <div class="hint" style="margin-top:5px">The on-PC plugin connects <b>here</b>. Use your NEURU's <b>HTTP</b> URL — the plugin's browser rejects self-signed HTTPS. If blank, deploy falls back to this page's URL.</div>
        </div>
        <div class="fld"><label>API token</label><div class="mono" id="token">—</div></div>
        <div class="fld">
          <label>Plugins folder <span style="color:#5a6472;text-transform:none;letter-spacing:0">(optional — auto-detected if blank)</span></label>
          <input id="plugdir" class="sd-inp" onchange="save()" placeholder="%APPDATA%\HotSpot\StreamDock\plugins" autocomplete="off">
          <div class="hint" style="margin-top:5px">Only set this if you installed Stream Dock / VSD&nbsp;Craft in a custom location and auto-deploy can't find the plugins folder.</div>
        </div>
        <button class="sd-btn ghost" onclick="rotate()"><i class="fa-solid fa-rotate"></i> Rotate token</button>
      </div>

      <div class="sd-card" style="margin-top:20px">
        <h3><i class="fa-solid fa-image"></i> Custom Icons</h3>
        <div class="hint" style="margin-top:-6px;margin-bottom:10px">Optional — upload your own icon/background for any tile (shown behind the live value). Click a tile to upload.</div>
        <div id="iconGrid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(80px,1fr));gap:8px;max-height:320px;overflow:auto;padding:2px"></div>
      </div>
    </div>
  </div>
</div>

<!-- key-assign dialog -->
<div class="dlg" id="pickDlg" onclick="if(event.target===this)closeDlg()">
  <div class="sd-card dlg-box">
    <h3><i class="fa-solid fa-grip"></i> Assign key <span id="pickIdx"></span></h3>
    <div class="pick-grid" id="pickGrid"></div>
    <div style="margin-top:14px;text-align:right"><button class="sd-btn ghost" onclick="assign('')">Clear key</button> <button class="sd-btn ghost" onclick="closeDlg()">Cancel</button></div>
  </div>
</div>

<!-- setup dialog -->
<div class="dlg" id="setupDlg" onclick="if(event.target===this)closeSetup()">
  <div class="sd-card dlg-box">
    <h3><i class="fa-solid fa-download"></i> Plugin & Setup</h3>
    <p class="hint">The NEURU plugin runs on the PC next to VSD&nbsp;Craft (Elgato-compatible) and talks to this NEURU over your LAN. Two ways to install:</p>

    <div class="sd-card" style="margin:10px 0;background:#0a1424">
      <div style="font-weight:700;margin-bottom:6px"><i class="fa-solid fa-bolt" style="color:var(--sd-cyan)"></i> One-click: Deploy to the selected rig</div>
      <p class="hint" style="margin-top:0">NEURU pushes the plugin to the rig over SSH, restarts VSD&nbsp;Craft, and the plugin auto-configures (endpoint + token baked in). Then just drag a <b>NEURU Tile</b> onto the deck once.</p>
      <button class="sd-btn" onclick="deployRig()"><i class="fa-solid fa-rocket"></i> Deploy to <span id="depRig">rig</span></button>
      <div id="depOut" class="hint" style="margin-top:8px"></div>
      <p class="hint" style="margin:8px 0 0;border-top:1px solid rgba(255,255,255,.08);padding-top:8px">
        <i class="fa-solid fa-shield-halved" style="color:var(--sd-warn)"></i> <b>If this is blocked, it's your antivirus — not NEURU.</b> Bitdefender / Defender flags any <i>remote software install</i> by behavior (a dropper pattern), even though this is your own plugin from your own NEURU. To allow it, add an antivirus <b>exception</b> for the folder <code>%appdata%\StreamDock\plugins</code> and retry — or just use the <b>Manual</b> option below, which the AV treats as a normal download.
      </p>
    </div>

    <div class="sd-card" style="margin:10px 0;background:#0a1424">
      <div style="font-weight:700;margin-bottom:6px"><i class="fa-solid fa-download"></i> Manual (AV-safe)</div>
      <label style="display:flex;align-items:center;gap:6px;font-size:12px;margin-bottom:8px;cursor:pointer"><input type="checkbox" id="dlAuto" checked onchange="updateDl()" style="width:auto"> Include my endpoint + token (auto-config — zero typing)</label>
      <ol class="steps" style="margin:6px 0">
        <li><a id="dlPlugin" href="stream_decks.php?api=plugin_download" download><b>Download the plugin .zip</b></a> and unzip into <code>%appdata%/StreamDock/plugins</code>.</li>
        <li>Open VSD&nbsp;Craft → drag a <b>NEURU Tile</b> / <b>NEURU Knob</b> onto the deck.</li>
        <li id="dlStep3">It auto-connects. <span id="dlManualNote" style="display:none">(Or paste the Endpoint + token below into the tile's settings.)</span></li>
      </ol>
      <p class="hint" style="margin:4px 0 0"><i class="fa-solid fa-circle-info"></i> Endpoint: <span class="mono" id="ep2"></span></p>
    </div>
    <div style="margin-top:6px;text-align:right"><button class="sd-btn ghost" onclick="closeSetup()">Close</button></div>
  </div>
</div>

<script>
const FA=(n)=>`<i class="fa-solid fa-${n}"></i>`;
let CFG=null, CAT={}, KNOBCAT={}, MODELS={}, SNAP=null, es=null, pickTarget=-1, KVAL={}, RTS=0, PROFILES={}, PAGE=1, ICONS={}, BINDMAP={};
async function fetchMirror(){ try{ const r=await fetch('stream_decks.php?api=binds').then(r=>r.json()); if(r&&r.binds&&typeof r.binds==='object') BINDMAP=r.binds; }catch(_){} }
function onMirror(){ if(el('mirror')&&el('mirror').checked) fetchMirror().then(renderPad); else renderPad(); }
function mirrorKeyHtml(b){ const tok=encodeURIComponent(el('token').textContent||'');
  const src=`stream_decks.php?api=render&key=${encodeURIComponent(b.k)}&tgt=${encodeURIComponent(b.t||'')}&token=${tok}&_=${RTS}`;
  return `<div class="key devkey" title="${esc(b.k)}"><img class="k-svg" src="${src}" alt=""></div>`;
}
const el=(id)=>document.getElementById(id);
function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

async function boot(){
  const r=await fetch('stream_decks.php?api=config').then(r=>r.json()).catch(()=>null);
  if(!r||!r.ok){ el('keys').innerHTML='<div style="color:#ff6b78;padding:20px">Failed to load config.</div>'; return; }
  CFG=r.cfg; CAT=r.catalog; KNOBCAT=r.knob_catalog; MODELS=r.models; initPages();
  // models dropdown
  el('model').innerHTML=Object.entries(MODELS).map(([k,m])=>`<option value="${k}" ${k===CFG.model?'selected':''}>${m.name} · ${m.keys} keys${m.knobs?(' · '+m.knobs+' knobs'):''}</option>`).join('');
  // rigs
  el('rig').innerHTML='<option value="0">— NOC only (no PC) —</option>'+r.rigs.map(x=>`<option value="${x.id}" ${x.id===CFG.rig?'selected':''}>${x.name}</option>`).join('');
  el('refresh').value=CFG.refresh; el('auto').checked=CFG.auto;
  el('endpoint').textContent=r.endpoint; el('ep2').textContent=r.endpoint;
  el('token').textContent=r.token;
  el('plugdir').value=CFG.plugins_dir||'';
  el('plugbase').value=CFG.plugin_base||'';
  el('modelBadge').className='badge '+(CFG.auto?'auto':'man');
  el('modelBadge').innerHTML=(CFG.auto?FA('magnifying-glass')+' auto':FA('hand')+' manual')+' · '+MODELS[CFG.model].name;
  ICONS=r.icons||{};
  await fetchMirror();
  renderKnobs(); renderPad(); syncCustomUI(); renderIcons(); startStream();
}
function renderIcons(){
  const box=el('iconGrid'); if(!box)return; let h='';
  for(const [k,c] of Object.entries(CAT)){ const has=ICONS[k];
    h+=`<div class="pick" style="position:relative;cursor:default;padding:8px 4px">
        <label style="cursor:pointer;display:block" title="Upload icon for ${c.label}">
          ${has?`<img src="${has}?_=${RTS||1}" style="width:36px;height:36px;object-fit:cover;border-radius:6px">`:`<i class="fa-solid fa-${c.icon}" style="font-size:20px;color:var(--sd-cyan);display:block;margin-bottom:5px"></i>`}
          <input type="file" accept="image/*" style="display:none" onchange="uploadIcon('${k}',this)">
        </label>
        <div style="font-size:9.5px;margin-top:3px;color:#bcd0ee">${c.label}</div>
        ${has?`<button onclick="clearIcon('${k}')" title="Remove" style="position:absolute;top:2px;right:2px;background:rgba(0,0,0,.55);border:none;color:#ff6b78;border-radius:4px;cursor:pointer;font-size:12px;width:17px;height:17px;line-height:1;padding:0">×</button>`:''}
      </div>`; }
  box.innerHTML=h;
}
async function uploadIcon(key,input){
  if(!input.files||!input.files[0])return;
  const fd=new FormData(); fd.append('key',key); fd.append('icon',input.files[0]);
  const r=await fetch('stream_decks.php?api=upload_icon',{method:'POST',body:fd}).then(r=>r.json()).catch(()=>({ok:false,error:'network'}));
  if(r&&r.ok){ ICONS[key]=r.path; RTS=Date.now(); renderIcons(); renderPad(); } else alert('Upload failed: '+((r&&r.error)||'?'));
  input.value='';
}
async function clearIcon(key){
  await fetch('stream_decks.php?api=clear_icon&key='+encodeURIComponent(key),{method:'POST'}).catch(()=>{});
  delete ICONS[key]; RTS=Date.now(); renderIcons(); renderPad();
}

function initPages(){ PROFILES=CFG.profiles||{1:CFG.profile}; if(!PROFILES[PAGE])PAGE=1; CFG.profile=PROFILES[PAGE]||[]; }
function renderPages(){
  const bar=el('pageBar'); if(!bar)return; const n=CFG.pages||1;
  // In mirror mode the DEVICE drives which page is shown (via willAppear/willDisappear), so page tabs
  // wouldn't switch anything — show a live badge instead of dead tabs.
  if(el('mirror')&&el('mirror').checked){ bar.innerHTML='<span class="ppill lbl">PAGES</span><div class="ppill on" title="Whatever page is showing on the device right now"><i class="fa-solid fa-circle" style="color:#e74c3c;font-size:8px;margin-right:5px"></i>LIVE · device page</div>'; return; }
  let h='<span class="ppill lbl">PAGES</span>';
  for(let p=1;p<=n;p++) h+=`<div class="ppill ${p===PAGE?'on':''}" onclick="switchPage(${p})" title="Page ${p}">${p}</div>`;
  if(n<8) h+=`<div class="ppill addp" onclick="addPage()" title="Add page"><i class="fa-solid fa-plus"></i></div>`;
  if(n>1) h+=`<div class="ppill" onclick="removePage()" title="Remove last page" style="color:#e07a86"><i class="fa-solid fa-minus"></i></div>`;
  bar.innerHTML=h;
}
function switchPage(p){ if(p===PAGE)return; PAGE=p; CFG.profile=PROFILES[PAGE]||[]; renderPad(); }
async function addPage(){ CFG.pages=Math.min(8,(CFG.pages||1)+1); await save(); PAGE=CFG.pages; CFG.profile=PROFILES[PAGE]||[]; renderPad(); }
async function removePage(){ if((CFG.pages||1)<=1)return; if(!confirm('Remove page '+CFG.pages+'?'))return; CFG.pages=(CFG.pages||1)-1; if(PAGE>CFG.pages)PAGE=CFG.pages; await save(); CFG.profile=PROFILES[PAGE]||[]; renderPad(); }
function renderPad(){
  renderPages();
  const m=MODELS[CFG.model]; el('padBrand').textContent='NEURU · '+m.name.replace('Stream Dock ','');
  el('rigName').textContent=el('rig').selectedOptions[0]?.textContent||'';
  const kEl=el('keys'); kEl.style.gridTemplateColumns=`repeat(${m.cols},1fr)`;
  let html='';
  // only ACTIVE binds (the tiles on the device's CURRENT page). Once the upgraded plugin runs it stamps a=1/0;
  // if NO bind carries `a` yet (pre-upgrade), fall back to showing all so nothing breaks mid-migration.
  const hasA = Object.keys(BINDMAP).some(c=>{const b=BINDMAP[c]; return b&&typeof b==='object'&&b.a!==undefined;});
  const keyB=[]; for(const ctx in BINDMAP){ const b=BINDMAP[ctx]; if(!b||typeof b!=='object'||!b.k) continue; if(b.ctrl&&b.ctrl!=='Keypad') continue; if(hasA ? (b.a===1) : true) keyB.push(b); }
  if(el('mirror')&&el('mirror').checked && keyB.length){
    // MIRROR: render the REAL device layout from the plugin-reported binds. Keypad tiles carry (col,row);
    // VSD numbers knob rows first, so normalize by the smallest key row so keys fill the grid from the top.
    let rowOff=99; for(const b of keyB){ const r=b.r||0; if(r<rowOff)rowOff=r; } if(rowOff===99)rowOff=0;
    const grid={}; for(const b of keyB){ grid[(b.c||0)+','+((b.r||0)-rowOff)]=b; }
    for(let i=0;i<m.keys;i++){ const c=i%m.cols, r=Math.floor(i/m.cols); const b=grid[c+','+r];
      html += b ? mirrorKeyHtml(b) : `<div class="key blank"><span class="k-lb" style="color:#2c3e5c">·</span></div>`; }
  } else {
    // fall back to the editable profile (mirror off, OR the device hasn't reported any configured tiles yet)
    const prof=CFG.profile||[];
    for(let i=0;i<m.keys;i++){ html+=keyHtml(i, prof[i]||''); }
  }
  kEl.innerHTML=html;
  // knobs (interactive: − / press / + drive the real knob action)
  const kn=el('knobs'); kn.innerHTML='';
  for(let i=0;i<m.knobs;i++){ const a=CFG.knobs[i]||'none'; const kc=KNOBCAT[a]||KNOBCAT['none']; const off=a==='none';
    kn.innerHTML+=`<div class="knob">
        <div class="dial${off?' off':''}" title="${off?'unassigned':'press '+kc.label}" ${off?'':`onclick="knobPress(${i})"`}></div>
        <div class="kl">${FA(kc.icon)} ${kc.label}</div>
        <div class="kval" id="kv${i}">${KVAL[i]||''}</div>
        ${off?'':`<div class="krow"><button class="kbtn" onclick="knobTurn(${i},-1)">−</button><button class="kbtn" onclick="knobTurn(${i},1)">+</button></div>`}
      </div>`; }
  el('knobCard').style.display=m.knobs?'block':'none';
  el('touchbar').style.display=m.touch?'flex':'none';
  if(m.touch) renderTouchbar();
}
function renderTouchbar(){
  const tb=el('touchbar'); const s=SNAP; const crit=s&&s.alarm;
  const ct=s?.metrics?.cpu_temp?.val, gt=s?.metrics?.gpu_temp?.val, ping=s?.metrics?.ping?.val;
  const rd=[];
  if(ct!=null&&ct!=='—') rd.push(`<span class="tb-read">${FA('temperature-half')}<b>${ct}°</b></span>`);
  if(gt!=null&&gt!=='—') rd.push(`<span class="tb-read">${FA('fire')}<b>${gt}°</b></span>`);
  if(ping!=null&&ping!=='—') rd.push(`<span class="tb-read">${FA('wifi')}<b>${ping}ms</b></span>`);
  let dots=''; const np=CFG.pages||6; for(let p=1;p<=np;p++) dots+=`<span class="${p===PAGE?'on':''}" onclick="switchPage(${p})">${p}</span>`;
  tb.innerHTML=`<div class="tb-l"><span class="tb-stat ${crit?'crit':'ok'}">${crit?'⚠ CRITICAL':'● NOC OK'}</span>${rd.join('')}</div><div class="tb-dots">${dots}</div>`;
}
function keyHtml(i,key){
  if(!key){ return `<div class="key blank" onclick="pick(${i})"><span class="k-ic" style="color:#2c3e5c">${FA('plus')}</span><span class="k-lb">empty</span></div>`; }
  const c=CAT[key]; if(!c){ return `<div class="key blank" onclick="pick(${i})"><span class="k-lb">?</span></div>`; }
  // Device view: show the ACTUAL server-rendered SVG face (what the pad displays)
  if(document.getElementById('devMode')?.checked){
    const tok=encodeURIComponent(el('token').textContent||'');
    const src=`stream_decks.php?api=render&key=${encodeURIComponent(key)}&rig=${CFG.rig}&token=${tok}&_=${RTS}`;
    const click = c.kind==='metric' ? `onclick="pick(${i})"` : `onclick="keyTap(${i},'${key}')" oncontextmenu="pick(${i});return false;"`;
    return `<div class="key devkey" ${click} title="${c.label}"><img class="k-svg" src="${src}" alt="${esc(c.label)}"></div>`;
  }
  if(c.kind==='metric'){
    const mv=SNAP?.metrics?.[key]; const st=mv?mv.state:'na'; const val=(mv&&mv.val!==null&&mv.val!==undefined)?mv.val:'—';
    return `<div class="key metric st-${st}" onclick="pick(${i})" title="${c.label}">
      <span class="k-ic">${FA(c.icon)}</span>
      <span class="k-val">${val}<span class="k-unit">${c.unit||''}</span></span>
      <span class="k-lb">${c.label}</span></div>`;
  }
  const cls=c.kind==='action'?'act':'nav';
  return `<div class="key ${cls}" onclick="keyTap(${i},'${key}')" oncontextmenu="pick(${i});return false;" title="${c.label} (right-click to reassign)">
    <span class="k-ic">${FA(c.icon)}</span><span class="k-lb">${c.label}</span></div>`;
}
function renderKnobs(){
  const m=MODELS[CFG.model]; const box=el('knobFields'); box.innerHTML='';
  for(let i=0;i<m.knobs;i++){ const cur=CFG.knobs[i]||'none';
    box.innerHTML+=`<div class="fld"><label>Knob ${i+1}</label><select class="sd-sel" onchange="setKnob(${i},this.value)">`+
      Object.entries(KNOBCAT).map(([k,v])=>`<option value="${k}" ${k===cur?'selected':''}>${v.label}</option>`).join('')+`</select></div>`; }
  el('knobCard').style.display=m.knobs?'block':'none';
}
function setKnob(i,v){ CFG.knobs[i]=v; renderPad(); save(); }

// ── assign dialog ──
function pick(i){ pickTarget=i; el('pickIdx').textContent='#'+(i+1);
  el('pickGrid').innerHTML=Object.entries(CAT).map(([k,c])=>`<div class="pick ${c.kind}" onclick="assign('${k}')">${FA(c.icon)}${c.label}</div>`).join('');
  el('pickDlg').classList.add('on'); }
function assign(key){ if(pickTarget<0)return; CFG.profile[pickTarget]=key; closeDlg(); renderPad(); save(); }
function closeDlg(){ el('pickDlg').classList.remove('on'); pickTarget=-1; }

// ── actions (preview lets you fire a real one-touch action) ──
async function keyTap(i,key){
  const c=CAT[key]; if(!c)return;
  if(c.kind==='nav'){ window.open(c.page,'_blank'); return; }
  if(!confirm('Run action "'+c.label+'" on the selected rig now?')) return;
  const r=await fetch('stream_decks.php?api=action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:key,rig:CFG.rig})}).then(r=>r.json()).catch(()=>({ok:false,msg:'network error'}));
  alert((r.ok?'✅ ':'⚠️ ')+(r.msg||(r.ok?'done':'failed')));
}

// ── knob rotate / press (drives the real knob action; node-knob retargets the deck) ──
async function knobTurn(i,ticks){
  const r=await fetch('stream_decks.php?api=knob',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({knob:i,ticks,rig:CFG.rig})}).then(r=>r.json()).catch(()=>({ok:false,msg:'network error'}));
  if(r&&r.ok){ KVAL[i]=r.value||''; const kv=el('kv'+i); if(kv)kv.textContent=r.value||'';
    if(r.mode==='node'&&r.rig){ CFG.rig=r.rig; el('rig').value=r.rig; el('rigName').textContent=el('rig').selectedOptions[0]?.textContent||''; restartStream(); } }
  else { const kv=el('kv'+i); if(kv)kv.textContent='⚠ '+((r&&r.msg)||'fail'); }
}
async function knobPress(i){
  const r=await fetch('stream_decks.php?api=knob',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({knob:i,ticks:0,pressed:true,rig:CFG.rig})}).then(r=>r.json()).catch(()=>({ok:false}));
  if(r&&r.ok&&r.value){ KVAL[i]=r.value; const kv=el('kv'+i); if(kv)kv.textContent=r.value; }
}
function syncCustomUI(){
  const isC=CFG.model==='custom'; el('customBox').style.display=isC?'block':'none';
  if(isC){ el('cCols').value=CFG.spec.cols; el('cRows').value=CFG.spec.rows; el('cKnobs').value=CFG.spec.knobs; el('cTouch').checked=!!CFG.spec.touch; }
}
function onModel(){ CFG.model=el('model').value;
  el('modelBadge').innerHTML=(CFG.auto?FA('magnifying-glass')+' auto':FA('hand')+' manual')+' · '+(MODELS[CFG.model]?MODELS[CFG.model].name:CFG.model);
  save(); }

async function save(){
  CFG.rig=parseInt(el('rig').value||'0'); CFG.refresh=parseInt(el('refresh').value||'15'); CFG.auto=el('auto').checked;
  el('modelBadge').className='badge '+(CFG.auto?'auto':'man');
  el('rigName').textContent=el('rig').selectedOptions[0]?.textContent||'';
  const custom={cols:parseInt(el('cCols').value||'5'),rows:parseInt(el('cRows').value||'3'),knobs:parseInt(el('cKnobs').value||'2'),touch:el('cTouch').checked};
  await fetch('stream_decks.php?api=save',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({model:CFG.model,custom,auto:CFG.auto,rig:CFG.rig,refresh:CFG.refresh,knobs:CFG.knobs,profile:CFG.profile,page:PAGE,pages:CFG.pages,plugins_dir:(el('plugdir')?el('plugdir').value:''),plugin_base:(el('plugbase')?el('plugbase').value:'')})}).catch(()=>{});
  // re-pull authoritative spec/profiles — custom dims / new model / page count change things
  const r=await fetch('stream_decks.php?api=config').then(r=>r.json()).catch(()=>null);
  if(r&&r.ok){ CFG=r.cfg; initPages(); renderKnobs(); renderPad(); syncCustomUI(); }
  restartStream();
}
async function rotate(){ if(!confirm('Rotate the API token? The current plugin will need the new token.'))return;
  const r=await fetch('stream_decks.php?api=rotate_token',{method:'POST'}).then(r=>r.json()).catch(()=>null);
  if(r&&r.ok){ el('token').textContent=r.token; } }

// ── live telemetry stream ──
function applySnap(s){ SNAP=s; RTS=s.ts||(RTS+1);
  if(el('mirror')&&el('mirror').checked){ fetchMirror().then(()=>renderPad()); } else { renderPad(); }
  const a=el('alarm'); if(s.alarm){ a.classList.add('on'); el('alarmTxt').textContent='CRITICAL STATE — check red tiles'; } else a.classList.remove('on');
  const ps=el('pcState'); if(CFG.rig<=0){ ps.className='pc-state none'; ps.textContent='PC: none'; }
  else if(s.pc_ok){ ps.className='pc-state ok'; ps.textContent='PC: live'; } else { ps.className='pc-state bad'; ps.textContent='PC: unreachable'; }
}
function startStream(){ try{ es=new EventSource('stream_decks.php?api=stream&rig='+CFG.rig+'&token='+encodeURIComponent(el('token').textContent));
  es.addEventListener('telemetry',e=>{ try{ applySnap(JSON.parse(e.data)); }catch(_){} });
  es.onerror=()=>{ /* auto-reconnect by browser */ }; }catch(_){ pollFallback(); } }
function restartStream(){ if(es){ es.close(); es=null; } startStream(); }
function pollFallback(){ setInterval(async()=>{ const r=await fetch('stream_decks.php?api=telemetry&rig='+CFG.rig+'&token='+encodeURIComponent(el('token').textContent)).then(r=>r.json()).catch(()=>null); if(r&&r.ok)applySnap(r.snap); }, (CFG.refresh||15)*1000); }

function openSetup(){
  el('depRig').textContent = CFG.rig>0 ? (el('rig').selectedOptions[0]?.textContent||('rig '+CFG.rig)) : 'rig (none selected)';
  updateDl();
  el('setupDlg').classList.add('on');
}
function plugBase(){ return (el('plugbase')&&el('plugbase').value.trim())||location.origin; }
function updateDl(){
  const auto=el('dlAuto')?.checked; const tok=encodeURIComponent(el('token').textContent||'');
  let href='stream_decks.php?api=plugin_download&token='+tok;
  if(auto) href+='&base='+encodeURIComponent(plugBase());
  el('dlPlugin').href=href;
  const note=el('dlManualNote'); if(note) note.style.display=auto?'none':'inline';
}
function closeSetup(){ el('setupDlg').classList.remove('on'); }
async function deployRig(){
  if(CFG.rig<=0){ el('depOut').innerHTML='⚠️ Pick a Monitored Rig first (Hardware panel).'; return; }
  el('depOut').innerHTML='⏳ Deploying over SSH — pulling the plugin to the PC + restarting VSD Craft…';
  const r=await fetch('stream_decks.php?api=deploy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rig:CFG.rig,base:plugBase()})}).then(r=>r.json()).catch(()=>({ok:false,msg:'network error'}));
  el('depOut').innerHTML=(r.ok?'✅ ':'⚠️ ')+(r.msg||(r.ok?'done':'failed'));
}
boot();
</script>
</body></html>
