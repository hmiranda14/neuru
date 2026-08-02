<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Stream Decks brain (nm_deck.php)
//
// Turns a VSDinside "Stream Dock" (or any Elgato-compatible macro pad) into a
// physical NOC. NEURU is the server-side brain: it aggregates live telemetry and
// executes actions; a thin Elgato-protocol plugin on the PC (see the downloadable
// package) renders NEURU's button faces and relays key/knob events back here.
//
// Design principles (match NEURU reality):
//  • NEURU is a LAN SERVER, not a PC agent → the deck shows the WHOLE NOC (any node,
//    incidents, threats), not just the local PC.
//  • Every "live" PC call is a 15-30s SSH round-trip → telemetry is THROTTLED + CACHED
//    (tiered: cheap NOC vitals always; PC-fast every `refresh`; PC-slow x4) so a deck
//    polling loop never triggers SSH per button.
//  • Reuse ONLY (no new SSH): nm_pcd_live, nm_wl_passport, nm_netdoc_run, nm_gaming_*,
//    nm_gamefix. Everything runs through the nm_cm_ssh_fetch primitive.
// ─────────────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/nm_secrets.php';   // nm_ssh_resolve / nm_secret_encrypt|decrypt

if (!function_exists('nm_deck_models')) {

// ── Device model profiles (grid + knobs + touch). Sensible defaults; the user can
//    override the active model manually (auto-detect fallback selector). ────────────
function nm_deck_models(): array {
    return [
        // grids / knobs / touch match the real VSDinside Stream Dock lineup (from the product photos).
        'n1'     => ['name' => 'Stream Dock N1 (6-key)',   'cols' => 3, 'rows' => 2, 'keys' => 6,  'knobs' => 3, 'touch' => false, 'screen' => 'keys',     'video_bg' => false],
        'n3'     => ['name' => 'Stream Dock N3 (15+3)',    'cols' => 5, 'rows' => 3, 'keys' => 15, 'knobs' => 3, 'touch' => false, 'screen' => 'keys',     'video_bg' => false],
        // N4 / N4 Pro: 10 LCD keys (5×2) + a WIDE LCD touch bar + 4 rotary knobs.
        'n4'     => ['name' => 'Stream Dock N4',           'cols' => 5, 'rows' => 2, 'keys' => 10, 'knobs' => 4, 'touch' => true,  'screen' => 'touchbar', 'video_bg' => true],
        'n4pro'  => ['name' => 'Stream Dock N4 Pro',       'cols' => 5, 'rows' => 2, 'keys' => 10, 'knobs' => 4, 'touch' => true,  'screen' => 'touchbar', 'video_bg' => true],
        'm15'    => ['name' => 'Stream Dock M15 (flat)',   'cols' => 5, 'rows' => 3, 'keys' => 15, 'knobs' => 0, 'touch' => false, 'screen' => 'keys',     'video_bg' => false],
        'm18'    => ['name' => 'Stream Dock M18',          'cols' => 6, 'rows' => 3, 'keys' => 18, 'knobs' => 0, 'touch' => false, 'screen' => 'keys',     'video_bg' => false],
        'xl'     => ['name' => 'Stream Dock XL (8×4)',     'cols' => 8, 'rows' => 4, 'keys' => 32, 'knobs' => 0, 'touch' => false, 'screen' => 'keys',     'video_bg' => false],
        'numpad' => ['name' => 'Stream Dock Numpad',       'cols' => 3, 'rows' => 4, 'keys' => 12, 'knobs' => 1, 'touch' => false, 'screen' => 'keys',     'video_bg' => false],
        'mobile' => ['name' => 'VSD Mobile / Virtual',     'cols' => 4, 'rows' => 2, 'keys' => 8,  'knobs' => 0, 'touch' => true,  'screen' => 'virtual',  'video_bg' => true],
        // fully user-defined — works for ANY current/future VSDinside unit (dims read from settings).
        'custom' => ['name' => 'Custom layout…',           'cols' => 5, 'rows' => 3, 'keys' => 15, 'knobs' => 2, 'touch' => true,  'screen' => 'keys',     'video_bg' => false],
    ];
}
function nm_deck_model(string $id): array {
    $m = nm_deck_models();
    return $m[$id] ?? $m['n3'];
}

// ── nm_settings config helpers (inline upsert, per NEURU convention) ───────────────
function nm_deck_get($conn, string $k, string $d = ''): string {
    try {
        $st = $conn->prepare("SELECT setting_val FROM nm_settings WHERE setting_key=? LIMIT 1");
        $st->bind_param('s', $k); $st->execute();
        $r = $st->get_result()->fetch_row(); $st->close();
        return $r ? (string)$r[0] : $d;
    } catch (\Throwable $e) { return $d; }
}
function nm_deck_set($conn, string $k, string $v): void {
    try {
        $st = $conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=?");
        $st->bind_param('sss', $k, $v, $v); $st->execute(); $st->close();
    } catch (\Throwable $e) { /* best-effort */ }
}

// Run a PowerShell script over SSH via -EncodedCommand (base64 UTF-16LE) — quoting-proof, so
// scripts may contain double quotes (e.g. C# [DllImport("psapi.dll")]) which the plain
// `powershell -Command "..."` wrapper mangles. ASCII interleave keeps it mbstring-free.
function nm_deck_ps_enc($ssh, string $script, int $timeout = 20): array {
    require_once __DIR__ . '/nm_confmgr.php';
    $u16 = ''; $len = strlen($script);
    for ($i = 0; $i < $len; $i++) { $u16 .= $script[$i] . "\x00"; }   // ASCII → UTF-16LE
    return nm_cm_ssh_fetch($ssh, 'powershell -NoProfile -NonInteractive -EncodedCommand ' . base64_encode($u16), $timeout);
}

// ── The action/metric catalog: what a key or knob can be bound to. ────────────────
//    kind: metric (live gauge) | action (one-touch fix) | nav (open a NEURU page) | knob
function nm_deck_action_catalog(): array {
    return [
        // ── live metrics (rendered as color-state gauges) ──
        'cpu'       => ['label' => 'CPU Load',      'icon' => 'microchip',            'kind' => 'metric', 'unit' => '%',  'src' => 'pc'],
        'cpu_temp'  => ['label' => 'CPU Temp',      'icon' => 'temperature-half',     'kind' => 'metric', 'unit' => '°',  'src' => 'pc'],
        'gpu'       => ['label' => 'GPU Load',      'icon' => 'display',              'kind' => 'metric', 'unit' => '%',  'src' => 'pc'],
        'gpu_temp'  => ['label' => 'GPU Temp',      'icon' => 'fire',                 'kind' => 'metric', 'unit' => '°',  'src' => 'pc'],
        'vram'      => ['label' => 'VRAM',          'icon' => 'memory',               'kind' => 'metric', 'unit' => '%',  'src' => 'pc'],
        'ram'       => ['label' => 'RAM',           'icon' => 'memory',               'kind' => 'metric', 'unit' => '%',  'src' => 'pc'],
        'nvme'      => ['label' => 'NVMe Health',   'icon' => 'hard-drive',           'kind' => 'metric', 'unit' => '%',  'src' => 'pc_slow'],
        'ping'      => ['label' => 'Ping',          'icon' => 'wifi',                 'kind' => 'metric', 'unit' => 'ms', 'src' => 'pc_slow'],
        'jitter'    => ['label' => 'Jitter',        'icon' => 'wave-square',          'kind' => 'metric', 'unit' => 'ms', 'src' => 'pc_slow'],
        'loss'      => ['label' => 'Packet Loss',   'icon' => 'plug-circle-xmark',    'kind' => 'metric', 'unit' => '%',  'src' => 'pc_slow'],
        'stability' => ['label' => 'Net Quality',   'icon' => 'wifi',                 'kind' => 'metric', 'unit' => '%',  'src' => 'pc_slow'],
        'net'       => ['label' => 'Net',           'icon' => 'wifi',                 'kind' => 'metric', 'unit' => 'Mbps','src' => 'pc'],
        // ── per-NODE metrics (any monitored device incl. routers/switches/APs) ──
        'node_up'   => ['label' => 'Reachable',     'icon' => 'server',               'kind' => 'metric', 'unit' => '',   'src' => 'node'],
        // ── whole-NOC / NEURU metrics (global — target ignored) ──
        'nodes'     => ['label' => 'Nodes Down',    'icon' => 'server',               'kind' => 'metric', 'unit' => '',   'src' => 'noc'],
        'nodes_up'  => ['label' => 'Nodes Up',      'icon' => 'server',               'kind' => 'metric', 'unit' => '',   'src' => 'noc'],
        'incidents' => ['label' => 'Incidents',     'icon' => 'triangle-exclamation', 'kind' => 'metric', 'unit' => '',   'src' => 'noc'],
        'threats'   => ['label' => 'Threats',       'icon' => 'shield-virus',         'kind' => 'metric', 'unit' => '',   'src' => 'noc'],
        // ── one-touch actions (reuse existing helpers) ──
        'act_gamemode'    => ['label' => 'Game Mode',    'icon' => 'gamepad',              'kind' => 'action', 'toggle' => true],
        'act_autoheal'    => ['label' => 'Auto-Heal Net','icon' => 'wand-magic-sparkles',  'kind' => 'action'],
        'act_purgevram'   => ['label' => 'Purge Shaders','icon' => 'broom',                'kind' => 'action'],
        'act_purgeram'    => ['label' => 'Purge RAM',    'icon' => 'memory',               'kind' => 'action'],
        'act_crashshield' => ['label' => 'Crash Shield', 'icon' => 'shield-halved',        'kind' => 'action'],
        'act_flushdns'    => ['label' => 'Flush DNS',    'icon' => 'water',                'kind' => 'action'],
        // ── open a NEURU command center on the pad's host browser (nav) ──
        'nav_commander'   => ['label' => 'Commander',    'icon' => 'brain',                'kind' => 'nav', 'page' => 'autopilotv2.php'],
        'nav_incidents'   => ['label' => 'Incidents',    'icon' => 'triangle-exclamation', 'kind' => 'nav', 'page' => 'incidents.php'],
        'nav_immunity'    => ['label' => 'Immunity',     'icon' => 'shield-virus',         'kind' => 'nav', 'page' => 'immunity.php'],
    ];
}

// Knob (rotary encoder) assignment options — for models like N3 / N4 Pro.
function nm_deck_knob_catalog(): array {
    return [
        'tdp'   => ['label' => 'TDP / Fan Profile', 'icon' => 'gauge-high'],
        'audio' => ['label' => 'Game/Chat Audio',   'icon' => 'headphones'],
        'node'  => ['label' => 'Homelab Node',      'icon' => 'server'],
        'none'  => ['label' => '— unused —',         'icon' => 'ban'],
    ];
}
function nm_deck_default_knobs(): array { return ['tdp', 'audio', 'node', 'none']; }

// A sensible starter layout per model (list of catalog keys, length = model key count).
function nm_deck_default_profile(string $model): array {
    $m = nm_deck_model($model); $n = (int)$m['keys'];
    $base = ['cpu', 'cpu_temp', 'gpu', 'gpu_temp', 'vram', 'ram', 'ping', 'nvme',
             'nodes', 'incidents', 'threats', 'act_gamemode', 'act_autoheal', 'act_purgevram', 'nav_commander',
             'loss', 'act_crashshield', 'nav_incidents'];
    $out = array_slice($base, 0, $n);
    while (count($out) < $n) $out[] = '';   // pad blanks
    return $out;
}

// ── Full config for the active install ────────────────────────────────────────────
function nm_deck_config($conn): array {
    $model = nm_deck_get($conn, 'deck_model', 'n3');
    if (!isset(nm_deck_models()[$model])) $model = 'n3';
    // resolve spec — 'custom' pulls its grid/knobs/touch from settings (any current/future unit).
    $spec = nm_deck_model($model);
    if ($model === 'custom') {
        $spec['cols']  = max(1, min(10, (int)(nm_deck_get($conn, 'deck_custom_cols', '5') ?: 5)));
        $spec['rows']  = max(1, min(8,  (int)(nm_deck_get($conn, 'deck_custom_rows', '3') ?: 3)));
        $spec['keys']  = $spec['cols'] * $spec['rows'];
        $spec['knobs'] = max(0, min(8,  (int)nm_deck_get($conn, 'deck_custom_knobs', '2')));
        $spec['touch'] = nm_deck_get($conn, 'deck_custom_touch', '1') !== '0';
    }
    $need = (int)$spec['keys'];
    // MULTI-PAGE: a layout can hold several pages of buttons (the pad's 1..N page selector). Page 1
    // uses the legacy key 'deck_profile_<model>'; pages 2+ use '..._p<N>'. Each page is its own grid.
    $pages = max(1, min(8, (int)(nm_deck_get($conn, 'deck_pages_' . $model, '6') ?: 6)));
    $fix = function ($pr) use ($need) {
        if (!(is_array($pr) && $pr)) return null;
        if (count($pr) !== $need) { $pr = array_slice($pr, 0, $need); while (count($pr) < $need) $pr[] = ''; }
        return $pr;
    };
    $profiles = [];
    for ($p = 1; $p <= $pages; $p++) {
        $kName = $p === 1 ? ('deck_profile_' . $model) : ('deck_profile_' . $model . '_p' . $p);
        $pr = $fix(json_decode(nm_deck_get($conn, $kName, ''), true));
        if ($pr === null) $pr = ($p === 1) ? $fix(nm_deck_default_profile($model)) : array_fill(0, $need, '');
        $profiles[$p] = $pr;
    }
    $kn = json_decode(nm_deck_get($conn, 'deck_knobs', ''), true);
    return [
        'model'    => $model,
        'auto'     => nm_deck_get($conn, 'deck_automodel', '1') !== '0',
        'rig'      => (int)nm_deck_get($conn, 'deck_rig', '0'),
        'node'     => (int)nm_deck_get($conn, 'deck_node', '0'),
        'port'     => (int)(nm_deck_get($conn, 'deck_ws_port', '1988') ?: 1988),
        'refresh'  => max(5, (int)(nm_deck_get($conn, 'deck_refresh', '15') ?: 15)),
        'has_token'=> nm_deck_get($conn, 'deck_api_token', '') !== '',
        'plugins_dir' => nm_deck_get($conn, 'deck_plugins_dir', ''),
        'plugin_base' => nm_deck_get($conn, 'deck_plugin_base', ''),   // the URL the PLUGIN connects to (HTTP, no self-signed cert)

        'knobs'    => (is_array($kn) && $kn) ? $kn : nm_deck_default_knobs(),
        'pages'    => $pages,
        'profiles' => $profiles,          // page => [keys]
        'profile'  => $profiles[1],       // page 1 (back-compat / plugin default)
        'spec'     => $spec,
    ];
}

// Get-or-create the API token the plugin uses to authenticate (bearer). Rotatable.
function nm_deck_token($conn, bool $create = true): string {
    $t = nm_deck_get($conn, 'deck_api_token', '');
    if ($t === '' && $create) { $t = 'nvd_' . bin2hex(random_bytes(20)); nm_deck_set($conn, 'deck_api_token', $t); }
    return $t;
}

// ── Color state for a metric value (green → yellow → red). Higher-is-worse by default;
//    nvme is inverted (higher health = better). Returns 'ok'|'warn'|'crit'. ──────────
function nm_deck_state(string $metric, $val): string {
    if ($val === null || $val === '') return 'na';
    $v = (float)$val;
    switch ($metric) {
        case 'cpu': case 'gpu': case 'ram': case 'vram':
            return $v >= 90 ? 'crit' : ($v >= 75 ? 'warn' : 'ok');
        case 'cpu_temp': return $v >= 90 ? 'crit' : ($v >= 80 ? 'warn' : 'ok');
        case 'gpu_temp': return $v >= 85 ? 'crit' : ($v >= 75 ? 'warn' : 'ok');
        case 'nvme':     return $v <= 40 ? 'crit' : ($v <= 70 ? 'warn' : 'ok');   // health: low = bad
        case 'ping':     return $v >= 120 ? 'crit' : ($v >= 60 ? 'warn' : 'ok');
        case 'jitter':   return $v >= 30 ? 'crit' : ($v >= 12 ? 'warn' : 'ok');
        case 'loss':     return $v >= 5 ? 'crit' : ($v >= 1 ? 'warn' : 'ok');
        case 'stability': return $v <= 60 ? 'crit' : ($v <= 85 ? 'warn' : 'ok');   // higher = better
        case 'nodes': case 'incidents': case 'threats':
            return $v >= 1 ? ($v >= 3 ? 'crit' : 'warn') : 'ok';
        case 'net': case 'nodes_up':
            return 'ok';   // informational
    }
    return 'ok';
}

// ── Targets: a tile can monitor a specific device. tgt string: '' / 'noc' = whole NOC; 'r<id>' = a PC
//    rig (SSH telemetry); 'n<id>' = any monitored node (router/switch/AP — status only). ──────────────
function nm_deck_rigs($conn): array {
    require_once __DIR__ . '/nm_winhost.php';
    $out = [];
    try { foreach ((array)nm_win_hosts($conn) as $r) $out[] = ['id' => (int)$r['id'], 'name' => (string)($r['name'] ?? ('rig ' . $r['id'])), 'node_id' => (int)($r['node_id'] ?? 0)]; } catch (\Throwable $e) {}
    return $out;
}
function nm_deck_nodes($conn): array {
    $out = [];
    try { if ($r = $conn->query("SELECT id,display_name,ip_address FROM nm_nodes ORDER BY display_name")) while ($x = $r->fetch_assoc()) $out[] = ['id' => (int)$x['id'], 'name' => (string)$x['display_name'], 'ip' => (string)$x['ip_address']]; } catch (\Throwable $e) {}
    return $out;
}
// resolve a tgt → the RIG id to read PC metrics from (r<id>; n<id> → rig linked to that node; else default)
function nm_deck_resolve_rig($conn, string $tgt): int {
    $tgt = trim($tgt);
    if (preg_match('/^r(\d+)$/', $tgt, $m)) return (int)$m[1];
    if (preg_match('/^n(\d+)$/', $tgt, $m)) {
        try { if ($r = $conn->query("SELECT id FROM nm_win_hosts WHERE node_id=" . (int)$m[1] . " LIMIT 1")) if ($x = $r->fetch_row()) return (int)$x[0]; } catch (\Throwable $e) {}
        return 0;
    }
    return (int)nm_deck_get($conn, 'deck_rig', '0');
}
// Every RIG a tile currently targets for PC metrics (default rig + all bound r/n targets) — the cron
// warms exactly these so multi-node scenes stay realtime without warming unused rigs.
function nm_deck_active_rigs($conn): array {
    $rigs = [];
    $def = (int)nm_deck_get($conn, 'deck_rig', '0'); if ($def > 0) $rigs[$def] = 1;
    $binds = json_decode(nm_deck_get($conn, 'deck_binds', ''), true);
    $cat = nm_deck_action_catalog();
    if (is_array($binds)) foreach ($binds as $b) {
        $k = is_array($b) ? ($b['k'] ?? '') : (string)$b;
        $src = $cat[$k]['src'] ?? '';
        if ($src === 'pc' || $src === 'pc_slow') { $r = nm_deck_resolve_rig($conn, is_array($b) ? ($b['t'] ?? '') : ''); if ($r > 0) $rigs[$r] = 1; }
    }
    return array_keys($rigs);
}

// a per-node metric (status / reachability) — cheap DB, works for ANY node incl. routers/switches/APs
function nm_deck_node_metric($conn, string $key, int $nid): array {
    if ($nid <= 0) return ['val' => null, 'state' => 'na'];
    if ($key === 'node_up') {
        $st = 'up';
        try { if ($r = $conn->query("SELECT last_status FROM nm_alert_state WHERE entity_type='node' AND entity_id=" . $nid . " LIMIT 1")) if ($x = $r->fetch_row()) $st = (string)$x[0]; } catch (\Throwable $e) {}
        $down = in_array($st, ['down', 'lowerlayerdown', 'notpresent'], true);
        $deg  = in_array($st, ['degraded', 'testing'], true);
        return ['val' => $down ? 'DOWN' : ($deg ? 'DEGR' : 'UP'), 'state' => $down ? 'crit' : ($deg ? 'warn' : 'ok')];
    }
    return ['val' => null, 'state' => 'na'];
}
// ── DYNAMIC per-node metrics (the "hundreds"): device_stats (cpu/ram/uptime/storage/cores/…) + port
//    traffic + status. Keys: st:up | pt:in | pt:out | ds:<type>:<metric_key>. All cheap DB reads. ─────
function nm_deck_node_meta(string $type, string $mk): array {   // label/unit/icon/thresholds (no value fetch)
    $t = strtolower($type);
    if ($t === 'cpu')      return ['label' => ($mk === 'avg' ? 'CPU' : 'CPU ' . $mk), 'unit' => '%',  'icon' => 'microchip',        'kind' => 'pct'];
    if ($t === 'storage')  return ['label' => 'Disk ' . $mk,                          'unit' => '%',  'icon' => 'hard-drive',       'kind' => 'pct'];
    if ($t === 'uptime')   return ['label' => 'Uptime',                               'unit' => '',   'icon' => 'server',           'kind' => 'uptime'];
    if ($t === 'ram' || $t === 'memory') return ['label' => ($mk === 'avg' ? 'RAM' : ucfirst($mk)),  'unit' => '', 'icon' => 'memory', 'kind' => 'raw'];
    if ($t === 'temperature' || $t === 'temp') return ['label' => 'Temp ' . $mk,      'unit' => '°',  'icon' => 'temperature-half', 'kind' => 'temp'];
    return ['label' => ucfirst($t) . ' ' . $mk, 'unit' => '', 'icon' => 'server', 'kind' => 'raw'];
}
function nm_deck_node_dynamic($conn, int $nid, string $key): array {
    $r = ['label' => $key, 'unit' => '', 'icon' => 'server', 'val' => null, 'state' => 'na', 'kind' => 'metric'];
    if ($nid <= 0) return $r;
    if ($key === 'st:up') { $s = nm_deck_node_metric($conn, 'node_up', $nid); return ['label' => 'Reachable', 'unit' => '', 'icon' => 'server', 'val' => $s['val'], 'state' => $s['state'], 'kind' => 'metric']; }
    if ($key === 'pt:in' || $key === 'pt:out') {
        $col = $key === 'pt:in' ? 'in_rate' : 'out_rate'; $v = null;
        try { if ($q = $conn->query("SELECT SUM(ps.$col) s FROM nm_port_stats ps JOIN (SELECT port_id, MAX(recorded_at) mx FROM nm_port_stats WHERE node_id=" . $nid . " AND recorded_at>NOW()-INTERVAL 1 HOUR GROUP BY port_id) l ON ps.port_id=l.port_id AND ps.recorded_at=l.mx WHERE ps.node_id=" . $nid)) { $x = $q->fetch_assoc(); $v = $x['s'] ?? null; } } catch (\Throwable $e) {}
        $mbps = $v !== null ? round(((float)$v) / 1e6, 1) : null;
        return ['label' => ($key === 'pt:in' ? 'Traffic In' : 'Traffic Out'), 'unit' => 'Mbps', 'icon' => 'wifi', 'val' => $mbps, 'state' => 'ok', 'kind' => 'metric'];
    }
    if (strpos($key, 'ds:') === 0) {
        $p = explode(':', $key, 3); $type = $p[1] ?? ''; $mk = $p[2] ?? '';
        $meta = nm_deck_node_meta($type, $mk); $v = null;
        try { $st = $conn->prepare("SELECT value FROM nm_device_stats WHERE node_id=? AND metric_type=? AND metric_key=? ORDER BY recorded_at DESC LIMIT 1"); $st->bind_param('iss', $nid, $type, $mk); $st->execute(); $row = $st->get_result()->fetch_row(); if ($row) $v = $row[0]; } catch (\Throwable $e) {}
        $state = 'ok';
        if ($v !== null) {
            if ($meta['kind'] === 'pct')      { $v = (int)round((float)$v); $state = $v >= 90 ? 'crit' : ($v >= 75 ? 'warn' : 'ok'); }
            elseif ($meta['kind'] === 'temp') { $v = (int)round((float)$v); $state = $v >= 80 ? 'crit' : ($v >= 70 ? 'warn' : 'ok'); }
            elseif ($meta['kind'] === 'uptime') { $d = (int)((float)$v / 86400); $h = (int)(((float)$v % 86400) / 3600); $v = $d > 0 ? ($d . 'd') : ($h . 'h'); }
            else { $v = is_numeric($v) ? (round((float)$v, 1) + 0) : $v; }
        }
        return ['label' => $meta['label'], 'unit' => $meta['unit'], 'icon' => $meta['icon'], 'val' => $v, 'state' => $state, 'kind' => 'metric'];
    }
    return $r;
}
// the metric list a NODE offers (for the PI dropdown) — status + traffic + every device_stats key it has
function nm_deck_node_metrics_list($conn, int $nid): array {
    $list = [['key' => 'st:up', 'label' => 'Reachable', 'unit' => '']];
    try { if ($q = $conn->query("SELECT COUNT(*) c FROM nm_port_stats WHERE node_id=" . $nid . " AND recorded_at>NOW()-INTERVAL 1 HOUR")) if ((int)($q->fetch_assoc()['c'] ?? 0) > 0) { $list[] = ['key' => 'pt:in', 'label' => 'Traffic In', 'unit' => 'Mbps']; $list[] = ['key' => 'pt:out', 'label' => 'Traffic Out', 'unit' => 'Mbps']; } } catch (\Throwable $e) {}
    try { if ($q = $conn->query("SELECT DISTINCT metric_type,metric_key FROM nm_device_stats WHERE node_id=" . $nid . " AND recorded_at>NOW()-INTERVAL 6 HOUR ORDER BY metric_type,metric_key LIMIT 150")) while ($x = $q->fetch_assoc()) { $meta = nm_deck_node_meta($x['metric_type'], $x['metric_key']); $list[] = ['key' => 'ds:' . $x['metric_type'] . ':' . $x['metric_key'], 'label' => $meta['label'], 'unit' => $meta['unit']]; } } catch (\Throwable $e) {}
    return $list;
}
function nm_deck_is_dynkey(string $key): bool { return strpos($key, 'ds:') === 0 || strpos($key, 'pt:') === 0 || strpos($key, 'st:') === 0; }

// resolve ONE metric for a tile's target → {val,state}. Cache/DB only (never SSH — the cron warms it).
function nm_deck_metric_for_target($conn, string $key, string $tgt): array {
    $meta = nm_deck_action_catalog()[$key] ?? null;
    if (!$meta || ($meta['kind'] ?? '') !== 'metric') return ['val' => null, 'state' => 'na'];
    $src = $meta['src'];
    if ($src === 'noc') { $noc = nm_deck_noc_vitals($conn); $v = $noc[$key] ?? null; return ['val' => $v, 'state' => nm_deck_state($key, $v)]; }
    if ($src === 'node') { return nm_deck_node_metric($conn, $key, preg_match('/^n(\d+)$/', trim($tgt), $m) ? (int)$m[1] : 0); }
    $rig = nm_deck_resolve_rig($conn, $tgt);
    if ($rig <= 0) return ['val' => null, 'state' => 'na'];
    $cache = json_decode(nm_deck_get($conn, ($src === 'pc_slow' ? 'deck_pcslow_' : 'deck_pcfast_') . $rig, ''), true);
    $v = is_array($cache) ? ($cache[$key] ?? null) : null;
    if ($key === 'net' && $v !== null) $v = (int)round(((float)$v) * 8 / 1e6);
    return ['val' => $v, 'state' => nm_deck_state($key, $v)];
}

// ── NOC vitals (cheap DB, always fresh) — mirrors home.php's counters. ─────────────
function nm_deck_noc_vitals($conn): array {
    $out = ['nodes' => null, 'incidents' => null, 'threats' => null, 'nodes_total' => 0, 'nodes_up' => 0];
    try {
        $total = 0; if ($r = $conn->query("SELECT COUNT(*) c FROM nm_nodes")) $total = (int)($r->fetch_assoc()['c'] ?? 0);
        $down = 0; $deg = 0;
        if ($r = $conn->query("SELECT last_status,COUNT(*) c FROM nm_alert_state WHERE entity_type='node' AND last_status IN('down','degraded','lowerlayerdown','notpresent','testing') GROUP BY last_status"))
            while ($x = $r->fetch_assoc()) { if ($x['last_status'] === 'degraded') $deg += (int)$x['c']; else $down += (int)$x['c']; }
        $out['nodes_total'] = $total; $out['nodes'] = $down; $out['nodes_up'] = max(0, $total - $down - $deg);
    } catch (\Throwable $e) {}
    try { if ($r = $conn->query("SELECT COUNT(*) c FROM nm_incidents WHERE status IN('open','acknowledged')")) $out['incidents'] = (int)($r->fetch_assoc()['c'] ?? 0); } catch (\Throwable $e) {}
    // pending immunity threats awaiting a block decision (Collective Immunity → nm_threats)
    try { if ($r = @$conn->query("SELECT COUNT(*) c FROM nm_threats WHERE status='pending'")) $out['threats'] = (int)($r->fetch_assoc()['c'] ?? 0); } catch (\Throwable $e) {}
    return $out;
}

// ── PC vitals via ONE throttled nm_pcd_live SSH call; cpu_temp/gpu_temp derived from
//    the temps[] LHM array it already returns (no second SSH). ───────────────────────
function nm_deck_pc_fast($conn, int $rigId): array {
    if ($rigId <= 0) return ['ok' => false, 'reason' => 'no_rig'];
    require_once __DIR__ . '/nm_confmgr.php';
    require_once __DIR__ . '/nm_winhost.php';
    require_once __DIR__ . '/nm_gaming.php';
    require_once __DIR__ . '/nm_pcdoctor.php';
    $h = nm_win_host($conn, $rigId);
    if (!$h) return ['ok' => false, 'reason' => 'rig_not_found'];
    try {
        $live = nm_pcd_live($conn, $h);
        if (empty($live['ok'])) return ['ok' => false, 'reason' => $live['error'] ?? 'ssh_failed'];
        $cpuT = null; $gpuT = null;
        foreach ((array)($live['temps'] ?? []) as $t) {
            $name = strtolower((string)($t['name'] ?? '') . ' ' . ($t['hw'] ?? ''));
            $val  = (float)($t['val'] ?? 0);
            if ($val <= 0) continue;
            if ($gpuT === null && strpos($name, 'gpu') !== false) $gpuT = $val;
            elseif ($cpuT === null && (strpos($name, 'cpu') !== false || strpos($name, 'core') !== false || strpos($name, 'package') !== false)) $cpuT = $val;
        }
        return ['ok' => true,
            'cpu'      => $live['cpu']      ?? null,
            'ram'      => $live['ram_pct']  ?? null,
            'gpu'      => $live['gpu']      ?? null,
            'gpu_temp' => $live['gpu_temp'] ?? $gpuT,
            'vram'     => $live['vram_pct'] ?? null,
            'cpu_temp' => $cpuT,
            'net'      => $live['net'] ?? null,
        ];
    } catch (\Throwable $e) { return ['ok' => false, 'reason' => $e->getMessage()]; }
}

// ── PC slow vitals (NVMe health + ping/loss) — changes slowly, refreshed x4 less. ──
function nm_deck_pc_slow($conn, int $rigId): array {
    if ($rigId <= 0) return ['ok' => false];
    require_once __DIR__ . '/nm_confmgr.php';
    require_once __DIR__ . '/nm_winhost.php';
    require_once __DIR__ . '/nm_wearlife.php';
    require_once __DIR__ . '/nm_netdoc.php';
    $h = nm_win_host($conn, $rigId);
    if (!$h) return ['ok' => false];
    $out = ['ok' => true, 'nvme' => null, 'ping' => null, 'loss' => null];
    try {
        $pass = nm_wl_passport($conn, (int)$h['id']);
        foreach ((array)($pass['subsystems'] ?? []) as $s) if (($s['key'] ?? '') === 'nand') { $out['nvme'] = (int)round((float)($s['health'] ?? 0)); break; }
    } catch (\Throwable $e) {}
    try {
        $net = nm_netdoc_run($conn, $h);
        foreach ((array)($net['hops'] ?? []) as $hop) if (($hop['id'] ?? '') === 'game' || ($hop['id'] ?? '') === 'isp') {
            $pc = $hop['pc'] ?? [];
            if (isset($pc['avg'])) {   // gaming network quality (Connection Doctor)
                $out['ping']   = round((float)$pc['avg']);
                $out['loss']   = round((float)($pc['loss'] ?? 0));
                $out['jitter'] = round((float)($pc['jitter'] ?? 0));
                if (isset($pc['stability'])) $out['stability'] = (int)round((float)$pc['stability']);
                break;
            }
        }
    } catch (\Throwable $e) {}
    return $out;
}

// Is the dedicated telemetry cron (cron_deck.php) alive? If so, the request path must NOT
// trigger SSH itself — the cron owns refresh and the API/SSE just read cache (instant).
function nm_deck_cron_alive($conn): bool {
    $last = (int)nm_deck_get($conn, 'deck_cron_last', '0');
    if ($last <= 0) return false;
    $refresh = max(5, (int)(nm_deck_get($conn, 'deck_refresh', '15') ?: 15));
    return (time() - $last) < ($refresh * 3 + 45);
}

// Refresh a rig's tiered PC cache (this is the ONLY path that may SSH). Called by the cron,
// and — when no cron is running — lazily by nm_deck_telemetry as an on-request fallback.
function nm_deck_refresh_cache($conn, int $rig, bool $force = false): void {
    if ($rig <= 0) return;
    $refresh = max(5, (int)(nm_deck_get($conn, 'deck_refresh', '15') ?: 15));
    $fk = 'deck_pcfast_' . $rig; $sk = 'deck_pcslow_' . $rig;
    $fast = json_decode(nm_deck_get($conn, $fk, ''), true);
    if ($force || !is_array($fast) || (time() - (int)($fast['ts'] ?? 0)) >= $refresh) {
        $fast = nm_deck_pc_fast($conn, $rig); $fast['ts'] = time();
        nm_deck_set($conn, $fk, json_encode($fast));
    }
    $slow = json_decode(nm_deck_get($conn, $sk, ''), true);
    if ($force || !is_array($slow) || (time() - (int)($slow['ts'] ?? 0)) >= $refresh * 4) {
        $slow = nm_deck_pc_slow($conn, $rig); $slow['ts'] = time();
        nm_deck_set($conn, $sk, json_encode($slow));
    }
}

// ── The aggregator: NOC vitals (always) + tiered-cached PC vitals. Returns a compact
//    snapshot { ts, noc:{...}, pc:{...}, alarm } that the plugin/preview renders. When the
//    cron is alive it is pure cache reads (no SSH); otherwise it self-refreshes on request. ─
function nm_deck_telemetry($conn, ?int $rigId = null, bool $force = false, bool $cacheOnly = false): array {
    $cfg = nm_deck_config($conn);
    $rig = $rigId ?? $cfg['rig'];

    $noc = nm_deck_noc_vitals($conn);

    $pc = ['ok' => false];
    if ($rig > 0) {
        // $cacheOnly (the on-PC plugin's render/telemetry) NEVER does inline SSH — a 15-30s SSH hang here
        // would freeze the plugin's fetch → it looks "disconnected" and reverts to the default icon. The
        // cron (cron_deck) keeps the cache warm; stale cache is served rather than blocking.
        if (!$cacheOnly && ($force || !nm_deck_cron_alive($conn))) nm_deck_refresh_cache($conn, $rig, $force);
        $fast = json_decode(nm_deck_get($conn, 'deck_pcfast_' . $rig, ''), true);
        $slow = json_decode(nm_deck_get($conn, 'deck_pcslow_' . $rig, ''), true);
        $pc = array_merge(is_array($fast) ? $fast : [], is_array($slow) ? $slow : []);
        $pc['ok'] = !empty($fast['ok']);
        $pc['age'] = time() - (int)(is_array($fast) ? ($fast['ts'] ?? 0) : 0);
    }

    // resolve every metric to {val,state}
    $vals = [];
    foreach (nm_deck_action_catalog() as $key => $meta) {
        if (($meta['kind'] ?? '') !== 'metric') continue;
        $src = $meta['src'];
        $v = ($src === 'noc') ? ($noc[$key] ?? null) : ($pc[$key] ?? null);
        $vals[$key] = ['val' => $v, 'state' => nm_deck_state($key, $v)];
    }
    $alarm = false;
    foreach ($vals as $k => $x) if ($x['state'] === 'crit') { $alarm = true; break; }

    return ['ts' => time(), 'rig' => $rig, 'noc' => $noc, 'pc' => $pc, 'metrics' => $vals,
            'alarm' => $alarm, 'pc_ok' => !empty($pc['ok'])];
}

// ── Action executor: run a bound key/knob action by reusing existing helpers.
//    Returns ['ok','msg','state'?]. Never throws. RBAC/auth is the caller's job. ──────
function nm_deck_run_action($conn, int $rigId, string $action, array $args = []): array {
    $cat = nm_deck_action_catalog();
    if (!isset($cat[$action])) return ['ok' => false, 'msg' => 'unknown action'];
    if (($cat[$action]['kind'] ?? '') === 'nav') return ['ok' => true, 'nav' => $cat[$action]['page'] ?? '', 'msg' => 'open'];

    require_once __DIR__ . '/nm_confmgr.php';
    require_once __DIR__ . '/nm_winhost.php';
    require_once __DIR__ . '/nm_gaming.php';
    $h = $rigId > 0 ? nm_win_host($conn, $rigId) : null;
    $ssh = null; if ($h) { try { $ssh = nm_win_resolve_ssh($conn, $h); } catch (\Throwable $e) {} }
    if (!$h && strpos($action, 'act_') === 0) return ['ok' => false, 'msg' => 'no rig selected'];

    try {
        switch ($action) {
            case 'act_gamemode': {   // reversible High-Perf boost toggle
                $skey = 'deck_gm_' . $rigId;
                $on = nm_deck_get($conn, $skey, '0') === '1';
                $want = !$on;
                if (function_exists('nm_gaming_boost')) {
                    $r = nm_gaming_boost($conn, $h, $want, 'streamdeck');
                    if (!empty($r['ok']) || $r === true) { nm_deck_set($conn, $skey, $want ? '1' : '0'); return ['ok' => true, 'state' => $want ? 'on' : 'off', 'msg' => 'Game Mode ' . ($want ? 'ON' : 'OFF')]; }
                    return ['ok' => false, 'msg' => $r['error'] ?? 'boost failed'];
                }
                return ['ok' => false, 'msg' => 'booster unavailable'];
            }
            case 'act_autoheal': case 'act_flushdns': {
                require_once __DIR__ . '/nm_gamefix.php';
                if (!$ssh) return ['ok' => false, 'msg' => 'no SSH'];
                $fix = $action === 'act_flushdns' ? 'preflight' : 'preflight';
                if (function_exists('nm_gf_fix')) { $r = nm_gf_fix($conn, $ssh, 'autoheal', $fix); return ['ok' => !empty($r['ok']), 'msg' => $r['msg'] ?? 'net healed', 'log' => $r['log'] ?? []]; }
                return ['ok' => false, 'msg' => 'gamefix unavailable'];
            }
            case 'act_purgevram': {
                require_once __DIR__ . '/nm_gamefix.php';
                if (!$ssh) return ['ok' => false, 'msg' => 'no SSH'];
                if (function_exists('nm_gf_fix')) { $r = nm_gf_fix($conn, $ssh, 'storage', 'shaders'); return ['ok' => !empty($r['ok']), 'msg' => $r['msg'] ?? 'shader caches purged', 'log' => $r['log'] ?? []]; }
                return ['ok' => false, 'msg' => 'gamefix unavailable'];
            }
            case 'act_purgeram': {   // trim every process working set → frees standby/used RAM (session-independent P/Invoke)
                require_once __DIR__ . '/nm_winhost.php';
                if (!$ssh) return ['ok' => false, 'msg' => 'no SSH'];
                $ps = 'Add-Type -Name Mem -Namespace Win -MemberDefinition \'[DllImport("psapi.dll")] public static extern bool EmptyWorkingSet(IntPtr h);\' -EA SilentlyContinue; '
                    . '$n=0; Get-Process | ForEach-Object { try { if([Win.Mem]::EmptyWorkingSet($_.Handle)){$n++} } catch {} }; "trimmed $n"';
                $r = nm_deck_ps_enc($ssh, $ps, 20);
                $n = preg_replace('/\D/', '', (string)($r['config'] ?? ''));
                return ['ok' => !empty($r['ok']), 'msg' => !empty($r['ok']) ? ('RAM trimmed on ' . ($n !== '' ? $n : '?') . ' processes') : ($r['error'] ?? 'failed')];
            }
            case 'act_crashshield': {
                require_once __DIR__ . '/nm_gamefix.php';
                if (!$ssh) return ['ok' => false, 'msg' => 'no SSH'];
                $ov = trim((string)($args['name'] ?? ''));
                if ($ov === '') return ['ok' => false, 'msg' => 'crash shield needs an overlay/process name (configure it)'];
                if (function_exists('nm_gf_fix')) { $r = nm_gf_fix($conn, $ssh, 'crashshield', 'killov:' . $ov); return ['ok' => !empty($r['ok']), 'msg' => $r['msg'] ?? 'overlay killed']; }
                return ['ok' => false, 'msg' => 'gamefix unavailable'];
            }
        }
    } catch (\Throwable $e) { return ['ok' => false, 'msg' => $e->getMessage()]; }
    return ['ok' => false, 'msg' => 'action not wired'];
}

// ── Knob (rotary encoder) execution — DialRotate (ticks ±) / DialDown (pressed). Returns a
//    compact result the plugin renders on the encoder LCD (feedback:{title,value,icon}). ─────
function nm_deck_run_knob($conn, int $rigId, int $knobIdx, int $ticks, bool $pressed = false): array {
    $cfg  = nm_deck_config($conn);
    $mode = $cfg['knobs'][$knobIdx] ?? 'none';
    if ($mode === 'none') return ['ok' => false, 'msg' => 'knob unassigned'];
    try {
        switch ($mode) {
            case 'node':  return nm_deck_knob_node($conn, $ticks);
            case 'tdp':   return nm_deck_knob_tdp($conn, $rigId, $ticks);
            case 'audio': return nm_deck_knob_audio($conn, $rigId, $ticks, $pressed);
        }
    } catch (\Throwable $e) { return ['ok' => false, 'msg' => $e->getMessage()]; }
    return ['ok' => false, 'msg' => 'unknown knob mode'];
}

// Homelab Node selector — cycle the monitored rig (cheap, no SSH); the deck instantly retargets.
function nm_deck_knob_node($conn, int $ticks): array {
    require_once __DIR__ . '/nm_winhost.php';
    $rigs = [];
    try { foreach ((array)nm_win_hosts($conn) as $r) $rigs[] = ['id' => (int)$r['id'], 'name' => (string)($r['name'] ?? ('rig ' . $r['id']))]; } catch (\Throwable $e) {}
    if (!$rigs) return ['ok' => false, 'msg' => 'no rigs configured'];
    $cur = (int)nm_deck_get($conn, 'deck_rig', '0');
    $idx = 0; foreach ($rigs as $i => $r) if ($r['id'] === $cur) { $idx = $i; break; }
    $n = count($rigs);
    $idx = (($idx + ($ticks <=> 0)) % $n + $n) % $n;
    nm_deck_set($conn, 'deck_rig', (string)$rigs[$idx]['id']);
    return ['ok' => true, 'mode' => 'node', 'value' => $rigs[$idx]['name'], 'rig' => $rigs[$idx]['id'],
            'feedback' => ['title' => 'Node', 'value' => $rigs[$idx]['name'], 'icon' => 'server']];
}

// TDP / Performance — cycle the Windows power plan (session-independent, instant via powercfg).
function nm_deck_knob_tdp($conn, int $rigId, int $ticks): array {
    if ($rigId <= 0) return ['ok' => false, 'msg' => 'no rig selected'];
    $plans = [
        ['Power Saver',      'a1841308-3541-4fab-bc81-f71556f20b4a'],
        ['Balanced',         '381b4222-f694-41f0-9685-ff5bb260df2e'],
        ['High Performance', '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'],
        ['Ultimate',         'e9a42b02-d5df-448d-aa00-03f14749eb61'],
    ];
    require_once __DIR__ . '/nm_confmgr.php'; require_once __DIR__ . '/nm_winhost.php';
    $k = 'deck_kn_tdp_' . $rigId; $idx = (int)nm_deck_get($conn, $k, '1');
    $idx = max(0, min(count($plans) - 1, $idx + ($ticks <=> 0)));
    nm_deck_set($conn, $k, (string)$idx);
    $h = nm_win_host($conn, $rigId); $ssh = $h ? nm_win_resolve_ssh($conn, $h) : null;
    $applied = false; $err = '';
    if ($ssh) {   // fall back to High-Perf if the Ultimate GUID isn't present on this box
        // trailing echo = sentinel (powercfg is silent on success, and empty SSH output = failure)
        $ps = 'powercfg /setactive ' . $plans[$idx][1] . '; if($LASTEXITCODE -ne 0){ powercfg /setactive ' . $plans[2][1] . ' }; \'NM_TDP_OK\'';
        try { $r = nm_win_ps($ssh, $ps, 12); $applied = !empty($r['ok']) && strpos((string)($r['config'] ?? ''), 'NM_TDP_OK') !== false; if (!$applied) $err = $r['error'] ?? 'apply failed'; } catch (\Throwable $e) { $err = $e->getMessage(); }
    }
    return ['ok' => ($ssh !== null), 'mode' => 'tdp', 'value' => $plans[$idx][0], 'idx' => $idx, 'applied' => $applied, 'err' => $err,
            'feedback' => ['title' => 'TDP', 'value' => $plans[$idx][0], 'icon' => 'gauge-high']];
}

// Game/Chat Audio — master volume nudge via media-key injection (press = mute toggle). Best-effort
// over SSH; VSD Craft's native audio mixer is the richer per-app option if this box runs headless.
function nm_deck_knob_audio($conn, int $rigId, int $ticks, bool $pressed): array {
    if ($rigId <= 0) return ['ok' => false, 'msg' => 'no rig selected'];
    require_once __DIR__ . '/nm_confmgr.php'; require_once __DIR__ . '/nm_winhost.php';
    $h = nm_win_host($conn, $rigId); $ssh = $h ? nm_win_resolve_ssh($conn, $h) : null;
    if (!$ssh) return ['ok' => false, 'msg' => 'no SSH'];
    $vk = $pressed ? 173 : ($ticks > 0 ? 175 : 174);          // 0xAD mute · 0xAF up · 0xAE down
    $rep = $pressed ? 1 : max(1, min(10, abs($ticks)));
    $ps = 'Add-Type -Name K -Namespace W -MemberDefinition \'[DllImport("user32.dll")] public static extern void keybd_event(byte b,byte s,uint f,int e);\' -EA SilentlyContinue; '
        . '1..' . $rep . ' | ForEach-Object { [W.K]::keybd_event(' . $vk . ',0,0,0); [W.K]::keybd_event(' . $vk . ',0,2,0) }; "NM_VOL_OK"';
    $r = nm_deck_ps_enc($ssh, $ps, 10);
    $lbl = $pressed ? 'Mute' : ($ticks > 0 ? 'Vol +' : 'Vol −');
    return ['ok' => !empty($r['ok']), 'mode' => 'audio', 'value' => $lbl,
            'feedback' => ['title' => 'Volume', 'value' => $lbl, 'icon' => $pressed ? 'volume-xmark' : ($ticks > 0 ? 'volume-high' : 'volume-low')]];
}

// ── Build the plugin .zip on disk (ZipArchive) → returns temp path, or '' on failure. Optionally
//    injects defaults.json (base+token) so the deployed plugin auto-configures (zero typing). ──────
function nm_deck_plugin_zip(string $base = '', string $token = '', string $fmt = 'zip'): string {
    $dir = realpath(__DIR__ . '/streamdeck-plugin/com.neuru.noc.sdPlugin');
    if (!$dir || !is_dir($dir)) return '';
    // collect files once (dir iterator is single-pass)
    $files = [];
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $f) {
        if (!$f->isFile()) continue;
        $files[] = [$f->getPathname(), 'com.neuru.noc.sdPlugin/' . str_replace('\\', '/', substr($f->getPathname(), strlen($dir) + 1))];
    }
    $defaults = $base !== '' ? json_encode(['base' => $base, 'token' => $token]) : null;

    // .tar for the auto-deploy — Windows tar.exe (bsdtar) reliably extracts tar, but chokes on some
    // ZipArchive zips ("Unrecognized archive format"). Manual download stays .zip (Explorer opens it).
    if ($fmt === 'tar') {
        if (!class_exists('PharData')) return '';
        $tmp = tempnam(sys_get_temp_dir(), 'nvdplug'); if ($tmp === false) return '';
        @unlink($tmp); $tmp .= '.tar'; @unlink($tmp);   // PharData needs the target to not exist
        try {
            $tar = new PharData($tmp);
            foreach ($files as $pair) $tar->addFile($pair[0], $pair[1]);
            if ($defaults !== null) $tar->addFromString('com.neuru.noc.sdPlugin/defaults.json', $defaults);
        } catch (\Throwable $e) { return ''; }
        return $tmp;
    }

    if (!class_exists('ZipArchive')) return '';
    $tmp = tempnam(sys_get_temp_dir(), 'nvdplug'); if ($tmp === false) return '';
    $tmp .= '.zip';
    $zip = new ZipArchive();
    if ($zip->open($tmp, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) return '';
    foreach ($files as $pair) $zip->addFile($pair[0], $pair[1]);
    if ($defaults !== null) $zip->addFromString('com.neuru.noc.sdPlugin/defaults.json', $defaults);
    $zip->close();
    return $tmp;
}

// ── "Deploy to this rig": tell the PC (over SSH) to pull the plugin zip from NEURU, install it into
//    %appdata%/StreamDock/plugins, and restart VSD Craft. NEURU is on the LAN so the PC can fetch it.
//    $base = a NEURU URL the PC can reach (passed from the admin's browser — same LAN). ──────────────
function nm_deck_deploy($conn, int $rigId, string $base, string $token): array {
    if ($rigId <= 0) return ['ok' => false, 'msg' => 'select a rig first'];
    $base = rtrim(trim($base), '/');
    // The plugin runs in a WebView that REJECTS self-signed HTTPS → use the configured HTTP plugin base
    // (e.g. http://host:8090) for BOTH the download and the injected defaults.json, so its fetch works.
    $pbase = rtrim(trim(nm_deck_get($conn, 'deck_plugin_base', '')), '/');
    if ($pbase !== '') $base = $pbase;
    if ($base === '') return ['ok' => false, 'msg' => 'no reachable NEURU URL'];
    require_once __DIR__ . '/nm_confmgr.php'; require_once __DIR__ . '/nm_winhost.php';
    $h = $rigId > 0 ? nm_win_host($conn, $rigId) : null;
    $ssh = $h ? nm_win_resolve_ssh($conn, $h) : null;
    if (!$ssh) return ['ok' => false, 'msg' => 'no SSH to the selected rig'];

    // Plugins folder resolution: (1) an explicit user override wins (custom install locations);
    // (2) else auto-detect the OEM subfolder (varies: HotSpot / Mirabox / none) — %~P expands
    // %APPDATA% to an absolute path, first existing = preferred; (3) else a sensible default.
    $plugdir = rtrim(trim(nm_deck_get($conn, 'deck_plugins_dir', '')), "/\\ ");
    if ($plugdir === '') {
        $det = 'for %P in ("%APPDATA%\\HotSpot\\StreamDock\\plugins" "%APPDATA%\\Mirabox\\StreamDock\\plugins" "%APPDATA%\\StreamDock\\plugins") do @if exist %P echo FOUND=%~P';
        $dr = nm_cm_ssh_fetch($ssh, $det, 20);
        foreach (preg_split('/\r?\n/', (string)($dr['config'] ?? '')) as $ln) {
            if (preg_match('/FOUND=(.+\S)/', $ln, $mm)) { $plugdir = trim($mm[1]); break; }
        }
    }
    if ($plugdir === '') $plugdir = '%APPDATA%\\HotSpot\\StreamDock\\plugins';   // default if none exist yet
    $dst = $plugdir . '\\com.neuru.noc.sdPlugin';

    // CRITICAL: the URL must have NO '&'. Handed to the Windows OpenSSH shell it is wrapped in cmd.exe
    // /c "…"; a '&' in the URL is then read as a cmd separator (nested quotes get eaten), truncating the
    // query string → curl hits stream_decks.php with no params → 302 → it downloads the denied_access.php
    // HTML page instead of the plugin → extract fails. Fix: single '?api=…' + token/fmt/base as HEADERS.
    $url = $base . '/stream_decks.php?api=plugin_download';
    // AV-SAFE: plain cmd.exe + signed native binaries only (curl.exe, tar.exe) — NO PowerShell /
    // -EncodedCommand (AMSI blocks base64 PS that downloads+drops+starts). tar.exe = bsdtar (Win10 1803+);
    // we serve a .tar (bsdtar rejects PHP's zip). Kill ONLY the main StreamDock app (NOT msfsDock — that's
    // MS Flight Simulator, a different plugin!). We don't relaunch — the user reopens it (needed to load
    // the plugin anyway). Also clean a stray install under the non-OEM %APPDATA%\StreamDock\plugins.
    // StreamDock caches plugin manifests in <root>\storecache — clearing it is REQUIRED for a manifest
    // change (new Controllers / knob support) to be re-read on next launch (a plain restart isn't enough).
    $storecache = dirname($plugdir) . '\\storecache';
    $hdr = '-H "X-NEURU-DECK:' . $token . '" -H "X-NEURU-FMT:tar" -H "X-NEURU-BASE:' . $base . '"';
    $cmd = 'curl.exe -f -k -s -L ' . $hdr . ' -o "%TEMP%\\nvd_plugin.tar" "' . $url . '"'
         . ' & (if not exist "%TEMP%\\nvd_plugin.tar" (echo NM_DEPLOY_ERR_DL) else ('
         . 'taskkill /F /T /IM "VSD Craft.exe" >nul 2>&1 & taskkill /F /IM VSDCraft.exe >nul 2>&1 & '
         . 'taskkill /F /IM StreamDock.exe >nul 2>&1 & taskkill /F /IM StreamDockApp.exe >nul 2>&1 & '
         . 'ping -n 5 127.0.0.1 >nul & '   // let "VSD Craft.exe" fully exit so it releases storecache + the plugin folder
         . 'rmdir /S /Q "%APPDATA%\\StreamDock\\plugins\\com.neuru.noc.sdPlugin" >nul 2>&1 & '
         . 'rmdir /S /Q "' . $dst . '" >nul 2>&1 & '
         . 'tar.exe -xf "%TEMP%\\nvd_plugin.tar" -C "' . $plugdir . '"'
         . ' && (rmdir /S /Q "' . $storecache . '" >nul 2>&1 & ping -n 2 127.0.0.1 >nul & rmdir /S /Q "' . $storecache . '" >nul 2>&1 & echo NM_DEPLOY_OK)'   // storecache clear (retry) → manifest re-read
         . ' || echo NM_DEPLOY_ERR_EXTRACT))';

    $r = nm_cm_ssh_fetch($ssh, $cmd, 90);
    $out = trim((string)($r['config'] ?? ''));
    if (strpos($out, 'NM_DEPLOY_OK') !== false)
        return ['ok' => true, 'msg' => 'Plugin installed (VSD Craft was closed to unlock it). REOPEN VSD Craft, then drag a NEURU Tile / Knob onto the deck once — it auto-configures.', 'log' => $out];
    if (strpos($out, 'NM_DEPLOY_ERR_DL') !== false)
        return ['ok' => false, 'msg' => 'Download step failed — the PC could not fetch ' . $base . ' (check the rig can reach that URL, or that curl.exe exists on Win10 1803+).', 'log' => $out];
    if (strpos($out, 'NM_DEPLOY_ERR_EXTRACT') !== false)
        return ['ok' => false, 'msg' => 'Downloaded, but extract failed (VSD Craft may still be locking the folder, or tar.exe is missing). Close VSD Craft and retry.', 'log' => $out];
    $err = $out !== '' ? $out : ($r['error'] ?? 'unknown error');
    return ['ok' => false, 'msg' => 'Deploy failed: ' . $err . '. (Check the SSH user = the VSD Craft Windows user, and that the PC can reach ' . $base . '.)', 'log' => $err];
}

// ── Server-side BUTTON FACE renderer (SVG — pure PHP, no GD; Elgato/Stream Dock setImage
//    accepts SVG data URIs). NEURU owns the cyberpunk identity + live value + color state; the
//    plugin just setImage()s whatever this returns. Reused by the in-portal "device view" too. ──

// Minimalist neon glyph for a catalog icon name — inner SVG centered ~(72,42), stroke=currentColor.
function nm_deck_svg_glyph(string $icon): string {
    $map = [
        'microchip' => 'chip', 'display' => 'chip', 'memory' => 'chip', 'hard-drive' => 'chip',
        'temperature-half' => 'thermo', 'fire' => 'thermo',
        'wifi' => 'net', 'plug-circle-xmark' => 'net',
        'server' => 'server',
        'triangle-exclamation' => 'warn',
        'shield-virus' => 'shield', 'shield-halved' => 'shield',
        'gamepad' => 'bolt', 'gauge-high' => 'bolt',
        'wand-magic-sparkles' => 'spark', 'broom' => 'spark', 'water' => 'spark',
        'brain' => 'nodes',
        'volume-high' => 'vol', 'volume-low' => 'vol', 'volume-xmark' => 'vol',
    ];
    switch ($map[$icon] ?? 'dot') {
        case 'chip':   return '<rect x="58" y="28" width="28" height="28" rx="4"/><rect x="65" y="35" width="14" height="14" rx="2"/><line x1="63" y1="24" x2="63" y2="28"/><line x1="72" y1="24" x2="72" y2="28"/><line x1="81" y1="24" x2="81" y2="28"/><line x1="63" y1="56" x2="63" y2="60"/><line x1="72" y1="56" x2="72" y2="60"/><line x1="81" y1="56" x2="81" y2="60"/>';
        case 'thermo': return '<rect x="68" y="22" width="8" height="24" rx="4"/><circle cx="72" cy="50" r="7"/><line x1="72" y1="30" x2="72" y2="47"/>';
        case 'net':    return '<path d="M56 40 a24 24 0 0 1 32 0"/><path d="M61 46 a16 16 0 0 1 22 0"/><circle cx="72" cy="55" r="2.6" fill="currentColor" stroke="none"/>';
        case 'server': return '<rect x="56" y="26" width="32" height="12" rx="2"/><rect x="56" y="42" width="32" height="12" rx="2"/><circle cx="62" cy="32" r="1.6" fill="currentColor" stroke="none"/><circle cx="62" cy="48" r="1.6" fill="currentColor" stroke="none"/>';
        case 'warn':   return '<path d="M72 24 L88 54 L56 54 Z"/><line x1="72" y1="37" x2="72" y2="46"/><circle cx="72" cy="50" r="1.4" fill="currentColor" stroke="none"/>';
        case 'shield': return '<path d="M72 24 L86 30 V44 C86 52 80 57 72 60 C64 57 58 52 58 44 V30 Z"/>';
        case 'bolt':   return '<path d="M74 24 L60 46 H70 L68 60 L84 38 H74 Z" fill="currentColor" stroke="none"/>';
        case 'spark':  return '<path d="M72 26 L75 39 L88 42 L75 45 L72 60 L69 45 L56 42 L69 39 Z" fill="currentColor" stroke="none"/>';
        case 'nodes':  return '<circle cx="72" cy="30" r="4"/><circle cx="60" cy="52" r="4"/><circle cx="84" cy="52" r="4"/><line x1="72" y1="34" x2="61" y2="49"/><line x1="72" y1="34" x2="83" y2="49"/><line x1="64" y1="52" x2="80" y2="52"/>';
        case 'vol':    return '<path d="M60 38 H66 L74 30 V58 L66 50 H60 Z" fill="currentColor" stroke="none"/><path d="M80 34 a10 10 0 0 1 0 20"/>';
        default:       return '<circle cx="72" cy="42" r="11"/>';
    }
}

// Render ONE key's face as an SVG string for a given catalog key + rig (uses live telemetry).
function nm_deck_render_svg($conn, string $key, int $rigId = 0): string {
    $cat  = nm_deck_action_catalog();
    $meta = $cat[$key] ?? null;
    $kind = $meta['kind'] ?? '';
    $label = $meta ? strtoupper($meta['label']) : '—';
    $icon  = $meta['icon'] ?? 'dot';
    $state = 'na'; $val = ''; $unit = ''; $isMetric = ($kind === 'metric');

    if ($isMetric) {
        $snap = nm_deck_telemetry($conn, $rigId > 0 ? $rigId : null, false, true);
        $m = $snap['metrics'][$key] ?? null;
        $v = $m['val'] ?? null; $state = $m['state'] ?? 'na';
        $val = ($v === null || $v === '') ? '—' : (string)$v; $unit = $meta['unit'] ?? '';
    } elseif ($kind === 'action') { $state = 'act'; }
    elseif ($kind === 'nav')      { $state = 'nav'; }

    $cols = ['ok' => '#22e08a', 'warn' => '#ffb020', 'crit' => '#ff4d5e', 'na' => '#5a6472', 'act' => '#4da3ff', 'nav' => '#38e0ff'];
    $col = $cols[$state] ?? '#4da3ff';
    $crit = $state === 'crit';
    $glyph = nm_deck_svg_glyph($icon);
    $lab = htmlspecialchars($label, ENT_QUOTES);
    $vv  = htmlspecialchars($val, ENT_QUOTES);
    $uu  = htmlspecialchars($unit, ENT_QUOTES);
    $pulse = $crit ? '<animate attributeName="stroke-opacity" values="0.35;1;0.35" dur="1.1s" repeatCount="indefinite"/>' : '';

    $mid = $isMetric
        ? '<text x="72" y="98" text-anchor="middle" font-family="Segoe UI,Arial,sans-serif" font-size="42" font-weight="800" fill="' . $col . '">' . $vv . '<tspan font-size="18" dx="1" fill="#9fb2cc">' . $uu . '</tspan></text>'
          . '<text x="72" y="129" text-anchor="middle" font-family="Segoe UI,Arial,sans-serif" font-size="12" font-weight="700" fill="#9fb2cc" letter-spacing="1">' . $lab . '</text>'
        : '<text x="72" y="104" text-anchor="middle" font-family="Segoe UI,Arial,sans-serif" font-size="16" font-weight="800" fill="' . $col . '" letter-spacing="0.5">' . $lab . '</text>';

    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 144 144" width="144" height="144">'
        . '<defs><linearGradient id="bg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#0c1626"/><stop offset="1" stop-color="#060a12"/></linearGradient>'
        . '<radialGradient id="gl" cx="0.5" cy="0.12" r="0.9"><stop offset="0" stop-color="' . $col . '" stop-opacity="0.28"/><stop offset="0.65" stop-color="' . $col . '" stop-opacity="0"/></radialGradient></defs>'
        . '<rect width="144" height="144" rx="18" fill="url(#bg)"/><rect width="144" height="144" rx="18" fill="url(#gl)"/>'
        . '<rect x="3" y="3" width="138" height="138" rx="16" fill="none" stroke="' . $col . '" stroke-width="2" stroke-opacity="0.8">' . $pulse . '</rect>'
        . '<g stroke="' . $col . '" stroke-width="2.4" fill="none" stroke-linecap="round" stroke-linejoin="round">' . $glyph . '</g>'
        . $mid . '</svg>';
}

// ── PNG button-face renderer (GD) — the reliable format for Stream Dock setImage (SVG data URIs
//    are unreliable across builds). Mirrors the SVG tile: state-colored border + glyph + big live
//    value + label on a dark cyberpunk background. Font bundled in the app dir (survives recreate). ──
function nm_deck_font(): string {
    $f = __DIR__ . '/nm_deck_font.ttf';
    if (is_file($f)) return $f;
    foreach (['/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'] as $s) if (is_file($s)) return $s;
    return $f;
}

function nm_deck_render_png($conn, string $key, string $tgt = '', bool $transparent = false): string {
    $state = 'na'; $val = ''; $unit = ''; $isMetric = false; $icon = 'dot'; $label = '—'; $kind = '';
    if (nm_deck_is_dynkey($key)) {   // dynamic per-node metric (device_stats / traffic / status)
        $nid = preg_match('/^n(\d+)$/', trim($tgt), $mm) ? (int)$mm[1] : 0;
        $d = nm_deck_node_dynamic($conn, $nid, $key);
        $isMetric = true; $label = strtoupper($d['label']); $icon = $d['icon']; $unit = $d['unit'];
        $v = $d['val']; $state = $d['state']; $val = ($v === null || $v === '') ? '—' : (string)$v;
    } else {
        $meta = nm_deck_action_catalog()[$key] ?? null;
        $kind = $meta['kind'] ?? '';
        $label = $meta ? strtoupper($meta['label']) : '—';
        $icon = $meta['icon'] ?? 'dot';
        $isMetric = ($kind === 'metric');
        if ($isMetric) {
            $mv = nm_deck_metric_for_target($conn, $key, $tgt);
            $v = $mv['val']; $state = $mv['state'];
            $val = ($v === null || $v === '') ? '—' : (string)$v; $unit = $meta['unit'] ?? '';
        } elseif ($kind === 'action') { $state = 'act'; }
        elseif ($kind === 'nav')      { $state = 'nav'; }
    }

    $cols = ['ok' => [34, 224, 138], 'warn' => [255, 176, 32], 'crit' => [255, 77, 94],
             'na' => [90, 100, 114], 'act' => [77, 163, 255], 'nav' => [56, 224, 255]];
    $c = $cols[$state] ?? $cols['act'];
    $W = 144; $im = imagecreatetruecolor($W, $W);
    if ($transparent) {
        // touch-bar / knob screen: transparent background so it blends with the pad's own wallpaper
        // (like the native tiles) — just glyph + value + label, drawn with a shadow for legibility.
        imagesavealpha($im, true); imagealphablending($im, false);
        imagefilledrectangle($im, 0, 0, $W, $W, imagecolorallocatealpha($im, 0, 0, 0, 127));
        imagealphablending($im, true);
    } else {
        imagealphablending($im, true);
        for ($y = 0; $y < $W; $y++) {   // dark gradient bg
            $t = $y / $W; $r = (int)(12 - 6 * $t); $g = (int)(22 - 12 * $t); $b = (int)(38 - 22 * $t);
            imageline($im, 0, $y, $W, $y, imagecolorallocate($im, max(0,$r), max(0,$g), max(0,$b)));
        }
        for ($y = 0; $y < 60; $y++) { $a = (int)(110 - $y * 1.8); if ($a < 0) $a = 0; imageline($im, 0, $y, $W, $y, imagecolorallocatealpha($im, $c[0], $c[1], $c[2], 127 - (int)($a / 4))); }
    }

    // ── custom icon/background (user upload per catalog key) — cover-fit + dark overlay for legibility ──
    $hasIcon = false;
    $iconRel = nm_deck_get($conn, 'deck_icon_' . $key, '');
    if ($iconRel !== '') {
        $ip = __DIR__ . '/' . ltrim($iconRel, '/');
        if (is_file($ip) && ($raw = @file_get_contents($ip)) !== false && ($src = @imagecreatefromstring($raw))) {
            $sw = imagesx($src); $sh = imagesy($src);
            if ($sw > 0 && $sh > 0) {
                $scale = max($W / $sw, $W / $sh); $dw = (int)($sw * $scale); $dh = (int)($sh * $scale);
                imagecopyresampled($im, $src, (int)(($W - $dw) / 2), (int)(($W - $dh) / 2), 0, 0, $dw, $dh, $sw, $sh);
                imagefilledrectangle($im, 0, 0, $W, $W, imagecolorallocatealpha($im, 0, 0, 0, $isMetric ? 72 : 40));   // legibility scrim
                $hasIcon = true;
            }
            imagedestroy($src);
        }
    }

    $font = nm_deck_font();
    $bc = imagecolorallocate($im, $c[0], $c[1], $c[2]);
    // neon border — opaque tiles only (transparent touch-bar/knob tiles stay borderless like the native ones)
    if (!$transparent) { imagesetthickness($im, 4); imagerectangle($im, 3, 3, $W - 4, $W - 4, $bc); imagesetthickness($im, 3); }
    // glyph (skip when a custom icon fills the tile)
    if (!$hasIcon) nm_deck_png_glyph($im, $icon, $c);

    // text writer with an optional drop-shadow (legibility over the touch bar's wallpaper)
    $shadow = imagecolorallocatealpha($im, 0, 0, 0, 55);
    $T = function ($sz, $x, $y, $col, $txt) use ($im, $font, $transparent, $shadow) {
        if ($transparent) imagettftext($im, $sz, 0, $x + 2, $y + 2, $shadow, $font, $txt);
        imagettftext($im, $sz, 0, $x, $y, $col, $font, $txt);
    };
    $grey = imagecolorallocate($im, $transparent ? 210 : 159, $transparent ? 222 : 178, $transparent ? 238 : 204);
    if ($isMetric) {
        $txt = $val . $unit;
        $sz = strlen($txt) >= 5 ? 26 : (strlen($txt) >= 4 ? 30 : 34);
        $bb = imagettfbbox($sz, 0, $font, $txt); $tw = $bb[2] - $bb[0];
        $T($sz, (int)(($W - $tw) / 2), 100, $bc, $txt);
        $ls = 11; $bb2 = imagettfbbox($ls, 0, $font, $label); $lw = $bb2[2] - $bb2[0];
        $T($ls, (int)(($W - $lw) / 2), 128, $grey, $label);
    } else {
        $words = explode(' ', $label); $lines = []; $cur = '';
        foreach ($words as $w) { $try = $cur === '' ? $w : $cur . ' ' . $w; $bb = imagettfbbox(13, 0, $font, $try); if (($bb[2] - $bb[0]) > $W - 20 && $cur !== '') { $lines[] = $cur; $cur = $w; } else $cur = $try; }
        if ($cur !== '') $lines[] = $cur;
        $y = 96; foreach (array_slice($lines, 0, 2) as $ln) { $bb = imagettfbbox(13, 0, $font, $ln); $lw = $bb[2] - $bb[0]; $T(13, (int)(($W - $lw) / 2), $y, $bc, $ln); $y += 20; }
    }

    ob_start(); imagepng($im); $png = ob_get_clean(); imagedestroy($im);
    return $png;
}

// simple GD glyph per icon (basic shapes), color $c, centered ~(72,40)
function nm_deck_png_glyph($im, string $icon, array $c): void {
    $col = imagecolorallocate($im, $c[0], $c[1], $c[2]);
    imagesetthickness($im, 3);
    $map = ['microchip'=>'chip','display'=>'chip','memory'=>'chip','hard-drive'=>'chip','temperature-half'=>'thermo','fire'=>'thermo',
            'wifi'=>'net','plug-circle-xmark'=>'net','server'=>'server','triangle-exclamation'=>'warn','shield-virus'=>'shield','shield-halved'=>'shield',
            'gamepad'=>'bolt','gauge-high'=>'bolt','wand-magic-sparkles'=>'spark','broom'=>'spark','water'=>'spark','brain'=>'nodes'];
    switch ($map[$icon] ?? 'dot') {
        case 'chip':   imagerectangle($im,58,26,86,54,$col); imagerectangle($im,66,34,78,46,$col);
                       foreach([63,72,81] as $x){ imageline($im,$x,22,$x,26,$col); imageline($im,$x,54,$x,58,$col); } break;
        case 'thermo': imagefilledrectangle($im,69,22,75,44,$col); imagefilledellipse($im,72,50,16,16,$col); break;
        case 'net':    imagearc($im,72,54,52,52,200,340,$col); imagearc($im,72,54,32,32,205,335,$col); imagefilledellipse($im,72,52,6,6,$col); break;
        case 'server': imagerectangle($im,56,26,88,38,$col); imagerectangle($im,56,42,88,54,$col); imagefilledellipse($im,63,32,4,4,$col); imagefilledellipse($im,63,48,4,4,$col); break;
        case 'warn':   $p=[72,24,88,54,56,54]; imagepolygon($im,$p,3,$col); imageline($im,72,36,72,46,$col); imagefilledellipse($im,72,50,4,4,$col); break;
        case 'shield': $p=[72,24,86,30,86,44,72,60,58,44,58,30]; imagepolygon($im,$p,6,$col); break;
        case 'bolt':   $p=[74,24,60,44,70,44,68,58,84,36,74,36]; imagefilledpolygon($im,$p,6,$col); break;
        case 'spark':  $p=[72,24,76,38,90,42,76,46,72,60,68,46,54,42,68,38]; imagefilledpolygon($im,$p,8,$col); break;
        case 'nodes':  imagefilledellipse($im,72,30,8,8,$col); imagefilledellipse($im,60,52,8,8,$col); imagefilledellipse($im,84,52,8,8,$col); imageline($im,72,34,60,48,$col); imageline($im,72,34,84,48,$col); break;
        default:       imageellipse($im,72,40,22,22,$col);
    }
}

} // function_exists guard
