<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — central access-control engine.
//
//   Permission model (industry-standard layered RBAC + per-user overrides):
//     1. ROLE default   — role_profiles(role_name, button_key, enabled)
//     2. USER override   — nm_user_perms(uid, button_key, effect=allow|deny)
//   Resolution: a per-user override (allow OR deny) ALWAYS wins over the role
//   default. Absence of an override = inherit the role. This lets you grant one
//   person an extra page, or revoke a page from one person, without minting a
//   whole new role.
//
//   Use nm_user_can($conn,$uid,$role,$key) everywhere. checkAccess() (page
//   handlers) and _nm_can() (nav) both funnel through it. Results for a given
//   (uid,role) are resolved with ONE role query + ONE override query and cached
//   for the rest of the request, so a page calling _nm_can() a dozen times is
//   two queries, not two dozen.
// ─────────────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/nm_audit.php';

// ── Permission catalog ───────────────────────────────────────────────────────
// The single source of truth for every gated page. Drives the role matrix UI
// (grouped by category) and documents what each button_key protects. Adding a
// new gated page = add one row here + a role_profiles seed.
if (!function_exists('nm_perm_catalog')) {
    function nm_perm_catalog(): array {
        return [
            // key               label                 category          icon                                  page
            ['net_mon',         'Dashboard',          'Monitoring',     'fa-solid fa-chart-line',             'net_mon.php'],
            ['incidents',       'Incident Command',   'Monitoring',     'fa-solid fa-triangle-exclamation',   'incidents.php'],
            ['net_mon_map',     'Network Map',        'Command Centers','fa-solid fa-diagram-project',        'net_mon_map.php'],
            ['geomap',          'Geo Wall (NOC)',     'Command Centers','fa-solid fa-earth-americas',         'geomap.php'],
            ['command',         'Command Center',     'Command Centers','fa-solid fa-satellite-dish',         'command.php'],
            ['federation',      'Federation',         'Site Configuration','fa-solid fa-sitemap',             'federation.php'],
            ['license',         'Licensing',          'Site Configuration','fa-solid fa-certificate',         'license.php'],
            ['update',          'Updates',            'Site Configuration','fa-solid fa-cloud-arrow-down',    'update.php'],
            ['config_backup',   'Save Configuration', 'Site Configuration','fa-solid fa-floppy-disk',         'config_backup.php'],
            ['stream_decks',    'Stream Decks',       'Site Configuration','fa-solid fa-grip',                'stream_decks.php'],
            ['vault',           'Data Vault',         'Site Configuration','fa-solid fa-vault',               'vault.php'],
            ['about',           'About',              'Site Configuration','fa-solid fa-circle-info',          'about.php'],
            ['neurutik',        'NEURUTIK (Unified)', 'Command Centers','fa-solid fa-circle-nodes',           'neurutik.php'],
            ['matrix_flow',     'NEURUTIK Matrix Flow','Command Centers','fa-solid fa-diagram-project',       'matrix_flow.php'],
            ['hologram',        'Traffic Hologram',   'Command Centers','fa-solid fa-cube',                   'hologram.php'],
            ['traffic_view',    'Realtime Traffic',   'Command Centers','fa-solid fa-wave-square',            'traffic_viewer.php'],
            ['cisco',           'Cisco Fleet',        'Cisco',          'fa-solid fa-network-wired',          'cisco.php'],
            ['cisco_switch',    'Cisco Switches',     'Cisco',          'fa-solid fa-ethernet',               'cisco_switch.php'],
            ['cisco_asa',       'Cisco ASA Firewall', 'Cisco',          'fa-solid fa-shield-halved',          'cisco_asa.php'],
            ['cisco_router',    'Cisco Routers',      'Cisco',          'fa-solid fa-route',                  'cisco_router.php'],
            ['cisco_orch',      'Cisco Orchestrator', 'Cisco',          'fa-solid fa-sliders',                'cisco_orch.php'],
            ['router_center',   'Router Command Ctr', 'Command Centers','fa-solid fa-route',                  'router_command.php'],
            ['routing_center',  'Routing Command Ctr','Command Centers','fa-solid fa-diagram-project',        'routing_command.php'],
            ['live_mon',        'Live Monitor',       'Monitoring',     'fa-solid fa-tower-broadcast',        'live_mon.php'],
            ['net_mon_stats',   'Statistics',         'Monitoring',     'fa-solid fa-chart-bar',              'net_mon_stats.php'],
            ['netflow',         'NetFlow Analyzer',   'Monitoring',     'fa-solid fa-chart-area',             'netflow.php'],
            ['l2switch',        'Unmanaged Switches', 'Monitoring',     'fa-solid fa-ethernet',               'l2switch.php'],
            ['shadowit',        'Shadow IT',          'Monitoring',     'fa-solid fa-user-secret',            'shadowit.php'],
            ['gaming',          'Game Mode',          'Gaming',         'fa-solid fa-gamepad',                'gaming.php'],
            ['pc_doctor',       'PC Doctor',          'Gaming',         'fa-solid fa-microchip',              'pc_troubleshoot.php'],
            ['health',          'Predictive Health',  'Monitoring',     'fa-solid fa-heart-pulse',            'health.php'],
            ['timetravel',      'Time-Travel',        'Monitoring',     'fa-solid fa-clock-rotate-left',      'timetravel.php'],
            ['chaos',           'Chaos Test',         'Monitoring',     'fa-solid fa-burst',                  'chaos.php'],
            ['heal',            'Self-Healing',       'Healing',        'fa-solid fa-robot',                  'heal.php'],
            ['autopilotv2',     'NEURU Commander', 'Command Centers','fa-solid fa-brain',                  'autopilotv2.php'],
            ['troubleshoot',    'Troubleshoot Wizard','Monitoring',     'fa-solid fa-stethoscope',            'troubleshoot.php'],
            ['sonify',          'Network Sonar',      'Monitoring',     'fa-solid fa-satellite-dish',         'sonify.php'],
            ['wear',            'Wear & Stress',      'Monitoring',     'fa-solid fa-heart-crack',            'wear.php'],

            ['nettools_ping',   'Live Ping',          'Net Tools',      'fa-solid fa-tower-broadcast',        'netping.php'],
            ['nettools_trace',  'Traceroute Map',     'Net Tools',      'fa-solid fa-route',                  'nettrace.php'],
            ['nettools_netstat','Netstat',            'Net Tools',      'fa-solid fa-diagram-project',        'netstat.php'],
            ['nettools_lookup', 'NS Lookup',          'Net Tools',      'fa-solid fa-magnifying-glass-location','netlookup.php'],
            ['nettools_portscan','Port Scanner',      'Net Tools',      'fa-solid fa-satellite-dish',         'portscan.php'],

            ['log_mon',         'Logs',               'Logs & AI',      'fa-solid fa-file-lines',             'log_mon.php'],
            ['archaeology',     'AI Archaeologist',  'AI Tools',       'fa-solid fa-magnifying-glass-chart', 'archaeology.php'],
            ['ai_insights',     'AI Insights',        'AI Tools',       'fa-solid fa-wand-magic-sparkles',    'ai_insights.php'],
            ['biosphere',       'Service Biosphere',  'Command Centers','fa-solid fa-dna',                    'biosphere.php'],
            ['copilot',         'NetOps Copilot',     'Logs & AI',      'fa-solid fa-robot',                  null],

            ['containers',      'Containers',         'Infrastructure', 'fa-brands fa-docker',                'containers.php'],
            ['dbmon',           'Data Core (DBs)',    'Infrastructure', 'fa-solid fa-database',               'dbmon.php'],
            ['dbobs',           'DB Observatory',     'Command Centers','fa-solid fa-satellite',              'dbobservatory.php'],
            ['smokeping',       'Smokeping',          'Infrastructure', 'fa-solid fa-wave-square',            'smokeping.php'],
            ['config_mgr',      'Config Manager',     'Infrastructure', 'fa-solid fa-file-shield',            'config_mgr.php'],
            ['router_commander','Adv. Solution Commander','Infrastructure', 'fa-solid fa-network-wired',        'router_commander.php'],
            ['mtfw',            'MikroTik Device Manager',  'Infrastructure', 'fa-solid fa-shield-halved',          'mtfw.php'],
            ['wifi',            'WiFi Control Center','Infrastructure', 'fa-solid fa-wifi',                   'wifi.php'],
            ['wireguard',       'WireGuard Orchestr.','Infrastructure', 'fa-solid fa-shield-halved',          'wireguard.php'],
            ['gpu',             'AI / GPU Monitor',   'AI Tools',       'fa-solid fa-microchip',              'gpu.php'],
            ['windows',         'Windows Monitor',    'Infrastructure', 'fa-brands fa-windows',               'windows.php'],
            ['linux',           'Linux Monitor',      'Infrastructure', 'fa-brands fa-linux',                 'linux.php'],
            ['watchdog',        'Service Watchdog',   'Infrastructure', 'fa-solid fa-shield-heart',           'watchdog.php'],
            ['routers',         'Router Monitor',     'Infrastructure', 'fa-solid fa-route',                  'routers.php'],
            ['pihole',          'Pi-hole',            'Infrastructure', 'fa-solid fa-shield-halved',          'pihole.php'],
            ['weather',         'Weather Routing',    'Infrastructure', 'fa-solid fa-hurricane',             'weather.php'],
            ['immunity',        'Collective Immunity','Healing',        'fa-solid fa-shield-virus',           'immunity.php'],
            ['deception',       'Deception Grid',     'Healing',        'fa-solid fa-mask',                   'deception.php'],

            ['ipam',            'IP Address Mgmt',    'Administration', 'fa-solid fa-sitemap',                'ipam.php'],
            ['reports',         'SLA &amp; Reports',  'Administration', 'fa-solid fa-gauge-high',             'reports.php'],
            ['sla_live',        'SLA Live Center',    'Monitoring',     'fa-solid fa-heart-pulse',            'sla.php'],
            ['net_mon_config',  'Configuration',      'Administration', 'fa-solid fa-gear',                   'net_mon_config.php'],
            ['user_admin',      'Access Control',     'Administration', 'fa-solid fa-user-shield',            'access_admin.php'],
            ['audit_log',       'Audit Log',          'Administration', 'fa-solid fa-clipboard-list',         'audit_log.php'],
            ['support',         'Support &amp; Bugs', 'Administration', 'fa-solid fa-life-ring',              'support.php'],
        ];
    }

    // Ordered list of category names as they should render.
    function nm_perm_categories(): array {
        $out = [];
        foreach (nm_perm_catalog() as $r) if (!in_array($r[2], $out, true)) $out[] = $r[2];
        return $out;
    }

    // Lookup metadata for one key (or null).
    function nm_perm_meta(string $key): ?array {
        foreach (nm_perm_catalog() as $r) {
            if ($r[0] === $key) return ['key'=>$r[0],'label'=>$r[1],'category'=>$r[2],'icon'=>$r[3],'page'=>$r[4]];
        }
        return null;
    }

    // All known keys.
    function nm_perm_keys(): array { return array_map(fn($r)=>$r[0], nm_perm_catalog()); }
}

// ── Schema guard ─────────────────────────────────────────────────────────────
// Idempotent; safe to call on any request. Creates the override table if a fresh
// environment is missing it (the main migration already did this in prod).
if (!function_exists('nm_access_ensure')) {
    function nm_access_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        try {
            $conn->query(
                "CREATE TABLE IF NOT EXISTS nm_user_perms (
                    uid INT NOT NULL,
                    button_key VARCHAR(50) NOT NULL,
                    effect ENUM('allow','deny') NOT NULL,
                    updated_by VARCHAR(50) DEFAULT NULL,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    PRIMARY KEY (uid, button_key),
                    KEY idx_uid (uid)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            );
        } catch (\Throwable $e) { /* best-effort */ }
        // Self-heal: the 'admin' (owner) role must have a grant row for EVERY catalog permission,
        // so a newly-added gated page (e.g. after a product update) is immediately visible to the
        // owner without a manual RBAC edit. Inserts only MISSING perms → non-destructive + idempotent.
        static $backfilled = false;
        if (!$backfilled && function_exists('nm_perm_catalog')) {
            $backfilled = true;
            try {
                $have = [];
                if ($r = $conn->query("SELECT button_key FROM role_profiles WHERE role_name='admin'"))
                    while ($x = $r->fetch_assoc()) $have[$x['button_key']] = 1;
                foreach (nm_perm_catalog() as $row) {
                    $k = $row[0];
                    if (!isset($have[$k])) {
                        $st = $conn->prepare("INSERT INTO role_profiles (role_name,button_key,enabled) VALUES ('admin',?,1)");
                        $st->bind_param('s', $k); $st->execute(); $st->close();
                    }
                }
            } catch (\Throwable $e) { /* best-effort */ }
        }
    }
}

// ── Resolution ───────────────────────────────────────────────────────────────
if (!function_exists('nm_access_resolve_all')) {
    // Returns ['button_key' => bool] — the FINAL effective grant for (uid,role),
    // role defaults overlaid with per-user overrides. Cached per request.
    function nm_access_resolve_all($conn, $uid, string $role, bool $bust = false): array {
        static $cache = [];
        if ($bust) { $cache = []; }
        $uid = (int)$uid;
        $ck  = $role . '#' . $uid;
        if (isset($cache[$ck])) return $cache[$ck];

        $map = [];
        // 1) role defaults
        try {
            $st = $conn->prepare("SELECT button_key, enabled FROM role_profiles WHERE role_name=?");
            $st->bind_param('s', $role);
            $st->execute();
            $r = $st->get_result();
            while ($x = $r->fetch_assoc()) $map[$x['button_key']] = (bool)$x['enabled'];
            $st->close();
        } catch (\Throwable $e) { /* role table missing → empty map */ }

        // 2) per-user overrides (deny or allow both win over the role default)
        if ($uid > 0) {
            try {
                $st = $conn->prepare("SELECT button_key, effect FROM nm_user_perms WHERE uid=?");
                $st->bind_param('i', $uid);
                $st->execute();
                $r = $st->get_result();
                while ($x = $r->fetch_assoc()) $map[$x['button_key']] = ($x['effect'] === 'allow');
                $st->close();
            } catch (\Throwable $e) { /* override table missing → role-only */ }
        }

        $cache[$ck] = $map;
        return $map;
    }

    // The single gate. true = allowed.
    function nm_user_can($conn, $uid, ?string $role, string $key): bool {
        $map = nm_access_resolve_all($conn, $uid, $role ?? 'guest');
        return !empty($map[$key]);
    }

    // Convenience: resolve for the CURRENT session user.
    function nm_can($conn, string $key): bool {
        return nm_user_can($conn, $_SESSION['UID'] ?? 0, $_SESSION['role'] ?? 'guest', $key);
    }
}

// ── Lockout protection ───────────────────────────────────────────────────────
// Count how many ENABLED user accounts would still be able to reach Access
// Control (button_key 'user_admin') AFTER a hypothetical change. The admin UI
// calls this before saving a role/override change and refuses any change that
// would drop the count to zero — so the portal can never lock every admin out.
if (!function_exists('nm_access_admin_count')) {
    function nm_access_admin_count($conn): int {
        $count = 0;
        nm_access_resolve_all($conn, 0, 'guest', true); // bust the per-request cache first
        try {
            $res = $conn->query("SELECT UID, role FROM users");
            while ($u = $res->fetch_assoc()) {
                if (nm_user_can($conn, (int)$u['UID'], $u['role'] ?? 'guest', 'user_admin')) $count++;
            }
        } catch (\Throwable $e) { return 1; } // fail safe: don't block on error
        return $count;
    }
}
