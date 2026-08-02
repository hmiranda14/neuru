<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — post-update migrations (idempotent). The self-updater includes this
// after swapping in new files, so installs that UPDATE (not fresh-install) pick up
// new permissions / schema tweaks automatically. $conn is in scope (mysqli).
// Fresh installs get the same grants from install/neuru-install.sql.
// Keep every statement idempotent and guarded.
// ─────────────────────────────────────────────────────────────────────────────
if (isset($conn) && $conn instanceof mysqli) {
    // grant new admin-only pages so their nav items appear after an update
    $grants = [
        ['admin', 'update'],        // Updates page (self-updater)
        ['admin', 'license'],       // Licensing page (activation)
        ['admin', 'traffic_view'],  // Realtime Traffic Viewer (WebGL command center)
        ['admin', 'cisco'],         // Cisco Fleet (Cisco Suite F0 hub)
        ['admin', 'cisco_switch'],  // Cisco Switches (F1 WebGL front-panel)
        ['admin', 'cisco_asa'],     // Cisco ASA Firewall (F2 dashboard)
        ['admin', 'cisco_router'],  // Cisco Routers (F3 control-plane)
        ['admin', 'cisco_orch'],    // Cisco Orchestrator (F4 config + Safe-Apply)
    ];
    foreach ($grants as [$role, $key]) {
        try {
            $st = $conn->prepare("INSERT INTO role_profiles (role_name,button_key,enabled) VALUES (?,?,1)
                                  ON DUPLICATE KEY UPDATE enabled=enabled");
            $st->bind_param('ss', $role, $key); $st->execute(); $st->close();
        } catch (\Throwable $e) { /* best-effort */ }
    }
}
