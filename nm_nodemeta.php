<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — node metadata: device classification + industry-standard asset fields.
//  · nm_node_meta_ensure()  adds asset columns to nm_nodes (guarded; flag-gated so
//    it's cheap to call on every request — mysqli is in EXCEPTION mode so ALTERs
//    must be probed first).
//  · nm_node_kind()  the ONE place that maps a node → windows|linux|router|ping|snmp
//    (mirrors nm_aip_capabilities() so the UI and the AI-pilot agree).
//  · nm_node_cc()  resolves a node → its "Command Center" / detail destination.
// ─────────────────────────────────────────────────────────────────────────────

if (!function_exists('nm_node_meta_ensure')) {

    // Asset columns we manage on nm_nodes (CMDB-style: model, serial, warranty …).
    function nm_node_asset_cols(): array {
        return [
            'photo_path'      => "VARCHAR(255) NULL",
            'manufacturer'    => "VARCHAR(120) NULL",
            'model'           => "VARCHAR(120) NULL",
            'serial_number'   => "VARCHAR(120) NULL",
            'asset_tag'       => "VARCHAR(80) NULL",
            'purchase_date'   => "DATE NULL",
            'warranty_expiry' => "DATE NULL",
            'asset_notes'     => "TEXT NULL",
        ];
    }

    // Idempotent, cheap (one nm_settings read short-circuits after first success).
    function nm_node_meta_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        try {
            $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='nm_asset_schema' LIMIT 1");
            if ($r && $r->num_rows) return;   // already migrated
        } catch (\Throwable $e) { /* nm_settings may not exist on a bare install — fall through */ }

        try {
            $have = [];
            $c = $conn->query("SELECT COLUMN_NAME FROM information_schema.COLUMNS
                               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_nodes'");
            while ($c && $x = $c->fetch_assoc()) $have[strtolower($x['COLUMN_NAME'])] = true;

            foreach (nm_node_asset_cols() as $col => $ddl) {
                if (!isset($have[strtolower($col)])) {
                    try { $conn->query("ALTER TABLE nm_nodes ADD COLUMN `$col` $ddl"); }
                    catch (\Throwable $e) { /* concurrent add / perms — non-fatal */ }
                }
            }
            // mark done (best-effort)
            try { $conn->query("INSERT INTO nm_settings(setting_key,setting_val) VALUES('nm_asset_schema','1')
                                ON DUPLICATE KEY UPDATE setting_val='1'"); } catch (\Throwable $e) {}
        } catch (\Throwable $e) { /* never let a schema probe take down a page */ }
    }

    // Canonical device kind. Keep in lockstep with nm_aip_capabilities() (nm_aiopilot.php).
    function nm_node_kind(array $n): string {
        $os = strtolower(trim((string)($n['os_icon'] ?? 'generic')));
        $mt = strtolower(trim((string)($n['monitor_type'] ?? 'snmp')));
        if ($mt === 'ping') return 'ping';
        if (in_array($os, ['mikrotik','routeros','router','cisco','juniper','arista','fortinet','fortigate','ubiquiti','edgeos','edgerouter','vyos','pfsense','opnsense'], true)) return 'router';
        if ($os === 'windows') return 'windows';
        if ($os === 'linux')   return 'linux';
        return 'snmp';
    }

    // Web path for a node's equipment photo, or null.
    function nm_node_photo_url(array $n): ?string {
        $p = trim((string)($n['photo_path'] ?? ''));
        if ($p === '') return null;
        $abs = __DIR__ . '/' . ltrim($p, '/');
        return is_file($abs) ? $p : null;
    }

    // Resolve a node to its best "open" destination.
    //   $winHostId / $lxHostId — the adopted nm_win_hosts.id / nm_lx_hosts.id if any.
    // Returns ['kind','url','label','icon','perm'].  router / ping / generic all land on
    // router_details.php (the universal device-detail page); windows/linux prefer their
    // immersive Command Center when the host has been adopted, else fall back to details.
    function nm_node_cc(array $n, ?int $winHostId = null, ?int $lxHostId = null): array {
        $kind = nm_node_kind($n);
        $nid  = (int)($n['id'] ?? 0);
        $detail = ['kind'=>$kind, 'url'=>"router_details.php?node=$nid", 'label'=>'Device Details', 'icon'=>'fa-circle-info', 'perm'=>'net_mon'];
        switch ($kind) {
            case 'windows':
                if ($winHostId) return ['kind'=>'windows','url'=>"win_screen.php?host=$winHostId",'label'=>'Command Center','icon'=>'fa-window-maximize','perm'=>'windows'];
                return $detail;
            case 'linux':
                if ($lxHostId)  return ['kind'=>'linux','url'=>"linux_screen.php?host=$lxHostId",'label'=>'Command Center','icon'=>'fa-server','perm'=>'linux'];
                return $detail;
            case 'router':
                return ['kind'=>'router','url'=>"router_details.php?node=$nid",'label'=>'Router Details','icon'=>'fa-route','perm'=>'net_mon'];
            case 'ping':
                return ['kind'=>'ping','url'=>"router_details.php?node=$nid",'label'=>'Device Details','icon'=>'fa-satellite-dish','perm'=>'net_mon'];
        }
        return $detail;   // generic SNMP host
    }
}
