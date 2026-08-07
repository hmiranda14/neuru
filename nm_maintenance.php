<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — per-node MAINTENANCE MODE ("Unmanage" / "Pause", industry-standard).
//
// While a node is in maintenance: NO collector gathers data from it (ping, SNMP,
// SSH, netflow, …), alerts & incidents for it are suppressed, it shows a distinct
// "maintenance" state system-wide (not up / not down), and the window is EXCLUDED
// from SLA/availability. A node is IN maintenance when `maintenance_until` is set
// and still in the future. Indefinite = a far-future sentinel. It AUTO-EXPIRES by
// time — no cron needed. This file is the single source of truth every view + the
// PHP collectors read; the Python pollers apply the same predicate in SQL.
//
//   nm_maint_ensure($conn)                     — create the columns (guarded)
//   nm_maint_exclude_sql($alias)               — SQL: nodes NOT in maintenance
//   nm_maint_only_sql($alias)                  — SQL: nodes IN maintenance
//   nm_maint_active_ids($conn)                 — [id=>1] currently in maintenance
//   nm_node_in_maint($conn,$id)                — bool
//   nm_maint_set($conn,$id,$until,$reason,$by) — enter maintenance (null $until = indefinite)
//   nm_maint_clear($conn,$id,$by)              — resume monitoring
//   nm_maint_row($conn,$id)                    — {until,since,by,reason,active,indefinite}
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_maint_ensure')) {

    // Sentinel used for "indefinite" so a single DATETIME column covers both cases.
    if (!defined('NM_MAINT_FOREVER')) define('NM_MAINT_FOREVER', '2999-12-31 00:00:00');

    // Add the maintenance columns to nm_nodes if missing. mysqli is in EXCEPTION mode,
    // so we check information_schema first and never blind-ALTER.
    function nm_maint_ensure($conn): void {
        try {
            $have = [];
            $r = $conn->query("SELECT COLUMN_NAME FROM information_schema.COLUMNS
                               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_nodes'
                                 AND COLUMN_NAME IN ('maintenance_until','maintenance_since','maintenance_by','maintenance_reason')");
            while ($r && $x = $r->fetch_assoc()) $have[$x['COLUMN_NAME']] = 1;
            $add = [];
            if (!isset($have['maintenance_until']))  $add[] = "ADD COLUMN maintenance_until DATETIME NULL";
            if (!isset($have['maintenance_since']))  $add[] = "ADD COLUMN maintenance_since DATETIME NULL";
            if (!isset($have['maintenance_by']))     $add[] = "ADD COLUMN maintenance_by VARCHAR(64) NULL";
            if (!isset($have['maintenance_reason'])) $add[] = "ADD COLUMN maintenance_reason VARCHAR(255) NULL";
            if ($add) $conn->query("ALTER TABLE nm_nodes " . implode(', ', $add));
        } catch (\Throwable $e) { /* best-effort — never break a page/cron over the schema check */ }
    }

    // SQL predicate that EXCLUDES nodes currently in maintenance. Drop into any collector's
    // node-selection WHERE. $alias = the nm_nodes alias in that query ('' for none).
    function nm_maint_exclude_sql(string $alias = ''): string {
        $p = $alias !== '' ? $alias . '.' : '';
        return "({$p}maintenance_until IS NULL OR {$p}maintenance_until <= NOW())";
    }
    // The inverse — ONLY nodes currently in maintenance.
    function nm_maint_only_sql(string $alias = ''): string {
        $p = $alias !== '' ? $alias . '.' : '';
        return "({$p}maintenance_until IS NOT NULL AND {$p}maintenance_until > NOW())";
    }

    // Per-request cached set of node ids currently in maintenance.
    function nm_maint_active_ids($conn): array {
        static $cache = null;
        if ($cache !== null) return $cache;
        $cache = [];
        try {
            $r = $conn->query("SELECT id FROM nm_nodes WHERE maintenance_until IS NOT NULL AND maintenance_until > NOW()");
            while ($r && $x = $r->fetch_row()) $cache[(int)$x[0]] = 1;
        } catch (\Throwable $e) { /* column may not exist yet on a very old install */ }
        return $cache;
    }
    function nm_node_in_maint($conn, int $id): bool {
        return isset(nm_maint_active_ids($conn)[$id]);
    }

    // Enter maintenance. $until = 'Y-m-d H:i:s' (or anything strtotime parses); null/'' = indefinite.
    function nm_maint_set($conn, int $id, ?string $until, string $reason = '', string $by = ''): bool {
        nm_maint_ensure($conn);
        if ($until === null || trim($until) === '') { $u = NM_MAINT_FOREVER; }
        else { $ts = strtotime($until); if ($ts === false) return false; $u = date('Y-m-d H:i:s', $ts); }
        try {
            $rz = function_exists('mb_substr') ? mb_substr($reason, 0, 255) : substr($reason, 0, 255);
            $st = $conn->prepare("UPDATE nm_nodes SET maintenance_until=?, maintenance_since=COALESCE(maintenance_since,NOW()),
                                  maintenance_reason=?, maintenance_by=? WHERE id=?");
            $st->bind_param('sssi', $u, $rz, $by, $id); $st->execute(); $st->close();
        } catch (\Throwable $e) { return false; }
        if (function_exists('nm_audit')) { try { nm_audit($conn, 'node.maintenance.on',
            ['target_type'=>'node','target_id'=>$id,'details'=>['until'=>$u,'reason'=>$reason]]); } catch (\Throwable $e) {} }
        return true;
    }
    function nm_maint_clear($conn, int $id, string $by = ''): bool {
        nm_maint_ensure($conn);
        try {
            $conn->query("UPDATE nm_nodes SET maintenance_until=NULL, maintenance_since=NULL,
                          maintenance_reason=NULL, maintenance_by=NULL WHERE id=" . (int)$id);
        } catch (\Throwable $e) { return false; }
        if (function_exists('nm_audit')) { try { nm_audit($conn, 'node.maintenance.off',
            ['target_type'=>'node','target_id'=>$id]); } catch (\Throwable $e) {} }
        return true;
    }

    // Full maintenance state for a node (for the UI).
    function nm_maint_row($conn, int $id): array {
        nm_maint_ensure($conn);
        $out = ['active'=>false, 'indefinite'=>false, 'until'=>null, 'since'=>null, 'by'=>null, 'reason'=>null];
        try {
            $st = $conn->prepare("SELECT maintenance_until, maintenance_since, maintenance_by, maintenance_reason FROM nm_nodes WHERE id=? LIMIT 1");
            $st->bind_param('i', $id); $st->execute();
            $x = $st->get_result()->fetch_assoc(); $st->close();
            if ($x && $x['maintenance_until'] !== null && strtotime($x['maintenance_until']) > time()) {
                $out['active']     = true;
                $out['until']      = $x['maintenance_until'];
                $out['since']      = $x['maintenance_since'];
                $out['by']         = $x['maintenance_by'];
                $out['reason']     = $x['maintenance_reason'];
                $out['indefinite'] = (substr((string)$x['maintenance_until'], 0, 4) >= '2999');
            }
        } catch (\Throwable $e) {}
        return $out;
    }
}
