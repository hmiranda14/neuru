<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Idempotent schema/feature UPDATER.
//
// Brings ANY existing NEURU database up to the CURRENT release by running every
// engine's self-ensure (each does CREATE TABLE IF NOT EXISTS + guarded ALTERs +
// default RBAC/config seeds), then adds the explicit performance indexes. It is
// SAFE to re-run any number of times and NEVER touches operational data — only
// schema + built-in default seeds.
//
// Run it after deploying new code, either way:
//   • Browser (recommended — runs as www-data so secret-dependent seeds work):
//       https://<host>/install/apply_updates.php        (must be logged in as admin)
//   • CLI:  php install/apply_updates.php
//
// setup.php also calls nm_apply_updates() on a fresh install so the schema is
// always complete even if neuru-install.sql lags behind the code.
// ─────────────────────────────────────────────────────────────────────────────

// file => one-or-more ensure functions. Order: RBAC/base first, then the rest.
function nm_apply_updates_map(): array {
    return [
        'nm_access.php'      => ['nm_access_ensure'],
        'nm_incidents.php'   => ['nm_inc_ensure'],
        'nm_notify.php'      => ['nm_notify_ensure'],
        'nm_confmgr.php'     => ['nm_cm_ensure'],
        'nm_nettools.php'    => ['nm_nt_ensure'],
        'nm_nodemeta.php'    => ['nm_node_meta_ensure'],
        'nm_profile.php'     => ['nm_user_meta_ensure'],
        'nm_widgets.php'     => ['nm_widgets_ensure'],
        'nm_ctr_templates.php'=> ['nm_ctr_ensure'],
        'nm_netstats.php'    => ['nm_netstats_ensure', 'nm_netalert_ensure'],
        'nm_netflow.php'     => ['nm_nf_ensure'],
        'nm_pihole.php'      => ['nm_ph_ensure'],
        'nm_smokeping.php'   => ['nm_sp_ensure', 'nm_sp_alert_ensure'],
        'nm_health.php'      => ['nm_health_ensure'],
        'nm_gpu.php'         => ['nm_gpu_ensure'],
        'nm_winhost.php'     => ['nm_win_ensure'],
        'nm_linuxhost.php'   => ['nm_lx_ensure'],
        'nm_dbmon.php'       => ['nm_db_ensure'],
        'nm_dbobs.php'       => ['nm_dbobs_ensure'],
        'nm_immunity.php'    => ['nm_imm_ensure'],
        'nm_decoy.php'       => ['nm_decoy_ensure'],
        'nm_chaos.php'       => ['nm_chaos_ensure'],
        'nm_heal.php'        => ['nm_heal_ensure'],
        'nm_hologram.php'    => ['nm_holo_ensure'],
        'nm_biosphere.php'   => ['nm_bio_ensure'],
        'nm_shadowit.php'    => ['nm_si_ensure'],
        'nm_weather.php'     => ['nm_wx_ensure'],
        'nm_geomap.php'      => ['nm_geomap_ensure'],
        'nm_command.php'     => ['nm_cmd_ensure'],
        'nm_timetravel.php'  => ['nm_tt_ensure_perm'],
        'nm_archaeology.php' => ['nm_arch_ensure'],
        'nm_aiopilot.php'    => ['nm_aip_ensure'],
        'nm_rcflow.php'      => ['nm_rc_ensure'],
        'nm_tplink.php'      => ['nm_tp_ensure'],
        'nm_wear.php'        => ['nm_wear_ensure'],
        'nm_ipam.php'        => ['nm_ipam_ensure'],
        'nm_wireguard.php'   => ['nm_wg_ensure'],
        'nm_routing.php'     => ['nm_routing_ensure'],
        'nm_mtfw.php'        => ['nm_mtfw_ensure'],
        'nm_cluster.php'     => ['nm_cluster_ensure'],
    ];
}

// Explicit performance indexes (guarded — CREATE fails harmlessly if present).
// These are the ones that turned 30s renders into 0.4s (net_mon / net_mon_stats).
function nm_apply_updates_indexes(): array {
    return [
        ['nm_device_stats', 'idx_node_recorded',      '(node_id, recorded_at)'],
        ['nm_device_stats', 'idx_node_type_key_time', '(node_id, metric_type, metric_key, recorded_at)'],
        // net_mon_map / command-center topology: "latest port stat per (node,port)" GROUP BY + MAX(recorded_at)
        // was a full scan (73s cumulative, flagged NO-INDEX by Data Core) → 108x faster with this composite.
        ['nm_port_stats',   'idx_node_port_time',     '(node_id, port_id, recorded_at)'],
        // "latest ping per node" (MAX(id) join) — node-scoped, monotonic id.
        ['nm_ping_stats',   'idx_node_id',            '(node_id, id)'],
    ];
}

// Core worker — reusable from setup.php. Returns a structured report.
function nm_apply_updates(mysqli $conn): array {
    $app = dirname(__DIR__);
    $count = function() use ($conn) {
        try { $r = $conn->query("SELECT COUNT(*) c FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()"); return (int)($r ? $r->fetch_assoc()['c'] : 0); }
        catch (\Throwable $e) { return 0; }
    };
    $before = $count();
    $log = []; $ok = 0; $fail = 0;

    foreach (nm_apply_updates_map() as $file => $fns) {
        $path = $app . '/' . $file;
        if (!is_file($path)) { $log[] = ['lvl'=>'skip', 'msg'=>"$file — not deployed"]; continue; }
        try { require_once $path; } catch (\Throwable $e) { $log[] = ['lvl'=>'fail', 'msg'=>"$file require: " . $e->getMessage()]; $fail++; continue; }
        foreach ($fns as $fn) {
            if (!function_exists($fn)) { $log[] = ['lvl'=>'skip', 'msg'=>"$fn() — missing"]; continue; }
            try { $fn($conn); $log[] = ['lvl'=>'ok', 'msg'=>"$fn()"]; $ok++; }
            catch (\Throwable $e) { $log[] = ['lvl'=>'fail', 'msg'=>"$fn(): " . $e->getMessage()]; $fail++; }
        }
    }

    // Grant the built-in 'admin' role EVERY catalog permission (idempotent). Some feature ensures
    // seed their own perm, others don't — so after adding new modules the admin could be missing
    // the perms → the new menu items stay hidden. This guarantees admin sees every module.
    if (function_exists('nm_perm_catalog')) {
        $cat = nm_perm_catalog(); $seeded = 0;
        foreach ($cat as $p) {
            $key = is_array($p) ? ($p[0] ?? null) : null; if (!$key) continue;
            $k = $conn->real_escape_string($key);
            try {
                $conn->query("INSERT INTO role_profiles (role_name,button_key,enabled)
                    SELECT 'admin','$k',1 FROM DUAL
                    WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='$k')");
                if ($conn->affected_rows > 0) $seeded++;
            } catch (\Throwable $e) {}
        }
        $log[] = ['lvl'=>$seeded?'ok':'have', 'msg'=>"admin perms — $seeded newly granted (".count($cat)." in catalog)"];
        if ($seeded) $ok++;
    }

    foreach (nm_apply_updates_indexes() as $ix) {
        [$tbl, $name, $cols] = $ix;
        // only try if the table exists
        try {
            $chk = $conn->query("SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='".$conn->real_escape_string($tbl)."' LIMIT 1");
            if (!$chk || !$chk->num_rows) { $log[] = ['lvl'=>'skip', 'msg'=>"index $name — $tbl absent"]; continue; }
            $has = $conn->query("SELECT 1 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='".$conn->real_escape_string($tbl)."' AND INDEX_NAME='".$conn->real_escape_string($name)."' LIMIT 1");
            if ($has && $has->num_rows) { $log[] = ['lvl'=>'have', 'msg'=>"index $name (already present)"]; continue; }
            $conn->query("CREATE INDEX $name ON $tbl $cols");
            $log[] = ['lvl'=>'ok', 'msg'=>"index $name on $tbl $cols"]; $ok++;
        } catch (\Throwable $e) { $log[] = ['lvl'=>'have', 'msg'=>"index $name ({$e->getMessage()})"]; }
    }

    $after = $count();
    return ['ok'=>$ok, 'fail'=>$fail, 'tables_before'=>$before, 'tables_after'=>$after, 'log'=>$log];
}

// ── Standalone execution (CLI or direct browser hit) ─────────────────────────
$__self = basename((string)($_SERVER['SCRIPT_FILENAME'] ?? ($_SERVER['PHP_SELF'] ?? '')));
if (PHP_SAPI === 'cli' || $__self === 'apply_updates.php') {
    $CLI = (PHP_SAPI === 'cli');
    require dirname(__DIR__) . '/connection.php';   // $conn (mysqli, EXCEPTION mode)

    if (!$CLI) {
        // Browser: admin-only. Reuse the portal session/RBAC.
        require_once dirname(__DIR__) . '/access_control.php';
        if (session_status() === PHP_SESSION_NONE) @session_start();
        $isAdmin = (($_SESSION['role'] ?? '') === 'admin') || checkAccess($conn, 'user_admin');
        if (empty($_SESSION['username']) || !$isAdmin) {
            http_response_code(403);
            echo '<body style="background:#05080f;color:#e6e9ee;font-family:Segoe UI,sans-serif;padding:40px">'
               . '<h2>⛔ Admin login required</h2><p>Log in as an administrator, then reload this page.</p>'
               . '<p><a style="color:#4da3ff" href="/login.php">Go to login →</a></p></body>';
            exit;
        }
    }

    $t0 = microtime(true);
    $rep = nm_apply_updates($conn);
    $secs = round(microtime(true) - $t0, 2);

    if ($CLI) {
        foreach ($rep['log'] as $l) {
            $mark = ['ok'=>'✓','fail'=>'✗','skip'=>'–','have'=>'•'][$l['lvl']] ?? '·';
            echo "  $mark {$l['msg']}\n";
        }
        echo "\nTables {$rep['tables_before']} → {$rep['tables_after']} · {$rep['ok']} applied · {$rep['fail']} failed · {$secs}s\n";
        exit($rep['fail'] > 0 ? 1 : 0);
    }

    // Browser report
    $newTables = $rep['tables_after'] - $rep['tables_before'];
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><meta charset="utf-8"><title>NEURU · Apply updates</title>';
    echo '<body style="margin:0;background:radial-gradient(1000px 600px at 50% -10%,rgba(40,70,140,.3),transparent 70%),#05060f;color:#dfe6f0;font-family:Segoe UI,Tahoma,sans-serif;padding:34px 20px">';
    echo '<div style="max-width:820px;margin:0 auto;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.12);border-radius:16px;padding:26px 30px;backdrop-filter:blur(14px)">';
    echo '<h1 style="margin:0 0 4px;font-size:22px">🛰 NEURU — Apply updates</h1>';
    echo '<p style="color:#8a96a8;margin:0 0 18px;font-size:13px">Idempotent schema + feature sync. Safe to re-run.</p>';
    echo '<div style="display:flex;gap:22px;margin-bottom:18px;flex-wrap:wrap">'
       . '<div><div style="font-size:26px;font-weight:800;color:#7fe0a3">'.$rep['ok'].'</div><div style="font-size:11px;color:#8a96a8;text-transform:uppercase">ensures applied</div></div>'
       . '<div><div style="font-size:26px;font-weight:800;color:'.($rep['fail']?'#ff9b91':'#7fe0a3').'">'.$rep['fail'].'</div><div style="font-size:11px;color:#8a96a8;text-transform:uppercase">failed</div></div>'
       . '<div><div style="font-size:26px;font-weight:800">'.$rep['tables_before'].' → '.$rep['tables_after'].'</div><div style="font-size:11px;color:#8a96a8;text-transform:uppercase">tables ('.($newTables>0?'+'.$newTables:'no new').')</div></div>'
       . '<div><div style="font-size:26px;font-weight:800">'.$secs.'s</div><div style="font-size:11px;color:#8a96a8;text-transform:uppercase">elapsed</div></div>'
       . '</div>';
    echo '<div style="font-family:Consolas,monospace;font-size:12.5px;line-height:1.7;background:rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.1);border-radius:10px;padding:12px 14px;max-height:52vh;overflow:auto">';
    foreach ($rep['log'] as $l) {
        $c = ['ok'=>'#7fe0a3','fail'=>'#ff9b91','skip'=>'#7c869a','have'=>'#8fb7e6'][$l['lvl']] ?? '#cfd6e0';
        $m = ['ok'=>'✓','fail'=>'✗','skip'=>'–','have'=>'•'][$l['lvl']] ?? '·';
        echo '<div style="color:'.$c.'">'.$m.' '.htmlspecialchars($l['msg']).'</div>';
    }
    echo '</div>';
    echo '<p style="color:#8a96a8;font-size:12.5px;margin-top:16px">'.($rep['fail']?'⚠ Some ensures failed — check the log above.':'✅ Database is up to date.').' You can safely re-run this any time.</p>';
    echo '<p style="margin-top:14px"><a style="color:#4da3ff;text-decoration:none" href="/home.php">← Back to NEURU</a></p>';
    echo '</div></body>';
    exit;
}
