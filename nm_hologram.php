<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Traffic Hologram engine (Volumetric Digital Twin, F1).
// A THIN assembler — no tables of its own. The 3D scene reuses the authoritative
// topology + live rates from net_mon_map.php (?api=topo); this engine only ADDS the
// per-node NetFlow "top application" + a stable color, so particle streams can be
// colored by what's actually flowing. Read-only. Everything else lives in the browser.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_holo_ensure')) {

    function nm_holo_ensure($conn): void {
        // RBAC seed only (no data tables — the scene is derived live).
        $conn->query("INSERT IGNORE INTO role_profiles (role_name, button_key, enabled) VALUES ('admin','hologram',1)");
    }

    function nm_holo_settings($conn): array {
        $get = function($k, $d) use ($conn) {
            $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='" . $conn->real_escape_string($k) . "' LIMIT 1");
            if ($r && $r->num_rows) { $v = $r->fetch_assoc()['setting_val']; if ($v !== '' && $v !== null) return $v; }
            return $d;
        };
        return [
            'poll_sec'     => max(2, (int)$get('holo_poll_sec', '5')),
            'particle_cap' => max(2000, (int)$get('holo_particle_cap', '48000')),
            'window_min'   => max(1, (int)$get('holo_window_min', '5')),  // NetFlow lookback for app color
        ];
    }

    // Deterministic, pleasant color per application name (stable across polls/sessions).
    function nm_holo_app_color(string $app): string {
        $app = trim($app);
        if ($app === '' || strtolower($app) === 'other') return '#7f8fa6';   // neutral grey
        $h = crc32(strtolower($app)) % 360;                 // hue 0..359
        // high S/L for a luminous, distinguishable neon palette that pops under additive blending
        return nm_holo_hsl_to_hex($h, 92, 64);
    }
    function nm_holo_hsl_to_hex(int $h, int $s, int $l): string {
        $s /= 100; $l /= 100;
        $c = (1 - abs(2 * $l - 1)) * $s;
        $x = $c * (1 - abs(fmod($h / 60, 2) - 1));
        $m = $l - $c / 2;
        [$r, $g, $b] = $h < 60 ? [$c,$x,0] : ($h < 120 ? [$x,$c,0] : ($h < 180 ? [0,$c,$x] :
                       ($h < 240 ? [0,$x,$c] : ($h < 300 ? [$x,0,$c] : [$c,0,$x]))));
        return sprintf('#%02x%02x%02x', (int)round(($r+$m)*255), (int)round(($g+$m)*255), (int)round(($b+$m)*255));
    }

    // Per-node dominant NetFlow application (last $mins) → {app,color,bps}. Best-effort: if NetFlow
    // isn't collecting, nodes simply get no app color and the client falls back to a volume tint.
    function nm_holo_enrich($conn, int $mins = 5): array {
        nm_holo_ensure($conn);
        $out = ['ok' => true, 'nodes' => [], 'apps' => [], 'ts' => date('Y-m-d H:i:s')];
        // NetFlow present?
        $has = $conn->query("SHOW TABLES LIKE 'nm_netflow_flows'");
        if (!$has || !$has->num_rows) return $out;
        if (!function_exists('nm_nf_app_name') && is_file(__DIR__ . '/nm_netflow.php')) {
            // pull in the friendly app-name mapper without running its page
            require_once __DIR__ . '/nm_netflow.php';
        }
        $mins = max(1, min(120, $mins));

        // node id ↔ ip
        $nodes = [];
        $nr = $conn->query("SELECT id, ip_address FROM nm_nodes WHERE ip_address IS NOT NULL AND ip_address<>''");
        while ($nr && $x = $nr->fetch_assoc()) $nodes[(int)$x['id']] = $x['ip_address'];
        if (!$nodes) return $out;

        $st = $conn->prepare("SELECT app_port, protocol, SUM(bytes) b
                              FROM nm_netflow_flows
                              WHERE bucket >= (NOW() - INTERVAL {$mins} MINUTE) AND (src_ip=? OR dst_ip=?)
                              GROUP BY app_port, protocol ORDER BY b DESC LIMIT 1");
        if (!$st) return $out;
        foreach ($nodes as $id => $ip) {
            $st->bind_param('ss', $ip, $ip);
            if (!$st->execute()) continue;
            $res = $st->get_result();
            if ($res && ($row = $res->fetch_assoc())) {
                $app = function_exists('nm_nf_app_name')
                     ? nm_nf_app_name((int)$row['app_port'], (int)$row['protocol'])
                     : (($row['app_port'] ? 'port ' . (int)$row['app_port'] : 'proto ' . (int)$row['protocol']));
                $bps = (float)$row['b'] * 8 / ($mins * 60);   // avg bits/sec over the window
                $color = nm_holo_app_color($app);
                $out['nodes'][$id] = ['app' => $app, 'color' => $color, 'bps' => $bps];
                $out['apps'][$app] = $color;
            }
        }
        $st->close();
        arsort($out['apps']);   // stable legend order isn't critical; keep as-is
        return $out;
    }

    // ── Full per-node dossier: every angle that could be affecting the node, incl. what the AI
    //    (NetAIObot + AI Insights) has said/done. Read-only; reuses existing tables. ───────────
    function nm_holo_node_detail($conn, int $id): array {
        nm_holo_ensure($conn);
        $out = ['ok' => false];
        if ($id <= 0) return $out + ['error' => 'bad node id'];
        $n = $conn->query("SELECT id, display_name, ip_address, os_icon, monitor_type,
                                  COALESCE(subnet_mask,'/24') subnet FROM nm_nodes WHERE id=$id LIMIT 1");
        $n = $n ? $n->fetch_assoc() : null;
        if (!$n) return $out + ['error' => 'node not found'];
        $ip = (string)$n['ip_address'];

        // authoritative status
        $status = 'unknown';
        $as = $conn->query("SELECT last_status FROM nm_alert_state WHERE entity_type='node' AND entity_id=$id LIMIT 1");
        if ($as && $as->num_rows) $status = (string)$as->fetch_assoc()['last_status'];

        // latest cpu / memory / uptime (metric_key-agnostic, like the map)
        $cpu = $mem = $uptime = null; $lastPoll = null;
        $sr = $conn->query("SELECT s.metric_type, s.metric_key, s.value, s.recorded_at
            FROM nm_device_stats s INNER JOIN (
                SELECT metric_type, MAX(recorded_at) mx FROM nm_device_stats
                WHERE node_id=$id AND metric_type IN ('cpu','memory','uptime') GROUP BY metric_type
            ) lx ON s.metric_type=lx.metric_type AND s.recorded_at=lx.mx WHERE s.node_id=$id");
        while ($sr && $r = $sr->fetch_assoc()) {
            if ($r['metric_type']==='cpu' && ($cpu===null || $r['metric_key']==='avg')) $cpu=(float)$r['value'];
            elseif ($r['metric_type']==='memory') $mem = max((float)$r['value'], $mem ?? 0);
            elseif ($r['metric_type']==='uptime') $uptime=(float)$r['value'];
            if ($r['recorded_at'] && (!$lastPoll || $r['recorded_at']>$lastPoll)) $lastPoll=$r['recorded_at'];
        }

        // 24h availability + latest latency (ping)
        $avail = null; $lat = null;
        $av = $conn->query("SELECT AVG(is_up)*100 pct FROM nm_ping_stats WHERE node_id=$id AND recorded_at >= (NOW()-INTERVAL 24 HOUR)");
        if ($av && $av->num_rows) { $x=$av->fetch_assoc(); $avail = $x['pct']!==null?round((float)$x['pct'],2):null; }
        $lt = $conn->query("SELECT latency_ms FROM nm_ping_stats WHERE node_id=$id ORDER BY id DESC LIMIT 1");
        if ($lt && $lt->num_rows) $lat = $lt->fetch_assoc()['latency_ms'];

        // NetAIObot — sessions + recent actions (what the AI observed / proposed / auto-corrected)
        $ai = ['sessions'=>0, 'last'=>null, 'actions'=>[]];
        $sc = $conn->query("SELECT COUNT(*) c FROM nm_aip_sessions WHERE node_id=$id");
        if ($sc) $ai['sessions'] = (int)$sc->fetch_assoc()['c'];
        $ls = $conn->query("SELECT status,title,summary,created_at FROM nm_aip_sessions WHERE node_id=$id ORDER BY id DESC LIMIT 1");
        if ($ls && $ls->num_rows) $ai['last'] = $ls->fetch_assoc();
        $ac = $conn->query("SELECT a.tool,a.status,a.risk,a.reason,LEFT(a.result,360) result,a.proposed_at,a.executed_at,s.trigger_kind
                            FROM nm_aip_actions a JOIN nm_aip_sessions s ON s.id=a.session_id
                            WHERE a.node_id=$id ORDER BY a.id DESC LIMIT 8");
        while ($ac && $r=$ac->fetch_assoc()) $ai['actions'][] = $r;

        // AI Insights for this node
        $insights = [];
        $ir = $conn->query("SELECT id,severity,status,title,kind,source,created_at FROM nm_ai_insights
                            WHERE node_id=$id ORDER BY (status IN('open','acknowledged')) DESC, created_at DESC LIMIT 10");
        while ($ir && $r=$ir->fetch_assoc()) $insights[] = $r;

        // Incidents currently affecting the node (root OR a correlated signal)
        $incidents = [];
        $inr = $conn->query("SELECT DISTINCT i.id,i.title,i.severity,i.status,i.opened_at,i.root_source
                             FROM nm_incidents i LEFT JOIN nm_incident_signals sg ON sg.incident_id=i.id AND sg.node_id=$id
                             WHERE i.status IN ('open','acknowledged') AND (i.root_node_id=$id OR sg.node_id=$id)
                             ORDER BY FIELD(i.severity,'critical','warning','info'), i.opened_at DESC LIMIT 10");
        while ($inr && $r=$inr->fetch_assoc()) $incidents[] = $r;

        // Predictive Health forecasts
        $health = [];
        $hr = $conn->query("SELECT metric,kind,severity,eta_days,direction,detail FROM nm_health_predictions
                            WHERE node_id=$id AND status='active' ORDER BY (eta_days IS NULL), eta_days ASC LIMIT 8");
        while ($hr && $r=$hr->fetch_assoc()) $health[] = $r;

        // Top interfaces by current traffic
        $ifaces = [];
        $ifr = $conn->query("SELECT COALESCE(i.display_name,i.if_name) name, ps.in_rate, ps.out_rate, ps.oper_status
                             FROM nm_interfaces i JOIN nm_port_stats ps ON ps.port_id=i.id AND ps.node_id=i.node_id
                             INNER JOIN (SELECT port_id,MAX(recorded_at) m FROM nm_port_stats WHERE node_id=$id GROUP BY port_id) lx
                               ON lx.port_id=ps.port_id AND ps.recorded_at=lx.m
                             WHERE i.node_id=$id ORDER BY (ps.in_rate+ps.out_rate) DESC LIMIT 6");
        while ($ifr && $r=$ifr->fetch_assoc()) $ifaces[] = $r;

        // Recent logs (native syslog, matched by host ip)
        $logs = [];
        if ($ip !== '') {
            $lg = $conn->prepare("SELECT received_at, severity, tag, message FROM nm_syslog WHERE host_ip=? ORDER BY id DESC LIMIT 15");
            if ($lg) { $lg->bind_param('s', $ip); $lg->execute(); $res=$lg->get_result();
                while ($res && $r=$res->fetch_assoc()) $logs[]=$r; $lg->close(); }
        }

        return [
            'ok' => true,
            'node' => [
                'id'=>(int)$n['id'], 'name'=>$n['display_name'], 'ip'=>$ip, 'os'=>$n['os_icon'],
                'monitor_type'=>$n['monitor_type'], 'subnet'=>$n['subnet'], 'status'=>$status,
                'cpu'=>$cpu, 'memory'=>$mem, 'uptime_sec'=>$uptime, 'last_poll'=>$lastPoll,
                'avail_24h'=>$avail, 'latency_ms'=>$lat,
            ],
            'ai'=>$ai, 'insights'=>$insights, 'incidents'=>$incidents,
            'health'=>$health, 'interfaces'=>$ifaces, 'logs'=>$logs,
            'ts'=>date('Y-m-d H:i:s'),
        ];
    }
}
