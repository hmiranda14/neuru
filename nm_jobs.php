<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Scheduled Jobs registry + throttle gate (the ONE place all cron cadences live).
//
// Every background job (cron_*.php + the Python pollers) is fired by the OS crontab at a FIXED tick,
// but the REAL cadence + on/off is controlled here from the DB — so the "Scheduled Jobs" tab in
// net_mon_config.php can retune or disable ANY job without touching the crontab (www-data can't).
//
//   • nm_job_registry()          — canonical metadata for all jobs (label, category, cost, default cadence).
//   • nm_job_should_run($conn,$j) — the GATE: returns true if $j may run now (respects enabled + interval),
//                                    and stamps last_run when it says yes. Called from nm_cron.sh (PHP crons)
//                                    and the Python pollers via nm_job_gate.php.
//   • nm_job_list / nm_job_save   — read/write for the UI.
//
// interval_min = 0 means "no extra throttle — run on every crontab tick" (the transparent default, so
// installing this changes NOTHING until the operator sets a slower interval or disables a job).
// ─────────────────────────────────────────────────────────────────────────────

if (!function_exists('nm_job_ensure')) {

    function nm_job_ensure($conn): void {
        static $done = false; if ($done) return; $done = true;
        try {
            $conn->query("CREATE TABLE IF NOT EXISTS nm_job_schedule (
                job VARCHAR(64) NOT NULL PRIMARY KEY,
                enabled TINYINT(1) NOT NULL DEFAULT 1,
                interval_min INT NOT NULL DEFAULT 0,     -- 0 = use the crontab tick (no extra throttle)
                last_run DATETIME NULL,
                last_result VARCHAR(20) NULL,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        } catch (\Throwable $e) {}
    }

    // Canonical list of every scheduled job. cat: core|monitor|healing|ai|maint|notify.
    // ai=1 → this job invokes a billed n8n flow (money). tick = human cadence from the shipped crontab.
    function nm_job_registry(): array {
        return [
            // ── Core monitoring (Python pollers + fast PHP) — throttling here slows DETECTION, warn ──
            'nm_ping'          => ['ICMP ping sweep', 'core', 0, 'every 1 min', 'Pings every node; drives up/down detection.'],
            'nm_poller'        => ['SNMP poller', 'core', 0, 'every 2 min', 'Polls SNMP counters/health for every monitored node.'],
            'nm_health'        => ['Host health probe', 'core', 0, 'every 5 min', 'Server/agent CPU/mem/disk health sampling.'],
            'cron_netstats'    => ['Interface stats roll-up', 'core', 0, 'every 1 min', 'Aggregates per-interface traffic samples.'],
            'cron_incidents'   => ['Incident correlation', 'core', 0, 'every 1 min', 'Correlates signals into incidents (the alert engine).'],
            'cron_netflow'     => ['NetFlow bandwidth eval', 'core', 0, 'every 1 min', 'Evaluates per-app bandwidth vs thresholds; opens/clears NetFlow alerts.'],
            // ── Device / infra monitoring ──
            'cron_gpu'         => ['GPU / AI monitor', 'monitor', 0, 'every 2 min', 'Agentless GPU telemetry over SSH.'],
            'cron_winhost'     => ['Windows monitor', 'monitor', 0, 'every 5 min', 'Windows-over-SSH (PowerShell) suite.'],
            'cron_linuxhost'   => ['Linux monitor', 'monitor', 0, 'every 5 min', 'Linux-over-SSH suite.'],
            'cron_cisco'       => ['Cisco fleet', 'monitor', 0, 'every 5 min', 'Cisco monitoring/orchestration poll.'],
            'cron_tplink'      => ['TP-Link switches', 'monitor', 0, 'every 2 min', 'Unmanaged/Easy-Smart switch web-scrape.'],
            'cron_wireguard'   => ['WireGuard peers', 'monitor', 0, 'every 2 min', 'WireGuard tunnel/peer status.'],
            'cron_dbmon'       => ['Data Core (DBs)', 'monitor', 0, 'every 1 min', 'Per-target DB probe + live counters.'],
            'cron_netdoc'      => ['Network doc / topology', 'monitor', 0, 'every 10 min', 'Auto-documentation + topology refresh.'],
            'cron_cluster'     => ['Federation cluster', 'monitor', 0, 'every 1 min', 'Master/slave federation sync.'],
            'cron_deck'        => ['Stream Deck state', 'monitor', 0, 'every 1 min', 'Pushes state to a connected Stream Deck.'],
            'cron_health'      => ['Predictive health', 'monitor', 0, 'hourly :15', 'Degradation forecasting (SFP/ethernet trends).'],
            // ── Healing / security ──
            'cron_heal'        => ['Self-Healing orchestrator', 'healing', 0, 'every 2 min', 'Runs healing playbooks (detect/propose/act).'],
            'cron_immunity'    => ['Collective Immunity', 'healing', 0, 'every 3 min', 'Fans out threat blocks to Pi-holes/firewalls.'],
            'cron_shadowit'    => ['Shadow IT scan', 'healing', 0, 'every 10 min', 'Detects unknown/unsanctioned devices.'],
            'cron_wear'        => ['Hardware wear', 'healing', 0, 'daily 04:30', 'Cumulative wear/lifespan (SMART/LHM).'],
            'cron_wearlife'    => ['Wear lifespan roll-up', 'healing', 0, 'every 10 min', 'Lifespan/passport aggregation.'],
            // ── AI / flow-cost (these invoke billed n8n flows) 💰 ──
            'cron_biosphere'   => ['Service Biosphere', 'ai', 1, 'every 1 min', 'Probes services; DNS-audit dispatch to bio-dns-audit (AI) is throttled by bio_dns_min in Biosphere settings.'],
            'cron_anomaly'     => ['AI Insights (anomaly)', 'ai', 1, 'every 10 min', 'Fires anomaly-detect (every run) + anomaly-learn (throttled 6h).'],
            'cron_decoy'       => ['Deception Grid', 'ai', 1, 'every 1 min', 'TTL sweep + deception-analyst (AI) on active diversions.'],
            'cron_aiopilot'    => ['AI Commander v1 (deprecated)', 'ai', 1, 'every 2 min', 'Legacy autonomous loop - superseded by NEURU Commander (v2). OFF by default.', 1],
            'cron_autopilotv2' => ['NEURU Commander (v2)', 'ai', 1, 'every 1 min', 'Autonomous NOC brain scan/dispatch (autopilot-v2).'],
            'cron_archaeology' => ['AI Archaeologist', 'ai', 1, 'weekly Mon 05:30', 'Long-horizon archaeology-analyze pass.'],
            'cron_container_logs' => ['Container log collector', 'ai', 1, 'every 5 min', 'Pulls container logs; error analysis via container-analyze/log-rca (AI).'],
            'cron_flows'       => ['Flow scheduler', 'ai', 1, 'every 5 min', 'Fires owner-scheduled flows on their cadence (Portal Control Center).'],
            'cron_notify'      => ['Notifications pipeline', 'ai', 1, 'every 5 min', 'Processes notifications; may call neuru-notify.'],
            'cron_smokeping'   => ['Smokeping manager', 'ai', 1, 'every 5 min', 'Manages Smokeping targets (smokeping-manage).'],
            'cron_weather'     => ['Weather routing', 'ai', 1, 'every 15 min', 'Weather-poll for node locations.'],
            'cron_config'      => ['Config backup (NCM)', 'ai', 1, 'daily 02:30', 'Router config fetch/versioning (config-backup).'],
            // ── Maintenance / housekeeping ──
            'cron_vault'       => ['Data Vault backups', 'maint', 0, 'hourly', 'DB retention + backup vault (mysqldump → S3/WebDAV/Portal).'],
            'cron_reports'     => ['SLA & reports', 'maint', 0, 'hourly', 'Rolls up SLA + scheduled reports.'],
            'cron_update'      => ['Self-Update check', 'maint', 0, 'daily 04:23', 'Checks the Portal for a new release (per policy).'],
            'cron_license'     => ['License heartbeat', 'maint', 0, 'every 6h :17', 'Re-validates the license with the Portal.'],
            'cron_aip_telegram'=> ['Telegram approvals', 'notify', 0, 'every 1 min', 'Delivers/collects AI Commander Telegram approvals.'],
        ];
    }

    // Which billed n8n flow(s) each AI-cost cron actually fires — so the panel maps to the billing ledger.
    function nm_job_flows(): array {
        return [
            'cron_biosphere'=>'bio-dns-audit', 'cron_anomaly'=>'anomaly-detect, anomaly-learn',
            'cron_decoy'=>'deception-analyst', 'cron_aiopilot'=>'aiopilot', 'cron_autopilotv2'=>'autopilot-v2',
            'cron_archaeology'=>'archaeology-analyze', 'cron_container_logs'=>'container-analyze, log-rca',
            'cron_flows'=>'(owner-scheduled flows)', 'cron_notify'=>'neuru-notify', 'cron_smokeping'=>'smokeping-manage',
            'cron_weather'=>'weather-poll', 'cron_config'=>'config-backup',
        ];
    }

    // THE GATE. Returns true if $job may run right now (and stamps last_run when it does).
    // Unknown jobs (not in the registry) are allowed through (fail-open) so nothing is ever silently killed.
    function nm_job_should_run($conn, string $job): bool {
        $job = preg_replace('/\.php$/', '', trim($job));
        if ($job === '') return true;
        nm_job_ensure($conn);
        $reg = nm_job_registry();
        if (!isset($reg[$job])) return true;                     // not managed here → run as the crontab intends
        try {
            $j = $conn->real_escape_string($job);
            $r = $conn->query("SELECT enabled, interval_min, last_run FROM nm_job_schedule WHERE job='$j' LIMIT 1");
            if (!$r || !$r->num_rows) {                           // first sight → seed default (deprecated jobs seed OFF)
                $defEn = empty($reg[$job][5]) ? 1 : 0;
                $conn->query("INSERT IGNORE INTO nm_job_schedule (job,enabled,interval_min) VALUES ('$j',$defEn,0)");
                if ($defEn === 1) { $conn->query("UPDATE nm_job_schedule SET last_run=NOW(), last_result='run' WHERE job='$j'"); return true; }
                $conn->query("UPDATE nm_job_schedule SET last_result='disabled' WHERE job='$j'"); return false;
            }
            $row = $r->fetch_assoc();
            if ((int)$row['enabled'] !== 1) {                     // disabled from the UI
                $conn->query("UPDATE nm_job_schedule SET last_result='disabled' WHERE job='$j'");
                return false;
            }
            $iv = max(0, (int)$row['interval_min']);
            if ($iv > 0 && $row['last_run']) {
                $due = $conn->query("SELECT 1 FROM nm_job_schedule WHERE job='$j' AND last_run > (NOW() - INTERVAL $iv MINUTE) LIMIT 1");
                if ($due && $due->num_rows) { return false; }     // throttled — not due yet
            }
            $conn->query("UPDATE nm_job_schedule SET last_run=NOW(), last_result='run' WHERE job='$j'");
            return true;
        } catch (\Throwable $e) { return true; }                 // never let the gate itself kill a job
    }

    // For the UI: every job with its config + registry metadata.
    function nm_job_list($conn): array {
        nm_job_ensure($conn);
        $cfg = [];
        try { $r = $conn->query("SELECT job,enabled,interval_min,last_run,last_result FROM nm_job_schedule");
              while ($r && $x = $r->fetch_assoc()) $cfg[$x['job']] = $x; } catch (\Throwable $e) {}
        $out = [];
        foreach (nm_job_registry() as $job => $m) {
            $c = $cfg[$job] ?? ['enabled'=>1,'interval_min'=>0,'last_run'=>null,'last_result'=>null];
            $out[] = ['job'=>$job, 'label'=>$m[0], 'cat'=>$m[1], 'ai'=>(int)$m[2], 'tick'=>$m[3], 'desc'=>$m[4], 'dep'=>(int)($m[5] ?? 0), 'flows'=>(nm_job_flows()[$job] ?? ''), 'kind'=>(preg_match('/^every [0-9]+ min$/', $m[3]) ? 'interval' : 'fixed'),
                      'enabled'=>(int)$c['enabled'], 'interval_min'=>(int)$c['interval_min'],
                      'last_run'=>$c['last_run'], 'last_result'=>$c['last_result']];
        }
        return $out;
    }

    function nm_job_save($conn, string $job, int $enabled, int $intervalMin): bool {
        $job = preg_replace('/\.php$/', '', trim($job));
        if (!isset(nm_job_registry()[$job])) return false;
        nm_job_ensure($conn);
        $intervalMin = max(0, min(10080, $intervalMin));         // cap 0..7d
        try {
            $st = $conn->prepare("INSERT INTO nm_job_schedule (job,enabled,interval_min) VALUES (?,?,?)
                                  ON DUPLICATE KEY UPDATE enabled=VALUES(enabled), interval_min=VALUES(interval_min)");
            $en = $enabled ? 1 : 0; $st->bind_param('sii', $job, $en, $intervalMin); $st->execute(); $st->close();
            return true;
        } catch (\Throwable $e) { return false; }
    }
}
