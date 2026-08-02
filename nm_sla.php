<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — SLA / availability, capacity forecasting & executive reports (Pillar 4).
//
//   • Availability per node: ping nodes use nm_ping_stats(is_up); SNMP nodes use a
//     heartbeat over nm_port_stats (5-min buckets that received data = up). Yields
//     uptime %, downtime minutes, outage count, vs an SLA target.
//   • Capacity forecast: linear-fit each interface's utilization (nm_port_stats
//     in/out_util) over a week → days until it crosses a threshold (default 80%).
//   • Reports: build an HTML summary (uptime + capacity + incidents) and email it
//     on a daily/weekly schedule via nm_smtp.php. Driven by cron_reports.php.
// ─────────────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/nm_smtp.php';

if (!function_exists('nm_sla_settings')) {
    function nm_sla_settings($conn): array {
        $d = ['sla_target'=>'99.9','cap_threshold'=>'80',
              'report_enabled'=>'0','report_freq'=>'weekly','report_hour'=>'7','report_dow'=>'1',
              'report_recipients'=>'','report_period'=>'7d','report_last_sent'=>''];
        $keys = "'" . implode("','", array_keys($d)) . "'";
        if ($r = $conn->query("SELECT setting_key,setting_val FROM nm_settings WHERE setting_key IN ($keys)"))
            while ($x = $r->fetch_assoc()) $d[$x['setting_key']] = $x['setting_val'];
        return [
            'target'      => (float)$d['sla_target'],
            'cap_threshold'=> (float)$d['cap_threshold'] ?: 80,
            'enabled'     => $d['report_enabled'] === '1',
            'freq'        => in_array($d['report_freq'],['daily','weekly'],true) ? $d['report_freq'] : 'weekly',
            'hour'        => max(0, min(23, (int)$d['report_hour'])),
            'dow'         => max(0, min(7, (int)$d['report_dow'])),   // 1=Mon … 7=Sun
            'recipients'  => $d['report_recipients'],
            'period'      => in_array($d['report_period'],['24h','7d','30d'],true) ? $d['report_period'] : '7d',
            'last_sent'   => $d['report_last_sent'],
        ];
    }
    function nm_sla_mins(string $p): int { return ['24h'=>1440,'7d'=>10080,'30d'=>43200][$p] ?? 1440; }
}

// ── Availability for one node ────────────────────────────────────────────────
if (!function_exists('nm_sla_node')) {
    function nm_sla_node($conn, array $node, int $mins): array {
        $nid = (int)$node['id'];
        $out = ['uptime'=>null, 'down_min'=>0, 'outages'=>0, 'samples'=>0, 'last'=>'unknown'];

        // Canonical availability = continuously-sampled ICMP reachability (nm_ping_stats),
        // which the poller records for EVERY node ~1/min, SNMP and ping alike. (Previously
        // SNMP nodes were scored from nm_port_stats — a table only written ON DEMAND by
        // live_mon.php — so a perfectly healthy SNMP node looked mostly-down and the tiny
        // 99.9% error budget magnified that into thousands of percent of "budget burned".)
        $r = $conn->query("SELECT is_up FROM nm_ping_stats
                           WHERE node_id=$nid AND recorded_at >= (NOW() - INTERVAL $mins MINUTE) ORDER BY recorded_at");
        $rows = []; while ($r && $x = $r->fetch_assoc()) $rows[] = (int)$x['is_up'];
        $n = count($rows);
        if ($n) {
            $up = array_sum($rows);
            $out['samples'] = $n;
            $out['uptime']  = round($up / $n * 100, 3);
            $out['down_min']= $n - $up;               // ~1 sample/min
            $out['last']    = end($rows) ? 'up' : 'down';
            $streaks = 0; $inDown = false;
            foreach ($rows as $v) { if ($v === 0 && !$inDown) { $streaks++; $inDown = true; } elseif ($v === 1) $inDown = false; }
            $out['outages'] = $streaks;
            return $out;
        }

        // Fallback only for SNMP nodes with NO ICMP history at all: coarse 5-min port-data
        // buckets. Best-effort (nm_port_stats is on-demand) — used just so such nodes aren't
        // dropped entirely; ping-based scoring above is the accurate path for everything else.
        if (($node['monitor_type'] ?? 'snmp') !== 'ping') {
            $bsec = 300; $totalBuckets = max(1, (int)floor($mins * 60 / $bsec));
            $r = $conn->query("SELECT DISTINCT FLOOR(UNIX_TIMESTAMP(recorded_at)/$bsec) b
                               FROM nm_port_stats WHERE node_id=$nid AND recorded_at >= (NOW() - INTERVAL $mins MINUTE) ORDER BY b");
            $buckets = []; while ($r && $x = $r->fetch_assoc()) $buckets[(int)$x['b']] = 1;
            if (!$buckets) return $out;
            $upB = count($buckets);
            $out['samples'] = $upB;
            $out['uptime']  = round(min(100, $upB / $totalBuckets * 100), 3);
            $out['down_min']= max(0, ($totalBuckets - $upB)) * 5;
            $keys = array_keys($buckets); sort($keys);
            $now_b = (int)floor(time()/$bsec);
            $out['last'] = (end($keys) >= $now_b - 2) ? 'up' : 'down';
            $gaps = 0; for ($i = 1; $i < count($keys); $i++) if ($keys[$i] - $keys[$i-1] > 1) $gaps++;
            $out['outages'] = $gaps;
        }
        return $out;
    }

    function nm_sla_all($conn, int $mins, ?float $target = null): array {
        $S = nm_sla_settings($conn); $target = $target ?? $S['target'];
        $nodes = [];
        $r = $conn->query("SELECT id,display_name,ip_address,monitor_type,os_icon FROM nm_nodes ORDER BY display_name");
        while ($r && $n = $r->fetch_assoc()) {
            $a = nm_sla_node($conn, $n, $mins);
            if ($a['uptime'] === null) continue;   // no data → skip
            $nodes[] = $n + $a + ['target'=>$target, 'meets'=>($a['uptime'] >= $target)];
        }
        usort($nodes, fn($a,$b)=>$a['uptime'] <=> $b['uptime']);  // worst first
        return $nodes;
    }
}

// ── Error budget (SRE) + outage timeline ─────────────────────────────────────
if (!function_exists('nm_sla_error_budget')) {
    // Allowed downtime for the window at the target, how much is consumed, what's left.
    function nm_sla_error_budget(float $uptime, float $target, int $mins): array {
        $allowed  = round((100 - $target) / 100 * $mins, 1);       // budgeted downtime (min)
        $consumed = round((100 - $uptime) / 100 * $mins, 1);       // actual downtime (min)
        $remaining= round($allowed - $consumed, 1);
        $burnRaw  = $allowed > 0 ? round($consumed / $allowed * 100, 1) : ($consumed > 0 ? 100 : 0);
        // "Budget burned" is a fraction of the budget → caps at 100% (exhausted). The overage
        // (a down node can blow a 1.4-min/24h budget hundreds of times over) lives in down_min,
        // not in an absurd 6-figure percentage. burn_raw keeps the true ratio for anyone who wants it.
        $burn     = min(100.0, $burnRaw);
        return ['allowed_min'=>$allowed, 'consumed_min'=>max(0,$consumed), 'remaining_min'=>$remaining,
                'burn_pct'=>$burn, 'burn_raw'=>$burnRaw, 'exhausted'=>($remaining < 0)];
    }
    // Discrete down episodes {start,end,dur_min,ongoing} within the window (for the timeline).
    function nm_sla_outage_episodes($conn, array $node, int $mins, int $limit = 60): array {
        $nid = (int)$node['id']; $isPing = ($node['monitor_type'] ?? 'snmp') === 'ping';
        $eps = [];
        if ($isPing) {
            $r = $conn->query("SELECT is_up, UNIX_TIMESTAMP(recorded_at) ts FROM nm_ping_stats
                               WHERE node_id=$nid AND recorded_at >= (NOW() - INTERVAL $mins MINUTE) ORDER BY recorded_at");
            $start = null; $lastDown = null;
            while ($r && $x = $r->fetch_assoc()) { $up=(int)$x['is_up']; $ts=(int)$x['ts'];
                if ($up===0) { if ($start===null) $start=$ts; $lastDown=$ts; }
                elseif ($start!==null) { $eps[]=['start'=>$start,'end'=>$ts,'dur'=>round(($ts-$start)/60,1)]; $start=null; }
            }
            if ($start!==null) $eps[]=['start'=>$start,'end'=>($lastDown?:time()),'dur'=>round((($lastDown?:time())-$start)/60,1),'ongoing'=>true];
        } else {
            $bsec = 300;
            $r = $conn->query("SELECT DISTINCT FLOOR(UNIX_TIMESTAMP(recorded_at)/$bsec) b FROM nm_port_stats
                               WHERE node_id=$nid AND recorded_at >= (NOW() - INTERVAL $mins MINUTE) ORDER BY b");
            $ks=[]; while ($r && $x=$r->fetch_assoc()) $ks[]=(int)$x['b'];
            for ($i=1;$i<count($ks);$i++) if ($ks[$i]-$ks[$i-1] > 1)
                $eps[]=['start'=>($ks[$i-1]+1)*$bsec,'end'=>$ks[$i]*$bsec,'dur'=>round(($ks[$i]-$ks[$i-1]-1)*5,1)];
        }
        usort($eps, fn($a,$b)=>$b['start'] <=> $a['start']);   // newest first
        return array_slice($eps, 0, $limit);
    }
}

// ── Capacity forecasting ─────────────────────────────────────────────────────
if (!function_exists('nm_cap_forecast')) {
    function nm_cap_forecast($conn, int $days = 7, float $threshold = 80, int $limit = 30): array {
        $mins = $days * 1440;
        // candidate interfaces with utilisation history
        $out = [];
        $if = $conn->query("SELECT ps.node_id, ps.port_id, n.display_name node,
                                   COALESCE(i.display_name,i.if_name,CONCAT('port ',ps.port_id)) iface
                            FROM nm_port_stats ps
                            JOIN nm_nodes n ON n.id=ps.node_id
                            LEFT JOIN nm_interfaces i ON i.id=ps.port_id
                            WHERE ps.recorded_at >= (NOW() - INTERVAL $mins MINUTE)
                            GROUP BY ps.node_id, ps.port_id, n.display_name, iface
                            HAVING COUNT(*) >= 12");
        $cands = []; while ($if && $x = $if->fetch_assoc()) $cands[] = $x;

        foreach ($cands as $c) {
            $nid = (int)$c['node_id']; $pid = (int)$c['port_id'];
            $pr = $conn->query("SELECT UNIX_TIMESTAMP(recorded_at) ts, GREATEST(COALESCE(in_util,0),COALESCE(out_util,0)) u
                                FROM nm_port_stats WHERE node_id=$nid AND port_id=$pid
                                  AND recorded_at >= (NOW() - INTERVAL $mins MINUTE) ORDER BY recorded_at");
            $X = []; $Y = []; $t0 = null;
            while ($pr && $p = $pr->fetch_assoc()) { $t0 = $t0 ?? (int)$p['ts']; $X[] = ((int)$p['ts'] - $t0)/3600.0; $Y[] = (float)$p['u']; }
            $n = count($X); if ($n < 12) continue;
            // skip flat/zero interfaces
            $cur = array_sum(array_slice($Y, -min(6,$n))) / min(6,$n);    // recent avg
            $peak = max($Y);
            if ($peak < 1) continue;
            // linear regression slope (util% per hour)
            $mx = array_sum($X)/$n; $my = array_sum($Y)/$n; $num = 0; $den = 0;
            for ($i=0;$i<$n;$i++){ $num += ($X[$i]-$mx)*($Y[$i]-$my); $den += ($X[$i]-$mx)**2; }
            $slopeH = $den > 0 ? $num/$den : 0;
            $slopeDay = $slopeH * 24;
            $eta = null;
            if ($slopeDay > 0.01 && $cur < $threshold) $eta = round(($threshold - $cur) / $slopeDay, 1);
            $out[] = ['node'=>$c['node'], 'iface'=>$c['iface'], 'current'=>round($cur,1), 'peak'=>round($peak,1),
                      'slope_day'=>round($slopeDay,3), 'eta_days'=>$eta, 'over'=>($cur >= $threshold)];
        }
        // rank: at-risk first (over capacity, then soonest ETA), then busiest by
        // current utilisation — so the page always shows the top consumers even
        // when nothing is at risk.
        usort($out, function($a,$b){
            if ($a['over'] !== $b['over']) return $b['over'] <=> $a['over'];
            $ae = $a['eta_days'] ?? 1e9; $be = $b['eta_days'] ?? 1e9;
            if ($ae !== $be) return $ae <=> $be;
            return $b['current'] <=> $a['current'];
        });
        return array_slice($out, 0, $limit);
    }
}

// ── HTML report builder + sender ─────────────────────────────────────────────
if (!function_exists('nm_report_html')) {
    function nm_report_html($conn, string $period = '7d'): string {
        $mins = nm_sla_mins($period);
        $S = nm_sla_settings($conn);
        $sla = nm_sla_all($conn, $mins);
        $cap = nm_cap_forecast($conn, max(2, (int)($mins/1440)));
        $up = 0; $down = 0; $avg = 0;
        foreach ($sla as $s) { if ($s['last']==='up') $up++; else $down++; $avg += $s['uptime']; }
        $avg = $sla ? round($avg / count($sla), 3) : 0;
        // incidents in the period
        $inc = ['critical'=>0,'warning'=>0,'info'=>0,'total'=>0];
        if ($r = $conn->query("SELECT severity,COUNT(*) c FROM nm_incidents WHERE opened_at >= (NOW() - INTERVAL $mins MINUTE) GROUP BY severity"))
            while ($x = $r->fetch_assoc()) { $inc[$x['severity']] = (int)$x['c']; $inc['total'] += (int)$x['c']; }
        $openInc = 0;
        if ($r = $conn->query("SELECT COUNT(*) c FROM nm_incidents WHERE status IN ('open','acknowledged')")) $openInc = (int)$r->fetch_assoc()['c'];

        $e = fn($s)=>htmlspecialchars((string)$s);
        $pretty = ['24h'=>'Last 24 hours','7d'=>'Last 7 days','30d'=>'Last 30 days'][$period] ?? $period;
        $css = "font-family:Segoe UI,Arial,sans-serif;";
        $h  = "<div style='max-width:680px;margin:0 auto;{$css}color:#1a1a1a;'>";
        $h .= "<div style='background:#0f172a;color:#fff;padding:20px 24px;border-radius:12px 12px 0 0;'>"
            . "<div style='font-size:12px;letter-spacing:2px;color:#4da3ff;'>NEURU · NETWORK REPORT</div>"
            . "<div style='font-size:22px;font-weight:700;margin-top:4px;'>Operations Summary</div>"
            . "<div style='font-size:12px;color:#9aa;margin-top:2px;'>{$pretty} · ".date('M j, Y H:i')."</div></div>";
        $h .= "<div style='border:1px solid #e3e6ea;border-top:none;border-radius:0 0 12px 12px;padding:20px 24px;'>";
        // KPIs
        $h .= "<table width='100%' cellpadding='0' style='margin-bottom:18px;'><tr>"
            . "<td style='text-align:center;'><div style='font-size:26px;font-weight:800;color:#2ecc71;'>{$up}</div><div style='font-size:11px;color:#888;'>UP</div></td>"
            . "<td style='text-align:center;'><div style='font-size:26px;font-weight:800;color:".($down?'#e74c3c':'#2ecc71')."'>{$down}</div><div style='font-size:11px;color:#888;'>DOWN</div></td>"
            . "<td style='text-align:center;'><div style='font-size:26px;font-weight:800;color:#4da3ff;'>{$avg}%</div><div style='font-size:11px;color:#888;'>AVG UPTIME</div></td>"
            . "<td style='text-align:center;'><div style='font-size:26px;font-weight:800;color:".($openInc?'#f39c12':'#2ecc71')."'>{$openInc}</div><div style='font-size:11px;color:#888;'>OPEN INCIDENTS</div></td>"
            . "</tr></table>";
        // SLA table — worst 10
        $h .= "<div style='font-size:13px;font-weight:700;margin:6px 0 8px;'>Availability vs target ({$S['target']}%)</div>";
        $h .= "<table width='100%' style='border-collapse:collapse;font-size:13px;'>";
        $h .= "<tr style='color:#888;font-size:11px;text-align:left;'><th style='padding:5px;'>Node</th><th style='padding:5px;'>Uptime</th><th style='padding:5px;'>Downtime</th><th style='padding:5px;'>Outages</th></tr>";
        foreach (array_slice($sla, 0, 10) as $s) {
            $col = $s['meets'] ? '#2ecc71' : '#e74c3c';
            $h .= "<tr style='border-top:1px solid #eee;'><td style='padding:6px 5px;'>".$e($s['display_name'])."</td>"
                . "<td style='padding:6px 5px;color:{$col};font-weight:700;'>".$s['uptime']."%</td>"
                . "<td style='padding:6px 5px;'>".$s['down_min']." min</td><td style='padding:6px 5px;'>".$s['outages']."</td></tr>";
        }
        $h .= "</table>";
        // capacity
        if ($cap) {
            $h .= "<div style='font-size:13px;font-weight:700;margin:18px 0 8px;'>Capacity — interfaces to watch</div><table width='100%' style='border-collapse:collapse;font-size:13px;'>";
            $h .= "<tr style='color:#888;font-size:11px;text-align:left;'><th style='padding:5px;'>Interface</th><th style='padding:5px;'>Now</th><th style='padding:5px;'>Peak</th><th style='padding:5px;'>Forecast</th></tr>";
            foreach (array_slice($cap, 0, 8) as $c) {
                $eta = $c['over'] ? "<b style='color:#e74c3c;'>over {$S['cap_threshold']}%</b>" : ($c['eta_days']!==null ? "~{$c['eta_days']}d to {$S['cap_threshold']}%" : 'stable');
                $h .= "<tr style='border-top:1px solid #eee;'><td style='padding:6px 5px;'>".$e($c['node'].' · '.$c['iface'])."</td>"
                    . "<td style='padding:6px 5px;'>".$c['current']."%</td><td style='padding:6px 5px;'>".$c['peak']."%</td><td style='padding:6px 5px;'>{$eta}</td></tr>";
            }
            $h .= "</table>";
        }
        // incidents
        $h .= "<div style='font-size:13px;font-weight:700;margin:18px 0 8px;'>Incidents this period</div>"
            . "<div style='font-size:13px;'>🔴 {$inc['critical']} critical · 🟠 {$inc['warning']} warning · 🔵 {$inc['info']} info · <b>{$inc['total']} total</b></div>";
        $h .= "<div style='margin-top:18px;font-size:11px;color:#aaa;'>Generated by NEURU — Neural Network Monitor.</div>";
        $h .= "</div></div>";
        return $h;
    }

    function nm_report_send($conn, string $recipientsCsv = '', string $period = '7d'): array {
        $S = nm_sla_settings($conn);
        $to = trim($recipientsCsv) !== '' ? $recipientsCsv : $S['recipients'];
        $tos = array_filter(array_map('trim', preg_split('/[,;]+/', $to)));
        if (!$tos) return ['ok'=>false,'err'=>'No recipients configured'];
        $html = nm_report_html($conn, $period);
        $subj = 'NEURU Network Report — ' . date('M j, Y');
        $sent = 0; $errs = [];
        foreach ($tos as $addr) {
            $err = null;
            // send HTML email — reuse SMTP with an HTML content type
            if (nm_smtp_send_html($conn, $addr, $subj, $html, $err)) $sent++;
            else $errs[] = "$addr: $err";
        }
        return ['ok'=>$sent>0, 'sent'=>$sent, 'errors'=>$errs];
    }

    function nm_report_due($conn): bool {
        $S = nm_sla_settings($conn);
        if (!$S['enabled'] || trim($S['recipients']) === '') return false;
        $now = new DateTime('now');
        if ((int)$now->format('G') !== $S['hour']) return false;       // only at the configured hour
        if ($S['freq'] === 'weekly') {
            $dow = (int)$now->format('N');                              // 1=Mon..7=Sun
            if ($dow !== ($S['dow'] ?: 1)) return false;
        }
        // not already sent today
        if ($S['last_sent'] !== '' && substr($S['last_sent'],0,10) === $now->format('Y-m-d')) return false;
        return true;
    }
}

// ── HTML email helper (small extension of nm_smtp) ───────────────────────────
if (!function_exists('nm_smtp_send_html')) {
    function nm_smtp_send_html($conn, string $to, string $subject, string $html, ?string &$err = null): bool {
        // wrap the SMTP client but send text/html — we replicate by passing a
        // pre-built body and overriding the content type via a marker.
        $plain = trim(strip_tags(str_replace(['</div>','</tr>','</table>'], "\n", $html)));
        // nm_smtp_send sends text/plain; for HTML we do a multipart by hand here.
        $s = nm_smtp_settings($conn);
        if ($s['host'] === '') { $err = 'SMTP not configured'; return false; }
        $boundary = 'neuru' . bin2hex(random_bytes(8));
        $body = "--{$boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{$plain}\r\n"
              . "--{$boundary}\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n{$html}\r\n--{$boundary}--";
        return nm_smtp_send($conn, $to, $subject, $body, $err, null, "multipart/alternative; boundary=\"{$boundary}\"");
    }
}
