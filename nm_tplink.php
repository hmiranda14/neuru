<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — TP-Link "Easy Smart" L2 switch monitor (TL-SG105E/108E/116E/1016DE…).
//
// These switches have NO SNMP and NO remote syslog, but their web UI exposes a
// per-port statistics page. We poll it over plain HTTP (no agents, no Python):
//   1. POST /logon.cgi  (username/password/logon=Login) → sets H_P_SSID cookie.
//   2. GET  /PortStatisticsRpm.htm → embeds a JS `all_info` object:
//        state:[..]        per-port admin enabled (1) / disabled (0)
//        link_status:[..]  0=down 1=auto 2=10H 3=10F 4=100H 5=100F 6=1000F
//        pkts:[..]         4 per port → [TxGoodPkt, TxBadPkt, RxGoodPkt, RxBadPkt]
//
// The counters are PACKET counts (32-bit, cumulative since clear/reboot) — there
// are no byte counters, so we derive packets/sec (not Mbps), plus error rates and
// link-flap detection. Wrap / counter-clear is detected (delta<0 → rate skipped).
//
// RBAC perm: 'l2switch'. Engine for cron_tplink.php + l2switch.php.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_tp_ensure')) {
    require_once __DIR__ . '/nm_secrets.php';

    // link_status code → label / nominal speed (Mbps)
    function nm_tp_link_label(int $c): string {
        return [0=>'Link Down',1=>'Auto',2=>'10 Half',3=>'10 Full',4=>'100 Half',
                5=>'100 Full',6=>'1000 Full',7=>'—'][$c] ?? '—';
    }
    function nm_tp_link_speed(int $c): int {
        return [0=>0,1=>0,2=>10,3=>10,4=>100,5=>100,6=>1000,7=>0][$c] ?? 0;
    }

    function nm_tp_ensure($conn): void {
        $conn->query("CREATE TABLE IF NOT EXISTS nm_tplink_switches (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(80) NOT NULL,
            host VARCHAR(64) NOT NULL,
            port INT NOT NULL DEFAULT 80,
            username VARCHAR(32) NOT NULL DEFAULT 'admin',
            pass_enc TEXT,
            model VARCHAR(40) NOT NULL DEFAULT '',
            enabled TINYINT NOT NULL DEFAULT 1,
            err_threshold_pps DOUBLE NOT NULL DEFAULT 1,
            last_poll DATETIME NULL,
            last_status VARCHAR(12) NOT NULL DEFAULT '',
            last_error VARCHAR(255) NOT NULL DEFAULT '',
            created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_host (host,port)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $conn->query("CREATE TABLE IF NOT EXISTS nm_tplink_samples (
            switch_id INT NOT NULL,
            port INT NOT NULL,
            ts DATETIME NOT NULL,
            enabled TINYINT NOT NULL DEFAULT 1,
            link_code TINYINT NOT NULL DEFAULT 0,
            speed_mbps INT NOT NULL DEFAULT 0,
            tx_good BIGINT UNSIGNED NOT NULL DEFAULT 0,
            tx_bad  BIGINT UNSIGNED NOT NULL DEFAULT 0,
            rx_good BIGINT UNSIGNED NOT NULL DEFAULT 0,
            rx_bad  BIGINT UNSIGNED NOT NULL DEFAULT 0,
            tx_pps DOUBLE NOT NULL DEFAULT 0,
            rx_pps DOUBLE NOT NULL DEFAULT 0,
            tx_err_pps DOUBLE NOT NULL DEFAULT 0,
            rx_err_pps DOUBLE NOT NULL DEFAULT 0,
            PRIMARY KEY (switch_id,port,ts),
            KEY idx_sw_ts (switch_id,ts)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $conn->query("CREATE TABLE IF NOT EXISTS nm_tplink_events (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            switch_id INT NOT NULL,
            port INT NOT NULL,
            ts DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            kind VARCHAR(16) NOT NULL,
            severity VARCHAR(8) NOT NULL DEFAULT 'warn',
            detail VARCHAR(255) NOT NULL DEFAULT '',
            acked TINYINT NOT NULL DEFAULT 0,
            KEY idx_sw (switch_id,ts), KEY idx_ack (switch_id,acked)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','l2switch',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='l2switch')");
    }

    // ── Config CRUD ──────────────────────────────────────────────────────────
    function nm_tp_switches($conn, bool $onlyEnabled = false): array {
        $w = $onlyEnabled ? 'WHERE enabled=1' : '';
        $out = [];
        $r = $conn->query("SELECT * FROM nm_tplink_switches $w ORDER BY name, id");
        while ($r && ($x = $r->fetch_assoc())) $out[] = $x;
        return $out;
    }
    function nm_tp_switch_get($conn, int $id): ?array {
        $st = $conn->prepare("SELECT * FROM nm_tplink_switches WHERE id=? LIMIT 1");
        $st->bind_param('i', $id); $st->execute();
        return $st->get_result()->fetch_assoc() ?: null;
    }
    // Save (insert/update). Password only re-encrypted when a non-empty one is given.
    function nm_tp_switch_save($conn, array $d): array {
        nm_tp_ensure($conn);
        $id   = (int)($d['id'] ?? 0);
        $name = trim((string)($d['name'] ?? '')) ?: 'Switch';
        $host = trim((string)($d['host'] ?? ''));
        $port = max(1, min(65535, (int)($d['port'] ?? 80)));
        $user = trim((string)($d['username'] ?? 'admin')) ?: 'admin';
        $model= trim((string)($d['model'] ?? ''));
        $en   = !empty($d['enabled']) ? 1 : 0;
        $thr  = max(0.0, (float)($d['err_threshold_pps'] ?? 1));
        if ($host === '') return ['ok'=>false,'error'=>'Host is required'];
        $pw = (string)($d['password'] ?? '');

        if ($id) {
            if ($pw !== '') {
                $enc = nm_secret_encrypt($pw);
                // name s,host s,port i,user s,model s,enabled i,thr d,enc s,id i
                $st = $conn->prepare("UPDATE nm_tplink_switches SET name=?,host=?,port=?,username=?,model=?,enabled=?,err_threshold_pps=?,pass_enc=? WHERE id=?");
                $st->bind_param('ssissidsi', $name,$host,$port,$user,$model,$en,$thr,$enc,$id);
            } else {
                // name s,host s,port i,user s,model s,enabled i,thr d,id i
                $st = $conn->prepare("UPDATE nm_tplink_switches SET name=?,host=?,port=?,username=?,model=?,enabled=?,err_threshold_pps=? WHERE id=?");
                $st->bind_param('ssissidi', $name,$host,$port,$user,$model,$en,$thr,$id);
            }
            $st->execute();
            return ['ok'=>true,'id'=>$id];
        }
        $enc = nm_secret_encrypt($pw);
        // name s,host s,port i,user s,model s,enabled i,thr d,enc s
        $st = $conn->prepare("INSERT INTO nm_tplink_switches (name,host,port,username,model,enabled,err_threshold_pps,pass_enc)
                              VALUES (?,?,?,?,?,?,?,?)
                              ON DUPLICATE KEY UPDATE name=VALUES(name),username=VALUES(username),model=VALUES(model),
                                  enabled=VALUES(enabled),err_threshold_pps=VALUES(err_threshold_pps),pass_enc=VALUES(pass_enc)");
        $st->bind_param('ssissids', $name,$host,$port,$user,$model,$en,$thr,$enc);
        $st->execute();
        return ['ok'=>true,'id'=>$conn->insert_id ?: 0];
    }
    function nm_tp_switch_delete($conn, int $id): void {
        $conn->query("DELETE FROM nm_tplink_switches WHERE id=".$id);
        $conn->query("DELETE FROM nm_tplink_samples WHERE switch_id=".$id);
        $conn->query("DELETE FROM nm_tplink_events  WHERE switch_id=".$id);
    }

    // ── Parse the all_info JS object → list of per-port dicts ─────────────────
    function nm_tp_parse(string $html): ?array {
        if (!preg_match('/max_port_num\s*=\s*(\d+)/', $html, $mn)) return null;
        if (!preg_match('/state:\s*\[([0-9,\s]*)\]/', $html, $ms))        return null;
        if (!preg_match('/link_status:\s*\[([0-9,\s]*)\]/', $html, $ml))  return null;
        if (!preg_match('/pkts:\s*\[([0-9,\s]*)\]/', $html, $mp))         return null;
        $n  = (int)$mn[1];
        $sp = fn($s) => array_map('intval', preg_split('/\s*,\s*/', trim($s), -1, PREG_SPLIT_NO_EMPTY));
        $state = $sp($ms[1]); $link = $sp($ml[1]); $pk = $sp($mp[1]);
        if ($n < 1 || $n > 64) return null;
        $ports = [];
        for ($i = 0; $i < $n; $i++) {
            $lc = $link[$i] ?? 0;
            $ports[] = [
                'port'      => $i + 1,
                'enabled'   => $state[$i] ?? 0,
                'link_code' => $lc,
                'speed'     => nm_tp_link_speed($lc),
                'tx_good'   => $pk[4*$i]     ?? 0,
                'tx_bad'    => $pk[4*$i + 1] ?? 0,
                'rx_good'   => $pk[4*$i + 2] ?? 0,
                'rx_bad'    => $pk[4*$i + 3] ?? 0,
            ];
        }
        return $ports;
    }

    // ── Live scrape: login + fetch + parse. Returns ['ok','ports'|'error'] ────
    function nm_tp_fetch(string $host, int $port, string $user, string $pass): array {
        if (!function_exists('curl_init')) return ['ok'=>false,'error'=>'php-curl not available'];
        $base = "http://{$host}:{$port}";
        $jar  = tempnam(sys_get_temp_dir(), 'nmtp');
        $hdr  = ['Referer: '.$base.'/'];

        $ch = curl_init("$base/logon.cgi");
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query(['username'=>$user,'password'=>$pass,'logon'=>'Login']),
            CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIEJAR => $jar, CURLOPT_COOKIEFILE => $jar,
            CURLOPT_TIMEOUT => 12, CURLOPT_CONNECTTIMEOUT => 6, CURLOPT_HTTPHEADER => $hdr,
        ]);
        $lr = curl_exec($ch); $lerr = curl_error($ch); curl_close($ch);
        if ($lr === false) { @unlink($jar); return ['ok'=>false,'error'=>'login failed: '.$lerr]; }
        // logonInfo first element: 0 = OK, 1 = bad credentials, 3/4 = sessions full, 5 = timeout
        if (preg_match('/logonInfo\s*=\s*new\s+Array\(\s*([0-9]+)/i', $lr, $mi) && (int)$mi[1] !== 0) {
            @unlink($jar);
            $code = (int)$mi[1];
            $msg  = [1=>'wrong username/password',2=>'user not allowed',3=>'login slots full',
                     4=>'too many sessions',5=>'session timeout'][$code] ?? ('login error '.$code);
            return ['ok'=>false,'error'=>$msg];
        }

        $ch = curl_init("$base/PortStatisticsRpm.htm");
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIEJAR => $jar, CURLOPT_COOKIEFILE => $jar,
            CURLOPT_TIMEOUT => 12, CURLOPT_CONNECTTIMEOUT => 6, CURLOPT_HTTPHEADER => $hdr,
        ]);
        $body = curl_exec($ch); $serr = curl_error($ch); curl_close($ch);
        @unlink($jar);
        if ($body === false) return ['ok'=>false,'error'=>'stats fetch failed: '.$serr];
        $ports = nm_tp_parse($body);
        if ($ports === null) return ['ok'=>false,'error'=>'could not parse statistics (auth expired or unsupported firmware)'];
        return ['ok'=>true,'ports'=>$ports];
    }

    // latest stored sample per port → map[port]=row
    function nm_tp_latest_map($conn, int $sid): array {
        $out = [];
        $r = $conn->query("SELECT s.* FROM nm_tplink_samples s
            JOIN (SELECT port, MAX(ts) mx FROM nm_tplink_samples WHERE switch_id={$sid} GROUP BY port) m
            ON s.port=m.port AND s.ts=m.mx WHERE s.switch_id={$sid}");
        while ($r && ($x = $r->fetch_assoc())) $out[(int)$x['port']] = $x;
        return $out;
    }

    function nm_tp_recent_event($conn, int $sid, int $port, string $kind, int $mins): bool {
        $kind = $conn->real_escape_string($kind);
        $r = $conn->query("SELECT 1 FROM nm_tplink_events WHERE switch_id={$sid} AND port={$port}
            AND kind='{$kind}' AND ts >= (NOW() - INTERVAL {$mins} MINUTE) LIMIT 1");
        return $r && $r->num_rows > 0;
    }
    function nm_tp_event($conn, int $sid, int $port, string $kind, string $sev, string $detail): void {
        $st = $conn->prepare("INSERT INTO nm_tplink_events (switch_id,port,kind,severity,detail) VALUES (?,?,?,?,?)");
        $st->bind_param('iisss', $sid,$port,$kind,$sev,$detail);
        $st->execute();
    }

    // ── Poll one switch: scrape, compute rate deltas, raise events, store ─────
    function nm_tp_poll_one($conn, array $sw): array {
        nm_tp_ensure($conn);
        $sid  = (int)$sw['id'];
        $pass = nm_secret_decrypt($sw['pass_enc'] ?? '');
        $res  = nm_tp_fetch($sw['host'], (int)$sw['port'], $sw['username'], $pass);

        if (!$res['ok']) {
            $err = substr($res['error'], 0, 250);
            $st = $conn->prepare("UPDATE nm_tplink_switches SET last_poll=NOW(),last_status='error',last_error=? WHERE id=?");
            $st->bind_param('si', $err, $sid); $st->execute();
            return ['ok'=>false,'switch'=>$sw['name'],'error'=>$res['error']];
        }

        $prev = nm_tp_latest_map($conn, $sid);
        $now  = time();
        $thr  = (float)($sw['err_threshold_pps'] ?? 1);
        $events = 0; $up = 0; $down = 0;

        $ins = $conn->prepare("INSERT INTO nm_tplink_samples
            (switch_id,port,ts,enabled,link_code,speed_mbps,tx_good,tx_bad,rx_good,rx_bad,tx_pps,rx_pps,tx_err_pps,rx_err_pps)
            VALUES (?,?,FROM_UNIXTIME(?),?,?,?,?,?,?,?,?,?,?,?)
            ON DUPLICATE KEY UPDATE tx_good=VALUES(tx_good)");

        foreach ($res['ports'] as $p) {
            $port = (int)$p['port'];
            $lc   = (int)$p['link_code'];
            $linkUp = ($lc !== 0);
            if ($linkUp) $up++; else $down++;

            // rates vs previous sample (skip on reset/wrap or first sample)
            $txpps = $rxpps = $txerr = $rxerr = 0.0;
            if (isset($prev[$port])) {
                $pv = $prev[$port];
                $dt = $now - strtotime($pv['ts']);
                if ($dt > 0) {
                    $d = fn($cur,$old) => ($cur >= $old) ? ($cur - $old) / $dt : 0.0;
                    $txpps = $d($p['tx_good'], (int)$pv['tx_good']);
                    $rxpps = $d($p['rx_good'], (int)$pv['rx_good']);
                    $txerr = $d($p['tx_bad'],  (int)$pv['tx_bad']);
                    $rxerr = $d($p['rx_bad'],  (int)$pv['rx_bad']);
                }
                // link transition events (edge-triggered, naturally deduped)
                $plc = (int)$pv['link_code'];
                if ($plc !== $lc) {
                    if ($lc === 0) {
                        nm_tp_event($conn,$sid,$port,'link_down','crit',
                            "Port {$port} link DOWN (was ".nm_tp_link_label($plc).")"); $events++;
                    } elseif ($plc === 0) {
                        nm_tp_event($conn,$sid,$port,'link_up','info',
                            "Port {$port} link UP at ".nm_tp_link_label($lc)); $events++;
                    } else {
                        $sev = (nm_tp_link_speed($lc) < nm_tp_link_speed($plc)) ? 'warn' : 'info';
                        nm_tp_event($conn,$sid,$port,'link_change',$sev,
                            "Port {$port} renegotiated ".nm_tp_link_label($plc)." → ".nm_tp_link_label($lc)); $events++;
                    }
                }
                // bad-packet (error) alert — suppress repeats within 20 min
                $errpps = $txerr + $rxerr;
                if ($errpps > $thr && !nm_tp_recent_event($conn,$sid,$port,'errors',20)) {
                    nm_tp_event($conn,$sid,$port,'errors','warn',
                        sprintf("Port %d bad packets rising (%.1f err/s: tx %.1f, rx %.1f)",$port,$errpps,$txerr,$rxerr));
                    $events++;
                }
            }

            $en=(int)$p['enabled']; $sm=(int)$p['speed'];
            $txg=(int)$p['tx_good']; $txb=(int)$p['tx_bad']; $rxg=(int)$p['rx_good']; $rxb=(int)$p['rx_bad'];
            $ins->bind_param('iiiiiiiiiidddd',
                $sid,$port,$now,$en,$lc,$sm,$txg,$txb,$rxg,$rxb,$txpps,$rxpps,$txerr,$rxerr);
            $ins->execute();
        }

        $st = $conn->prepare("UPDATE nm_tplink_switches SET last_poll=NOW(),last_status='ok',last_error='' WHERE id=?");
        $st->bind_param('i', $sid); $st->execute();
        return ['ok'=>true,'switch'=>$sw['name'],'ports'=>count($res['ports']),'up'=>$up,'down'=>$down,'events'=>$events];
    }

    function nm_tp_poll_all($conn): array {
        nm_tp_ensure($conn);
        $out = [];
        foreach (nm_tp_switches($conn, true) as $sw) $out[] = nm_tp_poll_one($conn, $sw);
        return $out;
    }

    function nm_tp_prune($conn, int $days = 7): void {
        $days = max(1, $days);
        $conn->query("DELETE FROM nm_tplink_samples WHERE ts < (NOW() - INTERVAL {$days} DAY)");
        $conn->query("DELETE FROM nm_tplink_events  WHERE ts < (NOW() - INTERVAL 30 DAY)");
    }

    // ── Read helpers for the UI ───────────────────────────────────────────────
    function nm_tp_ports_view($conn, int $sid): array {
        $latest = nm_tp_latest_map($conn, $sid);
        ksort($latest);
        $out = [];
        foreach ($latest as $port => $r) {
            $out[] = [
                'port'      => (int)$port,
                'enabled'   => (int)$r['enabled'],
                'link_code' => (int)$r['link_code'],
                'link'      => nm_tp_link_label((int)$r['link_code']),
                'speed'     => (int)$r['speed_mbps'],
                'tx_good'   => (int)$r['tx_good'],  'tx_bad' => (int)$r['tx_bad'],
                'rx_good'   => (int)$r['rx_good'],  'rx_bad' => (int)$r['rx_bad'],
                'tx_pps'    => round((float)$r['tx_pps'],1), 'rx_pps' => round((float)$r['rx_pps'],1),
                'tx_err_pps'=> round((float)$r['tx_err_pps'],2), 'rx_err_pps'=> round((float)$r['rx_err_pps'],2),
                'ts'        => $r['ts'],
            ];
        }
        return $out;
    }
    function nm_tp_spark($conn, int $sid, int $port, int $mins = 120): array {
        $r = $conn->query("SELECT ts,tx_pps,rx_pps FROM nm_tplink_samples
            WHERE switch_id={$sid} AND port={$port} AND ts >= (NOW() - INTERVAL {$mins} MINUTE) ORDER BY ts");
        $out = [];
        while ($r && ($x = $r->fetch_assoc())) $out[] = ['t'=>$x['ts'],'tx'=>round((float)$x['tx_pps'],1),'rx'=>round((float)$x['rx_pps'],1)];
        return $out;
    }
    function nm_tp_events($conn, int $sid, int $limit = 50): array {
        $limit = max(1, min(500, $limit));
        $out = [];
        $r = $conn->query("SELECT * FROM nm_tplink_events WHERE switch_id={$sid} ORDER BY ts DESC LIMIT {$limit}");
        while ($r && ($x = $r->fetch_assoc())) $out[] = $x;
        return $out;
    }
    function nm_tp_event_ack($conn, int $sid, int $eid): void {
        if ($eid > 0) $conn->query("UPDATE nm_tplink_events SET acked=1 WHERE id={$eid} AND switch_id={$sid}");
        else          $conn->query("UPDATE nm_tplink_events SET acked=1 WHERE switch_id={$sid}");
    }
}
