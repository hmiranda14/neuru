<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — CONNECTION DOCTOR engine (gamer network-quality). Measures the path
// YOU → Router → ISP → Game server from BOTH the gamer PC (over SSH, real ICMP)
// AND the NOC (TCP latency), so it can ISOLATE where lag comes from: your WiFi /
// router, your ISP, or the game server. Returns per-hop ping/jitter/loss/stability
// + a plain-language verdict. Read-only. Perm 'gaming'. Reuses nm_gaming.php.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_gaming.php';   // nm_win_ps, _nm_g_out, nm_win_resolve_ssh, detection/endpoints

// history table — every run (on-demand OR the cron) is stored so you can see EXACTLY when the connection degraded
function nm_netdoc_ensure($conn): void {
    static $done=false; if($done)return; $done=true;
    try { $conn->query("CREATE TABLE IF NOT EXISTS nm_netdoc_history (
        id BIGINT AUTO_INCREMENT PRIMARY KEY, rig_id INT NOT NULL, ts DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        target VARCHAR(255) DEFAULT '',
        game_ping FLOAT NULL, game_jitter FLOAT NULL, game_loss FLOAT NULL, game_stab INT NULL,
        net_ping FLOAT NULL, net_jitter FLOAT NULL, net_loss FLOAT NULL,
        gw_ping FLOAT NULL, isp_ping FLOAT NULL, noc_net_ping FLOAT NULL,
        verdict_level VARCHAR(8) DEFAULT 'ok', verdict_title VARCHAR(160) DEFAULT '',
        KEY rig_ts (rig_id, ts)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); } catch (\Throwable $e) {}
}
function nm_netdoc_save($conn, int $rid, array $res): void {
    if (empty($res['ok'])) return; nm_netdoc_ensure($conn);
    $by=[]; foreach (($res['hops']??[]) as $x) $by[$x['id']]=$x;
    $g=$by['game']['pc']??[]; $ng=$by['internet']['pc']??[]; $gw=$by['gateway']['pc']??[]; $isp=$by['isp']['pc']??[]; $nn=$by['internet']['noc']??[]; $v=$res['verdict']??[];
    try {
        $tgt=(string)($res['game_target']??''); $lvl=(string)($v['level']??'ok'); $ttl=substr((string)($v['title']??''),0,160);
        $gp=$g['avg']??null; $gj=$g['jitter']??null; $gl=$g['loss']??null; $gs=$g['stability']??null;
        $np=$ng['avg']??null; $nj=$ng['jitter']??null; $nl=$ng['loss']??null;
        $gwp=$gw['avg']??null; $ispp=$isp['avg']??null; $nnp=$nn['avg']??null;
        $st=$conn->prepare("INSERT INTO nm_netdoc_history (rig_id,target,game_ping,game_jitter,game_loss,game_stab,net_ping,net_jitter,net_loss,gw_ping,isp_ping,noc_net_ping,verdict_level,verdict_title) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
        $st->bind_param('isdddiddddddss',$rid,$tgt,$gp,$gj,$gl,$gs,$np,$nj,$nl,$gwp,$ispp,$nnp,$lvl,$ttl);
        $st->execute(); $st->close();
    } catch (\Throwable $e) {}
    // retention — keep ~30 days
    try { $conn->query("DELETE FROM nm_netdoc_history WHERE rig_id=".(int)$rid." AND ts < (NOW() - INTERVAL 30 DAY)"); } catch (\Throwable $e) {}
}
function nm_netdoc_get_history($conn, int $rid, int $hours=24): array {
    nm_netdoc_ensure($conn); $hours=max(1,min(720,$hours)); $out=[];
    try { $st=$conn->prepare("SELECT UNIX_TIMESTAMP(ts) t, game_ping gp, game_jitter gj, game_loss gl, game_stab gs, net_ping np, verdict_level vl FROM nm_netdoc_history WHERE rig_id=? AND ts >= (NOW() - INTERVAL ? HOUR) ORDER BY ts ASC LIMIT 3000");
        $st->bind_param('ii',$rid,$hours); $st->execute(); $r=$st->get_result();
        while ($x=$r->fetch_assoc()) $out[]=['t'=>(int)$x['t'],'ping'=>$x['gp']!==null?(float)$x['gp']:null,'jitter'=>$x['gj']!==null?(float)$x['gj']:null,'loss'=>$x['gl']!==null?(float)$x['gl']:null,'stab'=>$x['gs']!==null?(int)$x['gs']:null,'net'=>$x['np']!==null?(float)$x['np']:null,'lvl'=>(string)$x['vl']];
        $st->close(); } catch (\Throwable $e) {}
    return $out;
}

function nm_netdoc_validip(string $s): bool { return (bool)filter_var(trim($s), FILTER_VALIDATE_IP); }
function nm_netdoc_valid_host(string $s): bool {
    $s = trim($s); if ($s==='' || strlen($s)>255) return false;
    if (filter_var($s, FILTER_VALIDATE_IP)) return true;
    return (bool)preg_match('/^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/', $s);
}
// RFC1918 / loopback / link-local (NOT CGNAT 100.64/10 — that's the ISP's carrier network)
function nm_netdoc_is_private(string $ip): bool {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return false;
    $l = ip2long($ip);
    foreach ([['10.0.0.0','255.0.0.0'],['172.16.0.0','255.240.0.0'],['192.168.0.0','255.255.0.0'],['169.254.0.0','255.255.0.0'],['127.0.0.0','255.0.0.0']] as $r) {
        if (($l & ip2long($r[1])) === ip2long($r[0])) return true;
    }
    return false;
}

// stddev-based jitter + a 0..100 stability score from a list of RTTs + loss%
function nm_netdoc_stats(array $times, float $loss): array {
    $times = array_values(array_filter($times, fn($x)=>$x!==null && $x>=0));
    if (!$times) return ['avg'=>null,'min'=>null,'max'=>null,'jitter'=>null,'loss'=>round($loss,1),'stability'=>($loss>0?max(0,round(100-$loss*8)):null)];
    $n=count($times); $avg=array_sum($times)/$n;
    $var=0; foreach($times as $t) $var+=($t-$avg)*($t-$avg); $sd=sqrt($var/$n);
    $cv = $avg>0 ? $sd/$avg : 0;
    $stab = max(0, min(100, round(100 - $cv*160 - $loss*8)));
    return ['avg'=>round($avg,1),'min'=>round(min($times),1),'max'=>round(max($times),1),'jitter'=>round($sd,1),'loss'=>round($loss,1),'stability'=>$stab];
}

// ── PROBE from the gamer PC (Windows, over SSH): real ICMP ping -n N ──
function nm_netdoc_probe_pc($ssh, string $target, int $n=10): array {
    if (!nm_netdoc_valid_host($target)) return ['ok'=>false];
    $n = max(3, min(20, $n));
    $out = trim((string)_nm_g_out(nm_win_ps($ssh, 'ping -n '.$n.' '.$target.' 2>$null', 20)));
    if ($out === '') return ['ok'=>false];
    // per-reply RTTs: "time=12ms" / "time<1ms" / Spanish "tiempo=12ms"
    $times=[]; if (preg_match_all('/(?:time|tiempo)[=<]\s*(\d+)\s*ms/i', $out, $m)) foreach($m[1] as $v) $times[]=(float)$v;
    // loss %: "Lost = 1 (10% loss)" / Spanish "perdidos = 1 (10% perdidos)"
    $loss = 0.0; if (preg_match('/\((\d+)%\s*(?:loss|p[eé]rdid)/i', $out, $mm)) $loss=(float)$mm[1];
    elseif (preg_match_all('/(?:time|tiempo)[=<]/i',$out,$mr)) { $recv=count($mr[0]); $loss = $n>0 ? round(($n-$recv)/$n*100,1) : 0; }
    // 0 echo replies = the host simply doesn't answer ICMP (VERY common for ISP/backbone routers) — that is NOT
    // packet loss on the path, so flag it as "filtered" and NEVER let it drive the verdict or a red alert.
    $filtered = (count($times)===0);
    return ['ok'=>true,'filtered'=>$filtered,'recv'=>count($times)] + nm_netdoc_stats($times, $loss);
}

// ── PROBE from the NOC (PHP host): TCP connect latency loop (no binaries needed) ──
function nm_netdoc_probe_noc(string $host, int $port=443, int $n=8): array {
    if (!nm_netdoc_valid_host($host)) return ['ok'=>false];
    if (nm_netdoc_is_private($host)) return ['ok'=>false,'reason'=>'private'];   // NOC can't reach the PC's LAN
    $n=max(3,min(15,$n)); $times=[]; $fail=0;
    for ($i=0;$i<$n;$i++){ $t0=microtime(true); $fp=@fsockopen($host,$port,$e,$es,1.2);
        if ($fp){ $times[]=(microtime(true)-$t0)*1000; fclose($fp); } else $fail++; }
    $loss = $n>0 ? round($fail/$n*100,1) : 0;
    return ['ok'=>true,'via'=>'tcp:'.$port] + nm_netdoc_stats($times, $loss);
}

// ── discover the path hops (gateway + first ISP hop) from the PC via tracert to a stable anchor ──
function nm_netdoc_path($ssh): array {
    $gw=''; $isp='';
    $out = trim((string)_nm_g_out(nm_win_ps($ssh, 'tracert -d -h 6 -w 400 1.1.1.1 2>$null', 30)));
    if ($out!=='') {
        foreach (preg_split('/\r?\n/', $out) as $ln) {
            if (!preg_match('/^\s*\d+\s/', $ln)) continue;               // hop lines start with the hop number
            if (preg_match('/(\d{1,3}(?:\.\d{1,3}){3})\s*$/', trim($ln), $m)) {
                $ip=$m[1];
                if ($gw==='' && nm_netdoc_is_private($ip)) $gw=$ip;      // first private hop = your router
                if ($isp==='' && !nm_netdoc_is_private($ip)) { $isp=$ip; break; }   // first public hop = your ISP edge
            }
        }
    }
    // fallback for the gateway: default route next-hop
    if ($gw==='') { $g = trim((string)_nm_g_out(nm_win_ps($ssh, '(Get-NetRoute -DestinationPrefix \'0.0.0.0/0\' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop', 12)));
        if (nm_netdoc_validip($g)) $gw=$g; }
    return ['gateway'=>$gw,'isp'=>$isp];
}

// ── the full run: build the 3-hop path + an internet anchor, probe from BOTH vantages, render a verdict ──
function nm_netdoc_run($conn, array $h, string $gameTarget=''): array {
    $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn,$h) : null;
    if (!$ssh) return ['ok'=>false,'error'=>'no SSH for this rig'];

    // game server: caller-provided, else the detected game's first server endpoint, else an internet reference
    $gameLabel = 'Game Server';
    if ($gameTarget==='' ) {
        try { $g = nm_gaming_detect($ssh, nm_gaming_get_folders($conn));
            if ($g && !empty($g['ep']) && is_array($g['ep'])) { $gameTarget = (string)reset($g['ep']); $gameLabel = ($g['title']??'Game').' server'; }
        } catch (\Throwable $e) {}
    }
    // parse an optional :PORT off the target so the NOC TCP probe hits the game's real port (25565 Minecraft, 27015 CS2…)
    $gPort = 443;
    if ($gameTarget!=='' && preg_match('/^(.+):(\d{1,5})$/', $gameTarget, $mp)) { $gameTarget=$mp[1]; $gPort=(int)$mp[2]; }
    if ($gameTarget==='' || !nm_netdoc_valid_host($gameTarget)) { $gameTarget='1.1.1.1'; $gameLabel='Internet (no game server set)'; $gPort=443; }

    $path = nm_netdoc_path($ssh);
    $anchor = '1.1.1.1';   // stable internet reference for the PC-vs-NOC comparison

    $hops = [];
    $hops[] = ['id'=>'gateway','label'=>'Your Router / WiFi','ip'=>$path['gateway'],'icon'=>'router',
               'pc'=>$path['gateway']!==''?nm_netdoc_probe_pc($ssh,$path['gateway'],8):['ok'=>false],'noc'=>['ok'=>false,'reason'=>'local']];
    $hops[] = ['id'=>'isp','label'=>'Your ISP (first hop)','ip'=>$path['isp'],'icon'=>'isp',
               'pc'=>$path['isp']!==''?nm_netdoc_probe_pc($ssh,$path['isp'],8):['ok'=>false],'noc'=>['ok'=>false,'reason'=>'path-specific']];
    $hops[] = ['id'=>'internet','label'=>'Internet (1.1.1.1)','ip'=>$anchor,'icon'=>'cloud',
               'pc'=>nm_netdoc_probe_pc($ssh,$anchor,10),'noc'=>nm_netdoc_probe_noc($anchor,443,8)];
    $gTip = $gameTarget;   // already host-only (port parsed off above)
    $hops[] = ['id'=>'game','label'=>$gameLabel,'ip'=>$gTip,'icon'=>'game',
               'pc'=>nm_netdoc_probe_pc($ssh,$gTip,10),'noc'=>nm_netdoc_probe_noc($gTip,$gPort>0?$gPort:443,8)];

    $res = ['ok'=>true,'hops'=>$hops,'verdict'=>nm_netdoc_verdict($hops),'game_target'=>$gameTarget,'ts'=>time()];
    try { nm_netdoc_save($conn, (int)($h['id']??0), $res); } catch (\Throwable $e) {}   // record to history (monitoring)
    return $res;
}

// plain-language "is it your PC/WiFi, your ISP, or the game?" from the hop stats.
// KEY: intermediate hops (the ISP first hop) often don't answer ICMP at all → 'filtered'. We NEVER judge on a
// filtered hop; ISP/line health is read from the RELIABLE internet anchor (1.1.1.1, which always echo-replies).
function nm_netdoc_verdict(array $hops): array {
    $by=[]; foreach($hops as $x) $by[$x['id']]=$x;
    $ok  = function($p){ return !empty($p['ok']) && empty($p['filtered']); };   // has real, usable samples
    $bad = function($p) use($ok){ return $ok($p) && (($p['loss']??0)>=3 || ($p['jitter']??0)>=25 || ($p['avg']??0)>=140); };
    $warn= function($p) use($ok){ return $ok($p) && (($p['loss']??0)>0 || ($p['jitter']??0)>=12 || ($p['avg']??0)>=100); };
    $gw=$by['gateway']['pc']??[]; $net=$by['internet']['pc']??[]; $netN=$by['internet']['noc']??[]; $game=$by['game']['pc']??[];

    $level='ok'; $title='Connection looks healthy'; $detail='Ping, jitter and loss are all in a good range for gaming.';
    if ($bad($gw)) { $level='crit'; $title='Your local network / WiFi is the problem';
        $detail='High jitter or loss right at your own router — try Ethernet instead of WiFi, move closer to the router, or check for interference / a saturated line.'; }
    elseif ($bad($net)) { $level='crit'; $title='Your ISP / line is the bottleneck';
        $detail='Your router is fine, but the path to the wider internet (1.1.1.1) shows jitter or loss — that points to your provider or the last-mile line. Attach the Proof-of-Lag report to a support ticket.'; }
    elseif ($bad($game)) { $level='warn'; $title='The game server (or its route) looks worse';
        $detail='Your line to the general internet is clean, but the path to this game host is worse. NOTE: many game / web servers rate-limit ping and can report FALSE loss — confirm in-game before blaming the server.'; }
    elseif ($warn($gw)||$warn($net)) { $level='warn'; $title='Minor instability detected';
        $detail='Some jitter/loss is present but not severe. Watch it during a match — if it spikes, Ethernet usually helps.'; }

    // PC-vs-NOC cross-check note (only from the reliable anchor; never contradicts the headline)
    $note='';
    if ($ok($net) && !empty($netN['ok'])) {
        $dp=$net['avg']??0; $dn=$netN['avg']??0;
        if ($dp>$dn+40 || (($net['loss']??0) - ($netN['loss']??0))>=3) $note='NEURU reaches the internet cleaner than your PC → the weak link is between your PC and the internet (WiFi / cable), not the wider network.';
        elseif ($level==='ok' && ($net['jitter']??0)<8 && ($netN['jitter']??0)<8) $note='Both your PC and NEURU see a stable path — your line is solid.';
    }
    return ['level'=>$level,'title'=>$title,'detail'=>$detail,'note'=>$note];
}
