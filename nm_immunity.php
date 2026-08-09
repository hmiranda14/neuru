<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Collective Immunity engine ("the vaccine"). A threat seen at ONE node
// (malicious domain in a Pi-hole query log, a port-scanning source IP in syslog,
// or a manual indicator) is turned into a block rule and FANNED OUT instantly to
// EVERY Pi-hole (DNS deny list, v6 write API) and firewall (SSH address-list /
// iptables). If one node is hit, the rest become immune automatically.
//
//   nm_imm_add_threat()  — register/dedup an indicator (status 'pending')
//   nm_imm_vaccinate()   — distribute the block to all Pi-holes / firewalls
//   nm_imm_revoke()      — pull the block back everywhere
//   nm_imm_detect_*()    — auto-discover threats from syslog / Pi-hole queries
//
// Page gate = permission key 'immunity'. Reuses [[netmon-pihole]] write proxy +
// [[netmon-config-manager]] Python SSH for the firewall push.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_pihole.php';
require_once __DIR__ . '/nm_adguard.php';   // AdGuard Home fan-out (mirrors Pi-hole)
require_once __DIR__ . '/nm_confmgr.php';   // nm_cm_resolve_ssh + nm_cm_ssh_fetch + vendors
require_once __DIR__ . '/nm_audit.php';

if (!function_exists('nm_imm_vaccinate')) {

    // Shipped STARTER DNS threat patterns (regex vs queried domains, case-insensitive). Seeded on
    // ensure so EVERY install detects malware/abuse domains out-of-the-box from its Pi-hole/AdGuard
    // query logs — previously empty on fresh installs, so Collective Immunity silently found nothing.
    if (!defined('NM_IMM_DEFAULT_DNS_PATTERNS')) define('NM_IMM_DEFAULT_DNS_PATTERNS',
"# ── NEURU starter DNS threat patterns (regex, vs queried domains, case-insensitive) ──\n".
"# Heavily-abused free TLDs (malware / phishing / spam)\n".
"\\.(tk|ml|ga|cf|gq)$\n".
"# Other commonly-abused cheap TLDs\n".
"\\.(top|gdn|work|click|link|loan|men|date|racing|win|bid|stream|download|review|country|kim|science|party|trade|webcam|cricket|accountant|faith|mov|zip)$\n".
"# Crypto-mining / drive-by miners\n".
"(^|\\.)(coin-?hive|cryptonight|minexmr|webmine|jsecoin|coinimp|crypto-?loot|deepminer|miner[0-9])\n".
"# Malware / C2 / threat keywords embedded in the domain\n".
"(^|\\.|-)(malware|botnet|ransom(ware)?|trojan|keylogger|phish(ing)?|exploit|payload|cobaltstrike)\n".
"# DGA-like: very long random alphanumeric subdomain\n".
"^[a-z0-9]{25,}\\.\n".
"# DNS-tunneling: very long hex subdomain\n".
"^[0-9a-f]{32,}\\.\n");

    function nm_imm_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        static $done=false; if($done) return; $done=true;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_threats (
            id INT AUTO_INCREMENT PRIMARY KEY,
            indicator VARCHAR(255) NOT NULL,
            ind_type VARCHAR(8) NOT NULL DEFAULT 'domain',   -- domain | regex | ip
            severity VARCHAR(8) NOT NULL DEFAULT 'high',
            source VARCHAR(40) NOT NULL DEFAULT 'manual',     -- manual | portscan | dns | feed
            detail VARCHAR(400) DEFAULT NULL,
            hits INT NOT NULL DEFAULT 1,
            status VARCHAR(10) NOT NULL DEFAULT 'pending',     -- pending | active | revoked | dismissed
            distributed_ok INT NOT NULL DEFAULT 0,
            distributed_fail INT NOT NULL DEFAULT 0,
            first_seen DATETIME DEFAULT NULL,
            last_seen DATETIME DEFAULT NULL,
            vaccinated_at DATETIME DEFAULT NULL,
            created_by INT DEFAULT NULL,
            UNIQUE KEY uniq_ind (indicator, ind_type),
            KEY idx_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_threat_actions (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            threat_id INT NOT NULL,
            target_type VARCHAR(10) NOT NULL,   -- pihole | adguard | firewall
            target_id INT DEFAULT NULL,
            target_name VARCHAR(120) DEFAULT NULL,
            status VARCHAR(10) NOT NULL,         -- ok | existed | failed
            detail VARCHAR(300) DEFAULT NULL,
            acted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            KEY idx_threat (threat_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        try { $conn->query("INSERT INTO role_profiles (role_name,button_key,enabled)
            SELECT 'admin','immunity',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='immunity')"); } catch (\Throwable $e) {}
        // which device(s) reported the threat (syslog source) — added 2026-06-25 so an
        // operator with multiple firewalls knows WHERE it was seen vs where the block lands.
        // (mysqli is in exception mode, so '@' won't swallow a duplicate-column error → guard.)
        $c=$conn->query("SHOW COLUMNS FROM nm_threats LIKE 'reported_by'");
        if ($c && $c->num_rows===0) $conn->query("ALTER TABLE nm_threats ADD COLUMN reported_by VARCHAR(200) DEFAULT NULL");
        // Seed DNS detection ON + the starter patterns when the setting is absent OR empty (so it shows
        // in the UI on EVERY install — not just fresh ones — since the DB/settings never travel with an
        // update). Never clobbers a setting that already holds a real (non-empty) operator value.
        try {
            $seed = function($k,$v) use($conn){
                $q=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1");
                $cur = ($q && ($x=$q->fetch_row())) ? trim((string)$x[0]) : null;
                if ($cur !== null && $cur !== '') return;   // real value already present → keep it
                $st=$conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?)
                                    ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
                $st->bind_param('ss',$k,$v); $st->execute(); $st->close();
            };
            $seed('imm_detect_dns','1');
            $seed('imm_dns_patterns', NM_IMM_DEFAULT_DNS_PATTERNS);
        } catch (\Throwable $e) {}
    }

    function nm_imm_setting($conn,$k,$d){ $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; }

    function nm_imm_get($conn,int $id){ $r=$conn->query("SELECT * FROM nm_threats WHERE id=".(int)$id." LIMIT 1"); return $r?$r->fetch_assoc():null; }

    // Register an indicator (dedup). Returns ['id','new'=>bool].
    function nm_imm_add_threat($conn, string $indicator, string $type='domain', string $source='manual', string $severity='high', string $detail='', ?int $uid=null, string $reportedBy=''): array {
        nm_imm_ensure($conn);
        $indicator = trim($indicator);
        $type = in_array($type,['domain','regex','ip'],true)?$type:'domain';
        if ($indicator==='') return ['ok'=>false,'error'=>'empty indicator'];
        // False-positive guard: never AUTO-flag a known-good domain (CDN / cloud / OS-app
        // vendor / streaming / game). Manual adds are exempt — the operator chose deliberately.
        if ($type==='domain' && $source!=='manual' && nm_imm_is_safe_domain($conn,$indicator)) {
            return ['ok'=>true,'new'=>false,'skipped'=>'allowlisted'];
        }
        $reportedBy = substr(trim($reportedBy),0,200);
        $ex = $conn->prepare("SELECT id FROM nm_threats WHERE indicator=? AND ind_type=? LIMIT 1");
        $ex->bind_param('ss',$indicator,$type); $ex->execute();
        if ($row=$ex->get_result()->fetch_assoc()) {
            $id=(int)$row['id'];
            if ($reportedBy!=='') { $u=$conn->prepare("UPDATE nm_threats SET hits=hits+1, last_seen=NOW(), reported_by=? WHERE id=?"); $u->bind_param('si',$reportedBy,$id); $u->execute(); }
            else $conn->query("UPDATE nm_threats SET hits=hits+1, last_seen=NOW() WHERE id={$id}");
            return ['ok'=>true,'id'=>$id,'new'=>false];
        }
        $st=$conn->prepare("INSERT INTO nm_threats (indicator,ind_type,severity,source,detail,reported_by,hits,status,first_seen,last_seen,created_by)
                            VALUES (?,?,?,?,?,?,1,'pending',NOW(),NOW(),?)");
        $st->bind_param('ssssssi',$indicator,$type,$severity,$source,$detail,$reportedBy,$uid);
        $st->execute(); return ['ok'=>true,'id'=>$conn->insert_id,'new'=>true];
    }

    function nm_imm_log_action($conn,$tid,$ttype,$tid2,$tname,$status,$detail){
        try {   // best-effort audit row — must NEVER abort the live SSH fan-out (mysqli throws in exception mode)
            $st=$conn->prepare("INSERT INTO nm_threat_actions (threat_id,target_type,target_id,target_name,status,detail) VALUES (?,?,?,?,?,?)");
            $tn=substr((string)$tname,0,120); $d=substr((string)$detail,0,300);   // fit VARCHAR(120)/(…) — a long device name would else throw "Data too long"
            $st->bind_param('isisss',$tid,$ttype,$tid2,$tn,$status,$d); $st->execute(); $st->close();
        } catch (\Throwable $e) {}
    }

    // Firewall enforcement targets = the Config-Manager devices the user designates.
    function nm_imm_firewall_targets($conn): array {
        $ids = array_filter(array_map('intval', explode(',', (string)nm_imm_setting($conn,'imm_fw_device_ids',''))));
        if (!$ids) return [];
        $in = implode(',', $ids);
        $out=[]; $r=$conn->query("SELECT id,name,host_ip,vendor_key,ssh_cred_id FROM nm_config_devices WHERE id IN ({$in})");
        while($r&&$x=$r->fetch_assoc()) $out[]=$x;
        return $out;
    }

    // Per-brand firewall block/unblock command (always prints NEURU_OK so the SSH
    // primitive sees non-empty output even when the rule command is silent).
    function nm_imm_fw_cmd(string $vendor, string $ip, bool $remove): string {
        $ip = preg_replace('/[^0-9a-fA-F.:\/]/','',$ip);
        if ($vendor === 'mikrotik') {
            return $remove
              ? ':do { /ip/firewall/address-list/remove [find where list=NEURU-BLOCK and address='.$ip.'] } on-error={}; :put NEURU_OK'
              : ':do { /ip/firewall/address-list/add list=NEURU-BLOCK address='.$ip.' comment=NEURU } on-error={}; :put NEURU_OK';
        }
        // linux / generic — iptables (idempotent)
        return $remove
          ? 'iptables -D INPUT -s '.$ip.' -j DROP 2>/dev/null; echo NEURU_OK'
          : '(iptables -C INPUT -s '.$ip.' -j DROP 2>/dev/null || iptables -I INPUT -s '.$ip.' -j DROP) ; echo NEURU_OK';
    }

    function nm_imm_push_firewall($conn, array $dev, string $ip, bool $remove=false): array {
        $ssh = nm_cm_resolve_ssh($conn, $dev);
        if (!$ssh) return ['ok'=>false,'detail'=>'no SSH credential'];
        $cmd = nm_imm_fw_cmd((string)$dev['vendor_key'], $ip, $remove);
        $res = nm_cm_ssh_fetch($ssh, $cmd, 25);
        $out = (string)($res['config'] ?? '');
        $ok  = strpos($out,'NEURU_OK')!==false;
        return ['ok'=>$ok, 'detail'=> $ok ? trim(str_replace('NEURU_OK','',$out)) ?: 'applied' : ($res['error'] ?? 'failed')];
    }

    // ── The vaccine: distribute the block to every Pi-hole / firewall ────────
    function nm_imm_vaccinate($conn, int $threatId, bool $notify = true): array {
        nm_imm_ensure($conn);
        $t = nm_imm_get($conn,$threatId); if(!$t) return ['ok'=>false,'error'=>'Threat not found'];
        $conn->query("DELETE FROM nm_threat_actions WHERE threat_id={$threatId}");
        $type=$t['ind_type']; $ind=$t['indicator']; $okc=0;$failc=0;
        if ($type==='domain' || $type==='regex') {
            $kind = $type==='regex'?'regex':'exact';
            foreach (nm_ph_servers($conn,true) as $S) {
                $r = nm_ph_add_deny($conn,(int)$S['id'],$ind,$kind,'NEURU immunity ['.$t['source'].']');
                $stt = $r['ok'] ? (($r['existed']??false)?'existed':'ok') : 'failed';
                nm_imm_log_action($conn,$threatId,'pihole',(int)$S['id'],$S['name'],$stt, $r['ok']?'deny added':($r['error']??''));
                if($r['ok'])$okc++; else $failc++;
            }
            foreach (nm_ag_servers($conn,true) as $S) {   // AdGuard Home — same domain block, as a user-rule
                $r = nm_ag_add_deny($conn,(int)$S['id'],$ind,$kind,'NEURU immunity ['.$t['source'].']');
                $stt = $r['ok'] ? (($r['existed']??false)?'existed':'ok') : 'failed';
                nm_imm_log_action($conn,$threatId,'adguard',(int)$S['id'],$S['name'],$stt, $r['ok']?'rule added':($r['error']??''));
                if($r['ok'])$okc++; else $failc++;
            }
        } else { // ip → firewalls
            foreach (nm_imm_firewall_targets($conn) as $dev) {
                $r = nm_imm_push_firewall($conn,$dev,$ind,false);
                nm_imm_log_action($conn,$threatId,'firewall',(int)$dev['id'],$dev['name'], $r['ok']?'ok':'failed', $r['detail']??'');
                if($r['ok'])$okc++; else $failc++;
            }
        }
        try { $conn->query("UPDATE nm_threats SET status='active', distributed_ok={$okc}, distributed_fail={$failc}, vaccinated_at=NOW() WHERE id={$threatId}"); } catch (\Throwable $e) {}
        try { nm_audit($conn,'immunity.vaccinate',['target_type'=>'threat','target_id'=>$threatId,'details'=>['indicator'=>$ind,'type'=>$type,'ok'=>$okc,'fail'=>$failc]]); } catch (\Throwable $e) {}
        // Notification Center: an AUTOMATIC fleet-wide block is a security event worth paging.
        // Manual vaccinations from the console pass $notify=false — the operator just did it,
        // so there's no need to alert them (and a bulk manual run would spam one msg per threat).
        if ($notify && !function_exists('nm_notify_event')) { @include_once __DIR__.'/nm_notify.php'; }
        if ($notify && function_exists('nm_notify_event')) {
            $sev = (($t['severity']??'')==='high') ? 'critical' : 'warning';
            @nm_notify_event($conn,'security',$sev,"Threat blocked fleet-wide: {$ind}",
                "Type {$type} · distributed to {$okc} node(s)".($failc?" · {$failc} failed":"")." · source ".($t['source']??'manual'),
                ['entity'=>$ind,'source'=>'immunity']);
        }
        return ['ok'=>true,'distributed'=>$okc,'failed'=>$failc];
    }

    // Pull the block back everywhere.
    function nm_imm_revoke($conn, int $threatId): array {
        $t = nm_imm_get($conn,$threatId); if(!$t) return ['ok'=>false,'error'=>'Threat not found'];
        $type=$t['ind_type']; $ind=$t['indicator'];
        if ($type==='domain' || $type==='regex') {
            $kind = $type==='regex'?'regex':'exact';
            foreach (nm_ph_servers($conn,true) as $S) { try { nm_ph_remove_deny($conn,(int)$S['id'],$ind,$kind); } catch (\Throwable $e) {} }
            foreach (nm_ag_servers($conn,true) as $S) { try { nm_ag_remove_deny($conn,(int)$S['id'],$ind,$kind); } catch (\Throwable $e) {} }
        } else {
            foreach (nm_imm_firewall_targets($conn) as $dev) { try { nm_imm_push_firewall($conn,$dev,$ind,true); } catch (\Throwable $e) {} }
        }
        // always mark it revoked even if a target was unreachable (never leave it stuck 'active')
        try { $conn->query("DELETE FROM nm_threat_actions WHERE threat_id={$threatId}"); } catch (\Throwable $e) {}
        try { $conn->query("UPDATE nm_threats SET status='revoked', distributed_ok=0, distributed_fail=0 WHERE id={$threatId}"); } catch (\Throwable $e) {}
        try { nm_audit($conn,'immunity.revoke',['target_type'=>'threat','target_id'=>$threatId,'details'=>['indicator'=>$ind]]); } catch (\Throwable $e) {}
        return ['ok'=>true];
    }

    function nm_imm_set_status($conn,int $threatId,string $status){
        $status = in_array($status,['pending','dismissed','active'],true)?$status:'pending';
        $st=$conn->prepare("UPDATE nm_threats SET status=? WHERE id=?"); $st->bind_param('si',$status,$threatId); $st->execute();
    }

    function nm_imm_list($conn): array {
        nm_imm_ensure($conn);
        // PENDING first: they're the actionable ones (need vaccination). With active accumulating past
        // the row cap, an active-first order silently pushed every pending threat off the end of the
        // LIMIT → the list + "Pending" filter showed 0 despite many awaiting review. Cap raised too.
        $rows=[]; $r=$conn->query("SELECT * FROM nm_threats ORDER BY FIELD(status,'pending','active','revoked','dismissed'), last_seen DESC LIMIT 1000");
        while($r&&$x=$r->fetch_assoc()) $rows[]=$x;
        return $rows;
    }
    function nm_imm_actions($conn,int $threatId): array {
        $rows=[]; $st=$conn->prepare("SELECT * FROM nm_threat_actions WHERE threat_id=? ORDER BY id DESC LIMIT 100");
        $st->bind_param('i',$threatId); $st->execute(); $r=$st->get_result(); while($x=$r->fetch_assoc()) $rows[]=$x;
        return $rows;
    }
    function nm_imm_counts($conn): array {
        nm_imm_ensure($conn);
        $o=['active'=>0,'pending'=>0]; $r=$conn->query("SELECT status,COUNT(*) c FROM nm_threats WHERE status IN('active','pending') GROUP BY status");
        while($r&&$x=$r->fetch_assoc()) $o[$x['status']]=(int)$x['c'];
        return $o;
    }

    // ── Detection: port scans from syslog ────────────────────────────────────
    // Looks at recent firewall-style drop/deny syslog lines, extracts src→dst:port
    // and flags a source IP that hit many distinct destination ports.
    function nm_imm_detect_portscan($conn): array {
        $win  = (int)nm_imm_setting($conn,'imm_portscan_window','10') ?: 10;
        $minP = (int)nm_imm_setting($conn,'imm_portscan_ports','10') ?: 10;
        $found=[];
        if (!$conn->query("SHOW TABLES LIKE 'nm_syslog'")->num_rows) return $found;
        $r=$conn->query("SELECT hostname, host_ip, message FROM nm_syslog WHERE received_at>=DATE_SUB(NOW(),INTERVAL {$win} MINUTE)
            AND (message LIKE '%drop%' OR message LIKE '%deny%' OR message LIKE '%DROP%' OR message LIKE '%reject%') LIMIT 20000");
        $map=[]; $rep=[]; $tgt=[]; // src ip → set of dst ports / reporting devices / targets
        while($r&&$x=$r->fetch_assoc()){
            if (preg_match('/(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s*->\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d+)/', $x['message'], $m)) {
                $src=$m[1]; $map[$src][$m[4]]=1; $tgt[$src][$m[3]]=1;
                $h=trim((string)$x['hostname']); $hip=trim((string)$x['host_ip']);
                // label as "hostname (ip)" so it's unambiguous which device — and so the
                // enforcement-point cross-check can match on either the name or the IP.
                $dev = $h!=='' ? ($hip!=='' && stripos($h,$hip)===false ? $h.' ('.$hip.')' : $h) : $hip;
                if($dev!==''){ $rep[$src][$dev]=($rep[$src][$dev]??0)+1; }
            }
        }
        foreach($map as $src=>$ports){
            if (count($ports) < $minP) continue;
            $devs=$rep[$src]??[]; arsort($devs); $devList=array_slice(array_keys($devs),0,3);
            $found[] = ['ip'=>$src,'ports'=>count($ports),
                'reported_by'=>implode(', ',$devList),
                'target'=>$tgt[$src]?array_key_first($tgt[$src]):''];
        }
        return $found;
    }

    // ── Safe-domain allowlist (false-positive guard) ─────────────────────────
    // Curated "never a threat" domains — major CDNs, cloud, OS/app vendors, streaming
    // and game platforms. AUTOMATIC DNS-threat detection skips these, so a legit domain
    // (Amazon Prime Video, Apple, Microsoft, a game CDN…) can never be auto-blocked.
    // Users extend the list via the imm_dns_allowlist setting. MANUAL blocks bypass this
    // (a deliberate operator choice — you can still block a specific subdomain by hand).
    function nm_imm_safe_domains_default(): array {
        return [
            'amazonaws.com','amazon.com','media-amazon.com','ssl-images-amazon.com','pv-cdn.net','aiv-cdn.net','aiv-delivery.net','primevideo.com','cloudfront.net',
            'apple.com','icloud.com','apple-dns.net','mzstatic.com','cdn-apple.com','push.apple.com',
            'microsoft.com','windows.com','windowsupdate.com','office.com','office365.com','live.com','azure.com','azureedge.net','azurefd.net','msftncsi.com','msftconnecttest.com','msedge.net','microsoftonline.com','xboxlive.com','xbox.com','skype.com',
            'google.com','googleapis.com','gstatic.com','googleusercontent.com','ggpht.com','gvt1.com','gvt2.com','gvt3.com','googlevideo.com','youtube.com','ytimg.com','android.com',
            'cloudflare.com','cloudflare.net','cloudflare-dns.com','cloudflareinsights.com',
            'akamai.net','akamaized.net','akamaiedge.net','akamaihd.net','edgesuite.net','edgekey.net',
            'fastly.net','fastlylb.net','fbcdn.net','facebook.com','instagram.com','whatsapp.net','whatsapp.com',
            'netflix.com','nflxvideo.net','nflximg.net','nflxext.com','nflxso.net',
            'spotify.com','scdn.co','spotifycdn.com','twitch.tv','ttvnw.net','jtvnw.net',
            'github.com','githubusercontent.com','githubassets.com',
            'steampowered.com','steamcontent.com','steamstatic.com','steamserver.net','epicgames.com','unrealengine.com','ea.com','riotgames.com','riotcdn.net','battle.net','blizzard.com','playstation.net','playstation.com','nvidia.com','geforce.com','nvidiagrid.net','ubisoft.com','ubi.com','discord.com','discordapp.com','discord.gg',
        ];
    }
    // True if $domain equals, or is a subdomain of, an allowlisted safe domain
    // (built-in defaults + the user's imm_dns_allowlist, one entry per line/comma).
    function nm_imm_is_safe_domain($conn, string $domain): bool {
        $domain = strtolower(trim($domain));
        if ($domain === '') return false;
        $safe = nm_imm_safe_domains_default();
        $user = trim((string)nm_imm_setting($conn,'imm_dns_allowlist',''));
        if ($user !== '') foreach (preg_split('/[\r\n,]+/',$user) as $u) { $u=strtolower(trim($u)); if($u!=='' && $u[0]!=='#') $safe[]=ltrim($u,'.'); }
        foreach ($safe as $s) { $s=ltrim(strtolower(trim($s)),'.'); if($s==='') continue;
            if ($domain === $s || substr($domain, -(strlen($s)+1)) === '.'.$s) return true;
        }
        return false;
    }

    // ── Detection: malicious DNS from a Pi-hole's recent queries ──────────────
    // Matches queried domains against the admin's threat regex list (one per line).
    // Known-good domains (nm_imm_is_safe_domain) are skipped so a broad pattern can't
    // pull in a legit CDN/vendor. Returns [domain => the pattern that matched].
    // Scan the query logs of EVERY enabled Pi-hole AND AdGuard Home for domains matching the threat
    // patterns. (Was Pi-hole-only before → AdGuard-only installs detected nothing.) Domains are deduped
    // across all servers so the safe-domain check + regex run once per unique domain.
    function nm_imm_detect_dns($conn): array {
        $raw = trim((string)nm_imm_setting($conn,'imm_dns_patterns',''));
        if ($raw==='') $raw = defined('NM_IMM_DEFAULT_DNS_PATTERNS') ? NM_IMM_DEFAULT_DNS_PATTERNS : '';
        if ($raw==='') return [];
        $rx=[]; foreach(preg_split('/\r?\n/',$raw) as $p){ $p=trim($p); if($p===''||$p[0]==='#') continue;
            $r='~'.str_replace('~','\~',$p).'~i'; if(@preg_match($r,'')!==false) $rx[$r]=$p; }
        if (!$rx) return [];

        $domains=[];   // unique lowercased queried domains across all DNS servers
        // ── Pi-hole(s) — recent queries ──
        if (function_exists('nm_ph_servers')) foreach (nm_ph_servers($conn,true) as $S) {
            try { $q=nm_ph_call($conn,(int)$S['id'],'queries',['length'=>2000]);
                  if (!empty($q['ok'])) foreach (($q['data']['queries'] ?? []) as $qr) {
                      $d=strtolower(trim((string)($qr['domain'] ?? ''))); if($d!=='') $domains[$d]=1; } }
            catch (\Throwable $e) {}
        }
        // ── AdGuard Home(s) — recent query log (question.name, any reason) ──
        if (function_exists('nm_ag_servers')) foreach (nm_ag_servers($conn,true) as $S) {
            try { $q=nm_ag_call($conn,(int)$S['id'],'querylog',['limit'=>2000]);
                  if (!empty($q['ok'])) foreach (($q['data']['data'] ?? []) as $qr) {
                      $d=strtolower(trim((string)($qr['question']['name'] ?? ''))); if($d!=='') $domains[$d]=1; } }
            catch (\Throwable $e) {}
        }

        $hit=[];
        foreach (array_keys($domains) as $dom) {
            if (nm_imm_is_safe_domain($conn,$dom)) continue;   // never flag a known-good domain
            foreach ($rx as $r=>$p) { if (@preg_match($r,$dom)) { $hit[$dom]=$p; break; } }
        }
        return $hit;   // [domain => matched pattern]
    }
}
