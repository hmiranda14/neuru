<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Router Commander shared flow engine. AI-over-SSH troubleshooting for
// network devices AND linux boxes, modeled on the container Solution Commander
// (nm_fixflow.php) but with a TRANSPORT SPLIT:
//
//   AI reasoning  (modes suggest/chat/auto/explain)  → rc_suggest_url   (n8n AI)
//   EXECUTE a command (mode command) — ALL transports SSH directly from the portal
//   (nm_cm_ssh_fetch); n8n never touches device SSH, it only does the AI reasoning:
//     · transport='linux' → bash over SSH IN THE PORTAL (nm_rc_exec_linux)
//     · transport='windows' → PowerShell over SSH IN THE PORTAL (nm_rc_exec_windows)
//     · transport='cli'   → PYTHON paramiko IN THE PORTAL (nm_cm_ssh_fetch →
//                           scripts/nm_ssh_fetch.py, brand-aware), then loops the
//                           AI locally. n8n NEVER touches the router SSH — that is
//                           the whole point (n8n's SSH node only speaks bash).
//
// The KB/RAG (nm_solutionkb.php → container_kb) is SHARED with Containers; router
// sessions are captured with source='router'. n8n callbacks land in nm_router_api.php.
// Page gate = permission key 'router_commander'.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_n8n.php';
require_once __DIR__ . '/nm_secrets.php';
require_once __DIR__ . '/nm_solutionkb.php';
require_once __DIR__ . '/nm_confmgr.php';   // vendors + nm_cm_ssh_fetch (Python SSH)
require_once __DIR__ . '/nm_audit.php';

if (!function_exists('nm_rc_send')) {

    // ── Schema + perm seed ───────────────────────────────────────────────────
    function nm_rc_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        static $done = false; if ($done) return; $done = true;
        $conn->query("CREATE TABLE IF NOT EXISTS nm_rc_sessions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            target_kind VARCHAR(12) NOT NULL DEFAULT 'manual',
            target_ref INT DEFAULT NULL,
            name VARCHAR(120) NOT NULL DEFAULT '',
            host VARCHAR(64) NOT NULL DEFAULT '',
            vendor_key VARCHAR(40) NOT NULL DEFAULT 'generic',
            transport VARCHAR(8) NOT NULL DEFAULT 'cli',
            ssh_cred_id INT DEFAULT NULL,
            title VARCHAR(255) NOT NULL DEFAULT '',
            problem TEXT NULL,
            status VARCHAR(16) NOT NULL DEFAULT 'open',
            kb_id INT DEFAULT NULL,
            created_by INT DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            KEY idx_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_rc_logs (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            session_id INT NOT NULL,
            level VARCHAR(16) NOT NULL DEFAULT 'info',
            line MEDIUMTEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            KEY idx_sess (session_id, id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        // Make sure the admin role can reach the page (idempotent).
        @$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled)
            SELECT 'admin','router_commander',1 FROM DUAL
            WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='router_commander')");
    }

    // ── Small helpers ────────────────────────────────────────────────────────
    function nm_rc_setting($conn,$k,$d=''){ $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; }
    function nm_rc_session($conn,$id){ $r=$conn->query("SELECT * FROM nm_rc_sessions WHERE id=".(int)$id." LIMIT 1"); return $r?$r->fetch_assoc():null; }
    function nm_rc_base(){ return ((!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http').'://'.(($_SERVER['HTTP_HOST']??'')?:'localhost'); }
    function nm_rc_log($conn,$id,$level,$line){ $st=$conn->prepare("INSERT INTO nm_rc_logs(session_id,level,line) VALUES(?,?,?)"); $st->bind_param('iss',$id,$level,$line); $st->execute(); }

    // Derive the default transport from a vendor: linux/generic → n8n bash; every
    // network OS → Python CLI. The session may override this at creation.
    function nm_rc_auto_transport(string $vendor_key): string {
        if ($vendor_key === 'windows') return 'windows';   // PowerShell over SSH, run in the portal
        return in_array($vendor_key, ['linux','generic'], true) ? 'linux' : 'cli';
    }

    // Resolve the SSH credential bound to a session (ssh_cred_id, else default).
    function _nm_rc_ssh_from_cred(array $cred, string $host): array {
        $secret = nm_secret_decrypt($cred['secret_enc']);
        $out = ['host'=>$host, 'port'=>(int)($cred['port'] ?: 22) ?: 22,
                'username'=>$cred['username'], 'auth_type'=>$cred['auth_type'], 'cred_name'=>$cred['name']];
        if ($cred['auth_type'] === 'key') $out['private_key'] = $secret; else $out['password'] = $secret;
        return $out;
    }
    // Resolve SSH creds for a session, trying (in order): the session's explicit cred →
    // the TARGET NODE's assigned credential (the same mapping the rest of the portal uses,
    // so a node with a cred just works even if the session was created without one) →
    // the global default credential. Returns null only if none of those exist.
    function nm_rc_resolve_ssh($conn, array $sess): ?array {
        $host = (string)($sess['host'] ?? '');
        $cid  = (int)($sess['ssh_cred_id'] ?? 0);
        if ($cid) {
            $cr = $conn->query("SELECT * FROM nm_ssh_credentials WHERE id={$cid} LIMIT 1");
            if ($cr && ($cred = $cr->fetch_assoc())) return _nm_rc_ssh_from_cred($cred, $host);
        }
        // fall back to the node's assigned SSH credential (covers sessions created with no cred)
        if (($sess['target_kind'] ?? '') === 'node' && (int)($sess['target_ref'] ?? 0) && function_exists('nm_ssh_resolve')) {
            $r = nm_ssh_resolve($conn, (int)$sess['target_ref']);
            if ($r) { if ($host !== '') $r['host'] = $host; return $r; }
        }
        // last resort: an explicit global default credential
        $cr = $conn->query("SELECT * FROM nm_ssh_credentials WHERE is_default=1 ORDER BY id LIMIT 1");
        if ($cr && ($cred = $cr->fetch_assoc())) return _nm_rc_ssh_from_cred($cred, $host);
        return null;
    }

    // Conversation transcript for the AI (exclude control rows). Last 120, cap 12k.
    function nm_rc_transcript($conn,$id){
        $r=$conn->query("SELECT level,line FROM nm_rc_logs WHERE session_id=".(int)$id." AND level NOT IN ('proposal','proposal-ack','divider') ORDER BY id DESC LIMIT 120");
        $rows=$r?array_reverse($r->fetch_all(MYSQLI_ASSOC)):[]; $out='';
        foreach($rows as $x){ $l=$x['level']; $t=$x['line'];
            if($l==='user') $out.="User: $t\n"; elseif($l==='ai') $out.="Assistant: $t\n";
            elseif($l==='cmd') $out.="$t\n"; elseif($l==='out') $out.="$t\n";
            elseif($l==='error') $out.="ERROR: $t\n"; elseif($l==='done') $out.="Result: $t\n"; else $out.="(info) $t\n"; }
        return substr($out, -12000);
    }

    // ── Destructive-command risk assessment ──────────────────────────────────
    // Static, brand-aware heuristic. Returns severity safe|caution|destructive +
    // human reasons + what it could affect. Used to gate approval and to power the
    // local half of the "Explain" dry-run (the AI gives the deep explanation).
    function nm_rc_risk_assess(string $cmd, string $vendor_key): array {
        $c = strtolower(trim($cmd));
        $isWindows = ($vendor_key === 'windows');
        $isRouter = !$isWindows && !in_array($vendor_key, ['linux','generic'], true);
        $reasons = []; $affects = [];

        // PowerShell / Windows destructive patterns
        $windows = [
            '/\bremove-item\b.*-recurse|\brmdir\b|(^|\s)\bdel\b\s|(^|\s)\berase\b\s/' => ['Deleting files/folders', 'Files — irreversible loss'],
            '/\bformat-volume\b|\bclear-disk\b|\bclear-volume\b|\bremove-partition\b|\bdiskpart\b/' => ['Formatting / clearing a disk or volume', 'All data on that disk'],
            '/\b(stop-computer|restart-computer)\b|\bshutdown\b\s|\bdoexit\b/' => ['Powering off / rebooting the PC', 'Full outage of the machine'],
            '/\bremove-(service|localuser|localgroup|aduser|adgroup|item)\b/' => ['Removing a service / user / object', 'Access or service loss'],
            '/\b(uninstall|disable)-\w+/' => ['Uninstalling / disabling a feature', 'Feature or service availability'],
            '/\breg\s+delete\b|\bremove-itemproperty\b|(set|new)-itemproperty\b.*hk(lm|cu)/' => ['Writing / removing registry keys', 'System config — can break Windows'],
            '/\bset-netfirewallprofile\b.*-enabled\s+false|\bnetsh\s+advfirewall\s+(reset|set\s+allprofiles\s+state\s+off)/' => ['Disabling / resetting the firewall', 'Security & your own SSH session'],
            '/\b(stop-process)\b.*-force|\btaskkill\b.*\/f/' => ['Force-killing processes', 'Running apps — possible data loss'],
            '/\bset-executionpolicy\b|\bbcdedit\b|\bcipher\s+\/w/' => ['Changing execution policy / boot config / secure-wipe', 'Security or boot integrity'],
        ];

        $linux = [
            '/\brm\s+(-\w*[rf]\w*)\b/'                 => ['Recursive/forced file deletion (rm -rf)', 'Files — irreversible loss'],
            '/\bmkfs(\.\w+)?\b/'                       => ['Formatting a filesystem (mkfs)', 'All data on that device'],
            '/\bdd\b.*\bof=\/dev\//'                   => ['Raw write to a block device (dd of=/dev/…)', 'Disk/OS — can brick the box'],
            '/>\s*\/dev\/(sd|nvme|vd|xvd)/'            => ['Overwriting a block device', 'Disk contents'],
            '/\b(shutdown|poweroff|halt)\b|\binit\s+0\b/' => ['Powering off the host', 'Full service/connectivity loss'],
            '/\breboot\b/'                             => ['Rebooting the host', 'Temporary outage of everything on it'],
            '/:\s*\(\)\s*\{.*\}\s*;?\s*:/'             => ['Fork bomb', 'CPU/RAM exhaustion — host hang'],
            '/\b(iptables|ip6tables)\s+-f\b|\bnft\s+flush\b/' => ['Flushing ALL firewall rules', 'Network security & your own SSH session'],
            '/\buserdel\b|\bgroupdel\b/'               => ['Deleting a user/group', 'Access & file ownership'],
            '/\bchmod\s+-r\s+777\b/'                   => ['World-writable recursive permissions', 'Security exposure'],
            '/\bdrop\s+(database|table|schema)\b/'     => ['Dropping a database/table', 'Persistent data loss'],
            '/\bsystemctl\s+(stop|disable|mask)\b/'    => ['Stopping/disabling a service', 'Service availability'],
            '/\b(shred|truncate)\b/'                   => ['Destroying file contents', 'Data loss'],
            '/\bmv\s+\/\s|\brm\s+-\w*\s+\/\s*$/'       => ['Operating on / (root)', 'Entire filesystem'],
        ];
        $router = [
            '/\b(reload|reboot)\b/'                            => ['Rebooting the device', 'Outage for everything behind it'],
            '/\b(write\s+erase|erase\s+(startup|nvram|flash)|delete\s+flash|format\s+flash)\b/' => ['Erasing config/flash', 'Full config loss — may not recover'],
            '/system\s+reset-configuration|\/system\s+reset|factory-reset|request\s+system\s+zeroize/' => ['Factory reset / zeroize', 'Wipes the ENTIRE configuration'],
            '/\bshutdown\b/'                                   => ['Shutting an interface down', 'Link drops — possible self-lockout'],
            '/\bno\s+(interface|ip\s+route|router\s|ip\s+access|spanning-tree|vlan)\b/' => ['Negating a config stanza (no …)', 'Routing/switching/connectivity'],
            '/\bremove\b/'                                     => ['Removing config objects (RouterOS)', 'May drop interfaces/routes/firewall'],
            '/\b(clear\s+ip\s+route|clear\s+arp|clear\s+config|clear\s+ip\s+nat)\b/' => ['Clearing routing/ARP/NAT/config', 'Transient or persistent outage'],
            '/\bdelete\b/'                                     => ['Deleting config (JunOS/RouterOS)', 'Config stanza removal'],
            '/\bdisable\b/'                                    => ['Disabling an object', 'Feature/interface availability'],
        ];
        $rules = $isWindows ? $windows : ($isRouter ? $router : $linux);
        foreach ($rules as $rx => $meta) {
            if (preg_match($rx, $c)) { $reasons[] = $meta[0]; $affects[] = $meta[1]; }
        }
        if ($reasons) {
            return ['severity'=>'destructive','risky'=>true,
                    'reasons'=>array_values(array_unique($reasons)),
                    'affects'=>array_values(array_unique($affects))];
        }
        // Caution = writes/changes state but not catastrophic.
        $cautionRx = $isWindows
            ? '/\b(set|new|add|start|stop|restart|enable|install|copy|move|rename|clear)-\w+|\b(start|stop|restart)-service\b|\bnetsh\b|\breg\s+add\b|\bsc\s+(config|start|stop)\b/'
            : ($isRouter
            ? '/\b(set|add|commit|copy\s+run|write\s+mem|write\s+memory|save|enable\b)\b/'
            : '/(>|>>)\s|\btee\b|\bsed\s+-i\b|\bcp\s|\bmv\s|\b(apt|apt-get|yum|dnf|pip3?|npm)\s+(install|remove|purge)|\bsystemctl\s+restart\b|\bkill(all)?\b/');
        if (preg_match($cautionRx, $c)) {
            return ['severity'=>'caution','risky'=>false,
                    'reasons'=>['Modifies state/config — not read-only'],
                    'affects'=>['Persisted configuration or running services']];
        }
        return ['severity'=>'safe','risky'=>false,'reasons'=>[],'affects'=>[]];
    }

    // ── The core dispatcher ──────────────────────────────────────────────────
    // mode suggest|chat|auto|explain → rc_suggest_url (AI).
    // mode command → all transports SSH directly from the portal (cli/windows/linux);
    // n8n is used ONLY for AI modes (suggest/chat/auto/explain) via rc_suggest_url.
    function nm_rc_send($conn, array $sess, array $extra){
        $mode = $extra['mode'] ?? 'suggest';
        $id   = (int)$sess['id'];

        // EXECUTE locally over SSH (nm_cm_ssh_fetch) — routers (CLI), Windows (PowerShell)
        // AND Linux (bash). No command transport goes through n8n anymore; only the AI does.
        $tp = $sess['transport'] ?? 'cli';
        if ($mode === 'command' && $tp === 'cli')     return nm_rc_exec_router($conn, $sess, (string)($extra['command'] ?? ''));
        if ($mode === 'command' && $tp === 'windows') return nm_rc_exec_windows($conn, $sess, (string)($extra['command'] ?? ''));
        if ($mode === 'command' && $tp === 'linux')   return nm_rc_exec_linux($conn, $sess, (string)($extra['command'] ?? ''));

        $isAi = in_array($mode, ['suggest','chat','auto','explain'], true);
        $url  = $isAi ? nm_rc_setting($conn,'rc_suggest_url','') : nm_rc_setting($conn,'rc_execute_url','');
        if ($url === '' || !function_exists('curl_init')) return ['ok'=>false,'err'=>($isAi?'rc_suggest_url':'rc_execute_url').' not configured'];

        $cfg  = nm_n8n_get($conn);
        $base = function_exists('nm_n8n_callback_base') ? nm_n8n_callback_base($conn, $url) : nm_rc_base();  // per-flow: hosted→tunnel, local→LAN
        $vendor = nm_cm_vendor($conn, (string)$sess['vendor_key']) ?: ['label'=>$sess['vendor_key'],'command'=>''];
        $ssh  = nm_rc_resolve_ssh($conn, $sess) ?: [];

        $payload = array_merge([
            'session_id'   => 'rc-'.$id,
            'rc_id'        => $id,
            'name'         => $sess['name'],
            'host'         => $sess['host'],
            'vendor_key'   => $sess['vendor_key'],
            'vendor_label' => $vendor['label'] ?? $sess['vendor_key'],
            'device_kind'  => ($sess['transport']==='windows' ? 'windows' : ($sess['transport']==='linux' ? 'linux' : 'router')),
            'transport'    => $sess['transport'],
            'cli_prelude'  => $vendor['command'] ?? '',   // e.g. "terminal length 0" hint
            'problem'      => $sess['problem'],
            // SSH creds (used by the linux execute webhook; harmless context otherwise)
            'ssh'          => $ssh,
            'ssh_user'     => $ssh['username'] ?? '',
            'ssh_password' => $ssh['password'] ?? '',
            'ssh_host'     => $sess['host'],
            'ssh_port'     => $ssh['port'] ?? 22,
            // callbacks
            'log_url'      => $base.'/nm_router_api.php?ep=rc_log&id='.$id,
            'result_url'   => $base.'/nm_router_api.php?ep=rc_result&id='.$id,
            'proposal_url' => $base.'/nm_router_api.php?ep=rc_proposal&id='.$id,
            'continue_url' => $base.'/nm_router_api.php?ep=rc_continue&id='.$id,
        ], $extra);

        if ($isAi) {
            $payload['transcript'] = nm_rc_transcript($conn,$id);
            $kb = nm_kb_search($conn, ($sess['problem'].' '.($extra['message']??'')), ['container_name'=>$sess['name']]);
            $books = nm_kb_search_books($conn, (string)$sess['problem']);
            $payload['knowledge'] = $kb; $payload['knowledge_text'] = nm_kb_context($kb, $sess['name']);
            $payload['docs'] = $books; $payload['docs_text'] = nm_kb_docs_context($books);
            $payload['kb_search_url'] = nm_rc_setting($conn,'kb_search_url','');
        }

        if (function_exists('nm_n8n_neuru_stamp')) $payload = nm_n8n_neuru_stamp($conn, $payload, $url, ($isAi?'rc-suggest':'rc-exec'));  // hosted-flow gatecheck + per-flow model
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>json_encode($payload),
            CURLOPT_CONNECTTIMEOUT=>4, CURLOPT_TIMEOUT=>20, CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_SSL_VERIFYHOST=>false,
            CURLOPT_HTTPHEADER=>['Content-Type: application/json','X-NetMon-Token: '.$cfg['inbound_token']]]);
        curl_exec($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
        return ['ok'=>($code>=200&&$code<300),'err'=>($code>=200&&$code<300)?'':"Webhook HTTP {$code}"];
    }

    // ── Router transport: run the command locally via Python paramiko ─────────
    function nm_rc_exec_router($conn, array $sess, string $cmd){
        $id = (int)$sess['id'];
        $ssh = nm_rc_resolve_ssh($conn, $sess);
        if (!$ssh) { nm_rc_log($conn,$id,'error','No SSH credential resolved for this target.'); nm_rc_continue($conn,$id); return ['ok'=>false,'err'=>'no ssh cred']; }
        $res = nm_cm_ssh_fetch($ssh, $cmd, 35);   // brand-aware: single→exec, multi→shell
        if (!empty($res['ok'])) {
            $out = rtrim((string)$res['config']);
            nm_rc_log($conn,$id,'out', $out !== '' ? $out : '(command produced no output)');
        } else {
            nm_rc_log($conn,$id,'error','SSH error: '.($res['error'] ?? 'unknown'));
        }
        nm_rc_continue($conn,$id);   // loop the AI on the new output
        return ['ok'=>true];
    }

    // ── Windows transport: run the command as PowerShell over SSH, in the portal ──
    // Mirrors nm_rc_exec_router (n8n never SSHes the Windows box — only does the AI).
    function nm_rc_exec_windows($conn, array $sess, string $cmd){
        $id = (int)$sess['id'];
        $ssh = nm_rc_resolve_ssh($conn, $sess);
        if (!$ssh) { nm_rc_log($conn,$id,'error','No SSH credential resolved for this Windows host.'); nm_rc_continue($conn,$id); return ['ok'=>false,'err'=>'no ssh cred']; }
        // Windows OpenSSH default shell is cmd.exe → wrap as a PowerShell one-liner.
        $ps = 'powershell -NoProfile -NonInteractive -Command "' . str_replace('"','\"',trim($cmd)) . '"';
        $res = nm_cm_ssh_fetch($ssh, $ps, 35);
        if (!empty($res['ok'])) {
            $out = rtrim((string)$res['config']);
            nm_rc_log($conn,$id,'out', $out !== '' ? $out : '(command produced no output)');
        } else {
            nm_rc_log($conn,$id,'error','SSH error: '.($res['error'] ?? 'unknown'));
        }
        nm_rc_continue($conn,$id);
        return ['ok'=>true];
    }

    // ── Linux transport: run the command as bash over SSH, IN THE PORTAL ─────────
    // Was delegated to the n8n rc-exec webhook; doing it in-portal (same proven path as
    // routers/Windows via nm_cm_ssh_fetch) removes that dependency and its failure point.
    function nm_rc_exec_linux($conn, array $sess, string $cmd){
        $id = (int)$sess['id'];
        $ssh = nm_rc_resolve_ssh($conn, $sess);
        if (!$ssh) { nm_rc_log($conn,$id,'error','No SSH credential resolved for this Linux host (assign the node an SSH credential, or set a default in Config → Integrations & AI → SSH Credentials).'); nm_rc_continue($conn,$id); return ['ok'=>false,'err'=>'no ssh cred']; }
        $res = nm_cm_ssh_fetch($ssh, trim($cmd), 35);   // single→exec, multi→shell
        if (!empty($res['ok'])) {
            $out = rtrim((string)$res['config']);
            nm_rc_log($conn,$id,'out', $out !== '' ? $out : '(command produced no output)');
        } else {
            nm_rc_log($conn,$id,'error','SSH error: '.($res['error'] ?? 'unknown'));
        }
        nm_rc_continue($conn,$id);
        return ['ok'=>true];
    }

    // The last executed command and the output it produced (for the auto turn).
    function nm_rc_last_exchange($conn,$id){
        $r=$conn->query("SELECT id,line FROM nm_rc_logs WHERE session_id=".(int)$id." AND level='cmd' ORDER BY id DESC LIMIT 1");
        if(!$r || !($c=$r->fetch_assoc())) return null;
        $cid=(int)$c['id'];
        $o=$conn->query("SELECT line FROM nm_rc_logs WHERE session_id=".(int)$id." AND id>{$cid} AND level IN ('out','error') ORDER BY id ASC LIMIT 30");
        $out=[]; while($o && $x=$o->fetch_row()) $out[]=$x[0];
        return ['cmd'=>$c['line'], 'output'=>implode("\n",$out)];
    }

    // ── Auto-loop step: feed new output back to the AI. Caps at 40 commands. ──
    // We embed the just-run command + its output INTO the message (not just the
    // transcript) so the AI analyzes it even if the n8n flow doesn't wire the
    // transcript field through — and we forbid repeating the same command.
    function nm_rc_continue($conn,$id){
        $sess = nm_rc_session($conn,$id);
        if (!$sess) return ['ok'=>false,'error'=>'Session not found'];
        // Every command run this session (chronological) — for step budget + cycle detection.
        $all=[]; $ar=$conn->query("SELECT line FROM nm_rc_logs WHERE session_id=".(int)$id." AND level='cmd' ORDER BY id ASC");
        while($ar && $x=$ar->fetch_row()) { $c=trim((string)$x[0]); if($c!=='') $all[]=$c; }
        $n = count($all);

        // ── Loop / cycle detection ────────────────────────────────────────────
        // The old guard only caught the SAME command 3× in a row. Real loops cycle
        // through DIFFERENT commands (ping → curl → docker logs → ping → curl → …),
        // which slipped through. Now: normalize each command, count occurrences, and
        // treat it as looping if a multi-command cycle formed (≥2 commands repeated)
        // OR any command ran ≥3×. Also a much tighter step budget (was 40).
        $norm = function($c){ return preg_replace('/\s+/',' ', strtolower(trim((string)$c))); };
        $seen = [];
        foreach ($all as $c) { $k=$norm($c); $seen[$k]=($seen[$k]??0)+1; }
        $repeaters = count(array_filter($seen, fn($v)=>$v>=2));   // distinct commands run 2+ times
        $maxRepeat = $seen ? max($seen) : 0;
        $looping = ($n >= 5) && ($repeaters >= 2 || $maxRepeat >= 3);
        $hardCap = ($n >= 12);

        if ($looping || $hardCap) {
            $why = $hardCap ? "gathered {$n} commands of diagnostics" : "started re-running earlier commands (the read-only diagnosis is done)";
            nm_rc_log($conn,$id,'info','◆ Enough diagnosis — converging on the FIX ('.$why.').');
            $ranList = implode("\n", array_map(fn($c)=>'  • '.substr($c,0,120), array_slice(array_values(array_unique($all)),0,30)));
            // The whole point of a Solution Commander is to SOLVE — not to re-run diagnostics
            // forever, and NOT to surrender with a summary. When the read-only investigation has
            // enough data (or is looping), pivot to the FIX: name the root cause and propose the
            // concrete action(s) that resolve it, ready for the operator to approve.
            $msg = "You have enough diagnostic data — running the same commands again adds nothing.\n\n"
                 . "Diagnostics already gathered:\n{$ranList}\n\n"
                 . "Now SOLVE the operator's problem (\"".substr((string)$sess['problem'],0,300)."\"). You are a Solution Commander — resolving it is the job, not describing it. Reply with:\n"
                 . "1) ROOT CAUSE — one or two concrete sentences grounded in the outputs above.\n"
                 . "2) THE FIX — propose the exact command(s) or config change that resolves it, as the next command to run (the operator will approve/apply it). If it is a config edit, give the precise change and the command to apply + restart.\n"
                 . "Only if truly no fix exists (e.g. it is an external outage) say so plainly and give the workaround. Do NOT repeat any diagnostic command above.";
            $r = nm_rc_send($conn,$sess,['mode'=>'suggest','message'=>$msg]);
            return ['ok'=>($r['ok']??false),'paused'=>false,'concluded'=>true,'error'=>($r['err']??null)];
        }

        nm_rc_log($conn,$id,'info','AI is reviewing the command output…');
        $ex = nm_rc_last_exchange($conn,$id);
        $ranList = $all ? implode(' | ', array_slice(array_values(array_unique(array_map(fn($c)=>substr($c,0,70),$all))),-14)) : '';
        $msg = 'Review the command output above. If the issue is resolved, say so and stop. Otherwise propose the single next command.';
        if ($ex) {
            $out = substr((string)$ex['output'], 0, 4000);
            $msg = "The command you proposed just executed:\n\n{$ex['cmd']}\n\nIts actual output was:\n".($out!==''?$out:'(no output)')
                 . "\n\nAnalyze THIS output against the user's problem: \"".substr((string)$sess['problem'],0,300)."\".\n"
                 . "Commands ALREADY run this session — NEVER propose any of these again: ".($ranList!==''?$ranList:'(none)')."\n"
                 . "You are on step {$n} of ~10 — converge fast.\n"
                 . "• If the output already answers the problem, summarize the answer for the user and STOP — return NO command.\n"
                 . "• Otherwise propose ONE NEW command you have NOT run yet. Repeating a command above is forbidden.";
        }
        $r = nm_rc_send($conn,$sess,['mode'=>'auto','message'=>$msg]);
        return ['ok'=>$r['ok'],'paused'=>false,'error'=>$r['err'] ?: null];
    }

    // Build the KB resolution write-up from this session's commands + closing note.
    function nm_rc_build_resolution($conn,$id,$note=''){
        $parts = [];
        if (trim($note) !== '') $parts[] = trim($note);
        $r = $conn->query("SELECT line FROM nm_rc_logs WHERE session_id=".(int)$id." AND level='cmd' ORDER BY id LIMIT 40");
        $cmds = []; while($r && $x=$r->fetch_row()) $cmds[] = $x[0];
        if ($cmds) $parts[] = "Commands run:\n".implode("\n", $cmds);
        $d = $conn->query("SELECT line FROM nm_rc_logs WHERE session_id=".(int)$id." AND level='done' ORDER BY id DESC LIMIT 1");
        if ($d && $x=$d->fetch_row()) $parts[] = "Outcome: ".preg_replace('/^[✓✗]\s*/u','',$x[0]);
        $out = trim(implode("\n\n", $parts));
        return $out !== '' ? $out : 'Resolved.';
    }
}
