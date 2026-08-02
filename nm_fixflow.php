<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — Containers Solution Commander shared fix-flow logic. Used by BOTH the
// interactive page (container_fix.php) and the n8n callback dispatcher
// (nm_containers_api.php → fix_continue) so the autonomous loop actually closes:
// after a command runs, n8n calls fix_continue → portal feeds the new transcript
// back to the AI (mode=auto). Single source of truth for the payload + SSH/host
// resolution + KB context.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_n8n.php';
require_once __DIR__ . '/nm_secrets.php';
require_once __DIR__ . '/nm_solutionkb.php';
require_once __DIR__ . '/nm_portainer.php';

if (!function_exists('nm_fix_send')) {

    function nm_fix_setting($conn,$k,$d=''){ $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; }
    function nm_fix_incident($conn,$id){ $r=$conn->query("SELECT * FROM container_incidents WHERE id=".(int)$id." LIMIT 1"); return $r?$r->fetch_assoc():null; }
    function nm_fix_base(){ return ((!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http').'://'.($_SERVER['HTTP_HOST']??'localhost'); }
    function nm_fix_log($conn,$id,$level,$line){ $st=$conn->prepare("INSERT INTO container_fix_logs(incident_id,level,line) VALUES(?,?,?)"); $st->bind_param('iss',$id,$level,$line); $st->execute(); }
    function nm_fix_transcript($conn,$id){
        $r=$conn->query("SELECT level,line FROM container_fix_logs WHERE incident_id=".(int)$id." AND level NOT IN ('proposal','proposal-ack') ORDER BY id DESC LIMIT 120");
        $rows=$r?array_reverse($r->fetch_all(MYSQLI_ASSOC)):[]; $out='';
        foreach($rows as $x){ $l=$x['level']; $t=$x['line'];
            if($l==='user') $out.="User: $t\n"; elseif($l==='ai') $out.="Assistant: $t\n";
            elseif($l==='cmd') $out.="$t\n"; elseif($l==='out') $out.="$t\n";
            elseif($l==='error') $out.="ERROR: $t\n"; elseif($l==='done') $out.="Result: $t\n"; else $out.="(info) $t\n"; }
        return substr($out, -12000);
    }

    // Send to the fix flow. mode suggest|chat|auto|fix → fix_suggest_url; command → fix_webhook_url.
    function nm_fix_send($conn,$inc,array $extra){
        $mode=$extra['mode']??'suggest';
        $url = in_array($mode,['suggest','chat','auto','fix'],true) ? nm_fix_setting($conn,'fix_suggest_url','') : nm_fix_setting($conn,'fix_webhook_url','');
        if($url==='' || !function_exists('curl_init')) return ['ok'=>false,'err'=>'No fix webhook configured'];
        $id=(int)$inc['id']; $cfg=nm_n8n_get($conn); $base=function_exists('nm_n8n_callback_base')?nm_n8n_callback_base($conn,$url):nm_fix_base();  // per-flow: hosted→tunnel, local→LAN

        // Resolve the real Docker host IP (SSH target); backfill the incident.
        $hostIp = trim((string)($inc['host_ip'] ?? ''));
        if ($hostIp === '') {
            $pcfg = nm_portainer_cfg($conn);
            if (nm_portainer_configured($pcfg)) {
                $hostIp = nm_portainer_host_ip($pcfg, (int)$inc['endpoint_id'], (string)$inc['host']);
                if ($hostIp !== '') { $conn->query("UPDATE container_incidents SET host_ip='".$conn->real_escape_string($hostIp)."' WHERE id={$id}"); $inc['host_ip']=$hostIp; }
            }
        }
        // SSH creds: explicit fix_ssh_* settings win, else host assignment → default credential.
        $fu = nm_fix_setting($conn,'fix_ssh_user',''); $fpass = nm_secret_decrypt(nm_fix_setting($conn,'fix_ssh_password',''));
        if ($fu !== '') $ssh = ['host'=>$hostIp,'port'=>22,'username'=>$fu,'auth_type'=>'password','password'=>$fpass,'cred_name'=>'fix_ssh_*'];
        else            $ssh = nm_ssh_resolve_host($conn, $hostIp);
        $ssh_user = $ssh['username'] ?? ''; $ssh_pass = $ssh['password'] ?? '';

        $payload = array_merge([
            'incident_id'=>$id,'endpoint_id'=>(int)$inc['endpoint_id'],'host'=>$inc['host'],'host_ip'=>$hostIp,
            'container_id'=>$inc['container_id'],'container_name'=>$inc['container_name'],'severity'=>$inc['severity'],
            'error'=>$inc['error_text'],'ai_summary'=>$inc['ai_summary'],'ai_solution'=>$inc['ai_solution'],
            'ssh'=>$ssh, 'ssh_user'=>$ssh_user, 'ssh_password'=>$ssh_pass,
            'ssh_port'=>($ssh['port'] ?? 22), 'ssh_host'=>$hostIp,
            'log_url'=>$base.'/nm_containers_api.php?ep=fix_log&id='.$id,
            'result_url'=>$base.'/nm_containers_api.php?ep=fix_result&id='.$id,
            'proposal_url'=>$base.'/nm_containers_api.php?ep=fix_proposal&id='.$id,
            'continue_url'=>$base.'/nm_containers_api.php?ep=fix_continue&id='.$id,
        ], $extra);
        // For AI turns, attach KB + Books context.
        if (in_array($mode,['suggest','chat','auto','fix'],true)) {
            $payload['session_id']='fix-'.$id;
            $payload['transcript']=nm_fix_transcript($conn,$id);
            $kb=nm_kb_search($conn, $inc['error_text'].' '.($inc['ai_solution']??''), ['container_name'=>$inc['container_name'],'severity'=>$inc['severity']]);
            $books=nm_kb_search_books($conn, $inc['error_text']);
            $payload['knowledge']=$kb; $payload['knowledge_text']=nm_kb_context($kb,$inc['container_name']);
            $payload['docs']=$books; $payload['docs_text']=nm_kb_docs_context($books);
            $payload['kb_search_url']=nm_fix_setting($conn,'kb_search_url','');
        }
        if(function_exists('nm_n8n_neuru_stamp'))$payload=nm_n8n_neuru_stamp($conn,$payload,$url,(in_array($mode,['suggest','chat','auto','fix'],true)?'container-fix-suggest':'container-fix-exec'));  // gatecheck + per-flow model
        $ch=curl_init($url);
        curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>json_encode($payload),
            CURLOPT_CONNECTTIMEOUT=>4,CURLOPT_TIMEOUT=>20,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_SSL_VERIFYHOST=>false,
            CURLOPT_HTTPHEADER=>['Content-Type: application/json','X-NetMon-Token: '.$cfg['inbound_token']]]);
        curl_exec($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
        return ['ok'=>($code>=200&&$code<300),'err'=>($code>=200&&$code<300)?'':"Webhook HTTP {$code}"];
    }

    // The autonomous loop step: after a command finishes, feed the new transcript
    // back to the AI (mode=auto). Caps at 40 commands. Returns ['ok','paused'].
    function nm_fix_continue($conn,$id){
        $inc = nm_fix_incident($conn,$id);
        if (!$inc) return ['ok'=>false,'error'=>'Incident not found'];
        $cnt = $conn->query("SELECT COUNT(*) c FROM container_fix_logs WHERE incident_id=".(int)$id." AND level='cmd'");
        $n = $cnt ? (int)$cnt->fetch_assoc()['c'] : 0;
        if ($n >= 40) {
            nm_fix_log($conn,$id,'info','Auto-continue paused after 40 commands. Review and continue manually.');
            return ['ok'=>true,'paused'=>true];
        }
        nm_fix_log($conn,$id,'info','AI is reviewing the command output…');
        $r = nm_fix_send($conn,$inc,['mode'=>'auto','message'=>'Review the command output above. If the issue is fixed, say so and stop. Otherwise propose the single next command.']);
        return ['ok'=>$r['ok'],'paused'=>false,'error'=>$r['err'] ?: null];
    }

    // Resolve the SSH target (host IP + creds) for an incident, exactly like nm_fix_send does:
    // fix_ssh_* settings win, else the host assignment → default credential. Backfills host_ip.
    function nm_fix_resolve_ssh($conn,$inc){
        $id=(int)$inc['id']; $hostIp=trim((string)($inc['host_ip'] ?? ''));
        if ($hostIp===''){
            $pcfg=nm_portainer_cfg($conn);
            if(nm_portainer_configured($pcfg)){ $hostIp=nm_portainer_host_ip($pcfg,(int)$inc['endpoint_id'],(string)$inc['host']);
                if($hostIp!=='') $conn->query("UPDATE container_incidents SET host_ip='".$conn->real_escape_string($hostIp)."' WHERE id={$id}"); }
        }
        $fu=nm_fix_setting($conn,'fix_ssh_user',''); $fpass=nm_secret_decrypt(nm_fix_setting($conn,'fix_ssh_password',''));
        if($fu!=='') $ssh=['host'=>$hostIp,'port'=>22,'username'=>$fu,'auth_type'=>'password','password'=>$fpass,'cred_name'=>'fix_ssh_*'];
        else         $ssh=nm_ssh_resolve_host($conn,$hostIp);
        if($ssh && empty($ssh['host'])) $ssh['host']=$hostIp;
        return [$ssh,$hostIp];
    }

    // Run ONE approved command NATIVELY from NEURU (which sits on the LAN) via nm_cm_ssh_fetch,
    // instead of asking a possibly-remote/hosted n8n to SSH into a private LAN host it can't reach.
    // Logs the output (or a clear error) into the transcript. Returns ['ok'=>bool,'rc'=>?,'output'=>?].
    function nm_fix_exec_native($conn,$inc,string $cmd){
        require_once __DIR__ . '/nm_confmgr.php';
        $id=(int)$inc['id'];
        [$ssh,$hostIp]=nm_fix_resolve_ssh($conn,$inc);
        if($hostIp===''){ nm_fix_log($conn,$id,'error','No Docker host IP on this incident — cannot run commands. Set the host IP first.'); return ['ok'=>false]; }
        if(!$ssh || empty($ssh['username']) || (empty($ssh['password']) && empty($ssh['private_key']))){
            nm_fix_log($conn,$id,'error','No usable SSH credential for '.$hostIp.'. Add one (Config → Integrations) or set fix_ssh_user / fix_ssh_password.'); return ['ok'=>false]; }
        // nm_cm_ssh_fetch runs an INTERACTIVE PTY shell, so raw output is polluted with the shell
        // prompt, the echoed command, and ANSI/bracketed-paste codes. Bracket the real output with
        // unique START/END markers (END carries the exit code) so we can extract just the command's
        // stdout+stderr. The markers also guarantee non-empty output (empty = "failure" otherwise).
        $mk='NMFX'.substr(md5($cmd.$id.microtime(true)),0,10); $S=$mk.'S'; $E=$mk.'E';
        $wrapped='echo '.$S.'; { '.$cmd.'; } 2>&1; echo '.$E.'$?';
        $res=nm_cm_ssh_fetch($ssh,$wrapped,40);
        if(empty($res['ok'])){ nm_fix_log($conn,$id,'error','SSH did not execute ('.($res['error'] ?? 'connectivity').') — host '.$hostIp.'. Check connectivity/credentials.'); return ['ok'=>false]; }
        // strip ANSI CSI/OSC + carriage returns, then slice between the real marker lines.
        $raw=(string)($res['config'] ?? '');
        $raw=preg_replace('/\x1b\[[0-9;?]*[ -\/]*[@-~]/','',$raw);   // CSI (incl. [?2004h bracketed paste)
        $raw=preg_replace('/\x1b\][^\x07]*\x07/','',$raw);           // OSC (window title, etc.)
        $raw=str_replace("\r","",$raw);
        $lines=explode("\n",$raw); $si=-1; $ei=-1;
        foreach($lines as $k=>$ln){ $t=trim($ln);
            if($si<0 && $t===$S){ $si=$k; continue; }
            if($si>=0 && strpos($t,$E)===0){ $ei=$k; break; } }
        $rc=null;
        if($si>=0 && $ei>$si){ $rc=trim(substr(trim($lines[$ei]),strlen($E))); $out=rtrim(implode("\n",array_slice($lines,$si+1,$ei-$si-1))); }
        else { $out=rtrim($raw); }   // fallback: markers missing (unexpected shell) — show cleaned raw
        $out=mb_substr($out,0,8000);
        nm_fix_log($conn,$id,'out',$out!==''?$out:'(command completed with no output)');
        if($rc!==null && $rc!=='0') nm_fix_log($conn,$id,'info','Command exited with code '.$rc);
        return ['ok'=>true,'rc'=>$rc,'output'=>$out];
    }
}
