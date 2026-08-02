<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — AI Commander V2.0 cockpit (autopilotv2.php). A full-bleed WebGL console
// where NEURU (the bot) is the MAIN CHARACTER: a living neural core that Observes →
// Thinks → Acts on the fleet. The node under investigation "flies in" and orbits the
// core with data streams; every reasoning step streams live (SSE) into the transcript.
// Operator has FULL control: master switch, per-channel alert sources, per-device
// autonomy tier, learned rules (dismiss-forever / bot-suggested), and a conversational
// chat box (type to NEURU — voice is an optional P4 add-on). PARALLEL to the frozen
// aiopilot.php. Engine: nm_autopilotv2.php · Executor: autopilotv2_api.php · Perm: 'autopilotv2'.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_autopilotv2.php');   // pulls nm_n8n.php + nm_portainer.php + nm_aiopilot.php
require_once('nm_vapi.php');          // VAPI voice add-on (Phase A)
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'autopilotv2')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=autopilotv2'); exit;
}
nm_ap2_ensure($conn);
$uid = (int)($_SESSION['user_id'] ?? 0);
$uname = (string)($_SESSION['username'] ?? 'operator');
// CSRF — same in-repo pattern as access_admin.php / incidents.php. MUST be read before session_write_close().
if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$CSRF = $_SESSION['csrf_token'];
// CSRF: every WRITE (state-changing) endpoint MUST be a token-bearing POST — a GET/link can no longer trigger a
// mutation (fixes dismiss_all/scan/voice_set etc. running on GET). Reads stay GET (incl. the SSE stream); a POST
// read still requires the token. Keep this list in sync when adding a mutating ?api= handler.
$_NM_WRITE_APIS = ['toggle','channel','device','scan','investigate','dismiss','dismiss_all','approve','deny',
    'rule_add','rule_toggle','rule_del','mem_add','mem_del','mem_pin','mem_learn','vision_toggle','presence',
    'vapi_save','vapi_provision','voice_set','voice_spoken','voice_drain','tg_drain','xray_kill','chat'];
$_nm_isPost = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';
$_nm_tokOk  = hash_equals($CSRF, (string)($_POST['csrf'] ?? ''));
if ($api !== '' && (in_array($api, $_NM_WRITE_APIS, true) ? (!$_nm_isPost || !$_nm_tokOk) : ($_nm_isPost && !$_nm_tokOk))) {
    header('Content-Type: application/json'); http_response_code(403);
    echo json_encode(['ok'=>false,'error'=>'csrf','msg'=>'Session expired — reload the page.']); exit;
}
// release the session lock before any slow external I/O (chat → n8n flow, dispatch → webhook)
if (function_exists('session_write_close')) @session_write_close();

// ── SSE live stream ──────────────────────────────────────────────────────────
if ($api === 'stream') {
    while (ob_get_level()) ob_end_flush();
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('X-Accel-Buffering: no');
    $send = function ($ev, $data) { echo "event: {$ev}\ndata: " . json_encode($data) . "\n\n"; @ob_flush(); @flush(); };
    $sinceEv  = (int)($_GET['since'] ?? 0);
    if ($sinceEv === 0) { try { $r=$conn->query("SELECT COALESCE(MAX(id),0) m FROM nm_ap2_events"); $sinceEv=(int)($r?$r->fetch_assoc()['m']:0); } catch (\Throwable $e) {} }
    $sessSnap = [];
    $t0 = time();
    $send('hello', ['since'=>$sinceEv, 'enabled'=>nm_ap2_enabled($conn)]);
    while (!connection_aborted() && (time() - $t0) < 45) {
        // new transcript events
        try {
            $st = $conn->prepare("SELECT e.id,e.session_id,e.node_id,e.phase,e.body,UNIX_TIMESTAMP(e.created_at) ts, n.display_name node_name
                FROM nm_ap2_events e LEFT JOIN nm_nodes n ON n.id=e.node_id WHERE e.id>? ORDER BY e.id ASC LIMIT 40");
            $st->bind_param('i', $sinceEv); $st->execute(); $rs = $st->get_result();
            while ($x = $rs->fetch_assoc()) { $sinceEv = (int)$x['id']; $send('event', $x); }
            $st->close();
        } catch (\Throwable $e) {}
        // session status transitions (drives the stage state)
        try {
            $r = $conn->query("SELECT s.id,s.node_id,s.status,s.autonomy,s.confidence,s.summary, n.display_name node_name, n.ip_address, n.os_icon
                FROM nm_ap2_sessions s LEFT JOIN nm_nodes n ON n.id=s.node_id
                WHERE s.updated_at > (NOW() - INTERVAL 3 MINUTE) ORDER BY s.id DESC LIMIT 12");
            while ($r && $x = $r->fetch_assoc()) {
                $key = $x['id']; $sig = $x['status'].'|'.$x['confidence'].'|'.$x['summary'];
                if (($sessSnap[$key] ?? '') !== $sig) { $sessSnap[$key] = $sig; $send('session', $x); }
            }
        } catch (\Throwable $e) {}
        $send('ping', ['t'=>time()]);
        usleep(1500000);
    }
    $send('bye', ['reconnect'=>true]);
    exit;
}

// ── JSON API ─────────────────────────────────────────────────────────────────
if ($api) {
    header('Content-Type: application/json; charset=utf-8');
    $post = $_POST;

    if ($api === 'state') {
        // channels
        $chans = []; try { $r=$conn->query("SELECT channel_key,enabled,min_severity,act_mode FROM nm_ap2_channels ORDER BY channel_key"); while($r&&$x=$r->fetch_assoc()) $chans[]=$x; } catch (\Throwable $e) {}
        // devices joined to nodes (all nodes, with autonomy overlay)
        $devs = [];
        try {
            $r=$conn->query("SELECT n.id,n.display_name,n.ip_address,n.os_icon,
                COALESCE(d.enabled,0) d_enabled, COALESCE(d.autonomy_mode,'observe') autonomy_mode,
                COALESCE(d.allow_destructive,0) allow_destructive, COALESCE(d.allow_commands,0) allow_commands
                FROM nm_nodes n LEFT JOIN nm_ap2_devices d ON d.node_id=n.id ORDER BY n.display_name");
            while($r&&$x=$r->fetch_assoc()) $devs[]=$x;
        } catch (\Throwable $e) {}
        // counts
        $c = ['open'=>0,'investigating'=>0,'proposed'=>0,'active_sessions'=>0,'fleet'=>0,'rules'=>0,'down'=>0];
        try { $r=$conn->query("SELECT COUNT(*) n FROM nm_alert_state WHERE entity_type='node' AND last_status IN('down','lowerlayerdown','notpresent','testing')"); $c['down']=(int)($r?$r->fetch_assoc()['n']:0); } catch (\Throwable $e) {}
        try { $r=$conn->query("SELECT status,COUNT(*) n FROM nm_ap2_signals GROUP BY status"); while($r&&$x=$r->fetch_assoc()){ if($x['status']==='new')$c['open']=(int)$x['n']; if($x['status']==='investigating')$c['investigating']=(int)$x['n']; if($x['status']==='proposed')$c['proposed']+=(int)$x['n']; } } catch (\Throwable $e) {}
        try { $r=$conn->query("SELECT COUNT(*) n FROM nm_ap2_sessions WHERE status IN('queued','active','awaiting_approval')"); $c['active_sessions']=(int)($r?$r->fetch_assoc()['n']:0); } catch (\Throwable $e) {}
        try { $r=$conn->query("SELECT COUNT(*) n FROM nm_ap2_fleet"); $c['fleet']=(int)($r?$r->fetch_assoc()['n']:0); } catch (\Throwable $e) {}
        try { $r=$conn->query("SELECT COUNT(*) n FROM nm_ap2_rules WHERE active=1"); $c['rules']=(int)($r?$r->fetch_assoc()['n']:0); } catch (\Throwable $e) {}
        // brain readiness
        $wh = function_exists('nm_n8n_webhook_by_slug') ? nm_n8n_webhook_by_slug($conn,'autopilot-v2') : null;
        $chatwh = function_exists('nm_n8n_webhook_by_slug') ? nm_n8n_webhook_by_slug($conn,'autopilot-v2-chat') : null;
        echo json_encode(['ok'=>true,'enabled'=>nm_ap2_enabled($conn),'channels'=>$chans,'devices'=>$devs,'counts'=>$c,
            'brain_ready'=>(bool)($wh && !empty($wh['url']) && $wh['enabled']),
            'chat_ready'=>(bool)($chatwh && !empty($chatwh['url']) && $chatwh['enabled']),
            'scan_interval'=>60]); exit;
    }

    if ($api === 'toggle') {
        // The master switch governs AUTONOMOUS operation only (the cron's scan→pace auto-dispatch).
        // It does NOT disable the webhook: a manual "Investigate" or a chat message must still reach
        // the brain even while autonomy is paused. The webhook is enabled once a URL is configured.
        $on = (int)($post['on'] ?? 0) ? '1' : '0';
        nm_ap2_set($conn, 'ap2_enabled', $on);
        if ($on === '1') { foreach (['autopilot-v2','autopilot-v2-chat'] as $slug) {   // ensure a configured brain is live
            try { $conn->query("UPDATE nm_n8n_webhooks SET enabled=1 WHERE slug='".$conn->real_escape_string($slug)."' AND url<>''"); } catch (\Throwable $e) {}
        } }
        if (function_exists('nm_audit')) { try { nm_audit($conn, 'ap2_master_'.($on==='1'?'on':'off'), ['by'=>$uname]); } catch (\Throwable $e) {} }
        echo json_encode(['ok'=>true,'enabled'=>$on==='1']); exit;
    }

    if ($api === 'channel') {
        $key = preg_replace('/[^a-z_]/','',strtolower((string)($post['key'] ?? '')));
        $en  = isset($post['enabled']) ? ((int)$post['enabled']?1:0) : null;
        $mode= in_array(($post['act_mode']??''),['aware','propose','auto'],true) ? $post['act_mode'] : null;
        $sev = in_array(($post['min_severity']??''),['info','warning','critical'],true) ? $post['min_severity'] : null;
        $sets=[]; $types=''; $vals=[];
        if ($en!==null){ $sets[]='enabled=?'; $types.='i'; $vals[]=$en; }
        if ($mode!==null){ $sets[]='act_mode=?'; $types.='s'; $vals[]=$mode; }
        if ($sev!==null){ $sets[]='min_severity=?'; $types.='s'; $vals[]=$sev; }
        if ($key && $sets) { try { $types.='s'; $vals[]=$key; $st=$conn->prepare("UPDATE nm_ap2_channels SET ".implode(',',$sets)." WHERE channel_key=?"); $st->bind_param($types,...$vals); $st->execute(); $st->close(); } catch (\Throwable $e) {} }
        echo json_encode(['ok'=>true]); exit;
    }

    if ($api === 'device') {
        $nid = (int)($post['node_id'] ?? 0);
        if ($nid<=0){ echo json_encode(['ok'=>false,'error'=>'bad node']); exit; }
        $v = [];
        if (isset($post['enabled']))    $v['enabled']=(int)$post['enabled']?1:0;
        if (isset($post['autonomy_mode']) && in_array($post['autonomy_mode'],['observe','copilot','autopilot'],true)) $v['autonomy_mode']=$post['autonomy_mode'];
        if (isset($post['allow_destructive'])) $v['allow_destructive']=(int)$post['allow_destructive']?1:0;
        if (isset($post['allow_commands']))    $v['allow_commands']=(int)$post['allow_commands']?1:0;
        nm_ap2_device_set($conn, $nid, $v);
        echo json_encode(['ok'=>true]); exit;
    }

    if ($api === 'scan') {   // "Scan now" = SWEEP every selected node (health check) + pick up any bus issues,
        // then investigate. Already-reviewed nodes are skipped (use the per-node Rescan 🔍 to re-check one).
        $scan = nm_ap2_scan($conn); $swept = nm_ap2_sweep($conn); $pace = nm_ap2_pace($conn, true);
        echo json_encode(['ok'=>true,'scan'=>$scan,'swept'=>$swept,'pace'=>$pace]); exit;
    }

    if ($api === 'investigate') {   // operator points NEURU at one node NOW
        $nid = (int)($post['node_id'] ?? 0);
        if ($nid<=0){ echo json_encode(['ok'=>false,'error'=>'bad node']); exit; }
        nm_ap2_device($conn,$nid); // ensure a device row (defaults observe)
        $nm=''; try{ $st=$conn->prepare("SELECT display_name FROM nm_nodes WHERE id=?"); $st->bind_param('i',$nid); $st->execute(); $nm=(string)($st->get_result()->fetch_row()[0]??('node '.$nid)); $st->close(); }catch(\Throwable $e){}
        // don't pile up manual rescans: drop this node's prior IDLE manual scans (keep any in-flight one)
        // so re-checking a node repeatedly leaves exactly one fresh manual signal, not a growing stack.
        try { $conn->query("DELETE FROM nm_ap2_signals WHERE node_id=$nid AND channel='manual' AND status IN('new','acted','stale') AND session_id IS NULL"); } catch (\Throwable $e) {}
        $fp=nm_ap2_fp('manual','node:'.$nid,'manual_scan','m'.time());
        try {
            $chan='manual'; $typ='manual_scan'; $sev='info'; $title='Manual investigation of '.$nm; $det='Operator requested an on-demand scan.';
            $st=$conn->prepare("INSERT INTO nm_ap2_signals (fingerprint,channel,sig_type,target_kind,node_id,name,severity,title,detail,status) VALUES (?,?,?,'node',?,?,?,?,?, 'new')");
            $st->bind_param('sssissss',$fp,$chan,$typ,$nid,$nm,$sev,$title,$det); $st->execute(); $sigid=$st->insert_id; $st->close();
            $r=nm_ap2_dispatch($conn,$sigid,'manual');
            echo json_encode($r);
        } catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>$e->getMessage()]); }
        exit;
    }

    if ($api === 'signals') {
        $rows=[]; try { $r=$conn->query("SELECT s.id,s.channel,s.sig_type,s.node_id,s.name,s.severity,s.title,s.detail,s.status,s.session_id,s.seen_count,UNIX_TIMESTAMP(s.last_seen) ts
            FROM nm_ap2_signals s WHERE s.status NOT IN('resolved','ignored') ORDER BY FIELD(s.severity,'critical','warning','info'), s.id DESC LIMIT 40");
            while($r&&$x=$r->fetch_assoc()) $rows[]=$x; } catch (\Throwable $e) {}
        echo json_encode(['ok'=>true,'signals'=>$rows]); exit;
    }

    if ($api === 'dismiss') {   // remove ONE signal from the queue. For a DOMAIN signal (threat/heal), also
        // dismiss the underlying object so the batch doesn't re-surface it on the very next scan.
        $did = (int)($post['signal_id'] ?? 0);
        if ($did > 0) {
            try { $q=$conn->query("SELECT container_id FROM nm_ap2_signals WHERE id=$did LIMIT 1"); $cid=$q?(string)($q->fetch_assoc()['container_id']??''):'';
                if (strpos($cid,'threat:')===0) { $tid=(int)substr($cid,7); if($tid){ try{ $conn->query("UPDATE nm_threats SET status='dismissed' WHERE id=$tid AND status='pending'"); }catch(\Throwable $e){} } }
                elseif (strpos($cid,'heal:')===0) { $hid=(int)substr($cid,5); if($hid){ try{ $conn->query("UPDATE nm_heal_events SET status='dismissed' WHERE id=$hid AND status='proposed'"); }catch(\Throwable $e){} } }
            } catch (\Throwable $e) {}
            try { $conn->query("DELETE FROM nm_ap2_signals WHERE id=".$did); } catch (\Throwable $e) {}
        }
        echo json_encode(['ok'=>true]); exit;
    }
    if ($api === 'tg_drain') {   // opportunistic: while the cockpit is open, drain Telegram taps in ~seconds
        require_once __DIR__ . '/nm_aiopilot.php';   // poll_feed lives there (drains v1 + v2 via aip:/ap2:)
        $r = function_exists('nm_aip_tg_poll_feed') ? nm_aip_tg_poll_feed($conn) : ['ok'=>false,'skipped'=>'unavailable'];
        echo json_encode($r); exit;
    }
    if ($api === 'dismiss_all') {   // clear the reviewed/idle backlog (keeps anything investigating or awaiting you)
        // dismiss the underlying threats/heals for the domain signals we're clearing so they don't re-surface
        try { $conn->query("UPDATE nm_threats SET status='dismissed' WHERE status='pending' AND CONCAT('threat:',id) IN (SELECT container_id FROM nm_ap2_signals WHERE channel='events_threats' AND status IN('new','acted','stale') AND container_id IS NOT NULL)"); } catch (\Throwable $e) {}
        try { if ($conn->query("SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_heal_events' LIMIT 1")->num_rows) $conn->query("UPDATE nm_heal_events SET status='dismissed' WHERE status='proposed' AND CONCAT('heal:',id) IN (SELECT container_id FROM nm_ap2_signals WHERE channel='heal' AND status IN('new','acted','stale') AND container_id IS NOT NULL)"); } catch (\Throwable $e) {}
        try { $conn->query("DELETE FROM nm_ap2_signals WHERE status IN('new','acted','stale')"); } catch (\Throwable $e) {}
        echo json_encode(['ok'=>true]); exit;
    }

    if ($api === 'sessions') {
        $rows=[]; try { $r=$conn->query("SELECT s.id,s.node_id,s.status,s.autonomy,s.confidence,s.summary,UNIX_TIMESTAMP(s.updated_at) ts, n.display_name node_name
            FROM nm_ap2_sessions s LEFT JOIN nm_nodes n ON n.id=s.node_id ORDER BY s.id DESC LIMIT 20");
            while($r&&$x=$r->fetch_assoc()) $rows[]=$x; } catch (\Throwable $e) {}
        echo json_encode(['ok'=>true,'sessions'=>$rows]); exit;
    }

    if ($api === 'events') {   // transcript for one session (initial paint before SSE)
        $sid=(int)($_GET['session_id']??0); $rows=[];
        try { $st=$conn->prepare("SELECT id,session_id,node_id,phase,body,UNIX_TIMESTAMP(created_at) ts FROM nm_ap2_events WHERE session_id=? ORDER BY id ASC LIMIT 200"); $st->bind_param('i',$sid); $st->execute(); $r=$st->get_result(); while($x=$r->fetch_assoc())$rows[]=$x; $st->close(); } catch (\Throwable $e) {}
        echo json_encode(['ok'=>true,'events'=>$rows]); exit;
    }

    if ($api === 'actions') {   // proposed actions awaiting a human + recently executed (so you SEE what NEURU did)
        $rows=[]; $recent=[];
        try { $r=$conn->query("SELECT a.id,a.node_id,a.tool,a.args,a.risk,a.status,a.result,UNIX_TIMESTAMP(a.created_at) ts, n.display_name node_name
            FROM nm_ap2_actions a LEFT JOIN nm_nodes n ON n.id=a.node_id WHERE a.status='proposed' ORDER BY a.id DESC LIMIT 30");
            while($r&&$x=$r->fetch_assoc()) $rows[]=$x; } catch (\Throwable $e) {}
        try { $r=$conn->query("SELECT a.id,a.node_id,a.tool,a.args,a.status,LEFT(a.result,300) result,UNIX_TIMESTAMP(a.created_at) ts, n.display_name node_name
            FROM nm_ap2_actions a LEFT JOIN nm_nodes n ON n.id=a.node_id WHERE a.status IN('done','failed','denied') ORDER BY a.id DESC LIMIT 15");
            while($r&&$x=$r->fetch_assoc()) $recent[]=$x; } catch (\Throwable $e) {}
        echo json_encode(['ok'=>true,'actions'=>$rows,'recent'=>$recent]); exit;
    }

    if ($api === 'approve' || $api === 'deny') {
        $aid=(int)($post['action_id']??0);
        if ($aid<=0){ echo json_encode(['ok'=>false,'error'=>'bad action']); exit; }
        if ($api==='deny') {
            try { $conn->query("UPDATE nm_ap2_actions SET status='denied' WHERE id=$aid AND status='proposed'"); } catch (\Throwable $e) {}
            if (function_exists('nm_audit')) { try { nm_audit($conn,'ap2_deny',['action'=>$aid,'by'=>$uname]); } catch (\Throwable $e) {} }
            echo json_encode(['ok'=>true,'status'=>'denied']); exit;
        }
        // approve → mark approved then execute via the engine (reuses v1 executor + guards)
        try { $conn->query("UPDATE nm_ap2_actions SET status='approved' WHERE id=$aid AND status='proposed'"); } catch (\Throwable $e) {}
        if (function_exists('nm_audit')) { try { nm_audit($conn,'ap2_approve',['action'=>$aid,'by'=>$uname]); } catch (\Throwable $e) {} }
        $res = nm_ap2_execute_action($conn, $aid);
        echo json_encode(['ok'=>!empty($res['ok']),'result'=>$res]); exit;
    }

    if ($api === 'rules') {   // list
        $rows=[]; try { $r=$conn->query("SELECT id,match_type,match_val,policy,note,created_by,active,hits,UNIX_TIMESTAMP(created_at) ts FROM nm_ap2_rules ORDER BY active DESC, id DESC LIMIT 100");
            while($r&&$x=$r->fetch_assoc()) $rows[]=$x; } catch (\Throwable $e) {}
        echo json_encode(['ok'=>true,'rules'=>$rows]); exit;
    }
    if ($api === 'rule_add') {
        $mt=in_array(($post['match_type']??'channel_type'),['fingerprint','channel_type','node','regex'],true)?$post['match_type']:'channel_type';
        $mv=substr((string)($post['match_val']??''),0,255);
        $pol=in_array(($post['policy']??'ignore'),['ignore','auto_ack','auto_fix','always_ask'],true)?$post['policy']:'ignore';
        $note=substr('via cockpit: '.(string)($post['note']??''),0,255);
        if ($mv==='') { echo json_encode(['ok'=>false,'error'=>'match value required']); exit; }
        try { $st=$conn->prepare("INSERT INTO nm_ap2_rules (match_type,match_val,policy,note,created_by,active) VALUES (?,?,?,?,?,1)");
              $st->bind_param('sssss',$mt,$mv,$pol,$note,$uname); $st->execute(); $st->close(); } catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>$e->getMessage()]); exit; }
        echo json_encode(['ok'=>true]); exit;
    }
    if ($api === 'rule_toggle') {
        $id=(int)($post['id']??0); $act=(int)($post['active']??0)?1:0;
        try { $conn->query("UPDATE nm_ap2_rules SET active=$act WHERE id=$id"); } catch (\Throwable $e) {}
        echo json_encode(['ok'=>true]); exit;
    }
    if ($api === 'rule_del') {
        $id=(int)($post['id']??0);
        try { $conn->query("DELETE FROM nm_ap2_rules WHERE id=$id"); } catch (\Throwable $e) {}
        echo json_encode(['ok'=>true]); exit;
    }
    // ── NEURU Memory (learned facts) ──
    if ($api === 'mem_list') { echo json_encode(['ok'=>true,'count'=>nm_ap2_mem_count($conn),'memories'=>nm_ap2_mem_list($conn,(string)($_GET['q']??''),150)]); exit; }
    if ($api === 'mem_add')  { $id=nm_ap2_mem_add($conn,(string)($post['kind']??'fact'),(string)($post['scope']??'general'),(string)($post['subject']??''),(string)($post['content']??''),['source'=>'user','confidence'=>0.88,'by'=>$uname,'pinned'=>!empty($post['pinned'])?1:0]); echo json_encode(['ok'=>$id>0,'id'=>$id]); exit; }
    if ($api === 'mem_del')  { nm_ap2_mem_del($conn,(int)($post['id']??0)); echo json_encode(['ok'=>true]); exit; }
    if ($api === 'mem_pin')  { nm_ap2_mem_pin($conn,(int)($post['id']??0),!empty($post['pin'])?1:0); echo json_encode(['ok'=>true]); exit; }
    if ($api === 'mem_learn') {   // capture a spoken/typed TEACHING or CORRECTION (the VAPI direct-tool path bypasses the brain)
        $text = trim((string)($post['text']??'')); if ($text==='' || mb_strlen($text)<6) { echo json_encode(['ok'=>false]); exit; }
        $isCorr = (bool)preg_match('/\b(no,|en realidad|est[aá]s? mal|te equivocas|eso no|no es (as[ií]|cierto)|equivocad|incorrecto|es falso|corrige|actually|wrong)\b/iu', $text);
        $ents = function_exists('_nm_ap2_mem_entities') ? _nm_ap2_mem_entities($text) : [];
        $scope = !empty($ents) ? $ents[0] : 'general';
        $id = nm_ap2_mem_add($conn, $isCorr?'correction':'fact', $scope, mb_substr($text,0,80), $text, ['source'=>substr((string)($post['source']??'voice'),0,12),'confidence'=>0.86,'by'=>$uname]);
        echo json_encode(['ok'=>$id>0,'id'=>$id,'kind'=>$isCorr?'correction':'fact']); exit;
    }

    if ($api === 'vision_cfg') {   // Local Vision on/off + who's logged in (for the greeting) + face-enrolled?
        echo json_encode(['ok'=>true,'enabled'=>nm_ap2_get($conn,'vision_enabled','0')==='1','user'=>$uname,'enrolled'=>nm_ap2_get($conn,'vision_face_'.$uid,'')!=='']); exit;
    }
    if ($api === 'vision_toggle') {
        $on = !empty($post['on']) ? '1' : '0'; nm_ap2_set($conn,'vision_enabled',$on);
        echo json_encode(['ok'=>true,'enabled'=>$on==='1']); exit;
    }
    if ($api === 'face_enroll') {   // store the operator's face descriptor (128 floats) — enrolled once, verified locally
        $d = json_decode((string)($post['desc'] ?? ''), true);
        if (is_array($d) && count($d) >= 64 && count($d) <= 256) { nm_ap2_set($conn,'vision_face_'.$uid, json_encode(array_map('floatval',$d))); echo json_encode(['ok'=>true,'enrolled'=>true]); }
        else echo json_encode(['ok'=>false,'error'=>'bad descriptor']);
        exit;
    }
    if ($api === 'face_get') {   // enrolled descriptor for THIS user → the iframe verifies locally (never leaves the box)
        $d = nm_ap2_get($conn,'vision_face_'.$uid,'');
        echo json_encode(['ok'=>true,'desc'=>$d?json_decode($d,true):null]); exit;
    }
    if ($api === 'presence') {   // the browser Eye reports the operator's live presence (tiny JSON; video stays local)
        $state = preg_replace('/[^a-z]/','',strtolower((string)($post['state'] ?? '')));
        if (in_array($state,['engaged','passive','absent'],true)) {
            $att = round(max(0,min(1,(float)($post['attention'] ?? 0))),2);
            nm_ap2_set($conn,'presence_'.$uid, $state.'|'.$att.'|'.time());
        }
        echo json_encode(['ok'=>true]); exit;
    }
    if ($api === 'xray_hosts') {   // X-Ray target picker — EVERY monitored node (rich SSH hosts + SNMP routers/devices)
        @require_once __DIR__ . '/nm_linuxhost.php'; @require_once __DIR__ . '/nm_winhost.php'; @require_once __DIR__ . '/nm_nodemeta.php';
        $lx=[]; $wn=[];
        if (function_exists('nm_lx_hosts')) foreach (nm_lx_hosts($conn) as $h) if (!empty($h['node_id'])) $lx[(int)$h['node_id']]=1;
        if (function_exists('nm_win_hosts')) foreach (nm_win_hosts($conn) as $h) if (!empty($h['node_id'])) $wn[(int)$h['node_id']]=1;
        $out=[];
        try { $r=$conn->query("SELECT id,display_name,ip_address,os_icon FROM nm_nodes ORDER BY sort_order, display_name");
            while($r&&$n=$r->fetch_assoc()){ $nid=(int)$n['id'];
                $kind = isset($lx[$nid]) ? 'linux' : (isset($wn[$nid]) ? 'windows' : (function_exists('nm_node_kind') ? nm_node_kind($n) : 'snmp'));
                $out[]=['node_id'=>$nid,'name'=>$n['display_name'],'ip'=>$n['ip_address'],'kind'=>$kind,'rich'=>(isset($lx[$nid])||isset($wn[$nid]))?1:0]; }
        } catch (\Throwable $e){}
        echo json_encode(['ok'=>true,'hosts'=>$out]); exit;
    }
    if ($api === 'ui_poll') {   // cockpit polls for server-pushed UI actions (voice/chat: "show the x-ray of X")
        $j = nm_ap2_get($conn,'ap2_ui_xray',''); $d = $j ? json_decode($j,true) : null;
        echo json_encode(['ok'=>true,'xray'=>(is_array($d) && (time()-(int)($d['ts']??0) < 25)) ? $d : null]); exit;
    }
    // ── VOICE NARRATION of alerts (opt-in; alerts path only — the direct conversation is untouched) ──
    // The BUTTON reflects the customer's PREFERENCE (ap2_autonomous_voice), independent of the autonomous
    // master switch. Narration only SOUNDS when both are on (nm_ap2_voice_on) — but the toggle must stay
    // flippable even while autonomous is paused, so it must NOT read the combined gate.
    if ($api === 'voice_state') {   // preference for the toggle sync + whether it would actually sound now
        echo json_encode(['ok'=>true,'on'=>nm_ap2_get($conn,'ap2_autonomous_voice','0')==='1','effective'=>function_exists('nm_ap2_voice_on')?nm_ap2_voice_on($conn):false]); exit;
    }
    if ($api === 'voice_set') {      // customer flips the narrate toggle on/off → store + echo the PREFERENCE
        $on = !empty($post['on']) && $post['on']!=='0' && $post['on']!=='false';
        nm_ap2_set($conn,'ap2_autonomous_voice',$on?'1':'0');
        echo json_encode(['ok'=>true,'on'=>$on,'effective'=>function_exists('nm_ap2_voice_on')?nm_ap2_voice_on($conn):false]); exit;
    }
    if ($api === 'voice_drain') {    // cockpit calls this ONLY when idle → get the next line to speak (needs both switches)
        if (!function_exists('nm_ap2_voice_on') || !nm_ap2_voice_on($conn)) { echo json_encode(['ok'=>true,'line'=>null]); exit; }
        $line = nm_ap2_voice_drain($conn);
        echo json_encode(['ok'=>true,'line'=>$line]); exit;
    }
    if ($api === 'voice_spoken') {   // confirm a claimed line was actually spoken → mark it done
        nm_ap2_voice_spoken($conn,(int)($post['id'] ?? 0)); echo json_encode(['ok'=>true]); exit;
    }
    if ($api === 'diagnose') {   // deterministic 5-stage troubleshooting → structured verdict (decides "hay o no problema")
        $nid = (int)($post['node'] ?? $_GET['node'] ?? 0);
        if(!$nid){ $ref=(string)($post['name'] ?? $_GET['name'] ?? ''); if($ref!=='' && function_exists('nm_ap2_resolve_node')) $nid=nm_ap2_resolve_node($conn,$ref); }
        if(!$nid){ echo json_encode(['ok'=>false,'error'=>'no node']); exit; }
        $symptom = (string)($post['symptom'] ?? $_GET['symptom'] ?? '');
        $sigtext = (string)($post['signal'] ?? $_GET['signal'] ?? '');
        $d = function_exists('nm_ap2_diag_report') ? nm_ap2_diag_report($conn,$nid,$symptom,$sigtext) : ['ok'=>false,'error'=>'engine missing'];
        echo json_encode($d); exit;
    }
    if ($api === 'xray') {   // FULL-SPECTRUM surgical scan of one node → drives the 3D anatomy
        $nid=(int)($post['node'] ?? $_GET['node'] ?? 0); if(!$nid){ echo json_encode(['ok'=>false,'error'=>'no node']); exit; }
        $x = function_exists('nm_ap2_xray_full') ? nm_ap2_xray_full($conn,$nid) : ['ok'=>false,'error'=>'engine missing'];
        echo json_encode(empty($x['ok']) ? $x : ['ok'=>true,'xray'=>$x]); exit;
    }
    if ($api === 'topology') {   // interconnected 3D network map (all nodes | a router + connections | a subnet)
        $scope = (string)($post['scope'] ?? $_GET['scope'] ?? 'all');
        $t = function_exists('nm_ap2_topology') ? nm_ap2_topology($conn,$scope) : ['ok'=>false,'error'=>'engine missing'];
        echo json_encode(empty($t['ok']) ? $t : ['ok'=>true,'topo'=>$t]); exit;
    }
    if ($api === 'traffic') {   // live per-interface traffic (laser view) — ALL monitored interfaces, or scoped to a node
        $node = (string)($post['node'] ?? $_GET['node'] ?? '');
        $iface = (string)($post['iface'] ?? $post['interface'] ?? $_GET['iface'] ?? '');
        $t = function_exists('nm_ap2_traffic') ? nm_ap2_traffic($conn,$node,$iface) : ['ok'=>false,'error'=>'engine missing'];
        echo json_encode(empty($t['ok']) ? $t : ['ok'=>true,'traffic'=>$t]); exit;
    }
    if ($api === 'containers') {   // fleet-wide containers (WebGL layer) — ALL containers per node, or scoped to a node
        $node = (string)($post['node'] ?? $_GET['node'] ?? '');
        $ctr  = (string)($post['container'] ?? $post['cid'] ?? $_GET['container'] ?? $_GET['cid'] ?? '');
        $c = function_exists('nm_ap2_containers') ? nm_ap2_containers($conn,$node,$ctr) : ['ok'=>false,'error'=>'engine missing'];
        echo json_encode(empty($c['ok']) ? $c : ['ok'=>true,'containers'=>$c]); exit;
    }
    if ($api === 'nettool_resolve') {   // resolve a spoken node NAME → its IP so the Net Tools embed can target it
        $ref = trim((string)($post['ref'] ?? $_GET['ref'] ?? ''));
        $ip = $ref;
        if ($ref !== '' && !filter_var($ref, FILTER_VALIDATE_IP) && function_exists('nm_ap2_resolve_node')) {
            $nid = nm_ap2_resolve_node($conn, $ref);
            if ($nid && function_exists('nm_ap2_node_ip')) { $rip = nm_ap2_node_ip($conn, $nid); if ($rip !== '') $ip = $rip; }
        }
        echo json_encode(['ok'=>true,'target'=>$ip]); exit;
    }
    if ($api === 'container_detail') {   // deep detail for ONE container (focus panel + Q&A): volumes/sizes/partition/net
        $eidp = (int)($post['endpoint_id'] ?? $_GET['endpoint_id'] ?? 0);
        $cid  = (string)($post['cid'] ?? $_GET['cid'] ?? '');
        $nnm  = (string)($post['node'] ?? $_GET['node'] ?? '');
        $d = function_exists('nm_ap2_container_detail') ? nm_ap2_container_detail($conn,$eidp,$cid,$nnm) : ['ok'=>false,'error'=>'engine missing'];
        echo json_encode($d); exit;
    }
    if ($api === 'xray_kill') {   // Kernel Profiler — kill a process BY NAME (guarded + audited; operator action)
        @require_once __DIR__ . '/nm_linuxhost.php'; @require_once __DIR__ . '/nm_winhost.php';
        $nid=(int)($post['node']??0); $name=trim((string)($post['name']??''));
        if(!$nid||$name===''){ echo json_encode(['ok'=>false,'error'=>'node + name required']); exit; }
        $kind=null;$h=null;
        if (function_exists('nm_lx_hosts')) foreach (nm_lx_hosts($conn) as $x) if ((int)($x['node_id']??0)===$nid){ $kind='linux'; $h=$x; break; }
        if (!$h && function_exists('nm_win_hosts')) foreach (nm_win_hosts($conn) as $x) if ((int)($x['node_id']??0)===$nid){ $kind='windows'; $h=$x; break; }
        if (!$h){ echo json_encode(['ok'=>false,'error'=>'host not found']); exit; }
        try { $r = $kind==='linux' ? nm_lx_kill_process($conn,$h,$name,$uid) : nm_win_kill_process($conn,$h,$name,$uid); }
        catch (\Throwable $e){ $r=['ok'=>false,'error'=>$e->getMessage()]; }
        if (function_exists('nm_audit')){ try { nm_audit($conn,'ap2_xray_kill',['node'=>$nid,'proc'=>$name,'ok'=>!empty($r['ok'])]); } catch (\Throwable $e){} }
        echo json_encode($r); exit;
    }
    if ($api === 'tt_range') {   // Timeline DVR — available data window for the scrubber bounds
        @require_once __DIR__ . '/nm_timetravel.php';
        echo json_encode(['ok'=>true,'range'=>function_exists('nm_tt_range') ? nm_tt_range($conn) : ['min'=>time()-86400,'max'=>time()]]); exit;
    }
    if ($api === 'tt_snapshot') {   // Timeline DVR — the FULL fleet state at a past minute (rewinds the cockpit)
        @require_once __DIR__ . '/nm_timetravel.php';
        if (!function_exists('nm_tt_snapshot')) { echo json_encode(['ok'=>false,'error'=>'time-travel unavailable on this install']); exit; }
        $at = (string)($_GET['at'] ?? $post['at'] ?? '');
        try { $snap = nm_tt_snapshot($conn, $at !== '' ? $at : date('Y-m-d H:i:s')); }
        catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>$e->getMessage()]); exit; }
        echo json_encode(['ok'=>true,'snap'=>[
            'at'=>$snap['at'],'summary'=>$snap['summary'] ?? [],
            'nodes'=>array_map(fn($n)=>['id'=>$n['id'],'name'=>$n['name'],'state'=>$n['state'],'cpu'=>$n['cpu'],'latency'=>$n['latency']], $snap['nodes'] ?? []),
            'incidents'=>array_slice($snap['incidents'] ?? [], 0, 12),
            'netflow_mbps'=>$snap['netflow']['total_mbps'] ?? 0,
        ]]); exit;
    }
    if ($api === 'tool_activity') {   // recent tool runs (chat/voice/session) → futuristic live tool panel
        $rows=[]; try { $r=$conn->query("SELECT id,channel,tool,args_json,ok,status,summary,data_json,UNIX_TIMESTAMP(created_at) ts FROM nm_ap2_tool_events ORDER BY id DESC LIMIT 5");
            while($r&&$x=$r->fetch_assoc()){ $x['args']=json_decode($x['args_json']?:'{}',true); $x['data']=json_decode($x['data_json']?:'null',true); unset($x['args_json'],$x['data_json']); $rows[]=$x; } } catch(\Throwable $e){}
        echo json_encode(['ok'=>true,'events'=>$rows]); exit;
    }
    if ($api === 'vapi_cfg') {   // current VAPI config for the Voice card (never leaks the private key)
        nm_vapi_ensure($conn);
        echo json_encode(['ok'=>true,'cfg'=>nm_vapi_admin_cfg($conn)]); exit;
    }
    if ($api === 'vapi_save') {  // save public key / assistant id / enable + (optional) private key
        $save = [
            'public_key'    => (string)($post['public_key'] ?? ''),
            'assistant_id'  => (string)($post['assistant_id'] ?? ''),
            'enabled'       => !empty($post['enabled']),
            'private_key'   => (string)($post['private_key'] ?? ''),
            'clear_private' => !empty($post['clear_private']),
        ];
        if (isset($post['public_base'])) $save['public_base'] = (string)$post['public_base'];
        nm_vapi_save($conn, $save);
        echo json_encode(['ok'=>true,'cfg'=>nm_vapi_admin_cfg($conn)]); exit;
    }
    if ($api === 'vapi_provision') {  // create/update the assistant on the operator's VAPI account (explicit action)
        $r = nm_vapi_provision_assistant($conn, 'byo');
        echo json_encode(['ok'=>$r['ok'],'id'=>$r['id'],'error'=>$r['err'],'cfg'=>nm_vapi_admin_cfg($conn)]); exit;
    }

    if ($api === 'chat') {   // converse with NEURU — shared brain (nm_ap2_chat_exchange); voice uses the same
        $r = nm_ap2_chat_exchange($conn, (string)($post['message'] ?? ''), $uname, true);
        if (empty($r['ok'])) { echo json_encode(['ok'=>false,'error'=>$r['error'] ?? 'empty']); exit; }
        echo json_encode(['ok'=>true,'reply'=>$r['reply'],'command'=>$r['command'],'applied'=>$r['applied']]); exit;
    }

    if ($api === 'chat_history') {
        $rows=[]; try { $r=$conn->query("SELECT role,message,UNIX_TIMESTAMP(created_at) ts FROM nm_ap2_chat WHERE message IS NOT NULL ORDER BY id DESC LIMIT 30"); while($r&&$x=$r->fetch_assoc()) $rows[]=$x; $rows=array_reverse($rows); } catch (\Throwable $e) {}
        echo json_encode(['ok'=>true,'history'=>$rows]); exit;
    }

    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}

// ── server-side application of a chat command (validated; no risk-gate bypass) ──
if (!function_exists('nm_ap2_chat_apply')) {
function nm_ap2_chat_apply($conn, array $cmd, string $by): array {
    $op = preg_replace('/[^a-z_]/','',strtolower((string)($cmd['op'] ?? '')));
    switch ($op) {
        case 'set_channel': {
            $k=preg_replace('/[^a-z_]/','',strtolower((string)($cmd['channel']??''))); $en=(int)!empty($cmd['enabled']);
            if ($k) { try { $st=$conn->prepare("UPDATE nm_ap2_channels SET enabled=? WHERE channel_key=?"); $st->bind_param('is',$en,$k); $st->execute(); $st->close(); } catch (\Throwable $e) {} }
            return ['op'=>'set_channel','channel'=>$k,'enabled'=>(bool)$en];
        }
        case 'create_rule': {
            $m=$cmd['match']??[]; $mt=in_array(($m['type']??'channel_type'),['fingerprint','channel_type','node','regex'],true)?$m['type']:'channel_type';
            $mv=substr((string)($m['val']??($cmd['match_val']??'')),0,255);
            $pol=in_array(($cmd['policy']??'ignore'),['ignore','auto_ack','auto_fix','always_ask'],true)?$cmd['policy']:'ignore';
            $note=substr('via chat: '.(string)($cmd['note']??''),0,255);
            if ($mv!=='') { try { $st=$conn->prepare("INSERT INTO nm_ap2_rules (match_type,match_val,policy,note,created_by,active) VALUES (?,?,?,?,?,1)"); $st->bind_param('sssss',$mt,$mv,$pol,$note,$by); $st->execute(); $st->close(); } catch (\Throwable $e) {} }
            return ['op'=>'create_rule','match'=>$mv,'policy'=>$pol];
        }
        case 'set_tier': {
            $nid=(int)($cmd['node_id']??0); $tier=in_array(($cmd['tier']??''),['observe','copilot','autopilot'],true)?$cmd['tier']:'observe';
            if ($nid>0) nm_ap2_device_set($conn,$nid,['autonomy_mode'=>$tier,'enabled'=>1]);
            return ['op'=>'set_tier','node_id'=>$nid,'tier'=>$tier];
        }
        case 'investigate': {
            $nid=(int)(($cmd['target']['node_id'] ?? $cmd['node_id']) ?? 0);
            if ($nid>0) { nm_ap2_device($conn,$nid); $fp=nm_ap2_fp('manual','node:'.$nid,'manual_scan','c'.time());
                try { $chan='manual';$typ='manual_scan';$sev='info';$nm='node '.$nid;$title='Chat-requested investigation';$det='Requested via chat.';
                    $st=$conn->prepare("INSERT INTO nm_ap2_signals (fingerprint,channel,sig_type,target_kind,node_id,name,severity,title,detail,status) VALUES (?,?,?,'node',?,?,?,?,?, 'new')");
                    $st->bind_param('sssissss',$fp,$chan,$typ,$nid,$nm,$sev,$title,$det); $st->execute(); $sid=$st->insert_id; $st->close();
                    nm_ap2_dispatch($conn,$sid,'chat'); } catch (\Throwable $e) {} }
            return ['op'=>'investigate','node_id'=>$nid];
        }
        case 'pause':  nm_ap2_set($conn,'ap2_enabled','0'); return ['op'=>'pause'];
        case 'resume': nm_ap2_set($conn,'ap2_enabled','1'); return ['op'=>'resume'];
        case 'firewall_block': {   // "block IP X on router Y" → PROPOSE (operator Approves/Denies; never auto)
            $ip=trim((string)($cmd['ip']??$cmd['address']??''));
            $nid=nm_ap2_resolve_node($conn,(string)($cmd['node']??$cmd['router']??''));
            if(!filter_var($ip,FILTER_VALIDATE_IP)) return ['op'=>'firewall_block','error'=>'invalid IP'];
            if(!$nid) return ['op'=>'firewall_block','error'=>'router not found'];
            $reason='Operator ('.$by.') asked to block '.$ip;
            $sid=0; try{ $st=$conn->prepare("INSERT INTO nm_ap2_sessions (node_id,status,trigger_kind,summary) VALUES (?, 'awaiting_approval','chat',?)"); $sm=substr('block '.$ip,0,255); $st->bind_param('is',$nid,$sm); $st->execute(); $sid=$st->insert_id; $st->close(); }catch(\Throwable $e){}
            $r=$sid?nm_ap2_propose_action($conn,$sid,'firewall_block_ip',['node'=>$nid,'ip'=>$ip,'reason'=>$reason],'medium',$reason,true):['needs_approval'=>false];
            return ['op'=>'firewall_block','ip'=>$ip,'node_id'=>$nid,'proposed'=>!empty($r['needs_approval'])];
        }
        case 'firewall_apply': {   // add/remove/enable/disable a rule → PROPOSE (Safe-Apply on execute; approval first)
            $nid=nm_ap2_resolve_node($conn,(string)($cmd['node']??$cmd['router']??''));
            if(!$nid) return ['op'=>'firewall_apply','error'=>'router not found'];
            $a=is_array($cmd['args']??null)?$cmd['args']:$cmd;
            $args=['node'=>$nid]+array_intersect_key($a,array_flip(['table','op','chain','action','id','number','src_address','dst_address','protocol','dst_port','comment']));
            $reason='Operator ('.$by.') firewall '.($args['op']??'?').' on router';
            $sid=0; try{ $st=$conn->prepare("INSERT INTO nm_ap2_sessions (node_id,status,trigger_kind,summary) VALUES (?, 'awaiting_approval','chat',?)"); $sm=substr('fw '.($args['op']??''),0,255); $st->bind_param('is',$nid,$sm); $st->execute(); $sid=$st->insert_id; $st->close(); }catch(\Throwable $e){}
            $r=$sid?nm_ap2_propose_action($conn,$sid,'firewall_apply',$args,'high',$reason,true):['needs_approval'=>false];
            return ['op'=>'firewall_apply','node_id'=>$nid,'proposed'=>!empty($r['needs_approval'])];
        }
    }
    return ['op'=>$op,'ignored'=>true];
}}

$enabled = nm_ap2_enabled($conn);
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NEURU Commander · Autonomous NOC</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" media="print" onload="this.media='all'">
<noscript><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"></noscript>
<style>
:root{ --cyan:#38e1ff; --violet:#9b6bff; --amber:#ffb454; --green:#43e08a; --red:#ff5c7a; --ink:#e9eefb; --mut:#8b97b8; }
*{box-sizing:border-box}
/* SOLID deep-space bg — a dark radial-gradient here banded into horizontal stripes (8-bit steps on
   near-black arcs). The three.js starfield supplies all the depth; the WebGL clear color adds the glow. */
body{ margin:0; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; color:var(--ink); background:#05060e; }
/* opaque stage: the renderer paints its own band-free radial glow as the backdrop (netbg stays hidden) */
#nm-stage{ position:fixed; inset:0; z-index:0; background:#05060e; }
#nm-stage canvas{ display:block; }
/* fullscreen target — holds canvas + HUD + drawer, NOT the header (aiopilot/command pattern) */
#v2-stage{ position:fixed; inset:0; z-index:0; }
#v2-stage.fs, #v2-stage:fullscreen, #v2-stage:-webkit-full-screen, #v2-stage:-moz-full-screen{ background:#05060e; }
/* ANY fullscreen (my ⛶ button OR the browser's F11) → hide the portal header + pull the HUD flush to
   the top. JS stamps html.nm-fs on every fullscreenchange, so this works no matter what got fullscreened. */
html.nm-fs #nm-topbar{ display:none !important; }
html.nm-fs .v2-hud{ top:8px !important; }
html.nm-fs, html.nm-fs body{ background:#05060e !important; }
.v2-hud{ position:fixed; top:54px; left:0; right:0; bottom:0; z-index:2; pointer-events:none; display:grid;
  grid-template-columns:340px 1fr 380px; grid-template-rows:auto 1fr auto; gap:14px; padding:14px; }
.v2-hud > *{ pointer-events:auto; }
/* header ships its own square netbg — we render our OWN round three.js starfield instead */
#nm-netbg{ display:none !important; }
/* SEE-THROUGH glass: minimal tint + light blur so the cosmos reads clearly through the panels
   (heavy blur looked frosted/solid). The neon hairline + border give it the glass edge. */
.glass{ position:relative; background:linear-gradient(160deg, rgba(34,50,104,.04), rgba(8,13,34,.015));
  border:1px solid rgba(140,185,255,.20); border-radius:16px; overflow:hidden;
  backdrop-filter:blur(9px) saturate(1.4); -webkit-backdrop-filter:blur(9px) saturate(1.4);
  box-shadow:0 6px 30px rgba(0,0,0,.16), inset 0 1px 0 rgba(185,215,255,.16); }
.glass::before{ content:''; position:absolute; top:0; left:12%; right:12%; height:1px; pointer-events:none;
  background:linear-gradient(90deg, transparent, rgba(56,225,255,.55), rgba(155,107,255,.4), transparent); }
.panel{ display:flex; flex-direction:column; min-height:0; }
.panel h3{ margin:0; padding:12px 14px 8px; font-size:12px; letter-spacing:.14em; text-transform:uppercase; color:var(--mut);
  display:flex; align-items:center; gap:8px; border-bottom:1px solid rgba(120,150,255,.10); }
.panel h3 .fa-solid,.panel h3 .fa-brands{ color:var(--cyan); }
.panel .body{ overflow:auto; padding:10px 12px; flex:1 1 auto; }
.panel .body::-webkit-scrollbar{ width:8px } .panel .body::-webkit-scrollbar-thumb{ background:rgba(120,150,255,.25); border-radius:6px }

/* top bar */
#v2-top{ grid-column:1 / span 3; grid-row:1; display:flex; align-items:center; gap:14px; padding:10px 16px; }
#v2-top .brand{ display:flex; align-items:center; gap:12px; }
#v2-top .brand .orb{ width:40px; height:40px; border-radius:50%; position:relative; display:grid; place-items:center; flex:0 0 auto;
  background:radial-gradient(circle at 50% 50%, rgba(56,190,255,.22), transparent 68%); animation:neuruPulse 2.6s ease-in-out infinite; }
#v2-top .brand .orb::after{ content:''; position:absolute; inset:-3px; border-radius:50%; pointer-events:none; box-shadow:0 0 20px rgba(56,190,255,.55), inset 0 0 12px rgba(124,92,255,.25); animation:neuruGlow 2.6s ease-in-out infinite; }
#v2-top .brand .orb svg{ position:relative; z-index:1; filter:drop-shadow(0 0 7px rgba(90,200,255,.65)); animation:neuruSpin 26s linear infinite; }
@keyframes neuruPulse{ 0%,100%{ transform:scale(1) } 50%{ transform:scale(1.1) } }
@keyframes neuruGlow{ 0%,100%{ opacity:.55 } 50%{ opacity:1 } }
@keyframes neuruSpin{ to{ transform:rotate(360deg) } }
.tb-sep{ width:1px; height:20px; background:rgba(120,150,255,.18); margin:0 3px; flex:0 0 auto }
.btn.pbtn.on{ border-color:var(--cyan); color:var(--cyan); box-shadow:0 0 12px rgba(57,230,255,.3) }
#v2-top .brand b{ font-size:17px; letter-spacing:.03em; color:#fff } #v2-top .brand span{ font-size:11px; color:var(--mut); display:block; margin-top:1px }
#v2-top .spacer{ flex:1 }
.kpi{ text-align:center; padding:2px 12px; border-left:1px solid rgba(120,150,255,.14); }
.kpi b{ font-size:20px; color:#fff; display:block; line-height:1 } .kpi span{ font-size:10px; color:var(--mut); text-transform:uppercase; letter-spacing:.1em }
.kpi.warn b{ color:var(--amber) } .kpi.crit b{ color:var(--red) } .kpi.ok b{ color:var(--green) }
/* master switch */
.master{ display:flex; align-items:center; gap:10px; padding:6px 12px; border-radius:12px; background:rgba(8,12,28,.5); border:1px solid rgba(120,150,255,.2); }
.master .lbl{ font-size:11px; color:var(--mut); text-transform:uppercase; letter-spacing:.1em }
/* voice config form (drawer) */
.vlbl{ display:block; font-size:11px; color:var(--mut); text-transform:uppercase; letter-spacing:.08em; margin:10px 0 4px }
.vmut{ text-transform:none; letter-spacing:0; color:#5b7091; font-size:10px }
.vin{ width:100%; padding:8px 10px; border-radius:9px; border:1px solid rgba(120,150,255,.25); background:rgba(6,10,22,.6); color:#dbe6f5; font:inherit; font-size:13px }
.vin:focus{ outline:none; border-color:var(--cyan) }
.vrow{ display:flex; align-items:center; gap:8px; margin-top:12px; font-size:13px; color:#cfe }
.sw{ position:relative; width:52px; height:28px; cursor:pointer } .sw input{ display:none }
.sw .track{ position:absolute; inset:0; border-radius:20px; background:#243056; transition:.25s; border:1px solid rgba(120,150,255,.3) }
.sw .thumb{ position:absolute; top:3px; left:3px; width:22px; height:22px; border-radius:50%; background:#8b97b8; transition:.25s; box-shadow:0 2px 6px rgba(0,0,0,.4) }
.sw input:checked + .track{ background:linear-gradient(90deg,var(--cyan),var(--violet)); border-color:transparent }
.sw input:checked + .track + .thumb, .sw input:checked ~ .thumb{ transform:translateX(24px); background:#fff }
/* small switch (channel/device rows) — proportional so the thumb never overflows its track */
.sw.sm{ width:40px; height:22px; flex:0 0 auto } .sw.sm .thumb{ width:16px; height:16px; top:3px; left:3px } .sw.sm input:checked ~ .thumb{ transform:translateX(18px) }

/* left column */
#v2-left{ grid-column:1; grid-row:2; display:flex; flex-direction:column; gap:14px; min-height:0; perspective:1500px; perspective-origin:15% 50%; }
/* ── Data filaments: energy rays from critical alerts to the core (2D overlay over the WebGL, under the panels) ── */
#filaments{ position:fixed; inset:0; z-index:1; pointer-events:none; width:100vw; height:100vh; overflow:visible; }
.fila{ fill:none; stroke:currentColor; stroke-width:2; opacity:.8; stroke-linecap:round; filter:drop-shadow(0 0 5px currentColor);
  stroke-dasharray:5 13; animation:filflow 1.1s linear infinite; }
@keyframes filflow{ to{ stroke-dashoffset:-18 } }
/* ── Holographic curved HUD for the Signal queue (Iron-Man visor feel; stays 100% interactive) ── */
.hud-curve{ transform-style:preserve-3d; transform-origin:left center; transition:transform .25s ease-out;
  transform: rotateY(calc(6deg + var(--px,0)*4deg)) rotateX(calc(var(--py,0)*-3deg));
  border:1px solid rgba(57,230,255,.22) !important; overflow:hidden;
  background:linear-gradient(105deg, rgba(12,22,44,.5), rgba(8,13,34,.28)) !important;
  box-shadow: inset 0 0 55px rgba(57,230,255,.05), inset 2px 0 0 rgba(57,230,255,.4), 0 0 42px rgba(57,230,255,.10), 0 18px 60px rgba(0,0,0,.5) !important; }
.hud-curve::before{ content:''; position:absolute; inset:0; z-index:3; pointer-events:none; border-radius:inherit;
  background:linear-gradient(90deg, transparent 52%, rgba(4,7,16,.4) 100%); }   /* curved-glass falloff on the right edge */
.hud-curve::after{ content:''; position:absolute; inset:0; z-index:3; pointer-events:none; border-radius:inherit; opacity:.5;
  background:repeating-linear-gradient(0deg, rgba(57,230,255,.05) 0 1px, transparent 1px 4px); animation:hudscan 8s linear infinite; }
@keyframes hudscan{ to{ background-position:0 -64px } }
.hud-curve > h3, .hud-curve > .body{ position:relative; z-index:4; }
.hud-curve .body{ transform-style:preserve-3d; }
.hud-curve .body .row{ transition:transform .2s ease-out, background .2s, box-shadow .2s; }
.hud-curve .body .row:hover{ transform:translateZ(20px); background:rgba(57,230,255,.06); box-shadow:0 6px 22px rgba(0,0,0,.45); }
/* ── MIRROR of .hud-curve for the RIGHT column (Live reasoning + Talk to NEURU) → symmetric visor, curves toward center ── */
.hud-curve-r{ transform-origin:right center;
  transform: rotateY(calc(-6deg + var(--px,0)*4deg)) rotateX(calc(var(--py,0)*-3deg));
  background:linear-gradient(255deg, rgba(12,22,44,.5), rgba(8,13,34,.28)) !important;
  box-shadow: inset 0 0 55px rgba(57,230,255,.05), inset -2px 0 0 rgba(57,230,255,.4), 0 0 42px rgba(57,230,255,.10), 0 18px 60px rgba(0,0,0,.5) !important; }
.hud-curve-r::before{ background:linear-gradient(270deg, transparent 52%, rgba(4,7,16,.4) 100%); }   /* curved-glass falloff on the LEFT edge (mirror) */
/* keep the interactive control surfaces above the glass pseudo-layers (tabs live in h3, already z-4) */
#chat.hud-curve-r > #chatlog, #chat.hud-curve-r > #chatin{ position:relative; z-index:4; }
#chat.hud-curve-r .ev, #transcript.hud-curve-r .ev{ transition:transform .2s ease-out, background .2s; }
#transcript.hud-curve-r .body .ev:hover{ transform:translateZ(14px); }
/* center reserved for the WebGL bot — a status ribbon floats at its bottom */
#v2-center{ grid-column:2; grid-row:2; display:flex; flex-direction:column; justify-content:flex-end; align-items:center; gap:12px; pointer-events:none; padding-bottom:66px; }
#v2-state{ pointer-events:auto; text-align:center; }
#v2-state .now{ font-size:13px; color:var(--cyan); letter-spacing:.05em; min-height:18px; text-shadow:0 0 12px rgba(56,225,255,.5); }
#v2-state .sub{ font-size:12px; color:var(--mut); margin-top:3px; max-width:520px; }
#v2-narrate{ pointer-events:auto; max-width:560px; padding:12px 18px; margin-bottom:6px; font-size:14px; line-height:1.5; color:#eaf2ff; text-align:center; opacity:0; transition:opacity .4s; }
#v2-narrate.show{ opacity:1 }
/* embedded voice control — docked at the bottom-center of the neural core; transparent so the aurora shows */
#v2-voice{ pointer-events:auto; width:400px; max-width:44vw; height:250px; }
#v2-voice iframe{ width:100%; height:100%; border:0; background:transparent; color-scheme:normal; }
/* ── LIVE TOOL panel: hidden until NEURU runs a tool, then fades in (never clutters idle screen) ── */
/* top-CENTER over the middle column (above the neural core, voice control below) → never covers the side frames */
#tool-hud{ position:fixed; left:50%; top:80px; transform:translateX(-50%) translateY(-12px); width:360px; max-width:34vw; z-index:6;
  background:linear-gradient(180deg,rgba(10,18,34,.5),rgba(6,10,22,.32)); border:1px solid rgba(57,230,255,.22); border-radius:16px;
  box-shadow:0 0 0 1px rgba(57,230,255,.05), 0 12px 50px rgba(0,0,0,.45); backdrop-filter:blur(12px); -webkit-backdrop-filter:blur(12px);
  padding:14px 16px; opacity:0; pointer-events:none; transition:opacity .4s ease, transform .4s ease; }
#tool-hud.show{ opacity:1; transform:translateX(-50%) translateY(0); pointer-events:auto; }
#tool-hud .th-head{ display:flex; align-items:center; gap:11px; }
.th-ico{ width:34px; height:34px; border-radius:10px; display:grid; place-items:center; font-size:16px;
  background:radial-gradient(circle at 40% 30%,rgba(57,230,255,.32),rgba(57,230,255,.04)); border:1px solid rgba(57,230,255,.3); box-shadow:0 0 16px rgba(57,230,255,.22); }
.th-titles{ flex:1 1 auto; min-width:0; } .th-tool{ font-size:13px; font-weight:600; letter-spacing:.04em; color:#eaf6ff; text-transform:capitalize; }
.th-sub{ font-size:11px; color:#7fa6c8; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.th-chan{ font-size:9px; text-transform:uppercase; letter-spacing:.12em; color:var(--cyan); border:1px solid rgba(57,230,255,.3); border-radius:999px; padding:3px 8px; white-space:nowrap; }
.th-body{ margin-top:12px; }
.hopchain{ display:flex; flex-direction:column; }
.hop{ display:flex; align-items:center; gap:11px; position:relative; padding:6px 0; }
.hop .dot{ width:14px; height:14px; border-radius:50%; flex:0 0 auto; background:#2a3c66; box-shadow:0 0 0 3px rgba(57,230,255,.07); position:relative; z-index:2; }
.hop.ok .dot{ background:#39e6ff; box-shadow:0 0 12px rgba(57,230,255,.7),0 0 0 3px rgba(57,230,255,.15); }
.hop.end-delivered .dot{ background:#4fe0a0; box-shadow:0 0 12px rgba(79,224,160,.85) }
.hop.end-internet .dot{ background:#7aa2ff; box-shadow:0 0 12px rgba(122,162,255,.85) }
.hop.end-bad .dot{ background:#ff5a6e; box-shadow:0 0 12px rgba(255,90,110,.85) }
.hop .conn{ position:absolute; left:6px; top:-9px; width:2px; height:18px; background:linear-gradient(rgba(57,230,255,.04),rgba(57,230,255,.5)); z-index:1 }
.hop:first-child .conn,.hop:first-child .flow{ display:none }
.hop .htxt{ min-width:0 } .hop .hn{ font-size:12px; color:#dbe6f5 } .hop .hr{ font-size:10px; color:#7089a8 }
.hop .flow{ position:absolute; left:5px; width:4px; height:4px; border-radius:50%; background:#8bf3ff; box-shadow:0 0 8px #39e6ff; animation:hopflow 1.1s linear infinite }
@keyframes hopflow{ 0%{ top:-9px; opacity:0 } 25%{ opacity:1 } 100%{ top:9px; opacity:0 } }
.th-verdict{ margin-top:10px; text-align:center; font-size:11px; letter-spacing:.08em; text-transform:uppercase; padding:6px; border-radius:8px }
.th-verdict.good{ color:#7ff0c0; background:rgba(79,224,160,.1); border:1px solid rgba(79,224,160,.3) }
.th-verdict.bad{ color:#ffb3bd; background:rgba(255,90,110,.1); border:1px solid rgba(255,90,110,.3) }
.th-verdict.net{ color:#aec4ff; background:rgba(122,162,255,.1); border:1px solid rgba(122,162,255,.3) }
.th-rows{ display:flex; flex-direction:column; gap:6px }
.th-row{ display:flex; justify-content:space-between; gap:8px; font-size:12px; padding:6px 8px; border-radius:8px; background:rgba(255,255,255,.03); border:1px solid rgba(120,150,255,.08) }
.th-row b{ color:#dbe6f5; font-weight:600 } .th-row span{ color:#7fa6c8; text-align:right; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap }
.th-term{ font-family:ui-monospace,Menlo,Consolas,monospace; font-size:11px; color:#9fe8c8; background:rgba(0,0,0,.35); border:1px solid rgba(57,230,255,.12); border-radius:8px; padding:8px 10px; max-height:150px; overflow:auto; white-space:pre-wrap }
.th-working{ display:flex; align-items:center; gap:10px; font-size:12px; color:var(--cyan); letter-spacing:.03em; padding:4px 2px }
.th-spin{ width:15px; height:15px; border-radius:50%; border:2px solid rgba(57,230,255,.22); border-top-color:var(--cyan); animation:thspin .8s linear infinite; flex:0 0 auto }
@keyframes thspin{ to{ transform:rotate(360deg) } }
/* ── LOCAL VISION: camera preview box + passive-state edge glow (the presence ambiance lives in WebGL) ── */
/* right:410 clears the 380px right column (+gap); top:120 clears the top KPI/button row → lands in the free
   center-upper starfield (never over the queue, chat, buttons, or Live Reasoning). */
#vision-box{ position:fixed; right:410px; top:120px; width:2px; height:2px; z-index:10; overflow:hidden; border-radius:12px; opacity:0; pointer-events:none; transition:width .3s,height .3s,opacity .3s; }
#vision-box.preview{ width:190px; height:164px; opacity:1; pointer-events:auto; border:1px solid rgba(57,230,255,.3); box-shadow:0 10px 40px rgba(0,0,0,.55); background:#05060e; }
#vision-box iframe{ width:100%; height:100%; border:0; background:transparent; }
#vision-veil{ position:fixed; inset:0; z-index:1; pointer-events:none; opacity:0; transition:opacity .8s; }
body.vs-passive #vision-veil{ opacity:1; animation:vspulse 2.6s ease-in-out infinite; }
@keyframes vspulse{ 0%,100%{ box-shadow:inset 0 0 120px 30px rgba(255,180,90,.06) } 50%{ box-shadow:inset 0 0 210px 65px rgba(255,180,90,.22) } }
body.vs-stranger #vision-veil{ opacity:1; animation:vsred 1.8s ease-in-out infinite; }
@keyframes vsred{ 0%,100%{ box-shadow:inset 0 0 130px 30px rgba(255,60,90,.10) } 50%{ box-shadow:inset 0 0 230px 70px rgba(255,60,90,.30) } }
#vision-btn.on{ border-color:var(--cyan); box-shadow:0 0 12px rgba(57,230,255,.3) } #vision-preview-btn.on{ color:var(--cyan) }
/* ── SURGICAL X-RAY — full-screen living 3D anatomy of one node ── */
#xray-panel{ position:fixed; inset:0; z-index:9; display:none; }
#xray-panel.show{ display:block; }
/* #v2-stage is a z-index:0 stacking context → its X-Ray child is trapped under #nm-topbar (z1000). When the X-Ray
   takes over, lift the whole stage above the topbar so the close ✕ is always reachable (in AND out of fullscreen). */
body.xr-open #v2-stage{ z-index:2000 !important; }
#xr-veil{ position:absolute; inset:0; background:radial-gradient(120% 90% at 50% 42%, rgba(8,12,28,.66), rgba(2,4,12,.95)); backdrop-filter:blur(3px); -webkit-backdrop-filter:blur(3px); }
#xr-canvas{ position:absolute; inset:0; width:100%; height:100%; display:block; }
#xr-top{ position:absolute; top:0; left:0; right:0; z-index:6; display:flex; align-items:center; gap:12px; padding:15px 22px; background:linear-gradient(180deg,rgba(3,6,16,.82),transparent); }
.xr-ico{ width:36px; height:36px; border-radius:11px; display:grid; place-items:center; font-size:17px; background:radial-gradient(circle at 40% 30%,rgba(120,200,255,.35),rgba(90,170,255,.05)); border:1px solid rgba(120,200,255,.32); }
.xr-titles{ flex:1 1 auto; min-width:0 } .xr-name{ font-size:16px; font-weight:700; color:#eaf2ff; letter-spacing:.01em } .xr-sub{ font-size:12px; color:#8fb2d8; white-space:nowrap; overflow:hidden; text-overflow:ellipsis }
.xr-x{ cursor:pointer; flex:0 0 auto; color:#ffd7de; font-size:16px; width:36px; height:36px; border-radius:50%; display:grid; place-items:center; background:rgba(255,80,110,.16); border:1px solid rgba(255,90,120,.45); transition:.15s } .xr-x:hover{ background:rgba(255,80,110,.34); box-shadow:0 0 18px rgba(255,90,120,.45); transform:scale(1.06) }
/* floating metric labels anchored to each 3D organ */
#xr-labels{ position:absolute; inset:0; z-index:2; pointer-events:none; overflow:hidden }
.xr-lab{ position:absolute; top:0; left:0; display:flex; align-items:center; gap:6px; padding:4px 10px; border-radius:999px; white-space:nowrap; will-change:transform,opacity; transition:opacity .25s;
  background:rgba(6,12,26,.66); border:1px solid rgba(120,180,255,.32); box-shadow:0 0 16px rgba(60,160,255,.22); backdrop-filter:blur(3px); -webkit-backdrop-filter:blur(3px); font-size:12px; color:#eaf6ff; font-variant-numeric:tabular-nums }
.xr-lab .i{ font-size:13px } .xr-lab b{ font-weight:600; letter-spacing:.01em } .xr-lab.hot{ border-color:rgba(255,120,140,.5); box-shadow:0 0 16px rgba(255,90,120,.3) }
#xr-scan{ position:absolute; left:0; right:0; top:8%; height:2px; z-index:2; pointer-events:none; opacity:0; background:linear-gradient(90deg,transparent,rgba(120,230,255,.95),transparent); box-shadow:0 0 26px 7px rgba(90,210,255,.55); }
#xray-panel.xr-scanning #xr-scan{ animation:xrscan 1.4s ease-in-out; }
@keyframes xrscan{ 0%{ top:8%; opacity:0 } 8%{ opacity:1 } 90%{ opacity:1 } 100%{ top:90%; opacity:0 } }
/* left rail — subsystem organs */
#xr-rail{ position:absolute; left:22px; top:74px; z-index:3; display:none; flex-direction:column; gap:7px; width:192px; }
.xrr{ position:relative; display:flex; align-items:center; gap:10px; padding:9px 12px; border-radius:12px; cursor:pointer; transition:.15s; background:linear-gradient(100deg,rgba(12,22,44,.52),rgba(8,13,34,.3)); border:1px solid rgba(120,150,255,.14); }
.xrr:hover{ border-color:rgba(120,200,255,.5); transform:translateX(4px) } .xrr.on{ border-color:var(--cyan); box-shadow:0 0 16px rgba(57,230,255,.22) }
.xrr .ic{ font-size:16px; width:22px; text-align:center } .xrr .lb{ flex:1 1 auto; font-size:12px; color:#dbe6f5 } .xrr .vl{ font-size:11px; color:#9fd0ff; font-variant-numeric:tabular-nums }
/* detail HUD (organ dive) */
#xr-detail{ position:absolute; right:22px; top:74px; bottom:26px; z-index:3; width:344px; display:none; flex-direction:column; border-radius:16px; overflow:hidden;
  background:linear-gradient(180deg,rgba(10,18,34,.8),rgba(6,10,22,.62)); border:1px solid rgba(120,150,255,.2); box-shadow:0 22px 70px rgba(0,0,0,.55); backdrop-filter:blur(14px); -webkit-backdrop-filter:blur(14px); }
#xr-detail.show{ display:flex; }
#xr-detail .dh{ padding:14px 16px; border-bottom:1px solid rgba(120,150,255,.12); display:flex; align-items:center; gap:10px; font-size:14px; color:#eaf2ff; font-weight:600 }
#xr-detail .db{ padding:14px 16px; overflow:auto; }
.xr-metric{ margin-bottom:14px } .xr-metric .k{ font-size:10px; text-transform:uppercase; letter-spacing:.1em; color:var(--mut); margin-bottom:5px; display:flex; justify-content:space-between } .xr-metric .k b{ color:#dbe6f5; font-weight:600; font-variant-numeric:tabular-nums }
.xrbar{ position:relative; height:8px; border-radius:999px; background:rgba(255,255,255,.06); overflow:hidden; margin:4px 0 }
.xrbar > i{ position:absolute; left:0; top:0; bottom:0; border-radius:999px; background:linear-gradient(90deg,#39e6ff,#5fa8ff); transition:width .4s }
.xrbar.warn > i{ background:linear-gradient(90deg,#ffb454,#ff8a3d) } .xrbar.crit > i{ background:linear-gradient(90deg,#ff5a6e,#ff2d55) }
.xr-cores{ display:grid; grid-template-columns:repeat(8,1fr); gap:4px } .xr-core{ height:26px; border-radius:4px; background:rgba(255,255,255,.05); position:relative; overflow:hidden } .xr-core > i{ position:absolute; left:0; right:0; bottom:0; background:linear-gradient(0deg,#39e6ff,#5fa8ff) }
.xr-hint{ position:absolute; bottom:12px; left:50%; transform:translateX(-50%); z-index:3; font-size:11px; color:#6f93b8; letter-spacing:.04em; pointer-events:none; text-shadow:0 1px 8px #000 }
.xr-proc{ display:flex; align-items:center; gap:8px; padding:5px 0; font-size:12px; color:#dbe6f5; font-family:ui-monospace,Menlo,monospace }
.xr-proc .pn{ flex:1 1 auto; white-space:nowrap; overflow:hidden; text-overflow:ellipsis } .xr-proc .pv{ font-size:10px; color:#8fa6c8; white-space:nowrap }
.xr-kill{ flex:0 0 auto; border:1px solid rgba(255,90,110,.35); background:rgba(255,60,90,.1); color:#ffb3bd; border-radius:7px; padding:2px 7px; font-size:11px; cursor:pointer; transition:.15s } .xr-kill:hover{ background:rgba(255,60,90,.28) }
/* node picker */
#xr-picker{ position:absolute; left:50%; top:50%; transform:translate(-50%,-50%); z-index:3; width:min(720px,88vw); max-height:72vh; overflow:auto; display:none; grid-template-columns:repeat(auto-fill,minmax(210px,1fr)); gap:8px; padding:8px; }
#xray-panel.pick #xr-picker{ display:grid; }
.xr-pick{ display:flex; align-items:center; gap:9px; padding:11px 13px; border-radius:12px; cursor:pointer; background:rgba(12,20,40,.6); border:1px solid rgba(120,150,255,.14); transition:.15s }
.xr-pick:hover{ border-color:rgba(120,200,255,.55); box-shadow:0 0 16px rgba(90,200,255,.2); transform:translateY(-2px) }
.xr-pick .nm{ min-width:0; flex:1 1 auto } .xr-pick b{ font-size:13px; color:#eaf2ff; display:block; white-space:nowrap; overflow:hidden; text-overflow:ellipsis } .xr-pick .ip{ font-size:10px; color:var(--mut) }
.xr-pick .k{ font-size:9px; text-transform:uppercase; letter-spacing:.08em; color:var(--mut); border:1px solid rgba(120,150,255,.2); border-radius:999px; padding:2px 7px; flex:0 0 auto }
/* ── NETWORK TOPOLOGY MAP — interconnected 3D (routing_command aesthetic) ── */
#topo-panel{ position:fixed; inset:0; z-index:9; display:none; } #topo-panel.show{ display:block; }
#topo-veil{ position:absolute; inset:0; background:radial-gradient(120% 90% at 50% 22%, rgba(8,14,30,.5), rgba(3,5,13,.96)); }
#topo-canvas{ position:absolute; inset:0; width:100%; height:100%; display:block; }
#topo-top{ position:absolute; top:0; left:0; right:0; z-index:6; display:flex; align-items:center; gap:12px; padding:15px 22px; background:linear-gradient(180deg,rgba(3,6,16,.82),transparent); }
#topo-labels{ position:absolute; inset:0; z-index:2; pointer-events:none; overflow:hidden; }
.tn-lab{ position:absolute; top:0; left:0; transform:translate(-50%,-160%); white-space:nowrap; font-size:11px; color:#cfe0f5; text-shadow:0 1px 6px #000; pointer-events:none; padding:1px 6px; border-radius:6px; background:rgba(6,10,22,.45); transition:opacity .2s; }
.tn-lab.rt{ font-size:12px; color:#eaf1ff; font-weight:600; } .tn-lab.down{ color:#ff9aa6; }
#topo-rail{ position:absolute; left:22px; top:74px; z-index:3; display:none; flex-direction:column; gap:6px; width:210px; max-height:calc(100vh - 120px); overflow:auto; padding-right:4px; }
.tn-chip{ display:flex; align-items:center; gap:9px; padding:7px 10px; border-radius:9px; cursor:pointer; background:rgba(12,20,40,.5); border:1px solid rgba(120,150,255,.12); font-size:12px; color:#dbe6f5; transition:.15s } .tn-chip:hover{ border-color:rgba(120,200,255,.5); transform:translateX(3px) } .tn-chip.on{ border-color:var(--cyan) }
.tn-chip .d{ width:8px; height:8px; border-radius:50%; flex:0 0 auto } .tn-chip .nm{ flex:1 1 auto; white-space:nowrap; overflow:hidden; text-overflow:ellipsis } .tn-chip .k{ font-size:9px; color:var(--mut); text-transform:uppercase }
#topo-detail{ position:absolute; right:22px; top:74px; bottom:26px; z-index:3; width:330px; display:none; flex-direction:column; border-radius:16px; overflow:hidden; background:linear-gradient(180deg,rgba(10,18,34,.8),rgba(6,10,22,.62)); border:1px solid rgba(120,150,255,.2); box-shadow:0 22px 70px rgba(0,0,0,.55); backdrop-filter:blur(14px); -webkit-backdrop-filter:blur(14px); }
#topo-detail.show{ display:flex; } #topo-detail .dh{ padding:14px 16px; border-bottom:1px solid rgba(120,150,255,.12); font-size:14px; color:#eaf2ff; font-weight:600; display:flex; align-items:center; gap:9px } #topo-detail .db{ padding:14px 16px; overflow:auto }
.topo-hint{ position:absolute; bottom:12px; left:50%; transform:translateX(-50%); z-index:3; font-size:11px; color:#6f93b8; pointer-events:none; text-shadow:0 1px 8px #000 }
/* ── LIVE TRAFFIC — laser-per-interface (traffic_viewer.php aesthetic) ── */
#traf-panel{ position:fixed; inset:0; z-index:9; display:none; } #traf-panel.show{ display:block; }
#traf-veil{ position:absolute; inset:0; background:radial-gradient(120% 90% at 50% 30%, rgba(6,12,24,.5), rgba(3,5,12,.97)); }
#traf-canvas{ position:absolute; inset:0; width:100%; height:100%; display:block; }
#traf-top{ position:absolute; top:0; left:0; right:0; z-index:6; display:flex; align-items:center; gap:12px; padding:15px 22px; background:linear-gradient(180deg,rgba(3,6,16,.82),transparent); }
#traf-labels{ position:absolute; inset:0; z-index:2; pointer-events:none; overflow:hidden; }
.tv-lab{ position:absolute; top:0; left:0; transform:translate(-100%,-50%); white-space:nowrap; font-size:11px; padding:2px 8px; border-radius:7px; background:rgba(6,10,22,.6); border:1px solid rgba(120,150,255,.16); pointer-events:none; transition:opacity .2s; }
.tv-lab b{ color:#eaf1ff; font-weight:600 } .tv-lab .i{ color:#36e3d0 } .tv-lab .o{ color:#ff9d4d } .tv-lab.down b{ color:#ff9aa6 }
#traf-rail{ position:absolute; left:22px; top:74px; z-index:3; display:none; flex-direction:column; gap:6px; width:220px; max-height:calc(100vh - 120px); overflow:auto; padding-right:4px; }
.tv-chip{ display:flex; align-items:center; gap:8px; padding:7px 10px; border-radius:9px; cursor:pointer; background:rgba(12,20,40,.5); border:1px solid rgba(120,150,255,.12); font-size:12px; color:#dbe6f5; transition:.15s } .tv-chip:hover{ border-color:rgba(120,200,255,.5) } .tv-chip.on{ border-color:var(--cyan) }
.tv-chip .nm{ flex:1 1 auto; white-space:nowrap; overflow:hidden; text-overflow:ellipsis } .tv-chip .r{ font-size:10px; font-variant-numeric:tabular-nums } .tv-chip .r .i{ color:#36e3d0 } .tv-chip .r .o{ color:#ff9d4d }
.traf-hint{ position:absolute; bottom:12px; left:50%; transform:translateX(-50%); z-index:3; font-size:11px; color:#6f93b8; pointer-events:none; text-shadow:0 1px 8px #000 }
#traf-picker{ position:absolute; left:50%; top:50%; transform:translate(-50%,-50%); z-index:4; width:min(720px,88vw); max-height:72vh; overflow:auto; display:none; grid-template-columns:repeat(auto-fill,minmax(210px,1fr)); gap:8px; padding:8px; }
#traf-panel.pick #traf-picker{ display:grid; }
/* ── Containers layer (4th overlay) ── */
#cont-panel{ position:fixed; inset:0; z-index:9; display:none; } #cont-panel.show{ display:block; }
#cont-veil{ position:absolute; inset:0; background:radial-gradient(120% 90% at 50% 30%, rgba(6,12,24,.5), rgba(3,5,12,.97)); }
#cont-canvas{ position:absolute; inset:0; width:100%; height:100%; display:block; }
#cont-labels{ position:absolute; inset:0; z-index:2; pointer-events:none; overflow:hidden; }
#cont-top{ position:absolute; top:0; left:0; right:0; z-index:6; display:flex; align-items:center; gap:12px; padding:15px 22px; background:linear-gradient(180deg,rgba(3,6,16,.82),transparent); }
#cont-rail{ position:absolute; left:22px; top:74px; z-index:3; display:none; flex-direction:column; gap:4px; width:240px; max-height:calc(100vh - 120px); overflow:auto; padding-right:4px; }
#cont-detail{ position:absolute; right:22px; top:74px; z-index:5; display:none; width:300px; max-height:calc(100vh - 120px); overflow:auto; background:rgba(8,14,28,.88); border:1px solid rgba(120,150,255,.18); border-radius:12px; padding:14px; color:#dbe6f5; font-size:12px; backdrop-filter:blur(8px); }
#cont-detail.show{ display:block; }
#cont-detail h4{ margin:0 0 8px; font-size:13px; color:#8bf3ff; word-break:break-all; }
#cont-detail .kv{ display:flex; justify-content:space-between; gap:10px; padding:3px 0; border-bottom:1px solid rgba(255,255,255,.05); }
#cont-detail .kv b{ font-weight:600; color:#cfe; font-variant-numeric:tabular-nums; text-align:right; }
#cont-detail .danger, #cont-detail .danger b{ color:#ff5a6e; }
.cont-hint{ position:absolute; bottom:12px; left:50%; transform:translateX(-50%); z-index:3; font-size:11px; color:#6f93b8; pointer-events:none; text-shadow:0 1px 8px #000 }
.cv-chip{ display:flex; align-items:center; gap:8px; padding:6px 10px; border-radius:9px; cursor:pointer; background:rgba(12,20,40,.5); border:1px solid rgba(120,150,255,.12); font-size:12px; color:#dbe6f5; transition:.15s } .cv-chip:hover{ border-color:rgba(120,200,255,.5) } .cv-chip.on{ border-color:var(--cyan) }
.cv-chip .nm{ flex:1 1 auto; white-space:nowrap; overflow:hidden; text-overflow:ellipsis } .cv-chip .st{ width:8px; height:8px; border-radius:50%; flex:0 0 auto }
.cv-lab{ position:absolute; transform:translate(-50%,-50%); font-size:11px; color:#dbe6f5; text-shadow:0 1px 6px #000, 0 0 3px #000; pointer-events:none; white-space:nowrap; }
/* ── Net Tools layer (5th overlay — embeds the tool pages in WebGL) ── */
#nt-panel{ position:fixed; inset:0; z-index:9; display:none; } #nt-panel.show{ display:block; }
#nt-veil{ position:absolute; inset:0; background:radial-gradient(120% 90% at 50% 30%, rgba(6,12,24,.55), rgba(3,5,12,.98)); }
#nt-frame{ position:absolute; left:0; right:0; top:56px; bottom:0; width:100%; height:calc(100% - 56px); border:0; background:transparent; }
#nt-top{ position:absolute; top:0; left:0; right:0; height:56px; z-index:6; display:flex; align-items:center; gap:10px; padding:9px 18px; background:linear-gradient(180deg,rgba(3,6,16,.92),rgba(3,6,16,.4)); }
#nt-tabs{ display:flex; gap:6px; margin-left:8px; flex-wrap:wrap; }
.nt-tab{ padding:6px 11px; border-radius:8px; cursor:pointer; font-size:12px; color:#cfe4ff; background:rgba(12,20,40,.5); border:1px solid rgba(120,150,255,.14); display:flex; align-items:center; gap:6px; transition:.15s; } .nt-tab:hover{ border-color:rgba(120,200,255,.5) } .nt-tab.on{ background:rgba(77,163,255,.22); border-color:var(--cyan) }
#nt-target{ font-family:monospace; font-size:12px; color:#8bf3ff; }
/* ── TIMELINE DVR bar (bottom-center; rewinds the whole cockpit) ── */
#tt-bar{ position:fixed; left:50%; bottom:14px; transform:translateX(-50%); z-index:8; display:flex; align-items:center; gap:12px;
  width:min(640px,72vw); padding:9px 16px; border-radius:14px; background:linear-gradient(180deg,rgba(10,18,34,.6),rgba(6,10,22,.42));
  border:1px solid rgba(57,230,255,.18); box-shadow:0 8px 40px rgba(0,0,0,.4); backdrop-filter:blur(12px); -webkit-backdrop-filter:blur(12px); }
.tt-btn{ flex:0 0 auto; width:34px; height:34px; border-radius:50%; border:1px solid rgba(57,230,255,.3); background:rgba(8,14,30,.6); color:var(--cyan);
  font-size:14px; cursor:pointer; display:grid; place-items:center; transition:.15s; }
.tt-btn:hover{ border-color:var(--cyan); box-shadow:0 0 14px rgba(57,230,255,.3) }
.tt-btn.tt-live{ width:auto; padding:0 12px; border-radius:999px; color:#ffd7dd; border-color:rgba(255,90,110,.4); font-size:11px; letter-spacing:.05em; gap:5px }
#tt-slider{ flex:1 1 auto; -webkit-appearance:none; appearance:none; height:5px; border-radius:999px; outline:none; cursor:pointer;
  background:linear-gradient(90deg,rgba(57,230,255,.5),rgba(155,107,255,.5)); }
#tt-slider::-webkit-slider-thumb{ -webkit-appearance:none; width:16px; height:16px; border-radius:50%; background:radial-gradient(circle at 40% 35%,#8bf3ff,#0aa4c9); box-shadow:0 0 12px rgba(57,230,255,.8); cursor:pointer; border:2px solid #041018 }
#tt-slider::-moz-range-thumb{ width:16px; height:16px; border-radius:50%; background:#39e6ff; box-shadow:0 0 12px rgba(57,230,255,.8); cursor:pointer; border:2px solid #041018 }
.tt-time{ flex:0 0 auto; min-width:96px; text-align:center; font-size:11px; letter-spacing:.06em; color:#5fe0a0; font-variant-numeric:tabular-nums; }
.tt-time.past{ color:#e6b45a; }
/* subtle "rewound" cue on the whole stage */
body.tt-rewound #v2-state{ border-color:rgba(230,180,90,.4); box-shadow:0 0 24px rgba(230,180,90,.12) }
/* right column */
#v2-right{ grid-column:3; grid-row:2; display:flex; flex-direction:column; gap:14px; min-height:0; perspective:1500px; perspective-origin:85% 50%; }

/* transcript */
#transcript{ flex:1 1 60%; }
.ev{ display:flex; gap:9px; padding:6px 4px; border-bottom:1px solid rgba(120,150,255,.06); font-size:12.5px; animation:evin .35s ease; }
@keyframes evin{ from{opacity:0; transform:translateY(6px)} to{opacity:1;transform:none} }
.ev .ph{ flex:0 0 auto; width:20px; text-align:center; font-size:12px }
.ev .tx{ color:#d6def5; line-height:1.4; word-break:break-word }
.ev.think .ph{ color:var(--cyan) } .ev.observe .ph{ color:#6fb3ff } .ev.tool .ph{ color:#6fb3ff }
.ev.narrate .ph{ color:var(--violet) } .ev.narrate .tx{ color:#eadcff }
.ev.act .ph{ color:var(--amber) } .ev.result .ph{ color:var(--green) } .ev.error .ph{ color:var(--red) }
.ev .nn{ color:var(--mut); font-size:10.5px }
/* grouped session cards in the transcript */
.sess-card{ border:1px solid rgba(120,150,255,.12); border-radius:11px; margin:0 0 9px; overflow:hidden; background:rgba(120,150,255,.03); animation:evin .35s ease; }
.sess-card.collapsed .sess-events{ display:none }
.sess-head{ display:flex; align-items:center; gap:8px; padding:8px 11px; cursor:pointer; font-size:12px; }
.sess-head:hover{ background:rgba(120,150,255,.06) }
.sess-head .chev{ font-size:10px; color:var(--mut); transition:transform .2s }
.sess-card.collapsed .sess-head .chev{ transform:rotate(-90deg) }
.sess-head .sn{ color:#eaf2ff; font-weight:600 }
.sess-status{ margin-left:auto; font-size:9.5px; padding:2px 8px; border-radius:12px; text-transform:uppercase; letter-spacing:.05em }
.sess-status.ss-active{ background:rgba(56,225,255,.16); color:var(--cyan) }
.sess-status.ss-done{ background:rgba(67,224,138,.16); color:var(--green) }
.sess-status.ss-wait{ background:rgba(255,180,84,.18); color:var(--amber) }
.sess-status.ss-err{ background:rgba(255,92,122,.18); color:var(--red) }
.sess-count{ font-size:10px; color:var(--mut); min-width:16px; text-align:center; background:rgba(120,150,255,.1); border-radius:8px; padding:1px 5px }
.sess-events{ padding:2px 10px 8px; max-height:300px; overflow:auto }
.sess-events .ev{ border-bottom:1px solid rgba(120,150,255,.05) }
.hist-item{ border:1px solid rgba(120,150,255,.1); border-radius:10px; margin-bottom:7px; overflow:hidden }
.hist-head{ display:flex; align-items:center; gap:8px; padding:8px 10px; cursor:pointer; font-size:12px }
.hist-head:hover{ background:rgba(120,150,255,.06) }
.hist-head b{ color:#eaf2ff }
.hist-time{ margin-left:auto; color:var(--mut); font-size:10.5px }
.hist-sum{ padding:0 10px 8px; font-size:11.5px; color:var(--mut); line-height:1.45 }
.hist-events{ padding:4px 10px 8px; max-height:260px; overflow:auto; border-top:1px solid rgba(120,150,255,.08) }

/* chat */
#chat{ flex:1 1 40%; min-height:180px; }
#chatlog{ flex:1 1 auto; overflow:auto; padding:10px 12px; display:flex; flex-direction:column; gap:8px; }
.msg{ max-width:86%; padding:8px 12px; border-radius:14px; font-size:13px; line-height:1.45; }
.msg.user{ align-self:flex-end; background:linear-gradient(135deg,rgba(56,225,255,.16),rgba(155,107,255,.16)); border:1px solid rgba(120,150,255,.25); color:#eaf3ff }
.msg.bot{ align-self:flex-start; background:rgba(8,12,28,.6); border:1px solid rgba(120,150,255,.14); color:#dfe7fb }
.msg.bot .cmd{ margin-top:6px; font-size:11px; color:var(--amber) }
#chatin{ display:flex; gap:8px; padding:10px 12px; border-top:1px solid rgba(120,150,255,.1) }
#chatin input{ flex:1; background:rgba(6,9,20,.7); border:1px solid rgba(120,150,255,.22); border-radius:12px; padding:9px 12px; color:#fff; font-size:13px; outline:none }
#chatin input:focus{ border-color:var(--cyan) }
.btn{ cursor:pointer; border:none; border-radius:11px; padding:8px 14px; font-size:12.5px; font-weight:600; color:#06111f; background:linear-gradient(90deg,var(--cyan),#7fd0ff); transition:.2s; }
.btn:hover{ filter:brightness(1.12) } .btn.ghost{ background:rgba(120,150,255,.12); color:#cfe0ff; border:1px solid rgba(120,150,255,.25) }
.btn.sm{ padding:5px 10px; font-size:11px }

/* signal + device rows */
.row{ display:flex; align-items:center; gap:8px; padding:7px 6px; border-radius:9px; font-size:12.5px; }
.row:hover{ background:rgba(120,150,255,.06) }
.dot{ width:8px; height:8px; border-radius:50%; flex:0 0 auto } .dot.critical{ background:var(--red); box-shadow:0 0 8px var(--red) } .dot.warning{ background:var(--amber) } .dot.info{ background:#6fb3ff }
.row .t{ flex:1 1 auto; min-width:0; overflow:hidden } .row .t b{ display:block; color:#e9eefb; font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis }
.row .t span{ display:block; color:var(--mut); font-size:11px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis }
.badge{ flex:0 0 auto; white-space:nowrap; font-size:10px; padding:2px 7px; border-radius:20px; text-transform:uppercase; letter-spacing:.06em }
.row .btn.sm{ flex:0 0 auto }
.badge.new{ background:rgba(255,180,84,.16); color:var(--amber) } .badge.investigating{ background:rgba(56,225,255,.16); color:var(--cyan) }
.badge.proposed{ background:rgba(155,107,255,.18); color:#c8b0ff } .badge.resolved{ background:rgba(67,224,138,.16); color:var(--green) }
.badge.acted{ background:rgba(111,179,255,.16); color:#8fd0ff }
.row.ch-passive{ opacity:.6 }
.ch-tag{ font-size:8px; font-weight:700; padding:1px 6px; border-radius:10px; background:rgba(139,151,184,.2); color:var(--mut); text-transform:uppercase; letter-spacing:.05em; vertical-align:middle; margin-left:5px }
.src-pill{ font-size:9.5px; font-weight:600; color:var(--cyan); background:rgba(56,225,255,.1); padding:1px 6px; border-radius:8px } .badge.stale{ background:rgba(139,151,184,.16); color:var(--mut) }
/* tabs */
.tabs{ display:flex; gap:6px; padding:8px 10px 0 } .tab{ cursor:pointer; padding:6px 12px; font-size:11.5px; color:var(--mut); border-radius:9px 9px 0 0; border:1px solid transparent }
.tab.on{ color:#fff; background:rgba(120,150,255,.1); border-color:rgba(120,150,255,.18); border-bottom:none }
.tabpane{ display:none } .tabpane.on{ display:flex; flex-direction:column; min-height:0; flex:1 }
select,.mini{ background:rgba(6,9,20,.7); border:1px solid rgba(120,150,255,.22); border-radius:8px; color:#cfe0ff; font-size:11.5px; padding:4px 7px; outline:none }
.chip{ font-size:10.5px; padding:3px 8px; border-radius:16px; border:1px solid rgba(120,150,255,.25); color:var(--mut); cursor:pointer }
.chip.on{ background:linear-gradient(90deg,rgba(56,225,255,.25),rgba(155,107,255,.25)); color:#fff; border-color:transparent }
.muted{ color:var(--mut); font-size:12px; padding:10px; text-align:center }
.tier{ font-size:10px; padding:2px 7px; border-radius:14px }
.tier.observe{ background:rgba(111,179,255,.14); color:#6fb3ff } .tier.copilot{ background:rgba(255,180,84,.16); color:var(--amber) } .tier.autopilot{ background:rgba(67,224,138,.16); color:var(--green) }
.disabled-veil{ position:fixed; inset:0; z-index:5; display:none; align-items:center; justify-content:center; background:rgba(4,5,13,.55); backdrop-filter:blur(3px) }
a.back{ position:fixed; top:16px; right:18px; z-index:6; color:var(--mut); text-decoration:none; font-size:12px }
a.back:hover{ color:#fff }
@media (max-width:1200px){ .v2-hud{ grid-template-columns:1fr; grid-template-rows:auto auto auto auto; } #v2-left,#v2-right{ grid-column:1 } #v2-center{ display:none } }
<?= function_exists('nm_chrome_css') ? nm_chrome_css() : '' ?>
</style></head><body>
<?php include('header.php'); ?>
<!-- everything below lives INSIDE #v2-stage so Fullscreen shows ONLY the cockpit (no header),
     exactly like aiopilot.php / command.php fullscreen their #cc-stage — max consistency. -->
<div id="v2-stage">
<canvas id="nm-stage"></canvas>

<div class="v2-hud">
  <!-- TOP BAR -->
  <div id="v2-top" class="glass">
    <div class="brand"><div class="orb"><?= function_exists('nm_logo_svg') ? nm_logo_svg(36) : '' ?></div><div><b>NEURU</b><span>Commander · autonomous NOC</span></div></div>
    <div class="spacer"></div>
    <div class="kpi"><b id="k-fleet">—</b><span>Fleet</span></div>
    <div class="kpi warn"><b id="k-open">—</b><span>Open</span></div>
    <div class="kpi crit"><b id="k-inv">—</b><span>Investigating</span></div>
    <div class="kpi"><b id="k-prop">—</b><span>Awaiting you</span></div>
    <div class="kpi ok"><b id="k-rules">—</b><span>Rules</span></div>
    <button class="btn ghost sm" id="scan-btn" onclick="doScan(this)" title="Scan the signal bus now"><i class="fa-solid fa-radar"></i> Scan now</button>
    <button class="btn ghost sm" id="talk-btn" onclick="openVoice()" title="Talk to NEURU by voice"><i class="fa-solid fa-microphone"></i> Talk</button>
    <button class="btn ghost sm" id="xray-btn" onclick="openXray()" title="Surgical X-Ray — live 3D anatomy of any node (CPU/mem/GPU/net/disk/thermals)"><i class="fa-solid fa-dna"></i> X-Ray</button>
    <button class="btn ghost sm" id="topo-btn" onclick="openTopo('all')" title="Network Topology — interactive 3D map of every node interconnected"><i class="fa-solid fa-diagram-project"></i> Map</button>
    <button class="btn ghost sm" id="traf-btn" onclick="openTraffic('')" title="Live Traffic — animated laser per interface across ALL monitored nodes (say: 'el tráfico del core router', 'la interfaz 1')"><i class="fa-solid fa-bolt"></i> Traffic</button>
    <button class="btn ghost sm" id="cont-btn" onclick="openContainers('')" title="Containers — 3D view of every Docker container per node (say: 'los contenedores del nodo X', 'el contenedor mysql')"><i class="fa-solid fa-cubes-stacked"></i> Containers</button>
    <button class="btn ghost sm" id="nt-btn" onclick="openNetTool('portscan','')" title="Net Tools — Ping / Traceroute / Netstat / NS Lookup / Port Scanner (open manually)"><i class="fa-solid fa-toolbox"></i> Net Tools</button>
    <span class="tb-sep"></span>
    <button class="btn ghost sm pbtn" id="pb-queue" onclick="togglePanel('queue')" title="Show/hide the Signal Queue"><i class="fa-solid fa-list-ul"></i></button>
    <button class="btn ghost sm pbtn" id="pb-reason" onclick="togglePanel('reason')" title="Show/hide Live Reasoning"><i class="fa-solid fa-brain"></i></button>
    <button class="btn ghost sm pbtn" id="pb-chat" onclick="togglePanel('chat')" title="Show/hide Talk to NEURU"><i class="fa-solid fa-comments"></i></button>
    <button class="btn ghost sm pbtn" id="narrate-btn" onclick="toggleNarrate()" title="Narrar alertas por voz (VAPI) — opcional; solo durante una llamada activa y NUNCA interrumpe una conversación"><i class="fa-solid fa-bullhorn"></i></button>
    <span class="tb-sep"></span>
    <button class="btn ghost sm" id="vision-btn" onclick="toggleVision()" title="Local Vision — NEURU sees when you're at the PC (camera stays 100% local)"><i class="fa-solid fa-eye"></i> Vision</button>
    <button class="btn ghost sm" id="vision-preview-btn" onclick="toggleVisionPreview()" title="Show/hide the camera preview" style="display:none"><i class="fa-solid fa-video"></i></button>
    <button class="btn ghost sm" id="vision-enroll-btn" onclick="visionCmd('enroll')" title="Enroll your face — NEURU confirms it’s you (one-time; stays local)" style="display:none"><i class="fa-solid fa-id-badge"></i></button>
    <button class="btn ghost sm" id="cfg-btn" onclick="openTab('voice')" title="Settings & Voice — configure / re-provision the assistant, devices, rules, sources"><i class="fa-solid fa-gear"></i></button>
    <button class="btn ghost sm" id="fs-btn" onclick="toggleFull()" title="Fullscreen"><i class="fa-solid fa-expand"></i></button>
    <label class="master"><span class="lbl">NEURU</span>
      <label class="sw"><input type="checkbox" id="master" onchange="toggleMaster(this)"><span class="track"></span><span class="thumb"></span></label>
    </label>
  </div>

  <!-- LEFT: signals + channels -->
  <div id="v2-left">
    <div class="glass panel hud-curve" id="signal-queue" style="flex:1 1 auto">
      <h3><i class="fa-solid fa-satellite-dish"></i> Signal queue
        <span style="margin-left:auto;display:flex;align-items:center;gap:8px">
          <span id="scan-note" style="font-size:10px;color:var(--mut);text-transform:none;letter-spacing:0"></span>
          <button class="btn ghost sm" onclick="openTab('sources')" title="Alert sources — what NEURU watches"><i class="fa-solid fa-sliders"></i></button>
          <button class="btn ghost sm" onclick="clearSignals()" title="Clear the queue (Scan now re-detects what's still wrong)"><i class="fa-solid fa-trash-can"></i></button>
        </span></h3>
      <div class="body" id="signals"><div class="muted">Loading…</div></div>
    </div>
    <!-- Alert sources moved to the drawer (Sources tab). This lower-left frame is reserved for a future feature. -->
    <div id="v2-left-slot"></div>
  </div>

  <!-- CENTER: the bot is the WebGL scene; a status ribbon floats here -->
  <div id="v2-center">
    <div id="v2-narrate"></div>
    <div id="v2-state" class="glass" style="padding:10px 20px">
      <div class="now" id="state-now">Idle — watching the fleet</div>
      <div class="sub" id="state-sub">NEURU is standing by. Flip the switch to go autonomous, or “Scan now”.</div>
    </div>
<?php if (nm_vapi_configured($conn)): ?>
    <div id="v2-voice"><iframe id="voice-frame" src="/voice.php?embed=1" allow="microphone; autoplay" title="NEURU Voice"></iframe></div>
<?php endif; ?>
  </div>

  <!-- RIGHT: transcript + chat -->
  <div id="v2-right">
    <div class="glass panel hud-curve hud-curve-r" id="transcript">
      <h3><i class="fa-solid fa-brain"></i> Live reasoning
        <span style="margin-left:auto"><button class="btn ghost sm" onclick="openTab('devices')"><i class="fa-solid fa-microchip"></i> Devices</button>
        <button class="btn ghost sm" onclick="openTab('rules')"><i class="fa-solid fa-graduation-cap"></i> Rules</button>
        <button class="btn ghost sm" onclick="openTab('history')"><i class="fa-solid fa-clock-rotate-left"></i> History</button>
        <button class="btn ghost sm" onclick="openTab('sources')"><i class="fa-solid fa-sliders"></i> Sources</button></span></h3>
      <div class="body" id="feed"><div class="muted">NEURU’s Observe → Think → Act stream appears here in real time.</div></div>
    </div>
    <div class="glass panel hud-curve hud-curve-r" id="chat">
      <h3><i class="fa-solid fa-comments"></i> Talk to NEURU <span id="chat-note" style="margin-left:auto;font-size:10px;color:var(--mut);text-transform:none;letter-spacing:0"></span></h3>
      <div id="chatlog"></div>
      <div id="chatin"><input id="chat-msg" placeholder="Ask NEURU anything — “stop watching containers”, “investigate web-01”…" onkeydown="if(event.key==='Enter')sendChat()"><button class="btn" onclick="sendChat()">Send</button></div>
    </div>
  </div>
</div>

<!-- LIVE TOOL panel — futuristic glass HUD; fades in when NEURU uses a tool (chat/voice/auto) -->
<div id="tool-hud">
  <div class="th-head"><span class="th-ico" id="th-ico">⚙</span>
    <div class="th-titles"><div class="th-tool" id="th-tool">—</div><div class="th-sub" id="th-sub"></div></div>
    <span class="th-chan" id="th-chan"></span></div>
  <div class="th-body" id="th-body"></div>
</div>

<!-- DATA FILAMENTS — glowing Bézier rays from critical Signal-queue items to the central core (UI↔3D fusion) -->
<svg id="filaments"><g id="fila-g"></g></svg>

<!-- LOCAL VISION — hidden camera iframe (local face-api) + a passive-state amber edge glow (WebGL ambiance) -->
<div id="vision-box"></div>
<div id="vision-veil"></div>

<!-- KERNEL PROFILER — X-Ray a host's anatomy (containers + live processes; kill guarded) -->
<div id="xray-panel">
  <div id="xr-veil"></div>
  <canvas id="xr-canvas"></canvas>
  <div id="xr-labels"></div>
  <div id="xr-scan"></div>
  <div id="xr-top"><span class="xr-ico">🩻</span>
    <div class="xr-titles"><div class="xr-name" id="xr-name">Surgical X-Ray</div><div class="xr-sub" id="xr-vitals">pick a node to scan its anatomy</div></div>
    <button class="btn ghost sm" id="xr-full" onclick="xrUnfocus()" style="display:none"><i class="fa-solid fa-expand"></i> Full view</button>
    <button class="btn ghost sm" id="xr-rescan" onclick="xrRefresh(1)" style="display:none"><i class="fa-solid fa-rotate"></i> Re-scan</button>
    <span class="xr-x" onclick="closeXray()" title="Close">✕</span></div>
  <div id="xr-picker"></div>
  <div id="xr-rail"></div>
  <div id="xr-detail"><div class="dh" id="xr-dh"></div><div class="db" id="xr-db"></div></div>
  <div class="xr-hint" id="xr-hint" style="display:none">drag to orbit · click an organ to dive in · scroll to zoom</div>
</div>

<!-- NETWORK TOPOLOGY MAP — interconnected 3D graph of the whole network -->
<div id="topo-panel">
  <div id="topo-veil"></div>
  <canvas id="topo-canvas"></canvas>
  <div id="topo-labels"></div>
  <div id="topo-top"><span class="xr-ico">🗺️</span>
    <div class="xr-titles"><div class="xr-name" id="topo-name">Network Topology</div><div class="xr-sub" id="topo-sub">the whole network, interconnected</div></div>
    <button class="btn ghost sm" id="topo-full" onclick="topoUnfocus()" style="display:none"><i class="fa-solid fa-expand"></i> Full map</button>
    <button class="btn ghost sm" onclick="topoRefresh(1)" title="Re-map"><i class="fa-solid fa-rotate"></i></button>
    <span class="xr-x" onclick="closeTopo()" title="Close">✕</span></div>
  <div id="topo-rail"></div>
  <div id="topo-detail"><div class="dh" id="topo-dh"></div><div class="db" id="topo-db"></div></div>
  <div class="topo-hint">drag to orbit · click a node to focus · scroll to zoom</div>
</div>

<!-- LIVE TRAFFIC — animated laser per interface (traffic_viewer look) -->
<div id="traf-panel">
  <div id="traf-veil"></div>
  <canvas id="traf-canvas"></canvas>
  <div id="traf-labels"></div>
  <div id="traf-top"><span class="xr-ico">⚡</span>
    <div class="xr-titles"><div class="xr-name" id="traf-name">Live Traffic</div><div class="xr-sub" id="traf-sub">real-time interface throughput</div></div>
    <button class="btn ghost sm" id="traf-full" onclick="trafUnfocus()" style="display:none"><i class="fa-solid fa-expand"></i> All interfaces</button>
    <span class="xr-x" onclick="closeTraffic()" title="Close">✕</span></div>
  <div id="traf-picker"></div>
  <div id="traf-rail"></div>
  <div class="traf-hint">drag to orbit · scroll to zoom · teal = in · orange = out</div>
</div>
<div id="cont-panel">
  <div id="cont-veil"></div>
  <canvas id="cont-canvas"></canvas>
  <div id="cont-labels"></div>
  <div id="cont-top"><span class="xr-ico">📦</span>
    <div class="xr-titles"><div class="xr-name" id="cont-name">Fleet Containers</div><div class="xr-sub" id="cont-sub">every container per node</div></div>
    <button class="btn ghost sm" id="cont-full" onclick="contUnfocus()" style="display:none"><i class="fa-solid fa-expand"></i> All containers</button>
    <span class="xr-x" onclick="closeContainers()" title="Close">✕</span></div>
  <div id="cont-rail"></div>
  <div id="cont-detail"></div>
  <div class="cont-hint">drag to orbit · scroll to zoom · click a container for details · green = running · red = unhealthy</div>
</div>
<div id="nt-panel">
  <div id="nt-veil"></div>
  <div id="nt-top"><span class="xr-ico">🧰</span><div class="xr-name">Net Tools</div>
    <div id="nt-tabs">
      <div class="nt-tab" data-tool="netping" onclick="switchNetTool('netping')"><i class="fa-solid fa-tower-broadcast"></i> Ping</div>
      <div class="nt-tab" data-tool="nettrace" onclick="switchNetTool('nettrace')"><i class="fa-solid fa-route"></i> Traceroute</div>
      <div class="nt-tab" data-tool="netstat" onclick="switchNetTool('netstat')"><i class="fa-solid fa-diagram-project"></i> Netstat</div>
      <div class="nt-tab" data-tool="netlookup" onclick="switchNetTool('netlookup')"><i class="fa-solid fa-magnifying-glass-location"></i> NS Lookup</div>
      <div class="nt-tab" data-tool="portscan" onclick="switchNetTool('portscan')"><i class="fa-solid fa-satellite-dish"></i> Port Scanner</div>
    </div>
    <span id="nt-target" style="margin-left:auto"></span>
    <span class="xr-x" onclick="closeNetTools()" title="Close" style="margin-left:12px">✕</span></div>
  <iframe id="nt-frame" allow="autoplay; microphone" title="Net Tools"></iframe>
</div>

<!-- Devices & Rules drawer (overlays) -->
<div id="drawer" class="glass" style="position:fixed; z-index:7; right:14px; top:70px; bottom:14px; width:520px; display:none; flex-direction:column; border-radius:16px">
  <h3 style="margin:0;padding:12px 14px;font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--mut);display:flex;align-items:center;gap:8px;border-bottom:1px solid rgba(120,150,255,.1)">
    <i class="fa-solid fa-gears"></i> Control <span style="margin-left:auto;cursor:pointer" onclick="closeDrawer()"><i class="fa-solid fa-xmark"></i></span></h3>
  <div class="tabs">
    <div class="tab on" data-tab="devices" onclick="openTab('devices')">Devices & autonomy</div>
    <div class="tab" data-tab="rules" onclick="openTab('rules')">Learned rules</div>
    <div class="tab" data-tab="actions" onclick="openTab('actions')">Approvals</div>
    <div class="tab" data-tab="sources" onclick="openTab('sources')">Alert sources</div>
    <div class="tab" data-tab="memory" onclick="openTab('memory')">🧠 Memory</div>
    <div class="tab" data-tab="history" onclick="openTab('history')">History</div>
    <div class="tab" data-tab="voice" onclick="openTab('voice')">Voice</div>
  </div>
  <div class="tabpane on" id="pane-devices" style="overflow:auto;padding:8px 12px"></div>
  <div class="tabpane" id="pane-rules" style="overflow:auto;padding:8px 12px"></div>
  <div class="tabpane" id="pane-actions" style="overflow:auto;padding:8px 12px"></div>
  <div class="tabpane" id="pane-sources" style="overflow:auto;padding:8px 12px">
    <div style="font-size:11px;color:var(--mut);padding:2px 2px 10px">What NEURU watches — toggle a source on/off and set how it acts (watch only · propose &amp; ask · auto-fix).</div>
    <div class="body" id="channels" style="padding:0"><div class="muted">Loading…</div></div>
  </div>
  <div class="tabpane" id="pane-memory" style="overflow:auto;padding:8px 12px"></div>
  <div class="tabpane" id="pane-history" style="overflow:auto;padding:8px 12px"></div>
  <div class="tabpane" id="pane-voice" style="overflow:auto;padding:8px 12px"></div>
</div>

<!-- TIMELINE DVR — scrub the whole cockpit back in time (rewinds fleet state; reuses Time-Travel) -->
<div id="tt-bar">
  <button id="tt-play" class="tt-btn" title="Play / pause" onclick="ttPlay()">▶</button>
  <input type="range" id="tt-slider" min="0" max="1000" value="1000" oninput="ttScrubDebounced()" title="Drag to rewind the fleet in time">
  <div id="tt-time" class="tt-time">● LIVE</div>
  <button id="tt-live" class="tt-btn tt-live" title="Return to live" onclick="ttGoLive()" style="display:none">↩ LIVE</button>
</div>

</div><!-- /#v2-stage -->
<script src="/three.min.js"></script>
<script src="/three-orbitcontrols.js"></script>
<script>
// ─────────────────────────── WebGL: NEURU as a living neural core ───────────────────────────
const PHASE_ICON={observe:'',think:'',tool:'',act:'',result:'',narrate:'',error:''};
const PHASE_COL ={observe:0x6fb3ff,think:0x38e1ff,tool:0x6fb3ff,act:0xffb454,result:0x43e08a,narrate:0x9b6bff,error:0xff5c7a};
let scene,cam,rend,core,halo,ring,ring2,deviceMesh=null,streams=null,clock,controls,stars,starfar,ROUND;
let aurora=null,auroraBase=null,voiceLevel=0,voiceTarget=0,voiceSpeaking=false;   // reactive voice aurora
let LOGOS=[];   // NEURU emblems drifting through the universe
const LOGO_SVG=<?= json_encode(function_exists('nm_logo_svg')?nm_logo_svg(128):'') ?>;
var VOICE_ACTIVE=false;   // true while a VAPI voice call is live → Vision must NEVER speak over it
let brainState={phase:'idle',energy:0.15,color:new THREE.Color(0x38e1ff),targetColor:new THREE.Color(0x38e1ff),node:null};
// a soft ROUND sprite so every particle is a glowing sphere, never a square
function roundSprite(){ const c=document.createElement('canvas'); c.width=c.height=64; const x=c.getContext('2d');
  const g=x.createRadialGradient(32,32,0,32,32,32); g.addColorStop(0,'rgba(255,255,255,1)'); g.addColorStop(.35,'rgba(255,255,255,.85)');
  g.addColorStop(.7,'rgba(255,255,255,.18)'); g.addColorStop(1,'rgba(255,255,255,0)'); x.fillStyle=g; x.beginPath(); x.arc(32,32,32,0,7); x.fill();
  return new THREE.CanvasTexture(c); }
function starField(count,rMin,rMax,size,color,op){
  const pos=new Float32Array(count*3);
  for(let i=0;i<count;i++){ const r=rMin+Math.random()*(rMax-rMin), th=Math.random()*Math.PI*2, ph=Math.acos(2*Math.random()-1);
    pos[i*3]=r*Math.sin(ph)*Math.cos(th); pos[i*3+1]=r*Math.sin(ph)*Math.sin(th); pos[i*3+2]=r*Math.cos(ph); }
  const g=new THREE.BufferGeometry(); g.setAttribute('position',new THREE.BufferAttribute(pos,3));
  return new THREE.Points(g,new THREE.PointsMaterial({color,size,map:ROUND,transparent:true,opacity:op,depthWrite:false,sizeAttenuation:true,blending:THREE.AdditiveBlending}));
}
// 3-4 NEURU emblems drifting through the deep field — the brand, alive in its own universe
function makeLogoSprites(){
  if(!LOGO_SVG || typeof THREE==='undefined') return;
  const tex=new THREE.TextureLoader().load('data:image/svg+xml;charset=utf-8,'+encodeURIComponent(LOGO_SVG));
  tex.anisotropy=2;
  for(let i=0;i<4;i++){
    const mat=new THREE.SpriteMaterial({map:tex,transparent:true,opacity:0,depthWrite:false,blending:THREE.AdditiveBlending});
    const sp=new THREE.Sprite(mat); const sc=1.15+Math.random()*0.95; sp.scale.set(sc,sc,1); scene.add(sp);
    LOGOS.push({sp,mat, r:6.4+Math.random()*3.2, a:Math.random()*Math.PI*2, y:(Math.random()*2-1)*3.0,
      spd:(0.045+Math.random()*0.075)*(Math.random()<0.5?-1:1), bob:Math.random()*Math.PI*2, tw:0.34+Math.random()*0.26, fade:0});
  }
}
function initGL(){
  const cv=document.getElementById('nm-stage');
  rend=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true});
  rend.setPixelRatio(Math.min(2,devicePixelRatio)); resize();
  scene=new THREE.Scene();
  cam=new THREE.PerspectiveCamera(52,innerWidth/innerHeight,.1,300); cam.position.set(0,0,7);
  clock=new THREE.Clock();
  ROUND=roundSprite();
  // interactive orbit — drag to spin NEURU, wheel to zoom, gentle auto-rotate
  controls=new THREE.OrbitControls(cam,rend.domElement);
  controls.enableDamping=true; controls.dampingFactor=.06; controls.enablePan=false;
  controls.autoRotate=true; controls.autoRotateSpeed=.6; controls.minDistance=4.2; controls.maxDistance=16; controls.rotateSpeed=.7;
  // ROUND-particle starfields — FEWER + BIGGER so dense tiny points can't moiré into horizontal bands
  starfar=starField(650,46,105,1.4,0x3a5aa0,.42); scene.add(starfar);
  stars  =starField(760,11,40,.7,0x6fb0ff,.8);   scene.add(stars);
  // neural core: an icosahedron wireframe that breathes
  core=new THREE.Mesh(new THREE.IcosahedronGeometry(1.5,2),new THREE.MeshBasicMaterial({color:0x38e1ff,wireframe:true,transparent:true,opacity:.92}));
  scene.add(core);
  // inner glow sphere
  const gs=new THREE.Mesh(new THREE.SphereGeometry(1.16,48,48),new THREE.MeshBasicMaterial({color:0x1a2a66,transparent:true,opacity:.5}));
  scene.add(gs); brainState.glow=gs;
  // particle halo (the "mind") — round glowing motes
  const N=1500,pos=new Float32Array(N*3);
  for(let i=0;i<N;i++){ const r=2.1+Math.random()*2.7, th=Math.random()*Math.PI*2, ph=Math.acos(2*Math.random()-1);
    pos[i*3]=r*Math.sin(ph)*Math.cos(th); pos[i*3+1]=r*Math.sin(ph)*Math.sin(th); pos[i*3+2]=r*Math.cos(ph); }
  const pg=new THREE.BufferGeometry(); pg.setAttribute('position',new THREE.BufferAttribute(pos,3));
  halo=new THREE.Points(pg,new THREE.PointsMaterial({color:0x9b6bff,size:.085,map:ROUND,transparent:true,opacity:.9,depthWrite:false,sizeAttenuation:true,blending:THREE.AdditiveBlending}));
  scene.add(halo);
  // twin orbit rings (spin up when thinking)
  ring=new THREE.Mesh(new THREE.TorusGeometry(2.7,.014,10,160),new THREE.MeshBasicMaterial({color:0x38e1ff,transparent:true,opacity:.55}));
  ring.rotation.x=Math.PI/2.3; scene.add(ring);
  ring2=new THREE.Mesh(new THREE.TorusGeometry(3.25,.008,10,160),new THREE.MeshBasicMaterial({color:0x9b6bff,transparent:true,opacity:.35}));
  ring2.rotation.x=Math.PI/1.7; ring2.rotation.y=.5; scene.add(ring2);
  makeLogoSprites();   // NEURU emblems floating through the universe

  // VOICE AURORA — a curtain of particles wrapping the core that ripples with NEURU's speech.
  // Dormant (near-invisible) until a voice event bumps voiceLevel; then it blooms + dances.
  const AN=1600, ab=new Float32Array(AN*3), abase=new Float32Array(AN*2);
  for(let i=0;i<AN;i++){ const a=Math.random()*Math.PI*2, ny=(Math.random()*2-1); abase[i*2]=a; abase[i*2+1]=ny;
    ab[i*3]=Math.cos(a)*2.0; ab[i*3+1]=ny*0.9; ab[i*3+2]=Math.sin(a)*2.0; }
  const ageo=new THREE.BufferGeometry(); ageo.setAttribute('position',new THREE.BufferAttribute(ab,3));
  aurora=new THREE.Points(ageo,new THREE.PointsMaterial({color:0x39e6ff,size:.055,map:ROUND,transparent:true,opacity:0,depthWrite:false,sizeAttenuation:true,blending:THREE.AdditiveBlending}));
  auroraBase=abase; scene.add(aurora);
  animate();
}
function resize(){ if(!rend)return; rend.setSize(innerWidth,innerHeight); if(cam){cam.aspect=innerWidth/innerHeight; cam.updateProjectionMatrix();} }
addEventListener('resize',resize);
function setPhase(phase,node){
  brainState.phase=phase; brainState.node=node||brainState.node;
  brainState.targetColor=new THREE.Color(PHASE_COL[phase]||0x38e1ff);
  brainState.energy=Math.min(1.0,(phase==='think'?.9:phase==='act'?1.0:phase==='error'?1.0:phase==='result'?.5:.6));
}
// a device "flies in" and orbits the core during investigation
function attachDevice(name){
  detachDevice();
  const cnv=document.createElement('canvas'); cnv.width=512; cnv.height=160; const ctx=cnv.getContext('2d');
  ctx.fillStyle='rgba(10,16,40,.85)'; roundRect(ctx,4,4,504,152,18); ctx.fill();
  ctx.strokeStyle='#38e1ff'; ctx.lineWidth=3; roundRect(ctx,4,4,504,152,18); ctx.stroke();
  ctx.fillStyle='#eaf2ff'; ctx.font='bold 44px Segoe UI,Arial'; ctx.textAlign='center'; ctx.fillText((name||'device').slice(0,22),256,88);
  ctx.fillStyle='#38e1ff'; ctx.font='22px Segoe UI,Arial'; ctx.fillText('◉ under investigation',256,128);
  const tex=new THREE.CanvasTexture(cnv);
  deviceMesh=new THREE.Mesh(new THREE.PlaneGeometry(2.4,.75),new THREE.MeshBasicMaterial({map:tex,transparent:true}));
  deviceMesh.position.set(4.6,.4,0); deviceMesh.userData.t=0; scene.add(deviceMesh);
  // data streams core↔device
  const M=120,sp=new Float32Array(M*3); for(let i=0;i<M;i++){ const t=i/M; sp[i*3]=t*3.6; sp[i*3+1]=Math.sin(t*10)*.15; sp[i*3+2]=0; }
  const sg=new THREE.BufferGeometry(); sg.setAttribute('position',new THREE.BufferAttribute(sp,3));
  streams=new THREE.Points(sg,new THREE.PointsMaterial({color:0x38e1ff,size:.11,map:ROUND,transparent:true,opacity:.95,depthWrite:false,sizeAttenuation:true,blending:THREE.AdditiveBlending}));
  streams.position.set(1,.4,0); scene.add(streams);
}
function detachDevice(){
  if(deviceMesh){ scene.remove(deviceMesh); try{ deviceMesh.geometry.dispose(); if(deviceMesh.material.map)deviceMesh.material.map.dispose(); deviceMesh.material.dispose(); }catch(e){} deviceMesh=null; }
  if(streams){ scene.remove(streams); try{ streams.geometry.dispose(); streams.material.dispose(); }catch(e){} streams=null; }
}
function roundRect(c,x,y,w,h,r){ c.beginPath(); c.moveTo(x+r,y); c.arcTo(x+w,y,x+w,y+h,r); c.arcTo(x+w,y+h,x,y+h,r); c.arcTo(x,y+h,x,y,r); c.arcTo(x,y,x+w,y,r); c.closePath(); }
const STAR_TINT=new THREE.Color(0x5fa8ff);   // hoisted: was allocated every frame
function animate(){
  requestAnimationFrame(animate); const dt=clock.getDelta(), t=clock.elapsedTime;
  if(controls){ controls.autoRotateSpeed=.6+brainState.energy*1.4; controls.update(); }
  if(starfar){ starfar.rotation.y+=dt*.008; starfar.rotation.x+=dt*.002; }
  if(stars){ stars.rotation.y-=dt*.02; stars.rotation.z+=dt*.004; stars.material.color.copy(brainState.color).lerp(STAR_TINT,.5); }
  brainState.color.lerp(brainState.targetColor,.06);
  // voice level: smooth toward the latest bump, then decay — drives the aurora + the core's pulse
  voiceLevel += (voiceTarget - voiceLevel)*0.25; voiceTarget *= 0.90; if(voiceLevel<0.001) voiceLevel=0;
  const pulse=1+Math.sin(t*(2+brainState.energy*6))*.05*(0.4+brainState.energy)+voiceLevel*0.16;
  core.scale.setScalar(pulse); core.material.color.copy(brainState.color);
  core.rotation.y+=dt*(.15+brainState.energy*.7); core.rotation.x+=dt*.08;
  if(brainState.spin){ core.rotation.y+=brainState.spin*dt; if(halo)halo.rotation.y+=brainState.spin*dt*.5; brainState.spin*=Math.max(0,1-dt*2.2); if(brainState.spin<.02)brainState.spin=0; }   // focus-on-node impulse
  halo.rotation.y-=dt*(.05+brainState.energy*.25); halo.material.opacity=.6+brainState.energy*.4;
  halo.material.color.copy(brainState.color);
  ring.rotation.z+=dt*(.2+brainState.energy*1.6); ring.material.color.copy(brainState.color); ring.material.opacity=.3+brainState.energy*.5;
  if(ring2){ ring2.rotation.z-=dt*(.14+brainState.energy*1.1); ring2.rotation.x+=dt*.05; ring2.material.opacity=.22+brainState.energy*.4; }
  if(brainState.glow){ brainState.glow.material.opacity=.35+Math.sin(t*3)*.1+brainState.energy*.2; brainState.glow.material.color.copy(brainState.color).multiplyScalar(.5); }
  if(deviceMesh){ deviceMesh.userData.t=Math.min(1,deviceMesh.userData.t+dt*1.5); const e=deviceMesh.userData.t;
    deviceMesh.position.x=4.6-(1)*e - Math.sin(t*.6)*.05; deviceMesh.lookAt(cam.position); }
  if(streams){ const p=streams.geometry.attributes.position; for(let i=0;i<p.count;i++){ let x=p.getX(i)+dt*2.2; if(x>3.6)x-=3.6; p.setX(i,x);} p.needsUpdate=true; }
  // VOICE AURORA — ripple each particle's radius + height by its phase, bloom with voiceLevel,
  // and shift cyan→magenta as NEURU's voice peaks. Near-invisible when silent.
  if(aurora){ const v=voiceLevel;
    // heavy per-vertex ripple runs ONLY when there's actual voice energy — idle it (huge CPU save when silent)
    if(voiceSpeaking || v>0.01){
      const p=aurora.geometry.attributes.position, n=auroraBase.length/2;
      for(let i=0;i<n;i++){ const a=auroraBase[i*2], ny=auroraBase[i*2+1];
        const r=2.0 + Math.sin(a*6 + t*2.6 + ny*3)*(0.10 + v*0.95);
        p.setX(i, Math.cos(a)*r); p.setZ(i, Math.sin(a)*r);
        p.setY(i, ny*(0.9+v*0.7) + Math.sin(a*3 + t*3.2)*0.14*(0.3+v)); }
      p.needsUpdate=true;
      aurora.material.opacity = (voiceSpeaking?0.18:0.05) + v*0.9;
      aurora.material.size = 0.05 + v*0.06;
      aurora.material.color.setHSL(0.52 - Math.min(0.2,v*0.22), 1.0, 0.55 + v*0.12);
      aurora.rotation.y += dt*(0.05 + v*0.35);
    } else if(aurora.material.opacity!==0.05){ aurora.material.opacity=0.05; }
  }
  if(TT && TT.ghosts){ TT.ghosts.rotation.y += dt*0.15; TT.ghosts.rotation.x = Math.sin(t*0.2)*0.08; }   // Timeline DVR fleet ring
  if(LOGOS.length){ for(let i=0;i<LOGOS.length;i++){ const L=LOGOS[i]; L.a+=dt*L.spd; L.fade=Math.min(1,L.fade+dt*0.35);
    L.sp.position.set(Math.cos(L.a)*L.r, L.y+Math.sin(t*0.4+L.bob)*0.55, Math.sin(L.a)*L.r);
    L.mat.opacity=(L.tw+Math.sin(t*0.8+L.bob)*0.12)*L.fade*(0.6+brainState.energy*0.5); } }   // NEURU emblems drifting + glowing with the brain's energy
  // (X-Ray now renders in its own dedicated WebGL scene — see the XR engine)
  // decay energy toward idle
  brainState.energy=Math.max(.15,brainState.energy-dt*.12);
  rend.render(scene,cam);
}
initGL();

// receive voice events from the embedded voice iframe (voice.php?embed=1) → drive the reactive aurora
window.addEventListener('message', function(ev){
  if(ev.origin!==location.origin) return;
  const d=ev.data; if(!d||d.type!=='neuru-voice') return;
  if(d.event==='volume'){ voiceTarget=Math.min(1, Math.max(voiceTarget,(d.value||0)*3)); }
  else if(d.event==='speech-start'){ voiceSpeaking=true; }
  else if(d.event==='speech-end'){ voiceSpeaking=false; }
  else if(d.event==='call-start'){ VOICE_ACTIVE=true; try{ window.speechSynthesis&&window.speechSynthesis.cancel(); }catch(e){} visionCmd('pause'); try{ $('#state-now').textContent='🎙 Voice link active'; }catch(e){} }
  else if(d.event==='call-end'){ VOICE_ACTIVE=false; voiceSpeaking=false; voiceTarget=0; visionCmd('resume'); }
  else if(d.event==='user-speaking'){ lastUserSpeakTs=Date.now(); }   // operator mid-utterance → alerts must not interrupt
  else if(d.event==='transcript'){ lastFinalTs=Date.now(); handleVoiceCmd(d.value); }
});

// ── VOICE NARRATION of alerts (opt-in; ALERTS ONLY — the direct conversation is untouched) ──
var narrateOn=false, lastUserSpeakTs=0, lastFinalTs=0, narrateBusyUntil=0;
function refreshNarrateBtn(){ const b=document.getElementById('narrate-btn'); if(b) b.classList.toggle('on', !!narrateOn); }
function loadNarrate(){ j('?api=voice_state').then(r=>{ if(r&&r.ok){ narrateOn=!!r.on; refreshNarrateBtn(); } }).catch(()=>{}); }
function setNarrate(on){ post('voice_set',{on:on?'1':'0'}).then(r=>{ if(r&&r.ok){ narrateOn=!!r.on; refreshNarrateBtn(); const s=$('#state-now'); if(s) s.textContent = narrateOn ? (r.effective?'🔊 Narración de alertas ON':'🔊 Narración ON — sonará al activar el modo autónomo y una llamada de voz') : '🔇 Narración de alertas OFF'; } }).catch(()=>{}); }
function toggleNarrate(){ setNarrate(!narrateOn); }
function sayViaVoice(text){ try{ const f=document.getElementById('voice-frame'); if(f&&f.contentWindow) f.contentWindow.postMessage({type:'neuru-voice-cmd',cmd:'say',text:(''+text).slice(0,300)},location.origin); }catch(e){} }
// mid-conversation = assistant speaking OR operator spoke <6s ago OR a final transcript landed <6s ago
function conversationBusy(){ const now=Date.now(); return voiceSpeaking || (now-lastUserSpeakTs<6000) || (now-lastFinalTs<6000); }
// speak ONE queued alert line, ONLY when a call is live, narration is on, and we're not interrupting
function voiceDrain(){ const now=Date.now();
  if(!VOICE_ACTIVE || !narrateOn || now<narrateBusyUntil || conversationBusy()) return;
  narrateBusyUntil=now+1500;   // brief lock during the poll
  post('voice_drain',{}).then(r=>{
    if(r&&r.ok&&r.line&&r.line.text){ sayViaVoice(r.line.text); post('voice_spoken',{id:r.line.id});
      const secs=Math.min(13, Math.max(4, (''+r.line.text).length/13));   // size the lock to the sentence so the NEXT line can't cut it off (VAPI .say may not emit speech-start)
      narrateBusyUntil=Date.now()+secs*1000+900; }
    else { narrateBusyUntil=Date.now()+600; }
  }).catch(()=>{ narrateBusyUntil=Date.now()+1000; });
}
// Ctrl/Cmd+K toggles the VAPI voice link (start if idle, end if active) — no button click. Reuses the reverse
// channel; the iframe fires the same call-start/end path. Ignored while typing in an input/textarea.
function toggleVoiceCall(){ try{ const f=document.getElementById('voice-frame'); if(f&&f.contentWindow) f.contentWindow.postMessage({type:'neuru-voice-cmd',cmd:'toggle-call'},location.origin); }catch(e){} }
window.addEventListener('keydown', function(e){
  if((e.ctrlKey||e.metaKey) && !e.altKey && !e.shiftKey && (e.key==='k'||e.key==='K')){
    const el=document.activeElement, tag=el&&el.tagName;
    if(tag==='INPUT'||tag==='TEXTAREA'||(el&&el.isContentEditable)) return;
    e.preventDefault(); toggleVoiceCall();
  }
});
// ── collapsible panels (Signal Queue · Live Reasoning · Talk to NEURU) — HIDDEN by default; toggle by button or voice ──
var PANELS={queue:false,reason:false,chat:false};
try{ const s=JSON.parse(localStorage.getItem('nm_ap2_panels')||'null'); if(s&&typeof s==='object'){ PANELS.queue=!!s.queue; PANELS.reason=!!s.reason; PANELS.chat=!!s.chat; } }catch(e){}
const PANEL_EL={queue:'signal-queue',reason:'transcript',chat:'chat'};
function applyPanels(){ for(const k in PANEL_EL){ const el=document.getElementById(PANEL_EL[k]); if(el) el.style.display=PANELS[k]?'':'none'; const b=document.getElementById('pb-'+k); if(b) b.classList.toggle('on',PANELS[k]); } }
function togglePanel(k,force){ if(!(k in PANELS)) return; PANELS[k]=(force===undefined)?!PANELS[k]:!!force; try{ localStorage.setItem('nm_ap2_panels',JSON.stringify(PANELS)); }catch(e){} applyPanels(); }

// Local voice shortcut from the transcript so it ALWAYS works (even before the VAPI assistant is re-provisioned):
// close the X-Ray, or show/hide a named panel. Never needs a server round-trip.
// set NEURU's autonomous master switch (keeps the checkbox + server in sync) + a fleet scan — both usable by voice
function setAutonomous(on){ const el=$('#master'); if(!el) return; if(el.checked===!!on){ $('#state-sub').textContent = on?'⚡ NEURU is already autonomous.':'⏸ NEURU is already paused.'; return; } el.checked=!!on; toggleMaster(el); $('#state-now').textContent = on?'⚡ Autonomous mode ON':'⏸ Autonomous mode paused'; }
function voiceScan(){ const b=$('#scan-btn'); if(b && !b.disabled){ doScan(b); } else { post('scan',{}).then(()=>{ loadSignals(); loadState(); }); } $('#state-now').textContent='🛰 Scanning the fleet…'; }
function handleVoiceCmd(v){ if(!v||v.role!=='user'||!v.text) return; const t=(''+v.text).toLowerCase();
  // ── GLOBAL commands (work even with the X-Ray open) ──
  // Autonomous mode on/off (the NEURU master switch)
  if(/\b(aut[oó]nom\w*|autonomous|autopilot|autom[aá]tic\w*)\b/.test(t)){
    if(/\b(apaga\w*|desactiva\w*|det[eé]n\w*|deten\w*|pausa\w*|par[ae]\b|deshabilit\w*|desconecta\w*|off|disable|stop|turn off|s[aá]l\w*)\b/.test(t)){ setAutonomous(false); uiClaimed(); return; }
    if(/\b(prende\w*|enciende\w*|activa\w*|arranca\w*|inicia\w*|habilit\w*|conecta\w*|entra\w*|on\b|enable|go\b|start|ahora|ya|now)\b/.test(t)){ setAutonomous(true); uiClaimed(); return; }
    return;   // just mentioned "autónomo" without a clear on/off verb → ignore
  }
  // Narrate alerts by voice on/off ("narra las alertas" / "deja de narrar" / "no narres")
  if(/\bnarr\w*|vocifer\w*|an[uú]ncia\w*|av[ií]sa\w*\s+(por\s+)?voz\b/.test(t)){
    if(/\b(no\b|deja\w*|dejar|apaga\w*|desactiva\w*|det[eé]n\w*|deten\w*|para\w*|silenc\w*|off|stop|disable)\b/.test(t)){ setNarrate(false); uiClaimed(); return; }
    if(/\b(narr\w*|vocifer\w*|an[uú]ncia\w*|av[ií]sa\w*|activa\w*|prende\w*|enciende\w*|habilit\w*|on\b|enable)\b/.test(t)){ setNarrate(true); uiClaimed(); return; }
    return;
  }
  // NET TOOLS are MANUAL-ONLY now — the bot no longer opens them by voice/chat (kept simple + reliable).
  // Open them yourself with the "Net Tools" button in the toolbar.
  // Scan the fleet now
  if(/\b(escane\w*|escanea\w*|scan\w*|scannea\w*|barre\w*|sweep\w*|rastrea\w*)\b/.test(t)){ voiceScan(); uiClaimed(); return; }
  // Network TOPOLOGY MAP — open (if closed) / re-scope (if a subnet CIDR is named). NOT on a close verb.
  const _closeV=/\b(cierra|cierr\w*|ci[eé]rra\w*|cerrar|close|dismiss|ferme|fech\w*|schlie[sß]|quita|qu[ií]ta\w*|esconde|escond\w*|oc[uú]lta\w*|f[uú]era|sal\w*)\b/.test(t);
  const _wantsMap=/\btopolog[íi]?[ae]?\b|\btopology\b|\bmapa\b|\bnetwork map\b/.test(t);
  const _cidr=t.match(/\b\d{1,3}(\.\d{1,3}){2,3}(\/\d{1,2})?\b/);
  if(!_closeV && _wantsMap && (!$('#topo-panel').classList.contains('show') || _cidr)){
    let scope='all'; if(_cidr) scope=_cidr[0];
    else { const seg=t.match(/(?:segmento|segment|del?|de la|de el|map[a]? de|topolog[íi]a de)\s+(.+)$/); if(seg && seg[1] && !/\b(red|network|completo|entera?|todo|toda)\b/.test(seg[1])) scope=seg[1].trim().replace(/[.?!,]+$/,''); }
    openTopo(scope); uiClaimed(); return;
  }
  // LIVE TRAFFIC — open (if closed) fleet-wide, optionally FOCUS a device / interface(s). NOT on a close verb.
  if(!_closeV && /\btr[aá]fico\b|\btraffic\b|\blasers?\b/.test(t) && !$('#traf-panel').classList.contains('show')){
    let iface=''; const im=t.match(/\b(?:interfa[cz]e?s?|puertos?|ports?)\s+(\d+(?:\s*(?:y|and|e|,|al)\s*\d+)*)/); if(im) iface=im[1].trim();
    else { const em=t.match(/\bether\s*(\w+)/); if(em) iface='ether'+em[1]; }
    // node = the utterance minus traffic/interface/filler words + numbers → the device name (the server resolves it fuzzily)
    let node=t.replace(/\b(mu[eé]strame|muestra\w*|ense[nñ]a\w*|dame|abre|show|open|el|la|los|las|un|una|tod[oa]s?|tr[aá]fico|traffic|en vivo|live|lasers?|de la|de el|del|de|interfa[cz]e?s?|puertos?|ports?|ether\w*|\d+|y|e|al)\b/g,' ').replace(/[.?!,]+/g,' ').replace(/\s+/g,' ').trim();
    openTraffic(node, iface); uiClaimed(); return;   // node may be '' → all interfaces, nothing focused
  }
  // CONTAINERS layer — open (if closed) when the operator asks for containers/docker
  if(!_closeV && /\bcontenedor\w*|\bcontainers?\b|\bdocker\b/.test(t) && !($('#cont-panel')&&$('#cont-panel').classList.contains('show'))){
    let ref=t.replace(/\b(mu[eé]strame|muestra\w*|ense[nñ]a\w*|dame|abre|show|open|el|la|los|las|un|una|tod[oa]s?|contenedor\w*|containers?|docker|del nodo|en el nodo|de la|de el|del|de|nodo|node)\b/g,' ').replace(/[.?!,]+/g,' ').replace(/\s+/g,' ').trim();
    openContainers(ref, ref); uiClaimed(); return;   // ref may be '' → all containers; else a node OR a container name (server focuses)
  }
  // while a full-screen overlay (X-Ray, map, traffic, containers, or net tools) is up, voice targets IT: close it, or focus what's named
  if($('#xray-panel').classList.contains('show') || $('#topo-panel').classList.contains('show') || $('#traf-panel').classList.contains('show') || ($('#cont-panel')&&$('#cont-panel').classList.contains('show')) || ($('#nt-panel')&&$('#nt-panel').classList.contains('show'))){
    if(/\b(cierra|cierr[ae]|ci[eé]rral[oa]|cerrar|c[ie]erra|close|dismiss|ferme|fech[ae]|schlie[sß]|qu[ií]tal[oa]|s[aá]lte|esconde|escond\w*|oc[uú]lta\w*|f[uú]era)\b/.test(t)){
      if($('#xray-panel').classList.contains('show')) closeXray();
      if($('#topo-panel').classList.contains('show')) closeTopo();
      if($('#traf-panel').classList.contains('show')) closeTraffic();
      if($('#cont-panel')&&$('#cont-panel').classList.contains('show')) closeContainers();
      if($('#nt-panel')&&$('#nt-panel').classList.contains('show')) closeNetTools();
      uiClaimed(); return;
    }
    // MAP focus-by-voice: a node → focus it; a CONNECTION between two → focus both + highlight the link
    if($('#topo-panel').classList.contains('show') && !/\b(x.?ray|rayos|anatom)\b/.test(t)){
      if(/\b(completo|todo|toda|todos|full|entera?|reset|general|zoom out|al[eé]jate)\b/.test(t)){ topoUnfocus(); return; }
      const mm=topoMatchNodes(t);
      const wantsPair=/\b(conexi[oó]n\w*|conexion\w*|enlace|entre|between|\blink\b|conecta\w*|conectad\w*|va de|de .+ a )\b/.test(t);
      if(wantsPair && mm.length>=2){ topoFocusPair(mm[0].n.id, mm[1].n.id); return; }
      if(mm.length>=1){ topoFocus(mm[0].n.id); return; }
    }
    // TRAFFIC focus-by-voice: name interface(s) → focus them; "todas las interfaces" → show all
    if($('#traf-panel').classList.contains('show') && !/\b(x.?ray|rayos|anatom)\b/.test(t)){
      if(/\b(todas|todo|all|full|completo|reset|general|al[eé]jate|zoom out)\b/.test(t)){ trafUnfocus(); return; }
      const fi=trafMatchIfaces(t); if(fi.length){ trafFocusIds(fi); return; }
    }
    // CONTAINERS focus-by-voice: name a container/node → focus it; "todos" → show all
    if($('#cont-panel')&&$('#cont-panel').classList.contains('show') && !/\b(x.?ray|rayos|anatom)\b/.test(t)){
      if(/\b(todos|todas|todo|all|full|completo|reset|general|al[eé]jate|zoom out)\b/.test(t)){ contUnfocus(); return; }
      const cm=contMatch(t); if(cm.length){ contFocusIds(cm); return; }
    }
    return;
  }
  // 1) which panel? (queue "cola/señales", chat, reasoning). English "queue" is often mis-transcribed → phonetic variants.
  let k=null;
  if(/\b(queue|kiu|quiu|kiw|keu|qiu|cue|cola|colas|se[nñ]al\w*|senal\w*|signal\w*|lista)\b/.test(t)) k='queue';
  else if(/\b(chat|conversaci\w*|mensaj\w*|talk)\b/.test(t)) k='chat';
  else if(/\b(razona\w*|razonamiento|reasoning|reason\w*|pensam\w*|think\w*|logic\w*|l[oó]gic\w*)\b/.test(t)) k='reason';
  if(!k){ maybeLearn(t, v.text); return; }   // not a panel command → maybe it's a teaching/correction to remember
  // 2) show or hide? default = SHOW; hide only if an explicit hide-verb is present.
  const hide=/\b(oculta|oc[uú]lta\w*|esconde|escond\w*|cierra|cerrar|quita|qu[ií]ta\w*|guarda|remueve|hide|close|dismiss|remove|hidden)\b/.test(t);
  const show=/\b(muestra\w*|mu[eé]stra\w*|ense[nñ]a\w*|ens[eé][nñ]a\w*|abre|[aá]bre\w*|saca|dame|pon|trae|quiero|show|open|display|reveal|bring)\b/.test(t);
  const mentionsPanel=/\bpanel\w*\b|pantalla/.test(t);
  if(!hide && !show && !mentionsPanel){ maybeLearn(t, v.text); return; }   // mentions a panel word but no verb → not a toggle; might be a teaching to remember
  const want = !hide;   // hide wins if both somehow match
  togglePanel(k, want);
  uiClaimed();   // consume any concurrent server echo + block a racing X-Ray open from stomping this command
  const nm={queue:'Signal Queue',chat:'Chat',reason:'Reasoning'}[k];
  try{ $('#state-sub').textContent='🪟 '+nm+(want?' — shown':' — hidden'); }catch(e){}
}
// mark that the operator just issued a LOCAL UI command by voice → for ~6s, ignore any misrouted assistant X-Ray open
// (and consume the same-command server echo) so the assistant can't stomp what you asked for.
function uiClaimed(){ lastXrTs=Math.floor(Date.now()/1000); xrSuppressOpenUntil=Date.now()+6000; }
// LEARN from a spoken teaching/correction — the VAPI direct-tool path bypasses the chat brain, so capture it here so
// NEURU remembers what you told it (topology, IP ownership, a correction, a preference). Server picks kind + entity.
var _lastLearn=0;
function maybeLearn(t, raw){ raw=(''+(raw||'')).trim(); if(raw.length<8) return;
  if(Date.now()-_lastLearn<1500) return;   // debounce partials
  if(/\b(recuerda que|recuerda|apunta que|anota que|para que sepas|quiero que sepas|aprende que|que sepas que|ten en cuenta|en realidad|no es (as[ií]|cierto)|est[aá]s? (mal|equivocad)|te equivocas|eso no es|es incorrecto|es falso|corrige|correcci[oó]n|remember that|actually,|that'?s (wrong|incorrect)|for the record)\b/i.test(t)){
    _lastLearn=Date.now();
    try{ post('mem_learn',{text:raw,source:'voice'}).then(r=>{ if(r&&r.ok) $('#state-sub').textContent='🧠 Aprendido — lo recordaré.'; }); }catch(e){}
  }
}

// ─────────────────────────── data + live stream ───────────────────────────
let STATE={enabled:false,brain_ready:false,chat_ready:false}, DEVICES=[], CURSOR=0, es=null;
const $=s=>document.querySelector(s), feed=$('#feed');
const CSRF=<?= json_encode($CSRF) ?>;   // every mutation carries it; server rejects POST without it
function j(u,o){ return fetch(u,o).then(r=>r.json()); }
function post(api,body){ const f=new FormData(); for(const k in body) f.append(k,body[k]); f.append('csrf',CSRF); return j('?api='+api,{method:'POST',body:f}); }

async function loadState(){
  if(typeof TT!=='undefined' && !TT.live) return;   // frozen while the Timeline DVR is rewound
  const s=await j('?api=state'); if(!s.ok)return; STATE=s;
  $('#master').checked=!!s.enabled;
  $('#k-fleet').textContent=s.counts.fleet; $('#k-open').textContent=s.counts.open;
  $('#k-inv').textContent=s.counts.investigating; $('#k-prop').textContent=s.counts.proposed; $('#k-rules').textContent=s.counts.rules;
  $('#scan-note').textContent='auto-scan every '+s.scan_interval+'s';
  $('#chat-note').textContent = s.chat_ready?'':'chat brain offline';
  if(!s.brain_ready){ $('#state-sub').textContent='⚠ The autopilot-v2 flow isn’t wired yet — set its webhook URL in Integrations → n8n.'; }
  DEVICES=s.devices; renderChannels(s.channels); if(drawerTab==='devices')renderDevices();
}
function renderChannels(ch){
  const box=$('#channels');
  const names={nodes_down:'Nodes down / degraded',nodes_findings:'AI insights (findings)',containers_inc:'Container incidents',containers_err:'Container errors / logs',events_syslog:'Syslog patterns',events_threats:'Threats to immunize',predictive:'Predictive health',events_iface:'Interface flaps',heal:'Self-Healing proposals',deception:'Deception / honeypots',incidents:'Correlated incidents'};
  const src={nodes_down:'Node monitoring · ping / SNMP',nodes_findings:'AI insight flows · n8n',containers_inc:'Container incidents · Portainer',containers_err:'Container logs',events_syslog:'Syslog server',events_threats:'Collective Immunity · pending threats',predictive:'Predictive Health · SFP / error trends',events_iface:'Interface flaps · SNMP',heal:'Self-Healing · staged playbooks',deception:'Deception Grid · honeypots',incidents:'Troubleshooting · latency / loss / config'};
  box.innerHTML=ch.map(c=>`<div class="row ${c.act_mode==='aware'?'ch-passive':''}"><span class="dot ${c.min_severity==='critical'?'critical':c.min_severity==='warning'?'warning':'info'}"></span>
    <div class="t"><b>${names[c.channel_key]||c.channel_key}${c.act_mode==='aware'?' <span class="ch-tag">watch only</span>':''}</b><span>from ${esc(src[c.channel_key]||c.channel_key)}</span></div>
    <select class="mini" onchange="setChannel('${c.channel_key}','act_mode',this.value)" title="aware = watch only (sits in queue, no investigation) · propose = NEURU investigates + asks you to Approve/Deny · auto-fix = NEURU auto-runs SAFE fixes (immunize/heal + other domain actions ALWAYS still ask)">
      <option value="aware"${c.act_mode==='aware'?' selected':''}>watch only</option>
      <option value="propose"${c.act_mode==='propose'?' selected':''}>propose → approve</option>
      <option value="auto"${c.act_mode==='auto'?' selected':''}>auto-fix</option></select>
    <label class="sw sm"><input type="checkbox" ${c.enabled==1?'checked':''} onchange="setChannel('${c.channel_key}','enabled',this.checked?1:0)"><span class="track"></span><span class="thumb"></span></label>
    </div>`).join('');
}
function setChannel(key,field,val){
  const b={key}; b[field]=val;
  // optimistic local update so re-opening the tab (which re-renders from STATE, refreshed only every 30s)
  // doesn't visually revert a just-changed value; then persist + pull the authoritative state back.
  if(STATE&&STATE.channels){ const c=STATE.channels.find(x=>x.channel_key===key); if(c) c[field]=(field==='enabled')?(val?1:0):val; }
  post('channel',b).then(()=>{ if(typeof loadState==='function') loadState(); });
}

// where each signal comes FROM — shown on every queue row so the user knows the source at a glance
const CHAN_SRC={nodes_down:'Node monitoring',nodes_findings:'AI insights',containers_inc:'Container incidents',containers_err:'Container logs',events_syslog:'Syslog',events_threats:'Collective Immunity',predictive:'Predictive Health',events_iface:'Interface flaps',heal:'Self-Healing',deception:'Deception Grid',incidents:'Correlated incidents',manual:'Manual · operator'};
async function loadSignals(){
  if(typeof TT!=='undefined' && !TT.live) return;   // frozen while the Timeline DVR is rewound
  const s=await j('?api=signals'); const box=$('#signals');
  if(!s.signals||!s.signals.length){ box.innerHTML='<div class="muted">No open signals. NEURU is watching a calm fleet. ✨</div>'; return; }
  box.innerHTML=s.signals.map(g=>`<div class="row" data-sev="${esc(g.severity||'')}" data-status="${esc(g.status||'')}" data-node="${g.node_id||0}" data-nodename="${esc(g.name||'')}">
    <span class="dot ${g.severity}"></span>
    <div class="t"><b>${esc(g.title||g.name||g.sig_type)}</b><span><span class="src-pill">${esc(CHAN_SRC[g.channel]||g.channel)}</span>${g.name?' · '+esc(g.name):''}${g.seen_count>1?' ·×'+g.seen_count:''}</span></div>
    <span class="badge ${g.status}" title="${g.status==='acted'?'NEURU investigated this — it stays here until the condition clears':''}">${({acted:'reviewed',investigating:'investigating',proposed:'awaiting you','new':'new'})[g.status]||g.status}</span>
    ${g.node_id?`<button class="btn ghost sm" onclick="focusNode(${g.node_id},this)" title="Focus this node — the core turns to it + rescan"><i class="fa-solid fa-magnifying-glass"></i></button>`:''}
    <button class="btn ghost sm" onclick="dismissSignal(${g.id},event)" title="Remove from queue (Scan now re-adds it if still real)"><i class="fa-solid fa-xmark"></i></button>
    </div>`).join('');
}
function dismissSignal(id,ev){ if(ev)ev.stopPropagation(); post('dismiss',{signal_id:id}).then(()=>loadSignals()); }
function clearSignals(){ post('dismiss_all',{}).then(()=>{ loadSignals(); loadState(); $('#state-sub').textContent='Queue cleared — “Scan now” re-detects anything still wrong.'; }); }
function esc(s){ return (s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

function connectStream(){
  if(es) es.close();
  es=new EventSource('?api=stream&since='+CURSOR);
  es.addEventListener('hello',e=>{ const d=JSON.parse(e.data); CURSOR=d.since; });
  es.addEventListener('event',e=>{ const d=JSON.parse(e.data); CURSOR=Math.max(CURSOR,+d.id); pushEvent(d); });
  es.addEventListener('session',e=>{ const d=JSON.parse(e.data); onSession(d); });
  es.addEventListener('bye',()=>{ es.close(); setTimeout(connectStream,600); });
  es.onerror=()=>{ /* browser auto-reconnects; our since-cursor prevents dupes */ };
}
// grouped transcript: ONE collapsible card per investigation (session), newest on top — no interleaving.
const SESS={};
function sessCard(sid, node){
  sid = sid||0;
  if(SESS[sid]) return SESS[sid];
  const m=feed.querySelector('.muted'); if(m) m.remove();
  const card=document.createElement('div'); card.className='sess-card'; card.dataset.sid=sid;
  card.innerHTML=`<div class="sess-head" onclick="this.parentNode.classList.toggle('collapsed')">`+
    `<i class="fa-solid fa-chevron-down chev"></i><b class="sn">${esc(node||'NEURU')}</b>`+
    `<span class="sess-status ss-active">investigating</span><span class="sess-count">0</span></div>`+
    `<div class="sess-events"></div>`;
  feed.insertBefore(card, feed.firstChild);
  const rec={card, body:card.querySelector('.sess-events'), head:card.querySelector('.sess-head'), node:node, n:0};
  SESS[sid]=rec;
  const cards=feed.querySelectorAll('.sess-card'); if(cards.length>14){ const l=cards[cards.length-1]; delete SESS[l.dataset.sid]; l.remove(); }
  return rec;
}
function setSessStatus(rec, txt, cls){ const s=rec.head.querySelector('.sess-status'); s.textContent=txt; s.className='sess-status '+cls; }
function pushEvent(d){
  const rec=sessCard(d.session_id, d.node_name);
  if(d.node_name && rec.node!==d.node_name){ rec.node=d.node_name; rec.head.querySelector('.sn').textContent=d.node_name; }
  const bodyTxt=trimBody(d), raw=d.body||'';
  // DE-DUP: if the previous row is a repeat/prefix of this one (streamed partials, the final line, AND the
  // "finish (observed): <same text>" echo) — collapse them into ONE row and upgrade it to the newer phase.
  const prev=rec.body.lastElementChild;
  if(prev && prev.classList && prev.classList.contains('ev') && evDup(raw, prev.dataset.raw||'')){
    const tx=prev.querySelector('.tx'); if(tx) tx.textContent=bodyTxt; prev.dataset.raw=raw;
    prev.className='ev '+d.phase; const ico=prev.querySelector('.ph i'); if(ico) ico.className='fa-solid '+(PHASE_ICON[d.phase]||'fa-circle');
    pushEventFx(d,rec); return;
  }
  const ic=PHASE_ICON[d.phase]||'fa-circle';
  const el=document.createElement('div'); el.className='ev '+d.phase; el.dataset.raw=raw;
  el.innerHTML=`<span class="ph"><i class="fa-solid ${ic}"></i></span><div class="tx">${esc(bodyTxt)}</div>`;
  rec.body.appendChild(el); rec.n++; rec.head.querySelector('.sess-count').textContent=rec.n;
  pushEventFx(d,rec);
}
function pushEventFx(d,rec){
  if(d.phase==='result') setSessStatus(rec,'done','ss-done');
  else setSessStatus(rec, ({observe:'observing',think:'thinking',tool:'gathering',act:'acting',narrate:'explaining',error:'error'})[d.phase]||'working', d.phase==='error'?'ss-err':'ss-active');
  if(feed.firstChild!==rec.card) feed.insertBefore(rec.card, feed.firstChild);
  rec.body.scrollTop=rec.body.scrollHeight;
  // while the operator is REWOUND in the Timeline DVR, don't let live events clobber the frozen snapshot's
  // core/phase/attachDevice/state-now — the event still logs to the feed above, just no live-view repaint.
  if(typeof TT!=='undefined' && TT && !TT.live) return;
  setPhase(d.phase,d.node_name);
  if(d.phase==='narrate'){ showNarrate(d.body); }
  if(d.phase==='observe' && d.node_name){ if(!deviceMesh || currentNode!==d.node_name){ currentNode=d.node_name; attachDevice(d.node_name);} }
  const now={observe:'Observing',think:'Reasoning',tool:'Gathering data',act:'Taking action',result:'Concluded',narrate:'Explaining',error:'Hit a snag'}[d.phase]||'Working';
  $('#state-now').textContent=now+(d.node_name?' · '+d.node_name:'');
}
let currentNode=null;
// terse tool observations: turn "route_drift → {"node_id":5,"added":[],"removed":[]}" into "route_drift → sin cambios"
function terseObserve(body){
  const m=(''+body).match(/^([a-z_]+)\s*→\s*([\[{][\s\S]*)$/i); if(!m) return body;
  const tool=m[1]; let js=null; try{ js=JSON.parse(m[2]); }catch(e){ return tool+' → '+m[2].slice(0,60); }
  let s='';
  if(Array.isArray(js)){ s = js.length? (js.length+' resultado(s)') : '0 resultados'; }
  else if(js && typeof js==='object'){
    if('verdict' in js) s=js.verdict;
    else if('outcome' in js) s=js.outcome;
    else if('added' in js && 'removed' in js){ const ad=(js.added||[]).length, rm=(js.removed||[]).length; s=(ad+rm)===0?'sin cambios':(ad+' añadidas, '+rm+' removidas'); }
    else if('talkers' in js){ const tk=js.talkers||[]; s=(tk.length?('top '+((tk[0]||{}).ip||'')):'sin datos'); }
    else if('cpu_pct' in js||'mem_pct' in js) s='CPU '+Math.round(js.cpu_pct||0)+'% · RAM '+Math.round(js.mem_pct||0)+'%';
    else if('count' in js) s=js.count+(js.nodes?' nodos':(js.talkers?' talkers':''));
    else if('opened_map' in js||'opened_xray' in js) s='abierto en pantalla';
    else if('status' in js && 'finding' in js) s=js.finding;   // structured diag verdict
    else { const keys=Object.keys(js).slice(0,3); s=keys.map(k=>k+'='+(typeof js[k]==='object'?'…':js[k])).join(', '); }
  }
  return tool+' → '+(s||'ok');
}
function trimBody(d){ let b=d.body||'';
  if((d.phase==='observe'||d.phase==='tool') && /→\s*[\[{]/.test(b)) b=terseObserve(b);
  b=(''+b).replace(/^finish\s*\([^)]*\)\s*:\s*/i,'');   // drop the "finish (observed):" prefix — status shows in the card header
  if(b.length>220)b=b.slice(0,220)+'…'; return b;
}
// normalized text for de-dup: strip the finish() prefix + collapse whitespace so the streamed partials, the
// final line, AND the "finish (observed): <same text>" echo all compare equal → collapse to ONE row.
function normEv(b){ return (''+b).replace(/^finish\s*\([^)]*\)\s*:\s*/i,'').replace(/\s+/g,' ').trim(); }
function evDup(a,b){ a=normEv(a); b=normEv(b); return !!a && !!b && (a===b || a.startsWith(b) || b.startsWith(a)); }
// render an events ARRAY (history paint) with the SAME de-dup + terse rules as the live stream
function renderEventsList(events){
  const out=[]; let lastRaw='';
  (events||[]).forEach(e=>{ if(evDup(e.body||'', lastRaw)) out.pop();   // collapse a repeat/prefix of the previous row
    lastRaw=e.body||'';
    out.push(`<div class="ev ${e.phase}"><span class="ph"><i class="fa-solid ${PHASE_ICON[e.phase]||'fa-circle'}"></i></span><div class="tx">${esc(trimBody(e))}</div></div>`);
  });
  return out.join('');
}
function showNarrate(txt){ const n=$('#v2-narrate'); n.textContent='“'+txt+'”'; n.classList.add('show'); $('#state-sub').textContent=txt; clearTimeout(n._t); n._t=setTimeout(()=>n.classList.remove('show'),9000); }
function onSession(d){
  const rec=SESS[d.id];
  if(d.status==='done'){ if(rec){ setSessStatus(rec,'done','ss-done'); if(d.summary) rec.head.title=d.summary; } $('#state-now').textContent='Idle — watching the fleet'; if(d.summary)$('#state-sub').textContent=d.summary; setTimeout(()=>{ if(brainState.phase!=='think')detachDevice(); currentNode=null; },2500); loadSignals(); loadState(); if(drawerTab==='actions')renderActions(); }
  else if(d.status==='awaiting_approval'){ if(rec)setSessStatus(rec,'awaiting you','ss-wait'); $('#state-now').textContent='Waiting for your approval'; loadActions_badge(); }
  else if(d.status==='active'||d.status==='queued'){ if(d.node_name){currentNode=d.node_name; attachDevice(d.node_name);} }
}
function loadActions_badge(){ j('?api=actions').then(a=>{ if(a.actions&&a.actions.length){ openTab('actions'); openDrawer(); } }); }

// ─────────────────────────── controls ───────────────────────────
function toggleMaster(el){ post('toggle',{on:el.checked?1:0}).then(r=>{ STATE.enabled=r.enabled; $('#state-sub').textContent=r.enabled?'NEURU is autonomous — it will investigate signals as they arrive.':'NEURU paused. It still shows signals but won’t act until you switch it on.'; }); }
function doScan(btn){ btn.disabled=true; $('#state-now').textContent='Sweeping the fleet…'; post('scan',{}).then(r=>{ btn.disabled=false; loadSignals(); loadState(); const n=(r.pace&&r.pace.promoted)||0, sw=(r.swept||0), bus=((r.scan&&r.scan.new)||0); $('#state-sub').textContent='Sweep — '+(sw+bus)+' node(s) queued, '+n+' investigating now'+(sw+bus>n?' (the rest as slots free up)':'')+'.'; }); }
function investigate(nid,btn){ if(btn){btn.disabled=true;} post('investigate',{node_id:nid}).then(r=>{ if(btn)btn.disabled=false; if(!r.ok){ $('#state-sub').textContent='Could not investigate: '+(r.error||'brain offline'); } else { $('#state-now').textContent='🎯 Dispatching…'; } loadSignals(); }); }
// INSTANT deterministic verdict (the 5-stage engine) — shows "hay o no problema" right away, no metered brain needed.
function quickDiagnose(nid, signalText){
  if(!nid) return;
  const q='?api=diagnose&node='+encodeURIComponent(nid)+(signalText?('&signal='+encodeURIComponent((''+signalText).slice(0,160))):'');
  j(q).then(r=>{ if(!r||!r.ok||!r.data) return; const x=r.data;
    const ic={ok:'✅',problem:'⚠️',needs_action:'🔴',inconclusive:'❔'}[x.status]||'•';
    $('#state-sub').textContent=ic+' '+x.line+(x.action&&x.status!=='ok'?(' · '+x.action):'');
  }).catch(()=>{});
}
// PART 4 — focus-on-🔍: the core turns to the node (flies it in + spin impulse + energy surge) + announces, then investigates.
function focusNode(nid, btn){
  const row = (btn && btn.closest) ? btn.closest('.row') : null;
  const name = (row && row.getAttribute('data-nodename')) || '';
  const title = (row && row.querySelector('.t b')) ? row.querySelector('.t b').textContent : '';
  try{ if(name) attachDevice(name); currentNode = name || currentNode;
       if(typeof brainState!=='undefined' && brainState){ brainState.energy=1.0; brainState.targetColor=new THREE.Color(0x8bf3ff); brainState.spin=(brainState.spin||0)+2.6; } }catch(e){}
  $('#state-now').textContent='🎯 Focusing '+(name||'node'); $('#state-sub').textContent=title||('Investigating '+(name||'node'));
  quickDiagnose(nid, title);   // instant deterministic verdict on screen while the brain works
  investigate(nid, btn);   // real dispatch → status becomes 'investigating' → its cyan filament lights up to the core
}

// ─────────────────────────── chat ───────────────────────────
async function loadChat(){ const h=await j('?api=chat_history'); const log=$('#chatlog'); log.innerHTML=(h.history||[]).map(m=>chatBubble(m.role,m.message)).join(''); log.scrollTop=log.scrollHeight; if(!h.history||!h.history.length){ log.innerHTML=chatBubble('bot','Hi — I’m NEURU. I watch your fleet and fix what I can. Ask me what I’m seeing, tell me what to watch, or point me at a node.'); } }
function chatBubble(role,txt,cmd){ return `<div class="msg ${role==='bot'?'bot':'user'}">${esc(txt)}${cmd?`<div class="cmd">⚙ applied: ${esc(JSON.stringify(cmd))}</div>`:''}</div>`; }
async function sendChat(){
  const inp=$('#chat-msg'); const msg=inp.value.trim(); if(!msg)return; inp.value=''; const log=$('#chatlog');
  log.insertAdjacentHTML('beforeend',chatBubble('user',msg)); log.scrollTop=log.scrollHeight;
  const typing=document.createElement('div'); typing.className='msg bot'; typing.textContent='NEURU is thinking…'; log.appendChild(typing); log.scrollTop=log.scrollHeight;
  const r=await post('chat',{message:msg}); typing.remove();
  log.insertAdjacentHTML('beforeend',chatBubble('bot',r.reply||'…',r.applied)); log.scrollTop=log.scrollHeight;
  if(r.applied) loadState();
  xrUiPoll();   // near-instant: if NEURU opened an X-Ray via a tool, surface it now (don't wait for the 5s tick)
}
// server-pushed UI actions — voice/chat "show the x-ray of X" sets a pending action the cockpit opens here
var lastXrTs=Math.floor(Date.now()/1000);   // ignore any stale action from before this page load
var xrSuppressOpenUntil=0;   // after a LOCAL ui command (panel/scan/autonomous/x-ray-close), ignore a racing assistant X-Ray open
async function xrUiPoll(){ if(document.hidden) return; try{ const r=await j('?api=ui_poll'); const x=r&&r.xray; if(!x||!(x.ts>lastXrTs)) return;
    // autonomous/scan are NOT consumed here (security: the shared channel must not flip other operators' state — the local voice handler does them for the operator who spoke)
    if(x.action==='close'){ lastXrTs=x.ts; if($('#xray-panel').classList.contains('show')) closeXray(); if($('#topo-panel').classList.contains('show')) closeTopo(); if($('#traf-panel').classList.contains('show')) closeTraffic(); if($('#cont-panel')&&$('#cont-panel').classList.contains('show')) closeContainers(); if($('#nt-panel')&&$('#nt-panel').classList.contains('show')) closeNetTools(); }
    else if(x.action==='panel'){ lastXrTs=x.ts; togglePanel(x.panel, !!x.show); }
    else if(x.action==='topology'){ lastXrTs=x.ts; if(Date.now()<xrSuppressOpenUntil) return; openTopo(x.scope||'all'); }
    else if(x.action==='traffic'){ lastXrTs=x.ts; if(Date.now()<xrSuppressOpenUntil) return; openTraffic(x.node||'', x.iface||''); }
    else if(x.action==='containers'){ lastXrTs=x.ts; if(Date.now()<xrSuppressOpenUntil) return; openContainers(x.node||'', x.container||''); }
    else if(x.node_id){   // X-Ray open
      if(Date.now()<xrSuppressOpenUntil) return;   // you just gave a UI command → don't stomp it; DON'T consume the ts, retry after the window
      lastXrTs=x.ts; openXray(x.node_id, x.focus||null);
    } else { lastXrTs=x.ts; }   // unknown/stale action → consume + ignore
  }catch(e){} }

// ─────────────────────────── drawer: devices / rules / actions ───────────────────────────
let drawerTab='devices';
function openDrawer(){ $('#drawer').style.display='flex'; }
function closeDrawer(){ $('#drawer').style.display='none'; }
function openTab(tab){ drawerTab=tab; openDrawer();
  document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('on',t.dataset.tab===tab));
  document.querySelectorAll('.tabpane').forEach(p=>p.classList.toggle('on',p.id==='pane-'+tab));
  if(tab==='devices')renderDevices(); if(tab==='rules')renderRules(); if(tab==='actions')renderActions(); if(tab==='history')renderHistory(); if(tab==='voice')renderVoice(); if(tab==='sources')renderChannels((STATE&&STATE.channels)||[]); if(tab==='memory')renderMemory();
}

// ── VOICE (VAPI) config + launch ──────────────────────────────────────────────
let VAPI_CFG=null;
function openVoice(){
  // voice is EMBEDDED in the center now — draw the eye to it; only open config if unconfigured
  if(VAPI_CFG && VAPI_CFG.configured){
    const el=document.getElementById('v2-voice');
    if(el){ el.scrollIntoView({block:'center',behavior:'smooth'}); el.style.transition='box-shadow .3s'; el.style.boxShadow='0 0 46px rgba(57,230,255,.65)'; setTimeout(()=>{el.style.boxShadow='';},1000); }
    else { window.open('/voice.php','neuruvoice','width=460,height=700'); }   // fallback if the embed didn't render
  } else { openTab('voice'); }
}
// ── NEURU Memory tab — what NEURU has learned (facts, corrections, preferences); view / pin / add / forget ──
const MEM_ICO={fact:'💡',correction:'✏️',preference:'⭐',observation:'👁️',topology:'🕸️',baseline:'📊'};
async function renderMemory(){
  const pane=$('#pane-memory'); pane.innerHTML='<div class="muted">Loading memory…</div>';
  let r; try{ r=await j('?api=mem_list'); }catch(e){ pane.innerHTML='<div class="muted">Failed to load.</div>'; return; }
  const ms=(r&&r.memories)||[], n=(r&&r.count)||0;
  let h='<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><div style="font-size:11px;color:var(--mut);flex:1">NEURU has learned <b style="color:#9fd0ff">'+n+'</b> thing(s) from the network + your conversations. It recalls the relevant ones before every answer.</div>'+
    '<input id="mem-q" placeholder="filter…" oninput="memFilter()" style="width:120px;background:rgba(6,9,20,.7);border:1px solid rgba(120,150,255,.22);border-radius:8px;padding:5px 9px;color:#fff;font-size:12px;outline:none"></div>'+
    '<div style="display:flex;gap:6px;margin-bottom:10px"><input id="mem-new" placeholder="Teach NEURU a fact… (e.g. 192.168.0.253 is CORE-ROUTER ether2)" style="flex:1;background:rgba(6,9,20,.7);border:1px solid rgba(120,150,255,.22);border-radius:8px;padding:7px 10px;color:#fff;font-size:12px;outline:none" onkeydown="if(event.key===\'Enter\')memAdd()"><button class="btn ghost sm" onclick="memAdd()">Teach</button></div>'+
    '<div id="mem-rows">'+memRows(ms)+'</div>';
  pane.innerHTML=h;
}
function memRows(ms){ if(!ms.length) return '<div class="muted" style="padding:12px 2px">Nothing learned yet. It fills as you use NEURU.</div>';
  return ms.map(m=>`<div class="mem-row" style="display:flex;gap:9px;align-items:flex-start;padding:8px 9px;margin-bottom:5px;border-radius:9px;background:rgba(255,255,255,.03);border:1px solid rgba(120,150,255,.1)">
    <span style="font-size:15px">${MEM_ICO[m.kind]||'💡'}</span>
    <div style="flex:1;min-width:0"><div style="font-size:12px;color:#dbe6f5">${esc(m.subject||m.content)}</div>
      ${m.subject&&m.content&&m.content!==m.subject?`<div style="font-size:11px;color:#8fa6c8;margin-top:2px">${esc(m.content)}</div>`:''}
      <div style="font-size:9px;color:var(--mut);margin-top:3px;text-transform:uppercase;letter-spacing:.06em">${esc(m.kind)} · ${esc(m.scope||'general')} · ${esc(m.source||'')} · ${Math.round((m.confidence||0)*100)}%${m.use_count>0?(' · used '+m.use_count+'×'):''}</div></div>
    <span onclick="memPin(${m.id},${m.pinned?0:1})" title="Pin — always recalled" style="cursor:pointer;font-size:13px;opacity:${m.pinned?1:.4}">📌</span>
    <span onclick="memDel(${m.id})" title="Forget" style="cursor:pointer;color:#ff8a9a;font-size:12px">✕</span>
  </div>`).join('');
}
var _memFT=null, _memSeq=0;
function memFilter(){ clearTimeout(_memFT); _memFT=setTimeout(async function(){ const q=($('#mem-q').value||'').toLowerCase(); const seq=++_memSeq;
  try{ const r=await j('?api=mem_list&q='+encodeURIComponent(q)); if(seq===_memSeq) $('#mem-rows').innerHTML=memRows((r&&r.memories)||[]); }catch(e){} }, 220); }   // debounce + drop out-of-order responses
async function memAdd(){ const el=$('#mem-new'); const v=(el.value||'').trim(); if(!v)return; el.value=''; await post('mem_add',{content:v,kind:'fact',scope:'general'}); renderMemory(); }
async function memDel(id){ await post('mem_del',{id}); renderMemory(); }
async function memPin(id,pin){ await post('mem_pin',{id,pin}); renderMemory(); }
async function renderVoice(){
  const pane=$('#pane-voice'); pane.innerHTML='<div class="muted">Loading…</div>';
  const r=await j('?api=vapi_cfg'); const c=(r&&r.cfg)||{}; VAPI_CFG=c;
  const secure = window.isSecureContext;
  pane.innerHTML=
    '<div style="font-size:12px;color:var(--mut);line-height:1.5;margin-bottom:10px">'+
      'Talk to NEURU out loud. Bring your own <b>VAPI</b> account: paste your keys, enable, then <b>Talk</b>. '+
      'The assistant’s <code>ask_neuru</code> tool answers with your live fleet data — same brain as the chat.'+
    '</div>'+
    (secure?'':'<div style="background:rgba(255,90,110,.12);border:1px solid rgba(255,90,110,.4);border-radius:10px;padding:8px 10px;font-size:12px;color:#ffd7dd;margin-bottom:10px">🔒 You’re on HTTP — the mic is blocked. Open NEURU over <b>https://'+location.hostname+':8453</b> to use voice.</div>')+
    '<label class="vlbl">Public key <span class="vmut">(client SDK key — safe in the browser)</span></label>'+
    '<input class="vin" id="vp-pub" placeholder="pk_..." value="'+esc(c.public_key||'')+'">'+
    '<label class="vlbl">Assistant ID</label>'+
    '<input class="vin" id="vp-asst" placeholder="asst_... (leave blank to auto-provision)" value="'+esc(c.assistant_id||'')+'">'+
    '<label class="vlbl">Private key <span class="vmut">'+(c.has_private?'· stored ✓ (leave blank to keep)':'· server-side, encrypted')+'</span></label>'+
    '<input class="vin" id="vp-priv" type="password" placeholder="'+(c.has_private?'•••••••• (unchanged)':'sk_...')+'">'+
    '<label class="vlbl">Public URL <span class="vmut">where VAPI’s cloud reaches this NEURU for the ask_neuru tool</span></label>'+
    '<input class="vin" id="vp-base" placeholder="https://your-neuru.example.com" value="'+esc(c.public_base||'')+'">'+
    '<label class="vrow"><input type="checkbox" id="vp-en" '+(c.enabled?'checked':'')+'> <span>Voice enabled</span></label>'+
    '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px">'+
      '<button class="btn" onclick="saveVapi(this)"><i class="fa-solid fa-floppy-disk"></i> Save</button>'+
      '<button class="btn ghost" onclick="provisionVapi(this)" title="Create/update the NEURU assistant on your VAPI account (uses your private key)"><i class="fa-solid fa-wand-magic-sparkles"></i> Auto-provision assistant</button>'+
      '<button class="btn ghost" onclick="openVoice()" '+(c.configured?'':'disabled')+'><i class="fa-solid fa-microphone"></i> Talk</button>'+
    '</div>'+
    '<div id="vp-msg" style="font-size:12px;margin-top:10px;min-height:16px"></div>'+
    (c.public_base?'':'<div style="font-size:11px;color:#e6b45a;margin-top:8px">⚠ No public base URL set — VAPI’s cloud can’t reach this NEURU for tool calls or auto-provision. Enroll the AI Gateway or set <code>vapi_public_base</code>.</div>');
}
async function saveVapi(btn){
  btn.disabled=true;
  const r=await post('vapi_save',{public_key:$('#vp-pub').value.trim(),assistant_id:$('#vp-asst').value.trim(),public_base:$('#vp-base').value.trim(),enabled:$('#vp-en').checked?1:'',private_key:$('#vp-priv').value});
  btn.disabled=false; VAPI_CFG=(r&&r.cfg)||VAPI_CFG;
  $('#vp-msg').innerHTML=r&&r.ok?'<span style="color:#5fe0a0">Saved.</span>':'<span style="color:#ff8">Save failed.</span>';
  renderVoice();
}
async function provisionVapi(btn){
  if(!confirm('This will CREATE or UPDATE a “NEURU Commander” assistant on YOUR VAPI account (using your private key). Continue?')) return;
  btn.disabled=true; $('#vp-msg').textContent='Provisioning on VAPI…';
  const r=await post('vapi_provision',{}); btn.disabled=false; VAPI_CFG=(r&&r.cfg)||VAPI_CFG;
  $('#vp-msg').innerHTML=r&&r.ok?('<span style="color:#5fe0a0">Assistant ready: '+esc(r.id)+'</span>'):('<span style="color:#ff8">Failed: '+esc((r&&r.error)||'error')+'</span>');
  renderVoice();
}
function renderDevices(){
  const box=$('#pane-devices');
  box.innerHTML='<div style="font-size:11px;color:var(--mut);padding:4px 2px 10px">Per-node autonomy. <b>Observe</b> = watch only · <b>Copilot</b> = propose & ask you · <b>Autopilot</b> = auto-run safe fixes.</div>'+
   DEVICES.map(d=>`<div class="row" style="border-bottom:1px solid rgba(120,150,255,.06)">
    <span class="dot ${d.d_enabled==1?'info':''}" style="${d.d_enabled==1?'':'background:#334;box-shadow:none'}"></span>
    <div class="t"><b>${esc(d.display_name)}</b><span>${esc(d.ip_address||'')}</span></div>
    <select class="mini" onchange="setDevice(${d.id},'autonomy_mode',this.value)">
      <option value="observe"${d.autonomy_mode==='observe'?' selected':''}>observe</option>
      <option value="copilot"${d.autonomy_mode==='copilot'?' selected':''}>copilot</option>
      <option value="autopilot"${d.autonomy_mode==='autopilot'?' selected':''}>autopilot</option></select>
    <label class="sw sm" title="Enable NEURU on this node"><input type="checkbox" ${d.d_enabled==1?'checked':''} onchange="setDevice(${d.id},'enabled',this.checked?1:0)"><span class="track"></span><span class="thumb"></span></label>
   </div>`).join('');
}
function setDevice(nid,field,val){ const b={node_id:nid}; b[field]=val;
  post('device',b).then(r=>{ if(!r||!r.ok){ $('#state-sub').textContent='Could not save that node change.'; return; }
    const d=DEVICES.find(x=>x.id==nid); if(d){ if(field==='enabled') d.d_enabled=val; else d[field]=val; }   // cache uses d_enabled
    loadState(); }); }
async function renderRules(){
  const r=await j('?api=rules'); const box=$('#pane-rules');
  box.innerHTML=`<div style="display:flex;gap:6px;padding:6px 2px 12px;flex-wrap:wrap">
     <select id="r-mt" class="mini"><option value="channel_type">channel:type</option><option value="node">node id</option><option value="fingerprint">fingerprint</option><option value="regex">regex</option></select>
     <input id="r-mv" class="mini" placeholder="match (e.g. nodes_down:node_down)" style="flex:1;min-width:120px">
     <select id="r-pol" class="mini"><option value="ignore">ignore (dismiss forever)</option><option value="always_ask">always ask</option><option value="auto_ack">auto-ack</option><option value="auto_fix">auto-fix</option></select>
     <button class="btn sm" onclick="addRule()">Add</button></div>`+
    ((r.rules&&r.rules.length)?r.rules.map(rl=>`<div class="row" style="border-bottom:1px solid rgba(120,150,255,.06)">
      <div class="t"><b>${esc(rl.match_type)}: ${esc(rl.match_val)}</b><span>${esc(rl.policy)} · ${esc(rl.created_by||'')}${rl.hits>0?' · '+rl.hits+' hits':''}${rl.active==0?' · <i>suggested</i>':''}</span></div>
      ${rl.active==0?`<button class="btn sm" onclick="toggleRule(${rl.id},1)" title="Approve this bot-suggested rule">Approve</button>`:`<button class="btn ghost sm" onclick="toggleRule(${rl.id},0)">Disable</button>`}
      <button class="btn ghost sm" onclick="delRule(${rl.id})"><i class="fa-solid fa-trash"></i></button></div>`).join(''):'<div class="muted">No rules yet. NEURU learns from your dismissals — approve a signal’s “ignore” and it stops bringing it up.</div>');
}
function addRule(){ post('rule_add',{match_type:$('#r-mt').value,match_val:$('#r-mv').value,policy:$('#r-pol').value}).then(()=>{ renderRules(); loadState(); }); }
function toggleRule(id,a){ post('rule_toggle',{id,active:a}).then(()=>{ renderRules(); loadState(); }); }
function delRule(id){ post('rule_del',{id}).then(()=>{ renderRules(); loadState(); }); }
async function renderActions(){
  const a=await j('?api=actions'); const box=$('#pane-actions');
  const pend=(a.actions&&a.actions.length)?a.actions.map(x=>`<div class="row" style="border-bottom:1px solid rgba(120,150,255,.06)">
     <span class="dot ${x.risk==='high'?'critical':x.risk==='medium'?'warning':'info'}"></span>
     <div class="t"><b>${esc(x.tool)}(${esc(x.args||'')})</b><span>${esc(x.node_name||'')} · risk ${x.risk}</span></div>
     <button class="btn sm" onclick="approve(${x.id},this)">Approve</button>
     <button class="btn ghost sm" onclick="deny(${x.id},this)">Deny</button></div>`).join(''):'<div class="muted">Nothing awaiting approval — approve/deny arrive here + on Telegram.</div>';
  const done=(a.recent&&a.recent.length)?('<div style="margin-top:14px;font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.1em;padding:0 2px 6px">Recently done by NEURU</div>'+
     a.recent.map(x=>{ const ic=x.status==='done'?'✅':(x.status==='denied'?'🚫':'⚠️');
       let rep=''; try{ const j=JSON.parse(x.result||'{}'); rep=j.report||j.output||''; }catch(e){ rep=x.result||''; }
       return `<div class="row" style="border-bottom:1px solid rgba(120,150,255,.05);opacity:.92">
         <span style="flex:0 0 auto">${ic}</span>
         <div class="t"><b>${esc(x.tool)}(${esc(x.args||'')})</b><span>${esc(rep.slice(0,80)||x.status)}${x.node_name?' · '+esc(x.node_name):''}</span></div>
         <span class="hist-time">${x.ts?nmAgo(x.ts):''}</span></div>`; }).join('')):'';
  box.innerHTML = pend + done;
}
function approve(id,b){ b.disabled=true; post('approve',{action_id:id}).then(r=>{ renderActions(); loadState(); $('#state-sub').textContent=r.ok?'Action approved & executed.':'Action failed: '+(r.result&&r.result.error||'?'); }); }
function deny(id,b){ b.disabled=true; post('deny',{action_id:id}).then(()=>renderActions()); }

// ─────────────────────────── fullscreen (like the other command centers) ───────────────────────────
function toggleFull(){ const el=document.getElementById('v2-stage');   // fullscreen the STAGE, not the whole doc → no header (aiopilot/command consistency)
  if(!document.fullscreenElement && !document.webkitFullscreenElement){ (el.requestFullscreen||el.webkitRequestFullscreen||function(){}).call(el); }
  else { (document.exitFullscreen||document.webkitExitFullscreen||function(){}).call(document); } }
function onFsChange(){ const fs=!!(document.fullscreenElement||document.webkitFullscreenElement||document.mozFullScreenElement);
  document.documentElement.classList.toggle('nm-fs',fs);   // hides #nm-topbar + pulls HUD up for ANY fullscreen (button or F11)
  const st=document.getElementById('v2-stage'); if(st) st.classList.toggle('fs',fs);
  const b=document.querySelector('#fs-btn i'); if(b) b.className='fa-solid '+(fs?'fa-compress':'fa-expand');
  setTimeout(resize,60); }
document.addEventListener('mozfullscreenchange',onFsChange);
document.addEventListener('fullscreenchange',onFsChange);
document.addEventListener('webkitfullscreenchange',onFsChange);

async function renderHistory(){
  const s=await j('?api=sessions'); const box=$('#pane-history');
  if(!s.sessions||!s.sessions.length){ box.innerHTML='<div class="muted">No past investigations yet. NEURU logs every session here.</div>'; return; }
  box.innerHTML='<div style="font-size:11px;color:var(--mut);padding:4px 2px 10px">Past investigations — click one to expand its full transcript.</div>'+
    s.sessions.map(x=>`<div class="hist-item"><div class="hist-head" onclick="toggleHist(this.parentNode,${x.id})">
      <span class="sess-status ss-${x.status==='done'?'done':(x.status==='awaiting_approval'?'wait':(x.status==='error'?'err':'active'))}">${esc(x.status)}</span>
      <b>${esc(x.node_name||'—')}</b><span class="hist-time">${x.ts?nmAgo(x.ts):''}</span></div>
      ${x.summary?`<div class="hist-sum">${esc(x.summary)}</div>`:''}
      <div class="hist-events" style="display:none"></div></div>`).join('');
}
async function toggleHist(item,sid){
  const ev=item.querySelector('.hist-events');
  if(ev.style.display==='none'){ ev.style.display='block';
    if(!ev.dataset.loaded){ const r=await j('?api=events&session_id='+sid);
      ev.innerHTML=renderEventsList(r.events||[])||'<div class="muted">No events.</div>';
      ev.dataset.loaded='1'; } }
  else ev.style.display='none';
}
function nmAgo(ts){ const s=Math.max(0,Math.floor(Date.now()/1000-ts)); if(s<60)return s+'s ago'; if(s<3600)return Math.floor(s/60)+'m ago'; if(s<86400)return Math.floor(s/3600)+'h ago'; return Math.floor(s/86400)+'d ago'; }

// ─────────────────────────── boot ───────────────────────────
try{ if(window.NMLoader&&NMLoader.hide) NMLoader.hide(); }catch(e){}
// ── LIVE TOOL panel — only visible while NEURU is running a tool (never clutters idle screen) ──
let TH_SIG='', thHideTimer=null, thRunTimer=null, thPrimed=false;
const TH_ICON={reachability:'🛰️',route_lookup:'🧭',route_drift:'📿',run_show_command:'⌨️',ping_host:'📡',node_report:'🩺',bandwidth_top:'📊',traffic_by_app:'📊',traffic_by_country:'🌍',interfaces:'🔌',anomalies:'⚠️',list_nodes:'🗺️',database_report:'🗄️',firewall_rules:'🛡️',firewall_check:'🛡️',firewall_drift:'🛡️',firewall_traffic:'🔥',firewall_addrlists:'🚫',connections:'🔗',blast_radius:'💥'};
const TH_RUNMSG=['Executing…','Running over SSH…','Still working…','Verifying…','Almost there…'];
function esc2(s){ return (s||'').toString().replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function thHop(name,route,gw,cls,conn){ return '<div class="hop '+cls+'">'+(conn?'<span class="conn"></span><span class="flow"></span>':'')+'<span class="dot"></span><div class="htxt"><div class="hn">'+esc2(name)+'</div>'+((route||gw)?'<div class="hr">'+esc2([route,gw].filter(Boolean).join(' · '))+'</div>':'')+'</div></div>'; }
function thRender(ev){
  const d=ev.data||{};
  if(ev.tool==='reachability'){
    const hops=d.hops||[], oc=d.outcome||''; let rows=thHop('SRC',d.src||'source','','ok',false);
    hops.forEach((h,i)=>{ const last=i===hops.length-1; let cls='ok';
      if(last){ if(h.outcome==='delivered'||oc==='delivered')cls='end-delivered'; else if(h.outcome==='internet'||oc==='internet')cls='end-internet'; else if(['no-route','blackhole','loop','unresolved'].indexOf(h.outcome||oc)>=0)cls='end-bad'; }
      rows+=thHop(h.name||('R'+(i+1)), h.route?('route '+h.route):'', h.gw?('gw '+h.gw):'', cls, true); });
    const dcls = oc==='delivered'?'end-delivered':(oc==='internet'?'end-internet':'end-bad');
    rows+=thHop('DST',d.dst||'', '', dcls, true);
    const vcls=(d.verdict||'').indexOf('reachable')===0?(oc==='internet'?'net':'good'):'bad';
    return '<div class="hopchain">'+rows+'</div><div class="th-verdict '+vcls+'">'+esc2(d.verdict||oc)+'</div>';
  }
  if(ev.tool==='route_lookup') return '<div class="th-rows">'+(d.routers||[]).map(x=>'<div class="th-row"><b>'+esc2(x.router)+'</b><span>'+(x.match?esc2(x.match)+' → '+esc2(x.via||'?'):'no route')+'</span></div>').join('')+'</div>';
  if(ev.tool==='route_drift') return '<div class="th-rows"><div class="th-row"><b>added</b><span>'+((d.added||[]).length)+'</span></div><div class="th-row"><b>removed</b><span>'+((d.removed||[]).length)+'</span></div></div>';
  if(ev.tool==='run_show_command') return '<div class="th-term">'+esc2((d.output||'').slice(0,1600))+'</div>';
  return '<div class="th-rows"><div class="th-row"><b>'+(ev.ok?'done':'error')+'</b><span>'+esc2(ev.summary||'')+'</span></div></div>';
}
function renderToolHud(ev){
  const hud=$('#tool-hud'); if(!hud) return;
  $('#th-ico').textContent=TH_ICON[ev.tool]||'⚙';
  $('#th-tool').textContent=(ev.tool||'').replace(/_/g,' ');
  $('#th-chan').textContent=ev.channel==='session'?'AUTO':(ev.channel==='live'?'CHAT · VOICE':(ev.channel||''));
  if(thRunTimer){ clearInterval(thRunTimer); thRunTimer=null; }
  if(ev.status==='running'){                          // still executing → spinner + rotating reassurance
    $('#th-sub').textContent='working…';
    $('#th-body').innerHTML='<div class="th-working"><span class="th-spin"></span><span id="th-runmsg">'+TH_RUNMSG[0]+'</span></div>';
    let i=0; thRunTimer=setInterval(()=>{ i=(i+1)%TH_RUNMSG.length; const e=document.getElementById('th-runmsg'); if(e)e.textContent=TH_RUNMSG[i]; },3500);
    hud.classList.add('show');
    if(thHideTimer)clearTimeout(thHideTimer); thHideTimer=setTimeout(()=>hud.classList.remove('show'),45000);  // safety if it never finishes
  } else {                                            // done → render the rich result
    $('#th-sub').textContent=ev.summary||'';
    $('#th-body').innerHTML=thRender(ev);
    hud.classList.add('show');
    if(thHideTimer)clearTimeout(thHideTimer); thHideTimer=setTimeout(()=>hud.classList.remove('show'),12000);
  }
}
async function pollToolActivity(){ let r; try{ r=await j('?api=tool_activity'); }catch(e){ return; }
  if(!r||!r.ok||!r.events||!r.events.length){ thPrimed=true; return; }
  const ev=r.events[0], sig=ev.id+':'+(ev.status||'');
  if(!thPrimed){ thPrimed=true; TH_SIG=sig; return; }   // baseline on load → only NEW runs pop the panel
  if(sig===TH_SIG) return; TH_SIG=sig; renderToolHud(ev); }

// ── TIMELINE DVR — rewind the whole cockpit to a past minute (reuses Time-Travel) ──
var TT={min:0,max:0,at:null,live:true,playing:false,timer:null,ghosts:null,deb:null,seq:0};
async function ttInit(){ try{ const r=await j('?api=tt_range'); if(r&&r.ok&&r.range){ TT.min=r.range.min; TT.max=r.range.max; } }catch(e){} }
function ttPct(){ return (+($('#tt-slider').value))/1000; }
function ttTs(){ return Math.round(TT.min + (TT.max-TT.min)*ttPct()); }
function ttScrubDebounced(){ if(TT.deb)clearTimeout(TT.deb); TT.deb=setTimeout(ttScrub,120); }
async function ttScrub(){
  if(!TT.max){ return; }
  if(ttPct()>=0.999){ ttGoLive(); return; }
  TT.live=false; const ts=ttTs(); TT.at=ts;
  const d=new Date(ts*1000); $('#tt-time').textContent='⏪ '+d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})+' · '+d.toLocaleDateString();
  $('#tt-time').classList.add('past'); $('#tt-live').style.display='inline-flex'; document.body.classList.add('tt-rewound');
  const seq=++TT.seq;   // guard against out-of-order snapshot responses during fast scrub/playback
  try{ const r=await j('?api=tt_snapshot&at='+ts); if(seq===TT.seq && r&&r.ok&&r.snap) ttApply(r.snap); }catch(e){}
}
function ttApply(s){
  const su=s.summary||{}, tot=(su.up||0)+(su.down||0)+(su.unknown||0);
  $('#k-fleet').textContent=tot; $('#k-open').textContent=su.incidents||0; $('#k-inv').textContent='—'; $('#k-prop').textContent='—';
  $('#state-now').textContent='⏪ Rewound — '+s.at;
  $('#state-sub').textContent=(su.up||0)+' up · '+(su.down||0)+' down · '+(su.incidents||0)+' incidents · '+(s.netflow_mbps||0)+' Mbps';
  ttRenderFleet(s.nodes||[]);
  const downRatio=(su.down||0)/Math.max(1,(su.up||0)+(su.down||0));
  brainState.targetColor=new THREE.Color().setHSL(0.5-Math.min(0.5,downRatio*0.5),1,0.55);
  brainState.energy=Math.min(1,0.3+downRatio);
  ttRenderSlot(s);
}
function ttRenderFleet(nodes){
  if(TT.ghosts){ scene.remove(TT.ghosts); try{ TT.ghosts.geometry.dispose(); TT.ghosts.material.dispose(); }catch(e){} TT.ghosts=null; }
  const N=nodes.length; if(!N||typeof scene==='undefined') return;
  const pos=new Float32Array(N*3), col=new Float32Array(N*3), R=3.7;
  nodes.forEach((n,i)=>{ const a=i/N*Math.PI*2; pos[i*3]=Math.cos(a)*R; pos[i*3+1]=Math.sin(a*3)*0.35; pos[i*3+2]=Math.sin(a)*R;
    const c=n.state==='up'?[0.35,0.9,0.6]:(n.state==='down'?[1,0.24,0.34]:[0.42,0.47,0.62]);
    col[i*3]=c[0]; col[i*3+1]=c[1]; col[i*3+2]=c[2]; });
  const g=new THREE.BufferGeometry(); g.setAttribute('position',new THREE.BufferAttribute(pos,3)); g.setAttribute('color',new THREE.BufferAttribute(col,3));
  TT.ghosts=new THREE.Points(g,new THREE.PointsMaterial({size:.17,map:ROUND,vertexColors:true,transparent:true,opacity:.95,depthWrite:false,sizeAttenuation:true,blending:THREE.AdditiveBlending}));
  scene.add(TT.ghosts);
}
function ttRenderSlot(s){
  const el=$('#v2-left-slot'); if(!el) return;
  const down=(s.nodes||[]).filter(n=>n.state==='down');
  el.innerHTML='<div class="glass panel" style="height:100%"><h3><i class="fa-solid fa-clock-rotate-left"></i> At this moment'+
    '<span style="margin-left:auto;font-size:10px;color:var(--mut);text-transform:none;letter-spacing:0">'+esc(s.at)+'</span></h3>'+
    '<div class="body">'+
    (down.length?('<div style="font-size:11px;color:#ff8a9a;margin-bottom:6px">'+down.length+' node(s) were down</div>'+down.map(n=>'<div class="row"><span class="dot critical"></span><div class="t"><b>'+esc(n.name)+'</b></div></div>').join('')):'<div class="muted">All nodes were up. ✨</div>')+
    ((s.incidents&&s.incidents.length)?('<div style="font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.1em;margin:12px 0 4px">Incidents open then</div>'+s.incidents.map(i=>'<div class="row"><span class="dot '+(i.severity==='critical'?'critical':'warning')+'"></span><div class="t"><b>'+esc(i.title)+'</b></div></div>').join('')):'')+
    '</div></div>';
}
function ttGoLive(){ ttStop(); TT.live=true; TT.at=null; $('#tt-slider').value=1000; $('#tt-time').textContent='● LIVE'; $('#tt-time').classList.remove('past'); $('#tt-live').style.display='none'; document.body.classList.remove('tt-rewound');
  if(TT.ghosts){ scene.remove(TT.ghosts); try{ TT.ghosts.geometry.dispose(); TT.ghosts.material.dispose(); }catch(e){} TT.ghosts=null; } const el=$('#v2-left-slot'); if(el) el.innerHTML='';
  loadState(); loadSignals(); }
function ttPlay(){ if(TT.playing){ ttStop(); return; } if(!TT.max) return; TT.playing=true; $('#tt-play').textContent='⏸';
  if(ttPct()>=0.999){ $('#tt-slider').value=0; }
  TT.timer=setInterval(()=>{ let v=+($('#tt-slider').value)+7; if(v>=1000){ v=1000; $('#tt-slider').value=v; ttStop(); ttGoLive(); return; } $('#tt-slider').value=v; ttScrub(); }, 650); }
function ttStop(){ TT.playing=false; $('#tt-play').textContent='▶'; if(TT.timer){ clearInterval(TT.timer); TT.timer=null; } }

// ══ SURGICAL X-RAY — a living 3D anatomy of one node. Dedicated WebGL scene (own renderer/camera/controls) ══
// Each subsystem is an animated organ driven by REAL telemetry: CPU=beating heart, memory=filling reservoir,
// GPU=reactor, network=particle arteries, disk=platters, thermals=heat aura. Click an organ → dive + details.
var XR={node:0,name:'',data:null,ren:null,scene:null,cam:null,ctrl:null,rayc:null,clock:null,raf:0,
  organs:[],picks:[],focus:null,focusTgt:null,home:null,homeTgt:null,scanning:false,scanT:0,hp:0,railT:null,refreshT:null};

async function openXray(nid, focus){
  // only one full-screen overlay at a time
  if($('#topo-panel').classList.contains('show')) closeTopo();
  if($('#traf-panel').classList.contains('show')) closeTraffic();
  if($('#cont-panel')&&$('#cont-panel').classList.contains('show')) closeContainers();
  if($('#nt-panel')&&$('#nt-panel').classList.contains('show')) closeNetTools();
  if($('#cont-panel')&&$('#cont-panel').classList.contains('show')) closeContainers();
  const p=$('#xray-panel'); p.classList.add('show'); document.body.classList.add('xr-open');
  if(nid){ return pickXray(nid, null, focus); }
  p.classList.add('pick'); $('#xr-rail').style.display='none'; $('#xr-detail').classList.remove('show'); $('#xr-full').style.display='none'; $('#xr-rescan').style.display='none';
  $('#xr-name').textContent='Surgical X-Ray'; $('#xr-vitals').textContent='pick a node to scan its anatomy';
  const pk=$('#xr-picker'); pk.innerHTML='<div class="muted" style="padding:20px">Loading nodes…</div>';
  let r; try{ r=await j('?api=xray_hosts'); }catch(e){ pk.innerHTML='<div class="muted">Failed to load nodes.</div>'; return; }
  const hs=(r&&r.hosts)||[]; const ico={linux:'🐧',windows:'🪟',router:'📡',snmp:'📶',ping:'🔵'};
  pk.innerHTML=hs.length?hs.map(h=>`<div class="xr-pick" onclick="pickXray(${h.node_id},'${esc(h.name).replace(/[\\']/g,"")}')"><span style="font-size:18px">${ico[h.kind]||'🖥'}</span><div class="nm"><b>${esc(h.name)}</b><span class="ip">${esc(h.ip||'')}</span></div><span class="k">${h.rich?h.kind:h.kind+' · snmp'}</span></div>`).join(''):'<div class="muted" style="padding:20px">No monitored nodes.</div>';
}
async function pickXray(nid, name, focus){
  // only one full-screen overlay at a time
  if($('#topo-panel').classList.contains('show')) closeTopo();
  if($('#traf-panel').classList.contains('show')) closeTraffic();
  if($('#cont-panel')&&$('#cont-panel').classList.contains('show')) closeContainers();
  if($('#nt-panel')&&$('#nt-panel').classList.contains('show')) closeNetTools();
  if($('#cont-panel')&&$('#cont-panel').classList.contains('show')) closeContainers();
  const p=$('#xray-panel'); p.classList.add('show'); p.classList.remove('pick'); document.body.classList.add('xr-open');
  XR.node=nid; XR.focusPending=focus||null;
  $('#xr-rail').style.display='flex'; $('#xr-rescan').style.display='inline-flex';
  $('#xr-name').textContent=name||('Node #'+nid); $('#xr-vitals').textContent='🩻 surgical scan in progress…';
  xrInit();
  p.classList.remove('xr-scanning'); void p.offsetWidth; p.classList.add('xr-scanning');   // retrigger the scanline sweep
  let r; try{ r=await j('?api=xray&node='+nid); }catch(e){ $('#xr-vitals').textContent='scan error'; return; }
  if(!r||!r.ok){ $('#xr-vitals').textContent=(r&&r.error)||'scan failed'; return; }
  const x=r.xray; XR.name=x.name||name||('Node #'+nid); $('#xr-name').textContent=XR.name;
  xrBuild(x);
  if(XR.refreshT) clearInterval(XR.refreshT);
  XR.refreshT=setInterval(()=>xrRefresh(0), 8000);   // keep the anatomy live (SSH is heavy → 8s)
  if(XR.focusPending){ setTimeout(()=>{ xrFocus(XR.focusPending); XR.focusPending=null; }, 1500); }
}
async function xrRefresh(loud){
  if(!XR.node) return; if(loud){ $('#xr-vitals').textContent='🩻 re-scanning…'; const p=$('#xray-panel'); p.classList.remove('xr-scanning'); void p.offsetWidth; p.classList.add('xr-scanning'); }
  let r; try{ r=await j('?api=xray&node='+XR.node); }catch(e){ return; }
  if(r&&r.ok){ XR.data=r.xray; xrVitalsLine(r.xray); xrRailValues(); if(XR.focus) xrDetail(XR.focus); }
}
function xrVitalsLine(x){
  const c=x.cpu||{}, m=x.memory||{}, st=(x.status&&x.status.state)||'';
  $('#xr-vitals').textContent=[ (x.kind||''), (st?('● '+st):''), (c.pct!=null?('CPU '+Math.round(c.pct)+'%'):null), (m.pct!=null?('MEM '+Math.round(m.pct)+'%'):null),
    ((x.gpu&&x.gpu.length)?('GPU '+Math.round(x.gpu[0].util||0)+'%'):null), (x.uptime_s?('up '+xrDur(x.uptime_s)):null) ].filter(Boolean).join('  ·  ');
}
function xrDur(s){ s=+s||0; const d=Math.floor(s/86400), h=Math.floor(s%86400/3600); return d>0?(d+'d '+h+'h'):(h+'h'); }

// ── dedicated renderer / scene / loop ──
function xrInit(){
  if(XR.ren) return;
  const cv=document.getElementById('xr-canvas');
  XR.ren=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true}); XR.ren.setPixelRatio(Math.min(2,window.devicePixelRatio||1));
  XR.scene=new THREE.Scene();
  XR.cam=new THREE.PerspectiveCamera(52,1,0.1,120); XR.home=new THREE.Vector3(0,1.4,9.4); XR.homeTgt=new THREE.Vector3(0,-0.2,0);
  XR.cam.position.copy(XR.home);
  XR.ctrl=new THREE.OrbitControls(XR.cam,cv); XR.ctrl.enableDamping=true; XR.ctrl.dampingFactor=.08; XR.ctrl.minDistance=1.6; XR.ctrl.maxDistance=24; XR.ctrl.zoomSpeed=0.85; XR.ctrl.enablePan=false; XR.ctrl.target.copy(XR.homeTgt);
  XR.scene.add(new THREE.AmbientLight(0x5566aa,0.9));
  const p1=new THREE.PointLight(0x77bbff,1.3,60); p1.position.set(5,7,9); XR.scene.add(p1);
  const p2=new THREE.PointLight(0xff6a88,0.7,60); p2.position.set(-7,-4,5); XR.scene.add(p2);
  XR.rayc=new THREE.Raycaster(); XR.clock=new THREE.Clock();
  cv.addEventListener('click',xrPick);
  window.addEventListener('resize',xrResize); xrResize(); xrLoop();
  window.addEventListener('keydown',function(e){ if(e.key==='Escape' && $('#xray-panel').classList.contains('show')){ if(XR.focus) xrUnfocus(); else closeXray(); } });   // Esc: back out of focus, then close
  $('#xr-hint').style.display='block';
}
function xrResize(){ if(!XR.ren)return; const cv=XR.ren.domElement, w=cv.clientWidth||window.innerWidth, h=cv.clientHeight||window.innerHeight; XR.ren.setSize(w,h,false); XR.cam.aspect=w/h; XR.cam.updateProjectionMatrix(); }
function xrLoop(){ XR.raf=requestAnimationFrame(xrLoop); if(!XR.ren||!$('#xray-panel').classList.contains('show'))return;
  const dt=Math.min(0.05,XR.clock.getDelta()), t=XR.clock.elapsedTime, d=XR.data;
  if(XR.scanning){ XR.scanT+=dt; if(XR.scanT>=1.4){ XR.scanning=false; XR.organs.forEach(o=>{o.group.scale.setScalar(1);o.group.visible=true;}); } }
  XR.organs.forEach(o=>{
    if(XR.scanning){ const sweep=3.0 - (XR.scanT/1.4)*8.0; const y=o.group.position.y; let rev = y>sweep+0.5?0 : (y>sweep-1.0? (sweep+0.5-y)/1.5 : 1); rev=Math.max(0,Math.min(1,rev)); o.group.visible=rev>0.02; o.group.scale.setScalar(0.0001+rev); }
    try{ o.update(dt,t,d); }catch(e){}
  });
  if(XR.focusTgt){ XR.cam.position.lerp(XR.focusTgt.cam,0.09); XR.ctrl.target.lerp(XR.focusTgt.tgt,0.09);
    // release control once we've essentially arrived — otherwise the tween fights the user's zoom/orbit every frame
    if(XR.cam.position.distanceTo(XR.focusTgt.cam)<0.12 && XR.ctrl.target.distanceTo(XR.focusTgt.tgt)<0.12) XR.focusTgt=null; }
  XR.ctrl.update(); XR.ren.render(XR.scene,XR.cam);
  xrLabels();
}
// project each organ's 3D position → screen and float a live metric label on it (crisp HTML text)
var _xrPV=null;
function xrLabels(){ if(!XR.ren)return; if(!_xrPV)_xrPV=new THREE.Vector3(); const cv=XR.ren.domElement, w=cv.clientWidth, h=cv.clientHeight, d=XR.data;
  XR.organs.forEach(o=>{ if(!o.labEl)return; if(XR.scanning||!o.group.visible){ o.labEl.style.opacity=0; return; }
    _xrPV.copy(o.group.position); _xrPV.project(XR.cam); const behind=_xrPV.z>1;
    if(behind){ o.labEl.style.opacity=0; return; }
    const x=(_xrPV.x*0.5+0.5)*w, y=(-_xrPV.y*0.5+0.5)*h;
    o.labEl.style.transform='translate(-50%,-160%) translate('+(x|0)+'px,'+(y|0)+'px)';
    const dim=(XR.focus&&XR.focus!==o.key); o.labEl.style.opacity=dim?0.35:1;
    const vb=o.labEl.querySelector('b'); const nv=xrValFor(o.key,d); if(vb.textContent!==nv) vb.textContent=nv; });
}
function xrValFor(key,d){ d=d||{}; switch(key){
  case 'core': return (d.status&&d.status.state)?d.status.state:'';
  case 'cpu': return (d.cpu&&d.cpu.pct!=null)?Math.round(d.cpu.pct)+'%':'';
  case 'memory': return (d.memory&&d.memory.pct!=null)?Math.round(d.memory.pct)+'%':'';
  case 'gpu': return (d.gpu&&d.gpu.length)?Math.round(d.gpu[0].util||0)+'%'+(d.gpu[0].temp?(' · '+Math.round(d.gpu[0].temp)+'°'):''):'';
  case 'network': return d.network?('▾'+Math.round((d.network.rx_kbps||0)/125)+' ▴'+Math.round((d.network.tx_kbps||0)/125)+' Mb'):'';
  case 'disks': return (d.disks&&d.disks.length)?Math.max.apply(null,d.disks.map(x=>Math.round(x.pct||0)))+'%':'';
  case 'processes': return (d.processes||[]).length?((d.processes||[]).length+' proc'):'';
  case 'containers': return (d.containers||[]).length?((d.containers||[]).length+' ctr'):'';
  case 'sensors': return (d.sensors&&d.sensors.max_temp)?Math.round(d.sensors.max_temp)+'°C':'';
  default: return ''; } }
function xrDisposeGroup(g){ g.traverse(function(o){ if(o.geometry)try{o.geometry.dispose();}catch(e){} if(o.material){ (Array.isArray(o.material)?o.material:[o.material]).forEach(function(m){try{m.dispose();}catch(e){}}); } }); }
function xrClear(){ XR.organs.forEach(o=>{ XR.scene.remove(o.group); xrDisposeGroup(o.group); }); XR.organs=[]; XR.picks=[]; }

// ── build the organism from telemetry ──
function xrBuild(x){
  XR.data=x; xrClear();
  const add=(o)=>{ if(!o)return; o.group.userData.organKey=o.key; XR.scene.add(o.group); XR.organs.push(o); if(o.pickable!==false) XR.picks.push(o.group); };
  add(xrOrgCore());
  if(x.cpu) add(xrOrgHeart());
  if(x.memory && x.memory.pct!=null) add(xrOrgMem());
  (x.gpu||[]).slice(0,2).forEach((g,i)=>add(xrOrgGpu(i)));
  if(x.network) add(xrOrgNet());
  if((x.disks||[]).length) add(xrOrgDisk());
  if((x.processes||[]).length) add(xrOrgProcs());
  if((x.containers||[]).length) add(xrOrgConts());
  add(xrOrgAura());   // thermals (always, subtle)
  XR.scanning=true; XR.scanT=0; XR.hp=0;
  XR.focusTgt={cam:XR.home.clone(),tgt:XR.homeTgt.clone()}; XR.focus=null; $('#xr-detail').classList.remove('show'); $('#xr-full').style.display='none';
  xrVitalsLine(x); xrRail(); xrLabelsBuild();
  if(XR.railT) clearInterval(XR.railT); XR.railT=setInterval(xrRailValues,1200);
}
// one floating HTML label per organ (icon + live value), positioned each frame by xrLabels()
function xrLabelsBuild(){ const box=$('#xr-labels'); box.innerHTML=''; XR.organs.forEach(o=>{ o.labEl=null; if(!o.rail)return;
  const el=document.createElement('div'); el.className='xr-lab'; el.style.opacity=0; el.innerHTML='<span class="i">'+o.rail.ic+'</span><b></b>'; box.appendChild(el); o.labEl=el; }); }
function beat(ph){ return Math.exp(-Math.pow((ph-0.0)/0.045,2)) + 0.62*Math.exp(-Math.pow((ph-0.17)/0.05,2)); }   // lub-dub

// CORE — the node nucleus (status-colored)
function xrOrgCore(){ const g=new THREE.Group();
  const core=new THREE.Mesh(new THREE.IcosahedronGeometry(0.85,1), new THREE.MeshStandardMaterial({color:0x1b2a55,emissive:0x2a4a8f,emissiveIntensity:.6,metalness:.4,roughness:.35,transparent:true,opacity:.92}));
  const shell=new THREE.Mesh(new THREE.IcosahedronGeometry(1.12,1), new THREE.MeshBasicMaterial({color:0x5fa8ff,wireframe:true,transparent:true,opacity:.28}));
  g.add(core,shell);
  return {key:'core',rail:{ic:'🧬',lb:'Overview'},group:g,update:(dt,t,d)=>{ core.rotation.y+=dt*.2; shell.rotation.y-=dt*.12; shell.rotation.x+=dt*.05;
    const st=(d&&d.status&&d.status.state)||''; const col= st==='down'?0xff4d6a : (st==='degraded'?0xffb454 : 0x5fe0a0); shell.material.color.setHex(col); core.scale.setScalar(1+Math.sin(t*1.5)*0.02); }};
}
// CPU — beating heart + per-core satellites
function xrOrgHeart(){ const g=new THREE.Group(); g.position.set(-2.8,1.15,0);
  const mat=new THREE.MeshStandardMaterial({color:0xff3355,emissive:0xff1133,emissiveIntensity:.55,roughness:.35,metalness:.1,transparent:true,opacity:.94});
  const heart=new THREE.Group(); const s=0.42;
  const l=new THREE.Mesh(new THREE.SphereGeometry(s,22,22),mat); l.position.set(-s*0.6,s*0.34,0);
  const r=new THREE.Mesh(new THREE.SphereGeometry(s,22,22),mat); r.position.set(s*0.6,s*0.34,0);
  const c=new THREE.Mesh(new THREE.ConeGeometry(s*1.28,s*2.05,26),mat); c.rotation.x=Math.PI; c.position.set(0,-s*0.62,0);
  heart.add(l,r,c); g.add(heart);
  const sats=[]; const nc=Math.min(16,Math.max(1,(XR.data&&XR.data.cpu&&XR.data.cpu.cores_count)||4));
  for(let i=0;i<nc;i++){ const m=new THREE.Mesh(new THREE.SphereGeometry(0.065,12,12), new THREE.MeshBasicMaterial({color:0x39e6ff,transparent:true,opacity:.9})); g.add(m); sats.push(m); }
  return {key:'cpu',rail:{ic:'🫀',lb:'CPU'},group:g,update:(dt,t,d)=>{ const cpu=(d&&d.cpu&&d.cpu.pct)||0; const T=1.15-(Math.min(100,cpu)/100)*0.8;
    XR.hp=(XR.hp+dt/Math.max(0.2,T))%1; const amp=0.05+Math.min(100,cpu)/100*0.14; heart.scale.setScalar(1+amp*beat(XR.hp));
    const hue=0.33*(1-Math.min(100,cpu)/100); mat.color.setHSL(hue,.9,.55); mat.emissive.setHSL(hue,.95,.4);
    const cores=(d&&d.cpu&&d.cpu.cores)||[]; sats.forEach((m,i)=>{ const a=i/sats.length*Math.PI*2 + t*0.5; m.position.set(Math.cos(a)*0.95,Math.sin(a*2)*0.28+0.2,Math.sin(a)*0.95);
      const cp=cores.length?(cores[i%cores.length]||0):cpu; m.material.color.setHSL(0.33*(1-Math.min(100,cp)/100),1,0.55); m.scale.setScalar(0.7+Math.min(100,cp)/100*1.3); }); }};
}
// MEMORY — glass reservoir that fills to mem%
function xrOrgMem(){ const g=new THREE.Group(); g.position.set(2.8,1.0,0); const R=0.6,H=1.8;
  const glass=new THREE.Mesh(new THREE.CylinderGeometry(R,R,H,30,1,true), new THREE.MeshBasicMaterial({color:0x9b6bff,transparent:true,opacity:.13,side:THREE.DoubleSide}));
  const rimT=new THREE.Mesh(new THREE.TorusGeometry(R,0.022,8,30),new THREE.MeshBasicMaterial({color:0x9b6bff,transparent:true,opacity:.55})); rimT.rotation.x=Math.PI/2; rimT.position.y=H/2;
  const rimB=rimT.clone(); rimB.position.y=-H/2;
  const fillMat=new THREE.MeshStandardMaterial({color:0x8b5bff,emissive:0x6a3bff,emissiveIntensity:.5,transparent:true,opacity:.72});
  const fill=new THREE.Mesh(new THREE.CylinderGeometry(R*0.95,R*0.95,1,30),fillMat);
  const swap=new THREE.Mesh(new THREE.CylinderGeometry(R*0.95,R*0.95,1,30), new THREE.MeshBasicMaterial({color:0xff7a3d,transparent:true,opacity:.4}));
  g.add(glass,rimT,rimB,fill,swap);
  return {key:'memory',rail:{ic:'💾',lb:'Memory'},group:g,update:(dt,t,d)=>{ const m=(d&&d.memory)||{}; const pct=Math.max(0,Math.min(100,m.pct||0));
    const h=Math.max(0.02,H*pct/100); fill.scale.y=h; fill.position.y=-H/2+h/2; const hot=pct>85; fillMat.color.setHex(hot?0xff5a6e:(pct>70?0xff9a4d:0x8b5bff)); fillMat.emissive.setHex(hot?0xff2244:0x6a3bff);
    const sp=Math.max(0,Math.min(100,m.swap_pct||0)); const sh=Math.max(0.001,H*sp/100*0.5); swap.visible=sp>0.5; swap.scale.y=sh; swap.position.y=-H/2+sh/2; g.rotation.y+=dt*0.1; }};
}
// GPU — reactor turbine
function xrOrgGpu(gi){ const g=new THREE.Group(); g.position.set(1.2+gi*0.0,-2.0-gi*0.0,1.5-gi*1.4);
  const torus=new THREE.Mesh(new THREE.TorusGeometry(0.55,0.12,16,40), new THREE.MeshStandardMaterial({color:0x39e6ff,emissive:0x1a6a8f,emissiveIntensity:.5,metalness:.65,roughness:.3}));
  const coreM=new THREE.Mesh(new THREE.IcosahedronGeometry(0.28,0), new THREE.MeshBasicMaterial({color:0xff8a3d,transparent:true,opacity:.95}));
  const ring=new THREE.Mesh(new THREE.TorusGeometry(0.78,0.02,8,48), new THREE.MeshBasicMaterial({color:0x39e6ff,transparent:true,opacity:.35})); ring.rotation.x=Math.PI/2;
  g.add(torus,coreM,ring);
  return {key:gi===0?'gpu':'gpu'+gi,rail:gi===0?{ic:'⚛️',lb:'GPU'}:null,pickable:gi===0,group:g,update:(dt,t,d)=>{ const gg=(d&&d.gpu&&d.gpu[gi])||{}; const u=(gg.util||0)/100, temp=gg.temp||0;
    torus.rotation.y+=dt*(0.4+u*5); torus.rotation.x+=dt*(0.2+u*2.5); ring.rotation.z+=dt*(0.3+u*3);
    coreM.material.color.setHSL(Math.max(0,0.14-Math.min(0.14,temp/110*0.14)),1,0.55); coreM.scale.setScalar(0.85+u*0.5+Math.sin(t*7)*0.05*u); torus.material.emissiveIntensity=0.3+u*0.9; }};
}
// NETWORK — dual particle arteries (rx cyan in, tx magenta out)
function xrOrgNet(){ const g=new THREE.Group(); const streams=[];
  const mk=(dir,col)=>{ const curve=new THREE.QuadraticBezierCurve3(new THREE.Vector3(0,0.1,0.3), new THREE.Vector3(dir*2.0,0.5,1.4), new THREE.Vector3(dir*3.8,-1.0,1.0));
    const N=44, pos=new Float32Array(N*3), geo=new THREE.BufferGeometry();
    for(let i=0;i<N;i++){ const p=curve.getPoint(i/(N-1)); pos[i*3]=p.x;pos[i*3+1]=p.y;pos[i*3+2]=p.z; } geo.setAttribute('position',new THREE.BufferAttribute(pos,3));
    const mat=new THREE.PointsMaterial({color:col,size:0.1,map:(typeof ROUND!=='undefined'?ROUND:null),transparent:true,opacity:.5,depthWrite:false,blending:THREE.AdditiveBlending,sizeAttenuation:true});
    const pts=new THREE.Points(geo,mat); g.add(pts); const s={curve,geo,mat,off:0,N,dir}; streams.push(s); return s; };
  mk(-1,0x39e6ff); mk(1,0xff5aa8);
  return {key:'network',rail:{ic:'🌐',lb:'Network'},pickable:true,group:g,update:(dt,t,d)=>{ const nd=(d&&d.network)||{}; const rr=Math.min(1,(nd.rx_kbps||0)/6000), tr=Math.min(1,(nd.tx_kbps||0)/6000);
    streams.forEach((s,i)=>{ const rate=i===0?rr:tr; s.off=(s.off+dt*(0.25+rate*3.2))%1; const pa=s.geo.attributes.position; for(let k=0;k<s.N;k++){ const f=(k/s.N+s.off)%1; const p=s.curve.getPoint(f); pa.setXYZ(k,p.x,p.y,p.z);} pa.needsUpdate=true; s.mat.opacity=0.2+rate*0.75; s.mat.size=0.06+rate*0.09; }); }};
}
// STORAGE — stacked spinning platters, one per filesystem
function xrOrgDisk(){ const g=new THREE.Group(); g.position.set(0,-2.6,-0.5); const disks=(XR.data&&XR.data.disks)||[]; const rings=[]; const n=Math.min(6,Math.max(1,disks.length));
  for(let i=0;i<n;i++){ const rad=0.5+i*0.17; const ring=new THREE.Mesh(new THREE.TorusGeometry(rad,0.05,10,44), new THREE.MeshStandardMaterial({color:0x39e6ff,emissive:0x0a4a5f,emissiveIntensity:.4,metalness:.5,roughness:.4})); ring.rotation.x=Math.PI/2; ring.position.y=i*0.13; g.add(ring); rings.push(ring); }
  return {key:'disks',rail:{ic:'💿',lb:'Storage'},group:g,update:(dt,t,d)=>{ const dd=(d&&d.disks)||[]; rings.forEach((ring,i)=>{ ring.rotation.z+=dt*(0.25+i*0.06); const pct=(dd[i]&&dd[i].pct)||0; const hot=pct>85; ring.material.emissiveIntensity=0.25+pct/100*0.8; ring.material.color.setHex(hot?0xff5a6e:(pct>65?0xffb454:0x39e6ff)); }); }};
}
// PROCESSES — orbiting motes sized by CPU
function xrOrgProcs(){ const g=new THREE.Group(); const motes=[]; const ps=(XR.data&&XR.data.processes)||[]; const n=Math.min(14,ps.length);
  for(let i=0;i<n;i++){ const m=new THREE.Mesh(new THREE.SphereGeometry(0.06,10,10), new THREE.MeshBasicMaterial({color:0x8fd0ff,transparent:true,opacity:.85})); g.add(m); motes.push({m,a:i/n*Math.PI*2}); }
  return {key:'processes',rail:{ic:'⚙️',lb:'Processes'},group:g,update:(dt,t,d)=>{ const pp=(d&&d.processes)||[]; motes.forEach((o,i)=>{ const cpu=(pp[i]&&pp[i].cpu)||0; o.a+=dt*(0.18+Math.min(100,cpu)/100*0.9); const r=3.2, y=Math.sin(o.a*2+i)*0.55; o.m.position.set(Math.cos(o.a)*r,y,Math.sin(o.a)*r); o.m.scale.setScalar(0.7+Math.min(100,cpu)/100*2.4); o.m.material.color.setHSL(0.55-Math.min(100,cpu)/100*0.55,1,0.6); }); }};
}
// CONTAINERS — docked cubes at the base
function xrOrgConts(){ const g=new THREE.Group(); g.position.set(0,-3.3,0); const cs=(XR.data&&XR.data.containers)||[]; const n=Math.min(12,cs.length);
  for(let i=0;i<n;i++){ const c=cs[i]; const st=(typeof c==='object'&&(c.state||c.State))||''; const down=/exit|dead|stop/i.test(st);
    const m=new THREE.Mesh(new THREE.BoxGeometry(0.17,0.17,0.17), new THREE.MeshStandardMaterial({color:down?0xff5a6e:0x5fe0a0,emissive:down?0x5a1020:0x0a3a25,emissiveIntensity:.5,metalness:.3,roughness:.5})); m.position.set((i-(n-1)/2)*0.28,0,0); g.add(m); }
  return {key:'containers',rail:{ic:'📦',lb:'Containers'},group:g,update:(dt,t)=>{ g.rotation.y=Math.sin(t*0.3)*0.15; g.children.forEach((m,i)=>{ m.position.y=Math.sin(t*2+i)*0.04; }); }};
}
// THERMALS — heat aura enveloping the whole organism
function xrOrgAura(){ const m=new THREE.Mesh(new THREE.SphereGeometry(5,28,20), new THREE.MeshBasicMaterial({color:0xff6a3d,transparent:true,opacity:0,side:THREE.BackSide,blending:THREE.AdditiveBlending,depthWrite:false}));
  return {key:'sensors',rail:{ic:'🌡️',lb:'Thermals'},pickable:false,group:m,update:(dt,t,d)=>{ const mx=(d&&d.sensors&&d.sensors.max_temp)||0; const hot=Math.max(0,Math.min(1,(mx-40)/50)); m.material.opacity=hot*0.09+Math.sin(t*2)*0.008*hot; m.material.color.setHSL(Math.max(0,0.08-hot*0.08),1,0.5); }};
}

// ── raycast → focus an organ ──
function xrPick(ev){ if(!XR.ren||XR.scanning)return; const cv=XR.ren.domElement, r=cv.getBoundingClientRect();
  XR.rayc.setFromCamera({x:((ev.clientX-r.left)/r.width)*2-1, y:-((ev.clientY-r.top)/r.height)*2+1}, XR.cam);
  const hits=XR.rayc.intersectObjects(XR.picks,true);
  if(hits.length){ let o=hits[0].object; while(o&&!o.userData.organKey&&o.parent) o=o.parent; if(o&&o.userData.organKey) xrFocus(o.userData.organKey); }
}
function xrFocus(key){ const o=XR.organs.find(x=>x.key===key); if(!o){ return; } XR.focus=key;
  const p=o.group.position.clone(); const off=p.clone().setY(0); if(off.length()<0.2) off.set(0,0,1); off.normalize();
  XR.focusTgt={cam:p.clone().add(off.multiplyScalar(2.4)).add(new THREE.Vector3(0,0.8,2.7)), tgt:p.clone()};
  $('#xr-full').style.display='inline-flex'; xrDetail(key); xrRailActive(key);
}
function xrUnfocus(){ XR.focus=null; XR.focusTgt={cam:XR.home.clone(),tgt:XR.homeTgt.clone()}; $('#xr-detail').classList.remove('show'); $('#xr-full').style.display='none'; xrRailActive(''); }

// ── left rail ──
function xrRail(){ const el=$('#xr-rail'); el.innerHTML=XR.organs.filter(o=>o.rail).map(o=>`<div class="xrr" id="xrr-${o.key}" onclick="xrFocus('${o.key}')"><span class="ic">${o.rail.ic}</span><span class="lb">${o.rail.lb}</span><span class="vl" id="xrv-${o.key}"></span></div>`).join(''); xrRailValues(); }
function xrRailValues(){ const d=XR.data||{}; XR.organs.forEach(o=>{ if(!o.rail)return; const e=document.getElementById('xrv-'+o.key); if(e){ const v=xrValFor(o.key,d); e.textContent = (o.key==='cpu'||o.key==='memory') ? (v||'—') : v; } }); }
function xrRailActive(key){ document.querySelectorAll('#xr-rail .xrr').forEach(e=>e.classList.remove('on')); const a=document.getElementById('xrr-'+key); if(a)a.classList.add('on'); }

// ── detail HUD per organ ──
function xrBar(pct,cls){ pct=Math.max(0,Math.min(100,pct||0)); return `<div class="xrbar ${cls||''}"><i style="width:${pct}%"></i></div>`; }
function xrMetric(k,v,extra){ return `<div class="xr-metric"><div class="k">${k}${v!=null?('<b>'+v+'</b>'):''}</div>${extra||''}</div>`; }
function xrDetail(key){ const d=XR.data||{}; const dh=$('#xr-dh'), db=$('#xr-db'); const o=XR.organs.find(x=>x.key===key); dh.innerHTML=(o&&o.rail?o.rail.ic+' '+o.rail.lb:key); let h='';
  if(key==='core'){ const s=d.status||{}; h=xrMetric('Node',esc(d.name||''))+xrMetric('IP',esc(d.ip||'—'))+xrMetric('Kind',esc(d.kind||'—'))+xrMetric('OS',esc(d.os||'—'))+xrMetric('Uptime',d.uptime_s?xrDur(d.uptime_s):'—')+xrMetric('Live state',esc(s.state||'unknown'))+(s.detail?`<div style="font-size:11px;color:#8fb2d8">${esc(s.detail)}</div>`:'');
    if((d.health||[]).length){ h+='<div class="k" style="margin-top:8px">Predictive health</div>'+d.health.map(x=>`<div style="font-size:12px;color:${x.severity==='crit'?'#ff8a9a':'#ffcf8a'};margin:3px 0">${esc(x.metric)} · ${x.eta_days!=null?('~'+Math.round(x.eta_days)+'d'):''} ${esc(x.detail||'')}</div>`).join(''); } }
  else if(key==='cpu'){ const c=d.cpu||{}; h=xrMetric('Overall', (c.pct!=null?Math.round(c.pct)+'%':'—'), xrBar(c.pct, c.pct>85?'crit':c.pct>60?'warn':''));
    if(c.load) h+=xrMetric('Load avg', c.load.map(x=>(+x).toFixed(2)).join('  '));
    if(c.temp!=null) h+=xrMetric('Temperature', Math.round(c.temp)+'°C');
    h+=xrMetric('Cores', (c.cores&&c.cores.length?c.cores.length:c.cores_count||'—'));
    if(c.cores&&c.cores.length){ h+='<div class="xr-cores">'+c.cores.map(p=>`<div class="xr-core" title="${Math.round(p)}%"><i style="height:${Math.max(4,Math.min(100,p))}%;background:hsl(${(1-Math.min(100,p)/100)*120},90%,55%)"></i></div>`).join('')+'</div>'; } }
  else if(key==='memory'){ const m=d.memory||{}; h=xrMetric('Used', (m.pct!=null?Math.round(m.pct)+'%':'—')+(m.used_mb!=null?('  ·  '+xrMB(m.used_mb)+' / '+xrMB(m.total_mb)):''), xrBar(m.pct,m.pct>90?'crit':m.pct>75?'warn':''));
    if(m.cache_mb!=null) h+=xrMetric('Cache / buffers', xrMB((m.cache_mb||0)+(m.buffers_mb||0)));
    if(m.swap_total_mb) h+=xrMetric('Swap', Math.round(m.swap_pct||0)+'%  ·  '+xrMB(m.swap_used_mb)+' / '+xrMB(m.swap_total_mb), xrBar(m.swap_pct,'warn'));
    if(m.commit_total_mb) h+=xrMetric('Commit', xrMB(m.commit_used_mb)+' / '+xrMB(m.commit_total_mb)); }
  else if(key==='gpu'){ h=(d.gpu||[]).map((g,i)=>xrMetric((i+1)+'. '+esc(g.name||'GPU'), Math.round(g.util||0)+'%', xrBar(g.util,g.util>90?'warn':'')+`<div style="font-size:11px;color:#8fb2d8;margin-top:3px">${xrMB(g.mem_used)} / ${xrMB(g.mem_total)} VRAM · ${Math.round(g.temp||0)}°C · ${Math.round(g.power||0)}W</div>`)).join('')||'<div class="muted">no GPU</div>'; }
  else if(key==='network'){ const n=d.network||{}; h=xrMetric('Throughput', '▾ '+xrRate(n.rx_kbps)+'   ▴ '+xrRate(n.tx_kbps));
    h+='<div class="k">Interfaces</div>'+((n.ifaces||[]).length?n.ifaces.map(f=>`<div class="xr-proc"><span class="pn" style="color:${f.up?'#dbe6f5':'#8a94aa'}">${f.up?'●':'○'} ${esc(f.name)}</span><span class="pv">▾${(+f.rx).toFixed(2)} ▴${(+f.tx).toFixed(2)} ${esc(f.unit||'')}</span></div>`).join(''):'<div class="muted">no interface data</div>'); }
  else if(key==='disks'){ h=(d.disks||[]).map(x=>xrMetric(esc(x.mount||'/')+(x.total_gb?('  ·  '+Math.round(x.total_gb)+'GB'):''), (x.pct!=null?Math.round(x.pct)+'%':'—'), xrBar(x.pct,x.pct>90?'crit':x.pct>75?'warn':''))).join('')||'<div class="muted">no disks</div>'; }
  else if(key==='processes'){ const ps=d.processes||[]; h='<div class="k" style="margin-bottom:6px">Top by CPU · 💀 = guarded kill</div>'+(ps.length?ps.map(p=>`<div class="xr-proc"><span class="pn">${esc(p.name)}</span><span class="pv">${(+p.cpu||0).toFixed(0)}% · ${(+p.mem||0).toFixed(0)}MB</span>${(d.probe&&d.probe.indexOf('snmp')<0)?`<button class="xr-kill" onclick="killProc('${esc(p.name).replace(/[\\']/g,"")}')" title="Kill">💀</button>`:''}</div>`).join(''):'<div class="muted">no per-process data</div>'); }
  else if(key==='containers'){ h=(d.containers||[]).map(c=>{ const nm=typeof c==='string'?c:(c.name||c.Names||''); const st=(typeof c==='object'&&(c.state||c.State))||''; const down=/exit|dead|stop/i.test(st); return `<div class="xr-proc"><span class="pn" style="color:${down?'#ff8a9a':'#8ff0c0'}">${down?'○':'●'} ${esc(nm)}</span><span class="pv">${esc(st)}</span></div>`; }).join('')||'<div class="muted">none</div>'; }
  else if(key==='sensors'){ const s=d.sensors||{}; h=xrMetric('Max temp', (s.max_temp!=null?Math.round(s.max_temp)+'°C':'—'))+((s.temps||[]).map(x=>xrMetric(esc(x.name), Math.round(x.c)+'°C')).join(''))+((s.fans||[]).map(x=>xrMetric(esc(x.name), (x.rpm!=null?Math.round(x.rpm)+' rpm':'—'))).join(''))+(s.src?`<div style="font-size:10px;color:var(--mut)">via ${esc(s.src)}</div>`:''); }
  db.innerHTML=h||'<div class="muted">no data</div>'; $('#xr-detail').classList.add('show');
}
function xrMB(mb){ mb=+mb||0; return mb>=1024?((mb/1024).toFixed(1)+'GB'):(Math.round(mb)+'MB'); }
function xrRate(kb){ kb=+kb||0; return kb>=1024?((kb/1024).toFixed(1)+'MB/s'):(Math.round(kb)+'KB/s'); }

async function killProc(name){ if(!XR.node||!name) return;
  if(!confirm('Kill process "'+name+'" on this host?\n\nGuarded + audited terminate (TERM / Stop-Process). Protected system processes are refused.')) return;
  const r=await post('xray_kill',{node:XR.node,name});
  if(r&&r.ok){ $('#xr-vitals').textContent='killed '+name+((r.killed!=null)?(' ('+r.killed+')'):'')+' — re-scanning…'; setTimeout(()=>xrRefresh(0),1400); }
  else alert('Kill failed: '+((r&&r.error)||'unknown'));
}
function closeXray(){ const p=$('#xray-panel'); p.classList.remove('show','pick','xr-scanning'); document.body.classList.remove('xr-open'); if(XR.refreshT)clearInterval(XR.refreshT); if(XR.railT)clearInterval(XR.railT); XR.refreshT=XR.railT=null; XR.node=0; XR.focus=null; XR.focusTgt=null; xrClear(); const lb=$('#xr-labels'); if(lb)lb.innerHTML=''; }

// ══ NETWORK TOPOLOGY MAP — the whole network as an interconnected 3D graph (dedicated WebGL, routing_command look) ══
var TOPO={scope:'all',data:null,ren:null,scene:null,cam:null,ctrl:null,rayc:null,clock:null,raf:0,v:null,
  nodes:[],edges:[],picks:[],focus:null,focusSet:null,focusTgt:null,home:null,homeTgt:null,scanning:false,scanT:0,refreshT:null,rings:[],hlEdge:null};
const TCOL={up:0x4da3ff,down:0xe74c3c,degraded:0xf39c12};   // routing_command palette
const TEDGE={wired:0x36e3d0,gateway:0x4da3ff};
function tcolHex(s){ return {up:'#4da3ff',down:'#e74c3c',degraded:'#f39c12'}[s]||'#4da3ff'; }

async function openTopo(scope){ if($('#xray-panel').classList.contains('show')) closeXray(); if($('#traf-panel').classList.contains('show')) closeTraffic(); if($('#cont-panel')&&$('#cont-panel').classList.contains('show')) closeContainers(); if($('#nt-panel')&&$('#nt-panel').classList.contains('show')) closeNetTools();   // only one full-screen overlay at a time
  const p=$('#topo-panel'); p.classList.add('show'); document.body.classList.add('xr-open'); TOPO.scope=scope||'all';
  $('#topo-name').textContent='Network Topology'; $('#topo-sub').textContent='🛰 mapping…'; topoInit();
  let r; try{ r=await j('?api=topology&scope='+encodeURIComponent(TOPO.scope)); }catch(e){ $('#topo-sub').textContent='map error'; return; }
  if(!r||!r.ok){ $('#topo-sub').textContent=(r&&r.error)||'map failed'; return; }
  topoBuild(r.topo);
  if(TOPO.refreshT)clearInterval(TOPO.refreshT); TOPO.refreshT=setInterval(function(){ topoRefresh(0); }, 15000);
}
function topoInit(){ if(TOPO.ren) return; const cv=document.getElementById('topo-canvas');
  TOPO.ren=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true}); TOPO.ren.setPixelRatio(Math.min(2,window.devicePixelRatio||1));
  TOPO.scene=new THREE.Scene(); TOPO.scene.fog=new THREE.FogExp2(0x04060d,0.012);
  TOPO.cam=new THREE.PerspectiveCamera(55,1,0.1,600); TOPO.home=new THREE.Vector3(0,6,28); TOPO.homeTgt=new THREE.Vector3(0,0,0); TOPO.cam.position.copy(TOPO.home);
  TOPO.ctrl=new THREE.OrbitControls(TOPO.cam,cv); TOPO.ctrl.enableDamping=true; TOPO.ctrl.dampingFactor=.08; TOPO.ctrl.autoRotate=true; TOPO.ctrl.autoRotateSpeed=.35; TOPO.ctrl.minDistance=5; TOPO.ctrl.maxDistance=160; TOPO.ctrl.enablePan=false; TOPO.ctrl.target.copy(TOPO.homeTgt);
  TOPO.scene.add(new THREE.AmbientLight(0x8899cc,.95)); const pl=new THREE.PointLight(0xafc4ff,.85,300); pl.position.set(20,45,35); TOPO.scene.add(pl);
  TOPO.rayc=new THREE.Raycaster(); TOPO.clock=new THREE.Clock(); TOPO.v=new THREE.Vector3();
  cv.addEventListener('click',topoPick); window.addEventListener('resize',topoResize); topoResize();
  window.addEventListener('keydown',function(e){ if(e.key==='Escape' && $('#topo-panel').classList.contains('show')){ if(TOPO.focus)topoUnfocus(); else closeTopo(); } });
  topoLoop();
}
function topoResize(){ if(!TOPO.ren)return; const cv=TOPO.ren.domElement,w=cv.clientWidth||window.innerWidth,h=cv.clientHeight||window.innerHeight; TOPO.ren.setSize(w,h,false); TOPO.cam.aspect=w/h; TOPO.cam.updateProjectionMatrix(); }
// force-directed 3D layout (Fruchterman–Reingold-ish) — the "everything interconnected" organic look
function topoLayout(nodes,edges){ const N=nodes.length, pos={}, disp={};
  nodes.forEach((n,i)=>{ const a=i/N*Math.PI*2, ph=Math.acos(1-2*(i+0.5)/N), r=Math.min(16,4+N*0.15);
    pos[n.id]=new THREE.Vector3(r*Math.sin(ph)*Math.cos(a), r*Math.cos(ph), r*Math.sin(ph)*Math.sin(a));
    disp[n.id]=new THREE.Vector3(); });                          // hoist: allocate the displacement vectors ONCE
  const K=Math.min(15,5+N*0.2), tmp=new THREE.Vector3();
  const ITS = N>120 ? 120 : 260;                                  // O(n²)/iter — cap iterations on large fleets so the layout can't freeze the main thread
  for(let it=0; it<ITS; it++){ nodes.forEach(n=>disp[n.id].set(0,0,0));   // zero-reuse instead of re-allocating N vectors per iteration
    for(let i=0;i<N;i++){ for(let jj=i+1;jj<N;jj++){ const a=nodes[i].id,b=nodes[jj].id; tmp.copy(pos[a]).sub(pos[b]); let L=tmp.length()||0.01; const f=(K*K)/(L*L); disp[a].addScaledVector(tmp,f/L); disp[b].addScaledVector(tmp,-f/L); } }
    edges.forEach(e=>{ if(!pos[e.a]||!pos[e.b])return; tmp.copy(pos[e.a]).sub(pos[e.b]); let L=tmp.length()||0.01; const f=(L*L)/K; disp[e.a].addScaledVector(tmp,-f/L); disp[e.b].addScaledVector(tmp,f/L); });
    const step=Math.min(1.8, 0.4+(1-it/ITS)*2.2);
    nodes.forEach(n=>{ const dp=disp[n.id]; dp.addScaledVector(pos[n.id],-0.028); let L=dp.length()||0.01; pos[n.id].addScaledVector(dp, Math.min(L,step)/L); });
  }
  return pos;
}
function topoBuild(x){ TOPO.data=x; topoClear();
  const nodes=x.nodes||[], edges=x.edges||[];
  $('#topo-name').textContent=x.title||'Network Topology'; $('#topo-sub').textContent=nodes.length+' nodes · '+edges.length+' links';
  const pos=topoLayout(nodes,edges), NP={};
  nodes.forEach(n=>{ const p=pos[n.id], col=TCOL[n.status]||TCOL.up, isR=!!n.router, sz=isR?0.95:0.58;
    const core=new THREE.Mesh(new THREE.IcosahedronGeometry(sz,1), new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:.85,roughness:.35,metalness:.35,flatShading:true}));
    core.position.copy(p); core.userData.nodeId=n.id; TOPO.scene.add(core); TOPO.picks.push(core);
    const halo=new THREE.Mesh(new THREE.SphereGeometry(sz*1.55,16,16), new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:.10,blending:THREE.AdditiveBlending,depthWrite:false})); halo.position.copy(p); TOPO.scene.add(halo);
    NP[n.id]={n,core,halo,pos:p}; TOPO.nodes.push(NP[n.id]); });
  edges.forEach(e=>{ const A=NP[e.a],B=NP[e.b]; if(!A||!B)return; const col=TEDGE[e.type]||TEDGE.wired;
    const mid=A.pos.clone().add(B.pos).multiplyScalar(0.5); mid.y+=A.pos.distanceTo(B.pos)*0.13+0.6;
    const curve=new THREE.QuadraticBezierCurve3(A.pos.clone(),mid,B.pos.clone());
    const line=new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(20)), new THREE.LineBasicMaterial({color:col,transparent:true,opacity:.26})); TOPO.scene.add(line);
    const P=8, fg=new THREE.BufferGeometry(); fg.setAttribute('position',new THREE.BufferAttribute(new Float32Array(P*3),3));
    const flow=new THREE.Points(fg,new THREE.PointsMaterial({color:col,size:0.16,map:(typeof ROUND!=='undefined'?ROUND:null),transparent:true,opacity:.95,depthWrite:false,blending:THREE.AdditiveBlending,sizeAttenuation:true})); TOPO.scene.add(flow);
    TOPO.edges.push({A,B,curve,line,flow,fg,P,phase:Math.random(),speed:0.16+Math.random()*0.13}); });
  topoLabelsBuild(); topoRail();
  TOPO.scanning=true; TOPO.scanT=0; TOPO.focus=null; TOPO.focusTgt={cam:TOPO.home.clone(),tgt:TOPO.homeTgt.clone()};
  $('#topo-detail').classList.remove('show'); $('#topo-full').style.display='none'; $('#topo-rail').style.display='flex';
}
function topoLoop(){ TOPO.raf=requestAnimationFrame(topoLoop); if(!TOPO.ren||!$('#topo-panel').classList.contains('show'))return;
  const dt=Math.min(0.05,TOPO.clock.getDelta()), t=TOPO.clock.elapsedTime;
  if(TOPO.scanning){ TOPO.scanT+=dt; if(TOPO.scanT>1.3){ TOPO.scanning=false; TOPO.nodes.forEach(o=>{o.core.visible=true;o.halo.visible=true;}); } }
  const fs=TOPO.focusSet;
  TOPO.nodes.forEach((o,i)=>{ const base=1+Math.sin(t*2.1+i*0.6)*0.04; o.core.rotation.y+=dt*0.25;
    const foc=!fs || fs.indexOf(o.n.id)>=0; o.core.material.emissiveIntensity=(foc?0.7:0.18)+Math.sin(t*2.1+i)*0.2; o.halo.material.opacity=foc?0.10:0.03;
    if(TOPO.scanning){ const rev=Math.max(0,Math.min(1,(TOPO.scanT-i*0.015)/0.3)); o.core.visible=rev>0.02; o.halo.visible=rev>0.02; o.core.scale.setScalar(base*rev); } else o.core.scale.setScalar(base*(foc&&fs?1.15:1)); });
  TOPO.edges.forEach(e=>{ e.phase=(e.phase+e.speed*dt)%1; const pa=e.fg.attributes.position; for(let k=0;k<e.P;k++){ const f=(k/e.P+e.phase)%1, p=e.curve.getPoint(f); pa.setXYZ(k,p.x,p.y,p.z); } pa.needsUpdate=true;
    if(fs){ const dim=!(fs.indexOf(e.A.n.id)>=0 && fs.indexOf(e.B.n.id)>=0) && e!==TOPO.hlEdge; e.line.material.opacity=dim?0.07:(e===TOPO.hlEdge?0.95:0.26); } });
  TOPO.rings.forEach(r=>{ if(r.userData.pos) r.position.copy(r.userData.pos); r.lookAt(TOPO.cam.position); r.material.opacity=0.55+Math.sin(t*4)*0.35; r.scale.setScalar(1+Math.sin(t*4)*0.05); });
  if(TOPO.focusTgt){ TOPO.cam.position.lerp(TOPO.focusTgt.cam,0.08); TOPO.ctrl.target.lerp(TOPO.focusTgt.tgt,0.08); if(TOPO.cam.position.distanceTo(TOPO.focusTgt.cam)<0.15 && TOPO.ctrl.target.distanceTo(TOPO.focusTgt.tgt)<0.15) TOPO.focusTgt=null; }
  TOPO.ctrl.autoRotate=!TOPO.focus; TOPO.ctrl.update(); TOPO.ren.render(TOPO.scene,TOPO.cam); topoLabels();
}
function topoLabelsBuild(){ const box=$('#topo-labels'); box.innerHTML=''; TOPO.nodes.forEach(o=>{ const el=document.createElement('div'); el.className='tn-lab'+(o.n.router?' rt':'')+(o.n.status!=='up'?' down':''); el.textContent=o.n.name; el.style.opacity=0; box.appendChild(el); o.lab=el; }); }
function topoLabels(){ if(!TOPO.ren||!TOPO.v)return; const cv=TOPO.ren.domElement,w=cv.clientWidth,h=cv.clientHeight;
  TOPO.nodes.forEach(o=>{ if(!o.lab)return; if(TOPO.scanning||!o.core.visible){ o.lab.style.opacity=0; return; }
    TOPO.v.copy(o.pos).project(TOPO.cam); if(TOPO.v.z>1){ o.lab.style.opacity=0; return; }
    o.lab.style.transform='translate(-50%,-160%) translate('+(((TOPO.v.x*0.5+0.5)*w)|0)+'px,'+(((-TOPO.v.y*0.5+0.5)*h)|0)+'px)';
    const dim=TOPO.focusSet && TOPO.focusSet.indexOf(o.n.id)<0; o.lab.style.opacity=dim?0.15:(o.n.router?1:0.72); }); }
function topoRail(){ const el=$('#topo-rail'); const ns=TOPO.nodes.slice().sort((a,b)=>(b.n.router-a.n.router)||a.n.name.localeCompare(b.n.name));
  el.innerHTML=ns.map(o=>`<div class="tn-chip" id="tnc-${o.n.id}" onclick="topoFocus(${o.n.id})"><span class="d" style="background:${tcolHex(o.n.status)}"></span><span class="nm">${esc(o.n.name)}</span><span class="k">${esc(o.n.kind)}</span></div>`).join(''); }
function topoRailActive(id){ document.querySelectorAll('#topo-rail .tn-chip').forEach(e=>e.classList.remove('on')); const a=document.getElementById('tnc-'+id); if(a){ a.classList.add('on'); a.scrollIntoView({block:'nearest'}); } }
function topoPick(ev){ if(!TOPO.ren||TOPO.scanning)return; const cv=TOPO.ren.domElement,r=cv.getBoundingClientRect();
  TOPO.rayc.setFromCamera({x:((ev.clientX-r.left)/r.width)*2-1, y:-((ev.clientY-r.top)/r.height)*2+1}, TOPO.cam);
  const hits=TOPO.rayc.intersectObjects(TOPO.picks,false); if(hits.length && hits[0].object.userData.nodeId!=null) topoFocus(hits[0].object.userData.nodeId); }
function topoFocus(id){ const o=TOPO.nodes.find(x=>x.n.id===id); if(!o)return; TOPO.focus=id; TOPO.focusSet=[id];
  const dir=o.pos.clone(); if(dir.length()<0.2)dir.set(0,0,1); dir.normalize();
  TOPO.focusTgt={cam:o.pos.clone().add(dir.multiplyScalar(6)).add(new THREE.Vector3(0,2.5,0)), tgt:o.pos.clone()};
  topoRings([o]); topoHighlightEdge(null); $('#topo-full').style.display='inline-flex'; topoRailActive(id); topoDetail(o); }
// focus TWO nodes + highlight the link between them (e.g. "la conexión de core router a mikrotik")
function topoFocusPair(idA,idB){ if(idA===idB){ topoFocus(idA); return; } const A=TOPO.nodes.find(x=>x.n.id===idA), B=TOPO.nodes.find(x=>x.n.id===idB); if(!A){ if(B)topoFocus(idB); return; } if(!B){ topoFocus(idA); return; }
  TOPO.focus=idA; TOPO.focusSet=[idA,idB];
  const mid=A.pos.clone().add(B.pos).multiplyScalar(0.5), d=A.pos.distanceTo(B.pos);
  let dir=mid.clone(); if(dir.length()<0.2)dir.set(0,0,1); dir.normalize();
  TOPO.focusTgt={cam:mid.clone().add(dir.multiplyScalar(d*0.55+7)).add(new THREE.Vector3(0,d*0.35+2.5,0)), tgt:mid};
  topoRings([A,B]); topoHighlightEdge(idA,idB); $('#topo-full').style.display='inline-flex'; topoRailActive(idA); topoDetailPair(A,B); }
function topoRings(list){ TOPO.rings.forEach(r=>{ TOPO.scene.remove(r); topoDisposeObj(r); }); TOPO.rings=[];
  list.forEach(o=>{ const sz=(o.n.router?0.95:0.58)*1.9; const ring=new THREE.Mesh(new THREE.TorusGeometry(sz,0.06,10,40), new THREE.MeshBasicMaterial({color:0xffffff,transparent:true,opacity:.85,blending:THREE.AdditiveBlending,depthWrite:false})); ring.position.copy(o.pos); ring.userData.pos=o.pos; TOPO.scene.add(ring); TOPO.rings.push(ring); }); }
function topoHighlightEdge(idA,idB){ if(TOPO.hlEdge){ TOPO.hlEdge.line.material.opacity=.26; TOPO.hlEdge.line.material.color.setHex(TEDGE[TOPO.hlEdge.type]||TEDGE.wired); TOPO.hlEdge=null; }
  if(idA==null) return; const e=TOPO.edges.find(x=>(x.A.n.id===idA&&x.B.n.id===idB)||(x.A.n.id===idB&&x.B.n.id===idA)); if(e){ e.type=e.type||'wired'; e.line.material.opacity=.95; e.line.material.color.setHex(0xffd479); e.flow.material.color.setHex(0xffd479); TOPO.hlEdge=e; } }
function topoUnfocus(){ TOPO.focus=null; TOPO.focusSet=null; TOPO.focusTgt={cam:TOPO.home.clone(),tgt:TOPO.homeTgt.clone()}; topoRings([]); topoHighlightEdge(null); $('#topo-detail').classList.remove('show'); $('#topo-full').style.display='none'; document.querySelectorAll('#topo-rail .tn-chip').forEach(e=>e.classList.remove('on')); }
// fuzzy-match node NAMES mentioned in a spoken phrase against the loaded map (spoken numbers → digits, name flattened)
function _tnorm(s){ const w={cero:'0',uno:'1',una:'1',dos:'2',tres:'3',cuatro:'4',cinco:'5',seis:'6',siete:'7',ocho:'8',nueve:'9',zero:'0',one:'1',two:'2',three:'3',four:'4',five:'5',six:'6',seven:'7',eight:'8',nine:'9'};
  return (' '+(''+s).toLowerCase()+' ').replace(/\b(cero|uno|una|dos|tres|cuatro|cinco|seis|siete|ocho|nueve|zero|one|two|three|four|five|six|seven|eight|nine)\b/g,function(m){return w[m]||m;}); }
function topoMatchNodes(t){ if(!TOPO.nodes.length) return []; const uttflat=_tnorm(t).replace(/[^a-z0-9]+/g,''); if(uttflat.length<3) return []; const found=[];
  TOPO.nodes.forEach(o=>{ const nflat=o.n.name.toLowerCase().replace(/[^a-z0-9]+/g,''); const toks=o.n.name.toLowerCase().split(/[^a-z0-9]+/).filter(x=>x.length>=2);
    let hits=0, strong=false, firstPos=1e9;
    toks.forEach(tok=>{ if(tok.length<3 && !/\d/.test(tok)) return; const p=uttflat.indexOf(tok); if(p>=0){ hits++; firstPos=Math.min(firstPos,p); if(tok.length>=5)strong=true; } });
    if(nflat.length>=5 && uttflat.indexOf(nflat)>=0){ strong=true; hits=Math.max(hits,toks.length); firstPos=Math.min(firstPos,uttflat.indexOf(nflat)); }
    const score = strong?0.95 : (hits>=2?0.8 : (hits/Math.max(1,toks.length)));
    if(score>=0.55) found.push({o,score,pos:firstPos}); });
  found.sort((a,b)=> a.pos-b.pos || b.score-a.score); const seen={}, out=[]; found.forEach(f=>{ if(!seen[f.o.n.id]){ seen[f.o.n.id]=1; out.push(f.o); } }); return out; }
function topoDetailPair(A,B){ const e=(TOPO.data.edges||[]).find(x=>(x.a===A.n.id&&x.b===B.n.id)||(x.a===B.n.id&&x.b===A.n.id));
  $('#topo-dh').innerHTML='🔗 '+esc(A.n.name)+' ↔ '+esc(B.n.name);
  let h=`<div class="xr-metric"><div class="k">Link<b>${e?esc(e.label||e.type):'no direct link'}</b></div></div>`;
  [A,B].forEach(o=>{ h+=`<div class="tn-chip" style="cursor:pointer;margin-bottom:5px" onclick="topoFocus(${o.n.id})"><span class="d" style="background:${tcolHex(o.n.status)}"></span><span class="nm">${esc(o.n.name)}</span><span class="k">${esc(o.n.kind)}</span></div>`; });
  if(!e) h+='<div class="muted" style="margin-top:6px">These two are not directly wired — they connect through the fabric.</div>';
  $('#topo-db').innerHTML=h; $('#topo-detail').classList.add('show'); }
function topoDetail(o){ const n=o.n; const nb=[]; (TOPO.data.edges||[]).forEach(e=>{ if(e.a===n.id||e.b===n.id){ const other=(e.a===n.id?e.b:e.a); const om=TOPO.nodes.find(x=>x.n.id===other); if(om) nb.push({name:om.n.name,type:e.type,label:e.label,status:om.n.status}); } });
  $('#topo-dh').innerHTML=(n.router?'📡 ':'🖥 ')+esc(n.name);
  let h=`<div class="xr-metric"><div class="k">IP<b>${esc(n.ip||'—')}</b></div></div><div class="xr-metric"><div class="k">Kind<b>${esc(n.kind)}</b></div></div><div class="xr-metric"><div class="k">Status<b style="color:${tcolHex(n.status)}">${esc(n.status)}</b></div></div>`;
  h+='<div class="k" style="font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);margin:6px 0 6px">Connected to ('+nb.length+')</div>';
  h+= nb.length? nb.map(x=>`<div class="tn-chip" style="cursor:default;margin-bottom:5px"><span class="d" style="background:${tcolHex(x.status)}"></span><span class="nm">${esc(x.name)}</span><span class="k">${esc(x.label||x.type)}</span></div>`).join('') : '<div class="muted">no links</div>';
  h+=`<button class="btn ghost sm" style="margin-top:10px" onclick="openXray(${n.id})"><i class="fa-solid fa-dna"></i> X-Ray this node</button>`;
  $('#topo-db').innerHTML=h; $('#topo-detail').classList.add('show'); }
function topoRefresh(loud){ if(!TOPO.scope||TOPO._busy) return; TOPO._busy=true; if(loud) $('#topo-sub').textContent='🛰 re-mapping…';
  j('?api=topology&scope='+encodeURIComponent(TOPO.scope)).then(function(r){ if(!r||!r.ok)return; const x=r.topo;
    if(loud || (x.nodes||[]).length!==TOPO.nodes.length){                          // structure changed → rebuild
      const keep = loud ? null : (TOPO.focusSet?TOPO.focusSet.slice():null);       // preserve the operator's focus across a silent re-layout
      topoBuild(x);
      if(keep){ if(keep.length>=2) topoFocusPair(keep[0],keep[1]); else topoFocus(keep[0]); }
      return; }
    // light update: refresh status colors in place (no relayout)
    const byId={}; (x.nodes||[]).forEach(n=>byId[n.id]=n);
    TOPO.nodes.forEach(o=>{ const n=byId[o.n.id]; if(!n)return; o.n.status=n.status; const col=TCOL[n.status]||TCOL.up; o.core.material.color.setHex(col); o.core.material.emissive.setHex(col); o.halo.material.color.setHex(col); if(o.lab){ o.lab.className='tn-lab'+(o.n.router?' rt':'')+(n.status!=='up'?' down':''); } const c=document.getElementById('tnc-'+o.n.id); if(c){ const d=c.querySelector('.d'); if(d)d.style.background=tcolHex(n.status); } });
    $('#topo-sub').textContent=TOPO.nodes.length+' nodes · '+(x.edges||[]).length+' links'; }).catch(function(){}).then(function(){ TOPO._busy=false; }); }
function topoDisposeObj(o){ if(o.geometry)try{o.geometry.dispose();}catch(e){} if(o.material)try{o.material.dispose();}catch(e){} }
function topoClear(){ TOPO.rings.forEach(r=>{ TOPO.scene.remove(r); topoDisposeObj(r); }); TOPO.rings=[]; TOPO.hlEdge=null; TOPO.focusSet=null;
  TOPO.nodes.forEach(o=>{ TOPO.scene.remove(o.core); TOPO.scene.remove(o.halo); topoDisposeObj(o.core); topoDisposeObj(o.halo); });
  TOPO.edges.forEach(e=>{ TOPO.scene.remove(e.line); TOPO.scene.remove(e.flow); topoDisposeObj(e.line); topoDisposeObj(e.flow); });
  TOPO.nodes=[]; TOPO.edges=[]; TOPO.picks=[]; }
function closeTopo(){ const p=$('#topo-panel'); p.classList.remove('show'); document.body.classList.remove('xr-open'); if(TOPO.refreshT)clearInterval(TOPO.refreshT); TOPO.refreshT=null; TOPO.focus=null; TOPO.focusTgt=null; topoClear(); const lb=$('#topo-labels'); if(lb)lb.innerHTML=''; }

// ══ LIVE TRAFFIC — laser-per-interface, cloned from traffic_viewer.php (own WebGL scene) ══
const TV_beamVert=`varying vec2 vUv; void main(){ vUv=uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0);}`;
const TV_beamFrag=`precision highp float; varying vec2 vUv; uniform float uTime,uSpeed,uCore,uUtil,uDir,uOn; uniform vec3 uColor;
void main(){ float d=abs(vUv.y-0.5)*2.0; float beam=exp(-pow(d/max(uCore,0.015),2.0)); float dash=0.5+0.5*sin((vUv.x*46.0 - uTime*uSpeed*uDir)*6.2831); dash=pow(dash,3.0); float a=beam*(0.28+0.72*dash)*uOn; vec3 col=mix(uColor, vec3(1.0,0.42,0.32), uUtil); gl_FragColor=vec4(col*(1.0+uUtil*0.6), a); }`;
const TV_dotVert=`precision highp float; attribute float aoff; uniform float uTime,uSpeed,uDir,uLen,uSize; varying float vp;
void main(){ float p=fract(aoff+uDir*uTime*uSpeed); vp=p; vec3 pos=position; pos.x=(p-0.5)*uLen; vec4 mv=modelViewMatrix*vec4(pos,1.0); gl_PointSize=uSize*(360.0/max(1.0,-mv.z)); gl_Position=projectionMatrix*mv; }`;
const TV_dotFrag=`precision highp float; varying float vp; uniform vec3 uColor; uniform float uUtil,uOn;
void main(){ vec2 c=gl_PointCoord-0.5; float d=length(c); if(d>0.5)discard; float a=smoothstep(0.5,0.0,d)*uOn; gl_FragColor=vec4(mix(uColor,vec3(1.0,0.6,0.4),uUtil), a); }`;
const TV_LEN=220, TV_DOTS=54, TV_dY=26;
var TRAF={node:'',ifaceReq:'',data:null,ren:null,scene:null,cam:null,ctrl:null,clock:null,raf:0,v:null,lanes:[],focus:null,focusTgt:null,refreshT:null};
function trafNorm(b){ b=+b||0; return Math.min(1, Math.log(1+b)/Math.log(1+2e9)); }
async function openTraffic(nodeRef, iface){ if($('#xray-panel').classList.contains('show'))closeXray(); if($('#topo-panel').classList.contains('show'))closeTopo(); if($('#cont-panel')&&$('#cont-panel').classList.contains('show'))closeContainers(); if($('#nt-panel')&&$('#nt-panel').classList.contains('show'))closeNetTools();
  const p=$('#traf-panel'); p.classList.add('show'); document.body.classList.add('xr-open'); TRAF.node=nodeRef||''; TRAF.ifaceReq=iface||'';
  $('#traf-name').textContent='Live Traffic'; $('#traf-sub').textContent='⚡ connecting…'; trafInit();
  let r; try{ r=await j('?api=traffic&node='+encodeURIComponent(nodeRef||'')+'&iface='+encodeURIComponent(iface||'')); }catch(e){ $('#traf-sub').textContent='error'; return; }
  if(!r||!r.ok){ $('#traf-sub').textContent=(r&&r.error)||'no traffic data'; return; }
  trafBuild(r.traffic);
  if(TRAF.refreshT)clearInterval(TRAF.refreshT); TRAF.refreshT=setInterval(function(){ trafRefresh(); }, 3000);
}
function trafInit(){ if(TRAF.ren)return; const cv=document.getElementById('traf-canvas');
  TRAF.ren=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true}); TRAF.ren.setPixelRatio(Math.min(2,window.devicePixelRatio||1));
  TRAF.scene=new THREE.Scene(); TRAF.scene.fog=new THREE.FogExp2(0x04060c,0.0016);
  TRAF.cam=new THREE.PerspectiveCamera(52,1,1,3000); TRAF.cam.position.set(0,0,360);
  TRAF.ctrl=new THREE.OrbitControls(TRAF.cam,cv); TRAF.ctrl.enableDamping=true; TRAF.ctrl.dampingFactor=.08; TRAF.ctrl.enablePan=true; TRAF.ctrl.minDistance=120; TRAF.ctrl.maxDistance=1400; TRAF.ctrl.maxPolarAngle=Math.PI*0.85; TRAF.ctrl.minPolarAngle=Math.PI*0.15;
  TRAF.clock=new THREE.Clock(); TRAF.v=new THREE.Vector3();
  window.addEventListener('resize',trafResize); trafResize();
  window.addEventListener('keydown',function(e){ if(e.key==='Escape' && $('#traf-panel').classList.contains('show')){ if(TRAF.focus)trafUnfocus(); else closeTraffic(); } });
  trafLoop();
}
function trafResize(){ if(!TRAF.ren)return; const cv=TRAF.ren.domElement,w=cv.clientWidth||window.innerWidth,h=cv.clientHeight||window.innerHeight; TRAF.ren.setSize(w,h,false); TRAF.cam.aspect=w/h; TRAF.cam.updateProjectionMatrix(); }
function trafBeam(dir,color,y){ const u={uTime:{value:0},uSpeed:{value:1},uCore:{value:0.05},uUtil:{value:0},uDir:{value:dir},uOn:{value:1},uColor:{value:new THREE.Color(color)}};
  const m=new THREE.Mesh(new THREE.PlaneGeometry(TV_LEN,10,1,1), new THREE.ShaderMaterial({uniforms:u,vertexShader:TV_beamVert,fragmentShader:TV_beamFrag,transparent:true,depthWrite:false,blending:THREE.AdditiveBlending})); m.position.y=y; m.userData.u=u; return m; }
function trafDots(dir,color,y){ const g=new THREE.BufferGeometry(),pos=new Float32Array(TV_DOTS*3),off=new Float32Array(TV_DOTS);
  for(let i=0;i<TV_DOTS;i++){ pos[i*3]=0; pos[i*3+1]=y+(Math.random()-0.5)*4.2; pos[i*3+2]=(Math.random()-0.5)*3; off[i]=Math.random(); }
  g.setAttribute('position',new THREE.BufferAttribute(pos,3)); g.setAttribute('aoff',new THREE.BufferAttribute(off,1));
  const u={uTime:{value:0},uSpeed:{value:1},uDir:{value:dir},uLen:{value:TV_LEN},uSize:{value:8},uColor:{value:new THREE.Color(color)},uUtil:{value:0},uOn:{value:1}};
  const p=new THREE.Points(g,new THREE.ShaderMaterial({uniforms:u,vertexShader:TV_dotVert,fragmentShader:TV_dotFrag,transparent:true,depthWrite:false,blending:THREE.AdditiveBlending})); p.userData.u=u; return p; }
function trafBuild(x){ TRAF.data=x; trafClear();
  const ifs=x.interfaces||[]; $('#traf-name').textContent=x.title||'Live Traffic'; $('#traf-sub').textContent=ifs.length+' interfaces · teal = in · orange = out';
  const n=ifs.length, top=(n-1)*TV_dY/2;
  ifs.forEach((f,idx)=>{ const y=top-idx*TV_dY, grp=new THREE.Group(); grp.position.y=y;
    const bIn=trafBeam(1,0x36e3d0,3.0), bOut=trafBeam(-1,0xff9d4d,-3.0), dIn=trafDots(1,0x9ff6ec,3.0), dOut=trafDots(-1,0xffc48a,-3.0);
    grp.add(bIn,bOut,dIn,dOut); TRAF.scene.add(grp);
    TRAF.lanes.push({f,grp,y,bIn,bOut,dIn,dOut,anchor:new THREE.Vector3(-TV_LEN/2-6,y,0),lab:null}); });
  const need=Math.max(240, n*TV_dY*1.15+120); TRAF.cam.position.set(0,0,need); TRAF.ctrl.target.set(0,0,0); TRAF.ctrl.update();
  TRAF.focus=null; trafSetVisuals(); trafLabelsBuild(); trafRail();
  if((x.focus||[]).length) trafFocusIds(x.focus);
}
function trafSetLane(beam,dots,intensity,util,dim){ const bu=beam.userData.u,du=dots.userData.u;
  bu.uCore.value=0.05+0.55*intensity; bu.uSpeed.value=0.25+3.4*intensity; bu.uUtil.value=util; bu.uOn.value=dim;
  du.uSize.value=5+30*intensity; du.uSpeed.value=0.12+0.9*intensity; du.uUtil.value=util; du.uOn.value=dim; }
function trafSetVisuals(){ const fs=TRAF.focus;
  TRAF.lanes.forEach(l=>{ const f=l.f; const inN=trafNorm(f.in_mbps*1e6), outN=trafNorm(f.out_mbps*1e6);
    const uIn=f.in_util!=null?Math.min(1,f.in_util/100):inN*0.6, uOut=f.out_util!=null?Math.min(1,f.out_util/100):outN*0.6;
    const down=!f.up, dimmed=fs && fs.indexOf(f.id)<0; const on = down?0.12 : (dimmed?0.14:1);
    trafSetLane(l.bIn,l.dIn, inN, uIn, on); trafSetLane(l.bOut,l.dOut, outN, uOut, on); }); }
function trafLoop(){ TRAF.raf=requestAnimationFrame(trafLoop); if(!TRAF.ren||!$('#traf-panel').classList.contains('show'))return;
  const t=TRAF.clock.getElapsedTime();
  TRAF.lanes.forEach(l=>{ l.bIn.userData.u.uTime.value=t; l.bOut.userData.u.uTime.value=t; l.dIn.userData.u.uTime.value=t; l.dOut.userData.u.uTime.value=t; });
  if(TRAF.focusTgt){ TRAF.cam.position.lerp(TRAF.focusTgt.cam,0.08); TRAF.ctrl.target.lerp(TRAF.focusTgt.tgt,0.08); if(TRAF.cam.position.distanceTo(TRAF.focusTgt.cam)<0.6) TRAF.focusTgt=null; }
  TRAF.ctrl.update(); TRAF.ren.render(TRAF.scene,TRAF.cam); trafLabels(); }
function trafLabelsBuild(){ const box=$('#traf-labels'); box.innerHTML=''; TRAF.lanes.forEach(l=>{ const el=document.createElement('div'); el.className='tv-lab'+(l.f.up?'':' down'); box.appendChild(el); l.lab=el; }); }
function trafLabels(){ if(!TRAF.ren||!TRAF.v)return; const cv=TRAF.ren.domElement,w=cv.clientWidth,h=cv.clientHeight; const fs=TRAF.focus;
  TRAF.lanes.forEach(l=>{ if(!l.lab)return; TRAF.v.copy(l.anchor).project(TRAF.cam); if(TRAF.v.z>1){ l.lab.style.opacity=0; return; }
    l.lab.style.transform='translate(-100%,-50%) translate('+(((TRAF.v.x*0.5+0.5)*w)|0)+'px,'+(((-TRAF.v.y*0.5+0.5)*h)|0)+'px)';
    l.lab.innerHTML=(l.f.node?('<span style="color:#7fa6c8">'+esc(l.f.node)+' · </span>'):'')+'<b>'+esc(l.f.name)+'</b> <span class="i">▾'+l.f.in_mbps+'</span> <span class="o">▴'+l.f.out_mbps+'</span> Mb';
    const dim=fs && fs.indexOf(l.f.id)<0; l.lab.style.opacity=dim?0.25:1; }); }
function trafRail(){ const el=$('#traf-rail'); el.style.display='flex'; el.innerHTML=TRAF.lanes.map(l=>`<div class="tv-chip" id="tvc-${l.f.id}" onclick="trafFocusIds([${l.f.id}])"><span class="nm">${l.f.node?('<span style="color:var(--mut);font-size:10px">'+esc(l.f.node)+'</span> '):''}${esc(l.f.name)}</span><span class="r"><span class="i">▾${l.f.in_mbps}</span> <span class="o">▴${l.f.out_mbps}</span></span></div>`).join(''); }
function trafFocusIds(ids){ if(!ids||!ids.length){ trafUnfocus(); return; } TRAF.focus=ids.slice();
  const sel=TRAF.lanes.filter(l=>ids.indexOf(l.f.id)>=0); if(!sel.length){ trafUnfocus(); return; }
  let ymin=1e9,ymax=-1e9; sel.forEach(l=>{ ymin=Math.min(ymin,l.y); ymax=Math.max(ymax,l.y); }); const yc=(ymin+ymax)/2, spread=(ymax-ymin)+TV_dY;
  TRAF.focusTgt={cam:new THREE.Vector3(0,yc,Math.max(150,spread*2.6+140)), tgt:new THREE.Vector3(0,yc,0)};
  trafSetVisuals(); $('#traf-full').style.display='inline-flex';
  document.querySelectorAll('#traf-rail .tv-chip').forEach(e=>e.classList.remove('on')); ids.forEach(id=>{ const c=document.getElementById('tvc-'+id); if(c){ c.classList.add('on'); c.scrollIntoView({block:'nearest'}); } }); }
function trafUnfocus(){ TRAF.focus=null; TRAF.focusTgt={cam:new THREE.Vector3(0,0,Math.max(240,TRAF.lanes.length*TV_dY*1.15+120)), tgt:new THREE.Vector3(0,0,0)}; trafSetVisuals(); $('#traf-full').style.display='none'; document.querySelectorAll('#traf-rail .tv-chip').forEach(e=>e.classList.remove('on')); }
function trafRefresh(){ if(!TRAF.node||TRAF._busy) return; TRAF._busy=true; j('?api=traffic&node='+encodeURIComponent(TRAF.node)+'&iface='+encodeURIComponent(TRAF.ifaceReq||'')).then(function(r){ if(!r||!r.ok)return; const x=r.traffic;
  if((x.interfaces||[]).length!==TRAF.lanes.length){ const keep=TRAF.focus?TRAF.focus.slice():null; trafBuild(x); if(keep&&keep.length) trafFocusIds(keep); return; }
  const byId={}; (x.interfaces||[]).forEach(f=>byId[f.id]=f); TRAF.lanes.forEach(l=>{ const f=byId[l.f.id]; if(f)l.f=f; }); trafSetVisuals();
  TRAF.lanes.forEach(l=>{ const c=document.getElementById('tvc-'+l.f.id); if(c){ const rr=c.querySelector('.r'); if(rr)rr.innerHTML='<span class="i">▾'+l.f.in_mbps+'</span> <span class="o">▴'+l.f.out_mbps+'</span>'; } }); }).catch(function(){}).then(function(){ TRAF._busy=false; }); }
function trafMatchIfaces(t){ if(!TRAF.lanes.length)return []; const utt=_tnorm(t), flat=utt.replace(/[^a-z0-9]+/g,''); const out=[];
  // 1) a NODE mentioned? (restrict to its lanes → "interfaz 1 del core router" = that node's 1st)
  let nodeId=0; const seen={}; TRAF.lanes.forEach(l=>{ if(seen[l.f.node_id])return; seen[l.f.node_id]=1;
    const toks=(''+l.f.node).toLowerCase().split(/[^a-z0-9]+/).filter(x=>x.length>=3); let hit=0,strong=false; toks.forEach(tk=>{ if(flat.indexOf(tk)>=0){ hit++; if(tk.length>=5)strong=true; } }); if((strong||hit>=2)&&!nodeId) nodeId=l.f.node_id; });
  const cands = nodeId ? TRAF.lanes.filter(l=>l.f.node_id===nodeId) : TRAF.lanes;
  const nums=utt.match(/\d+/g)||[];
  nums.forEach(ns=>{ const num=parseInt(ns,10); cands.forEach(l=>{ const pos = nodeId ? l.f.nn : (TRAF.lanes.indexOf(l)+1); if(pos===num) out.push(l.f.id); }); });
  cands.forEach(l=>{ l.f.name.toLowerCase().split(/[^a-z0-9]+/).filter(x=>x.length>=4).forEach(tok=>{ if(flat.indexOf(tok)>=0) out.push(l.f.id); }); });
  if(!out.length && nodeId){ cands.forEach(l=>out.push(l.f.id)); }   // node named, no interface → whole node
  return out.filter((v,i,a)=>a.indexOf(v)===i); }
function trafClear(){ TRAF.lanes.forEach(l=>{ TRAF.scene.remove(l.grp); l.grp.traverse(o=>{ if(o.geometry)try{o.geometry.dispose();}catch(e){} if(o.material)try{o.material.dispose();}catch(e){} }); }); TRAF.lanes=[]; TRAF.focus=null; TRAF.focusTgt=null; }
function closeTraffic(){ const p=$('#traf-panel'); p.classList.remove('show'); document.body.classList.remove('xr-open'); if(TRAF.refreshT)clearInterval(TRAF.refreshT); TRAF.refreshT=null; trafClear(); const lb=$('#traf-labels'); if(lb)lb.innerHTML=''; }

// ═══════════ CONTAINERS LAYER — 4th WebGL overlay (siblings: X-Ray/Topology/Traffic) ═══════════
// Every Docker container per node as a stacked tower of glowing cubes around each node hub. Click/voice → focus
// a container + deep detail (volumes/sizes/partition/net). Mutual-exclusive with the other three overlays.
var CONT={node:'',ctrReq:'',data:null,ren:null,scene:null,cam:null,ctrl:null,clock:null,raf:0,v:null,rayc:null,pods:[],hubs:[],focus:null,focusTgt:null,refreshT:null,_busy:false};
const CSTATE={running:0x36e3d0,exited:0x8892a6,dead:0x8892a6,stopped:0x8892a6,created:0x5b8cff,paused:0xb07cff,restarting:0xff9d4d};
function contStateColor(c){ if((''+(c.status||'')).toLowerCase().indexOf('unhealthy')>=0) return 0xff5a6e; return CSTATE[c.state]||0x8892a6; }
function contGroupByNode(cs){ const g={}; (cs||[]).forEach(c=>{ const k=c.node_id+''; (g[k]=g[k]||[]).push(c); }); return g; }
async function openContainers(nodeRef, ctrRef){
  if($('#xray-panel').classList.contains('show')) closeXray();
  if($('#topo-panel').classList.contains('show')) closeTopo();
  if($('#traf-panel').classList.contains('show')) closeTraffic();
  if($('#nt-panel')&&$('#nt-panel').classList.contains('show')) closeNetTools();
  const p=$('#cont-panel'); p.classList.add('show'); document.body.classList.add('xr-open'); CONT.node=nodeRef||''; CONT.ctrReq=ctrRef||'';
  $('#cont-name').textContent='Fleet Containers'; $('#cont-sub').textContent='📦 loading…'; contInit();
  let r; try{ r=await j('?api=containers&node='+encodeURIComponent(nodeRef||'')+'&container='+encodeURIComponent(ctrRef||'')); }catch(e){ $('#cont-sub').textContent='error'; return; }
  if(!r||!r.ok){ $('#cont-sub').textContent=(r&&r.error)||'no container data'; return; }
  contBuild(r.containers);
  if(CONT.refreshT)clearInterval(CONT.refreshT); CONT.refreshT=setInterval(contRefresh, 6000);
}
function contInit(){ if(CONT.ren)return; const cv=document.getElementById('cont-canvas');
  CONT.ren=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true}); CONT.ren.setPixelRatio(Math.min(2,window.devicePixelRatio||1));
  CONT.scene=new THREE.Scene(); CONT.scene.fog=new THREE.FogExp2(0x04060d,0.010);
  CONT.cam=new THREE.PerspectiveCamera(55,1,0.1,900); CONT.cam.position.set(0,26,90);
  CONT.ctrl=new THREE.OrbitControls(CONT.cam,cv); CONT.ctrl.enableDamping=true; CONT.ctrl.dampingFactor=.08; CONT.ctrl.autoRotate=true; CONT.ctrl.autoRotateSpeed=.3; CONT.ctrl.minDistance=12; CONT.ctrl.maxDistance=340; CONT.ctrl.enablePan=false;
  CONT.scene.add(new THREE.AmbientLight(0x8899cc,.95)); const pl=new THREE.PointLight(0xafc4ff,.9,600); pl.position.set(30,70,50); CONT.scene.add(pl);
  CONT.rayc=new THREE.Raycaster(); CONT.clock=new THREE.Clock(); CONT.v=new THREE.Vector3();
  cv.addEventListener('click',contPick); window.addEventListener('resize',contResize); contResize();
  window.addEventListener('keydown',function(e){ if(e.key==='Escape' && $('#cont-panel').classList.contains('show')){ if(CONT.focus)contUnfocus(); else closeContainers(); } });
  contLoop();
}
function contResize(){ if(!CONT.ren)return; const cv=CONT.ren.domElement,w=cv.clientWidth||window.innerWidth,h=cv.clientHeight||window.innerHeight; CONT.ren.setSize(w,h,false); CONT.cam.aspect=w/h; CONT.cam.updateProjectionMatrix(); }
function contBuild(x){ CONT.data=x; contClear();
  const cs=x.containers||[]; const groups=contGroupByNode(cs); const nodeIds=Object.keys(groups); const N=nodeIds.length||1; const R=Math.max(16, N*4.4);
  $('#cont-name').textContent=x.title||'Fleet Containers'; $('#cont-sub').textContent=cs.length+' containers · '+(x.running||0)+' running · '+N+' nodes';
  CONT.pods=[]; CONT.hubs=[];
  nodeIds.forEach((nid,i)=>{ const ang=i/N*Math.PI*2; const hx=Math.cos(ang)*R, hz=Math.sin(ang)*R; const list=groups[nid];
    const hub=new THREE.Mesh(new THREE.CylinderGeometry(2.6,3.0,0.5,24), new THREE.MeshStandardMaterial({color:0x18243c,emissive:0x1a3a66,emissiveIntensity:.5,roughness:.5,metalness:.45}));
    hub.position.set(hx,0,hz); CONT.scene.add(hub);
    const ring=new THREE.Mesh(new THREE.TorusGeometry(3.1,0.08,8,32), new THREE.MeshBasicMaterial({color:0x38bffe,transparent:true,opacity:.5})); ring.position.set(hx,0.15,hz); ring.rotation.x=Math.PI/2; CONT.scene.add(ring);
    CONT.hubs.push({mesh:hub,ring:ring,name:list[0].node,pos:new THREE.Vector3(hx,0,hz)});
    list.forEach((c,j)=>{ const col=contStateColor(c); const y=3+j*2.4; const sz=1.6;
      const cube=new THREE.Mesh(new THREE.BoxGeometry(sz,sz*0.9,sz), new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:c.state==='running'?.75:.25,roughness:.35,metalness:.4,flatShading:true}));
      cube.position.set(hx,y,hz); cube.userData.n=c.n; CONT.scene.add(cube);
      const halo=new THREE.Mesh(new THREE.BoxGeometry(sz*1.5,sz*1.35,sz*1.5), new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:.10,blending:THREE.AdditiveBlending,depthWrite:false})); halo.position.set(hx,y,hz); CONT.scene.add(halo);
      CONT.pods.push({c,cube,halo,base:new THREE.Vector3(hx,y,hz)});
    });
  });
  const need=Math.max(70, R*3.0); CONT.cam.position.set(0,R*0.9,need); CONT.ctrl.target.set(0,6,0); CONT.ctrl.update();
  CONT.focus=null; contLabelsBuild(); contRail(); contApplyVisuals();
  if((x.focus||[]).length) contFocusIds(x.focus);
}
function contApplyVisuals(){ const fs=CONT.focus;
  CONT.pods.forEach(p=>{ const dim = fs && fs.indexOf(p.c.n)<0; const foc = fs && fs.indexOf(p.c.n)>=0;
    p.cube.material.opacity=dim?0.12:1; p.cube.material.transparent=!!dim; p.cube.scale.setScalar(dim?0.9:(foc?1.3:1));
    p.halo.material.opacity=dim?0.03:(foc?0.30:0.10);
  });
}
function contLoop(){ CONT.raf=requestAnimationFrame(contLoop); if(!CONT.ren||!$('#cont-panel').classList.contains('show'))return;
  const t=CONT.clock.getElapsedTime();
  CONT.pods.forEach(p=>{ if(p.c.state==='running'){ const dim=CONT.focus&&CONT.focus.indexOf(p.c.n)<0; p.cube.material.emissiveIntensity=dim?0.2:(0.6+Math.sin(t*2+p.base.y)*0.22); } p.cube.rotation.y+=0.005; });
  CONT.hubs.forEach(h=>{ h.ring.rotation.z+=0.01; });
  if(CONT.focusTgt){ CONT.cam.position.lerp(CONT.focusTgt.cam,0.08); CONT.ctrl.target.lerp(CONT.focusTgt.tgt,0.08); if(CONT.cam.position.distanceTo(CONT.focusTgt.cam)<0.8) CONT.focusTgt=null; }
  CONT.ctrl.autoRotate=!CONT.focus; CONT.ctrl.update(); CONT.ren.render(CONT.scene,CONT.cam); contLabels();
}
function contLabelsBuild(){ const box=$('#cont-labels'); box.innerHTML=''; CONT.hubs.forEach(h=>{ const el=document.createElement('div'); el.className='cv-lab'; el.style.fontWeight='700'; el.style.color='#8bf3ff'; el.textContent=h.name; box.appendChild(el); h.lab=el; }); }
function contLabels(){ if(!CONT.ren||!CONT.v)return; const cv=CONT.ren.domElement,w=cv.clientWidth,h=cv.clientHeight;
  CONT.hubs.forEach(hb=>{ if(!hb.lab)return; CONT.v.copy(hb.pos).project(CONT.cam); if(CONT.v.z>1){ hb.lab.style.opacity=0; return; } hb.lab.style.opacity=.9; hb.lab.style.transform='translate(-50%,-50%) translate('+(((CONT.v.x*0.5+0.5)*w)|0)+'px,'+(((-CONT.v.y*0.5+0.5)*h)|0)+'px)'; }); }
function contRail(){ const el=$('#cont-rail'); el.style.display='flex'; const groups=contGroupByNode(CONT.data.containers||[]);
  let html=''; Object.keys(groups).forEach(nid=>{ const list=groups[nid]; html+='<div style="font-size:10px;color:var(--mut);margin:6px 0 2px;text-transform:uppercase;letter-spacing:.08em">'+esc(list[0].node)+'</div>';
    list.forEach(c=>{ const hex='#'+contStateColor(c).toString(16).padStart(6,'0'); html+=`<div class="cv-chip" id="cvc-${c.n}" onclick="contFocusIds([${c.n}])"><span class="st" style="background:${hex}"></span><span class="nm">${esc(c.name)}</span></div>`; }); });
  el.innerHTML=html; }
function contFocusIds(ids){ if(!ids||!ids.length){ contUnfocus(); return; } CONT.focus=ids.slice();
  const sel=CONT.pods.filter(p=>ids.indexOf(p.c.n)>=0); if(!sel.length){ contUnfocus(); return; }
  const c=new THREE.Vector3(); sel.forEach(p=>c.add(p.base)); c.multiplyScalar(1/sel.length);
  const dist=sel.length>3?60:26; CONT.focusTgt={cam:new THREE.Vector3(c.x*1.5+8,c.y+9,c.z*1.5+dist), tgt:c.clone()};
  contApplyVisuals(); $('#cont-full').style.display='inline-flex';
  document.querySelectorAll('#cont-rail .cv-chip').forEach(e=>e.classList.remove('on')); ids.forEach(id=>{ const el=document.getElementById('cvc-'+id); if(el){ el.classList.add('on'); el.scrollIntoView({block:'nearest'}); } });
  if(ids.length===1){ const p=CONT.pods.find(p=>p.c.n===ids[0]); if(p) contDetail(p.c); } else { $('#cont-detail').classList.remove('show'); }
}
function contUnfocus(){ CONT.focus=null; CONT.focusTgt={cam:new THREE.Vector3(0, (Object.keys(contGroupByNode(CONT.data?CONT.data.containers:[]) ).length*4.4||20)*0.9, 90), tgt:new THREE.Vector3(0,6,0)}; contApplyVisuals(); $('#cont-full').style.display='none'; $('#cont-detail').classList.remove('show'); document.querySelectorAll('#cont-rail .cv-chip').forEach(e=>e.classList.remove('on')); }
function contPick(e){ if(!CONT.ren)return; const cv=CONT.ren.domElement,rc=cv.getBoundingClientRect(); const m=new THREE.Vector2(((e.clientX-rc.left)/rc.width)*2-1, -((e.clientY-rc.top)/rc.height)*2+1);
  CONT.rayc.setFromCamera(m,CONT.cam); const hits=CONT.rayc.intersectObjects(CONT.pods.map(p=>p.cube)); if(hits.length){ contFocusIds([hits[0].object.userData.n]); } }
function contFmtBytes(b){ b=+b||0; if(b>=1073741824)return (b/1073741824).toFixed(1)+' GB'; if(b>=1048576)return (b/1048576).toFixed(0)+' MB'; if(b>=1024)return (b/1024).toFixed(0)+' KB'; return b+' B'; }
function contDetail(c){ const box=$('#cont-detail'); box.classList.add('show'); box.innerHTML='<h4>'+esc(c.name)+'</h4><div class="kv">node<b>'+esc(c.node)+'</b></div><div class="kv">state<b>'+esc(c.state)+'</b></div><div class="kv" style="opacity:.6">loading detail…</div>';
  j('?api=container_detail&endpoint_id='+c.endpoint_id+'&cid='+encodeURIComponent(c.cid)+'&node='+encodeURIComponent(c.node)).then(r=>{ if(!r||!r.ok){ box.innerHTML='<h4>'+esc(c.name)+'</h4><div class="kv danger">detail unavailable</div>'; return; } const d=r.data; const f=contFmtBytes;
    let h='<h4>'+esc(d.name)+'</h4>';
    h+='<div class="kv">node<b>'+esc(d.node)+'</b></div>';
    h+='<div class="kv">image<b style="font-size:10px">'+esc((d.image||'').slice(0,30))+'</b></div>';
    h+='<div class="kv">state<b>'+esc(d.state)+(d.health?(' · '+esc(d.health)):'')+'</b></div>';
    if(d.restart_count)h+='<div class="kv">restarts<b>'+d.restart_count+'</b></div>';
    h+='<div class="kv">partition (rw+root)<b>'+f(d.partition.total)+'</b></div>';
    if(d.stats)h+='<div class="kv">CPU / MEM<b>'+Math.round(d.stats.cpu_pct)+'% · '+Math.round(d.stats.mem_pct)+'%</b></div>';
    if(d.net_history&&d.net_history.arx!=null)h+='<div class="kv">net avg in/out<b>'+f(d.net_history.arx)+'/s · '+f(d.net_history.atx)+'/s</b></div>';
    if(d.biggest_volume){ const dg=(d.biggest_volume.size>2147483648); h+='<div class="kv'+(dg?' danger':'')+'">biggest volume<b>'+esc((d.biggest_volume.name||'').slice(0,16))+' · '+f(d.biggest_volume.size)+(dg?' ⚠':'')+'</b></div>'; }
    if(d.mounts&&d.mounts.length){ h+='<div style="margin:8px 0 2px;font-size:10px;color:var(--mut);text-transform:uppercase">Volumes ('+d.mounts.length+')</div>';
      d.mounts.slice(0,8).forEach(m=>{ const dg=(m.size&&m.size>2147483648); h+='<div class="kv'+(dg?' danger':'')+'"><span style="font-size:10px">'+esc((m.name||m.dest||m.source||'').slice(0,22))+'</span><b>'+(m.size?f(m.size)+(dg?' ⚠':''):'—')+'</b></div>'; }); }
    box.innerHTML=h;
  }).catch(()=>{});
}
function contRefresh(){ if(!$('#cont-panel').classList.contains('show')||CONT._busy) return; CONT._busy=true; j('?api=containers&node='+encodeURIComponent(CONT.node)+'&container='+encodeURIComponent(CONT.ctrReq||'')).then(r=>{ if(!r||!r.ok)return; const x=r.containers;
    if((x.containers||[]).length!==CONT.pods.length){ const keep=CONT.focus?CONT.focus.slice():null; contBuild(x); if(keep&&keep.length)contFocusIds(keep); return; }
    const byN={}; (x.containers||[]).forEach(c=>byN[c.n]=c); CONT.pods.forEach(p=>{ const c=byN[p.c.n]; if(!c)return; p.c=c; const col=contStateColor(c); p.cube.material.color.setHex(col); p.cube.material.emissive.setHex(col); }); CONT.data=x;
  }).catch(()=>{}).then(()=>{ CONT._busy=false; }); }
function contMatch(t){ if(!CONT.pods.length)return []; const utt=(''+t).toLowerCase(); const flat=utt.replace(/[^a-z0-9]+/g,''); const out=[];
  let nodeId=0; const seen={}; CONT.pods.forEach(p=>{ if(seen[p.c.node_id])return; seen[p.c.node_id]=1; const toks=(''+p.c.node).toLowerCase().split(/[^a-z0-9]+/).filter(x=>x.length>=3); let hit=0,strong=false; toks.forEach(tk=>{ if(flat.indexOf(tk)>=0){ hit++; if(tk.length>=5)strong=true; } }); if((strong||hit>=2)&&!nodeId)nodeId=p.c.node_id; });
  const cands = nodeId ? CONT.pods.filter(p=>p.c.node_id===nodeId) : CONT.pods;
  cands.forEach(p=>{ (''+p.c.name).toLowerCase().split(/[^a-z0-9]+/).filter(x=>x.length>=3).forEach(tok=>{ if(flat.indexOf(tok)>=0) out.push(p.c.n); }); const img=(''+p.c.image).toLowerCase().split(/[/:]/)[0].replace(/[^a-z0-9]+/g,''); if(img.length>=3 && flat.indexOf(img)>=0) out.push(p.c.n); });
  if(!out.length && nodeId){ cands.forEach(p=>out.push(p.c.n)); }
  return out.filter((v,i,a)=>a.indexOf(v)===i); }
function contClear(){ CONT.pods.forEach(p=>{ CONT.scene.remove(p.cube); CONT.scene.remove(p.halo); try{p.cube.geometry.dispose();p.cube.material.dispose();p.halo.geometry.dispose();p.halo.material.dispose();}catch(e){} }); CONT.hubs.forEach(h=>{ CONT.scene.remove(h.mesh); CONT.scene.remove(h.ring); try{h.mesh.geometry.dispose();h.mesh.material.dispose();h.ring.geometry.dispose();h.ring.material.dispose();}catch(e){} }); CONT.pods=[]; CONT.hubs=[]; CONT.focus=null; CONT.focusTgt=null; }
function closeContainers(){ const p=$('#cont-panel'); p.classList.remove('show'); document.body.classList.remove('xr-open'); if(CONT.refreshT)clearInterval(CONT.refreshT); CONT.refreshT=null; contClear(); const lb=$('#cont-labels'); if(lb)lb.innerHTML=''; $('#cont-detail').classList.remove('show'); }

// ═══════════ NET TOOLS — 5th overlay: hosts the tool pages (Ping/Traceroute/Netstat/NS/Port Scanner) (MANUAL overlay — opened only by the Net Tools button) ═══════════
// panels in embed mode (?embed=1&target=&autostart=1). Reuses each tool's own WebGL viz (sonar radar, geo map…).
var NT={tool:'',target:''};
const NT_FILES={netping:'netping.php',nettrace:'nettrace.php',netstat:'netstat.php',netlookup:'netlookup.php',portscan:'portscan.php'};
async function openNetTool(tool, target, autostart){
  if(!NT_FILES[tool]) tool='portscan';
  autostart = (autostart!==false);   // default true; the server (cross-operator) push passes false → no active probe fires on others' screens
  if($('#xray-panel').classList.contains('show')) closeXray();
  if($('#topo-panel').classList.contains('show')) closeTopo();
  if($('#traf-panel').classList.contains('show')) closeTraffic();
  if($('#cont-panel')&&$('#cont-panel').classList.contains('show')) closeContainers();
  const p=$('#nt-panel'); p.classList.add('show'); document.body.classList.add('xr-open');
  NT.tool=tool; NT.target=target||'';
  document.querySelectorAll('#nt-tabs .nt-tab').forEach(e=>e.classList.toggle('on', e.dataset.tool===tool));
  $('#nt-target').textContent = target?('▶ '+target):'';
  let tgt=target||'';
  // a spoken NODE NAME → resolve to its IP (embed tools expect an IP/hostname). Leave IPs + hostnames (with a dot) as-is.
  if(tgt && !/^\d{1,3}(\.\d{1,3}){3}$/.test(tgt) && tgt.indexOf('.')<0){
    try{ const r=await j('?api=nettool_resolve&ref='+encodeURIComponent(tgt)); if(r&&r.ok&&r.target) tgt=r.target; }catch(e){}
  }
  if(!$('#nt-panel').classList.contains('show') || NT.tool!==tool) return;   // operator switched/closed during the async resolve
  let src=NT_FILES[tool]+'?embed=1'; if(tgt){ src+='&target='+encodeURIComponent(tgt)+(autostart?'&autostart=1':''); }
  const f=$('#nt-frame'); if(f) f.src=src;
}
function switchNetTool(tool){ openNetTool(tool, NT.target); }   // keep the target when switching tools
function closeNetTools(){ const p=$('#nt-panel'); if(!p)return; p.classList.remove('show'); document.body.classList.remove('xr-open'); const f=$('#nt-frame'); if(f)f.src='about:blank'; NT.tool=''; NT.target=''; }

// ── LOCAL VISION — presence-aware Command Center (camera stays local; only {state} crosses) ──
var VISION={on:false,state:'',att:0,preview:false,user:'operator',greetedAt:0,lastAnnounced:0,identity:'unknown',enrolled:false};
// ── Vision i18n (greeting/approval/gesture speak in the operator's language) ──
var VLANG=(function(){ var l=(navigator.language||'es').slice(0,2); return ['es','en','pt','fr','de'].indexOf(l)>=0?l:'es'; })();
var VSPEAK_LANG={es:'es-ES',en:'en-US',pt:'pt-BR',fr:'fr-FR',de:'de-DE'}[VLANG];
var VI18N={
  es:{gm:['Buenos días','Buenas tardes','Buenas noches'], st:function(d,o){return (d>0?(d+' nodo'+(d>1?'s':'')+' caído'+(d>1?'s':'')+', '):'todo en orden, ')+o+' señal'+(o===1?'':'es')+' abierta'+(o===1?'':'s')+'.';}, greet:function(g,n,s){return g+', '+n+'. '+s+' ¿En qué te ayudo?';}, ask:function(n,w){return n+', ¿apruebo '+w+'? Asiente para sí, niega para no.';}, ok:'Aprobado.', no:'Denegado.', stranger:'No reconozco tu cara.'},
  en:{gm:['Good morning','Good afternoon','Good evening'], st:function(d,o){return (d>0?(d+' node'+(d>1?'s':'')+' down, '):'all clear, ')+o+' open signal'+(o===1?'':'s')+'.';}, greet:function(g,n,s){return g+', '+n+'. '+s+' How can I help?';}, ask:function(n,w){return n+', should I approve '+w+'? Nod for yes, shake for no.';}, ok:'Approved.', no:'Denied.', stranger:'I don’t recognize your face.'},
  pt:{gm:['Bom dia','Boa tarde','Boa noite'], st:function(d,o){return (d>0?(d+' nó(s) fora do ar, '):'tudo certo, ')+o+' sinal(is) aberto(s).';}, greet:function(g,n,s){return g+', '+n+'. '+s+' Como posso ajudar?';}, ask:function(n,w){return n+', devo aprovar '+w+'? Acene para sim, negue para não.';}, ok:'Aprovado.', no:'Negado.', stranger:'Não reconheço o seu rosto.'},
  fr:{gm:['Bonjour','Bon après-midi','Bonsoir'], st:function(d,o){return (d>0?(d+' nœud(s) hors service, '):'tout va bien, ')+o+' signal(aux) ouvert(s).';}, greet:function(g,n,s){return g+', '+n+'. '+s+' Comment puis-je aider ?';}, ask:function(n,w){return n+', dois-je approuver '+w+' ? Hochez pour oui, secouez pour non.';}, ok:'Approuvé.', no:'Refusé.', stranger:'Je ne reconnais pas votre visage.'},
  de:{gm:['Guten Morgen','Guten Tag','Guten Abend'], st:function(d,o){return (d>0?(d+' Knoten ausgefallen, '):'alles in Ordnung, ')+o+' offene Signale.';}, greet:function(g,n,s){return g+', '+n+'. '+s+' Wie kann ich helfen?';}, ask:function(n,w){return n+', soll ich '+w+' genehmigen? Nicken für Ja, schütteln für Nein.';}, ok:'Genehmigt.', no:'Abgelehnt.', stranger:'Ich erkenne Ihr Gesicht nicht.'}
};
var VT=VI18N[VLANG];
async function visionInit(){ try{ const r=await j('?api=vision_cfg'); if(r&&r.ok){ VISION.user=r.user||'operator'; VISION.enrolled=!!r.enrolled; } }catch(e){} }
function toggleVision(){
  VISION.on=!VISION.on;
  try{ post('vision_toggle',{on:VISION.on?1:''}); }catch(e){}
  $('#vision-btn').classList.toggle('on',VISION.on);
  const box=$('#vision-box');
  if(VISION.on){ box.innerHTML='<iframe id="vision-frame" src="/vision.php?embed=1" allow="camera"></iframe>'; $('#vision-preview-btn').style.display='inline-flex'; $('#vision-enroll-btn').style.display=VISION.enrolled?'none':'inline-flex'; $('#state-sub').textContent='👁 Vision on — allow the camera. It stays 100% local; NEURU only knows if you’re here.'; }
  else { visionCmd('stop'); setTimeout(function(){ box.innerHTML=''; },150);   // explicitly release the camera track BEFORE tearing down the iframe
    box.classList.remove('preview'); $('#vision-preview-btn').style.display='none'; $('#vision-preview-btn').classList.remove('on'); $('#vision-enroll-btn').style.display='none'; VISION.preview=false; document.body.classList.remove('vs-stranger'); visionApply('',0); }
}
function toggleVisionPreview(){
  VISION.preview=!VISION.preview; $('#vision-box').classList.toggle('preview',VISION.preview); $('#vision-preview-btn').classList.toggle('on',VISION.preview);
  const f=document.getElementById('vision-frame'); if(f&&f.contentWindow){ try{ f.contentWindow.postMessage({type:'neuru-vision-cmd',cmd:'preview',show:VISION.preview},location.origin); }catch(e){} }
}
function visionApply(state,att,identity){
  const prev=VISION.state; VISION.state=state; VISION.att=att; if(identity) VISION.identity=identity;
  const stranger=(VISION.identity==='stranger' && state!=='absent');
  document.body.classList.toggle('vs-stranger', stranger);
  if(state!==prev){ try{ post('presence',{state:state||'absent',attention:att||0}); }catch(e){} }
  // WebGL ambiance: dim the whole universe when absent, amber edge-pulse when passive, full when engaged
  document.body.classList.toggle('vs-passive', state==='passive' && !stranger);
  document.body.classList.toggle('vs-absent', state==='absent');
  try{ if(typeof rend!=='undefined'&&rend&&rend.domElement){ rend.domElement.style.transition='filter 1s'; rend.domElement.style.filter = state==='absent'?'brightness(.34) saturate(.6)':(state==='passive'?'brightness(.92)':'none'); } }catch(e){}
  if(typeof brainState!=='undefined'&&brainState){ brainState.energy = state==='engaged'?Math.max(brainState.energy,.55):(state==='absent'?.15:brainState.energy); }
  if(stranger){ $('#state-now').textContent='⚠ '+VT.stranger; $('#state-sub').textContent='Vision does not recognize this face.'; }
  else if(state==='engaged' && (prev==='absent'||prev==='')) visionGreet();   // proactive wake-up (only for YOU)
}
function visionGreet(){
  if(VISION.identity==='stranger') return;            // don't greet an unrecognized face
  if(Date.now()-VISION.greetedAt < 300000) return;    // at most once / 5 min
  VISION.greetedAt=Date.now();
  const c=(STATE&&STATE.counts)||{}, hr=new Date().getHours();
  const gm=VT.gm[hr<12?0:hr<19?1:2];
  const msg=VT.greet(gm, VISION.user, VT.st(c.down||0, c.open||0));   // localized (es/en/pt/fr/de)
  $('#state-now').textContent='👁 '+VISION.user+' detected'; $('#state-sub').textContent=msg;
}
function visionCmd(cmd){ try{ const f=document.getElementById('vision-frame'); if(f&&f.contentWindow) f.contentWindow.postMessage({type:'neuru-vision-cmd',cmd:cmd,csrf:CSRF},location.origin); }catch(e){} }
// ALL voice is VAPI — NO local speechSynthesis (it produced the wrong-voice gibberish + fed back into the mic).
// Vision speaks VISUALLY (the state ribbon, already localized by the callers). VAPI is the single voice engine.
function visionSpeak(text){ /* intentionally silent — visual only; VAPI is the only voice */ }
// GESTIC APPROVALS: when engaged + a pending approval appears, NEURU announces it and ARMS a gesture window.
// A head NOD approves, a head SHAKE denies — hands-free, and only for the action it just asked about.
async function visionArmApproval(){
  if(!VISION.on || VISION.state!=='engaged') return;
  const n=(STATE&&STATE.counts&&STATE.counts.proposed)||0;
  if(!n){ VISION.armedAction=null; VISION.lastArmedId=0; return; }
  let r; try{ r=await j('?api=actions'); }catch(e){ return; }
  const pend=(r&&r.actions)||[]; if(!pend.length) return;
  const a=pend[0];
  if(a.id===VISION.lastArmedId) return;   // already armed/asked this one
  VISION.lastArmedId=a.id; VISION.armedAction=a.id; VISION.armExpires=Date.now()+22000;
  const what=((a.tool||'action').replace(/_/g,' '))+(a.node_name?(' · '+a.node_name):'');
  $('#state-now').textContent='👁 gesture approval'; $('#state-sub').textContent=VT.ask(VISION.user, what);
}
function visionGesture(g){
  if(!VISION.on || !VISION.armedAction || Date.now()>VISION.armExpires){ VISION.armedAction=null; return; }
  const aid=VISION.armedAction; VISION.armedAction=null;
  if(g==='nod'){ $('#state-sub').textContent='✅ '+VT.ok; post('approve',{action_id:aid}).then(function(){ loadState(); if(typeof drawerTab!=='undefined'&&drawerTab==='actions')renderActions(); }); }
  else if(g==='shake'){ $('#state-sub').textContent='🚫 '+VT.no; post('deny',{action_id:aid}).then(function(){ loadState(); if(typeof drawerTab!=='undefined'&&drawerTab==='actions')renderActions(); }); }
}
window.addEventListener('message',function(ev){ if(ev.origin!==location.origin) return; const d=ev.data; if(!d) return;
  if(d.type==='neuru-vision') visionApply(d.state,d.attention||0,d.identity);
  else if(d.type==='neuru-gesture') visionGesture(d.gesture);
  else if(d.type==='neuru-vision-enrolled'){ VISION.enrolled=true; const b=$('#vision-enroll-btn'); if(b)b.style.display='none'; $('#state-sub').textContent='✅ Face enrolled — NEURU will confirm it’s you.'; } });

// ── DATA FILAMENTS: glowing rays from critical/warning queue items → the core (2D overlay, ~16fps) ──
var FIL={paths:[],v:null,shown:0};
function filInit(){ var g=document.getElementById('fila-g'); if(!g)return; for(var i=0;i<28;i++){ var p=document.createElementNS('http://www.w3.org/2000/svg','path'); p.setAttribute('class','fila'); p.style.display='none'; g.appendChild(p); FIL.paths.push(p); } if(typeof THREE!=='undefined')FIL.v=new THREE.Vector3(); }
function filHideAll(){ if(!FIL.shown)return; for(var i=0;i<FIL.paths.length;i++) FIL.paths[i].style.display='none'; FIL.shown=0; }
function filUpdate(){
  var svg=document.getElementById('filaments'); if(!svg||!FIL.paths.length) return;
  if(document.hidden){ return; }                 // tab hidden → nothing paints, skip layout thrash
  // active-only query FIRST — if nothing is investigating/proposed there are no lasers, so bail before any layout read.
  var rows=document.querySelectorAll('#signals .row[data-status="investigating"],#signals .row[data-status="proposed"]');
  if(!rows.length){ filHideAll(); return; }
  var W=innerWidth,H=innerHeight; svg.setAttribute('viewBox','0 0 '+W+' '+H);
  var cx=W*0.5, cy=H*0.5;
  try{ if(typeof cam!=='undefined'&&cam&&FIL.v){ FIL.v.set(0,0,0).project(cam); cx=(FIL.v.x*0.5+0.5)*W; cy=(-FIL.v.y*0.5+0.5)*H; } }catch(e){}
  var idx=0;
  for(var k=0;k<rows.length;k++){ var row=rows[k]; var st=row.getAttribute('data-status');
    var r=row.getBoundingClientRect(); if(r.width<5||r.bottom<60||r.top>H-16) continue;
    if(idx>=FIL.paths.length) break;
    var sev=row.getAttribute('data-sev');
    var sx=r.right-6, sy=r.top+r.height/2;
    var col=(st==='proposed')?(sev==='critical'?'#ff5a6e':'#ffb454'):'#39e6ff';   // proposed=attention, investigating=cyan
    var mx=(sx+cx)/2, my=(sy+cy)/2-70;
    var p=FIL.paths[idx++]; p.setAttribute('d','M'+(sx|0)+','+(sy|0)+' Q'+(mx|0)+','+(my|0)+' '+(cx|0)+','+(cy|0)); p.style.color=col; p.style.display='';
  }
  for(var i=idx;i<FIL.paths.length;i++) FIL.paths[i].style.display='none';
  FIL.shown=idx;
}

// ── Left-HUD parallax: the holographic Signal queue floats with the mouse (zero-g feel) ──
(function(){
  var px=0,py=0,tpx=0,tpy=0,el=null,apx=99,apy=99;
  window.addEventListener('mousemove',function(e){ tpx=(e.clientX/Math.max(1,innerWidth)-0.5)*2; tpy=(e.clientY/Math.max(1,innerHeight)-0.5)*2; },{passive:true});
  function loop(){ requestAnimationFrame(loop); if(document.hidden)return; px+=(tpx-px)*0.07; py+=(tpy-py)*0.07;
    // epsilon-gate: only rewrite the CSS vars (which repaint the backdrop-filtered glass) when the value actually moved.
    if(Math.abs(px-apx)<0.002 && Math.abs(py-apy)<0.002) return;
    apx=px; apy=py; if(!el)el=document.querySelector('.v2-hud'); if(el){ el.style.setProperty('--px',px.toFixed(3)); el.style.setProperty('--py',py.toFixed(3)); } }   // set on the grid → both L + R holo panels inherit
  requestAnimationFrame(loop);
})();

applyPanels();   // panels start hidden by default (persisted per user) — full-bleed universe
loadState(); loadSignals(); loadChat(); connectStream(); ttInit(); visionInit();
setInterval(visionArmApproval, 5000);
setInterval(xrUiPoll, 5000);   // voice/chat "show the x-ray of X" → open it in the cockpit
loadNarrate(); setInterval(voiceDrain, 2000);   // alert voice narration: sync toggle + drain the queue when idle
filInit(); setInterval(filUpdate, 100);   // data filaments (critical alerts → core) — 10fps is plenty, halves layout reads
// when the tab is hidden, stop Vision's camera/detection loop (saves CPU + battery); resume on return unless a VAPI call owns it
document.addEventListener('visibilitychange', function(){
  if(document.hidden){ if(typeof VISION!=='undefined'&&VISION.on) visionCmd('pause'); }
  else { if(typeof VISION!=='undefined'&&VISION.on && !VOICE_ACTIVE) visionCmd('resume'); }
});
try{ j('?api=vapi_cfg').then(r=>{ VAPI_CFG=(r&&r.cfg)||null; }); }catch(e){}   // so Talk knows if voice is configured
setInterval(loadSignals,15000); setInterval(loadState,30000);
setInterval(pollToolActivity, 2500); pollToolActivity();
// fast Telegram drain while the cockpit is open — a phone Approve/Deny reflects here in ~seconds, not the 60s cron
setInterval(()=>{ post('tg_drain',{}).then(r=>{ if(r&&(r.processed>0)){ loadSignals(); loadState(); if(drawerTab==='actions')renderActions(); } }).catch(()=>{}); }, 6000);
</script>
</body></html>
