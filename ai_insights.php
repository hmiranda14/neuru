<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — AI Insights & Incidents. Renders nm_ai_insights (written by n8n AI
// flows via nm_ai_ingest.php) as plain-English cards. Blast-radius incidents
// group their downstream members by correlation_key. Engineers acknowledge /
// resolve / dismiss. See docs/AI-ROADMAP.md (build-order #1).
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');

include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_n8n.php');
require_once('nm_secrets.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'ai_insights')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'err'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=ai_insights'); exit;
}

// Keep the board CONSISTENT with reality: age out stale point-in-time insights (an
// open insight older than the TTL describes a window that has passed). Same sweep the
// incident engine runs, so incidents / insights / troubleshoot wizard always agree.
@require_once('nm_incidents.php');
if (function_exists('nm_ai_expire_stale')) nm_ai_expire_stale($conn);

// Mute rules — "Ignore" hides an insight AND auto-suppresses future matching ones
// (by correlation_key, else kind+node) so the same finding stops reappearing.
$conn->query("CREATE TABLE IF NOT EXISTS nm_ai_ignores (
    id INT AUTO_INCREMENT PRIMARY KEY,
    match_type VARCHAR(12) NOT NULL,      /* corr | kindnode */
    match_val  VARCHAR(255) NOT NULL,
    label      VARCHAR(255) DEFAULT '',
    active     TINYINT DEFAULT 1,
    created_by INT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_match (match_type, match_val)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

// SQL fragment: an insight `i` matches an ACTIVE ignore rule
$_IGN_MATCH = "EXISTS (SELECT 1 FROM nm_ai_ignores g WHERE g.active=1 AND (
        (g.match_type='corr' AND i.correlation_key<>'' AND g.match_val=i.correlation_key)
     OR (g.match_type='kindnode' AND g.match_val=CONCAT(i.kind,':',COALESCE(i.node_id,0))) ))";

// ── API ───────────────────────────────────────────────────────────────────────
if (function_exists('session_write_close')) @session_write_close(); // free session lock before slow SSH/n8n I/O (prevents whole-portal freeze)
if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');

    if ($api === 'list') {
        $status = $_GET['status'] ?? 'active';      // active = open+acknowledged
        $sev    = $_GET['severity'] ?? 'all';
        $fnode  = (int)($_GET['node'] ?? 0);        // optional: focus the list on ONE node
        $where  = [];
        if ($status === 'active')        $where[] = "i.status IN ('open','acknowledged','suppressed')";
        elseif ($status !== 'all')       $where[] = "i.status='" . $conn->real_escape_string($status) . "'";
        if (in_array($sev, ['critical','warning','info'], true)) $where[] = "i.severity='" . $conn->real_escape_string($sev) . "'";
        if ($fnode > 0)                  $where[] = "i.node_id=" . $fnode;
        $where[] = "NOT {$_IGN_MATCH}";   // hide anything covered by an active Ignore rule
        $w = $where ? ('WHERE ' . implode(' AND ', $where)) : '';
        // Command-Center host mapping (only if those tables exist) so each card can offer
        // the right deep-link to windows.php / linux.php — same pattern as net_mon.php.
        $hasWin = ($conn->query("SHOW TABLES LIKE 'nm_win_hosts'")->num_rows > 0);
        $hasLx  = ($conn->query("SHOW TABLES LIKE 'nm_lx_hosts'")->num_rows > 0);
        $winSel = $hasWin ? "(SELECT MIN(w.id) FROM nm_win_hosts w WHERE w.node_id=n.id)" : "NULL";
        $lxSel  = $hasLx  ? "(SELECT MIN(l.id) FROM nm_lx_hosts l WHERE l.node_id=n.id)"  : "NULL";
        $sql = "SELECT i.id, i.node_id, i.kind, i.severity, i.title, i.body, i.data,
                       i.source, i.status, i.correlation_key, i.created_at,
                       TIMESTAMPDIFF(SECOND, i.created_at, NOW()) age_sec,
                       n.display_name node_name, n.ip_address node_ip, n.os_icon,
                       COALESCE(n.monitor_type,'snmp') monitor_type,
                       {$winSel} win_host_id, {$lxSel} lx_host_id
                FROM nm_ai_insights i
                LEFT JOIN nm_nodes n ON n.id = i.node_id
                {$w}
                ORDER BY FIELD(i.severity,'critical','warning','info','') ,
                         (i.status='open') DESC, i.created_at DESC
                LIMIT 500";
        $rows = $conn->query($sql);
        $focusName = null;
        if ($fnode > 0) { $fr = $conn->query("SELECT display_name FROM nm_nodes WHERE id={$fnode} LIMIT 1");
            if ($fr && ($fx = $fr->fetch_assoc())) $focusName = $fx['display_name']; }
        echo json_encode(['ok'=>true, 'insights'=> $rows ? $rows->fetch_all(MYSQLI_ASSOC) : [],
                          'focus_node'=>$fnode ?: null, 'focus_name'=>$focusName]);
        exit;
    }

    if ($api === 'counts') {
        $r = $conn->query("SELECT i.severity severity, COUNT(*) c FROM nm_ai_insights i
                           WHERE i.status IN ('open','acknowledged') AND NOT {$_IGN_MATCH} GROUP BY i.severity");
        $out = ['critical'=>0,'warning'=>0,'info'=>0,'total'=>0];
        if ($r) while ($x = $r->fetch_assoc()) { $out[$x['severity']] = (int)$x['c']; $out['total'] += (int)$x['c']; }
        echo json_encode($out);
        exit;
    }

    if ($api === 'update') {
        $b  = json_decode(file_get_contents('php://input'), true) ?? [];
        $id = (int)($b['id'] ?? 0);
        $st = $b['status'] ?? '';
        if (!$id || !in_array($st, ['open','acknowledged','resolved','dismissed'], true)) { echo json_encode(['ok'=>false,'err'=>'Bad request']); exit; }
        $stmt = $conn->prepare("UPDATE nm_ai_insights SET status=? WHERE id=?");
        $stmt->bind_param('si', $st, $id); $stmt->execute();
        // Resolving/dismissing a master also closes its correlated members.
        if (in_array($st, ['resolved','dismissed'], true)) {
            $cr = $conn->query("SELECT correlation_key FROM nm_ai_insights WHERE id={$id} AND correlation_key IS NOT NULL AND correlation_key<>''");
            if ($cr && ($row = $cr->fetch_assoc())) {
                $ck = $conn->real_escape_string($row['correlation_key']);
                $conn->query("UPDATE nm_ai_insights SET status='{$conn->real_escape_string($st)}' WHERE correlation_key='{$ck}'");
            }
        }
        nm_audit($conn, 'ai_insight.'.$st, ['target_type'=>'ai_insight','target_id'=>$id]);
        echo json_encode(['ok'=>true]);
        exit;
    }

    if ($api === 'delete') {
        $b  = json_decode(file_get_contents('php://input'), true) ?? [];
        $id = (int)($b['id'] ?? 0);
        if ($id) $conn->query("DELETE FROM nm_ai_insights WHERE id={$id}");
        echo json_encode(['ok'=>true]);
        exit;
    }

    // IGNORE: mute this insight's pattern so it (and future matches) stop showing.
    if ($api === 'ignore') {
        $b  = json_decode(file_get_contents('php://input'), true) ?? [];
        $id = (int)($b['id'] ?? 0);
        if (!$id) { echo json_encode(['ok'=>false,'err'=>'Bad request']); exit; }
        $r = $conn->query("SELECT i.kind,i.node_id,i.correlation_key,i.title,n.display_name nm
                           FROM nm_ai_insights i LEFT JOIN nm_nodes n ON n.id=i.node_id WHERE i.id={$id} LIMIT 1");
        $ins = $r ? $r->fetch_assoc() : null;
        if (!$ins) { echo json_encode(['ok'=>false,'err'=>'Not found']); exit; }
        if (!empty($ins['correlation_key'])) {
            $mt='corr'; $mv=$ins['correlation_key']; $label='“'.$ins['title'].'”';
        } else {
            $mt='kindnode'; $mv=$ins['kind'].':'.(int)$ins['node_id'];
            $label=$ins['kind'].' · '.($ins['nm'] ?: ($ins['node_id']?('node '.$ins['node_id']):'network-wide'));
        }
        $st=$conn->prepare("INSERT INTO nm_ai_ignores (match_type,match_val,label,created_by)
                            VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE active=1,label=VALUES(label)");
        $uid=(int)($_SESSION['user_id'] ?? 0); $st->bind_param('sssi',$mt,$mv,$label,$uid); $st->execute(); $st->close();
        // dismiss currently-matching insights so they vanish now
        if ($mt==='corr') $conn->query("UPDATE nm_ai_insights SET status='dismissed' WHERE correlation_key='".$conn->real_escape_string($mv)."'");
        else $conn->query("UPDATE nm_ai_insights SET status='dismissed' WHERE kind='".$conn->real_escape_string($ins['kind'])."' AND COALESCE(node_id,0)=".(int)$ins['node_id']);
        nm_audit($conn,'ai_insight.ignore',['target_type'=>'ai_insight','target_id'=>$id,'details'=>['match'=>$mt.':'.$mv]]);
        echo json_encode(['ok'=>true]); exit;
    }
    if ($api === 'ignores_list') {
        $r=$conn->query("SELECT id,match_type,match_val,label,created_at FROM nm_ai_ignores WHERE active=1 ORDER BY id DESC");
        echo json_encode(['ok'=>true,'rules'=>$r?$r->fetch_all(MYSQLI_ASSOC):[]]); exit;
    }
    if ($api === 'unignore') {
        $b=json_decode(file_get_contents('php://input'),true)??[]; $rid=(int)($b['rule_id']??0);
        if ($rid) $conn->query("UPDATE nm_ai_ignores SET active=0 WHERE id={$rid}");
        nm_audit($conn,'ai_insight.unignore',['target_type'=>'ai_ignore','target_id'=>$rid]);
        echo json_encode(['ok'=>true]); exit;
    }

    // ── Self-heal: ask the AI to PROPOSE a remediation for an incident/insight ──
    // Fires the `self-heal` n8n flow; that flow posts a kind='remediation' insight
    // back via nm_ai_ingest.php (which then shows an Approve & Apply card).
    if ($api === 'suggest_fix') {
        $b  = json_decode(file_get_contents('php://input'), true) ?? [];
        $id = (int)($b['id'] ?? 0);
        $r  = $conn->query("SELECT i.*, n.display_name node_name, n.ip_address node_ip
                            FROM nm_ai_insights i LEFT JOIN nm_nodes n ON n.id=i.node_id WHERE i.id={$id} LIMIT 1");
        $ins = $r ? $r->fetch_assoc() : null;
        if (!$ins) { echo json_encode(['ok'=>false,'err'=>'Insight not found']); exit; }
        nm_audit($conn, 'ai_insight.suggest_fix', ['target_type'=>'ai_insight','target_id'=>$id]);
        // Link the remediation that comes back to THIS finding, so they render as ONE card (same
        // device/issue). Give the source a correlation_key (reuse an existing one, e.g. a blast group),
        // and remember node→key so nm_ai_ingest can stamp the returned remediation with it.
        $curCk  = trim((string)($ins['correlation_key'] ?? ''));
        $healCk = $curCk !== '' ? $curCk : ('heal-'.$id);
        if ($curCk === '') $conn->query("UPDATE nm_ai_insights SET correlation_key='".$conn->real_escape_string($healCk)."' WHERE id={$id}");
        $conn->query("CREATE TABLE IF NOT EXISTS nm_ai_heal_link (node_id INT PRIMARY KEY,
            correlation_key VARCHAR(120) NOT NULL, source_id BIGINT NOT NULL,
            requested_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        if ($ins['node_id'] !== null && $ins['node_id'] !== '') {
            $nid = (int)$ins['node_id']; $ck = $conn->real_escape_string($healCk);
            $conn->query("REPLACE INTO nm_ai_heal_link (node_id,correlation_key,source_id,requested_at) VALUES ({$nid},'{$ck}',{$id},NOW())");
        }
        $__bk=[]; try { require_once __DIR__.'/nm_solutionkb.php'; if (function_exists('nm_kb_search_books')) $__bk=nm_kb_search_books($conn, trim(((string)$ins['title']).' '.((string)$ins['body']))); } catch (\Throwable $e) {}
        [$code,$resp,$err] = nm_n8n_call($conn, 'self-heal', [
            'event'   => 'self_heal_propose',
            'insight' => [
                'id'=>(int)$ins['id'],'node_id'=>$ins['node_id'],'node'=>$ins['node_name'],'ip'=>$ins['node_ip'],
                'kind'=>$ins['kind'],'severity'=>$ins['severity'],'title'=>$ins['title'],'body'=>$ins['body'],
                'correlation_key'=>$healCk,   // an updated flow can echo this back; the portal also links it defensively
                'data'=>$ins['data'] ? json_decode($ins['data'], true) : null,
            ],
            'docs'      => $__bk,
            'docs_text' => (function_exists('nm_kb_docs_context')?nm_kb_docs_context($__bk):''),
        ]);
        $replySnip = is_string($resp) ? mb_substr($resp,0,400) : mb_substr((string)json_encode($resp),0,400);
        if ($err) { echo json_encode(['ok'=>false,'err'=>$err,'http'=>$code,'reply'=>$replySnip,
            'hint'=>'n8n returned an error for slug "self-heal". Check that a workflow is ACTIVE on /webhook/self-heal in n8n (Config → Integrations & AI lists the URL).']); exit; }
        echo json_encode(['ok'=>true,'queued'=>true,'http'=>$code,'reply'=>$replySnip,'result'=>$resp]);
        exit;
    }

    // ── Self-heal: APPLY an approved remediation (human-in-the-loop) ────────────
    // Only for kind='remediation' insights. Fires the `self-heal-apply` flow which
    // actually runs the playbook/script (n8n SSH/Ansible) and returns the result.
    if ($api === 'apply') {
        $b  = json_decode(file_get_contents('php://input'), true) ?? [];
        $id = (int)($b['id'] ?? 0);
        $r  = $conn->query("SELECT i.*, n.display_name node_name, n.ip_address node_ip
                            FROM nm_ai_insights i LEFT JOIN nm_nodes n ON n.id=i.node_id WHERE i.id={$id} LIMIT 1");
        $ins = $r ? $r->fetch_assoc() : null;
        if (!$ins) { echo json_encode(['ok'=>false,'err'=>'Insight not found']); exit; }
        if ($ins['kind'] !== 'remediation') { echo json_encode(['ok'=>false,'err'=>'Not a remediation card']); exit; }
        $data = $ins['data'] ? json_decode($ins['data'], true) : [];

        // Mark applying + audit the approval (who approved what, when)
        $conn->query("UPDATE nm_ai_insights SET status='acknowledged' WHERE id={$id}");
        nm_audit($conn, 'ai_insight.apply_approved', ['target_type'=>'ai_insight','target_id'=>$id,
            'details'=>['title'=>$ins['title'],'target'=>$data['target'] ?? ($ins['node_name'] ?? '')]]);

        // Resolve the device's SSH credential (its own, else default) and pass it to
        // the flow's SSH node. Decrypted only here, sent over the n8n call.
        $ssh = $ins['node_id'] ? nm_ssh_resolve($conn, (int)$ins['node_id']) : null;

        [$code,$resp,$err] = nm_n8n_call($conn, 'self-heal-apply', [
            'event'      => 'self_heal_apply',
            'insight_id' => (int)$ins['id'],
            'node_id'    => $ins['node_id'],
            'node'       => $ins['node_name'],
            'ip'         => $ins['node_ip'],
            'target'     => $data['target']   ?? null,
            'playbook'   => $data['playbook'] ?? null,
            'data'       => $data,
            'ssh'        => $ssh,   // {host,port,username,auth_type,password|private_key,cred_name} or null
            'approved_by'=> $_SESSION['username'] ?? '',
        ]);
        if ($err) {
            $conn->query("UPDATE nm_ai_insights SET status='open' WHERE id={$id}");   // revert
            echo json_encode(['ok'=>false,'err'=>$err,
                'hint'=>'Add an enabled n8n webhook with slug "self-heal-apply" in Config → Integrations & AI']); exit;
        }
        // Did the remediation actually succeed? The flow signals failure via ok:false /
        // success:false / a non-zero exit_code. HTTP 200 alone ≠ command succeeded.
        $succeeded = true;
        if (is_array($resp)) {
            if (array_key_exists('ok', $resp))        $succeeded = (bool)$resp['ok'];
            elseif (array_key_exists('success', $resp)) $succeeded = (bool)$resp['success'];
            if (isset($resp['exit_code']) && (int)$resp['exit_code'] !== 0) $succeeded = false;
        }
        $outcome = is_array($resp) ? ($resp['output'] ?? ($resp['result'] ?? ($resp['message'] ?? json_encode($resp)))) : (string)$resp;
        $data['apply_result'] = ['ts'=>date('c'),'by'=>$_SESSION['username'] ?? '','ok'=>$succeeded,'output'=>$outcome];
        $newData = $conn->real_escape_string(json_encode($data));
        // Success → resolve. Failure → leave OPEN so it's still actionable, but record the attempt.
        $newStatus = $succeeded ? 'resolved' : 'open';
        $conn->query("UPDATE nm_ai_insights SET status='{$newStatus}', data='{$newData}' WHERE id={$id}");
        nm_audit($conn, $succeeded ? 'ai_insight.applied' : 'ai_insight.apply_failed', ['target_type'=>'ai_insight','target_id'=>$id]);
        echo json_encode(['ok'=>true,'applied'=>$succeeded,'result'=>$outcome]);
        exit;
    }

    echo json_encode(['ok'=>false,'err'=>'Unknown endpoint']);
    exit;
}

// ── Page ──────────────────────────────────────────────────────────────────────
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
include('header.php');
log_user_action($conn, 'view_page', 'ai_insights.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AI Insights | SG-PR Console</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.07); --border:rgba(255,255,255,.12); --accent:#4da3ff;
       --crit:#e74c3c; --warn:#f39c12; --info:#4da3ff; --ai:#9b59b6; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#fff; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.28; }
.wrap{ max-width:1150px; margin:0 auto; padding:22px 20px 50px; }
.head{ display:flex; align-items:center; gap:14px; flex-wrap:wrap; margin-bottom:18px; }
.head h1{ font-size:23px; margin:0; font-weight:700; }
.head h1 i{ color:var(--ai); }
.head .sub{ font-size:12px; color:#8a909a; }
.pill-row{ display:flex; gap:10px; flex-wrap:wrap; margin-left:auto; }
.kpi{ background:var(--glass); border:1px solid var(--border); border-radius:12px; padding:8px 14px; text-align:center; min-width:78px; }
.kpi .n{ font-size:20px; font-weight:800; } .kpi .l{ font-size:9px; text-transform:uppercase; letter-spacing:1px; color:#888; }
.kpi.c .n{ color:var(--crit);} .kpi.w .n{ color:var(--warn);} .kpi.i .n{ color:var(--info);}
.filters{ display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:16px; }
.fbtn{ background:rgba(255,255,255,.05); border:1px solid var(--border); color:#aaa; padding:6px 13px; border-radius:7px; cursor:pointer; font-size:12px; font-weight:600; }
.fbtn.active,.fbtn:hover{ background:rgba(77,163,255,.2); color:var(--accent); border-color:var(--accent); }
.fbtn.sev-c.active{ background:rgba(231,76,60,.2); color:var(--crit); border-color:var(--crit);}
.fbtn.sev-w.active{ background:rgba(243,156,18,.2); color:var(--warn); border-color:var(--warn);}
.sep{ width:1px; height:20px; background:var(--border); }
.auto{ font-size:11px; color:#888; display:flex; gap:6px; align-items:center; margin-left:auto; }

.card{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border);
       border-left-width:4px; border-radius:13px; padding:15px 17px; margin-bottom:13px; }
.card.sev-critical{ border-left-color:var(--crit); }
.card.sev-warning { border-left-color:var(--warn); }
.card.sev-info    { border-left-color:var(--info); }
.card.dim{ opacity:.55; }
.card-top{ display:flex; align-items:flex-start; gap:12px; }
.sev-ic{ font-size:18px; margin-top:2px; }
.sev-critical .sev-ic{ color:var(--crit);} .sev-warning .sev-ic{ color:var(--warn);} .sev-info .sev-ic{ color:var(--info);}
.card-title{ font-size:15px; font-weight:700; margin:0 0 3px; }
.card-meta{ font-size:11px; color:#7d838d; display:flex; gap:12px; flex-wrap:wrap; align-items:center; }
.badge{ font-size:9.5px; font-weight:700; text-transform:uppercase; letter-spacing:.5px; padding:2px 7px; border-radius:5px; }
.b-kind{ background:rgba(155,89,182,.18); color:#c08fd6; }
.b-src{ background:rgba(255,255,255,.06); color:#888; }
.b-status-open{ background:rgba(231,76,60,.16); color:#e74c3c; }
.b-status-acknowledged{ background:rgba(243,156,18,.16); color:#f39c12; }
.b-status-resolved{ background:rgba(46,204,113,.16); color:#2ecc71; }
.b-status-dismissed{ background:rgba(255,255,255,.06); color:#888; }
.card-body{ font-size:13px; color:#cfd3da; line-height:1.55; margin:10px 0 0; white-space:pre-wrap; }
.dev-link{ color:var(--accent); text-decoration:none; } .dev-link:hover{ text-decoration:underline; }
.actions{ display:flex; gap:7px; margin-top:12px; flex-wrap:wrap; }
.act{ background:rgba(255,255,255,.05); border:1px solid var(--border); color:#bbb; padding:5px 11px; border-radius:7px; cursor:pointer; font-size:11px; display:inline-flex; gap:6px; align-items:center; }
.act:hover{ background:rgba(255,255,255,.12); color:#fff; }
.act.ok:hover{ border-color:#2ecc71; color:#2ecc71; } .act.warn:hover{ border-color:#f39c12; color:#f39c12; }
.act.fix{ border-color:rgba(155,89,182,.5); color:#c08fd6; } .act.fix:hover{ background:rgba(155,89,182,.18); color:#fff; }
.act.apply{ background:rgba(46,204,113,.15); border-color:#2ecc71; color:#2ecc71; font-weight:700; } .act.apply:hover{ background:#2ecc71; color:#0b1f14; }
.rem{ margin-top:11px; border:1px solid rgba(155,89,182,.3); background:rgba(155,89,182,.07); border-radius:10px; padding:10px 12px; }
.rem-h{ font-size:12px; color:#c08fd6; font-weight:700; display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
.rem-t{ font-size:10px; color:#9aa; font-weight:400; }
.rem-risk{ font-size:9.5px; font-weight:700; text-transform:uppercase; border:1px solid; border-radius:5px; padding:1px 6px; }
.rem-pb{ margin:9px 0 0; background:rgba(0,0,0,.45); border:1px solid rgba(255,255,255,.1); border-radius:8px; padding:10px; font-family:Consolas,monospace; font-size:11.5px; color:#cfe; overflow-x:auto; white-space:pre; }
.rem-res{ margin-top:8px; font-size:12px; color:#2ecc71; }
.rem-group{ margin-top:11px; display:flex; flex-direction:column; gap:9px; }
.rem-group .rem.embed{ margin-top:0; border-color:rgba(46,204,113,.32); background:rgba(46,204,113,.06); }
.rem.embed.dim{ opacity:.5; }
.members{ margin-top:11px; border-top:1px dashed rgba(255,255,255,.1); padding-top:9px; }
.member{ font-size:12px; color:#9aa; padding:3px 0; display:flex; gap:10px; }
.member .mt{ color:#ccd; } .member .ms{ color:#666; margin-left:auto; }
.empty{ text-align:center; color:#5a6472; padding:70px 20px; }
.empty i{ font-size:46px; color:#2ecc71; display:block; margin-bottom:14px; }
.spinner{ width:16px; height:16px; border:2px solid rgba(255,255,255,.2); border-top-color:var(--accent); border-radius:50%; display:inline-block; animation:spin .7s linear infinite; }
@keyframes spin{ to{ transform:rotate(360deg);} }
.data-toggle{ font-size:11px; color:#667; cursor:pointer; margin-top:8px; display:inline-block; }
pre.data{ display:none; background:rgba(0,0,0,.4); border:1px solid var(--border); border-radius:8px; padding:10px; font-size:11px; color:#9aa; overflow-x:auto; margin-top:8px; }
/* Investigate dropdown — one-click jump to every tool to diagnose this node */
.inv-wrap{ position:relative; display:inline-block; }
.inv-btn{ border-color:rgba(77,163,255,.55)!important; color:#4da3ff!important; font-weight:700; }
.inv-btn:hover{ background:rgba(77,163,255,.16)!important; color:#fff!important; }
.inv-menu{ display:none; position:absolute; z-index:1001; top:calc(100% + 5px); left:0; min-width:200px;
  background:#0d1422; border:1px solid var(--border); border-radius:11px; padding:6px; box-shadow:0 12px 34px rgba(0,0,0,.55); }
.inv-menu.open{ display:block; }
/* lift the whole card above later cards while its menu is open, so the dropdown is on top & clickable */
.card.menu-open{ position:relative; z-index:1000; }
.inv-menu .ttl{ font-size:9.5px; letter-spacing:1px; text-transform:uppercase; color:#5a6472; padding:5px 10px 4px; }
.inv-menu a{ display:flex; align-items:center; gap:10px; padding:8px 10px; border-radius:7px; color:#cdd6e2; text-decoration:none; font-size:12.5px; }
.inv-menu a:hover{ background:rgba(77,163,255,.14); color:#fff; }
.inv-menu a i{ width:16px; text-align:center; color:#4da3ff; }
.focus-banner{ display:flex; align-items:center; gap:12px; background:rgba(77,163,255,.1); border:1px solid rgba(77,163,255,.35);
  border-radius:10px; padding:10px 14px; margin-bottom:12px; font-size:13px; color:#cfe0f5; }
.focus-banner b{ color:#fff; } .focus-banner .clr{ color:#4da3ff; cursor:pointer; margin-left:auto; white-space:nowrap; }
.focus-banner .clr:hover{ text-decoration:underline; }
.card.focused{ border-color:#4da3ff!important; box-shadow:0 0 0 2px rgba(77,163,255,.45), 0 0 26px rgba(77,163,255,.28); }
</style>
</head>
<body>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>

<div class="wrap">
    <div class="head">
        <div>
            <h1><i class="fas fa-wand-magic-sparkles"></i> AI Insights &amp; Incidents</h1>
            <div class="sub">Plain-English findings from the AI flows — root-cause cards, anomalies, and correlated incidents.</div>
        </div>
        <div class="pill-row">
            <div class="kpi c"><div class="n" id="k-crit">0</div><div class="l">Critical</div></div>
            <div class="kpi w"><div class="n" id="k-warn">0</div><div class="l">Warning</div></div>
            <div class="kpi i"><div class="n" id="k-info">0</div><div class="l">Info</div></div>
        </div>
    </div>

    <div class="filters">
        <button class="fbtn active" data-status="active" onclick="setStatus(this,'active')">Active</button>
        <button class="fbtn" data-status="resolved" onclick="setStatus(this,'resolved')">Resolved</button>
        <button class="fbtn" data-status="all" onclick="setStatus(this,'all')">All</button>
        <button class="fbtn" data-status="ignored" onclick="setStatus(this,'ignored')"><i class="fas fa-bell-slash"></i> Ignored</button>
        <span class="sep"></span>
        <button class="fbtn sev-c" data-sev="critical" onclick="setSev(this,'critical')">Critical</button>
        <button class="fbtn sev-w" data-sev="warning" onclick="setSev(this,'warning')">Warning</button>
        <button class="fbtn" data-sev="info" onclick="setSev(this,'info')">Info</button>
        <button class="fbtn active" data-sev="all" onclick="setSev(this,'all')">Any</button>
        <span class="auto"><label><input type="checkbox" id="auto" onchange="toggleAuto()"> Auto-refresh</label>
            <button class="fbtn" onclick="load()"><i class="fas fa-rotate"></i></button></span>
    </div>

    <div id="list"><div class="empty"><span class="spinner"></span></div></div>
</div>

<script>
let fStatus='active', fSev='all', autoTimer=null;
// Deep-link focus: ?node=<id> filters the list to one node; ?focus=<insight_id>
// highlights + scrolls to that exact card (so "view" from an incident lands precisely).
let gFocusNode=0, gFocusId=0;
(function(){ const p=new URLSearchParams(location.search);
    gFocusNode=parseInt(p.get('node')||'0',10)||0;
    gFocusId  =parseInt(p.get('focus')||'0',10)||0;
    if(gFocusId) fStatus='all';   // ensure the specific insight shows even if acknowledged/resolved
})();
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function ago(s){ s=+s||0; if(s<60)return s+'s ago'; if(s<3600)return Math.floor(s/60)+'m ago';
    if(s<86400)return Math.floor(s/3600)+'h ago'; return Math.floor(s/86400)+'d ago'; }
const SEVIC={critical:'fa-circle-exclamation',warning:'fa-triangle-exclamation',info:'fa-circle-info'};
const ICON={mikrotik:'network-wired',cisco:'server',ping:'satellite-dish'};

function setStatus(b,v){ fStatus=v; document.querySelectorAll('.fbtn[data-status]').forEach(x=>x.classList.toggle('active',x===b)); load(); }
function setSev(b,v){ fSev=v; document.querySelectorAll('.fbtn[data-sev]').forEach(x=>x.classList.toggle('active',x===b)); load(); }
function toggleAuto(){ if(document.getElementById('auto').checked) autoTimer=setInterval(load,15000); else { clearInterval(autoTimer); autoTimer=null; } }

function clearFocus(){ gFocusNode=0; gFocusId=0;
    history.replaceState(null,'','ai_insights.php');   // drop the deep-link params from the URL
    load(); }

async function load(){
    if(fStatus==='ignored'){ return loadIgnored(); }
    const nodeQ = gFocusNode ? ('&node='+gFocusNode) : '';
    const [r,c]=await Promise.all([
        fetch(`ai_insights.php?api=list&status=${fStatus}&severity=${fSev}${nodeQ}&_=${Date.now()}`).then(r=>r.json()),
        fetch('ai_insights.php?api=counts').then(r=>r.json())
    ]);
    document.getElementById('k-crit').textContent=c.critical||0;
    document.getElementById('k-warn').textContent=c.warning||0;
    document.getElementById('k-info').textContent=c.info||0;
    const box=document.getElementById('list');
    const I=(r.insights)||[];
    // Focused-node context banner (so the user knows the list is scoped + can clear it)
    const banner = gFocusNode ? `<div class="focus-banner"><i class="fas fa-crosshairs" style="color:#4da3ff;"></i>
        <span>Showing insights for <b>${esc(r.focus_name||('Node #'+gFocusNode))}</b> only — focused from an incident.</span>
        <span class="clr" onclick="clearFocus()"><i class="fas fa-list"></i> Show all nodes</span></div>` : '';
    if(!I.length){ box.innerHTML=banner+`<div class="empty"><i class="fas fa-circle-check"></i>
        <div style="font-size:16px;color:#aaa;">No ${fStatus==='active'?'active ':''}insights${gFocusNode?' for this node':''}.</div>
        <div style="font-size:12px;color:#667;margin-top:6px;">AI flows post findings here. Trigger one from <a href="log_mon.php" style="color:var(--accent)">Logs → AI Analyze</a>.</div></div>`; return; }

    // Group blast-radius incidents by correlation_key; non-correlated stand alone.
    const groups={}, order=[];
    I.forEach(x=>{ const k=x.correlation_key||('solo-'+x.id); if(!groups[k]){groups[k]=[];order.push(k);} groups[k].push(x); });
    box.innerHTML=banner+order.map(k=>{
        const g=groups[k];
        // master = the non-suppressed, highest-severity item; suppressed downstream become members
        const SV={critical:0,warning:1,info:2};
        g.sort((a,b)=>{
            const am=a.status==='suppressed'?1:0, bm=b.status==='suppressed'?1:0;
            if(am!==bm) return am-bm;
            return (SV[a.severity]??3)-(SV[b.severity]??3);
        });
        const m=g[0], rest=g.slice(1);
        return card(m, rest);
    }).join('');

    // Highlight + scroll to the exact insight we were sent to investigate.
    if(gFocusId){
        const el=box.querySelector('.card[data-id="'+gFocusId+'"]');
        if(el){ el.classList.add('focused'); el.scrollIntoView({behavior:'smooth',block:'center'}); }
    }
}

// Build the context-aware "Investigate" menu for a card. Only nodes get it; the
// Command Center option appears only for windows/linux hosts that have a host mapping
// (hidden for ping-only / generic SNMP). Goal: every tool to diagnose a node, on hand.
function investigateMenu(m){
    if(!m.node_id) return '';
    const n=+m.node_id;
    let opts=`<div class="ttl">Investigate this node</div>`;
    opts+=`<a href="troubleshoot.php?node=${n}" style="font-weight:700;color:#9cffc7;"><i class="fas fa-stethoscope" style="color:#2ecc71;"></i> Troubleshoot (guided)</a>`;
    opts+=`<a href="log_mon.php?node=${n}"><i class="fas fa-file-lines"></i> Device Log</a>`;
    opts+=`<a href="net_mon_stats.php?node=${n}"><i class="fas fa-chart-line"></i> Node Status</a>`;
    if(m.monitor_type!=='ping'){
        if(m.os_icon==='windows' && m.win_host_id) opts+=`<a href="windows.php?host=${+m.win_host_id}"><i class="fab fa-windows"></i> Command Center</a>`;
        else if(m.os_icon==='linux' && m.lx_host_id) opts+=`<a href="linux.php?host=${+m.lx_host_id}"><i class="fab fa-linux"></i> Command Center</a>`;
    }
    opts+=`<a href="smokeping.php?node=${n}"><i class="fas fa-wave-square"></i> Smokeping</a>`;
    return `<div class="inv-wrap"><button type="button" class="act inv-btn" onclick="toggleInv(this)"><i class="fas fa-stethoscope"></i> Investigate <i class="fas fa-caret-down"></i></button><div class="inv-menu">${opts}</div></div>`;
}
function closeAllInv(){
    document.querySelectorAll('.inv-menu.open').forEach(x=>x.classList.remove('open'));
    document.querySelectorAll('.card.menu-open').forEach(x=>x.classList.remove('menu-open'));
}
function toggleInv(btn){
    const menu=btn.nextElementSibling, isOpen=menu.classList.contains('open');
    closeAllInv();
    if(!isOpen){ menu.classList.add('open'); const c=btn.closest('.card'); if(c) c.classList.add('menu-open'); }
}
document.addEventListener('click',e=>{ if(!e.target.closest('.inv-wrap')) closeAllInv(); });

// Render a remediation FULLY inside its parent finding's card: the proposed command + risk +
// its own Approve/Resolve/Dismiss actions. Keeps the fix grouped with the anomaly (same device).
function remCard(x){
    let d=null; if(x.data){ try{ d=JSON.parse(x.data); }catch(e){} }
    const risk=((d&&d.risk)||'').toString();
    const riskC=/high|crit/i.test(risk)?'#e74c3c':(/med/i.test(risk)?'#f39c12':'#2ecc71');
    const applied=d&&d.apply_result;
    const done=(x.status==='resolved'||x.status==='dismissed');
    return `<div class="rem embed ${done?'dim':''}" data-id="${x.id}">
        <div class="rem-h"><i class="fas fa-screwdriver-wrench"></i> Proposed fix
            ${d&&d.target?`<span class="rem-t">target: ${esc(d.target)}</span>`:''}
            ${risk?`<span class="rem-risk" style="color:${riskC};border-color:${riskC}">risk: ${esc(risk)}</span>`:''}
            <span class="badge b-status-${esc(x.status)}" style="margin-left:6px;">${esc(x.status)}</span>
            <span class="ms" style="margin-left:auto;color:#667;">${ago(x.age_sec)}</span></div>
        ${x.body?`<div class="card-body" style="margin:6px 0 4px;">${esc(x.body)}</div>`:''}
        ${d&&d.playbook?`<pre class="rem-pb">${esc(typeof d.playbook==='string'?d.playbook:JSON.stringify(d.playbook,null,2))}</pre>`:''}
        ${applied?`<div class="rem-res"><b>✓ Applied</b> by ${esc(d.apply_result.by||'')} — <span style="color:#9aa;">${esc(d.apply_result.output||'')}</span></div>`:''}
        <div class="actions" style="margin-top:8px;">
            ${!done?`<button class="act apply" onclick='applyFix(${x.id}, ${JSON.stringify((d&&d.target)||x.node_name||"")})'><i class="fas fa-bolt"></i> Approve &amp; Apply</button>`:''}
            ${x.status!=='resolved'?`<button class="act ok" onclick="upd(${x.id},'resolved')"><i class="fas fa-check"></i> Resolve</button>`:`<button class="act" onclick="upd(${x.id},'open')"><i class="fas fa-rotate-left"></i> Reopen</button>`}
            ${!done?`<button class="act" onclick="upd(${x.id},'dismissed')" title="Discard this proposal"><i class="fas fa-ban"></i> Dismiss</button>`:''}
            <button class="act" onclick="del(${x.id})" title="Delete"><i class="fas fa-trash"></i></button>
        </div>
    </div>`;
}
function card(m, members){
    const sev=m.severity||'info';
    const dim=(m.status==='resolved'||m.status==='dismissed')?'dim':'';
    const dev = m.node_id ? `<a class="dev-link" href="log_mon.php?node=${m.node_id}"><i class="fas fa-${ICON[m.os_icon]||'desktop'}"></i> ${esc(m.node_name||('Node #'+m.node_id))}</a>` : '<span style="color:#667;">network-wide</span>';
    let dObj=null; if(m.data){ try{ dObj=JSON.parse(m.data); }catch(e){} }
    let dataBlock='';
    if(m.data){ let d=m.data; try{ d=JSON.stringify(dObj,null,2);}catch(e){} dataBlock=`<span class="data-toggle" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='block'?'none':'block'"><i class="fas fa-code"></i> details</span><pre class="data">${esc(d)}</pre>`; }
    // Split members: remediations (rendered FULLY inside this card, actionable) vs other correlated
    // findings (collapsed one-liners). This is what makes "Suggest fix" land in the SAME device card.
    const remMembers = members.filter(x=>x.kind==='remediation');
    const others     = members.filter(x=>x.kind!=='remediation');
    const mem = others.length ? `<div class="members"><div style="font-size:10px;color:#667;text-transform:uppercase;letter-spacing:1px;margin-bottom:5px;">${others.length} correlated / suppressed</div>${others.map(x=>`<div class="member"><span class="mt">${esc(x.node_name||('Node #'+x.node_id))}</span><span>${esc(x.title)}</span><span class="ms">${ago(x.age_sec)}</span></div>`).join('')}</div>` : '';
    const remEmbed = remMembers.length ? `<div class="rem-group">${remMembers.map(remCard).join('')}</div>` : '';

    // Remediation card: show the proposed playbook + risk + the apply result (if any)
    const isRem = m.kind==='remediation';
    let remBlock='';
    if(isRem && dObj){
        const risk=(dObj.risk||'').toString();
        const riskC = /high|crit/i.test(risk)?'#e74c3c':(/med/i.test(risk)?'#f39c12':'#2ecc71');
        remBlock=`<div class="rem">
            <div class="rem-h"><i class="fas fa-screwdriver-wrench"></i> Proposed remediation
                ${dObj.target?`<span class="rem-t">target: ${esc(dObj.target)}</span>`:''}
                ${risk?`<span class="rem-risk" style="color:${riskC};border-color:${riskC}">risk: ${esc(risk)}</span>`:''}</div>
            ${dObj.playbook?`<pre class="rem-pb">${esc(typeof dObj.playbook==='string'?dObj.playbook:JSON.stringify(dObj.playbook,null,2))}</pre>`:''}
            ${dObj.apply_result?`<div class="rem-res"><b>✓ Applied</b> by ${esc(dObj.apply_result.by||'')} — <span style="color:#9aa;">${esc(dObj.apply_result.output||'')}</span></div>`:''}
        </div>`;
    }
    return `<div class="card sev-${sev} ${dim}" data-id="${m.id}">
        <div class="card-top">
            <i class="sev-ic fas ${SEVIC[sev]||'fa-circle-info'}"></i>
            <div style="flex:1;min-width:0;">
                <div class="card-title">${esc(m.title)}</div>
                <div class="card-meta">
                    ${dev}
                    <span class="badge b-kind">${esc(m.kind)}</span>
                    <span class="badge b-status-${esc(m.status)}">${esc(m.status)}</span>
                    <span class="badge b-src">${esc(m.source)}</span>
                    <span><i class="far fa-clock"></i> ${ago(m.age_sec)}</span>
                    ${others.length?`<span style="color:#c08fd6;"><i class="fas fa-layer-group"></i> incident · ${others.length+1} devices</span>`:''}
                    ${remMembers.length?`<span style="color:#2ecc71;"><i class="fas fa-screwdriver-wrench"></i> ${remMembers.length} proposed fix${remMembers.length>1?'es':''}</span>`:''}
                </div>
                ${m.body?`<div class="card-body">${esc(m.body)}</div>`:''}
                ${remBlock}
                ${dataBlock}
                ${remEmbed}
                ${mem}
                <div class="actions">
                    ${investigateMenu(m)}
                    ${isRem && m.status!=='resolved'?`<button class="act apply" onclick='applyFix(${m.id}, ${JSON.stringify((dObj&&dObj.target)||m.node_name||"")})'><i class="fas fa-bolt"></i> Approve &amp; Apply</button>`:''}
                    ${!isRem && m.status!=='resolved'?`<button class="act fix" onclick="suggestFix(${m.id}, this)"><i class="fas fa-screwdriver-wrench"></i> Suggest fix</button>`:''}
                    ${m.status!=='acknowledged'&&m.status!=='resolved'?`<button class="act warn" onclick="upd(${m.id},'acknowledged')"><i class="fas fa-eye"></i> Acknowledge</button>`:''}
                    ${m.status!=='resolved'?`<button class="act ok" onclick="upd(${m.id},'resolved')"><i class="fas fa-check"></i> Resolve</button>`:`<button class="act" onclick="upd(${m.id},'open')"><i class="fas fa-rotate-left"></i> Reopen</button>`}
                    <button class="act" onclick="upd(${m.id},'dismissed')" title="Close this one (it may reappear if re-detected)"><i class="fas fa-ban"></i> Dismiss</button>
                    <button class="act" onclick="ignoreInsight(${m.id})" title="Mute this finding AND future matching ones"><i class="fas fa-bell-slash"></i> Ignore</button>
                    <button class="act" onclick="del(${m.id})" title="Delete"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        </div>
    </div>`;
}

async function upd(id,status){
    await fetch('ai_insights.php?api=update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,status})});
    load();
}
async function ignoreInsight(id){
    if(!confirm('Ignore this finding?\n\nThis hides it AND auto-suppresses future matching ones (same correlation, or same kind on this device). Manage/undo under the “Ignored” filter.'))return;
    await fetch('ai_insights.php?api=ignore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});
    load();
}
async function loadIgnored(){
    const r=await fetch('ai_insights.php?api=ignores_list&_='+Date.now()).then(r=>r.json()).catch(()=>null);
    const box=document.getElementById('list'); const rules=(r&&r.rules)||[];
    if(!rules.length){ box.innerHTML=`<div class="empty"><i class="fas fa-bell-slash"></i><div style="font-size:16px;color:#aaa;">Nothing ignored.</div><div style="font-size:12px;color:#667;margin-top:6px;">Hit <b>Ignore</b> on any insight to mute it and future matches.</div></div>`; return; }
    box.innerHTML=`<div style="font-size:12px;color:#8a909a;margin-bottom:10px;">${rules.length} active ignore rule(s). New insights matching these are auto-suppressed.</div>`+
      rules.map(g=>`<div class="card" style="display:flex;align-items:center;gap:12px;">
        <i class="fas fa-bell-slash" style="color:#888;font-size:18px;"></i>
        <div style="flex:1;min-width:0;"><div class="card-title">${esc(g.label||g.match_val)}</div>
          <div class="card-meta"><span class="badge b-kind">${esc(g.match_type==='corr'?'correlation':'kind + device')}</span>
          <span class="badge b-src mono">${esc(g.match_val)}</span> <span><i class="far fa-clock"></i> ${ago((Date.now()/1000)-(new Date(g.created_at.replace(' ','T')).getTime()/1000))}</span></div></div>
        <button class="act ok" onclick="unignore(${g.id})"><i class="fas fa-rotate-left"></i> Un-ignore</button></div>`).join('');
}
async function unignore(rid){
    await fetch('ai_insights.php?api=unignore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rule_id:rid})});
    load();
}
async function del(id){ if(!confirm('Delete this insight?'))return;
    await fetch('ai_insights.php?api=delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}); load(); }

// Ask the AI to propose a remediation (fires the self-heal flow → posts a remediation card back)
async function suggestFix(id, btn){
    if(btn){ btn.disabled=true; btn.innerHTML='<span class="spinner" style="width:11px;height:11px;"></span> Asking…'; }
    const r=await fetch('ai_insights.php?api=suggest_fix',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}).then(r=>r.json()).catch(()=>({ok:false}));
    if(btn){btn.disabled=false;btn.innerHTML='<i class="fas fa-screwdriver-wrench"></i> Suggest fix';}
    if(!r.ok){ alert('Could not request a fix:\n'+(r.err||'unknown')+(r.http?(' (HTTP '+r.http+')'):'')+(r.reply?('\n\nn8n said: '+r.reply):'')+(r.hint?('\n\n'+r.hint):'')); return; }
    // show what n8n actually replied so a non-responding flow is obvious, not silently "queued"
    const reply=(r.reply||'').trim();
    const started=/workflow was started/i.test(reply);
    alert('Sent to n8n (HTTP '+(r.http||'?')+').'+
      (started?'\n\nThe self-heal flow accepted it and is running async — a remediation card will appear here when it posts back (refresh in a moment).'
              :'\n\nn8n replied: '+(reply||'(empty)')+'\n\nIf no remediation card appears, the n8n "self-heal" workflow either isn\'t ACTIVE or doesn\'t POST a kind=\'remediation\' insight back to nm_ai_ingest.php.'));
    setTimeout(load, 2500);
}

// Approve & apply an AI remediation — explicit human confirmation (destructive, outward-facing)
async function applyFix(id, target){
    if(!confirm('APPROVE & APPLY this remediation?\n\nTarget: '+(target||'(device)')+'\n\nThis runs the proposed playbook/script on the device via n8n. Proceed only if you have reviewed it.')) return;
    const r=await fetch('ai_insights.php?api=apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}).then(r=>r.json()).catch(()=>({ok:false}));
    if(!r.ok){ alert('Apply failed:\n'+(r.err||'unknown')+(r.hint?('\n\n'+r.hint):'')); load(); return; }
    const res = r.result ? ('\n\nResult:\n'+(typeof r.result==='string'?r.result:JSON.stringify(r.result,null,2))) : '';
    if(r.applied===false) alert('⚠️ The remediation ran but reported FAILURE — the card stays open.'+res);
    else alert('✓ Applied successfully.'+res);
    load();
}

load();
</script>
</body>
</html>
