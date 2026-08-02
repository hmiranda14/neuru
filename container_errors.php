<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — Containers: AI Error Watch (incident desk). Reads container_incidents
// (written by the n8n error-watch flow via nm_containers_api.php). Acknowledge /
// resolve / ignore / reopen / reanalyze + Remediate hand-off. RBAC: 'containers'.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_n8n.php');
require_once('nm_solutionkb.php');
require_once('nm_portainer.php');
require_once('nm_chrome.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'containers')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=containers'); exit;
}
function cset_get($conn,$k,$d=''){ $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; }
function incident_summary($conn){
    $out=['active'=>0,'analyzing'=>0,'open'=>0,'acknowledged'=>0,'resolved'=>0,'ignored'=>0,'total'=>0];
    $r=$conn->query("SELECT status,COUNT(*) c FROM container_incidents GROUP BY status");
    while($r&&$x=$r->fetch_assoc()){ $out[$x['status']]=(int)$x['c']; $out['total']+=(int)$x['c']; }
    $out['active']=$out['analyzing']+$out['open']+$out['acknowledged'];
    return $out;
}

// ── API ───────────────────────────────────────────────────────────────────────
if (function_exists('session_write_close')) @session_write_close(); // free session lock before slow SSH/n8n I/O (prevents whole-portal freeze)
if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');

    if ($api === 'data') {
        $status = $_GET['status'] ?? 'active';
        $where = []; $p = [];
        if ($status === 'active')         $where[] = "status IN ('analyzing','open','acknowledged')";
        elseif (in_array($status,['analyzing','open','acknowledged','resolved','ignored'],true)) $where[] = "status='".$conn->real_escape_string($status)."'";
        if (!empty($_GET['severity'])) $where[] = "severity='".$conn->real_escape_string($_GET['severity'])."'";
        if (!empty($_GET['q'])) { $q=$conn->real_escape_string($_GET['q']); $where[] = "(error_text LIKE '%$q%' OR container_name LIKE '%$q%' OR host LIKE '%$q%')"; }
        if (!empty($_GET['from'])) $where[] = "last_seen >= '".$conn->real_escape_string($_GET['from'])." 00:00:00'";
        if (!empty($_GET['to']))   $where[] = "last_seen <= '".$conn->real_escape_string($_GET['to'])." 23:59:59'";
        $lim = max(1, min(500, (int)($_GET['limit'] ?? 200)));
        $w = $where ? ('WHERE '.implode(' AND ',$where)) : '';
        $r = $conn->query("SELECT id,endpoint_id,host,host_ip,container_id,container_name,severity,error_text,
            ai_summary,ai_solution,fingerprint,occurrences,status,first_seen,last_seen,
            remediation_status,remediation_log,fix_status FROM container_incidents {$w}
            ORDER BY FIELD(status,'analyzing','open','acknowledged','ignored','resolved'), last_seen DESC LIMIT {$lim}");
        $rows = $r ? $r->fetch_all(MYSQLI_ASSOC) : [];
        // Resolve endpoint_id → the real Docker HOST (name + ip) so the operator knows WHICH
        // server each container runs on (the stored host/host_ip are often blank/the container name).
        $pcfg = nm_portainer_cfg($conn);
        $emap = nm_portainer_configured($pcfg) ? nm_portainer_endpoint_map($pcfg) : [];
        // IP → NEURU node map, so each container error shows WHICH monitored node hosts it
        // (bridge is host_ip ↔ nm_nodes.ip_address — no stored node_id exists).
        $nodeByIp = [];
        $nr = $conn->query("SELECT id, display_name, ip_address FROM nm_nodes WHERE ip_address IS NOT NULL AND ip_address<>''");
        while ($nr && $nx = $nr->fetch_assoc()) $nodeByIp[trim($nx['ip_address'])] = ['id'=>(int)$nx['id'], 'name'=>$nx['display_name']];
        foreach ($rows as &$row) {
            $ep = $emap[(int)$row['endpoint_id']] ?? null;
            $row['server'] = $ep['name'] ?? ($row['host'] ?: '');
            if (empty($row['host_ip']) && $ep && !empty($ep['ip'])) {
                $row['host_ip'] = $ep['ip'];
                $conn->query("UPDATE container_incidents SET host_ip='".$conn->real_escape_string($ep['ip'])."' WHERE id=".(int)$row['id']);
            }
            $nd = ($row['host_ip'] !== '' ? ($nodeByIp[trim($row['host_ip'])] ?? null) : null);
            $row['node']    = $nd['name'] ?? null;
            $row['node_id'] = $nd['id'] ?? null;
        }
        unset($row);
        echo json_encode(['ok'=>true,'incidents'=>$rows,'summary'=>incident_summary($conn)]);
        exit;
    }

    if ($api === 'update') {
        $b = json_decode(file_get_contents('php://input'), true) ?? [];
        $id = (int)($b['id'] ?? 0); $action = $b['action'] ?? ''; $note = substr(trim($b['note'] ?? ''),0,2000);
        $uid = (int)($_SESSION['UID'] ?? 0) ?: null;
        $r = $conn->query("SELECT * FROM container_incidents WHERE id={$id} LIMIT 1");
        $inc = $r ? $r->fetch_assoc() : null;
        if (!$inc) { echo json_encode(['ok'=>false,'error'=>'Not found']); exit; }

        if ($action === 'acknowledge') {
            $conn->query("UPDATE container_incidents SET status='acknowledged' WHERE id={$id}");
        } elseif ($action === 'resolve' || $action === 'ignore') {
            $st = $action === 'resolve' ? 'resolved' : 'ignored';
            $stp = $conn->prepare("UPDATE container_incidents SET status=?, resolution_note=?, resolved_by=?, resolved_at=NOW() WHERE id=?");
            $stp->bind_param('ssii', $st, $note, $uid, $id); $stp->execute();
            $kb_saved = false;
            if ($action === 'resolve') {  // snapshot the fix into the Knowledge Base
                $kb_saved = (bool)nm_kb_capture($conn, ['subject'=>$inc['container_name'],'severity'=>$inc['severity'],
                    'error'=>$inc['error_text'],'summary'=>$inc['ai_summary'],
                    'resolution'=>nm_kb_build_resolution($conn,$id,$note,(string)$inc['ai_solution']),
                    'source'=>'resolve','incident_id'=>$id]);
            }
            nm_audit($conn,'incident.'.$action,['target_type'=>'container_incident','target_id'=>$id]);
            echo json_encode(['ok'=>true,'kb_saved'=>$kb_saved]); exit;
        } elseif ($action === 'reopen') {
            $conn->query("UPDATE container_incidents SET status='open', resolved_by=NULL, resolved_at=NULL WHERE id={$id}");
        } elseif ($action === 'reanalyze') {
            // SYNCHRONOUS analysis: call whatever AI-RCA flow is live (dedicated `container-analyze`
            // if present, else the always-shipped `log-rca`), read the result straight from the HTTP
            // reply, and write ai_summary/ai_solution ourselves. This replaces the old fire-and-forget
            // push to `container-analyze` — which silently did nothing after the flow got wiped (the
            // "Reanalyze does nothing" bug). Existing analysis is preserved if the flow fails.
            require_once __DIR__ . '/nm_erroranalyze.php';
            $conn->query("UPDATE container_incidents SET status='analyzing', ai_requested_at=NOW() WHERE id={$id}");
            $res = nm_container_ai_analyze($conn, $id, 40);
            if (!empty($res['ok'])) {
                // nothing new to analyze on this one? revert the 'analyzing' flip if the flow gave nothing
                $msg = '✅ Re-analyzed via '.($res['via'] ?? 'AI').'.';
            } else {
                // roll the status back so it doesn't sit stuck in 'analyzing'
                $conn->query("UPDATE container_incidents SET status=IF(status='analyzing','open',status), ai_requested_at=NULL WHERE id={$id}");
                $msg = '⚠️ Re-analysis failed: '.($res['error'] ?? 'unknown').'. The AI flow ('.($res['via'] ?? 'container-analyze/log-rca').') may be down — check Config → Integrations & AI.';
            }
            nm_audit($conn,'incident.reanalyze',['target_type'=>'container_incident','target_id'=>$id,'details'=>['ok'=>!empty($res['ok']),'via'=>$res['via']??'','http'=>$res['http']??0]]);
            echo json_encode(['ok'=>true,'pushed'=>!empty($res['ok']),'http'=>$res['http']??0,'summary'=>$res['summary']??'','solution'=>$res['solution']??'','message'=>$msg]); exit;
        } else { echo json_encode(['ok'=>false,'error'=>'Unknown action']); exit; }
        nm_audit($conn,'incident.'.$action,['target_type'=>'container_incident','target_id'=>$id]);
        echo json_encode(['ok'=>true]); exit;
    }

    if ($api === 'bulk') {
        $b = json_decode(file_get_contents('php://input'), true) ?? [];
        $ids = array_values(array_filter(array_map('intval', (array)($b['ids'] ?? [])), fn($x)=>$x>0));
        $action = $b['action'] ?? ''; $note = substr(trim($b['note'] ?? ''),0,2000);
        $saveKb = !isset($b['kb']) || !empty($b['kb']);   // default ON; user can turn it off for a bulk resolve
        $uid = (int)($_SESSION['UID'] ?? 0) ?: null;
        if (!$ids) { echo json_encode(['ok'=>false,'error'=>'No incidents selected']); exit; }
        if (!in_array($action,['acknowledge','resolve','ignore','reopen'],true)) { echo json_encode(['ok'=>false,'error'=>'Unknown action']); exit; }
        $ids = array_slice($ids, 0, 500);   // hard cap
        $done = 0; $kb_saved = 0;
        foreach ($ids as $id) {
            try {
                $r = $conn->query("SELECT * FROM container_incidents WHERE id={$id} LIMIT 1");
                $inc = $r ? $r->fetch_assoc() : null;
                if (!$inc) continue;
                if ($action === 'acknowledge') {
                    $conn->query("UPDATE container_incidents SET status='acknowledged' WHERE id={$id}");
                } elseif ($action === 'reopen') {
                    $conn->query("UPDATE container_incidents SET status='open', resolved_by=NULL, resolved_at=NULL WHERE id={$id}");
                } else { // resolve | ignore
                    $st = $action === 'resolve' ? 'resolved' : 'ignored';
                    $stp = $conn->prepare("UPDATE container_incidents SET status=?, resolution_note=?, resolved_by=?, resolved_at=NOW() WHERE id=?");
                    $stp->bind_param('ssii', $st, $note, $uid, $id); $stp->execute();
                    if ($action === 'resolve' && $saveKb) {   // best-effort KB snapshot (never abort the batch)
                        // push=false → store the KB row locally but DON'T block on the n8n vector push
                        // per-incident (that hangs a big "resolve all"); re-vectorize later from the KB page.
                        try { if (nm_kb_capture($conn, ['subject'=>$inc['container_name'],'severity'=>$inc['severity'],
                            'error'=>$inc['error_text'],'summary'=>$inc['ai_summary'],
                            'resolution'=>nm_kb_build_resolution($conn,$id,$note,(string)$inc['ai_solution']),
                            'source'=>'resolve','incident_id'=>$id], false)) $kb_saved++; } catch (\Throwable $e) {}
                    }
                }
                try { nm_audit($conn,'incident.'.$action,['target_type'=>'container_incident','target_id'=>$id,'details'=>['bulk'=>true]]); } catch (\Throwable $e) {}
                $done++;
            } catch (\Throwable $e) {}
        }
        echo json_encode(['ok'=>true,'done'=>$done,'kb_saved'=>$kb_saved]); exit;
    }

    if ($api === 'remediate') {
        $b = json_decode(file_get_contents('php://input'), true) ?? [];
        $id = (int)($b['id'] ?? 0);
        $url = cset_get($conn,'error_watch_remediation_url','');
        if ($url === '') { echo json_encode(['ok'=>false,'error'=>'No remediation webhook configured']); exit; }
        if (!function_exists('curl_init')) { echo json_encode(['ok'=>false,'error'=>'cURL unavailable']); exit; }
        $r = $conn->query("SELECT * FROM container_incidents WHERE id={$id} LIMIT 1");
        $inc = $r ? $r->fetch_assoc() : null;
        if (!$inc) { echo json_encode(['ok'=>false,'error'=>'Not found']); exit; }
        $cfg = nm_n8n_get($conn);
        // Resolve the real Docker host IP if the incident lacks one (backfill).
        $hostIp = trim((string)($inc['host_ip'] ?? ''));
        if ($hostIp === '') { $pcfg = nm_portainer_cfg($conn);
            if (nm_portainer_configured($pcfg)) { $hostIp = nm_portainer_host_ip($pcfg, (int)$inc['endpoint_id'], (string)$inc['host']);
                if ($hostIp !== '') $conn->query("UPDATE container_incidents SET host_ip='".$conn->real_escape_string($hostIp)."' WHERE id={$id}"); } }
        $base = function_exists('nm_n8n_callback_base') ? nm_n8n_callback_base($conn, $url) : (((!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http').'://'.($_SERVER['HTTP_HOST']??''));  // per-flow: hosted→tunnel, local→LAN
        $payload = ['event'=>'remediate','incident_id'=>$id,'endpoint_id'=>(int)$inc['endpoint_id'],
            'host'=>$inc['host'],'host_ip'=>$hostIp,'container_id'=>$inc['container_id'],'container_name'=>$inc['container_name'],
            'severity'=>$inc['severity'],'error'=>$inc['error_text'],'ai_solution'=>$inc['ai_solution'],
            'callback_url'=>$base.'/nm_containers_api.php?ep=incident_remediation&id='.$id];
        if(function_exists('nm_n8n_neuru_stamp'))$payload=nm_n8n_neuru_stamp($conn,$payload,$url,'container-remediate');  // gatecheck + per-flow model
        $ch=curl_init($url);
        curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>json_encode($payload),
            CURLOPT_CONNECTTIMEOUT=>4,CURLOPT_TIMEOUT=>15,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_SSL_VERIFYHOST=>false,
            CURLOPT_HTTPHEADER=>['Content-Type: application/json','X-NetMon-Token: '.$cfg['inbound_token']]]);
        curl_exec($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
        if ($code>=200 && $code<300) {
            $conn->query("UPDATE container_incidents SET remediation_status='sent', remediated_at=NULL WHERE id={$id}");
            nm_audit($conn,'incident.remediate',['target_type'=>'container_incident','target_id'=>$id]);
            echo json_encode(['ok'=>true,'message'=>'Remediation requested']);
        } else echo json_encode(['ok'=>false,'error'=>"Webhook failed (HTTP {$code})"]);
        exit;
    }

    if ($api === 'ai_toggle') {
        $on = (($_POST['on'] ?? $_GET['on'] ?? '1') === '1');
        $conn->query("INSERT INTO nm_settings(setting_key,setting_val) VALUES('error_watch_ai','".($on?'1':'0')."')
                      ON DUPLICATE KEY UPDATE setting_val='".($on?'1':'0')."'");
        // Turning AI OFF unsticks everything waiting on analysis → plain 'open' errors (no AI expected).
        $freed = 0;
        if (!$on) { $conn->query("UPDATE container_incidents SET status='open', ai_requested_at=NULL WHERE status='analyzing' AND (ai_summary IS NULL OR ai_summary='')"); $freed = $conn->affected_rows; }
        nm_audit($conn,'container.ai_toggle',['details'=>['on'=>$on,'freed'=>$freed]]);
        echo json_encode(['ok'=>true,'on'=>$on,'freed'=>$freed]); exit;
    }

    echo json_encode(['ok'=>false,'error'=>'Unknown endpoint']); exit;
}

// ── Page ──────────────────────────────────────────────────────────────────────
$summary = incident_summary($conn);
// Flow-health: are container errors actually being AI-analyzed? The "AI Error Watch" n8n flow is what fills
// ai_summary/ai_solution. If incidents pile up in 'analyzing' with no summary, that flow isn't running/imported.
$ceStuck = 0;
try { $r = $conn->query("SELECT COUNT(*) c FROM container_incidents WHERE status='analyzing' AND (ai_summary IS NULL OR ai_summary='') AND first_seen < (NOW() - INTERVAL 15 MINUTE)"); $ceStuck = $r ? (int)$r->fetch_row()[0] : 0; } catch (\Throwable $e) {}
// An analyzer is available if EITHER the dedicated `container-analyze` flow OR the general `log-rca`
// flow is live — the AI Insight now reuses whichever is up (nm_erroranalyze.php), synchronously.
require_once __DIR__ . '/nm_erroranalyze.php';
$ceHasAnalyze = function_exists('nm_erroranalyze_pick_flow') && nm_erroranalyze_pick_flow($conn) !== '';
$aiOn = cset_get($conn,'error_watch_ai','1') !== '0';   // master AI switch for Error Watch
// Only nag about a missing/stuck AI flow when AI is actually turned ON. With AI OFF this is a plain
// error desk and nothing is "stuck".
$ceShowBanner = $aiOn && (($ceStuck > 0) || (!$ceHasAnalyze && $summary['active'] > 0));
$remediateEnabled = cset_get($conn,'error_watch_remediation_url','') !== '';
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
log_user_action($conn, 'view_page', 'container_errors.php');
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><title>Container Errors | SG-PR Console</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --docker:#0db7ed;
       --crit:#e74c3c; --warn:#f39c12; --ok:#2ecc71; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.25; }
.wrap{ max-width:1200px; margin:0 auto; padding:18px 20px 60px; } a{ color:var(--accent); text-decoration:none; }
.ctr-head{ display:flex; align-items:center; gap:14px; flex-wrap:wrap; margin-bottom:14px; }
.ctr-head h1{ margin:0; font-size:22px; font-weight:700; } .ctr-head h1 i{ color:var(--docker); }
.ctr-subnav{ display:flex; gap:4px; flex-wrap:wrap; margin-bottom:16px; border-bottom:1px solid var(--border); }
.ctr-subtab{ padding:8px 14px; font-size:13px; color:#9aa; border-bottom:2px solid transparent; display:inline-flex; gap:7px; align-items:center; }
.ctr-subtab:hover{ color:#fff; } .ctr-subtab.is-active{ color:var(--docker); border-bottom-color:var(--docker); font-weight:600; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.stat-grid{ display:grid; grid-template-columns:repeat(auto-fit,minmax(110px,1fr)); gap:12px; margin-bottom:16px; }
.stat{ padding:12px 16px; } .stat .n{ font-size:23px; font-weight:800; } .stat .l{ font-size:10px; text-transform:uppercase; letter-spacing:1px; color:#888; margin-top:3px; }
.stat .n.warn{ color:var(--warn);} .stat .n.crit{ color:var(--crit);} .stat .n.ok{ color:var(--ok);}
.filters{ display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:14px; }
select,input[type=text],input[type=date]{ background:rgba(0,0,0,.4); border:1px solid var(--border); color:#ddd; border-radius:8px; padding:7px 10px; font-size:12px; outline:none; }
input[type=text]{ flex:1; min-width:160px; }
.fbtn{ background:rgba(255,255,255,.05); border:1px solid var(--border); color:#aaa; padding:6px 12px; border-radius:7px; cursor:pointer; font-size:12px; font-weight:600; }
.fbtn.active,.fbtn:hover{ background:rgba(77,163,255,.2); color:var(--accent); border-color:var(--accent); }
.inc{ background:rgba(255,255,255,.05); backdrop-filter:blur(16px); border:1px solid var(--border); border-left:4px solid var(--warn); border-radius:12px; margin-bottom:12px; overflow:hidden; transition:border-color .15s, background .15s; }
.inc:hover{ background:rgba(255,255,255,.07); border-top-color:rgba(255,255,255,.22); border-right-color:rgba(255,255,255,.22); border-bottom-color:rgba(255,255,255,.22); }
.inc.sev-crit,.inc.sev-critical,.inc.sev-fatal{ border-left-color:var(--crit); }
.inc[open]{ background:rgba(255,255,255,.06); border-top-color:rgba(255,255,255,.2); border-right-color:rgba(255,255,255,.2); border-bottom-color:rgba(255,255,255,.2); }
.inc summary{ list-style:none; cursor:pointer; padding:13px 16px; display:flex; gap:12px; align-items:center; }
.inc summary:hover{ background:rgba(255,255,255,.03); }
.inc[open] summary{ border-bottom:1px solid rgba(255,255,255,.08); }
.inc summary::-webkit-details-marker{ display:none; }
.sevb{ font-size:9.5px; font-weight:700; padding:2px 8px; border-radius:5px; text-transform:uppercase; white-space:nowrap; }
.sevb.crit{ background:rgba(231,76,60,.18); color:var(--crit);} .sevb.warn{ background:rgba(243,156,18,.18); color:var(--warn);} .sevb.info{ background:rgba(77,163,255,.16); color:var(--accent);}
.statusb{ font-size:9px; font-weight:700; padding:2px 7px; border-radius:5px; text-transform:uppercase; }
.s-analyzing{ background:rgba(155,89,182,.18); color:#c08fd6;} .s-open{ background:rgba(231,76,60,.14); color:#e74c3c;} .s-acknowledged{ background:rgba(243,156,18,.16); color:var(--warn);} .s-resolved{ background:rgba(46,204,113,.16); color:var(--ok);} .s-ignored{ background:rgba(255,255,255,.07); color:#888;}
.inc .title{ font-weight:600; flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.inc .meta{ font-size:11px; color:#7c828c; white-space:nowrap; }
.inc-body{ padding:0 16px 16px; }
.errbox{ background:rgba(231,76,60,.07); border:1px solid rgba(231,76,60,.2); border-radius:8px; padding:10px 12px; font-family:Consolas,monospace; font-size:11.5px; color:#e9b5b0; white-space:pre-wrap; word-break:break-word; max-height:180px; overflow:auto; }
.aibox{ background:rgba(155,89,182,.07); border:1px solid rgba(155,89,182,.22); border-radius:8px; padding:10px 12px; margin-top:10px; font-size:13px; line-height:1.55; color:#dcd; white-space:pre-wrap; }
.aibox b{ color:#c08fd6; }
.acts{ display:flex; gap:7px; flex-wrap:wrap; margin-top:12px; }
.act{ background:rgba(255,255,255,.05); border:1px solid var(--border); color:#bbb; padding:5px 11px; border-radius:7px; cursor:pointer; font-size:11px; display:inline-flex; gap:6px; align-items:center; }
.act:hover{ background:rgba(255,255,255,.12); color:#fff; } .act.ok:hover{ border-color:var(--ok); color:var(--ok);} .act.warn:hover{ border-color:var(--warn); color:var(--warn);} .act.heal:hover{ border-color:#9b59b6; color:#c08fd6;}
.empty{ text-align:center; color:#667; padding:50px 20px; } .empty i{ font-size:40px; color:#2ecc71; display:block; margin-bottom:12px; }
.spin{ width:15px; height:15px; border:2px solid rgba(255,255,255,.2); border-top-color:var(--accent); border-radius:50%; display:inline-block; animation:sp .7s linear infinite; } @keyframes sp{ to{ transform:rotate(360deg);} }
.selbox{ width:16px; height:16px; accent-color:var(--accent); cursor:pointer; flex:0 0 auto; }
#bulkbar{ display:none; align-items:center; gap:12px; flex-wrap:wrap; padding:10px 14px; margin-bottom:12px; }
#bulkbar .selall{ display:flex; align-items:center; gap:8px; font-size:12.5px; color:#cdd3db; cursor:pointer; user-select:none; }
#bulkbar .selall input{ width:16px; height:16px; accent-color:var(--accent); cursor:pointer; }
#bulkbar .selcount{ font-size:12px; color:#8a93a0; }
#bulkbar .bulk-act[disabled]{ opacity:.4; pointer-events:none; }
#bulkNote{ min-width:150px; max-width:240px; }
#nm-toast{ position:fixed; right:20px; bottom:20px; z-index:9999; display:flex; flex-direction:column; gap:8px; pointer-events:none; }
.nm-toast{ background:rgba(20,28,44,.96); border:1px solid var(--border); border-left:3px solid var(--ok); color:#e6ecf7; padding:11px 15px; border-radius:10px; font-size:13px; box-shadow:0 8px 30px rgba(0,0,0,.5); max-width:340px; opacity:0; transform:translateY(8px); transition:opacity .25s, transform .25s; }
.nm-toast.show{ opacity:1; transform:none; } .nm-toast.err{ border-left-color:var(--crit); }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
    <?php nm_page_header('Containers', '', 'Error Watch', 'fa-brands fa-docker',
        '<label style="display:flex;gap:7px;align-items:center;font-size:12px;color:#aaa;cursor:pointer;" title="Master switch for AI analysis of container errors. OFF = a plain error desk (no AI flow / no billing); new errors show as Open instead of Analyzing."><input type="checkbox" id="aiSw" '.($aiOn?'checked':'').' onchange="toggleAi(this.checked)"> <i class="fas fa-wand-magic-sparkles" style="color:'.($aiOn?'#b06bff':'#667').'"></i> AI analysis</label>'
        .'<label style="display:flex;gap:7px;align-items:center;font-size:12px;color:#aaa;cursor:pointer;"><input type="checkbox" id="auto" checked> Auto-refresh</label>'); ?>
    <?php nm_container_tabs('errors'); ?>

    <?php if ($ceShowBanner): ?>
    <div class="glass" style="border-left:4px solid var(--warn);padding:14px 16px;margin-bottom:16px;">
        <div style="font-weight:700;color:var(--warn);margin-bottom:4px"><i class="fas fa-triangle-exclamation"></i> Container errors aren't being AI-analyzed</div>
        <div style="font-size:12.5px;color:#c3c9d2;line-height:1.6">
            Errors are being collected<?php if ($ceStuck>0): ?>, but <b><?= (int)$ceStuck ?></b> incident<?= $ceStuck==1?'':'s' ?> <?= $ceStuck==1?'has':'have' ?> been stuck in <b>Analyzing</b> with no AI summary for 15&nbsp;min+<?php endif; ?> — the analysis flow isn't producing results in your n8n. Import &amp; <b>activate</b> these flows (from <b>NEURU&nbsp;Portal → n8n&nbsp;Flows</b>):
            <ul style="margin:6px 0 2px 18px;padding:0">
                <li><b>AI Error Watch</b> — detects errors &amp; writes the AI summary/solution <i>(the missing piece)</i></li>
                <li><b>Container Log Collector</b> — feeds container logs into the watch</li>
                <li><b>AI Error Remediation</b> — powers the <b>Remediate</b> button</li>
            </ul>
            <?php if (!$ceHasAnalyze): ?><div style="margin-top:4px">For the instant <b>Re-analyze</b> button, also add &amp; enable an n8n webhook slug <code>container-analyze</code> under <a href="net_mon_config.php">Config → Integrations &amp; AI</a>.</div><?php endif; ?>
        </div>
    </div>
    <?php endif; ?>

    <div class="stat-grid">
        <div class="glass stat"><div class="n crit" data-k="active"><?= $summary['active'] ?></div><div class="l">Active</div></div>
        <div class="glass stat"><div class="n" data-k="analyzing" style="color:#c08fd6"><?= $summary['analyzing'] ?></div><div class="l">Analyzing</div></div>
        <div class="glass stat"><div class="n" data-k="open"><?= $summary['open'] ?></div><div class="l">Open</div></div>
        <div class="glass stat"><div class="n warn" data-k="acknowledged"><?= $summary['acknowledged'] ?></div><div class="l">Acknowledged</div></div>
        <div class="glass stat"><div class="n ok" data-k="resolved"><?= $summary['resolved'] ?></div><div class="l">Resolved</div></div>
        <div class="glass stat"><div class="n" data-k="ignored" style="color:#888"><?= $summary['ignored'] ?></div><div class="l">Ignored</div></div>
    </div>

    <div class="filters">
        <?php foreach (['active'=>'Active','analyzing'=>'Analyzing','open'=>'Open','acknowledged'=>'Ack','resolved'=>'Resolved','ignored'=>'Ignored','all'=>'All'] as $v=>$l): ?>
        <button class="fbtn <?= $v==='active'?'active':'' ?>" data-status="<?= $v ?>" onclick="setStatus(this,'<?= $v ?>')"><?= $l ?></button>
        <?php endforeach; ?>
        <select id="sev" onchange="load()"><option value="">Any severity</option><option>CRITICAL</option><option>ERROR</option><option>WARNING</option></select>
        <input type="text" id="q" placeholder="Search error / container / host…" onkeydown="if(event.key==='Enter')load()">
        <button class="fbtn" onclick="load()"><i class="fas fa-rotate"></i></button>
    </div>

    <div id="bulkbar" class="glass">
        <label class="selall"><input type="checkbox" id="selAll" onclick="toggleAll(this.checked)"> Select all (<span id="selAllCount">0</span>)</label>
        <span class="selcount" id="selCount">0 selected</span>
        <span style="flex:1"></span>
        <input type="text" id="bulkNote" placeholder="Note for resolve/ignore (optional)…">
        <label class="selall" title="Snapshot each resolved incident into the AI Knowledge Base. Turn off if these resolutions aren't worth saving."><input type="checkbox" id="bulkKb" checked> <i class="fas fa-brain" style="color:#c08fd6"></i> Save to KB</label>
        <button class="act warn bulk-act" onclick="bulk('acknowledge')" disabled><i class="fas fa-eye"></i> Acknowledge</button>
        <button class="act ok bulk-act" onclick="bulk('resolve')" disabled><i class="fas fa-check"></i> Resolve</button>
        <button class="act bulk-act" onclick="bulk('ignore')" disabled><i class="fas fa-ban"></i> Ignore</button>
        <button class="act bulk-act" onclick="clearSel()" disabled><i class="fas fa-xmark"></i> Clear</button>
    </div>

    <div id="list"><div class="empty"><span class="spin"></span></div></div>
</div>

<script>
const REMEDIATE=<?= $remediateEnabled?'true':'false' ?>;
const AI_ON=<?= $aiOn?'true':'false' ?>;
async function toggleAi(on){
  try{ const r=await fetch('container_errors.php?api=ai_toggle',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'on='+(on?1:0)}).then(x=>x.json());
    if(r.ok){ if(!on && r.freed>0) alert('AI turned off. '+r.freed+' incident(s) unstuck from Analyzing → Open.'); location.reload(); }
  }catch(e){ alert('Could not change the AI setting.'); }
}
let fStatus='active', autoTimer=null;
const selIds=new Set();   // survives the 12s auto-refresh (module-scoped)
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function toggleSel(id,checked){ if(checked) selIds.add(String(id)); else selIds.delete(String(id)); updateBulkBar(); }
function toggleAll(checked){ const I=window.__ALL_INC||[]; if(checked) I.forEach(x=>selIds.add(String(x.id))); else selIds.clear(); renderPage(); }
function clearSel(){ selIds.clear(); renderPage(); }
function updateBulkBar(){
    const I=window.__ALL_INC||[]; const bar=document.getElementById('bulkbar'); if(!bar) return;
    const idset=new Set(I.map(x=>String(x.id)));
    [...selIds].forEach(id=>{ if(!idset.has(id)) selIds.delete(id); });   // prune ids no longer in the result set
    if(!I.length){ bar.style.display='none'; return; }
    bar.style.display='flex';
    const n=selIds.size;
    document.getElementById('selCount').textContent = n+' selected';
    document.getElementById('selAllCount').textContent = I.length;
    const sa=document.getElementById('selAll'); sa.checked = n>0 && n===I.length; sa.indeterminate = n>0 && n<I.length;
    bar.querySelectorAll('.bulk-act').forEach(b=>{ b.disabled = n===0; });
}
function toast(msg,isErr){
    let box=document.getElementById('nm-toast'); if(!box){ box=document.createElement('div'); box.id='nm-toast'; document.body.appendChild(box); }
    const t=document.createElement('div'); t.className='nm-toast'+(isErr?' err':''); t.textContent=msg; box.appendChild(t);
    requestAnimationFrame(()=>t.classList.add('show'));
    setTimeout(()=>{ t.classList.remove('show'); setTimeout(()=>t.remove(),300); }, 4200);
}
// Dialog-free bulk: selecting + clicking the action IS the confirmation (all actions are reversible via
// Reopen). No native confirm/prompt/alert — those silently no-op if the browser has "block dialogs" on.
async function bulk(action){
    const ids=[...selIds]; if(!ids.length){ toast('Select at least one incident first.',true); return; }
    const note=(document.getElementById('bulkNote')?.value||'').trim();
    const kb=document.getElementById('bulkKb')?.checked ? 1 : 0;
    let r; try{ r=await fetch('container_errors.php?api=bulk',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids,action,note,kb})}).then(x=>x.json()); }catch(e){ r={ok:false,error:'network/parse error'}; }
    if(!r||!r.ok){ toast('Bulk action failed: '+((r&&r.error)||'unknown'),true); return; }
    selIds.clear(); const nEl=document.getElementById('bulkNote'); if(nEl) nEl.value='';
    const verb={acknowledge:'acknowledged',resolve:'resolved',ignore:'ignored',reopen:'reopened'}[action]||action;
    let msg='✅ '+r.done+' incident(s) '+verb+'.'; if(r.kb_saved) msg+=' '+r.kb_saved+' saved to Knowledge Base.';
    if(action==='acknowledge' && (fStatus==='active'||fStatus==='acknowledged'||fStatus==='all')) msg+=' (still shown — acknowledged is an active state)';
    toast(msg); load();
}
function sevCls(s){ s=(s||'').toLowerCase(); if(/crit|fatal/.test(s))return'crit'; if(/warn/.test(s))return'warn'; if(/info|notice/.test(s))return'info'; return'crit'; }
function setStatus(b,v){ fStatus=v; document.querySelectorAll('.fbtn[data-status]').forEach(x=>x.classList.toggle('active',x===b)); load(); }
document.getElementById('auto').addEventListener('change',e=>{ if(e.target.checked){autoTimer=setInterval(load,12000);}else{clearInterval(autoTimer);} });
const openIds=new Set();
// Deep-link from the dashboard alert: ?focus=<incident id> opens, scrolls to,
// and highlights that one incident.
let FOCUS_ID=new URLSearchParams(location.search).get('focus');
if(FOCUS_ID) openIds.add(String(FOCUS_ID));

async function load(){
    const sev=document.getElementById('sev').value, q=encodeURIComponent(document.getElementById('q').value.trim());
    document.querySelectorAll('.inc[open]').forEach(d=>openIds.add(d.dataset.id));
    try{ const r=await fetch(`container_errors.php?api=data&status=${fStatus}&severity=${sev}&q=${q}&_=${Date.now()}`).then(r=>r.json());
        if(!r.ok) return;
        const s=r.summary; document.querySelectorAll('.stat .n[data-k]').forEach(el=>el.textContent=s[el.dataset.k]??0);
        const box=document.getElementById('list'); const I=r.incidents||[];
        if(!I.length){ box.innerHTML='<div class="empty"><i class="fas fa-circle-check"></i><div style="font-size:15px;color:#aaa;">No incidents.</div></div>'; window.__ALL_INC=[]; updateBulkBar(); return; }
        window.__ALL_INC=I; renderPage();
    }catch(e){}
}
let PAGE=0; const PER=10;
function renderPage(){
    const box=document.getElementById('list'); const I=window.__ALL_INC||[];
    const pages=Math.max(1,Math.ceil(I.length/PER));
    if(FOCUS_ID){ const idx=I.findIndex(x=>String(x.id)===String(FOCUS_ID)); if(idx>=0) PAGE=Math.floor(idx/PER); }
    if(PAGE>=pages) PAGE=pages-1; if(PAGE<0) PAGE=0;
    const slice=I.slice(PAGE*PER,PAGE*PER+PER);
    let html=slice.map(card).join('');
    if(pages>1){ html+=`<div class="pager" style="display:flex;align-items:center;justify-content:center;gap:12px;padding:14px;color:#9aa3af;font-size:13px;">
        <button class="fbtn" onclick="pg(-1)" ${PAGE===0?'disabled style=\"opacity:.4\"':''}><i class="fas fa-chevron-left"></i> Prev</button>
        <span>Page <b style="color:#e6e9ee">${PAGE+1}</b> / ${pages} · ${I.length} incidents</span>
        <button class="fbtn" onclick="pg(1)" ${PAGE>=pages-1?'disabled style=\"opacity:.4\"':''}>Next <i class="fas fa-chevron-right"></i></button></div>`; }
    box.innerHTML=html;
    if(FOCUS_ID){ const el=box.querySelector(`.inc[data-id="${FOCUS_ID}"]`);
        if(el){ el.setAttribute('open',''); el.scrollIntoView({behavior:'smooth',block:'center'});
            el.style.transition='box-shadow .3s'; el.style.boxShadow='0 0 0 2px #4da3ff'; setTimeout(()=>{ el.style.boxShadow=''; },2600); }
        FOCUS_ID=null; }
    updateBulkBar();
}
function pg(d){ PAGE+=d; renderPage(); document.getElementById('list').scrollIntoView({behavior:'smooth',block:'start'}); }
function card(i){
    const sv=sevCls(i.severity), open=openIds.has(String(i.id))?'open':'';
    const rem = i.remediation_status&&i.remediation_status!=='none' ? `<span class="statusb s-acknowledged">remediation: ${esc(i.remediation_status)}</span>` : '';
    return `<details class="inc sev-${sv}" data-id="${i.id}" ${open}>
        <summary>
            <input type="checkbox" class="selbox" data-id="${i.id}" onclick="event.stopPropagation();toggleSel('${i.id}',this.checked)" ${selIds.has(String(i.id))?'checked':''} title="Select">
            <span class="sevb ${sv}">${esc(i.severity)}</span>
            <span class="title">${esc(i.container_name||'—')}: ${esc((i.error_text||'').slice(0,140))}</span>
            <span class="statusb s-${esc(i.status)}">${esc(i.status)}</span>
            <span class="meta" title="Docker host / server"><i class="fas fa-server" style="color:#4da3ff;"></i> ${esc(i.server||i.host||'?')}</span>
            ${i.node?`<span class="meta" title="Monitored NEURU node"><i class="fas fa-network-wired" style="color:#2ecc71;"></i> ${esc(i.node)}</span>`:''}
            ${i.occurrences>1?`<span class="meta">×${i.occurrences}</span>`:''}
            <span class="meta">${esc((window.nmLocal?nmLocal(i.last_seen):(i.last_seen||'')).slice(5,16))}</span>
        </summary>
        <div class="inc-body">
            <div class="meta" style="margin:0 0 8px;color:#9fb0c4;"><i class="fas fa-server" style="color:#4da3ff;"></i> <b>${esc(i.server||i.host||'unknown host')}</b>${i.host_ip?' · '+esc(i.host_ip):' · <span style=\"color:#e08a3a;\">no SSH target</span>'}${i.node?` · <a href="router_details.php?node=${i.node_id}" style="color:#2ecc71;text-decoration:none;" title="Open device details"><i class="fas fa-network-wired"></i> ${esc(i.node)}</a>`:''} · <span style="color:#778;">${esc(i.container_id||'').slice(0,12)}</span> ${rem}</div>
            <div class="errbox">${esc(i.error_text)}</div>
            ${i.ai_summary||i.ai_solution ? `<div class="aibox"><b><i class="fas fa-wand-magic-sparkles"></i> AI analysis</b>
                ${i.ai_summary?`<div style="margin-top:6px;">${esc(i.ai_summary)}</div>`:''}
                ${i.ai_solution?`<div style="margin-top:8px;border-top:1px dashed rgba(255,255,255,.12);padding-top:8px;"><b style="color:#2ecc71">Fix:</b>\n${esc(i.ai_solution)}</div>`:''}</div>`
              : (AI_ON && i.status==='analyzing'?'<div class="aibox" style="color:#c08fd6"><span class="spin" style="width:12px;height:12px;"></span> Awaiting AI analysis…</div>':'')}
            <div class="acts">
                ${i.status!=='acknowledged'&&i.status!=='resolved'?`<button class="act warn" onclick="upd(${i.id},'acknowledge')"><i class="fas fa-eye"></i> Acknowledge</button>`:''}
                ${AI_ON?`<button class="act" onclick="upd(${i.id},'reanalyze')"><i class="fas fa-rotate"></i> Reanalyze</button>`:''}
                ${AI_ON&&REMEDIATE?`<button class="act heal" onclick="remediate(${i.id})"><i class="fas fa-screwdriver-wrench"></i> Remediate</button>`:''}
                ${AI_ON?`<a class="act heal" href="container_fix.php?id=${i.id}" title="Solution Commander"><i class="fas fa-wand-magic-sparkles"></i> Fix with AI</a>`:''}
                ${i.status!=='resolved'?`<button class="act ok" onclick="upd(${i.id},'resolve',true)"><i class="fas fa-check"></i> Resolve</button>`:`<button class="act" onclick="upd(${i.id},'reopen')"><i class="fas fa-rotate-left"></i> Reopen</button>`}
                ${i.status!=='ignored'?`<button class="act" onclick="upd(${i.id},'ignore',true)"><i class="fas fa-ban"></i> Ignore</button>`:''}
            </div>
        </div>
    </details>`;
}
async function upd(id,action,askNote){
    let note=''; if(askNote){ note=prompt(action==='resolve'?'Resolution note (optional):':'Reason (optional):')||''; }
    const r=await fetch('container_errors.php?api=update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,action,note})}).then(r=>r.json()).catch(()=>({ok:false}));
    if(!r||!r.ok){ alert('Action failed: '+((r&&r.error)||'unknown')); }
    else if(action==='reanalyze'){ alert((r.pushed?'✅ ':'⚠️ ')+(r.message||'Re-analysis requested')); }
    else if(r.message){ alert(r.message); }
    load();
}
async function remediate(id){
    if(!confirm('Hand this incident to the n8n remediation flow?')) return;
    const r=await fetch('container_errors.php?api=remediate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}).then(r=>r.json()).catch(()=>({ok:false}));
    alert(r.ok?(r.message||'Requested'):('Failed: '+(r.error||'unknown'))); load();
}
load(); autoTimer=setInterval(load,12000);
</script>
</body></html>
