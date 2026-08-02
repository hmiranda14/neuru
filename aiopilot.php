<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — AI Command Center ("NetAIObot"). Fullscreen, particle-backed autonomous
// agent console: an animated bot you watch Observe→Think→Act on SELECTED devices,
// live transcript, data flowing in/out, and Approve/Deny for gated actions.
// Engine: nm_aiopilot.php.  Perm: 'aiopilot'.
// ─────────────────────────────────────────────────────────────────────────────
include('check.php');
include('connection.php');   // applies the configured display tz (UTC storage) via nm_tz_apply
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_aiopilot.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'aiopilot')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=aiopilot'); exit;
}
nm_aip_ensure($conn);
$uid = (int)($_SESSION['user_id'] ?? 0);
// Release the session lock before any external I/O (Telegram getUpdates in the feed, SSH on
// approve) so a slow round-trip can't freeze this user's other tabs. Only $_SESSION reads above.
if (function_exists('session_write_close')) @session_write_close();

// ── JSON API ────────────────────────────────────────────────────────────────
if ($api) {
    header('Content-Type: application/json; charset=utf-8');

    if ($api === 'devices') {
        $sel = nm_aip_devices($conn);
        $all = [];
        $r = $conn->query("SELECT id,display_name,ip_address,os_icon FROM nm_nodes ORDER BY display_name");
        while ($r && $x = $r->fetch_assoc()) $all[] = $x;
        $tgReady = function_exists('nm_aip_tg_channel') ? (nm_aip_tg_channel($conn) !== null) : false;
        echo json_encode(['ok'=>true,'selected'=>$sel,'nodes'=>$all,'tg_ready'=>$tgReady]); exit;
    }

    if ($api === 'set_device') {
        $nid = (int)($_POST['node_id'] ?? 0);
        if ($nid <= 0) { echo json_encode(['ok'=>false,'error'=>'bad node']); exit; }
        echo json_encode(nm_aip_device_set($conn, $nid,
            (string)($_POST['mode'] ?? 'observe'),
            (int)($_POST['enabled'] ?? 1),
            (int)($_POST['destructive'] ?? 0), $uid,
            (int)($_POST['commands'] ?? 0),
            (int)($_POST['telegram'] ?? 0))); exit;
    }
    if ($api === 'remove_device') {
        echo json_encode(nm_aip_device_remove($conn, (int)($_POST['node_id'] ?? 0))); exit;
    }

    if ($api === 'master') {   // master kill switch (on/off)
        if ($_SERVER['REQUEST_METHOD'] === 'POST')
            nm_aip_set_enabled($conn, (string)($_POST['on'] ?? '1') === '1', $uid);
        echo json_encode(['ok'=>true,'enabled'=>nm_aip_enabled($conn)]); exit;
    }

    if ($api === 'run') {   // manual "Run now" → start a session + dispatch (one device)
        if (!nm_aip_enabled($conn)) { echo json_encode(['ok'=>false,'error'=>'AI Copilot is OFF — flip the master switch on first.']); exit; }
        $nid = (int)($_POST['node_id'] ?? 0);
        $dev = nm_aip_device($conn, $nid);
        if (!$dev || !$dev['enabled']) { echo json_encode(['ok'=>false,'error'=>'device not enabled']); exit; }
        $name = $conn->query("SELECT display_name FROM nm_nodes WHERE id=$nid")->fetch_assoc()['display_name'] ?? "node $nid";
        $sid = nm_aip_session_start($conn, $nid, 'manual', "Manual investigation: $name");
        $r = nm_aip_dispatch($conn, $sid, $nid, 'manual');
        echo json_encode(['ok'=>!empty($r['ok']),'session_id'=>$sid,'error'=>$r['error'] ?? null]); exit;
    }

    if ($api === 'scan_all') {   // enqueue ALL enabled devices; the cron pacer dispatches them
        if (!nm_aip_enabled($conn)) { echo json_encode(['ok'=>false,'error'=>'AI Copilot is OFF — flip the master switch on first.']); exit; }
        $n = 0;
        foreach (nm_aip_devices($conn) as $d) {
            if (!empty($d['enabled']) && nm_aip_enqueue($conn, (int)$d['node_id'], 'manual', 'Manual scan: ' . $d['display_name'])) $n++;
        }
        echo json_encode(['ok'=>true,'queued'=>$n]); exit;
    }

    if ($api === 'settings') {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            foreach (['aip_compact','aip_max_concurrent','aip_min_gap_sec','aip_per_run_cap'] as $k)
                if (isset($_POST[$k])) nm_aip_setting_set($conn, $k, (string)$_POST[$k]);
        }
        echo json_encode(['ok'=>true,'settings'=>nm_aip_settings($conn)]); exit;
    }

    if ($api === 'approve' || $api === 'deny') {
        $aid = (int)($_POST['action_id'] ?? 0);
        if ($aid <= 0) { echo json_encode(['ok'=>false,'error'=>'bad action']); exit; }
        if ($api === 'deny') {
            $r = nm_aip_deny_action($conn, $aid, $uid, 'Operator denied in portal — taking manual control.');
            if (!empty($r['ok']) && function_exists('nm_aip_tg_close')) nm_aip_tg_close($conn, $aid, 'denied', '🚫 *Denied in portal*');
            echo json_encode($r); exit;
        }
        $r = nm_aip_execute_action($conn, $aid, $uid, false);
        if (!empty($r['ok']) && function_exists('nm_aip_tg_close')) nm_aip_tg_close($conn, $aid, 'approved', '✅ *Approved &amp; executed in portal*');
        echo json_encode($r); exit;
    }

    if ($api === 'feed') {
        // Drain any Telegram Approve/Deny taps NOW (throttled + single-flight) so a decision made
        // on the phone reflects here within seconds — a lingering card can't be double-actioned.
        if (function_exists('nm_aip_tg_poll_feed')) @nm_aip_tg_poll_feed($conn, 4);
        // Self-heal phantom "active" sessions (dead n8n turns) so the counter reflects reality
        // without waiting for the 2-min cron.
        if (function_exists('nm_aip_reap_stale')) @nm_aip_reap_stale($conn, 8);
        $focus = (int)($_GET['node'] ?? 0);
        $w = $focus ? " AND e.node_id=$focus" : '';
        // events (newest first; the JS reverses for chrono display)
        $ev = $conn->query("SELECT e.id,e.session_id,e.node_id,e.phase,e.title,e.body,e.created_at,n.display_name
                            FROM nm_aip_events e JOIN nm_nodes n ON n.id=e.node_id
                            WHERE 1=1 $w ORDER BY e.id DESC LIMIT 60");
        $events = $ev ? $ev->fetch_all(MYSQLI_ASSOC) : [];
        // pending approvals
        $wf = $focus ? " AND a.node_id=$focus" : '';
        $pa = $conn->query("SELECT a.id,a.node_id,a.tool,a.args,a.risk,a.reason,a.proposed_at,n.display_name
                            FROM nm_aip_actions a JOIN nm_nodes n ON n.id=a.node_id
                            WHERE a.status='proposed' $wf ORDER BY a.id DESC LIMIT 20");
        $pending = $pa ? $pa->fetch_all(MYSQLI_ASSOC) : [];
        // active sessions
        $ws = $focus ? " AND s.node_id=$focus" : '';
        $ss = $conn->query("SELECT s.id,s.node_id,s.status,s.title,s.summary,s.updated_at,n.display_name
                            FROM nm_aip_sessions s JOIN nm_nodes n ON n.id=s.node_id
                            WHERE s.status IN ('active','awaiting_approval') $ws ORDER BY s.updated_at DESC LIMIT 10");
        $sessions = $ss ? $ss->fetch_all(MYSQLI_ASSOC) : [];
        // stats
        $stat = ['active'=>0,'awaiting'=>0,'auto_today'=>0,'actions_today'=>0];
        $q = $conn->query("SELECT status, COUNT(*) c FROM nm_aip_sessions WHERE status IN ('active','awaiting_approval') GROUP BY status");
        while ($q && $x = $q->fetch_assoc()) { if ($x['status']==='active') $stat['active']=(int)$x['c']; else $stat['awaiting']=(int)$x['c']; }
        $q = $conn->query("SELECT COUNT(*) c,SUM(status='done') d FROM nm_aip_actions WHERE DATE(proposed_at)=CURDATE()");
        if ($q && $x=$q->fetch_assoc()) { $stat['actions_today']=(int)$x['c']; $stat['auto_today']=(int)$x['d']; }
        $stat['queued'] = nm_aip_queue_depth($conn);
        // bot state from newest event phase
        $botPhase = $events[0]['phase'] ?? 'idle';
        echo json_encode(['ok'=>true,'enabled'=>nm_aip_enabled($conn),'events'=>$events,'pending'=>$pending,'sessions'=>$sessions,'stats'=>$stat,'bot'=>$botPhase,'ts'=>time()]); exit;
    }

    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
}

log_user_action($conn, 'view_page', 'aiopilot.php');
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetAIObot · AI Command Center | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --accent:#4da3ff; --ai:#9b6bff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --cyan:#22d3ee; --border:rgba(255,255,255,.12); }
*,*::before,*::after{ box-sizing:border-box; }
/* particle recipe: dark on html, transparent body */
html{ background:#05060f; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#e6e9ee; }
.wrap{ max-width:1640px; margin:0 auto; padding:16px 20px 40px; }
.glass{ background:rgba(255,255,255,.05); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.muted{ color:#8a909a; font-size:12px; } .mono{ font-family:monospace; }
.btn{ background:rgba(77,163,255,.14); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:8px 14px; font-size:13px; cursor:pointer; }
.btn:hover{ border-color:var(--accent); color:#fff; }
.btn.ai{ background:rgba(155,107,255,.16); border-color:rgba(155,107,255,.5); color:#d9c8ff; }
.btn.ok{ background:rgba(46,204,113,.16); border-color:rgba(46,204,113,.5); color:#9af3c0; }
.btn.no{ background:rgba(231,76,60,.14); border-color:rgba(231,76,60,.5); color:#ffb3ab; }
.icon-btn{ background:rgba(10,16,28,.72); border:1px solid var(--border); color:#cfe4ff; border-radius:8px; min-width:34px; height:32px; padding:0 9px; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:6px; }
.icon-btn:hover{ border-color:var(--accent); color:#fff; }

/* ── KPI strip ───────────────────────────────────────────────────────────── */
.kpis{ display:flex; gap:12px; flex-wrap:wrap; margin:12px 0 16px; }
.kpi{ padding:10px 18px; text-align:center; } .kpi .n{ font-size:22px; font-weight:800; } .kpi .l{ font-size:10px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; }

/* ── The command stage (fullscreen target) ──────────────────────────────────
   Left: the animated NetAIObot.  Right: live transcript + approvals. */
/* Bot CENTERED on top, actions/logs BELOW (stacked) */
#cc-stage{ display:flex; flex-direction:column; gap:16px; position:relative; }
#cc-fsctrl{ position:absolute; top:10px; right:10px; z-index:8; display:flex; gap:6px; }

/* Bot panel — big, centered, glass; the robot gently floats */
#bot-panel{ position:relative; min-height:48vh; border-radius:18px; overflow:hidden;
  background:radial-gradient(circle at 50% 40%, rgba(155,107,255,.12), transparent 68%);
  display:flex; flex-direction:column; align-items:center; justify-content:center; gap:18px; padding:30px 24px; }
.netbot{ animation:botFloat 7s ease-in-out infinite; }
@keyframes botFloat{ 0%,100%{ transform:translateY(0) } 50%{ transform:translateY(-16px) } }
.bot-name{ position:absolute; top:16px; left:20px; font-weight:800; letter-spacing:1px; font-size:15px; color:#d9c8ff; }
.bot-name i{ color:var(--ai); }
.bot-dev{ position:absolute; top:18px; right:20px; font-size:12px; color:#8a97aa; }

/* ── The robot (pure CSS/SVG) ───────────────────────────────────────────── */
.netbot{ position:relative; width:230px; height:260px; }
.nb-ring{ position:absolute; inset:0; margin:auto; width:230px; height:230px; border-radius:50%;
  border:1.5px dashed rgba(155,107,255,.35); animation:nbspin 14s linear infinite; }
.nb-ring.r2{ width:184px; height:184px; border-color:rgba(77,163,255,.28); animation-duration:9s; animation-direction:reverse; }
.nb-ring.r3{ width:262px; height:262px; border-style:solid; border-color:rgba(155,107,255,.10); animation-duration:24s; }
@keyframes nbspin{ to{ transform:rotate(360deg);} }
.nb-core{ position:absolute; inset:0; margin:auto; width:150px; height:160px; display:flex; flex-direction:column; align-items:center; }
.nb-head{ width:130px; height:104px; border-radius:26px; background:linear-gradient(160deg,#1b2236,#0c1020);
  border:2px solid rgba(155,107,255,.55); box-shadow:0 0 34px rgba(155,107,255,.28), inset 0 0 26px rgba(77,163,255,.12); position:relative; transition:border-color .4s, box-shadow .4s; }
.nb-antenna{ position:absolute; top:-22px; left:50%; transform:translateX(-50%); width:2px; height:20px; background:rgba(155,107,255,.6); }
.nb-antenna::after{ content:''; position:absolute; top:-7px; left:50%; transform:translateX(-50%); width:9px; height:9px; border-radius:50%; background:var(--ai); box-shadow:0 0 12px var(--ai); animation:nbpulse 1.6s ease-in-out infinite; }
@keyframes nbpulse{ 0%,100%{ opacity:.5; transform:translateX(-50%) scale(.85);} 50%{ opacity:1; transform:translateX(-50%) scale(1.25);} }
.nb-eyes{ position:absolute; top:38px; left:0; right:0; display:flex; justify-content:center; gap:26px; }
.nb-eye{ width:26px; height:14px; border-radius:8px; background:var(--cyan); box-shadow:0 0 16px var(--cyan); animation:nbscan 3.2s ease-in-out infinite; }
@keyframes nbscan{ 0%,100%{ transform:translateX(-6px) scaleY(1);} 45%{ transform:translateX(6px) scaleY(1);} 50%{ transform:translateX(6px) scaleY(.15);} 52%{ transform:translateX(6px) scaleY(1);} }
.nb-mouth{ position:absolute; bottom:16px; left:50%; transform:translateX(-50%); display:flex; gap:3px; align-items:flex-end; height:14px; }
.nb-mouth i{ width:4px; height:6px; background:rgba(155,107,255,.7); border-radius:2px; animation:nbeq 1s ease-in-out infinite; }
.nb-mouth i:nth-child(2){ animation-delay:.12s } .nb-mouth i:nth-child(3){ animation-delay:.24s } .nb-mouth i:nth-child(4){ animation-delay:.36s } .nb-mouth i:nth-child(5){ animation-delay:.48s }
@keyframes nbeq{ 0%,100%{ height:4px } 50%{ height:13px } }
.nb-reactor{ margin-top:8px; width:30px; height:30px; border-radius:50%; background:radial-gradient(circle,#fff,var(--ai) 60%,transparent);
  box-shadow:0 0 26px var(--ai); animation:nbreact 2.2s ease-in-out infinite; }
@keyframes nbreact{ 0%,100%{ transform:scale(.86); opacity:.8 } 50%{ transform:scale(1.08); opacity:1 } }

/* state tints (toggled on #bot-panel) */
#bot-panel.s-think .nb-head{ border-color:rgba(155,107,255,.95); box-shadow:0 0 50px rgba(155,107,255,.55), inset 0 0 30px rgba(155,107,255,.25); }
#bot-panel.s-observe .nb-eye{ background:var(--cyan); box-shadow:0 0 22px var(--cyan); }
#bot-panel.s-act .nb-head{ border-color:rgba(243,156,18,.95); box-shadow:0 0 50px rgba(243,156,18,.5); }
#bot-panel.s-act .nb-reactor{ background:radial-gradient(circle,#fff,var(--warn) 60%,transparent); box-shadow:0 0 30px var(--warn); }
#bot-panel.s-result .nb-head{ border-color:rgba(46,204,113,.95); box-shadow:0 0 50px rgba(46,204,113,.5); }
#bot-panel.s-error .nb-head{ border-color:rgba(231,76,60,.95); box-shadow:0 0 50px rgba(231,76,60,.55); }

/* status chip + scrolling "thought" ticker */
.bot-status{ display:inline-flex; align-items:center; gap:9px; padding:7px 16px; border-radius:30px; font-weight:700; font-size:13px; letter-spacing:.5px;
  background:rgba(155,107,255,.14); border:1px solid rgba(155,107,255,.4); color:#d9c8ff; }
.bot-status .dot{ width:9px; height:9px; border-radius:50%; background:var(--ai); box-shadow:0 0 10px var(--ai); animation:nbpulse 1.4s infinite; }
.bot-think{ max-width:90%; text-align:center; color:#b9c2d4; font-size:13px; min-height:38px; line-height:1.5; }

/* data streams (in/out) */
.stream{ position:absolute; top:0; bottom:0; width:120px; pointer-events:none; opacity:.7; }
.stream.in{ left:0; } .stream.out{ right:0; }
.stream span{ position:absolute; width:6px; height:6px; border-radius:50%; }
.stream.in span{ background:var(--cyan); box-shadow:0 0 8px var(--cyan); animation:flowIn 2.6s linear infinite; }
.stream.out span{ background:var(--warn); box-shadow:0 0 8px var(--warn); animation:flowOut 2.6s linear infinite; }
@keyframes flowIn{ 0%{ left:-8px; opacity:0 } 10%{opacity:1} 90%{opacity:1} 100%{ left:118px; opacity:0 } }
@keyframes flowOut{ 0%{ right:-8px; opacity:0 } 10%{opacity:1} 90%{opacity:1} 100%{ right:118px; opacity:0 } }

/* ── extra futuristic FX ─────────────────────────────────────────────────── */
/* holographic grid floor + aura behind the bot */
.holo-grid{ position:absolute; left:0; right:0; bottom:0; height:42%; pointer-events:none; opacity:.5;
  background:
    linear-gradient(rgba(155,107,255,.10) 1px, transparent 1px) 0 0/100% 26px,
    linear-gradient(90deg, rgba(77,163,255,.08) 1px, transparent 1px) 0 0/26px 100%;
  transform:perspective(420px) rotateX(64deg); transform-origin:bottom; mask-image:linear-gradient(to top, #000, transparent); }
.bot-aura{ position:absolute; width:300px; height:300px; border-radius:50%; filter:blur(40px); opacity:.35;
  background:radial-gradient(circle, var(--ai), transparent 65%); animation:auraPulse 4s ease-in-out infinite; transition:background .5s; }
@keyframes auraPulse{ 0%,100%{ transform:scale(.9); opacity:.28 } 50%{ transform:scale(1.12); opacity:.45 } }
/* radar sweep ring (shows when observing) */
.nb-radar{ position:absolute; inset:0; margin:auto; width:262px; height:262px; border-radius:50%; opacity:0; transition:opacity .4s;
  background:conic-gradient(from 0deg, rgba(34,211,238,.30), transparent 22%); animation:nbspin 2.4s linear infinite; mask:radial-gradient(circle, transparent 52%, #000 53%); }
#bot-panel.s-observe .nb-radar{ opacity:.9; }
/* scanline sweeping the head while thinking */
.nb-scan{ position:absolute; top:0; left:8%; right:8%; height:2px; border-radius:2px; opacity:0;
  background:linear-gradient(90deg, transparent, var(--cyan), transparent); box-shadow:0 0 10px var(--cyan); }
#bot-panel.s-think .nb-scan, #bot-panel.s-observe .nb-scan{ opacity:1; animation:scanline 1.8s ease-in-out infinite; }
@keyframes scanline{ 0%{ top:6% } 50%{ top:86% } 100%{ top:6% } }
/* rising data bits */
.bits{ position:absolute; inset:0; pointer-events:none; overflow:hidden; }
.bits b{ position:absolute; bottom:-14px; font-family:monospace; font-size:11px; color:rgba(155,107,255,.55); animation:rise linear infinite; }
@keyframes rise{ 0%{ transform:translateY(0); opacity:0 } 12%{opacity:.8} 88%{opacity:.8} 100%{ transform:translateY(-340px); opacity:0 } }
/* typing indicator + caret */
.typing{ display:inline-flex; gap:4px; height:14px; align-items:center; margin-left:6px; vertical-align:middle; }
.typing i{ width:5px; height:5px; border-radius:50%; background:var(--ai); animation:nbeq 1s ease-in-out infinite; }
.typing i:nth-child(2){ animation-delay:.15s } .typing i:nth-child(3){ animation-delay:.3s }
.caret{ display:inline-block; width:7px; margin-left:1px; color:var(--cyan); animation:blinkc .9s step-end infinite; }
@keyframes blinkc{ 50%{ opacity:0 } }
/* aura tint per state */
#bot-panel.s-observe .bot-aura{ background:radial-gradient(circle, var(--cyan), transparent 65%); }
#bot-panel.s-act .bot-aura{ background:radial-gradient(circle, var(--warn), transparent 65%); }
#bot-panel.s-result .bot-aura{ background:radial-gradient(circle, var(--ok), transparent 65%); }
#bot-panel.s-error .bot-aura{ background:radial-gradient(circle, var(--crit), transparent 65%); }
/* new transcript rows fade/slide in */
@keyframes evIn{ from{ opacity:0; transform:translateX(10px) } to{ opacity:1; transform:none } }
.ev.fresh{ animation:evIn .35s ease; }

/* actions / logs row — sits BELOW the bot. approvals (left) + transcript (right) */
#cc-right{ display:grid; grid-template-columns:1fr 1.6fr; gap:14px; align-items:start; }
@media(max-width:980px){ #cc-right{ grid-template-columns:1fr; } }
#cc-right.no-ap{ grid-template-columns:1fr; }   /* full-width transcript when nothing pending */
.panel{ padding:14px 16px; } .panel h3{ margin:0 0 10px; font-size:12px; color:var(--accent); text-transform:uppercase; letter-spacing:1px; display:flex; align-items:center; gap:8px; }
#approvals .ap{ border:1px solid rgba(243,156,18,.4); background:rgba(243,156,18,.07); border-radius:10px; padding:11px 13px; margin-bottom:10px; }
#approvals .ap .t{ font-weight:700; color:#ffd089; } #approvals .ap .r{ font-size:12px; color:#cdd; margin:5px 0 9px; }
.risk{ font-size:10px; font-weight:700; padding:1px 8px; border-radius:20px; margin-left:6px; }
.risk.low{ background:rgba(46,204,113,.18); color:#8af0b4 } .risk.medium{ background:rgba(243,156,18,.18); color:#f3c879 } .risk.high{ background:rgba(231,76,60,.2); color:#ff9c91 }
#log{ flex:1; overflow:auto; max-height:42vh; display:flex; flex-direction:column; gap:7px; }
.ev{ border-left:3px solid #444; padding:7px 11px; border-radius:0 8px 8px 0; background:rgba(255,255,255,.03); }
.ev .h{ font-size:12px; font-weight:700; display:flex; gap:8px; align-items:center; }
.ev .b{ font-size:12px; color:#aeb6c2; margin-top:3px; white-space:pre-wrap; line-height:1.45; }
.ev .when{ margin-left:auto; font-size:10px; color:#667; font-weight:400; }
.ev.observe{ border-left-color:var(--cyan); } .ev.observe .h{ color:#7fe6f5; }
.ev.think{ border-left-color:var(--ai); } .ev.think .h{ color:#cdb4ff; }
.ev.act{ border-left-color:var(--warn); } .ev.act .h{ color:#f3c879; }
/* EXECUTED commands → red, so it's unmistakable they ran on the device */
.ev.result{ border-left:3px solid var(--crit); background:rgba(231,76,60,.07); } .ev.result .h{ color:#ff9c91; }
.ev.result .b{ background:rgba(0,0,0,.35); border-radius:6px; padding:7px 9px; margin-top:5px; font-family:monospace; color:#ffd7d1; }
.ran-badge{ font-size:9px; font-weight:800; letter-spacing:.5px; background:rgba(231,76,60,.28); color:#ff9c91; padding:1px 7px; border-radius:20px; margin-left:6px; }
.node-chip{ font-size:10px; font-weight:800; background:rgba(77,163,255,.16); color:#bcd; border:1px solid rgba(77,163,255,.32); padding:1px 8px; border-radius:20px; white-space:nowrap; }
.node-chip i{ font-size:9px; margin-right:3px; color:var(--accent); }
.ev.error{ border-left-color:var(--crit); } .ev.error .h{ color:#ff9c91; }
.ev.system{ border-left-color:#667; } .ev.system .h{ color:#9aa; }

/* device / autonomy control */
.dev-row{ display:flex; align-items:center; gap:10px; padding:8px 0; border-bottom:1px solid rgba(255,255,255,.05); flex-wrap:wrap; }
.seg{ display:inline-flex; border:1px solid var(--border); border-radius:8px; overflow:hidden; }
.seg button{ background:transparent; border:none; color:#9aa; padding:5px 10px; font-size:11px; cursor:pointer; }
.seg button.on{ color:#fff; } .seg button.m-observe.on{ background:rgba(34,211,238,.25); } .seg button.m-copilot.on{ background:rgba(77,163,255,.28); } .seg button.m-autopilot.on{ background:rgba(155,107,255,.32); }
.tgt-sel{ background:rgba(10,16,28,.85); border:1px solid rgba(77,163,255,.4); color:#cfe4ff; border-radius:9px; padding:7px 12px; font-size:13px; }
.modal{ position:fixed; inset:0; background:rgba(0,0,0,.7); backdrop-filter:blur(4px); display:none; align-items:flex-start; justify-content:center; z-index:1000; padding:50px 16px; overflow:auto; }
.switch{ font-size:11px; color:#9aa; display:inline-flex; gap:5px; align-items:center; }
.tnum{ width:56px; background:rgba(0,0,0,.4); border:1px solid var(--border); color:#eee; border-radius:6px; padding:4px 6px; font-size:12px; margin-left:4px; }
/* master kill switch */
.ai-master{ display:inline-flex; align-items:center; gap:9px; cursor:pointer; margin-right:12px; user-select:none; }
.aim-lbl{ font-size:11px; font-weight:800; letter-spacing:1px; text-transform:uppercase; color:#8a909a; min-width:56px; text-align:right; }
.aim-sw input{ display:none; }
.aim-track{ display:inline-block; width:46px; height:24px; border-radius:20px; background:rgba(231,76,60,.25); border:1px solid rgba(231,76,60,.5); position:relative; transition:.25s; }
.aim-thumb{ position:absolute; top:2px; left:2px; width:18px; height:18px; border-radius:50%; background:#e74c3c; box-shadow:0 0 8px rgba(231,76,60,.7); transition:.25s; }
.aim-sw input:checked + .aim-track{ background:rgba(46,204,113,.25); border-color:rgba(46,204,113,.55); }
.aim-sw input:checked + .aim-track .aim-thumb{ left:24px; background:var(--ok); box-shadow:0 0 10px rgba(46,204,113,.8); }
/* whole page dims to "offline" when master is off */
#cc-stage.offline{ opacity:.55; filter:grayscale(.5); }
#cc-stage.offline #bot-panel::after{ content:'NetAIObot OFFLINE — master switch is OFF'; position:absolute; top:14px; left:0; right:0; text-align:center; font-size:12px; font-weight:800; letter-spacing:1px; color:#ff9c91; z-index:9; }

/* fullscreen: stage fills, particles reparented behind */
/* FULLSCREEN: bot floats DEAD CENTER over the live particles; action logs glass strip below.
   Panels go transparent so the particles are visible behind everything. */
#cc-stage:fullscreen, #cc-stage:-webkit-full-screen{ background:#05060f; padding:18px; height:100vh!important; display:flex; flex-direction:column; gap:14px; overflow:auto; }
#cc-stage:fullscreen #bot-panel, #cc-stage:-webkit-full-screen #bot-panel{ flex:1 1 auto; min-height:0; background:radial-gradient(circle at 50% 46%, rgba(155,107,255,.10), transparent 60%); border:none; box-shadow:none; backdrop-filter:none; }
#cc-stage:fullscreen #cc-right, #cc-stage:-webkit-full-screen #cc-right{ flex:0 0 auto; }
#cc-stage:fullscreen #cc-right .panel, #cc-stage:-webkit-full-screen #cc-right .panel{ background:rgba(10,14,28,.55); backdrop-filter:blur(14px); }
#cc-stage:fullscreen #log, #cc-stage:-webkit-full-screen #log{ max-height:26vh; }
#cc-stage:fullscreen #nm-netbg, #cc-stage:-webkit-full-screen #nm-netbg{ z-index:0!important; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-robot"></i> NetAIObot', 'AI Command Center',
    'Autonomous Ops · Observe → Think → Act', 'fa-solid fa-robot',
    '<label class="ai-master" title="Master switch — stop/start the whole bot (also disables the n8n webhook)">'
    . '<span class="aim-lbl" id="aim-lbl">…</span>'
    . '<span class="aim-sw"><input type="checkbox" id="aim-tgl" onchange="toggleMaster(this)"><span class="aim-track"><span class="aim-thumb"></span></span></span>'
    . '</label>'
    . '<a href="aiopilot_history.php" class="btn" style="text-decoration:none;"><i class="fas fa-clock-rotate-left"></i> History</a>'
    . '<button class="btn ai" onclick="openDevices()"><i class="fas fa-microchip"></i> Devices &amp; Autonomy</button>'); ?>

<div class="kpis">
  <div class="glass kpi"><div class="n" id="k-active" style="color:var(--accent)">—</div><div class="l">active sessions</div></div>
  <div class="glass kpi"><div class="n" id="k-wait" style="color:var(--warn)">—</div><div class="l">awaiting approval</div></div>
  <div class="glass kpi"><div class="n" id="k-acts">—</div><div class="l">actions today</div></div>
  <div class="glass kpi"><div class="n" id="k-auto" style="color:var(--ok)">—</div><div class="l">auto-resolved</div></div>
  <div class="glass kpi"><div class="n" id="k-queue" style="color:var(--ai)">—</div><div class="l">queued</div></div>
  <div class="glass kpi" style="margin-left:auto;display:flex;align-items:center;gap:10px;">
     <select id="focus" class="tgt-sel" onchange="loadFeed()"><option value="0">All selected devices</option></select>
     <button class="btn" id="scan-btn" onclick="scanAll()" title="Queue every enabled device — the pacer feeds them to the AI a few at a time"><i class="fas fa-radar"></i> Scan all</button>
     <button class="btn ai" id="run-btn" onclick="runNow()"><i class="fas fa-bolt"></i> Run now</button>
  </div>
</div>

<div id="cc-stage">
  <div id="cc-fsctrl">
    <button class="icon-btn" onclick="loadFeed()" title="Refresh"><i class="fas fa-rotate"></i></button>
    <button class="icon-btn" id="fs-btn" onclick="toggleFs()" title="Fullscreen"><i class="fas fa-expand"></i></button>
  </div>

  <!-- ANIMATED BOT -->
  <div id="bot-panel" class="glass s-idle">
    <div class="holo-grid"></div>
    <div class="bot-aura"></div>
    <div class="bits" id="bits"></div>
    <div class="bot-name"><i class="fas fa-robot"></i> NetAIObot</div>
    <div class="bot-dev" id="bot-dev">standing by</div>
    <div class="stream in"  id="stream-in"></div>
    <div class="stream out" id="stream-out"></div>
    <div class="netbot">
      <div class="nb-radar"></div>
      <div class="nb-ring r3"></div><div class="nb-ring"></div><div class="nb-ring r2"></div>
      <div class="nb-core">
        <div class="nb-head">
          <div class="nb-scan"></div>
          <div class="nb-antenna"></div>
          <div class="nb-eyes"><div class="nb-eye"></div><div class="nb-eye"></div></div>
          <div class="nb-mouth"><i></i><i></i><i></i><i></i><i></i></div>
        </div>
        <div class="nb-reactor"></div>
      </div>
    </div>
    <div class="bot-status"><span class="dot"></span><span id="bot-state-txt">IDLE</span><span class="typing" id="bot-typing" style="display:none;"><i></i><i></i><i></i></span></div>
    <div class="bot-think" id="bot-think">Select devices and enable autonomy — I’ll watch them and step in when something breaks.</div>
  </div>

  <!-- LIVE OPS -->
  <div id="cc-right">
    <div class="glass panel" id="approvals" style="display:none;">
      <h3><i class="fas fa-triangle-exclamation" style="color:var(--warn)"></i> Awaiting your approval</h3>
      <div id="ap-list"></div>
    </div>
    <div class="glass panel" style="flex:1;display:flex;flex-direction:column;min-height:0;">
      <h3><i class="fas fa-wave-square"></i> Live transcript <span class="muted" id="feed-meta" style="margin-left:auto;font-weight:400;"></span></h3>
      <div id="log"><div class="muted" style="padding:14px;">No activity yet. NetAIObot wakes automatically on a device concern, or hit <b>Run now</b>.</div></div>
    </div>
  </div>
</div>
</div>

<!-- Devices & Autonomy modal -->
<div class="modal" id="dev-modal">
  <div class="glass" style="max-width:760px;width:100%;padding:20px 22px;">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
      <h2 style="margin:0;font-size:18px;color:var(--ai);"><i class="fas fa-microchip"></i> Devices &amp; Autonomy</h2>
      <button class="icon-btn" style="margin-left:auto;" onclick="closeDevices()"><i class="fas fa-xmark"></i></button>
    </div>
    <div class="muted" style="margin-bottom:12px;">Pick which devices NetAIObot manages and how much it may do on its own.
      <b style="color:#7fe6f5;">Observe</b> = watch only · <b style="color:#9ec5ff;">Copilot</b> = propose &amp; ask · <b style="color:#cdb4ff;">Autopilot</b> = act on safe fixes.</div>
    <!-- AI tuning: the levers that control tokens-per-minute -->
    <div class="glass" style="padding:11px 13px;margin-bottom:12px;background:rgba(155,107,255,.06);border-color:rgba(155,107,255,.3);">
      <div style="font-size:12px;color:#d9c8ff;font-weight:700;margin-bottom:9px;"><i class="fas fa-gauge-high"></i> AI tuning — token budget &amp; pacing</div>
      <div style="display:flex;gap:16px;flex-wrap:wrap;align-items:center;font-size:12px;color:#aeb6c2;">
        <label class="switch"><input type="checkbox" id="set-compact"> Compact context <span class="muted">(5–8× fewer tokens)</span></label>
        <label>Max concurrent <input type="number" id="set-conc" min="1" max="10" class="tnum"></label>
        <label>Gap&nbsp;sec <input type="number" id="set-gap" min="0" max="120" class="tnum"></label>
        <label>Per-run cap <input type="number" id="set-cap" min="1" max="10" class="tnum"></label>
        <button class="btn" onclick="saveSettings(this)"><i class="fas fa-floppy-disk"></i> Save</button>
        <span class="muted" id="set-msg"></span>
      </div>
      <div class="muted" style="margin-top:7px;font-size:11px;">Lower <b>Max concurrent</b> + higher <b>Gap</b> = fewer tokens/min (avoids the OpenAI TPM cap). Compact context shrinks each call.</div>
    </div>

    <div style="display:flex;gap:8px;margin-bottom:10px;">
      <select id="add-node" class="tgt-sel" style="flex:1;"></select>
      <button class="btn" onclick="addDevice()"><i class="fas fa-plus"></i> Add</button>
    </div>
    <div id="dev-list"></div>
  </div>
</div>

<script src="/nm_netbg.js"></script>
<?= function_exists('nm_tz_js') ? nm_tz_js() : '' ?>
<script>
const esc=s=>(s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let FOCUS=0, _seenTop=null;

// time shown in the configured display tz (app_timezone) — stored values are UTC
function nl(ts){ return window.nmTimeStr ? window.nmTimeStr(ts) : (ts||''); }

// ── feed / live transcript ───────────────────────────────────────────────
async function loadFeed(){
  FOCUS=+document.getElementById('focus').value||0;
  let r=null; try{ r=await fetch('aiopilot.php?api=feed&node='+FOCUS+'&_='+Date.now()).then(x=>x.json()); }catch(e){}
  if(!r||!r.ok) return;
  const s=r.stats||{};
  document.getElementById('k-active').textContent=s.active||0;
  document.getElementById('k-wait').textContent=s.awaiting||0;
  document.getElementById('k-acts').textContent=s.actions_today||0;
  document.getElementById('k-auto').textContent=s.auto_today||0;
  document.getElementById('k-queue').textContent=s.queued||0;
  renderLog(r.events||[]);
  renderApprovals(r.pending||[]);
  setBot(r.enabled===false?'system':(r.bot||'idle'), r.events||[]);
  setMaster(r.enabled!==false);
  document.getElementById('feed-meta').textContent=(r.events||[]).length+' events';
}
function setMaster(on){
  const t=document.getElementById('aim-tgl'), l=document.getElementById('aim-lbl'), st=document.getElementById('cc-stage');
  if(t && document.activeElement!==t) t.checked=on;
  if(l){ l.textContent=on?'ON':'OFF'; l.style.color=on?'#9af3c0':'#ff9c91'; }
  if(st) st.classList.toggle('offline', !on);
}
async function toggleMaster(cb){
  const on=cb.checked;
  if(!on && !confirm('Stop NetAIObot completely?\n\nThis disables the n8n webhook and clears the queue — the bot will take NO actions until you switch it back on.')){ cb.checked=true; return; }
  try{ const r=await fetch('aiopilot.php?api=master',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'on='+(on?1:0)}).then(x=>x.json());
    setMaster(r.enabled); }catch(e){ setMaster(!on); }
  loadFeed();
}

let _topEventId=0;
function renderLog(events){
  const box=document.getElementById('log');
  if(!events.length){ box.innerHTML='<div class="muted" style="padding:14px;">No activity yet.</div>'; return; }
  const chrono=[...events].reverse();
  const newTop=events.length?+events[0].id:0;
  box.innerHTML=chrono.map(e=>{
   const nm=e.display_name||('node '+e.node_id);
   // the node is enforced into the stored title; the chip already shows it, so strip the
   // redundant "<node> · " prefix from the displayed title (keeps the transcript clean).
   let ttl=e.title||e.phase;
   if(e.display_name && ttl.indexOf(e.display_name+' · ')===0) ttl=ttl.slice((e.display_name+' · ').length);
   return `<div class="ev ${esc(e.phase)} ${(+e.id>_topEventId)?'fresh':''}">
     <div class="h"><span class="node-chip"><i class="fas fa-server"></i>${esc(nm)}</span>
        <i class="fas ${phaseIcon(e.phase)}"></i> ${esc(ttl)}
        ${e.phase==='result'?'<span class="ran-badge">⚡ RAN ON DEVICE</span>':''}
        <span class="when">${nl(e.created_at)}</span></div>
     ${e.body?`<div class="b">${esc(e.body).slice(0,1200)}</div>`:''}</div>`;
  }).join('');
  _topEventId=newTop;
  box.scrollTop=box.scrollHeight;
}
function phaseIcon(p){ return {observe:'fa-satellite-dish',think:'fa-brain',act:'fa-bolt',result:'fa-circle-check',error:'fa-triangle-exclamation',system:'fa-gear'}[p]||'fa-circle'; }

function renderApprovals(pending){
  const wrap=document.getElementById('approvals'), list=document.getElementById('ap-list'), right=document.getElementById('cc-right');
  if(!pending.length){ wrap.style.display='none'; list.innerHTML=''; if(right) right.classList.add('no-ap'); return; }
  wrap.style.display='block'; if(right) right.classList.remove('no-ap');
  list.innerHTML=pending.map(a=>{
    let args=''; try{ args=JSON.stringify(JSON.parse(a.args||'{}')); }catch(e){ args=a.args||''; }
    return `<div class="ap">
      <div class="t">${esc(a.display_name)} — <span class="mono">${esc(a.tool)}</span><span class="risk ${esc(a.risk)}">${esc((a.risk||'').toUpperCase())}</span></div>
      <div class="r">${esc(a.reason||'')}<div class="muted mono" style="margin-top:4px;">${esc(args).slice(0,200)}</div></div>
      <div style="display:flex;gap:8px;">
        <button class="btn ok" onclick="decide(${a.id},'approve',this)"><i class="fas fa-check"></i> Approve &amp; run</button>
        <button class="btn no" onclick="decide(${a.id},'deny',this)"><i class="fas fa-ban"></i> Deny / manual</button>
      </div></div>`;
  }).join('');
}
async function decide(id,what,btn){
  if(btn){ btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i>'; }
  try{ await fetch('aiopilot.php?api='+what,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'action_id='+id}); }catch(e){}
  setTimeout(loadFeed,400);
}

// ── bot state machine ─────────────────────────────────────────────────────
const STATE={ observe:['OBSERVING','Pulling telemetry & logs…','s-observe'],
  think:['THINKING','Reasoning over the evidence…','s-think'],
  act:['ACTING','Executing a fix…','s-act'],
  result:['VERIFYING','Checking the result…','s-result'],
  error:['ERROR','Something went wrong — see log.','s-error'],
  system:['STANDBY','Idle — watching your devices.','s-idle'],
  idle:['IDLE','Standing by.','s-idle'] };
let _typeTimer=null, _lastThink='';
function typeWriter(el, text){
  if(text===_lastThink){ return; }              // don't retype the same thought
  _lastThink=text; clearInterval(_typeTimer);
  let i=0; el.innerHTML='';
  _typeTimer=setInterval(()=>{
    if(i>=text.length){ clearInterval(_typeTimer); el.innerHTML=esc(text); return; }
    i+=2; el.innerHTML=esc(text.slice(0,i))+'<span class="caret">▌</span>';
  }, 16);
}
function setBot(phase, events){
  const p=document.getElementById('bot-panel'), st=STATE[phase]||STATE.idle;
  p.className='glass '+st[2];
  document.getElementById('bot-state-txt').textContent=st[0];
  // typing indicator while the bot is actively working
  const busy=['observe','think','act'].includes(phase);
  document.getElementById('bot-typing').style.display = busy?'inline-flex':'none';
  // typewriter the latest think/observe/act body as the live "thought"
  const top=events.find(e=>['think','observe','act','result','error'].includes(e.phase));
  typeWriter(document.getElementById('bot-think'), (top && top.body) ? top.body.slice(0,200) : st[1]);
  document.getElementById('bot-dev').textContent= top ? ('on '+(top.display_name||'')) : 'standing by';
  // pulse data streams faster while active
  document.getElementById('stream-in').style.opacity = busy?'.9':'.22';
  document.getElementById('stream-out').style.opacity = (phase==='act')?'.95':'.18';
}
// build the flowing dots + rising data bits once
(function fx(){
  for(const id of ['stream-in','stream-out']){ const el=document.getElementById(id); let h='';
    for(let i=0;i<7;i++){ const top=10+i*12+Math.round(i*1.5); h+=`<span style="top:${top}%;animation-delay:${(i*0.34).toFixed(2)}s"></span>`; }
    el.innerHTML=h; }
  const bits=document.getElementById('bits'); const glyphs=['0','1','{','}','</>','01','10','#','x','ƒ','⌁','∑'];
  let bh=''; for(let i=0;i<16;i++){ const L=6+(i*6)%88, dur=(5+(i%5)*1.4).toFixed(1), del=(i*0.5).toFixed(1);
    bh+=`<b style="left:${L}%;animation-duration:${dur}s;animation-delay:${del}s;">${glyphs[i%glyphs.length]}</b>`; }
  bits.innerHTML=bh;
})();

// ── run now ───────────────────────────────────────────────────────────────
async function runNow(){
  const n=FOCUS|| (+document.getElementById('focus').value||0);
  if(!n){ alert('Pick a specific device in the selector first (NetAIObot runs per device).'); return; }
  const b=document.getElementById('run-btn'); b.disabled=true; b.innerHTML='<i class="fas fa-spinner fa-spin"></i> Dispatching…';
  try{ const r=await fetch('aiopilot.php?api=run',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'node_id='+n}).then(x=>x.json());
    if(!r.ok) alert('Could not start: '+(r.error||'failed')); }catch(e){ alert('Request failed'); }
  b.disabled=false; b.innerHTML='<i class="fas fa-bolt"></i> Run now'; setTimeout(loadFeed,500);
}
async function scanAll(){
  const b=document.getElementById('scan-btn'); b.disabled=true; b.innerHTML='<i class="fas fa-spinner fa-spin"></i> Queuing…';
  try{ const r=await fetch('aiopilot.php?api=scan_all',{method:'POST'}).then(x=>x.json());
    b.innerHTML='<i class="fas fa-check"></i> '+(r.queued||0)+' queued';
  }catch(e){ b.innerHTML='<i class="fas fa-radar"></i> Scan all'; }
  setTimeout(()=>{ b.disabled=false; b.innerHTML='<i class="fas fa-radar"></i> Scan all'; loadFeed(); }, 2200);
}

// ── devices & autonomy modal ──────────────────────────────────────────────
let DEVDATA={selected:[],nodes:[]}; let TG_READY=false;
async function openDevices(){
  document.getElementById('dev-modal').style.display='flex';
  DEVDATA=await fetch('aiopilot.php?api=devices').then(x=>x.json()); TG_READY=!!DEVDATA.tg_ready;
  renderDevModal(); loadSettings();
}
async function loadSettings(){
  const r=await fetch('aiopilot.php?api=settings').then(x=>x.json()).catch(()=>null);
  if(!r||!r.ok) return; const s=r.settings;
  document.getElementById('set-compact').checked=!!s.compact;
  document.getElementById('set-conc').value=s.max_concurrent;
  document.getElementById('set-gap').value=s.min_gap_sec;
  document.getElementById('set-cap').value=s.per_run_cap;
}
async function saveSettings(btn){
  const body=new URLSearchParams({
    aip_compact: document.getElementById('set-compact').checked?'1':'0',
    aip_max_concurrent: document.getElementById('set-conc').value||'2',
    aip_min_gap_sec: document.getElementById('set-gap').value||'15',
    aip_per_run_cap: document.getElementById('set-cap').value||'3'});
  await fetch('aiopilot.php?api=settings',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});
  const m=document.getElementById('set-msg'); m.textContent='Saved ✓'; setTimeout(()=>m.textContent='',2000);
}
function closeDevices(){ document.getElementById('dev-modal').style.display='none'; loadFeed(); refreshFocus(); }
function renderDevModal(){
  const selIds=new Set(DEVDATA.selected.map(d=>+d.node_id));
  document.getElementById('add-node').innerHTML='<option value="0">+ add a device…</option>'+
    DEVDATA.nodes.filter(n=>!selIds.has(+n.id)).map(n=>`<option value="${n.id}">${esc(n.display_name)} — ${esc(n.ip_address)}</option>`).join('');
  const list=document.getElementById('dev-list');
  if(!DEVDATA.selected.length){ list.innerHTML='<div class="muted" style="padding:10px 0;">No devices yet. Add one above.</div>'; return; }
  list.innerHTML=DEVDATA.selected.map(d=>{
    const m=d.autonomy_mode;
    return `<div class="dev-row">
      <div style="min-width:200px;"><b>${esc(d.display_name)}</b> <span class="muted mono">${esc(d.ip_address)}</span></div>
      <div class="seg">
        <button class="m-observe ${m==='observe'?'on':''}" onclick="setMode(${d.node_id},'observe')">Observe</button>
        <button class="m-copilot ${m==='copilot'?'on':''}" onclick="setMode(${d.node_id},'copilot')">Copilot</button>
        <button class="m-autopilot ${m==='autopilot'?'on':''}" onclick="setMode(${d.node_id},'autopilot')">Autopilot</button>
      </div>
      <label class="switch"><input type="checkbox" ${+d.allow_destructive?'checked':''} onchange="setDestructive(${d.node_id},this.checked)"> medium-risk auto</label>
      <label class="switch" title="Let autopilot AUTO-RUN shell/SSH commands without asking (high-risk). Red in the log."><input type="checkbox" ${+d.allow_commands?'checked':''} onchange="setCommands(${d.node_id},this.checked)" style="accent-color:#e74c3c;"> <span style="color:#ff9c91;">auto-run commands</span></label>
      <label class="switch" title="When this device needs approval, also send the command + explanation to Telegram with Approve/Deny buttons — decide from your phone. Uses the bot configured in Notifications."><input type="checkbox" ${+d.telegram_approve?'checked':''} onchange="setTelegram(${d.node_id},this.checked)" style="accent-color:#29b6f6;"> <span style="color:#7fd3ff;"><i class="fab fa-telegram"></i> Telegram approval</span></label>
      <label class="switch"><input type="checkbox" ${+d.enabled?'checked':''} onchange="setEnabled(${d.node_id},this.checked)"> enabled</label>
      <button class="icon-btn" style="margin-left:auto;" onclick="removeDevice(${d.node_id})" title="Remove"><i class="fas fa-trash"></i></button>
    </div>`;
  }).join('');
}
function devOf(id){ return DEVDATA.selected.find(d=>+d.node_id===+id)||{autonomy_mode:'observe',allow_destructive:0,allow_commands:0,telegram_approve:0,enabled:1}; }
async function saveDev(id){ const d=devOf(id);
  await fetch('aiopilot.php?api=set_device',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:`node_id=${id}&mode=${d.autonomy_mode}&enabled=${+d.enabled?1:0}&destructive=${+d.allow_destructive?1:0}&commands=${+d.allow_commands?1:0}&telegram=${+d.telegram_approve?1:0}`});
}
async function setMode(id,m){ devOf(id).autonomy_mode=m; await saveDev(id); renderDevModal(); }
async function setDestructive(id,v){ devOf(id).allow_destructive=v?1:0; await saveDev(id); }
async function setTelegram(id,v){ if(v && !TG_READY && !confirm('No enabled Telegram channel is configured in Notifications yet.\n\nTurn this on anyway? Approval requests will start reaching Telegram once you add the bot in notify_admin.php.')){ renderDevModal(); return; } devOf(id).telegram_approve=v?1:0; await saveDev(id); }
async function setCommands(id,v){ if(v && !confirm('Let NetAIObot AUTO-RUN shell/SSH commands on this device WITHOUT asking?\n\nOnly do this on devices you fully trust the bot to operate.')){ renderDevModal(); return; } devOf(id).allow_commands=v?1:0; await saveDev(id); }
async function setEnabled(id,v){ devOf(id).enabled=v?1:0; await saveDev(id); }
async function addDevice(){ const id=+document.getElementById('add-node').value; if(!id) return;
  await fetch('aiopilot.php?api=set_device',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:`node_id=${id}&mode=observe&enabled=1&destructive=0`});
  DEVDATA=await fetch('aiopilot.php?api=devices').then(x=>x.json()); renderDevModal(); }
async function removeDevice(id){ if(!confirm('Stop NetAIObot from managing this device?'))return;
  await fetch('aiopilot.php?api=remove_device',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'node_id='+id});
  DEVDATA=await fetch('aiopilot.php?api=devices').then(x=>x.json()); renderDevModal(); }

async function refreshFocus(){
  const d=await fetch('aiopilot.php?api=devices').then(x=>x.json());
  const sel=document.getElementById('focus'), cur=sel.value;
  sel.innerHTML='<option value="0">All selected devices</option>'+d.selected.map(x=>`<option value="${x.node_id}">${esc(x.display_name)}</option>`).join('');
  sel.value=cur;
}

// ── fullscreen (netflow pattern: fullscreen the stage, reparent particles) ──
function toggleFs(){ const w=document.getElementById('cc-stage'); const rf=w.requestFullscreen||w.webkitRequestFullscreen;
  if(!document.fullscreenElement&&!document.webkitFullscreenElement){ rf&&rf.call(w); } else { (document.exitFullscreen||document.webkitExitFullscreen||function(){}).call(document); } }
function moveBg(into){ const bg=document.getElementById('nm-netbg'); if(!bg)return;
  if(into){ const w=document.getElementById('cc-stage'); bg.style.zIndex='0'; w.insertBefore(bg,w.firstChild); }
  else { bg.style.zIndex='-1'; document.body.insertBefore(bg,document.body.firstChild); }
  setTimeout(()=>window.dispatchEvent(new Event('resize')),50); }
function _fsSync(){ const on=!!(document.fullscreenElement||document.webkitFullscreenElement);
  const b=document.getElementById('fs-btn'); if(b) b.innerHTML=on?'<i class="fas fa-compress"></i>':'<i class="fas fa-expand"></i>'; moveBg(on); }
document.addEventListener('fullscreenchange',_fsSync); document.addEventListener('webkitfullscreenchange',_fsSync);
document.getElementById('dev-modal').addEventListener('click',e=>{ if(e.target.id==='dev-modal') closeDevices(); });

refreshFocus(); loadFeed(); setInterval(loadFeed, 3500);
</script>
</body></html>
