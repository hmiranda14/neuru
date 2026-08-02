<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — GAME MODE (Gaming). A futuristic WebGL gamer command center over the
// agentless Windows/GPU stack: live game detection, GPU/thermal reactor, Game
// Ping Radar, 1-Click Game Booster. Perm 'gaming'. Engine: nm_gaming.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_gaming.php');
require_once('nm_fanprofiler.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'gaming')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=gaming'); exit;
}
nm_gaming_ensure($conn);
$uid = (int)($_SESSION['user_id'] ?? 0);
$uname = (string)($_SESSION['username'] ?? 'operator');

// ── Proof-of-Lag report (printable, self-contained; open in a new tab → Ctrl+P for PDF) ──
if (($_GET['report'] ?? '') === 'lag') {
    if (function_exists('session_write_close')) @session_write_close();   // release the session lock before the DB-heavy report
    $rid = (int)($_GET['rig'] ?? 0); $hours = (int)($_GET['hours'] ?? 24);
    $rh = function_exists('nm_win_host') ? nm_win_host($conn,$rid) : null;
    $rep = nm_gaming_lag_report($conn,$rid,$hours); $s=$rep['summary'];
    $rig = $rh['name'] ?? ('rig '.$rid); $now = gmdate('Y-m-d H:i').' UTC';
    ?><!DOCTYPE html><html><head><meta charset="UTF-8"><title>NEURU — Proof-of-Lag Report</title><script src="/three.min.js"></script>
    <style>
    body{ margin:0; background:#05070f; color:#e6ecf7; font-family:'Segoe UI',Tahoma,sans-serif; }
    .rwrap{ max-width:900px; margin:0 auto; padding:34px 40px; }
    .rhead{ display:flex; align-items:center; gap:14px; border-bottom:1px solid rgba(120,150,255,.2); padding-bottom:16px; margin-bottom:22px; }
    .rlogo{ font-size:26px; font-weight:900; letter-spacing:2px; background:linear-gradient(90deg,#39e1ff,#b06bff); -webkit-background-clip:text; background-clip:text; color:transparent; }
    .rt{ font-size:13px; color:#8fb4dd; } h1{ font-size:20px; margin:0; }
    .tiles{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:22px 0; }
    .tile{ background:linear-gradient(180deg,rgba(14,22,40,.7),rgba(9,14,26,.5)); border:1px solid rgba(120,150,255,.16); border-radius:14px; padding:14px; text-align:center; }
    .tile .n{ font-size:26px; font-weight:900; } .tile .l{ font-size:10px; color:#8fb4dd; text-transform:uppercase; letter-spacing:.1em; }
    .crit{ color:#ff4d6d } .warn{ color:#f0a92c } .ok{ color:#2ee66e }
    canvas{ width:100%; height:220px; display:block; background:rgba(8,14,28,.4); border-radius:14px; border:1px solid rgba(120,150,255,.14); margin:10px 0; }
    .verdict{ background:rgba(255,77,109,.08); border:1px solid rgba(255,77,109,.3); border-radius:14px; padding:16px; font-size:14px; line-height:1.6; }
    .btnbar{ margin:18px 0; } .pbtn{ background:linear-gradient(180deg,#0bbfe0,#067a95); color:#02121a; border:0; border-radius:10px; padding:11px 22px; font-weight:800; cursor:pointer; font-size:14px; }
    .foot{ font-size:11px; color:#6f93b8; margin-top:26px; border-top:1px solid rgba(120,150,255,.14); padding-top:12px; }
    @media print{ .btnbar,.rbg{ display:none } body{ background:#fff; color:#111 } .tile,.verdict,canvas{ border-color:#ccc } }
    </style></head><body>
    <div class="rwrap">
      <div class="btnbar"><button class="pbtn" onclick="window.print()">⬇ Download / Print as PDF</button> &nbsp; <span class="rt">attach this to your ISP support ticket</span></div>
      <div class="rhead"><div><div class="rlogo">◈ NEURU</div><div class="rt">Network Evidence Report</div></div>
        <div style="margin-left:auto;text-align:right"><h1>Proof-of-Lag</h1><div class="rt">Rig: <b><?= htmlspecialchars($rig) ?></b> · Window: last <?= (int)$rep['hours'] ?>h · Generated <?= $now ?></div></div></div>
      <?php $lc = ($s['avg_loss']>=2?'crit':($s['avg_loss']>0?'warn':'ok')); $jc=(($s['max_jit']??0)>=20?'crit':'warn'); ?>
      <div class="tiles">
        <div class="tile"><div class="n"><?= $s['avg_ms']!==null?$s['avg_ms']:'—' ?><span class="l" style="font-size:13px">ms</span></div><div class="l">Avg latency</div></div>
        <div class="tile"><div class="n crit"><?= $s['max_ms']!==null?$s['max_ms']:'—' ?></div><div class="l">Peak latency (ms)</div></div>
        <div class="tile"><div class="n <?= $jc ?>"><?= $s['max_jit']!==null?$s['max_jit']:'—' ?></div><div class="l">Peak jitter (ms)</div></div>
        <div class="tile"><div class="n <?= $lc ?>"><?= $s['avg_loss'] ?>%</div><div class="l">Avg packet loss</div></div>
      </div>
      <div class="rt">Latency &amp; loss to your game servers over time (each point = hourly average). <b><?= (int)$s['samples'] ?></b> samples · <b><?= (int)$s['loss_events'] ?></b> loss events<?= $s['worst_region']?(' · worst path: <b>'.htmlspecialchars($s['worst_region']['region']).'</b> ('.htmlspecialchars($s['worst_region']['host']).')'):'' ?>.</div>
      <canvas id="chart"></canvas>
      <div class="verdict"><b>Assessment for your ISP:</b><br><?= htmlspecialchars($rep['verdict']) ?></div>
      <div class="foot">Generated by NEURU NOC · Game Mode · Proof-of-Lag. Measurements taken from the gamer's PC (<?= htmlspecialchars($rig) ?>) to the official game-server regions via ICMP echo. This is diagnostic evidence of the connection path condition during the stated window.</div>
    </div>
    <script>
    const S=<?= json_encode($rep['series']) ?>;
    (function(){ const cv=document.getElementById('chart'); const dpr=Math.min(2,devicePixelRatio); const w=cv.clientWidth,h=220; cv.width=w*dpr;cv.height=h*dpr; const c=cv.getContext('2d'); c.setTransform(dpr,0,0,dpr,0,0);
      if(!S.length){ c.fillStyle='#6f93b8'; c.font='13px sans-serif'; c.fillText('Not enough samples yet — keep the Ping Radar running to build history.',20,110); return; }
      const pad=34, ph=h-pad*1.4, pw=w-pad*2; const maxMs=Math.max(60,...S.map(x=>x.ms));
      // grid
      c.strokeStyle='rgba(120,150,255,.12)'; for(let i=0;i<=4;i++){ const y=pad*0.4+ph*i/4; c.beginPath();c.moveTo(pad,y);c.lineTo(w-pad,y);c.stroke(); c.fillStyle='#5f7799';c.font='9px sans-serif';c.fillText(Math.round(maxMs*(1-i/4))+'ms',4,y+3); }
      // loss bars (red)
      S.forEach((x,i)=>{ if(x.loss>0){ const bx=pad+pw*i/(S.length-1||1); c.fillStyle='rgba(255,77,109,.28)'; c.fillRect(bx-2,pad*0.4,4,ph); } });
      // ms line
      c.beginPath(); S.forEach((x,i)=>{ const px=pad+pw*i/(S.length-1||1), py=pad*0.4+ph*(1-Math.min(1,x.ms/maxMs)); i?c.lineTo(px,py):c.moveTo(px,py); }); c.strokeStyle='#39e1ff'; c.lineWidth=2; c.stroke();
      // jitter line
      c.beginPath(); S.forEach((x,i)=>{ const px=pad+pw*i/(S.length-1||1), py=pad*0.4+ph*(1-Math.min(1,x.jit/maxMs)); i?c.lineTo(px,py):c.moveTo(px,py); }); c.strokeStyle='#f0a92c'; c.lineWidth=1.4; c.setLineDash([4,3]); c.stroke(); c.setLineDash([]);
      c.fillStyle='#39e1ff';c.fillText('— latency',pad,h-8); c.fillStyle='#f0a92c';c.fillText('— jitter',pad+80,h-8); c.fillStyle='#ff4d6d';c.fillText('▮ packet loss',pad+150,h-8);
    })();
    </script></body></html><?php
    exit;
}

// ── JSON API ──
if ($api !== '') {
    header('Content-Type: application/json');
    if (function_exists('session_write_close')) @session_write_close();
    try {
    if ($api === 'rigs') {   // available rigs = monitored Windows hosts
        $rows = function_exists('nm_win_hosts') ? nm_win_hosts($conn) : [];
        $out = [];
        foreach ($rows as $h) $out[] = ['id'=>(int)$h['id'],'name'=>$h['name'] ?? ('host '.$h['id']),'ip'=>$h['host_ip'] ?? ''];
        echo json_encode(['ok'=>true,'rigs'=>$out]); exit;
    }
    $h = (isset($_GET['rig']) && function_exists('nm_win_host')) ? nm_win_host($conn,(int)$_GET['rig']) : null;
    if ($api === 'vitals') {
        if (!$h) { echo json_encode(['ok'=>false,'error'=>'pick a rig']); exit; }
        $v = nm_gaming_vitals($conn,$h); $v['boost']=nm_gaming_boost_state($conn,(int)$h['id']);
        // session tracking: open/close + bump running max temp / peak VRAM
        $hid=(int)$h['id']; $game = !empty($v['game']) ? $v['game'] : null;
        if ($game) { $sid=nm_gaming_session_open($conn,$hid,$game); $g=$v['gpu']??[]; nm_gaming_session_bump($conn,$sid,!empty($g['ok'])?(int)($g['temp']??0):null,!empty($g['ok'])?(int)($g['vram_used']??0):null,null); }
        else nm_gaming_session_close_if_idle($conn,$hid,null);
        $v['session']=nm_gaming_last_session($conn,$hid);
        if (!empty($v['ok'])) nm_gaming_cache_set($conn,$hid,'vitals',$v);   // keep the OBS overlay warm
        echo json_encode($v); exit;
    }
    if ($api === 'fps') {   // capture real FPS (PresentMon) + roll into the session
        if (!$h) { echo json_encode(['ok'=>false,'error'=>'pick a rig']); exit; }
        $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn,$h) : null;
        if (!$ssh) { echo json_encode(['ok'=>false,'error'=>'no SSH']); exit; }
        $game = nm_gaming_detect_cached($conn,(int)$h['id'],$ssh);
        if (!$game) { echo json_encode(['ok'=>true,'no_game'=>true]); exit; }
        $fps = nm_gaming_fps($ssh, $game['process']);
        if (!empty($fps['ok'])) { $sid=nm_gaming_session_open($conn,(int)$h['id'],$game); nm_gaming_session_bump($conn,$sid,null,null,$fps); nm_gaming_cache_set($conn,(int)$h['id'],'fps',$fps); }
        echo json_encode($fps + ['game'=>$game['title']]); exit;
    }
    if ($api === 'detect_debug') {   // diagnostic — shows what the detector sees on this rig
        if (!$h) { echo json_encode(['ok'=>false,'error'=>'pick a rig']); exit; }
        $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn,$h) : null;
        if (!$ssh) { echo json_encode(['ok'=>false,'error'=>'no SSH for this rig']); exit; }
        echo json_encode(['ok'=>true] + nm_gaming_detect_debug($ssh, nm_gaming_get_folders($conn))); exit;
    }
    if ($api === 'pm_status') { if(!$h){echo json_encode(['ok'=>false]);exit;} $ssh=nm_win_resolve_ssh($conn,$h); echo json_encode($ssh?nm_gaming_pm_status($ssh):['ok'=>false]); exit; }
    if ($api === 'pm_deploy') {
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){ echo json_encode(['ok'=>false,'error'=>'POST only']); exit; }
        $h = function_exists('nm_win_host') ? nm_win_host($conn,(int)($_POST['rig']??0)) : null; if(!$h){echo json_encode(['ok'=>false,'error'=>'pick a rig']);exit;}
        $ssh=nm_win_resolve_ssh($conn,$h); log_user_action($conn,'game_pm_deploy',$h['name']??('rig '.$h['id']));
        echo json_encode($ssh?nm_gaming_pm_deploy($conn,$ssh):['ok'=>false,'error'=>'no SSH']); exit;
    }
    if ($api === 'hogs') { if(!$h){echo json_encode(['ok'=>false,'error'=>'pick a rig']);exit;} echo json_encode(nm_gaming_bandwidth_hogs($conn,$h)); exit; }
    if ($api === 'fan_list') { if(!$h){ echo json_encode(['ok'=>false,'error'=>'pick a rig']); exit; }
        $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn,$h) : null;
        echo json_encode($ssh ? nm_fp_list($ssh, nm_fp_dir($conn,(int)$h['id'])) : ['ok'=>false,'error'=>'no SSH']); exit; }
    if ($api === 'dna') { $rid=(int)($_GET['rig']??0); if(!$rid){ echo json_encode(['ok'=>false,'error'=>'pick a rig']); exit; }
        echo json_encode(nm_gaming_dna($conn,$rid)); exit; }
    if ($api === 'fan_apply') { if(($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){ echo json_encode(['ok'=>false,'error'=>'POST only']); exit; }
        $h = function_exists('nm_win_host') ? nm_win_host($conn,(int)($_POST['rig']??0)) : null; if(!$h){ echo json_encode(['ok'=>false,'error'=>'pick a rig']); exit; }
        $ssh = nm_win_resolve_ssh($conn,$h); if(!$ssh){ echo json_encode(['ok'=>false,'error'=>'no SSH']); exit; }
        $name = (string)($_POST['file'] ?? ''); if(!preg_match('/^[A-Za-z0-9 ._\\-()]+\\.json$/',$name)){ echo json_encode(['ok'=>false,'error'=>'bad name']); exit; }
        $dir = nm_fp_dir($conn,(int)$h['id']); $path = rtrim($dir,'\\').'\\'.$name;
        log_user_action($conn,'game_fan_apply',($h['name']??('rig '.$h['id'])).' -> '.$name);
        echo json_encode(nm_fp_apply($ssh,$path)); exit; }
    if ($api === 'sensors') { if(!$h){echo json_encode(['ok'=>false,'error'=>'pick a rig']);exit;}
        $ssh=function_exists('nm_win_resolve_ssh')?nm_win_resolve_ssh($conn,$h):null; $s=$ssh?nm_gaming_sensors($ssh):['ok'=>false,'error'=>'no SSH'];
        $s['fan_names']=nm_gaming_fan_names($conn,(int)$h['id']); echo json_encode($s); exit; }
    if ($api === 'fan_name_set') { if(($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){ echo json_encode(['ok'=>false,'error'=>'POST only']); exit; }
        nm_gaming_fan_name_set($conn,(int)($_POST['rig']??0),(string)($_POST['orig']??''),(string)($_POST['label']??'')); echo json_encode(['ok'=>true]); exit; }
    if ($api === 'map_servers') { if(($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){ echo json_encode(['ok'=>false,'error'=>'POST only']); exit; }
        $game=(string)($_POST['game']??''); $regs=[];
        for ($i=1;$i<=4;$i++){ $rg=trim((string)($_POST['r'.$i]??'')); $hs=trim((string)($_POST['h'.$i]??'')); if($rg!==''&&$hs!=='') $regs[$rg]=$hs; }
        nm_gaming_endpoints_set($conn,$game,$regs); echo json_encode(['ok'=>true,'map'=>nm_gaming_custom_endpoints($conn)]); exit; }
    if ($api === 'server_map_get') { echo json_encode(['ok'=>true,'map'=>nm_gaming_custom_endpoints($conn)]); exit; }
    if ($api === 'disks') { if(!$h){echo json_encode(['ok'=>false,'error'=>'pick a rig']);exit;}
        $ssh=function_exists('nm_win_resolve_ssh')?nm_win_resolve_ssh($conn,$h):null; echo json_encode($ssh?nm_gaming_disks($ssh):['ok'=>false,'error'=>'no SSH']); exit; }
    if ($api === 'games') { if(!$h){echo json_encode(['ok'=>false,'error'=>'pick a rig']);exit;}
        $ssh=function_exists('nm_win_resolve_ssh')?nm_win_resolve_ssh($conn,$h):null; echo json_encode($ssh?nm_gaming_games($conn,$ssh):['ok'=>false,'error'=>'no SSH']); exit; }
    if ($api === 'game_launch') { if(($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){ echo json_encode(['ok'=>false,'error'=>'POST only']); exit; }
        $h = function_exists('nm_win_host') ? nm_win_host($conn,(int)($_POST['rig']??0)) : null; if(!$h){ echo json_encode(['ok'=>false,'error'=>'pick a rig']); exit; }
        $ssh=function_exists('nm_win_resolve_ssh')?nm_win_resolve_ssh($conn,$h):null; log_user_action($conn,'game_launch',(string)($_POST['folder']??''));
        echo json_encode($ssh?nm_gaming_launch($ssh,(string)($_POST['folder']??'')):['ok'=>false,'error'=>'no SSH']); exit; }
    if ($api === 'games_folders_set') { if(($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){ echo json_encode(['ok'=>false,'error'=>'POST only']); exit; }
        $v=trim((string)($_POST['folders']??''));
        try { $st=$conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES ('game_folders',?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)"); $st->bind_param('s',$v); $st->execute(); $st->close(); } catch (\Throwable $e){}
        echo json_encode(['ok'=>true,'folders'=>nm_gaming_get_folders($conn)]); exit; }
    if ($api === 'ping_radar') {
        if (!$h) { echo json_encode(['ok'=>false,'error'=>'pick a rig']); exit; }
        $eps = [];
        $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn,$h) : null;
        $game = $ssh ? nm_gaming_detect_cached($conn,(int)$h['id'],$ssh) : null;
        // custom user map (by detected game title) → built-in title ep → a named ?game → generic reference
        if ($game) $eps = nm_gaming_endpoints_for($conn, (string)$game['title'], $game['ep'] ?? []);
        if (!$eps) { $t = (string)($_GET['game'] ?? ''); if ($t!==''){ $eps = nm_gaming_endpoints_for($conn,$t,[]); if(!$eps){ foreach (nm_gaming_titles() as $tt) if ($tt['title']===$t){ $eps=$tt['ep']; break; } } } }
        if (!$eps) $eps = ['NA (Google)'=>'8.8.8.8','EU (Cloudflare)'=>'1.1.1.1'];   // generic reference if no game/map
        $res = nm_gaming_ping_radar($conn,$h,$eps);
        $res['game']   = $game ? $game['title'] : ((string)($_GET['game'] ?? '') ?: null);
        $res['pub']    = $game ? $game['pub'] : null;
        $res['source'] = ($h['name'] ?? ('rig '.$h['id'])) . (empty($h['host_ip'])?'':(' · '.$h['host_ip']));
        $res['reference'] = $game ? false : true;
        // cache the best region ping for the OBS overlay
        $best=null; foreach(($res['regions']??[]) as $rg){ if($rg['ms']!==null && ($best===null || $rg['ms']<$best['ms'])) $best=$rg; }
        if ($best) nm_gaming_cache_set($conn,(int)$h['id'],'ping',['ms'=>$best['ms'],'region'=>$best['region'],'loss'=>$best['loss']??0,'jitter'=>$best['jitter']??null,'game'=>$res['game']]);
        // log samples for the Proof-of-Lag ISP report
        try { $st=$conn->prepare("INSERT INTO nm_game_lag_log (rig_id,region,host,ms,jitter,loss) VALUES (?,?,?,?,?,?)");
              foreach(($res['regions']??[]) as $rg){ $rid2=(int)$h['id']; $reg=(string)$rg['region']; $hst=(string)($rg['host']??''); $ms=$rg['ms']; $jit=$rg['jitter']; $los=(int)($rg['loss']??0); $st->bind_param('issddi',$rid2,$reg,$hst,$ms,$jit,$los); $st->execute(); }
              $st->close(); if(rand(1,40)===1) $conn->query("DELETE FROM nm_game_lag_log WHERE sampled_at < (NOW() - INTERVAL 7 DAY)"); } catch(\Throwable $e){}
        echo json_encode($res); exit;
    }
    if ($api === 'boost') {   // POST: {rig, on}
        if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST only']); exit; }
        $h = function_exists('nm_win_host') ? nm_win_host($conn,(int)($_POST['rig']??0)) : null;
        if (!$h) { echo json_encode(['ok'=>false,'error'=>'pick a rig']); exit; }
        $on = ($_POST['on'] ?? '1')==='1';
        log_user_action($conn,'game_boost',($on?'ON':'OFF').' on rig '.($h['name']??$h['id']));
        $r = nm_gaming_boost($conn,$h,$on,$uname);
        if (!empty($r['ok'])) nm_gaming_notify($conn, $on?'boost_on':'boost_off', $h['name']??('rig '.$h['id']));   // Discord + Smart-Home
        echo json_encode($r); exit;
    }
    if ($api === 'webhooks_get') { echo json_encode(['ok'=>true,'discord'=>nm_gaming_get($conn,'game_discord_webhook',''),'smarthome'=>nm_gaming_get($conn,'game_smarthome_webhook','')]); exit; }
    if ($api === 'webhooks_set') { if(($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){ echo json_encode(['ok'=>false,'error'=>'POST only']); exit; }
        foreach (['discord'=>'game_discord_webhook','smarthome'=>'game_smarthome_webhook'] as $k=>$sk){ $u=trim((string)($_POST[$k]??'')); if($u!=='' && !preg_match('#^https?://#i',$u)){ echo json_encode(['ok'=>false,'error'=>'invalid '.$k.' URL']); exit; }
            try { $st=$conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES (?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)"); $st->bind_param('ss',$sk,$u); $st->execute(); $st->close(); } catch (\Throwable $e){} }
        if (($_POST['test']??'')==='1'){ nm_gaming_notify($conn,'test',(string)($_SESSION['username']??'you')); }
        echo json_encode(['ok'=>true]); exit; }
    if ($api === 'servers') { $rc = ($_GET['recheck'] ?? '1')!=='0'; echo json_encode(nm_gaming_servers_status($conn,$rc)); exit; }
    if ($api === 'server_add') { if(($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){ echo json_encode(['ok'=>false,'error'=>'POST only']); exit; }
        log_user_action($conn,'game_server_add',($_POST['host']??'').':'.($_POST['port']??'')); echo json_encode(nm_gaming_server_add($conn,$_POST,$uname)); exit; }
    if ($api === 'server_del') { if(($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){ echo json_encode(['ok'=>false,'error'=>'POST only']); exit; }
        echo json_encode(nm_gaming_server_del($conn,(int)($_POST['id']??0))); exit; }
    if ($api === 'overlays') { echo json_encode(['ok'=>true,'overlays'=>array_map(function($o){ return ['id'=>(int)$o['id'],'token'=>$o['token'],'rig'=>$o['rig_name']??('rig '.$o['rig_id']),'theme'=>$o['theme'],'opts'=>json_decode($o['opts']??'{}',true)]; }, nm_gaming_overlays($conn))]); exit; }
    if ($api === 'overlay_create') { if(($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){ echo json_encode(['ok'=>false,'error'=>'POST only']); exit; }
        $rid=(int)($_POST['rig']??0); if(!$rid){ echo json_encode(['ok'=>false,'error'=>'pick a rig']); exit; }
        $opts=['ping'=>($_POST['w_ping']??'1')==='1','gpu'=>($_POST['w_gpu']??'1')==='1','cpu'=>($_POST['w_cpu']??'1')==='1','fps'=>($_POST['w_fps']??'1')==='1','net'=>($_POST['w_net']??'1')==='1'];
        log_user_action($conn,'game_overlay_create','rig '.$rid);
        echo json_encode(nm_gaming_overlay_create($conn,$rid,$opts,(string)($_POST['theme']??'synthwave'),$uname)); exit; }
    if ($api === 'overlay_del') { if(($_SERVER['REQUEST_METHOD']??'GET')!=='POST'){ echo json_encode(['ok'=>false,'error'=>'POST only']); exit; }
        echo json_encode(nm_gaming_overlay_del($conn,(int)($_POST['id']??0))); exit; }
    echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
    } catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>$e->getMessage()]); exit; }   // graceful degrade — a bad SSH/secret call returns {ok:false}, never a 500 that blanks the widget
}

$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Game Mode | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="/three.min.js"></script>
<style>
:root{ --ok:#2ee66e; --warn:#f0a92c; --crit:#ff4d6d; --cy:#39e1ff; --pk:#b06bff; --bd:rgba(120,150,255,.14); }
*,*::before,*::after{ box-sizing:border-box; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#04060d; color:#e6ecf7; overflow-x:hidden; }
#gbg{ position:fixed; inset:0; z-index:-1; }
.gwrap{ max-width:1400px; margin:0 auto; padding:16px 20px 60px; }
.ghead{ display:flex; align-items:center; gap:16px; flex-wrap:wrap; margin-bottom:18px; }
.gtitle{ font-size:26px; font-weight:900; letter-spacing:1px; background:linear-gradient(90deg,var(--cy),var(--pk)); -webkit-background-clip:text; background-clip:text; color:transparent; transition:filter .6s; }
select.rig{ background:#111a2b; color:#dbe6f5; border:1px solid var(--bd); border-radius:10px; padding:10px 14px; font-size:14px; }
/* the hero toggle */
.gmode{ margin-left:auto; display:flex; align-items:center; gap:14px; }
.gmbtn{ position:relative; padding:14px 30px; border-radius:14px; border:1px solid rgba(57,225,255,.4); background:linear-gradient(180deg,rgba(57,225,255,.14),rgba(176,107,255,.10)); color:#eaf6ff; font-size:16px; font-weight:800; letter-spacing:1px; cursor:pointer; transition:.2s; text-transform:uppercase; }
.gmbtn:hover{ box-shadow:0 0 28px rgba(57,225,255,.35); transform:translateY(-1px); }
.gmbtn.on{ background:linear-gradient(180deg,rgba(46,230,110,.22),rgba(46,230,110,.08)); border-color:rgba(46,230,110,.6); box-shadow:0 0 32px rgba(46,230,110,.4); }
.grid{ display:grid; grid-template-columns:repeat(12,1fr); gap:14px; }
.card{ background:linear-gradient(180deg,rgba(14,22,40,.66),rgba(9,14,26,.5)); border:1px solid var(--bd); border-radius:16px; padding:16px; backdrop-filter:blur(10px); position:relative; overflow:hidden; }
.card h3{ margin:0 0 10px; font-size:12px; text-transform:uppercase; letter-spacing:.12em; color:#8fb4dd; display:flex; align-items:center; gap:8px; }
.c-hero{ grid-column:span 5; min-height:320px; } .c-thermal{ grid-column:span 3; } .c-radar{ grid-column:span 4; } .c-boost{ grid-column:span 5; } .c-hog{ grid-column:span 4; } .c-sys{ grid-column:span 3; }
/* animated fan */
@keyframes fanspin{ to{ transform:rotate(360deg); } }
.fanwrap{ display:flex; align-items:center; gap:10px; margin-top:8px; }
#fanBlades{ transform-origin:50px 50px; animation:fanspin 3s linear infinite; animation-play-state:paused; }
.fanpct{ font-size:15px; font-weight:800; } .fanpct .muted{ font-weight:400; }
/* radar detail */
#radarHead{ font-size:12px; color:#cfe4ff; margin-bottom:6px; }
.ms-in{ background:#111a2b; color:#dbe6f5; border:1px solid var(--bd); border-radius:7px; padding:6px 9px; font-size:11px; font-family:monospace; }
.reg{ display:flex; justify-content:space-between; align-items:flex-start; gap:10px; font-size:13px; padding:6px 0; border-bottom:1px solid rgba(255,255,255,.05); }
.reg .rl{ min-width:0; } .reg .rl b{ font-size:13px; } .reg .rl .host{ display:block; font-size:10px; color:#7c99bd; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:190px; }
.reg .rr{ text-align:right; white-space:nowrap; } .reg .ms{ font-variant-numeric:tabular-nums; font-weight:700; } .reg .rr .sub{ display:block; font-size:10px; color:#8fb4dd; }
@media(max-width:1050px){ .grid>*{ grid-column:1/-1 !important; } }
#fpsCanvas{ width:100%; height:220px; display:block; }
.gameName{ font-size:22px; font-weight:800; margin-top:6px; } .gamePub{ font-size:12px; color:#8fb4dd; }
.big{ font-size:40px; font-weight:900; font-variant-numeric:tabular-nums; } .unit{ font-size:14px; color:#8fb4dd; }
.tiles{ display:flex; gap:10px; margin-top:10px; } .tile{ flex:1; text-align:center; background:rgba(8,14,28,.5); border:1px solid var(--bd); border-radius:10px; padding:8px; } .tile .n{ font-size:20px; font-weight:800; } .tile .l{ font-size:9px; color:#8fb4dd; text-transform:uppercase; letter-spacing:.08em; }
.bar{ height:10px; border-radius:6px; background:rgba(255,255,255,.08); overflow:hidden; margin:6px 0; } .bar > span{ display:block; height:100%; border-radius:6px; }
.thr-alert{ color:var(--crit); font-weight:800; display:none; } .thr-alert.on{ display:block; }
#radarCanvas{ width:100%; height:200px; display:block; }
.reg{ display:flex; justify-content:space-between; font-size:13px; padding:4px 0; border-bottom:1px solid rgba(255,255,255,.05); } .reg .ms{ font-variant-numeric:tabular-nums; font-weight:700; }
.g-good{ color:var(--ok) } .g-ok{ color:var(--warn) } .g-bad{ color:var(--crit) } .g-down{ color:#7c828c }
.verdict{ font-size:12px; color:#cfe4ff; margin-top:8px; }
.hoglist .h-row{ display:flex; align-items:center; gap:8px; font-size:12px; margin:5px 0; } .hoglist .h-row .nm{ flex:0 0 120px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.sens-row{ display:flex; align-items:center; gap:9px; font-size:12px; padding:4px 0; border-bottom:1px solid rgba(255,255,255,.04); }
.sens-row .fi{ color:#8bf3ff; width:15px; } .sens-row .nm{ flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; } .sens-row .hw{ color:#6f93b8; font-size:10px; } .sens-row .v{ font-weight:700; font-variant-numeric:tabular-nums; } .sens-row .v small{ font-size:9px; opacity:.7; }
.sens-row.thresh{ opacity:.42; } .sens-row.thresh .v{ color:#7c8698; font-weight:400; }   /* config threshold, not a live reading */
.sens-row.hot{ background:rgba(255,77,109,.08); border-radius:6px; padding-left:6px; padding-right:6px; }
/* framed sections + BIG fan tiles */
.sframe{ background:rgba(6,11,22,.5); border:1px solid var(--bd); border-radius:16px; padding:14px 16px; margin-top:12px; }
.sframe-h{ font-size:12px; text-transform:uppercase; letter-spacing:.1em; color:#8fb4dd; margin-bottom:12px; display:flex; align-items:center; gap:8px; }
.fan-grid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); gap:14px; }
.fan-tile{ background:linear-gradient(180deg,rgba(14,22,40,.6),rgba(9,14,26,.4)); border:1px solid var(--bd); border-radius:16px; padding:16px 10px 12px; text-align:center; position:relative; }
.fan-tile.stopped{ border-color:rgba(255,77,109,.5); box-shadow:0 0 18px rgba(255,77,109,.2); }
.fan-tile svg{ width:78px; height:78px; }
.fan-tile .fan-name{ font-size:13px; font-weight:800; margin-top:8px; cursor:pointer; display:inline-flex; align-items:center; gap:5px; } .fan-tile .fan-name .ed{ font-size:9px; opacity:.45; } .fan-tile .fan-name:hover .ed{ opacity:1; color:#39e1ff; }
.fan-tile .fan-rpm{ font-size:22px; font-weight:900; font-variant-numeric:tabular-nums; margin-top:3px; } .fan-tile .fan-rpm small{ font-size:10px; color:#8fb4dd; font-weight:600; }
.fan-tile .fan-pct{ font-size:11px; color:#8fb4dd; } .fan-tile.stopped .fan-rpm{ color:#ff4d6d; }
.temp-grid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:3px 20px; }
.muted{ color:#7c828c; font-size:12px; } .boostlog{ font-size:12px; color:#9fd; margin-top:8px; }
.chip{ display:inline-block; padding:3px 9px; border-radius:999px; font-size:11px; background:rgba(57,225,255,.12); border:1px solid var(--bd); margin:2px; cursor:pointer; }
/* server status board */
.srv-grid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(210px,1fr)); gap:10px; margin-top:10px; }
.srv{ background:rgba(8,14,28,.55); border:1px solid var(--bd); border-radius:12px; padding:11px 13px; position:relative; }
.srv .sname{ font-weight:700; font-size:13px; display:flex; align-items:center; gap:7px; }
.srv .sdot{ width:9px; height:9px; border-radius:50%; flex:0 0 auto; box-shadow:0 0 8px currentColor; }
.srv .smeta{ font-size:11px; color:#8fb4dd; margin-top:4px; } .srv .sdet{ font-size:11px; color:#cfe4ff; margin-top:3px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.srv .sping{ position:absolute; top:10px; right:12px; font-size:12px; font-weight:700; font-variant-numeric:tabular-nums; }
.srv .players{ display:inline-block; margin-top:5px; font-size:12px; font-weight:700; color:#8bf3ff; }
.srv .sdel{ position:absolute; bottom:8px; right:10px; font-size:11px; color:#7c828c; cursor:pointer; } .srv .sdel:hover{ color:#ff4d6d; }
.s-up{ color:#2ee66e } .s-degraded{ color:#f0a92c } .s-down{ color:#ff4d6d }
.addform{ display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; background:rgba(8,14,28,.4); padding:12px; border-radius:12px; border:1px solid var(--bd); }
.addform input,.addform select{ background:#111a2b; color:#dbe6f5; border:1px solid var(--bd); border-radius:8px; padding:8px 11px; font-size:13px; }
/* aesthetic theme presets (Synthwave default) + Kiosk/Sensor-Panel mode */
body.t-matrix{ --cy:#22ff88; --pk:#0aff9d; } body.t-neon{ --cy:#22a7ff; --pk:#3a7bff; } body.t-obsidian{ --cy:#9aa6bd; --pk:#c9d2e3; }
body.t-matrix .gtitle,body.t-neon .gtitle,body.t-obsidian .gtitle{ background:linear-gradient(90deg,var(--cy),var(--pk)); -webkit-background-clip:text; background-clip:text; }
/* === Adaptive HUD Skinning — auto game-reactive skins === */
body::before{ content:''; position:fixed; top:0; left:0; right:0; height:3px; z-index:60; pointer-events:none; opacity:0; transition:opacity 1s;
  background:linear-gradient(90deg,var(--cy),var(--pk),var(--cy)); background-size:200% 100%; animation:skinflow 7s linear infinite; }
body.skinned::before{ opacity:.85; }
@keyframes skinflow{ to{ background-position:200% 0; } }
body.gt-cyber{ --cy:#f3e600; --pk:#ff2e88; }  body.gt-souls{ --cy:#e8c96a; --pk:#a9743a; }
body.gt-valorant{ --cy:#ff4655; --pk:#18e6c8; }  body.gt-fortnite{ --cy:#a06bff; --pk:#22c9ff; }
body.gt-cod{ --cy:#c2ce78; --pk:#ff7a1a; }  body.gt-mc{ --cy:#5fd35a; --pk:#c08a4a; }
body.gt-arcane{ --cy:#3aa0ff; --pk:#f0c05a; }  body.gt-cs{ --cy:#f0902a; --pk:#8fb6d8; }
body.gt-gta{ --cy:#ff3fa4; --pk:#22e0d0; }  body.gt-halo{ --cy:#3ad07a; --pk:#3a8bff; }
body.gt-apex{ --cy:#ff3b30; --pk:#ff9a1e; }  body.gt-doom{ --cy:#ff2a1a; --pk:#8aff3a; }
body.gt-race{ --cy:#39e17a; --pk:#e6ebf2; }  body.gt-hell{ --cy:#f5c518; --pk:#8091a6; }
body.gt-sci{ --cy:#39e1ff; --pk:#b06bff; }
.skin-badge{ display:none; margin-top:7px; align-items:center; gap:7px; font-size:11px; font-weight:700; letter-spacing:.04em; padding:4px 11px; border-radius:999px; width:fit-content;
  background:linear-gradient(90deg, color-mix(in srgb, var(--cy) 20%, transparent), color-mix(in srgb, var(--pk) 20%, transparent));
  border:1px solid color-mix(in srgb, var(--cy) 45%, transparent); color:#eef4ff; }
.skin-badge.on{ display:inline-flex; }
.skin-badge .dot{ width:8px; height:8px; border-radius:50%; background:var(--cy); box-shadow:0 0 8px var(--cy); }
#skinToast{ position:fixed; top:16px; left:50%; transform:translate(-50%,-24px); z-index:120; padding:10px 18px; border-radius:12px; font-size:13px; font-weight:800; letter-spacing:.03em; color:#08111f; pointer-events:none; opacity:0; transition:opacity .5s, transform .5s;
  background:linear-gradient(90deg,var(--cy),var(--pk)); box-shadow:0 8px 34px rgba(0,0,0,.5); }
#skinToast.show{ opacity:1; transform:translate(-50%,0); }
body.kiosk #header, body.kiosk .ghead .muted, body.kiosk #bg-video{ display:none !important; }
body.kiosk .gwrap{ max-width:none; padding:8px 12px; } body.kiosk .grid{ gap:10px; }
.hdrctl{ display:flex; align-items:center; gap:8px; }
.hdrctl select,.hdrctl button{ background:#111a2b; color:#cfe4ff; border:1px solid var(--bd); border-radius:9px; padding:8px 11px; font-size:12px; cursor:pointer; }
/* .deckbtn works identically on <button> AND <a> (the a's didn't inherit .hdrctl button sizing → looked like plain text) */
.deckbtn{ display:inline-flex !important; align-items:center; gap:7px; background:linear-gradient(90deg,rgba(57,225,255,.2),rgba(176,107,255,.2)) !important; border:1px solid rgba(57,225,255,.55) !important; color:#e6f7ff !important; font-weight:700 !important; border-radius:9px; padding:8px 13px; font-size:12px; line-height:1; cursor:pointer; text-decoration:none !important; white-space:nowrap; }
.deckbtn:hover{ box-shadow:0 0 18px rgba(57,225,255,.45); transform:translateY(-1px); }
.deckbtn i{ font-size:13px; }
/* ══ NEURU Copilot — reactive battle-buddy (event-driven micro-alerts + safe actions + voice) ══ */
.cpilot{ grid-column:1/-1; background:linear-gradient(120deg,rgba(18,24,46,.72),rgba(9,14,26,.5)); }
.cp-head{ display:flex; align-items:center; gap:14px; }
.cp-orb{ width:48px; height:48px; flex:none; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:20px; color:#eaf4ff; transition:.5s;
  background:radial-gradient(circle at 40% 32%, color-mix(in srgb,var(--cy) 55%, #0a1020), rgba(10,16,32,.4)); box-shadow:0 0 22px color-mix(in srgb,var(--cy) 45%, transparent); }
.cp-orb.think{ animation:cpthink 1.3s ease-in-out infinite; }
@keyframes cpthink{ 0%,100%{ transform:scale(1); } 50%{ transform:scale(1.09); box-shadow:0 0 32px color-mix(in srgb,var(--cy) 65%, transparent); } }
.cp-live{ font-size:11px; font-weight:700; color:var(--ok); letter-spacing:.05em; margin-left:6px; vertical-align:middle; }
.cp-status{ font-size:12.5px; color:#9fb6d4; margin-top:3px; }
.cp-voice{ font-size:12px; color:#cfe0f5; display:flex; align-items:center; gap:5px; cursor:pointer; user-select:none; white-space:nowrap; }
.cp-feed{ margin-top:12px; display:flex; flex-direction:column; gap:8px; max-height:300px; overflow:auto; }
.cp-msg{ display:flex; gap:11px; align-items:flex-start; background:rgba(8,14,28,.55); border:1px solid var(--bd); border-left:3px solid var(--cpc,#39e1ff); border-radius:10px; padding:10px 13px; animation:cpin .4s ease; }
@keyframes cpin{ from{ opacity:0; transform:translateY(-6px); } to{ opacity:1; transform:none; } }
.cp-msg i.ic{ margin-top:2px; color:var(--cpc,#39e1ff); flex:none; }
.cp-msg .body{ flex:1; }
.cp-msg .tx{ font-size:13px; line-height:1.45; color:#dfeaf7; }
.cp-msg .tm{ font-size:10px; color:#6f819a; margin-top:3px; }
.cp-msg .act{ margin-top:8px; display:flex; gap:7px; flex-wrap:wrap; }
.cp-act{ font-size:11px; font-weight:700; padding:4px 10px; border-radius:8px; cursor:pointer; text-decoration:none; display:inline-flex; align-items:center; gap:5px;
  background:color-mix(in srgb,var(--cpc,#39e1ff) 16%, transparent); border:1px solid color-mix(in srgb,var(--cpc,#39e1ff) 45%, transparent); color:#eef6ff; }
.cp-act:hover{ background:color-mix(in srgb,var(--cpc,#39e1ff) 30%, transparent); }
/* ══ GAMER HUD — Performance Score · reactive orb · optimization tips ══ */
.ghud{ grid-column:1/-1; display:grid; grid-template-columns:300px 1fr; gap:26px; align-items:center; background:linear-gradient(120deg,rgba(20,28,52,.72),rgba(9,14,26,.55)); }
.ghud-score{ border-right:1px solid rgba(255,255,255,.07); padding-right:22px; }
@media(max-width:820px){ .ghud{ grid-template-columns:1fr; } .ghud-score{ border-right:0; border-bottom:1px solid rgba(255,255,255,.07); padding-right:0; padding-bottom:16px; } }
.ghud-score{ display:flex; flex-direction:column; align-items:center; gap:12px; }
.perf-orb{ width:62px; height:62px; border-radius:50%; display:grid; place-items:center; font-size:30px; --orbC:#39e1ff; --orbG:rgba(57,225,255,.55);
  background:radial-gradient(circle at 40% 32%, var(--orbC), rgba(10,16,32,.2) 72%); box-shadow:0 0 26px var(--orbG); transition:box-shadow .6s, background .6s; }
.perf-orb.pulse{ animation:orbPulse 1.1s ease-in-out infinite; }
@keyframes orbPulse{ 0%,100%{ transform:scale(1); } 50%{ transform:scale(1.13); } }
.perf-ring{ position:relative; width:132px; height:132px; --scoreC:#2ee66e; }
.perf-ring svg{ transform:rotate(-90deg); width:132px; height:132px; }
.perf-ring .rg-bg{ fill:none; stroke:rgba(255,255,255,.08); stroke-width:9; }
.perf-ring .rg-fg{ fill:none; stroke:var(--scoreC); stroke-width:9; stroke-linecap:round; stroke-dasharray:351.9; stroke-dashoffset:351.9; transition:stroke-dashoffset .8s cubic-bezier(.2,.8,.2,1), stroke .6s; filter:drop-shadow(0 0 6px var(--scoreC)); }
.perf-ring .rg-num{ position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; }
.perf-ring .rg-num b{ font-size:40px; font-weight:800; line-height:1; }
.perf-ring .rg-num span{ font-size:9.5px; text-transform:uppercase; letter-spacing:.11em; color:#8fb4dd; margin-top:4px; font-weight:700; }
.perf-bars{ width:100%; display:flex; flex-direction:column; gap:7px; }
.perf-bars .pb .pl{ display:flex; justify-content:space-between; font-size:10.5px; color:#9fb6d6; margin-bottom:2px; text-transform:uppercase; letter-spacing:.05em; }
.perf-bars .pb .track{ height:6px; background:rgba(255,255,255,.07); border-radius:5px; overflow:hidden; }
.perf-bars .pb .fill{ height:100%; border-radius:5px; transition:width .6s, background .6s; }
.tips{ list-style:none; margin:8px 0 0; padding:0; display:flex; flex-direction:column; gap:8px; }
.tips .tip{ display:flex; gap:10px; align-items:flex-start; font-size:13px; line-height:1.45; background:rgba(8,14,28,.5); border:1px solid var(--bd); border-left:3px solid var(--tipC,#39e1ff); border-radius:9px; padding:9px 12px; }
.tips .tip i{ margin-top:2px; color:var(--tipC,#39e1ff); flex:none; }
.tips .tip.good{ --tipC:#2ee66e; } .tips .tip.warn{ --tipC:#f0a92c; } .tips .tip.crit{ --tipC:#ff4d6d; } .tips .tip.muted{ --tipC:#5b6b7a; color:#8fb4dd; }
/* ── 3D COMMAND DECK (immersive fullscreen cockpit) ── */
#deck{ position:fixed; inset:0; z-index:99999; background:radial-gradient(ellipse at 50% 38%,#0a1226 0%,#04060d 68%,#000 100%); display:none; overflow:hidden; }
#deck.on{ display:block; }
#deckgl{ position:absolute; inset:0; width:100%; height:100%; display:block; }
#deckTitle{ position:absolute; top:24px; left:0; right:0; text-align:center; pointer-events:none; z-index:3; }
#deckTitle .gm{ font-size:clamp(24px,3.4vw,40px); font-weight:900; letter-spacing:3px; text-transform:uppercase; background:linear-gradient(90deg,#39e1ff,#b06bff,#ff4dd0); -webkit-background-clip:text; background-clip:text; color:transparent; filter:drop-shadow(0 0 26px rgba(120,140,255,.35)); }
#deckTitle .sub{ font-size:12px; letter-spacing:5px; color:#8fb0dd; text-transform:uppercase; margin-top:4px; }
#deckLabels{ position:absolute; inset:0; z-index:2; pointer-events:none; }
.dlab{ position:absolute; transform:translate(-50%,-50%); text-align:center; will-change:transform,opacity; white-space:nowrap; }
.dlab .dl{ font-size:14px; letter-spacing:2.5px; font-weight:700; text-transform:uppercase; color:rgba(196,216,246,.85); text-shadow:0 1px 6px rgba(0,0,0,.8); }
.dlab .dv{ font-size:46px; font-weight:900; font-variant-numeric:tabular-nums; line-height:1.02; text-shadow:0 2px 4px #000,0 2px 22px rgba(0,0,0,.85); color:#f2f8ff; }
.dlab .dv small{ font-size:19px; opacity:.7; font-weight:700; }
.dlab .du{ font-size:12px; font-weight:600; color:rgba(170,196,230,.72); margin-top:3px; letter-spacing:1.5px; text-shadow:0 1px 5px rgba(0,0,0,.8); }
.dlab.c-ok .dv{ color:#39e1ff; } .dlab.c-good .dv{ color:#2ee66e; } .dlab.c-warn .dv{ color:#f0a92c; } .dlab.c-crit .dv{ color:#ff4d6d; text-shadow:0 0 18px rgba(255,77,109,.5); }
#deckBar{ position:absolute; bottom:26px; left:0; right:0; display:flex; justify-content:center; gap:16px; z-index:3; pointer-events:none; flex-wrap:wrap; padding:0 16px; }
#deckBar .pill{ background:rgba(10,16,32,.5); border:1px solid rgba(120,150,255,.22); border-radius:30px; padding:8px 18px; font-size:13px; color:#cfe0f5; backdrop-filter:blur(9px); }
#deckBar .pill b{ color:#fff; } #deckBar .pill.on{ border-color:rgba(46,230,110,.55); color:#c9ffdf; }
#deckExit{ position:absolute; top:20px; right:24px; z-index:4; background:rgba(20,26,44,.6); border:1px solid rgba(255,120,150,.42); color:#ffd0da; border-radius:10px; padding:9px 15px; font-size:13px; cursor:pointer; pointer-events:auto; backdrop-filter:blur(6px); }
#deckExit:hover{ background:rgba(255,77,109,.28); }
#deckBoost{ position:absolute; top:20px; left:24px; z-index:4; background:rgba(20,26,44,.6); border:1px solid rgba(57,225,255,.42); color:#dff3ff; border-radius:10px; padding:9px 16px; font-size:13px; font-weight:800; letter-spacing:.6px; cursor:pointer; pointer-events:auto; backdrop-filter:blur(6px); transition:.2s; }
#deckBoost:hover{ box-shadow:0 0 20px rgba(57,225,255,.35); transform:translateY(-1px); }
#deckBoost.on{ background:rgba(46,230,110,.2); border-color:rgba(46,230,110,.6); color:#c9ffdf; box-shadow:0 0 26px rgba(46,230,110,.4); }
#deckFan{ position:absolute; top:66px; right:24px; z-index:4; display:flex; align-items:center; gap:8px; background:rgba(20,26,44,.6); border:1px solid rgba(120,150,255,.3); border-radius:10px; padding:7px 13px; font-size:12px; color:#cfe0f5; backdrop-filter:blur(6px); pointer-events:auto; }
#deckFan i{ color:#39e1ff; } #deckFan select{ background:rgba(10,16,32,.75); color:#dbe6f5; border:1px solid rgba(120,150,255,.3); border-radius:8px; padding:4px 9px; font-size:12px; cursor:pointer; max-width:230px; }
#deckFan #deckFanMsg{ font-size:11px; }
#deckHint{ position:absolute; bottom:7px; left:0; right:0; text-align:center; font-size:11px; color:rgba(140,165,200,.5); z-index:3; pointer-events:none; }
#deckSpecs{ position:absolute; top:96px; left:26px; z-index:3; width:230px; background:rgba(9,14,28,.42); border:1px solid rgba(120,150,255,.2); border-radius:14px; padding:14px 16px; backdrop-filter:blur(10px); pointer-events:none; animation:specfloat 6s ease-in-out infinite; box-shadow:0 10px 40px rgba(0,0,0,.35); }
#deckSpecs .sh{ font-size:11px; letter-spacing:3px; color:#8fb0dd; text-transform:uppercase; margin-bottom:9px; }
#deckSpecs .sr{ display:flex; justify-content:space-between; align-items:baseline; gap:10px; font-size:12px; padding:5px 0; border-top:1px solid rgba(120,150,255,.08); }
#deckSpecs .sr span{ color:rgba(160,185,220,.7); } #deckSpecs .sr b{ color:#dfeeff; font-weight:700; text-align:right; font-variant-numeric:tabular-nums; }
@keyframes specfloat{ 0%,100%{ transform:translateY(0) rotateY(3deg); } 50%{ transform:translateY(-8px) rotateY(-3deg); } }
#deckCopilot{ position:absolute; top:120px; right:24px; z-index:3; width:252px; background:rgba(9,14,28,.44); border:1px solid rgba(120,150,255,.2); border-radius:14px; padding:13px 15px; backdrop-filter:blur(10px); box-shadow:0 10px 40px rgba(0,0,0,.35); pointer-events:none; }
#deckCopilot .ch{ font-size:11px; letter-spacing:1.4px; color:#8fb4dd; font-weight:700; display:flex; align-items:center; gap:7px; }
#deckCopilot .ch i{ color:var(--cy); }
.dcp-live{ font-size:9px; color:var(--ok); margin-left:auto; letter-spacing:.5px; }
.dcp-status{ font-size:11.5px; color:#9fb6d4; margin-top:8px; line-height:1.4; }
.dcp-msg{ font-size:12px; color:#eaf2fc; margin-top:9px; line-height:1.45; border-left:3px solid var(--dcpc,#39e1ff); padding-left:9px; display:none; }
.dcp-msg.on{ display:block; }
.dcp-msg .dt{ font-size:9px; color:#6f819a; display:block; margin-top:3px; }
/* ══ Player DNA emblem on the Gaming Deck ══ */
#deckDna{ position:absolute; left:24px; bottom:80px; z-index:3; width:248px; background:rgba(11,10,28,.46); border:1px solid rgba(176,107,255,.3); border-radius:14px; padding:12px 14px; backdrop-filter:blur(10px); box-shadow:0 10px 40px rgba(0,0,0,.4); pointer-events:none; }
#deckDna .dd-head{ display:flex; align-items:center; gap:10px; }
#deckDna .dd-emo{ font-size:28px; filter:drop-shadow(0 0 10px rgba(176,107,255,.6)); }
#deckDna .dd-arch{ font-size:14px; font-weight:900; background:linear-gradient(90deg,var(--cy),var(--pk)); -webkit-background-clip:text; background-clip:text; color:transparent; }
#deckDna .dd-rank{ font-size:11px; color:#9fb6d6; } #deckDna .dd-rank b{ color:#fff; }
.dd-traits{ display:flex; flex-direction:column; gap:4px; margin-top:9px; }
.dd-traits .r{ display:flex; align-items:center; gap:7px; font-size:9.5px; color:#9fb6d6; }
.dd-traits .r .pl{ width:56px; } .dd-traits .r .tk{ flex:1; height:5px; background:rgba(255,255,255,.06); border-radius:3px; overflow:hidden; } .dd-traits .r .tf{ height:100%; border-radius:3px; }
.dd-ach{ display:flex; flex-wrap:wrap; gap:5px; margin-top:10px; }
.dd-ach .b{ font-size:15px; filter:grayscale(1); opacity:.4; } .dd-ach .b.on{ filter:none; opacity:1; text-shadow:0 0 8px rgba(240,169,44,.7); }
/* ══ Player DNA + Achievements card (gaming.php) ══ */
.pdna{ grid-column:1/-1; display:grid; grid-template-columns:minmax(300px,400px) 1fr; gap:24px; background:linear-gradient(120deg,rgba(24,18,52,.72),rgba(9,14,26,.55)); }
@media(max-width:820px){ .pdna{ grid-template-columns:1fr; } }
.pdna-id{ display:flex; align-items:center; gap:16px; flex-wrap:wrap; }
.pdna-emblem{ font-size:46px; filter:drop-shadow(0 0 14px rgba(176,107,255,.6)); }
.pdna-ring{ position:relative; width:96px; height:96px; flex:none; }
.pdna-ring svg{ width:96px; height:96px; transform:rotate(-90deg); }
.pr-bg{ fill:none; stroke:rgba(255,255,255,.08); stroke-width:8; }
.pr-fg{ fill:none; stroke:var(--pk); stroke-width:8; stroke-linecap:round; stroke-dasharray:326.7; stroke-dashoffset:326.7; transition:stroke-dashoffset 1s cubic-bezier(.2,.8,.2,1); filter:drop-shadow(0 0 6px var(--pk)); }
.pdna-lvl{ position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; }
.pdna-lvl b{ font-size:26px; font-weight:900; } .pdna-lvl span{ font-size:9px; letter-spacing:.1em; text-transform:uppercase; color:#9fb6d6; }
.pdna-meta{ flex:1; min-width:190px; }
.pdna-arch{ font-size:20px; font-weight:900; background:linear-gradient(90deg,var(--cy),var(--pk)); -webkit-background-clip:text; background-clip:text; color:transparent; }
.pdna-desc{ font-size:12px; color:#9fb6d6; margin:2px 0 9px; line-height:1.4; }
.pdna-stats{ display:flex; gap:14px; flex-wrap:wrap; font-size:11px; color:#8fb4dd; margin-bottom:9px; }
.pdna-stats b{ color:#eaf2fc; font-size:14px; }
.pdna-traits{ display:flex; flex-direction:column; gap:5px; }
.ptrait{ display:flex; align-items:center; gap:8px; font-size:10.5px; }
.ptrait .pl{ width:66px; color:#9fb6d6; } .ptrait .tk{ flex:1; height:6px; background:rgba(255,255,255,.06); border-radius:4px; overflow:hidden; } .ptrait .tf{ height:100%; border-radius:4px; }
.pdna-ach h3{ font-size:14px; margin:0 0 4px; }
.ach-grid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); gap:9px; }
.ach{ display:flex; gap:9px; align-items:flex-start; background:rgba(8,14,28,.5); border:1px solid var(--bd); border-radius:11px; padding:8px 10px; position:relative; overflow:hidden; opacity:.5; filter:grayscale(.7); transition:.3s; }
.ach.on{ opacity:1; filter:none; border-color:rgba(240,169,44,.5); box-shadow:0 0 16px rgba(240,169,44,.16); }
.ach .ae{ font-size:22px; flex:none; line-height:1; } .ach .an{ font-size:11.5px; font-weight:800; } .ach .ad{ font-size:9.5px; color:#8fb4dd; line-height:1.3; }
.ach .apg{ position:absolute; left:0; bottom:0; height:3px; background:linear-gradient(90deg,var(--cy),var(--pk)); }
.ach.on .apg{ background:#f0a92c; }
.dna-i{ cursor:pointer; font-size:13px; color:#8fb4dd; opacity:.85; user-select:none; } .dna-i:hover{ opacity:1; color:var(--cy); }
.ptrait .pl{ cursor:help; } .ptrait .pl.q{ border-bottom:1px dotted rgba(160,185,220,.4); }
.dna-info{ margin-top:10px; background:rgba(8,14,28,.6); border:1px solid var(--bd); border-radius:10px; padding:10px 12px; font-size:11.5px; line-height:1.5; color:#b8c8de; }
.dna-info b{ color:#eaf2fc; } .dna-info .row{ margin:3px 0; }
#deckfanhint{ position:absolute; bottom:70px; left:0; right:0; text-align:center; font-size:10px; letter-spacing:2px; text-transform:uppercase; color:rgba(140,165,200,.4); z-index:2; pointer-events:none; }
.fanlab{ position:absolute; transform:translate(-50%,-50%); text-align:center; pointer-events:none; white-space:nowrap; will-change:transform,opacity; }
.fanlab .fn{ font-size:12.5px; font-weight:600; letter-spacing:.5px; color:rgba(202,222,248,.9); max-width:150px; overflow:hidden; text-overflow:ellipsis; text-shadow:0 1px 5px rgba(0,0,0,.85); }
.fanlab .fr{ font-size:20px; font-weight:800; color:#8bf3ff; font-variant-numeric:tabular-nums; text-shadow:0 2px 8px rgba(0,0,0,.8); } .fanlab.stopped .fr{ color:#ff4d6d; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); nm_gamers_hub_pill(); ?>
<video autoplay muted loop playsinline id="bg-video" style="position:fixed;inset:0;z-index:-2;object-fit:cover;min-width:100%;min-height:100%;opacity:.10"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<canvas id="gbg"></canvas>

<!-- ══ 3D COMMAND DECK — immersive fullscreen cockpit ══ -->
<div id="deck">
  <canvas id="deckgl"></canvas>
  <div id="deckTitle"><div class="gm" id="deckGame">NEURU</div><div class="sub" id="deckRigName">command deck</div></div>
  <div id="deckLabels"></div>
  <div id="deckSpecs">
    <div class="sh">◈ RIG SPECS</div>
    <div class="sr"><span>GPU</span><b id="spGpu">—</b></div>
    <div class="sr"><span>VRAM</span><b id="spVram">—</b></div>
    <div class="sr"><span>RAM</span><b id="spRam">—</b></div>
    <div class="sr"><span>CPU load</span><b id="spCpu">—</b></div>
    <div class="sr"><span>Storage</span><b id="spDisk">—</b></div>
    <div class="sr"><span>Sensors</span><b id="spSens">—</b></div>
  </div>
  <button id="deckExit" onclick="closeDeck()"><i class="fa-solid fa-xmark"></i> Exit &nbsp;·&nbsp; Esc</button>
  <button id="deckBoost" onclick="toggleBoost()"><i class="fa-solid fa-bolt"></i> <span id="deckBoostTxt">GAMEMODE OFF</span></button>
  <div id="deckFan"><i class="fa-solid fa-fan"></i> <select id="deckFanSel" onchange="deckFanApply(this.value)"><option value="">Fan profile…</option></select> <span id="deckFanMsg"></span></div>
  <div id="deckCopilot">
    <div class="ch"><i class="fa-solid fa-robot"></i> NEURU COPILOT <span class="dcp-live" id="dcpLive">● watching</span></div>
    <div class="dcp-status" id="dcpStatus">Launch a game — I'll watch your rig live.</div>
    <div class="dcp-msg" id="dcpMsg"></div>
  </div>
  <div id="deckDna">
    <div class="dd-head"><span class="dd-emo" id="ddEmo">🌱</span><div><div class="dd-arch" id="ddArch">Player DNA</div><div class="dd-rank">Lv <b id="ddLvl">1</b> · <span id="ddRank">Bronze</span> · <span id="ddAchN">0/0</span></div></div></div>
    <div class="dd-traits" id="ddTraits"></div>
    <div class="dd-ach" id="ddAch"></div>
  </div>
  <div id="deckBar">
    <span class="pill" id="dpSession">⏱ —</span>
    <span class="pill" id="dpBoost">Game Mode —</span>
    <span class="pill" id="dpNet">🌐 ↓ — &nbsp; ↑ —</span>
  </div>
  <div id="deckfanhint">◇ cooling ◇</div>
  <div id="deckHint">NEURU Gaming Deck — drag to orbit · scroll to zoom · Esc to exit</div>
</div>

<div class="gwrap">
  <div class="ghead">
    <div><div class="gtitle"><i class="fa-solid fa-gamepad"></i> GAME MODE</div><div class="muted">futuristic rig command center · reuses Windows + GPU telemetry</div></div>
    <select class="rig" id="rig" onchange="pickRig()"><option value="">Loading rigs…</option></select>
    <div class="hdrctl">
      <select id="theme" onchange="setTheme(this.value)" title="Screen theme">
        <option value="auto">✨ Auto skin (game)</option><option value="">🌆 Synthwave</option><option value="t-matrix">🟢 Matrix</option><option value="t-neon">🔵 Neon Blue</option><option value="t-obsidian">⬛ Obsidian</option>
      </select>
      <button class="deckbtn" onclick="openDeck()" title="Gaming Deck — immersive 3D fullscreen cockpit"><i class="fa-solid fa-cube"></i> Gaming Deck</button>
      <a class="deckbtn" href="game_lab.php" style="text-decoration:none" title="Game Lab — one-click optimizers: network heal, crash shield, drivers, storage, FPS, auto-repair"><i class="fa-solid fa-flask-vial"></i> Game Lab</a>
      <a class="deckbtn" href="reality.php" style="text-decoration:none" title="Parallel Reality Engine — preview 4 futures of your rig in 3D, then collapse the one you want into reality"><i class="fa-solid fa-atom"></i> Parallel Reality</a>
      <a class="deckbtn" href="synaptic.php" style="text-decoration:none" title="Synaptic Map — your reflexes mapped against your rig's telemetry as a live 3D neural network + Cyborg Profile"><i class="fa-solid fa-brain"></i> Synaptic Map</a>
      <a class="deckbtn" href="pc_troubleshoot.php" style="text-decoration:none" title="PC Doctor — virtualize & troubleshoot your PC hardware in 3D"><i class="fa-solid fa-microchip"></i> PC Doctor</a>
      <a class="deckbtn" href="net_doctor.php" style="text-decoration:none" title="Connection Doctor — is the lag your WiFi, your ISP, or the game? 3-hop path + history"><i class="fa-solid fa-wave-square"></i> Connection Doctor</a>
      <a class="deckbtn" href="fan_profiler.php" style="text-decoration:none" title="Fan Profiler — visualize & optimize your FanControl fan curves to run cooler"><i class="fa-solid fa-fan"></i> Fan Profiler</a>
      <button onclick="toggleKiosk()" title="Kiosk / Sensor-Panel — fullscreen for a 2nd monitor or in-case LCD"><i class="fa-solid fa-expand"></i></button>
    </div>
    <div class="gmode"><button class="gmbtn" id="gmbtn" onclick="toggleBoost()">Game On</button></div>
  </div>

  <div id="skinToast"></div>

  <div class="grid">

    <div class="card c-hero"><h3><i class="fa-solid fa-bolt"></i> Game Performance</h3>
      <canvas id="fpsCanvas"></canvas>
      <div class="gameName" id="gameName">No game detected</div><div class="gamePub" id="gamePub">launch a game — NEURU auto-detects it</div>
      <div class="skin-badge" id="skinBadge"></div>
      <div style="margin-top:4px"><span class="chip" style="padding:2px 9px;cursor:pointer;font-size:11px" onclick="detectDebug()" title="See exactly which processes NEURU sees and why one did/didn't match">🔍 Why not detected?</span></div>
      <pre id="detectDbg" style="display:none;max-height:230px;overflow:auto;background:rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.1);border-radius:8px;padding:9px 11px;margin-top:8px;font-size:11px;line-height:1.5;white-space:pre-wrap"></pre>
      <div class="tiles"><div class="tile"><div class="n" id="t-fps">—</div><div class="l">FPS</div></div>
        <div class="tile"><div class="n" id="t-low1">—</div><div class="l">1% low</div></div>
        <div class="tile"><div class="n" id="t-low01">—</div><div class="l">0.1% low</div></div></div>
      <div class="muted" id="fpsNote" style="margin-top:8px">FPS + 1% lows need the PresentMon helper (Phase 2). GPU load shown live now.</div>
    </div>

    <div class="card c-thermal"><h3><i class="fa-solid fa-temperature-three-quarters"></i> Thermal &amp; GPU Reactor</h3>
      <div style="display:flex;align-items:center;gap:16px">
        <div><div class="big" id="gpuTemp">—<span class="unit">°C</span></div><div class="muted" id="gpuName">GPU</div></div>
        <div style="flex:1">
          <div class="muted">GPU load <span id="gpuUtil">—</span>%</div><div class="bar"><span id="gpuUtilBar" style="width:0;background:linear-gradient(90deg,#39e1ff,#b06bff)"></span></div>
          <div class="muted">VRAM <span id="vram">—</span></div><div class="bar"><span id="vramBar" style="width:0;background:linear-gradient(90deg,#2ee66e,#f0a92c)"></span></div>
          <div class="fanwrap">
            <svg viewBox="0 0 100 100" width="46" height="46" aria-label="fan">
              <defs><radialGradient id="fg" cx="50%" cy="50%" r="60%"><stop offset="0%" stop-color="#8bf3ff"/><stop offset="100%" stop-color="#b06bff"/></radialGradient></defs>
              <g id="fanBlades" fill="url(#fg)" opacity=".9">
                <path d="M50,50 Q34,14 50,7 Q66,20 50,50 Z" transform="rotate(0 50 50)"/>
                <path d="M50,50 Q34,14 50,7 Q66,20 50,50 Z" transform="rotate(72 50 50)"/>
                <path d="M50,50 Q34,14 50,7 Q66,20 50,50 Z" transform="rotate(144 50 50)"/>
                <path d="M50,50 Q34,14 50,7 Q66,20 50,50 Z" transform="rotate(216 50 50)"/>
                <path d="M50,50 Q34,14 50,7 Q66,20 50,50 Z" transform="rotate(288 50 50)"/>
              </g>
              <circle cx="50" cy="50" r="8" fill="#0b1220" stroke="#39e1ff" stroke-width="2"/>
            </svg>
            <div class="fanpct"><span id="fan">—</span>% <span class="muted" style="font-size:11px">fan</span></div>
          </div>
        </div>
      </div>
      <div class="muted" id="hotSensor" style="margin-top:9px;font-size:12px"></div>
      <div class="thr-alert" id="thrAlert"><i class="fa-solid fa-fire"></i> THERMAL THROTTLING — the GPU is capping clocks from heat.</div>
    </div>

    <div class="card c-radar"><h3><i class="fa-solid fa-satellite-dish"></i> Game Ping Radar</h3>
      <div id="radarHead" class="muted">Pick a rig — radar pings your game's server regions.</div>
      <canvas id="radarCanvas"></canvas>
      <div id="regions"></div>
      <div class="verdict" id="pingVerdict"></div>
      <span class="chip" onclick="openLagReport()" style="margin-top:8px;display:inline-block;background:rgba(255,77,109,.14);border-color:rgba(255,77,109,.35)"><i class="fa-solid fa-file-lines"></i> Proof-of-Lag report (for your ISP)</span>
      <details style="margin-top:8px"><summary style="cursor:pointer;color:#8bf3ff;font-size:11px">⚙ map this game's real servers (custom ping targets)</summary>
        <div style="margin-top:6px">
          <input id="ms-game" class="ms-in" placeholder="game name (auto-fills the detected game)" style="width:100%;margin-bottom:5px">
          <div style="display:grid;grid-template-columns:.8fr 1.3fr;gap:5px">
            <input id="ms-r1" class="ms-in" placeholder="region e.g. NA-East"><input id="ms-h1" class="ms-in" placeholder="server host / IP">
            <input id="ms-r2" class="ms-in" placeholder="region e.g. EU"><input id="ms-h2" class="ms-in" placeholder="server host / IP">
            <input id="ms-r3" class="ms-in" placeholder="region"><input id="ms-h3" class="ms-in" placeholder="server host / IP">
          </div>
          <span class="chip" onclick="saveGameServers()" style="margin-top:6px;display:inline-block">Save &amp; use</span> <span class="muted" id="msNote" style="font-size:11px"></span>
          <div class="muted" style="font-size:10px;margin-top:4px">NEURU pings these FROM your PC whenever this game is running. Leave empty to reset.</div>
        </div>
      </details>
    </div>

    <!-- ══ GAMER HUD: Performance Score · reactive orb · optimization tips ══ -->
    <div class="card ghud">
      <div class="ghud-score">
        <div class="perf-orb" id="perfOrb"><span id="orbFace">🎮</span></div>
        <div class="perf-ring">
          <svg viewBox="0 0 132 132"><circle class="rg-bg" cx="66" cy="66" r="56"></circle><circle class="rg-fg" id="scoreRing" cx="66" cy="66" r="56"></circle></svg>
          <div class="rg-num"><b id="scoreVal">—</b><span id="scoreGrade">rig score</span></div>
        </div>
        <div class="perf-bars" id="perfBars"></div>
      </div>
      <div class="ghud-tips">
        <h3><i class="fa-solid fa-wand-magic-sparkles"></i> Optimization Tips</h3>
        <ul class="tips" id="tipsList"><li class="tip muted"><i class="fa-solid fa-gamepad"></i><span>Launch a game — NEURU analyzes your rig live and coaches you here.</span></li></ul>
      </div>
    </div>
    <div class="card cpilot" id="cpilotCard">
      <div class="cp-head">
        <div class="cp-orb" id="cpOrb"><i class="fa-solid fa-robot"></i></div>
        <div style="flex:1;min-width:0">
          <h3 style="margin:0"><i class="fa-solid fa-brain"></i> NEURU Copilot <span class="cp-live" id="cpLive">● watching</span></h3>
          <div class="cp-status" id="cpStatus">Launch a game — I'll watch your rig and speak up the moment something could cost you frames.</div>
        </div>
        <label class="cp-voice" title="NEURU speaks micro-alerts out loud (browser voice)"><input type="checkbox" id="cpVoice" onchange="cpToggleVoice()"> <i class="fa-solid fa-volume-high"></i> Voice</label>
      </div>
      <div class="cp-feed" id="cpFeed"></div>
    </div>
    <div class="card pdna" id="pdnaCard" style="display:none">
      <div class="pdna-id">
        <div class="pdna-emblem" id="pdnaEmblem">🌱</div>
        <div class="pdna-ring"><svg viewBox="0 0 120 120"><circle class="pr-bg" cx="60" cy="60" r="52"></circle><circle class="pr-fg" id="pdnaRing" cx="60" cy="60" r="52"></circle></svg><div class="pdna-lvl"><b id="pdnaLvl">—</b><span id="pdnaRank">rank</span></div></div>
        <div class="pdna-meta">
          <div style="display:flex;align-items:center;gap:8px"><div class="pdna-arch" id="pdnaArch">Rising Contender</div><span class="dna-i" onclick="toggleDnaInfo()" title="What do these scores mean?"><i class="fa-solid fa-circle-info"></i></span></div>
          <div class="pdna-desc" id="pdnaDesc">Play games — NEURU reads your telemetry and builds your gamer DNA.</div>
          <div class="pdna-stats" id="pdnaStats"></div>
          <div class="pdna-traits" id="pdnaTraits"></div>
          <div class="dna-info" id="pdnaInfo" style="display:none"></div>
        </div>
      </div>
      <div class="pdna-ach">
        <h3><i class="fa-solid fa-trophy" style="color:#f0a92c"></i> Achievements <span class="muted" id="pdnaAchCount" style="font-weight:400;font-size:11px"></span></h3>
        <div class="ach-grid" id="pdnaAchGrid"></div>
      </div>
    </div>
    <div class="card c-boost"><h3><i class="fa-solid fa-rocket"></i> 1-Click Game Booster</h3>
      <div class="muted">High-Performance power plan + stops the junk (Spooler, SysMain, Search index, Telemetry). Fully reversible.</div>
      <div class="boostlog" id="boostlog"></div>
      <div id="boostChips" style="margin-top:8px"></div>
    </div>

    <div class="card c-hog"><h3><i class="fa-solid fa-wifi"></i> Bandwidth Hog Detector</h3>
      <div class="hoglist" id="hoglist"><div class="muted">Who's eating the pipe while you play (Phase 2: per-process bandwidth).</div></div>
    </div>

    <div class="card c-sys"><h3><i class="fa-solid fa-microchip"></i> System</h3>
      <div class="muted">CPU <span id="cpu">—</span>%</div><div class="bar"><span id="cpuBar" style="width:0;background:linear-gradient(90deg,#39e1ff,#ff4d6d)"></span></div>
      <div class="muted">RAM <span id="ram">—</span></div><div class="bar"><span id="ramBar" style="width:0;background:linear-gradient(90deg,#b06bff,#39e1ff)"></span></div>
      <div class="muted" id="sessTimer" style="margin-top:10px"></div>
    </div>
  </div>

  <div class="card" style="margin-top:14px">
    <h3><i class="fa-solid fa-fan"></i> Fans &amp; Sensors <span class="muted" id="sensSrc" style="text-transform:none;letter-spacing:0"></span></h3>
    <div id="sensNeed" style="display:none">
      <div class="muted" style="margin-bottom:8px">To see <b>every fan RPM and temperature</b> (CPU, GPU, motherboard, case fans, VRM, drives…), run a tiny free tool on this PC. NEURU reads it over SSH — nothing else to configure.</div>
      <div style="background:rgba(57,225,255,.08);border:1px solid rgba(57,225,255,.3);border-radius:10px;padding:9px 13px;font-size:12px;color:#a9e6ff;margin-bottom:8px"><b>💡 It’s a portable app — there’s NO installer.</b> The ZIP you downloaded already IS the program. You just run the .exe.</div>
      <ol style="font-size:13px;line-height:1.9;color:#cfe4ff;margin:4px 0">
        <li><b>Extract the ZIP</b> to a permanent folder — e.g. <code style="background:#0c1424;padding:1px 5px;border-radius:4px">C:\LibreHardwareMonitor</code> (don’t leave it in Downloads/Temp).</li>
        <li><b>Right-click <code style="background:#0c1424;padding:1px 5px;border-radius:4px">LibreHardwareMonitor.exe</code> → “Run as administrator”</b> (needed to read CPU / motherboard chips). If Windows SmartScreen warns → “More info → Run anyway”.</li>
        <li><b>Turn on the Remote Web Server</b> (this is what NEURU reads):
          <div style="margin:2px 0 2px 14px;color:#8bf3ff">Options ▸ Remote Web Server ▸ <b>Run</b> &nbsp;— leave the <b>Port at 8085</b> (default). Authentication OFF.</div>
          <span class="muted">Newer LibreHardwareMonitor has no “Publish to WMI” checkbox — the Remote Web Server is the way (and NEURU also auto-detects WMI if your version publishes it).</span></li>
        <li>Also tick (optional, so it just works forever): <span style="color:#8bf3ff">☑ Run On Windows Startup · ☑ Run As Administrator · ☑ Start Minimized · ☑ Minimize To Tray</span>.</li>
        <li>Leave it running (it minimizes to the system tray). Then hit <b>refresh</b> here — all fans &amp; temps appear. 🌀</li>
      </ol>
      <div style="margin-top:8px"><a class="gmbtn" style="padding:8px 18px;font-size:13px;text-decoration:none;display:inline-block" href="https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/releases/latest" target="_blank"><i class="fa-solid fa-download"></i> Get LibreHardwareMonitor</a> <span class="chip" onclick="refreshSensors()">↻ It’s running — refresh</span></div>
    </div>
    <div id="sensBanner" style="display:none;margin-bottom:10px;background:rgba(240,169,44,.1);border:1px solid rgba(240,169,44,.4);border-radius:12px;padding:11px 14px;font-size:12px;color:#ffd9a0">
      <b>⚠ Only your GPU is showing.</b> OpenHardwareMonitor (2020, discontinued) can’t read modern CPUs / motherboards. For <b>CPU · motherboard · RAM · storage · case-fan</b> sensors, switch to <b><a href="https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/releases/latest" target="_blank" style="color:#39e1ff">LibreHardwareMonitor</a></b> and <b>run it as Administrator</b> (needed to read CPU/mobo chips), then <span class="chip" onclick="refreshSensors()" style="background:rgba(57,225,255,.15)">↻ refresh</span>.
    </div>
    <div id="sensBody" style="display:none">
      <div class="sframe"><div class="sframe-h">🌀 Fans <span id="fanCount" class="muted"></span> <span class="muted" style="text-transform:none;letter-spacing:0;font-weight:400">— click a name to label it (CPU / GPU / Case…)</span></div>
        <div id="fanGrid" class="fan-grid"></div></div>
      <div class="sframe"><div class="sframe-h">🌡 Temperatures <span id="tempCount" class="muted"></span></div>
        <div id="tempList" class="temp-grid"></div></div>
      <details style="margin-top:12px"><summary style="cursor:pointer;color:#8bf3ff;font-size:12px">Loads · clocks · power · voltage (all sensors)</summary><div id="sensMore" style="margin-top:8px;font-size:12px;line-height:2"></div></details>
    </div>
    <div class="muted" id="sensLoading">checking for LibreHardwareMonitor / OpenHardwareMonitor…</div>
  </div>

  <div class="card" style="margin-top:14px">
    <h3><i class="fa-solid fa-hard-drive"></i> Storage &amp; Game Library <span class="chip" onclick="loadDisks();loadGames()">↻ scan</span></h3>
    <div style="display:grid;grid-template-columns:1fr 1.2fr;gap:22px" id="storeGrid">
      <div>
        <div class="muted" style="margin-bottom:6px">💾 DISK USAGE</div>
        <div id="diskList"><div class="muted">scanning…</div></div>
        <div id="physList" style="margin-top:10px"></div>
      </div>
      <div>
        <div class="muted" style="margin-bottom:6px">🎮 INSTALLED GAMES <span id="gameCount"></span></div>
        <div style="display:flex;gap:6px;margin-bottom:6px"><input id="gf-input" placeholder="add a game folder — e.g. D:\XboxGames" style="flex:1;background:#111a2b;color:#dbe6f5;border:1px solid var(--bd);border-radius:8px;padding:7px 10px;font-size:12px;font-family:monospace"><span class="chip" onclick="addGameFolder()"><i class="fa-solid fa-plus"></i> add</span></div>
        <div id="gameFolders" class="muted" style="font-size:11px;margin-bottom:6px"></div>
        <div id="gameList" style="max-height:300px;overflow:auto"><div class="muted">scanning your drives &amp; stores…</div></div>
      </div>
    </div>
    <div class="muted" style="font-size:11px;margin-top:8px">Auto-scans Steam · Xbox · Epic · EA · Ubisoft · GOG folders on every drive + the registry. Add any custom folder above.</div>
  </div>

  <div class="card" style="margin-top:14px">
    <h3><i class="fa-solid fa-server"></i> Game Server Status <span class="chip" onclick="loadServers(true)">↻ refresh</span> <span class="muted" id="srvNote" style="text-transform:none;letter-spacing:0"></span></h3>
    <div class="muted" style="margin-bottom:4px">Most-played services — is the game up?</div>
    <div class="srv-grid" id="srvOfficial"><div class="muted">checking…</div></div>
    <div style="margin-top:16px;display:flex;align-items:center;gap:10px"><b style="font-size:13px">My servers</b><span class="chip" onclick="toggleAddSrv()"><i class="fa-solid fa-plus"></i> add your server</span></div>
    <div id="addSrv" style="display:none">
      <div class="addform">
        <input id="s-name" placeholder="Name (e.g. My Minecraft)" style="min-width:170px">
        <input id="s-host" placeholder="host or IP (e.g. mc.myserver.com)" style="min-width:200px">
        <input id="s-port" placeholder="port" type="number" style="width:90px">
        <select id="s-proto" onchange="protoHint()">
          <option value="minecraft">Minecraft (players + MOTD)</option>
          <option value="source">CS2 / Source (players + map)</option>
          <option value="tcp">Generic TCP (up/ping)</option>
          <option value="ping">Reachability</option>
        </select>
        <button class="gmbtn" style="padding:8px 18px;font-size:13px" onclick="addServer(this)">Add &amp; monitor</button>
      </div>
      <div class="muted" id="protoHint" style="margin:6px 2px">Minecraft Java: default port 25565 — NEURU shows live players + MOTD.</div>
    </div>
    <div class="srv-grid" id="srvCustom"></div>
  </div>

  <div class="card" style="margin-top:14px">
    <h3><i class="fa-solid fa-tower-broadcast"></i> OBS / Streamlabs Live Overlay <span class="chip" style="background:rgba(176,107,255,.16)">stream your stats</span></h3>
    <div class="muted" style="margin-bottom:10px">Generate a link, drop it into OBS as a <b>Browser Source</b>, and a transparent futuristic HUD (ping · FPS · GPU · CPU · net) appears live on your Twitch/YouTube — zero PC impact.</div>
    <div class="addform" style="align-items:center">
      <span class="muted">Rig: <b id="ovRig">— pick a rig above —</b></span>
      <select id="ov-theme"><option value="synthwave">🌆 Synthwave</option><option value="matrix">🟢 Matrix</option><option value="neon">🔵 Neon Blue</option><option value="obsidian">⬛ Dark Obsidian</option></select>
      <label class="muted"><input type="checkbox" id="ov-ping" checked> Ping</label>
      <label class="muted"><input type="checkbox" id="ov-fps" checked> FPS</label>
      <label class="muted"><input type="checkbox" id="ov-gpu" checked> GPU</label>
      <label class="muted"><input type="checkbox" id="ov-cpu" checked> CPU</label>
      <label class="muted"><input type="checkbox" id="ov-net" checked> Net</label>
      <button class="gmbtn" style="padding:8px 18px;font-size:13px" onclick="genOverlay(this)"><i class="fa-solid fa-link"></i> Generate URL</button>
    </div>
    <div id="ovResult" style="display:none;margin-top:12px">
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><input id="ovUrl" readonly style="flex:1;min-width:280px;background:#0c1424;color:#8bf3ff;border:1px solid var(--bd);border-radius:8px;padding:9px 12px;font-family:monospace;font-size:12px">
        <button class="chip" onclick="copyOv()">📋 Copy</button><button class="chip" onclick="window.open($('#ovUrl').value,'_blank')">↗ Preview</button></div>
      <div style="margin-top:10px;background:#05070d;border:1px solid var(--bd);border-radius:12px;overflow:hidden;height:110px"><iframe id="ovPreview" style="width:100%;height:100%;border:0;background:transparent"></iframe></div>
    </div>
    <details style="margin-top:12px"><summary style="cursor:pointer;color:#8bf3ff;font-size:13px">📖 How to add it to OBS / Streamlabs (step by step)</summary>
      <ol style="font-size:13px;line-height:1.9;color:#cfe4ff;margin:8px 0">
        <li><b>Generate</b> your URL above (pick your rig + theme + which stats to show) and click <b>Copy</b>.</li>
        <li>In <b>OBS Studio</b>: bottom-left <b>Sources</b> panel → click <b>＋</b> → choose <b>Browser</b> → <i>Create new</i> → OK.</li>
        <li><b>Paste your NEURU URL</b> into the <b>URL</b> field. Set <b>Width 640</b>, <b>Height 130</b>. Make sure <b>“Shutdown source when not visible”</b> is <u>off</u> so it keeps updating.</li>
        <li>Click <b>OK</b>. The HUD appears (transparent background). <b>Drag it</b> to a corner of your scene and resize.</li>
        <li><b>Streamlabs Desktop:</b> same idea — <b>Add Source → Browser Source → paste the URL</b>, set the size, done.</li>
        <li>That’s it — your live ping, FPS and temps now show on stream. It updates every ~2s and never touches your game’s performance. 🎮</li>
      </ol>
      <div class="muted">Tip: keep this link private — anyone with it can see your overlay stats. You can revoke it anytime below.</div>
    </details>
    <div id="ovList" style="margin-top:10px"></div>
  </div>

  <div class="card" style="margin-top:14px">
    <h3><i class="fa-solid fa-plug"></i> Automations — Discord &amp; Smart Home</h3>
    <div class="muted" style="margin-bottom:10px">NEURU pings your Discord channel on Game-Mode / thermal / lag events, and can trigger a Smart-Home webhook (Home Assistant / RGB lights / router QoS) when you go into Game Mode — zero PC impact.</div>
    <div class="addform" style="flex-direction:column;align-items:stretch;gap:10px">
      <div><div class="muted" style="margin-bottom:3px">🎮 Discord Webhook URL <span style="opacity:.6">(Server Settings → Integrations → Webhooks → New → Copy URL)</span></div>
        <input id="wh-discord" placeholder="https://discord.com/api/webhooks/…" style="width:100%"></div>
      <div><div class="muted" style="margin-bottom:3px">🏠 Smart-Home Webhook URL <span style="opacity:.6">(Home Assistant automation trigger / Hue / Govee bridge / router API)</span></div>
        <input id="wh-smarthome" placeholder="http://homeassistant.local:8123/api/webhook/gamemode" style="width:100%"></div>
      <div><button class="gmbtn" style="padding:8px 18px;font-size:13px" onclick="saveWebhooks(this,false)">Save</button>
        <span class="chip" onclick="saveWebhooks(null,true)">Send test 🔔</span> <span class="muted" id="whNote"></span></div>
    </div>
  </div>
</div>

<script>
const $=s=>document.querySelector(s);
function esc(s){ return (''+s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
let RIG=0, BOOST=false, vitalsTimer=null, radarTimer=null, fpsTimer=null, hogTimer=null, sensTimer=null, diskTimer=null, hudTimer=null, GAME=null, PM_OK=null;
// live snapshot the 3D Gaming Deck reads each frame (fed by the refresh* functions below)
const STATE={ game:null, gpu:{}, cpu:null, mem_used:0, mem_total:0, ping:null, loss:0, fps:null, low1:null, low01:null, rx:0, tx:0, hotTemp:null, tempScore:null, hotName:null, hotHw:null, topFan:null, fanCount:0, boost:false, rigName:'', session:null, fans:[], temps:[], disks:[], phys:[], diskTotal:0, diskFree:0, sensSrc:'', gpuOnly:false };
// a LIVE temperature reading — NOT a config threshold/limit (NVMe Warning/Critical temp, Distance-to-TjMax, sensor limits)
function _realTemp(n){ return !/distance to tjmax|tjmax|warning|critical|thermal sensor|high limit|low limit|resolution/i.test(n||''); }
// ══ GAMER HUD — Performance Score (0-100), reactive orb, auto optimization tips (all from STATE) ══
function _gclamp(v,a,b){ return Math.max(a,Math.min(b,v)); }
function _scoreCol(v){ return v>=80?'#2ee66e':v>=60?'#39e1ff':v>=40?'#f0a92c':'#ff4d6d'; }
function _scoreGrade(v){ return v>=90?'ELITE':v>=80?'GREAT':v>=65?'GOOD':v>=45?'OK':'NEEDS TUNING'; }
function gamerHud(){
  const s=STATE, g=s.gpu||{}, parts=[];
  if(s.fps!=null){
    const stab=(s.low1!=null&&s.fps>0)?_gclamp(100-((s.fps-s.low1)/s.fps)*220,0,100):70;
    const lvl=_gclamp((s.fps/120)*100,0,100);
    parts.push(['Frames', Math.round(stab*0.6+lvl*0.4)]);
  }
  // use the SMOOTHED temp for the score (steady), not the raw hottest core (jittery)
  const temp=(s.tempScore!=null)?s.tempScore:((s.hotTemp!=null)?s.hotTemp:(g.temp!=null?g.temp:null));
  if(temp!=null) parts.push(['Thermals', Math.round(_gclamp(100-_gclamp(temp-60,0,40)*(100/40),0,100))]);
  if(s.stability!=null) parts.push(['Network', Math.round(s.stability)]);
  else if(s.ping!=null) parts.push(['Network', Math.round(_gclamp(100-s.ping*0.5-(s.loss||0)*8,0,100))]);
  { let pen=0, have=false;
    if(g.vram_total){ have=true; const v=g.vram_used/g.vram_total*100; if(v>85)pen+=(v-85)*3; }
    if(s.mem_total){ have=true; const m=s.mem_used/s.mem_total*100; if(m>88)pen+=(m-88)*3; }
    if(have) parts.push(['Resources', Math.round(_gclamp(100-pen,0,100))]);
  }
  const score = parts.length? Math.round(parts.reduce((a,p)=>a+p[1],0)/parts.length) : null;
  // ring + number + component bars
  const ring=document.getElementById('scoreRing'), num=document.getElementById('scoreVal'), gr=document.getElementById('scoreGrade'), bars=document.getElementById('perfBars'), rw=document.querySelector('.perf-ring'); const C=351.9;
  if(ring){ if(score==null){ ring.style.strokeDashoffset=C; num.textContent='—'; num.style.color=''; gr.textContent='rig score'; if(bars)bars.innerHTML=''; }
    else { const col=_scoreCol(score); ring.style.strokeDashoffset=C*(1-score/100); if(rw)rw.style.setProperty('--scoreC',col);
      num.textContent=score; num.style.color=col; gr.textContent=_scoreGrade(score);
      if(bars) bars.innerHTML=parts.map(function(p){ const cc=_scoreCol(p[1]); return '<div class="pb"><div class="pl"><span>'+p[0]+'</span><span style="color:'+cc+'">'+p[1]+'</span></div><div class="track"><div class="fill" style="width:'+p[1]+'%;background:'+cc+'"></div></div></div>'; }).join(''); } }
  // reactive orb (personality)
  const orb=document.getElementById('perfOrb'), face=document.getElementById('orbFace');
  if(orb){ let col='#39e1ff', glow='rgba(57,225,255,.55)', emo='🎮', pulse=false;
    const stutter=(s.fps!=null&&s.low1!=null&&s.fps>0)?(s.fps-s.low1)/s.fps:null;
    if(temp!=null&&temp>=88){ col='#ff4d6d'; glow='rgba(255,77,109,.7)'; emo='🥵'; pulse=true; }
    else if(stutter!=null&&stutter>0.35){ col='#f0a92c'; glow='rgba(240,169,44,.7)'; emo='😰'; pulse=true; }
    else if(score!=null&&score>=80){ col='#2ee66e'; glow='rgba(46,230,110,.75)'; emo='😎'; pulse=true; }
    else if(score!=null&&score<45){ col='#ff4d6d'; glow='rgba(255,77,109,.6)'; emo='😟'; }
    else if(score!=null&&score<65){ col='#f0a92c'; glow='rgba(240,169,44,.55)'; emo='🙂'; }
    orb.style.setProperty('--orbC',col); orb.style.setProperty('--orbG',glow); face.textContent=emo; orb.classList.toggle('pulse',pulse); }
  gamerTips(s, score);
  copilotWatch(s, score);
}
function gamerTips(s, score){
  const el=document.getElementById('tipsList'); if(!el)return;
  const g=s.gpu||{}, tips=[];
  const vram=g.vram_total? g.vram_used/g.vram_total*100 : null;
  const mem =s.mem_total? s.mem_used/s.mem_total*100 : null;
  const temp=(s.hotTemp!=null)?s.hotTemp:(g.temp!=null?g.temp:null);
  const stut=(s.fps!=null&&s.low1!=null&&s.fps>0)?(s.fps-s.low1)/s.fps:null;
  if(vram!=null&&vram>=90) tips.push(['crit','fa-memory','VRAM at '+Math.round(vram)+'% — lower texture quality or resolution to stop texture pop-in and stutter.']);
  else if(vram!=null&&vram>=80) tips.push(['warn','fa-memory','VRAM at '+Math.round(vram)+'% — near the limit; drop textures one notch if you see hitching.']);
  if(g.util!=null&&s.cpu!=null&&g.util<75&&s.cpu>=88) tips.push(['warn','fa-microchip','CPU is bottlenecking ('+Math.round(s.cpu)+'% CPU vs '+Math.round(g.util)+'% GPU) — try disabling ray-tracing / heavy sim settings, or close background apps.']);
  const _hn=s.hotName?(' — '+esc(s.hotName)+(s.hotHw?(' ('+esc(s.hotHw)+')'):'')):'';   // escape: sensor name comes from the remote box (untrusted)
  if(temp!=null&&temp>=90) tips.push(['crit','fa-fire',Math.round(temp)+'°C'+_hn+' — likely thermal-throttling. Improve airflow, raise the fan curve, or re-check case ventilation.']);
  else if(temp!=null&&temp>=82) tips.push(['warn','fa-temperature-three-quarters','Running warm — '+Math.round(temp)+'°C'+_hn+'. Bump the fan curve to protect boost clocks.']);
  if((s.jitter!=null&&s.jitter>=15)||(s.loss||0)>=1) tips.push(['warn','fa-wifi','Network '+(s.jitter!=null?('jitter '+s.jitter+'ms'):'')+((s.loss||0)>=1?((s.jitter!=null?' + ':'')+Math.round(s.loss)+'% loss'):'')+' — switch to a wired connection or QoS-prioritize this PC.']);
  else if(s.ping!=null&&s.ping>=80) tips.push(['warn','fa-satellite-dish','Ping is high ('+Math.round(s.ping)+'ms) — pick a closer server region or check for background downloads.']);
  if(mem!=null&&mem>=90) tips.push(['crit','fa-layer-group','RAM at '+Math.round(mem)+'% — close browser tabs / background apps to free memory for the game.']);
  if(stut!=null&&stut>0.35&&!(temp!=null&&temp>=90)) tips.push(['warn','fa-bolt','Frame stutter: your 1% low ('+Math.round(s.low1)+') is far below your average ('+Math.round(s.fps)+') — cap FPS just under your refresh or enable low-latency mode.']);
  if(s.diskTotal){ const fp=s.diskFree/s.diskTotal*100; if(fp<8) tips.push(['warn','fa-hard-drive','Disk almost full ('+Math.round(fp)+'% free) — free space to avoid shader-cache / streaming hitches.']); }
  if(!tips.length){
    if(score!=null&&score>=80) tips.push(['good','fa-check','Your rig is dialed in — temps, frames and network all look great. Game on! 🎮']);
    else if(s.game) tips.push(['good','fa-check','No issues detected right now — NEURU keeps watching and will coach you if anything drifts.']);
    else tips.push(['muted','fa-gamepad','Launch a game — NEURU analyzes your rig live and coaches you here.']);
  }
  el.innerHTML = tips.map(function(t){ return '<li class="tip '+t[0]+'"><i class="fa-solid '+t[1]+'"></i><span>'+t[2]+'</span></li>'; }).join('');
}

// ── NEURU Copilot — reactive battle-buddy (event-driven, reuses HUD thresholds + existing features) ──
const CP_COL={crit:'#ff4d6d',warn:'#f0a92c',good:'#2ee66e',info:'#39e1ff'};
let CP_PREV={}, CP_FIRED={}, CP_GAME=null, CP_HADALERT=false, CP_VOICE=false;
const CP_REFRACTORY=90000; // don't re-nag the same signal for 90s
function cpActFan(){ return {label:'Fan Profiler',icon:'fa-fan',href:'fan_profiler.php'}; }
function cpActNet(){ return {label:'Connection Doctor',icon:'fa-stethoscope',href:'net_doctor.php'}; }
function cpActBoost(){ return {label:'Game Mode',icon:'fa-rocket',fn:'toggleBoost()'}; }
// signals: id, sev, test(s,g,d)->bool, msg(...)->string, icon, acts()->[]
function cpSignals(){ return [
  {id:'therm_crit',sev:'crit',icon:'fa-fire',
    test:(s,g,d)=>d.temp!=null&&d.temp>=90,
    msg:(s,g,d)=>'You\'re thermal-throttling at '+Math.round(d.temp)+'°C — that\'s costing you boost clocks. Raise your fan curve now.',
    acts:()=>[cpActFan(),cpActBoost()]},
  {id:'therm_warn',sev:'warn',icon:'fa-temperature-three-quarters',
    test:(s,g,d)=>d.temp!=null&&d.temp>=82&&d.temp<90,
    msg:(s,g,d)=>'Getting warm — '+Math.round(d.temp)+'°C. Bump the fan curve a notch to protect your frames.',
    acts:()=>[cpActFan()]},
  {id:'vram_crit',sev:'crit',icon:'fa-memory',
    test:(s,g,d)=>d.vram!=null&&d.vram>=90,
    msg:(s,g,d)=>'VRAM is maxed at '+Math.round(d.vram)+'% — drop texture quality one notch to kill the pop-in and stutter.',
    acts:()=>[]},
  {id:'cpu_bound',sev:'warn',icon:'fa-microchip',
    test:(s,g,d)=>g.util!=null&&s.cpu!=null&&g.util<75&&s.cpu>=88,
    msg:(s,g,d)=>'Your CPU is the bottleneck ('+Math.round(s.cpu)+'% CPU vs '+Math.round(g.util)+'% GPU). Close background apps or ease heavy sim settings.',
    acts:()=>[cpActBoost()]},
  {id:'ram_crit',sev:'crit',icon:'fa-layer-group',
    test:(s,g,d)=>d.mem!=null&&d.mem>=90,
    msg:(s,g,d)=>'RAM at '+Math.round(d.mem)+'% — close some browser tabs to free memory for the game.',
    acts:()=>[cpActBoost()]},
  {id:'net_stress',sev:'warn',icon:'fa-wifi',
    test:(s,g,d)=>(s.jitter!=null&&s.jitter>=15)||(s.loss||0)>=1||(s.stability!=null&&s.stability<60),
    msg:(s,g,d)=>'Your connection just got shaky'+(s.jitter!=null?(' — jitter '+s.jitter+'ms'):'')+((s.loss||0)>=1?(' + '+Math.round(s.loss)+'% loss'):'')+'. Go wired or QoS-prioritize this PC.',
    acts:()=>[cpActNet()]},
  {id:'ping_high',sev:'warn',icon:'fa-satellite-dish',
    test:(s,g,d)=>s.ping!=null&&s.ping>=80&&!((s.jitter!=null&&s.jitter>=15)||(s.loss||0)>=1),
    msg:(s,g,d)=>'Ping climbed to '+Math.round(s.ping)+'ms — pick a closer server region or pause background downloads.',
    acts:()=>[cpActNet()]},
  {id:'stutter',sev:'warn',icon:'fa-bolt',
    test:(s,g,d)=>d.stut!=null&&d.stut>0.35&&!(d.temp!=null&&d.temp>=90),
    msg:(s,g,d)=>'Frame-time went unstable — your 1% low ('+Math.round(s.low1)+') is way under your average ('+Math.round(s.fps)+'). Cap FPS just under your refresh or enable low-latency mode.',
    acts:()=>[]},
]; }
function cpSpeak(text){ if(!CP_VOICE||!window.speechSynthesis)return; try{ const u=new SpeechSynthesisUtterance(text.replace(/[^\x00-\x7F]/g,'').trim()); u.rate=1.02; u.pitch=1; u.volume=.9; window.speechSynthesis.cancel(); window.speechSynthesis.speak(u); }catch(e){} }
function cpToggleVoice(){ CP_VOICE=document.getElementById('cpVoice').checked; try{ localStorage.setItem('nm_cp_voice',CP_VOICE?'1':'0'); }catch(e){} if(CP_VOICE)cpSpeak('Copilot voice on. I\'ve got your back.'); }
function cpPush(sev,icon,text,acts){
  const feed=document.getElementById('cpFeed'); if(!feed)return;
  const col=CP_COL[sev]||CP_COL.info;
  const now=new Date(); const hh=('0'+now.getHours()).slice(-2)+':'+('0'+now.getMinutes()).slice(-2)+':'+('0'+now.getSeconds()).slice(-2);
  const actsHtml=(acts&&acts.length)?('<div class="act">'+acts.map(function(a){ return a.href?('<a class="cp-act" href="'+a.href+'"><i class="fa-solid '+a.icon+'"></i> '+a.label+'</a>'):('<span class="cp-act" onclick="'+a.fn+'"><i class="fa-solid '+a.icon+'"></i> '+a.label+'</span>'); }).join('')+'</div>'):'';
  const el=document.createElement('div'); el.className='cp-msg'; el.style.setProperty('--cpc',col);
  el.innerHTML='<i class="ic fa-solid '+icon+'"></i><div class="body"><div class="tx">'+text+'</div>'+actsHtml+'<div class="tm">'+hh+'</div></div>';
  feed.prepend(el); while(feed.children.length>14) feed.removeChild(feed.lastChild);
  const orb=document.getElementById('cpOrb'); if(orb){ orb.classList.add('think'); setTimeout(function(){ orb.classList.remove('think'); },2600); }
  // mirror the latest alert onto the Gaming Deck panel
  const dm=document.getElementById('dcpMsg'); if(dm){ dm.style.setProperty('--dcpc',col); dm.innerHTML=text+'<span class="dt">'+hh+'</span>'; dm.classList.add('on'); }
  cpSpeak(text);
}
function cpStatus(txt,col){ const st=document.getElementById('cpStatus'); if(st){ st.textContent=txt; st.style.color=col||'#9fb6d4'; }
  const dst=document.getElementById('dcpStatus'); if(dst){ dst.textContent=txt; dst.style.color=col||'#9fb6d4'; }
  const dl=document.getElementById('dcpLive'); if(dl) dl.style.color=col||'var(--ok)'; }
function copilotWatch(s, score){
  const g=s.gpu||{};
  const d={ vram:g.vram_total?g.vram_used/g.vram_total*100:null, mem:s.mem_total?s.mem_used/s.mem_total*100:null,
            temp:(s.hotTemp!=null)?s.hotTemp:(g.temp!=null?g.temp:null),
            stut:(s.fps!=null&&s.low1!=null&&s.fps>0)?(s.fps-s.low1)/s.fps:null };
  // greet on a newly-detected game
  const gt=s.game?s.game.title:null;
  if(gt&&gt!==CP_GAME){ CP_GAME=gt; CP_PREV={}; CP_FIRED={};
    cpPush('info','fa-gamepad','<b>'+esc(gt)+'</b> detected — I\'m on it. I\'ll flag anything that could cost you frames.',[]); }
  else if(!gt&&CP_GAME){ CP_GAME=null; }
  const now=Date.now(); let anyActive=false, worst=null;
  cpSignals().forEach(function(sig){
    let active=false; try{ active=!!sig.test(s,g,d); }catch(e){}
    if(active){ anyActive=true; if(!worst||({crit:3,warn:2,info:1,good:0}[sig.sev]>{crit:3,warn:2,info:1,good:0}[worst.sev])) worst=sig;
      const fresh=!CP_PREV[sig.id] && ((now-(CP_FIRED[sig.id]||0))>CP_REFRACTORY || !CP_FIRED[sig.id]);
      if(fresh){ CP_FIRED[sig.id]=now; cpPush(sig.sev,sig.icon,sig.msg(s,g,d),sig.acts()); CP_HADALERT=true; } }
    CP_PREV[sig.id]=active;
  });
  // recovery note when everything clears after an alert
  if(!anyActive){
    if(CP_HADALERT && gt && score!=null && score>=80){ CP_HADALERT=false; cpPush('good','fa-shield-heart','All clear — everything\'s smooth again. Score back up to '+score+'. I\'ll keep watching.',[]); }
    if(gt) cpStatus(score!=null?('👁 Watching · all systems nominal · score '+score):'👁 Watching your session…','#7fd6a0');
    else cpStatus('Launch a game — I\'ll watch your rig and speak up the moment something could cost you frames.');
  } else if(worst){ cpStatus((worst.sev==='crit'?'🔴 ':'🟠 ')+'On it — '+worst.id.replace(/_/g,' ')+' flagged', CP_COL[worst.sev]); }
}
(function(){ try{ CP_VOICE=localStorage.getItem('nm_cp_voice')==='1'; const cb=document.getElementById('cpVoice'); if(cb)cb.checked=CP_VOICE; }catch(e){} })();


// ── WebGL: ambient particle backdrop + the FPS/GPU reactor ──
let bg={}, fx={};
// round, soft particle sprite — PointsMaterial renders SQUARES without a texture map; this radial-gradient dot
// (opaque centre → transparent edge) makes every particle a crisp round glow. Shared by both point systems.
const NM_DOT=(()=>{ const c=document.createElement('canvas'); c.width=c.height=64; const x=c.getContext('2d');
  const g=x.createRadialGradient(32,32,0,32,32,32); g.addColorStop(0,'rgba(255,255,255,1)'); g.addColorStop(.4,'rgba(255,255,255,.9)'); g.addColorStop(1,'rgba(255,255,255,0)');
  x.fillStyle=g; x.beginPath(); x.arc(32,32,32,0,7); x.fill(); const t=new THREE.CanvasTexture(c); t.needsUpdate=true; return t; })();
function initBG(){ const cv=document.getElementById('gbg'); const rn=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true}); rn.setPixelRatio(Math.min(2,devicePixelRatio)); rn.setSize(innerWidth,innerHeight);
  const sc=new THREE.Scene(), cam=new THREE.PerspectiveCamera(60,innerWidth/innerHeight,.1,100); cam.position.z=30;
  const N=900, g=new THREE.BufferGeometry(), pos=new Float32Array(N*3); for(let i=0;i<N;i++){ pos[i*3]=(Math.random()-.5)*80; pos[i*3+1]=(Math.random()-.5)*50; pos[i*3+2]=(Math.random()-.5)*40; } g.setAttribute('position',new THREE.BufferAttribute(pos,3));
  const pts=new THREE.Points(g,new THREE.PointsMaterial({color:0x39e1ff,size:.16,map:NM_DOT,transparent:true,opacity:.6,depthWrite:false,blending:THREE.AdditiveBlending})); sc.add(pts);
  bg={rn,sc,cam,pts}; addEventListener('resize',()=>{ rn.setSize(innerWidth,innerHeight); cam.aspect=innerWidth/innerHeight; cam.updateProjectionMatrix(); });
}
function initFX(){ const cv=document.getElementById('fpsCanvas'); const w=cv.clientWidth||600,h=220; const rn=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true}); rn.setPixelRatio(Math.min(2,devicePixelRatio)); rn.setSize(w,h,false);
  const sc=new THREE.Scene(), cam=new THREE.PerspectiveCamera(50,w/h,.1,100); cam.position.z=9;
  const core=new THREE.Mesh(new THREE.IcosahedronGeometry(2.4,1), new THREE.MeshBasicMaterial({color:0x39e1ff,wireframe:true,transparent:true,opacity:.85})); sc.add(core);
  const halo=new THREE.Mesh(new THREE.SphereGeometry(2.9,24,24), new THREE.MeshBasicMaterial({color:0xb06bff,transparent:true,opacity:.12,blending:THREE.AdditiveBlending})); sc.add(halo);
  const ring=new THREE.Mesh(new THREE.TorusGeometry(4,0.06,8,64), new THREE.MeshBasicMaterial({color:0x2ee66e,transparent:true,opacity:.6})); ring.rotation.x=Math.PI/2.4; sc.add(ring);
  fx={rn,sc,cam,core,halo,ring,load:0,heat:0}; addEventListener('resize',()=>{ const w=cv.clientWidth||600; rn.setSize(w,h,false); cam.aspect=w/h; cam.updateProjectionMatrix(); });
}
function loop(){ requestAnimationFrame(loop); const t=performance.now()/1000;
  if(bg.rn){ bg.pts.rotation.y=t*0.03; bg.pts.rotation.x=Math.sin(t*0.1)*0.1; bg.rn.render(bg.sc,bg.cam); }
  if(fx.rn){ const spin=0.15+fx.load*0.9; fx.core.rotation.y+=0.01*spin*3; fx.core.rotation.x+=0.006*spin*3;
    const pulse=1+Math.sin(t*(2+fx.load*6))*0.05*(0.3+fx.load); fx.core.scale.setScalar(pulse); fx.halo.scale.setScalar(pulse);
    const col=fx.heat>0.8? new THREE.Color(0xff4d6d) : new THREE.Color().setHSL(0.55-fx.load*0.15,1,0.6); fx.core.material.color=col;
    fx.ring.rotation.z+=0.01+fx.load*0.05; fx.ring.material.color.setHex(fx.heat>0.8?0xff4d6d:(fx.load>0.85?0xf0a92c:0x2ee66e));
    fx.rn.render(fx.sc,fx.cam); } }

async function loadRigs(){ try{ const r=await fetch('?api=rigs').then(r=>r.json()); const sel=$('#rig'); if(!r.ok||!r.rigs.length){ sel.innerHTML='<option value="">No Windows rigs — add one in Windows Monitor</option>'; return; } sel.innerHTML='<option value="">— pick your rig —</option>'+r.rigs.map(x=>`<option value="${x.id}">${esc(x.name)} (${esc(x.ip)})</option>`).join(''); }catch(e){} }
function stopPolls(){ [vitalsTimer,radarTimer,fpsTimer,hogTimer,sensTimer,diskTimer,hudTimer,dnaTimer].forEach(t=>t&&clearInterval(t)); vitalsTimer=radarTimer=fpsTimer=hogTimer=sensTimer=diskTimer=hudTimer=dnaTimer=null; }
function startPolls(){ if(!RIG||document.hidden)return;
  refreshVitals(); refreshRadar(); refreshFps(); refreshHogs(); refreshSensors(); loadDisks(); loadGames(); gamerHud(); loadDna();
  vitalsTimer=setInterval(refreshVitals,4000); radarTimer=setInterval(refreshRadar,15000); fpsTimer=setInterval(refreshFps,12000); hogTimer=setInterval(refreshHogs,10000); sensTimer=setInterval(refreshSensors,8000); hudTimer=setInterval(gamerHud,3000); diskTimer=setInterval(loadDisks,30000); dnaTimer=setInterval(loadDna,60000); }
// Blank every readout + shared state so switching rigs never shows the PREVIOUS rig's numbers while the
// new one loads over SSH (the 3D deck reads STATE each frame, so clearing STATE resets it too).
function resetDeck(){
  Object.assign(STATE,{gpu:{},cpu:null,mem_used:0,mem_total:0,ping:null,loss:0,fps:null,low1:null,low01:null,
    hotTemp:null,hotName:null,hotHw:null,topFan:null,fanCount:0,game:null,session:null,fans:[],temps:[],disks:[],phys:[],diskTotal:0,diskFree:0});
  GAME=null; DNA=null;
  const T=(id,v)=>{const e=document.getElementById(id); if(e)e.textContent=v;};
  const H=(id,v)=>{const e=document.getElementById(id); if(e)e.innerHTML=v;};
  H('gpuTemp','—<span class="unit">°C</span>'); T('gpuName','GPU'); T('gpuUtil','—'); T('vram','— MB'); T('fan','—'); T('fanCount','');
  ['gpuUtilBar','vramBar','cpuBar','ramBar'].forEach(id=>{const e=document.getElementById(id); if(e)e.style.width='0%';});
  T('cpu','—'); T('ram','—'); T('t-fps','—'); T('t-low1','—'); T('t-low01','—');
  T('gameName','Loading…'); T('gamePub',''); T('hoglist',''); T('dpSession','');
  ['ov-cpu','ov-fps','ov-gpu','ov-ping','ms-game'].forEach(id=>T(id,'—'));
  const thr=document.getElementById('thrAlert'); if(thr)thr.classList.remove('on');
}
function pickRig(){ RIG=+$('#rig').value||0; stopPolls(); PM_OK=null; resetDeck();
  { const s=$('#rig'); STATE.rigName = s && s.selectedIndex>=0 ? s.options[s.selectedIndex].text : ''; }
  const ro=$('#ovRig'); if(ro) ro.textContent = RIG ? ($('#rig').selectedOptions[0].textContent) : '— pick a rig above —';
  if(!RIG)return;
  startPolls(); }
// pause all SSH-backed polling when the tab is hidden (stop hammering the rig); resume when visible
document.addEventListener('visibilitychange',function(){ if(document.hidden) stopPolls(); else if(RIG){ stopPolls(); startPolls(); } });
// ── Player DNA + Achievements (gamer identity + gamification) — shows on gaming.php AND the Gaming Deck ──
let DNA=null, dnaTimer=null;
const DNA_TCOL={Thermals:'#39e1ff',Frames:'#b06bff',Stability:'#2ee66e',Endurance:'#f0a92c',Explorer:'#ff6bd6'};
const DNA_TINFO={
  Thermals:'How cool your rig runs — from your AVERAGE peak GPU temp across sessions. 100 = ice-cold; drops as peak temps climb past ~58°C.',
  Frames:'Your BEST sustained average FPS. Reaches 100 around 144 FPS.',
  Stability:'Frame-time consistency — how close your 1% low FPS stays to your average. 100 = rock-steady, no stutter.',
  Endurance:'Total REAL gameplay logged. Reaches 100 around ~40 hours — so it stays low until you\'ve tracked a lot of play time.',
  Explorer:'Game variety — how many different games you\'ve played. Reaches 100 around 8 games.'
};
function toggleDnaInfo(){ const el=document.getElementById('pdnaInfo'); if(!el)return;
  if(el.style.display==='none'||!el.style.display){ el.innerHTML=Object.keys(DNA_TINFO).map(function(k){ const col=DNA_TCOL[k]||'#39e1ff'; return '<div class="row"><b style="color:'+col+'">'+k+'</b> — '+DNA_TINFO[k]+'</div>'; }).join('')+'<div class="row" style="margin-top:6px;color:#8fb4dd">Your <b>archetype</b> = your strongest trait. <b>Level &amp; rank</b> grow with total play time + achievements unlocked. All of it is computed from your real session history (non-game apps are excluded).</div>'; el.style.display='block'; }
  else el.style.display='none'; }
async function loadDna(){ if(!RIG)return; try{ const r=await fetch('?api=dna&rig='+RIG).then(x=>x.json()); if(r&&r.ok){ DNA=r; renderDnaCard(r); renderDnaDeck(r); } }catch(e){} }
function renderDnaCard(r){ const c=document.getElementById('pdnaCard'); if(!c)return; c.style.display='';
  document.getElementById('pdnaEmblem').textContent=r.archetype.emoji;
  document.getElementById('pdnaArch').textContent=r.archetype.name;
  document.getElementById('pdnaDesc').textContent=r.archetype.desc;
  document.getElementById('pdnaLvl').textContent=r.level; document.getElementById('pdnaRank').textContent=r.rank;
  const ring=document.getElementById('pdnaRing'),C=326.7,p=r.xpSpan?r.xpInto/r.xpSpan:0; if(ring)ring.style.strokeDashoffset=C*(1-Math.max(0,Math.min(1,p)));
  const a=r.agg||{};
  document.getElementById('pdnaStats').innerHTML='<span><b>'+r.hours+'</b> h played</span><span><b>'+a.games+'</b> games</span><span><b>'+a.sessions+'</b> sessions</span>'+(a.best_fps?'<span><b>'+a.best_fps+'</b> best FPS</span>':'')+(a.coolest!=null?'<span><b>'+a.coolest+'°</b> coolest</span>':'');
  document.getElementById('pdnaTraits').innerHTML=Object.keys(r.traits||{}).map(function(k){ const v=r.traits[k],col=DNA_TCOL[k]||'#39e1ff'; return '<div class="ptrait" title="'+esc(DNA_TINFO[k]||'')+'"><span class="pl q">'+k+'</span><span class="tk"><span class="tf" style="width:'+v+'%;background:'+col+'"></span></span><span style="color:'+col+';width:26px;text-align:right;font-weight:700">'+v+'</span></div>'; }).join('');
  document.getElementById('pdnaAchCount').textContent='· '+r.unlocked+'/'+r.total+' unlocked';
  document.getElementById('pdnaAchGrid').innerHTML=(r.achievements||[]).map(function(x){ return '<div class="ach'+(x.unlocked?' on':'')+'"><span class="ae">'+x.emoji+'</span><div><div class="an">'+esc(x.name)+'</div><div class="ad">'+esc(x.desc)+'</div></div><span class="apg" style="width:'+Math.round(x.progress*100)+'%"></span></div>'; }).join('');
}
function renderDnaDeck(r){ const p=document.getElementById('deckDna'); if(!p)return;
  document.getElementById('ddEmo').textContent=r.archetype.emoji;
  document.getElementById('ddArch').textContent=r.archetype.name;
  document.getElementById('ddLvl').textContent=r.level; document.getElementById('ddRank').textContent=r.rank;
  document.getElementById('ddAchN').textContent=r.unlocked+'/'+r.total;
  document.getElementById('ddTraits').innerHTML=Object.keys(r.traits||{}).map(function(k){ const v=r.traits[k],col=DNA_TCOL[k]||'#39e1ff'; return '<div class="r" title="'+esc(DNA_TINFO[k]||'')+'"><span class="pl">'+k+'</span><span class="tk"><span class="tf" style="width:'+v+'%;background:'+col+'"></span></span><span style="width:22px;text-align:right;color:'+col+'">'+v+'</span></div>'; }).join('');
  document.getElementById('ddAch').innerHTML=(r.achievements||[]).map(function(x){ return '<span class="b'+(x.unlocked?' on':'')+'" title="'+esc(x.name)+' — '+esc(x.desc)+'">'+x.emoji+'</span>'; }).join('');
}

// ── FPS (crown jewel): real frame-times via PresentMon ──
async function refreshFps(){ if(!RIG)return; try{ const r=await fetch('?api=fps&rig='+RIG).then(r=>r.json());
  if(r.no_game){ $('#t-fps').textContent='—'; $('#t-low1').textContent='—'; $('#t-low01').textContent='—'; $('#fpsNote').textContent='No game running — launch one and NEURU captures your FPS.'; STATE.fps=null; STATE.low1=null; return; }
  if(r.need_helper){ PM_OK=false; $('#fpsNote').innerHTML='FPS capture needs the PresentMon helper. <button class="chip" style="cursor:pointer;border-color:#39e1ff" onclick="deployPm(this)">⬇ Deploy FPS capture</button>'; return; }
  if(r.ok){ PM_OK=true; $('#t-fps').textContent=Math.round(r.avg); $('#t-low1').textContent=Math.round(r.low1); $('#t-low01').textContent=Math.round(r.low01);
    const stut=(r.avg-r.low1)/r.avg>0.35; $('#t-low1').style.color=stut?'#ff4d6d':''; $('#fpsNote').textContent='Live · '+r.frames+' frames · frame-time '+r.frametime+'ms'+(stut?' · ⚠ stutter (1% low far below avg)':''); STATE.fps=r.avg; STATE.low1=r.low1; STATE.low01=r.low01; }
  else { $('#fpsNote').textContent='FPS: '+(r.error||'unavailable'); }
}catch(e){} }
async function deployPm(btn){ if(!RIG)return; btn.textContent='deploying…'; btn.disabled=true;
  try{ const fd=new FormData(); fd.append('rig',RIG); const r=await fetch('?api=pm_deploy',{method:'POST',body:fd}).then(r=>r.json());
    $('#fpsNote').textContent = r.ok ? '✅ PresentMon deployed — capturing FPS…' : ('Deploy failed: '+(r.error||'?')); if(r.ok){ PM_OK=true; setTimeout(refreshFps,1500); } }catch(e){ $('#fpsNote').textContent='Deploy error'; } }

let hogEmpty=0;
async function refreshHogs(){ if(!RIG)return; try{ const r=await fetch('?api=hogs&rig='+RIG).then(r=>r.json()); if(!r.ok)return;
  const procs=r.procs||[], lan=r.lan||[], net=r.net;
  if(net){ STATE.rx=net.rx; STATE.tx=net.tx; }
  const fmt=b=>b>1e6?(b/1e6).toFixed(1)+' MB/s':(b/1e3).toFixed(0)+' KB/s';
  // headline: system-wide network throughput — this comes from a NIC counter, so it's basically always present online
  let head='';
  if(net){ head=`<div class="h-row" style="border-bottom:1px solid rgba(255,255,255,.12);padding-bottom:7px;margin-bottom:6px">
      <span class="nm" style="font-weight:800">🌐 Network now</span>
      <span style="color:#39e1ff;font-weight:700">↓ ${fmt(net.rx)}</span>
      <span style="color:#ff4dd0;font-weight:700;margin-left:10px">↑ ${fmt(net.tx)}</span></div>`; }
  // STICKY: keep the last per-process list through brief idle samples; only fall back to the calm message after 3 empties
  if(!procs.length && !lan.length){
    if(++hogEmpty>=3 || head){ $('#hoglist').innerHTML = head + (r.err?`<div class="muted" title="${esc(r.err)}">Per-process I/O counters unavailable on this rig.</div>`:'<div class="muted">Nothing hogging the pipe right now. 🎯</div>'); }
    return;
  }
  hogEmpty=0;
  let h=head;
  procs.forEach(p=>{ const pct=Math.min(100,p.bps/2e6*100); h+=`<div class="h-row"><span class="nm">${esc(p.name)}</span><div class="bar" style="flex:1;margin:0"><span style="width:${pct}%;background:linear-gradient(90deg,#39e1ff,#ff4d6d)"></span></div><span>${fmt(p.bps)}</span></div>`; });
  lan.forEach(l=>{ h+=`<div class="h-row"><span class="nm">🖧 ${esc(l.ip)}</span><span class="muted">LAN ${fmt(l.bytes/300)}</span></div>`; });
  $('#hoglist').innerHTML=h;
}catch(e){} }

async function detectDebug(){ const pre=$('#detectDbg'); if(!RIG){ alert('Pick a rig first'); return; }
  pre.style.display='block'; pre.textContent='Scanning the rig…';
  try{ const d=await fetch('?api=detect_debug&rig='+RIG).then(r=>r.json());
    if(!d.ok){ pre.textContent='✖ '+(d.error||'failed'); return; }
    let s='';
    s+= d.detected ? ('✅ MATCHED: '+d.detected.title+'  ('+(d.detected.ram_mb||0)+' MB'+(d.detected.guess?', heuristic':', known')+')\n') : '❌ No game matched.\n';
    s+= 'Processes seen: '+d.procs_seen+'   ·   exe paths visible: '+(d.paths_visible?'yes':'NO (SSH not admin — paths hidden)')+'\n';
    if(!d.paths_visible) s+= '⚠ SSH can\'t read process paths → run the rig\'s SSH as an Administrator for best detection.\n';
    s+= '\nTop processes by RAM (✔=candidate, ·=ignored as system/launcher/browser):\n';
    (d.top||[]).forEach(p=>{ s+= (p.noise?' · ':' ✔ ')+String(p.ram_mb).padStart(6)+' MB  '+p.name+(p.path?('   '+p.path):'   (path hidden)')+'\n'; });
    s+= '\nTip: if your game shows here but wasn\'t matched, add its folder in Game Library → Add folder.';
    pre.textContent=s;
  }catch(e){ pre.textContent='✖ '+e; }
}
async function refreshVitals(){ if(!RIG)return; try{ const v=await fetch('?api=vitals&rig='+RIG).then(r=>r.json()); if(!v.ok)return;
  BOOST=!!v.boost; $('#gmbtn').classList.toggle('on',BOOST); $('#gmbtn').textContent=BOOST?'Game Mode ON':'Game On'; syncDeckBoost();
  GAME=v.game;
  if(v.game){ $('#gameName').textContent=v.game.title; $('#gamePub').textContent=v.game.pub+' · '+(v.game.ram_mb||0)+' MB'; }
  else { $('#gameName').textContent='No game detected'; $('#gamePub').textContent='launch a game — NEURU auto-detects it'; }
  applyAutoSkin();
  const g=v.gpu||{};
  if(g.ok){ const gt=(g.temp!=null)?g.temp:(STATE.hotTemp!=null?STATE.hotTemp:null);   // iGPU/AMD have no nvidia-smi temp → use the hottest LHM sensor; never render literal "null"
    $('#gpuTemp').innerHTML=(gt!=null?Math.round(gt):'—')+'<span class="unit">°C</span>'; $('#gpuName').textContent=g.name||'GPU';
    $('#gpuUtil').textContent=Math.round(g.util); $('#gpuUtilBar').style.width=Math.min(100,g.util)+'%';
    const vp=g.vram_total?Math.round(g.vram_used/g.vram_total*100):0; $('#vram').textContent=(g.vram_used||0)+' / '+(g.vram_total||0)+' MB'; $('#vramBar').style.width=vp+'%';
    $('#fan').textContent=g.fan==null?'—':g.fan;
    const fb=document.getElementById('fanBlades'); if(fb){ const fp=g.fan||0; fb.style.animationDuration=(fp>0?(2.6-Math.min(1,fp/100)*2.3):3)+'s'; fb.style.animationPlayState=fp>0?'running':'paused'; }
    const thr=g.throttle&&g.throttle.thermal; $('#thrAlert').classList.toggle('on',!!thr);
    fx.load=Math.min(1,(g.util||0)/100); fx.heat=Math.min(1,(gt||0)/90);
  } else { $('#gpuName').textContent=g.error||'no GPU'; }
  const s=v.sys||{}; if(s.cpu!=null){ $('#cpu').textContent=s.cpu; $('#cpuBar').style.width=s.cpu+'%'; } if(s.mem_total){ const mp=Math.round(s.mem_used/s.mem_total*100); $('#ram').textContent=(s.mem_used||0)+' / '+(s.mem_total||0)+' MB'; $('#ramBar').style.width=mp+'%'; }
  const se=v.session; if(se){ const live=!se.ended_at; $('#sessTimer').innerHTML=(live?'🎮 <b>'+esc(se.title||'session')+'</b> · ':'⏱ last: '+esc(se.title||'')+' · ')+(se.mins||0)+' min'
    +(se.max_gpu_temp?(' · max '+se.max_gpu_temp+'°C'):'')+(se.peak_vram_mb?(' · peak '+se.peak_vram_mb+'MB VRAM'):'')+(se.avg_fps?(' · '+Math.round(se.avg_fps)+' avg / '+Math.round(se.low1_fps)+' (1%) fps'):''); }
  STATE.game=v.game; STATE.gpu=v.gpu||{}; STATE.boost=BOOST; STATE.session=v.session||null;
  if(v.sys){ if(v.sys.cpu!=null)STATE.cpu=v.sys.cpu; if(v.sys.mem_total){ STATE.mem_used=v.sys.mem_used; STATE.mem_total=v.sys.mem_total; } }
}catch(e){} }

async function refreshRadar(){ if(!RIG)return; try{ const r=await fetch('?api=ping_radar&rig='+RIG).then(r=>r.json()); if(!r.ok)return;
  // who → who header
  $('#radarHead').innerHTML = r.game
    ? ('🎯 <b>'+esc(r.game)+'</b>'+(r.pub?' <span class="muted">('+esc(r.pub)+')</span>':'')+' servers &nbsp;·&nbsp; desde <b>'+esc(r.source||'rig')+'</b>')
    : ('📡 Ping de referencia desde <b>'+esc(r.source||'rig')+'</b> <span class="muted">— lanza un juego para medir sus servidores</span>');
  $('#regions').innerHTML=r.regions.map(x=>{
    const ms = x.ms==null? '<span class="ms g-down">timeout</span>' : ('<span class="ms g-'+x.grade+'">'+x.ms+' ms</span>');
    const sub = [ x.jitter!=null?('±'+x.jitter+'ms jitter'):'', x.loss?(x.loss+'% loss'):'', (x.min!=null&&x.max!=null)?(x.min+'–'+x.max+'ms'):'' ].filter(Boolean).join(' · ');
    return `<div class="reg"><div class="rl"><b>${esc(x.region)}</b><span class="host" title="${esc(x.host)}">${esc(x.host)}${x.ip?(' → '+esc(x.ip)):''}</span></div><div class="rr">${ms}${sub?('<span class="sub">'+sub+'</span>'):''}</div></div>`;
  }).join('');
  $('#pingVerdict').textContent=r.verdict||''; drawRadar(r.regions);
  const mg=$('#ms-game'); if(mg && !mg.value && r.game) mg.value=r.game;   // auto-fill the detected game
  const up=(r.regions||[]).filter(x=>x.ms!=null); STATE.ping = up.length? Math.min(...up.map(x=>x.ms)) : null; STATE.loss = up.length? Math.max(...up.map(x=>x.loss||0)) : 0;
  STATE.jitter = up.length? Math.round(Math.max(...up.map(x=>x.jitter||0))) : null;
  // Connection Stability — consistency of ping over time (coefficient of variation) + packet-loss penalty
  STATE._pingHist = STATE._pingHist||[]; if(STATE.ping!=null){ STATE._pingHist.push(STATE.ping); if(STATE._pingHist.length>15) STATE._pingHist.shift(); }
  { const h=STATE._pingHist; let cvPen=0;
    if(h.length>=3){ const mean=h.reduce((a,b)=>a+b,0)/h.length; const sd=Math.sqrt(h.reduce((a,b)=>a+(b-mean)*(b-mean),0)/h.length); cvPen=(mean>0?sd/mean:0)*180; }
    else if(STATE.jitter!=null && STATE.ping){ cvPen=(STATE.jitter/Math.max(1,STATE.ping))*180; }
    STATE.stability = (STATE.ping==null)?null:Math.max(0,Math.min(100,Math.round(100-cvPen-(STATE.loss||0)*8))); }
}catch(e){} }
function saveGameServers(){ const fd=new FormData(); fd.append('game',($('#ms-game').value.trim())||(GAME&&GAME.title)||'');
  for(let i=1;i<=3;i++){ fd.append('r'+i,($('#ms-r'+i).value||'').trim()); fd.append('h'+i,($('#ms-h'+i).value||'').trim()); }
  fetch('?api=map_servers',{method:'POST',body:fd}).then(r=>r.json()).then(r=>{ $('#msNote').textContent=r.ok?'saved ✓ — pinging your servers':'error'; if(r.ok) setTimeout(refreshRadar,300); }).catch(()=>{ $('#msNote').textContent='error'; }); }
let radar={};
function drawRadar(regions){ const cv=document.getElementById('radarCanvas'); if(!cv)return; const dpr=Math.min(2,devicePixelRatio); const w=cv.clientWidth,h=200; cv.width=w*dpr; cv.height=h*dpr; const c=cv.getContext('2d'); c.setTransform(dpr,0,0,dpr,0,0); c.clearRect(0,0,w,h);
  const cx=w/2,cy=h/2,R=Math.min(w,h)/2-8;
  for(let i=1;i<=3;i++){ c.beginPath(); c.arc(cx,cy,R*i/3,0,7); c.strokeStyle='rgba(120,170,255,.15)'; c.stroke(); }
  const cols={good:'#2ee66e',ok:'#f0a92c',bad:'#ff4d6d',down:'#556'};
  (regions||[]).forEach((x,i)=>{ const a=-Math.PI/2 + i/(regions.length||1)*Math.PI*2; const rr = x.ms==null?R : R*Math.min(1,(x.ms||0)/150); const px=cx+Math.cos(a)*rr, py=cy+Math.sin(a)*rr;
    c.beginPath(); c.arc(px,py,6,0,7); c.fillStyle=cols[x.grade]||'#556'; c.fill(); c.font='10px sans-serif'; c.fillStyle='#9fb4d8'; c.fillText(x.region,px+8,py+3); });
}

async function deckFanLoad(){ const s=document.getElementById('deckFanSel'); if(!s)return; if(!RIG){ s.innerHTML='<option value="">pick a rig</option>'; return; }
  s.innerHTML='<option value="">loading…</option>';
  const r=await fetch('?api=fan_list&rig='+RIG).then(x=>x.json()).catch(()=>null);
  if(!r||!r.ok||!r.files||!r.files.length){ s.innerHTML='<option value="">'+((r&&r.error)||'no FanControl configs')+'</option>'; return; }
  s.innerHTML='<option value="">🌀 Fan profile ('+r.files.length+')…</option>'+r.files.map(function(fo){ return '<option value="'+fo.name+'"'+(fo.active?' selected':'')+'>'+fo.name.replace(/\.json$/i,'')+(fo.active?' ✓':'')+'</option>'; }).join('');
}
async function deckFanApply(name){ if(!name||!RIG)return;
  if(!confirm('Switch FanControl to "'+name.replace(/\.json$/i,'')+'"?\nFanControl relaunches (~2s). Your fans keep running.')){ deckFanLoad(); return; }
  const m=document.getElementById('deckFanMsg'); if(m)m.textContent='applying…';
  const fd=new FormData(); fd.append('rig',RIG); fd.append('file',name);
  const r=await fetch('?api=fan_apply',{method:'POST',body:fd}).then(x=>x.json()).catch(()=>({ok:false}));
  if(m)m.innerHTML=r.ok?'<span style="color:#8ff0b6">✓ applied</span>':'<span style="color:#ffb0b0">✗ '+((r&&r.error)||'failed')+'</span>';
  setTimeout(function(){ if(m)m.textContent=''; deckFanLoad(); },2500);
}
function syncDeckBoost(){ const d=document.getElementById('deckBoost'); if(!d)return; d.classList.toggle('on',BOOST); const t=document.getElementById('deckBoostTxt'); if(t)t.textContent=BOOST?'GAMEMODE ON':'GAMEMODE OFF'; }
async function toggleBoost(){  if(!RIG){ alert('Pick a rig first'); return; } const to=!BOOST; const b=$('#gmbtn'); b.disabled=true; b.textContent='…';
  try{ const fd=new FormData(); fd.append('rig',RIG); fd.append('on',to?'1':'0'); const r=await fetch('?api=boost',{method:'POST',body:fd}).then(r=>r.json());
    if(r.ok){ BOOST=r.on; b.classList.toggle('on',BOOST); syncDeckBoost(); $('#boostlog').textContent = r.on ? ('⚡ Boosted — stopped: '+((r.stopped||[]).join(', ')||'none')+' · plan: High Performance') : ('↩ Restored — '+((r.restored||[]).join(', ')||'services')+' · plan reverted');
      $('#boostChips').innerHTML = r.on ? (r.stopped||[]).map(s=>'<span class="chip">⏹ '+esc(s)+'</span>').join('') : ''; }
    else { $('#boostlog').textContent='Boost failed: '+(r.error||'?'); }
  }catch(e){ $('#boostlog').textContent='Boost error'; }
  b.disabled=false; b.textContent=BOOST?'Game Mode ON':'Game On';
}

// ── Game Server Status board (checked from the NOC — independent of rigs) ──
function srvTile(s){ const dot='<span class="sdot s-'+s.status+'" style="color:'+({up:'#2ee66e',degraded:'#f0a92c',down:'#ff4d6d'}[s.status])+'"></span>';
  const ping = s.ms!=null ? ('<span class="sping s-'+s.status+'">'+s.ms+'ms</span>') : '<span class="sping s-down">—</span>';
  const players = (s.players!=null && s.max!=null) ? ('<span class="players">👥 '+s.players+' / '+s.max+' players</span>') : '';
  const det = s.detail ? ('<div class="sdet" title="'+esc(s.detail)+'">'+esc(s.detail)+'</div>') : '';
  const del = s.id && s.proto!=='official' ? '' : '';
  return `<div class="srv">${ping}<div class="sname">${dot}${esc(s.name)}</div><div class="smeta">${esc(s.game||'')} · ${esc(s.host)}:${s.port} · ${esc(s.proto)}</div>${players}${det}${s.custom?('<span class="sdel" onclick="delServer('+s.id+')" title="remove">✕ remove</span>'):''}</div>`;
}
async function loadServers(recheck){ try{ if(recheck) $('#srvNote').textContent='checking servers…';
  const r=await fetch('?api=servers&recheck='+(recheck?1:0)).then(r=>r.json()); if(!r.ok)return;
  $('#srvOfficial').innerHTML=(r.official||[]).map(srvTile).join('')||'<div class="muted">none</div>';
  $('#srvCustom').innerHTML=(r.custom||[]).map(s=>srvTile({...s,custom:true})).join('')||'<div class="muted" style="margin-top:8px">No custom servers yet — add yours above (Minecraft / CS2 / any host:port).</div>';
  $('#srvNote').textContent='updated '+new Date().toLocaleTimeString();
}catch(e){} }
function openLagReport(){ if(!RIG){ alert('Pick a rig above first'); return; } window.open('?report=lag&rig='+RIG+'&hours=24','_blank'); }
// ── Storage & Game Library ──
const _gb=b=>b>=1e12?(b/1e12).toFixed(2)+' TB':(b>=1e9?(b/1e9).toFixed(0)+' GB':(b/1e6).toFixed(0)+' MB');
async function loadDisks(){ if(!RIG)return; try{ const r=await fetch('?api=disks&rig='+RIG).then(r=>r.json()); if(!r.ok){ $('#diskList').innerHTML='<div class="muted">'+esc(r.error||'no data')+'</div>'; return; }
  { const L=r.logical||[]; STATE.disks=L; STATE.diskTotal=L.reduce((a,d)=>a+(d.size||0),0); STATE.diskFree=L.reduce((a,d)=>a+(d.free||0),0); STATE.phys=r.physical||[]; }
  $('#diskList').innerHTML=(r.logical||[]).map(d=>{ const cl=d.pct>=90?'#ff4d6d':(d.pct>=75?'#f0a92c':'#39e1ff'); return `<div style="margin-bottom:10px"><div style="display:flex;justify-content:space-between;font-size:12px"><span><b>${esc(d.id)}</b> ${esc(d.label||'')} <span class="hw">${esc(d.fs||'')}</span></span><span>${_gb(d.free)} free / ${_gb(d.size)} · ${d.pct}%</span></div><div class="bar" style="margin:4px 0"><span style="width:${d.pct}%;background:${cl}"></span></div></div>`; }).join('')||'<div class="muted">no drives</div>';
  $('#physList').innerHTML=(r.physical||[]).map(p=>{ const t=(p.type&&p.type!=='Unspecified')?p.type:(p.bus||''); const hc=(p.health&&p.health!=='Healthy')?'g-bad':''; return `<div class="muted" style="font-size:11px;padding:2px 0">🖴 ${esc(p.name||'')} · <b>${esc(t)}</b> · ${_gb(p.size)} <span class="${hc}">${esc(p.health||'')}</span></div>`; }).join('');
}catch(e){} }
async function loadGames(){ if(!RIG)return; try{ const r=await fetch('?api=games&rig='+RIG).then(r=>r.json()); if(!r.ok)return;
  $('#gameCount').textContent='('+(r.count||0)+')';
  $('#gameFolders').textContent = (r.folders&&r.folders.length)?('also scanning: '+r.folders.join(', ')):'';
  const icon={Steam:'🟦',Xbox:'🟩',Epic:'⬛',EA:'🟧',Ubisoft:'🔷',GOG:'🟪',Folder:'📁'};
  $('#gameList').innerHTML=(r.games||[]).map(g=>`<div class="sens-row"><span style="flex:0 0 auto">${icon[g.store]||'🎮'}</span><span class="nm">${esc(g.name)} <span class="hw">${esc(g.store||'')}${g.drive?(' · '+esc(g.drive)):''}</span></span><span class="v">${g.mb?_gb(g.mb*1e6):'—'}</span>${g.path?`<span class="chip" style="padding:2px 8px;margin:0" title="Launch on the rig" data-path="${esc(g.path)}" onclick="launchGame(this)">▶</span>`:''}</div>`).join('')||'<div class="muted">No games detected. Add your game folder above (e.g. D:\\XboxGames) and re-scan.</div>';
}catch(e){} }
async function launchGame(el){ const folder=(el&&el.dataset&&el.dataset.path)||''; if(!folder||!RIG)return; const o=el.textContent; el.textContent='…';
  try{ const fd=new FormData(); fd.append('rig',RIG); fd.append('folder',folder); const r=await fetch('?api=game_launch',{method:'POST',body:fd}).then(r=>r.json());
    el.textContent=r.ok?'✓':'▶'; if(!r.ok) alert('Launch: '+(r.error||'failed')); else setTimeout(()=>{el.textContent=o;},2500);
  }catch(e){ el.textContent=o; } }
async function addGameFolder(){ const v=$('#gf-input').value.trim(); if(!v)return; const cur=($('#gameFolders').textContent.replace('also scanning: ','')); const list=(cur?cur.split(', '):[]).concat([v]).filter((x,i,a)=>x&&a.indexOf(x)===i);
  try{ const fd=new FormData(); fd.append('folders',list.join(',')); await fetch('?api=games_folders_set',{method:'POST',body:fd}); $('#gf-input').value=''; $('#gameList').innerHTML='<div class="muted">re-scanning…</div>'; loadGames(); }catch(e){} }
// ── Fans & Sensors (LibreHardwareMonitor / OpenHardwareMonitor over SSH) ──
let FAN_NAMES={};
async function renameFan(el){ const orig=(el&&el.dataset&&el.dataset.fan)||''; if(!orig)return; const cur=FAN_NAMES[orig]||'';
  const v=prompt('Name this fan (e.g. CPU, GPU, Case Front). Leave empty to reset to the sensor name:', cur);
  if(v===null)return; try{ const fd=new FormData(); fd.append('rig',RIG); fd.append('orig',orig); fd.append('label',(v||'').trim()); const r=await fetch('?api=fan_name_set',{method:'POST',body:fd}).then(r=>r.json()); if(r&&r.ok){ FAN_NAMES[orig]=(v||'').trim(); refreshSensors(); } }catch(e){} }
async function refreshSensors(){ if(!RIG)return; try{ const r=await fetch('?api=sensors&rig='+RIG).then(r=>r.json());
  $('#sensLoading').style.display='none';
  if(!r.ok || r.need_helper){ $('#sensNeed').style.display='block'; $('#sensBody').style.display='none'; $('#sensBanner').style.display='none'; $('#sensSrc').textContent=''; return; }
  $('#sensNeed').style.display='none'; $('#sensBody').style.display='block'; $('#sensSrc').textContent='· via '+esc(r.src);
  $('#sensBanner').style.display = r.gpu_only ? 'block' : 'none';
  FAN_NAMES = r.fan_names || {};
  const ctl={}; (r.controls||[]).forEach(c=>ctl[c.name]=c.val);
  $('#fanCount').textContent = (r.fans||[]).length ? ('('+r.fans.length+')') : '';
  $('#tempCount').textContent = (r.temps||[]).length ? ('('+r.temps.length+')') : '';
  const BLADES='<path d="M50,50 Q34,14 50,7 Q66,20 50,50 Z" transform="rotate(0 50 50)"/><path d="M50,50 Q34,14 50,7 Q66,20 50,50 Z" transform="rotate(72 50 50)"/><path d="M50,50 Q34,14 50,7 Q66,20 50,50 Z" transform="rotate(144 50 50)"/><path d="M50,50 Q34,14 50,7 Q66,20 50,50 Z" transform="rotate(216 50 50)"/><path d="M50,50 Q34,14 50,7 Q66,20 50,50 Z" transform="rotate(288 50 50)"/>';
  const grad='<svg width="0" height="0" style="position:absolute"><defs><linearGradient id="fanGrad" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#8bf3ff"/><stop offset="1" stop-color="#b06bff"/></linearGradient><linearGradient id="fanStop" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ff8fa3"/><stop offset="1" stop-color="#ff4d6d"/></linearGradient></defs></svg>';
  $('#fanGrid').innerHTML = (r.fans||[]).length ? (grad + r.fans.map(f=>{ const rpm=f.val||0, dur=rpm>0?Math.max(0.25,3-Math.min(1,rpm/2600)*2.75):0, pct=ctl[f.name], stopped=(rpm===0), label=FAN_NAMES[f.name]||f.name;
    return `<div class="fan-tile ${stopped?'stopped':''}"><svg viewBox="0 0 100 100"><g style="transform-origin:50px 50px;animation:fanspin ${dur||3}s linear infinite;animation-play-state:${rpm>0?'running':'paused'}" fill="url(#${stopped?'fanStop':'fanGrad'})" opacity=".92">${BLADES}</g><circle cx="50" cy="50" r="8" fill="#0b1220" stroke="#39e1ff" stroke-width="2"/></svg>
      <div class="fan-name" data-fan="${esc(f.name)}" onclick="renameFan(this)">${esc(label)} <i class="fa-solid fa-pen ed"></i></div>
      <div class="fan-rpm">${rpm} <small>RPM</small></div>
      <div class="fan-pct">${stopped?'⚠ stopped':(pct!=null?(Math.round(pct)+'% speed'):(f.hw?esc(f.hw):'fan'))}</div></div>`; }).join('')) : '<div class="muted">No fan sensors (GPU/case fans may be hidden — run the monitor as Admin).</div>';
  // hottest REAL sensor (skip config thresholds/limits) → what actually drives the thermal score
  let _hv=null,_hn=null,_hh=null; (r.temps||[]).forEach(t=>{ const c=t.val||0; if(_realTemp(t.name)&&c>0&&c<=150&&(_hv==null||c>_hv)){ _hv=c;_hn=t.name;_hh=t.hw||''; } });
  STATE.hotTemp=_hv; STATE.hotName=_hn; STATE.hotHw=_hh;
  // SMOOTHED temp that drives the rig SCORE. The instantaneous hottest CORE spikes (e.g. 63↔76°C)
  // every second — normal CPU behaviour — and each °C is worth ~2.5 score points, so the raw hottest
  // reading made the score jump 73↔95 every poll. An exponential moving average keeps the score steady
  // while the reactor + "hottest sensor" readout still show the LIVE value.
  if(_hv!=null){ STATE.tempScore = (STATE.tempScore==null) ? _hv : (STATE.tempScore*0.8 + _hv*0.2); }
  $('#tempList').innerHTML = (r.temps||[]).length ? r.temps.map(t=>{ const c=t.val||0, thr=!_realTemp(t.name), hot=(!thr&&t.name===_hn&&t.hw===_hh&&c===_hv), cl=thr?'':(c>=85?'g-bad':(c>=72?'g-ok':''));
    return `<div class="sens-row${thr?' thresh':''}${hot?' hot':''}"><span class="nm">${esc(t.name)}${t.hw?(' <span class="hw">'+esc(t.hw)+'</span>'):''}${thr?' <span class="hw">threshold</span>':(hot?' <span class="hw" style="color:#ff8fa3">◄ hottest</span>':'')}</span><span class="v ${cl}">${c}°C</span></div>`; }).join('') : '<div class="muted">No temperature sensors.</div>';
  const more=[]; [['loads','%'],['clocks',' MHz'],['powers',' W'],['voltages',' V'],['data','']].forEach(([k,u])=>{ (r[k]||[]).slice(0,20).forEach(x=>more.push('<span class="chip" style="cursor:default">'+esc(x.name)+(x.hw?(' <span class="hw">'+esc(x.hw)+'</span>'):'')+': '+x.val+u+'</span>')); });
  $('#sensMore').innerHTML = more.length ? more.join(' ') : '<span class="muted">none</span>';
  { const hs=$('#hotSensor'); if(hs) hs.innerHTML = (_hv!=null) ? ('🌡 Hottest sensor: <b style="color:'+(_hv>=85?'#ff4d6d':_hv>=72?'#f0a92c':'#8fe6b0')+'">'+esc(_hn)+(_hh?(' ('+esc(_hh)+')'):'')+' · '+Math.round(_hv)+'°C</b>') : ''; }
  const fn=(r.fans||[]).map(f=>f.val||0); STATE.topFan = fn.length? Math.max(...fn) : null; STATE.fanCount=(r.fans||[]).length;
  STATE.fans = (r.fans||[]).map(f=>({name:(FAN_NAMES[f.name]||f.name), rpm:f.val||0})); STATE.temps=(r.temps||[]).map(t=>({name:t.name,val:t.val||0}));
  STATE.sensSrc = r.src||''; STATE.gpuOnly=!!r.gpu_only;
}catch(e){} }
function toggleAddSrv(){ const el=$('#addSrv'); el.style.display=el.style.display==='none'?'block':'none'; }
function protoHint(){ const p=$('#s-proto').value; const m={minecraft:'Minecraft Java: default port 25565 — live players + MOTD.',source:'Source/CS2/Rust/Gmod: default port 27015 (UDP) — live players + map.',tcp:'Any host:port — up/down + latency.',ping:'Reachability check (TCP 443).'}; $('#protoHint').textContent=m[p]||''; const dp={minecraft:25565,source:27015,tcp:443,ping:''}; if(!$('#s-port').value) $('#s-port').placeholder='port ('+(dp[p]||'')+')'; }
async function addServer(btn){ const host=$('#s-host').value.trim(); if(!host){ alert('Enter a host or IP'); return; } btn.disabled=true; btn.textContent='…';
  try{ const fd=new FormData(); fd.append('name',$('#s-name').value); fd.append('host',host); fd.append('port',$('#s-port').value); fd.append('proto',$('#s-proto').value); fd.append('game','Custom');
    const r=await fetch('?api=server_add',{method:'POST',body:fd}).then(r=>r.json());
    if(r.ok){ $('#s-name').value=''; $('#s-host').value=''; $('#s-port').value=''; loadServers(true); } else alert('Add failed: '+(r.error||'?'));
  }catch(e){ alert('error'); } btn.disabled=false; btn.textContent='Add & monitor'; }
async function delServer(id){ if(!confirm('Remove this server?'))return; try{ const fd=new FormData(); fd.append('id',id); await fetch('?api=server_del',{method:'POST',body:fd}); loadServers(false); }catch(e){} }

// ── OBS Overlay generator ──
async function genOverlay(btn){ if(!RIG){ alert('Pick a rig above first'); return; } btn.disabled=true;
  try{ const fd=new FormData(); fd.append('rig',RIG); fd.append('theme',$('#ov-theme').value);
    ['ping','fps','gpu','cpu','net'].forEach(w=>fd.append('w_'+w, $('#ov-'+w).checked?'1':'0'));
    const r=await fetch('?api=overlay_create',{method:'POST',body:fd}).then(r=>r.json());
    if(r.ok){ const url=location.origin+'/overlay.php?token='+r.token; $('#ovUrl').value=url; $('#ovPreview').src=url; $('#ovResult').style.display='block'; loadOverlays(); }
    else alert('Failed: '+(r.error||'?'));
  }catch(e){ alert('error'); } btn.disabled=false; }
function copyOv(){ const i=$('#ovUrl'); i.select(); try{ navigator.clipboard.writeText(i.value); }catch(e){ document.execCommand('copy'); } }
async function loadOverlays(){ try{ const r=await fetch('?api=overlays').then(r=>r.json()); if(!r.ok)return;
  $('#ovList').innerHTML = (r.overlays||[]).length ? ('<div class="muted" style="margin:8px 0 4px">Your overlays:</div>'+r.overlays.map(o=>`<div class="h-row" style="font-size:12px"><span class="nm" style="flex:0 0 auto">🔗 ${esc(o.rig)} · ${esc(o.theme)}</span><input readonly value="${esc(location.origin+'/overlay.php?token='+o.token)}" style="flex:1;background:#0c1424;color:#7fa;border:1px solid var(--bd);border-radius:6px;padding:4px 8px;font-family:monospace;font-size:11px"><span class="chip" onclick="delOverlay(${o.id})">revoke</span></div>`).join('')) : '';
}catch(e){} }
async function delOverlay(id){ if(!confirm('Revoke this overlay link?'))return; try{ const fd=new FormData(); fd.append('id',id); await fetch('?api=overlay_del',{method:'POST',body:fd}); loadOverlays(); }catch(e){} }

// ── themes + kiosk + Adaptive HUD Skinning (auto game-reactive skins) ──
const GAME_SKINS=[
  {re:/cyberpunk/i, cls:'gt-cyber', name:'Cyberpunk', emoji:'🌆'},
  {re:/elden ring|dark ?souls|sekiro|bloodborne|lies of p|\bnioh\b/i, cls:'gt-souls', name:'Soulslike', emoji:'⚔️'},
  {re:/valorant/i, cls:'gt-valorant', name:'Valorant', emoji:'🎯'},
  {re:/fortnite/i, cls:'gt-fortnite', name:'Fortnite', emoji:'🌀'},
  {re:/call of duty|warzone|\bcod\b|modern warfare|black ops/i, cls:'gt-cod', name:'Call of Duty', emoji:'🎖️'},
  {re:/minecraft/i, cls:'gt-mc', name:'Minecraft', emoji:'⛏️'},
  {re:/league of legends|\bdota\b|\bsmite\b|arcane/i, cls:'gt-arcane', name:'Arcane', emoji:'🔮'},
  {re:/counter.?strike|\bcs2\b|\bcsgo\b|cs:go/i, cls:'gt-cs', name:'Counter-Strike', emoji:'💣'},
  {re:/grand theft|\bgta\b|red dead|rockstar/i, cls:'gt-gta', name:'Rockstar', emoji:'🌴'},
  {re:/\bhalo\b/i, cls:'gt-halo', name:'Halo', emoji:'🛸'},
  {re:/apex ?legends/i, cls:'gt-apex', name:'Apex Legends', emoji:'🔺'},
  {re:/\bdoom\b|\bquake\b|wolfenstein/i, cls:'gt-doom', name:'DOOM', emoji:'👹'},
  {re:/forza|\bf1\b|gran turismo|need for speed|assetto|\bdirt\b|racing/i, cls:'gt-race', name:'Racing', emoji:'🏁'},
  {re:/helldivers/i, cls:'gt-hell', name:'Helldivers', emoji:'🪖'},
  {re:/starfield|no man'?s sky|elite dangerous|star citizen|mass effect|destiny|warframe/i, cls:'gt-sci', name:'Sci-Fi', emoji:'🚀'},
];
function skinForGame(g){ if(!g) return null; const t=((g.title||'')+' '+(g.pub||'')); for(const s of GAME_SKINS){ if(s.re.test(t)) return s; } return null; }
let THEME_MODE='auto', CUR_SKIN='', _lastToast='';
function clearGameSkin(){ if(CUR_SKIN){ document.body.classList.remove(CUR_SKIN); CUR_SKIN=''; } document.body.classList.remove('skinned'); }
function updateSkinBadge(sk){ const b=document.getElementById('skinBadge'); if(!b)return; if(sk && THEME_MODE==='auto'){ b.innerHTML='<span class="dot"></span> '+sk.emoji+' '+esc(sk.name)+' skin'; b.classList.add('on'); } else b.classList.remove('on'); }
function flashSkin(sk){ const t=document.getElementById('skinToast'); if(!t||!sk)return; if(_lastToast===sk.cls)return; _lastToast=sk.cls; t.textContent=sk.emoji+' '+sk.name+' skin activated'; t.classList.add('show'); setTimeout(function(){ t.classList.remove('show'); },2600); }
function applyAutoSkin(){ if(THEME_MODE!=='auto')return; const sk=skinForGame(typeof GAME!=='undefined'?GAME:null); const cls=sk?sk.cls:''; if(cls===CUR_SKIN){ updateSkinBadge(sk); return; } clearGameSkin(); if(cls){ document.body.classList.add(cls,'skinned'); CUR_SKIN=cls; } updateSkinBadge(sk); if(sk)flashSkin(sk); }
function setTheme(t){ THEME_MODE=t; document.body.classList.remove('t-matrix','t-neon','t-obsidian'); clearGameSkin(); _lastToast=''; if(t==='auto'){ applyAutoSkin(); } else if(t){ document.body.classList.add(t,'skinned'); updateSkinBadge(null); } else { updateSkinBadge(null); } try{ localStorage.setItem('nm_game_theme',t); }catch(e){} }
function toggleKiosk(){ document.body.classList.toggle('kiosk'); if(document.body.classList.contains('kiosk')){ try{ document.documentElement.requestFullscreen&&document.documentElement.requestFullscreen(); }catch(e){} } else { try{ document.fullscreenElement&&document.exitFullscreen(); }catch(e){} } }
(function(){ let t='auto'; try{ const s=localStorage.getItem('nm_game_theme'); if(s!==null) t=s; }catch(e){} const sel=$('#theme'); if(sel) sel.value=t; setTheme(t); if(new URLSearchParams(location.search).get('panel')==='1') document.body.classList.add('kiosk'); })();

// ── webhooks ──
async function loadWebhooks(){ try{ const r=await fetch('?api=webhooks_get').then(r=>r.json()); if(r.ok){ $('#wh-discord').value=r.discord||''; $('#wh-smarthome').value=r.smarthome||''; } }catch(e){} }
async function saveWebhooks(btn,test){ if(btn){btn.disabled=true;} try{ const fd=new FormData(); fd.append('discord',$('#wh-discord').value.trim()); fd.append('smarthome',$('#wh-smarthome').value.trim()); if(test)fd.append('test','1');
  const r=await fetch('?api=webhooks_set',{method:'POST',body:fd}).then(r=>r.json()); $('#whNote').textContent = r.ok?(test?'test sent ✓':'saved ✓'):('error: '+(r.error||'?')); }catch(e){ $('#whNote').textContent='error'; } if(btn)btn.disabled=false; }

// ═══════════════════════════════════════════════════════════════════════════
//  3D COMMAND DECK — immersive fullscreen cockpit. A three.js scene (synthwave
//  grid + nebula + reactor core that reacts to GPU/FPS) with metric "satellites"
//  orbiting in 3D; each satellite carries a crisp HTML label projected to screen.
// ═══════════════════════════════════════════════════════════════════════════
let DECK=null, deckOn=false, deckRAF=0, deckT=0;
// metric ring: key, label, unit, and how to pull + grade the live value from STATE
const fmtBW=b=>b==null?'—':(b>=1e6?(b/1e6).toFixed(1):(b/1e3).toFixed(0));
const fmtBWU=b=>b==null?'':(b>=1e6?'MB/s':'KB/s');
const DECK_METRICS=[
  {key:'fps',  lab:'FPS',      get:()=>STATE.fps,      sub:()=>STATE.low1!=null?('1% '+Math.round(STATE.low1)):'', unit:'frames/s', grade:v=>v==null?'':(v>=100?'good':v>=60?'ok':v>=30?'warn':'crit'), col:0x39e1ff},
  {key:'ping', lab:'PING',     get:()=>STATE.ping,     sub:()=>STATE.loss?(STATE.loss+'% loss'):'', unit:'ms', grade:v=>v==null?'':(v<40?'good':v<90?'ok':v<140?'warn':'crit'), col:0x2ee66e},
  {key:'jitter',lab:'JITTER',  get:()=>STATE.jitter,   unit:'ms', grade:v=>v==null?'':(v<5?'good':v<15?'ok':v<30?'warn':'crit'), col:0x5ea0ff},
  {key:'loss', lab:'PACKET LOSS', get:()=>STATE.loss,  unit:'%', grade:v=>v==null?'':(v<=0?'good':v<1?'ok':v<3?'warn':'crit'), col:0xff4d6d},
  {key:'down', lab:'NET DOWN',  get:()=>STATE.rx, fmt:v=>fmtBW(v), unit2:()=>fmtBWU(STATE.rx), unit:'', grade:()=>'ok', col:0x39e1ff},
  {key:'up',   lab:'NET UP',    get:()=>STATE.tx, fmt:v=>fmtBW(v), unit2:()=>fmtBWU(STATE.tx), unit:'', grade:()=>'ok', col:0xff4dd0},
  {key:'stab', lab:'STABILITY', get:()=>STATE.stability, unit:'%', grade:v=>v==null?'':(v>=90?'good':v>=75?'ok':v>=50?'warn':'crit'), col:0x2ee66e},
  {key:'gpu',  lab:'GPU LOAD', get:()=>STATE.gpu&&STATE.gpu.util!=null?Math.round(STATE.gpu.util):null, unit:'%', grade:v=>v==null?'':(v<80?'ok':v<95?'warn':'crit'), col:0xb06bff},
  {key:'gtmp', lab:'GPU TEMP', get:()=>STATE.gpu&&STATE.gpu.temp!=null?STATE.gpu.temp:null, unit:'°C', grade:v=>v==null?'':(v<70?'good':v<83?'ok':v<90?'warn':'crit'), col:0xff8f3a},
  {key:'cpu',  lab:'CPU',      get:()=>STATE.cpu, unit:'%', grade:v=>v==null?'':(v<70?'ok':v<90?'warn':'crit'), col:0x39e1ff},
  {key:'ram',  lab:'RAM',      get:()=>STATE.mem_total?Math.round(STATE.mem_used/STATE.mem_total*100):null, sub:()=>STATE.mem_total?((STATE.mem_used/1024).toFixed(1)+'/'+(STATE.mem_total/1024).toFixed(0)+'G'):'', unit:'%', grade:v=>v==null?'':(v<75?'ok':v<90?'warn':'crit'), col:0x7a5cff},
  {key:'vram', lab:'VRAM',     get:()=>STATE.gpu&&STATE.gpu.vram_total?Math.round(STATE.gpu.vram_used/STATE.gpu.vram_total*100):null, sub:()=>STATE.gpu&&STATE.gpu.vram_total?((STATE.gpu.vram_used/1024).toFixed(1)+'/'+(STATE.gpu.vram_total/1024).toFixed(0)+'G'):'', unit:'%', grade:v=>v==null?'':(v<80?'ok':v<93?'warn':'crit'), col:0x39e1ff},
  {key:'temp', lab:'SYS TEMP', get:()=>STATE.hotTemp!=null?STATE.hotTemp:(STATE.gpu&&STATE.gpu.temp!=null?STATE.gpu.temp:null), unit:'°C', grade:v=>v==null?'':(v<65?'good':v<80?'ok':v<90?'warn':'crit'), col:0xff4dd0},
];
function initDeck(){
  const cv=document.getElementById('deckgl');
  const rn=new THREE.WebGLRenderer({canvas:cv,antialias:true,alpha:true}); rn.setPixelRatio(Math.min(2,devicePixelRatio)); rn.setSize(innerWidth,innerHeight);
  const sc=new THREE.Scene(); sc.fog=new THREE.FogExp2(0x04060d,0.012);
  const cam=new THREE.PerspectiveCamera(58,innerWidth/innerHeight,.1,400); cam.position.set(0,5,36);
  // synthwave grid floor
  const grid=new THREE.GridHelper(220,80,0x2f4bff,0x14264d); grid.position.y=-9; grid.material.transparent=true; grid.material.opacity=.5; sc.add(grid);
  // nebula particles
  const N=1500, pg=new THREE.BufferGeometry(), pp=new Float32Array(N*3); for(let i=0;i<N;i++){ pp[i*3]=(Math.random()-.5)*180; pp[i*3+1]=(Math.random()-.5)*90; pp[i*3+2]=(Math.random()-.5)*120; } pg.setAttribute('position',new THREE.BufferAttribute(pp,3));
  const neb=new THREE.Points(pg,new THREE.PointsMaterial({color:0x4aa0ff,size:.32,map:NM_DOT,transparent:true,opacity:.6,blending:THREE.AdditiveBlending,depthWrite:false})); sc.add(neb);
  // reactor
  const rg=new THREE.Group(); rg.position.set(0,3,0); sc.add(rg);
  const core=new THREE.Mesh(new THREE.IcosahedronGeometry(3,1), new THREE.MeshBasicMaterial({color:0x39e1ff,wireframe:true,transparent:true,opacity:.9})); rg.add(core);
  const glow=new THREE.Mesh(new THREE.SphereGeometry(2.3,28,28), new THREE.MeshBasicMaterial({color:0x5ea0ff,transparent:true,opacity:.16,blending:THREE.AdditiveBlending,depthWrite:false})); rg.add(glow);
  const rings=[]; [[4.7,.05,0],[5.7,.045,1.1],[6.7,.06,2.2]].forEach(([R,t,rot])=>{ const m=new THREE.Mesh(new THREE.TorusGeometry(R,t,10,90), new THREE.MeshBasicMaterial({color:0xb06bff,transparent:true,opacity:.55})); m.rotation.x=rot; m.rotation.y=rot*.6; rg.add(m); rings.push(m); });
  // metric satellites + their HTML labels
  const labWrap=document.getElementById('deckLabels'); labWrap.innerHTML='';
  const sats=DECK_METRICS.map((m,i)=>{
    const mesh=new THREE.Mesh(new THREE.OctahedronGeometry(0.72,0), new THREE.MeshBasicMaterial({color:m.col,wireframe:true,transparent:true,opacity:.9})); sc.add(mesh);
    const halo=new THREE.Mesh(new THREE.SphereGeometry(1.0,16,16), new THREE.MeshBasicMaterial({color:m.col,transparent:true,opacity:.18,blending:THREE.AdditiveBlending,depthWrite:false})); mesh.add(halo);
    const el=document.createElement('div'); el.className='dlab'; el.innerHTML='<div class="dl">'+m.lab+'</div><div class="dv">—</div><div class="du"></div>'; labWrap.appendChild(el);
    return {m, mesh, el, dv:el.querySelector('.dv'), du:el.querySelector('.du'), R:9.5+(i%3)*1.9, spd:0.10+i*0.012, ph:i/DECK_METRICS.length*Math.PI*2};
  });
  // 3D cooling fans live in their own group; labels in an overlay layer
  const fanGroup=new THREE.Group(); sc.add(fanGroup);
  const fanLabels=document.createElement('div'); fanLabels.style.cssText='position:absolute;inset:0;z-index:2;pointer-events:none'; document.getElementById('deck').appendChild(fanLabels);
  DECK={rn,sc,cam,grid,neb,rg,core,glow,rings,sats,fanGroup,fanLabels,fans:[],tmp:new THREE.Vector3(),
        ctl:{az:0.35,pol:0.14,rad:36, taz:0.35,tpol:0.14,trad:36, drag:false,lx:0,ly:0,idle:0}};
  deckBindControls(cv);
  addEventListener('resize',deckResize);
}
// mouse / touch: drag to orbit the universe, wheel to zoom
function deckBindControls(cv){
  const c=DECK.ctl;
  const down=e=>{ c.drag=true; c.idle=0; const p=e.touches?e.touches[0]:e; c.lx=p.clientX; c.ly=p.clientY; };
  const move=e=>{ if(!c.drag)return; const p=e.touches?e.touches[0]:e; const dx=p.clientX-c.lx, dy=p.clientY-c.ly; c.lx=p.clientX; c.ly=p.clientY;
    c.taz-=dx*0.005; c.tpol=Math.max(-0.55,Math.min(1.25,c.tpol+dy*0.005)); c.idle=0; if(e.cancelable&&e.touches)e.preventDefault(); };
  const up=()=>{ c.drag=false; };
  cv.addEventListener('mousedown',down); addEventListener('mousemove',move); addEventListener('mouseup',up);
  cv.addEventListener('touchstart',down,{passive:false}); cv.addEventListener('touchmove',move,{passive:false}); addEventListener('touchend',up);
  cv.addEventListener('wheel',e=>{ c.trad=Math.max(14,Math.min(92,c.trad*(1+(e.deltaY>0?0.09:-0.09)))); c.idle=0; e.preventDefault(); },{passive:false});
  cv.style.cursor='grab'; cv.addEventListener('mousedown',()=>cv.style.cursor='grabbing'); addEventListener('mouseup',()=>cv.style.cursor='grab');
}
// a glowing 3D fan: outer ring + hub + 7 spinning blades
function deckMakeFan(){
  const g=new THREE.Group();
  const ring=new THREE.Mesh(new THREE.TorusGeometry(1.15,0.07,10,44), new THREE.MeshBasicMaterial({color:0x39e1ff,transparent:true,opacity:.82})); g.add(ring);
  const hub=new THREE.Mesh(new THREE.CylinderGeometry(0.2,0.2,0.22,18), new THREE.MeshBasicMaterial({color:0x0b1220})); hub.rotation.x=Math.PI/2; g.add(hub);
  const blades=new THREE.Group();
  for(let i=0;i<7;i++){ const b=new THREE.Mesh(new THREE.BoxGeometry(0.86,0.34,0.03), new THREE.MeshBasicMaterial({color:0x8bf3ff,transparent:true,opacity:.6}));
    const a=i/7*Math.PI*2; b.position.set(Math.cos(a)*0.52,Math.sin(a)*0.52,0); b.rotation.z=a+0.6; blades.add(b); }
  g.add(blades); g.userData.blades=blades; g.userData.ring=ring;
  return g;
}
// sync the fan row to the live sensor list, spin each by RPM, project labels
function deckUpdateFans(){
  const D=DECK, fans=STATE.fans||[];
  while(D.fans.length<fans.length){ const grp=deckMakeFan(); D.fanGroup.add(grp);
    const el=document.createElement('div'); el.className='fanlab'; el.innerHTML='<div class="fn"></div><div class="fr">—</div>'; D.fanLabels.appendChild(el);
    D.fans.push({grp,el,fn:el.querySelector('.fn'),fr:el.querySelector('.fr')}); }
  while(D.fans.length>fans.length){ const f=D.fans.pop(); D.fanGroup.remove(f.grp); f.el.remove(); }
  const n=D.fans.length, W=innerWidth,H=innerHeight, spread=Math.min(3.4, 24/Math.max(1,n));
  D.fans.forEach((f,i)=>{ const data=fans[i]||{}; const rpm=data.rpm||0, stopped=rpm===0;
    const x=(i-(n-1)/2)*spread; f.grp.position.set(x,-5.4,7); f.grp.scale.setScalar(Math.min(1.2,spread/2.7));
    const bl=f.grp.userData.blades; if(bl) bl.rotation.z += stopped?0:(0.03+Math.min(1,rpm/2600)*0.5);
    const col=stopped?0xff4d6d:0x39e1ff; f.grp.userData.ring.material.color.setHex(col); bl.children.forEach(b=>b.material.color.setHex(stopped?0xff8fa3:0x8bf3ff));
    f.fn.textContent=data.name||('Fan '+(i+1)); f.fr.textContent=stopped?'0 RPM':(rpm+' RPM'); f.el.className='fanlab'+(stopped?' stopped':'');
    D.tmp.set(x,-4.0,7).project(D.cam); const px=(D.tmp.x*0.5+0.5)*W, py=(-D.tmp.y*0.5+0.5)*H;
    f.el.style.opacity=D.tmp.z<1?'1':'0'; f.el.style.transform='translate(-50%,-50%) translate('+px.toFixed(1)+'px,'+py.toFixed(1)+'px)';
  });
  document.getElementById('deckfanhint').style.display = n? 'block':'none';
}
function deckResize(){ if(!DECK)return; DECK.rn.setSize(innerWidth,innerHeight); DECK.cam.aspect=innerWidth/innerHeight; DECK.cam.updateProjectionMatrix(); }
function deckFrame(){
  if(!deckOn)return; deckT+=0.016; const t=deckT, D=DECK; const g=STATE.gpu||{};
  // reactor reacts to GPU temp (color) + util (pulse) + FPS (spin)
  const temp=g.temp!=null?g.temp:40, util=g.util!=null?g.util:0, fps=STATE.fps!=null?STATE.fps:0;
  D.core.material.color.setHSL(THREE.MathUtils.clamp(0.62-temp/90*0.62,0,0.62),1,0.56);
  const spin=0.15+fps/240; D.core.rotation.y+=spin*0.05; D.core.rotation.x+=spin*0.02;
  const puls=1+util/100*0.28+Math.sin(t*4)*0.05; D.glow.scale.setScalar(puls); D.glow.material.opacity=0.12+util/100*0.22;
  D.rings.forEach((r,i)=>{ r.rotation.z+=(0.004+i*0.003)*(1+fps/160); });
  // nebula drift — faster with more network throughput
  const flow=Math.min(1,(STATE.rx+STATE.tx)/4e6); const pos=D.neb.geometry.attributes.position; const arr=pos.array;
  for(let i=1;i<arr.length;i+=3){ arr[i]-=0.05+flow*0.5; if(arr[i]<-45)arr[i]=45; } pos.needsUpdate=true; D.neb.rotation.y+=0.0006;
  // camera — mouse orbit + zoom, with a gentle idle drift that resumes after ~1.5s of no input
  const c=D.ctl; c.idle++; if(!c.drag && c.idle>90) c.taz+=0.0015;
  c.az+=(c.taz-c.az)*0.08; c.pol+=(c.tpol-c.pol)*0.08; c.rad+=(c.trad-c.rad)*0.08;
  D.cam.position.set(Math.sin(c.az)*Math.cos(c.pol)*c.rad, 3+Math.sin(c.pol)*c.rad, Math.cos(c.az)*Math.cos(c.pol)*c.rad); D.cam.lookAt(0,3,0);
  // grid scroll
  D.grid.position.z=((D.grid.position.z+0.06)%2.75);
  // satellites orbit + project labels
  const W=innerWidth,H=innerHeight;
  D.sats.forEach(s=>{
    const a=t*s.spd+s.ph; const wx=Math.cos(a)*s.R, wz=Math.sin(a)*s.R*0.62, wy=3+Math.sin(a*0.9+s.ph)*1.7;
    s.mesh.position.set(wx,wy,wz); s.mesh.rotation.x+=0.01; s.mesh.rotation.y+=0.015;
    const raw=s.m.get(); const grade=s.m.grade(raw);
    // colour the node by health
    const gc={good:0x2ee66e,ok:0x39e1ff,warn:0xf0a92c,crit:0xff4d6d}[grade]||s.m.col; s.mesh.material.color.setHex(gc); if(s.mesh.children[0])s.mesh.children[0].material.color.setHex(gc);
    // value text
    s.el.className='dlab'+(grade?(' c-'+grade):'');
    if(raw==null){ s.dv.innerHTML='<small>—</small>'; s.du.textContent=s.m.unit2?s.m.unit2():s.m.unit; }
    else { const sub=s.m.sub?s.m.sub():''; const val=s.m.fmt?s.m.fmt(raw):Math.round(raw); s.dv.innerHTML=val+(sub?(' <small>'+sub+'</small>'):''); s.du.textContent=s.m.unit2?s.m.unit2():s.m.unit; }
    // project to screen
    D.tmp.set(wx,wy,wz).project(D.cam);
    const px=(D.tmp.x*0.5+0.5)*W, py=(-D.tmp.y*0.5+0.5)*H;
    const front=(wz+ s.R*0.62)/(s.R*1.24);            // 0=back .. 1=front
    const op=0.5+0.5*front, sc2=0.92+0.26*front;      // stay legible even when orbiting to the back
    s.el.style.transform='translate(-50%,-50%) translate('+px.toFixed(1)+'px,'+py.toFixed(1)+'px) scale('+sc2.toFixed(2)+')';
    s.el.style.opacity=op.toFixed(2); s.el.style.zIndex=Math.round(front*100);
  });
  deckUpdateFans();
  D.rn.render(D.sc,D.cam);
  // HUD text (throttled)
  if((deckT*60|0)%20===0) deckHUD();
  deckRAF=requestAnimationFrame(deckFrame);
}
function deckHUD(){
  document.getElementById('deckGame').textContent = STATE.game? STATE.game.title : (RIG?'NO GAME':'NEURU');
  document.getElementById('deckRigName').textContent = STATE.rigName || 'command deck';
  const se=STATE.session; document.getElementById('dpSession').textContent = se? ((se.ended_at?'⏱ last ':'🎮 ')+(se.title||'session')+' · '+(se.mins||0)+'m'+(se.avg_fps?(' · '+Math.round(se.avg_fps)+'fps'):'')) : '⏱ no session';
  const bp=document.getElementById('dpBoost'); bp.textContent=STATE.boost?'⚡ Game Mode ON':'Game Mode off'; bp.classList.toggle('on',!!STATE.boost);
  const fmt=b=>b>1e6?(b/1e6).toFixed(1)+'MB/s':(b/1e3).toFixed(0)+'KB/s';
  document.getElementById('dpNet').innerHTML='🌐 ↓ <b>'+fmt(STATE.rx||0)+'</b> &nbsp; ↑ <b>'+fmt(STATE.tx||0)+'</b>';
  // floating RIG SPECS panel
  const g=STATE.gpu||{}, gb=b=>b>=1e12?(b/1e12).toFixed(2)+' TB':(b/1e9).toFixed(0)+' GB';
  document.getElementById('spGpu').textContent  = g.name||'—';
  document.getElementById('spVram').textContent = g.vram_total? ((g.vram_used||0)+' / '+g.vram_total+' MB') : '—';
  document.getElementById('spRam').textContent  = STATE.mem_total? ((STATE.mem_used/1024).toFixed(1)+' / '+(STATE.mem_total/1024).toFixed(0)+' GB') : '—';
  document.getElementById('spCpu').textContent  = STATE.cpu!=null? (STATE.cpu+' %') : '—';
  document.getElementById('spDisk').textContent = STATE.diskTotal? (gb(STATE.diskFree)+' free / '+gb(STATE.diskTotal)) : '—';
  document.getElementById('spSens').textContent = STATE.fanCount? (STATE.fanCount+' fans · '+((STATE.temps||[]).length)+' temps') : (STATE.sensSrc||'—');
}
function openDeck(){
  if(!RIG){ alert('Pick a rig first — the deck shows that rig\'s live telemetry.'); return; }
  if(!DECK) initDeck();
  const d=document.getElementById('deck'); d.classList.add('on'); deckOn=true; deckFanLoad(); loadDna();
  try{ d.requestFullscreen&&d.requestFullscreen(); }catch(e){}
  document.addEventListener('fullscreenchange',deckFsChange);
  document.addEventListener('keydown',deckKey);
  deckResize(); deckHUD();
  // force-refresh every stream so the deck is instantly current
  refreshVitals(); refreshFps(); refreshRadar(); refreshHogs(); refreshSensors(); loadDisks();
  cancelAnimationFrame(deckRAF); deckFrame();
}
function closeDeck(){
  deckOn=false; cancelAnimationFrame(deckRAF);
  document.getElementById('deck').classList.remove('on');
  document.removeEventListener('keydown',deckKey);
  document.removeEventListener('fullscreenchange',deckFsChange);
  try{ document.fullscreenElement&&document.exitFullscreen(); }catch(e){}
}
function deckKey(e){ if(e.key==='Escape'){ closeDeck(); } }
function deckFsChange(){ if(!document.fullscreenElement && deckOn) closeDeck(); }

initBG(); initFX(); loop(); loadRigs();
loadServers(false).then(()=>loadServers(true)); setInterval(()=>loadServers(true), 60000);   // cached instant → live update → refresh each min
loadOverlays(); loadWebhooks();
if(window.NMLoader)NMLoader.hide();
</script>
</body></html>
