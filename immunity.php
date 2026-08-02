<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Collective Immunity UI. Block a threat (domain/regex/IP) once and it
// fans out to EVERY Pi-hole + firewall instantly. Auto-detects port-scans (syslog)
// and malicious DNS (Pi-hole query logs). RBAC: 'immunity'. Engine: nm_immunity.php.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_immunity.php');
require_once('nm_nettools.php');   // nm_geo_badge() — country flag for attacker IPs
if (is_file(__DIR__.'/nm_decoy.php')) require_once('nm_decoy.php');   // for the "Divert to honeypot" action
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'immunity')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=immunity'); exit;
}
nm_imm_ensure($conn);
$uid = (int)($_SESSION['UID'] ?? 0);
$canConfig = nm_can($conn,'net_mon_config');

if ($api !== '') {
    header('Content-Type: application/json; charset=utf-8');
    $body = json_decode(file_get_contents('php://input'), true) ?? $_POST;
    // release the PHP session lock BEFORE any slow SSH fan-out — otherwise a bulk vaccinate freezes the
    // whole portal for this user until it finishes (no handler writes $_SESSION after this point).
    if (function_exists('session_write_close')) @session_write_close();
    @set_time_limit(0);   // an SSH fan-out to many firewalls/Pi-holes can outlast max_execution_time (would 500 mid-distribution)

    if ($api === 'data') {
        // Resolve a syslog reporter ("x86 (10.10.0.1)") to the NEURU node NAME the user
        // knows — match by the node's IP or its SNMP hostname. Also figure out whether
        // that device is one of the firewall enforcement points the block actually lands on.
        $nodeByIp=[]; $nodeByHost=[];
        if($nr=$conn->query("SELECT display_name,ip_address,hostname FROM nm_nodes")){
            while($x=$nr->fetch_assoc()){
                if(!empty($x['ip_address'])) $nodeByIp[$x['ip_address']]=$x['display_name'];
                if(!empty($x['hostname']))   $nodeByHost[strtolower($x['hostname'])]=$x['display_name'];
            }
        }
        $fwt = nm_imm_firewall_targets($conn);
        $fwNames=[]; $fwIps=[];
        foreach($fwt as $d){ $fwNames[strtolower($d['name'])]=1; if(!empty($d['host_ip'])) $fwIps[$d['host_ip']]=1; }
        $resolve = function($rb) use ($nodeByIp,$nodeByHost,$fwNames,$fwIps){
            $rb=(string)$rb; if($rb==='') return ['raw'=>'','name'=>'','ip'=>'','known'=>false,'enforced'=>null];
            $rip=''; if(preg_match('/(\d{1,3}(?:\.\d{1,3}){3})/',$rb,$m)) $rip=$m[1];
            $rhost=trim(preg_replace('/\s*\(.*$/','',$rb));
            $name=''; if($rip!=='' && isset($nodeByIp[$rip])) $name=$nodeByIp[$rip];
            elseif($rhost!=='' && isset($nodeByHost[strtolower($rhost)])) $name=$nodeByHost[strtolower($rhost)];
            $enforced = ($name!=='' && isset($fwNames[strtolower($name)])) || ($rip!=='' && isset($fwIps[$rip]));
            return ['raw'=>$rb,'name'=>$name,'ip'=>$rip,'known'=>($name!==''),'enforced'=>$enforced];
        };
        // which IPs are currently being DIVERTED into a honeypot (Deception Grid)? So the list can
        // show "diverted" instead of a bare "pending" once the operator sends an IP to deception.
        $divertedIps = [];
        if ($conn->query("SHOW TABLES LIKE 'nm_decoy_diversions'")->num_rows) {
            $dr = $conn->query("SELECT src_ip, MAX(id) id FROM nm_decoy_diversions WHERE status='active' GROUP BY src_ip");
            while ($dr && $x=$dr->fetch_assoc()) $divertedIps[$x['src_ip']] = (int)$x['id'];
        }
        $threats=[];
        foreach(nm_imm_list($conn) as $t){
            $rep=$resolve($t['reported_by']??'');
            $geo = ($t['ind_type']==='ip') ? nm_geo_badge($conn, $t['indicator']) : null;   // where's this attacker?
            $threats[]=['id'=>(int)$t['id'],'indicator'=>$t['indicator'],'type'=>$t['ind_type'],'severity'=>$t['severity'],
                'source'=>$t['source'],'detail'=>$t['detail'],'hits'=>(int)$t['hits'],'status'=>$t['status'],
                'reported_raw'=>$rep['raw'],'reported_name'=>$rep['name'],'reported_ip'=>$rep['ip'],
                'reported_known'=>$rep['known'],'enforced'=>$rep['enforced'],
                'diverted'=>($divertedIps[$t['indicator']] ?? 0),
                'geo'=>$geo?['flag'=>$geo['flag'],'country'=>$geo['country'],'city'=>$geo['city']]:null,
                'ok'=>(int)$t['distributed_ok'],'fail'=>(int)$t['distributed_fail'],'last_seen'=>$t['last_seen'],'vaccinated_at'=>$t['vaccinated_at']];
        }
        $ph = count(nm_ph_servers($conn,true));
        echo json_encode(['ok'=>true,'threats'=>$threats,'counts'=>nm_imm_counts($conn),
            'piholes'=>$ph,'firewalls'=>count($fwt),
            'fw_points'=>array_map(fn($d)=>['name'=>$d['name'],'ip'=>$d['host_ip']], $fwt)]); exit;
    }
    if ($api === 'actions') {
        echo json_encode(['ok'=>true,'actions'=>nm_imm_actions($conn,(int)($_GET['id']??0))]); exit;
    }
    if (($_SERVER['REQUEST_METHOD']??'GET')!=='POST') { echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }

    if ($api === 'add') {
        $ind=trim((string)($body['indicator']??'')); $type=(string)($body['type']??'domain');
        if($ind===''){ echo json_encode(['ok'=>false,'error'=>'Indicator required']); exit; }
        $a=nm_imm_add_threat($conn,$ind,$type,'manual','high','Manually added',$uid);
        if(empty($a['ok'])){ echo json_encode($a); exit; }
        $res=['ok'=>true,'id'=>$a['id'],'new'=>$a['new']];
        if(!empty($body['vaccinate'])) $res['vaccine']=nm_imm_vaccinate($conn,(int)$a['id']);
        echo json_encode($res); exit;
    }
    if ($api === 'vaccinate') { echo json_encode(nm_imm_vaccinate($conn,(int)($body['id']??0))); exit; }
    if ($api === 'vaccinate_bulk') {   // vaccinate many threats at once → STREAM per-threat progress (NDJSON)
        $ids = array_values(array_filter(array_map('intval', (array)($body['ids'] ?? []))));
        header('Content-Type: application/x-ndjson; charset=utf-8');
        header('X-Accel-Buffering: no');                 // defeat nginx/proxy buffering so frames arrive live
        @ini_set('zlib.output_compression', '0');
        @set_time_limit(0);                              // a big fan-out over SSH can outlast max_execution_time
        while (ob_get_level() > 0) @ob_end_flush();
        $emit = function($o){ echo json_encode($o), "\n"; @ob_flush(); @flush(); };
        $n = count($ids); $done=0; $dist=0; $failed=0;
        $emit(['t'=>'start','n'=>$n]);
        foreach ($ids as $k => $tid) {
            $th = nm_imm_get($conn, $tid); $label = $th ? (string)($th['indicator'] ?? ('#'.$tid)) : ('#'.$tid);
            $emit(['t'=>'progress','i'=>$k+1,'n'=>$n,'id'=>$tid,'indicator'=>$label]);   // "applying #k of n"
            try { $r = nm_imm_vaccinate($conn, $tid); } catch (\Throwable $e) { $r = ['ok'=>false,'error'=>$e->getMessage()]; }
            $ok = !empty($r['ok']); if ($ok) { $done++; $dist += (int)($r['distributed'] ?? 0); $failed += (int)($r['failed'] ?? 0); }
            $emit(['t'=>'result','i'=>$k+1,'n'=>$n,'id'=>$tid,'indicator'=>$label,'ok'=>$ok,
                'distributed'=>(int)($r['distributed'] ?? 0),'failed'=>(int)($r['failed'] ?? 0),'error'=>$ok?null:($r['error'] ?? 'failed')]);
        }
        $emit(['t'=>'done','count'=>$n,'vaccinated'=>$done,'distributed'=>$dist,'failed'=>$failed]);
        exit;
    }
    if ($api === 'revoke')    { echo json_encode(nm_imm_revoke($conn,(int)($body['id']??0))); exit; }
    if ($api === 'dismiss')   { nm_imm_set_status($conn,(int)($body['id']??0),'dismissed'); echo json_encode(['ok'=>true]); exit; }
    if ($api === 'divert') {   // send an IP threat to the Deception Grid (divert to a honeypot)
        if (!function_exists('nm_decoy_quick_divert')) { echo json_encode(['ok'=>false,'error'=>'Deception module unavailable']); exit; }
        if (!checkAccess($conn,'deception')) { echo json_encode(['ok'=>false,'error'=>'You lack the deception permission']); exit; }
        $t = nm_imm_get($conn, (int)($body['id']??0));
        if (!$t) { echo json_encode(['ok'=>false,'error'=>'Threat not found']); exit; }
        if (($t['ind_type']??'') !== 'ip') { echo json_encode(['ok'=>false,'error'=>'Only IP threats can be diverted (a dst-nat needs an IP).']); exit; }
        if (function_exists('session_write_close')) @session_write_close();   // SSH to the router ahead
        echo json_encode(nm_decoy_quick_divert($conn, (string)$t['indicator'], $uid)); exit;
    }
    if ($api === 'detect_now') {
        $ps=nm_imm_detect_portscan($conn); $dn=nm_imm_detect_dns($conn); $added=0;
        foreach($ps as $p){ $det='Port scan — '.$p['ports'].' ports'.(!empty($p['target'])?(' → '.$p['target']):''); $r=nm_imm_add_threat($conn,$p['ip'],'ip','portscan','high',$det,null,$p['reported_by']??''); if(!empty($r['new']))$added++; }
        foreach($dn as $d){ $r=nm_imm_add_threat($conn,$d,'domain','dns','high','Matched DNS threat pattern'); if(!empty($r['new']))$added++; }
        echo json_encode(['ok'=>true,'portscan'=>count($ps),'dns'=>count($dn),'new'=>$added]); exit;
    }
    if ($api === 'save_settings') {
        if(!$canConfig){ echo json_encode(['ok'=>false,'error'=>'Not allowed']); exit; }
        $set=function($k,$v)use($conn){ $st=$conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)"); $st->bind_param('ss',$k,$v); $st->execute(); $st->close(); };
        foreach(['immunity_enabled','imm_auto_vaccinate','imm_detect_portscan','imm_detect_dns'] as $k) $set($k, !empty($body[$k])?'1':'0');
        $set('imm_portscan_window', (string)max(1,(int)($body['imm_portscan_window']??10)));
        $set('imm_portscan_ports',  (string)max(2,(int)($body['imm_portscan_ports']??10)));
        $set('imm_dns_patterns',    substr((string)($body['imm_dns_patterns']??''),0,4000));
        $fw = $body['imm_fw_device_ids'] ?? [];
        $set('imm_fw_device_ids', is_array($fw)?implode(',',array_map('intval',$fw)):'');
        nm_audit($conn,'immunity.settings');
        echo json_encode(['ok'=>true]); exit;
    }
    echo json_encode(['ok'=>false,'error'=>'Unknown endpoint']); exit;
}

$counts=nm_imm_counts($conn);
$devices=[]; $dr=$conn->query("SELECT id,name,host_ip,vendor_key FROM nm_config_devices ORDER BY name"); while($dr&&$x=$dr->fetch_assoc()) $devices[]=$x;
$fwids = array_filter(array_map('intval', explode(',', (string)nm_imm_setting($conn,'imm_fw_device_ids',''))));
$S=[ 'enabled'=>nm_imm_setting($conn,'immunity_enabled','1'),'auto'=>nm_imm_setting($conn,'imm_auto_vaccinate','0'),
     'ps'=>nm_imm_setting($conn,'imm_detect_portscan','1'),'dns'=>nm_imm_setting($conn,'imm_detect_dns','0'),
     'win'=>nm_imm_setting($conn,'imm_portscan_window','10'),'ports'=>nm_imm_setting($conn,'imm_portscan_ports','10'),
     'patterns'=>nm_imm_setting($conn,'imm_dns_patterns','') ];
log_user_action($conn,'view_page','immunity.php');
$videoFile = !empty($_SESSION['user_bgsite_video']) ? $_SESSION['user_bgsite_video'] : 'sg_homepage_notext8-1-2022.mp4';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Collective Immunity | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --glass:rgba(255,255,255,.06); --border:rgba(255,255,255,.12); --accent:#4da3ff; --ok:#2ecc71; --warn:#f39c12; --crit:#e74c3c; --imm:#2ecc71; }
*,*::before,*::after{ box-sizing:border-box; }
body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:#000; color:#e6e9ee; }
#bg-video{ position:fixed; inset:0; min-width:100%; min-height:100%; z-index:-1; object-fit:cover; opacity:.18; }
.wrap{ max-width:1320px; margin:0 auto; padding:18px 20px 40px; } a{ color:var(--accent); text-decoration:none; }
.glass{ background:var(--glass); backdrop-filter:blur(16px); border:1px solid var(--border); border-radius:14px; }
.card{ padding:16px 18px; margin-bottom:16px; } .card h3{ margin:0 0 12px; font-size:12px; color:var(--accent); text-transform:uppercase; letter-spacing:1px; }
.kpis{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:16px; } @media(max-width:760px){ .kpis{ grid-template-columns:repeat(2,1fr); } }
.kpi{ padding:14px 16px; } .kpi .n{ font-size:26px; font-weight:800; } .kpi .l{ font-size:11px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; }
.grid2{ display:grid; grid-template-columns:1.6fr 1fr; gap:16px; } @media(max-width:900px){ .grid2{ grid-template-columns:1fr; } }
label{ display:block; font-size:11px; color:#8a909a; text-transform:uppercase; letter-spacing:.5px; margin:10px 0 4px; }
.inp,select,textarea{ width:100%; background:rgba(0,0,0,.4); border:1px solid var(--border); color:#eee; border-radius:9px; padding:9px 11px; font-size:13px; font-family:inherit; }
textarea{ resize:vertical; min-height:60px; font-family:Consolas,monospace; }
.btn{ background:rgba(255,255,255,.06); border:1px solid var(--border); color:#cfd3da; padding:8px 13px; border-radius:9px; cursor:pointer; font-size:12px; display:inline-flex; gap:7px; align-items:center; }
.btn:hover{ background:rgba(255,255,255,.13); color:#fff; }
.btn.go{ background:rgba(46,204,113,.18); border-color:var(--imm); color:#7ee2a8; } .btn.go:hover{ background:var(--imm); color:#04140a; }
.fbtn{ background:rgba(255,255,255,.04); border:1px solid var(--border); color:#9aa; padding:5px 12px; border-radius:20px; cursor:pointer; font-size:12px; }
.fbtn:hover{ color:#fff; border-color:var(--accent); }
.fbtn.on{ background:rgba(77,163,255,.18); border-color:var(--accent); color:#cfe4ff; font-weight:700; }
.fc{ font-size:10px; background:rgba(255,255,255,.08); border-radius:10px; padding:0 6px; margin-left:3px; }
.btn.danger:hover{ border-color:var(--crit); color:var(--crit); }
.row{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
table{ width:100%; border-collapse:collapse; font-size:13px; } th,td{ text-align:left; padding:9px 10px; border-bottom:1px solid rgba(255,255,255,.07); vertical-align:middle; }
th{ color:#7c828c; font-size:11px; text-transform:uppercase; letter-spacing:.5px; }
.b{ font-size:9px; font-weight:800; padding:2px 7px; border-radius:5px; text-transform:uppercase; }
.t-domain{ background:rgba(46,204,113,.16); color:var(--imm);} .t-regex{ background:rgba(155,89,182,.16); color:#c08fd6;} .t-ip{ background:rgba(243,156,18,.16); color:var(--warn);}
.st-active{ background:rgba(46,204,113,.16); color:var(--imm);} .st-pending{ background:rgba(243,156,18,.16); color:var(--warn);} .st-revoked{ background:rgba(138,144,154,.16); color:#8a909a;} .st-dismissed{ background:rgba(138,144,154,.12); color:#777;}
.src{ font-size:9px; color:#888; }
.muted{ color:#7c828c; font-size:12px; } .mono{ font-family:Consolas,monospace; }
.toggle{ display:flex; align-items:center; gap:8px; margin:8px 0; font-size:13px; }
.sw{ position:relative; width:38px; height:20px; } .sw input{ display:none; } .sw i{ position:absolute; inset:0; background:#333; border-radius:20px; transition:.2s; } .sw i::before{ content:''; position:absolute; width:14px; height:14px; left:3px; top:3px; background:#888; border-radius:50%; transition:.2s; } .sw input:checked + i{ background:rgba(46,204,113,.5);} .sw input:checked + i::before{ transform:translateX(18px); background:var(--imm);}
.fwlist{ max-height:160px; overflow:auto; border:1px solid var(--border); border-radius:8px; padding:8px; }
.fwlist label{ display:flex; align-items:center; gap:8px; text-transform:none; letter-spacing:0; color:#cfd3da; margin:4px 0; font-size:12.5px; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php include('header.php'); ?>
<video autoplay muted loop playsinline id="bg-video"><source src="/videos/<?= htmlspecialchars($videoFile) ?>" type="video/mp4"></video>
<div class="wrap">
<?php nm_page_header('<i class="fas fa-shield-virus"></i>Collective Immunity', '', 'Crowdsourced Threat Defense', 'fa-solid fa-shield-virus',
    '<button class="refresh-btn" onclick="detectNow(this)"><i class="fas fa-radar"></i> Scan now</button>'); ?>

<div class="kpis">
  <div class="glass kpi"><div class="n" style="color:var(--imm)" id="k-active"><?= (int)$counts['active'] ?></div><div class="l">Active vaccines</div></div>
  <div class="glass kpi"><div class="n" style="color:var(--warn)" id="k-pending"><?= (int)$counts['pending'] ?></div><div class="l">Pending review</div></div>
  <div class="glass kpi"><div class="n" id="k-ph">—</div><div class="l">Pi-holes protected</div></div>
  <div class="glass kpi"><div class="n" id="k-fw">—</div><div class="l">Firewall targets</div></div>
</div>

<div class="grid2">
  <div>
    <!-- Manual vaccine -->
    <div class="glass card">
      <h3><i class="fas fa-syringe"></i> Vaccinate the whole fleet</h3>
      <p class="muted" style="margin:0 0 10px;">Block an indicator once → it's pushed to <b>every Pi-hole</b> (domains/regex) and <b>firewall</b> (IPs) instantly.</p>
      <div class="row">
        <select class="inp" id="v-type" style="max-width:130px;"><option value="domain">Domain</option><option value="regex">Regex</option><option value="ip">IP (firewall)</option></select>
        <input class="inp" id="v-ind" placeholder="bad-domain.com  ·  (^|\.)evil\.net$  ·  203.0.113.5" style="flex:1;min-width:200px;">
        <button class="btn go" onclick="vaccinate(this)" title="Add this NEW indicator and vaccinate it"><i class="fas fa-plus"></i> Add &amp; vaccinate</button>
      </div>
      <span class="muted" id="v-msg"></span>
    </div>
    <!-- Threats -->
    <div class="glass card">
      <h3><i class="fas fa-biohazard"></i> Threats &amp; distribution</h3>
      <div id="fw-banner" style="background:rgba(77,163,255,.07);border:1px solid rgba(77,163,255,.25);border-radius:10px;padding:9px 12px;margin-bottom:10px;font-size:12px;line-height:1.55;color:#cfe0f5;"></div>
      <div id="filter-bar" style="display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap;">
        <button class="fbtn on" data-f="all"       onclick="setFilter('all',this)">All <span class="fc" id="fc-all">0</span></button>
        <button class="fbtn"    data-f="pending"   onclick="setFilter('pending',this)">Pending <span class="fc" id="fc-pending">0</span></button>
        <button class="fbtn"    data-f="active"    onclick="setFilter('active',this)">Active <span class="fc" id="fc-active">0</span></button>
        <button class="fbtn"    data-f="diverted"  onclick="setFilter('diverted',this)" title="IPs currently being diverted into a honeypot (Deception Grid)">🎭 Diverted <span class="fc" id="fc-diverted">0</span></button>
        <button class="fbtn"    data-f="dismissed" onclick="setFilter('dismissed',this)">Dismissed <span class="fc" id="fc-dismissed">0</span></button>
      </div>
      <div id="empty" class="muted" style="display:none;padding:8px;">No threats yet. Add one above or hit “Scan now”. 🛡️</div>
      <div id="bulk-bar" style="display:none;align-items:center;gap:12px;margin-bottom:10px;padding:11px 14px;background:rgba(46,204,113,.12);border:1px solid rgba(46,204,113,.5);border-radius:10px;">
        <span style="color:var(--imm);font-weight:800;font-size:14px;"><i class="fas fa-check-double"></i> <span id="bulk-n">0</span> threat(s) selected</span>
        <button class="btn go" onclick="vaccSelected(this)" style="font-weight:700;"><i class="fas fa-shield-virus"></i> Vaccinate the <span id="bulk-n2">0</span> selected → push to Pi-holes/firewalls</button>
        <button class="btn" onclick="clearSel()">Clear</button>
        <span id="bulk-status" style="font-size:13px;color:#cfe0f5;font-weight:600;"></span>
      </div>
      <div style="overflow:auto;max-height:62vh;border-radius:8px;"><table id="tbl"><thead><tr>
        <th style="width:30px;text-align:center;position:sticky;top:0;background:#11151d;z-index:2;"><input type="checkbox" id="sel-all" onchange="selAll(this)" title="Select all on this page"></th>
        <th style="position:sticky;top:0;background:#11151d;z-index:2;">Indicator</th><th style="position:sticky;top:0;background:#11151d;z-index:2;">Type</th><th style="position:sticky;top:0;background:#11151d;z-index:2;">Source</th><th style="position:sticky;top:0;background:#11151d;z-index:2;">Status</th><th style="position:sticky;top:0;background:#11151d;z-index:2;">Spread</th><th style="position:sticky;top:0;background:#11151d;z-index:2;"></th>
      </tr></thead><tbody id="tb"><tr><td colspan="7" class="muted" style="text-align:center;padding:16px;">Loading…</td></tr></tbody></table></div>
      <div id="pager" style="display:none;align-items:center;justify-content:flex-end;gap:12px;margin-top:10px;">
        <span class="muted" id="pg-info"></span>
        <button class="btn" id="pg-prev" onclick="pageGo(-1)"><i class="fas fa-chevron-left"></i> Prev</button>
        <button class="btn" id="pg-next" onclick="pageGo(1)">Next <i class="fas fa-chevron-right"></i></button>
      </div>
    </div>
  </div>

  <!-- Settings -->
  <div class="glass card">
    <h3><i class="fas fa-gears"></i> Detection &amp; targets</h3>
    <?php $dis = $canConfig?'':'disabled'; ?>
    <div class="toggle"><label class="sw" style="cursor:pointer"><input type="checkbox" id="s-enabled" <?= $S['enabled']!=='0'?'checked':'' ?> <?= $dis ?>><i></i></label> Immunity engine enabled</div>
    <div class="toggle"><label class="sw" style="cursor:pointer"><input type="checkbox" id="s-auto" <?= $S['auto']==='1'?'checked':'' ?> <?= $dis ?>><i></i></label> <b>Auto-vaccinate</b> on detect <span class="muted">(off = review first)</span></div>
    <div class="toggle"><label class="sw" style="cursor:pointer"><input type="checkbox" id="s-ps" <?= $S['ps']!=='0'?'checked':'' ?> <?= $dis ?>><i></i></label> Detect port-scans (syslog)</div>
    <div class="row" style="gap:8px;">
      <div style="flex:1;"><label>Scan window (min)</label><input class="inp" id="s-win" value="<?= htmlspecialchars($S['win']) ?>" <?= $dis ?>></div>
      <div style="flex:1;"><label>Min distinct ports</label><input class="inp" id="s-ports" value="<?= htmlspecialchars($S['ports']) ?>" <?= $dis ?>></div>
    </div>
    <div class="toggle" style="margin-top:10px;"><label class="sw" style="cursor:pointer"><input type="checkbox" id="s-dns" <?= $S['dns']==='1'?'checked':'' ?> <?= $dis ?>><i></i></label> Detect malicious DNS (Pi-hole logs)</div>
    <label>DNS threat patterns <span class="muted">(regex, one per line)</span></label>
    <textarea class="inp" id="s-patterns" placeholder="\.ru$&#10;(^|\.)malware&#10;dga-[a-z0-9]{12}" <?= $dis ?>><?= htmlspecialchars($S['patterns']) ?></textarea>
    <label id="fw-config">Firewall enforcement points <span class="muted">(Config Manager devices — IP blocks are SSH'd here)</span></label>
    <div class="fwlist">
      <?php if(!$devices): ?><span class="muted">No Config Manager devices. Add routers/firewalls there first.</span>
      <?php else: foreach($devices as $d): ?>
      <label><input type="checkbox" class="fwchk" value="<?= (int)$d['id'] ?>" <?= in_array((int)$d['id'],$fwids,true)?'checked':'' ?> <?= $dis ?>> <?= htmlspecialchars($d['name'].' ('.$d['host_ip'].' · '.$d['vendor_key'].')') ?></label>
      <?php endforeach; endif; ?>
    </div>
    <?php if($canConfig): ?><div class="row" style="margin-top:12px;"><button class="btn" onclick="saveSettings(this)"><i class="fas fa-save"></i> Save</button><span class="muted" id="s-msg"></span></div>
    <?php else: ?><div class="muted" style="margin-top:10px;">Configuration access needed to edit.</div><?php endif; ?>
    <div class="muted" style="margin-top:12px;line-height:1.6;border-top:1px solid var(--border);padding-top:10px;">
      <b>MikroTik firewalls:</b> IP blocks go to an address-list <code>NEURU-BLOCK</code>. Add this drop rule once:<br>
      <code style="font-size:10.5px;">/ip firewall filter add chain=input src-address-list=NEURU-BLOCK action=drop</code>
    </div>
  </div>
</div>
</div>
<script>
const CAN=<?= $canConfig?'true':'false' ?>;
let FW_POINTS=[], THREATS={}, PIHOLES=0;
let ALL_THREATS=[], SELECTED=new Set(), PAGE=1, FILTER='all'; const PAGE_SIZE=100;
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }   // also escape quotes → safe in title="…" attributes (untrusted syslog/geo)

// In-page confirm/toast — the browser can PERMANENTLY suppress native confirm()/alert()
// (the "don't show again" checkbox makes confirm() always return false → actions silently
// do nothing). These custom dialogs can't be suppressed.
function nmConfirm(msg){
  return new Promise(res=>{
    const ov=document.createElement('div');
    ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.7);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;z-index:100000;padding:20px;';
    ov.innerHTML='<div style="max-width:460px;width:100%;background:#11151d;border:1px solid rgba(255,255,255,.14);border-radius:14px;padding:22px;color:#e6e9ee;">'
      +'<div style="font-size:13.5px;line-height:1.55;white-space:pre-wrap;margin-bottom:18px;">'+esc(msg)+'</div>'
      +'<div style="display:flex;gap:10px;justify-content:flex-end;">'
      +'<button id="nmc-no" class="btn">Cancel</button><button id="nmc-yes" class="btn go"><i class="fas fa-shield-virus"></i> Confirm</button></div></div>';
    document.body.appendChild(ov);
    const done=v=>{ ov.remove(); res(v); };
    ov.querySelector('#nmc-yes').onclick=()=>done(true);
    ov.querySelector('#nmc-no').onclick=()=>done(false);
    ov.addEventListener('click',e=>{ if(e.target===ov) done(false); });
  });
}
function nmToast(msg,ok){
  const t=document.createElement('div');
  t.style.cssText='position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:100001;background:#11151d;border:1px solid '+(ok===false?'rgba(231,76,60,.6)':'rgba(46,204,113,.6)')+';border-left:4px solid '+(ok===false?'#e74c3c':'#2ecc71')+';border-radius:10px;padding:11px 18px;font-size:13px;color:#e6e9ee;box-shadow:0 8px 30px rgba(0,0,0,.5);max-width:90vw;';
  t.textContent=msg; document.body.appendChild(t);
  setTimeout(()=>{ t.style.transition='opacity .4s'; t.style.opacity='0'; setTimeout(()=>t.remove(),420); }, 3200);
}

// ── bulk selection ──────────────────────────────────────────────────────────
function updSel(){ const n=SELECTED.size;
  document.getElementById('bulk-bar').style.display=n?'flex':'none';
  document.getElementById('bulk-n').textContent=n; const b2=document.getElementById('bulk-n2'); if(b2)b2.textContent=n;
  const all=document.querySelectorAll('.tsel'), sa=document.getElementById('sel-all');
  if(sa){ const onpage=[...all]; sa.checked=onpage.length>0 && onpage.every(c=>SELECTED.has(+c.dataset.id)); } }
function selAll(cb){ document.querySelectorAll('.tsel').forEach(c=>{ c.checked=cb.checked; if(cb.checked)SELECTED.add(+c.dataset.id); else SELECTED.delete(+c.dataset.id); }); updSel(); }
function clearSel(){ SELECTED.clear(); document.querySelectorAll('.tsel,#sel-all').forEach(c=>c.checked=false); updSel(); }
async function vaccSelected(btn){
  const ids=[...SELECTED];
  if(!ids.length) return;
  if(!await nmConfirm('Vaccinate '+ids.length+' selected threat(s)?\n\nEach IP threat is pushed to the firewall enforcement points and each domain threat to all enabled Pi-holes.')) return;
  const st=document.getElementById('bulk-status');
  if(btn)btn.disabled=true; if(st)st.innerHTML='<i class="fas fa-spinner fa-spin"></i> starting…';
  let done=0,dist=0,failed=0,total=ids.length;
  try{
    const resp=await fetch('?api=vaccinate_bulk',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids})});
    if(!resp.ok||!resp.body) throw new Error('HTTP '+resp.status);
    const reader=resp.body.getReader(), dec=new TextDecoder(); let buf='';
    for(;;){ const {value,done:rd}=await reader.read(); if(rd)break; buf+=dec.decode(value,{stream:true});
      let nl; while((nl=buf.indexOf('\n'))>=0){ const line=buf.slice(0,nl).trim(); buf=buf.slice(nl+1); if(!line)continue;
        let f; try{ f=JSON.parse(line); }catch(e){ continue; }
        if(f.t==='start'){ total=f.n; if(st)st.innerHTML='<i class="fas fa-spinner fa-spin"></i> 0/'+total+' — pushing to Pi-holes/firewalls…'; }
        else if(f.t==='progress'){ if(st)st.innerHTML='<i class="fas fa-spinner fa-spin"></i> '+f.i+'/'+f.n+' — <b>'+esc(f.indicator)+'</b>…'; }
        else if(f.t==='result'){ if(f.ok){done++;dist+=f.distributed||0;failed+=f.failed||0;} else failed+=1;
          if(st)st.innerHTML='<i class="fas fa-shield-virus"></i> '+f.i+'/'+f.n+' done · '+dist+' applied'+(failed?(' · <span style="color:#ff6b6b">'+failed+' failed</span>'):''); }
        else if(f.t==='done'){ if(st)st.innerHTML='<i class="fas fa-check-double" style="color:#2ecc71"></i> '+f.vaccinated+'/'+f.count+' vaccinated · '+f.distributed+' applied'+(f.failed?(' · <span style="color:#ff6b6b">'+f.failed+' failed</span>'):''); }
      }
    }
    nmToast('Vaccinated '+done+'/'+total+' → '+dist+' target(s)'+(failed?(', '+failed+' failed'):'')+'.', failed?false:true);
  }catch(e){ if(st)st.innerHTML='<span style="color:#ff6b6b">✖ '+esc(e.message||e)+'</span>'; nmToast('Bulk vaccinate failed: '+(e.message||e), false); }
  if(btn)btn.disabled=false;
  setTimeout(function(){ if(st)st.textContent=''; },6000);
  clearSel(); load();
}
function reporterInfo(t){
  if(!t.reported_raw) return '';
  // show the NEURU node NAME the user knows; raw syslog id only as a hover tooltip
  const label = t.reported_known
    ? `<b title="syslog id: ${esc(t.reported_raw)}" style="color:#dbe7f5;">${esc(t.reported_name)}</b>`
    : `<b title="not matched to a monitored node">${esc(t.reported_raw)}</b> <span style="color:#f0a559;">— unknown device</span>`;
  let chip='';
  if(t.type==='ip' && FW_POINTS.length){
    chip = t.enforced
      ? ` <span style="color:#16c79a;font-weight:700;font-size:10px;white-space:nowrap;"><i class="fas fa-check"></i> block enforces here</span>`
      : ` <span title="The device that SAW this is not one of your firewall enforcement points, so vaccinating won't block on the router that actually sees this traffic. Add it under Detection & targets ↓." style="color:#f0a559;font-weight:700;font-size:10px;white-space:nowrap;"><i class="fas fa-triangle-exclamation"></i> won't block here — not an enforcement point</span>`;
  }
  return `<div class="src" style="margin-top:3px;"><i class="fas fa-satellite-dish" style="opacity:.65"></i> seen by ${label}${chip}</div>`;
}
async function post(api,obj){ return fetch('immunity.php?api='+api,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj||{})}).then(r=>r.json()).catch(()=>({ok:false,error:'failed'})); }
async function load(){
  const r=await fetch('immunity.php?api=data').then(r=>r.json()).catch(()=>null); if(!r||!r.ok)return;
  document.getElementById('k-active').textContent=r.counts.active||0;
  document.getElementById('k-pending').textContent=r.counts.pending||0;
  document.getElementById('k-ph').textContent=r.piholes; document.getElementById('k-fw').textContent=r.firewalls;
  FW_POINTS=r.fw_points||[]; PIHOLES=r.piholes||0; THREATS={}; (r.threats||[]).forEach(t=>THREATS[t.id]=t);
  const fwNames=FW_POINTS.map(p=>p.name);
  document.getElementById('fw-banner').innerHTML =
    `<i class="fas fa-shield-halved"></i> On <b>Vaccinate</b>: <b>IP</b> threats are blocked on `+
    (fwNames.length?`<b style="color:#cfe4ff">${fwNames.map(esc).join(', ')}</b>`:`<b style="color:#f0a559">no firewalls configured yet</b>`)+
    ` · <b>domain</b> threats on <b>${PIHOLES}</b> Pi-hole(s). `+
    `<a href="#fw-config" onclick="document.getElementById('fw-config').scrollIntoView({behavior:'smooth'});return false;">Change which routers ↓</a>`;
  ALL_THREATS = r.threats || [];
  // drop selections for threats that no longer exist
  const ids = new Set(ALL_THREATS.map(t=>t.id)); [...SELECTED].forEach(id=>{ if(!ids.has(id)) SELECTED.delete(id); });
  if(!ALL_THREATS.length){ document.getElementById('tbl').style.display='none'; document.getElementById('pager').style.display='none'; document.getElementById('empty').style.display='block'; return; }
  document.getElementById('tbl').style.display=''; document.getElementById('empty').style.display='none';
  renderThreats();
}
function rowHTML(t){
  const spread = t.status==='active' ? `<span style="color:var(--imm)">${t.ok}✓</span>${t.fail?` <span style="color:var(--crit)">${t.fail}✗</span>`:''}` : '<span class="muted">—</span>';
  let acts='';
  if(t.status==='pending') acts=`<button class="btn go" onclick="vacc(${t.id},this)"><i class="fas fa-shield-virus"></i> Vaccinate</button> ${t.type==='ip'?(t.diverted?`<a class="btn" href="deception.php" title="This IP is being diverted — open Deception Grid to watch/promote it" style="text-decoration:none;color:#d9c8ff;border-color:rgba(155,107,255,.5);"><i class="fas fa-mask"></i> Diverted ↗</a> `:`<button class="btn" onclick="divert(${t.id},this)" title="Divert to a honeypot instead of blocking (Deception Grid)"><i class="fas fa-mask"></i> Divert</button> `):''}<button class="btn" onclick="dismiss(${t.id})">Dismiss</button>`;
  else if(t.status==='active') acts=`<button class="btn" onclick="vacc(${t.id},this)" title="Re-push"><i class="fas fa-rotate"></i></button> <button class="btn danger" onclick="revoke(${t.id})"><i class="fas fa-trash"></i> Revoke</button>`;
  else acts=`<button class="btn go" onclick="vacc(${t.id},this)"><i class="fas fa-shield-virus"></i> Re-vaccinate</button>`;
  return `<tr>
    <td style="text-align:center;"><input type="checkbox" class="tsel" data-id="${t.id}" ${SELECTED.has(t.id)?'checked':''} onchange="toggleSel(${t.id},this.checked)"></td>
    <td class="mono"><b>${esc(t.indicator)}</b>${t.hits>1?` <span class="muted">×${t.hits}</span>`:''}${t.geo?` <span class="muted" title="${esc(t.geo.country)}${t.geo.city?' · '+esc(t.geo.city):''}" style="font-family:initial;">${t.geo.flag} ${esc(t.geo.country)}</span>`:''}</td>
    <td><span class="b t-${t.type}">${t.type}</span></td>
    <td>${esc(t.source)}<div class="src">${esc(t.detail||'')}</div>${reporterInfo(t)}</td>
    <td><span class="b st-${t.status}">${t.status}</span>${t.diverted?` <span class="b" style="background:rgba(155,107,255,.18);color:#d9c8ff;" title="Being diverted into a honeypot (Deception Grid) — not blocked, deceived">🎭 diverted</span>`:''}</td>
    <td>${spread}</td>
    <td style="white-space:nowrap;text-align:right;">${acts}</td></tr>`;
}
function filteredThreats(){ return FILTER==='all' ? ALL_THREATS : (FILTER==='diverted' ? ALL_THREATS.filter(t=>t.diverted) : ALL_THREATS.filter(t=>t.status===FILTER)); }
function renderThreats(){
  // filter counts (always over the full set)
  const c={all:ALL_THREATS.length,pending:0,active:0,dismissed:0,diverted:0};
  ALL_THREATS.forEach(t=>{ if(c[t.status]!==undefined)c[t.status]++; if(t.diverted)c.diverted++; });
  for(const k of ['all','pending','active','dismissed','diverted']){ const e=document.getElementById('fc-'+k); if(e)e.textContent=c[k]; }
  const list=filteredThreats(), total=list.length, pages=Math.max(1,Math.ceil(total/PAGE_SIZE));
  if(PAGE>pages) PAGE=pages; if(PAGE<1) PAGE=1;
  const start=(PAGE-1)*PAGE_SIZE, slice=list.slice(start, start+PAGE_SIZE);
  document.getElementById('tb').innerHTML = total ? slice.map(rowHTML).join('')
    : `<tr><td colspan="7" class="muted" style="text-align:center;padding:18px;">No ${FILTER==='all'?'':FILTER+' '}threats.</td></tr>`;
  const pg=document.getElementById('pager');
  if(total>PAGE_SIZE){ pg.style.display='flex';
    document.getElementById('pg-info').textContent=`${start+1}–${Math.min(start+PAGE_SIZE,total)} of ${total}`;
    document.getElementById('pg-prev').disabled=(PAGE<=1); document.getElementById('pg-next').disabled=(PAGE>=pages);
  } else pg.style.display='none';
  updSel();
}
function setFilter(f,btn){ FILTER=f; PAGE=1;
  document.querySelectorAll('#filter-bar .fbtn').forEach(b=>b.classList.toggle('on', b===btn));
  renderThreats(); }
function pageGo(d){ PAGE+=d; renderThreats(); }
function toggleSel(id,on){ if(on)SELECTED.add(+id); else SELECTED.delete(+id); updSel(); }
async function vaccinate(btn){
  const ind=document.getElementById('v-ind').value.trim(); const type=document.getElementById('v-type').value;
  if(!ind){ document.getElementById('v-msg').textContent='Enter an indicator.'; return; }
  btn.disabled=true; document.getElementById('v-msg').textContent='Distributing…';
  const r=await post('add',{indicator:ind,type,vaccinate:1}); btn.disabled=false;
  if(r.ok){ const v=r.vaccine||{}; document.getElementById('v-msg').textContent=`Vaccinated → ${v.distributed||0} target(s)${v.failed?`, ${v.failed} failed`:''}.`; document.getElementById('v-ind').value=''; load(); }
  else document.getElementById('v-msg').textContent=r.error||'Failed';
}
async function vacc(id,btn){
  const t=THREATS[id]||{}; let targets='', warn='';
  if(t.type==='ip'){
    const names=FW_POINTS.map(p=>p.name+' ('+p.ip+')');
    if(!names.length){ nmToast('No firewall enforcement points configured — add one under “Detection & targets” first.', false); return; }
    targets='Firewall(s):\n  • '+names.join('\n  • ');
    if(t.enforced===false){
      const who=t.reported_name||t.reported_raw||'a device';
      warn='\n\n⚠ WARNING: this threat was SEEN BY “'+who+'”, which is NOT in the list above. The block applies on the router(s) listed — NOT on the one that sees this traffic. Add that device as an enforcement point to stop it at the source.';
    }
  } else {
    targets='All enabled Pi-hole(s): '+PIHOLES;
  }
  if(!await nmConfirm('Vaccinate '+(t.indicator||'')+' ?\n\nThis pushes a block to:\n'+targets+warn)) return;
  if(btn)btn.disabled=true; const r=await post('vaccinate',{id}); if(btn)btn.disabled=false;
  if(!r.ok){ nmToast(r.error||'Failed', false); } else { nmToast('Done — distributed to '+(r.distributed||0)+' target(s)'+(r.failed?(', '+r.failed+' failed'):'')+'.', r.failed?false:true); }
  load();
}
async function revoke(id){ if(!await nmConfirm('Revoke this block from all Pi-holes/firewalls?'))return; const r=await post('revoke',{id}); if(!r.ok)nmToast(r.error||'Failed', false); load(); }
async function dismiss(id){ await post('dismiss',{id}); load(); }
async function divert(id,btn){
  const t=THREATS[id]||{};
  if(!await nmConfirm('Divert '+(t.indicator||'this IP')+' into a honeypot?\n\nAdds a time-boxed dst-nat on your border router (Deception Grid) — auto-reverts on the TTL. The attacker is watched instead of blocked.')) return;
  if(btn){ btn.disabled=true; btn.innerHTML='<i class="fas fa-spinner fa-spin"></i>'; }
  const r=await post('divert',{id});
  if(r.ok) nmToast('Diverted to honeypot (auto-reverts in '+(r.ttl_min||30)+'m). Watch it in Deception Grid.',true);
  else nmToast(r.error||'Divert failed',false);
  load();
}
async function detectNow(btn){ btn.disabled=true; const r=await post('detect_now',{}); btn.disabled=false;
  nmToast(r.ok?`Scan: ${r.portscan} port-scan signal(s), ${r.dns} DNS match(es) → ${r.new} new threat(s).`:(r.error||'Failed'), r.ok!==false); load(); }
async function saveSettings(btn){
  btn.disabled=true;
  const fw=[...document.querySelectorAll('.fwchk:checked')].map(c=>+c.value);
  const r=await post('save_settings',{ immunity_enabled:document.getElementById('s-enabled').checked, imm_auto_vaccinate:document.getElementById('s-auto').checked,
    imm_detect_portscan:document.getElementById('s-ps').checked, imm_detect_dns:document.getElementById('s-dns').checked,
    imm_portscan_window:document.getElementById('s-win').value, imm_portscan_ports:document.getElementById('s-ports').value,
    imm_dns_patterns:document.getElementById('s-patterns').value, imm_fw_device_ids:fw });
  btn.disabled=false; document.getElementById('s-msg').textContent=r.ok?'Saved ✓':(r.error||'Failed'); load();
}
load(); setInterval(load, 30000);
</script>
</body></html>
