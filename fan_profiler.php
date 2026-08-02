<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — FAN PROFILER. Visual, WebGL cockpit that reads the gamer's FanControl
// config JSONs (over the same SSH as Game Mode), draws every fan curve with the
// PC's LIVE temperature marked on it, advises how to run cooler, lets you switch
// the active profile on-demand, and apply Cooler / Balanced / Quiet presets.
// Sibling of PC Doctor + Connection Doctor. Reached from Game Mode. Perm 'gaming'.
// Engine: nm_fanprofiler.php
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
require_once('nm_fanprofiler.php');
include('logger.php');

$api = $_GET['api'] ?? '';
if (!checkAccess($conn, 'gaming')) {
    if ($api) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Access denied']); exit; }
    header('Location: /denied_access.php?page=gaming'); exit;
}
if (function_exists('session_write_close')) @session_write_close();

// resolve a rig (monitored Windows host) → its SSH
function _fp_rig($conn, int $id) {
    $rows = function_exists('nm_win_hosts') ? nm_win_hosts($conn) : [];
    foreach ($rows as $r) if ((int)$r['id'] === $id) return $r;
    return null;
}
function _fp_safe_name(string $n): string { return preg_match('/^[A-Za-z0-9 ._\-()]+\.json$/', $n) ? $n : ''; }
// best-effort live temps from the rig's sensors (cpu / gpu / hottest)
// classify an LHM temperature sensor → component category. UNIVERSAL: trust LHM's HardwareType
// (Cpu/GpuNvidia/GpuAmd/GpuIntel/Memory/Storage/Motherboard/SuperIO…) for ANY PC; the brand/name
// regex is only a fallback for OpenHardwareMonitor or the data.json web path (which lack the type).
function _fp_cat(string $hw, string $name, string $type=''): string {
    $ty = strtolower(trim($type));
    if ($ty !== '') {
        if (strpos($ty,'gpu') !== false) return 'gpu';                 // GpuNvidia / GpuAmd / GpuIntel
        if ($ty === 'cpu') return 'cpu';
        if ($ty === 'memory') return 'ram';
        if ($ty === 'storage') return 'storage';
        if (in_array($ty, ['motherboard','superio','embeddedcontroller','cooler','psu'], true)) return 'mobo';
    }
    $s = strtolower($hw.' '.$name);
    if (preg_match('/nvidia|geforce|radeon|\brtx\b|\bgtx\b|\bgpu\b|arc a\d/', $s)) return 'gpu';
    if (preg_match('/team group|g\.?skill|corsair (venge|domin)|\bddr\d|\bdimm\b|udimm|sodimm/', $s)) return 'ram';
    if (preg_match('/nvme|\bssd\b|\bhdd\b|samsung|wd_black|wd black|\bwdc?\b|sn\d{3}|snv|crucial|seagate|kingston|sandisk|sabrent|\badata\b|solid state|composite temp/', $s)) return 'storage';
    if (preg_match('/ryzen|threadripper|core i[3579]|\bi[3579]-|xeon|\bcpu\b|tctl|tccd|\bccd\b|p-core|e-core|core (max|average)|package/', $s)) return 'cpu';
    if (preg_match('/nuvoton|\bite\b|it8[0-9]|fintek|nct\d|motherboard|mainboard|chipset|\bvrm\b|system|gigabyte|asrock|\basus\b|\bmsi\b|b[467][45]0|x[567][67]0|z[679]90|aquacomputer|water|coolant|temperature #\d/', $s)) return 'mobo';
    return 'other';
}
// friendly short name for a physical drive from its LHM hardware label
function _fp_drive_short(string $hw): string {
    if (preg_match('/kingston/i',$hw)) return 'Kingston NVMe';
    if (preg_match('/wd_black|wd black|\bwdc?\b|western|\bsn\d{3}/i',$hw)) return 'WD NVMe';
    if (preg_match('/samsung/i',$hw)) return 'Samsung SSD';
    if (preg_match('/crucial/i',$hw)) return 'Crucial SSD';
    if (preg_match('/seagate/i',$hw)) return 'Seagate';
    $w = preg_split('/\s+/', trim($hw)); return $w && $w[0]!=='' ? (ucfirst(strtolower($w[0])).' drive') : 'Drive';
}
function _fp_temps($ssh, bool $fast=false): array {
    $t = ['cpu'=>null,'gpu'=>null,'gpumem'=>null,'mobo'=>null,'vrm'=>null,'ram'=>null,'storage'=>null,'hot'=>null,
          'hotName'=>null,'hotHw'=>null,'sensors'=>[],'src'=>null];
    try {
        $s = function_exists('nm_gaming_sensors') ? nm_gaming_sensors($ssh) : ['temps'=>[]];
        $t['src'] = $s['src'] ?? null;
        // LIVE fan RPMs straight from LHM (the real source of truth — the config's saved Calibration
        // is often stale/incomplete, e.g. an AIO pump reads 452 there but 3140 live). Keyed by sensor id.
        $t['fanById'] = []; $t['fansLHM'] = [];
        foreach (($s['fans'] ?? []) as $fn) {
            $id = (string)($fn['id'] ?? ''); $rpm = (int)round((float)($fn['val'] ?? 0));
            if ($id !== '') $t['fanById'][$id] = $rpm;
            $t['fansLHM'][] = ['id'=>$id,'name'=>(string)($fn['name'] ?? ''),'hw'=>(string)($fn['hw'] ?? ''),'rpm'=>$rpm];
        }
        $rows = []; $max = null;
        foreach (($s['temps'] ?? []) as $tp) {
            $name = trim((string)($tp['name'] ?? $tp['label'] ?? '')); $hw = trim((string)($tp['hw'] ?? ''));
            $v = (float)($tp['val'] ?? 0);
            if ($v <= 0 || $v > 150) continue;                       // skip zero/garbage readings
            // skip pseudo-temps that AREN'T a live temperature: headroom + threshold/config sensors
            if (preg_match('/distance to tjmax|tjmax|warning|critical|thermal sensor|high limit|low limit|resolution/i', $name)) continue;
            $rows[] = ['name'=>$name,'hw'=>$hw,'val'=>round($v,1),'cat'=>_fp_cat($hw,$name,(string)($tp['type'] ?? ''))];
            if ($max === null || $v > $max) { $max=$v; $t['hotName']=$name; $t['hotHw']=$hw; }
        }
        $best = function($cat) use ($rows) { $b=null; foreach($rows as $r){ if($r['cat']===$cat && ($b===null||$r['val']>$b)) $b=$r['val']; } return $b; };
        $t['cpu']=$best('cpu'); $t['mobo']=$best('mobo'); $t['ram']=$best('ram'); $t['storage']=$best('storage');
        // GPU: separate core temp from memory-junction temp
        foreach ($rows as $r){ if($r['cat']==='gpu'){
            if (stripos($r['name'],'junction')!==false || stripos($r['name'],'memory')!==false){ if($t['gpumem']===null||$r['val']>$t['gpumem'])$t['gpumem']=$r['val']; }
            else { if($t['gpu']===null||$r['val']>$t['gpu'])$t['gpu']=$r['val']; } } }
        if ($t['gpu']===null) $t['gpu']=$best('gpu');
        foreach ($rows as $r){ if(preg_match('/vrm|vcore|vddc|\bmos\b|vreg/i',$r['name']) && ($t['vrm']===null||$r['val']>$t['vrm'])) $t['vrm']=$r['val']; }
        $t['hot']=$max;
        // clean per-component HUD list (dedupe 20+ P/E-core rows → one CPU row; one row per drive; etc.)
        $rep=[]; $seen=[];
        $push=function($label,$val,$cat) use (&$rep,&$seen){ if($val===null)return; if(isset($seen[$label]))return; $seen[$label]=1; $rep[]=['label'=>$label,'val'=>round($val,1),'cat'=>$cat]; };
        $push('CPU Package', $t['cpu'], 'cpu');
        $push('GPU Core', $t['gpu'], 'gpu');
        $push('GPU Mem', $t['gpumem'], 'gpu');
        $push('Mobo / VRM', $t['vrm']!==null?$t['vrm']:$t['mobo'], 'mobo');
        $push('RAM', $t['ram'], 'ram');
        $drv=[]; foreach($rows as $r){ if($r['cat']==='storage'){ $d=_fp_drive_short($r['hw']); if(!isset($drv[$d])||$r['val']>$drv[$d]) $drv[$d]=$r['val']; } }
        foreach($drv as $d=>$v){ $push($d, $v, 'storage'); }
        $t['sensors']=$rep;
    } catch (\Throwable $e) {}
    // authoritative GPU core temp from nvidia-smi (skipped in fast/live mode — LHM "GPU Core" is used instead)
    if (!$fast) {
        try { $g = nm_win_ps($ssh, 'try{ (nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader,nounits) }catch{ \'\' }', 10);
              $gt = (int)trim(_nm_g_out($g)); if ($gt > 0 && $gt < 130) $t['gpu'] = $gt; } catch (\Throwable $e) {}
    }
    return $t;
}

if ($api) {
    header('Content-Type: application/json');
    try {
        if ($api === 'rigs') {
            $rows = function_exists('nm_win_hosts') ? nm_win_hosts($conn) : [];
            echo json_encode(['ok'=>true,'rigs'=>array_map(fn($r)=>['id'=>(int)$r['id'],'name'=>$r['name']], $rows)]); exit;
        }
        $rid = (int)($_GET['rig'] ?? $_POST['rig'] ?? 0);
        $h = $rid ? _fp_rig($conn, $rid) : null;
        $ssh = $h && function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn, $h) : null;

        if ($api === 'list') {
            if (!$ssh) { echo json_encode(['ok'=>false,'error'=>'pick a rig (a monitored Windows PC)']); exit; }
            $dir = nm_fp_dir($conn, $rid);
            $r = nm_fp_list($ssh, $dir); $r['dir'] = $dir; echo json_encode($r); exit;
        }
        if ($api === 'setdir') {
            nm_fp_dir_set($conn, $rid, trim((string)($_POST['dir'] ?? ''))); echo json_encode(['ok'=>true,'dir'=>nm_fp_dir($conn,$rid)]); exit;
        }
        if ($api === 'config') {
            if (!$ssh) { echo json_encode(['ok'=>false,'error'=>'no SSH to the rig']); exit; }
            $name = _fp_safe_name((string)($_GET['file'] ?? '')); if ($name==='') { echo json_encode(['ok'=>false,'error'=>'bad config name']); exit; }
            $dir = nm_fp_dir($conn, $rid); $path = rtrim($dir,'\\') . '\\' . $name;
            $raw = nm_fp_read_raw($ssh, $path);
            $parsed = nm_fp_parse($raw);
            if (empty($parsed['ok'])) { echo json_encode(['ok'=>false,'error'=>$parsed['error'] ?? 'parse failed']); exit; }
            $temps = _fp_temps($ssh);
            $parsed['temps'] = $temps;                                        // includes fansLHM (id+name+rpm) → client matches RPM to each fan
            unset($parsed['temps']['fanById']);                               // internal only
            $parsed['tips']  = nm_fp_analyze($parsed, $temps);
            $parsed['ok'] = true; echo json_encode($parsed); exit;
        }
        if ($api === 'live') {                                               // lightweight realtime poll (≤2s): temps + fan RPMs, no nvidia-smi/config read
            if (!$ssh) { echo json_encode(['ok'=>false,'error'=>'no ssh']); exit; }
            $temps = _fp_temps($ssh, true);
            unset($temps['fanById']);
            echo json_encode(['ok'=>true,'temps'=>$temps]); exit;
        }
        if ($api === 'apply') {
            if (!$ssh) { echo json_encode(['ok'=>false,'error'=>'no SSH']); exit; }
            $name = _fp_safe_name((string)($_POST['file'] ?? '')); if ($name==='') { echo json_encode(['ok'=>false,'error'=>'bad name']); exit; }
            $dir = nm_fp_dir($conn, $rid); $path = rtrim($dir,'\\') . '\\' . $name;
            log_user_action($conn, 'fanprofiler_apply', ($h['name'] ?? ('rig '.$rid)).' → '.$name);
            echo json_encode(nm_fp_apply($ssh, $path)); exit;
        }
        if ($api === 'preset') {
            if (!$ssh) { echo json_encode(['ok'=>false,'error'=>'no SSH']); exit; }
            $name = _fp_safe_name((string)($_POST['file'] ?? '')); $preset = (string)($_POST['preset'] ?? '');
            if ($name==='' || !in_array($preset,['cooler','balanced','quiet'],true)) { echo json_encode(['ok'=>false,'error'=>'bad request']); exit; }
            $dir = nm_fp_dir($conn, $rid); $path = rtrim($dir,'\\') . '\\' . $name;
            $raw = nm_fp_read_raw($ssh, $path); $j = json_decode($raw, true);
            if (!is_array($j) || !isset($j['FanControl']['FanCurves'])) { echo json_encode(['ok'=>false,'error'=>'could not read config']); exit; }
            // nudge every graph curve's % points (cooler = +, quiet = −). Keeps temps/shape, shifts the whole ramp.
            $delta = $preset==='cooler' ? 12 : ($preset==='quiet' ? -10 : 0);
            foreach ($j['FanControl']['FanCurves'] as &$cv) {
                if (!isset($cv['Points']) || !is_array($cv['Points'])) continue;
                foreach ($cv['Points'] as &$p) { $xy = explode(',', (string)$p); if (count($xy)!==2) continue;
                    $pct = max(0, min(100, (float)$xy[1] + ($preset==='balanced' ? 0 : $delta)));
                    $p = $xy[0] . ',' . $pct; }
                unset($p);
            }
            unset($cv);
            log_user_action($conn, 'fanprofiler_preset', ($h['name'] ?? ('rig '.$rid)).' '.$name.' '.$preset);
            echo json_encode(nm_fp_write($ssh, $path, json_encode($j))); exit;
        }
        if ($api === 'patch') {
            if (!$ssh) { echo json_encode(['ok'=>false,'error'=>'no SSH']); exit; }
            $name = _fp_safe_name((string)($_POST['file'] ?? '')); if ($name==='') { echo json_encode(['ok'=>false,'error'=>'bad name']); exit; }
            $dir = nm_fp_dir($conn, $rid); $path = rtrim($dir,'\\') . '\\' . $name;
            $patch = json_decode((string)($_POST['patch'] ?? ''), true);
            if (!is_array($patch)) { echo json_encode(['ok'=>false,'error'=>'bad patch']); exit; }
            log_user_action($conn, 'fanprofiler_edit', ($h['name'] ?? ('rig '.$rid)).' '.$name.' '.implode(',',array_keys($patch)));
            echo json_encode(nm_fp_patch($ssh, $path, $patch)); exit;
        }
        echo json_encode(['ok'=>false,'error'=>'unknown api']); exit;
    } catch (\Throwable $e) { echo json_encode(['ok'=>false,'error'=>$e->getMessage()]); exit; }
}
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Fan Profiler | NEURU</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="/three.min.js"></script>
<script src="/nm_netbg.js"></script>
<style>
:root{ --cy:#39e1ff; --pk:#b06bff; --ok:#2ee66e; --warn:#f0a92c; --crit:#ff4d6d; --bd:rgba(120,150,255,.16); }
*,*::before,*::after{ box-sizing:border-box; }
html,body{ margin:0; height:100%; font-family:'Segoe UI',Tahoma,sans-serif; background:radial-gradient(ellipse at 50% 34%,#0a1226 0%,#05070f 62%,#02040a 100%); color:#e6ecf7; }
body{ min-height:100%; overflow-y:auto; }
#nm-netbg{ position:fixed; inset:0; z-index:0 !important; opacity:.8; }
#fp{ position:relative; z-index:1; padding:76px 22px 40px; max-width:1500px; margin:0 auto; }
#fptop{ position:fixed; top:0; left:0; right:0; z-index:6; display:flex; align-items:center; gap:11px; flex-wrap:wrap; padding:14px 20px; background:linear-gradient(180deg,rgba(6,10,20,.82),rgba(6,10,20,0)); backdrop-filter:blur(6px); }
.brand{ font-size:20px; font-weight:900; letter-spacing:2px; background:linear-gradient(90deg,#39e1ff,#b06bff); -webkit-background-clip:text; background-clip:text; color:transparent; }
.brand small{ display:block; font-size:9px; letter-spacing:4px; color:#7f9dc8; -webkit-text-fill-color:#7f9dc8; }
select.rig,.tin,.tbtn{ background:rgba(17,26,43,.72); color:#dbe6f5; border:1px solid var(--bd); border-radius:10px; padding:9px 13px; font-size:13px; cursor:pointer; backdrop-filter:blur(8px); }
.tin{ cursor:text; } .tbtn:hover{ border-color:var(--cy); } a.tbtn{ text-decoration:none; display:inline-flex; align-items:center; gap:6px; }
.tbtn.go{ background:linear-gradient(90deg,rgba(57,225,255,.22),rgba(176,107,255,.22)); border-color:rgba(57,225,255,.55); font-weight:700; }
.tbtn.on{ background:rgba(46,230,110,.2); border-color:rgba(46,230,110,.6); color:#c9ffdf; }
.tbtn[disabled]{ opacity:.5; cursor:default; }
.spacer{ flex:1; }
.badge{ font-size:10px; font-weight:800; letter-spacing:.08em; text-transform:uppercase; padding:3px 8px; border-radius:20px; background:rgba(46,230,110,.16); border:1px solid rgba(46,230,110,.5); color:#a9ffce; }
/* intro / advice */
.panel{ background:rgba(9,14,28,.55); border:1px solid var(--bd); border-radius:16px; padding:16px 20px; backdrop-filter:blur(10px); margin-bottom:18px; }
.panel h2{ margin:0 0 4px; font-size:15px; letter-spacing:.06em; display:flex; align-items:center; gap:9px; }
.panel .sub{ font-size:12.5px; color:#9fb6d6; line-height:1.5; }
.tips{ list-style:none; margin:10px 0 0; padding:0; display:flex; flex-direction:column; gap:8px; }
.tips li{ display:flex; gap:10px; align-items:flex-start; font-size:13px; line-height:1.45; background:rgba(8,14,28,.5); border:1px solid var(--bd); border-left:3px solid var(--tc,#39e1ff); border-radius:9px; padding:9px 12px; }
.tips li i{ margin-top:2px; color:var(--tc,#39e1ff); flex:none; }
.tips li.good{ --tc:#2ee66e } .tips li.warn{ --tc:#f0a92c } .tips li.crit{ --tc:#ff4d6d } .tips li.info{ --tc:#39e1ff }
/* fan curve grid */
#fangrid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:16px; }
.fancard{ background:rgba(11,17,33,.6); border:1px solid var(--bd); border-radius:16px; padding:14px 16px 10px; backdrop-filter:blur(10px); position:relative; overflow:hidden; }
.fancard.k-gpu{ border-color:rgba(57,225,255,.32) } .fancard.k-cpu{ border-color:rgba(176,107,255,.32) } .fancard.k-case{ border-color:rgba(46,230,110,.28) }
.fancard .fh{ display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; }
.fancard .fn{ font-size:13.5px; font-weight:800; letter-spacing:.03em; display:flex; align-items:center; gap:8px; }
.fancard .fk{ font-size:9px; letter-spacing:.12em; text-transform:uppercase; color:#8fb0dd; padding:2px 7px; border:1px solid var(--bd); border-radius:20px; }
.fancard canvas{ width:100%; height:170px; display:block; }
.fancard .live{ display:flex; justify-content:space-between; align-items:baseline; margin-top:6px; font-size:12px; color:#9fb6d6; }
.fancard .live b{ font-size:20px; font-weight:900; font-variant-numeric:tabular-nums; }
.fancard.manual .fn::after{ content:'MANUAL'; font-size:8px; background:rgba(240,169,44,.2); border:1px solid rgba(240,169,44,.5); color:#ffd98a; padding:1px 6px; border-radius:20px; letter-spacing:.1em; }
#empty{ text-align:center; color:#8fb0dd; padding:50px 20px; font-size:14px; }
#load{ position:fixed; inset:0; z-index:9; display:none; align-items:center; justify-content:center; flex-direction:column; gap:14px; background:rgba(4,6,13,.7); }
#load .sp{ width:52px; height:52px; border:3px solid rgba(120,150,255,.2); border-top-color:#39e1ff; border-radius:50%; animation:spin 1s linear infinite; }
@keyframes spin{ to{ transform:rotate(360deg) } }
.msg{ font-size:12.5px; margin-left:8px; }
.fancard .finfo{ display:flex; flex-wrap:wrap; gap:6px 12px; font-size:10.5px; color:#8fb0dd; margin:-2px 0 8px; }
.fancard.off{ opacity:.55; filter:grayscale(.4); }
.offb{ font-size:8px; background:rgba(150,160,180,.18); border:1px solid rgba(150,160,180,.4); color:#b8c4d6; padding:1px 6px; border-radius:20px; letter-spacing:.08em; text-transform:uppercase; }
.sec{ font-size:15px; letter-spacing:.04em; margin:18px 0 12px; display:flex; align-items:baseline; gap:10px; }
.sec small{ font-size:11.5px; color:#8fb0dd; font-weight:400; }
#curvegrid{ display:grid; grid-template-columns:repeat(auto-fill,minmax(340px,1fr)); gap:16px; }
.ccard{ background:rgba(11,17,33,.6); border:1px solid var(--bd); border-radius:16px; padding:14px 16px 10px; backdrop-filter:blur(10px); }
.ccard .ch{ display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; }
.ccard .cn{ font-size:14px; font-weight:800; display:flex; align-items:center; gap:8px; }
.ccard .cmeta{ font-size:10.5px; color:#8fb0dd; }
.ccanvas{ width:100%; height:200px; display:block; cursor:grab; touch-action:none; }
.ccard .cfoot{ display:flex; justify-content:space-between; align-items:baseline; margin-top:6px; font-size:11px; color:#8fb0dd; }
.ccard.mix{ border-color:rgba(240,169,44,.3); } .ccard.other{ opacity:.75; }
.tag{ font-size:8px; background:rgba(240,169,44,.18); border:1px solid rgba(240,169,44,.5); color:#ffd98a; padding:1px 6px; border-radius:20px; letter-spacing:.1em; }
.mrow{ display:flex; align-items:center; gap:9px; margin:8px 0; flex-wrap:wrap; }
.mrow .ml{ font-size:11px; color:#9fb6d6; width:62px; } .mrow .mh{ font-size:10.5px; color:#7f9dc8; }
.mini{ background:rgba(17,26,43,.9); color:#dbe6f5; border:1px solid var(--bd); border-radius:8px; padding:5px 8px; font-size:12px; cursor:pointer; }
.chips{ display:flex; flex-wrap:wrap; gap:6px; align-items:center; }
.chip2{ font-size:11.5px; background:rgba(57,225,255,.12); border:1px solid rgba(57,225,255,.3); color:#dff3ff; padding:3px 8px; border-radius:20px; }
.chip2 i{ cursor:pointer; opacity:.7; margin-left:3px; } .chip2 i:hover{ opacity:1; color:var(--crit); }
.fcard{ background:rgba(11,17,33,.6); border:1px solid var(--bd); border-radius:14px; padding:12px 14px; backdrop-filter:blur(10px); }
.fcard.k-gpu{ border-color:rgba(57,225,255,.3) } .fcard.k-cpu{ border-color:rgba(176,107,255,.3) } .fcard.k-case{ border-color:rgba(46,230,110,.26) } .fcard.off{ opacity:.5; }
.fcard .fh{ display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; }
.fcard .fn{ font-size:13px; font-weight:800; display:flex; align-items:center; gap:7px; }
.fcard .fk{ font-size:8.5px; letter-spacing:.1em; text-transform:uppercase; color:#8fb0dd; padding:2px 6px; border:1px solid var(--bd); border-radius:20px; }
.fcard .frow{ display:flex; align-items:center; gap:8px; font-size:12px; color:#9fb6d6; margin:5px 0; }
.fcard .frow.rpm b{ font-size:18px; font-variant-numeric:tabular-nums; }
.fcard .frow input[type=range]{ flex:1; accent-color:var(--cy); } .fcard .mvv{ font-variant-numeric:tabular-nums; min-width:38px; } .fcard .rr{ margin-left:auto; font-size:10px; color:#7f9dc8; }
.mtog{ display:inline-flex; align-items:center; gap:6px; cursor:pointer; } .fl{ color:#8fb0dd; }
/* ══ 3D RIG — live heat · airflow · RPM ══ */
.rig3d-panel{ padding:0; overflow:hidden; position:relative; background:rgba(9,14,28,.30); }  /* lighter so the #nm-netbg particles show behind the alpha WebGL rig */
.rig3d-head{ display:flex; align-items:center; gap:12px; padding:13px 18px 11px; flex-wrap:wrap; }
.rig3d-head h2{ font-size:15px; margin:0; letter-spacing:.06em; display:flex; align-items:center; gap:9px; }
.rig3d-legend{ display:flex; gap:14px; flex:1; flex-wrap:wrap; font-size:11px; color:#9fb6d6; }
.rig3d-legend .lg{ display:inline-flex; align-items:center; gap:5px; } .rig3d-legend .dot{ width:9px; height:9px; border-radius:50%; box-shadow:0 0 7px currentColor; }
.rig3d-legend .heat{ width:64px; height:9px; border-radius:6px; background:linear-gradient(90deg,#2ee66e,#f0a92c,#ff4d6d); }
.rig3d-stage{ position:relative; height:440px; }
#rig3d{ width:100%; height:100%; display:block; cursor:grab; touch-action:none; }
#rig3d:active{ cursor:grabbing; }
#rigLabels{ position:absolute; inset:0; pointer-events:none; overflow:hidden; }
.rl{ position:absolute; transform:translate(-50%,-50%); text-align:center; white-space:nowrap; pointer-events:none; will-change:left,top; }
.rl .rn{ font-size:10px; color:rgba(202,222,248,.85); text-shadow:0 1px 4px #000; max-width:120px; overflow:hidden; text-overflow:ellipsis; }
.rl .rr{ font-size:14px; font-weight:800; font-variant-numeric:tabular-nums; text-shadow:0 1px 5px #000; }
.rl.stopped .rr{ color:#ff4d6d; }
.rig3d-hint{ position:absolute; bottom:8px; left:0; right:0; text-align:center; font-size:10px; letter-spacing:1.5px; text-transform:uppercase; color:rgba(140,165,200,.45); pointer-events:none; }
.rig3d-sensors{ position:absolute; top:12px; left:14px; display:flex; flex-direction:column; gap:3px; max-width:216px; pointer-events:none; z-index:2; }
.rig3d-sensors .ss{ display:flex; justify-content:space-between; gap:10px; font-size:10.5px; background:rgba(6,11,22,.5); border:1px solid var(--bd); border-left:3px solid var(--sc,#39e1ff); border-radius:6px; padding:2px 8px; backdrop-filter:blur(4px); }
.rig3d-sensors .ss .sl{ color:#c3d4ec; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.rig3d-sensors .ss .sv{ font-weight:800; color:var(--sc,#39e1ff); font-variant-numeric:tabular-nums; }
#rig3dP.rig-full{ position:fixed; inset:0; z-index:30; margin:0; border-radius:0; height:100vh; display:flex; flex-direction:column; background:rgba(5,8,16,.34); }  /* translucent → particle bg stays visible in fullscreen */
#rig3dP.rig-full .rig3d-stage{ flex:1; height:auto; }
.rig3d-pick{ position:absolute; z-index:5; min-width:150px; max-width:236px; background:rgba(8,13,26,.93); border:1px solid var(--pc,#39e1ff); border-radius:11px; padding:9px 12px; pointer-events:none; box-shadow:0 10px 34px rgba(0,0,0,.6); display:none; }
.rig3d-pick.on{ display:block; }
.rig3d-pick .pkh{ font-size:12.5px; font-weight:800; display:flex; align-items:center; gap:7px; color:#eaf2fc; }
.rig3d-pick .pkh .d{ width:9px; height:9px; border-radius:50%; background:var(--pc,#39e1ff); box-shadow:0 0 8px var(--pc,#39e1ff); flex:none; }
.rig3d-pick .pkt{ font-size:22px; font-weight:900; font-variant-numeric:tabular-nums; margin:2px 0 3px; color:var(--pc,#39e1ff); }
.rig3d-pick .pl{ font-size:11px; color:#9fb6d6; line-height:1.55; }
<?= nm_chrome_css() ?>
</style></head><body>
<?php nm_gamers_hub_pill(); ?>
<div id="fptop">
  <div class="brand">◈ NEURU<small>FAN PROFILER</small></div>
  <select class="rig" id="rig" onchange="loadConfigs()"><option value="">Loading rigs…</option></select>
  <select class="rig" id="cfg" style="max-width:260px" onchange="loadConfig()"><option value="">— pick a config —</option></select>
  <span class="badge" id="activeBadge" style="display:none">active</span>
  <button class="tbtn go" id="applyBtn" onclick="applyProfile()" disabled title="Make this the active FanControl profile (relaunches FanControl ~2s)"><i class="fa-solid fa-circle-check"></i> Apply profile</button>
  <span class="msg" id="topMsg"></span>
  <div class="spacer"></div>
  <button class="tbtn" onclick="togglePath()" title="Set a custom FanControl Configurations folder"><i class="fa-solid fa-folder"></i></button>
  <button class="tbtn" onclick="toggleFs()" title="Fullscreen"><i class="fa-solid fa-expand"></i></button>
  <a class="tbtn" href="gaming.php" title="Back to Game Mode"><i class="fa-solid fa-gamepad"></i></a>
</div>

<div id="fp">
  <!-- path config (hidden) -->
  <div class="panel" id="pathPanel" style="display:none">
    <h2><i class="fa-solid fa-folder-open" style="color:var(--cy)"></i> FanControl configs folder</h2>
    <div class="sub">Default: <code>C:\Program Files (x86)\FanControl\Configurations</code> — change it only if you moved FanControl to a custom location.</div>
    <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
      <input class="tin" id="pathIn" style="flex:1;min-width:300px" placeholder="C:\Program Files (x86)\FanControl\Configurations">
      <button class="tbtn go" onclick="savePath()">Save path</button>
    </div>
  </div>

  <!-- advice -->
  <div class="panel" id="adviceP" style="display:none">
    <h2><i class="fa-solid fa-wand-magic-sparkles" style="color:var(--pk)"></i> How to run cooler <span id="tempSummary" style="font-weight:400;font-size:12px;color:#8fb0dd;margin-left:8px"></span></h2>
    <div id="cfgMeta" style="font-size:11.5px;color:#7f9dc8;margin:-2px 0 4px"></div>
    <ul class="tips" id="tips"></ul>
    <div style="margin-top:12px;display:flex;gap:9px;flex-wrap:wrap;align-items:center">
      <span style="font-size:12px;color:#9fb6d6">Preview a preset (see the new curve dashed on each fan before saving):</span>
      <button class="tbtn" onclick="previewPreset('cooler')" title="See a cooler curve (+12%) previewed on every fan"><i class="fa-solid fa-snowflake" style="color:#39e1ff"></i> Preview Cooler</button>
      <button class="tbtn" onclick="previewPreset('quiet')" title="See a quieter curve (−10%) previewed on every fan"><i class="fa-solid fa-volume-low" style="color:#2ee66e"></i> Preview Quiet</button>
      <span class="msg" id="presetMsg"></span>
    </div>
    <div id="previewBar" style="display:none;margin-top:10px;padding:10px 14px;border:1px solid rgba(57,225,255,.4);border-radius:11px;background:rgba(57,225,255,.08);display:none;align-items:center;gap:12px;flex-wrap:wrap">
      <b id="previewLbl" style="color:var(--cy)"></b>
      <span style="font-size:12px;color:#c3d4ec">The dashed line on each fan is the previewed curve.</span>
      <div style="flex:1"></div>
      <button class="tbtn go" onclick="savePreviewed()"><i class="fa-solid fa-floppy-disk"></i> Save to config</button>
      <button class="tbtn" onclick="cancelPreview()">Cancel</button>
      <span class="msg" id="presetMsg2"></span>
    </div>
    <div class="sub" style="margin-top:8px"><i class="fa-solid fa-circle-info"></i> Preview shows the change on-screen; <b>Save to config</b> writes it, then <b>Apply profile</b> makes it live in FanControl.</div>
  </div>

  <!-- 3D RIG — live heat (LHM) · airflow · RPM -->
  <div class="panel rig3d-panel" id="rig3dP" style="display:none">
    <div class="rig3d-head">
      <h2><i class="fa-solid fa-cube" style="color:var(--cy)"></i> 3D Rig <small style="font-weight:400;font-size:11px;color:#8fb0dd">live heat · airflow · fan RPM — from LibreHardwareMonitor</small></h2>
      <div class="rig3d-legend">
        <span class="lg" style="color:#b06bff"><span class="dot"></span> CPU/AIO</span>
        <span class="lg" style="color:#39e1ff"><span class="dot"></span> GPU</span>
        <span class="lg" style="color:#2ee66e"><span class="dot"></span> Case</span>
        <span class="lg" style="color:#9fb6d6">Heat <span class="heat"></span></span>
      </div>
      <button class="tbtn" onclick="loadConfig()" title="Re-read live temps + RPM"><i class="fa-solid fa-rotate"></i></button>
      <button class="tbtn" onclick="rigFullscreen()" title="Fullscreen 3D rig"><i class="fa-solid fa-expand" id="rigFsIcon"></i></button>
    </div>
    <div class="rig3d-stage">
      <canvas id="rig3d"></canvas>
      <div id="rigLabels"></div>
      <div class="rig3d-sensors" id="rigSensors"></div>
      <div class="rig3d-pick" id="rigPick"></div>
      <div class="rig3d-hint">drag to orbit · scroll to zoom · click a component for its temp</div>
    </div>
  </div>

  <div id="empty">Pick a rig and a FanControl config to visualize + tune your fan curves. 🌀</div>
  <h2 class="sec" id="curvesH" style="display:none"><i class="fa-solid fa-chart-line" style="color:var(--cy)"></i> Curves <small>the shared rules your fans follow · <b>drag the dots</b> to reshape a graph curve</small></h2>
  <div id="curvegrid"></div>
  <h2 class="sec" id="fansH" style="display:none"><i class="fa-solid fa-fan" style="color:var(--pk)"></i> Fans <small>each follows a curve (or Manual) · change what it follows</small></h2>
  <div id="fangrid"></div>
</div>

<div id="saveBar" style="display:none;position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:8;align-items:center;gap:14px;background:rgba(9,14,28,.96);border:1px solid rgba(240,169,44,.55);border-radius:14px;padding:12px 18px;box-shadow:0 14px 44px rgba(0,0,0,.55);flex-wrap:wrap">
  <b style="color:var(--warn)"><i class="fa-solid fa-pen-to-square"></i> Unsaved changes</b>
  <span style="font-size:12px;color:#c3d4ec">Nothing is written to FanControl until you save.</span>
  <button class="tbtn go" onclick="saveChanges()"><i class="fa-solid fa-floppy-disk"></i> Save changes</button>
  <button class="tbtn" onclick="discardChanges()">Discard</button>
  <span class="msg" id="saveMsg"></span>
</div>
<div id="load"><div class="sp"></div><div class="msg" id="loadMsg">Reading FanControl over SSH…</div></div>

<script>
const $=s=>document.querySelector(s);
let RIG=0, CFG='', DATA=null, animT=0;
function esc(s){ return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function toggleFs(){ if(!document.fullscreenElement)document.documentElement.requestFullscreen&&document.documentElement.requestFullscreen(); else document.exitFullscreen&&document.exitFullscreen(); }
function togglePath(){ const p=$('#pathPanel'); p.style.display=p.style.display==='none'?'block':'none'; }
const KIND={gpu:{c:'#39e1ff',n:'GPU'},cpu:{c:'#b06bff',n:'CPU / AIO'},case:{c:'#2ee66e',n:'CASE'}};

try{ if(window.NMNetBG) NMNetBG.init&&NMNetBG.init(); }catch(e){}

async function j(u,o){ return fetch(u,o).then(r=>r.json()).catch(()=>({ok:false,error:'network'})); }
function showLoad(m){ $('#loadMsg').textContent=m||'Working…'; $('#load').style.display='flex'; }
function hideLoad(){ $('#load').style.display='none'; }

async function loadRigs(){
  const r=await j('?api=rigs'); const s=$('#rig');
  if(!r.ok||!r.rigs.length){ s.innerHTML='<option value="">No Windows rigs — add one in Windows Monitor</option>'; return; }
  s.innerHTML='<option value="">— pick your rig —</option>'+r.rigs.map(x=>'<option value="'+x.id+'">'+esc(x.name)+'</option>').join('');
}
async function loadConfigs(){
  RIG=+$('#rig').value||0; CFG=''; $('#cfg').innerHTML='<option value="">— pick a config —</option>'; $('#activeBadge').style.display='none'; $('#applyBtn').disabled=true;
  stopFpLive(); $('#fangrid').innerHTML=''; $('#adviceP').style.display='none'; $('#rig3dP').style.display='none'; $('#empty').style.display='block';
  if(!RIG)return;
  showLoad('Listing FanControl configs…');
  const r=await j('?api=list&rig='+RIG); hideLoad();
  $('#pathIn').value=r.dir||'';
  if(!r.ok){ $('#topMsg').innerHTML='<span style="color:var(--warn)">'+esc(r.error||'could not list')+'</span> — check the folder (📁).'; return; }
  $('#topMsg').textContent = r.running ? '' : 'FanControl isn\'t running on this rig.';
  if(!r.files.length){ $('#cfg').innerHTML='<option value="">No .json configs found in the folder</option>'; return; }
  const newest=[...r.files].sort((a,b)=>(b.mtime||'').localeCompare(a.mtime||''))[0];
  $('#cfg').innerHTML='<option value="">— pick a config ('+r.files.length+') —</option>'+r.files.map(f=>'<option value="'+esc(f.name)+'" data-mtime="'+esc(f.mtime||'')+'"'+(f.active?' data-active="1"':'')+'>'+esc(f.name.replace(/\.json$/i,''))+(f.active?'  ✓ active':(newest&&f.name===newest.name?'  · newest':''))+'</option>').join('');
  if(newest){ $('#cfg').value=newest.name; loadConfig(); }   // auto-open the most recently edited config
}
async function loadConfig(){
  CFG=$('#cfg').value; if(!CFG){ $('#applyBtn').disabled=true; $('#activeBadge').style.display='none'; return; }
  const opt=$('#cfg').selectedOptions[0]; const isActive=opt&&opt.dataset.active==='1';
  $('#activeBadge').style.display=isActive?'inline-block':'none'; $('#applyBtn').disabled=isActive; $('#applyBtn').innerHTML=isActive?'<i class="fa-solid fa-circle-check"></i> Active':'<i class="fa-solid fa-circle-check"></i> Apply profile';
  showLoad('Reading '+CFG+' + your live temps…');
  const r=await j('?api=config&rig='+RIG+'&file='+encodeURIComponent(CFG)); hideLoad();
  if(!r.ok){ $('#topMsg').innerHTML='<span style="color:var(--warn)">'+esc(r.error||'read failed')+'</span>'; return; }
  $('#topMsg').textContent='';
  DATA=r; PENDING={}; markClean(); matchLiveRpm(); renderConfig(); startFpLive();
}
function renderTips(r){
  $('#adviceP').style.display='block';
  const t=r.temps||{}; const parts=[]; if(t.cpu!=null)parts.push('CPU '+Math.round(t.cpu)+'°C'); if(t.gpu!=null)parts.push('GPU '+Math.round(t.gpu)+'°C'); if(t.hot!=null)parts.push('hottest '+Math.round(t.hot)+'°C');
  const meta=[]; if(r.fansActive!=null)meta.push(r.fansActive+' active fan'+(r.fansActive===1?'':'s')+(r.fansTotal>r.fansActive?(' ('+r.fansTotal+' total)'):'')); if(r.curveCount)meta.push(r.curveCount+' curves'); if(r.version)meta.push('FanControl v'+r.version);
  $('#cfgMeta').textContent=meta.join(' · ');
  $('#tempSummary').textContent = parts.length?('· live: '+parts.join(' · ')):'· live temps unavailable';
  $('#tips').innerHTML=(r.tips||[]).map(function(t){ return '<li class="'+t[0]+'"><i class="fa-solid '+({good:'fa-check',warn:'fa-triangle-exclamation',crit:'fa-fire'}[t[0]]||'fa-circle-info')+'"></i><span>'+esc(t[1])+'</span></li>'; }).join('');
}
// map a curve NAME → its points; resolve "Mix" to the hottest of its members' points (Max function)
function curvePoints(r, name){
  const cv=(r.curves||[]).find(c=>c.name===name); if(!cv)return null;
  if(cv.type==='graph')return cv.points;
  if(cv.type==='mix'){ // draw the member with the steepest ramp as representative
    let best=null; (cv.mix||[]).forEach(function(m){ const p=curvePoints(r,m); if(p&&(!best||p.length>best.length))best=p; }); return best; }
  return null;
}
function pctAt(pts,temp){ if(!pts||!pts.length)return null; if(temp<=pts[0][0])return pts[0][1]; if(temp>=pts[pts.length-1][0])return pts[pts.length-1][1];
  for(let i=1;i<pts.length;i++){ if(temp<=pts[i][0]){ const[x0,y0]=pts[i-1],[x1,y1]=pts[i]; const f=(x1-x0)>0?(temp-x0)/(x1-x0):0; return y0+(y1-y0)*f; } } return pts[pts.length-1][1]; }
function rpmAt(cal,pct){ if(!cal||!cal.length)return null; if(pct<=cal[0][0])return cal[0][1]; if(pct>=cal[cal.length-1][0])return cal[cal.length-1][1];
  for(let i=1;i<cal.length;i++){ if(pct<=cal[i][0]){ const[x0,y0]=cal[i-1],[x1,y1]=cal[i]; const f=(x1-x0)>0?(pct-x0)/(x1-x0):0; return Math.round(y0+(y1-y0)*f); } } return cal[cal.length-1][1]; }
function tempFor(r,kind){ const t=r.temps||{}; return kind==='gpu'?t.gpu:(kind==='cpu'?(t.cpu!=null?t.cpu:t.hot):t.hot); }
// prefer the LIVE LHM fan RPM (real) over the config's saved Calibration estimate (often stale/incomplete)
function fanRpm(f,live){ if(f&&f.liveRpm!=null)return f.liveRpm; return rpmAt(f.cal,live); }
// match FanControl controls to LIVE LHM fan RPMs by (chip + index) — universal, format-agnostic.
// FanControl: /lpc/it8689e/control/1  ·  LHM data.json SensorId: /lpc/it8689e/0/fan/1  → same chip 'it8689e', idx 1.
function fpSensorKey(id){ if(!id)return null; const m=(''+id).match(/([a-z0-9-]+)\/(?:\d+\/)?(?:control|fan)\/(\d+)\s*$/i); return m?{chip:m[1].toLowerCase(),idx:+m[2]}:null; }
function matchLiveRpm(){ if(!DATA||!DATA.fans)return; const lhm=(DATA.temps&&DATA.temps.fansLHM)||[];
  if(!lhm.length){ DATA.fans.forEach(function(f){ f.liveRpm=null; }); return; }
  const byKey={},byName={}; let gpuRpm=null;
  lhm.forEach(function(lf){ const k=fpSensorKey(lf.id); if(k)byKey[k.chip+'|'+k.idx]=lf.rpm; const nm=(''+(lf.name||'')).toLowerCase().trim(); if(nm)byName[nm]=lf.rpm; if((nm.indexOf('gpu')>=0||(''+(lf.hw||'')).toLowerCase().indexOf('gpu')>=0)&&gpuRpm==null)gpuRpm=lf.rpm; });
  DATA.fans.forEach(function(f){ let rpm=null; const k=fpSensorKey(f.ident);
    if(k&&byKey[k.chip+'|'+k.idx]!=null)rpm=byKey[k.chip+'|'+k.idx];
    if(rpm==null&&/nvapi|nvidia|gpu|radeon|geforce|amd/i.test(f.ident||'')&&gpuRpm!=null)rpm=gpuRpm;
    if(rpm==null){ const nn=(''+(f.name||'')).toLowerCase().trim(); if(nn&&byName[nn]!=null)rpm=byName[nn]; }
    f.liveRpm=(rpm!=null)?rpm:null; }); }
// live % EXACTLY like FanControl: each curve evaluated at ITS OWN temp source; Mix = fn over members
function curveObj(name){ return (DATA&&DATA.curves||[]).find(c=>c.name===name)||null; }
function srcTemp(src){ const t=(DATA&&DATA.temps)||{}; if(src==='CPU')return t.cpu!=null?t.cpu:t.hot; if(src==='GPU')return t.gpu; return t.hot; }
function liveCurvePct(name){ const cv=curveObj(name); if(!cv)return null;
  if(cv.type==='graph'){ const st=srcTemp(cv.src); return st!=null?pctAt(cv.points,st):null; }
  if(cv.type==='mix'){ const vals=(cv.mix||[]).map(liveCurvePct).filter(v=>v!=null); if(!vals.length)return null;
    const fn=cv.fnName||'Max'; if(fn==='Min')return Math.min(...vals); if(fn==='Average')return vals.reduce((a,b)=>a+b,0)/vals.length; if(fn==='Sum')return Math.min(100,vals.reduce((a,b)=>a+b,0)); return Math.max(...vals); }
  return null; }
function livePct(f){ if(f.manual)return f.manualV; const p=liveCurvePct(f.curve); return p!=null?Math.max(p,f.minPct||0):null; }

function curveColor(src){ return src==='GPU'?'#39e1ff':(src==='CPU'?'#b06bff':'#2ee66e'); }
function jsq(s){ return String(s).replace(/\\/g,'\\\\').replace(/'/g,"\\'"); }
var DRAG={ci:-1,pi:-1}, PREVIEW=null;
// ── CURVES panel (the editable objects — fans follow these) ──
function renderCurves(r){
  $('#empty').style.display='none'; $('#curvesH').style.display='block';
  const grid=$('#curvegrid'); grid.innerHTML='';
  (r.curves||[]).forEach(function(cv,ci){
    const used=(cv.usedBy||[]).length?('used by: '+cv.usedBy.map(esc).join(', ')):'not assigned to a fan';
    const card=document.createElement('div'); card.className='ccard';
    if(cv.type==='graph'){
      const col=curveColor(cv.src); card.style.borderColor=col+'40';
      card.innerHTML='<div class="ch"><div class="cn"><i class="fa-solid fa-chart-line" style="color:'+col+'"></i> '+esc(cv.name)+'</div><div class="cmeta">🌡 '+esc(cv.src)+' · '+cv.min+'–'+cv.max+'°C</div></div>'+
        '<canvas id="cg'+ci+'" class="ccanvas"></canvas>'+
        '<div class="cfoot"><span>'+esc(used)+'</span><b id="cl'+ci+'" style="color:'+col+'"></b></div>';
    } else if(cv.type==='mix'){
      card.className='ccard mix';
      const fnOpts=['Max','Min','Average','Sum','Subtract'].map(function(fn){ return '<option'+(fn===cv.fnName?' selected':'')+'>'+fn+'</option>'; }).join('');
      const chips=(cv.mix||[]).map(function(m){ return '<span class="chip2">'+esc(m)+' <i class="fa-solid fa-xmark" title="remove" onclick="mixRemove(\''+jsq(cv.name)+'\',\''+jsq(m)+'\')"></i></span>'; }).join('');
      const addable=(r.curves||[]).filter(function(x){ return x.name!==cv.name && !(cv.mix||[]).includes(x.name); }).map(function(x){ return x.name; });
      const addSel=addable.length?('<select class="mini" onchange="mixAdd(\''+jsq(cv.name)+'\',this.value)"><option value="">+ add</option>'+addable.map(function(n){return '<option>'+esc(n)+'</option>';}).join('')+'</select>'):'';
      const lv=liveCurvePct(cv.name);
      card.innerHTML='<div class="ch"><div class="cn"><i class="fa-solid fa-code-merge" style="color:#f0a92c"></i> '+esc(cv.name)+' <span class="tag">MIX</span></div><b style="color:#f0a92c;font-size:14px">'+(lv!=null?Math.round(lv)+'%':'')+'</b></div>'+
        '<div class="mrow"><span class="ml">Function</span><select class="mini" onchange="mixFn(\''+jsq(cv.name)+'\',this.selectedIndex)">'+fnOpts+'</select><span class="mh">combines the curves below</span></div>'+
        '<div class="mrow"><span class="ml">Curves</span><div class="chips">'+chips+addSel+'</div></div>'+
        '<div class="cfoot"><span>'+esc(used)+'</span></div>';
    } else {
      card.className='ccard other';
      card.innerHTML='<div class="ch"><div class="cn"><i class="fa-solid fa-wave-square"></i> '+esc(cv.name)+' <span class="tag">'+esc((cv.type||'other').toUpperCase())+'</span></div></div><div class="cmeta" style="padding:10px 2px 4px">This curve type isn\'t editable in NEURU yet — tune it in FanControl. '+esc(used)+'</div>';
    }
    grid.appendChild(card);
  });
  drawCurves();
}
function curveGeom(cv){ const dpr=window.devicePixelRatio||1,W=cv.clientWidth,H=200; cv.width=W*dpr;cv.height=H*dpr; const g=cv.getContext('2d'); g.setTransform(dpr,0,0,dpr,0,0);
  const padL=32,padR=14,padT=14,gh=H-14-22,gw=W-padL-padR,T0=20,T1=90;
  return {g:g,W:W,H:H,padL:padL,padR:padR,padT:padT,gh:gh,gw:gw,T0:T0,T1:T1,X:function(t){return padL+((t-T0)/(T1-T0))*gw;},Y:function(p){return padT+(1-p/100)*gh;},xt:function(x){return T0+((x-padL)/gw)*(T1-T0);},yp:function(y){return Math.max(0,Math.min(100,(1-(y-padT)/gh)*100));}}; }
function drawGraph(cv,curve,ci){
  const G=curveGeom(cv),g=G.g,col=curveColor(curve.src); g.clearRect(0,0,G.W,G.H);
  g.strokeStyle='rgba(255,255,255,.06)';g.lineWidth=1;g.font='9px Segoe UI';g.fillStyle='rgba(150,180,220,.5)';
  for(let p=0;p<=100;p+=25){g.beginPath();g.moveTo(G.padL,G.Y(p));g.lineTo(G.W-G.padR,G.Y(p));g.stroke();g.fillText(p+'%',4,G.Y(p)+3);}
  for(let t=G.T0;t<=G.T1;t+=10){g.fillText(t+'°',G.X(t)-7,G.H-6);}
  const pts=curve.points;
  const grd=g.createLinearGradient(0,G.padT,0,G.padT+G.gh);grd.addColorStop(0,col+'55');grd.addColorStop(1,col+'05');
  g.beginPath();g.moveTo(G.X(pts[0][0]),G.Y(pts[0][1]));pts.forEach(function(p){g.lineTo(G.X(p[0]),G.Y(p[1]));});g.lineTo(G.X(pts[pts.length-1][0]),G.Y(0));g.lineTo(G.X(pts[0][0]),G.Y(0));g.closePath();g.fillStyle=grd;g.fill();
  g.beginPath();g.moveTo(G.X(pts[0][0]),G.Y(pts[0][1]));pts.forEach(function(p){g.lineTo(G.X(p[0]),G.Y(p[1]));});g.strokeStyle=col;g.lineWidth=2.4;g.shadowColor=col;g.shadowBlur=8;g.stroke();g.shadowBlur=0;
  if(PREVIEW&&PREVIEW.curves[curve.name]){ const pv=PREVIEW.curves[curve.name]; g.beginPath();g.moveTo(G.X(pv[0][0]),G.Y(pv[0][1]));pv.forEach(function(p){g.lineTo(G.X(p[0]),G.Y(p[1]));});g.strokeStyle='#fff';g.lineWidth=2;g.setLineDash([4,4]);g.lineDashOffset=-animT*1.2;g.stroke();g.setLineDash([]); }
  pts.forEach(function(p,pi){ const hov=(DRAG.ci===ci&&DRAG.pi===pi); g.beginPath();g.arc(G.X(p[0]),G.Y(p[1]),hov?6.5:4.5,0,7);g.fillStyle=hov?'#fff':col;g.strokeStyle='#fff';g.lineWidth=1.6;g.fill();g.stroke(); });
  const st=srcTemp(curve.src),pc=(st!=null)?pctAt(pts,st):null;
  if(st!=null&&pc!=null){ const x=G.X(Math.max(G.T0,Math.min(G.T1,st))),y=G.Y(pc);
    g.strokeStyle='rgba(255,255,255,.28)';g.lineWidth=1;g.setLineDash([3,4]);g.beginPath();g.moveTo(x,G.padT);g.lineTo(x,G.padT+G.gh);g.stroke();g.setLineDash([]);
    const pr=3+Math.sin(animT*0.12)*1.4;g.beginPath();g.arc(x,y,7,0,7);g.fillStyle=col+'33';g.fill();g.beginPath();g.arc(x,y,pr,0,7);g.fillStyle='#fff';g.shadowColor=col;g.shadowBlur=12;g.fill();g.shadowBlur=0;
    const el=document.getElementById('cl'+ci); if(el)el.textContent=Math.round(st)+'°C → '+Math.round(pc)+'%'; }
  cv._geom=G; cv._curve=curve;
}
function drawCurves(){ if(!DATA)return; (DATA.curves||[]).forEach(function(cv,ci){ if(cv.type!=='graph')return; const el=document.getElementById('cg'+ci); if(!el)return; drawGraph(el,cv,ci); if(!el._drag){ el._drag=1; attachDrag(el,ci); } }); }
function attachDrag(cv,ci){
  function pos(e){ const r=cv.getBoundingClientRect(),t=e.touches&&e.touches[0]; return {x:(t?t.clientX:e.clientX)-r.left,y:(t?t.clientY:e.clientY)-r.top}; }
  function nearest(p){ const G=cv._geom; if(!G)return -1; const pts=cv._curve.points; let bi=-1,bd=16; pts.forEach(function(pt,i){ const d=Math.hypot(G.X(pt[0])-p.x,G.Y(pt[1])-p.y); if(d<bd){bd=d;bi=i;} }); return bi; }
  function down(e){ const i=nearest(pos(e)); if(i<0)return; DRAG.ci=ci;DRAG.pi=i; cv.style.cursor='grabbing'; e.preventDefault(); }
  function move(e){ if(DRAG.ci!==ci)return; const G=cv._geom,pts=cv._curve.points,p=pos(e); let t=G.xt(p.x);
    const lo=DRAG.pi>0?pts[DRAG.pi-1][0]+0.5:G.T0, hi=DRAG.pi<pts.length-1?pts[DRAG.pi+1][0]-0.5:G.T1; t=Math.max(lo,Math.min(hi,t));
    pts[DRAG.pi]=[Math.round(t*10)/10,Math.round(G.yp(p.y)*10)/10]; drawGraph(cv,cv._curve,ci); e.preventDefault(); }
  cv.addEventListener('mousedown',down); cv.addEventListener('mousemove',move);
  cv.addEventListener('touchstart',down,{passive:false}); cv.addEventListener('touchmove',move,{passive:false}); cv.style.cursor='grab';
}
function fpDragEnd(){ if(DRAG.ci<0)return; const cv=DATA&&DATA.curves[DRAG.ci]; const el=document.getElementById('cg'+DRAG.ci); DRAG.ci=-1;DRAG.pi=-1; if(el)el.style.cursor='grab'; if(cv)curveEdited(cv.name); }
window.addEventListener('mouseup',fpDragEnd); window.addEventListener('touchend',fpDragEnd);
// ── FANS panel (each follows a curve or Manual) ──
function renderFans(r){
  $('#fansH').style.display='block';
  const grid=$('#fangrid'); grid.innerHTML='';
  const cnames=(r.curves||[]).map(function(c){return c.name;});
  (r.fans||[]).forEach(function(f){
    const k=f.kind||'case',col=KIND[k].c,off=(!f.enabled||f.hidden);
    const live=off?null:livePct(f),rpm=off?null:fanRpm(f,live),rr=f.liveRpm!=null?'live sensor':(f.rpmMax?(f.rpmMin+'–'+f.rpmMax+' RPM'):'');
    const card=document.createElement('div'); card.className='fcard k-'+k+(off?' off':'');
    let ctrl;
    if(off){ ctrl='<div class="frow"><span class="offb">disabled in FanControl</span></div>'; }
    else if(f.manual){ ctrl='<div class="frow"><label class="mtog"><input type="checkbox" checked onchange="fanManual(\''+jsq(f.name)+'\',this.checked)"> Manual'+(f.pump?' 💧 pump':'')+'</label></div><div class="frow"><input type="range" min="0" max="100" value="'+(f.manualV||0)+'" oninput="this.nextElementSibling.textContent=this.value+\'%\'" onchange="fanManualV(\''+jsq(f.name)+'\',this.value)"><span class="mvv">'+(f.manualV||0)+'%</span></div>'; }
    else { ctrl='<div class="frow"><label class="mtog"><input type="checkbox" onchange="fanManual(\''+jsq(f.name)+'\',this.checked)"> Manual</label></div><div class="frow"><span class="fl">Follows</span> <select class="mini" onchange="fanCurve(\''+jsq(f.name)+'\',this.value)">'+cnames.map(function(n){return '<option'+(n===f.curve?' selected':'')+'>'+esc(n)+'</option>';}).join('')+'</select></div>'; }
    card.innerHTML='<div class="fh"><div class="fn"><i class="fa-solid fa-fan" style="color:'+col+'"></i> '+esc(f.name)+'</div><div class="fk">'+KIND[k].n+'</div></div>'+ctrl+
      '<div class="frow rpm"><b style="color:'+col+'">'+(live!=null?Math.round(live)+'%':(f.manual?(f.manualV||0)+'%':'—'))+'</b> '+(rpm!=null?((f.liveRpm!=null?'':'~')+rpm+' RPM'):'')+' <span class="rr">'+esc(rr)+'</span></div>';
    grid.appendChild(card);
  });
}
// ── LOCAL edits only — nothing is written until you click "Save changes" ──
var PENDING={};
function renderConfig(){ renderTips(DATA); try{ buildRig(DATA); }catch(e){} renderCurves(DATA); renderFans(DATA); }
function markDirty(){ $('#saveBar').style.display='flex'; }
function markClean(){ $('#saveBar').style.display='none'; $('#saveMsg').textContent=''; }
function pmerge(cat,name,obj){ PENDING[cat]=PENDING[cat]||{}; PENDING[cat][name]=Object.assign(PENDING[cat][name]||{},obj); markDirty(); }
function curveEdited(name){ const cv=curveObj(name); if(cv&&cv.points){ PENDING.curvePoints=PENDING.curvePoints||{}; PENDING.curvePoints[name]=cv.points.map(function(p){return [p[0],p[1]];}); markDirty(); } }
function mixFn(name,idx){ const cv=curveObj(name); if(cv){ cv.fn=idx; cv.fnName=['Max','Min','Average','Sum','Subtract'][idx]; pmerge('mix',name,{fn:idx}); renderConfig(); } }
function mixRemove(name,m){ const cv=curveObj(name); if(cv){ cv.mix=(cv.mix||[]).filter(function(x){return x!==m;}); pmerge('mix',name,{members:cv.mix.slice()}); renderConfig(); } }
function mixAdd(name,m){ if(!m)return; const cv=curveObj(name); if(cv){ cv.mix=(cv.mix||[]).concat([m]); pmerge('mix',name,{members:cv.mix.slice()}); renderConfig(); } }
function fanCurve(name,cc){ const f=(DATA.fans||[]).find(function(x){return x.name===name;}); if(f){ f.curve=cc; f.manual=false; pmerge('fans',name,{curve:cc,manual:false}); renderConfig(); } }
function fanManual(name,on){ const f=(DATA.fans||[]).find(function(x){return x.name===name;}); if(f){ f.manual=on; pmerge('fans',name,{manual:on}); renderConfig(); } }
function fanManualV(name,v){ const f=(DATA.fans||[]).find(function(x){return x.name===name;}); if(f){ f.manualV=+v; pmerge('fans',name,{manual:true,manualV:+v}); } }
async function saveChanges(){ const keys=Object.keys(PENDING); if(!keys.length){ markClean(); return; } $('#saveMsg').textContent='saving…';
  const fd=new FormData(); fd.append('rig',RIG); fd.append('file',CFG); fd.append('patch',JSON.stringify(PENDING));
  const r=await j('?api=patch',{method:'POST',body:fd});
  if(r.ok){ PENDING={}; markClean(); $('#topMsg').innerHTML='<span style="color:var(--ok)">✓ saved — <b>Apply profile</b> to go live</span>'; loadConfig(); }
  else $('#saveMsg').innerHTML='<span style="color:var(--warn)">✗ '+esc(r.error||'failed')+'</span>'; }
function discardChanges(){ PENDING={}; markClean(); loadConfig(); }
// ── preset preview (shifts every graph curve; dashed overlay on the curve cards) ──
function previewPreset(p){ if(!DATA)return; const d=p==='cooler'?12:(p==='quiet'?-10:0); const curves={};
  (DATA.curves||[]).forEach(function(cv){ if(cv.type!=='graph')return; curves[cv.name]=cv.points.map(function(pt){return [pt[0],Math.max(0,Math.min(100,Math.round((pt[1]+d)*10)/10))];}); });
  PREVIEW={preset:p,curves:curves}; $('#previewLbl').textContent=(p==='cooler'?'❄ Cooler (+12%)':'🔊 Quiet (−10%)')+' — preview (dashed)'; $('#previewBar').style.display='flex'; $('#presetMsg').textContent=''; drawCurves(); }
function cancelPreview(){ PREVIEW=null; $('#previewBar').style.display='none'; $('#presetMsg2').textContent=''; drawCurves(); }
async function savePreviewed(){ if(!PREVIEW||!RIG||!CFG)return; $('#presetMsg2').textContent='saving…';
  const fd=new FormData(); fd.append('rig',RIG); fd.append('file',CFG); fd.append('preset',PREVIEW.preset);
  const r=await j('?api=preset',{method:'POST',body:fd});
  if(r.ok){ $('#presetMsg2').innerHTML='<span style="color:var(--ok)">✓ saved</span>'; PREVIEW=null; setTimeout(function(){ $('#previewBar').style.display='none'; loadConfig(); },800); }
  else $('#presetMsg2').innerHTML='<span style="color:var(--warn)">✗ '+esc(r.error||'failed')+'</span>'; }
// ══ 3D RIG — live heat (LHM sensors) · airflow · RPM (three.js) ══
var R3=null;
function heatHue(t){ if(t==null)return 200; const c=Math.max(0,Math.min(1,(t-45)/45)); return (1-c)*120; }   // 120=green .. 0=red
function heatCss(t){ return t==null?'#39e1ff':'hsl('+heatHue(t).toFixed(0)+',82%,55%)'; }
function tColor3(t){ const c=new THREE.Color(); if(t==null)c.setHSL(0.55,0.8,0.55); else c.setHSL(heatHue(t)/360,0.85,0.5); return c; }
function heatInt(t){ return t==null?0.3:(0.28+Math.max(0,Math.min(1,(t-45)/45))*1.1); }
function fanSprite3(){ const c=document.createElement('canvas'); c.width=c.height=64; const g=c.getContext('2d'); const gr=g.createRadialGradient(32,32,0,32,32,32); gr.addColorStop(0,'rgba(255,255,255,1)'); gr.addColorStop(.4,'rgba(180,220,255,.5)'); gr.addColorStop(1,'rgba(120,180,255,0)'); g.fillStyle=gr; g.fillRect(0,0,64,64); return new THREE.CanvasTexture(c); }
function makeFan3(hex){ const c=new THREE.Color(hex),g=new THREE.Group();
  const ring=new THREE.Mesh(new THREE.TorusGeometry(0.44,0.055,8,26),new THREE.MeshStandardMaterial({color:c,emissive:c,emissiveIntensity:0.5,metalness:0.4,roughness:0.5})); g.add(ring);
  const hub=new THREE.Mesh(new THREE.CylinderGeometry(0.11,0.11,0.06,12),new THREE.MeshStandardMaterial({color:0x223049,emissive:c,emissiveIntensity:0.25})); hub.rotation.x=Math.PI/2; g.add(hub);
  const blades=new THREE.Group();
  for(let i=0;i<7;i++){ const h=new THREE.Group(); h.rotation.z=(i/7)*Math.PI*2; const b=new THREE.Mesh(new THREE.BoxGeometry(0.34,0.13,0.012),new THREE.MeshStandardMaterial({color:c,emissive:c,emissiveIntensity:0.3,transparent:true,opacity:0.7})); b.position.x=0.2; b.rotation.z=0.55; h.add(b); blades.add(h); }
  g.add(blades); g._blades=blades; return g; }
function makePump3(hex){ const c=new THREE.Color(hex),g=new THREE.Group();
  const body=new THREE.Mesh(new THREE.CylinderGeometry(0.4,0.4,0.34,20),new THREE.MeshStandardMaterial({color:0x1a2740,emissive:c,emissiveIntensity:0.4,metalness:0.6,roughness:0.4})); body.rotation.x=Math.PI/2; g.add(body);
  g.add(new THREE.Mesh(new THREE.TorusGeometry(0.3,0.03,8,24),new THREE.MeshStandardMaterial({color:c,emissive:c,emissiveIntensity:0.7})));
  const blades=new THREE.Group(); for(let i=0;i<6;i++){ const h=new THREE.Group(); h.rotation.z=(i/6)*Math.PI*2; const b=new THREE.Mesh(new THREE.BoxGeometry(0.24,0.06,0.01),new THREE.MeshStandardMaterial({color:c,emissive:c,emissiveIntensity:0.4,transparent:true,opacity:0.5})); b.position.x=0.13; h.add(b); blades.add(h); }
  g.add(blades); g._blades=blades; g._pump=true; return g; }
function makeHot3(w,h,d,t){ const c=tColor3(t),group=new THREE.Group();
  const mat=new THREE.MeshStandardMaterial({color:0x16233c,emissive:c,emissiveIntensity:heatInt(t),metalness:0.5,roughness:0.5});
  group.add(new THREE.Mesh(new THREE.BoxGeometry(w,h,d),mat));
  const light=new THREE.PointLight(c.getHex(),heatInt(t)*1.2,7); group.add(light);
  const ring=new THREE.Mesh(new THREE.TorusGeometry(Math.max(w,h)*0.62,0.05,8,36),new THREE.MeshBasicMaterial({color:0xff3b52,transparent:true,opacity:0})); ring.position.z=d/2+0.06; group.add(ring);
  return {group:group,mat:mat,light:light,ring:ring,temp:t}; }
function buildFlow3(R,count){ const geo=new THREE.BufferGeometry(),pos=new Float32Array(count*3);
  for(let i=0;i<count;i++){ pos[i*3]=(Math.random()-0.5)*4.6; pos[i*3+1]=(Math.random()-0.5)*4.4; pos[i*3+2]=(Math.random()-0.5)*2.5; }
  geo.setAttribute('position',new THREE.BufferAttribute(pos,3));
  R.flow=new THREE.Points(geo,new THREE.PointsMaterial({size:0.13,map:R.tex,color:0x8bd6ff,transparent:true,opacity:0.6,blending:THREE.AdditiveBlending,depthWrite:false})); R.pivot.add(R.flow); }
function initRig3D(){ if(R3&&R3.renderer)return R3; const canvas=$('#rig3d'); if(!canvas||!window.THREE)return null;
  const renderer=new THREE.WebGLRenderer({canvas:canvas,alpha:true,antialias:true}); renderer.setPixelRatio(Math.min(2,window.devicePixelRatio||1));
  const scene=new THREE.Scene(), camera=new THREE.PerspectiveCamera(42,1.6,0.1,100);
  scene.add(new THREE.AmbientLight(0x50608a,1.0)); const key=new THREE.DirectionalLight(0xbcd4ff,0.6); key.position.set(4,6,8); scene.add(key);
  const pivot=new THREE.Group(); scene.add(pivot);
  R3={renderer:renderer,scene:scene,camera:camera,pivot:pivot,fans:[],hot:[],flow:null,dist:9,ry:0.5,rx:0.1,flowSpeed:0.3,tex:fanSprite3(),ready:false,drag:null,moved:false,down:null,ray:new THREE.Raycaster(),mouse:new THREE.Vector2(),_v:new THREE.Vector3()};
  canvas.addEventListener('pointerdown',function(e){ R3.drag={x:e.clientX,y:e.clientY}; R3.down={x:e.clientX,y:e.clientY}; R3.moved=false; });
  canvas.addEventListener('pointermove',function(e){ if(!R3.drag)return; if(R3.down&&Math.hypot(e.clientX-R3.down.x,e.clientY-R3.down.y)>6)R3.moved=true; R3.ry+=(e.clientX-R3.drag.x)*0.01; R3.rx=Math.max(-0.7,Math.min(0.9,R3.rx+(e.clientY-R3.drag.y)*0.006)); R3.drag={x:e.clientX,y:e.clientY}; });
  window.addEventListener('pointerup',function(){ if(R3)R3.drag=null; });
  canvas.addEventListener('click',function(e){ if(!R3.moved) rigPick(e); });
  canvas.addEventListener('wheel',function(e){ R3.dist=Math.max(5.5,Math.min(16,R3.dist+(e.deltaY>0?0.7:-0.7))); e.preventDefault(); },{passive:false});
  return R3; }
function rigResize(){ if(!R3)return; const c=$('#rig3d'),w=c.clientWidth,h=c.clientHeight; if(!w||!h)return; R3.renderer.setSize(w,h,false); R3.camera.aspect=w/h; R3.camera.updateProjectionMatrix(); }
function addFan3(f,x,y,z,cH){ const R=R3,k=(f.kind==='cpu'||f.pump)?'cpu':(f.kind==='gpu'?'gpu':'case'),hex=cH[k];
  const g=f.pump?makePump3(hex):makeFan3(hex); g.position.set(x,y,z); R.pivot.add(g);
  const el=document.createElement('div'); $('#rigLabels').appendChild(el);
  const o={g:g,el:el,f:f,hex:hex,off:false,live:0,spin:0}; R.fans.push(o); updateFan(o); }
function updateFan(o){ const f=o.f,cstr='#'+o.hex.toString(16).padStart(6,'0'),off=(!f.enabled||f.hidden);
  const live=off?0:(livePct(f)||0),rpm=off?null:fanRpm(f,live);
  o.off=off; o.live=live; o.spin=off?0:Math.max(0.02,live/100);
  o.g.userData.pick={label:esc(f.name)+(f.pump?' (AIO pump)':''),temp:null,color:cstr,
    big:(off?'off':(rpm!=null?rpm+' RPM':Math.round(live)+'%')),
    lines:[ off?'disabled in FanControl':((rpm!=null?(rpm+' RPM · '):'')+Math.round(live)+'%'),
            f.pump?'AIO pump — runs flat-out per spec':(f.manual?('manual '+Math.round(f.manualV||0)+'%'):('follows: '+(f.curve||'—'))) ]};
  o.el.className='rl'+(off||live<=0?' stopped':'');
  o.el.innerHTML='<div class="rn">'+esc(f.name)+(f.pump?' 💧':'')+'</div><div class="rr" style="color:'+(off?'#7c828c':cstr)+'">'+(off?'off':(rpm!=null?rpm+' RPM':Math.round(live)+'%'))+'</div>'; }
function buildRig(r){
  if(!window.THREE) return;
  $('#rig3dP').style.display='block';
  const R=initRig3D(); if(!R)return; rigResize();
  while(R.pivot.children.length){ const ch=R.pivot.children[0]; R.pivot.remove(ch);   // dispose GPU buffers (not the shared sprite texture) to avoid a WebGL leak on config switch
    ch.traverse && ch.traverse(function(o){ if(o.geometry)o.geometry.dispose(); if(o.material){ (Array.isArray(o.material)?o.material:[o.material]).forEach(function(m){ m.dispose&&m.dispose(); }); } }); }
  R.fans=[]; R.hot=[]; R.hotByKey={}; R.flow=null; $('#rigLabels').innerHTML=''; const _pk=$('#rigPick'); if(_pk)_pk.classList.remove('on');
  const T=r.temps||{};
  rigSensorHud(T);
  const CW=5.4,CH=5,CD=2.7;
  R.pivot.add(new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(CW,CH,CD)),new THREE.LineBasicMaterial({color:0x3a5c8f,transparent:true,opacity:0.45})));
  const mobo=new THREE.Mesh(new THREE.PlaneGeometry(CW-0.5,CH-0.5),new THREE.MeshStandardMaterial({color:0x0b1830,emissive:0x0a1426,metalness:0.3,roughness:0.85,transparent:true,opacity:0.85})); mobo.position.z=-CD/2+0.05; R.pivot.add(mobo);
  function comp(w,h,d,x,y,z,key,label){ const t=compTemp(key,T),o=makeHot3(w,h,d,t); o.group.position.set(x,y,z); o.key=key; o.label=label;
    o.group.userData.pick={label:label,temp:t,color:heatCss(t),lines:compLines(key,T)}; R.pivot.add(o.group); R.hot.push(o); R.hotByKey[key]=o; }
  comp(1.1,1.1,0.42,-1.1,1.15,-CD/2+0.42,'cpu','CPU');
  comp(3.5,0.55,1.35,0.15,-0.75,-CD/2+0.95,'gpu','GPU');
  if(T.vrm!=null||T.mobo!=null) comp(1.7,0.28,0.2,0.75,1.95,-CD/2+0.25,'vrm','Motherboard / VRM');
  if(T.ram!=null) comp(0.28,1.6,0.2,1.9,0.9,-CD/2+0.25,'ram','RAM');
  if(T.storage!=null) comp(1.5,0.16,0.5,-1.6,-1.95,-CD/2+0.4,'storage','Storage');
  const groups={cpu:[],gpu:[],case:[]};
  (r.fans||[]).forEach(function(f){ const k=(f.kind==='cpu'||f.pump)?'cpu':(f.kind==='gpu'?'gpu':'case'); groups[k].push(f); });
  const cH={cpu:0xb06bff,gpu:0x39e1ff,case:0x2ee66e};
  function row(list,y,z,spanx){ const n=list.length; list.forEach(function(f,i){ const tx=n>1?(i/(n-1)-0.5):0; addFan3(f,tx*spanx,y,z,cH); }); }
  row(groups.cpu,2.05,0.2,Math.min(3.6,groups.cpu.length*1.0));
  row(groups.gpu,-0.75,0.78,Math.min(3.0,groups.gpu.length*1.1));
  { const list=groups['case'],n=list.length,cols=Math.min(2,Math.max(1,Math.ceil(n/2))); list.forEach(function(f,i){ const cx=(i%cols)-(cols-1)/2,ry=Math.floor(i/cols); addFan3(f,cx*1.25-1.9,1.0-ry*1.3,CD/2+0.05,cH); }); }
  buildFlow3(R,420);
  let sum=0,cnt=0; R.fans.forEach(function(o){ if(!o.off){ sum+=o.live; cnt++; } }); R.flowSpeed=cnt?(sum/cnt/100):0.2;
  R.ready=true; }
function rigFrame(){ const R=R3; if(!R||!R.ready)return;
  R.pivot.rotation.y=R.ry; R.pivot.rotation.x=R.rx;
  R.camera.position.set(0,0.6,R.dist); R.camera.lookAt(0,0,0);
  R.fans.forEach(function(o){ if(o.g._blades&&o.spin>0) o.g._blades.rotation.z+=o.spin*0.45; });
  if(R.flow){ const p=R.flow.geometry.attributes.position,sp=0.012+R.flowSpeed*0.07; for(let i=0;i<p.count;i++){ let z=p.getZ(i)-sp; if(z<-1.35)z=1.35; p.setZ(i,z); } p.needsUpdate=true; }
  R.hot.forEach(function(o){ if(o.temp!=null&&o.temp>=85) o.ring.material.opacity=0.35+Math.sin(animT*0.14)*0.3; });
  const c=$('#rig3d'),W=c.clientWidth,H=c.clientHeight;
  R.fans.forEach(function(o){ const v=o.g.getWorldPosition(R._v); v.project(R.camera); const x=(v.x*0.5+0.5)*W,y=(-v.y*0.5+0.5)*H; o.el.style.left=x+'px'; o.el.style.top=(y-34)+'px'; o.el.style.display=(v.z<1)?'block':'none'; });
  R.renderer.render(R.scene,R.camera); }
// ── shared component temp/lines builders (used by both build + live update) ──
function compTemp(key,T){ return key==='cpu'?(T.cpu!=null?T.cpu:T.hot):key==='gpu'?T.gpu:key==='vrm'?(T.vrm!=null?T.vrm:T.mobo):key==='ram'?T.ram:key==='storage'?T.storage:null; }
function compLines(key,T){
  if(key==='cpu')return['Package '+(T.cpu!=null?Math.round(T.cpu)+'°C':'—'),(T.hotName?('hottest sensor: '+T.hotName):'')].filter(Boolean);
  if(key==='gpu')return['Core '+(T.gpu!=null?Math.round(T.gpu)+'°C':'—'),(T.gpumem!=null?('Memory junction '+Math.round(T.gpumem)+'°C'):'')].filter(Boolean);
  if(key==='vrm')return['VRM '+Math.round(T.vrm!=null?T.vrm:T.mobo)+'°C'];
  if(key==='ram')return['DIMM '+Math.round(T.ram)+'°C'];
  if(key==='storage')return['NVMe/SSD '+Math.round(T.storage)+'°C']; return []; }
function rigSensorHud(T){ const el=$('#rigSensors'); if(!el)return; const ss=(T.sensors)||[];
  el.innerHTML=ss.map(function(s){ const col=heatCss(s.val); return '<div class="ss" style="--sc:'+col+'"><span class="sl">'+esc(s.label||s.name||'')+'</span><span class="sv">'+Math.round(s.val)+'°</span></div>'; }).join(''); }
function updateHot(o,t,lines){ o.temp=t; const c=tColor3(t); o.mat.emissive.copy(c); o.mat.emissiveIntensity=heatInt(t); o.light.color.copy(c); o.light.intensity=heatInt(t)*1.2;
  if(o.temp==null||o.temp<85) o.ring.material.opacity=0;
  if(o.group.userData.pick){ o.group.userData.pick.temp=t; o.group.userData.pick.color=heatCss(t); if(lines)o.group.userData.pick.lines=lines; } }
// realtime in-place refresh of the 3D rig from the current DATA.temps (no scene rebuild)
function updateRigLive(){ const R=R3; if(!R||!R.ready||!DATA)return; const T=DATA.temps||{};
  rigSensorHud(T);
  Object.keys(R.hotByKey||{}).forEach(function(k){ updateHot(R.hotByKey[k],compTemp(k,T),compLines(k,T)); });
  R.fans.forEach(updateFan);
  let sum=0,cnt=0; R.fans.forEach(function(o){ if(!o.off){ sum+=o.live; cnt++; } }); R.flowSpeed=cnt?(sum/cnt/100):0.2; }
// ── REALTIME workbench: poll temps + RPMs every 2s so you see changes live after adjusting a profile ──
var FPLIVE=0,FPLIVEID=null;
async function fpLivePoll(){ if(!FPLIVE||!RIG||!CFG||!DATA)return;
  try{ const r=await fetch('?api=live&rig='+RIG).then(x=>x.json());
    if(r&&r.ok&&r.temps){ DATA.temps=r.temps; matchLiveRpm(); updateRigLive(); refreshFanCards(); } }catch(e){} }
function startFpLive(){ stopFpLive(); FPLIVE=1; const loop=async function(){ if(!FPLIVE)return; await fpLivePoll(); if(FPLIVE)FPLIVEID=setTimeout(loop,2000); }; FPLIVEID=setTimeout(loop,2000); }
function stopFpLive(){ FPLIVE=0; if(FPLIVEID){ clearTimeout(FPLIVEID); FPLIVEID=null; } }
// refresh the fan cards' live numbers, but never while the user is editing one (would steal focus)
function refreshFanCards(){ if(!DATA)return; const ae=document.activeElement, grid=$('#fangrid'); if(ae&&grid&&grid.contains(ae))return; if(PREVIEW)return; renderFans(DATA); }
document.addEventListener('visibilitychange',function(){ if(document.hidden)stopFpLive(); else if(RIG&&CFG&&DATA)startFpLive(); });
// click/tap a component → show its live temp + details (raycast into the scene)
function rigPick(e){ const R=R3; if(!R||!R.ready)return; const c=$('#rig3d'),rect=c.getBoundingClientRect();
  R.mouse.x=((e.clientX-rect.left)/rect.width)*2-1; R.mouse.y=-((e.clientY-rect.top)/rect.height)*2+1;
  R.ray.setFromCamera(R.mouse,R.camera);
  const hits=R.ray.intersectObjects(R.pivot.children,true); let info=null;
  for(let i=0;i<hits.length;i++){ let o=hits[i].object; while(o&&!(o.userData&&o.userData.pick)) o=o.parent; if(o&&o.userData&&o.userData.pick){ info=o.userData.pick; break; } }
  const pk=$('#rigPick'); if(!pk)return; if(!info){ pk.classList.remove('on'); return; }
  pk.style.setProperty('--pc',info.color||'#39e1ff');
  const big=(info.temp!=null)?(Math.round(info.temp)+'°C'):(info.big||'');
  pk.innerHTML='<div class="pkh"><span class="d"></span>'+info.label+'</div>'+(big?('<div class="pkt">'+esc(big)+'</div>'):'')+'<div class="pl">'+(info.lines||[]).map(esc).join('<br>')+'</div>';
  const sx=e.clientX-rect.left,sy=e.clientY-rect.top;
  pk.style.left=Math.max(6,Math.min(rect.width-244,sx+14))+'px'; pk.style.top=Math.max(6,sy-10)+'px'; pk.classList.add('on'); }
function rigFullscreen(){ const p=$('#rig3dP'); if(!p)return; const on=p.classList.toggle('rig-full');
  const ic=$('#rigFsIcon'); if(ic)ic.className='fa-solid '+(on?'fa-compress':'fa-expand');
  document.body.style.overflow=on?'hidden':''; setTimeout(rigResize,60); }
window.addEventListener('keydown',function(e){ if(e.key==='Escape'){ const p=$('#rig3dP'); if(p&&p.classList.contains('rig-full')) rigFullscreen(); } });
function tick(){ animT++; if(DATA) drawCurves(); if(R3&&R3.ready) rigFrame(); requestAnimationFrame(tick); }

async function applyProfile(){
  if(!RIG||!CFG)return;
  if(!confirm('Make "'+CFG.replace(/\.json$/i,'')+'" the ACTIVE FanControl profile?\n\nNEURU will copy it over configuration.json and relaunch FanControl (~2s). Your fans keep running.')) return;
  showLoad('Applying profile + relaunching FanControl…');
  const fd=new FormData(); fd.append('rig',RIG); fd.append('file',CFG);
  const r=await j('?api=apply',{method:'POST',body:fd}); hideLoad();
  $('#topMsg').innerHTML = r.ok ? '<span style="color:var(--ok)">✓ '+esc(r.note||'Applied')+'</span>' : '<span style="color:var(--warn)">✗ '+esc(r.error||'failed')+'</span>';
  if(r.ok) setTimeout(loadConfigs,1500);
}
async function applyPreset(p){
  if(!RIG||!CFG){ $('#presetMsg').textContent='pick a config first'; return; }
  const names={cooler:'Cooler (+12%)',balanced:'Balanced (no change)',quiet:'Quiet (−10%)'};
  if(p!=='balanced' && !confirm('Apply the '+names[p]+' preset to "'+CFG.replace(/\.json$/i,'')+'"?\n\nThis edits every fan curve in this config file. Then click Apply profile to make it live.')) return;
  $('#presetMsg').textContent='saving…';
  const fd=new FormData(); fd.append('rig',RIG); fd.append('file',CFG); fd.append('preset',p);
  const r=await j('?api=preset',{method:'POST',body:fd});
  $('#presetMsg').innerHTML = r.ok ? '<span style="color:var(--ok)">✓ curves updated — click Apply profile</span>' : '<span style="color:var(--warn)">✗ '+esc(r.error||'failed')+'</span>';
  if(r.ok) loadConfig();
}
async function savePath(){
  if(!RIG){ alert('Pick a rig first'); return; }
  const fd=new FormData(); fd.append('rig',RIG); fd.append('dir',$('#pathIn').value.trim());
  const r=await j('?api=setdir',{method:'POST',body:fd});
  if(r.ok){ togglePath(); loadConfigs(); }
}
loadRigs(); requestAnimationFrame(tick);
window.addEventListener('resize',()=>{ if(DATA)drawCurves(); rigResize(); });
</script>
</body></html>
