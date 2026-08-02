<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — SYSTEM PASSPORT & Re-sell Certificate (public viewer). Renders an issued,
// immutable certificate (nm_hw_cert) of a rig's REAL NEURU-recorded history for used-
// hardware resale. PUBLIC by design (a buyer opens the shareable link — no login), but
// the data is frozen at issue time + carries a sha256 integrity seal. Print → clean PDF.
// Issuing (auth-gated) lives in longevity.php ?api=cert. RBAC: none to VIEW.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('connection.php');
require_once('nm_chrome.php');       // nm_logo_svg()
require_once('nm_wearlife.php');

$id = preg_replace('/[^A-Za-z0-9\-]/', '', (string)($_GET['cert'] ?? ''));
$cert = $id !== '' ? nm_wl_cert_get($conn, $id) : null;
$d = $cert['data'] ?? null;
$ok = is_array($d);
$e = fn($s)=>htmlspecialchars((string)$s, ENT_QUOTES);
$tierCol = $ok && !empty($d['tier']) ? $d['tier'][2] : '#7CFFB2';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NEURU System Passport<?= $ok ? ' · '.$e($id) : '' ?></title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --tier:<?= $e($tierCol) ?>; --bd:rgba(120,150,255,.16); --gold:#e9c46a; }
*,*::before,*::after{ box-sizing:border-box; }
html,body{ margin:0; background:#04060d; color:#e6ecf7; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; }
.bgwrap{ min-height:100vh; padding:34px 18px 70px; background:
  radial-gradient(60% 40% at 50% 0%, rgba(60,90,180,.16), transparent 70%),
  radial-gradient(50% 40% at 80% 90%, rgba(124,255,178,.08), transparent 70%); }
.cert{ max-width:820px; margin:0 auto; background:linear-gradient(180deg,rgba(12,18,36,.92),rgba(8,12,26,.96));
  border:1px solid var(--bd); border-radius:22px; overflow:hidden; box-shadow:0 24px 70px rgba(0,0,0,.55);
  position:relative; }
.cert::before{ content:''; position:absolute; inset:0; border-radius:22px; padding:1px; pointer-events:none;
  background:linear-gradient(120deg,var(--tier),transparent 40%,transparent 60%,var(--gold)); -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0); -webkit-mask-composite:xor; mask-composite:exclude; opacity:.5; }
.hd{ display:flex; align-items:center; gap:16px; padding:24px 30px; border-bottom:1px solid var(--bd);
  background:linear-gradient(90deg,rgba(120,150,255,.06),transparent); }
.seal{ width:66px; height:66px; display:grid; place-items:center; border-radius:16px; background:rgba(120,150,255,.08); border:1px solid var(--bd); flex:none; }
.hd h1{ margin:0; font-size:22px; font-weight:900; letter-spacing:1px; }
.hd .sub{ font-size:12.5px; color:#9fb0d8; margin-top:2px; letter-spacing:.5px; }
.hd .cid{ margin-left:auto; text-align:right; }
.hd .cid b{ font-size:15px; font-variant-numeric:tabular-nums; letter-spacing:1px; color:#dfeaff; }
.hd .cid span{ display:block; font-size:11px; color:#8fa4c8; margin-top:2px; }
.body{ padding:26px 30px; }
.gradeRow{ display:flex; align-items:center; gap:22px; flex-wrap:wrap; margin-bottom:22px; }
.gring{ width:120px; height:120px; border-radius:50%; display:grid; place-items:center; flex:none;
  background:conic-gradient(var(--tier) calc(var(--g,0)*1%), rgba(255,255,255,.07) 0);
  box-shadow:0 0 26px color-mix(in srgb,var(--tier) 30%,transparent); }
.gring .in{ width:98px; height:98px; border-radius:50%; background:#070c18; display:grid; place-items:center; text-align:center; }
.gring b{ font-size:38px; font-weight:900; line-height:1; color:var(--tier); }
.gring small{ font-size:10px; color:#8fa4c8; letter-spacing:1px; }
.gmeta h2{ margin:0; font-size:19px; font-weight:900; } .gmeta h2 .tk{ color:var(--tier); }
.gmeta p{ margin:6px 0 0; font-size:12.5px; color:#c3d3ee; max-width:440px; line-height:1.55; }
.grid{ display:grid; grid-template-columns:1fr 1fr; gap:14px; }
@media(max-width:640px){ .grid{ grid-template-columns:1fr; } }
.box{ background:rgba(255,255,255,.03); border:1px solid var(--bd); border-radius:14px; padding:15px 16px; }
.box h3{ margin:0 0 10px; font-size:11px; letter-spacing:1px; text-transform:uppercase; color:#8fa4c8; display:flex; align-items:center; gap:7px; }
.kv{ display:flex; justify-content:space-between; gap:12px; font-size:12.5px; padding:4px 0; border-bottom:1px dashed rgba(120,150,255,.1); }
.kv:last-child{ border-bottom:0; } .kv .k{ color:#9fb0d8; } .kv .v{ color:#eaf2ff; font-weight:700; text-align:right; }
.sub-bar{ margin:9px 0; } .sub-bar .top{ display:flex; justify-content:space-between; font-size:12px; }
.sub-bar .nm{ font-weight:700; } .sub-bar .track{ height:7px; border-radius:6px; background:rgba(255,255,255,.07); margin-top:4px; overflow:hidden; }
.sub-bar .track i{ display:block; height:100%; border-radius:6px; }
.badge{ font-size:9px; font-weight:800; padding:1px 6px; border-radius:999px; text-transform:uppercase; margin-left:5px; }
.badge.m{ background:rgba(124,255,178,.16); color:#7CFFB2; } .badge.est{ background:rgba(233,196,106,.16); color:var(--gold); }
.bench{ display:flex; gap:6px; align-items:flex-end; height:44px; margin-top:8px; }
.bench .b{ flex:1; background:linear-gradient(180deg,var(--tier),rgba(120,150,255,.2)); border-radius:3px 3px 0 0; min-height:4px; opacity:.85; }
.verify{ margin-top:22px; padding:16px 18px; border-radius:14px; border:1px solid rgba(124,255,178,.3);
  background:rgba(124,255,178,.05); display:flex; gap:14px; align-items:flex-start; }
.verify i.big{ font-size:26px; color:#7CFFB2; margin-top:2px; }
.verify .t{ font-size:12.5px; color:#d7e3f7; line-height:1.6; }
.verify .t b{ color:#eaf2ff; } .verify code{ background:rgba(120,150,255,.12); padding:1px 7px; border-radius:5px; font-size:11.5px; color:#cfe4ff; word-break:break-all; }
.acts{ display:flex; gap:10px; flex-wrap:wrap; margin:20px auto 0; max-width:820px; justify-content:center; }
.btn{ display:inline-flex; align-items:center; gap:8px; cursor:pointer; border:1px solid var(--bd); background:rgba(10,16,34,.7); color:#dbe9ff; border-radius:11px; padding:11px 18px; font-size:13px; font-weight:800; text-decoration:none; }
.btn.pri{ color:#04121f; background:linear-gradient(90deg,var(--gold),#f2d98a); border:0; }
.btn:hover{ border-color:var(--tier); }
.foot{ text-align:center; margin-top:16px; font-size:11px; color:#6f7f9c; }
.miss{ max-width:520px; margin:12vh auto; text-align:center; padding:34px; background:rgba(12,18,36,.9); border:1px solid var(--bd); border-radius:18px; }
/* ── PRINT: a clean light certificate → Save as PDF ── */
@media print{
  html,body{ background:#fff !important; color:#111 !important; }
  .bgwrap{ background:#fff !important; padding:0; }
  .cert{ box-shadow:none; border:2px solid #0b1220; background:#fff !important; }
  .cert::before{ display:none; }
  .hd{ background:#f4f6fb !important; border-bottom:2px solid #0b1220; }
  .hd h1,.hd .cid b{ color:#0b1220 !important; } .hd .sub,.hd .cid span{ color:#555 !important; }
  .gmeta h2,.box .kv .v,.sub-bar .nm{ color:#0b1220 !important; } .gmeta p,.kv .k{ color:#444 !important; }
  .box,.verify{ background:#fafbfe !important; border:1px solid #ccd; }
  .gring .in{ background:#fff !important; } .box h3{ color:#667 !important; }
  .acts,.foot{ display:none !important; }
  .verify code{ background:#eef !important; color:#224 !important; }
}
</style></head>
<body>
<?php if (!$ok): ?>
  <div class="miss">
    <div style="font-size:40px;color:#ff7a9c"><i class="fa-solid fa-file-circle-xmark"></i></div>
    <h1 style="font-size:20px;margin:10px 0 6px">Certificate not found</h1>
    <p style="color:#9fb0d8;font-size:13px;line-height:1.6">This NEURU System Passport link is invalid or was never issued. Ask the seller to generate a fresh one from <b>Gamers Hub → Hardware Longevity → Passport</b>.</p>
  </div>
<?php else:
  $rig=$d['rig']; $u=$d['usage']; $grade=$d['grade']; $tier=$d['tier'];
  $best=$d['benchmark']['best'] ?? 0; $hist=$d['benchmark']['history'] ?? [];
?>
  <div class="bgwrap">
    <div class="cert">
      <div class="hd">
        <div class="seal"><?= function_exists('nm_logo_svg') ? nm_logo_svg(46) : '<i class="fa-solid fa-shield-halved" style="font-size:30px;color:#7CFFB2"></i>' ?></div>
        <div>
          <h1>NEURU · SYSTEM PASSPORT</h1>
          <div class="sub">Hardware Health &amp; Re-sell Certificate — data-backed, not self-reported</div>
        </div>
        <div class="cid"><b><?= $e($id) ?></b><span>issued <?= $e(substr((string)($cert['created_at'] ?? $d['issued_at']),0,16)) ?> UTC</span></div>
      </div>
      <div class="body">
        <div class="gradeRow">
          <div class="gring" style="--g:<?= (int)($grade ?? 0) ?>"><div class="in"><b><?= $grade===null?'—':(int)$grade ?></b><small>LONGEVITY</small></div></div>
          <div class="gmeta">
            <h2><?= $e($rig['name'] ?: 'Gaming PC') ?> — <span class="tk"><?= $tier?$e($tier[0].' · '.$tier[1]):'unrated' ?></span></h2>
            <p>This passport certifies the <b>real, NEURU-recorded</b> operating history of the components below. Figures are frozen at issue and carry a tamper-evident seal — a used-hardware buyer gets transparency, not a promise.</p>
          </div>
        </div>

        <?php $sp=$d['specs'] ?? []; $drives=$rig['disks'] ?? []; ?>
        <div class="grid">
          <div class="box">
            <h3><i class="fa-solid fa-microchip"></i> Full specifications</h3>
            <?php foreach([['System','system'],['Motherboard','motherboard'],['BIOS','bios'],['CPU','cpu'],['GPU','gpu'],['Memory','ram'],['Display','display'],['OS','os']] as $sr): $val=trim((string)($sp[$sr[1]] ?? '')); if($val==='') continue; ?>
              <div class="kv"><span class="k"><?= $e($sr[0]) ?></span><span class="v"><?= $e($val) ?></span></div>
            <?php endforeach; ?>
          </div>
          <div class="box">
            <h3><i class="fa-solid fa-clock-rotate-left"></i> Usage on record</h3>
            <div class="kv"><span class="k">Watched by NEURU</span><span class="v"><?= $e($u['watched_hours']) ?> h<?= $u['first_seen']?(' · since '.$e(substr($u['first_seen'],0,10))):'' ?></span></div>
            <div class="kv"><span class="k">Heavy-load hours</span><span class="v"><?= $e($u['heavy_load_hours']) ?> h</span></div>
            <div class="kv"><span class="k">Peak temps</span><span class="v">GPU <?= $e($u['gpu_peak_c']) ?>°C · CPU <?= $e($u['cpu_peak_c']) ?>°C</span></div>
            <?php if(($u['ssd_poweron_days']??null)!==null): ?><div class="kv"><span class="k">Drive powered</span><span class="v"><?= $e($u['ssd_poweron_days']) ?> days</span></div><?php endif; ?>
          </div>
        </div>

        <?php if($drives): ?>
        <div class="box" style="margin-top:14px">
          <h3><i class="fa-solid fa-hard-drive"></i> Storage — all <?= count($drives) ?> drive<?= count($drives)===1?'':'s' ?></h3>
          <?php foreach($drives as $dk): ?>
            <div class="kv"><span class="k"><?= $e($dk['model'] ?: 'drive') ?> <span style="color:#8fa4c8"><?= $e(trim(($dk['media']?:'').' '.($dk['bus']?:''))) ?></span></span><span class="v"><?= (int)$dk['size_gb'] ?> GB</span></div>
          <?php endforeach; ?>
        </div>
        <?php endif; ?>
        <div class="box" style="margin-top:14px">
          <h3><i class="fa-solid fa-heart-pulse"></i> Subsystem health at issue</h3>
          <?php foreach(($d['subsystems'] ?? []) as $s): $col=['nand'=>'#7CFFB2','thermal'=>'#ff7a9c','vrm'=>'#e9c46a','fan'=>'#36e3d0'][$s['key']]??'#4da3ff'; $h=$s['health']; ?>
            <div class="sub-bar"><div class="top"><span class="nm"><?= $e($s['name']) ?><span class="badge <?= $s['measured']?'m':'est' ?>"><?= $s['measured']?'measured':'estimate' ?></span></span><span style="color:<?= $col ?>;font-weight:900"><?= $h===null?'—':(int)$h ?></span></div><div class="track"><i style="width:<?= $h===null?0:(int)$h ?>%;background:<?= $col ?>"></i></div></div>
          <?php endforeach; ?>
        </div>

        <?php if($best>0): ?>
        <div class="box" style="margin-top:14px">
          <h3><i class="fa-solid fa-gauge-high"></i> NEURU Benchmark history</h3>
          <div class="kv"><span class="k">Best NEURU Score</span><span class="v" style="color:var(--tier)"><?= number_format($best) ?> / 10,000</span></div>
          <?php if(count($hist)>1): $mx=max(array_map(fn($b)=>$b['score'],$hist))?:1; ?>
          <div class="bench"><?php foreach(array_reverse($hist) as $b): ?><div class="b" title="<?= $e($b['when'].' · '.$b['score']) ?>" style="height:<?= max(8,round($b['score']/$mx*100)) ?>%"></div><?php endforeach; ?></div>
          <div style="font-size:10.5px;color:#8fa4c8;margin-top:5px;text-align:right"><?= count($hist) ?> runs on record</div>
          <?php endif; ?>
        </div>
        <?php endif; ?>

        <div class="verify">
          <i class="fa-solid fa-circle-check big"></i>
          <div class="t">
            <b><?= $cert['valid'] ? 'Integrity verified — data unchanged since issue.' : 'Integrity seal mismatch.' ?></b><br>
            Issued by NEURU install <code><?= $e(substr((string)($cert['fingerprint'] ?? ''),0,16) ?: 'unregistered') ?></code>. All figures were recorded by NEURU's own agentless telemetry (LibreHardwareMonitor + SMART), not entered by the seller.<br>
            <span style="color:#8fa4c8">Seal (SHA-256): <code><?= $e(substr((string)($cert['hash'] ?? ''),0,32)) ?>…</code></span>
          </div>
        </div>
      </div>
    </div>
    <div class="acts">
      <a class="btn pri" onclick="window.print()"><i class="fa-solid fa-file-arrow-down"></i> Save as PDF / Print</a>
      <a class="btn" id="copyBtn" onclick="copyLink()"><i class="fa-solid fa-link"></i> Copy verifiable link</a>
      <a class="btn" href="longevity.php"><i class="fa-solid fa-arrow-left"></i> Back to Longevity</a>
    </div>
    <div class="foot">This passport is a snapshot of real telemetry recorded by NEURU. It cannot be edited after issue. Re-issue any time for fresh figures.</div>
  </div>
  <script>
  function copyLink(){ const u=location.origin+location.pathname+'?cert=<?= $e($id) ?>'; navigator.clipboard.writeText(u).then(()=>{ const b=document.getElementById('copyBtn'); const o=b.innerHTML; b.innerHTML='<i class="fa-solid fa-check"></i> Copied!'; setTimeout(()=>b.innerHTML=o,1600); }).catch(()=>prompt('Copy this link:',u)); }
  </script>
<?php endif; ?>
</body></html>
