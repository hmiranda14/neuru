<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — OBS LIVE STREAM OVERLAY. PUBLIC, token-authed (no login — OBS Browser
// Source carries no session). Renders a transparent futuristic HUD of live game
// stats (ping/GPU/CPU/net/FPS) for ONE rig. The token = read-only bearer.
//   overlay.php?token=<32hex>[&theme=…]        &api=data → JSON
// ─────────────────────────────────────────────────────────────────────────────
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_gaming.php';

$token = preg_replace('/[^a-f0-9]/', '', strtolower((string)($_GET['token'] ?? '')));

if (($_GET['api'] ?? '') === 'data') {
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');   // OBS/Streamlabs CEF is fine same-origin, but be permissive
    if (function_exists('session_write_close')) @session_write_close();
    if ($token === '') { echo json_encode(['ok'=>false,'error'=>'no token']); exit; }
    echo json_encode(nm_gaming_overlay_data($conn, $token)); exit;
}

$ov = $token ? nm_gaming_overlay_by_token($conn, $token) : null;
$theme = preg_replace('/[^a-z]/','', strtolower((string)($_GET['theme'] ?? ($ov['theme'] ?? 'synthwave'))));
if (!in_array($theme, ['synthwave','matrix','neon','obsidian'], true)) $theme = 'synthwave';
?>
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NEURU Overlay</title>
<style>
/* transparent so OBS composites it over your gameplay */
html,body{ margin:0; background:transparent !important; overflow:hidden; font-family:'Segoe UI',Tahoma,sans-serif; -webkit-font-smoothing:antialiased; }
:root{ --a:#ff4ecd; --b:#7a5cff; --c:#39e1ff; --ok:#2ee66e; --warn:#ffb020; --crit:#ff4d6d; --ink:#ffffff; --panel:rgba(10,10,26,.42); --edge:rgba(255,255,255,.14); }
body.matrix{ --a:#22ff88; --b:#0f8; --c:#7dffb0; --panel:rgba(0,16,6,.5); --edge:rgba(50,255,140,.25); }
body.neon{ --a:#22a7ff; --b:#3a7bff; --c:#66e0ff; --panel:rgba(4,12,28,.5); --edge:rgba(60,160,255,.28); }
body.obsidian{ --a:#8a93a6; --b:#c9d2e3; --c:#e6ecf7; --panel:rgba(8,10,16,.62); --edge:rgba(180,190,210,.18); }
.hud{ position:fixed; top:14px; left:14px; display:inline-flex; align-items:center; gap:14px; padding:11px 16px; border-radius:14px;
  background:var(--panel); border:1px solid var(--edge); backdrop-filter:blur(9px);
  box-shadow:0 6px 26px rgba(0,0,0,.35), inset 0 0 22px rgba(120,140,255,.06); color:var(--ink); }
.hud::before{ content:''; position:absolute; inset:0; border-radius:14px; padding:1px; background:linear-gradient(120deg,var(--a),var(--b),var(--c)); -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0); -webkit-mask-composite:xor; mask-composite:exclude; opacity:.55; pointer-events:none; }
.brand{ display:flex; align-items:center; gap:7px; font-weight:900; letter-spacing:1px; font-size:13px; background:linear-gradient(90deg,var(--a),var(--c)); -webkit-background-clip:text; background-clip:text; color:transparent; }
.brand .dot{ width:8px; height:8px; border-radius:50%; background:var(--ok); box-shadow:0 0 10px var(--ok); animation:bl 1.6s infinite; } @keyframes bl{50%{opacity:.35}}
.stat{ display:flex; flex-direction:column; line-height:1.1; min-width:52px; }
.stat .v{ font-size:19px; font-weight:800; font-variant-numeric:tabular-nums; text-shadow:0 1px 6px rgba(0,0,0,.5); }
.stat .l{ font-size:9px; letter-spacing:.14em; text-transform:uppercase; color:rgba(255,255,255,.62); }
.stat .v small{ font-size:11px; opacity:.7 }
.sep{ width:1px; height:26px; background:var(--edge); }
.g-ok{ color:var(--ok) } .g-warn{ color:var(--warn) } .g-crit{ color:var(--crit) }
.game{ font-size:12px; font-weight:700; opacity:.9; max-width:150px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.thr{ color:var(--crit); animation:bl .8s infinite; }
#err{ position:fixed; top:14px; left:14px; color:#fff; background:rgba(200,30,60,.7); padding:8px 12px; border-radius:10px; font-size:12px; display:none; }
/* ── Dimensional HUD — reactive geometry states (the HUD breathes/retracts/distorts with the game) ── */
.hud{ transition:transform .55s cubic-bezier(.2,.8,.2,1), opacity .5s, filter .4s, box-shadow .4s, border-color .4s; transform-origin:top left; }
.hud.st-tactical{ box-shadow:0 6px 26px rgba(0,0,0,.4), 0 0 22px rgba(57,225,255,.28), inset 0 0 22px rgba(120,140,255,.1); }
.hud.st-kinetic{ transform:scale(.8) translate(-2px,-3px); backdrop-filter:blur(4px); box-shadow:0 4px 14px rgba(0,0,0,.3); }
.hud.st-kinetic .stat .l, .hud.st-kinetic .brand span:not(.dot), .hud.st-kinetic .game{ opacity:.28; }
.hud.st-kinetic::before{ opacity:.9; }
.hud.st-unstable{ animation:hudUnstable 1.05s infinite; border-color:rgba(255,90,120,.55); box-shadow:0 8px 30px rgba(255,60,90,.4), inset 0 0 26px rgba(255,60,90,.2); }
.hud.st-unstable::before{ opacity:1; background:linear-gradient(120deg,var(--crit),var(--warn),var(--crit)); }
@keyframes hudUnstable{ 0%,100%{ transform:perspective(520px) rotateX(0deg) translateZ(0); filter:none; } 46%{ transform:perspective(520px) rotateX(6deg) translateZ(16px); filter:drop-shadow(2px 0 0 rgba(255,0,90,.55)) drop-shadow(-2px 0 0 rgba(0,200,255,.5)); } }
</style></head>
<body class="<?= htmlspecialchars($theme) ?>">
<?php if (!$ov): ?>
  <div id="err" style="display:block">NEURU overlay — invalid or missing token. Generate one in Game Mode → Stream Overlay.</div>
<?php else: ?>
<div class="hud" id="hud" style="opacity:.35">
  <div class="brand"><span class="dot"></span> NEURU</div>
  <div class="sep" data-w="game"></div>
  <div class="game" data-w="game" id="w-game">—</div>
  <div class="sep" data-w="ping"></div>
  <div class="stat" data-w="ping"><span class="v" id="w-ping">—</span><span class="l">ping</span></div>
  <div class="sep" data-w="fps"></div>
  <div class="stat" data-w="fps"><span class="v" id="w-fps">—</span><span class="l">fps</span></div>
  <div class="sep" data-w="gpu"></div>
  <div class="stat" data-w="gpu"><span class="v" id="w-gpu">—</span><span class="l">gpu</span></div>
  <div class="sep" data-w="cpu"></div>
  <div class="stat" data-w="cpu"><span class="v" id="w-cpu">—</span><span class="l">cpu</span></div>
  <div class="sep" data-w="net"></div>
  <div class="stat" data-w="net"><span class="v" id="w-net">—</span><span class="l">net</span></div>
</div>
<script>
const TOKEN=<?= json_encode($token) ?>;
const $=s=>document.querySelector(s);
function show(w,on){ document.querySelectorAll('[data-w="'+w+'"]').forEach(e=>e.style.display=on?'':'none'); }
async function tick(){ try{ const d=await fetch('?api=data&token='+TOKEN).then(r=>r.json()); if(!d.ok)return;
  const o=d.opts||{};
  ['game','ping','gpu','cpu','net','fps'].forEach(w=>show(w, o[w]!==false));
  $('#hud').style.opacity=1;
  // game
  $('#w-game').textContent = d.game || 'idle';
  // ping
  if(o.ping!==false){ const p=d.ping; if(p&&p.ms!=null){ const g=p.ms<40?'g-ok':(p.ms<90?'g-warn':'g-crit'); $('#w-ping').className='v '+g; $('#w-ping').innerHTML=p.ms+'<small>ms</small>'; } else $('#w-ping').textContent='—'; }
  // fps
  if(o.fps!==false){ const f=d.fps; if(f&&f.ok){ $('#w-fps').innerHTML=Math.round(f.avg)+' <small>'+Math.round(f.low1)+'</small>'; } else $('#w-fps').textContent='—'; }
  // gpu
  if(o.gpu!==false){ const g=d.gpu||{}; if(g.util!=null){ const gc=g.temp>=85?'g-crit':(g.util>=90?'g-warn':''); $('#w-gpu').className='v '+gc+(g.throttle?' thr':''); $('#w-gpu').innerHTML=Math.round(g.util)+'%<small> '+(g.temp||0)+'°</small>'; } else $('#w-gpu').textContent='—'; }
  // cpu
  if(o.cpu!==false){ $('#w-cpu').innerHTML = d.cpu!=null ? (d.cpu+'<small>%</small>') : '—'; }
  // net (RAM% as a "system" proxy + loss flag)
  if(o.net!==false){ const loss=(d.ping&&d.ping.loss)||0; const ram = d.mem_total? Math.round(d.mem_used/d.mem_total*100):null; $('#w-net').className='v '+(loss>=3?'g-crit':'g-ok'); $('#w-net').innerHTML = loss>=3 ? (loss+'<small>% loss</small>') : (ram!=null? ('OK'):'OK'); }
  // ── Dimensional HUD: pick a reactive geometry state from the live signals ──
  const gp=d.gpu||{}, pg=d.ping||{};
  const crisis = (pg.loss>=3) || gp.throttle || (gp.temp>=85) || ((pg.jitter||0)>=20);
  const combat = (gp.util>=88) || (d.fps&&d.fps.ok&&d.fps.avg>0);
  const hasGame = d.game && d.game!=='—';
  const state = crisis ? 'unstable' : (combat ? 'kinetic' : (hasGame ? 'tactical' : 'zen'));
  const hud=document.getElementById('hud'); hud.className='hud st-'+state; hud.style.opacity = (state==='kinetic') ? '' : '1';
}catch(e){} }
tick(); setInterval(tick, 2000);
</script>
<?php endif; ?>
</body></html>
