<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — About / Credits. A cinematic end-of-movie credit roll of every
// open-source project NEURU stands on. RBAC: 'about' (seeded for every role —
// everyone can see the credits). In Site Configuration (last item).
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_chrome.php');
include('logger.php');

// About is for everyone — seed the perm for all roles (idempotent) so it's never hidden.
@$conn->query("INSERT INTO role_profiles (role_name,button_key,enabled)
    SELECT DISTINCT role_name,'about',1 FROM role_profiles r
    WHERE NOT EXISTS (SELECT 1 FROM role_profiles x WHERE x.role_name=r.role_name AND x.button_key='about')");
if (!checkAccess($conn, 'about')) { header('Location: /denied_access.php?page=about'); exit; }
log_user_action($conn, 'view_page', 'about.php');

// Version = the VERSION file (SINGLE source of truth — the self-updater ships it, so About and
// the updater can never disagree). Bump ONLY the VERSION file; this reads it. Fallback if absent.
define('NEURU_VERSION', (is_file(__DIR__.'/VERSION') && trim((string)@file_get_contents(__DIR__.'/VERSION')) !== '')
    ? trim((string)file_get_contents(__DIR__.'/VERSION')) : '0.1.1.6');

// Every open-source project NEURU builds on — rolled like film credits.
$credits = [
    'Core Platform'            => ['PHP 8.3', 'MySQL 8', 'Apache HTTP Server', 'Docker', 'Python 3'],
    'Real-time Visualization'  => ['three.js', 'Leaflet', 'OpenStreetMap · CartoDB', 'Chart.js', 'vis-network', 'Font Awesome', 'qrcode.js'],
    'Automation & Integrations'=> ['n8n', 'Portainer', 'Pi-hole', 'Smokeping', 'Graylog'],
    'Security & Cryptography'  => ['WireGuard', 'libsodium', 'OpenSSL', 'Paramiko'],
    'Geo & Data'               => ['ip-api · GeoIP', 'date-fns', 'MaxMind GeoLite'],
];
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{ --accent:#4da3ff; --cyan:#36e3d0; --violet:#c084fc; }
html{ background:#03050b; } body{ margin:0; font-family:'Segoe UI',Tahoma,sans-serif; background:transparent !important; color:#e9eef6; }
<?= nm_chrome_css() ?>
/* cinematic stage — a masked viewport the credits roll through */
#reel-stage{ position:relative; height:calc(100vh - 92px); min-height:560px; overflow:hidden;
  -webkit-mask-image:linear-gradient(180deg,transparent 0%,#000 16%,#000 82%,transparent 100%);
          mask-image:linear-gradient(180deg,transparent 0%,#000 16%,#000 82%,transparent 100%); }
#reel-stage::after{ content:''; position:absolute; inset:0; pointer-events:none;
  background:radial-gradient(ellipse 70% 55% at 50% 42%, transparent 40%, rgba(3,5,11,.55) 100%); }
#reel{ position:absolute; left:0; right:0; text-align:center; padding:0 24px;
  animation:roll 62s linear infinite; will-change:transform; }
#reel.paused{ animation-play-state:paused; }
#reel-stage{ cursor:pointer; }
@keyframes roll{ from{ transform:translateY(100vh);} to{ transform:translateY(-100%);} }

.hero{ margin:2vh auto 8vh; }
.hero .logo{ filter:drop-shadow(0 0 26px rgba(77,163,255,.55)); animation:breathe 4.5s ease-in-out infinite; display:inline-block; }
@keyframes breathe{ 0%,100%{ transform:scale(1);opacity:.96;} 50%{ transform:scale(1.05);opacity:1;} }
.hero h1{ font-size:52px; font-weight:800; letter-spacing:10px; margin:22px 0 2px;
  background:linear-gradient(120deg,#7fc0ff,#36e3d0 55%,#c084fc); -webkit-background-clip:text; background-clip:text; color:transparent; }
.hero .tag{ font-size:13px; letter-spacing:6px; text-transform:uppercase; color:#8ea6c4; margin-bottom:34px; }
.hero .role{ font-size:11px; letter-spacing:4px; text-transform:uppercase; color:#6f88a8; }
.hero .who{ font-size:24px; font-weight:700; letter-spacing:1px; color:#eaf2ff; margin:6px 0 3px; }
.hero .mail{ font-size:14px; color:#8ff0e4; letter-spacing:.5px; } .hero .mail a{ color:#8ff0e4; text-decoration:none; }
.hero .ver{ margin-top:26px; display:inline-block; font-family:Consolas,monospace; font-size:12.5px; letter-spacing:3px;
  color:#bcd8ff; border:1px solid rgba(77,163,255,.35); border-radius:30px; padding:7px 18px; background:rgba(77,163,255,.06); }

.block{ margin:0 auto 6.5vh; }
.block .cat{ font-size:12px; letter-spacing:6px; text-transform:uppercase; color:var(--cyan); margin-bottom:16px; position:relative; display:inline-block; }
.block .cat::before,.block .cat::after{ content:''; position:absolute; top:50%; width:40px; height:1px; background:linear-gradient(90deg,transparent,rgba(54,227,208,.6)); }
.block .cat::before{ right:calc(100% + 16px); transform:scaleX(-1);} .block .cat::after{ left:calc(100% + 16px); }
.block .name{ font-size:26px; font-weight:600; letter-spacing:1.5px; color:#eef3fb; line-height:1.95; text-shadow:0 0 20px rgba(120,170,255,.18); }
.block .name:hover{ color:#fff; text-shadow:0 0 24px rgba(120,200,255,.5); }

.finale{ margin:4vh auto 12vh; }
.finale .heart{ font-size:34px; }
.finale .thanks{ font-size:22px; font-weight:700; letter-spacing:3px; margin:14px 0 6px;
  background:linear-gradient(120deg,#ff9a9a,#ffd98a,#8ff0b6); -webkit-background-clip:text; background-clip:text; color:transparent; }
.finale .sub{ font-size:12.5px; letter-spacing:4px; text-transform:uppercase; color:#7d93b0; }
.finale .cc{ font-size:11px; color:#5f728c; letter-spacing:2px; margin-top:20px; }

#controls{ position:absolute; bottom:16px; left:50%; transform:translateX(-50%); z-index:5; display:flex; gap:8px; align-items:center; }
.cbtn{ background:rgba(10,16,28,.72); border:1px solid rgba(255,255,255,.14); color:#cfe4ff; border-radius:22px; padding:8px 15px; font-size:12.5px; cursor:pointer; backdrop-filter:blur(6px); }
.cbtn:hover{ border-color:var(--accent); color:#fff; }
#hint{ position:absolute; top:14px; left:50%; transform:translateX(-50%); z-index:5; font-size:11px; letter-spacing:2px; text-transform:uppercase; color:#5f728c; }
</style>

<?php include('header.php'); ?>
<div id="reel-stage" onclick="togglePlay()">
  <div id="hint">click to pause · the projects that make NEURU possible</div>
  <div id="reel">
    <div class="hero">
      <div class="logo"><?= nm_logo_svg(88) ?></div>
      <h1>NEURU</h1>
      <div class="tag">Neural Network Monitor</div>
      <div class="role">Developed by</div>
      <div class="who">Hector Miranda</div>
      <div class="role" style="margin-bottom:10px">System Engineer</div>
      <div class="mail"><i class="fa-solid fa-envelope"></i> <a href="mailto:hectorm.miranda@gmail.com">hectorm.miranda@gmail.com</a></div>
      <div class="ver">PORTAL VERSION <?= NEURU_VERSION ?></div>
      <div class="lic-line" style="margin-top:16px;font-size:13px;color:#9fb2c8;line-height:1.85;text-align:center">
        <i class="fa-solid fa-scale-balanced" style="color:#8bf3ff"></i> Free &amp; open source · <b>GNU AGPL-3.0</b> license<br>
        <i class="fa-brands fa-github" style="color:#8bf3ff"></i> <a href="https://github.com/hmiranda14/neuru" target="_blank" rel="noopener" style="color:#8bf3ff">github.com/hmiranda14/neuru</a><br>
        <i class="fa-solid fa-globe" style="color:#8bf3ff"></i> Get your free license at <a href="https://neurunetpr.com" target="_blank" rel="noopener" style="color:#8bf3ff">neurunetpr.com</a>
      </div>
    </div>

    <div class="block" style="margin-bottom:8vh">
      <div class="cat" style="color:var(--violet)">Standing on the shoulders of giants</div>
      <div class="name" style="font-size:16px;color:#9fb2c8;font-weight:400;letter-spacing:2px;max-width:560px;margin:0 auto">NEURU is built with, and grateful to, these open-source projects</div>
    </div>

    <?php foreach ($credits as $cat => $items): ?>
    <div class="block">
      <div class="cat"><?= htmlspecialchars($cat) ?></div>
      <?php foreach ($items as $it): ?><div class="name"><?= htmlspecialchars($it) ?></div><?php endforeach; ?>
    </div>
    <?php endforeach; ?>

    <div class="finale">
      <div class="heart">💙</div>
      <div class="thanks">Thank you</div>
      <div class="sub">Built with care in Puerto Rico 🇵🇷</div>
      <div class="cc">NEURU · Neural Network Monitor · v<?= NEURU_VERSION ?> · © <?= date('Y') ?> Hector Miranda</div>
    </div>
  </div>

  <div id="controls" onclick="event.stopPropagation()">
    <button class="cbtn" id="pp" onclick="togglePlay()"><i class="fa-solid fa-pause"></i> Pause</button>
    <button class="cbtn" onclick="replay()"><i class="fa-solid fa-rotate-left"></i> Replay</button>
    <button class="cbtn" onclick="cycleSpeed()" id="spd">1×</button>
  </div>
</div>

<script>
const reel=document.getElementById('reel'); let paused=false, speed=1; const speeds=[0.5,1,1.6,2.4];
function togglePlay(){ paused=!paused; reel.classList.toggle('paused',paused);
  document.getElementById('pp').innerHTML=paused?'<i class="fa-solid fa-play"></i> Play':'<i class="fa-solid fa-pause"></i> Pause'; }
function replay(){ reel.style.animation='none'; void reel.offsetWidth; applySpeed(); if(paused)togglePlay(); }
function cycleSpeed(){ speed=speeds[(speeds.indexOf(speed)+1)%speeds.length]; document.getElementById('spd').textContent=speed+'×'; applySpeed(); }
function applySpeed(){ reel.style.animationDuration=(62/speed)+'s'; reel.style.animationName='roll'; reel.style.animationTimingFunction='linear'; reel.style.animationIterationCount='infinite'; }
window.addEventListener('DOMContentLoaded',()=>{ if(window.NMLoader)NMLoader.hide(); });
</script>
</body></html>
