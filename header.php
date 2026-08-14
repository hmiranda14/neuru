<?php
// NetMon standalone header/nav — included at top of every page
// Requires: session started, $conn available
if (session_status() === PHP_SESSION_NONE) session_start();
require_once __DIR__ . '/nm_chrome.php';   // brand mark + shared chrome helpers
require_once __DIR__ . '/nm_access.php';   // central permission engine

$_nm_role     = $_SESSION['role']     ?? 'guest';
$_nm_username = $_SESSION['username'] ?? '';
$_nm_uid      = (int)($_SESSION['UID'] ?? 0);
$_nm_avatar   = null;   // profile photo for the top-bar badge (best-effort)
if ($_nm_uid && is_file(__DIR__ . '/nm_profile.php')) {
    require_once __DIR__ . '/nm_profile.php';
    try { $_nm_avatar = nm_user_avatar_for($conn, $_nm_uid); } catch (\Throwable $e) {}
}
// License state for the top-bar indicator (best-effort; must never be fatal).
$_nm_lic = null;
if (is_file(__DIR__ . '/nm_license.php')) {
    require_once __DIR__ . '/nm_license.php';
    try { $_nm_lic = nm_lic_badge_state($conn); } catch (\Throwable $e) {}
}

// Nav gate — funnels through the shared engine (role default + per-user override).
function _nm_can($key) {
    global $conn, $_nm_role, $_nm_uid;
    return nm_user_can($conn, $_nm_uid, $_nm_role, $key);
}

$_nm_current = basename($_SERVER['PHP_SELF']);
function _nm_active($page) {
    global $_nm_current;
    return $page === $_nm_current ? 'active' : '';
}
?>
<!DOCTYPE html>
<!-- header fragment — pages should NOT repeat DOCTYPE; include this at the very top -->

<!-- NEURU favicon (brand neural emblem). /favicon.ico at the web root is auto-fetched by every
     page too; these tags add the crisp SVG + apple-touch for pages that include this header. -->
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png">
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="apple-touch-icon" href="/favicon-180.png">

<!-- ── Global page loader (all pages) — a fixed overlay that fades OUT on load to reveal
     the page. NEVER touches body opacity (that would re-create a stacking context and hide
     the NMNetBG particle canvas). Self-contained styles so it works before page CSS loads. -->
<style id="nm-loader-css">
/* veil = dark backdrop (z 99997). Particles (#nm-netbg) get raised to 99998 while loading
   so they show OVER the veil but UNDER the spinner (99999) → particle network behind the
   loader. On hide, the class is removed and the canvas returns to its normal z-index:-1. */
#nm-loader-veil{position:fixed;inset:0;z-index:99997;background:radial-gradient(circle at 50% 42%,#0a1018,#04060b);transition:opacity .5s ease;}
#nm-loader-veil.nm-hide{opacity:0;pointer-events:none;}
html.nm-loading #nm-netbg{z-index:99998 !important;}
#nm-loader{position:fixed;inset:0;z-index:99999;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;background:transparent;transition:opacity .5s ease;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;}
#nm-loader.nm-hide{opacity:0;pointer-events:none;}
#nm-loader .nlr{position:relative;width:120px;height:120px;}
#nm-loader .nlr i{position:absolute;border-radius:50%;border:2px solid transparent;}
#nm-loader .nlr i:nth-child(1){inset:0;border-top-color:#4da3ff;border-right-color:#4da3ff;animation:nmspin 1.1s linear infinite;box-shadow:0 0 16px rgba(77,163,255,.35);}
#nm-loader .nlr i:nth-child(2){inset:15px;border-bottom-color:#36e3d0;border-left-color:#36e3d0;animation:nmspin 1.6s linear infinite reverse;}
#nm-loader .nlr i:nth-child(3){inset:30px;border-top-color:#c084fc;border-right-color:#c084fc;animation:nmspin .9s linear infinite;}
#nm-loader .nlc{position:absolute;inset:46px;border-radius:50%;background:radial-gradient(circle,#4da3ff,transparent 70%);animation:nmcore 1.4s ease-in-out infinite;}
@keyframes nmspin{to{transform:rotate(360deg)}}
@keyframes nmcore{0%,100%{transform:scale(.7);opacity:.6}50%{transform:scale(1.1);opacity:1}}
#nm-loader .nlt{font-size:16px;font-weight:800;letter-spacing:4px;color:#eaf2ff;text-shadow:0 0 14px rgba(77,163,255,.5);}
#nm-loader .nls{font-size:11.5px;color:#7d8aa0;margin-top:-8px;letter-spacing:.5px;}
#nm-loader .nlbar{width:210px;height:3px;border-radius:3px;background:rgba(255,255,255,.08);overflow:hidden;}
#nm-loader .nlbar>span{display:block;height:100%;width:38%;border-radius:3px;background:linear-gradient(90deg,transparent,#4da3ff,#36e3d0,transparent);animation:nmslide 1.3s linear infinite;}
@keyframes nmslide{from{transform:translateX(-130%)}to{transform:translateX(330%)}}
@media print{#nm-loader{display:none!important;}}
</style>
<div id="nm-loader-veil"></div>
<div id="nm-loader"><div class="nlr"><i></i><i></i><i></i><div class="nlc"></div></div>
  <div class="nlt">NEURU</div><div class="nls" id="nm-loader-sub">initializing…</div>
  <div class="nlbar"><span></span></div></div>
<script>
// Global loader API: pages that load data via AJAX can call NMLoader.keep() early to hold
// the loader, then NMLoader.hide() when their data is ready (NMLoader.msg('…') updates the
// status). Pages that do nothing auto-hide on window.load. A 15s hard fallback never sticks.
window.NMLoader=(function(){var L=document.getElementById('nm-loader'),V=document.getElementById('nm-loader-veil');if(!L)return {hide:function(){},keep:function(){},msg:function(){}};
  document.documentElement.classList.add('nm-loading');   // raise the particle canvas behind the loader
  var m=['initializing NEURU…','loading layout…','gathering device data…','rendering view…','almost ready…'],i=0,s=document.getElementById('nm-loader-sub'),auto=true,done=false;
  var t=setInterval(function(){i=(i+1)%m.length;if(s)s.textContent=m[i];},1100);
  function hide(){if(done)return;done=true;clearInterval(t);L.classList.add('nm-hide');if(V)V.classList.add('nm-hide');
    setTimeout(function(){document.documentElement.classList.remove('nm-loading');if(L)L.style.display='none';if(V)V.style.display='none';},550);}
  function keep(){auto=false;}
  function msg(txt){if(s&&txt){s.textContent=txt;clearInterval(t);}}
  if(document.readyState==='complete'){setTimeout(function(){if(auto)hide();},250);}else{window.addEventListener('load',function(){setTimeout(function(){if(auto)hide();},250);});}
  setTimeout(hide,25000); // hard fallback — never stick (headroom for heavy pages that hold via keep())
  return {hide:hide,keep:keep,msg:msg};
})();
</script>

<?php if (!empty($GLOBALS['_NM_FED']) && function_exists('nm_fed_embed_script')) echo nm_fed_embed_script(); ?>
<?php if (empty($GLOBALS['_NM_FED']) && empty($_GET['embed'])): /* embed (fed remote OR same-origin ?embed=1) → strip the portal nav, show only the native dashboard */ ?>
<div id="nm-topbar">
    <nav class="nm-nav">
        <div class="nm-nav-brand">
            <a href="net_mon.php" title="NEURU — Neural Network Monitor">
                <?= nm_logo_svg(26) ?>
                <span class="neuru-word" style="font-size:1.15rem;">NEURU</span>
            </a>
        </div>
        <?php
        // NEURU BRAIN — WireGuard tunnel-to-brain health bulb (green=connected · yellow=issue · red=disconnected).
        // Shown only when WG is on/configured on THIS install AND the viewer has net_mon access (same RBAC as
        // the WG page). Live: polls wg_connection.php?api=wg_status every 30s. Universal — hidden if WG unused.
        if ((function_exists('_nm_can') ? _nm_can('net_mon') : true)) {
            require_once __DIR__ . '/nm_wgconn.php';
            if (function_exists('nm_wgconn_state')) {
                $__wg = nm_wgconn_state($conn);
                if ((($__wg['status'] ?? 'off') === 'on') || !empty($__wg['conf_present'])) {
                    if ((($__wg['status'] ?? '') === 'on') && !empty($__wg['link_up'])) { $__wgState = 'up';   $__wgMsg = 'connected' . (!empty($__wg['ip']) ? ' — ' . $__wg['ip'] : ''); }
                    elseif (($__wg['status'] ?? '') === 'on')                            { $__wgState = 'warn'; $__wgMsg = 'tunnel enrolled but wg0 is not up'; }
                    else                                                                 { $__wgState = 'down'; $__wgMsg = 'disconnected'; }
                    if (!empty($__wg['last_err']) && $__wgState !== 'up') { $__wgState = 'warn'; $__wgMsg = (string)$__wg['last_err']; }
        ?>
        <style>
        .nm-wgbrain{display:inline-flex;align-items:center;gap:7px;text-decoration:none;padding:4px 11px;border-radius:999px;border:1px solid rgba(255,255,255,.10);background:rgba(255,255,255,.03);margin-left:14px;transition:background .2s,border-color .2s;line-height:1;}
        .nm-wgbrain:hover{background:rgba(255,255,255,.08);border-color:rgba(255,255,255,.20);}
        .nm-wglabel{font-size:10px;font-weight:800;letter-spacing:1.3px;color:#9fb2cb;white-space:nowrap;}
        .nm-wgbulb{width:11px;height:11px;border-radius:50%;flex:0 0 auto;background:#6b7688;transition:background .35s,box-shadow .35s;}
        .nm-wgbulb[data-state="up"]{background:#2ee66e;box-shadow:0 0 9px #2ee66e;animation:nmwgpulse 2.2s ease-in-out infinite;}
        .nm-wgbulb[data-state="warn"]{background:#f0b429;box-shadow:0 0 9px #f0b429;animation:nmwgpulse 1s ease-in-out infinite;}
        .nm-wgbulb[data-state="down"]{background:#ff4d4d;box-shadow:0 0 9px #ff4d4d;}
        @keyframes nmwgpulse{0%,100%{opacity:1}50%{opacity:.4}}
        @media (max-width:820px){.nm-wglabel{display:none;}}
        </style>
        <a id="nm-wgbrain" href="wg_connection.php" class="nm-wgbrain" title="NEURU BRAIN — WireGuard tunnel to the NEURU brain: <?= htmlspecialchars($__wgMsg, ENT_QUOTES) ?>">
            <span class="nm-wgbulb" data-state="<?= $__wgState ?>"></span><span class="nm-wglabel">NEURU BRAIN</span>
        </a>
        <script>
        (function(){var el=document.getElementById('nm-wgbrain');if(!el)return;var b=el.querySelector('.nm-wgbulb');
        el.addEventListener('click',function(e){e.preventDefault();var w=780,h=700,x=Math.max(0,((screen.width||1200)-w)/2),y=Math.max(0,((screen.height||800)-h)/2);var p=window.open('wg_connection.php','nmwgbrain','width='+w+',height='+h+',left='+x+',top='+y+',menubar=no,toolbar=no,location=no,status=no,resizable=yes,scrollbars=yes');if(p)p.focus();});
        function apply(st){var s='down',m='disconnected';
          if(st){ if(st.status==='on'&&st.link_up){s='up';m='connected'+(st.ip?' — '+st.ip:'');}
            else if(st.status==='on'){s='warn';m='tunnel enrolled but wg0 is not up';}
            else{s='down';m='disconnected';}
            if(st.last_err&&s!=='up'){s='warn';m=st.last_err;} }
          b.setAttribute('data-state',s);el.title='NEURU BRAIN — WireGuard tunnel to the NEURU brain: '+m;}
        function poll(){fetch('wg_connection.php?api=wg_status',{cache:'no-store'}).then(function(r){return r.json();}).then(function(r){if(r&&r.ok)apply(r.state);}).catch(function(){});}
        poll();setInterval(poll,30000);})();
        </script>
        <?php
                }
            }
        }
        ?>
        <?php
        // Smokeping is gated by permission AND the optional tool being enabled.
        $_nm_sp_on = false;
        if (_nm_can('smokeping')) { $_r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='smokeping_enabled' LIMIT 1"); $_nm_sp_on = $_r && ($_x=$_r->fetch_row()) && $_x[0]==='1'; }

        // Grouped nav. Each item: [permission key, page, icon, label].
        // '__smokeping' is special-cased (needs the tool enabled, not just permission).
        $_nm_groups = [
            'Command Centers' => ['icon'=>'fa-solid fa-satellite-dish', 'items'=>[
                ['neurutik',      'neurutik.php',      'fa-solid fa-circle-nodes',         'NEURUTIK'],
                ['matrix_flow',   'matrix_flow.php',   'fa-solid fa-diagram-project',      'NEURUTIK Matrix Flow'],
                ['command',       'command.php',       'fa-solid fa-satellite-dish',       'Command Center'],
                ['dbobs',         'dbobservatory.php', 'fa-solid fa-satellite',            'DB Observatory'],
                ['geomap',        'geomap.php',        'fa-solid fa-earth-americas',       'Geo Wall', '_blank'],
                ['net_mon_map',   'net_mon_map.php',   'fa-solid fa-diagram-project',      'Map'],
                ['autopilotv2',   'autopilotv2.php',   'fa-solid fa-brain',                'NEURU Commander'],
                ['traffic_view',  'traffic_viewer.php','fa-solid fa-wave-square',          'Realtime Traffic'],
                ['federation',    'remote_console.php','fa-solid fa-satellite-dish',       'Remote Console'],
                ['router_center', 'router_command.php','fa-solid fa-route',                'Router Command Center'],
                ['routing_center','routing_command.php','fa-solid fa-diagram-project',     'Routing Command Center'],
                ['biosphere',     'biosphere.php',     'fa-solid fa-dna',                  'Service Biosphere'],
                ['hologram',      'hologram.php',      'fa-solid fa-cube',                 'Traffic Hologram'],
            ]],
            'Monitoring' => ['icon'=>'fa-solid fa-gauge-high', 'items'=>[
                ['__always',      'monitoring_center.php', 'fa-solid fa-gauge-high',       'Monitoring Center'],
                ['switches',      'switch_center.php', 'fa-solid fa-ethernet',             'Switch Control Center'],
                ['chaos',         'chaos.php',         'fa-solid fa-burst',                'Chaos Test'],
                ['cisco_asa',     'cisco_asa.php',     'fa-solid fa-shield-halved',        'Cisco ASA Firewall'],
                ['cisco',         'cisco.php',         'fa-solid fa-network-wired',        'Cisco Fleet'],
                ['cisco_orch',    'cisco_orch.php',    'fa-solid fa-sliders',              'Cisco Orchestrator'],
                ['cisco_router',  'cisco_router.php',  'fa-solid fa-route',                'Cisco Routers'],
                ['cisco_switch',  'cisco_switch.php',  'fa-solid fa-ethernet',             'Cisco Switches'],
                ['linux',         'linux.php',         'fa-brands fa-linux',               'Linux Monitor'],
                ['live_mon',      'live_mon.php',      'fa-solid fa-tower-broadcast',      'Live'],
                ['log_mon',       'log_mon.php',       'fa-solid fa-file-lines',           'Logs'],
                ['netflow',       'netflow.php',       'fa-solid fa-chart-area',           'NetFlow'],
                ['sonify',        'sonify.php',        'fa-solid fa-satellite-dish',       'Network Sonar'],
                ['health',        'health.php',        'fa-solid fa-heart-pulse',          'Predictive Health'],
                ['routers',       'routers.php',       'fa-solid fa-route',                'Router Monitor'],
                ['watchdog',      'watchdog.php',      'fa-solid fa-shield-heart',         'Service Watchdog'],
                ['shadowit',      'shadowit.php',      'fa-solid fa-user-secret',          'Shadow IT'],
                ['sla_live',      'sla.php',           'fa-solid fa-heart-pulse',          'SLA Live Center'],
                ['net_mon_stats', 'net_mon_stats.php', 'fa-solid fa-chart-bar',            'Stats'],
                ['timetravel',    'timetravel.php',    'fa-solid fa-clock-rotate-left',    'Time-Travel'],
                ['troubleshoot',  'troubleshoot.php',  'fa-solid fa-stethoscope',          'Troubleshoot Wizard'],
                ['l2switch',      'l2switch.php',      'fa-solid fa-ethernet',             'Unmanaged Switches'],
                ['wear',          'wear.php',          'fa-solid fa-heart-crack',          'Wear & Stress'],
                ['windows',       'windows.php',       'fa-brands fa-windows',             'Windows Monitor'],
            ]],
            'AI Tools' => ['icon'=>'fa-solid fa-brain', 'items'=>[
                ['gpu',         'gpu.php',         'fa-solid fa-microchip',               'AI / GPU Monitor'],
                ['archaeology', 'archaeology.php', 'fa-solid fa-magnifying-glass-chart',  'AI Archaeologist'],
                ['ai_insights', 'ai_insights.php', 'fa-solid fa-wand-magic-sparkles',     'AI Insights'],
            ]],
            'Ext Monitoring' => ['icon'=>'fa-solid fa-satellite-dish', 'items'=>[
                ['containers',  'containers.php', 'fa-brands fa-docker',       'Containers'],
                ['dbmon',       'dbmon.php',      'fa-solid fa-database',      'Data Core (DBs)'],
                ['pihole',      'pihole.php',     'fa-solid fa-shield-halved', 'Pi-hole'],
                ['adguard',     'adguard.php',    'fa-solid fa-shield-cat',    'AdGuard Home'],
                ['__smokeping', 'smokeping.php',  'fa-solid fa-wave-square',   'Smokeping'],
                ['weather',     'weather.php',   'fa-solid fa-hurricane',  'Weather Routing'],
            ]],
            'Healing' => ['icon'=>'fa-solid fa-shield-heart', 'items'=>[
                ['sentinel',    'sentinel.php',   'fa-solid fa-shield-halved', 'Sentinel Engine'],
                ['immunity',    'immunity.php',   'fa-solid fa-shield-virus',  'Collective Immunity'],
                ['deception',   'deception.php',  'fa-solid fa-mask',          'Deception Grid'],
                ['heal',        'heal.php',       'fa-solid fa-robot',         'Self-Healing'],
            ]],
            'Net Tools' => ['icon'=>'fa-solid fa-toolbox', 'items'=>[
                ['nettools_ping',    'netping.php',   'fa-solid fa-tower-broadcast',  'Live Ping'],
                ['nettools_netstat', 'netstat.php',   'fa-solid fa-diagram-project',  'Netstat'],
                ['nettools_lookup',  'netlookup.php', 'fa-solid fa-magnifying-glass-location', 'NS Lookup'],
                ['nettools_portscan','portscan.php',  'fa-solid fa-satellite-dish',   'Port Scanner'],
                ['nettools_trace',   'nettrace.php',  'fa-solid fa-route',            'Traceroute Map'],
            ]],
            'Gaming' => ['icon'=>'fa-solid fa-gamepad', 'items'=>[
                ['gaming',            'game_hub.php',  'fa-solid fa-gamepad',          'Gamers Hub'],
            ]],
            'Device Tools' => ['icon'=>'fa-solid fa-network-wired', 'items'=>[
                ['router_commander', 'router_commander.php', 'fa-solid fa-network-wired',  'Adv. Solution Commander'],
                ['config_mgr',       'config_mgr.php',       'fa-solid fa-file-shield',    'Config Manager'],
                ['mtfw',             'mtfw.php',             'fa-solid fa-shield-halved',  'MikroTik Device Manager'],
                ['wifi',             'wifi.php',             'fa-solid fa-wifi',           'WiFi Control Center'],
                ['wireguard',        'wireguard.php',        'fa-solid fa-shield-halved',  'WireGuard Orchestrator'],
                ['utilities',        'utilities.php',        'fa-solid fa-toolbox',        'NEURU Utilities'],
            ]],
            'Site Configuration' => ['icon'=>'fa-solid fa-sliders', 'items'=>[
                ['__always',       'site_config.php',    'fa-solid fa-compass',        'Configuration Center'],
                ['about',          'about.php',          'fa-solid fa-circle-info',    'About'],
                ['user_admin',     'access_admin.php',   'fa-solid fa-user-shield',    'Access Control'],
                ['audit_log',      'audit_log.php',      'fa-solid fa-clipboard-list', 'Audit Log'],
                ['net_mon_config', 'net_mon_config.php', 'fa-solid fa-gear',           'Config'],
                ['vault',          'vault.php',          'fa-solid fa-vault',          'Data Vault'],
                ['federation',     'federation.php',     'fa-solid fa-sitemap',        'Federation'],
                ['__always',       'https://neurunetpr.com/?p=guide', 'fa-solid fa-circle-question', 'Help & Support', '_blank'],
                ['ipam',           'ipam.php',           'fa-solid fa-sitemap',        'IP Address Mgmt'],
                ['license',        'license.php',        'fa-solid fa-certificate',    'Licensing'],
                ['incidents',      'notify_admin.php',   'fa-solid fa-bell',           'Notifications & Maintenance'],
                ['config_backup',  'config_backup.php',  'fa-solid fa-floppy-disk',    'Save Configuration'],
                ['reports',        'reports.php',        'fa-solid fa-gauge-high',     'SLA & Reports'],
                ['stream_decks',   'stream_decks.php',   'fa-solid fa-grip',           'Stream Decks'],
                ['support',        'support.php',        'fa-solid fa-life-ring',      'Support & Bugs'],
                ['net_mon_config', 'thresholds.php',    'fa-solid fa-sliders',        'Thresholds & Sensitivity'],
                ['update',         'update.php',         'fa-solid fa-cloud-arrow-down', 'Updates'],
                ['command',        'widget_market.php',  'fa-solid fa-store',          'Widget Marketplace'],
                ['command',        'widget_sdk.php',     'fa-solid fa-graduation-cap', 'Widget SDK Guide'],
                ['command',        'widgets.php',        'fa-solid fa-puzzle-piece',   'Widget Studio'],
            ]],
        ];
        ?>
        <?= function_exists('nm_tz_js') ? nm_tz_js($conn ?? null) : '' ?>
        <ul class="nm-nav-links">
            <li><a href="home.php" class="nm-hero <?= _nm_active('home.php') ?>" title="Command Deck — your launchpad to every module">
                <span>Home</span>
            </a></li>

            <?php if (_nm_can('net_mon')): ?>
            <li><a href="net_mon.php" class="<?= _nm_active('net_mon.php') ?>">
                <i class="fa-solid fa-chart-line"></i> Dashboard
            </a></li>
            <?php endif; ?>

            <?php if (_nm_can('incidents')): ?>
            <li><a href="incidents.php" class="<?= _nm_active('incidents.php') ?>" style="position:relative;">
                <i class="fa-solid fa-triangle-exclamation"></i> Incidents
                <span id="nm-inc-badge" style="display:none;position:absolute;top:-2px;right:-2px;background:#e74c3c;color:#fff;font-size:9px;font-weight:700;min-width:15px;height:15px;line-height:15px;text-align:center;border-radius:8px;padding:0 3px;"></span>
            </a></li>
            <?php endif; ?>


            <?php
            // Groups whose dropdown COLLAPSES to a single "center" hub link — everything else in the group
            // is reached from inside that center. The center page itself is an item of the group, and the
            // center reads the FULL $_nm_groups list to build its cards, so the data stays untouched here.
            $_nm_collapse = ['Site Configuration' => 'site_config.php', 'Monitoring' => 'monitoring_center.php'];
            foreach ($_nm_groups as $_gname => $_grp):
                $_vis = [];
                foreach ($_grp['items'] as $_it) {
                    if (isset($_nm_collapse[$_gname]) && $_it[1] !== $_nm_collapse[$_gname]) continue;
                    if ($_it[0] === '__smokeping') { if ($_nm_sp_on) $_vis[] = $_it; continue; }
                    if ($_it[0] === '__always') { $_vis[] = $_it; continue; }   // visible to every user (e.g. Help)
                    if (_nm_can($_it[0])) $_vis[] = $_it;
                }
                if (!$_vis) continue;
                $_gactive = false;
                foreach ($_vis as $_it) if ($_it[1] === $_nm_current) { $_gactive = true; break; }
            ?>
            <li class="nm-group <?= $_gactive ? 'active' : '' ?>">
                <span class="nm-group-label"><i class="<?= $_grp['icon'] ?>"></i> <?= htmlspecialchars($_gname) ?>
                    <i class="fa-solid fa-chevron-down nm-caret"></i></span>
                <ul class="nm-submenu">
                    <?php foreach ($_vis as $_it): $_blank = (($_it[4] ?? '') === '_blank'); ?>
                    <li><a href="<?= $_it[1] ?>" class="<?= _nm_active($_it[1]) ?>"<?= $_blank ? ' target="_blank" rel="noopener"' : '' ?>>
                        <i class="<?= $_it[2] ?>"></i> <?= htmlspecialchars($_it[3]) ?><?= $_blank ? ' <i class="fa-solid fa-up-right-from-square" style="font-size:.7em;opacity:.6;"></i>' : '' ?>
                    </a></li>
                    <?php endforeach; ?>
                </ul>
            </li>
            <?php endforeach; ?>
        </ul>
        <div class="nm-nav-user">
            <?php if ($_nm_lic && empty($_nm_lic['licensed'])):
                $_lic_link = _nm_can('license'); ?>
            <?php if ($_lic_link): ?><a href="license.php" class="nm-lic-pill" title="This install is not licensed — click to activate a NEURU license"><?php else: ?><span class="nm-lic-pill" title="This install is not licensed"><?php endif; ?>
                <i class="fa-solid fa-triangle-exclamation"></i> Unlicensed
            <?php if ($_lic_link): ?></a><?php else: ?></span><?php endif; ?>
            <?php endif; ?>
            <a href="user_profile.php" class="nm-user-badge" title="My profile" style="text-decoration:none;color:inherit;">
                <?php if ($_nm_avatar): ?>
                <img src="<?= htmlspecialchars($_nm_avatar) ?>" alt="" class="nm-user-avatar">
                <?php else: ?>
                <i class="fa-solid fa-user-circle"></i>
                <?php endif; ?>
                <?= htmlspecialchars($_nm_username) ?>
                <span class="nm-role-tag"><?= htmlspecialchars($_nm_role) ?></span>
            </a>
            <a href="logout.php" class="nm-logout-btn" title="Logout">
                <i class="fa-solid fa-right-from-bracket"></i>
            </a>
        </div>
    </nav>
</div>
<?php
// Auto back-link to the hub/center that OWNS the current page (Configuration / Monitoring / …).
// Data-driven from the same $_nm_groups source — no per-page edits, always consistent. To add a new
// center later: register it here (page → label + the nav groups it aggregates) and nowhere else.
$_nm_centers = [
    'site_config.php'       => ['label' => 'Site Configuration Center', 'groups' => ['Site Configuration']],
    'monitoring_center.php' => ['label' => 'Monitoring Center',         'groups' => ['Monitoring', 'AI Tools', 'Ext Monitoring']],
];
if (($_nm_current ?? '') !== '' && !isset($_nm_centers[$_nm_current])) {
    $_back = null;
    foreach ($_nm_centers as $_cpage => $_cdef) {
        foreach ($_cdef['groups'] as $_cg) {
            foreach (($_nm_groups[$_cg]['items'] ?? []) as $_ci) {
                if (!empty($_ci[1]) && strpos($_ci[1], 'http') !== 0 && basename($_ci[1]) === $_nm_current) {
                    $_back = ['page' => $_cpage, 'label' => $_cdef['label']]; break 3;
                }
            }
        }
    }
    if ($_back) {
        echo '<div style="max-width:1400px;margin:12px auto 0;padding:0 20px;">'
           . '<a href="' . htmlspecialchars($_back['page']) . '" style="display:inline-flex;align-items:center;gap:8px;font-size:12px;font-weight:600;color:#7fb2ff;text-decoration:none;background:rgba(77,163,255,.09);border:1px solid rgba(77,163,255,.26);padding:6px 14px;border-radius:20px;transition:background .15s;" onmouseover="this.style.background=\'rgba(77,163,255,.18)\'" onmouseout="this.style.background=\'rgba(77,163,255,.09)\'">'
           . '<i class="fa-solid fa-arrow-left"></i> ' . htmlspecialchars($_back['label']) . '</a></div>';
    }
}
?>
<?php endif; /* end not-embedded nav */ ?>

<style>
#nm-topbar {
    position: sticky;
    top: 0;
    z-index: 1000;
    background: #0f172a;
    border-bottom: 1px solid rgba(255,255,255,0.08);
    box-shadow: 0 2px 12px rgba(0,0,0,0.4);
}
.nm-nav {
    display: flex;
    align-items: center;
    max-width: 1980px;       /* wider so the full menu fits one row on big screens */
    margin: 0 auto;
    padding: 6px 16px;
    min-height: 52px;        /* grows (instead of clipping) when the menu wraps on small screens */
    gap: 0;
}
.nm-nav-brand a {
    display: flex;
    align-items: center;
    gap: 8px;
    color: #38bdf8;
    text-decoration: none;
    font-weight: 700;
    font-size: 1.1rem;
    margin-right: 32px;
    white-space: nowrap;
}
.nm-nav-brand a i { font-size: 1.2rem; }
<?= nm_brand_css() ?>
.nm-nav-links {
    display: flex;
    list-style: none;
    margin: 0;
    padding: 0;
    gap: 2px;
    row-gap: 4px;
    flex: 1;
    min-width: 0;
    flex-wrap: wrap;          /* cramped screens → wrap to a second row instead of clipping off the right
                                 (NOT overflow:auto — that would clip the dropdown submenus) */
    align-items: center;
    justify-content: center;  /* balance the menu in the bar (brand left · menu centered · user right) */
}
.nm-nav-links li a {
    display: flex;
    align-items: center;
    gap: 5px;
    padding: 6px 10px;
    color: rgba(241,245,249,0.7);
    text-decoration: none;
    font-size: 0.84rem;
    font-weight: 500;
    border-radius: 8px;
    transition: background 0.15s, color 0.15s;
    white-space: nowrap;
}
.nm-nav-links li a:hover,
.nm-nav-links li a.active {
    background: rgba(56,189,248,0.12);
    color: #38bdf8;
}
.nm-nav-links li a.active {
    font-weight: 700;
}
/* ── Command Center: delicate highlight (same size as siblings) ──────────── */
.nm-nav-links li a.nm-hero {
    color: #7dd3fc;
    font-weight: 600;
    background: rgba(77,163,255,0.06);
    box-shadow: inset 0 0 0 1px rgba(77,163,255,0.30);
}
.nm-nav-links li a.nm-hero i {
    color: #38bdf8;
    filter: drop-shadow(0 0 4px rgba(56,189,248,0.55));
    animation: nm-hero-glow 3s ease-in-out infinite;
}
.nm-nav-links li a.nm-hero:hover,
.nm-nav-links li a.nm-hero.active {
    color: #bae6fd;
    background: rgba(77,163,255,0.14);
    box-shadow: inset 0 0 0 1px rgba(77,163,255,0.55);
}
@keyframes nm-hero-glow {
    0%, 100% { filter: drop-shadow(0 0 3px rgba(56,189,248,0.40)); }
    50%      { filter: drop-shadow(0 0 7px rgba(56,189,248,0.85)); }
}
@media (prefers-reduced-motion: reduce) {
    .nm-nav-links li a.nm-hero i { animation: none; }
}
/* ── Grouped dropdown menus ─────────────────────────────────────────────── */
.nm-group { position: relative; }
.nm-group-label {
    display: flex; align-items: center; gap: 5px;
    padding: 6px 10px; cursor: pointer; user-select: none;
    color: rgba(241,245,249,0.7); font-size: 0.84rem; font-weight: 500;
    border-radius: 8px; white-space: nowrap; transition: background 0.15s, color 0.15s;
}
.nm-group:hover > .nm-group-label,
.nm-group.open  > .nm-group-label,
.nm-group.active > .nm-group-label { background: rgba(56,189,248,0.12); color: #38bdf8; }
.nm-group.active > .nm-group-label { font-weight: 700; }
.nm-caret { font-size: 0.6rem; opacity: 0.65; transition: transform 0.15s; }
.nm-group:hover .nm-caret, .nm-group.open .nm-caret { transform: rotate(180deg); }
/* invisible hover bridge so the 6px gap doesn't drop the menu */
.nm-group::after { content: ''; position: absolute; top: 100%; left: 0; right: 0; height: 8px; }
.nm-submenu {
    position: absolute; top: 100%; left: 0; margin-top: 6px; min-width: 210px;
    background: #0f172a; border: 1px solid rgba(255,255,255,0.1); border-radius: 10px;
    box-shadow: 0 14px 34px rgba(0,0,0,0.55); padding: 6px; list-style: none;
    display: none; flex-direction: column; gap: 2px; z-index: 1100;
}
.nm-group:hover > .nm-submenu, .nm-group.open > .nm-submenu { display: flex; }
.nm-submenu li { width: 100%; }
.nm-submenu li a {
    display: flex; align-items: center; gap: 9px; padding: 8px 12px;
    border-radius: 7px; color: rgba(241,245,249,0.75); text-decoration: none;
    font-size: 0.85rem; font-weight: 500; white-space: nowrap;
}
.nm-submenu li a i { width: 16px; text-align: center; opacity: 0.85; }
.nm-submenu li a:hover, .nm-submenu li a.active { background: rgba(56,189,248,0.12); color: #38bdf8; }
.nm-submenu li a.active { font-weight: 700; }
.nm-nav-user {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-left: auto;
}
.nm-user-badge {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 0.82rem;
    color: rgba(241,245,249,0.6);
    cursor: pointer;
    transition: color .15s ease;
}
.nm-user-badge:hover { color: rgba(241,245,249,0.95); }
.nm-user-avatar {
    width: 24px; height: 24px; border-radius: 50%; object-fit: cover;
    border: 1px solid rgba(77,163,255,0.55);
    box-shadow: 0 0 0 2px rgba(77,163,255,0.12);
}
.nm-role-tag {
    background: rgba(56,189,248,0.15);
    color: #38bdf8;
    border-radius: 4px;
    padding: 1px 6px;
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.nm-lic-pill {
    display: inline-flex; align-items: center; gap: 6px;
    background: rgba(240,169,44,0.12); border: 1px solid rgba(240,169,44,0.45);
    color: #ffd98a; border-radius: 20px; padding: 4px 11px;
    font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
    text-decoration: none; white-space: nowrap; cursor: pointer;
    transition: background 0.15s, border-color 0.15s;
}
.nm-lic-pill:hover { background: rgba(240,169,44,0.22); border-color: rgba(240,169,44,0.75); color: #ffe6ad; }
.nm-lic-pill i { animation: nm-lic-blink 2.4s ease-in-out infinite; }
@keyframes nm-lic-blink { 0%,100%{ opacity:.65; } 50%{ opacity:1; } }
@media (prefers-reduced-motion: reduce) { .nm-lic-pill i { animation: none; } }
@media (max-width: 768px) { .nm-lic-pill span { display: none; } }
.nm-logout-btn {
    color: rgba(241,245,249,0.5);
    text-decoration: none;
    font-size: 1rem;
    padding: 5px 8px;
    border-radius: 6px;
    transition: color 0.15s, background 0.15s;
}
.nm-logout-btn:hover {
    color: #ef4444;
    background: rgba(239,68,68,0.1);
}
@media (max-width: 768px) {
    .nm-nav { flex-wrap: wrap; height: auto; padding: 8px 12px; gap: 8px; }
    .nm-nav-links { gap: 1px; flex-wrap: wrap; }
    .nm-nav-links li a span { display: none; }
    .nm-user-badge .nm-username { display: none; }
}
/* Futuristic network background — sits above the (now dimmed) bg video, behind content. */
#nm-netbg { position: fixed; inset: 0; z-index: -1; pointer-events: none; }
#bg-video { z-index: -2 !important; opacity: .12 !important; }
</style>
<script>
// Dropdown groups: hover opens on desktop; click/tap toggles (touch-friendly).
document.querySelectorAll('.nm-group-label').forEach(function (lbl) {
    lbl.addEventListener('click', function (e) {
        e.stopPropagation();
        var g = lbl.parentElement, open = g.classList.contains('open');
        document.querySelectorAll('.nm-group.open').forEach(function (x) { x.classList.remove('open'); });
        if (!open) g.classList.add('open');
    });
});
document.addEventListener('click', function () {
    document.querySelectorAll('.nm-group.open').forEach(function (x) { x.classList.remove('open'); });
});
</script>
<?php
// Live signals → glowing alert hubs on the network background. Best-effort: any
// DB hiccup just yields a decorative field (mysqli throws in 8.1+, so guard).
$_nm_signals = [];
$_sev_lvl = function ($sev) {
    $sev = strtolower(trim((string)$sev));
    return in_array($sev, ['critical','crit','fatal','error']) ? 'crit'
         : (in_array($sev, ['warning','warn']) ? 'warn' : 'info');
};
// operator toggles (net_mon_config → Settings): show error / event markers on the particle bg?
$_nm_bg = ['errors' => true, 'events' => true];
try { $_bgq = $conn->query("SELECT setting_key, setting_val FROM nm_settings WHERE setting_key IN ('netbg_show_errors','netbg_show_events')");
    while ($_bgq && $_x = $_bgq->fetch_assoc()) {
        if ($_x['setting_key'] === 'netbg_show_errors') $_nm_bg['errors'] = ($_x['setting_val'] !== '0');
        else $_nm_bg['events'] = ($_x['setting_val'] !== '0');
    }
} catch (\Throwable $e) {}
// 1) container errors
if ($_nm_bg['errors']) try {
    $_sg = $conn->query("SELECT container_name, severity FROM container_incidents
                         WHERE status IN ('open','analyzing','acknowledged')
                         ORDER BY last_seen DESC LIMIT 4");
    if ($_sg) while ($row = $_sg->fetch_assoc()) {
        $_nm_signals[] = ['label' => ($row['container_name'] ?: 'container') . ' · ' . strtoupper($row['severity'] ?: 'ERROR'),
                          'level' => $_sev_lvl($row['severity'])];
    }
} catch (\Throwable $e) {}
// 2) network incidents / EVENTS (device down, high loss, anomalies…) — marked the same way
if ($_nm_bg['events']) try {
    $_ev = $conn->query("SELECT title, severity, root_entity FROM nm_incidents
                         WHERE status IN ('open','acknowledged')
                         ORDER BY opened_at DESC LIMIT 6");
    if ($_ev) while ($row = $_ev->fetch_assoc()) {
        $lab = trim((string)($row['root_entity'] ?: $row['title'])); if ($lab === '') $lab = 'event';
        $_nm_signals[] = ['label' => mb_substr($lab, 0, 26) . ' · ' . strtoupper((string)($row['severity'] ?: 'INFO')),
                          'level' => $_sev_lvl($row['severity'])];
    }
} catch (\Throwable $e) {}
$_nm_signals = array_slice($_nm_signals, 0, 10);
?>
<script src="/nm_netbg.js"></script>
<script>
    // Start the particles IMMEDIATELY (body already exists here — the nav was emitted above).
    // Waiting for DOMContentLoaded delayed them until the WHOLE page parsed, so on slow
    // server-rendered pages the loader showed with no particle background for several seconds.
    (function () {
        function nmBoot() {
            if (!window.NMNetBG) return;
            window.NMNetBG.init({ color: '#4da3ff', density: 0.9, linkDist: 140, mouseDist: 175 });
            var signals = <?= json_encode($_nm_signals, JSON_UNESCAPED_SLASHES) ?>;
            if (signals && signals.length) window.NMNetBG.setData(signals);
        }
        if (document.body) nmBoot(); else document.addEventListener("DOMContentLoaded", nmBoot);
    })();
    // Active-incident count badge on the nav (best-effort).
    (function(){
        var badge = document.getElementById('nm-inc-badge');
        if (!badge) return;
        function refresh(){
            fetch('incidents.php?api=list&status=active').then(function(r){return r.json();}).then(function(d){
                if (!d || !d.ok) return;
                var n = (d.stats && d.stats.active) || 0;
                badge.textContent = n > 99 ? '99+' : n;
                badge.style.display = n > 0 ? '' : 'none';
                badge.style.background = (d.stats && d.stats.critical > 0) ? '#e74c3c' : '#f39c12';
            }).catch(function(){});
        }
        refresh(); setInterval(function(){ if(!document.hidden) refresh(); }, 30000);
    })();
</script>
<?php
// Global NetOps Copilot slide-out (only for users with access; harmless if the
// netops-copilot webhook isn't configured yet — the panel shows "not configured").
if ($_nm_username && _nm_can('copilot') && is_file(__DIR__ . '/copilot_widget.php')) {
    include __DIR__ . '/copilot_widget.php';
}
?>
