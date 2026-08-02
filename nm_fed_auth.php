<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Federation SSO. Lets the MASTER embed a slave's NATIVE device dashboard
// (router_details / win_screen / linux_screen / ping) so it looks EXACTLY like a
// local node — without a second login.
//
// How: the master mints a short-lived HMAC-signed URL. The secret is the per-site
// push token BOTH sides already share (the slave uses it to authenticate to the
// master; the master stored it as token_enc). The slave verifies the signature
// PER REQUEST (stateless — no cross-origin cookies, which browsers block in a
// third-party iframe over HTTP) and grants READ-ONLY access: GET requests only, so
// the native page + its GET data-apis render, while every write (POST) stays blocked.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_fed_params_present')) {

    function nm_fed_params_present(): bool {
        return isset($_GET['fed_sig'], $_GET['fed_site'], $_GET['fed_exp']);
    }

    // A federation embed token authorizes ONLY these scripts (page entry points + the GET
    // data-apis they load). This keeps a token minted to view a remote site from becoming a
    // blanket GET credential for the whole portal (e.g. config_mgr's snapshot api returns
    // device running-configs WITH secrets → NEVER allowlisted). Tight by allowlist.
    //
    // Every script here has been audited: none echo a decrypted secret / password / SSH key /
    // running-config over a GET request path. Writes are POST and stay blocked by the fed
    // read-only bypass, so these render + refresh live but cannot be changed remotely.
    // The Federated Remote Console (remote_console.php) embeds exactly this set.
    function nm_fed_allowed_scripts(): array {
        return [
            // ── device command centers (original SSO set) ──
            'router_details.php', 'win_screen.php', 'windows.php',
            'linux_screen.php', 'linux.php', 'net_mon_stats.php',
            // ── the master dashboard + incident desk ──
            'net_mon.php', 'net_mon_map.php', 'incidents.php',
            // ── Monitoring group (view-only dashboards; writes are POST → blocked) ──
            'troubleshoot.php', 'live_mon.php', 'netflow.php', 'l2switch.php',
            'shadowit.php', 'health.php', 'watchdog.php', 'routers.php',
            'timetravel.php', 'chaos.php', 'sonify.php', 'wear.php',
            'sla.php', 'log_mon.php',
            // ── Command Centers (WebGL / read dashboards) ──
            'router_command.php', 'routing_command.php', 'hologram.php',
            'biosphere.php', 'dbobservatory.php', 'command.php',
            // ── AI Tools (read/insight dashboards) ──
            'ai_insights.php', 'gpu.php', 'archaeology.php',
            // ── External monitoring (read dashboards) ──
            'pihole.php', 'smokeping.php', 'weather.php', 'dbmon.php',
            // ── Reporting ──
            'reports.php',
        ];
    }
    function nm_fed_page_allowed(?string $script = null): bool {
        $s = basename((string)($script ?? ($_SERVER['SCRIPT_NAME'] ?? '')));
        return in_array($s, nm_fed_allowed_scripts(), true);
    }

    // The module catalog the Remote Console shows for a remote site: mirrors the local nav
    // ($_nm_groups in header.php) so the operator sees the WHOLE remote menu. Each item is
    // flagged `embed` = can be viewed inline now (allowlisted), else `lock` = why not yet.
    // 'action' = it mainly performs writes/executes on the device (Phase 3 remote-action
    // territory); 'secret' = it can expose credentials on GET (never embeddable, e.g.
    // config_mgr); 'admin' = local site-admin config, out of scope for a remote read console.
    function nm_fed_module_groups(): array {
        $A = nm_fed_allowed_scripts();
        $mk = function(string $file, string $icon, string $label, string $lock = '') use ($A) {
            $embed = in_array($file, $A, true);
            return ['file'=>$file, 'icon'=>$icon, 'label'=>$label, 'embed'=>$embed,
                    'lock'=>$embed ? '' : ($lock ?: 'action')];
        };
        return [
            ['name'=>'Overview', 'icon'=>'fa-solid fa-gauge-high', 'items'=>[
                $mk('net_mon.php',       'fa-solid fa-chart-line',       'Dashboard'),
                $mk('incidents.php',     'fa-solid fa-triangle-exclamation','Incidents'),
                $mk('net_mon_map.php',   'fa-solid fa-diagram-project',  'Topology Map'),
            ]],
            ['name'=>'Monitoring', 'icon'=>'fa-solid fa-gauge-high', 'items'=>[
                $mk('troubleshoot.php',  'fa-solid fa-stethoscope',      'Troubleshoot Wizard'),
                $mk('live_mon.php',      'fa-solid fa-tower-broadcast',  'Live'),
                $mk('net_mon_stats.php', 'fa-solid fa-chart-bar',        'Stats'),
                $mk('netflow.php',       'fa-solid fa-chart-area',       'NetFlow'),
                $mk('l2switch.php',      'fa-solid fa-ethernet',         'Unmanaged Switches'),
                $mk('shadowit.php',      'fa-solid fa-user-secret',      'Shadow IT'),
                $mk('health.php',        'fa-solid fa-heart-pulse',      'Predictive Health'),
                $mk('windows.php',       'fa-brands fa-windows',         'Windows Monitor'),
                $mk('linux.php',         'fa-brands fa-linux',           'Linux Monitor'),
                $mk('watchdog.php',      'fa-solid fa-shield-heart',     'Service Watchdog'),
                $mk('routers.php',       'fa-solid fa-route',            'Router Monitor'),
                $mk('timetravel.php',    'fa-solid fa-clock-rotate-left','Time-Travel'),
                $mk('chaos.php',         'fa-solid fa-burst',            'Chaos Test'),
                $mk('sonify.php',        'fa-solid fa-satellite-dish',   'Network Sonar'),
                $mk('wear.php',          'fa-solid fa-heart-crack',      'Wear & Stress'),
                $mk('sla.php',           'fa-solid fa-heart-pulse',      'SLA Live Center'),
                $mk('log_mon.php',       'fa-solid fa-file-lines',       'Logs'),
            ]],
            ['name'=>'Command Centers', 'icon'=>'fa-solid fa-satellite-dish', 'items'=>[
                $mk('command.php',        'fa-solid fa-satellite-dish',  'Command Center'),
                $mk('router_command.php', 'fa-solid fa-route',           'Router Command Center'),
                $mk('routing_command.php','fa-solid fa-diagram-project', 'Routing Command Center'),
                $mk('hologram.php',       'fa-solid fa-cube',            'Traffic Hologram'),
                $mk('biosphere.php',      'fa-solid fa-dna',             'Service Biosphere'),
                $mk('dbobservatory.php',  'fa-solid fa-satellite',       'DB Observatory'),
                $mk('aiopilot.php',       'fa-solid fa-robot',           'AI Command Center', 'action'),
            ]],
            ['name'=>'AI Tools', 'icon'=>'fa-solid fa-brain', 'items'=>[
                $mk('ai_insights.php',    'fa-solid fa-wand-magic-sparkles','AI Insights'),
                $mk('gpu.php',            'fa-solid fa-microchip',       'AI / GPU Monitor'),
                $mk('archaeology.php',    'fa-solid fa-magnifying-glass-chart','AI Archaeologist'),
            ]],
            ['name'=>'External Monitoring', 'icon'=>'fa-solid fa-satellite-dish', 'items'=>[
                $mk('pihole.php',         'fa-solid fa-shield-halved',   'Pi-hole'),
                $mk('smokeping.php',      'fa-solid fa-wave-square',     'Smokeping'),
                $mk('dbmon.php',          'fa-solid fa-database',        'Data Core (DBs)'),
                $mk('weather.php',        'fa-solid fa-hurricane',       'Weather Routing'),
                $mk('containers.php',     'fa-brands fa-docker',         'Containers', 'action'),
            ]],
            ['name'=>'Reporting', 'icon'=>'fa-solid fa-file-lines', 'items'=>[
                $mk('reports.php',        'fa-solid fa-gauge-high',      'SLA & Reports'),
            ]],
            ['name'=>'Device Tools', 'icon'=>'fa-solid fa-network-wired', 'items'=>[
                $mk('mtfw.php',           'fa-solid fa-shield-halved',   'MikroTik Device Manager', 'action'),
                $mk('wireguard.php',      'fa-solid fa-shield-halved',   'WireGuard Orchestrator', 'action'),
                $mk('router_commander.php','fa-solid fa-network-wired',  'Adv. Solution Commander', 'action'),
                $mk('config_mgr.php',     'fa-solid fa-file-shield',     'Config Manager', 'secret'),
            ]],
            ['name'=>'Healing & Security', 'icon'=>'fa-solid fa-shield-heart', 'items'=>[
                $mk('immunity.php',       'fa-solid fa-shield-virus',    'Collective Immunity', 'action'),
                $mk('heal.php',           'fa-solid fa-robot',           'Self-Healing', 'action'),
                $mk('deception.php',      'fa-solid fa-mask',            'Deception Grid', 'action'),
            ]],
        ];
    }

    // SLAVE side — validate the incoming request. Returns ['site','ro','embed','exp'] or null.
    function nm_fed_request_auth($conn): ?array {
        $site = (string)($_GET['fed_site'] ?? '');
        $exp  = (int)($_GET['fed_exp'] ?? 0);
        $sig  = (string)($_GET['fed_sig'] ?? '');
        if ($site === '' || $sig === '' || $exp <= 0 || $exp < time()) return null;   // missing / expired
        if (!function_exists('nm_cluster_cfg')) { $f = __DIR__ . '/nm_cluster.php'; if (is_file($f)) require_once $f; }
        if (!function_exists('nm_cluster_cfg')) return null;
        $cfg = nm_cluster_cfg($conn);
        if ((string)($cfg['site_slug'] ?? '') !== $site) return null;                 // not minted for THIS install
        $secret = function_exists('nm_cluster_my_token_get') ? nm_cluster_my_token_get($conn) : '';
        if ($secret === '') return null;
        $calc = hash_hmac('sha256', "fed:$site:$exp", $secret);
        if (!hash_equals($calc, $sig)) return null;
        return ['site'=>$site, 'ro'=>true, 'embed'=>!empty($_GET['embed']), 'exp'=>$exp];
    }

    // Is the CURRENT request an authorized federated read-only embed? (set by check.php)
    function nm_fed_active(): bool { return !empty($GLOBALS['_NM_FED']); }

    // MASTER side — the per-site shared secret as the master stored it (decrypt; needs www-data).
    function nm_fed_site_secret($conn, string $slug): string {
        $r = @$conn->query("SELECT token_enc FROM nm_cluster_sites WHERE site_slug='" . $conn->real_escape_string($slug) . "' LIMIT 1");
        $enc = ($r && $r->num_rows) ? ($r->fetch_assoc()['token_enc'] ?? '') : '';
        return ($enc && function_exists('nm_secret_decrypt')) ? (string)nm_secret_decrypt($enc) : '';
    }

    // MASTER side — build a signed embed URL into a slave's native page.
    // $relPath e.g. "router_details.php?node=7". '' if the site has no URL or token.
    function nm_fed_master_embed_url($conn, string $slug, string $relPath, int $ttl = 1800): string {
        if ($relPath === '') return '';
        if (!function_exists('nm_cluster_sites')) { $f = __DIR__ . '/nm_cluster.php'; if (is_file($f)) require_once $f; }
        $ep = '';
        foreach (nm_cluster_sites($conn) as $s) if ($s['site'] === $slug) { $ep = rtrim((string)$s['endpoint'], '/'); break; }
        if ($ep === '') return '';
        $secret = nm_fed_site_secret($conn, $slug);
        if ($secret === '') return '';
        $exp = time() + max(60, $ttl);
        $sig = hash_hmac('sha256', "fed:$slug:$exp", $secret);
        $sep = (strpos($relPath, '?') !== false) ? '&' : '?';
        return $ep . '/' . ltrim($relPath, '/') . $sep . 'embed=1&fed_site=' . rawurlencode($slug) . '&fed_exp=' . $exp . '&fed_sig=' . $sig;
    }

    // Injected into embedded pages: propagate the fed params onto same-origin GET fetches
    // so the native page's data-apis stay authorized (no cookies needed). Writes are POST
    // and are intentionally NOT propagated → they stay blocked.
    function nm_fed_embed_script(): string {
        // In an embedded (SSO iframe) render, propagate the fed auth params (fed_site/exp/sig,
        // which sign slug:exp — NOT the path, so they're valid for EVERY page until expiry) onto:
        //   1) same-origin GET fetch   2) <a href> link navigations   3) GET form submits
        // Without this, clicking a link inside the iframe drops the params → the slave bounces to
        // login → login sends X-Frame-Options → the browser refuses to frame it ("Can't Open This Page").
        $allow = json_encode(array_values(nm_fed_allowed_scripts()));
        return <<<JS
<script>(function(){
  var m=/(?:[?&])(fed_site=[^&]+&fed_exp=[^&]+&fed_sig=[^&]+)/.exec(location.search);
  if(!m)return; var fp=m[1];
  var ALLOW=$allow;                                   // pages that CAN render inside the console
  var SELF=(location.pathname.split("/").pop()||"").toLowerCase();
  function rel(u){ return typeof u==="string" && u!=="" && !/^(https?:)?\/\//i.test(u)
      && u.charAt(0)!=="#" && !/^(mailto:|tel:|javascript:)/i.test(u); }
  function needs(u){ return rel(u) && u.indexOf("fed_sig=")<0; }
  function withFp(u){ return u + (u.indexOf("?")>=0?"&":"?") + fp; }
  function scriptOf(u){ try{ var b=(u.split("#")[0].split("?")[0].split("/").pop()||"").toLowerCase(); return /\.php$/.test(b)?b:""; }catch(e){ return ""; } }
  // A relative link is embeddable if it targets THIS page, an allowlisted page, or is a
  // same-page query/api (no .php basename). Non-allowlisted pages (net_mon_config, etc.) are
  // NOT — navigating the iframe there bounces to the slave login → X-Frame-Options → the
  // "Firefox Can't Open This Page" error. We neutralize those with a read-only explanation.
  function embeddable(u){ var s=scriptOf(u); return s===""||s===SELF||ALLOW.indexOf(s)>=0; }
  // 1) same-origin GET fetch + XHR — carry fed params so data-apis authorize
  var of=window.fetch; window.fetch=function(u,o){ try{ if(needs(u)&&(!o||!o.method||String(o.method).toUpperCase()==="GET")) u=withFp(u); }catch(e){} return of.call(this,u,o); };
  try{ var ox=XMLHttpRequest.prototype.open; XMLHttpRequest.prototype.open=function(method,url){ try{ if((!method||String(method).toUpperCase()==="GET")&&needs(url)) url=withFp(url); }catch(e){} return ox.apply(this,[method,url].concat([].slice.call(arguments,2))); }; }catch(e){}
  // 2) links: embeddable → keep authed inline; non-embeddable config pages → neutralize + explain
  function fixLink(a){ var h=a.getAttribute("href"); if(!rel(h)) return;
    if(embeddable(h)){ if(needs(h)) a.setAttribute("href",withFp(h)); return; }
    if(a.__fedBlocked) return; a.__fedBlocked=1;
    a.setAttribute("title","This opens the site's own configuration — the Remote Console is read-only.");
    a.style.opacity="0.6"; a.style.cursor="not-allowed";
    a.addEventListener("click",function(e){ e.preventDefault(); e.stopPropagation();
      alert("“"+(scriptOf(h)||"That page")+"” is the site's own configuration page.\\n\\nThe Remote Console is read-only — to change settings, open that page directly on the site itself."); },true);
  }
  function fixNode(n){ if(!n||n.nodeType!==1)return;
    if(n.matches&&n.matches("a[href]")) fixLink(n);
    if(n.querySelectorAll){ var as=n.querySelectorAll("a[href]"); for(var i=0;i<as.length;i++) fixLink(as[i]); }
  }
  function fixAll(){ fixNode(document.body||document.documentElement); }
  if(document.readyState==="loading") document.addEventListener("DOMContentLoaded",fixAll); else fixAll();
  try{ new MutationObserver(function(ms){ for(var j=0;j<ms.length;j++){ var ad=ms[j].addedNodes; for(var k=0;k<ad.length;k++) fixNode(ad[k]); } }).observe(document.documentElement,{childList:true,subtree:true}); }catch(e){}
  // 3) GET forms → carry fed params (only when the target page is embeddable)
  document.addEventListener("submit",function(e){ var f=e.target; if(!f||(f.method&&f.method.toUpperCase()!=="GET"))return;
    var act=f.getAttribute("action")||""; if(/^(https?:)?\/\//i.test(act))return; if(!embeddable(act))return;
    fp.split("&").forEach(function(kv){ var p=kv.split("="); if(!p[0]||f.querySelector('[name="'+p[0]+'"]'))return;
      var inp=document.createElement("input"); inp.type="hidden"; inp.name=p[0]; inp.value=decodeURIComponent(p[1]||""); f.appendChild(inp); }); }, true);
})();</script>
JS;
    }
}
