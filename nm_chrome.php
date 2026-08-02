<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — shared page chrome. Canonical look-and-feel lifted from net_mon.php so
// the Containers module (and any new page) matches the rest of the portal: the
// glassy "bento" header bar (glowing accent strip + status pill + orbit icon) and
// the pill-style tab row. Functions only — including this file emits nothing.
//
//   echo nm_chrome_css();                       // inside a page's <style> block
//   nm_page_header($main,$thin,$pill,$icon,$r); // the header bar (in <body>)
//   nm_module_tabs($tabs);                      // the pill tab row
// ─────────────────────────────────────────────────────────────────────────────

if (!function_exists('nm_chrome_css')) {

    // ── NEURU brand mark ──────────────────────────────────────────────────────
    // Proprietary neural-network emblem (inline SVG, themes to the portal gradient).
    // Unique gradient ids per call so multiple instances on a page don't collide.
    $GLOBALS['_neuru_uid'] = $GLOBALS['_neuru_uid'] ?? 0;
    function nm_logo_svg(int $size = 28): string {
        $u = ++$GLOBALS['_neuru_uid'];
        $s = $size;
        return '<svg class="neuru-mark" width="'.$s.'" height="'.$s.'" viewBox="0 0 48 48" fill="none" '
          .'xmlns="http://www.w3.org/2000/svg" role="img" aria-label="NEURU" style="display:inline-block;vertical-align:middle;">'
          .'<defs>'
          .'<linearGradient id="ng'.$u.'" x1="4" y1="4" x2="44" y2="44" gradientUnits="userSpaceOnUse">'
          .'<stop stop-color="#38bdf8"/><stop offset=".55" stop-color="#4da3ff"/><stop offset="1" stop-color="#7c5cff"/>'
          .'</linearGradient>'
          .'<radialGradient id="ngl'.$u.'" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" '
          .'gradientTransform="translate(24 24) scale(10)"><stop stop-color="#7cc4ff" stop-opacity=".9"/>'
          .'<stop offset="1" stop-color="#7cc4ff" stop-opacity="0"/></radialGradient></defs>'
          .'<circle cx="24" cy="24" r="22" stroke="url(#ng'.$u.')" stroke-width="1.6" opacity=".9"/>'
          .'<circle cx="24" cy="24" r="16.5" stroke="url(#ng'.$u.')" stroke-width="1" stroke-dasharray="2 4" opacity=".35"/>'
          .'<g stroke="url(#ng'.$u.')" stroke-width="1" opacity=".55">'
          .'<line x1="13" y1="17" x2="24" y2="14"/><line x1="13" y1="17" x2="24" y2="24"/>'
          .'<line x1="13" y1="24" x2="24" y2="14"/><line x1="13" y1="24" x2="24" y2="24"/><line x1="13" y1="24" x2="24" y2="34"/>'
          .'<line x1="13" y1="31" x2="24" y2="24"/><line x1="13" y1="31" x2="24" y2="34"/>'
          .'<line x1="24" y1="14" x2="35" y2="19"/><line x1="24" y1="24" x2="35" y2="19"/>'
          .'<line x1="24" y1="24" x2="35" y2="29"/><line x1="24" y1="34" x2="35" y2="29"/></g>'
          .'<circle cx="24" cy="24" r="9" fill="url(#ngl'.$u.')"/>'
          .'<g fill="url(#ng'.$u.')">'
          .'<circle cx="13" cy="17" r="2"/><circle cx="13" cy="24" r="2"/><circle cx="13" cy="31" r="2"/>'
          .'<circle cx="24" cy="14" r="2"/><circle cx="24" cy="34" r="2"/>'
          .'<circle cx="35" cy="19" r="2"/><circle cx="35" cy="29" r="2"/></g>'
          .'<circle cx="24" cy="24" r="3.2" fill="#bfe2ff"/></svg>';
    }

    // Brand lockup: emblem + "NEURU" gradient wordmark (+ optional tagline).
    function nm_brand_html(int $mark = 30, bool $tagline = false, int $word = 22): string {
        $h = '<span class="neuru-brand" style="display:inline-flex;align-items:center;gap:10px;">'
           . nm_logo_svg($mark)
           . '<span style="display:inline-flex;flex-direction:column;line-height:1;">'
           . '<span class="neuru-word" style="font-size:'.$word.'px;">NEURU</span>';
        if ($tagline) $h .= '<span class="neuru-tag" style="font-size:'.max(8,(int)round($word*0.42)).'px;">Neural Network Monitor</span>';
        $h .= '</span></span>';
        return $h;
    }

    // CSS for the wordmark — include once per page (added to nm_chrome_css()).
    function nm_brand_css(): string {
        return '.neuru-word{font-weight:800;letter-spacing:3px;background:linear-gradient(90deg,#38bdf8,#6f8bff 55%,#9b6cff);'
             .'-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;color:transparent;}'
             .'.neuru-tag{margin-top:4px;color:#7c93b3;letter-spacing:2.5px;text-transform:uppercase;font-weight:600;}';
    }

    // Canonical CSS (no <style> wrapper) — drop into a page's existing <style>.
    // Call it LAST so the .wrap width override wins over the page's own rule.
    function nm_chrome_css(): string {
        return <<<CSS
/* ── NetMon shared chrome (matches net_mon.php) ───────────────────────────── */
.wrap, .page-wrapper{ max-width:1600px; margin:0 auto; }
.nav-header{ display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; }
.modern-header-container{ flex-grow:1; }
.bento-glass-card-header{ background:rgba(255,255,255,0.05); backdrop-filter:blur(15px); border:1px solid rgba(255,255,255,0.1); border-radius:20px; padding:15px 25px; display:flex; justify-content:space-between; align-items:center; position:relative; overflow:hidden; gap:16px; }
.visual-accent{ position:absolute; top:0; left:0; width:4px; height:100%; background:var(--accent,#4da3ff); box-shadow:0 0 15px var(--accent,#4da3ff); }
.content-left{ min-width:0; }
.status-pill{ display:inline-flex; align-items:center; gap:8px; background:rgba(77,163,255,0.1); color:var(--accent,#4da3ff); padding:4px 12px; border-radius:20px; font-size:11px; font-weight:bold; text-transform:uppercase; letter-spacing:1px; margin-bottom:6px; }
.pulse-dot{ width:6px; height:6px; background:var(--accent,#4da3ff); border-radius:50%; animation:nmpulse 2s infinite; }
.main-title{ margin:0; font-size:26px; letter-spacing:-1px; font-weight:700; color:#fff; }
.main-title i{ color:var(--accent,#4da3ff); margin-right:8px; }
.header-meta{ font-size:11px; color:#888; }
.refresh-bar{ display:flex; align-items:center; gap:10px; font-size:12px; color:#aaa; flex-wrap:wrap; }
.refresh-btn{ background:rgba(77,163,255,0.15); border:1px solid var(--accent,#4da3ff); color:var(--accent,#4da3ff); padding:6px 14px; border-radius:8px; cursor:pointer; font-size:12px; font-weight:600; display:inline-flex; align-items:center; gap:6px; transition:0.2s; text-decoration:none; }
.refresh-btn:hover{ background:var(--accent,#4da3ff); color:#000; }
.icon-right .orbit-container{ position:relative; width:50px; height:50px; display:flex; align-items:center; justify-content:center; }
.orbit-path{ position:absolute; width:100%; height:100%; border:1px dashed rgba(77,163,255,0.3); border-radius:50%; animation:nmrotate 10s linear infinite; }
.rotation-core{ font-size:20px; color:var(--accent,#4da3ff); animation:nmrotate 3s linear infinite; }
@keyframes nmpulse{ 0%{ box-shadow:0 0 0 0 rgba(77,163,255,0.7); } 70%{ box-shadow:0 0 0 10px rgba(77,163,255,0); } 100%{ box-shadow:0 0 0 0 rgba(77,163,255,0); } }
@keyframes nmrotate{ from{ transform:rotate(0deg); } to{ transform:rotate(360deg); } }
/* pill tab row (replaces the old underline subnav) */
.nm-tabs{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:18px; }
.nm-tab{ background:rgba(255,255,255,0.05); border:1px solid var(--border,rgba(255,255,255,0.15)); color:#aaa; padding:7px 15px; border-radius:8px; cursor:pointer; font-size:12px; font-weight:600; transition:0.2s; text-decoration:none; display:inline-flex; align-items:center; gap:7px; }
.nm-tab:hover{ background:rgba(77,163,255,0.12); color:#fff; }
.nm-tab.is-active{ background:var(--accent,#4da3ff); color:#000; border-color:transparent; }
@media(max-width:760px){ .bento-glass-card-header{ flex-wrap:wrap; } .icon-right{ display:none; } }
CSS
        . "\n" . nm_brand_css();
    }

    // The glassy bento header bar.
    //   $main  bold title text (may contain an <i> icon)
    //   $thin  lighter-weight trailing word (e.g. "Monitor"); '' to omit
    //   $pill  status-pill label (e.g. "Container Operations")
    //   $icon  Font Awesome class for the orbit icon (e.g. 'fa-brands fa-docker')
    //   $right raw HTML for the middle action bar (clock, toggles, buttons); '' to omit
    function nm_page_header(string $main, string $thin = '', string $pill = '', string $icon = 'fa-brands fa-docker', string $right = ''): void {
        $thinHtml = $thin !== '' ? ' <span style="font-weight:300;">'.$thin.'</span>' : '';
        echo '<header class="nav-header"><div class="modern-header-container">';
        echo '<div class="bento-glass-card-header"><div class="visual-accent"></div>';
        echo '<div class="content-left">';
        if ($pill !== '') echo '<div class="status-pill"><span class="pulse-dot"></span> '.$pill.'</div>';
        echo '<h1 class="main-title">'.$main.$thinHtml.'</h1></div>';
        if ($right !== '') echo '<div class="refresh-bar" style="margin:0 14px;">'.$right.'</div>';
        echo '<div class="icon-right"><div class="orbit-container"><div class="orbit-path"></div><i class="'.$icon.' rotation-core"></i></div></div>';
        echo '</div></div></header>';
    }

    // Pill tab row. $tabs = [['href'=>'..','icon'=>'fas fa-..','label'=>'..','active'=>bool], ...]
    function nm_module_tabs(array $tabs): void {
        echo '<div class="nm-tabs">';
        foreach ($tabs as $t) {
            $cls = 'nm-tab'.(!empty($t['active']) ? ' is-active' : '');
            $ic  = !empty($t['icon']) ? '<i class="'.htmlspecialchars($t['icon']).'"></i> ' : '';
            echo '<a class="'.$cls.'" href="'.htmlspecialchars($t['href']).'">'.$ic.htmlspecialchars($t['label']).'</a>';
        }
        echo '</div>';
    }

    // The standard Containers-module tab set, with one marked active.
    //   $active  one of: overview|detail|stats|volumes|logs|errors|knowledge
    //   $envq    optional query suffix for the containers.php view links (e.g. "&endpoint=3")
    function nm_container_tabs(string $active, string $envq = ''): void {
        $views = [
            'overview'=>['fas fa-table-cells-large','Overview','containers.php?view=overview'.$envq],
            'detail'  =>['fas fa-cube','Detail','containers.php?view=detail'.$envq],
            'stats'   =>['fas fa-chart-line','Stats','containers.php?view=stats'.$envq],
            'network' =>['fas fa-gauge-high','Network','containers.php?view=network'.$envq],
            'images'  =>['fas fa-layer-group','Images','containers.php?view=images'.$envq],
            'volumes' =>['fas fa-hard-drive','Volumes','containers.php?view=volumes'.$envq],
            'logs'    =>['fas fa-file-lines','Logs','container_logs.php'],
            'errors'  =>['fas fa-triangle-exclamation','Errors','container_errors.php'],
            'fix'     =>['fas fa-wand-magic-sparkles','Solution Commander','container_fix.php'],
            'knowledge'=>['fas fa-book','Knowledge','container_kb.php'],
        ];
        $tabs = [];
        foreach ($views as $k=>$v) $tabs[] = ['icon'=>$v[0],'label'=>$v[1],'href'=>$v[2],'active'=>($k===$active)];
        nm_module_tabs($tabs);
    }

    // Floating "◈ Gamers Hub" back-pill. Every gaming page echoes this right after
    // the header so a player can always warp back to the hub. Fixed, top-right,
    // out of the way; neon glass to match the gaming look. Universal (no hardcoding).
    function nm_gamers_hub_pill(): void {
        echo '<a href="game_hub.php" class="nm-ghub-pill" title="Back to Gamers Hub">'
           . '<i class="fa-solid fa-gamepad"></i><span>Gamers Hub</span></a>'
           . '<style>'
           . '.nm-ghub-pill{position:fixed;top:70px;right:18px;z-index:60;display:inline-flex;align-items:center;gap:9px;'
           . 'padding:9px 15px 9px 13px;border-radius:999px;text-decoration:none;font:800 13px/1 "Segoe UI",Tahoma,sans-serif;'
           . 'letter-spacing:.3px;color:#dbe9ff;background:linear-gradient(120deg,rgba(24,32,58,.82),rgba(40,26,66,.82));'
           . 'border:1px solid rgba(120,150,255,.34);box-shadow:0 4px 22px rgba(80,120,255,.28),inset 0 0 18px rgba(120,150,255,.08);'
           . 'backdrop-filter:blur(9px);-webkit-backdrop-filter:blur(9px);transition:transform .18s ease,box-shadow .18s ease,border-color .18s ease;}'
           . '.nm-ghub-pill i{color:#b06bff;font-size:14px;filter:drop-shadow(0 0 6px rgba(176,107,255,.8));}'
           . '.nm-ghub-pill:hover{transform:translateY(-2px) scale(1.04);border-color:rgba(176,107,255,.7);'
           . 'box-shadow:0 8px 30px rgba(150,90,255,.5),inset 0 0 22px rgba(150,110,255,.18);}'
           . '@media(max-width:640px){.nm-ghub-pill span{display:none;}.nm-ghub-pill{padding:10px 12px;}}'
           . '</style>';
    }
}
