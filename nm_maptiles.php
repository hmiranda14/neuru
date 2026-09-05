<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — shared basemap tile provider. CARTO's dark_all tiles began demanding an
// API key (2026), watermarking every map. This centralizes the Leaflet basemap so
// ALL map pages (command.php, federation.php geowall, geomap.php, weather.php,
// nettrace.php, net_mon_config preview) share ONE provider, keyless by default,
// and the operator can switch it in Config without touching code.
//
// Default: Esri "World Dark Gray Base" — keyless, real dark tiles (verified 200 /
// image, no key). Presets also include Esri Imagery (satellite), OSM (+ optional
// CSS dark-filter), and CARTO (only if the operator supplies a key via 'custom').
//
// Usage in a page (with $conn in scope, Leaflet loaded):
//     require_once __DIR__.'/nm_maptiles.php';
//     echo nm_map_tile_css($conn);      // once, in <head>/<body> (empty unless a filter preset)
//     echo nm_map_tile_js($conn) . '.addTo(map);';   // replaces the old L.tileLayer(...)
// ─────────────────────────────────────────────────────────────────────────────

if (!function_exists('nm_map_tile_cfg')) {

    function nm_map_tile_cfg($conn): array {
        $g = function($k, $d='') use ($conn) {
            if (!($conn instanceof mysqli)) return $d;
            $r = @$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1");
            return ($r && ($x = $r->fetch_row()) && $x[0] !== null && $x[0] !== '') ? (string)$x[0] : $d;
        };
        $prov = $g('map_provider', 'esri_dark');

        // Keyless presets (except 'custom'/carto-with-key). {r}=retina, {s}=subdomain.
        // NOTE the Esri tile order is {z}/{y}/{x} (y before x) and has NO {s}.
        $P = [
            'esri_dark' => [
                'url' => 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}',
                'sub' => '', 'maxnative' => 16, 'filter' => false,
                'attr' => 'Tiles &copy; Esri &mdash; Esri, HERE, Garmin, &copy; OpenStreetMap contributors',
            ],
            'esri_imagery' => [
                'url' => 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
                'sub' => '', 'maxnative' => 18, 'filter' => false,
                'attr' => 'Tiles &copy; Esri &mdash; Source: Esri, Maxar, Earthstar Geographics',
            ],
            'osm_dark' => [   // keyless, made dark with a CSS filter (see nm_map_tile_css)
                'url' => 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
                'sub' => 'abc', 'maxnative' => 19, 'filter' => true,
                'attr' => '&copy; OpenStreetMap contributors',
            ],
            'osm' => [
                'url' => 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
                'sub' => 'abc', 'maxnative' => 19, 'filter' => false,
                'attr' => '&copy; OpenStreetMap contributors',
            ],
            'carto' => [      // legacy — now needs a key; keep for operators who buy one (via 'custom')
                'url' => 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
                'sub' => 'abcd', 'maxnative' => 19, 'filter' => false,
                'attr' => '&copy; OpenStreetMap, &copy; CARTO',
            ],
        ];
        $c = $P[$prov] ?? $P['esri_dark'];

        // 'custom' = operator supplies their own URL/attr (e.g. a CARTO/Mapbox key baked in).
        if ($prov === 'custom') {
            $c = [
                'url'       => $g('map_tile_url', $P['esri_dark']['url']),
                'sub'       => $g('map_tile_sub', ''),
                'maxnative' => (int)($g('map_tile_maxnative', '19')) ?: 19,
                'filter'    => $g('map_tile_filter', '0') === '1',
                'attr'      => $g('map_tile_attr', '&copy; map'),
            ];
        }
        $c['provider'] = $prov;
        return $c;
    }

    // A ready-to-chain Leaflet expression: L.tileLayer(url, opts). Add .addTo(map) after it.
    // For a filter preset (osm_dark) it self-injects the dark-filter CSS once, so a single
    // call site works everywhere with no extra <style> needed on the page.
    function nm_map_tile_js($conn): string {
        $c = nm_map_tile_cfg($conn);
        $opts = ['maxZoom' => 19, 'maxNativeZoom' => $c['maxnative']];
        if ($c['sub'] !== '')       $opts['subdomains'] = $c['sub'];
        if (!empty($c['filter']))   $opts['className']   = 'nm-tile-dark';
        $opts['attribution'] = $c['attr'];
        $layer = 'L.tileLayer(' . json_encode($c['url'], JSON_UNESCAPED_SLASHES)
               . ',' . json_encode($opts, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . ')';
        if (empty($c['filter'])) return $layer;
        // Wrap so the CSS is guaranteed present before the layer renders (chainable IIFE).
        $rule = '.nm-tile-dark{filter:invert(1) hue-rotate(180deg) brightness(.92) contrast(.9) saturate(.6);}';
        return "(function(){if(!document.getElementById('nm-tile-dark-css')){var s=document.createElement('style');s.id='nm-tile-dark-css';s.textContent=" . json_encode($rule, JSON_UNESCAPED_SLASHES) . ";document.head.appendChild(s);}return " . $layer . ";})()";
    }

    // One-time <style> for the osm_dark CSS filter. Returns '' for non-filter presets,
    // so it is safe to emit on every map page.
    function nm_map_tile_css($conn): string {
        $c = nm_map_tile_cfg($conn);
        if (empty($c['filter'])) return '';
        return '<style id="nm-tile-dark-css">.nm-tile-dark{filter:invert(1) hue-rotate(180deg) brightness(.92) contrast(.9) saturate(.6);}</style>';
    }
}
