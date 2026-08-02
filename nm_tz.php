<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — timezone layer. Canonical storage is UTC (the container, MySQL and the
// Python collectors all run UTC); this module pins PHP + the MySQL session to UTC
// so EVERY write and time-window query agrees, and converts to the user-chosen
// display timezone (setting `app_timezone`, default America/Puerto_Rico) only at
// the edge — PHP via nm_local()/nm_local_now(), JS via the helpers in nm_tz_js().
//
//   nm_tz_apply($conn)              — call once per request (done in connection.php)
//   nm_tz_get($conn)                — the display timezone id
//   nm_local($utc,$fmt)             — UTC db string → app-tz formatted string
//   nm_local_now($fmt)              — "now" in app tz
//   echo nm_tz_js()                 — window.NM_TZ + nmLocal()/nmClock()/nmDate()
// ─────────────────────────────────────────────────────────────────────────────

if (!function_exists('nm_tz_get')) {

    function nm_tz_get($conn = null): string {
        static $tz = null;
        if ($tz !== null) return $tz;
        $tz = 'America/Puerto_Rico';
        $conn = $conn ?: ($GLOBALS['conn'] ?? null);
        if ($conn instanceof mysqli) {
            $r = @$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='app_timezone' LIMIT 1");
            if ($r && ($x = $r->fetch_row()) && $x[0]) $tz = $x[0];
        }
        if (!in_array($tz, timezone_identifiers_list(), true)) $tz = 'America/Puerto_Rico';
        return $tz;
    }

    // Pin PHP + MySQL session to UTC (canonical storage). Overrides any per-page
    // date_default_timezone_set() because connection.php includes this last.
    function nm_tz_apply($conn = null): void {
        date_default_timezone_set('UTC');
        if ($conn instanceof mysqli) @$conn->query("SET time_zone = '+00:00'");
    }

    function nm_local($utc, string $fmt = 'Y-m-d H:i:s', $conn = null): string {
        if ($utc === null || $utc === '' || $utc === '0000-00-00 00:00:00') return '';
        try {
            $d = new DateTime((string)$utc, new DateTimeZone('UTC'));
            $d->setTimezone(new DateTimeZone(nm_tz_get($conn)));
            return $d->format($fmt);
        } catch (\Throwable $e) { return (string)$utc; }
    }

    function nm_local_now(string $fmt = 'Y-m-d H:i:s', $conn = null): string {
        $d = new DateTime('now', new DateTimeZone('UTC'));
        $d->setTimezone(new DateTimeZone(nm_tz_get($conn)));
        return $d->format($fmt);
    }

    // Client-side helpers: treat bare DB strings as UTC, render in the app tz.
    function nm_tz_js($conn = null): string {
        $tz = nm_tz_get($conn);
        return '<script>window.NM_TZ=' . json_encode($tz) . ';'
            . 'window.nmFmt=function(d,o){try{return new Intl.DateTimeFormat("en-CA",Object.assign({timeZone:window.NM_TZ,hour12:false},o)).format(d).replace(",","");}catch(e){return d.toLocaleString();}};'
            . 'window.nmLocal=function(utc,sec){if(utc==null||utc==="")return"";var s=String(utc).trim().replace(" ","T");if(!/[zZ]|[+\\-]\\d\\d:?\\d\\d$/.test(s))s+="Z";var d=new Date(s);if(isNaN(d))return String(utc);return window.nmFmt(d,{year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit"})+(sec?":"+String(new Date(d).getSeconds()).padStart(2,"0"):"");};'
            . 'window.nmTimeStr=function(utc){if(utc==null||utc==="")return"";var s=String(utc).trim().replace(" ","T");if(!/[zZ]|[+\\-]\\d\\d:?\\d\\d$/.test(s))s+="Z";var d=new Date(s);if(isNaN(d))return String(utc);return window.nmFmt(d,{hour:"2-digit",minute:"2-digit",second:"2-digit"});};'
            . 'window.nmClock=function(es){return window.nmFmt(new Date(es*1000),{hour:"2-digit",minute:"2-digit"});};'
            . 'window.nmClockS=function(es){return window.nmFmt(new Date(es*1000),{hour:"2-digit",minute:"2-digit",second:"2-digit"});};'
            . 'window.nmDate=function(es){return window.nmFmt(new Date(es*1000),{year:"numeric",month:"2-digit",day:"2-digit"});};'
            . 'window.nmAxisTs=function(utc){if(utc==null||utc==="")return utc;var s=String(utc).trim().replace(" ","T");if(!/[zZ]|[+\\-]\\d\\d:?\\d\\d$/.test(s))s+="Z";var d=new Date(s);if(isNaN(d))return utc;var p=new Intl.DateTimeFormat("en-CA",{timeZone:window.NM_TZ,year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:false}).formatToParts(d).reduce(function(a,x){a[x.type]=x.value;return a;},{});var h=(p.hour==="24"?"00":p.hour);return p.year+"-"+p.month+"-"+p.day+"T"+h+":"+p.minute+":"+p.second;};'
            . '</script>';
    }
}
