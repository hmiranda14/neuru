<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — global error/exception safety net.
//
// mysqli runs in throw-on-error mode (PHP 8.1+ default), and the portal had NO
// global handler — so any uncaught DB/PHP error produced a blank white 500 with
// no message and (often) no log. This installs:
//   • set_exception_handler     → uncaught Throwable
//   • register_shutdown_function → fatal PHP errors (E_ERROR/E_PARSE/…)
// Both log full detail (file:line + request URI) and show the user a styled page
// (or a JSON envelope for API/AJAX calls) carrying a short error id, instead of a
// blank screen. Included once, as early as possible, from connection.php.
//
// Must NOT depend on $conn (the DB may be exactly what failed).
// ─────────────────────────────────────────────────────────────────────────────
if (!defined('NM_ERRORS_LOADED')) {
    define('NM_ERRORS_LOADED', 1);

    // Is this an API/AJAX request that expects JSON rather than an HTML page?
    function nm_err_is_json(): bool {
        if (!empty($_GET['api']) || !empty($_POST['action']) || !empty($_GET['ep'])) return true;
        if (stripos($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') !== false) return true;
        if (strcasecmp($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '', 'XMLHttpRequest') === 0) return true;
        foreach (headers_list() as $h) if (stripos($h, 'Content-Type: application/json') !== false) return true;
        return false;
    }

    function nm_err_eid(): string { return substr(md5(uniqid('', true)), 0, 8); }

    function nm_err_log(string $type, string $msg, string $file, int $line, string $eid): void {
        $uri   = $_SERVER['REQUEST_URI'] ?? ($_SERVER['SCRIPT_NAME'] ?? 'cli');
        $entry = sprintf('[%s] NEURU %s eid=%s %s in %s:%d (%s)',
            date('c'), $type, $eid, $msg, $file, $line, $uri);
        error_log($entry);                                  // → PHP/container stderr (always)
        @file_put_contents(__DIR__ . '/logs/nm_error.log', $entry . "\n", FILE_APPEND);  // app log (logs/ is HTTP-denied)
    }

    function nm_err_render(string $eid): void {
        static $done = false; if ($done) return; $done = true;   // never render twice
        if (nm_err_is_json()) {
            if (!headers_sent()) { http_response_code(500); header('Content-Type: application/json; charset=utf-8'); }
            echo json_encode(['ok' => false, 'error' => 'Internal server error', 'error_id' => $eid]);
            return;
        }
        if (!headers_sent()) { http_response_code(500); header('Content-Type: text/html; charset=utf-8'); }
        echo '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
           . '<meta name="viewport" content="width=device-width, initial-scale=1.0"><title>NEURU — Error</title>'
           . '<style>*{box-sizing:border-box}body{margin:0;font-family:"Segoe UI",Tahoma,sans-serif;background:#0a0d12;'
           . 'color:#e6e9ee;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}'
           . '.b{max-width:480px;width:100%;padding:34px 38px;background:rgba(255,255,255,.05);'
           . 'border:1px solid rgba(255,255,255,.12);border-radius:16px;text-align:center;backdrop-filter:blur(14px)}'
           . '.i{font-size:44px;line-height:1;color:#e74c3c;margin-bottom:12px}h1{font-size:20px;margin:6px 0}'
           . 'p{color:#9aa3ad;font-size:13.5px;line-height:1.65;margin:8px 0}'
           . 'code{background:rgba(77,163,255,.12);padding:3px 10px;border-radius:6px;color:#cfe4ff;'
           . 'font-size:12.5px;letter-spacing:1px}a{color:#4da3ff;text-decoration:none}</style></head><body><div class="b">'
           . '<div class="i">&#9888;</div><h1>Something went wrong</h1>'
           . '<p>NEURU hit an unexpected error handling this request. It has been logged. '
           . 'If this keeps happening, share this reference with your administrator:</p>'
           . '<p><code>' . htmlspecialchars($eid) . '</code></p>'
           . '<p style="margin-top:18px"><a href="javascript:history.back()">&larr; Go back</a></p>'
           . '</div></body></html>';
    }

    set_exception_handler(function (\Throwable $e) {
        $eid = nm_err_eid();
        nm_err_log('EXCEPTION', get_class($e) . ': ' . $e->getMessage(), $e->getFile(), $e->getLine(), $eid);
        nm_err_render($eid);
    });

    register_shutdown_function(function () {
        $e = error_get_last();
        if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) {
            $eid = nm_err_eid();
            nm_err_log('FATAL', $e['message'], $e['file'], $e['line'], $eid);
            nm_err_render($eid);
        }
    });
}
