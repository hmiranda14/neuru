<?php
// Install the global error/exception safety net before anything can fail, so DB
// or PHP fatals render a styled page (or JSON) instead of a blank white 500.
require_once __DIR__ . '/nm_errors.php';

$host     = '__DB_HOST__';
$dbname   = '__DB_NAME__';
$username = '__DB_USER__';
$password = '__DB_PASS__';

$conn = new mysqli($host, $username, $password, $dbname);
if ($conn->connect_error) {
    die('Database connection failed: ' . $conn->connect_error);
}
$conn->set_charset('utf8mb4');
// Timezone: canonical storage = UTC (PHP + MySQL session pinned); display converts
// to the user's app_timezone. Overrides any per-page date_default_timezone_set().
require_once __DIR__ . '/nm_tz.php';
nm_tz_apply($conn);
