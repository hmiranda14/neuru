<?php
// NEURU — Scheduled Jobs API (feeds the "Scheduled Jobs" tab in net_mon_config.php).
//   GET  ?api=list                 -> {ok, jobs:[...]}
//   POST ?api=save {job,enabled,interval_min}
if (session_status() !== PHP_SESSION_ACTIVE) session_start();
require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/access_control.php';
require_once __DIR__ . '/nm_jobs.php';
header('Content-Type: application/json');
if (empty($_SESSION['username']) || !checkAccess($conn, 'net_mon')) { http_response_code(403); echo json_encode(['ok'=>false,'error'=>'unauthorized']); exit; }
$api = $_GET['api'] ?? ($_POST['api'] ?? 'list');
if ($api === 'list') { echo json_encode(['ok'=>true, 'jobs'=>nm_job_list($conn)]); exit; }
if ($api === 'save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $b = json_decode(file_get_contents('php://input'), true); if (!is_array($b)) $b = $_POST;
    $ok = nm_job_save($conn, (string)($b['job'] ?? ''), !empty($b['enabled']) ? 1 : 0, (int)($b['interval_min'] ?? 0));
    echo json_encode(['ok'=>$ok]); exit;
}
echo json_encode(['ok'=>false, 'error'=>'bad api']);
