<?php
// NEURU — cron gate endpoint. nm_cron.sh (and the Python pollers) call this before running a job:
//   GET nm_job_gate.php?job=<name>   (header X-NetMon-Token)  ->  echoes "run" or "skip"
// It stamps last_run when it says "run", so the DB-configured interval/on-off actually takes effect.
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_jobs.php';
$tok = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
$want = '';
try { $r = $conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='n8n_inbound_token' LIMIT 1"); if ($r && $r->num_rows) $want = (string)$r->fetch_assoc()['setting_val']; } catch (\Throwable $e) {}
if ($want === '' || !hash_equals($want, (string)$tok)) { http_response_code(403); echo 'skip'; exit; }  // fail-safe: unauth = skip
header('Content-Type: text/plain');
echo nm_job_should_run($conn, (string)($_GET['job'] ?? '')) ? 'run' : 'skip';
