<?php
// NEURU — detached backup-job runner. Executes ONE queued backup so the web request
// that created it returns instantly. Invoked as:  php nm_vault_runjob.php <id>
// (passphrase, if any, arrives via the NMV_PASS env so it never hits the process list).
if (PHP_SAPI !== 'cli') { http_response_code(403); exit; }
$id = (int)($argv[1] ?? 0);
if ($id <= 0) { fwrite(STDERR, "usage: nm_vault_runjob.php <backup_id>\n"); exit(2); }
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_vault.php';
require __DIR__ . '/nm_vault_backup.php';
@set_time_limit(0);
$pass = getenv('NMV_PASS') ?: '';
$r = nm_vault_backup_run($conn, $id, $pass);
fwrite(STDOUT, json_encode($r) . "\n");
