<?php
// NEURU — Data Vault maintenance. Enforces retention (chunked deletes), records DB
// size for the growth trend, runs the Size-Budget Autopilot, refreshes the stats
// cache, and (when scheduled) runs auto-backups. Runs under www-data via localhost so
// backup credential ops work. Schedule hourly (retention prune is idempotent + cheap):
//   0 * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_vault.php
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_vault.php';
require __DIR__ . '/nm_n8n.php';
$hasBackup = @include_once __DIR__ . '/nm_vault_backup.php';

header('Content-Type: application/json; charset=utf-8');
$cfg  = nm_n8n_get($conn);
$hdr  = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
$want = (string)($cfg['inbound_token'] ?? '');
if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }

@set_time_limit(600);
$out = ['ok' => true];

// 1) enforce retention (chunked — never a giant lock; ~4 min budget)
try { $out['prune'] = nm_vault_prune($conn, ['max_seconds' => 240]); } catch (\Throwable $e) { $out['prune'] = ['error' => $e->getMessage()]; }

// 2) record DB size (once/hour is plenty) for the growth trend + forecast
try { nm_vault_record_size($conn); } catch (\Throwable $e) {}

// 3) Size-Budget Autopilot (no-op unless enabled + a budget is set)
try { $out['autopilot'] = nm_vault_autopilot($conn); } catch (\Throwable $e) { $out['autopilot'] = ['error' => $e->getMessage()]; }

// 4) scheduled auto-backups (only if the Backup Vault engine is present + a schedule is due)
if ($hasBackup && function_exists('nm_vault_backup_tick')) {
    try { $out['backup'] = nm_vault_backup_tick($conn); } catch (\Throwable $e) { $out['backup'] = ['error' => $e->getMessage()]; }
}

// 5) refresh the stats cache so the cockpit loads instantly
try { nm_vault_stats_cached($conn, 0, true); } catch (\Throwable $e) {}

echo json_encode($out);
