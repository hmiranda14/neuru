<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Collective Immunity tick. Detects port-scans (syslog) + malicious DNS
// (Pi-hole logs), registers threats, and (if auto-vaccinate is on) fans the block
// out to every Pi-hole/firewall. Run every few minutes:
//   */3 * * * * curl -s -H "X-NetMon-Token: <token>" http://localhost/cron_immunity.php
// ─────────────────────────────────────────────────────────────────────────────
$IS_CLI = (PHP_SAPI === 'cli');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_immunity.php';
require __DIR__ . '/nm_n8n.php';

if (!$IS_CLI) {
    header('Content-Type: application/json; charset=utf-8');
    $cfg = nm_n8n_get($conn);
    $hdr = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
    $want = (string)($cfg['inbound_token'] ?? '');
    if ($want === '' || !hash_equals($want, (string)$hdr)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
}

if (nm_imm_setting($conn,'immunity_enabled','1') === '0') { echo $IS_CLI ? "disabled\n" : json_encode(['ok'=>true,'skipped'=>'disabled']); exit; }

$auto = nm_imm_setting($conn,'imm_auto_vaccinate','0') === '1';
$newIds = [];

if (nm_imm_setting($conn,'imm_detect_portscan','1') !== '0') {
    foreach (nm_imm_detect_portscan($conn) as $p) {
        $det = 'Port scan — '.$p['ports'].' ports'.(!empty($p['target'])?(' → '.$p['target']):'');
        $r = nm_imm_add_threat($conn, $p['ip'], 'ip', 'portscan', 'high', $det, null, $p['reported_by'] ?? '');
        if (!empty($r['new'])) $newIds[] = (int)$r['id'];
    }
}
if (nm_imm_setting($conn,'imm_detect_dns','0') === '1') {
    foreach (nm_imm_detect_dns($conn) as $d) {
        $r = nm_imm_add_threat($conn, $d, 'domain', 'dns', 'high', 'Matched DNS threat pattern');
        if (!empty($r['new'])) $newIds[] = (int)$r['id'];
    }
}

$vacc = 0;
if ($auto) foreach ($newIds as $id) { $v = nm_imm_vaccinate($conn, $id); if (!empty($v['ok'])) $vacc++; }

$res = ['new'=>count($newIds), 'auto_vaccinated'=>$vacc, 'mode'=>($auto?'auto':'review')];
echo $IS_CLI ? ("immunity: ".json_encode($res)."\n") : json_encode(['ok'=>true] + $res + ['at'=>date('c')]);
