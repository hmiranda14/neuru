<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Cluster ingest endpoint (MASTER). Machine-to-machine: a slave POSTs its
// site rollup here with X-Cluster-Site + X-Cluster-Token headers (no user session).
// Token is matched per-site against the master's registry. Only active when this
// install's role is 'master'. Engine: nm_cluster.php.
//   POST /cluster_ingest.php   headers: X-Cluster-Site, X-Cluster-Token   body: JSON rollup or {batch:[…]}
// ─────────────────────────────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_cluster.php';

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') { http_response_code(405); echo json_encode(['ok'=>false,'error'=>'POST only']); exit; }

$cfg = nm_cluster_cfg($conn);
if ($cfg['role'] !== 'master') { http_response_code(409); echo json_encode(['ok'=>false,'error'=>'this install is not a cluster master']); exit; }

$site  = (string)($_SERVER['HTTP_X_CLUSTER_SITE'] ?? '');
$token = (string)($_SERVER['HTTP_X_CLUSTER_TOKEN'] ?? '');
$raw   = file_get_contents('php://input', false, null, 0, 262144);   // 256KB cap
$body  = json_decode((string)$raw, true);
if (!is_array($body)) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'invalid JSON']); exit; }

try {
    $r = nm_cluster_ingest($conn, $site, $token, $body);
    // AUDIT-FIX: slow + log auth failures (basic brute-force resistance + visibility)
    if (empty($r['ok']) && in_array((int)($r['http'] ?? 0), [401, 403], true)) {
        usleep(400000);
        error_log('NEURU cluster ingest AUTH-FAIL site=' . preg_replace('/[^a-z0-9_-]/i','',$site) . ' ip=' . ($_SERVER['REMOTE_ADDR'] ?? '?') . ' http=' . (int)$r['http']);
    }
    http_response_code((int)($r['http'] ?? ($r['ok'] ? 200 : 400)));
    echo json_encode(['ok'=>!empty($r['ok'])]
        + (isset($r['stored']) ? ['stored'=>$r['stored']] : [])
        + (isset($r['acked']) ? ['acked'=>$r['acked']] : [])
        + (isset($r['commands']) ? ['commands'=>$r['commands']] : [])   // F3: fleet-wide commands to apply
        + (empty($r['ok']) ? ['error'=>$r['error'] ?? 'ingest failed'] : []));
} catch (\Throwable $e) {
    http_response_code(500); echo json_encode(['ok'=>false,'error'=>'ingest error']);
}
