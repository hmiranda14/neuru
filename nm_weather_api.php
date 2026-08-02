<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Weather n8n callback. n8n pulls node geo, queries a weather API per
// point, and posts active alerts back.
//   GET  ?ep=nodes    → {nodes:[{id,name,lat,lon,link_type}]}
//   POST ?ep=alerts   {alerts:[{ext_id?,node_id?|lat/lon/radius_km,event,severity,headline,effective,expires}]}
// Auth: X-NetMon-Token.
// ─────────────────────────────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/nm_n8n.php';
require_once __DIR__ . '/nm_weather.php';

$tok = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_SERVER['HTTP_X_API_KEY'] ?? '');
if ($tok === '' && !empty($_SERVER['HTTP_AUTHORIZATION']) && preg_match('/Bearer\s+(.+)/i',$_SERVER['HTTP_AUTHORIZATION'],$m)) $tok=trim($m[1]);
if (!nm_n8n_verify_inbound($conn,$tok)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
nm_wx_ensure($conn);

$ep = $_GET['ep'] ?? '';
if ($ep === 'nodes') { echo json_encode(['ok'=>true,'nodes'=>nm_wx_nodes_geo($conn)]); exit; }
if ($ep === 'alerts') {
    $body = json_decode(file_get_contents('php://input'), true) ?: [];
    $alerts = $body['alerts'] ?? (isset($body['event'])?[$body]:[]);
    echo json_encode(['ok'=>true] + nm_wx_ingest($conn,(array)$alerts)); exit;
}
http_response_code(404); echo json_encode(['ok'=>false,'error'=>'Unknown endpoint','endpoints'=>['nodes','alerts']]);
