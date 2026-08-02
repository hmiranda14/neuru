<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Archaeologist n8n callback. The AI flow posts enriched findings here.
//   POST ?ep=findings  {findings:[{pattern_key?, title, confidence, hypothesis,
//                                   suggested_fix, evidence?}…]}
// Auth: X-NetMon-Token (shared inbound token).
// ─────────────────────────────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/nm_n8n.php';
require_once __DIR__ . '/nm_archaeology.php';

$tok = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_SERVER['HTTP_X_API_KEY'] ?? '');
if ($tok === '' && !empty($_SERVER['HTTP_AUTHORIZATION']) && preg_match('/Bearer\s+(.+)/i',$_SERVER['HTTP_AUTHORIZATION'],$m)) $tok=trim($m[1]);
if (!nm_n8n_verify_inbound($conn,$tok)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); exit; }
nm_arch_ensure($conn);

$ep = $_GET['ep'] ?? '';
$body = json_decode(file_get_contents('php://input'), true) ?: [];

if ($ep === 'findings') {
    $list = $body['findings'] ?? [];
    $n=0;
    foreach ((array)$list as $f) {
        $title=substr((string)($f['title']??''),0,255); if($title==='') continue;
        $key=substr((string)($f['pattern_key']??('ai:'.sha1($title))),0,64);
        $conf=(int)($f['confidence']??60); $sup=(int)($f['support']??0); $lag=(float)($f['avg_lag_min']??0);
        $hyp=(string)($f['hypothesis']??''); $fix=(string)($f['suggested_fix']??''); $ev=(string)(is_array($f['evidence']??null)?json_encode($f['evidence']):($f['evidence']??''));
        // A fresh AI enrichment is an active signal → surface it (status='open'). Preserve only the
        // operator's explicit ACK; do NOT keep it 'dismissed' — otherwise a finding dismissed once
        // (e.g. while debugging the flow) can never reappear even when the AI re-sends it. Keep the
        // stat support/lag if the AI omits them (don't clobber good numbers with 0).
        $st=$conn->prepare("INSERT INTO nm_archaeology_findings (pattern_key,title,confidence,support,avg_lag_min,hypothesis,suggested_fix,evidence,source,status,updated_at)
            VALUES (?,?,?,?,?,?,?,?,'ai','open',NOW())
            ON DUPLICATE KEY UPDATE title=VALUES(title),confidence=VALUES(confidence),
                support=GREATEST(support,VALUES(support)),
                avg_lag_min=IF(VALUES(avg_lag_min)>0,VALUES(avg_lag_min),avg_lag_min),
                hypothesis=VALUES(hypothesis),suggested_fix=VALUES(suggested_fix),evidence=VALUES(evidence),
                source='ai', status=IF(status='ack','ack','open'), updated_at=NOW()");
        $st->bind_param('ssiidsss',$key,$title,$conf,$sup,$lag,$hyp,$fix,$ev); $st->execute(); $n++;
    }
    echo json_encode(['ok'=>true,'ingested'=>$n]); exit;
}
http_response_code(404); echo json_encode(['ok'=>false,'error'=>'Unknown endpoint','endpoints'=>['findings']]);
