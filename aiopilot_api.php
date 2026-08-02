<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — AI Copilot inbound API (n8n → portal). The n8n "NetAIObot" flow runs the
// ReAct loop and calls these endpoints to: log its reasoning (think), pull more
// data (tool), propose/auto-run an action (propose), and finish (finish).
// Auth: X-NetMon-Token (shared inbound token), constant-time verified.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_config.php';
require_once __DIR__ . '/connection.php';
require_once __DIR__ . '/nm_aiopilot.php';
require_once __DIR__ . '/nm_n8n.php';

header('Content-Type: application/json; charset=utf-8');

$tok = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? '');
if (!nm_n8n_verify_inbound($conn, $tok)) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'unauthorized']); exit; }

$ep  = $_GET['ep'] ?? '';
$raw = file_get_contents('php://input');
$b   = json_decode($raw, true);
if (!is_array($b)) $b = $_POST;

$sid  = (int)($b['session_id'] ?? 0);
// The session is bound to ONE device — it is authoritative. Ignore any node_id the LLM sends
// (weak/local models pass the IP, a wrong id, or nothing). This kills the "bad node → []" class.
$snode = nm_aip_session_node($conn, $sid);
$nid   = $snode ?: (int)($b['node_id'] ?? 0);

switch ($ep) {

    case 'think':   // AI shares an observation / reasoning step
        if (!$sid || !$nid) { echo json_encode(['ok'=>false,'error'=>'missing session/node']); exit; }
        $id = nm_aip_event($conn, $sid, $nid, 'think',
            substr((string)($b['title'] ?? 'Reasoning'), 0, 240),
            (string)($b['body'] ?? ''), $b['data'] ?? null);
        echo json_encode(['ok'=>true,'event_id'=>$id]);
        break;

    case 'tool':    // AI requests a READ tool (its "eyes") → returns data
        if (!$sid) { echo json_encode(['ok'=>false,'error'=>'missing session']); exit; }
        $tool = (string)($b['tool'] ?? '');
        $args = (array)($b['args'] ?? []);
        $res  = nm_aip_run_tool($conn, $nid, $tool, $args);
        // log a READABLE result (not just the empty args) so the operator sees what happened
        $cnt  = is_array($res['data'] ?? null) ? count($res['data']) : null;
        $summary = !empty($res['ok'])
            ? (!empty($res['noop']) ? 'no-op' : ($cnt !== null ? "$cnt item(s)" : 'ok'))
            : ('error: ' . substr((string)($res['error'] ?? ''), 0, 120));
        // Body = only the MEANINGFUL args (drop node_id/session_id noise the LLM tacks on).
        $shown = array_diff_key($args, ['node_id'=>1,'session_id'=>1,'node'=>1]);
        $body  = $shown ? json_encode($shown) : '';
        nm_aip_event($conn, $sid, $nid, 'observe', "Tool: $tool → $summary", $body, ['tool'=>$tool,'result'=>$summary]);
        echo json_encode($res);
        break;

    case 'propose': // AI proposes an ACTION (gated by autonomy tier + risk)
        if (!$sid || !$nid) { echo json_encode(['ok'=>false,'error'=>'missing session/node']); exit; }
        echo json_encode(nm_aip_propose_action($conn, $sid, $nid,
            (string)($b['tool'] ?? ''), (array)($b['args'] ?? []),
            (string)($b['risk'] ?? 'high'), (string)($b['reason'] ?? '')));
        break;

    case 'finish':  // AI ends the turn/session with a summary
        if (!$sid) { echo json_encode(['ok'=>false,'error'=>'missing session']); exit; }
        $status = in_array(($b['status'] ?? ''), ['resolved','idle','failed','awaiting_approval','active'], true) ? $b['status'] : 'idle';
        // Guard: the flow can only PARK in awaiting_approval if a real action is pending —
        // otherwise there's nothing to click and the session would hang. Coerce to idle.
        if ($status === 'awaiting_approval') {
            $hp = $conn->query("SELECT 1 FROM nm_aip_actions WHERE session_id=$sid AND status='proposed' LIMIT 1");
            if (!$hp || !$hp->num_rows) $status = 'idle';
        }
        nm_aip_event($conn, $sid, $nid, 'system', 'NetAIObot finished this turn', (string)($b['summary'] ?? ''));
        nm_aip_session_set($conn, $sid, $status, (string)($b['summary'] ?? ''));
        // Close the loop: when the bot says it RESOLVED the issue, clear the device's open
        // insights too (so a fixed problem doesn't linger as a pending alert).
        $closed = 0;
        if ($status === 'resolved' && $nid) $closed = nm_aip_resolve_node_insights($conn, $nid, $sid);
        echo json_encode(['ok'=>true,'insights_closed'=>$closed]);
        break;

    default:
        http_response_code(404);
        echo json_encode(['ok'=>false,'error'=>'unknown endpoint']);
}
