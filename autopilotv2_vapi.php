<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — AI Commander V2.0 VOICE bridge (VAPI cloud → portal). PUBLIC endpoint:
// the customer's VAPI assistant has ONE function-tool `ask_neuru` whose server URL
// points here. VAPI POSTs the tool call; we run the SAME chat ReAct brain as the
// text cockpit (nm_ap2_chat_exchange) and return the answer for VAPI to speak.
//
// AUTH = the per-install shared secret (vapi_tool_secret), which VAPI sends as the
// `x-vapi-secret` header on every server request (assistant.server.secret). Constant-time.
//
//   ?ep=ask     tool call  → { results:[{toolCallId, result:"<answer>"}] }
//   ?ep=report  end-of-call → logged now; Phase B meters voice MINUTES here (→ Portal wallet)
//
// Phase A: voice ANSWERS + runs read-only commands (allowCommands=false — no structural
// changes by voice). See nm_vapi.php + docs/N8N_AUTOPILOT_V2_CONTRACT.md FLOW 3.
// ─────────────────────────────────────────────────────────────────────────────
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_autopilotv2.php';
require __DIR__ . '/nm_vapi.php';

header('Content-Type: application/json');
nm_vapi_ensure($conn);

$ep   = preg_replace('/[^a-z_]/', '', strtolower((string)($_GET['ep'] ?? 'ask')));
$body = json_decode(file_get_contents('php://input'), true) ?: [];

// auth: x-vapi-secret header (VAPI). Body token allowed for our own JSON testing; NO ?token= — a query
// secret leaks into access logs / Referer / proxies. Header or POST-body only.
$sent = $_SERVER['HTTP_X_VAPI_SECRET'] ?? ($body['token'] ?? '');
$want = nm_vapi_tool_secret($conn);
if ($want === '' || !hash_equals($want, (string)$sent)) {
    http_response_code(403); echo json_encode(['error' => 'forbidden']); exit;
}

// ── end-of-call report: Phase A logs it; Phase B debits voice minutes to the wallet ──
if ($ep === 'report') {
    $m = is_array($body['message'] ?? null) ? $body['message'] : $body;
    $secs = (float)($m['durationSeconds'] ?? $m['duration'] ?? 0);
    $cost = (float)($m['cost'] ?? 0);
    // TODO Phase B: POST {conn_key, minutes, cost} to the Portal minutes-meter (sibling of neuru-meter).
    try { nm_vapi_set($conn, 'vapi_last_call', gmdate('Y-m-d H:i:s') . ' · ' . round($secs) . 's · $' . $cost); } catch (\Throwable $e) {}
    echo json_encode(['ok' => true]); exit;
}

// ── ask_neuru: extract the question from whatever shape VAPI sends, answer via the brain ──
// VAPI (current): body.message.toolCallList[i] = { id, function:{ name, arguments } }
//        (legacy): body.message.functionCall  = { name, parameters }
// arguments may be a JSON string OR an object. We also accept a bare {question:"…"} for testing.
function nm_vapi_extract_calls(array $body): array {
    $m = is_array($body['message'] ?? null) ? $body['message'] : [];
    $out = [];
    $list = $m['toolCallList'] ?? $m['toolCalls'] ?? null;
    if (is_array($list)) {
        foreach ($list as $c) {
            $fn = $c['function'] ?? $c;
            $args = $fn['arguments'] ?? $fn['parameters'] ?? [];
            if (is_string($args)) { $d = json_decode($args, true); $args = is_array($d) ? $d : ['question' => $args]; }
            $out[] = ['id' => (string)($c['id'] ?? $c['toolCallId'] ?? ''), 'name' => (string)($fn['name'] ?? ''), 'args' => is_array($args) ? $args : []];
        }
    } elseif (isset($m['functionCall'])) {
        $fc = $m['functionCall'];
        $args = $fc['parameters'] ?? $fc['arguments'] ?? [];
        if (is_string($args)) { $d = json_decode($args, true); $args = is_array($d) ? $d : ['question' => $args]; }
        $out[] = ['id' => '', 'name' => (string)($fc['name'] ?? ''), 'args' => is_array($args) ? $args : []];
    } elseif (isset($body['question'])) {          // bare test call
        $out[] = ['id' => (string)($body['toolCallId'] ?? ''), 'name' => 'ask_neuru', 'args' => ['question' => (string)$body['question']]];
    }
    return $out;
}

$calls = nm_vapi_extract_calls($body);
$results = [];
// DIRECT tools the VAPI assistant now calls itself (fast path — no 2nd LLM). ask_neuru stays as a legacy fallback.
$KNOWN = ['list_nodes','node_report','node_xray','close_xray','show_topology','show_traffic','show_containers','container_report','set_panel','set_autonomous','scan_fleet','interfaces','bandwidth_top','traffic_by_app','traffic_by_country','anomalies','run_show_command','reachability','route_lookup','locate_ip','route_drift','database_report','firewall_rules','firewall_check','firewall_drift','firewall_traffic','firewall_addrlists','connections','blast_radius'];
foreach ($calls as $c) {
    $name = (string)($c['name'] ?? '');
    if ($name !== '' && $name !== 'ask_neuru' && in_array($name, $KNOWN, true)) {
        // run the single tool directly → return raw DATA (VAPI's LLM speaks it in the operator's language).
        // Also logs to nm_ap2_tool_events so the cockpit's futuristic tool panel lights up for VOICE too.
        $tid = 0; try { $tid = nm_ap2_tool_log_start($conn, 'live', $name, $c['args']); } catch (\Throwable $e) {}
        try { $tr = nm_ap2_chat_run_tool($conn, $name, $c['args']); }
        catch (\Throwable $e) { $tr = ['ok' => false, 'error' => 'tool_error: ' . $e->getMessage()]; }
        try { nm_ap2_tool_log_finish($conn, $tid, 'live', $name, $c['args'], $tr); } catch (\Throwable $e) {}
        $payload = !empty($tr['ok']) ? ($tr['data'] ?? ['ok' => true]) : ['error' => $tr['error'] ?? 'tool failed'];
        $results[] = ['toolCallId' => $c['id'], 'result' => substr(json_encode($payload), 0, 6000)];
        continue;
    }
    // legacy ask_neuru → the full chat ReAct brain (slower)
    $q = trim((string)($c['args']['question'] ?? ''));
    if ($q === '') { $results[] = ['toolCallId' => $c['id'], 'result' => 'No question was provided.']; continue; }
    try { $r = nm_ap2_chat_exchange($conn, $q, 'voice', false); $answer = (string)($r['reply'] ?? ''); }
    catch (\Throwable $e) { $answer = 'NEURU hit an error answering that: ' . $e->getMessage(); }
    if ($answer === '') $answer = 'NEURU could not produce an answer just now.';
    $results[] = ['toolCallId' => $c['id'], 'result' => $answer];
}

if (!$results) { echo json_encode(['error' => 'no tool call found in request']); exit; }
echo json_encode(['results' => $results]); exit;
