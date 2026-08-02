<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — AI Commander V2.0 EXECUTOR callback (n8n brain → portal). PARALLEL to
// the frozen aiopilot_api.php. The portal is the ONLY executor: the `autopilot-v2`
// flow calls these endpoints; NEURU's risk-gate decides. Auth = shared inbound token
// (constant-time). The SESSION is authoritative — any target the LLM invents is ignored.
//   ?ep=think|tool|narrate|propose|finish     Plan: docs/AUTOPILOT_V2_PLAN.md
// ─────────────────────────────────────────────────────────────────────────────
require __DIR__ . '/connection.php';
require __DIR__ . '/nm_autopilotv2.php';

header('Content-Type: application/json');
$body = json_decode(file_get_contents('php://input'), true) ?: [];
$ep   = preg_replace('/[^a-z_]/', '', strtolower((string)($_GET['ep'] ?? ($body['ep'] ?? ''))));

// auth: shared inbound token (reuse the n8n verifier)
$tok = $_SERVER['HTTP_X_NETMON_TOKEN'] ?? ($_GET['token'] ?? ($body['token'] ?? ''));
$okAuth = function_exists('nm_n8n_verify_inbound') ? nm_n8n_verify_inbound($conn, (string)$tok)
        : hash_equals((string)nm_ap2_get($conn, 'n8n_inbound_token', ''), (string)$tok);
if (!$okAuth) { http_response_code(403); echo json_encode(['ok' => false, 'error' => 'forbidden']); exit; }

nm_ap2_ensure($conn);
$sid  = (int)($body['session_id'] ?? $_GET['session_id'] ?? 0);
$node = $sid ? nm_ap2_session_node($conn, $sid) : 0;
$done = function (array $a) { echo json_encode($a); exit; };
if ($sid <= 0 && !in_array($ep, ['health', 'chat_tool'], true)) $done(['ok' => false, 'error' => 'missing session_id']);

switch ($ep) {

    case 'think': {   // log a reasoning step (drives the UI narration)
        $id = nm_ap2_event($conn, $sid, $node, 'think', (string)($body['text'] ?? $body['thought'] ?? ''));
        $done(['ok' => true, 'event_id' => $id]);
    }

    case 'narrate': { // a warm human one-liner (UI + voice)
        $id = nm_ap2_event($conn, $sid, $node, 'narrate', (string)($body['text'] ?? ''));
        $done(['ok' => true, 'event_id' => $id]);
    }

    case 'tool': {    // run a READ tool (the bot's eyes) — no side effects
        $tool = preg_replace('/[^a-z_]/', '', strtolower((string)($body['tool'] ?? '')));
        $args = is_array($body['args'] ?? null) ? $body['args'] : [];
        $tid = 0; try { $tid = nm_ap2_tool_log_start($conn, 'session', $tool, $args); } catch (\Throwable $e) {}
        // a tool failure must degrade to a clean {ok:false} the LLM can reason about — never a 500
        try { $r = nm_ap2_run_tool($conn, $sid, $tool, $args); }
        catch (\Throwable $e) { $r = ['ok' => false, 'error' => 'tool_error: ' . $e->getMessage(), 'data' => null]; }
        // log a readable observation so the console shows what it looked at
        $summary = is_array($r['data'] ?? null) ? substr(json_encode($r['data']), 0, 500) : substr((string)($r['data'] ?? ''), 0, 500);
        nm_ap2_event($conn, $sid, $node, 'observe', $tool . ' → ' . $summary);
        try { nm_ap2_tool_log_finish($conn, $tid, 'session', $tool, $args, $r); } catch (\Throwable $e) {}
        $done(['ok' => !empty($r['ok']), 'tool' => $tool, 'data' => $r['data'] ?? null, 'error' => $r['error'] ?? null]);
    }

    case 'propose': { // propose an ACT tool → risk-gate → {status, needs_approval, rejected, recurrence}
        $tool = preg_replace('/[^a-z_]/', '', strtolower((string)($body['tool'] ?? '')));
        $args = is_array($body['args'] ?? null) ? $body['args'] : [];
        $risk = in_array(($body['risk'] ?? 'low'), ['low', 'medium', 'high'], true) ? $body['risk'] : 'low';
        $reason = substr((string)($body['reason'] ?? ''), 0, 400);
        $conf = isset($body['confidence']) ? max(0, min(100, (int)$body['confidence'])) : null;
        // confidence gate: low confidence NEVER auto-acts — pass forceApproval=true so propose_action does NOT
        // execute before returning (the old code relabeled the JSON AFTER the side effect had already happened).
        if ($conf !== null && $conf < (int)(nm_ap2_get($conn, 'ap2_min_confidence', '55') ?: 55)) {
            $r = nm_ap2_propose_action($conn, $sid, $tool, $args, $risk, '[LOW-CONFIDENCE ' . $conf . '] ' . $reason, true);
            $r['status'] = 'proposed'; $r['needs_approval'] = true; $done($r);
        }
        $done(nm_ap2_propose_action($conn, $sid, $tool, $args, $risk, $reason));
    }

    case 'finish': {  // end the turn; set outcome + close/keep the signal
        $status = (string)($body['status'] ?? 'observed');
        $summary = substr((string)($body['summary'] ?? ''), 0, 255);
        $conf = isset($body['confidence']) ? max(0, min(100, (int)$body['confidence'])) : null;
        nm_ap2_event($conn, $sid, $node, 'result', 'finish (' . $status . '): ' . $summary);
        nm_ap2_session_set($conn, $sid, ['status' => 'done', 'summary' => $summary] + ($conf !== null ? ['confidence' => $conf] : []));
        // map to the signal
        $sigid = 0; try { $q = $conn->query("SELECT signal_id FROM nm_ap2_sessions WHERE id=$sid"); $sigid = $q ? (int)($q->fetch_row()[0] ?? 0) : 0; } catch (\Throwable $e) {}
        if ($sigid) {
            // 'resolved' = NEURU believes the issue is FIXED (leaves the queue). 'observed'/'insufficient' =
            // it investigated but the condition persists (e.g. a node that's still down) → 'acted': stays
            // VISIBLE in the queue with NEURU's conclusion, but is NOT re-investigated every tick (push treats
            // 'acted' as open → just bumps seen_count). The signal auto-resolves when the node recovers (scan).
            $sstat = 'resolved';
            if ($status === 'proposed') $sstat = 'proposed';
            elseif ($status === 'error') $sstat = 'new';           // hard error → retry later
            elseif (in_array($status, ['observed','insufficient','observe','watching'], true)) $sstat = 'acted';
            // uq_fp_open is (fingerprint,status): a prior row of the SAME fingerprint already in the target
            // status (an earlier 'resolved' for a recurring down-node) makes this UPDATE THROW → finish aborts
            // and the signal stays stuck 'investigating'. Collapse sibling-fingerprint rows first, guard it all.
            try {
                $fp = ''; $q = $conn->query("SELECT fingerprint FROM nm_ap2_signals WHERE id=$sigid");
                if ($q) { $fp = (string)($q->fetch_row()[0] ?? ''); }
                if ($fp !== '') { $fpe = $conn->real_escape_string($fp); $conn->query("DELETE FROM nm_ap2_signals WHERE fingerprint='$fpe' AND id<>$sigid"); }
                $conn->query("UPDATE nm_ap2_signals SET status='" . $sstat . "', session_id=NULL WHERE id=$sigid");
            } catch (\Throwable $e) {}
            if ($sstat === 'resolved' && $node && function_exists('nm_aip_resolve_node_insights')) { try { nm_aip_resolve_node_insights($conn, $node); } catch (\Throwable $e) {} }
            // A MANUAL Rescan (operator re-checked one node) that concludes CLEAN means the node is fine now →
            // also clear that node's other 'reviewed' (acted) incidents that were parked "until the condition
            // clears". Without this a clean Rescan leaves the original incident lingering in the queue forever.
            // Row-by-row + clear any same-fingerprint 'resolved' first so the uq_fp_open unique never throws.
            if ($sstat === 'resolved' && $node) {
                $trig = ''; try { $q = $conn->query("SELECT trigger_kind FROM nm_ap2_sessions WHERE id=$sid"); $trig = $q ? (string)($q->fetch_row()[0] ?? '') : ''; } catch (\Throwable $e) {}
                if ($trig === 'manual') {
                    try {
                        $rs = $conn->query("SELECT id, fingerprint FROM nm_ap2_signals WHERE node_id=$node AND status='acted' AND id<>$sigid");
                        while ($rs && $row = $rs->fetch_assoc()) {
                            $rid = (int)$row['id']; $rfp = $conn->real_escape_string((string)$row['fingerprint']);
                            try { $conn->query("DELETE FROM nm_ap2_signals WHERE fingerprint='$rfp' AND status='resolved'"); } catch (\Throwable $e) {}
                            try { $conn->query("UPDATE nm_ap2_signals SET status='resolved', session_id=NULL WHERE id=$rid"); } catch (\Throwable $e) {}
                        }
                    } catch (\Throwable $e) {}
                }
            }
        }
        // VOICE narration of the VERDICT — ALERTS path only (autonomous/manual Investigate); NEVER the direct
        // conversation (trigger 'chat'). Terse + concrete; the drainer speaks it only when the operator is idle.
        if (function_exists('nm_ap2_voice_on') && nm_ap2_voice_on($conn)) {
            try {
                $trg = ''; $vname = '';
                $vq = $conn->query("SELECT s.trigger_kind, COALESCE(sg.name, n.display_name, '') AS nm FROM nm_ap2_sessions s LEFT JOIN nm_ap2_signals sg ON sg.id=s.signal_id LEFT JOIN nm_nodes n ON n.id=s.node_id WHERE s.id=$sid LIMIT 1");
                if ($vq && ($vx = $vq->fetch_assoc())) { $trg = (string)$vx['trigger_kind']; $vname = (string)$vx['nm']; }
                if ($trg !== 'chat') {
                    $vsig = $sigid ?: null; $vnode = $node ?: null;
                    if ($status === 'proposed')       nm_ap2_voice_enqueue($conn, 'proposed', $vsig, $vnode, nm_ap2_voice_terse($vname, $summary !== '' ? $summary : 'propongo una acción'));
                    elseif ($status === 'resolved')   nm_ap2_voice_enqueue($conn, 'clean',    $vsig, $vnode, ($vname !== '' ? $vname . ': ' : '') . 'resuelto.');
                    elseif ($status === 'insufficient') nm_ap2_voice_enqueue($conn, 'found',  $vsig, $vnode, nm_ap2_voice_terse($vname, $summary !== '' ? $summary : 'sin conclusión, requiere revisión'));
                    else                              nm_ap2_voice_enqueue($conn, 'found',    $vsig, $vnode, nm_ap2_voice_terse($vname, $summary !== '' ? $summary : 'revisado'));
                }
            } catch (\Throwable $e) {}
        }
        // learning: a bot-suggested rule lands INACTIVE for the operator to approve
        if (!empty($body['suggested_rule']) && is_array($body['suggested_rule'])) {
            $sr = $body['suggested_rule'];
            $mt = in_array(($sr['match']['type'] ?? 'channel_type'), ['fingerprint', 'channel_type', 'node', 'regex'], true) ? $sr['match']['type'] : 'channel_type';
            $mv = substr((string)($sr['match']['val'] ?? ($sr['match'] ?? '')), 0, 255);
            $pol = in_array(($sr['policy'] ?? 'ignore'), ['ignore', 'auto_ack', 'auto_fix', 'always_ask'], true) ? $sr['policy'] : 'ignore';
            $note = substr('bot-suggested: ' . (string)($sr['reason'] ?? ''), 0, 255);
            if ($mv !== '') { try { $st = $conn->prepare("INSERT INTO nm_ap2_rules (match_type,match_val,policy,note,created_by,active) VALUES (?,?,?,?, 'bot', 0)");
                $st->bind_param('ssss', $mt, $mv, $pol, $note); $st->execute(); $st->close(); } catch (\Throwable $e) {} }
        }
        $done(['ok' => true]);
    }

    case 'chat_tool': {   // fleet-wide READ tool for the conversational flow (NOT session-bound)
        $tool = (string)($body['tool'] ?? '');
        $args = is_array($body['args'] ?? null) ? $body['args'] : [];
        $tid = 0; try { $tid = nm_ap2_tool_log_start($conn, 'live', $tool, $args); } catch (\Throwable $e) {}
        try { $r = nm_ap2_chat_run_tool($conn, $tool, $args); }
        catch (\Throwable $e) { $r = ['ok' => false, 'error' => 'tool_error: ' . $e->getMessage(), 'data' => null]; }
        try { nm_ap2_tool_log_finish($conn, $tid, 'live', $tool, $args, $r); } catch (\Throwable $e) {}
        $done(['ok' => !empty($r['ok']), 'tool' => $tool, 'data' => $r['data'] ?? null, 'error' => $r['error'] ?? null]);
    }

    case 'health':
        $done(['ok' => true, 'service' => 'autopilotv2', 'enabled' => nm_ap2_enabled($conn)]);

    default:
        http_response_code(400); $done(['ok' => false, 'error' => 'unknown ep']);
}
