<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — NetOps Copilot proxy. Session-auth'd endpoint that relays a chat
// question to the `netops-copilot` n8n webhook (token stays server-side) and
// returns the AI's answer. The flow may call back into nm_ai_api.php (read) and
// nm_ai_ingest.php (write) using the shared inbound token to run real checks.
// ─────────────────────────────────────────────────────────────────────────────
date_default_timezone_set('America/Puerto_Rico');
header('Content-Type: application/json; charset=utf-8');

include('check.php');
include('connection.php');
require_once('access_control.php');
require_once('nm_access.php');
require_once('nm_n8n.php');
require_once('nm_audit.php');
require_once('nm_copilot_kb.php');

if (empty($_SESSION['username']) || !checkAccess($conn, 'copilot')) {
    http_response_code(403);
    echo json_encode(['ok'=>false,'err'=>'Unauthorized']); exit;
}

$api = $_GET['api'] ?? 'ask';

// Is the copilot wired up? (webhook registered + enabled)
if ($api === 'health') {
    $wh = nm_n8n_webhook_by_slug($conn, 'netops-copilot');
    echo json_encode(['ok'=>true, 'ready'=> (bool)($wh && $wh['enabled'])]);
    exit;
}

if ($api === 'ask') {
    $b = json_decode(file_get_contents('php://input'), true) ?? [];
    $question = trim((string)($b['question'] ?? ''));
    if ($question === '') { echo json_encode(['ok'=>false,'err'=>'Empty question']); exit; }
    $history = array_slice((array)($b['history'] ?? []), -8);   // last few turns for context
    $context = (array)($b['context'] ?? []);
    $context['user'] = $_SESSION['username'];
    $context['role'] = $_SESSION['role'] ?? 'user';
    // Resolve a friendly name for the page the user is on (helps "where is this option?")
    if (!empty($context['page']) && function_exists('nm_perm_catalog')) {
        foreach (nm_perm_catalog() as $r) { if ($r[4] === $context['page']) { $context['page_label'] = $r[1]; break; } }
    }

    // Portal expertise: ship the operator knowledge base so the flow's LLM answers
    // as a NEURU expert (navigation, how-tos, glossary) — gated to THIS user's perms.
    $portal_kb = nm_copilot_kb($conn, $context, (string)$_SESSION['username']);

    nm_audit($conn, 'copilot.ask', ['target_type'=>'copilot',
        'details'=>['q'=>mb_substr($question,0,200),'page'=>$context['page'] ?? '']]);

    [$code, $resp, $err] = nm_n8n_call($conn, 'netops-copilot', [
        'event'     => 'copilot_chat',
        'question'  => $question,
        'history'   => $history,
        'context'   => $context,
        'portal_kb' => $portal_kb,
    ]);
    if ($err) {
        echo json_encode(['ok'=>false,'err'=>$err,
            'hint'=>'Add an enabled n8n webhook with slug "netops-copilot" in Config → Integrations & AI']);
        exit;
    }
    // Normalise the flow's reply into {answer, evidence[], diagram?}. n8n returns
    // data in many shapes, so unwrap the common envelopes before reading fields.
    $node = $resp;
    if (is_array($node) && isset($node[0]) && count($node) === 1 && is_array($node[0])) $node = $node[0]; // [ {...} ]
    if (is_array($node) && isset($node['json'])  && is_array($node['json']))  $node = $node['json'];      // { json: {...} }
    if (is_array($node) && isset($node['data'])  && is_array($node['data']))  $node = $node['data'];      // { data: {...} }

    $pick = function ($a, array $keys) {
        foreach ($keys as $k) if (is_array($a) && isset($a[$k]) && $a[$k] !== '' && $a[$k] !== null) return $a[$k];
        return null;
    };
    // 'output' is the n8n AI-Agent node's default result key — accept it + common aliases.
    $answer = ''; $evidence = []; $diagram = null;
    if (is_array($node)) {
        $answer   = (string)($pick($node, ['answer','output','summary','text','message','reply','response','content']) ?? '');
        $evidence = $node['evidence'] ?? ($node['evidences'] ?? []);
        $diagram  = $node['diagram'] ?? ($node['mermaid'] ?? null);
        // AI-Agent sometimes returns the JSON-as-a-string inside 'output'
        if ($answer !== '' && isset($answer[0]) && $answer[0] === '{') {
            $d = json_decode($answer, true);
            if (is_array($d)) { $a2 = $pick($d, ['answer','output','summary','text','message']);
                if ($a2 !== null) { $answer=(string)$a2; $evidence=$d['evidence']??$evidence; $diagram=$d['diagram']??$diagram; } }
        }
    } elseif (is_string($node)) {
        $answer = trim($node);
    }

    if ($answer === '') {
        // The flow answered but with nothing usable — surface what it actually sent
        // so the operator can fix the n8n side instead of seeing a blank "(no answer)".
        $raw = is_string($resp) ? $resp : json_encode($resp);
        $snippet = mb_substr((string)$raw, 0, 500);
        echo json_encode(['ok'=>false,
            'err'=>"The n8n flow replied (HTTP {$code}) but with no answer field.",
            'hint'=>"Fix the netops-copilot flow: (1) Webhook node → Respond = \"Using Respond to Webhook Node\"; (2) end with a 'Respond to Webhook' node returning JSON {\"answer\":\"…\"}; (3) if you use an AI-Agent, its text is in \"output\" — map output → answer. Raw reply received: " . ($snippet === '' ? '(empty body)' : $snippet)]);
        exit;
    }
    echo json_encode(['ok'=>true,'answer'=>$answer,
        'evidence'=>is_array($evidence)?$evidence:[$evidence],'diagram'=>$diagram]);
    exit;
}

echo json_encode(['ok'=>false,'err'=>'Unknown endpoint']);
