<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — VAPI voice engine (AI Commander V2.0 · Phase A "BYO", Phase-B-ready).
//
// The operator can TALK to NEURU. Phase A = the customer brings their own VAPI
// account (public key + assistant id + private key). The browser opens a VAPI web
// call (voice.php, self-hosted SDK) whose assistant has ONE function-tool,
// `ask_neuru`, that calls back into THIS NEURU (autopilotv2_vapi.php) → the same
// chat ReAct brain as the text cockpit. So voice answers ANY fleet question and can
// run read-only commands, exactly like typing.
//
// Phase-B-ready: every call carries the tenant `conn_key`; the assistant's LLM can be
// pointed at NEURU's LiteLLM (metered per token like GPT) and voice MINUTES metered via
// the end-of-call webhook (autopilotv2_vapi.php?ep=report) → Portal wallet. See
// docs/N8N_AUTOPILOT_V2_CONTRACT.md FLOW 3 + docs/RELEASE_0.1.1.40_CHECKLIST.md Part B.
//
// SECURITY: the private key is stored ENCRYPTED (nm_secret_encrypt → www-data only).
// The public key + assistant id are safe to expose to the browser (that is their job).
// The bridge endpoint is authed by a per-install `vapi_tool_secret` (VAPI sends it as
// the `x-vapi-secret` header on every tool call).
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_secrets.php';

if (!function_exists('nm_vapi_get')) {

// ── tiny settings accessors (nm_settings; self-contained so this file can load alone) ──
function nm_vapi_get($conn, string $k, string $d = ''): string {
    try { $st = $conn->prepare("SELECT setting_val FROM nm_settings WHERE setting_key=? LIMIT 1");
          $st->bind_param('s', $k); $st->execute(); $r = $st->get_result()->fetch_row(); $st->close();
          return $r ? (string)$r[0] : $d; } catch (\Throwable $e) { return $d; }
}
function nm_vapi_set($conn, string $k, string $v): void {
    try { $st = $conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES (?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
          $st->bind_param('ss', $k, $v); $st->execute(); $st->close(); } catch (\Throwable $e) {}
}

// ── one-time bootstrap: mint the bridge shared-secret so the tool endpoint is authed ──
function nm_vapi_ensure($conn): void {
    if (nm_vapi_get($conn, 'vapi_tool_secret', '') === '') {
        try { nm_vapi_set($conn, 'vapi_tool_secret', bin2hex(random_bytes(24))); } catch (\Throwable $e) {}
    }
}
function nm_vapi_tool_secret($conn): string {
    $s = nm_vapi_get($conn, 'vapi_tool_secret', '');
    if ($s === '') { nm_vapi_ensure($conn); $s = nm_vapi_get($conn, 'vapi_tool_secret', ''); }
    return $s;
}

// ── config surface ───────────────────────────────────────────────────────────
function nm_vapi_enabled($conn): bool { return nm_vapi_get($conn, 'vapi_enabled', '0') === '1'; }
function nm_vapi_private_key($conn): string { return nm_secret_decrypt(nm_vapi_get($conn, 'vapi_private_key', '')); }

// Fully wired for a browser web-call? (enabled + public key + assistant id present)
function nm_vapi_configured($conn): bool {
    return nm_vapi_enabled($conn)
        && nm_vapi_get($conn, 'vapi_public_key', '') !== ''
        && nm_vapi_get($conn, 'vapi_assistant_id', '') !== '';
}

// The MINIMAL, non-secret config the browser (voice.php) needs.
function nm_vapi_public_cfg($conn): array {
    return [
        'public_key'   => nm_vapi_get($conn, 'vapi_public_key', ''),
        'assistant_id' => nm_vapi_get($conn, 'vapi_assistant_id', ''),
    ];
}

// What the config CARD shows (never leaks the private key — only whether one is stored).
function nm_vapi_admin_cfg($conn): array {
    return [
        'enabled'      => nm_vapi_enabled($conn),
        'public_key'   => nm_vapi_get($conn, 'vapi_public_key', ''),
        'assistant_id' => nm_vapi_get($conn, 'vapi_assistant_id', ''),
        'has_private'  => nm_vapi_get($conn, 'vapi_private_key', '') !== '',
        'configured'   => nm_vapi_configured($conn),
        'public_base'  => nm_vapi_public_base($conn),
    ];
}

// Save from the config card. Private key: only (re)written when a NON-empty value is
// supplied, so leaving the field blank keeps the stored secret. '' in public/assistant
// is allowed (clearing). enabled is coerced to 0/1.
function nm_vapi_save($conn, array $f): void {
    nm_vapi_ensure($conn);
    if (array_key_exists('public_key', $f))   nm_vapi_set($conn, 'vapi_public_key',   trim((string)$f['public_key']));
    if (array_key_exists('assistant_id', $f)) nm_vapi_set($conn, 'vapi_assistant_id', trim((string)$f['assistant_id']));
    if (array_key_exists('enabled', $f))      nm_vapi_set($conn, 'vapi_enabled', !empty($f['enabled']) ? '1' : '0');
    if (array_key_exists('public_base', $f))  nm_vapi_set($conn, 'vapi_public_base', rtrim(trim((string)$f['public_base']), '/'));
    if (!empty($f['private_key'])) {
        $enc = nm_secret_encrypt(trim((string)$f['private_key']));
        if ($enc !== '') nm_vapi_set($conn, 'vapi_private_key', $enc);
    }
    if (!empty($f['clear_private'])) nm_vapi_set($conn, 'vapi_private_key', '');
}

// The public URL VAPI's cloud uses to reach THIS NEURU for tool calls + the end-of-call
// report. Defaults to the AI-gateway public base (already set when enrolled); overridable
// via vapi_public_base for installs behind a different reverse proxy.
function nm_vapi_public_base($conn): string {
    $b = nm_vapi_get($conn, 'vapi_public_base', '');
    if ($b === '') $b = nm_vapi_get($conn, 'ai_public_base', '');
    return rtrim($b, '/');
}

// The tenant id for metering (Phase B) — same conn_key GPT bills under.
function nm_vapi_conn_key($conn): string { return nm_vapi_get($conn, 'ai_conn_key', ''); }

// ── VAPI REST (assistant auto-provision) — uses the PRIVATE key; server-side only ────
// Returns [http_code:int, json:array|null, err:string].
function nm_vapi_api($conn, string $method, string $path, ?array $body = null): array {
    $key = nm_vapi_private_key($conn);
    if ($key === '') return [0, null, 'no private key configured'];
    $url = 'https://api.vapi.ai/' . ltrim($path, '/');
    $ch = curl_init($url);
    $hdr = ['Authorization: Bearer ' . $key, 'Content-Type: application/json'];
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST  => strtoupper($method),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => $hdr,
        CURLOPT_TIMEOUT        => 20,
        CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4,   // portal/hosted IPv6 is flaky (see dev notes)
    ]);
    if ($body !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
    $raw = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = $raw === false ? curl_error($ch) : '';
    curl_close($ch);
    $json = is_string($raw) ? json_decode($raw, true) : null;
    return [$code, is_array($json) ? $json : null, $err];
}

// The single function-tool NEURU's assistant exposes. `ask_neuru` forwards ANY question
// to the text chat ReAct brain (fleet data, netflow, country traffic, read-only commands).
// DIRECT tools exposed to VAPI (the assistant's LLM calls the RIGHT tool → the bridge runs it via
// nm_ap2_chat_run_tool with NO second LLM → 2-4s instead of 10-25s). The bridge returns raw DATA and
// VAPI's LLM speaks it in the operator's language (also fixes cross-language blending). 'slow' tools
// (SSH/route sims) carry the localized "still working…" fillers; instant DB tools don't need them.
function nm_vapi_tool_defs(): array {
    $obj = function (array $props, array $req = []) { return ['type' => 'object', 'properties' => $props, 'required' => $req]; };
    $str = function ($d) { return ['type' => 'string', 'description' => $d]; };
    $num = function ($d) { return ['type' => 'number', 'description' => $d]; };
    $enum = function (array $vals, $d) { return ['type' => 'string', 'enum' => $vals, 'description' => $d]; };
    // [name, description, parameters, slow?]
    $defs = [
        ['ask_neuru', 'NEURU\'s full reasoning brain — for OPEN-ENDED questions, anything no specific tool fits, and especially when the operator TEACHES or CORRECTS you ("recuerda que…", "no, en realidad…"). It knows ALL learned memory (topology, IP ownership, corrections, preferences) and LEARNS from the exchange, returning a natural-language answer you relay in the operator\'s language. Prefer a specific tool when one clearly fits; use ask_neuru as the fallback + for teachings/corrections so they are remembered.', $obj(['question' => $str('the operator\'s question or statement, verbatim in their own words')], ['question']), true],
        ['list_nodes', 'List fleet nodes with up/down status + IP.', $obj(['filter' => $enum(['up','down','all'], 'which nodes (default all)')]), false],
        ['node_report', 'Full live context for ONE node: CPU/RAM/disk, interfaces, netflow, forecast, recent findings.', $obj(['node' => $str('node name, id, or IP')], ['node']), false],
        ['node_xray', 'Open the SURGICAL X-RAY — a live 3D anatomy of ONE monitored NETWORK NODE/device (a real server or router): CPU as a beating heart, memory, GPU, network, disk, thermals, processes, containers. Use ONLY when the operator explicitly asks for the X-RAY / anatomy of a named device (e.g. "x-ray de web-01"). This is NOT for the cockpit side panels — for "abre/oculta el panel de chat/cola/razonamiento" use set_panel, NEVER node_xray. If the "node" would be a panel word (chat, cola, señales, razonamiento), do NOT call this — call set_panel.', $obj(['node' => $str('a real device name/id/ip — never a panel word'), 'focus' => $enum(['cpu','memory','gpu','network','disk','processes','containers','thermals'], 'optional subsystem to zoom into')], ['node']), true],
        ['close_xray', 'CLOSE any on-screen full-screen overlay if open — the X-Ray 3D anatomy OR the network topology MAP. Use when the operator says "close the screen", "close the x-ray", "cierra la pantalla", "ciérralo", "close it".', $obj([]), false],
        ['show_topology', 'Open the interactive 3D NETWORK TOPOLOGY MAP on the operator\'s screen — all nodes interconnected. Use for "muéstrame el mapa/la topología de la red", "el mapa completo", a router segment ("el segmento del core router", "qué conecta al core-router"), or a subnet ("el segmento 192.168.2.0"). Do it + confirm in ONE short sentence.', $obj(['scope' => $str('optional: "all", a router/node name, or a subnet CIDR')]), false],
        ['show_traffic', 'Open the LIVE TRAFFIC view (animated laser per interface) for a device, optionally focusing interface(s). Use for "muéstrame el tráfico en vivo de la interfaz 1 del core router", "el tráfico del core router", "las interfaces 1 y 3". Do it + confirm in ONE short sentence with the in/out rate.', $obj(['node' => $str('the device name'), 'interface' => $str('optional interface number or name, or several')], ['node']), false],
        ['show_containers', 'Open the 3D CONTAINERS layer on the operator\'s screen — every Docker container across every node. Use for "muéstrame los contenedores", "los contenedores del nodo X", "enséñame el contenedor mysql". Focuses the named node/container. Do it + confirm in ONE short sentence.', $obj(['node' => $str('optional device name'), 'container' => $str('optional container name or image')]), false],
        ['container_report', 'Full detail of ONE container to answer any question about it: state/health, image, VOLUMES with sizes (biggest / dangerous >2GB), partition size (writable layer + rootfs), live CPU/mem/net + net-traffic history. Use for "cuánto pesa el volumen de mysql", "qué contenedor está más grande", "cómo está el contenedor X".', $obj(['node' => $str('optional device'), 'container' => $str('container name / image / id')], ['container']), false],
        ['set_panel', 'SHOW or HIDE a cockpit side panel (they are hidden by default). Use when the operator asks to show/open/hide/close the chat panel, the queue/cola/señales panel, or the reasoning/razonamiento panel. This performs the action on their screen — do NOT say you cannot; just do it and confirm in ONE short sentence.', $obj(['panel' => $enum(['chat','queue','reasoning'], 'which panel'), 'action' => $enum(['show','hide'], 'show or hide')], ['panel','action']), false],
        ['set_autonomous', 'Turn NEURU AUTONOMOUS mode ON or OFF (master switch — ON = auto-investigate signals). Use for "prende/enciende/apaga/pausa el modo autónomo", "go autonomous", "pausa NEURU". Do it + confirm in ONE short sentence.', $obj(['action' => $enum(['on','off'], 'on or off')], ['action']), false],
        ['scan_fleet', 'Run a fleet SCAN now. Use for "escanea ahora", "barre la flota", "scan now". Do it + confirm in ONE short sentence.', $obj([]), false],
        ['interfaces', 'Interfaces + per-interface bandwidth for a node.', $obj(['node' => $str('node name/id/ip')], ['node']), false],
        ['bandwidth_top', 'Top bandwidth talkers (IPs, Mbps) fleet-wide or per node, with country.', $obj(['node' => $str('optional node'), 'dir' => $enum(['src','dst'], 'src or dst'), 'limit' => $num('max rows'), 'minutes' => $num('time window')]), false],
        ['traffic_by_app', 'Top applications/ports by bandwidth.', $obj(['node' => $str('optional node'), 'limit' => $num('max rows'), 'minutes' => $num('time window')]), false],
        ['traffic_by_country', 'Bandwidth aggregated by COUNTRY via GeoIP.', $obj(['dir' => $enum(['src','dst'], 'src or dst'), 'limit' => $num('max rows'), 'minutes' => $num('time window')]), false],
        ['anomalies', 'Recent AI-insight anomalies + active threats (Collective Immunity).', $obj(['node' => $str('optional node')]), false],
        ['run_show_command', 'Run ONE READ-ONLY device CLI command over SSH and return its raw output (e.g. "/system resource print", "show ip route", "/interface print", or a probe FROM that device like "/ping 8.8.8.8" / "/tool traceroute X"). Config/write commands are refused.', $obj(['node' => $str('device name/id/ip'), 'command' => $str('the read-only command')], ['node','command']), true],
        ['reachability', 'Simulate whether traffic can get from SRC to DST across the monitored routers/firewalls, hop-by-hop over their real routing tables. Answers "can host A reach IP B?".', $obj(['src' => $str('source IP or router name (optional)'), 'dst' => $str('destination IP or node')], ['dst']), true],
        ['route_lookup', 'Which routers have a route to DST (longest-prefix match: prefix, gateway, protocol).', $obj(['dst' => $str('destination IP or node')], ['dst']), true],
        ['locate_ip', 'WHOSE IP is this? Say if an IP belongs to a monitored device — a management IP OR a router/device INTERFACE IP (with the interface name) — and which routers forward toward it. Use whenever an IP comes up ("a qué router pertenece/va esta IP", "is it monitored"). An interface IP IS monitored — never say it is not.', $obj(['ip' => $str('the IP address')], ['ip']), true],
        ['route_drift', 'Recent routing-table changes (routes added/removed) for a router.', $obj(['node' => $str('router name/id/ip')], ['node']), true],
        ['database_report', 'Monitored databases (Data Core): no db → summary of all; a db name → its status, live metrics (connections/threads/blocked/slow), replication lag, tuning advice, schema drift.', $obj(['db' => $str('database name or id (optional)')]), false],
        ['firewall_rules', 'MikroTik firewall ruleset (chains, actions, matches) for a router.', $obj(['node' => $str('mikrotik router'), 'table' => $enum(['filter','nat','mangle'], 'table (default filter)')], ['node']), true],
        ['firewall_check', 'Does the MikroTik firewall ALLOW traffic SRC→DST? A→B emulation (routing+NAT+firewall) → verdict + deciding rule.', $obj(['node' => $str('mikrotik router'), 'src' => $str('source IP'), 'dst' => $str('destination IP'), 'proto' => $str('tcp/udp/icmp (optional)'), 'dport' => $str('destination port (optional)')], ['node','src','dst']), true],
        ['firewall_drift', 'Firewall config drift (rules added/removed vs snapshot) for a router.', $obj(['node' => $str('mikrotik router'), 'table' => $enum(['filter','nat','mangle'], 'table')], ['node']), true],
        ['firewall_traffic', 'Live firewall connections (connection-tracking torch) on a router.', $obj(['node' => $str('mikrotik router'), 'limit' => $num('max rows')], ['node']), true],
        ['firewall_addrlists', 'MikroTik firewall address lists (blocked/whitelist) on a router.', $obj(['node' => $str('mikrotik router')], ['node']), true],
        ['connections', 'What is connected to a node — its topology neighbors (wired links + gateway) with interface + label. "What is connected to the core router?"', $obj(['node' => $str('node name/id/ip')], ['node']), false],
        ['blast_radius', 'If a node fails, what breaks — downstream nodes cut off + business services impacted. "If the core router goes down, what is affected?"', $obj(['node' => $str('node name/id/ip')], ['node']), false],
    ];
    $msgs = nm_vapi_tool_messages();
    $out = [];
    foreach ($defs as [$name, $desc, $params, $slow]) {
        $t = ['type' => 'function', 'function' => ['name' => $name, 'description' => $desc, 'parameters' => $params]];
        if ($slow) $t['messages'] = $msgs;   // localized "still working…" only where a wait is expected
        $out[] = $t;
    }
    return $out;
}

// Multilingual tool fillers (VAPI plays these by the caller's language). request-start = "let me check…",
// request-response-delayed = a reassurance at ~7s ("still working…"), request-failed = a graceful apology.
function nm_vapi_tool_messages(): array {
    $L = function ($es, $en, $pt, $fr, $de) {
        return [
            ['type' => 'text', 'text' => $es, 'language' => 'es'],
            ['type' => 'text', 'text' => $en, 'language' => 'en'],
            ['type' => 'text', 'text' => $pt, 'language' => 'pt'],
            ['type' => 'text', 'text' => $fr, 'language' => 'fr'],
            ['type' => 'text', 'text' => $de, 'language' => 'de'],
        ];
    };
    return [
        ['type' => 'request-start', 'contents' => $L(
            'Dame un segundo, lo estoy revisando…', 'Give me a second, I\'m checking that…',
            'Um segundo, estou verificando…', 'Un instant, je vérifie ça…', 'Einen Moment, ich prüfe das…')],
        ['type' => 'request-response-delayed', 'timingMilliseconds' => 7000, 'contents' => $L(
            'Sigo trabajando en eso, un momento por favor…', 'Still working on it, one moment please…',
            'Ainda estou trabalhando nisso, um momento…', 'Je travaille toujours dessus, un instant…',
            'Ich arbeite noch daran, einen Moment…')],
        ['type' => 'request-failed', 'contents' => $L(
            'No pude completar esa consulta ahora mismo.', 'I couldn\'t complete that query right now.',
            'Não consegui completar essa consulta agora.', 'Je n\'ai pas pu terminer cette requête.',
            'Ich konnte diese Abfrage gerade nicht abschließen.')],
    ];
}

// The voice persona.
function nm_vapi_system_prompt(): string {
    return "You are NEURU, a warm, sharp AI network operations commander speaking OUT LOUD to an operator. "
        . "You monitor their whole network and have TOOLS to inspect it live — always CALL the right tool, never "
        . "guess or say you lack access. Pick the tool that fits: who's up/down → list_nodes; a node's health → "
        . "node_report; SHOW/DISPLAY/OPEN the X-RAY, the visual anatomy, or the 3D view of a node — OR a subsystem "
        . "like its CPU/memory/GPU/disk (e.g. 'muéstrame el x-ray de web-01', 'show me the CPU of core-router', "
        . "'enséñame la memoria del servidor') → node_xray (this OPENS the live 3D anatomy on the operator's SCREEN "
        . "and returns its vitals for you to describe out loud) — use node_xray whenever they ask to SEE it, not "
        . "node_report; CLOSE / dismiss the x-ray or on-screen view ('cierra la pantalla', 'close it') → close_xray; "
        . "SHOW/HIDE a cockpit panel — the chat, the queue/cola/señales, or the reasoning/razonamiento panel ('abre el "
        . "panel de chat', 'muéstrame la cola', 'oculta el razonamiento') → set_panel; turn AUTONOMOUS mode on/off "
        . "('prende/apaga el modo autónomo', 'pausa NEURU') → set_autonomous; SCAN the fleet now ('escanea', 'barre la "
        . "flota') → scan_fleet. "
        . "UI-COMMAND RULE — CRITICAL: a UI command (panels, autonomous mode, scan, open/close x-ray) is NEVER a node or "
        . "a data question. NEVER search for a node, NEVER call node_report/node_xray for 'cola/chat/razonamiento/panel', "
        . "NEVER say you can't. Just call the matching UI tool and reply with ONE very short confirmation (e.g. 'Listo, "
        . "ahí está la cola.'). Do not explain, do not ramble. "
        . "bandwidth/talkers → bandwidth_top; traffic by country → traffic_by_country; anomalies or "
        . "threats → anomalies; 'can host A reach IP B?' → reachability; which routers route to X → route_lookup; "
        . "SHOW the network MAP / topology ('muéstrame el mapa/la topología', 'el segmento del core router', 'el "
        . "segmento 192.168.2.0') → show_topology (opens the interactive 3D map; close_xray closes it too). "
        . "SHOW LIVE TRAFFIC of a device/interface ('muéstrame el tráfico en vivo de la interfaz 1 del core router', "
        . "'el tráfico del core router') → show_traffic{node,interface?} (animated laser view; close_xray closes it). "
        . "SHOW CONTAINERS ('muéstrame los contenedores', 'los contenedores del nodo X', 'el contenedor mysql') → "
        . "show_containers{node?,container?} (3D layer; close_xray closes it). ANY question about a container "
        . "(size/volume/health/traffic — 'cuánto pesa el volumen de X', 'qué contenedor está más grande') → container_report{container}. "
        . "ONLY use run_show_command when they want a CLI probe FROM a specific device ('traceroute desde el core "
        . "router a X', 'ping from <node>'). "
        . "'whose IP is this / which router does this IP belong to / is this IP monitored' → locate_ip (a ROUTER "
        . "INTERFACE IP counts as monitored — NEVER say an IP is not monitored without calling locate_ip first). "
        . "MEMORY: the request includes a `memory` list of facts NEURU has already LEARNED (network topology, IP "
        . "ownership, the operator's corrections and preferences). TREAT IT AS KNOWN TRUTH — use it to answer directly "
        . "instead of starting from zero, and prefer a learned correction over a fresh guess. "
        . "route changes → route_drift; database health / replication lag / tuning → database_report; "
        . "inspect a device via a read-only CLI command (show/print/config read, e.g. '/system resource print', "
        . "'show ip route'), OR run a probe FROM a named device ('traceroute desde el core router a X', 'ping from "
        . "<node>') → run_show_command. "
        . "The tools return raw data — YOU turn it into a clear, natural spoken answer. "
        . "NODE NAMES: pass the node/router EXACTLY as the operator said it (e.g. 'main server 1', 'core router', "
        . "'sg mikrotik') — NEURU resolves spoken/fuzzy names to the real node, so never refuse over the wording. "
        . "If a tool replies 'node not found', call list_nodes to get the real names and retry — do NOT give up. "
        . "EXTERNAL hosts: for a public domain or IP that is NOT one of the monitored nodes (e.g. google.com), do "
        . "NOT use node_report; use reachability with the destination IP. "
        . "LANGUAGE — CRITICAL, NEVER MIX LANGUAGES: NEURU serves operators worldwide. Detect the operator's "
        . "language from their FIRST utterance and speak ONLY that one language for the ENTIRE call (Spanish, "
        . "English, Portuguese, French, German, Italian, Dutch, Hindi, Japanese, and more). If unclear, default to "
        . "Spanish. Do NOT switch or blend languages mid-conversation. The ask_neuru tool may return text in a "
        . "DIFFERENT language than the operator's — you MUST fully TRANSLATE its content into the operator's "
        . "language before speaking; never read back mixed-language text. Keep IPs, hostnames and numbers as-is. "
        . "When you call ask_neuru, pass the operator's question in their own words. "
        . "BEFORE you call ask_neuru, say ONE short sentence (in the operator's language) about what you're about "
        . "to check so they know you're working and the call didn't drop. "
        . "Keep spoken answers concise and conversational; offer to go deeper. You never invent data.";
}

// Build the assistant spec. $llm: 'byo' (Phase A, the account's own model) or a
// ['provider'=>'custom-llm','url'=>litellm,'model'=>..,'key'=>vkey] for Phase B metering.
function nm_vapi_assistant_spec($conn, $llm = 'byo'): array {
    $base = nm_vapi_public_base($conn);
    // timeoutSeconds: the ask_neuru round-trip (VAPI cloud → NEURU → chat flow → LiteLLM → tool callback → back)
    // is slower than VAPI's 20s default when the answer needs a tool (anomalies, node report, routing…), which
    // caused "No result returned". 45s covers the real-world latency; the 7s delayed filler covers the wait.
    $server = ['url' => $base . '/autopilotv2_vapi.php?ep=ask', 'secret' => nm_vapi_tool_secret($conn), 'timeoutSeconds' => 45];
    $model = [
        'provider' => 'openai',
        'model'    => 'gpt-4o',
        'messages' => [['role' => 'system', 'content' => nm_vapi_system_prompt()]],
        'tools'    => nm_vapi_tool_defs(),
    ];
    if (is_array($llm) && ($llm['provider'] ?? '') === 'custom-llm') {   // Phase B: meter tokens via LiteLLM
        $model['provider'] = 'custom-llm';
        $model['url']      = $llm['url'];
        $model['model']    = $llm['model'] ?? 'neuru';
    }
    return [
        'name'         => 'NEURU Commander',
        // Wait for the operator to speak first → NEURU adopts THEIR language from the start (no English
        // greeting priming a language, which was causing half-Spanish/half-English replies).
        'firstMessage'     => '',
        'firstMessageMode' => 'assistant-waits-for-user',
        // MULTILINGUAL transcriber — the operator may speak Spanish or English; the default VAPI
        // transcriber is English-only, so Spanish speech was never heard. 'multi' handles both + code-switching.
        'transcriber'  => ['provider' => 'deepgram', 'model' => 'nova-2', 'language' => 'multi'],
        'model'        => $model,
        'server'       => $server,   // where tool calls + reports are POSTed
    ];
}

// Create or update the assistant on the customer's VAPI account. WRITES to their account
// → callers MUST have explicit operator consent. Returns [ok:bool, id:string, err:string].
function nm_vapi_provision_assistant($conn, $llm = 'byo'): array {
    if (nm_vapi_public_base($conn) === '') return ['ok' => false, 'id' => '', 'err' => 'no public base URL — VAPI cannot reach this NEURU for tool calls'];
    $spec = nm_vapi_assistant_spec($conn, $llm);
    // A stored id must look like a VAPI id (UUID) to be PATCH-able — a hand-typed value like
    // "NEURU" is not, so skip straight to CREATE instead of erroring on it.
    $id = nm_vapi_get($conn, 'vapi_assistant_id', '');
    $looksId = (bool)preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $id);
    if ($id !== '' && $looksId) {
        [$code, $json, $err] = nm_vapi_api($conn, 'PATCH', 'assistant/' . rawurlencode($id), $spec);
        if ($code >= 200 && $code < 300) return ['ok' => true, 'id' => $id, 'err' => ''];
        // fall through to CREATE on a bad/stale id (400/404); a real server error is reported
        if ($code !== 404 && $code !== 400) return ['ok' => false, 'id' => $id, 'err' => $err ?: ('vapi http ' . $code . ' ' . json_encode($json))];
    }
    [$code, $json, $err] = nm_vapi_api($conn, 'POST', 'assistant', $spec);
    if ($code >= 200 && $code < 300 && !empty($json['id'])) {
        nm_vapi_set($conn, 'vapi_assistant_id', (string)$json['id']);
        return ['ok' => true, 'id' => (string)$json['id'], 'err' => ''];
    }
    return ['ok' => false, 'id' => '', 'err' => $err ?: ('vapi http ' . $code . ' ' . json_encode($json))];
}

}  // function_exists guard
