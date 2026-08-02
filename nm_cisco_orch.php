<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Cisco Orchestrator engine (F4).
//   · Config backup / versioning / diff / drift — REUSES nm_confmgr helpers
//     (nm_cm_ssh_fetch, nm_cm_normalize, nm_cm_diff, nm_cm_vendor) so we don't
//     reinvent SSH exec or diffing; stores Cisco versions in nm_cisco_config.
//   · Safe-Apply (commit-confirm + auto-rollback) modelled on nm_mtfw's pattern,
//     but Cisco-native per platform:
//       - ios / iosxe / asa → armed `reload in <win>` (unsaved change reverts on
//         reload → anti-lockout); Keep = `reload cancel` + `write memory`.
//       - iosxr            → native `commit confirmed <win> minutes`; Keep = `commit`.
//       - nxos             → `checkpoint` before change; no timer → operator Keep/Revert.
//   · Builders are pure string functions (unit-testable without hardware). The live
//     apply uses nm_cm_ssh_fetch; because interactive `reload in` confirm prompts vary
//     by IOS train, live push is EXPERIMENTAL and must be validated on real gear — the
//     dry-run preview is always safe. WLC/AireOS is out of scope (→ WiFi Control Center).
//
// See docs/NEURU_CISCO_SUITE_PLAN.md (F4).
// ─────────────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/nm_confmgr.php';   // nm_cm_ssh_fetch / nm_cm_normalize / nm_cm_diff / nm_cm_vendor / nm_cm_ensure
require_once __DIR__ . '/nm_secrets.php';   // nm_ssh_resolve
require_once __DIR__ . '/nm_cisco.php';     // nm_cisco_nodes / nm_cisco_class

if (!function_exists('nm_cisco_orch_platform')) {

    // Best-effort Cisco platform from hw_model/name → drives Safe-Apply syntax.
    function nm_cisco_orch_platform(array $n): string {
        $s = strtolower((string)($n['hw_model'] ?? '') . ' ' . (string)($n['display_name'] ?? ''));
        if (strpos($s, 'xr') !== false || strpos($s, 'ncs') !== false || strpos($s, 'asr9') !== false) return 'iosxr';
        if (strpos($s, 'nexus') !== false || strpos($s, 'nx-os') !== false || preg_match('/n[579]k/', $s)) return 'nxos';
        if (strpos($s, 'asa') !== false || strpos($s, 'firepower') !== false || strpos($s, 'ftd') !== false) return 'asa';
        if (strpos($s, 'ios-xe') !== false || strpos($s, 'iosxe') !== false
            || strpos($s, 'isr4') !== false || strpos($s, 'isr 4') !== false
            || strpos($s, 'asr1') !== false || strpos($s, 'asr 1') !== false
            || strpos($s, 'c9') !== false || strpos($s, 'cat9') !== false || strpos($s, 'catalyst 9') !== false
            || preg_match('/\b9[2345]00\b/', $s)) return 'iosxe';
        return 'ios';
    }

    // Backup command vendor key (reuse nm_config_vendors seeds from nm_confmgr).
    function nm_cisco_orch_vendor_key(string $platform): string {
        if ($platform === 'asa')  return 'cisco_asa';
        if ($platform === 'nxos') return 'cisco_nxos';
        return 'cisco_ios';
    }

    // Cisco nodes eligible for the Orchestrator (routers/switches/firewalls; NOT wlc).
    function nm_cisco_orch_nodes($conn): array {
        $out = [];
        foreach (nm_cisco_nodes($conn) as $n) {
            $cls = $n['cisco_class'] ?? '';
            if (!in_array($cls, ['router','switch','firewall'], true)) continue;
            $n['platform'] = nm_cisco_orch_platform($n);
            $out[] = $n;
        }
        return $out;
    }

    // ── Config backup / versioning (reuse nm_cm_normalize + nm_cm_diff) ───────
    function nm_cisco_orch_latest($conn, int $nid): ?array {
        try {
            $st = $conn->prepare("SELECT version,sha256,added,removed,captured_at FROM nm_cisco_config
                                  WHERE node_id=? ORDER BY version DESC LIMIT 1");
            $st->bind_param('i', $nid); $st->execute();
            $r = $st->get_result()->fetch_assoc(); $st->close();
            return $r ?: null;
        } catch (\Throwable $e) { return null; }
    }

    function nm_cisco_orch_versions($conn, int $nid, int $limit = 20): array {
        $out = [];
        try {
            $st = $conn->prepare("SELECT id,version,sha256,added,removed,captured_at FROM nm_cisco_config
                                  WHERE node_id=? ORDER BY version DESC LIMIT ?");
            $st->bind_param('ii', $nid, $limit); $st->execute();
            $res = $st->get_result();
            while ($x = $res->fetch_assoc()) $out[] = $x;
            $st->close();
        } catch (\Throwable $e) {}
        return $out;
    }

    function nm_cisco_orch_config_text($conn, int $id): ?string {
        try {
            $st = $conn->prepare("SELECT config_text FROM nm_cisco_config WHERE id=?");
            $st->bind_param('i', $id); $st->execute();
            $st->bind_result($t); $ok = $st->fetch(); $st->close();
            return $ok ? (string)$t : null;
        } catch (\Throwable $e) { return null; }
    }

    // Interactive Cisco config fetch — handles privileged-exec (enable) for IOS/ASA/NX-OS
    // and the AireOS secondary login, via scripts/nm_cisco_ssh.py. Works from a raw SSH
    // array (host/port/username/password/private_key), so BOTH the node-based Orchestrator
    // AND the device-based Config Manager can use it. Creds go through the ENVIRONMENT
    // (never argv). Returns ['ok','config'|'error'].
    function nm_cisco_ssh_run(array $ssh, string $platform, ?string $cmd = null, ?string $enable = null): array {
        if (empty($ssh['username']) || (empty($ssh['password']) && empty($ssh['private_key'])))
            return ['ok'=>false, 'error'=>'SSH credential incomplete (empty username or secret).'];
        $scr = __DIR__ . '/scripts/nm_cisco_ssh.py';
        if (!is_file($scr)) return ['ok'=>false, 'error'=>'nm_cisco_ssh.py missing'];
        $env = [
            'NM_SSH_HOST'    => (string)($ssh['host'] ?? ''),
            'NM_SSH_PORT'    => (string)($ssh['port'] ?? 22),
            'NM_SSH_USER'    => (string)($ssh['username'] ?? ''),
            'NM_SSH_PASS'    => (string)($ssh['password'] ?? ''),
            'NM_SSH_KEY'     => (string)($ssh['private_key'] ?? ''),
            'NM_SSH_TIMEOUT' => '40',
            'NM_CISCO_PLATFORM' => $platform,
            'NM_CISCO_CMD'   => (string)($cmd ?? ''),
            'NM_CISCO_ENABLE'=> (string)($enable ?? ''),
            'NM_PYLIBS'      => getenv('NM_PYLIBS') ?: '/home/hmiranda/netmon-pylibs',
            'PATH'           => getenv('PATH') ?: '/usr/bin:/bin',
        ];
        $descr = [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']];
        $proc = @proc_open(['/usr/bin/python3', $scr], $descr, $pipes, null, $env);
        if (!is_resource($proc)) return ['ok'=>false, 'error'=>'could not launch fetcher'];
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]); fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]); fclose($pipes[2]);
        proc_close($proc);
        $j = json_decode(trim($stdout), true);
        if (!is_array($j)) return ['ok'=>false, 'error'=>'fetcher returned no JSON'.($stderr?(': '.substr($stderr,0,200)):'')];
        return $j;
    }

    // Node-based convenience wrapper (Orchestrator).
    function nm_cisco_ssh_fetch($conn, int $nid, string $platform, ?string $cmd = null, ?string $enable = null): array {
        $ssh = nm_ssh_resolve($conn, $nid);
        if (!$ssh) return ['ok'=>false, 'error'=>'No SSH credential for this node (set one in Config / Nodes).'];
        return nm_cisco_ssh_run($ssh, $platform, $cmd, $enable);
    }

    // Fetch running-config over SSH (interactive: enable-aware), normalize, and store
    // a new version only if changed.
    function nm_cisco_orch_backup($conn, array $node): array {
        $nid = (int)$node['id'];
        $platform = nm_cisco_orch_platform($node);

        try { nm_cm_ensure($conn); } catch (\Throwable $e) {}
        $vk = nm_cisco_orch_vendor_key($platform);
        $vendor = function_exists('nm_cm_vendor') ? nm_cm_vendor($conn, $vk) : null;
        $ignore = $vendor['ignore_regex'] ?? '';

        $r = nm_cisco_ssh_fetch($conn, $nid, $platform, 'show running-config');
        if (empty($r['ok'])) return ['ok'=>false, 'error'=>($r['error'] ?? 'SSH fetch failed')];
        $raw = (string)($r['config'] ?? '');

        $norm = function_exists('nm_cm_normalize') ? nm_cm_normalize($raw, $ignore) : $raw;
        $sha  = hash('sha256', $norm);
        $latest = nm_cisco_orch_latest($conn, $nid);
        if ($latest && $latest['sha256'] === $sha) {
            return ['ok'=>true, 'changed'=>false, 'version'=>(int)$latest['version']];
        }

        $prevText = '';
        if ($latest) {
            // fetch the previous full text for a diff
            try {
                $st = $conn->prepare("SELECT config_text FROM nm_cisco_config WHERE node_id=? ORDER BY version DESC LIMIT 1");
                $st->bind_param('i', $nid); $st->execute(); $st->bind_result($pt); $st->fetch(); $st->close();
                $prevText = (string)$pt;
            } catch (\Throwable $e) {}
        }
        $added = 0; $removed = 0;
        if ($prevText !== '' && function_exists('nm_cm_diff')) {
            $d = nm_cm_diff($prevText, $norm);
            $added = (int)($d['added'] ?? 0); $removed = (int)($d['removed'] ?? 0);
        }
        $ver = ($latest ? (int)$latest['version'] : 0) + 1;
        $now = gmdate('Y-m-d H:i:s');
        try {
            $st = $conn->prepare("INSERT INTO nm_cisco_config (node_id,version,sha256,config_text,added,removed,captured_at)
                                  VALUES (?,?,?,?,?,?,?)");
            // types: node_id i, version i, sha256 s, config_text s, added i, removed i, captured_at s
            $st->bind_param('iissiis', $nid, $ver, $sha, $norm, $added, $removed, $now);
            $st->execute(); $st->close();
        } catch (\Throwable $e) { return ['ok'=>false, 'error'=>'store failed']; }

        // keep last 20 versions
        try { $conn->query("DELETE FROM nm_cisco_config WHERE node_id=$nid AND version <= " . ($ver - 20)); } catch (\Throwable $e) {}
        if (function_exists('nm_audit')) { try { nm_audit($conn, 'cisco.orch.backup', ['target_type'=>'node','target_id'=>$nid,'details'=>['version'=>$ver,'added'=>$added,'removed'=>$removed]]); } catch (\Throwable $e) {} }
        return ['ok'=>true, 'changed'=>true, 'version'=>$ver, 'first'=>!$latest, 'added'=>$added, 'removed'=>$removed];
    }

    // Diff between two stored versions (or latest vs previous).
    function nm_cisco_orch_diff($conn, int $nid, ?int $vFrom = null, ?int $vTo = null): array {
        $vers = nm_cisco_orch_versions($conn, $nid, 100);
        if (count($vers) < 1) return ['ok'=>false, 'error'=>'no versions'];
        $byv = [];
        foreach ($vers as $v) $byv[(int)$v['version']] = (int)$v['id'];
        $vTo   = $vTo   ?? (int)$vers[0]['version'];
        $vFrom = $vFrom ?? ($vTo - 1);
        $tTo   = isset($byv[$vTo])   ? nm_cisco_orch_config_text($conn, $byv[$vTo])   : null;
        $tFrom = isset($byv[$vFrom]) ? nm_cisco_orch_config_text($conn, $byv[$vFrom]) : '';
        if ($tTo === null) return ['ok'=>false, 'error'=>'version not found'];
        $d = function_exists('nm_cm_diff') ? nm_cm_diff((string)$tFrom, $tTo) : ['diff'=>'', 'added'=>0, 'removed'=>0];
        return ['ok'=>true, 'from'=>$vFrom, 'to'=>$vTo] + $d;
    }

    // ── Safe-Apply (commit-confirm) — pure builders ──────────────────────────
    // Returns the exact command plan; steps=arm+change, keep=confirm, revert=rollback now.
    function nm_cisco_saf_plan(string $platform, array $lines, int $window, string $token): array {
        $lines = array_values(array_filter(array_map(fn($l) => rtrim((string)$l), $lines), fn($l) => $l !== ''));
        $win = max(1, min(60, $window));
        if ($platform === 'iosxr') {
            return [
                'method' => 'commit', 'platform' => $platform, 'window' => $win,
                'steps'  => array_merge(['configure terminal'], $lines, ["commit confirmed {$win} minutes", 'end']),
                'keep'   => ['configure terminal', 'commit', 'end'],
                'revert' => ['rollback configuration last 1'],
                'desc'   => "IOS-XR native 'commit confirmed {$win}m' — auto-rolls back unless you Keep (final commit).",
                'timed'  => true,
            ];
        }
        if ($platform === 'nxos') {
            $cp = 'neuru_' . $token;
            return [
                'method' => 'checkpoint', 'platform' => $platform, 'window' => $win,
                'steps'  => array_merge(["checkpoint {$cp}", 'configure terminal'], $lines, ['end']),
                'keep'   => ['copy running-config startup-config', "no checkpoint {$cp}"],
                'revert' => ["rollback running-config checkpoint {$cp}", "no checkpoint {$cp}"],
                'desc'   => "NX-OS checkpoint '{$cp}' taken before the change. No auto-timer — Keep saves, Revert rolls back.",
                'timed'  => false,
            ];
        }
        // ios / iosxe / asa → armed reload (unsaved change reverts on reload)
        $armReload = ($platform === 'asa') ? "reload in {$win} noconfirm" : "reload in {$win}";
        return [
            'method' => 'reload', 'platform' => $platform, 'window' => $win,
            'steps'  => array_merge([$armReload, 'configure terminal'], $lines, ['end']),
            'keep'   => ['reload cancel', 'write memory'],
            'revert' => [($platform === 'asa') ? 'reload in 1 noconfirm' : 'reload in 1'],
            'desc'   => "Armed 'reload in {$win}m'. The change is NOT saved, so if you don't Keep in time the device reloads to its saved config and the change vanishes (anti-lockout).",
            'timed'  => true,
        ];
    }

    // Human-readable preview text of the whole sequence (for the dry-run panel).
    function nm_cisco_saf_preview(array $plan): string {
        $out  = "# METHOD: " . strtoupper($plan['method']) . " (" . $plan['platform'] . ")\n";
        $out .= "# " . $plan['desc'] . "\n\n";
        $out .= "## APPLY (armed):\n" . implode("\n", $plan['steps']) . "\n\n";
        $out .= "## KEEP (confirm):\n" . implode("\n", $plan['keep']) . "\n\n";
        $out .= "## REVERT (rollback now):\n" . implode("\n", $plan['revert']) . "\n";
        return $out;
    }

    // Live apply — EXPERIMENTAL (interactive confirm prompts vary by IOS train).
    function nm_cisco_saf_apply($conn, array $node, array $lines, int $window, ?int $uid = null): array {
        $nid = (int)$node['id'];
        $platform = nm_cisco_orch_platform($node);
        $ssh = nm_ssh_resolve($conn, $nid);
        if (!$ssh || empty($ssh['username'])) return ['ok'=>false, 'error'=>'No SSH credential for this node.'];
        if (!$lines) return ['ok'=>false, 'error'=>'No configuration lines to apply.'];

        $token = 'co' . substr(bin2hex(random_bytes(10)), 0, 18);
        $plan  = nm_cisco_saf_plan($platform, $lines, $window, $token);

        $script = implode("\n", $plan['steps']);
        $r = nm_cm_ssh_fetch($ssh, $script, 45);
        $out = (string)($r['config'] ?? '');
        $applied = !empty($r['ok']) && stripos($out, '% Invalid') === false && stripos($out, '% Incomplete') === false;
        if (!$applied) return ['ok'=>false, 'error'=>'Apply not confirmed by device', 'output'=>substr($out, 0, 600), 'plan'=>$plan];

        $now = gmdate('Y-m-d H:i:s');
        try {
            $keep = json_encode($plan['keep']); $rev = json_encode($plan['revert']);
            $st = $conn->prepare("INSERT INTO nm_cisco_orch_pending
                (token,node_id,platform,method,keep_cmds,revert_cmds,window_min,status,created_at,created_by)
                VALUES (?,?,?,?,?,?,?, 'armed', ?, ?)");
            // types: token s, node_id i, platform s, method s, keep s, revert s,
            //        window_min i, created_at s(datetime), created_by i
            $st->bind_param('sissssisi', $token, $nid, $platform, $plan['method'], $keep, $rev, $plan['window'], $now, $uid);
            $st->execute(); $st->close();
        } catch (\Throwable $e) {}
        if (function_exists('nm_audit')) { try { nm_audit($conn, 'cisco.orch.apply', ['target_type'=>'node','target_id'=>$nid,'details'=>['token'=>$token,'method'=>$plan['method'],'lines'=>count($lines)]]); } catch (\Throwable $e) {} }
        return ['ok'=>true, 'token'=>$token, 'plan'=>$plan, 'timed'=>$plan['timed']];
    }

    function nm_cisco_orch_pending_get($conn, string $token): ?array {
        try {
            $st = $conn->prepare("SELECT token,node_id,platform,method,keep_cmds,revert_cmds,window_min,status,created_at
                                  FROM nm_cisco_orch_pending WHERE token=?");
            $st->bind_param('s', $token); $st->execute();
            $r = $st->get_result()->fetch_assoc(); $st->close();
            return $r ?: null;
        } catch (\Throwable $e) { return null; }
    }

    function nm_cisco_orch_pending_list($conn, int $nid): array {
        $out = [];
        try {
            $st = $conn->prepare("SELECT token,platform,method,window_min,status,created_at FROM nm_cisco_orch_pending
                                  WHERE node_id=? AND status='armed' ORDER BY created_at DESC");
            $st->bind_param('i', $nid); $st->execute();
            $res = $st->get_result();
            while ($x = $res->fetch_assoc()) $out[] = $x;
            $st->close();
        } catch (\Throwable $e) {}
        return $out;
    }

    function nm_cisco_saf_finalize($conn, array $node, string $token, string $action): array {
        $p = nm_cisco_orch_pending_get($conn, $token);
        if (!$p || (int)$p['node_id'] !== (int)$node['id']) return ['ok'=>false, 'error'=>'unknown token'];
        if ($p['status'] !== 'armed') return ['ok'=>false, 'error'=>'already ' . $p['status']];
        $cmds = json_decode((string)($action === 'keep' ? $p['keep_cmds'] : $p['revert_cmds']), true);
        if (!is_array($cmds) || !$cmds) return ['ok'=>false, 'error'=>'no commands'];
        $ssh = nm_ssh_resolve($conn, (int)$node['id']);
        if (!$ssh) return ['ok'=>false, 'error'=>'no ssh'];
        $r = nm_cm_ssh_fetch($ssh, implode("\n", $cmds), 40);
        if (empty($r['ok'])) return ['ok'=>false, 'error'=>($r['error'] ?? 'ssh failed')];
        $status = ($action === 'keep') ? 'kept' : 'reverted';
        try {
            $st = $conn->prepare("UPDATE nm_cisco_orch_pending SET status=? WHERE token=?");
            $st->bind_param('ss', $status, $token); $st->execute(); $st->close();
        } catch (\Throwable $e) {}
        if (function_exists('nm_audit')) { try { nm_audit($conn, 'cisco.orch.' . $action, ['target_type'=>'node','target_id'=>(int)$node['id'],'details'=>['token'=>$token]]); } catch (\Throwable $e) {} }
        return ['ok'=>true, 'status'=>$status];
    }
}
