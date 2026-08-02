<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — MikroTik Firewall Control engine (backs mtfw.php). Reads /ip firewall
// filter · nat · address-list from a RouterOS router, lets the UI build rules as
// objects, previews the EXACT commands (dry-run), and injects them with an
// anti-lockout SAFE-APPLY: before the change we install a RouterOS scheduler that
// auto-reverts in N minutes; the operator clicks "Keep" to cancel it — if a rule
// locks out SSH, the router reverts itself and access returns (commit-confirm).
// Strict per-field validation (RouterOS command-injection safe). RBAC: 'mtfw'.
// Reuses nm_router.php SSH plumbing + nm_audit.
// ─────────────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/nm_router.php';

if (!function_exists('nm_mtfw_ensure')) {

    function nm_mtfw_tables(): array { return ['filter','nat','mangle']; }
    function nm_mtfw_chains(): array { return ['input','forward','output','srcnat','dstnat','prerouting','postrouting']; }
    function nm_mtfw_actions(): array { return ['accept','drop','reject','log','return','jump','passthrough','fasttrack-connection',
        'masquerade','dst-nat','src-nat','redirect','netmap','add-src-to-address-list','add-dst-to-address-list','tarpit']; }
    function nm_mtfw_protocols(): array { return ['','tcp','udp','icmp','icmpv6','gre','esp','ah','ipsec-esp','ipsec-ah','ospf','vrrp','sctp','udp-lite','137','47']; }
    function nm_mtfw_states(): array { return ['new','established','related','invalid','untracked']; }

    function nm_mtfw_ensure($conn): void {
        if (!($conn instanceof mysqli)) return;
        try {
            $conn->query("CREATE TABLE IF NOT EXISTS nm_mtfw_snapshots (
                id INT AUTO_INCREMENT PRIMARY KEY, node_id INT NOT NULL, fw_table VARCHAR(10) NOT NULL DEFAULT 'filter',
                taken_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, rule_count INT DEFAULT 0,
                rules_json MEDIUMTEXT NULL, reason VARCHAR(64) NULL, created_by INT NULL,
                KEY idx_node (node_id, fw_table, taken_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
            $conn->query("CREATE TABLE IF NOT EXISTS nm_mtfw_pending (
                token VARCHAR(24) PRIMARY KEY, node_id INT NOT NULL, fw_table VARCHAR(10) NOT NULL,
                op VARCHAR(10) NOT NULL, cmd TEXT NULL, revert TEXT NULL, window_min INT DEFAULT 2,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, created_by INT NULL, status VARCHAR(12) DEFAULT 'armed'
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        } catch (\Throwable $e) {}
    }

    function nm_mtfw_supported(array $node): bool {
        return in_array(strtolower((string)($node['os_icon'] ?? '')), ['mikrotik','routeros'], true);
    }
    function nm_mtfw_ssh($conn, array $node): ?array {
        if (!nm_mtfw_supported($node)) return null;
        if (!function_exists('nm_cm_ssh_fetch')) require_once __DIR__ . '/nm_confmgr.php';
        $ssh = nm_ssh_resolve($conn, (int)$node['id']);
        if (!$ssh || empty($ssh['username']) || (empty($ssh['password']) && empty($ssh['private_key']))) return null;
        return $ssh;
    }

    // ── READ ────────────────────────────────────────────────────────────────────
    // print terse (all props, ordered) + a parallel .id list (terse omits .id).
    function nm_mtfw_fetch($conn, array $node, string $table = 'filter'): array {
        if (!in_array($table, nm_mtfw_tables(), true)) return ['ok'=>false, 'error'=>'bad table'];
        $ssh = nm_mtfw_ssh($conn, $node);
        if (!$ssh) return ['ok'=>false, 'error'=>'MikroTik SSH credential required'];
        $path = "/ip firewall $table";
        // terse gives config props but NOT the .id/counters. The .id is what edit/remove need, so we
        // fetch it as BULLETPROOF as possible: `:put [find]` prints the WHOLE ordered id set on ONE
        // line ("*A;*2;*1F"), which no per-rule line can misalign or drop (the old per-line format let
        // one malformed line shift the whole mapping → a later rule got no id → "remove null").
        // Counters are cosmetic (hit bars) → best-effort per-rule after; a bad counter line only zeroes
        // that one rule's bar, never touches ids.
        $cmd = "$path print terse without-paging; :put \"NM_IDS\"; :put [$path find]; :put \"NM_CTR\"; "
             . ":foreach r in=[$path find] do={ :put ([$path get \$r bytes] . \"|\" . [$path get \$r packets]) }; :put \"NM_END\"";
        $f = nm_cm_ssh_fetch($ssh, $cmd, 25);
        if (empty($f['ok'])) return ['ok'=>false, 'error'=>$f['error'] ?? 'SSH failed'];
        $raw = (string)$f['config'];
        [$terse, $rest1] = array_pad(explode('NM_IDS', $raw, 2), 2, '');
        [$idsRaw, $ctrRaw] = array_pad(explode('NM_CTR', $rest1, 2), 2, '');
        $ctrRaw = explode('NM_END', $ctrRaw, 2)[0];
        // ids: one clean line of "*A;*2;*1F" (tolerate space- or ;-separated); keep only real ids.
        $ids = [];
        foreach (preg_split('/[;\s]+/', trim($idsRaw)) as $tok) {
            $tok = trim($tok); if ($tok !== '' && $tok[0] === '*' && preg_match('/^\*[0-9A-Fa-f]+$/', $tok)) $ids[] = $tok;
        }
        // counters: one "bytes|packets" line per rule, in the same find-order (cosmetic).
        $ctr = [];
        foreach (preg_split('/\r?\n/', $ctrRaw) as $ln) {
            $ln = trim($ln); if ($ln === '' || strpos($ln, '|') === false) continue;
            $p = explode('|', $ln); $ctr[] = ['bytes'=>(int)($p[0] ?? 0), 'packets'=>(int)($p[1] ?? 0)];
        }
        $rules = nm_mtfw_parse_terse($terse);
        foreach ($rules as $i => &$r) {
            if (isset($ids[$i]))  $r['id'] = $ids[$i];
            if (isset($ctr[$i])) { $r['bytes'] = $ctr[$i]['bytes']; $r['packets'] = $ctr[$i]['packets']; }
        }
        unset($r);
        return ['ok'=>true, 'table'=>$table, 'rules'=>$rules, 'count'=>count($rules)];
    }
    function nm_mtfw_fetch_addrlists($conn, array $node): array {
        $ssh = nm_mtfw_ssh($conn, $node); if (!$ssh) return ['ok'=>false];
        $f = nm_cm_ssh_fetch($ssh, "/ip firewall address-list print terse without-paging", 20);
        if (empty($f['ok'])) return ['ok'=>false];
        $out = []; foreach (nm_mtfw_parse_terse((string)$f['config']) as $r) {
            $ln = $r['props']['list'] ?? ''; if ($ln === '') continue;
            $out[$ln] = ($out[$ln] ?? 0) + 1;
        }
        return ['ok'=>true, 'lists'=>$out];
    }
    // Router interfaces + their interface-list membership (for the Packet Tracer's
    // In-interface picker + accurate in-interface-list rule resolution).
    function nm_mtfw_fetch_interfaces($conn, array $node): array {
        $ssh = nm_mtfw_ssh($conn, $node); if (!$ssh) return ['ok'=>false,'error'=>'MikroTik SSH credential required'];
        $r = nm_cm_ssh_fetch($ssh, "/interface print terse without-paging", 20);
        if (empty($r['ok'])) return ['ok'=>false,'error'=>$r['error'] ?? 'SSH failed'];
        $ifaces = [];
        foreach (nm_mtfw_parse_terse((string)$r['config']) as $row) {
            $n = $row['props']['name'] ?? ''; if ($n === '') continue;
            $ifaces[$n] = ['name'=>$n, 'type'=>$row['props']['type'] ?? '', 'lists'=>[]];
        }
        $lm = nm_cm_ssh_fetch($ssh, "/interface list member print terse without-paging", 20);
        if (!empty($lm['ok'])) foreach (nm_mtfw_parse_terse((string)$lm['config']) as $row) {
            $ifn = $row['props']['interface'] ?? ''; $ln = $row['props']['list'] ?? '';
            if ($ifn !== '' && $ln !== '' && isset($ifaces[$ifn]) && !in_array($ln, $ifaces[$ifn]['lists'], true)) $ifaces[$ifn]['lists'][] = $ln;
        }
        return ['ok'=>true, 'interfaces'=>array_values($ifaces)];
    }
    // Address-list MEMBERS (list => [addresses]) — lets the Packet Tracer resolve
    // src/dst-address-list conditions for real instead of guessing.
    function nm_mtfw_addrlist_members($conn, array $node): array {
        $ssh = nm_mtfw_ssh($conn, $node); if (!$ssh) return [];
        $f = nm_cm_ssh_fetch($ssh, "/ip firewall address-list print terse without-paging", 20);
        if (empty($f['ok'])) return [];
        $out = [];
        foreach (nm_mtfw_parse_terse((string)$f['config']) as $r) {
            $ln = $r['props']['list'] ?? ''; $addr = $r['props']['address'] ?? '';
            if ($ln !== '' && $addr !== '') $out[$ln][] = $addr;
        }
        return $out;
    }

    // Parse RouterOS `print terse`: "<idx> <FLAGS> key=value key=\"quoted value\" ..."
    function nm_mtfw_parse_terse(string $raw): array {
        $rules = [];
        foreach (preg_split('/\r?\n/', $raw) as $line) {
            $line = rtrim($line); if (trim($line) === '' || strpos($line, 'NM_') === 0) continue;
            if (!preg_match('/^\s*(\d+)\s+(.*)$/', $line, $m)) continue;
            $idx = (int)$m[1]; $rest = $m[2];
            // leading uppercase flag letters (X disabled, D dynamic, I invalid, …) before first key=
            $flags = ''; if (preg_match('/^((?:[A-Z]\s*)+?)(?=[a-z0-9_.-]+=)/', $rest, $fm)) { $flags = str_replace(' ', '', $fm[1]); $rest = substr($rest, strlen($fm[1])); }
            $props = [];
            if (preg_match_all('/([a-z0-9_.\-]+)=(?:"([^"]*)"|(\S+))/', $rest, $pm, PREG_SET_ORDER)) {
                foreach ($pm as $p) $props[$p[1]] = ($p[2] !== '' || isset($p[3]) === false) ? $p[2] : ($p[3] ?? '');
            }
            $rules[] = [
                'idx'=>$idx, 'id'=>null, 'flags'=>$flags,
                'disabled'=>(strpos($flags,'X')!==false), 'dynamic'=>(strpos($flags,'D')!==false), 'invalid'=>(strpos($flags,'I')!==false),
                'chain'=>$props['chain'] ?? '', 'action'=>$props['action'] ?? '',
                'comment'=>$props['comment'] ?? '',
                'bytes'=>(int)($props['bytes'] ?? 0), 'packets'=>(int)($props['packets'] ?? 0),
                'props'=>$props,
            ];
        }
        return $rules;
    }

    // ── VALIDATION + COMMAND BUILDING (RouterOS-injection safe) ──────────────────
    // Sanitize a free-text value → strip quotes/semicolons/newlines, cap length.
    function nm_mtfw_clean_text(string $s, int $max = 120): string {
        $s = preg_replace('/[";\r\n\\\\]/', '', $s); return substr(trim($s), 0, $max);
    }
    function nm_mtfw_valid_ipspec(string $s): bool {
        $s = trim($s); if ($s === '') return true;
        foreach (explode(',', $s) as $part) { $part = trim($part);
            if (strpos($part, '-') !== false) { [$a,$b] = explode('-', $part, 2); if (!filter_var(trim($a),FILTER_VALIDATE_IP)||!filter_var(trim($b),FILTER_VALIDATE_IP)) return false; continue; }
            if (strpos($part, '/') !== false) { [$ip,$pfx] = explode('/', $part, 2); if (!filter_var($ip,FILTER_VALIDATE_IP)||!ctype_digit($pfx)||(int)$pfx>128) return false; continue; }
            if (!filter_var($part, FILTER_VALIDATE_IP)) return false;
        } return true;
    }
    function nm_mtfw_valid_ports(string $s): bool { $s=trim($s); return $s==='' || (bool)preg_match('/^[0-9,\-]+$/', $s); }
    function nm_mtfw_valid_name(string $s): bool { $s=trim($s); return $s==='' || (bool)preg_match('/^[A-Za-z0-9_.\- ]{1,64}$/', $s); }

    // Whitelisted field map: input key => [validator, routeros key]. Returns cleaned props or throws.
    function nm_mtfw_prep_props(array $in): array {
        $out = []; $err = [];
        $set = function($k, $v) use (&$out) { $v = trim((string)$v); if ($v !== '') $out[$k] = $v; };
        if (isset($in['chain']))   { $c=nm_mtfw_clean_text((string)$in['chain'],32); if($c!==''&&!nm_mtfw_valid_name($c)) $err[]='chain'; else $set('chain',$c); }
        if (isset($in['action']))  { $a=(string)$in['action']; if(!in_array($a,nm_mtfw_actions(),true)) $err[]='action'; else $set('action',$a); }
        if (isset($in['protocol'])){ $p=(string)$in['protocol']; if(!in_array($p,nm_mtfw_protocols(),true) && !ctype_digit($p)) $err[]='protocol'; else $set('protocol',$p); }
        foreach (['src-address','dst-address'] as $k) if (isset($in[$k])) { $v=(string)$in[$k]; if(!nm_mtfw_valid_ipspec($v)) $err[]=$k; else $set($k,$v); }
        foreach (['src-port','dst-port'] as $k) if (isset($in[$k])) { $v=(string)$in[$k]; if(!nm_mtfw_valid_ports($v)) $err[]=$k; else $set($k,$v); }
        foreach (['in-interface','out-interface','in-interface-list','out-interface-list','src-address-list','dst-address-list','jump-target','address-list'] as $k)
            if (isset($in[$k])) { $v=nm_mtfw_clean_text((string)$in[$k],64); if($v!==''&&!nm_mtfw_valid_name($v)) $err[]=$k; else $set($k,$v); }
        if (isset($in['connection-state'])) { $st=array_filter(array_map('trim',explode(',',(string)$in['connection-state']))); $bad=array_diff($st,nm_mtfw_states()); if($bad) $err[]='connection-state'; else if($st) $set('connection-state',implode(',',$st)); }
        if (isset($in['to-addresses'])) { $v=(string)$in['to-addresses']; if(!nm_mtfw_valid_ipspec($v)) $err[]='to-addresses'; else $set('to-addresses',$v); }
        if (isset($in['to-ports']))     { $v=(string)$in['to-ports']; if(!nm_mtfw_valid_ports($v)) $err[]='to-ports'; else $set('to-ports',$v); }
        if (isset($in['comment']))      $set('comment', nm_mtfw_clean_text((string)$in['comment'],120));
        if (isset($in['log']))          $set('log', !empty($in['log'])?'yes':'no');
        if (isset($in['log-prefix']))   $set('log-prefix', nm_mtfw_clean_text((string)$in['log-prefix'],32));
        if (isset($in['disabled']))     $set('disabled', !empty($in['disabled'])?'yes':'no');
        if ($err) return ['ok'=>false, 'error'=>'invalid: '.implode(', ',array_unique($err))];
        return ['ok'=>true, 'props'=>$out];
    }
    // props array → " key=\"value\"..." (all quoted+escaped; safe values already validated)
    function nm_mtfw_props_to_cmd(array $props): string {
        $frag = '';
        foreach ($props as $k => $v) { $v = str_replace('"','',$v); $frag .= ' '.$k.'="'.$v.'"'; }
        return $frag;
    }

    // Build the apply command + its revert. $op: add|set|toggle|remove. Returns
    // ['ok','cmd','revert','desc','tag'].
    function nm_mtfw_build($op, string $table, array $data, array $existing = []): array {
        $path = "/ip firewall $table";
        if ($op === 'add') {
            $prep = nm_mtfw_prep_props($data['props'] ?? []); if (empty($prep['ok'])) return $prep;
            $props = $prep['props']; if (empty($props['chain']) || empty($props['action'])) return ['ok'=>false,'error'=>'chain and action required'];
            $tag = 'nfw'.substr(bin2hex(random_bytes(4)),0,8);
            $props['comment'] = trim(($props['comment'] ?? '').' ['.$tag.']');   // tag for revert-by-comment
            $place = '';
            if (!empty($data['place_before']) && preg_match('/^\*[0-9A-F]+$/', $data['place_before'])) $place = ' place-before='.$data['place_before'];
            $cmd = "$path add".nm_mtfw_props_to_cmd($props).$place;
            $revert = "$path remove [find comment~\"$tag\"]";
            return ['ok'=>true, 'cmd'=>$cmd, 'revert'=>$revert, 'tag'=>$tag, 'desc'=>"add $table rule (".($props['action']).' '.($props['chain']).')'];
        }
        if ($op === 'set') {
            $id = (string)($data['id'] ?? ''); if (!preg_match('/^\*[0-9A-F]+$/', $id)) return ['ok'=>false,'error'=>'bad rule id'];
            $prep = nm_mtfw_prep_props($data['props'] ?? []); if (empty($prep['ok'])) return $prep;
            $props = $prep['props']; if (!$props) return ['ok'=>false,'error'=>'nothing to change'];
            $cmd = "$path set $id".nm_mtfw_props_to_cmd($props);
            // revert = restore old values of the changed keys
            $old = []; $ex = $existing['props'] ?? [];
            foreach ($props as $k=>$v) $old[$k] = $ex[$k] ?? '';
            $revert = "$path set $id".nm_mtfw_props_to_cmd($old);
            return ['ok'=>true, 'cmd'=>$cmd, 'revert'=>$revert, 'desc'=>"edit $table rule $id"];
        }
        if ($op === 'toggle') {
            $id = (string)($data['id'] ?? ''); if (!preg_match('/^\*[0-9A-F]+$/', $id)) return ['ok'=>false,'error'=>'bad rule id'];
            $enable = !empty($data['enable']);
            $cmd = "$path ".($enable?'enable':'disable')." $id";
            $revert = "$path ".($enable?'disable':'enable')." $id";
            return ['ok'=>true, 'cmd'=>$cmd, 'revert'=>$revert, 'desc'=>($enable?'enable':'disable')." $table rule $id"];
        }
        if ($op === 'remove') {
            $id = (string)($data['id'] ?? ''); if (!preg_match('/^\*[0-9A-F]+$/', $id)) return ['ok'=>false,'error'=>'bad rule id'];
            // re-add for revert (best-effort, same props, placed before the next rule)
            $props = $existing['props'] ?? []; unset($props['bytes'],$props['packets'],$props['.id']);
            $prep = nm_mtfw_prep_props($props); $re = !empty($prep['ok']) ? ("$path add".nm_mtfw_props_to_cmd($prep['props'])) : '';
            $cmd = "$path remove $id";
            return ['ok'=>true, 'cmd'=>$cmd, 'revert'=>$re, 'desc'=>"remove $table rule $id"];
        }
        if ($op === 'batch') {
            // inject a whole ordered ruleset as ONE unit (baseline firewall). All rules share a
            // tag so a single revert removes them all; an optional mgmt-IP is seeded first so the
            // operator's own access survives the "drop all other input" rule.
            $rules = $data['rules'] ?? []; if (!$rules) return ['ok'=>false,'error'=>'no rules'];
            $tag = 'nfw'.substr(bin2hex(random_bytes(4)),0,8); $cmds = [];
            if (!empty($data['mgmt_ip']) && filter_var($data['mgmt_ip'], FILTER_VALIDATE_IP)) {
                $mg = str_replace('"','',$data['mgmt_ip']);
                $cmds[] = "/ip firewall address-list add list=mgmt address=\"$mg\" comment=\"NEURU mgmt [$tag]\"";
            }
            foreach ($rules as $r) {
                $prep = nm_mtfw_prep_props($r); if (empty($prep['ok'])) return $prep;
                $props = $prep['props']; if (empty($props['chain']) || empty($props['action'])) return ['ok'=>false,'error'=>'each rule needs chain+action'];
                $props['comment'] = trim(($props['comment'] ?? '').' ['.$tag.']');
                $cmds[] = "$path add".nm_mtfw_props_to_cmd($props);
            }
            $cmd = implode('; ', $cmds);
            $revert = "$path remove [find comment~\"$tag\"]; /ip firewall address-list remove [find comment~\"$tag\"]";
            return ['ok'=>true, 'cmd'=>$cmd, 'revert'=>$revert, 'tag'=>$tag, 'desc'=>'inject '.count($rules).'-rule baseline firewall'];
        }
        return ['ok'=>false, 'error'=>'unknown op'];
    }

    // ── DRY RUN ───────────────────────────────────────────────────────────────────
    function nm_mtfw_dryrun(string $op, string $table, array $data, array $existing = []): array {
        $b = nm_mtfw_build($op, $table, $data, $existing);
        if (empty($b['ok'])) return $b;
        return ['ok'=>true, 'cmd'=>$b['cmd'], 'revert'=>$b['revert'], 'desc'=>$b['desc']];
    }

    // ── SAFE APPLY (auto-rollback commit-confirm) ────────────────────────────────
    function nm_mtfw_apply($conn, array $node, string $op, string $table, array $data, bool $safe = true, int $window = 2): array {
        nm_mtfw_ensure($conn);
        $ssh = nm_mtfw_ssh($conn, $node); if (!$ssh) return ['ok'=>false,'error'=>'MikroTik SSH credential required'];
        $existing = $data['existing'] ?? [];
        $b = nm_mtfw_build($op, $table, $data, $existing); if (empty($b['ok'])) return $b;
        $window = max(1, min(30, $window));
        // snapshot current table for undo/drift
        $cur = nm_mtfw_fetch($conn, $node, $table);
        if (!empty($cur['ok'])) nm_mtfw_snapshot_save($conn, (int)$node['id'], $table, $cur['rules'], 'pre-'.$op, (int)($data['uid'] ?? 0));

        $token = 'fw'.substr(bin2hex(random_bytes(8)),0,20);
        $schedName = 'neuru-'.$token;
        $seq = [];
        if ($safe && $b['revert'] !== '') {
            // Commit-confirm, robust design: the revert lives in a NAMED SCRIPT (one clean level of
            // quoting — no fragile triple-nesting inside the scheduler's on-event). A scheduler runs
            // that script once after $window, then removes BOTH itself and the script. "Keep" simply
            // deletes both so the revert can never fire. This is what fixes "Keep rolled back anyway".
            $src = str_replace('"','\\"', $b['revert']);                                  // escape quotes for source="…"
            $seq[] = "/system script add name=\"$schedName\" source=\"$src\"";
            $onEvent = "/system script run $schedName; /system scheduler remove [/system scheduler find name=$schedName]; /system script remove [/system script find name=$schedName]";
            $seq[] = "/system scheduler add name=\"$schedName\" interval={$window}m on-event=\"$onEvent\" comment=\"NEURU firewall auto-rollback\"";
        }
        $seq[] = $b['cmd'];
        $script = implode('; ', $seq);
        $res = nm_cm_ssh_fetch($ssh, $script.'; :put "NM_APPLIED"', 30);
        $applied = !empty($res['ok']) && strpos((string)$res['config'], 'NM_APPLIED') !== false;
        if (!$applied) {
            // apply failed → try to remove any scheduler + script we added
            if ($safe) @nm_cm_ssh_fetch($ssh, "/system scheduler remove [/system scheduler find name=\"$schedName\"]; /system script remove [/system script find name=\"$schedName\"]", 12);
            return ['ok'=>false, 'error'=>$res['error'] ?? 'apply failed on router'];
        }
        if ($safe && $b['revert'] !== '') {
            try { $st=$conn->prepare("INSERT INTO nm_mtfw_pending (token,node_id,fw_table,op,cmd,revert,window_min,created_by,status) VALUES (?,?,?,?,?,?,?,?,'armed')");
                $nid=(int)$node['id']; $uid=(int)($data['uid']??0); $st->bind_param('sisssssi',$token,$nid,$table,$op,$b['cmd'],$b['revert'],$window,$uid); $st->execute(); } catch (\Throwable $e) {}
        }
        if (function_exists('nm_audit')) { try { nm_audit($conn, 'mtfw.apply', ['target_type'=>'node','target_id'=>(int)$node['id'],'details'=>['op'=>$op,'table'=>$table,'safe'=>$safe,'cmd'=>$b['cmd']]]); } catch (\Throwable $e) {} }
        return ['ok'=>true, 'applied'=>true, 'safe'=>($safe && $b['revert']!==''), 'token'=>$token, 'window'=>$window, 'desc'=>$b['desc'], 'revert'=>$b['revert']];
    }

    // Operator confirms the change is good → cancel the pending auto-rollback.
    function nm_mtfw_keep($conn, array $node, string $token): array {
        if (!preg_match('/^fw[0-9a-f]{20}$/', $token)) return ['ok'=>false,'error'=>'bad token'];
        $ssh = nm_mtfw_ssh($conn, $node); if (!$ssh) return ['ok'=>false,'error'=>'ssh'];
        // cancel the rollback: delete BOTH the scheduler and the revert script → it can never fire
        $r = nm_cm_ssh_fetch($ssh, "/system scheduler remove [/system scheduler find name=\"neuru-$token\"]; /system script remove [/system script find name=\"neuru-$token\"]; :put \"OK\"", 15);
        try { $conn->query("UPDATE nm_mtfw_pending SET status='kept' WHERE token='".$conn->real_escape_string($token)."'"); } catch (\Throwable $e) {}
        if (function_exists('nm_audit')) { try { nm_audit($conn,'mtfw.keep',['target_type'=>'node','target_id'=>(int)$node['id'],'details'=>['token'=>$token]]); } catch (\Throwable $e) {} }
        return ['ok'=>!empty($r['ok'])];
    }
    // Operator reverts NOW (run the revert + remove scheduler immediately).
    function nm_mtfw_revert_now($conn, array $node, string $token): array {
        if (!preg_match('/^fw[0-9a-f]{20}$/', $token)) return ['ok'=>false,'error'=>'bad token'];
        $ssh = nm_mtfw_ssh($conn, $node); if (!$ssh) return ['ok'=>false,'error'=>'ssh'];
        $revert = '';
        try { $q=$conn->query("SELECT revert FROM nm_mtfw_pending WHERE token='".$conn->real_escape_string($token)."' LIMIT 1"); if($q&&($x=$q->fetch_assoc())) $revert=$x['revert']; } catch (\Throwable $e) {}
        $cmd = ($revert!==''?$revert.'; ':'')."/system scheduler remove [/system scheduler find name=\"neuru-$token\"]; /system script remove [/system script find name=\"neuru-$token\"]; :put \"OK\"";
        $r = nm_cm_ssh_fetch($ssh, $cmd, 20);
        try { $conn->query("UPDATE nm_mtfw_pending SET status='reverted' WHERE token='".$conn->real_escape_string($token)."'"); } catch (\Throwable $e) {}
        if (function_exists('nm_audit')) { try { nm_audit($conn,'mtfw.revert',['target_type'=>'node','target_id'=>(int)$node['id'],'details'=>['token'=>$token]]); } catch (\Throwable $e) {} }
        return ['ok'=>!empty($r['ok'])];
    }

    // ══════════════════════════════════════════════════════════════════════════
    // NETWORK OBJECTS (Command Center Phase 1) — Address Lists, IP Addresses,
    // Interfaces (+ VETH). Read via a generic id-mapped fetch; write via the SAME
    // anti-lockout Safe-Apply (commit-confirm auto-rollback) as the firewall, so a
    // change that cuts your own access self-reverts. keep/revert reuse the existing
    // token-based nm_mtfw_keep / nm_mtfw_revert_now.
    // ══════════════════════════════════════════════════════════════════════════
    function nm_mtfw_obj_kinds(): array {
        return [
            'addrlist'   => ['path'=>'/ip firewall address-list', 'label'=>'address list',   'tag'=>true],
            'ipaddr'     => ['path'=>'/ip address',               'label'=>'IP address',     'tag'=>true],
            'route'      => ['path'=>'/ip route',                 'label'=>'route',          'tag'=>true],
            'iface'      => ['path'=>'/interface',                'label'=>'interface',      'tag'=>false],
            'veth'       => ['path'=>'/interface veth',           'label'=>'VETH',           'tag'=>false],
            // Telemetry (Phase 5)
            'logaction'  => ['path'=>'/system logging action',    'label'=>'logging action', 'tag'=>false],
            'logrule'    => ['path'=>'/system logging',           'label'=>'logging rule',   'tag'=>false],
            'flowtarget' => ['path'=>'/ip traffic-flow target',   'label'=>'flow target',    'tag'=>false],
            'flowcfg'    => ['path'=>'/ip traffic-flow',          'label'=>'traffic-flow',   'tag'=>false],
        ];
    }
    // Generic id-mapped fetch for any RouterOS menu path (bulletproof id list via [find]).
    function nm_mtfw_fetch_objects($conn, array $node, string $path): array {
        $ssh = nm_mtfw_ssh($conn, $node); if (!$ssh) return ['ok'=>false,'error'=>'MikroTik SSH credential required'];
        $cmd = "$path print terse without-paging; :put \"NM_IDS\"; :put [$path find]; :put \"NM_END\"";
        $f = nm_cm_ssh_fetch($ssh, $cmd, 20);
        if (empty($f['ok'])) return ['ok'=>false,'error'=>$f['error'] ?? 'SSH failed'];
        $raw = (string)$f['config'];
        [$terse,$rest] = array_pad(explode('NM_IDS',$raw,2),2,'');
        $idsRaw = explode('NM_END',$rest,2)[0];
        $ids = [];
        foreach (preg_split('/[;\s]+/', trim($idsRaw)) as $t) { $t=trim($t); if ($t!==''&&$t[0]==='*'&&preg_match('/^\*[0-9A-Fa-f]+$/',$t)) $ids[]=$t; }
        $rows = nm_mtfw_parse_terse($terse);
        foreach ($rows as $i=>&$r) { if (isset($ids[$i])) $r['id']=$ids[$i]; }
        unset($r);
        return ['ok'=>true, 'rows'=>$rows, 'count'=>count($rows)];
    }
    // Dedicated /ip route fetch: reads .id + props via `get` per route (RouterOS v7 `print terse`
    // drops dynamic/connected routes and its flag column is unreliable — get is authoritative).
    // Returns ALL routes (static + connected + dynamic) with real active/dynamic/disabled booleans.
    function nm_mtfw_routes_full($conn, array $node): array {
        $ssh = nm_mtfw_ssh($conn, $node); if (!$ssh) return ['ok'=>false,'error'=>'MikroTik SSH credential required'];
        // $r IS the .id in a :foreach (get $r .id is not a valid value-name here); gateway/comment
        // may be unset (blackhole / no-comment) → fetch them into safe locals so a route isn't lost.
        $cmd = ':foreach r in=[/ip route find] do={ :local gw ""; :do { :set gw [/ip route get $r gateway] } on-error={}; :local cm ""; :do { :set cm [/ip route get $r comment] } on-error={}; :do { :put ($r . "|" . [/ip route get $r dst-address] . "|" . $gw . "|" . [/ip route get $r distance] . "|" . [/ip route get $r active] . "|" . [/ip route get $r dynamic] . "|" . [/ip route get $r disabled] . "|" . $cm) } on-error={} }; :put "NM_END"';
        $f = nm_cm_ssh_fetch($ssh, $cmd, 25);
        if (empty($f['ok'])) return ['ok'=>false,'error'=>$f['error'] ?? 'SSH failed'];
        $B = fn($v) => in_array(strtolower(trim((string)$v)), ['true','yes'], true);
        $rows = [];
        foreach (preg_split('/\r?\n/', (string)$f['config']) as $ln) {
            $ln = rtrim($ln); if (trim($ln) === '' || strpos(ltrim($ln), 'NM_') === 0 || strpos($ln, '|') === false) continue;
            $p = explode('|', $ln, 8); if (count($p) < 7) continue;
            if (($p[0] ?? '') === '' || $p[0][0] !== '*') continue;   // a real .id starts with '*'
            $rows[] = ['id'=>$p[0], 'dst'=>$p[1], 'gateway'=>$p[2], 'distance'=>$p[3],
                       'active'=>$B($p[4] ?? ''), 'dynamic'=>$B($p[5] ?? ''), 'disabled'=>$B($p[6] ?? ''), 'comment'=>$p[7] ?? ''];
        }
        return ['ok'=>true, 'rows'=>$rows, 'count'=>count($rows)];
    }
    // Shape rows per kind for the UI (stable field set).
    function nm_mtfw_fetch_kind($conn, array $node, string $kind): array {
        if ($kind === 'route') {   // dedicated fetch — see nm_mtfw_routes_full
            $r = nm_mtfw_routes_full($conn, $node); if (empty($r['ok'])) return $r;
            $out = [];
            foreach ($r['rows'] as $x) $out[] = ['id'=>$x['id'], 'disabled'=>!empty($x['disabled']), 'dynamic'=>!empty($x['dynamic']), 'flags'=>'',
                'dst'=>$x['dst'], 'gateway'=>$x['gateway'], 'distance'=>$x['distance'], 'active'=>!empty($x['active'])?1:0, 'comment'=>$x['comment']];
            return ['ok'=>true, 'kind'=>'route', 'rows'=>$out, 'count'=>count($out)];
        }
        $kinds = nm_mtfw_obj_kinds(); if (!isset($kinds[$kind])) return ['ok'=>false,'error'=>'bad kind'];
        $r = nm_mtfw_fetch_objects($conn, $node, $kinds[$kind]['path']); if (empty($r['ok'])) return $r;
        $out = [];
        foreach ($r['rows'] as $row) {
            $p = $row['props'] ?? []; $fl = (string)($row['flags'] ?? '');
            $base = ['id'=>$row['id'] ?? null, 'disabled'=>!empty($row['disabled']), 'dynamic'=>!empty($row['dynamic']), 'flags'=>$fl];
            if ($kind==='addrlist')       $out[] = $base + ['list'=>$p['list']??'', 'address'=>$p['address']??'', 'timeout'=>$p['timeout']??'', 'comment'=>$p['comment']??''];
            elseif ($kind==='ipaddr')     $out[] = $base + ['address'=>$p['address']??'', 'network'=>$p['network']??'', 'interface'=>$p['interface']??'', 'comment'=>$p['comment']??''];
            elseif ($kind==='route')      $out[] = $base + ['dst'=>($p['dst-address']??''), 'gateway'=>($p['gateway']??($p['immediate-gw']??'')), 'distance'=>($p['distance']??''), 'active'=>(strpos($fl,'A')!==false)?1:0, 'comment'=>$p['comment']??''];
            elseif ($kind==='logaction')  $out[] = $base + ['name'=>$p['name']??'', 'target'=>$p['target']??'', 'remote'=>$p['remote']??'', 'remoteport'=>$p['remote-port']??'', 'builtin'=>in_array(($p['name']??''),['memory','disk','echo','remote'],true)?1:0];
            elseif ($kind==='logrule')    $out[] = $base + ['topics'=>$p['topics']??'', 'action'=>$p['action']??'', 'prefix'=>$p['prefix']??''];
            elseif ($kind==='flowtarget') $out[] = $base + ['dst'=>($p['dst-address']??($p['address']??'')), 'port'=>$p['port']??'', 'version'=>$p['version']??'', 'src'=>$p['src-address']??''];
            else                          $out[] = $base + ['name'=>$p['name']??'', 'type'=>$p['type']??'', 'mtu'=>($p['mtu']??($p['actual-mtu']??'')), 'mac'=>$p['mac-address']??'', 'running'=>(strpos($fl,'R')!==false)?1:0, 'comment'=>$p['comment']??''];
        }
        return ['ok'=>true, 'kind'=>$kind, 'rows'=>$out, 'count'=>count($out)];
    }
    // props → " k=\"v\"" (quotes stripped from values; RouterOS-injection safe)
    function nm_mtfw_obj_propcmd(array $p): string { $s=''; foreach($p as $k=>$v){ $v=str_replace(['"',';',"\r","\n","\\"],'',(string)$v); if($v!=='') $s.=" $k=\"$v\""; } return $s; }
    // Build cmd + revert for an object op. Mirrors nm_mtfw_build's tag/set-old/re-add pattern.
    function nm_mtfw_obj_build(string $kind, string $op, array $data, array $existing = []): array {
        $kinds = nm_mtfw_obj_kinds(); if (!isset($kinds[$kind])) return ['ok'=>false,'error'=>'bad kind'];
        $path = $kinds[$kind]['path']; $props = [];
        // traffic-flow SETTINGS is a single config menu (set only, no id)
        if ($kind==='flowcfg') {
            if ($op!=='set') return ['ok'=>false,'error'=>'traffic-flow settings only support set'];
            $p = [];
            if (isset($data['enabled']))            $p['enabled'] = (!empty($data['enabled']) && $data['enabled']!=='no') ? 'yes' : 'no';
            if (($data['interfaces']??'')!=='')    { if(!preg_match('/^[A-Za-z0-9_.,\- ]+$/',(string)$data['interfaces'])) return ['ok'=>false,'error'=>'invalid interfaces']; $p['interfaces']=$data['interfaces']; }
            if (($data['cache-entries']??'')!=='' && preg_match('/^\d+[kK]?$/',(string)$data['cache-entries'])) $p['cache-entries']=$data['cache-entries'];
            if (empty($p)) return ['ok'=>false,'error'=>'nothing to change'];
            $old=[]; foreach($p as $k=>$v){ $old[$k]=(string)($existing[$k]??''); }
            return ['ok'=>true,'cmd'=>"/ip traffic-flow set".nm_mtfw_obj_propcmd($p),'revert'=>"/ip traffic-flow set".nm_mtfw_obj_propcmd($old),'desc'=>'traffic-flow settings'];
        }
        if ($op==='add' || $op==='set') {
            if ($kind==='addrlist') {
                if (($data['list']??'')!=='')    { if(!nm_mtfw_valid_name((string)$data['list'])) return ['ok'=>false,'error'=>'invalid list name']; $props['list']=$data['list']; }
                if (($data['address']??'')!=='') { if(!nm_mtfw_valid_ipspec((string)$data['address'])) return ['ok'=>false,'error'=>'invalid address']; $props['address']=$data['address']; }
                if (($data['timeout']??'')!=='') $props['timeout']=preg_replace('/[^0-9smhdw:]/','',(string)$data['timeout']);
                if (isset($data['comment']))     $props['comment']=nm_mtfw_clean_text((string)$data['comment']);
                if ($op==='add' && (($props['list']??'')===''||($props['address']??'')==='')) return ['ok'=>false,'error'=>'list and address are required'];
            } elseif ($kind==='ipaddr') {
                if (($data['address']??'')!=='') { if(!nm_mtfw_valid_ipspec((string)$data['address'])) return ['ok'=>false,'error'=>'invalid address (use IP or IP/cidr)']; $props['address']=$data['address']; }
                if (($data['interface']??'')!=='') { if(!nm_mtfw_valid_name((string)$data['interface'])) return ['ok'=>false,'error'=>'invalid interface']; $props['interface']=$data['interface']; }
                if (isset($data['comment']))     $props['comment']=nm_mtfw_clean_text((string)$data['comment']);
                if ($op==='add' && (($props['address']??'')===''||($props['interface']??'')==='')) return ['ok'=>false,'error'=>'address and interface are required'];
            } elseif ($kind==='iface') {
                if ($op==='add') return ['ok'=>false,'error'=>'physical interfaces cannot be added'];
                if (($data['mtu']??'')!=='')     { if(!preg_match('/^\d{2,5}$/',(string)$data['mtu'])) return ['ok'=>false,'error'=>'invalid MTU']; $props['mtu']=$data['mtu']; }
                if (isset($data['comment']))     $props['comment']=nm_mtfw_clean_text((string)$data['comment']);
            } elseif ($kind==='veth') {
                if (($data['name']??'')!=='')    { if(!nm_mtfw_valid_name((string)$data['name'])) return ['ok'=>false,'error'=>'invalid name']; $props['name']=$data['name']; }
                if (($data['address']??'')!=='') { if(!nm_mtfw_valid_ipspec((string)$data['address'])) return ['ok'=>false,'error'=>'invalid address']; $props['address']=$data['address']; }
                if (($data['gateway']??'')!=='') { if(!nm_mtfw_valid_ipspec((string)$data['gateway'])) return ['ok'=>false,'error'=>'invalid gateway']; $props['gateway']=$data['gateway']; }
                if (isset($data['comment']))     $props['comment']=nm_mtfw_clean_text((string)$data['comment']);
                if ($op==='add' && ($props['name']??'')==='') return ['ok'=>false,'error'=>'VETH name is required'];
            } elseif ($kind==='route') {
                if (($data['dst-address']??'')!=='') { if(!nm_mtfw_valid_ipspec((string)$data['dst-address'])) return ['ok'=>false,'error'=>'destination must be an IP or CIDR (e.g. 10.0.0.0/24)']; $props['dst-address']=$data['dst-address']; }
                if (($data['gateway']??'')!=='')  { $g=trim((string)$data['gateway']); if(!filter_var($g,FILTER_VALIDATE_IP)&&!nm_mtfw_valid_name($g)) return ['ok'=>false,'error'=>'gateway must be an IP or interface name']; $props['gateway']=$g; }
                if (($data['distance']??'')!=='') { if(!preg_match('/^\d{1,3}$/',(string)$data['distance'])||(int)$data['distance']>255) return ['ok'=>false,'error'=>'distance must be 0-255']; $props['distance']=$data['distance']; }
                if (isset($data['comment']))      $props['comment']=nm_mtfw_clean_text((string)$data['comment']);
                if ($op==='add' && (($props['dst-address']??'')===''||($props['gateway']??'')==='')) return ['ok'=>false,'error'=>'destination and gateway are required'];
            } elseif ($kind==='logaction') {
                if (($data['name']??'')!=='')    { if(!preg_match('/^[A-Za-z0-9]{1,32}$/',(string)$data['name'])) return ['ok'=>false,'error'=>'action name: letters and numbers only']; $props['name']=$data['name']; }
                if (($data['target']??'')!=='')  { if(!in_array($data['target'],['memory','disk','echo','remote','email'],true)) return ['ok'=>false,'error'=>'invalid target type']; $props['target']=$data['target']; }
                if (($data['remote']??'')!=='')  { if(!filter_var($data['remote'],FILTER_VALIDATE_IP)) return ['ok'=>false,'error'=>'remote must be an IP']; $props['remote']=$data['remote']; }
                if (($data['remote-port']??'')!=='') { if(!preg_match('/^\d{1,5}$/',(string)$data['remote-port'])||(int)$data['remote-port']>65535) return ['ok'=>false,'error'=>'invalid port']; $props['remote-port']=$data['remote-port']; }
                if ($op==='add' && (($props['name']??'')===''||($props['target']??'')==='')) return ['ok'=>false,'error'=>'name and target are required'];
            } elseif ($kind==='logrule') {
                if (($data['topics']??'')!=='')  { if(!preg_match('/^[a-z0-9,!.\-]+$/i',(string)$data['topics'])) return ['ok'=>false,'error'=>'invalid topics']; $props['topics']=$data['topics']; }
                if (($data['action']??'')!=='')  { if(!nm_mtfw_valid_name((string)$data['action'])) return ['ok'=>false,'error'=>'invalid action']; $props['action']=$data['action']; }
                if (isset($data['prefix']))      $props['prefix']=nm_mtfw_clean_text((string)$data['prefix'],40);
                if ($op==='add' && (($props['topics']??'')===''||($props['action']??'')==='')) return ['ok'=>false,'error'=>'topics and action are required'];
            } elseif ($kind==='flowtarget') {
                if (($data['dst-address']??'')!=='') { if(!filter_var($data['dst-address'],FILTER_VALIDATE_IP)) return ['ok'=>false,'error'=>'dst-address must be an IP']; $props['dst-address']=$data['dst-address']; }
                if (($data['port']??'')!=='')    { if(!preg_match('/^\d{1,5}$/',(string)$data['port'])||(int)$data['port']>65535) return ['ok'=>false,'error'=>'invalid port']; $props['port']=$data['port']; }
                if (($data['version']??'')!=='') { if(!in_array((string)$data['version'],['1','5','9','ipfix'],true)) return ['ok'=>false,'error'=>'version must be 1, 5, 9 or ipfix']; $props['version']=$data['version']; }
                if (($data['src-address']??'')!=='') { if(!filter_var($data['src-address'],FILTER_VALIDATE_IP)) return ['ok'=>false,'error'=>'src-address must be an IP']; $props['src-address']=$data['src-address']; }
                if ($op==='add' && (($props['dst-address']??'')===''||($props['port']??'')==='')) return ['ok'=>false,'error'=>'dst-address and port are required'];
            }
        }
        if ($op === 'add') {
            $tag = 'nob'.substr(bin2hex(random_bytes(4)),0,8);
            if (!empty($kinds[$kind]['tag'])) $props['comment']=trim(($props['comment']??'').' ['.$tag.']');
            $cmd = "$path add".nm_mtfw_obj_propcmd($props);
            if (!empty($kinds[$kind]['tag']))        $revert = "$path remove [find comment~\"$tag\"]";
            elseif ($kind==='veth' && ($props['name']??'')!=='')       $revert = "$path remove [find name=\"".str_replace('"','',$props['name'])."\"]";
            elseif ($kind==='logaction' && ($props['name']??'')!=='')  $revert = "$path remove [find name=\"".str_replace('"','',$props['name'])."\"]";
            elseif ($kind==='flowtarget' && ($props['dst-address']??'')!=='') $revert = "$path remove [find dst-address=\"".str_replace('"','',$props['dst-address'])."\"]";
            elseif ($kind==='logrule' && ($props['action']??'')!=='')  $revert = "$path remove [find action=\"".str_replace('"','',$props['action'])."\"]";
            else                                     $revert = '';
            return ['ok'=>true,'cmd'=>$cmd,'revert'=>$revert,'tag'=>$tag,'desc'=>"add ".$kinds[$kind]['label']];
        }
        if ($op === 'set') {
            $id=(string)($data['id']??''); if(!preg_match('/^\*[0-9A-Fa-f]+$/',$id)) return ['ok'=>false,'error'=>'bad id'];
            if (empty($props)) return ['ok'=>false,'error'=>'nothing to change'];
            $old=[]; foreach($props as $k=>$v){ $old[$k]=(string)($existing[$k]??''); }
            return ['ok'=>true,'cmd'=>"$path set $id".nm_mtfw_obj_propcmd($props),'revert'=>"$path set $id".nm_mtfw_obj_propcmd($old),'desc'=>"edit ".$kinds[$kind]['label']];
        }
        if ($op === 'toggle') {
            $id=(string)($data['id']??''); if(!preg_match('/^\*[0-9A-Fa-f]+$/',$id)) return ['ok'=>false,'error'=>'bad id'];
            $en=!empty($data['enable']);
            return ['ok'=>true,'cmd'=>"$path ".($en?'enable':'disable')." $id",'revert'=>"$path ".($en?'disable':'enable')." $id",'desc'=>($en?'enable':'disable')." ".$kinds[$kind]['label']];
        }
        if ($op === 'remove') {
            $id=(string)($data['id']??''); if(!preg_match('/^\*[0-9A-Fa-f]+$/',$id)) return ['ok'=>false,'error'=>'bad id'];
            $re='';
            if ($kind==='addrlist' && ($existing['list']??'')!=='')      $re="$path add".nm_mtfw_obj_propcmd(['list'=>$existing['list']??'','address'=>$existing['address']??'','comment'=>$existing['comment']??'','timeout'=>$existing['timeout']??'']);
            elseif ($kind==='ipaddr' && ($existing['address']??'')!=='')  $re="$path add".nm_mtfw_obj_propcmd(['address'=>$existing['address']??'','interface'=>$existing['interface']??'','comment'=>$existing['comment']??'']);
            elseif ($kind==='route' && ($existing['dst']??'')!=='')       $re="$path add".nm_mtfw_obj_propcmd(['dst-address'=>$existing['dst']??'','gateway'=>$existing['gateway']??'','distance'=>$existing['distance']??'','comment'=>$existing['comment']??'']);
            elseif ($kind==='veth' && ($existing['name']??'')!=='')       $re="$path add".nm_mtfw_obj_propcmd(['name'=>$existing['name']??'','comment'=>$existing['comment']??'']);
            elseif ($kind==='logaction' && ($existing['name']??'')!=='')  $re="$path add".nm_mtfw_obj_propcmd(['name'=>$existing['name']??'','target'=>$existing['target']??'','remote'=>$existing['remote']??'','remote-port'=>$existing['remoteport']??'']);
            elseif ($kind==='logrule' && ($existing['topics']??'')!=='')  $re="$path add".nm_mtfw_obj_propcmd(['topics'=>$existing['topics']??'','action'=>$existing['action']??'','prefix'=>$existing['prefix']??'']);
            elseif ($kind==='flowtarget' && ($existing['dst']??'')!=='')  $re="$path add".nm_mtfw_obj_propcmd(['dst-address'=>$existing['dst']??'','port'=>$existing['port']??'','version'=>$existing['version']??'']);
            return ['ok'=>true,'cmd'=>"$path remove $id",'revert'=>$re,'desc'=>"remove ".$kinds[$kind]['label']];
        }
        return ['ok'=>false,'error'=>'unknown op'];
    }
    // Which firewall rules reference each address-list (src/dst-address-list) → [list => count].
    function nm_mtfw_addrlist_usedby($conn, array $node): array {
        $counts = [];
        foreach (['filter','nat'] as $tbl) {
            $f = nm_mtfw_fetch($conn, $node, $tbl); if (empty($f['ok'])) continue;
            foreach ($f['rules'] as $r) { $p = $r['props'] ?? [];
                foreach (['src-address-list','dst-address-list'] as $key) {
                    $v = trim((string)($p[$key] ?? '')); if ($v === '') continue;
                    $v = ltrim($v, '!'); $counts[$v] = ($counts[$v] ?? 0) + 1;
                }
            }
        }
        return $counts;
    }
    function nm_mtfw_obj_dryrun(string $kind, string $op, array $data, array $existing = []): array {
        $b = nm_mtfw_obj_build($kind,$op,$data,$existing); if (empty($b['ok'])) return $b;
        return ['ok'=>true,'cmd'=>$b['cmd'],'revert'=>$b['revert'],'desc'=>$b['desc']];
    }
    // Safe-Apply an object change (commit-confirm auto-rollback), same mechanism as the firewall.
    function nm_mtfw_obj_apply($conn, array $node, string $kind, string $op, array $data, bool $safe = true, int $window = 2): array {
        nm_mtfw_ensure($conn);
        $kinds = nm_mtfw_obj_kinds(); if (!isset($kinds[$kind])) return ['ok'=>false,'error'=>'bad kind'];
        $ssh = nm_mtfw_ssh($conn, $node); if (!$ssh) return ['ok'=>false,'error'=>'MikroTik SSH credential required'];
        $b = nm_mtfw_obj_build($kind,$op,$data,$data['existing']??[]); if (empty($b['ok'])) return $b;
        $window = max(1, min(30, $window));
        $token = 'fw'.substr(bin2hex(random_bytes(8)),0,20); $schedName='neuru-'.$token; $seq=[];
        if ($safe && !empty($b['revert'])) {
            $src=str_replace('"','\\"',$b['revert']);
            $seq[]="/system script add name=\"$schedName\" source=\"$src\"";
            $onEvent="/system script run $schedName; /system scheduler remove [/system scheduler find name=$schedName]; /system script remove [/system script find name=$schedName]";
            $seq[]="/system scheduler add name=\"$schedName\" interval={$window}m on-event=\"$onEvent\" comment=\"NEURU object auto-rollback\"";
        }
        $seq[]=$b['cmd'];
        $res=nm_cm_ssh_fetch($ssh, implode('; ',$seq).'; :put "NM_APPLIED"', 30);
        $applied=!empty($res['ok']) && strpos((string)$res['config'],'NM_APPLIED')!==false;
        if (!$applied) {
            if ($safe) @nm_cm_ssh_fetch($ssh,"/system scheduler remove [/system scheduler find name=\"$schedName\"]; /system script remove [/system script find name=\"$schedName\"]",12);
            return ['ok'=>false,'error'=>$res['error']??'apply failed on router'];
        }
        if ($safe && !empty($b['revert'])) {
            try { $st=$conn->prepare("INSERT INTO nm_mtfw_pending (token,node_id,fw_table,op,cmd,revert,window_min,created_by,status) VALUES (?,?,?,?,?,?,?,?,'armed')");
                $nid=(int)$node['id']; $uid=(int)($data['uid']??0); $tbl='obj:'.$kind; $st->bind_param('sisssssi',$token,$nid,$tbl,$op,$b['cmd'],$b['revert'],$window,$uid); $st->execute(); } catch (\Throwable $e) {}
        }
        if (function_exists('nm_audit')) { try { nm_audit($conn,'mtfw.obj_apply',['target_type'=>'node','target_id'=>(int)$node['id'],'details'=>['kind'=>$kind,'op'=>$op,'safe'=>$safe,'cmd'=>$b['cmd']]]); } catch (\Throwable $e) {} }
        return ['ok'=>true,'applied'=>true,'safe'=>($safe && !empty($b['revert'])),'token'=>$token,'window'=>$window,'desc'=>$b['desc'],'cmd'=>$b['cmd'],'revert'=>$b['revert']];
    }

    // ══ TELEMETRY (Command Center Phase 5) — Logging + Traffic-Flow, auto-wired to NEURU ══
    function nm_mtfw_setting($conn, string $k, string $def=''): string {
        $r=@$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1");
        return ($r&&$r->num_rows)?(string)$r->fetch_assoc()['setting_val']:$def;
    }
    // the single /ip traffic-flow settings menu (enabled/interfaces/cache-entries)
    function nm_mtfw_flow_settings($conn, array $node): array {
        $ssh=nm_mtfw_ssh($conn,$node); if(!$ssh) return ['ok'=>false,'error'=>'MikroTik SSH credential required'];
        $cmd=':put ("enabled=".[/ip traffic-flow get enabled]); :put ("interfaces=".[/ip traffic-flow get interfaces]); :put ("cache-entries=".[/ip traffic-flow get cache-entries]); :put "NM_END"';
        $f=nm_cm_ssh_fetch($ssh,$cmd,15); if(empty($f['ok'])) return ['ok'=>false,'error'=>$f['error']??'SSH failed'];
        $s=['enabled'=>'','interfaces'=>'','cache-entries'=>''];
        foreach(preg_split('/\r?\n/',(string)$f['config']) as $ln){ $ln=trim($ln); if(strpos($ln,'=')===false)continue; [$k,$v]=explode('=',$ln,2); if(array_key_exists($k,$s))$s[$k]=trim($v); }
        return ['ok'=>true,'settings'=>$s];
    }
    // router's view of NEURU's SSH source IP = the reachable host IP (behind Docker NAT)
    function nm_mtfw_ssh_source($conn, array $node): string {
        $ssh=nm_mtfw_ssh($conn,$node); if(!$ssh) return '';
        $f=nm_cm_ssh_fetch($ssh, ":foreach a in=[/user active find] do={ :if ([/user active get \$a via]=\"ssh\") do={ :put [/user active get \$a address] } }; :put \"END\"", 12);
        if(empty($f['ok'])) return '';
        foreach(preg_split('/\r?\n/',(string)$f['config']) as $ln){ $ln=trim($ln); if(filter_var($ln,FILTER_VALIDATE_IP)) return $ln; }
        return '';
    }
    function nm_mtfw_neuru_endpoints($conn, array $node): array {
        $saved=nm_mtfw_setting($conn,'telemetry_neuru_ip',''); $ip=$saved; $auto='';
        if($ip===''){ $auto=nm_mtfw_ssh_source($conn,$node); if($auto!=='') $ip=$auto; }
        $sys=(int)(nm_mtfw_setting($conn,'syslog_port','514')?:514); if($sys<=0)$sys=514;
        $nf=(int)(nm_mtfw_setting($conn,'netflow_port','2055')?:2055); if($nf<=0)$nf=2055;
        return ['ip'=>$ip,'auto_ip'=>$auto,'saved'=>($saved!==''),'syslog_port'=>$sys,'netflow_port'=>$nf,
                'netflow_enabled'=>(nm_mtfw_setting($conn,'netflow_enabled','0')==='1')];
    }
    // generic pre-built cmd/revert Safe-Apply core (shared by the one-click Ship/Export)
    function nm_mtfw_run_seq($conn, array $node, $ssh, string $cmd, string $revert, bool $safe, int $window, int $uid, string $table, string $op): array {
        $window=max(1,min(30,$window));
        $token='fw'.substr(bin2hex(random_bytes(8)),0,20); $schedName='neuru-'.$token; $seq=[];
        if($safe && $revert!==''){
            $src=str_replace('"','\\"',$revert);
            $seq[]="/system script add name=\"$schedName\" source=\"$src\"";
            $onEvent="/system script run $schedName; /system scheduler remove [/system scheduler find name=$schedName]; /system script remove [/system script find name=$schedName]";
            $seq[]="/system scheduler add name=\"$schedName\" interval={$window}m on-event=\"$onEvent\" comment=\"NEURU auto-rollback\"";
        }
        $seq[]=$cmd;
        $res=nm_cm_ssh_fetch($ssh, implode('; ',$seq).'; :put "NM_APPLIED"',30);
        if(!(!empty($res['ok']) && strpos((string)$res['config'],'NM_APPLIED')!==false)){
            if($safe) @nm_cm_ssh_fetch($ssh,"/system scheduler remove [/system scheduler find name=\"$schedName\"]; /system script remove [/system script find name=\"$schedName\"]",12);
            return ['ok'=>false,'error'=>$res['error']??'apply failed on router'];
        }
        if($safe && $revert!==''){ try{ $st=$conn->prepare("INSERT INTO nm_mtfw_pending (token,node_id,fw_table,op,cmd,revert,window_min,created_by,status) VALUES (?,?,?,?,?,?,?,?,'armed')"); $nid=(int)$node['id']; $st->bind_param('sisssssi',$token,$nid,$table,$op,$cmd,$revert,$window,$uid); $st->execute(); }catch(\Throwable $e){} }
        if(function_exists('nm_audit')){ try{ nm_audit($conn,'mtfw.apply2',['target_type'=>'node','target_id'=>(int)$node['id'],'details'=>['table'=>$table,'op'=>$op,'cmd'=>$cmd]]); }catch(\Throwable $e){} }
        return ['ok'=>true,'applied'=>true,'safe'=>($safe && $revert!==''),'token'=>$token,'window'=>$window];
    }
    function nm_mtfw_raw_apply($conn, array $node, string $cmd, string $revert, string $desc, bool $safe, int $window, int $uid, string $label='raw'): array {
        nm_mtfw_ensure($conn);
        $ssh=nm_mtfw_ssh($conn,$node); if(!$ssh) return ['ok'=>false,'error'=>'MikroTik SSH credential required'];
        if(trim($cmd)==='') return ['ok'=>false,'error'=>'nothing to apply'];
        $r=nm_mtfw_run_seq($conn,$node,$ssh,$cmd,$revert,$safe,$window,$uid,$label,'raw');
        if(empty($r['ok'])) return $r;
        return $r+['desc'=>$desc,'cmd'=>$cmd,'revert'=>$revert];
    }
    // one-click: ship logs to NEURU (remote action + one logging rule). Idempotent.
    function nm_mtfw_ship_syslog_build(string $ip, int $port, string $topics='info,error,warning,critical'): array {
        if(!filter_var($ip,FILTER_VALIDATE_IP)) return ['ok'=>false,'error'=>'set NEURU IP first'];
        if($port<=0||$port>65535) $port=514;
        if(!preg_match('/^[a-z0-9,!.\-]+$/i',$topics)) $topics='info';
        $name='neurusyslog';
        $cmd="/system logging remove [find action=\"$name\"]; "
            ."/system logging action remove [find name=\"$name\"]; "
            ."/system logging action add name=\"$name\" target=remote remote=\"$ip\" remote-port=$port; "
            ."/system logging add topics=\"$topics\" action=\"$name\"";
        $revert="/system logging remove [find action=\"$name\"]; /system logging action remove [find name=\"$name\"]";
        return ['ok'=>true,'cmd'=>$cmd,'revert'=>$revert,'desc'=>"ship logs ($topics) → NEURU $ip:$port"];
    }
    // one-click: export NetFlow to NEURU (enable traffic-flow + add/replace the target). Idempotent.
    function nm_mtfw_export_flow_build(string $ip, int $port, string $version='9'): array {
        if(!filter_var($ip,FILTER_VALIDATE_IP)) return ['ok'=>false,'error'=>'set NEURU IP first'];
        if($port<=0||$port>65535) $port=2055;
        if(!in_array($version,['1','5','9','ipfix'],true)) $version='9';
        $cmd="/ip traffic-flow set enabled=yes interfaces=all; "
            ."/ip traffic-flow target remove [find dst-address=\"$ip\"]; "
            ."/ip traffic-flow target add dst-address=\"$ip\" port=$port version=$version";
        $revert="/ip traffic-flow target remove [find dst-address=\"$ip\"]";
        return ['ok'=>true,'cmd'=>$cmd,'revert'=>$revert,'desc'=>"export NetFlow v$version → NEURU $ip:$port"];
    }

    // ══ TORCH (Command Center Phase 2) — live traffic via connection tracking ══
    // Reliable + scriptable (real /tool torch is interactive/ANSI). Per-flow bytes;
    // the UI computes live rates from byte deltas between polls. Filter by protocol
    // (server-side) + address (client-visible). Capped so a huge conntrack table can't
    // blow up the response.
    function nm_mtfw_torch($conn, array $node, array $filter = [], int $cap = 400): array {
        $ssh=nm_mtfw_ssh($conn,$node); if(!$ssh) return ['ok'=>false,'error'=>'MikroTik SSH credential required'];
        $proto=strtolower(trim((string)($filter['protocol']??'')));
        $where = in_array($proto,['tcp','udp','icmp'],true) ? " where protocol=$proto" : '';
        $r=nm_cm_ssh_fetch($ssh,"/ip firewall connection print terse without-paging".$where,20);
        if(empty($r['ok'])) return ['ok'=>false,'error'=>$r['error']??'SSH failed'];
        $addr=trim((string)($filter['address']??''));
        $rows=[]; $total=0;
        foreach(nm_mtfw_parse_terse((string)$r['config']) as $row){
            $p=$row['props']??[]; $src=$p['src-address']??''; $dst=$p['dst-address']??'';
            if($src===''&&$dst==='') continue;
            if($addr!=='' && stripos($src,$addr)===false && stripos($dst,$addr)===false) continue;
            $total++; if(count($rows)>=$cap) continue;
            $rows[]=[
                'proto'=>$p['protocol']??'',
                'src'=>$src, 'dst'=>$dst,
                'ob'=>(int)($p['orig-bytes']??0), 'rb'=>(int)($p['repl-bytes']??0),
                'orate'=>(int)($p['orig-rate']??0), 'rrate'=>(int)($p['repl-rate']??0),
                'state'=>$p['tcp-state']??'', 'flags'=>$row['flags']??'',
            ];
        }
        return ['ok'=>true,'rows'=>$rows,'count'=>count($rows),'total'=>$total,'capped'=>($total>$cap)];
    }

    // ══ ROUTING EMULATOR (Command Center Phase 4) — full A→B forwarding trace ══
    // = the packet tracer (dst-nat → filter → src-nat) PLUS a routing lookup that
    // resolves the in-interface (from src) and the out-interface + next-hop (from the
    // POST-dst-nat dst) using the live routing table + connected subnets.
    function nm_mtfw_routes($conn, array $node): array {
        $ssh=nm_mtfw_ssh($conn,$node); if(!$ssh) return ['ok'=>false,'error'=>'MikroTik SSH credential required'];
        if(!function_exists('nm_routing_routeros_script')){ $f=__DIR__.'/nm_routing.php'; if(is_file($f)) require_once $f; }
        if(!function_exists('nm_routing_routeros_script')) return ['ok'=>false,'error'=>'routing helper missing'];
        $r=nm_cm_ssh_fetch($ssh, nm_routing_routeros_script(600), 20);
        if(empty($r['ok'])) return ['ok'=>false,'error'=>$r['error']??'SSH failed'];
        $p=nm_routing_parse_routeros((string)$r['config']);
        return ['ok'=>true,'routes'=>$p['routes'],'total'=>$p['total']];
    }
    function nm_mtfw_conn_iface(array $connected, string $ip): string {
        if(!filter_var($ip,FILTER_VALIDATE_IP)) return '';
        $best=''; $bestp=-1;
        foreach($connected as $c){ if(nm_routing_in_cidr_safe($ip,$c['net'],(int)$c['prefix']) && (int)$c['prefix']>$bestp){ $best=$c['iface']; $bestp=(int)$c['prefix']; } }
        return $best;
    }
    // longest-prefix (then lowest-distance) match over connected + active routes
    function nm_mtfw_route_lookup(array $routes, array $connected, string $ip): array {
        if(!filter_var($ip,FILTER_VALIDATE_IP)) return ['type'=>'invalid','out_if'=>'','next_hop'=>'','dst'=>''];
        $cand=[];
        foreach($connected as $c) $cand[]=['net'=>$c['net'],'prefix'=>(int)$c['prefix'],'protocol'=>'connected','gw_iface'=>$c['iface'],'gw_ip'=>null,'distance'=>0,'is_default'=>false];
        foreach($routes as $r){ if(empty($r['active'])) continue; $cand[]=$r; }
        $best=null; $bestp=-1; $bestd=PHP_INT_MAX;
        foreach($cand as $r){ if(!nm_routing_in_cidr_safe($ip,(string)$r['net'],(int)$r['prefix'])) continue;
            $pfx=(int)$r['prefix']; $d=(int)($r['distance']??0);
            if($pfx>$bestp || ($pfx===$bestp && $d<$bestd)){ $best=$r; $bestp=$pfx; $bestd=$d; } }
        if(!$best) return ['type'=>'none','out_if'=>'','next_hop'=>'','dst'=>''];
        if(($best['protocol']??'')==='blackhole') return ['type'=>'blackhole','out_if'=>'','next_hop'=>'','dst'=>$best['net'].'/'.$best['prefix']];
        $outIf=(string)($best['gw_iface']??''); $nh=(string)($best['gw_ip']??'');
        if($outIf==='' && $nh!=='') $outIf=nm_mtfw_conn_iface($connected,$nh);
        $type=(string)($best['protocol']??'static'); if(!empty($best['is_default'])) $type='default';
        return ['type'=>$type,'out_if'=>$outIf,'next_hop'=>($nh!==''?$nh:'directly connected'),'dst'=>$best['net'].'/'.$best['prefix']];
    }
    function nm_mtfw_route_emulate($conn, array $node, array $pkt): array {
        $ff=nm_mtfw_fetch($conn,$node,'filter'); if(empty($ff['ok'])) return $ff;
        $nf=nm_mtfw_fetch($conn,$node,'nat'); $natRules=!empty($nf['ok'])?$nf['rules']:[];
        $lists=nm_mtfw_addrlist_members($conn,$node);
        $ipr=nm_mtfw_fetch_kind($conn,$node,'ipaddr');
        $rt=nm_mtfw_routes($conn,$node);
        $connected=[]; if(!empty($ipr['ok'])) foreach($ipr['rows'] as $a){ $ad=(string)($a['address']??''); if(strpos($ad,'/')===false)continue; [$aip,$ap]=explode('/',$ad,2); if(!filter_var($aip,FILTER_VALIDATE_IP))continue; $connected[]=['net'=>$aip,'prefix'=>(int)$ap,'iface'=>(string)($a['interface']??'')]; }
        $src=trim((string)($pkt['src']??'')); $dst=trim((string)($pkt['dst']??''));
        $inIf=nm_mtfw_conn_iface($connected,$src);
        // interface-list membership of the ingress iface (for accurate in-interface-list rule matching)
        $inLists=[];
        if($inIf!==''){ $ifc=nm_mtfw_fetch_interfaces($conn,$node); if(!empty($ifc['ok'])) foreach(($ifc['interfaces']??[]) as $I){ if(($I['name']??'')===$inIf){ $inLists=$I['lists']??[]; break; } } }
        // pass 1: dst-nat → effective dst (used for routing). KEYS must match nm_mtfw_trace: in_if / state / dst_port.
        $p1=$pkt; $p1['chain']='forward'; if($inIf!==''){ $p1['in_if']=$inIf; $p1['in_if_lists']=$inLists; }
        $t1=nm_mtfw_trace($ff['rules'],$p1,$lists,$natRules);
        $effDst=(string)($t1['effective']['dst']??$dst);
        // routing decision on the effective dst
        $route=(!empty($rt['ok']))?nm_mtfw_route_lookup($rt['routes'],$connected,$effDst):['type'=>'unknown','out_if'=>'','next_hop'=>'','dst'=>''];
        // pass 2: with the resolved out-interface (trace matches forward on in_if; out_if carried for completeness)
        $p2=$p1; if(($route['out_if']??'')!=='')$p2['out_if']=$route['out_if'];
        $t2=nm_mtfw_trace($ff['rules'],$p2,$lists,$natRules);
        $verdict=$t2['verdict']; $kind=$t2['kind'];
        if($route['type']==='none'){ $verdict='NO ROUTE'; $kind='drop'; }
        elseif($route['type']==='blackhole'){ $verdict='BLACKHOLE'; $kind='drop'; }
        elseif($route['type']==='invalid'){ $verdict='BAD DST'; $kind='drop'; }
        return ['ok'=>true,'src'=>$src,'dst'=>$dst,'eff_dst'=>$effDst,'in_if'=>($inIf?:'(external)'),
                'route'=>$route,'out_if'=>(string)$route['out_if'],'next_hop'=>(string)$route['next_hop'],
                'routed'=>!in_array($route['type'],['none','blackhole','invalid','unknown'],true),
                'verdict'=>$verdict,'kind'=>$kind,'steps'=>$t2['steps'],'hints'=>$t2['hints'],'effective'=>$t2['effective']];
    }

    // ── Snapshots / drift ─────────────────────────────────────────────────────────
    function nm_mtfw_rule_key(array $r): string { $p=$r['props']??[]; unset($p['bytes'],$p['packets']); ksort($p); return $r['chain'].'|'.$r['action'].'|'.json_encode($p); }
    function nm_mtfw_snapshot_save($conn, int $nid, string $table, array $rules, string $reason='', int $uid=0): void {
        nm_mtfw_ensure($conn);
        try { $keys=array_map('nm_mtfw_rule_key',$rules); $json=json_encode($keys); $cnt=count($rules);
            $st=$conn->prepare("INSERT INTO nm_mtfw_snapshots (node_id,fw_table,rule_count,rules_json,reason,created_by) VALUES (?,?,?,?,?,?)");
            $u=$uid?:null; $st->bind_param('isissi',$nid,$table,$cnt,$json,$reason,$u); $st->execute();
            $conn->query("DELETE FROM nm_mtfw_snapshots WHERE node_id=$nid AND fw_table='".$conn->real_escape_string($table)."' AND id NOT IN (SELECT id FROM (SELECT id FROM nm_mtfw_snapshots WHERE node_id=$nid AND fw_table='".$conn->real_escape_string($table)."' ORDER BY id DESC LIMIT 30) t)");
        } catch (\Throwable $e) {}
    }
    function nm_mtfw_drift($conn, int $nid, string $table, array $rules): array {
        nm_mtfw_ensure($conn); $cur=array_map('nm_mtfw_rule_key',$rules); $prev=[];
        try { $q=$conn->query("SELECT rules_json FROM nm_mtfw_snapshots WHERE node_id=$nid AND fw_table='".$conn->real_escape_string($table)."' ORDER BY id DESC LIMIT 1"); if($q&&($x=$q->fetch_assoc())) $prev=json_decode($x['rules_json'],true)?:[]; } catch (\Throwable $e) {}
        return ['added'=>array_values(array_diff($cur,$prev)),'removed'=>array_values(array_diff($prev,$cur)),'had_prev'=>(bool)$prev];
    }

    // ── WHAT-IF packet simulator (walks the rule objects, NO router write) ────────
    // Evaluates a synthetic packet {chain,src,dst,protocol,dst_port,src_port,state,in_if}
    // through the fetched rules in order → verdict + the deciding rule + trace.
    function nm_mtfw_whatif(array $rules, array $pkt): array {
        $chain = $pkt['chain'] ?? 'forward'; $trace = []; $verdict = 'accept (default)'; $decideIdx = null;
        $ipMatch = function($spec, $ip) {
            if ($spec === '' || $ip === '') return true;
            foreach (explode(',', $spec) as $part) { $part=trim($part); $neg=false; if($part!==''&&$part[0]==='!'){$neg=true;$part=substr($part,1);} $ok=false;
                if (strpos($part,'/')!==false){ [$n,$p]=explode('/',$part,2); $ok=nm_routing_in_cidr_safe($ip,$n,(int)$p); }
                elseif (strpos($part,'-')!==false){ [$a,$b]=explode('-',$part,2); $li=ip2long($ip); $ok=($li!==false&&$li>=ip2long(trim($a))&&$li<=ip2long(trim($b))); }
                else $ok=($part===$ip);
                if ($neg) $ok=!$ok; if ($ok) return true;
            } return false;
        };
        $portMatch = function($spec, $port){ if($spec===''||$port==='')return true; foreach(explode(',',$spec) as $p){ $p=trim($p);
            if(strpos($p,'-')!==false){ [$a,$b]=explode('-',$p,2); if((int)$port>=(int)$a&&(int)$port<=(int)$b)return true; } elseif((int)$p===(int)$port)return true; } return false; };
        $curChain = $chain; $hops = 0;
        $walk = function($c) use (&$walk,&$trace,&$verdict,&$decideIdx,$rules,$pkt,$ipMatch,$portMatch,&$hops) {
            foreach ($rules as $i=>$r) {
                if ($r['chain'] !== $c || !empty($r['disabled'])) continue;
                $p = $r['props'];
                if (!$ipMatch($p['src-address'] ?? '', $pkt['src'] ?? '')) continue;
                if (!$ipMatch($p['dst-address'] ?? '', $pkt['dst'] ?? '')) continue;
                if (($p['protocol'] ?? '') !== '' && ($pkt['protocol'] ?? '') !== '' && $p['protocol'] !== $pkt['protocol']) continue;
                if (!$portMatch($p['dst-port'] ?? '', (string)($pkt['dst_port'] ?? ''))) continue;
                if (!$portMatch($p['src-port'] ?? '', (string)($pkt['src_port'] ?? ''))) continue;
                if (($p['in-interface'] ?? '') !== '' && ($pkt['in_if'] ?? '') !== '' && $p['in-interface'] !== $pkt['in_if']) continue;
                if (($p['connection-state'] ?? '') !== '' && ($pkt['state'] ?? '') !== '' && !in_array($pkt['state'], explode(',', $p['connection-state']), true)) continue;
                $trace[] = ['idx'=>$r['idx'],'chain'=>$c,'action'=>$r['action'],'comment'=>$r['comment']];
                $act = $r['action'];
                if (in_array($act, ['accept','fasttrack-connection'], true)) { $verdict='ACCEPT'; $decideIdx=$r['idx']; return true; }
                if (in_array($act, ['drop','reject','tarpit'], true)) { $verdict=strtoupper($act); $decideIdx=$r['idx']; return true; }
                if ($act === 'jump' && !empty($p['jump-target']) && $hops++ < 10) { if ($walk($p['jump-target'])) return true; }
                if ($act === 'return') return false;
                // log/passthrough/add-to-list → continue
            }
            return false;
        };
        $walk($curChain);
        if ($decideIdx === null) $verdict = 'ACCEPT (no matching rule — default policy)';
        return ['verdict'=>$verdict, 'decided_by'=>$decideIdx, 'trace'=>$trace];
    }
    // Short human summary of a rule's match conditions (for the tracer labels + step log).
    function nm_mtfw_rule_summary(array $r): string {
        $p = $r['props'] ?? []; $s = [];
        foreach ([['src-address','src='],['src-address-list','srclist='],['dst-address','dst='],['dst-address-list','dstlist='],
                  ['protocol',''],['dst-port','dport='],['src-port','sport='],['connection-state','state='],
                  ['in-interface','in='],['in-interface-list','in-list='],['out-interface','out='],['out-interface-list','out-list='],
                  ['jump-target','→']] as $x)
            if (!empty($p[$x[0]])) $s[] = $x[1] . $p[$x[0]];
        return implode(' · ', $s) ?: 'match all';
    }

    // FULL packet trace (for the Packet Tracer animation): unlike nm_mtfw_whatif (which logs only
    // matched rules), this records EVERY rule the packet is evaluated against in order — with the
    // first failing condition ('miss') for non-matches — so the UI can fly the packet past each rule
    // and stop it at the deciding gate. Read-only; no router change.
    function nm_mtfw_trace(array $rules, array $pkt, array $lists = [], array $nat = []): array {
        $chain = $pkt['chain'] ?? 'forward';
        $orig = $pkt;   // keep the user's ORIGINAL packet (before dst-nat mutates it) for the hints
        $isPriv = fn($ip) => $ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) && !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
        $steps = []; $verdict = 'ACCEPT'; $kind = 'accept'; $decideIdx = null;
        $ipMatch = function($spec, $ip) {
            if ($spec === '' || $ip === '') return true;
            foreach (explode(',', $spec) as $part) { $part=trim($part); $neg=false; if($part!==''&&$part[0]==='!'){$neg=true;$part=substr($part,1);} $ok=false;
                if (strpos($part,'/')!==false){ [$n,$p]=explode('/',$part,2); $ok=nm_routing_in_cidr_safe($ip,$n,(int)$p); }
                elseif (strpos($part,'-')!==false){ [$a,$b]=explode('-',$part,2); $li=ip2long($ip); $ok=($li!==false&&$li>=ip2long(trim($a))&&$li<=ip2long(trim($b))); }
                else $ok=($part===$ip);
                if ($neg) $ok=!$ok; if ($ok) return true;
            } return false;
        };
        $portMatch = function($spec, $port){ if($spec===''||$port==='')return true; foreach(explode(',',$spec) as $p){ $p=trim($p);
            if(strpos($p,'-')!==false){ [$a,$b]=explode('-',$p,2); if((int)$port>=(int)$a&&(int)$port<=(int)$b)return true; } elseif((int)$p===(int)$port)return true; } return false; };
        // src/dst-address-list membership, resolved from the live lists ($lists: name => [addrs]).
        // Unknown/empty list ⇒ treated as NOT a member (so a test packet flies past blocklists it
        // isn't in, instead of the old sim's false "dropped by rule #0"). Empty pkt IP ⇒ can't
        // evaluate ⇒ passes (mirrors ipMatch). Honors '!list' negation.
        $listMatch = function($listSpec, $ip) use ($lists, $ipMatch) {
            if ($listSpec === '') return true;
            $neg = false; if ($listSpec[0] === '!') { $neg = true; $listSpec = substr($listSpec, 1); }
            if ($ip === '') return true;
            $addrs = $lists[$listSpec] ?? null;
            $member = ($addrs) ? $ipMatch(implode(',', $addrs), $ip) : false;
            return $neg ? !$member : $member;
        };
        $firstMiss = function($r) use (&$pkt,$ipMatch,$portMatch,$listMatch) {   // &$pkt: sees NAT transforms
            if (!empty($r['disabled'])) return 'disabled';
            $p = $r['props'];
            if (!$ipMatch($p['src-address'] ?? '', $pkt['src'] ?? '')) return 'src-address';
            if (!$ipMatch($p['dst-address'] ?? '', $pkt['dst'] ?? '')) return 'dst-address';
            if (!$listMatch($p['src-address-list'] ?? '', $pkt['src'] ?? '')) return 'src-address-list';
            if (!$listMatch($p['dst-address-list'] ?? '', $pkt['dst'] ?? '')) return 'dst-address-list';
            if (($p['protocol'] ?? '') !== '' && ($pkt['protocol'] ?? '') !== '' && $p['protocol'] !== $pkt['protocol']) return 'protocol';
            if (!$portMatch($p['dst-port'] ?? '', (string)($pkt['dst_port'] ?? ''))) return 'dst-port';
            if (!$portMatch($p['src-port'] ?? '', (string)($pkt['src_port'] ?? ''))) return 'src-port';
            if (($p['in-interface'] ?? '') !== '' && ($pkt['in_if'] ?? '') !== '' && $p['in-interface'] !== $pkt['in_if']) return 'in-interface';
            // in-interface-list: resolved ONLY when we know the chosen interface's memberships
            // (pkt['in_if_lists']). Unknown ⇒ can't evaluate ⇒ left as wildcard (matches). Honors '!list'.
            $ifl = $p['in-interface-list'] ?? '';
            if ($ifl !== '' && isset($pkt['in_if_lists']) && is_array($pkt['in_if_lists'])) {
                $neg = false; if ($ifl[0] === '!') { $neg = true; $ifl = substr($ifl, 1); }
                $member = in_array($ifl, $pkt['in_if_lists'], true);
                if ($neg ? $member : !$member) return 'in-interface-list';
            }
            if (($p['connection-state'] ?? '') !== '' && ($pkt['state'] ?? '') !== '' && !in_array($pkt['state'], explode(',', $p['connection-state']), true)) return 'connection-state';
            return null;
        };
        $hops = 0;
        $walk = function($c) use (&$walk,&$steps,&$verdict,&$kind,&$decideIdx,$rules,$firstMiss,&$hops) {
            foreach ($rules as $r) {
                if ($r['chain'] !== $c) continue;
                $miss = $firstMiss($r); $matched = ($miss === null);
                $act = $r['action']; $terminal = false; $note = '';
                if ($matched) {
                    if (in_array($act, ['accept','fasttrack-connection'], true))      { $verdict='ACCEPT'; $kind='accept'; $decideIdx=$r['idx']; $terminal=true; }
                    elseif (in_array($act, ['drop','reject','tarpit'], true))          { $verdict=strtoupper($act); $kind='drop'; $decideIdx=$r['idx']; $terminal=true; }
                    elseif ($act === 'jump')   { $note = 'jump → '.($r['props']['jump-target'] ?? '?'); }
                    elseif ($act === 'return') { $note = 'return to caller'; }
                    else { $note = $act; }   // log / passthrough / add-to-address-list → matched, keeps going
                }
                $steps[] = ['stage'=>'filter','idx'=>$r['idx'],'chain'=>$c,'action'=>$act,'comment'=>preg_replace('/\s*\[nfw[0-9a-f]+\]\s*/','',(string)($r['comment'] ?? '')),
                            'matched'=>$matched,'terminal'=>$terminal,'miss'=>$miss,'note'=>$note,'disabled'=>!empty($r['disabled']),
                            'summary'=>nm_mtfw_rule_summary($r)];
                if ($terminal) return true;
                if ($matched && $act === 'jump' && !empty($r['props']['jump-target']) && $hops++ < 10) { if ($walk($r['props']['jump-target'])) return true; }
                if ($matched && $act === 'return') return false;
            }
            return false;
        };
        // ── PREROUTING · dst-nat (runs BEFORE the filter) ─────────────────────
        // First matching dst-nat/redirect/netmap rewrites the destination, so the FILTER sees the NAT'd
        // packet — exactly like RouterOS. Shown as a NAT gate in the tracer.
        foreach ($nat as $r) {
            if (($r['chain'] ?? '') !== 'dstnat' || !empty($r['disabled'])) continue;
            if ($firstMiss($r) !== null) continue;
            $act = $r['action']; if (!in_array($act, ['dst-nat','netmap','redirect'], true)) continue;
            $p = $r['props']; $oldDst = (string)($pkt['dst'] ?? ''); $oldPort = (string)($pkt['dst_port'] ?? '');
            $newDst = $act === 'redirect' ? 'router' : (trim(explode(',', (string)($p['to-addresses'] ?? ''))[0]) ?: $oldDst);
            $newPort = (($p['to-ports'] ?? '') !== '') ? trim(explode(',', (string)$p['to-ports'])[0]) : $oldPort;
            $steps[] = ['stage'=>'dstnat','kind'=>'nat','idx'=>$r['idx'],'action'=>$act,'matched'=>true,'terminal'=>false,'miss'=>null,'note'=>'',
                'comment'=>preg_replace('/\s*\[nfw[0-9a-f]+\]\s*/','',(string)($r['comment'] ?? '')), 'summary'=>nm_mtfw_rule_summary($r),
                'transform'=>'dst '.($oldDst?:'*').' → '.$newDst.($newPort!==$oldPort?(' :'.$newPort):'')];
            if ($act !== 'redirect') { $pkt['dst'] = $newDst; if (($p['to-ports'] ?? '') !== '') $pkt['dst_port'] = $newPort; }
            break;   // first dst-nat match wins (terminal for that packet in the nat chain)
        }
        // ── the FILTER chain (sees the post-dst-nat packet) ──────────────────
        $walk($chain);
        // ── POSTROUTING · src-nat (only if the packet was ACCEPTED) ──────────
        if ($kind === 'accept') foreach ($nat as $r) {
            if (($r['chain'] ?? '') !== 'srcnat' || !empty($r['disabled'])) continue;
            if ($firstMiss($r) !== null) continue;
            $act = $r['action']; if (!in_array($act, ['masquerade','src-nat','netmap'], true)) continue;
            $p = $r['props']; $oldSrc = (string)($pkt['src'] ?? '');
            $newSrc = $act === 'masquerade' ? 'router WAN' : (trim(explode(',', (string)($p['to-addresses'] ?? ''))[0]) ?: $oldSrc);
            $steps[] = ['stage'=>'srcnat','kind'=>'nat','idx'=>$r['idx'],'action'=>$act,'matched'=>true,'terminal'=>false,'miss'=>null,'note'=>'',
                'comment'=>preg_replace('/\s*\[nfw[0-9a-f]+\]\s*/','',(string)($r['comment'] ?? '')), 'summary'=>nm_mtfw_rule_summary($r),
                'transform'=>'src '.($oldSrc?:'*').' → '.$newSrc];
            if ($act !== 'masquerade') $pkt['src'] = $newSrc;
            break;
        }
        if ($decideIdx === null) { $verdict = 'ACCEPT (no matching rule — default policy)'; $kind = 'accept'; }

        // ── EXACTNESS HINTS (why a "should work" flow is really blocked) ─────
        $hints = [];
        // 1) wrong chain: LAN↔LAN goes through FORWARD, not INPUT/OUTPUT.
        if ($chain === 'input' && $isPriv($orig['src'] ?? '') && $isPriv($orig['dst'] ?? '') && ($orig['src'] ?? '') !== ($orig['dst'] ?? ''))
            $hints[] = ['kind'=>'chain', 'text'=>'This looks like traffic BETWEEN two networks ('.($orig['src']??'').' → '.($orig['dst']??'').'), which traverses the FORWARD chain — not input (input = traffic TO the router itself). Switch CHAIN to “forward”.'];
        // 2) src-nat/masquerade can never unblock a filter DROP (it's postrouting, and only rewrites src).
        if ($kind !== 'accept') foreach ($nat as $r) {
            if (($r['chain'] ?? '') !== 'srcnat' || !empty($r['disabled'])) continue;
            if (!in_array($r['action'], ['masquerade','src-nat','netmap'], true)) continue;
            $p = $r['props'];
            if (!$ipMatch($p['src-address'] ?? '', $orig['src'] ?? '')) continue;      // match the ORIGINAL flow
            if (!$ipMatch($p['dst-address'] ?? '', $orig['dst'] ?? '')) continue;
            if (($p['protocol'] ?? '') !== '' && ($orig['protocol'] ?? '') !== '' && $p['protocol'] !== $orig['protocol']) continue;
            if (!$portMatch($p['dst-port'] ?? '', (string)($orig['dst_port'] ?? ''))) continue;
            $hints[] = ['kind'=>'nat', 'text'=>'A '.$r['action'].' rule (#'.$r['idx'].') matches this traffic — but src-nat is POSTROUTING, applied only AFTER the filter accepts. It rewrites the SOURCE; it does NOT grant permission. To let this flow through, add a filter ACCEPT rule in the '.$chain.' chain (the masquerade then handles the return path).'];
            break;
        }
        return ['ok'=>true, 'verdict'=>$verdict, 'kind'=>$kind, 'decided_by'=>$decideIdx, 'chain'=>$chain,
                'steps'=>$steps, 'effective'=>['src'=>(string)($pkt['src'] ?? ''), 'dst'=>(string)($pkt['dst'] ?? '')], 'hints'=>$hints];
    }
    function nm_routing_in_cidr_safe(string $ip, string $net, int $prefix): bool {
        if (function_exists('nm_routing_in_cidr')) { require_once __DIR__.'/nm_routing.php'; $n=ip2long($net); if($n===false)return false; return nm_routing_in_cidr($ip,$n & 0xFFFFFFFF,$prefix); }
        $i=ip2long($ip); $n=ip2long($net); if($i===false||$n===false)return false; if($prefix<=0)return true; if($prefix>=32)return $i===$n;
        $mask=(~((1<<(32-$prefix))-1))&0xFFFFFFFF; return ($i&$mask)===($n&$mask);
    }

    // ── Templates (return rule objects → dry-run/apply through the normal path) ───
    function nm_mtfw_templates(): array {
        return [
            'baseline' => ['label'=>'★ Baseline firewall (secure a new router)', 'batch'=>true, 'table'=>'filter',
                'desc'=>'One-click protective RouterOS baseline for a fresh/unconfigured router: accept established/related, drop invalid, accept ICMP, accept your management address-list, then DROP all other input; fasttrack + accept-established on forward. Your management IP is auto-added so you are not locked out — and Safe-Apply auto-reverts if anything goes wrong.',
                'rules'=>[
                    ['chain'=>'input','action'=>'accept','connection-state'=>'established,related,untracked','comment'=>'baseline: accept established/related/untracked'],
                    ['chain'=>'input','action'=>'drop','connection-state'=>'invalid','comment'=>'baseline: drop invalid'],
                    ['chain'=>'input','action'=>'accept','protocol'=>'icmp','comment'=>'baseline: accept ICMP (ping)'],
                    ['chain'=>'input','action'=>'accept','src-address-list'=>'mgmt','comment'=>'baseline: accept trusted management'],
                    ['chain'=>'input','action'=>'drop','comment'=>'baseline: DROP all other input'],
                    ['chain'=>'forward','action'=>'fasttrack-connection','connection-state'=>'established,related','comment'=>'baseline: fasttrack established/related'],
                    ['chain'=>'forward','action'=>'accept','connection-state'=>'established,related,untracked','comment'=>'baseline: accept forward established/related'],
                    ['chain'=>'forward','action'=>'drop','connection-state'=>'invalid','comment'=>'baseline: drop invalid forward'],
                ]],
            'secure_input' =>['label'=>'Secure the router (input)', 'desc'=>'Accept established/related, accept from a trusted address-list, drop the rest on input.',
                'rules'=>[
                    ['chain'=>'input','action'=>'accept','connection-state'=>'established,related','comment'=>'accept established/related'],
                    ['chain'=>'input','action'=>'drop','connection-state'=>'invalid','comment'=>'drop invalid'],
                    ['chain'=>'input','action'=>'accept','src-address-list'=>'trusted','comment'=>'accept trusted mgmt'],
                    ['chain'=>'input','action'=>'accept','protocol'=>'icmp','comment'=>'accept ping'],
                    ['chain'=>'input','action'=>'drop','comment'=>'drop all other input'],
                ]],
            'port_forward' => ['label'=>'Port-forward (dst-nat)', 'desc'=>'Forward a WAN port to an internal host.', 'table'=>'nat',
                'rules'=>[['chain'=>'dstnat','action'=>'dst-nat','protocol'=>'tcp','dst-port'=>'{PORT}','in-interface'=>'{WAN}','to-addresses'=>'{HOST}','to-ports'=>'{PORT}','comment'=>'port-forward']]],
            'block_ip' => ['label'=>'Block an IP / list', 'desc'=>'Drop forward+input from a source address or address-list (also offer to hand off to Collective Immunity).',
                'rules'=>[['chain'=>'forward','action'=>'drop','src-address'=>'{IP}','comment'=>'blocked by NEURU'],
                          ['chain'=>'input','action'=>'drop','src-address'=>'{IP}','comment'=>'blocked by NEURU']]],
        ];
    }
}
