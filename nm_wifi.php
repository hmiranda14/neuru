<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — WiFi Control Center engine (universal, driver-based).
//
// Manages WiFi controllers of ANY family over SSH CLI: monitor clients / access
// points / RF / SSIDs, and run core control actions (deauth a client, block /
// unblock a MAC, reboot an AP or the controller) — the SAME way an operator would
// at the CLI, behind confirm + audit. Universal by a DRIVER model: each family
// (Cisco AireOS / Mobility Express now; IOS-XE 9800, autonomous IOS, Aruba, UniFi,
// MikroTik CAPsMAN as slots) declares its command set, prompt, parsers and a
// CAPABILITY MATRIX, so the cockpit only offers what THAT controller supports.
//
// Transport: scripts/nm_wifi_ssh.py (interactive shell — pager off, optional 2nd
// login, y/N confirmations). Creds: nm_ssh_resolve (needs www-data to decrypt).
// Reuse-first: SSH creds + audit + RBAC are the shared NEURU primitives.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_wifi_ensure')) {

require_once __DIR__ . '/nm_secrets.php';   // nm_ssh_resolve / nm_secret_decrypt

// ── schema + RBAC seed ───────────────────────────────────────────────────────
function nm_wifi_ensure($conn): void {
    static $done = false; if ($done) return; $done = true;
    $conn->query("CREATE TABLE IF NOT EXISTS nm_wifi_controllers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        node_id INT NOT NULL,
        driver VARCHAR(24) NOT NULL DEFAULT 'auto',
        label VARCHAR(120) NULL,
        enabled TINYINT NOT NULL DEFAULT 1,
        last_ok DATETIME NULL,
        last_err VARCHAR(255) NULL,
        detected VARCHAR(24) NULL,
        created_by INT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uk_node (node_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    // best-effort RBAC seed: grant the admin role the 'wifi' perm (no admin superuser bypass
    // exists — access is purely role_profiles rows). NOT EXISTS = idempotent without needing a
    // unique index on (role_name,button_key).
    try { $conn->query("INSERT INTO role_profiles (role_name,button_key,enabled) SELECT 'admin','wifi',1 FROM DUAL
        WHERE NOT EXISTS (SELECT 1 FROM role_profiles WHERE role_name='admin' AND button_key='wifi')"); } catch (\Throwable $e) {}
}

// ── driver registry + capability matrix ──────────────────────────────────────
// supported=true → wired up now. false → a slot the framework already knows about.
function nm_wifi_drivers(): array {
    return [
        'aireos' => [
            'label' => 'Cisco AireOS / Mobility Express', 'vendor' => 'cisco', 'supported' => true,
            'prompt' => '\\)\\s*>\\s*$', 'login' => 1, 'prep' => ['config paging disable'],
            'detect' => ['cmd' => 'show sysinfo', 'match' => '/Cisco Controller|AIR-|Mobility Express|Product Version\\.+8\\./i'],
            'caps'  => ['sysinfo','clients','client_detail','aps','wlans','rf','deauth','block','unblock','reboot_ap','reboot_system'],
        ],
        'ios_xe_9800' => [
            'label' => 'Cisco Catalyst 9800 (IOS-XE)', 'vendor' => 'cisco', 'supported' => false,
            'prompt' => '[>#]\\s*$', 'login' => 0, 'prep' => ['terminal length 0'],
            'caps'  => ['sysinfo','clients','aps','wlans','rf','deauth','reboot_ap'],
        ],
        'autonomous_ios' => [
            'label' => 'Cisco Autonomous IOS AP', 'vendor' => 'cisco', 'supported' => false,
            'prompt' => '[>#]\\s*$', 'login' => 0, 'prep' => ['terminal length 0'],
            'caps'  => ['sysinfo','clients','deauth','reboot_system'],
        ],
        'aruba_iap'      => ['label'=>'Aruba Instant AP', 'vendor'=>'aruba', 'supported'=>false, 'prompt'=>'[>#]\\s*$','login'=>0,'prep'=>['no paging'],'caps'=>['clients','aps','wlans','deauth']],
        'unifi'          => ['label'=>'Ubiquiti UniFi',   'vendor'=>'ubiquiti','supported'=>false,'prompt'=>'[>#\\$]\\s*$','login'=>0,'prep'=>[],'caps'=>['clients','aps']],
        'mikrotik_caps'  => ['label'=>'MikroTik CAPsMAN', 'vendor'=>'mikrotik','supported'=>false,'prompt'=>'>\\s*$','login'=>0,'prep'=>[],'caps'=>['clients','aps','deauth']],
    ];
}
function nm_wifi_driver(string $key): ?array { $d = nm_wifi_drivers(); return $d[$key] ?? null; }
function nm_wifi_cap(string $driver, string $cap): bool { $d = nm_wifi_driver($driver); return $d && in_array($cap, $d['caps'] ?? [], true); }

// The show command for each monitor key, per driver.
function nm_wifi_show_cmd(string $driver, string $key, string $arg = ''): string {
    if ($driver === 'aireos') {
        switch ($key) {
            case 'sysinfo':       return 'show sysinfo';
            case 'clients':       return 'show client summary';
            case 'client_detail': return 'show client detail ' . $arg;
            case 'aps':           return 'show ap summary';
            case 'wlans':         return 'show wlan summary';
            case 'rf':            return 'show ap dot11 5ghz summary';
            case 'rf24':          return 'show ap dot11 24ghz summary';
        }
    }
    if ($driver === 'ios_xe_9800') {
        switch ($key) {
            case 'sysinfo': return 'show version';
            case 'clients': return 'show wireless client summary';
            case 'aps':     return 'show ap summary';
            case 'wlans':   return 'show wlan summary';
            case 'rf':      return 'show ap dot11 5ghz summary';
        }
    }
    return '';
}

// The control-action command sequence (steps sent to the shell), per driver.
function nm_wifi_action_steps(string $driver, string $action, array $p): ?array {
    $mac = strtolower(preg_replace('/[^0-9a-fA-F:.-]/', '', (string)($p['mac'] ?? '')));
    if ($driver === 'aireos') {
        switch ($action) {
            case 'deauth':    if ($mac==='') return null; return ['steps'=>['config client deauthenticate ' . $mac], 'summary'=>'deauth ' . $mac];
            case 'block':     if ($mac==='') return null; $d = substr(preg_replace('/[^\w .-]/','',(string)($p['desc'] ?? 'NEURU')),0,40) ?: 'NEURU';
                              return ['steps'=>['config exclusionlist add ' . $mac . ' ' . $d], 'summary'=>'block ' . $mac];
            case 'unblock':   if ($mac==='') return null; return ['steps'=>['config exclusionlist delete ' . $mac], 'summary'=>'unblock ' . $mac];
            case 'reboot_ap': $ap = preg_replace('/[^\w .-]/','',(string)($p['ap'] ?? '')); if ($ap==='') return null;
                              return ['steps'=>['config ap reset ' . $ap, 'y'], 'summary'=>'reboot AP ' . $ap, 'destructive'=>true];
            case 'reboot_system': return ['steps'=>['reset system', 'y', 'y'], 'summary'=>'reboot controller', 'destructive'=>true];
        }
    }
    return null;
}

// ── controllers CRUD ─────────────────────────────────────────────────────────
function nm_wifi_controllers($conn): array {
    nm_wifi_ensure($conn);
    $out = [];
    $r = @$conn->query("SELECT w.*, n.display_name, n.ip_address, n.os_icon
        FROM nm_wifi_controllers w JOIN nm_nodes n ON n.id=w.node_id ORDER BY COALESCE(w.label,n.display_name)");
    while ($r && ($x = $r->fetch_assoc())) {
        $out[] = [
            'id'=>(int)$x['id'], 'node_id'=>(int)$x['node_id'],
            'name'=>$x['label'] ?: $x['display_name'], 'node_name'=>$x['display_name'],
            'ip'=>$x['ip_address'], 'driver'=>$x['driver'], 'detected'=>$x['detected'],
            'enabled'=>(int)$x['enabled'], 'last_ok'=>$x['last_ok'], 'last_err'=>$x['last_err'],
        ];
    }
    return $out;
}
function nm_wifi_controller($conn, int $id): ?array {
    foreach (nm_wifi_controllers($conn) as $c) if ($c['id'] === $id) return $c;
    return null;
}
// Nodes that could be WiFi controllers but aren't registered yet (SSH-capable, router/AP-ish).
function nm_wifi_candidates($conn): array {
    nm_wifi_ensure($conn);
    $out = [];
    $r = @$conn->query("SELECT n.id, n.display_name, n.ip_address, n.os_icon
        FROM nm_nodes n WHERE n.id NOT IN (SELECT node_id FROM nm_wifi_controllers) ORDER BY n.display_name");
    while ($r && ($x = $r->fetch_assoc())) $out[] = ['id'=>(int)$x['id'],'name'=>$x['display_name'],'ip'=>$x['ip_address'],'os_icon'=>$x['os_icon']];
    return $out;
}
function nm_wifi_add($conn, int $node_id, string $driver, string $label, ?int $uid): array {
    nm_wifi_ensure($conn);
    if ($node_id <= 0) return ['ok'=>false,'error'=>'pick a node'];
    $drivers = nm_wifi_drivers();
    if ($driver !== 'auto' && !isset($drivers[$driver])) return ['ok'=>false,'error'=>'unknown driver'];
    $label = substr(trim($label), 0, 120) ?: null;
    $st = $conn->prepare("INSERT INTO nm_wifi_controllers (node_id,driver,label,created_by) VALUES (?,?,?,?)
        ON DUPLICATE KEY UPDATE driver=VALUES(driver), label=VALUES(label), enabled=1");
    $st->bind_param('issi', $node_id, $driver, $label, $uid); $st->execute();
    return ['ok'=>true];
}
function nm_wifi_update($conn, int $id, array $f): array {
    nm_wifi_ensure($conn);
    $sets = []; $types = ''; $vals = [];
    if (isset($f['driver'])) { $sets[]='driver=?'; $types.='s'; $vals[]=substr((string)$f['driver'],0,24); }
    if (isset($f['label']))  { $sets[]='label=?';  $types.='s'; $vals[]=substr(trim((string)$f['label']),0,120); }
    if (isset($f['enabled'])){ $sets[]='enabled=?';$types.='i'; $vals[]=!empty($f['enabled'])?1:0; }
    if (!$sets) return ['ok'=>false,'error'=>'nothing to update'];
    $types.='i'; $vals[]=$id;
    $st = $conn->prepare("UPDATE nm_wifi_controllers SET ".implode(',',$sets)." WHERE id=?");
    $st->bind_param($types, ...$vals); $st->execute();
    return ['ok'=>true];
}
function nm_wifi_delete($conn, int $id): array { nm_wifi_ensure($conn); $conn->query("DELETE FROM nm_wifi_controllers WHERE id=".(int)$id); return ['ok'=>true]; }
function nm_wifi_mark($conn, int $id, bool $ok, string $detail = ''): void {
    nm_wifi_ensure($conn);
    if ($ok) { $st=$conn->prepare("UPDATE nm_wifi_controllers SET last_ok=NOW(), last_err=NULL WHERE id=?"); $st->bind_param('i',$id); $st->execute(); }
    else { $d=substr($detail,0,255); $st=$conn->prepare("UPDATE nm_wifi_controllers SET last_err=? WHERE id=?"); $st->bind_param('si',$d,$id); $st->execute(); }
}

// ── transport ────────────────────────────────────────────────────────────────
// Run a set of shell steps on a controller's node via the WiFi SSH helper.
function nm_wifi_ssh_run($ssh, array $prep, array $steps, string $prompt, int $login, int $timeout = 30): array {
    $py = '/opt/netmon-venv/bin/python3';
    if (!is_file($py)) $py = trim((string)@shell_exec('command -v python3')) ?: 'python3';
    $script = __DIR__ . '/scripts/nm_wifi_ssh.py';
    if (!is_file($script)) return ['ok'=>false,'error'=>'wifi ssh helper missing'];
    $env = [
        'NM_SSH_HOST'=>(string)($ssh['host'] ?? ''), 'NM_SSH_PORT'=>(string)((int)($ssh['port'] ?? 22) ?: 22),
        'NM_SSH_USER'=>(string)($ssh['username'] ?? ''), 'NM_SSH_PASS'=>(string)($ssh['password'] ?? ''),
        'NM_SSH_KEY'=>(string)($ssh['private_key'] ?? ''), 'NM_SSH_TIMEOUT'=>(string)$timeout,
        'NM_WIFI_PREP'=>json_encode(array_values($prep)), 'NM_WIFI_STEPS'=>json_encode(array_values($steps)),
        'NM_WIFI_PROMPT'=>$prompt, 'NM_WIFI_LOGIN'=>$login ? '1' : '0',
        'NM_PYLIBS'=>(is_dir('/home/neuru/netmon-pylibs')?'/home/neuru/netmon-pylibs':'/home/hmiranda/netmon-pylibs'), 'PATH'=>'/usr/bin:/bin:/usr/local/bin', 'HOME'=>'/tmp', 'LANG'=>'C.UTF-8',
    ];
    $desc = [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];
    $proc = @proc_open([$py,$script], $desc, $pipes, null, $env);
    if (!is_resource($proc)) return ['ok'=>false,'error'=>'cannot start wifi ssh helper'];
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]); fclose($pipes[1]);
    $err = stream_get_contents($pipes[2]); fclose($pipes[2]);
    $code = proc_close($proc);
    if ($code !== 0) return ['ok'=>false,'error'=>trim($err) ?: ('ssh exit '.$code)];
    if (trim((string)$out) === '') return ['ok'=>false,'error'=>trim($err) ?: 'empty output'];
    return ['ok'=>true,'transcript'=>$out];
}

// Resolve the effective driver ('auto' → detect once, remember it).
function nm_wifi_effective_driver($conn, array $ctrl): array {
    $drv = (string)$ctrl['driver'];
    if ($drv !== 'auto') return ['ok'=>true,'driver'=>$drv];
    if (!empty($ctrl['detected'])) return ['ok'=>true,'driver'=>$ctrl['detected']];
    $det = nm_wifi_detect($conn, (int)$ctrl['node_id']);
    if (!empty($det['ok'])) { $conn->query("UPDATE nm_wifi_controllers SET detected='".$conn->real_escape_string($det['driver'])."' WHERE id=".(int)$ctrl['id']); return ['ok'=>true,'driver'=>$det['driver']]; }
    return ['ok'=>false,'error'=>$det['error'] ?? 'could not detect controller type'];
}

// Probe a node to identify its WiFi controller family.
function nm_wifi_detect($conn, int $node_id): array {
    $ssh = nm_ssh_resolve($conn, $node_id);
    if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'no SSH credential for node'];
    // Try AireOS first (the common standalone/ME case), then others.
    foreach (nm_wifi_drivers() as $key => $d) {
        if (empty($d['supported']) || empty($d['detect'])) continue;
        $r = nm_wifi_ssh_run($ssh, $d['prep'] ?? [], [$d['detect']['cmd']], $d['prompt'] ?? '[>#]\\s*$', (int)($d['login'] ?? 0), 20);
        if (!empty($r['ok']) && preg_match($d['detect']['match'], $r['transcript'])) return ['ok'=>true,'driver'=>$key,'raw'=>substr($r['transcript'],0,400)];
    }
    return ['ok'=>false,'error'=>'unrecognized controller (no supported driver matched show sysinfo)'];
}

// ── transcript splitting + parsers ───────────────────────────────────────────
// Split a multi-command transcript into per-command output blocks (the shell
// echoes each command, so we slice between echoes — sequential to avoid matching
// a command string that appears inside another command's output).
function nm_wifi_split(string $transcript, array $cmds): array {
    $t = str_replace(["\r\n","\r"], "\n", $transcript);
    $len = strlen($t); $pos = []; $off = 0;
    foreach ($cmds as $i => $c) { $p = ($c === '') ? false : strpos($t, $c, $off); $pos[$i] = $p; if ($p !== false) $off = $p + strlen($c); }
    $out = [];
    foreach ($cmds as $i => $c) {
        if ($pos[$i] === false) { $out[$i] = ''; continue; }
        $start = $pos[$i] + strlen($c);
        $end = $len;
        for ($j = $i + 1; $j < count($cmds); $j++) { if ($pos[$j] !== false) { $end = $pos[$j]; break; } }
        $block = substr($t, $start, $end - $start);
        // drop the trailing CLI prompt line(s)
        $block = preg_replace('/\n?\([^)]*\)\s*>\s*$/', '', $block);
        $block = preg_replace('/\n?[\w.\-]+[>#]\s*$/', '', $block);
        $out[$i] = trim($block, "\n");
    }
    return $out;
}

// AireOS dotted "Key.......... value" block → assoc.
function nm_wifi_parse_dotted(string $block): array {
    $o = [];
    foreach (preg_split('/\n/', $block) as $ln) {
        if (preg_match('/^\s*(.+?)\.{2,}\s*(.*)$/', $ln, $m)) { $k = trim($m[1]); $v = trim($m[2]); if ($k !== '') $o[$k] = $v; }
    }
    return $o;
}

// AireOS space-aligned table → array of assoc rows, using the dash separator line
// to compute column spans (robust against variable spacing).
function nm_wifi_parse_table(string $block): array {
    $lines = preg_split('/\n/', $block);
    $sepIdx = -1;
    for ($i = 0; $i < count($lines); $i++) {
        $ln = $lines[$i];
        if (preg_match('/^[\s-]*-{2,}[\s-]*$/', $ln) && strpos($ln, '-') !== false) { $sepIdx = $i; break; }
    }
    if ($sepIdx < 1) return [];
    $header = $lines[$sepIdx - 1];
    // column spans from contiguous dash groups
    $spans = [];
    if (preg_match_all('/-+/', $lines[$sepIdx], $mm, PREG_OFFSET_CAPTURE)) {
        foreach ($mm[0] as $g) $spans[] = [$g[1], strlen($g[0])];
    }
    if (!$spans) return [];
    // Each column runs from its dash-group start to the NEXT group's start (last → EOL),
    // so it captures the dash run + the inter-column gap; trim removes the padding. This
    // avoids bleeding characters between adjacent columns.
    $n = count($spans);
    $slice = function(string $s, int $start, int $end): string {
        if ($start >= strlen($s)) return '';
        return trim($end === PHP_INT_MAX ? substr($s, $start) : substr($s, $start, max(0, $end - $start)));
    };
    $bound = [];
    for ($k = 0; $k < $n; $k++) $bound[$k] = ($k + 1 < $n) ? $spans[$k + 1][0] : PHP_INT_MAX;
    $cols = [];
    foreach ($spans as $k => $sp) $cols[] = $slice($header, $sp[0], $bound[$k]) ?: ('col' . $k);
    $rows = [];
    for ($i = $sepIdx + 1; $i < count($lines); $i++) {
        $ln = rtrim($lines[$i]);
        if (trim($ln) === '' || preg_match('/^\s*-{2,}/', $ln)) continue;
        if (preg_match('/^\s*\([^)]*\)\s*>/', $ln) || preg_match('/Number of/i', $ln)) continue;
        $row = [];
        foreach ($spans as $k => $sp) $row[$cols[$k]] = $slice($ln, $sp[0], $bound[$k]);
        if (implode('', $row) !== '') $rows[] = $row;
    }
    return $rows;
}

// Normalize a parsed table into the cockpit's client/ap/wlan shapes (AireOS).
function nm_wifi_norm_clients(array $rows): array {
    $out = [];
    foreach ($rows as $r) {
        $g = function(array $r, array $keys) { foreach ($keys as $k) foreach ($r as $kk => $vv) if (stripos($kk, $k) !== false) return $vv; return ''; };
        $mac = $g($r, ['MAC']);
        if ($mac === '' || !preg_match('/[0-9a-f]{2}[:.]/i', $mac)) continue;
        $out[] = [
            'mac'=>strtolower($mac), 'ap'=>$g($r, ['AP Name','AP']), 'status'=>$g($r, ['Status','State']),
            'wlan'=>$g($r, ['WLAN']), 'proto'=>$g($r, ['Protocol','Proto']), 'auth'=>$g($r, ['Auth']),
        ];
    }
    return $out;
}
function nm_wifi_norm_aps(array $rows): array {
    $out = [];
    foreach ($rows as $r) {
        $g = function(array $r, array $keys) { foreach ($keys as $k) foreach ($r as $kk => $vv) if (stripos($kk, $k) !== false) return $vv; return ''; };
        $name = $g($r, ['AP Name','Name']);
        if ($name === '') continue;
        $out[] = ['name'=>$name, 'model'=>$g($r,['Model']), 'mac'=>$g($r,['Ethernet MAC','MAC']),
            'ip'=>$g($r,['IP']), 'clients'=>$g($r,['Clients','Client']), 'slots'=>$g($r,['Slots','Slot'])];
    }
    return $out;
}
function nm_wifi_norm_wlans(array $rows): array {
    $out = [];
    foreach ($rows as $r) {
        $g = function(array $r, array $keys) { foreach ($keys as $k) foreach ($r as $kk => $vv) if (stripos($kk, $k) !== false) return $vv; return ''; };
        $id = $g($r, ['WLAN ID','ID']);
        if ($id === '' && $g($r,['Profile','SSID']) === '') continue;
        $out[] = ['id'=>$id, 'name'=>$g($r,['Profile','SSID','Name']), 'status'=>$g($r,['Status']), 'iface'=>$g($r,['Interface'])];
    }
    return $out;
}
function nm_wifi_norm_rf(array $rows): array {
    $out = [];
    foreach ($rows as $r) {
        $g = function(array $r, array $keys) { foreach ($keys as $k) foreach ($r as $kk => $vv) if (stripos($kk, $k) !== false) return $vv; return ''; };
        $name = $g($r,['AP Name','Name']); if ($name==='') continue;
        $out[] = ['ap'=>$name, 'channel'=>$g($r,['Channel']), 'power'=>$g($r,['Power','TxPower','Tx']),
            'admin'=>$g($r,['Admin']), 'oper'=>$g($r,['Oper'])];
    }
    return $out;
}

// ── high-level: fetch a monitor snapshot ─────────────────────────────────────
// $keys ⊂ [sysinfo,clients,aps,wlans,rf]. Returns parsed data + raw per command.
function nm_wifi_snapshot($conn, array $ctrl, array $keys, bool $withRaw = false): array {
    $ed = nm_wifi_effective_driver($conn, $ctrl);
    if (empty($ed['ok'])) { nm_wifi_mark($conn, (int)$ctrl['id'], false, $ed['error'] ?? 'no driver'); return ['ok'=>false,'error'=>$ed['error'] ?? 'no driver']; }
    $driver = $ed['driver']; $d = nm_wifi_driver($driver);
    if (!$d) return ['ok'=>false,'error'=>'driver not available'];
    $ssh = nm_ssh_resolve($conn, (int)$ctrl['node_id']);
    if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'no SSH credential (set one on the node)'];
    // build the command list for the requested keys the driver supports
    $cmds = []; $map = [];
    foreach ($keys as $k) { if (!nm_wifi_cap($driver, $k)) continue; $c = nm_wifi_show_cmd($driver, $k); if ($c === '') continue; $cmds[] = $c; $map[$k] = $c; }
    if (!$cmds) return ['ok'=>false,'error'=>'no supported monitor commands for this driver'];
    $r = nm_wifi_ssh_run($ssh, $d['prep'] ?? [], $cmds, $d['prompt'] ?? '[>#]\\s*$', (int)($d['login'] ?? 0), 35);
    if (empty($r['ok'])) { nm_wifi_mark($conn, (int)$ctrl['id'], false, $r['error'] ?? 'ssh failed'); return ['ok'=>false,'error'=>$r['error'] ?? 'ssh failed']; }
    $blocks = nm_wifi_split($r['transcript'], $cmds);
    $byCmd = []; foreach ($cmds as $i => $c) $byCmd[$c] = $blocks[$i] ?? '';
    $data = []; $raw = [];
    foreach ($map as $k => $c) {
        $blk = $byCmd[$c] ?? '';
        if ($withRaw) $raw[$k] = $blk;
        if ($driver === 'aireos') {
            if ($k === 'sysinfo')      $data[$k] = nm_wifi_parse_dotted($blk);
            elseif ($k === 'clients')  $data[$k] = nm_wifi_norm_clients(nm_wifi_parse_table($blk));
            elseif ($k === 'aps')      $data[$k] = nm_wifi_norm_aps(nm_wifi_parse_table($blk));
            elseif ($k === 'wlans')    $data[$k] = nm_wifi_norm_wlans(nm_wifi_parse_table($blk));
            elseif ($k === 'rf')       $data[$k] = nm_wifi_norm_rf(nm_wifi_parse_table($blk));
            else                       $data[$k] = $blk;
        } else {
            $data[$k] = $blk;   // other drivers: raw for now (slots)
        }
    }
    nm_wifi_mark($conn, (int)$ctrl['id'], true);
    return ['ok'=>true,'driver'=>$driver,'data'=>$data] + ($withRaw ? ['raw'=>$raw] : []);
}

// One client's detail (RSSI/SNR/throughput/capabilities).
function nm_wifi_client_detail($conn, array $ctrl, string $mac): array {
    $ed = nm_wifi_effective_driver($conn, $ctrl); if (empty($ed['ok'])) return ['ok'=>false,'error'=>$ed['error']];
    $driver = $ed['driver']; $d = nm_wifi_driver($driver);
    if (!nm_wifi_cap($driver, 'client_detail')) return ['ok'=>false,'error'=>'not supported'];
    $mac = strtolower(preg_replace('/[^0-9a-fA-F:.-]/', '', $mac)); if ($mac==='') return ['ok'=>false,'error'=>'bad mac'];
    $ssh = nm_ssh_resolve($conn, (int)$ctrl['node_id']); if (!$ssh) return ['ok'=>false,'error'=>'no ssh'];
    $cmd = nm_wifi_show_cmd($driver, 'client_detail', $mac);
    $r = nm_wifi_ssh_run($ssh, $d['prep'] ?? [], [$cmd], $d['prompt'] ?? '[>#]\\s*$', (int)($d['login'] ?? 0), 30);
    if (empty($r['ok'])) return ['ok'=>false,'error'=>$r['error']];
    $blk = nm_wifi_split($r['transcript'], [$cmd])[0] ?? '';
    return ['ok'=>true,'mac'=>$mac,'detail'=>nm_wifi_parse_dotted($blk),'raw'=>$blk];
}

// ── control action (deauth / block / unblock / reboot) — cap-checked + audited ─
function nm_wifi_action($conn, array $ctrl, string $action, array $params, ?int $uid): array {
    $ed = nm_wifi_effective_driver($conn, $ctrl); if (empty($ed['ok'])) return ['ok'=>false,'error'=>$ed['error']];
    $driver = $ed['driver']; $d = nm_wifi_driver($driver);
    if (!nm_wifi_cap($driver, $action)) return ['ok'=>false,'error'=>'This controller does not support: '.$action];
    $seq = nm_wifi_action_steps($driver, $action, $params);
    if (!$seq) return ['ok'=>false,'error'=>'invalid parameters for '.$action];
    $ssh = nm_ssh_resolve($conn, (int)$ctrl['node_id']);
    if (!$ssh || empty($ssh['username'])) return ['ok'=>false,'error'=>'no SSH credential'];
    $r = nm_wifi_ssh_run($ssh, $d['prep'] ?? [], $seq['steps'], $d['prompt'] ?? '[>#]\\s*$', (int)($d['login'] ?? 0), 40);
    $ok = !empty($r['ok']);
    // audit every action (best-effort)
    if (function_exists('nm_audit')) { try { nm_audit($conn, 'wifi.'.$action, ['target_type'=>'wifi_controller','target_id'=>(int)$ctrl['id'],'details'=>['summary'=>$seq['summary'],'node'=>$ctrl['node_id']]]); } catch (\Throwable $e) {} }
    nm_wifi_mark($conn, (int)$ctrl['id'], $ok, $ok ? '' : ($r['error'] ?? 'action failed'));
    if (!$ok) return ['ok'=>false,'error'=>$r['error'] ?? 'action failed'];
    $tail = trim(substr((string)($r['transcript'] ?? ''), -280));
    return ['ok'=>true,'summary'=>$seq['summary'],'output'=>$tail];
}

} // end guard
