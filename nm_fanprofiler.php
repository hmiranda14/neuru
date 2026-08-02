<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Fan Profiler engine. Reads / analyzes / edits / switches the gamer's
// FanControl (github.com/Rem0o/FanControl.Releases) config JSON files over the
// SAME agentless Windows-over-SSH we already use for Game Mode telemetry.
//
// NEURU does NOT drive the fans live (FanControl does) — it OPTIMIZES the CONFIG:
// list the saved configs, visualize every fan curve, mark where the PC runs now,
// advise how to lower temps, edit curve points, and switch the active profile
// (write it over configuration.json + relaunch FanControl). Perm 'gaming'.
//
// Reuses nm_win_ps / _nm_g_out / nm_win_resolve_ssh / nm_win_hosts (nm_gaming.php).
// PowerShell is single-quoted throughout (nm_win_ps sends single-line PS).
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_gaming.php';   // pulls nm_winhost.php (nm_win_ps, nm_win_resolve_ssh, nm_win_hosts)

if (!function_exists('nm_fp_default_dir')) {

function nm_fp_default_dir(): string { return 'C:\\Program Files (x86)\\FanControl\\Configurations'; }
function nm_fp_root_config(): string  { return 'C:\\Program Files (x86)\\FanControl\\configuration.json'; }
function nm_fp_exe(): string          { return 'C:\\Program Files (x86)\\FanControl\\FanControl.exe'; }

// per-rig config directory (default overridable — the gamer may move it)
function nm_fp_dir($conn, int $rigId): string {
    $d = '';
    if ($conn instanceof mysqli) { try {
        $st = $conn->prepare("SELECT setting_val FROM nm_settings WHERE setting_key=? LIMIT 1");
        $k = 'fanprofiler_dir_' . $rigId; $st->bind_param('s', $k); $st->execute();
        $r = $st->get_result()->fetch_assoc(); $st->close(); $d = trim((string)($r['setting_val'] ?? ''));
    } catch (\Throwable $e) {} }
    return $d !== '' ? $d : nm_fp_default_dir();
}
function nm_fp_dir_set($conn, int $rigId, string $dir): bool {
    if (!($conn instanceof mysqli)) return false;
    $dir = trim($dir); if ($dir === '') $dir = nm_fp_default_dir();
    try {
        $st = $conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES (?,?)
                              ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
        $k = 'fanprofiler_dir_' . $rigId; $st->bind_param('ss', $k, $dir); $st->execute(); $st->close(); return true;
    } catch (\Throwable $e) { return false; }
}

// a single-quoted PS path literal (FanControl paths have spaces/backslashes/parens — all literal in '')
function _nm_fp_q(string $path): string { return "'" . str_replace("'", "''", $path) . "'"; }

// list the saved configs + flag which one is currently ACTIVE (matches configuration.json by hash)
function nm_fp_list($ssh, string $dir): array {
    $q = _nm_fp_q($dir); $root = _nm_fp_q(nm_fp_root_config());
    $ps = '$ErrorActionPreference=\'SilentlyContinue\'; '
        . '$root=' . $root . '; $rh=\'\'; if(Test-Path $root){ $rh=(Get-FileHash -Algorithm MD5 $root).Hash }; '
        . '$fc=Get-Process FanControl -ErrorAction SilentlyContinue; '
        . '$items=@(Get-ChildItem -Path ' . $q . ' -Filter *.json | ForEach-Object { [pscustomobject]@{ name=$_.Name; size=$_.Length; mtime=$_.LastWriteTimeUtc.ToString(\'o\'); hash=(Get-FileHash -Algorithm MD5 $_.FullName).Hash } }); '
        . '[pscustomobject]@{ ok=$true; dir=' . $q . '; rootHash=$rh; running=[bool]$fc; files=$items } | ConvertTo-Json -Depth 4 -Compress';
    $r = nm_win_ps($ssh, $ps, 25); $out = trim(_nm_g_out($r));
    $j = json_decode($out, true);
    if (!is_array($j)) return ['ok' => false, 'error' => 'could not list configs (is FanControl installed / path correct?)', 'raw' => mb_substr($out, 0, 200)];
    $files = [];
    foreach (($j['files'] ?? []) as $f) {
        if (!is_array($f)) continue;
        $files[] = [
            'name'   => (string)($f['name'] ?? ''),
            'size'   => (int)($f['size'] ?? 0),
            'mtime'  => (string)($f['mtime'] ?? ''),
            'active' => ($j['rootHash'] ?? '') !== '' && strcasecmp((string)($f['hash'] ?? ''), (string)$j['rootHash']) === 0,
        ];
    }
    usort($files, fn($a, $b) => strcasecmp($a['name'], $b['name']));
    return ['ok' => true, 'dir' => $dir, 'running' => (bool)($j['running'] ?? false), 'files' => $files];
}

// read one config file → raw JSON string
function nm_fp_read_raw($ssh, string $filepath): string {
    $ps = 'Get-Content -Raw -LiteralPath ' . _nm_fp_q($filepath);
    return trim(_nm_g_out(nm_win_ps($ssh, $ps, 20)));
}

// friendly-ify a FanControl sensor Identifier → a readable temp source name
function _nm_fp_src(string $id): string {
    if ($id === '') return '';
    if (stripos($id, 'gpu') !== false || stripos($id, 'nvapi') !== false || stripos($id, 'gb2') !== false) return 'GPU';
    if (stripos($id, 'cpu') !== false || stripos($id, 'core') !== false || stripos($id, 'package') !== false) return 'CPU';
    if (stripos($id, 'intelcpu') !== false || stripos($id, 'amdcpu') !== false) return 'CPU';
    if (stripos($id, 'lpc') !== false || stripos($id, 'it86') !== false || stripos($id, 'nct') !== false) return 'Motherboard';
    $bits = array_values(array_filter(explode('/', $id))); return ucfirst($bits[0] ?? 'sensor');
}
// parse a FanControl config into a rich, viz-ready structure (surfaces everything useful in the JSON)
function nm_fp_parse(string $rawJson): array {
    $j = json_decode($rawJson, true);
    if (!is_array($j) || !isset($j['FanControl'])) return ['ok' => false, 'error' => 'not a FanControl config'];
    $fc = $j['FanControl'];
    // curves: name => {points:[[temp,pct]], src, min, max, type, mix, fn}
    $curves = [];
    foreach (($fc['FanCurves'] ?? []) as $cv) {
        if (!is_array($cv)) continue;
        $name = (string)($cv['Name'] ?? '');
        if (isset($cv['Points']) && is_array($cv['Points'])) {           // graph curve (temp → %)
            $pts = [];
            foreach ($cv['Points'] as $p) { $xy = explode(',', (string)$p); if (count($xy) === 2) $pts[] = [round((float)$xy[0], 1), round((float)$xy[1], 1)]; }
            usort($pts, fn($a, $b) => $a[0] <=> $b[0]);
            $curves[$name] = ['name' => $name, 'type' => 'graph', 'points' => $pts,
                'srcId' => (string)($cv['SelectedTempSource']['Identifier'] ?? ''),
                'src'   => _nm_fp_src((string)($cv['SelectedTempSource']['Identifier'] ?? '')),
                'min'   => (float)($cv['MinimumTemperature'] ?? 20), 'max' => (float)($cv['MaximumTemperature'] ?? 90),
                'hyst'  => isset($cv['HysteresisConfig']) ? true : false];
        } elseif (isset($cv['SelectedFanCurves'])) {                     // mix curve (combines others)
            $mix = array_map(fn($m) => (string)($m['Name'] ?? ''), (array)$cv['SelectedFanCurves']);
            $fnMap = [0 => 'Max', 1 => 'Min', 2 => 'Average', 3 => 'Sum', 4 => 'Subtract'];
            $curves[$name] = ['name' => $name, 'type' => 'mix', 'mix' => $mix,
                'fn' => (int)($cv['SelectedMixFunction'] ?? 0), 'fnName' => $fnMap[(int)($cv['SelectedMixFunction'] ?? 0)] ?? 'Max'];
        } elseif ($name !== '') {                                        // Flat / Trigger / Sync / Linear / Auto — show, not editable yet
            $ct = 'other';
            if (isset($cv['SelectedControl']))       $ct = 'sync';
            elseif (isset($cv['IdleTemperature']) && isset($cv['LoadSpeed']))  $ct = 'trigger';
            elseif (isset($cv['IdleTemperature']) && isset($cv['Step']))       $ct = 'auto';
            elseif (isset($cv['Speed']) || isset($cv['FanSpeed']))            $ct = 'flat';
            elseif (isset($cv['MinimumTemperature']) && isset($cv['MinimumSpeed'])) $ct = 'linear';
            $curves[$name] = ['name' => $name, 'type' => $ct,
                'src' => _nm_fp_src((string)($cv['SelectedTempSource']['Identifier'] ?? '')),
                'raw' => $cv];
        }
    }
    // fans (Controls): ALL of them (flag enabled/hidden) with full detail
    $fans = [];
    foreach (($fc['Controls'] ?? []) as $ctl) {
        if (!is_array($ctl)) continue;
        $cal = [];
        foreach (($ctl['Calibration'] ?? []) as $c) { if (is_array($c) && count($c) >= 2) $cal[] = [(int)$c[0], (int)$c[1]]; }
        $rpms = array_map(fn($c) => $c[1], $cal);
        $nick = (string)($ctl['NickName'] ?? 'Fan');
        $fans[] = [
            'name'     => $nick,
            'pump'     => (stripos($nick, 'pump') !== false),   // AIO pumps run flat-out (95-100%) per cooler spec — never nag to change them
            'curve'    => (string)($ctl['SelectedFanCurve']['Name'] ?? ''),
            'cal'      => $cal,                                          // [[pct,rpm],...]
            'rpmMin'   => $rpms ? min(array_filter($rpms, fn($r) => $r > 0) ?: [0]) : 0,
            'rpmMax'   => $rpms ? max($rpms) : 0,
            'enabled'  => !empty($ctl['Enable']),
            'hidden'   => !empty($ctl['IsHidden']),
            'manual'   => !empty($ctl['ManualControl']),
            'manualV'  => (int)($ctl['ManualControlValue'] ?? 0),
            'minPct'   => (int)($ctl['MinimumPercent'] ?? 0),
            'start'    => (int)($ctl['SelectedStart'] ?? 0),
            'stop'     => (int)($ctl['SelectedStop'] ?? 0),
            'offset'   => (int)($ctl['SelectedOffset'] ?? 0),
            'ident'    => (string)($ctl['Identifier'] ?? ''),
            'kind'     => _nm_fp_kind((string)($ctl['NickName'] ?? '') . ' ' . (string)($ctl['SelectedFanCurve']['Name'] ?? '')),
        ];
    }
    // which enabled fans follow each curve (a curve is shared — this is the real relationship)
    $usedBy = [];
    foreach ($fans as $fn2) { if (empty($fn2['enabled']) || !empty($fn2['hidden']) || $fn2['manual']) continue;
        $cn = $fn2['curve']; if ($cn === '') continue; $usedBy[$cn][] = $fn2['name']; }
    foreach ($curves as &$cvr) { $cvr['usedBy'] = $usedBy[$cvr['name']] ?? []; } unset($cvr);
    // config-level meta
    $enabledFans = array_values(array_filter($fans, fn($f) => $f['enabled'] && !$f['hidden']));
    $sensSet = $j['Sensors']['LibreHardwareMonitorSettings'] ?? [];
    return ['ok' => true, 'version' => (string)($j['__VERSION__'] ?? ''),
        'fans' => $fans, 'fansActive' => count($enabledFans), 'fansTotal' => count($fans),
        'curves' => array_values($curves), 'curveCount' => count($curves),
        'fahrenheit' => !empty($j['MainWindow']['Fahrenheit']),
        'sensorsOn' => array_values(array_filter(array_keys(array_filter($sensSet, fn($v) => $v === true)))),
    ];
}

// PREVIEW a preset without writing: returns each graph curve's shifted points (for the on-screen overlay)
function nm_fp_preview_points(array $parsed, string $preset): array {
    $delta = $preset === 'cooler' ? 12 : ($preset === 'quiet' ? -10 : 0);
    $out = [];
    foreach (($parsed['curves'] ?? []) as $cv) {
        if (($cv['type'] ?? '') !== 'graph') continue;
        $out[$cv['name']] = array_map(fn($p) => [$p[0], max(0, min(100, round($p[1] + $delta, 1)))], $cv['points']);
    }
    return $out;
}

function _nm_fp_kind(string $s): string {
    $s = strtolower($s);
    if (strpos($s, 'gpu') !== false) return 'gpu';
    if (strpos($s, 'cpu') !== false || strpos($s, 'aio') !== false || strpos($s, 'pump') !== false) return 'cpu';
    return 'case';
}

// interpolate a curve's % at a given temp (piecewise linear)
function nm_fp_pct_at(array $points, float $temp): ?float {
    if (!$points) return null;
    if ($temp <= $points[0][0]) return $points[0][1];
    $n = count($points);
    if ($temp >= $points[$n-1][0]) return $points[$n-1][1];
    for ($i = 1; $i < $n; $i++) {
        if ($temp <= $points[$i][0]) {
            [$x0, $y0] = $points[$i-1]; [$x1, $y1] = $points[$i];
            $t = ($x1 - $x0) > 0 ? ($temp - $x0) / ($x1 - $x0) : 0;
            return round($y0 + ($y1 - $y0) * $t, 1);
        }
    }
    return $points[$n-1][1];
}

// ADVICE: compare the config's curves against the rig's LIVE temps → plain tips to run cooler.
// $temps = ['cpu'=>°C|null, 'gpu'=>°C|null, 'hot'=>°C|null]  (from nm_gaming live telemetry)
function nm_fp_analyze(array $parsed, array $temps): array {
    $tips = [];
    $curveByName = [];
    foreach (($parsed['curves'] ?? []) as $c) $curveByName[$c['name']] = $c;

    foreach (($parsed['fans'] ?? []) as $fan) {
        if (empty($fan['enabled']) || !empty($fan['hidden'])) continue;   // ignore disabled/hidden fans
        $kind = $fan['kind'];
        $t = $kind === 'gpu' ? ($temps['gpu'] ?? null) : ($kind === 'cpu' ? ($temps['cpu'] ?? $temps['hot'] ?? null) : ($temps['hot'] ?? null));
        if (!empty($fan['pump'])) {
            // AIO pumps are SUPPOSED to run flat-out (95-100%) per the cooler spec — never advise a curve.
            if ($fan['manual'] && $fan['manualV'] < 95) $tips[] = ['info', $fan['name'] . ' (AIO pump) is at ' . $fan['manualV'] . '%. Pumps usually run 95-100% per the cooler spec — nudge it up ONLY if you want a cooler CPU. Your call.'];
            continue;   // pump at 95-100% (or on its own curve) = leave it exactly as the user set it
        }
        if ($fan['manual']) { $tips[] = ['info', $fan['name'] . ' is on manual ' . $fan['manualV'] . '% — your choice, and NEURU keeps it. Optional: put it on a temp curve so it ramps under load (cooler when needed, quieter at idle).']; continue; }
        $cv = $curveByName[$fan['curve']] ?? null;
        if (!$cv || $cv['type'] !== 'graph' || empty($cv['points'])) continue;
        if ($t === null) continue;
        $pctNow = nm_fp_pct_at($cv['points'], (float)$t);
        // steepness: % at 80°C vs at 60°C — a lazy curve barely ramps
        $p80 = nm_fp_pct_at($cv['points'], 80.0); $p60 = nm_fp_pct_at($cv['points'], 60.0);
        $ramp = ($p80 !== null && $p60 !== null) ? ($p80 - $p60) : null;
        if ($t >= 78 && $pctNow !== null && $pctNow < 75) {
            $tips[] = ['crit', $fan['name'] . ' is HOT (' . round($t) . '°C) but the curve only spins it at ' . round($pctNow) . '% — raise the ' . ($kind === 'gpu' ? 'GPU' : 'CPU') . ' curve above ~70°C toward 90–100% to pull temps down fast.'];
        } elseif ($ramp !== null && $ramp < 25) {
            $tips[] = ['warn', $fan['name'] . '\'s curve is lazy (only +' . round($ramp) . '% from 60→80°C) — steepen it so the fan reacts before the chip gets hot. Cooler under load, still quiet at idle.'];
        } elseif ($t !== null && $t < 55 && $pctNow !== null && $pctNow > 55) {
            $tips[] = ['good', $fan['name'] . ' runs at ' . round($pctNow) . '% while cool (' . round($t) . '°C) — you can lower the low-temp points a bit for a quieter idle without hurting load temps.'];
        }
    }
    // ── component-level heat from the full LHM sensor tree — flag what's hot even if no fan directly cools it ──
    $gm = $temps['gpumem'] ?? null;
    if ($gm !== null && $gm >= 90)      $tips[] = ['crit', 'GPU memory (VRAM) junction is at ' . round($gm) . '°C — very hot. Raise the GPU fan curve + improve case airflow; sustained >95°C throttles the memory.'];
    elseif ($gm !== null && $gm >= 84)  $tips[] = ['warn', 'GPU memory junction is warm (' . round($gm) . '°C) — a steeper GPU fan curve keeps GDDR happy under load.'];
    $vm = $temps['vrm'] ?? ($temps['mobo'] ?? null);
    if ($vm !== null && $vm >= 90)      $tips[] = ['crit', 'Motherboard/VRM is at ' . round($vm) . '°C — speed up a rear/top exhaust fan; hot VRMs throttle the CPU.'];
    elseif ($vm !== null && $vm >= 80)  $tips[] = ['warn', 'Motherboard/VRM is running warm (' . round($vm) . '°C) — a top/rear exhaust fan on a steeper curve helps.'];
    $nv = $temps['storage'] ?? null;
    if ($nv !== null && $nv >= 72)      $tips[] = ['crit', 'An NVMe/SSD is at ' . round($nv) . '°C — it will thermal-throttle (slower load times). Add airflow over the M.2 or fit its heatsink.'];
    elseif ($nv !== null && $nv >= 62)  $tips[] = ['warn', 'NVMe/SSD is warm (' . round($nv) . '°C) — some front-intake airflow keeps sequential speeds up.'];
    $ram = $temps['ram'] ?? null;
    if ($ram !== null && $ram >= 60)    $tips[] = ['warn', 'RAM is at ' . round($ram) . '°C — for XMP/EXPO stability at high clocks, aim a case fan across the DIMMs.'];

    if (!$tips) $tips[] = ['good', 'These curves look well-balanced for your current temps. NEURU will flag anything that drifts hot.'];
    return $tips;
}

// EDIT: write a (validated) FanControl config JSON back to a file over SSH.
function nm_fp_write($ssh, string $filepath, string $rawJson): array {
    if (json_decode($rawJson, true) === null) return ['ok' => false, 'error' => 'refusing to write invalid JSON'];
    // base64 → send in CHUNKS to a temp file (a big config in one PS command exceeds the Windows cmd length
    // limit → 'write failed'), then decode + write the target in one final command.
    $b64 = base64_encode($rawJson);
    $tmp = 'C:\\Windows\\Temp\\_neuru_fp_' . substr(md5($filepath), 0, 8) . '.b64';
    $chunks = str_split($b64, 3500);
    foreach ($chunks as $i => $ch) {
        $verb = $i === 0 ? 'Set-Content' : 'Add-Content';
        $r = nm_win_ps($ssh, $verb . ' -LiteralPath ' . _nm_fp_q($tmp) . ' -Value \'' . $ch . '\' -NoNewline -Encoding ascii; \'K' . $i . '\'', 15);
        if (strpos(_nm_g_out($r), 'K' . $i) === false) return ['ok' => false, 'error' => 'write failed (chunk ' . $i . ')'];
    }
    $ps = '$b=[System.Convert]::FromBase64String((Get-Content -Raw -LiteralPath ' . _nm_fp_q($tmp) . ')); '
        . '[System.IO.File]::WriteAllBytes(' . _nm_fp_q($filepath) . ',$b); '
        . 'Remove-Item -LiteralPath ' . _nm_fp_q($tmp) . ' -Force -ErrorAction SilentlyContinue; \'WROK\'';
    $out = trim(_nm_g_out(nm_win_ps($ssh, $ps, 20)));
    return strpos($out, 'WROK') !== false ? ['ok' => true] : ['ok' => false, 'error' => 'write failed (decode)', 'raw' => mb_substr($out, 0, 160)];
}

// GENERIC EDIT: read → apply structured changes → write. $patch keys:
//   curvePoints: { curveName: [[temp,pct],...] }   (graph curves)
//   mix:         { curveName: { fn?:int, members?:[curveNames] } }
//   fans:        { fanName:  { curve?:name, manual?:bool, manualV?:int } }
function nm_fp_patch($ssh, string $filepath, array $patch): array {
    $raw = nm_fp_read_raw($ssh, $filepath); $j = json_decode($raw, true);
    if (!is_array($j) || !isset($j['FanControl'])) return ['ok' => false, 'error' => 'could not read config'];
    $changed = 0;
    if (isset($j['FanControl']['FanCurves']) && is_array($j['FanControl']['FanCurves'])) {
        foreach ($j['FanControl']['FanCurves'] as &$cv) {
            $nm = (string)($cv['Name'] ?? '');
            if (isset($patch['curvePoints'][$nm]) && isset($cv['Points'])) {
                $pts = $patch['curvePoints'][$nm];
                if (is_array($pts) && $pts) { usort($pts, fn($a,$b)=>$a[0]<=>$b[0]);
                    $cv['Points'] = array_map(fn($p) => round((float)$p[0],2) . ',' . round(max(0,min(100,(float)$p[1])),2), $pts); $changed++; }
            }
            if (isset($patch['mix'][$nm]) && isset($cv['SelectedFanCurves'])) {
                $m = $patch['mix'][$nm];
                if (isset($m['fn'])) { $cv['SelectedMixFunction'] = max(0, min(3, (int)$m['fn'])); $changed++; }
                if (isset($m['members']) && is_array($m['members'])) { $cv['SelectedFanCurves'] = array_map(fn($x) => ['Name' => (string)$x], array_values(array_filter($m['members'], fn($x)=>$x!==''))); $changed++; }
            }
        } unset($cv);
    }
    if (isset($j['FanControl']['Controls']) && is_array($j['FanControl']['Controls'])) {
        foreach ($j['FanControl']['Controls'] as &$ctl) {
            $nm = (string)($ctl['NickName'] ?? '');
            if (!isset($patch['fans'][$nm])) continue; $fp = $patch['fans'][$nm];
            if (array_key_exists('curve', $fp) && $fp['curve'] !== null && $fp['curve'] !== '') { $ctl['SelectedFanCurve'] = ['Name' => (string)$fp['curve']]; $changed++; }
            if (isset($fp['manual']))  { $ctl['ManualControl'] = (bool)$fp['manual']; $changed++; }
            if (isset($fp['manualV'])) { $ctl['ManualControlValue'] = max(0, min(100, (int)$fp['manualV'])); $changed++; }
        } unset($ctl);
    }
    if (!$changed) return ['ok' => false, 'error' => 'nothing to change'];
    $w = nm_fp_write($ssh, $filepath, json_encode($j, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    if (!empty($w['ok'])) $w['changed'] = $changed; return $w;
}

// SWITCH the active profile: copy the chosen config over configuration.json, then relaunch FanControl
// so it loads it. (~2s restart — the only way FanControl adopts a new config.)
function nm_fp_apply($ssh, string $filepath): array {
    $root = _nm_fp_q(nm_fp_root_config()); $exe = _nm_fp_q(nm_fp_exe());
    $ps = '$ErrorActionPreference=\'Stop\'; try { '
        . 'Copy-Item -LiteralPath ' . _nm_fp_q($filepath) . ' -Destination ' . $root . ' -Force; '
        . 'Get-Process FanControl -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep -Milliseconds 700; '
        . 'if(Test-Path ' . $exe . '){ Start-Process -FilePath ' . $exe . ' } ; \'APPOK\' } catch { \'APPERR:\'+$_.Exception.Message }';
    $out = trim(_nm_g_out(nm_win_ps($ssh, $ps, 30)));
    return strpos($out, 'APPOK') !== false
        ? ['ok' => true, 'note' => 'Applied — FanControl relaunched with this profile.']
        : ['ok' => false, 'error' => 'apply failed', 'raw' => mb_substr($out, 0, 200)];
}

} // function_exists guard
