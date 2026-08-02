<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — GAMING / Game Mode engine. Turns the agentless Windows/GPU monitoring
// into a gamer command center: live game detection, GPU/CPU/thermal vitals,
// Game Ping Radar (to game-server regions), a 1-Click reversible Game Booster.
// A "rig" = a monitored Windows host (nm_win_hosts). Reuses nm_winhost.php +
// nvidia-smi over the SAME SSH. Perm: 'gaming'. Plan: docs/GAMING_MODE_PLAN.md.
// ─────────────────────────────────────────────────────────────────────────────
if (is_file(__DIR__.'/nm_winhost.php')) require_once __DIR__.'/nm_winhost.php';
if (is_file(__DIR__.'/nm_confmgr.php')) require_once __DIR__.'/nm_confmgr.php';

if (!function_exists('nm_gaming_ensure')) {

// nm_cm_ssh_fetch returns output under 'config'; nm_win_ps rides it. Read whatever key carries the text.
function _nm_g_out($r): string { if (!is_array($r)) return ''; return (string)($r['config'] ?? $r['out'] ?? $r['data'] ?? $r['raw'] ?? $r['output'] ?? ''); }

function nm_gaming_ensure($conn): void {
    if (!($conn instanceof mysqli)) return;
    $t = [
    "CREATE TABLE IF NOT EXISTS nm_game_sessions (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        host_id INT NOT NULL, title VARCHAR(80) NULL, process VARCHAR(80) NULL,
        started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, ended_at TIMESTAMP NULL DEFAULT NULL,
        max_gpu_temp INT NULL, peak_vram_mb INT NULL, avg_fps FLOAT NULL, low1_fps FLOAT NULL, low01_fps FLOAT NULL,
        KEY k_host (host_id, started_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    "CREATE TABLE IF NOT EXISTS nm_game_boost_log (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        host_id INT NOT NULL, action ENUM('on','off') NOT NULL,
        prev_plan VARCHAR(80) NULL, stopped_services TEXT NULL, ok TINYINT(1) NOT NULL DEFAULT 1,
        detail TEXT NULL, created_by VARCHAR(60) NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY k_host (host_id, id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    ];
    $t[] = "CREATE TABLE IF NOT EXISTS nm_game_lag_log (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, rig_id INT NOT NULL, region VARCHAR(40) NULL, host VARCHAR(120) NULL,
        ms FLOAT NULL, jitter FLOAT NULL, loss INT NULL, sampled_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY k (rig_id, sampled_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
    foreach ($t as $sql) { try { $conn->query($sql); } catch (\Throwable $e) {} }
    try { $conn->query("INSERT IGNORE INTO role_profiles (role_name,button_key,enabled) VALUES ('admin','gaming',1)"); } catch (\Throwable $e) {}
}

// ── Game DB: process-name (lowercase, no .exe) → {title, endpoints[region=>host]} ──
// endpoints are pingable region hosts; latency/jitter/loss is measured FROM the gamer's PC.
function nm_gaming_titles(): array {
    return [
        'valorant'                        => ['title'=>'Valorant','pub'=>'Riot','ep'=>['NA'=>'na.gaming.riotgames.com','LATAM'=>'la1.lol.riotgames.com','EU'=>'euw.gaming.riotgames.com']],
        'valorant-win64-shipping'         => ['title'=>'Valorant','pub'=>'Riot','ep'=>['NA'=>'na.gaming.riotgames.com','LATAM'=>'la1.lol.riotgames.com','EU'=>'euw.gaming.riotgames.com']],
        'league of legends'               => ['title'=>'League of Legends','pub'=>'Riot','ep'=>['NA'=>'na.gaming.riotgames.com','LATAM'=>'la1.lol.riotgames.com','EU'=>'euw.gaming.riotgames.com']],
        'leagueclient'                    => ['title'=>'League of Legends','pub'=>'Riot','ep'=>['NA'=>'na.gaming.riotgames.com','LATAM'=>'la1.lol.riotgames.com','EU'=>'euw.gaming.riotgames.com']],
        'cs2'                             => ['title'=>'CS2','pub'=>'Valve','ep'=>['NA-East'=>'atl.valve.net','NA-West'=>'sea.valve.net','EU'=>'ams.valve.net']],
        'csgo'                            => ['title'=>'CS:GO','pub'=>'Valve','ep'=>['NA-East'=>'atl.valve.net','NA-West'=>'sea.valve.net','EU'=>'ams.valve.net']],
        'dota2'                           => ['title'=>'Dota 2','pub'=>'Valve','ep'=>['NA-East'=>'atl.valve.net','NA-West'=>'sea.valve.net','EU'=>'ams.valve.net']],
        'fortniteclient-win64-shipping'   => ['title'=>'Fortnite','pub'=>'Epic','ep'=>['NA-East'=>'ping-nae.ds.on.epicgames.com','NA-West'=>'ping-naw.ds.on.epicgames.com','EU'=>'ping-eu.ds.on.epicgames.com']],
        'modernwarfare'                   => ['title'=>'Call of Duty','pub'=>'Activision','ep'=>['NA'=>'cod.activision.com','EU'=>'eu.cod.activision.com']],
        'cod'                             => ['title'=>'Call of Duty','pub'=>'Activision','ep'=>['NA'=>'cod.activision.com','EU'=>'eu.cod.activision.com']],
        'r5apex'                          => ['title'=>'Apex Legends','pub'=>'EA','ep'=>['NA-East'=>'gsm-sjc.ea.com','EU'=>'gsm-fra.ea.com']],
        'overwatch'                       => ['title'=>'Overwatch 2','pub'=>'Blizzard','ep'=>['NA'=>'us.actual.battle.net','EU'=>'eu.actual.battle.net']],
        'rustclient'                      => ['title'=>'Rust','pub'=>'Facepunch','ep'=>['NA'=>'8.8.8.8','EU'=>'1.1.1.1']],
        'gta5'                            => ['title'=>'GTA V','pub'=>'Rockstar','ep'=>['NA'=>'8.8.8.8','EU'=>'1.1.1.1']],
        'minecraft'                       => ['title'=>'Minecraft','pub'=>'Mojang','ep'=>['NA'=>'8.8.8.8','EU'=>'1.1.1.1']],
    ];
}

// ── user-defined game → server-region endpoints (dynamic; overrides/extends the built-in titles) ──
function nm_gaming_custom_endpoints($conn): array { $j=json_decode(nm_gaming_get($conn,'game_server_map','{}'),true); return is_array($j)?$j:[]; }
function nm_gaming_endpoints_set($conn, string $game, array $regions): void {
    $m=nm_gaming_custom_endpoints($conn); $k=strtolower(trim($game)); if ($k==='') return;
    $clean=[]; foreach ($regions as $reg=>$host){ $reg=trim(mb_substr((string)$reg,0,24)); $host=preg_replace('/[^a-zA-Z0-9_.\-]/','',(string)$host); if ($reg!=='' && $host!=='') $clean[$reg]=$host; }
    if (!$clean) unset($m[$k]); else $m[$k]=$clean;
    try { $st=$conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES ('game_server_map',?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)"); $v=json_encode($m); $st->bind_param('s',$v); $st->execute(); $st->close(); } catch (\Throwable $e){}
}
// resolve the ping-radar endpoints for a game: the user's custom map (by title) → the built-in title ep → none.
function nm_gaming_endpoints_for($conn, string $title, array $builtin=[]): array {
    $m=nm_gaming_custom_endpoints($conn); $k=strtolower(trim($title));
    if ($k!=='' && !empty($m[$k]) && is_array($m[$k])) return $m[$k];
    return $builtin;
}

// pretty-print a process/folder name for the HUD
function _nm_g_pretty(string $s): string { $s=trim(preg_replace('/\.(exe)$/i','',$s)); $s=str_replace(['_','-'],' ',$s); return trim(preg_replace('/\s+/',' ',$s)); }

// Detect the running game on a rig. Strategy: (1) known-title match by process name (gives ping-radar server
// endpoints); (2) GENERIC — ANY process whose EXE path lives inside a game-store folder (steamapps\common,
// XboxGames, Epic/EA/Ubisoft/GOG…) with a window → that's the running game (works for any installed game).
function nm_gaming_detect($ssh, array $extra=[]): ?array {
    // Win32_Process (CIM) exposes ExecutablePath for EVERY process across user sessions when the SSH user is
    // admin — far more reliable than Get-Process.Path (per-process access-denied + can't see other sessions).
    // NOTE: do NOT filter on ExecutablePath — protected/elevated games (Xbox app, anti-cheat) return an EMPTY
    // path even to admin, and filtering them out made the detector lock onto the biggest *pathed* app (an AV
    // service!). We keep every process >100MB; the exe path is used opportunistically (markers) but the game is
    // ultimately found by NAME + size, which is always visible.
    $ps = '$out=@(); Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.WorkingSetSize -gt 104857600 } | ForEach-Object { $out += @{ n=[string]$_.Name; id=[int]$_.ProcessId; ws=[math]::Round([double]$_.WorkingSetSize/1MB,0); path=[string]$_.ExecutablePath; sess=[int]$_.SessionId } }; ($out | ConvertTo-Json -Compress)';
    $r = nm_win_ps($ssh, $ps, 22); $out = _nm_g_out($r);
    if (!is_string($out) || $out === '') return null;
    $procs = json_decode(trim($out), true); if (!is_array($procs)) return null;
    if (isset($procs['n'])) $procs = [$procs];
    $titles = nm_gaming_titles();
    // 1) known title by process name (strip .exe) → has server endpoints for the Ping Radar
    foreach ($procs as $p) { $n = strtolower(preg_replace('/\.exe$/i','',(string)($p['n'] ?? ''))); if ($n !== '' && isset($titles[$n])) { $t=$titles[$n]; return ['process'=>$n,'title'=>$t['title'],'pub'=>$t['pub'],'pid'=>(int)($p['id']??0),'ram_mb'=>(int)($p['ws']??0),'ep'=>$t['ep']]; } }
    // 2) generic: a process whose EXE path is inside a game-store folder — built-in markers PLUS the user's OWN
    // configured game folders (dynamic — every user stores games wherever they want).
    $markers = ['steamapps\\common','xboxgames','epic games','ea games','ea desktop\\installed','origin games','ubisoft','gog games','riot games','battle.net','\\games\\'];
    foreach ($extra as $ef){ $ef=strtolower(trim((string)$ef)); if($ef!=='') $markers[]=$ef; }
    $best = null;
    foreach ($procs as $p) {
        $path = (string)($p['path'] ?? ''); if ($path === '') continue; $pl = strtolower($path); $ws = (int)($p['ws'] ?? 0);
        foreach ($markers as $m) {
            if (strpos($pl, $m) !== false) {
                if ($ws > 200) {   // >200MB floor cuts launchers/anti-cheat; biggest-RAM candidate = the game
                    $title = _nm_g_pretty(preg_replace('/\.exe$/i','',(string)($p['n'] ?? '')));
                    $pos = strpos($pl, $m); if ($pos!==false){ $after=ltrim(substr($path, $pos+strlen($m)), '\\/'); $seg=explode('\\', $after)[0]; if ($seg!=='' && strtolower($seg)!=='common') $title=_nm_g_pretty($seg); }
                    if (!$best || $ws > $best['ram_mb']) $best = ['process'=>strtolower(preg_replace('/\.exe$/i','',(string)($p['n']??''))),'title'=>$title,'pub'=>'Game','pid'=>(int)($p['id']??0),'ram_mb'=>$ws,'ep'=>[],'path'=>$path];
                }
                break;
            }
        }
    }
    if ($best) return $best;

    // 3) LAUNCHER-AGNOSTIC fallback. Games started via Battle.net (CoD/Activision), Ubisoft Connect, EA app or
    // the Xbox app install to arbitrary folders that carry NO store marker (e.g. CoD → C:\Program Files\Call of
    // Duty) — so marker-matching misses them entirely. Heuristic: the biggest NON-system / non-browser /
    // non-launcher / non-background process is almost certainly the running game. Works with OR without
    // ExecutablePath (name-based exclusion still applies when SSH can't read other sessions' paths).
    $cand = null;
    foreach ($procs as $p) {
        $name = (string)($p['n'] ?? ''); if ($name === '') continue;
        $ws = (int)($p['ws'] ?? 0); if ($ws < 400) continue;   // a real game holds lots of RAM; cuts helpers/agents
        // UNIVERSAL: a game runs in the INTERACTIVE desktop session (SessionId >= 1). Windows SERVICES + VM/host
        // processes (vmmem, security suites, container/db daemons) run in SESSION 0 → never the running game.
        if (array_key_exists('sess',$p) && (int)$p['sess'] === 0) continue;
        $path = (string)($p['path'] ?? '');
        if (nm_gaming_is_noise($name, $path)) continue;
        if (!$cand || $ws > $cand['ram_mb']) {
            $proc  = strtolower(preg_replace('/\.exe$/i','',$name));
            $t     = $titles[$proc] ?? null;   // label it nicely if we happen to know it
            $title = $t ? $t['title'] : nm_gaming_title_from_path($path, $name);
            $cand  = ['process'=>$proc,'title'=>$title,'pub'=>$t['pub']??'Game','pid'=>(int)($p['id']??0),'ram_mb'=>$ws,'ep'=>$t['ep']??[],'path'=>$path,'guess'=>true];
        }
    }
    return $cand;
}

// Background/system/launcher/browser processes that are NOT the game (so the "biggest process = game" fallback
// doesn't lock onto Chrome or the Battle.net launcher). Name-based (works even when the exe path is hidden) +
// a few system path markers. Deliberately NOT user-facing config — this is universal Windows noise.
// Substrings that identify a NON-game app even when the exact process name varies (packaged/UWP apps run with
// odd names like "whatsapp.root", "mscopilot"; service variants). UNIVERSAL — deliberately specific enough to
// never match a real game exe. Shared by live detection (nm_gaming_is_noise) + the DNA history filter.
function nm_gaming_noise_tokens(): array {
    return ['vmmem','vmware','virtualbox','vboxheadless','vboxsvc','dockerd','com.docker','wslservice','vmcompute','vmwp',
        'bitdefender','bdservicehost','bdagent','kaspersky','mcafee','malwarebytes','sentinelagent','crowdstrike','csfalcon','carbonblack','msmpeng','nissrv',
        'remotedesktopmanager','anydesk','teamviewer','rustdesk','splashtop','parsecd',
        'whatsapp','msedgewebview','onedrive','phonelink','yourphone','gamingservices','mscopilot','ms-copilot',
        'steamwebhelper','epicgameslauncher','ubisoftconnect','eadesktop','galaxyclient','riotclientservices'];
}
function nm_gaming_is_noise(string $name, string $path=''): bool {
    static $NOISE = [
        'system','registry','idle','memcompression','memory compression','svchost','csrss','wininit','winlogon','services','lsass','smss',
        'fontdrvhost','dwm','explorer','sihost','taskhostw','runtimebroker','dllhost','conhost','ctfmon','audiodg',
        'searchindexer','searchapp','searchhost','startmenuexperiencehost','shellexperiencehost','applicationframehost',
        'textinputhost','wmiprvse','wmiapsrv','powershell','pwsh','cmd','spoolsv','msmpeng','nissrv','securityhealthservice',
        'securityhealthsystray','lockapp','useroobebroker','systemsettings','widgets','widgetservice','phoneexperiencehost',
        'crossdeviceservice','wsappx','trustedinstaller','backgroundtaskhost','gamebar','gamebarft','gamebarpresencewriter',
        // browsers / chat / media / dev — can be large but aren't games
        'chrome','msedge','msedgewebview2','firefox','opera','opera_gx','brave','vivaldi','iexplore','whatsapp','telegram',
        'discord','slack','teams','ms-teams','spotify','zoom','skype','obs64','obs','streamlabs','xsplit','code','devenv',
        'photoshop','onedrive','dropbox','googledrivefs','acrobat','acrord32','outlook','excel','winword','powerpnt','notion',
        // the LAUNCHERS themselves (we want the game they SPAWN, not the launcher)
        'steam','steamwebhelper','steamservice','epicgameslauncher','epicwebhelper','unrealcefsubprocess','battle.net',
        'agent','blizzarderror','upc','ubisoftconnect','uplaywebcore','ubisoftgamelauncher','eadesktop','easteamproxy',
        'link2ea','origin','originwebhelperservice','galaxyclient','galaxyclientservice','riotclientservices','riotclientux',
        'rockstarservice','rockstarerrorhandler','socialclubhelper','gameoverlayui','nvcontainer','nvsphelper64','nvdisplay',
        'rtkauduservice64','armsvc','jusched','msiafterburner','rtss','razer','synapse','icue','qmlrenderer','cuelfdiscoveryservice',
        'logi','logioptionsplus_agent','armourycrate','armourycrateservice','asusservice','asussoftwaremanager','gameservice',
        // antivirus / security suites (huge resident services that aren't games)
        'msmpeng','nissrv','bdservicehost','bdagent','bdntwrk','bdredline','vsserv','vsservppl','updatesrv','avp','avpui',
        'avgui','avguard','avastui','aswidsagent','afwserv','mcshield','masvc','mfemms','nortonsecurity','ns','sense',
        'windefend','securityhealthhost','mpdefendercoreservice','ekrn','egui','wrsa','malwarebytes','mbamservice',
        // electron / productivity apps that can be large but are never the game
        'claude','notion','obsidian','postman','figma','signal','wechat','evernote','1password','bitwarden','keepass',
        // VMs / containers / WSL / hypervisors (vmmem can hold GBs of RAM but is NEVER a game)
        'vmmem','vmmemwsl','vmwp','vmcompute','vmms','vmwareservice','vmware-vmx','vmware','vmnat','vmnetdhcp',
        'virtualbox','virtualboxvm','vboxheadless','vboxsvc','docker','dockerd','com.docker.service','com.docker.backend',
        'wsl','wslservice','wslhost','hyperv','qemu-system-x86_64',
        // databases / dev servers / runtimes that hog RAM but aren't games (NOTE: javaw/java kept — Minecraft)
        'mysqld','mysql','mariadbd','postgres','pg_ctl','mongod','redis-server','sqlservr','sqlwriter','oracle',
        'node','nodejs','nginx','httpd','apache','php','php-cgi','python','python3','ruby','dotnet','gradle','w3wp',
        // remote-desktop / remote-access tools
        'remotedesktopmanager','rdm','mstsc','rdpclip','rustdesk','splashtop','srmanager','dwservice','ammyy','supremo',
        'todesk','anydesk','teamviewer','parsecd','parsec','sunshine','logioptions',
        // more antivirus / EDR / security agents
        'bdservicehost','bdagent','productagentservice','sentinelagent','sentinelui','cybereason','csfalconservice',
        'csagent','elastic-endpoint','cb','carbonblack','tanium','crowdstrike','huntress','threatlockerservice',
    ];
    $n = strtolower(preg_replace('/\.exe$/i','',$name));
    if ($n !== '' && in_array($n, $NOISE, true)) return true;
    // substring match for packaged/UWP apps whose process name varies (whatsapp.root, mscopilot, bdservicehost…)
    if ($n !== '') foreach (nm_gaming_noise_tokens() as $tk) if (strpos($n, $tk) !== false) return true;
    if ($path !== '') { $pl = strtolower(str_replace('/','\\',$path));
        foreach (['\\windows\\','\\windows defender','\\microsoft\\edge','\\common files\\microsoft','\\windowsapps\\microsoft.','\\system32\\','\\syswow64\\'] as $sd) if (strpos($pl,$sd)!==false) return true;
    }
    return false;
}

// Derive a readable game name from an exe path by walking UP past generic build folders
// (bin/win64/retail/content…) to the first meaningful folder — else the prettified exe name.
function nm_gaming_title_from_path(string $path, string $fallbackExe=''): string {
    $path  = str_replace('/','\\',$path);
    $parts = array_values(array_filter(explode('\\', $path), fn($s)=>trim($s)!==''));
    if ($parts) array_pop($parts);   // drop the exe
    static $generic = ['bin','binaries','binaries64','win64','win32','x64','x86','retail','_retail_','shipping','content',
        'game','games','build','builds','release','current','data','app','application','client','engine','redist',
        'program files','program files (x86)','steamapps','common','xboxgames','ea games','ea desktop','installed'];
    for ($i = count($parts) - 1; $i >= 0; $i--) {
        $seg = trim($parts[$i]); if ($seg === '') continue;
        $low = strtolower($seg);
        if (preg_match('/^[a-z]:$/', $low)) break;
        if (in_array($low, $generic, true) || strlen($seg) <= 1) continue;
        return _nm_g_pretty($seg);
    }
    $fx = preg_replace('/\.exe$/i','', $fallbackExe);
    $fx = preg_replace('/\s*[-_]?\s*\b(retail|shipping|final|release|win64|win32|x64|x86|64bit|64-bit|steam|epic|standalone)\b.*$/i','',$fx);
    return _nm_g_pretty(trim($fx) !== '' ? trim($fx) : preg_replace('/\.exe$/i','', $fallbackExe));
}

// Diagnostic — returns what the detector SEES so the user can tell why a game did/didn't match.
// { detected: <detect result|null>, procs_seen: N, paths_visible: bool, top: [ {name,ram_mb,path,noise} x15 ] }.
function nm_gaming_detect_debug($ssh, array $extra=[]): array {
    $ps = '$out=@(); Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.WorkingSetSize -gt 104857600 } | ForEach-Object { $out += @{ n=[string]$_.Name; id=[int]$_.ProcessId; ws=[math]::Round([double]$_.WorkingSetSize/1MB,0); path=[string]$_.ExecutablePath; sess=[int]$_.SessionId } }; ($out | ConvertTo-Json -Compress)';
    $r = nm_win_ps($ssh, $ps, 22); $out = _nm_g_out($r);
    $procs = json_decode(trim((string)$out), true);
    if (!is_array($procs)) return ['detected'=>null,'procs_seen'=>0,'paths_visible'=>false,'top'=>[],'raw_empty'=>($out===''||$out===null)];
    if (isset($procs['n'])) $procs = [$procs];
    usort($procs, fn($a,$b)=>(int)($b['ws']??0)-(int)($a['ws']??0));
    $withPath = 0; $top = [];
    foreach ($procs as $p) {
        $name=(string)($p['n']??''); $path=(string)($p['path']??''); $ws=(int)($p['ws']??0);
        if ($path!=='') $withPath++;
        if (count($top) < 15) $top[] = ['name'=>$name,'ram_mb'=>$ws,'path'=>$path,'noise'=>nm_gaming_is_noise($name,$path)];
    }
    return ['detected'=>nm_gaming_detect($ssh,$extra),'procs_seen'=>count($procs),'paths_visible'=>($withPath>0),'top'=>$top];
}

// GPU vitals via nvidia-smi over the same SSH (util/VRAM/temp/fan/power + thermal-throttle decode).
function nm_gaming_gpu($ssh): array {
    $q = 'nvidia-smi --query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,fan.speed,power.draw,clocks_throttle_reasons.active --format=csv,noheader,nounits';
    $r = function_exists('nm_cm_ssh_fetch') ? nm_cm_ssh_fetch($ssh, $q, 15) : ['out'=>''];
    $out = trim(_nm_g_out($r));
    if ($out === '' || stripos($out,'not found')!==false || stripos($out,'is not recognized')!==false) return nm_gaming_gpu_any($ssh);
    $line = strtok($out, "\n"); $c = array_map('trim', explode(',', $line));
    if (count($c) < 8) return ['ok'=>false,'error'=>'unparsed'];
    $thr = strtolower($c[7]); $thrHex = hexdec(ltrim($thr,'0x') ?: '0');
    $thermal = ($thrHex & 0x8) || ($thrHex & 0x80) || ($thrHex & 0x40);   // HW slowdown / HW+SW thermal
    $powerCap = ($thrHex & 0x4);
    return ['ok'=>true,'name'=>$c[0],'util'=>(float)$c[1],'vram_used'=>(int)$c[2],'vram_total'=>(int)$c[3],
        'temp'=>(int)$c[4],'fan'=>is_numeric($c[5])?(int)$c[5]:null,'power'=>(float)$c[6],
        'throttle'=>['thermal'=>(bool)$thermal,'power'=>(bool)$powerCap,'raw'=>$c[7]]];
}

// Fallback GPU vitals for ANY vendor (Intel/AMD, or NVIDIA without nvidia-smi) via Win32 + Windows GPU
// performance counters — so the Thermal & GPU Reactor still shows the card. GPU temperature for non-NVIDIA
// comes from the LHM sensor panel (nm_gaming_sensors), which already reads Radeon/Intel temps.
function nm_gaming_gpu_any($ssh): array {
    if (!function_exists('nm_win_ps') && is_file(__DIR__ . '/nm_winhost.php')) require_once __DIR__ . '/nm_winhost.php';
    if (!function_exists('nm_win_ps')) return ['ok'=>false,'error'=>'no NVIDIA GPU / nvidia-smi'];
    $ps = '$ErrorActionPreference=\'SilentlyContinue\'; $o=@{}; '
        . '$g=Get-CimInstance Win32_VideoController | Sort-Object AdapterRAM -Descending | Select-Object -First 1; $o.name=[string]$g.Name; '
        . '$vram=0; $gk=\'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\'; '
        . 'Get-ChildItem $gk -ErrorAction SilentlyContinue | ForEach-Object { $q=(Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).\'HardwareInformation.qwMemorySize\'; if($q -and $q -gt $vram){$vram=$q} }; '
        . '$o.vram_total=[int]$(if($vram){[math]::Round($vram/1MB)}else{[math]::Round([double]$g.AdapterRAM/1MB)}); '
        . '$u=(Get-Counter \'\GPU Engine(*engtype_3D)\Utilization Percentage\' -ErrorAction SilentlyContinue).CounterSamples | Measure-Object CookedValue -Sum; $o.util=[math]::Round([double]$u.Sum,0); '
        . '$m=(Get-Counter \'\GPU Adapter Memory(*)\Dedicated Usage\' -ErrorAction SilentlyContinue).CounterSamples | Measure-Object CookedValue -Sum; $o.vram_used=[int]([math]::Round([double]$m.Sum/1MB)); '
        . '$o | ConvertTo-Json -Compress';
    $r = nm_win_ps($ssh, $ps, 20);
    $out = trim(_nm_g_out($r));
    $s = strpos($out,'{'); if ($s!==false && $s>0) $out = substr($out,$s);
    $j = json_decode($out, true);
    if (!is_array($j) || empty($j['name'])) return ['ok'=>false,'error'=>'no GPU detected'];
    $vend = 'GPU'; $ln=strtolower($j['name']);
    if (strpos($ln,'intel')!==false||strpos($ln,'iris')!==false) $vend='Intel';
    elseif (strpos($ln,'radeon')!==false||strpos($ln,'amd')!==false) $vend='AMD';
    elseif (strpos($ln,'nvidia')!==false||strpos($ln,'geforce')!==false) $vend='NVIDIA';
    return ['ok'=>true,'name'=>$j['name'],'util'=>(float)($j['util']??0),'vram_used'=>(int)($j['vram_used']??0),
        'vram_total'=>(int)($j['vram_total']??0),'temp'=>null,'fan'=>null,'power'=>0,'vendor'=>$vend,   // temp=null → reactor uses the LHM sensor temp (real, all vendors) instead of showing 0°
        'throttle'=>['thermal'=>false,'power'=>false,'raw'=>''],'fallback'=>true];
}

// ── custom fan labels per rig (so the user can name CPU / GPU / Case fans) ──
function nm_gaming_fan_names($conn, int $rid): array { $j=json_decode(nm_gaming_get($conn,'game_fan_names_'.$rid,'{}'),true); return is_array($j)?$j:[]; }
function nm_gaming_fan_name_set($conn, int $rid, string $orig, string $label): void {
    $m=nm_gaming_fan_names($conn,$rid); $orig=trim($orig); $label=trim(mb_substr($label,0,40));
    if ($orig==='') return; if ($label==='') unset($m[$orig]); else $m[$orig]=$label;
    try { $st=$conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES (?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)"); $k='game_fan_names_'.$rid; $v=json_encode($m); $st->bind_param('ss',$k,$v); $st->execute(); $st->close(); } catch (\Throwable $e){}
}

// ── LHM/OHM "Remote Web Server" (data.json) reader — recursively walks the sensor tree ──
function _nm_g_walk($node, string $hw, array &$acc, int $depth): void {
    if (!is_array($node)) return;
    $text = (string)($node['Text'] ?? '');
    if ($depth === 1 && $text !== '') $hw = $text;   // depth 1 = a hardware node (CPU / GPU / Mainboard)
    $type = (string)($node['Type'] ?? '');
    $val  = (string)($node['Value'] ?? '');
    if ($type !== '' && $val !== '' && preg_match('/-?\d+(?:\.\d+)?/', $val, $m)) {
        $map = ['Temperature'=>'temps','Fan'=>'fans','Control'=>'controls','Load'=>'loads','Clock'=>'clocks','Power'=>'powers','Voltage'=>'voltages','Data'=>'data','SmallData'=>'data'];
        if (isset($map[$type])) $acc[$map[$type]][] = ['name'=>$text,'hw'=>$hw,'id'=>(string)($node['SensorId'] ?? ''),'type'=>$type,'val'=>(float)$m[0]];
    }
    foreach (($node['Children'] ?? []) as $ch) _nm_g_walk($ch, $hw, $acc, $depth + 1);
}
function nm_gaming_sensors_web($ssh, int $port=8085): ?array {
    $script = 'try{ (Invoke-WebRequest -UseBasicParsing -TimeoutSec 6 -Uri http://localhost:'.$port.'/data.json).Content }catch{ \'ERR\' }';
    $r = nm_win_ps($ssh, $script, 15); $out = trim(_nm_g_out($r));
    if ($out === '' || strpos($out,'ERR')===0) return null;
    $d = json_decode($out, true); if (!is_array($d)) return null;
    $acc = ['fans'=>[],'temps'=>[],'controls'=>[],'loads'=>[],'clocks'=>[],'powers'=>[],'voltages'=>[],'data'=>[]];
    _nm_g_walk($d, '', $acc, 0);
    if (!$acc['fans'] && !$acc['temps'] && !$acc['clocks']) return null;
    $hasCpuMobo=false; foreach ($acc['temps'] as $t){ $hw=strtolower($t['hw'].' '.$t['name']); if (strpos($hw,'gpu')===false && strpos($hw,'nvidia')===false && strpos($hw,'radeon')===false){ $hasCpuMobo=true; break; } }
    return ['ok'=>true,'src'=>'Remote Web Server','gpu_only'=>!$hasCpuMobo] + $acc;
}

// ── ALL fans + temps + sensors: try the WMI namespace first, then the LHM/OHM Remote Web Server (data.json) ──
function nm_gaming_sensors($ssh): array {
    $ps = '$out=@{fans=@();temps=@();controls=@();loads=@();clocks=@();powers=@();voltages=@();data=@();src=$null}; '
        . 'foreach($ns in @(\'root/LibreHardwareMonitor\',\'root/OpenHardwareMonitor\')){ try{ $sens=@(Get-CimInstance -Namespace $ns -ClassName Sensor -ErrorAction Stop); if($sens.Count -eq 0){continue}; $out.src=($ns -replace \'root/\',\'\'); '
        . '$hw=@{}; $ht=@{}; try{ Get-CimInstance -Namespace $ns -ClassName Hardware -ErrorAction Stop | ForEach-Object { $hw[[string]$_.Identifier]=[string]$_.Name; $ht[[string]$_.Identifier]=[string]$_.HardwareType } }catch{}; '
        . 'foreach($x in $sens){ $t=[string]$x.SensorType; if(-not $t){continue}; $pid=[string]$x.Parent; $hn=[string]$hw[$pid]; $row=@{name=[string]$x.Name;hw=$hn;type=[string]$ht[$pid];id=[string]$x.Identifier;val=[math]::Round([double]$x.Value,1)}; '
        . 'switch($t){ \'Fan\'{$out.fans+=$row}; \'Temperature\'{$out.temps+=$row}; \'Control\'{$out.controls+=$row}; \'Load\'{$out.loads+=$row}; \'Clock\'{$out.clocks+=$row}; \'Power\'{$out.powers+=$row}; \'Voltage\'{$out.voltages+=$row}; \'Data\'{$out.data+=$row}; \'SmallData\'{$out.data+=$row} } }; break }catch{} } '
        . '($out | ConvertTo-Json -Compress -Depth 4)';
    $r = nm_win_ps($ssh, $ps, 25); $out = trim(_nm_g_out($r));
    $d = json_decode($out, true);
    if (!is_array($d) || empty($d['src'])) {
        // no WMI namespace → try the LHM/OHM "Remote Web Server" (data.json) on the common ports
        foreach ([8085,8086,8080] as $port) { $web = nm_gaming_sensors_web($ssh,$port); if ($web) return $web; }
        return ['ok'=>false,'need_helper'=>true];
    }
    foreach (['fans','temps','controls','loads','clocks','powers','voltages','data'] as $k){ if (isset($d[$k]['name'])) $d[$k]=[$d[$k]]; if (!isset($d[$k])||!is_array($d[$k])) $d[$k]=[]; }
    // was only the GPU exposed? (old OpenHardwareMonitor on modern HW, or OHM not run as admin) → advise LibreHardwareMonitor
    $hasCpuMobo = false;
    foreach ($d['temps'] as $t){ $hw=strtolower((string)($t['hw']??'').' '.(string)($t['name']??'')); if (strpos($hw,'gpu')===false && strpos($hw,'nvidia')===false && strpos($hw,'radeon')===false){ $hasCpuMobo=true; break; } }
    $gpuOnly = ($d['src']==='OpenHardwareMonitor' && !$hasCpuMobo);
    return ['ok'=>true,'src'=>$d['src'],'gpu_only'=>$gpuOnly,'fans'=>$d['fans'],'temps'=>$d['temps'],'controls'=>$d['controls'],'loads'=>$d['loads'],'clocks'=>$d['clocks'],'powers'=>$d['powers'],'voltages'=>$d['voltages'],'data'=>$d['data']];
}

// ── ALL disks with full metrics (logical drives + physical disk type/health) ──
function nm_gaming_disks($ssh): array {
    $ps = '$d=@(Get-CimInstance Win32_LogicalDisk -Filter \'DriveType=3\' | ForEach-Object { $u=$_.Size-$_.FreeSpace; @{id=[string]$_.DeviceID;label=[string]$_.VolumeName;fs=[string]$_.FileSystem;size=[long]$_.Size;free=[long]$_.FreeSpace;used=[long]$u;pct=$(if($_.Size){[math]::Round($u/$_.Size*100)}else{0})} }); '
        . '$p=@(); try{ $p=@(Get-PhysicalDisk | ForEach-Object { @{name=[string]$_.FriendlyName;type=[string]$_.MediaType;bus=[string]$_.BusType;size=[long]$_.Size;health=[string]$_.HealthStatus} }) }catch{}; '
        . '(@{logical=$d;physical=$p} | ConvertTo-Json -Compress -Depth 4)';
    $r = nm_win_ps($ssh,$ps,20); $j=json_decode(trim(_nm_g_out($r)),true);
    if (!is_array($j)) return ['ok'=>false,'error'=>'no disk data'];
    foreach (['logical','physical'] as $k){ if (isset($j[$k]['id'])||isset($j[$k]['name'])) $j[$k]=[$j[$k]]; if(!isset($j[$k])||!is_array($j[$k])) $j[$k]=[]; }
    return ['ok'=>true,'logical'=>$j['logical'],'physical'=>$j['physical']];
}

// ── Launch a game on the rig. GUI apps started from an SSH (session 0) context won't show on the user's
// monitor, so we register a ONE-SHOT scheduled task with Interactive logon that runs in the logged-on user's
// session (the documented reliable way), fire it, then delete it. Finds the main .exe in the game folder. ──
function nm_gaming_launch($ssh, string $folder): array {
    $folder = trim($folder); if ($folder==='' || !preg_match('/^[A-Za-z]:\\\\/', $folder)) return ['ok'=>false,'error'=>'invalid folder'];
    $f = str_replace('\'','',$folder);   // strip quotes (goes into a single-quoted PS literal)
    $ps = '$dir=\''.$f.'\'; if(-not (Test-Path -LiteralPath $dir)){ \'NODIR\'; return }; '
        . '$exe=Get-ChildItem -LiteralPath $dir -Recurse -Depth 3 -Filter *.exe -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch \'unins|crash|redist|vcredist|setup|helper|report|service|dxsetup|prereq|eac|battleye\' } | Sort-Object Length -Descending | Select-Object -First 1; '
        . 'if(-not $exe){ \'NOEXE\'; return }; '
        . 'try{ $u=(Get-CimInstance Win32_ComputerSystem).UserName; if(-not $u){ \'NOUSER\'; return }; '
        . '$act=New-ScheduledTaskAction -Execute $exe.FullName -WorkingDirectory $exe.DirectoryName; '
        . '$pr=New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest; '
        . 'Register-ScheduledTask -TaskName \'NEURU_Launch\' -Action $act -Principal $pr -Force | Out-Null; '
        . 'Start-ScheduledTask -TaskName \'NEURU_Launch\'; Start-Sleep -Milliseconds 1500; Unregister-ScheduledTask -TaskName \'NEURU_Launch\' -Confirm:$false; '
        . '(\'OK:\'+$exe.Name) }catch{ (\'ERR:\'+$_.Exception.Message) }';
    $r = nm_win_ps($ssh, $ps, 40); $out = trim(_nm_g_out($r));
    if (strpos($out,'OK:')===0) return ['ok'=>true,'exe'=>substr($out,3)];
    if (strpos($out,'NODIR')===0) return ['ok'=>false,'error'=>'game folder not found on the rig'];
    if (strpos($out,'NOEXE')===0) return ['ok'=>false,'error'=>'no launchable .exe found in that folder'];
    if (strpos($out,'NOUSER')===0) return ['ok'=>false,'error'=>'nobody is logged in on the rig — a game can only launch onto an active desktop'];
    return ['ok'=>false,'error'=>($out!==''?substr($out,0,120):'launch failed')];
}

// ── GAME LIBRARY scan: store folders across ALL drives + custom folders, enriched by the registry ──
function nm_gaming_get_folders($conn): array {
    $raw = nm_gaming_get($conn,'game_folders',''); $out=[];
    // strict whole-string path validation — the value flows into a PowerShell literal, so reject anything that
    // could break the shell wrapper (", ;, $, backtick, %…). Only drive + safe path chars allowed.
    foreach (preg_split('/[\r\n,;]+/',$raw) as $f){ $f=trim($f); if($f!=='' && strlen($f)<160 && preg_match('/^[A-Za-z]:\\\\[A-Za-z0-9 _.\\\\()\-]*$/',$f)) $out[]=$f; }
    return $out;
}
function nm_gaming_games($conn, $ssh): array {
    $extra = nm_gaming_get_folders($conn);
    $extraLit = ''; foreach($extra as $f){ $extraLit .= ($extraLit===''?'':',').'\''.str_replace('\'','',$f).'\''; }
    if ($extraLit==='') $extraLit = '\'\'';
    $ps = '$g=@{}; $drives=@((Get-CimInstance Win32_LogicalDisk -Filter \'DriveType=3\').DeviceID); '
        . '$rel=@(\'\SteamLibrary\steamapps\common\',\'\Program Files (x86)\Steam\steamapps\common\',\'\Steam\steamapps\common\',\'\XboxGames\',\'\Program Files\Epic Games\',\'\Epic Games\',\'\Program Files\EA Games\',\'\Program Files (x86)\EA Games\',\'\EA Games\',\'\Origin Games\',\'\Program Files\Ubisoft\Ubisoft Game Launcher\games\',\'\Ubisoft\games\',\'\GOG Games\'); '
        . '$extra=@('.$extraLit.'); $roots=@(); foreach($dv in $drives){ foreach($r in $rel){ $roots+=($dv+$r) } }; foreach($e in $extra){ if($e){$roots+=$e} }; '
        . 'foreach($rt in $roots){ if(Test-Path -LiteralPath $rt){ $store=\'Folder\'; if($rt -match \'steamapps\'){$store=\'Steam\'}elseif($rt -match \'XboxGames\'){$store=\'Xbox\'}elseif($rt -match \'Epic\'){$store=\'Epic\'}elseif($rt -match \'EA|Origin\'){$store=\'EA\'}elseif($rt -match \'Ubisoft\'){$store=\'Ubisoft\'}elseif($rt -match \'GOG\'){$store=\'GOG\'}; '
        . 'Get-ChildItem -LiteralPath $rt -Directory -ErrorAction SilentlyContinue | ForEach-Object { $nm=$_.Name; if($nm -and -not $g.ContainsKey($nm)){ $dl=$_.FullName.Substring(0,2); $g[$nm]=@{name=$nm;store=$store;drive=$dl;mb=0;path=$_.FullName} } } } } '
        . '$pubs=\'Valve|Rockstar|Ubisoft|Electronic Arts|Activision|Riot|Epic|Bethesda|Blizzard|CD PROJEKT|Square Enix|Capcom|SEGA|Bandai|2K|Paradox|Xbox|Mojang\'; '
        . 'foreach($rk in @(\'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*\',\'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*\')){ Get-ItemProperty $rk -ErrorAction SilentlyContinue | ForEach-Object { $nm=[string]$_.DisplayName; if(-not $nm){return}; $mb=0; if($_.EstimatedSize){$mb=[math]::Round([double]$_.EstimatedSize/1024)}; if($g.ContainsKey($nm)){ if($g[$nm].mb -eq 0){$g[$nm].mb=$mb} } elseif($_.Publisher -match $pubs -or ([string]$_.InstallLocation) -match \'steamapps|XboxGames|Epic Games|EA Games|Ubisoft|GOG Games\'){ $dl=\'\'; $il=\'\'; if($_.InstallLocation){ $il=[string]$_.InstallLocation; if($il.Length -ge 2){$dl=$il.Substring(0,2)} }; $g[$nm]=@{name=$nm;store=[string]$_.Publisher;drive=$dl;mb=$mb;path=$il} } } } '
        . '(@{games=@($g.Values | Sort-Object {-$_.mb}); count=$g.Count} | ConvertTo-Json -Compress -Depth 4)';
    $r = nm_win_ps($ssh,$ps,40); $j=json_decode(trim(_nm_g_out($r)),true);
    if (!is_array($j)) return ['ok'=>true,'games'=>[],'count'=>0];
    $games = $j['games'] ?? []; if (isset($games['name'])) $games=[$games];
    return ['ok'=>true,'games'=>is_array($games)?$games:[],'count'=>(int)($j['count']??0),'folders'=>$extra];
}

// Combined live vitals for a rig: game + GPU + CPU/RAM (+ the game process). Best-effort; never throws.
// Cached game detection — the heaviest PowerShell call (full Win32_Process scan) is shared by the vitals(4s),
// ping-radar(15s) and fps(12s) pollers. A game only changes when the user launches/quits one (minutes apart),
// so cache it per-rig for a short TTL → ~24 process scans/min collapse to ~5. Caches null (no game) too.
function nm_gaming_detect_cached($conn, int $rid, $ssh, int $ttl=12): ?array {
    if ($rid > 0) { $c = nm_gaming_cache_get($conn, $rid);
        if (isset($c['detect_ts']) && (time() - (int)$c['detect_ts']) < $ttl) return $c['detect'] ?? null; }
    $game = null; try { $game = nm_gaming_detect($ssh, nm_gaming_get_folders($conn)); } catch (\Throwable $e) {}
    if ($rid > 0) nm_gaming_cache_set($conn, $rid, 'detect', $game);
    return $game;
}
function nm_gaming_vitals($conn, array $h): array {
    $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn, $h) : null;
    if (!$ssh) return ['ok'=>false,'error'=>'no SSH for this rig'];
    $game = nm_gaming_detect_cached($conn, (int)($h['id'] ?? 0), $ssh);
    $gpu  = ['ok'=>false]; try { $gpu = nm_gaming_gpu($ssh); } catch (\Throwable $e) {}
    // quick CPU/RAM (cheap PS) — avoid the heavy diagnose on the live loop
    $sys = ['cpu'=>null,'mem_used'=>null,'mem_total'=>null];
    try {
        $ps = '$os=Get-CimInstance Win32_OperatingSystem; $cpu=[int]((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average); (@{cpu=$cpu; mt=[math]::Round($os.TotalVisibleMemorySize/1024); mf=[math]::Round($os.FreePhysicalMemory/1024)} | ConvertTo-Json -Compress)';
        $r = nm_win_ps($ssh, $ps, 15); $j = json_decode(trim(_nm_g_out($r)), true);
        if (is_array($j)) { $sys['cpu']=(int)($j['cpu']??0); $sys['mem_total']=(int)($j['mt']??0); $sys['mem_used']=(int)(($j['mt']??0)-($j['mf']??0)); }
    } catch (\Throwable $e) {}
    return ['ok'=>true,'game'=>$game,'gpu'=>$gpu,'sys'=>$sys,'ts'=>time()];
}

// Game Ping Radar: FROM the gamer's PC, Test-Connection to each region endpoint → latency + jitter + loss.
function nm_gaming_ping_radar($conn, array $h, array $endpoints): array {
    $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn, $h) : null;
    if (!$ssh) return ['ok'=>false,'error'=>'no SSH'];
    $regions = [];
    foreach ($endpoints as $region => $host) {
        $host = preg_replace('/[^a-zA-Z0-9_.\-]/','',(string)$host); if ($host==='') continue;
        // resolve the server IP (always, even on timeout) + 6 pings → avg, jitter (stdev), loss%
        $ps = '$ip=\'\'; try{ $ip=([System.Net.Dns]::GetHostAddresses(\''.$host.'\') | Where-Object { $_.AddressFamily -eq \'InterNetwork\' } | Select-Object -First 1).IPAddressToString }catch{}; '
            . '$r=Test-Connection -ComputerName \''.$host.'\' -Count 6 -ErrorAction SilentlyContinue; $t=@($r | ForEach-Object { $_.ResponseTime }); '
            . 'if($t.Count -eq 0){ (@{ip=$ip;loss=100;avg=$null;jit=$null;min=$null;max=$null} | ConvertTo-Json -Compress) } else { '
            . '$avg=[math]::Round(($t | Measure-Object -Average).Average,1); $sd=[math]::Round([math]::Sqrt((($t | ForEach-Object { [math]::Pow($_-$avg,2) } | Measure-Object -Sum).Sum)/$t.Count),1); '
            . '$mn=($t | Measure-Object -Minimum).Minimum; $mx=($t | Measure-Object -Maximum).Maximum; '
            . '(@{ip=$ip; loss=[math]::Round((6-$t.Count)/6*100); avg=$avg; jit=$sd; min=$mn; max=$mx} | ConvertTo-Json -Compress) }';
        $lat = null; $jit = null; $loss = 100; $ip = ''; $mn = null; $mx = null;
        try { $r = nm_win_ps($ssh, $ps, 22); $j = json_decode(trim(_nm_g_out($r)), true);
              if (is_array($j)) { $lat=isset($j['avg'])?(float)$j['avg']:null; $jit=isset($j['jit'])?(float)$j['jit']:null; $loss=(int)($j['loss']??100); $ip=(string)($j['ip']??''); $mn=isset($j['min'])?(float)$j['min']:null; $mx=isset($j['max'])?(float)$j['max']:null; } } catch (\Throwable $e) {}
        $grade = $lat===null ? 'down' : ($lat<40?'good':($lat<90?'ok':'bad'));
        $regions[] = ['region'=>$region,'host'=>$host,'ip'=>$ip,'ms'=>$lat,'jitter'=>$jit,'loss'=>$loss,'min'=>$mn,'max'=>$mx,'grade'=>$grade];
    }
    // verdict: worst loss / jitter
    $verdict=''; $worst=null;
    foreach ($regions as $r) { if ($r['ms']!==null && ($worst===null || $r['ms']<$worst['ms'])) $worst=$r; }
    foreach ($regions as $r) { if (($r['loss']??0) >= 3) { $verdict='⚠ Tu ISP presenta '.$r['loss'].'% packet loss hacia '.$r['region'].' ('.$r['host'].') — vas a sentir lag/desync.'; break; } if (($r['jitter']??0) >= 15) { $verdict='⚠ Jitter alto ('.$r['jitter'].'ms) hacia '.$r['region'].' — posible micro-stutter.'; break; } }
    if ($verdict==='' && $worst) $verdict='✅ Mejor ruta: '.$worst['region'].' a '.$worst['ms'].'ms ('.$worst['host'].').';
    return ['ok'=>true,'regions'=>$regions,'verdict'=>$verdict];
}

// 1-Click Game Booster — reversible + logged. ON: High-Performance power plan + stop junk services.
// OFF: restore prior plan + restart the stopped services. Native PowerShell (no helper needed for P1).
function nm_gaming_boost($conn, array $h, bool $on, ?string $by=null): array {
    nm_gaming_ensure($conn);
    $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn, $h) : null;
    if (!$ssh) return ['ok'=>false,'error'=>'no SSH for this rig'];
    $hid = (int)($h['id'] ?? 0);
    $JUNK = ['Spooler','SysMain','WSearch','DiagTrack'];   // print spooler, superfetch, search index, telemetry
    if ($on) {
        // capture prior plan GUID, switch to High Performance (fallback: create it), stop junk services
        $svc = implode("','", $JUNK);
        $ps = '$prev=(powercfg /getactivescheme); $hp=\'8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c\'; powercfg /setactive $hp 2>$null; if((powercfg /getactivescheme) -notmatch $hp){ $dup=(powercfg -duplicatescheme $hp 2>$null | Out-String); if($dup -match \'([0-9a-fA-F-]{36})\'){ powercfg /setactive $matches[1] 2>$null } }; $stopped=@(); foreach($s in @(\''.$svc.'\')){ try{ $sv=Get-Service -Name $s -ErrorAction SilentlyContinue; if($sv -and $sv.Status -eq \'Running\'){ Stop-Service -Name $s -Force -ErrorAction SilentlyContinue; $stopped+=$s } }catch{} }; (@{prev=$prev; stopped=$stopped; plan=(powercfg /getactivescheme)} | ConvertTo-Json -Compress)';
        $r = nm_win_ps($ssh, $ps, 30); $out = trim(_nm_g_out($r));
        $j = json_decode($out, true); $prev = is_array($j) ? (string)($j['prev'] ?? '') : '';
        $stopped = is_array($j) && !empty($j['stopped']) ? (array)$j['stopped'] : [];
        // parse prior plan GUID for revert
        $prevGuid=''; if (preg_match('/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i',$prev,$mm)) $prevGuid=$mm[1];
        try { $st=$conn->prepare("INSERT INTO nm_game_boost_log (host_id,action,prev_plan,stopped_services,ok,detail,created_by) VALUES (?, 'on', ?, ?, 1, ?, ?)");
              $sj=json_encode($stopped); $det=substr($out,0,500); $st->bind_param('issss',$hid,$prevGuid,$sj,$det,$by); $st->execute(); $st->close(); } catch (\Throwable $e) {}
        return ['ok'=>true,'on'=>true,'stopped'=>$stopped,'plan'=>'High Performance','prev_plan'=>$prevGuid];
    } else {
        // find the last ON log to know what to restore
        $prevGuid=''; $stopped=[];
        try { $q=$conn->query("SELECT prev_plan,stopped_services FROM nm_game_boost_log WHERE host_id=$hid AND action='on' ORDER BY id DESC LIMIT 1");
              if ($q && $x=$q->fetch_assoc()) { $prevGuid=(string)$x['prev_plan']; $stopped=json_decode((string)$x['stopped_services'],true) ?: []; } } catch (\Throwable $e) {}
        $restorePlan = $prevGuid !== '' ? $prevGuid : '381b4222-f694-41f0-9685-ff5bb260df2e';  // fallback: Balanced
        $svc = $stopped ? implode("','", array_map(fn($s)=>preg_replace('/[^A-Za-z0-9_]/','',$s),$stopped)) : '';
        $ps = 'powercfg /setactive \''.$restorePlan.'\' 2>$null; $started=@();'.($svc!=='' ? ' foreach($s in @(\''.$svc.'\')){ try{ Start-Service -Name $s -ErrorAction SilentlyContinue; $started+=$s }catch{} }' : '').' (@{started=$started; plan=(powercfg /getactivescheme)} | ConvertTo-Json -Compress)';
        $r = nm_win_ps($ssh, $ps, 30); $out = trim(_nm_g_out($r));
        try { $st=$conn->prepare("INSERT INTO nm_game_boost_log (host_id,action,prev_plan,stopped_services,ok,detail,created_by) VALUES (?, 'off', ?, ?, 1, ?, ?)");
              $sj=json_encode($stopped); $det=substr($out,0,500); $st->bind_param('issss',$hid,$restorePlan,$sj,$det,$by); $st->execute(); $st->close(); } catch (\Throwable $e) {}
        return ['ok'=>true,'on'=>false,'restored'=>$stopped,'plan'=>'restored'];
    }
}

// small settings getter (nm_settings)
function nm_gaming_get($conn, string $k, string $d=''): string {
    try { $st=$conn->prepare("SELECT setting_val FROM nm_settings WHERE setting_key=? LIMIT 1"); $st->bind_param('s',$k); $st->execute(); $r=$st->get_result()->fetch_row(); $st->close(); return $r?(string)$r[0]:$d; } catch (\Throwable $e){ return $d; }
}

// ── FPS (crown jewel) via PresentMon over SSH — real frame-times → avg + 1% / 0.1% lows ──
// PresentMon = Microsoft/Intel's ETW frame capture. Needs an ADMIN SSH user. Lives at C:\NEURU\PresentMon.exe.
function nm_gaming_pm_status($ssh): array {
    $r = nm_win_ps($ssh, "if(Test-Path 'C:\\NEURU\\PresentMon.exe'){'yes'}else{'no'}", 12);
    return ['ok'=>true,'present'=>strpos(_nm_g_out($r),'yes')!==false];
}
function nm_gaming_pm_deploy($conn, $ssh): array {
    $url = nm_gaming_get($conn,'game_presentmon_url','https://github.com/GameTechDev/PresentMon/releases/download/v1.9.2/PresentMon-1.9.2-x64.exe');
    $url = preg_replace('/[^a-zA-Z0-9_.:\/?&=%\-]/','',$url);   // allow query strings; still strips quotes/`;$ that could break the PS literal
    $ps = 'try{ New-Item -ItemType Directory -Force C:\\NEURU | Out-Null; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri \''.$url.'\' -OutFile \'C:\\NEURU\\PresentMon.exe\' -UseBasicParsing; if(Test-Path \'C:\\NEURU\\PresentMon.exe\'){\'ok\'}else{\'fail\'} }catch{ \'err:\'+$_.Exception.Message }';
    $r = nm_win_ps($ssh,$ps,90); $out = trim(_nm_g_out($r));
    return strpos($out,'ok')!==false ? ['ok'=>true] : ['ok'=>false,'error'=>($out?:'download failed')];
}
// capture N seconds of frames for a process → {avg, low1, low01, frames, frametime}. Percentile method (RTSS/Afterburner).
function nm_gaming_fps($ssh, string $process, int $secs=4): array {
    $st = nm_gaming_pm_status($ssh); if (empty($st['present'])) return ['ok'=>false,'need_helper'=>true];
    $proc = preg_replace('/[^a-zA-Z0-9_\-]/','',$process); if ($proc==='') return ['ok'=>false,'error'=>'no process'];
    $secs = max(2,min(8,$secs));
    $cmd = 'Remove-Item \'C:\\NEURU\\pm.csv\' -ErrorAction SilentlyContinue; & \'C:\\NEURU\\PresentMon.exe\' -process_name '.$proc.'.exe -output_file \'C:\\NEURU\\pm.csv\' -timed '.$secs.' -terminate_after_timed -stop_existing_session -no_top 2>&1 | Out-Null; if(Test-Path \'C:\\NEURU\\pm.csv\'){ Get-Content \'C:\\NEURU\\pm.csv\' -Raw } else { \'NOCSV\' }';
    $r = nm_win_ps($ssh,$cmd,$secs+22); $out = _nm_g_out($r);
    if ($out==='' || strpos($out,'NOCSV')!==false) return ['ok'=>false,'error'=>'no frames — PresentMon needs an admin SSH user, or the game must be in-focus'];
    $lines = preg_split('/\r?\n/', trim($out)); if (count($lines)<2) return ['ok'=>false,'error'=>'no frames captured'];
    $hdr = str_getcsv($lines[0]); $ftIdx=-1;
    foreach ($hdr as $i=>$col){ if (strpos(strtolower(trim($col)),'msbetweenpresents')!==false){ $ftIdx=$i; break; } }
    if ($ftIdx<0) foreach ($hdr as $i=>$col){ if (strpos(strtolower($col),'msbetweendisplaychange')!==false){ $ftIdx=$i; break; } }
    if ($ftIdx<0) return ['ok'=>false,'error'=>'no frame-time column'];
    $ft=[]; for($i=1;$i<count($lines);$i++){ $row=str_getcsv($lines[$i]); if(isset($row[$ftIdx])&&is_numeric($row[$ftIdx])){ $v=(float)$row[$ftIdx]; if($v>0 && $v<1000) $ft[]=$v; } }
    if (count($ft)<10) return ['ok'=>false,'error'=>'too few frames ('.count($ft).')'];
    sort($ft); $n=count($ft); $mean=array_sum($ft)/$n;
    $pct=function($p) use($ft,$n){ $idx=(int)floor($p/100*($n-1)); return $ft[max(0,min($n-1,$idx))]; };
    return ['ok'=>true,'avg'=>round(1000/$mean,1),'low1'=>round(1000/$pct(99),1),'low01'=>round(1000/$pct(99.9),1),'frames'=>$n,'frametime'=>round($mean,2)];
}

// ── Game session tracking (summary: duration, max GPU temp, peak VRAM, avg/1%/0.1% FPS) ──
function nm_gaming_session_open($conn, int $hid, array $game): int {
    try { $q=$conn->query("SELECT id FROM nm_game_sessions WHERE host_id=$hid AND ended_at IS NULL AND process='".$conn->real_escape_string($game['process'])."' ORDER BY id DESC LIMIT 1");
          if ($q && $x=$q->fetch_row()) return (int)$x[0]; } catch (\Throwable $e){}
    // close any other open session on this host (game changed)
    try { $conn->query("UPDATE nm_game_sessions SET ended_at=NOW() WHERE host_id=$hid AND ended_at IS NULL"); } catch (\Throwable $e){}
    try { $st=$conn->prepare("INSERT INTO nm_game_sessions (host_id,title,process) VALUES (?,?,?)"); $st->bind_param('iss',$hid,$game['title'],$game['process']); $st->execute(); $id=$st->insert_id; $st->close(); return (int)$id; } catch (\Throwable $e){ return 0; }
}
function nm_gaming_session_bump($conn, int $sid, ?int $temp, ?int $vram, ?array $fps): void {
    if ($sid<=0) return;
    try {
        $sets=[]; if($temp!==null) $sets[]="max_gpu_temp=GREATEST(COALESCE(max_gpu_temp,0),".(int)$temp.")"; if($vram!==null) $sets[]="peak_vram_mb=GREATEST(COALESCE(peak_vram_mb,0),".(int)$vram.")";
        if($fps && !empty($fps['ok'])){ $sets[]="avg_fps=".(float)$fps['avg']; $sets[]="low1_fps=".(float)$fps['low1']; $sets[]="low01_fps=".(float)$fps['low01']; }
        if($sets) $conn->query("UPDATE nm_game_sessions SET ".implode(',',$sets)." WHERE id=".(int)$sid);
    } catch (\Throwable $e){}
}
function nm_gaming_session_close_if_idle($conn, int $hid, ?array $game): void {
    if ($game) return;   // still gaming
    try { $conn->query("UPDATE nm_game_sessions SET ended_at=NOW() WHERE host_id=$hid AND ended_at IS NULL"); } catch (\Throwable $e){}
}
function nm_gaming_last_session($conn, int $hid): ?array {
    try { $q=$conn->query("SELECT title,process,started_at,ended_at,max_gpu_temp,peak_vram_mb,avg_fps,low1_fps,low01_fps, TIMESTAMPDIFF(MINUTE,started_at,COALESCE(ended_at,NOW())) mins FROM nm_game_sessions WHERE host_id=$hid ORDER BY id DESC LIMIT 1");
          if ($q && $x=$q->fetch_assoc()) return $x; } catch (\Throwable $e){}
    return null;
}

// ── Player DNA + Achievements (gamer identity + gamification) from the nm_game_sessions history ──
function nm_gaming_dna($conn, int $rid): array {
    nm_gaming_ensure($conn);
    $a = ['sessions'=>0,'mins'=>0,'games'=>0,'best_fps'=>0,'best_low1'=>0,'coolest'=>null,'avg_max_temp'=>null,'longest'=>0,'peak_vram'=>0,'stab'=>null];
    $titles = [];
    // exclude any mis-detected NON-game sessions (vmmem, security suites, WhatsApp/Copilot…) so historical junk
    // never inflates Player DNA / achievements — universal, non-destructive (works for every user's old data).
    $noiseRe = implode('|', nm_gaming_noise_tokens());
    try {
        $q = $conn->prepare("SELECT COUNT(*) c,
            COALESCE(SUM(TIMESTAMPDIFF(MINUTE,started_at,COALESCE(ended_at,NOW()))),0) mins,
            COUNT(DISTINCT process) games, COALESCE(MAX(avg_fps),0) best_fps, COALESCE(MAX(low1_fps),0) best_low1,
            MIN(NULLIF(max_gpu_temp,0)) coolest, AVG(NULLIF(max_gpu_temp,0)) avg_max_temp,
            COALESCE(MAX(TIMESTAMPDIFF(MINUTE,started_at,COALESCE(ended_at,NOW()))),0) longest,
            COALESCE(MAX(peak_vram_mb),0) peak_vram,
            AVG(CASE WHEN avg_fps>0 THEN low1_fps/avg_fps END) stab
            FROM nm_game_sessions WHERE host_id=? AND (process IS NULL OR process NOT REGEXP ?)");
        $q->bind_param('is',$rid,$noiseRe); $q->execute(); $r=$q->get_result()->fetch_assoc(); $q->close();
        if ($r) {
            $a['sessions']=(int)$r['c']; $a['mins']=(int)$r['mins']; $a['games']=(int)$r['games'];
            $a['best_fps']=round((float)$r['best_fps']); $a['best_low1']=round((float)$r['best_low1']);
            $a['coolest']=$r['coolest']!==null?round((float)$r['coolest']):null;
            $a['avg_max_temp']=$r['avg_max_temp']!==null?round((float)$r['avg_max_temp']):null;
            $a['longest']=(int)$r['longest']; $a['peak_vram']=(int)$r['peak_vram'];
            $a['stab']=$r['stab']!==null?(float)$r['stab']:null;
        }
        $tq=$conn->prepare("SELECT DISTINCT title FROM nm_game_sessions WHERE host_id=? AND title IS NOT NULL AND title<>'' AND (process IS NULL OR process NOT REGEXP ?) ORDER BY title LIMIT 40");
        $tq->bind_param('is',$rid,$noiseRe); $tq->execute(); $rs=$tq->get_result(); while($x=$rs->fetch_row()) $titles[]=$x[0]; $tq->close();
    } catch (\Throwable $e) {}

    $cl = fn($v,$lo=0,$hi=100)=>max($lo,min($hi,$v));
    $hours = round($a['mins']/60,1);
    // traits 0-100 (null when we have no data for that axis yet)
    $traits = [];
    if ($a['avg_max_temp']!==null) $traits['Thermals'] = (int)round($cl(100-($a['avg_max_temp']-58)*2.5));
    if ($a['best_fps']>0)          $traits['Frames']   = (int)round($cl($a['best_fps']/144*100));
    if ($a['stab']!==null)         $traits['Stability']= (int)round($cl($a['stab']*100));
    $traits['Endurance'] = (int)round($cl($hours/40*100));
    $traits['Explorer']  = (int)round($cl($a['games']/8*100));

    // archetype = dominant trait (+ a couple of expressive combos)
    $arch = ['name'=>'Rising Contender','emoji'=>'🌱','desc'=>'Just getting started — play more and your DNA takes shape.'];
    if ($a['sessions']>0 && $traits) {
        $tt=$traits; arsort($tt); $top=array_key_first($tt);
        $hot = ($a['avg_max_temp']!==null && $a['avg_max_temp']>=80);
        if (($traits['Frames']??0)>=70 && $hot)        $arch=['name'=>'Thermal Daredevil','emoji'=>'🔥','desc'=>'High frames, running hot — raw performance over caution.'];
        elseif ($top==='Thermals')                     $arch=['name'=>'Thermal Zen','emoji'=>'❄️','desc'=>'Ice-cold and composed. Your rig barely breaks a sweat.'];
        elseif ($top==='Stability')                    $arch=['name'=>'Precision Sniper','emoji'=>'🎯','desc'=>'Rock-steady frame-times — every shot lands where you aim.'];
        elseif ($top==='Frames')                       $arch=['name'=>'Speedrunner Optimized','emoji'=>'⚡','desc'=>'Maximum frames, minimum latency. Built for speed.'];
        elseif ($top==='Endurance')                    $arch=['name'=>'Endurance Marathoner','emoji'=>'🕹️','desc'=>'Marathon sessions — you and your rig go the distance.'];
        elseif ($top==='Explorer')                     $arch=['name'=>'Realm Explorer','emoji'=>'🌌','desc'=>'A wide library — always a new world to conquer.'];
    }

    // achievements — technical milestones
    $mk = fn($id,$emoji,$name,$desc,$unlocked,$prog)=>['id'=>$id,'emoji'=>$emoji,'name'=>$name,'desc'=>$desc,'unlocked'=>(bool)$unlocked,'progress'=>round(max(0,min(1,$prog)),3)];
    $ach = [];
    $cool=$a['coolest'];
    $ach[]=$mk('subzero','❄️','Sub-Zero','Peak GPU temp under 60°C in a session', $cool!==null&&$cool<60, $cool!==null?(75-$cool)/15:0);
    $ach[]=$mk('framelord','⚡','Frame Lord','Average 120+ FPS in a session', $a['best_fps']>=120, $a['best_fps']/120);
    $ach[]=$mk('rocksolid','🪨','Rock Solid','1% low within 12% of your average FPS', $a['stab']!==null&&$a['stab']>=0.88, $a['stab']!==null?$a['stab']/0.88:0);
    $ach[]=$mk('marathon','🕹️','Marathoner','A single 2-hour+ session', $a['longest']>=120, $a['longest']/120);
    $ach[]=$mk('veteran','🎖️','Veteran','24 hours total playtime', $hours>=24, $hours/24);
    $ach[]=$mk('explorer','🌌','Realm Explorer','Play 5 different games', $a['games']>=5, $a['games']/5);
    $ach[]=$mk('chill','🧊','Cool Operator','Average peak temp under 70°C (3+ sessions)', $a['avg_max_temp']!==null&&$a['avg_max_temp']<70&&$a['sessions']>=3, $a['avg_max_temp']!==null?(85-$a['avg_max_temp'])/15:0);
    $ach[]=$mk('regular','🔁','Regular','25 gaming sessions logged', $a['sessions']>=25, $a['sessions']/25);
    $ach[]=$mk('vram','🧠','VRAM Bender','Push 12GB+ VRAM in a session', $a['peak_vram']>=12000, $a['peak_vram']/12000);

    $unlocked = count(array_filter($ach, fn($x)=>$x['unlocked']));
    $xp = $a['mins'] + $unlocked*600 + $a['games']*150;
    $level = max(1,(int)floor(sqrt(max(0,$xp)/120)));
    $ranks = ['Bronze','Silver','Gold','Platinum','Diamond','Master','Grandmaster','Legend'];
    $rank = $ranks[min(count($ranks)-1, intdiv($level,3))];
    $curBase=(int)(pow($level,2)*120); $nextBase=(int)(pow($level+1,2)*120);

    return ['ok'=>true,'agg'=>$a,'hours'=>$hours,'titles'=>$titles,'traits'=>$traits,'archetype'=>$arch,
            'achievements'=>$ach,'unlocked'=>$unlocked,'total'=>count($ach),
            'xp'=>$xp,'level'=>$level,'rank'=>$rank,'xpInto'=>max(0,$xp-$curBase),'xpSpan'=>max(1,$nextBase-$curBase)];
}

// ── Bandwidth hog detector: per-process I/O throughput (proxy) + LAN top-talkers (NetFlow) ──
function nm_gaming_bandwidth_hogs($conn, array $h): array {
    $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn,$h) : null; if (!$ssh) return ['ok'=>false,'error'=>'no SSH'];
    $procs=[]; $net=null; $err='';
    try {
        // Use CIM PerfFormattedData classes — their property names are ENGLISH regardless of Windows display
        // language (Get-Counter counter PATHS are localized → they THROW on a Spanish/German/… rig, which is why
        // the panel was permanently blank). (a) system-wide network Bytes Received/Sent per sec across real NICs;
        // (b) busiest processes by IODataBytesPersec (disk+net+pipe — the only native per-process hogging proxy).
        $ps = 'try{ '
            . '$p=@(Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch \'^(_Total|Idle|System|Memory Compression)$\' -and $_.IODataBytesPersec -gt 5000 } | Sort-Object IODataBytesPersec -Descending | Select-Object -First 8 | ForEach-Object { @{ name=[string]$_.Name; bps=[int64]$_.IODataBytesPersec } }); '
            . '$ni=Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch \'Loopback|isatap|Teredo|Pseudo|Virtual|Filter|Tunnel\' }; '
            . '$rx=($ni | Measure-Object BytesReceivedPersec -Sum).Sum; $tx=($ni | Measure-Object BytesSentPersec -Sum).Sum; '
            . '(@{ procs=@($p); rx=[math]::Round([double]$rx,0); tx=[math]::Round([double]$tx,0) } | ConvertTo-Json -Compress -Depth 4) '
            . '}catch{ (@{err=[string]$_.Exception.Message} | ConvertTo-Json -Compress) }';
        $r=nm_win_ps($ssh,$ps,20); $j=json_decode(trim(_nm_g_out($r)),true);
        if (is_array($j)){
            if (isset($j['err'])) $err=(string)$j['err'];
            if (isset($j['rx']) || isset($j['tx'])) $net=['rx'=>(int)($j['rx']??0),'tx'=>(int)($j['tx']??0)];
            $list = $j['procs'] ?? (isset($j['name'])?[$j]:[]); if (isset($list['name'])) $list=[$list];
            // aggregate multiple instances of the same app (Get-Counter emits "firefox", "firefox#1", …) into one row
            $agg=[]; foreach((array)$list as $x){ $nm=preg_replace('/#\d+$/','',strtolower((string)($x['name']??''))); if($nm===''||$nm==='memory compression')continue; $agg[$nm]=($agg[$nm]??0)+(int)($x['bps']??0); }
            arsort($agg); foreach(array_slice($agg,0,6,true) as $nm=>$bps) $procs[]=['name'=>$nm,'bps'=>$bps]; }
    } catch (\Throwable $e){ $err=$e->getMessage(); }
    // LAN top-talkers from NetFlow (last 5 min), best-effort
    $lan=[];
    try { $q=$conn->query("SELECT src_addr ip, SUM(bytes) b FROM nm_netflow_flows WHERE ts >= (UTC_TIMESTAMP() - INTERVAL 5 MINUTE) GROUP BY src_addr ORDER BY b DESC LIMIT 5");
          while($q && $x=$q->fetch_assoc()) $lan[]=['ip'=>$x['ip'],'bytes'=>(int)$x['b']]; } catch (\Throwable $e){}
    return ['ok'=>true,'procs'=>$procs,'lan'=>$lan,'net'=>$net,'err'=>$err];
}

// ── Webhook automation: Discord alerts + Smart-Home Game Mode (fire-and-forget POST) ──
function nm_gaming_webhook_fire(string $url, array $payload, bool $discord=false): bool {
    if ($url==='' || !preg_match('#^https?://#i',$url)) return false;
    $ch=curl_init($url); if(!$ch) return false;
    $body = $discord ? json_encode(['content'=>(string)($payload['content']??''),'username'=>'NEURU Game Mode']) : json_encode($payload);
    curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$body,CURLOPT_HTTPHEADER=>['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>6,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_FOLLOWLOCATION=>false]);
    $ok = curl_exec($ch)!==false && curl_getinfo($ch,CURLINFO_HTTP_CODE) < 400; curl_close($ch); return $ok;
}
// fire the configured Discord + Smart-Home hooks for a Game-Mode event (best-effort, never throws).
function nm_gaming_notify($conn, string $event, string $rig, array $extra=[]): void {
    try {
        $dc = nm_gaming_get($conn,'game_discord_webhook','');
        if ($dc!=='') { $msg = $event==='boost_on' ? ('🎮 **Game Mode ON** on **'.$rig.'** — power plan boosted, junk services stopped. GLHF!')
            : ($event==='boost_off' ? ('🛑 Game Mode OFF on **'.$rig.'** — everything restored.')
            : ($event==='thermal' ? ('🔥 **Thermal alert** on **'.$rig.'** — GPU '.($extra['temp']??'?').'°C, throttling.')
            : ('⚠ **Lag alert** on **'.$rig.'** — '.($extra['detail']??'network issue to your game server.'))));
            nm_gaming_webhook_fire($dc,['content'=>$msg],true); }
        $sh = nm_gaming_get($conn,'game_smarthome_webhook','');
        if ($sh!=='') nm_gaming_webhook_fire($sh,['event'=>$event,'rig'=>$rig,'game_mode'=>($event==='boost_on'),'source'=>'neuru']+$extra);
    } catch (\Throwable $e) {}
}

// ── Proof-of-Lag: aggregate the ping history into an ISP-ready evidence report ──
function nm_gaming_lag_report($conn, int $rid, int $hours=24): array {
    nm_gaming_ensure($conn); $hours=max(1,min(720,$hours));
    $sum=['samples'=>0,'avg_ms'=>null,'max_ms'=>null,'avg_jit'=>null,'max_jit'=>null,'loss_events'=>0,'avg_loss'=>0,'worst_region'=>null];
    try { $q=$conn->prepare("SELECT COUNT(*) n, ROUND(AVG(ms),1) am, ROUND(MAX(ms),1) mm, ROUND(AVG(jitter),1) aj, ROUND(MAX(jitter),1) mj, SUM(loss>0) le, ROUND(AVG(loss),1) al FROM nm_game_lag_log WHERE rig_id=? AND sampled_at >= (UTC_TIMESTAMP() - INTERVAL ? HOUR)");
        $q->bind_param('ii',$rid,$hours); $q->execute(); $r=$q->get_result()->fetch_assoc(); $q->close();
        if ($r){ $sum['samples']=(int)$r['n']; $sum['avg_ms']=$r['am']; $sum['max_ms']=$r['mm']; $sum['avg_jit']=$r['aj']; $sum['max_jit']=$r['mj']; $sum['loss_events']=(int)$r['le']; $sum['avg_loss']=(float)$r['al']; }
    } catch (\Throwable $e){}
    // worst region by avg loss+ms
    try { $q=$conn->prepare("SELECT region, host, ROUND(AVG(ms),1) am, ROUND(AVG(jitter),1) aj, ROUND(AVG(loss),1) al, COUNT(*) n FROM nm_game_lag_log WHERE rig_id=? AND sampled_at >= (UTC_TIMESTAMP() - INTERVAL ? HOUR) GROUP BY region,host ORDER BY al DESC, am DESC LIMIT 1");
        $q->bind_param('ii',$rid,$hours); $q->execute(); $r=$q->get_result()->fetch_assoc(); $q->close(); if($r) $sum['worst_region']=$r; } catch (\Throwable $e){}
    // hourly series (for the timeline chart)
    $series=[]; try { $q=$conn->prepare("SELECT DATE_FORMAT(sampled_at,'%Y-%m-%d %H:00') hr, ROUND(AVG(ms),0) ms, ROUND(MAX(jitter),0) jit, ROUND(AVG(loss),0) loss FROM nm_game_lag_log WHERE rig_id=? AND sampled_at >= (UTC_TIMESTAMP() - INTERVAL ? HOUR) GROUP BY hr ORDER BY hr");
        $q->bind_param('ii',$rid,$hours); $q->execute(); $rs=$q->get_result(); while($x=$rs->fetch_assoc()) $series[]=['t'=>$x['hr'],'ms'=>(float)$x['ms'],'jit'=>(float)$x['jit'],'loss'=>(float)$x['loss']]; $q->close(); } catch (\Throwable $e){}
    // verdict for the ISP
    $v=[]; if($sum['avg_loss']>=2) $v[]='Sustained packet loss averaging '.$sum['avg_loss'].'% over '.$hours.'h';
    if(($sum['max_jit']??0)>=20) $v[]='Latency instability (jitter peaks of '.$sum['max_jit'].'ms)';
    if(($sum['max_ms']??0)>=120) $v[]='Latency spikes up to '.$sum['max_ms'].'ms';
    $verdict = $v ? ('This connection shows: '.implode('; ',$v).'. These conditions cause in-game lag, rubber-banding and desync — consistent with a problem on the ISP path, not the local PC.') : 'No significant loss/jitter recorded in this window.';
    return ['ok'=>true,'hours'=>$hours,'summary'=>$sum,'series'=>$series,'verdict'=>$verdict];
}

// is boost currently ON for this rig? (last log row is 'on')
function nm_gaming_boost_state($conn, int $hid): bool {
    try { $q=$conn->query("SELECT action FROM nm_game_boost_log WHERE host_id=".(int)$hid." ORDER BY id DESC LIMIT 1");
          if ($q && $x=$q->fetch_assoc()) return $x['action']==='on'; } catch (\Throwable $e) {}
    return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// GAME SERVER STATUS — monitor famous game services (are they down?) + the user's OWN
// server (Minecraft/CS2/etc.) with live player counts. Checked FROM the NOC host (pure PHP
// sockets) — no gaming rig needed. Reachability + latency, plus real game-query protocols.
// ═══════════════════════════════════════════════════════════════════════════════
function nm_gaming_servers_ensure($conn): void {
    if (!($conn instanceof mysqli)) return;
    try { $conn->query("CREATE TABLE IF NOT EXISTS nm_game_servers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(80) NOT NULL, game VARCHAR(60) NULL, host VARCHAR(191) NOT NULL, port INT NOT NULL DEFAULT 443,
        proto ENUM('tcp','ping','minecraft','source') NOT NULL DEFAULT 'tcp',
        kind ENUM('official','custom') NOT NULL DEFAULT 'custom', enabled TINYINT(1) NOT NULL DEFAULT 1,
        last_up TINYINT(1) NULL, last_ms INT NULL, last_players INT NULL, last_max INT NULL,
        last_detail VARCHAR(160) NULL, last_check TIMESTAMP NULL DEFAULT NULL,
        created_by VARCHAR(60) NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq (host,port,proto), KEY k_kind (kind)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); } catch (\Throwable $e) {}
    // seed the famous game services (reachability of their official endpoints, port 443/game-port)
    foreach (nm_gaming_famous() as $f) {
        try { $st=$conn->prepare("INSERT IGNORE INTO nm_game_servers (name,game,host,port,proto,kind,created_by) VALUES (?,?,?,?,?, 'official','seed')");
              $st->bind_param('sssis',$f['name'],$f['game'],$f['host'],$f['port'],$f['proto']); $st->execute(); $st->close(); } catch (\Throwable $e) {}
    }
}

// curated list of the most famous game services (non-gamer friendly) — reachability targets.
function nm_gaming_famous(): array {
    return [
        ['name'=>'Valorant / LoL (Riot)','game'=>'Riot','host'=>'www.riotgames.com','port'=>443,'proto'=>'tcp'],
        ['name'=>'CS2 / Dota 2 (Steam)','game'=>'Valve','host'=>'api.steampowered.com','port'=>443,'proto'=>'tcp'],
        ['name'=>'Fortnite (Epic)','game'=>'Epic','host'=>'epicgames.com','port'=>443,'proto'=>'tcp'],
        ['name'=>'Call of Duty (Activision)','game'=>'Activision','host'=>'www.callofduty.com','port'=>443,'proto'=>'tcp'],
        ['name'=>'Apex / EA','game'=>'EA','host'=>'www.ea.com','port'=>443,'proto'=>'tcp'],
        ['name'=>'Overwatch / Blizzard','game'=>'Blizzard','host'=>'www.battle.net','port'=>443,'proto'=>'tcp'],
        ['name'=>'Minecraft (Mojang)','game'=>'Mojang','host'=>'sessionserver.mojang.com','port'=>443,'proto'=>'tcp'],
        ['name'=>'GTA Online (Rockstar)','game'=>'Rockstar','host'=>'www.rockstargames.com','port'=>443,'proto'=>'tcp'],
        ['name'=>'Roblox','game'=>'Roblox','host'=>'www.roblox.com','port'=>443,'proto'=>'tcp'],
        ['name'=>'Xbox Live','game'=>'Xbox','host'=>'www.xbox.com','port'=>443,'proto'=>'tcp'],
        ['name'=>'PlayStation Network','game'=>'PSN','host'=>'www.playstation.com','port'=>443,'proto'=>'tcp'],
        ['name'=>'Discord','game'=>'Discord','host'=>'discord.com','port'=>443,'proto'=>'tcp'],
    ];
}

// ── low-level query protocols (pure PHP sockets, from the NOC host) ──
function _nm_g_varint(int $v): string { $out=''; $v &= 0xFFFFFFFF; do { $b=$v & 0x7F; $v = ($v >> 7) & 0x01FFFFFF; if ($v) $b |= 0x80; $out.=chr($b); } while ($v); return $out; }
function _nm_g_read_varint($fp){ $val=0; $pos=0; while(true){ $byte=fread($fp,1); if($byte===''||$byte===false) return false; $b=ord($byte); $val |= (($b & 0x7F) << (7*$pos)); if(!($b & 0x80)) break; $pos++; if($pos>5) return false; } return $val; }
function _nm_g_cstr(string $buf, int &$off): string { $s=''; $n=strlen($buf); while($off<$n && $buf[$off]!=="\x00"){ $s.=$buf[$off]; $off++; } $off++; return $s; }

function nm_gaming_query_tcp(string $host, int $port, float $to=2.0): array {
    $t0=microtime(true); $fp=@fsockopen($host,$port,$e,$es,$to); if(!$fp) return ['up'=>false,'detail'=>$es?:'no connect']; fclose($fp);
    return ['up'=>true,'ms'=>(int)round((microtime(true)-$t0)*1000)];
}
function nm_gaming_query_ping(string $host, float $to=3.0): array {
    // pure-PHP: TCP 443 as a reachability proxy (ICMP needs raw sockets/root)
    return nm_gaming_query_tcp($host, 443, $to) + ['detail'=>'reachability (tcp/443)'];
}
function nm_gaming_query_minecraft(string $host, int $port=25565, float $to=3.0): array {
    $t0=microtime(true); $fp=@fsockopen($host,$port,$e,$es,$to); if(!$fp) return ['up'=>false,'detail'=>'offline'];
    stream_set_timeout($fp,(int)$to);
    $payload = "\x00"._nm_g_varint(-1)._nm_g_varint(strlen($host)).$host.pack('n',$port)."\x01";  // handshake, next-state=status
    @fwrite($fp, _nm_g_varint(strlen($payload)).$payload);
    @fwrite($fp, "\x01\x00");   // status request
    $len=_nm_g_read_varint($fp); if($len===false){ fclose($fp); return ['up'=>true,'ms'=>(int)round((microtime(true)-$t0)*1000)]; }
    _nm_g_read_varint($fp);     // packet id
    $jlen=_nm_g_read_varint($fp); if($jlen===false){ fclose($fp); return ['up'=>true]; }
    $json=''; $guard=0; while(strlen($json)<$jlen && $guard++<2000){ $c=fread($fp,$jlen-strlen($json)); if($c===''||$c===false)break; $json.=$c; }
    fclose($fp); $ms=(int)round((microtime(true)-$t0)*1000);
    $d=json_decode($json,true); if(!is_array($d)) return ['up'=>true,'ms'=>$ms];
    $motd = is_array($d['description']??null) ? (string)($d['description']['text'] ?? '') : (string)($d['description'] ?? '');
    return ['up'=>true,'ms'=>$ms,'players'=>(int)($d['players']['online']??0),'max'=>(int)($d['players']['max']??0),
            'detail'=>trim(($d['version']['name']??'').' · '.substr(preg_replace('/\xC2?\xA7./u','',$motd),0,50))];
}
function nm_gaming_query_source(string $host, int $port=27015, float $to=3.0): array {
    $t0=microtime(true); $s=@fsockopen('udp://'.$host,$port,$e,$es,$to); if(!$s) return ['up'=>false,'detail'=>'offline'];
    stream_set_timeout($s,(int)$to);
    $req="\xFF\xFF\xFF\xFFTSource Engine Query\x00"; @fwrite($s,$req); $resp=@fread($s,1400);
    if (is_string($resp) && strlen($resp)>=5 && $resp[4]==="\x41"){ $chal=substr($resp,5,4); @fwrite($s,$req.$chal); $resp=@fread($s,1400); }  // challenge
    fclose($s); $ms=(int)round((microtime(true)-$t0)*1000);
    if (!is_string($resp) || strlen($resp)<6 || $resp[4]!=="\x49") return ['up'=>(is_string($resp)&&strlen($resp)>0),'ms'=>$ms];
    $off=6; $name=_nm_g_cstr($resp,$off); $map=_nm_g_cstr($resp,$off); _nm_g_cstr($resp,$off); _nm_g_cstr($resp,$off); $off+=2;
    $players=isset($resp[$off])?ord($resp[$off]):0; $max=isset($resp[$off+1])?ord($resp[$off+1]):0;
    return ['up'=>true,'ms'=>$ms,'players'=>$players,'max'=>$max,'detail'=>trim(substr($name,0,34).' · '.$map)];
}

function nm_gaming_server_check(array $srv): array {
    $host=(string)$srv['host']; $port=(int)$srv['port']; $proto=(string)$srv['proto'];
    switch ($proto) {
        case 'minecraft': $r=nm_gaming_query_minecraft($host,$port?:25565); break;
        case 'source':    $r=nm_gaming_query_source($host,$port?:27015); break;
        case 'ping':      $r=nm_gaming_query_ping($host); break;
        default:          $r=nm_gaming_query_tcp($host,$port?:443); break;
    }
    return $r + ['up'=>$r['up']??false];
}

function nm_gaming_valid_host(string $h): bool {
    $h=trim($h); if ($h===''||strlen($h)>190) return false;
    return (bool)preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9.\-]*[a-zA-Z0-9])?$/', $h) || filter_var($h, FILTER_VALIDATE_IP);
}
function nm_gaming_server_add($conn, array $f, ?string $by): array {
    nm_gaming_servers_ensure($conn);
    $host=trim((string)($f['host']??'')); if (!nm_gaming_valid_host($host)) return ['ok'=>false,'error'=>'invalid host'];
    $proto=in_array(($f['proto']??'tcp'),['tcp','ping','minecraft','source'],true)?$f['proto']:'tcp';
    $defPort=['minecraft'=>25565,'source'=>27015,'tcp'=>443,'ping'=>0][$proto];
    $port=(int)($f['port']??$defPort); if($port<0||$port>65535) $port=$defPort;
    $name=substr(trim((string)($f['name']??$host)),0,80) ?: $host; $game=substr(trim((string)($f['game']??'Custom')),0,60);
    try { $st=$conn->prepare("INSERT INTO nm_game_servers (name,game,host,port,proto,kind,created_by) VALUES (?,?,?,?,?, 'custom',?) ON DUPLICATE KEY UPDATE name=VALUES(name), enabled=1");
          $st->bind_param('sssiss',$name,$game,$host,$port,$proto,$by); $st->execute(); $id=$st->insert_id; $st->close();
          return ['ok'=>true,'id'=>(int)$id]; } catch (\Throwable $e){ return ['ok'=>false,'error'=>'save failed']; }
}
function nm_gaming_server_del($conn, int $id): array {
    try { $conn->query("DELETE FROM nm_game_servers WHERE id=".(int)$id." AND kind='custom'"); return ['ok'=>true]; } catch (\Throwable $e){ return ['ok'=>false]; }
}
// check all enabled servers (cap runtime), persist status, return the board grouped official|custom.
function nm_gaming_servers_status($conn, bool $recheck=true): array {
    nm_gaming_servers_ensure($conn);
    $rows=[]; try { $r=$conn->query("SELECT * FROM nm_game_servers WHERE enabled=1 ORDER BY kind DESC, name"); while($r && $x=$r->fetch_assoc()) $rows[]=$x; } catch (\Throwable $e){}
    $out=['official'=>[],'custom'=>[]];
    foreach ($rows as $s) {
        $up=$s['last_up']; $ms=$s['last_ms']; $players=$s['last_players']; $max=$s['last_max']; $detail=$s['last_detail'];
        if ($recheck) {
            $c=nm_gaming_server_check($s);
            $up=!empty($c['up'])?1:0; $ms=$c['ms']??null; $players=$c['players']??null; $max=$c['max']??null; $detail=$c['detail']??null;
            try { $st=$conn->prepare("UPDATE nm_game_servers SET last_up=?, last_ms=?, last_players=?, last_max=?, last_detail=?, last_check=NOW() WHERE id=?");
                  $st->bind_param('iiiisi',$up,$ms,$players,$max,$detail,$s['id']); $st->execute(); $st->close(); } catch (\Throwable $e){}
        }
        $status = $up ? (($ms!==null && $ms>250)?'degraded':'up') : 'down';
        $item=['id'=>(int)$s['id'],'name'=>$s['name'],'game'=>$s['game'],'host'=>$s['host'],'port'=>(int)$s['port'],'proto'=>$s['proto'],
               'status'=>$status,'ms'=>$ms!==null?(int)$ms:null,'players'=>$players!==null?(int)$players:null,'max'=>$max!==null?(int)$max:null,'detail'=>$detail];
        $out[$s['kind']==='official'?'official':'custom'][]=$item;
    }
    return ['ok'=>true,'official'=>$out['official'],'custom'=>$out['custom']];
}

// ═══════════════════════════════════════════════════════════════════════════════
// OBS LIVE STREAM OVERLAY ENGINE — the unique killer feature. A tokenized PUBLIC page
// (overlay.php?token=xyz) the gamer drops into OBS/Streamlabs as a Browser Source: a
// transparent futuristic HUD (ping/GPU/CPU/net/FPS) live on stream, zero PC impact.
// The token = read-only bearer to ONE rig's cached vitals (no login cookie in OBS).
// ═══════════════════════════════════════════════════════════════════════════════
function nm_gaming_overlay_ensure($conn): void {
    try { $conn->query("CREATE TABLE IF NOT EXISTS nm_game_overlays (
        id INT AUTO_INCREMENT PRIMARY KEY, token CHAR(32) NOT NULL, rig_id INT NOT NULL,
        theme VARCHAR(24) NOT NULL DEFAULT 'synthwave', opts JSON NULL, label VARCHAR(60) NULL,
        created_by VARCHAR(60) NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_token (token), KEY k_rig (rig_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"); } catch (\Throwable $e) {}
}
// cache a rig's live payload in nm_settings so the overlay (and dashboard) don't SSH on every poll.
function nm_gaming_cache_set($conn, int $rid, string $part, $data): void {
    $key='game_cache_'.$rid; $cur=json_decode(nm_gaming_get($conn,$key,'{}'),true) ?: [];
    $cur[$part]=$data; $cur[$part.'_ts']=time();
    try { $st=$conn->prepare("INSERT INTO nm_settings (setting_key,setting_val) VALUES (?,?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)"); $v=json_encode($cur); $st->bind_param('ss',$key,$v); $st->execute(); $st->close(); } catch (\Throwable $e) {}
}
function nm_gaming_cache_get($conn, int $rid): array { return json_decode(nm_gaming_get($conn,'game_cache_'.$rid,'{}'),true) ?: []; }

function nm_gaming_overlay_create($conn, int $rid, array $opts, string $theme, ?string $by): array {
    nm_gaming_overlay_ensure($conn);
    $token = bin2hex(random_bytes(16));
    $theme = in_array($theme,['synthwave','matrix','neon','obsidian'],true)?$theme:'synthwave';
    try { $st=$conn->prepare("INSERT INTO nm_game_overlays (token,rig_id,theme,opts,created_by) VALUES (?,?,?,?,?)"); $oj=json_encode($opts); $st->bind_param('sisss',$token,$rid,$theme,$oj,$by); $st->execute(); $st->close();
          return ['ok'=>true,'token'=>$token]; } catch (\Throwable $e){ return ['ok'=>false,'error'=>'create failed']; }
}
function nm_gaming_overlay_by_token($conn, string $token): ?array {
    if (!preg_match('/^[a-f0-9]{32}$/',$token)) return null;
    try { $st=$conn->prepare("SELECT * FROM nm_game_overlays WHERE token=? LIMIT 1"); $st->bind_param('s',$token); $st->execute(); $r=$st->get_result()->fetch_assoc(); $st->close(); return $r?:null; } catch (\Throwable $e){ return null; }
}
function nm_gaming_overlays($conn): array {
    nm_gaming_overlay_ensure($conn); $out=[];
    try { $r=$conn->query("SELECT o.*, w.name rig_name FROM nm_game_overlays o LEFT JOIN nm_win_hosts w ON w.id=o.rig_id ORDER BY o.id DESC"); while($r && $x=$r->fetch_assoc()) $out[]=$x; } catch (\Throwable $e){}
    return $out;
}
function nm_gaming_overlay_del($conn, int $id): array { try { $conn->query("DELETE FROM nm_game_overlays WHERE id=".(int)$id); return ['ok'=>true]; } catch (\Throwable $e){ return ['ok'=>false]; } }

// the live data an overlay renders. Reads the rig cache; refreshes via live vitals if stale (>7s).
function nm_gaming_overlay_data($conn, string $token): array {
    $ov = nm_gaming_overlay_by_token($conn,$token); if (!$ov) return ['ok'=>false,'error'=>'invalid token'];
    $rid=(int)$ov['rig_id']; $c=nm_gaming_cache_get($conn,$rid);
    $vts=(int)($c['vitals_ts']??0);
    if (time()-$vts > 7) {
        $h = function_exists('nm_win_host') ? nm_win_host($conn,$rid) : null;
        if ($h) { $v=nm_gaming_vitals($conn,$h); nm_gaming_cache_set($conn,$rid,'vitals',$v); $c['vitals']=$v; }
    }
    $v = $c['vitals'] ?? []; $ping = $c['ping'] ?? null; $fps = $c['fps'] ?? null;
    $opts = json_decode((string)($ov['opts']??'{}'),true) ?: [];
    return ['ok'=>true,'theme'=>$ov['theme'],'opts'=>$opts,'label'=>$ov['label'],
        'game'=>$v['game']['title'] ?? null,
        'gpu'=>['util'=>$v['gpu']['util'] ?? null,'temp'=>$v['gpu']['temp'] ?? null,'throttle'=>!empty($v['gpu']['throttle']['thermal'])],
        'cpu'=>$v['sys']['cpu'] ?? null,'mem_used'=>$v['sys']['mem_used'] ?? null,'mem_total'=>$v['sys']['mem_total'] ?? null,
        'ping'=>is_array($ping)?$ping:null,'fps'=>is_array($fps)?$fps:null];
}

} // function_exists guard
