<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — PC BENCHMARK engine (nm_benchmark). "Is this PC good for gaming?" answered
// with a REAL, reproducible, scientific score.
//
// HOW IT RUNS (the key design win the user asked for):
//   The actual benchmark WORK (CPU compute loop, disk seq I/O, hardware probe) runs
//   as ONE PowerShell one-liner ON the gamer's rig via the existing agentless SSH
//   pipeline (nm_win_ps). The rig does the heavy lifting locally — your NEURU server
//   spends ~0 CPU. PowerShell returns RAW measurements; PHP then composes the verdict
//   using the SHARED universal GPU classifier (nm_gf_gpu_class) so scoring is identical
//   across every gaming feature and can be tuned server-side without re-running on the rig.
//
// SCORING (gaming-oriented, defensible): GPU is the dominant factor for whether a PC
// can actually play games, so it carries the most weight. Weights:
//     GPU 55% · CPU 22% · RAM 12% · Storage 11%
//   Each component → a 0-100 sub-score; the weighted sum is the composite (0-100), and
//   the headline "NEURU Score" = composite × 100 (0–10000, the admirable big number).
//   Tiers map the composite to a real gaming capability (resolution + FPS class).
//
// Reuses nm_winhost (SSH) + nm_gamefix (GPU classifier, PS helpers) — NO duplicated logic.
// RBAC: 'gaming'. Universal: works on ANY monitored Windows rig; hides what it can't read.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_winhost.php';
require_once __DIR__ . '/nm_gamefix.php';   // nm_gf_gpu_class(), nm_gf_ps(), _gf_wrap()
require_once __DIR__ . '/nm_audit.php';

if (!function_exists('nm_bench_run')) {

    // Tier table: composite 0-100 → real gaming meaning. Universal (resolution/FPS class).
    function nm_bench_tiers(): array {
        return [
            ['key'=>'S','min'=>90,'name'=>'Tier S — Elite','color'=>'#7CFFB2','meaning'=>'Runs anything maxed: 1440p/4K high-refresh, AAA on Ultra, competitive 240 FPS. Zero worries.'],
            ['key'=>'A','min'=>75,'name'=>'Tier A — High Performance','color'=>'#4da3ff','meaning'=>'AAA at 1440p High / 1080p Ultra, esports 144 FPS+. A serious gaming machine.'],
            ['key'=>'B','min'=>60,'name'=>'Tier B — Solid 1080p','color'=>'#39e1ff','meaning'=>'AAA at 1080p High ~60 FPS, esports at high frame-rates. Great mainstream gaming.'],
            ['key'=>'C','min'=>42,'name'=>'Tier C — Competitive / Entry','color'=>'#ffcf6b','meaning'=>'AAA at 1080p Medium, esports smooth. Tune settings and it plays almost everything.'],
            ['key'=>'D','min'=>0, 'name'=>'Tier D — Casual / iGPU','color'=>'#ff7a9c','meaning'=>'Esports & light titles at 1080p Low. Not built for heavy AAA — a discrete GPU changes everything.'],
        ];
    }
    function nm_bench_tier_for(int $c): array {
        foreach (nm_bench_tiers() as $t) if ($c >= $t['min']) return $t;
        return nm_bench_tiers()[4];
    }

    // The PowerShell body (single line, SINGLE quotes only — nm_win_ps wraps in cmd "…").
    // Measures locally and returns RAW numbers; _gf_wrap adds $o=@{} + ConvertTo-Json.
    function nm_bench_ps(): string {
        $b  = '';
        // 1) CPU single-thread compute: fixed 4M float workload timed with a Stopwatch (ms).
        $b .= '$sw=[System.Diagnostics.Stopwatch]::StartNew(); $acc=0.0; for($i=1;$i -lt 4000000;$i++){ $acc+=[Math]::Sqrt($i)*1.0000001 }; $sw.Stop(); $o.cpu_ms=[math]::Round($sw.Elapsed.TotalMilliseconds,1); ';
        // 2) CPU hardware.
        $b .= '$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1; $o.cpu_name=[string]$cpu.Name; $o.cores=[int]$cpu.NumberOfCores; $o.threads=[int]$cpu.NumberOfLogicalProcessors; $o.cpu_mhz=[int]$cpu.MaxClockSpeed; ';
        // 3) GPU + real VRAM (AdapterRAM is UINT32/caps at 4GB → read qwMemorySize from the registry).
        $b .= '$gpu=Get-CimInstance Win32_VideoController | Sort-Object AdapterRAM -Descending | Select-Object -First 1; $vram=0; $gk=\'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\'; Get-ChildItem $gk -ErrorAction SilentlyContinue | ForEach-Object { $q=(Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).\'HardwareInformation.qwMemorySize\'; if($q -and $q -gt $vram){ $vram=$q } }; $o.gpu_name=[string]$gpu.Name; $o.vram=$(if($vram){[math]::Round($vram/1GB,1)}else{[math]::Round([double]$gpu.AdapterRAM/1GB,1)}); $o.res=([string]$gpu.CurrentHorizontalResolution+\'x\'+[string]$gpu.CurrentVerticalResolution); $o.refresh=[int]$gpu.CurrentRefreshRate; ';
        // 4) RAM capacity + fastest module speed + stick count.
        $b .= '$mem=Get-CimInstance Win32_PhysicalMemory; $o.ram_gb=[math]::Round((($mem | Measure-Object Capacity -Sum).Sum)/1GB,0); $o.ram_mhz=[int](($mem | Measure-Object -Property Speed -Maximum).Maximum); $o.ram_sticks=[int]($mem | Measure-Object).Count; ';
        // 5) Storage: test EVERY fixed drive (a gamer may keep games on a 2nd disk). Real speed via
        //    a 48MB WriteThrough write (bypasses the OS cache) + auto-detect which drives hold games
        //    (Steam / Epic / Games folders). Cap at 4 drives so many-disk rigs stay fast.
        $b .= '$disks=@(); $cnt=0; foreach($v in (Get-CimInstance Win32_LogicalDisk -Filter \'DriveType=3\')){ if($cnt -ge 4){break}; try{ if([double]$v.FreeSpace -lt 200MB){continue}; $dl=[string]$v.DeviceID; $p=$dl+\'\\neuru_bench.tmp\'; $bb=New-Object byte[] (50331648); (New-Object Random).NextBytes($bb); $fs=[System.IO.File]::Create($p,4194304,[System.IO.FileOptions]::WriteThrough); $swx=[System.Diagnostics.Stopwatch]::StartNew(); $fs.Write($bb,0,$bb.Length); $fs.Flush($true); $swx.Stop(); $fs.Close(); Remove-Item $p -ErrorAction SilentlyContinue; $mb=[math]::Round(48/[math]::Max(0.001,$swx.Elapsed.TotalSeconds),0); $gm=$false; foreach($sfx in @(\'SteamLibrary\',\'Program Files (x86)\\Steam\\steamapps\',\'Program Files\\Epic Games\',\'Epic Games\',\'Games\',\'SteamLibrary\\steamapps\')){ if(Test-Path ($dl+\'\\\'+$sfx)){ $gm=$true; break } }; $disks+=@{letter=$dl; write=$mb; size=[math]::Round([double]$v.Size/1GB,0); free=[math]::Round([double]$v.FreeSpace/1GB,0); games=$gm}; $cnt++ }catch{} }; $o.disks=$disks; ';
        // physical media/bus (reliable SSD/HDD/NVMe labels), independent of the speed test
        $b .= '$phys=@(); Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object { $phys+=@{model=[string]$_.FriendlyName; media=[string]$_.MediaType; bus=[string]$_.BusType; size=[math]::Round([double]$_.Size/1GB,0)} }; $o.phys=$phys; ';
        // 6) OS.
        $b .= '$os=Get-CimInstance Win32_OperatingSystem; $o.os=[string]$os.Caption';
        return _gf_wrap($b);
    }

    // clamp helper
    function _bn_cl($v,$lo=0,$hi=100){ return max($lo,min($hi,$v)); }

    // Run the benchmark on $ssh and compose the full scored verdict.
    function nm_bench_run($conn, $ssh): array {
        $d = nm_gf_ps($ssh, nm_bench_ps(), 70);
        if (isset($d['_err']))  return ['ok'=>false,'error'=>'Could not reach the rig over SSH: '.substr((string)$d['_err'],0,240)];
        if (!isset($d['cpu_ms'])) return ['ok'=>false,'error'=>'The benchmark returned no data'.(isset($d['_raw'])?': '.substr((string)$d['_raw'],0,240):'. The rig may block PowerShell or the temp folder.')];

        // ── raw measurements ──
        $cpuMs  = max(1.0,(float)($d['cpu_ms'] ?? 9999));
        $threads= (int)($d['threads'] ?? 0);
        $cores  = (int)($d['cores'] ?? 0);
        $cpuMhz = (int)($d['cpu_mhz'] ?? 0);
        $ramGb  = (int)round((float)($d['ram_gb'] ?? 0));
        $ramMhz = (int)($d['ram_mhz'] ?? 0);
        $disks  = is_array($d['disks'] ?? null) ? array_values($d['disks']) : [];
        $phys   = is_array($d['phys']  ?? null) ? array_values($d['phys'])  : [];
        $gpuName= (string)($d['gpu_name'] ?? '');
        $vram   = (float)($d['vram'] ?? 0);
        $res    = (string)($d['res'] ?? '1920x1080'); if ($res==='x'||$res==='') $res='1920x1080';
        $refresh= (int)($d['refresh'] ?? 60);

        // ── GPU (shared universal classifier) ──
        $gc = nm_gf_gpu_class($gpuName, $vram);
        $gpuScore = (int)$gc['capability'];

        // ── CPU: single-thread index (from the timed loop) blended with core/thread count ──
        // The 4M-op loop is interpreter-bound, so we score it by THROUGHPUT (iterations/sec),
        // which still tracks single-thread performance. Windows PowerShell 5.1 reference:
        // a fast modern core ≈ 1.1–1.3M ips (100), a weak/old core ≈ 0.35–0.5M ips (~20).
        $ips = 4000000000.0 / max(1.0, $cpuMs);                 // = 4e6 iters ÷ (cpu_ms/1000)
        $st  = (int)_bn_cl(round(($ips - 300000) / 9500), 8, 100);  // 300k→~0 · 1.25M→100
        $cn  = $threads>=24?100:($threads>=16?92:($threads>=12?82:($threads>=8?68:($threads>=6?54:($threads>=4?40:($threads>=2?26:20))))));
        $cpuScore = (int)round(0.62*$st + 0.38*$cn);

        // ── RAM: capacity (dominant for gaming) + module speed ──
        $cap = $ramGb>=32?100:($ramGb>=16?80:($ramGb>=12?62:($ramGb>=8?45:($ramGb>=4?25:($ramGb>0?12:0)))));
        $spd = $ramMhz>=6000?100:($ramMhz>=4800?92:($ramMhz>=3600?86:($ramMhz>=3200?76:($ramMhz>=2666?62:($ramMhz>=2133?48:($ramMhz>0?38:62))))));
        $ramScore = (int)round(0.62*$cap + 0.38*$spd);

        // ── Storage: score the drive the GAMES live on (auto-detected), not just C: ──
        // Media is inferred from the real WriteThrough speed: NVMe ≥1500 · SATA-SSD ≥200 · HDD <200.
        $mediaOf = function(int $w): string { return $w>=1500 ? 'NVMe SSD' : ($w>=200 ? 'SATA SSD' : 'Hard drive (HDD)'); };
        $scoreOf = function(int $w): int { return (int)($w>=3000?100:($w>=1500?92:($w>=500?76:($w>=200?66:($w>=120?40:24))))); };
        // pick the gaming drive: one that HAS games → else fastest drive with ≥50GB free → else fastest
        $gameDrive=null;
        foreach ($disks as $dk) if (!empty($dk['games'])) { $gameDrive=$dk; break; }
        if (!$gameDrive) { $best=null; foreach ($disks as $dk) { if ((int)($dk['free']??0)>=50 && (!$best || (int)($dk['write']??0)>(int)($best['write']??0))) $best=$dk; } if(!$best) foreach ($disks as $dk){ if(!$best || (int)($dk['write']??0)>(int)($best['write']??0)) $best=$dk; } $gameDrive=$best; }
        $gw = (int)($gameDrive['write'] ?? 0);
        $diskKind  = $gameDrive ? $mediaOf($gw) : 'SSD';
        $diskScore = $gameDrive ? (int)_bn_cl($scoreOf($gw)) : 60;
        // fastest drive available (for "move your games here" advice) + any HDD present
        $fastest=null; foreach ($disks as $dk){ if(!$fastest || (int)($dk['write']??0)>(int)($fastest['write']??0)) $fastest=$dk; }
        $gamesOnHdd = $gameDrive && $gw>0 && $gw<200;
        $hasFasterSsd = $fastest && (int)($fastest['write']??0)>=200 && ($fastest['letter']??'')!==($gameDrive['letter']??'');
        // human summary of every drive
        $driveList = array_map(fn($dk)=>($dk['letter']??'?').' '.($mediaOf((int)($dk['write']??0))).' '.(int)($dk['write']??0).' MB/s'.(!empty($dk['games'])?' 🎮games':'').' ('.(int)($dk['free']??0).'/'.(int)($dk['size']??0).' GB free)', $disks);
        $physList  = array_map(fn($p)=>trim((string)($p['media']??'?').' '.(string)($p['bus']??'').' '.mb_substr((string)($p['model']??''),0,24)), $phys);

        // ── composite + headline ──
        $composite = (int)round($gpuScore*0.55 + $cpuScore*0.22 + $ramScore*0.12 + $diskScore*0.11);
        $composite = (int)_bn_cl($composite);
        $neuru     = $composite*100;
        $tier      = nm_bench_tier_for($composite);

        // ── expected in-game FPS at the panel's native resolution ──
        $mult = 1.0; if (strpos($res,'2560')!==false) $mult=0.68; elseif (strpos($res,'3840')!==false) $mult=0.42;
        $fpsAvg = (int)round($gc['fps_base']*$mult);
        $fpsLow = (int)round($fpsAvg*0.82);

        // ── bottleneck analysis ──
        if      ($gpuScore-$cpuScore >= 25) $bottleneck=['type'=>'cpu','label'=>'CPU-limited at low res','msg'=>'Your CPU can\'t fully feed this GPU at 1080p — in CPU-heavy games the GPU will sit below 99% usage. It evens out at 1440p/4K where the GPU carries more of the load. Closing background apps helps.'];
        elseif  ($cpuScore-$gpuScore >= 28) $bottleneck=['type'=>'gpu','label'=>'GPU-limited (normal)','msg'=>'The GPU is the limiting part — which is normal and healthy for gaming. A GPU upgrade would buy the most extra FPS here.'];
        else                                $bottleneck=['type'=>'balanced','label'=>'Well balanced','msg'=>'CPU and GPU are well matched — no obvious bottleneck. This rig converts its parts into frames efficiently.'];

        // ── per-component findings: novice ("mean") + expert ("data"), with actions ──
        $st_of = fn($s)=>$s>=75?'ok':($s>=50?'warn':'crit');
        $components = [
            ['key'=>'gpu','name'=>'Graphics (GPU)','icon'=>'fa-tv','score'=>$gpuScore,'weight'=>55,
             'value'=>($gpuName?:'Unknown GPU').' · '.($vram?:'?').' GB VRAM',
             'mean'=>'The single biggest factor in whether a PC can play games. It draws every frame — a stronger GPU = higher settings and more FPS.',
             'data'=>$gc['class'].' class ('.$gc['vendor'].'), '.$gc['verdict'].'. '.$gc['examples']],
            ['key'=>'cpu','name'=>'Processor (CPU)','icon'=>'fa-microchip','score'=>$cpuScore,'weight'=>22,
             'value'=>trim(($d['cpu_name']?:'CPU').' — '.($cores?:'?').' cores / '.($threads?:'?').' threads'.($cpuMhz?' · '.round($cpuMhz/1000,1).' GHz':'')),
             'mean'=>'Feeds the GPU with work and runs game logic, physics & AI. A weak CPU caps your FPS even with a great GPU, especially at 1080p.',
             'data'=>'Single-thread index '.$st.'/100 (~'.round($ips/1000000,2).'M ops/s in the compute test) · multi-core index '.$cn.'/100 from '.($threads?:'?').' threads.'],
            ['key'=>'ram','name'=>'Memory (RAM)','icon'=>'fa-memory','score'=>$ramScore,'weight'=>12,
             'value'=>($ramGb?:'?').' GB'.($ramMhz?' @ '.$ramMhz.' MHz':'').(($d['ram_sticks']??0)>1?' · '.$d['ram_sticks'].' sticks (dual-channel)':' · single stick'),
             'mean'=>'Holds the game and textures while you play. Too little RAM causes stutters and long loads; dual-channel and speed add smoothness.',
             'data'=>'Capacity index '.$cap.'/100 ('.($ramGb?:'?').' GB) · speed index '.$spd.'/100 ('.($ramMhz?($ramMhz.' MHz'):'speed unreported').').'],
            ['key'=>'disk','name'=>'Storage','icon'=>'fa-hard-drive','score'=>$diskScore,'weight'=>11,
             'value'=>($gameDrive?('Games drive '.($gameDrive['letter']??'?').' — '.$diskKind.' · '.$gw.' MB/s'):'No drive tested').' · '.count($disks).' drive'.(count($disks)===1?'':'s').' tested',
             'mean'=>'Where games load from. It doesn\'t change your FPS, but a fast SSD slashes load screens and stops textures popping in mid-game. NEURU tests EVERY drive and scores the one your games live on.',
             'data'=>'All fixed drives (real WriteThrough speed): '.($driveList?implode(' · ',$driveList):'none detected').'.'.($physList?' Physical: '.implode(' · ',$physList).'.':'')],
        ];
        foreach ($components as &$c) $c['status']=$st_of($c['score']); unset($c);

        // ── headline findings (ranked, actionable) ──
        $findings = [];
        $findings[] = ['icon'=>'🎮','title'=>$tier['name'],'status'=>$composite>=75?'ok':($composite>=42?'warn':'crit'),
            'mean'=>$tier['meaning'],
            'data'=>'NEURU Score '.number_format($neuru).' / 10,000 (composite '.$composite.'/100). At '.$res.' expect ~'.$fpsAvg.' FPS average, ~'.$fpsLow.' FPS 1% low in a typical AAA title.'];
        // GPU-driven advice
        if ($gc['igpu'])            $findings[] = ['icon'=>'⚠️','title'=>'Integrated graphics','status'=>'warn','mean'=>'This PC uses the CPU\'s built-in graphics — great for esports and light games, but heavy AAA needs a dedicated GPU.','data'=>$gc['examples'],'tool'=>'Game Lab','url'=>'game_lab.php'];
        elseif ($gpuScore<50)       $findings[] = ['icon'=>'📉','title'=>'GPU is the weak link','status'=>'warn','mean'=>'The graphics card is what holds this rig back. Lowering settings or using upscaling (DLSS/FSR) recovers a lot of FPS.','data'=>$gc['class'].' — '.$gc['verdict'].'.','tool'=>'Game Lab','url'=>'game_lab.php'];
        if ($vram>0 && $vram<8 && !$gc['igpu']) $findings[] = ['icon'=>'🧠','title'=>'Limited VRAM','status'=>'warn','mean'=>'Only '.$vram.' GB of video memory — modern AAA at high textures can exceed this and stutter. Drop textures one notch if you see hitching.','data'=>'8 GB is the comfortable modern minimum; 12 GB+ for 1440p Ultra.'];
        // CPU
        if ($cpuScore<50)           $findings[] = ['icon'=>'🐢','title'=>'CPU may cap frame-rates','status'=>'warn','mean'=>'A slower processor can limit FPS in busy scenes even with a good GPU. Closing background apps and enabling the game\'s performance mode helps.','data'=>'Single-thread index '.$st.'/100 · '.($threads?:'?').' threads.','tool'=>'Game Lab','url'=>'game_lab.php'];
        // RAM
        if ($ramGb>0 && $ramGb<16)  $findings[] = ['icon'=>'📥','title'=>'16 GB is the gaming floor','status'=>'warn','mean'=>'You have '.$ramGb.' GB. Modern games expect 16 GB — below that you\'ll get stutters and long loads. Adding a matching stick also unlocks faster dual-channel.','data'=>'Capacity index '.$cap.'/100.'];
        elseif (($d['ram_sticks']??2)<2 && $ramGb>=16) $findings[]=['icon'=>'🔀','title'=>'Single-stick RAM','status'=>'warn','mean'=>'Your RAM is one stick, so it runs in single-channel — adding a matching second stick can add real FPS for free.','data'=>'Dual-channel roughly doubles memory bandwidth to the GPU/CPU.'];
        // storage (multi-disk aware: where are the games, and is that drive fast?)
        if ($gamesOnHdd && $hasFasterSsd) {
            $findings[] = ['icon'=>'💽','title'=>'Move your games to the SSD','status'=>'warn','mean'=>'Your games are on '.($gameDrive['letter']??'?').', a mechanical hard drive ('.$gw.' MB/s), but you have a faster SSD at '.($fastest['letter']??'?').' ('.(int)($fastest['write']??0).' MB/s). Moving your game library there is the single most-noticeable upgrade — far shorter loads and no texture pop-in.','data'=>'Games detected on '.($gameDrive['letter']??'?').'. Fastest drive: '.($fastest['letter']??'?').' with '.(int)($fastest['free']??0).' GB free.'];
        } elseif ($gamesOnHdd) {
            $findings[] = ['icon'=>'💽','title'=>'Games on a hard drive','status'=>'warn','mean'=>'Your games live on a mechanical HDD ('.$gw.' MB/s) — that means long load screens and textures popping in as you move. Adding an SSD and moving your library there transforms load times.','data'=>'Games drive '.($gameDrive['letter']??'?').' measured '.$gw.' MB/s — an NVMe SSD is 10-20× faster.'];
        } elseif (count($disks)>1) {
            $findings[] = ['icon'=>'💾','title'=>'Storage looks good','status'=>'ok','mean'=>'NEURU tested all '.count($disks).' of your drives. Your games are on '.($diskKind).' — fast enough for quick loads and smooth texture streaming.','data'=>'Games drive '.($gameDrive['letter']??'?').': '.$gw.' MB/s ('.$diskKind.').'];
        }
        // thermals note (benchmark doesn't load the GPU long enough to measure heat)
        $findings[] = ['icon'=>'🌡️','title'=>'Check thermals under load','status'=>'ok','mean'=>'This score measures capability, not heat. If frames drop after 10-15 min of play, the rig is thermal-throttling — a better fan curve fixes it.','data'=>'Sustained clocks depend on cooling; a hot GPU quietly steals FPS.','tool'=>'Fan Profiler','url'=>'fan_profiler.php'];
        // bottleneck as a finding too
        $findings[] = ['icon'=>$bottleneck['type']==='balanced'?'⚖️':'🔗','title'=>'Balance: '.$bottleneck['label'],'status'=>$bottleneck['type']==='balanced'?'ok':'warn','mean'=>$bottleneck['msg'],'data'=>'GPU '.$gpuScore.'/100 vs CPU '.$cpuScore.'/100.'];

        log_user_action($conn,'benchmark_run',$gc['class'].' score='.$neuru);
        return [
            'ok'=>true,
            'neuru_score'=>$neuru,'composite'=>$composite,
            'tier'=>['key'=>$tier['key'],'name'=>$tier['name'],'color'=>$tier['color'],'meaning'=>$tier['meaning']],
            'components'=>$components,
            'findings'=>$findings,
            'bottleneck'=>$bottleneck,
            'fps'=>['avg'=>$fpsAvg,'low1'=>$fpsLow,'res'=>$res,'refresh'=>$refresh],
            'hardware'=>['gpu'=>$gpuName,'vram'=>$vram,'cpu'=>$d['cpu_name']??'','ram_gb'=>$ramGb,'disk'=>$diskKind,'os'=>$d['os']??'','res'=>$res,'refresh'=>$refresh],
            'gpu_class'=>$gc,
        ];
    }

    // ── Persistence: save every run so a gamer can compare BEFORE vs AFTER optimizing ──
    function nm_bench_ensure($conn): void {
        // CREATE ... IF NOT EXISTS is safe under mysqli exception mode (no-op if present).
        try {
            $conn->query("CREATE TABLE IF NOT EXISTS nm_bench_runs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                host_id INT NOT NULL,
                neuru_score INT NOT NULL DEFAULT 0,
                composite INT NOT NULL DEFAULT 0,
                tier_key VARCHAR(4) NOT NULL DEFAULT '',
                gpu_score INT NOT NULL DEFAULT 0,
                cpu_score INT NOT NULL DEFAULT 0,
                ram_score INT NOT NULL DEFAULT 0,
                disk_score INT NOT NULL DEFAULT 0,
                fps_avg INT NOT NULL DEFAULT 0,
                note VARCHAR(120) NOT NULL DEFAULT '',
                payload MEDIUMTEXT,
                created_at DATETIME NOT NULL,
                KEY host_created (host_id, id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        } catch (\Throwable $e) {}
    }
    function _bn_sub(array $r, string $k): int {
        foreach ($r['components'] ?? [] as $c) if (($c['key'] ?? '') === $k) return (int)($c['score'] ?? 0);
        return 0;
    }
    function nm_bench_save($conn, int $hid, array $r, string $note=''): int {
        if (empty($r['ok'])) return 0;
        nm_bench_ensure($conn);
        $note = mb_substr(trim($note), 0, 120);
        try {
            $ns=(int)$r['neuru_score']; $cp=(int)$r['composite']; $tk=(string)($r['tier']['key']??'');
            $g=_bn_sub($r,'gpu'); $c=_bn_sub($r,'cpu'); $rm=_bn_sub($r,'ram'); $dk=_bn_sub($r,'disk');
            $fa=(int)($r['fps']['avg']??0); $pl=json_encode($r);
            $st=$conn->prepare("INSERT INTO nm_bench_runs (host_id,neuru_score,composite,tier_key,gpu_score,cpu_score,ram_score,disk_score,fps_avg,note,payload,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,NOW())");
            $st->bind_param('iiisiiiiiss',$hid,$ns,$cp,$tk,$g,$c,$rm,$dk,$fa,$note,$pl);
            $st->execute(); $id=(int)$st->insert_id; $st->close(); return $id;
        } catch (\Throwable $e) { return 0; }
    }
    function nm_bench_history($conn, int $hid, int $limit=30): array {
        nm_bench_ensure($conn); $out=[];
        try {
            $st=$conn->prepare("SELECT id,neuru_score,composite,tier_key,gpu_score,cpu_score,ram_score,disk_score,fps_avg,note,created_at FROM nm_bench_runs WHERE host_id=? ORDER BY id DESC LIMIT ?");
            $st->bind_param('ii',$hid,$limit); $st->execute(); $rs=$st->get_result();
            while ($x=$rs->fetch_assoc()) { foreach(['id','neuru_score','composite','gpu_score','cpu_score','ram_score','disk_score','fps_avg'] as $k) $x[$k]=(int)$x[$k]; $out[]=$x; }
            $st->close();
        } catch (\Throwable $e) {}
        return $out;
    }
    function nm_bench_label($conn, int $hid, int $id, string $note): bool {
        nm_bench_ensure($conn);
        try { $note=mb_substr(trim($note),0,120); $st=$conn->prepare("UPDATE nm_bench_runs SET note=? WHERE id=? AND host_id=?"); $st->bind_param('sii',$note,$id,$hid); $st->execute(); $st->close(); return true; } catch (\Throwable $e) { return false; }
    }
    function nm_bench_delete($conn, int $hid, int $id): bool {
        nm_bench_ensure($conn);
        try { $st=$conn->prepare("DELETE FROM nm_bench_runs WHERE id=? AND host_id=?"); $st->bind_param('ii',$id,$hid); $st->execute(); $st->close(); return true; } catch (\Throwable $e) { return false; }
    }
    // Delta between two history rows (before → after). Positive = improvement.
    function nm_bench_compare(array $prev, array $cur): array {
        $d=fn($k)=>(int)($cur[$k]??0)-(int)($prev[$k]??0);
        return ['score'=>$d('neuru_score'),'composite'=>$d('composite'),
                'gpu'=>$d('gpu_score'),'cpu'=>$d('cpu_score'),'ram'=>$d('ram_score'),'disk'=>$d('disk_score'),'fps'=>$d('fps_avg'),
                'prev'=>['id'=>(int)($prev['id']??0),'note'=>(string)($prev['note']??''),'score'=>(int)($prev['neuru_score']??0),'when'=>(string)($prev['created_at']??'')]];
    }
}
