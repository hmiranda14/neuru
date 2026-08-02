<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — HARDWARE LONGEVITY engine (nm_wearlife). A cumulative "Hardware Health
// Passport" for a gamer's rig: it doesn't guess — it ACCUMULATES real agentless
// telemetry over time and projects wear/lifespan. Four subsystems, all from REAL
// sensors (no fabricated %):
//   1. SSD/NVMe NAND endurance  ← SMART Wear% + power-on hours (Get-StorageReliabilityCounter)
//   2. Thermal stress (GPU/CPU) ← accumulated hours in hot zones (LHM temps)
//   3. Power-delivery / VRM     ← accumulated hours at sustained 95%+ load (LHM loads)
//   4. Fan bearing wear         ← accumulated hours at high RPM + nominal-RPM drift (LHM fans)
// Where a value is directly measured (SSD Wear%) → a real projection. Where wear can't
// be measured (silicon/VRM/bearings) → an EXPOSURE advisory, honestly labelled an estimate.
//
// Reuses nm_gaming_sensors (LHM/OHM over SSH) + nm_gf_gpu_class + nm_winhost. RBAC 'gaming'.
// Universal: degrades per available sensor; works NVIDIA/AMD/Intel + any SSD/fans.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_winhost.php';
require_once __DIR__ . '/nm_gaming.php';    // nm_gaming_sensors()
require_once __DIR__ . '/nm_gamefix.php';   // nm_gf_gpu_class(), nm_gf_ps(), _gf_wrap()

if (!function_exists('nm_wl_passport')) {

    function nm_wl_ensure($conn): void {
        try {
            $conn->query("CREATE TABLE IF NOT EXISTS nm_hw_wear (
                host_id INT PRIMARY KEY,
                sample_sec BIGINT NOT NULL DEFAULT 0,
                gpu_hot_sec BIGINT NOT NULL DEFAULT 0,
                gpu_warm_sec BIGINT NOT NULL DEFAULT 0,
                cpu_hot_sec BIGINT NOT NULL DEFAULT 0,
                load_high_sec BIGINT NOT NULL DEFAULT 0,
                fan_high_sec BIGINT NOT NULL DEFAULT 0,
                gpu_name VARCHAR(120) DEFAULT '', gpu_vram_gb FLOAT DEFAULT 0,
                gpu_temp_last FLOAT DEFAULT NULL, gpu_temp_max FLOAT DEFAULT 0,
                cpu_temp_last FLOAT DEFAULT NULL, cpu_temp_max FLOAT DEFAULT 0,
                fan_rpm_last INT DEFAULT NULL, fan_rpm_max INT DEFAULT 0, fan_nominal_rpm INT DEFAULT 0,
                ssd_model VARCHAR(120) DEFAULT '', ssd_media VARCHAR(24) DEFAULT '', ssd_size_gb INT DEFAULT 0,
                ssd_wear FLOAT DEFAULT NULL, ssd_temp INT DEFAULT NULL, ssd_poweron_hrs INT DEFAULT NULL,
                ssd_wear_first FLOAT DEFAULT NULL, ssd_first_at DATETIME DEFAULT NULL,
                disks_json MEDIUMTEXT, specs_json MEDIUMTEXT,
                first_seen DATETIME DEFAULT NULL, updated_at DATETIME DEFAULT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
            // guarded: existing installs get specs_json (full spec sheet for the passport)
            $c=$conn->query("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_hw_wear' AND COLUMN_NAME='specs_json' LIMIT 1");
            if ($c && $c->num_rows===0) { try{ $conn->query("ALTER TABLE nm_hw_wear ADD COLUMN specs_json MEDIUMTEXT"); }catch(\Throwable $e){} }
        } catch (\Throwable $e) {}
    }

    // ── read the SSD/NVMe SMART reliability counters (the real NAND-endurance signal) ──
    function nm_wl_smart($ssh): array {
        $body =
          '$disks=@(); Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object { $pd=$_; $rc=$null; try{ $rc=$pd | Get-StorageReliabilityCounter -ErrorAction Stop }catch{}; '
        . '$disks += @{ model=[string]$pd.FriendlyName; media=[string]$pd.MediaType; bus=[string]$pd.BusType; size_gb=[math]::Round([double]$pd.Size/1GB,0); '
        . 'wear=$(if($rc -and $rc.Wear -ne $null){[int]$rc.Wear}else{$null}); temp=$(if($rc -and $rc.Temperature){[int]$rc.Temperature}else{$null}); '
        . 'poweron=$(if($rc -and $rc.PowerOnHours){[int]$rc.PowerOnHours}else{$null}); readerr=$(if($rc){[int64]$rc.ReadErrorsTotal}else{$null}); writeerr=$(if($rc){[int64]$rc.WriteErrorsTotal}else{$null}) } }; $o.disks=$disks';
        $d = nm_gf_ps($ssh, _gf_wrap($body), 30);
        return is_array($d['disks'] ?? null) ? array_values($d['disks']) : [];
    }

    // ── comprehensive spec sheet: GPU + motherboard + BIOS + CPU + RAM + system + OS (one call) ──
    function nm_wl_gpu($ssh): array {
        $body =
          '$g=Get-CimInstance Win32_VideoController | Sort-Object AdapterRAM -Descending | Select-Object -First 1; $vram=0; '
        . '$gk=\'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\'; '
        . 'Get-ChildItem $gk -ErrorAction SilentlyContinue | ForEach-Object { $q=(Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).\'HardwareInformation.qwMemorySize\'; if($q -and $q -gt $vram){ $vram=$q } }; '
        . '$o.name=[string]$g.Name; $o.vram=$(if($vram){[math]::Round($vram/1GB,1)}else{[math]::Round([double]$g.AdapterRAM/1GB,1)}); '
        . '$scr=Get-CimInstance Win32_VideoController | Select-Object -First 1; $o.res=([string]$scr.CurrentHorizontalResolution+\'x\'+[string]$scr.CurrentVerticalResolution); $o.refresh=[int]$scr.CurrentRefreshRate; '
        . '$mb=Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object -First 1; $o.mb_brand=[string]$mb.Manufacturer; $o.mb_model=[string]$mb.Product; $o.mb_ver=[string]$mb.Version; '
        . '$bios=Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -First 1; $o.bios_ver=[string]$bios.SMBIOSBIOSVersion; $o.bios_date=[string]$bios.ReleaseDate; '
        . '$cpu=Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1; $o.cpu_name=[string]$cpu.Name; $o.cpu_cores=[int]$cpu.NumberOfCores; $o.cpu_threads=[int]$cpu.NumberOfLogicalProcessors; $o.cpu_ghz=[math]::Round([double]$cpu.MaxClockSpeed/1000,2); '
        . '$mem=Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue; $o.ram_gb=[math]::Round((($mem | Measure-Object Capacity -Sum).Sum)/1GB,0); $o.ram_mhz=[int](($mem | Measure-Object -Property Speed -Maximum).Maximum); $o.ram_sticks=[int]($mem | Measure-Object).Count; $o.ram_type=[int](@($mem)[0].SMBIOSMemoryType); '
        . '$cs=Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object -First 1; $o.sys_brand=[string]$cs.Manufacturer; $o.sys_model=[string]$cs.Model; '
        . '$os=Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object -First 1; $o.os=[string]$os.Caption; $o.os_ver=[string]$os.Version';
        $d = nm_gf_ps($ssh, _gf_wrap($body), 25);
        $ddr = ['20'=>'DDR','21'=>'DDR2','24'=>'DDR3','26'=>'DDR4','34'=>'DDR5','35'=>'DDR5'];
        return ['name'=>(string)($d['name'] ?? ''), 'vram'=>(float)($d['vram'] ?? 0),
                'res'=>(string)($d['res'] ?? ''), 'refresh'=>(int)($d['refresh'] ?? 0),
                'mb_brand'=>(string)($d['mb_brand'] ?? ''), 'mb_model'=>(string)($d['mb_model'] ?? ''), 'mb_ver'=>(string)($d['mb_ver'] ?? ''),
                'bios_ver'=>(string)($d['bios_ver'] ?? ''), 'bios_date'=>substr((string)($d['bios_date'] ?? ''),0,8),
                'cpu_name'=>(string)($d['cpu_name'] ?? ''), 'cpu_cores'=>(int)($d['cpu_cores'] ?? 0), 'cpu_threads'=>(int)($d['cpu_threads'] ?? 0), 'cpu_ghz'=>(float)($d['cpu_ghz'] ?? 0),
                'ram_gb'=>(int)($d['ram_gb'] ?? 0), 'ram_mhz'=>(int)($d['ram_mhz'] ?? 0), 'ram_sticks'=>(int)($d['ram_sticks'] ?? 0), 'ram_type'=>$ddr[(string)($d['ram_type'] ?? '')] ?? '',
                'sys_brand'=>(string)($d['sys_brand'] ?? ''), 'sys_model'=>(string)($d['sys_model'] ?? ''),
                'os'=>(string)($d['os'] ?? ''), 'os_ver'=>(string)($d['os_ver'] ?? '')];
    }

    // pull the hottest GPU/CPU temp, max fan RPM, and peak GPU/CPU load out of an LHM sensor dump
    function _nm_wl_extract(array $sensors): array {
        $out = ['gpu_temp'=>null,'cpu_temp'=>null,'fan_max'=>null,'fan_count'=>0,'gpu_load'=>null,'cpu_load'=>null];
        $isGpu = fn($h)=>(bool)preg_match('/gpu|nvidia|radeon|geforce|\brtx\b|\bgtx\b|intel.*graphics|iris/i',$h);
        $isCpu = fn($h)=>(bool)preg_match('/cpu|core|ryzen|processor|intel\(r\) core/i',$h) && !preg_match('/gpu|graphics/i',$h);
        foreach (($sensors['temps'] ?? []) as $t) {
            $n=strtolower((string)($t['name']??'')); $hw=strtolower((string)($t['hw']??'')); $v=(float)($t['val']??0);
            if ($v<=0 || $v>150) continue;
            if (preg_match('/tjmax|distance|limit|warning|critical/',$n)) continue;   // skip thresholds
            $ctx=$hw.' '.$n;
            if ($isGpu($ctx)) { if ($out['gpu_temp']===null || $v>$out['gpu_temp']) $out['gpu_temp']=$v; }
            elseif ($isCpu($ctx)) { if ($out['cpu_temp']===null || $v>$out['cpu_temp']) $out['cpu_temp']=$v; }
        }
        foreach (($sensors['fans'] ?? []) as $f) { $v=(int)($f['val']??0); if ($v>0){ $out['fan_count']++; if ($out['fan_max']===null||$v>$out['fan_max']) $out['fan_max']=$v; } }
        foreach (($sensors['loads'] ?? []) as $l) {
            $n=strtolower((string)($l['name']??'')); $hw=strtolower((string)($l['hw']??'')); $v=(float)($l['val']??0); $ctx=$hw.' '.$n;
            if ($isGpu($ctx) && preg_match('/core|gpu|d3d|total/',$n)) { if ($out['gpu_load']===null||$v>$out['gpu_load']) $out['gpu_load']=$v; }
            elseif ($isCpu($ctx) && preg_match('/total|cpu/',$n)) { if ($out['cpu_load']===null||$v>$out['cpu_load']) $out['cpu_load']=$v; }
        }
        return $out;
    }

    // ONE probe = sensors (temps/fans/loads) + SSD SMART + GPU id. Returns a normalized snapshot.
    function nm_wl_probe($conn, $ssh): array {
        $sensors = function_exists('nm_gaming_sensors') ? nm_gaming_sensors($ssh) : ['ok'=>false];
        if (empty($sensors['ok'])) {
            // no LHM → we can still do SSD SMART + GPU id (thermal/fan just won't accumulate)
            $ex = ['gpu_temp'=>null,'cpu_temp'=>null,'fan_max'=>null,'fan_count'=>0,'gpu_load'=>null,'cpu_load'=>null];
            $sensorsOk = false;
        } else { $ex = _nm_wl_extract($sensors); $sensorsOk = true; }
        $gpu   = nm_wl_gpu($ssh);
        $disks = nm_wl_smart($ssh);
        return ['ok'=>true,'sensors_ok'=>$sensorsOk,'src'=>$sensors['src']??null,'gpu'=>$gpu,'disks'=>$disks] + $ex;
    }

    // fold one probe into the running accumulation (dt = time since last sample, capped so a cron
    // gap or a reboot can't inject a huge fake block of "hot hours").
    function nm_wl_accumulate($conn, int $hid, array $p): void {
        nm_wl_ensure($conn);
        $now = gmdate('Y-m-d H:i:s');
        $row = null; try { $r=$conn->query("SELECT * FROM nm_hw_wear WHERE host_id=$hid"); $row=$r?$r->fetch_assoc():null; } catch (\Throwable $e) {}
        $dt = 0;
        if ($row && !empty($row['updated_at'])) { $dt = max(0, min(600, time() - strtotime($row['updated_at'].' UTC'))); }  // cap 10 min
        // pick the games SSD (prefer one WITH a wear reading; else largest)
        $disk = null; foreach (($p['disks']??[]) as $d) { if (($d['wear']??null)!==null) { $disk=$d; break; } }
        if (!$disk) foreach (($p['disks']??[]) as $d) { if (!$disk || (int)($d['size_gb']??0)>(int)($disk['size_gb']??0)) $disk=$d; }

        $gt=$p['gpu_temp']; $ct=$p['cpu_temp']; $fm=$p['fan_max']; $gl=$p['gpu_load']; $cl=$p['cpu_load'];
        $inHot  = ($gt!==null && $gt>=83) || ($ct!==null && $ct>=90);
        $inWarm = ($gt!==null && $gt>=75 && $gt<83);
        $cpuHot = ($ct!==null && $ct>=90);
        $loadHi = ($gl!==null && $gl>=95) || ($cl!==null && $cl>=97);
        $fanHi  = ($fm!==null && $fm>=2400);

        if (!$row) {
            $st=$conn->prepare("INSERT INTO nm_hw_wear (host_id,first_seen,updated_at) VALUES (?,?,?)");
            $st->bind_param('iss',$hid,$now,$now); try{$st->execute();}catch(\Throwable $e){} $st->close();
            $row = ['ssd_wear_first'=>null,'ssd_first_at'=>null,'gpu_temp_max'=>0,'cpu_temp_max'=>0,'fan_rpm_max'=>0,'fan_nominal_rpm'=>0];
        }
        // accumulate zone-seconds
        $sets = ["sample_sec=sample_sec+$dt"];
        if ($inHot)  $sets[]="gpu_hot_sec=gpu_hot_sec+$dt";
        if ($inWarm) $sets[]="gpu_warm_sec=gpu_warm_sec+$dt";
        if ($cpuHot) $sets[]="cpu_hot_sec=cpu_hot_sec+$dt";
        if ($loadHi) $sets[]="load_high_sec=load_high_sec+$dt";
        if ($fanHi)  $sets[]="fan_high_sec=fan_high_sec+$dt";
        // latest snapshot + running maxima
        $q = fn($s)=> $s===null ? 'NULL' : (is_string($s)? "'".$conn->real_escape_string($s)."'" : $s);
        $sets[]="gpu_name=".$q((string)($p['gpu']['name']??''));
        $sets[]="gpu_vram_gb=".$q((float)($p['gpu']['vram']??0));
        if ($gt!==null){ $sets[]="gpu_temp_last=".$q($gt); $sets[]="gpu_temp_max=GREATEST(gpu_temp_max,".$q($gt).")"; }
        if ($ct!==null){ $sets[]="cpu_temp_last=".$q($ct); $sets[]="cpu_temp_max=GREATEST(cpu_temp_max,".$q($ct).")"; }
        if ($fm!==null){ $sets[]="fan_rpm_last=".$q($fm); $sets[]="fan_rpm_max=GREATEST(fan_rpm_max,".$q($fm).")"; }
        if ($disk) {
            $sets[]="ssd_model=".$q((string)($disk['model']??''));
            $sets[]="ssd_media=".$q((string)($disk['media']??''));
            $sets[]="ssd_size_gb=".$q((int)($disk['size_gb']??0));
            if (($disk['wear']??null)!==null)    $sets[]="ssd_wear=".$q((float)$disk['wear']);
            if (($disk['temp']??null)!==null)    $sets[]="ssd_temp=".$q((int)$disk['temp']);
            if (($disk['poweron']??null)!==null) $sets[]="ssd_poweron_hrs=".$q((int)$disk['poweron']);
            // seed the first wear reading (for the rate projection) once
            if (($disk['wear']??null)!==null && empty($row['ssd_first_at'])) { $sets[]="ssd_wear_first=".$q((float)$disk['wear']); $sets[]="ssd_first_at='$now'"; }
        }
        $sets[]="disks_json=".$q(json_encode($p['disks']??[]));
        $sets[]="specs_json=".$q(json_encode($p['gpu']??[]));   // full spec sheet (GPU+MB+BIOS+CPU+RAM+system+OS)
        $sets[]="updated_at='$now'";
        try { $conn->query("UPDATE nm_hw_wear SET ".implode(',',$sets)." WHERE host_id=$hid"); } catch (\Throwable $e) {}
    }

    // clamp
    function _wl_cl($v,$lo=0,$hi=100){ return max($lo,min($hi,$v)); }

    // Compose the Hardware Health Passport from the accumulated row.
    function nm_wl_passport($conn, int $hid): array {
        nm_wl_ensure($conn);
        $row=null; try{ $r=$conn->query("SELECT * FROM nm_hw_wear WHERE host_id=$hid"); $row=$r?$r->fetch_assoc():null; }catch(\Throwable $e){}
        if (!$row) return ['ok'=>true,'fresh'=>true,'subsystems'=>[],'grade'=>null];
        $obsHrs = round(((int)$row['sample_sec'])/3600,1);
        // does this rig expose LHM sensors at all? If yes, the exposure meters read 100 ("fresh") on the
        // first scan and DROP as real hot/full-power/high-RPM hours accumulate — consistent with SSD/fan,
        // instead of a bare "—". Only null when there is genuinely no sensor to track.
        $hasSensors = (($row['gpu_temp_max']?:0)>0 || ($row['cpu_temp_max']?:0)>0 || ($row['fan_rpm_max']?:0)>0);
        $sub=[]; $maint=[];

        // 1) SSD/NVMe NAND endurance — consider EVERY REAL drive on the node. The health = the WORST-worn
        // drive (any aging disk is a resale risk), but the certificate LISTS drives by model + SIZE only —
        // buyers identify a PC by capacity, not a raw wear %. Virtual / 0-GB disks are filtered out (noise).
        $allDisks = json_decode((string)($row['disks_json'] ?? '[]'), true); if(!is_array($allDisks)) $allDisks=[];
        $disks = array_values(array_filter($allDisks, fn($d)=>(int)($d['size_gb']??0)>0 && stripos((string)($d['model']??''),'virtual')===false && stripos((string)($d['media']??''),'virtual')===false));
        $measured = array_values(array_filter($disks, fn($d)=>isset($d['wear']) && $d['wear']!==null));
        $totGb = array_sum(array_map(fn($d)=>(int)($d['size_gb']??0), $disks));
        $capStr = $totGb>=1000 ? (round($totGb/1000,1).' TB') : ($totGb.' GB');
        $fmtDrive = function($d){ $t=trim(((string)($d['media']??'')).' '.((string)($d['bus']??''))); return trim(($d['model']?:'drive')).($t!==''?(' '.$t):'').' · '.(int)($d['size_gb']??0).'GB'; };
        $driveList = $disks ? (count($disks).' drive'.(count($disks)===1?'':'s').' · '.$capStr.': '.implode(' · ', array_map($fmtDrive,$disks))) : 'no physical drives detected';
        if ($measured) {
            $worst=0; foreach($measured as $d){ $worst=max($worst,(float)$d['wear']); }
            $health=(int)round(_wl_cl(100-$worst));
            $proj=null;
            if ($row['ssd_wear_first']!==null && !empty($row['ssd_first_at']) && $row['ssd_wear']!==null) {
                $days=max(0.01,(time()-strtotime($row['ssd_first_at'].' UTC'))/86400); $delta=(float)$row['ssd_wear']-(float)$row['ssd_wear_first'];
                if ($days>=3 && $delta>0.05) { $perMonth=$delta/$days*30; $monthsLeft=(int)round((100-(float)$row['ssd_wear'])/max(0.01,$perMonth)); $proj='≈ '.($monthsLeft>=12?round($monthsLeft/12,1).' yr':$monthsLeft.' mo').' of life left on '.trim((string)$row['ssd_model']).' at your write rate'; if($monthsLeft<18)$maint[]='An SSD is nearing its rated writes — plan a replacement / offload heavy write workloads.'; }
                else $proj='the drives are in good health — write-life projection sharpens over a few days';
            } else $proj='the drives are in good health — write-life projection builds over time';
            $sub[]=['key'=>'nand','name'=>'SSD / NVMe Endurance','icon'=>'fa-hard-drive','color'=>'#7CFFB2','health'=>$health,
                    'measured'=>true,'value'=>$capStr,'detail'=>$driveList,'projection'=>$proj,
                    'extra'=>$row['ssd_poweron_hrs']!==null?('primary powered '.round($row['ssd_poweron_hrs']/24).'d'):''];
        } else {
            $detail = $disks ? ($driveList.' — SMART wear not exposed') : 'no physical drives detected';
            $sub[]=['key'=>'nand','name'=>'SSD / NVMe Endurance','icon'=>'fa-hard-drive','color'=>'#7CFFB2','health'=>null,
                    'measured'=>false,'value'=>($disks?$capStr:'—'),'detail'=>$detail,'projection'=>'These drives don\'t expose a SMART wear indicator (common on some NVMe) — capacity is certified, write-life isn\'t reported.','extra'=>($row['ssd_poweron_hrs']!==null?('power-on '.round($row['ssd_poweron_hrs']/24).'d'):'')];
        }

        // 2) Thermal stress (GPU/CPU silicon) — real accumulated hot-hours (exposure, not a fake %)
        $hotH=round(((int)$row['gpu_hot_sec']+(int)$row['cpu_hot_sec'])/3600,1);
        $frac = $obsHrs>0 ? _wl_cl($hotH/$obsHrs*100) : 0;
        $tHealth=(int)round(_wl_cl(100 - $frac*0.9 - min(20,(($row['gpu_temp_max']?:0)>90?($row['gpu_temp_max']-90):0)*1.5)));
        $sub[]=['key'=>'thermal','name'=>'Thermal Stress (silicon)','icon'=>'fa-temperature-three-quarters','color'=>'#ff7a9c','health'=>$hasSensors?$tHealth:null,
                'measured'=>false,'value'=>$hotH.' h hot','detail'=>'peaks GPU '.round($row['gpu_temp_max']?:0).'°C · CPU '.round($row['cpu_temp_max']?:0).'°C. '.$hotH.' h in the >83°C zone of '.$obsHrs.' h watched',
                'projection'=>($frac>25?'High thermal exposure — sustained heat ages paste/pads & solder over time.':'Healthy thermal exposure so far.'),'extra'=>''];
        if ($frac>25) $maint[]='Consider a thermal-paste / pad refresh in ~'.max(3,12-(int)round($frac/8)).' months to prevent throttling.';

        // 3) Power delivery / VRM — real accumulated hours at sustained 95%+ load
        $loadH=round(((int)$row['load_high_sec'])/3600,1);
        $lFrac=$obsHrs>0?_wl_cl($loadH/$obsHrs*100):0;
        $vHealth=(int)round(_wl_cl(100-$lFrac*0.7));
        $sub[]=['key'=>'vrm','name'=>'Power Delivery (VRM)','icon'=>'fa-bolt','color'=>'#ffcf6b','health'=>$hasSensors?$vHealth:null,
                'measured'=>false,'value'=>$loadH.' h @ max','detail'=>$loadH.' h at sustained 95%+ load — the window where VRMs/caps run hottest and hardest',
                'projection'=>($lFrac>40?'Heavy sustained-full-power use — keep airflow over the VRM area strong.':'Power-stage stress is moderate.'),'extra'=>''];

        // 4) Fan bearing wear — real accumulated high-RPM hours + max RPM seen
        $fanH=round(((int)$row['fan_high_sec'])/3600,1);
        $fHealth=(int)round(_wl_cl(100-min(60,$fanH*0.4)));
        $sub[]=['key'=>'fan','name'=>'Fan Bearing Wear','icon'=>'fa-fan','color'=>'#36e3d0','health'=>($row['fan_rpm_max']?$fHealth:null),
                'measured'=>false,'value'=>$fanH.' h high','detail'=>($row['fan_rpm_max']?('max '.$row['fan_rpm_max'].' RPM · '.$fanH.' h spinning hard'):'no fan sensor exposed by LHM'),
                'projection'=>($fanH>200?'Bearings have logged many high-RPM hours — listen for new noise; a fan swap is cheap insurance.':'Bearings are fresh.'),'extra'=>''];
        if ($fanH>300) $maint[]='Fans have many high-RPM hours — have a spare ready before they start humming.';

        // overall longevity grade = weighted composite of the measurable subsystems
        $w=['nand'=>0.4,'thermal'=>0.25,'vrm'=>0.2,'fan'=>0.15]; $num=0;$den=0;
        foreach($sub as $s){ if($s['health']!==null){ $num+=$s['health']*$w[$s['key']]; $den+=$w[$s['key']]; } }
        $grade = $den>0 ? (int)round($num/$den) : null;
        $tier = $grade===null?null:($grade>=90?['S','Pristine','#7CFFB2']:($grade>=75?['A','Healthy','#4da3ff']:($grade>=60?['B','Aging well','#39e1ff']:($grade>=45?['C','Watch it','#ffcf6b']:['D','Service soon','#ff7a9c']))));

        return ['ok'=>true,'fresh'=>($obsHrs<0.1 && !$measured),'observed_hours'=>$obsHrs,
                'gpu'=>['name'=>$row['gpu_name'],'vram'=>(float)$row['gpu_vram_gb']],
                'grade'=>$grade,'tier'=>$tier,'subsystems'=>$sub,'maintenance'=>$maint,
                'first_seen'=>$row['first_seen'],'updated_at'=>$row['updated_at']];
    }

    // ── System Passport & Re-sell Certificate ──────────────────────────────────
    // A shareable, tamper-evident snapshot of a rig's REAL NEURU-recorded history (wear +
    // benchmark scores) so a used-hardware buyer gets data-backed transparency instead of
    // a seller's word. Issued once → immutable (id + figures frozen + a sha256 integrity seal).
    function nm_wl_cert_ensure($conn): void {
        try {
            $conn->query("CREATE TABLE IF NOT EXISTS nm_hw_cert (
                id VARCHAR(24) PRIMARY KEY, host_id INT NOT NULL,
                rig_name VARCHAR(120) DEFAULT '', fingerprint VARCHAR(64) DEFAULT '',
                hash CHAR(64) DEFAULT '', payload MEDIUMTEXT, created_at DATETIME NOT NULL,
                KEY host (host_id, id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
            // guarded add of the Portal-publish state (mysqli is in EXCEPTION mode → check first)
            foreach (['portal_url'=>"VARCHAR(255) DEFAULT ''",'portal_shared_at'=>"DATETIME DEFAULT NULL"] as $col=>$def) {
                $c=$conn->query("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='nm_hw_cert' AND COLUMN_NAME='$col' LIMIT 1");
                if ($c && $c->num_rows===0) { try{ $conn->query("ALTER TABLE nm_hw_cert ADD COLUMN $col $def"); }catch(\Throwable $e){} }
            }
        } catch (\Throwable $e) {}
    }

    // Publish an issued certificate to the NEURU Portal VIP (public, always-on host) behind a
    // password the OWNER sets — so an external buyer (who can't reach a NAT'd home NEURU) opens a
    // Portal link + enters that password to view the report. Returns the public URL.
    function nm_wl_cert_publish($conn, string $certId, string $password): array {
        nm_wl_cert_ensure($conn);
        $cert = nm_wl_cert_get($conn, $certId);
        if (!$cert) return ['ok'=>false,'error'=>'certificate not found'];
        if (strlen($password) < 4) return ['ok'=>false,'error'=>'set a password of at least 4 characters'];
        require_once __DIR__ . '/nm_license.php';
        $base = function_exists('nm_lic_api_base') ? nm_lic_api_base($conn) : '';
        if ($base === '') return ['ok'=>false,'error'=>'Portal API URL is not configured (Config → License).'];
        $row = function_exists('nm_lic_row') ? nm_lic_row($conn) : null;
        $body = json_encode([
            'license_key' => is_array($row) ? (string)($row['license_key'] ?? '') : '',
            'fingerprint' => function_exists('nm_lic_fingerprint') ? nm_lic_fingerprint() : '',
            'cert_id'     => $cert['id'],
            'rig_name'    => (string)($cert['data']['rig']['name'] ?? 'PC'),
            'hash'        => (string)$cert['hash'],
            'password'    => $password,                       // over HTTPS → Portal stores a salted hash
            'payload'     => $cert['data'],
        ]);
        $ch = curl_init(rtrim($base,'/').'/v1/passport/publish');
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>$body,
            CURLOPT_HTTPHEADER=>['Content-Type: application/json'], CURLOPT_CONNECTTIMEOUT=>6, CURLOPT_TIMEOUT=>20,
            CURLOPT_IPRESOLVE=>CURL_IPRESOLVE_V4, CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_SSL_VERIFYHOST=>false]);
        $res = curl_exec($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); $err=curl_error($ch); curl_close($ch);
        if ($res===false || $code===0) return ['ok'=>false,'error'=>$err ?: 'could not reach the Portal'];
        if ($code===404) return ['ok'=>false,'error'=>'Passport sharing is not available on the Portal yet.'];
        $j = json_decode($res, true);
        if (!is_array($j) || empty($j['ok'])) return ['ok'=>false,'error'=>(string)($j['error'] ?? ('HTTP '.$code))];
        $url = (string)($j['url'] ?? '');
        if ($url!=='') { try { $st=$conn->prepare("UPDATE nm_hw_cert SET portal_url=?, portal_shared_at=NOW() WHERE id=?"); $st->bind_param('ss',$url,$certId); $st->execute(); $st->close(); } catch (\Throwable $e) {} }
        if (function_exists('nm_audit')) { try { nm_audit($conn,'longevity.cert_publish',['details'=>['id'=>$certId]]); } catch (\Throwable $e) {} }
        return ['ok'=>true,'url'=>$url,'id'=>$certId];
    }

    // ── manage published passports on the Portal (list / revoke / change password) ──
    function _nm_wl_portal_call($conn, string $path, array $extra=[]): array {
        require_once __DIR__ . '/nm_license.php';
        $base = function_exists('nm_lic_api_base') ? nm_lic_api_base($conn) : '';
        if ($base==='') return ['ok'=>false,'error'=>'Portal API is not configured (Config → License).'];
        $row = function_exists('nm_lic_row') ? nm_lic_row($conn) : null;
        $body = json_encode(array_merge([
            'license_key'=>is_array($row)?(string)($row['license_key']??''):'',
            'fingerprint'=>function_exists('nm_lic_fingerprint')?nm_lic_fingerprint():'',
        ], $extra));
        $ch=curl_init(rtrim($base,'/').$path);
        curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>1,CURLOPT_POST=>1,CURLOPT_POSTFIELDS=>$body,
            CURLOPT_HTTPHEADER=>['Content-Type: application/json'],CURLOPT_CONNECTTIMEOUT=>6,CURLOPT_TIMEOUT=>18,
            CURLOPT_IPRESOLVE=>CURL_IPRESOLVE_V4,CURLOPT_SSL_VERIFYPEER=>0,CURLOPT_SSL_VERIFYHOST=>0]);
        $res=curl_exec($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); $err=curl_error($ch); curl_close($ch);
        if($res===false||$code===0) return ['ok'=>false,'error'=>$err?:'could not reach the Portal'];
        if($code===404) return ['ok'=>false,'error'=>'Passport management is not available on the Portal yet.'];
        $j=json_decode($res,true); return is_array($j)?$j:['ok'=>false,'error'=>'bad Portal response'];
    }
    function nm_wl_cert_shared_list($conn): array { return _nm_wl_portal_call($conn,'/v1/passport/list'); }
    function nm_wl_cert_revoke($conn, string $id): array { return _nm_wl_portal_call($conn,'/v1/passport/revoke',['id'=>$id]); }
    function nm_wl_cert_setpass($conn, string $id, string $pass): array { return _nm_wl_portal_call($conn,'/v1/passport/setpass',['id'=>$id,'password'=>$pass]); }

    // aggregate everything a passport shows (all REAL, from what NEURU already recorded)
    function nm_wl_cert_data($conn, int $hid, string $rigName=''): array {
        $pass = nm_wl_passport($conn, $hid);
        $row = null; try { $r=$conn->query("SELECT * FROM nm_hw_wear WHERE host_id=$hid"); $row=$r?$r->fetch_assoc():null; } catch (\Throwable $e) {}
        // benchmark score history (best + trend)
        $bench = []; $bestScore = 0; $cpu = '';
        if (function_exists('nm_bench_history')) {
            foreach (nm_bench_history($conn, $hid, 12) as $b) {
                $bench[] = ['score'=>(int)$b['neuru_score'],'tier'=>(string)$b['tier_key'],'when'=>substr((string)$b['created_at'],0,10)];
                if ((int)$b['neuru_score'] > $bestScore) $bestScore = (int)$b['neuru_score'];
                if ($cpu==='') { $pl=json_decode((string)($b['payload']??''),true); if(is_array($pl)) $cpu=(string)($pl['hardware']['cpu']??''); }
            }
        }
        $samH = $row ? round(((int)$row['sample_sec'])/3600,1) : 0;
        $loadH= $row ? round(((int)$row['load_high_sec'])/3600,1) : 0;
        $hotH = $row ? round((((int)$row['gpu_hot_sec'])+((int)$row['cpu_hot_sec']))/3600,1) : 0;
        $specs = json_decode((string)($row['specs_json'] ?? '{}'), true); if(!is_array($specs)) $specs=[];
        // every REAL drive on the node (physical only — filter virtual / 0-GB noise), model + size
        $rawDisks = json_decode((string)($row['disks_json'] ?? '[]'), true); if(!is_array($rawDisks)) $rawDisks=[];
        $disks = array_values(array_map(fn($d)=>[
            'model'=>(string)($d['model'] ?? ''),'size_gb'=>(int)($d['size_gb'] ?? 0),
            'media'=>(string)($d['media'] ?? ''),'bus'=>(string)($d['bus'] ?? ''),
        ], array_filter($rawDisks, fn($d)=>(int)($d['size_gb']??0)>0 && stripos((string)($d['model']??''),'virtual')===false && stripos((string)($d['media']??''),'virtual')===false)));
        if ($cpu==='' && !empty($specs['cpu_name'])) $cpu = (string)$specs['cpu_name'];
        return [
            'v'=>2,'issued_at'=>gmdate('c'),'fingerprint'=>function_exists('nm_lic_fingerprint')?nm_lic_fingerprint():'',
            'rig'=>['name'=>$rigName ?: (string)($pass['gpu']['name'] ?? 'PC'),
                    'gpu'=>(string)($pass['gpu']['name'] ?? ($row['gpu_name'] ?? '')),'vram'=>(float)($pass['gpu']['vram'] ?? ($row['gpu_vram_gb'] ?? 0)),
                    'cpu'=>$cpu,'ssd'=>(string)($row['ssd_model'] ?? ''),'ssd_gb'=>(int)($row['ssd_size_gb'] ?? 0),
                    'disks'=>$disks],
            // full spec sheet (all real, agentless): motherboard, BIOS, CPU, RAM, system, OS, display
            'specs'=>[
                'system'   => trim(((string)($specs['sys_brand'] ?? '')).' '.((string)($specs['sys_model'] ?? ''))),
                'motherboard' => trim(((string)($specs['mb_brand'] ?? '')).' '.((string)($specs['mb_model'] ?? ''))).(!empty($specs['mb_ver'])?(' (v'.$specs['mb_ver'].')'):''),
                'bios'     => trim(((string)($specs['bios_ver'] ?? '')).(!empty($specs['bios_date'])?(' · '.$specs['bios_date']):'')),
                'cpu'      => trim((string)($specs['cpu_name'] ?? $cpu)).((int)($specs['cpu_cores']??0)?(' · '.$specs['cpu_cores'].'C/'.$specs['cpu_threads'].'T'):'').(($specs['cpu_ghz']??0)?(' @ '.$specs['cpu_ghz'].' GHz'):''),
                'gpu'      => trim((string)($pass['gpu']['name'] ?? '')).(($pass['gpu']['vram']??0)?(' · '.$pass['gpu']['vram'].' GB'):''),
                'ram'      => (($specs['ram_gb']??0)?($specs['ram_gb'].' GB'):'—').(($specs['ram_type']??'')?(' '.$specs['ram_type']):'').(($specs['ram_mhz']??0)?(' @ '.$specs['ram_mhz'].' MHz'):'').(($specs['ram_sticks']??0)>1?(' · '.$specs['ram_sticks'].' sticks'):''),
                'display'  => (($specs['res']??'')?:'—').(($specs['refresh']??0)?(' @ '.$specs['refresh'].'Hz'):''),
                'os'       => trim((string)($specs['os'] ?? '')).(!empty($specs['os_ver'])?(' ('.$specs['os_ver'].')'):''),
            ],
            'grade'=>$pass['grade'] ?? null,'tier'=>$pass['tier'] ?? null,'subsystems'=>$pass['subsystems'] ?? [],
            'usage'=>['watched_hours'=>$samH,'heavy_load_hours'=>$loadH,'hot_zone_hours'=>$hotH,
                      'gpu_peak_c'=>round($row['gpu_temp_max'] ?? 0),'cpu_peak_c'=>round($row['cpu_temp_max'] ?? 0),
                      'ssd_wear_pct'=>$row && $row['ssd_wear']!==null?round((float)$row['ssd_wear'],1):null,
                      'ssd_poweron_days'=>$row && $row['ssd_poweron_hrs']!==null?round(((int)$row['ssd_poweron_hrs'])/24):null,
                      'first_seen'=>$row['first_seen'] ?? null],
            'benchmark'=>['best'=>$bestScore,'history'=>$bench],
        ];
    }

    function nm_wl_cert_issue($conn, int $hid, string $rigName=''): array {
        nm_wl_cert_ensure($conn);
        $data = nm_wl_cert_data($conn, $hid, $rigName);
        $payload = json_encode($data, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
        $id = 'NRU-'.strtoupper(bin2hex(random_bytes(6)));                 // e.g. NRU-A1B2C3D4E5F6
        $hash = hash('sha256', $payload);                                  // integrity seal (data ↔ id are frozen)
        try {
            $st=$conn->prepare("INSERT INTO nm_hw_cert (id,host_id,rig_name,fingerprint,hash,payload,created_at) VALUES (?,?,?,?,?,?,NOW())");
            $rn=(string)$data['rig']['name']; $fp=(string)$data['fingerprint'];
            $st->bind_param('sissss',$id,$hid,$rn,$fp,$hash,$payload); $st->execute(); $st->close();
        } catch (\Throwable $e) { return ['ok'=>false,'error'=>'issue failed']; }
        if (function_exists('nm_audit')) { try { nm_audit($conn,'longevity.cert_issue',['details'=>['id'=>$id,'host'=>$hid]]); } catch (\Throwable $e) {} }
        return ['ok'=>true,'id'=>$id];
    }

    function nm_wl_cert_get($conn, string $id): ?array {
        nm_wl_cert_ensure($conn);
        try { $st=$conn->prepare("SELECT * FROM nm_hw_cert WHERE id=? LIMIT 1"); $st->bind_param('s',$id); $st->execute(); $row=$st->get_result()->fetch_assoc(); $st->close(); } catch (\Throwable $e) { return null; }
        if (!$row) return null;
        $data = json_decode((string)$row['payload'], true);
        $valid = is_array($data) && hash('sha256',(string)$row['payload']) === (string)$row['hash'];   // stored data unchanged since issue
        return ['id'=>$row['id'],'host_id'=>(int)$row['host_id'],'created_at'=>$row['created_at'],'hash'=>$row['hash'],
                'fingerprint'=>$row['fingerprint'],'valid'=>$valid,'data'=>$data];
    }

    // probe + accumulate + return the fresh passport (used by the page's "Scan now" and the cron)
    function nm_wl_scan($conn, int $hid, $ssh): array {
        $p = nm_wl_probe($conn, $ssh);
        if (empty($p['ok'])) return ['ok'=>false,'error'=>'probe failed'];
        nm_wl_accumulate($conn, $hid, $p);
        return nm_wl_passport($conn, $hid) + ['probe'=>['sensors_ok'=>$p['sensors_ok'],'disks'=>count($p['disks'])]];
    }
}
