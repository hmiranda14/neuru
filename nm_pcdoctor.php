<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — PC DOCTOR engine. Agentless full hardware inventory over the same
// Windows-over-SSH stack (nm_win_ps). Returns CPU / motherboard / BIOS / RAM
// DIMMs / GPU(s) / NVMe+SATA disks / PCIe cards, each enriched with a real
// manufacturer link + an image-search link, so the WebGL virtual PC can render
// every part and open its true brand/model/version. Live "currents" (loads +
// temps) reuse nm_gaming_vitals + nm_gaming_sensors. Perm 'pc_doctor'.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_gaming.php';   // nm_win_ps, _nm_g_out, sensors, vitals

// Map a hardware brand to its official site; unknown → a web search. Keeps links real.
function nm_pcd_vendor_home(string $brand): string {
    $b = strtolower(trim($brand));
    if ($b === '') return '';
    static $map = [
        'nvidia'=>'nvidia.com','amd'=>'amd.com','advanced micro devices'=>'amd.com','ati'=>'amd.com','intel'=>'intel.com',
        'asus'=>'asus.com','asustek'=>'asus.com','asrock'=>'asrock.com','gigabyte'=>'gigabyte.com','micro-star'=>'msi.com',
        'msi'=>'msi.com','biostar'=>'biostar.com','evga'=>'evga.com','zotac'=>'zotac.com','sapphire'=>'sapphire.com',
        'powercolor'=>'powercolor.com','pny'=>'pny.com','palit'=>'palit.com','gainward'=>'gainward.com','xfx'=>'xfx.com',
        'corsair'=>'corsair.com','g.skill'=>'gskill.com','g skill'=>'gskill.com','gskill'=>'gskill.com','kingston'=>'kingston.com',
        'crucial'=>'crucial.com','micron'=>'micron.com','samsung'=>'samsung.com','adata'=>'adata.com','teamgroup'=>'teamgroupinc.com',
        'team'=>'teamgroupinc.com','patriot'=>'patriotmemory.com','hynix'=>'skhynix.com','sk hynix'=>'skhynix.com',
        'western digital'=>'westerndigital.com','wdc'=>'westerndigital.com','wd'=>'westerndigital.com','sandisk'=>'sandisk.com',
        'seagate'=>'seagate.com','toshiba'=>'toshiba-storage.com','kioxia'=>'kioxia.com','sabrent'=>'sabrent.com',
        'realtek'=>'realtek.com','broadcom'=>'broadcom.com','qualcomm'=>'qualcomm.com','mediatek'=>'mediatek.com',
        'killer'=>'intel.com','aquantia'=>'marvell.com','marvell'=>'marvell.com','creative'=>'creative.com',
        'nzxt'=>'nzxt.com','be quiet'=>'bequiet.com','cooler master'=>'coolermaster.com','thermaltake'=>'thermaltake.com',
        'deepcool'=>'deepcool.com','noctua'=>'noctua.at','lian li'=>'lian-li.com','fractal'=>'fractal-design.com',
        'dell'=>'dell.com','hp'=>'hp.com','hewlett'=>'hp.com','lenovo'=>'lenovo.com','acer'=>'acer.com',
    ];
    foreach ($map as $k=>$dom) if (strpos($b, $k) !== false) return 'https://www.' . $dom;
    return 'https://www.google.com/search?q=' . rawurlencode(trim($brand) . ' official site');
}
function nm_pcd_search(string $q): string   { return $q==='' ? '' : 'https://www.google.com/search?q=' . rawurlencode($q); }
function nm_pcd_images(string $q): string    { return $q==='' ? '' : 'https://www.google.com/search?tbm=isch&q=' . rawurlencode($q); }

// Attach vendor_url / spec_url / img_url to a part given its brand + model text.
function nm_pcd_links(string $brand, string $model): array {
    $q = trim($brand . ' ' . $model);
    return ['vendor_url'=>nm_pcd_vendor_home($brand), 'spec_url'=>nm_pcd_search($q . ' specifications'), 'img_url'=>nm_pcd_images($q)];
}

// Bus-type code/string → friendly label (NVMe vs SATA is the money question for gamers).
function nm_pcd_bus(string $bus): string {
    $b = strtolower(trim($bus));
    if ($b==='' ) return '';
    if (strpos($b,'nvme')!==false || $b==='17') return 'NVMe';
    if (strpos($b,'sata')!==false || $b==='11') return 'SATA';
    if (strpos($b,'usb')!==false  || $b==='7')  return 'USB';
    if (strpos($b,'raid')!==false || $b==='10') return 'RAID';
    if (strpos($b,'sas')!==false  || $b==='9')  return 'SAS';
    return strtoupper($bus);
}

// ── The full inventory. One combined CIM/WMI round-trip (best-effort per section). ──
function nm_pcd_hardware($ssh): array {
    $ps = '$ErrorActionPreference=\'SilentlyContinue\'; '
        . '$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1; '
        . '$bb=Get-CimInstance Win32_BaseBoard; $bios=Get-CimInstance Win32_BIOS; $cs=Get-CimInstance Win32_ComputerSystem; $os=Get-CimInstance Win32_OperatingSystem; '
        . '$biosdate=if($bios.ReleaseDate){$bios.ReleaseDate.ToString(\'yyyy-MM-dd\')}else{\'\'}; '
        . '$insdate=if($os.InstallDate){$os.InstallDate.ToString(\'yyyy-MM-dd\')}else{\'\'}; '
        . '$uph=if($os.LastBootUpTime){[int]((Get-Date)-$os.LastBootUpTime).TotalHours}else{0}; '
        . '$mem=@(Get-CimInstance Win32_PhysicalMemory | ForEach-Object { @{ loc=[string]$_.DeviceLocator; bank=[string]$_.BankLabel; mfr=[string]$_.Manufacturer; part=([string]$_.PartNumber).Trim(); serial=([string]$_.SerialNumber).Trim(); cap=[int64]$_.Capacity; spd=[int]$_.Speed; cspd=[int]$_.ConfiguredClockSpeed; ff=[int]$_.FormFactor; smt=[int]$_.SMBIOSMemoryType; mt=[int]$_.MemoryType; volt=[int]$_.ConfiguredVoltage; dw=[int]$_.DataWidth; tw=[int]$_.TotalWidth } }); '
        . '$gpu=@(Get-CimInstance Win32_VideoController | Where-Object { $_.Name -notmatch \'Basic|Remote|Meta|Mirror|DameWare\' } | ForEach-Object { $dld=if($_.DriverDate){$_.DriverDate.ToString(\'yyyy-MM-dd\')}else{\'\'}; @{ name=[string]$_.Name; vram=[int64]$_.AdapterRAM; drv=[string]$_.DriverVersion; drvdate=$dld; vendor=[string]$_.AdapterCompatibility; proc=[string]$_.VideoProcessor; mode=[string]$_.VideoModeDescription; hres=[int]$_.CurrentHorizontalResolution; vres=[int]$_.CurrentVerticalResolution; hz=[int]$_.CurrentRefreshRate; pnp=[string]$_.PNPDeviceID; status=[string]$_.Status } }); '
        . '$dd=@(Get-CimInstance Win32_DiskDrive | ForEach-Object { @{ idx=[int]$_.Index; model=([string]$_.Model).Trim(); serial=([string]$_.SerialNumber).Trim(); fw=([string]$_.FirmwareRevision).Trim(); iface=[string]$_.InterfaceType; parts=[int]$_.Partitions; size=[int64]$_.Size; sector=[int]$_.BytesPerSector } }); '
        . '$pd=@(Get-PhysicalDisk | ForEach-Object { @{ idx=[int]$_.DeviceId; name=[string]$_.FriendlyName; media=[string]$_.MediaType; bus=[string]$_.BusType; size=[int64]$_.Size; model=[string]$_.Model; health=[string]$_.HealthStatus; spindle=[int]$_.SpindleSpeed } }); '
        . '$net=@(Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -and $_.PNPDeviceID -like \'PCI*\' } | ForEach-Object { @{ name=[string]$_.Name; mfr=[string]$_.Manufacturer; speed=[int64]$_.Speed; mac=[string]$_.MACAddress; type=[string]$_.AdapterType } }); '
        . '$snd=@(Get-CimInstance Win32_SoundDevice | Where-Object { $_.Name -notmatch \'NVIDIA|AMD High|Display Audio\' } | ForEach-Object { @{ name=[string]$_.Name; mfr=[string]$_.Manufacturer } }); '
        . '$out=@{ '
        .   'cpu=@{ name=[string]$cpu.Name; mfr=[string]$cpu.Manufacturer; cores=[int]$cpu.NumberOfCores; threads=[int]$cpu.NumberOfLogicalProcessors; clock=[int]$cpu.MaxClockSpeed; curclock=[int]$cpu.CurrentClockSpeed; socket=[string]$cpu.SocketDesignation; l2=[int]$cpu.L2CacheSize; l3=[int]$cpu.L3CacheSize; aw=[int]$cpu.AddressWidth; virt=[string]$cpu.VirtualizationFirmwareEnabled; desc=[string]$cpu.Description; pid=[string]$cpu.ProcessorId }; '
        .   'board=@{ mfr=[string]$bb.Manufacturer; product=[string]$bb.Product; ver=[string]$bb.Version; serial=([string]$bb.SerialNumber).Trim() }; '
        .   'bios=@{ mfr=[string]$bios.Manufacturer; ver=[string]$bios.SMBIOSBIOSVersion; date=$biosdate; serial=([string]$bios.SerialNumber).Trim(); smaj=[int]$bios.SMBIOSMajorVersion; smin=[int]$bios.SMBIOSMinorVersion }; '
        .   'system=@{ mfr=[string]$cs.Manufacturer; model=[string]$cs.Model; type=[string]$cs.SystemType; ram=[int64]$cs.TotalPhysicalMemory; lps=[int]$cs.NumberOfLogicalProcessors; domain=[string]$cs.Domain; sku=[string]$cs.SystemSKUNumber }; '
        .   'os=@{ name=[string]$os.Caption; ver=[string]$os.Version; build=[string]$os.BuildNumber; arch=[string]$os.OSArchitecture; install=$insdate; uptime_h=$uph }; '
        .   'mem=$mem; gpu=$gpu; dd=$dd; pd=$pd; net=$net; snd=$snd }; '
        . '($out | ConvertTo-Json -Compress -Depth 6)';
    $r = nm_win_ps($ssh, $ps, 30);
    $out = trim((string)_nm_g_out($r));
    $j = json_decode($out, true);
    if (!is_array($j)) return ['ok'=>false,'error'=>'hardware query returned no data (is the rig online & SSH admin?)','raw'=>substr($out,0,200)];

    $norm = function($v){ return is_array($v) ? (isset($v['name'])||isset($v['loc'])||isset($v['idx'])||isset($v['mfr']) ? [$v] : array_values($v)) : []; };
    $sp = function(array $rows){ $o=[]; foreach($rows as $r){ if($r[1]!==''&&$r[1]!==null&&$r[1]!=='0'&&!($r[1]===0)) $o[]=[(string)$r[0],(string)$r[1]]; } return $o; };  // drop blank/zero specs

    // ── CPU ──
    $c = $j['cpu'] ?? [];
    $cpuName = trim((string)($c['name']??'Unknown CPU'));
    $cpuBrand = stripos($cpuName,'intel')!==false?'Intel':(stripos($cpuName,'amd')!==false||stripos($cpuName,'ryzen')!==false?'AMD':(string)($c['mfr']??''));
    $cpu = ['name'=>$cpuName,'brand'=>$cpuBrand,'cores'=>(int)($c['cores']??0),'threads'=>(int)($c['threads']??0),'clock'=>(int)($c['clock']??0),'socket'=>trim((string)($c['socket']??'')),'l3'=>(int)($c['l3']??0)]
        + nm_pcd_links($cpuBrand,$cpuName)
        + ['specs'=>$sp([
            ['Brand',$cpuBrand],['Cores / Threads',(($c['cores']??0)?:'?').' cores · '.(($c['threads']??0)?:'?').' threads'],
            ['Max clock',($c['clock']??0)?($c['clock'].' MHz'):''],['Current clock',($c['curclock']??0)?($c['curclock'].' MHz'):''],
            ['Socket',trim((string)($c['socket']??''))],['L2 cache',($c['l2']??0)?round(($c['l2'])/1024,1).' MB':''],['L3 cache',($c['l3']??0)?round(($c['l3'])/1024).' MB':''],
            ['Architecture',($c['aw']??0)?($c['aw'].'-bit'):''],['Virtualization',(strtolower((string)($c['virt']??''))==='true')?'Enabled':((string)($c['virt']??'')!==''?'Disabled':'')],
            ['Family / model',trim((string)($c['desc']??''))],['Processor ID',trim((string)($c['pid']??''))],
        ])];

    // ── Motherboard + BIOS + System + OS (the board/chipset panel = the whole machine's identity) ──
    $b = $j['board'] ?? []; $bi = $j['bios'] ?? []; $sy = $j['system'] ?? []; $osj = $j['os'] ?? [];
    $board = ['brand'=>trim((string)($b['mfr']??'')),'product'=>trim((string)($b['product']??'Unknown board')),'ver'=>trim((string)($b['ver']??'')),
              'bios'=>trim((string)(($bi['mfr']??'').' '.($bi['ver']??'')))]
        + nm_pcd_links((string)($b['mfr']??''),(string)($b['product']??''))
        + ['specs'=>$sp([
            ['Manufacturer',trim((string)($b['mfr']??''))],['Model',trim((string)($b['product']??''))],['Revision',trim((string)($b['ver']??''))],['Serial #',trim((string)($b['serial']??''))],
            ['BIOS vendor',trim((string)($bi['mfr']??''))],['BIOS version',trim((string)($bi['ver']??''))],['BIOS date',trim((string)($bi['date']??''))],
            ['System',trim((string)(($sy['mfr']??'').' '.($sy['model']??'')))],['System type',trim((string)($sy['type']??''))],['SKU',trim((string)($sy['sku']??''))],['Domain / workgroup',trim((string)($sy['domain']??''))],
            ['Installed RAM',($sy['ram']??0)?round(($sy['ram'])/1073741824).' GB':''],['Logical processors',(string)($sy['lps']??'')],
            ['OS',trim((string)($osj['name']??''))],['OS build',trim((string)(($osj['ver']??'').' ('.($osj['build']??'').')'))],['Architecture',trim((string)($osj['arch']??''))],
            ['Installed on',trim((string)($osj['install']??''))],['Uptime',($osj['uptime_h']??0)?(($osj['uptime_h']>=48?round($osj['uptime_h']/24).' days':$osj['uptime_h'].' h')):''],
        ])];

    // ── RAM DIMMs ──
    $mem = [];
    foreach ($norm($j['mem']??[]) as $m) {
        $brand=trim((string)($m['mfr']??'')); $part=trim((string)($m['part']??'')); $type=nm_pcd_memtype((int)($m['smt']??0),(int)($m['mt']??0)); $form=nm_pcd_formfactor((int)($m['ff']??0));
        $mem[] = ['slot'=>trim((string)($m['loc']??'')),'brand'=>$brand,'part'=>$part,'gb'=>round(((int)($m['cap']??0))/1073741824),'speed'=>(int)($m['cspd']??($m['spd']??0)),'type'=>$type]
            + nm_pcd_links($brand,$part)
            + ['specs'=>$sp([
                ['Slot',trim((string)($m['loc']??''))],['Brand',$brand],['Part #',$part],['Type',$type],['Capacity',(($m['cap']??0)?round(($m['cap'])/1073741824).' GB':'')],
                ['Speed',($m['cspd']??0)?($m['cspd'].' MT/s'):(($m['spd']??0)?($m['spd'].' MT/s (rated)'):'')],['Rated speed',($m['spd']??0)?($m['spd'].' MT/s'):''],
                ['Form factor',$form],['Voltage',($m['volt']??0)?round(($m['volt'])/1000,2).' V':''],['Data / total width',(($m['dw']??0)?($m['dw'].' / '.($m['tw']??'?').' bit'):'')],
                ['Bank',trim((string)($m['bank']??''))],['Serial #',trim((string)($m['serial']??''))],
            ])];
    }

    // ── GPUs ──
    $gpu = [];
    foreach ($norm($j['gpu']??[]) as $g) {
        $name=trim((string)($g['name']??'')); if($name==='')continue;
        $brand = stripos($name,'nvidia')!==false||stripos($name,'geforce')!==false||stripos($name,'rtx')!==false||stripos($name,'gtx')!==false?'NVIDIA'
               : (stripos($name,'radeon')!==false||stripos($name,'amd')!==false?'AMD':(stripos($name,'intel')!==false||stripos($name,'arc')!==false?'Intel':(string)($g['vendor']??'')));
        $res = ((int)($g['hres']??0)>0)?(($g['hres']).'×'.($g['vres']??'?').(($g['hz']??0)?(' @ '.$g['hz'].'Hz'):'')):'';
        $gpu[] = ['name'=>$name,'brand'=>$brand,'vram'=>round(((int)($g['vram']??0))/1048576),'driver'=>trim((string)($g['drv']??'')),'proc'=>trim((string)($g['proc']??''))]
            + nm_pcd_links($brand,$name)
            + ['specs'=>$sp([
                ['Brand',$brand],['GPU',trim((string)($g['proc']??''))],['VRAM',(($g['vram']??0)?round(($g['vram'])/1048576).' MB':'')],
                ['Driver',trim((string)($g['drv']??''))],['Driver date',trim((string)($g['drvdate']??''))],
                ['Resolution',$res],['Video mode',trim((string)($g['mode']??''))],['Status',trim((string)($g['status']??''))],
                ['PCIe bus',nm_pcd_pci_slot((string)($g['pnp']??''))],
            ])];
    }

    // ── Disks — merge Win32_DiskDrive (identity) with Get-PhysicalDisk (bus/media/health) by disk index ──
    $pdByIdx = []; foreach ($norm($j['pd']??[]) as $p) $pdByIdx[(int)($p['idx']??-1)] = $p;
    $disks = [];
    foreach ($norm($j['dd']??[]) as $d) {
        $idx=(int)($d['idx']??-1); $p=$pdByIdx[$idx]??[];
        $name = trim((string)(($p['name']??'')?:($d['model']??''))); if($name==='')continue;
        $bus = nm_pcd_bus((string)($p['bus']??$d['iface']??''));
        $media=(string)($p['media']??''); if($media===''||$media==='Unspecified') $media=((int)($p['spindle']??0)>0?'HDD':'SSD');
        $brand=nm_pcd_disk_brand($name);
        $disks[] = ['name'=>$name,'brand'=>$brand,'bus'=>$bus,'media'=>$media,'gb'=>round(((int)($d['size']??$p['size']??0))/1073741824),'health'=>trim((string)($p['health']??''))]
            + nm_pcd_links($brand,$name)
            + ['specs'=>$sp([
                ['Brand',$brand],['Interface',$bus.(($d['iface']??'')&&$d['iface']!==$bus?(' ('.$d['iface'].')'):'')],['Type',$media],
                ['Capacity',(($d['size']??$p['size']??0)?round(((int)($d['size']??$p['size']))/1073741824).' GB':'')],['Health',trim((string)($p['health']??''))],
                ['Firmware',trim((string)($d['fw']??''))],['Serial #',trim((string)($d['serial']??''))],['Partitions',(($d['parts']??0)?:'')],
                ['Sector size',(($d['sector']??0)?($d['sector'].' B'):'')],['Spindle',(($p['spindle']??0)?($p['spindle'].' RPM'):'')],
            ])];
    }

    // ── PCIe cards = discrete network + sound ──
    $pcie = [];
    foreach ($norm($j['net']??[]) as $n) { $nm=trim((string)($n['name']??'')); if($nm==='')continue; $br=trim((string)($n['mfr']??''));
        $pcie[] = ['kind'=>'Network','name'=>$nm,'brand'=>$br] + nm_pcd_links($br,$nm)
            + ['specs'=>$sp([['Brand',$br],['Type','Network adapter'],['MAC address',trim((string)($n['mac']??''))],['Link speed',(($n['speed']??0)>0?round(((int)$n['speed'])/1e6).' Mbps':'')],['Adapter',trim((string)($n['type']??''))]])]; }
    foreach ($norm($j['snd']??[]) as $n) { $nm=trim((string)($n['name']??'')); if($nm==='')continue; $br=trim((string)($n['mfr']??''));
        $pcie[] = ['kind'=>'Audio','name'=>$nm,'brand'=>$br] + nm_pcd_links($br,$nm) + ['specs'=>$sp([['Brand',$br],['Type','Audio device']])]; }

    return ['ok'=>true,'cpu'=>$cpu,'board'=>$board,'mem'=>$mem,'gpu'=>$gpu,'disks'=>$disks,'pcie'=>$pcie,
            'system'=>['brand'=>trim((string)($sy['mfr']??'')),'model'=>trim((string)($sy['model']??'')),'ram_gb'=>round(((int)($sy['ram']??0))/1073741824)],
            'os'=>['name'=>trim((string)($osj['name']??'')),'uptime_h'=>(int)($osj['uptime_h']??0)],
            'ts'=>time()];
}

// ── DIAGNOSTICS — a battery of READ-ONLY SSH/PowerShell health checks for troubleshooting. Each returns
//    {id,label,status: ok|warn|crit|info, summary, detail[]}. Nothing here changes system state. ──
function nm_pcd_diagnostics($conn, array $h): array {
    $ssh = function_exists('nm_win_resolve_ssh') ? nm_win_resolve_ssh($conn,$h) : null;
    if (!$ssh) return ['ok'=>false,'error'=>'no SSH'];
    $checks = [];
    $add = function($id,$label,$status,$summary,$detail=[]) use (&$checks){ $checks[] = ['id'=>$id,'label'=>$label,'status'=>$status,'summary'=>$summary,'detail'=>array_values(array_filter((array)$detail))]; };

    // 1) DISK SMART / reliability — the #1 troubleshooting signal
    try {
        $ps = '$ErrorActionPreference=\'SilentlyContinue\'; $d=@(Get-PhysicalDisk | ForEach-Object { $r=$_ | Get-StorageReliabilityCounter; @{ name=[string]$_.FriendlyName; health=[string]$_.HealthStatus; media=[string]$_.MediaType; temp=[int]$r.Temperature; wear=[int]$r.Wear; poh=[int]$r.PowerOnHours; rerr=[int64]$r.ReadErrorsTotal; werr=[int64]$r.WriteErrorsTotal; realloc=[int64]$r.ReallocatedSectorsCount } }); ($d | ConvertTo-Json -Compress -Depth 4)';
        $j = json_decode(trim((string)_nm_g_out(nm_win_ps($ssh,$ps,25))), true); if (isset($j['name'])) $j=[$j];
        foreach ((array)($j?:[]) as $d) {
            $nm=(string)($d['name']??'disk'); $health=(string)($d['health']??''); $wear=(int)($d['wear']??0); $temp=(int)($d['temp']??0); $ra=(int)($d['realloc']??0); $poh=(int)($d['poh']??0);
            $st='ok'; if ($health!=='' && $health!=='Healthy') $st='crit'; elseif ($ra>0 || $wear>=90) $st='crit'; elseif ($wear>=70 || $temp>=65 || (int)($d['rerr']??0)>0 || (int)($d['werr']??0)>0) $st='warn';
            $det=[]; if($health)$det[]='Health: '.$health; if($temp)$det[]=$temp.'°C'; if($wear)$det[]='Wear '.$wear.'%'; if($poh)$det[]=round($poh/24).' days powered on'; if($ra)$det[]='⚠ '.$ra.' reallocated sectors'; if((int)($d['rerr']??0)||(int)($d['werr']??0))$det[]='R/W errors: '.($d['rerr']??0).'/'.($d['werr']??0);
            $add('disk_'.md5($nm),'Drive · '.$nm,$st,$st==='ok'?'Healthy':($st==='crit'?'Failing / SMART fault':'Watch this drive'),$det);
        }
    } catch (\Throwable $e) {}

    // 2) STABILITY + system checks in one PS: crashes/WHEA/unexpected shutdowns, problem devices, power plan, HAGS, pending reboot, RAM XMP
    try {
        $ps = '$ErrorActionPreference=\'SilentlyContinue\'; $since=(Get-Date).AddDays(-14); '
            . '$k41=@(Get-WinEvent -FilterHashtable @{LogName=\'System\';Id=41;StartTime=$since} -MaxEvents 60).Count; '
            . '$dirty=@(Get-WinEvent -FilterHashtable @{LogName=\'System\';Id=6008;StartTime=$since} -MaxEvents 60).Count; '
            . '$bsod=@(Get-WinEvent -FilterHashtable @{LogName=\'System\';Id=1001;ProviderName=\'Microsoft-Windows-WER-SystemErrorReporting\';StartTime=$since} -MaxEvents 60).Count; '
            . '$whea=@(Get-WinEvent -FilterHashtable @{LogName=\'System\';ProviderName=\'Microsoft-Windows-WHEA-Logger\';StartTime=$since} -MaxEvents 60 | Where-Object { $_.LevelDisplayName -match \'Error|Critical\' }).Count; '
            . '$bad=@(Get-PnpDevice -PresentOnly -Status Error | Select-Object -First 12 | ForEach-Object { [string]$_.FriendlyName }); '
            . '$plan=(powercfg /getactivescheme | Out-String).Trim(); '
            . '$hags=(Get-ItemProperty \'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\' -Name HwSchMode).HwSchMode; '
            . '$reboot=((Test-Path \'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending\') -or (Test-Path \'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired\')); '
            . '$ram=@(Get-CimInstance Win32_PhysicalMemory | ForEach-Object { @{ cfg=[int]$_.ConfiguredClockSpeed; rated=[int]$_.Speed } }); '
            . '(@{ k41=$k41; dirty=$dirty; bsod=$bsod; whea=$whea; bad=@($bad); plan=$plan; hags=[int]$hags; reboot=[bool]$reboot; ram=$ram } | ConvertTo-Json -Compress -Depth 4)';
        $s = json_decode(trim((string)_nm_g_out(nm_win_ps($ssh,$ps,30))), true);
        if (is_array($s)) {
            $whea=(int)($s['whea']??0); $bsod=(int)($s['bsod']??0); $k41=(int)($s['k41']??0); $dirty=(int)($s['dirty']??0);
            if ($whea>0) $add('whea','Hardware errors (WHEA)','crit',$whea.' WHEA hardware error(s) in 14 days',['WHEA = CPU/RAM/PCIe hardware faults — investigate cooling, memory (XMP), or a failing component.']);
            else $add('whea','Hardware errors (WHEA)','ok','No hardware (WHEA) errors in 14 days');
            $cr=$k41+$dirty+$bsod; $add('stability','Crash & stability',$bsod>0?'crit':($cr>2?'warn':'ok'),
                $cr===0?'No crashes or unexpected shutdowns':($bsod.' BSOD · '.($k41+$dirty).' unexpected shutdowns (14d)'),
                [$bsod?($bsod.' blue-screen bugcheck(s)'):'', ($k41+$dirty)?(($k41+$dirty).' unexpected power-loss/reset event(s)'):'']);
            $bad=(array)($s['bad']??[]); $add('devices','Device Manager',$bad?'warn':'ok',$bad?(count($bad).' device(s) with a driver problem'):'All devices OK',$bad);
            $plan=(string)($s['plan']??''); $pn=''; if(preg_match('/\(([^)]+)\)\s*$/',$plan,$mm)) $pn=trim($mm[1]);
            $hi = (stripos($pn,'high')!==false||stripos($pn,'ultimate')!==false); $add('powerplan','Power plan',$hi?'ok':'info',$pn!==''?('Active: '.$pn):'unknown',$hi?[]:['For gaming, switch to High Performance / Ultimate Performance (the 1-Click Booster in Game Mode does this).']);
            $hags=(int)($s['hags']??0); $add('hags','GPU scheduling (HAGS)',$hags>=2?'ok':'info',$hags>=2?'Hardware-accelerated GPU scheduling ON':'HAGS off / unset',$hags>=2?[]:['Enabling Hardware-Accelerated GPU Scheduling can lower latency on modern GPUs (Settings → Display → Graphics).']);
            if (!empty($s['reboot'])) $add('reboot','Pending reboot','warn','Windows has a reboot pending',['A pending reboot can cause instability / block driver updates.']);
            $ram=(array)($s['ram']??[]); if(isset($ram['cfg']))$ram=[$ram]; $under=false; $cfg=0;$rated=0; foreach($ram as $m){ $cfg=max($cfg,(int)($m['cfg']??0)); $rated=max($rated,(int)($m['rated']??0)); }
            if ($cfg>0 && $rated>0) { $under = $cfg < $rated-50; $add('xmp','Memory speed (XMP/EXPO)',$under?'warn':'ok',$under?('Running '.$cfg.' MT/s — rated '.$rated):('At rated '.$cfg.' MT/s'),$under?['Your RAM is running below its rated speed. Enable XMP/EXPO in BIOS for full gaming performance.']:[]); }
        }
    } catch (\Throwable $e) {}

    // 3) GPU health via nvidia-smi (PCIe link, throttle, ECC, driver)
    try {
        $q = 'nvidia-smi --query-gpu=name,driver_version,pcie.link.gen.gpu.current,pcie.link.gen.gpu.max,pcie.link.width.current,pcie.link.width.max,temperature.gpu,clocks_throttle_reasons.active,ecc.errors.uncorrected.aggregate.total --format=csv,noheader,nounits';
        $out = trim((string)_nm_g_out(nm_win_ps($ssh,$q,15)));
        if ($out!=='' && stripos($out,'not recognized')===false && stripos($out,'error')!==0) {
            foreach (preg_split('/\r?\n/',$out) as $ln) { if(trim($ln)==='')continue; $c=array_map('trim',explode(',',$ln));
                $name=$c[0]??'GPU'; $drv=$c[1]??''; $wcur=(int)($c[4]??0); $wmax=(int)($c[5]??0); $gtemp=(int)($c[6]??0); $thr=strtolower($c[7]??''); $ecc=$c[8]??'';
                $st='ok'; $det=[]; if($drv)$det[]='Driver '.$drv; if($gtemp)$det[]=$gtemp.'°C';
                if ($wmax>0 && $wcur>0 && $wcur<$wmax){ $st='warn'; $det[]='⚠ PCIe link x'.$wcur.' (card supports x'.$wmax.') — reseat the GPU / check the slot'; }
                if ($thr!=='' && $thr!=='not active' && $thr!=='0x0000000000000000' && strpos($thr,'0x0')!==0){ $st= $st==='ok'?'warn':$st; $det[]='Throttling: '.$c[7]; }
                if (is_numeric($ecc) && (int)$ecc>0){ $st='crit'; $det[]='⚠ '.$ecc.' uncorrected ECC/VRAM errors'; }
                $add('gpu_'.md5($name),'GPU · '.$name,$st,$st==='ok'?'Healthy · full PCIe link':'Check GPU',$det);
            }
        }
    } catch (\Throwable $e) {}

    // 4) Thermals snapshot (LHM) — hottest CPU / GPU right now
    try { $s = nm_gaming_sensors($ssh); if(!empty($s['ok'])){ $t=array_map(fn($x)=>(int)$x['val'],($s['temps']??[])); $mx=$t?max($t):0;
        if($mx>0){ $st=$mx>=90?'crit':($mx>=80?'warn':'ok'); $add('thermal','Thermals (live)',$st,'Hottest sensor '.$mx.'°C',$st!=='ok'?['Check case airflow, dust, and fan curves — sustained high temps throttle performance and shorten hardware life.']:[]); } } } catch (\Throwable $e) {}

    // overall score
    $crit=0;$warn=0; foreach($checks as $c){ if($c['status']==='crit')$crit++; elseif($c['status']==='warn')$warn++; }
    $overall = $crit? 'crit' : ($warn? 'warn' : 'ok');
    return ['ok'=>true,'overall'=>$overall,'crit'=>$crit,'warn'=>$warn,'checks'=>$checks,'ts'=>time()];
}

// SMBIOS memory-type / form-factor decoders (codes → human string)
function nm_pcd_memtype(int $smt, int $mt): string {
    static $m=[20=>'DDR',21=>'DDR2',22=>'DDR2 FB-DIMM',24=>'DDR3',26=>'DDR4',34=>'DDR5',27=>'LPDDR',28=>'LPDDR2',29=>'LPDDR3',30=>'LPDDR4',35=>'LPDDR5'];
    if (isset($m[$smt])) return $m[$smt];
    static $o=[24=>'DDR3',26=>'DDR4',20=>'DDR',21=>'DDR2'];
    return $o[$mt] ?? '';
}
function nm_pcd_formfactor(int $ff): string { static $f=[7=>'RIMM',8=>'DIMM',9=>'SIMM',12=>'SODIMM',13=>'Micro-DIMM']; return $f[$ff] ?? ''; }
// PCI\VEN_10DE&… PNPDeviceID → a short "PCIe" hint (best-effort; the bus/slot isn't in the string, but confirms PCIe)
function nm_pcd_pci_slot(string $pnp): string { return stripos($pnp,'PCI\\')===0 ? 'PCI Express' : ''; }

// Guess a storage brand from the model string (models rarely carry a Manufacturer field).
function nm_pcd_disk_brand(string $name): string {
    $n = strtolower($name);
    foreach (['samsung'=>'Samsung','wd'=>'Western Digital','western digital'=>'Western Digital','wdc'=>'Western Digital',
        'seagate'=>'Seagate','crucial'=>'Crucial','micron'=>'Micron','kingston'=>'Kingston','sandisk'=>'SanDisk',
        'sabrent'=>'Sabrent','adata'=>'ADATA','corsair'=>'Corsair','sk hynix'=>'SK hynix','hynix'=>'SK hynix',
        'toshiba'=>'Toshiba','kioxia'=>'Kioxia','intel'=>'Intel','pny'=>'PNY','teamgroup'=>'TeamGroup','gigabyte'=>'Gigabyte',
        'nvme'=>'','ssd'=>'' ] as $k=>$v) if ($v!=='' && strpos($n,$k)!==false) return $v;
    return '';
}

// Live per-component telemetry for the virtual board: CPU load, RAM %, per-drive usage, network throughput,
// GPU util/temp/VRAM, and component temps — drives the heat colour, the load pulse, the currents AND the live
// value shown on each part's label. ONE light PS (cpu+ram+disks+net) + nvidia-smi + best-effort sensor temps.
function nm_pcd_live($conn, array $h): array {
    $out = ['ok'=>true,'cpu'=>null,'ram_pct'=>null,'ram_used'=>null,'ram_total'=>null,'gpu'=>null,'gpu_temp'=>null,
            'vram_pct'=>null,'vram_used'=>null,'vram_total'=>null,'net'=>null,'disks'=>[],'temps'=>[]];
    $ssh = null; try { $ssh = nm_win_resolve_ssh($conn,$h); } catch (\Throwable $e) {}
    if (!$ssh) return ['ok'=>false,'error'=>'no SSH'];
    // light combined PS — instantaneous, no heavy game-detection
    try {
        $ps = '$os=Get-CimInstance Win32_OperatingSystem; '
            . '$cpu=[int]((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average); '
            . '$disks=@(Get-CimInstance Win32_LogicalDisk -Filter \'DriveType=3\' | ForEach-Object { @{ id=[string]$_.DeviceID; used=[int]((($_.Size-$_.FreeSpace)/[math]::Max(1,$_.Size))*100); freegb=[math]::Round($_.FreeSpace/1073741824,0); sizegb=[math]::Round($_.Size/1073741824,0) } }); '
            . '$ni=Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch \'Loopback|isatap|Teredo|Virtual|Pseudo|Filter|Tunnel\' }; '
            . '$net=[math]::Round([double](($ni | Measure-Object BytesTotalPersec -Sum).Sum),0); '
            . '(@{ cpu=$cpu; mt=[math]::Round($os.TotalVisibleMemorySize/1024); mf=[math]::Round($os.FreePhysicalMemory/1024); disks=$disks; net=$net } | ConvertTo-Json -Compress -Depth 4)';
        $r = nm_win_ps($ssh, $ps, 18); $j = json_decode(trim((string)_nm_g_out($r)), true);
        if (is_array($j)) {
            $out['cpu'] = isset($j['cpu']) ? (int)$j['cpu'] : null;
            $mt=(int)($j['mt']??0); $mf=(int)($j['mf']??0);
            if ($mt>0) { $out['ram_total']=$mt; $out['ram_used']=$mt-$mf; $out['ram_pct']=(int)round(($mt-$mf)/$mt*100); }
            $out['net'] = isset($j['net']) ? (int)$j['net'] : null;
            $dl = $j['disks'] ?? []; if (isset($dl['id'])) $dl=[$dl];
            foreach ((array)$dl as $d) $out['disks'][] = ['id'=>(string)($d['id']??''),'used'=>(int)($d['used']??0),'free_gb'=>(int)($d['freegb']??0),'size_gb'=>(int)($d['sizegb']??0)];
        }
    } catch (\Throwable $e) {}
    // GPU (nvidia-smi — cheap) via the gaming helper
    try { $g = nm_gaming_gpu($ssh); if (!empty($g['ok'])) { $out['gpu']=$g['util']??null; $out['gpu_temp']=$g['temp']??null;
        if (!empty($g['vram_total'])) { $out['vram_total']=$g['vram_total']; $out['vram_used']=$g['vram_used']??0; $out['vram_pct']=(int)round(($g['vram_used']??0)/$g['vram_total']*100); } } } catch (\Throwable $e) {}
    // Rich per-component sensors from LibreHardwareMonitor — temps, per-core LOADS, CLOCKS (MHz), POWERS (W),
    // VOLTAGES (V) and FAN speeds. Lets the virtual board show real clock/power/load/voltage on every part.
    try { $s = nm_gaming_sensors($ssh); if (!empty($s['ok'])) {
        foreach (['temps','loads','clocks','powers','voltages','fans','data'] as $b) {
            $out[$b] = [];
            foreach (($s[$b] ?? []) as $x) $out[$b][] = ['name'=>$x['name'],'val'=>$x['val'],'hw'=>$x['hw'] ?? ''];
        }
        $out['sens_src'] = $s['src'] ?? '';
    } } catch (\Throwable $e) {}
    return $out;
}
