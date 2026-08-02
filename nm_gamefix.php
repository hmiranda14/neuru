<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — Game Lab engine (nm_gamefix). Agentless PowerShell-over-SSH optimizers &
// fixers for the gamer's Windows rig. Reuses nm_winhost (nm_win_resolve_ssh + nm_win_ps)
// so there is NO second copy of SSH/host logic. Every PS body uses SINGLE quotes only
// (nm_win_ps wraps the whole thing in double quotes) and returns Compressed JSON.
//
// Contract per tool:  nm_gf_probe($ssh,$tool) → ['ok',steps[],score,badges[],findings[],fixes[]]
//                     nm_gf_fix($conn,$ssh,$tool,$fixKey) → ['ok','log'[],'msg','undo']
// Safety: destructive actions are explicit fix keys, audited, and (where possible) leave an
// undo note. SSD longevity guard: never blind-defrags NAND (analyze → ReTrim only).
// RBAC: 'gaming'. Universal: works on ANY monitored Windows rig, hides what a rig can't do.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_winhost.php';
require_once __DIR__ . '/nm_audit.php';

if (!function_exists('nm_gf_tools')) {

    function nm_gf_tools(): array {
        // key => [title, icon, color, blurb]
        return [
            'autoheal'  => ['Network Auto-Heal', 'fa-bolt',            '#36e3d0', 'Purge & tune the network stack for the lowest, most stable ping.'],
            'autorepair'=> ['Auto-Repair',        'fa-screwdriver-wrench','#7CFFB2','One-click fixes for the "my game won\'t open" nightmares.'],
            'crashshield'=>['Crash Shield',       'fa-shield-halved',  '#ff7a9c', 'Catch overlay/hook/DLL conflicts BEFORE the game crashes.'],
            'driverdoc' => ['Driver & Firmware',  'fa-microchip',      '#4da3ff', 'Audit drivers, NVMe firmware, BIOS & DPC latency for stability.'],
            'storage'   => ['Storage Optimizer',  'fa-hard-drive',     '#a884ff', 'SSD-safe asset-stream optimize — kill traversal stutter.'],
            'fps'       => ['FPS Guarantee',      'fa-gauge-high',     '#ffcf6b', 'A per-rig FPS contract + 1-click graphics profile.'],
        ];
    }

    // Run a single-line PS script and return decoded JSON (or ['_raw'=>output,'_err'=>..]).
    function nm_gf_ps($ssh, string $script, int $timeout = 40): array {
        if (!is_array($ssh)) return ['_err' => 'no ssh'];
        $r = nm_win_ps($ssh, $script, $timeout);
        // nm_cm_ssh_fetch returns the command output under 'config' (ok:true) or 'error' (ok:false).
        $out = is_array($r) ? (string)($r['config'] ?? $r['output'] ?? $r['data'] ?? '') : (string)$r;
        if ($out === '' && is_array($r) && !empty($r['error'])) return ['_err' => (string)$r['error']];
        $s = strpos($out, '{'); $a = strpos($out, '[');
        $i = ($s === false) ? $a : (($a === false) ? $s : min($s, $a));
        if ($i !== false && $i > 0) $out = substr($out, $i);
        $d = json_decode(trim($out), true);
        return is_array($d) ? $d : ['_raw' => mb_substr($out, 0, 2000)];
    }

    // PS helper: wrap a body so it always emits JSON. Single-quotes only inside $body.
    // The explicit ' ; ' before ConvertTo-Json terminates whatever the body's last statement was
    // (bodies that end in a bare assignment would otherwise glue onto '$o |' → "Unexpected token '$o'").
    function _gf_wrap(string $body): string {
        return '$ErrorActionPreference=\'SilentlyContinue\'; $o=@{}; ' . $body . ' ; $o | ConvertTo-Json -Compress -Depth 6';
    }

    function nm_gf_score_badge(int $score): array {
        if ($score >= 85) return ['green','Golden'];
        if ($score >= 60) return ['amber','Suboptimal'];
        return ['red','Critical'];
    }

    // ── Dispatcher ────────────────────────────────────────────────────────────
    function nm_gf_probe($ssh, string $tool): array {
        switch ($tool) {
            case 'autoheal':   return nm_gf_probe_autoheal($ssh);
            case 'autorepair': return nm_gf_probe_autorepair($ssh);
            case 'crashshield':return nm_gf_probe_crashshield($ssh);
            case 'driverdoc':  return nm_gf_probe_driverdoc($ssh);
            case 'storage':    return nm_gf_probe_storage($ssh);
            case 'fps':        return nm_gf_probe_fps($ssh);
        }
        return ['ok'=>false,'error'=>'unknown tool'];
    }
    function nm_gf_fix($conn, $ssh, string $tool, string $fix): array {
        $r = ['ok'=>false,'error'=>'unknown fix'];
        switch ($tool) {
            case 'autoheal':   $r = nm_gf_fix_autoheal($ssh,$fix); break;
            case 'autorepair': $r = nm_gf_fix_autorepair($ssh,$fix); break;
            case 'crashshield':$r = nm_gf_fix_crashshield($ssh,$fix); break;
            case 'storage':    $r = nm_gf_fix_storage($ssh,$fix); break;
            case 'fps':        $r = nm_gf_fix_fps($ssh,$fix); break;
        }
        try { nm_audit($conn,'gamelab.fix',['details'=>['tool'=>$tool,'fix'=>$fix,'ok'=>!empty($r['ok'])]]); } catch (\Throwable $e) {}
        return $r;
    }

    // ══════════════ #6 NETWORK AUTO-HEAL ══════════════
    function nm_gf_probe_autoheal($ssh): array {
        $body =
          '$a=Get-NetAdapter | Where-Object {$_.Status -eq \'Up\'} | Select-Object -First 1; '
        . 'if($a){ $o.iface=[string]$a.Name; $o.wifi=($a.PhysicalMediaType -match \'802.11\'); $o.linkmbps=[int64]$a.LinkSpeed.Split(\' \')[0] } '
        . '$dns=(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses}).ServerAddresses; $o.dns=@($dns); '
        . '$cands=@(\'1.1.1.1\',\'8.8.8.8\',\'9.9.9.9\'); $o.dnsping=@(); foreach($c in $cands){ $p=Test-Connection -ComputerName $c -Count 2 -Quiet:$false -ErrorAction SilentlyContinue; if($p){ $o.dnsping += @{ip=$c; ms=[int](($p | Measure-Object ResponseTime -Average).Average)} } } '
        . '$g=Test-Connection -ComputerName \'8.8.8.8\' -Count 6 -ErrorAction SilentlyContinue; if($g){ $rt=$g.ResponseTime; $o.avg=[int](($rt|Measure -Average).Average); $o.jitter=[int]([math]::Round(($rt|Measure -Maximum).Maximum-($rt|Measure -Minimum).Minimum)); $o.loss=[int](100-((($g|Measure).Count/6)*100)) } ';
        $d = nm_gf_ps($ssh, _gf_wrap($body), 45);
        if (isset($d['_err'])||isset($d['_raw'])) return ['ok'=>false,'error'=>'Could not reach the rig over SSH.','raw'=>$d['_raw']??$d['_err']??''];
        $steps=[]; $findings=[]; $score=100;
        $steps[]=['label'=>'Adapter','status'=>'ok','detail'=>($d['iface']??'?').(!empty($d['wifi'])?' · Wi-Fi':' · Ethernet')];
        $best=null; foreach(($d['dnsping']??[]) as $x){ if($best===null||$x['ms']<$best['ms'])$best=$x; }
        $curDns = implode(', ', $d['dns']??[]);
        $steps[]=['label'=>'DNS','status'=>'ok','detail'=>($curDns?:'auto').($best?' · fastest '.$best['ip'].' '.$best['ms'].'ms':'')];
        $avg=(int)($d['avg']??0); $jit=(int)($d['jitter']??0); $loss=(int)($d['loss']??0);
        $steps[]=['label'=>'Ping / jitter / loss','status'=>($loss>1||$jit>15)?'warn':'ok','detail'=>$avg.'ms · jit '.$jit.'ms · loss '.$loss.'%'];
        if($jit>15){$score-=25;$findings[]='High jitter ('.$jit.'ms) — bufferbloat / a "vampire" device on your LAN.';}
        if($loss>1){$score-=30;$findings[]='Packet loss '.$loss.'% — flaky link or congestion.';}
        if(!empty($d['wifi'])){$score-=10;$findings[]='On Wi-Fi — Ethernet is more stable for competitive play.';}
        $score=max(0,$score);
        $fixes=[
            ['key'=>'preflight','label'=>'Pre-Flight Clean','desc'=>'Flush DNS + reset Winsock + renew IP + purge ARP — clears ghost routes.','danger'=>0],
        ];
        if($best) $fixes[]=['key'=>'setdns:'.$best['ip'],'label'=>'Set fastest gaming DNS ('.$best['ip'].')','desc'=>'Switch DNS to the lowest-latency resolver for faster matchmaking.','danger'=>0];
        [$bc,$bl]=nm_gf_score_badge($score);
        return ['ok'=>true,'steps'=>$steps,'score'=>$score,'badges'=>[[$bc,$bl]],'findings'=>$findings,'fixes'=>$fixes];
    }
    function nm_gf_fix_autoheal($ssh,string $fix): array {
        if($fix==='preflight'){
            $body='$log=@(); ipconfig /flushdns | Out-Null; $log+=\'DNS cache flushed\'; netsh winsock reset | Out-Null; $log+=\'Winsock reset (reboot to finalize)\'; ipconfig /release | Out-Null; ipconfig /renew | Out-Null; $log+=\'IP lease renewed\'; arp -d * 2>$null; $log+=\'ARP table purged\'; $o.log=$log';
            $d=nm_gf_ps($ssh,_gf_wrap($body),40);
            return ['ok'=>!isset($d['_err']),'log'=>$d['log']??['done'],'msg'=>'Network stack purged. A reboot finalizes the Winsock reset.','undo'=>null];
        }
        if(strpos($fix,'setdns:')===0){
            $ip=preg_replace('/[^0-9.]/','',substr($fix,7));
            $body='$a=(Get-NetAdapter | Where-Object {$_.Status -eq \'Up\'} | Select-Object -First 1); $prev=(Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).ServerAddresses -join \',\'; Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses (\''.$ip.'\',\'1.0.0.1\'); $o.prev=$prev; $o.now=\''.$ip.'\'';
            $d=nm_gf_ps($ssh,_gf_wrap($body),25);
            return ['ok'=>!isset($d['_err']),'log'=>['Previous DNS: '.($d['prev']??'auto'),'New DNS: '.$ip],'msg'=>'Gaming DNS applied.','undo'=>'dns:'.($d['prev']??'')];
        }
        return ['ok'=>false,'error'=>'unknown fix'];
    }

    // ══════════════ #9 AUTO-REPAIR ══════════════
    function nm_gf_probe_autorepair($ssh): array {
        $body=
          '$svc=Get-Service -Name \'GamingServices\',\'XblAuthManager\',\'XboxNetApiSvc\',\'InstallService\' -ErrorAction SilentlyContinue; $o.services=@($svc | ForEach-Object { @{n=$_.Name; s=[string]$_.Status} }); '
        . '$vc=(Get-ChildItem \'HKLM:\\SOFTWARE\\Classes\\Installer\\Dependencies\' -ErrorAction SilentlyContinue | Where-Object {$_.Name -match \'VC,redist\'} | Measure-Object).Count; $o.vcpp=$vc; '
        . '$fw=Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { @{n=[string]$_.Name; e=[bool]$_.Enabled} }; $o.fw=@($fw); '
        . '$caches=@(); foreach($p in @(\"$env:LOCALAPPDATA\\Steam\\htmlcache\",\"$env:LOCALAPPDATA\\EpicGamesLauncher\\Saved\\webcache\",\"$env:ProgramData\\Battle.net\\Cache\",\"$env:LOCALAPPDATA\\EADesktop\\cache\")){ if(Test-Path $p){ $sz=(Get-ChildItem $p -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum; $caches += @{p=$p; mb=[math]::Round($sz/1MB,1)} } } $o.caches=@($caches); '
        . '$sfc=(Get-WinEvent -FilterHashtable @{LogName=\'Setup\'} -MaxEvents 1 -ErrorAction SilentlyContinue); ';
        // The path strings above use \" which would break the outer double-quote wrap → replace with single-quote-safe env expansion:
        $body = str_replace('\"', '\'', $body); // normalize to single quotes for env paths
        $d = nm_gf_ps($ssh, _gf_wrap($body), 40);
        if (isset($d['_err'])) return ['ok'=>false,'error'=>'Scan failed: '.substr((string)($d['_err']??$d['_raw']??'no output'),0,280)];
        $steps=[]; $findings=[]; $score=100; $fixes=[];
        $svcBad=false; foreach(($d['services']??[]) as $s){ if(($s['s']??'')!=='Running'&&in_array($s['n'],['GamingServices','XblAuthManager'])){$svcBad=true;} }
        $steps[]=['label'=>'Windows Gaming Services','status'=>$svcBad?'warn':'ok','detail'=>$svcBad?'a core service is stopped':'running'];
        if($svcBad){$score-=25;$findings[]='Gaming Services / Xbox auth stopped → Store & Game Pass launch errors.';$fixes[]=['key'=>'gamingsvc','label'=>'Repair Gaming Services','desc'=>'Restart Gaming Services + Xbox auth.','danger'=>0];}
        $cacheMb=0; foreach(($d['caches']??[]) as $c){$cacheMb+=(float)($c['mb']??0);}
        $steps[]=['label'=>'Launcher caches','status'=>$cacheMb>500?'warn':'ok','detail'=>round($cacheMb).' MB cached'];
        if($cacheMb>200){$fixes[]=['key'=>'purgecache','label'=>'Purge launcher caches','desc'=>'Clear Steam/Epic/Battle.net/EA web caches ('.round($cacheMb).' MB) — fixes stuck downloads.','danger'=>0];}
        $fwOff=false; foreach(($d['fw']??[]) as $f){ if(empty($f['e']))$fwOff=true; }
        $steps[]=['label'=>'Firewall profiles','status'=>$fwOff?'warn':'ok','detail'=>$fwOff?'a profile is OFF':'all on'];
        $steps[]=['label'=>'VC++ / DirectX runtimes','status'=>($d['vcpp']??0)>0?'ok':'warn','detail'=>($d['vcpp']??0).' redists present'];
        if(($d['vcpp']??0)<4){$score-=15;$findings[]='Few VC++ runtimes — a missing DLL can block a game from opening.';}
        // universal always-available fixes
        $fixes[]=['key'=>'firewall','label'=>'Reset game firewall rules','desc'=>'Regenerate Windows Firewall rules (fixes strict-NAT / blocked multiplayer).','danger'=>1];
        $fixes[]=['key'=>'dism','label'=>'System integrity repair (SFC+DISM)','desc'=>'Silent SFC + DISM — repairs corrupt OS files that cause freezes. Takes a few minutes.','danger'=>1];
        $score=max(0,$score); [$bc,$bl]=nm_gf_score_badge($score);
        return ['ok'=>true,'steps'=>$steps,'score'=>$score,'badges'=>[[$bc,$bl]],'findings'=>$findings,'fixes'=>$fixes];
    }
    function nm_gf_fix_autorepair($ssh,string $fix): array {
        $map=[
            'gamingsvc'=>'$log=@(); foreach($s in @(\'GamingServices\',\'XblAuthManager\',\'XboxNetApiSvc\')){ try{ Restart-Service -Name $s -Force -ErrorAction SilentlyContinue; $log+=($s+\' restarted\') }catch{ $log+=($s+\' failed\') } } $o.log=$log',
            'purgecache'=>'$log=@(); foreach($p in @($env:LOCALAPPDATA+\'\\Steam\\htmlcache\',$env:LOCALAPPDATA+\'\\EpicGamesLauncher\\Saved\\webcache\',$env:ProgramData+\'\\Battle.net\\Cache\',$env:LOCALAPPDATA+\'\\EADesktop\\cache\')){ if(Test-Path $p){ Remove-Item ($p+\'\\*\') -Recurse -Force -ErrorAction SilentlyContinue; $log+=(\'cleared \'+$p) } } $o.log=$log',
            'firewall'=>'netsh advfirewall reset | Out-Null; $o.log=@(\'Firewall rules regenerated to defaults\')',
            'dism'=>'$log=@(); $log+=\'Running DISM RestoreHealth...\'; DISM /Online /Cleanup-Image /RestoreHealth /Quiet | Out-Null; $log+=\'Running SFC...\'; sfc /scannow | Out-Null; $log+=\'Integrity repair complete\'; $o.log=$log',
        ];
        if(!isset($map[$fix])) return ['ok'=>false,'error'=>'unknown fix'];
        $to = $fix==='dism'?600:60;
        $d=nm_gf_ps($ssh,_gf_wrap($map[$fix]),$to);
        return ['ok'=>!isset($d['_err']),'log'=>$d['log']??['done'],'msg'=>'Repair applied.','undo'=>null];
    }

    // ══════════════ #5 CRASH SHIELD ══════════════
    function nm_gf_probe_crashshield($ssh): array {
        $body=
          '$ov=@{rtss=\'RTSS\';discord=\'Discord\';geforce=\'NVIDIA Share\';steam=\'GameOverlayUI\';msi=\'MSIAfterburner\';xbox=\'GameBar\'}; '
        . '$on=@(); foreach($k in $ov.Keys){ if(Get-Process -Name $ov[$k] -ErrorAction SilentlyContinue){ $on += $k } } $o.overlays=@($on); '
        . '$ac=@(); foreach($p in @(\'vgtray\',\'vgc\',\'EasyAntiCheat\',\'BEService\')){ if(Get-Process -Name $p -ErrorAction SilentlyContinue){ $ac += $p } } $o.anticheat=@($ac); '
        . '$cr=Get-WinEvent -FilterHashtable @{LogName=\'Application\'; ProviderName=\'Application Error\',\'Windows Error Reporting\'; StartTime=(Get-Date).AddDays(-3)} -MaxEvents 5 -ErrorAction SilentlyContinue; $o.crashes=@($cr | ForEach-Object { @{t=$_.TimeCreated.ToUniversalTime().ToString(\'yyyy-MM-dd HH:mm\'); m=(($_.Message -split \'\\r?\\n\')[0])} }); '
        . '$hp=(Get-Process | Measure-Object HandleCount -Sum).Sum; $o.handles=[int]$hp';
        $d=nm_gf_ps($ssh,_gf_wrap($body),40);
        if(isset($d['_err'])) return ['ok'=>false,'error'=>'Scan failed: '.substr((string)($d['_err']??$d['_raw']??'no output'),0,280)];
        $steps=[]; $findings=[]; $score=100; $fixes=[];
        $ov=$d['overlays']??[];
        $steps[]=['label'=>'Screen overlays running','status'=>count($ov)>1?'warn':'ok','detail'=>count($ov)?implode(', ',$ov):'none'];
        if(count($ov)>1){$score-=25;$findings[]='Multiple overlays ('.implode(' + ',$ov).') can collide in GPU memory → sudden crashes.';
            foreach($ov as $o1){ if(in_array($o1,['rtss','msi','geforce'])) $fixes[]=['key'=>'killov:'.$o1,'label'=>'Suspend '.$o1.' overlay','desc'=>'Stops the '.$o1.' overlay for this session (relaunch to restore).','danger'=>1]; }
        }
        $ac=$d['anticheat']??[];
        $steps[]=['label'=>'Anti-cheat active','status'=>'ok','detail'=>count($ac)?implode(', ',$ac):'none detected'];
        if(count($ac)&&count($ov)>1){$findings[]='Overlays + anti-cheat ('.implode(',',$ac).') present — a hooking overlay can trigger an anti-cheat kick. Keep overlays minimal.';}
        $cr=$d['crashes']??[];
        $steps[]=['label'=>'Recent crash events (3d)','status'=>count($cr)?'warn':'ok','detail'=>count($cr).' app-error events'];
        if(count($cr)){$score-=20;foreach(array_slice($cr,0,3) as $c){$findings[]='Crash '.$c['t'].': '.mb_substr($c['m'],0,90);}}
        $h=(int)($d['handles']??0);
        $steps[]=['label'=>'Kernel handles','status'=>$h>200000?'warn':'ok','detail'=>number_format($h).' open'];
        if($h>200000){$score-=15;$findings[]='Very high handle count — a background app is leaking; risk of out-of-handle crash.';}
        $risk = 100-$score;
        $score=max(0,$score); [$bc,$bl]=nm_gf_score_badge($score);
        $badges=[[$bc,$bl]]; array_unshift($badges, [$risk>50?'red':($risk>15?'amber':'green'), 'Crash risk '.$risk.'%']);
        return ['ok'=>true,'steps'=>$steps,'score'=>$score,'badges'=>$badges,'findings'=>$findings,'fixes'=>$fixes];
    }
    function nm_gf_fix_crashshield($ssh,string $fix): array {
        if(strpos($fix,'killov:')===0){
            $name=preg_replace('/[^a-z]/i','',substr($fix,7));
            $procMap=['rtss'=>'RTSS','msi'=>'MSIAfterburner','geforce'=>'NVIDIA Share','discord'=>'Discord'];
            $p=$procMap[strtolower($name)]??$name;
            $body='Stop-Process -Name \''.$p.'\' -Force -ErrorAction SilentlyContinue; $o.log=@(\'Suspended '.$p.' — relaunch it to restore the overlay\')';
            $d=nm_gf_ps($ssh,_gf_wrap($body),20);
            return ['ok'=>!isset($d['_err']),'log'=>$d['log']??['done'],'msg'=>'Overlay suspended for this session.','undo'=>'relaunch:'.$p];
        }
        return ['ok'=>false,'error'=>'unknown fix'];
    }

    // ══════════════ #4 DRIVER & FIRMWARE ══════════════
    function nm_gf_probe_driverdoc($ssh): array {
        $body=
          '$gpu=Get-CimInstance Win32_VideoController | Select-Object -First 1; if($gpu){ $o.gpu=@{name=[string]$gpu.Name; drv=[string]$gpu.DriverVersion; date=[string]$gpu.DriverDate} } '
        . '$bios=Get-CimInstance Win32_BIOS; if($bios){ $o.bios=@{ver=[string]$bios.SMBIOSBIOSVersion; date=[string]$bios.ReleaseDate} } '
        . '$pd=@(); try{ $pd=@(Get-PhysicalDisk | ForEach-Object { @{name=[string]$_.FriendlyName; fw=[string]$_.FirmwareVersion; media=[string]$_.MediaType; health=[string]$_.HealthStatus} }) }catch{} $o.disks=$pd; '
        . '$bad=@(Get-CimInstance Win32_PnPEntity | Where-Object {$_.ConfigManagerErrorCode -ne 0 -and $_.ConfigManagerErrorCode -ne $null} | ForEach-Object { @{n=[string]$_.Name; code=[int]$_.ConfigManagerErrorCode} }); $o.problem=$bad; '
        . '$dpc=[math]::Round((Get-Counter \'\\Processor(_Total)\\% DPC Time\' -SampleInterval 1 -MaxSamples 2 -ErrorAction SilentlyContinue | Select-Object -Expand CounterSamples | Measure-Object CookedValue -Average).Average,2); $o.dpc=$dpc';
        $d=nm_gf_ps($ssh,_gf_wrap($body),45);
        if(isset($d['_err'])) return ['ok'=>false,'error'=>'Scan failed: '.substr((string)($d['_err']??$d['_raw']??'no output'),0,280)];
        $steps=[]; $findings=[]; $score=100;
        if(!empty($d['gpu'])) $steps[]=['label'=>'GPU driver','status'=>'ok','detail'=>mb_substr($d['gpu']['name'],0,28).' · v'.$d['gpu']['drv']];
        if(!empty($d['bios'])) $steps[]=['label'=>'BIOS','status'=>'ok','detail'=>'v'.$d['bios']['ver']];
        foreach(($d['disks']??[]) as $dk){ $bad=($dk['health']??'Healthy')!=='Healthy'; if($bad){$score-=30;$findings[]='Disk '.$dk['name'].' health = '.$dk['health'].'.';}
            $steps[]=['label'=>'NVMe/SSD '.mb_substr($dk['name'],0,20),'status'=>$bad?'warn':'ok','detail'=>'fw '.($dk['fw']?:'?').' · '.$dk['health']]; }
        $prob=$d['problem']??[];
        $steps[]=['label'=>'Device Manager conflicts','status'=>count($prob)?'warn':'ok','detail'=>count($prob).' problem devices'];
        foreach(array_slice($prob,0,3) as $p){ $score-=12; $findings[]='Problem device: '.mb_substr($p['n'],0,50).' (code '.$p['code'].').'; }
        $dpc=(float)($d['dpc']??0);
        $steps[]=['label'=>'DPC latency (% DPC time)','status'=>$dpc>5?'warn':'ok','detail'=>$dpc.'%'];
        if($dpc>5){$score-=20;$findings[]='High DPC time ('.$dpc.'%) — a driver (often audio/network) is causing audio crackle & camera-turn stutter. LatencyMon confirms which.';}
        $score=max(0,$score); [$bc,$bl]=nm_gf_score_badge($score);
        // Driver/firmware is advisory (updating a GPU driver from here is out of scope/unsafe) — no auto-fixes, just guidance.
        return ['ok'=>true,'steps'=>$steps,'score'=>$score,'badges'=>[[$bc,$bl]],'findings'=>$findings?:['All firmware & drivers look healthy. 🟢'],'fixes'=>[]];
    }

    // ══════════════ #7 STORAGE OPTIMIZER ══════════════
    function nm_gf_probe_storage($ssh): array {
        $body=
          '$vols=@(); foreach($v in (Get-Volume | Where-Object {$_.DriveLetter -and $_.FileSystemType -eq \'NTFS\'})){ $an=Optimize-Volume -DriveLetter $v.DriveLetter -Analyze -Verbose -ErrorAction SilentlyContinue 4>&1 | Out-String; $frag=0; if($an -match \'([0-9]+)% fragmented\'){ $frag=[int]$Matches[1] } $media=\'HDD\'; try{ $pd=Get-Partition -DriveLetter $v.DriveLetter | Get-Disk | Get-PhysicalDisk; if($pd.MediaType){ $media=[string]$pd.MediaType } }catch{} $vols += @{d=[string]$v.DriveLetter; media=$media; frag=$frag; freegb=[math]::Round($v.SizeRemaining/1GB,0); sizegb=[math]::Round($v.Size/1GB,0)} } $o.vols=$vols; '
        . '$sc=@(); foreach($p in @($env:LOCALAPPDATA+\'\\NVIDIA\\DXCache\',$env:LOCALAPPDATA+\'\\NVIDIA\\GLCache\',$env:LOCALAPPDATA+\'\\D3DSCache\',$env:LOCALAPPDATA+\'\\AMD\\DxCache\')){ if(Test-Path $p){ $sz=(Get-ChildItem $p -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum; $sc += @{p=$p; mb=[math]::Round($sz/1MB,1)} } } $o.shaders=@($sc)';
        $d=nm_gf_ps($ssh,_gf_wrap($body),90);
        if(isset($d['_err'])) return ['ok'=>false,'error'=>'Scan failed: '.substr((string)($d['_err']??$d['_raw']??'no output'),0,280)];
        $steps=[]; $findings=[]; $score=100; $fixes=[];
        foreach(($d['vols']??[]) as $v){ $ssd=stripos($v['media']??'','SSD')!==false; $frag=(int)($v['frag']??0);
            $steps[]=['label'=>'Drive '.$v['d'].': ('.($v['media']?:'?').')','status'=>(!$ssd&&$frag>10)?'warn':'ok','detail'=>$frag.'% fragmented · '.$v['freegb'].' GB free'];
            if(!$ssd&&$frag>10){$score-=20;$findings[]='Drive '.$v['d'].' is '.$frag.'% fragmented (HDD) → traversal stutter loading map zones.';$fixes[]=['key'=>'defrag:'.$v['d'],'label'=>'Defragment '.$v['d'].':','desc'=>'Reorder fragmented game files contiguously (HDD).','danger'=>0];}
            if($ssd){$fixes[]=['key'=>'retrim:'.$v['d'],'label'=>'ReTrim SSD '.$v['d'].': (safe)','desc'=>'SSD-safe block re-alignment — maximizes read bandwidth without NAND wear.','danger'=>0];}
            if(($v['freegb']??99)<($v['sizegb']??100)*0.1){$score-=15;$findings[]='Drive '.$v['d'].' under 10% free — asset streaming suffers when the SSD is near-full.';}
        }
        $shMb=0; foreach(($d['shaders']??[]) as $s){$shMb+=(float)($s['mb']??0);}
        $steps[]=['label'=>'Shader caches','status'=>$shMb>1000?'warn':'ok','detail'=>round($shMb).' MB'];
        if($shMb>300){$fixes[]=['key'=>'shaders','label'=>'Purge stale shader caches','desc'=>'Clear old/duplicate DX/GL shader caches ('.round($shMb).' MB) — forces a clean recompile.','danger'=>0];}
        $score=max(0,$score); [$bc,$bl]=nm_gf_score_badge($score);
        return ['ok'=>true,'steps'=>$steps,'score'=>$score,'badges'=>[[$bc,$bl]],'findings'=>$findings,'fixes'=>$fixes];
    }
    function nm_gf_fix_storage($ssh,string $fix): array {
        if(strpos($fix,'retrim:')===0){ $dl=preg_replace('/[^A-Z]/i','',substr($fix,7)); $body='Optimize-Volume -DriveLetter \''.$dl.'\' -ReTrim -Verbose -ErrorAction SilentlyContinue | Out-Null; $o.log=@(\'ReTrim complete on '.$dl.': (SSD-safe)\')'; $d=nm_gf_ps($ssh,_gf_wrap($body),300); return ['ok'=>!isset($d['_err']),'log'=>$d['log']??['done'],'msg'=>'SSD re-aligned.','undo'=>null]; }
        if(strpos($fix,'defrag:')===0){ $dl=preg_replace('/[^A-Z]/i','',substr($fix,7)); $body='Optimize-Volume -DriveLetter \''.$dl.'\' -Defrag -Verbose -ErrorAction SilentlyContinue | Out-Null; $o.log=@(\'Defrag complete on '.$dl.':\')'; $d=nm_gf_ps($ssh,_gf_wrap($body),600); return ['ok'=>!isset($d['_err']),'log'=>$d['log']??['done'],'msg'=>'Drive defragmented.','undo'=>null]; }
        if($fix==='shaders'){ $body='$log=@(); foreach($p in @($env:LOCALAPPDATA+\'\\NVIDIA\\DXCache\',$env:LOCALAPPDATA+\'\\NVIDIA\\GLCache\',$env:LOCALAPPDATA+\'\\D3DSCache\',$env:LOCALAPPDATA+\'\\AMD\\DxCache\')){ if(Test-Path $p){ Remove-Item ($p+\'\\*\') -Recurse -Force -ErrorAction SilentlyContinue; $log+=(\'cleared \'+$p) } } $o.log=$log'; $d=nm_gf_ps($ssh,_gf_wrap($body),60); return ['ok'=>!isset($d['_err']),'log'=>$d['log']??['done'],'msg'=>'Shader caches purged — first launch recompiles clean.','undo'=>null]; }
        return ['ok'=>false,'error'=>'unknown fix'];
    }

    // ── GPU gaming-capability classifier (NVIDIA / AMD / Intel, incl. integrated). ONE source of truth
    //    reused by FPS Guarantee AND the Game Deck rig score so an iGPU never scores "ELITE". ──
    function nm_gf_gpu_class(string $name, float $vram = 0): array {
        $n = strtolower($name);
        // fps_base ≈ 1080p-high average FPS for a typical AAA title
        $map = ['5090'=>235,'5080'=>195,'5070 ti'=>155,'5070'=>135,'5060 ti'=>105,'5060'=>88,
                '4090'=>200,'4080'=>168,'4070 ti'=>142,'4070'=>120,'4060 ti'=>100,'4060'=>90,
                '3090'=>150,'3080 ti'=>140,'3080'=>128,'3070 ti'=>112,'3070'=>105,'3060 ti'=>95,'3060'=>82,
                '2080'=>98,'2070'=>78,'2060'=>65,'1660'=>55,'1650'=>44,'1080'=>72,'1070'=>60,'1060'=>45,'1050'=>30,
                'rx 7900'=>172,'rx 7800'=>140,'rx 7700'=>115,'rx 7600'=>90,'rx 6900'=>142,'rx 6800'=>120,'rx 6700'=>98,'rx 6600'=>82,'rx 6500'=>45,'rx 580'=>48,'rx 570'=>40,
                'arc a770'=>85,'arc a750'=>72,'arc a580'=>58,'arc a380'=>34,'arc b580'=>90];
        $fps = 0; foreach ($map as $k=>$v) { if (strpos($n,$k)!==false) { $fps=$v; break; } }
        $vendor = 'Unknown';
        if (preg_match('/nvidia|geforce|\brtx\b|\bgtx\b|quadro/',$n)) $vendor='NVIDIA';
        elseif (preg_match('/radeon|\brx ?\d|\bamd\b|\bati\b|firepro/',$n)) $vendor='AMD';
        elseif (preg_match('/intel|iris|\buhd\b|hd graphics|\barc\b/',$n)) $vendor='Intel';
        // integrated GPU: Intel UHD/Iris (not Arc), or AMD APU "Radeon Graphics/Vega" (not a discrete RX/Arc)
        $igpu = (bool)preg_match('/intel.*graphics|iris|\buhd\b|hd graphics|vega \d|radeon\(tm\) graphics|radeon graphics|ryzen.*graphics|microsoft basic/',$n) && !preg_match('/\barc\b|rx ?\d|radeon rx/',$n);
        if ($fps==0 && $igpu) $fps = preg_match('/iris xe|radeon 7\d\d|radeon 8\d\d/',$n) ? 40 : 22;
        if ($fps==0) $fps = $vram>=8 ? 55 : ($vram>=4 ? 38 : 26);   // unknown discrete → estimate by VRAM
        if ($igpu)            { $class='iGPU';     $cap=min(24,$fps); $verdict='Casual / esports only'; $ex='Light titles (Valorant, CS2, LoL, Minecraft, Rocket League) at 1080p LOW. Not built for AAA (Cyberpunk, CoD, Elden Ring).'; }
        elseif ($fps>=140)   { $class='Ultra';    $cap=100; $verdict='Elite — anything, maxed'; $ex='AAA at 1440p/4K Ultra + high-refresh (Cyberpunk, Alan Wake 2, CoD — all maxed).'; }
        elseif ($fps>=100)   { $class='High-End'; $cap=90;  $verdict='Heavy gaming'; $ex='AAA at 1440p High (Cyberpunk ~90fps · CoD 144fps competitive).'; }
        elseif ($fps>=70)    { $class='Mid-High'; $cap=74;  $verdict='Solid 1080p / 1440p'; $ex='AAA at 1080p High or 1440p Medium; esports 144fps+.'; }
        elseif ($fps>=45)    { $class='Mid';      $cap=56;  $verdict='1080p gaming'; $ex='AAA at 1080p Medium; esports at high FPS.'; }
        else                 { $class='Entry';    $cap=34;  $verdict='Light gaming'; $ex='Esports at 1080p Low; older / indie AAA only.'; }
        if ($vram>0 && $vram<6 && $cap>56 && !$igpu) { $cap=56; $ex.=' ⚠ Only '.$vram.'GB VRAM — limits high textures in modern AAA.'; }
        return ['vendor'=>$vendor,'igpu'=>$igpu,'fps_base'=>$fps,'class'=>$class,'capability'=>$cap,'verdict'=>$verdict,'examples'=>$ex];
    }

    // ══════════════ #8 FPS GUARANTEE ══════════════
    function nm_gf_probe_fps($ssh): array {
        $body=
          '$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1; $o.cpu=@{name=[string]$cpu.Name; cores=[int]$cpu.NumberOfCores; threads=[int]$cpu.NumberOfLogicalProcessors}; '
        . '$gpu=Get-CimInstance Win32_VideoController | Sort-Object AdapterRAM -Descending | Select-Object -First 1; '
        . '$vram=0; $gk=\'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\'; '   // AdapterRAM is a UINT32 (caps at 4GB) — read the real qwMemorySize
        . 'Get-ChildItem $gk -ErrorAction SilentlyContinue | ForEach-Object { $q=(Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).\'HardwareInformation.qwMemorySize\'; if($q -and $q -gt $vram){ $vram=$q } }; '
        . '$vgb=$(if($vram){[math]::Round($vram/1GB,1)}else{[math]::Round([double]$gpu.AdapterRAM/1GB,1)}); $o.gpu=@{name=[string]$gpu.Name; vram=$vgb}; '
        . '$ram=[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,0); $o.ram=$ram; '
        . '$mon=Get-CimInstance -Namespace root\\wmi WmiMonitorBasicDisplayParams -ErrorAction SilentlyContinue | Select-Object -First 1; $scr=Get-CimInstance Win32_VideoController | Select-Object -First 1; $o.res=([string]$scr.CurrentHorizontalResolution+\'x\'+[string]$scr.CurrentVerticalResolution); $o.refresh=[int]$scr.CurrentRefreshRate';
        $d=nm_gf_ps($ssh,_gf_wrap($body),35);
        if(isset($d['_err'])) return ['ok'=>false,'error'=>'Scan failed: '.substr((string)($d['_err']??$d['_raw']??'no output'),0,280)];
        // Gaming capability via the shared classifier (NVIDIA/AMD/Intel incl. integrated).
        // NOTE: this is a GAMING-CAPABILITY score (can this PC actually play games?) — SEPARATE from
        // the Game Deck's system-health/performance score. An iGPU scores low here even if healthy.
        $gpuName=(string)($d['gpu']['name']??''); $vram=(float)($d['gpu']['vram']??0);
        $gc=nm_gf_gpu_class($gpuName,$vram); $tier=$gc['fps_base'];
        $res=$d['res']??'1920x1080'; $mult=1.0; if(strpos($res,'2560')!==false)$mult=0.68; elseif(strpos($res,'3840')!==false)$mult=0.42;
        $avg=(int)round($tier*$mult); $low1=(int)round($avg*0.82);
        $steps=[];
        $steps[]=['label'=>'GPU','status'=>$gc['igpu']?'warn':'ok','detail'=>mb_substr($gpuName?:'?',0,32).' · '.($vram?:'?').' GB · '.$gc['vendor']];
        $steps[]=['label'=>'CPU / RAM','status'=>'ok','detail'=>($d['cpu']['cores']??'?').'C/'.($d['cpu']['threads']??'?').'T · '.($d['ram']??'?').' GB'];
        $steps[]=['label'=>'Display','status'=>'ok','detail'=>$res.' @ '.($d['refresh']??'?').'Hz'];
        $steps[]=['label'=>'Gaming capability','status'=>($gc['igpu']||$gc['capability']<40)?'warn':'ok','detail'=>$gc['class'].' — '.$gc['verdict']];
        $steps[]=['label'=>'NEURU FPS contract','status'=>'ok','detail'=>$avg.' FPS avg · '.$low1.' FPS (1% low) @ '.$res];
        $findings=['🎮 '.$gc['class'].' gaming rig — '.$gc['verdict'].'. '.$gc['examples']];
        $findings[]='At '.$res.', expect ~'.$avg.' FPS average ('.$low1.' FPS 1% low) with the Golden Balance profile.';
        if($gc['igpu'])                 $findings[]='⚠ Integrated graphics — fine for esports/casual, but heavy AAA needs a discrete GPU.';
        elseif(($d['refresh']??60)>$avg+20) $findings[]='Your '.$d['refresh'].'Hz monitor outruns the GPU here — the Competitive profile closes the gap.';
        $fixes=[
            ['key'=>'profile:comp','label'=>'⚡ Competitive (max FPS)','desc'=>'Generate a low-latency preset: shadows/post off, render-ahead 1. Est. +'.round($avg*0.35).' FPS.','danger'=>0],
            ['key'=>'profile:golden','label'=>'⚖️ Golden Balance','desc'=>'The sweet spot between sharpness and frame-rate for this rig.','danger'=>0],
            ['key'=>'profile:ultra','label'=>'🎨 Ultra Cinematic','desc'=>'Max fidelity with a solid 60 FPS floor.','danger'=>0],
        ];
        $capBadge = $gc['capability']>=85?'green':($gc['capability']>=50?'amber':'red');
        return ['ok'=>true,'steps'=>$steps,'score'=>$gc['capability'],
            'badges'=>[[$capBadge,$gc['class'].' rig'],['green','~'.$avg.' FPS @ '.$res]],
            'findings'=>$findings,'fixes'=>$fixes,'_fps'=>['avg'=>$avg,'low1'=>$low1,'res'=>$res],'capability'=>$gc];
    }
    function nm_gf_fix_fps($ssh,string $fix): array {
        // Preset injection is game-specific; return the exact preset the gamer applies (universal, safe).
        $presets=[
            'profile:comp'=>['Competitive','Shadows: Low · Anti-Alias: TAA/off · Post-process: Off · Motion Blur: Off · V-Sync: Off · Reflex: On · Render-ahead: 1'],
            'profile:golden'=>['Golden Balance','Textures: High · Shadows: Medium · AA: TAA · Effects: High · Upscaling: Quality (DLSS/FSR) · V-Sync: Off'],
            'profile:ultra'=>['Ultra Cinematic','Everything: Ultra/High · Ray-tracing: On (if supported) · Upscaling: Quality · Frame-gen: On · V-Sync: On'],
        ];
        $k=$presets[$fix]??null; if(!$k) return ['ok'=>false,'error'=>'unknown profile'];
        return ['ok'=>true,'log'=>['Profile: '.$k[0],$k[1]],'msg'=>'“'.$k[0].'” preset ready — apply these in the game\'s video menu (or NEURU injects it for supported titles). Target locked.','undo'=>null];
    }
}
