<?php
// ─────────────────────────────────────────────────────────────────────────────
// NEURU — deploy an OCI container ON a router that runs containers natively
// (MikroTik RouterOS 7.4+ `/container`) over SSH. This makes such routers first-class
// deploy targets in containers.php, alongside Portainer Docker hosts — so you can push
// NEURU Sentinel / Pi-hole / any image straight onto the MikroTik. Purely ADDITIVE +
// idempotent (detects the existing container network + storage; never touches other
// containers). Generalizes the sentinel router-deploy. Universal to any OCI-container router.
// ─────────────────────────────────────────────────────────────────────────────
if (!function_exists('nm_rctr_deploy')) {

    function nm_rctr_ssh($conn, int $nodeId): array {
        require_once __DIR__.'/nm_secrets.php'; require_once __DIR__.'/nm_confmgr.php'; require_once __DIR__.'/nm_nodemeta.php';
        $nr = $conn->query("SELECT display_name,os_icon FROM nm_nodes WHERE id=".(int)$nodeId." LIMIT 1"); $node=$nr?$nr->fetch_assoc():null;
        if (!$node) return ['ok'=>false,'error'=>'router not found'];
        $os = strtolower((string)$node['os_icon']);
        if (strpos($os,'mikrotik')===false && strpos($os,'routeros')===false) return ['ok'=>false,'error'=>'router-container deploy supported on MikroTik only'];
        $ssh = nm_ssh_resolve($conn,$nodeId); if (!$ssh) return ['ok'=>false,'error'=>'router has no SSH credential'];
        return ['ok'=>true,'ssh'=>$ssh,'name'=>$node['display_name']];
    }
    function nm_rctr_run($ssh, string $cmd, int $t=25): array {
        $r = nm_cm_ssh_fetch($ssh, $cmd.' ; :put "NM_END"', $t);
        if (empty($r['ok'])) return ['ok'=>false,'out'=>'','err'=>$r['error']??''];
        return ['ok'=>true,'out'=>trim(str_replace('NM_END','',(string)$r['config']))];
    }
    // MikroTik nodes that can host containers (have SSH). Detection of package/storage is at deploy time.
    function nm_rctr_targets($conn): array {
        require_once __DIR__.'/nm_nodemeta.php';
        $out=[]; $r=$conn->query("SELECT id,display_name,ip_address,os_icon FROM nm_nodes WHERE ssh_cred_id IS NOT NULL AND ssh_cred_id<>0 ORDER BY display_name");
        while ($r && ($x=$r->fetch_assoc())) { $os=strtolower((string)$x['os_icon']);
            if (strpos($os,'mikrotik')!==false || strpos($os,'routeros')!==false) $out[]=$x; }
        return $out;
    }
    // Detect the router's container capability + network + storage (universal, not hardcoded).
    function nm_rctr_probe($conn, int $nodeId, string $cname='neuru-app'): array {
        $x = nm_rctr_ssh($conn,$nodeId); if (empty($x['ok'])) return $x; $ssh=$x['ssh'];
        $pkg = nm_rctr_run($ssh, '/system/package/print where name~"container"');
        $has = stripos($pkg['out'] ?? '', 'container') !== false;
        // Resource pre-flight (NEURU is a resource dragon → x86 CHR + real RAM only for the full box).
        $res = nm_rctr_run($ssh, ':put ([/system/resource/get architecture-name].",".[/system/resource/get total-memory])');
        $rp  = explode(',', trim($res['out'] ?? '')); $arch=strtolower(trim($rp[0] ?? ''));
        $totmem=(int)preg_replace('/\D/','', $rp[1] ?? '0'); $mem_mb = $totmem>0 ? intdiv($totmem,1048576) : 0;
        $veth = nm_rctr_run($ssh, ':foreach v in=[/interface/veth/find] do={ :put ([/interface/veth/get $v name].",".[/interface/veth/get $v address].",".[/interface/veth/get $v gateway]) }');
        $subnet=$gw=''; $used=[];
        foreach (preg_split('/\r?\n/',$veth['out'] ?? '') as $ln){ $p=explode(',',$ln); if(count($p)>=3 && strpos($p[1],'/')!==false){ $used[]=explode('/',$p[1])[0]; if(!$subnet){ $subnet=$p[1]; $gw=$p[2]; } } }
        $disk = nm_rctr_run($ssh, ':foreach d in=[/disk/find where slot!=""] do={ :put [/disk/get $d slot] }');
        $slots = array_values(array_filter(array_map('trim', preg_split('/\r?\n/',$disk['out'] ?? '')), fn($s)=>$s!=='' && stripos($s,'swap')===false));
        $free='';
        if ($subnet && strpos($subnet,'/')!==false){ [$net]=explode('/',$subnet); $base=preg_replace('/\.\d+$/','',$net);
            for($i=11;$i<=250;$i++){ $c="$base.$i"; if($c!==$gw && !in_array($c,$used,true)){ $free=$c; break; } } }
        $exists = nm_rctr_run($ssh, ':put [:len [/container/find where interface="'.$cname.'"]]');
        return ['ok'=>true,'router'=>$x['name'],'has_container'=>$has,'subnet'=>$subnet,'gateway'=>$gw,
                'free_ip'=>$free,'prefix'=>$subnet?explode('/',$subnet)[1]:'24','arch'=>$arch,'mem_mb'=>$mem_mb,
                'storage'=>$slots[0]??'','storage_options'=>array_values($slots),'installed'=>trim($exists['out'] ?? '0')!=='0'];
    }
    // Ensure a container network exists on a FRESH router (no Pi-hole/veth yet). Additive + reversible:
    // creates a dedicated bridge on a private /24 that doesn't collide with the router's own addresses,
    // plus a masquerade so the container can reach the internet to pull its image. Returns the net.
    function nm_rctr_ensure_net($ssh): array {
        // candidate container subnets (Docker-style, unlikely on a LAN) — pick the first not already used
        $cands = ['172.17.0','172.18.0','172.20.0','10.111.0'];
        $addrs = nm_rctr_run($ssh, ':foreach a in=[/ip/address/find] do={ :put [/ip/address/get $a address] }');
        $have  = strtolower($addrs['out'] ?? '');
        $pick=''; foreach ($cands as $c){ if (strpos($have, $c.'.')===false){ $pick=$c; break; } }
        if ($pick==='') $pick='172.17.0';
        $gw=$pick.'.1'; $bridge='br-neuru';
        $log=[];
        $mk=function($cmd,$label) use($ssh,&$log){ $r=nm_rctr_run($ssh,$cmd,40); $log[]=$label.': '.($r['ok']?'ok':('ERR '.($r['err']??''))); };
        $mk(':if ([:len [/interface/bridge/find where name="'.$bridge.'"]]=0) do={ /interface/bridge/add name='.$bridge.' }', 'create '.$bridge);
        $mk(':if ([:len [/ip/address/find where interface="'.$bridge.'"]]=0) do={ /ip/address/add address='.$gw.'/24 interface='.$bridge.' }', 'bridge ip '.$gw);
        $mk(':if ([:len [/ip/firewall/nat/find comment="neuru-container-net"]]=0) do={ /ip/firewall/nat/add chain=srcnat action=masquerade src-address='.$pick.'.0/24 comment="neuru-container-net" }', 'nat '.$pick.'.0/24');
        return ['bridge'=>$bridge,'gateway'=>$gw,'prefix'=>'24','free_ip'=>$pick.'.11','provision_log'=>$log];
    }
    // Sanitize an image into a short container/veth name (ghcr.io/x/neuru-sentinel:latest → neuru-sentinel).
    function nm_rctr_name(string $image, string $override=''): string {
        if ($override!=='') $n=$override; else { $base=preg_replace('/:.*/','', $image); $n=substr(strrchr('/'.$base,'/'),1); }
        $n=strtolower(preg_replace('/[^a-z0-9\-]/','-', $n)); return substr(trim($n,'-') ?: 'neuru-app', 0, 24);
    }
    // Deploy $spec (image, name?, env[], storage?) onto the router. Additive + idempotent.
    function nm_rctr_deploy($conn, int $nodeId, array $spec, ?int $uid=null): array {
        @set_time_limit(180);
        $image = trim((string)($spec['image'] ?? '')); if ($image==='') return ['ok'=>false,'error'=>'no image'];
        $cname = nm_rctr_name($image, (string)($spec['name'] ?? ''));
        $probe = nm_rctr_probe($conn,$nodeId,$cname); if (empty($probe['ok'])) return $probe;
        if (!$probe['has_container']) return ['ok'=>false,'error'=>'the RouterOS "container" package/device-mode is not enabled on this router'];
        if (!$probe['storage'])      return ['ok'=>false,'error'=>'no mounted storage (USB/NVMe) on this router for the container root-dir'];
        // NEURU-in-a-Box is the FULL platform (Apache+PHP+MariaDB) → resource pre-flight. Refuse ARM
        // RouterOS (too small) and warn on <2 GB RAM. Lightweight images (sentinel/pihole) skip this.
        $isBox = stripos($image,'neuru-box')!==false;
        if ($isBox) {
            if ($probe['arch']!=='' && strpos($probe['arch'],'x86')===false && strpos($probe['arch'],'amd')===false && strpos($probe['arch'],'86_64')===false)
                return ['ok'=>false,'error'=>'NEURU-in-a-Box needs an x86 CHR — this router is "'.$probe['arch'].'" (the full platform is too heavy for ARM RouterOS). Deploy it on a Pi/Ubuntu host, or wait for the slim edge profile.'];
            if ($probe['mem_mb']>0 && $probe['mem_mb']<1500)
                return ['ok'=>false,'error'=>'NEURU-in-a-Box needs ≥2 GB RAM — this CHR reports '.$probe['mem_mb'].' MB. Raise the CHR memory first.'];
        }
        $store = (!empty($spec['storage']) && in_array($spec['storage'],$probe['storage_options'],true)) ? $spec['storage'] : $probe['storage'];
        $x = nm_rctr_ssh($conn,$nodeId); $ssh=$x['ssh'];
        $log=[]; $step=function($cmd,$label) use($ssh,&$log){ $r=nm_rctr_run($ssh,$cmd,60); $log[]=$label.': '.($r['ok']?'ok':('ERR '.($r['err']??''))); return $r; };
        if (!$probe['free_ip']) {
            // Fresh router with no container network yet → auto-provision a dedicated bridge + subnet.
            $net = nm_rctr_ensure_net($ssh);
            $log = array_merge($log, $net['provision_log'] ?? []);
            $ip=$net['free_ip']; $pfx=$net['prefix']; $gw=$net['gateway']; $bridge=$net['bridge'];
        } else {
            $ip=$probe['free_ip']; $pfx=$probe['prefix']; $gw=$probe['gateway'];
            $br = nm_rctr_run($ssh, ':local b ""; :foreach p in=[/interface/bridge/port/find] do={ :local i [/interface/bridge/port/get $p interface]; :if ([/interface/find where name=$i type=veth]!="") do={ :set b [/interface/bridge/port/get $p bridge] } }; :put $b');
            $bridge = trim($br['out'] ?? '') ?: 'br-docker';
        }
        $step('/interface/veth/add name='.$cname.' address='.$ip.'/'.$pfx.' gateway='.$gw, 'create veth');
        $step('/interface/bridge/port/add bridge='.$bridge.' interface='.$cname, 'attach to '.$bridge);
        $step(':if ([:len [/ip/firewall/nat/find comment="neuru-container-nat"]]=0) do={ /ip/firewall/nat/add chain=srcnat action=masquerade src-address='.$ip.' comment="neuru-container-nat" }', 'nat');
        // envs (from the deploy form: ["KEY=VAL", …])
        $step('/container/envs/remove [find where list='.$cname.']', 'clear envs');
        foreach ((array)($spec['env'] ?? []) as $e) {
            $e=trim((string)$e); $eq=strpos($e,'='); if ($eq===false) continue;
            $k=substr($e,0,$eq); $v=substr($e,$eq+1);
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/',$k)) continue;
            $step('/container/envs/add list='.$cname.' key='.$k.' value="'.str_replace('"','',$v).'"', 'env '.$k);
        }
        // For the full box, keep the database on a persistent mount so it survives a container
        // remove/re-pull (the DB outlives image upgrades). Root-dir alone only survives restarts.
        $mounts='';
        if ($isBox) {
            $step(':if ([:len [/container/mounts/find where name="'.$cname.'-db"]]=0) do={ /container/mounts/add name="'.$cname.'-db" src='.$store.'/'.$cname.'-db dst=/var/lib/mysql }', 'db mount');
            $mounts=' mounts='.$cname.'-db';
        }
        if (!$probe['installed']) {
            $step('/container/add remote-image='.$image.' interface='.$cname.' root-dir='.$store.'/'.$cname.$mounts.' envlist='.$cname.' start-on-boot=yes logging=yes', 'add container (pulling image…)');
        } else { $log[]='container: already present (reusing)'; }
        $step('/container/start [find where interface='.$cname.']', 'start container');
        if (function_exists('nm_audit')) { try { nm_audit($conn,'router.container.deploy',['target_type'=>'node','target_id'=>$nodeId,'details'=>['image'=>$image,'name'=>$cname]]); } catch (\Throwable $e) {} }
        return ['ok'=>true,'router'=>$probe['router'],'name'=>$cname,'container_ip'=>$ip,'bridge'=>$bridge,'storage'=>$store,'log'=>$log,
                'note'=>'Image is pulling on the router (~1-2 min).'];
    }
}
