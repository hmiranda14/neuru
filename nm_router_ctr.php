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
    // ── NEURU brain tunnel on a MikroTik (native RouterOS WireGuard) ──────────────
    // A NEURU-in-a-Box container can't run its own wg0 (RouterOS gives containers no /dev/net/tun),
    // so we translate the box's Portal-issued wg0.conf into a NATIVE RouterOS WireGuard interface
    // named `neuru-brain` + its peer, and NAT so the container reaches the brain and the brain's
    // callbacks reach the container. 100% ADDITIVE + idempotent + name-scoped: this ONLY ever
    // touches interfaces/peers/NAT rules named/commented `neuru-brain` — it NEVER enumerates or
    // modifies any other WireGuard interface the router already has.
    function nm_rctr_wg_parse(string $conf): array {
        $o=['priv'=>'','addr'=>'','peer'=>'','psk'=>'','endpoint_host'=>'','endpoint_port'=>'','allowed'=>'','keepalive'=>'25'];
        foreach (preg_split('/\r?\n/', $conf) as $ln) {
            if (preg_match('/^\s*PrivateKey\s*=\s*(\S+)/i',$ln,$m))   $o['priv']=$m[1];
            elseif (preg_match('/^\s*Address\s*=\s*([0-9.]+)/i',$ln,$m)) $o['addr']=$m[1];
            elseif (preg_match('/^\s*PublicKey\s*=\s*(\S+)/i',$ln,$m))  $o['peer']=$m[1];
            elseif (preg_match('/^\s*PresharedKey\s*=\s*(\S+)/i',$ln,$m)) $o['psk']=$m[1];   // wg-easy issues a PSK — REQUIRED for the handshake
            elseif (preg_match('/^\s*Endpoint\s*=\s*([^:]+):(\d+)/i',$ln,$m)) { $o['endpoint_host']=$m[1]; $o['endpoint_port']=$m[2]; }
            elseif (preg_match('/^\s*AllowedIPs\s*=\s*(.+)/i',$ln,$m))  $o['allowed']=trim($m[1]);
            elseif (preg_match('/^\s*PersistentKeepalive\s*=\s*(\d+)/i',$ln,$m)) $o['keepalive']=$m[1];
        }
        return $o;
    }
    function nm_rctr_wg_setup($conn, int $nodeId, string $conf, string $containerIp, string $containerSubnet): array {
        $x = nm_rctr_ssh($conn,$nodeId); if (empty($x['ok'])) return $x; $ssh=$x['ssh'];
        $p = nm_rctr_wg_parse($conf);
        if ($p['priv']==='' || $p['peer']==='' || $p['addr']==='' || $p['endpoint_host']==='')
            return ['ok'=>false,'error'=>'incomplete wg0.conf (need PrivateKey, Address, Peer PublicKey, Endpoint)'];
        // pick a listen-port that does NOT collide with any existing WG interface's port
        $used = nm_rctr_run($ssh, ':foreach w in=[/interface/wireguard/find] do={ :put [/interface/wireguard/get $w listen-port] }');
        $taken = array_map('intval', preg_split('/\r?\n/', trim($used['out'] ?? '')));
        $port=13232; while (in_array($port,$taken,true)) $port++;
        $allowed = $p['allowed'] !== '' ? $p['allowed'] : '0.0.0.0/0';
        // RouterOS peer takes ONE allowed-address per entry; take the first (the brain subnet).
        $allow1 = trim(explode(',', $allowed)[0]);
        $log=[]; $step=function($cmd,$label) use($ssh,&$log){ $r=nm_rctr_run($ssh,$cmd,40); $ok=$r['ok']; $log[]=$label.': '.($ok?'ok':('ERR '.($r['err']??''))); return $r; };
        // 1) the interface (private key from the box's conf) — created ONLY if absent
        $step(':if ([:len [/interface/wireguard/find where name="neuru-brain"]]=0) do={ /interface/wireguard/add name=neuru-brain listen-port='.$port.' private-key="'.$p['priv'].'" comment="neuru-brain (NEURU auto — brain tunnel, do not delete)" }', 'wg interface neuru-brain');
        // 2) the tunnel address (box's assigned IP)
        $step(':if ([:len [/ip/address/find where interface="neuru-brain"]]=0) do={ /ip/address/add address='.$p['addr'].'/32 interface=neuru-brain }', 'address '.$p['addr']);
        // 3) the Portal peer — ONLY on our interface (create if absent). PSK included when present.
        $pskAdd = $p['psk']!=='' ? ' preshared-key="'.$p['psk'].'"' : '';
        $step(':if ([:len [/interface/wireguard/peers/find where interface="neuru-brain"]]=0) do={ /interface/wireguard/peers/add interface=neuru-brain public-key="'.$p['peer'].'" endpoint-address='.$p['endpoint_host'].' endpoint-port='.$p['endpoint_port'].' allowed-address='.$allow1.' persistent-keepalive='.$p['keepalive'].'s'.$pskAdd.' comment="neuru-brain" }', 'peer '.$p['endpoint_host']);
        // 3b) heal an existing peer to the current conf (endpoint/allowed/PSK can rotate on re-enroll)
        $step('/interface/wireguard/peers/set [find where interface="neuru-brain"] public-key="'.$p['peer'].'" endpoint-address='.$p['endpoint_host'].' endpoint-port='.$p['endpoint_port'].' allowed-address='.$allow1.($p['psk']!==''?' preshared-key="'.$p['psk'].'"':'').' persistent-keepalive='.$p['keepalive'].'s', 'sync peer + PSK');
        // 4) container → brain (masquerade the container subnet out the tunnel)
        $step(':if ([:len [/ip/firewall/nat/find comment="neuru-brain-out"]]=0) do={ /ip/firewall/nat/add chain=srcnat action=masquerade out-interface=neuru-brain src-address='.$containerSubnet.' comment="neuru-brain-out" }', 'nat out');
        // 5) brain → container (callbacks to the tunnel IP land on the box container, not the router)
        $step(':if ([:len [/ip/firewall/nat/find comment="neuru-brain-in"]]=0) do={ /ip/firewall/nat/add chain=dstnat dst-address='.$p['addr'].' in-interface=neuru-brain action=dst-nat to-addresses='.$containerIp.' comment="neuru-brain-in" }', 'nat in');
        // verify: did a handshake happen?
        sleep(3);
        $hs = nm_rctr_run($ssh, ':put [/interface/wireguard/peers/get [find where interface="neuru-brain"] last-handshake]');
        $up = trim($hs['out'] ?? ''); $ok = ($up!=='' && stripos($up,'never')===false && $up!=='0s');
        if (function_exists('nm_audit')) { try { nm_audit($conn,'router.wg.brain',['target_type'=>'node','target_id'=>$nodeId,'details'=>['iface'=>'neuru-brain','addr'=>$p['addr'],'handshake'=>$up]]); } catch (\Throwable $e) {} }
        return ['ok'=>true,'interface'=>'neuru-brain','address'=>$p['addr'],'listen_port'=>$port,'handshake'=>$up,'tunnel_up'=>$ok,'log'=>$log];
    }

    // Fetch the box's wg0.conf THROUGH the router (router→container HTTP, since the container is
    // behind the router), then create the native neuru-brain tunnel + tell the box it's router-mode.
    // The box exposes it token-gated (NEURU_WG_SETUP_TOKEN). Returns 'pending' if the box isn't enrolled yet.
    function nm_rctr_wg_from_box($conn, int $nodeId, string $boxIp, string $token, string $containerSubnet): array {
        if ($token==='') return ['ok'=>false,'error'=>'no setup token'];
        $x = nm_rctr_ssh($conn,$nodeId); if (empty($x['ok'])) return $x; $ssh=$x['ssh'];
        $url = 'http://'.$boxIp.'/wg_connection.php?api=wg_export&token='.$token;
        $r = nm_rctr_run($ssh, ':do { :local z [/tool/fetch url="'.$url.'" http-method=get output=user as-value]; :put ($z->"data") } on-error={ :put "FETCHERR" }', 30);
        $body = trim($r['out'] ?? '');
        if ($body==='' || strpos($body,'FETCHERR')!==false) return ['ok'=>false,'pending'=>true,'error'=>'box not answering yet'];
        $j = json_decode($body, true);
        if (!is_array($j) || empty($j['ok']) || empty($j['conf'])) return ['ok'=>false,'pending'=>true,'error'=>'box not enrolled yet'];
        $setup = nm_rctr_wg_setup($conn, $nodeId, (string)$j['conf'], $boxIp, $containerSubnet);
        if (empty($setup['ok'])) return $setup;
        // stop the box's "wg0 down" warning — its tunnel is live on the router now
        nm_rctr_run($ssh, ':do { /tool/fetch url="http://'.$boxIp.'/wg_connection.php?api=wg_router_mode&up=1&iface=neuru-brain&token='.$token.'" http-method=get output=none } on-error={}; :put ok', 20);
        return $setup + ['box_ip'=>$boxIp];
    }
    // Reconcile loop (called from a cron): for every router-box we deployed, if its brain tunnel isn't
    // wired yet, try to wire it (the user may have enabled WG on the box after deploy). Idempotent.
    function nm_rctr_wg_reconcile($conn): array {
        $done=[]; $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='rctr_wg_pending' LIMIT 1");
        $map = ($r && ($v=$r->fetch_row())) ? (json_decode((string)$v[0],true) ?: []) : [];
        if (!$map) return ['ok'=>true,'wired'=>0];
        $still=[];
        foreach ($map as $m) {
            $res = nm_rctr_wg_from_box($conn,(int)$m['node'],(string)$m['ip'],(string)$m['token'],(string)$m['subnet']);
            if (!empty($res['ok']) && !empty($res['tunnel_up'])) { $done[]=$m['ip']; }        // wired + handshaking → drop from pending
            else $still[]=$m;                                                                  // keep trying
        }
        try { $st=$conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES('rctr_wg_pending',?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
            $sv=json_encode(array_values($still)); $st->bind_param('s',$sv); $st->execute(); $st->close(); } catch (\Throwable $e) {}
        return ['ok'=>true,'wired'=>count($done),'pending'=>count($still)];
    }
    function nm_rctr_wg_remember($conn, int $node, string $ip, string $token, string $subnet): void {
        try { $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='rctr_wg_pending' LIMIT 1");
            $map=($r && ($v=$r->fetch_row()))?(json_decode((string)$v[0],true)?:[]):[];
            $map=array_values(array_filter($map, fn($m)=>($m['ip']??'')!==$ip));   // de-dup by ip
            $map[]=['node'=>$node,'ip'=>$ip,'token'=>$token,'subnet'=>$subnet];
            $st=$conn->prepare("INSERT INTO nm_settings(setting_key,setting_val) VALUES('rctr_wg_pending',?) ON DUPLICATE KEY UPDATE setting_val=VALUES(setting_val)");
            $sv=json_encode($map); $st->bind_param('s',$sv); $st->execute(); $st->close();
        } catch (\Throwable $e) {}
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
        // Fresh CHR: RouterOS needs a tmpdir on disk to extract images (esp. large ones like the
        // full box) — without it the pull silently fails. Set it once if empty (idempotent).
        $cfg = nm_rctr_run($ssh, ':put [/container/config/get tmpdir]');
        if (trim($cfg['out'] ?? '')==='') $step('/container/config/set tmpdir='.$store.'/tmp', 'set tmpdir');
        // The container's whole writable layer (incl. /var/lib/mysql) lives under root-dir on the
        // selected storage, so the database persists across restarts. (RouterOS 7.23 rejects a
        // mounts= that references a not-yet-existing mount; root-dir persistence is enough here.)
        if (!$probe['installed']) {
            $step('/container/add remote-image='.$image.' interface='.$cname.' root-dir='.$store.'/'.$cname.' envlist='.$cname.' start-on-boot=yes logging=yes', 'add container (pulling image…)');
        } else { $log[]='container: already present (reusing)'; }
        $step('/container/start [find where interface='.$cname.']', 'start container');
        if (function_exists('nm_audit')) { try { nm_audit($conn,'router.container.deploy',['target_type'=>'node','target_id'=>$nodeId,'details'=>['image'=>$image,'name'=>$cname]]); } catch (\Throwable $e) {} }
        // NEURU-in-a-Box brain tunnel: remember this box so the reconcile loop (cron) can auto-wire
        // its native `neuru-brain` WG on the router the moment WireGuard is enabled on the box — the
        // user never touches RouterOS. (The box can't run its own wg0: RouterOS gives it no TUN.)
        $wgNote='';
        if ($isBox) {
            $wgTok=''; foreach ((array)($spec['env'] ?? []) as $e) { if (strpos($e,'NEURU_WG_SETUP_TOKEN=')===0) { $wgTok=substr($e,21); break; } }
            $subnet=preg_replace('/\.\d+$/','.0/'.$pfx,$ip);
            if ($wgTok!=='') { nm_rctr_wg_remember($conn,$nodeId,$ip,$wgTok,$subnet);
                $wgNote=' The brain WireGuard tunnel will auto-configure on the router (neuru-brain) once you enable WireGuard on the box.'; }
        }
        return ['ok'=>true,'router'=>$probe['router'],'name'=>$cname,'container_ip'=>$ip,'bridge'=>$bridge,'storage'=>$store,'log'=>$log,
                'note'=>'Image is pulling on the router (~1-2 min).'.$wgNote];
    }
}
